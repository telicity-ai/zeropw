"""Invite/join/remove and environment sharing (docs/team-sync.md sections 4.3, 4.4, 12).

Invite secrets at rest
-----------------------
An invite (docs/team-sync.md section 4.3) is a one-time bootstrap credential:
``create_invite`` returns a base32 string encoding a canonical JSON payload
that carries a fresh 32-byte ``invite_secret`` in the clear -- it has to, since
it is handed to the joining person out of band (chat, a QR code, whatever) and
they need the raw secret to compute the HMAC proof in the handshake.  The
*node* that created the invite never writes that raw secret to disk in the
clear, though: the design brief for this stage settles the shape as

    ``team/<env_id>/invites.json`` = ``{invite_id: {"wrapped_secret": ...,
    "role", "name", "expires_at", "used"}}``

where ``invite_id = sha256(secret)[:16].hex()`` and ``wrapped_secret`` is the
secret sealed under this node's own local KMS (``zeropw.kms.Kms.wrap``) --
the same protection every other local key material gets (device key, vault
DEK).  It is a bootstrap secret, not a vault value: it is never subject to
rotation/reveal/audit-value rules, but it is exactly as sensitive as a device
key until it is consumed, so it gets the same at-rest treatment.

Accepting an invite (``consume_invite``, called from
``zeropw.team.sync.TeamSync._invite_check``) needs the actual secret bytes
back to verify ``HMAC-SHA256(secret, transcript_hash)`` -- an approach where
the node stored only ``sha256(secret)`` cannot do this, since verifying an
HMAC needs the key, not its hash.  So the node unwraps ``wrapped_secret`` for
the candidate invite id, checks expiry and the ``used`` flag, computes the
same HMAC, and -- inside ``ctx.state.lock()``, before any resulting
``member.add`` commit is even built -- marks the invite ``used`` so a second
join attempt (even a byte-identical replay of msg3) is refused.  Expired,
already-used or unknown invites, and any other verification failure, are
uniformly a ``consume_invite`` return of ``None`` --
``transport.HandshakeFailed("invite_invalid")`` from the caller's perspective,
so a probing peer learns nothing about *why* an invite id failed to match.

Node-local commit/fact authorship without a live ``TeamSync``
---------------------------------------------------------------
The administrator CLI (``zeropw.admin_cli``) is, by design, a separate
one-shot process from any running ``serve --team-listen`` (docs/team-sync.md
section 12): it has no live session to any peer.  ``author_commit``/
``author_fact`` below write straight to this node's own ``CommitStore``/
``facts.jsonl`` and fold+derive locally under the state lock; a separately
running ``serve`` process's ``TeamSync.poll()`` notices the new local vector
or new fact lines on its next tick and broadcasts them (see
``TeamSync._pick_up_local_commits``/``_pick_up_local_facts``).  When a caller
*does* have a live ``TeamSync`` in the same process (every test in this
module's own test suite, and ``join``, which cannot avoid one), passing it in
makes the commit/fact apply and broadcast immediately instead of waiting for
a poll tick.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Callable

from .. import policy as P
from ..errors import AuthFailed, InvalidInput, NotFound, PolicyDenied, StateError
from ..kms import WrappedKey
from ..store import iso
from ..vault import VAULT_DOC
from . import commit as C
from . import envelope
from . import fold as F
from . import sync as S
from .identity import DeviceKey, DeviceRecord
from .transport import HandshakeFailed, SessionClosed

INVITE_FORMAT = "zeropw-team-invite-v1"
DEFAULT_INVITE_TTL_SECONDS = 24 * 3600
MAX_INVITE_TTL_SECONDS = 30 * 24 * 3600
MAX_ADDRESSES = 16
JOIN_TIMEOUT_SECONDS = 20.0


def _canon(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b32e(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=").lower()


def _b32d(text: str) -> bytes:
    padded = text.strip().upper()
    padded += "=" * (-len(padded) % 8)
    return base64.b32decode(padded)


def _invites_path(env_id: str) -> str:
    return f"team/{env_id}/invites.json"


def _rotation_flags_path(env_id: str) -> str:
    return f"team/{env_id}/rotation_flags.json"


# ------------------------------------------------------------- env name mapping
# Thin re-exports: the node-local {env_id: {project, environment}} map (section 12's "--env P/E")
# lives in sync.py (so TeamSync's own _refold can use it without importing this module and creating
# an import cycle); membership just needs the read/write surface too.
env_mapping = S.read_env_mapping
set_env_mapping = S.write_env_mapping
env_project_environment = S.env_project_environment
resolve_env_id = S.resolve_env_id


def load_environment(ctx: Any, env_id: str) -> F.FoldResult:
    store = C.CommitStore(ctx.state, env_id)
    facts, _, _ = S.load_facts(ctx.state, env_id)
    return F.fold_with_snapshot(env_id, store.all_commits(), ctx.state, facts=facts, audit=ctx.audit)


def _refold_and_derive(ctx: Any, env_id: str) -> F.FoldResult:
    fold_result = load_environment(ctx, env_id)
    device = DeviceKey.load_or_create(ctx.state, ctx.kms)
    project, environment = env_project_environment(ctx.state, env_id)
    F.derive_local(fold_result, ctx.state, ctx.vault, ctx.policy, ctx.audit, device=device,
                   project=project, environment=environment)
    return fold_result


def _is_admin(doc: dict, fp: str) -> bool:
    member = doc.get("members", {}).get(fp)
    if not member or member.get("status") != "active":
        return False
    return fp == doc.get("owner") or member.get("role") == "admin"


# -------------------------------------------------------------------- authorship
def author_commit(ctx: Any, team_sync: Any, env_id: str, ops: list[dict[str, Any]]) -> C.Commit:
    """Sign, store, fold+derive (and, with a live ``team_sync``, broadcast) one commit.

    Safe to call repeatedly in a loop for a multi-commit operation
    (``share_environment``): each call re-reads the store's current
    per-author sequence and HLC, so sequencing is always correct regardless
    of whether ``team_sync`` is live.
    """
    device = DeviceKey.load_or_create(ctx.state, ctx.kms)
    store = C.CommitStore(ctx.state, env_id)
    with ctx.state.lock():
        hlc = C.Hlc()
        last_seq = store.last_seq(device.fingerprint)
        if last_seq:
            previous = store.get(device.fingerprint, last_seq)
            if previous is not None:
                hlc.observe(previous.hlc)
        seq = last_seq + 1
        hlc_value = hlc.tick()
        vector = store.vector()
        commit_obj = C.sign_commit(device, env_id, seq, hlc_value, vector, ops)
        if team_sync is not None:
            outcome = team_sync.submit_commit(env_id, commit_obj)
        else:
            outcome = C.receive_commit(store, commit_obj, C.now_ms(), audit=ctx.audit)
    if outcome != "accepted":
        raise StateError(f"team_local_commit_{outcome}")
    if team_sync is None:
        _refold_and_derive(ctx, env_id)
    return commit_obj


def author_fact(ctx: Any, team_sync: Any, env_id: str, kind: str, **target: Any) -> dict:
    """Sign, persist (and, with a live ``team_sync``, broadcast) one fact (section 7.4)."""
    if team_sync is not None:
        return team_sync.publish_fact(env_id, kind, **target)
    device = DeviceKey.load_or_create(ctx.state, ctx.kms)
    doc = load_environment(ctx, env_id).document
    if kind == "member_removed":
        facts, _, removal_authors = S.load_facts(ctx.state, env_id)
        author_fp = device.fingerprint
        removed_by = removal_authors.get(author_fp, ())
        if author_fp in facts.removed_members and set(removed_by) == {target.get("fingerprint")}:
            relaxed = facts.copy()
            relaxed.removed_members = set(relaxed.removed_members) - {author_fp}
            store = C.CommitStore(ctx.state, env_id)
            doc = F.fold_with_snapshot(env_id, store.all_commits(), ctx.state, facts=relaxed,
                                       audit=ctx.audit).document
    if not S._fact_role_ok(doc, kind, device.fingerprint, target):
        raise PolicyDenied("team_fact_not_authorized")
    hlc_value = C.Hlc().tick()
    fact = S.sign_fact(device, env_id, kind, dict(target), hlc_value)
    with ctx.state.lock():
        ctx.state.append_line(f"team/{env_id}/facts.jsonl", json.dumps(fact.to_dict(), sort_keys=True,
                                                                        separators=(",", ":")))
    try:
        ctx.audit.record("team_fact_apply", caller="admin", result="ok", extra={"env_id": env_id, "kind": kind})
    except Exception:
        pass
    _refold_and_derive(ctx, env_id)
    return fact.to_dict()


# ------------------------------------------------------------------------ invites
def create_invite(ctx: Any, env_id: str, role: str, name: str, ttl_seconds: int = DEFAULT_INVITE_TTL_SECONDS,
                  addresses: list[str] | None = None) -> str:
    """``team invite`` (section 4.3 step 1).  Returns the base32 invite string; the CLI attaches a
    "do not paste this into chat/issues" warning to its own JSON output, not this function."""
    if role not in ("admin", "user"):
        raise InvalidInput("invalid_role")
    if not isinstance(name, str) or not (0 < len(name) <= 200):
        raise InvalidInput("invalid_member_name")
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or not (0 < ttl_seconds <= MAX_INVITE_TTL_SECONDS):
        raise InvalidInput("invalid_ttl")
    addrs = list(addresses or [])
    if len(addrs) > MAX_ADDRESSES:
        raise InvalidInput("too_many_addresses")
    for addr in addrs:
        if not isinstance(addr, str) or not (0 < len(addr) <= 128):
            raise InvalidInput("invalid_address")

    device = DeviceKey.load_or_create(ctx.state, ctx.kms)
    doc = load_environment(ctx, env_id).document
    if doc.get("owner") is None:
        raise NotFound("team_env_not_found")
    if not _is_admin(doc, device.fingerprint):
        raise PolicyDenied("not_admin")

    secret = secrets.token_bytes(32)
    invite_id = hashlib.sha256(secret).hexdigest()[:32]
    expires_at = ctx.clock() + ttl_seconds
    payload = {"format": INVITE_FORMAT, "env_id": env_id, "inviter": device.fingerprint, "addresses": addrs,
               "invite_secret": base64.b64encode(secret).decode("ascii"), "expires_at": iso(expires_at),
               "role": role, "name": name}
    text = _b32e(_canon(payload))
    with ctx.state.lock():
        invites = ctx.state.read_json(_invites_path(env_id), {}) or {}
        invites[invite_id] = {"wrapped_secret": ctx.kms.wrap(secret).to_dict(), "role": role, "name": name,
                              "expires_at": expires_at, "used": False}
        ctx.state.write_json(_invites_path(env_id), invites)
    try:
        ctx.audit.record("team_invite_create", caller="admin", result="ok", extra={"env_id": env_id, "role": role})
    except Exception:
        pass
    return text


def parse_invite(text: str) -> dict[str, Any]:
    try:
        payload = json.loads(_b32d(text).decode("utf-8"))
    except Exception as exc:
        raise InvalidInput("invite_malformed") from exc
    if not isinstance(payload, dict) or payload.get("format") != INVITE_FORMAT:
        raise InvalidInput("invite_malformed")
    try:
        env_id = str(payload["env_id"])
        if not C.valid_env_id(env_id):
            raise InvalidInput("invite_malformed")
        inviter = str(payload["inviter"])
        addresses = [str(a) for a in payload.get("addresses", [])]
        secret = base64.b64decode(payload["invite_secret"])
        expires_at = str(payload["expires_at"])
        role = str(payload["role"])
        name = str(payload["name"])
    except (KeyError, TypeError, ValueError) as exc:
        raise InvalidInput("invite_malformed") from exc
    if len(secret) != 32 or role not in ("admin", "user") or not (0 < len(name) <= 200):
        raise InvalidInput("invite_malformed")
    return {"env_id": env_id, "inviter": inviter, "addresses": addresses, "invite_secret": secret,
            "expires_at": expires_at, "role": role, "name": name}


def consume_invite(ctx: Any, env_id: str, transcript_hash: bytes, proof: bytes) -> dict[str, str] | None:
    """Responder side (section 4.3 step 3): verify ``proof`` against every unexpired, unused
    invite; on a match, mark it used (one-time) and return its ``{"role", "name"}``.  ``None`` on
    any failure (unknown env, no matching invite, expired, already used).
    """
    if not isinstance(proof, (bytes, bytearray)) or not proof:
        return None
    now = ctx.clock()
    with ctx.state.lock():
        invites = ctx.state.read_json(_invites_path(env_id), {}) or {}
        matched_id = None
        matched: dict[str, Any] | None = None
        for invite_id, entry in invites.items():
            if not isinstance(entry, dict) or entry.get("used"):
                continue
            try:
                expires_at = _parse_expiry(entry.get("expires_at"))
            except (TypeError, ValueError):
                continue
            if expires_at is None or now > expires_at:
                continue
            try:
                secret = ctx.kms.unwrap(WrappedKey.from_dict(entry["wrapped_secret"]))
            except Exception:
                continue
            expected = hmac.new(secret, bytes(transcript_hash), hashlib.sha256).digest()
            if hmac.compare_digest(expected, bytes(proof)):
                matched_id, matched = invite_id, entry
                break
        if matched is None:
            return None
        invites[matched_id]["used"] = True
        ctx.state.write_json(_invites_path(env_id), invites)
    return {"role": str(matched["role"]), "name": str(matched["name"])}


def _parse_expiry(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        return time.mktime(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ")) - time.timezone
    return None


# --------------------------------------------------------------------------- join
def join(ctx: Any, invite_text: str, transport: Any, team_sync: Any, project: str | None = None,
        environment: str | None = None, timeout: float = JOIN_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Initiator side of section 4.3: dial the inviter, prove the invite, receive the full history,
    fold, and derive local project/environment entries.  ``team_sync`` must be live (a
    ``TeamSync`` over ``transport``, not necessarily listening) -- this is the one membership
    operation that genuinely needs a network round trip, unlike ``share_environment``/
    ``remove_member``, which never need one to make local progress.
    """
    payload = parse_invite(invite_text)
    env_id = payload["env_id"]
    device = DeviceKey.load_or_create(ctx.state, ctx.kms)
    proj = project or f"team-{payload['inviter'][:8]}"
    envr = environment or "shared"
    set_env_mapping(ctx.state, env_id, proj, envr)
    team_sync.register_env(env_id)
    secret = payload["invite_secret"]

    def make_proof(transcript_hash: bytes) -> bytes:
        return hmac.new(secret, transcript_hash, hashlib.sha256).digest()

    session = None
    last_reason = "team_join_no_address"
    for address in payload["addresses"]:
        try:
            session = transport.dial(address, env_id, invite_proof=make_proof)
            dialed_address = address
            break
        except (SessionClosed, HandshakeFailed) as exc:
            last_reason = getattr(exc, "reason", None) or str(exc) or last_reason
            continue
    if session is None:
        raise StateError("team_join_failed", last_reason)
    if session.peer.fingerprint != payload["inviter"]:
        session.close()
        raise StateError("team_join_wrong_peer")
    team_sync.adopt_outbound_session(env_id, session, dialed_address)

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if team_sync.is_active_member(env_id, device.fingerprint):
            break
        time.sleep(0.05)
    else:
        raise StateError("team_join_timeout")

    try:
        ctx.audit.record("team_join", caller="admin", result="ok",
                         extra={"env_id": env_id, "fingerprint": payload["inviter"]})
    except Exception:
        pass
    return {"env_id": env_id, "self_fingerprint": device.fingerprint, "inviter_fingerprint": payload["inviter"],
            "project": proj, "environment": envr}


# ---------------------------------------------------------------- remove + rotate
def remove_member(ctx: Any, team_sync: Any, env_id: str, fingerprint: str) -> dict[str, Any]:
    """``team remove`` (section 4.4): publish a ``member_removed`` fact, then -- only when the
    caller is admin and the removed device is not the caller's own -- rotate the DEK to a fresh
    generation wrapping every remaining active member's device, flag the environment's active
    secrets ``rotation_recommended``, and write an alert.
    """
    device = DeviceKey.load_or_create(ctx.state, ctx.kms)
    doc = team_sync.document(env_id) if team_sync is not None else load_environment(ctx, env_id).document
    if doc.get("owner") is None:
        raise NotFound("team_env_not_found")
    caller_fp = device.fingerprint
    caller_is_self = fingerprint == caller_fp
    caller_is_admin = _is_admin(doc, caller_fp)

    fact = author_fact(ctx, team_sync, env_id, "member_removed", fingerprint=fingerprint)

    rotated_generation = None
    if caller_is_admin and not caller_is_self:
        rotated_generation = _rotate_dek(ctx, team_sync, env_id)
        _flag_rotation_recommended(ctx, team_sync, env_id)
    try:
        ctx.audit.record("team_member_remove", caller="admin", result="ok",
                         extra={"env_id": env_id, "fingerprint": fingerprint})
    except Exception:
        pass
    return {"env_id": env_id, "fingerprint": fingerprint, "fact": fact,
            "dek_rotated": rotated_generation is not None, "new_generation": rotated_generation}


def _rotate_dek(ctx: Any, team_sync: Any, env_id: str) -> str:
    doc = team_sync.document(env_id) if team_sync is not None else load_environment(ctx, env_id).document
    new_dek = secrets.token_bytes(32)
    generation_id = secrets.token_hex(16)
    wraps: dict[str, Any] = {}
    for fp, member in doc.get("members", {}).items():
        if member.get("status") != "active":
            continue
        try:
            record = DeviceRecord.from_dict(member["device"])
        except InvalidInput:
            continue
        wraps[fp] = envelope.wrap_dek(new_dek, env_id, generation_id, record)
    op = {"op": "dek.rotate", "generation_id": generation_id, "wraps": wraps}
    author_commit(ctx, team_sync, env_id, [op])
    try:
        ctx.audit.record("team_dek_rotate", caller="admin", result="ok",
                         extra={"env_id": env_id, "count": len(wraps)})
    except Exception:
        pass
    return generation_id


def _flag_rotation_recommended(ctx: Any, team_sync: Any, env_id: str) -> None:
    """Node-local marker (section 4.4): every active secret of this environment needs a
    provider-side credential replacement.  Never replicated -- each admin node writes its own copy
    and its own alert, mirroring the existing local ``alerts``/audit posture."""
    document = team_sync.document(env_id) if team_sync is not None else load_environment(ctx, env_id).document
    secret_ids = sorted(document.get("secrets", {}).keys())
    with ctx.state.lock():
        flags = ctx.state.read_json(_rotation_flags_path(env_id), {}) or {}
        for secret_id in secret_ids:
            flags[secret_id] = {"reason": "member_removed_rotation_recommended", "flagged_at": iso(ctx.clock())}
        ctx.state.write_json(_rotation_flags_path(env_id), flags)
    try:
        ctx.audit.record("team_dek_rotate", caller="admin", result="ok", reason="member_removed_rotation_recommended",
                         extra={"env_id": env_id, "count": len(secret_ids)})
    except Exception:
        pass


# --------------------------------------------------------------------------- share
def share_environment(ctx: Any, team_sync: Any, project: str, environment: str, owner_name: str,
                      admin_passphrase: str) -> dict[str, Any]:
    """``team share`` (section 12): promote an existing local project/environment to a shared one.

    Requires a fresh administrator re-authentication (the same re-auth every
    other sensitive local admin action uses).  Refuses if this
    project/environment is already shared.  Every pre-existing local secret
    that has at least one active/staged version is re-emitted as commits
    against the new environment; a connection is converted alongside it only
    if its ``secret_id`` is one of those secrets -- a connection whose secret
    was never carried over (a cross-project reference, or a secret with only
    retired/revoked versions) is left exactly as it was, plain and local, and
    is reported back in ``not_shared`` rather than being silently disabled by
    ``derive_local``'s "vanished shared connection" rule (which would
    otherwise fire once such a connection's ``secret_id`` fails
    ``connection.create``'s ``secret_not_found`` fold-time check).  Converted
    entries are re-tagged ``shared_env`` *before* the first fold so
    ``derive_local``'s ``local_id_conflict`` guard recognizes them as this
    environment's own rather than skipping them as a collision.

    Every version is decrypted/re-encrypted and every commit op is built
    *before* anything on disk is touched; the retag-and-commit sequence that
    follows runs inside one ``ctx.state.lock()`` so a failure during that
    compute phase (a corrupt version, an unreadable secret) leaves local
    state completely untouched.
    """
    ctx.admin.verify(admin_passphrase)  # AuthFailed propagates untouched on a wrong passphrase
    ctx.projects.require_environment(project, environment)

    for entry in env_mapping(ctx.state).values():
        if entry.get("project") == project and entry.get("environment") == environment:
            raise InvalidInput("team_env_already_shared")
    vault_doc = ctx.state.read_json(VAULT_DOC, {}) or {}
    secrets_doc = vault_doc.get("secrets") or {}
    for entry in secrets_doc.values():
        if entry.get("project") == project and entry.get("environment") == environment and entry.get("shared_env"):
            raise InvalidInput("team_env_already_shared")

    device = DeviceKey.load_or_create(ctx.state, ctx.kms)
    env_id = C.new_env_id(device.fingerprint)
    generation_id = secrets.token_hex(16)
    dek = secrets.token_bytes(32)
    wraps = {device.fingerprint: envelope.wrap_dek(dek, env_id, generation_id, device.record)}
    init_op = {"op": "env.init", "owner_device": device.record.to_dict(), "owner_name": owner_name,
              "generation_id": generation_id, "wraps": wraps}

    # ---- pure computation phase: reads and crypto only, no write to disk yet.
    shareable: dict[str, dict] = {}  # secret_id -> its (pre-tag) vault entry, for secrets actually going
    for secret_id, entry in secrets_doc.items():
        if entry.get("project") != project or entry.get("environment") != environment or entry.get("shared_env"):
            continue
        if any(v.get("status") in ("active", "staged") for v in entry.get("versions", {}).values()):
            shareable[secret_id] = entry

    version_id_by_secret: dict[str, dict[int, str]] = {}
    ops_per_secret: dict[str, list[dict]] = {}
    for secret_id, entry in shareable.items():
        version_id_by_secret[secret_id] = {}
        ops: list[dict] = []
        for version_number, version_entry in sorted(entry["versions"].items(), key=lambda kv: int(kv[0])):
            if version_entry.get("status") not in ("active", "staged"):
                continue  # retired/revoked local versions are not carried into the shared history
            value = ctx.vault.secret_for_trusted_use(secret_id, int(version_number))
            version_id = secrets.token_hex(8)
            ciphertext = envelope.encrypt_secret(dek, env_id, secret_id, version_id, value)
            ops.append({"op": "secret.put_version", "secret_id": secret_id, "kind": entry["kind"],
                       "generation_id": generation_id, "version_id": version_id, "ciphertext": ciphertext,
                       "public": dict(version_entry.get("public") or {})})
            version_id_by_secret[secret_id][int(version_number)] = version_id
            if entry.get("active_version") == int(version_number):
                ops.append({"op": "secret.activate", "secret_id": secret_id, "version_id": version_id})
        ops_per_secret[secret_id] = ops

    connections_doc = ctx.state.read_json(P.CONNECTIONS, {}) or {}
    not_shared: list[dict[str, str]] = []
    connection_ops: dict[str, dict] = {}
    for conn_id, entry in connections_doc.items():
        if entry.get("project") != project or entry.get("environment") != environment or entry.get("shared_env"):
            continue
        if entry.get("secret_id") not in shareable:
            not_shared.append({"connection": conn_id, "reason": "secret_not_shared"})
            continue
        fields = {k: v for k, v in entry.items()
                 if k not in ("id", "policy_version", "status", "created_at", "updated_at", "shared_env")}
        raw_version = fields.get("secret_version")
        if raw_version is not None:
            fields["secret_version"] = version_id_by_secret.get(fields["secret_id"], {}).get(raw_version)
        connection_ops[conn_id] = {"op": "connection.create", "id": conn_id, **fields}

    # ---- mutation phase: everything above succeeded; retag + commit atomically under one lock.
    with ctx.state.lock():
        _retag_local_secrets(ctx, project, environment, env_id, only_ids=set(shareable))
        connections_to_share = _retag_local_connections(ctx, project, environment, env_id,
                                                        only_ids=set(connection_ops))
        for conn_id, _entry in connections_to_share:
            _force_grant_reevaluation_for_share(ctx, conn_id)

        if team_sync is not None:
            team_sync.register_env(env_id)
        author_commit(ctx, team_sync, env_id, [init_op])
        for secret_id in shareable:
            for op in ops_per_secret.get(secret_id, []):
                author_commit(ctx, team_sync, env_id, [op])
        for op in connection_ops.values():
            author_commit(ctx, team_sync, env_id, [op])

        set_env_mapping(ctx.state, env_id, project, environment)
    try:
        ctx.audit.record("team_share", caller="admin", result="ok",
                         extra={"env_id": env_id, "project": project, "environment": environment,
                                "count": len(not_shared)})
    except Exception:
        pass
    return {"env_id": env_id, "not_shared": not_shared}


def _retag_local_secrets(ctx: Any, project: str, environment: str, env_id: str,
                         only_ids: set[str]) -> list[tuple[str, dict]]:
    """Tag exactly ``only_ids`` (secrets ``share_environment`` already decided are going -- at
    least one active/staged version) with ``shared_env``; every other local secret of this
    project/environment, if any, is left untouched."""
    with ctx.state.lock():
        doc = ctx.state.read_json(VAULT_DOC, {}) or {}
        secrets_doc = doc.get("secrets", {})
        matched: list[tuple[str, dict]] = []
        for secret_id, entry in secrets_doc.items():
            if secret_id not in only_ids:
                continue
            if entry.get("project") == project and entry.get("environment") == environment and not entry.get("shared_env"):
                entry["shared_env"] = env_id
                matched.append((secret_id, copy.deepcopy(entry)))
        if matched:
            ctx.state.write_json(VAULT_DOC, doc)
    return matched


def _retag_local_connections(ctx: Any, project: str, environment: str, env_id: str,
                             only_ids: set[str]) -> list[tuple[str, dict]]:
    """Tag exactly ``only_ids`` (connections ``share_environment`` already decided reference a
    secret that IS going) with ``shared_env``; a connection referencing an unshared secret is
    never in ``only_ids`` and is left exactly as it was -- plain, local, and active."""
    with ctx.state.lock():
        doc = ctx.state.read_json(P.CONNECTIONS, {}) or {}
        matched: list[tuple[str, dict]] = []
        for conn_id, entry in doc.items():
            if conn_id not in only_ids:
                continue
            if entry.get("project") == project and entry.get("environment") == environment and not entry.get("shared_env"):
                entry["shared_env"] = env_id
                matched.append((conn_id, copy.deepcopy(entry)))
        if matched:
            ctx.state.write_json(P.CONNECTIONS, doc)
    return matched


def _force_grant_reevaluation_for_share(ctx: Any, conn_id: str) -> None:
    """Treat local -> shared as a widening change for grant purposes (docs/team-sync.md sections
    3.1/6.5 only describe a *later* effective-definition change bumping the policy version, but
    converting a purely local connection into a commit-derived one changes its trust boundary just
    as fundamentally: the credential now flows through environment-DEK wraps every team device
    holds, not this node's private local DEK alone.  So existing grants are re-evaluated exactly as
    if the definition had widened, never silently carried over unexamined -- this is what the
    stage-3 test list calls "a grant on the old local connection is re-evaluated (policy_version
    bump) rather than silently kept"."""
    from .. import policy as P  # local import: avoids a module-level cycle with zeropw.policy tests

    with ctx.state.lock():
        doc = ctx.state.read_json(P.CONNECTIONS, {}) or {}
        entry = doc.get(conn_id)
        if entry is None:
            return
        entry["policy_version"] = int(entry.get("policy_version", 0)) + 1
        ctx.state.write_json(P.CONNECTIONS, doc)
        ctx.policy._reevaluate_grants(conn_id, entry["policy_version"], True, None)
        ctx.policy._invalidate_approvals(lambda e, cid=conn_id: e.get("connection") == cid, "policy_changed")
