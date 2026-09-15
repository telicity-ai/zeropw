"""Deterministic total-order fold into an environment document, plus
derivation into node-local policy/vault state (docs/team-sync.md sections
5.1, 7.2, 7.3, 7.4, 6.5).

``fold()`` applies every known commit, in the total order of section 7.1, to
build the environment document of section 5.1.  State-dependent checks
(author role, target existence, ...) happen here, one commit at a time, in
order; an op that fails one is *skipped*, never aborts the fold.  Facts
(section 7.4: connection disabled, secret version revoked, member removed)
are a second, order-independent input that is consulted throughout the fold
and re-applied once more at the end, so they always win regardless of where
in the total order the corresponding commit (if any) falls.

``derive_local()`` then writes the parts of the document this node cares
about into its own ``policy/connections.json`` and ``vault/secrets.json``,
tagged ``shared_env``, reusing ``Policy._widens`` / ``_reevaluate_grants`` /
``_invalidate_approvals`` for exactly the same policy-version-bump and
stale/re-evaluate rules a local connection change gets (section 3.1, 6.5).
It is idempotent and recomputed from scratch on every call: a hand-edited
derived entry is simply overwritten on the next fold.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Iterable

from .. import policy as P
from ..errors import InvalidInput
from ..store import StateDir, iso
from ..vault import VAULT_DOC
from . import envelope
from .commit import Commit, Hlc, env_owner_fingerprint, sort_total_order
from .identity import DeviceKey, DeviceRecord

ENV_FORMAT = "zeropw-team-env-v1"
DEFAULT_SYNC_INTERVAL_SECONDS = 10


# ------------------------------------------------------------------------ facts
@dataclass
class Facts:
    """Monotone, order-independent facts (docs/team-sync.md section 7.4).

    Not derived from folding commits: a real node also learns these from
    out-of-band ``FACT`` messages (stage 2/3).  Stage 1 takes them as a plain
    argument to ``fold()`` so the "facts win regardless of order" property
    can be exercised without a transport.
    """

    disabled_connections: set[str] = field(default_factory=set)
    revoked_versions: set[tuple[str, str]] = field(default_factory=set)
    removed_members: set[str] = field(default_factory=set)
    incidents: list[dict[str, Any]] = field(default_factory=list)

    def copy(self) -> "Facts":
        return Facts(set(self.disabled_connections), set(self.revoked_versions),
                    set(self.removed_members), list(self.incidents))


# --------------------------------------------------------------------- document
def new_document(env_id: str) -> dict[str, Any]:
    return {
        "env_id": env_id, "format": ENV_FORMAT, "owner": None, "members": {},
        "dek": {"current": None, "generations": {}},
        "connections": {}, "secrets": {},
        "settings": {"sync_interval_seconds": DEFAULT_SYNC_INTERVAL_SECONDS},
    }


@dataclass
class FoldResult:
    document: dict[str, Any]
    skipped: list[tuple[str, int, str]]
    version_order: dict[str, list[str]]
    vector: dict[str, int]


def _commit_time(commit: Commit) -> str:
    wall_ms, _ = Hlc.parse(commit.hlc)
    return iso(wall_ms / 1000)


def _is_active_member(doc: dict[str, Any], fingerprint: str) -> bool:
    member = doc["members"].get(fingerprint)
    return bool(member) and member["status"] == "active"


def _is_admin(doc: dict[str, Any], fingerprint: str) -> bool:
    if not _is_active_member(doc, fingerprint):
        return False
    if fingerprint == doc["owner"]:
        return True
    return doc["members"][fingerprint]["role"] == "admin"


def _is_owner(doc: dict[str, Any], fingerprint: str) -> bool:
    return doc["owner"] == fingerprint and _is_active_member(doc, fingerprint)


# ------------------------------------------------------------- connection ops
def _connection_entry(commit_module, conn_id: str, args: dict[str, Any], status: str, timestamp: str,
                      created_at: str | None = None) -> dict[str, Any]:
    fields = commit_module.build_connection_fields(args)
    fields["id"] = conn_id
    fields["status"] = status
    fields["created_at"] = created_at or timestamp
    fields["updated_at"] = timestamp
    return fields


def _op_connection_create(doc, commit, facts, op) -> str | None:
    from . import commit as commit_module

    if not _is_admin(doc, commit.author):
        return "not_admin"
    conn_id = op["id"]
    if conn_id in doc["connections"] or conn_id in facts.disabled_connections:
        return "connection_id_taken"
    # F3: the secret must already be one of THIS document's secrets.  Without this a shared
    # connection could name a victim node's private local secret id, and derive_local's
    # id-collision guard would then be the only thing standing between an attacker's connection
    # definition and a completely unrelated local credential.
    if op["secret_id"] not in doc["secrets"]:
        return "secret_not_found"
    try:
        entry = _connection_entry(commit_module, conn_id, op, "active", _commit_time(commit))
    except InvalidInput as exc:
        return exc.reason
    doc["connections"][conn_id] = entry
    return None


def _op_connection_update(doc, commit, facts, op) -> str | None:
    from . import commit as commit_module

    if not _is_admin(doc, commit.author):
        return "not_admin"
    conn_id = op["id"]
    current = doc["connections"].get(conn_id)
    if current is None or current["status"] == "disabled" or conn_id in facts.disabled_connections:
        return "connection_not_found"
    merged = dict(current)
    for name in ("description", "http_target", "http_auth", "http_scope", "ssh_target", "cli"):
        if name in op:
            merged[name] = op[name]
    try:
        entry = _connection_entry(commit_module, conn_id, merged, current["status"], _commit_time(commit),
                                  created_at=current["created_at"])
    except InvalidInput as exc:
        return exc.reason
    doc["connections"][conn_id] = entry
    return None


def _op_connection_switch_credential(doc, commit, facts, op) -> str | None:
    if not _is_admin(doc, commit.author):
        return "not_admin"
    conn_id = op["id"]
    current = doc["connections"].get(conn_id)
    if current is None or current["status"] == "disabled" or conn_id in facts.disabled_connections:
        return "connection_not_found"
    secret_id = op.get("secret_id", current["secret_id"])
    if secret_id not in doc["secrets"]:
        return "secret_not_found"
    merged = dict(current)
    merged["secret_id"] = secret_id
    merged["secret_version"] = op.get("secret_version")
    merged["updated_at"] = _commit_time(commit)
    doc["connections"][conn_id] = merged
    return None


def _op_connection_disable(doc, commit, facts, op) -> str | None:
    if not _is_admin(doc, commit.author):
        return "not_admin"
    conn_id = op["id"]
    current = doc["connections"].get(conn_id)
    if current is None:
        return "connection_not_found"
    if current["status"] == "disabled":
        return "already_disabled"
    current["status"] = "disabled"
    current["updated_at"] = _commit_time(commit)
    facts.disabled_connections.add(conn_id)
    return None


# ------------------------------------------------------------------ secret ops
def _op_secret_put_version(doc, commit, facts, op) -> str | None:
    if not _is_admin(doc, commit.author):
        return "not_admin"
    secret_id, version_id = op["secret_id"], op["version_id"]
    # F1: a generation id this document has never seen (typo, or a node deliberately naming one
    # its peers cannot derive) must not create a version other nodes then choke on -- checked
    # before touching doc["secrets"] so a skipped op leaves no ghost secret entry behind either.
    if op["generation_id"] not in doc["dek"]["generations"]:
        return "generation_unknown"
    entry = doc["secrets"].setdefault(secret_id, {"kind": op["kind"], "active_version": None, "versions": {}})
    if entry["kind"] != op["kind"]:
        return "secret_kind_mismatch"
    if version_id in entry["versions"]:
        return "version_id_taken"
    entry["versions"][version_id] = {
        "status": "staged", "generation": op["generation_id"],
        "nonce": op["ciphertext"]["nonce"], "ciphertext": op["ciphertext"]["ciphertext"],
        "public": dict(op.get("public") or {}),
    }
    doc.setdefault("_version_order", {}).setdefault(secret_id, []).append(version_id)
    return None


def _set_secret_status(doc, facts, secret_id: str, version_id: str, status: str) -> str | None:
    entry = doc["secrets"].get(secret_id)
    version = entry["versions"].get(version_id) if entry else None
    if version is None:
        return "version_not_found"
    if version["status"] == "revoked" or (secret_id, version_id) in facts.revoked_versions:
        return "version_revoked"
    version["status"] = status
    if status == "active":
        previous = entry["active_version"]
        if previous is not None and previous != version_id and entry["versions"][previous]["status"] == "active":
            entry["versions"][previous]["status"] = "retired"
        entry["active_version"] = version_id
    elif entry["active_version"] == version_id:
        entry["active_version"] = None
    return None


def _op_secret_set_status(doc, commit, facts, op) -> str | None:
    if not _is_admin(doc, commit.author):
        return "not_admin"
    return _set_secret_status(doc, facts, op["secret_id"], op["version_id"], op["status"])


def _op_secret_activate(doc, commit, facts, op) -> str | None:
    if not _is_admin(doc, commit.author):
        return "not_admin"
    return _set_secret_status(doc, facts, op["secret_id"], op["version_id"], "active")


# ------------------------------------------------------------------ member ops
def _op_member_add(doc, commit, facts, op) -> str | None:
    if not _is_admin(doc, commit.author):
        return "not_admin"
    try:
        record = DeviceRecord.from_dict(op["device"])
    except InvalidInput:
        return "member_add_malformed"
    if not record.verify():
        return "member_add_malformed"
    fp = record.fingerprint
    if fp in facts.removed_members:
        return "member_removed"
    existing = doc["members"].get(fp)
    if existing is not None and existing["status"] == "removed":
        return "member_removed"
    if existing is not None:
        return "member_exists"
    doc["members"][fp] = {"name": op["name"], "role": op["role"], "status": "active", "device": record.to_dict()}
    return None


def _op_member_set_role(doc, commit, facts, op) -> str | None:
    if not _is_admin(doc, commit.author):
        return "not_admin"
    fp = op["fingerprint"]
    if fp == doc["owner"]:
        return "cannot_change_owner_role"
    if not _is_active_member(doc, fp):
        return "member_not_found"
    doc["members"][fp]["role"] = op["role"]
    return None


def _op_member_remove(doc, commit, facts, op) -> str | None:
    fp = op["fingerprint"]
    if not (_is_admin(doc, commit.author) or commit.author == fp):
        return "not_authorized"
    if fp == doc["owner"]:
        return "cannot_remove_owner"
    if not _is_active_member(doc, fp):
        return "member_not_found"
    doc["members"][fp]["status"] = "removed"
    facts.removed_members.add(fp)
    return None


def _op_owner_transfer(doc, commit, facts, op) -> str | None:
    if not _is_owner(doc, commit.author):
        return "not_owner"
    fp = op["fingerprint"]
    if not _is_active_member(doc, fp):
        return "member_not_found"
    doc["owner"] = fp
    doc["members"][fp]["role"] = "admin"
    return None


# --------------------------------------------------------------------- dek/settings
def _op_dek_rotate(doc, commit, facts, op) -> str | None:
    if not _is_admin(doc, commit.author):
        return "not_admin"
    gen_id = op["generation_id"]
    if gen_id in doc["dek"]["generations"]:
        return "generation_exists"
    doc["dek"]["generations"][gen_id] = {"wraps": dict(op["wraps"])}
    doc["dek"]["current"] = gen_id  # last-in-order wins (section 5.3)
    return None


def _op_settings_update(doc, commit, facts, op) -> str | None:
    if not _is_admin(doc, commit.author):
        return "not_admin"
    doc["settings"]["sync_interval_seconds"] = op["sync_interval_seconds"]
    return None


# --------------------------------------------------------------------- env.init
def _op_env_init(doc, commit, facts, op) -> str | None:
    if doc["owner"] is not None:
        return "env_already_initialized"
    if commit.author_seq != 1:
        return "env_init_not_first"
    # F2: env.init is honoured only from the fingerprint the environment id itself binds to
    # (docs/team-sync.md section 3's env id is "the owner's fingerprint + a random suffix" in
    # this implementation) -- a forged genesis from a non-owner member, whatever hlc it claims,
    # is skipped here even if it somehow reached the store (receive_commit already refuses it).
    try:
        expected_owner = env_owner_fingerprint(commit.env_id)
    except InvalidInput:
        return "env_id_malformed"
    if commit.author != expected_owner:
        return "env_init_wrong_owner"
    try:
        owner_record = DeviceRecord.from_dict(op["owner_device"])
    except InvalidInput:
        return "env_init_malformed"
    if owner_record.fingerprint != commit.author or not owner_record.verify():
        return "env_init_malformed"
    doc["owner"] = commit.author
    doc["members"][commit.author] = {"name": op["owner_name"], "role": "admin", "status": "active",
                                     "device": owner_record.to_dict()}
    doc["dek"]["current"] = op["generation_id"]
    doc["dek"]["generations"][op["generation_id"]] = {"wraps": dict(op["wraps"])}
    return None


_OP_HANDLERS: dict[str, Callable[[dict, Commit, Facts, dict], str | None]] = {
    "env.init": _op_env_init,
    "connection.create": _op_connection_create,
    "connection.update": _op_connection_update,
    "connection.switch_credential": _op_connection_switch_credential,
    "connection.disable": _op_connection_disable,
    "secret.put_version": _op_secret_put_version,
    "secret.set_status": _op_secret_set_status,
    "secret.activate": _op_secret_activate,
    "member.add": _op_member_add,
    "member.set_role": _op_member_set_role,
    "member.remove": _op_member_remove,
    "owner.transfer": _op_owner_transfer,
    "dek.rotate": _op_dek_rotate,
    "settings.update": _op_settings_update,
}


def _apply_op(doc: dict[str, Any], commit: Commit, facts: Facts, op: dict[str, Any]) -> str | None:
    handler = _OP_HANDLERS.get(op.get("op"))
    if handler is None:
        return "unknown_op"
    return handler(doc, commit, facts, op)


def _reapply_facts(doc: dict[str, Any], facts: Facts) -> None:
    """Force the monotone facts onto the fold result once more (section 7.4).

    Defends against a fact that has no corresponding commit at all in this
    fold's input (it arrived as a bare ``FACT`` in later stages, or was
    passed in directly by a test) -- the loop above only catches facts that
    line up with an op it actually processed.
    """
    for conn_id in facts.disabled_connections:
        entry = doc["connections"].get(conn_id)
        if entry is not None:
            entry["status"] = "disabled"
    for secret_id, version_id in facts.revoked_versions:
        entry = doc["secrets"].get(secret_id)
        version = entry["versions"].get(version_id) if entry else None
        if version is not None:
            version["status"] = "revoked"
            if entry["active_version"] == version_id:
                entry["active_version"] = None
    for fp in facts.removed_members:
        member = doc["members"].get(fp)
        if member is not None:
            member["status"] = "removed"


def fold(env_id: str, commits: Iterable[Commit], facts: Facts | None = None, *,
         base_document: dict[str, Any] | None = None,
         base_version_order: dict[str, list[str]] | None = None,
         audit: Any = None) -> FoldResult:
    """Fold ``commits`` (any arrival order) into the environment document (section 7.2).

    Deterministic: the same commit set always yields byte-identical output
    (as JSON), whatever order the commits are passed in, because they are
    always re-sorted into the total order of section 7.1 before anything is
    applied.  ``base_document`` / ``base_version_order`` let a snapshot
    (``save_snapshot`` / ``load_snapshot``) seed the fold instead of starting
    from an empty environment; the caller is responsible for only passing
    commits that are not already reflected in the snapshot.
    """
    doc = copy.deepcopy(base_document) if base_document is not None else new_document(env_id)
    doc.setdefault("_version_order", {k: list(v) for k, v in (base_version_order or {}).items()})
    working_facts = facts.copy() if facts is not None else Facts()
    skipped: list[tuple[str, int, str]] = []
    ordered = sort_total_order(c for c in commits if c.env_id == env_id)
    for commit in ordered:
        for index, op in enumerate(commit.ops):
            reason = _apply_op(doc, commit, working_facts, op)
            if reason:
                skipped.append((commit.hash, index, reason))
                if audit is not None:
                    audit.record("team_op_skipped", result="skipped", reason=reason,
                                 extra={"env_id": env_id, "fingerprint": commit.author,
                                        "author_seq": commit.author_seq, "op": str(op.get("op", ""))[:64]})
    _reapply_facts(doc, working_facts)
    version_order = doc.pop("_version_order")
    vector: dict[str, int] = {}
    for commit in ordered:
        vector[commit.author] = max(vector.get(commit.author, 0), commit.author_seq)
    return FoldResult(document=doc, skipped=skipped, version_order=version_order, vector=vector)


# --------------------------------------------------------------------- snapshots
def _snapshot_dir(env_id: str) -> str:
    return f"team/{env_id}/snapshots"


def save_snapshot(state: StateDir, env_id: str, number: int, result: FoldResult) -> None:
    state.write_json(f"{_snapshot_dir(env_id)}/{number}.json",
                     {"document": result.document, "version_order": result.version_order, "vector": result.vector})


def load_latest_snapshot(state: StateDir, env_id: str) -> dict[str, Any] | None:
    directory = state.path / _snapshot_dir(env_id)
    if not directory.is_dir():
        return None
    numbers = sorted((int(p.stem) for p in directory.glob("*.json") if p.stem.isdigit()), reverse=True)
    if not numbers:
        return None
    return state.read_json(f"{_snapshot_dir(env_id)}/{numbers[0]}.json", None)


def fold_with_snapshot(env_id: str, all_commits: Iterable[Commit], state: StateDir,
                       facts: Facts | None = None, audit: Any = None) -> FoldResult:
    """Fold using the latest snapshot as a base, applying only later commits.

    Only correct when no commit older (in total order) than the snapshot's
    vector has newly appeared -- exactly the condition ``team compact``
    (stage 3, out of scope here) is responsible for guaranteeing before it
    ever deletes history.  A caller that suspects a late-arriving commit
    should call ``fold()`` directly instead.
    """
    snapshot = load_latest_snapshot(state, env_id)
    if snapshot is None:
        return fold(env_id, all_commits, facts, audit=audit)
    base_vector = snapshot.get("vector") or {}
    later = [c for c in all_commits if c.author_seq > base_vector.get(c.author, 0)]
    return fold(env_id, later, facts, base_document=snapshot.get("document"),
               base_version_order=snapshot.get("version_order"), audit=audit)


# --------------------------------------------------------------------- derive
def _document_connection_object(entry: dict[str, Any], secret_version: int | None) -> P.Connection:
    data = dict(entry)
    data["policy_version"] = 0
    data["secret_version"] = secret_version
    return P.Connection.from_dict(data)


def _connection_changed(before: P.Connection, after: P.Connection) -> bool:
    fields = ("project", "environment", "service", "kind", "secret_id", "secret_version", "description",
             "http_target", "http_auth", "http_scope", "ssh_target", "cli", "status")
    return tuple(getattr(before, f) for f in fields) != tuple(getattr(after, f) for f in fields)


def _derive_connections(document: dict[str, Any], state: StateDir, env_id: str,
                        version_index: dict[str, dict[str, int]], policy: Any, audit: Any) -> None:
    local = state.read_json(P.CONNECTIONS, {}) or {}
    now_iso = iso()
    for conn_id, entry in document["connections"].items():
        existing_raw = local.get(conn_id)
        # F3: never let a shared connection overwrite a pre-existing LOCAL entry (or one derived
        # from a *different* shared environment) that merely happens to share this id -- that
        # would let one environment's connection definition redirect a victim's id to an
        # attacker-controlled target/credential.
        if existing_raw and existing_raw.get("shared_env") != env_id:
            if audit is not None:
                audit.record("team_op_skipped", result="skipped", reason="local_id_conflict",
                             extra={"env_id": env_id, "detail": "connection"})
            continue
        secret_id = entry["secret_id"]
        raw_version = entry.get("secret_version")
        local_version = version_index.get(secret_id, {}).get(raw_version) if raw_version is not None else None
        after = _document_connection_object(entry, local_version)
        if existing_raw:
            before = P.Connection.from_dict(existing_raw)
            if _connection_changed(before, after):
                widened = P.Policy._widens(before, after) or (after.status == "disabled"
                                                               and before.status == "active")
                new_version = before.policy_version + 1
                after = replace(after, policy_version=new_version, updated_at=now_iso, created_at=before.created_at)
                policy._reevaluate_grants(conn_id, new_version, widened, local_version)
                policy._invalidate_approvals(
                    lambda e, cid=conn_id: e.get("connection") == cid,
                    "connection_disabled" if after.status == "disabled" else "policy_changed")
            else:
                after = replace(after, policy_version=before.policy_version, created_at=before.created_at,
                                updated_at=before.updated_at)
        else:
            after = replace(after, policy_version=1, created_at=entry.get("created_at", now_iso), updated_at=now_iso)
        raw = after.to_dict()
        raw["shared_env"] = env_id
        local[conn_id] = raw
    state.write_json(P.CONNECTIONS, local)


def _derive_vault(document: dict[str, Any], state: StateDir, env_id: str,
                  version_index: dict[str, dict[str, int]], audit: Any, *,
                  project: str | None, environment: str | None) -> None:
    doc = state.read_json(VAULT_DOC, None)
    if not doc:
        return  # local vault not initialized; nothing to derive into
    # F7: must satisfy projects.NAME_RE (no ":") so secret list --project and friends work on
    # derived entries; stage 3's `team share`/`team join` will pass real project/environment names.
    project = project or f"shared-{env_id.split('-', 1)[-1][:8]}"
    environment = environment or "shared"
    secrets_doc = doc.setdefault("secrets", {})
    for secret_id, entry in document["secrets"].items():
        existing = secrets_doc.get(secret_id)
        # F3: same id-collision guard as connections -- never clobber a local secret, or one
        # derived from a different shared environment, that happens to share this id.
        if existing and existing.get("shared_env") != env_id:
            if audit is not None:
                audit.record("team_op_skipped", result="skipped", reason="local_id_conflict",
                             extra={"env_id": env_id, "secret_id": secret_id})
            continue
        vindex = version_index.get(secret_id, {})
        local_versions: dict[str, Any] = {}
        for version_id, record in entry["versions"].items():
            local_number = vindex.get(version_id)
            if local_number is None:
                continue
            # F1: only a version whose generation this node has actually unwrapped (a local
            # generation-key file exists) is written locally.  ``derive_local`` runs DEK
            # derivation before this function specifically so that check is meaningful here --
            # a version under a generation this node has no wrap for (an admin's dek.rotate that
            # omitted it, or one it just has not derived yet) is left out entirely rather than
            # written with no way to ever decrypt it, which is what previously let one bad shared
            # version take down every `exec` on the node via `values_for_trusted_scan`.
            if not state.exists(f"team/{env_id}/dek/{record['generation']}.json"):
                if audit is not None:
                    audit.record("team_op_skipped", result="skipped", reason="generation_unavailable",
                                 extra={"env_id": env_id, "secret_id": secret_id})
                continue
            local_versions[str(local_number)] = {
                "nonce": record["nonce"], "ciphertext": record["ciphertext"],
                "created_at": secrets_doc.get(secret_id, {}).get("versions", {}).get(str(local_number), {})
                                       .get("created_at", iso()),
                "status": record["status"], "public": dict(record.get("public") or {}),
                "shared_env": env_id, "generation": record["generation"], "version_id": version_id,
            }
        active_version_id = entry.get("active_version")
        active_number = vindex.get(active_version_id) if active_version_id else None
        # The active version's generation may itself be unavailable to this node: fall back to
        # "no active version" (secret_for_trusted_use then raises NotFound) rather than pointing
        # active_version at an int that was left out of `versions` above.
        if active_number is not None and str(active_number) not in local_versions:
            active_number = None
        secrets_doc[secret_id] = {
            "project": project, "environment": environment, "kind": entry["kind"],
            "created_at": secrets_doc.get(secret_id, {}).get("created_at", iso()),
            "active_version": active_number, "versions": local_versions, "shared_env": env_id,
        }
    state.write_json(VAULT_DOC, doc)


def _derive_dek_generations(document: dict[str, Any], state: StateDir, kms: Any, device: DeviceKey,
                            env_id: str) -> None:
    fp = device.fingerprint
    for gen_id, generation in document["dek"]["generations"].items():
        wraps = generation.get("wraps", {})
        my_wrap = wraps.get(fp)
        if my_wrap is None:
            continue
        local_path = f"team/{env_id}/dek/{gen_id}.json"
        if state.exists(local_path):
            continue
        try:
            dek = envelope.unwrap_dek(my_wrap, env_id, gen_id, device)
        except InvalidInput:
            continue
        state.write_json(local_path, kms.wrap(dek).to_dict())


def derive_local(fold_result: FoldResult, state: StateDir, vault: Any, policy: Any, audit: Any = None, *,
                 device: DeviceKey | None = None, project: str | None = None,
                 environment: str | None = None) -> dict[str, dict[str, int]]:
    """Write this node's derived connections/vault entries for one shared environment (section 6.5).

    Always recomputed from ``fold_result.document`` in fold order; never
    reads back anything it wrote on a previous call except to decide whether
    a connection's *effective* definition changed (for the policy-version
    bump and stale/re-evaluate decision).  Returns the
    ``{secret_id: {version_id: local_int}}`` map used to translate document
    version ids into the node-local integer versions ``Vault``/``Connection``
    already use everywhere else.
    """
    document = fold_result.document
    env_id = document["env_id"]
    version_index = {sid: {vid: i + 1 for i, vid in enumerate(order)}
                     for sid, order in fold_result.version_order.items()}
    with state.lock():
        # F1: derive this node's local copies of every DEK generation it can unwrap BEFORE
        # deriving vault entries, so _derive_vault can tell (by the presence of that file) which
        # shared secret versions it is actually able to decrypt.
        if device is not None and vault is not None:
            _derive_dek_generations(document, state, vault.kms, device, env_id)
        _derive_vault(document, state, env_id, version_index, audit, project=project, environment=environment)
        _derive_connections(document, state, env_id, version_index, policy, audit)
    if audit is not None:
        # F6: count commits folded, not ops skipped (which get their own team_op_skipped records).
        audit.record("team_commit_apply", result="ok",
                     extra={"env_id": env_id, "count": sum(fold_result.vector.values())})
    return version_index
