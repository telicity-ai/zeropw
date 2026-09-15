"""Commit model: signing, format validation, hybrid logical clock, per-author
commit store (docs/team-sync.md sections 5.2-5.4).

A commit is one node's signed batch of operations against a shared
environment.  This module covers everything that is true of a commit on its
own, independent of the rest of the environment's history:

* ``Hlc`` -- the hybrid logical clock used to give every commit a total
  order (section 5.2, section 7.1).
* ``Commit`` -- the canonical-JSON shape, its hash, and Ed25519
  sign/verify (section 5.2).
* ``validate_ops`` -- format-only validation of every operation shape
  (section 5.3, section 5.4 point 4).  State-dependent checks (role,
  target existence, ...) are done during folding (``zeropw/team/fold.py``,
  section 7.2), not here.
* ``CommitStore`` -- the on-disk, per-author-sequence commit log, plus the
  deferred-commit holding area for clock-skewed commits (section 5.4 point 3).
* ``receive_commit`` -- the section 5.4 receipt pipeline: signature,
  sequence and clock checks, in that order, before a commit is trusted
  enough to fold.

Version identifiers (docs/team-sync.md section 5.1 says a secret version id
"is the hash of the commit that added it") are, in this implementation, a
random 128-bit hex token chosen by the writer and carried in the
``secret.put_version`` op itself, not literally recomputed from the finished
commit hash.  The literal reading is circular: the op's ciphertext is
encrypted with an AAD that includes the version id (section 4.2), but the
commit hash is a SHA-256 of the whole commit including that op, so the id
cannot be both an input to the ciphertext and a function of it.  The token is
authenticated by the same commit signature as everything else, is unique per
commit (``fold.py`` rejects reuse), and is exposed to the rest of the system
exactly like the spec's "version id" -- this is a deliberate, documented
resolution of that ambiguity, not an oversight.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass, replace
from typing import Any, Callable, Iterable

from .. import policy as P
from ..crypto import ed25519
from ..errors import InvalidInput
from ..projects import validate_name
from ..store import StateDir
from ..vault import SECRET_KINDS
from .identity import DeviceKey, DeviceRecord

COMMIT_FORMAT = "zeropw-team-commit-v1"

MAX_CLOCK_SKEW_MS = 5 * 60 * 1000  # docs/team-sync.md section 5.4 point 3 / section 14 item 1
MAX_NAME_LENGTH = 200  # docs/team-sync.md section 6.3: same bound as the audit log

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_FINGERPRINT_RE = re.compile(r"^[a-z2-7]{26}$")
_TOKEN_RE = re.compile(r"^[0-9a-f]{16,64}$")

_TEAM_ROOT = "team"

# Environment id = "<owner fingerprint>-<32 hex random chars>" (fix for F2: binding the id to
# the genesis author closes the "any member forges hlc=0 + env.init and becomes owner
# everywhere" hijack -- env.init is only ever honoured from the one fingerprint the id itself
# names, so a forged bootstrap is rejected/skipped regardless of what hlc it claims).
ENV_ID_RANDOM_HEX_LEN = 32
_ENV_ID_RE = re.compile(rf"^([a-z2-7]{{26}})-([0-9a-f]{{{ENV_ID_RANDOM_HEX_LEN}}})$")


def new_env_id(owner_fingerprint: str) -> str:
    if not _valid_fingerprint(owner_fingerprint):
        raise InvalidInput("invalid_fingerprint")
    return f"{owner_fingerprint}-{secrets.token_hex(ENV_ID_RANDOM_HEX_LEN // 2)}"


def env_owner_fingerprint(env_id: Any) -> str:
    """The fingerprint bound into ``env_id`` at creation, or ``InvalidInput`` if malformed."""
    if not isinstance(env_id, str):
        raise InvalidInput("invalid_env_id")
    match = _ENV_ID_RE.fullmatch(env_id)
    if not match:
        raise InvalidInput("invalid_env_id")
    return match.group(1)


def valid_env_id(env_id: Any) -> bool:
    return isinstance(env_id, str) and bool(_ENV_ID_RE.fullmatch(env_id))


def _env_root(env_id: str) -> str:
    return f"{_TEAM_ROOT}/{env_id}"


# ------------------------------------------------------------------------ HLC
@dataclass
class Hlc:
    """Hybrid logical clock (docs/team-sync.md section 5.2).

    ``tick`` is called when this node authors a new commit; ``observe`` is
    called whenever a commit (local or remote) with a given ``hlc`` string is
    learned about, so a later ``tick`` always sorts after everything this
    node has seen.  The rendered form is ``"<wall_ms>-<counter:04d>"``; total
    order (section 7.1) compares the *parsed* ``(wall_ms, counter)`` pair,
    not the string, since a wall-clock component can exceed 9999 and would
    then sort incorrectly as text.
    """

    wall_ms: int = 0
    counter: int = 0

    @staticmethod
    def parse(value: str) -> tuple[int, int]:
        try:
            wall_str, counter_str = value.split("-")
            wall_ms, counter = int(wall_str), int(counter_str)
        except (ValueError, AttributeError) as exc:
            raise InvalidInput("hlc_malformed") from exc
        if wall_ms < 0 or counter < 0:
            raise InvalidInput("hlc_malformed")
        return wall_ms, counter

    def render(self) -> str:
        return f"{self.wall_ms}-{self.counter:04d}"

    def observe(self, remote: str) -> None:
        """Raise this clock to at least ``remote`` (section 5.2: "받을 때마다 자기 시계를 그 값 이상으로 올린다")."""
        remote_wall, remote_counter = self.parse(remote)
        if remote_wall > self.wall_ms:
            self.wall_ms, self.counter = remote_wall, remote_counter
        elif remote_wall == self.wall_ms:
            self.counter = max(self.counter, remote_counter)
        # remote_wall < self.wall_ms: this clock is already ahead; leave it.

    def tick(self, now_ms: int | None = None) -> str:
        """Advance the clock for a new local commit and return its rendered ``hlc``."""
        now_ms = int(time.time() * 1000) if now_ms is None else now_ms
        candidate = max(now_ms, self.wall_ms)
        if candidate > self.wall_ms:
            self.wall_ms, self.counter = candidate, 0
        else:
            self.counter += 1
        return self.render()


def now_ms(clock: Callable[[], float] = time.time) -> int:
    return int(clock() * 1000)


def order_key(commit: "Commit") -> tuple[int, int, str]:
    """Total order key (docs/team-sync.md section 7.1): (hlc, author) as a numeric/text tuple."""
    wall_ms, counter = Hlc.parse(commit.hlc)
    return wall_ms, counter, commit.author


def sort_total_order(commits: Iterable["Commit"]) -> list["Commit"]:
    return sorted(commits, key=order_key)


# --------------------------------------------------------------------- Commit
@dataclass(frozen=True)
class Commit:
    format: str
    env_id: str
    author: str
    author_seq: int
    hlc: str
    seen: dict[str, int]
    ops: tuple[dict[str, Any], ...]
    sig: str  # base64 Ed25519 signature, empty until signed

    def _canonical_dict(self, include_sig: bool) -> dict[str, Any]:
        data = {
            "format": self.format,
            "env_id": self.env_id,
            "author": self.author,
            "author_seq": self.author_seq,
            "hlc": self.hlc,
            "seen": dict(sorted(self.seen.items())),
            "ops": [dict(op) for op in self.ops],
        }
        if include_sig:
            data["sig"] = self.sig
        return data

    def canonical_json(self, include_sig: bool) -> bytes:
        return json.dumps(self._canonical_dict(include_sig), sort_keys=True, separators=(",", ":")).encode("utf-8")

    @property
    def hash(self) -> str:
        """SHA-256 hex of the canonical JSON *including* ``sig`` (section 5.2)."""
        return hashlib.sha256(self.canonical_json(True)).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return self._canonical_dict(True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Commit":
        try:
            ops = tuple(dict(op) for op in data["ops"])
            return cls(
                format=str(data["format"]), env_id=str(data["env_id"]), author=str(data["author"]),
                author_seq=int(data["author_seq"]), hlc=str(data["hlc"]),
                seen={str(k): int(v) for k, v in dict(data.get("seen") or {}).items()},
                ops=ops, sig=str(data["sig"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidInput("commit_malformed") from exc


def sign_commit(device: DeviceKey, env_id: str, author_seq: int, hlc: str, seen: dict[str, int],
                ops: list[dict[str, Any]]) -> Commit:
    """Build, format-validate and sign a new commit (docs/team-sync.md section 5.2)."""
    validate_ops(ops)
    unsigned = Commit(COMMIT_FORMAT, env_id, device.fingerprint, author_seq, hlc, dict(seen), tuple(ops), "")
    sig = base64.b64encode(device.sign(unsigned.canonical_json(False))).decode("ascii")
    return replace(unsigned, sig=sig)


def verify_commit(commit: Commit, author_record: DeviceRecord) -> bool:
    """True iff ``commit`` is well-formed and validly signed by ``author_record``.  Never raises."""
    if commit.format != COMMIT_FORMAT:
        return False
    if author_record.fingerprint != commit.author:
        return False
    try:
        sig = base64.b64decode(commit.sig, validate=True)
        Hlc.parse(commit.hlc)
        validate_ops(commit.ops)
    except (InvalidInput, ValueError, TypeError, binascii.Error):
        return False
    return ed25519.verify(author_record.sign_pub, commit.canonical_json(False), sig)


# ------------------------------------------------------------------- op shapes
def _valid_name_field(value: Any, max_len: int = MAX_NAME_LENGTH) -> bool:
    return isinstance(value, str) and 0 < len(value) <= max_len and not _CONTROL_RE.search(value)


def _valid_fingerprint(value: Any) -> bool:
    return isinstance(value, str) and bool(_FINGERPRINT_RE.fullmatch(value))


def _valid_token(value: Any) -> bool:
    return isinstance(value, str) and bool(_TOKEN_RE.fullmatch(value))


def _valid_wrap(value: Any) -> bool:
    return isinstance(value, dict) and all(isinstance(value.get(k), str) for k in ("eph_pub", "nonce", "ciphertext"))


def _valid_wraps(value: Any) -> bool:
    return isinstance(value, dict) and bool(value) and all(
        _valid_fingerprint(fp) and _valid_wrap(wrap) for fp, wrap in value.items()
    )


def _build_http_target(value: Any) -> P.HttpTarget | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise InvalidInput("invalid_http_target")
    try:
        return P.HttpTarget(scheme=value["scheme"], host=value["host"], port=value["port"],
                            ca_file=value.get("ca_file"), allow_private_network=value.get("allow_private_network", False))
    except KeyError as exc:
        raise InvalidInput("invalid_http_target") from exc


def _build_http_auth(value: Any) -> P.HttpAuth | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise InvalidInput("invalid_http_auth")
    try:
        return P.HttpAuth(mode=value["mode"], header_name=value.get("header_name"),
                          value_prefix=value.get("value_prefix"), basic_username=value.get("basic_username"))
    except KeyError as exc:
        raise InvalidInput("invalid_http_auth") from exc


def _build_http_scope(value: Any) -> P.HttpScope | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise InvalidInput("invalid_http_scope")
    try:
        return P.HttpScope(
            methods=tuple(value["methods"]) if value.get("methods") is not None else None,
            path_prefixes=tuple(value["path_prefixes"]) if value.get("path_prefixes") is not None else None,
            confirm_methods=tuple(value.get("confirm_methods") or ()),
        )
    except (KeyError, TypeError) as exc:
        raise InvalidInput("invalid_http_scope") from exc


def _build_ssh_target(value: Any) -> P.SshTarget | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise InvalidInput("invalid_ssh_target")
    try:
        return P.SshTarget(host=value["host"], port=value["port"], username=value["username"],
                           host_keys=tuple(value["host_keys"]))
    except (KeyError, TypeError) as exc:
        raise InvalidInput("invalid_ssh_target") from exc


def _build_cli_profile(value: Any) -> P.CliProfile | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise InvalidInput("invalid_cli_profile")
    try:
        return P.CliProfile(program=value["program"], kind=value["kind"],
                            base_url_env=value.get("base_url_env", "ZEROPW_API_BASE_URL"),
                            extra_env=dict(value.get("extra_env") or {}))
    except (KeyError, TypeError) as exc:
        raise InvalidInput("invalid_cli_profile") from exc


def build_connection_fields(args: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize connection.create/connection.update args.

    Reuses the existing policy dataclasses (``HttpTarget``, ``HttpAuth``,
    ``HttpScope``, ``SshTarget``, ``CliProfile``) for every nested shape, so
    a shared-environment connection is held to exactly the same format rules
    as a local one (docs/team-sync.md section 5.4 point 4).  Returns a plain
    dict shaped like ``Connection.to_dict()`` minus ``id``, ``policy_version``,
    ``status`` and the timestamps -- the caller fills those in.
    """
    kind = args.get("kind")
    if kind not in P.CONNECTION_KINDS:
        raise InvalidInput("invalid_connection_kind")
    project = validate_name(args.get("project", ""), "project")
    environment = validate_name(args.get("environment", ""), "environment")
    service = args.get("service")
    if not _valid_name_field(service, 200):
        raise InvalidInput("invalid_service")
    secret_id = validate_name(args.get("secret_id", ""), "secret_id")
    secret_version = args.get("secret_version")
    if secret_version is not None and not isinstance(secret_version, str):
        raise InvalidInput("invalid_secret_version")
    description = args.get("description", "")
    if not isinstance(description, str) or len(description) > MAX_NAME_LENGTH or _CONTROL_RE.search(description):
        raise InvalidInput("invalid_description")
    http_target = _build_http_target(args.get("http_target"))
    http_auth = _build_http_auth(args.get("http_auth"))
    http_scope = _build_http_scope(args.get("http_scope"))
    ssh_target = _build_ssh_target(args.get("ssh_target"))
    cli = _build_cli_profile(args.get("cli"))
    if kind == "http" and not (http_target and http_auth and http_scope):
        raise InvalidInput("http_connection_incomplete")
    if kind == "ssh" and not ssh_target:
        raise InvalidInput("ssh_connection_incomplete")
    if cli and cli.kind != kind:
        raise InvalidInput("cli_kind_mismatch")
    connection = P.Connection(
        id="placeholder", project=project, environment=environment, service=service, kind=kind,
        secret_id=secret_id, secret_version=secret_version, description=description,
        http_target=http_target, http_auth=http_auth, http_scope=http_scope,
        ssh_target=ssh_target, cli=cli, policy_version=0, status="active", created_at="", updated_at="",
    )
    data = connection.to_dict()
    for key in ("id", "policy_version", "status", "created_at", "updated_at"):
        data.pop(key, None)
    return data


# ------------------------------------------------------------- op validators
def _validate_connection_create(op: dict[str, Any]) -> None:
    if not _valid_name_field(op.get("id"), 64):
        raise InvalidInput("invalid_connection_id")
    build_connection_fields(op)


_CONNECTION_UPDATE_FIELDS = frozenset({"description", "http_target", "http_auth", "http_scope", "ssh_target", "cli"})


def _validate_connection_update(op: dict[str, Any]) -> None:
    if not _valid_name_field(op.get("id"), 64):
        raise InvalidInput("invalid_connection_id")
    extra = set(op) - _CONNECTION_UPDATE_FIELDS - {"op", "id"}
    if extra:
        raise InvalidInput("connection_update_field_not_allowed")
    if not (set(op) & _CONNECTION_UPDATE_FIELDS):
        raise InvalidInput("connection_update_empty")
    if "http_target" in op and op["http_target"] is not None:
        _build_http_target(op["http_target"])
    if "http_auth" in op and op["http_auth"] is not None:
        _build_http_auth(op["http_auth"])
    if "http_scope" in op and op["http_scope"] is not None:
        _build_http_scope(op["http_scope"])
    if "ssh_target" in op and op["ssh_target"] is not None:
        _build_ssh_target(op["ssh_target"])
    if "cli" in op and op["cli"] is not None:
        _build_cli_profile(op["cli"])
    if "description" in op and (not isinstance(op["description"], str) or len(op["description"]) > MAX_NAME_LENGTH
                                or _CONTROL_RE.search(op["description"])):
        raise InvalidInput("invalid_description")


def _validate_connection_switch_credential(op: dict[str, Any]) -> None:
    if not _valid_name_field(op.get("id"), 64):
        raise InvalidInput("invalid_connection_id")
    if "secret_id" in op and not _valid_name_field(op["secret_id"], 64):
        raise InvalidInput("invalid_secret_id")
    if op.get("secret_version") is not None and not isinstance(op.get("secret_version"), str):
        raise InvalidInput("invalid_secret_version")


def _validate_connection_disable(op: dict[str, Any]) -> None:
    if not _valid_name_field(op.get("id"), 64):
        raise InvalidInput("invalid_connection_id")


def _validate_secret_put_version(op: dict[str, Any]) -> None:
    if not _valid_name_field(op.get("secret_id"), 64):
        raise InvalidInput("invalid_secret_id")
    if op.get("kind") not in SECRET_KINDS:
        raise InvalidInput("invalid_secret_kind")
    if not _valid_token(op.get("generation_id")):
        raise InvalidInput("invalid_generation_id")
    if not _valid_token(op.get("version_id")):
        raise InvalidInput("invalid_version_id")
    ciphertext = op.get("ciphertext")
    if not isinstance(ciphertext, dict) or not isinstance(ciphertext.get("nonce"), str) \
            or not isinstance(ciphertext.get("ciphertext"), str):
        raise InvalidInput("invalid_ciphertext")
    public = op.get("public", {})
    if not isinstance(public, dict):
        raise InvalidInput("invalid_public_metadata")


def _validate_secret_set_status(op: dict[str, Any]) -> None:
    if not _valid_name_field(op.get("secret_id"), 64):
        raise InvalidInput("invalid_secret_id")
    if not _valid_token(op.get("version_id")):
        raise InvalidInput("invalid_version_id")
    if op.get("status") not in ("active", "retired"):
        raise InvalidInput("invalid_version_status")


def _validate_secret_activate(op: dict[str, Any]) -> None:
    if not _valid_name_field(op.get("secret_id"), 64):
        raise InvalidInput("invalid_secret_id")
    if not _valid_token(op.get("version_id")):
        raise InvalidInput("invalid_version_id")


def _validate_member_add(op: dict[str, Any]) -> None:
    device = op.get("device")
    if not isinstance(device, dict):
        raise InvalidInput("invalid_device_record")
    DeviceRecord.from_dict(device)
    if not _valid_name_field(op.get("name"), 200):
        raise InvalidInput("invalid_member_name")
    if op.get("role") not in ("admin", "user"):
        raise InvalidInput("invalid_role")


def _validate_member_set_role(op: dict[str, Any]) -> None:
    if not _valid_fingerprint(op.get("fingerprint")):
        raise InvalidInput("invalid_fingerprint")
    if op.get("role") not in ("admin", "user"):
        raise InvalidInput("invalid_role")


def _validate_member_remove(op: dict[str, Any]) -> None:
    if not _valid_fingerprint(op.get("fingerprint")):
        raise InvalidInput("invalid_fingerprint")


def _validate_owner_transfer(op: dict[str, Any]) -> None:
    if not _valid_fingerprint(op.get("fingerprint")):
        raise InvalidInput("invalid_fingerprint")


def _validate_dek_rotate(op: dict[str, Any]) -> None:
    if not _valid_token(op.get("generation_id")):
        raise InvalidInput("invalid_generation_id")
    if not _valid_wraps(op.get("wraps")):
        raise InvalidInput("invalid_wraps")


def _validate_settings_update(op: dict[str, Any]) -> None:
    value = op.get("sync_interval_seconds")
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise InvalidInput("invalid_settings")


def _validate_env_init(op: dict[str, Any]) -> None:
    device = op.get("owner_device")
    if not isinstance(device, dict):
        raise InvalidInput("invalid_device_record")
    DeviceRecord.from_dict(device)
    if not _valid_name_field(op.get("owner_name"), 200):
        raise InvalidInput("invalid_member_name")
    if not _valid_token(op.get("generation_id")):
        raise InvalidInput("invalid_generation_id")
    if not _valid_wraps(op.get("wraps")):
        raise InvalidInput("invalid_wraps")


OP_VALIDATORS: dict[str, Callable[[dict[str, Any]], None]] = {
    "env.init": _validate_env_init,
    "connection.create": _validate_connection_create,
    "connection.update": _validate_connection_update,
    "connection.switch_credential": _validate_connection_switch_credential,
    "connection.disable": _validate_connection_disable,
    "secret.put_version": _validate_secret_put_version,
    "secret.set_status": _validate_secret_set_status,
    "secret.activate": _validate_secret_activate,
    "member.add": _validate_member_add,
    "member.set_role": _validate_member_set_role,
    "member.remove": _validate_member_remove,
    "owner.transfer": _validate_owner_transfer,
    "dek.rotate": _validate_dek_rotate,
    "settings.update": _validate_settings_update,
}


def validate_op(op: Any) -> None:
    if not isinstance(op, dict):
        raise InvalidInput("op_malformed")
    name = op.get("op")
    validator = OP_VALIDATORS.get(name) if isinstance(name, str) else None
    if validator is None:
        raise InvalidInput("op_unknown")
    validator(op)


def validate_ops(ops: Any) -> None:
    if not isinstance(ops, (list, tuple)) or not ops:
        raise InvalidInput("ops_empty")
    for op in ops:
        validate_op(op)


# --------------------------------------------------------------- CommitStore
class CommitStore:
    """The per-author-sequence commit log for one shared environment (section 5.2, 5.4)."""

    def __init__(self, state: StateDir, env_id: str) -> None:
        self.state = state
        self.env_id = env_id
        self.root = _env_root(env_id)

    def _commit_path(self, fingerprint: str, seq: int) -> str:
        return f"{self.root}/commits/{fingerprint}/{seq}.json"

    def vector(self) -> dict[str, int]:
        """Version vector: fingerprint -> highest ``author_seq`` stored (section 6.3)."""
        result: dict[str, int] = {}
        commits_dir = self.state.path / self.root / "commits"
        if not commits_dir.is_dir():
            return result
        for device_dir in sorted(p for p in commits_dir.iterdir() if p.is_dir()):
            seqs = [int(f.stem) for f in device_dir.glob("*.json") if f.stem.isdigit()]
            if seqs:
                result[device_dir.name] = max(seqs)
        return result

    def last_seq(self, fingerprint: str) -> int:
        return self.vector().get(fingerprint, 0)

    def append(self, commit: Commit) -> None:
        """Store a commit, enforcing contiguous per-author sequence (no gaps, no duplicates)."""
        if commit.env_id != self.env_id:
            raise InvalidInput("team_env_id_mismatch")
        last = self.last_seq(commit.author)
        if commit.author_seq <= last:
            raise InvalidInput("team_seq_duplicate")
        if commit.author_seq > last + 1:
            raise InvalidInput("team_seq_gap")
        self.state.write_json(self._commit_path(commit.author, commit.author_seq), commit.to_dict())

    def get(self, fingerprint: str, seq: int) -> Commit | None:
        data = self.state.read_json(self._commit_path(fingerprint, seq), None)
        return Commit.from_dict(data) if data else None

    def all_commits(self) -> list[Commit]:
        commits: list[Commit] = []
        for fingerprint, last in self.vector().items():
            for seq in range(1, last + 1):
                commit = self.get(fingerprint, seq)
                if commit is not None:
                    commits.append(commit)
        return sort_total_order(commits)

    # -------------------------------------------------------- reject / defer
    def reject(self, commit: Commit, reason: str) -> None:
        path = f"{self.root}/rejected/{commit.author}-{commit.author_seq:010d}-{commit.hash[:12]}.json"
        self.state.write_json(path, {**commit.to_dict(), "rejected_reason": reason})

    def _deferred_path(self, commit: Commit) -> str:
        return f"{self.root}/deferred/{commit.author}-{commit.author_seq:010d}.json"

    def defer(self, commit: Commit) -> None:
        self.state.write_json(self._deferred_path(commit), commit.to_dict())

    def deferred_commits(self) -> list[Commit]:
        deferred_dir = self.state.path / self.root / "deferred"
        if not deferred_dir.is_dir():
            return []
        commits = []
        for path in sorted(deferred_dir.glob("*.json")):
            data = self.state.read_json(f"{self.root}/deferred/{path.name}", None)
            if data:
                commits.append(Commit.from_dict(data))
        return commits

    def release_deferred(self, now_ms_value: int) -> list[Commit]:
        """Move every deferred commit whose wall clock is no longer too far ahead into the store.

        Docs/team-sync.md section 5.4 point 3: a commit whose ``hlc`` wall
        clock is more than ``MAX_CLOCK_SKEW_MS`` ahead of this node's clock is
        held here instead of applied, so a node with a fast clock cannot
        always win.  Returns the commits that were released, in the order
        they were appended to the store (which enforces per-author sequence
        again -- a still-out-of-sequence commit stays deferred).
        """
        released: list[Commit] = []
        for commit in self.deferred_commits():
            wall_ms, _ = Hlc.parse(commit.hlc)
            if wall_ms > now_ms_value + MAX_CLOCK_SKEW_MS:
                continue
            path = self._deferred_path(commit)
            try:
                self.append(commit)
            except InvalidInput:
                continue  # still out of sequence; leave it deferred
            target = self.state.path / path
            try:
                target.unlink()
            except OSError:
                pass
            released.append(commit)
        return released


# ------------------------------------------------------------- receipt pipeline
def _device_registry(commits: Iterable[Commit]) -> dict[str, DeviceRecord]:
    """Every device record announced so far, keyed by fingerprint (for signature checks only).

    Built from ``env.init`` and ``member.add`` ops in already-accepted
    commits.  Membership *status* and *role* are not consulted here -- that
    is a fold-time (section 7.2), not a receipt-time (section 5.4), decision.
    A record whose self-signature does not verify is never registered.
    """
    registry: dict[str, DeviceRecord] = {}
    for commit in commits:
        for op in commit.ops:
            record_dict = None
            if op.get("op") == "env.init":
                record_dict = op.get("owner_device")
            elif op.get("op") == "member.add":
                record_dict = op.get("device")
            if not isinstance(record_dict, dict):
                continue
            try:
                record = DeviceRecord.from_dict(record_dict)
            except InvalidInput:
                continue
            if record.verify():
                registry.setdefault(record.fingerprint, record)
    return registry


def receive_commit(store: CommitStore, commit: Commit, now_ms_value: int, audit: Any = None) -> str:
    """Validate and store one incoming commit (docs/team-sync.md section 5.4).

    Checks, in order: env id, op format, bootstrap-owner binding, signature
    (using either the already-known device registry or -- for the very
    first, bootstrapping commit -- the record embedded in its own
    ``env.init`` op), duplicate/equivocation, per-author HLC monotonicity,
    clock skew, and per-author sequence.  Returns one of ``"accepted"``,
    ``"deferred"``, ``"duplicate"`` or ``"rejected"``.

    A structural failure is recorded to ``team/<env-id>/rejected/`` and
    audited as ``team_commit_rejected``; that author's later commits are
    then refused too, by the ordinary sequence check.  A commit that exactly
    repeats one already stored (gossip re-delivery: same author, same
    sequence, same hash) is silently a ``"duplicate"`` -- not an error, not
    audited.  A commit that claims an already-used (author, sequence) slot
    with *different* content is equivocation by that author and is rejected
    with the distinct, audited reason ``team_author_equivocation``.
    """

    def _reject(reason: str) -> str:
        store.reject(commit, reason)
        if audit is not None:
            audit.record("team_commit_rejected", result="denied", reason=reason,
                         extra={"env_id": commit.env_id, "fingerprint": commit.author,
                                "author_seq": commit.author_seq})
        return "rejected"

    if commit.format != COMMIT_FORMAT:
        return _reject("team_format_unknown")
    if commit.env_id != store.env_id:
        return _reject("team_env_id_mismatch")
    try:
        validate_ops(commit.ops)
    except InvalidInput as exc:
        return _reject(f"team_op_format_{exc.reason}")

    is_bootstrap = commit.author_seq == 1 and bool(commit.ops) and commit.ops[0].get("op") == "env.init"
    if is_bootstrap:
        # F2: env.init is only ever honoured from the fingerprint the env id itself names, so a
        # forged early bootstrap from any other member cannot become "the" genesis on any node.
        try:
            expected_owner = env_owner_fingerprint(commit.env_id)
        except InvalidInput:
            return _reject("team_env_id_malformed")
        if commit.author != expected_owner:
            return _reject("team_bootstrap_wrong_owner")

    existing = store.all_commits()
    registry = _device_registry(existing)
    if is_bootstrap and commit.author not in registry:
        try:
            owner_record = DeviceRecord.from_dict(commit.ops[0]["owner_device"])
        except InvalidInput:
            return _reject("team_bootstrap_malformed")
        if owner_record.fingerprint != commit.author or not owner_record.verify():
            return _reject("team_bootstrap_malformed")
        registry[commit.author] = owner_record

    record = registry.get(commit.author)
    if record is None:
        return _reject("team_author_unknown")
    if not verify_commit(commit, record):
        return _reject("team_signature_invalid")

    # F4: gossip naturally re-delivers commits.  An exact repeat of an already-stored (author,
    # seq) is not an error; a *different* commit claiming the same slot is equivocation.
    last_seq = store.last_seq(commit.author)
    if commit.author_seq <= last_seq:
        previously_stored = store.get(commit.author, commit.author_seq)
        if previously_stored is not None and previously_stored.hash == commit.hash:
            return "duplicate"
        return _reject("team_author_equivocation")

    # F2: per-author HLC must strictly increase commit-to-commit, independent of wall clock.
    if commit.author_seq > 1:
        previous = store.get(commit.author, commit.author_seq - 1)
        if previous is not None and Hlc.parse(commit.hlc) <= Hlc.parse(previous.hlc):
            return _reject("team_hlc_not_monotone")

    wall_ms, _ = Hlc.parse(commit.hlc)
    if wall_ms > now_ms_value + MAX_CLOCK_SKEW_MS:
        store.defer(commit)
        return "deferred"

    try:
        store.append(commit)
    except InvalidInput as exc:
        return _reject(exc.reason)
    return "accepted"
