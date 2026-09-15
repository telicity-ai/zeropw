"""Connections, principals, grants, approvals and global stop.  Default deny.

Model (docs/security-design.md §3, §5):

* A *principal* is an agent identity.  It authenticates to the tools API with
  its own random token (never a vault value).
* A *connection* binds a service, a vault credential (id + optional pinned
  version), a fixed target, the authentication profile the gateway or signer
  applies, and the scope the user allows (methods / path prefixes for HTTP,
  username for SSH).  Scope is configured once per connection; individual
  operations are never registered.
* A *grant* gives one principal use of one connection with expiry and an
  optional usage cap.  It records the connection's policy version at grant
  time.  Changes that could widen what the connection allows (target, auth
  mode, broader scope) make existing grants ``stale`` so nothing inherits a
  broader permission automatically; narrowing changes and credential
  rotation re-evaluate grants in place.  A grant also records the credential
  version it resolves to; when a different vault version becomes the one an
  unpinned connection uses, the connection's policy version is bumped (so
  earlier handles stop working) and its grants are re-evaluated in place.
* ``stop_all`` refuses every new relay, signature and execution until
  ``resume``.  ``restore_pending`` does the same after a backup restore until
  the administrator acknowledges the latest revocation state.
* ``consume`` is the authoritative last-moment decision: under the state lock
  it re-checks restore-pending, global stop, principal, connection, grant,
  the operation's scope and that the policy version is still the one the
  caller evaluated, then counts one use.
* Every revocation (grant revoke, principal/connection disable, secret
  version revoke) is also appended to ``policy/revocations.jsonl``, which is
  not part of a backup, so a restore can re-apply it.
* Risky methods can require a one-shot approval bound to a digest of the
  caller, connection, method, path and body, and to the grant and connection
  policy version in use.  Approvals expire, are invalidated by revocation or
  policy changes, and a used or dead approval starts a new cycle instead of
  blocking the request forever.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import secrets
import threading
import time
import uuid
from dataclasses import InitVar, asdict, dataclass, field, replace
from typing import Any, Callable, Iterable

from .errors import AuthFailed, InvalidInput, NotFound, PolicyDenied, StateError
from .projects import validate_name
from .store import StateDir, iso

PRINCIPALS = "policy/principals.json"
CONNECTIONS = "policy/connections.json"
GRANTS = "policy/grants.json"
CONTROL = "policy/control.json"
REVOCATIONS = "policy/revocations.jsonl"
VAULT_SECRETS = "vault/secrets.json"   # read for version metadata only (no ciphertext is touched)
APPROVAL_TTL_SECONDS = 15 * 60
APPROVAL_HISTORY_LIMIT = 256
_EVALUATED_MEMO_LIMIT = 64
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_SSH_USERNAME_RE = re.compile(r"[a-z_][a-z0-9_.-]{0,31}")

HTTP_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
AUTH_MODES = ("bearer", "basic", "header")
CONNECTION_KINDS = ("http", "ssh")
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
FORBIDDEN_CUSTOM_HEADERS = {"host", "content-length", "transfer-encoding", "connection", "cookie",
                            "proxy-authorization", "location"}
MAX_GRANT_TTL = 30 * 86400


# --------------------------------------------------------------------- models
def _validate_host(host: str) -> str:
    if not isinstance(host, str):
        raise InvalidInput("invalid_host")
    lowered = host.strip().lower()
    try:
        ipaddress.ip_address(lowered)
        return lowered
    except ValueError:
        pass
    if not HOST_RE.match(lowered):
        raise InvalidInput("invalid_host")
    return lowered


def _validate_port(port: Any) -> int:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise InvalidInput("invalid_port")
    return port


# Addresses that must never receive a relayed credential, whatever the connection says:
# link-local ranges (where cloud instance metadata services live) and the metadata and
# credential endpoints that some providers expose outside link-local space.
NEVER_TARGET_NETWORKS = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("100.100.100.200/32"),      # Alibaba Cloud metadata
    ipaddress.ip_network("168.63.129.16/32"),        # Azure platform endpoint (WireServer)
    ipaddress.ip_network("fd00:ec2::/64"),           # AWS IPv6 services: IMDS ::254, EKS Pod Identity ::23, ...
    ipaddress.ip_network("fd20:ce::254/128"),        # Google Cloud metadata server over IPv6
    ipaddress.ip_network("fd00:c1::a9fe:a9fe/128"),  # Oracle Cloud IMDS over IPv6
)

# IPv6 forms that deliver to an IPv4 address carried inside them.
_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")      # RFC 6052: IPv4 address in the last 32 bits
_NAT64_LOCAL_USE = ipaddress.ip_network("64:ff9b:1::/48")     # RFC 8215: RFC 6052 layout chosen by the operator
_IPV4_COMPATIBLE = ipaddress.ip_network("::/96")              # RFC 4291 (deprecated)
_IPV4_TRANSLATED = ipaddress.ip_network("::ffff:0:0:0/96")    # SIIT, RFC 2765

_Address = ipaddress.IPv4Address | ipaddress.IPv6Address


def _normalized_address(address: _Address) -> _Address:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _embedded_ipv4(address: _Address) -> tuple[tuple[ipaddress.IPv4Address, ...], tuple[ipaddress.IPv4Address, ...]]:
    """IPv4 addresses a translator or tunnel delivers a packet for ``address`` to.

    Returns ``(exact, possible)``.  ``exact`` addresses are fixed by the IPv6
    form: the well-known NAT64 prefix, IPv4-compatible and SIIT addresses, 6to4
    and Teredo (server and client).  ``possible`` lists every RFC 6052 layout
    of the local-use NAT64 prefix, whose prefix length only the operator knows.
    """
    if not isinstance(address, ipaddress.IPv6Address):
        return (), ()
    value = int(address)
    low32 = ipaddress.IPv4Address(value & 0xFFFFFFFF)
    exact: list[ipaddress.IPv4Address] = []
    if address in _NAT64_WELL_KNOWN or address in _IPV4_TRANSLATED or (address in _IPV4_COMPATIBLE and value > 1):
        exact.append(low32)                      # "::" and "::1" are the unspecified and loopback addresses
    if address.sixtofour is not None:
        exact.append(address.sixtofour)
    if address.teredo is not None:
        exact.extend(address.teredo)
    possible: tuple[ipaddress.IPv4Address, ...] = ()
    if address in _NAT64_LOCAL_USE:
        possible = (
            ipaddress.IPv4Address(((value >> 64) & 0xFFFF) << 16 | ((value >> 40) & 0xFFFF)),   # /48
            ipaddress.IPv4Address(((value >> 64) & 0xFF) << 24 | ((value >> 32) & 0xFFFFFF)),   # /56
            ipaddress.IPv4Address((value >> 24) & 0xFFFFFFFF),                                  # /64
            low32,                                                                              # /96
        )
    return tuple(exact), possible


def address_block_reason(address: _Address, allow_private_network: bool) -> str | None:
    """Why a relayed credential must not be sent to ``address``, or ``None``.

    Metadata and link-local addresses are always refused.  Every other
    non-public address (loopback, RFC 1918, unique-local, site-local,
    carrier-grade NAT, reserved, documentation, unspecified, multicast) is
    refused unless the connection explicitly allows private networks.

    An IPv6 address that carries an IPv4 address (NAT64, IPv4-compatible,
    SIIT, 6to4, Teredo) is judged by that IPv4 address as well, so a DNS answer
    such as ``64:ff9b::169.254.169.254`` cannot reach metadata or internal IPv4
    space through a translator.  The well-known NAT64 prefix is reserved IPv6
    space that reaches whatever public IPv4 address it embeds, so only its
    embedded address decides there.
    """
    address = _normalized_address(address)
    exact, possible = _embedded_ipv4(address)
    for candidate in (address, *exact, *possible):
        if any(candidate in network for network in NEVER_TARGET_NETWORKS):
            return "metadata_address_not_allowed"
    if any(candidate.is_unspecified or candidate.is_multicast for candidate in (address, *exact)):
        return "target_address_not_allowed"
    if not allow_private_network:
        special = address.is_reserved or getattr(address, "is_site_local", False)
        if not address.is_global or (special and address not in _NAT64_WELL_KNOWN):
            return "target_address_not_allowed"
        if any(not candidate.is_global or candidate.is_reserved for candidate in exact):
            return "target_address_not_allowed"
    return None


@dataclass(frozen=True)
class HttpTarget:
    """Fixed relay destination.

    An IP literal is an explicit administrator choice and cannot be changed by
    DNS, so only metadata/link-local (and unspecified/multicast) literals are
    refused, including those embedded in an IPv6 literal.  A host name is
    resolved by the gateway for every request; the resolved addresses must be
    public unless ``allow_private_network`` is set (an internal service), and
    the connection is made to the address that was checked.

    ``check_address=False`` is only for loading stored documents: a record
    saved before a literal became forbidden must still load, so the
    administrator can list and disable it.  The relay refuses (and audits) such
    a target at use time, and ``Policy.create_connection`` /
    ``update_connection`` re-check every new target.
    """

    scheme: str
    host: str
    port: int
    ca_file: str | None = None
    allow_private_network: bool = False
    check_address: InitVar[bool] = True

    def __post_init__(self, check_address: bool) -> None:
        if self.scheme not in ("http", "https"):
            raise InvalidInput("invalid_scheme")
        object.__setattr__(self, "host", _validate_host(self.host))
        _validate_port(self.port)
        if not isinstance(self.allow_private_network, bool):
            raise InvalidInput("invalid_allow_private_network")
        if check_address:
            self.require_allowed_literal()

    def literal_block_reason(self) -> str | None:
        """Why this target's IP literal may never receive a credential, or ``None`` (also for host names)."""
        try:
            literal = ipaddress.ip_address(self.host)
        except ValueError:
            return None
        return address_block_reason(literal, allow_private_network=True)

    def require_allowed_literal(self) -> None:
        reason = self.literal_block_reason()
        if reason is not None:
            raise InvalidInput(reason)

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


@dataclass(frozen=True)
class HttpAuth:
    mode: str
    header_name: str | None = None
    value_prefix: str | None = None
    basic_username: str | None = None

    def __post_init__(self) -> None:
        if self.mode not in AUTH_MODES:
            raise InvalidInput("unsupported_auth_mode")
        if self.mode == "header":
            if not self.header_name or not HEADER_NAME_RE.match(self.header_name):
                raise InvalidInput("invalid_header_name")
            if self.header_name.lower() in FORBIDDEN_CUSTOM_HEADERS:
                raise InvalidInput("invalid_header_name")
        if self.mode == "basic" and (not self.basic_username or ":" in self.basic_username):
            raise InvalidInput("invalid_basic_username")


@dataclass(frozen=True)
class HttpScope:
    methods: tuple[str, ...] | None = None          # None = every method
    path_prefixes: tuple[str, ...] | None = None    # None = every path
    confirm_methods: tuple[str, ...] = ()           # risky methods needing one-shot approval

    def __post_init__(self) -> None:
        for group in (self.methods, self.confirm_methods):
            if group is None:
                continue
            for method in group:
                if method not in HTTP_METHODS:
                    raise InvalidInput("invalid_method")
        if self.path_prefixes is not None:
            if not self.path_prefixes:
                raise InvalidInput("empty_path_prefixes")
            for prefix in self.path_prefixes:
                if not prefix.startswith("/") or ".." in prefix or "?" in prefix:
                    raise InvalidInput("invalid_path_prefix")

    def allows_method(self, method: str) -> bool:
        return self.methods is None or method in self.methods

    def allows_path(self, path: str) -> bool:
        if self.path_prefixes is None:
            return True
        return any(path == p or path.startswith(p.rstrip("/") + "/") or (p.endswith("/") and path.startswith(p))
                   for p in self.path_prefixes)

    def widens(self, other: "HttpScope") -> bool:
        """True when ``other`` allows something this scope did not."""
        if other.methods is None and self.methods is not None:
            return True
        if other.methods is not None and self.methods is not None and set(other.methods) - set(self.methods):
            return True
        if other.path_prefixes is None and self.path_prefixes is not None:
            return True
        if other.path_prefixes is not None and self.path_prefixes is not None:
            for prefix in other.path_prefixes:
                if not self.allows_path(prefix):
                    return True
        if set(self.confirm_methods) - set(other.confirm_methods):
            return True
        return False


@dataclass(frozen=True)
class SshTarget:
    host: str
    port: int
    username: str
    host_keys: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "host", _validate_host(self.host))
        _validate_port(self.port)
        # fullmatch, not ``^...$``: ``$`` also matches before a trailing newline ("deploy\n").
        if not isinstance(self.username, str) or not _SSH_USERNAME_RE.fullmatch(self.username):
            raise InvalidInput("invalid_ssh_username")
        if isinstance(self.host_keys, (str, bytes)) or not self.host_keys:
            raise InvalidInput("ssh_host_keys_required")
        object.__setattr__(self, "host_keys", tuple(_canonical_host_key(line) for line in self.host_keys))


def _canonical_host_key(line: Any) -> str:
    """One canonical ``ssh-ed25519 <base64> [comment]`` line, or ``InvalidInput``.

    The stored value is written verbatim into a run's ``known_hosts``; a line
    carrying a newline (or any other control character) would add a second,
    unrelated trust entry there.  The line is parsed exactly like the admin
    CLI does and re-serialised, so policy state can only ever hold one key
    per line.
    """
    if not isinstance(line, str) or not line.startswith("ssh-ed25519 "):
        raise InvalidInput("unsupported_host_key")
    if _CONTROL_CHARS_RE.search(line):
        raise InvalidInput("invalid_host_key")
    from . import sshwire  # lazy: pure-Python key parsing

    try:
        entry = sshwire.parse_authorized_key_entry(line)
        if entry.options:
            raise InvalidInput("invalid_host_key")
        return entry.key.to_authorized_key(entry.comment)
    except (sshwire.WireError, ValueError) as exc:
        raise InvalidInput("invalid_host_key") from exc


@dataclass(frozen=True)
class CliProfile:
    """How a supported CLI is pointed at the gateway or signer without secrets."""

    program: str
    kind: str
    base_url_env: str = "ZEROPW_API_BASE_URL"
    extra_env: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in CONNECTION_KINDS:
            raise InvalidInput("invalid_cli_kind")
        if not self.program or "\x00" in self.program:
            raise InvalidInput("invalid_cli_program")
        if not re.match(r"^[A-Z][A-Z0-9_]{0,63}$", self.base_url_env):
            raise InvalidInput("invalid_env_name")
        for key, value in self.extra_env.items():
            if not re.match(r"^[A-Z][A-Z0-9_]{0,63}$", key) or key in ("SSH_AUTH_SOCK", self.base_url_env):
                raise InvalidInput("invalid_env_name")
            if not isinstance(value, str) or "\x00" in value:
                raise InvalidInput("invalid_env_value")


@dataclass(frozen=True)
class Connection:
    id: str
    project: str
    environment: str
    service: str
    kind: str
    secret_id: str
    secret_version: int | None
    description: str
    http_target: HttpTarget | None
    http_auth: HttpAuth | None
    http_scope: HttpScope | None
    ssh_target: SshTarget | None
    cli: CliProfile | None
    policy_version: int
    status: str
    created_at: str
    updated_at: str

    def __post_init__(self) -> None:
        validate_name(self.id, "connection_id")
        if self.kind not in CONNECTION_KINDS:
            raise InvalidInput("invalid_connection_kind")
        if self.kind == "http" and not (self.http_target and self.http_auth and self.http_scope):
            raise InvalidInput("http_connection_incomplete")
        if self.kind == "ssh" and not self.ssh_target:
            raise InvalidInput("ssh_connection_incomplete")
        if self.cli and self.cli.kind != self.kind:
            raise InvalidInput("cli_kind_mismatch")
        if self.status not in ("active", "disabled"):
            raise InvalidInput("invalid_status")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Connection":
        def build(model: type, value: Any) -> Any:
            if value is None:
                return None
            if model is HttpScope:
                return HttpScope(
                    tuple(value["methods"]) if value.get("methods") is not None else None,
                    tuple(value["path_prefixes"]) if value.get("path_prefixes") is not None else None,
                    tuple(value.get("confirm_methods") or ()),
                )
            if model is SshTarget:
                return SshTarget(value["host"], value["port"], value["username"], tuple(value["host_keys"]))
            if model is CliProfile:
                return CliProfile(value["program"], value["kind"], value.get("base_url_env", "ZEROPW_API_BASE_URL"),
                                  dict(value.get("extra_env") or {}))
            if model is HttpTarget:
                # A stored literal that is forbidden now still loads (so it can be listed and
                # disabled); the relay refuses it before any use, approval or credential is spent.
                return HttpTarget(**value, check_address=False)
            return model(**value)

        return cls(
            id=data["id"], project=data["project"], environment=data["environment"], service=data["service"],
            kind=data["kind"], secret_id=data["secret_id"], secret_version=data.get("secret_version"),
            description=data.get("description", ""),
            http_target=build(HttpTarget, data.get("http_target")),
            http_auth=build(HttpAuth, data.get("http_auth")),
            http_scope=build(HttpScope, data.get("http_scope")),
            ssh_target=build(SshTarget, data.get("ssh_target")),
            cli=build(CliProfile, data.get("cli")),
            policy_version=int(data["policy_version"]), status=data["status"],
            created_at=data["created_at"], updated_at=data["updated_at"],
        )

    def public_view(self) -> dict[str, Any]:
        """What an agent may see: no secret ids, no internal file paths."""
        view: dict[str, Any] = {
            "id": self.id, "project": self.project, "environment": self.environment,
            "service": self.service, "kind": self.kind, "description": self.description,
            "policy_version": self.policy_version,
            "cli": {"program": self.cli.program} if self.cli else None,
        }
        if self.kind == "http" and self.http_target and self.http_scope and self.http_auth:
            view["target"] = {"scheme": self.http_target.scheme, "host": self.http_target.host,
                              "port": self.http_target.port}
            view["auth_mode"] = self.http_auth.mode
            view["scope"] = {"methods": list(self.http_scope.methods) if self.http_scope.methods else "all",
                             "path_prefixes": list(self.http_scope.path_prefixes) if self.http_scope.path_prefixes else "all",
                             "confirm_methods": list(self.http_scope.confirm_methods)}
        if self.kind == "ssh" and self.ssh_target:
            view["target"] = {"host": self.ssh_target.host, "port": self.ssh_target.port,
                              "username": self.ssh_target.username}
            view["auth_mode"] = "ssh-ed25519-signature"
        return view


@dataclass(frozen=True)
class Principal:
    id: str
    token_hash: str
    status: str
    created_at: str


@dataclass(frozen=True)
class Grant:
    id: str
    principal: str
    connection: str
    policy_version: int
    expires_at: float | None
    max_uses: int | None
    uses: int
    status: str
    created_at: str
    revoked_at: str | None = None
    credential_version: int | None = None   # vault version the connection resolved to when last evaluated

    def public_view(self) -> dict[str, Any]:
        return {
            "id": self.id, "connection": self.connection, "status": self.status,
            "expires_at": iso(self.expires_at) if self.expires_at else None,
            "remaining_uses": (self.max_uses - self.uses) if self.max_uses is not None else None,
        }


@dataclass(frozen=True)
class Action:
    kind: str
    method: str | None = None
    path: str | None = None
    username: str | None = None


@dataclass
class Decision:
    allowed: bool
    reason: str
    grant: Grant | None = None
    connection: Connection | None = None

    @property
    def policy_version(self) -> int | None:
        return self.connection.policy_version if self.connection else None

    def require(self) -> "Decision":
        if not self.allowed:
            raise PolicyDenied(self.reason)
        return self


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def approval_digest(caller: str, connection: str, method: str, path: str, body: bytes) -> str:
    body_digest = hashlib.sha256(body or b"").hexdigest()
    canonical = "\n".join(["zeropw-approval-v1", caller, connection, method, path, body_digest])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class _Evaluated:
    """What an allowed ``evaluate`` decided, remembered per thread for the matching ``consume``."""

    caller: str
    connection: str
    grant: str
    action: Action
    policy_version: int


@dataclass
class Revocations:
    """Every revocation known from the revocation ledger and the audit log (monotone: never undone)."""

    grants: set[str] = field(default_factory=set)
    principals: set[str] = field(default_factory=set)
    connections: set[str] = field(default_factory=set)
    secret_versions: set[tuple[str, int]] = field(default_factory=set)


def append_revocation(state: StateDir, kind: str, **fields: Any) -> None:
    """Append one line to the revocation ledger (outside the backup set).

    Best effort by design: a revocation is never blocked because this line
    could not be written; the audit log is replayed as a second source.
    """
    entry = {"kind": kind, "ts": iso(), **fields}
    try:
        state.append_line(REVOCATIONS, json.dumps(entry, sort_keys=True, separators=(",", ":")))
    except (OSError, StateError):
        pass


def collect_revocations(state: StateDir, audit_records: Iterable[dict[str, Any]] = ()) -> Revocations:
    """Read the revocation ledger plus revocation events from the audit log.

    Ledger lines are processed in order because the core API can re-enable a
    connection; for the ledger only a connection whose last event is a disable
    counts.  Audit events are the administrator CLI's records
    (``grant_revoke``, ``grant_regrant``, ``principal_disable``,
    ``connection_disable``, ``secret_revoke``); they cover states written
    before the ledger existed and always count (the CLI has no re-enable).
    Identifiers are not reused by design: a principal or connection id that
    was disabled stays disabled across restores, so a re-created one needs a
    new id.
    """
    found = Revocations()
    try:
        lines = state.read_lines(REVOCATIONS, None)
    except (OSError, ValueError):
        lines = []
    for line in lines:
        try:
            entry = json.loads(line) if line.strip() else None
        except ValueError:
            continue
        if not isinstance(entry, dict):
            continue
        kind, ident = entry.get("kind"), entry.get("id")
        if kind == "grant" and isinstance(ident, str):
            found.grants.add(ident)
        elif kind == "principal" and isinstance(ident, str):
            found.principals.add(ident)
        elif kind == "connection" and isinstance(ident, str):
            found.connections.add(ident)
        elif kind == "connection_enable" and isinstance(ident, str):
            found.connections.discard(ident)
        elif kind == "secret_version" and isinstance(entry.get("secret_id"), str) and isinstance(entry.get("version"), int):
            found.secret_versions.add((entry["secret_id"], entry["version"]))
    for record in audit_records:
        if not isinstance(record, dict) or record.get("result") != "ok":
            continue
        event = record.get("event")
        if event == "grant_revoke" and isinstance(record.get("grant"), str):
            found.grants.add(record["grant"])
        elif event == "grant_regrant" and isinstance(record.get("detail"), str):
            found.grants.add(record["detail"])  # the replaced (old) grant id
        elif event == "principal_disable" and isinstance(record.get("principal"), str):
            found.principals.add(record["principal"])
        elif event == "connection_disable" and isinstance(record.get("connection"), str):
            found.connections.add(record["connection"])
        elif event == "secret_revoke" and isinstance(record.get("secret_id"), str) and isinstance(record.get("version"), int):
            found.secret_versions.add((record["secret_id"], record["version"]))
    return found


# --------------------------------------------------------------------- policy
class Policy:
    def __init__(self, state: StateDir, clock: Callable[[], float] = time.time) -> None:
        self.state = state
        self.clock = clock
        self._revoke_listeners: list[Callable[[str, str | None], None]] = []
        self._local = threading.local()

    # persistence helpers ----------------------------------------------------
    def _principals(self) -> dict[str, dict[str, Any]]:
        return self.state.read_json(PRINCIPALS, {}) or {}

    def _connections(self) -> dict[str, dict[str, Any]]:
        return self.state.read_json(CONNECTIONS, {}) or {}

    def _grants(self) -> dict[str, dict[str, Any]]:
        return self.state.read_json(GRANTS, {}) or {}

    def _control(self) -> dict[str, Any]:
        return self.state.read_json(CONTROL, None) or {"stopped": False, "restore_pending": False, "approvals": {}}

    def on_revoke(self, listener: Callable[[str, str | None], None]) -> None:
        self._revoke_listeners.append(listener)

    def _notify_revoke(self, kind: str, grant_id: str | None) -> None:
        for listener in list(self._revoke_listeners):
            listener(kind, grant_id)

    # per-thread memory of the last allowed evaluation (for consume) ---------
    def _remember(self, caller: str, action: Action, decision: Decision) -> None:
        if not decision.allowed or decision.grant is None or decision.connection is None:
            return
        memo = getattr(self._local, "evaluated", None)
        if memo is None or len(memo) >= _EVALUATED_MEMO_LIMIT:
            memo = {}
            self._local.evaluated = memo
        memo.pop(decision.grant.id, None)
        memo[decision.grant.id] = _Evaluated(caller, decision.connection.id, decision.grant.id, action,
                                             decision.connection.policy_version)

    def _recall(self, grant_id: str, pop: bool = False) -> _Evaluated | None:
        memo = getattr(self._local, "evaluated", None) or {}
        return memo.pop(grant_id, None) if pop else memo.get(grant_id)

    def _recall_pair(self, caller: str, connection_id: str) -> _Evaluated | None:
        memo = getattr(self._local, "evaluated", None) or {}
        for evaluated in reversed(list(memo.values())):
            if evaluated.caller == caller and evaluated.connection == connection_id:
                return evaluated
        return None

    # credential version -------------------------------------------------------
    def _vault_doc(self) -> dict[str, Any]:
        doc = self.state.read_json(VAULT_SECRETS, None)
        return doc if isinstance(doc, dict) else {}

    def _resolved_credential_version(self, connection: Connection, vault_doc: dict[str, Any] | None = None) -> int | None:
        """The vault version this connection uses now: the pinned one, else the secret's active version."""
        if connection.secret_version is not None:
            return connection.secret_version
        doc = self._vault_doc() if vault_doc is None else vault_doc
        entry = (doc.get("secrets") or {}).get(connection.secret_id) if isinstance(doc.get("secrets"), dict) else None
        active = entry.get("active_version") if isinstance(entry, dict) else None
        return active if isinstance(active, int) and not isinstance(active, bool) else None

    def credential_versions_changed(self, secret_id: str) -> list[Connection]:
        """Re-bind unpinned connections that follow ``secret_id`` to its current active version.

        Called by the vault after the active version of a secret changes.  For
        every active, unpinned connection whose active grants were evaluated
        against another credential version, the policy version is bumped (so
        handles issued for the old version are refused as ``grant_stale``),
        grants are re-evaluated in place with the new version, and approvals
        bound to the old policy version are invalidated.  A secret that has no
        active version any more changes nothing: no credential can be used.
        Returns the updated connections.
        """
        changed: list[tuple[Connection, int]] = []
        with self.state.lock():
            doc = self._connections()
            grants = self._grants()
            vault_doc = self._vault_doc()
            for connection_id, entry in sorted(doc.items()):
                if entry.get("secret_id") != secret_id or entry.get("secret_version") is not None \
                        or entry.get("status") != "active":
                    continue
                connection = Connection.from_dict(entry)
                resolved = self._resolved_credential_version(connection, vault_doc)
                if resolved is None:
                    continue
                recorded = [g for g in grants.values()
                            if g.get("connection") == connection_id and g.get("status") == "active"
                            and "credential_version" in g]
                if not any(g.get("credential_version") != resolved for g in recorded):
                    continue
                after = replace(connection, policy_version=connection.policy_version + 1, updated_at=iso(self.clock()))
                doc[connection_id] = after.to_dict()
                changed.append((after, resolved))
            if changed:
                self.state.write_json(CONNECTIONS, doc)
                for after, resolved in changed:
                    self._reevaluate_grants(after.id, after.policy_version, False, resolved)
                ids = {after.id for after, _ in changed}
                self._invalidate_approvals(lambda e: e.get("connection") in ids, "policy_changed")
        return [after for after, _ in changed]

    # principals -------------------------------------------------------------
    def create_principal(self, principal_id: str) -> str:
        validate_name(principal_id, "principal_id")
        token = "zpwc_" + secrets.token_urlsafe(32)
        with self.state.lock():
            doc = self._principals()
            if principal_id in doc:
                raise InvalidInput("principal_exists")
            doc[principal_id] = {"token_hash": hash_token(token), "status": "active", "created_at": iso(self.clock())}
            self.state.write_json(PRINCIPALS, doc)
        return token

    def disable_principal(self, principal_id: str) -> None:
        with self.state.lock():
            doc = self._principals()
            if principal_id not in doc:
                raise NotFound("principal_not_found")
            append_revocation(self.state, "principal", id=principal_id)
            doc[principal_id]["status"] = "disabled"
            self.state.write_json(PRINCIPALS, doc)
            self._invalidate_approvals(lambda e: e.get("caller") == principal_id, "principal_disabled")
        self._notify_revoke("principal", None)

    def get_principal(self, principal_id: str) -> Principal:
        entry = self._principals().get(principal_id)
        if entry is None:
            raise NotFound("principal_not_found")
        return Principal(principal_id, entry["token_hash"], entry["status"], entry["created_at"])

    def list_principals(self) -> list[Principal]:
        return [Principal(pid, e["token_hash"], e["status"], e["created_at"]) for pid, e in sorted(self._principals().items())]

    def authenticate(self, token: str) -> Principal:
        if not isinstance(token, str) or not token.startswith("zpwc_") or len(token) > 256:
            raise AuthFailed("caller_token_invalid")
        digest = hash_token(token)
        for pid, entry in self._principals().items():
            if secrets.compare_digest(entry["token_hash"], digest):
                if entry["status"] != "active":
                    raise AuthFailed("principal_disabled")
                return Principal(pid, entry["token_hash"], entry["status"], entry["created_at"])
        raise AuthFailed("caller_token_invalid")

    # connections ------------------------------------------------------------
    def create_connection(self, connection: Connection) -> Connection:
        if connection.http_target is not None:
            connection.http_target.require_allowed_literal()
        with self.state.lock():
            doc = self._connections()
            if connection.id in doc:
                raise InvalidInput("connection_exists")
            stamped = replace(connection, policy_version=1, created_at=iso(self.clock()), updated_at=iso(self.clock()))
            doc[connection.id] = stamped.to_dict()
            self.state.write_json(CONNECTIONS, doc)
        return stamped

    def get_connection(self, connection_id: str) -> Connection:
        entry = self._connections().get(connection_id)
        if entry is None:
            raise NotFound("connection_not_found")
        return Connection.from_dict(entry)

    def list_connections(self) -> list[Connection]:
        return [Connection.from_dict(e) for _, e in sorted(self._connections().items())]

    def update_connection(self, connection_id: str, **changes: Any) -> tuple[Connection, bool]:
        """Apply changes, bump the policy version, and re-evaluate grants.

        Returns (connection, widened).  Widening changes mark grants stale.
        """
        allowed = {"description", "http_target", "http_auth", "http_scope", "ssh_target", "cli",
                   "secret_id", "secret_version", "status"}
        unknown = set(changes) - allowed
        if unknown:
            raise InvalidInput("connection_field_not_updatable")
        if isinstance(changes.get("http_target"), HttpTarget):
            changes["http_target"].require_allowed_literal()
        with self.state.lock():
            doc = self._connections()
            entry = doc.get(connection_id)
            if entry is None:
                raise NotFound("connection_not_found")
            before = Connection.from_dict(entry)
            after = replace(before, **changes)
            widened = self._widens(before, after)
            after = replace(after, policy_version=before.policy_version + 1, updated_at=iso(self.clock()))
            if after.status == "disabled" and before.status != "disabled":
                append_revocation(self.state, "connection", id=connection_id)
            elif after.status == "active" and before.status != "active":
                append_revocation(self.state, "connection_enable", id=connection_id)
            doc[connection_id] = after.to_dict()
            self.state.write_json(CONNECTIONS, doc)
            self._reevaluate_grants(connection_id, after.policy_version, widened,
                                    self._resolved_credential_version(after))
            # Approvals are bound to the policy version they were requested under.
            self._invalidate_approvals(lambda e: e.get("connection") == connection_id,
                                       "connection_disabled" if after.status == "disabled" else "policy_changed")
        if widened:
            self._notify_revoke("connection", None)
        return after, widened

    @staticmethod
    def _widens(before: Connection, after: Connection) -> bool:
        if before.kind != after.kind or before.status != after.status and after.status == "active":
            return True
        # Another secret is another credential (possibly with broader rights); only a
        # version switch within the same secret is re-evaluated in place.
        if before.secret_id != after.secret_id:
            return True
        if before.kind == "http":
            assert before.http_target and after.http_target and before.http_scope and after.http_scope
            assert before.http_auth and after.http_auth
            if (before.http_target.scheme, before.http_target.host, before.http_target.port) != \
                    (after.http_target.scheme, after.http_target.host, after.http_target.port):
                return True
            # A different TLS trust anchor (another CA file, or the system store) can
            # authenticate servers the old one did not.
            if before.http_target.ca_file != after.http_target.ca_file:
                return True
            # Opening private networks lets the credential reach addresses it could not before.
            if after.http_target.allow_private_network and not before.http_target.allow_private_network:
                return True
            if before.http_auth != after.http_auth:
                return True
            if before.http_scope.widens(after.http_scope):
                return True
        if before.kind == "ssh":
            assert before.ssh_target and after.ssh_target
            if (before.ssh_target.host, before.ssh_target.port, before.ssh_target.username) != \
                    (after.ssh_target.host, after.ssh_target.port, after.ssh_target.username):
                return True
            if set(after.ssh_target.host_keys) - set(before.ssh_target.host_keys):
                return True
        if (before.cli is None) != (after.cli is None) or (before.cli and after.cli and before.cli != after.cli):
            return True
        return False

    def _reevaluate_grants(self, connection_id: str, new_version: int, widened: bool,
                           credential_version: int | None = None) -> None:
        grants = self._grants()
        changed = False
        for gid, entry in grants.items():
            if entry["connection"] != connection_id or entry["status"] != "active":
                continue
            if widened:
                entry["status"] = "stale"
            else:
                entry["policy_version"] = new_version
                entry["credential_version"] = credential_version
            changed = True
        if changed:
            self.state.write_json(GRANTS, grants)

    def switch_credential(self, connection_id: str, secret_version: int | None) -> Connection:
        connection, _ = self.update_connection(connection_id, secret_version=secret_version)
        return connection

    def disable_connection(self, connection_id: str) -> Connection:
        connection, _ = self.update_connection(connection_id, status="disabled")
        self._notify_revoke("connection", None)
        return connection

    # grants -----------------------------------------------------------------
    def create_grant(self, principal_id: str, connection_id: str, ttl_seconds: int | None,
                     max_uses: int | None) -> Grant:
        if ttl_seconds is not None and (ttl_seconds <= 0 or ttl_seconds > MAX_GRANT_TTL):
            raise InvalidInput("invalid_ttl")
        if max_uses is not None and (isinstance(max_uses, bool) or max_uses <= 0):
            raise InvalidInput("invalid_max_uses")
        with self.state.lock():
            principal = self.get_principal(principal_id)
            if principal.status != "active":
                raise InvalidInput("principal_disabled")
            connection = self.get_connection(connection_id)
            if connection.status != "active":
                raise InvalidInput("connection_disabled")
            now = self.clock()
            grant = Grant(
                id="g-" + uuid.uuid4().hex[:16], principal=principal_id, connection=connection_id,
                policy_version=connection.policy_version,
                expires_at=(now + ttl_seconds) if ttl_seconds is not None else None,
                max_uses=max_uses, uses=0, status="active", created_at=iso(now),
                credential_version=self._resolved_credential_version(connection),
            )
            doc = self._grants()
            doc[grant.id] = asdict(grant)
            self.state.write_json(GRANTS, doc)
        return grant

    def get_grant(self, grant_id: str) -> Grant:
        entry = self._grants().get(grant_id)
        if entry is None:
            raise NotFound("grant_not_found")
        return Grant(**entry)

    def list_grants(self, principal_id: str | None = None) -> list[Grant]:
        return [Grant(**e) for _, e in sorted(self._grants().items())
                if principal_id is None or e["principal"] == principal_id]

    @staticmethod
    def _approval_of_grant(grant: dict[str, Any], grant_id: str) -> Callable[[dict[str, Any]], bool]:
        """Approvals recorded for this grant, or recorded without a grant for its caller and connection."""
        def matches(entry: dict[str, Any]) -> bool:
            if entry.get("grant") is not None:
                return entry.get("grant") == grant_id
            return entry.get("caller") == grant.get("principal") and entry.get("connection") == grant.get("connection")
        return matches

    def revoke_grant(self, grant_id: str) -> Grant:
        with self.state.lock():
            doc = self._grants()
            entry = doc.get(grant_id)
            if entry is None:
                raise NotFound("grant_not_found")
            append_revocation(self.state, "grant", id=grant_id)
            entry["status"] = "revoked"
            entry["revoked_at"] = iso(self.clock())
            self.state.write_json(GRANTS, doc)
            self._invalidate_approvals(self._approval_of_grant(entry, grant_id), "grant_revoked")
        self._notify_revoke("grant", grant_id)
        return Grant(**entry)

    def revoke_all(self) -> int:
        """Revoke every active or stale grant and invalidate every open approval (used by recovery)."""
        count = 0
        with self.state.lock():
            doc = self._grants()
            for grant_id, entry in doc.items():
                if entry["status"] in ("active", "stale"):
                    append_revocation(self.state, "grant", id=grant_id)
                    entry["status"] = "revoked"
                    entry["revoked_at"] = iso(self.clock())
                    count += 1
            self.state.write_json(GRANTS, doc)
            self._invalidate_approvals(lambda e: True, "grant_revoked")
        self._notify_revoke("all", None)
        return count

    def regrant(self, grant_id: str) -> Grant:
        """Issue a fresh grant with the same limits at the current policy version."""
        with self.state.lock():
            old = self.get_grant(grant_id)
            if old.status not in ("stale", "active"):
                raise InvalidInput("grant_not_regrantable")
            remaining_ttl = None
            if old.expires_at is not None:
                remaining_ttl = int(old.expires_at - self.clock())
                if remaining_ttl <= 0:
                    raise InvalidInput("grant_expired")
            remaining_uses = None if old.max_uses is None else max(old.max_uses - old.uses, 0)
            if remaining_uses == 0:
                raise InvalidInput("grant_exhausted")
            doc = self._grants()
            append_revocation(self.state, "grant", id=grant_id)
            doc[grant_id]["status"] = "revoked"
            doc[grant_id]["revoked_at"] = iso(self.clock())
            self.state.write_json(GRANTS, doc)
            self._invalidate_approvals(self._approval_of_grant(doc[grant_id], grant_id), "grant_revoked")
            fresh = self.create_grant(old.principal, old.connection, remaining_ttl, remaining_uses)
        return fresh

    # control ----------------------------------------------------------------
    def stop_all(self) -> None:
        with self.state.lock():
            control = self._control()
            control["stopped"] = True
            control["stopped_at"] = iso(self.clock())
            self.state.write_json(CONTROL, control)
        self._notify_revoke("stop", None)

    def resume(self) -> None:
        with self.state.lock():
            control = self._control()
            control["stopped"] = False
            self.state.write_json(CONTROL, control)

    def is_stopped(self) -> bool:
        return bool(self._control().get("stopped"))

    def set_restore_pending(self, pending: bool) -> None:
        with self.state.lock():
            control = self._control()
            control["restore_pending"] = bool(pending)
            self.state.write_json(CONTROL, control)
        if pending:
            self._notify_revoke("restore", None)

    def restore_pending(self) -> bool:
        return bool(self._control().get("restore_pending"))

    # approvals --------------------------------------------------------------
    # Lifecycle of one digest: pending -> approved -> consumed, or -> expired /
    # invalidated.  Only ``pending`` and ``approved`` are open.  A digest whose
    # current entry is closed starts a new cycle on the next request; the
    # closed entry moves to ``approval_history``.
    OPEN_APPROVAL_STATES = ("pending", "approved")

    def _approval_expired(self, entry: dict[str, Any], now: float) -> bool:
        expires = entry.get("expires_at")
        if isinstance(expires, bool) or not isinstance(expires, (int, float)):
            return True   # entries without an expiry (older state) are never usable
        return now >= expires

    def _close_approval(self, entry: dict[str, Any], status: str, reason: str | None, now: float) -> None:
        entry["status"] = status
        entry[f"{status}_at"] = iso(now)
        if reason is not None:
            entry["closed_reason"] = reason

    def _invalidate_approvals(self, predicate: Callable[[dict[str, Any]], bool], reason: str) -> int:
        """Close every open approval matching ``predicate``.  Call with the state lock held."""
        control = self._control()
        approvals = control.get("approvals") or {}
        now = self.clock()
        count = 0
        for entry in approvals.values():
            if isinstance(entry, dict) and entry.get("status") in self.OPEN_APPROVAL_STATES and predicate(entry):
                self._close_approval(entry, "invalidated", reason, now)
                count += 1
        if count:
            self.state.write_json(CONTROL, control)
        return count

    def _archive_approval(self, control: dict[str, Any], digest: str, entry: dict[str, Any]) -> None:
        history = control.setdefault("approval_history", [])
        history.append({"digest": digest, **entry})
        del history[:-APPROVAL_HISTORY_LIMIT]

    def _usable_grant_id(self, caller: str, connection_id: str) -> str | None:
        decision = self._decide(caller, connection_id, None, None)
        return decision.grant.id if decision.allowed and decision.grant else None

    def request_approval(self, digest: str, caller: str, connection: str, method: str, path: str) -> dict[str, Any]:
        """Open (or return the open) approval for ``digest``.

        The entry records the grant and connection policy version in use and
        expires after ``APPROVAL_TTL_SECONDS``.  A digest whose previous entry
        was consumed, expired or invalidated gets a new pending cycle, so a
        request that used up its approval without being sent can be approved
        again.
        """
        now = self.clock()
        with self.state.lock():
            control = self._control()
            approvals = control.setdefault("approvals", {})
            entry = approvals.get(digest)
            cycle = 1
            if isinstance(entry, dict):
                if entry.get("status") in self.OPEN_APPROVAL_STATES and not self._approval_expired(entry, now):
                    return dict(entry)
                if entry.get("status") in self.OPEN_APPROVAL_STATES:
                    self._close_approval(entry, "expired", "approval_expired", now)
                self._archive_approval(control, digest, entry)
                cycle = int(entry.get("cycle") or 1) + 1
            evaluated = self._recall_pair(caller, connection)
            try:
                policy_version: int | None = self.get_connection(connection).policy_version
            except NotFound:
                policy_version = None
            if evaluated is not None and evaluated.policy_version != policy_version:
                policy_version = evaluated.policy_version   # bound to what the caller was evaluated under
            entry = {"caller": caller, "connection": connection, "method": method, "path": path,
                     "status": "pending", "created_at": iso(now), "expires_at": now + APPROVAL_TTL_SECONDS,
                     "grant": evaluated.grant if evaluated is not None else self._usable_grant_id(caller, connection),
                     "policy_version": policy_version, "cycle": cycle}
            approvals[digest] = entry
            self.state.write_json(CONTROL, control)
            return dict(entry)

    def approve(self, digest: str) -> dict[str, Any]:
        now = self.clock()
        with self.state.lock():
            control = self._control()
            entry = control.get("approvals", {}).get(digest)
            if entry is None:
                raise NotFound("approval_not_found")
            if entry["status"] != "pending":
                raise InvalidInput("approval_not_pending")
            if self._approval_expired(entry, now):
                self._close_approval(entry, "expired", "approval_expired", now)
                self.state.write_json(CONTROL, control)
                raise InvalidInput("approval_expired")
            entry["status"] = "approved"
            entry["approved_at"] = iso(now)
            entry["expires_at"] = now + APPROVAL_TTL_SECONDS   # must be used shortly after approval
            self.state.write_json(CONTROL, control)
            return dict(entry)

    def consume_approval(self, digest: str, caller: str, connection: str, *, grant_id: str | None = None,
                         policy_version: int | None = None) -> bool:
        """Use an approved, unexpired approval once.

        It must still match the grant and the connection policy version it was
        requested under.  ``grant_id`` / ``policy_version`` name what the caller
        is about to use; when omitted, the last allowed ``evaluate`` for this
        caller and connection in the current thread supplies them.  A mismatch
        or expiry closes the approval (the next request opens a new cycle).
        """
        now = self.clock()
        with self.state.lock():
            control = self._control()
            entry = control.get("approvals", {}).get(digest)
            if not isinstance(entry, dict) or entry.get("status") != "approved":
                return False
            if entry.get("caller") != caller or entry.get("connection") != connection:
                return False
            evaluated = self._recall_pair(caller, connection)
            in_use_grant = grant_id if grant_id is not None else (evaluated.grant if evaluated else None)
            in_use_version = policy_version if policy_version is not None else (
                evaluated.policy_version if evaluated else None)
            reason = self._approval_mismatch(entry, caller, connection, in_use_grant, in_use_version, now)
            if reason is not None:
                self._close_approval(entry, "expired" if reason == "approval_expired" else "invalidated", reason, now)
                self.state.write_json(CONTROL, control)
                return False
            entry["status"] = "consumed"
            entry["consumed_at"] = iso(now)
            if in_use_grant is not None:
                entry["consumed_grant"] = in_use_grant
            self.state.write_json(CONTROL, control)
            return True

    def _approval_mismatch(self, entry: dict[str, Any], caller: str, connection_id: str, in_use_grant: str | None,
                           in_use_version: int | None, now: float) -> str | None:
        if self._approval_expired(entry, now):
            return "approval_expired"
        try:
            connection = self.get_connection(connection_id)
        except NotFound:
            return "connection_unknown"
        recorded_version = entry.get("policy_version")
        if recorded_version != connection.policy_version:
            return "policy_changed"
        if in_use_version is not None and in_use_version != connection.policy_version:
            return "policy_changed"
        recorded_grant = entry.get("grant")
        if recorded_grant is not None:
            if in_use_grant is not None and in_use_grant != recorded_grant:
                return "grant_changed"
            try:
                grant = self.get_grant(recorded_grant)
            except NotFound:
                return "grant_changed"
            if grant.principal != caller or grant.connection != connection_id:
                return "grant_changed"
            state = self._grant_state(grant, connection)
            if state is not None:
                return state
        return None

    def list_approvals(self) -> dict[str, dict[str, Any]]:
        return dict(self._control().get("approvals", {}))

    def approval_history(self) -> list[dict[str, Any]]:
        return list(self._control().get("approval_history", []))

    # restore -----------------------------------------------------------------
    def reapply_revocations(self, revocations: Revocations) -> dict[str, int]:
        """Apply every known revocation to the current policy documents (idempotent).

        Used after a restore: the archive may pre-date revocations, and a
        restore must never bring a revoked grant, a disabled principal or a
        disabled connection back.  Returns how many records had to change.
        """
        counts = {"grants": 0, "principals": 0, "connections": 0}
        with self.state.lock():
            now = iso(self.clock())
            grants = self._grants()
            for grant_id in revocations.grants:
                entry = grants.get(grant_id)
                if isinstance(entry, dict) and entry.get("status") != "revoked":
                    entry["status"] = "revoked"
                    entry["revoked_at"] = entry.get("revoked_at") or now
                    counts["grants"] += 1
            if counts["grants"]:
                self.state.write_json(GRANTS, grants)
            principals = self._principals()
            for principal_id in revocations.principals:
                entry = principals.get(principal_id)
                if isinstance(entry, dict) and entry.get("status") != "disabled":
                    entry["status"] = "disabled"
                    counts["principals"] += 1
            if counts["principals"]:
                self.state.write_json(PRINCIPALS, principals)
            connections = self._connections()
            for connection_id in revocations.connections:
                entry = connections.get(connection_id)
                if isinstance(entry, dict) and entry.get("status") != "disabled":
                    entry["status"] = "disabled"
                    entry["policy_version"] = int(entry.get("policy_version", 0)) + 1
                    entry["updated_at"] = now
                    counts["connections"] += 1
            if counts["connections"]:
                self.state.write_json(CONNECTIONS, connections)
            self._invalidate_approvals(
                lambda e: e.get("grant") in revocations.grants or e.get("caller") in revocations.principals
                or e.get("connection") in revocations.connections, "revoked_before_restore")
        return counts

    # evaluation -------------------------------------------------------------
    def _grant_state(self, grant: Grant, connection: Connection) -> str | None:
        if grant.status == "revoked":
            return "grant_revoked"
        if grant.status == "stale" or grant.policy_version != connection.policy_version:
            return "grant_stale"
        if grant.status != "active":
            return "grant_inactive"
        if grant.expires_at is not None and self.clock() >= grant.expires_at:
            return "grant_expired"
        if grant.max_uses is not None and grant.uses >= grant.max_uses:
            return "grant_exhausted"
        return None

    def evaluate(self, caller: str, connection_id: str, action: Action, grant_id: str | None = None) -> Decision:
        """Full decision for one operation (lock-free read).

        An allowed decision is remembered for the current thread so that the
        matching ``consume`` re-applies the same operation scope and requires
        the same connection policy version under the state lock.
        """
        decision = self._decide(caller, connection_id, action, grant_id)
        self._remember(caller, action, decision)
        return decision

    def check_grant(self, caller: str, connection_id: str, grant_id: str) -> Decision:
        """Is this (caller, connection, grant) still usable at all, independent of any one operation?

        Checks restore-pending, global stop, principal, connection and grant
        state; no scope check.  Used to find running executions and signer
        sockets whose permission was withdrawn by another process.
        """
        return self._decide(caller, connection_id, None, grant_id)

    @staticmethod
    def _scope_reason(connection: Connection, action: Action) -> str | None:
        if action.kind != connection.kind:
            return "action_kind_mismatch"
        if connection.kind == "http":
            assert connection.http_scope
            if not action.method or action.method not in HTTP_METHODS:
                return "method_not_allowed"
            if not connection.http_scope.allows_method(action.method):
                return "method_not_allowed"
            if action.path is None or not connection.http_scope.allows_path(action.path):
                return "path_not_allowed"
            return None
        assert connection.ssh_target
        if action.username != connection.ssh_target.username:
            return "ssh_user_mismatch"
        return None

    def _decide(self, caller: str, connection_id: str, action: Action | None, grant_id: str | None) -> Decision:
        control = self._control()
        if control.get("restore_pending"):
            return Decision(False, "restore_pending")
        if control.get("stopped"):
            return Decision(False, "global_stop")
        try:
            principal = self.get_principal(caller)
        except NotFound:
            return Decision(False, "principal_unknown")
        if principal.status != "active":
            return Decision(False, "principal_disabled")
        try:
            connection = self.get_connection(connection_id)
        except NotFound:
            return Decision(False, "connection_unknown")
        if connection.status != "active":
            return Decision(False, "connection_disabled", connection=connection)
        if action is not None and action.kind != connection.kind:
            return Decision(False, "action_kind_mismatch", connection=connection)

        candidates: list[Grant]
        if grant_id is not None:
            try:
                grant = self.get_grant(grant_id)
            except NotFound:
                return Decision(False, "grant_unknown", connection=connection)
            if grant.principal != caller or grant.connection != connection_id:
                return Decision(False, "grant_mismatch", connection=connection)
            candidates = [grant]
        else:
            candidates = [g for g in self.list_grants(caller) if g.connection == connection_id]
            if not candidates:
                return Decision(False, "no_grant", connection=connection)

        failure = "no_grant"
        chosen: Grant | None = None
        for grant in candidates:
            state = self._grant_state(grant, connection)
            if state is None:
                chosen = grant
                break
            failure = state
        if chosen is None:
            return Decision(False, failure, connection=connection)
        if action is not None:
            reason = self._scope_reason(connection, action)
            if reason is not None:
                return Decision(False, reason, chosen, connection)
        return Decision(True, "allowed", chosen, connection)

    def consume(self, grant_id: str, *, caller: str | None = None, connection_id: str | None = None,
                action: Action | None = None, policy_version: int | None = None) -> Grant:
        """The authoritative last-moment decision, then count one use (default deny).

        Everything is re-read under the state lock, so an administrator change
        committed by any process before this call is honoured: restore-pending,
        global stop, principal and connection status, grant state (revoked,
        stale, expired, exhausted), the operation's scope and the connection
        policy version.  ``action`` and ``policy_version`` name the operation
        and the version the caller evaluated (for a handle: the handle's
        version).  When omitted, the last allowed ``evaluate`` of this grant in
        the current thread supplies them, so the relay and the signer are held
        to exactly what they were allowed a moment earlier.  A policy version
        that moved since then refuses with ``grant_stale``: the caller's
        connection snapshot (target, credential version) is no longer current.
        """
        evaluated = self._recall(grant_id, pop=True)
        if evaluated is not None:
            if action is None:
                action = evaluated.action
            if policy_version is None:
                policy_version = evaluated.policy_version
        with self.state.lock():
            doc = self._grants()
            entry = doc.get(grant_id)
            if entry is None:
                raise PolicyDenied("grant_unknown")
            grant = Grant(**entry)
            if caller is not None and caller != grant.principal:
                raise PolicyDenied("grant_mismatch")
            if connection_id is not None and connection_id != grant.connection:
                raise PolicyDenied("grant_mismatch")
            decision = self._decide(grant.principal, grant.connection, action, grant_id)
            if not decision.allowed:
                raise PolicyDenied(decision.reason)
            assert decision.connection is not None
            if policy_version is not None and policy_version != decision.connection.policy_version:
                raise PolicyDenied("grant_stale")
            entry["uses"] = grant.uses + 1
            self.state.write_json(GRANTS, doc)
            return Grant(**entry)

    def usable_connections(self, caller: str) -> list[tuple[Connection, Grant]]:
        """Connections the caller may use right now, with the grant that allows each."""
        result: list[tuple[Connection, Grant]] = []
        control = self._control()
        if control.get("restore_pending") or control.get("stopped"):
            return result
        for grant in self.list_grants(caller):
            try:
                connection = self.get_connection(grant.connection)
            except NotFound:
                continue
            if connection.status != "active" or self._grant_state(grant, connection) is not None:
                continue
            result.append((connection, grant))
        return result
