"""Agent-native tools: ``list_connections``, ``request``, ``exec``, ``status``, ``cancel``.

Security scope
--------------
* Tools are invoked with an already-authenticated caller id (``server.py``
  verifies the caller token, which is the agent's own identity and never a
  vault value).  No tool returns vault values, secret ids, handles, internal
  paths, or another principal's connections or runs.
* ``request`` delegates HTTP authentication to ``zeropw.gateway``; this module
  never touches the credential.  It first checks that the caller holds a
  usable grant for the connection (denials never reach the gateway), and the
  gateway re-evaluates the full method/path scope and consumes usage.
* ``exec`` runs only the program fixed by the connection's CLI profile; agent
  input is limited to the arguments.  The child receives a minimal
  environment carrying an opaque short-lived handle (HTTP) or a per-run
  signer socket (SSH), never the credential.  For SSH the run directory also
  holds the connection key's *public* half (``id.pub``) so OpenSSH with
  ``IdentitiesOnly=yes`` offers the agent key, and ``-F /dev/null`` keeps
  user/system ssh_config out of the picture.  Connections without a CLI
  profile, missing programs, a missing signer or an unset public URL fail
  with an explicit reason; there is no plaintext fallback.  A CLI profile
  whose environment (``extra_env`` names/values or ``base_url_env``) carries
  any vault value -- the connection's credential or any version, whatever its
  status, of any other secret -- in any scanned encoding is refused with
  ``cli_env_contains_credential`` before any handle or signer socket exists.
* The run is registered in the registry *before* audit/secret/handle work so
  a concurrent revoke or global stop can cancel it while queued, and policy
  is re-evaluated (grant state, stop, restore pending) immediately before
  the child is spawned.  Request ids are reserved atomically with the run.
* The child's cwd/HOME/TMPDIR and the signer socket live under
  ``ctx.config.run_dir`` / ``socket_dir``, which ``Context`` keeps outside
  the trusted state directory; no path into the state store is ever handed
  to the child.
* Policy (grant state, expiry, usage, revocation, global stop, restore
  pending, policy version) is re-evaluated on every call through
  ``Policy.usable_connections`` / ``Policy.evaluate``.  An audit record is
  written before any credential-bearing artefact is issued or used; if it
  cannot be written the operation is refused.
* ``status`` / ``cancel`` only see runs owned by the caller; anything else is
  ``NotFound`` so run ids cannot be enumerated.  ``cancel`` is never refused
  because the audit log is unavailable: the run is cancelled first and the
  audit failure is then raised to the caller.
* Tool audit records name the connection's target (HTTP origin or ssh
  ``host:port``) and policy version; runs carry both into ``run_start`` /
  ``run_cancel`` / ``run_finish``.

Limitations: output scanning in ``zeropw.runs`` is defence in depth and does
not cover every transformation; cancellation cannot undo remote work already
performed; the inherited ``PATH`` is the only environment variable the child
shares with the trusted process.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping

from .errors import AuditUnavailable, InvalidInput, NotFound, PolicyDenied, StateError, Unsupported, ZeroPWError
from .policy import HEADER_NAME_RE, HTTP_METHODS, Action, Connection, Grant, SshTarget
from .projects import validate_name
from .runs import RunRegistry, contains_sensitive, credential_patterns
from .store import iso

TOOL_NAMES = ("list_connections", "request", "exec", "status", "cancel")

MAX_ARGV_ITEMS = 256
MAX_ARG_LENGTH = 4096
MAX_PATH_LENGTH = 4096
MAX_HEADERS = 64
MAX_HEADER_VALUE = 8192
RUN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
PATH_RE = re.compile(r"^/[\x21-\x7e]*$")
HEADER_VALUE_RE = re.compile(r"^[^\x00-\x08\x0a-\x1f\x7f]*$")
PUBLIC_URL_RE = re.compile(r"^https?://[A-Za-z0-9.\-\[\]:_]+(?:/[\x21-\x7e]*)?$")
DEFAULT_PATH = "/usr/bin:/bin"
FIXED_ENV_KEYS = ("PATH", "HOME", "LANG", "TMPDIR", "ZEROPW_RUN_ID")

# Response headers never handed back to an agent, even if the gateway passed them.
DROP_RESPONSE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "proxy-authenticate", "www-authenticate", "set-cookie",
    "set-cookie2", "cookie", "x-zeropw-handle", "connection", "keep-alive", "transfer-encoding", "upgrade",
    "te", "trailer",
})


# ------------------------------------------------------------------ install
def install(ctx: Any) -> RunRegistry:
    """Attach a ``RunRegistry`` to ``ctx.runs`` and cancel runs on revocation.  Idempotent."""
    if isinstance(ctx.runs, RunRegistry):
        return ctx.runs
    registry = RunRegistry(ctx)
    ctx.runs = registry
    ctx.policy.on_revoke(registry.on_revoke)
    return registry


def set_public_url(ctx: Any, url: str) -> str:
    """Record the URL under which the server is reachable (used to build child base URLs)."""
    if not isinstance(url, str) or not PUBLIC_URL_RE.match(url):
        raise InvalidInput("invalid_public_url")
    cleaned = url.rstrip("/")
    ctx.config.extra["public_url"] = cleaned
    return cleaned


def _registry(ctx: Any) -> RunRegistry:
    registry = getattr(ctx, "runs", None)
    if not isinstance(registry, RunRegistry):
        raise StateError("runs_not_installed")
    return registry


# ------------------------------------------------------------- validation
def _str(payload: Mapping[str, Any], key: str, required: bool = True, max_length: int = 4096) -> str | None:
    value = payload.get(key)
    if value is None:
        if required:
            raise InvalidInput(f"missing_{key}")
        return None
    if not isinstance(value, str) or len(value) > max_length or "\x00" in value:
        raise InvalidInput(f"invalid_{key}")
    return value


def _connection_id(payload: Mapping[str, Any]) -> str:
    value = _str(payload, "connection")
    assert value is not None
    validate_name(value, "connection")
    return value


def _method(payload: Mapping[str, Any]) -> str:
    value = _str(payload, "method", max_length=16)
    assert value is not None
    value = value.upper()
    if value not in HTTP_METHODS:
        raise InvalidInput("invalid_method")
    return value


def _path(payload: Mapping[str, Any]) -> str:
    value = _str(payload, "path", max_length=MAX_PATH_LENGTH)
    assert value is not None
    if not PATH_RE.match(value) or "://" in value:
        raise InvalidInput("invalid_path")
    return value


def _headers(payload: Mapping[str, Any]) -> dict[str, str]:
    raw = payload.get("headers")
    if raw is None:
        return {}
    if not isinstance(raw, dict) or len(raw) > MAX_HEADERS:
        raise InvalidInput("invalid_headers")
    headers: dict[str, str] = {}
    for name, value in raw.items():
        if not isinstance(name, str) or not HEADER_NAME_RE.match(name):
            raise InvalidInput("invalid_header_name")
        if not isinstance(value, str) or len(value) > MAX_HEADER_VALUE or not HEADER_VALUE_RE.match(value):
            raise InvalidInput("invalid_header_value")
        headers[name] = value
    return headers


def _body(payload: Mapping[str, Any], limit: int) -> bytes:
    text = payload.get("body")
    encoded = payload.get("body_base64")
    if text is not None and encoded is not None:
        raise InvalidInput("invalid_body")
    if text is not None:
        if not isinstance(text, str):
            raise InvalidInput("invalid_body")
        body = text.encode("utf-8")
    elif encoded is not None:
        if not isinstance(encoded, str):
            raise InvalidInput("invalid_body")
        try:
            body = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise InvalidInput("invalid_body_base64") from exc
    else:
        body = b""
    if len(body) > limit:
        raise InvalidInput("request_body_too_large")
    return body


def _request_id(payload: Mapping[str, Any]) -> str | None:
    value = _str(payload, "request_id", required=False, max_length=128)
    if value is not None and not REQUEST_ID_RE.match(value):
        raise InvalidInput("invalid_request_id")
    return value


def _argv(payload: Mapping[str, Any]) -> list[str]:
    raw = payload.get("argv", [])
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise InvalidInput("invalid_argv")
    if len(raw) > MAX_ARGV_ITEMS:
        raise InvalidInput("argv_too_long")
    argv: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            raise InvalidInput("invalid_argv")
        if len(item) > MAX_ARG_LENGTH:
            raise InvalidInput("argument_too_long")
        if "\x00" in item:
            raise InvalidInput("invalid_argv")
        argv.append(item)
    return argv


def _run_id(payload: Mapping[str, Any]) -> str:
    value = _str(payload, "run_id", max_length=64)
    assert value is not None
    if not RUN_ID_RE.match(value):
        raise InvalidInput("invalid_run_id")
    return value


# ---------------------------------------------------------------- dispatch
def dispatch(ctx: Any, name: str, caller: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    """Route a tools API call.  Unknown keys in ``payload`` are ignored; wrong types are refused."""
    if not isinstance(name, str) or name not in TOOL_NAMES:
        # The caller already authenticated (server.py); the tool name itself is agent-chosen
        # free text and is never recorded (docs/compromise-response.md §4.2 "미제공 도구 호출").
        if isinstance(caller, str) and caller:
            ctx.audit.record("tools_unknown", caller=caller, result="denied", reason="tool_not_found")
        raise NotFound("tool_not_found")
    if not isinstance(payload, Mapping):
        raise InvalidInput("invalid_payload")
    if not isinstance(caller, str) or not caller:
        raise InvalidInput("invalid_caller")
    if name == "list_connections":
        return list_connections(ctx, caller)
    if name == "request":
        return request(ctx, caller, _connection_id(payload), _method(payload), _path(payload), _headers(payload),
                       _body(payload, int(ctx.config.max_request_body_bytes)), _request_id(payload))
    if name == "exec":
        return exec(ctx, caller, _connection_id(payload), _argv(payload), _request_id(payload))
    if name == "status":
        return status(ctx, caller, _run_id(payload))
    return cancel(ctx, caller, _run_id(payload))


# ------------------------------------------------------------------ policy
def _usable(ctx: Any, caller: str, connection_id: str) -> tuple[Connection | None, Grant | None, str]:
    """(connection, grant, reason).  Reason is precise when the caller cannot use the connection."""
    for connection, grant in ctx.policy.usable_connections(caller):
        if connection.id == connection_id:
            return connection, grant, "allowed"
    action = Action("http", method="GET", path="/")
    try:
        known = ctx.policy.get_connection(connection_id)
        if known.kind == "ssh" and known.ssh_target is not None:
            action = Action("ssh", username=known.ssh_target.username)
    except NotFound:
        pass
    decision = ctx.policy.evaluate(caller, connection_id, action)
    reason = decision.reason if not decision.allowed else "policy_denied"
    return None, None, reason


def _target_label(connection: Connection) -> str | None:
    """Audit label for where a connection points: HTTP origin or ssh ``host:port``."""
    if connection.kind == "http" and connection.http_target is not None:
        return connection.http_target.origin
    if connection.kind == "ssh" and connection.ssh_target is not None:
        return f"{connection.ssh_target.host}:{connection.ssh_target.port}"
    return None


# --------------------------------------------------------- list_connections
def list_connections(ctx: Any, caller: str) -> dict[str, Any]:
    usable = ctx.policy.usable_connections(caller)
    ctx.audit.record("tools_list_connections", caller=caller, action="list", result="ok",
                     extra={"count": len(usable)})
    return {"connections": [{**connection.public_view(), "grant": grant.public_view()} for connection, grant in usable]}


# ------------------------------------------------------------------ request
def _filter_response_headers(headers: Any) -> dict[str, str]:
    items = headers.items() if isinstance(headers, Mapping) else (headers or [])
    filtered: dict[str, str] = {}
    for name, value in items:
        lowered = str(name).lower()
        if lowered in DROP_RESPONSE_HEADERS:
            continue
        if lowered in filtered:
            filtered[lowered] = f"{filtered[lowered]}, {value}"
        else:
            filtered[lowered] = str(value)
    return filtered


def _denied_relay(reason: str) -> dict[str, Any]:
    return {"status": 403, "headers": {}, "body": None, "body_base64": None, "reason": reason}


def request(ctx: Any, caller: str, connection: str, method: str, path: str,
            headers: Mapping[str, str] | None = None, body: bytes | str | None = None,
            request_id: str | None = None) -> dict[str, Any]:
    if isinstance(body, str):
        body = body.encode("utf-8")
    body = bytes(body or b"")
    headers = dict(headers or {})
    known, _grant, reason = _usable(ctx, caller, connection)
    if known is None:
        ctx.audit.record("tools_request", caller=caller, connection=connection, action=method, result="denied",
                         reason=reason, request_id=request_id, extra={"method": method, "path": path})
        return _denied_relay(reason)
    if known.kind != "http":
        ctx.audit.record("tools_request", caller=caller, connection=connection, target=_target_label(known),
                         action=method, result="denied", reason="action_kind_mismatch", request_id=request_id,
                         policy_version=known.policy_version, extra={"method": method, "path": path})
        return _denied_relay("action_kind_mismatch")
    # Recorded before the gateway touches the credential.  Failure to record refuses the call.
    ctx.audit.record("tools_request", caller=caller, connection=known.id, target=_target_label(known),
                     action=method, result="ok", request_id=request_id, policy_version=known.policy_version,
                     extra={"method": method, "path": path, "bytes": len(body)})
    try:
        from . import gateway
    except ImportError as exc:
        raise Unsupported("gateway_unavailable") from exc
    result = gateway.relay_for_caller(ctx, caller, known.id, method, path, headers, body, request_id)
    raw = result.body or b""
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    try:
        text: str | None = raw.decode("utf-8")
        encoded: str | None = None
    except UnicodeDecodeError:
        text = None
        encoded = base64.b64encode(raw).decode("ascii")
    relay_reason = getattr(result, "reason", None)
    if relay_reason is None:
        relay_reason = getattr(result, "blocked_reason", None)
    return {
        "status": int(result.status),
        "headers": _filter_response_headers(result.headers),
        "body": text,
        "body_base64": encoded,
        "reason": relay_reason,
    }


# --------------------------------------------------------------------- exec
def _resolve_program(program: str) -> str | None:
    """Absolute path of the profile's program if it exists and is executable; else ``None``."""
    candidate = program if os.sep in program else shutil.which(program, path=os.environ.get("PATH", DEFAULT_PATH))
    if not candidate:
        return None
    if not os.path.isfile(candidate) or not os.access(candidate, os.X_OK):
        return None
    return os.path.abspath(candidate)


def _child_env(run_dir: Path, run_id: str, specific: Mapping[str, str], extra_env: Mapping[str, str]) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", DEFAULT_PATH),
        "HOME": str(run_dir),
        "LANG": "C.UTF-8",
        "TMPDIR": str(run_dir),
        "ZEROPW_RUN_ID": run_id,
    }
    env.update(specific)
    for key, value in extra_env.items():
        if key in env:
            raise Unsupported("cli_env_conflict")
        env[key] = value
    return env


def _env_bytes(text: str) -> bytes:
    try:
        return os.fsencode(text)  # what subprocess hands the child
    except UnicodeError:
        return text.encode("utf-8", "surrogatepass")


def _profile_env_carries_credential(connection: Connection, credential: bytes) -> bool:
    """True if any admin-configured environment name/value of the CLI profile holds the credential.

    Product rule: no path puts the real secret into a child's environment.  The
    same encodings the output scan knows (raw, base64 variants, hex, URL
    encoding) are refused.
    """
    cli = connection.cli
    if cli is None:
        return False
    patterns = credential_patterns(credential)
    if not patterns:
        return False
    items = [cli.base_url_env, *cli.extra_env.keys(), *cli.extra_env.values()]
    return any(contains_sensitive(_env_bytes(item), patterns) for item in items if isinstance(item, str))


def _profile_env_carries_vault_value(ctx: Any, connection: Connection) -> bool:
    """True if the CLI profile's environment holds any vault value (every secret, every version and status)."""
    if connection.cli is None:
        return False
    try:
        values = ctx.vault.values_for_trusted_scan()
    except ZeroPWError as exc:
        raise StateError("credential_unavailable") from exc
    return any(_profile_env_carries_credential(connection, value) for value in values)


def _write_private_file(path: Path, text: str) -> Path:
    """Create ``path`` (0600, must not exist) inside the run directory and write ``text``."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(text)
    return path


def _write_known_hosts(run_dir: Path, target: SshTarget) -> Path:
    lines = []
    for key in target.host_keys:
        prefix = target.host if target.port == 22 else f"[{target.host}]:{target.port}"
        lines.append(f"{prefix} {key.strip()}")
    return _write_private_file(run_dir / "known_hosts", "\n".join(lines) + "\n")


def _ssh_public_key_line(ctx: Any, connection: Connection) -> str:
    """The connection key's PUBLIC half as an authorized_keys line, from vault metadata.

    With ``IdentitiesOnly=yes`` OpenSSH only offers agent keys that match an
    ``IdentityFile``; a public-key file is enough for that match, so the child
    gets the public line and nothing else.  Anything but a well-formed
    ssh-ed25519 line is refused (no fallback to other material).
    """
    from . import sshwire  # lazy: pure-Python key parsing

    try:
        resolved = ctx.vault.resolve_version(connection.secret_id, connection.secret_version)
        meta = ctx.vault.get_meta(connection.secret_id)
    except ZeroPWError as exc:
        raise StateError("credential_unavailable") from exc
    for version in meta.versions:
        if version.version != resolved:
            continue
        line = (version.public or {}).get("public_key")
        if isinstance(line, str):
            try:
                key = sshwire.parse_authorized_key(line)
            except sshwire.WireError:
                break
            return key.to_authorized_key(f"zeropw:{connection.id}")
        break
    raise Unsupported("ssh_public_key_unavailable")


def _make_cleanup(binding: Any, run_dir: Path | None) -> Callable[[], None]:
    def cleanup() -> None:
        if binding is not None:
            try:
                binding.close()
            except Exception:
                pass
        if run_dir is not None:
            shutil.rmtree(run_dir, ignore_errors=True)

    return cleanup


def _refuse_exec(ctx: Any, caller: str, connection: str, request_id: str | None, result: str, reason: str,
                 policy_version: int | None = None, target: str | None = None) -> None:
    ctx.audit.record("tools_exec", caller=caller, connection=connection, target=target, action="exec", result=result,
                     reason=reason, request_id=request_id, policy_version=policy_version)


def _probe_action(connection: Connection) -> Action:
    """An action inside the connection's own scope, used only to re-check grant and control state."""
    if connection.kind == "ssh" and connection.ssh_target is not None:
        return Action("ssh", username=connection.ssh_target.username)
    method, path = "GET", "/"
    scope = connection.http_scope
    if scope is not None:
        if scope.methods:
            method = scope.methods[0]
        if scope.path_prefixes:
            path = scope.path_prefixes[0]
    return Action("http", method=method, path=path)


def _recheck(ctx: Any, caller: str, connection: Connection, grant: Grant) -> str | None:
    """Reason the run must not start *now*, or ``None``.  Called immediately before spawning.

    Covers everything that may have changed since the first check: global
    stop, restore pending, principal/connection disablement, grant revocation,
    staleness (policy version), expiry and exhaustion.
    """
    if ctx.policy.restore_pending():
        return "restore_pending"
    if ctx.policy.is_stopped():
        return "global_stop"
    decision = ctx.policy.evaluate(caller, connection.id, _probe_action(connection), grant.id)
    return None if decision.allowed else decision.reason


def _setup_failure_reason(exc: BaseException) -> str:
    if isinstance(exc, (AuditUnavailable, StateError, Unsupported)) and exc.reason:
        return exc.reason
    return "exec_setup_failed"


def _exec_view(registry: RunRegistry, run: Any) -> dict[str, Any]:
    view = registry.view(run)
    return {"run_id": view["run_id"], "state": view["state"], "reason": view["reason"]}


def exec(ctx: Any, caller: str, connection: str, argv: list[str],  # noqa: A001 - name fixed by the tool contract
         request_id: str | None = None) -> dict[str, Any]:
    registry = _registry(ctx)
    argv = list(argv)
    digest = hashlib.sha256(json.dumps([connection, argv], separators=(",", ":")).encode("utf-8")).hexdigest()
    if request_id is not None:  # replay fast path; the authoritative reservation is find_or_create below
        existing = registry.find_by_request(caller, request_id, digest)
        if existing is not None:
            return _exec_view(registry, existing)

    known, grant, reason = _usable(ctx, caller, connection)
    if known is None or grant is None:
        _refuse_exec(ctx, caller, connection, request_id, "denied", reason)
        raise PolicyDenied(reason)
    target_label = _target_label(known)
    if known.cli is None:
        _refuse_exec(ctx, caller, known.id, request_id, "unsupported", "cli_not_supported", known.policy_version,
                     target_label)
        raise Unsupported("cli_not_supported")
    program = _resolve_program(known.cli.program)
    if program is None:
        _refuse_exec(ctx, caller, known.id, request_id, "unsupported", "cli_program_missing", known.policy_version,
                     target_label)
        raise Unsupported("cli_program_missing")
    public_url: str | None = None
    manager: Any = None
    if known.kind == "http":
        public_url = ctx.config.extra.get("public_url")
        if not isinstance(public_url, str) or not public_url:
            _refuse_exec(ctx, caller, known.id, request_id, "failed", "public_url_unset", known.policy_version,
                         target_label)
            raise StateError("public_url_unset")
    elif known.kind == "ssh":
        manager = getattr(ctx, "signer_manager", None)
        if manager is None or known.ssh_target is None:
            _refuse_exec(ctx, caller, known.id, request_id, "unsupported", "ssh_signer_unavailable",
                         known.policy_version, target_label)
            raise Unsupported("ssh_signer_unavailable")
    else:
        _refuse_exec(ctx, caller, known.id, request_id, "unsupported", "cli_kind_unsupported", known.policy_version,
                     target_label)
        raise Unsupported("cli_kind_unsupported")
    run_root = getattr(ctx.config, "run_dir", None)
    if run_root is None:
        raise StateError("run_dir_unset")

    # Registered before any slow work so a concurrent revoke/stop (on_revoke -> cancel_all) can see and
    # cancel the queued run; the request-id slot is reserved in the same critical section.
    run, created = registry.find_or_create(caller, known.id, grant.id, known.kind, program, request_id, digest,
                                           target=target_label, policy_version=known.policy_version)
    if not created:
        return _exec_view(registry, run)

    binding: Any = None
    run_dir: Path | None = None
    try:
        # Audit before any credential-bearing artefact (handle / signer socket) exists.
        ctx.audit.record("tools_exec", caller=caller, connection=known.id, target=target_label, action="exec",
                         result="ok", request_id=request_id, policy_version=known.policy_version,
                         extra={"program": program, "kind": known.kind, "grant": grant.id, "count": len(argv)})
        try:  # scan material only; the value never leaves this process
            credential = ctx.vault.secret_for_trusted_use(known.secret_id, known.secret_version)
        except ZeroPWError as exc:
            raise StateError("credential_unavailable") from exc
        if _profile_env_carries_vault_value(ctx, known):
            # No plaintext path into the child: refuse before any handle, socket or run directory exists.
            _refuse_exec(ctx, caller, known.id, request_id, "unsupported", "cli_env_contains_credential",
                         known.policy_version, target_label)
            raise Unsupported("cli_env_contains_credential")
        run_dir = Path(tempfile.mkdtemp(prefix=f"{run.id}-", dir=str(run_root))).resolve()
        os.chmod(run_dir, 0o700)
        sensitive: list[bytes] = [credential]
        if known.kind == "http":
            assert known.cli is not None and public_url is not None
            ttl = int(ctx.config.handle_ttl_seconds)
            ctx.audit.record("handle_issue", caller=caller, connection=known.id, target=target_label, run_id=run.id,
                             request_id=request_id, policy_version=known.policy_version, result="ok",
                             extra={"grant": grant.id, "expires_at": iso(ctx.clock() + ttl)})
            handle = ctx.handles.issue(caller, known.id, grant.id, known.policy_version, ttl)
            sensitive.append(handle.encode("utf-8"))
            env = _child_env(run_dir, run.id, {known.cli.base_url_env: f"{public_url.rstrip('/')}/h/{handle}"},
                             known.cli.extra_env)
            child_argv = [program, *argv]
        else:
            assert known.ssh_target is not None and known.cli is not None
            target = known.ssh_target
            public_key = _ssh_public_key_line(ctx, known)
            binding = manager.bind(caller, known.id, grant.id)
            known_hosts = _write_known_hosts(run_dir, target)
            identity = _write_private_file(run_dir / "id.pub", public_key + "\n")
            socket_path = str(binding.socket_path)
            env = _child_env(run_dir, run.id, {"SSH_AUTH_SOCK": socket_path}, known.cli.extra_env)
            # -F /dev/null first: neither the user's nor the system ssh_config is consulted.  The public
            # key file makes IdentitiesOnly=yes accept the agent key; the private key never exists here.
            child_argv = [
                program,
                "-F", "/dev/null",
                "-o", "IdentitiesOnly=yes",
                "-o", f"IdentityFile={identity}",
                "-o", f"IdentityAgent={socket_path}",
                "-o", "ForwardAgent=no",
                "-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={known_hosts}",
                "-o", "BatchMode=yes",
                "-o", "PasswordAuthentication=no",
                "-o", "KbdInteractiveAuthentication=no",
                "-p", str(target.port),
                f"{target.username}@{target.host}",
                "--", *argv,
            ]
        cleanup = _make_cleanup(binding, run_dir)
    except BaseException as exc:
        _make_cleanup(binding, run_dir)()
        registry.fail(run, _setup_failure_reason(exc))
        raise

    # Re-check immediately before spawning: a revoke/stop/disable that landed after the first check
    # must cancel this run instead of letting the child start under withdrawn policy.
    denial = _recheck(ctx, caller, known, grant)
    if denial is not None:
        cleanup()
        registry.cancel(run.id, caller, denial)  # audited run_cancel + run_finish with the policy reason
        _refuse_exec(ctx, caller, known.id, request_id, "denied", denial, known.policy_version, target_label)
        return _exec_view(registry, run)
    registry.start(run, child_argv, env, str(run_dir), sensitive, cleanup=cleanup)
    return _exec_view(registry, run)


# ----------------------------------------------------------- status/cancel
def status(ctx: Any, caller: str, run_id: str) -> dict[str, Any]:
    registry = _registry(ctx)
    try:
        run = registry.get(run_id, caller)
    except NotFound:
        ctx.audit.record("tools_status", caller=caller, run_id=run_id, action="status", result="denied",
                         reason="run_not_found")
        raise
    ctx.audit.record("tools_status", caller=caller, connection=run.connection, target=run.target, run_id=run.id,
                     action="status", result="ok", policy_version=run.policy_version, extra={"run_state": run.state})
    return registry.view(run)


def cancel(ctx: Any, caller: str, run_id: str) -> dict[str, Any]:
    registry = _registry(ctx)
    try:
        run = registry.get(run_id, caller)
    except NotFound:
        ctx.audit.record("tools_cancel", caller=caller, run_id=run_id, action="cancel", result="denied",
                         reason="run_not_found")
        raise
    # Cancelling is the safe direction: it is never refused because the log is unavailable (same rule as
    # RunRegistry._record_cancel).  Record best effort, cancel, then report the audit failure.
    audit_error: AuditUnavailable | None = None
    try:
        ctx.audit.record("tools_cancel", caller=caller, connection=run.connection, target=run.target, run_id=run.id,
                         action="cancel", result="ok", policy_version=run.policy_version,
                         extra={"run_state": run.state})
    except AuditUnavailable as exc:
        audit_error = exc
    registry.cancel(run.id, caller)
    if audit_error is not None:
        raise audit_error
    view = registry.view(run)
    return {"run_id": view["run_id"], "state": view["state"], "reason": view["reason"]}


__all__ = ["TOOL_NAMES", "install", "set_public_url", "dispatch", "list_connections", "request", "exec", "status",
           "cancel"]
