"""Administrator command-line interface for the ZeroPW prototype.

``python3.12 -m zeropw.admin_cli --state-dir DIR <command> ...``

Security scope
--------------
This is the *trusted administrator* surface.  It runs with direct access to
the 0700 state directory, which is exactly the authority an agent process must
never have (docs/security-design.md §6).  Nothing here is reachable from the
tools API, and the CLI never hands anything to an agent.

* Secret values enter only through ``--value-file`` or ``--stdin``.  They are
  never accepted on the command line, because argv is visible to every process
  on the host and ends up in shell history.
* The single documented plaintext path is ``secret reveal``: one secret, one
  version, after a fresh administrator re-authentication, with an audit record
  and an alert written *before* the value is decrypted (``Vault.reveal``).
  Every other command prints metadata only; listings never include
  ciphertext, nonces, or values.
* Passphrases come from ``ZEROPW_ADMIN_PASSPHRASE`` / ``ZEROPW_RECOVERY_PASSPHRASE``
  or an interactive ``getpass`` prompt, never from argv.
* Every mutating command produces a value-free audit record.  Core methods
  that already audit are used as-is; for the rest this module probes that the
  audit log is writable *before* changing state and records the event
  afterwards.  An unwritable audit log makes the command fail.
* Error output is fixed reason codes plus identifiers.  Unexpected exceptions
  are reported by class name only, so an exception message can never carry a
  value to the terminal.
* ``serve`` binds loopback addresses only.  The prototype's trusted process
  must not be exposed on a network interface; the production isolation
  boundary is a separate host/identity, not a listen address.
* ``serve --team-listen HOST:PORT`` (docs/team-sync.md section 6.1) opens a
  *second*, separate socket for team sync only -- never implied by, and
  never sharing a port with, the tools/relay listener above.  This one is
  explicitly LAN/VPN-facing: team members' devices are not all on loopback,
  and there is no default (omit the flag and no team socket is opened at
  all, whether or not this node has any shared environment).  Every
  connection to it must complete the mutual-authentication handshake of
  section 6.2 before any other byte is accepted; a failure closes the
  socket without returning anything, and the tools/relay listener's
  loopback restriction is unrelated to and unaffected by this flag.

Limitations (prototype)
-----------------------
* The KMS is ``LocalFileKms``; the state directory mode is the only isolation
  on a shared host.
* Revocation, ``stop-all`` and ``restore`` written by this CLI are applied by a
  separately running ``serve`` process on its next relay or signature: the
  last-moment ``Policy.consume`` re-reads the state under the lock.  Within
  one poll interval (``SERVE_POLL_SECONDS``) ``serve`` also re-checks every
  queued or running execution and every signer socket against the state on
  disk: a revoked or stale grant, a disabled principal or connection, a
  global stop or a pending restore cancels the affected executions (audited
  ``run_cancel``) and closes the affected signer sockets.  ``serve`` reloads
  the handle key when ``restore`` or ``recover`` rotated it.  Already
  authenticated SSH sessions are outside the product's control (documented
  in the security design).
* ``recover`` needs a state directory that still opens.  ``restore`` refuses
  an archive whose wrapped DEK the current KMS key cannot open
  (``backup_kms_mismatch``) instead of writing a state that no command could
  reopen; such an archive must be restored and recovered with the core
  ``Vault.restore`` / ``Vault.recover`` APIs directly.
* ``restore`` keeps a global stop that is set at restore time, re-applies every
  revocation recorded in the revocation ledger or the audit log (grant
  revoke/regrant, principal disable, connection disable, secret version
  revoke), rotates the handle key and never reopens an approval; ``restore-ack``
  re-applies them once more before it clears ``restore_pending``.  Changes
  that are not revocations (for example a scope change or a new secret
  version made after the backup) are rolled back to the archive and must be
  redone.  Revocations are keyed by id and never expire: a principal or
  connection id that was disabled once stays disabled after any later
  restore, so a replacement needs a new id.
* Retiring a version in the vault does not revoke the credential at the
  provider.  ``rotation finish`` prints that reminder; it cannot do it.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import importlib
import ipaddress
import json
import os
import re
import secrets
import signal
import sys
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Sequence
from urllib.parse import urlsplit

from . import policy as P
from .audit import ALERT_FILE, AUDIT_FILE
from .context import HANDLE_KEY, Config, Context
from .errors import AuditUnavailable, AuthFailed, InvalidInput, NotFound, Unsupported, ZeroPWError
from .handles import HandleIssuer
from .projects import DEFAULT_ENVIRONMENTS
from .server import ZeroPWServer
from .store import iso
from .vault import MAX_SECRET_BYTES, SECRET_KINDS, Vault

ADMIN_PASSPHRASE_ENV = "ZEROPW_ADMIN_PASSPHRASE"
RECOVERY_PASSPHRASE_ENV = "ZEROPW_RECOVERY_PASSPHRASE"
MIN_PASSPHRASE_LENGTH = 8
DEFAULT_GRANT_TTL = "1h"
DEFAULT_LISTEN = "127.0.0.1:0"
DEFAULT_HTTP_METHODS = ("GET", "HEAD")
HTTP_SECRET_KINDS = ("api_key", "password", "env_var")
SSH_SECRET_KINDS = ("ssh_private_key",)
ADMIN_CALLER = "admin"
SERVE_POLL_SECONDS = 0.25
TTL_RE = re.compile(r"([0-9]+)([smhd]?)")
# Version metadata keys that may be printed: public SSH key material only, never anything
# derived from a secret value (a hash prefix or length would be an offline oracle).
PUBLIC_METADATA_KEYS = ("public_key", "fingerprint", "algorithm")
RESTORE_NEXT = ("revocations recorded after the backup (grant revoke/regrant, principal disable, connection "
                "disable, secret revoke) were re-applied and the handle key was rotated; approvals keep their "
                "current state (open approvals that exist only in the archive were dropped; re-approve if needed). "
                "Redo non-revocation changes made after the backup (scope, rotation), review grant list, then "
                "restore-ack (a global stop stays set until resume)")
PROVIDER_REMINDER = ("Retiring a vault version does not revoke the credential at the provider. "
                     "Revoke the old credential in the provider's console or API now.")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

Handler = Callable[[argparse.Namespace], "dict[str, Any] | None"]


# ----------------------------------------------------------------- output helpers
def _emit(payload: Any, *, compact: bool = False) -> None:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":")) if compact else json.dumps(payload, sort_keys=True, indent=2)
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def _emit_error(payload: dict[str, Any]) -> None:
    sys.stderr.write(json.dumps(payload, sort_keys=True) + "\n")
    sys.stderr.flush()


def _notice(message: str) -> None:
    sys.stderr.write(message + "\n")
    sys.stderr.flush()


class _Parser(argparse.ArgumentParser):
    """argparse with JSON usage errors (exit code 2) and no option abbreviation.

    Abbreviation is off for every (sub)parser: with it on, ``--value X`` would
    silently become ``--value-file X`` and a secret typed on the command line
    would be accepted as a path.  Unrecognized arguments are reported by count;
    the only tokens ever named are those that are, or abbreviate, an option
    registered somewhere in the command tree (``--value`` for ``--value-file``).
    Anything else on argv, including a token that merely starts with ``-``,
    could be a secret typed by mistake and is never echoed.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)

    def parse_args(self, args: Sequence[str] | None = None, namespace: Any = None) -> Any:  # type: ignore[override]
        parsed, extras = self.parse_known_args(args, namespace)
        if extras:
            self.error(self._unrecognized_detail(extras))
        return parsed

    def _registered_options(self) -> set[str]:
        registered: set[str] = set()
        pending: list[argparse.ArgumentParser] = [self]
        while pending:
            parser = pending.pop()
            registered.update(parser._option_string_actions)
            for action in parser._actions:
                choices = getattr(action, "choices", None)
                if isinstance(choices, dict):  # a subcommand action: recurse into its parsers
                    pending.extend(p for p in choices.values() if isinstance(p, argparse.ArgumentParser))
        return registered

    def _unrecognized_detail(self, extras: Sequence[str]) -> str:
        registered = self._registered_options()
        names = sorted({name for name in (item.split("=", 1)[0] for item in extras)
                        if name.startswith("--") and len(name) > 2
                        and any(option.startswith(name) for option in registered)})
        detail = f"unrecognized arguments: {len(extras)}"
        if names:
            detail += " (not accepted: " + " ".join(names) + ")"
        return detail + "; values are not echoed"

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        _emit_error({"error": "UsageError", "reason": "usage", "detail": message})
        self.exit(EXIT_USAGE)


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if value < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value


# --------------------------------------------------------------- input helpers
def _passphrase(env_name: str, prompt: str) -> str:
    value = os.environ.get(env_name)
    if value:
        return value
    stdin = sys.stdin
    if stdin is not None and hasattr(stdin, "isatty") and stdin.isatty():
        return getpass.getpass(prompt)
    raise AuthFailed("passphrase_missing", f"set {env_name} or run on a terminal")


def _check_passphrase_strength(value: str, what: str) -> str:
    if len(value) < MIN_PASSPHRASE_LENGTH:
        raise InvalidInput("passphrase_too_short", f"{what} passphrase needs at least {MIN_PASSPHRASE_LENGTH} characters")
    return value


def _read_stdin_bytes(limit: int) -> bytes:
    stream = sys.stdin
    if stream is None:
        raise InvalidInput("stdin_unavailable")
    buffer = getattr(stream, "buffer", None)
    if buffer is not None:
        return buffer.read(limit)
    return stream.read(limit).encode("utf-8")


def _read_secret_value(args: argparse.Namespace, kind: str) -> bytes:
    """Secret bytes from ``--value-file`` or ``--stdin`` (mutually exclusive, one required)."""
    limit = MAX_SECRET_BYTES + 1
    if getattr(args, "value_file", None):
        with open(args.value_file, "rb") as stream:
            data = stream.read(limit)
    elif getattr(args, "stdin", False):
        data = _read_stdin_bytes(limit)
    else:  # argparse enforces the group; keep the fail-closed default anyway
        raise InvalidInput("secret_source_required", "use --value-file or --stdin")
    if kind not in SSH_SECRET_KINDS:
        # Editors and `echo` append a newline that is not part of a token.
        if data.endswith(b"\r\n"):
            data = data[:-2]
        elif data.endswith(b"\n"):
            data = data[:-1]
    if not data:
        raise InvalidInput("empty_secret_value")
    return data


def _csv(value: str | None) -> list[str]:
    if value is None:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _methods(value: str | None, default: tuple[str, ...] | None) -> tuple[str, ...] | None:
    if value is None:
        return default
    if value.strip().lower() == "all":
        return None
    items = tuple(item.upper() for item in _csv(value))
    if not items:
        raise InvalidInput("invalid_method", "empty method list")
    return items


def _path_prefixes(value: str | None, default: tuple[str, ...] | None) -> tuple[str, ...] | None:
    if value is None:
        return default
    if value.strip().lower() == "all":
        return None
    items = tuple(_csv(value))
    if not items:
        raise InvalidInput("invalid_path_prefix", "empty prefix list")
    return items


def _confirm_methods(value: str | None, default: tuple[str, ...]) -> tuple[str, ...]:
    if value is None:
        return default
    if value.strip().lower() in ("none", ""):
        return ()
    return tuple(item.upper() for item in _csv(value))


def _parse_ttl(text: str) -> int:
    units = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}
    match = TTL_RE.fullmatch(text.strip().lower())  # ASCII digits only: str.isdigit() also accepts '²' and '٣'
    if match is None:
        raise InvalidInput("invalid_ttl", "use forms like 30m, 1h, 3600s or 86400")
    seconds = int(match.group(1)) * units[match.group(2)]
    if seconds <= 0:
        raise InvalidInput("invalid_ttl")
    return seconds


def _parse_target(text: str) -> tuple[str, str, int]:
    """``scheme://host[:port]`` with no path, query, fragment or userinfo."""
    try:
        parts = urlsplit(text.strip())
        host = parts.hostname
    except ValueError as exc:  # malformed bracketed host such as http://[::1 or http://[evil]
        raise InvalidInput("invalid_host") from exc
    if parts.scheme not in ("http", "https"):
        raise InvalidInput("invalid_scheme", "target must start with http:// or https://")
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username or parts.password:
        raise InvalidInput("target_must_be_origin", "target is scheme://host[:port] only")
    try:
        port = parts.port
    except ValueError as exc:
        raise InvalidInput("invalid_port") from exc
    if not host:
        raise InvalidInput("invalid_host")
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return parts.scheme, host, port


def _parse_env_assignments(items: Sequence[str] | None) -> dict[str, str]:
    env: dict[str, str] = {}
    for item in items or ():
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise InvalidInput("invalid_cli_env", "use KEY=VALUE")
        env[key] = value
    return env


def _parse_listen(text: str) -> tuple[str, int]:
    raw = text.strip()
    host, sep, port_text = raw.rpartition(":")
    if not sep:
        raise InvalidInput("invalid_listen", "use HOST:PORT")
    host = host.strip("[]")
    if not port_text.isdigit() or not 0 <= int(port_text) <= 65535:
        raise InvalidInput("invalid_listen", "port must be 0-65535")
    return host, int(port_text)


def _require_loopback(host: str) -> None:
    if host == "localhost":
        return
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and address.is_loopback:
        if address.version == 6:  # the server is AF_INET only; say so instead of failing in the resolver
            raise Unsupported("listen_ipv6_unsupported", "the trusted process binds IPv4 loopback only")
        return
    raise Unsupported("listen_not_loopback", "the trusted process binds loopback addresses only")


# ---------------------------------------------------------------- state helpers
def _state_dir(args: argparse.Namespace) -> Path:
    return Path(args.state_dir).expanduser()


def _open(args: argparse.Namespace, *, mutating: bool = False) -> Context:
    """Open the state; for mutating commands, fail closed before touching state if the audit log is unwritable."""
    ctx = Context.open(_state_dir(args))
    if mutating:
        ctx.audit.require_writable()
    return ctx


def _admin_record(ctx: Context, event: str, **fields: Any) -> None:
    ctx.audit.record(event, caller=ADMIN_CALLER, **fields)


def _record_auth_failure(ctx: Context, reason: str, **extra: Any) -> None:
    try:
        _admin_record(ctx, "auth_failed", result="denied", reason=reason, extra=extra or None)
    except AuditUnavailable:
        pass  # the caller is already refusing; nothing more to protect


# ------------------------------------------------------------------ views
def _secret_view(meta: Any) -> dict[str, Any]:
    return {
        "id": meta.id, "project": meta.project, "environment": meta.environment, "kind": meta.kind,
        "active_version": meta.active_version,
        "versions": [{"version": v.version, "status": v.status, "created_at": v.created_at,
                      "public": {k: v.public[k] for k in PUBLIC_METADATA_KEYS if k in v.public}}
                     for v in meta.versions],
    }


def _grant_view(grant: P.Grant) -> dict[str, Any]:
    view = asdict(grant)
    view["expires_at"] = iso(grant.expires_at) if grant.expires_at is not None else None
    return view


def _principal_view(principal: P.Principal) -> dict[str, Any]:
    return {"id": principal.id, "status": principal.status, "created_at": principal.created_at}


def _connection_view(connection: P.Connection) -> dict[str, Any]:
    return connection.to_dict()


def _control_view(ctx: Context) -> dict[str, Any]:
    return {"stopped": ctx.policy.is_stopped(), "restore_pending": ctx.policy.restore_pending()}


# ------------------------------------------------------- team sync (docs/team-sync.md section 12)
def _connection_shared_env(ctx: Context, connection_id: str) -> str | None:
    doc = ctx.state.read_json(P.CONNECTIONS, {}) or {}
    entry = doc.get(connection_id)
    return entry.get("shared_env") if isinstance(entry, dict) else None


def _secret_shared_env(ctx: Context, secret_id: str) -> str | None:
    from .vault import VAULT_DOC

    doc = ctx.state.read_json(VAULT_DOC, {}) or {}
    entry = (doc.get("secrets") or {}).get(secret_id)
    return entry.get("shared_env") if isinstance(entry, dict) else None


def _project_env_shared_env(ctx: Context, project: str, environment: str) -> str | None:
    from .team import sync as team_sync_mod

    return team_sync_mod.resolve_env_id(ctx.state, project, environment)


def _shared_version_id(ctx: Context, secret_id: str, local_version: int) -> str:
    """The environment document's own version id for a locally-numbered shared secret version
    (docs/team-sync.md section 5.1: the integer is a node-local display convenience derived at
    fold time; commits and connection definitions always address a version by its real id)."""
    from .vault import VAULT_DOC

    doc = ctx.state.read_json(VAULT_DOC, {}) or {}
    entry = (doc.get("secrets") or {}).get(secret_id) or {}
    record = (entry.get("versions") or {}).get(str(local_version))
    if not isinstance(record, dict) or "version_id" not in record:
        raise NotFound("secret_version_not_found")
    return record["version_id"]


def _current_generation_dek(ctx: Context, env_id: str) -> tuple[str, bytes]:
    from .kms import WrappedKey
    from .team import membership as M

    doc = M.load_environment(ctx, env_id).document
    generation_id = doc.get("dek", {}).get("current")
    if not generation_id:
        raise InvalidInput("team_env_no_generation")
    wrapped = ctx.state.read_json(f"team/{env_id}/dek/{generation_id}.json", None)
    if not wrapped:
        raise InvalidInput("team_dek_generation_missing")
    dek = ctx.kms.unwrap(WrappedKey.from_dict(wrapped))
    return generation_id, dek


def _team_commit_output(ctx: Context, env_id: str, ops: list[dict[str, Any]]) -> tuple[dict[str, Any], Any]:
    """Author one commit against a shared environment from this (separate, one-shot) admin CLI
    process; a running ``serve``'s own ``TeamSync`` picks it up and broadcasts it on its next poll
    (docs/team-sync.md section 12).  This process holds no live session of its own, so
    ``propagated_to`` is always 0 here -- never a live broadcast count."""
    from .team import membership as M

    commit_obj = M.author_commit(ctx, None, env_id, ops)
    return {"commit": {"author_seq": commit_obj.author_seq, "hlc": commit_obj.hlc}, "propagated_to": 0}, commit_obj


def _team_fact_output(ctx: Context, env_id: str, kind: str, **target: Any) -> dict[str, Any]:
    from .team import membership as M

    fact = M.author_fact(ctx, None, env_id, kind, **target)
    fact_hash = hashlib.sha256(json.dumps(fact, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return {"fact": {"hash": fact_hash}, "propagated_to": 0}


def _connection_to_share_op(connection: P.Connection, conn_id: str, secret_version_id: str | None) -> dict[str, Any]:
    data = connection.to_dict()
    for key in ("id", "policy_version", "status", "created_at", "updated_at"):
        data.pop(key, None)
    data["secret_version"] = secret_version_id
    return {"op": "connection.create", "id": conn_id, **data}


# ------------------------------------------------------------------ commands
def cmd_init(args: argparse.Namespace) -> dict[str, Any]:
    admin = _check_passphrase_strength(_passphrase(ADMIN_PASSPHRASE_ENV, "Administrator passphrase: "), "administrator")
    recovery = _check_passphrase_strength(_passphrase(RECOVERY_PASSPHRASE_ENV, "Recovery passphrase: "), "recovery")
    if admin == recovery:
        raise InvalidInput("passphrases_identical", "the recovery passphrase must be independent of the admin one")
    ctx = Context.initialize(_state_dir(args), admin, recovery)
    return {"state_dir": str(ctx.state.path), "kms_key_id": ctx.kms.key_id}


def cmd_project_create(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    environments = tuple(_csv(args.environments)) if args.environments else DEFAULT_ENVIRONMENTS
    project = ctx.projects.create(args.name, environments)
    _admin_record(ctx, "project_create", result="ok", extra={"project": project.name, "count": len(project.environments)})
    return {"name": project.name, "environments": list(project.environments), "created_at": project.created_at}


def cmd_project_list(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args)
    return {"projects": [{"name": p.name, "environments": list(p.environments), "created_at": p.created_at}
                         for p in ctx.projects.list()]}


def _shared_secret_put(ctx: Context, env_id: str, args: argparse.Namespace, value: bytes) -> dict[str, Any]:
    from .team import envelope as team_envelope
    from .vault import Vault

    generation_id, dek = _current_generation_dek(ctx, env_id)
    public = Vault._public_metadata(args.kind, value)
    version_id = secrets.token_hex(8)
    ciphertext = team_envelope.encrypt_secret(dek, env_id, args.id, version_id, value)
    put_op = {"op": "secret.put_version", "secret_id": args.id, "kind": args.kind, "generation_id": generation_id,
             "version_id": version_id, "ciphertext": ciphertext, "public": public}
    result, _ = _team_commit_output(ctx, env_id, [put_op])
    if not args.staged:
        result, _ = _team_commit_output(ctx, env_id, [{"op": "secret.activate", "secret_id": args.id,
                                                       "version_id": version_id}])
    return {"id": args.id, "version_id": version_id, "status": "staged" if args.staged else "active",
           "kind": args.kind, "project": args.project, "environment": args.environment, **result}


def cmd_secret_put(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    value = _read_secret_value(args, args.kind)
    env_id = _project_env_shared_env(ctx, args.project, args.environment)
    if env_id is not None:
        return _shared_secret_put(ctx, env_id, args, value)
    with ctx.state.lock():  # check and write in one critical section (a concurrent connection save waits)
        _refuse_value_in_existing_cli_env(ctx, args.id, value, "secret_put")
        version = ctx.vault.put_secret(args.id, args.kind, value, args.project, args.environment,
                                       activate=not args.staged)
    return {"id": args.id, "version": version, "status": "staged" if args.staged else "active", "kind": args.kind,
            "project": args.project, "environment": args.environment}


def cmd_secret_list(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args)
    return {"secrets": [_secret_view(m) for m in ctx.vault.list_secrets(args.project, args.environment)]}


def cmd_secret_versions(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args)
    return _secret_view(ctx.vault.get_meta(args.id))


def cmd_secret_reveal(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args)
    passphrase = _passphrase(ADMIN_PASSPHRASE_ENV, "Administrator passphrase: ")
    try:
        auth = ctx.admin.verify(passphrase)
    except AuthFailed as exc:
        _record_auth_failure(ctx, exc.reason, secret_id=args.id)
        raise
    value = ctx.vault.reveal(args.id, args.version, auth)
    resolved = ctx.vault.resolve_version(args.id, args.version)
    payload: dict[str, Any] = {"id": args.id, "version": resolved}
    try:
        payload["value"] = value.decode("utf-8")
    except UnicodeDecodeError:
        payload["value_base64"] = base64.b64encode(value).decode("ascii")
        payload["encoding"] = "base64"
    return payload


def _connections_pinned_to(ctx: Context, secret_id: str, version: int) -> list[str]:
    return [c.id for c in ctx.policy.list_connections()
            if c.secret_id == secret_id and c.secret_version == version and c.status == "active"]


def _connections_using(ctx: Context, secret_id: str) -> list[str]:
    return [c.id for c in ctx.policy.list_connections() if c.secret_id == secret_id and c.status == "active"]


def _retire_version(ctx: Context, secret_id: str, version: int) -> dict[str, Any]:
    meta = ctx.vault.get_meta(secret_id)
    if meta.active_version == version:
        raise InvalidInput("version_is_active", "activate another version first (rotation activate)")
    pinned = _connections_pinned_to(ctx, secret_id, version)
    if pinned:
        raise InvalidInput("version_in_use", "pinned by connections: " + ",".join(pinned))
    ctx.vault.set_version_status(secret_id, version, "retired")
    return {"secret_id": secret_id, "version": version, "status": "retired"}


def cmd_secret_retire(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    env_id = _secret_shared_env(ctx, args.id)
    if env_id is not None:
        version_id = _shared_version_id(ctx, args.id, args.version)
        result, _ = _team_commit_output(ctx, env_id, [{"op": "secret.set_status", "secret_id": args.id,
                                                       "version_id": version_id, "status": "retired"}])
        return {"secret_id": args.id, "version": args.version, "status": "retired", **result}
    return _retire_version(ctx, args.id, args.version)


def cmd_secret_revoke(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    env_id = _secret_shared_env(ctx, args.id)
    if env_id is not None:
        version_id = _shared_version_id(ctx, args.id, args.version)
        result = _team_fact_output(ctx, env_id, "secret_version_revoked", secret_id=args.id, version_id=version_id)
        return {"secret_id": args.id, "version": args.version, "status": "revoked",
               "provider_revocation_required": True, "reminder": PROVIDER_REMINDER, **result}
    meta = ctx.vault.get_meta(args.id)
    affected = _connections_pinned_to(ctx, args.id, args.version)
    if meta.active_version == args.version:
        affected = sorted(set(affected) | {c.id for c in ctx.policy.list_connections()
                                            if c.secret_id == args.id and c.secret_version is None and c.status == "active"})
    ctx.vault.set_version_status(args.id, args.version, "revoked")
    return {"secret_id": args.id, "version": args.version, "status": "revoked",
            "affected_connections": affected, "provider_revocation_required": True, "reminder": PROVIDER_REMINDER}


def _check_secret_for_connection(ctx: Context, secret_id: str, secret_version: int | None, project: str,
                                 environment: str, kind: str) -> Any:
    meta = ctx.vault.get_meta(secret_id)
    if (meta.project, meta.environment) != (project, environment):
        raise InvalidInput("secret_scope_mismatch", "secret belongs to another project/environment")
    allowed = HTTP_SECRET_KINDS if kind == "http" else SSH_SECRET_KINDS
    if meta.kind not in allowed:
        raise InvalidInput("secret_kind_mismatch", f"{kind} connections need a secret of kind {'/'.join(allowed)}")
    # A pinned version must exist and be usable; an unpinned connection needs an active version.
    # Otherwise the connection could never relay and the admin would only learn it from agent failures.
    resolved = ctx.vault.resolve_version(secret_id, secret_version)
    status = next((v.status for v in meta.versions if v.version == resolved), None)
    if status not in ("active", "staged"):
        raise InvalidInput("secret_version_unusable", str(status))
    return meta


def _refuse_credential_in_cli_env(ctx: Context, connection: P.Connection, values: list[bytes], event: str,
                                  secret_id: str | None = None) -> None:
    """Product rule: no vault value goes into a CLI child's environment, not even as configuration.

    Checked when a connection is saved (against every version, whatever its
    status, of every secret in the vault) and when a new secret version is
    added (against every connection's profile, whatever secret it uses).  The
    exec-time check in ``zeropw.tools`` stays authoritative; this keeps the
    value out of ``policy/connections.json`` and backups in the first place.
    Callers hold the state lock across this check and the write it guards.
    Only the connection id is reported, never the matching value.
    """
    if connection.cli is None:
        return
    from . import tools  # lazy: the exec module is not needed for most admin commands

    for value in values:
        if tools._profile_env_carries_credential(connection, value):
            _admin_record(ctx, event, connection=connection.id, result="denied", reason="cli_env_contains_credential",
                          extra={"secret_id": secret_id} if secret_id else None)
            raise InvalidInput("cli_env_contains_credential", connection.id)


def _refuse_value_in_existing_cli_env(ctx: Context, secret_id: str, value: bytes, event: str) -> None:
    for connection in ctx.policy.list_connections():
        _refuse_credential_in_cli_env(ctx, connection, [value], event, secret_id)


def _create_connection(ctx: Context, connection: P.Connection, target: str, extra: dict[str, Any]) -> P.Connection:
    ctx.projects.require_environment(connection.project, connection.environment)
    _check_secret_for_connection(ctx, connection.secret_id, connection.secret_version, connection.project,
                                 connection.environment, connection.kind)
    with ctx.state.lock():  # check and write in one critical section (a concurrent secret put waits)
        if connection.cli is not None:
            _refuse_credential_in_cli_env(ctx, connection, ctx.vault.values_for_trusted_scan(), "connection_create")
        stamped = ctx.policy.create_connection(connection)
    _admin_record(ctx, "connection_create", connection=stamped.id, target=target, result="ok",
                  policy_version=stamped.policy_version,
                  extra={"kind": stamped.kind, "service": stamped.service, "project": stamped.project,
                         "environment": stamped.environment, "secret_id": stamped.secret_id,
                         "version": stamped.secret_version, **extra})
    return stamped


def cmd_connection_create_http(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    scheme, host, port = _parse_target(args.target)
    ca_file = None
    if args.ca_file:
        ca_path = Path(args.ca_file).expanduser()
        if not ca_path.is_file():
            raise InvalidInput("ca_file_missing", str(ca_path))
        ca_file = str(ca_path.resolve())
    http_target = P.HttpTarget(scheme, host, port, ca_file, bool(args.allow_private_network))
    http_auth = P.HttpAuth(args.auth, header_name=args.header_name, value_prefix=args.value_prefix,
                           basic_username=args.basic_username)
    http_scope = P.HttpScope(_methods(args.methods, DEFAULT_HTTP_METHODS), _path_prefixes(args.path_prefixes, None),
                             _confirm_methods(args.confirm_methods, ()))
    cli = P.CliProfile(args.cli_program, "http", extra_env=_parse_env_assignments(args.cli_env)) if args.cli_program else None
    connection = P.Connection(
        id=args.id, project=args.project, environment=args.environment, service=args.service, kind="http",
        secret_id=args.secret_id, secret_version=args.secret_version, description=args.description or "",
        http_target=http_target, http_auth=http_auth, http_scope=http_scope, ssh_target=None, cli=cli,
        policy_version=0, status="active", created_at="", updated_at="",
    )
    env_id = _project_env_shared_env(ctx, args.project, args.environment)
    if env_id is not None:
        secret_version_id = (_shared_version_id(ctx, args.secret_id, args.secret_version)
                             if args.secret_version is not None else None)
        op = _connection_to_share_op(connection, args.id, secret_version_id)
        result, _ = _team_commit_output(ctx, env_id, [op])
        return {**_connection_view(ctx.policy.get_connection(args.id)), **result}
    stamped = _create_connection(ctx, connection, http_target.origin,
                                 {"scheme": scheme, "host": host, "port": port, "method": args.auth})
    return _connection_view(stamped)


def cmd_connection_create_ssh(args: argparse.Namespace) -> dict[str, Any]:
    from . import sshwire

    ctx = _open(args, mutating=True)
    host_keys: list[str] = []
    for line in args.host_key:
        try:
            entry = sshwire.parse_authorized_key_entry(line)
        except sshwire.WireError as exc:
            raise InvalidInput("invalid_host_key", type(exc).__name__) from exc
        if entry.options.startswith("@"):  # known_hosts markers (@revoked, @cert-authority) are not host keys
            raise InvalidInput("invalid_host_key", "known_hosts_marker")
        # Store the canonical "ssh-ed25519 <b64> [comment]" line: tabs or an authorized_keys
        # options field would otherwise be refused downstream as an unsupported key.
        host_keys.append(entry.key.to_authorized_key(entry.comment))
    ssh_target = P.SshTarget(args.host, args.port, args.username, tuple(host_keys))
    cli = P.CliProfile(args.cli_program, "ssh") if args.cli_program else None
    connection = P.Connection(
        id=args.id, project=args.project, environment=args.environment, service=args.service, kind="ssh",
        secret_id=args.secret_id, secret_version=args.secret_version, description=args.description or "",
        http_target=None, http_auth=None, http_scope=None, ssh_target=ssh_target, cli=cli,
        policy_version=0, status="active", created_at="", updated_at="",
    )
    env_id = _project_env_shared_env(ctx, args.project, args.environment)
    if env_id is not None:
        secret_version_id = (_shared_version_id(ctx, args.secret_id, args.secret_version)
                             if args.secret_version is not None else None)
        op = _connection_to_share_op(connection, args.id, secret_version_id)
        result, _ = _team_commit_output(ctx, env_id, [op])
        stamped = ctx.policy.get_connection(args.id)
    else:
        stamped = _create_connection(ctx, connection, f"{ssh_target.host}:{ssh_target.port}",
                                     {"host": ssh_target.host, "port": ssh_target.port, "username": ssh_target.username})
        result = {}
    view = _connection_view(stamped)
    meta = ctx.vault.get_meta(stamped.secret_id)
    resolved = ctx.vault.resolve_version(stamped.secret_id, stamped.secret_version) if (
        stamped.secret_version is not None or meta.active_version is not None) else None
    for item in meta.versions:
        if item.version == resolved:
            view["public_key"] = item.public.get("public_key")
            view["fingerprint"] = item.public.get("fingerprint")
    view.update(result)
    return view


def cmd_connection_list(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args)
    return {"connections": [_connection_view(c) for c in ctx.policy.list_connections()]}


def cmd_connection_show(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args)
    return _connection_view(ctx.policy.get_connection(args.id))


def cmd_connection_update_scope(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    before = ctx.policy.get_connection(args.id)
    if before.kind != "http" or before.http_scope is None:
        raise InvalidInput("scope_requires_http", "only HTTP connections carry a method/path scope")
    if args.methods is None and args.path_prefixes is None and args.confirm_methods is None:
        raise InvalidInput("no_scope_changes", "give --methods, --path-prefixes or --confirm-methods")
    scope = P.HttpScope(_methods(args.methods, before.http_scope.methods),
                        _path_prefixes(args.path_prefixes, before.http_scope.path_prefixes),
                        _confirm_methods(args.confirm_methods, before.http_scope.confirm_methods))
    env_id = _connection_shared_env(ctx, args.id)
    if env_id is not None:
        from dataclasses import asdict as _asdict

        op = {"op": "connection.update", "id": args.id, "http_scope": _asdict(scope)}
        result, _ = _team_commit_output(ctx, env_id, [op])
        after = ctx.policy.get_connection(args.id)
        return {"id": after.id, "policy_version": after.policy_version, "scope": after.public_view().get("scope"),
               **result}
    after, widened = ctx.policy.update_connection(args.id, http_scope=scope)
    _admin_record(ctx, "connection_update", connection=after.id, result="ok", policy_version=after.policy_version,
                  extra={"detail": "scope", "state": "widened" if widened else "narrowed"})
    return {"id": after.id, "widened": widened, "policy_version": after.policy_version,
            "scope": after.public_view().get("scope"),
            "note": "existing grants are stale and need regrant" if widened else "existing grants re-evaluated in place"}


def _switch_credential(ctx: Context, connection_id: str, version: int) -> P.Connection:
    before = ctx.policy.get_connection(connection_id)
    meta = ctx.vault.get_meta(before.secret_id)
    status = next((v.status for v in meta.versions if v.version == version), None)
    if status is None:
        raise NotFound("secret_version_not_found")
    if status not in ("active", "staged"):
        raise InvalidInput("secret_version_unusable", status)
    after = ctx.policy.switch_credential(connection_id, version)
    _admin_record(ctx, "connection_switch_credential", connection=after.id, result="ok",
                  policy_version=after.policy_version, extra={"secret_id": after.secret_id, "version": version})
    return after


def cmd_connection_switch_credential(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    env_id = _connection_shared_env(ctx, args.id)
    if env_id is not None:
        connection = ctx.policy.get_connection(args.id)
        version_id = _shared_version_id(ctx, connection.secret_id, args.version)
        op = {"op": "connection.switch_credential", "id": args.id, "secret_id": connection.secret_id,
             "secret_version": version_id}
        result, _ = _team_commit_output(ctx, env_id, [op])
        after = ctx.policy.get_connection(args.id)
        return {"id": after.id, "secret_id": after.secret_id, "secret_version": after.secret_version,
               "policy_version": after.policy_version, **result}
    after = _switch_credential(ctx, args.id, args.version)
    return {"id": after.id, "secret_id": after.secret_id, "secret_version": after.secret_version,
            "policy_version": after.policy_version}


def cmd_connection_disable(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    env_id = _connection_shared_env(ctx, args.id)
    if env_id is not None:
        result = _team_fact_output(ctx, env_id, "connection_disabled", connection_id=args.id)
        after = ctx.policy.get_connection(args.id)
        return {"id": after.id, "status": after.status, "policy_version": after.policy_version, **result}
    after = ctx.policy.disable_connection(args.id)
    _admin_record(ctx, "connection_disable", connection=after.id, result="ok", policy_version=after.policy_version)
    return {"id": after.id, "status": after.status, "policy_version": after.policy_version}


def cmd_principal_create(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    token = ctx.policy.create_principal(args.id)
    _admin_record(ctx, "principal_create", result="ok", extra={"principal": args.id})
    return {"id": args.id, "token": token,
            "note": "shown once; only its hash is stored. Give it to the agent runtime, never to a vault."}


def cmd_principal_list(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args)
    return {"principals": [_principal_view(p) for p in ctx.policy.list_principals()]}


def cmd_principal_disable(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    ctx.policy.disable_principal(args.id)
    _admin_record(ctx, "principal_disable", result="ok", extra={"principal": args.id})
    return {"id": args.id, "status": "disabled"}


def cmd_grant_create(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    ttl = _parse_ttl(args.ttl)
    grant = ctx.policy.create_grant(args.principal, args.connection, ttl, args.max_uses)
    _admin_record(ctx, "grant_create", connection=grant.connection, result="ok", policy_version=grant.policy_version,
                  extra={"grant": grant.id, "principal": grant.principal, "max_uses": grant.max_uses,
                         "expires_at": iso(grant.expires_at) if grant.expires_at else None})
    return _grant_view(grant)


def cmd_grant_list(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args)
    return {"grants": [_grant_view(g) for g in ctx.policy.list_grants(args.principal)]}


def cmd_grant_revoke(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    grant = ctx.policy.revoke_grant(args.id)
    _admin_record(ctx, "grant_revoke", connection=grant.connection, result="ok",
                  extra={"grant": grant.id, "principal": grant.principal})
    return _grant_view(grant)


def cmd_grant_regrant(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    fresh = ctx.policy.regrant(args.id)
    _admin_record(ctx, "grant_regrant", connection=fresh.connection, result="ok", policy_version=fresh.policy_version,
                  extra={"grant": fresh.id, "principal": fresh.principal, "detail": args.id})
    view = _grant_view(fresh)
    view["replaces"] = args.id
    return view


def cmd_stop_all(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    ctx.policy.stop_all()
    _admin_record(ctx, "stop_all", result="ok")
    return _control_view(ctx)


def cmd_resume(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    ctx.policy.resume()
    _admin_record(ctx, "resume", result="ok")
    view = _control_view(ctx)
    if view["restore_pending"]:
        view["note"] = "restore_pending is still set; run restore-ack after re-applying revocations"
    return view


def cmd_approvals_list(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args)
    approvals = [{"digest": digest, **entry} for digest, entry in sorted(ctx.policy.list_approvals().items())]
    return {"approvals": approvals, "history": ctx.policy.approval_history()}


def cmd_approvals_approve(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    entry = ctx.policy.approve(args.digest)
    _admin_record(ctx, "approval_grant", connection=entry.get("connection"), result="ok",
                  extra={"digest": args.digest, "principal": entry.get("caller"), "method": entry.get("method"),
                         "path": entry.get("path")})
    return {"digest": args.digest, **entry}


def _shared_rotation_start(ctx: Context, env_id: str, secret_id: str, meta: Any, value: bytes) -> dict[str, Any]:
    from .team import envelope as team_envelope
    from .vault import Vault

    generation_id, dek = _current_generation_dek(ctx, env_id)
    public = Vault._public_metadata(meta.kind, value)
    version_id = secrets.token_hex(8)
    ciphertext = team_envelope.encrypt_secret(dek, env_id, secret_id, version_id, value)
    put_op = {"op": "secret.put_version", "secret_id": secret_id, "kind": meta.kind, "generation_id": generation_id,
             "version_id": version_id, "ciphertext": ciphertext, "public": public}
    result, _ = _team_commit_output(ctx, env_id, [put_op])
    local_version = _local_version_for(ctx, secret_id, version_id)
    return {"secret_id": secret_id, "version_id": version_id, "version": local_version, "status": "staged",
           "previous_active": meta.active_version,
           "next": "rotation activate --connection <id> --version %s" % (local_version if local_version is not None
                                                                          else version_id),
           **result}


def _local_version_for(ctx: Context, secret_id: str, version_id: str) -> int | None:
    from .vault import VAULT_DOC

    doc = ctx.state.read_json(VAULT_DOC, {}) or {}
    entry = (doc.get("secrets") or {}).get(secret_id) or {}
    for local_str, record in (entry.get("versions") or {}).items():
        if isinstance(record, dict) and record.get("version_id") == version_id:
            return int(local_str)
    return None


def cmd_rotation_start(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    meta = ctx.vault.get_meta(args.secret_id)
    value = _read_secret_value(args, meta.kind)
    env_id = _secret_shared_env(ctx, args.secret_id)
    if env_id is not None:
        return _shared_rotation_start(ctx, env_id, args.secret_id, meta, value)
    with ctx.state.lock():  # check and write in one critical section
        _refuse_value_in_existing_cli_env(ctx, args.secret_id, value, "rotation")
        version = ctx.vault.put_secret(args.secret_id, meta.kind, value, meta.project, meta.environment,
                                       activate=False)
    _admin_record(ctx, "rotation", result="ok", extra={"secret_id": args.secret_id, "version": version, "state": "staged"})
    return {"secret_id": args.secret_id, "version": version, "status": "staged", "previous_active": meta.active_version,
            "next": "rotation activate --connection <id> --version %d" % version}


def _shared_rotation_activate(ctx: Context, env_id: str, connection_id: str, local_version: int) -> dict[str, Any]:
    connection = ctx.policy.get_connection(connection_id)
    secret_id = connection.secret_id
    version_id = _shared_version_id(ctx, secret_id, local_version)
    previous_active = ctx.vault.get_meta(secret_id).active_version
    _team_commit_output(ctx, env_id, [{"op": "connection.switch_credential", "id": connection_id,
                                       "secret_id": secret_id, "secret_version": version_id}])
    result, _ = _team_commit_output(ctx, env_id, [{"op": "secret.activate", "secret_id": secret_id,
                                                   "version_id": version_id}])
    after = ctx.policy.get_connection(connection_id)
    others = [cid for cid in _connections_using(ctx, secret_id) if cid != connection_id]
    return {"connection": after.id, "secret_id": after.secret_id, "version": local_version,
            "previous_active": previous_active, "policy_version": after.policy_version, "other_connections": others,
            "next": "verify the new credential works, then: rotation finish --secret-id %s --version %s"
                    % (secret_id, previous_active if previous_active is not None else "<old>"), **result}


def cmd_rotation_activate(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    env_id = _connection_shared_env(ctx, args.connection)
    if env_id is not None:
        return _shared_rotation_activate(ctx, env_id, args.connection, args.version)
    connection = ctx.policy.get_connection(args.connection)
    meta = ctx.vault.get_meta(connection.secret_id)
    previous = meta.active_version
    # Pin first (one policy-version bump for this connection), then activate: activating re-binds only the
    # other unpinned connections that follow the secret.
    after = _switch_credential(ctx, args.connection, args.version)
    ctx.vault.set_version_status(connection.secret_id, args.version, "active")
    after = ctx.policy.get_connection(after.id)
    others = [cid for cid in _connections_using(ctx, connection.secret_id) if cid != after.id]
    return {"connection": after.id, "secret_id": after.secret_id, "version": args.version,
            "previous_active": previous, "policy_version": after.policy_version, "other_connections": others,
            "next": "verify the new credential works, then: rotation finish --secret-id %s --version %s"
                    % (after.secret_id, previous if previous is not None else "<old>")}


def cmd_rotation_finish(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    env_id = _secret_shared_env(ctx, args.secret_id)
    if env_id is not None:
        version_id = _shared_version_id(ctx, args.secret_id, args.version)
        result, _ = _team_commit_output(ctx, env_id, [{"op": "secret.set_status", "secret_id": args.secret_id,
                                                       "version_id": version_id, "status": "retired"}])
        result.update({"secret_id": args.secret_id, "version": args.version, "status": "retired",
                       "provider_revocation_required": True, "reminder": PROVIDER_REMINDER})
        return result
    result = _retire_version(ctx, args.secret_id, args.version)
    result.update({"provider_revocation_required": True, "reminder": PROVIDER_REMINDER})
    return result


def cmd_backup(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    out = Path(args.out).expanduser()
    manifest = ctx.vault.backup(out)
    return {"out": str(out), "manifest": manifest, "note": "encrypted archive; needs the KMS key or recovery passphrase"}


def cmd_restore(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    manifest = Vault.restore(ctx.state, Path(args.input).expanduser(), ctx.audit, kms=ctx.kms)
    view = _control_view(ctx)
    reapplied = (ctx.state.read_json(P.CONTROL, None) or {}).get("restore_reapplied")
    view.update({"manifest": manifest, "reapplied": reapplied, "handle_key_rotated": True, "next": RESTORE_NEXT})
    return view


def cmd_restore_ack(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    passphrase = _passphrase(ADMIN_PASSPHRASE_ENV, "Administrator passphrase: ")
    try:
        ctx.admin.verify(passphrase)
    except AuthFailed as exc:
        _record_auth_failure(ctx, exc.reason, state="restore_pending")
        raise
    # The latest revocation state is applied again under the lock before execution reopens.
    with ctx.state.lock():
        reapplied = Vault.reapply_revocations(ctx.state)
        ctx.policy.set_restore_pending(False)
    active = [g.id for g in ctx.policy.list_grants() if g.status == "active"]
    _admin_record(ctx, "restore_ack", result="ok", extra={"count": len(active), "state": "restore_pending_cleared"})
    view = _control_view(ctx)
    view.update({"active_grants": len(active), "active_grant_ids": active, "reapplied": reapplied,
                 "note": ("restore_pending cleared; the global stop is still set (run resume to lift it)"
                          if view["stopped"] else
                          "restore_pending cleared; execution is open under the restored grants")})
    return view


def cmd_recover(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    passphrase = _passphrase(RECOVERY_PASSPHRASE_ENV, "Recovery passphrase: ")
    try:
        revoked = ctx.recover(passphrase)
    except AuthFailed as exc:
        _record_auth_failure(ctx, exc.reason, state="recover")
        raise
    return {"kms_key_id": ctx.kms.key_id, "grants_revoked": revoked, "handles_invalidated": True}


def _read_log(ctx: Context, name: str, limit: int) -> tuple[list[dict[str, Any]], int]:
    """The last ``limit`` parseable records of an append-only JSONL log plus the number of lines
    that did not parse: one truncated line must not make the whole log unreadable."""
    records: list[dict[str, Any]] = []
    unparseable = 0
    for line in ctx.state.read_lines(name, None):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            unparseable += 1
            continue
        if isinstance(record, dict):
            records.append(record)
        else:
            unparseable += 1
    return records[-limit:], unparseable


def cmd_audit_tail(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args)
    records, unparseable = _read_log(ctx, AUDIT_FILE, args.limit)
    return {"records": records, "unparseable_lines": unparseable}


def cmd_alerts(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args)
    alerts, unparseable = _read_log(ctx, ALERT_FILE, args.limit)
    return {"alerts": alerts, "unparseable_lines": unparseable}


# --------------------------------------------------------------- team (section 12)
def _team_env_id(ctx: Context, env_ref: str) -> str:
    """Resolve a ``--env PROJECT/ENVIRONMENT`` reference to its env id via the node-local
    ``team/envs.json`` map (written by ``team share``/``team join``)."""
    from .team import sync as team_sync_mod

    project, sep, environment = env_ref.partition("/")
    if not sep or not project or not environment:
        raise InvalidInput("invalid_env_ref", "use PROJECT/ENVIRONMENT")
    env_id = team_sync_mod.resolve_env_id(ctx.state, project, environment)
    if env_id is None:
        raise NotFound("team_env_not_found")
    return env_id


class _NoopTeamTransport:
    """A transport stand-in for offline ``team`` subcommands (``compact``, ``peers --add``) that
    only need ``TeamSync``'s on-disk bookkeeping (facts, peer vectors, snapshots) and never call
    ``listen``/``dial`` -- there is no network here, only local state."""


def _offline_team_sync(ctx: Context) -> Any:
    from .team.identity import DeviceKey
    from .team.sync import TeamSync

    device = DeviceKey.load_or_create(ctx.state, ctx.kms)
    return TeamSync(ctx, _NoopTeamTransport(), device)


def cmd_team_init(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    from .team.identity import DeviceKey

    device = DeviceKey.create(ctx.state, ctx.kms)
    return {"fingerprint": device.fingerprint}


def cmd_team_share(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    from .team import membership as M

    passphrase = _passphrase(ADMIN_PASSPHRASE_ENV, "Administrator passphrase: ")
    try:
        result = M.share_environment(ctx, None, args.project, args.environment, args.name or "owner", passphrase)
    except AuthFailed as exc:
        _record_auth_failure(ctx, exc.reason, project=args.project, environment=args.environment)
        raise
    return {"env_id": result["env_id"], "project": args.project, "environment": args.environment,
            "not_shared": result["not_shared"]}


def cmd_team_invite(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    from .team import membership as M

    env_id = _team_env_id(ctx, args.env)
    ttl_seconds = _parse_ttl(args.ttl) if args.ttl else M.DEFAULT_INVITE_TTL_SECONDS
    invite = M.create_invite(ctx, env_id, args.role, args.name, ttl_seconds, list(args.address or []))
    return {"env_id": env_id, "invite": invite, "role": args.role, "name": args.name,
            "warning": "this string is a secret: never paste it into chat, issues, tickets, or logs"}


def cmd_team_join(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    from .team import membership as M
    from .team.identity import DeviceKey
    from .team.sync import TeamSync
    from .team.transport import TcpTransport

    device = DeviceKey.load_or_create(ctx.state, ctx.kms)
    transport = TcpTransport(device)
    team_sync = TeamSync(ctx, transport, device)
    team_sync.start(None)  # no listen address: this call only needs to dial out and catch up
    try:
        return M.join(ctx, args.invite, transport, team_sync, project=args.project, environment=args.environment)
    finally:
        team_sync.stop()


def cmd_team_members(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args)
    from .team import membership as M

    env_id = _team_env_id(ctx, args.env)
    doc = M.load_environment(ctx, env_id).document
    members = [{"fingerprint": fp, "name": m.get("name"), "role": m.get("role"), "status": m.get("status"),
               "owner": fp == doc.get("owner")} for fp, m in sorted(doc.get("members", {}).items())]
    return {"env_id": env_id, "members": members}


def cmd_team_remove(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    from .team import membership as M

    env_id = _team_env_id(ctx, args.env)
    return M.remove_member(ctx, None, env_id, args.device)


def cmd_team_set_role(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    from .team import membership as M

    env_id = _team_env_id(ctx, args.env)
    commit_obj = M.author_commit(ctx, None, env_id, [{"op": "member.set_role", "fingerprint": args.device,
                                                      "role": args.role}])
    return {"env_id": env_id, "fingerprint": args.device, "role": args.role,
            "commit": {"author_seq": commit_obj.author_seq, "hlc": commit_obj.hlc}}


def cmd_team_transfer_owner(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    from .team import membership as M

    env_id = _team_env_id(ctx, args.env)
    commit_obj = M.author_commit(ctx, None, env_id, [{"op": "owner.transfer", "fingerprint": args.device}])
    return {"env_id": env_id, "new_owner": args.device,
            "commit": {"author_seq": commit_obj.author_seq, "hlc": commit_obj.hlc}}


def cmd_team_status(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args)
    from .team import commit as team_commit_mod
    from .team import membership as M

    env_id = _team_env_id(ctx, args.env)
    store = team_commit_mod.CommitStore(ctx.state, env_id)
    fold_result = M.load_environment(ctx, env_id)
    vector = store.vector()
    rejected_dir = ctx.state.path / "team" / env_id / "rejected"
    rejected = len(list(rejected_dir.glob("*.json"))) if rejected_dir.is_dir() else 0
    return {"env_id": env_id, "vector": vector, "commits_folded": sum(vector.values()),
            "skipped_ops": len(fold_result.skipped), "rejected_commits": rejected,
            "pending_deferred": len(store.deferred_commits()),
            "note": "sessions/synced_at reflect a running `serve --team-listen`; this one-shot CLI holds none"}


def cmd_team_log(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args)
    from .team import commit as team_commit_mod
    from .team import membership as M

    env_id = _team_env_id(ctx, args.env)
    store = team_commit_mod.CommitStore(ctx.state, env_id)
    commits = team_commit_mod.sort_total_order(store.all_commits())
    fold_result = M.load_environment(ctx, env_id)
    skip_by_hash: dict[str, list[str]] = {}
    for commit_hash, _index, reason in fold_result.skipped:
        skip_by_hash.setdefault(commit_hash, []).append(reason)
    entries = [{"author": c.author, "author_seq": c.author_seq, "hlc": c.hlc,
               "ops": [op.get("op") for op in c.ops], "skipped": skip_by_hash.get(c.hash, [])}
              for c in commits]
    return {"env_id": env_id, "log": entries}


def cmd_team_show(args: argparse.Namespace) -> None | dict[str, Any]:
    ctx = _open(args)
    from .team import humanview
    from .team import membership as M

    env_id = _team_env_id(ctx, args.env)
    view = humanview.strip_document(M.load_environment(ctx, env_id).document)
    if args.format == "yaml":
        sys.stdout.write(humanview.to_yaml(view))
        sys.stdout.flush()
        return None
    return view


def cmd_team_diff(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args)
    from .team import commit as team_commit_mod
    from .team import fold as team_fold_mod
    from .team import humanview
    from .team import sync as team_sync_mod

    env_id = _team_env_id(ctx, args.env)
    store = team_commit_mod.CommitStore(ctx.state, env_id)
    commits = team_commit_mod.sort_total_order(store.all_commits())
    facts, _, _ = team_sync_mod.load_facts(ctx.state, env_id)

    def find(prefix: str):
        matches = [c for c in commits if c.hash.startswith(prefix)]
        if not matches:
            raise NotFound("commit_hash_not_found")
        if len(matches) > 1:
            raise InvalidInput("commit_hash_ambiguous")
        return matches[0]

    def view_upto(commit_obj: Any) -> dict[str, Any]:
        index = commits.index(commit_obj)
        result = team_fold_mod.fold(env_id, commits[: index + 1], facts)
        return humanview.strip_document(result.document)

    left_commit, right_commit = find(args.left), find(args.right)
    return {"env_id": env_id, "left": {"hash": left_commit.hash, "view": view_upto(left_commit)},
            "right": {"hash": right_commit.hash, "view": view_upto(right_commit)}}


def cmd_team_peers(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=bool(args.add))
    env_id = _team_env_id(ctx, args.env)
    if args.add:
        if not args.device:
            raise InvalidInput("peer_add_needs_device", "use --device FP with --add")
        team_sync = _offline_team_sync(ctx)
        team_sync.register_env(env_id)
        team_sync.set_peer_address(env_id, args.device, args.add)
    doc = ctx.state.read_json(f"team/{env_id}/peers.json", {}) or {}
    return {"env_id": env_id, "peers": doc}


def cmd_team_compact(args: argparse.Namespace) -> dict[str, Any]:
    ctx = _open(args, mutating=True)
    env_id = _team_env_id(ctx, args.env)
    team_sync = _offline_team_sync(ctx)
    team_sync.register_env(env_id)
    return team_sync.compact(env_id)


def cmd_team_incidents(args: argparse.Namespace) -> dict[str, Any]:
    """``team incidents`` (docs/team-sync.md section 9/12): every incident summary this node has
    received (value-free -- a summary never carries a secret value, only ids/timestamps/counts) and
    the rotation flags derived from them or from a ``team remove``'s DEK rotation."""
    ctx = _open(args)
    env_id = _team_env_id(ctx, args.env)
    incidents_dir = ctx.state.path / "team" / env_id / "incidents"
    incidents = []
    if incidents_dir.is_dir():
        for path in sorted(incidents_dir.glob("*.json")):
            record = ctx.state.read_json(f"team/{env_id}/incidents/{path.name}", None)
            if isinstance(record, dict):
                incidents.append({"id": path.stem, **record})
    rotation_flags = ctx.state.read_json(f"team/{env_id}/rotation_flags.json", {}) or {}
    return {"env_id": env_id, "incidents": incidents, "rotation_flags": rotation_flags}


# -------------------------------------------------------------------- serve
def _cancel_runs(ctx: Context, reason: str, quiet: bool) -> None:
    cancel_all = getattr(ctx.runs, "cancel_all", None)
    if not callable(cancel_all):
        return
    try:
        cancel_all(reason)
    except Exception as exc:  # the registry is a sibling module; never take the server down
        if not quiet:
            _notice(f"run cancellation failed: {type(exc).__name__}")


# Denials that mean another process withdrew the permission.  Expiry and an exhausted usage cap are not
# included: they are enforced on every relay and signature, and a run that legitimately spent its last use
# must not be killed for it.
WITHDRAWN_REASONS = frozenset({
    "restore_pending", "global_stop", "principal_unknown", "principal_disabled", "connection_unknown",
    "connection_disabled", "grant_unknown", "grant_mismatch", "grant_revoked", "grant_stale", "grant_inactive",
})


def _withdrawn(ctx: Context, caller: Any, connection: Any, grant: Any) -> str | None:
    if not all(isinstance(value, str) for value in (caller, connection, grant)):
        return None
    decision = ctx.policy.check_grant(caller, connection, grant)
    return decision.reason if not decision.allowed and decision.reason in WITHDRAWN_REASONS else None


def _enforce_withdrawn_permissions(ctx: Context, quiet: bool) -> None:
    """Cancel executions and close signer sockets whose permission was withdrawn by another process.

    Revocations made through this process's own ``Policy`` reach the run
    registry and the signer through ``on_revoke``; an ``admin_cli`` command is
    a separate process, so ``serve`` re-checks every active (caller,
    connection, grant) against the state on disk once per poll.
    """
    registry = ctx.runs
    active_runs = getattr(registry, "active_runs", None)
    if callable(active_runs):
        for run in active_runs():
            if getattr(run, "cancel_requested", False):
                continue
            try:
                reason = _withdrawn(ctx, getattr(run, "caller", None), getattr(run, "connection", None),
                                    getattr(run, "grant", None))
                if reason is not None:
                    registry.cancel(run.id, run.caller, reason)
            except Exception as exc:  # never take the server down; the next poll retries
                if not quiet:
                    _notice(f"run revocation check failed: {type(exc).__name__}")
    manager = ctx.signer_manager
    active_bindings = getattr(manager, "active_bindings", None)
    release = getattr(manager, "release", None)
    if callable(active_bindings) and callable(release):
        for binding in active_bindings():
            try:
                reason = _withdrawn(ctx, getattr(binding, "caller", None), getattr(binding, "connection_id", None),
                                    getattr(binding, "grant_id", None))
                if reason is not None:
                    release(binding)
            except Exception as exc:
                if not quiet:
                    _notice(f"signer revocation check failed: {type(exc).__name__}")


def _reload_handle_key(ctx: Context, current: bytes | None) -> bytes | None:
    """Pick up a handle key rotated by another process (restore, recover): old handles stop verifying."""
    try:
        key = ctx.state.read_bytes(HANDLE_KEY)
    except ZeroPWError:
        return current
    if current is not None and key != current:
        ctx.handles = HandleIssuer(key)
    return key


def _shutdown_runs(ctx: Context, quiet: bool) -> None:
    shutdown = getattr(ctx.runs, "shutdown", None)
    if not callable(shutdown):
        _cancel_runs(ctx, "shutdown", quiet)
        return
    try:
        shutdown("shutdown")
    except Exception as exc:
        if not quiet:
            _notice(f"run shutdown failed: {type(exc).__name__}")


def _start_team_sync(ctx: Context, team_listen: str) -> Any:
    """Construct the TCP transport and ``TeamSync``, and start listening on ``team_listen``.

    A device key is created on first use (``team init`` from docs/team-sync.md
    section 12 is the stage-3 CLI entry point for this; ``serve
    --team-listen`` does not require it to have been run first, so that this
    flag is independently testable in stage 2).
    """
    from .team.identity import DeviceKey
    from .team.sync import TeamSync
    from .team.transport import TcpTransport

    device = DeviceKey.load_or_create(ctx.state, ctx.kms)
    transport = TcpTransport(device, max_connections=64)
    sync = TeamSync(ctx, transport, device)
    sync.start(team_listen)
    return sync


def run_serve(state_dir: str | os.PathLike[str], listen: str = DEFAULT_LISTEN, quiet: bool = False,
              stop_event: threading.Event | None = None, install_signals: bool = True,
              team_listen: str | None = None) -> dict[str, Any]:
    """Start the trusted server and block until SIGINT/SIGTERM (or ``stop_event``).

    Returns the startup payload that was printed.  ``zeropw.tools`` is required;
    ``zeropw.signer`` is optional and its absence is reported explicitly.
    ``team_listen`` (``--team-listen HOST:PORT``) starts team sync on a
    separate, LAN/VPN-facing socket (docs/team-sync.md section 6.1); omitted,
    no team socket is opened and no dial is ever attempted.
    """
    host, port = _parse_listen(listen)
    _require_loopback(host)
    team_host = team_port = None
    if team_listen is not None:
        team_host, team_port = _parse_listen(team_listen)   # format-checked only; LAN/VPN addresses are allowed
    try:
        tools = importlib.import_module("zeropw.tools")
    except ImportError as exc:
        raise Unsupported("tools_unavailable", "zeropw.tools is not importable; the tools API cannot be served") from exc
    ctx = Context.open(Path(state_dir).expanduser(), Config(listen_host=host, listen_port=port))
    ctx.audit.require_writable()
    tools.install(ctx)
    signer_state = "available"
    try:
        signer: Any = importlib.import_module("zeropw.signer")
    except ImportError:
        signer = None
        signer_state = "unavailable"
    if signer is not None:
        signer.install(ctx)

    team_sync = _start_team_sync(ctx, team_listen) if team_listen is not None else None
    ctx.team = team_sync

    server = ZeroPWServer(ctx, quiet=quiet)
    set_public_url = getattr(tools, "set_public_url", None)
    if callable(set_public_url):
        set_public_url(ctx, server.url)
    else:
        ctx.config.extra["public_url"] = server.url
    server.serve_in_thread()

    payload: dict[str, Any] = {"url": server.url, "pid": os.getpid(), "ssh_signer": signer_state,
                               "state_dir": str(ctx.state.path), "team_listen": team_listen, **_control_view(ctx)}
    _emit(payload, compact=True)

    stop = stop_event or threading.Event()
    previous_handlers: dict[int, Any] = {}
    if install_signals and threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.signal(signum, lambda *_: stop.set())
    was_stopped, was_pending = payload["stopped"], payload["restore_pending"]
    handle_key = _reload_handle_key(ctx, None)

    def drain_request_log() -> None:
        # The server records only "METHOD query-free-path" lines; handles are already masked.
        while not quiet and server.log_lines:
            _notice(server.log_lines.pop(0))

    try:
        while not stop.wait(SERVE_POLL_SECONDS):
            drain_request_log()
            handle_key = _reload_handle_key(ctx, handle_key)
            try:
                now_stopped, now_pending = ctx.policy.is_stopped(), ctx.policy.restore_pending()
            except (ZeroPWError, OSError):
                continue
            if now_stopped and not was_stopped:
                _cancel_runs(ctx, "global_stop", quiet)
            if now_pending and not was_pending:
                _cancel_runs(ctx, "restore_pending", quiet)
            was_stopped, was_pending = now_stopped, now_pending
            _enforce_withdrawn_permissions(ctx, quiet)
            if team_sync is not None:
                try:
                    team_sync.poll()
                except Exception as exc:
                    if not quiet:
                        _notice(f"team sync poll failed: {type(exc).__name__}")
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        _shutdown_runs(ctx, quiet)
        manager = ctx.signer_manager
        shutdown = getattr(manager, "shutdown", None)
        if callable(shutdown):
            try:
                shutdown()
            except Exception as exc:
                if not quiet:
                    _notice(f"signer shutdown failed: {type(exc).__name__}")
        if team_sync is not None:
            try:
                team_sync.stop()
            except Exception as exc:
                if not quiet:
                    _notice(f"team sync shutdown failed: {type(exc).__name__}")
        server.stop()
    return payload


def cmd_serve(args: argparse.Namespace) -> None:
    run_serve(_state_dir(args), args.listen, args.quiet, team_listen=args.team_listen)
    return None


# ------------------------------------------------------------------- parser
def _add(sub: Any, name: str, handler: Handler, help_text: str) -> argparse.ArgumentParser:
    parser = sub.add_parser(name, help=help_text, description=help_text)
    parser.set_defaults(handler=handler)
    return parser


def _group(sub: Any, name: str, help_text: str) -> Any:
    parser = sub.add_parser(name, help=help_text, description=help_text)
    return parser.add_subparsers(dest=f"{name}_command", required=True, metavar="SUBCOMMAND")


def _value_source(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--value-file", metavar="PATH", help="read the secret value from this file (delete it afterwards)")
    group.add_argument("--stdin", action="store_true", help="read the secret value from standard input")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="zeropw-admin", description="ZeroPW administrator CLI (trusted; JSON output).")
    parser.add_argument("--state-dir", required=True, metavar="DIR", help="trusted state directory (0700)")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    _add(sub, "init", cmd_init, "create a new state directory (passphrases from env or prompt)")

    project = _group(sub, "project", "projects and environments")
    p = _add(project, "create", cmd_project_create, "create a project")
    p.add_argument("name")
    p.add_argument("--environments", metavar="A,B", help="default: dev,staging,prod")
    _add(project, "list", cmd_project_list, "list projects")

    secret = _group(sub, "secret", "vault secrets (metadata only, except reveal)")
    p = _add(secret, "put", cmd_secret_put, "store a new secret version; value via --value-file or --stdin only")
    p.add_argument("--id", required=True)
    p.add_argument("--kind", required=True, choices=SECRET_KINDS)
    p.add_argument("--project", required=True)
    p.add_argument("--environment", required=True)
    p.add_argument("--staged", action="store_true", help="store without activating")
    _value_source(p)
    p = _add(secret, "list", cmd_secret_list, "list secrets (metadata only)")
    p.add_argument("--project")
    p.add_argument("--environment")
    p = _add(secret, "versions", cmd_secret_versions, "list the versions of one secret (metadata only)")
    p.add_argument("--id", required=True)
    p = _add(secret, "reveal", cmd_secret_reveal, "reveal ONE secret version (admin re-auth; audited and alerted)")
    p.add_argument("--id", required=True)
    p.add_argument("--version", type=int)
    p = _add(secret, "retire", cmd_secret_retire, "retire a non-active version")
    p.add_argument("--id", required=True)
    p.add_argument("--version", type=int, required=True)
    p = _add(secret, "revoke", cmd_secret_revoke, "revoke a version (connections using it fail closed)")
    p.add_argument("--id", required=True)
    p.add_argument("--version", type=int, required=True)

    connection = _group(sub, "connection", "service connections")
    p = _add(connection, "create-http", cmd_connection_create_http, "create an HTTP connection (gateway-injected auth)")
    p.add_argument("--id", required=True)
    p.add_argument("--project", required=True)
    p.add_argument("--environment", required=True)
    p.add_argument("--service", required=True)
    p.add_argument("--secret-id", required=True)
    p.add_argument("--secret-version", type=int, help="pin a version (default: follow the active version)")
    p.add_argument("--target", required=True, metavar="URL", help="scheme://host[:port]; port defaults to 80/443")
    p.add_argument("--auth", required=True, choices=P.AUTH_MODES)
    p.add_argument("--header-name", help="header for --auth header")
    p.add_argument("--value-prefix", help='e.g. "token " placed before the credential')
    p.add_argument("--basic-username", help="username for --auth basic (the vault value is the password)")
    p.add_argument("--methods", metavar="GET,POST|all", help="default: GET,HEAD")
    p.add_argument("--path-prefixes", metavar="/a,/b|all", help="default: all")
    p.add_argument("--confirm-methods", metavar="DELETE", help="methods needing a one-shot approval")
    p.add_argument("--ca-file", help="CA bundle for TLS verification (tests)")
    p.add_argument("--allow-private-network", action="store_true",
                   help="allow a host-name target to resolve to loopback/private addresses (internal services); "
                        "metadata and link-local addresses stay refused")
    p.add_argument("--cli-program", metavar="PATH", help="supported CLI executable for exec")
    p.add_argument("--cli-env", action="append", metavar="K=V", help="non-secret env for the CLI (repeatable)")
    p.add_argument("--description")
    p = _add(connection, "create-ssh", cmd_connection_create_ssh, "create an SSH connection (signer-delegated auth)")
    p.add_argument("--id", required=True)
    p.add_argument("--project", required=True)
    p.add_argument("--environment", required=True)
    p.add_argument("--service", required=True)
    p.add_argument("--secret-id", required=True)
    p.add_argument("--secret-version", type=int)
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--username", required=True)
    p.add_argument("--host-key", action="append", required=True, metavar='"ssh-ed25519 AAAA..."',
                   help="expected host key (repeatable)")
    p.add_argument("--cli-program", metavar="PATH", help="ssh executable (default: none registered)")
    p.add_argument("--description")
    _add(connection, "list", cmd_connection_list, "list connections")
    p = _add(connection, "show", cmd_connection_show, "show one connection")
    p.add_argument("--id", required=True)
    # "update" is the primary name (docs/team-sync.md section 12); "update-scope" is kept as an alias.
    for _update_name in ("update", "update-scope"):
        p = _add(connection, _update_name, cmd_connection_update_scope, "change the HTTP scope (widening stales grants)")
        p.add_argument("--id", required=True)
        p.add_argument("--methods", metavar="GET,POST|all")
        p.add_argument("--path-prefixes", metavar="/a,/b|all")
        p.add_argument("--confirm-methods", metavar="DELETE|none")
    p = _add(connection, "switch-credential", cmd_connection_switch_credential, "pin the connection to a secret version")
    p.add_argument("--id", required=True)
    p.add_argument("--version", type=int, required=True)
    p = _add(connection, "disable", cmd_connection_disable, "disable a connection")
    p.add_argument("--id", required=True)

    principal = _group(sub, "principal", "agent identities")
    p = _add(principal, "create", cmd_principal_create, "create a principal; prints its caller token once")
    p.add_argument("--id", required=True)
    _add(principal, "list", cmd_principal_list, "list principals (no tokens, no hashes)")
    p = _add(principal, "disable", cmd_principal_disable, "disable a principal")
    p.add_argument("--id", required=True)

    grant = _group(sub, "grant", "grants (principal x connection, expiry, usage)")
    p = _add(grant, "create", cmd_grant_create, "grant a principal use of a connection")
    p.add_argument("--principal", required=True)
    p.add_argument("--connection", required=True)
    p.add_argument("--ttl", default=DEFAULT_GRANT_TTL, help="30m, 1h, 3600s, 86400 (default: 1h; max 30d)")
    p.add_argument("--max-uses", type=int)
    p = _add(grant, "list", cmd_grant_list, "list grants")
    p.add_argument("--principal")
    p = _add(grant, "revoke", cmd_grant_revoke, "revoke a grant immediately")
    p.add_argument("--id", required=True)
    p = _add(grant, "regrant", cmd_grant_regrant, "re-issue a stale grant at the current policy version")
    p.add_argument("--id", required=True)

    _add(sub, "stop-all", cmd_stop_all, "refuse every relay, signature and execution until resume")
    _add(sub, "resume", cmd_resume, "lift the global stop")

    approvals = _group(sub, "approvals", "one-shot approvals for risky methods")
    _add(approvals, "list", cmd_approvals_list, "list approval requests")
    p = _add(approvals, "approve", cmd_approvals_approve, "approve a pending request by digest")
    p.add_argument("--digest", required=True)

    rotation = _group(sub, "rotation", "credential rotation: start -> activate -> finish")
    p = _add(rotation, "start", cmd_rotation_start, "stage a new version of a secret")
    p.add_argument("--secret-id", required=True)
    _value_source(p)
    p = _add(rotation, "activate", cmd_rotation_activate, "activate a version and switch a connection to it")
    p.add_argument("--connection", required=True)
    p.add_argument("--version", type=int, required=True)
    p = _add(rotation, "finish", cmd_rotation_finish, "retire the old version (provider revocation is separate)")
    p.add_argument("--secret-id", required=True)
    p.add_argument("--version", type=int, required=True, help="the OLD version to retire")

    p = _add(sub, "backup", cmd_backup, "write an encrypted backup archive")
    p.add_argument("--out", required=True, metavar="FILE")
    p = _add(sub, "restore", cmd_restore, "restore an archive; leaves restore_pending set")
    p.add_argument("--in", dest="input", required=True, metavar="FILE")
    _add(sub, "restore-ack", cmd_restore_ack, "clear restore_pending after re-applying revocations (admin re-auth)")
    _add(sub, "recover", cmd_recover, "disaster recovery: new KMS key, grants revoked, handles rotated")

    audit = _group(sub, "audit", "audit log (administrator only)")
    p = _add(audit, "tail", cmd_audit_tail, "print the last records")
    p.add_argument("--limit", type=_positive_int, default=50, metavar="N", help="last N records (default 50)")
    p = _add(sub, "alerts", cmd_alerts, "print the last alerts")
    p.add_argument("--limit", type=_positive_int, default=50, metavar="N", help="last N alerts (default 50)")

    team = _group(sub, "team", "team sync: environment sharing between teammate nodes (docs/team-sync.md)")
    _add(team, "init", cmd_team_init, "create this node's device key; refuses if one already exists")
    p = _add(team, "share", cmd_team_share, "promote a local project/environment to a shared one (admin re-auth)")
    p.add_argument("--project", required=True)
    p.add_argument("--environment", required=True)
    p.add_argument("--name", help="this node's displayed member name (default: owner)")
    p = _add(team, "invite", cmd_team_invite, "print a one-time invite string (never paste it into chat/issues)")
    p.add_argument("--env", required=True, metavar="PROJECT/ENVIRONMENT")
    p.add_argument("--role", required=True, choices=("admin", "user"))
    p.add_argument("--name", required=True, help="display name for the invited member")
    p.add_argument("--ttl", help="30m, 1h, 3600s, 86400 (default: 24h)")
    p.add_argument("--address", action="append", metavar="HOST:PORT", help="this node's reachable address (repeatable)")
    p = _add(team, "join", cmd_team_join, "dial the inviter, prove the invite, and join")
    p.add_argument("invite")
    p.add_argument("--project", help="local project name (default: derived from the inviter)")
    p.add_argument("--environment", help="local environment name (default: shared)")
    p = _add(team, "members", cmd_team_members, "list team members")
    p.add_argument("--env", required=True, metavar="PROJECT/ENVIRONMENT")
    p = _add(team, "remove", cmd_team_remove, "remove a team member (fact) and rotate the DEK if applicable")
    p.add_argument("--env", required=True, metavar="PROJECT/ENVIRONMENT")
    p.add_argument("--device", required=True, metavar="FINGERPRINT")
    p = _add(team, "set-role", cmd_team_set_role, "change a member's role")
    p.add_argument("--env", required=True, metavar="PROJECT/ENVIRONMENT")
    p.add_argument("--device", required=True, metavar="FINGERPRINT")
    p.add_argument("--role", required=True, choices=("admin", "user"))
    p = _add(team, "transfer-owner", cmd_team_transfer_owner, "transfer ownership to another active admin/member")
    p.add_argument("--env", required=True, metavar="PROJECT/ENVIRONMENT")
    p.add_argument("--device", required=True, metavar="FINGERPRINT")
    p = _add(team, "status", cmd_team_status, "version vector, folded/skipped/rejected/pending counts")
    p.add_argument("--env", required=True, metavar="PROJECT/ENVIRONMENT")
    p = _add(team, "log", cmd_team_log, "commits in fold order, with skip reasons (no values)")
    p.add_argument("--env", required=True, metavar="PROJECT/ENVIRONMENT")
    p = _add(team, "show", cmd_team_show, "render the environment document (no ciphertext/wraps/signatures)")
    p.add_argument("--env", required=True, metavar="PROJECT/ENVIRONMENT")
    p.add_argument("--format", choices=("json", "yaml"), default="json")
    p = _add(team, "diff", cmd_team_diff, "compare the folded view at two commit hashes (prefixes accepted)")
    p.add_argument("--env", required=True, metavar="PROJECT/ENVIRONMENT")
    p.add_argument("left", metavar="COMMIT-HASH-PREFIX")
    p.add_argument("right", metavar="COMMIT-HASH-PREFIX")
    p = _add(team, "peers", cmd_team_peers, "list, or (with --device) add, a peer's known address")
    p.add_argument("--env", required=True, metavar="PROJECT/ENVIRONMENT")
    p.add_argument("--add", metavar="HOST:PORT")
    p.add_argument("--device", metavar="FINGERPRINT", help="required with --add")
    p = _add(team, "compact", cmd_team_compact, "delete commits every active member's vector already covers")
    p.add_argument("--env", required=True, metavar="PROJECT/ENVIRONMENT")
    p = _add(team, "incidents", cmd_team_incidents, "list received incident summaries and rotation flags")
    p.add_argument("--env", required=True, metavar="PROJECT/ENVIRONMENT")

    p = _add(sub, "serve", cmd_serve, "run the trusted server (tools API, relay, signer) until SIGINT/SIGTERM")
    p.add_argument("--listen", default=DEFAULT_LISTEN, metavar="HOST:PORT",
                   help="IPv4 loopback only (127.0.0.1 or localhost); port 0 = ephemeral")
    p.add_argument("--team-listen", default=None, metavar="HOST:PORT",
                   help="start team sync on a separate LAN/VPN-facing socket (default: team sync off)")
    p.add_argument("--quiet", action="store_true", help="no request log lines on stderr")
    return parser


# --------------------------------------------------------------------- main
def _exit_code(exc: SystemExit) -> int:
    code = exc.code
    if code is None:
        return EXIT_OK
    if isinstance(code, int):
        return code
    return EXIT_USAGE


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return _exit_code(exc)
    handler: Handler | None = getattr(args, "handler", None)
    if handler is None:
        parser.print_usage(sys.stderr)
        return EXIT_USAGE
    try:
        payload = handler(args)
    except ZeroPWError as exc:
        _emit_error(exc.to_dict())
        return EXIT_ERROR
    except FileNotFoundError:
        # No filename in the output: the path came from argv and could be a value typed by mistake.
        _emit_error({"error": "FileNotFoundError", "reason": "file_not_found"})
        return EXIT_ERROR
    except OSError as exc:
        _emit_error({"error": type(exc).__name__, "reason": "io_error", "detail": exc.strerror or ""})
        return EXIT_ERROR
    except KeyboardInterrupt:
        return 130
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        # Once the state opened, these come from documents that are valid JSON but semantically
        # broken (missing or mistyped fields).  Name the class only; the message could carry a value.
        _emit_error({"error": "StateError", "reason": "state_corrupt", "detail": type(exc).__name__})
        return EXIT_ERROR
    except Exception as exc:  # never print an exception message: it could carry a value
        _emit_error({"error": type(exc).__name__, "reason": "internal_error"})
        return EXIT_ERROR
    if payload is not None:
        _emit(payload)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
