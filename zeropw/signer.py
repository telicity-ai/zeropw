"""SSH signing delegation: an SSH agent that only signs bound authentication requests.

The signer speaks the OpenSSH agent protocol over a Unix socket.  Each socket
is created for exactly one (caller, connection, grant) binding by
``SignerManager.bind`` — the socket *is* the capability handed to the
secret-free execution environment via ``SSH_AUTH_SOCK``.

What the signer will do
-----------------------
* list the single Ed25519 identity of the bound connection;
* accept one ``session-bind@openssh.com`` per client connection when the
  presented host key is one of the connection's configured destination host
  keys, the host key's signature over the session identifier verifies, and
  the binding is not a forwarding hop;
* sign exactly one shape of data: a strictly parsed
  ``SSH_MSG_USERAUTH_REQUEST`` for the connection's username, this key,
  ``ssh-ed25519``, whose session identifier (and, for hostbound requests,
  host key) equals the bound session — after re-checking policy (revocation,
  expiry, usage, global stop, restore state) and writing the audit record.

What it refuses (``SSH_AGENT_FAILURE``)
--------------------------------------
Any other message type — adding, removing, locking or unlocking keys,
smartcards, legacy protocol-1 requests — arbitrary-data signing (so
``ssh-add -T`` fails by design), sign requests before a session bind, a
second bind on the same client connection, forwarding binds, unknown host
keys, mismatched session identifiers, other usernames, non-zero flags, and
malformed input.  Private key export is not part of the agent protocol at
all; the seed only exists in this trusted process.

Limitations
-----------
Clients that do not send ``session-bind@openssh.com`` (OpenSSH < 8.9 and
most non-OpenSSH clients) cannot authenticate through this signer: that is an
explicit unsupported mode, not a degraded one.  The signer does not proxy the
SSH session; the client talks to the server directly.  On a shared
development host the socket mode (0600) is the only isolation between the
execution environment and other local processes.
"""

from __future__ import annotations

import os
import socket
import stat
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import sshwire
from .audit import Audit
from .context import Context
from .crypto import ed25519
from .errors import AuditUnavailable, NotFound, PolicyDenied, Unsupported, ZeroPWError
from .policy import Action

MAX_UNIX_PATH = 100  # conservative: macOS sun_path is 104 bytes including NUL
# Concurrent agent client connections per binding.  One ``ssh`` process uses one
# agent connection, so a run needs a handful at most; beyond this the signer
# refuses (and audits) new clients instead of spawning unbounded threads.
MAX_AGENT_CLIENTS = 32
CLIENT_JOIN_TIMEOUT = 2.0
SUPPORTED_EXTENSIONS = (sshwire.SESSION_BIND_EXTENSION,)
SSH_ED25519 = "ssh-ed25519"

_MESSAGE_NAMES = {
    sshwire.SSH_AGENTC_REQUEST_IDENTITIES: "request_identities",
    sshwire.SSH_AGENTC_SIGN_REQUEST: "sign_request",
    sshwire.SSH_AGENTC_ADD_IDENTITY: "add_identity",
    sshwire.SSH_AGENTC_REMOVE_IDENTITY: "remove_identity",
    sshwire.SSH_AGENTC_REMOVE_ALL_IDENTITIES: "remove_all_identities",
    sshwire.SSH_AGENTC_ADD_SMARTCARD_KEY: "add_smartcard_key",
    sshwire.SSH_AGENTC_REMOVE_SMARTCARD_KEY: "remove_smartcard_key",
    sshwire.SSH_AGENTC_LOCK: "lock",
    sshwire.SSH_AGENTC_UNLOCK: "unlock",
    sshwire.SSH_AGENTC_ADD_ID_CONSTRAINED: "add_id_constrained",
    sshwire.SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED: "add_smartcard_key_constrained",
    sshwire.SSH_AGENTC_EXTENSION: "extension",
}


@dataclass
class SignerBinding:
    socket_path: Path
    caller: str
    connection_id: str
    grant_id: str
    _manager: "SignerManager | None" = None

    def close(self) -> None:
        if self._manager is not None:
            self._manager.release(self)


class _ClientState:
    """Per client-connection state (one accepted socket)."""

    __slots__ = ("bound", "bind_attempts")

    def __init__(self) -> None:
        self.bound: sshwire.SessionBind | None = None
        self.bind_attempts = 0


class _BindingServer:
    def __init__(self, ctx: Context, binding: SignerBinding) -> None:
        self.ctx = ctx
        self.binding = binding
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        path = str(binding.socket_path)
        old_umask = os.umask(0o177)
        try:
            self._sock.bind(path)
        finally:
            os.umask(old_umask)
        os.chmod(path, 0o600)
        self._sock.listen(16)
        self._sock.settimeout(0.2)
        self._closed = threading.Event()
        # Only live client connections are tracked: a serving thread removes its
        # own entry when it finishes, so this never grows past MAX_AGENT_CLIENTS.
        self._clients_lock = threading.Lock()
        self._clients: dict[threading.Thread, socket.socket] = {}
        self._accept_thread = threading.Thread(target=self._accept_loop, name=f"zeropw-signer-{binding.grant_id}", daemon=True)
        self._accept_thread.start()

    @property
    def _threads(self) -> list[threading.Thread]:
        """Snapshot of the threads currently serving a client connection."""
        with self._clients_lock:
            return list(self._clients)

    # ---------------------------------------------------------------- lifecycle
    def close(self) -> None:
        self._closed.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._accept_thread.join(timeout=2)
        try:
            os.unlink(self.binding.socket_path)
        except OSError:
            pass
        # Releasing the binding also ends connections accepted before it: a
        # lingering client must not keep a signing channel after release.
        # Shutdown happens under the lock: a serving thread removes its entry
        # under the same lock before closing its socket, so no fd is reused here.
        with self._clients_lock:
            live = list(self._clients)
            for client in self._clients.values():
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        current = threading.current_thread()
        deadline = time.monotonic() + CLIENT_JOIN_TIMEOUT  # one bound for all clients together
        for thread in live:
            if thread is not current:
                try:
                    thread.join(timeout=max(0.0, deadline - time.monotonic()))
                except RuntimeError:  # registered but never started (accept thread join timed out)
                    pass

    def _accept_loop(self) -> None:
        while not self._closed.is_set():
            try:
                client, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(target=self._serve_client, args=(client,), daemon=True)
            with self._clients_lock:
                admitted = not self._closed.is_set() and len(self._clients) < MAX_AGENT_CLIENTS
                if admitted:
                    self._clients[thread] = client
            if not admitted:
                try:
                    client.close()
                except OSError:
                    pass
                if not self._closed.is_set():
                    try:
                        self._safe_audit("ssh_agent_refused", "denied", "too_many_agent_clients", count=MAX_AGENT_CLIENTS)
                    except Exception:  # the refusal stands; never let auditing kill the accept loop
                        pass
                continue
            thread.start()

    # ------------------------------------------------------------------ audit
    def _audit(self, event: str, result: str, reason: str | None = None, *,
               policy_version: int | None = None, **extra: Any) -> None:
        """Write one record.  ``policy_version`` is the version the decision was
        evaluated against; records written before a decision carry the bound
        connection's current version (security-design §6)."""
        payload = {k: v for k, v in extra.items() if v is not None}
        target, current_version = self._connection_labels()
        self.ctx.audit.record(event, caller=self.binding.caller, connection=self.binding.connection_id,
                              target=target, action="ssh-sign" if event == "ssh_sign" else event,
                              result=result, reason=reason,
                              policy_version=policy_version if policy_version is not None else current_version,
                              extra=payload or None)

    def _connection_labels(self) -> tuple[str, int | None]:
        try:
            conn = self.ctx.policy.get_connection(self.binding.connection_id)
        except ZeroPWError:
            return "unknown", None
        target = f"{conn.ssh_target.host}:{conn.ssh_target.port}" if conn.ssh_target else "unknown"
        return target, conn.policy_version

    def _target_label(self) -> str:
        return self._connection_labels()[0]

    # ---------------------------------------------------------------- serving
    def _serve_client(self, client: socket.socket) -> None:
        state = _ClientState()
        client.settimeout(30)
        conn = sshwire.AgentConnection(client)
        try:
            while not self._closed.is_set():
                try:
                    message = conn.read_message()
                except sshwire.WireError:
                    self._safe_audit("ssh_agent_refused", "denied", "malformed_agent_message")
                    break
                except OSError:
                    break
                if message is None or self._closed.is_set():
                    break
                try:
                    reply = self._handle(state, message)
                except Exception:
                    reply = sshwire.build_failure()
                try:
                    conn.write_message(reply)
                except OSError:
                    break
        finally:
            with self._clients_lock:
                self._clients.pop(threading.current_thread(), None)
            try:
                client.close()
            except OSError:
                pass

    def _safe_audit(self, event: str, result: str, reason: str | None, **extra: Any) -> bool:
        try:
            self._audit(event, result, reason, **extra)
            return True
        except AuditUnavailable:
            return False

    def _handle(self, state: _ClientState, message: bytes) -> bytes:
        msg_type = message[0]
        rest = message[1:]
        if msg_type == sshwire.SSH_AGENTC_REQUEST_IDENTITIES:
            return self._identities()
        if msg_type == sshwire.SSH_AGENTC_EXTENSION:
            return self._extension(state, rest)
        if msg_type == sshwire.SSH_AGENTC_SIGN_REQUEST:
            return self._sign(state, rest)
        name = _MESSAGE_NAMES.get(msg_type, f"type_{msg_type}")
        self._safe_audit("ssh_agent_refused", "denied", "unsupported_agent_message", message_type=name)
        return sshwire.build_failure()

    # ------------------------------------------------------------ identities
    def _connection(self):
        conn = self.ctx.policy.get_connection(self.binding.connection_id)
        if conn.kind != "ssh" or not conn.ssh_target:
            raise Unsupported("connection_not_ssh")
        return conn

    def _public_key(self) -> sshwire.Ed25519PublicKey:
        """Public key from vault metadata: no plaintext is touched to list identities."""
        conn = self._connection()
        version = self.ctx.vault.resolve_version(conn.secret_id, conn.secret_version)
        meta = self.ctx.vault.get_meta(conn.secret_id)
        for item in meta.versions:
            if item.version == version:
                line = item.public.get("public_key")
                if not line:
                    raise Unsupported("ssh_key_metadata_missing")
                return sshwire.parse_authorized_key(line)
        raise NotFound("secret_version_not_found")

    def _identities(self) -> bytes:
        try:
            key = self._public_key()
        except (ZeroPWError, sshwire.WireError):
            return sshwire.build_failure()
        return sshwire.build_identities_answer([(key.blob(), f"zeropw:{self.binding.connection_id}")])

    # -------------------------------------------------------------- extension
    def _extension(self, state: _ClientState, rest: bytes) -> bytes:
        try:
            name, data = sshwire.parse_extension(rest)
        except sshwire.WireError:
            self._safe_audit("ssh_agent_refused", "denied", "malformed_extension")
            return sshwire.build_failure()
        if name == sshwire.EXTENSION_QUERY:
            return sshwire.build_extension_query_response(list(SUPPORTED_EXTENSIONS))
        if name != sshwire.SESSION_BIND_EXTENSION:
            self._safe_audit("ssh_agent_refused", "denied", "unsupported_extension", extension=name[:64])
            return sshwire.build_failure()
        return self._session_bind(state, data)

    def _session_bind(self, state: _ClientState, data: bytes) -> bytes:
        state.bind_attempts += 1
        try:
            bind = sshwire.parse_session_bind(data)
        except sshwire.WireError:
            self._safe_audit("ssh_bind", "denied", "malformed_session_bind")
            return sshwire.build_failure()
        if state.bound is not None:
            self._safe_audit("ssh_bind", "denied", "session_already_bound")
            return sshwire.build_failure()
        if bind.is_forwarding:
            self._safe_audit("ssh_bind", "denied", "agent_forwarding_not_allowed")
            return sshwire.build_failure()
        try:
            conn = self._connection()
            host_key = sshwire.parse_public_key_blob(bind.host_key_blob)
        except (ZeroPWError, sshwire.WireError):
            self._safe_audit("ssh_bind", "denied", "host_key_unsupported")
            return sshwire.build_failure()
        allowed = False
        for line in conn.ssh_target.host_keys:  # type: ignore[union-attr]
            try:
                if sshwire.parse_authorized_key(line).key_bytes == host_key.key_bytes:
                    allowed = True
                    break
            except sshwire.WireError:
                continue
        if not allowed:
            self._safe_audit("ssh_bind", "denied", "host_key_not_allowed", fingerprint=host_key.fingerprint())
            return sshwire.build_failure()
        try:
            raw_sig = sshwire.parse_ssh_signature(bind.signature)
        except sshwire.WireError:
            self._safe_audit("ssh_bind", "denied", "host_signature_malformed", fingerprint=host_key.fingerprint())
            return sshwire.build_failure()
        if not ed25519.verify(host_key.key_bytes, bind.session_id, raw_sig):
            self._safe_audit("ssh_bind", "denied", "host_signature_invalid", fingerprint=host_key.fingerprint())
            return sshwire.build_failure()
        decision = self.ctx.policy.evaluate(self.binding.caller, self.binding.connection_id,
                                            Action("ssh", username=conn.ssh_target.username),  # type: ignore[union-attr]
                                            self.binding.grant_id)
        if not decision.allowed:
            self._safe_audit("ssh_bind", "denied", decision.reason, policy_version=decision.policy_version,
                             fingerprint=host_key.fingerprint())
            return sshwire.build_failure()
        if not self._safe_audit("ssh_bind", "ok", None, policy_version=decision.policy_version,
                                fingerprint=host_key.fingerprint(),
                                username=conn.ssh_target.username):  # type: ignore[union-attr]
            return sshwire.build_failure()
        state.bound = bind
        return sshwire.build_success()

    # ------------------------------------------------------------------- sign
    def _sign(self, state: _ClientState, rest: bytes) -> bytes:
        try:
            request = sshwire.parse_sign_request(rest)
        except sshwire.WireError:
            self._safe_audit("ssh_sign", "denied", "malformed_sign_request")
            return sshwire.build_failure()
        if request.flags != 0:
            self._safe_audit("ssh_sign", "denied", "unsupported_sign_flags")
            return sshwire.build_failure()
        try:
            conn = self._connection()
            our_key = self._public_key()
        except (ZeroPWError, sshwire.WireError):
            self._safe_audit("ssh_sign", "denied", "key_unavailable")
            return sshwire.build_failure()
        if request.key_blob != our_key.blob():
            self._safe_audit("ssh_sign", "denied", "unknown_key")
            return sshwire.build_failure()
        if state.bound is None:
            self._safe_audit("ssh_sign", "denied", "no_session_bind")
            return sshwire.build_failure()
        try:
            auth = sshwire.parse_userauth_request(request.data)
        except sshwire.WireError:
            # Arbitrary data (including ssh-add -T probes) is never signed.
            self._safe_audit("ssh_sign", "denied", "not_userauth_request")
            return sshwire.build_failure()
        if auth.session_id != state.bound.session_id:
            self._safe_audit("ssh_sign", "denied", "session_mismatch")
            return sshwire.build_failure()
        if auth.host_key_blob is not None and auth.host_key_blob != state.bound.host_key_blob:
            self._safe_audit("ssh_sign", "denied", "hostbound_key_mismatch")
            return sshwire.build_failure()
        if auth.algorithm != SSH_ED25519 or auth.public_key_blob != our_key.blob():
            self._safe_audit("ssh_sign", "denied", "userauth_key_mismatch")
            return sshwire.build_failure()
        if auth.username != conn.ssh_target.username:  # type: ignore[union-attr]
            self._safe_audit("ssh_sign", "denied", "ssh_user_mismatch", username=auth.username[:64])
            return sshwire.build_failure()
        decision = self.ctx.policy.evaluate(self.binding.caller, self.binding.connection_id,
                                            Action("ssh", username=auth.username), self.binding.grant_id)
        pv = decision.policy_version
        if not decision.allowed:
            self._safe_audit("ssh_sign", "denied", decision.reason, policy_version=pv, username=auth.username)
            return sshwire.build_failure()
        # Mandatory audit before the key is used; audit failure refuses the signature.
        if not self._safe_audit("ssh_sign", "ok", None, policy_version=pv, username=auth.username,
                                fingerprint=our_key.fingerprint(), grant=self.binding.grant_id):
            return sshwire.build_failure()
        try:
            self.ctx.policy.consume(self.binding.grant_id)
        except PolicyDenied as exc:
            self._safe_audit("ssh_sign", "denied", exc.reason, policy_version=pv, username=auth.username)
            return sshwire.build_failure()
        try:
            pem = self.ctx.vault.secret_for_trusted_use(conn.secret_id, conn.secret_version)
            private = sshwire.parse_openssh_private_key(pem)
            if private.public.key_bytes != our_key.key_bytes:
                self._safe_audit("ssh_sign", "denied", "key_metadata_mismatch", policy_version=pv)
                return sshwire.build_failure()
            signature = private.sign(request.data)
        except (ZeroPWError, sshwire.WireError):
            self._safe_audit("ssh_sign", "denied", "key_unavailable", policy_version=pv)
            return sshwire.build_failure()
        return sshwire.build_sign_response(sshwire.encode_ssh_signature(signature))


class SignerManager:
    """Creates one dedicated agent socket per (caller, connection, grant) binding."""

    def __init__(self, ctx: Context, socket_dir: Path | None = None) -> None:
        self.ctx = ctx
        self._lock = threading.Lock()
        self._servers: dict[str, _BindingServer] = {}
        self.socket_dir = self._choose_socket_dir(socket_dir or ctx.config.socket_dir)

    @staticmethod
    def _choose_socket_dir(preferred: Path | None) -> Path:
        candidate = Path(preferred) if preferred else None
        if candidate is not None and len(str(candidate / ("s" * 24))) <= MAX_UNIX_PATH:
            candidate.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(candidate, 0o700)
            return candidate
        short = Path(tempfile.mkdtemp(prefix="zpws-"))
        os.chmod(short, 0o700)
        return short

    def bind(self, caller: str, connection_id: str, grant_id: str) -> SignerBinding:
        conn = self.ctx.policy.get_connection(connection_id)
        if conn.kind != "ssh":
            raise Unsupported("connection_not_ssh")
        decision = self.ctx.policy.evaluate(caller, connection_id,
                                            Action("ssh", username=conn.ssh_target.username), grant_id)  # type: ignore[union-attr]
        decision.require()
        name = f"a{uuid.uuid4().hex[:12]}.sock"
        path = self.socket_dir / name
        if len(str(path)) > MAX_UNIX_PATH + 3:
            raise Unsupported("socket_path_too_long")
        binding = SignerBinding(path, caller, connection_id, grant_id, self)
        server = _BindingServer(self.ctx, binding)
        with self._lock:
            self._servers[str(path)] = server
        return binding

    def release(self, binding: SignerBinding) -> None:
        with self._lock:
            server = self._servers.pop(str(binding.socket_path), None)
        if server is not None:
            server.close()

    def active_bindings(self) -> list[SignerBinding]:
        with self._lock:
            return [s.binding for s in self._servers.values()]

    def release_for_grant(self, grant_id: str | None) -> int:
        """Close sockets for a revoked grant (or every socket when grant_id is None)."""
        with self._lock:
            victims = [s for s in self._servers.values() if grant_id is None or s.binding.grant_id == grant_id]
            for server in victims:
                self._servers.pop(str(server.binding.socket_path), None)
        for server in victims:
            server.close()
        return len(victims)

    def shutdown(self) -> None:
        self.release_for_grant(None)


def install(ctx: Context, socket_dir: Path | None = None) -> SignerManager:
    manager = SignerManager(ctx, socket_dir)
    ctx.signer_manager = manager

    def on_revoke(kind: str, grant_id: str | None) -> None:
        manager.release_for_grant(grant_id if kind == "grant" else None)

    ctx.policy.on_revoke(on_revoke)
    return manager


def socket_mode_ok(path: Path) -> bool:
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return False
    return stat.S_ISSOCK(mode) and (mode & 0o077) == 0
