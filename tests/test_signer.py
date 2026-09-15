"""SSH signer: agent-protocol behaviour with a scripted client (no sshd needed)."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from zeropw import policy as P
from zeropw import signer as S
from zeropw import sshwire
from zeropw.context import Config, Context
from zeropw.crypto import ed25519
from zeropw.errors import PolicyDenied, Unsupported

ADMIN = "admin-passphrase-1"
RECOVERY = "recovery-passphrase-1"


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_700_000_000.0

    def __call__(self) -> float:
        return self.now


class SignerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.clock = FakeClock()
        self.ctx = Context.initialize(root / "state", ADMIN, RECOVERY, Config(), self.clock)
        self.ctx.projects.create("demo")
        self.user_key = sshwire.generate_ed25519_private_key("agent-key")
        self.host_key = sshwire.generate_ed25519_private_key("host")
        self.other_host_key = sshwire.generate_ed25519_private_key("other-host")
        self.ctx.vault.put_secret("box-key", "ssh_private_key", self.user_key.to_openssh_private_key().encode(),
                                  "demo", "dev")
        self.token = self.ctx.policy.create_principal("agent-1")
        self.ctx.policy.create_connection(P.Connection(
            id="box", project="demo", environment="dev", service="ssh-box", kind="ssh", secret_id="box-key",
            secret_version=None, description="", http_target=None, http_auth=None, http_scope=None,
            ssh_target=P.SshTarget("127.0.0.1", 2222, "deploy", (self.host_key.public.to_authorized_key("host"),)),
            cli=None, policy_version=0, status="active", created_at="", updated_at=""))
        self.grant = self.ctx.policy.create_grant("agent-1", "box", 3600, 5)
        self.manager = S.install(self.ctx)
        self.binding = self.manager.bind("agent-1", "box", self.grant.id)
        self.session_id = os.urandom(32)

    def tearDown(self) -> None:
        self.manager.shutdown()
        self.tmp.cleanup()

    # ------------------------------------------------------------ helpers
    def connect(self) -> sshwire.AgentConnection:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect(str(self.binding.socket_path))
        except OSError:
            sock.close()
            raise
        return sshwire.AgentConnection(sock)

    def bind_message(self, host_key: sshwire.Ed25519PrivateKey | None = None, session_id: bytes | None = None,
                     forwarding: bool = False, bad_signature: bool = False) -> bytes:
        host = host_key or self.host_key
        sid = session_id or self.session_id
        sig = host.sign(sid)
        if bad_signature:
            sig = bytes([sig[0] ^ 1]) + sig[1:]
        return sshwire.build_session_bind(host.public.blob(), sid, sshwire.encode_ssh_signature(sig), forwarding)

    def userauth(self, username: str = "deploy", session_id: bytes | None = None, algorithm: str = "ssh-ed25519",
                 key_blob: bytes | None = None, hostbound: bytes | None = None) -> bytes:
        return sshwire.build_userauth_request(session_id or self.session_id, username, algorithm,
                                              key_blob or self.user_key.public.blob(), host_key_blob=hostbound)

    def sign(self, conn: sshwire.AgentConnection, data: bytes, flags: int = 0, key_blob: bytes | None = None) -> bytes:
        return conn.request(sshwire.build_sign_request(key_blob or self.user_key.public.blob(), data, flags))

    def audit_reasons(self) -> list[str | None]:
        return [r.get("reason") for r in self.ctx.audit.tail(200) if r["event"] in ("ssh_sign", "ssh_bind", "ssh_agent_refused")]

    # -------------------------------------------------------------- tests
    def test_socket_is_private(self) -> None:
        self.assertTrue(S.socket_mode_ok(self.binding.socket_path))
        self.assertEqual(self.manager.socket_dir.stat().st_mode & 0o077, 0)

    def test_identities_lists_only_the_bound_key_without_touching_plaintext(self) -> None:
        with self.connect() as conn:
            reply = conn.request(bytes([sshwire.SSH_AGENTC_REQUEST_IDENTITIES]))
        self.assertEqual(reply[0], sshwire.SSH_AGENT_IDENTITIES_ANSWER)
        keys = sshwire.parse_identities_answer(reply[1:])
        self.assertEqual(keys, [(self.user_key.public.blob(), "zeropw:box")])

    def test_bind_then_sign_produces_valid_signature(self) -> None:
        with self.connect() as conn:
            self.assertEqual(conn.request(self.bind_message()), sshwire.build_success())
            data = self.userauth()
            reply = self.sign(conn, data)
            self.assertEqual(reply[0], sshwire.SSH_AGENT_SIGN_RESPONSE)
            sig = sshwire.parse_ssh_signature(sshwire.parse_sign_response(reply[1:]))
            self.assertTrue(ed25519.verify(self.user_key.public.key_bytes, data, sig))
            # hostbound variant bound to the same host key also works
            reply = self.sign(conn, self.userauth(hostbound=self.host_key.public.blob()))
            self.assertEqual(reply[0], sshwire.SSH_AGENT_SIGN_RESPONSE)
        self.assertEqual(self.ctx.policy.get_grant(self.grant.id).uses, 2)
        events = [r for r in self.ctx.audit.tail(50) if r["event"] == "ssh_sign" and r["result"] == "ok"]
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["username"], "deploy")
        raw = (self.ctx.state.path / "audit" / "audit.jsonl").read_text()
        self.assertNotIn(self.user_key.seed.hex(), raw)
        self.assertNotIn("PRIVATE KEY", raw)

    def test_extension_query_advertises_session_bind(self) -> None:
        with self.connect() as conn:
            reply = conn.request(sshwire.build_extension_query())
        self.assertEqual(sshwire.parse_extension_query_response(reply[1:]), [sshwire.SESSION_BIND_EXTENSION])

    def test_sign_without_bind_refused(self) -> None:
        with self.connect() as conn:
            self.assertEqual(self.sign(conn, self.userauth()), sshwire.build_failure())
        self.assertIn("no_session_bind", self.audit_reasons())

    def test_arbitrary_data_never_signed(self) -> None:
        with self.connect() as conn:
            conn.request(self.bind_message())
            self.assertEqual(self.sign(conn, b"please sign this arbitrary blob"), sshwire.build_failure())
            self.assertEqual(self.sign(conn, self.userauth() + b"trailing"), sshwire.build_failure())
            self.assertEqual(self.sign(conn, b""), sshwire.build_failure())
        self.assertIn("not_userauth_request", self.audit_reasons())

    def test_destination_binding(self) -> None:
        with self.connect() as conn:
            self.assertEqual(conn.request(self.bind_message(host_key=self.other_host_key)), sshwire.build_failure())
            self.assertEqual(self.sign(conn, self.userauth()), sshwire.build_failure())
        self.assertIn("host_key_not_allowed", self.audit_reasons())
        with self.connect() as conn:
            self.assertEqual(conn.request(self.bind_message(bad_signature=True)), sshwire.build_failure())
        self.assertIn("host_signature_invalid", self.audit_reasons())

    def test_session_binding_and_reuse(self) -> None:
        with self.connect() as conn:
            conn.request(self.bind_message())
            other_session = os.urandom(32)
            self.assertEqual(self.sign(conn, self.userauth(session_id=other_session)), sshwire.build_failure())
            # rebinding the same client connection to another session is refused
            self.assertEqual(conn.request(self.bind_message(session_id=other_session)), sshwire.build_failure())
            # hostbound request naming a different host key is refused
            self.assertEqual(self.sign(conn, self.userauth(hostbound=self.other_host_key.public.blob())), sshwire.build_failure())
        reasons = self.audit_reasons()
        self.assertIn("session_mismatch", reasons)
        self.assertIn("session_already_bound", reasons)
        self.assertIn("hostbound_key_mismatch", reasons)
        # a new client connection does not inherit the previous binding
        with self.connect() as conn:
            self.assertEqual(self.sign(conn, self.userauth()), sshwire.build_failure())

    def test_forwarding_bind_refused(self) -> None:
        with self.connect() as conn:
            self.assertEqual(conn.request(self.bind_message(forwarding=True)), sshwire.build_failure())
            self.assertEqual(self.sign(conn, self.userauth()), sshwire.build_failure())
        self.assertIn("agent_forwarding_not_allowed", self.audit_reasons())

    def test_username_algorithm_key_and_flags_bound(self) -> None:
        other = sshwire.generate_ed25519_private_key("other")
        with self.connect() as conn:
            conn.request(self.bind_message())
            self.assertEqual(self.sign(conn, self.userauth(username="root")), sshwire.build_failure())
            self.assertEqual(self.sign(conn, self.userauth(algorithm="ssh-rsa")), sshwire.build_failure())
            self.assertEqual(self.sign(conn, self.userauth(key_blob=other.public.blob())), sshwire.build_failure())
            self.assertEqual(self.sign(conn, self.userauth(), key_blob=other.public.blob()), sshwire.build_failure())
            self.assertEqual(self.sign(conn, self.userauth(), flags=2), sshwire.build_failure())
            self.assertEqual(self.sign(conn, self.userauth())[0], sshwire.SSH_AGENT_SIGN_RESPONSE)
        reasons = self.audit_reasons()
        for expected in ("ssh_user_mismatch", "userauth_key_mismatch", "unknown_key", "unsupported_sign_flags"):
            self.assertIn(expected, reasons)

    def test_key_management_messages_refused(self) -> None:
        with self.connect() as conn:
            for msg_type in (sshwire.SSH_AGENTC_ADD_IDENTITY, sshwire.SSH_AGENTC_REMOVE_IDENTITY,
                             sshwire.SSH_AGENTC_REMOVE_ALL_IDENTITIES, sshwire.SSH_AGENTC_LOCK, sshwire.SSH_AGENTC_UNLOCK,
                             sshwire.SSH_AGENTC_ADD_ID_CONSTRAINED, sshwire.SSH_AGENTC_ADD_SMARTCARD_KEY, 1, 2, 3, 99):
                self.assertEqual(conn.request(bytes([msg_type]) + b"\x00" * 8), sshwire.build_failure(), msg_type)
            # unknown extension
            self.assertEqual(conn.request(bytes([sshwire.SSH_AGENTC_EXTENSION]) + sshwire.encode_string(b"nope")),
                             sshwire.build_failure())
            # still healthy afterwards
            self.assertEqual(conn.request(self.bind_message()), sshwire.build_success())

    def test_malformed_and_oversized_messages_do_not_crash_server(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(str(self.binding.socket_path))
        sock.sendall(sshwire.encode_uint32(sshwire.MAX_AGENT_MESSAGE + 1) + b"\x0d")
        # The signer drops the connection without reading the oversized payload.  With the unread
        # byte still queued, Linux reports the close as a reset while macOS reports a clean EOF.
        try:
            reply = sock.recv(1024)
        except ConnectionResetError:
            reply = b""
        self.assertEqual(reply, b"")
        sock.close()
        with self.connect() as conn:
            self.assertEqual(conn.request(bytes([sshwire.SSH_AGENTC_SIGN_REQUEST]) + b"\xff\xff"), sshwire.build_failure())
            self.assertEqual(conn.request(bytes([sshwire.SSH_AGENTC_EXTENSION]) + sshwire.encode_string(sshwire.SESSION_BIND_EXTENSION.encode()) + b"\x01"),
                             sshwire.build_failure())
            self.assertEqual(conn.request(self.bind_message()), sshwire.build_success())

    def test_policy_checked_at_bind_and_sign_time(self) -> None:
        with self.connect() as conn:
            conn.request(self.bind_message())
            self.assertEqual(self.sign(conn, self.userauth())[0], sshwire.SSH_AGENT_SIGN_RESPONSE)
            self.clock.now += 3600
            self.assertEqual(self.sign(conn, self.userauth()), sshwire.build_failure())
            self.assertIn("grant_expired", self.audit_reasons())
            self.clock.now -= 3600
            self.assertEqual(self.sign(conn, self.userauth())[0], sshwire.SSH_AGENT_SIGN_RESPONSE)
        # global stop closes every signer socket; new binds are refused until resume
        self.ctx.policy.stop_all()
        self.assertFalse(self.binding.socket_path.exists())
        with self.assertRaises(OSError):
            self.connect()
        with self.assertRaises(PolicyDenied):
            self.manager.bind("agent-1", "box", self.grant.id)
        self.ctx.policy.resume()
        self.binding = self.manager.bind("agent-1", "box", self.grant.id)
        with self.connect() as conn:
            conn.request(self.bind_message())
            self.assertEqual(self.sign(conn, self.userauth())[0], sshwire.SSH_AGENT_SIGN_RESPONSE)
        # revoking the grant closes the socket entirely
        self.ctx.policy.revoke_grant(self.grant.id)
        self.assertFalse(self.binding.socket_path.exists())
        with self.assertRaises(OSError):
            self.connect()

    def test_usage_cap_enforced_per_signature(self) -> None:
        with self.connect() as conn:
            conn.request(self.bind_message())
            for _ in range(5):
                self.assertEqual(self.sign(conn, self.userauth())[0], sshwire.SSH_AGENT_SIGN_RESPONSE)
            self.assertEqual(self.sign(conn, self.userauth()), sshwire.build_failure())
        self.assertIn("grant_exhausted", self.audit_reasons())

    def test_bind_refuses_non_ssh_connection_and_denied_grant(self) -> None:
        self.ctx.policy.create_connection(P.Connection(
            id="web", project="demo", environment="dev", service="fake", kind="http", secret_id="box-key",
            secret_version=None, description="", http_target=P.HttpTarget("http", "127.0.0.1", 1),
            http_auth=P.HttpAuth("bearer"), http_scope=P.HttpScope(), ssh_target=None, cli=None,
            policy_version=0, status="active", created_at="", updated_at=""))
        with self.assertRaises(Unsupported):
            self.manager.bind("agent-1", "web", self.grant.id)
        with self.assertRaises(PolicyDenied):
            self.manager.bind("agent-2", "box", self.grant.id)
        self.ctx.policy.stop_all()
        with self.assertRaises(PolicyDenied):
            self.manager.bind("agent-1", "box", self.grant.id)

    def test_audit_failure_refuses_signature(self) -> None:
        with self.connect() as conn:
            conn.request(self.bind_message())
            original = self.ctx.state.append_line

            def broken(name: str, line: str) -> None:
                raise OSError("disk full")

            self.ctx.state.append_line = broken  # type: ignore[assignment]
            try:
                self.assertEqual(self.sign(conn, self.userauth()), sshwire.build_failure())
            finally:
                self.ctx.state.append_line = original  # type: ignore[assignment]
            self.assertEqual(self.ctx.policy.get_grant(self.grant.id).uses, 0)

    def test_release_removes_socket(self) -> None:
        path = self.binding.socket_path
        self.binding.close()
        self.assertFalse(path.exists())
        self.assertEqual(self.manager.active_bindings(), [])

    # ------------------------------------------------- client tracking (SSH-3)
    def server(self) -> S._BindingServer:
        return self.manager._servers[str(self.binding.socket_path)]

    def wait_until(self, predicate, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.01)
        return predicate()

    def test_finished_client_threads_are_pruned(self) -> None:
        server = self.server()
        for _ in range(40):
            with self.connect() as conn:
                reply = conn.request(bytes([sshwire.SSH_AGENTC_REQUEST_IDENTITIES]))
                self.assertEqual(reply[0], sshwire.SSH_AGENT_IDENTITIES_ANSWER)
        self.assertTrue(self.wait_until(lambda: len(server._threads) == 0), len(server._threads))
        self.assertEqual(len(server._clients), 0)

    def test_concurrent_clients_are_capped_and_refusal_audited(self) -> None:
        server = self.server()
        original = S.MAX_AGENT_CLIENTS
        S.MAX_AGENT_CLIENTS = 3
        held: list[sshwire.AgentConnection] = []
        try:
            for _ in range(3):
                conn = self.connect()
                held.append(conn)
                self.assertEqual(conn.request(bytes([sshwire.SSH_AGENTC_REQUEST_IDENTITIES]))[0],
                                 sshwire.SSH_AGENT_IDENTITIES_ANSWER)
            self.assertEqual(len(server._threads), 3)
            with self.connect() as extra:
                with self.assertRaises((sshwire.WireError, OSError)):
                    extra.request(bytes([sshwire.SSH_AGENTC_REQUEST_IDENTITIES]))
            self.assertLessEqual(len(server._threads), 3)
            # the refusal record is written right after the client is closed
            self.assertTrue(self.wait_until(lambda: "too_many_agent_clients" in self.audit_reasons()))
            for conn in held:
                conn.close()
            held.clear()
            self.assertTrue(self.wait_until(lambda: len(server._threads) == 0))
            # capacity is returned once clients disconnect
            with self.connect() as conn:
                self.assertEqual(conn.request(self.bind_message()), sshwire.build_success())
                self.assertEqual(self.sign(conn, self.userauth())[0], sshwire.SSH_AGENT_SIGN_RESPONSE)
        finally:
            S.MAX_AGENT_CLIENTS = original
            for conn in held:
                conn.close()

    def test_release_ends_live_client_connections(self) -> None:
        server = self.server()
        conn = self.connect()
        try:
            self.assertEqual(conn.request(self.bind_message()), sshwire.build_success())
            self.assertEqual(len(server._threads), 1)
            started = time.monotonic()
            self.binding.close()
            self.assertLess(time.monotonic() - started, 5)
            self.assertEqual(server._threads, [])
            # the already-bound client connection no longer gets signatures
            with self.assertRaises((sshwire.WireError, OSError)):
                self.sign(conn, self.userauth())
        finally:
            conn.close()
        self.assertEqual(self.ctx.policy.get_grant(self.grant.id).uses, 0)

    # --------------------------------------------- audit policy version (F8)
    def ssh_records(self) -> list[dict]:
        return [r for r in self.ctx.audit.tail(500) if r["event"] in ("ssh_sign", "ssh_bind", "ssh_agent_refused")]

    def test_ssh_audit_records_carry_policy_version(self) -> None:
        version = self.ctx.policy.get_connection("box").policy_version
        with self.connect() as conn:
            self.assertEqual(self.sign(conn, self.userauth()), sshwire.build_failure())  # pre-decision refusal
            self.assertEqual(conn.request(bytes([sshwire.SSH_AGENTC_LOCK])), sshwire.build_failure())
            self.assertEqual(conn.request(self.bind_message()), sshwire.build_success())
            self.assertEqual(self.sign(conn, self.userauth())[0], sshwire.SSH_AGENT_SIGN_RESPONSE)
            self.assertEqual(self.sign(conn, self.userauth(username="root")), sshwire.build_failure())
        records = self.ssh_records()
        kinds = {(r["event"], r["result"]) for r in records}
        for expected in (("ssh_bind", "ok"), ("ssh_sign", "ok"), ("ssh_sign", "denied"), ("ssh_agent_refused", "denied")):
            self.assertIn(expected, kinds)
        for record in records:
            self.assertEqual(record["policy_version"], version, record)
            self.assertEqual(record["target"], "127.0.0.1:2222")
        # a non-widening connection update bumps the version; later records name the new one
        self.ctx.policy.update_connection("box", description="renamed")
        new_version = self.ctx.policy.get_connection("box").policy_version
        self.assertNotEqual(new_version, version)
        seen = len(records)
        with self.connect() as conn:
            self.assertEqual(self.sign(conn, self.userauth()), sshwire.build_failure())
            self.assertEqual(conn.request(self.bind_message()), sshwire.build_success())
            self.assertEqual(self.sign(conn, self.userauth())[0], sshwire.SSH_AGENT_SIGN_RESPONSE)
        later = self.ssh_records()[seen:]
        self.assertEqual({(r["event"], r["result"]) for r in later},
                         {("ssh_sign", "denied"), ("ssh_bind", "ok"), ("ssh_sign", "ok")})
        for record in later:
            self.assertEqual(record["policy_version"], new_version, record)

    # ------------------------------------------------------------ OpenSSH interop
    @unittest.skipIf(shutil.which("ssh-add") is None, "ssh-add not available")
    def test_ssh_add_lists_key_but_cannot_sign_random_data_or_delete(self) -> None:
        env = {"PATH": os.environ.get("PATH", ""), "SSH_AUTH_SOCK": str(self.binding.socket_path)}
        listed = subprocess.run(["ssh-add", "-L"], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertIn(self.user_key.public.to_authorized_key().split()[1], listed.stdout)
        pub = Path(self.tmp.name) / "id.pub"
        pub.write_text(self.user_key.public.to_authorized_key("agent-key") + "\n")
        probe = subprocess.run(["ssh-add", "-T", str(pub)], env=env, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(probe.returncode, 0, "random-data signing must be refused")
        deleted = subprocess.run(["ssh-add", "-D"], env=env, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(deleted.returncode, 0)
        with self.connect() as conn:
            reply = conn.request(bytes([sshwire.SSH_AGENTC_REQUEST_IDENTITIES]))
        self.assertEqual(len(sshwire.parse_identities_answer(reply[1:])), 1)
        reasons = self.audit_reasons()
        self.assertTrue({"no_session_bind", "not_userauth_request"} & set(reasons), reasons)
        self.assertIn("unsupported_agent_message", reasons)


if __name__ == "__main__":
    unittest.main()
