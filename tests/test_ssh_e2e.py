"""End-to-end SSH signing delegation against a real OpenSSH sshd (non-root, loopback).

The test starts ``sshd`` as the current user on an ephemeral 127.0.0.1 port
with a generated host key and an ``authorized_keys`` file holding the public
half of the vault key.  The real ``ssh`` client authenticates with nothing but
``SSH_AUTH_SOCK`` pointing at a ZeroPW signer socket: the private key never
leaves the trusted process.  Skipped (never silently passed) when sshd/ssh
are missing or cannot start in this environment.

``sshd`` runs under ``tests/lifeline.py``: it is stopped (and its temporary
directory removed) when the test process goes away, even if ``tearDown`` never
runs.  The exec-tool test drives ``ssh`` through an inspector wrapper that
records what the exec child could see (its working directory, every file
there, its whole environment) before it becomes the real ``ssh``, and asserts
none of it holds the private key in any encoding.
"""

from __future__ import annotations

import getpass
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from zeropw import policy as P
from zeropw import signer as S
from zeropw import sshwire
from zeropw.context import Config, Context

try:  # test helpers next to this file
    from tests import lifeline
    from tests.leakcheck import find_secret, ssh_key_material
except ImportError:  # pragma: no cover - discovery from another working directory
    import lifeline  # type: ignore[no-redef]
    from leakcheck import find_secret, ssh_key_material  # type: ignore[no-redef]

SSHD = shutil.which("sshd") or ("/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None)
SSH = shutil.which("ssh")
SSH_KEYGEN = shutil.which("ssh-keygen")


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class Sshd:
    """A real sshd on 127.0.0.1, supervised by ``tests/lifeline.py`` (reaped with the test process)."""

    START_ATTEMPTS = 3

    def __init__(self, root: Path, authorized_keys_line: str) -> None:
        self.root = root
        self.port = free_port()
        self.host_key = root / "host_ed25519"
        subprocess.run([SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-f", str(self.host_key)], check=True)
        self.host_key_line = (root / "host_ed25519.pub").read_text().strip()
        self.authorized = root / "authorized_keys"
        self.authorized.write_text(authorized_keys_line + "\n")
        os.chmod(self.authorized, 0o600)
        self.config = root / "sshd_config"
        self._write_config()
        self.proc: subprocess.Popen[str] | None = None
        self.output = ""

    def _write_config(self) -> None:
        self.config.write_text(
            f"Port {self.port}\nListenAddress 127.0.0.1\nHostKey {self.host_key}\nPidFile none\n"
            f"AuthorizedKeysFile {self.authorized}\nPubkeyAuthentication yes\nPasswordAuthentication no\n"
            "KbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nLogLevel ERROR\n"
            "AllowAgentForwarding no\nAllowTcpForwarding no\nX11Forwarding no\nPermitUserEnvironment no\n"
        )

    def start(self) -> bool:
        """True once *this* sshd answers with an OpenSSH banner.

        A port taken by another process between ``free_port()`` and sshd's bind
        makes sshd exit with a bind error; that is retried on a new port.  Any
        other early exit means sshd cannot run here (the caller skips).
        """
        for _attempt in range(self.START_ATTEMPTS):
            self.proc = lifeline.spawn([SSHD, "-D", "-e", "-f", str(self.config)], cleanup_dir=self.root,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            if self._wait_until_serving():
                return True
            self.stop()
            if "Address already in use" not in self.output and "Cannot bind" not in self.output:
                return False
            self.port = free_port()
            self._write_config()
        return False

    def _wait_until_serving(self) -> bool:
        assert self.proc is not None
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                return False
            if self._banner().startswith(b"SSH-2.0-OpenSSH"):
                time.sleep(0.2)   # a squatter can answer before our sshd fails to bind; it would have exited
                return self.proc.poll() is None
            time.sleep(0.1)
        return False

    def _banner(self) -> bytes:
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=0.5) as sock:
                sock.settimeout(1.0)
                data = b""
                while b"\n" not in data and len(data) < 256:
                    chunk = sock.recv(256)
                    if not chunk:
                        break
                    data += chunk
                return data
        except OSError:
            return b""

    def stop(self) -> None:
        proc, self.proc = self.proc, None
        if proc is None:
            return
        try:
            if proc.poll() is None:
                proc.terminate()
            try:
                out, _ = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                lifeline.kill(proc)
                out, _ = proc.communicate()
            self.output = out or ""
        finally:
            lifeline.release(proc)


# Wraps the real ssh client as a connection's CLI program: records what the exec child can see, then becomes ssh.
INSPECTOR_TEMPLATE = """#!{python}
import json, os, sys, time
entries = {{}}
for name in sorted(os.listdir(".")):
    if os.path.isfile(name):
        with open(name, "rb") as fh:
            entries[name] = fh.read().hex()
    else:
        entries[name] = None
report = {{"argv": sys.argv, "cwd": os.getcwd(), "env": dict(os.environ), "entries": entries}}
with open(os.path.join({reports!r}, "%d-%d.json" % (time.time_ns(), os.getpid())), "w") as fh:
    json.dump(report, fh)
os.execv({ssh!r}, [{ssh!r}, *sys.argv[1:]])
"""
EXEC_CHILD_SSH_ENV = {"PATH", "HOME", "LANG", "TMPDIR", "ZEROPW_RUN_ID", "SSH_AUTH_SOCK"}
EXEC_CHILD_SSH_FILES = {"id.pub", "known_hosts"}


def write_ssh_inspector(root: Path) -> tuple[str, Path]:
    """(program path, reports directory) for an inspector that execs the real ssh."""
    bin_dir, reports = root / "inspector-bin", root / "inspector-reports"
    bin_dir.mkdir(mode=0o700, exist_ok=True)
    reports.mkdir(mode=0o700, exist_ok=True)
    program = bin_dir / "ssh-inspector"
    program.write_text(INSPECTOR_TEMPLATE.format(python=sys.executable, reports=str(reports), ssh=SSH))
    os.chmod(program, 0o700)
    return str(program), reports


def assert_exec_children_held_no_key(test: unittest.TestCase, reports: Path, private_key_pem: str,
                                     minimum_reports: int = 1) -> None:
    """Every recorded exec child: only id.pub + known_hosts in its cwd, a fixed env, no key material anywhere."""
    material = ssh_key_material(private_key_pem)
    files = sorted(reports.glob("*.json"))
    test.assertGreaterEqual(len(files), minimum_reports, "the inspector never ran")
    for path in files:
        report = json.loads(path.read_text())
        test.assertEqual(set(report["entries"]), EXEC_CHILD_SSH_FILES, "files in the exec run directory")
        for name, content in report["entries"].items():
            test.assertIsNone(find_secret(bytes.fromhex(content), material), f"run directory file {name}")
        env = report["env"]
        # macOS CoreFoundation adds __CF_USER_TEXT_ENCODING inside the process; ZeroPW does not set it.
        test.assertEqual({name for name in env if not name.startswith("__CF_")}, EXEC_CHILD_SSH_ENV)
        for name, value in env.items():
            test.assertIsNone(find_secret(value, material), f"environment variable {name}")
        for item in report["argv"]:
            test.assertIsNone(find_secret(item, material), "exec child argument")


@unittest.skipIf(not (SSHD and SSH and SSH_KEYGEN), "sshd, ssh, or ssh-keygen not available")
class SshEndToEndTestCase(unittest.TestCase):
    def setUp(self) -> None:
        # Every resource registers its cleanup as soon as it exists: a later setUp failure or skip still
        # stops sshd and removes the directories (tearDown would not run).
        self.tmp = tempfile.TemporaryDirectory(prefix="zpwe-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ctx = Context.initialize(self.root / "state", "admin-passphrase-1", "recovery-passphrase-1", Config())
        self.addCleanup(self.ctx.close)
        self.ctx.projects.create("demo")
        self.user_key = sshwire.generate_ed25519_private_key("agent")
        self.ctx.vault.put_secret("box-key", "ssh_private_key", self.user_key.to_openssh_private_key().encode(),
                                  "demo", "dev")
        self.ctx.policy.create_principal("agent-1")
        self.username = getpass.getuser()
        self.sshd = Sshd(self.root, self.user_key.public.to_authorized_key("agent"))
        self.addCleanup(self.sshd.stop)
        if not self.sshd.start():
            self.skipTest("sshd could not start as a non-root user in this environment")
        self.manager = S.install(self.ctx)
        self.addCleanup(self.manager.shutdown)

    def connection(self, host_key_line: str) -> P.Connection:
        return self.ctx.policy.create_connection(P.Connection(
            id="box", project="demo", environment="dev", service="ssh-box", kind="ssh", secret_id="box-key",
            secret_version=None, description="", http_target=None, http_auth=None, http_scope=None,
            ssh_target=P.SshTarget("127.0.0.1", self.sshd.port, self.username, (host_key_line,)),
            cli=None, policy_version=0, status="active", created_at="", updated_at=""))

    def run_ssh(self, socket_path: Path, known_host_line: str, *remote: str) -> subprocess.CompletedProcess[str]:
        run_dir = self.root / "run"
        run_dir.mkdir(mode=0o700, exist_ok=True)
        known = run_dir / "known_hosts"
        known.write_text(f"[127.0.0.1]:{self.sshd.port} {known_host_line}\n")
        pub = run_dir / "id.pub"
        pub.write_text(self.user_key.public.to_authorized_key("agent") + "\n")
        argv = [SSH, "-F", "/dev/null", "-o", "IdentitiesOnly=yes", "-o", f"IdentityFile={pub}",
                "-o", f"IdentityAgent={socket_path}", "-o", "ForwardAgent=no", "-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={known}", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
                "-o", "KbdInteractiveAuthentication=no", "-o", "ConnectTimeout=10", "-p", str(self.sshd.port),
                f"{self.username}@127.0.0.1", "--", *remote]
        env = {"PATH": os.environ.get("PATH", ""), "HOME": str(run_dir), "SSH_AUTH_SOCK": str(socket_path)}
        return subprocess.run(argv, env=env, capture_output=True, text=True, timeout=60)

    def ssh_audit(self) -> list[tuple[str, str, str | None]]:
        return [(r["event"], r["result"], r.get("reason")) for r in self.ctx.audit.tail(200) if r["event"].startswith("ssh")]

    def test_real_ssh_client_authenticates_through_signer_without_private_key(self) -> None:
        self.connection(self.sshd.host_key_line)
        grant = self.ctx.policy.create_grant("agent-1", "box", 3600, None)
        binding = self.manager.bind("agent-1", "box", grant.id)
        first = self.run_ssh(binding.socket_path, self.sshd.host_key_line, "echo", "hello-from-sshd")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout.strip(), "hello-from-sshd")
        # Same connection, a different remote command: no per-operation registration.
        second = self.run_ssh(binding.socket_path, self.sshd.host_key_line, "printf", "second-%s", "command")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(second.stdout.strip(), "second-command")
        audit = self.ssh_audit()
        self.assertIn(("ssh_bind", "ok", None), audit)
        self.assertEqual(sum(1 for e in audit if e == ("ssh_sign", "ok", None)), 2)
        self.assertEqual(self.ctx.policy.get_grant(grant.id).uses, 2)
        # The execution environment never held the private key.
        for path in (self.root / "run").rglob("*"):
            if path.is_file():
                self.assertNotIn("PRIVATE KEY", path.read_text(errors="replace"))
        binding.close()

    def test_wrong_destination_host_key_is_refused(self) -> None:
        other = sshwire.generate_ed25519_private_key("impostor")
        self.connection(other.public.to_authorized_key("impostor"))
        grant = self.ctx.policy.create_grant("agent-1", "box", 3600, None)
        binding = self.manager.bind("agent-1", "box", grant.id)
        # The client trusts the real server key, but the signer only signs for the configured destination.
        result = self.run_ssh(binding.socket_path, self.sshd.host_key_line, "echo", "should-not-run")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("should-not-run", result.stdout)
        audit = self.ssh_audit()
        self.assertIn(("ssh_bind", "denied", "host_key_not_allowed"), audit)
        self.assertIn(("ssh_sign", "denied", "no_session_bind"), audit)
        self.assertEqual(self.ctx.policy.get_grant(grant.id).uses, 0)

    def test_revoked_grant_cannot_authenticate(self) -> None:
        self.connection(self.sshd.host_key_line)
        grant = self.ctx.policy.create_grant("agent-1", "box", 3600, None)
        binding = self.manager.bind("agent-1", "box", grant.id)
        self.ctx.policy.revoke_grant(grant.id)
        result = self.run_ssh(binding.socket_path, self.sshd.host_key_line, "echo", "should-not-run")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("should-not-run", result.stdout)
        self.assertFalse(binding.socket_path.exists())


@unittest.skipIf(not (SSHD and SSH and SSH_KEYGEN), "sshd, ssh, or ssh-keygen not available")
class ExecToolSshEndToEndTestCase(unittest.TestCase):
    """The agent-native exec tool drives the real ssh client through the signer to a real sshd."""

    def setUp(self) -> None:
        from zeropw import tools

        self.tools = tools
        self.tmp = tempfile.TemporaryDirectory(prefix="zpwx-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ctx = Context.initialize(self.root / "state", "admin-passphrase-1", "recovery-passphrase-1", Config())
        self.addCleanup(self.ctx.close)
        self.ctx.projects.create("demo")
        self.user_key = sshwire.generate_ed25519_private_key("agent")
        self.private_pem = self.user_key.to_openssh_private_key()
        self.ctx.vault.put_secret("box-key", "ssh_private_key", self.private_pem.encode(), "demo", "dev")
        self.ctx.policy.create_principal("agent-1")
        self.sshd = Sshd(self.root, self.user_key.public.to_authorized_key("agent"))
        self.addCleanup(self.sshd.stop)
        if not self.sshd.start():
            self.skipTest("sshd could not start as a non-root user in this environment")
        # The connection's CLI program records what the exec child sees, then becomes the real ssh.
        self.inspector, self.reports = write_ssh_inspector(self.root)
        self.ctx.policy.create_connection(P.Connection(
            id="box", project="demo", environment="dev", service="ssh-box", kind="ssh", secret_id="box-key",
            secret_version=None, description="", http_target=None, http_auth=None, http_scope=None,
            ssh_target=P.SshTarget("127.0.0.1", self.sshd.port, getpass.getuser(), (self.sshd.host_key_line,)),
            cli=P.CliProfile(self.inspector, "ssh"), policy_version=0, status="active", created_at="", updated_at=""))
        self.grant = self.ctx.policy.create_grant("agent-1", "box", 3600, None)
        self.registry = tools.install(self.ctx)
        self.manager = S.install(self.ctx)
        self.addCleanup(self.registry.shutdown)   # runs after manager.shutdown below (cleanups are LIFO)
        self.addCleanup(self.manager.shutdown)

    def run_exec(self, *remote: str) -> dict:
        result = self.tools.exec(self.ctx, "agent-1", "box", list(remote))
        run = self.registry.get(result["run_id"], "agent-1")
        self.registry.wait(run, 60)
        return self.tools.status(self.ctx, "agent-1", result["run_id"])

    def test_exec_tool_runs_two_remote_commands_on_one_connection(self) -> None:
        first = self.run_exec("echo", "exec-tool-first")
        self.assertEqual((first["state"], first["exit_code"]), ("completed", 0), first)
        self.assertEqual(first["stdout"].strip(), "exec-tool-first")
        second = self.run_exec("printf", "exec-%s", "second")
        self.assertEqual((second["state"], second["exit_code"]), ("completed", 0), second)
        self.assertEqual(second["stdout"].strip(), "exec-second")
        signs = [r for r in self.ctx.audit.tail(200) if r["event"] == "ssh_sign" and r["result"] == "ok"]
        self.assertEqual(len(signs), 2)
        self.assertEqual(self.manager.active_bindings(), [])  # per-run sockets are closed afterwards
        material = ssh_key_material(self.private_pem)
        blob = json.dumps([first, second, self.tools.list_connections(self.ctx, "agent-1"),
                           self.ctx.audit.tail(500)])
        self.assertIsNone(find_secret(blob, material))
        self.assertNotIn(str(self.root / "state"), blob)
        # What both exec children could see: their run directory, its files and their environment.
        assert_exec_children_held_no_key(self, self.reports, self.private_pem, minimum_reports=2)

    def test_exec_tool_after_revocation_is_denied_before_ssh_starts(self) -> None:
        from zeropw.errors import PolicyDenied

        self.ctx.policy.revoke_grant(self.grant.id)
        with self.assertRaises(PolicyDenied) as caught:
            self.tools.exec(self.ctx, "agent-1", "box", ["echo", "should-not-run"])
        self.assertEqual(caught.exception.reason, "grant_revoked")


if __name__ == "__main__":
    unittest.main()
