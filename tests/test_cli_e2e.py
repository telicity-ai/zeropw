"""Multi-process end-to-end test through the shipped command-line entry points.

Every ZeroPW component runs as its own OS process, exactly as documented in
docs/implementation.md §9:

* the administrator configures state with ``python -m zeropw.admin_cli``;
* the trusted process is ``python -m zeropw.admin_cli ... serve``;
* the agent side only runs ``python -m zeropw.agent_cli`` with a gateway URL
  and its caller token in a minimal environment;
* the external service is a controlled fake API (in this test process), and
  the SSH destination is a real ``sshd`` started as the current user.

The test covers one connection used for several different operations without
registration, the CLI exec path for HTTP and SSH, reflection blocking,
revocation and global stop issued by a separate admin process while ``serve``
is running, and a final sweep that the synthetic credential and the SSH
private key never appear -- raw or in any encoding ``tests/leakcheck.py``
knows, including decoded base64/hex/percent tokens -- on the agent side, in
``serve`` output, or anywhere in the state directory.  SSH exec children are
inspected directly (run directory files and environment).

``serve`` and ``sshd`` run under ``tests/lifeline.py`` and die with the test
process; ``serve``'s startup line is read with a deadline.

Cancelling an SSH run stops the local ``ssh`` client only.  A command already
running on the server keeps running (docs/security-design.md §5: revocation
does not end an authenticated SSH session); the test observes that through a
heartbeat file and stops the remote loops itself.
"""

from __future__ import annotations

import getpass
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any

from zeropw import sshwire
from zeropw.fake_upstream import FakeUpstream

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMOCLI = REPO_ROOT / "examples" / "democli.py"
SYNTHETIC = "synthetic-token-cli-e2e-0123456789"
ADMIN = "admin-passphrase-cli-e2e"
RECOVERY = "recovery-passphrase-cli-e2e"
PYTHON = sys.executable

SERVE_STARTUP_SECONDS = 60.0

try:  # the real-sshd helper lives next to the SSH end-to-end tests
    from tests import lifeline
    from tests.leakcheck import find_secret, find_secret_in_tree, ssh_key_material
    from tests.test_ssh_e2e import SSH, SSHD, SSH_KEYGEN, Sshd, assert_exec_children_held_no_key, write_ssh_inspector
except ImportError:  # pragma: no cover - discovery from another working directory
    import lifeline  # type: ignore[no-redef]
    from leakcheck import find_secret, find_secret_in_tree, ssh_key_material  # type: ignore[no-redef]
    from test_ssh_e2e import (SSH, SSHD, SSH_KEYGEN, Sshd, assert_exec_children_held_no_key,  # type: ignore[no-redef]
                              write_ssh_inspector)


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _readline_with_deadline(stream: Any, timeout: float) -> str | None:
    """One line from ``stream``; ``None`` if none arrived within ``timeout`` (the reader stays blocked)."""
    box: list[str] = []
    reader = threading.Thread(target=lambda: box.append(stream.readline()), daemon=True)
    reader.start()
    reader.join(timeout)
    return box[0] if box else None


class CliEndToEndTestCase(unittest.TestCase):
    def setUp(self) -> None:
        # Cleanups are registered as each resource is created, so a failure anywhere still releases it.
        self.tmp = tempfile.TemporaryDirectory(prefix="zpwc-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.agent_home = self.root / "agent-home"
        self.agent_home.mkdir(mode=0o700)
        self.transcript: list[tuple[str, str]] = []   # (who, text) of everything captured
        self.serve: subprocess.Popen[str] | None = None
        self.upstream = FakeUpstream(SYNTHETIC, "bearer").start()
        self.addCleanup(self.upstream.stop)
        self.addCleanup(self.halt_serve)
        self.sshd: Sshd | None = None

    def halt_serve(self) -> None:
        serve, self.serve = self.serve, None
        if serve is None:
            return
        try:
            if serve.poll() is None:
                serve.terminate()
            try:
                serve.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                lifeline.kill(serve)
                serve.communicate()
        finally:
            lifeline.release(serve)

    # ------------------------------------------------------------ processes
    def admin(self, *argv: str, stdin: bytes | None = None, expect: int = 0) -> dict[str, Any]:
        env = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.root),
               "ZEROPW_ADMIN_PASSPHRASE": ADMIN, "ZEROPW_RECOVERY_PASSPHRASE": RECOVERY}
        proc = subprocess.run([PYTHON, "-m", "zeropw.admin_cli", "--state-dir", str(self.state), *argv],
                              input=stdin, capture_output=True, cwd=REPO_ROOT, env=env, timeout=120)
        out, err = proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")
        if "reveal" not in argv:
            self.transcript.append((f"admin {' '.join(argv[:2])}", out + err))
        self.assertEqual(proc.returncode, expect, f"admin {argv}: {err}")
        text = out if proc.returncode == 0 else err.strip().splitlines()[-1]
        return json.loads(text) if text.strip() else {}

    def agent(self, *argv: str, expect: int | None = 0) -> tuple[int, dict[str, Any]]:
        # The agent side gets the gateway URL and its own caller token, nothing else.
        env = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.agent_home),
               "ZEROPW_GATEWAY_URL": self.url, "ZEROPW_CALLER_TOKEN": self.token}
        proc = subprocess.run([PYTHON, "-m", "zeropw.agent_cli", *argv], capture_output=True, cwd=REPO_ROOT,
                              env=env, timeout=120)
        out, err = proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")
        self.transcript.append((f"agent {' '.join(argv[:3])}", out + err))
        if expect is not None:
            self.assertEqual(proc.returncode, expect, f"agent {argv}: out={out} err={err}")
        payload = out if out.strip() else err
        return proc.returncode, (json.loads(payload) if payload.strip() else {})

    def start_serve(self) -> None:
        env = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.root), "ZEROPW_ADMIN_PASSPHRASE": ADMIN}
        # Supervised: if this test process dies, serve is stopped and the state directory removed.
        self.serve = lifeline.spawn([PYTHON, "-m", "zeropw.admin_cli", "--state-dir", str(self.state), "serve",
                                     "--quiet"], cleanup_dir=self.root, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True, cwd=REPO_ROOT, env=env)
        assert self.serve.stdout is not None
        line = _readline_with_deadline(self.serve.stdout, SERVE_STARTUP_SECONDS)
        if line is None:
            self.halt_serve()
            self.fail(f"serve printed no startup line within {SERVE_STARTUP_SECONDS:.0f}s")
        if not line:  # read stderr only on failure: reading it eagerly would block until serve exits
            self.fail(f"serve printed nothing: {self.serve.stderr.read() if self.serve.stderr else ''}")
        startup = json.loads(line)
        self.transcript.append(("serve startup", line))
        self.url = startup["url"]
        self.startup = startup

    def stop_serve(self) -> tuple[int, str]:
        assert self.serve is not None
        serve, self.serve = self.serve, None
        try:
            serve.terminate()
            out, err = serve.communicate(timeout=20)
        finally:
            lifeline.release(serve)
        self.transcript.append(("serve exit", out + err))
        return serve.returncode, out + err

    def wait_run(self, run_id: str, timeout: float = 60.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            _code, status = self.agent("status", "--run", run_id)
            if status.get("state") not in ("queued", "running"):
                return status
            if time.monotonic() > deadline:
                self.fail(f"run {run_id} did not finish: {status}")
            time.sleep(0.2)

    def until(self, predicate, timeout: float = 10.0) -> Any:
        deadline = time.monotonic() + timeout
        while True:
            value = predicate()
            if value:
                return value
            if time.monotonic() > deadline:
                return value
            time.sleep(0.2)

    # ------------------------------------------------------------ assertions
    def assert_no_secret_anywhere(self, private_key_pem: str | None) -> None:
        """No secret -- raw, in any scanned encoding, or inside a decoded base64/hex/percent token -- in any
        captured agent/admin/serve output or in any file of the state directory."""
        secrets = [SYNTHETIC.encode()]
        if private_key_pem:
            secrets += ssh_key_material(private_key_pem)
        for who, text in self.transcript:
            self.assertIsNone(find_secret(text, secrets), f"{who} output carried secret material")
        self.assertIsNone(find_secret_in_tree(self.state, secrets), "secret material in the state directory")

    # ------------------------------------------------------------ shared setup
    def admin_base(self) -> None:
        init = self.admin("init")
        self.assertEqual(set(init), {"state_dir", "kms_key_id"})
        self.admin("project", "create", "demo")
        principal = self.admin("principal", "create", "--id", "agent-1")
        self.token = principal["token"]
        self.assertTrue(self.token.startswith("zpwc_"))

    def sample_cli(self) -> Path:
        # A copy of the sample CLI pinned to this interpreter: on macOS "#!/usr/bin/env python3" can go
        # through the Xcode shim, which adds SDKROOT/CPATH/... inside the child and would blur what ZeroPW sets.
        program = self.root / "bin" / "democli.py"
        program.parent.mkdir(mode=0o700, exist_ok=True)
        program.write_text("#!" + PYTHON + "\n" + DEMOCLI.read_text().split("\n", 1)[1])
        os.chmod(program, 0o700)
        return program

    # ------------------------------------------------------------ HTTP
    def test_http_connection_through_admin_serve_and_agent_processes(self) -> None:
        self.admin_base()
        self.admin("secret", "put", "--id", "gh", "--kind", "api_key", "--project", "demo", "--environment", "dev",
                   "--stdin", stdin=SYNTHETIC.encode())
        self.admin("connection", "create-http", "--id", "gh", "--project", "demo", "--environment", "dev",
                   "--service", "fake-code-host", "--secret-id", "gh",
                   "--target", f"http://127.0.0.1:{self.upstream.port}", "--auth", "bearer",
                   "--methods", "GET,POST", "--path-prefixes", "/repos,/me,/echo-headers",
                   "--cli-program", str(self.sample_cli()))
        grant = self.admin("grant", "create", "--principal", "agent-1", "--connection", "gh",
                           "--ttl", "1h", "--max-uses", "50")
        self.start_serve()

        # One connection, several different operations, no registration.
        _code, listed = self.agent("list-connections")
        self.assertEqual([c["id"] for c in listed["connections"]], ["gh"])
        self.assertNotIn("secret_id", json.dumps(listed))
        _code, repos = self.agent("request", "--connection", "gh", "--method", "GET", "--path", "/repos")
        self.assertEqual((repos["status"], json.loads(repos["body"])), (200, [{"name": "demo"}, {"name": "tools"}]))
        _code, issue = self.agent("request", "--connection", "gh", "--method", "POST", "--path", "/repos/demo/issues",
                                  "--header", "Content-Type: application/json", "--body", '{"title": "from agent"}')
        self.assertEqual((issue["status"], json.loads(issue["body"])["title"]), (201, "from agent"))
        _code, run = self.agent("exec", "--connection", "gh", "--", "whoami")
        whoami = self.wait_run(run["run_id"])
        self.assertEqual((whoami["state"], whoami["exit_code"]), ("completed", 0), whoami)
        self.assertEqual(json.loads(whoami["stdout"])["body"], {"login": "synthetic-user"})

        # The CLI child holds nothing but the opaque base URL.
        _code, run = self.agent("exec", "--connection", "gh", "--", "steal")
        steal = self.wait_run(run["run_id"])
        self.assertEqual(steal["state"], "completed", steal)
        report = json.loads(steal["stdout"])
        # __CF_USER_TEXT_ENCODING is added by macOS CoreFoundation inside the process, not by ZeroPW.
        env_names = sorted(n for n in report["env_names"] if n != "__CF_USER_TEXT_ENCODING")
        self.assertEqual(env_names, ["HOME", "LANG", "PATH", "TMPDIR", "ZEROPW_API_BASE_URL", "ZEROPW_RUN_ID"])
        self.assertEqual(report["home_entries"], [], "the exec run directory (HOME) must be empty for an HTTP CLI")
        self.assertEqual(report["probes"], {name: "missing" for name in report["probes"]})
        self.assertEqual(len(report["probes"]), 8)
        self.assertNotIn(str(self.state), json.dumps(report))

        # The upstream saw the real synthetic credential every time, never the CLI placeholder.
        self.assertEqual({r["headers"].get("authorization") for r in self.upstream.requests}, {f"Bearer {SYNTHETIC}"})
        self.assertEqual(len(self.upstream.requests), 3)

        # Reflection is refused and the agent CLI exits non-zero with the reason; so is a path outside the scope.
        code, reflected = self.agent("request", "--connection", "gh", "--method", "GET", "--path", "/echo-headers",
                                     expect=None)
        self.assertEqual((code != 0, reflected["reason"]), (True, "credential_reflection_blocked"))
        code, denied = self.agent("request", "--connection", "gh", "--method", "GET", "--path", "/debug/token",
                                  expect=None)
        self.assertEqual((code != 0, denied["reason"]), (True, "path_not_allowed"))

        # Revocation by a separate admin process while serve is running.
        self.admin("grant", "revoke", "--id", grant["id"])
        code, revoked = self.agent("request", "--connection", "gh", "--method", "GET", "--path", "/repos", expect=None)
        self.assertEqual((code != 0, revoked["reason"]), (True, "grant_revoked"))
        code, refused = self.agent("exec", "--connection", "gh", "--", "whoami", expect=None)
        self.assertEqual((code != 0, refused["reason"]), (True, "grant_revoked"))
        self.assertEqual(len(self.upstream.requests), 4)   # only the blocked /echo-headers call was added

        # Global stop and resume from the admin process.
        self.admin("grant", "create", "--principal", "agent-1", "--connection", "gh", "--ttl", "1h")
        self.admin("stop-all")
        _code, stopped = self.agent("list-connections")
        self.assertEqual(stopped["connections"], [])
        code, refused = self.agent("request", "--connection", "gh", "--method", "GET", "--path", "/me", expect=None)
        self.assertEqual((code != 0, refused["reason"]), (True, "global_stop"))
        self.admin("resume")
        _code, back = self.agent("request", "--connection", "gh", "--method", "GET", "--path", "/me")
        self.assertEqual(back["status"], 200)

        # Value-free audit records and alerts for the administrator.
        events = {r["event"] for r in self.admin("audit", "tail", "--limit", "500")["records"]}
        for expected in ("http_relay", "tools_request", "tools_exec", "run_start", "run_finish", "grant_revoke",
                         "stop_all", "resume"):
            self.assertIn(expected, events)
        alerts = {a["alert"] for a in self.admin("alerts", "--limit", "100")["alerts"]}
        self.assertIn("credential_reflection", alerts)

        code, serve_output = self.stop_serve()
        self.assertEqual(code, 0, serve_output)
        self.assert_no_secret_anywhere(None)
        self.assertEqual(list(self.agent_home.iterdir()), [], "the agent side wrote nothing to its home directory")

    # ------------------------------------------------------------ SSH
    def beats(self, heartbeat: Path) -> int:
        try:
            return len(heartbeat.read_bytes().splitlines())
        except FileNotFoundError:
            return 0

    def stop_remote_loops(self) -> None:
        """Stop every heartbeat loop still running on sshd (each checks this file between beats)."""
        stop = self.root / "remote-stop"
        try:
            stop.touch()
        except OSError:
            return   # the directory is gone; the loops end on their next failed append
        beating = sorted(self.root.glob("heartbeat-*"))
        deadline = time.monotonic() + 5
        counts = [self.beats(path) for path in beating]
        while time.monotonic() < deadline:
            time.sleep(0.5)
            now = [self.beats(path) for path in beating]
            if now == counts:
                break
            counts = now
        stop.unlink(missing_ok=True)

    def assert_long_run_cancelled_by(self, admin_argv: tuple[str, ...], reason: str) -> None:
        heartbeat = self.root / f"heartbeat-{reason}"
        stop = self.root / "remote-stop"
        # One argument: ssh hands it to the remote login shell.  The loop ends by itself after ~60 s, when the
        # stop file appears, or when the test directory is gone (the append fails).
        remote = (f"i=0; while [ $i -lt 600 ] && [ ! -e '{stop}' ] && echo beat >> '{heartbeat}'; "
                  f"do i=$((i+1)); sleep 0.1; done")
        known_reports = set(self.inspector_reports.glob("*.json"))
        _code, run = self.agent("exec", "--connection", "box", "--", remote)
        started = time.monotonic()
        self.assertTrue(self.until(lambda: self.beats(heartbeat) > 0, timeout=20),
                        "the long remote command never started on sshd")
        # The inspector names its report after its pid, which the real ssh client keeps (execv).
        (report,) = [path for path in self.inspector_reports.glob("*.json") if path not in known_reports]
        client_pid = int(report.stem.split("-")[1])
        self.assertTrue(_pid_alive(client_pid))
        self.admin(*admin_argv)
        final = self.wait_run(run["run_id"], timeout=30)
        self.assertEqual((final["state"], final["reason"]), ("cancelled", reason), final)
        self.assertLess(time.monotonic() - started, 30, "cancellation must not wait for the remote command")
        # What cancellation does stop: the local ssh client process.
        self.assertTrue(self.until(lambda: not _pid_alive(client_pid), timeout=10),
                        "the local ssh client still runs after its run was cancelled")
        # Documented limit (docs/security-design.md §5, docs/implementation.md §6/§8): cancelling kills the local
        # ssh client; the command already running on the server is not ended by ZeroPW.
        at_cancel = self.beats(heartbeat)
        self.assertTrue(self.until(lambda: self.beats(heartbeat) > at_cancel + 3, timeout=10),
                        "the remote command stopped: update the documented SSH cancellation limit")
        self.stop_remote_loops()

    @unittest.skipIf(not (SSHD and SSH and SSH_KEYGEN), "sshd, ssh, or ssh-keygen not available")
    def test_ssh_connection_through_admin_serve_agent_processes_and_real_sshd(self) -> None:
        self.admin_base()
        user_key = sshwire.generate_ed25519_private_key("cli-e2e")
        private_pem = user_key.to_openssh_private_key()
        self.sshd = Sshd(self.root, user_key.public.to_authorized_key("cli-e2e"))
        self.addCleanup(self.sshd.stop)
        self.addCleanup(self.stop_remote_loops)   # runs before sshd.stop (cleanups are LIFO)
        if not self.sshd.start():
            self.skipTest("sshd could not start as a non-root user in this environment")
        inspector, reports = write_ssh_inspector(self.root)   # records what each exec child sees, then runs ssh
        self.inspector_reports = reports
        key_file = self.root / "admin-only" / "id_ed25519"
        key_file.parent.mkdir(mode=0o700)
        key_file.write_text(private_pem)
        os.chmod(key_file, 0o600)
        self.admin("secret", "put", "--id", "box-key", "--kind", "ssh_private_key", "--project", "demo",
                   "--environment", "dev", "--value-file", str(key_file))
        key_file.unlink()   # the only plaintext copy lived in the administrator's own directory
        self.admin("connection", "create-ssh", "--id", "box", "--project", "demo", "--environment", "dev",
                   "--service", "ssh-box", "--secret-id", "box-key", "--host", "127.0.0.1",
                   "--port", str(self.sshd.port), "--username", getpass.getuser(),
                   "--host-key", self.sshd.host_key_line, "--cli-program", inspector)
        grant = self.admin("grant", "create", "--principal", "agent-1", "--connection", "box", "--ttl", "1h")
        self.start_serve()
        self.assertEqual(self.startup["ssh_signer"], "available")

        # Two different remote commands on one connection.
        _code, run = self.agent("exec", "--connection", "box", "--", "echo", "cli-e2e-ssh-first")
        first = self.wait_run(run["run_id"])
        self.assertEqual((first["state"], first["exit_code"], first["stdout"].strip()),
                         ("completed", 0, "cli-e2e-ssh-first"), first)
        _code, run = self.agent("exec", "--connection", "box", "--", "printf", "second-%s", "command")
        second = self.wait_run(run["run_id"])
        self.assertEqual((second["state"], second["stdout"].strip()), ("completed", "second-command"), second)

        # A long remote command's run is cancelled when a separate admin process stops everything.
        self.assert_long_run_cancelled_by(("stop-all",), "global_stop")
        code, refused = self.agent("exec", "--connection", "box", "--", "echo", "must-not-run", expect=None)
        self.assertEqual((code != 0, refused["reason"]), (True, "global_stop"))
        self.admin("resume")

        # Revoking the grant from the admin process cancels the in-flight run (the local ssh client); the next
        # exec is refused.
        self.assert_long_run_cancelled_by(("grant", "revoke", "--id", grant["id"]), "grant_revoked")
        code, refused = self.agent("exec", "--connection", "box", "--", "echo", "must-not-run", expect=None)
        self.assertEqual((code != 0, refused["reason"]), (True, "grant_revoked"))

        # Disabling the connection from the admin process cancels the in-flight run as well (local client only).
        self.admin("grant", "create", "--principal", "agent-1", "--connection", "box", "--ttl", "1h")
        self.assert_long_run_cancelled_by(("connection", "disable", "--id", "box"), "connection_disabled")
        code, refused = self.agent("exec", "--connection", "box", "--", "echo", "must-not-run", expect=None)
        self.assertEqual((code != 0, refused["reason"]), (True, "connection_disabled"))

        tail = self.admin("audit", "tail", "--limit", "500")["records"]
        signs = [r for r in tail if r["event"] == "ssh_sign" and r["result"] == "ok"]
        self.assertGreaterEqual(len(signs), 3)
        self.assertTrue(all(r.get("policy_version") is not None for r in signs))
        cancels = {(r["event"], r["reason"]) for r in tail}
        for expected in ("global_stop", "grant_revoked", "connection_disabled"):
            self.assertIn(("run_cancel", expected), cancels)

        code, serve_output = self.stop_serve()
        self.assertEqual(code, 0, serve_output)
        self.assert_no_secret_anywhere(private_pem)
        # Every exec child (two commands and three cancelled loops): run directory and environment hold no key.
        assert_exec_children_held_no_key(self, reports, private_pem, minimum_reports=5)
        self.assertEqual(list(self.agent_home.iterdir()), [], "the agent side wrote nothing to its home directory")


if __name__ == "__main__":
    unittest.main()
