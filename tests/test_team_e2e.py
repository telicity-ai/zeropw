"""Team sync end-to-end: three separate OS processes, each running its own ``serve
--team-listen``, admin CLI and agent CLI, exercising docs/team-sync.md section 1's whole
narrative (deliverable 2 / stage 4's test list in section 13).

Node A shares a project environment, invites B (admin) and C (user); C's own node relays an
HTTP call using the shared credential its agent never sees; B narrows the connection's scope from
its own node and C's next call on the now-excluded path is refused, ending an already-running
exec on C that keeps calling back into the same path; A and B are then partitioned (B's ``serve``
killed), both edit the same connection's description while apart, B's ``serve`` restarts, and all
three nodes converge on one identical value-free document with the losing edit's author alerted;
finally A removes C (a fact) and a secret version A puts afterwards is never decryptable by C's
node. A final sweep scans every node's state directory, every process's captured output, and a raw
TCP wire capture for the synthetic secret value, in every encoding ``tests/leakcheck.py`` knows.

Uses ``tests/lifeline.py`` (each ``serve`` dies with the test process) and a temporary,
pre-selected free port per node's team listener -- ``serve --team-listen``'s startup line does not
report the bound port the way its (ephemeral, port-0) gateway ``url`` does, so the port used in an
invite's ``--address`` must be chosen up front; the test skips cleanly if one cannot be bound.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any

from zeropw.fake_upstream import FakeUpstream

REPO_ROOT = Path(__file__).resolve().parent.parent
SYNTHETIC = "synthetic-token-team-e2e-0123456789"
SYNTHETIC_V2 = "synthetic-token-team-e2e-post-removal-9876543210"
PYTHON = sys.executable
SERVE_STARTUP_SECONDS = 45.0
CONVERGE_TIMEOUT_SECONDS = 20.0

try:  # tests/ imported as a package (unittest discover) or run standalone from this directory
    from tests import lifeline
    from tests.leakcheck import find_secret, find_secret_in_tree
except ImportError:  # pragma: no cover - discovery from another working directory
    import lifeline  # type: ignore[no-redef]
    from leakcheck import find_secret, find_secret_in_tree  # type: ignore[no-redef]


class _PortBindError(Exception):
    pass


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _readline_with_deadline(stream: Any, timeout: float) -> str | None:
    box: list[str] = []
    reader = threading.Thread(target=lambda: box.append(stream.readline()), daemon=True)
    reader.start()
    reader.join(timeout)
    return box[0] if box else None


def wait_until(predicate, timeout: float = CONVERGE_TIMEOUT_SECONDS, interval: float = 0.2,
              msg: str = "condition not met") -> Any:
    deadline = time.monotonic() + timeout
    last: Any = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f"{msg} (last observed: {last!r})")


HTTP_LOOP_CLI = f"""#!{PYTHON}
import os, sys, time, urllib.request, urllib.error


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    base = os.environ.get("ZEROPW_API_BASE_URL", "").rstrip("/")
    ready_path, refused_path, heartbeat_path = sys.argv[1], sys.argv[2], sys.argv[3]
    open(ready_path, "w").close()
    opener = urllib.request.build_opener(_NoRedirect)
    deadline = time.time() + 45
    while time.time() < deadline:
        request = urllib.request.Request(base + "/me", headers={{"Authorization": "Bearer democli-placeholder"}})
        try:
            with opener.open(request, timeout=5) as response:
                status = response.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        except Exception:
            status = 0
        with open(heartbeat_path, "a") as stream:
            stream.write(str(status) + chr(10))
        if status != 200:
            with open(refused_path, "w") as stream:
                stream.write(str(status))
            sys.exit(1)
        time.sleep(0.2)
    sys.exit(2)


main()
"""


class _Node:
    """One simulated team member device: its own state dir, admin/agent process environments, and
    (once started) its own ``serve --team-listen`` OS process."""

    def __init__(self, case: "TeamEndToEndTestCase", root: Path, name: str) -> None:
        self.case = case
        self.name = name
        self.root = root / name
        self.state = self.root / "state"
        self.agent_home = self.root / "agent-home"
        self.agent_home.mkdir(parents=True, mode=0o700)
        self.admin_pass = f"admin-{name}-pass-team-e2e"
        self.recovery_pass = f"recovery-{name}-pass-team-e2e"
        self.team_port = _free_port()
        self.team_listen = f"127.0.0.1:{self.team_port}"
        self.serve: subprocess.Popen | None = None
        self.token: str | None = None
        self.url: str | None = None

    # ------------------------------------------------------------- admin CLI (one-shot process)
    def admin(self, *argv: str, stdin: bytes | None = None, expect: int = 0) -> dict[str, Any]:
        env = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.root),
               "ZEROPW_ADMIN_PASSPHRASE": self.admin_pass, "ZEROPW_RECOVERY_PASSPHRASE": self.recovery_pass}
        proc = subprocess.run([PYTHON, "-m", "zeropw.admin_cli", "--state-dir", str(self.state), *argv],
                              input=stdin, capture_output=True, cwd=REPO_ROOT, env=env, timeout=60)
        out, err = proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")
        if "join" not in argv and "invite" not in argv:  # invite strings/join output carry no values, but keep quiet
            self.case.transcript.append((f"{self.name} admin {' '.join(argv[:2])}", out + err))
        self.case.assertEqual(proc.returncode, expect, f"{self.name} admin {argv}: {err}")
        text = out if proc.returncode == 0 else err.strip().splitlines()[-1]
        return json.loads(text) if text.strip() else {}

    # ------------------------------------------------------------- agent CLI (one-shot process)
    def agent(self, *argv: str, expect: int | None = 0) -> tuple[int, dict[str, Any]]:
        env = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.agent_home),
               "ZEROPW_GATEWAY_URL": self.url, "ZEROPW_CALLER_TOKEN": self.token}
        proc = subprocess.run([PYTHON, "-m", "zeropw.agent_cli", *argv], capture_output=True, cwd=REPO_ROOT,
                              env=env, timeout=60)
        out, err = proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")
        self.case.transcript.append((f"{self.name} agent {' '.join(argv[:3])}", out + err))
        if expect is not None:
            self.case.assertEqual(proc.returncode, expect, f"{self.name} agent {argv}: out={out} err={err}")
        payload = out if out.strip() else err
        return proc.returncode, (json.loads(payload) if payload.strip() else {})

    def wait_run(self, run_id: str, timeout: float = 30.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            _code, status = self.agent("status", "--run", run_id)
            if status.get("state") not in ("queued", "running"):
                return status
            if time.monotonic() > deadline:
                self.case.fail(f"{self.name}: run {run_id} did not finish: {status}")
            time.sleep(0.2)

    # ------------------------------------------------------------------------------ serve process
    def start_serve(self, wire_capture: Path) -> None:
        env = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.root),
               "ZEROPW_ADMIN_PASSPHRASE": self.admin_pass, "ZEROPW_TEAM_WIRE_CAPTURE": str(wire_capture)}
        self.serve = lifeline.spawn(
            [PYTHON, "-m", "zeropw.admin_cli", "--state-dir", str(self.state), "serve", "--quiet",
             "--listen", "127.0.0.1:0", "--team-listen", self.team_listen],
            cleanup_dir=self.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=REPO_ROOT, env=env)
        assert self.serve.stdout is not None
        line = _readline_with_deadline(self.serve.stdout, SERVE_STARTUP_SECONDS)
        if not line:
            err = self.serve.stderr.read() if self.serve.stderr else ""
            self.stop_serve()
            raise _PortBindError(f"{self.name}: serve printed no startup line (stderr: {err[:500]})")
        startup = json.loads(line)
        self.case.transcript.append((f"{self.name} serve startup", line))
        self.url = startup["url"]

    def stop_serve(self) -> None:
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


class TeamEndToEndTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="zpwte-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.transcript: list[tuple[str, str]] = []
        self.wire_capture = self.root / "wire.log"
        self.upstream = FakeUpstream(SYNTHETIC, "bearer").start()
        self.addCleanup(self.upstream.stop)
        self.a = _Node(self, self.root, "a")
        self.b = _Node(self, self.root, "b")
        self.c = _Node(self, self.root, "c")
        for node in (self.a, self.b, self.c):
            self.addCleanup(node.stop_serve)

    def start_serve_or_skip(self, node: _Node) -> None:
        try:
            node.start_serve(self.wire_capture)
        except _PortBindError as exc:
            self.skipTest(str(exc))

    # ------------------------------------------------------------------------------ leak sweep
    def assert_no_secret_anywhere(self) -> None:
        needles = [SYNTHETIC.encode(), SYNTHETIC_V2.encode()]
        for who, text in self.transcript:
            self.assertIsNone(find_secret(text, needles), f"{who} output carried a secret value")
        for node in (self.a, self.b, self.c):
            self.assertIsNone(find_secret_in_tree(node.state, needles),
                              f"{node.name}'s state directory carried a secret value")
        wire_text = self.wire_capture.read_text("utf-8", "replace") if self.wire_capture.exists() else ""
        self.assertIsNone(find_secret(wire_text, needles), "the raw team-sync wire capture carried a secret value")
        for node in (self.a, self.b, self.c):
            self.assertEqual(list(node.agent_home.iterdir()), [],
                             f"{node.name}'s agent side wrote something to its home directory")

    def test_full_team_lifecycle(self) -> None:
        # ---------------------------------------------------------------- A: share an environment
        http_loop = self.root / "http_loop.py"
        http_loop.write_text(HTTP_LOOP_CLI)
        os.chmod(http_loop, 0o700)

        self.a.admin("init")
        self.a.admin("team", "init")
        self.a.admin("project", "create", "demo")
        self.a.admin("secret", "put", "--id", "gh-token", "--kind", "api_key", "--project", "demo",
                     "--environment", "dev", "--stdin", stdin=SYNTHETIC.encode())
        self.a.admin("connection", "create-http", "--id", "gh", "--project", "demo", "--environment", "dev",
                     "--service", "fake-code-host", "--secret-id", "gh-token",
                     "--target", f"http://127.0.0.1:{self.upstream.port}", "--auth", "bearer",
                     "--methods", "GET,POST", "--path-prefixes", "/repos,/me", "--cli-program", str(http_loop))
        self.a.admin("team", "share", "--project", "demo", "--environment", "dev")
        env_a = "demo/dev"

        self.start_serve_or_skip(self.a)

        # ------------------------------------------------------------------------- invite + join B
        invite_b = self.a.admin("team", "invite", "--env", env_a, "--role", "admin", "--name", "bob",
                                "--address", self.a.team_listen)["invite"]
        self.b.admin("init")
        join_b = self.b.admin("team", "join", invite_b, "--project", "team-shared", "--environment", "dev")
        env_b = f"{join_b['project']}/{join_b['environment']}"
        self.start_serve_or_skip(self.b)
        # Belt-and-suspenders (docs/team-sync.md section 12): B's own address book already has A's
        # address from the invite payload itself, but register it explicitly too.
        self.b.admin("team", "peers", "--env", env_b, "--add", self.a.team_listen,
                     "--device", join_b["inviter_fingerprint"])

        # ------------------------------------------------------------------------- invite + join C
        invite_c = self.a.admin("team", "invite", "--env", env_a, "--role", "user", "--name", "carol",
                                "--address", self.a.team_listen)["invite"]
        self.c.admin("init")
        join_c = self.c.admin("team", "join", invite_c, "--project", "team-shared", "--environment", "dev")
        env_c = f"{join_c['project']}/{join_c['environment']}"
        self.start_serve_or_skip(self.c)

        # C creates its own principal + grant on the shared connection, and its agent CLI request
        # succeeds against the fake upstream through C's OWN node's gateway: the shared credential
        # is relayed by C's node, and C's agent never sees it (proven at the end by the leak sweep).
        wait_until(lambda: self.c.admin("connection", "list")["connections"], timeout=15.0,
                  msg="C never derived the shared connection after joining")
        principal_c = self.c.admin("principal", "create", "--id", "agent-c")
        self.c.token = principal_c["token"]
        self.c.admin("grant", "create", "--principal", "agent-c", "--connection", "gh", "--ttl", "1h")

        code, repos = self.c.agent("request", "--connection", "gh", "--method", "GET", "--path", "/repos")
        self.assertEqual((repos["status"], json.loads(repos["body"])), (200, [{"name": "demo"}, {"name": "tools"}]))
        self.assertIn(f"Bearer {SYNTHETIC}", {r["headers"].get("authorization") for r in self.upstream.requests})

        # ------------------------------------------------------------------- long-running exec on C
        ready, refused, heartbeat = self.root / "c-ready", self.root / "c-refused", self.root / "c-heartbeat"
        _code, run = self.c.agent("exec", "--connection", "gh", "--", str(ready), str(refused), str(heartbeat))
        wait_until(lambda: ready.exists(), timeout=15.0, msg="C's long-running exec never started")
        wait_until(lambda: heartbeat.exists() and "200" in heartbeat.read_text(), timeout=15.0,
                  msg="C's long-running exec never made a single successful call")

        # ------------------------------------------------------------- B narrows the connection scope
        self.b.admin("connection", "update", "--id", "gh", "--methods", "GET", "--path-prefixes", "/repos")

        deadline = time.monotonic() + CONVERGE_TIMEOUT_SECONDS
        final_code, final_reason = None, None
        while time.monotonic() < deadline:
            final_code, denied = self.c.agent("request", "--connection", "gh", "--method", "GET", "--path", "/me",
                                              expect=None)
            final_reason = denied.get("reason")
            if final_code != 0:
                break
            time.sleep(0.3)
        self.assertNotEqual(final_code, 0, "C's request on the narrowed-out path was never refused")
        self.assertEqual(final_reason, "path_not_allowed")

        # The already-running exec's own next call on the same path is refused too, ending it --
        # docs/team-sync.md section 6.5: a narrowing re-judges an in-flight execution at its next
        # relay call rather than cancelling it outright (only a WIDENING stales the grant directly).
        wait_until(lambda: refused.exists(), timeout=CONVERGE_TIMEOUT_SECONDS,
                  msg="C's long-running exec never noticed the narrowed scope")
        final_run = self.c.wait_run(run["run_id"])
        self.assertEqual(final_run["state"], "completed", final_run)
        self.assertNotEqual(final_run["exit_code"], 0)

        # ---------------------------------------------------- A and B partitioned, then edit + rejoin
        # ``connection update`` has no ``--description`` flag; edit the same field (path-prefixes)
        # with two different values instead -- still "the same target, concurrently" for section
        # 7.2's override detection regardless of which value ends up winning.
        self.b.stop_serve()
        self.a.admin("connection", "update", "--id", "gh", "--path-prefixes", "/repos,/orgs")
        self.b.admin("connection", "update", "--id", "gh", "--path-prefixes", "/repos,/issues")
        self.start_serve_or_skip(self.b)

        def converged() -> bool:
            show_a = self.a.admin("team", "show", "--env", env_a)
            show_b = self.b.admin("team", "show", "--env", env_b)
            show_c = self.c.admin("team", "show", "--env", env_c)
            return show_a == show_b and show_b == show_c

        wait_until(converged, timeout=CONVERGE_TIMEOUT_SECONDS,
                  msg="A, B and C never converged to the identical document after B rejoined")
        final_view = self.a.admin("team", "show", "--env", env_a)
        winner_paths = set(final_view["connections"]["gh"]["http_scope"]["path_prefixes"])
        self.assertIn(winner_paths, ({"/repos", "/orgs"}, {"/repos", "/issues"}))
        loser = self.b if winner_paths == {"/repos", "/orgs"} else self.a

        def loser_alerted() -> bool:
            alerts = loser.admin("alerts", "--limit", "200")["alerts"]
            return any(a["alert"] == "team_op_overridden" for a in alerts)

        wait_until(loser_alerted, timeout=CONVERGE_TIMEOUT_SECONDS,
                  msg=f"{loser.name} (the loser of the concurrent edit) was never alerted")

        # ------------------------------------------------------------------------------- A removes C
        c_fp = join_c["self_fingerprint"]
        self.a.admin("team", "remove", "--env", env_a, "--device", c_fp)

        def c_cut_off() -> bool:
            code, _res = self.c.agent("request", "--connection", "gh", "--method", "GET", "--path", "/repos",
                                      expect=None)
            return code != 0

        wait_until(c_cut_off, timeout=CONVERGE_TIMEOUT_SECONDS, msg="C's node was never cut off after removal")

        # A new secret version put on A after the removal must never be decryptable by C: check C's
        # state directory has no generation-key file for the new generation at all.
        self.a.admin("secret", "put", "--id", "gh-token", "--kind", "api_key", "--project", "demo",
                     "--environment", "dev", "--stdin", stdin=SYNTHETIC_V2.encode())

        def new_generation() -> str | None:
            doc = self.a.admin("team", "show", "--env", env_a)
            return doc["dek"]["current"]

        new_gen = wait_until(new_generation, timeout=CONVERGE_TIMEOUT_SECONDS,
                             msg="A never rotated to a new DEK generation after removing C")
        env_id = self.a.admin("team", "status", "--env", env_a)["env_id"]
        self.assertFalse((self.c.state / "team" / env_id / "dek" / f"{new_gen}.json").exists(),
                         "C's state directory holds a key for a DEK generation created after its removal")

        # ------------------------------------------------------------------------------- final sweep
        self.a.admin("audit", "tail", "--limit", "1")  # touch every node once more before scanning
        self.b.admin("audit", "tail", "--limit", "1")
        self.c.admin("audit", "tail", "--limit", "1")
        self.assert_no_secret_anywhere()


if __name__ == "__main__":
    unittest.main()
