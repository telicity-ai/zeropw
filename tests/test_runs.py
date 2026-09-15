"""RunRegistry: state transitions, bounded capture, cancellation, stop, owner isolation, timeout, scanning."""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

from zeropw import runs as R
from zeropw.context import Config, Context
from zeropw.errors import AuditUnavailable, InvalidInput, NotFound

ADMIN = "admin-passphrase-1"
RECOVERY = "recovery-passphrase-1"
SYNTHETIC = b"synthetic-token-0123456789abcdef"
HANDLE = "zpw1.eyJmYWtlIjoxfQ.c2lnbmF0dXJl"

# Sleeps; when a second argument is given, creates that file once it is running (test synchronisation).
SLEEP_SCRIPT = """
import sys, time
print("sleeping", flush=True)
if len(sys.argv) > 2:
    open(sys.argv[2], "w").write("ready")
time.sleep(float(sys.argv[1]) if len(sys.argv) > 1 else 30)
print("woke")
"""

IGNORE_TERM_SCRIPT = """
import signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
print("armored", flush=True)
open(sys.argv[1], "w").write("ready")
time.sleep(30)
"""

FLOOD_SCRIPT = """
import sys
out = sys.argv[1] if len(sys.argv) > 1 else "600"
err = sys.argv[2] if len(sys.argv) > 2 else "300"
sys.stdout.write("O" * (int(out) * 1024))
sys.stderr.write("E" * (int(err) * 1024))
"""

ECHO_SCRIPT = """
import sys
sys.stdout.write(" ".join(sys.argv[1:]))
sys.stderr.write("err:" + str(len(sys.argv) - 1))
sys.exit(int(sys.argv[1]) if sys.argv[1:] and sys.argv[1].isdigit() else 0)
"""


def write_script(path: Path, body: str) -> str:
    path.write_text(f"#!{sys.executable}\n{body}")
    path.chmod(0o700)
    return str(path)


def minimal_env(home: str) -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home, "LANG": "C.UTF-8"}


class RunRegistryTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ctx = Context.initialize(self.root / "state", ADMIN, RECOVERY, Config())
        self.registry = R.RunRegistry(self.ctx, grace_seconds=1.0)
        self.scripts = self.root / "bin"
        self.scripts.mkdir()
        self.work = self.root / "work"
        self.work.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self.registry.shutdown()
        self.tmp.cleanup()

    # helpers ----------------------------------------------------------------
    def script(self, name: str, body: str) -> str:
        return write_script(self.scripts / name, body)

    def launch(self, program: str, args: list[str], caller: str = "agent-1", grant: str = "g-1",
               sensitive: list[bytes] | None = None, cleanup=None, timeout: float | None = None,
               request_id: str | None = None) -> R.Run:
        run = self.registry.create(caller, "gh", grant, "http", program, request_id=request_id)
        return self.registry.start(run, [program, *args], minimal_env(str(self.work)), str(self.work),
                                   sensitive if sensitive is not None else [SYNTHETIC], cleanup=cleanup,
                                   timeout=timeout)

    def events(self, name: str | None = None) -> list[dict]:
        records = self.ctx.audit.tail(500)
        return [r for r in records if name is None or r["event"] == name]

    # tests ------------------------------------------------------------------
    def test_state_transitions_and_audit(self) -> None:
        program = self.script("echo.py", ECHO_SCRIPT)
        run = self.registry.create("agent-1", "gh", "g-1", "http", program)
        self.assertEqual(run.state, "queued")
        self.assertIsNone(run.started_at)
        started = self.registry.start(run, [program, "hello", "world"], minimal_env(str(self.work)),
                                      str(self.work), [SYNTHETIC])
        self.assertIs(started, run)
        self.assertIn(run.state, ("running", "completed"))
        self.registry.wait(run, 15)
        self.assertEqual(run.state, "completed")
        self.assertEqual(run.exit_code, 0)
        self.assertEqual(run.stdout, b"hello world")
        self.assertEqual(run.stderr, b"err:2")
        self.assertIsNotNone(run.started_at)
        self.assertIsNotNone(run.finished_at)
        self.assertIsNone(run.proc)
        view = self.registry.view(run)
        self.assertEqual(view["state"], "completed")
        self.assertFalse(view["truncated"])
        self.assertNotIn("run_dir", view)
        self.assertNotIn("env", view)
        starts = self.events("run_start")
        finishes = self.events("run_finish")
        self.assertEqual(len(starts), 1)
        self.assertEqual(len(finishes), 1)
        self.assertEqual(finishes[0]["run_id"], run.id)
        self.assertEqual(finishes[0]["result"], "ok")
        self.assertEqual(finishes[0]["exit_code"], 0)
        self.assertEqual(finishes[0]["run_state"], "completed")
        raw = (self.ctx.state.path / "audit" / "audit.jsonl").read_text()
        self.assertNotIn("hello world", raw)  # output text never enters the log

    def test_nonzero_exit_is_completed_with_exit_code(self) -> None:
        program = self.script("echo.py", ECHO_SCRIPT)
        run = self.launch(program, ["3", "x"])
        self.registry.wait(run, 15)
        self.assertEqual(run.state, "completed")
        self.assertEqual(run.exit_code, 3)

    def test_bounded_capture_and_truncation(self) -> None:
        program = self.script("flood.py", FLOOD_SCRIPT)
        run = self.launch(program, ["600", "300"])
        self.registry.wait(run, 30)
        self.assertEqual(run.state, "completed")
        self.assertEqual(len(run.stdout), R.CAPTURE_LIMIT)
        self.assertEqual(len(run.stderr), R.CAPTURE_LIMIT)
        self.assertTrue(run.stdout_truncated)
        self.assertTrue(run.stderr_truncated)
        self.assertTrue(self.registry.view(run)["truncated"])
        small = self.launch(program, ["1", "1"])
        self.registry.wait(small, 30)
        self.assertEqual(len(small.stdout), 1024)
        self.assertFalse(small.stdout_truncated)
        self.assertFalse(self.registry.view(small)["truncated"])

    def await_file(self, path: Path, timeout: float = 15) -> None:
        deadline = time.monotonic() + timeout
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(path.exists(), f"child never signalled readiness via {path}")

    def test_cancel_sleeping_child(self) -> None:
        program = self.script("sleep.py", SLEEP_SCRIPT)
        ready = self.root / "ready"
        run = self.launch(program, ["30", str(ready)])
        self.assertEqual(run.state, "running")
        self.await_file(ready)
        began = time.monotonic()
        self.registry.cancel(run.id, "agent-1")
        self.assertLess(time.monotonic() - began, 8)
        self.registry.wait(run, 10)
        self.assertEqual(run.state, "cancelled")
        self.assertEqual(run.reason, "cancelled_by_caller")
        self.assertEqual(run.exit_code, -15)
        self.assertEqual(run.stdout, b"sleeping\n")
        self.assertEqual(len(self.events("run_cancel")), 1)
        finish = self.events("run_finish")[-1]
        self.assertEqual(finish["result"], "cancelled")
        self.assertEqual(finish["reason"], "cancelled_by_caller")
        # cancelling again is a no-op on a terminal run
        self.registry.cancel(run.id, "agent-1")
        self.assertEqual(run.state, "cancelled")
        self.assertEqual(len(self.events("run_cancel")), 1)

    def test_run_audit_records_carry_target_and_policy_version(self) -> None:
        program = self.script("sleep.py", SLEEP_SCRIPT)
        ready = self.root / "ready-target"
        run, created = self.registry.find_or_create("agent-1", "gh", "g-1", "http", program, "req-t", "d",
                                                    target="https://api.example.test:443", policy_version=7)
        self.assertTrue(created)
        self.assertEqual((run.target, run.policy_version), ("https://api.example.test:443", 7))
        self.registry.start(run, [program, "30", str(ready)], minimal_env(str(self.work)), str(self.work), [SYNTHETIC])
        self.await_file(ready)
        self.registry.cancel(run.id, "agent-1")
        self.registry.wait(run, 10)
        for event in ("run_start", "run_cancel", "run_finish"):
            record = self.events(event)[-1]
            self.assertEqual((record["target"], record["policy_version"]), ("https://api.example.test:443", 7), event)
        # queued cancellation and plain create() keep the fields too
        queued = self.registry.create("agent-1", "box", "g-2", "ssh", program, target="127.0.0.1:2222", policy_version=3)
        self.registry.cancel(queued.id, "agent-1")
        for event in ("run_cancel", "run_finish"):
            record = [r for r in self.events(event) if r["run_id"] == queued.id][-1]
            self.assertEqual((record["target"], record["policy_version"]), ("127.0.0.1:2222", 3), event)
        self.assertNotIn("target", run.public_view())
        self.assertNotIn("policy_version", run.public_view())

    def test_cancel_escalates_to_sigkill(self) -> None:
        program = self.script("armored.py", IGNORE_TERM_SCRIPT)
        ready = self.root / "armored-ready"
        run = self.launch(program, [str(ready)])
        self.await_file(ready)  # the SIGTERM handler is installed before the file appears
        began = time.monotonic()
        self.registry.cancel(run.id, "agent-1")
        elapsed = time.monotonic() - began
        self.registry.wait(run, 10)
        self.assertEqual(run.state, "cancelled")
        self.assertGreaterEqual(elapsed, 0.9)  # SIGTERM was ignored; grace period elapsed
        self.assertLess(elapsed, 8)
        self.assertEqual(run.exit_code, -9)

    def test_cancel_all_on_stop_and_grant_filter(self) -> None:
        program = self.script("sleep.py", SLEEP_SCRIPT)
        run_a = self.launch(program, ["30"], grant="g-a")
        run_b = self.launch(program, ["30"], grant="g-b")
        run_c = self.launch(program, ["30"], caller="agent-2", grant="g-c")
        self.assertEqual(self.registry.on_revoke("grant", "g-a"), None)
        self.registry.wait(run_a, 10)
        self.assertEqual(run_a.state, "cancelled")
        self.assertEqual(run_a.reason, "grant_revoked")
        self.assertEqual(run_b.state, "running")
        self.assertEqual(run_c.state, "running")
        self.registry.on_revoke("stop", None)
        for run in (run_b, run_c):
            self.registry.wait(run, 10)
            self.assertEqual(run.state, "cancelled")
            self.assertEqual(run.reason, "global_stop")
        self.assertEqual(self.registry.cancel_all("anything"), 0)
        self.assertEqual(sorted(r["reason"] for r in self.events("run_cancel")),
                         ["global_stop", "global_stop", "grant_revoked"])

    def test_on_revoke_reason_mapping(self) -> None:
        program = self.script("sleep.py", SLEEP_SCRIPT)
        for kind, reason in (("restore", "restore_pending"), ("connection", "connection_changed"),
                             ("principal", "principal_disabled"), ("all", "grant_revoked")):
            run = self.launch(program, ["30"])
            self.registry.on_revoke(kind, None)
            self.registry.wait(run, 10)
            self.assertEqual((run.state, run.reason), ("cancelled", reason))

    def test_queued_run_cancelled_before_start_never_spawns(self) -> None:
        program = self.script("sleep.py", SLEEP_SCRIPT)
        run = self.registry.create("agent-1", "gh", "g-1", "http", program)
        self.assertEqual(self.registry.cancel_all("global_stop"), 1)
        self.assertEqual(run.state, "cancelled")
        cleaned: list[bool] = []
        self.registry.start(run, [program, "30"], minimal_env(str(self.work)), str(self.work), [SYNTHETIC],
                            cleanup=lambda: cleaned.append(True))
        self.assertEqual(run.state, "cancelled")
        self.assertIsNone(run.proc)
        self.assertEqual(cleaned, [True])
        self.assertEqual(self.events("run_start"), [])

    def test_owner_isolation(self) -> None:
        program = self.script("sleep.py", SLEEP_SCRIPT)
        run = self.launch(program, ["30"], caller="agent-1")
        with self.assertRaises(NotFound) as caught:
            self.registry.get(run.id, "agent-2")
        self.assertEqual(caught.exception.reason, "run_not_found")
        with self.assertRaises(NotFound):
            self.registry.cancel(run.id, "agent-2")
        with self.assertRaises(NotFound):
            self.registry.get("r-doesnotexist", "agent-1")
        self.assertEqual(run.state, "running")
        self.registry.cancel(run.id, "agent-1")
        self.registry.wait(run, 10)
        self.assertEqual(run.state, "cancelled")

    def test_timeout_fails_run(self) -> None:
        program = self.script("sleep.py", SLEEP_SCRIPT)
        began = time.monotonic()
        run = self.launch(program, ["30"], timeout=0.5)
        self.registry.wait(run, 15)
        self.assertEqual(run.state, "failed")
        self.assertEqual(run.reason, "timeout")
        self.assertLess(time.monotonic() - began, 10)
        self.assertEqual(self.events("run_finish")[-1]["result"], "failed")
        self.assertEqual(self.events("run_finish")[-1]["reason"], "timeout")

    def test_output_with_credential_is_blocked(self) -> None:
        program = self.script("echo.py", ECHO_SCRIPT)
        encoded = base64.b64encode(b"prefix:" + SYNTHETIC + b":suffix").decode()
        cases = {
            "raw": SYNTHETIC.decode(),
            "base64": encoded,
            "urlsafe": base64.urlsafe_b64encode(SYNTHETIC).decode(),
            "hex": SYNTHETIC.hex(),
            "urlencoded": "token=" + SYNTHETIC.decode().replace("-", "%2D"),
            "handle": "url http://127.0.0.1:1/h/" + HANDLE + "/repos",
        }
        for label, text in cases.items():
            with self.subTest(label):
                run = self.launch(program, ["0", text], sensitive=[SYNTHETIC, HANDLE.encode()])
                self.registry.wait(run, 15)
                self.assertEqual(run.state, "blocked")
                self.assertEqual(run.reason, "output_credential_blocked")
                self.assertEqual(run.stdout.decode(), R.BLOCKED_MARKER)
                self.assertEqual(run.stderr.decode(), R.BLOCKED_MARKER)
                self.assertFalse(self.registry.view(run)["truncated"])
        finish = [r for r in self.events("run_finish") if r["result"] == "blocked"]
        self.assertEqual(len(finish), len(cases))
        self.assertTrue(all(r["reason"] == "output_credential_blocked" for r in finish))
        clean = self.launch(program, ["0", "nothing sensitive here"], sensitive=[SYNTHETIC, HANDLE.encode()])
        self.registry.wait(clean, 15)
        self.assertEqual(clean.state, "completed")
        self.assertEqual(clean.stdout, b"0 nothing sensitive here")

    def test_credential_patterns_cover_encodings(self) -> None:
        patterns = R.credential_patterns(SYNTHETIC)
        self.assertIn(SYNTHETIC, patterns)
        self.assertIn(base64.b64encode(SYNTHETIC), patterns)
        self.assertIn(base64.urlsafe_b64encode(SYNTHETIC).rstrip(b"="), patterns)
        self.assertIn(SYNTHETIC.hex().encode(), patterns)
        self.assertIn(SYNTHETIC.hex().upper().encode(), patterns)
        self.assertIn(b"synthetic%2Dtoken%2D0123456789abcdef", patterns)
        for shift in range(3):
            blob = base64.b64encode(b"x" * shift + SYNTHETIC + b"trailing-bytes")
            self.assertTrue(R.contains_sensitive(blob, patterns), shift)
        self.assertFalse(R.contains_sensitive(b"unrelated output", patterns))
        self.assertEqual(R.credential_patterns(b""), [])
        short = R.credential_patterns(b"abc")
        self.assertEqual(short[0], b"abc")  # the raw value is always present
        self.assertTrue(all(len(p) >= R.MIN_PATTERN_LENGTH for p in short[1:]), short)
        self.assertNotIn(base64.b64encode(b"abc"), short)  # 4-char derived forms would match noise

    def test_audit_failure_before_start_refuses_and_after_finish_drops_output(self) -> None:
        program = self.script("echo.py", ECHO_SCRIPT)
        original = self.ctx.audit.record

        def broken(event: str, **fields):
            raise AuditUnavailable("audit_write_failed")

        self.ctx.audit.record = broken  # type: ignore[assignment]
        cleaned: list[bool] = []
        run = self.registry.create("agent-1", "gh", "g-1", "http", program)
        with self.assertRaises(AuditUnavailable):
            self.registry.start(run, [program, "hi"], minimal_env(str(self.work)), str(self.work), [SYNTHETIC],
                                cleanup=lambda: cleaned.append(True))
        self.assertEqual(run.state, "failed")
        self.assertEqual(run.reason, "audit_unavailable")
        self.assertEqual(cleaned, [True])

        def finish_only_broken(event: str, **fields):
            if event == "run_finish":
                raise AuditUnavailable("audit_write_failed")
            return original(event, **fields)

        self.ctx.audit.record = finish_only_broken  # type: ignore[assignment]
        run2 = self.launch(program, ["0", "business output"])
        self.registry.wait(run2, 15)
        self.assertEqual(run2.state, "failed")
        self.assertEqual(run2.reason, "audit_unavailable")
        self.assertEqual(run2.stdout, b"")
        self.assertEqual(run2.stderr, b"")
        self.ctx.audit.record = original  # type: ignore[assignment]

    def test_spawn_failure_is_reported_not_raised(self) -> None:
        bogus = self.scripts / "bogus.bin"
        bogus.write_bytes(b"\x00\x01not-an-executable")
        bogus.chmod(0o700)
        cleaned: list[bool] = []
        run = self.registry.create("agent-1", "gh", "g-1", "http", str(bogus))
        self.registry.start(run, [str(bogus)], minimal_env(str(self.work)), str(self.work), [SYNTHETIC],
                            cleanup=lambda: cleaned.append(True))
        self.assertEqual(run.state, "failed")
        self.assertEqual(run.reason, "spawn_failed")
        self.assertEqual(cleaned, [True])
        self.assertEqual(self.events("run_finish")[-1]["reason"], "spawn_failed")

    def test_request_id_idempotency(self) -> None:
        program = self.script("echo.py", ECHO_SCRIPT)
        run = self.launch(program, ["0", "a"], request_id="req-1")
        self.registry.wait(run, 15)
        self.assertIs(self.registry.find_by_request("agent-1", "req-1", ""), run)
        self.assertIsNone(self.registry.find_by_request("agent-2", "req-1", ""))
        self.assertIsNone(self.registry.find_by_request("agent-1", "req-2", ""))
        with self.assertRaises(InvalidInput):
            self.registry.find_by_request("agent-1", "req-1", "different-input")

    def test_cleanup_runs_after_child_exit_and_run_finishes(self) -> None:
        program = self.script("echo.py", ECHO_SCRIPT)
        seen: list[str] = []
        run = self.launch(program, ["0", "x"], cleanup=lambda: seen.append("cleanup"))
        self.registry.wait(run, 15)
        self.assertEqual(seen, ["cleanup"])
        self.assertEqual(run.state, "completed")
        view = json.dumps(self.registry.view(run))
        self.assertNotIn(SYNTHETIC.decode(), view)


if __name__ == "__main__":
    unittest.main()
