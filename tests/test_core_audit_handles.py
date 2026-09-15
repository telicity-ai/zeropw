"""Audit log value-freedom, fail-closed behaviour, alerts, and handle tokens."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from zeropw.audit import Audit
from zeropw.errors import AuditUnavailable, AuthFailed, InvalidInput
from zeropw.handles import HandleIssuer
from zeropw.store import StateDir


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_700_000_000.0

    def __call__(self) -> float:
        return self.now


class AuditTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state = StateDir(Path(self.tmp.name) / "state")
        self.state.create()
        self.clock = FakeClock()
        self.audit = Audit(self.state, self.clock)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_records_are_whitelisted_and_bounded(self) -> None:
        record = self.audit.record("http_relay", caller="agent-1", connection="gh", target="127.0.0.1:8080",
                                   action="GET", result="ok", policy_version=3,
                                   extra={"path": "/repos?token=synthetic-secret", "status": 200})
        self.assertEqual(record["path"], "/repos")
        raw = (self.state.path / "audit" / "audit.jsonl").read_text()
        self.assertNotIn("synthetic-secret", raw)
        with self.assertRaises(InvalidInput):
            self.audit.record("http_relay", extra={"authorization": "Bearer x"})
        with self.assertRaises(InvalidInput):
            self.audit.record("made_up_event")
        with self.assertRaises(InvalidInput):
            self.audit.record("http_relay", extra={"path": {"nested": 1}})
        long_record = self.audit.record("http_relay", reason="x" * 1000)
        self.assertEqual(len(long_record["reason"]), 200)
        control = self.audit.record("http_relay", target="a\nb\x00c")
        self.assertEqual(control["target"], "a?b?c")

    def test_write_failure_raises_audit_unavailable(self) -> None:
        def broken(name: str, line: str) -> None:
            raise OSError("disk full")

        self.state.append_line = broken  # type: ignore[assignment]
        with self.assertRaises(AuditUnavailable):
            self.audit.record("http_relay", result="ok")
        with self.assertRaises(AuditUnavailable):
            self.audit.require_writable()

    def test_alerts_for_revoked_use_reflection_and_repeated_denials(self) -> None:
        self.audit.record("http_relay", caller="agent-1", result="denied", reason="grant_revoked")
        self.audit.record("http_relay", caller="agent-1", result="denied", reason="credential_reflection_blocked")
        alerts = [a["alert"] for a in self.audit.alerts()]
        self.assertIn("revoked_use_attempt", alerts)
        self.assertIn("credential_reflection", alerts)
        for _ in range(3):
            self.audit.record("http_relay", caller="agent-1", result="denied", reason="path_not_allowed")
        self.assertIn("repeated_denials", [a["alert"] for a in self.audit.alerts()])
        self.assertEqual(sum(1 for a in self.audit.alerts() if a["alert"] == "repeated_denials"), 1)
        self.clock.now += 120
        for _ in range(5):
            self.audit.record("http_relay", caller="agent-2", result="denied", reason="path_not_allowed")
        self.assertEqual(sum(1 for a in self.audit.alerts() if a["alert"] == "repeated_denials"), 2)

    def test_alerts_for_exposure_failures_and_unauthenticated_floods(self) -> None:
        """F6: near-exposures, authenticated-path failures and forged-handle floods raise alerts."""
        cases = (
            ("run_finish", "blocked", "output_credential_blocked", "credential_exposure"),
            ("http_relay", "blocked", "redirect_not_followed", "credential_exposure"),
            ("http_relay", "error", "upstream_tls_failed", "failure"),
            ("http_relay", "error", "credential_unavailable", "failure"),
            ("run_finish", "failed", "credential_unavailable", "failure"),
        )
        for event, result, reason, alert in cases:
            before = len(self.audit.alerts(1000))
            self.audit.record(event, caller="agent-1", connection="gh", result=result, reason=reason)
            added = self.audit.alerts(1000)[before:]
            self.assertEqual([(a["alert"], a["reason"], a["event"]) for a in added], [(alert, reason, event)])
        # Unauthenticated denials (no caller) are counted per event and reason.
        before = len(self.audit.alerts(1000))
        for _ in range(4):
            self.audit.record("http_relay", caller=None, result="denied", reason="handle_signature")
            self.audit.record("http_relay", caller=None, result="denied", reason="handle_malformed")
        self.assertEqual(self.audit.alerts(1000)[before:], [])
        self.audit.record("http_relay", caller=None, result="denied", reason="handle_signature")
        added = self.audit.alerts(1000)[before:]
        self.assertEqual([(a["alert"], a["caller"], a["reason"]) for a in added],
                         [("repeated_denials", None, "handle_signature")])
        # A caller's denials and unauthenticated denials never share a window.
        for _ in range(4):
            self.audit.record("http_relay", caller="agent-9", result="denied", reason="handle_signature")
        self.assertEqual(len(self.audit.alerts(1000)), len(added) + before)

    def test_tail_returns_parsed_records(self) -> None:
        for i in range(5):
            self.audit.record("tools_status", run_id=f"r{i}")
        tail = self.audit.tail(2)
        self.assertEqual([r["run_id"] for r in tail], ["r3", "r4"])
        self.assertTrue(all(json.dumps(r) for r in tail))


class HandleTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.key = HandleIssuer.generate_key()
        self.issuer = HandleIssuer(self.key)
        self.now = 1_700_000_000.0

    def test_issue_and_verify(self) -> None:
        token = self.issuer.issue("agent-1", "gh", "g-1", 4, 300, now=self.now)
        self.assertTrue(token.startswith("zpw1."))
        handle = self.issuer.verify(token, now=self.now + 10)
        self.assertEqual((handle.caller, handle.connection, handle.grant, handle.policy_version), ("agent-1", "gh", "g-1", 4))
        self.assertEqual(handle.expires_at, int(self.now) + 300)

    def test_expiry_signature_and_format(self) -> None:
        token = self.issuer.issue("agent-1", "gh", "g-1", 4, 300, now=self.now)
        with self.assertRaises(AuthFailed) as ctx:
            self.issuer.verify(token, now=self.now + 300)
        self.assertEqual(ctx.exception.reason, "handle_expired")
        head, payload, sig = token.split(".")
        forged_payload = payload[:-2] + ("AA" if payload[-2:] != "AA" else "BB")
        with self.assertRaises(AuthFailed):
            self.issuer.verify(f"{head}.{forged_payload}.{sig}", now=self.now)
        with self.assertRaises(AuthFailed):
            self.issuer.verify(f"{head}.{payload}.{sig[:-1]}x", now=self.now)
        with self.assertRaises(AuthFailed):
            HandleIssuer(HandleIssuer.generate_key()).verify(token, now=self.now)
        for bad in ("", "zpw1", "zpw1.a", "zpw0.a.b", "x" * 5000, None):
            with self.assertRaises(AuthFailed):
                self.issuer.verify(bad, now=self.now)  # type: ignore[arg-type]
        with self.assertRaises(InvalidInput):
            self.issuer.issue("a", "b", "c", 1, 0)
        with self.assertRaises(InvalidInput):
            HandleIssuer(b"short")

    def test_handle_carries_no_secret_material(self) -> None:
        token = self.issuer.issue("agent-1", "gh", "g-1", 4, 300, now=self.now)
        self.assertNotIn(self.key.hex(), token)
        self.assertGreater(len(set(self.issuer.issue("agent-1", "gh", "g-1", 4, 300, now=self.now) for _ in range(3))), 1)


if __name__ == "__main__":
    unittest.main()
