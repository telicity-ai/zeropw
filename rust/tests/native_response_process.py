"""Native-process equivalents of response tests that originally mocked serve.

Only test driving/endpoints use Python. All product work is performed by the
native administrator, server, agent, and configured /bin/sleep executable.
"""
import json
import os
import time

from tests.test_cli_e2e import (
    SYNTHETIC, SMTP_PASSWORD, _CliProcessTestCase, FakeSmtp, parse_message,
)


class NativeResponseProcessTests(_CliProcessTestCase):
    def seed(self):
        self.admin("init")
        self.admin("project", "create", "demo")
        self.token = self.admin("principal", "create", "--id", "agent-1", "--runtime", "rt-shared")["token"]
        self.admin("principal", "create", "--id", "agent-2", "--runtime", "rt-shared")
        self.admin("secret", "put", "--id", "key", "--kind", "api_key", "--project", "demo",
                   "--environment", "dev", "--stdin", stdin=SYNTHETIC.encode())
        self.admin("connection", "create-http", "--id", "gh", "--project", "demo", "--environment", "dev",
                   "--service", "fake", "--secret-id", "key", "--auth", "bearer",
                   "--target", f"http://127.0.0.1:{self.upstream.port}", "--cli-program", "/bin/sleep")
        self.admin("grant", "create", "--principal", "agent-1", "--connection", "gh", "--ttl", "1h")

    def notify_config(self, smtp):
        password = self.root / "smtp.pass"
        password.write_text(SMTP_PASSWORD + "\n")
        os.chmod(password, 0o600)
        config = self.state / "notify.json"
        config.write_text(json.dumps({
            "host": smtp.host, "port": smtp.port, "mode": "plain", "sender": "zeropw@example.com",
            "recipients": ["admin@example.com"], "username": "smtpuser", "password_file": str(password),
        }))
        os.chmod(config, 0o600)

    def test_live_serve_retries_pending_then_widening_sends_new_scope(self):
        self.seed()
        smtp = FakeSmtp().start()
        self.addCleanup(smtp.stop)
        self.notify_config(smtp)
        smtp.stop()
        self.start_serve()
        declared = self.admin("incident", "declare", "--scope", "principal", "--principal", "agent-1")
        shown = self.admin("incident", "show", "--id", declared["id"])
        self.assertEqual(shown["notification"]["status"], "pending")
        smtp.start()

        def delivered():
            latest = self.admin("incident", "show", "--id", declared["id"])
            return latest if latest["notification"]["status"] == "sent" else None

        self.assertIsNotNone(self.until(delivered, timeout=20))
        self.assertEqual(len(smtp.messages), 1)
        self.assertIn(("smtpuser", SMTP_PASSWORD), smtp.auth_attempts)
        _, first_body = parse_message(smtp.messages[0]["data"])
        self.assertNotIn("rt-shared", first_body)
        widened = self.admin("incident", "declare", "--scope", "runtime", "--runtime", "rt-shared")
        self.assertEqual(widened["id"], declared["id"])
        self.assertTrue(widened["widened"])
        self.assertEqual(len(smtp.messages), 2)
        _, second_body = parse_message(smtp.messages[1]["data"])
        self.assertIn("rt-shared", second_body)
        self.assertIn("실행 환경", second_body)
        self.assertNotIn(SYNTHETIC, second_body)
        self.assertNotIn(SMTP_PASSWORD, second_body)
        code, _ = self.agent("list-connections", expect=None)
        self.assertNotEqual(code, 0)
        self.assertEqual(self.stop_serve()[0], 0)
        self.assert_no_secret_anywhere(None)

    def test_external_manual_incident_cancels_live_native_execution(self):
        self.seed()
        self.start_serve()
        _, run = self.agent("exec", "--connection", "gh", "--", "30")
        _, before = self.agent("status", "--run", run["run_id"])
        self.assertEqual(before["state"], "running")
        declared = self.admin("incident", "declare", "--scope", "principal", "--principal", "agent-1")

        def cancelled():
            records = self.admin("audit", "tail", "--limit", "500")["records"]
            return next((r for r in records if r["event"] == "run_finish"
                         and r.get("run_id") == run["run_id"] and r.get("result") == "cancelled"), None)

        self.assertIsNotNone(self.until(cancelled), "serve did not cancel the running child after a separate-process incident")
        shown = self.admin("incident", "show", "--id", declared["id"])
        self.assertEqual(shown["status"], "open")
        self.assertIn("agent-1", shown["principals"])
        code, refused = self.agent("list-connections", expect=None)
        self.assertNotEqual(code, 0)
        self.assertEqual(refused["reason"], "principal_disabled")
        self.assertEqual(self.stop_serve()[0], 0)
        self.assert_no_secret_anywhere(None)

    def test_closed_pending_incident_is_not_retried_by_live_serve(self):
        self.seed()
        smtp = FakeSmtp().start()
        self.addCleanup(smtp.stop)
        self.notify_config(smtp)
        smtp.stop()
        declared = self.admin("incident", "declare", "--scope", "principal", "--principal", "agent-1")
        shown = self.admin("incident", "show", "--id", declared["id"])
        self.assertEqual(shown["notification"]["status"], "pending")
        self.admin("incident", "close", "--id", declared["id"])
        smtp.start()
        self.start_serve()
        # Explicitly observe several 250ms polls after the original retry due time.
        deadline = max(time.time() + 1.25, shown["notification"]["next_attempt_at"] + 1)
        while time.time() < deadline:
            time.sleep(0.1)
        self.assertEqual(smtp.messages, [])
        self.assertEqual(smtp.auth_attempts, [])
        code, _ = self.agent("list-connections", expect=None)
        self.assertNotEqual(code, 0)
        self.assertEqual(self.stop_serve()[0], 0)
        self.assert_no_secret_anywhere(None)
