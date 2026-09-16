"""Compromise-response replacement-guidance email (stage 4): docs/compromise-response.md §6.

``NotifyTestCase.build_incident`` builds one incident (through ``open_incident``, exactly the
production path) carrying three secrets -- an HTTP bearer ``api_key``, a Basic-auth ``password``,
and an ``ssh_private_key`` -- so rendering tests exercise every kind-specific §6.2 block at once.
"""

from __future__ import annotations

import email
import json
import os
import tempfile
import threading
import time
import unittest
from email.header import decode_header
from pathlib import Path
from typing import Any
from unittest.mock import patch

from zeropw import admin_cli
from zeropw import incident as I
from zeropw import notify as N
from zeropw import policy as P
from zeropw import runs as R
from zeropw import sshwire
from zeropw.context import Config, Context
from zeropw.errors import InvalidInput

try:  # tests/ is imported both as a package and by running this file's directory directly
    from tests.fake_smtp import FakeSmtp
    from tests.test_admin_cli import AdminCliTestCase
    from tests.test_incident import ADMIN, RECOVERY, FakeClock, http_connection
except ImportError:  # pragma: no cover - discovery from another working directory
    from fake_smtp import FakeSmtp  # type: ignore[no-redef]
    from test_admin_cli import AdminCliTestCase  # type: ignore[no-redef]
    from test_incident import ADMIN, RECOVERY, FakeClock, http_connection  # type: ignore[no-redef]

SMTP_PASSWORD = "smtp-secret-password-0123456789"


def parse_message(raw: bytes) -> tuple[str, str]:
    """(subject, body) as a human would read them, regardless of which Content-Transfer-Encoding
    smtplib chose for the wire (base64 when the fake server doesn't advertise 8BITMIME, 8bit
    otherwise) -- so tests assert on meaning, not on one particular wire encoding."""
    msg = email.message_from_bytes(raw)
    decoded_parts = decode_header(msg.get("Subject", ""))
    subject = "".join(part.decode(enc or "ascii", "replace") if isinstance(part, bytes) else part
                      for part, enc in decoded_parts)
    payload = msg.get_payload(decode=True) or b""
    charset = msg.get_content_charset() or "utf-8"
    return subject, payload.decode(charset, "replace")


def write_notify_config(ctx: Any, fake: FakeSmtp, root: Path, *, mode: str = "plain",
                        overrides: dict[str, Any] | None = None) -> Path:
    pw_path = root / "smtp.pass"
    pw_path.write_text(SMTP_PASSWORD + "\n")
    os.chmod(pw_path, 0o600)
    config: dict[str, Any] = {
        "host": fake.host, "port": fake.port, "mode": mode, "sender": "zeropw@example.com",
        "recipients": ["admin@example.com"], "username": "smtpuser", "password_file": str(pw_path),
    }
    if overrides:
        config.update(overrides)
    path = ctx.state.path / N.NOTIFY_FILE
    path.write_text(json.dumps(config))
    os.chmod(path, 0o600)
    return path


class NotifyTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.clock = FakeClock()
        self.ctx = Context.initialize(self.root / "state", ADMIN, RECOVERY, Config(), self.clock)
        self.ctx.projects.create("demo")

    def build_incident(self, *, scope: str = "principal", incident_runtime: str | None = None,
                       principal_runtime: str = "default") -> I.Incident:
        self.ctx.vault.put_secret("gh-token", "api_key", b"synthetic-gh-secret-0123456789", "demo", "dev")
        self.ctx.policy.create_connection(http_connection("gh", secret_id="gh-token", service="fake-github"))

        self.ctx.vault.put_secret("svc-pw", "password", b"synthetic-pw-secret-0123456789", "demo", "dev")
        self.ctx.policy.create_connection(http_connection(
            "svc", secret_id="svc-pw", service="fake-service-basic",
            http_auth=P.HttpAuth("basic", basic_username="svcuser")))

        key = sshwire.generate_ed25519_private_key("demo")
        host_key = sshwire.generate_ed25519_private_key("host")
        self.ctx.vault.put_secret("box-key", "ssh_private_key", key.to_openssh_private_key().encode(),
                                  "demo", "dev")
        self.ctx.policy.create_connection(P.Connection(
            id="box", project="demo", environment="dev", service="fake-ssh-box", kind="ssh", secret_id="box-key",
            secret_version=None, description="", http_target=None, http_auth=None, http_scope=None,
            ssh_target=P.SshTarget("127.0.0.1", 2222, "deploy", (host_key.public.to_authorized_key("host"),)),
            cli=None, policy_version=0, status="active", created_at="", updated_at=""))

        # A fourth connection the principal is granted but never uses: "recommended" tier.
        self.ctx.vault.put_secret("jira-token", "api_key", b"synthetic-jira-secret-0123456789", "demo", "dev")
        self.ctx.policy.create_connection(http_connection("jira", secret_id="jira-token", service="fake-jira"))

        self.ctx.policy.create_principal("agent-1", principal_runtime)
        self.ctx.policy.create_grant("agent-1", "gh", 3600, None)
        self.ctx.policy.create_grant("agent-1", "svc", 3600, None)
        self.ctx.policy.create_grant("agent-1", "box", 3600, None)
        self.ctx.policy.create_grant("agent-1", "jira", 3600, None)  # never used

        self.clock.advance(1)
        self.ctx.audit.record("http_relay", caller="agent-1", connection="gh", result="ok", action="GET")
        self.ctx.audit.record("http_relay", caller="agent-1", connection="svc", result="ok", action="GET")
        self.ctx.audit.record("ssh_sign", caller="agent-1", connection="box", result="ok", action="ssh-sign")

        principals = ["agent-1"] if scope == "principal" else None
        return I.open_incident(self.ctx, scope=scope, principals=principals, runtime=incident_runtime,
                               trigger="manual")

    def vault_patterns(self) -> list[bytes]:
        patterns: list[bytes] = []
        for value in self.ctx.vault.values_for_trusted_scan():
            patterns.extend(R.credential_patterns(value))
        return patterns


# ============================================================== rendering
class RenderingTests(NotifyTestCase):
    def test_rendering_is_pure_and_deterministic(self) -> None:
        incident = self.build_incident()
        rendered_a = N.render_incident_email(incident, now="2026-09-16T00:00:00Z")
        rendered_b = N.render_incident_email(incident, now="2026-09-16T00:00:00Z")
        self.assertEqual(rendered_a, rendered_b)

    def test_subject_matches_6_2_exactly(self) -> None:
        incident = self.build_incident()
        subject, _body = N.render_incident_email(incident, now="2026-09-16T00:00:00Z")
        self.assertEqual(subject, f"[ZeroPW] 침입 감지 — 서비스 정지, 자격증명 교체 필요 (사건 {incident.id})")

    def test_body_contains_every_6_2_section_in_order(self) -> None:
        incident = self.build_incident()
        _subject, body = N.render_incident_email(incident, now="2026-09-16T00:00:00Z")
        sections = ["1. 무슨 일이 있었나", "2. ZeroPW가 이미 한 것", "3. 지금 해야 할 것 — 필수 교체",
                   "4. 권장 교체", "5. 실행 환경", "6. 복구 명령"]
        positions = [body.index(s) for s in sections]
        self.assertEqual(positions, sorted(positions))

    def test_kind_specific_blocks_and_every_mandatory_secret_present(self) -> None:
        incident = self.build_incident()
        _subject, body = N.render_incident_email(incident, now="2026-09-16T00:00:00Z")
        for secret_id in ("gh-token", "svc-pw", "box-key"):
            self.assertIn(secret_id, body)
        self.assertIn("rotation start", body)
        self.assertIn("rotation activate", body)
        self.assertIn("rotation finish", body)
        self.assertIn("authorized_keys", body)
        self.assertIn("ss -tnp", body)
        self.assertIn("서비스에서 비밀번호를 변경", body)      # password-kind step
        self.assertIn("활성 세션을 종료", body)               # password-kind step
        self.assertTrue(incident.assessment["secrets"])       # sanity: assessment actually has secrets

    def test_recommended_tier_secret_is_listed_separately_from_mandatory(self) -> None:
        incident = self.build_incident()
        _subject, body = N.render_incident_email(incident, now="2026-09-16T00:00:00Z")
        mandatory_block, recommended_block = body.split("4. 권장 교체", 1)
        self.assertIn("jira-token", recommended_block)
        self.assertNotIn("jira-token", mandatory_block)

    def test_recovery_commands_present_in_order(self) -> None:
        incident = self.build_incident()
        _subject, body = N.render_incident_email(incident, now="2026-09-16T00:00:00Z")
        show = body.index(f"incident show --id {incident.id}")
        close = body.index(f"incident close --id {incident.id}")
        principal_create = body.index("principal create --runtime")
        grant_create = body.index("grant create")
        resume = body.index("resume")
        self.assertEqual([show, close, principal_create, grant_create, resume],
                         sorted([show, close, principal_create, grant_create, resume]))

    def test_no_urls_anywhere(self) -> None:
        incident = self.build_incident()
        subject, body = N.render_incident_email(incident, now="2026-09-16T00:00:00Z")
        for text in (subject, body):
            self.assertNotIn("http://", text)
            self.assertNotIn("https://", text)

    def test_principal_scope_wording_warns_before_creating_a_new_principal(self) -> None:
        incident = self.build_incident(scope="principal")
        _subject, body = N.render_incident_email(incident, now="2026-09-16T00:00:00Z")
        self.assertIn(f"incident escalate --id {incident.id} --scope runtime|all", body)

    def test_runtime_scope_wording_says_rebuild_the_host(self) -> None:
        incident = self.build_incident(scope="runtime", incident_runtime="default")
        _subject, body = N.render_incident_email(incident, now="2026-09-16T00:00:00Z")
        self.assertIn("폐기하고 새로 구축", body)
        self.assertNotIn("incident escalate", body)

    def test_all_scope_adds_recover_and_passphrase_guidance(self) -> None:
        incident = self.build_incident(scope="all")
        _subject, body = N.render_incident_email(incident, now="2026-09-16T00:00:00Z")
        self.assertIn("recover", body)
        self.assertIn("패스프레이즈", body)

    def test_render_never_contains_a_vault_value_handle_or_path(self) -> None:
        incident = self.build_incident()
        subject, body = N.render_incident_email(incident, now="2026-09-16T00:00:00Z")
        blob = (subject + "\n" + body).encode("utf-8")
        self.assertFalse(R.contains_sensitive(blob, self.vault_patterns()))
        self.assertNotIn(str(self.ctx.state.path), subject + body)
        self.assertNotIn("zpw1.", subject + body)   # handle prefix
        self.assertNotIn("zpwc_", subject + body)   # caller-token prefix

    def test_every_vault_secret_kind_has_a_dedicated_step_block(self) -> None:
        """§6.2 item 3 requires a kind-specific block for every kind the vault actually accepts
        (``env`` in the design doc's prose is ``env_var`` in ``zeropw.vault.SECRET_KINDS``): this
        pins ``_KIND_STEPS``'s keys to that list so a future kind is a deliberate choice -- either
        a dedicated block or the generic fallback -- not a silent gap."""
        from zeropw.vault import SECRET_KINDS
        self.assertEqual(set(N._KIND_STEPS.keys()), set(SECRET_KINDS))


# ================================================================== config
class ConfigTests(NotifyTestCase):
    def test_missing_config_file_means_not_configured(self) -> None:
        self.assertIsNone(N.NotifyConfig.load(self.ctx))

    def test_deliver_without_config_marks_not_configured_and_does_not_send(self) -> None:
        # No notify.json exists: open_incident's own step 8 already calls deliver() once, so the
        # incident returned here already reflects the outcome -- calling deliver() again would
        # double-count the audit record this test checks for.
        incident = self.build_incident()
        self.assertEqual(incident.notification, {"status": "not_configured", "attempts": 0})
        events = [r for r in self.ctx.audit.tail(50) if r["event"] == "incident_notify"]
        self.assertEqual(len(events), 1)
        self.assertEqual((events[0]["result"], events[0]["reason"]), ("ok", "not_configured"))

    def test_config_file_with_wrong_mode_is_refused(self) -> None:
        path = self.ctx.state.path / N.NOTIFY_FILE
        path.write_text(json.dumps({"host": "127.0.0.1", "port": 25, "mode": "plain",
                                   "sender": "a@example.com", "recipients": ["b@example.com"]}))
        os.chmod(path, 0o644)
        with self.assertRaises(InvalidInput) as caught:
            N.NotifyConfig.load(self.ctx)
        self.assertEqual(caught.exception.reason, "notify_config_insecure")

    def test_password_file_with_wrong_mode_is_refused(self) -> None:
        pw_path = self.root / "smtp.pass"
        pw_path.write_text("x\n")
        os.chmod(pw_path, 0o644)
        path = self.ctx.state.path / N.NOTIFY_FILE
        path.write_text(json.dumps({"host": "127.0.0.1", "port": 25, "mode": "plain",
                                   "sender": "a@example.com", "recipients": ["b@example.com"],
                                   "password_file": str(pw_path)}))
        os.chmod(path, 0o600)
        with self.assertRaises(InvalidInput) as caught:
            N.NotifyConfig.load(self.ctx)
        self.assertEqual(caught.exception.reason, "notify_config_insecure")

    def test_plain_mode_on_a_non_loopback_host_is_refused(self) -> None:
        path = self.ctx.state.path / N.NOTIFY_FILE
        path.write_text(json.dumps({"host": "mail.example.com", "port": 25, "mode": "plain",
                                   "sender": "a@example.com", "recipients": ["b@example.com"]}))
        os.chmod(path, 0o600)
        with self.assertRaises(InvalidInput) as caught:
            N.NotifyConfig.load(self.ctx)
        self.assertEqual(caught.exception.reason, "notify_plain_requires_loopback")

    def test_starttls_and_smtps_are_accepted_on_a_non_loopback_host(self) -> None:
        for mode in ("starttls", "smtps"):
            path = self.ctx.state.path / N.NOTIFY_FILE
            path.write_text(json.dumps({"host": "mail.example.com", "port": 587 if mode == "starttls" else 465,
                                       "mode": mode, "sender": "a@example.com", "recipients": ["b@example.com"]}))
            os.chmod(path, 0o600)
            config = N.NotifyConfig.load(self.ctx)
            self.assertEqual(config.mode, mode)

    def test_deliver_with_an_insecure_config_goes_pending_not_a_crash(self) -> None:
        path = self.ctx.state.path / N.NOTIFY_FILE
        path.write_text(json.dumps({"host": "127.0.0.1", "port": 25, "mode": "plain",
                                   "sender": "a@example.com", "recipients": ["b@example.com"]}))
        os.chmod(path, 0o644)
        incident = self.build_incident()  # open_incident's own step 8 already attempted delivery
        self.assertEqual(incident.notification["status"], "pending")
        self.assertEqual(incident.notification["last_error"], "notify_config_insecure")


# ================================================================ delivery
class DeliveryTests(NotifyTestCase):
    def test_successful_send_delivers_subject_body_and_auth_from_the_password_file(self) -> None:
        fake = FakeSmtp().start()
        self.addCleanup(fake.stop)
        # Built before notify.json exists, so open_incident's own automatic step-8 delivery is a
        # not_configured no-op; the explicit deliver() call below is then the only real send.
        incident = self.build_incident()
        write_notify_config(self.ctx, fake, self.root)
        result = N.deliver(self.ctx, incident)

        self.assertEqual(result.notification["status"], "sent")
        self.assertIn("sent_at", result.notification)
        self.assertEqual(len(fake.messages), 1)
        subject, body = parse_message(fake.messages[0]["data"])
        self.assertIn(incident.id, subject)
        self.assertIn(incident.id, body)
        self.assertEqual(fake.messages[0]["sender"], "<zeropw@example.com>")
        self.assertEqual(fake.messages[0]["recipients"], ["<admin@example.com>"])
        self.assertEqual(fake.auth_attempts, [("smtpuser", SMTP_PASSWORD)])

        events = [r for r in self.ctx.audit.tail(50) if r["event"] == "incident_notify"]
        self.assertTrue(any(e["result"] == "ok" and e["reason"] == "sent" for e in events))
        for e in events:
            self.assertNotIn("admin@example.com", json.dumps(e))
            self.assertNotIn("smtpuser", json.dumps(e))

    def test_password_never_appears_anywhere_captured(self) -> None:
        fake = FakeSmtp().start()
        self.addCleanup(fake.stop)
        incident = self.build_incident()
        write_notify_config(self.ctx, fake, self.root)
        N.deliver(self.ctx, incident)

        incident_path = self.ctx.state.path / "incidents" / f"{incident.id}.json"
        self.assertNotIn(SMTP_PASSWORD.encode("utf-8"), incident_path.read_bytes())
        audit_path = self.ctx.state.path / "audit" / "audit.jsonl"
        self.assertNotIn(SMTP_PASSWORD.encode("utf-8"), audit_path.read_bytes())
        alerts_path = self.ctx.state.path / "audit" / "alerts.jsonl"
        if alerts_path.exists():
            self.assertNotIn(SMTP_PASSWORD.encode("utf-8"), alerts_path.read_bytes())

    def test_server_down_goes_pending_with_backoff_then_retry_succeeds(self) -> None:
        fake = FakeSmtp().start()
        self.addCleanup(fake.stop)
        port = fake.port
        fake.stop()
        incident = self.build_incident()   # built while notify.json doesn't exist yet: a no-op
        write_notify_config(self.ctx, fake, self.root)

        result = N.deliver(self.ctx, incident)
        self.assertEqual(result.notification["status"], "pending")
        self.assertEqual(result.notification["attempts"], 1)
        self.assertIn("last_error", result.notification)
        self.assertGreater(result.notification["next_attempt_at"], self.ctx.clock())

        fake.start()
        self.assertEqual(fake.port, port)
        attempted = N.retry_pending(self.ctx, self.ctx.clock() + 400)
        self.assertEqual(attempted, 1)
        refreshed = I.get_incident(self.ctx, incident.id)
        self.assertEqual(refreshed.notification["status"], "sent")
        self.assertEqual(len(fake.messages), 1)

    def test_retry_pending_respects_next_attempt_at(self) -> None:
        fake = FakeSmtp().start()
        self.addCleanup(fake.stop)
        fake.stop()
        incident = self.build_incident()   # built while notify.json doesn't exist yet: a no-op
        write_notify_config(self.ctx, fake, self.root)
        N.deliver(self.ctx, incident)   # pending; backoff ~1s from ctx.clock()

        fake.start()
        not_yet = N.retry_pending(self.ctx, self.ctx.clock())
        self.assertEqual(not_yet, 0)
        self.assertEqual(len(fake.messages), 0)

        due = N.retry_pending(self.ctx, self.ctx.clock() + 5)
        self.assertEqual(due, 1)
        self.assertEqual(len(fake.messages), 1)

    def test_retry_pending_only_reads_the_single_open_incident_pointer(self) -> None:
        """M1: at most one incident can ever be open (``Policy.open_incident_id`` is a single
        pointer); ``retry_pending`` must use that pointer directly rather than scanning every
        incident file on every 0.25s poll.  A closed incident with a stale ``pending``
        notification (declared, then closed before the email ever sent) must never be retried."""
        fake = FakeSmtp().start()
        self.addCleanup(fake.stop)
        fake.stop()
        incident = self.build_incident()   # built while notify.json doesn't exist yet: a no-op
        write_notify_config(self.ctx, fake, self.root)
        N.deliver(self.ctx, incident)   # pending
        self.assertEqual(self.ctx.policy.open_incident_id(), incident.id)  # sanity: still open

        I.close_incident(self.ctx, incident.id)
        self.assertIsNone(self.ctx.policy.open_incident_id())

        fake.start()
        attempted = N.retry_pending(self.ctx, self.ctx.clock() + 400)
        self.assertEqual(attempted, 0)
        self.assertEqual(len(fake.messages), 0)

    def test_rendered_value_leak_is_blocked_and_marked_failed(self) -> None:
        fake = FakeSmtp().start()
        self.addCleanup(fake.stop)
        incident = self.build_incident()   # built while notify.json doesn't exist yet: a no-op
        write_notify_config(self.ctx, fake, self.root)
        with patch.object(N, "render_incident_email", return_value=("subject", "leak: synthetic-gh-secret-0123456789")):
            result = N.deliver(self.ctx, incident)
        self.assertEqual(result.notification["status"], "failed")
        self.assertEqual(result.notification["reason"], "rendered_value_detected")
        self.assertEqual(len(fake.messages), 0, "a render that scans as sensitive must never be sent")

    def test_widening_resends_the_email_mentioning_the_wider_scope(self) -> None:
        fake = FakeSmtp().start()
        self.addCleanup(fake.stop)
        write_notify_config(self.ctx, fake, self.root)

        incident = self.build_incident(principal_runtime="rt-shared")
        self.assertEqual(len(fake.messages), 1)
        _first_subject, first_body = parse_message(fake.messages[0]["data"])
        self.assertNotIn("rt-shared", first_body)

        self.ctx.policy.create_principal("agent-2", "rt-shared")
        widened = I.widen_incident(self.ctx, incident.id, scope="runtime", runtime="rt-shared")
        self.assertEqual(widened.scope, "runtime")
        self.assertEqual(len(fake.messages), 2, "widening must send a second message")
        _second_subject, second_body = parse_message(fake.messages[1]["data"])
        self.assertIn("rt-shared", second_body)
        self.assertIn("실행 환경", second_body)


# ======================================================== serve integration
class ServeRetryTests(AdminCliTestCase):
    """``serve``'s poll loop must retry a pending notification (docs/compromise-response.md §6.1)."""

    def test_serve_poll_retries_a_pending_notification_once_the_smtp_server_is_up(self) -> None:
        self.seed_project()
        self.put_secret()
        self.create_http("gh")
        self.ok("principal", "create", "--id", "agent-1")
        self.ok("grant", "create", "--principal", "agent-1", "--connection", "gh")

        fake = FakeSmtp().start()
        self.addCleanup(fake.stop)
        port = fake.port
        fake.stop()  # down when the incident is declared: the first attempt must go pending

        pw_path = self.root / "smtp.pass"
        pw_path.write_text(SMTP_PASSWORD + "\n")
        os.chmod(pw_path, 0o600)
        notify_path = self.state / N.NOTIFY_FILE
        notify_path.write_text(json.dumps({
            "host": "127.0.0.1", "port": port, "mode": "plain", "sender": "zeropw@example.com",
            "recipients": ["admin@example.com"], "username": "smtpuser", "password_file": str(pw_path),
        }))
        os.chmod(notify_path, 0o600)

        startup: list[dict] = []
        original_emit = admin_cli._emit

        def emit(payload: Any, *, compact: bool = False) -> None:
            if compact:
                startup.append(payload)
            else:
                original_emit(payload)

        stop = threading.Event()
        emit_patch = patch.object(admin_cli, "_emit", emit)
        emit_patch.start()
        self.addCleanup(emit_patch.stop)
        serve = threading.Thread(target=admin_cli.run_serve, args=(self.state, "127.0.0.1:0"),
                                 kwargs={"quiet": True, "stop_event": stop, "install_signals": False}, daemon=True)
        serve.start()
        self.addCleanup(serve.join, 30)
        self.addCleanup(stop.set)
        deadline = time.monotonic() + 30
        while not startup and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(startup, "serve did not start")

        declared = self.ok("incident", "declare", "--scope", "principal", "--principal", "agent-1")
        shown = self.ok("incident", "show", "--id", declared["id"])
        self.assertEqual(shown["notification"]["status"], "pending")

        fake.start()
        self.assertEqual(fake.port, port)

        status = None
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            shown = self.ok("incident", "show", "--id", declared["id"])
            status = shown["notification"]["status"]
            if status == "sent":
                break
            time.sleep(0.2)
        self.assertEqual(status, "sent")
        self.assertEqual(len(fake.messages), 1)

        stop.set()
        serve.join(30)
        self.assertFalse(serve.is_alive())


# ============================================================== notify-test
class NotifyTestCliTests(AdminCliTestCase):
    def test_notify_test_sends_through_the_configured_path(self) -> None:
        self.seed_project()
        fake = FakeSmtp().start()
        self.addCleanup(fake.stop)
        pw_path = self.root / "smtp.pass"
        pw_path.write_text(SMTP_PASSWORD + "\n")
        os.chmod(pw_path, 0o600)
        notify_path = self.state / N.NOTIFY_FILE
        notify_path.write_text(json.dumps({
            "host": fake.host, "port": fake.port, "mode": "plain", "sender": "zeropw@example.com",
            "recipients": ["admin@example.com"], "username": "smtpuser", "password_file": str(pw_path),
        }))
        os.chmod(notify_path, 0o600)

        result = self.ok("incident", "notify-test")
        self.assertEqual(result["status"], "sent")
        self.assertEqual(len(fake.messages), 1)

        events = [r for r in self.ctx().audit.tail(50) if r["event"] == "incident_notify"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].get("kind"), "notify_test")
        self.assertNotIn("incident_id", events[0])   # distinguishable without inventing a fake incident id

    def test_notify_test_without_config_reports_not_configured(self) -> None:
        self.seed_project()
        result = self.ok("incident", "notify-test")
        self.assertEqual(result["status"], "not_configured")


if __name__ == "__main__":
    unittest.main()
