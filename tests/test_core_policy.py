"""Policy engine: default deny, grant lifecycle, scope, expiry, revocation, stop, approvals."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from zeropw import policy as P
from zeropw.errors import AuthFailed, InvalidInput, NotFound, PolicyDenied
from zeropw.store import StateDir


class FakeClock:
    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


def http_connection(cid: str = "gh", **overrides) -> P.Connection:
    base = dict(
        id=cid, project="demo", environment="dev", service="fake-github", kind="http",
        secret_id="gh-token", secret_version=None, description="demo connection",
        http_target=P.HttpTarget("http", "127.0.0.1", 8080),
        http_auth=P.HttpAuth("bearer"),
        http_scope=P.HttpScope(("GET", "POST"), ("/repos", "/me"), ("DELETE",)),
        ssh_target=None, cli=None, policy_version=0, status="active", created_at="", updated_at="",
    )
    base.update(overrides)
    return P.Connection(**base)


def ssh_connection(cid: str = "box") -> P.Connection:
    return P.Connection(
        id=cid, project="demo", environment="dev", service="ssh-box", kind="ssh",
        secret_id="box-key", secret_version=None, description="",
        http_target=None, http_auth=None, http_scope=None,
        ssh_target=P.SshTarget("127.0.0.1", 22, "deploy", ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA host",)),
        cli=None, policy_version=0, status="active", created_at="", updated_at="",
    )


class PolicyTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state = StateDir(Path(self.tmp.name) / "state")
        self.state.create()
        self.clock = FakeClock()
        self.policy = P.Policy(self.state, self.clock)
        self.token = self.policy.create_principal("agent-1")
        self.policy.create_connection(http_connection())

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def grant(self, ttl: int | None = 3600, max_uses: int | None = None, cid: str = "gh") -> P.Grant:
        return self.policy.create_grant("agent-1", cid, ttl, max_uses)

    # ---------------------------------------------------------- principals
    def test_principal_token_authenticates_and_is_hashed(self) -> None:
        principal = self.policy.authenticate(self.token)
        self.assertEqual(principal.id, "agent-1")
        self.assertNotIn(self.token, (self.state.path / "policy" / "principals.json").read_text())
        with self.assertRaises(AuthFailed):
            self.policy.authenticate(self.token + "x")
        with self.assertRaises(AuthFailed):
            self.policy.authenticate("zpwc_" + "a" * 43)
        with self.assertRaises(AuthFailed):
            self.policy.authenticate("")

    def test_disabled_principal_cannot_authenticate_or_use(self) -> None:
        self.grant()
        self.policy.disable_principal("agent-1")
        with self.assertRaises(AuthFailed):
            self.policy.authenticate(self.token)
        decision = self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "principal_disabled")

    # ------------------------------------------------------- default deny
    def test_no_grant_is_denied(self) -> None:
        decision = self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "no_grant")
        with self.assertRaises(PolicyDenied):
            decision.require()

    def test_unknown_caller_and_connection_denied(self) -> None:
        self.assertEqual(self.policy.evaluate("ghost", "gh", P.Action("http", "GET", "/repos")).reason, "principal_unknown")
        self.assertEqual(self.policy.evaluate("agent-1", "nope", P.Action("http", "GET", "/repos")).reason, "connection_unknown")

    def test_one_connection_many_operations_without_registration(self) -> None:
        self.grant()
        for method, path in (("GET", "/repos"), ("POST", "/repos/demo/issues"), ("GET", "/me"), ("GET", "/repos/x/y/z")):
            decision = self.policy.evaluate("agent-1", "gh", P.Action("http", method, path))
            self.assertTrue(decision.allowed, (method, path, decision.reason))

    def test_scope_method_and_path_enforced(self) -> None:
        self.grant()
        self.assertEqual(self.policy.evaluate("agent-1", "gh", P.Action("http", "PUT", "/repos")).reason, "method_not_allowed")
        self.assertEqual(self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/admin")).reason, "path_not_allowed")
        self.assertEqual(self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/reposx")).reason, "path_not_allowed")
        self.assertEqual(self.policy.evaluate("agent-1", "gh", P.Action("http", "TRACE", "/repos")).reason, "method_not_allowed")
        self.assertEqual(self.policy.evaluate("agent-1", "gh", P.Action("ssh", username="deploy")).reason, "action_kind_mismatch")

    def test_grant_is_bound_to_caller_and_connection(self) -> None:
        other_token = self.policy.create_principal("agent-2")
        self.assertTrue(other_token.startswith("zpwc_"))
        self.policy.create_connection(http_connection("gh2"))
        grant = self.grant()
        self.assertEqual(self.policy.evaluate("agent-2", "gh", P.Action("http", "GET", "/repos")).reason, "no_grant")
        self.assertEqual(self.policy.evaluate("agent-1", "gh2", P.Action("http", "GET", "/repos")).reason, "no_grant")
        self.assertEqual(self.policy.evaluate("agent-1", "gh2", P.Action("http", "GET", "/repos"), grant.id).reason, "grant_mismatch")
        self.assertEqual(self.policy.evaluate("agent-2", "gh", P.Action("http", "GET", "/repos"), grant.id).reason, "grant_mismatch")

    # -------------------------------------------------- expiry / usage / revoke
    def test_expiry_is_enforced_at_evaluation_time(self) -> None:
        self.grant(ttl=100)
        self.assertTrue(self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).allowed)
        self.clock.now += 100
        self.assertEqual(self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).reason, "grant_expired")

    def test_usage_cap_consumed_atomically(self) -> None:
        grant = self.grant(max_uses=2)
        self.policy.consume(grant.id)
        self.policy.consume(grant.id)
        with self.assertRaises(PolicyDenied) as ctx:
            self.policy.consume(grant.id)
        self.assertEqual(ctx.exception.reason, "grant_exhausted")
        self.assertEqual(self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).reason, "grant_exhausted")

    def test_revocation_applies_immediately_and_notifies(self) -> None:
        seen: list[tuple[str, str | None]] = []
        self.policy.on_revoke(lambda kind, gid: seen.append((kind, gid)))
        grant = self.grant()
        self.policy.revoke_grant(grant.id)
        self.assertEqual(self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).reason, "grant_revoked")
        with self.assertRaises(PolicyDenied):
            self.policy.consume(grant.id)
        self.assertIn(("grant", grant.id), seen)
        with self.assertRaises(NotFound):
            self.policy.revoke_grant("g-missing")

    def test_global_stop_blocks_everything_until_resume(self) -> None:
        grant = self.grant()
        self.policy.stop_all()
        self.assertTrue(self.policy.is_stopped())
        self.assertEqual(self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).reason, "global_stop")
        self.assertEqual(self.policy.usable_connections("agent-1"), [])
        self.policy.resume()
        self.assertTrue(self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"), grant.id).allowed)

    def test_restore_pending_blocks_until_acknowledged(self) -> None:
        self.grant()
        self.policy.set_restore_pending(True)
        self.assertEqual(self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).reason, "restore_pending")
        self.policy.set_restore_pending(False)
        self.assertTrue(self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).allowed)

    # ------------------------------------------------ policy version changes
    def test_widening_change_makes_grants_stale_no_inheritance(self) -> None:
        grant = self.grant()
        conn, widened = self.policy.update_connection("gh", http_scope=P.HttpScope(None, ("/repos", "/me"), ("DELETE",)))
        self.assertTrue(widened)
        self.assertEqual(conn.policy_version, 2)
        self.assertEqual(self.policy.evaluate("agent-1", "gh", P.Action("http", "PUT", "/repos")).reason, "grant_stale")
        self.assertEqual(self.policy.get_grant(grant.id).status, "stale")
        fresh = self.policy.regrant(grant.id)
        self.assertEqual(fresh.policy_version, 2)
        self.assertTrue(self.policy.evaluate("agent-1", "gh", P.Action("http", "PUT", "/repos")).allowed)
        self.assertEqual(self.policy.get_grant(grant.id).status, "revoked")

    def test_target_change_is_widening(self) -> None:
        self.grant()
        _, widened = self.policy.update_connection("gh", http_target=P.HttpTarget("http", "127.0.0.2", 8080))
        self.assertTrue(widened)
        self.assertEqual(self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).reason, "grant_stale")

    def test_narrowing_or_rotation_reevaluates_in_place(self) -> None:
        grant = self.grant()
        conn, widened = self.policy.update_connection("gh", http_scope=P.HttpScope(("GET",), ("/repos",), ("DELETE",)))
        self.assertFalse(widened)
        self.assertEqual(conn.policy_version, 2)
        self.assertEqual(self.policy.get_grant(grant.id).policy_version, 2)
        self.assertEqual(self.policy.evaluate("agent-1", "gh", P.Action("http", "POST", "/repos")).reason, "method_not_allowed")
        self.assertTrue(self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).allowed)
        conn = self.policy.switch_credential("gh", 2)
        self.assertEqual(conn.secret_version, 2)
        self.assertTrue(self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).allowed)

    def test_disabled_connection_denied(self) -> None:
        self.grant()
        self.policy.disable_connection("gh")
        self.assertEqual(self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).reason, "connection_disabled")
        with self.assertRaises(InvalidInput):
            self.policy.create_grant("agent-1", "gh", 10, None)

    # ------------------------------------------------------------- approvals
    def test_approval_bound_to_digest_caller_connection_and_one_shot(self) -> None:
        digest = P.approval_digest("agent-1", "gh", "DELETE", "/repos/demo", b"")
        self.assertNotEqual(digest, P.approval_digest("agent-1", "gh", "DELETE", "/repos/demo", b"{}"))
        self.assertNotEqual(digest, P.approval_digest("agent-1", "gh", "DELETE", "/repos/other", b""))
        self.policy.request_approval(digest, "agent-1", "gh", "DELETE", "/repos/demo")
        self.assertFalse(self.policy.consume_approval(digest, "agent-1", "gh"))
        with self.assertRaises(NotFound):
            self.policy.approve("0" * 64)
        self.policy.approve(digest)
        with self.assertRaises(InvalidInput):
            self.policy.approve(digest)
        self.assertFalse(self.policy.consume_approval(digest, "agent-2", "gh"))
        self.assertTrue(self.policy.consume_approval(digest, "agent-1", "gh"))
        self.assertFalse(self.policy.consume_approval(digest, "agent-1", "gh"))

    # ------------------------------------------------------------ validation
    def test_connection_validation_rejects_bad_targets(self) -> None:
        with self.assertRaises(InvalidInput):
            P.HttpTarget("ftp", "example.com", 21)
        with self.assertRaises(InvalidInput):
            P.HttpTarget("https", "http://example.com", 443)
        with self.assertRaises(InvalidInput):
            P.HttpTarget("https", "example.com/path", 443)
        with self.assertRaises(InvalidInput):
            P.HttpTarget("https", "user@example.com", 443)
        with self.assertRaises(InvalidInput):
            P.HttpTarget("https", "example.com", 0)
        with self.assertRaises(InvalidInput):
            P.HttpAuth("query")
        with self.assertRaises(InvalidInput):
            P.HttpAuth("header", header_name="Host")
        with self.assertRaises(InvalidInput):
            P.HttpAuth("header", header_name="X Bad")
        with self.assertRaises(InvalidInput):
            P.HttpAuth("basic", basic_username="a:b")
        with self.assertRaises(InvalidInput):
            P.HttpScope(("GET",), ("repos",))
        with self.assertRaises(InvalidInput):
            P.HttpScope(("GET",), ("/repos/../admin",))
        with self.assertRaises(InvalidInput):
            P.SshTarget("host", 22, "deploy", ("ssh-rsa AAAA",))
        with self.assertRaises(InvalidInput):
            P.SshTarget("host", 22, "Deploy!", ("ssh-ed25519 AAAA",))
        with self.assertRaises(InvalidInput):
            P.CliProfile("prog", "http", extra_env={"SSH_AUTH_SOCK": "/x"})
        with self.assertRaises(InvalidInput):
            http_connection(http_target=None)

    def test_public_view_hides_secret_reference_and_others(self) -> None:
        self.grant()
        self.policy.create_connection(ssh_connection())
        views = [c.public_view() for c, _ in self.policy.usable_connections("agent-1")]
        self.assertEqual([v["id"] for v in views], ["gh"])
        self.assertNotIn("secret_id", views[0])
        self.assertNotIn("ca_file", str(views[0]))
        self.assertEqual(views[0]["target"], {"scheme": "http", "host": "127.0.0.1", "port": 8080})
        ssh_view = ssh_connection().public_view()
        self.assertNotIn("host_keys", ssh_view)
        self.assertEqual(ssh_view["target"]["username"], "deploy")

    def test_ssh_action_requires_matching_username(self) -> None:
        self.policy.create_connection(ssh_connection())
        self.grant(cid="box")
        self.assertTrue(self.policy.evaluate("agent-1", "box", P.Action("ssh", username="deploy")).allowed)
        self.assertEqual(self.policy.evaluate("agent-1", "box", P.Action("ssh", username="root")).reason, "ssh_user_mismatch")

    def test_grant_limits_validated(self) -> None:
        with self.assertRaises(InvalidInput):
            self.grant(ttl=0)
        with self.assertRaises(InvalidInput):
            self.grant(max_uses=0)
        with self.assertRaises(InvalidInput):
            self.grant(ttl=P.MAX_GRANT_TTL + 1)

    def test_revoke_all_marks_everything(self) -> None:
        self.grant()
        self.grant()
        self.assertEqual(self.policy.revoke_all(), 2)
        self.assertEqual(self.policy.usable_connections("agent-1"), [])

    # ------------------------------------------ PL-1: consume is authoritative
    def other_process(self) -> P.Policy:
        """A second Policy on the same state: no in-process listeners, like a separate admin_cli process."""
        return P.Policy(StateDir(self.state.path), self.clock)

    def assert_consume_denied(self, grant_id: str, reason: str, **kwargs) -> None:
        with self.assertRaises(PolicyDenied) as caught:
            self.policy.consume(grant_id, **kwargs)
        self.assertEqual(caught.exception.reason, reason)

    def test_consume_rechecks_control_principal_and_connection_committed_after_evaluate(self) -> None:
        """PL-1: a change committed between evaluate() and consume() by another process is honoured."""
        grant = self.grant()
        changes = (
            ("global_stop", lambda p: p.stop_all(), lambda p: p.resume()),
            ("restore_pending", lambda p: p.set_restore_pending(True), lambda p: p.set_restore_pending(False)),
        )
        for reason, apply, undo in changes:
            self.assertTrue(self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"), grant.id).allowed)
            apply(self.other_process())
            self.assert_consume_denied(grant.id, reason)
            undo(self.other_process())
        self.assertEqual(self.policy.get_grant(grant.id).uses, 0)
        self.assertTrue(self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"), grant.id).allowed)
        self.assertEqual(self.policy.consume(grant.id).uses, 1)

        self.assertTrue(self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"), grant.id).allowed)
        self.other_process().disable_principal("agent-1")
        self.assert_consume_denied(grant.id, "principal_disabled")

        self.policy.create_principal("agent-2")
        self.policy.create_connection(http_connection("gh2"))
        other = self.policy.create_grant("agent-2", "gh2", 3600, None)
        self.assertTrue(self.policy.evaluate("agent-2", "gh2", P.Action("http", "GET", "/me"), other.id).allowed)
        self.other_process().disable_connection("gh2")
        self.assert_consume_denied(other.id, "connection_disabled")
        self.assertEqual(self.policy.get_grant(other.id).uses, 0)

    def test_consume_reapplies_the_evaluated_scope_and_policy_version(self) -> None:
        """PL-1: scope narrowing or any policy-version change after evaluate() refuses the in-flight use."""
        grant = self.grant()
        self.assertTrue(self.policy.evaluate("agent-1", "gh", P.Action("http", "POST", "/repos"), grant.id).allowed)
        self.other_process().update_connection("gh", http_scope=P.HttpScope(("GET",), ("/repos", "/me"), ("DELETE",)))
        self.assert_consume_denied(grant.id, "method_not_allowed")
        # A version change that does not affect this operation still refuses: the caller's connection
        # snapshot (target, credential version) is no longer the current one.
        self.assertTrue(self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"), grant.id).allowed)
        self.other_process().update_connection("gh", description="renamed")
        self.assert_consume_denied(grant.id, "grant_stale")
        # Explicit arguments work without a preceding evaluate in this thread.
        self.assert_consume_denied(grant.id, "method_not_allowed", action=P.Action("http", "PUT", "/repos"))
        self.assert_consume_denied(grant.id, "path_not_allowed", action=P.Action("http", "GET", "/admin"))
        current = self.policy.get_connection("gh").policy_version
        self.assert_consume_denied(grant.id, "grant_stale", policy_version=current - 1)
        self.assert_consume_denied(grant.id, "grant_mismatch", caller="agent-2")
        self.assertEqual(self.policy.get_grant(grant.id).uses, 0)
        self.assertEqual(self.policy.consume(grant.id, action=P.Action("http", "GET", "/me"),
                                             policy_version=current).uses, 1)
        # The remembered evaluation is used once: a later consume falls back to the base checks.
        self.assertTrue(self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"), grant.id).allowed)
        self.assertEqual(self.policy.consume(grant.id).uses, 2)
        self.other_process().update_connection("gh", description="again")
        self.assertEqual(self.policy.consume(grant.id).uses, 3)

    def test_consume_in_another_thread_still_rechecks_control(self) -> None:
        import threading

        grant = self.grant()
        self.assertTrue(self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"), grant.id).allowed)
        self.other_process().stop_all()
        errors: list[str] = []

        def worker() -> None:
            try:
                self.policy.consume(grant.id)
            except PolicyDenied as exc:
                errors.append(exc.reason)

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(10)
        self.assertEqual(errors, ["global_stop"])

    def test_ssh_consume_rechecks_username_and_stop(self) -> None:
        self.policy.create_connection(ssh_connection())
        grant = self.grant(cid="box")
        self.assertTrue(self.policy.evaluate("agent-1", "box", P.Action("ssh", username="deploy"), grant.id).allowed)
        self.other_process().stop_all()
        self.assert_consume_denied(grant.id, "global_stop")
        self.other_process().resume()
        self.assert_consume_denied(grant.id, "ssh_user_mismatch", action=P.Action("ssh", username="root"))

    # ------------------------------------------------ PL-6: widening changes
    def test_trust_anchor_and_secret_changes_are_widening(self) -> None:
        grant = self.grant()
        _, widened = self.policy.update_connection("gh", http_target=P.HttpTarget("http", "127.0.0.1", 8080, "/tmp/other-ca.pem"))
        self.assertTrue(widened)
        self.assertEqual(self.policy.get_grant(grant.id).status, "stale")
        fresh = self.policy.regrant(grant.id)
        _, widened = self.policy.update_connection("gh", http_target=P.HttpTarget("http", "127.0.0.1", 8080, None))
        self.assertTrue(widened)   # back to the system trust store
        self.assertEqual(self.policy.get_grant(fresh.id).status, "stale")
        fresh = self.policy.regrant(fresh.id)
        _, widened = self.policy.update_connection("gh", secret_id="gh-admin-token")
        self.assertTrue(widened)
        self.assertEqual(self.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"), fresh.id).reason,
                         "grant_stale")
        fresh = self.policy.regrant(fresh.id)
        _, widened = self.policy.update_connection("gh", secret_version=3)   # a version of the same secret
        self.assertFalse(widened)
        self.assertEqual(self.policy.get_grant(fresh.id).status, "active")

    # --------------------------------------------- SSH-1 / SSH-2: validation
    def test_ssh_target_rejects_multiline_host_keys_and_trailing_newline_usernames(self) -> None:
        good = ssh_connection().ssh_target.host_keys[0]
        evil = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB evil"
        for line in (good + "\n[victim.example.com]:22 " + evil, good + "\r\n" + evil, good + "\x00",
                     good.replace(" host", "\thost"), "ssh-ed25519 AAAA", "ssh-ed25519 not-base64!"):
            with self.assertRaises(InvalidInput, msg=repr(line)) as caught:
                P.SshTarget("127.0.0.1", 22, "deploy", (line,))
            self.assertEqual(caught.exception.reason, "invalid_host_key")
        with self.assertRaises(InvalidInput):
            P.SshTarget("127.0.0.1", 22, "deploy", good)   # a bare string is not a tuple of lines
        for username in ("deploy\n", "deploy\r", "deploy\x00", "\ndeploy"):
            with self.assertRaises(InvalidInput, msg=repr(username)) as caught:
                P.SshTarget("127.0.0.1", 22, username, (good,))
            self.assertEqual(caught.exception.reason, "invalid_ssh_username")
        target = P.SshTarget("127.0.0.1", 22, "deploy", (good + "  ",))
        self.assertEqual(target.host_keys, (good,))   # canonical single-line form is stored
        self.assertTrue(all("\n" not in line for line in target.host_keys))

    # ------------------------------------------ PL-4 / PL-7: approval lifecycle
    def approval(self, path: str = "/repos/demo") -> str:
        digest = P.approval_digest("agent-1", "gh", "DELETE", path, b"")
        self.policy.request_approval(digest, "agent-1", "gh", "DELETE", path)
        return digest

    def test_approval_expires(self) -> None:
        self.grant()
        digest = self.approval()
        self.clock.now += P.APPROVAL_TTL_SECONDS
        with self.assertRaises(InvalidInput) as caught:
            self.policy.approve(digest)
        self.assertEqual(caught.exception.reason, "approval_expired")
        digest = self.approval()   # a new cycle for the same digest
        self.assertEqual(self.policy.list_approvals()[digest]["cycle"], 2)
        self.policy.approve(digest)
        self.clock.now += P.APPROVAL_TTL_SECONDS
        self.assertFalse(self.policy.consume_approval(digest, "agent-1", "gh"))
        self.assertEqual(self.policy.list_approvals()[digest]["status"], "expired")

    def test_approval_is_bound_to_grant_and_policy_version_and_dies_with_them(self) -> None:
        """PL-4: revocation, recovery (revoke_all) and policy changes invalidate open approvals."""
        grant = self.grant()
        digest = self.approval()
        entry = self.policy.list_approvals()[digest]
        self.assertEqual((entry["grant"], entry["policy_version"]), (grant.id, 1))
        self.assertIsInstance(entry["expires_at"], float)
        self.policy.approve(digest)
        self.other_process().revoke_grant(grant.id)
        self.assertEqual(self.policy.list_approvals()[digest]["status"], "invalidated")
        fresh = self.grant()
        self.assertFalse(self.policy.consume_approval(digest, "agent-1", "gh", grant_id=fresh.id))

        for invalidate in (lambda p: p.revoke_all(), lambda p: p.update_connection("gh", description="x"),
                           lambda p: p.disable_principal("agent-1")):
            fresh = self.grant()
            digest = self.approval(f"/repos/{fresh.id}")
            self.policy.approve(digest)
            invalidate(self.other_process())
            self.assertEqual(self.policy.list_approvals()[digest]["status"], "invalidated")
            self.assertFalse(self.policy.consume_approval(digest, "agent-1", "gh"))

    def test_approval_refused_under_another_grant_or_version(self) -> None:
        grants = {self.grant().id, self.grant().id}
        digest = self.approval()
        self.policy.approve(digest)
        # Without a prior evaluate() the approval records the usable grant policy picks; which of two
        # equally usable grants that is follows grant-id order (random), so derive both roles from it.
        recorded = self.policy.list_approvals()[digest]["grant"]
        self.assertIn(recorded, grants)
        (other,) = grants - {recorded}
        self.assertFalse(self.policy.consume_approval(digest, "agent-2", "gh"))   # wrong caller: untouched
        self.assertEqual(self.policy.list_approvals()[digest]["status"], "approved")
        self.assertFalse(self.policy.consume_approval(digest, "agent-1", "gh", grant_id=other))
        self.assertEqual(self.policy.list_approvals()[digest]["closed_reason"], "grant_changed")
        digest = self.approval()
        self.policy.approve(digest)
        self.assertFalse(self.policy.consume_approval(digest, "agent-1", "gh", policy_version=7))
        self.assertEqual(self.policy.list_approvals()[digest]["closed_reason"], "policy_changed")
        digest = self.approval()
        self.policy.approve(digest)
        self.assertEqual(self.policy.list_approvals()[digest]["grant"], recorded)
        self.assertTrue(self.policy.consume_approval(digest, "agent-1", "gh", grant_id=recorded, policy_version=1))

    def test_used_approval_starts_a_new_cycle_with_history(self) -> None:
        """PL-7: an approval used up by a request that was refused before transmission can be approved again."""
        self.grant()
        digest = self.approval()
        self.policy.approve(digest)
        self.assertTrue(self.policy.consume_approval(digest, "agent-1", "gh"))
        again = self.policy.request_approval(digest, "agent-1", "gh", "DELETE", "/repos/demo")
        self.assertEqual((again["status"], again["cycle"]), ("pending", 2))
        self.assertEqual([(h["digest"], h["status"], h["cycle"]) for h in self.policy.approval_history()],
                         [(digest, "consumed", 1)])
        self.assertFalse(self.policy.consume_approval(digest, "agent-1", "gh"))   # still one-shot
        self.policy.approve(digest)
        self.assertTrue(self.policy.consume_approval(digest, "agent-1", "gh"))
        # The open entry is returned as-is while it is usable.
        digest = self.approval("/repos/other")
        self.assertEqual(self.policy.request_approval(digest, "agent-1", "gh", "DELETE", "/repos/other")["cycle"], 1)

    # -------------------------------------- F10 / F12: ledger, credential version
    def test_revocations_are_ledgered_and_reapplied(self) -> None:
        self.policy.create_principal("agent-2")
        self.policy.create_connection(http_connection("gh2"))
        grant = self.grant()
        other = self.policy.create_grant("agent-2", "gh2", 3600, None)
        stale = self.grant()
        snapshot = {name: self.state.read_json(name) for name in (P.GRANTS, P.PRINCIPALS, P.CONNECTIONS)}
        self.policy.revoke_grant(grant.id)
        self.policy.disable_principal("agent-2")
        self.policy.disable_connection("gh2")
        fresh = self.policy.regrant(stale.id)
        for name, doc in snapshot.items():   # roll the documents back, as an old archive would
            self.state.write_json(name, doc)
        found = P.collect_revocations(self.state)
        self.assertEqual((found.grants, found.principals, found.connections), ({grant.id, stale.id}, {"agent-2"}, {"gh2"}))
        counts = self.policy.reapply_revocations(found)
        self.assertEqual(counts, {"grants": 2, "principals": 1, "connections": 1})
        self.assertEqual(self.policy.get_grant(grant.id).status, "revoked")
        self.assertEqual(self.policy.get_grant(stale.id).status, "revoked")
        self.assertEqual(self.policy.get_principal("agent-2").status, "disabled")
        self.assertEqual(self.policy.get_connection("gh2").status, "disabled")
        self.assertEqual(self.policy.reapply_revocations(found), {"grants": 0, "principals": 0, "connections": 0})
        self.assertNotIn(fresh.id, found.grants)
        # A connection re-enabled through the core API is not disabled again by a replay.
        self.policy.update_connection("gh2", status="active")
        self.assertNotIn("gh2", P.collect_revocations(self.state).connections)
        # Audit records are a second source.
        audit = [{"event": "grant_revoke", "result": "ok", "grant": other.id},
                 {"event": "principal_disable", "result": "denied", "principal": "agent-1"}]
        self.assertIn(other.id, P.collect_revocations(self.state, audit).grants)
        self.assertNotIn("agent-1", P.collect_revocations(self.state, audit).principals)

    def test_grant_records_credential_version_and_activation_rebinds_unpinned_connections(self) -> None:
        """F12: a new active vault version bumps the policy version of unpinned connections that follow it."""
        vault = {"secrets": {"gh-token": {"active_version": 1, "versions": {}}}}
        self.state.write_json(P.VAULT_SECRETS, vault)
        self.policy.create_connection(http_connection("pinned", secret_version=1))
        grant = self.grant()
        pinned = self.grant(cid="pinned")
        self.assertEqual((grant.credential_version, pinned.credential_version), (1, 1))
        self.assertEqual(self.policy.credential_versions_changed("gh-token"), [])   # unchanged
        vault["secrets"]["gh-token"]["active_version"] = 2
        self.state.write_json(P.VAULT_SECRETS, vault)
        changed = self.policy.credential_versions_changed("gh-token")
        self.assertEqual([(c.id, c.policy_version) for c in changed], [("gh", 2)])
        after = self.policy.get_grant(grant.id)
        self.assertEqual((after.status, after.policy_version, after.credential_version), ("active", 2, 2))
        self.assertEqual(self.policy.get_connection("pinned").policy_version, 1)
        vault["secrets"]["gh-token"]["active_version"] = None   # no credential at all: nothing to re-bind
        self.state.write_json(P.VAULT_SECRETS, vault)
        self.assertEqual(self.policy.credential_versions_changed("gh-token"), [])
        self.assertEqual(self.policy.get_connection("gh").policy_version, 2)


if __name__ == "__main__":
    unittest.main()
