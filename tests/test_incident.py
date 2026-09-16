"""Compromise-response incidents: manual lockdown (stage 1) and exposure assessment (stage 2).

docs/compromise-response.md §4.4 (containment order), §5 (exposure tiers).  Tests behaviour and
failure boundaries -- scope isolation, idempotency, audit-failure tolerance, cross-process
application via ``serve`` -- not a line-by-line mirror of ``zeropw/incident.py``.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from zeropw import admin_cli
from zeropw import incident as I
from zeropw import policy as P
from zeropw import runs as R
from zeropw import signer as S
from zeropw import sshwire
from zeropw import tools
from zeropw.context import Config, Context
from zeropw.errors import AuthFailed, InvalidInput, NotFound
from zeropw.store import iso

try:  # tests/ is imported both as a package and by running this file's directory directly
    from tests.test_admin_cli import AdminCliTestCase
except ImportError:  # pragma: no cover - discovery from another working directory
    from test_admin_cli import AdminCliTestCase  # type: ignore[no-redef]

ADMIN = "admin-passphrase-1"
RECOVERY = "recovery-passphrase-1"
SYNTHETIC = b"synthetic-incident-secret-0123456789"
PYTHON = sys.executable

# Writes a "ready" marker then sleeps: lets a test wait for the child to actually be running
# before it triggers containment, and cancellation is observed as an early exit.
SLEEP_SCRIPT = "import sys, time\nopen(sys.argv[2], 'w').write('ready')\ntime.sleep(float(sys.argv[1]))\n"


class FakeClock:
    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float = 1.0) -> None:
        self.now += seconds


def http_connection(cid: str, secret_id: str = "gh-token", program: str | None = None,
                    **overrides: Any) -> P.Connection:
    base: dict[str, Any] = dict(
        id=cid, project="demo", environment="dev", service="fake-service", kind="http", secret_id=secret_id,
        secret_version=None, description="",
        http_target=P.HttpTarget("http", "127.0.0.1", 8080), http_auth=P.HttpAuth("bearer"),
        http_scope=P.HttpScope(None, None, ()),
        ssh_target=None, cli=P.CliProfile(program, "http") if program else None,
        policy_version=0, status="active", created_at="", updated_at="",
    )
    base.update(overrides)
    return P.Connection(**base)


def write_script(path: Path, body: str) -> str:
    path.write_text(f"#!{PYTHON}\n{body}")
    path.chmod(0o700)
    return str(path)


# ============================================================ containment ==
class IncidentTestCase(unittest.TestCase):
    """A ``Context`` with the tools registry and signer installed, like a running ``serve`` process."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.clock = FakeClock()
        self.ctx = Context.initialize(self.root / "state", ADMIN, RECOVERY, Config(), self.clock)
        self.ctx.projects.create("demo")
        self.ctx.vault.put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev")
        self.scripts = self.root / "bin"
        self.scripts.mkdir()
        self.registry = tools.install(self.ctx)
        tools.set_public_url(self.ctx, "http://127.0.0.1:1")
        self.manager = S.install(self.ctx)

    def tearDown(self) -> None:
        self.registry.shutdown()
        self.manager.shutdown()
        self.tmp.cleanup()

    # helpers -----------------------------------------------------------
    def make_principal(self, pid: str, runtime: str = "default") -> str:
        return self.ctx.policy.create_principal(pid, runtime)

    def make_connection(self, cid: str, program: str | None = None, **overrides: Any) -> P.Connection:
        return self.ctx.policy.create_connection(http_connection(cid, program=program, **overrides))

    def make_grant(self, pid: str, cid: str, ttl: int | None = 3600) -> P.Grant:
        return self.ctx.policy.create_grant(pid, cid, ttl, None)

    def sleeper(self, name: str = "sleep.py") -> str:
        return write_script(self.scripts / name, SLEEP_SCRIPT)

    def start_run(self, pid: str, cid: str, seconds: float, ready: Path) -> Any:
        view = tools.exec(self.ctx, pid, cid, [str(seconds), str(ready)])
        return self.registry.get(view["run_id"], pid)

    def wait_for(self, predicate: Any, message: str, timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.02)
        self.fail(message)


class PrincipalScopeTests(IncidentTestCase):
    def test_disables_only_target_and_keeps_the_other_principal_alive(self) -> None:
        token1 = self.make_principal("agent-1")
        token2 = self.make_principal("agent-2")
        program = self.sleeper()
        self.make_connection("gh", program=program)
        self.make_connection("gh2", program=program)
        g1 = self.make_grant("agent-1", "gh")
        g2 = self.make_grant("agent-2", "gh2")
        conn2_version = self.ctx.policy.get_connection("gh2").policy_version
        handle2 = self.ctx.handles.issue("agent-2", "gh2", g2.id, conn2_version, 600)

        # agent-1 also holds an open SSH signer socket; the incident must close it too.
        host_key = sshwire.generate_ed25519_private_key("host")
        self.ctx.vault.put_secret("box-key", "ssh_private_key",
                                  sshwire.generate_ed25519_private_key("box").to_openssh_private_key().encode(),
                                  "demo", "dev")
        self.ctx.policy.create_connection(P.Connection(
            id="box", project="demo", environment="dev", service="ssh-box", kind="ssh", secret_id="box-key",
            secret_version=None, description="", http_target=None, http_auth=None, http_scope=None,
            ssh_target=P.SshTarget("127.0.0.1", 2222, "deploy", (host_key.public.to_authorized_key("host"),)),
            cli=None, policy_version=0, status="active", created_at="", updated_at=""))
        ssh_grant = self.make_grant("agent-1", "box")
        binding = self.manager.bind("agent-1", "box", ssh_grant.id)
        self.assertTrue(Path(binding.socket_path).exists())

        ready1, ready2 = self.root / "ready1", self.root / "ready2"
        run1 = self.start_run("agent-1", "gh", 30, ready1)
        run2 = self.start_run("agent-2", "gh2", 30, ready2)
        self.wait_for(ready1.exists, "run1 never started")
        self.wait_for(ready2.exists, "run2 never started")

        incident = I.open_incident(self.ctx, scope="principal", principals=["agent-1"], trigger="manual")

        self.assertEqual(incident.scope, "principal")
        self.assertEqual(incident.principals, ["agent-1"])
        with self.assertRaises(AuthFailed):
            self.ctx.policy.authenticate(token1)
        self.assertEqual(self.ctx.policy.authenticate(token2).id, "agent-2")

        self.assertEqual(self.ctx.policy.get_grant(g1.id).status, "revoked")
        self.assertEqual(self.ctx.policy.get_grant(g2.id).status, "active")
        self.assertEqual(self.ctx.policy.get_grant(ssh_grant.id).status, "revoked")

        run1.done.wait(10)
        self.assertEqual(run1.state, R.CANCELLED)
        self.assertEqual(self.registry.view(run2)["state"], "running")

        self.assertNotIn(binding, self.manager.active_bindings())
        self.assertFalse(Path(binding.socket_path).exists())

        self.assertFalse(self.ctx.policy.is_stopped())
        self.ctx.handles.verify(handle2)  # does not raise: the handle key is untouched for principal scope

        self.assertEqual(incident.actions["principals_disabled"], 1)
        self.assertEqual(incident.actions["grants_revoked"], 2)
        self.assertGreaterEqual(incident.actions["runs_cancelled"], 1)
        self.assertGreaterEqual(incident.actions["sockets_closed"], 1)
        self.assertFalse(incident.actions.get("applied_by_serve", False))

        self.registry.cancel(run2.id, "agent-2")  # tidy up the still-running child


class RuntimeScopeTests(IncidentTestCase):
    def test_partial_runtime_disables_its_principals_but_does_not_stop_all(self) -> None:
        token1 = self.make_principal("agent-1", runtime="rt-a")
        token2 = self.make_principal("agent-2", runtime="rt-a")
        token3 = self.make_principal("agent-3", runtime="default")
        self.make_connection("gh")
        g3 = self.make_grant("agent-3", "gh")
        conn_version = self.ctx.policy.get_connection("gh").policy_version
        handle3 = self.ctx.handles.issue("agent-3", "gh", g3.id, conn_version, 600)
        self.ctx.handles.verify(handle3)  # sanity: valid before the incident

        incident = I.open_incident(self.ctx, scope="runtime", runtime="rt-a", trigger="manual")

        self.assertEqual(sorted(incident.principals), ["agent-1", "agent-2"])
        with self.assertRaises(AuthFailed):
            self.ctx.policy.authenticate(token1)
        with self.assertRaises(AuthFailed):
            self.ctx.policy.authenticate(token2)
        self.assertEqual(self.ctx.policy.authenticate(token3).id, "agent-3")
        self.assertFalse(incident.actions["stopped"])
        self.assertFalse(self.ctx.policy.is_stopped())

        # Every handle is invalidated once the (single, global) handle key is rotated -- including
        # agent-3's, even though agent-3 is outside the incident's runtime (§4.4 step 5; there is
        # no per-runtime handle key in this design, so escalating past "principal" is deliberately blunt).
        self.assertTrue(incident.actions["handle_key_rotated"])
        with self.assertRaises(AuthFailed):
            self.ctx.handles.verify(handle3)

    def test_runtime_covering_every_active_principal_stops_all(self) -> None:
        self.make_principal("agent-1", runtime="rt-a")
        self.make_principal("agent-2", runtime="rt-a")
        incident = I.open_incident(self.ctx, scope="runtime", runtime="rt-a", trigger="manual")
        self.assertTrue(incident.actions["stopped"])
        self.assertTrue(self.ctx.policy.is_stopped())


class AllScopeTests(IncidentTestCase):
    def test_all_scope_stops_everything_and_marks_every_secret_mandatory(self) -> None:
        token1 = self.make_principal("agent-1")
        token2 = self.make_principal("agent-2")
        self.make_connection("gh")
        self.make_connection("gh2")
        g1 = self.make_grant("agent-1", "gh")
        g2 = self.make_grant("agent-2", "gh2")
        self.ctx.vault.put_secret("unrelated-secret", "password", b"synthetic-unrelated-000000", "demo", "dev")

        incident = I.open_incident(self.ctx, scope="all", trigger="manual")

        for token in (token1, token2):
            with self.assertRaises(AuthFailed):
                self.ctx.policy.authenticate(token)
        self.assertTrue(self.ctx.policy.is_stopped())
        self.assertTrue(incident.actions["handle_key_rotated"])
        # revoke_all-equivalent effect: every principal's grants are gone, not only the first one's.
        self.assertEqual(self.ctx.policy.get_grant(g1.id).status, "revoked")
        self.assertEqual(self.ctx.policy.get_grant(g2.id).status, "revoked")
        self.assertEqual(incident.actions["principals_disabled"], 2)
        self.assertEqual(incident.actions["grants_revoked"], 2)

        secrets_by_id = {s["secret_id"]: s for s in incident.assessment["secrets"]}
        self.assertEqual(secrets_by_id["gh-token"]["tier"], "mandatory")
        self.assertTrue(secrets_by_id["gh-token"]["recover_required"])
        self.assertEqual(secrets_by_id["unrelated-secret"]["tier"], "mandatory")
        self.assertTrue(secrets_by_id["unrelated-secret"]["recover_required"])
        self.assertTrue(incident.assessment["recover_required"])  # top-level flag too (M2)


class OpenWidenTests(IncidentTestCase):
    def test_opening_while_one_is_open_at_an_equal_scope_returns_it_unchanged(self) -> None:
        self.make_principal("agent-1")
        first = I.open_incident(self.ctx, scope="principal", principals=["agent-1"], trigger="manual")
        token2 = self.make_principal("agent-2")
        second = I.open_incident(self.ctx, scope="principal", principals=["agent-2"], trigger="manual")
        self.assertEqual(second.id, first.id)
        self.assertEqual(second.scope, "principal")
        self.assertEqual(second.principals, ["agent-1"])  # agent-2's request was absorbed, not applied
        self.assertEqual(self.ctx.policy.authenticate(token2).id, "agent-2")

    def test_opening_with_a_wider_scope_widens_the_existing_incident_instead(self) -> None:
        """M1 regression: a wider signal while an incident is open must not be silently absorbed."""
        self.make_principal("agent-1", runtime="rt-b")
        first = I.open_incident(self.ctx, scope="principal", principals=["agent-1"], trigger="manual")
        token2 = self.make_principal("agent-2", runtime="rt-b")
        second = I.open_incident(self.ctx, scope="runtime", runtime="rt-b", trigger="manual")
        self.assertEqual(second.id, first.id)
        self.assertEqual(second.scope, "runtime")
        self.assertEqual(sorted(second.principals), ["agent-1", "agent-2"])
        with self.assertRaises(AuthFailed):
            self.ctx.policy.authenticate(token2)
        self.assertEqual(len(second.widened_from), 1)

    def test_widen_principal_to_runtime_adds_the_others_and_rotates_the_key(self) -> None:
        self.make_principal("agent-1", runtime="rt-a")
        incident = I.open_incident(self.ctx, scope="principal", principals=["agent-1"], trigger="manual")
        self.assertFalse(incident.actions["handle_key_rotated"])
        token2 = self.make_principal("agent-2", runtime="rt-a")

        widened = I.widen_incident(self.ctx, incident.id, scope="runtime", runtime="rt-a")

        self.assertEqual(widened.scope, "runtime")
        self.assertEqual(sorted(widened.principals), ["agent-1", "agent-2"])
        self.assertTrue(widened.actions["handle_key_rotated"])
        with self.assertRaises(AuthFailed):
            self.ctx.policy.authenticate(token2)
        self.assertEqual(len(widened.widened_from), 1)
        self.assertEqual(widened.widened_from[0]["scope"], "principal")
        self.assertEqual(I.get_incident(self.ctx, incident.id).scope, "runtime")  # persisted

    def test_widen_refuses_a_narrower_or_equal_scope(self) -> None:
        self.make_principal("agent-1", runtime="rt-a")
        self.make_principal("agent-2", runtime="rt-a")
        incident = I.open_incident(self.ctx, scope="runtime", runtime="rt-a", trigger="manual")
        with self.assertRaises(InvalidInput) as caught:
            I.widen_incident(self.ctx, incident.id, scope="runtime", runtime="rt-a")
        self.assertEqual(caught.exception.reason, "incident_scope_not_wider")
        with self.assertRaises(InvalidInput) as caught:
            I.widen_incident(self.ctx, incident.id, scope="principal", principals=["agent-1"])
        self.assertEqual(caught.exception.reason, "incident_scope_not_wider")


class ResumeTests(IncidentTestCase):
    def test_resume_refused_while_open_then_allowed_after_close(self) -> None:
        token1 = self.make_principal("agent-1")
        self.ctx.policy.stop_all()
        incident = I.open_incident(self.ctx, scope="principal", principals=["agent-1"], trigger="manual")

        with self.assertRaises(InvalidInput) as caught:
            self.ctx.policy.resume()
        self.assertEqual(caught.exception.reason, "incident_open")
        self.assertEqual(caught.exception.detail, incident.id)

        closed = I.close_incident(self.ctx, incident.id)
        self.assertEqual(closed.status, "closed")
        self.assertIsNone(self.ctx.policy.open_incident_id())

        self.ctx.policy.resume()  # closing does not itself resume; this now succeeds
        self.assertFalse(self.ctx.policy.is_stopped())
        with self.assertRaises(AuthFailed):
            self.ctx.policy.authenticate(token1)  # disabled principals never come back

    def test_close_refuses_a_closed_incident(self) -> None:
        self.make_principal("agent-1")
        incident = I.open_incident(self.ctx, scope="principal", principals=["agent-1"], trigger="manual")
        I.close_incident(self.ctx, incident.id)
        with self.assertRaises(InvalidInput) as caught:
            I.close_incident(self.ctx, incident.id)
        self.assertEqual(caught.exception.reason, "incident_already_closed")


class IdempotencyTests(IncidentTestCase):
    def test_apply_lockdown_twice_with_the_same_targets_does_not_double_count(self) -> None:
        self.make_principal("agent-1")
        self.make_connection("gh")
        self.make_grant("agent-1", "gh")
        incident = I.Incident(
            id="inc-test", opened_at="2026-01-01T00:00:00Z", status="open", scope="principal", runtime=None,
            principals=["agent-1"], trigger="manual", rule=None, detail=None,
            actions=I._initial_actions(), assessment={}, notification={"status": "not_configured", "attempts": 0},
        )
        I._apply_lockdown(self.ctx, incident, ["agent-1"], scope="principal", runtime=None)
        after_first = dict(incident.actions)
        self.assertEqual(after_first["failed_steps"], [])

        I._apply_lockdown(self.ctx, incident, ["agent-1"], scope="principal", runtime=None)
        self.assertEqual(incident.actions["principals_disabled"], after_first["principals_disabled"])
        self.assertEqual(incident.actions["grants_revoked"], after_first["grants_revoked"])
        self.assertEqual(incident.actions["runs_cancelled"], after_first["runs_cancelled"])
        self.assertEqual(incident.actions["sockets_closed"], after_first["sockets_closed"])
        self.assertEqual(incident.actions["failed_steps"], [])


class FailureToleranceTests(IncidentTestCase):
    def test_rotate_handle_key_failure_does_not_block_the_rest_of_the_lockdown(self) -> None:
        token1 = self.make_principal("agent-1", runtime="rt-a")
        self.make_principal("agent-2", runtime="rt-a")
        with patch.object(self.ctx, "rotate_handle_key", side_effect=RuntimeError("boom")):
            incident = I.open_incident(self.ctx, scope="runtime", runtime="rt-a", trigger="manual")
        self.assertIn("rotate_handle_key", incident.actions["failed_steps"])
        self.assertFalse(incident.actions["handle_key_rotated"])
        self.assertTrue(incident.actions["stopped"])   # both active principals are inside rt-a
        self.assertEqual(incident.actions["principals_disabled"], 2)
        with self.assertRaises(AuthFailed):
            self.ctx.policy.authenticate(token1)


# ============================================================== assessment ==
class AssessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.clock = FakeClock()
        self.ctx = Context.initialize(self.root / "state", ADMIN, RECOVERY, Config(), self.clock)
        self.ctx.projects.create("demo")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_mandatory_recommended_and_none_tiers(self) -> None:
        self.ctx.vault.put_secret("gh-token", "api_key", b"synthetic-gh-000000", "demo", "dev")
        self.ctx.vault.put_secret("jira-token", "api_key", b"synthetic-jira-000000", "demo", "dev")
        self.ctx.vault.put_secret("slack-token", "api_key", b"synthetic-slack-000000", "demo", "dev")
        self.ctx.policy.create_connection(http_connection("gh", secret_id="gh-token"))
        self.ctx.policy.create_connection(http_connection("jira", secret_id="jira-token"))
        self.ctx.policy.create_connection(http_connection("slack", secret_id="slack-token"))
        self.ctx.policy.create_principal("agent-1")
        created_at = self.ctx.policy.get_principal("agent-1").created_at
        self.ctx.policy.create_grant("agent-1", "gh", 3600, None)
        self.ctx.policy.create_grant("agent-1", "jira", 3600, None)
        # no grant at all for "slack": it must not appear.

        # Usage logged as having happened BEFORE the principal's own creation must be ignored --
        # temporally impossible for a genuine record, but this is exactly the boundary assess() must
        # get right, so the clock is wound back to write one.
        self.clock.now -= 10
        self.ctx.audit.record("http_relay", caller="agent-1", connection="gh", result="ok", action="GET")
        self.clock.now += 10

        self.clock.advance(5)
        self.ctx.audit.record("http_relay", caller="agent-1", connection="gh", result="ok", action="GET")

        result = I.assess(self.ctx, ["agent-1"], "principal", since=iso(self.clock.now))
        by_id = {s["secret_id"]: s for s in result["secrets"]}
        self.assertEqual(by_id["gh-token"]["tier"], "mandatory")
        self.assertEqual(by_id["gh-token"]["use_count"], 1)  # only the post-creation record counted
        self.assertEqual(by_id["jira-token"]["tier"], "recommended")
        self.assertNotIn("slack-token", by_id)
        self.assertEqual(result["principals"], [{"id": "agent-1", "created_at": created_at, "runtime": "default"}])

    def test_two_principals_merge_into_one_mandatory_secret(self) -> None:
        self.ctx.vault.put_secret("gh-token", "api_key", b"synthetic-gh-1", "demo", "dev")
        self.ctx.policy.create_connection(http_connection("gh", secret_id="gh-token"))
        self.ctx.policy.create_principal("agent-1")
        self.ctx.policy.create_principal("agent-2")
        self.ctx.policy.create_grant("agent-1", "gh", 3600, None)   # never used
        self.ctx.policy.create_grant("agent-2", "gh", 3600, None)
        self.clock.advance(1)
        self.ctx.audit.record("http_relay", caller="agent-2", connection="gh", result="ok", action="GET")

        result = I.assess(self.ctx, ["agent-1", "agent-2"], "principal", since=iso(self.clock.now))
        secret = {s["secret_id"]: s for s in result["secrets"]}["gh-token"]
        self.assertEqual(secret["tier"], "mandatory")
        self.assertEqual(secret["use_count"], 1)
        self.assertEqual(len(result["principals"]), 2)

    def test_ssh_secret_carries_fingerprint_and_target(self) -> None:
        key = sshwire.generate_ed25519_private_key("demo")
        host_key = sshwire.generate_ed25519_private_key("host")
        self.ctx.vault.put_secret("box-key", "ssh_private_key", key.to_openssh_private_key().encode(), "demo", "dev")
        connection = P.Connection(
            id="box", project="demo", environment="dev", service="ssh-box", kind="ssh", secret_id="box-key",
            secret_version=None, description="", http_target=None, http_auth=None, http_scope=None,
            ssh_target=P.SshTarget("127.0.0.1", 2222, "deploy", (host_key.public.to_authorized_key("host"),)),
            cli=None, policy_version=0, status="active", created_at="", updated_at="")
        self.ctx.policy.create_connection(connection)
        self.ctx.policy.create_principal("agent-1")
        self.ctx.policy.create_grant("agent-1", "box", 3600, None)
        self.clock.advance(1)
        self.ctx.audit.record("ssh_sign", caller="agent-1", connection="box", result="ok", action="ssh-sign")

        result = I.assess(self.ctx, ["agent-1"], "principal", since=iso(self.clock.now))
        secret = {s["secret_id"]: s for s in result["secrets"]}["box-key"]
        self.assertEqual(secret["tier"], "mandatory")
        self.assertEqual(secret["fingerprint"], key.public.fingerprint())
        self.assertEqual(secret["targets"], [{"host": "127.0.0.1", "port": 2222, "username": "deploy"}])

    def test_incident_file_never_contains_a_vault_value(self) -> None:
        self.ctx.vault.put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev")
        self.ctx.policy.create_connection(http_connection("gh", secret_id="gh-token"))
        self.ctx.policy.create_principal("agent-1")
        self.ctx.policy.create_grant("agent-1", "gh", 3600, None)
        self.clock.advance(1)
        self.ctx.audit.record("http_relay", caller="agent-1", connection="gh", result="ok", action="GET")

        incident = I.open_incident(self.ctx, scope="principal", principals=["agent-1"], trigger="manual")
        path = self.ctx.state.path / "incidents" / f"{incident.id}.json"
        data = path.read_bytes()
        patterns = R.credential_patterns(SYNTHETIC)
        self.assertFalse(R.contains_sensitive(data, patterns))
        self.assertEqual(incident.assessment.get("redacted"), None)  # the real assessment was written

    def test_recommended_tier_survives_open_incidents_own_grant_revocation(self) -> None:
        """H1 regression: open_incident's step 4 revokes grants before step 7 assesses them,
        so a granted-but-unused connection must still come out "recommended", not vanish."""
        self.ctx.vault.put_secret("gh-token", "api_key", b"synthetic-gh-000000", "demo", "dev")
        self.ctx.vault.put_secret("jira-token", "api_key", b"synthetic-jira-000000", "demo", "dev")
        self.ctx.policy.create_connection(http_connection("gh", secret_id="gh-token"))
        self.ctx.policy.create_connection(http_connection("jira", secret_id="jira-token"))
        self.ctx.policy.create_principal("agent-1")
        self.ctx.policy.create_grant("agent-1", "gh", 3600, None)
        self.ctx.policy.create_grant("agent-1", "jira", 3600, None)   # never used
        self.clock.advance(1)
        self.ctx.audit.record("http_relay", caller="agent-1", connection="gh", result="ok", action="GET")

        incident = I.open_incident(self.ctx, scope="principal", principals=["agent-1"], trigger="manual")

        jira_grant = next(g for g in self.ctx.policy.list_grants("agent-1") if g.connection == "jira")
        self.assertEqual(jira_grant.status, "revoked")  # the incident's own step 4 already revoked it
        by_id = {s["secret_id"]: s for s in incident.assessment["secrets"]}
        self.assertEqual(by_id["gh-token"]["tier"], "mandatory")
        self.assertEqual(by_id["jira-token"]["tier"], "recommended")

    def test_recommended_tier_survives_widening(self) -> None:
        """Same H1 regression, through widen_incident: the *original* principal's
        granted-but-unused connection must still read "recommended" after a widen."""
        self.ctx.vault.put_secret("gh-token", "api_key", b"synthetic-gh-000000", "demo", "dev")
        self.ctx.vault.put_secret("jira-token", "api_key", b"synthetic-jira-000000", "demo", "dev")
        self.ctx.policy.create_connection(http_connection("gh", secret_id="gh-token"))
        self.ctx.policy.create_connection(http_connection("jira", secret_id="jira-token"))
        self.ctx.policy.create_principal("agent-1", "rt-a")
        self.ctx.policy.create_grant("agent-1", "gh", 3600, None)
        self.ctx.policy.create_grant("agent-1", "jira", 3600, None)   # never used
        self.clock.advance(1)
        self.ctx.audit.record("http_relay", caller="agent-1", connection="gh", result="ok", action="GET")

        incident = I.open_incident(self.ctx, scope="principal", principals=["agent-1"], trigger="manual")
        self.clock.advance(1)
        self.ctx.policy.create_principal("agent-2", "rt-a")

        widened = I.widen_incident(self.ctx, incident.id, scope="runtime", runtime="rt-a")

        by_id = {s["secret_id"]: s for s in widened.assessment["secrets"]}
        self.assertEqual(by_id["gh-token"]["tier"], "mandatory")
        self.assertEqual(by_id["jira-token"]["tier"], "recommended")


# ============================================================ tools_unknown ==
class ToolsUnknownAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ctx = Context.initialize(self.root / "state", ADMIN, RECOVERY, Config())
        self.ctx.projects.create("demo")
        self.ctx.policy.create_principal("agent-1")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_unknown_tool_is_audited_with_caller_and_never_the_tool_name(self) -> None:
        with self.assertRaises(NotFound):
            tools.dispatch(self.ctx, "reveal_secret", "agent-1", {})
        records = [r for r in self.ctx.audit.tail(50) if r["event"] == "tools_unknown"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["caller"], "agent-1")
        self.assertEqual(records[0]["result"], "denied")
        self.assertEqual(records[0]["reason"], "tool_not_found")
        for record in records:
            self.assertNotIn("reveal_secret", json.dumps(record))


# =================================================================== CLI ==
class AdminCliIncidentTests(AdminCliTestCase):
    """Incident commands driven through ``admin_cli.main`` (see AdminCliTestCase for the harness)."""

    def test_scope_all_without_the_admin_passphrase_is_refused(self) -> None:
        self.seed_project()
        with patch.dict(os.environ, {admin_cli.ADMIN_PASSPHRASE_ENV: "wrong-passphrase"}):
            self.assertEqual(self.fail("incident", "declare", "--scope", "all")["reason"], "admin_reauth_failed")
        self.assertIsNone(self.ctx().policy.open_incident_id())
        self.assertIn("auth_failed", self.events())

    def test_incident_close_requires_admin_reauth(self) -> None:
        self.seed_project()
        self.ok("principal", "create", "--id", "agent-1")
        declared = self.ok("incident", "declare", "--scope", "principal", "--principal", "agent-1")
        with patch.dict(os.environ, {admin_cli.ADMIN_PASSPHRASE_ENV: "wrong-passphrase"}):
            self.assertEqual(self.fail("incident", "close", "--id", declared["id"])["reason"], "admin_reauth_failed")
        closed = self.ok("incident", "close", "--id", declared["id"])
        self.assertEqual(closed["status"], "closed")
        self.ok("resume")  # closing does not resume by itself, but resume is no longer refused

    def test_incident_show_and_list_carry_the_assessment_and_no_values(self) -> None:
        self.seed_project()
        self.put_secret()
        self.create_http("gh")
        self.ok("principal", "create", "--id", "agent-1")
        self.ok("grant", "create", "--principal", "agent-1", "--connection", "gh")
        declared = self.ok("incident", "declare", "--scope", "principal", "--principal", "agent-1",
                           "--reason", "synthetic test lockdown")
        shown = self.ok("incident", "show", "--id", declared["id"])
        self.assertIn("assessment", shown)
        self.assertEqual(shown["detail"], "synthetic test lockdown")
        listed = self.ok("incident", "list")
        self.assertEqual([i["id"] for i in listed["incidents"]], [declared["id"]])
        self.assertNotIn(SYNTHETIC.decode(), json.dumps(shown))
        self.assertNotIn(SYNTHETIC.decode(), json.dumps(listed))

    def test_resume_reports_the_open_incident_id(self) -> None:
        self.seed_project()
        self.ok("principal", "create", "--id", "agent-1")
        declared = self.ok("incident", "declare", "--scope", "principal", "--principal", "agent-1")
        error = self.fail("resume")
        self.assertEqual((error["error"], error["reason"], error["detail"]),
                         ("InvalidInput", "incident_open", declared["id"]))

    def test_declare_absorbs_a_narrower_or_equal_request_without_extra_lockdown(self) -> None:
        """M1 branch 1: a second declare that is not wider than the open incident changes nothing."""
        self.seed_project()
        self.ok("principal", "create", "--id", "agent-1")
        self.ok("principal", "create", "--id", "agent-2")
        first = self.ok("incident", "declare", "--scope", "principal", "--principal", "agent-1")
        self.assertNotIn("existing", first)
        second = self.ok("incident", "declare", "--scope", "principal", "--principal", "agent-2")
        self.assertEqual(second["id"], first["id"])
        self.assertEqual(second["scope"], "principal")
        self.assertTrue(second["existing"])
        self.assertFalse(second["widened"])
        # agent-2 was named in the absorbed declare but never actually locked down by it.
        self.assertEqual(self.ctx().policy.get_principal("agent-2").status, "active")

    def test_declare_widens_an_open_incident_when_the_new_scope_is_wider(self) -> None:
        """M1 branch 2: a wider declare on an open incident applies containment to the new scope."""
        self.seed_project()
        self.ok("principal", "create", "--id", "agent-1", "--runtime", "rt-a")
        self.ok("principal", "create", "--id", "agent-2", "--runtime", "rt-a")
        first = self.ok("incident", "declare", "--scope", "principal", "--principal", "agent-1")
        self.assertNotIn("existing", first)
        second = self.ok("incident", "declare", "--scope", "runtime", "--runtime", "rt-a")
        self.assertEqual(second["id"], first["id"])
        self.assertEqual(second["scope"], "runtime")
        self.assertTrue(second["existing"])
        self.assertTrue(second["widened"])
        self.assertEqual(self.ctx().policy.get_principal("agent-2").status, "disabled")

    def test_serve_applies_an_incident_declared_by_another_process(self) -> None:
        """The incident CLI writes state only; a running ``serve`` picks it up on its poll,
        exactly like a plain grant revoke or principal disable from a separate process
        (see test_admin_cli.test_serve_cancels_runs_and_closes_signer_sockets_revoked_by_another_process)."""
        self.seed_project()
        self.put_secret()
        sleeper = self.root / "sleeper.py"
        sleeper.write_text(f"#!{PYTHON}\nimport sys, time\nopen(sys.argv[2], 'w').write('ready')\n"
                           "time.sleep(float(sys.argv[1]))\n")
        sleeper.chmod(0o700)
        self.create_http("gh", "--cli-program", str(sleeper))
        self.ok("principal", "create", "--id", "agent-1")
        self.ok("principal", "create", "--id", "agent-2")
        self.ok("grant", "create", "--principal", "agent-1", "--connection", "gh")
        self.ok("secret", "put", "--id", "box-key", "--kind", "ssh_private_key", "--project", "demo",
                "--environment", "dev", "--stdin", stdin_bytes=self.ssh_pem.encode())
        self.ok("connection", "create-ssh", "--id", "box", "--project", "demo", "--environment", "dev",
                "--service", "s", "--secret-id", "box-key", "--host", "127.0.0.1", "--username", "deploy",
                "--host-key", self.host_key)
        ssh_grant = self.ok("grant", "create", "--principal", "agent-1", "--connection", "box")["id"]

        startup: list[dict] = []
        original_emit = admin_cli._emit

        def emit(payload: Any, *, compact: bool = False) -> None:
            if compact:
                startup.append(payload)
            else:
                original_emit(payload)

        captured: list[Context] = []

        class CapturingContext(Context):
            @classmethod
            def open(cls, *args: Any, **kwargs: Any) -> Context:  # type: ignore[override]
                ctx = Context.open(*args, **kwargs)
                captured.append(ctx)
                return ctx

        stop = threading.Event()
        emit_patch = patch.object(admin_cli, "_emit", emit)
        emit_patch.start()
        self.addCleanup(emit_patch.stop)
        with patch.object(admin_cli, "Context", CapturingContext):
            serve = threading.Thread(target=admin_cli.run_serve, args=(self.state, "127.0.0.1:0"),
                                     kwargs={"quiet": True, "stop_event": stop, "install_signals": False}, daemon=True)
            serve.start()
            self.addCleanup(serve.join, 30)
            self.addCleanup(stop.set)
            deadline = time.monotonic() + 30
            while not startup and time.monotonic() < deadline:
                time.sleep(0.05)
        self.assertTrue(startup, "serve did not start")
        serve_ctx = captured[0]

        def wait_for(predicate: Any, what: str, timeout: float = 10.0) -> None:
            limit = time.monotonic() + timeout
            while time.monotonic() < limit:
                if predicate():
                    return
                time.sleep(0.05)
            self.fail(what)

        ready = self.root / "ready"
        view = tools.exec(serve_ctx, "agent-1", "gh", ["30", str(ready)])
        run = serve_ctx.runs.get(view["run_id"], "agent-1")
        wait_for(ready.exists, "the run never started")
        self.assertEqual(serve_ctx.runs.view(run)["state"], "running")
        binding = serve_ctx.signer_manager.bind("agent-1", "box", ssh_grant)
        self.assertTrue(Path(binding.socket_path).exists())

        declared = self.ok("incident", "declare", "--scope", "principal", "--principal", "agent-1")

        wait_for(lambda: serve_ctx.runs.view(run)["state"] == "cancelled", "run not cancelled by the incident")
        wait_for(lambda: binding not in serve_ctx.signer_manager.active_bindings(), "signer binding not released")
        wait_for(lambda: not Path(binding.socket_path).exists(), "signer socket not removed")
        self.assertEqual(self.ctx().policy.open_incident_id(), declared["id"])
        self.assertEqual(self.ctx().policy.get_principal("agent-1").status, "disabled")

        stop.set()
        serve.join(30)
        self.assertFalse(serve.is_alive())


if __name__ == "__main__":
    unittest.main()
