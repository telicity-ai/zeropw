"""Automatic intrusion detection (stage 3): docs/compromise-response.md §4.1-§4.3.

Tests behaviour against the audit-record stream, not a line-by-line mirror of
``zeropw/intrusion.py``.  Most tests feed ``ctx.audit.record(...)`` directly with the exact
event/result/reason shape the real gateway/tools/signer/runs modules write (confirmed by
reading those call sites), since the detector's only input is that value-free record -- see
``zeropw.audit.Audit.subscribe``.  A few tests drive the real ``tools``/``signer`` APIs (or a
live ``serve`` process) where the thing under test is the end-to-end wiring itself: synchronous
lockdown, re-entrancy against real run cancellation/socket release, and ``admin_cli.run_serve``
actually installing the detector.
"""

from __future__ import annotations

import threading
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from zeropw import admin_cli
from zeropw import incident as I
from zeropw import intrusion
from zeropw import tools
from zeropw.context import Config, Context
from zeropw.errors import InvalidInput, NotFound

try:  # tests/ is imported both as a package and by running this file's directory directly
    from tests.test_admin_cli import AdminCliTestCase
    from tests.test_incident import ADMIN, RECOVERY, FakeClock, IncidentTestCase
except ImportError:  # pragma: no cover - discovery from another working directory
    from test_admin_cli import AdminCliTestCase  # type: ignore[no-redef]
    from test_incident import ADMIN, RECOVERY, FakeClock, IncidentTestCase  # type: ignore[no-redef]


class IntrusionTestCase(IncidentTestCase):
    """Adds a detector on top of ``IncidentTestCase``'s tools+signer-equipped ``Context``.
    Each test installs its own detector (with whatever config it needs) rather than relying on
    a shared default, so a config override in one test can never leak into another."""

    def install_detector(self, **config_kwargs: Any) -> intrusion.Detector:
        config = intrusion.DetectorConfig(**config_kwargs)
        detector = intrusion.Detector(self.ctx, config)
        self.ctx.audit.subscribe(detector.on_record)
        self.ctx.intrusion = detector
        return detector

    def open_incident_id(self) -> str | None:
        return self.ctx.policy.open_incident_id()


# ===================================================================== strong
class StrongRuleTests(IntrusionTestCase):
    def test_unknown_tool_strong_rule_opens_principal_scope_at_its_threshold(self) -> None:
        self.install_detector()
        self.make_principal("agent-1")
        with self.assertRaises(NotFound):
            tools.dispatch(self.ctx, "does-not-exist", "agent-1", {})
        self.assertIsNone(self.open_incident_id(), "one occurrence must not trip a 2-threshold rule")
        with self.assertRaises(NotFound):
            tools.dispatch(self.ctx, "still-not-a-tool", "agent-1", {})
        inc_id = self.open_incident_id()
        self.assertIsNotNone(inc_id)
        inc = I.get_incident(self.ctx, inc_id)
        self.assertEqual(inc.scope, "principal")
        self.assertEqual(inc.principals, ["agent-1"])
        self.assertEqual(inc.rule, "unknown_tool")
        self.assertEqual(inc.trigger, "auto")

    def test_signer_misuse_strong_rule_opens_runtime_scope(self) -> None:
        self.install_detector()
        self.make_principal("agent-1", runtime="rt-a")
        self.ctx.audit.record("ssh_sign", caller="agent-1", connection="box", action="ssh-sign",
                              result="denied", reason="not_userauth_request")
        inc_id = self.open_incident_id()
        self.assertIsNotNone(inc_id)
        inc = I.get_incident(self.ctx, inc_id)
        self.assertEqual(inc.scope, "runtime")
        self.assertEqual(inc.runtime, "rt-a")
        self.assertEqual(inc.rule, "signer_misuse")

    def test_output_exfiltration_strong_rule_opens_runtime_scope(self) -> None:
        self.install_detector()
        self.make_principal("agent-1", runtime="rt-b")
        self.ctx.audit.record("run_finish", caller="agent-1", connection="gh", action="exec",
                              result="blocked", reason="output_credential_blocked")
        inc_id = self.open_incident_id()
        self.assertIsNotNone(inc_id)
        inc = I.get_incident(self.ctx, inc_id)
        self.assertEqual(inc.scope, "runtime")
        self.assertEqual(inc.runtime, "rt-b")
        self.assertEqual(inc.rule, "output_exfiltration")

    def test_below_threshold_strong_signals_open_nothing(self) -> None:
        self.install_detector()
        self.make_principal("agent-1", runtime="rt-a")
        # unknown_tool needs 2; leave it at 1.
        with self.assertRaises(NotFound):
            tools.dispatch(self.ctx, "nope", "agent-1", {})
        self.assertIsNone(self.open_incident_id())


class RuleMatchingTests(unittest.TestCase):
    """``_match_denial_rule`` against every documented event/reason combination (§4.2's table),
    as a pure-function check independent of any ``Context`` -- the end-to-end scope/threshold
    behaviour for one representative combination per rule is covered above and in ``ScopeTests``."""

    def test_every_documented_combination_maps_to_its_rule(self) -> None:
        cases = [
            ("tools_unknown", "denied", "tool_not_found", ("unknown_tool", "strong")),
            ("http_relay", "denied", "handle_signature", ("handle_forgery", "strong")),
            ("http_relay", "denied", "handle_malformed", ("handle_forgery", "strong")),
            ("http_relay", "denied", "handle_version", ("handle_forgery", "strong")),
            ("http_relay", "denied", "handle_expired", ("expired_handle", "weak")),
            ("ssh_agent_refused", "denied", "unsupported_agent_message", ("signer_misuse", "strong")),
            ("ssh_agent_refused", "denied", "unsupported_extension", ("signer_misuse", "strong")),
            ("ssh_bind", "denied", "agent_forwarding_not_allowed", ("signer_misuse", "strong")),
            ("ssh_sign", "denied", "not_userauth_request", ("signer_misuse", "strong")),
            ("ssh_sign", "denied", "no_session_bind", ("signer_misuse", "strong")),
            ("ssh_sign", "denied", "unsupported_sign_flags", ("signer_misuse", "strong")),
            ("run_finish", "blocked", "output_credential_blocked", ("output_exfiltration", "strong")),
            ("http_relay", "denied", "grant_revoked", ("revoked_use", "weak")),
            ("tools_request", "denied", "grant_stale", ("revoked_use", "weak")),
            ("ssh_sign", "denied", "principal_disabled", ("revoked_use", "weak")),
            ("http_relay", "denied", "method_not_allowed", ("scope_violation", "weak")),
            ("tools_request", "denied", "path_not_allowed", ("scope_violation", "weak")),
            ("tools_exec", "denied", "approval_required", ("scope_violation", "weak")),
            ("tools_request", "denied", "no_grant", ("unauthorized_connection", "weak")),
            ("tools_exec", "denied", "grant_unknown", ("unauthorized_connection", "weak")),
            ("tools_request", "denied", "connection_unknown", ("unauthorized_connection", "weak")),
        ]
        for event, result, reason, expected in cases:
            with self.subTest(event=event, result=result, reason=reason):
                self.assertEqual(intrusion._match_denial_rule(event, result, reason), expected)

    def test_global_stop_and_restore_pending_never_match_any_rule(self) -> None:
        for event in ("http_relay", "tools_request", "tools_exec", "ssh_sign"):
            for reason in ("global_stop", "restore_pending"):
                with self.subTest(event=event, reason=reason):
                    self.assertEqual(intrusion._match_denial_rule(event, "denied", reason), (None, None))

    def test_unauthorized_connection_reasons_do_not_match_on_http_relay(self) -> None:
        """§4.2's table scopes unauthorized_connection to tools_request/tools_exec only."""
        for reason in ("no_grant", "grant_unknown", "connection_unknown"):
            with self.subTest(reason=reason):
                self.assertEqual(intrusion._match_denial_rule("http_relay", "denied", reason), (None, None))

    def test_ok_and_unmatched_records_return_no_rule(self) -> None:
        self.assertEqual(intrusion._match_denial_rule("http_relay", "ok", None), (None, None))
        self.assertEqual(intrusion._match_denial_rule("tools_list_connections", "ok", None), (None, None))
        self.assertEqual(intrusion._match_denial_rule("run_finish", "cancelled", "cancelled_by_caller"),
                         (None, None))


# ================================================================ unattributed
class UnattributedTests(IntrusionTestCase):
    def test_unattributed_handle_forgery_opens_principal_scope_over_every_active_principal(self) -> None:
        self.install_detector()
        self.make_principal("agent-1")
        self.make_principal("agent-2")
        self.make_principal("agent-3")
        self.ctx.policy.disable_principal("agent-3", notify=False)

        for reason in ("handle_signature", "handle_malformed"):
            self.ctx.audit.record("http_relay", caller=None, connection=None, target=None, action="GET",
                                  result="denied", reason=reason)
        inc_id = self.open_incident_id()
        self.assertIsNotNone(inc_id)
        inc = I.get_incident(self.ctx, inc_id)
        self.assertEqual(inc.scope, "principal")
        self.assertEqual(inc.rule, "handle_forgery_unattributed")
        self.assertEqual(sorted(inc.principals), ["agent-1", "agent-2"])  # agent-3 excluded: not active

    def test_unattributed_expired_handle_weak_points_also_trip_the_global_bucket(self) -> None:
        detector = self.install_detector(weak_threshold=3)
        self.make_principal("agent-1")
        for _ in range(3):  # expired_handle is 1 weak point by default; 3 * 1 == weak_threshold
            self.ctx.audit.record("http_relay", caller=None, connection=None, target=None, action="GET",
                                  result="denied", reason="handle_expired")
        del detector  # silence "unused" - kept for readability of the setup line above
        inc_id = self.open_incident_id()
        self.assertIsNotNone(inc_id)
        self.assertEqual(I.get_incident(self.ctx, inc_id).rule, "handle_forgery_unattributed")


# ======================================================================= weak
class WeakRuleTests(IntrusionTestCase):
    def test_weak_points_accumulate_across_rules_to_the_default_threshold(self) -> None:
        self.install_detector()
        self.make_principal("agent-1")
        # unauthorized_connection is 2 points by default; three occurrences = 6 < 8.
        for _ in range(3):
            self.ctx.audit.record("tools_request", caller="agent-1", connection="gh", action="GET",
                                  result="denied", reason="no_grant")
        self.assertIsNone(self.open_incident_id())
        # A fourth occurrence takes the total to 8 and trips.
        self.ctx.audit.record("tools_request", caller="agent-1", connection="gh", action="GET",
                              result="denied", reason="no_grant")
        inc_id = self.open_incident_id()
        self.assertIsNotNone(inc_id)
        inc = I.get_incident(self.ctx, inc_id)
        self.assertEqual(inc.scope, "principal")
        self.assertEqual(inc.rule, "unauthorized_connection")

    def test_window_expiry_drops_old_weak_signals(self) -> None:
        self.install_detector(window_seconds=60, weak_points={"unauthorized_connection": 4})
        self.make_principal("agent-1")
        for _ in range(1):  # 4 points, below the default weak_threshold (8)
            self.ctx.audit.record("tools_request", caller="agent-1", connection="gh", action="GET",
                                  result="denied", reason="no_grant")
        self.assertIsNone(self.open_incident_id())
        self.clock.advance(61)  # the first signal falls out of the 60s window
        self.ctx.audit.record("tools_request", caller="agent-1", connection="gh", action="GET",
                              result="denied", reason="no_grant")
        self.assertIsNone(self.open_incident_id(), "the expired signal must not still be counted")
        self.ctx.audit.record("tools_request", caller="agent-1", connection="gh", action="GET",
                              result="denied", reason="no_grant")
        self.assertIsNotNone(self.open_incident_id(), "two fresh signals inside the window trip it")

    def test_global_stop_and_restore_pending_denials_are_not_scored(self) -> None:
        """Regression: these two reasons are whole-system state, not caller-specific evidence --
        every active caller gets the identical denial the instant an admin acts, so scoring them
        here would make routine post-stop/-restore traffic look identical to sustained misuse
        (this is exactly what tripped tests/test_cli_e2e.py before this exclusion was added)."""
        self.install_detector()
        self.make_principal("agent-1")
        for reason in ("global_stop", "restore_pending"):
            for _ in range(5):
                self.ctx.audit.record("tools_request", caller="agent-1", connection="gh", action="GET",
                                      result="denied", reason=reason)
        self.assertIsNone(self.open_incident_id())


class EnumerationTests(IntrusionTestCase):
    def test_enumeration_triggers_only_once_distinct_use_reaches_min_and_half_of_usable(self) -> None:
        self.install_detector(weak_threshold=4, enumeration_min=4, enumeration_ratio=0.5)
        self.make_principal("agent-1")
        for i in range(10):
            self.make_connection(f"gh{i}")
            self.make_grant("agent-1", f"gh{i}")
        # usable == 10, half == 5: four distinct connections satisfy the minimum but not the ratio.
        for i in range(4):
            self.ctx.audit.record("http_relay", caller="agent-1", connection=f"gh{i}", action="GET", result="ok")
        self.assertIsNone(self.open_incident_id())
        # A fifth distinct connection satisfies both (5 >= 4 and 5 >= 10*0.5).
        self.ctx.audit.record("http_relay", caller="agent-1", connection="gh4", action="GET", result="ok")
        inc_id = self.open_incident_id()
        self.assertIsNotNone(inc_id)
        self.assertEqual(I.get_incident(self.ctx, inc_id).rule, "enumeration")

    def test_repeated_use_of_the_same_connections_is_not_enumeration(self) -> None:
        # 10 usable connections (enumeration needs >= 4 AND >= half == 5 distinct), but only ever
        # 2 of them are actually used -- repeatedly.  Distinct use never grows past 2, so heavy
        # repeat traffic must never itself look like enumeration.
        self.install_detector(weak_threshold=4, enumeration_min=4, enumeration_ratio=0.5)
        self.make_principal("agent-1")
        for i in range(10):
            self.make_connection(f"gh{i}")
            self.make_grant("agent-1", f"gh{i}")
        for _ in range(20):
            for i in range(2):
                self.ctx.audit.record("http_relay", caller="agent-1", connection=f"gh{i}", action="GET", result="ok")
        self.assertIsNone(self.open_incident_id())

    def test_using_an_old_connection_again_is_not_a_new_first_use(self) -> None:
        """H2 regression, second half: '처음 사용하는 연결' is a lifetime fact.  A connection used
        once long ago (now outside the window) and used again now must not count as a *new*
        first use just because its original first-use timestamp fell out of the window."""
        self.install_detector(window_seconds=60, weak_threshold=4, enumeration_min=4, enumeration_ratio=0.5)
        self.make_principal("agent-1")
        for i in range(10):
            self.make_connection(f"gh{i}")
            self.make_grant("agent-1", f"gh{i}")
        self.ctx.audit.record("http_relay", caller="agent-1", connection="gh0", action="GET", result="ok")
        self.clock.advance(61)   # gh0's first use is now outside the window
        for i in range(1, 4):
            self.ctx.audit.record("http_relay", caller="agent-1", connection=f"gh{i}", action="GET", result="ok")
        self.assertIsNone(self.open_incident_id(), "only 3 first-ever uses are inside the window so far")
        self.ctx.audit.record("http_relay", caller="agent-1", connection="gh0", action="GET", result="ok")
        self.assertIsNone(self.open_incident_id(),
                          "re-using gh0 is not a new first use even though its own first use aged out")

    def test_enumeration_fires_once_per_crossing_not_once_per_additional_connection(self) -> None:
        """H2 regression: with the default weak_points (enumeration=4) and weak_threshold (8), using
        5 of 8 granted connections in one window must NOT open an incident on its own -- before the
        fix, each additional distinct connection past the 4th added another 4 points by itself."""
        self.install_detector()   # every default: enumeration_min=4, ratio=0.5, weak_threshold=8
        self.make_principal("agent-1")
        for i in range(8):
            self.make_connection(f"gh{i}")
            self.make_grant("agent-1", f"gh{i}")
        for i in range(5):
            self.ctx.audit.record("http_relay", caller="agent-1", connection=f"gh{i}", action="GET", result="ok")
        self.assertIsNone(self.open_incident_id())

    def test_using_most_granted_connections_plus_heavy_status_polling_opens_nothing(self) -> None:
        """A legitimate agent may reasonably use most of what it was granted, and poll `status`
        while a long exec runs; neither alone should look like an attack (H1 + H2 regression)."""
        self.install_detector()
        self.make_principal("agent-1")
        for i in range(8):
            self.make_connection(f"gh{i}")
            self.make_grant("agent-1", f"gh{i}")
        for i in range(6):   # 6 of 8 usable: past enumeration's min/ratio, but it fires only once
            self.ctx.audit.record("http_relay", caller="agent-1", connection=f"gh{i}", action="GET", result="ok")
        for _ in range(100):  # tools_status is not a credential-using request: never counted
            self.ctx.audit.record("tools_status", caller="agent-1", run_id="run-1", action="status", result="ok")
        self.assertIsNone(self.open_incident_id())


class BurstTests(IntrusionTestCase):
    def test_burst_trips_once_the_per_caller_record_count_exceeds_the_configured_limit(self) -> None:
        self.install_detector(weak_threshold=2, burst_count=5)
        self.make_principal("agent-1")
        for _ in range(5):
            self.ctx.audit.record("tools_request", caller="agent-1", action="GET", result="ok")
        self.assertIsNone(self.open_incident_id())
        self.ctx.audit.record("tools_request", caller="agent-1", action="GET", result="ok")
        inc_id = self.open_incident_id()
        self.assertIsNotNone(inc_id)
        self.assertEqual(I.get_incident(self.ctx, inc_id).rule, "burst")

    def test_burst_fires_once_per_crossing_not_once_per_record_past_the_limit(self) -> None:
        """H1 regression: with the default burst weight (2) and weak_threshold (8), 5 records past
        a 60-count burst_count must NOT open an incident on their own -- before the fix, every
        record past the limit added another 2 points by itself (the 64th record alone tripped it)."""
        self.install_detector(burst_count=60)   # weak_threshold stays the default (8)
        self.make_principal("agent-1")
        for _ in range(65):
            self.ctx.audit.record("tools_request", caller="agent-1", action="GET", result="ok")
        self.assertIsNone(self.open_incident_id())

    def test_burst_ignores_non_credential_using_events(self) -> None:
        """tools_status polling, handle_issue, run_start/run_finish etc. must never feed burst --
        only tools_request/tools_exec/http_relay are 'credential-using requests' (H1)."""
        self.install_detector(weak_threshold=2, burst_count=5)
        self.make_principal("agent-1")
        for _ in range(50):
            self.ctx.audit.record("tools_status", caller="agent-1", run_id="run-1", action="status", result="ok")
        self.assertIsNone(self.open_incident_id())


class CombinedSignalTests(IntrusionTestCase):
    def test_enumeration_burst_and_unauthorized_connection_together_still_open_an_incident(self) -> None:
        """Each sub-signal alone stays under the weak threshold with the once-per-crossing fix;
        accumulating across *different* rules must still open an incident -- the fix for H1/H2
        must not make the detector blind to a real, multi-signal compromise."""
        self.install_detector(burst_count=4, enumeration_min=4, enumeration_ratio=0.5)
        self.make_principal("agent-1")
        for i in range(8):
            self.make_connection(f"gh{i}")
            self.make_grant("agent-1", f"gh{i}")
        for i in range(4):   # enumeration fires once: +4 points (default weak_points)
            self.ctx.audit.record("http_relay", caller="agent-1", connection=f"gh{i}", action="GET", result="ok")
        self.assertIsNone(self.open_incident_id(), "enumeration alone (4 points) must not trip an 8-point threshold")
        # The 5th credential-using record crosses burst's own threshold (+2) and is itself denied
        # for lack of a grant (unauthorized_connection, +2): 4 + 2 + 2 == the default weak_threshold.
        self.ctx.audit.record("tools_request", caller="agent-1", connection="gh-unrelated", action="GET",
                              result="denied", reason="no_grant")
        inc_id = self.open_incident_id()
        self.assertIsNotNone(inc_id, "enumeration + burst + unauthorized_connection together must open")


# =================================================================== scope
class ScopeTests(IntrusionTestCase):
    def test_two_principals_in_one_runtime_escalate_a_pure_http_trip_to_runtime_scope(self) -> None:
        self.install_detector()
        self.make_principal("agent-1", runtime="rt-a")
        self.make_principal("agent-2", runtime="rt-a")
        # agent-2 leaves one recent (non-tripping) signal in rt-a's activity window.
        self.ctx.audit.record("tools_request", caller="agent-2", connection="gh", action="GET",
                              result="denied", reason="path_not_allowed")
        with self.assertRaises(NotFound):
            tools.dispatch(self.ctx, "nope", "agent-1", {})
        with self.assertRaises(NotFound):
            tools.dispatch(self.ctx, "nope", "agent-1", {})  # trips unknown_tool (http-located) for agent-1
        inc_id = self.open_incident_id()
        self.assertIsNotNone(inc_id)
        inc = I.get_incident(self.ctx, inc_id)
        self.assertEqual(inc.scope, "runtime")
        self.assertEqual(inc.runtime, "rt-a")

    def test_a_single_principal_with_only_http_signals_stays_principal_scoped(self) -> None:
        self.install_detector()
        self.make_principal("agent-1", runtime="rt-a")
        with self.assertRaises(NotFound):
            tools.dispatch(self.ctx, "nope", "agent-1", {})
        with self.assertRaises(NotFound):
            tools.dispatch(self.ctx, "nope", "agent-1", {})
        inc = I.get_incident(self.ctx, self.open_incident_id())
        self.assertEqual(inc.scope, "principal")

    def test_widening_when_a_runtime_located_signal_follows_an_open_principal_incident(self) -> None:
        self.install_detector()
        self.make_principal("agent-1", runtime="rt-a")
        with self.assertRaises(NotFound):
            tools.dispatch(self.ctx, "nope", "agent-1", {})
        with self.assertRaises(NotFound):
            tools.dispatch(self.ctx, "nope", "agent-1", {})
        first_id = self.open_incident_id()
        self.assertEqual(I.get_incident(self.ctx, first_id).scope, "principal")

        self.ctx.audit.record("run_finish", caller="agent-1", connection="gh", action="exec",
                              result="blocked", reason="output_credential_blocked")

        self.assertEqual(self.open_incident_id(), first_id, "the same incident widens; a new one is not opened")
        widened = I.get_incident(self.ctx, first_id)
        self.assertEqual(widened.scope, "runtime")
        self.assertEqual(widened.runtime, "rt-a")
        self.assertEqual(len(widened.widened_from), 1)
        self.assertEqual(widened.widened_from[0]["scope"], "principal")
        # Never narrows: a further http-only signal for the same caller changes nothing.
        with self.assertRaises(NotFound):
            tools.dispatch(self.ctx, "nope", "agent-1", {})
        self.assertEqual(I.get_incident(self.ctx, first_id).scope, "runtime")


# ============================================================== no false trip
class NoFalseTripTests(IntrusionTestCase):
    def test_normal_list_two_requests_one_exec_opens_nothing(self) -> None:
        """The tests/test_cli_e2e.py-style happy path: list, two successful requests, one exec."""
        self.install_detector()
        self.make_principal("agent-1")
        self.make_connection("gh")
        self.make_grant("agent-1", "gh")
        self.ctx.audit.record("tools_list_connections", caller="agent-1", action="list", result="ok",
                              extra={"count": 1})
        self.ctx.audit.record("tools_request", caller="agent-1", connection="gh", action="GET", result="ok",
                              extra={"method": "GET", "path": "/repos", "bytes": 0})
        self.ctx.audit.record("tools_request", caller="agent-1", connection="gh", action="POST", result="ok",
                              extra={"method": "POST", "path": "/repos/x/issues", "bytes": 12})
        self.ctx.audit.record("tools_exec", caller="agent-1", connection="gh", target="http://127.0.0.1:1",
                              action="exec", result="ok", extra={"program": "whoami"})
        self.assertIsNone(self.open_incident_id())


# ============================================================ synchronous
class SynchronousLockdownTests(IntrusionTestCase):
    def test_the_very_next_call_after_the_tripping_record_is_already_refused(self) -> None:
        self.install_detector()
        self.make_principal("agent-1")
        self.make_connection("gh")
        self.make_grant("agent-1", "gh")
        with self.assertRaises(NotFound):
            tools.dispatch(self.ctx, "nope", "agent-1", {})
        with self.assertRaises(NotFound):
            tools.dispatch(self.ctx, "nope", "agent-1", {})  # trips synchronously inside this call
        result = tools.request(self.ctx, "agent-1", "gh", "GET", "/", {})
        self.assertEqual(result["reason"], "principal_disabled")


# =============================================================== re-entrancy
class ReentrancyTests(IntrusionTestCase):
    def test_open_triggered_inside_record_completes_without_recursion_or_deadlock(self) -> None:
        self.install_detector()
        token1 = self.make_principal("agent-1")
        program = self.sleeper()
        self.make_connection("gh", program=program)
        g1 = self.make_grant("agent-1", "gh")

        ready = self.root / "ready"
        run = self.start_run("agent-1", "gh", 30, ready)
        self.wait_for(ready.exists, "run never started")

        start = time.monotonic()
        with self.assertRaises(NotFound):
            tools.dispatch(self.ctx, "nope", "agent-1", {})
        with self.assertRaises(NotFound):
            tools.dispatch(self.ctx, "nope", "agent-1", {})   # trips: open_incident cancels the run above
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 15.0, "lockdown must not hang even though it cancels a running exec")

        self.assertIsNotNone(self.open_incident_id())
        run.done.wait(10)
        self.assertEqual(run.state, "cancelled")
        with self.assertRaises(Exception):
            self.ctx.policy.authenticate(token1)
        self.assertEqual(self.ctx.policy.get_grant(g1.id).status, "revoked")


# =============================================================== concurrency
class ConcurrencyTests(IntrusionTestCase):
    def test_two_threads_tripping_at_once_produce_exactly_one_incident(self) -> None:
        self.install_detector()
        self.make_principal("agent-1")
        # Pre-seed one occurrence (below the 2-threshold), so each of the two threads below
        # only needs to add one more to cross it -- both will see the trip condition.
        with self.assertRaises(NotFound):
            tools.dispatch(self.ctx, "nope", "agent-1", {})
        self.assertIsNone(self.open_incident_id())

        barrier = threading.Barrier(2)

        def fire() -> None:
            barrier.wait(timeout=5)
            try:
                tools.dispatch(self.ctx, "nope", "agent-1", {})
            except NotFound:
                pass

        threads = [threading.Thread(target=fire) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)
            self.assertFalse(t.is_alive())

        incidents = I.list_incidents(self.ctx)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].principals, ["agent-1"])


# ============================================================ decision errors
class DecisionErrorTests(IntrusionTestCase):
    def test_a_failing_open_incident_is_counted_not_raised(self) -> None:
        detector = self.install_detector()
        self.make_principal("agent-1")
        with patch.object(intrusion.I, "open_incident", side_effect=RuntimeError("boom")):
            with self.assertRaises(NotFound):
                tools.dispatch(self.ctx, "nope", "agent-1", {})
            with self.assertRaises(NotFound):
                # Trips the strong rule; open_incident raises inside _apply_decision, which must
                # not propagate out through on_record (called synchronously from Audit.record).
                tools.dispatch(self.ctx, "nope", "agent-1", {})
        self.assertEqual(detector.decision_errors, 1)
        self.assertIsNone(self.open_incident_id(), "the failed decision must not have left anything open")

        # Without the patch, the very next crossing still opens an incident normally --
        # a decision failure must not leave the caller's state permanently un-actionable.
        with self.assertRaises(NotFound):
            tools.dispatch(self.ctx, "nope", "agent-1", {})
        self.assertIsNotNone(self.open_incident_id())


# =================================================================== config
class ConfigTests(unittest.TestCase):
    def test_config_overrides_change_when_a_rule_trips(self) -> None:
        tmp_case = IntrusionTestCase()
        tmp_case.setUp()
        try:
            tmp_case.install_detector(weak_threshold=2, weak_points={"scope_violation": 2})
            tmp_case.make_principal("agent-1")
            tmp_case.ctx.audit.record("tools_request", caller="agent-1", connection="gh", action="GET",
                                      result="denied", reason="path_not_allowed")
            self.assertIsNotNone(tmp_case.ctx.policy.open_incident_id())
        finally:
            tmp_case.tearDown()

    def test_from_mapping_merges_overrides_onto_defaults(self) -> None:
        cfg = intrusion.DetectorConfig.from_mapping({"weak_threshold": 5, "strong_thresholds": {"unknown_tool": 3}})
        self.assertEqual(cfg.weak_threshold, 5)
        self.assertEqual(cfg.strong_thresholds["unknown_tool"], 3)
        self.assertEqual(cfg.strong_thresholds["signer_misuse"], 1)  # untouched default preserved

    def test_context_config_intrusion_dict_flows_into_the_installed_detector(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            ctx = Context.initialize(Path(tmp) / "state", ADMIN, RECOVERY,
                                     Config(intrusion={"weak_threshold": 3}), FakeClock())
            detector = intrusion.install(ctx)
            self.assertEqual(detector.config.weak_threshold, 3)
            ctx.close()

    def test_install_is_idempotent(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            ctx = Context.initialize(Path(tmp) / "state", ADMIN, RECOVERY, Config(), FakeClock())
            first = intrusion.install(ctx)
            second = intrusion.install(ctx)
            self.assertIs(first, second)
            self.assertIs(ctx.intrusion, first)
            ctx.close()

    def test_strong_threshold_must_be_a_positive_int_and_cannot_disable_a_rule(self) -> None:
        for bad in (0, -1, None, 1.5, True, "2"):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidInput) as caught:
                    intrusion.DetectorConfig(strong_thresholds={"unknown_tool": bad})
                self.assertEqual(caught.exception.reason, "intrusion_strong_threshold_invalid")
        # An omitted rule still validates against its (unmodified) default.
        cfg = intrusion.DetectorConfig(strong_thresholds={"handle_forgery": 5})
        self.assertEqual(cfg.strong_thresholds["unknown_tool"], 2)

    def test_weak_threshold_and_window_are_validated_too(self) -> None:
        with self.assertRaises(InvalidInput):
            intrusion.DetectorConfig(weak_threshold=0)
        with self.assertRaises(InvalidInput):
            intrusion.DetectorConfig(window_seconds=0)
        with self.assertRaises(InvalidInput):
            intrusion.DetectorConfig(enumeration_ratio=0)
        with self.assertRaises(InvalidInput):
            intrusion.DetectorConfig(burst_count=-5)


# =========================================================== serve wiring
class ServeIntegrationTests(AdminCliTestCase):
    """``run_serve`` must install the detector (the admin CLI's other commands do not)."""

    def test_serve_installs_the_detector_and_locks_down_on_unknown_tool(self) -> None:
        self.seed_project()
        self.ok("principal", "create", "--id", "agent-1")

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

        from unittest.mock import patch

        stop = threading.Event()
        emit_patch = patch.object(admin_cli, "_emit", emit)
        emit_patch.start()
        self.addCleanup(emit_patch.stop)
        with patch.object(admin_cli, "Context", CapturingContext):
            serve = threading.Thread(target=admin_cli.run_serve, args=(self.state, "127.0.0.1:0"),
                                     kwargs={"quiet": True, "stop_event": stop, "install_signals": False},
                                     daemon=True)
            serve.start()
            self.addCleanup(serve.join, 30)
            self.addCleanup(stop.set)
            deadline = time.monotonic() + 30
            while not startup and time.monotonic() < deadline:
                time.sleep(0.05)
        self.assertTrue(startup, "serve did not start")
        serve_ctx = captured[0]
        self.assertIsInstance(serve_ctx.intrusion, intrusion.Detector)

        with self.assertRaises(NotFound):
            tools.dispatch(serve_ctx, "nope", "agent-1", {})
        with self.assertRaises(NotFound):
            tools.dispatch(serve_ctx, "nope", "agent-1", {})

        self.assertIsNotNone(serve_ctx.policy.open_incident_id())
        self.assertEqual(serve_ctx.policy.get_principal("agent-1").status, "disabled")

        stop.set()
        serve.join(30)
        self.assertFalse(serve.is_alive())


if __name__ == "__main__":
    unittest.main()
