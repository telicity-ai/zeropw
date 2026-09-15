"""Automatic intrusion detection: docs/compromise-response.md §4.1, §4.2, §4.3 (stage 3).

``Detector`` subscribes to ``Audit`` (``Audit.subscribe``, stage 3's other half) and watches
every record synchronously, right after it is durable.  It never reads a vault value, a handle,
a request id, or free text -- only the whitelisted, value-free fields ``event``/``result``/
``reason``/``caller``/``connection`` that the audit log already carries, so it is safe input by
construction (docs/compromise-response.md §4.1's own reasoning).

Rule table (§4.2), implemented in ``_match_denial_rule`` plus the enumeration/burst checks:

* **Strong** signals stand alone: reaching their (small, non-disableable) threshold opens an
  incident by itself.  ``unknown_tool``, ``handle_forgery``, ``signer_misuse``,
  ``output_exfiltration``.
* **Weak** signals accumulate points per caller in a sliding window; reaching the weak threshold
  (default 8) opens an incident.  ``revoked_use``, ``scope_violation``, ``expired_handle``,
  ``unauthorized_connection``, ``enumeration``, ``burst``.
* Records with no caller (a forged, malformed or expired handle: ``handle_forgery`` /
  ``expired_handle`` with ``caller`` unset -- see ``zeropw.gateway._refuse_unauthenticated``, the
  only site that writes these) cannot be pinned on one principal, so they accumulate in a single
  *global* bucket instead of a per-caller one.  Tripping that bucket opens scope ``principal``
  over every *active* principal (rule ``handle_forgery_unattributed``) -- never scope ``all``,
  which stage 1 reserves for a manual, re-authenticated trusted-host declaration.

Scope (§4.3): a per-caller trip looks at every rule that fired for that caller inside the current
window.  Any ``runtime``-located rule (``signer_misuse``, ``output_exfiltration``: both need
runtime-level access, not just the HTTP path) escalates to scope ``runtime`` for that caller's
own ``Principal.runtime``.  Otherwise, if a second principal in the *same* runtime also has a
signal in the window, it still escalates to ``runtime`` (two callers from one runtime is itself a
runtime-level signal).  Otherwise scope stays ``principal``.  The actual containment/widening
logic (never narrowing, absorbing a same-or-narrower signal into an already-open incident) is
``zeropw.incident.open_incident``'s own job -- the detector always calls ``open_incident`` (never
``widen_incident`` directly) and lets it decide whether to open, widen, or leave an existing
incident alone.

Concurrency (the reason for the two-lock, thread-local design below): ``Audit.record`` runs on
every request-handling thread, so ``on_record`` must be cheap, safe to call from many threads at
once, and safe to call *reentrantly* on the same thread -- ``open_incident`` itself audits
(``incident_open``), disables principals, revokes grants and cancels runs/sockets, and each of
those can write further audit records (notably ``run_cancel``) on the very same call stack,
re-entering ``on_record`` before the outer call returns.

* ``_lock`` (plain, non-reentrant) guards only the bookkeeping dictionaries and is never held
  while calling into ``open_incident``.
* A thread-local ``in_lockdown`` flag recognises that reentry: while set, ``on_record`` still
  accumulates (so a nested signal is not silently dropped) but never tries to decide or open
  anything -- the outer call's decision already covers the window as of the tripping record.
* ``_lockdown_lock`` (plain, acquired non-blocking) serialises the *decision* step across
  threads: two callers tripping at the same instant both accumulate under ``_lock``, but only
  the one that wins ``_lockdown_lock`` calls ``open_incident``; the other simply returns (its
  state is already accumulated, and ``open_incident`` is idempotent for an equal-or-narrower
  request, so nothing is lost).
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque

from . import incident as I
from .errors import InvalidInput

# ------------------------------------------------------------------- rules
STRONG_RULES = ("unknown_tool", "handle_forgery", "signer_misuse", "output_exfiltration")
WEAK_RULES = ("revoked_use", "scope_violation", "expired_handle", "unauthorized_connection",
             "enumeration", "burst")

DEFAULT_STRONG_THRESHOLDS: dict[str, int] = {
    "unknown_tool": 2, "handle_forgery": 2, "signer_misuse": 1, "output_exfiltration": 1,
}
DEFAULT_WEAK_POINTS: dict[str, int] = {
    "revoked_use": 3, "scope_violation": 1, "expired_handle": 1, "unauthorized_connection": 2,
    "enumeration": 4, "burst": 2,
}
# Where a rule can only fire from (§4.3): "runtime" needs runtime-level access (the signer
# socket, or the exec child's own output); everything else is reachable over the HTTP/tools path.
RULE_LOCATION: dict[str, str] = {
    "unknown_tool": "http", "handle_forgery": "http", "signer_misuse": "runtime",
    "output_exfiltration": "runtime", "revoked_use": "http", "scope_violation": "http",
    "expired_handle": "http", "unauthorized_connection": "http", "enumeration": "http", "burst": "http",
}
UNATTRIBUTED_RULE = "handle_forgery_unattributed"

# "global_stop" / "restore_pending" are deliberately excluded from this set even though they
# share the existing "revoked_use_attempt" alert's reason list (zeropw.audit._maybe_alert):
# both are whole-system states an admin sets once, and from that instant EVERY active caller's
# next request gets the identical denial regardless of which (if any) caller is compromised --
# so they carry no discriminative per-caller evidence, only a self-inflicted flood of "signal"
# for every legitimate caller that simply notices the stop.  Scoring them here would make a
# routine admin `stop-all` (or a restore) followed by ordinary callers finding out about it a
# reliable way to trip a weak-threshold incident with zero attacker behaviour involved -- exactly
# the false-positive shape docs/compromise-response.md §4.2 says a *rare* weak signal should not
# have.  "grant_revoked" / "grant_stale" / "principal_disabled" stay: each names one specific
# caller's specific permission, so repeated use after one of *those* is real per-caller evidence.
_REVOKED_REASONS = frozenset({"grant_revoked", "grant_stale", "principal_disabled"})
_SCOPE_REASONS = frozenset({"method_not_allowed", "path_not_allowed", "approval_required"})
_UNAUTHORIZED_REASONS = frozenset({"no_grant", "grant_unknown", "connection_unknown"})
_HANDLE_FORGERY_REASONS = frozenset({"handle_signature", "handle_malformed", "handle_version"})
_AGENT_REFUSED_REASONS = frozenset({"unsupported_agent_message", "unsupported_extension"})
_SIGN_REFUSED_REASONS = frozenset({"not_userauth_request", "no_session_bind", "unsupported_sign_flags"})


def _match_denial_rule(event: Any, result: Any, reason: Any) -> tuple[str | None, str | None]:
    """(rule_id, kind) for one audit record, or ``(None, None)`` if no rule matches.

    ``output_exfiltration`` is the one row whose own result is ``blocked`` (``zeropw.runs``'
    ``RESULT_BY_STATE[BLOCKED] == "blocked"``), not ``denied`` -- every other row is a plain
    denial, checked below the single ``result == "denied"`` gate.
    """
    if event == "run_finish" and result == "blocked" and reason == "output_credential_blocked":
        return "output_exfiltration", "strong"
    if result != "denied":
        return None, None
    if event == "tools_unknown":
        return "unknown_tool", "strong"
    if event == "http_relay" and reason in _HANDLE_FORGERY_REASONS:
        return "handle_forgery", "strong"
    if event == "http_relay" and reason == "handle_expired":
        return "expired_handle", "weak"
    if event == "ssh_agent_refused" and reason in _AGENT_REFUSED_REASONS:
        return "signer_misuse", "strong"
    if event == "ssh_bind" and reason == "agent_forwarding_not_allowed":
        return "signer_misuse", "strong"
    if event == "ssh_sign" and reason in _SIGN_REFUSED_REASONS:
        return "signer_misuse", "strong"
    if reason in _REVOKED_REASONS:
        return "revoked_use", "weak"
    if event in ("http_relay", "tools_request", "tools_exec") and reason in _SCOPE_REASONS:
        return "scope_violation", "weak"
    if event in ("tools_request", "tools_exec") and reason in _UNAUTHORIZED_REASONS:
        return "unauthorized_connection", "weak"
    return None, None


# ------------------------------------------------------------------ config
def _validate_strong_thresholds(overrides: dict[str, Any] | None) -> dict[str, int]:
    merged = dict(DEFAULT_STRONG_THRESHOLDS)
    merged.update(overrides or {})
    for rule_id in DEFAULT_STRONG_THRESHOLDS:
        value = merged.get(rule_id)
        # bool is an int subclass; excluded explicitly so `True` cannot pass as 1 by accident.
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise InvalidInput("intrusion_strong_threshold_invalid")
    return merged


def _validate_weak_points(overrides: dict[str, Any] | None) -> dict[str, int]:
    merged = dict(DEFAULT_WEAK_POINTS)
    merged.update(overrides or {})
    for rule_id in DEFAULT_WEAK_POINTS:
        value = merged.get(rule_id)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise InvalidInput("intrusion_weak_points_invalid")
    return merged


@dataclass
class DetectorConfig:
    """§4.2 thresholds.  Every strong threshold is validated to be a positive integer: there is
    no configuration that disables a strong rule (docs/compromise-response.md §4.2's own
    "강한 신호를 끄는 설정은 두지 않는다")."""

    window_seconds: float = 120.0
    weak_threshold: int = 8
    enumeration_min: int = 4
    enumeration_ratio: float = 0.5
    burst_count: int = 60
    weak_points: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_WEAK_POINTS))
    strong_thresholds: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_STRONG_THRESHOLDS))

    def __post_init__(self) -> None:
        self.strong_thresholds = _validate_strong_thresholds(self.strong_thresholds)
        self.weak_points = _validate_weak_points(self.weak_points)
        if not isinstance(self.window_seconds, (int, float)) or isinstance(self.window_seconds, bool) \
                or self.window_seconds <= 0:
            raise InvalidInput("intrusion_window_invalid")
        if isinstance(self.weak_threshold, bool) or not isinstance(self.weak_threshold, int) \
                or self.weak_threshold < 1:
            raise InvalidInput("intrusion_weak_threshold_invalid")
        if isinstance(self.enumeration_min, bool) or not isinstance(self.enumeration_min, int) \
                or self.enumeration_min < 1:
            raise InvalidInput("intrusion_enumeration_min_invalid")
        if not isinstance(self.enumeration_ratio, (int, float)) or isinstance(self.enumeration_ratio, bool) \
                or not (0 < self.enumeration_ratio <= 1):
            raise InvalidInput("intrusion_enumeration_ratio_invalid")
        if isinstance(self.burst_count, bool) or not isinstance(self.burst_count, int) or self.burst_count < 1:
            raise InvalidInput("intrusion_burst_count_invalid")

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> "DetectorConfig":
        data = dict(data or {})
        kwargs: dict[str, Any] = {}
        for key in ("window_seconds", "weak_threshold", "enumeration_min", "enumeration_ratio", "burst_count"):
            if key in data:
                kwargs[key] = data[key]
        if isinstance(data.get("weak_points"), dict):
            kwargs["weak_points"] = data["weak_points"]
        if isinstance(data.get("strong_thresholds"), dict):
            kwargs["strong_thresholds"] = data["strong_thresholds"]
        return cls(**kwargs)


# -------------------------------------------------------------------- state
@dataclass
class _CallerState:
    strong: dict[str, Deque[float]] = field(default_factory=dict)
    weak_events: Deque[tuple[float, str, int]] = field(default_factory=deque)
    # Connection id -> this caller's first-ever use of it (never pruned: "처음 사용하는 연결" is a
    # lifetime fact, not a windowed one -- a connection used long ago and used again now is not a
    # *new* one just because the earlier use fell out of the window).  Enumeration counts how many
    # of these first-ever-use timestamps currently fall inside the window.
    first_used: dict[str, float] = field(default_factory=dict)
    enumeration_armed: bool = True   # latch: cleared on the firing record, reset once back under threshold
    all_records: Deque[float] = field(default_factory=deque)
    burst_armed: bool = True         # latch: same shape as enumeration_armed, for the burst rule
    fired_rules: Deque[tuple[float, str]] = field(default_factory=deque)


@dataclass
class _GlobalState:
    strong: dict[str, Deque[float]] = field(default_factory=dict)
    weak_events: Deque[tuple[float, str, int]] = field(default_factory=deque)


@dataclass
class _Trip:
    rule: str
    detail: str
    unattributed: bool = False
    scope: str = "principal"
    runtime: str | None = None
    principal: str | None = None


# ----------------------------------------------------------------- detector
class Detector:
    def __init__(self, ctx: Any, config: DetectorConfig | None = None) -> None:
        self.ctx = ctx
        self.config = config or DetectorConfig()
        self._lock = threading.Lock()
        self._lockdown_lock = threading.Lock()
        self._local = threading.local()
        self._callers: dict[str, _CallerState] = {}
        self._runtime_activity: dict[str, dict[str, float]] = {}
        self._global = _GlobalState()
        # Counts a decision-step failure (e.g. the tripping principal vanished between
        # accumulation and decision) so tests/diagnostics can observe it -- the failure itself is
        # still swallowed (Audit.subscribe already would, but decide-time errors are expected and
        # must never surface as an audit-pipeline crash either).
        self.decision_errors = 0

    # -------------------------------------------------------------- prune
    def _prune_ts(self, dq: Deque[float], now: float) -> None:
        window = self.config.window_seconds
        while dq and now - dq[0] > window:
            dq.popleft()

    def _prune_tagged(self, dq: Deque[tuple], now: float) -> None:
        window = self.config.window_seconds
        while dq and now - dq[0][0] > window:
            dq.popleft()

    # -------------------------------------------------------------- entry
    def on_record(self, record: dict[str, Any]) -> None:
        event = record.get("event")
        if not isinstance(event, str) or event.startswith("incident_"):
            return  # never feed on the detector's own containment (or notification) records
        reentered = bool(getattr(self._local, "in_lockdown", False))
        now = self.ctx.clock()
        with self._lock:
            trip = self._accumulate(record, now)
        if trip is None or reentered:
            return
        if not self._lockdown_lock.acquire(blocking=False):
            return  # another thread is deciding right now; state is accumulated, next record retries
        try:
            self._local.in_lockdown = True
            self._apply_decision(trip)
        finally:
            self._local.in_lockdown = False
            self._lockdown_lock.release()

    # --------------------------------------------------------- bookkeeping
    def _accumulate(self, record: dict[str, Any], now: float) -> _Trip | None:
        caller_raw = record.get("caller")
        caller = caller_raw if isinstance(caller_raw, str) and caller_raw else None
        event = record.get("event")
        result = record.get("result")
        reason = record.get("reason")

        trip: _Trip | None = None

        # Both enumeration and burst are about *credential-using* requests -- tools_request,
        # tools_exec, http_relay -- not every audited event.  A caller polling tools_status while
        # its own exec runs, or a run_start/run_finish pair, carries no new use-of-a-connection
        # signal and must not feed either rule (a polling loop must not look like a burst).
        if caller is not None and event in ("tools_request", "tools_exec", "http_relay"):
            if result == "ok":
                candidate = self._record_enumeration(caller, record.get("connection"), now)
                if candidate is not None:
                    trip = candidate
            candidate = self._record_burst(caller, now)
            if candidate is not None:
                trip = candidate

        rule_id, kind = _match_denial_rule(event, result, reason)
        if rule_id is not None:
            if caller is not None:
                candidate = (self._add_caller_strong(caller, rule_id, now) if kind == "strong"
                            else self._add_caller_weak(caller, rule_id, now))
            else:
                candidate = (self._add_global_strong(rule_id, now) if kind == "strong"
                            else self._add_global_weak(rule_id, now))
            if candidate is not None:
                trip = candidate
        return trip

    def _caller_state(self, caller: str) -> _CallerState:
        state = self._callers.get(caller)
        if state is None:
            state = _CallerState()
            self._callers[caller] = state
        return state

    def _touch_runtime_activity(self, caller: str, now: float) -> None:
        try:
            runtime = self.ctx.policy.get_principal(caller).runtime
        except Exception:
            return
        bucket = self._runtime_activity.setdefault(runtime, {})
        bucket[caller] = now

    def _siblings_in_runtime(self, runtime: str, now: float) -> set[str]:
        bucket = self._runtime_activity.get(runtime, {})
        stale = [c for c, ts in bucket.items() if now - ts > self.config.window_seconds]
        for c in stale:
            del bucket[c]
        return set(bucket.keys())

    def _record_enumeration(self, caller: str, connection: Any, now: float) -> _Trip | None:
        """§4.2 "열거": the count of connections this caller has ever used *for the first time*
        whose first use falls inside the current window.  Recording ``first_used`` permanently
        (never pruned) is what makes re-using an already-established connection a non-event --
        only a genuinely new connection can ever add to the windowed count.

        Fires (contributes weak points) once per crossing into the tripping condition, not once
        per record while the condition holds: without the ``enumeration_armed`` latch, every
        further new connection after the 4th/5th/... would each add another 4 points on its own,
        turning "used more of your own granted connections than usual" into an automatic incident
        by itself.  The latch re-arms once the windowed distinct count falls back under threshold
        (checked lazily, on this caller's next qualifying record).
        """
        if not isinstance(connection, str) or not connection:
            return None
        state = self._caller_state(caller)
        if connection not in state.first_used:
            state.first_used[connection] = now
        window = self.config.window_seconds
        distinct = sum(1 for ts in state.first_used.values() if now - ts <= window)
        try:
            usable = len(self.ctx.policy.usable_connections(caller))
        except Exception:
            usable = 0
        over = usable > 0 and distinct >= self.config.enumeration_min \
            and distinct >= usable * self.config.enumeration_ratio
        if not over:
            state.enumeration_armed = True
            return None
        if not state.enumeration_armed:
            return None
        state.enumeration_armed = False
        return self._add_caller_weak(caller, "enumeration", now)

    def _record_burst(self, caller: str, now: float) -> _Trip | None:
        """§4.2 "속도 급증": one signal per crossing of ``burst_count`` records in the window, not
        a point added for every record past it -- otherwise the 64th, 65th, 66th... record of a
        caller that is simply busy would each tax another 2 points on their own, turning volume
        alone into an incident.  Re-arms once the windowed count falls back to/under the limit."""
        state = self._caller_state(caller)
        self._prune_ts(state.all_records, now)
        state.all_records.append(now)
        over = len(state.all_records) > self.config.burst_count
        if not over:
            state.burst_armed = True
            return None
        if not state.burst_armed:
            return None
        state.burst_armed = False
        return self._add_caller_weak(caller, "burst", now)

    def _add_caller_strong(self, caller: str, rule_id: str, now: float) -> _Trip | None:
        state = self._caller_state(caller)
        dq = state.strong.setdefault(rule_id, deque())
        dq.append(now)
        self._prune_ts(dq, now)
        state.fired_rules.append((now, rule_id))
        self._prune_tagged(state.fired_rules, now)
        self._touch_runtime_activity(caller, now)
        threshold = self.config.strong_thresholds.get(rule_id, 1)
        if len(dq) < threshold:
            return None
        return self._build_trip(caller, rule_id, len(dq), now)

    def _add_caller_weak(self, caller: str, rule_id: str, now: float) -> _Trip | None:
        state = self._caller_state(caller)
        points = self.config.weak_points.get(rule_id, 0)
        state.weak_events.append((now, rule_id, points))
        self._prune_tagged(state.weak_events, now)
        state.fired_rules.append((now, rule_id))
        self._prune_tagged(state.fired_rules, now)
        self._touch_runtime_activity(caller, now)
        total = sum(p for _, _, p in state.weak_events)
        if total < self.config.weak_threshold:
            return None
        return self._build_trip(caller, rule_id, total, now)

    def _build_trip(self, caller: str, rule_id: str, count: int, now: float) -> _Trip:
        state = self._caller_state(caller)
        self._prune_tagged(state.fired_rules, now)
        fired = {r for _, r in state.fired_rules}
        runtime_located = any(RULE_LOCATION.get(r) == "runtime" for r in fired)

        principal_runtime: str | None = None
        try:
            principal_runtime = self.ctx.policy.get_principal(caller).runtime
        except Exception:
            principal_runtime = None

        scope, runtime = "principal", None
        if principal_runtime is not None:
            if runtime_located:
                scope, runtime = "runtime", principal_runtime
            elif len(self._siblings_in_runtime(principal_runtime, now)) >= 2:
                scope, runtime = "runtime", principal_runtime

        detail = f"rule={rule_id} signals={count} rules_in_window={len(fired)}"
        return _Trip(rule=rule_id, detail=detail, scope=scope, runtime=runtime, principal=caller)

    # ------------------------------------------------------------- global
    def _add_global_strong(self, rule_id: str, now: float) -> _Trip | None:
        dq = self._global.strong.setdefault(rule_id, deque())
        dq.append(now)
        self._prune_ts(dq, now)
        threshold = self.config.strong_thresholds.get(rule_id, 1)
        if len(dq) < threshold:
            return None
        return _Trip(rule=UNATTRIBUTED_RULE, detail=f"unattributed rule={rule_id} signals={len(dq)}",
                    unattributed=True)

    def _add_global_weak(self, rule_id: str, now: float) -> _Trip | None:
        points = self.config.weak_points.get(rule_id, 0)
        self._global.weak_events.append((now, rule_id, points))
        self._prune_tagged(self._global.weak_events, now)
        total = sum(p for _, _, p in self._global.weak_events)
        if total < self.config.weak_threshold:
            return None
        return _Trip(rule=UNATTRIBUTED_RULE, detail=f"unattributed rule={rule_id} points={total}",
                    unattributed=True)

    # ------------------------------------------------------------ decide
    def _apply_decision(self, trip: _Trip) -> None:
        try:
            if trip.unattributed:
                active = [p.id for p in self.ctx.policy.list_principals() if p.status == "active"]
                if not active:
                    return
                I.open_incident(self.ctx, scope="principal", principals=active, trigger="auto",
                                rule=trip.rule, detail=trip.detail)
            elif trip.scope == "runtime":
                I.open_incident(self.ctx, scope="runtime", runtime=trip.runtime, trigger="auto",
                                rule=trip.rule, detail=trip.detail)
            else:
                I.open_incident(self.ctx, scope="principal", principals=[trip.principal], trigger="auto",
                                rule=trip.rule, detail=trip.detail)
        except Exception:
            # Detection must never take the audit pipeline down; Audit.subscribe already
            # swallows listener exceptions, but a decision failure here is expected to be
            # rare (e.g. the tripping principal vanished between accumulation and decision)
            # and is not worth surfacing as a crash.  Counted, not raised, so a test or an
            # operator can still see that a decision was lost.
            self.decision_errors += 1


# -------------------------------------------------------------------- install
def install(ctx: Any, config: DetectorConfig | None = None) -> Detector:
    """Attach a ``Detector`` to ``ctx.audit`` and store it on ``ctx.intrusion``.  Idempotent."""
    existing = getattr(ctx, "intrusion", None)
    if isinstance(existing, Detector):
        return existing
    resolved = config if config is not None else DetectorConfig.from_mapping(getattr(ctx.config, "intrusion", None))
    detector = Detector(ctx, resolved)
    ctx.audit.subscribe(detector.on_record)
    ctx.intrusion = detector
    return detector
