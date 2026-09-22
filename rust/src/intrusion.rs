//! Audit-stream intrusion detector, port of `zeropw/intrusion.py`.
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicU64, Ordering},
};

use crate::context::Context;
use crate::errors::{Error, Result};
use crate::incident;
use serde_json::{Map, Value};

pub const STRONG_RULES: &[&str] = &[
    "unknown_tool",
    "handle_forgery",
    "signer_misuse",
    "output_exfiltration",
];
pub const WEAK_RULES: &[&str] = &[
    "revoked_use",
    "scope_violation",
    "expired_handle",
    "unauthorized_connection",
    "enumeration",
    "burst",
];
pub const UNATTRIBUTED_RULE: &str = "handle_forgery_unattributed";
fn strong_defaults() -> HashMap<String, i64> {
    [
        ("unknown_tool", 2),
        ("handle_forgery", 2),
        ("signer_misuse", 1),
        ("output_exfiltration", 1),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v))
    .collect()
}
fn weak_defaults() -> HashMap<String, i64> {
    [
        ("revoked_use", 3),
        ("scope_violation", 1),
        ("expired_handle", 1),
        ("unauthorized_connection", 2),
        ("enumeration", 4),
        ("burst", 2),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v))
    .collect()
}

pub fn match_denial_rule(
    event: Option<&str>,
    result: Option<&str>,
    reason: Option<&str>,
) -> Option<(&'static str, &'static str)> {
    if event == Some("run_finish")
        && result == Some("blocked")
        && reason == Some("output_credential_blocked")
    {
        return Some(("output_exfiltration", "strong"));
    }
    if result != Some("denied") {
        return None;
    }
    if event == Some("tools_unknown") {
        return Some(("unknown_tool", "strong"));
    }
    if event == Some("http_relay")
        && ["handle_signature", "handle_malformed", "handle_version"]
            .iter()
            .any(|r| Some(*r) == reason)
    {
        return Some(("handle_forgery", "strong"));
    }
    if event == Some("http_relay") && reason == Some("handle_expired") {
        return Some(("expired_handle", "weak"));
    }
    if event == Some("ssh_agent_refused")
        && ["unsupported_agent_message", "unsupported_extension"]
            .iter()
            .any(|r| Some(*r) == reason)
    {
        return Some(("signer_misuse", "strong"));
    }
    if event == Some("ssh_bind") && reason == Some("agent_forwarding_not_allowed") {
        return Some(("signer_misuse", "strong"));
    }
    if event == Some("ssh_sign")
        && [
            "not_userauth_request",
            "no_session_bind",
            "unsupported_sign_flags",
        ]
        .iter()
        .any(|r| Some(*r) == reason)
    {
        return Some(("signer_misuse", "strong"));
    }
    if ["grant_revoked", "grant_stale", "principal_disabled"]
        .iter()
        .any(|r| Some(*r) == reason)
    {
        return Some(("revoked_use", "weak"));
    }
    if ["http_relay", "tools_request", "tools_exec"]
        .iter()
        .any(|e| Some(*e) == event)
        && [
            "method_not_allowed",
            "path_not_allowed",
            "approval_required",
        ]
        .iter()
        .any(|r| Some(*r) == reason)
    {
        return Some(("scope_violation", "weak"));
    }
    if ["tools_request", "tools_exec"]
        .iter()
        .any(|e| Some(*e) == event)
        && ["no_grant", "grant_unknown", "connection_unknown"]
            .iter()
            .any(|r| Some(*r) == reason)
    {
        return Some(("unauthorized_connection", "weak"));
    }
    None
}

#[derive(Clone, Debug, PartialEq)]
pub struct DetectorConfig {
    pub window_seconds: f64,
    pub weak_threshold: i64,
    pub enumeration_min: i64,
    pub enumeration_ratio: f64,
    pub burst_count: i64,
    pub weak_points: HashMap<String, i64>,
    pub strong_thresholds: HashMap<String, i64>,
}
impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            window_seconds: 120.0,
            weak_threshold: 8,
            enumeration_min: 4,
            enumeration_ratio: 0.5,
            burst_count: 60,
            weak_points: weak_defaults(),
            strong_thresholds: strong_defaults(),
        }
    }
}
impl DetectorConfig {
    pub fn from_mapping(data: Option<&Value>) -> Result<Self> {
        let mut c = Self::default();
        let Some(o) = data.and_then(Value::as_object) else {
            return Ok(c);
        };
        for (key, out) in [
            ("window_seconds", &mut c.window_seconds),
            ("enumeration_ratio", &mut c.enumeration_ratio),
        ] {
            if let Some(v) = o.get(key) {
                *out = v.as_f64().ok_or_else(|| {
                    Error::invalid_input(if key == "window_seconds" {
                        "intrusion_window_invalid"
                    } else {
                        "intrusion_enumeration_ratio_invalid"
                    })
                })?;
            }
        }
        for (key, out) in [
            ("weak_threshold", &mut c.weak_threshold),
            ("enumeration_min", &mut c.enumeration_min),
            ("burst_count", &mut c.burst_count),
        ] {
            if let Some(v) = o.get(key) {
                *out = v.as_i64().ok_or_else(|| {
                    Error::invalid_input(match key {
                        "weak_threshold" => "intrusion_weak_threshold_invalid",
                        "enumeration_min" => "intrusion_enumeration_min_invalid",
                        _ => "intrusion_burst_count_invalid",
                    })
                })?;
            }
        }
        if let Some(points) = o.get("weak_points").and_then(Value::as_object) {
            for (k, v) in points {
                c.weak_points.insert(
                    k.clone(),
                    v.as_i64()
                        .ok_or_else(|| Error::invalid_input("intrusion_weak_points_invalid"))?,
                );
            }
        }
        if let Some(thresholds) = o.get("strong_thresholds").and_then(Value::as_object) {
            for (k, v) in thresholds {
                c.strong_thresholds.insert(
                    k.clone(),
                    v.as_i64().ok_or_else(|| {
                        Error::invalid_input("intrusion_strong_threshold_invalid")
                    })?,
                );
            }
        }
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&self) -> Result<()> {
        for rule in STRONG_RULES {
            if self.strong_thresholds.get(*rule).is_none_or(|v| *v < 1) {
                return Err(Error::invalid_input("intrusion_strong_threshold_invalid"));
            }
        }
        for rule in WEAK_RULES {
            if self.weak_points.get(*rule).is_none_or(|v| *v < 0) {
                return Err(Error::invalid_input("intrusion_weak_points_invalid"));
            }
        }
        if !(self.window_seconds > 0.0) {
            return Err(Error::invalid_input("intrusion_window_invalid"));
        }
        if self.weak_threshold < 1 {
            return Err(Error::invalid_input("intrusion_weak_threshold_invalid"));
        }
        if self.enumeration_min < 1 {
            return Err(Error::invalid_input("intrusion_enumeration_min_invalid"));
        }
        if !(self.enumeration_ratio > 0.0 && self.enumeration_ratio <= 1.0) {
            return Err(Error::invalid_input("intrusion_enumeration_ratio_invalid"));
        }
        if self.burst_count < 1 {
            return Err(Error::invalid_input("intrusion_burst_count_invalid"));
        }
        Ok(())
    }
}

#[derive(Default)]
struct CallerState {
    strong: HashMap<String, VecDeque<f64>>,
    weak_events: VecDeque<(f64, String, i64)>,
    first_used: HashMap<String, f64>,
    enumeration_disarmed: bool,
    all_records: VecDeque<f64>,
    burst_disarmed: bool,
    fired_rules: VecDeque<(f64, String)>,
}
#[derive(Default)]
struct GlobalState {
    strong: HashMap<String, VecDeque<f64>>,
    weak_events: VecDeque<(f64, String, i64)>,
}
#[derive(Default)]
struct State {
    callers: HashMap<String, CallerState>,
    runtime_activity: HashMap<String, HashMap<String, f64>>,
    global: GlobalState,
}
#[derive(Clone)]
struct Trip {
    rule: String,
    detail: String,
    unattributed: bool,
    scope: String,
    runtime: Option<String>,
    principal: Option<String>,
}
impl Trip {
    fn global(rule: &str, detail: String) -> Self {
        Self {
            rule: UNATTRIBUTED_RULE.into(),
            detail: format!("unattributed rule={rule} {detail}"),
            unattributed: true,
            scope: "principal".into(),
            runtime: None,
            principal: None,
        }
    }
}
pub struct Detector {
    ctx: Arc<Context>,
    pub config: DetectorConfig,
    state: Mutex<State>,
    decision: Mutex<()>,
    pub decision_errors: AtomicU64,
}
impl Detector {
    pub fn new(ctx: Arc<Context>, config: DetectorConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            ctx,
            config,
            state: Mutex::new(State::default()),
            decision: Mutex::new(()),
            decision_errors: AtomicU64::new(0),
        })
    }
    pub fn on_record(&self, record: &Map<String, Value>) {
        let event = record.get("event").and_then(Value::as_str);
        if event.is_none_or(|e| e.starts_with("incident_")) {
            return;
        }
        let now = (self.ctx.clock)();
        let trip = self
            .state
            .lock()
            .ok()
            .and_then(|mut s| self.accumulate(&mut s, record, now));
        let Some(trip) = trip else { return };
        let Ok(_decision) = self.decision.try_lock() else {
            return;
        };
        if self.apply_decision(trip).is_err() {
            self.decision_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn accumulate(&self, s: &mut State, record: &Map<String, Value>, now: f64) -> Option<Trip> {
        let caller = record
            .get("caller")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty());
        let event = record.get("event").and_then(Value::as_str);
        let result = record.get("result").and_then(Value::as_str);
        let reason = record.get("reason").and_then(Value::as_str);
        let mut trip = None;
        if let Some(caller) = caller.filter(|_| {
            ["tools_request", "tools_exec", "http_relay"]
                .iter()
                .any(|e| Some(*e) == event)
        }) {
            if result == Some("ok") {
                trip = self.record_enumeration(
                    s,
                    caller,
                    record.get("connection").and_then(Value::as_str),
                    now,
                );
            }
            if let Some(t) = self.record_burst(s, caller, now) {
                trip = Some(t);
            }
        }
        if let Some((rule, kind)) = match_denial_rule(event, result, reason) {
            let candidate = if let Some(caller) = caller {
                if kind == "strong" {
                    self.add_caller_strong(s, caller, rule, now)
                } else {
                    self.add_caller_weak(s, caller, rule, now)
                }
            } else if kind == "strong" {
                self.add_global_strong(s, rule, now)
            } else {
                self.add_global_weak(s, rule, now)
            };
            if candidate.is_some() {
                trip = candidate;
            }
        }
        trip
    }
    fn touch(&self, s: &mut State, caller: &str, now: f64) {
        if let Ok(p) = self.ctx.policy.get_principal(caller) {
            s.runtime_activity
                .entry(p.runtime)
                .or_default()
                .insert(caller.into(), now);
        }
    }
    fn record_enumeration(
        &self,
        s: &mut State,
        caller: &str,
        connection: Option<&str>,
        now: f64,
    ) -> Option<Trip> {
        let cid = connection.filter(|c| !c.is_empty())?;
        let st = s.callers.entry(caller.into()).or_default();
        st.first_used.entry(cid.into()).or_insert(now);
        let distinct = st
            .first_used
            .values()
            .filter(|ts| now - **ts <= self.config.window_seconds)
            .count();
        let usable = self
            .ctx
            .policy
            .usable_connections(caller)
            .map(|v| v.len())
            .unwrap_or(0);
        let over = usable > 0
            && distinct >= self.config.enumeration_min as usize
            && (distinct as f64) >= usable as f64 * self.config.enumeration_ratio;
        if !over {
            st.enumeration_disarmed = false;
            return None;
        }
        if st.enumeration_disarmed {
            return None;
        }
        st.enumeration_disarmed = true;
        self.add_caller_weak(s, caller, "enumeration", now)
    }
    fn record_burst(&self, s: &mut State, caller: &str, now: f64) -> Option<Trip> {
        let st = s.callers.entry(caller.into()).or_default();
        prune_ts(&mut st.all_records, now, self.config.window_seconds);
        st.all_records.push_back(now);
        if st.all_records.len() <= self.config.burst_count as usize {
            st.burst_disarmed = false;
            return None;
        }
        if st.burst_disarmed {
            return None;
        }
        st.burst_disarmed = true;
        self.add_caller_weak(s, caller, "burst", now)
    }
    fn add_caller_strong(&self, s: &mut State, caller: &str, rule: &str, now: f64) -> Option<Trip> {
        let st = s.callers.entry(caller.into()).or_default();
        let dq = st.strong.entry(rule.into()).or_default();
        dq.push_back(now);
        prune_ts(dq, now, self.config.window_seconds);
        let count = dq.len();
        st.fired_rules.push_back((now, rule.into()));
        prune_tagged(&mut st.fired_rules, now, self.config.window_seconds);
        self.touch(s, caller, now);
        if count < *self.config.strong_thresholds.get(rule).unwrap_or(&1) as usize {
            return None;
        }
        Some(self.build_trip(s, caller, rule, count, now))
    }
    fn add_caller_weak(&self, s: &mut State, caller: &str, rule: &str, now: f64) -> Option<Trip> {
        let st = s.callers.entry(caller.into()).or_default();
        let points = *self.config.weak_points.get(rule).unwrap_or(&0);
        st.weak_events.push_back((now, rule.into(), points));
        prune_weak(&mut st.weak_events, now, self.config.window_seconds);
        let total = st.weak_events.iter().map(|e| e.2).sum::<i64>();
        st.fired_rules.push_back((now, rule.into()));
        prune_tagged(&mut st.fired_rules, now, self.config.window_seconds);
        self.touch(s, caller, now);
        if total < self.config.weak_threshold {
            return None;
        }
        Some(self.build_trip(s, caller, rule, total as usize, now))
    }
    fn build_trip(&self, s: &mut State, caller: &str, rule: &str, count: usize, now: f64) -> Trip {
        let st = s.callers.entry(caller.into()).or_default();
        prune_tagged(&mut st.fired_rules, now, self.config.window_seconds);
        let fired: HashSet<&str> = st.fired_rules.iter().map(|(_, r)| r.as_str()).collect();
        let runtime_located =
            fired.contains("signer_misuse") || fired.contains("output_exfiltration");
        let principal_runtime = self
            .ctx
            .policy
            .get_principal(caller)
            .ok()
            .map(|p| p.runtime);
        let mut scope = "principal".to_owned();
        let mut runtime = None;
        if let Some(r) = principal_runtime {
            let bucket = s.runtime_activity.entry(r.clone()).or_default();
            bucket.retain(|_, ts| now - *ts <= self.config.window_seconds);
            if runtime_located || bucket.len() >= 2 {
                scope = "runtime".into();
                runtime = Some(r);
            }
        }
        Trip {
            rule: rule.into(),
            detail: format!(
                "rule={rule} signals={count} rules_in_window={}",
                fired.len()
            ),
            unattributed: false,
            scope,
            runtime,
            principal: Some(caller.into()),
        }
    }
    fn add_global_strong(&self, s: &mut State, rule: &str, now: f64) -> Option<Trip> {
        let dq = s.global.strong.entry(rule.into()).or_default();
        dq.push_back(now);
        prune_ts(dq, now, self.config.window_seconds);
        if dq.len() < *self.config.strong_thresholds.get(rule).unwrap_or(&1) as usize {
            None
        } else {
            Some(Trip::global(rule, format!("signals={}", dq.len())))
        }
    }
    fn add_global_weak(&self, s: &mut State, rule: &str, now: f64) -> Option<Trip> {
        let points = *self.config.weak_points.get(rule).unwrap_or(&0);
        let dq = &mut s.global.weak_events;
        dq.push_back((now, rule.into(), points));
        prune_weak(dq, now, self.config.window_seconds);
        let total = dq.iter().map(|e| e.2).sum::<i64>();
        if total < self.config.weak_threshold {
            None
        } else {
            Some(Trip::global(rule, format!("points={total}")))
        }
    }
    fn apply_decision(&self, trip: Trip) -> Result<()> {
        if trip.unattributed {
            let active: Vec<_> = self
                .ctx
                .policy
                .list_principals()?
                .into_iter()
                .filter(|p| p.status == "active")
                .map(|p| p.id)
                .collect();
            if active.is_empty() {
                return Ok(());
            }
            incident::open_incident(
                &self.ctx,
                "principal",
                Some(&active),
                None,
                "auto",
                Some(&trip.rule),
                Some(&trip.detail),
            )?;
        } else if trip.scope == "runtime" {
            incident::open_incident(
                &self.ctx,
                "runtime",
                None,
                trip.runtime.as_deref(),
                "auto",
                Some(&trip.rule),
                Some(&trip.detail),
            )?;
        } else {
            incident::open_incident(
                &self.ctx,
                "principal",
                Some(&[trip.principal.unwrap_or_default()]),
                None,
                "auto",
                Some(&trip.rule),
                Some(&trip.detail),
            )?;
        }
        Ok(())
    }
}
fn prune_ts(dq: &mut VecDeque<f64>, now: f64, window: f64) {
    while dq.front().is_some_and(|t| now - *t > window) {
        dq.pop_front();
    }
}
fn prune_tagged<T>(dq: &mut VecDeque<(f64, T)>, now: f64, window: f64) {
    while dq.front().is_some_and(|e| now - e.0 > window) {
        dq.pop_front();
    }
}
fn prune_weak(dq: &mut VecDeque<(f64, String, i64)>, now: f64, window: f64) {
    while dq.front().is_some_and(|e| now - e.0 > window) {
        dq.pop_front();
    }
}

pub fn install(ctx: Arc<Context>, config: Option<DetectorConfig>) -> Result<Arc<Detector>> {
    if let Some(existing) = ctx.intrusion.lock().ok().and_then(|s| {
        s.as_ref()
            .and_then(|v| v.downcast_ref::<Weak<Detector>>())
            .and_then(Weak::upgrade)
    }) {
        return Ok(existing);
    }
    let config = match config {
        Some(c) => c,
        None => DetectorConfig::from_mapping(ctx.config.intrusion.as_ref())?,
    };
    let detector = Arc::new(Detector::new(Arc::clone(&ctx), config)?);
    let weak = Arc::downgrade(&detector);
    ctx.audit.subscribe(move |record| {
        if let Some(detector) = weak.upgrade() {
            detector.on_record(record);
        }
    });
    *ctx.intrusion.lock().expect("intrusion mutex poisoned") =
        Some(Box::new(Arc::downgrade(&detector)));
    Ok(detector)
}
