//! Port of `zeropw/audit.py`: a value-free, append-only audit log with simple
//! anomaly alerts.
//!
//! Design rules (`docs/security-design.md` §6), copied from the Python
//! module because they are the actual specification for this port:
//!
//! * Records name the caller, connection, target, action, result and policy
//!   version. They never contain vault values, authentication headers,
//!   request bodies, query strings, or free text supplied by an agent. Every
//!   field is whitelisted and bounded here, so a caller cannot smuggle a
//!   value in.
//! * The log is mandatory: if a record cannot be written, `record` returns
//!   `AuditUnavailable` and the caller must refuse the authenticated
//!   operation.
//! * Agents cannot read the log. There is no tools endpoint for it; only the
//!   administrator CLI (which has state-directory access) reads it.
//! * Alerts (`audit/alerts.jsonl`): administrator secret reveal, credential
//!   reflection, other near-exposures (execution output carrying the
//!   credential or handle, blocked upstream redirects), failures of the
//!   authenticated path (TLS server identity, unavailable credential), use
//!   under revoked/stale/stopped policy, and repeated denials -- counted per
//!   caller, and per event and reason for unauthenticated requests such as
//!   forged handles.
//! * [`Audit::subscribe`] (`docs/compromise-response.md` §4.1, stage 3) lets a
//!   trusted in-process component -- the intrusion detector -- observe every
//!   record synchronously, right after it is persisted and after
//!   `_maybe_alert` has run. A listener never sees a record before it is
//!   durable. A listener panic/error is swallowed (never breaks `record` for
//!   its caller) and counted on `listener_errors` for diagnostics.
//! * The record line and any alert it triggers are written under the *same*
//!   state lock, so the two files are never observed half-updated by another
//!   thread/process (this crate matches the Python fix that added the shared
//!   lock: without it a reader can wake up right after seeing the record but
//!   still find the alerts file one line short).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value, json};

use crate::clock::Clock;
use crate::errors::Error;
use crate::pyjson::{self, DumpOptions};
use crate::store::{StateDir, iso};

pub const AUDIT_FILE: &str = "audit/audit.jsonl";
pub const ALERT_FILE: &str = "audit/alerts.jsonl";

pub const MAX_FIELD_LENGTH: usize = 200;
pub const DENIAL_WINDOW_SECONDS: f64 = 60.0;
pub const DENIAL_THRESHOLD: usize = 5;

/// `audit.EVENTS`.
pub const EVENTS: &[&str] = &[
    "init",
    "principal_create",
    "principal_disable",
    "project_create",
    "secret_put",
    "secret_retire",
    "secret_revoke",
    "secret_reveal",
    "secret_reveal_denied",
    "connection_create",
    "connection_update",
    "connection_disable",
    "connection_switch_credential",
    "grant_create",
    "grant_revoke",
    "grant_regrant",
    "grant_stale",
    "stop_all",
    "resume",
    "approval_request",
    "approval_grant",
    "approval_consume",
    "handle_issue",
    "tools_list_connections",
    "tools_request",
    "tools_exec",
    "tools_status",
    "tools_cancel",
    "tools_unknown",
    "http_relay",
    "ssh_bind",
    "ssh_sign",
    "ssh_agent_refused",
    "run_start",
    "run_finish",
    "run_cancel",
    "backup",
    "restore",
    "restore_ack",
    "recover",
    "rotation",
    "unsupported",
    "auth_failed",
    "team_commit_apply",
    "team_commit_rejected",
    "team_op_skipped",
    "team_op_overridden",
    "team_handshake_failed",
    "team_session_open",
    "team_session_close",
    "team_fact_apply",
    "team_fact_rejected",
    "team_sync_vector",
    "team_share",
    "team_invite_create",
    "team_join",
    "team_member_add",
    "team_member_remove",
    "team_dek_rotate",
    "team_compact",
    "team_incident_received",
    "incident_open",
    "incident_widen",
    "incident_close",
    "incident_notify",
];

/// `audit.EXTRA_KEYS`.
pub const EXTRA_KEYS: &[&str] = &[
    "method",
    "path",
    "status",
    "host",
    "port",
    "username",
    "fingerprint",
    "bytes",
    "count",
    "exit_code",
    "program",
    "secret_id",
    "version",
    "grant",
    "principal",
    "digest",
    "state",
    "kind",
    "detail",
    "message_type",
    "extension",
    "scheme",
    "project",
    "environment",
    "service",
    "backup_id",
    "reviewed_sha",
    "run_state",
    "uses",
    "max_uses",
    "expires_at",
    "reason_code",
    "author_seq",
    "op",
    "env_id",
    "commits",
    "role",
    "incident_id",
    "scope",
    "runtime",
    "rule",
    "tier",
];

/// `audit.CREDENTIAL_EXPOSURE_REASONS`: anomalies that mean a credential or
/// handle nearly left the trusted boundary (alerted every time).
pub const CREDENTIAL_EXPOSURE_REASONS: &[(&str, &str)] = &[
    (
        "output_credential_blocked",
        "execution output carried the credential or handle; output withheld",
    ),
    (
        "redirect_not_followed",
        "upstream redirect was blocked; its Location may carry request or credential data",
    ),
    (
        "target_address_not_allowed",
        "credential delivery to a non-public address was refused (possible DNS change)",
    ),
    (
        "metadata_address_not_allowed",
        "credential delivery to a metadata or link-local address was refused",
    ),
];

/// `audit.FAILURE_ALERT_REASONS`: failures of the authenticated path that the
/// user must hear about (alerted every time).
pub const FAILURE_ALERT_REASONS: &[(&str, &str)] = &[
    (
        "upstream_tls_failed",
        "upstream TLS server identity could not be verified; request refused",
    ),
    (
        "credential_unavailable",
        "the connection's credential is unavailable (revoked, retired or corrupt)",
    ),
    (
        "local_id_conflict",
        "a shared environment tried to derive a connection or secret id already used locally",
    ),
    (
        "member_removed_rotation_recommended",
        "a team member was removed; this environment's active secrets should be rotated at the provider",
    ),
];

const REVOKED_USE_REASONS: &[&str] = &[
    "grant_revoked",
    "global_stop",
    "grant_stale",
    "principal_disabled",
    "restore_pending",
];

fn lookup(table: &'static [(&'static str, &'static str)], reason: &str) -> Option<&'static str> {
    table
        .iter()
        .find(|(k, _)| *k == reason)
        .map(|(_, v)| v)
        .copied()
}

/// `audit._clean`: whitelists field types, bounds strings, replaces control
/// characters, rounds floats to 3 decimals (Python `round(value, 3)`, banker's
/// rounding -- see `round_half_even_3dp`).
fn clean(value: Value) -> Result<Value, Error> {
    match value {
        Value::Null | Value::Bool(_) => Ok(value),
        Value::Number(n) => {
            if n.is_f64() {
                let f = n.as_f64().expect("checked is_f64");
                Ok(json!(round_half_even_3dp(f)))
            } else {
                Ok(Value::Number(n))
            }
        }
        Value::String(s) => {
            let cleaned: String = s
                .chars()
                .map(|c| {
                    if (c as u32) < 0x20 || c as u32 == 0x7f {
                        '?'
                    } else {
                        c
                    }
                })
                .collect();
            let truncated: String = cleaned.chars().take(MAX_FIELD_LENGTH).collect();
            Ok(Value::String(truncated))
        }
        Value::Array(_) | Value::Object(_) => Err(Error::invalid_input("audit_field_type")),
    }
}

/// Python's `round(x, 3)` correctly rounds the *exact* binary value of the
/// float to 3 decimal digits, half-to-even on exact ties (via CPython's
/// `_Py_dg_dtoa` mode 3) -- not `(x * 1000.0).round() / 1000.0`, which
/// operates on an already-rounded intermediate and disagrees with Python on
/// values near a `*.*5` boundary (e.g. `2.675`, whose nearest `f64` is
/// actually `2.67499999999999982...`, so both Python and this round down to
/// `2.675`). Rust's `{:.N}` float formatting is documented to perform the
/// same correctly-rounded, ties-to-even conversion from the exact binary
/// value, so formatting and reparsing reproduces `round(x, 3)` exactly
/// without a bignum-decimal dependency; verified against the CPython oracle
/// for the classic trap cases plus 200 randomized values --
/// `oracle_tests::round_3dp_matches_python_oracle`, below `tests`'
/// (non-oracle, hardcoded-literal) `round_3dp_matches_python_examples`.
fn round_half_even_3dp(f: f64) -> f64 {
    if !f.is_finite() {
        return f;
    }
    format!("{f:.3}").parse::<f64>().unwrap_or(f)
}

/// Python `str()` of a JSON scalar as `_clean` would have left it (`None`,
/// `bool`, `int`, `float`, or `str` -- `_clean` already rejects arrays/dicts,
/// so `record.get(...)` values reaching here are always one of these).  Used
/// by [`Audit::maybe_alert`]'s `f"...{record.get('scope')}..."` formatting,
/// which calls Python's `str()` on whatever type `scope` happens to hold.
fn python_scalar_str(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "None".to_string(),
        Some(Value::Bool(true)) => "True".to_string(),
        Some(Value::Bool(false)) => "False".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => {
            if n.is_f64() {
                pyjson::python_float_repr(n.as_f64().unwrap_or(0.0))
            } else {
                n.as_str().to_string()
            }
        }
        // Unreachable in practice: `_clean` rejects arrays/objects before a
        // value can land in `record`.
        Some(other) => other.to_string(),
    }
}

/// `audit.strip_query`.
pub fn strip_query(path: &str) -> String {
    path.split('?').next().unwrap_or("").to_string()
}

/// Fields accepted by [`Audit::record`], mirroring the Python keyword
/// arguments. All optional fields default to `None` like Python.
#[derive(Default, Clone, Debug)]
pub struct RecordArgs<'a> {
    pub caller: Option<&'a str>,
    pub connection: Option<&'a str>,
    pub target: Option<&'a str>,
    pub action: Option<&'a str>,
    /// Defaults to `"ok"`, like Python's `result: str = "ok"`.
    pub result: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub policy_version: Option<i64>,
    pub run_id: Option<&'a str>,
    pub request_id: Option<&'a str>,
    /// `extra`: keys must be in [`EXTRA_KEYS`]; values must already be
    /// JSON scalars (`null`/bool/number/string) -- arrays/objects raise
    /// `audit_field_type` like Python's `_clean`.
    pub extra: Vec<(&'a str, Value)>,
}

type ListenerFn = dyn Fn(&Map<String, Value>) + Send + Sync;

struct Listener(Arc<ListenerFn>);

/// Port of `audit.Audit`.
pub struct Audit<'a> {
    state: &'a StateDir,
    clock: Clock,
    recent_denials: Mutex<HashMap<String, VecDeque<f64>>>,
    listeners: Mutex<Vec<Listener>>,
    pub listener_errors: Mutex<u64>,
}

impl<'a> Audit<'a> {
    pub fn new(state: &'a StateDir, clock: Clock) -> Self {
        Audit {
            state,
            clock,
            recent_denials: Mutex::new(HashMap::new()),
            listeners: Mutex::new(Vec::new()),
            listener_errors: Mutex::new(0),
        }
    }

    /// `Audit.subscribe`: register a listener called synchronously at the end
    /// of every [`Audit::record`] call, after the line is durable. A panic
    /// unwinding out of `listener` is caught (via `catch_unwind`, mirroring
    /// Python swallowing any `Exception`) and counted on `listener_errors` so
    /// a detection bug can never take down the audit log itself.
    pub fn subscribe(&self, listener: impl Fn(&Map<String, Value>) + Send + Sync + 'static) {
        self.listeners
            .lock()
            .expect("listeners mutex poisoned")
            .push(Listener(Arc::new(listener)));
    }

    /// Mirrors `Audit._notify_listeners`'s `for listener in list(self._listeners)`:
    /// Python iterates a *copy* of the listener list taken without holding any
    /// lock, so a listener that calls back into `record`/`subscribe` on the
    /// same thread never re-enters a held lock. We snapshot (clone the `Arc`s)
    /// under the listeners mutex, drop it, then invoke -- a listener calling
    /// `subscribe` only mutates the `Vec` for the *next* `record`, exactly
    /// like Python's `list(...)` snapshot missing a listener registered during
    /// iteration.
    fn notify_listeners(&self, record: &Map<String, Value>) {
        let snapshot: Vec<Arc<ListenerFn>> = {
            let listeners = self.listeners.lock().expect("listeners mutex poisoned");
            listeners.iter().map(|l| l.0.clone()).collect()
        };
        for listener in snapshot {
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (listener)(record)));
            if result.is_err() {
                *self
                    .listener_errors
                    .lock()
                    .expect("listener_errors mutex poisoned") += 1;
            }
        }
    }

    /// `Audit.record`.
    pub fn record(&self, event: &str, args: RecordArgs<'_>) -> Result<Map<String, Value>, Error> {
        if !EVENTS.contains(&event) {
            return Err(Error::invalid_input("audit_event_unknown"));
        }
        let mut record = Map::new();
        record.insert("ts".into(), Value::String(iso(Some((self.clock)()))));
        record.insert("event".into(), Value::String(event.to_string()));
        record.insert("caller".into(), clean(opt_str(args.caller))?);
        record.insert("connection".into(), clean(opt_str(args.connection))?);
        record.insert("target".into(), clean(opt_str(args.target))?);
        record.insert("action".into(), clean(opt_str(args.action))?);
        record.insert(
            "result".into(),
            clean(Value::String(args.result.unwrap_or("ok").to_string()))?,
        );
        record.insert("reason".into(), clean(opt_str(args.reason))?);
        record.insert(
            "policy_version".into(),
            clean(args.policy_version.map(|v| json!(v)).unwrap_or(Value::Null))?,
        );
        record.insert("run_id".into(), clean(opt_str(args.run_id))?);
        record.insert("request_id".into(), clean(opt_str(args.request_id))?);

        for (key, value) in args.extra {
            if !EXTRA_KEYS.contains(&key) {
                return Err(Error::invalid_input("audit_extra_key"));
            }
            let value = if key == "path" {
                match value {
                    Value::String(s) => Value::String(strip_query(&s)),
                    other => other,
                }
            } else {
                value
            };
            record.insert(key.to_string(), clean(value)?);
        }

        let line = pyjson::dumps(
            &Value::Object(record.clone()),
            DumpOptions::compact_sorted(),
        )?;
        let _lock = self.state.lock()?;
        self.state
            .append_line(AUDIT_FILE, &line)
            .map_err(|_| Error::audit_unavailable("audit_write_failed"))?;
        self.maybe_alert(&record)?;
        drop(_lock);
        self.notify_listeners(&record);
        Ok(record)
    }

    /// `Audit.require_writable`: probe that the audit file can be appended to
    /// before authenticating.
    pub fn require_writable(&self) -> Result<(), Error> {
        (|| -> Result<(), Error> {
            self.state.subdir("audit")?;
            self.state.append_line(AUDIT_FILE, "")
        })()
        .map_err(|_| Error::audit_unavailable("audit_write_failed"))
    }

    fn alert(&self, kind: &str, record: &Map<String, Value>, detail: &str) -> Result<(), Error> {
        let mut alert = Map::new();
        alert.insert(
            "ts".into(),
            record.get("ts").cloned().unwrap_or(Value::Null),
        );
        alert.insert("alert".into(), Value::String(kind.to_string()));
        alert.insert(
            "caller".into(),
            record.get("caller").cloned().unwrap_or(Value::Null),
        );
        alert.insert(
            "connection".into(),
            record.get("connection").cloned().unwrap_or(Value::Null),
        );
        alert.insert(
            "event".into(),
            record.get("event").cloned().unwrap_or(Value::Null),
        );
        alert.insert(
            "reason".into(),
            record.get("reason").cloned().unwrap_or(Value::Null),
        );
        alert.insert("detail".into(), clean(Value::String(detail.to_string()))?);
        let line = pyjson::dumps(&Value::Object(alert), DumpOptions::compact_sorted())?;
        self.state
            .append_line(ALERT_FILE, &line)
            .map_err(|_| Error::audit_unavailable("alert_write_failed"))
    }

    fn maybe_alert(&self, record: &Map<String, Value>) -> Result<(), Error> {
        let event = record.get("event").and_then(Value::as_str).unwrap_or("");
        let reason = record.get("reason").and_then(Value::as_str);
        let result = record.get("result").and_then(Value::as_str);

        if event == "secret_reveal" {
            self.alert(
                "secret_reveal",
                record,
                "administrator revealed a single secret version",
            )?;
        }
        if event == "team_incident_received" {
            self.alert(
                "team_incident_received",
                record,
                "a shared environment received an incident summary; check rotation flags",
            )?;
        }
        if event == "team_op_overridden" {
            self.alert(
                "team_op_overridden",
                record,
                "a later commit from another device overrode this node's change to the same target",
            )?;
        }
        if event == "incident_open" {
            let scope = python_scalar_str(record.get("scope"));
            // Python: `reason or "unknown"` -- falsy is `None` *or* `""`.
            let reason_display = match reason {
                Some(r) if !r.is_empty() => r,
                _ => "unknown",
            };
            self.alert(
                "intrusion",
                record,
                &format!("incident opened: scope={scope} reason={reason_display}"),
            )?;
        }
        if event == "incident_widen" {
            let scope = python_scalar_str(record.get("scope"));
            self.alert(
                "intrusion",
                record,
                &format!("incident widened to scope={scope}"),
            )?;
        }
        if reason == Some("credential_reflection_blocked") {
            self.alert(
                "credential_reflection",
                record,
                "upstream response reflected the credential; blocked",
            )?;
        }
        if let Some(detail) = reason.and_then(|r| lookup(CREDENTIAL_EXPOSURE_REASONS, r)) {
            self.alert("credential_exposure", record, detail)?;
        }
        if let Some(detail) = reason.and_then(|r| lookup(FAILURE_ALERT_REASONS, r))
            && result != Some("attempt")
        {
            self.alert("failure", record, detail)?;
        }
        if reason.is_some_and(|r| REVOKED_USE_REASONS.contains(&r)) {
            self.alert(
                "revoked_use_attempt",
                record,
                "use attempted under a revoked, stale, or stopped grant",
            )?;
        }
        if result == Some("denied") {
            // Authenticated denials count per caller. Unauthenticated ones
            // (forged or tampered handles, unknown tokens) carry no caller,
            // so they count per event and reason. Python: `record.get("caller")`
            // truthiness -- `None` *and* `""` both take the unauthenticated
            // branch, not just `None`.
            let caller = record
                .get("caller")
                .and_then(Value::as_str)
                .filter(|c| !c.is_empty());
            let key = match caller {
                Some(c) => format!("caller:{c}"),
                None => format!(
                    "unauthenticated:{event}:{}",
                    reason
                        .map(str::to_string)
                        .unwrap_or_else(|| "None".to_string())
                ),
            };
            let now = (self.clock)();
            let mut denials = self
                .recent_denials
                .lock()
                .expect("recent_denials mutex poisoned");
            let window = denials.entry(key).or_default();
            window.push_back(now);
            while let Some(&front) = window.front() {
                if now - front > DENIAL_WINDOW_SECONDS {
                    window.pop_front();
                } else {
                    break;
                }
            }
            let hit_threshold = window.len() == DENIAL_THRESHOLD;
            drop(denials);
            if hit_threshold {
                self.alert(
                    "repeated_denials",
                    record,
                    &format!(
                        "{DENIAL_THRESHOLD} denials within {}s",
                        DENIAL_WINDOW_SECONDS as i64
                    ),
                )?;
            }
        }
        Ok(())
    }

    /// `Audit.tail`.
    pub fn tail(&self, limit: usize) -> Result<Vec<Value>, Error> {
        let lines = self.state.read_lines(AUDIT_FILE, None)?;
        parse_tail(&lines, limit)
    }

    /// `Audit.iter_records`: every parsed record in the log, in order.
    /// Unlike [`Audit::tail`] this is not capped: used by the
    /// compromise-response exposure assessment, which must see the whole
    /// history from a principal's token creation onward. Unparseable lines
    /// are skipped.
    pub fn iter_records(&self) -> Result<Vec<Value>, Error> {
        let lines = self.state.read_lines(AUDIT_FILE, None)?;
        Ok(lines
            .into_iter()
            .filter(|l| !l.is_empty())
            .filter_map(|l| pyjson::loads(&l).ok())
            .filter(|v| v.is_object())
            .collect())
    }

    /// `Audit.alerts`.
    pub fn alerts(&self, limit: usize) -> Result<Vec<Value>, Error> {
        let lines = self.state.read_lines(ALERT_FILE, None)?;
        parse_tail(&lines, limit)
    }
}

fn parse_tail(lines: &[String], limit: usize) -> Result<Vec<Value>, Error> {
    let non_empty: Vec<&String> = lines.iter().filter(|l| !l.is_empty()).collect();
    // Python: `lines[-limit:]`. `-0 == 0`, so a `limit` of `0` means the
    // *whole* list (`lines[0:]`), not an empty slice.
    let start = if limit == 0 {
        0
    } else {
        non_empty.len().saturating_sub(limit)
    };
    non_empty[start..]
        .iter()
        .map(|l| pyjson::loads(l).map_err(|_| Error::state("state_corrupt").with_detail("audit")))
        .collect()
}

fn opt_str(v: Option<&str>) -> Value {
    match v {
        Some(s) => Value::String(s.to_string()),
        None => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tempfile::TempDir;

    use super::*;
    use crate::clock;
    use crate::errors::ErrorClass;

    fn new_audit() -> (TempDir, StateDir) {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        (tmp, state)
    }

    fn extra(pairs: &[(&'static str, Value)]) -> Vec<(&'static str, Value)> {
        pairs.to_vec()
    }

    // Port of test_core_audit_handles.py::AuditTestCase::test_records_are_whitelisted_and_bounded
    #[test]
    fn records_are_whitelisted_and_bounded() {
        let (tmp, state) = new_audit();
        let audit = Audit::new(&state, clock::fixed(1_700_000_000.0));
        let record = audit
            .record(
                "http_relay",
                RecordArgs {
                    caller: Some("agent-1"),
                    connection: Some("gh"),
                    target: Some("127.0.0.1:8080"),
                    action: Some("GET"),
                    result: Some("ok"),
                    policy_version: Some(3),
                    extra: extra(&[
                        ("path", json!("/repos?token=synthetic-secret")),
                        ("status", json!(200)),
                    ]),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(record["path"], json!("/repos"));
        let raw = std::fs::read_to_string(tmp.path().join("state/audit/audit.jsonl")).unwrap();
        assert!(!raw.contains("synthetic-secret"));

        let err = audit
            .record(
                "http_relay",
                RecordArgs {
                    extra: extra(&[("authorization", json!("Bearer x"))]),
                    ..Default::default()
                },
            )
            .unwrap_err();
        assert!(err.is(ErrorClass::InvalidInput));
        assert_eq!(err.reason, "audit_extra_key");

        let err = audit
            .record("made_up_event", RecordArgs::default())
            .unwrap_err();
        assert_eq!(err.reason, "audit_event_unknown");

        let err = audit
            .record(
                "http_relay",
                RecordArgs {
                    extra: extra(&[("path", json!({"nested": 1}))]),
                    ..Default::default()
                },
            )
            .unwrap_err();
        assert_eq!(err.reason, "audit_field_type");

        let long_record = audit
            .record(
                "http_relay",
                RecordArgs {
                    reason: Some(&"x".repeat(1000)),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(long_record["reason"].as_str().unwrap().len(), 200);

        let control = audit
            .record(
                "http_relay",
                RecordArgs {
                    target: Some("a\nb\x00c"),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(control["target"], json!("a?b?c"));
    }

    // Port of test_write_failure_raises_audit_unavailable, adapted: instead of
    // monkeypatching `StateDir.append_line` (not possible on a Rust struct),
    // point the audit log at a path a regular file occupies so append fails.
    #[test]
    fn write_failure_raises_audit_unavailable() {
        let (tmp, state) = new_audit();
        std::fs::create_dir_all(tmp.path().join("state/audit")).unwrap();
        std::fs::write(tmp.path().join("state/audit/audit.jsonl"), b"x").unwrap();
        // Make the target itself unwritable as a directory-collision instead:
        // replace the audit dir with a file so `append_line`'s mkdir_p/open fails.
        std::fs::remove_file(tmp.path().join("state/audit/audit.jsonl")).unwrap();
        std::fs::remove_dir(tmp.path().join("state/audit")).unwrap();
        std::fs::write(tmp.path().join("state/audit"), b"blocking file").unwrap();

        let audit = Audit::new(&state, clock::fixed(1_700_000_000.0));
        let err = audit
            .record(
                "http_relay",
                RecordArgs {
                    result: Some("ok"),
                    ..Default::default()
                },
            )
            .unwrap_err();
        assert!(err.is(ErrorClass::AuditUnavailable));
        let err = audit.require_writable().unwrap_err();
        assert!(err.is(ErrorClass::AuditUnavailable));
    }

    // Port of test_alerts_for_revoked_use_reflection_and_repeated_denials
    #[test]
    fn alerts_for_revoked_use_reflection_and_repeated_denials() {
        let (_tmp, state) = new_audit();
        let clock = Arc::new(Mutex::new(1_700_000_000.0));
        let clock_cb = {
            let clock = clock.clone();
            move || *clock.lock().unwrap()
        };
        let audit = Audit::new(&state, Arc::new(clock_cb));

        audit
            .record(
                "http_relay",
                RecordArgs {
                    caller: Some("agent-1"),
                    result: Some("denied"),
                    reason: Some("grant_revoked"),
                    ..Default::default()
                },
            )
            .unwrap();
        audit
            .record(
                "http_relay",
                RecordArgs {
                    caller: Some("agent-1"),
                    result: Some("denied"),
                    reason: Some("credential_reflection_blocked"),
                    ..Default::default()
                },
            )
            .unwrap();
        let alerts: Vec<String> = audit
            .alerts(1000)
            .unwrap()
            .iter()
            .map(|a| a["alert"].as_str().unwrap().to_string())
            .collect();
        assert!(alerts.contains(&"revoked_use_attempt".to_string()));
        assert!(alerts.contains(&"credential_reflection".to_string()));

        for _ in 0..3 {
            audit
                .record(
                    "http_relay",
                    RecordArgs {
                        caller: Some("agent-1"),
                        result: Some("denied"),
                        reason: Some("path_not_allowed"),
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        let alerts = audit.alerts(1000).unwrap();
        assert!(alerts.iter().any(|a| a["alert"] == "repeated_denials"));
        assert_eq!(
            alerts
                .iter()
                .filter(|a| a["alert"] == "repeated_denials")
                .count(),
            1
        );

        *clock.lock().unwrap() += 120.0;
        for _ in 0..5 {
            audit
                .record(
                    "http_relay",
                    RecordArgs {
                        caller: Some("agent-2"),
                        result: Some("denied"),
                        reason: Some("path_not_allowed"),
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        let alerts = audit.alerts(1000).unwrap();
        assert_eq!(
            alerts
                .iter()
                .filter(|a| a["alert"] == "repeated_denials")
                .count(),
            2
        );
    }

    // Port of test_alerts_for_exposure_failures_and_unauthenticated_floods (F6)
    #[test]
    fn alerts_for_exposure_failures_and_unauthenticated_floods() {
        let (_tmp, state) = new_audit();
        let audit = Audit::new(&state, clock::fixed(1_700_000_000.0));
        let cases: &[(&str, &str, &str, &str)] = &[
            (
                "run_finish",
                "blocked",
                "output_credential_blocked",
                "credential_exposure",
            ),
            (
                "http_relay",
                "blocked",
                "redirect_not_followed",
                "credential_exposure",
            ),
            ("http_relay", "error", "upstream_tls_failed", "failure"),
            ("http_relay", "error", "credential_unavailable", "failure"),
            ("run_finish", "failed", "credential_unavailable", "failure"),
        ];
        for (event, result, reason, alert) in cases {
            let before = audit.alerts(1000).unwrap().len();
            audit
                .record(
                    event,
                    RecordArgs {
                        caller: Some("agent-1"),
                        connection: Some("gh"),
                        result: Some(result),
                        reason: Some(reason),
                        ..Default::default()
                    },
                )
                .unwrap();
            let added = &audit.alerts(1000).unwrap()[before..];
            let got: Vec<(String, String, String)> = added
                .iter()
                .map(|a| {
                    (
                        a["alert"].as_str().unwrap().to_string(),
                        a["reason"].as_str().unwrap().to_string(),
                        a["event"].as_str().unwrap().to_string(),
                    )
                })
                .collect();
            assert_eq!(
                got,
                vec![(alert.to_string(), reason.to_string(), event.to_string())]
            );
        }

        let before = audit.alerts(1000).unwrap().len();
        for _ in 0..4 {
            audit
                .record(
                    "http_relay",
                    RecordArgs {
                        caller: None,
                        result: Some("denied"),
                        reason: Some("handle_signature"),
                        ..Default::default()
                    },
                )
                .unwrap();
            audit
                .record(
                    "http_relay",
                    RecordArgs {
                        caller: None,
                        result: Some("denied"),
                        reason: Some("handle_malformed"),
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        assert_eq!(&audit.alerts(1000).unwrap()[before..], &[] as &[Value]);
        audit
            .record(
                "http_relay",
                RecordArgs {
                    caller: None,
                    result: Some("denied"),
                    reason: Some("handle_signature"),
                    ..Default::default()
                },
            )
            .unwrap();
        let added = &audit.alerts(1000).unwrap()[before..];
        let got: Vec<(String, Value, String)> = added
            .iter()
            .map(|a| {
                (
                    a["alert"].as_str().unwrap().to_string(),
                    a["caller"].clone(),
                    a["reason"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![(
                "repeated_denials".to_string(),
                Value::Null,
                "handle_signature".to_string()
            )]
        );

        for _ in 0..4 {
            audit
                .record(
                    "http_relay",
                    RecordArgs {
                        caller: Some("agent-9"),
                        result: Some("denied"),
                        reason: Some("handle_signature"),
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        assert_eq!(audit.alerts(1000).unwrap().len(), added.len() + before);
    }

    // Port of test_tail_returns_parsed_records
    #[test]
    fn tail_returns_parsed_records() {
        let (_tmp, state) = new_audit();
        let audit = Audit::new(&state, clock::fixed(1_700_000_000.0));
        for i in 0..5 {
            audit
                .record(
                    "tools_status",
                    RecordArgs {
                        run_id: Some(&format!("r{i}")),
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        let tail = audit.tail(2).unwrap();
        let run_ids: Vec<&str> = tail.iter().map(|r| r["run_id"].as_str().unwrap()).collect();
        assert_eq!(run_ids, vec!["r3", "r4"]);
    }

    // A-4: Python's `lines[-limit:]` treats `limit == 0` as the whole list.
    #[test]
    fn tail_and_alerts_limit_zero_returns_everything() {
        let (_tmp, state) = new_audit();
        let audit = Audit::new(&state, clock::fixed(1_700_000_000.0));
        for i in 0..5 {
            audit
                .record(
                    "tools_status",
                    RecordArgs {
                        run_id: Some(&format!("r{i}")),
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        audit
            .record(
                "secret_reveal",
                RecordArgs {
                    caller: Some("admin"),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(audit.tail(0).unwrap().len(), 6);
        assert_eq!(audit.alerts(0).unwrap().len(), 1);
    }

    #[test]
    fn subscribe_sees_durable_records_and_swallows_panics() {
        let (_tmp, state) = new_audit();
        let audit = Audit::new(&state, clock::fixed(1_700_000_000.0));
        let seen = Arc::new(AtomicUsize::new(0));
        let seen2 = seen.clone();
        audit.subscribe(move |_record| {
            seen2.fetch_add(1, Ordering::SeqCst);
        });
        audit.subscribe(|_record| panic!("listener bug"));
        audit.record("init", RecordArgs::default()).unwrap();
        assert_eq!(seen.load(Ordering::SeqCst), 1);
        assert_eq!(*audit.listener_errors.lock().unwrap(), 1);
    }

    // A-1: `notify_listeners` must not hold the listeners lock while
    // invoking listeners -- a listener that calls back into `record` or
    // `subscribe` on the same thread must not deadlock (Python's
    // `_notify_listeners` iterates `list(self._listeners)`, a snapshot taken
    // without holding any lock, so this is always safe there). Each
    // reentrant call runs on its own thread with a watchdog timeout so a
    // regression fails the test instead of hanging the suite.
    #[test]
    fn listener_calling_record_does_not_deadlock() {
        let (_tmp, state) = new_audit();
        let state: &'static StateDir = Box::leak(Box::new(state));
        let audit: &'static Audit<'static> =
            Box::leak(Box::new(Audit::new(state, clock::fixed(1_700_000_000.0))));

        audit.subscribe(move |record| {
            if record["event"] == "init" {
                audit.record("resume", RecordArgs::default()).unwrap();
            }
        });

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            audit.record("init", RecordArgs::default()).unwrap();
            let _ = tx.send(());
        });
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("listener calling record() deadlocked notify_listeners");

        let log = audit.tail(10).unwrap();
        let events: Vec<&str> = log.iter().map(|r| r["event"].as_str().unwrap()).collect();
        assert_eq!(events, vec!["init", "resume"]);
        assert_eq!(*audit.listener_errors.lock().unwrap(), 0);
    }

    #[test]
    fn listener_calling_subscribe_does_not_deadlock() {
        let (_tmp, state) = new_audit();
        let state: &'static StateDir = Box::leak(Box::new(state));
        let audit: &'static Audit<'static> =
            Box::leak(Box::new(Audit::new(state, clock::fixed(1_700_000_000.0))));

        audit.subscribe(move |_record| {
            audit.subscribe(|_record| {});
        });

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            audit.record("init", RecordArgs::default()).unwrap();
            let _ = tx.send(());
        });
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("listener calling subscribe() deadlocked notify_listeners");

        let log = audit.tail(10).unwrap();
        let events: Vec<&str> = log.iter().map(|r| r["event"].as_str().unwrap()).collect();
        assert_eq!(events, vec!["init"]);
        assert_eq!(*audit.listener_errors.lock().unwrap(), 0);
    }

    // A-6: Python's `record.get("caller")` is falsy for both `None` and
    // `""`, so denials with an empty-string caller land in the same
    // unauthenticated bucket as a missing caller, keyed by event and reason.
    #[test]
    fn empty_string_caller_is_treated_as_unauthenticated() {
        let (_tmp, state) = new_audit();
        let audit = Audit::new(&state, clock::fixed(1_700_000_000.0));
        for _ in 0..5 {
            audit
                .record(
                    "http_relay",
                    RecordArgs {
                        caller: None,
                        result: Some("denied"),
                        reason: Some("r1"),
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        for _ in 0..5 {
            audit
                .record(
                    "http_relay",
                    RecordArgs {
                        caller: Some(""),
                        result: Some("denied"),
                        reason: Some("r2"),
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        let alerts = audit.alerts(1000).unwrap();
        assert_eq!(
            alerts
                .iter()
                .filter(|a| a["alert"] == "repeated_denials")
                .count(),
            2
        );
    }

    #[test]
    fn team_events_and_extra_keys_are_accepted() {
        let (_tmp, state) = new_audit();
        let audit = Audit::new(&state, clock::fixed(1_700_000_000.0));
        let record = audit
            .record(
                "team_commit_apply",
                RecordArgs {
                    extra: extra(&[
                        ("author_seq", json!(3)),
                        ("op", json!("grant_create")),
                        ("env_id", json!("e1")),
                    ]),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(record["op"], json!("grant_create"));

        let alerts_before = audit.alerts(1000).unwrap().len();
        audit
            .record("team_incident_received", RecordArgs::default())
            .unwrap();
        audit
            .record("team_op_overridden", RecordArgs::default())
            .unwrap();
        let alerts = audit.alerts(1000).unwrap();
        assert_eq!(alerts.len(), alerts_before + 2);
        assert_eq!(
            alerts[alerts_before]["alert"],
            json!("team_incident_received")
        );
        assert_eq!(
            alerts[alerts_before + 1]["alert"],
            json!("team_op_overridden")
        );
    }

    #[test]
    fn round_3dp_matches_python_examples() {
        // These are the classic float/decimal traps, checked against the
        // CPython oracle (`python3.12 -c "round(x, 3)"`):
        // - 2.675 is actually 2.67499999999999982... in binary, so both
        //   Python's round(2.675, 3) and this port give 2.675, not 2.68.
        // - 0.0005 is actually 0.0005000000000000000104... (just above the
        //   halfway point), so both round up to 0.001, not down to 0.0.
        assert_eq!(round_half_even_3dp(2.675), 2.675);
        assert_eq!(round_half_even_3dp(0.0005), 0.001);
        assert_eq!(round_half_even_3dp(-0.0005), -0.001);
        assert_eq!(round_half_even_3dp(0.0015), 0.002);
        assert_eq!(round_half_even_3dp(0.1234), 0.123);
        assert_eq!(round_half_even_3dp(1.0), 1.0);
        assert_eq!(round_half_even_3dp(0.5005), 0.5);
        assert_eq!(round_half_even_3dp(0.1235), 0.123);
    }
}

/// Differential tests against the CPython oracle: the same sequence of
/// `record`/`alert` calls, against a fixed clock, must produce byte-identical
/// `audit/audit.jsonl` and `audit/alerts.jsonl` files whether the caller is
/// Python's `zeropw.audit.Audit` or this port.
#[cfg(test)]
mod oracle_tests {
    use tempfile::TempDir;

    use super::*;
    use crate::clock;
    use crate::oracle;

    #[test]
    fn record_and_alert_lines_are_byte_identical_to_python() {
        let script = r#"
import tempfile, pathlib
from zeropw.audit import Audit
from zeropw.store import StateDir

tmp = tempfile.mkdtemp()
state = StateDir(pathlib.Path(tmp) / "state")
state.create()
audit = Audit(state, lambda: 1700000000.0)

audit.record("http_relay", caller="agent-1", connection="gh", target="127.0.0.1:8080",
             action="GET", result="ok", policy_version=3,
             extra={"path": "/repos?token=x", "status": 200})
audit.record("secret_reveal", caller="admin", connection="gh")
audit.record("http_relay", caller="agent-1", result="denied", reason="grant_revoked")
audit.record("team_incident_received", caller="dev-2", connection="gh")
audit.record("http_relay", target="a\nb\x00c\x7f", reason="x" * 250)
audit.record("incident_open", caller="admin", extra={"scope": "connection", "incident_id": "inc-1"})

print((pathlib.Path(tmp) / "state" / "audit" / "audit.jsonl").read_text(), end="")
print("---ALERTS---")
print((pathlib.Path(tmp) / "state" / "audit" / "alerts.jsonl").read_text(), end="")
"#;
        let py_out = oracle::python(script);
        let (py_audit, py_alerts) = py_out.split_once("---ALERTS---\n").expect("marker present");

        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        let audit = Audit::new(&state, clock::fixed(1700000000.0));

        audit
            .record(
                "http_relay",
                RecordArgs {
                    caller: Some("agent-1"),
                    connection: Some("gh"),
                    target: Some("127.0.0.1:8080"),
                    action: Some("GET"),
                    result: Some("ok"),
                    policy_version: Some(3),
                    extra: vec![("path", json!("/repos?token=x")), ("status", json!(200))],
                    ..Default::default()
                },
            )
            .unwrap();
        audit
            .record(
                "secret_reveal",
                RecordArgs {
                    caller: Some("admin"),
                    connection: Some("gh"),
                    ..Default::default()
                },
            )
            .unwrap();
        audit
            .record(
                "http_relay",
                RecordArgs {
                    caller: Some("agent-1"),
                    result: Some("denied"),
                    reason: Some("grant_revoked"),
                    ..Default::default()
                },
            )
            .unwrap();
        audit
            .record(
                "team_incident_received",
                RecordArgs {
                    caller: Some("dev-2"),
                    connection: Some("gh"),
                    ..Default::default()
                },
            )
            .unwrap();
        let long_reason = "x".repeat(250);
        audit
            .record(
                "http_relay",
                RecordArgs {
                    target: Some("a\nb\x00c\x7f"),
                    reason: Some(&long_reason),
                    ..Default::default()
                },
            )
            .unwrap();
        audit
            .record(
                "incident_open",
                RecordArgs {
                    caller: Some("admin"),
                    extra: vec![
                        ("scope", json!("connection")),
                        ("incident_id", json!("inc-1")),
                    ],
                    ..Default::default()
                },
            )
            .unwrap();

        let rust_audit =
            std::fs::read_to_string(tmp.path().join("state/audit/audit.jsonl")).unwrap();
        let rust_alerts =
            std::fs::read_to_string(tmp.path().join("state/audit/alerts.jsonl")).unwrap();

        assert_eq!(rust_audit, py_audit);
        assert_eq!(rust_alerts, py_alerts);
    }

    // A-5: `incident_open`/`incident_widen` alert detail uses Python's
    // `str()` on `record.get("scope")` (which can be any JSON scalar that
    // survived `_clean`: None, bool, int, float, string) and `reason or
    // "unknown"` truthiness (empty string is falsy). Byte-compares every
    // alert line against the CPython oracle for each scalar kind.
    #[test]
    fn incident_alert_detail_matches_python_for_scope_and_reason_kinds() {
        let script = r#"
import tempfile, pathlib
from zeropw.audit import Audit
from zeropw.store import StateDir

tmp = tempfile.mkdtemp()
state = StateDir(pathlib.Path(tmp) / "state")
state.create()
audit = Audit(state, lambda: 1700000000.0)

audit.record("incident_open", caller="admin", extra={"scope": "connection", "incident_id": "inc-1"})
audit.record("incident_open", caller="admin", extra={"scope": 3, "incident_id": "inc-2"})
audit.record("incident_open", caller="admin", reason="manual", extra={"scope": True, "incident_id": "inc-3"})
audit.record("incident_open", caller="admin", reason="", extra={"scope": False, "incident_id": "inc-4"})
audit.record("incident_open", caller="admin", extra={"scope": 1.5, "incident_id": "inc-5"})
audit.record("incident_open", caller="admin", extra={"incident_id": "inc-6"})
audit.record("incident_widen", caller="admin", extra={"scope": "project", "incident_id": "inc-1"})
audit.record("incident_widen", caller="admin", extra={"scope": None, "incident_id": "inc-1"})

print((pathlib.Path(tmp) / "state" / "audit" / "alerts.jsonl").read_text(), end="")
"#;
        let py_alerts = oracle::python(script);

        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        let audit = Audit::new(&state, clock::fixed(1700000000.0));

        audit
            .record(
                "incident_open",
                RecordArgs {
                    caller: Some("admin"),
                    extra: vec![
                        ("scope", json!("connection")),
                        ("incident_id", json!("inc-1")),
                    ],
                    ..Default::default()
                },
            )
            .unwrap();
        audit
            .record(
                "incident_open",
                RecordArgs {
                    caller: Some("admin"),
                    extra: vec![("scope", json!(3)), ("incident_id", json!("inc-2"))],
                    ..Default::default()
                },
            )
            .unwrap();
        audit
            .record(
                "incident_open",
                RecordArgs {
                    caller: Some("admin"),
                    reason: Some("manual"),
                    extra: vec![("scope", json!(true)), ("incident_id", json!("inc-3"))],
                    ..Default::default()
                },
            )
            .unwrap();
        audit
            .record(
                "incident_open",
                RecordArgs {
                    caller: Some("admin"),
                    reason: Some(""),
                    extra: vec![("scope", json!(false)), ("incident_id", json!("inc-4"))],
                    ..Default::default()
                },
            )
            .unwrap();
        audit
            .record(
                "incident_open",
                RecordArgs {
                    caller: Some("admin"),
                    extra: vec![("scope", json!(1.5)), ("incident_id", json!("inc-5"))],
                    ..Default::default()
                },
            )
            .unwrap();
        audit
            .record(
                "incident_open",
                RecordArgs {
                    caller: Some("admin"),
                    extra: vec![("incident_id", json!("inc-6"))],
                    ..Default::default()
                },
            )
            .unwrap();
        audit
            .record(
                "incident_widen",
                RecordArgs {
                    caller: Some("admin"),
                    extra: vec![("scope", json!("project")), ("incident_id", json!("inc-1"))],
                    ..Default::default()
                },
            )
            .unwrap();
        audit
            .record(
                "incident_widen",
                RecordArgs {
                    caller: Some("admin"),
                    extra: vec![("scope", Value::Null), ("incident_id", json!("inc-1"))],
                    ..Default::default()
                },
            )
            .unwrap();

        let rust_alerts =
            std::fs::read_to_string(tmp.path().join("state/audit/alerts.jsonl")).unwrap();
        assert_eq!(rust_alerts, py_alerts);
    }

    // A-R3-3: `round_half_even_3dp`'s doc comment claims CPython-oracle
    // verification for the classic tie-trap cases; before this test existed
    // that claim was backed only by hardcoded literals
    // (`round_3dp_matches_python_examples`, `super::tests`), not an actual
    // comparison against Python. Run the same trap values (plus a batch of
    // randomized ones) through real `python3.12` `round(x, 3)` and compare.
    #[test]
    fn round_3dp_matches_python_oracle() {
        struct Xorshift64(u64);
        impl Xorshift64 {
            fn next_f64(&mut self) -> f64 {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                // A mix of magnitudes, including many that land near a
                // *.*5 tie at 3 decimal places.
                ((x as i64) as f64 / i64::MAX as f64) * 10_000.0
            }
        }
        let mut values = vec![
            2.675, 0.0005, -0.0005, 0.0015, 0.1234, 1.0, 0.5005, 0.1235, -2.675, -0.1235, 0.0, -0.0,
        ];
        let mut rng = Xorshift64(0xA24BAED4963EE407);
        for _ in 0..200 {
            values.push(rng.next_f64());
        }

        let script = format!("for x in {values:?}:\n    print(repr(round(x, 3)))\n",);
        let output = oracle::python(&script);
        let py_lines: Vec<&str> = output.lines().collect();
        assert_eq!(py_lines.len(), values.len());

        for (x, want) in values.iter().zip(py_lines.iter()) {
            let got = round_half_even_3dp(*x);
            let want: f64 = want.parse().unwrap();
            assert_eq!(
                got.to_bits(),
                want.to_bits(),
                "round_half_even_3dp({x}) = {got}, python round({x}, 3) = {want}"
            );
        }
    }
}
