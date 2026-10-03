//! Compromise response, port of `zeropw/incident.py`.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::sync::{Arc, Weak};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::audit::RecordArgs;
use crate::context::Context;
use crate::errors::{Error, ErrorClass, Result};
use crate::pyjson::{self, DumpOptions};
use crate::signer::SignerManager;
use crate::store::iso;

pub const INCIDENTS_DIR: &str = "incidents";
pub const SCOPES: &[&str] = &["principal", "runtime", "all"];
pub const TRIGGERS: &[&str] = &["manual", "auto"];
pub const MAX_DETAIL_LENGTH: usize = 200;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Incident {
    pub id: String,
    pub opened_at: String,
    pub status: String,
    pub scope: String,
    pub runtime: Option<String>,
    pub principals: Vec<String>,
    pub trigger: String,
    pub rule: Option<String>,
    pub detail: Option<String>,
    pub actions: Value,
    pub assessment: Value,
    pub notification: Value,
    pub closed_at: Option<String>,
    pub widened_from: Vec<Value>,
    #[serde(skip)]
    raw_fields: Map<String, Value>,
}

impl Incident {
    pub fn to_dict(&self) -> Value {
        let mut value = serde_json::to_value(self).unwrap_or(Value::Null);
        if let Some(obj) = value.as_object_mut() {
            for (key, raw) in &self.raw_fields {
                obj.insert(key.clone(), raw.clone());
            }
        }
        value
    }
    pub fn from_dict(data: &Value) -> Result<Self> {
        let obj = data
            .as_object()
            .ok_or_else(|| Error::not_found("incident_corrupt"))?;
        let required = |key: &str| -> Result<String> {
            obj.get(key)
                .map(crate::pystr::repr_value)
                .map(|s| {
                    if let Some(v) = obj.get(key).and_then(Value::as_str) {
                        v.to_owned()
                    } else {
                        s
                    }
                })
                .ok_or_else(|| Error::not_found("incident_corrupt"))
        };
        let principals_raw = python_list(obj.get("principals"))?;
        let mut raw_fields = Map::new();
        for key in ["runtime", "rule", "detail", "closed_at"] {
            if let Some(v) = obj.get(key).filter(|v| !v.is_null() && !v.is_string()) {
                raw_fields.insert(key.into(), v.clone());
            }
        }
        if principals_raw.iter().any(|v| !v.is_string()) {
            raw_fields.insert("principals".into(), Value::Array(principals_raw.clone()));
        }
        Ok(Self {
            id: required("id")?,
            opened_at: required("opened_at")?,
            status: required("status")?,
            scope: required("scope")?,
            runtime: obj
                .get("runtime")
                .and_then(Value::as_str)
                .map(str::to_owned),
            principals: principals_raw.iter().map(python_str).collect(),
            trigger: obj
                .get("trigger")
                .map(python_str)
                .unwrap_or_else(|| "manual".into()),
            rule: obj.get("rule").and_then(Value::as_str).map(str::to_owned),
            detail: obj.get("detail").and_then(Value::as_str).map(str::to_owned),
            actions: python_dict(obj.get("actions"), json!({}))?,
            assessment: python_dict(obj.get("assessment"), json!({}))?,
            notification: python_dict(
                obj.get("notification"),
                json!({"status":"not_configured","attempts":0}),
            )?,
            closed_at: obj
                .get("closed_at")
                .and_then(Value::as_str)
                .map(str::to_owned),
            widened_from: python_list(obj.get("widened_from"))?,
            raw_fields,
        })
    }
}

fn python_str(v: &Value) -> String {
    v.as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| crate::pystr::repr_value(v))
}
/// Python `bool(value)` for a JSON-decoded value.
pub(crate) fn python_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}
fn python_list(v: Option<&Value>) -> Result<Vec<Value>> {
    let Some(v) = v.filter(|v| python_truthy(v)) else {
        return Ok(vec![]);
    };
    match v {
        Value::Array(a) => Ok(a.clone()),
        Value::String(s) => Ok(s.chars().map(|c| json!(c.to_string())).collect()),
        Value::Object(o) => Ok(o.keys().map(|k| json!(k)).collect()),
        _ => Err(Error::not_found("incident_corrupt")),
    }
}
fn python_dict(v: Option<&Value>, default: Value) -> Result<Value> {
    let Some(v) = v.filter(|v| python_truthy(v)) else {
        return Ok(default);
    };
    match v {
        Value::Object(_) => Ok(v.clone()),
        Value::Array(_) => {
            let pairs = crate::team::commit::python_dict_pairs(v)
                .ok_or_else(|| Error::not_found("incident_corrupt"))?;
            let mut merged: Vec<(Value, Value)> = Vec::new();
            for (key, value) in pairs {
                if !crate::team::commit::dict_key_is_hashable(&key) {
                    return Err(Error::not_found("incident_corrupt"));
                }
                if let Some((_, existing)) = merged
                    .iter_mut()
                    .find(|(prior, _)| crate::team::commit::dict_keys_equal(prior, &key))
                {
                    *existing = value;
                } else {
                    merged.push((key, value));
                }
            }
            let mut out = Map::new();
            for (key, value) in merged {
                let key = match key {
                    Value::String(s) => s,
                    Value::Bool(true) => "true".into(),
                    Value::Bool(false) => "false".into(),
                    Value::Null => "null".into(),
                    Value::Number(_) => pyjson::dumps(&key, DumpOptions::plain())
                        .map_err(|_| Error::not_found("incident_corrupt"))?,
                    _ => return Err(Error::not_found("incident_corrupt")),
                };
                out.insert(key, value);
            }
            Ok(Value::Object(out))
        }
        _ => Err(Error::not_found("incident_corrupt")),
    }
}

fn path_for(id: &str) -> String {
    format!("{INCIDENTS_DIR}/{id}.json")
}
fn bounded(value: Option<&str>) -> Option<String> {
    value.map(|v| {
        v.chars()
            .map(|c| {
                if c <= '\u{1f}' || c == '\u{7f}' {
                    '?'
                } else {
                    c
                }
            })
            .take(MAX_DETAIL_LENGTH)
            .collect()
    })
}
fn actions() -> Value {
    json!({"stopped":false,"principals_disabled":0,"grants_revoked":0,"handle_key_rotated":false,"runs_cancelled":0,"sockets_closed":0,"failed_steps":[]})
}
/// `incident.actions.setdefault("failed_steps", [])`, returning the list
/// Python would `.append` to. `None` is a persisted non-list value, on which
/// Python's `.append` raises an uncaught `AttributeError` that aborts the
/// remaining containment steps; containment continues here instead (see
/// `DEVIATIONS.md`, incident hand-edited `actions` shapes).
pub(crate) fn failed_steps(i: &mut Incident) -> Option<&mut Vec<Value>> {
    let actions = i.actions.as_object_mut()?;
    actions
        .entry("failed_steps")
        .or_insert_with(|| json!([]))
        .as_array_mut()
}
/// `incident.actions.setdefault("failed_steps", []).append(step)`.
fn fail(i: &mut Incident, step: impl Into<String>) {
    if let Some(steps) = failed_steps(i) {
        steps.push(json!(step.into()));
    }
}
/// `actions[key] = actions.get(key, 0) + delta` for a persisted counter,
/// with Python's numeric promotion: `bool` counts as `int`, an integer stays
/// exact, a float stays a float. A non-numeric value (Python `TypeError`) is
/// left unchanged, like a non-list `failed_steps`.
fn increment(i: &mut Incident, key: &str, delta: usize) {
    let sum = match i.actions.get(key) {
        None => Some(json!(delta)),
        Some(value @ (Value::Bool(_) | Value::Number(_))) => {
            match crate::pyint::PyInt::from_python_int(value) {
                Some(int) => Some(crate::pyint::PyInt(int.0 + delta).value()),
                None => value.as_f64().map(|float| json!(float + delta as f64)),
            }
        }
        Some(_) => None,
    };
    if let (Some(sum), Some(actions)) = (sum, i.actions.as_object_mut()) {
        actions.insert(key.into(), sum);
    }
}
fn rank(scope: &str) -> Option<usize> {
    SCOPES.iter().position(|s| *s == scope)
}

pub fn save_incident(ctx: &Context, incident: &mut Incident) -> Result<()> {
    let payload = pyjson::dumps(&incident.to_dict(), DumpOptions::default_sorted())
        .map_err(|_| Error::state("state_write_failed"))?;
    if value_leak(ctx, payload.as_bytes()) {
        incident.assessment = json!({"redacted":true});
        if let Some(steps) = failed_steps(incident)
            && !steps.contains(&json!("assessment_redacted"))
        {
            steps.push(json!("assessment_redacted"));
        }
    }
    ctx.state
        .write_json(&path_for(&incident.id), &incident.to_dict())
}

pub fn value_leak(ctx: &Context, payload: &[u8]) -> bool {
    let Ok(values) = ctx.vault.values_for_trusted_scan() else {
        return false;
    };
    values.iter().any(|v| {
        crate::runs::credential_patterns(v.expose())
            .iter()
            .any(|p| !p.is_empty() && payload.windows(p.len()).any(|w| w == p))
    })
}

pub fn get_incident(ctx: &Context, incident_id: &str) -> Result<Incident> {
    let data = ctx.state.read_json(&path_for(incident_id), Value::Null)?;
    if data.is_null() {
        return Err(Error::not_found("incident_not_found"));
    }
    Incident::from_dict(&data)
}

pub fn list_incidents(ctx: &Context) -> Result<Vec<Incident>> {
    let dir = ctx.state.path.join(INCIDENTS_DIR);
    if !dir.is_dir() {
        return Ok(vec![]);
    }
    let mut paths: Vec<_> = fs::read_dir(dir)
        .map_err(|_| Error::state("state_read_failed"))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    let mut out = Vec::new();
    for path in paths {
        let Ok(bytes) = fs::read(path) else { continue };
        let Ok(v) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        if let Ok(i) = Incident::from_dict(&v) {
            out.push(i);
        }
    }
    Ok(out)
}

fn resolve_principals(
    ctx: &Context,
    scope: &str,
    principals: Option<&[String]>,
    runtime: Option<&str>,
) -> Result<Vec<String>> {
    let mut ids: Vec<String> = match scope {
        "principal" => {
            // `None` is what the administrator CLI passes when `--scope
            // principal` has no `--principal`; Python's `cmd_incident_declare`
            // passes `[args.principal]`, i.e. `[None]`, and
            // `ctx.policy.get_principal(None)` reads the principal document
            // and finds no such key. `Some(&[])` stays Python's empty list.
            let Some(ids) = principals else {
                let doc = ctx.state.read_json(crate::policy::PRINCIPALS, json!({}))?;
                if python_truthy(&doc) && !doc.is_object() {
                    // `.get` on a non-dict document: uncaught AttributeError
                    // in Python (PORTING.md §3.5); Policy's own reader
                    // reports this document shape as state_corrupt.
                    return Err(
                        Error::state("state_corrupt").with_detail(crate::policy::PRINCIPALS)
                    );
                }
                return Err(Error::not_found("principal_not_found"));
            };
            if ids.is_empty() {
                return Err(Error::invalid_input("incident_principals_required"));
            }
            for pid in ids {
                ctx.policy.get_principal(pid)?;
            }
            ids.to_vec()
        }
        "runtime" => {
            let r = runtime
                .filter(|r| !r.is_empty())
                .ok_or_else(|| Error::invalid_input("incident_runtime_required"))?;
            ctx.policy
                .principals_in_runtime(r)?
                .into_iter()
                .map(|p| p.id)
                .collect()
        }
        "all" => ctx
            .policy
            .list_principals()?
            .into_iter()
            .map(|p| p.id)
            .collect(),
        _ => return Err(Error::invalid_input("invalid_incident_scope")),
    };
    ids.sort();
    ids.dedup();
    Ok(ids)
}

fn runtime_covers_all_active(ctx: &Context, runtime: Option<&str>) -> bool {
    ctx.policy
        .list_principals()
        .map(|ps| {
            ps.iter()
                .filter(|p| p.status_is("active"))
                .all(|p| p.runtime_eq(runtime))
        })
        // A corrupt/unreadable principal document cannot safely prove that any
        // active principal lies outside this runtime. Over-stop in that case.
        .unwrap_or(true)
}

pub fn apply_lockdown(
    ctx: &Arc<Context>,
    incident: &mut Incident,
    target_ids: &[String],
    scope: &str,
    runtime: Option<&str>,
) {
    failed_steps(incident);
    let ids: BTreeSet<&str> = target_ids.iter().map(String::as_str).collect();
    let registry = crate::runs::registry(ctx);
    let signer = ctx.signer_manager.lock().ok().and_then(|s| {
        s.as_ref()
            .and_then(|v| v.downcast_ref::<Weak<SignerManager>>())
            .and_then(Weak::upgrade)
    });
    let runs_before = registry
        .as_ref()
        .map(|r| {
            r.active_runs()
                .into_iter()
                .filter(|run| ids.contains(run.caller.as_str()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let bindings_before = signer
        .as_ref()
        .map(|m| {
            m.active_bindings()
                .into_iter()
                .filter(|b| ids.contains(b.caller.as_str()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if !python_truthy(&incident.actions["stopped"])
        && (scope == "all" || (scope == "runtime" && runtime_covers_all_active(ctx, runtime)))
    {
        match ctx.policy.stop_all() {
            Ok(()) => incident.actions["stopped"] = json!(true),
            Err(_) => fail(incident, "stop_all"),
        }
    }
    let (mut disabled, mut revoked) = (0, 0);
    for pid in target_ids {
        let active = ctx
            .policy
            .get_principal(pid)
            .is_ok_and(|p| p.status_is("active"));
        match ctx.policy.disable_principal(pid, false) {
            Ok(()) if active => disabled += 1,
            Ok(()) => (),
            Err(_) => fail(incident, format!("disable_principal:{pid}")),
        }
        match ctx.policy.revoke_grants_of(pid) {
            Ok(n) => revoked += n,
            Err(_) => fail(incident, format!("revoke_grants:{pid}")),
        }
    }
    increment(incident, "principals_disabled", disabled);
    increment(incident, "grants_revoked", revoked);
    if (scope == "runtime" || scope == "all")
        && !python_truthy(&incident.actions["handle_key_rotated"])
    {
        match ctx.rotate_handle_key() {
            Ok(()) => incident.actions["handle_key_rotated"] = json!(true),
            Err(_) => fail(incident, "rotate_handle_key"),
        }
    }
    for run in &runs_before {
        if registry
            .as_ref()
            .is_some_and(|r| r.cancel(&run.id, &run.caller, "incident_lockdown").is_err())
        {
            fail(incident, "cancel_runs");
        }
    }
    if !runs_before.is_empty() {
        increment(incident, "runs_cancelled", runs_before.len());
    }
    for binding in &bindings_before {
        if let Some(manager) = &signer {
            manager.release(binding);
        }
    }
    if !bindings_before.is_empty() {
        increment(incident, "sockets_closed", bindings_before.len());
    }
    if registry.is_none() && signer.is_none() {
        incident.actions["applied_by_serve"] = json!(true);
    }
}

fn safe_assess(ctx: &Context, incident: &mut Incident) -> Value {
    match assess(
        ctx,
        &incident.principals,
        &incident.scope,
        &incident.opened_at,
    ) {
        Ok(v) => v,
        Err(_) => {
            fail(incident, "assess");
            incident.assessment.clone()
        }
    }
}

fn audit_incident(
    ctx: &Context,
    event: &str,
    incident: &mut Incident,
    reason: Option<&str>,
) -> Result<()> {
    let record = ctx.audit.record(
        event,
        RecordArgs {
            result: Some("ok"),
            reason,
            extra: vec![
                ("incident_id", json!(incident.id)),
                ("scope", json!(incident.scope)),
                ("runtime", json!(incident.runtime)),
                ("rule", json!(incident.rule)),
            ],
            ..Default::default()
        },
    );
    if let Err(e) = record {
        if e.is(ErrorClass::AuditUnavailable) {
            fail(incident, format!("audit_{event}"));
            save_incident(ctx, incident)?;
        } else {
            return Err(e);
        }
    }
    Ok(())
}

pub fn open_incident(
    ctx: &Arc<Context>,
    scope: &str,
    principals: Option<&[String]>,
    runtime: Option<&str>,
    trigger: &str,
    rule: Option<&str>,
    detail: Option<&str>,
) -> Result<Incident> {
    if rank(scope).is_none() {
        return Err(Error::invalid_input("invalid_incident_scope"));
    }
    if !TRIGGERS.contains(&trigger) {
        return Err(Error::invalid_input("invalid_incident_trigger"));
    }
    if let Some(id) = ctx.policy.open_incident_id()? {
        match get_incident(ctx, &id) {
            Ok(existing) => {
                if rank(scope) > rank(&existing.scope) {
                    return widen_incident(ctx, &id, scope, runtime, principals, rule);
                }
                return Ok(existing);
            }
            Err(e) if e.is(ErrorClass::NotFound) => (),
            Err(e) => return Err(e),
        }
    }
    let resolved = resolve_principals(ctx, scope, principals, runtime)?;
    let mut nonce = [0u8; 4];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::state("state_write_failed"))?;
    let stamp = iso(Some((ctx.clock)())).replace(['-', ':'], "");
    let mut incident = Incident {
        id: format!("inc-{stamp}-{}", hex::encode(nonce)),
        opened_at: iso(Some((ctx.clock)())),
        status: "open".into(),
        scope: scope.into(),
        runtime: runtime.map(str::to_owned),
        principals: resolved.clone(),
        trigger: trigger.into(),
        rule: bounded(rule),
        detail: bounded(detail),
        actions: actions(),
        assessment: json!({}),
        notification: json!({"status":"not_configured","attempts":0}),
        closed_at: None,
        widened_from: vec![],
        raw_fields: Map::new(),
    };
    save_incident(ctx, &mut incident)?;
    ctx.policy.set_open_incident(Some(&incident.id))?;
    apply_lockdown(ctx, &mut incident, &resolved, scope, runtime);
    incident.assessment = safe_assess(ctx, &mut incident);
    if crate::notify::deliver(ctx, &mut incident).is_err() {
        fail(&mut incident, "notify");
    }
    save_incident(ctx, &mut incident)?;
    let audit_reason = incident.trigger.clone();
    audit_incident(ctx, "incident_open", &mut incident, Some(&audit_reason))?;
    Ok(incident)
}

pub fn widen_incident(
    ctx: &Arc<Context>,
    incident_id: &str,
    scope: &str,
    runtime: Option<&str>,
    principals: Option<&[String]>,
    rule: Option<&str>,
) -> Result<Incident> {
    let mut incident = get_incident(ctx, incident_id)?;
    if incident.status != "open" {
        return Err(Error::invalid_input("incident_not_open"));
    }
    if rank(scope).is_none() || rank(scope) <= rank(&incident.scope) {
        return Err(Error::invalid_input("incident_scope_not_wider"));
    }
    let resolved = resolve_principals(ctx, scope, principals, runtime)?;
    let old: BTreeSet<String> = incident.principals.iter().cloned().collect();
    let added: Vec<String> = resolved
        .iter()
        .filter(|p| !old.contains(*p))
        .cloned()
        .collect();
    incident.widened_from.push(
        json!({"scope":incident.scope,"runtime":incident.runtime,"at":iso(Some((ctx.clock)()))}),
    );
    incident.scope = scope.into();
    incident.runtime = runtime.map(str::to_owned);
    incident.raw_fields.remove("runtime");
    if rule.is_some_and(|s| !s.is_empty()) {
        incident.rule = bounded(rule);
        incident.raw_fields.remove("rule");
    }
    incident.principals.extend(resolved);
    incident.principals.sort();
    incident.principals.dedup();
    incident.raw_fields.remove("principals");
    apply_lockdown(ctx, &mut incident, &added, scope, runtime);
    incident.assessment = safe_assess(ctx, &mut incident);
    if crate::notify::deliver(ctx, &mut incident).is_err() {
        fail(&mut incident, "notify");
    }
    save_incident(ctx, &mut incident)?;
    audit_incident(ctx, "incident_widen", &mut incident, Some("widen"))?;
    Ok(incident)
}

pub fn close_incident(ctx: &Arc<Context>, incident_id: &str) -> Result<Incident> {
    let mut incident = get_incident(ctx, incident_id)?;
    if incident.status == "closed" {
        return Err(Error::invalid_input("incident_already_closed"));
    }
    incident.status = "closed".into();
    incident.closed_at = Some(iso(Some((ctx.clock)())));
    incident.raw_fields.remove("closed_at");
    save_incident(ctx, &mut incident)?;
    if ctx.policy.open_incident_id()?.as_deref() == Some(&incident.id) {
        ctx.policy.set_open_incident(None)?;
    }
    audit_incident(ctx, "incident_close", &mut incident, None)?;
    Ok(incident)
}

fn new_secret_entry(meta: &crate::vault::SecretMeta, service: Option<&str>) -> Value {
    let mut entry = json!({"secret_id":meta.id,"kind":meta.kind,"project":meta.project,"environment":meta.environment,"service":service,"connections":[],"targets":[],"first_used":null,"last_used":null,"use_count":0,"active_version":meta.active_version.clone(),"tier":"none"});
    if meta.kind == "ssh_private_key" {
        entry["fingerprint"] = meta
            .versions
            .iter()
            .find(|v| {
                meta.active_version
                    .as_ref()
                    .is_some_and(|active| active.equals_integer(&v.version))
            })
            .and_then(|v| v.public.get("fingerprint"))
            // `_fingerprint`: `fingerprint if isinstance(fingerprint, str) else None`.
            .filter(|fingerprint| fingerprint.is_string())
            .cloned()
            .unwrap_or(Value::Null);
    }
    entry
}
fn merge_ts(current: &mut Value, candidate: &str, newest: bool) {
    if current.as_str().is_none_or(|old| {
        if newest {
            candidate > old
        } else {
            candidate < old
        }
    }) {
        *current = json!(candidate);
    }
}
pub fn assess(ctx: &Context, principals: &[String], scope: &str, since: &str) -> Result<Value> {
    let mut starts = BTreeMap::new();
    let mut principal_views = vec![];
    for pid in principals {
        match ctx.policy.get_principal(pid) {
            Ok(p) => {
                starts.insert(pid.clone(), p.created_at.clone());
                principal_views
                    .push(json!({"id":p.id,"created_at":p.created_at_value(),"runtime":p.runtime_value()}));
            }
            Err(e) if e.is(ErrorClass::NotFound) => (),
            Err(e) => return Err(e),
        }
    }
    let mut uses: BTreeMap<String, (String, String, usize)> = BTreeMap::new();
    for record in ctx.audit.iter_records()? {
        let Some(caller) = record.get("caller").and_then(Value::as_str) else {
            continue;
        };
        let Some(start) = starts.get(caller) else {
            continue;
        };
        if !["http_relay", "ssh_sign", "run_start"]
            .contains(&record["event"].as_str().unwrap_or(""))
            || record["result"] != "ok"
        {
            continue;
        }
        let (Some(ts), Some(cid)) = (record["ts"].as_str(), record["connection"].as_str()) else {
            continue;
        };
        if ts < start {
            continue;
        }
        let entry = uses
            .entry(cid.to_owned())
            .or_insert((ts.into(), ts.into(), 0));
        if ts < entry.0.as_str() {
            entry.0 = ts.into()
        }
        if ts > entry.1.as_str() {
            entry.1 = ts.into()
        }
        entry.2 += 1;
    }
    let mut held = BTreeSet::new();
    for pid in starts.keys() {
        for grant in ctx.policy.list_grants(Some(pid))? {
            if grant.status == "active"
                || grant.status == "stale"
                || (grant.status == "revoked"
                    && grant.revoked_at.as_deref().is_some_and(|t| t >= since))
            {
                held.insert(grant.connection);
            }
        }
    }
    let mut secrets: BTreeMap<String, Value> = BTreeMap::new();
    for cid in uses
        .keys()
        .chain(held.iter())
        .cloned()
        .collect::<BTreeSet<_>>()
    {
        let c = match ctx.policy.get_connection(&cid) {
            Ok(c) => c,
            Err(e) if e.is(ErrorClass::NotFound) => continue,
            Err(e) => return Err(e),
        };
        if !secrets.contains_key(&c.secret_id) {
            let meta = ctx.vault.get_meta(&c.secret_id)?;
            secrets.insert(
                c.secret_id.clone(),
                new_secret_entry(&meta, Some(&c.service)),
            );
        }
        let entry = secrets
            .get_mut(&c.secret_id)
            .ok_or_else(|| Error::state("state_corrupt"))?;
        entry["connections"]
            .as_array_mut()
            .unwrap()
            .push(json!(cid));
        let target = if c.kind == "http" {
            c.http_target
                .as_ref()
                .map(|t| json!({"host":t.host,"port":t.port}))
        } else {
            c.ssh_target
                .as_ref()
                .map(|t| json!({"host":t.host,"port":t.port,"username":t.username}))
        };
        entry["targets"]
            .as_array_mut()
            .unwrap()
            .push(target.unwrap_or(json!({})));
        if let Some((first, last, count)) = uses.get(&cid) {
            merge_ts(&mut entry["first_used"], first, false);
            merge_ts(&mut entry["last_used"], last, true);
            entry["use_count"] = json!(entry["use_count"].as_u64().unwrap_or(0) + *count as u64);
            entry["tier"] = json!("mandatory");
        } else if entry["tier"] == "none" {
            entry["tier"] = json!("recommended");
        }
    }
    let mut result = json!({"principals":principal_views,"secrets":[]});
    if scope == "all" {
        for meta in ctx.vault.list_secrets(None, None)? {
            if meta.active_version.is_none() {
                continue;
            }
            let entry = secrets
                .entry(meta.id.clone())
                .or_insert_with(|| new_secret_entry(&meta, None));
            entry["tier"] = json!("mandatory");
            entry["recover_required"] = json!(true);
        }
        result["recover_required"] = json!(true);
    }
    result["secrets"] = Value::Array(secrets.into_values().collect());
    Ok(result)
}
