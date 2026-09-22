//! Original response boundaries plus byte-for-byte Python rendering oracles.
use serde_json::{Value, json};
use std::{
    path::Path,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use zeropw::{
    audit::RecordArgs,
    context::{Config, Context},
    incident,
    intrusion::{self, DetectorConfig},
    notify,
    policy::{Connection, HttpAuth, HttpScope, HttpTarget},
};

fn python(script: &str) -> Value {
    let result = Command::new("python3.12")
        .args(["-c", script])
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

#[test]
fn every_rule_combination_matches_original_python_table_and_nonmatches() {
    let events = [
        "tools_unknown",
        "http_relay",
        "ssh_agent_refused",
        "ssh_bind",
        "ssh_sign",
        "run_finish",
        "tools_request",
        "tools_exec",
        "tools_status",
        "unmatched",
    ];
    let results = ["ok", "denied", "blocked", "cancelled", ""];
    let reasons = [
        "tool_not_found",
        "handle_signature",
        "handle_malformed",
        "handle_version",
        "handle_expired",
        "unsupported_agent_message",
        "unsupported_extension",
        "agent_forwarding_not_allowed",
        "not_userauth_request",
        "no_session_bind",
        "unsupported_sign_flags",
        "output_credential_blocked",
        "grant_revoked",
        "grant_stale",
        "principal_disabled",
        "method_not_allowed",
        "path_not_allowed",
        "approval_required",
        "no_grant",
        "grant_unknown",
        "connection_unknown",
        "global_stop",
        "restore_pending",
        "cancelled_by_caller",
        "",
    ];
    let mut cases = Vec::new();
    for e in events {
        for r in results {
            for why in reasons {
                cases.push(json!([e, r, why]));
            }
        }
    }
    let expected = python(&format!(
        "import json\nfrom zeropw.intrusion import _match_denial_rule\ncases={}\nprint(json.dumps([_match_denial_rule(*c) for c in cases]))",
        json!(cases)
    ));
    for (input, want) in cases.iter().zip(expected.as_array().unwrap()) {
        let got =
            intrusion::match_denial_rule(input[0].as_str(), input[1].as_str(), input[2].as_str());
        let got = got
            .map(|(rule, strength)| json!([rule, strength]))
            .unwrap_or(json!([null, null]));
        assert_eq!(&got, want, "{input}");
    }
}

#[test]
fn all_scope_email_bodies_match_original_python_exactly() {
    let cases = python(
        r#"
import json
from tests.test_notify import NotifyTestCase
from zeropw.notify import render_incident_email
out=[]
for scope in ('principal','runtime','all'):
 case=NotifyTestCase(); case.setUp()
 try:
  i=case.build_incident(scope=scope,incident_runtime='default' if scope=='runtime' else None)
  out.append([i.to_dict(),render_incident_email(i,now='2026-09-16T00:00:00Z')])
 finally: case.doCleanups()
print(json.dumps(out))
"#,
    );
    for case in cases.as_array().unwrap() {
        let incident = incident::Incident::from_dict(&case[0]).unwrap();
        let (subject, body) = notify::render_incident_email(&incident, "2026-09-16T00:00:00Z");
        assert_eq!(json!([subject, body]), case[1], "scope {}", incident.scope);
        assert!(!body.contains("http://") && !body.contains("https://"));
        assert!(!body.contains("synthetic-") && !body.contains("zpw1.") && !body.contains("zpwc_"));
    }
}

fn fixture(config: Value, connections: usize) -> (tempfile::TempDir, Arc<Context>, Arc<AtomicU64>) {
    let tmp = tempfile::tempdir().unwrap();
    let time = Arc::new(AtomicU64::new(1_700_000_000));
    let clock = time.clone();
    let ctx = Arc::new(
        Context::initialize(
            tmp.path().join("state"),
            "synthetic-admin-pass",
            "synthetic-recovery-pass",
            Config {
                intrusion: Some(config),
                ..Default::default()
            },
            Arc::new(move || clock.load(Ordering::SeqCst) as f64),
        )
        .unwrap(),
    );
    ctx.projects
        .create("demo", zeropw::projects::DEFAULT_ENVIRONMENTS)
        .unwrap();
    ctx.policy.create_principal("agent", "runtime").unwrap();
    ctx.vault
        .put_secret(
            "key",
            "api_key",
            b"synthetic-response-edge-secret-012345",
            "demo",
            "dev",
            true,
        )
        .unwrap();
    for number in 0..connections {
        let id = format!("c{number}");
        let c = Connection::new(
            &id,
            "demo",
            "dev",
            "service",
            "http",
            "key",
            None,
            "",
            Some(HttpTarget::new("http", "127.0.0.1", 9, None, false).unwrap()),
            Some(HttpAuth::bearer()),
            Some(HttpScope::new(None, None, vec![]).unwrap()),
            None,
            None,
            0,
            "active",
            "",
            "",
        )
        .unwrap();
        ctx.policy.create_connection(c).unwrap();
        ctx.policy
            .create_grant("agent", &id, Some(3600), None)
            .unwrap();
    }
    // Deliberately discard the return value: protection belongs to Context.
    intrusion::install(ctx.clone(), None).unwrap();
    (tmp, ctx, time)
}
fn event(
    ctx: &Context,
    name: &str,
    caller: Option<&str>,
    connection: Option<&str>,
    result: &str,
    reason: Option<&str>,
) {
    ctx.audit
        .record(
            name,
            RecordArgs {
                caller,
                connection,
                result: Some(result),
                reason,
                ..Default::default()
            },
        )
        .unwrap();
}

#[test]
fn weak_window_expiry_and_unattributed_expired_handle_preserve_boundaries() {
    let (_tmp, ctx, time) = fixture(
        json!({"window_seconds":60,"weak_points":{"unauthorized_connection":4}}),
        0,
    );
    event(
        &ctx,
        "tools_request",
        Some("agent"),
        Some("unknown"),
        "denied",
        Some("no_grant"),
    );
    assert!(ctx.policy.open_incident_id().unwrap().is_none());
    time.fetch_add(61, Ordering::SeqCst);
    event(
        &ctx,
        "tools_request",
        Some("agent"),
        Some("unknown"),
        "denied",
        Some("no_grant"),
    );
    assert!(ctx.policy.open_incident_id().unwrap().is_none());
    event(
        &ctx,
        "tools_request",
        Some("agent"),
        Some("unknown"),
        "denied",
        Some("no_grant"),
    );
    assert!(ctx.policy.open_incident_id().unwrap().is_some());
    let (_tmp, ctx, _) = fixture(json!({"weak_threshold":3}), 0);
    for _ in 0..2 {
        event(
            &ctx,
            "http_relay",
            None,
            None,
            "denied",
            Some("handle_expired"),
        );
    }
    assert!(ctx.policy.open_incident_id().unwrap().is_none());
    event(
        &ctx,
        "http_relay",
        None,
        None,
        "denied",
        Some("handle_expired"),
    );
    let id = ctx.policy.open_incident_id().unwrap().unwrap();
    assert_eq!(
        incident::get_incident(&ctx, &id).unwrap().rule.as_deref(),
        Some("handle_forgery_unattributed")
    );
}

#[test]
fn enumeration_first_use_is_lifetime_and_combined_signals_still_trip() {
    let (_tmp, ctx, time) = fixture(
        json!({"window_seconds":60,"weak_threshold":4,"enumeration_min":4,"enumeration_ratio":0.5}),
        10,
    );
    event(&ctx, "http_relay", Some("agent"), Some("c0"), "ok", None);
    time.fetch_add(61, Ordering::SeqCst);
    for id in ["c1", "c2", "c3", "c0"] {
        event(&ctx, "http_relay", Some("agent"), Some(id), "ok", None);
    }
    assert!(ctx.policy.open_incident_id().unwrap().is_none());
    event(&ctx, "http_relay", Some("agent"), Some("c4"), "ok", None);
    assert!(
        ctx.policy.open_incident_id().unwrap().is_none(),
        "four fresh uses don't reach half of ten"
    );
    event(&ctx, "http_relay", Some("agent"), Some("c5"), "ok", None);
    assert!(ctx.policy.open_incident_id().unwrap().is_some());

    let (_tmp, ctx, _) = fixture(
        json!({"burst_count":4,"enumeration_min":4,"enumeration_ratio":0.5}),
        8,
    );
    for id in ["c0", "c1", "c2", "c3"] {
        event(&ctx, "http_relay", Some("agent"), Some(id), "ok", None);
    }
    assert!(ctx.policy.open_incident_id().unwrap().is_none());
    event(
        &ctx,
        "tools_request",
        Some("agent"),
        Some("unknown"),
        "denied",
        Some("no_grant"),
    );
    assert!(ctx.policy.open_incident_id().unwrap().is_some());
}

#[test]
fn normal_business_use_and_status_polling_never_score_as_burst() {
    let (_tmp, ctx, _) = fixture(json!({}), 8);
    event(
        &ctx,
        "tools_list_connections",
        Some("agent"),
        None,
        "ok",
        None,
    );
    for id in ["c0", "c1", "c2", "c3", "c4", "c5"] {
        event(&ctx, "http_relay", Some("agent"), Some(id), "ok", None);
    }
    event(&ctx, "tools_exec", Some("agent"), Some("c0"), "ok", None);
    for _ in 0..100 {
        event(&ctx, "tools_status", Some("agent"), None, "ok", None);
    }
    assert!(ctx.policy.open_incident_id().unwrap().is_none());
}

#[test]
fn invalid_threshold_variants_never_disable_required_rules() {
    for bad in [
        json!(0),
        json!(-1),
        Value::Null,
        json!(1.5),
        json!(true),
        json!("2"),
    ] {
        assert_eq!(
            DetectorConfig::from_mapping(Some(&json!({"strong_thresholds":{"unknown_tool":bad}})))
                .unwrap_err()
                .reason,
            "intrusion_strong_threshold_invalid"
        );
    }
    for config in [
        json!({"weak_threshold":0}),
        json!({"window_seconds":0}),
        json!({"enumeration_ratio":0}),
        json!({"burst_count":-5}),
    ] {
        assert!(DetectorConfig::from_mapping(Some(&config)).is_err());
    }
    let config = DetectorConfig::from_mapping(Some(
        &json!({"weak_threshold":5,"strong_thresholds":{"unknown_tool":3}}),
    ))
    .unwrap();
    assert_eq!(config.strong_thresholds["unknown_tool"], 3);
    assert_eq!(config.strong_thresholds["signer_misuse"], 1);
    assert_eq!(config.weak_threshold, 5);
}
