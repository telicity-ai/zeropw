//! Original response boundaries plus byte-for-byte rendering recorded from
//! the Python prototype.
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use zeropw::{
    audit::RecordArgs,
    context::{Config, Context},
    incident,
    intrusion::{self, DetectorConfig},
    notify,
    policy::{Connection, HttpAuth, HttpScope, HttpTarget},
};

/// The original detector rule table: every `(event, result, reason)`
/// combination that matched a rule in the Python prototype, with its rule
/// and strength (`fixtures/python/response/denial_rules.json`).
#[test]
fn every_rule_combination_matches_original_python_table_and_nonmatches() {
    let table: Value =
        serde_json::from_str(include_str!("fixtures/python/response/denial_rules.json")).unwrap();
    let strings = |key: &str| -> Vec<String> {
        table[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    };
    let matches: std::collections::HashMap<(String, String, String), Value> = table["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            (
                (
                    m[0].as_str().unwrap().to_owned(),
                    m[1].as_str().unwrap().to_owned(),
                    m[2].as_str().unwrap().to_owned(),
                ),
                json!([m[3], m[4]]),
            )
        })
        .collect();
    assert!(!matches.is_empty());
    let mut checked = 0;
    for e in strings("events") {
        for r in strings("results") {
            for why in strings("reasons") {
                let got = intrusion::match_denial_rule(Some(&e), Some(&r), Some(&why))
                    .map(|(rule, strength)| json!([rule, strength]))
                    .unwrap_or(json!([null, null]));
                let want = matches
                    .get(&(e.clone(), r.clone(), why.clone()))
                    .cloned()
                    .unwrap_or(json!([null, null]));
                assert_eq!(got, want, "{e} {r} {why}");
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 1250);
}

/// Incident email subject and body for each scope, exactly as the original
/// rendered them for the same incident documents
/// (`fixtures/python/response/scope_emails.json`).
#[test]
fn all_scope_email_bodies_match_original_python_exactly() {
    let cases: Value =
        serde_json::from_str(include_str!("fixtures/python/response/scope_emails.json")).unwrap();
    assert_eq!(cases.as_array().unwrap().len(), 3);
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

#[test]
fn assessment_distinguishes_used_held_and_never_granted_secrets() {
    let (_tmp, ctx, time) = fixture(json!({}), 1);
    for (id, granted) in [("held", true), ("ungranted", false)] {
        ctx.vault
            .put_secret(
                id,
                "api_key",
                format!("synthetic-{id}-0123456789").as_bytes(),
                "demo",
                "dev",
                true,
            )
            .unwrap();
        let mut c = ctx.policy.get_connection("c0").unwrap();
        c.id = id.into();
        c.secret_id = id.into();
        ctx.policy.create_connection(c).unwrap();
        if granted {
            ctx.policy
                .create_grant("agent", id, Some(3600), None)
                .unwrap();
        }
    }
    let principal = ctx.policy.get_principal("agent").unwrap();
    time.fetch_sub(10, Ordering::SeqCst);
    event(&ctx, "http_relay", Some("agent"), Some("c0"), "ok", None);
    time.fetch_add(15, Ordering::SeqCst);
    event(&ctx, "http_relay", Some("agent"), Some("c0"), "ok", None);
    let assessment = incident::assess(
        &ctx,
        &["agent".into()],
        "principal",
        &zeropw::store::iso(Some((ctx.clock)())),
    )
    .unwrap();
    let secrets = assessment["secrets"].as_array().unwrap();
    assert_eq!(secrets.len(), 2);
    let used = secrets.iter().find(|s| s["secret_id"] == "key").unwrap();
    assert_eq!(used["tier"], "mandatory");
    assert_eq!(used["use_count"], 1);
    assert_eq!(
        secrets.iter().find(|s| s["secret_id"] == "held").unwrap()["tier"],
        "recommended"
    );
    assert!(!secrets.iter().any(|s| s["secret_id"] == "ungranted"));
    assert_eq!(
        assessment["principals"],
        json!([{"id":"agent","created_at":principal.created_at,"runtime":"runtime"}])
    );
}

#[test]
fn assessment_merges_two_principals_into_one_mandatory_secret() {
    let (_tmp, ctx, time) = fixture(json!({}), 1);
    ctx.policy.create_principal("agent-2", "runtime").unwrap();
    ctx.policy
        .create_grant("agent-2", "c0", Some(3600), None)
        .unwrap();
    time.fetch_add(1, Ordering::SeqCst);
    event(&ctx, "http_relay", Some("agent-2"), Some("c0"), "ok", None);
    let assessment = incident::assess(
        &ctx,
        &["agent".into(), "agent-2".into()],
        "principal",
        &zeropw::store::iso(Some((ctx.clock)())),
    )
    .unwrap();
    assert_eq!(assessment["principals"].as_array().unwrap().len(), 2);
    assert_eq!(assessment["secrets"].as_array().unwrap().len(), 1);
    assert_eq!(assessment["secrets"][0]["secret_id"], "key");
    assert_eq!(assessment["secrets"][0]["tier"], "mandatory");
    assert_eq!(assessment["secrets"][0]["use_count"], 1);
    assert_eq!(assessment["secrets"][0]["connections"], json!(["c0"]));
}
