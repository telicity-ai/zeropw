//! Behavioural ports of incident/intrusion/notify cases using synthetic values.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    thread,
};

use serde_json::{Value, json};
use tempfile::TempDir;
use zeropw::audit::RecordArgs;
use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::incident;
use zeropw::intrusion::{self, DetectorConfig};
use zeropw::notify;
use zeropw::policy::{Connection, HttpAuth, HttpScope, HttpTarget, SshTarget};
use zeropw::projects;
use zeropw::runs;
use zeropw::signer;
use zeropw::sshwire;

const SECRET: &[u8] = b"synthetic-token-0123456789";
fn fixture() -> (TempDir, Arc<Context>) {
    let tmp = TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            tmp.path().join("state"),
            "admin-passphrase-1",
            "recovery-passphrase-1",
            Config {
                socket_dir: Some(tmp.path().join("socket")),
                run_dir: Some(tmp.path().join("run")),
                ..Config::default()
            },
            clock::fixed(1_700_000_000.0),
        )
        .unwrap(),
    );
    ctx.projects
        .create("demo", projects::DEFAULT_ENVIRONMENTS)
        .unwrap();
    ctx.vault
        .put_secret("gh-token", "api_key", SECRET, "demo", "dev", true)
        .unwrap();
    (tmp, ctx)
}
fn connection(id: &str, secret: &str) -> Connection {
    Connection::new(
        id,
        "demo",
        "dev",
        "fake-service",
        "http",
        secret,
        None,
        "",
        Some(HttpTarget::new("http", "127.0.0.1", 8080, None, false).unwrap()),
        Some(HttpAuth::bearer()),
        Some(HttpScope::new(None, None, vec![]).unwrap()),
        None,
        None,
        0,
        "active",
        "",
        "",
    )
    .unwrap()
}
fn setup_grant(ctx: &Context, pid: &str, cid: &str) {
    ctx.policy
        .create_connection(connection(cid, "gh-token"))
        .unwrap();
    ctx.policy.create_grant(pid, cid, Some(3600), None).unwrap();
}
fn open(
    ctx: &Arc<Context>,
    scope: &str,
    principals: Option<&[String]>,
    runtime: Option<&str>,
) -> incident::Incident {
    incident::open_incident(ctx, scope, principals, runtime, "manual", None, None).unwrap()
}

#[test]
fn principal_scope_disables_only_selected_and_keeps_other_handle_key() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    ctx.policy.create_principal("agent-2", "box-2").unwrap();
    setup_grant(&ctx, "agent-1", "gh");
    let before = ctx.state.read_bytes("policy/handle.key").unwrap();
    let i = open(&ctx, "principal", Some(&["agent-1".into()]), None);
    assert_eq!(i.actions["principals_disabled"], 1);
    assert_eq!(i.actions["grants_revoked"], 1);
    assert_eq!(
        ctx.policy.get_principal("agent-1").unwrap().status,
        "disabled"
    );
    assert_eq!(
        ctx.policy.get_principal("agent-2").unwrap().status,
        "active"
    );
    assert!(!ctx.policy.is_stopped().unwrap());
    assert_eq!(before, ctx.state.read_bytes("policy/handle.key").unwrap());
    assert_eq!(i.assessment["secrets"][0]["tier"], "recommended");
    assert_eq!(
        i.notification,
        json!({"status":"not_configured","attempts":0})
    );
    assert!(i.actions["applied_by_serve"] == true);
}

#[test]
fn runtime_scope_rotates_key_and_stops_only_when_covering_every_active_principal() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    ctx.policy.create_principal("agent-2", "box-2").unwrap();
    let before = ctx.state.read_bytes("policy/handle.key").unwrap();
    let i = open(&ctx, "runtime", None, Some("box-1"));
    assert_eq!(i.principals, vec!["agent-1"]);
    assert!(!ctx.policy.is_stopped().unwrap());
    assert_eq!(i.actions["handle_key_rotated"], true);
    assert_ne!(before, ctx.state.read_bytes("policy/handle.key").unwrap());
    incident::close_incident(&ctx, &i.id).unwrap();
    let (_tmp2, ctx2) = fixture();
    ctx2.policy.create_principal("agent-1", "box-1").unwrap();
    let all_runtime = open(&ctx2, "runtime", None, Some("box-1"));
    assert_eq!(all_runtime.actions["stopped"], true);
    assert!(ctx2.policy.is_stopped().unwrap());
}

#[test]
fn widening_adds_principals_and_close_does_not_resume() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    ctx.policy.create_principal("agent-2", "box-1").unwrap();
    let i = open(&ctx, "principal", Some(&["agent-1".into()]), None);
    let same = open(&ctx, "principal", Some(&["agent-2".into()]), None);
    assert_eq!(same.id, i.id);
    assert_eq!(same.principals, vec!["agent-1"]);
    let wider = incident::widen_incident(
        &ctx,
        &i.id,
        "runtime",
        Some("box-1"),
        None,
        Some("signer_misuse"),
    )
    .unwrap();
    assert_eq!(wider.principals, vec!["agent-1", "agent-2"]);
    assert_eq!(wider.actions["principals_disabled"], 2);
    assert_eq!(wider.widened_from.len(), 1);
    assert_eq!(
        incident::get_incident(&ctx, &i.id).unwrap().scope,
        "runtime"
    );
    assert!(incident::widen_incident(&ctx, &i.id, "principal", None, None, None).is_err());
    let closed = incident::close_incident(&ctx, &i.id).unwrap();
    assert_eq!(closed.status, "closed");
    assert_eq!(ctx.policy.open_incident_id().unwrap(), None);
    assert!(ctx.policy.is_stopped().unwrap());
}

#[test]
fn lockdown_reapplication_is_idempotent_and_rotation_failure_continues() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    ctx.policy.create_principal("agent-2", "box-1").unwrap();
    setup_grant(&ctx, "agent-1", "gh");
    let mut i = open(&ctx, "principal", Some(&["agent-1".into()]), None);
    let before = i.actions.clone();
    incident::apply_lockdown(&ctx, &mut i, &["agent-1".into()], "principal", None);
    assert_eq!(
        i.actions["principals_disabled"],
        before["principals_disabled"]
    );
    assert_eq!(i.actions["grants_revoked"], before["grants_revoked"]);

    let key_path = ctx.state.path.join("policy/handle.key");
    fs::rename(&key_path, key_path.with_extension("saved")).unwrap();
    fs::create_dir(&key_path).unwrap();
    let widened =
        incident::widen_incident(&ctx, &i.id, "runtime", Some("box-1"), None, None).unwrap();
    assert_eq!(widened.actions["handle_key_rotated"], false);
    assert!(
        widened.actions["failed_steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s == "rotate_handle_key")
    );
    assert_eq!(
        ctx.policy.get_principal("agent-2").unwrap().status,
        "disabled"
    );
    assert_eq!(widened.actions["principals_disabled"], 2);
}

#[test]
fn widening_keeps_previously_held_secret_recommended() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    ctx.policy.create_principal("agent-2", "box-1").unwrap();
    setup_grant(&ctx, "agent-2", "gh");
    let i = open(&ctx, "principal", Some(&["agent-1".into()]), None);
    assert!(i.assessment["secrets"].as_array().unwrap().is_empty());
    let wider =
        incident::widen_incident(&ctx, &i.id, "runtime", Some("box-1"), None, None).unwrap();
    assert_eq!(wider.assessment["secrets"][0]["secret_id"], "gh-token");
    assert_eq!(wider.assessment["secrets"][0]["tier"], "recommended");
}

#[test]
fn ssh_assessment_carries_fingerprint_target_and_mandatory_tier() {
    let (_tmp, ctx) = fixture();
    let key = sshwire::generate_ed25519_private_key("test");
    ctx.vault
        .put_secret(
            "ssh-key",
            "ssh_private_key",
            key.to_openssh_private_key().as_bytes(),
            "demo",
            "dev",
            true,
        )
        .unwrap();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    let host_key = key.public.to_authorized_key("test").unwrap();
    let conn = Connection::new(
        "box",
        "demo",
        "dev",
        "box-service",
        "ssh",
        "ssh-key",
        None,
        "",
        None,
        None,
        None,
        Some(SshTarget::new("127.0.0.1", 2222, "deploy", vec![host_key]).unwrap()),
        None,
        0,
        "active",
        "",
        "",
    )
    .unwrap();
    ctx.policy.create_connection(conn).unwrap();
    let grant = ctx
        .policy
        .create_grant("agent-1", "box", Some(3600), None)
        .unwrap();
    let manager = signer::install(ctx.clone(), None).unwrap();
    let binding = manager.bind("agent-1", "box", &grant.id).unwrap();
    assert!(binding.socket_path.exists());
    ctx.audit
        .record(
            "ssh_sign",
            RecordArgs {
                caller: Some("agent-1"),
                connection: Some("box"),
                result: Some("ok"),
                ..Default::default()
            },
        )
        .unwrap();
    let i = open(&ctx, "principal", Some(&["agent-1".into()]), None);
    let secret = &i.assessment["secrets"][0];
    assert_eq!(secret["tier"], "mandatory");
    assert_eq!(secret["secret_id"], "ssh-key");
    assert!(
        secret["fingerprint"]
            .as_str()
            .is_some_and(|s| s.starts_with("SHA256:"))
    );
    assert_eq!(secret["targets"][0]["username"], "deploy");
    assert_eq!(secret["targets"][0]["port"], 2222);
    assert!(manager.active_bindings().is_empty());
    assert!(!binding.socket_path.exists());
    manager.shutdown();
}

#[test]
fn assessment_ignores_audit_use_before_principal_creation() {
    let tmp = TempDir::new().unwrap();
    let ticks = Arc::new(AtomicU64::new(1_700_000_000));
    let clock_ticks = ticks.clone();
    let ctx = Arc::new(
        Context::initialize(
            tmp.path().join("state"),
            "admin-passphrase-1",
            "recovery-passphrase-1",
            Config::default(),
            Arc::new(move || clock_ticks.load(Ordering::Relaxed) as f64),
        )
        .unwrap(),
    );
    ctx.projects
        .create("demo", projects::DEFAULT_ENVIRONMENTS)
        .unwrap();
    ctx.vault
        .put_secret("gh-token", "api_key", SECRET, "demo", "dev", true)
        .unwrap();
    ctx.policy
        .create_connection(connection("gh", "gh-token"))
        .unwrap();
    ctx.audit
        .record(
            "http_relay",
            RecordArgs {
                caller: Some("agent-1"),
                connection: Some("gh"),
                result: Some("ok"),
                ..Default::default()
            },
        )
        .unwrap();
    ticks.store(1_700_000_060, Ordering::Relaxed);
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    ctx.policy
        .create_grant("agent-1", "gh", Some(3600), None)
        .unwrap();
    let i = open(&ctx, "principal", Some(&["agent-1".into()]), None);
    assert_eq!(i.assessment["secrets"][0]["tier"], "recommended");
    assert_eq!(i.assessment["secrets"][0]["use_count"], 0);
}

#[test]
fn detector_install_is_idempotent_and_decision_failure_is_counted() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    let detector = intrusion::install(ctx.clone(), None).unwrap();
    let same = intrusion::install(ctx.clone(), None).unwrap();
    assert!(Arc::ptr_eq(&detector, &same));
    let record = json!({"event":"tools_unknown","caller":"missing-agent","result":"denied"});
    for _ in 0..2 {
        detector.on_record(record.as_object().unwrap());
    }
    assert_eq!(detector.decision_errors.load(Ordering::Relaxed), 1);
    let valid = json!({"event":"tools_unknown","caller":"agent-1","result":"denied"});
    for _ in 0..2 {
        detector.on_record(valid.as_object().unwrap());
    }
    assert!(ctx.policy.open_incident_id().unwrap().is_some());
}

#[test]
fn concurrent_detector_trips_open_one_incident_without_reentrancy() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    let detector = intrusion::install(ctx.clone(), None).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let ctx = ctx.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                ctx.audit
                    .record(
                        "tools_unknown",
                        RecordArgs {
                            caller: Some("agent-1"),
                            result: Some("denied"),
                            ..Default::default()
                        },
                    )
                    .unwrap();
            })
        })
        .collect();
    barrier.wait();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(incident::list_incidents(&ctx).unwrap().len(), 1);
    assert_eq!(detector.decision_errors.load(Ordering::Relaxed), 0);
}

#[test]
fn principal_lockdown_cancels_only_its_live_run() {
    let (tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    ctx.policy.create_principal("agent-2", "box-2").unwrap();
    let registry = runs::install(ctx.clone());
    let spawn = |caller: &str| {
        let run = registry.create(
            caller, "gh", "grant", "http", "sh", None, "digest", None, None,
        );
        registry
            .start(
                &run,
                &["/bin/sh".into(), "-c".into(), "sleep 30".into()],
                &HashMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
                tmp.path(),
                &[],
                None,
                Some(60.0),
            )
            .unwrap();
        run
    };
    let owned = spawn("agent-1");
    let other = spawn("agent-2");
    let i = open(&ctx, "principal", Some(&["agent-1".into()]), None);
    assert_eq!(i.actions["runs_cancelled"], 1);
    assert_eq!(registry.wait(&owned, Some(2.0)).state, "cancelled");
    assert_eq!(registry.get(&other.id, "agent-2").unwrap().state, "running");
    registry
        .cancel(&other.id, "agent-2", "test_cleanup")
        .unwrap();
}

#[test]
fn audit_use_makes_secret_mandatory_and_incident_file_has_no_value() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    setup_grant(&ctx, "agent-1", "gh");
    ctx.audit
        .record(
            "http_relay",
            RecordArgs {
                caller: Some("agent-1"),
                connection: Some("gh"),
                result: Some("ok"),
                ..Default::default()
            },
        )
        .unwrap();
    let i = open(&ctx, "principal", Some(&["agent-1".into()]), None);
    assert_eq!(i.assessment["secrets"][0]["tier"], "mandatory");
    assert_eq!(i.assessment["secrets"][0]["use_count"], 1);
    let bytes = ctx
        .state
        .read_bytes(&format!("incidents/{}.json", i.id))
        .unwrap();
    assert!(!bytes.windows(SECRET.len()).any(|w| w == SECRET));
}

#[test]
fn all_scope_marks_every_active_secret_mandatory() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    let i = open(&ctx, "all", None, None);
    assert_eq!(i.assessment["recover_required"], true);
    assert_eq!(i.assessment["secrets"][0]["tier"], "mandatory");
    assert_eq!(i.assessment["secrets"][0]["recover_required"], true);
}

#[test]
fn strong_detector_is_synchronous_and_scope_aware() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    let _d = intrusion::install(Arc::clone(&ctx), None).unwrap();
    let denial = || {
        ctx.audit
            .record(
                "tools_unknown",
                RecordArgs {
                    caller: Some("agent-1"),
                    result: Some("denied"),
                    reason: Some("tool_not_found"),
                    ..Default::default()
                },
            )
            .unwrap()
    };
    denial();
    assert_eq!(ctx.policy.open_incident_id().unwrap(), None);
    denial();
    let id = ctx.policy.open_incident_id().unwrap().unwrap();
    let i = incident::get_incident(&ctx, &id).unwrap();
    assert_eq!(i.scope, "principal");
    assert_eq!(i.rule.as_deref(), Some("unknown_tool"));
    assert_eq!(
        ctx.policy.get_principal("agent-1").unwrap().status,
        "disabled"
    );
}

#[test]
fn signer_signal_and_unattributed_forgery_scopes() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    ctx.policy.create_principal("agent-2", "box-2").unwrap();
    let _d = intrusion::install(Arc::clone(&ctx), None).unwrap();
    ctx.audit
        .record(
            "ssh_sign",
            RecordArgs {
                caller: Some("agent-1"),
                result: Some("denied"),
                reason: Some("no_session_bind"),
                ..Default::default()
            },
        )
        .unwrap();
    let id = ctx.policy.open_incident_id().unwrap().unwrap();
    assert_eq!(incident::get_incident(&ctx, &id).unwrap().scope, "runtime");
    let (_tmp2, ctx2) = fixture();
    ctx2.policy.create_principal("agent-1", "box-1").unwrap();
    ctx2.policy.create_principal("agent-2", "box-2").unwrap();
    let _d2 = intrusion::install(Arc::clone(&ctx2), None).unwrap();
    for _ in 0..2 {
        ctx2.audit
            .record(
                "http_relay",
                RecordArgs {
                    result: Some("denied"),
                    reason: Some("handle_signature"),
                    ..Default::default()
                },
            )
            .unwrap();
    }
    let i =
        incident::get_incident(&ctx2, &ctx2.policy.open_incident_id().unwrap().unwrap()).unwrap();
    assert_eq!(i.scope, "principal");
    assert_eq!(i.principals, vec!["agent-1", "agent-2"]);
}

#[test]
fn config_merges_thresholds_and_rejects_disabled_strong_rule() {
    let c = DetectorConfig::from_mapping(Some(
        &json!({"weak_threshold":5,"strong_thresholds":{"unknown_tool":3}}),
    ))
    .unwrap();
    assert_eq!(c.strong_thresholds["signer_misuse"], 1);
    assert_eq!(c.strong_thresholds["unknown_tool"], 3);
    for value in [
        json!(0),
        json!(-1),
        Value::Null,
        json!(1.5),
        json!(true),
        json!("2"),
    ] {
        assert_eq!(
            DetectorConfig::from_mapping(Some(
                &json!({"strong_thresholds":{"unknown_tool":value}})
            ))
            .unwrap_err()
            .reason,
            "intrusion_strong_threshold_invalid"
        );
    }
}

#[test]
fn weak_signals_accumulate_but_global_stop_does_not_score() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    let _detector = intrusion::install(Arc::clone(&ctx), None).unwrap();
    for _ in 0..10 {
        ctx.audit
            .record(
                "tools_request",
                RecordArgs {
                    caller: Some("agent-1"),
                    result: Some("denied"),
                    reason: Some("global_stop"),
                    ..Default::default()
                },
            )
            .unwrap();
    }
    assert_eq!(ctx.policy.open_incident_id().unwrap(), None);
    for reason in ["no_grant", "no_grant", "grant_revoked", "path_not_allowed"] {
        ctx.audit
            .record(
                "tools_request",
                RecordArgs {
                    caller: Some("agent-1"),
                    result: Some("denied"),
                    reason: Some(reason),
                    ..Default::default()
                },
            )
            .unwrap();
    }
    let id = ctx.policy.open_incident_id().unwrap().unwrap();
    assert_eq!(
        incident::get_incident(&ctx, &id).unwrap().rule.as_deref(),
        Some("scope_violation")
    );
}

#[test]
fn enumeration_counts_first_uses_and_burst_ignores_status_polling() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    for n in 1..=4 {
        let cid = format!("c{n}");
        ctx.policy
            .create_connection(connection(&cid, "gh-token"))
            .unwrap();
        ctx.policy
            .create_grant("agent-1", &cid, Some(3600), None)
            .unwrap();
    }
    let cfg = DetectorConfig {
        weak_threshold: 4.into(),
        burst_count: 100.into(),
        ..DetectorConfig::default()
    };
    let _detector = intrusion::install(Arc::clone(&ctx), Some(cfg)).unwrap();
    for _ in 0..100 {
        ctx.audit
            .record(
                "tools_status",
                RecordArgs {
                    caller: Some("agent-1"),
                    result: Some("ok"),
                    ..Default::default()
                },
            )
            .unwrap();
    }
    assert_eq!(ctx.policy.open_incident_id().unwrap(), None);
    for n in 1..=3 {
        let cid = format!("c{n}");
        ctx.audit
            .record(
                "tools_request",
                RecordArgs {
                    caller: Some("agent-1"),
                    connection: Some(&cid),
                    result: Some("ok"),
                    ..Default::default()
                },
            )
            .unwrap();
    }
    assert_eq!(ctx.policy.open_incident_id().unwrap(), None);
    ctx.audit
        .record(
            "tools_request",
            RecordArgs {
                caller: Some("agent-1"),
                connection: Some("c4"),
                result: Some("ok"),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        incident::get_incident(&ctx, &ctx.policy.open_incident_id().unwrap().unwrap())
            .unwrap()
            .rule
            .as_deref(),
        Some("enumeration")
    );
}

#[test]
fn burst_fires_once_when_crossing_limit_not_on_every_later_record() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    let cfg = DetectorConfig {
        weak_threshold: 2.into(),
        burst_count: 2.into(),
        ..DetectorConfig::default()
    };
    let _detector = intrusion::install(ctx.clone(), Some(cfg)).unwrap();
    let request = || {
        ctx.audit
            .record(
                "tools_request",
                RecordArgs {
                    caller: Some("agent-1"),
                    result: Some("ok"),
                    ..Default::default()
                },
            )
            .unwrap()
    };
    request();
    request();
    assert_eq!(ctx.policy.open_incident_id().unwrap(), None);
    request();
    let id = ctx.policy.open_incident_id().unwrap().unwrap();
    assert_eq!(
        incident::get_incident(&ctx, &id).unwrap().rule.as_deref(),
        Some("burst")
    );
    incident::close_incident(&ctx, &id).unwrap();
    request();
    request();
    assert_eq!(ctx.policy.open_incident_id().unwrap(), None);
}

#[test]
fn two_callers_with_http_signals_escalate_to_runtime() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    ctx.policy.create_principal("agent-2", "box-1").unwrap();
    let cfg = DetectorConfig {
        weak_threshold: 3.into(),
        ..DetectorConfig::default()
    };
    let _detector = intrusion::install(Arc::clone(&ctx), Some(cfg)).unwrap();
    for pid in ["agent-1", "agent-2"] {
        ctx.audit
            .record(
                "tools_request",
                RecordArgs {
                    caller: Some(pid),
                    result: Some("denied"),
                    reason: Some("grant_revoked"),
                    ..Default::default()
                },
            )
            .unwrap();
    }
    let id = ctx.policy.open_incident_id().unwrap().unwrap();
    let i = incident::get_incident(&ctx, &id).unwrap();
    assert_eq!(i.scope, "runtime");
    assert_eq!(i.principals, vec!["agent-1", "agent-2"]);
}

#[test]
fn email_render_has_ordered_sections_and_no_detail_or_value() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    let mut i = open(&ctx, "all", None, None);
    i.detail = Some("do not render me".into());
    let (subject, body) = notify::render_incident_email(&i, "2023-11-14T22:13:20Z");
    assert!(subject.contains(&i.id));
    let mut previous = 0;
    for n in 1..=6 {
        let found = body.find(&format!("{n}. ")).unwrap();
        assert!(found >= previous);
        previous = found;
    }
    assert!(body.contains("recover"));
    assert!(body.contains("공급자 콘솔"));
    assert!(!body.contains("do not render me"));
    assert!(!body.contains(std::str::from_utf8(SECRET).unwrap()));
}

fn smtp_server(listener: TcpListener, plain_auth: bool) -> thread::JoinHandle<(String, Vec<u8>)> {
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        stream.write_all(b"220 fake ready\r\n").unwrap();
        let mut auth = String::new();
        let mut message = vec![];
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }
            if line.starts_with("EHLO") {
                stream
                    .write_all(if plain_auth {
                        b"250-fake\r\n250-AUTH PLAIN\r\n250 OK\r\n"
                    } else {
                        b"250-fake\r\n250-AUTH LOGIN\r\n250 OK\r\n"
                    })
                    .unwrap();
            } else if line.starts_with("AUTH PLAIN ") {
                auth = line.trim().to_owned();
                stream.write_all(b"235 authenticated\r\n").unwrap();
            } else if line.starts_with("AUTH LOGIN") {
                if line.trim() == "AUTH LOGIN" {
                    stream.write_all(b"334 VXNlcm5hbWU6\r\n").unwrap();
                } else {
                    auth = line.trim().to_owned();
                    stream.write_all(b"334 UGFzc3dvcmQ6\r\n").unwrap();
                }
            } else if line.starts_with("MAIL FROM") || line.starts_with("RCPT TO") {
                stream.write_all(b"250 OK\r\n").unwrap();
            } else if line.starts_with("DATA") {
                stream.write_all(b"354 send\r\n").unwrap();
                loop {
                    let mut data = Vec::new();
                    reader.read_until(b'\n', &mut data).unwrap();
                    if data == b".\r\n" {
                        break;
                    }
                    message.extend(data);
                }
                stream.write_all(b"250 OK\r\n").unwrap();
            } else if line.starts_with("QUIT") {
                stream.write_all(b"221 bye\r\n").unwrap();
                break;
            } else if auth.is_empty() {
                auth = line.trim().to_owned();
                stream.write_all(b"334 UGFzc3dvcmQ6\r\n").unwrap();
            } else {
                auth.push(':');
                auth.push_str(line.trim());
                stream.write_all(b"235 authenticated\r\n").unwrap();
            }
        }
        (auth, message)
    })
}

#[test]
fn smtp_transport_failure_names_track_the_failing_phase() {
    for (phase, expected) in [
        ("greeting", "SMTPConnectError"),
        ("sender", "SMTPSenderRefused"),
        ("recipient", "SMTPRecipientsRefused"),
        ("data", "SMTPDataError"),
        ("disconnect", "SMTPServerDisconnected"),
        // Measured with original `notify._send` and a loopback peer that
        // withholds DATA's reply past a 0.1s socket timeout: smtplib.getreply
        // wraps the read's TimeoutError as SMTPServerDisconnected.
        ("timeout", "SMTPServerDisconnected"),
    ] {
        let (tmp, ctx) = fixture();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let phase = phase.to_owned();
        let receiver_phase = phase.clone();
        let receiver = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            if receiver_phase == "greeting" {
                stream.write_all(b"554 unavailable\r\n").unwrap();
                return;
            }
            stream.write_all(b"220 ready\r\n").unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                if line.starts_with("EHLO") {
                    stream.write_all(b"250 ready\r\n").unwrap();
                } else if line.starts_with("MAIL FROM") {
                    if receiver_phase == "sender" {
                        stream.write_all(b"550 no\r\n").unwrap();
                        break;
                    }
                    stream.write_all(b"250 ok\r\n").unwrap();
                } else if line.starts_with("RCPT TO") {
                    if receiver_phase == "recipient" {
                        stream.write_all(b"550 no\r\n").unwrap();
                        break;
                    }
                    stream.write_all(b"250 ok\r\n").unwrap();
                } else if line.starts_with("DATA") {
                    if receiver_phase == "data" {
                        stream.write_all(b"554 no\r\n").unwrap();
                        break;
                    }
                    if receiver_phase == "disconnect" {
                        break;
                    }
                    thread::sleep(std::time::Duration::from_millis(250));
                    break;
                }
            }
        });
        ctx.state.write_json("notify.json", &json!({"host":"127.0.0.1","port":port,"mode":"plain","sender":"sender@example.com","recipients":["admin@example.com"],"timeout_seconds":0.1})).unwrap();
        let result = notify::send_test_message(&ctx).unwrap();
        assert_eq!(result["error"], expected, "{phase}");
        receiver.join().unwrap();
        drop(tmp);
    }
}

#[test]
fn smtp_delivery_uses_password_file_and_marks_sent_without_logging_password() {
    let (tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    let mut i = open(&ctx, "principal", Some(&["agent-1".into()]), None);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let receiver = smtp_server(listener, false);
    let pw = tmp.path().join("smtp.pass");
    fs::write(&pw, "synthetic-smtp-password-0123456789\n").unwrap();
    fs::set_permissions(&pw, fs::Permissions::from_mode(0o600)).unwrap();
    let cfg = json!({"host":"127.0.0.1","port":port,"mode":"plain","sender":"zeropw@example.com","recipients":["admin@example.com"],"username":"smtpuser","password_file":pw.to_str().unwrap()});
    ctx.state.write_json("notify.json", &cfg).unwrap();
    notify::deliver(&ctx, &mut i).unwrap();
    assert_eq!(i.notification["status"], "sent");
    let (auth, message) = receiver.join().unwrap();
    assert!(auth.contains("c210cHVzZXI="));
    assert!(auth.contains("c3ludGhldGljLXNtdHAtcGFzc3dvcmQtMDEyMzQ1Njc4OQ=="));
    let msg = String::from_utf8(message).unwrap();
    assert!(msg.contains("Content-Transfer-Encoding: base64"));
    let incident_bytes = ctx
        .state
        .read_bytes(&format!("incidents/{}.json", i.id))
        .unwrap();
    assert!(
        !incident_bytes
            .windows(23)
            .any(|w| w == b"synthetic-smtp-password")
    );
}

#[test]
fn smtp_plain_auth_only_server_is_supported() {
    let (tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    let mut i = open(&ctx, "principal", Some(&["agent-1".into()]), None);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let receiver = smtp_server(listener, true);
    let pw = tmp.path().join("smtp.pass");
    fs::write(&pw, "synthetic-smtp-password-0123456789\n").unwrap();
    fs::set_permissions(&pw, fs::Permissions::from_mode(0o600)).unwrap();
    ctx.state.write_json("notify.json",&json!({"host":"127.0.0.1","port":port,"mode":"plain","sender":"zeropw@example.com","recipients":["admin@example.com"],"username":"smtpuser","password_file":pw.to_str().unwrap()})).unwrap();
    notify::deliver(&ctx, &mut i).unwrap();
    assert_eq!(i.notification["status"], "sent");
    let (auth, message) = receiver.join().unwrap();
    assert!(auth.starts_with("AUTH PLAIN "));
    assert!(!message.is_empty());
}

#[test]
fn failed_smtp_delivery_goes_pending_and_due_retry_sends() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    let mut i = open(&ctx, "principal", Some(&["agent-1".into()]), None);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    ctx.state.write_json("notify.json",&json!({"host":"127.0.0.1","port":port,"mode":"plain","sender":"zeropw@example.com","recipients":["admin@example.com"]})).unwrap();
    notify::deliver(&ctx, &mut i).unwrap();
    assert_eq!(i.notification["status"], "pending");
    assert_eq!(i.notification["attempts"], 1);
    assert_eq!(notify::retry_pending(&ctx, 1_700_000_000.0).unwrap(), 0);
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let receiver = smtp_server(listener, false);
    assert_eq!(notify::retry_pending(&ctx, 1_700_000_400.0).unwrap(), 1);
    assert_eq!(
        incident::get_incident(&ctx, &i.id).unwrap().notification["status"],
        "sent"
    );
    let (_, message) = receiver.join().unwrap();
    assert!(!message.is_empty());
}

#[test]
fn insecure_notify_config_is_pending_and_never_sends() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    fs::write(ctx.state.path.join("notify.json"), b"{}").unwrap();
    fs::set_permissions(
        ctx.state.path.join("notify.json"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let i = open(&ctx, "principal", Some(&["agent-1".into()]), None);
    assert_eq!(i.notification["status"], "pending");
    assert_eq!(i.notification["last_error"], "notify_config_insecure");
    assert_eq!(i.notification["attempts"], 1);
}

#[test]
fn notify_config_rejects_header_and_smtp_command_injection() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    ctx.state.write_json("notify.json",&json!({"host":"127.0.0.1","port":25,"mode":"plain","sender":"zeropw@example.com\r\nBcc: attacker@example.com","recipients":["admin@example.com"]})).unwrap();
    assert_eq!(
        notify::NotifyConfig::load(&ctx).unwrap_err().reason,
        "notify_config_invalid"
    );
}

#[test]
fn rendered_value_leak_blocks_delivery_without_opening_socket() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    let mut i = open(&ctx, "principal", Some(&["agent-1".into()]), None);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    ctx.state.write_json("notify.json",&json!({"host":"127.0.0.1","port":port,"mode":"plain","sender":"zeropw@example.com","recipients":["admin@example.com"]})).unwrap();
    i.rule = Some(std::str::from_utf8(SECRET).unwrap().into());
    notify::deliver(&ctx, &mut i).unwrap();
    assert_eq!(i.notification["status"], "failed");
    assert_eq!(i.notification["reason"], "rendered_value_detected");
    listener.set_nonblocking(true).unwrap();
    assert!(listener.accept().is_err());
    let stored = incident::get_incident(&ctx, &i.id).unwrap();
    assert_eq!(stored.assessment, json!({"redacted":true}));
}
