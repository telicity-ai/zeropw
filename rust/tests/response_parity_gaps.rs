//! Response parity gaps: each test pins one Python behaviour of
//! `zeropw/{incident,intrusion,notify}.py` (and `smtplib` as used there) that
//! the Rust port previously diverged from. Synthetic values and loopback only.
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use serde_json::{Value, json};
use tempfile::TempDir;
use zeropw::audit::RecordArgs;
use zeropw::clock::{self, Clock};
use zeropw::context::{Config, Context};
use zeropw::intrusion;

#[path = "../src/oracle.rs"]
#[allow(dead_code)]
mod oracle;

fn fixture_with_clock(clock: Clock) -> (TempDir, Arc<Context>) {
    let tmp = TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            tmp.path().join("state"),
            "synthetic-admin-passphrase",
            "synthetic-recovery-passphrase",
            Config {
                socket_dir: Some(tmp.path().join("sockets")),
                run_dir: Some(tmp.path().join("runs")),
                ..Config::default()
            },
            clock,
        )
        .unwrap(),
    );
    (tmp, ctx)
}

fn unknown_tool(ctx: &Context, caller: &str) {
    ctx.audit
        .record(
            "tools_unknown",
            RecordArgs {
                caller: Some(caller),
                result: Some("denied"),
                reason: Some("tool_not_found"),
                ..Default::default()
            },
        )
        .unwrap();
}

/// Python `test_a_failing_open_incident_is_counted_not_raised`: an exception
/// inside `_apply_decision` increments `decision_errors` and the very next
/// crossing still opens an incident. In Rust the equivalent failure is a
/// panic inside `open_incident`; it must neither escape nor poison the
/// decision lock (which silently disabled every later trip).
#[test]
fn panic_inside_the_decision_is_counted_and_detection_keeps_working() {
    // A clock that panics on its N-th call once armed. The arming listener is
    // subscribed before the detector, so on the tripping record the detector
    // reads the clock once (`now`) and `open_incident` reads it next.
    let countdown = Arc::new(AtomicI64::new(0));
    let clock_countdown = Arc::clone(&countdown);
    let clock: Clock = Arc::new(move || {
        if clock_countdown.load(Ordering::SeqCst) > 0
            && clock_countdown.fetch_sub(1, Ordering::SeqCst) == 1
        {
            panic!("synthetic failure inside the intrusion decision");
        }
        1_700_000_000.0
    });
    let (_tmp, ctx) = fixture_with_clock(clock);
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    let arm = Arc::new(AtomicI64::new(0));
    let (listener_arm, listener_countdown) = (Arc::clone(&arm), Arc::clone(&countdown));
    ctx.audit.subscribe(move |record| {
        if record.get("event").and_then(Value::as_str) == Some("tools_unknown")
            && listener_arm.swap(0, Ordering::SeqCst) == 1
        {
            listener_countdown.store(2, Ordering::SeqCst);
        }
    });
    let detector = intrusion::install(Arc::clone(&ctx), None).unwrap();

    unknown_tool(&ctx, "agent-1");
    arm.store(1, Ordering::SeqCst);
    unknown_tool(&ctx, "agent-1"); // trips unknown_tool; open_incident panics
    assert_eq!(countdown.load(Ordering::SeqCst), 0, "the panic was reached");
    assert_eq!(detector.decision_errors.load(Ordering::SeqCst), 1);
    assert!(
        ctx.policy.open_incident_id().unwrap().is_none(),
        "the failed decision must not have left anything open"
    );

    unknown_tool(&ctx, "agent-1");
    let open = ctx.policy.open_incident_id().unwrap();
    assert!(
        open.is_some(),
        "the next crossing must still open an incident"
    );
    let incident = zeropw::incident::get_incident(&ctx, &open.unwrap()).unwrap();
    assert_eq!(incident.principals, vec!["agent-1".to_owned()]);
    assert_eq!(incident.rule.as_deref(), Some("unknown_tool"));
    assert_eq!(detector.decision_errors.load(Ordering::SeqCst), 1);
}

/// `DetectorConfig.__post_init__` validates strong -> weak -> window ->
/// weak_threshold -> enumeration_min -> enumeration_ratio -> burst_count.
/// Every pair of differently invalid fields (wrong type or out of range)
/// must report the same first reason as Python.
#[test]
fn detector_config_reports_invalid_fields_in_python_order() {
    let invalid: Vec<(&str, Value)> = vec![
        ("strong_thresholds", json!({"unknown_tool": "2"})),
        ("strong_thresholds", json!({"signer_misuse": 0})),
        ("weak_points", json!({"burst": 1.5})),
        ("weak_points", json!({"revoked_use": -1})),
        ("window_seconds", json!("120")),
        ("window_seconds", json!(true)),
        ("window_seconds", json!(0)),
        ("weak_threshold", json!(2.0)),
        ("weak_threshold", json!(0)),
        ("enumeration_min", json!(null)),
        ("enumeration_min", json!(0)),
        ("enumeration_ratio", json!([0.5])),
        ("enumeration_ratio", json!(1.5)),
        ("burst_count", json!("60")),
        ("burst_count", json!(-3)),
    ];
    let mut configs = vec![];
    for (i, (key_a, value_a)) in invalid.iter().enumerate() {
        for (key_b, value_b) in invalid.iter().skip(i + 1) {
            if key_a != key_b {
                configs.push(json!({ *key_a: value_a, *key_b: value_b }));
            }
        }
    }
    let script = format!(
        "import json\nfrom zeropw.errors import InvalidInput\nfrom zeropw.intrusion import DetectorConfig\nout=[]\nfor c in json.loads({:?}):\n    try:\n        DetectorConfig.from_mapping(c)\n        out.append(None)\n    except InvalidInput as e:\n        out.append(e.reason)\nprint(json.dumps(out))\n",
        Value::Array(configs.clone()).to_string()
    );
    let expected: Vec<Option<String>> =
        serde_json::from_str(oracle::python(&script).trim()).unwrap();
    for (config, expected) in configs.iter().zip(expected) {
        let actual = intrusion::DetectorConfig::from_mapping(Some(config))
            .err()
            .map(|e| e.reason.to_string());
        assert_eq!(actual, expected, "config {config}");
    }
}

fn fixture() -> (TempDir, Arc<Context>) {
    fixture_with_clock(clock::fixed(1_700_000_000.0))
}

fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    fs::set_permissions(dst, fs::metadata(src).unwrap().permissions()).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let target = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}

fn edit_incident_actions(ctx: &Context, id: &str, actions: Value) {
    let path = format!("incidents/{id}.json");
    let mut doc = ctx.state.read_json(&path, Value::Null).unwrap();
    doc["actions"] = actions;
    ctx.state.write_json(&path, &doc).unwrap();
}

/// `_apply_lockdown` starts with `actions.setdefault("failed_steps", [])`,
/// always adds `principals_disabled`/`grants_revoked` with Python numeric
/// promotion (`True + 1 == 2`, a float stays a float), touches
/// `runs_cancelled`/`sockets_closed` only when something was cancelled, and
/// tests `stopped`/`handle_key_rotated` by truthiness. A legacy or
/// hand-edited `actions` document must widen exactly like Python's.
#[test]
fn widening_a_hand_edited_incident_updates_actions_like_python() {
    let (tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    ctx.policy.create_principal("agent-2", "box-1").unwrap();
    ctx.policy.create_principal("agent-3", "box-2").unwrap();
    let opened = zeropw::incident::open_incident(
        &ctx,
        "principal",
        Some(&["agent-1".to_owned()]),
        None,
        "manual",
        None,
        None,
    )
    .unwrap();
    edit_incident_actions(
        &ctx,
        &opened.id,
        json!({"stopped": 1, "principals_disabled": true, "grants_revoked": 1.5,
               "runs_cancelled": "legacy", "handle_key_rotated": 0}),
    );
    let python_state = tmp.path().join("python-state");
    copy_dir(&tmp.path().join("state"), &python_state);

    let widened =
        zeropw::incident::widen_incident(&ctx, &opened.id, "runtime", Some("box-1"), None, None)
            .unwrap();
    let script = format!(
        "import json\nfrom zeropw.context import Context\nfrom zeropw import incident as I\nc=Context.open({:?})\ninc=I.widen_incident(c, {:?}, scope='runtime', runtime='box-1')\nprint(json.dumps(inc.to_dict()['actions']))\n",
        python_state.to_str().unwrap(),
        opened.id
    );
    let python: Value = serde_json::from_str(oracle::python(&script).trim()).unwrap();
    assert_eq!(widened.to_dict()["actions"], python);
    assert_eq!(python["principals_disabled"], json!(2));
    assert_eq!(python["failed_steps"], json!([]));
}

/// `_audit_incident` records an unavailable audit log with
/// `actions.setdefault("failed_steps", []).append(...)`, so an incident whose
/// `actions` has no `failed_steps` list still records the failed step.
#[test]
fn close_with_unavailable_audit_records_the_step_without_a_prior_list() {
    let (tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    let opened = zeropw::incident::open_incident(
        &ctx,
        "principal",
        Some(&["agent-1".to_owned()]),
        None,
        "manual",
        None,
        None,
    )
    .unwrap();
    edit_incident_actions(&ctx, &opened.id, json!({"stopped": false}));
    let audit_log = tmp.path().join("state/audit/audit.jsonl");
    fs::remove_file(&audit_log).unwrap();
    fs::create_dir(&audit_log).unwrap();
    let python_state = tmp.path().join("python-state");
    copy_dir(&tmp.path().join("state"), &python_state);

    let closed = zeropw::incident::close_incident(&ctx, &opened.id).unwrap();
    let script = format!(
        "import json\nfrom zeropw.context import Context\nfrom zeropw import incident as I\nc=Context.open({:?})\ninc=I.close_incident(c, {:?})\nprint(json.dumps(inc.to_dict()['actions']))\n",
        python_state.to_str().unwrap(),
        opened.id
    );
    let python: Value = serde_json::from_str(oracle::python(&script).trim()).unwrap();
    assert_eq!(python["failed_steps"], json!(["audit_incident_close"]));
    assert_eq!(closed.to_dict()["actions"], python);
}

fn admin_cli(language: &str, state: &Path, args: &[&str]) -> (i32, Value) {
    let mut command = if language == "python" {
        let mut command = Command::new(
            std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".to_string()),
        );
        command
            .args(["-m", "zeropw.admin_cli"])
            .env("PYTHONPATH", oracle::repo_root())
            .env("PYTHONDONTWRITEBYTECODE", "1");
        command
    } else {
        Command::new(env!("CARGO_BIN_EXE_zeropw-admin"))
    };
    let output = command
        .arg("--state-dir")
        .arg(state)
        .args(args)
        .env("ZEROPW_ADMIN_PASSPHRASE", "synthetic-admin-passphrase")
        .env(
            "ZEROPW_RECOVERY_PASSPHRASE",
            "synthetic-recovery-passphrase",
        )
        .output()
        .unwrap();
    let text = if output.status.success() {
        output.stdout
    } else {
        output.stderr
    };
    let text = String::from_utf8(text).unwrap();
    let last = text.lines().last().unwrap_or_default().to_owned();
    (
        output.status.code().unwrap_or(-1),
        serde_json::from_str(&last).unwrap_or(Value::String(text)),
    )
}

/// `incident declare --scope principal` without `--principal`: Python passes
/// `principals=[None]`, so `get_principal(None)` fails `principal_not_found`
/// rather than `incident_principals_required`.
#[test]
fn declare_principal_scope_without_principal_matches_python_cli() {
    let tmp = TempDir::new().unwrap();
    let mut results = vec![];
    for language in ["python", "rust"] {
        let state = tmp.path().join(language);
        let (code, _) = admin_cli(language, &state, &["init"]);
        assert_eq!(code, 0, "{language} init");
        let (_, created) = admin_cli(
            language,
            &state,
            &[
                "principal",
                "create",
                "--id",
                "agent-1",
                "--runtime",
                "box-1",
            ],
        );
        assert!(created.get("error").is_none(), "{created}");
        results.push(admin_cli(
            language,
            &state,
            &["incident", "declare", "--scope", "principal"],
        ));
    }
    assert_eq!(results[0].1["reason"], json!("principal_not_found"));
    assert_eq!(results[1], results[0]);
}

/// `render_incident_email` skips a falsy runtime/rule, uses `x or default`
/// for first/last use, service, creation time and fingerprint, renders
/// `.get(key, 0)` values with `str()`, and tests flags by truthiness. Loaded
/// (legacy or hand-edited) incidents must render byte-identically.
#[test]
fn email_rendering_follows_python_truthiness_for_loaded_incidents() {
    let base = json!({
        "id": "inc-20231114T221320Z-0123abcd", "opened_at": "2023-11-14T22:13:20Z",
        "status": "open", "scope": "principal", "principals": ["agent-1"],
        "trigger": "manual", "detail": null, "closed_at": null, "widened_from": [],
        "notification": {"status": "not_configured", "attempts": 0},
        "actions": {"stopped": false, "principals_disabled": 1, "grants_revoked": 0,
                    "handle_key_rotated": false, "runs_cancelled": 0, "sockets_closed": 0,
                    "failed_steps": []},
        "assessment": {"principals": [{"id": "agent-1", "created_at": "2023-11-14T22:00:00Z"}],
                       "secrets": []}
    });
    let mandatory = json!({
        "secret_id": "deploy-key", "kind": "ssh_private_key", "project": "demo",
        "environment": "dev", "service": "", "connections": "ab",
        "targets": [{"host": 7, "port": null, "username": 0},
                    {"host": "box.example", "port": 22, "username": "deploy"}, "not-a-dict"],
        "first_used": "", "last_used": 0, "use_count": 2.5, "active_version": 1,
        "fingerprint": "", "tier": "mandatory"
    });
    let mut cases = vec![];
    for (runtime, rule) in [
        (json!(""), json!("")),
        (json!(null), json!(null)),
        (json!(5), json!(["x"])),
        (json!("box-1"), json!("unknown_tool")),
    ] {
        let mut case = base.clone();
        case["runtime"] = runtime;
        case["rule"] = rule;
        cases.push(case);
    }
    let mut case = base.clone();
    case["runtime"] = json!(null);
    case["rule"] = json!(null);
    case["actions"] = json!({"stopped": 1, "principals_disabled": true, "grants_revoked": 1.5,
                             "handle_key_rotated": "yes", "runs_cancelled": null});
    case["assessment"] = json!({
        "principals": [{"id": "agent-1", "created_at": ""}, {"id": 5}, "x"],
        "secrets": [mandatory, {"secret_id": 9, "kind": null, "tier": "recommended"}],
        "recover_required": 1
    });
    cases.push(case);
    let script = format!(
        "import json\nfrom zeropw import incident as I\nfrom zeropw.notify import render_incident_email\nout=[]\nfor d in json.loads({:?}):\n    out.append(render_incident_email(I.Incident.from_dict(d), now='2023-11-14T22:13:21Z'))\nprint(json.dumps(out))\n",
        Value::Array(cases.clone()).to_string()
    );
    let expected: Vec<(String, String)> =
        serde_json::from_str(oracle::python(&script).trim()).unwrap();
    for (case, expected) in cases.iter().zip(expected) {
        let incident = zeropw::incident::Incident::from_dict(case).unwrap();
        let actual = zeropw::notify::render_incident_email(&incident, "2023-11-14T22:13:21Z");
        assert_eq!(actual.0, expected.0);
        assert_eq!(actual.1, expected.1, "case {case}");
    }
}
