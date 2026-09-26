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

// ---------------------------------------------------------------- SMTP
// Every SMTP scenario runs Python's `send_test_message` and Rust's against a
// fresh scripted loopback server, then compares the outcome, the new audit
// records and the exact bytes the server received (the EHLO/HELO argument
// is compared separately by `smtp::tests`, since Python may answer it from
// DNS).

const EHLO_BASE: &str = "250-fake.example\r\n250-SIZE 1000000\r\n250-8BITMIME\r\n";

fn ehlo_reply(scenario: &str) -> String {
    let extra = match scenario {
        "auth_plain" | "password_crlf" | "password_non_ascii" | "bad_challenge" | "plain_five" => {
            "250-AUTH PLAIN\r\n"
        }
        "auth_login" | "login_non_ascii" => "250-AUTH LOGIN\r\n",
        "cram_six" | "cram_non_ascii" => "250-AUTH CRAM-MD5\r\n",
        "auth_no_suitable" => "250-AUTH XOAUTH2\r\n",
        "auth_lowercase" => "250-AUTH plain login\r\n",
        "oldstyle_auth" => "250-AUTH=LOGIN\r\n",
        "smtputf8" => "250-SMTPUTF8\r\n",
        "starttls_refused" => "250-STARTTLS\r\n",
        _ => "",
    };
    format!("{EHLO_BASE}{extra}250 HELP\r\n")
}

/// The reply to one received line, or `None` to close the connection.
fn scripted_reply(
    scenario: &str,
    line: &[u8],
    auth: &mut bool,
    rcpt: &mut usize,
) -> Option<String> {
    let text = String::from_utf8_lossy(line).to_ascii_uppercase();
    let verb = text
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    let known = [
        "EHLO", "HELO", "STARTTLS", "AUTH", "MAIL", "RCPT", "DATA", "RSET", "QUIT",
    ];
    if *auth && !known.contains(&verb.as_str()) {
        return Some(match scenario {
            "auth_login" | "oldstyle_auth" | "login_non_ascii" => {
                *auth = false;
                "235 authenticated\r\n".into()
            }
            "cram_six" => "334 PDEyMzQ1LjY3ODlAZXhhbXBsZT4=\r\n".into(),
            "plain_five" => "334 \r\n".into(),
            _ => {
                *auth = false;
                "235 authenticated\r\n".into()
            }
        });
    }
    *auth = false;
    Some(match verb.as_str() {
        "EHLO" => match scenario {
            "helo_fallback" => "500 unknown\r\n".into(),
            "ehlo_251" => "251 fine\r\n".into(),
            "ehlo_garbage" => "xyz\r\n".into(),
            _ => ehlo_reply(scenario),
        },
        "HELO" => "250 fake\r\n".into(),
        "STARTTLS" => "454 not now\r\n".into(),
        "AUTH" => {
            *auth = true;
            match scenario {
                "auth_plain" | "password_crlf" => {
                    *auth = false;
                    "235 authenticated\r\n".into()
                }
                "bad_challenge" => "334 abc\r\n".into(),
                "plain_five" => "334 \r\n".into(),
                "auth_login" | "oldstyle_auth" | "login_non_ascii" => "334 UGFzc3dvcmQ6\r\n".into(),
                _ => "334 PDEyMzQ1LjY3ODlAZXhhbXBsZT4=\r\n".into(),
            }
        }
        "MAIL" => match scenario {
            "sender_refused" | "error_then_quit_non221" => "550 sender refused\r\n".into(),
            "sender_421" => return Some("421 closing\r\n".into()).filter(|_| false).or(None),
            _ => "250 sender ok\r\n".into(),
        },
        "RCPT" => {
            *rcpt += 1;
            match (scenario, *rcpt) {
                ("recipients_partial", 1) | ("recipients_all_refused", _) => {
                    "550 no such user\r\n".into()
                }
                ("rcpt_251", _) => "251 forwarded\r\n".into(),
                _ => "250 recipient ok\r\n".into(),
            }
        }
        "DATA" => match scenario {
            "data_refused" => "554 no data\r\n".into(),
            _ => "354 go ahead\r\n".into(),
        },
        "RSET" => "250 reset\r\n".into(),
        "QUIT" => match scenario {
            "quit_non_221" | "error_then_quit_non221" => "500 not quitting\r\n".into(),
            _ => "221 bye\r\n".into(),
        },
        _ => "500 unrecognized\r\n".into(),
    })
}

fn scripted_server(
    scenario: &'static str,
    listener: std::net::TcpListener,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<Vec<Vec<u8>>> {
    use std::io::{BufRead, BufReader, Write};
    std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let (mut stream, _) = loop {
            if let Ok(pair) = listener.accept() {
                break pair;
            }
            if stop.load(Ordering::SeqCst) {
                return vec![];
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        if scenario == "tls_eof" {
            // Read the ClientHello, then end the stream cleanly (FIN).
            use std::io::Read;
            let mut hello = [0u8; 4096];
            let _ = stream.read(&mut hello);
            let _ = stream.shutdown(std::net::Shutdown::Write);
            while stream.read(&mut hello).unwrap_or(0) > 0 {}
            return vec![];
        }
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut log = vec![];
        let greeting: &[u8] = if scenario == "greeting_rejected" {
            b"554 unavailable\r\n"
        } else {
            b"220 fake ready\r\n"
        };
        if stream.write_all(greeting).is_err() {
            return log;
        }
        let (mut auth, mut rcpt) = (false, 0);
        loop {
            let mut line = Vec::new();
            match reader.read_until(b'\n', &mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            log.push(line.clone());
            if scenario == "sender_421" && line.to_ascii_uppercase().starts_with(b"MAIL") {
                let _ = stream.write_all(b"421 closing\r\n");
                break;
            }
            let Some(reply) = scripted_reply(scenario, &line, &mut auth, &mut rcpt) else {
                break;
            };
            let data = reply.starts_with("354");
            if stream.write_all(reply.as_bytes()).is_err() {
                break;
            }
            if data {
                loop {
                    let mut chunk = Vec::new();
                    if reader.read_until(b'\n', &mut chunk).unwrap_or(0) == 0 {
                        return log;
                    }
                    log.push(chunk.clone());
                    if chunk == b".\r\n" {
                        break;
                    }
                }
                let final_reply: &[u8] = if scenario == "data_final_refused" {
                    b"550 rejected\r\n"
                } else {
                    b"250 accepted\r\n"
                };
                if stream.write_all(final_reply).is_err() {
                    break;
                }
            }
            if line.to_ascii_uppercase().starts_with(b"QUIT") {
                break;
            }
        }
        log
    })
}

/// `EHLO`/`HELO` argument masked: `smtp::tests` compares it directly.
fn mask_greeting_argument(line: &[u8]) -> Vec<u8> {
    let upper = line.to_ascii_uppercase();
    if upper.starts_with(b"EHLO ") || upper.starts_with(b"HELO ") {
        let mut masked = line[..5].to_vec();
        masked.extend_from_slice(b"<local>\r\n");
        masked
    } else {
        line.to_vec()
    }
}

fn audit_lines(ctx: &Context) -> Vec<Value> {
    ctx.audit
        .iter_records()
        .unwrap()
        .into_iter()
        .map(|record| {
            json!([
                record.get("event"),
                record.get("result"),
                record.get("reason"),
                record.get("kind")
            ])
        })
        .collect()
}

enum Password {
    None,
    Text(&'static [u8]),
    Directory,
}

#[test]
fn smtp_sessions_match_python_transcripts_outcomes_and_audit() {
    let scenarios: Vec<(&'static str, Value, Password)> = vec![
        ("plain_ok", json!({}), Password::None),
        ("helo_fallback", json!({}), Password::None),
        ("ehlo_251", json!({}), Password::None),
        ("ehlo_garbage", json!({}), Password::None),
        ("greeting_rejected", json!({}), Password::None),
        ("sender_refused", json!({}), Password::None),
        ("sender_421", json!({}), Password::None),
        (
            "recipients_partial",
            json!({"recipients": ["bad@example.com", "good@example.com"]}),
            Password::None,
        ),
        (
            "recipients_all_refused",
            json!({"recipients": ["bad@example.com", "worse@example.com"]}),
            Password::None,
        ),
        ("rcpt_251", json!({}), Password::None),
        ("data_refused", json!({}), Password::None),
        ("data_final_refused", json!({}), Password::None),
        ("quit_non_221", json!({}), Password::None),
        ("error_then_quit_non221", json!({}), Password::None),
        (
            "auth_plain",
            json!({"username": "synthetic-user"}),
            Password::Text(b"synthetic-password\n"),
        ),
        (
            "password_crlf",
            json!({"username": "synthetic-user"}),
            Password::Text(b" pa\rss\r\nword \r\n"),
        ),
        (
            "auth_login",
            json!({"username": "synthetic-user"}),
            Password::Text(b"synthetic-password"),
        ),
        (
            "oldstyle_auth",
            json!({"username": "synthetic-user"}),
            Password::Text(b"synthetic-password"),
        ),
        (
            "cram_six",
            json!({"username": "synthetic-user"}),
            Password::Text(b"synthetic-password"),
        ),
        (
            "plain_five",
            json!({"username": "synthetic-user"}),
            Password::Text(b"synthetic-password"),
        ),
        (
            "bad_challenge",
            json!({"username": "synthetic-user"}),
            Password::Text(b"synthetic-password"),
        ),
        (
            "password_non_ascii",
            json!({"username": "synthetic-user"}),
            Password::Text("synthetic-pässword".as_bytes()),
        ),
        (
            "cram_non_ascii",
            json!({"username": "synthetic-user"}),
            Password::Text("synthetic-pässword".as_bytes()),
        ),
        (
            "login_non_ascii",
            json!({"username": "synthetic-user"}),
            Password::Text("synthetic-pässword".as_bytes()),
        ),
        (
            "auth_no_suitable",
            json!({"username": "synthetic-user"}),
            Password::Text(b"synthetic-password"),
        ),
        (
            "auth_lowercase",
            json!({"username": "synthetic-user"}),
            Password::Text(b"synthetic-password"),
        ),
        (
            "auth_unadvertised",
            json!({"username": "synthetic-user"}),
            Password::None,
        ),
        ("password_directory", json!({}), Password::Directory),
        (
            "password_non_utf8",
            json!({}),
            Password::Text(b"synthetic-\xff-password"),
        ),
        (
            "starttls_unsupported",
            json!({"mode": "starttls"}),
            Password::None,
        ),
        (
            "starttls_refused",
            json!({"mode": "starttls"}),
            Password::None,
        ),
        (
            "smtputf8",
            json!({"recipients": ["관리자 <사용자@example.com>"]}),
            Password::None,
        ),
        (
            "smtputf8_missing",
            json!({"recipients": ["사용자@example.com"]}),
            Password::None,
        ),
        (
            "display_names",
            json!({"sender": "ZeroPW 알림 <zeropw@example.com>", "recipients": ["\"Doe, John\" <john@example.com>", "관리자 <admin@example.com>"]}),
            Password::None,
        ),
        (
            "multi_address_entry",
            json!({"recipients": ["a@example.com, b@example.com", "c@example.com"]}),
            Password::None,
        ),
        (
            "timeout_overflow",
            json!({"timeout_seconds": 1e10}),
            Password::None,
        ),
        (
            "unresolvable",
            json!({"host": "zeropw-nonexistent.invalid", "mode": "starttls"}),
            Password::None,
        ),
        ("connection_refused", json!({}), Password::None),
        // TLS: the ClientHello bytes differ by TLS stack, so only the
        // outcome and audit are compared for these.
        ("tls_plaintext", json!({"mode": "smtps"}), Password::None),
        ("tls_eof", json!({"mode": "smtps"}), Password::None),
    ];
    let (tmp, ctx) = fixture();
    let state = tmp.path().join("state");
    let mut failures = vec![];
    for (scenario, overrides, password) in scenarios {
        let mut results = vec![];
        for language in ["python", "rust"] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let server = scripted_server(scenario, listener, Arc::clone(&stop));
            let port = if scenario == "connection_refused" {
                let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                closed.local_addr().unwrap().port()
            } else {
                port
            };
            let mut config = json!({"host": "127.0.0.1", "port": port, "mode": "plain",
                "sender": "zeropw@example.com", "recipients": ["admin@example.com"],
                "timeout_seconds": 2.0});
            for (key, value) in overrides.as_object().unwrap() {
                config[key] = value.clone();
            }
            let password_path = tmp
                .path()
                .join(format!("smtp-password-{scenario}-{language}"));
            match password {
                Password::None => {}
                Password::Text(bytes) => {
                    fs::write(&password_path, bytes).unwrap();
                    config["password_file"] = json!(password_path);
                }
                Password::Directory => {
                    fs::create_dir(&password_path).unwrap();
                    config["password_file"] = json!(password_path);
                }
            }
            if password_path.exists() {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&password_path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            ctx.state.write_json("notify.json", &config).unwrap();
            let before = audit_lines(&ctx).len();
            let outcome = if language == "python" {
                let script = format!(
                    "import json\nfrom zeropw.context import Context\nfrom zeropw.notify import send_test_message\nc=Context.open({:?})\ntry:\n    out={{'result': send_test_message(c)}}\nexcept Exception as e:\n    out={{'exception': type(e).__name__}}\nprint(json.dumps(out))\n",
                    state.to_str().unwrap()
                );
                serde_json::from_str::<Value>(oracle::python(&script).trim()).unwrap()
            } else {
                match zeropw::notify::send_test_message(&ctx) {
                    Ok(result) => json!({"result": result}),
                    Err(error) if error.reason == "state_corrupt" => {
                        json!({"exception": error.detail})
                    }
                    Err(error) => json!({"exception": error.name}),
                }
            };
            stop.store(true, Ordering::SeqCst);
            let transcript: Vec<Vec<u8>> = server
                .join()
                .unwrap()
                .iter()
                .map(|line| mask_greeting_argument(line))
                .filter(|_| !scenario.starts_with("tls_"))
                .collect();
            let audit: Vec<Value> = audit_lines(&ctx).split_off(before);
            results.push((outcome, audit, transcript));
        }
        println!("{scenario}: python {} rust {}", results[0].0, results[1].0);
        if results[0] != results[1] {
            let show = |r: &(Value, Vec<Value>, Vec<Vec<u8>>)| {
                format!(
                    "{} audit={:?} transcript={:?}",
                    r.0,
                    r.1,
                    r.2.iter()
                        .map(|l| String::from_utf8_lossy(l).into_owned())
                        .collect::<Vec<_>>()
                )
            };
            failures.push(format!(
                "{scenario}:\n  python {}\n  rust   {}",
                show(&results[0]),
                show(&results[1])
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} scenario(s) differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// `deliver` reads the password file before connecting, whether or not a
/// username is configured: an `OSError` (here `IsADirectoryError`) becomes
/// `notification.last_error` and the `incident_notify` audit reason, while
/// a `UnicodeDecodeError` escapes `deliver` and `_deliver_notification`
/// records `notify` in `failed_steps`, leaving the notification as it was.
#[test]
fn incident_delivery_failures_record_what_python_records() {
    for case in [
        "password_directory",
        "password_non_utf8",
        "connection_refused",
    ] {
        let (tmp, ctx) = fixture();
        ctx.policy.create_principal("agent-1", "box-1").unwrap();
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let mut config = json!({"host": "127.0.0.1", "port": port, "mode": "plain",
            "sender": "zeropw@example.com", "recipients": ["admin@example.com"]});
        let password = tmp.path().join("smtp-password");
        match case {
            "password_directory" => fs::create_dir(&password).unwrap(),
            "password_non_utf8" => fs::write(&password, b"synthetic-\xff").unwrap(),
            _ => {}
        }
        if password.exists() {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
            config["password_file"] = json!(password);
        }
        ctx.state.write_json("notify.json", &config).unwrap();
        let python_state = tmp.path().join("python-state");
        copy_dir(&tmp.path().join("state"), &python_state);

        let incident = zeropw::incident::open_incident(
            &ctx,
            "principal",
            Some(&["agent-1".to_owned()]),
            None,
            "manual",
            None,
            None,
        )
        .unwrap();
        let notify_audit = |records: Vec<Value>| -> Vec<Value> {
            records
                .into_iter()
                .filter(|r| r.get("event").and_then(Value::as_str) == Some("incident_notify"))
                .map(|r| json!([r.get("result"), r.get("reason")]))
                .collect()
        };
        let rust = json!({
            "status": incident.notification["status"],
            "attempts": incident.notification["attempts"],
            "last_error": incident.notification.get("last_error"),
            "failed_steps": incident.actions["failed_steps"],
            "audit": notify_audit(ctx.audit.iter_records().unwrap()),
        });
        let script = format!(
            "import json\nfrom zeropw.context import Context\nfrom zeropw import incident as I\nc=Context.open({:?})\ninc=I.open_incident(c, scope='principal', principals=['agent-1'], trigger='manual')\nn=inc.notification\naudit=[[r.get('result'), r.get('reason')] for r in c.audit.iter_records() if r.get('event')=='incident_notify']\nprint(json.dumps({{'status': n.get('status'), 'attempts': n.get('attempts'), 'last_error': n.get('last_error'), 'failed_steps': inc.actions['failed_steps'], 'audit': audit}}))\n",
            python_state.to_str().unwrap()
        );
        let python: Value = serde_json::from_str(oracle::python(&script).trim()).unwrap();
        assert_eq!(rust, python, "{case}");
    }
}

/// `incident notify-test` when `_send` raises a built-in exception: the
/// administrator CLIs report the same error object and exit status
/// (`OverflowError` from the socket timeout). The `ValueError` family
/// (`UnicodeDecodeError` from the password file) additionally depends on
/// `admin_cli.rs`'s `state_corrupt` rendering, recorded in `DEVIATIONS.md`.
#[test]
fn notify_test_cli_reports_escaping_errors_like_python() {
    let tmp = TempDir::new().unwrap();
    for case in ["timeout_overflow"] {
        let mut results = vec![];
        for language in ["python", "rust"] {
            let state = tmp.path().join(format!("{case}-{language}"));
            let (code, _) = admin_cli(language, &state, &["init"]);
            assert_eq!(code, 0, "{language} init");
            let mut config = json!({"host": "127.0.0.1", "port": 9, "mode": "plain",
                "sender": "zeropw@example.com", "recipients": ["admin@example.com"]});
            if case == "password_non_utf8" {
                let password = tmp.path().join(format!("{case}-{language}.pass"));
                fs::write(&password, b"synthetic-\xff").unwrap();
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
                config["password_file"] = json!(password);
            } else {
                config["timeout_seconds"] = json!(1e10);
            }
            let path = state.join("notify.json");
            fs::write(&path, config.to_string()).unwrap();
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            results.push(admin_cli(language, &state, &["incident", "notify-test"]));
        }
        assert_ne!(results[0].0, 0, "{case}");
        assert_eq!(results[1], results[0], "{case}");
    }
}
