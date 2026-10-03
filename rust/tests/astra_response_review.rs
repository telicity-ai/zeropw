//! Independent Astra review probes at 692fc7566005f2dcd25e9b48fd401031f01c79de.
//! Assertions express the original Python contract (expected values recorded
//! from the prototype); failures intentionally reproduce open findings.
use serde_json::json;
use std::{
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;
use zeropw::{
    audit::RecordArgs,
    clock,
    context::{Config, Context},
    intrusion, notify,
};

fn fixture() -> (TempDir, Arc<Context>) {
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
            clock::fixed(1_700_000_000.0),
        )
        .unwrap(),
    );
    (tmp, ctx)
}

#[test]
fn installed_detector_survives_dropped_return_value() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    drop(intrusion::install(Arc::clone(&ctx), None).unwrap());
    for _ in 0..2 {
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
            .unwrap();
    }
    assert!(
        ctx.policy.open_incident_id().unwrap().is_some(),
        "R-INTRUSION-LIFETIME: dropping install's return silently unregisters detection"
    );
}

fn receiver(scenario: &str) -> (u16, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let scenario = scenario.to_owned();
    let worker = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let limit = Instant::now() + Duration::from_secs(3);
        let (mut stream, _) = loop {
            if let Ok(pair) = listener.accept() {
                break pair;
            }
            if Instant::now() > limit {
                return vec!["NO CONNECTION".into()];
            }
            thread::sleep(Duration::from_millis(5));
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut log = vec![];
        if scenario == "malformed_utf8_boundary" {
            let _ = stream.write_all("22é hi\r\n".as_bytes());
            return log;
        }
        if scenario == "greeting_rejected" {
            let _ = stream.write_all(b"554 unavailable\r\n");
            return log;
        }
        if scenario == "long_reply" {
            let _ = stream.write_all(format!("220 {}\r\n", "x".repeat(9000)).as_bytes());
        } else {
            let _ = stream.write_all(b"220 fake ready\r\n");
        }
        let mut login_step = 0;
        let mut challenge = false;
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                _ => (),
            }
            log.push(line.trim().to_owned());
            let upper = line.to_ascii_uppercase();
            let reply = if upper.starts_with("EHLO") {
                match scenario.as_str() {
                    "helo" => "500 unsupported\r\n",
                    "cram" => "250-fake\r\n250 AUTH CRAM-MD5\r\n",
                    "auth_fallback" => "250-fake\r\n250 AUTH PLAIN LOGIN\r\n",
                    "plain_challenge" => "250-fake\r\n250 AUTH PLAIN\r\n",
                    _ => "250 fake\r\n",
                }
            } else if upper.starts_with("HELO") {
                "250 fake\r\n"
            } else if upper.starts_with("AUTH CRAM-MD5") {
                challenge = true;
                "334 c3ludGhldGljLWNoYWxsZW5nZQ==\r\n"
            } else if upper.starts_with("AUTH PLAIN") && scenario == "auth_fallback" {
                "535 retry alternate auth\r\n"
            } else if upper.starts_with("AUTH PLAIN") {
                challenge = true;
                "334 \r\n"
            } else if challenge {
                challenge = false;
                "235 authenticated\r\n"
            } else if upper.starts_with("AUTH LOGIN") {
                login_step = if upper.trim() == "AUTH LOGIN" { 1 } else { 2 };
                "334 VXNlcm5hbWU6\r\n"
            } else if login_step == 1 {
                login_step = 2;
                "334 UGFzc3dvcmQ6\r\n"
            } else if login_step == 2 {
                login_step = 0;
                "235 authenticated\r\n"
            } else if upper.starts_with("MAIL FROM") {
                if scenario == "display_address" && line.contains("Display") {
                    "501 invalid envelope\r\n"
                } else {
                    "250 ok\r\n"
                }
            } else if upper.starts_with("RCPT TO") {
                if scenario == "recipient_251" {
                    "251 forwarded\r\n"
                } else if scenario == "partial_recipient" && line.contains("bad@example.com") {
                    "550 rejected\r\n"
                } else {
                    "250 ok\r\n"
                }
            } else if upper.starts_with("DATA") {
                let _ = stream.write_all(b"354 data\r\n");
                loop {
                    let mut data = String::new();
                    if reader.read_line(&mut data).unwrap_or(0) == 0 || data == ".\r\n" {
                        break;
                    }
                }
                "250 accepted\r\n"
            } else if upper.starts_with("QUIT") {
                let _ = stream.write_all(b"221 bye\r\n");
                break;
            } else {
                "250 ok\r\n"
            };
            if stream.write_all(reply.as_bytes()).is_err() {
                break;
            }
        }
        log
    });
    (port, worker)
}

#[test]
fn smtp_python_interoperability_matrix() {
    let (_tmp, ctx) = fixture();
    let mut regressions = vec![];
    for scenario in [
        "cram",
        "helo",
        "recipient_251",
        "partial_recipient",
        "display_address",
        "auth_fallback",
        "plain_challenge",
        "malformed_utf8_boundary",
        "greeting_rejected",
        "long_reply",
    ] {
        let expected = match scenario {
            "malformed_utf8_boundary" | "greeting_rejected" => "SMTPConnectError",
            "long_reply" => "SMTPResponseException",
            _ => "sent",
        };
        let (port, worker) = receiver(scenario);
        let auth = ["cram", "auth_fallback", "plain_challenge"].contains(&scenario);
        let cfg = json!({"host":"127.0.0.1", "port":port, "mode":"plain", "sender":if scenario == "display_address" { "Display Name <sender@example.com>" } else { "sender@example.com" }, "recipients":if scenario == "partial_recipient" { vec!["bad@example.com", "good@example.com"] } else { vec!["good@example.com"] }, "username":if auth { Some("synthetic-user") } else { None }, "timeout_seconds":2.0});
        ctx.state.write_json("notify.json", &cfg).unwrap();
        let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            notify::send_test_message(&ctx)
        })) {
            Ok(Ok(v)) => v
                .get("error")
                .or_else(|| v.get("status"))
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned(),
            Ok(Err(e)) => e.reason.to_string(),
            Err(_) => "PANIC".into(),
        };
        let commands = worker.join().unwrap();
        println!("{scenario}: {result}; commands={commands:?}");
        if result != expected {
            regressions.push(format!("{scenario}: Python={expected} Rust={result}"));
        }
    }
    assert!(
        regressions.is_empty(),
        "R-SMTP compatibility failures: {regressions:#?}"
    );
}

#[test]
fn large_accepted_weak_weights_do_not_poison_detection() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    let config = intrusion::DetectorConfig::from_mapping(Some(&json!({"weak_threshold":i64::MAX, "weak_points":{"scope_violation":4_611_686_018_427_387_904_i64}}))).unwrap();
    let _detector = intrusion::install(Arc::clone(&ctx), Some(config)).unwrap();
    for _ in 0..2 {
        ctx.audit
            .record(
                "tools_request",
                RecordArgs {
                    caller: Some("agent-1"),
                    result: Some("denied"),
                    reason: Some("path_not_allowed"),
                    ..Default::default()
                },
            )
            .unwrap();
    }
    let opened = ctx.policy.open_incident_id().unwrap();
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
    assert!(
        opened.is_some(),
        "R-INTRUSION-OVERFLOW: two valid weights cross threshold but overflow suppresses the decision; subsequent signer signal incident={:?}",
        ctx.policy.open_incident_id().unwrap()
    );
}

#[test]
fn notify_secure_mode_includes_special_bits() {
    use std::os::unix::fs::PermissionsExt;
    let (_tmp, ctx) = fixture();
    ctx.state.write_json("notify.json", &json!({"host":"127.0.0.1","port":25,"mode":"plain","sender":"sender@example.com","recipients":["recipient@example.com"]})).unwrap();
    std::fs::set_permissions(
        ctx.state.path.join("notify.json"),
        std::fs::Permissions::from_mode(0o4600),
    )
    .unwrap();
    assert!(
        notify::NotifyConfig::load(&ctx).is_err(),
        "R-NOTIFY-MODE: Python rejects 04600 while Rust masks away special mode bits"
    );
}

/// A minimal persisted incident document loads with the original defaults.
#[test]
fn incident_document_roundtrip_fills_the_original_defaults() {
    let data = json!({"id":"inc-test", "opened_at":"2023-11-14T22:13:20Z", "status":"open", "scope":"principal", "actions":{}, "assessment":{}, "notification":{}});
    let rs = zeropw::incident::Incident::from_dict(&data)
        .unwrap()
        .to_dict();
    assert_eq!(
        rs,
        json!({"id":"inc-test","opened_at":"2023-11-14T22:13:20Z","status":"open","scope":"principal","runtime":null,"principals":[],"trigger":"manual","rule":null,"detail":null,"actions":{},"assessment":{},"notification":{"status":"not_configured","attempts":0},"closed_at":null,"widened_from":[]})
    );
}

#[test]
fn corrupted_incident_is_not_treated_as_missing() {
    let (_tmp, ctx) = fixture();
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    ctx.policy.set_open_incident(Some("inc-broken")).unwrap();
    ctx.state
        .write_bytes("incidents/inc-broken.json", b"{")
        .unwrap();
    let retry = notify::retry_pending(&ctx, 1_700_000_000.0);
    let opened = zeropw::incident::open_incident(
        &ctx,
        "principal",
        Some(&["agent-1".into()]),
        None,
        "manual",
        None,
        None,
    );
    assert!(
        retry.is_err() && opened.is_err(),
        "R-INCIDENT-CORRUPT: Rust retry={retry:?}, Rust open succeeded={}",
        opened.is_ok()
    );
}
