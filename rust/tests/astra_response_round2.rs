//! Independent gpt-6-astra response review at d44eebe85dc6dd83fc57b3ba576a9b8135356af2.
//! Synthetic loopback SMTP fixtures; Python is only a behavioral oracle.
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::Arc,
    thread,
    time::Duration,
};
use tempfile::TempDir;
use zeropw::{
    clock,
    context::{Config, Context},
    incident::Incident,
    notify,
};
#[path = "../src/oracle.rs"]
mod oracle;

fn fixture() -> (TempDir, Arc<Context>) {
    let tmp = TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            tmp.path().join("state"),
            "synthetic-admin",
            "synthetic-recovery",
            Config::default(),
            clock::fixed(1700000000.0),
        )
        .unwrap(),
    );
    (tmp, ctx)
}
fn line(wire: &mut impl Read) -> String {
    let mut bytes = vec![];
    loop {
        let mut b = [0];
        if wire.read(&mut b).unwrap_or(0) == 0 {
            break;
        }
        bytes.push(b[0]);
        if b[0] == b'\n' {
            break;
        }
    }
    String::from_utf8_lossy(&bytes).into()
}
fn dialog(wire: &mut (impl Read + Write), scenario: &str, greet: bool) -> Vec<String> {
    if greet {
        let _ = wire.write_all(b"220 synthetic ready\r\n");
    }
    let mut log = vec![];
    let mut challenge = false;
    loop {
        let cmd = line(wire);
        if cmd.is_empty() {
            break;
        }
        log.push(cmd.trim().into());
        let upper = cmd.to_ascii_uppercase();
        let response = if upper.starts_with("EHLO") {
            match scenario {
                "auth_equals" => "250-synthetic\r\n250 AUTH=PLAIN\r\n",
                "cram_verified" => "250-synthetic\r\n250 AUTH CRAM-MD5\r\n",
                "international" => "250-synthetic\r\n250 SMTPUTF8\r\n",
                "auth_failure" => "250-synthetic\r\n250 AUTH PLAIN LOGIN\r\n",
                _ => "250 synthetic\r\n",
            }
        } else if cmd.starts_with("AUTH CRAM-MD5") {
            challenge = true;
            "334 c3ludGhldGljLWNoYWxsZW5nZQ==\r\n"
        } else if challenge {
            challenge = false;
            use base64::Engine;
            use hmac::Mac;
            let mut mac = hmac::Hmac::<md5::Md5>::new_from_slice(b"synthetic-pass").unwrap();
            mac.update(b"synthetic-challenge");
            let expected = format!(
                "synthetic-user {}",
                hex::encode(mac.finalize().into_bytes())
            );
            assert_eq!(
                base64::engine::general_purpose::STANDARD
                    .decode(cmd.trim())
                    .unwrap(),
                expected.as_bytes()
            );
            "235 accepted\r\n"
        } else if cmd.starts_with("AUTH") {
            if scenario == "auth_failure" {
                "535 synthetic-denied\r\n"
            } else {
                "235 accepted\r\n"
            }
        } else if upper.starts_with("MAIL") {
            if scenario == "comment_address"
                && !cmd
                    .to_ascii_lowercase()
                    .starts_with("mail from:<sender@example.com>")
            {
                "501 invalid envelope\r\n"
            } else {
                "250 ok\r\n"
            }
        } else if cmd.to_ascii_uppercase().starts_with("RCPT") {
            "250 ok\r\n"
        } else if cmd.to_ascii_uppercase().starts_with("DATA") {
            let _ = wire.write_all(b"354 data\r\n");
            loop {
                let bodyline = line(wire);
                if bodyline.is_empty() || bodyline == ".\r\n" {
                    break;
                }
            }
            "250 accepted\r\n"
        } else if cmd.to_ascii_uppercase().starts_with("QUIT") {
            let _ = wire.write_all(if scenario == "quit_failure" {
                b"500 failed\r\n"
            } else {
                b"221 bye\r\n"
            });
            break;
        } else {
            "250 ok\r\n"
        };
        if wire.write_all(response.as_bytes()).is_err() {
            break;
        }
    }
    log
}
fn receiver(scenario: &str) -> (u16, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let scenario = scenario.to_owned();
    let worker = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        dialog(&mut socket, &scenario, true)
    });
    (port, worker)
}
fn python_send(config: &Value) -> String {
    oracle::python(&format!("import json\nfrom zeropw.notify import NotifyConfig, _send\ntry:\n _send(NotifyConfig(**json.loads({:?})), 'synthetic subject', 'synthetic body\\n')\n print('sent')\nexcept Exception as e:\n print(type(e).__name__)\n", config.to_string())).trim().into()
}
fn rust_send(ctx: &Arc<Context>, config: &Value) -> String {
    ctx.state.write_json("notify.json", config).unwrap();
    let out = notify::send_test_message(ctx).unwrap();
    out.get("error")
        .or_else(|| out.get("status"))
        .unwrap()
        .as_str()
        .unwrap()
        .into()
}

#[test]
fn smtp_remaining_address_capability_and_completion_parity() {
    let (tmp, ctx) = fixture();
    let pass = tmp.path().join("password");
    std::fs::write(&pass, b"synthetic-pass\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&pass, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut differences: Vec<String> = vec![];
    for scenario in [
        "comment_address",
        "auth_equals",
        "quit_failure",
        "international",
        "auth_failure",
        "cram_verified",
    ] {
        let mut outcomes = vec![];
        for language in ["python", "rust"] {
            let (port, worker) = receiver(scenario);
            let auth = ["auth_equals", "auth_failure", "cram_verified"].contains(&scenario);
            let config = json!({"host":"127.0.0.1","port":port,"mode":"plain","sender":if scenario == "comment_address" {"sender@example.com (Synthetic Sender)"} else {"sender@example.com"},"recipients":[if scenario == "international" {"관리자@example.com"} else {"recipient@example.com"}],"username":if auth {Some("synthetic-user")} else {None},"password_file":pass,"timeout_seconds":1.0});
            let result = if language == "python" {
                python_send(&config)
            } else {
                rust_send(&ctx, &config)
            };
            let commands = worker.join().unwrap();
            println!("{scenario} {language}={result} commands={commands:?}");
            outcomes.push(result);
        }
        if outcomes[0] != outcomes[1] {
            differences.push(format!(
                "{scenario}: Python={} Rust={}",
                outcomes[0], outcomes[1]
            ));
        }
    }
    assert!(
        differences.is_empty(),
        "residual SMTP parity: {differences:?}"
    );
}

#[test]
fn incident_full_shape_differential() {
    let base = json!({"id":"inc-test","opened_at":"2023-11-14T22:13:20Z","status":"open","scope":"principal"});
    let mut cases = vec![];
    for field in [
        "id",
        "opened_at",
        "status",
        "scope",
        "trigger",
        "runtime",
        "rule",
        "detail",
        "closed_at",
        "principals",
        "widened_from",
        "actions",
        "assessment",
        "notification",
    ] {
        for value in [
            json!(null),
            json!(false),
            json!(0),
            json!(12),
            json!("ab"),
            json!([]),
            json!({}),
            json!([true, 3]),
            json!([[true, 1]]),
            json!([[null, 1]]),
            json!([[[], 1]]),
            json!({"a":1,"b":2}),
        ] {
            let mut input = base.clone();
            input[field] = value;
            cases.push((field, input));
        }
    }
    let inputs: Vec<_> = cases.iter().map(|(_, input)| input).collect();
    let code = format!(
        "import json\nfrom zeropw.incident import Incident\nout=[]\nfor x in json.loads({:?}):\n try: out.append({{'ok':Incident.from_dict(x).to_dict()}})\n except Exception as e: out.append({{'error':getattr(e,'reason',type(e).__name__)}})\nprint(json.dumps(out))",
        serde_json::to_string(&inputs).unwrap()
    );
    let expected: Vec<Value> = serde_json::from_str(&oracle::python(&code)).unwrap();
    let mut differences = vec![];
    for ((field, input), py) in cases.iter().zip(expected) {
        let actual = match Incident::from_dict(input) {
            Ok(i) => json!({"ok":i.to_dict()}),
            Err(e) => json!({"error":e.reason}),
        };
        if actual != py {
            differences.push(format!(
                "{field}={} Python={py} Rust={actual}",
                input[field]
            ));
        }
    }
    assert!(
        differences.is_empty(),
        "shape differences: {differences:#?}"
    );
}

#[test]
fn persisted_negative_notification_attempt_count_matches_python() {
    let (_tmp, ctx) = fixture();
    ctx.state.write_json("notify.json", &json!({})).unwrap();
    let mut incident = Incident::from_dict(&json!({"id":"inc-max","opened_at":"2023-11-14T22:13:20Z","status":"open","scope":"principal","notification":{"attempts":-1}})).unwrap();
    let before = incident.to_dict();
    let py = oracle::python(&format!(
        "import json\nfrom zeropw.context import Context\nfrom zeropw.incident import Incident\nfrom zeropw.notify import deliver\nc=Context.open({:?},clock=lambda:1700000000.0)\ni=Incident.from_dict(json.loads({:?}))\ndeliver(c,i)\nprint(json.dumps(i.notification))",
        ctx.state.path.to_str().unwrap(),
        before.to_string()
    ));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        notify::deliver(&ctx, &mut incident)
    }));
    assert!(
        result.is_ok(),
        "Rust pending panicked for an accepted persisted count; Python returned {py}"
    );
    assert_eq!(
        incident.notification,
        serde_json::from_str::<Value>(&py).unwrap()
    );
}

#[test]
fn successful_delivery_of_maximum_persisted_attempt_count_does_not_panic() {
    let (_tmp, ctx) = fixture();
    let original = json!({"id":"inc-max","opened_at":"2023-11-14T22:13:20Z","status":"open","scope":"principal","notification":{"attempts":u64::MAX}});
    let mut expected = Value::Null;
    for language in ["python", "rust"] {
        let (port, worker) = receiver("normal");
        ctx.state.write_json("notify.json",&json!({"host":"127.0.0.1","port":port,"mode":"plain","sender":"sender@example.com","recipients":["recipient@example.com"],"timeout_seconds":1.0})).unwrap();
        if language == "python" {
            let py = oracle::python(&format!(
                "import json\nfrom zeropw.context import Context\nfrom zeropw.incident import Incident\nfrom zeropw.notify import deliver\nc=Context.open({:?},clock=lambda:1700000000.0)\ni=Incident.from_dict(json.loads({:?}))\ndeliver(c,i)\nprint(json.dumps(i.notification))",
                ctx.state.path.to_str().unwrap(),
                original.to_string()
            ));
            expected = serde_json::from_str(&py).unwrap();
            worker.join().unwrap();
        } else {
            let mut incident = Incident::from_dict(&original).unwrap();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                notify::deliver(&ctx, &mut incident)
            }));
            worker.join().unwrap();
            assert!(
                result.is_ok(),
                "successful send panicked on attempts + 1; Python={expected}"
            );
            assert_eq!(incident.notification, expected);
        }
    }
}

#[test]
fn detector_valid_pair_list_and_large_configuration_parity() {
    let cases = json!([
        [["weak_threshold",1]],
        {"weak_points":[["scope_violation",8]]},
        {"strong_thresholds":[["unknown_tool",1]]},
        {"weak_threshold":18446744073709551616u128},
        {"weak_points":{"scope_violation":18446744073709551616u128}}
    ]);
    let py = oracle::python(&format!(
        "import json\nfrom dataclasses import asdict\nfrom zeropw.intrusion import DetectorConfig\nout=[]\nfor x in json.loads({:?}):\n try: out.append({{'ok':asdict(DetectorConfig.from_mapping(x))}})\n except Exception as e: out.append({{'error':getattr(e,'reason',type(e).__name__)}})\nprint(json.dumps(out))",
        cases.to_string()
    ));
    let expected: Vec<Value> = serde_json::from_str(&py).unwrap();
    let mut differences = vec![];
    for (input, py) in cases.as_array().unwrap().iter().zip(expected) {
        let rs = match zeropw::intrusion::DetectorConfig::from_mapping(Some(input)) {
            Ok(c) => {
                json!({"ok":{"window_seconds":c.window_seconds,"weak_threshold":c.weak_threshold,"enumeration_min":c.enumeration_min,"enumeration_ratio":c.enumeration_ratio,"burst_count":c.burst_count,"weak_points":c.weak_points,"strong_thresholds":c.strong_thresholds}})
            }
            Err(e) => json!({"error":e.reason}),
        };
        if py != rs {
            differences.push(format!("input={input} Python={py} Rust={rs}"));
        }
    }
    assert!(
        differences.is_empty(),
        "detector config differences: {differences:#?}"
    );
}

#[test]
fn assessment_merges_shared_secrets_and_excludes_ungranted_secrets() {
    use zeropw::{
        audit::RecordArgs,
        policy::{Connection, HttpAuth, HttpScope, HttpTarget},
    };
    let (_tmp, ctx) = fixture();
    ctx.projects
        .create("demo", zeropw::projects::DEFAULT_ENVIRONMENTS)
        .unwrap();
    for id in ["used", "held", "ungranted"] {
        ctx.vault
            .put_secret(
                id,
                "api_key",
                format!("synthetic-secret-{id}-0123456789").as_bytes(),
                "demo",
                "dev",
                true,
            )
            .unwrap();
        ctx.policy
            .create_connection(
                Connection::new(
                    id,
                    "demo",
                    "dev",
                    "synthetic",
                    "http",
                    id,
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
                .unwrap(),
            )
            .unwrap();
    }
    for id in ["agent-1", "agent-2"] {
        ctx.policy
            .create_principal(id, "synthetic-runtime")
            .unwrap();
        ctx.policy
            .create_grant(id, "used", Some(3600), None)
            .unwrap();
    }
    ctx.policy
        .create_grant("agent-1", "held", Some(3600), None)
        .unwrap();
    ctx.audit
        .record(
            "http_relay",
            RecordArgs {
                caller: Some("agent-2"),
                connection: Some("used"),
                result: Some("ok"),
                action: Some("GET"),
                ..Default::default()
            },
        )
        .unwrap();
    let result = zeropw::incident::assess(
        &ctx,
        &["agent-1".into(), "agent-2".into()],
        "principal",
        "2023-11-14T22:13:20Z",
    )
    .unwrap();
    let entries = result["secrets"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    let used = entries.iter().find(|v| v["secret_id"] == "used").unwrap();
    assert_eq!(used["tier"], "mandatory");
    assert_eq!(used["use_count"], 1);
    assert_eq!(used["connections"], json!(["used"]));
    assert_eq!(
        entries.iter().find(|v| v["secret_id"] == "held").unwrap()["tier"],
        "recommended"
    );
    assert_eq!(result["principals"].as_array().unwrap().len(), 2);
    let py = oracle::python(&format!(
        "import json\nfrom zeropw.context import Context\nfrom zeropw.incident import assess\nc=Context.open({:?},clock=lambda:1700000000.0)\nprint(json.dumps(assess(c,['agent-1','agent-2'],'principal',since='2023-11-14T22:13:20Z')))",
        ctx.state.path.to_str().unwrap()
    ));
    assert_eq!(result, serde_json::from_str::<Value>(&py).unwrap());
}

#[test]
fn tls_client_child() {
    let Ok(config) = std::env::var("ASTRA_SMTP_TLS_CONFIG") else {
        return;
    };
    let (_tmp, ctx) = fixture();
    println!(
        "ASTRA_RESULT={}",
        rust_send(&ctx, &serde_json::from_str(&config).unwrap())
    );
}

#[test]
fn smtp_tls_verified_starttls_smtps_and_untrusted_cert_parity() {
    let tmp = TempDir::new().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let pem = tmp.path().join("root.pem");
    std::fs::write(&pem, cert.cert.pem()).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let server = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key.into())
            .unwrap(),
    );
    let empty = tmp.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    let mut differences = vec![];
    for mode in ["smtps", "starttls"] {
        for trusted in [true, false] {
            let mut outcomes = vec![];
            for language in ["python", "rust"] {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let port = listener.local_addr().unwrap().port();
                let server = server.clone();
                let worker = thread::spawn(move || {
                    let (mut tcp, _) = listener.accept().unwrap();
                    tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                    if mode == "starttls" {
                        tcp.write_all(b"220 synthetic ready\r\n").unwrap();
                        assert!(line(&mut tcp).to_ascii_uppercase().starts_with("EHLO"));
                        tcp.write_all(b"250-synthetic\r\n250 STARTTLS\r\n").unwrap();
                        assert_eq!(line(&mut tcp).trim().to_ascii_uppercase(), "STARTTLS");
                        tcp.write_all(b"220 start tls\r\n").unwrap();
                    }
                    let mut tls = rustls::StreamOwned::new(
                        rustls::ServerConnection::new(server).unwrap(),
                        tcp,
                    );
                    while tls.conn.is_handshaking() {
                        if tls.conn.complete_io(&mut tls.sock).is_err() {
                            return vec![];
                        }
                    }
                    dialog(&mut tls, "tls", mode == "smtps")
                });
                let config = json!({"host":"127.0.0.1","port":port,"mode":mode,"sender":"sender@example.com","recipients":["recipient@example.com"],"timeout_seconds":1.0});
                let mut command = if language == "rust" {
                    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
                    command
                        .args(["--exact", "tls_client_child", "--nocapture"])
                        .env("ASTRA_SMTP_TLS_CONFIG", config.to_string());
                    command
                } else {
                    let mut command = std::process::Command::new(
                        std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".into()),
                    );
                    command.arg("-c").arg(format!("import json\nfrom zeropw.notify import NotifyConfig,_send\ntry:\n _send(NotifyConfig(**json.loads({:?})), 'subject', 'body')\n print('ASTRA_RESULT=sent')\nexcept Exception as e: print('ASTRA_RESULT='+type(e).__name__)",config.to_string())).env("PYTHONPATH",oracle::repo_root());
                    command
                };
                command.env("SSL_CERT_DIR", &empty).env(
                    "SSL_CERT_FILE",
                    if trusted {
                        pem.clone()
                    } else {
                        empty.join("nonexistent.pem")
                    },
                );
                let output = command.output().unwrap();
                assert!(
                    output.status.success(),
                    "client failed {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let stdout = String::from_utf8_lossy(&output.stdout);
                let result = stdout
                    .lines()
                    .find_map(|l| l.strip_prefix("ASTRA_RESULT="))
                    .expect("child result")
                    .to_owned();
                let commands = worker.join().unwrap();
                if trusted {
                    assert!(commands.iter().any(|c| c.eq_ignore_ascii_case("DATA")));
                } else {
                    assert!(
                        commands.is_empty(),
                        "untrusted TLS received application data"
                    );
                }
                println!("{mode} trusted={trusted} {language}={result}");
                outcomes.push(result);
            }
            if outcomes[0] != outcomes[1] {
                differences.push(format!(
                    "{mode} trusted={trusted}: Python={} Rust={}",
                    outcomes[0], outcomes[1]
                ));
            }
        }
    }
    assert!(differences.is_empty(), "TLS error parity: {differences:?}");
}
