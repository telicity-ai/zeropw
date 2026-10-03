//! Independent gpt-6-astra response review at d44eebe85dc6dd83fc57b3ba576a9b8135356af2.
//! Synthetic loopback SMTP fixtures; expected outcomes were recorded from the
//! original Python prototype.
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
        let expected = match scenario {
            "quit_failure" => "SMTPResponseException",
            "auth_failure" => "SMTPAuthenticationError",
            _ => "sent",
        };
        let (port, worker) = receiver(scenario);
        let auth = ["auth_equals", "auth_failure", "cram_verified"].contains(&scenario);
        let config = json!({"host":"127.0.0.1","port":port,"mode":"plain","sender":if scenario == "comment_address" {"sender@example.com (Synthetic Sender)"} else {"sender@example.com"},"recipients":[if scenario == "international" {"관리자@example.com"} else {"recipient@example.com"}],"username":if auth {Some("synthetic-user")} else {None},"password_file":pass,"timeout_seconds":1.0});
        let result = rust_send(&ctx, &config);
        let commands = worker.join().unwrap();
        println!("{scenario}={result} commands={commands:?}");
        if result != expected {
            differences.push(format!("{scenario}: Python={expected} Rust={result}"));
        }
    }
    assert!(
        differences.is_empty(),
        "residual SMTP parity: {differences:?}"
    );
}

/// Hand-edited notification attempt counts (negative, beyond 64 bits) must
/// not panic delivery; a successful send records `sent`.
#[test]
fn hand_edited_notification_attempt_counts_do_not_panic_delivery() {
    let (_tmp, ctx) = fixture();
    ctx.state.write_json("notify.json", &json!({})).unwrap();
    let mut incident = Incident::from_dict(&json!({"id":"inc-max","opened_at":"2023-11-14T22:13:20Z","status":"open","scope":"principal","notification":{"attempts":-1}})).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        notify::deliver(&ctx, &mut incident)
    }));
    assert!(result.is_ok(), "delivery panicked for a persisted count");

    let original = json!({"id":"inc-max","opened_at":"2023-11-14T22:13:20Z","status":"open","scope":"principal","notification":{"attempts":u64::MAX}});
    let (port, worker) = receiver("normal");
    ctx.state.write_json("notify.json",&json!({"host":"127.0.0.1","port":port,"mode":"plain","sender":"sender@example.com","recipients":["recipient@example.com"],"timeout_seconds":1.0})).unwrap();
    let mut incident = Incident::from_dict(&original).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        notify::deliver(&ctx, &mut incident)
    }));
    worker.join().unwrap();
    assert!(result.is_ok(), "successful send panicked on attempts + 1");
    assert_eq!(incident.notification["status"], "sent");
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
    // The complete assessment the original computed for the same state.
    assert_eq!(
        result,
        json!({"principals": [{"id": "agent-1", "created_at": "2023-11-14T22:13:20Z", "runtime": "synthetic-runtime"}, {"id": "agent-2", "created_at": "2023-11-14T22:13:20Z", "runtime": "synthetic-runtime"}], "secrets": [{"secret_id": "held", "kind": "api_key", "project": "demo", "environment": "dev", "service": "synthetic", "connections": ["held"], "targets": [{"host": "127.0.0.1", "port": 8080}], "first_used": null, "last_used": null, "use_count": 0, "active_version": 1, "tier": "recommended"}, {"secret_id": "used", "kind": "api_key", "project": "demo", "environment": "dev", "service": "synthetic", "connections": ["used"], "targets": [{"host": "127.0.0.1", "port": 8080}], "first_used": "2023-11-14T22:13:20Z", "last_used": "2023-11-14T22:13:20Z", "use_count": 1, "active_version": 1, "tier": "mandatory"}]})
    );
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
            let expected = if trusted {
                "sent"
            } else {
                "SSLCertVerificationError"
            };
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
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", "tls_client_child", "--nocapture"])
                .env("ASTRA_SMTP_TLS_CONFIG", config.to_string())
                .env("SSL_CERT_DIR", &empty)
                .env(
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
            println!("{mode} trusted={trusted} {result}");
            if result != expected {
                differences.push(format!(
                    "{mode} trusted={trusted}: Python={expected} Rust={result}"
                ));
            }
        }
    }
    assert!(differences.is_empty(), "TLS error parity: {differences:?}");
}
