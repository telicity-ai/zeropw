//! Independent gpt-6-astra response compatibility review at 92abed0.
//! Synthetic state and loopback SMTP only; Python is the behavior oracle.
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
fn receiver(enforce_mailboxes: bool) -> (u16, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let worker = thread::spawn(move || {
        let (mut wire, _) = listener.accept().unwrap();
        wire.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        wire.write_all(b"220 synthetic ready\r\n").unwrap();
        let mut log = vec![];
        loop {
            let cmd = line(&mut wire);
            if cmd.is_empty() {
                break;
            }
            log.push(cmd.trim().to_owned());
            let upper = cmd.to_ascii_uppercase();
            let response = if upper.starts_with("EHLO") {
                "250 synthetic\r\n"
            } else if upper.starts_with("MAIL")
                && enforce_mailboxes
                && !upper.starts_with("MAIL FROM:<SENDER@EXAMPLE.COM>")
            {
                "501 invalid sender\r\n"
            } else if upper.starts_with("RCPT")
                && enforce_mailboxes
                && !upper.starts_with("RCPT TO:<RECIPIENT@EXAMPLE.COM>")
            {
                "501 invalid recipient\r\n"
            } else if upper.starts_with("DATA") {
                wire.write_all(b"354 data\r\n").unwrap();
                loop {
                    let body = line(&mut wire);
                    if body.is_empty() || body == ".\r\n" {
                        break;
                    }
                }
                "250 accepted\r\n"
            } else if upper.starts_with("QUIT") {
                let _ = wire.write_all(b"221 bye\r\n");
                break;
            } else {
                "250 ok\r\n"
            };
            if wire.write_all(response.as_bytes()).is_err() {
                break;
            }
        }
        log
    });
    (port, worker)
}

#[test]
fn successful_notification_numeric_attempts_match_python() {
    let (_tmp, ctx) = fixture();
    let mut differences = vec![];
    for attempts in [
        json!(1.5),
        json!(-2.5),
        json!(1.0),
        json!(true),
        json!(-18446744073709551616_i128),
        json!(18446744073709551616_u128),
    ] {
        let original = json!({"id":"inc-test","opened_at":"2023-11-14T22:13:20Z","status":"open","scope":"principal","notification":{"attempts":attempts}});
        let mut outcomes = vec![];
        for language in ["python", "rust"] {
            let (port, worker) = receiver(false);
            ctx.state.write_json("notify.json", &json!({"host":"127.0.0.1","port":port,"mode":"plain","sender":"sender@example.com","recipients":["recipient@example.com"],"timeout_seconds":1.0})).unwrap();
            let value = if language == "python" {
                serde_json::from_str::<Value>(&oracle::python(&format!("import json\nfrom zeropw.context import Context\nfrom zeropw.incident import Incident\nfrom zeropw.notify import deliver\nc=Context.open({:?},clock=lambda:1700000000.0)\ni=Incident.from_dict(json.loads({:?}))\ndeliver(c,i)\nprint(json.dumps(i.notification))",ctx.state.path.to_str().unwrap(), original.to_string()))).unwrap()
            } else {
                let mut incident = Incident::from_dict(&original).unwrap();
                notify::deliver(&ctx, &mut incident).unwrap();
                incident.notification
            };
            worker.join().unwrap();
            outcomes.push(value);
        }
        if outcomes[0] != outcomes[1] {
            differences.push(format!(
                "attempts={attempts} Python={} Rust={}",
                outcomes[0], outcomes[1]
            ));
        }
    }
    assert!(
        differences.is_empty(),
        "successful count differences: {differences:#?}"
    );
}

#[test]
fn smtp_supported_comment_mailbox_forms_match_python() {
    let (_tmp, ctx) = fixture();
    let mut differences = vec![];
    for (sender, recipient) in [
        (
            "sender@example.com(Synthetic Sender)",
            "recipient@example.com",
        ),
        (
            "(Synthetic Sender) sender@example.com",
            "recipient@example.com",
        ),
        (
            "sender@example.com",
            "recipient@example.com(Synthetic Recipient)",
        ),
        (
            "sender@example.com",
            "(Synthetic Recipient) recipient@example.com",
        ),
        (
            "sender@example.com (Synthetic Sender)",
            "recipient@example.com (Synthetic Recipient)",
        ),
    ] {
        let mut outcomes = vec![];
        for language in ["python", "rust"] {
            let (port, worker) = receiver(true);
            let config = json!({"host":"127.0.0.1","port":port,"mode":"plain","sender":sender,"recipients":[recipient],"timeout_seconds":1.0});
            let outcome = if language == "python" {
                oracle::python(&format!("import json\nfrom zeropw.notify import NotifyConfig,_send\ntry:\n _send(NotifyConfig(**json.loads({:?})), 'synthetic subject','synthetic body')\n print('sent')\nexcept Exception as e: print(type(e).__name__)", config.to_string())).trim().to_owned()
            } else {
                ctx.state.write_json("notify.json", &config).unwrap();
                let result = notify::send_test_message(&ctx).unwrap();
                result
                    .get("error")
                    .or_else(|| result.get("status"))
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned()
            };
            let commands = worker.join().unwrap();
            outcomes.push((outcome, commands));
        }
        if outcomes[0].0 != outcomes[1].0 {
            differences.push(format!(
                "sender={sender:?} recipient={recipient:?}: {outcomes:?}"
            ));
        }
    }
    assert!(
        differences.is_empty(),
        "mailbox differences: {differences:#?}"
    );
}

#[test]
fn incident_dictionary_keys_keep_exact_python_numeric_identity() {
    let mut inputs = vec![];
    for field in ["actions", "assessment", "notification"] {
        for pairs in [
            json!([
                [9007199254740992_u64, "first"],
                [9007199254740993_u64, "second"]
            ]),
            json!([
                [9007199254740992.0, "first"],
                [9007199254740993_u64, "second"]
            ]),
            json!([[true, "first"], [1, "second"]]),
            json!([[null, "first"], ["null", "second"]]),
            json!([[[], 1]]),
            json!([{"a":0,"b":1}]),
        ] {
            let mut input = json!({"id":"inc-test","opened_at":"2023-11-14T22:13:20Z","status":"open","scope":"principal"});
            input[field] = pairs;
            inputs.push(input);
        }
    }
    let expected: Vec<Value> = serde_json::from_str(&oracle::python(&format!("import json\nfrom zeropw.incident import Incident\nout=[]\nfor x in json.loads({:?}):\n try: out.append({{'ok':Incident.from_dict(x).to_dict()}})\n except Exception as e: out.append({{'error':getattr(e,'reason',type(e).__name__)}})\nprint(json.dumps(out))",serde_json::to_string(&inputs).unwrap()))).unwrap();
    let mut differences = vec![];
    for (input, expected) in inputs.iter().zip(expected) {
        let actual = match Incident::from_dict(input) {
            Ok(i) => json!({"ok":i.to_dict()}),
            Err(e) => json!({"error":e.reason}),
        };
        if expected != actual {
            differences.push(format!("input={input} Python={expected} Rust={actual}"));
        }
    }
    assert!(
        differences.is_empty(),
        "dictionary key differences: {differences:#?}"
    );
}

#[test]
fn smtp_reply_timeout_identity_matches_python() {
    let (_tmp, ctx) = fixture();
    let mut outcomes = vec![];
    for language in ["python", "rust"] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let worker = thread::spawn(move || {
            let (_socket, _) = listener.accept().unwrap();
            // A connected SMTP peer that has not yet sent its greeting.
            thread::sleep(Duration::from_millis(250));
        });
        let config = json!({"host":"127.0.0.1","port":port,"mode":"plain","sender":"sender@example.com","recipients":["recipient@example.com"],"timeout_seconds":0.05});
        let outcome = if language == "python" {
            oracle::python(&format!("import json\nfrom zeropw.notify import NotifyConfig,_send\ntry:\n _send(NotifyConfig(**json.loads({:?})), 'synthetic subject','synthetic body')\n print('sent')\nexcept Exception as e: print(type(e).__name__)", config.to_string())).trim().to_owned()
        } else {
            ctx.state.write_json("notify.json", &config).unwrap();
            let result = notify::send_test_message(&ctx).unwrap();
            result["error"].as_str().unwrap().to_owned()
        };
        worker.join().unwrap();
        outcomes.push(outcome);
    }
    assert_eq!(
        outcomes[0], outcomes[1],
        "SMTP greeting read timeout: Python then Rust"
    );
}
