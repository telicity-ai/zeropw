//! Independent gpt-6-astra response compatibility review at 92abed0.
//! Synthetic state and loopback SMTP only; expected outcomes were recorded
//! from the original Python prototype.
use serde_json::json;
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

/// Hand-edited numeric attempt counts must not break a successful delivery.
#[test]
fn successful_notification_with_hand_edited_numeric_attempts_is_sent() {
    let (_tmp, ctx) = fixture();
    for attempts in [
        json!(1.5),
        json!(-2.5),
        json!(1.0),
        json!(true),
        json!(-18446744073709551616_i128),
        json!(18446744073709551616_u128),
    ] {
        let original = json!({"id":"inc-test","opened_at":"2023-11-14T22:13:20Z","status":"open","scope":"principal","notification":{"attempts":attempts}});
        let (port, worker) = receiver(false);
        ctx.state.write_json("notify.json", &json!({"host":"127.0.0.1","port":port,"mode":"plain","sender":"sender@example.com","recipients":["recipient@example.com"],"timeout_seconds":1.0})).unwrap();
        let mut incident = Incident::from_dict(&original).unwrap();
        notify::deliver(&ctx, &mut incident).unwrap();
        worker.join().unwrap();
        assert_eq!(incident.notification["status"], "sent", "attempts={attempts}");
    }
}

#[test]
fn smtp_supported_comment_mailbox_forms_match_python() {
    let (_tmp, ctx) = fixture();
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
        // The receiver refuses any envelope but the bare mailboxes; the
        // original delivered every one of these.
        let (port, worker) = receiver(true);
        let config = json!({"host":"127.0.0.1","port":port,"mode":"plain","sender":sender,"recipients":[recipient],"timeout_seconds":1.0});
        ctx.state.write_json("notify.json", &config).unwrap();
        let result = notify::send_test_message(&ctx).unwrap();
        let commands = worker.join().unwrap();
        assert_eq!(
            result.get("error").or_else(|| result.get("status")),
            Some(&json!("sent")),
            "sender={sender:?} recipient={recipient:?}: {commands:?}"
        );
    }
}

#[test]
fn smtp_reply_timeout_identity_matches_python() {
    let (_tmp, ctx) = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let worker = thread::spawn(move || {
        let (_socket, _) = listener.accept().unwrap();
        // A connected SMTP peer that has not yet sent its greeting.
        thread::sleep(Duration::from_millis(250));
    });
    let config = json!({"host":"127.0.0.1","port":port,"mode":"plain","sender":"sender@example.com","recipients":["recipient@example.com"],"timeout_seconds":0.05});
    ctx.state.write_json("notify.json", &config).unwrap();
    let result = notify::send_test_message(&ctx).unwrap();
    worker.join().unwrap();
    // The error name the original reported for a greeting read timeout.
    assert_eq!(result["error"], "SMTPServerDisconnected", "{result}");
}
