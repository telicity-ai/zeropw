//! Loopback SMTP receiver and native `incident notify-test` driver for the
//! mailbox envelope checks. The expected envelopes are the `MAIL FROM` /
//! `RCPT TO` arguments the original Python prototype sent for the same
//! configured addresses (`fixtures/python/response/envelope_comments.json`).
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};
use zeropw::context::{Config, Context};

pub struct Receiver {
    /// Refuse every envelope except `sender@example.com` and
    /// `recipient@example.com` with 501.
    pub enforce: bool,
    /// Close the connection 0.2 s after `DATA` without replying.
    pub data_timeout: bool,
}

/// Start a one-connection receiver; the handle yields every command line.
pub fn receiver(options: Receiver) -> (u16, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let worker = thread::spawn(move || {
        let (mut wire, _) = listener.accept().unwrap();
        wire.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut reader = BufReader::new(wire.try_clone().unwrap());
        wire.write_all(b"220 synthetic ready\r\n").unwrap();
        let mut commands = vec![];
        loop {
            let mut line = Vec::new();
            if reader.read_until(b'\n', &mut line).unwrap_or(0) == 0 {
                break;
            }
            let text = String::from_utf8(line.clone()).unwrap();
            commands.push(text.trim().to_owned());
            let upper = text.to_ascii_uppercase();
            let reply: &[u8] = if upper.starts_with("EHLO") {
                b"250 synthetic\r\n"
            } else if options.enforce
                && upper.starts_with("MAIL")
                && !upper.starts_with("MAIL FROM:<SENDER@EXAMPLE.COM>")
            {
                b"501 invalid sender\r\n"
            } else if options.enforce
                && upper.starts_with("RCPT")
                && !upper.starts_with("RCPT TO:<RECIPIENT@EXAMPLE.COM>")
            {
                b"501 invalid recipient\r\n"
            } else if upper.starts_with("DATA") {
                if options.data_timeout {
                    thread::sleep(Duration::from_millis(200));
                    break;
                }
                wire.write_all(b"354 data\r\n").unwrap();
                loop {
                    let mut body = Vec::new();
                    if reader.read_until(b'\n', &mut body).unwrap_or(0) == 0 || body == b".\r\n" {
                        break;
                    }
                }
                b"250 accepted\r\n"
            } else if upper.starts_with("QUIT") {
                let _ = wire.write_all(b"221 bye\r\n");
                break;
            } else {
                b"250 ok\r\n"
            };
            if wire.write_all(reply).is_err() {
                break;
            }
        }
        commands
    });
    (port, worker)
}

pub struct State {
    _temp: tempfile::TempDir,
    pub ctx: Arc<Context>,
    pub path: PathBuf,
}

pub fn state() -> State {
    let temp = tempfile::TempDir::new().unwrap();
    let path = temp.path().join("state");
    let ctx = Arc::new(
        Context::initialize(
            &path,
            "synthetic-admin",
            "synthetic-recovery",
            Config::default(),
            zeropw::clock::system(),
        )
        .unwrap(),
    );
    State {
        _temp: temp,
        ctx,
        path,
    }
}

/// Configure `sender`/`recipient` and run the native `incident notify-test`.
pub fn notify_test(state: &State, port: u16, sender: &str, recipient: &str, timeout: f64) -> Value {
    state
        .ctx
        .state
        .write_json(
            "notify.json",
            &json!({"host": "127.0.0.1", "port": port, "mode": "plain", "sender": sender,
                    "recipients": [recipient], "timeout_seconds": timeout}),
        )
        .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_zeropw-admin"))
        .arg("--state-dir")
        .arg(&state.path)
        .args(["incident", "notify-test"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    let text = if output.stdout.is_empty() {
        output.stderr
    } else {
        output.stdout
    };
    serde_json::from_slice(&text).unwrap()
}

/// The envelope the original sent for `sender` and `recipient`.
pub fn recorded_envelope(sender: &str, recipient: &str) -> Vec<String> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/python/response/envelope_comments.json"
    ))
    .unwrap();
    let case = fixture["transport"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["sender"] == sender && c["recipient"] == recipient)
        .unwrap_or_else(|| panic!("no recorded envelope for {sender:?} -> {recipient:?}"));
    assert_eq!(case["result"], json!({"status": "sent"}));
    case["envelope"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

/// Send through the native CLI and require the recorded envelope.
pub fn check_envelopes(pairs: &[(&str, &str)]) {
    let state = state();
    let mut differences = vec![];
    for &(sender, recipient) in pairs {
        let (port, worker) = receiver(Receiver {
            enforce: false,
            data_timeout: false,
        });
        let result = notify_test(&state, port, sender, recipient, 1.0);
        let commands = worker.join().unwrap();
        assert_eq!(result, json!({"status": "sent"}), "{sender:?} -> {recipient:?}");
        let envelope: Vec<String> = commands
            .iter()
            .filter(|c| {
                let upper = c.to_ascii_uppercase();
                upper.starts_with("MAIL") || upper.starts_with("RCPT")
            })
            .map(|c| c.split_once(':').unwrap().1.to_owned())
            .collect();
        let expected = recorded_envelope(sender, recipient);
        if envelope != expected {
            differences.push(format!(
                "{sender:?} -> {recipient:?}: original={expected:?} native={envelope:?}"
            ));
        }
    }
    assert!(differences.is_empty(), "{differences:#?}");
}
