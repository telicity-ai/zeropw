//! `serve` prints the server's request log (method and query-free path, with
//! handles masked) to stderr like the original CLI did, and `--quiet` prints
//! none.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn admin() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_zeropw-admin"));
    command
        .env("ZEROPW_ADMIN_PASSPHRASE", "admin-passphrase-1")
        .env("ZEROPW_RECOVERY_PASSPHRASE", "recovery-passphrase-1");
    command
}

fn get(port: u16, path: &str) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .unwrap();
    let mut reply = Vec::new();
    let _ = stream.read_to_end(&mut reply);
}

/// Start serve, send the requests, and collect the stderr lines printed
/// within a bounded wait.
fn serve_log(quiet: bool) -> Vec<String> {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    assert!(
        admin()
            .arg("--state-dir")
            .arg(&state)
            .arg("init")
            .output()
            .unwrap()
            .status
            .success()
    );
    let mut command = admin();
    command.arg("--state-dir").arg(&state).arg("serve");
    if quiet {
        command.arg("--quiet");
    }
    let mut child: Child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut startup = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut startup)
        .unwrap();
    let startup: serde_json::Value = serde_json::from_str(&startup).unwrap();
    let port: u16 = startup["url"]
        .as_str()
        .unwrap()
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let (tx, rx) = mpsc::channel();
    let stderr = child.stderr.take().unwrap();
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    get(port, "/nope?token=synthetic-query");
    get(port, "/h/zpw1.synthetic-handle-value/repos?x=1");
    let mut lines = Vec::new();
    let expected = if quiet { 0 } else { 2 };
    while lines.len() < expected {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(line) => lines.push(line),
            Err(_) => break,
        }
    }
    // Nothing more may arrive (e.g. under --quiet).
    thread::sleep(Duration::from_millis(600));
    lines.extend(rx.try_iter());
    let _ = child.kill();
    let _ = child.wait();
    lines
}

#[test]
fn serve_request_log_masks_queries_and_handles() {
    // The prototype's CLI printed exactly these lines for these requests.
    assert_eq!(serve_log(false), ["GET /nope", "GET /h/<handle>/..."]);
}

#[test]
fn quiet_serve_prints_no_request_log() {
    assert_eq!(serve_log(true), Vec::<String>::new());
}
