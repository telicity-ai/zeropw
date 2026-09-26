//! `serve` prints the server's request log (method and query-free path, with
//! handles masked) to stderr like the original CLI, and `--quiet` prints none.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn python() -> String {
    std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".into())
}

fn admin(native: bool) -> Command {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut command = if native {
        Command::new(env!("CARGO_BIN_EXE_zeropw-admin"))
    } else {
        let mut c = Command::new(python());
        c.args(["-m", "zeropw.admin_cli"]);
        c
    };
    command
        .current_dir(root)
        .env("PYTHONPATH", root)
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
fn serve_log(native: bool, quiet: bool) -> Vec<String> {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    assert!(
        admin(true)
            .arg("--state-dir")
            .arg(&state)
            .arg("init")
            .output()
            .unwrap()
            .status
            .success()
    );
    let mut command = admin(native);
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
fn serve_request_log_matches_the_original_and_masks_handles() {
    let original = serve_log(false, false);
    let native = serve_log(true, false);
    assert_eq!(native, original);
    assert_eq!(native, ["GET /nope", "GET /h/<handle>/..."]);
}

#[test]
fn quiet_serve_prints_no_request_log() {
    assert_eq!(serve_log(true, true), Vec::<String>::new());
    assert_eq!(serve_log(false, true), Vec::<String>::new());
}
