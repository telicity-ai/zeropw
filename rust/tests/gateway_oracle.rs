//! Differential tests for `zeropw::gateway`/`zeropw::fake_upstream` against
//! the Python prototype, per `rust/PORTING.md`'s "add oracle differential
//! tests" rule for work unit F.
//!
//! `crate::oracle` is `#[cfg(test)] pub(crate)` and not reachable from an
//! integration test binary (see `tests/policy_oracle.rs`'s doc comment for
//! why); this file has its own small `run_python` helper, same as the other
//! `*_oracle.rs` files.
//!
//! Covers:
//! - `credential_patterns` byte-identical with Python's
//!   `gateway.credential_patterns`, for a table of secrets/usernames
//!   exercising every encoding (plain, base64 std/urlsafe padded and core
//!   alignments, hex, percent both hex casings and both `quote`/
//!   `quote_plus`, JSON with/without `ensure_ascii`, HTML-escaped, and the
//!   Basic `user:secret` forms).
//! - The exact HTTP/1.1 request bytes `gateway::relay_for_caller` sends are
//!   byte-identical to what `zeropw.gateway.relay_for_caller` sends for the
//!   same inputs, captured by a raw TCP listener shared by both languages
//!   (so the `Host` header's port matches without normalization).
//! - `gateway::relay_for_caller` (Rust) successfully relays to a live
//!   `zeropw.fake_upstream.FakeUpstream` running as a Python subprocess,
//!   and the credential the fake recorded is exactly the one the Rust
//!   vault stored -- proving the two languages' HTTP framing and auth
//!   header construction interoperate, not just "look the same".

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use tempfile::TempDir;

use zeropw::context::{Config, Context};
use zeropw::gateway::{self, Headers};
use zeropw::policy::{Connection, HttpAuth, HttpScope, HttpTarget};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn run_python(script: &str) -> String {
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".to_string());
    let output = Command::new(interpreter)
        .arg("-c")
        .arg(script)
        .env("PYTHONPATH", repo_root())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run python");
    assert!(
        output.status.success(),
        "python stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

fn py_str_literal(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
}

// -------------------------------------------------------- credential_patterns

#[test]
fn credential_patterns_matches_python_byte_for_byte() {
    use base64::Engine as _;
    let table: &[(&[u8], Option<&str>)] = &[
        (b"synthetic-token-alpha-0123456789ABCDEFGHIJ", None),
        (
            b"synthetic-token-alpha-0123456789ABCDEFGHIJ",
            Some("synthetic-user"),
        ),
        (b"AKIA/secret+Key 9=abc", None),
        (b"synthetic pass word/+=", Some("synthetic-user")),
        (
            b"synthetic-token/enc+ode=chars:>>>?<&\"\\x-0123456789",
            Some("synthetic-user"),
        ),
        (b"Synthetic/TOKEN", None),
        (
            b"synthetic\x00\xff\xfe-binary-credential",
            Some("synthetic-user"),
        ),
    ];
    for (secret, username) in table {
        let rust_patterns = gateway::credential_patterns(secret, *username);
        let rust_b64: Vec<String> = rust_patterns
            .iter()
            .map(|p| base64::engine::general_purpose::STANDARD.encode(p))
            .collect();

        let secret_b64 = base64::engine::general_purpose::STANDARD.encode(secret);
        let username_py = match username {
            Some(u) => py_str_literal(u),
            None => "None".to_string(),
        };
        let script = format!(
            "import base64, json\nfrom zeropw.gateway import credential_patterns\nsecret = base64.b64decode({})\npatterns = credential_patterns(secret, {})\nprint(json.dumps([base64.b64encode(p).decode() for p in patterns]))",
            py_str_literal(&secret_b64),
            username_py
        );
        let out = run_python(&script);
        let python_b64: Vec<String> = serde_json::from_str(out.trim()).expect("json array");
        assert_eq!(
            rust_b64,
            python_b64,
            "secret={:?} username={:?}",
            String::from_utf8_lossy(secret),
            username
        );
    }
}

// -------------------------------------------------------------- ADMIN setup

const ADMIN: &str = "admin-passphrase-1";
const RECOVERY: &str = "recovery-passphrase-1";
const SECRET: &str = "synthetic-token-oracle-cross-lang-0123456789";

fn rust_ctx(tmp: &TempDir) -> Context {
    let clock = zeropw::clock::fixed(1_700_000_000.0);
    let ctx = Context::initialize(
        tmp.path().join("state"),
        ADMIN,
        RECOVERY,
        Config::default(),
        clock,
    )
    .expect("init ctx");
    ctx.projects
        .create("demo", zeropw::projects::DEFAULT_ENVIRONMENTS)
        .unwrap();
    ctx
}

// --------------------------------------------------- raw request byte oracle

/// Accepts exactly one connection on `listener`, reads until the peer
/// closes (both the Rust and the Python relay always send `Connection:
/// close` and finish the write side before reading the response), and
/// writes back a minimal `200 OK` so the relay call completes normally.
fn capture_one_request(listener: &TcpListener) -> Vec<u8> {
    let (mut stream, _) = listener.accept().expect("accept");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut received = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => received.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let _ = stream.flush();
    received
}

fn rust_request_bytes(port: u16) -> Vec<u8> {
    let tmp = TempDir::new().unwrap();
    let ctx = rust_ctx(&tmp);
    ctx.vault
        .put_secret(
            "gh-token",
            "api_key",
            SECRET.as_bytes(),
            "demo",
            "dev",
            true,
        )
        .unwrap();
    ctx.policy.create_principal("agent-1", "cli").unwrap();
    let connection = Connection::new(
        "gh",
        "demo",
        "dev",
        "svc",
        "http",
        "gh-token",
        None,
        "",
        Some(HttpTarget::new("http", "127.0.0.1", port as i64, None, false).unwrap()),
        Some(HttpAuth::bearer()),
        Some(HttpScope::new(None, None, vec![]).unwrap()),
        None,
        None,
        0,
        "active",
        "",
        "",
    )
    .unwrap();
    ctx.policy.create_connection(connection).unwrap();
    ctx.policy
        .create_grant("agent-1", "gh", Some(3600), None)
        .unwrap();

    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind capture port");
    let capture = std::thread::spawn(move || capture_one_request(&listener));

    let headers: Headers = vec![
        ("Accept".to_string(), "application/json".to_string()),
        ("User-Agent".to_string(), "oracle-test/1".to_string()),
    ];
    let body = br#"{"title":"from oracle"}"#;
    let result = gateway::relay_for_caller(
        &ctx,
        "agent-1",
        "gh",
        "POST",
        "/repos/demo/issues",
        &headers,
        body,
        None,
    );
    assert!(
        result.status == 200 || result.reason.is_some(),
        "relay result: {result:?}"
    );
    capture.join().expect("capture thread")
}

fn python_request_bytes(port: u16) -> Vec<u8> {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().join("state");
    let capture_thread = {
        let addr = ("127.0.0.1".to_string(), port);
        std::thread::spawn(move || {
            let listener = TcpListener::bind(addr).expect("bind capture port (python)");
            capture_one_request(&listener)
        })
    };
    // Give the Rust-side listener a beat to bind before the subprocess dials it.
    std::thread::sleep(Duration::from_millis(50));

    let script = format!(
        r#"
from pathlib import Path
from zeropw import policy as P
from zeropw.context import Config, Context
from zeropw import gateway

ctx = Context.initialize(Path({state}), {admin}, {recovery}, Config(), lambda: 1700000000.0)
ctx.projects.create("demo")
ctx.vault.put_secret("gh-token", "api_key", {secret}.encode(), "demo", "dev")
ctx.policy.create_principal("agent-1")
ctx.policy.create_connection(P.Connection(
    id="gh", project="demo", environment="dev", service="svc", kind="http", secret_id="gh-token",
    secret_version=None, description="", http_target=P.HttpTarget("http", "127.0.0.1", {port}, None),
    http_auth=P.HttpAuth("bearer"), http_scope=P.HttpScope(), ssh_target=None, cli=None,
    policy_version=0, status="active", created_at="", updated_at=""))
ctx.policy.create_grant("agent-1", "gh", 3600, None)
gateway.relay_for_caller(ctx, "agent-1", "gh", "POST", "/repos/demo/issues",
    {{"Accept": "application/json", "User-Agent": "oracle-test/1"}}, b'{{"title":"from oracle"}}')
"#,
        state = py_str_literal(state_dir.to_str().unwrap()),
        admin = py_str_literal(ADMIN),
        recovery = py_str_literal(RECOVERY),
        secret = py_str_literal(SECRET),
        port = port,
    );
    run_python(&script);
    capture_thread.join().expect("capture thread (python)")
}

/// Normalizes the one piece of the request that legitimately differs
/// between the two captures: none, actually -- both dial the *same* fixed
/// port, chosen up front, so `Host: 127.0.0.1:<port>` is identical too.
fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.local_addr().unwrap().port()
}

#[test]
fn relay_for_caller_request_bytes_match_python_byte_for_byte() {
    // Two fixed, distinct ports (chosen up front and released) so each
    // capture step can bind its own listener without a race between the
    // Rust and Python runs.
    let rust_port = free_port();
    let python_port = free_port();
    assert_ne!(rust_port, python_port);

    let rust_bytes = rust_request_bytes(rust_port);
    let python_bytes = python_request_bytes(python_port);

    let normalize = |bytes: &[u8], port: u16| -> String {
        String::from_utf8_lossy(bytes).replace(&format!("127.0.0.1:{port}"), "127.0.0.1:PORT")
    };
    let rust_text = normalize(&rust_bytes, rust_port);
    let python_text = normalize(&python_bytes, python_port);
    assert_eq!(rust_text, python_text);
}

// ------------------------------------------------- live Python FakeUpstream

/// Runs `zeropw.fake_upstream.FakeUpstream` in a subprocess, printing its
/// port on stdout, and keeps it alive until the returned child is killed.
struct PythonFakeUpstream {
    child: std::process::Child,
    port: u16,
}

impl PythonFakeUpstream {
    fn start(secret: &str) -> Self {
        let interpreter =
            std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".to_string());
        let script = format!(
            r#"
import sys, time
from zeropw.fake_upstream import FakeUpstream
fake = FakeUpstream({secret}).start()
print(fake.port, flush=True)
try:
    time.sleep(30)
finally:
    fake.stop()
"#,
            secret = py_str_literal(secret),
        );
        let mut child = Command::new(interpreter)
            .arg("-c")
            .arg(script)
            .env("PYTHONPATH", repo_root())
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn python fake upstream");
        let stdout = child.stdout.take().expect("stdout");
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        use std::io::BufRead;
        reader.read_line(&mut line).expect("read port line");
        let port: u16 = line.trim().parse().expect("port number");
        PythonFakeUpstream { child, port }
    }
}

impl Drop for PythonFakeUpstream {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn rust_relay_reaches_a_live_python_fake_upstream() {
    let fake = PythonFakeUpstream::start(SECRET);
    // Give the subprocess a moment to bind before dialing it.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", fake.port)).is_err()
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(20));
    }

    let tmp = TempDir::new().unwrap();
    let ctx = rust_ctx(&tmp);
    ctx.vault
        .put_secret(
            "gh-token",
            "api_key",
            SECRET.as_bytes(),
            "demo",
            "dev",
            true,
        )
        .unwrap();
    ctx.policy.create_principal("agent-1", "cli").unwrap();
    let connection = Connection::new(
        "gh",
        "demo",
        "dev",
        "svc",
        "http",
        "gh-token",
        None,
        "",
        Some(HttpTarget::new("http", "127.0.0.1", fake.port as i64, None, false).unwrap()),
        Some(HttpAuth::bearer()),
        Some(HttpScope::new(None, None, vec![]).unwrap()),
        None,
        None,
        0,
        "active",
        "",
        "",
    )
    .unwrap();
    ctx.policy.create_connection(connection).unwrap();
    ctx.policy
        .create_grant("agent-1", "gh", Some(3600), None)
        .unwrap();

    // `FakeUpstream._authorized` only accepts `Authorization: Bearer
    // <exact SECRET>`; a 200 here (rather than the fixture's 401) proves
    // the *exact* credential the Rust vault stored reached the live Python
    // fixture byte-for-byte, not merely "some" bearer token. (`/debug/token`
    // would also prove it, but the gateway's own reflection guard blocks
    // that response before it reaches this assertion, credential included.)
    let result = gateway::relay_for_caller(
        &ctx,
        "agent-1",
        "gh",
        "GET",
        "/me",
        &Headers::new(),
        b"",
        None,
    );
    assert_eq!(result.status, 200);
    assert_eq!(
        result.json().expect("test body is valid utf-8 JSON"),
        serde_json::json!({"login": "synthetic-user"})
    );
}
