//! Built-in exceptions that escape to the HTTP server (PORTING.md §3c/§3d).
//!
//! DEVIATIONS rows 39/40, measured end to end: a handle
//! whose payload or signature segment holds a non-ASCII character makes
//! Python's `HandleIssuer.verify` raise a built-in exception
//! (`UnicodeEncodeError` from `_sign`, `TypeError` from
//! `hmac.compare_digest`). `gateway.relay` only catches `AuthFailed`, so the
//! HTTP server's catch-all answers a fixed 500 `internal_error` and no
//! `http_relay` denial is audited. An agent controls the token (URL prefix or
//! `X-ZeroPW-Handle` header, both decoded as latin-1), so the native server
//! must answer the same bytes and write the same audit records.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use zeropw::context::{Config, Context};
use zeropw::server::ZeroPWServer;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn run_python(script: &str) -> String {
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".into());
    let output = Command::new(interpreter)
        .arg("-c")
        .arg(script)
        .env("PYTHONPATH", repo_root())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run python3.12");
    assert!(
        output.status.success(),
        "python failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf-8 stdout")
}

/// Raw request bytes for each token, once in the URL prefix and once in the
/// handle header; the last token is ASCII (an ordinary forged signature).
fn requests() -> Vec<Vec<u8>> {
    let tokens: [&[u8]; 3] = [b"zpw1.ab\xe9.sig", b"zpw1.abc.si\xe9", b"zpw1.abc.sig"];
    let mut out = Vec::new();
    for token in tokens {
        let mut header = b"GET /relay/x HTTP/1.1\r\nHost: a\r\nX-ZeroPW-Handle: ".to_vec();
        header.extend_from_slice(token);
        header.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
        out.push(header);
        let mut url = b"GET /h/".to_vec();
        url.extend_from_slice(token);
        url.extend_from_slice(b"/x HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
        out.push(url);
    }
    out
}

/// The response with its `Date` header removed (the only line that varies).
fn normalise(response: &[u8]) -> String {
    String::from_utf8_lossy(response)
        .split("\r\n")
        .filter(|line| !line.starts_with("Date: "))
        .collect::<Vec<_>>()
        .join("\r\n")
}

#[test]
fn non_ascii_handle_segments_answer_like_the_python_server() {
    let hex: Vec<String> = requests().iter().map(hex::encode).collect();
    let script = format!(
        r#"
import json, socket, tempfile
from pathlib import Path
from zeropw.context import Context
from zeropw.server import ZeroPWServer
tmp = tempfile.mkdtemp()
ctx = Context.initialize(Path(tmp) / "state", "admin-passphrase-123456", "recovery-passphrase-123456")
srv = ZeroPWServer(ctx).serve_in_thread()
host, port = srv.server_address[:2]
before = len(ctx.audit.tail(10000))
out = []
for raw in {hex:?}:
    s = socket.create_connection((host, port))
    s.sendall(bytes.fromhex(raw))
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    out.append(data.hex())
events = [[r["event"], r.get("reason")] for r in ctx.audit.tail(10000)[before:]]
print(json.dumps({{"responses": out, "events": events}}))
srv.shutdown(); srv.server_close(); ctx.close()
"#
    );
    let python: serde_json::Value = serde_json::from_str(run_python(&script).trim()).unwrap();

    let temp = TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            temp.path().join("state"),
            "admin-passphrase-123456",
            "recovery-passphrase-123456",
            Config::default(),
            zeropw::clock::system(),
        )
        .unwrap(),
    );
    let server = ZeroPWServer::new(ctx.clone(), None, None).unwrap();
    server.serve_in_thread().unwrap();
    let before = ctx.audit.tail(10000).unwrap().len();
    let mut responses = Vec::new();
    for raw in requests() {
        let mut socket = TcpStream::connect(server.url().trim_start_matches("http://")).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket.write_all(&raw).unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).unwrap();
        responses.push(response);
    }
    let events: Vec<serde_json::Value> = ctx.audit.tail(10000).unwrap()[before..]
        .iter()
        .map(|r| serde_json::json!([r["event"], r["reason"]]))
        .collect();
    server.stop();

    let python_responses = python["responses"].as_array().unwrap();
    assert_eq!(python_responses.len(), responses.len());
    for (index, (rust, python)) in responses.iter().zip(python_responses).enumerate() {
        let python = hex::decode(python.as_str().unwrap()).unwrap();
        assert_eq!(normalise(rust), normalise(&python), "request {index}");
    }
    // Python itself: four 500s (no audit) and two audited AuthFailed 401s.
    assert!(normalise(&responses[0]).starts_with("HTTP/1.1 500 "));
    assert_eq!(
        serde_json::Value::Array(events),
        python["events"],
        "audit records written by the requests"
    );
}

/// PORTING.md §3d for the store rows (62-70): an `OSError` that escapes a
/// `StateDir` call made while serving a tool request is caught only by
/// `_dispatch`'s final `except Exception`, which answers the fixed 500
/// without the exception text. Here `.lock` is a directory, so the lock's
/// `os.open` raises `IsADirectoryError` inside `list_connections`.
#[test]
fn escaped_os_error_in_a_tool_call_answers_the_fixed_500() {
    let script = r#"
import os, socket, tempfile
from pathlib import Path
from zeropw.context import Context
from zeropw.server import ZeroPWServer
tmp = tempfile.mkdtemp()
ctx = Context.initialize(Path(tmp) / "state", "admin-passphrase-123456", "recovery-passphrase-123456")
token = ctx.policy.create_principal("alice", "cli")
srv = ZeroPWServer(ctx).serve_in_thread()
host, port = srv.server_address[:2]
lock = Path(tmp) / "state" / ".lock"
if lock.exists():
    lock.unlink()
lock.mkdir()
s = socket.create_connection((host, port))
s.sendall(("POST /v1/tools/list_connections HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer %s\r\n"
           "Content-Length: 2\r\nConnection: close\r\n\r\n{}" % token).encode())
data = b""
while True:
    chunk = s.recv(65536)
    if not chunk:
        break
    data += chunk
print(data.hex())
srv.shutdown(); srv.server_close()
"#;
    let python = hex::decode(run_python(script).trim()).unwrap();

    let temp = TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            temp.path().join("state"),
            "admin-passphrase-123456",
            "recovery-passphrase-123456",
            Config::default(),
            zeropw::clock::system(),
        )
        .unwrap(),
    );
    let token = ctx.policy.create_principal("alice", "cli").unwrap();
    let server = ZeroPWServer::new(ctx.clone(), None, None).unwrap();
    server.serve_in_thread().unwrap();
    let lock = temp.path().join("state").join(".lock");
    if lock.exists() {
        std::fs::remove_file(&lock).unwrap();
    }
    std::fs::create_dir(&lock).unwrap();
    let mut socket = TcpStream::connect(server.url().trim_start_matches("http://")).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    socket
        .write_all(
            format!(
                "POST /v1/tools/list_connections HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer {token}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            )
            .as_bytes(),
        )
        .unwrap();
    let mut response = Vec::new();
    socket.read_to_end(&mut response).unwrap();
    std::fs::remove_dir(&lock).unwrap();
    server.stop();
    assert!(normalise(&python).starts_with("HTTP/1.1 500 "));
    assert_eq!(normalise(&response), normalise(&python));
}
