//! Built-in errors that escape to the HTTP server fail closed with the fixed
//! reply (`PORTING.md` §0 boundary 4).
//!
//! A handle whose payload or signature segment holds a non-ASCII character
//! is refused with a fixed `500 internal_error` and no `http_relay` denial
//! is audited; an ordinary forged ASCII signature is an audited
//! `401 handle_signature`. An agent controls the token (URL prefix or
//! `X-ZeroPW-Handle` header, both decoded as latin-1), so the reply must
//! never echo it. The expected bytes are the ones the prototype's server
//! answered (measured once; only the `Date` header varies).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use zeropw::context::{Config, Context};
use zeropw::server::ZeroPWServer;

const INTERNAL_ERROR: &str = "HTTP/1.1 500 Internal Server Error\r\nServer: zeropw-prototype \r\nContent-Type: application/json\r\nContent-Length: 54\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{\"error\": \"InternalError\", \"reason\": \"internal_error\"}";
const HANDLE_SIGNATURE: &str = "HTTP/1.1 401 Unauthorized\r\nServer: zeropw-prototype \r\nContent-Type: application/json\r\nContent-Length: 53\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{\"error\": \"AuthFailed\", \"reason\": \"handle_signature\"}";

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
fn non_ascii_handle_segments_answer_the_fixed_500() {
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

    let normalised: Vec<String> = responses.iter().map(|r| normalise(r)).collect();
    assert_eq!(
        normalised,
        [
            INTERNAL_ERROR,
            INTERNAL_ERROR,
            INTERNAL_ERROR,
            INTERNAL_ERROR,
            HANDLE_SIGNATURE,
            HANDLE_SIGNATURE
        ]
    );
    // Only the two ASCII forgeries are audited denials.
    assert_eq!(
        serde_json::Value::Array(events),
        serde_json::json!([
            ["http_relay", "handle_signature"],
            ["http_relay", "handle_signature"]
        ]),
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
    assert_eq!(normalise(&response), INTERNAL_ERROR);
}
