//! Wire-format tests for `zeropw::gateway` against golden fixtures the Python
//! prototype produced once (`tests/fixtures/python/gateway/GENERATE.md`).
//! The gateway's upstream request is a wire format another party parses
//! (`PORTING.md` §0 boundary 2), and `credential_patterns` decides what the
//! gateway redacts from upstream output (boundary 4).
//!
//! Covers:
//! - `credential_patterns` byte-identical with the patterns Python's
//!   `gateway.credential_patterns` derived, for a table of secrets/usernames
//!   exercising every encoding (plain, base64 std/urlsafe padded and core
//!   alignments, hex, percent both hex casings and both `quote`/
//!   `quote_plus`, JSON with/without `ensure_ascii`, HTML-escaped, and the
//!   Basic `user:secret` forms).
//! - The exact HTTP/1.1 request bytes `gateway::relay_for_caller` sends for
//!   every header-order, method/body, auth-mode and header-collision shape
//!   are byte-identical to what `zeropw.gateway.relay_for_caller` sent for
//!   the same inputs (the upstream port normalized to `PORT`).
//! - `gateway::relay_for_caller` relays to a live `FakeUpstream`, and the
//!   credential the fake checked is exactly the one the vault stored.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use base64::Engine as _;
use serde_json::Value;
use tempfile::TempDir;

use zeropw::context::{Config, Context};
use zeropw::fake_upstream::FakeUpstream;
use zeropw::gateway::{self, Headers};
use zeropw::policy::{Connection, HttpAuth, HttpScope, HttpTarget};

const CREDENTIAL_PATTERNS: &str = include_str!("fixtures/python/gateway/credential_patterns.json");
const REQUEST_BYTES: &str = include_str!("fixtures/python/gateway/request_bytes.json");

fn b64(text: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .expect("fixture base64")
}

// -------------------------------------------------------- credential_patterns

#[test]
fn credential_patterns_match_the_python_fixture() {
    let table: Vec<Value> = serde_json::from_str(CREDENTIAL_PATTERNS).unwrap();
    assert_eq!(table.len(), 7);
    for row in &table {
        let secret = b64(row["secret_b64"].as_str().unwrap());
        let username = row["username"].as_str();
        let expected: Vec<Vec<u8>> = row["patterns_b64"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| b64(p.as_str().unwrap()))
            .collect();
        assert!(!expected.is_empty());
        assert_eq!(
            gateway::credential_patterns(&secret, username),
            expected,
            "secret={:?} username={username:?}",
            String::from_utf8_lossy(&secret),
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
    ctx
}

fn connect_gh(ctx: &Context, port: u16, auth: HttpAuth) {
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
        Some(auth),
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
}

// --------------------------------------------------- raw request bytes

/// Accepts exactly one connection on `listener`, reads the request head and
/// its `Content-Length` body, and writes back a minimal `200 OK` so the
/// relay call completes normally.
fn capture_one_request(listener: &TcpListener) -> Vec<u8> {
    let (mut stream, _) = listener.accept().expect("accept");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut received = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        // Stop once the head and its declared `Content-Length` body have
        // arrived (the relay does not half-close before reading the reply,
        // so waiting for EOF would only wait out the read timeout).
        if let Some(head_end) = received.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&received[..head_end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if received.len() >= head_end + 4 + length {
                break;
            }
        }
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

/// The bytes `relay_for_caller` writes upstream for one fixture case, with
/// the upstream port normalized to `PORT` like the fixture.
fn rust_wire_bytes(case: &Value) -> String {
    let tmp = TempDir::new().unwrap();
    let ctx = rust_ctx(&tmp);
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind capture port");
    let port = listener.local_addr().unwrap().port();
    let auth = &case["auth"];
    let auth = HttpAuth::new(
        auth[0].as_str().unwrap(),
        auth[1].as_str().map(str::to_string),
        auth[2].as_str().map(str::to_string),
        auth[3].as_str().map(str::to_string),
    )
    .unwrap();
    connect_gh(&ctx, port, auth);
    let capture = std::thread::spawn(move || capture_one_request(&listener));
    let headers: Headers = case["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            (
                h[0].as_str().unwrap().to_string(),
                h[1].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let result = gateway::relay_for_caller(
        &ctx,
        "agent-1",
        "gh",
        case["method"].as_str().unwrap(),
        case["target"].as_str().unwrap(),
        &headers,
        &b64(case["body_b64"].as_str().unwrap()),
        None,
    );
    assert_eq!(result.status, 200, "{}: {result:?}", case["name"]);
    let bytes = capture.join().expect("capture thread");
    String::from_utf8(bytes)
        .expect("ASCII request")
        .replace(&format!("127.0.0.1:{port}"), "127.0.0.1:PORT")
}

/// `DEVIATIONS.md` "HTTP request byte-identity": the exact bytes on the wire
/// for every header-order, method/body, auth-mode and header-collision
/// shape, Rust against what `zeropw.gateway.relay_for_caller` sent.
#[test]
fn request_bytes_match_the_python_fixture_across_shapes() {
    let fixture: Value = serde_json::from_str(REQUEST_BYTES).unwrap();
    assert_eq!(fixture["secret"], SECRET);
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 13);
    let mut mismatches = Vec::new();
    for case in cases {
        let expected = case["request"].as_str().unwrap();
        assert!(
            !expected.is_empty(),
            "{}: python sent nothing",
            case["name"]
        );
        let rust = rust_wire_bytes(case);
        if rust != expected {
            mismatches.push(format!(
                "{}:\n  rust:   {rust:?}\n  python: {expected:?}",
                case["name"]
            ));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

// ------------------------------------------------------ live FakeUpstream

#[test]
fn relay_reaches_a_live_fake_upstream_with_the_stored_credential() {
    let fake = FakeUpstream::new(SECRET).start();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", fake.port())).is_err()
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(20));
    }

    let tmp = TempDir::new().unwrap();
    let ctx = rust_ctx(&tmp);
    connect_gh(&ctx, fake.port(), HttpAuth::bearer());

    // The fake only accepts `Authorization: Bearer <exact SECRET>`; a 200
    // here (rather than its 401) proves the exact credential the vault
    // stored reached the upstream, not merely "some" bearer token.
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
    let recorded = fake.requests();
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        recorded[0].headers.get("authorization").map(String::as_str),
        Some(format!("Bearer {SECRET}").as_str())
    );
}
