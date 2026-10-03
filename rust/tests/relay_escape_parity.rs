//! What happens when a relay cannot return an ordinary `RelayResult`: an
//! adversarial upstream (negative or malformed chunk sizes), an unusable
//! configured upstream timeout, a hand-edited request ledger, corrupt policy
//! state or an unsupported stored auth mode. Outside the persisted-state
//! and wire boundaries Rust only has to fail closed (`PORTING.md` §0): each
//! case runs in a fresh `Context` against a raw local upstream, and the
//! observation -- the call's outcome (a returned result, or the escaping
//! error), the request ledger left behind and the audit trail, or for the
//! server cases the raw reply bytes -- never carries the credential; the
//! cases that must refuse do refuse, and the server answers an escaped
//! error with its fixed reply.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{Value, json};
use tempfile::TempDir;
use zeropw::context::{Config, Context};
use zeropw::gateway::{self, RequestLedger};
use zeropw::policy::{Connection, HttpAuth, HttpScope, HttpTarget};
use zeropw::server::ZeroPWServer;

const ADMIN: &str = "admin-passphrase-1";
const RECOVERY: &str = "recovery-passphrase-1";
const SECRET: &str = "synthetic-escape-parity-token-0123456789";
const NOW: f64 = 1_700_000_000.0;
const DIGEST_PLACEHOLDER: &str = "$DIGEST";

/// A raw upstream: every connection gets `response` once the request head
/// has arrived, then the socket is closed.
struct RawUpstream {
    port: u16,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl RawUpstream {
    fn start(response: Vec<u8>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let mut head = Vec::new();
                        let mut byte = [0u8; 1];
                        while !head.ends_with(b"\r\n\r\n") {
                            match stream.read(&mut byte) {
                                Ok(1) => head.push(byte[0]),
                                _ => break,
                            }
                        }
                        let _ = stream.write_all(&response);
                        let _ = stream.flush();
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        RawUpstream {
            port,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for RawUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[derive(Clone)]
enum Mode {
    /// `relay_for_caller(ctx, "agent", "svc", "GET", "/x", {}, b"", "rid-1")`.
    Direct,
    /// `POST /v1/tools/request` through the server.
    Tools,
    /// `GET /h/<handle>/x` through the server.
    Handle,
}

#[derive(Clone)]
struct Case {
    name: &'static str,
    mode: Mode,
    timeout: &'static str,
    response: Vec<u8>,
    /// Ledger document written before the call (`$DIGEST` replaced by the
    /// request's real digest).
    ledger: Option<Value>,
    /// Overwrite `policy/connections.json` with invalid JSON after setup.
    corrupt_connections: bool,
    /// Hand-edit the stored connection's `http_auth.mode` after setup.
    auth_mode: Option<&'static str>,
}

impl Case {
    fn new(name: &'static str, mode: Mode, response: &[u8]) -> Self {
        Case {
            name,
            mode,
            timeout: "5.0",
            response: response.to_vec(),
            ledger: None,
            corrupt_connections: false,
            auth_mode: None,
        }
    }
}

fn substitute_digest(value: &Value, digest: &str) -> Value {
    match value {
        Value::String(s) if s == DIGEST_PLACEHOLDER => Value::String(digest.to_string()),
        Value::Array(items) => {
            Value::Array(items.iter().map(|v| substitute_digest(v, digest)).collect())
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), substitute_digest(v, digest)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn python_float(text: &str) -> f64 {
    match text {
        "inf" => f64::INFINITY,
        "-inf" => f64::NEG_INFINITY,
        "nan" => f64::NAN,
        other => other.parse().unwrap(),
    }
}

/// Drop the `Date:` header line (the only per-call value in the reply).
fn without_date(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw).into_owned();
    let mut out = String::new();
    for line in text.split_inclusive("\r\n") {
        if !line.starts_with("Date: ") {
            out.push_str(line);
        }
    }
    out
}

fn exchange(address: &str, request: &[u8]) -> Vec<u8> {
    let mut socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    socket.write_all(request).unwrap();
    let mut out = Vec::new();
    let _ = socket.read_to_end(&mut out);
    out
}

fn tools_request(token: &str) -> Vec<u8> {
    let body = r#"{"connection": "svc", "method": "GET", "path": "/x", "request_id": "rid-1"}"#;
    format!(
        "POST /v1/tools/request HTTP/1.1\r\nHost: zeropw\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn handle_request(handle: &str) -> Vec<u8> {
    format!(
        "GET /h/{handle}/x HTTP/1.1\r\nHost: zeropw\r\nX-ZeroPW-Request-Id: rid-1\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

fn audit_triples(records: &[Value]) -> Value {
    Value::Array(
        records
            .iter()
            .map(|r| json!([r["event"], r["result"], r["reason"]]))
            .collect(),
    )
}

fn rust_case(case: &Case, port: u16) -> Value {
    let tmp = TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            tmp.path().join("state"),
            ADMIN,
            RECOVERY,
            Config {
                upstream_timeout: python_float(case.timeout),
                ..Config::default()
            },
            zeropw::clock::fixed(NOW),
        )
        .unwrap(),
    );
    ctx.projects
        .create("demo", zeropw::projects::DEFAULT_ENVIRONMENTS)
        .unwrap();
    ctx.vault
        .put_secret("tok", "api_key", SECRET.as_bytes(), "demo", "dev", true)
        .unwrap();
    let token = ctx.policy.create_principal("agent", "cli").unwrap();
    ctx.policy
        .create_connection(
            Connection::new(
                "svc",
                "demo",
                "dev",
                "svc",
                "http",
                "tok",
                None,
                "",
                Some(HttpTarget::new("http", "127.0.0.1", i64::from(port), None, false).unwrap()),
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
    let grant = ctx
        .policy
        .create_grant("agent", "svc", Some(3600), None)
        .unwrap();
    let policy_version = ctx.policy.get_connection("svc").unwrap().policy_version;
    let handle = ctx
        .handles
        .issue("agent", "svc", &grant.id, policy_version, 300, Some(NOW))
        .unwrap();
    if let Some(ledger) = &case.ledger {
        let digest = RequestLedger::digest("svc", "GET", "/x", b"");
        ctx.state
            .write_json(gateway::LEDGER_DOC, &substitute_digest(ledger, &digest))
            .unwrap();
    }
    if case.corrupt_connections {
        std::fs::write(ctx.state.path.join("policy/connections.json"), b"{").unwrap();
    }
    if let Some(mode) = case.auth_mode {
        let mut doc = ctx
            .state
            .read_json("policy/connections.json", json!({}))
            .unwrap();
        doc["svc"]["http_auth"]["mode"] = json!(mode);
        ctx.state
            .write_json("policy/connections.json", &doc)
            .unwrap();
    }
    let outcome = match case.mode {
        Mode::Direct => {
            match gateway::try_relay_for_caller(
                &ctx,
                "agent",
                "svc",
                "GET",
                "/x",
                &Vec::new(),
                b"",
                Some("rid-1"),
            ) {
                Ok(result) => json!({
                    "status": result.status.to_string(),
                    "reason": result.reason,
                    "body": String::from_utf8_lossy(&result.body),
                }),
                Err(error) => json!({
                    "raises": error.name,
                    "dict": if gateway::is_escaped_builtin(&error) {
                        Value::Null
                    } else {
                        error.to_dict()
                    },
                }),
            }
        }
        Mode::Tools | Mode::Handle => {
            let server = ZeroPWServer::new(ctx.clone(), None, None).unwrap();
            server.serve_in_thread().unwrap();
            let address = server.url().trim_start_matches("http://").to_string();
            let request = match case.mode {
                Mode::Tools => tools_request(&token),
                _ => handle_request(&handle),
            };
            let raw = exchange(&address, &request);
            server.stop();
            json!({"raw": without_date(&raw)})
        }
    };
    let ledger = ctx
        .state
        .read_json(gateway::LEDGER_DOC, Value::Null)
        .unwrap_or(json!("unreadable"));
    let audit = audit_triples(&ctx.audit.tail(100).unwrap());
    json!({"outcome": outcome, "ledger": ledger, "audit": audit})
}

/// Runs every case and returns the observations by case name. No
/// observation may carry the credential, in any encoding the gateway itself
/// redacts.
fn observe(cases: Vec<Case>) -> std::collections::HashMap<&'static str, Value> {
    let patterns = gateway::credential_patterns(SECRET.as_bytes(), None);
    let mut observed = std::collections::HashMap::new();
    for case in cases {
        let upstream = RawUpstream::start(case.response.clone());
        let actual = rust_case(&case, upstream.port);
        drop(upstream);
        let text = actual.to_string();
        for pattern in &patterns {
            assert!(
                !text.contains(&*String::from_utf8_lossy(pattern)),
                "{}: credential in {text}",
                case.name
            );
        }
        eprintln!("{}: {actual}", case.name);
        observed.insert(case.name, actual);
    }
    observed
}

/// The call did not relay a success: a direct refusal result or escaping
/// error, a server error reply, or a tools reply carrying a refused relay.
fn refused(observed: &Value) -> bool {
    let Some(raw) = observed["outcome"]["raw"].as_str() else {
        return observed["outcome"]["status"] != "200";
    };
    if !raw.starts_with("HTTP/1.1 2") {
        return true;
    }
    let body = raw.split_once("\r\n\r\n").map_or("", |(_, body)| body);
    serde_json::from_str::<Value>(body).is_ok_and(|reply| reply["status"] != 200)
}

fn raw_status_line(observed: &Value) -> &str {
    observed["outcome"]["raw"]
        .as_str()
        .unwrap()
        .split("\r\n")
        .next()
        .unwrap()
}

fn chunked(size: &[u8]) -> Vec<u8> {
    let mut out = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    out.extend_from_slice(size);
    out.extend_from_slice(b"\r\nhello\r\n0\r\n\r\n");
    out
}

const OK_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok";

#[test]
fn negative_chunk_sizes_fail_closed() {
    let mut cases = Vec::new();
    for (name, size) in [
        ("chunk -1", b"-1".as_slice()),
        ("chunk -5", b"-5".as_slice()),
        ("chunk -a", b"-a".as_slice()),
        ("chunk -2**63", b"-8000000000000000".as_slice()),
        ("chunk -2**63-1", b"-8000000000000001".as_slice()),
        (
            "chunk huge negative",
            b"-99999999999999999999999999999999".as_slice(),
        ),
        ("chunk NBSP byte", b"\xa05".as_slice()),
        ("chunk NEL byte", b"5\x85".as_slice()),
    ] {
        cases.push(Case::new(name, Mode::Direct, &chunked(size)));
    }
    cases.push(Case::new(
        "tools chunk overflow",
        Mode::Tools,
        &chunked(b"-8000000000000001"),
    ));
    cases.push(Case::new(
        "handle chunk overflow",
        Mode::Handle,
        &chunked(b"-8000000000000001"),
    ));
    cases.push(Case::new("tools chunk -5", Mode::Tools, &chunked(b"-5")));
    let seen = observe(cases);
    // An adversarial chunk size never becomes a relayed success.
    for (name, observed) in &seen {
        assert!(refused(observed), "{name}: {observed}");
    }
    assert_eq!(
        seen["chunk -1"]["outcome"]["reason"],
        "upstream_protocol_error"
    );
    assert_eq!(
        seen["chunk NBSP byte"]["outcome"]["reason"],
        "upstream_protocol_error"
    );
    assert_eq!(
        raw_status_line(&seen["tools chunk overflow"]),
        "HTTP/1.1 500 Internal Server Error"
    );
    assert_eq!(
        raw_status_line(&seen["handle chunk overflow"]),
        "HTTP/1.1 500 Internal Server Error"
    );
}

#[test]
fn invalid_upstream_timeouts_fail_closed() {
    let mut cases = Vec::new();
    for (name, timeout) in [
        ("timeout inf", "inf"),
        ("timeout -inf", "-inf"),
        ("timeout nan", "nan"),
        ("timeout -1", "-1.0"),
        ("timeout 9.3e9", "9.3e9"),
        ("timeout 1e30", "1e30"),
        ("timeout 0", "0.0"),
        ("timeout -0", "-0.0"),
        ("timeout 2147483.648", "2147483.648"),
    ] {
        let mut case = Case::new(name, Mode::Direct, OK_RESPONSE);
        case.timeout = timeout;
        cases.push(case);
    }
    let mut tools = Case::new("tools timeout nan", Mode::Tools, OK_RESPONSE);
    tools.timeout = "nan";
    cases.push(tools);
    let mut handle = Case::new("handle timeout inf", Mode::Handle, OK_RESPONSE);
    handle.timeout = "inf";
    cases.push(handle);
    let seen = observe(cases);
    // An unusable timeout refuses before anything is relayed; the server
    // answers the escaped error with its fixed reply.
    for name in [
        "timeout inf",
        "timeout -inf",
        "timeout nan",
        "timeout -1",
        "timeout 9.3e9",
        "timeout 1e30",
        "timeout 0",
        "timeout -0",
    ] {
        assert!(refused(&seen[name]), "{name}: {}", seen[name]);
    }
    // A large but representable timeout is an ordinary relay.
    assert_eq!(seen["timeout 2147483.648"]["outcome"]["status"], "200");
    assert_eq!(
        raw_status_line(&seen["tools timeout nan"]),
        "HTTP/1.1 500 Internal Server Error"
    );
    assert_eq!(
        raw_status_line(&seen["handle timeout inf"]),
        "HTTP/1.1 500 Internal Server Error"
    );
}

fn completed_entry(status: Value) -> Value {
    json!({"agent": {"rid-1": {
        "digest": DIGEST_PLACEHOLDER, "state": "completed", "connection": "svc",
        "created_at": NOW, "updated_at": NOW,
        "response": {"status": status, "headers": [["Content-Type", "text/plain"]],
                     "reason": null, "body_b64": "b2s=", "body_stored": true},
    }}})
}

#[test]
fn hand_edited_ledger_shapes_never_leak_and_corrupt_claims_fail_closed() {
    let mut cases = Vec::new();
    let ledgers: Vec<(&'static str, Value)> = vec![
        ("unrelated empty str caller", json!({"other": ""})),
        ("unrelated empty list caller", json!({"other": []})),
        ("unrelated str caller", json!({"other": "oops"})),
        ("unrelated null caller", json!({"other": null})),
        ("unrelated number caller", json!({"other": 0})),
        ("own str caller", json!({"agent": "oops"})),
        ("own null caller", json!({"agent": null})),
        ("own null entry", json!({"agent": {"rid-1": null}})),
        ("own str entry", json!({"agent": {"rid-1": "oops"}})),
        ("unrelated str entry", json!({"agent": {"rid-0": "oops"}})),
        ("unrelated null entry", json!({"agent": {"rid-0": null}})),
        (
            "unparsable updated_at",
            json!({"agent": {"rid-0": {"updated_at": "soon", "state": "completed"}}}),
        ),
        (
            "underscored updated_at",
            json!({"agent": {"rid-0": {"updated_at": "1_700_000_000.5", "state": "completed"}}}),
        ),
        (
            "huge integer updated_at",
            json!({"agent": {"rid-0": {"updated_at": serde_json::Number::from_string_unchecked("1".repeat(400)), "state": "completed"}}}),
        ),
        ("replay status str", completed_entry(json!("abc"))),
        ("replay status null", completed_entry(Value::Null)),
        ("replay status huge", completed_entry(json!("9".repeat(40)))),
        (
            "replay non-mapping response",
            json!({"agent": {"rid-1": {
                "digest": DIGEST_PLACEHOLDER, "state": "completed", "updated_at": NOW,
                "response": "oops"}}}),
        ),
    ];
    for (name, ledger) in ledgers {
        let mut case = Case::new(name, Mode::Direct, OK_RESPONSE);
        case.ledger = Some(ledger);
        cases.push(case);
    }
    let mut tools = Case::new("tools replay status str", Mode::Tools, OK_RESPONSE);
    tools.ledger = Some(completed_entry(json!("abc")));
    cases.push(tools);
    let mut handle = Case::new("handle replay status huge", Mode::Handle, OK_RESPONSE);
    handle.ledger = Some(completed_entry(json!("9".repeat(40))));
    cases.push(handle);
    let seen = observe(cases);
    // A corrupt entry for this very request, or a stored response the
    // replay cannot read, never relays as a success.
    for name in [
        "own str entry",
        "replay status str",
        "replay status null",
        "replay non-mapping response",
    ] {
        assert!(refused(&seen[name]), "{name}: {}", seen[name]);
    }
    assert_eq!(
        raw_status_line(&seen["tools replay status str"]),
        "HTTP/1.1 500 Internal Server Error"
    );
}

#[test]
fn zeropw_errors_escaping_relay_fail_closed_at_every_boundary() {
    let mut cases = Vec::new();
    let mut direct = Case::new("direct corrupt connections", Mode::Direct, OK_RESPONSE);
    direct.corrupt_connections = true;
    cases.push(direct);
    let mut handle = Case::new("handle corrupt connections", Mode::Handle, OK_RESPONSE);
    handle.corrupt_connections = true;
    cases.push(handle);
    let mut tools = Case::new("tools corrupt connections", Mode::Tools, OK_RESPONSE);
    tools.corrupt_connections = true;
    cases.push(tools);
    for (name, mode) in [
        ("direct stored auth mode digest", Mode::Direct),
        ("handle stored auth mode digest", Mode::Handle),
        ("tools stored auth mode digest", Mode::Tools),
    ] {
        let mut case = Case::new(name, mode, OK_RESPONSE);
        case.auth_mode = Some("digest");
        cases.push(case);
    }
    let mut ledger = Case::new("direct non-dict ledger document", Mode::Direct, OK_RESPONSE);
    ledger.ledger = Some(json!("not a document"));
    cases.push(ledger);
    let seen = observe(cases);
    assert_eq!(
        seen["direct corrupt connections"]["outcome"]["raises"],
        "StateError"
    );
    assert_eq!(
        raw_status_line(&seen["handle corrupt connections"]),
        "HTTP/1.1 503 Service Unavailable"
    );
    assert_eq!(
        seen["direct stored auth mode digest"]["outcome"]["dict"],
        json!({"error": "InvalidInput", "reason": "unsupported_auth_mode"})
    );
    assert_eq!(
        raw_status_line(&seen["handle stored auth mode digest"]),
        "HTTP/1.1 400 Bad Request"
    );
    for name in ["tools corrupt connections", "tools stored auth mode digest"] {
        assert!(refused(&seen[name]), "{name}: {}", seen[name]);
    }
}
