//! Differential tests: what happens when CPython's `gateway.relay` /
//! `relay_for_caller` RAISE instead of returning a `RelayResult`
//! (`DEVIATIONS.md` gateway rows for `unexpected_error_result`, the chunked
//! `read_body` negative sizes, `upstream_timeout` and the ledger replay
//! status).
//!
//! Each case builds the same state in a fresh Rust `Context` and a fresh
//! Python `zeropw.context.Context`, both pointed at the same raw local
//! upstream, then compares
//!
//! * the call's outcome -- a returned result (status, reason, body), or the
//!   escaping exception (`type(exc).__name__`, and `exc.to_dict()` for a
//!   `ZeroPWError`);
//! * the request ledger document left behind (claim state, `in_flight`
//!   versus released versus `uncertain`); and
//! * the audit trail (event, result, reason),
//!
//! and, for the server cases, the raw bytes `zeropw.server.ZeroPWServer`
//! and `server::ZeroPWServer` send back (only the `Date` header removed).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

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

const PYTHON_HARNESS: &str = r#"
import json, socket, sys, tempfile
from pathlib import Path
from zeropw import gateway
from zeropw import policy as P
from zeropw.context import Config, Context
from zeropw.errors import ZeroPWError
from zeropw.server import ZeroPWServer

spec = json.load(sys.stdin)

def substitute(value, digest):
    if value == "$DIGEST":
        return digest
    if isinstance(value, list):
        return [substitute(v, digest) for v in value]
    if isinstance(value, dict):
        return {k: substitute(v, digest) for k, v in value.items()}
    return value

def exchange(address, request):
    host, port = address
    with socket.create_connection((host, port), timeout=20) as sock:
        sock.sendall(request)
        chunks = []
        while True:
            try:
                data = sock.recv(65536)
            except OSError:
                break
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks)

def without_date(raw):
    text = raw.decode("utf-8", "replace")
    return "".join(line for line in text.splitlines(keepends=True) if not line.startswith("Date: "))

out = []
for case in spec["cases"]:
    with tempfile.TemporaryDirectory() as tmp:
        ctx = Context.initialize(Path(tmp) / "state", spec["admin"], spec["recovery"],
                                 Config(upstream_timeout=float(case["timeout"])), lambda: spec["now"])
        ctx.projects.create("demo")
        ctx.vault.put_secret("tok", "api_key", spec["secret"].encode(), "demo", "dev")
        token = ctx.policy.create_principal("agent", "cli")
        ctx.policy.create_connection(P.Connection(
            id="svc", project="demo", environment="dev", service="svc", kind="http", secret_id="tok",
            secret_version=None, description="", http_target=P.HttpTarget("http", "127.0.0.1", case["port"], None),
            http_auth=P.HttpAuth("bearer"), http_scope=P.HttpScope(), ssh_target=None, cli=None,
            policy_version=0, status="active", created_at="", updated_at=""))
        grant = ctx.policy.create_grant("agent", "svc", 3600, None)
        handle = ctx.handles.issue("agent", "svc", grant.id, ctx.policy.get_connection("svc").policy_version,
                                   300, now=spec["now"])
        if case["ledger"] is not None:
            digest = gateway.RequestLedger.digest("svc", "GET", "/x", b"")
            ctx.state.write_json(gateway.LEDGER_DOC, substitute(case["ledger"], digest))
        if case["corrupt_connections"]:
            (Path(tmp) / "state" / "policy" / "connections.json").write_bytes(b"{")
        if case["mode"] == "direct":
            try:
                result = gateway.relay_for_caller(ctx, "agent", "svc", "GET", "/x", {}, b"", "rid-1")
                outcome = {"status": str(result.status), "reason": result.reason,
                           "body": result.body.decode("utf-8", "replace")}
            except Exception as exc:
                outcome = {"raises": type(exc).__name__,
                           "dict": exc.to_dict() if isinstance(exc, ZeroPWError) else None}
        else:
            server = ZeroPWServer(ctx).serve_in_thread()
            try:
                if case["mode"] == "tools":
                    body = b'{"connection": "svc", "method": "GET", "path": "/x", "request_id": "rid-1"}'
                    request = (f"POST /v1/tools/request HTTP/1.1\r\nHost: zeropw\r\nAuthorization: Bearer {token}\r\n"
                               f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
                               f"Connection: close\r\n\r\n").encode() + body
                else:
                    request = (f"GET /h/{handle}/x HTTP/1.1\r\nHost: zeropw\r\nX-ZeroPW-Request-Id: rid-1\r\n"
                               f"Connection: close\r\n\r\n").encode()
                outcome = {"raw": without_date(exchange(server.server_address[:2], request))}
            finally:
                server.stop()
        try:
            ledger = ctx.state.read_json(gateway.LEDGER_DOC, None)
        except Exception:
            ledger = "unreadable"
        audit = [[r.get("event"), r.get("result"), r.get("reason")] for r in ctx.audit.tail(100)]
        out.append({"outcome": outcome, "ledger": ledger, "audit": audit})
print(json.dumps(out))
"#;

fn python_cases(cases: &[(Case, u16)]) -> Vec<Value> {
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".into());
    let spec = json!({
        "admin": ADMIN,
        "recovery": RECOVERY,
        "secret": SECRET,
        "now": NOW,
        "cases": cases.iter().map(|(case, port)| json!({
            "mode": match case.mode {
                Mode::Direct => "direct",
                Mode::Tools => "tools",
                Mode::Handle => "handle",
            },
            "timeout": case.timeout,
            "port": port,
            "ledger": case.ledger,
            "corrupt_connections": case.corrupt_connections,
        })).collect::<Vec<_>>(),
    });
    let mut child = Command::new(interpreter)
        .arg("-c")
        .arg(PYTHON_HARNESS)
        .env("PYTHONPATH", repo_root())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run python");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(spec.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "python stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("python json")
}

/// Runs every case in both languages, asserts equality, and returns
/// Python's observations by case name for spot checks.
fn assert_cases_match_python(cases: Vec<Case>) -> std::collections::HashMap<&'static str, Value> {
    let upstreams: Vec<RawUpstream> = cases
        .iter()
        .map(|case| RawUpstream::start(case.response.clone()))
        .collect();
    let with_ports: Vec<(Case, u16)> = cases
        .iter()
        .cloned()
        .zip(upstreams.iter().map(|u| u.port))
        .collect();
    let python = python_cases(&with_ports);
    assert_eq!(python.len(), with_ports.len());
    let mut mismatches = Vec::new();
    let mut observed = std::collections::HashMap::new();
    for ((case, port), expected) in with_ports.iter().zip(python) {
        let actual = rust_case(case, *port);
        if actual != expected {
            mismatches.push(format!(
                "{}:\n  rust:   {actual}\n  python: {expected}",
                case.name
            ));
        }
        observed.insert(case.name, expected);
    }
    drop(upstreams);
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    observed
}

fn claim_state(observed: &Value) -> &Value {
    &observed["ledger"]["agent"]["rid-1"]["state"]
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
fn negative_chunk_sizes_match_python_outcome_ledger_and_audit() {
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
    let seen = assert_cases_match_python(cases);
    // The shapes the comparison above pins, spelled out.
    let overflow = &seen["chunk -2**63-1"];
    assert_eq!(overflow["outcome"]["raises"], "OverflowError");
    assert_eq!(claim_state(overflow), "in_flight");
    let lost = &seen["chunk -5"];
    assert_eq!(lost["outcome"]["reason"], "upstream_connection_lost");
    assert_eq!(claim_state(lost), "uncertain");
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
fn invalid_upstream_timeouts_match_python_outcome_ledger_and_audit() {
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
    let seen = assert_cases_match_python(cases);
    assert_eq!(seen["timeout inf"]["outcome"]["raises"], "OverflowError");
    assert_eq!(claim_state(&seen["timeout inf"]), "in_flight");
    assert_eq!(seen["timeout nan"]["outcome"]["raises"], "ValueError");
    assert_eq!(
        seen["timeout 0"]["outcome"]["reason"],
        "upstream_unreachable"
    );
    assert_eq!(seen["timeout 2147483.648"]["outcome"]["status"], "200");
    assert_eq!(
        raw_status_line(&seen["tools timeout nan"]),
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
fn ledger_shapes_match_python_outcome_ledger_and_audit() {
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
    let seen = assert_cases_match_python(cases);
    assert_eq!(
        seen["unrelated empty str caller"]["outcome"]["status"],
        "200"
    );
    assert_eq!(seen["own null entry"]["outcome"]["status"], "200");
    assert_eq!(
        seen["unrelated str caller"]["outcome"]["raises"],
        "TypeError"
    );
    assert_eq!(seen["replay status str"]["outcome"]["raises"], "ValueError");
    assert_eq!(
        seen["replay status huge"]["outcome"]["status"],
        "9".repeat(40).as_str()
    );
    assert!(
        raw_status_line(&seen["handle replay status huge"])
            .starts_with(&format!("HTTP/1.1 {} ", "9".repeat(40)))
    );
}

#[test]
fn zeropw_errors_escaping_relay_match_python_at_every_boundary() {
    let mut cases = Vec::new();
    let mut direct = Case::new("direct corrupt connections", Mode::Direct, OK_RESPONSE);
    direct.corrupt_connections = true;
    cases.push(direct);
    let mut handle = Case::new("handle corrupt connections", Mode::Handle, OK_RESPONSE);
    handle.corrupt_connections = true;
    cases.push(handle);
    let mut ledger = Case::new("direct non-dict ledger document", Mode::Direct, OK_RESPONSE);
    ledger.ledger = Some(json!("not a document"));
    cases.push(ledger);
    let seen = assert_cases_match_python(cases);
    assert_eq!(
        seen["direct corrupt connections"]["outcome"]["raises"],
        "StateError"
    );
    assert_eq!(
        raw_status_line(&seen["handle corrupt connections"]),
        "HTTP/1.1 503 Service Unavailable"
    );
}
