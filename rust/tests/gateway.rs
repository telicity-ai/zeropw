//! Port of `tests/test_gateway.py`.
//!
//! `ServerRouteTests`, `SlowClientTests` and the `ZeroPWServer`-dependent
//! parts of `SelfReferenceTests` are ported against a live
//! `zeropw::server::ZeroPWServer` in the "server routes" section at the end
//! of this file (`server_*` tests). Where Python disables a check with
//! `mock.patch`, the port reaches the same situation without a mock: a name
//! resolved through the resolver seam for `_self_referential_target`, a
//! loopback TCP forwarder (the "another host, a proxy" case) for both address
//! checks, and a directory in the audit log's place for `append_line`
//! failing. `test_request_cut_at_the_deadline_is_never_acted_on` drives the
//! server's connection table directly and is the `server.rs` unit test of
//! the same name. The self-referential-target mechanism is also exercised
//! with a raw `TcpListener` in `self_reference` below.
//!
//! `TlsTests` used `openssl` via `subprocess` to generate test certificates;
//! this port uses `rcgen` (dev-dependency) instead, a test-infrastructure
//! substitute for the same reason the production TLS stack itself is
//! substituted (Python's `ssl`/OpenSSL -> `rustls` + `rustls-native-certs` +
//! `webpki`) -- see the "gateway (TLS stack)" row in `DEVIATIONS.md` for the
//! observable differences that substitution carries (finding F-19). There is
//! no `PORTING.md` instruction naming either substitution; a previous
//! version of this comment incorrectly claimed one.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use zeropw::context::{Config, Context};
use zeropw::fake_upstream::FakeUpstream;
use zeropw::gateway::{self, Headers, RelayResult};
use zeropw::policy::{self as P, Connection, ConnectionChanges, HttpAuth, HttpScope, HttpTarget};

// ------------------------------------------------------------------ helpers

const ADMIN: &str = "admin-passphrase-1";
const RECOVERY: &str = "recovery-passphrase-1";
const SECRET_A: &str = "synthetic-token-alpha-0123456789ABCDEFGHIJ";
const SECRET_B: &str = "synthetic-token-bravo-ZYXWVUTSRQPONMLKJIHG";
const SECRET_RESERVED: &str = "synthetic/token+reserved=chars:0123456789";
const SECRET_ENCODINGS: &str = "synthetic-token/enc+ode=chars:>>>?<&\"\\x-0123456789";
const PLACEHOLDER: &str = "Bearer democli-placeholder";

fn headers(pairs: &[(&str, &str)]) -> Headers {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn no_headers() -> Headers {
    Headers::new()
}

fn fake_clock(start: f64) -> (zeropw::clock::Clock, Arc<Mutex<f64>>) {
    let now = Arc::new(Mutex::new(start));
    let inner = now.clone();
    let clock: zeropw::clock::Clock = Arc::new(move || *inner.lock().unwrap());
    (clock, now)
}

fn http_connection(
    cid: &str,
    fake: &FakeUpstream,
    secret_id: &str,
    auth: HttpAuth,
    scope: HttpScope,
) -> Connection {
    http_connection_ca(cid, fake, secret_id, auth, scope, None)
}

fn http_connection_ca(
    cid: &str,
    fake: &FakeUpstream,
    secret_id: &str,
    auth: HttpAuth,
    scope: HttpScope,
    ca_file: Option<String>,
) -> Connection {
    Connection::new(
        cid,
        "demo",
        "dev",
        "fake-github",
        "http",
        secret_id,
        None,
        "test connection",
        Some(
            HttpTarget::new(
                fake.scheme(),
                fake.host(),
                fake.port() as i64,
                ca_file,
                false,
            )
            .unwrap(),
        ),
        Some(auth),
        Some(scope),
        None,
        None,
        0,
        "active",
        "",
        "",
    )
    .unwrap()
}

fn all_encodings(secret: &str) -> Vec<String> {
    gateway::credential_patterns(secret.as_bytes(), Some("synthetic-user"))
        .into_iter()
        .map(|p| String::from_utf8_lossy(&p).into_owned())
        .collect()
}

struct GatewayTest {
    _tmp: TempDir,
    ctx: Context,
    clock: Arc<Mutex<f64>>,
    fake: FakeUpstream,
    grant: P::Grant,
    handle: String,
}

impl GatewayTest {
    fn new() -> Self {
        let tmp = TempDir::new().expect("tempdir");
        let (clock, clock_state) = fake_clock(1_700_000_000.0);
        let config = Config {
            upstream_timeout: 3.0,
            ..Config::default()
        };
        let ctx = Context::initialize(tmp.path().join("state"), ADMIN, RECOVERY, config, clock)
            .expect("init ctx");
        ctx.projects
            .create("demo", zeropw::projects::DEFAULT_ENVIRONMENTS)
            .unwrap();
        let fake = FakeUpstream::new(SECRET_A).start();
        ctx.vault
            .put_secret(
                "gh-token",
                "api_key",
                SECRET_A.as_bytes(),
                "demo",
                "dev",
                true,
            )
            .unwrap();
        ctx.policy.create_principal("agent-1", "cli").unwrap();
        ctx.policy
            .create_connection(http_connection(
                "gh",
                &fake,
                "gh-token",
                HttpAuth::bearer(),
                HttpScope::new(None, None, vec!["DELETE".to_string()]).unwrap(),
            ))
            .unwrap();
        let grant = ctx
            .policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        let handle = issue_handle(
            &ctx,
            *clock_state.lock().unwrap(),
            "agent-1",
            "gh",
            &grant.id,
            None,
            300,
        );
        GatewayTest {
            _tmp: tmp,
            ctx,
            clock: clock_state,
            fake,
            grant,
            handle,
        }
    }

    fn now(&self) -> f64 {
        *self.clock.lock().unwrap()
    }

    fn advance(&self, seconds: f64) {
        *self.clock.lock().unwrap() += seconds;
    }

    fn issue_handle_for(
        &self,
        caller: &str,
        connection: &str,
        grant: &str,
        policy_version: Option<i64>,
        ttl: i64,
    ) -> String {
        issue_handle(
            &self.ctx,
            self.now(),
            caller,
            connection,
            grant,
            policy_version,
            ttl,
        )
    }

    fn relay(&self, method: &str, path: &str) -> RelayResult {
        self.relay_full(method, path, &no_headers(), b"", None, None)
    }

    fn relay_h(&self, method: &str, path: &str, hdrs: &Headers) -> RelayResult {
        self.relay_full(method, path, hdrs, b"", None, None)
    }

    fn relay_full(
        &self,
        method: &str,
        path: &str,
        hdrs: &Headers,
        body: &[u8],
        handle: Option<&str>,
        request_id: Option<&str>,
    ) -> RelayResult {
        let token = handle.unwrap_or(&self.handle);
        gateway::relay(&self.ctx, token, method, path, hdrs, body, request_id)
    }

    fn audit_records(&self) -> Vec<serde_json::Value> {
        self.ctx
            .audit
            .tail(10_000)
            .unwrap()
            .into_iter()
            .filter(|r| r["event"] == "http_relay")
            .collect()
    }

    fn state_text(&self, names: &[&str]) -> String {
        let mut chunks = Vec::new();
        for name in names {
            let path = self.ctx.state.path.join(name);
            if let Ok(text) = std::fs::read_to_string(&path) {
                chunks.push(text);
            }
        }
        chunks.join("\n")
    }

    fn assert_credential_free(&self, blob: &str, secrets: &[&str]) {
        for secret in secrets {
            for encoding in all_encodings(secret) {
                assert!(
                    !blob.contains(&encoding),
                    "leaked encoding of {secret}: {encoding}"
                );
            }
        }
    }

    fn assert_result_credential_free(&self, result: &RelayResult) {
        let body = String::from_utf8_lossy(&result.body);
        self.assert_credential_free(&body, &[SECRET_A, SECRET_B]);
        let headers_json = serde_json::to_string(&result.headers).unwrap();
        self.assert_credential_free(&headers_json, &[SECRET_A, SECRET_B]);
        self.assert_credential_free(
            result.reason.as_deref().unwrap_or(""),
            &[SECRET_A, SECRET_B],
        );
    }
}

fn issue_handle(
    ctx: &Context,
    now: f64,
    caller: &str,
    connection: &str,
    grant: &str,
    policy_version: Option<i64>,
    ttl: i64,
) -> String {
    let pv = policy_version.unwrap_or_else(|| {
        ctx.policy
            .get_connection(connection)
            .unwrap()
            .policy_version
            .to_i64()
            .unwrap()
    });
    ctx.handles
        .issue(caller, connection, grant, pv, ttl, Some(now))
        .unwrap()
}

fn header_names(result: &RelayResult) -> std::collections::HashSet<String> {
    result
        .headers
        .iter()
        .map(|(k, _)| k.to_lowercase())
        .collect()
}

// ---------------------------------------------------------------- normal flow

#[test]
fn one_connection_two_operations_placeholder_replaced() {
    let t = GatewayTest::new();
    let client_headers = headers(&[
        ("Authorization", PLACEHOLDER),
        ("Cookie", "session=agent-cookie"),
        ("Host", "evil.invalid"),
        ("X-ZeroPW-Handle", "stale"),
        ("Proxy-Authorization", "Basic xx"),
        ("Accept", "application/json"),
        ("User-Agent", "democli/1"),
        ("Accept-Encoding", "gzip"),
        ("Connection", "keep-alive"),
        ("Transfer-Encoding", "identity"),
    ]);
    let first = t.relay_h("GET", "/repos", &client_headers);
    assert_eq!(
        (first.status.clone(), first.reason.clone()),
        (200.into(), None)
    );
    assert_eq!(
        first.json().expect("test body is valid utf-8 JSON"),
        serde_json::json!([{"name": "demo"}, {"name": "tools"}])
    );

    let mut second_headers = client_headers.clone();
    second_headers.push(("Content-Type".to_string(), "application/json".to_string()));
    let body = serde_json::to_vec(&serde_json::json!({"title": "from agent"})).unwrap();
    let second = t.relay_full(
        "POST",
        "/repos/demo/issues",
        &second_headers,
        &body,
        None,
        None,
    );
    assert_eq!(
        (second.status.clone(), second.reason.clone()),
        (201.into(), None)
    );
    assert_eq!(
        second.json().expect("test body is valid utf-8 JSON")["title"],
        "from agent"
    );

    let seen = t.fake.requests();
    assert_eq!(seen.len(), 2);
    for req in &seen {
        assert_eq!(
            req.headers.get("authorization").unwrap(),
            &format!("Bearer {SECRET_A}")
        );
        assert!(
            !serde_json::to_string(&req.headers)
                .unwrap()
                .contains("democli-placeholder")
        );
        assert!(!req.headers.contains_key("cookie"));
        assert!(!req.headers.contains_key("proxy-authorization"));
        assert!(!req.headers.contains_key("x-zeropw-handle"));
        assert!(!req.headers.contains_key("transfer-encoding"));
        assert_eq!(
            req.headers.get("host").unwrap(),
            &format!("127.0.0.1:{}", t.fake.port())
        );
        assert_eq!(req.headers.get("accept").unwrap(), "application/json");
        assert_eq!(req.headers.get("user-agent").unwrap(), "democli/1");
        assert_eq!(req.headers.get("accept-encoding").unwrap(), "identity");
        assert_eq!(req.headers.get("connection").unwrap(), "close");
    }
    assert_eq!(seen[1].body, body);
    assert_eq!(
        seen[1].headers.get("content-type").unwrap(),
        "application/json"
    );

    let results: Vec<(String, Option<i64>)> = t
        .audit_records()
        .iter()
        .map(|r| {
            (
                r["result"].as_str().unwrap().to_string(),
                r["status"].as_i64(),
            )
        })
        .collect();
    assert_eq!(
        results,
        vec![
            ("attempt".to_string(), None),
            ("ok".to_string(), Some(200)),
            ("attempt".to_string(), None),
            ("ok".to_string(), Some(201)),
        ]
    );
    let record = t.audit_records().last().unwrap().clone();
    assert_eq!(record["caller"], "agent-1");
    assert_eq!(record["connection"], "gh");
    assert_eq!(record["action"], "POST");
    assert_eq!(record["path"], "/repos/demo/issues");
    assert_eq!(
        record["target"],
        format!("http://127.0.0.1:{}", t.fake.port())
    );
    assert_eq!(record["policy_version"], 1);
    assert_eq!(record["grant"], t.grant.id);
    assert_eq!(t.ctx.policy.get_grant(&t.grant.id).unwrap().uses, 2);
}

#[test]
fn basic_mode() {
    let t = GatewayTest::new();
    let fake = FakeUpstream::new(SECRET_B)
        .mode_basic("synthetic-user")
        .start();
    t.ctx
        .vault
        .put_secret(
            "basic-pw",
            "password",
            SECRET_B.as_bytes(),
            "demo",
            "dev",
            true,
        )
        .unwrap();
    t.ctx
        .policy
        .create_connection(http_connection(
            "basic",
            &fake,
            "basic-pw",
            HttpAuth::new("basic", None, None, Some("synthetic-user".to_string())).unwrap(),
            HttpScope::new(None, None, vec![]).unwrap(),
        ))
        .unwrap();
    let grant = t
        .ctx
        .policy
        .create_grant("agent-1", "basic", Some(3600), None)
        .unwrap();
    let handle = t.issue_handle_for("agent-1", "basic", &grant.id, None, 300);
    let result = t.relay_full(
        "GET",
        "/me",
        &headers(&[("Authorization", PLACEHOLDER)]),
        b"",
        Some(&handle),
        None,
    );
    assert_eq!(result.status, 200);
    assert_eq!(
        result.json().expect("test body is valid utf-8 JSON"),
        serde_json::json!({"login": "synthetic-user"})
    );
    use base64::Engine as _;
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("synthetic-user:{SECRET_B}"))
    );
    assert_eq!(
        fake.requests()
            .last()
            .unwrap()
            .headers
            .get("authorization")
            .unwrap(),
        &expected
    );
    let echoed = t.relay_full(
        "GET",
        "/echo-headers",
        &no_headers(),
        b"",
        Some(&handle),
        None,
    );
    assert_eq!(
        (echoed.status.clone(), echoed.reason.as_deref()),
        (502.into(), Some("credential_reflection_blocked"))
    );
    assert!(!String::from_utf8_lossy(&echoed.body).contains(expected.split(' ').nth(1).unwrap()));
}

#[test]
fn header_mode() {
    let t = GatewayTest::new();
    let fake = FakeUpstream::new(SECRET_B)
        .mode_header("X-Api-Key", "Key ")
        .start();
    t.ctx
        .vault
        .put_secret(
            "api-key",
            "api_key",
            SECRET_B.as_bytes(),
            "demo",
            "dev",
            true,
        )
        .unwrap();
    t.ctx
        .policy
        .create_connection(http_connection(
            "keyed",
            &fake,
            "api-key",
            HttpAuth::new(
                "header",
                Some("X-Api-Key".to_string()),
                Some("Key ".to_string()),
                None,
            )
            .unwrap(),
            HttpScope::new(None, None, vec![]).unwrap(),
        ))
        .unwrap();
    let grant = t
        .ctx
        .policy
        .create_grant("agent-1", "keyed", Some(3600), None)
        .unwrap();
    let handle = t.issue_handle_for("agent-1", "keyed", &grant.id, None, 300);
    let result = t.relay_full(
        "GET",
        "/repos",
        &headers(&[("X-Api-Key", "agent-guess"), ("Authorization", PLACEHOLDER)]),
        b"",
        Some(&handle),
        None,
    );
    assert_eq!(result.status, 200);
    let seen = fake.requests();
    let seen = seen.last().unwrap();
    assert_eq!(
        seen.headers.get("x-api-key").unwrap(),
        &format!("Key {SECRET_B}")
    );
    assert!(!seen.headers.contains_key("authorization"));
}

#[test]
fn relay_for_caller_without_handle() {
    let t = GatewayTest::new();
    let result = gateway::relay_for_caller(
        &t.ctx,
        "agent-1",
        "gh",
        "GET",
        "/me",
        &headers(&[("Authorization", PLACEHOLDER)]),
        b"",
        None,
    );
    assert_eq!(result.status, 200);
    assert_eq!(
        result.json().expect("test body is valid utf-8 JSON"),
        serde_json::json!({"login": "synthetic-user"})
    );
    assert_eq!(
        t.fake
            .requests()
            .last()
            .unwrap()
            .headers
            .get("authorization")
            .unwrap(),
        &format!("Bearer {SECRET_A}")
    );
    let denied = gateway::relay_for_caller(
        &t.ctx,
        "agent-1",
        "missing",
        "GET",
        "/me",
        &no_headers(),
        b"",
        None,
    );
    assert_eq!(
        (denied.status.clone(), denied.reason.as_deref()),
        (403.into(), Some("connection_unknown"))
    );
    let ghost = gateway::relay_for_caller(
        &t.ctx,
        "ghost",
        "gh",
        "GET",
        "/me",
        &no_headers(),
        b"",
        None,
    );
    assert_eq!(
        (ghost.status.clone(), ghost.reason.as_deref()),
        (403.into(), Some("principal_unknown"))
    );
    assert_eq!(t.fake.requests().len(), 1);
}

#[test]
fn query_forwarded_untouched_but_never_audited() {
    let t = GatewayTest::new();
    let result = t.relay("GET", "/repos?page=2&token=agent-guess");
    assert_eq!(result.status, 200);
    assert_eq!(
        t.fake.requests().last().unwrap().path,
        "/repos?page=2&token=agent-guess"
    );
    for record in t.audit_records() {
        assert!(!record["path"].as_str().unwrap_or("").contains('?'));
        assert!(!record.to_string().contains("agent-guess"));
    }
    assert!(!t.state_text(&["audit/audit.jsonl"]).contains("agent-guess"));
}

#[test]
fn head_and_no_content_responses() {
    let t = GatewayTest::new();
    let head = t.relay("HEAD", "/repos");
    assert_eq!(
        (head.status.clone(), head.body.clone(), head.reason.clone()),
        (200.into(), Vec::new(), None)
    );
    let digest = t
        .relay("DELETE", "/repos/demo")
        .json()
        .expect("test body is valid utf-8 JSON")["approval_digest"]
        .as_str()
        .unwrap()
        .to_string();
    t.ctx.policy.approve(&digest).unwrap();
    let gone = t.relay("DELETE", "/repos/demo");
    assert_eq!(
        (gone.status.clone(), gone.body.clone(), gone.reason.clone()),
        (204.into(), Vec::new(), None)
    );
}

#[test]
fn response_header_filter_and_upstream_401() {
    let t = GatewayTest::new();
    let ok = t.relay("GET", "/repos");
    let names = header_names(&ok);
    assert!(names.contains("content-type"));
    for dropped in [
        "server",
        "date",
        "connection",
        "content-length",
        "transfer-encoding",
    ] {
        assert!(!names.contains(dropped), "unexpected header {dropped}");
    }
    t.ctx
        .vault
        .put_secret(
            "wrong-token",
            "api_key",
            b"synthetic-token-not-accepted-upstream",
            "demo",
            "dev",
            true,
        )
        .unwrap();
    t.ctx
        .policy
        .create_connection(http_connection(
            "bad",
            &t.fake,
            "wrong-token",
            HttpAuth::bearer(),
            HttpScope::new(None, None, vec![]).unwrap(),
        ))
        .unwrap();
    let grant = t
        .ctx
        .policy
        .create_grant("agent-1", "bad", Some(3600), None)
        .unwrap();
    let handle = t.issue_handle_for("agent-1", "bad", &grant.id, None, 300);
    let result = t.relay_full("GET", "/repos", &no_headers(), b"", Some(&handle), None);
    assert_eq!(
        (result.status.clone(), result.reason.clone()),
        (401.into(), None)
    );
    assert!(!header_names(&result).contains("www-authenticate"));
    assert_eq!(
        result.json().expect("test body is valid utf-8 JSON"),
        serde_json::json!({"error": "unauthorized"})
    );
}

#[test]
fn usage_consumed_only_after_policy_pass() {
    let t = GatewayTest::new();
    let limited = t
        .ctx
        .policy
        .create_grant("agent-1", "gh", Some(3600), Some(1))
        .unwrap();
    let handle = t.issue_handle_for("agent-1", "gh", &limited.id, None, 300);
    assert_eq!(
        t.relay_full(
            "GET",
            "/repos/../x",
            &no_headers(),
            b"",
            Some(&handle),
            None
        )
        .status,
        400
    );
    assert_eq!(
        t.relay_full(
            "DELETE",
            "/repos/demo",
            &no_headers(),
            b"",
            Some(&handle),
            None
        )
        .status,
        428
    );
    assert_eq!(t.ctx.policy.get_grant(&limited.id).unwrap().uses, 0);
    assert_eq!(t.fake.requests().len(), 0);
    assert_eq!(
        t.relay_full("GET", "/repos", &no_headers(), b"", Some(&handle), None)
            .status,
        200
    );
    assert_eq!(t.ctx.policy.get_grant(&limited.id).unwrap().uses, 1);
    let exhausted = t.relay_full("GET", "/repos", &no_headers(), b"", Some(&handle), None);
    assert_eq!(
        (exhausted.status.clone(), exhausted.reason.as_deref()),
        (403.into(), Some("grant_exhausted"))
    );
    assert_eq!(t.fake.requests().len(), 1);
}

#[test]
fn invalid_inputs_are_explicit() {
    let t = GatewayTest::new();
    assert_eq!(
        t.relay("GE T", "/repos").reason.as_deref(),
        Some("invalid_method")
    );
    assert_eq!(
        t.relay("TRACE", "/repos").reason.as_deref(),
        Some("method_not_allowed")
    );
    assert_eq!(
        t.relay_h("GET", "/repos", &headers(&[("Accept", "a\r\nInjected: 1")]))
            .reason
            .as_deref(),
        Some("invalid_header_value")
    );
    assert_eq!(
        t.relay_full(
            "GET",
            "/repos",
            &no_headers(),
            b"",
            None,
            Some("x".repeat(200).as_str())
        )
        .reason
        .as_deref(),
        Some("invalid_request_id")
    );
    assert_eq!(
        t.relay_full("GET", "/repos", &no_headers(), b"", None, Some("bad id"))
            .reason
            .as_deref(),
        Some("invalid_request_id")
    );
    assert_eq!(t.fake.requests().len(), 0);
}

// -------------------------------------------------------------- target & path

#[test]
fn path_traversal_and_smuggling_rejected() {
    let t = GatewayTest::new();
    let bad = [
        "repos",
        "",
        "/repos/../admin",
        "/../",
        "/repos/..",
        "/repos//x",
        "//evil.invalid/x",
        "/repos/%2e%2e/admin",
        "/repos/%2E%2E/admin",
        "/repos%2f..%2fadmin",
        "/repos/%2f%2f",
        "/repos/%252e%252e/x",
        "/re\x00pos",
        "/re pos",
        "/repos\r\nX: 1",
        "/http://evil.invalid/",
        "/repos/./x",
        "/repos/%2e/x",
        "/repos\\x",
        "/repos#frag",
        "/re\u{e9}pos",
    ];
    for path in bad {
        let result = t.relay("GET", path);
        assert_eq!(
            (result.status.clone(), result.reason.as_deref()),
            (400.into(), Some("invalid_path")),
            "path={path}"
        );
    }
    let long_path = format!("/{}", "a".repeat(9000));
    let result = t.relay("GET", &long_path);
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (400.into(), Some("invalid_path"))
    );
    assert_eq!(t.fake.requests().len(), 0);
    for record in t.audit_records() {
        assert_eq!(record["result"], "denied");
        assert!(!record.to_string().contains('\u{0}'));
    }
    let good = [
        "/",
        "/repos/",
        "/repos/demo%20x/issues",
        "/repos?q=a//b://c",
        "/repos/a%2fb",
    ];
    for path in good {
        let result = t.relay("GET", path);
        assert_ne!(
            result.reason.as_deref(),
            Some("invalid_path"),
            "path={path}"
        );
    }
    assert!(gateway::normalize_path("/a/../b").is_err());
    assert_eq!(
        gateway::normalize_path("/a/b?c=1").unwrap(),
        ("/a/b".to_string(), "/a/b?c=1".to_string())
    );
}

#[test]
fn scope_method_and_path_denied_with_reason() {
    let t = GatewayTest::new();
    t.ctx
        .policy
        .create_connection(http_connection(
            "scoped",
            &t.fake,
            "gh-token",
            HttpAuth::bearer(),
            HttpScope::new(
                Some(vec!["GET".to_string(), "POST".to_string()]),
                Some(vec!["/repos".to_string(), "/me".to_string()]),
                vec![],
            )
            .unwrap(),
        ))
        .unwrap();
    let grant = t
        .ctx
        .policy
        .create_grant("agent-1", "scoped", Some(3600), None)
        .unwrap();
    let handle = t.issue_handle_for("agent-1", "scoped", &grant.id, None, 300);
    assert_eq!(
        t.relay_full("GET", "/repos", &no_headers(), b"", Some(&handle), None)
            .status,
        200
    );
    assert_eq!(
        t.relay_full(
            "GET",
            "/repos/x/y?z=1",
            &no_headers(),
            b"",
            Some(&handle),
            None
        )
        .status,
        404
    );
    let cases = [
        ("PUT", "/repos", "method_not_allowed"),
        ("DELETE", "/repos/demo", "method_not_allowed"),
        ("GET", "/debug/token", "path_not_allowed"),
        ("GET", "/reposx", "path_not_allowed"),
        ("GET", "/repos%2fx", "path_not_allowed"),
        ("GET", "/m%65", "path_not_allowed"),
    ];
    for (method, path, reason) in cases {
        let result = t.relay_full(method, path, &no_headers(), b"", Some(&handle), None);
        assert_eq!(
            (result.status.clone(), result.reason.as_deref()),
            (403.into(), Some(reason)),
            "{method} {path}"
        );
        assert_eq!(
            result.json().expect("test body is valid utf-8 JSON")["reason"],
            reason
        );
    }
    assert_eq!(t.fake.requests().len(), 2);
    assert_eq!(
        t.audit_records().last().unwrap()["reason"],
        "path_not_allowed"
    );
}

// ------------------------------------------------------- connection substitution

#[test]
fn handle_is_bound_to_its_connection_caller_and_grant() {
    let t = GatewayTest::new();
    let fake_b = FakeUpstream::new(SECRET_B).start();
    t.ctx
        .vault
        .put_secret(
            "b-token",
            "api_key",
            SECRET_B.as_bytes(),
            "demo",
            "dev",
            true,
        )
        .unwrap();
    t.ctx
        .policy
        .create_connection(http_connection(
            "gh-b",
            &fake_b,
            "b-token",
            HttpAuth::bearer(),
            HttpScope::new(None, None, vec![]).unwrap(),
        ))
        .unwrap();
    t.ctx.policy.create_principal("agent-2", "cli").unwrap();
    let grant_b = t
        .ctx
        .policy
        .create_grant("agent-2", "gh-b", Some(3600), None)
        .unwrap();

    assert_eq!(t.relay("GET", "/me").status, 200);
    let handle_b = t.issue_handle_for("agent-2", "gh-b", &grant_b.id, None, 300);
    assert_eq!(
        t.relay_full("GET", "/me", &no_headers(), b"", Some(&handle_b), None)
            .status,
        200
    );
    assert_eq!(
        t.fake
            .requests()
            .last()
            .unwrap()
            .headers
            .get("authorization")
            .unwrap(),
        &format!("Bearer {SECRET_A}")
    );
    assert_eq!(
        fake_b
            .requests()
            .last()
            .unwrap()
            .headers
            .get("authorization")
            .unwrap(),
        &format!("Bearer {SECRET_B}")
    );
    let before = (t.fake.requests().len(), fake_b.requests().len());

    let cross = [
        (
            t.issue_handle_for("agent-1", "gh-b", &t.grant.id, None, 300),
            "grant_mismatch",
        ),
        (
            t.issue_handle_for("agent-1", "gh-b", &grant_b.id, None, 300),
            "grant_mismatch",
        ),
        (
            t.issue_handle_for("agent-2", "gh", &grant_b.id, None, 300),
            "grant_mismatch",
        ),
        (
            t.issue_handle_for("agent-2", "gh", &t.grant.id, None, 300),
            "grant_mismatch",
        ),
        (
            t.issue_handle_for("agent-1", "gh", "g-unknown", None, 300),
            "grant_unknown",
        ),
    ];
    for (handle, reason) in cross {
        let result = t.relay_full("GET", "/me", &no_headers(), b"", Some(&handle), None);
        assert_eq!(
            (result.status.clone(), result.reason.as_deref()),
            (403.into(), Some(reason))
        );
    }
    let result = gateway::relay_for_caller(
        &t.ctx,
        "agent-1",
        "gh-b",
        "GET",
        "/me",
        &no_headers(),
        b"",
        None,
    );
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (403.into(), Some("no_grant"))
    );
    assert_eq!((t.fake.requests().len(), fake_b.requests().len()), before);
}

#[test]
fn tampered_or_foreign_handles_are_unauthorized() {
    let t = GatewayTest::new();
    let parts: Vec<&str> = t.handle.split('.').collect();
    let (head, payload, sig) = (parts[0], parts[1], parts[2]);
    let forged = if let Some(stripped) = payload.strip_suffix("AA") {
        format!("{stripped}BB")
    } else {
        format!("{}AA", &payload[..payload.len() - 2])
    };
    let cases = [
        (format!("{head}.{forged}.{sig}"), "handle_signature"),
        (
            format!("{head}.{payload}.{}x", &sig[..sig.len() - 1]),
            "handle_signature",
        ),
        ("".to_string(), "handle_malformed"),
        ("zpw1.abc".to_string(), "handle_malformed"),
        (format!("Bearer {SECRET_A}"), "handle_malformed"),
    ];
    for (token, reason) in cases {
        let result = t.relay_full("GET", "/me", &no_headers(), b"", Some(&token), None);
        assert_eq!(
            (result.status.clone(), result.reason.as_deref()),
            (401.into(), Some(reason))
        );
        assert_eq!(
            result.json().expect("test body is valid utf-8 JSON")["error"],
            "AuthFailed"
        );
    }
    use zeropw::handles::HandleIssuer;
    let foreign_key = HandleIssuer::generate_key();
    let foreign_issuer = HandleIssuer::new(foreign_key.expose()).unwrap();
    let foreign = foreign_issuer
        .issue("agent-1", "gh", &t.grant.id, 1, 300, Some(t.now()))
        .unwrap();
    assert_eq!(
        t.relay_full("GET", "/me", &no_headers(), b"", Some(&foreign), None)
            .reason
            .as_deref(),
        Some("handle_signature")
    );
    let short = t.issue_handle_for("agent-1", "gh", &t.grant.id, None, 60);
    t.advance(60.0);
    let expired = t.relay_full("GET", "/me", &no_headers(), b"", Some(&short), None);
    assert_eq!(
        (expired.status.clone(), expired.reason.as_deref()),
        (401.into(), Some("handle_expired"))
    );
    assert_eq!(t.fake.requests().len(), 0);
    let denied: Vec<_> = t
        .audit_records()
        .into_iter()
        .filter(|r| r["result"] == "denied")
        .collect();
    assert!(!denied.is_empty());
    assert!(denied.iter().all(|r| r["caller"].is_null()));
}

// ------------------------------------------------------------- policy state

fn assert_denied(t: &GatewayTest, reason: &str, handle: Option<&str>) {
    let before = t.fake.requests().len();
    let result = t.relay_full("GET", "/repos", &no_headers(), b"", handle, None);
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (403.into(), Some(reason))
    );
    assert_eq!(
        result.json().expect("test body is valid utf-8 JSON"),
        serde_json::json!({"error": "PolicyDenied", "reason": reason})
    );
    assert_eq!(t.fake.requests().len(), before);
    assert_eq!(t.audit_records().last().unwrap()["reason"], reason);
    assert_eq!(t.audit_records().last().unwrap()["result"], "denied");
}

#[test]
fn revoked() {
    let t = GatewayTest::new();
    assert_eq!(t.relay("GET", "/repos").status, 200);
    t.ctx.policy.revoke_grant(&t.grant.id).unwrap();
    assert_denied(&t, "grant_revoked", None);
    let alerts = t.ctx.audit.alerts(1000).unwrap();
    assert!(alerts.iter().any(|a| a["alert"] == "revoked_use_attempt"));
}

#[test]
fn expired() {
    let t = GatewayTest::new();
    let grant = t
        .ctx
        .policy
        .create_grant("agent-1", "gh", Some(100), None)
        .unwrap();
    let handle = t.issue_handle_for("agent-1", "gh", &grant.id, None, 3600);
    assert_eq!(
        t.relay_full("GET", "/repos", &no_headers(), b"", Some(&handle), None)
            .status,
        200
    );
    t.advance(100.0);
    assert_denied(&t, "grant_expired", Some(&handle));
}

#[test]
fn max_uses() {
    let t = GatewayTest::new();
    let grant = t
        .ctx
        .policy
        .create_grant("agent-1", "gh", Some(3600), Some(2))
        .unwrap();
    let handle = t.issue_handle_for("agent-1", "gh", &grant.id, None, 300);
    assert_eq!(
        t.relay_full("GET", "/repos", &no_headers(), b"", Some(&handle), None)
            .status,
        200
    );
    assert_eq!(
        t.relay_full("GET", "/me", &no_headers(), b"", Some(&handle), None)
            .status,
        200
    );
    assert_denied(&t, "grant_exhausted", Some(&handle));
}

#[test]
fn global_stop_and_resume() {
    let t = GatewayTest::new();
    t.ctx.policy.stop_all().unwrap();
    assert_denied(&t, "global_stop", None);
    assert_eq!(
        gateway::relay_for_caller(
            &t.ctx,
            "agent-1",
            "gh",
            "GET",
            "/me",
            &no_headers(),
            b"",
            None
        )
        .reason
        .as_deref(),
        Some("global_stop")
    );
    t.ctx.policy.resume().unwrap();
    assert_eq!(t.relay("GET", "/repos").status, 200);
}

#[test]
fn restore_pending() {
    let t = GatewayTest::new();
    t.ctx.policy.set_restore_pending(true).unwrap();
    assert_denied(&t, "restore_pending", None);
    t.ctx.policy.set_restore_pending(false).unwrap();
    assert_eq!(t.relay("GET", "/repos").status, 200);
}

#[test]
fn stale_policy_version_on_handle_after_narrowing_change() {
    let t = GatewayTest::new();
    t.ctx
        .policy
        .update_connection("gh", ConnectionChanges::new().description("renamed"))
        .unwrap();
    assert_eq!(
        t.ctx.policy.get_grant(&t.grant.id).unwrap().status,
        "active"
    );
    assert_denied(&t, "grant_stale", None);
    let fresh = t.issue_handle_for("agent-1", "gh", &t.grant.id, None, 300);
    assert_eq!(
        t.relay_full("GET", "/repos", &no_headers(), b"", Some(&fresh), None)
            .status,
        200
    );
    assert_eq!(
        gateway::relay_for_caller(
            &t.ctx,
            "agent-1",
            "gh",
            "GET",
            "/me",
            &no_headers(),
            b"",
            None
        )
        .status,
        200
    );
}

#[test]
fn widening_change_makes_grant_stale_until_regrant() {
    let t = GatewayTest::new();
    t.ctx
        .policy
        .create_connection(http_connection(
            "scoped",
            &t.fake,
            "gh-token",
            HttpAuth::bearer(),
            HttpScope::new(
                Some(vec!["GET".to_string()]),
                Some(vec!["/repos".to_string()]),
                vec![],
            )
            .unwrap(),
        ))
        .unwrap();
    let grant = t
        .ctx
        .policy
        .create_grant("agent-1", "scoped", Some(3600), None)
        .unwrap();
    let handle = t.issue_handle_for("agent-1", "scoped", &grant.id, None, 300);
    assert_eq!(
        t.relay_full("GET", "/repos", &no_headers(), b"", Some(&handle), None)
            .status,
        200
    );
    let (_, widened) = t
        .ctx
        .policy
        .update_connection(
            "scoped",
            ConnectionChanges::new().http_scope(Some(
                HttpScope::new(
                    Some(vec!["GET".to_string()]),
                    Some(vec!["/repos".to_string(), "/me".to_string()]),
                    vec![],
                )
                .unwrap(),
            )),
        )
        .unwrap();
    assert!(widened);
    let result = t.relay_full("GET", "/repos", &no_headers(), b"", Some(&handle), None);
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (403.into(), Some("grant_stale"))
    );
    let denied = gateway::relay_for_caller(
        &t.ctx,
        "agent-1",
        "scoped",
        "GET",
        "/me",
        &no_headers(),
        b"",
        None,
    );
    assert_eq!(denied.reason.as_deref(), Some("grant_stale"));
    let fresh = t.ctx.policy.regrant(&grant.id).unwrap();
    let fresh_handle = t.issue_handle_for("agent-1", "scoped", &fresh.id, None, 300);
    let result = t.relay_full("GET", "/me", &no_headers(), b"", Some(&fresh_handle), None);
    assert_eq!(result.status, 200);
}

#[test]
fn principal_and_connection_disabled() {
    let t = GatewayTest::new();
    t.ctx.policy.disable_connection("gh").unwrap();
    assert_denied(&t, "connection_disabled", None);
    t.ctx.policy.disable_principal("agent-1", false).unwrap();
    assert_denied(&t, "principal_disabled", None);
}

// ------------------------------------------------------ reflection & upstream

fn assert_blocked(t: &GatewayTest, path: &str, reason: &str) -> RelayResult {
    let result = t.relay("GET", path);
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (502.into(), Some(reason)),
        "path={path}"
    );
    assert_eq!(
        result.json().expect("test body is valid utf-8 JSON"),
        serde_json::json!({"error": "UpstreamError", "reason": reason})
    );
    t.assert_result_credential_free(&result);
    assert_eq!(
        header_names(&result),
        std::collections::HashSet::from(["content-type".to_string()])
    );
    let record = t.audit_records().last().unwrap().clone();
    assert_eq!(record["result"], "blocked");
    assert_eq!(record["reason"], reason);
    result
}

#[test]
fn reflection_in_body_and_headers_is_blocked() {
    let t = GatewayTest::new();
    for path in [
        "/echo-headers",
        "/debug/token",
        "/base64-leak",
        "/set-cookie",
    ] {
        assert_blocked(&t, path, "credential_reflection_blocked");
    }
    let alerts = t.ctx.audit.alerts(1000).unwrap();
    let count = alerts
        .iter()
        .filter(|a| a["alert"] == "credential_reflection")
        .count();
    assert_eq!(count, 4);
    t.assert_credential_free(
        &t.state_text(&["audit/audit.jsonl", "audit/alerts.jsonl"]),
        &[SECRET_A, SECRET_B],
    );
}

#[test]
fn relay_result_json_returns_none_instead_of_panicking_on_malformed_body() {
    // Finding X-19: `RelayResult.json()` is `json.loads(self.body.
    // decode("utf-8"))` in Python -- a catchable `UnicodeDecodeError` for
    // non-UTF-8 bytes, a catchable `json.JSONDecodeError` for text that
    // isn't valid JSON. `body` is upstream socket data, which PORTING.md
    // §4 names untrusted and forbids panicking on; the previous Rust
    // `.expect()`-panicked on both failure modes instead of returning an
    // error the caller can handle.
    let non_utf8 = RelayResult {
        status: 200.into(),
        headers: Headers::new(),
        body: vec![0xff, 0xfe, 0xfd],
        reason: None,
    };
    assert_eq!(
        non_utf8.json(),
        None,
        "non-UTF-8 body must return None, not panic"
    );

    let non_json = RelayResult {
        status: 200.into(),
        headers: Headers::new(),
        body: b"not json at all {".to_vec(),
        reason: None,
    };
    assert_eq!(
        non_json.json(),
        None,
        "UTF-8 but non-JSON body must return None, not panic"
    );

    let valid = RelayResult {
        status: 200.into(),
        headers: Headers::new(),
        body: b"{\"ok\": true}".to_vec(),
        reason: None,
    };
    assert_eq!(
        valid.json(),
        Some(serde_json::json!({"ok": true})),
        "a well-formed body must still parse normally"
    );
}

#[test]
fn credential_patterns_cover_both_percent_encoding_casings() {
    let patterns = gateway::credential_patterns(b"AKIA/secret+Key 9=abc", None);
    for expected in [
        &b"AKIA%2Fsecret%2BKey%209%3Dabc"[..],
        &b"AKIA%2fsecret%2bKey%209%3dabc"[..],
        &b"AKIA%2Fsecret%2BKey+9%3Dabc"[..],
        &b"AKIA%2fsecret%2bKey+9%3dabc"[..],
    ] {
        assert!(patterns.iter().any(|p| p == expected), "{:?}", expected);
        let mut blob = b"{\"echo\":\"".to_vec();
        blob.extend_from_slice(expected);
        blob.extend_from_slice(b"\"}");
        assert!(gateway::contains_credential(&blob, &patterns));
    }
    let unique_count = {
        let mut u = patterns.clone();
        u.sort();
        u.dedup();
        u.len()
    };
    assert_eq!(patterns.len(), unique_count);
    let plain = gateway::credential_patterns(SECRET_A.as_bytes(), None);
    let unique_count = {
        let mut u = plain.clone();
        u.sort();
        u.dedup();
        u.len()
    };
    assert_eq!(plain.len(), unique_count);
}

#[test]
fn lowercase_percent_encoded_reflection_is_blocked() {
    let t = GatewayTest::new();
    let fake = FakeUpstream::new(SECRET_RESERVED).start();
    t.ctx
        .vault
        .put_secret(
            "reserved-token",
            "api_key",
            SECRET_RESERVED.as_bytes(),
            "demo",
            "dev",
            true,
        )
        .unwrap();
    t.ctx
        .policy
        .create_connection(http_connection(
            "gh-reserved",
            &fake,
            "reserved-token",
            HttpAuth::bearer(),
            HttpScope::new(None, None, vec!["DELETE".to_string()]).unwrap(),
        ))
        .unwrap();
    let grant = t
        .ctx
        .policy
        .create_grant("agent-1", "gh-reserved", Some(3600), None)
        .unwrap();
    let handle = t.issue_handle_for("agent-1", "gh-reserved", &grant.id, None, 300);
    for path in ["/urlencoded-leak?case=lower", "/urlencoded-leak"] {
        let result = t.relay_full("GET", path, &no_headers(), b"", Some(&handle), None);
        assert_eq!(
            (result.status.clone(), result.reason.as_deref()),
            (502.into(), Some("credential_reflection_blocked")),
            "path={path}"
        );
        assert_eq!(
            result.json().expect("test body is valid utf-8 JSON"),
            serde_json::json!({"error": "UpstreamError", "reason": "credential_reflection_blocked"})
        );
        t.assert_credential_free(&String::from_utf8_lossy(&result.body), &[SECRET_RESERVED]);
        assert!(
            !String::from_utf8_lossy(&result.body)
                .to_lowercase()
                .contains("%2f")
        );
    }
    assert_eq!(fake.requests().len(), 2);
    t.assert_credential_free(
        &t.state_text(&["audit/audit.jsonl", "audit/alerts.jsonl"]),
        &[SECRET_RESERVED],
    );
}

#[test]
fn every_credential_encoding_in_upstream_body_is_blocked() {
    let t = GatewayTest::new();
    for mode in ["bearer", "basic"] {
        let fake_builder = FakeUpstream::new(SECRET_ENCODINGS);
        let fake = if mode == "basic" {
            fake_builder.mode_basic("synthetic-user")
        } else {
            fake_builder
        }
        .start();
        let cid = format!("enc-{mode}");
        let secret_id = format!("enc-{mode}-secret");
        t.ctx
            .vault
            .put_secret(
                &secret_id,
                if mode == "basic" {
                    "password"
                } else {
                    "api_key"
                },
                SECRET_ENCODINGS.as_bytes(),
                "demo",
                "dev",
                true,
            )
            .unwrap();
        let auth = if mode == "basic" {
            HttpAuth::new("basic", None, None, Some("synthetic-user".to_string())).unwrap()
        } else {
            HttpAuth::bearer()
        };
        t.ctx
            .policy
            .create_connection(http_connection(
                &cid,
                &fake,
                &secret_id,
                auth,
                HttpScope::new(None, None, vec![]).unwrap(),
            ))
            .unwrap();
        let grant = t
            .ctx
            .policy
            .create_grant("agent-1", &cid, Some(3600), None)
            .unwrap();
        let handle = t.issue_handle_for("agent-1", &cid, &grant.id, None, 300);
        let result = t.relay_full(
            "GET",
            "/me",
            &headers(&[("Authorization", PLACEHOLDER)]),
            b"",
            Some(&handle),
            None,
        );
        assert_eq!(
            (
                result.status.clone(),
                result.json().expect("test body is valid utf-8 JSON")
            ),
            (200.into(), serde_json::json!({"login": "synthetic-user"})),
            "{mode}"
        );
        let mut forms: Vec<&str> = zeropw::fake_upstream::ENCODED_LEAK_FORMS.to_vec();
        if mode == "basic" {
            forms.extend_from_slice(zeropw::fake_upstream::BASIC_LEAK_FORMS);
        }
        for form in &forms {
            let result = t.relay_full(
                "GET",
                &format!("/encoded-leak?form={form}"),
                &no_headers(),
                b"",
                Some(&handle),
                None,
            );
            assert_eq!(
                (result.status.clone(), result.reason.as_deref()),
                (502.into(), Some("credential_reflection_blocked")),
                "{mode} {form}"
            );
            assert_eq!(
                result.json().expect("test body is valid utf-8 JSON"),
                serde_json::json!({"error": "UpstreamError", "reason": "credential_reflection_blocked"})
            );
            assert!(!result.body.windows(5).any(|w| w == b"leak="));
            t.assert_credential_free(&String::from_utf8_lossy(&result.body), &[SECRET_ENCODINGS]);
            assert_eq!(
                header_names(&result),
                std::collections::HashSet::from(["content-type".to_string()])
            );
        }
        let result = t.relay_full(
            "GET",
            "/encoded-leak?form=nope",
            &no_headers(),
            b"",
            Some(&handle),
            None,
        );
        assert_eq!(
            (
                result.status.clone(),
                result.reason.clone(),
                result.json().expect("test body is valid utf-8 JSON")
            ),
            (
                400.into(),
                None,
                serde_json::json!({"error": "unknown_form"})
            )
        );
        assert_eq!(fake.requests().len(), forms.len() + 2);
    }
    t.assert_credential_free(
        &t.state_text(&["audit/audit.jsonl", "audit/alerts.jsonl"]),
        &[SECRET_ENCODINGS],
    );
}

#[test]
fn credential_embedded_in_base64_blob_is_blocked_at_every_alignment() {
    let t = GatewayTest::new();
    for alphabet in ["std", "url"] {
        for offset in 0..3 {
            for wrap in [0, 60] {
                assert_blocked(
                    &t,
                    &format!(
                        "/base64-embedded-leak?offset={offset}&wrap={wrap}&alphabet={alphabet}"
                    ),
                    "credential_reflection_blocked",
                );
            }
        }
    }
    assert_eq!(t.fake.requests().len(), 12);
    t.assert_credential_free(
        &t.state_text(&["audit/audit.jsonl", "audit/alerts.jsonl"]),
        &[SECRET_A, SECRET_B],
    );
}

#[test]
fn redirects_are_not_followed_and_location_never_forwarded() {
    let t = GatewayTest::new();
    for path in ["/redirect", "/redirect-external"] {
        let result = assert_blocked(&t, path, "redirect_not_followed");
        assert!(!header_names(&result).contains("location"));
        assert!(!String::from_utf8_lossy(&result.body).contains("leak"));
        assert!(!String::from_utf8_lossy(&result.body).contains("evil.invalid"));
    }
    let paths: Vec<String> = t.fake.requests().iter().map(|r| r.path.clone()).collect();
    assert_eq!(
        paths,
        vec!["/redirect".to_string(), "/redirect-external".to_string()]
    );
    assert_eq!(t.audit_records().last().unwrap()["status"], 302);
}

#[test]
fn chunked_stream_is_buffered() {
    let t = GatewayTest::new();
    let result = t.relay("GET", "/stream");
    let expected: Vec<u8> = zeropw::fake_upstream::STREAM_PARTS.concat();
    assert_eq!(
        (result.status.clone(), result.body.clone()),
        (200.into(), expected)
    );
    assert!(!header_names(&result).contains("transfer-encoding"));
}

#[test]
fn large_ok_and_huge_rejected() {
    let mut t = GatewayTest::new();
    let result = t.relay("GET", "/large");
    assert_eq!(
        (result.status.clone(), result.body.len()),
        (200.into(), zeropw::fake_upstream::LARGE_BODY_SIZE)
    );
    let huge = assert_blocked(&t, "/huge", "response_too_large");
    assert!(!huge.body.windows(4).any(|w| w == b"yyyy"));
    // finding F-13 (tests/test_gateway.py:552-560's `test_large_ok_and_huge_rejected`):
    // the original port stopped at the `/huge` case above and dropped the
    // `max_response_bytes` mutation entirely, so a response that is only
    // too large *for this connection's own configured limit* (not the
    // hard-coded `/huge` fixture) was never exercised.
    t.ctx.config.max_response_bytes = 1024;
    let small = t.relay("GET", "/large");
    assert_eq!(small.reason.as_deref(), Some("response_too_large"));
}

#[test]
fn upstream_down_and_timeout() {
    // `Context::config` is a plain field the test owns, so it can be
    // mutated directly through a `mut` binding (finding F-5: a slow
    // upstream must classify as `upstream_timeout`, not
    // `upstream_connection_lost`, matching `tests/test_gateway.py:561`'s
    // `test_upstream_down_and_timeout`).
    let mut t = GatewayTest::new();
    t.ctx.config.upstream_timeout = 0.3;
    let slow = t.relay("GET", "/slow?seconds=1");
    assert_eq!(
        (slow.status.clone(), slow.reason.as_deref()),
        (502.into(), Some("upstream_timeout"))
    );
    t.assert_result_credential_free(&slow);
    assert_eq!(t.audit_records().last().unwrap()["result"], "error");

    t.fake.stop();
    let down = t.relay("GET", "/repos");
    assert_eq!(
        (down.status.clone(), down.reason.as_deref()),
        (502.into(), Some("upstream_unreachable"))
    );
    t.assert_result_credential_free(&down);
    assert_eq!(
        t.audit_records().last().unwrap()["reason"],
        "upstream_unreachable"
    );
    std::thread::sleep(Duration::from_millis(800)); // let the sleeping fake handler thread finish
}

#[test]
fn invalid_upstream_timeout_escapes_relay_like_python() {
    // Finding X-18, re-measured: `float(self.ctx.config.upstream_timeout)`
    // never raises; `socket.create_connection`'s `sock.settimeout(timeout)`
    // does, with a built-in exception none of `_exchange`'s handlers catch
    // (CPython 3.12.14: `inf`/`-inf`/`1e30`/`9.3e9` -> `OverflowError`,
    // `nan`/`-1.0`/`-1e-300` -> `ValueError`), so `relay` raises and
    // `zeropw.server` answers its fixed `500 internal_error`. A zero
    // timeout is a non-blocking connect whose `BlockingIOError` is the
    // ordinary `upstream_unreachable` refusal. The ledger/audit scope of the
    // escape is compared with Python in `relay_escape_parity`.
    for (label, timeout, expected) in [
        ("infinity", f64::INFINITY, (500, "internal_error")),
        ("neg_infinity", f64::NEG_INFINITY, (500, "internal_error")),
        ("huge_finite", 1e30, (500, "internal_error")),
        ("past_int64_nanoseconds", 9.3e9, (500, "internal_error")),
        ("nan", f64::NAN, (500, "internal_error")),
        ("negative", -1.0, (500, "internal_error")),
        ("tiny_negative", -1e-300, (500, "internal_error")),
        ("zero", 0.0, (502, "upstream_unreachable")),
        ("negative_zero", -0.0, (502, "upstream_unreachable")),
    ] {
        let mut t = GatewayTest::new();
        t.ctx.config.upstream_timeout = timeout;
        let result = t.relay("GET", "/repos");
        assert_eq!(
            (result.status.clone(), result.reason.as_deref()),
            (expected.0.into(), Some(expected.1)),
            "{label}"
        );
        t.assert_result_credential_free(&result);
    }
}

#[test]
fn unsupported_auth_mode_and_unsafe_credential_fail_closed() {
    let t = GatewayTest::new();
    t.ctx
        .vault
        .put_secret(
            "crlf",
            "api_key",
            b"synthetic\r\nX-Injected: 1",
            "demo",
            "dev",
            true,
        )
        .unwrap();
    t.ctx
        .policy
        .create_connection(http_connection(
            "crlf",
            &t.fake,
            "crlf",
            HttpAuth::bearer(),
            HttpScope::new(None, None, vec![]).unwrap(),
        ))
        .unwrap();
    let grant = t
        .ctx
        .policy
        .create_grant("agent-1", "crlf", Some(3600), None)
        .unwrap();
    let handle = t.issue_handle_for("agent-1", "crlf", &grant.id, None, 300);
    let result = t.relay_full("GET", "/repos", &no_headers(), b"", Some(&handle), None);
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (501.into(), Some("credential_header_unsafe"))
    );
    assert_eq!(t.fake.requests().len(), 0);
}

#[test]
fn unsupported_auth_mode_via_corrupted_stored_document() {
    // finding F-R2-11 (correcting round-1 finding F-18's mischaracterization
    // of this exact scenario): a hand-edited stored `connections.json` with
    // `http_auth.mode: "digest"` makes the real Python
    // `HttpAuth(**value)` constructor's own `__post_init__` reject the
    // unknown mode with `InvalidInput("unsupported_auth_mode")`
    // (`policy.py:248`) *at connection-load time* -- before `_Relay.run`
    // ever reaches `_auth_header` -- propagating uncaught through
    // `Policy.evaluate` to `relay`'s top level, exactly the shape
    // `DEVIATIONS.md`'s `unexpected_error_result` row already documents.
    // Confirmed directly against real `python3.12`, not just reasoned
    // about.
    //
    // Rust's `Connection::from_value` -> `HttpAuth::from_value` fails the
    // same way, at the same point, propagating to `relay`'s own
    // `unexpected_error_result` and surfacing as `(400, "InvalidInput",
    // "unsupported_auth_mode")` -- matching Python for this input, not
    // diverging from it. `HttpAuth::new`/`from_value` are the only ways to
    // construct an `HttpAuth` in Rust, and both already reject an unknown
    // `mode` eagerly, same as the real Python constructor.
    //
    // Round-1's `test_unsupported_auth_mode_fails_closed` (a *different*
    // Python test, `tests/test_gateway.py:574-596`) reaches `_auth_header`'s
    // own defensive fallback (`gateway.py:377`, raising
    // `Unsupported("unsupported_auth_mode")`, i.e. 501) only via
    // `object.__new__(P.HttpAuth)`, which bypasses `__post_init__` entirely
    // and then injects the resulting object into a `Decision` via
    // `mock.patch.object(policy, "evaluate", ...)`. That is a
    // PORTING.md §3.4 case (a Python-only mechanism -- reflection bypassing
    // a constructor's own validation -- with no Rust equivalent): Rust's
    // `HttpAuth` has no `object.__new__`-style backdoor, so there is no way
    // to reach `auth_header`'s analogous fallback with an invalid `mode` in
    // the first place, and this test does not attempt to reproduce that
    // unreachable scenario -- it instead pins the *reachable* hand-edited-
    // document scenario, which matches Python exactly. See the "gateway
    // (`unsupported_auth_mode` via a hand-edited stored document)" row in
    // `DEVIATIONS.md`.
    let t = GatewayTest::new();
    let path = t.ctx.state.path.join(P::CONNECTIONS);
    let text = std::fs::read_to_string(&path).unwrap();
    let mut doc: Value = serde_json::from_str(&text).unwrap();
    doc["gh"]["http_auth"]["mode"] = serde_json::json!("digest");
    std::fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();

    let result = t.relay("GET", "/repos");
    assert_eq!(result.reason.as_deref(), Some("unsupported_auth_mode"));
    assert_eq!(result.status, 400);
    assert_eq!(
        result.json().expect("test body is valid utf-8 JSON")["error"],
        "InvalidInput"
    );
    assert_eq!(t.fake.requests().len(), 0);
}

#[test]
fn zeropw_authority_is_never_a_business_credential() {
    // finding F-16(c) (tests/test_gateway.py:1099-1115's
    // `test_zeropw_authority_is_never_a_business_credential`): not ported
    // at all previously.
    let t = GatewayTest::new();
    let token = t.ctx.policy.create_principal("agent-2", "cli").unwrap();
    let bearer_token = format!("Bearer {token}");
    let cases: [(&str, &[u8]); 3] = [
        ("caller-token", token.as_bytes()),
        ("handle", t.handle.as_bytes()),
        ("bearer-caller-token", bearer_token.as_bytes()),
    ];
    for (name, value) in cases {
        t.ctx
            .vault
            .put_secret(name, "api_key", value, "demo", "dev", true)
            .unwrap();
        t.ctx
            .policy
            .create_connection(http_connection(
                name,
                &t.fake,
                name,
                HttpAuth::bearer(),
                HttpScope::new(None, None, vec![]).unwrap(),
            ))
            .unwrap();
        t.ctx
            .policy
            .create_grant("agent-1", name, Some(3600), None)
            .unwrap();
        let result = gateway::relay_for_caller(
            &t.ctx,
            "agent-1",
            name,
            "GET",
            "/me",
            &no_headers(),
            b"",
            None,
        );
        assert_eq!(
            (result.status.clone(), result.reason.as_deref()),
            (501.into(), Some("self_referential_credential")),
            "{name}"
        );
    }
    assert_eq!(t.fake.requests().len(), 0);

    // A credential that merely contains the letters is not mistaken for ZeroPW authority.
    t.ctx
        .vault
        .put_secret(
            "lookalike",
            "api_key",
            b"synthetic-token-xzpw1.abc-zpwc_def",
            "demo",
            "dev",
            true,
        )
        .unwrap();
    t.ctx
        .policy
        .create_connection(http_connection(
            "lookalike",
            &t.fake,
            "lookalike",
            HttpAuth::bearer(),
            HttpScope::new(None, None, vec![]).unwrap(),
        ))
        .unwrap();
    t.ctx
        .policy
        .create_grant("agent-1", "lookalike", Some(3600), None)
        .unwrap();
    let result = gateway::relay_for_caller(
        &t.ctx,
        "agent-1",
        "lookalike",
        "GET",
        "/me",
        &no_headers(),
        b"",
        None,
    );
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (401.into(), None)
    );
    t.assert_credential_free(&t.state_text(&["audit/audit.jsonl"]), &[token.as_str()]);
}

#[test]
fn missing_credential_is_explicit() {
    let t = GatewayTest::new();
    t.ctx
        .vault
        .set_version_status("gh-token", &1.into(), "retired")
        .unwrap();
    let result = t.relay("GET", "/repos");
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (503.into(), Some("credential_unavailable"))
    );
    assert_eq!(t.fake.requests().len(), 0);
}

#[test]
fn audit_unavailable_refuses_before_credential_use() {
    // finding F-16(a) (tests/test_gateway.py:603-618's
    // `test_audit_unavailable_refuses_before_credential_use`): not ported at
    // all previously ("audit_unavailable"/"append_line" did not appear
    // anywhere in this file). Python monkeypatches
    // `ctx.state.append_line` to raise `OSError("disk full")`; this port
    // reaches the same `StateDir::append_line` failure through the
    // filesystem instead -- stripping the audit log's write permission --
    // since there is no injectable seam for that method.
    let t = GatewayTest::new();
    let audit_path = t.ctx.state.path.join(zeropw::audit::AUDIT_FILE);
    let original_perms = std::fs::metadata(&audit_path).unwrap().permissions();
    let mut readonly = original_perms.clone();
    readonly.set_readonly(true);
    std::fs::set_permissions(&audit_path, readonly).unwrap();
    let result = t.relay("GET", "/repos");
    std::fs::set_permissions(&audit_path, original_perms).unwrap();
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (503.into(), Some("audit_unavailable"))
    );
    assert_eq!(t.fake.requests().len(), 0);
    assert_eq!(t.ctx.policy.get_grant(&t.grant.id).unwrap().uses, 0);
    // Audit back: the request proceeds.
    assert_eq!(t.relay("GET", "/repos").status, 200);
}

#[test]
fn audit_and_alerts_are_value_free() {
    let t = GatewayTest::new();
    for path in [
        "/repos",
        "/echo-headers",
        "/debug/token",
        "/redirect",
        "/repos?secret=agent-guess",
    ] {
        t.relay_h(
            "GET",
            path,
            &headers(&[("Authorization", PLACEHOLDER), ("Cookie", "c=1")]),
        );
    }
    t.ctx.policy.revoke_grant(&t.grant.id).unwrap();
    t.relay("GET", "/repos");
    let blob = t.state_text(&[
        "audit/audit.jsonl",
        "audit/alerts.jsonl",
        "gateway/requests.json",
    ]);
    t.assert_credential_free(&blob, &[SECRET_A, SECRET_B]);
    assert!(!blob.contains("democli-placeholder"));
    assert!(!blob.contains("agent-guess"));
    assert!(!blob.contains(&t.handle));
    assert!(!blob.contains("c=1"));
}

// --------------------------------------------------------------- approvals

#[test]
fn delete_requires_one_shot_approval_bound_to_digest() {
    let t = GatewayTest::new();
    let first = t.relay("DELETE", "/repos/demo");
    assert_eq!(
        (first.status.clone(), first.reason.as_deref()),
        (428.into(), Some("approval_required"))
    );
    let digest = first.json().expect("test body is valid utf-8 JSON")["approval_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let subject = zeropw::pyjson::dumps(
        &serde_json::json!({"content_type": null, "origin": format!("http://127.0.0.1:{}", t.fake.port()), "policy_version": 1, "target": "/repos/demo"}),
        zeropw::pyjson::DumpOptions::compact_sorted(),
    )
    .unwrap();
    assert_eq!(
        digest,
        P::approval_digest("agent-1", "gh", "DELETE", &subject, b"")
    );
    assert_eq!(t.fake.requests().len(), 0);
    assert_eq!(
        t.ctx.policy.list_approvals().unwrap()[&digest]["status"],
        "pending"
    );
    let record = t.audit_records().last().unwrap().clone();
    assert_eq!(record["result"], "denied");
    assert_eq!(record["reason"], "approval_required");
    assert_eq!(record["digest"], digest);
    t.ctx.policy.approve(&digest).unwrap();
    let other = t.relay("DELETE", "/repos/other");
    assert_eq!(other.status, 428);
    assert_ne!(
        other.json().expect("test body is valid utf-8 JSON")["approval_digest"],
        digest
    );
    assert_eq!(t.fake.requests().len(), 0);
    let done = t.relay("DELETE", "/repos/demo");
    assert_eq!(
        (done.status.clone(), done.reason.clone()),
        (204.into(), None)
    );
    assert_eq!(t.fake.requests().last().unwrap().method, "DELETE");
    let again = t.relay("DELETE", "/repos/demo");
    assert_eq!(
        (again.status.clone(), again.reason.as_deref()),
        (428.into(), Some("approval_required"))
    );
    assert_eq!(t.fake.requests().len(), 1);
    assert_eq!(t.ctx.policy.get_grant(&t.grant.id).unwrap().uses, 1);
}

#[test]
fn pending_approval_shows_what_the_digest_binds() {
    // finding F-15 (tests/test_gateway.py:660-717's
    // `test_pending_approval_shows_what_the_digest_binds`): not ported at
    // all previously -- `Relay::annotate_approval` had no test coverage.
    let t = GatewayTest::new();
    t.ctx
        .policy
        .create_connection(http_connection(
            "writes",
            &t.fake,
            "gh-token",
            HttpAuth::bearer(),
            HttpScope::new(None, None, vec!["POST".to_string()]).unwrap(),
        ))
        .unwrap();
    let grant = t
        .ctx
        .policy
        .create_grant("agent-1", "writes", Some(3600), None)
        .unwrap();
    let handle = t.issue_handle_for("agent-1", "writes", &grant.id, None, 300);
    let json_type = headers(&[("Content-Type", "application/json")]);
    let benign_body = serde_json::to_vec(&serde_json::json!({"title": "typo fix"})).unwrap();
    let evil_body = serde_json::to_vec(&serde_json::json!({"title": "wipe everything"})).unwrap();
    let benign = t.relay_full(
        "POST",
        "/repos/demo/issues",
        &json_type,
        &benign_body,
        Some(&handle),
        None,
    );
    let evil = t.relay_full(
        "POST",
        "/repos/demo/issues?admin_override=1",
        &json_type,
        &evil_body,
        Some(&handle),
        None,
    );
    assert_eq!(
        (benign.reason.as_deref(), evil.reason.as_deref()),
        (Some("approval_required"), Some("approval_required"))
    );
    let approvals = t.ctx.policy.list_approvals().unwrap();
    let benign_digest = benign.json().expect("test body is valid utf-8 JSON")["approval_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let evil_digest = evil.json().expect("test body is valid utf-8 JSON")["approval_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let benign_entry = &approvals[&benign_digest];
    let evil_entry = &approvals[&evil_digest];
    let origin = format!("http://127.0.0.1:{}", t.fake.port());
    assert_eq!(evil_entry["caller"], "agent-1");
    assert_eq!(evil_entry["connection"], "writes");
    assert_eq!(evil_entry["method"], "POST");
    assert_eq!(evil_entry["path"], "/repos/demo/issues");
    assert_eq!(evil_entry["origin"], origin);
    assert_eq!(evil_entry["query"], "admin_override=1");
    assert_eq!(evil_entry["content_type"], "application/json");
    assert_eq!(evil_entry["body_bytes"], evil_body.len());
    assert_eq!(
        evil_entry["body_sha256"],
        hex::encode(Sha256::digest(&evil_body))
    );
    assert_eq!(
        evil_entry["body_preview"],
        String::from_utf8(evil_body.clone()).unwrap()
    );
    assert_eq!(evil_entry["body_preview_truncated"], false);
    assert_eq!(evil_entry["policy_version"], 1);
    assert_eq!(evil_entry["status"], "pending");
    assert_eq!(benign_entry["query"], Value::Null);
    assert_eq!(
        benign_entry["body_preview"],
        String::from_utf8(benign_body.clone()).unwrap()
    );
    assert_ne!(benign_entry["body_sha256"], evil_entry["body_sha256"]);
    // The details live only in the admin-only approval record, never in the audit log.
    let audit = t.state_text(&["audit/audit.jsonl"]);
    assert!(!audit.contains("admin_override"));
    assert!(!audit.contains("wipe everything"));
    // Approving the benign entry releases exactly the benign request.
    t.ctx.policy.approve(&benign_digest).unwrap();
    let still_pending = t.relay_full(
        "POST",
        "/repos/demo/issues?admin_override=1",
        &json_type,
        &evil_body,
        Some(&handle),
        None,
    );
    assert_eq!(still_pending.reason.as_deref(), Some("approval_required"));
    let done = t.relay_full(
        "POST",
        "/repos/demo/issues",
        &json_type,
        &benign_body,
        Some(&handle),
        None,
    );
    assert_eq!(
        (done.status.clone(), done.reason.clone()),
        (201.into(), None)
    );
    let last = t.fake.requests().last().unwrap().clone();
    assert_eq!(
        (last.path.as_str(), last.body),
        ("/repos/demo/issues", benign_body)
    );
    // Content-Type is bound as well: the approved bytes under another type need a new approval.
    t.ctx.policy.approve(&evil_digest).unwrap();
    let retyped = t.relay_full(
        "POST",
        "/repos/demo/issues?admin_override=1",
        &headers(&[("Content-Type", "text/plain")]),
        &evil_body,
        Some(&handle),
        None,
    );
    assert_eq!(retyped.reason.as_deref(), Some("approval_required"));
    let retyped_digest = retyped.json().expect("test body is valid utf-8 JSON")["approval_digest"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        t.ctx.policy.list_approvals().unwrap()[&retyped_digest]["content_type"],
        "text/plain"
    );
    assert_eq!(t.fake.requests().len(), 1);
    // Long and binary bodies: bounded preview, or size and digest only.
    let mut long_body = b"{\"title\":\"".to_vec();
    long_body.extend(std::iter::repeat_n(b'x', 1000));
    long_body.push(b'"');
    long_body.push(b'}');
    let long_result = t.relay_full(
        "POST",
        "/repos/demo/issues",
        &json_type,
        &long_body,
        Some(&handle),
        None,
    );
    let long_digest = long_result.json().expect("test body is valid utf-8 JSON")["approval_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let long_entry = t.ctx.policy.list_approvals().unwrap()[&long_digest].clone();
    assert_eq!(
        long_entry["body_preview"].as_str().unwrap().chars().count(),
        gateway::APPROVAL_PREVIEW_CHARS
    );
    assert_eq!(long_entry["body_preview_truncated"], true);
    let binary_result = t.relay_full(
        "POST",
        "/repos/demo/issues",
        &no_headers(),
        b"\xff\xfe\x00binary",
        Some(&handle),
        None,
    );
    let binary_digest =
        binary_result.json().expect("test body is valid utf-8 JSON")["approval_digest"]
            .as_str()
            .unwrap()
            .to_string();
    let binary_entry = t.ctx.policy.list_approvals().unwrap()[&binary_digest].clone();
    assert_eq!(binary_entry["body_preview"], Value::Null);
    assert_eq!(binary_entry["body_bytes"], 9);
    assert_eq!(binary_entry["content_type"], Value::Null);
}

#[test]
fn approval_does_not_survive_a_changed_target_or_policy_version() {
    // finding F-15 (tests/test_gateway.py:718-749's
    // `test_approval_does_not_follow_a_changed_origin_or_policy_version`):
    // not ported at all previously. Python's first half additionally
    // mock-patches `Policy.evaluate` to simulate the *same* connection
    // resolving to a different origin without changing stored state at
    // all; there is no portable Rust seam for that (evaluate is not
    // injectable), so this port exercises the origin-binding property via
    // the mechanism the equivalence review itself called out as portable:
    // `update_connection` to another port, plus `regrant` -- which changes
    // both the origin and the policy version together, still proving the
    // same thing (an approval granted under one resolved origin/policy
    // version is refused under another).
    let t = GatewayTest::new();
    let first = t.relay("DELETE", "/repos/demo");
    let digest = first.json().expect("test body is valid utf-8 JSON")["approval_digest"]
        .as_str()
        .unwrap()
        .to_string();
    t.ctx.policy.approve(&digest).unwrap();

    let other = FakeUpstream::new(SECRET_A).start();
    let (_, widened) = t
        .ctx
        .policy
        .update_connection(
            "gh",
            ConnectionChanges::new().http_target(Some(
                HttpTarget::new("http", "127.0.0.1", other.port() as i64, None, false).unwrap(),
            )),
        )
        .unwrap();
    assert!(widened);
    let fresh = t.ctx.policy.regrant(&t.grant.id).unwrap();
    let fresh_handle = t.issue_handle_for("agent-1", "gh", &fresh.id, None, 300);
    let after_move = t.relay_full(
        "DELETE",
        "/repos/demo",
        &no_headers(),
        b"",
        Some(&fresh_handle),
        None,
    );
    assert_eq!(
        (after_move.status.clone(), after_move.reason.as_deref()),
        (428.into(), Some("approval_required"))
    );
    let after_move_digest =
        after_move.json().expect("test body is valid utf-8 JSON")["approval_digest"]
            .as_str()
            .unwrap()
            .to_string();
    assert_ne!(after_move_digest, digest);
    assert_eq!(
        t.ctx.policy.list_approvals().unwrap()[&after_move_digest]["origin"],
        format!("http://127.0.0.1:{}", other.port())
    );

    // A policy-version change alone (not widening) also needs a new approval.
    t.ctx.policy.approve(&after_move_digest).unwrap();
    t.ctx
        .policy
        .update_connection("gh", ConnectionChanges::new().description("renamed"))
        .unwrap();
    let renamed = gateway::relay_for_caller(
        &t.ctx,
        "agent-1",
        "gh",
        "DELETE",
        "/repos/demo",
        &no_headers(),
        b"",
        None,
    );
    assert_eq!(
        (renamed.status.clone(), renamed.reason.as_deref()),
        (428.into(), Some("approval_required"))
    );
    let renamed_digest = renamed.json().expect("test body is valid utf-8 JSON")["approval_digest"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(renamed_digest, after_move_digest);
    assert_eq!(t.fake.requests().len(), 0);
    assert_eq!(other.requests().len(), 0);
}

// ---------------------------------------------------------------- ledger

fn issue_ledger(t: &GatewayTest, request_id: &str, title: &str) -> RelayResult {
    let body = serde_json::to_vec(&serde_json::json!({"title": title})).unwrap();
    t.relay_full(
        "POST",
        "/repos/demo/issues",
        &headers(&[("Content-Type", "application/json")]),
        &body,
        None,
        Some(request_id),
    )
}

/// Overwrites the stored `response` object of an already-`"completed"`
/// ledger entry (as left behind by `issue_ledger`) with an arbitrary,
/// possibly-corrupted value, for `RequestLedger::replay` differential
/// probes (findings F-R4-3, F-R4-4, F-R4-5). The entry's `digest` is left
/// untouched, so replaying the exact same `(method, target, body,
/// request_id)` still matches and takes the replay path.
fn set_ledger_response(
    t: &GatewayTest,
    caller: &str,
    request_id: &str,
    response: serde_json::Value,
) {
    let ledger_path = t.ctx.state.path.join(gateway::LEDGER_DOC);
    let raw = std::fs::read_to_string(&ledger_path).unwrap();
    let mut doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
    doc[caller][request_id]["response"] = response;
    doc[caller][request_id]["state"] = serde_json::json!("completed");
    std::fs::write(&ledger_path, serde_json::to_vec(&doc).unwrap()).unwrap();
}

#[test]
fn completed_request_is_replayed_without_upstream_contact() {
    let t = GatewayTest::new();
    let first = issue_ledger(&t, "req-1", "same");
    assert_eq!(first.status, 201);
    let replay = issue_ledger(&t, "req-1", "same");
    assert_eq!(
        (
            replay.status.clone(),
            replay.body.clone(),
            replay.reason.clone()
        ),
        (201.into(), first.body.clone(), None)
    );
    assert!(
        replay
            .headers
            .iter()
            .any(|(k, v)| k == "X-ZeroPW-Replay" && v == "true")
    );
    assert_eq!(t.fake.requests().len(), 1);
    assert_eq!(t.ctx.policy.get_grant(&t.grant.id).unwrap().uses, 1);
    assert_eq!(t.audit_records().last().unwrap()["reason"], "replayed");
    assert_eq!(t.audit_records().last().unwrap()["request_id"], "req-1");

    let via_header = t.relay_full(
        "POST",
        "/repos/demo/issues",
        &headers(&[
            ("Content-Type", "application/json"),
            ("X-ZeroPW-Request-Id", "req-1"),
        ]),
        &serde_json::to_vec(&serde_json::json!({"title": "same"})).unwrap(),
        None,
        None,
    );
    assert_eq!(via_header.status, 201);
    assert_eq!(t.fake.requests().len(), 1);

    t.ctx.policy.revoke_grant(&t.grant.id).unwrap();
    assert_eq!(
        issue_ledger(&t, "req-1", "same").reason.as_deref(),
        Some("grant_revoked")
    );
}

#[test]
fn replay_decodes_body_b64_leniently_like_python_b64decode() {
    // Finding F-R4-3: CPython's `base64.b64decode` is lenient, discarding
    // non-alphabet bytes rather than rejecting them -- confirmed directly
    // against live `python3.12`: `base64.b64decode("YWJj\n") == b"abc"`.
    // The previous Rust `replay` used the `base64` crate's *strict*
    // `STANDARD` engine and silently emptied the body on any decode
    // failure instead of using the canonical `crate::pybase64::b64decode`
    // (PORTING.md §3b) or failing closed.
    let t = GatewayTest::new();
    assert_eq!(issue_ledger(&t, "req-b64-lenient", "same").status, 201);
    set_ledger_response(
        &t,
        "agent-1",
        "req-b64-lenient",
        serde_json::json!({
            "status": 200, "headers": [], "reason": null,
            "body_b64": "YWJj\n", "body_stored": true,
        }),
    );
    let replayed = issue_ledger(&t, "req-b64-lenient", "same");
    assert_eq!(
        (
            replayed.status.clone(),
            replayed.body.clone(),
            replayed.reason.clone()
        ),
        (200.into(), b"abc".to_vec(), None),
        "a newline inside the base64 body must be discarded, not rejected, matching \
         Python's lenient b64decode"
    );
}

#[test]
fn replay_fails_closed_for_genuinely_undecodable_body_b64() {
    // Finding F-R4-3: `base64.b64decode("A")` raises `binascii.Error`
    // (confirmed against live `python3.12`) -- a single leftover base64
    // character can never complete a quad even leniently. The previous
    // Rust `replay` relayed a `200` with a silently emptied body instead
    // of failing closed.
    let t = GatewayTest::new();
    assert_eq!(issue_ledger(&t, "req-b64-bad", "same").status, 201);
    set_ledger_response(
        &t,
        "agent-1",
        "req-b64-bad",
        serde_json::json!({
            "status": 200, "headers": [], "reason": null,
            "body_b64": "A", "body_stored": true,
        }),
    );
    let replayed = issue_ledger(&t, "req-b64-bad", "same");
    assert_eq!(
        (replayed.status.clone(), replayed.reason.as_deref()),
        (500.into(), Some("internal_error"))
    );
}

#[test]
fn replay_fails_closed_for_non_string_body_b64() {
    // Finding F-R4-3/F-R4-4: `base64.b64decode(5)` raises `TypeError`
    // (confirmed against live `python3.12`) since `response.get("body_b64")
    // or ""` only substitutes an empty default for a *falsy* stored value,
    // not for a truthy wrongly-typed one.
    let t = GatewayTest::new();
    assert_eq!(issue_ledger(&t, "req-b64-nonstr", "same").status, 201);
    set_ledger_response(
        &t,
        "agent-1",
        "req-b64-nonstr",
        serde_json::json!({
            "status": 200, "headers": [], "reason": null,
            "body_b64": 5, "body_stored": true,
        }),
    );
    let replayed = issue_ledger(&t, "req-b64-nonstr", "same");
    assert_eq!(
        (replayed.status.clone(), replayed.reason.as_deref()),
        (500.into(), Some("internal_error"))
    );
}

#[test]
fn replay_treats_a_truthy_non_bool_body_stored_as_stored() {
    // Finding F-R4-4(a): `if not response.get("body_stored")` is Python
    // truthiness, not `== True` -- confirmed against live `python3.12`:
    // `not "yes"` is `False`, so a truthy non-bool `body_stored` still
    // takes the real-body path. The previous Rust `replay` used
    // `.and_then(Value::as_bool) != Some(true)`, which treated any
    // non-`true` JSON value (including a truthy string) as "not stored"
    // and withheld the real body via `replay_body_unavailable`.
    let t = GatewayTest::new();
    assert_eq!(issue_ledger(&t, "req-stored-truthy", "same").status, 201);
    set_ledger_response(
        &t,
        "agent-1",
        "req-stored-truthy",
        serde_json::json!({
            "status": 200, "headers": [], "reason": null,
            "body_b64": "YWJj", "body_stored": "yes",
        }),
    );
    let replayed = issue_ledger(&t, "req-stored-truthy", "same");
    assert_eq!(
        (
            replayed.status.clone(),
            replayed.body.clone(),
            replayed.reason.clone()
        ),
        (200.into(), b"abc".to_vec(), None),
        "a truthy non-bool body_stored must still replay the real stored body"
    );
}

#[test]
fn replay_unpacks_a_two_character_string_header_element() {
    // Finding F-R4-4(c): `for k, v in [ "ab" ]` unpacks the two-character
    // string element into `k="a", v="b"` -- confirmed against live
    // `python3.12`. The previous Rust `python_headers_from_json` required
    // every element to be a 2-element JSON *array* and refused this shape
    // with `state_corrupt`/503, and its own doc comment wrongly claimed
    // "Python's unpacking itself raises" for it.
    let t = GatewayTest::new();
    assert_eq!(issue_ledger(&t, "req-headers-str", "same").status, 201);
    set_ledger_response(
        &t,
        "agent-1",
        "req-headers-str",
        serde_json::json!({
            "status": 200, "headers": ["ab"], "reason": null,
            "body_b64": "", "body_stored": true,
        }),
    );
    let replayed = issue_ledger(&t, "req-headers-str", "same");
    assert_eq!(replayed.status, 200);
    assert_eq!(replayed.reason, None);
    assert!(
        replayed.headers.iter().any(|(k, v)| k == "a" && v == "b"),
        "a two-character string header element must unpack to (\"a\", \"b\"): {:?}",
        replayed.headers
    );
}

#[test]
fn replay_keeps_a_non_string_reason_and_reports_it_as_blocked() {
    // Finding F-R4-4(b): `reason = response.get("reason")` keeps whatever
    // is stored, unconverted -- `RelayResult.relayed` is `self.reason is
    // None`, so a truthy non-string like `5` still makes `relayed` `False`
    // (confirmed against live `python3.12`). The previous Rust `replay`
    // used `.and_then(Value::as_str)`, turning a non-string `reason` into
    // `None` -- `relayed()` became `true` and the caller's audit outcome
    // was `"ok"` instead of `"blocked"`.
    let t = GatewayTest::new();
    assert_eq!(issue_ledger(&t, "req-reason-int", "same").status, 201);
    set_ledger_response(
        &t,
        "agent-1",
        "req-reason-int",
        serde_json::json!({
            "status": 200, "headers": [], "reason": 5,
            "body_b64": "YWJj", "body_stored": true,
        }),
    );
    let replayed = issue_ledger(&t, "req-reason-int", "same");
    assert_eq!(replayed.status, 200);
    assert_eq!(replayed.reason.as_deref(), Some("5"));
    assert!(
        !replayed.relayed(),
        "a present (even wrongly-typed) reason must not be `relayed`"
    );
}

#[test]
fn replay_renders_a_stored_float_reason_via_cpython_repr() {
    // Finding F-R4-5: `python_str_of` must render a float the way CPython
    // `str(float)` does, via the canonical `pyjson::python_float_repr`
    // (PORTING.md §3b) -- confirmed against live `python3.12`:
    // `str(1e-07) == "1e-07"`. The previous version used
    // `serde_json::Number::to_string()`, which preserves the JSON source
    // literal's own spelling (`"1e-7"`) instead.
    let t = GatewayTest::new();
    assert_eq!(issue_ledger(&t, "req-reason-float", "same").status, 201);
    set_ledger_response(
        &t,
        "agent-1",
        "req-reason-float",
        serde_json::json!({
            "status": 200, "headers": [], "reason": 1e-7,
            "body_b64": "YWJj", "body_stored": true,
        }),
    );
    let replayed = issue_ledger(&t, "req-reason-float", "same");
    assert_eq!(replayed.reason.as_deref(), Some("1e-07"));
}

#[test]
fn replay_fails_closed_for_a_truthy_non_mapping_response() {
    // Finding F-R4-4(d): `response = entry.get("response") or {}` only
    // substitutes `{}` for a *falsy* stored value; a truthy non-mapping
    // (`"oops"`, `[1, 2]`, `7`) makes the very next `response.get(...)`
    // raise `AttributeError`, uncaught (confirmed against live
    // `python3.12`). The previous Rust `replay` used
    // `unwrap_or(json!({}))`, silently treating any non-object `response`
    // as empty and returning `502 replay_body_unavailable` instead of
    // refusing outright.
    let t = GatewayTest::new();
    for (label, bad_response) in [
        ("string", serde_json::json!("oops")),
        ("array", serde_json::json!([1, 2])),
        ("number", serde_json::json!(7)),
    ] {
        let request_id = format!("req-response-{label}");
        assert_eq!(issue_ledger(&t, &request_id, "same").status, 201);
        set_ledger_response(&t, "agent-1", &request_id, bad_response);
        let replayed = issue_ledger(&t, &request_id, "same");
        assert_eq!(
            (replayed.status.clone(), replayed.reason.as_deref()),
            (500.into(), Some("internal_error")),
            "a truthy non-mapping response ({label}) must fail closed, not relay a \
             502 replay_body_unavailable"
        );
    }
}

#[test]
fn replay_status_preserves_out_of_range_magnitudes_exactly() {
    // Finding X-5: Python's `int(v)` (`RequestLedger.replay`,
    // `status = int(response.get("status", 502))`) has no upper/lower
    // bound -- CPython's arbitrary-precision `int` never raises here, so
    // `relayed=True` for every case below. Derive every expected value by
    // passing the same JSON-decoded status through the real Python
    // `RequestLedger.replay`; in particular, `int(1e300)` reflects the exact
    // binary64 value and must not be replaced with a hand-written power of
    // ten.
    //
    // The previous fixed-width status path silently wrapped these into
    // small, plausible-looking values. `RelayResult::status` is now an
    // unbounded `PyInt`, preserving Python's exact integer through replay,
    // audit, and the tools response.
    let t = GatewayTest::new();
    let out_of_range: [(&str, serde_json::Value); 6] = [
        ("65736", serde_json::json!(65736)),
        ("65536", serde_json::json!(65536)),
        ("1000000", serde_json::json!(1_000_000)),
        ("1e300", serde_json::json!(1e300)),
        (
            "numeric_string_huge",
            serde_json::json!("18446744073709551816"),
        ),
        ("numeric_string_underscore", serde_json::json!(" 65736_0 ")),
    ];
    let oracle_input = serde_json::to_string(
        &out_of_range
            .iter()
            .map(|(_, status)| status)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let oracle_output = run_python_oracle_stdin(
        r#"import json, sys
from zeropw.gateway import RequestLedger
for status in json.load(sys.stdin):
    replayed = RequestLedger.replay({"response": {
        "status": status, "headers": [], "reason": None,
        "body_b64": "YWJj", "body_stored": True,
    }})
    print(json.dumps({
        "status": str(replayed.status),
        "headers": replayed.headers,
        "body_hex": replayed.body.hex(),
        "reason": replayed.reason,
    }, separators=(",", ":")))
"#,
        &oracle_input,
    );
    let oracle_results = oracle_output
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(oracle_results.len(), out_of_range.len());

    for ((label, status), oracle) in out_of_range.into_iter().zip(oracle_results) {
        let expected = oracle["status"].as_str().unwrap();
        assert_eq!(
            oracle["headers"],
            serde_json::json!([["X-ZeroPW-Replay", "true"]])
        );
        assert_eq!(oracle["body_hex"], "616263");
        assert_eq!(oracle["reason"], Value::Null);
        let request_id = format!("req-status-oor-{label}");
        assert_eq!(issue_ledger(&t, &request_id, "same").status, 201);
        set_ledger_response(
            &t,
            "agent-1",
            &request_id,
            serde_json::json!({
                "status": status, "headers": [], "reason": null,
                "body_b64": "YWJj", "body_stored": true,
            }),
        );
        let replayed = issue_ledger(&t, &request_id, "same");
        assert_eq!(replayed.status.to_string(), expected, "{label}");
        assert_eq!(replayed.reason, None, "{label}");
        assert_eq!(replayed.body, b"abc", "{label}");
        assert!(
            replayed
                .headers
                .iter()
                .any(|(name, value)| name == "X-ZeroPW-Replay" && value == "true"),
            "{label}: replay marker must be retained"
        );
        let expected_value: Value = serde_json::from_str(expected).unwrap();
        assert_eq!(
            t.audit_records().last().unwrap()["status"],
            expected_value,
            "{label}: replay audit must retain the exact status"
        );
        let body = serde_json::to_vec(&serde_json::json!({"title": "same"})).unwrap();
        let tool_result = zeropw::tools::request(
            &t.ctx,
            "agent-1",
            "gh",
            "POST",
            "/repos/demo/issues",
            &headers(&[("Content-Type", "application/json")]),
            &body,
            Some(&request_id),
        )
        .unwrap();
        assert_eq!(
            tool_result["status"], expected_value,
            "{label}: tools.request must retain the exact status"
        );
    }

    // In-range values (including the u16::MAX boundary) must still match
    // Python exactly -- this fix must not turn a VALID status into an
    // error.
    let in_range: [(&str, serde_json::Value, u16); 5] = [
        ("plain_200", serde_json::json!(200), 200),
        ("float_truncates", serde_json::json!(200.9), 200),
        ("bool_true", serde_json::json!(true), 1),
        ("numeric_string", serde_json::json!("404"), 404),
        ("u16_max_boundary", serde_json::json!(65535), 65535),
    ];
    for (label, status, expected) in in_range {
        let request_id = format!("req-status-ok-{label}");
        assert_eq!(issue_ledger(&t, &request_id, "same").status, 201);
        set_ledger_response(
            &t,
            "agent-1",
            &request_id,
            serde_json::json!({
                "status": status, "headers": [], "reason": null,
                "body_b64": "YWJj", "body_stored": true,
            }),
        );
        let replayed = issue_ledger(&t, &request_id, "same");
        assert_eq!(
            (replayed.status.clone(), replayed.reason.clone()),
            (expected.into(), None),
            "{label}: an in-range status must match python's int() exactly, not fail"
        );
    }
}

#[test]
fn same_id_different_request_is_rejected() {
    let t = GatewayTest::new();
    assert_eq!(issue_ledger(&t, "req-2", "same").status, 201);
    let reused = issue_ledger(&t, "req-2", "different");
    assert_eq!(
        (reused.status.clone(), reused.reason.as_deref()),
        (409.into(), Some("request_id_reused"))
    );
    assert_eq!(t.fake.requests().len(), 1);
    let other_path = t.relay_full("GET", "/repos", &no_headers(), b"", None, Some("req-2"));
    assert_eq!(other_path.reason.as_deref(), Some("request_id_reused"));
}

#[test]
fn uncertain_outcome_is_not_retried_blindly() {
    // finding F-14 (tests/test_gateway.py:797-807's
    // `test_uncertain_outcome_is_not_retried_blindly`): the previous version
    // of this test was a stub -- it issued one ledgered request and then
    // asserted nothing about the actual uncertain-outcome behaviour,
    // claiming `ctx.config` could not be mutated from this test helper. It
    // can: `Context::config` is a plain public field, and `upstream_timeout`
    // is genuinely mutable through a `mut` binding, exactly like
    // `upstream_down_and_timeout` above already does. Neither
    // "outcome_uncertain" nor "request_in_flight" appeared anywhere else in
    // this file before this fix.
    let mut t = GatewayTest::new();
    let first = issue_ledger(&t, "req-3", "same");
    assert_eq!(
        (first.status.clone(), first.reason.clone()),
        (201.into(), None)
    );
    t.ctx.config.upstream_timeout = 0.3;
    let timed_out = t.relay_full(
        "GET",
        "/slow?seconds=1",
        &no_headers(),
        b"",
        None,
        Some("slow-2"),
    );
    assert_eq!(timed_out.reason.as_deref(), Some("upstream_timeout"));
    let again = t.relay_full(
        "GET",
        "/slow?seconds=1",
        &no_headers(),
        b"",
        None,
        Some("slow-2"),
    );
    assert_eq!(
        (again.status.clone(), again.reason.as_deref()),
        (409.into(), Some("outcome_uncertain"))
    );
    assert_eq!(
        t.fake
            .requests()
            .iter()
            .filter(|r| r.path.starts_with("/slow"))
            .count(),
        1
    );
    std::thread::sleep(Duration::from_millis(800));
}

#[test]
fn in_flight_duplicate_is_rejected_then_replayed() {
    // finding F-14 (tests/test_gateway.py:718-749's
    // `test_in_flight_duplicate_is_rejected_then_replayed`): not ported at
    // all previously. A second thread races the first request under the
    // same request id while it is still in flight against `/slow`.
    let t = GatewayTest::new();
    let first_result: Mutex<Option<RelayResult>> = Mutex::new(None);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let r = t.relay_full(
                "GET",
                "/slow?seconds=0.8",
                &no_headers(),
                b"",
                None,
                Some("in-flight"),
            );
            *first_result.lock().unwrap() = Some(r);
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while t.fake.requests().is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let duplicate = t.relay_full(
            "GET",
            "/slow?seconds=0.8",
            &no_headers(),
            b"",
            None,
            Some("in-flight"),
        );
        assert_eq!(
            (duplicate.status.clone(), duplicate.reason.as_deref()),
            (409.into(), Some("request_in_flight"))
        );
    });
    let first = first_result.into_inner().unwrap().expect("worker ran");
    assert_eq!(first.status, 200);
    let replay = t.relay_full(
        "GET",
        "/slow?seconds=0.8",
        &no_headers(),
        b"",
        None,
        Some("in-flight"),
    );
    assert_eq!(
        (replay.status.clone(), replay.body.clone()),
        (200.into(), first.body)
    );
    assert_eq!(t.fake.requests().len(), 1);
}

#[test]
fn pre_transmission_failure_releases_claim() {
    let t = GatewayTest::new();
    t.ctx
        .vault
        .set_version_status("gh-token", &1.into(), "retired")
        .unwrap();
    let failed = issue_ledger(&t, "req-4", "same");
    assert_eq!(failed.reason.as_deref(), Some("credential_unavailable"));
    t.ctx
        .vault
        .set_version_status("gh-token", &1.into(), "active")
        .unwrap();
    assert_eq!(issue_ledger(&t, "req-4", "same").status, 201);
    let mut fake = FakeUpstream::new(SECRET_A);
    fake = fake.start();
    drop(fake); // nothing bound; simulate "unreachable" via a closed fake below
    let unreachable = FakeUpstream::new("x").start();
    let port = unreachable.port();
    drop(unreachable);
    t.ctx
        .policy
        .update_connection(
            "gh",
            ConnectionChanges::new().http_target(Some(
                HttpTarget::new("http", "127.0.0.1", port as i64, None, false).unwrap(),
            )),
        )
        .unwrap();
    let fresh = t.ctx.policy.regrant(&t.grant.id).unwrap();
    let handle = t.issue_handle_for("agent-1", "gh", &fresh.id, None, 300);
    let down = t.relay_full(
        "POST",
        "/repos/demo/issues",
        &headers(&[("Content-Type", "application/json")]),
        &serde_json::to_vec(&serde_json::json!({"title": "same"})).unwrap(),
        Some(&handle),
        Some("req-5"),
    );
    assert_eq!(down.reason.as_deref(), Some("upstream_unreachable"));
    let doc = t
        .ctx
        .state
        .read_json(gateway::LEDGER_DOC, serde_json::json!({}))
        .unwrap();
    assert!(
        !doc["agent-1"]
            .as_object()
            .map(|m| m.contains_key("req-5"))
            .unwrap_or(false)
    );
    assert!(
        doc["agent-1"]
            .as_object()
            .map(|m| m.contains_key("req-4"))
            .unwrap_or(false)
    );
}

#[test]
fn ledger_file_is_bounded_and_value_free() {
    let t = GatewayTest::new();
    for i in 0..3 {
        let result = t.relay_full(
            "GET",
            "/repos",
            &no_headers(),
            b"",
            None,
            Some(&format!("r{i}")),
        );
        assert_eq!(result.status, 200);
    }
    t.advance(gateway::LEDGER_TTL_SECONDS + 1.0);
    let durable = t
        .ctx
        .policy
        .create_grant("agent-1", "gh", None, None)
        .unwrap();
    let fresh_handle = t.issue_handle_for("agent-1", "gh", &durable.id, None, 300);
    let result = t.relay_full(
        "GET",
        "/me",
        &no_headers(),
        b"",
        Some(&fresh_handle),
        Some("r0"),
    );
    assert_eq!(result.status, 200);
    assert_eq!(t.fake.requests().len(), 4);
    let doc = t
        .ctx
        .state
        .read_json(gateway::LEDGER_DOC, serde_json::json!({}))
        .unwrap();
    let ids: std::collections::HashSet<String> = doc["agent-1"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(ids, std::collections::HashSet::from(["r0".to_string()]));
    t.assert_credential_free(&doc.to_string(), &[SECRET_A]);
}

#[test]
fn large_replay_body_is_not_stored() {
    // finding F-16(b) (tests/test_gateway.py:823-831's
    // `test_large_replay_body_is_not_stored`): Python shrinks
    // `LEDGER_MAX_STORED_BODY` to 16 bytes via monkeypatching; this port
    // instead uses `/large` (2 MiB), which is already above the real
    // `gateway::LEDGER_MAX_STORED_BODY` (1 MiB) and below the default
    // `max_response_bytes` (8 MiB), so no seam is needed at all.
    const _: () = assert!(zeropw::fake_upstream::LARGE_BODY_SIZE > gateway::LEDGER_MAX_STORED_BODY);
    let t = GatewayTest::new();
    let first = t.relay_full("GET", "/large", &no_headers(), b"", None, Some("big"));
    assert_eq!(first.status, 200);
    let replay = t.relay_full("GET", "/large", &no_headers(), b"", None, Some("big"));
    assert_eq!(
        (replay.status.clone(), replay.reason.as_deref()),
        (200.into(), Some("replay_body_unavailable"))
    );
    assert_eq!(
        replay.json().expect("test body is valid utf-8 JSON")["reason"],
        "replay_body_unavailable"
    );
    assert_eq!(t.fake.requests().len(), 1);
}

// -------------------------------------------------------------------- pure

#[test]
fn space_in_password_covers_plus_and_percent20_forms() {
    let secret = b"synthetic pass word/+=";
    let patterns = gateway::credential_patterns(secret, Some("synthetic-user"));
    use base64::Engine as _;
    let plus_upper = b"synthetic+pass+word%2F%2B%3D".to_vec();
    let plus_lower = b"synthetic+pass+word%2f%2b%3d".to_vec();
    let pct_upper = b"synthetic%20pass%20word%2F%2B%3D".to_vec();
    let pct_lower = b"synthetic%20pass%20word%2f%2b%3d".to_vec();
    let basic = {
        let mut pair = b"synthetic-user:".to_vec();
        pair.extend_from_slice(secret);
        base64::engine::general_purpose::STANDARD
            .encode(&pair)
            .trim_end_matches('=')
            .as_bytes()
            .to_vec()
    };
    for form in [
        secret.to_vec(),
        plus_upper,
        plus_lower,
        pct_upper,
        pct_lower,
        basic,
    ] {
        assert!(
            patterns.contains(&form),
            "{:?}",
            String::from_utf8_lossy(&form)
        );
        let mut blob = b"prefix ".to_vec();
        blob.extend_from_slice(&form);
        blob.extend_from_slice(b" suffix");
        assert!(gateway::contains_credential(&blob, &patterns));
    }
}

#[test]
fn base64_patterns_find_the_credential_at_any_offset() {
    use base64::Engine as _;
    for secret in [
        SECRET_A.as_bytes().to_vec(),
        SECRET_ENCODINGS.as_bytes().to_vec(),
        b"synthetic\x00\xff\xfe-binary-credential".to_vec(),
    ] {
        for username in [None, Some("synthetic-user")] {
            let patterns = gateway::credential_patterns(&secret, username);
            let mut values = vec![secret.clone()];
            if let Some(u) = username {
                let mut v = u.as_bytes().to_vec();
                v.push(b':');
                v.extend_from_slice(&secret);
                values.push(v);
            }
            for value in &values {
                let encoded = base64::engine::general_purpose::STANDARD.encode(value);
                let mut blob = b"{\"content\":\"".to_vec();
                blob.extend_from_slice(encoded.as_bytes());
                blob.extend_from_slice(b"\"}");
                assert!(gateway::contains_credential(&blob, &patterns));
                assert!(gateway::contains_credential(
                    encoded.trim_end_matches('=').as_bytes(),
                    &patterns
                ));
                let wrapped: Vec<u8> = encoded
                    .as_bytes()
                    .chunks(16)
                    .map(|c| c.to_vec())
                    .collect::<Vec<_>>()
                    .join(&b"\\n"[..]);
                let mut blob2 = b"{\"content\":\"".to_vec();
                blob2.extend_from_slice(&wrapped);
                blob2.extend_from_slice(b"\"}");
                assert!(gateway::contains_credential(&blob2, &patterns));
            }
        }
    }
    assert!(gateway::base64_cores(b"abc").is_empty());
    for core in gateway::base64_cores(b"synthetic-token") {
        assert!(core.len() >= gateway::MIN_ALIGNED_PATTERN_LENGTH);
    }
}

#[test]
fn letters_of_the_credential_keep_their_case() {
    let secret = b"Synthetic/TOKEN";
    let patterns = gateway::credential_patterns(secret, None);
    assert!(patterns.contains(&b"Synthetic%2fTOKEN".to_vec()));
    assert!(!patterns.contains(&b"synthetic%2ftoken".to_vec()));
    assert!(patterns.contains(&hex::encode(secret).to_uppercase().into_bytes()));
    assert!(!gateway::contains_credential(
        b"an ordinary business response",
        &patterns
    ));
}

// ------------------------------------------------------------ resolved address

type AddressExpectation = (&'static str, (Option<&'static str>, Option<&'static str>));

#[test]
fn address_classes() {
    let table: &[AddressExpectation] = &[
        ("8.8.8.8", (None, None)),
        ("2606:4700:4700::1111", (None, None)),
        ("127.0.0.1", (Some("target_address_not_allowed"), None)),
        ("10.1.2.3", (Some("target_address_not_allowed"), None)),
        (
            "169.254.169.254",
            (
                Some("metadata_address_not_allowed"),
                Some("metadata_address_not_allowed"),
            ),
        ),
        ("::1", (Some("target_address_not_allowed"), None)),
        (
            "fe80::1",
            (
                Some("metadata_address_not_allowed"),
                Some("metadata_address_not_allowed"),
            ),
        ),
        (
            "64:ff9b::127.0.0.1",
            (Some("target_address_not_allowed"), None),
        ),
        ("64:ff9b::8.8.8.8", (None, None)),
        (
            "2002:a9fe:a9fe::1",
            (
                Some("metadata_address_not_allowed"),
                Some("metadata_address_not_allowed"),
            ),
        ),
    ];
    for (text, (public_only, private_allowed)) in table {
        let addr: IpAddr = text.parse().unwrap();
        assert_eq!(P::address_block_reason(addr, false), *public_only, "{text}");
        assert_eq!(
            P::address_block_reason(addr, true),
            *private_allowed,
            "{text}"
        );
    }
    for literal in ["169.254.169.254", "fe80::1"] {
        let err = HttpTarget::new("http", literal, 80, None, false).unwrap_err();
        assert_eq!(err.reason, "metadata_address_not_allowed");
    }
}

fn named_connection(t: &GatewayTest, cid: &str, host: &str, allow_private: bool) -> String {
    named_connection_port(t, cid, host, t.fake.port(), allow_private)
}

fn named_connection_port(
    t: &GatewayTest,
    cid: &str,
    host: &str,
    port: u16,
    allow_private: bool,
) -> String {
    t.ctx
        .policy
        .create_connection(
            Connection::new(
                cid,
                "demo",
                "dev",
                "named",
                "http",
                "gh-token",
                None,
                "",
                Some(HttpTarget::new("http", host, port as i64, None, allow_private).unwrap()),
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
    let grant = t
        .ctx
        .policy
        .create_grant("agent-1", cid, Some(3600), None)
        .unwrap();
    t.issue_handle_for("agent-1", cid, &grant.id, None, 300)
}

fn resolver_answering(addresses: Vec<IpAddr>) -> gateway::Resolver {
    Arc::new(move |_host, _port| Ok(addresses.clone()))
}

/// A connection pointed at a raw `127.0.0.1` port, with a caller-chosen
/// secret/auth mode -- for the equivalence-review round-1 fixes below (F-1
/// through F-12), which need hand-written raw HTTP responses a real
/// `FakeUpstream` fixture can't produce (a malformed status line, a `100
/// Continue` interim response, duplicate headers, ...). This is the same
/// "drive a scratch listener with hand-written bytes" pattern the review
/// itself used to find these findings.
fn raw_port_connection(
    t: &GatewayTest,
    cid: &str,
    secret_id: &str,
    auth: HttpAuth,
    port: u16,
) -> String {
    t.ctx
        .policy
        .create_connection(
            Connection::new(
                cid,
                "demo",
                "dev",
                "raw",
                "http",
                secret_id,
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
            .unwrap(),
        )
        .unwrap();
    let grant = t
        .ctx
        .policy
        .create_grant("agent-1", cid, Some(3600), None)
        .unwrap();
    t.issue_handle_for("agent-1", cid, &grant.id, None, 300)
}

/// Spawns a background thread that accepts exactly one connection, discards
/// whatever the client sends, and writes `response` back verbatim before
/// closing (signalling EOF once the whole response has been sent, which is
/// what makes an `UntilClose`-framed body terminate). Returns the bound
/// port.
fn raw_response_port(response: Vec<u8>) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .ok();
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(&response);
            let _ = stream.flush();
        }
    });
    port
}

/// Relays a `GET /me` through `gh`'s bearer credential to a scratch listener
/// that answers with the given raw response bytes.
fn relay_via_raw_response(t: &GatewayTest, cid: &str, response: Vec<u8>) -> RelayResult {
    let port = raw_response_port(response);
    let handle = raw_port_connection(t, cid, "gh-token", HttpAuth::bearer(), port);
    gateway::relay(&t.ctx, &handle, "GET", "/me", &no_headers(), b"", None)
}

#[test]
fn hostname_resolving_to_loopback_is_refused_without_opt_in() {
    let t = GatewayTest::new();
    let handle = named_connection(&t, "named", "upstream.zeropw.test", false);
    let resolver = resolver_answering(vec!["127.0.0.1".parse().unwrap()]);
    let result = gateway::relay_with_resolver(
        &t.ctx,
        &handle,
        "GET",
        "/me",
        &no_headers(),
        b"",
        None,
        resolver,
    );
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (403.into(), Some("target_address_not_allowed"))
    );
    assert_eq!(t.fake.requests().len(), 0);
    t.assert_result_credential_free(&result);
    let alerts = t.ctx.audit.alerts(1000).unwrap();
    assert!(alerts.iter().any(|a| a["alert"] == "credential_exposure"));
}

#[test]
fn mixed_answer_is_refused_as_a_whole() {
    let t = GatewayTest::new();
    let handle = named_connection(&t, "mixed", "upstream.zeropw.test", false);
    let resolver = resolver_answering(vec![
        "8.8.8.8".parse().unwrap(),
        "127.0.0.1".parse().unwrap(),
    ]);
    let result = gateway::relay_with_resolver(
        &t.ctx,
        &handle,
        "GET",
        "/me",
        &no_headers(),
        b"",
        None,
        resolver,
    );
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (403.into(), Some("target_address_not_allowed"))
    );
    assert_eq!(t.fake.requests().len(), 0);
}

#[test]
fn metadata_answer_is_refused_even_for_private_opt_in() {
    // finding F-17 (tests/test_gateway.py:1504-1513's
    // `test_metadata_answer_is_refused_even_for_private_opt_in`): not
    // ported at all previously.
    let t = GatewayTest::new();
    let handle = named_connection(&t, "meta", "upstream.zeropw.test", true);
    for answer in [
        "169.254.169.254",
        "fd00:ec2::254",
        "::ffff:169.254.169.254",
        "fd00:ec2::23",
        "fd20:ce::254",
        "fd00:c1::a9fe:a9fe",
        "64:ff9b::169.254.169.254",
        "::169.254.169.254",
        "168.63.129.16",
    ] {
        let resolver = resolver_answering(vec![answer.parse().unwrap()]);
        let result = gateway::relay_with_resolver(
            &t.ctx,
            &handle,
            "GET",
            "/me",
            &no_headers(),
            b"",
            None,
            resolver,
        );
        assert_eq!(
            (result.status.clone(), result.reason.as_deref()),
            (403.into(), Some("metadata_address_not_allowed")),
            "answer={answer}"
        );
    }
    assert_eq!(t.fake.requests().len(), 0);
}

#[test]
fn ipv4_embedded_in_ipv6_answers_are_judged_by_the_ipv4_address() {
    // finding F-17 (tests/test_gateway.py:1514-1525's
    // `test_ipv4_embedded_in_ipv6_answers_is_judged_by_the_ipv4_address`):
    // not ported at all previously. Python additionally asserts nothing was
    // *dialed* via a `socket.create_connection` patch; this port uses the
    // same proxy every other resolver test in this file already uses for
    // "never reached upstream" -- the fake upstream's own request count.
    let t = GatewayTest::new();
    let handle = named_connection(&t, "nat64", "upstream.zeropw.test", false);
    for answer in [
        "64:ff9b::10.0.0.1",
        "64:ff9b::127.0.0.1",
        "::10.0.0.1",
        "::ffff:0:10.0.0.1",
        "fec0::1",
    ] {
        let resolver = resolver_answering(vec![answer.parse().unwrap()]);
        let result = gateway::relay_with_resolver(
            &t.ctx,
            &handle,
            "GET",
            "/me",
            &no_headers(),
            b"",
            None,
            resolver,
        );
        assert_eq!(
            (result.status.clone(), result.reason.as_deref()),
            (403.into(), Some("target_address_not_allowed")),
            "answer={answer}"
        );
    }
    assert_eq!(t.fake.requests().len(), 0);
}

#[test]
fn address_refusal_spends_no_grant_use_approval_or_credential() {
    // finding F-17 (tests/test_gateway.py:1526-1560's
    // `test_address_refusal_spends_no_use_approval_or_credential`). Python
    // resolves to a genuinely public address (`8.8.8.8`) and patches
    // `socket.create_connection` (`dial_recorder(deliver_to_fake=True)`) to
    // redirect the actual TCP dial to the local fake upstream -- there is
    // no Rust seam for that (only DNS resolution is injectable via
    // `gateway::Resolver`, per the `gateway`/`_getaddrinfo` row in
    // `DEVIATIONS.md`). This port instead uses an
    // `allow_private_network=true` connection: a loopback answer is
    // allowed and really reaches the fake upstream (the same pattern
    // `opt_in_connects_to_the_checked_address_and_resolves_once_per_request`
    // above already relies on), while a *metadata* answer is refused
    // regardless of that opt-in -- exercising the same "a refused DNS
    // answer spends nothing" property through the public resolver seam
    // alone, without needing to mock `Vault::secret_for_trusted_use`
    // either: the vault is never reached as long as no upstream request
    // ever left (`t.fake.requests()` stays empty) and the grant's use
    // counter/approval status never move.
    let t = GatewayTest::new();
    t.ctx
        .policy
        .create_connection(
            Connection::new(
                "capped",
                "demo",
                "dev",
                "named",
                "http",
                "gh-token",
                None,
                "test connection",
                Some(
                    HttpTarget::new(
                        "http",
                        "upstream.zeropw.test",
                        t.fake.port() as i64,
                        None,
                        true,
                    )
                    .unwrap(),
                ),
                Some(HttpAuth::bearer()),
                Some(HttpScope::new(None, None, vec!["DELETE".to_string()]).unwrap()),
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
    let grant = t
        .ctx
        .policy
        .create_grant("agent-1", "capped", Some(3600), Some(2))
        .unwrap();
    let handle = t.issue_handle_for("agent-1", "capped", &grant.id, None, 300);

    let allowed = resolver_answering(vec!["127.0.0.1".parse().unwrap()]);
    let pending = gateway::relay_with_resolver(
        &t.ctx,
        &handle,
        "DELETE",
        "/repos/demo",
        &no_headers(),
        b"",
        None,
        allowed,
    );
    assert_eq!(
        (pending.status.clone(), pending.reason.as_deref()),
        (428.into(), Some("approval_required"))
    );
    let digest = pending.json().expect("test body is valid utf-8 JSON")["approval_digest"]
        .as_str()
        .unwrap()
        .to_string();
    t.ctx.policy.approve(&digest).unwrap();

    // A metadata answer is refused regardless of the opt-in, for every
    // method -- and never spends the approval or a grant use.
    let refused = resolver_answering(vec!["169.254.169.254".parse().unwrap()]);
    for (method, path) in [("GET", "/me"), ("GET", "/repos"), ("DELETE", "/repos/demo")] {
        let result = gateway::relay_with_resolver(
            &t.ctx,
            &handle,
            method,
            path,
            &no_headers(),
            b"",
            None,
            refused.clone(),
        );
        assert_eq!(
            (result.status.clone(), result.reason.as_deref()),
            (403.into(), Some("metadata_address_not_allowed")),
            "{method} {path}"
        );
    }
    assert_eq!(t.fake.requests().len(), 0);
    assert_eq!(t.ctx.policy.get_grant(&grant.id).unwrap().uses, 0);
    let approvals = t.ctx.policy.list_approvals().unwrap();
    assert_eq!(approvals[&digest]["status"], "approved");
    assert!(
        !t.audit_records()
            .iter()
            .any(|r| r["connection"] == "capped" && r["result"] == "attempt")
    );

    // Once DNS points back at the checked upstream, the approval and both uses are still there.
    let allowed_again = resolver_answering(vec!["127.0.0.1".parse().unwrap()]);
    let done = gateway::relay_with_resolver(
        &t.ctx,
        &handle,
        "DELETE",
        "/repos/demo",
        &no_headers(),
        b"",
        None,
        allowed_again.clone(),
    );
    assert_eq!(done.status, 204);
    let me = gateway::relay_with_resolver(
        &t.ctx,
        &handle,
        "GET",
        "/me",
        &no_headers(),
        b"",
        None,
        allowed_again,
    );
    assert_eq!(me.status, 200);
    assert_eq!(t.fake.requests().len(), 2);
    assert_eq!(t.ctx.policy.get_grant(&grant.id).unwrap().uses, 2);
}

#[test]
fn stored_metadata_literal_loads_and_is_refused_at_use() {
    // finding F-17 (tests/test_gateway.py:1577-1610's
    // `test_stored_metadata_literal_loads_and_is_refused_at_use`): not
    // ported at all previously. Dropping only the `tools.list_connections`
    // assertion (`tools` is out of this half's scope).
    let t = GatewayTest::new();
    let _handle = named_connection(&t, "old-meta", "upstream.zeropw.test", false);

    // Simulate a record saved before this literal became forbidden: there
    // is no public API to create an already-forbidden literal directly
    // (`HttpTarget::new`/`create_connection` always check it eagerly), so
    // hand-edit the stored `connections.json`, the same technique Python's
    // test uses (`json.loads(path.read_text())`).
    let path = t.ctx.state.path.join(P::CONNECTIONS);
    let text = std::fs::read_to_string(&path).unwrap();
    let mut doc: Value = serde_json::from_str(&text).unwrap();
    doc["old-meta"]["http_target"]["host"] = serde_json::json!("169.254.169.254");
    doc["old-meta"]["http_target"]
        .as_object_mut()
        .unwrap()
        .remove("allow_private_network");
    std::fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();

    let grant = t
        .ctx
        .policy
        .list_grants(Some("agent-1"))
        .unwrap()
        .into_iter()
        .find(|g| g.connection == "old-meta")
        .unwrap();

    assert_eq!(
        t.ctx
            .policy
            .get_connection("old-meta")
            .unwrap()
            .http_target
            .unwrap()
            .host,
        "169.254.169.254"
    );
    assert!(
        t.ctx
            .policy
            .list_connections()
            .unwrap()
            .iter()
            .any(|c| c.id == "old-meta")
    );
    let result = gateway::relay_for_caller(
        &t.ctx,
        "agent-1",
        "old-meta",
        "GET",
        "/me",
        &no_headers(),
        b"",
        None,
    );
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (403.into(), Some("metadata_address_not_allowed"))
    );
    let record = t.audit_records().last().unwrap().clone();
    assert_eq!(record["connection"], "old-meta");
    assert_eq!(record["reason"], "metadata_address_not_allowed");
    assert_eq!(t.ctx.policy.get_grant(&grant.id).unwrap().uses, 0);
    assert_eq!(t.fake.requests().len(), 0);
    let disabled = t.ctx.policy.disable_connection("old-meta").unwrap();
    assert_eq!(disabled.status, "disabled");
    // New input is still checked strictly, also when it bypasses the constructor check.
    let lenient = HttpTarget::from_stored("http", "fd20:ce::254", 80, None, false).unwrap();
    let err = t
        .ctx
        .policy
        .update_connection(
            "old-meta",
            ConnectionChanges::new().http_target(Some(lenient.clone())),
        )
        .unwrap_err();
    assert_eq!(err.reason, "metadata_address_not_allowed");
    let stored = t.ctx.policy.get_connection("old-meta").unwrap();
    let mut new_conn = stored.clone();
    new_conn.id = "new-meta".to_string();
    new_conn.http_target = Some(lenient);
    let err2 = t.ctx.policy.create_connection(new_conn).unwrap_err();
    assert_eq!(err2.reason, "metadata_address_not_allowed");
}

#[test]
fn opt_in_connects_to_the_checked_address_and_resolves_once_per_request() {
    let t = GatewayTest::new();
    let handle = named_connection(&t, "internal", "upstream.zeropw.test", true);
    let calls = Arc::new(AtomicI64::new(0));
    let calls2 = calls.clone();
    let resolver: gateway::Resolver = Arc::new(move |_h, _p| {
        calls2.fetch_add(1, Ordering::SeqCst);
        Ok(vec!["127.0.0.1".parse().unwrap()])
    });
    let first = gateway::relay_with_resolver(
        &t.ctx,
        &handle,
        "GET",
        "/me",
        &no_headers(),
        b"",
        None,
        resolver.clone(),
    );
    let second = gateway::relay_with_resolver(
        &t.ctx,
        &handle,
        "GET",
        "/repos",
        &no_headers(),
        b"",
        None,
        resolver,
    );
    assert_eq!(
        (first.status.clone(), second.status),
        (200.into(), 200.into())
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        t.fake
            .requests()
            .last()
            .unwrap()
            .headers
            .get("host")
            .unwrap(),
        &format!("upstream.zeropw.test:{}", t.fake.port())
    );
    assert_eq!(
        t.fake
            .requests()
            .last()
            .unwrap()
            .headers
            .get("authorization")
            .unwrap(),
        &format!("Bearer {SECRET_A}")
    );
}

#[test]
fn resolution_failure_is_explicit() {
    let t = GatewayTest::new();
    let handle = named_connection(&t, "nxdomain", "upstream.zeropw.test", true);
    let resolver: gateway::Resolver = Arc::new(|_h, _p| Err(std::io::Error::other("no such name")));
    let result = gateway::relay_with_resolver(
        &t.ctx,
        &handle,
        "GET",
        "/me",
        &no_headers(),
        b"",
        None,
        resolver,
    );
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (502.into(), Some("upstream_unreachable"))
    );
    t.assert_result_credential_free(&result);
}

#[test]
fn dns_change_between_requests_takes_effect_on_the_next_request() {
    // finding F-17 (tests/test_gateway.py:1611-1621's
    // `test_dns_change_between_requests_takes_effect_on_the_next_request`):
    // not ported at all previously.
    let t = GatewayTest::new();
    let handle = named_connection(&t, "rebind", "upstream.zeropw.test", true);
    let good = resolver_answering(vec!["127.0.0.1".parse().unwrap()]);
    let first = gateway::relay_with_resolver(
        &t.ctx,
        &handle,
        "GET",
        "/me",
        &no_headers(),
        b"",
        None,
        good,
    );
    assert_eq!(first.status, 200);
    let rebound = resolver_answering(vec!["169.254.169.254".parse().unwrap()]);
    let result = gateway::relay_with_resolver(
        &t.ctx,
        &handle,
        "GET",
        "/me",
        &no_headers(),
        b"",
        None,
        rebound,
    );
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (403.into(), Some("metadata_address_not_allowed"))
    );
    assert_eq!(t.fake.requests().len(), 1);
}

#[test]
fn private_network_opt_in_is_a_widening_change() {
    // finding F-17 (tests/test_gateway.py:1633-1643's
    // `test_private_network_opt_in_is_a_widening_change`): not ported at
    // all previously -- `policy.rs`'s `allow_private_network` widening rule
    // had no test coverage anywhere in this crate.
    let t = GatewayTest::new();
    named_connection(&t, "widen", "upstream.zeropw.test", false);
    let before = t.ctx.policy.get_connection("widen").unwrap();
    let bt = before.http_target.clone().unwrap();
    let target = HttpTarget::new(bt.scheme.clone(), bt.host.clone(), bt.port, None, true).unwrap();
    let (_, widened) = t
        .ctx
        .policy
        .update_connection(
            "widen",
            ConnectionChanges::new().http_target(Some(target.clone())),
        )
        .unwrap();
    assert!(widened);
    let narrowed = HttpTarget::new(
        target.scheme.clone(),
        target.host.clone(),
        target.port,
        None,
        false,
    )
    .unwrap();
    let (_, widened_again) = t
        .ctx
        .policy
        .update_connection(
            "widen",
            ConnectionChanges::new().http_target(Some(narrowed)),
        )
        .unwrap();
    assert!(!widened_again);
}

// ----------------------------------------------------------- self-reference

#[test]
fn self_reference_via_registered_listener() {
    let t = GatewayTest::new();
    let listener = Arc::new(TcpListener::bind(("127.0.0.1", 0)).unwrap());
    let port = listener.local_addr().unwrap().port();
    gateway::register_local_listener(&listener);
    assert!(gateway::listener_addresses().contains(&(IpAddr::from([127, 0, 0, 1]), port)));

    // Never accept: a self-referential relay must be refused before any
    // bytes reach this listener (the literal-host check alone catches a
    // direct 127.0.0.1 target -- see `self_referential_target`).
    let _handle = named_connection_port(&t, "self", "127.0.0.1", port, false);
    let result = gateway::relay_for_caller(
        &t.ctx,
        "agent-1",
        "self",
        "GET",
        "/me",
        &no_headers(),
        b"",
        None,
    );
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (501.into(), Some("self_referential_target"))
    );

    gateway::unregister_local_listener(&listener);
    assert!(!gateway::listener_addresses().contains(&(IpAddr::from([127, 0, 0, 1]), port)));
}

#[test]
fn peer_check_catches_a_dns_resolved_self_reference() {
    // A hostname (not a literal) resolving to a registered listener's
    // address bypasses the cheap literal check in `self_referential_target`
    // (it only special-cases "localhost") entirely, so this exercises the
    // *post-connect* `_peer_is_local_listener` defense-in-depth check
    // instead -- without needing to monkeypatch `_self_referential_target`
    // the way the Python test does (not portable: no process-global mutable
    // seam under Rust's parallel test runner).
    let t = GatewayTest::new();
    let listener = Arc::new(TcpListener::bind(("127.0.0.1", 0)).unwrap());
    let port = listener.local_addr().unwrap().port();
    gateway::register_local_listener(&listener);
    // Accept in the background so the relay's connect doesn't hang forever
    // if the self-reference check were ever to regress.
    let listener_clone = listener.clone();
    std::thread::spawn(move || {
        let _ = listener_clone.accept();
    });

    let handle = named_connection_port(&t, "alias", "upstream.zeropw.test", port, true);
    let resolver = resolver_answering(vec!["127.0.0.1".parse().unwrap()]);
    let result = gateway::relay_with_resolver(
        &t.ctx,
        &handle,
        "GET",
        "/healthz",
        &no_headers(),
        b"",
        None,
        resolver,
    );
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (501.into(), Some("self_referential_target"))
    );
    gateway::unregister_local_listener(&listener);
}

#[test]
fn dropped_listener_is_forgotten_without_explicit_unregister() {
    // finding F-16(d) (tests/test_gateway.py:1116-1123's
    // `test_closed_listener_is_forgotten`): the existing tests in this file
    // only ever call `unregister_local_listener` explicitly. Python's
    // registry is a `weakref.WeakSet`, so a listener that is simply garbage
    // collected (closed) without ever being explicitly unregistered still
    // disappears; the Rust equivalent (`LOCAL_LISTENERS: Vec<Weak<TcpListener>>`)
    // must forget it the same way once the last `Arc` is dropped.
    let listener = Arc::new(TcpListener::bind(("127.0.0.1", 0)).unwrap());
    let port = listener.local_addr().unwrap().port();
    gateway::register_local_listener(&listener);
    assert!(gateway::listener_addresses().contains(&(IpAddr::from([127, 0, 0, 1]), port)));
    drop(listener); // no `unregister_local_listener` call.
    assert!(!gateway::listener_addresses().contains(&(IpAddr::from([127, 0, 0, 1]), port)));
}

// --------------------------------------------------------------------- TLS

fn self_signed(hosts: Vec<String>) -> (rcgen::Certificate, rcgen::KeyPair) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(hosts).expect("self sign");
    (cert, key_pair)
}

fn tls_server_config(cert: &rcgen::Certificate, key: &rcgen::KeyPair) -> Arc<rustls::ServerConfig> {
    let cert_der = rustls_pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
        rustls_pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
    );
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server config");
    Arc::new(config)
}

fn write_pem(dir: &TempDir, name: &str, pem: &str) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, pem).unwrap();
    path.to_str().unwrap().to_string()
}

#[test]
fn https_with_pinned_ca_succeeds_and_untrusted_or_wrong_name_fails() {
    let t = GatewayTest::new();
    t.ctx
        .vault
        .put_secret(
            "tls-token",
            "api_key",
            SECRET_B.as_bytes(),
            "demo",
            "dev",
            true,
        )
        .unwrap();
    let (cert, key) = self_signed(vec!["127.0.0.1".to_string()]);
    let cert_pem = cert.pem();
    let good = FakeUpstream::new(SECRET_B)
        .tls(tls_server_config(&cert, &key))
        .start();
    assert!(good.url().starts_with("https://"));

    let cert_path = write_pem(&t._tmp, "good.pem", &cert_pem);

    let trusted_conn = http_connection_ca(
        "tls-good",
        &good,
        "tls-token",
        HttpAuth::bearer(),
        HttpScope::new(None, None, vec![]).unwrap(),
        Some(cert_path.clone()),
    );
    t.ctx.policy.create_connection(trusted_conn).unwrap();
    let grant = t
        .ctx
        .policy
        .create_grant("agent-1", "tls-good", Some(3600), None)
        .unwrap();
    let handle = t.issue_handle_for("agent-1", "tls-good", &grant.id, None, 300);
    let trusted = t.relay_full("GET", "/me", &no_headers(), b"", Some(&handle), None);
    assert_eq!(
        (
            trusted.status.clone(),
            trusted.json().expect("test body is valid utf-8 JSON")
        ),
        (200.into(), serde_json::json!({"login": "synthetic-user"}))
    );
    assert_eq!(
        good.requests()
            .last()
            .unwrap()
            .headers
            .get("authorization")
            .unwrap(),
        &format!("Bearer {SECRET_B}")
    );

    let untrusted_conn = http_connection(
        "tls-untrusted",
        &good,
        "tls-token",
        HttpAuth::bearer(),
        HttpScope::new(None, None, vec![]).unwrap(),
    );
    t.ctx.policy.create_connection(untrusted_conn).unwrap();
    let grant = t
        .ctx
        .policy
        .create_grant("agent-1", "tls-untrusted", Some(3600), None)
        .unwrap();
    let handle = t.issue_handle_for("agent-1", "tls-untrusted", &grant.id, None, 300);
    let untrusted = t.relay_full("GET", "/me", &no_headers(), b"", Some(&handle), None);
    assert_eq!(
        (untrusted.status.clone(), untrusted.reason.as_deref()),
        (502.into(), Some("upstream_tls_failed"))
    );
    t.assert_result_credential_free(&untrusted);
    assert_eq!(good.requests().len(), 1);

    let (other_cert, other_key) = self_signed(vec!["other.invalid".to_string()]);
    let wrong_name = FakeUpstream::new(SECRET_B)
        .tls(tls_server_config(&other_cert, &other_key))
        .start();
    let other_cert_path = write_pem(&t._tmp, "other.pem", &other_cert.pem());
    let mismatch_conn = http_connection_ca(
        "tls-mismatch",
        &wrong_name,
        "tls-token",
        HttpAuth::bearer(),
        HttpScope::new(None, None, vec![]).unwrap(),
        Some(other_cert_path),
    );
    t.ctx.policy.create_connection(mismatch_conn).unwrap();
    let grant = t
        .ctx
        .policy
        .create_grant("agent-1", "tls-mismatch", Some(3600), None)
        .unwrap();
    let handle = t.issue_handle_for("agent-1", "tls-mismatch", &grant.id, None, 300);
    let mismatch = t.relay_full("GET", "/me", &no_headers(), b"", Some(&handle), None);
    assert_eq!(
        (mismatch.status.clone(), mismatch.reason.as_deref()),
        (502.into(), Some("upstream_tls_failed"))
    );
    assert_eq!(wrong_name.requests().len(), 0);
    assert_eq!(t.audit_records().last().unwrap()["result"], "error");
    t.assert_credential_free(&t.state_text(&["audit/audit.jsonl"]), &[SECRET_A, SECRET_B]);

    let missing_conn = http_connection_ca(
        "tls-missing-ca",
        &good,
        "tls-token",
        HttpAuth::bearer(),
        HttpScope::new(None, None, vec![]).unwrap(),
        Some(format!("{cert_path}.missing")),
    );
    t.ctx.policy.create_connection(missing_conn).unwrap();
    let grant = t
        .ctx
        .policy
        .create_grant("agent-1", "tls-missing-ca", Some(3600), None)
        .unwrap();
    let handle = t.issue_handle_for("agent-1", "tls-missing-ca", &grant.id, None, 300);
    let missing = t.relay_full("GET", "/me", &no_headers(), b"", Some(&handle), None);
    assert_eq!(
        (missing.status.clone(), missing.reason.as_deref()),
        (502.into(), Some("ca_file_unavailable"))
    );
}

/// OpenSSL's legacy Common Name fallback is DNS-only.  A CN spelling an IP
/// address does not satisfy IP identity verification when SAN is absent.
#[test]
fn tls_cert_with_ip_cn_but_no_san_is_rejected() {
    let t = GatewayTest::new();
    t.ctx
        .vault
        .put_secret(
            "tls-token",
            "api_key",
            SECRET_B.as_bytes(),
            "demo",
            "dev",
            true,
        )
        .unwrap();

    let key = rcgen::KeyPair::generate().expect("keypair");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("no SANs");
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "127.0.0.1");
    let cert = params.self_signed(&key).expect("self sign");
    let cert_pem = cert.pem();

    let good = FakeUpstream::new(SECRET_B)
        .tls(tls_server_config(&cert, &key))
        .start();
    let cert_path = write_pem(&t._tmp, "cn-only.pem", &cert_pem);

    let conn = http_connection_ca(
        "tls-cn-only",
        &good,
        "tls-token",
        HttpAuth::bearer(),
        HttpScope::new(None, None, vec![]).unwrap(),
        Some(cert_path),
    );
    t.ctx.policy.create_connection(conn).unwrap();
    let grant = t
        .ctx
        .policy
        .create_grant("agent-1", "tls-cn-only", Some(3600), None)
        .unwrap();
    let handle = t.issue_handle_for("agent-1", "tls-cn-only", &grant.id, None, 300);
    let result = t.relay_full("GET", "/me", &no_headers(), b"", Some(&handle), None);
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (502.into(), Some("upstream_tls_failed"))
    );
    assert!(good.requests().is_empty());
}

#[test]
fn tls_is_verified_against_the_configured_name_not_the_pinned_address() {
    let t = GatewayTest::new();
    t.ctx
        .vault
        .put_secret(
            "tls-named",
            "api_key",
            SECRET_B.as_bytes(),
            "demo",
            "dev",
            true,
        )
        .unwrap();
    let (cert, key) = self_signed(vec!["upstream.zeropw.test".to_string()]);
    let fake = FakeUpstream::new(SECRET_B)
        .tls(tls_server_config(&cert, &key))
        .start();
    let cert_path = write_pem(&t._tmp, "named.pem", &cert.pem());

    let good = Connection::new(
        "tls-good",
        "demo",
        "dev",
        "named",
        "http",
        "tls-named",
        None,
        "",
        Some(
            HttpTarget::new(
                "https",
                "upstream.zeropw.test",
                fake.port() as i64,
                Some(cert_path.clone()),
                true,
            )
            .unwrap(),
        ),
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
    let wrong = Connection::new(
        "tls-wrong",
        "demo",
        "dev",
        "named",
        "http",
        "tls-named",
        None,
        "",
        Some(
            HttpTarget::new(
                "https",
                "other.zeropw.test",
                fake.port() as i64,
                Some(cert_path),
                true,
            )
            .unwrap(),
        ),
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
    t.ctx.policy.create_connection(good).unwrap();
    t.ctx.policy.create_connection(wrong).unwrap();
    let grant_good = t
        .ctx
        .policy
        .create_grant("agent-1", "tls-good", Some(3600), None)
        .unwrap();
    let grant_wrong = t
        .ctx
        .policy
        .create_grant("agent-1", "tls-wrong", Some(3600), None)
        .unwrap();
    let handle_good = t.issue_handle_for("agent-1", "tls-good", &grant_good.id, None, 300);
    let handle_wrong = t.issue_handle_for("agent-1", "tls-wrong", &grant_wrong.id, None, 300);

    let resolver = resolver_answering(vec!["127.0.0.1".parse().unwrap()]);
    let ok = gateway::relay_with_resolver(
        &t.ctx,
        &handle_good,
        "GET",
        "/me",
        &no_headers(),
        b"",
        None,
        resolver.clone(),
    );
    let bad = gateway::relay_with_resolver(
        &t.ctx,
        &handle_wrong,
        "GET",
        "/me",
        &no_headers(),
        b"",
        None,
        resolver,
    );
    assert_eq!((ok.status.clone(), ok.reason.clone()), (200.into(), None));
    assert_eq!(
        (bad.status.clone(), bad.reason.as_deref()),
        (502.into(), Some("upstream_tls_failed"))
    );
    assert_eq!(fake.requests().len(), 1);
}

// ----------------------------------- equivalence review round-1 (behaviour)

#[test]
fn ledger_corruption_fails_closed_before_reaching_upstream() {
    // Finding F-1: `RequestLedger::load`/`save` used to swallow a
    // `state.read_json`/`write_json` failure (mapping it to an empty
    // ledger, or discarding a write error with `let _ = ...`); Python's
    // `_load`/`_save` let a `StateError` propagate out of `_Relay.run`
    // uncaught, refusing the request *before* the upstream is ever
    // contacted. Probe from the finding: after a successful `request_id =
    // "r-1"` relay, corrupt the ledger file and replay the same request id
    // -- Python raises `StateError("state_corrupt")` with the upstream
    // still only having been contacted once; the pre-fix Rust returned 200
    // and re-executed the request upstream a second time.
    let t = GatewayTest::new();
    let first = t.relay_full("GET", "/me", &no_headers(), b"", None, Some("r-1"));
    assert_eq!(first.status, 200);
    assert_eq!(t.fake.requests().len(), 1);

    std::fs::write(t.ctx.state.path.join(gateway::LEDGER_DOC), b"{not json").unwrap();

    let second = t.relay_full("GET", "/me", &no_headers(), b"", None, Some("r-1"));
    assert_eq!(second.status, 503);
    assert_eq!(second.reason.as_deref(), Some("state_corrupt"));
    assert_eq!(
        second.json().expect("test body is valid utf-8 JSON")["error"],
        "StateError"
    );
    assert_eq!(
        t.fake.requests().len(),
        1,
        "a corrupt ledger must refuse the request, not re-execute it upstream"
    );
}

#[test]
fn credential_reflection_is_caught_via_latin1_bytes_not_utf8() {
    // Finding F-2: `filter_response`'s scanned header blob used to be built
    // with `format!(...).into_bytes()` (UTF-8), but Python scans
    // `f"{name}: {value}".encode("latin-1", "replace")` -- the exact
    // upstream bytes. A credential byte >= 0x80 reflected in a response
    // header (here in `ETag`, via HTTP/1.1's basic-auth password path) was
    // therefore missed: the byte 0xE9 UTF-8-encodes to two bytes (0xC3
    // 0xA9), which never matches the raw single-byte secret pattern.
    let t = GatewayTest::new();
    let mut secret = b"p".to_vec();
    secret.push(0xE9);
    secret.extend_from_slice(b"ssword-synthetic-0123456789");
    t.ctx
        .vault
        .put_secret(
            "basic-pw-nonascii",
            "password",
            &secret,
            "demo",
            "dev",
            true,
        )
        .unwrap();
    let auth = HttpAuth::new("basic", None, None, Some("synthetic-user".to_string())).unwrap();

    let mut response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nETag: ".to_vec();
    response.extend_from_slice(&secret);
    response.extend_from_slice(b"\r\n\r\n");
    let port = raw_response_port(response);
    let handle = raw_port_connection(&t, "basic-nonascii", "basic-pw-nonascii", auth, port);
    let result = gateway::relay(&t.ctx, &handle, "GET", "/me", &no_headers(), b"", None);
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (502.into(), Some("credential_reflection_blocked"))
    );
}

#[test]
fn duplicate_content_encoding_headers_are_joined_before_checking() {
    // Finding F-3: `HTTPResponse.getheader("Content-Encoding")` joins ALL
    // occurrences with `", "` (`Message.get_all`); reading only the first
    // occurrence let a duplicate `Content-Encoding: identity` + `gzip`
    // through as if the response were uncompressed.
    let t = GatewayTest::new();
    let response =
        b"HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Encoding: gzip\r\nContent-Length: 5\r\n\r\nhello"
            .to_vec();
    let result = relay_via_raw_response(&t, "dup-content-encoding", response);
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (502.into(), Some("response_encoding_unsupported"))
    );
}

#[test]
fn self_referential_target_via_public_url_is_case_insensitive() {
    // Finding F-4: Python compares against `urlsplit(public_url).hostname`,
    // which is always lower-cased; a mixed-case `public_url` (as an
    // operator might configure, e.g. from a mixed-case DNS name) must still
    // trigger the self-referential-target refusal. Oracle-checked directly
    // against `urllib.parse.urlsplit` below.
    let mut t = GatewayTest::new();
    t.ctx.config.extra.insert(
        "public_url".to_string(),
        serde_json::Value::String("http://ZEROPW.invalid:8443".to_string()),
    );
    let _handle = named_connection_port(&t, "public-self", "zeropw.invalid", 8443, false);
    let result = gateway::relay_for_caller(
        &t.ctx,
        "agent-1",
        "public-self",
        "GET",
        "/me",
        &no_headers(),
        b"",
        None,
    );
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (501.into(), Some("self_referential_target"))
    );
}

#[test]
fn urlsplit_hostname_matches_python_lower_casing() {
    let out = run_python_oracle(
        r#"
import urllib.parse
print(urllib.parse.urlsplit("http://ZEROPW.invalid:8443").hostname)
"#,
    );
    assert_eq!(out.trim(), "zeropw.invalid");
}

#[test]
fn slow_upstream_read_is_a_timeout_not_connection_lost() {
    // Finding F-5: every read (and the request write) error used to become
    // `upstream_connection_lost`, but Python classifies `socket.timeout`/
    // `TimeoutError` as `upstream_timeout` -- see the fixed
    // `upstream_down_and_timeout` test above (`tests/test_gateway.py:561`)
    // for the primary regression test; this one pins the same
    // classification via a raw scratch listener that never answers at all
    // (so the very first status-line read times out, rather than a slow
    // `FakeUpstream` response).
    let mut t = GatewayTest::new();
    t.ctx.config.upstream_timeout = 0.2;
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        // Accept and then just hold the connection open without writing
        // anything, so the client's status-line read times out.
        if let Ok((stream, _)) = listener.accept() {
            std::thread::sleep(Duration::from_secs(2));
            drop(stream);
        }
    });
    let handle = raw_port_connection(&t, "never-answers", "gh-token", HttpAuth::bearer(), port);
    let result = gateway::relay(&t.ctx, &handle, "GET", "/me", &no_headers(), b"", None);
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (502.into(), Some("upstream_timeout"))
    );
}

#[test]
fn status_code_outside_100_999_is_a_protocol_error() {
    // Finding F-6: CPython's `_read_status` rejects a status outside
    // `100..=999` as `BadStatusLine` -> `upstream_protocol_error`; probe
    // from the finding.
    let t = GatewayTest::new();
    let too_small =
        relay_via_raw_response(&t, "status-too-small", b"HTTP/1.1 12 Nope\r\n\r\n".to_vec());
    assert_eq!(
        (too_small.status.clone(), too_small.reason.as_deref()),
        (502.into(), Some("upstream_protocol_error"))
    );
    let too_large = relay_via_raw_response(
        &t,
        "status-too-large",
        b"HTTP/1.1 1000 Nope\r\n\r\n".to_vec(),
    );
    assert_eq!(
        (too_large.status.clone(), too_large.reason.as_deref()),
        (502.into(), Some("upstream_protocol_error"))
    );
}

#[test]
fn continue_interim_response_is_skipped_and_the_real_response_relayed() {
    // Finding F-7: a `100 Continue` interim response must be consumed (its
    // own header block skipped) and the response that follows relayed;
    // probe from the finding.
    let t = GatewayTest::new();
    let response =
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi".to_vec();
    let result = relay_via_raw_response(&t, "continue-then-ok", response);
    assert_eq!(
        (result.status.clone(), result.body),
        (200.into(), b"hi".to_vec())
    );
}

#[test]
fn transfer_encoding_value_is_compared_without_trimming() {
    // Finding F-8: CPython compares `tr_enc.lower() == "chunked"` with no
    // stripping; `"chunked "` (trailing space) is therefore NOT chunked, so
    // the raw chunk-framing bytes are relayed verbatim as an unframed
    // (`UntilClose`) body. Probe from the finding.
    let t = GatewayTest::new();
    let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked \r\n\r\n".to_vec();
    response.extend_from_slice(b"5\r\nhello\r\n0\r\n\r\n");
    let result = relay_via_raw_response(&t, "te-trailing-space", response);
    assert_eq!(result.status, 200);
    assert_eq!(result.body, b"5\r\nhello\r\n0\r\n\r\n".to_vec());
}

#[test]
fn tab_separated_status_line_is_accepted() {
    // Finding F-9a: `line.split(None, 2)` splits on any whitespace run, not
    // just a literal space.
    let t = GatewayTest::new();
    let response = b"HTTP/1.1\t200\tOK\r\nContent-Length: 2\r\n\r\nhi".to_vec();
    let result = relay_via_raw_response(&t, "tab-status-line", response);
    assert_eq!(
        (result.status.clone(), result.body),
        (200.into(), b"hi".to_vec())
    );
}

#[test]
fn folded_header_continuation_line_does_not_error() {
    // Finding F-9b: a header continuation line (starting with a space or
    // tab) folds into the previous header instead of being rejected.
    let t = GatewayTest::new();
    let response =
        b"HTTP/1.1 200 OK\r\nX-Custom: first\r\n second-part\r\nContent-Length: 2\r\n\r\nhi"
            .to_vec();
    let result = relay_via_raw_response(&t, "folded-continuation", response);
    assert_eq!(
        (result.status.clone(), result.body),
        (200.into(), b"hi".to_vec())
    );
}

#[test]
fn header_line_without_colon_ends_recognised_headers_without_erroring() {
    // Finding F-9c: `email.feedparser` stops recognising further headers at
    // a line with no colon (and no leading whitespace) instead of raising;
    // subsequent lines (even otherwise-valid-looking headers) are simply
    // never parsed, but bytes up to the blank line are still consumed. Here
    // `Content-Length` is set *before* the bad line, so the body still
    // frames correctly.
    let t = GatewayTest::new();
    let response =
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nBadHeaderNoColon\r\nX-After: ignored\r\n\r\nhi"
            .to_vec();
    let result = relay_via_raw_response(&t, "no-colon-header", response);
    assert_eq!(
        (result.status.clone(), result.body),
        (200.into(), b"hi".to_vec())
    );
}

#[test]
fn malformed_chunk_size_is_a_protocol_error_not_connection_lost() {
    // Finding F-9d: `_read_next_chunk_size`'s `int(line, 16)` `ValueError`
    // is caught by `_get_chunk_left` and re-raised as `IncompleteRead` (an
    // `http.client.HTTPException`), so it maps to `upstream_protocol_error`,
    // not `upstream_connection_lost`.
    let t = GatewayTest::new();
    let response =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\nhello\r\n0\r\n\r\n".to_vec();
    let result = relay_via_raw_response(&t, "malformed-chunk-size", response);
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (502.into(), Some("upstream_protocol_error"))
    );
}

// ---------------------------------------------- equivalence review round 2

#[test]
fn more_than_max_headers_is_a_protocol_error() {
    // Finding F-R2-2: `http.client._MAXHEADERS` (100) caps the physical
    // line count `_read_headers` allows, counting the terminating blank
    // line too; probe from the finding (120 header lines).
    let t = GatewayTest::new();
    let mut response = b"HTTP/1.1 200 OK\r\n".to_vec();
    for i in 0..120 {
        response.extend_from_slice(format!("X-Many-{i}: v\r\n").as_bytes());
    }
    response.extend_from_slice(b"\r\nbody");
    let result = relay_via_raw_response(&t, "too-many-headers", response);
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (502.into(), Some("upstream_protocol_error"))
    );
}

#[test]
fn oversized_header_line_is_a_protocol_error() {
    // Finding F-R2-2: `http.client._MAXLINE` (65536) caps every physical
    // line; probe from the finding (a 70000-byte header value).
    let t = GatewayTest::new();
    let mut response = b"HTTP/1.1 200 OK\r\n".to_vec();
    response.extend_from_slice(b"X-Huge: ");
    response.extend_from_slice(&vec![b'a'; 70_000]);
    response.extend_from_slice(b"\r\n\r\nbody");
    let result = relay_via_raw_response(&t, "oversized-header-line", response);
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (502.into(), Some("upstream_protocol_error"))
    );
}

#[test]
fn header_block_ended_by_eof_is_relayed_normally() {
    // Finding F-R2-3a: `_read_headers`' own terminator set is `(b'\r\n',
    // b'\n', b'')` -- EOF (`b''`) ends the header block exactly like a
    // blank line, not an error.
    let t = GatewayTest::new();
    let response = b"HTTP/1.1 200 OK\r\nX-Custom: value".to_vec();
    let result = relay_via_raw_response(&t, "headers-end-at-eof", response);
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (200.into(), None)
    );
    assert_eq!(result.body, Vec::<u8>::new());
    assert!(
        !header_names(&result).contains("x-custom"),
        "X-Custom is not on the response allowlist, so it must still be filtered out"
    );
}

#[test]
fn status_line_then_immediate_eof_is_relayed_as_empty_ok() {
    // Finding F-R2-3b: a status line with no headers at all, immediately
    // followed by EOF, still parses (empty header block via the same EOF
    // terminator as F-R2-3a) and relays as a 200 with an empty body
    // (`UntilClose` framing, no bytes available).
    let t = GatewayTest::new();
    let response = b"HTTP/1.1 200 OK\r\n".to_vec();
    let result = relay_via_raw_response(&t, "status-then-eof", response);
    assert_eq!(
        (
            result.status.clone(),
            result.body.clone(),
            result.reason.as_deref()
        ),
        (200.into(), Vec::new(), None)
    );
}

#[test]
fn content_length_larger_than_bytes_sent_relays_the_short_body() {
    // Finding F-R2-3c: `HTTPResponse.read(amt)`'s amt-limited branch calls
    // plain `self.fp.read(amt)`, not `_safe_read`: a `Content-Length`
    // bigger than what the server actually sends does not raise
    // `IncompleteRead` -- the short body is relayed as a 200.
    let t = GatewayTest::new();
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nshort".to_vec();
    let result = relay_via_raw_response(&t, "content-length-too-big", response);
    assert_eq!(
        (
            result.status.clone(),
            result.body.clone(),
            result.reason.as_deref()
        ),
        (200.into(), b"short".to_vec(), None)
    );
}

#[test]
fn chunked_body_ending_at_eof_after_terminal_chunk_is_relayed_normally() {
    // Finding F-R2-3d: `_read_and_discard_trailer` ends its own block on
    // EOF too ("a vanishingly small number of sites EOF without sending
    // the trailer"), not an error; the decoded body is still relayed.
    let t = GatewayTest::new();
    let response =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n".to_vec();
    let result = relay_via_raw_response(&t, "chunked-eof-after-terminal", response);
    assert_eq!(
        (
            result.status.clone(),
            result.body.clone(),
            result.reason.as_deref()
        ),
        (200.into(), b"hello".to_vec(), None)
    );
}

#[test]
fn chunk_terminator_bytes_are_consumed_without_validation() {
    // Finding F-R2-4: `_get_chunk_left`'s `self._safe_read(2)` discards
    // exactly 2 bytes after a chunk's data, unconditionally -- it never
    // checks they are `\r\n`. Probe from the finding: `5\r\nhelloXY0\r\n\r\n`
    // relays body `hello` (the "XY" bytes are simply discarded, and the
    // "0\r\n\r\n" that follows is read as the terminal chunk + trailer).
    let t = GatewayTest::new();
    let response =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXY0\r\n\r\n".to_vec();
    let result = relay_via_raw_response(&t, "chunk-terminator-unchecked", response);
    assert_eq!(
        (
            result.status.clone(),
            result.body.clone(),
            result.reason.as_deref()
        ),
        (200.into(), b"hello".to_vec(), None)
    );
}

#[test]
fn chunk_terminator_lf_only_framing_is_a_protocol_error() {
    // Finding F-R2-4 (the inverse probe): `5\nhello\n0\n\n` uses bare `\n`
    // chunk-size-line and chunk-terminator bytes throughout. The chunk-size
    // lines themselves parse fine (`readline` splits on `\n` alone), but
    // the *unconditional* 2-byte terminator discard after `hello`'s data
    // consumes `"\n0"` (not `"\r\n"`), leaving just `"\n\n"` -- so the next
    // chunk-size line read is empty, which fails to parse as hex and is a
    // protocol error. (Rust used to instead read a full line and require it
    // *empty*, which happened to accept this framing -- exactly backwards
    // from Python, which refuses it.)
    let t = GatewayTest::new();
    let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\nhello\n0\n\n".to_vec();
    let result = relay_via_raw_response(&t, "chunk-terminator-lf-only", response);
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (502.into(), Some("upstream_protocol_error"))
    );
}

#[test]
fn content_length_with_pep515_underscore_is_parsed_like_python_int() {
    // Finding F-R2-5: CPython's `int(length)` accepts PEP 515 underscore
    // separators between digits; `Content-Length: 1_0` frames exactly 10
    // bytes, not "fall through to UntilClose and relay everything sent".
    let t = GatewayTest::new();
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 1_0\r\n\r\n0123456789tail".to_vec();
    let result = relay_via_raw_response(&t, "content-length-underscore", response);
    assert_eq!(
        (
            result.status.clone(),
            result.body.clone(),
            result.reason.as_deref()
        ),
        (200.into(), b"0123456789".to_vec(), None)
    );
}

#[test]
fn chunk_size_with_pep515_underscore_is_parsed_like_python_int() {
    // Finding F-R2-5: `int(line, 16)` accepts underscores too; chunk size
    // `1_0` is 16 (decimal), not a parse failure.
    let t = GatewayTest::new();
    let body = b"0123456789abcdef".to_vec(); // 16 bytes
    let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1_0\r\n".to_vec();
    response.extend_from_slice(&body);
    response.extend_from_slice(b"\r\n0\r\n\r\n");
    let result = relay_via_raw_response(&t, "chunk-size-underscore", response);
    assert_eq!(
        (
            result.status.clone(),
            result.body.clone(),
            result.reason.as_deref()
        ),
        (200.into(), body, None)
    );
}

#[test]
fn status_code_with_pep515_underscore_is_parsed_like_python_int() {
    // Finding F-R2-5: `int(status)` accepts underscores too; `2_00` is 200.
    let t = GatewayTest::new();
    let response = b"HTTP/1.1 2_00 OK\r\nContent-Length: 2\r\n\r\nhi".to_vec();
    let result = relay_via_raw_response(&t, "status-underscore", response);
    assert_eq!(
        (
            result.status.clone(),
            result.body.clone(),
            result.reason.as_deref()
        ),
        (200.into(), b"hi".to_vec(), None)
    );
}

#[test]
fn only_http_1_x_and_0_9_versions_are_accepted() {
    // Finding F-R2-6: `HTTPResponse.begin` accepts only `HTTP/1.0`,
    // `HTTP/0.9`, or anything starting `HTTP/1.`; anything else
    // (`HTTP/2`, `HTTP/2.0`, a bare `HTTP/`) is `UnknownProtocol` ->
    // `upstream_protocol_error`, even though `_read_status`'s own looser
    // `"HTTP/"`-prefix check would have accepted all of them. Probes from
    // the finding.
    let t = GatewayTest::new();
    for (name, version) in [
        ("http2", "HTTP/2"),
        ("http2.0", "HTTP/2.0"),
        ("bare-http-slash", "HTTP/"),
    ] {
        let response = format!("{version} 200 OK\r\nContent-Length: 2\r\n\r\nhi").into_bytes();
        let result = relay_via_raw_response(&t, &format!("bad-version-{name}"), response);
        assert_eq!(
            (result.status.clone(), result.reason.as_deref()),
            (502.into(), Some("upstream_protocol_error")),
            "version {version:?} should have been refused"
        );
    }
    // And the accepted forms still work.
    for (name, version) in [
        ("1.0", "HTTP/1.0"),
        ("0.9", "HTTP/0.9"),
        ("1.1", "HTTP/1.1"),
    ] {
        let response = format!("{version} 200 OK\r\nContent-Length: 2\r\n\r\nhi").into_bytes();
        let result = relay_via_raw_response(&t, &format!("good-version-{name}"), response);
        assert_eq!(
            (
                result.status.clone(),
                result.body.clone(),
                result.reason.as_deref()
            ),
            (200.into(), b"hi".to_vec(), None),
            "version {version:?} should have been accepted"
        );
    }
}

#[test]
fn no_content_status_with_chunked_transfer_encoding_still_decodes_the_body() {
    // Finding F-R2-7: `HTTPResponse.read` checks `self._method == "HEAD"`
    // first, then `self.chunked` (set independently of the 204/304/1xx
    // `self.length = 0` override) -- so a `204` with `Transfer-Encoding:
    // chunked` still gets its chunked body decoded and relayed in Python.
    // Probe from the finding: `204 bodylen=5 'hello'`.
    let t = GatewayTest::new();
    let response =
        b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
            .to_vec();
    let result = relay_via_raw_response(&t, "204-chunked-has-body", response);
    assert_eq!(
        (
            result.status.clone(),
            result.body.clone(),
            result.reason.as_deref()
        ),
        (204.into(), b"hello".to_vec(), None)
    );
}

#[test]
fn head_request_still_forces_an_empty_body_even_when_chunked() {
    // Finding F-R2-7 (the ordering's other half): `HEAD` must stay the
    // *first* check -- `read()` short-circuits on it before ever consulting
    // `self.chunked`, so a `HEAD` response is always empty regardless of
    // `Transfer-Encoding`.
    let t = GatewayTest::new();
    let port = raw_response_port(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec(),
    );
    let handle = raw_port_connection(
        &t,
        "head-with-chunked",
        "gh-token",
        HttpAuth::bearer(),
        port,
    );
    let result = gateway::relay(&t.ctx, &handle, "HEAD", "/me", &no_headers(), b"", None);
    assert_eq!(
        (
            result.status.clone(),
            result.body.clone(),
            result.reason.as_deref()
        ),
        (200.into(), Vec::new(), None)
    );
}

#[test]
fn header_value_ending_in_newline_is_accepted_then_fails_after_transmission() {
    // Finding F-R2-8: `_HEADER_VALUE_RE.match(value)` accepts a single
    // trailing `"\n"` (CPython's `$` matches just before one); the value is
    // forwarded, and only fails downstream, at `conn.request(...)` ->
    // `putheader`'s own illegal-value check, *after* `self.transmitted =
    // True` -- so the outcome is `502 upstream_connection_lost`, and the
    // ledger entry (since a request id was given) ends up `"uncertain"`,
    // not released, because the request may have partially reached the
    // upstream from Python's perspective.
    let t = GatewayTest::new();
    let result = t.relay_full(
        "GET",
        "/me",
        &headers(&[("user-agent", "bad-value\n")]),
        b"",
        None,
        Some("req-header-newline"),
    );
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (502.into(), Some("upstream_connection_lost"))
    );
    assert_eq!(
        t.fake.requests().len(),
        0,
        "the illegal header must never actually reach the wire"
    );
    let doc = t
        .ctx
        .state
        .read_json(gateway::LEDGER_DOC, serde_json::json!({}))
        .unwrap();
    assert_eq!(doc["agent-1"]["req-header-newline"]["state"], "uncertain");
}

#[test]
fn bearer_credential_ending_in_newline_is_accepted_then_fails_after_transmission() {
    // Finding F-R2-8, the credential half: `_HEADER_CREDENTIAL_RE.match`
    // has the same trailing-`"\n"` leniency; a credential ending in `"\n"`
    // is accepted by `_auth_header` and only fails downstream the same way.
    let t = GatewayTest::new();
    t.ctx
        .vault
        .put_secret(
            "nl-token",
            "api_key",
            b"secret-value\n",
            "demo",
            "dev",
            true,
        )
        .unwrap();
    t.ctx
        .policy
        .create_connection(http_connection(
            "nl-conn",
            &t.fake,
            "nl-token",
            HttpAuth::bearer(),
            HttpScope::new(None, None, vec![]).unwrap(),
        ))
        .unwrap();
    let grant = t
        .ctx
        .policy
        .create_grant("agent-1", "nl-conn", Some(3600), None)
        .unwrap();
    let handle = t.issue_handle_for("agent-1", "nl-conn", &grant.id, None, 300);
    let result = t.relay_full(
        "GET",
        "/me",
        &no_headers(),
        b"",
        Some(&handle),
        Some("req-cred-newline"),
    );
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (502.into(), Some("upstream_connection_lost"))
    );
    assert_eq!(t.fake.requests().len(), 0);
}

#[test]
fn ca_file_unavailable_takes_priority_over_an_unreachable_target() {
    // Finding F-R2-9: Python's `_open_connection` builds the whole
    // `ssl.SSLContext` (including `load_verify_locations(cafile=...)`,
    // which is where a bad `ca_file` actually fails) *before* `_exchange`
    // ever calls `conn.connect()` -- so for an unreachable target with a
    // bad `ca_file`, the reason is always `ca_file_unavailable`, never
    // `upstream_unreachable`.
    let t = GatewayTest::new();
    t.ctx
        .vault
        .put_secret(
            "ca-token",
            "api_key",
            SECRET_B.as_bytes(),
            "demo",
            "dev",
            true,
        )
        .unwrap();
    // A `FakeUpstream` bound then immediately dropped: the OS-assigned port
    // is very likely still free, but nothing listens there, so a TCP
    // connect attempt is refused essentially immediately.
    let unreachable = FakeUpstream::new("x").start();
    let port = unreachable.port();
    drop(unreachable);
    let bad_ca_path = std::env::temp_dir().join(format!(
        "zeropw-test-missing-ca-{}-{port}.pem",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&bad_ca_path); // ensure it does not exist
    let target = HttpTarget::new(
        "https",
        "127.0.0.1",
        port as i64,
        Some(bad_ca_path.to_string_lossy().into_owned()),
        false,
    )
    .unwrap();
    t.ctx
        .policy
        .create_connection(
            Connection::new(
                "ca-unreachable",
                "demo",
                "dev",
                "test",
                "http",
                "ca-token",
                None,
                "",
                Some(target),
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
    let grant = t
        .ctx
        .policy
        .create_grant("agent-1", "ca-unreachable", Some(3600), None)
        .unwrap();
    let handle = t.issue_handle_for("agent-1", "ca-unreachable", &grant.id, None, 300);
    let result = t.relay_full("GET", "/me", &no_headers(), b"", Some(&handle), None);
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (502.into(), Some("ca_file_unavailable"))
    );
}

#[test]
fn raw_ca_file_truthiness_fails_closed_without_default_trust_fallback() {
    let t = GatewayTest::new();
    t.ctx
        .vault
        .put_secret(
            "raw-ca-token",
            "api_key",
            SECRET_B.as_bytes(),
            "demo",
            "dev",
            true,
        )
        .unwrap();
    let unreachable = FakeUpstream::new("x").start();
    let port = unreachable.port();
    drop(unreachable);

    // A truthy non-`str` `ca_file` makes CPython's `load_verify_locations`
    // raise `TypeError`, which escapes `relay` uncaught; `zeropw.server`
    // answers it with its fixed 500 `internal_error` reply (see
    // `python_open_connection_uses_ca_file_truthiness_before_path_type`).
    for (suffix, raw_ca_file, expected_status, expected_reason) in [
        ("null", serde_json::Value::Null, 502, "upstream_unreachable"),
        (
            "false",
            serde_json::json!(false),
            502,
            "upstream_unreachable",
        ),
        ("zero", serde_json::json!(0), 502, "upstream_unreachable"),
        (
            "empty-list",
            serde_json::json!([]),
            502,
            "upstream_unreachable",
        ),
        (
            "empty-string",
            serde_json::json!(""),
            502,
            "upstream_unreachable",
        ),
        ("number", serde_json::json!(5), 500, "internal_error"),
        ("true", serde_json::json!(true), 500, "internal_error"),
        (
            "list",
            serde_json::json!(["not", "a", "path"]),
            500,
            "internal_error",
        ),
        ("nul", serde_json::json!("a\u{0}b"), 500, "internal_error"),
    ] {
        let connection_id = format!("raw-ca-{suffix}");
        let target = HttpTarget::new("https", "127.0.0.1", port as i64, None, false).unwrap();
        t.ctx
            .policy
            .create_connection(
                Connection::new(
                    &connection_id,
                    "demo",
                    "dev",
                    "test",
                    "http",
                    "raw-ca-token",
                    None,
                    "",
                    Some(target),
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
        let mut connections = t
            .ctx
            .state
            .read_json(P::CONNECTIONS, serde_json::json!({}))
            .unwrap();
        connections[&connection_id]["http_target"]["ca_file"] = raw_ca_file;
        t.ctx
            .state
            .write_json(P::CONNECTIONS, &connections)
            .unwrap();

        let grant = t
            .ctx
            .policy
            .create_grant("agent-1", &connection_id, Some(3600), None)
            .unwrap();
        let handle = t.issue_handle_for("agent-1", &connection_id, &grant.id, None, 300);
        let result = t.relay_full("GET", "/me", &no_headers(), b"", Some(&handle), None);
        assert_eq!(
            (result.status.clone(), result.reason.as_deref()),
            (expected_status.into(), Some(expected_reason)),
            "{suffix}"
        );
    }
}

#[test]
fn python_open_connection_uses_ca_file_truthiness_before_path_type() {
    let output = run_python_oracle(
        r#"
import json
from zeropw import gateway as G
from zeropw import policy as P

for value in (None, False, 0, [], {}, 5, True, ["not", "a", "path"], {"x": 1}, "", "a\x00b"):
    target = P.HttpTarget("https", "example.com", 443, value)
    connection = P.Connection(
        "c", "demo", "dev", "test", "http", "secret", None, "", target,
        P.HttpAuth("bearer"), P.HttpScope(), None, None, 0, "active", "", "",
    )
    try:
        G._open_connection(connection, 1.0)
        result = "ok"
    except Exception as exc:
        result = type(exc).__name__
    print(json.dumps([value, result], sort_keys=True))
"#,
    );
    let observed: Vec<Value> = output
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        observed,
        vec![
            serde_json::json!([null, "ok"]),
            serde_json::json!([false, "ok"]),
            serde_json::json!([0, "ok"]),
            serde_json::json!([[], "ok"]),
            serde_json::json!([{}, "ok"]),
            serde_json::json!([5, "TypeError"]),
            serde_json::json!([true, "TypeError"]),
            serde_json::json!([["not", "a", "path"], "TypeError"]),
            serde_json::json!([{"x": 1}, "TypeError"]),
            serde_json::json!(["", "ok"]),
            serde_json::json!(["a\u{0}b", "ValueError"]),
        ]
    );
}

#[test]
fn unbracketed_ipv6_like_public_url_does_not_false_positive_self_referential() {
    // Finding F-R2-10: `urlsplit`'s `_hostinfo` partitions the unbracketed
    // authority on the *first* colon, not the last, so
    // `public_url = "http://::1:8443"` gives Python `hostname=None` (empty
    // string before the first colon) and a `.port` access that raises
    // `ValueError` (swallowed by the surrounding `except ValueError: pass`)
    // -- NOT self-referential, regardless of what `target.host`/`.port`
    // are. The old last-colon `rsplit_once` implementation instead parsed
    // this as host `"::1"` port `8443`, which spuriously matched a
    // same-valued target and refused it as self-referential -- a false
    // positive Python itself does not produce. With the connection's own
    // target literally at `::1:8443` (a literal-IP target skips the
    // private-network gate entirely -- see `resolve_pinned_address`, only
    // the DNS-resolved-answer path consults `allow_private_network`), the
    // real outcome once the self-referential shortcut is correctly skipped
    // is an ordinary failed connection attempt to a real, but
    // unlistened-on, address: `502 upstream_unreachable`. The only thing
    // this test pins is that it is *not* `501 self_referential_target`.
    let mut t = GatewayTest::new();
    t.ctx.config.extra.insert(
        "public_url".to_string(),
        serde_json::Value::String("http://::1:8443".to_string()),
    );
    let handle = named_connection_port(&t, "v6-unbracketed", "::1", 8443, false);
    let result = gateway::relay(&t.ctx, &handle, "GET", "/me", &no_headers(), b"", None);
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (502.into(), Some("upstream_unreachable")),
        "must not be refused as self_referential_target (that would be the pre-fix, \
         Python-diverging false positive)"
    );
}

#[test]
fn refuse_unauthenticated_audits_stripped_path_unconditionally_and_untrimmed_method() {
    // Finding F-10: Python audits `strip_query(path)` for *any* `str` path
    // (no `normalize_path` validation at all), and sets `action` only when
    // `_METHOD_RE` matches the *unstripped* upper-cased method -- so a
    // padded method like `" get "` normalises to `" GET "`, which does not
    // match `^[A-Z]{1,16}$`, giving `action: null`.
    let t = GatewayTest::new();
    let result = gateway::relay(
        &t.ctx,
        "not-a-real-handle-token",
        " get ",
        "/a/../b?token=secret",
        &no_headers(),
        b"",
        None,
    );
    assert_eq!(result.status, 401);
    let record = t.audit_records().last().unwrap().clone();
    assert_eq!(record["path"], "/a/../b");
    assert_eq!(record["action"], serde_json::Value::Null);
}

#[test]
fn method_and_header_name_strip_information_separator_control_chars() {
    // Finding F-11: `str.strip()` also strips U+001C-U+001F; Rust's
    // `str::trim()` does not, so a method/header name padded with one of
    // these was rejected/dropped instead of normalising like Python.
    let t = GatewayTest::new();
    let result = t.relay_h(
        "GET\u{1c}",
        "/me",
        &headers(&[("accept\u{1c}", "application/json")]),
    );
    assert_eq!(result.status, 200);
    assert_eq!(
        t.fake
            .requests()
            .last()
            .unwrap()
            .headers
            .get("accept")
            .unwrap(),
        "application/json"
    );
}

#[test]
fn normalize_path_accepts_a_single_trailing_newline_like_python() {
    // Finding F-12: Python's `re` `$` also matches immediately before a
    // single trailing `"\n"`, so `_TARGET_CHARS.match("/a?b\n")` succeeds in
    // Python (returning `("/a", "/a?b\n")`), where the `regex` crate's own
    // `$`/`is_match` only accepts the true end of the haystack. Oracle
    // checked against real `python3.12` below.
    assert_eq!(
        gateway::normalize_path("/a?b\n").unwrap(),
        ("/a".to_string(), "/a?b\n".to_string())
    );
    // An embedded newline elsewhere, or more than one trailing newline,
    // must still be refused (only exactly one *trailing* newline is
    // special-cased by Python's `$`).
    assert!(gateway::normalize_path("/a\nb").is_err());
    assert!(gateway::normalize_path("/a?b\n\n").is_err());
}

#[test]
fn normalize_path_trailing_newline_matches_python_target_chars_regex() {
    let out = run_python_oracle(
        r#"
import re
pat = re.compile(r"^[\x21-\x7e]*$")
tests = ["/a?b\n", "/a\nb", "/a?b\n\n", "/a?b"]
print([bool(pat.match(t)) for t in tests])
"#,
    );
    assert_eq!(out.trim(), "[True, False, False, True]");
}

/// Small seeded xorshift64* PRNG, same technique used by the internal
/// `http_framing_fuzz` module in `rust/src/gateway.rs` -- deterministic
/// across runs, no extra crate dependency.
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Lcg(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
    fn one_in(&mut self, n: usize) -> bool {
        self.below(n) == 0
    }
}

/// Encodes `cp` (a Unicode scalar value) as its UTF-8 bytes, each rendered
/// as an uppercase or lowercase `%XX` triplet (mixed per byte, to also
/// exercise `credential`/percent-decoding's case-insensitivity elsewhere).
fn percent_encode_codepoint(rng: &mut Lcg, cp: u32, double_encode_percent: bool) -> String {
    let ch = char::from_u32(cp).unwrap_or('?');
    let mut buf = [0u8; 4];
    let bytes = ch.encode_utf8(&mut buf).as_bytes();
    let mut out = String::new();
    for &b in bytes {
        let hex = if rng.one_in(2) {
            format!("{b:02X}")
        } else {
            format!("{b:02x}")
        };
        if double_encode_percent {
            // First-pass-decodes-to-a-literal-percent nesting: "%25" decodes
            // once to "%", so "%25E4" decodes *twice* to the same byte "%E4"
            // would decode to once -- this is the exact shape that used to
            // panic (finding F-R2-1: a percent-triplet whose first decode
            // pass lands the '%' + hex digits *inside* a multi-byte
            // character produced by an earlier triplet in the same pass).
            out.push_str("%25");
            out.push_str(&hex);
        } else {
            out.push('%');
            out.push_str(&hex);
        }
    }
    out
}

/// One random adversarial path candidate: a `/`-prefixed mix of literal
/// printable-ASCII characters, well-formed and malformed `%XX` triplets, and
/// percent-encoded multi-byte Unicode codepoints (1-4 UTF-8 bytes), some of
/// them double-percent-encoded to chain across `normalize_path`'s two decode
/// passes -- the exact shape finding F-R2-1's panic needed.
fn random_path_candidate(rng: &mut Lcg) -> String {
    let mut s = String::from("/");
    let pieces = 1 + rng.below(10);
    for _ in 0..pieces {
        match rng.below(6) {
            0 => {
                // Literal printable-ASCII byte (0x21-0x7e), skipping '%' so
                // stray literal percents are covered by arm 3 below instead.
                let b = 0x21u8 + (rng.below(0x7e - 0x21 + 1) as u8);
                let b = if b == b'%' { b'a' } else { b };
                s.push(b as char);
            }
            1 => {
                // Well-formed hex triplet.
                let byte = (rng.next_u64() % 256) as u8;
                s.push_str(&format!("%{byte:02X}"));
            }
            2 => {
                // Malformed/truncated triplet.
                let bad: &[&str] = &["%", "%g", "%1", "%zz", "%%"];
                s.push_str(bad[rng.below(bad.len())]);
            }
            3 => {
                // A random multi-byte codepoint, single-percent-encoded.
                let codepoints: &[u32] = &[0xE9, 0x4E2D, 0x1F600, 0x80, 0x7FF];
                let cp = codepoints[rng.below(codepoints.len())];
                s.push_str(&percent_encode_codepoint(rng, cp, false));
            }
            4 => {
                // Same, but double-percent-encoded (the panic shape).
                let codepoints: &[u32] = &[0xE9, 0x4E2D, 0x1F600, 0x2764, 0x10FFFF];
                let cp = codepoints[rng.below(codepoints.len())];
                s.push_str(&percent_encode_codepoint(rng, cp, true));
            }
            _ => {
                // A literal '/' or '?' to exercise segment/query splitting.
                let seps: &[char] = &['/', '?', '.'];
                s.push(seps[rng.below(seps.len())]);
            }
        }
    }
    s
}

#[test]
fn normalize_path_percent_decoding_never_panics_and_matches_python() {
    // Finding F-R2-1: `percent_decode_lossy` used to index a `str` slice at
    // a byte offset that can land inside a multi-byte UTF-8 character
    // produced by the *first* decode pass (e.g. `/%25%E4%B8%AD` decodes
    // once to bytes `2f 25 e4 b8 ad`, and offset 4 sits inside `中`),
    // panicking on agent-supplied input. Generate several thousand random
    // and adversarial percent-sequences (including ones specifically
    // engineered to reproduce that exact shape) and assert `normalize_path`
    // never panics on any of them, and its accept/reject outcome (and, when
    // accepted, its `(path, target)` pair) matches the real
    // `zeropw.gateway.normalize_path` for every one of them.
    let mut rng = Lcg::new(0xA5A5_1234_5678_9ABC);
    let case_count = 6000usize;
    let cases: Vec<String> = (0..case_count)
        .map(|_| random_path_candidate(&mut rng))
        .collect();

    // No panic: computing every outcome up front is itself the assertion
    // (a panic fails the test with a backtrace pointing at the case).
    let rust_results: Vec<Result<(String, String), &'static str>> =
        cases.iter().map(|c| gateway::normalize_path(c)).collect();

    let script = r#"
import sys, json
from zeropw import gateway as G
cases = json.loads(sys.stdin.read())
out = []
for raw in cases:
    try:
        path, target = G.normalize_path(raw)
        out.append(["ok", path, target])
    except G._Invalid as e:
        out.append(["err", e.reason])
sys.stdout.write(json.dumps(out))
"#;
    let stdin_json = serde_json::to_string(&cases).unwrap();
    let py_out = run_python_oracle_stdin(script, &stdin_json);
    let py_results: Vec<Value> = serde_json::from_str(py_out.trim()).unwrap();
    assert_eq!(py_results.len(), cases.len());

    let mut mismatches = Vec::new();
    for (i, (case, rust_result)) in cases.iter().zip(rust_results.iter()).enumerate() {
        let py = &py_results[i];
        let matches = match (rust_result, py[0].as_str().unwrap()) {
            (Ok((path, target)), "ok") => {
                path.as_str() == py[1].as_str().unwrap()
                    && target.as_str() == py[2].as_str().unwrap()
            }
            (Err(_), "err") => true,
            _ => false,
        };
        if !matches {
            mismatches.push(format!(
                "case {i} ({case:?}): rust={rust_result:?} python={py:?}"
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} / {} cases diverged from python3.12 gateway.normalize_path:\n{}",
        mismatches.len(),
        cases.len(),
        mismatches.join("\n")
    );
    eprintln!(
        "normalize_path percent-decode fuzz: {} cases, 0 divergences, 0 panics",
        cases.len()
    );
}

// ---------------------------------------------- equivalence review round 3

/// Spawns a background thread that accepts exactly one connection and
/// records every byte the client sends into `captured`, without writing any
/// response at all (used to prove a rejected request never reaches the
/// wire, finding F-R3-1). Returns the bound port.
fn capturing_port() -> (u16, Arc<Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let captured_clone = captured.clone();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            stream
                .set_read_timeout(Some(Duration::from_millis(300)))
                .ok();
            let mut buf = [0u8; 8192];
            if let Ok(n) = stream.read(&mut buf) {
                captured_clone.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        }
    });
    (port, captured)
}

#[test]
fn write_request_rejects_agent_controlled_request_line_injection() {
    // Finding F-R3-1 (HIGH): `normalize_path` correctly allows a target
    // ending in exactly one trailing "\n" (finding F-R2-8), but
    // `write_request` used to write that target straight onto the wire
    // with no further check -- the reviewer's probe: an agent-controlled
    // target of `"/x?y\n"` let a second, injected line reach the upstream
    // with the credential attached, and Rust relayed 200. CPython's
    // `HTTPConnection.putrequest` runs `_validate_path`
    // (`_contains_disallowed_url_pchar_re = re.compile('[\x00-\x20\x7f]')`)
    // BEFORE writing a single byte, raising `InvalidURL` (an
    // `http.client.HTTPException`) -- `_exchange`'s `except
    // http.client.HTTPException` clause turns that into
    // `upstream_protocol_error`, marks the ledger `"uncertain"` (the
    // request may or may not have reached the upstream from Python's own
    // point of view, even though here it provably did not), and the
    // upstream receives zero bytes.
    let t = GatewayTest::new();
    let (port, captured) = capturing_port();
    let handle = raw_port_connection(&t, "inject", "gh-token", HttpAuth::bearer(), port);
    let result = gateway::relay(
        &t.ctx,
        &handle,
        "GET",
        "/x?y\n",
        &no_headers(),
        b"",
        Some("inject-1"),
    );
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (502.into(), Some("upstream_protocol_error"))
    );
    assert!(
        captured.lock().unwrap().is_empty(),
        "the upstream must receive zero bytes when the request line itself is rejected"
    );
    let doc = t
        .ctx
        .state
        .read_json(gateway::LEDGER_DOC, serde_json::json!({}))
        .unwrap();
    assert_eq!(doc["agent-1"]["inject-1"]["state"], "uncertain");
}

#[test]
fn validate_method_and_validate_path_raise_different_exception_types_in_python() {
    // Finding F-R3-1: both guards live in the same `putrequest` call, but
    // they raise DIFFERENT exception types in CPython, which
    // `_Relay._exchange`'s except clauses classify differently --
    // `_validate_method` is a plain `ValueError` (caught by `except
    // (OSError, ValueError): upstream_connection_lost`, the same outcome as
    // an illegal header value), while `_validate_path` is `InvalidURL`, an
    // `http.client.HTTPException` (caught by `except
    // http.client.HTTPException: upstream_protocol_error`). Verified
    // directly against a live `python3.12`.
    let out = run_python_oracle(
        r#"
import http.client
conn = http.client.HTTPConnection("127.0.0.1", 1)
try:
    conn.putrequest("GE\x01T", "/ok")
    print("no-error")
except http.client.HTTPException:
    print("http-exception")
except ValueError:
    print("value-error")
conn2 = http.client.HTTPConnection("127.0.0.1", 1)
try:
    conn2.putrequest("GET", "/x?y\n")
    print("no-error")
except http.client.HTTPException:
    print("http-exception")
except ValueError:
    print("value-error")
"#,
    );
    assert_eq!(out.trim(), "value-error\nhttp-exception");
}

#[test]
fn content_length_with_information_separator_control_char_is_not_a_valid_int() {
    // Finding F-R3-2 (HIGH): the old `python_int` trimmed with
    // `pystr::is_space` (`str.isspace()`'s predicate), which wrongly
    // includes U+001C-U+001F; CPython's `int()` does not strip them (they
    // are ASCII, so the Unicode-to-ASCII transform stage never touches
    // them, and the final `Py_ISSPACE`-based strip does not count them as
    // whitespace either), so `int("\x1c5")` raises `ValueError`, and
    // `HTTPResponse.begin` falls back to `self.length = None` (`UntilClose`
    // framing): all 10 body bytes are relayed, not just 5. Probe from the
    // finding.
    let t = GatewayTest::new();
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: \x1c5\r\n\r\n1234567890".to_vec();
    let result = relay_via_raw_response(&t, "content-length-info-sep", response);
    assert_eq!(
        (result.status.clone(), result.body),
        (200.into(), b"1234567890".to_vec())
    );
}

#[test]
fn chunk_size_of_only_information_separator_control_chars_is_a_protocol_error() {
    // Finding F-R3-2 (HIGH): a chunk-size line of `"\x1c5"` must fail
    // `int(text, 16)` in Python (same reasoning as above), raising
    // `IncompleteRead` -> `upstream_protocol_error`; the old Rust code
    // instead parsed it as `5` and relayed `200 "hello"`.
    let t = GatewayTest::new();
    let response =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\x1c5\r\nhello\r\n0\r\n\r\n"
            .to_vec();
    let result = relay_via_raw_response(&t, "chunk-size-info-sep", response);
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (502.into(), Some("upstream_protocol_error"))
    );
}

#[test]
fn status_line_split_and_int_semantics_for_control_chars_match_python_oracle() {
    // Finding F-R3-2: U+001C-U+001F count as whitespace for
    // `line.split(None, 2)` (`str.isspace()`'s predicate, the same one
    // `_read_status`'s tokenizing uses) -- so a status token can never
    // actually *contain* one internally; splitting `"HTTP/1.1
    // 2\x1c00 OK\r\n"` therefore yields `status_text = "2"`, which is a
    // valid `int()` parse (`2`) but fails the `100 <= status <= 999` range
    // check, landing on the same `upstream_protocol_error` outcome via a
    // different route than the `Content-Length`/chunk-size cases above.
    // Confirmed directly against python3.12 below, then pinned end-to-end.
    let out = run_python_oracle(
        r#"
line = "HTTP/1.1 2\x1c00 OK\r\n"
print(line.split(None, 2))
print(int("2"))
"#,
    );
    assert_eq!(out.trim(), "['HTTP/1.1', '2', '00 OK\\r\\n']\n2");

    let t = GatewayTest::new();
    let response = b"HTTP/1.1 2\x1c00 OK\r\n\r\n".to_vec();
    let result = relay_via_raw_response(&t, "status-info-sep", response);
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (502.into(), Some("upstream_protocol_error"))
    );
}

#[test]
fn doubled_trailing_cr_in_header_block_does_not_leak_a_header_into_the_body() {
    // Finding F-R3-3: `read_line` used to pop EVERY trailing CR/LF, so the
    // line `b"\r\r\n"` collapsed to empty and was wrongly treated as the
    // header block's blank separator one line early; every header after it
    // was then read as part of the BODY instead. After the fix, `"\r\r\n"`
    // is not `_read_headers`'s exact blank-line value, so the physical byte
    // consumption (and therefore body framing) is unaffected -- but
    // re-splitting the header block on `\r\n|\r|\n` (finding F-R3-4) means
    // the bare `\r` this line contains still ends *recognition*, so
    // `Content-Type` (sharing this response's header block after the
    // doubled CR) is correctly dropped rather than becoming a header OR
    // leaking into the body. Pinned end-to-end against python3.12 by the
    // `http_framing_fuzz` differential fuzzer's `"\r\r\n"`
    // header-terminator mutation in `gateway.rs`.
    let t = GatewayTest::new();
    let response =
        b"HTTP/1.1 200 OK\r\nETag: keep-going\r\n\r\r\nContent-Type: text/plain\r\n\r\nbody"
            .to_vec();
    let result = relay_via_raw_response(&t, "doubled-cr-header-block", response);
    assert_eq!(result.status, 200);
    assert_eq!(result.body, b"body".to_vec());
    assert!(header_names(&result).contains("etag"));
    assert!(
        !header_names(&result).contains("content-type"),
        "a header after the malformed doubled-CR line must not be recognised"
    );
}

#[test]
fn header_name_with_a_space_ends_recognition_and_drops_every_later_header() {
    // Finding F-R3-4: `headerRE` requires the field-name run (ASCII
    // `0x21-0x39`/`0x3B-0x7E`) to be followed immediately by `:` -- a space
    // in the name (`"Bad Name: x"`) never matches, ending recognition
    // entirely (not merely dropping that one line): every later header,
    // even a well-formed one, is lost too. The old Rust code only checked
    // for the *presence* of a colon, so it kept "Bad Name" as a header name
    // and kept parsing every header after it.
    let t = GatewayTest::new();
    let response =
        b"HTTP/1.1 200 OK\r\nETag: before\r\nBad Name: x\r\nContent-Type: text/plain\r\n\r\nhi"
            .to_vec();
    let result = relay_via_raw_response(&t, "bad-header-name-space", response);
    assert_eq!(result.status, 200);
    assert!(
        !header_names(&result).contains("content-type"),
        "a header after the malformed name must not be recognised"
    );
}

#[test]
fn header_name_with_a_del_character_ends_recognition() {
    // Finding F-R3-4: DEL (0x7F) is likewise outside `headerRE`'s allowed
    // field-name range (`0x21-0x39`/`0x3B-0x7E`).
    let t = GatewayTest::new();
    let response =
        b"HTTP/1.1 200 OK\r\nETag: before\r\nX\x7fA: x\r\nContent-Type: text/plain\r\n\r\nhi"
            .to_vec();
    let result = relay_via_raw_response(&t, "bad-header-name-del", response);
    assert_eq!(result.status, 200);
    assert!(
        !header_names(&result).contains("content-type"),
        "a header after the malformed name must not be recognised"
    );
}

#[test]
fn header_line_with_leading_colon_is_dropped_without_ending_recognition() {
    // Finding F-R3-4: `": value"` DOES match `headerRE` (the field-name run
    // may be empty), so recognition continues past it -- but
    // `_parse_headers` drops it (`InvalidHeaderDefect("Missing header
    // name.")`) instead of recording an empty-named header, unlike the
    // "Bad Name"/DEL cases above, which fail `headerRE` itself and stop
    // recognition outright.
    let t = GatewayTest::new();
    let response =
        b"HTTP/1.1 200 OK\r\n: stray-value\r\nContent-Type: text/plain\r\n\r\nhi".to_vec();
    let result = relay_via_raw_response(&t, "leading-colon-header", response);
    assert_eq!(result.status, 200);
    assert!(
        header_names(&result).contains("content-type"),
        "a well-formed header after a dropped leading-colon line must still be recognised"
    );
    assert!(
        !result.headers.iter().any(|(k, _)| k.is_empty()),
        "the leading-colon line must not produce an empty-named header"
    );
}

#[test]
fn from_envelope_line_is_skipped_without_ending_recognition() {
    // Finding F-R3-4: a `"From "`-prefixed line matches `headerRE` (its own
    // dedicated alternative) and is always consumed as an envelope/
    // misplaced-envelope line -- never a header, but also never an end to
    // recognition. The old Rust code treated it like any other colon-less
    // line and stopped recognising headers at that point.
    let t = GatewayTest::new();
    let response = b"HTTP/1.1 200 OK\r\nFrom nobody\r\nContent-Type: text/plain\r\n\r\nhi".to_vec();
    let result = relay_via_raw_response(&t, "from-envelope-line", response);
    assert_eq!(result.status, 200);
    assert!(
        header_names(&result).contains("content-type"),
        "a header after a \"From \" envelope line must still be recognised"
    );
}

#[test]
fn embedded_bare_cr_inside_one_physical_line_splits_into_two_headers() {
    // Finding F-R3-4/F-R3-7: `_read_headers` reads by `\n` only, so
    // `"X-A: a\rETag: xyz\r\n"` is ONE physical line -- but
    // `email.feedparser` re-splits the whole header block on `\r\n|\r|\n`
    // before ever applying `headerRE`, so the embedded bare `\r` produces
    // TWO logical lines, `"X-A: a\r"` and `"ETag: xyz\r\n"`, each parsed as
    // its own header. The old Rust code read physical lines only (never
    // re-splitting), so it saw one line with a colon in the *name* position
    // colliding with nothing -- actually kept it as a single header whose
    // value contains the literal text `"a\rETag: xyz"`, never surfacing
    // `ETag` as a header of its own.
    let t = GatewayTest::new();
    let mut response = b"HTTP/1.1 200 OK\r\n".to_vec();
    response.extend_from_slice(b"X-A: a\rETag: xyz\r\n");
    response.extend_from_slice(b"\r\nhi");
    let result = relay_via_raw_response(&t, "embedded-bare-cr", response);
    assert_eq!(result.status, 200);
    let etag = result
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("etag"));
    assert_eq!(
        etag.map(|(_, v)| v.as_str()),
        Some("xyz"),
        "the embedded bare CR must split the physical line into two logical headers"
    );
}

#[test]
fn folded_continuation_response_with_a_real_crlf_fold_is_relayed_normally() {
    // Finding F-R3-7 (integration-level half): the exact value
    // `header_source_parse` assembles for a folded continuation is pinned
    // directly, at the unit level, by
    // `gateway::header_parsing_tests::folded_continuation_keeps_the_original_wire_terminator`
    // (`read_headers_block` is private to `gateway.rs`, so that test lives
    // there) -- a header value containing an embedded raw `\r`/`\n` is
    // filtered out of the *exposed* response by `HEADER_VALUE_RE` before it
    // would ever reach a `RelayResult` here regardless of whether the fold
    // preserved `\r\n` or collapsed it to `\n`, so this end-to-end probe
    // only confirms the response as a whole still parses and relays
    // normally (status/body), not the filtered-out header's own value.
    let t = GatewayTest::new();
    let response =
        b"HTTP/1.1 200 OK\r\nETag: AAAA\r\n\tBBBB\r\nContent-Length: 2\r\n\r\nhi".to_vec();
    let result = relay_via_raw_response(&t, "folded-terminator", response);
    assert_eq!(result.status, 200);
    assert_eq!(result.body, b"hi".to_vec());
    assert!(
        !result
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("etag")),
        "a header value containing an embedded raw CR/LF must not be exposed to the caller"
    );
}

#[test]
fn content_encoding_with_information_separator_prefix_is_still_accepted() {
    // Finding F-R3-8: `str::trim()` does not strip U+001C-U+001F, which
    // `str.strip()` (and this crate's own `python_strip`, already used for
    // methods and header names) does -- `Content-Encoding: \x1cidentity`
    // must still be treated as plain `identity`, not rejected as
    // unsupported.
    let t = GatewayTest::new();
    let response =
        b"HTTP/1.1 200 OK\r\nContent-Encoding: \x1cidentity\r\nContent-Length: 2\r\n\r\nhi"
            .to_vec();
    let result = relay_via_raw_response(&t, "content-encoding-info-sep", response);
    assert_eq!(
        (result.status.clone(), result.body),
        (200.into(), b"hi".to_vec())
    );
}

#[test]
fn self_referential_target_via_scheme_relative_public_url() {
    // Finding F-R3-6: `parse_authority` used to require a literal `"://"`,
    // so a scheme-relative `public_url` (`//host:port`, a shape
    // `urlsplit` accepts with `scheme == ""`) skipped the self-reference
    // comparison entirely -- failing the guard OPEN.
    let mut t = GatewayTest::new();
    t.ctx.config.extra.insert(
        "public_url".to_string(),
        serde_json::Value::String("//zeropw.invalid:8443".to_string()),
    );
    let _handle = named_connection_port(&t, "public-self-relative", "zeropw.invalid", 8443, false);
    let result = gateway::relay_for_caller(
        &t.ctx,
        "agent-1",
        "public-self-relative",
        "GET",
        "/me",
        &no_headers(),
        b"",
        None,
    );
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (501.into(), Some("self_referential_target"))
    );
}

#[test]
fn self_referential_target_treats_public_url_port_zero_as_unspecified() {
    // Finding F-R3-6: `urlsplit(...).port` returns `0` for an explicit
    // `:0`, but Python's call site is `parts.port or (443 if https else
    // 80)` -- `0` is falsy, so it falls back to the scheme default (`80`
    // for `http`) rather than being compared as port `0` itself.
    let mut t = GatewayTest::new();
    t.ctx.config.extra.insert(
        "public_url".to_string(),
        serde_json::Value::String("http://zeropw.invalid:0".to_string()),
    );
    let _handle = named_connection_port(&t, "public-self-port0", "zeropw.invalid", 80, false);
    let result = gateway::relay_for_caller(
        &t.ctx,
        "agent-1",
        "public-self-port0",
        "GET",
        "/me",
        &no_headers(),
        b"",
        None,
    );
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (501.into(), Some("self_referential_target"))
    );
}

#[test]
fn self_referential_target_via_bracketed_public_url_with_empty_port() {
    // Finding F-R4-1: `urlsplit("//[::1]:")._hostinfo` gives `port = ""`,
    // which becomes `None`, so `parts.port or (443 if https else 80)`
    // supplies the scheme default and the comparison runs normally --
    // confirmed directly against live `python3.12` (`urlsplit("//[::1]:")
    // .hostname == "::1"`, `.port is None`). The previous `parse_authority`
    // instead returned `None` for this shape (an empty port after `]:`),
    // so `self_referential_target`'s `if let Some(...)` short-circuited and
    // the public-URL comparison was never made -- the guard failed OPEN.
    let mut t = GatewayTest::new();
    t.ctx.config.extra.insert(
        "public_url".to_string(),
        serde_json::Value::String("//[::1]:".to_string()),
    );
    let _handle = named_connection_port(&t, "public-self-v6-empty-port", "::1", 80, false);
    let result = gateway::relay_for_caller(
        &t.ctx,
        "agent-1",
        "public-self-v6-empty-port",
        "GET",
        "/me",
        &no_headers(),
        b"",
        None,
    );
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (501.into(), Some("self_referential_target")),
        "a bracketed host with a colon but an empty port must still use the scheme default \
         port and run the self-reference comparison, matching real urlsplit"
    );
}

#[test]
fn invalid_bracketed_public_url_does_not_false_positive_self_referential() {
    // Finding F-R4-1: `urlsplit("//[::1]junk")` itself raises `ValueError`
    // ("Invalid IPv6 URL") -- confirmed directly against live
    // `python3.12` -- which `_self_referential_target`'s `except
    // ValueError: pass` swallows, skipping the public-URL comparison
    // entirely regardless of what `target.host`/`.port` are. The previous
    // `parse_authority` instead parsed this malformed authority as
    // `Some(("::1", 80))` (falling through to the "no colon before the
    // port" default-port arm), so a target literally at `::1:80` was
    // wrongly refused as self-referential -- a false positive Python
    // itself does not produce.
    let mut t = GatewayTest::new();
    t.ctx.config.extra.insert(
        "public_url".to_string(),
        serde_json::Value::String("//[::1]junk".to_string()),
    );
    let handle = named_connection_port(&t, "public-self-v6-invalid", "::1", 80, false);
    let result = gateway::relay(&t.ctx, &handle, "GET", "/me", &no_headers(), b"", None);
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (502.into(), Some("upstream_unreachable")),
        "must not be refused as self_referential_target (that would be the pre-fix, \
         Python-diverging false positive)"
    );
}

#[test]
fn ledger_wrong_typed_caller_entry_fails_closed_before_reaching_upstream() {
    // Finding F-R3-5 (shape 1): `{"agent-1": "oops"}` -- Python's
    // `doc.get(caller, {}).get(request_id)` raises `AttributeError` calling
    // `.get` on a `str`, uncaught, fail-closed per PORTING.md §3.5. The
    // pre-fix Rust silently treated the caller entry as absent, relayed
    // anyway (spending the credential), and never actually recorded the
    // claim -- permanently disabling idempotency for this caller while
    // reporting success.
    let t = GatewayTest::new();
    let ledger_path = t.ctx.state.path.join(gateway::LEDGER_DOC);
    std::fs::create_dir_all(ledger_path.parent().unwrap()).unwrap();
    std::fs::write(&ledger_path, br#"{"agent-1": "oops"}"#).unwrap();
    let result = t.relay_full("GET", "/me", &no_headers(), b"", None, Some("r-shape-1"));
    // An escaping built-in: `zeropw.server`'s fixed `except Exception` reply.
    assert_eq!(result.status, 500);
    assert_eq!(result.reason.as_deref(), Some("internal_error"));
    assert_eq!(
        result.json().expect("test body is valid utf-8 JSON")["error"],
        "InternalError"
    );
    assert_eq!(
        t.fake.requests().len(),
        0,
        "a corrupt ledger caller entry must refuse before reaching the upstream"
    );
}

#[test]
fn ledger_wrong_typed_request_entry_fails_closed_before_reaching_upstream() {
    // Finding F-R3-5 (shape 2): `{"agent-1": {"rid-1": "oops"}}` --
    // Python's `entry.get("updated_at", 0)` raises `AttributeError` on the
    // `str` entry, uncaught. The pre-fix Rust silently overwrote the entry
    // with a fresh well-typed one and relayed anyway.
    let t = GatewayTest::new();
    let ledger_path = t.ctx.state.path.join(gateway::LEDGER_DOC);
    std::fs::create_dir_all(ledger_path.parent().unwrap()).unwrap();
    std::fs::write(&ledger_path, br#"{"agent-1": {"r-shape-2": "oops"}}"#).unwrap();
    let result = t.relay_full("GET", "/me", &no_headers(), b"", None, Some("r-shape-2"));
    // An escaping built-in: `zeropw.server`'s fixed `except Exception` reply.
    assert_eq!(result.status, 500);
    assert_eq!(result.reason.as_deref(), Some("internal_error"));
    assert_eq!(
        result.json().expect("test body is valid utf-8 JSON")["error"],
        "InternalError"
    );
    assert_eq!(
        t.fake.requests().len(),
        0,
        "a corrupt ledger request entry must refuse before reaching the upstream"
    );
}

#[test]
fn ledger_non_numeric_updated_at_fails_closed_before_reaching_upstream() {
    // Finding F-R3-5 (shape 3): `updated_at: "soon"` -- Python's
    // `float(entry.get("updated_at", 0))` raises `ValueError`, uncaught.
    let t = GatewayTest::new();
    let ledger_path = t.ctx.state.path.join(gateway::LEDGER_DOC);
    std::fs::create_dir_all(ledger_path.parent().unwrap()).unwrap();
    std::fs::write(
        &ledger_path,
        br#"{"agent-1": {"r-shape-3": {"digest": "x", "state": "in_flight", "connection": "gh", "created_at": 1, "updated_at": "soon", "response": null}}}"#,
    )
    .unwrap();
    let result = t.relay_full("GET", "/me", &no_headers(), b"", None, Some("r-shape-3"));
    // An escaping built-in: `zeropw.server`'s fixed `except Exception` reply.
    assert_eq!(result.status, 500);
    assert_eq!(result.reason.as_deref(), Some("internal_error"));
    assert_eq!(
        result.json().expect("test body is valid utf-8 JSON")["error"],
        "InternalError"
    );
    assert_eq!(
        t.fake.requests().len(),
        0,
        "a corrupt ledger updated_at must refuse before reaching the upstream"
    );
}

#[test]
fn ledger_save_fails_closed_for_a_corrupted_entry_of_a_different_request_id() {
    // Finding F-R4-2: Python's `RequestLedger._save` evaluates
    // `float(entries[rid].get("updated_at", 0))` for *every* entry of
    // *every* caller on *every* write, not just the one being claimed --
    // so a corrupted `rid-1` entry refuses the whole save (uncaught
    // `ValueError` out of `claim`) even while claiming an unrelated
    // `rid-2`. The previous Rust `save` read `updated_at` with a plain
    // `.as_f64().unwrap_or(0.0)`, silently treating the corrupted `rid-1`
    // as already-expired (`now - 0.0 > LEDGER_TTL_SECONDS`), deleting its
    // live `in_flight` claim, and then relaying `rid-2` with a `200` where
    // Python refuses before ever contacting the upstream.
    let t = GatewayTest::new();
    let ledger_path = t.ctx.state.path.join(gateway::LEDGER_DOC);
    std::fs::create_dir_all(ledger_path.parent().unwrap()).unwrap();
    std::fs::write(
        &ledger_path,
        br#"{"agent-1": {"rid-1": {"digest": "x", "state": "in_flight", "connection": "gh", "created_at": 1, "updated_at": "soon", "response": null}}}"#,
    )
    .unwrap();
    let result = t.relay_full("GET", "/me", &no_headers(), b"", None, Some("rid-2"));
    // An escaping built-in: `zeropw.server`'s fixed `except Exception` reply.
    assert_eq!(result.status, 500);
    assert_eq!(result.reason.as_deref(), Some("internal_error"));
    assert_eq!(
        result.json().expect("test body is valid utf-8 JSON")["error"],
        "InternalError"
    );
    assert_eq!(
        t.fake.requests().len(),
        0,
        "a corrupted unrelated ledger entry must refuse the whole save before reaching the upstream"
    );
    let raw = std::fs::read_to_string(&ledger_path).unwrap();
    assert!(
        raw.contains("\"rid-1\"") && raw.contains("\"soon\"") && !raw.contains("rid-2"),
        "the ledger must be left byte-for-byte untouched on a failed save: {raw}"
    );
}

#[test]
fn ledger_save_fails_closed_for_a_corrupted_unrelated_caller() {
    // Finding F-R4-2: `_save`'s `for caller in list(doc)` walks *every*
    // caller in the document, not just the one being claimed -- a
    // wrong-typed caller value (`"agent-2": "oops"`) refuses the save even
    // while claiming a request for a completely different caller
    // (`agent-1`). The previous Rust `save` silently `continue`d past a
    // non-object caller value instead of failing closed.
    let t = GatewayTest::new();
    let ledger_path = t.ctx.state.path.join(gateway::LEDGER_DOC);
    std::fs::create_dir_all(ledger_path.parent().unwrap()).unwrap();
    std::fs::write(&ledger_path, br#"{"agent-2": "oops"}"#).unwrap();
    let result = t.relay_full("GET", "/me", &no_headers(), b"", None, Some("rid-agent1"));
    assert_eq!(result.status, 500);
    assert_eq!(result.reason.as_deref(), Some("internal_error"));
    assert_eq!(
        t.fake.requests().len(),
        0,
        "a corrupted unrelated caller must refuse the whole save before reaching the upstream"
    );
    let raw = std::fs::read_to_string(&ledger_path).unwrap();
    assert_eq!(
        raw, r#"{"agent-2": "oops"}"#,
        "the ledger must be left byte-for-byte untouched on a failed save"
    );
}

/// Like `run_python_oracle`, but pipes `stdin_data` to the script's stdin
/// (for a batch of test cases too large to embed as a `-c` argument) and
/// sets `PYTHONPATH` to the repository root so `import zeropw...` works,
/// same as `rust/tests/gateway_oracle.rs`'s `run_python`.
fn run_python_oracle_stdin(script: &str, stdin_data: &str) -> String {
    use std::io::Write as _;
    use std::process::Stdio;
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".to_string());
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf();
    let mut child = std::process::Command::new(&interpreter)
        .arg("-c")
        .arg(script)
        .env("PYTHONPATH", repo_root)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot run {interpreter}: {e}"));
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin_data.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "python stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

/// Minimal Python runner for the oracle checks above -- same technique as
/// `rust/tests/gateway_oracle.rs`'s `run_python` (not reused directly since
/// that helper lives in a separate integration-test binary and isn't
/// exported).
fn run_python_oracle(script: &str) -> String {
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".to_string());
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf();
    let output = std::process::Command::new(interpreter)
        .arg("-c")
        .arg(script)
        .current_dir(&repo_root)
        .env("PYTHONPATH", &repo_root)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run python3.12");
    assert!(
        output.status.success(),
        "python stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

// ------------------------------------------------------------- HashMap import
#[allow(unused)]
fn _anchor(_: HashMap<(), ()>) {}

// ------------------------------------------------------------ server routes
//
// Ports of `ServerRouteTests`, the `ZeroPWServer`-dependent
// `SelfReferenceTests` and `SlowClientTests`
// (`SlowClientTests.test_request_cut_at_the_deadline_is_never_acted_on`
// drives `mark_reading`/`reap_slow_clients` on mock sockets; it is ported as
// the `server.rs` unit test `request_cut_at_the_deadline_is_never_acted_on`).

/// `GatewayBase` plus `ZeroPWServer(self.ctx, quiet=False).serve_in_thread()`.
struct ServerTest {
    _tmp: TempDir,
    ctx: Arc<Context>,
    fake: FakeUpstream,
    grant: P::Grant,
    handle: String,
    now: f64,
    server: zeropw::server::ZeroPWServer,
    address: String,
}

impl ServerTest {
    fn new() -> Self {
        Self::with_limits(None)
    }

    /// `SlowClientTests.start(timeout, deadline, max_connections)`.
    fn with_limits(limits: Option<(Duration, Duration, usize)>) -> Self {
        let GatewayTest {
            _tmp,
            ctx,
            clock,
            fake,
            grant,
            handle,
        } = GatewayTest::new();
        let now = *clock.lock().unwrap();
        let ctx = Arc::new(ctx);
        let server =
            zeropw::server::ZeroPWServer::new_with_quiet(ctx.clone(), None, None, false).unwrap();
        if let Some((timeout, deadline, max_connections)) = limits {
            server.set_limits(max_connections, timeout, deadline);
        }
        server.serve_in_thread().unwrap();
        let address = server.url().trim_start_matches("http://").to_string();
        ServerTest {
            _tmp,
            ctx,
            fake,
            grant,
            handle,
            now,
            server,
            address,
        }
    }

    /// `http.client` request (keep-alive, `Host` added unless given):
    /// `(status, lower-cased headers, body)`.
    fn http(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> (u16, HashMap<String, String>, Vec<u8>) {
        let mut stream = std::net::TcpStream::connect(&self.address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = format!("{method} {path} HTTP/1.1\r\n");
        if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
            request.push_str(&format!("Host: {}\r\n", self.address));
        }
        request.push_str("Accept-Encoding: identity\r\n");
        if let Some(body) = body {
            request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        for (k, v) in headers {
            request.push_str(&format!("{k}: {v}\r\n"));
        }
        request.push_str("\r\n");
        let mut bytes = request.into_bytes();
        bytes.extend_from_slice(body.unwrap_or_default());
        stream.write_all(&bytes).unwrap();
        let mut raw = Vec::new();
        let mut chunk = [0u8; 65536];
        let split = loop {
            if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            let n = stream.read(&mut chunk).unwrap();
            assert!(n > 0, "connection closed before the response head");
            raw.extend_from_slice(&chunk[..n]);
        };
        let head = String::from_utf8_lossy(&raw[..split]).into_owned();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .unwrap()
            .split(' ')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let headers: HashMap<String, String> = lines
            .filter_map(|l| l.split_once(": "))
            .map(|(k, v)| (k.to_lowercase(), v.to_string()))
            .collect();
        let length: usize = headers
            .get("content-length")
            .map_or(0, |v| v.parse().unwrap());
        let mut body = raw[split..].to_vec();
        while body.len() < length && method != "HEAD" {
            let n = stream.read(&mut chunk).unwrap();
            assert!(n > 0);
            body.extend_from_slice(&chunk[..n]);
        }
        (status, headers, body)
    }

    /// `raw(request)`: send, then read until EOF or a 5 s timeout.
    fn raw(&self, request: &[u8]) -> Vec<u8> {
        let mut stream = std::net::TcpStream::connect(&self.address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(request).unwrap();
        let mut out = Vec::new();
        let mut chunk = [0u8; 65536];
        while let Ok(n) = stream.read(&mut chunk) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n]);
        }
        out
    }

    fn uses(&self) -> i64 {
        self.ctx.policy.get_grant(&self.grant.id).unwrap().uses
    }

    fn assert_credential_free(&self, blob: &[u8]) {
        let text = String::from_utf8_lossy(blob);
        for secret in [SECRET_A, SECRET_B] {
            for encoding in all_encodings(secret) {
                assert!(!text.contains(&encoding), "leaked {encoding}");
            }
        }
    }
}

impl Drop for ServerTest {
    fn drop(&mut self) {
        self.server.stop();
        self.fake.stop();
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn json_body(body: &[u8]) -> Value {
    serde_json::from_slice(body).unwrap()
}

#[test]
fn server_handle_in_url_route() {
    let s = ServerTest::new();
    let (status, headers, body) = s.http(
        "GET",
        &format!("/h/{}/repos?page=1", s.handle),
        &[
            ("Authorization", PLACEHOLDER),
            ("Host", "evil.invalid"),
            ("Cookie", "a=b"),
        ],
        None,
    );
    assert_eq!(
        (status, json_body(&body)),
        (
            200,
            serde_json::json!([{"name": "demo"}, {"name": "tools"}])
        )
    );
    assert_eq!(headers["content-type"], "application/json");
    assert_eq!(headers["cache-control"], "no-store");
    assert!(!headers.contains_key("set-cookie"));
    let seen = s.fake.requests().last().unwrap().clone();
    assert_eq!(seen.path, "/repos?page=1");
    assert_eq!(seen.headers["authorization"], format!("Bearer {SECRET_A}"));
    assert_eq!(seen.headers["host"], format!("127.0.0.1:{}", s.fake.port()));
    assert!(!seen.headers.contains_key("cookie"));
    let payload = br#"{"title": "via server"}"#;
    let (status, _, body) = s.http(
        "POST",
        &format!("/h/{}/repos/demo/issues", s.handle),
        &[
            ("Authorization", PLACEHOLDER),
            ("Content-Type", "application/json"),
        ],
        Some(payload),
    );
    assert_eq!(
        (status, json_body(&body)["title"].clone()),
        (201, Value::from("via server"))
    );
    assert_eq!(s.fake.requests().last().unwrap().body, payload);
    let (status, _, _) = s.http("GET", &format!("/h/{}", s.handle), &[], None);
    assert_eq!(status, 404); // "/" is relayed; the fake has no root route
    assert_eq!(s.fake.requests().last().unwrap().path, "/");
}

#[test]
fn server_header_handle_route() {
    let s = ServerTest::new();
    let (status, _, body) = s.http(
        "GET",
        "/relay/me",
        &[
            ("X-ZeroPW-Handle", &s.handle),
            ("Authorization", PLACEHOLDER),
        ],
        None,
    );
    assert_eq!(
        (status, json_body(&body)),
        (200, serde_json::json!({"login": "synthetic-user"}))
    );
    assert!(
        !s.fake
            .requests()
            .last()
            .unwrap()
            .headers
            .contains_key("x-zeropw-handle")
    );
    let (status, _, body) = s.http("GET", "/relay/me", &[], None);
    assert_eq!(
        (status, json_body(&body)["reason"].clone()),
        (401, Value::from("handle_malformed"))
    );
    let forged = format!("{}xyz", &s.handle[..s.handle.len() - 3]);
    let (status, _, body) = s.http("GET", "/relay/me", &[("X-ZeroPW-Handle", &forged)], None);
    assert_eq!(
        (status, json_body(&body)["reason"].clone()),
        (401, Value::from("handle_signature"))
    );
    let (status, _, body) = s.http(
        "GET",
        "/relay/../admin",
        &[("X-ZeroPW-Handle", &s.handle)],
        None,
    );
    assert_eq!(
        (status, json_body(&body)["reason"].clone()),
        (400, Value::from("invalid_path"))
    );
    let (status, _, body) = s.http("GET", &format!("/h/{}/debug/token", s.handle), &[], None);
    assert_eq!(
        (status, json_body(&body)["reason"].clone()),
        (502, Value::from("credential_reflection_blocked"))
    );
    s.assert_credential_free(&body);
}

#[test]
fn server_client_cannot_change_target() {
    let s = ServerTest::new();
    let response = s.raw(
        format!(
            "GET http://evil.invalid/repos HTTP/1.1\r\nHost: evil.invalid\r\n\
             X-ZeroPW-Handle: {}\r\nConnection: close\r\n\r\n",
            s.handle
        )
        .as_bytes(),
    );
    assert!(response.starts_with(b"HTTP/1.1 400"));
    assert!(contains(&response, b"absolute_uri_unsupported"));
    let response = s.raw(
        b"CONNECT evil.invalid:443 HTTP/1.1\r\nHost: evil.invalid:443\r\nConnection: close\r\n\r\n",
    );
    assert!(response.starts_with(b"HTTP/1.1 405"));
    assert!(contains(&response, b"connect_tunnel_unsupported"));
    let response = s.raw(
        format!(
            "GET /h/{}/repos HTTP/1.1\r\nHost: evil.invalid:1\r\nConnection: close\r\n\r\n",
            s.handle
        )
        .as_bytes(),
    );
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert_eq!(
        s.fake.requests().last().unwrap().headers["host"],
        format!("127.0.0.1:{}", s.fake.port())
    );
    assert_eq!(s.fake.requests().len(), 1);
}

#[test]
fn server_ambiguous_request_framing_is_refused() {
    let s = ServerTest::new();
    let h = s.handle.as_bytes();
    let smuggled = [b"GET /h/".as_slice(), h, b"/me HTTP/1.1\r\nHost: x\r\n\r\n"].concat();
    let post = [
        b"POST /h/".as_slice(),
        h,
        b"/repos/demo/issues HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n",
    ]
    .concat();
    let with = |tail: &[u8]| [post.as_slice(), tail].concat();
    let get = |line_end: &[u8], rest: &[u8]| {
        [b"GET /h/".as_slice(), h, b"/repos HTTP/1.1", line_end, rest].concat()
    };
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (
            with(b"Transfer-Encoding: gzip, chunked\r\n\r\nd\r\nHELLO-PAYLOAD\r\n0\r\n\r\n"),
            "transfer_encoding_unsupported",
        ),
        (
            with(b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
            "transfer_encoding_unsupported",
        ),
        (
            with(b"Transfer-Encoding: chunked \r\n\r\n0\r\n\r\n"),
            "transfer_encoding_unsupported",
        ),
        (
            with(b"Transfer-Encoding: identity\r\nContent-Length: 2\r\n\r\n{}"),
            "transfer_encoding_unsupported",
        ),
        (
            [
                with(
                    format!(
                        "Content-Length: 5\r\nContent-Length: {}\r\n\r\nAAAAA",
                        5 + smuggled.len()
                    )
                    .as_bytes(),
                ),
                smuggled.clone(),
            ]
            .concat(),
            "invalid_content_length",
        ),
        (
            with(b"Content-Length: 5, 5\r\n\r\nAAAAA"),
            "invalid_content_length",
        ),
        (
            with(b"Content-Length: +5\r\n\r\nAAAAA"),
            "invalid_content_length",
        ),
        (
            with(b"Content-Length: 1_0\r\n\r\nAAAAAAAAAA"),
            "invalid_content_length",
        ),
        (
            with(b"Content-Length: -1\r\n\r\n"),
            "invalid_content_length",
        ),
        (
            with(b"Transfer-Encoding : chunked\r\nContent-Length: 3\r\n\r\nabc"),
            "malformed_header",
        ),
        (
            with(b"X-A: 1\r\n Transfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}"),
            "obsolete_line_folding",
        ),
        (
            get(b"\n", b"Host: x\nConnection: close\n\n"),
            "malformed_header",
        ),
        (
            get(b"\n", b"Host: x\r\nConnection: close\r\n\r\n"),
            "malformed_request_line",
        ),
        (
            [
                b"GET  /h/".as_slice(),
                h,
                b"/repos HTTP/1.1\r\nHost: x\r\n\r\n",
            ]
            .concat(),
            "malformed_request_line",
        ),
        (
            get(b"\r\n", b"Host: x\r\nX-Nul: a\x00b\r\n\r\n"),
            "malformed_header",
        ),
    ];
    for (raw, reason) in cases {
        let response = s.raw(&raw);
        let shown = String::from_utf8_lossy(&raw[raw.len().saturating_sub(60)..]).into_owned();
        assert!(
            response.starts_with(b"HTTP/1.1 400"),
            "{reason} {shown:?}: {:?}",
            String::from_utf8_lossy(&response[..response.len().min(80)])
        );
        assert!(
            contains(&response, format!("\"reason\": \"{reason}\"").as_bytes()),
            "{reason} {shown:?}"
        );
        assert!(
            contains(&response, b"\r\nConnection: close\r\n"),
            "{reason}"
        );
        assert_eq!(
            String::from_utf8_lossy(&response)
                .matches("HTTP/1.1 ")
                .count(),
            1,
            "{reason}"
        );
    }
    assert!(s.fake.requests().is_empty());
    assert_eq!(s.uses(), 0);
}

#[test]
fn server_keep_alive_works_and_unread_or_short_bodies_never_frame_a_request() {
    let s = ServerTest::new();
    let h = &s.handle;
    let pair = s.raw(
        format!(
            "GET /h/{h}/repos HTTP/1.1\r\nHost: x\r\n\r\n\
             GET /h/{h}/me HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    );
    assert_eq!(
        String::from_utf8_lossy(&pair)
            .matches("HTTP/1.1 200 OK")
            .count(),
        2
    );
    let paths: Vec<_> = s.fake.requests().into_iter().map(|r| r.path).collect();
    assert_eq!(paths, ["/repos", "/me"]);
    // A tools call refused before its body is read closes the connection, so
    // the body is never parsed as a second (authenticated) request.
    let smuggled = format!("GET /h/{h}/repos HTTP/1.1\r\nHost: x\r\n\r\n");
    let refused = s.raw(
        format!(
            "POST /v1/tools/request HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer zpwc_wrong\r\n\
             Content-Length: {}\r\n\r\n{smuggled}",
            smuggled.len()
        )
        .as_bytes(),
    );
    assert_eq!(
        String::from_utf8_lossy(&refused)
            .matches("HTTP/1.1 ")
            .count(),
        1
    );
    assert!(contains(&refused, b"caller_token_invalid"));
    assert!(contains(&refused, b"\r\nConnection: close\r\n"));
    // A body the client cuts short is never relayed as a truncated write.
    let mut sock = std::net::TcpStream::connect(&s.address).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    sock.write_all(
        format!(
            "POST /h/{h}/repos/demo/issues HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\
             Content-Length: 100\r\n\r\n{{\"title\":\"cut\"}}"
        )
        .as_bytes(),
    )
    .unwrap();
    sock.shutdown(std::net::Shutdown::Write).unwrap();
    let mut buf = [0u8; 65536];
    assert_eq!(sock.read(&mut buf).unwrap(), 0);
    assert_eq!(s.fake.requests().len(), 2);
    assert_eq!(s.uses(), 2);
}

#[test]
fn server_tools_caller_authentication_failures_are_audited_and_alerted() {
    let s = ServerTest::new();
    let token = s.ctx.policy.create_principal("agent-2", "cli").unwrap();
    let call = |headers: &[(&str, &str)], name: &str| -> (u16, Value) {
        let (status, _, body) = s.http("POST", &format!("/v1/tools/{name}"), headers, Some(b"{}"));
        (status, json_body(&body))
    };
    let bearer = format!("Bearer {token}");
    assert_eq!(
        call(&[("Authorization", &bearer)], "list_connections").0,
        200
    );
    s.ctx.policy.disable_principal("agent-2", true).unwrap();
    type Case<'a> = (&'a [(&'a str, &'a str)], &'a str, Option<&'a str>);
    let cases: [Case; 4] = [
        (&[], "caller_token_missing", None),
        (
            &[("Authorization", "Basic c3ludGhldGlj")],
            "caller_token_missing",
            None,
        ),
        (
            &[("Authorization", "Bearer zpwc_synthetic-not-issued")],
            "caller_token_invalid",
            None,
        ),
        (
            &[("Authorization", &bearer)],
            "principal_disabled",
            Some("agent-2"),
        ),
    ];
    for (headers, reason, caller) in cases {
        let (status, payload) = call(headers, "list_connections");
        assert_eq!(
            (status, payload),
            (
                401,
                serde_json::json!({"error": "AuthFailed", "reason": reason})
            )
        );
        let record = s
            .ctx
            .audit
            .tail(1000)
            .unwrap()
            .into_iter()
            .rfind(|r| r["event"] == "auth_failed")
            .unwrap();
        assert_eq!(
            (
                record["caller"].clone(),
                record["action"].clone(),
                record["result"].clone(),
                record["reason"].clone()
            ),
            (
                caller.map_or(Value::Null, Value::from),
                Value::from("list_connections"),
                Value::from("denied"),
                Value::from(reason)
            )
        );
    }
    let alerts = s.ctx.audit.alerts(50).unwrap();
    assert!(
        alerts
            .iter()
            .any(|a| a["alert"] == "revoked_use_attempt" && a["caller"] == "agent-2")
    );
    // An agent-chosen tool name is not copied into the log.
    assert_eq!(
        call(
            &[("Authorization", "Bearer zpwc_synthetic-not-issued")],
            "free-text-name"
        )
        .0,
        401
    );
    let last = s
        .ctx
        .audit
        .tail(1000)
        .unwrap()
        .into_iter()
        .rfind(|r| r["event"] == "auth_failed")
        .unwrap();
    assert!(last["action"].is_null());
    let state =
        |name: &str| std::fs::read_to_string(s.ctx.state.path.join(name)).unwrap_or_default();
    let blob = format!(
        "{}\n{}",
        state("audit/audit.jsonl"),
        state("audit/alerts.jsonl")
    );
    assert!(!blob.contains(&token));
    assert!(!blob.contains("zpwc_synthetic-not-issued"));
    assert!(!blob.contains("free-text-name"));
    // If the failure cannot be recorded, the answer is audit_unavailable, not
    // a silent 401. (Python patches `state.append_line` to raise `OSError`;
    // a directory in the log's place makes the append fail even as root.)
    let log = s.ctx.state.path.join(zeropw::audit::AUDIT_FILE);
    let aside = s.ctx.state.path.join("audit/audit.jsonl.aside");
    std::fs::rename(&log, &aside).unwrap();
    std::fs::create_dir(&log).unwrap();
    let refused = call(&[("Authorization", &bearer)], "list_connections");
    std::fs::remove_dir(&log).unwrap();
    std::fs::rename(&aside, &log).unwrap();
    assert_eq!(
        refused,
        (
            503,
            serde_json::json!({"error": "AuditUnavailable", "reason": "audit_unavailable"})
        )
    );
}

#[test]
fn server_logs_never_contain_handles_or_queries() {
    let s = ServerTest::new();
    s.http(
        "GET",
        &format!("/h/{}/repos?token=agent-guess", s.handle),
        &[("Authorization", PLACEHOLDER)],
        None,
    );
    s.http(
        "GET",
        "/relay/me?x=1",
        &[("X-ZeroPW-Handle", &s.handle)],
        None,
    );
    let lines = s.server.log_lines();
    assert!(!lines.is_empty());
    let signature_part: String = s
        .handle
        .split('.')
        .nth(1)
        .unwrap()
        .chars()
        .take(20)
        .collect();
    for line in &lines {
        assert!(!line.contains(&s.handle));
        assert!(!line.contains(&signature_part));
        assert!(!line.contains("agent-guess"));
        assert!(!line.contains('?'));
    }
    assert!(lines.contains(&"GET /h/<handle>/...".to_string()));
    s.assert_credential_free(lines.join("\n").as_bytes());
}

// ------------------------------------------ self-reference with a live server

fn server_connection(
    s: &ServerTest,
    cid: &str,
    host: &str,
    port: u16,
    secret_id: &str,
    allow_private: bool,
) -> String {
    s.ctx
        .policy
        .create_connection(
            Connection::new(
                cid,
                "demo",
                "dev",
                "named",
                "http",
                secret_id,
                None,
                "",
                Some(
                    HttpTarget::from_stored("http", host, i64::from(port), None, allow_private)
                        .unwrap(),
                ),
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
    s.ctx
        .policy
        .create_grant("agent-1", cid, Some(3600), None)
        .unwrap()
        .id
}

#[test]
fn server_target_that_is_zeropw_itself_is_refused_before_use() {
    let s = ServerTest::new();
    let (host, port) = s.address.rsplit_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    let token = s.ctx.policy.create_principal("agent-2", "cli").unwrap();
    s.ctx
        .vault
        .put_secret("zpw-self", "api_key", token.as_bytes(), "demo", "dev", true)
        .unwrap();
    zeropw::tools::set_public_url(&s.ctx, "http://zeropw.invalid:8443").unwrap();
    // An unspecified address (0.0.0.0 / ::) is never a valid credential
    // target: refused at configuration.
    for unspecified in ["0.0.0.0", "::"] {
        let error = HttpTarget::new("http", unspecified, i64::from(port), None, false).unwrap_err();
        assert_eq!(error.reason, "target_address_not_allowed");
    }
    for (cid, target_host, target_port, secret_id) in [
        ("literal", host, port, "zpw-self"),
        ("localhost", "localhost", port, "gh-token"),
        ("public", "zeropw.invalid", 8443, "gh-token"),
    ] {
        let grant = server_connection(&s, cid, target_host, target_port, secret_id, false);
        let result = gateway::relay_for_caller(
            &s.ctx,
            "agent-1",
            cid,
            "POST",
            "/v1/tools/list_connections",
            &headers(&[("Content-Type", "application/json")]),
            b"{}",
            None,
        );
        assert_eq!(
            (result.status.clone(), result.reason.as_deref()),
            (501.into(), Some("self_referential_target")),
            "{cid}"
        );
        assert_eq!(result.json().unwrap()["error"], "Unsupported");
        assert_eq!(s.ctx.policy.get_grant(&grant).unwrap().uses, 0);
        let last = s
            .ctx
            .audit
            .tail(10_000)
            .unwrap()
            .into_iter()
            .rfind(|r| r["event"] == "http_relay")
            .unwrap();
        assert_eq!(
            (last["result"].clone(), last["reason"].clone()),
            (
                Value::from("denied"),
                Value::from("self_referential_target")
            )
        );
    }
    assert!(s.server.log_lines().is_empty()); // ZeroPW's API was never contacted
    assert!(
        !s.ctx
            .audit
            .tail(1000)
            .unwrap()
            .iter()
            .any(|r| r["event"] == "tools_list_connections")
    );
}

/// `test_peer_that_resolves_to_zeropw_is_refused_before_transmission`:
/// Python disables the literal check with a mock; here a name the literal
/// check cannot recognise resolves (resolver seam) to the live server.
#[test]
fn server_peer_that_resolves_to_zeropw_is_refused_before_transmission() {
    let s = ServerTest::new();
    let port: u16 = s.address.rsplit_once(':').unwrap().1.parse().unwrap();
    // A name (with the private-network opt-in its loopback answer needs).
    let grant = server_connection(&s, "alias", "upstream.zeropw.test", port, "gh-token", true);
    let handle = s
        .ctx
        .handles
        .issue(
            "agent-1",
            "alias",
            &grant,
            s.ctx
                .policy
                .get_connection("alias")
                .unwrap()
                .policy_version
                .to_i64()
                .unwrap(),
            300,
            Some(s.now),
        )
        .unwrap();
    let result = gateway::relay_with_resolver(
        &s.ctx,
        &handle,
        "GET",
        "/healthz",
        &no_headers(),
        b"",
        Some("r-alias"),
        resolver_answering(vec!["127.0.0.1".parse().unwrap()]),
    );
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (501.into(), Some("self_referential_target"))
    );
    assert!(s.server.log_lines().is_empty());
    let ledger = s
        .ctx
        .state
        .read_json(gateway::LEDGER_DOC, Value::Null)
        .unwrap();
    assert!(
        ledger
            .get("agent-1")
            .and_then(|e| e.get("r-alias"))
            .is_none()
    );
}

/// A loopback TCP forwarder: what neither address check can recognise as
/// ZeroPW ("another host, a proxy").
fn forwarder(to: String) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for client in listener.incoming() {
            let Ok(client) = client else { return };
            let Ok(upstream) = std::net::TcpStream::connect(&to) else {
                return;
            };
            for (mut from, mut into) in [
                (client.try_clone().unwrap(), upstream.try_clone().unwrap()),
                (upstream, client),
            ] {
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut from, &mut into);
                    let _ = into.shutdown(std::net::Shutdown::Write);
                });
            }
        }
    });
    port
}

#[test]
fn server_relayed_request_marker_is_refused_by_the_server() {
    let s = ServerTest::new();
    // Normal relays announce themselves to the upstream.
    let normal = gateway::relay(&s.ctx, &s.handle, "GET", "/me", &no_headers(), b"", None);
    assert_eq!(normal.status, 200);
    assert_eq!(
        s.fake.requests().last().unwrap().headers["via"],
        format!("1.1 {}", gateway::RELAY_PSEUDONYM)
    );
    // Even when neither address check recognises ZeroPW (another host, a
    // proxy), the server refuses.
    let proxy = forwarder(s.address.clone());
    server_connection(&s, "proxied", "127.0.0.1", proxy, "gh-token", false);
    let result = gateway::relay_for_caller(
        &s.ctx,
        "agent-1",
        "proxied",
        "GET",
        "/healthz",
        &no_headers(),
        b"",
        None,
    );
    assert_eq!(
        (result.status.clone(), result.json().unwrap()),
        (
            501.into(),
            serde_json::json!({"error": "Unsupported", "reason": "self_referential_target"})
        )
    );
    let refused: Vec<_> = s
        .ctx
        .audit
        .tail(1000)
        .unwrap()
        .into_iter()
        .filter(|r| r["event"] == "unsupported")
        .map(|r| {
            (
                r["action"].clone(),
                r["reason"].clone(),
                r["result"].clone(),
            )
        })
        .collect();
    assert_eq!(
        refused,
        [(
            Value::from("GET"),
            Value::from("self_referential_target"),
            Value::from("denied")
        )]
    );
    for (via, status) in [
        ("1.1 zeropw-relay", 501),
        ("1.0 edge, 1.1 ZEROPW-RELAY (x)", 501),
        ("1.1 proxy.example", 200),
    ] {
        assert_eq!(
            s.http("GET", "/healthz", &[("Via", via)], None).0,
            status,
            "{via}"
        );
    }
}

#[test]
fn server_closed_listener_is_forgotten() {
    let s = ServerTest::new();
    let other = zeropw::server::ZeroPWServer::new(s.ctx.clone(), None, None).unwrap();
    let port: u16 = other.url().rsplit_once(':').unwrap().1.parse().unwrap();
    assert!(
        gateway::listener_addresses()
            .iter()
            .any(|(_, p)| *p == port)
    );
    other.server_close();
    assert!(
        !gateway::listener_addresses()
            .iter()
            .any(|(_, p)| *p == port)
    );
}

// --------------------------------------------------------------- slow clients

fn seconds_until_closed(sock: &mut std::net::TcpStream, limit: Duration) -> Duration {
    let started = std::time::Instant::now();
    sock.set_read_timeout(Some(limit)).unwrap();
    let mut buf = [0u8; 65536];
    while let Ok(n) = sock.read(&mut buf) {
        if n == 0 {
            break;
        }
    }
    started.elapsed()
}

#[test]
fn server_idle_and_dribbling_clients_are_dropped() {
    let s = ServerTest::with_limits(Some((
        Duration::from_millis(300),
        Duration::from_millis(800),
        128,
    )));
    let h = s.handle.clone();
    let mut partial = std::net::TcpStream::connect(&s.address).unwrap();
    partial
        .write_all(
            format!(
                "POST /h/{h}/repos/demo/issues HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\nabc"
            )
            .as_bytes(),
        )
        .unwrap();
    assert!(seconds_until_closed(&mut partial, Duration::from_secs(5)) < Duration::from_secs(3));
    let mut dribbler = std::net::TcpStream::connect(&s.address).unwrap();
    let mut request = format!("GET /h/{h}/repos HTTP/1.1\r\nHost: x\r\nX-Slow: ").into_bytes();
    request.extend(std::iter::repeat_n(b'a', 200));
    let mut writer = dribbler.try_clone().unwrap();
    std::thread::spawn(move || {
        for byte in request {
            if writer.write_all(&[byte]).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    let elapsed = seconds_until_closed(&mut dribbler, Duration::from_secs(5));
    assert!(elapsed > Duration::from_millis(600), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
    assert!(s.fake.requests().is_empty());
    assert_eq!(s.uses(), 0);
    let ok = s.raw(
        format!("GET /h/{h}/repos HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
    );
    assert!(ok.starts_with(b"HTTP/1.1 200"));
}

#[test]
fn server_concurrent_connections_are_capped() {
    let s = ServerTest::with_limits(Some((Duration::from_secs(5), Duration::from_secs(10), 2)));
    let held: Vec<_> = (0..2)
        .map(|_| std::net::TcpStream::connect(&s.address).unwrap())
        .collect();
    // Admission happens on the accept thread; let it see both.
    std::thread::sleep(Duration::from_millis(100));
    let mut extra = std::net::TcpStream::connect(&s.address).unwrap();
    extra
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut response = Vec::new();
    let _ = extra.read_to_end(&mut response);
    assert!(
        response.starts_with(b"HTTP/1.1 503"),
        "{:?}",
        String::from_utf8_lossy(&response[..response.len().min(40)])
    );
    assert!(contains(&response, b"\"reason\": \"too_many_connections\""));
    drop(held);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let again = s.raw(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        if again.starts_with(b"HTTP/1.1 200") || std::time::Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(std::time::Instant::now() < deadline);
}

#[test]
fn server_stop_does_not_wait_for_idle_keep_alive_clients() {
    let s = ServerTest::new();
    let mut idle = std::net::TcpStream::connect(&s.address).unwrap();
    idle.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    idle.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut buf = [0u8; 65536];
    let n = idle.read(&mut buf).unwrap();
    assert!(buf[..n].starts_with(b"HTTP/1.1 200"));
    let started = std::time::Instant::now();
    s.server.stop();
    assert!(started.elapsed() < Duration::from_secs(3));
}
