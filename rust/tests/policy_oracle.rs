//! Differential tests for `zeropw::policy` against the Python prototype
//! (`zeropw/policy.py`), per `rust/PORTING.md`'s "add oracle differential
//! tests" rule for work unit D.
//!
//! Lives under `rust/tests/` as a standalone test binary (like
//! `state_dir_cross_language.rs`): `crate::oracle` is `#[cfg(test)]
//! pub(crate)` and not reachable from here, so this file has its own tiny
//! Python-running helper.
//!
//! Covers:
//! - `hash_token` / `approval_digest` byte-identical with Python.
//! - `address_block_reason` classifies a table of addresses identically to
//!   Python's `ipaddress`-based implementation (private/loopback/link-local/
//!   multicast/reserved/unspecified/IPv4-mapped IPv6/NAT64/6to4/Teredo/
//!   metadata edge cases).
//! - A state directory written by Python's `Policy` loads and authorizes
//!   identically through Rust's `Policy`, and vice versa.
//! - A table of authorization scenarios (revoked, expired, exhausted,
//!   stopped, restore-pending, stale, disabled principal, disabled
//!   connection, wrong scope) yields the same `(allowed, reason)` in both
//!   languages.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;
use zeropw::clock;
use zeropw::policy::{self, Action, ConnectionChanges, Policy};
use zeropw::store::StateDir;

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

fn py_str_literal(p: &Path) -> String {
    let s = p.to_str().expect("utf8 path");
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
}

// ---------------------------------------------------------------- digests
#[test]
fn hash_token_and_approval_digest_are_byte_identical_with_python() {
    let cases: &[(&str, &str, &str, &str, &[u8])] = &[
        ("agent-1", "gh", "DELETE", "/repos/demo", b""),
        ("agent-1", "gh", "DELETE", "/repos/demo", b"{}"),
        ("agent-1", "gh", "DELETE", "/repos/other", b""),
        ("", "", "", "", b""),
        (
            "agent-\u{e9}",
            "gh2",
            "GET",
            "/a/b?c=1",
            b"\x00\x01\xffbinary",
        ),
    ];
    let mut script = String::from("from zeropw.policy import approval_digest, hash_token\n");
    for (caller, connection, method, path, body) in cases {
        script.push_str(&format!(
            "print(approval_digest({caller:?}, {connection:?}, {method:?}, {path:?}, bytes({body:?})))\n",
            caller = caller,
            connection = connection,
            method = method,
            path = path,
            body = body,
        ));
    }
    let tokens = [
        "zpwc_abc123".to_string(),
        String::new(),
        format!("zpwc_{}", "a".repeat(64)),
    ];
    for token in &tokens {
        script.push_str(&format!("print(hash_token({token:?}))\n"));
    }
    let out = run_python(&script);
    let mut lines = out.lines();
    for (caller, connection, method, path, body) in cases {
        let want = lines.next().unwrap();
        let got = policy::approval_digest(caller, connection, method, path, body);
        assert_eq!(
            got,
            want,
            "approval_digest{:?}",
            (caller, connection, method, path, body)
        );
    }
    for token in &tokens {
        let want = lines.next().unwrap();
        let got = policy::hash_token(token);
        assert_eq!(got, want, "hash_token({token:?})");
    }
}

// ------------------------------------------------------- address classification
#[test]
fn address_block_reason_matches_python_for_address_table() {
    let addresses: &[&str] = &[
        // public
        "8.8.8.8",
        "1.1.1.1",
        "2001:4860:4860::8888",
        // private / RFC 1918 and friends
        "10.0.0.1",
        "172.16.0.5",
        "192.168.1.1",
        "127.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "224.0.0.1",
        "100.64.0.1",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "198.18.0.1",
        "240.0.0.1",
        // exceptions to the private list (still global)
        "192.0.0.9",
        "192.0.0.10",
        // metadata / link-local -- always blocked
        "169.254.169.254",
        "169.254.1.1",
        "100.100.100.200",
        "168.63.129.16",
        // IPv6
        "::1",
        "::",
        "fe80::1",
        "fec0::1",
        "2001:db8::1",
        "2001::1",
        "ff02::1",
        "fc00::1",
        "3fff::1",
        "2001:1::1",
        "2001:3::1",
        // IPv6 carrying an embedded IPv4
        "64:ff9b::8.8.8.8",
        "64:ff9b::169.254.169.254",
        "64:ff9b:1::8.8.8.8",
        "64:ff9b:1::169.254.169.254",
        "::ffff:8.8.8.8",
        "::ffff:169.254.169.254",
        "::ffff:0:8.8.8.8",
        "::ffff:0:169.254.169.254",
        "2002:0808:0808::",
        "2002:a9fe:a9fe::",                     // 6to4 embedding 169.254.169.254
        "2001:0:4136:e378:8000:63bf:3fff:fdd2", // teredo, embeds a client IP
        // provider metadata over IPv6
        "fd00:ec2::254",
        "fd00:ec2::23",
        "fd20:ce::254",
        "fd00:c1::a9fe:a9fe",
    ];

    let script = format!(
        "import ipaddress\nfrom zeropw.policy import address_block_reason\naddrs = {addrs:?}\nfor a in addrs:\n    addr = ipaddress.ip_address(a)\n    print(address_block_reason(addr, False), address_block_reason(addr, True))\n",
        addrs = addresses,
    );
    let out = run_python(&script);
    let mut lines = out.lines();
    for addr_str in addresses {
        let want = lines.next().unwrap();
        let addr: IpAddr = addr_str
            .parse()
            .expect("std parses every address in this table");
        let got_private = policy::address_block_reason(addr, false);
        let got_public = policy::address_block_reason(addr, true);
        let got = format!(
            "{} {}",
            got_private
                .map(str::to_string)
                .unwrap_or_else(|| "None".to_string()),
            got_public
                .map(str::to_string)
                .unwrap_or_else(|| "None".to_string()),
        );
        assert_eq!(got, want, "address_block_reason mismatch for {addr_str}");
    }
}

// ----------------------------------------------------- state directory round trip
fn python_setup_and_grant(state_path: &Path) -> String {
    let out = run_python(&format!(
        r#"
from zeropw.store import StateDir
from zeropw import policy as P

state = StateDir({path})
state.create()
policy = P.Policy(state, clock=lambda: 1700000000.0)
policy.create_principal("agent-1")
conn = P.Connection(
    id="gh", project="demo", environment="dev", service="fake-github", kind="http",
    secret_id="gh-token", secret_version=None, description="demo",
    http_target=P.HttpTarget("http", "127.0.0.1", 8080),
    http_auth=P.HttpAuth("bearer"),
    http_scope=P.HttpScope(("GET", "POST"), ("/repos", "/me"), ("DELETE",)),
    ssh_target=None, cli=None, policy_version=0, status="active", created_at="", updated_at="",
)
policy.create_connection(conn)
grant = policy.create_grant("agent-1", "gh", 3600, None)
print(grant.id)
"#,
        path = py_str_literal(state_path),
    ));
    out.lines().next().unwrap().to_string()
}

#[test]
fn state_written_by_python_authorizes_identically_in_rust() {
    let tmp = TempDir::new().unwrap();
    let state_path = tmp.path().join("state");
    let grant_id = python_setup_and_grant(&state_path);

    let state = StateDir::new(&state_path);
    let policy = Policy::new(&state, clock::fixed(1_700_000_000.0));

    let allowed = policy
        .evaluate(
            "agent-1",
            "gh",
            &Action::http("GET", "/repos"),
            Some(&grant_id),
        )
        .unwrap();
    assert!(allowed.allowed);
    assert_eq!(allowed.reason, "allowed");

    let denied = policy
        .evaluate(
            "agent-1",
            "gh",
            &Action::http("PUT", "/repos"),
            Some(&grant_id),
        )
        .unwrap();
    assert!(!denied.allowed);
    assert_eq!(denied.reason, "method_not_allowed");

    let grant = policy
        .consume(
            &grant_id,
            None,
            None,
            Some(Action::http("GET", "/repos")),
            None,
        )
        .expect("the grant Python wrote is usable from Rust");
    assert_eq!(grant.uses, 1);

    // Python must see the use Rust just recorded.
    let out = run_python(&format!(
        r#"
from zeropw.store import StateDir
from zeropw import policy as P
state = StateDir({path})
policy = P.Policy(state, clock=lambda: 1700000000.0)
print(policy.get_grant("{grant_id}").uses)
"#,
        path = py_str_literal(&state_path),
        grant_id = grant_id,
    ));
    assert_eq!(out.trim(), "1");
}

#[test]
fn state_written_by_rust_authorizes_identically_in_python() {
    let tmp = TempDir::new().unwrap();
    let state_path = tmp.path().join("state");
    let state = StateDir::new(&state_path);
    state.create().unwrap();
    let policy = Policy::new(&state, clock::fixed(1_700_000_000.0));
    policy.create_principal("agent-1", "default").unwrap();
    let conn = policy::Connection::new(
        "gh",
        "demo",
        "dev",
        "fake-github",
        "http",
        "gh-token",
        None,
        "demo",
        Some(policy::HttpTarget::new("http", "127.0.0.1", 8080, None, false).unwrap()),
        Some(policy::HttpAuth::bearer()),
        Some(
            policy::HttpScope::new(
                Some(vec!["GET".into(), "POST".into()]),
                Some(vec!["/repos".into(), "/me".into()]),
                vec!["DELETE".into()],
            )
            .unwrap(),
        ),
        None,
        None,
        0,
        "active",
        "",
        "",
    )
    .unwrap();
    policy.create_connection(conn).unwrap();
    let grant = policy
        .create_grant("agent-1", "gh", Some(3600), None)
        .unwrap();

    let out = run_python(&format!(
        r#"
from zeropw.store import StateDir
from zeropw import policy as P
state = StateDir({path})
policy = P.Policy(state, clock=lambda: 1700000000.0)
d1 = policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"), "{grant_id}")
print(d1.allowed, d1.reason)
d2 = policy.evaluate("agent-1", "gh", P.Action("http", "PUT", "/repos"), "{grant_id}")
print(d2.allowed, d2.reason)
g = policy.consume("{grant_id}", action=P.Action("http", "GET", "/repos"))
print(g.uses)
"#,
        path = py_str_literal(&state_path),
        grant_id = grant.id,
    ));
    let mut lines = out.lines();
    assert_eq!(lines.next().unwrap(), "True allowed");
    assert_eq!(lines.next().unwrap(), "False method_not_allowed");
    assert_eq!(lines.next().unwrap(), "1");

    // Rust must see the use Python just recorded.
    let after = policy.get_grant(&grant.id).unwrap();
    assert_eq!(after.uses, 1);
}

// --------------------------------------------------- authorization scenarios
/// One `(name, python_setup_block)` pair. Each block runs against its own
/// fresh state dir (`state.create()` already done) with `policy`/`Action`
/// bound, and must `print(decision.allowed, decision.reason)` for the
/// evaluate() call that exercises the scenario.
const SCENARIOS: &[(&str, &str)] = &[
    (
        "revoked",
        r#"
grant = policy.create_grant("agent-1", "gh", 3600, None)
policy.revoke_grant(grant.id)
d = policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"), grant.id)
print(d.allowed, d.reason)
"#,
    ),
    (
        "expired",
        r#"
grant = policy.create_grant("agent-1", "gh", 10, None)
clock_box[0] += 10
d = policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"), grant.id)
print(d.allowed, d.reason)
"#,
    ),
    (
        "exhausted",
        r#"
grant = policy.create_grant("agent-1", "gh", 3600, 1)
policy.consume(grant.id, action=P.Action("http", "GET", "/repos"))
d = policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"), grant.id)
print(d.allowed, d.reason)
"#,
    ),
    (
        "stopped",
        r#"
grant = policy.create_grant("agent-1", "gh", 3600, None)
policy.stop_all()
d = policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"), grant.id)
print(d.allowed, d.reason)
"#,
    ),
    (
        "restore_pending",
        r#"
grant = policy.create_grant("agent-1", "gh", 3600, None)
policy.set_restore_pending(True)
d = policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"), grant.id)
print(d.allowed, d.reason)
"#,
    ),
    (
        "stale",
        r#"
grant = policy.create_grant("agent-1", "gh", 3600, None)
policy.update_connection("gh", http_scope=P.HttpScope(None, ("/repos", "/me"), ("DELETE",)))
d = policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"), grant.id)
print(d.allowed, d.reason)
"#,
    ),
    (
        "principal_disabled",
        r#"
grant = policy.create_grant("agent-1", "gh", 3600, None)
policy.disable_principal("agent-1")
d = policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"), grant.id)
print(d.allowed, d.reason)
"#,
    ),
    (
        "connection_disabled",
        r#"
grant = policy.create_grant("agent-1", "gh", 3600, None)
policy.disable_connection("gh")
d = policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"), grant.id)
print(d.allowed, d.reason)
"#,
    ),
    (
        "wrong_scope_method",
        r#"
grant = policy.create_grant("agent-1", "gh", 3600, None)
d = policy.evaluate("agent-1", "gh", P.Action("http", "DELETE", "/repos"), grant.id)
print(d.allowed, d.reason)
"#,
    ),
    (
        "wrong_scope_path",
        r#"
grant = policy.create_grant("agent-1", "gh", 3600, None)
d = policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/admin"), grant.id)
print(d.allowed, d.reason)
"#,
    ),
];

fn python_scenario(name: &str, body: &str) -> (bool, String) {
    let script = format!(
        r#"
import tempfile, pathlib
from zeropw.store import StateDir
from zeropw import policy as P

tmp = tempfile.TemporaryDirectory()
state = StateDir(pathlib.Path(tmp.name) / "state")
state.create()
clock_box = [1700000000.0]
policy = P.Policy(state, clock=lambda: clock_box[0])
policy.create_principal("agent-1")
conn = P.Connection(
    id="gh", project="demo", environment="dev", service="fake-github", kind="http",
    secret_id="gh-token", secret_version=None, description="demo",
    http_target=P.HttpTarget("http", "127.0.0.1", 8080),
    http_auth=P.HttpAuth("bearer"),
    http_scope=P.HttpScope(("GET", "POST"), ("/repos", "/me"), ()),
    ssh_target=None, cli=None, policy_version=0, status="active", created_at="", updated_at="",
)
policy.create_connection(conn)
{body}
"#,
    );
    let out = run_python(&script);
    let line = out.trim();
    let (allowed, reason) = line.split_once(' ').unwrap_or((line, ""));
    let _ = name;
    (allowed == "True", reason.to_string())
}

fn rust_connection() -> policy::Connection {
    policy::Connection::new(
        "gh",
        "demo",
        "dev",
        "fake-github",
        "http",
        "gh-token",
        None,
        "demo",
        Some(policy::HttpTarget::new("http", "127.0.0.1", 8080, None, false).unwrap()),
        Some(policy::HttpAuth::bearer()),
        Some(
            policy::HttpScope::new(
                Some(vec!["GET".into(), "POST".into()]),
                Some(vec!["/repos".into(), "/me".into()]),
                vec![],
            )
            .unwrap(),
        ),
        None,
        None,
        0,
        "active",
        "",
        "",
    )
    .unwrap()
}

fn rust_scenario(name: &str) -> (bool, String) {
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let clock_val = std::sync::Arc::new(std::sync::Mutex::new(1_700_000_000.0));
    let clock = {
        let clock_val = clock_val.clone();
        std::sync::Arc::new(move || *clock_val.lock().unwrap()) as zeropw::clock::Clock
    };
    let policy = Policy::new(&state, clock);
    policy.create_principal("agent-1", "default").unwrap();
    policy.create_connection(rust_connection()).unwrap();

    let decision = match name {
        "revoked" => {
            let grant = policy
                .create_grant("agent-1", "gh", Some(3600), None)
                .unwrap();
            policy.revoke_grant(&grant.id).unwrap();
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id),
                )
                .unwrap()
        }
        "expired" => {
            let grant = policy
                .create_grant("agent-1", "gh", Some(10), None)
                .unwrap();
            *clock_val.lock().unwrap() += 10.0;
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id),
                )
                .unwrap()
        }
        "exhausted" => {
            let grant = policy
                .create_grant("agent-1", "gh", Some(3600), Some(1))
                .unwrap();
            policy
                .consume(
                    &grant.id,
                    None,
                    None,
                    Some(Action::http("GET", "/repos")),
                    None,
                )
                .unwrap();
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id),
                )
                .unwrap()
        }
        "stopped" => {
            let grant = policy
                .create_grant("agent-1", "gh", Some(3600), None)
                .unwrap();
            policy.stop_all().unwrap();
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id),
                )
                .unwrap()
        }
        "restore_pending" => {
            let grant = policy
                .create_grant("agent-1", "gh", Some(3600), None)
                .unwrap();
            policy.set_restore_pending(true).unwrap();
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id),
                )
                .unwrap()
        }
        "stale" => {
            let grant = policy
                .create_grant("agent-1", "gh", Some(3600), None)
                .unwrap();
            let scope = policy::HttpScope::new(
                None,
                Some(vec!["/repos".into(), "/me".into()]),
                vec!["DELETE".into()],
            )
            .unwrap();
            policy
                .update_connection("gh", ConnectionChanges::new().http_scope(Some(scope)))
                .unwrap();
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id),
                )
                .unwrap()
        }
        "principal_disabled" => {
            let grant = policy
                .create_grant("agent-1", "gh", Some(3600), None)
                .unwrap();
            policy.disable_principal("agent-1", true).unwrap();
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id),
                )
                .unwrap()
        }
        "connection_disabled" => {
            let grant = policy
                .create_grant("agent-1", "gh", Some(3600), None)
                .unwrap();
            policy.disable_connection("gh").unwrap();
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id),
                )
                .unwrap()
        }
        "wrong_scope_method" => {
            let grant = policy
                .create_grant("agent-1", "gh", Some(3600), None)
                .unwrap();
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("DELETE", "/repos"),
                    Some(&grant.id),
                )
                .unwrap()
        }
        "wrong_scope_path" => {
            let grant = policy
                .create_grant("agent-1", "gh", Some(3600), None)
                .unwrap();
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/admin"),
                    Some(&grant.id),
                )
                .unwrap()
        }
        other => panic!("unknown scenario {other}"),
    };
    (decision.allowed, decision.reason.to_string())
}

#[test]
fn authorization_scenarios_match_python() {
    for (name, body) in SCENARIOS {
        let want = python_scenario(name, body);
        let got = rust_scenario(name);
        assert_eq!(got, want, "scenario {name}");
    }
}
