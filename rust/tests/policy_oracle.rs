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

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use tempfile::TempDir;
use zeropw::clock;
use zeropw::policy::{
    self, Action, CliProfile, Connection, ConnectionChanges, HttpAuth, HttpScope, HttpTarget,
    Policy, SshTarget,
};
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

/// A Python `str` literal for `s`, safe to splice into a `python3.12 -c`
/// script for *any* content, including control characters. Rust's `{:?}`
/// (`Debug`) escaping is not a safe substitute here: it agrees with Python's
/// string-escape syntax for the handful of characters both languages give a
/// short escape (`\0`, `\n`, `\r`, `\t`, `\\`, `\"`), but a character outside
/// that set (e.g. `\x1f`) becomes Rust's own `\u{1f}` syntax, which Python's
/// tokenizer does not recognise as an escape at all.
fn py_str_literal_any(s: &str) -> String {
    let mut out = String::from("'");
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('\'');
    out
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

// ------------------------------------------------------------------- D-1
// `HEADER_NAME_RE`/`CliProfile`'s env-name pattern are matched with Python
// `.match()`, which (with no `.strip()` first) also accepts one trailing
// `"\n"`, unlike `SshTarget`'s username check (`.fullmatch()`, deliberately
// exempt) or `HOST_RE` (always matched post-`.strip()`, so the newline is
// already gone by then).
#[test]
fn header_name_and_cli_env_name_accept_one_trailing_newline_like_python_match() {
    let script = "\
from zeropw import policy as P
from zeropw.errors import InvalidInput


def probe(fn):
    try:
        fn()
        print(\"OK\")
    except InvalidInput as e:
        print(f\"ERR:{e.reason}\")


probe(lambda: P.HttpAuth(\"header\", header_name=\"X-Custom\\n\"))
probe(lambda: P.HttpAuth(\"header\", header_name=\"X-Custom\\n\\n\"))
probe(lambda: P.CliProfile(\"git\", \"http\", base_url_env=\"FOO\\n\"))
probe(lambda: P.CliProfile(\"git\", \"http\", extra_env={\"SSH_AUTH_SOCK\\n\": \"x\"}))
";
    let out = run_python(script);
    assert_eq!(
        out.lines().collect::<Vec<_>>(),
        vec!["OK", "ERR:invalid_header_name", "OK", "OK"]
    );

    // Rust: the same four cases, the same outcomes, and (for the accepted
    // ones) the stored value keeps the trailing newline exactly like Python.
    let auth = HttpAuth::new("header", Some("X-Custom\n".into()), None, None).unwrap();
    assert_eq!(auth.header_name.as_deref(), Some("X-Custom\n"));
    assert!(HttpAuth::new("header", Some("X-Custom\n\n".into()), None, None).is_err());

    let cli =
        CliProfile::new("git", "http", Some("FOO\n".to_string()), Default::default()).unwrap();
    assert_eq!(cli.base_url_env, "FOO\n");

    // `extra_env={"SSH_AUTH_SOCK\n": "x"}`: the trailing-newline key is
    // *not* `"SSH_AUTH_SOCK"`, so it escapes the reserved-name membership
    // check too (`key == "SSH_AUTH_SOCK"` is false) and is accepted.
    let mut extra = std::collections::BTreeMap::new();
    extra.insert("SSH_AUTH_SOCK\n".to_string(), "x".to_string());
    let cli2 = CliProfile::new("git", "http", None, extra).unwrap();
    assert_eq!(
        cli2.extra_env.get("SSH_AUTH_SOCK\n").map(String::as_str),
        Some("x")
    );
}

// ------------------------------------------------------------------- D-2
// `_validate_host`'s `host.strip().lower()`: `str.strip()` removes every
// `str.isspace()` character, including the four bidirectional-class-`B`/`S`
// ASCII separators `\x1c`-`\x1f` that Rust's `char::is_whitespace()` does
// not treat as whitespace.
#[test]
fn validate_host_strips_python_isspace_characters_rust_trim_does_not() {
    let script = "\
from zeropw import policy as P
from zeropw.errors import InvalidInput

for host in (\"\\x1cexample.com\", \"example.com\\x1f\", \"\\u3000example.com\", \"EXAMPLE.COM\"):
    try:
        print(repr(P._validate_host(host)))
    except InvalidInput as e:
        print(f\"ERR:{e.reason}\")
";
    let out = run_python(script);
    let want: Vec<&str> = out.lines().collect();
    assert_eq!(
        want,
        vec![
            "'example.com'",
            "'example.com'",
            "'example.com'",
            "'example.com'",
        ]
    );

    // `HttpTarget`'s `host` field runs the exact same `_validate_host`; the
    // control-character and full-width-space cases would be rejected
    // (`invalid_host`) by a plain `str::trim()`, since neither is Unicode
    // `White_Space`.
    for host in [
        "\x1cexample.com",
        "example.com\x1f",
        "\u{3000}example.com",
        "EXAMPLE.COM",
    ] {
        let target = HttpTarget::new("https", host, 443, None, false).unwrap();
        assert_eq!(target.host, "example.com", "host={host:?}");
    }
}

// ------------------------------------------------------------------- D-3
// `_canonical_host_key` (`SshTarget.host_keys`) now goes through
// `crate::sshwire`'s general-purpose `authorized_keys` parser instead of a
// duplicate, self-contained one; this checks a table of lines (valid,
// comment, options, tabs, wrong type, bad base64, trailing data, control
// characters, newline "comment") against Python end to end.
#[test]
fn canonical_host_key_matches_python_over_a_table_of_lines() {
    let good = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBIiixV5ZS+n29XxvfIT9WV3jN8gvyc0/eOKlxJvpz20";
    let lines: Vec<String> = vec![
        good.to_string(),
        format!("{good}  "),
        format!("{good} deploy key"),
        // a leading options field before the key type: the caller
        // (`_canonical_host_key`) requires the line to start with
        // `"ssh-ed25519 "`, so any leading options field already fails
        // that check before the parser ever runs.
        "command=\"/bin/true\" ssh-ed25519 AAAA".to_string(),
        // tab-separated fields are still parsed by `parse_authorized_key_entry`
        good.replacen(' ', "\t", 1),
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDT".to_string(),
        "ssh-ed25519 not-base64!".to_string(),
        // an embedded newline (no genuine wire trailing data reached: the
        // control-character check runs first, exactly like Python's
        // `_CONTROL_CHARS_RE.search(line)`)
        format!("{good}\n[victim.example.com]:22 {good}"),
        format!("{good}\x00"),
        format!("{good} evil\ncomment"),
        // genuine wire-level trailing data: extra bytes appended after the
        // 32-byte key inside the base64 blob itself (no control character
        // involved, so this one actually reaches the parser's own
        // trailing-data check)
        {
            let (_, b64) = good.split_once(' ').unwrap();
            let mut blob = BASE64_STANDARD.decode(b64).unwrap();
            blob.extend_from_slice(b"\x00\x00\x00\x01Z");
            format!("ssh-ed25519 {}", BASE64_STANDARD.encode(blob))
        },
    ];
    let mut script =
        "from zeropw import policy as P\nfrom zeropw.errors import InvalidInput\n".to_string();
    for line in &lines {
        let literal = py_str_literal_any(line);
        script.push_str(&format!(
            "try:\n    print(repr(P._canonical_host_key({literal})))\nexcept InvalidInput as e:\n    print(f'ERR:{{e.reason}}')\n"
        ));
    }
    let out = run_python(&script);
    let want: Vec<&str> = out.lines().collect();
    assert_eq!(want.len(), lines.len());

    for (line, want) in lines.iter().zip(want.iter()) {
        let got = SshTarget::new("127.0.0.1", 22, "deploy", vec![line.clone()]);
        match got {
            Ok(target) => {
                let expected = &want[1..want.len() - 1]; // strip Python repr's quotes
                assert_eq!(
                    target.host_keys[0], *expected,
                    "line={line:?} want={want:?}"
                );
            }
            Err(e) => {
                assert_eq!(*want, format!("ERR:{}", e.reason), "line={line:?}");
            }
        }
    }
}

// ------------------------------------------------------------------- D-5
// `Connection.public_view()["scope"]["methods"]`/`"path_prefixes"` is
// `"all"` when the stored value is falsy -- `None` *or* an empty list --
// not merely `None`. `methods=()` is legal (`HttpScope.__post_init__` only
// rejects an empty `path_prefixes`, not an empty `methods`), so it is a
// real, reachable case, not just a hypothetical.
#[test]
fn public_view_scope_treats_empty_methods_as_all_like_python() {
    let script = r#"
import json
from zeropw import policy as P

c = P.Connection(
    id="gh", project="demo", environment="dev", service="fake-github", kind="http",
    secret_id="gh-token", secret_version=None, description="demo",
    http_target=P.HttpTarget("http", "127.0.0.1", 8080),
    http_auth=P.HttpAuth("bearer"),
    http_scope=P.HttpScope(methods=(), path_prefixes=("/repos",)),
    ssh_target=None, cli=None, policy_version=0, status="active", created_at="", updated_at="",
)
print(json.dumps(c.public_view()["scope"]))
"#;
    let out = run_python(script);
    assert_eq!(
        out.trim(),
        r#"{"methods": "all", "path_prefixes": ["/repos"], "confirm_methods": []}"#
    );

    let conn = Connection::new(
        "gh",
        "demo",
        "dev",
        "fake-github",
        "http",
        "gh-token",
        None,
        "demo",
        Some(HttpTarget::new("http", "127.0.0.1", 8080, None, false).unwrap()),
        Some(HttpAuth::bearer()),
        Some(HttpScope::new(Some(vec![]), Some(vec!["/repos".into()]), vec![]).unwrap()),
        None,
        None,
        0,
        "active",
        "",
        "",
    )
    .unwrap();
    let view = conn.public_view();
    assert_eq!(view["scope"]["methods"], serde_json::json!("all"));
    assert_eq!(
        view["scope"]["path_prefixes"],
        serde_json::json!(["/repos"])
    );
    assert_eq!(view["scope"]["confirm_methods"], serde_json::json!([]));
}

// ------------------------------------------------------------------- D-6
// `Connection.from_dict` (and the nested-model `build()` it uses) re-runs
// full dataclass `__post_init__` validation on a stored document, so a
// malformed stored field raises the *same documented* `InvalidInput` a bad
// value passed to the constructor directly would -- not a generic
// `state_corrupt` -- except where Python itself lets a built-in exception
// escape uncaught (PORTING.md §3.5) or silently accepts a value Rust's
// typed fields cannot represent (a genuine, narrower residual; see
// `DEVIATIONS.md`).
#[test]
fn connection_from_value_matches_python_over_a_table_of_malformed_documents() {
    let script = r#"
import json
from zeropw import policy as P
from zeropw.errors import InvalidInput


def http_doc():
    c = P.Connection(
        id="gh", project="demo", environment="dev", service="fake-github", kind="http",
        secret_id="gh-token", secret_version=None, description="demo connection",
        http_target=P.HttpTarget("http", "127.0.0.1", 8080),
        http_auth=P.HttpAuth("bearer"),
        http_scope=P.HttpScope(("GET", "POST"), ("/repos", "/me"), ("DELETE",)),
        ssh_target=None, cli=None, policy_version=0, status="active", created_at="", updated_at="",
    )
    return json.loads(json.dumps(c.to_dict()))


def ssh_doc():
    c = P.Connection(
        id="box", project="demo", environment="dev", service="ssh-box", kind="ssh",
        secret_id="box-key", secret_version=None, description="",
        http_target=None, http_auth=None, http_scope=None,
        ssh_target=P.SshTarget(
            "127.0.0.1", 22, "deploy",
            ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA host",),
        ),
        cli=None, policy_version=0, status="active", created_at="", updated_at="",
    )
    return json.loads(json.dumps(c.to_dict()))


def cli_doc():
    c = P.Connection(
        id="gh", project="demo", environment="dev", service="fake-github", kind="http",
        secret_id="gh-token", secret_version=None, description="demo connection",
        http_target=P.HttpTarget("http", "127.0.0.1", 8080),
        http_auth=P.HttpAuth("bearer"),
        http_scope=P.HttpScope(("GET", "POST"), ("/repos", "/me"), ("DELETE",)),
        ssh_target=None, cli=P.CliProfile("git", "http"),
        policy_version=0, status="active", created_at="", updated_at="",
    )
    return json.loads(json.dumps(c.to_dict()))


def probe(label, doc, extract):
    try:
        c = P.Connection.from_dict(doc)
        print(f"{label} OK {extract(c)!r}")
    except InvalidInput as e:
        print(f"{label} InvalidInput {e.reason}")
    except Exception as e:
        print(f"{label} {type(e).__name__}")


noop = lambda c: None

d = http_doc(); d["http_target"]["port"] = "8080"
probe("port_str", d, noop)
d = http_doc(); d["http_target"]["port"] = 8080.0
probe("port_float", d, noop)
d = http_doc(); d["http_target"]["port"] = True
probe("port_bool", d, noop)
d = http_doc(); d["http_target"]["port"] = 2 ** 70
probe("port_huge", d, noop)
d = http_doc(); d["http_target"]["allow_private_network"] = None
probe("apn_null", d, noop)
d = http_doc(); d["http_target"]["allow_private_network"] = 1
probe("apn_int", d, noop)
d = http_doc(); d["http_target"]["scheme"] = 5
probe("scheme_int", d, noop)
d = http_doc(); d["http_target"]["host"] = 5
probe("host_int", d, noop)

d = ssh_doc(); d["ssh_target"]["username"] = 5
probe("ssh_username_int", d, noop)
d = ssh_doc(); d["ssh_target"]["host_keys"] = ""
probe("host_keys_empty_str", d, noop)
d = ssh_doc(); d["ssh_target"]["host_keys"] = "somestring"
probe("host_keys_nonempty_str", d, noop)
d = ssh_doc(); d["ssh_target"]["host_keys"] = [5]
probe("host_keys_nonstr_element", d, noop)

d = cli_doc(); d["cli"]["extra_env"] = {"FOO": 5}
probe("extra_env_value_int", d, noop)
d = cli_doc(); d["cli"]["base_url_env"] = 5
probe("base_url_env_int", d, noop)

d = http_doc(); d["http_auth"]["mode"] = "header"; d["http_auth"]["header_name"] = 0
probe("header_name_falsy_int", d, noop)
d = http_doc(); d["http_auth"]["mode"] = "basic"; d["http_auth"]["basic_username"] = False
probe("basic_username_falsy_bool", d, noop)

d = http_doc(); d["policy_version"] = "3"
probe("policy_version_str", d, lambda c: c.policy_version)
d = http_doc(); d["policy_version"] = 3.7
probe("policy_version_float", d, lambda c: c.policy_version)
d = http_doc(); d["policy_version"] = True
probe("policy_version_bool", d, lambda c: c.policy_version)
d = http_doc(); d["policy_version"] = "abc"
probe("policy_version_bad_str", d, noop)
d = http_doc(); del d["policy_version"]
probe("policy_version_missing", d, noop)

d = http_doc(); d["secret_version"] = "abc"
probe("secret_version_str", d, lambda c: c.secret_version)
d = http_doc(); d["secret_version"] = 5
probe("secret_version_int", d, lambda c: c.secret_version)
"#;
    let out = run_python(script);
    let lines: std::collections::HashMap<&str, &str> = out
        .lines()
        .map(|l| l.split_once(' ').expect("label + rest"))
        .collect();
    let want = |label: &str| -> &str {
        lines
            .get(label)
            .unwrap_or_else(|| panic!("no line for {label}"))
    };

    // Every case expected to raise `InvalidInput` in Python is confirmed
    // here so a future edit to the Python probe script can't silently
    // change what's being tested without failing loudly.
    for label in [
        "port_str",
        "port_float",
        "port_bool",
        "port_huge",
        "apn_null",
        "apn_int",
        "scheme_int",
        "host_int",
        "ssh_username_int",
        "host_keys_empty_str",
        "host_keys_nonempty_str",
        "host_keys_nonstr_element",
        "extra_env_value_int",
        "header_name_falsy_int",
        "basic_username_falsy_bool",
    ] {
        assert!(
            want(label).starts_with("InvalidInput "),
            "{label}: {}",
            want(label)
        );
    }
    assert_eq!(want("port_str"), "InvalidInput invalid_port");
    assert_eq!(want("port_float"), "InvalidInput invalid_port");
    assert_eq!(want("port_bool"), "InvalidInput invalid_port");
    assert_eq!(want("port_huge"), "InvalidInput invalid_port");
    assert_eq!(
        want("apn_null"),
        "InvalidInput invalid_allow_private_network"
    );
    assert_eq!(
        want("apn_int"),
        "InvalidInput invalid_allow_private_network"
    );
    assert_eq!(want("scheme_int"), "InvalidInput invalid_scheme");
    assert_eq!(want("host_int"), "InvalidInput invalid_host");
    assert_eq!(
        want("ssh_username_int"),
        "InvalidInput invalid_ssh_username"
    );
    assert_eq!(
        want("host_keys_empty_str"),
        "InvalidInput ssh_host_keys_required"
    );
    assert_eq!(
        want("host_keys_nonempty_str"),
        "InvalidInput unsupported_host_key"
    );
    assert_eq!(
        want("host_keys_nonstr_element"),
        "InvalidInput unsupported_host_key"
    );
    assert_eq!(
        want("extra_env_value_int"),
        "InvalidInput invalid_env_value"
    );
    assert_eq!(
        want("header_name_falsy_int"),
        "InvalidInput invalid_header_name"
    );
    assert_eq!(
        want("basic_username_falsy_bool"),
        "InvalidInput invalid_basic_username"
    );
    // Python raises an uncaught `TypeError` here (`re.match` on a non-string
    // `base_url_env`) -- confirms PORTING.md §3.5 is the right bucket for
    // Rust's `state_corrupt` on this one field.
    assert_eq!(want("base_url_env_int"), "TypeError");
    // Missing key / non-numeric string: uncaught `KeyError`/`ValueError` in
    // Python.
    assert_eq!(want("policy_version_bad_str"), "ValueError");
    assert_eq!(want("policy_version_missing"), "KeyError");
    assert_eq!(want("policy_version_str"), "OK 3");
    assert_eq!(want("policy_version_float"), "OK 3");
    assert_eq!(want("policy_version_bool"), "OK 1");
    // `secret_version` is stored completely untyped by Python; the int case
    // agrees byte for byte, the string case is the documented residual (see
    // `DEVIATIONS.md`) that Rust's typed `Option<i64>` cannot represent.
    assert_eq!(want("secret_version_int"), "OK 5");
    assert_eq!(want("secret_version_str"), "OK 'abc'");

    // ---- Rust side: the same cases through `Connection::from_value`.
    let http_doc = || rust_connection().to_value();
    let ssh_base = || {
        Connection::new(
            "box",
            "demo",
            "dev",
            "ssh-box",
            "ssh",
            "box-key",
            None,
            "",
            None,
            None,
            None,
            Some(
                SshTarget::new(
                    "127.0.0.1",
                    22,
                    "deploy",
                    vec![
                        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA host"
                            .to_string(),
                    ],
                )
                .unwrap(),
            ),
            None,
            0,
            "active",
            "",
            "",
        )
        .unwrap()
        .to_value()
    };
    let cli_doc = || {
        Connection::new(
            "gh",
            "demo",
            "dev",
            "fake-github",
            "http",
            "gh-token",
            None,
            "demo connection",
            Some(HttpTarget::new("http", "127.0.0.1", 8080, None, false).unwrap()),
            Some(HttpAuth::bearer()),
            Some(
                HttpScope::new(
                    Some(vec!["GET".into(), "POST".into()]),
                    Some(vec!["/repos".into(), "/me".into()]),
                    vec!["DELETE".into()],
                )
                .unwrap(),
            ),
            None,
            Some(CliProfile::new("git", "http", None, Default::default()).unwrap()),
            0,
            "active",
            "",
            "",
        )
        .unwrap()
        .to_value()
    };

    let mut d = http_doc();
    d["http_target"]["port"] = serde_json::json!("8080");
    assert!(
        Connection::from_value(&d)
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::InvalidInput)
    );

    let mut d = http_doc();
    d["http_target"]["port"] = serde_json::json!(8080.0);
    assert!(Connection::from_value(&d).is_err());

    let mut d = http_doc();
    d["http_target"]["port"] = serde_json::json!(true);
    assert!(Connection::from_value(&d).is_err());

    let mut d = http_doc();
    // `2**70`: `arbitrary_precision` preserves the exact literal.
    d["http_target"]["port"] = serde_json::Value::Number("1180591620717411303424".parse().unwrap());
    assert!(Connection::from_value(&d).is_err());

    let mut d = http_doc();
    d["http_target"]["allow_private_network"] = serde_json::Value::Null;
    let err = Connection::from_value(&d).unwrap_err();
    assert_eq!(err.reason, "invalid_allow_private_network");

    let mut d = http_doc();
    d["http_target"]["allow_private_network"] = serde_json::json!(1);
    let err = Connection::from_value(&d).unwrap_err();
    assert_eq!(err.reason, "invalid_allow_private_network");

    let mut d = http_doc();
    d["http_target"]["scheme"] = serde_json::json!(5);
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "invalid_scheme"
    );

    let mut d = http_doc();
    d["http_target"]["host"] = serde_json::json!(5);
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "invalid_host"
    );

    let mut d = ssh_base();
    d["ssh_target"]["username"] = serde_json::json!(5);
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "invalid_ssh_username"
    );

    let mut d = ssh_base();
    d["ssh_target"]["host_keys"] = serde_json::json!("");
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "ssh_host_keys_required"
    );

    let mut d = ssh_base();
    d["ssh_target"]["host_keys"] = serde_json::json!("somestring");
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "unsupported_host_key"
    );

    let mut d = ssh_base();
    d["ssh_target"]["host_keys"] = serde_json::json!([5]);
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "unsupported_host_key"
    );

    let mut d = cli_doc();
    d["cli"]["extra_env"] = serde_json::json!({"FOO": 5});
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "invalid_env_value"
    );

    // `base_url_env` non-string: Python raises an uncaught `TypeError`
    // (§3.5); Rust's `state_corrupt` is the documented counterpart.
    let mut d = cli_doc();
    d["cli"]["base_url_env"] = serde_json::json!(5);
    assert!(
        Connection::from_value(&d)
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    // A present-but-JSON-falsy non-string `header_name`/`basic_username`,
    // when `mode` requires the field: Python's `not value` short-circuit
    // gives the documented reason, not an uncaught `TypeError`.
    let mut d = http_doc();
    d["http_auth"]["mode"] = serde_json::json!("header");
    d["http_auth"]["header_name"] = serde_json::json!(0);
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "invalid_header_name"
    );

    let mut d = http_doc();
    d["http_auth"]["mode"] = serde_json::json!("basic");
    d["http_auth"]["basic_username"] = serde_json::json!(false);
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "invalid_basic_username"
    );

    // `policy_version`: Python's `int()` coercion.
    let mut d = http_doc();
    d["policy_version"] = serde_json::json!("3");
    assert_eq!(Connection::from_value(&d).unwrap().policy_version, 3);

    let mut d = http_doc();
    d["policy_version"] = serde_json::json!(3.7);
    assert_eq!(Connection::from_value(&d).unwrap().policy_version, 3);

    let mut d = http_doc();
    d["policy_version"] = serde_json::json!(true);
    assert_eq!(Connection::from_value(&d).unwrap().policy_version, 1);

    let mut d = http_doc();
    d["policy_version"] = serde_json::json!("abc");
    assert!(
        Connection::from_value(&d)
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    let mut d = http_doc();
    d.as_object_mut().unwrap().remove("policy_version");
    assert!(
        Connection::from_value(&d)
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    // `secret_version`: stored untyped by Python. The plain-integer case
    // agrees exactly; the string case is the documented residual (Rust's
    // typed `Option<i64>` cannot hold it, so `state_corrupt` is returned
    // where Python would silently succeed -- see `DEVIATIONS.md`).
    let mut d = http_doc();
    d["secret_version"] = serde_json::json!(5);
    assert_eq!(Connection::from_value(&d).unwrap().secret_version, Some(5));

    let mut d = http_doc();
    d["secret_version"] = serde_json::json!("abc");
    assert!(
        Connection::from_value(&d)
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );
}

// ------------------------------------------------------------------- D-4
// `is_stopped`/`restore_pending`/`_decide`/`usable_connections` read
// `control.json`'s `"stopped"`/`"restore_pending"` flags with Python
// truthiness (`if control.get("stopped")`), not `bool`-only equality: a
// non-boolean truthy stored value (`1`, `"true"`, `[1]`) must still stop
// everything. Both languages load the *same* state directory here, so any
// remaining divergence in the flag read itself -- not just a difference in
// how each language's Policy independently constructs its own state --
// would show up directly.
#[test]
fn control_flag_truthiness_matches_python_for_non_boolean_values() {
    let tmp = TempDir::new().unwrap();
    let state_path = tmp.path().join("state");
    let script = format!(
        r#"
import json
from zeropw.store import StateDir
from zeropw import policy as P

state = StateDir({path})
state.create()
p = P.Policy(state, clock=lambda: 1700000000.0)
p.create_principal("agent-1")
conn = P.Connection(
    id="gh", project="demo", environment="dev", service="fake-github", kind="http",
    secret_id="gh-token", secret_version=None, description="demo",
    http_target=P.HttpTarget("http", "127.0.0.1", 8080),
    http_auth=P.HttpAuth("bearer"),
    http_scope=P.HttpScope(("GET", "POST"), ("/repos", "/me"), ("DELETE",)),
    ssh_target=None, cli=None, policy_version=0, status="active", created_at="", updated_at="",
)
p.create_connection(conn)
grant = p.create_grant("agent-1", "gh", 3600, None)

control = state.read_json(P.CONTROL, {{}})
control["stopped"] = 1  # truthy non-bool
state.write_json(P.CONTROL, control)

print(grant.id)
print(p.is_stopped())
print(p.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"), grant.id).reason)
print(p.usable_connections("agent-1"))

control["stopped"] = False
control["restore_pending"] = [1]  # truthy non-bool
state.write_json(P.CONTROL, control)
print(p.restore_pending())
print(p.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"), grant.id).reason)
"#,
        path = py_str_literal(&state_path),
    );
    let out = run_python(&script);
    let mut lines = out.lines();
    let grant_id = lines.next().unwrap().to_string();
    assert_eq!(lines.next().unwrap(), "True"); // p.is_stopped()
    assert_eq!(lines.next().unwrap(), "global_stop");
    assert_eq!(lines.next().unwrap(), "[]"); // p.usable_connections(...)
    assert_eq!(lines.next().unwrap(), "True"); // p.restore_pending()
    assert_eq!(lines.next().unwrap(), "restore_pending");

    // Rust: the exact same state directory Python just wrote (with
    // `"stopped": 1` still on disk from the first half of the script above,
    // before Python's own second half reset it to `false` /
    // `"restore_pending": [1]`) -- reload to check the `"stopped": 1` half
    // fresh, then re-apply the `restore_pending` corruption the same way.
    let state = StateDir::new(&state_path);
    let policy = Policy::new(&state, clock::fixed(1_700_000_000.0));

    let mut control = state
        .read_json(policy::CONTROL, serde_json::json!({}))
        .unwrap();
    control["stopped"] = serde_json::json!(1);
    control["restore_pending"] = serde_json::json!(false);
    state.write_json(policy::CONTROL, &control).unwrap();
    assert!(policy.is_stopped().unwrap());
    assert_eq!(
        policy
            .evaluate(
                "agent-1",
                "gh",
                &Action::http("GET", "/repos"),
                Some(&grant_id)
            )
            .unwrap()
            .reason,
        "global_stop"
    );
    assert!(policy.usable_connections("agent-1").unwrap().is_empty());

    control["stopped"] = serde_json::json!(false);
    control["restore_pending"] = serde_json::json!([1]);
    state.write_json(policy::CONTROL, &control).unwrap();
    assert!(policy.restore_pending().unwrap());
    assert_eq!(
        policy
            .evaluate(
                "agent-1",
                "gh",
                &Action::http("GET", "/repos"),
                Some(&grant_id)
            )
            .unwrap()
            .reason,
        "restore_pending"
    );
}

// ------------------------------------------------------- round-2 findings
// (equivalence review of work unit D, `policy.rs`) -- D-R2-1..D-R2-9.

// D-R2-1: `Policy::control` used to fold *any* non-object read (including a
// truthy one like `[1]`) into the default document. Python's `... or
// {defaults}` only falls back for a *falsy* read; a truthy non-dict value is
// returned as-is and every caller's `.get(...)` then raises an uncaught
// `AttributeError` -- fail closed instead (`state_corrupt`).
#[test]
fn control_document_truthy_non_object_fails_closed_like_python_attributeerror() {
    let script = r#"
def probe(value):
    control = value or {"stopped": False, "restore_pending": False, "approvals": {}}
    try:
        print("OK", control.get("stopped"))
    except AttributeError:
        print("AttributeError")

for v in ([1], "x", 5, [], None, {}):
    probe(v)
"#;
    let out = run_python(script);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines,
        vec![
            "AttributeError",
            "AttributeError",
            "AttributeError",
            "OK False",
            "OK False",
            "OK False",
        ]
    );

    // Truthy non-object: Rust must fail closed with `state_corrupt`.
    for value in [
        serde_json::json!([1]),
        serde_json::json!("x"),
        serde_json::json!(5),
    ] {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        state.write_json(policy::CONTROL, &value).unwrap();
        let policy = Policy::new(&state, clock::fixed(1_700_000_000.0));
        let err = policy.is_stopped().unwrap_err();
        assert!(
            err.is(zeropw::errors::ErrorClass::StateError),
            "{value:?}: {err:?}"
        );
        assert_eq!(err.reason, "state_corrupt", "{value:?}");
    }

    // Falsy (missing, `[]`, `null`, `{}`): the default document, exactly
    // like before.
    for value in [
        serde_json::json!([]),
        serde_json::Value::Null,
        serde_json::json!({}),
    ] {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        state.write_json(policy::CONTROL, &value).unwrap();
        let policy = Policy::new(&state, clock::fixed(1_700_000_000.0));
        assert!(!policy.is_stopped().unwrap(), "{value:?}");
    }

    // An unparseable file already agreed before this fix (`read_json`
    // itself raises `state_corrupt`) -- still true after it.
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    std::fs::create_dir_all(tmp.path().join("state").join("policy")).unwrap();
    std::fs::write(
        tmp.path().join("state").join("policy/control.json"),
        b"{not json",
    )
    .unwrap();
    let policy = Policy::new(&state, clock::fixed(1_700_000_000.0));
    assert_eq!(policy.is_stopped().unwrap_err().reason, "state_corrupt");
}

// D-R2-2: `Policy::vault_doc` used to swallow a corrupt (unparseable)
// `vault/secrets.json` the same way it treats a successfully-parsed
// non-dict value, silently returning `{}`. Python's `_vault_doc` only
// narrows a *parsed* non-dict to `{}`; an unparseable file makes
// `read_json` itself raise `StateError("state_corrupt", ...)`, uncaught,
// propagating out of `create_grant` (via `_resolved_credential_version`).
#[test]
fn vault_doc_corrupt_file_propagates_state_corrupt_through_create_grant() {
    let script = r#"
import os, tempfile
from zeropw.store import StateDir
from zeropw import policy as P
from zeropw.errors import StateError

with tempfile.TemporaryDirectory() as d:
    state_path = os.path.join(d, "state")
    state = StateDir(state_path)
    state.create()
    p = P.Policy(state, clock=lambda: 1700000000.0)
    p.create_principal("agent-1")
    conn = P.Connection(
        id="gh", project="demo", environment="dev", service="fake-github", kind="http",
        secret_id="gh-token", secret_version=None, description="demo",
        http_target=P.HttpTarget("http", "127.0.0.1", 8080),
        http_auth=P.HttpAuth("bearer"),
        http_scope=P.HttpScope(("GET", "POST"), ("/repos", "/me"), ("DELETE",)),
        ssh_target=None, cli=None, policy_version=0, status="active", created_at="", updated_at="",
    )
    p.create_connection(conn)
    os.makedirs(os.path.join(state_path, "vault"), exist_ok=True)
    with open(os.path.join(state_path, "vault", "secrets.json"), "w") as f:
        f.write("{not json")
    try:
        p.create_grant("agent-1", "gh", 3600, None)
        print("OK")
    except StateError as e:
        print(f"StateError {e.reason} {e.detail}")
"#;
    assert_eq!(
        run_python(script).trim(),
        "StateError state_corrupt vault/secrets.json"
    );

    let tmp = TempDir::new().unwrap();
    let state_path = tmp.path().join("state");
    let state = StateDir::new(&state_path);
    state.create().unwrap();
    let policy = Policy::new(&state, clock::fixed(1_700_000_000.0));
    policy.create_principal("agent-1", "default").unwrap();
    policy.create_connection(rust_connection()).unwrap();
    std::fs::create_dir_all(state_path.join("vault")).unwrap();
    std::fs::write(state_path.join("vault").join("secrets.json"), b"{not json").unwrap();

    let err = policy
        .create_grant("agent-1", "gh", Some(3600), None)
        .unwrap_err();
    assert!(err.is(zeropw::errors::ErrorClass::StateError));
    assert_eq!(err.reason, "state_corrupt");
    assert_eq!(err.detail, "vault/secrets.json");

    // A successfully-*parsed* non-dict value is still treated as `{}`, not
    // an error -- only an unparseable file propagates.
    std::fs::write(state_path.join("vault").join("secrets.json"), b"[1]").unwrap();
    assert!(
        policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .is_ok()
    );
}

// D-R2-3: `Policy::approval_mismatch` used `entry.get("grant").and_then
// (Value::as_str)`, silently treating a present *non-string* `grant` (e.g.
// `5`) the same as a *missing* one and skipping the grant-binding check
// entirely. Python's `recorded_grant = entry.get("grant")` only skips a
// `None`; a present non-string value reaches `self.get_grant(...)`, which
// can never find a match and raises `NotFound` -> `"grant_changed"`.
#[test]
fn approval_mismatch_treats_present_non_string_grant_as_grant_changed() {
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let policy = Policy::new(&state, clock::fixed(1_700_000_000.0));
    policy.create_principal("agent-1", "default").unwrap();
    policy.create_connection(rust_connection()).unwrap();

    let mut control = state
        .read_json(policy::CONTROL, serde_json::json!({}))
        .unwrap();
    let mut approvals = serde_json::Map::new();
    approvals.insert(
        "dg1".to_string(),
        serde_json::json!({
            "caller": "agent-1", "connection": "gh", "method": "GET", "path": "/repos",
            "status": "approved", "created_at": "", "expires_at": 1_700_003_600.0,
            "grant": 5, "policy_version": 1, "cycle": 1,
        }),
    );
    control["approvals"] = serde_json::Value::Object(approvals);
    state.write_json(policy::CONTROL, &control).unwrap();

    let consumed = policy
        .consume_approval("dg1", "agent-1", "gh", None, None)
        .unwrap();
    assert!(!consumed, "a non-string grant must not be consumable");

    let after = state
        .read_json(policy::CONTROL, serde_json::json!({}))
        .unwrap();
    let entry = &after["approvals"]["dg1"];
    assert_eq!(entry["status"], serde_json::json!("invalidated"));
    assert_eq!(entry["closed_reason"], serde_json::json!("grant_changed"));
}

// D-R2-4: `collect_revocations` used `Value::as_i64` for a ledger/audit
// entry's `version`, silently dropping a JSON `true`/`false`. Python's
// `isinstance(entry.get("version"), int)` accepts a `bool` too (`bool` is
// an `int` subclass: `True == 1`, `False == 0`), so a stored `true`
// revokes version 1 on replay.
#[test]
fn secret_version_revocations_treat_json_bool_as_python_int_isinstance() {
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();

    // The reviewer's 7-line ledger: a `true`/`false` version (must count as
    // 1/0), a float version (dropped by both languages: not an `int`
    // `isinstance`), a plain int, plus one of each of the other kinds to
    // confirm they are untouched by this fix.
    let lines = [
        r#"{"kind":"secret_version","secret_id":"s1","version":true}"#,
        r#"{"kind":"secret_version","secret_id":"s2","version":2}"#,
        r#"{"kind":"secret_version","secret_id":"s3","version":3.0}"#,
        r#"{"kind":"secret_version","secret_id":"s4","version":false}"#,
        r#"{"kind":"grant","id":"g1"}"#,
        r#"{"kind":"connection","id":"c1"}"#,
        r#"{"kind":"connection_enable","id":"c1"}"#,
    ];
    for line in lines {
        state.append_line(policy::REVOCATIONS, line).unwrap();
    }

    let script = format!(
        r#"
from zeropw.store import StateDir
from zeropw import policy as P

state = StateDir({path})
found = P.collect_revocations(state, [])
print(sorted(found.secret_versions))
print(sorted(found.grants))
print(sorted(found.connections))
"#,
        path = py_str_literal(&tmp.path().join("state")),
    );
    let out = run_python(&script);
    let mut py_lines = out.lines();
    assert_eq!(
        py_lines.next().unwrap(),
        "[('s1', True), ('s2', 2), ('s4', False)]"
    );
    assert_eq!(py_lines.next().unwrap(), "['g1']");
    assert_eq!(py_lines.next().unwrap(), "[]");

    let found = policy::collect_revocations(&state, std::iter::empty());
    let mut secret_versions: Vec<(String, i64)> = found.secret_versions.into_iter().collect();
    secret_versions.sort();
    assert_eq!(
        secret_versions,
        vec![
            ("s1".to_string(), 1),
            ("s2".to_string(), 2),
            ("s4".to_string(), 0),
        ]
    );
    assert!(found.grants.contains("g1"));
    assert!(found.connections.is_empty());
}

// D-R2-5: `CliProfile::from_value` checked every `extra_env` *value*'s type
// while extracting the map (before ever looking at any key name), and
// `CliProfile::new` iterates a key-sorted `BTreeMap` -- both lose the
// original document order. Python's `__post_init__` checks name-then-value
// per entry in dict *insertion* order, so the first fault in document order
// decides the reported reason.
#[test]
fn cli_profile_extra_env_validates_name_then_value_in_document_order() {
    let script = r#"
import json
from zeropw import policy as P
from zeropw.errors import InvalidInput


def cli_doc(extra_env):
    c = P.Connection(
        id="gh", project="demo", environment="dev", service="fake-github", kind="http",
        secret_id="gh-token", secret_version=None, description="demo",
        http_target=P.HttpTarget("http", "127.0.0.1", 8080),
        http_auth=P.HttpAuth("bearer"),
        http_scope=P.HttpScope(("GET", "POST"), ("/repos", "/me"), ("DELETE",)),
        ssh_target=None, cli=P.CliProfile("git", "http"),
        policy_version=0, status="active", created_at="", updated_at="",
    )
    d = json.loads(json.dumps(c.to_dict()))
    d["cli"]["extra_env"] = extra_env
    return d


def probe(label, extra_env):
    d = cli_doc(extra_env)
    try:
        P.Connection.from_dict(d)
        print(f"{label} OK")
    except InvalidInput as e:
        print(f"{label} {e.reason}")


probe("name_then_value", {"A-B": "v", "GOOD": 5})
probe("value_then_name", {"GOOD": 5, "A-B": "v"})
probe("reserved_name_then_nul_value", {"SSH_AUTH_SOCK": "x", "GOOD": "a\x00b"})
probe("nul_value_then_reserved_name", {"GOOD": "a\x00b", "SSH_AUTH_SOCK": "x"})
"#;
    let out = run_python(script);
    let lines: std::collections::HashMap<&str, &str> = out
        .lines()
        .map(|l| l.split_once(' ').expect("label + rest"))
        .collect();
    assert_eq!(lines["name_then_value"], "invalid_env_name");
    assert_eq!(lines["value_then_name"], "invalid_env_value");
    assert_eq!(lines["reserved_name_then_nul_value"], "invalid_env_name");
    assert_eq!(lines["nul_value_then_reserved_name"], "invalid_env_value");

    let cli_conn = |extra_env: serde_json::Value| {
        let mut d = Connection::new(
            "gh",
            "demo",
            "dev",
            "fake-github",
            "http",
            "gh-token",
            None,
            "demo",
            Some(HttpTarget::new("http", "127.0.0.1", 8080, None, false).unwrap()),
            Some(HttpAuth::bearer()),
            Some(
                HttpScope::new(
                    Some(vec!["GET".into(), "POST".into()]),
                    Some(vec!["/repos".into(), "/me".into()]),
                    vec!["DELETE".into()],
                )
                .unwrap(),
            ),
            None,
            Some(CliProfile::new("git", "http", None, Default::default()).unwrap()),
            0,
            "active",
            "",
            "",
        )
        .unwrap()
        .to_value();
        d["cli"]["extra_env"] = extra_env;
        d
    };

    let err =
        Connection::from_value(&cli_conn(serde_json::json!({"A-B": "v", "GOOD": 5}))).unwrap_err();
    assert_eq!(err.reason, "invalid_env_name");

    let err =
        Connection::from_value(&cli_conn(serde_json::json!({"GOOD": 5, "A-B": "v"}))).unwrap_err();
    assert_eq!(err.reason, "invalid_env_value");

    let err = Connection::from_value(&cli_conn(
        serde_json::json!({"SSH_AUTH_SOCK": "x", "GOOD": "a\0b"}),
    ))
    .unwrap_err();
    assert_eq!(err.reason, "invalid_env_name");

    let err = Connection::from_value(&cli_conn(
        serde_json::json!({"GOOD": "a\0b", "SSH_AUTH_SOCK": "x"}),
    ))
    .unwrap_err();
    assert_eq!(err.reason, "invalid_env_value");
}

// D-R2-6: `HttpTarget::from_value`/`HttpAuth::from_value` silently ignored
// unknown keys. Python builds these via `HttpTarget(**value,
// check_address=False)` / `HttpAuth(**value)`, so an unknown key -- or a
// stored `check_address`, which `Connection.from_dict` itself already
// passes for `HttpTarget` -- collides with or adds an unexpected keyword
// argument, an uncaught `TypeError`, and the whole document fails to load.
#[test]
fn http_target_and_http_auth_reject_unknown_keys_like_pythons_kwarg_unpacking() {
    let script = r#"
import json
from zeropw import policy as P


def http_doc():
    c = P.Connection(
        id="gh", project="demo", environment="dev", service="fake-github", kind="http",
        secret_id="gh-token", secret_version=None, description="demo",
        http_target=P.HttpTarget("http", "127.0.0.1", 8080),
        http_auth=P.HttpAuth("bearer"),
        http_scope=P.HttpScope(("GET", "POST"), ("/repos", "/me"), ("DELETE",)),
        ssh_target=None, cli=None, policy_version=0, status="active", created_at="", updated_at="",
    )
    return json.loads(json.dumps(c.to_dict()))


def probe(label, mutate):
    d = http_doc()
    mutate(d)
    try:
        P.Connection.from_dict(d)
        print(f"{label} OK")
    except Exception as e:
        print(f"{label} {type(e).__name__}")


probe("target_unknown_key", lambda d: d["http_target"].__setitem__("foo", 1))
probe("target_check_address", lambda d: d["http_target"].__setitem__("check_address", False))
probe("auth_unknown_key", lambda d: d["http_auth"].__setitem__("bogus", "x"))
probe("valid", lambda d: None)
"#;
    let out = run_python(script);
    let lines: std::collections::HashMap<&str, &str> = out
        .lines()
        .map(|l| l.split_once(' ').expect("label + rest"))
        .collect();
    assert_eq!(lines["target_unknown_key"], "TypeError");
    assert_eq!(lines["target_check_address"], "TypeError");
    assert_eq!(lines["auth_unknown_key"], "TypeError");
    assert_eq!(lines["valid"], "OK");

    let base = || rust_connection().to_value();

    let mut d = base();
    d["http_target"]["foo"] = serde_json::json!(1);
    assert!(
        Connection::from_value(&d)
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    let mut d = base();
    d["http_target"]["check_address"] = serde_json::json!(false);
    assert!(
        Connection::from_value(&d)
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    let mut d = base();
    d["http_auth"]["bogus"] = serde_json::json!("x");
    assert!(
        Connection::from_value(&d)
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    assert!(Connection::from_value(&base()).is_ok());
}

// D-R2-7: `Connection::from_value`'s `description` and `principal_from_entry`'s
// `runtime` silently replaced a stored *non-string* value with the default
// (`""`/`"default"`) instead of `state_corrupt`. Python keeps the stored
// value completely verbatim (`public_view()["description"] == 5`, and a
// principal with a corrupt `runtime` does not match
// `principals_in_runtime("default")`, which incident/intrusion scoping
// relies on) -- inconsistent with every sibling field's exact-type-or-
// `state_corrupt` treatment.
#[test]
fn description_and_runtime_reject_non_string_values_like_sibling_fields() {
    let script = r#"
from zeropw.store import StateDir
from zeropw import policy as P
import tempfile, os

with tempfile.TemporaryDirectory() as d:
    state_path = os.path.join(d, "state")
    state = StateDir(state_path)
    state.create()
    p = P.Policy(state, clock=lambda: 1700000000.0)
    p.create_principal("agent-1")
    conn = P.Connection(
        id="gh", project="demo", environment="dev", service="fake-github", kind="http",
        secret_id="gh-token", secret_version=None, description="demo",
        http_target=P.HttpTarget("http", "127.0.0.1", 8080),
        http_auth=P.HttpAuth("bearer"),
        http_scope=P.HttpScope(("GET", "POST"), ("/repos", "/me"), ("DELETE",)),
        ssh_target=None, cli=None, policy_version=0, status="active", created_at="", updated_at="",
    )
    p.create_connection(conn)

    doc = state.read_json(P.CONNECTIONS, {})
    doc["gh"]["description"] = 5
    state.write_json(P.CONNECTIONS, doc)
    c = p.get_connection("gh")
    print("description", repr(c.description), repr(c.public_view()["description"]))

    doc = state.read_json(P.PRINCIPALS, {})
    doc["agent-1"]["runtime"] = 5
    state.write_json(P.PRINCIPALS, doc)
    principal = p.get_principal("agent-1")
    in_default = any(x.id == "agent-1" for x in p.principals_in_runtime("default"))
    print("runtime", repr(principal.runtime), in_default)
"#;
    let out = run_python(script);
    let mut lines = out.lines();
    assert_eq!(lines.next().unwrap(), "description 5 5");
    assert_eq!(lines.next().unwrap(), "runtime 5 False");

    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let policy = Policy::new(&state, clock::fixed(1_700_000_000.0));
    policy.create_principal("agent-1", "default").unwrap();
    policy.create_connection(rust_connection()).unwrap();

    let mut doc = state
        .read_json(policy::CONNECTIONS, serde_json::json!({}))
        .unwrap();
    doc["gh"]["description"] = serde_json::json!(5);
    state.write_json(policy::CONNECTIONS, &doc).unwrap();
    let err = policy.get_connection("gh").unwrap_err();
    assert!(err.is(zeropw::errors::ErrorClass::StateError));
    assert_eq!(err.reason, "state_corrupt");

    let mut doc = state
        .read_json(policy::PRINCIPALS, serde_json::json!({}))
        .unwrap();
    doc["agent-1"]["runtime"] = serde_json::json!(5);
    state.write_json(policy::PRINCIPALS, &doc).unwrap();
    let err = policy.get_principal("agent-1").unwrap_err();
    assert!(err.is(zeropw::errors::ErrorClass::StateError));
    assert_eq!(err.reason, "state_corrupt");
}

// D-R2-8: `Policy::request_approval`'s `cycle` computation used
// `entry.get("cycle").and_then(Value::as_i64).unwrap_or(1)`, only
// defaulting on a *missing or non-integer* `cycle`. Python's
// `int(entry.get("cycle") or 1) + 1` falls back to `1` for *any falsy*
// stored `cycle` (`0`, `null`, `""`), not just a missing one, and coerces a
// truthy value the full `int()` way (numeric string, float truncation).
#[test]
fn request_approval_cycle_uses_python_truthiness_and_int_coercion() {
    let script = r#"
for c in (0, None, "", "7", 7.5):
    print(int(c or 1) + 1)
"#;
    let out = run_python(script);
    let expected: Vec<i64> = out.lines().map(|l| l.parse().unwrap()).collect();
    assert_eq!(expected, vec![2, 2, 2, 8, 8]);

    let cycle_values = [
        serde_json::json!(0),
        serde_json::Value::Null,
        serde_json::json!(""),
        serde_json::json!("7"),
        serde_json::json!(7.5),
    ];

    for (value, want) in cycle_values.iter().zip(expected.iter()) {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        let policy = Policy::new(&state, clock::fixed(1_700_000_000.0));
        policy.create_principal("agent-1", "default").unwrap();
        policy.create_connection(rust_connection()).unwrap();

        let mut control = state
            .read_json(policy::CONTROL, serde_json::json!({}))
            .unwrap();
        let mut approvals = serde_json::Map::new();
        approvals.insert(
            "dg1".to_string(),
            serde_json::json!({
                "caller": "agent-1", "connection": "gh", "method": "GET", "path": "/repos",
                "status": "consumed", "created_at": "", "expires_at": 1_700_003_600.0,
                "grant": null, "policy_version": 0, "cycle": value,
            }),
        );
        control["approvals"] = serde_json::Value::Object(approvals);
        state.write_json(policy::CONTROL, &control).unwrap();

        let entry = policy
            .request_approval("dg1", "agent-1", "gh", "GET", "/repos")
            .unwrap();
        assert_eq!(entry["cycle"].as_i64(), Some(*want), "value={value:?}");
    }
}

// D-R2-9: `Policy::reapply_revocations` kept a stored `revoked_at` only
// when it was already a JSON *string* (so `""` was kept, and a truthy
// non-string became `now`), and coerced `policy_version` with plain
// `as_i64`. Python's `entry.get("revoked_at") or now` keeps any *truthy*
// value verbatim regardless of type, replacing only a falsy one with `now`;
// `int(entry.get("policy_version", 0)) + 1` coerces a numeric
// string/float/bool.
#[test]
fn reapply_revocations_uses_python_truthiness_and_int_coercion() {
    let script = r#"
for c in ("", None, 0, 12345):
    print(repr(c or "NOW"))
for c in ("3", 3.0, True):
    print(int(c) + 1)
"#;
    let out = run_python(script);
    let mut lines = out.lines();
    assert_eq!(lines.next().unwrap(), "'NOW'");
    assert_eq!(lines.next().unwrap(), "'NOW'");
    assert_eq!(lines.next().unwrap(), "'NOW'");
    assert_eq!(lines.next().unwrap(), "12345");
    assert_eq!(lines.next().unwrap(), "4");
    assert_eq!(lines.next().unwrap(), "4");
    assert_eq!(lines.next().unwrap(), "2");

    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let policy = Policy::new(&state, clock::fixed(1_700_000_000.0));

    let mut grants = serde_json::Map::new();
    grants.insert(
        "g-empty".into(),
        serde_json::json!({"status": "active", "revoked_at": ""}),
    );
    grants.insert(
        "g-null".into(),
        serde_json::json!({"status": "active", "revoked_at": null}),
    );
    grants.insert(
        "g-zero".into(),
        serde_json::json!({"status": "active", "revoked_at": 0}),
    );
    grants.insert(
        "g-truthy".into(),
        serde_json::json!({"status": "active", "revoked_at": 12345}),
    );
    state
        .write_json(policy::GRANTS, &serde_json::Value::Object(grants))
        .unwrap();

    let mut connections = serde_json::Map::new();
    connections.insert(
        "c-str".into(),
        serde_json::json!({"status": "active", "policy_version": "3"}),
    );
    connections.insert(
        "c-float".into(),
        serde_json::json!({"status": "active", "policy_version": 3.0}),
    );
    connections.insert(
        "c-bool".into(),
        serde_json::json!({"status": "active", "policy_version": true}),
    );
    state
        .write_json(policy::CONNECTIONS, &serde_json::Value::Object(connections))
        .unwrap();

    let revocations = policy::Revocations {
        grants: ["g-empty", "g-null", "g-zero", "g-truthy"]
            .into_iter()
            .map(String::from)
            .collect(),
        principals: Default::default(),
        connections: ["c-str", "c-float", "c-bool"]
            .into_iter()
            .map(String::from)
            .collect(),
        secret_versions: Default::default(),
    };
    policy.reapply_revocations(&revocations).unwrap();

    let now = zeropw::store::iso(Some(1_700_000_000.0));
    let grants_after = state
        .read_json(policy::GRANTS, serde_json::json!({}))
        .unwrap();
    assert_eq!(
        grants_after["g-empty"]["revoked_at"],
        serde_json::json!(now)
    );
    assert_eq!(grants_after["g-null"]["revoked_at"], serde_json::json!(now));
    assert_eq!(grants_after["g-zero"]["revoked_at"], serde_json::json!(now));
    // A truthy non-string value is kept completely verbatim, not replaced.
    assert_eq!(
        grants_after["g-truthy"]["revoked_at"],
        serde_json::json!(12345)
    );

    let connections_after = state
        .read_json(policy::CONNECTIONS, serde_json::json!({}))
        .unwrap();
    assert_eq!(
        connections_after["c-str"]["policy_version"],
        serde_json::json!(4)
    );
    assert_eq!(
        connections_after["c-float"]["policy_version"],
        serde_json::json!(4)
    );
    assert_eq!(
        connections_after["c-bool"]["policy_version"],
        serde_json::json!(2)
    );
}

// ================================================================ round 3

// D-R3-1: `Policy._principals`/`_connections`/`_grants` are `read_json(name,
// {}) or {}` -- the same falsy/truthy split `Policy._control` (D-R2-1)
// already reproduces. A *truthy* non-dict document ([1], "x", 5) is
// returned verbatim by Python's `or`, and the first `.items()` on it raises
// an uncaught `AttributeError`; a *falsy* one ([], null, {}, 0, "") is
// replaced with `{}`. `list_principals`/`list_connections`/`list_grants`
// are pure reads through exactly these helpers, with no side effects to set
// up first.
#[test]
fn read_doc_matches_pythons_read_json_or_default_falsy_truthy_split() {
    let script = r#"
import tempfile, os
from zeropw.store import StateDir
from zeropw import policy as P

def probe(doc_name, method, value):
    d = tempfile.mkdtemp()
    state = StateDir(os.path.join(d, "state"))
    state.create()
    state.write_json(doc_name, value)
    pol = P.Policy(state)
    try:
        getattr(pol, method)()
        print("OK")
    except Exception as e:
        print(type(e).__name__)

values = [[1], "x", 5, [], None, {}, 0, ""]
for name, method in ((P.PRINCIPALS, "list_principals"), (P.CONNECTIONS, "list_connections"),
                     (P.GRANTS, "list_grants")):
    for v in values:
        probe(name, method, v)
"#;
    let out = run_python(script);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 24, "expected 3 docs x 8 values: {lines:?}");
    let expect = [
        "AttributeError",
        "AttributeError",
        "AttributeError",
        "OK",
        "OK",
        "OK",
        "OK",
        "OK",
    ];
    assert_eq!(&lines[0..8], expect);
    assert_eq!(&lines[8..16], expect);
    assert_eq!(&lines[16..24], expect);

    let values: [(serde_json::Value, bool); 8] = [
        (serde_json::json!([1]), true),
        (serde_json::json!("x"), true),
        (serde_json::json!(5), true),
        (serde_json::json!([]), false),
        (serde_json::Value::Null, false),
        (serde_json::json!({}), false),
        (serde_json::json!(0), false),
        (serde_json::json!(""), false),
    ];

    for (value, should_fail) in &values {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        state.write_json(policy::PRINCIPALS, value).unwrap();
        let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
        let result = pol.list_principals();
        if *should_fail {
            let err = result.unwrap_err();
            assert!(
                err.is(zeropw::errors::ErrorClass::StateError),
                "principals value={value:?} err={err:?}"
            );
            let raw =
                std::fs::read_to_string(tmp.path().join("state").join(policy::PRINCIPALS)).unwrap();
            let reparsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
            assert_eq!(&reparsed, value, "principals.json must be left untouched");
        } else {
            assert!(
                result.is_ok(),
                "principals value={value:?}: {:?}",
                result.err()
            );
        }
    }

    for (value, should_fail) in &values {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        state.write_json(policy::CONNECTIONS, value).unwrap();
        let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
        let result = pol.list_connections();
        if *should_fail {
            let err = result.unwrap_err();
            assert!(
                err.is(zeropw::errors::ErrorClass::StateError),
                "connections value={value:?} err={err:?}"
            );
            let raw = std::fs::read_to_string(tmp.path().join("state").join(policy::CONNECTIONS))
                .unwrap();
            let reparsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
            assert_eq!(&reparsed, value, "connections.json must be left untouched");
        } else {
            assert!(
                result.is_ok(),
                "connections value={value:?}: {:?}",
                result.err()
            );
        }
    }

    for (value, should_fail) in &values {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        state.write_json(policy::GRANTS, value).unwrap();
        let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
        let result = pol.list_grants(None);
        if *should_fail {
            let err = result.unwrap_err();
            assert!(
                err.is(zeropw::errors::ErrorClass::StateError),
                "grants value={value:?} err={err:?}"
            );
            let raw =
                std::fs::read_to_string(tmp.path().join("state").join(policy::GRANTS)).unwrap();
            let reparsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
            assert_eq!(&reparsed, value, "grants.json must be left untouched");
        } else {
            assert!(result.is_ok(), "grants value={value:?}: {:?}", result.err());
        }
    }
}

// D-R3-2: `control.setdefault("approvals", {})` only inserts the empty-dict
// default for an ABSENT key; a present non-dict value is returned unchanged
// by `setdefault`, and the subsequent `.get(...)` raises an uncaught
// `AttributeError` -- `request_approval`/`approve`/`consume_approval` must
// fail closed and never overwrite the corrupt value.
#[test]
fn approvals_setdefault_fails_closed_on_truthy_non_object_like_pythons_setdefault() {
    let script = r#"
import tempfile, os
from zeropw.store import StateDir
from zeropw import policy as P

def probe(op, value):
    d = tempfile.mkdtemp()
    state = StateDir(os.path.join(d, "state"))
    state.create()
    control = {"stopped": False, "restore_pending": False, "approvals": value}
    state.write_json(P.CONTROL, control)
    pol = P.Policy(state)
    try:
        if op == "request":
            pol.request_approval("dg1", "agent-1", "conn-1", "GET", "/x")
        elif op == "approve":
            pol.approve("dg1")
        elif op == "consume":
            pol.consume_approval("dg1", "agent-1", "conn-1")
        print("OK")
    except Exception as e:
        print(type(e).__name__)
    after = state.read_json(P.CONTROL, None)
    print(after["approvals"] == value)

for op in ("request", "approve", "consume"):
    for v in ("x", [1], 5):
        probe(op, v)
"#;
    let out = run_python(script);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 18, "{lines:?}");
    for chunk in lines.chunks(2) {
        assert_eq!(chunk, ["AttributeError", "True"], "{lines:?}");
    }

    for value in [
        serde_json::json!("x"),
        serde_json::json!([1]),
        serde_json::json!(5),
    ] {
        for op in ["request", "approve", "consume"] {
            let tmp = TempDir::new().unwrap();
            let state = StateDir::new(tmp.path().join("state"));
            state.create().unwrap();
            let control = serde_json::json!({
                "stopped": false, "restore_pending": false, "approvals": value,
            });
            state.write_json(policy::CONTROL, &control).unwrap();
            let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
            let err_class = match op {
                "request" => pol
                    .request_approval("dg1", "agent-1", "conn-1", "GET", "/x")
                    .unwrap_err()
                    .is(zeropw::errors::ErrorClass::StateError),
                "approve" => pol
                    .approve("dg1")
                    .unwrap_err()
                    .is(zeropw::errors::ErrorClass::StateError),
                "consume" => pol
                    .consume_approval("dg1", "agent-1", "conn-1", None, None)
                    .unwrap_err()
                    .is(zeropw::errors::ErrorClass::StateError),
                _ => unreachable!(),
            };
            assert!(err_class, "op={op} value={value:?}");
            let after = state
                .read_json(policy::CONTROL, serde_json::json!({}))
                .unwrap();
            assert_eq!(
                after["approvals"], value,
                "op={op} value={value:?}: approvals must be left untouched"
            );
        }
    }
}

// D-R3-2 (continued): `dict(self._control().get("approvals", {}))` and
// `list(self._control().get("approval_history", []))` -- CPython's
// `dict()`/`list()` coercion, not the falsy/truthy split `control()` uses.
// An object -> the identity map for `dict`, the list of its keys for
// `list`; a string -> `list` yields its individual characters (a genuine
// success, not a failure); a bare number/bool/an explicit `null` is a
// genuinely uncaught `TypeError` in Python either way.
#[test]
fn list_approvals_and_approval_history_reproduce_pythons_dict_and_list_coercion() {
    let script = r#"
import tempfile, os
from zeropw.store import StateDir
from zeropw import policy as P

def probe_approvals(value):
    d = tempfile.mkdtemp()
    state = StateDir(os.path.join(d, "state"))
    state.create()
    state.write_json(P.CONTROL, {"approvals": value})
    pol = P.Policy(state)
    try:
        print(sorted(pol.list_approvals().items()))
    except Exception as e:
        print(type(e).__name__)

for v in ({}, "x", 5, None, {"a": 1}):
    probe_approvals(v)

def probe_history(value):
    d = tempfile.mkdtemp()
    state = StateDir(os.path.join(d, "state"))
    state.create()
    state.write_json(P.CONTROL, {"approval_history": value})
    pol = P.Policy(state)
    try:
        print(pol.approval_history())
    except Exception as e:
        print(type(e).__name__)

for v in ([], "ab", 5, None, {"a": 1, "b": 2}):
    probe_history(v)
"#;
    let out = run_python(script);
    let mut lines = out.lines();
    assert_eq!(lines.next().unwrap(), "[]"); // {} -> {}
    assert_eq!(lines.next().unwrap(), "ValueError"); // "x": dict("x") iterates 1-char elements, length 1 != 2
    assert_eq!(lines.next().unwrap(), "TypeError"); // 5
    assert_eq!(lines.next().unwrap(), "TypeError"); // None (explicit null, present key)
    assert_eq!(lines.next().unwrap(), "[('a', 1)]"); // {"a": 1}
    assert_eq!(lines.next().unwrap(), "[]"); // []
    assert_eq!(lines.next().unwrap(), "['a', 'b']"); // "ab" -> chars
    assert_eq!(lines.next().unwrap(), "TypeError"); // 5
    assert_eq!(lines.next().unwrap(), "TypeError"); // None
    assert_eq!(lines.next().unwrap(), "['a', 'b']"); // {"a":1,"b":2} -> keys
    assert!(lines.next().is_none());

    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));

    state
        .write_json(policy::CONTROL, &serde_json::json!({"approvals": {}}))
        .unwrap();
    assert_eq!(pol.list_approvals().unwrap(), serde_json::Map::new());

    state
        .write_json(policy::CONTROL, &serde_json::json!({"approvals": "x"}))
        .unwrap();
    assert!(
        pol.list_approvals()
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    state
        .write_json(policy::CONTROL, &serde_json::json!({"approvals": 5}))
        .unwrap();
    assert!(
        pol.list_approvals()
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    state
        .write_json(policy::CONTROL, &serde_json::json!({"approvals": null}))
        .unwrap();
    assert!(
        pol.list_approvals()
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    state
        .write_json(policy::CONTROL, &serde_json::json!({"approvals": {"a": 1}}))
        .unwrap();
    assert_eq!(
        pol.list_approvals().unwrap().get("a"),
        Some(&serde_json::json!(1))
    );

    state
        .write_json(
            policy::CONTROL,
            &serde_json::json!({"approval_history": []}),
        )
        .unwrap();
    assert_eq!(
        pol.approval_history().unwrap(),
        Vec::<serde_json::Value>::new()
    );

    state
        .write_json(
            policy::CONTROL,
            &serde_json::json!({"approval_history": "ab"}),
        )
        .unwrap();
    assert_eq!(
        pol.approval_history().unwrap(),
        vec![serde_json::json!("a"), serde_json::json!("b")]
    );

    state
        .write_json(policy::CONTROL, &serde_json::json!({"approval_history": 5}))
        .unwrap();
    assert!(
        pol.approval_history()
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    state
        .write_json(
            policy::CONTROL,
            &serde_json::json!({"approval_history": null}),
        )
        .unwrap();
    assert!(
        pol.approval_history()
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    state
        .write_json(
            policy::CONTROL,
            &serde_json::json!({"approval_history": {"a": 1, "b": 2}}),
        )
        .unwrap();
    assert_eq!(
        pol.approval_history().unwrap(),
        vec![serde_json::json!("a"), serde_json::json!("b")]
    );
}

// D-R3-3: `validate_name` has an explicit `isinstance(value, str)` guard, so
// a present non-string connection `id` gets the documented
// `InvalidInput("invalid_connection_id")`; `__post_init__` runs it BEFORE
// the `kind` membership check and AFTER the nested `build()` calls.
#[test]
fn connection_id_and_kind_checks_run_in_pythons_exact_order() {
    let base = r#"
base = {
    "id": "conn-1", "project": "p", "environment": "dev", "service": "svc",
    "kind": "http", "secret_id": "sec", "secret_version": None,
    "description": "",
    "http_target": {"scheme": "https", "host": "example.com", "port": 443},
    "http_auth": {"mode": "bearer"}, "http_scope": {},
    "ssh_target": None, "cli": None, "policy_version": 1, "status": "active",
    "created_at": "2020-01-01T00:00:00Z", "updated_at": "2020-01-01T00:00:00Z",
}
"#;
    let script = format!(
        r#"
from zeropw import policy as P

{base}

def probe(label, overrides):
    d = dict(base)
    d.update(overrides)
    try:
        P.Connection.from_dict(d)
        print(f"{{label}} OK")
    except Exception as e:
        print(f"{{label}} {{type(e).__name__}} {{getattr(e, 'reason', '')}}")

probe("id5", {{"id": 5}})
probe("idnull", {{"id": None}})
probe("idarr", {{"id": []}})
probe("id5_kind5", {{"id": 5, "kind": 5}})
probe("id5_badscheme", {{"id": 5, "http_target": {{"scheme": "ftp", "host": "example.com", "port": 443}}}})
probe("validid_kindzz", {{"kind": "zz"}})
"#
    );
    let out = run_python(&script);
    let lines: std::collections::HashMap<&str, &str> = out
        .lines()
        .map(|l| l.split_once(' ').expect("label + rest"))
        .collect();
    assert_eq!(lines["id5"], "InvalidInput invalid_connection_id");
    assert_eq!(lines["idnull"], "InvalidInput invalid_connection_id");
    assert_eq!(lines["idarr"], "InvalidInput invalid_connection_id");
    assert_eq!(lines["id5_kind5"], "InvalidInput invalid_connection_id");
    assert_eq!(lines["id5_badscheme"], "InvalidInput invalid_scheme");
    assert_eq!(
        lines["validid_kindzz"],
        "InvalidInput invalid_connection_kind"
    );

    let http_doc = || rust_connection().to_value();

    for bad_id in [
        serde_json::json!(5),
        serde_json::Value::Null,
        serde_json::json!([]),
    ] {
        let mut d = http_doc();
        d["id"] = bad_id.clone();
        assert_eq!(
            Connection::from_value(&d).unwrap_err().reason,
            "invalid_connection_id",
            "id={bad_id:?}"
        );
    }

    let mut d = http_doc();
    d["id"] = serde_json::json!(5);
    d["kind"] = serde_json::json!(5);
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "invalid_connection_id"
    );

    let mut d = http_doc();
    d["id"] = serde_json::json!(5);
    d["http_target"]["scheme"] = serde_json::json!("ftp");
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "invalid_scheme"
    );

    let mut d = http_doc();
    d["kind"] = serde_json::json!("zz");
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "invalid_connection_kind"
    );
}

// D-R3-4: `HttpScope`'s nested `build()` applies Python's `tuple(x)` to
// `methods`/`path_prefixes`/`confirm_methods`: a JSON string yields its
// characters, an object yields its keys, and only a genuinely non-iterable
// value (a number, bool) is an uncaught `TypeError`.
#[test]
fn http_scope_methods_and_path_prefixes_reproduce_pythons_tuple_semantics() {
    let script = r#"
from zeropw import policy as P

def probe(label, methods=None, path_prefixes=None, confirm_methods=()):
    try:
        s = P.HttpScope(methods, path_prefixes, confirm_methods)
        print(f"{label} OK {s.methods!r} {s.path_prefixes!r} {s.confirm_methods!r}")
    except Exception as e:
        print(f"{label} {type(e).__name__} {getattr(e, 'reason', '')}")

# methods
probe("methods_str_GET", methods=tuple("GET"))
probe("methods_empty_str", methods=tuple(""))
probe("methods_dict", methods=tuple({"GET": 1, "POST": 2}))
probe("methods_list_nonstr", methods=tuple([1, 2]))
probe("methods_num", methods=5)
# path_prefixes
probe("pp_nonstr_element", path_prefixes=tuple([1, "/api"]))
probe("pp_num", path_prefixes=5)
# confirm_methods
probe("cm_str_GET", confirm_methods=tuple("GET"))
probe("cm_dict", confirm_methods=tuple({"DELETE": 1}))
probe("cm_num", confirm_methods=5)
"#;
    let out = run_python(script);
    let lines: std::collections::HashMap<&str, &str> = out
        .lines()
        .map(|l| l.split_once(' ').expect("label + rest"))
        .collect();
    assert!(lines["methods_str_GET"].starts_with("InvalidInput invalid_method"));
    assert!(lines["methods_empty_str"].starts_with("OK"));
    // `{"GET": 1, "POST": 2}`'s *keys* are both valid HTTP methods, so
    // `tuple(dict)` -> `("GET", "POST")` succeeds -- this pins the
    // object-iterates-its-keys case as a genuine success, not a failure.
    assert!(lines["methods_dict"].starts_with("OK"));
    assert!(lines["methods_list_nonstr"].starts_with("InvalidInput invalid_method"));
    assert_eq!(lines["methods_num"], "TypeError ");
    assert_eq!(lines["pp_nonstr_element"], "AttributeError ");
    assert_eq!(lines["pp_num"], "TypeError ");
    assert!(lines["cm_str_GET"].starts_with("InvalidInput invalid_method"));
    // `{"DELETE": 1}`'s key is a valid HTTP method too.
    assert!(lines["cm_dict"].starts_with("OK"));
    assert_eq!(lines["cm_num"], "TypeError ");

    let http_doc = || rust_connection().to_value();

    let mut d = http_doc();
    d["http_scope"]["methods"] = serde_json::json!("GET");
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "invalid_method"
    );

    let mut d = http_doc();
    d["http_scope"]["methods"] = serde_json::json!("");
    assert!(Connection::from_value(&d).is_ok());

    let mut d = http_doc();
    d["http_scope"]["methods"] = serde_json::json!({"GET": 1, "POST": 2});
    assert!(Connection::from_value(&d).is_ok());

    let mut d = http_doc();
    d["http_scope"]["methods"] = serde_json::json!([1, 2]);
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "invalid_method"
    );

    let mut d = http_doc();
    d["http_scope"]["methods"] = serde_json::json!(5);
    assert!(
        Connection::from_value(&d)
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    let mut d = http_doc();
    d["http_scope"]["path_prefixes"] = serde_json::json!([1, "/api"]);
    assert!(
        Connection::from_value(&d)
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    let mut d = http_doc();
    d["http_scope"]["path_prefixes"] = serde_json::json!(5);
    assert!(
        Connection::from_value(&d)
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    let mut d = http_doc();
    d["http_scope"]["confirm_methods"] = serde_json::json!("GET");
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "invalid_method"
    );

    let mut d = http_doc();
    d["http_scope"]["confirm_methods"] = serde_json::json!({"DELETE": 1});
    assert!(Connection::from_value(&d).is_ok());

    let mut d = http_doc();
    d["http_scope"]["confirm_methods"] = serde_json::json!(5);
    assert!(
        Connection::from_value(&d)
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );
}

// D-R3-5 / D-R3-6: `CliProfile`'s `program` gets the documented
// `invalid_cli_program` for any present falsy value (not just an empty
// string); `extra_env`'s `dict(... or {})` coercion accepts an
// iterable-of-pairs; and the scalar `kind`/`program`/`base_url_env` checks
// must run BEFORE the per-entry `extra_env` loop, restoring Python's
// `__post_init__` order (a round-2 regression).
#[test]
fn cli_profile_program_falsy_and_extra_env_pairs_and_check_order() {
    let script = r#"
from zeropw import policy as P

def probe(label, program, kind="http", base_url_env="ZEROPW_API_BASE_URL", extra_env=None):
    try:
        c = P.CliProfile(program, kind, base_url_env, extra_env if extra_env is not None else {})
        print(f"{label} OK {c.program!r} {c.extra_env!r}")
    except Exception as e:
        print(f"{label} {type(e).__name__} {getattr(e, 'reason', '')}")

probe("program_empty", "")
probe("program_none", None)
probe("program_zero", 0)
probe("program_false", False)
probe("program_emptylist", [])
probe("program_emptydict", {})

# order regression probes (finding D-R3-6)
probe("kind_ftp_extra_zz", "git", kind="ftp", extra_env={"zz": "x"})
probe("program_empty_extra_bad_value", "", kind="http", extra_env={"AA": 5})

# extra_env pairs coercion (finding D-R3-5)
probe("extra_pairs_ok", "git", extra_env=dict([["A", "b"]]))
"#;
    let out = run_python(script);
    let lines: std::collections::HashMap<&str, &str> = out
        .lines()
        .map(|l| l.split_once(' ').expect("label + rest"))
        .collect();
    for label in [
        "program_empty",
        "program_none",
        "program_zero",
        "program_false",
        "program_emptylist",
        "program_emptydict",
    ] {
        assert_eq!(
            lines[label], "InvalidInput invalid_cli_program",
            "label={label}"
        );
    }
    assert_eq!(lines["kind_ftp_extra_zz"], "InvalidInput invalid_cli_kind");
    assert_eq!(
        lines["program_empty_extra_bad_value"],
        "InvalidInput invalid_cli_program"
    );
    assert!(lines["extra_pairs_ok"].starts_with("OK"));

    // `CliProfile::from_value` is private (as its Python counterpart's
    // constructor is only ever reached through `Connection.from_dict`'s
    // nested `build()`); exercise it the same way the rest of this file
    // does, through `Connection::from_value`'s public `cli` field.
    let cli_conn = |program: serde_json::Value, kind: &str, extra_env: serde_json::Value| {
        let mut d = rust_connection().to_value();
        d["cli"] = serde_json::json!({
            "program": program, "kind": kind, "base_url_env": "ZEROPW_API_BASE_URL",
            "extra_env": extra_env,
        });
        d
    };
    let good_extra = serde_json::json!({});

    for bad_program in [
        serde_json::json!(""),
        serde_json::Value::Null,
        serde_json::json!(0),
        serde_json::json!(false),
        serde_json::json!([]),
        serde_json::json!({}),
    ] {
        let d = cli_conn(bad_program.clone(), "http", good_extra.clone());
        assert_eq!(
            Connection::from_value(&d).unwrap_err().reason,
            "invalid_cli_program",
            "program={bad_program:?}"
        );
    }

    // Order regression (D-R3-6).
    let d = cli_conn(
        serde_json::json!("git"),
        "ftp",
        serde_json::json!({"zz": "x"}),
    );
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "invalid_cli_kind"
    );
    let d = cli_conn(serde_json::json!(""), "http", serde_json::json!({"AA": 5}));
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "invalid_cli_program"
    );

    // extra_env array-of-pairs coercion (D-R3-5).
    let d = cli_conn(
        serde_json::json!("git"),
        "http",
        serde_json::json!([["A", "b"]]),
    );
    let profile = Connection::from_value(&d).unwrap().cli.unwrap();
    assert_eq!(profile.extra_env.get("A"), Some(&"b".to_string()));
}

// D-R3-7: `Grant(**entry)` -- an unrecognised key in the stored grant makes
// the `**entry` unpacking raise an uncaught `TypeError`, the same shape
// `HttpTarget`/`HttpAuth` already reject (D-R2-6).
#[test]
fn grant_from_value_rejects_unknown_keys_like_pythons_kwarg_unpacking() {
    let script = r#"
from zeropw import policy as P

entry = {
    "id": "g-1", "principal": "agent-1", "connection": "conn-1", "policy_version": 1,
    "expires_at": None, "max_uses": None, "uses": 0, "status": "active",
    "created_at": "2020-01-01T00:00:00Z", "revoked_at": None, "credential_version": None,
    "unexpected_field": "x",
}
try:
    P.Grant(**entry)
    print("OK")
except TypeError as e:
    print("TypeError")
"#;
    let out = run_python(script);
    assert_eq!(out.trim(), "TypeError");

    // `Grant::from_value` is private (reached only through public `Policy`
    // methods, as `Grant(**entry)` is only ever reached through `Policy`
    // methods in Python); exercise it through `Policy::get_grant`.
    let entry = serde_json::json!({
        "id": "g-1", "principal": "agent-1", "connection": "conn-1", "policy_version": 1,
        "expires_at": null, "max_uses": null, "uses": 0, "status": "active",
        "created_at": "2020-01-01T00:00:00Z", "revoked_at": null, "credential_version": null,
        "unexpected_field": "x",
    });
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let mut grants = serde_json::Map::new();
    grants.insert("g-1".into(), entry.clone());
    state
        .write_json(policy::GRANTS, &serde_json::Value::Object(grants))
        .unwrap();
    let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
    assert!(
        pol.get_grant("g-1")
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    // A well-formed entry with only known keys still loads.
    let mut ok_entry = entry.clone();
    ok_entry.as_object_mut().unwrap().remove("unexpected_field");
    let mut grants = serde_json::Map::new();
    grants.insert("g-1".into(), ok_entry);
    state
        .write_json(policy::GRANTS, &serde_json::Value::Object(grants))
        .unwrap();
    assert!(pol.get_grant("g-1").is_ok());
}

// D-R3-8: `python_int_coerce(...).unwrap_or(default)` substituted a default
// (and completed the write) for a truthy value `int()` itself cannot
// coerce, where Python raises uncaught and writes nothing. The default must
// apply only to a genuinely ABSENT key.
#[test]
fn int_coerce_defaults_only_apply_to_an_absent_key_not_an_uncoercible_value() {
    let script = r#"
for c in ([1], {"a": 1}, "abc"):
    try:
        print(int(c or 1) + 1)
    except Exception as e:
        print(type(e).__name__)
for c in ([1], {"a": 1}, "abc", None):
    try:
        print(int(c) + 1)
    except Exception as e:
        print(type(e).__name__)
"#;
    let out = run_python(script);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines,
        vec![
            "TypeError",
            "TypeError",
            "ValueError", // cycle: truthy uncoercible
            "TypeError",
            "TypeError",
            "ValueError",
            "TypeError", // policy_version incl. explicit null
        ]
    );

    // `request_approval`'s `cycle` computation.
    for bad_cycle in [
        serde_json::json!([1]),
        serde_json::json!({"a": 1}),
        serde_json::json!("abc"),
    ] {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
        pol.create_principal("agent-1", "default").unwrap();
        pol.create_connection(rust_connection()).unwrap();
        let mut control = state
            .read_json(policy::CONTROL, serde_json::json!({}))
            .unwrap();
        let mut approvals = serde_json::Map::new();
        approvals.insert(
            "dg1".into(),
            serde_json::json!({
                "caller": "agent-1", "connection": "gh", "method": "GET", "path": "/repos",
                "status": "consumed", "created_at": "", "expires_at": 1_700_003_600.0,
                "grant": null, "policy_version": 0, "cycle": bad_cycle,
            }),
        );
        control["approvals"] = serde_json::Value::Object(approvals);
        state.write_json(policy::CONTROL, &control).unwrap();
        assert!(
            pol.request_approval("dg1", "agent-1", "gh", "GET", "/repos")
                .unwrap_err()
                .is(zeropw::errors::ErrorClass::StateError),
            "cycle={bad_cycle:?}"
        );
    }

    // `reapply_revocations`'s `policy_version` computation, including a
    // present explicit `null` (finding D-R3-8's extra probe).
    for bad_pv in [
        serde_json::json!([1]),
        serde_json::json!({"a": 1}),
        serde_json::json!("abc"),
        serde_json::Value::Null,
    ] {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
        let mut connections = serde_json::Map::new();
        connections.insert(
            "c-bad".into(),
            serde_json::json!({"status": "active", "policy_version": bad_pv}),
        );
        state
            .write_json(policy::CONNECTIONS, &serde_json::Value::Object(connections))
            .unwrap();
        let revocations = policy::Revocations {
            grants: Default::default(),
            principals: Default::default(),
            connections: ["c-bad"].into_iter().map(String::from).collect(),
            secret_versions: Default::default(),
        };
        assert!(
            pol.reapply_revocations(&revocations)
                .unwrap_err()
                .is(zeropw::errors::ErrorClass::StateError),
            "policy_version={bad_pv:?}"
        );
        // Nothing must have been written: the connection document is
        // untouched (still holds the original, uncoercible value).
        let after = state
            .read_json(policy::CONNECTIONS, serde_json::json!({}))
            .unwrap();
        assert_eq!(after["c-bad"]["status"], serde_json::json!("active"));
    }

    // Missing key still legitimately defaults (unaffected by this fix).
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
    let mut connections = serde_json::Map::new();
    connections.insert("c-missing".into(), serde_json::json!({"status": "active"}));
    state
        .write_json(policy::CONNECTIONS, &serde_json::Value::Object(connections))
        .unwrap();
    let revocations = policy::Revocations {
        grants: Default::default(),
        principals: Default::default(),
        connections: ["c-missing"].into_iter().map(String::from).collect(),
        secret_versions: Default::default(),
    };
    pol.reapply_revocations(&revocations).unwrap();
    let after = state
        .read_json(policy::CONNECTIONS, serde_json::json!({}))
        .unwrap();
    assert_eq!(after["c-missing"]["policy_version"], serde_json::json!(1));
}

// D-R3-9: Python compares the *raw* stored value against a resolved `int`
// using ordinary numeric equality across types (a stored float `2.0`, or
// `True` vs a resolved `1`, compares equal, so nothing changes); `as_i64`
// treats a float-shaped number as a mismatch, spuriously bumping the
// connection's policy version / reporting `policy_changed`.
#[test]
fn python_numeric_equality_used_for_stored_int_comparisons() {
    let script = r#"
print(2.0 != 2)
print(True != 1)
print(1.0 != 1)
print("2" != 2)
"#;
    let out = run_python(script);
    let mut lines = out.lines();
    assert_eq!(lines.next().unwrap(), "False");
    assert_eq!(lines.next().unwrap(), "False");
    assert_eq!(lines.next().unwrap(), "False");
    assert_eq!(lines.next().unwrap(), "True");

    assert!(python_numeric_eq_for_test(Some(&serde_json::json!(2.0)), 2));
    assert!(python_numeric_eq_for_test(
        Some(&serde_json::json!(true)),
        1
    ));
    assert!(python_numeric_eq_for_test(Some(&serde_json::json!(1.0)), 1));
    assert!(!python_numeric_eq_for_test(
        Some(&serde_json::json!("2")),
        2
    ));
    assert!(!python_numeric_eq_for_test(None, 2));

    // End-to-end through `credential_versions_changed`: a stored grant
    // `credential_version: 1.0` (float) must NOT be treated as a mismatch
    // against a resolved active version of `1`.
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
    pol.create_principal("agent-1", "default").unwrap();
    let connection = pol.create_connection(rust_connection()).unwrap();
    let grant = pol
        .create_grant("agent-1", &connection.id, None, None)
        .unwrap();

    let mut vault = serde_json::Map::new();
    let mut secrets = serde_json::Map::new();
    secrets.insert("gh-token".into(), serde_json::json!({"active_version": 1}));
    vault.insert("secrets".into(), serde_json::Value::Object(secrets));
    state
        .write_json(policy::VAULT_SECRETS, &serde_json::Value::Object(vault))
        .unwrap();

    let mut grants = state
        .read_json(policy::GRANTS, serde_json::json!({}))
        .unwrap();
    grants[&grant.id]["credential_version"] = serde_json::json!(1.0);
    state.write_json(policy::GRANTS, &grants).unwrap();

    let before_version = pol.get_connection(&connection.id).unwrap().policy_version;
    let changed = pol.credential_versions_changed("gh-token").unwrap();
    assert!(
        changed.is_empty(),
        "a numerically-equal float credential_version must not trigger a change"
    );
    let after_version = pol.get_connection(&connection.id).unwrap().policy_version;
    assert_eq!(before_version, after_version);
}

/// Exercises the same private numeric-equality logic `credential_versions_changed`
/// and `_approval_mismatch` use, via the observable `credential_versions_changed`
/// path above; this small standalone helper documents the exact truth table
/// asserted against Python above without re-deriving it by hand.
fn python_numeric_eq_for_test(stored: Option<&serde_json::Value>, resolved: i64) -> bool {
    match stored {
        Some(serde_json::Value::Bool(b)) => i64::from(*b) == resolved,
        Some(serde_json::Value::Number(n)) => {
            n.as_i64() == Some(resolved) || n.as_f64() == Some(resolved as f64)
        }
        _ => false,
    }
}

// D-R3-10: Python indexes `entry["token_hash"]` in `authenticate` and
// `entry["status"]` in `revoke_all` -- both raw dict indexing, not `.get()`
// -- so a malformed entry raises an uncaught `KeyError`, aborting the whole
// operation; `revoke_grants_of` legitimately uses `.get()` and keeps
// skipping a well-formed entry missing a key, but still crashes for an
// entry that isn't a dict at all.
#[test]
fn authenticate_and_revoke_all_fail_closed_on_a_malformed_entry() {
    let script = r#"
import tempfile, os
from zeropw.store import StateDir
from zeropw import policy as P

d = tempfile.mkdtemp()
state = StateDir(os.path.join(d, "state"))
state.create()
state.write_json(P.PRINCIPALS, {
    "bad": {"status": "active", "created_at": ""},  # missing token_hash
    "good": {"token_hash": P.hash_token("zpwc_abc"), "status": "active", "created_at": ""},
})
pol = P.Policy(state)
try:
    pol.authenticate("zpwc_abc")
    print("authenticate OK")
except Exception as e:
    print("authenticate", type(e).__name__)

d2 = tempfile.mkdtemp()
state2 = StateDir(os.path.join(d2, "state"))
state2.create()
state2.write_json(P.GRANTS, {"bad": "not-a-dict", "good": {"status": "active"}})
pol2 = P.Policy(state2)
try:
    pol2.revoke_all()
    print("revoke_all OK")
except Exception as e:
    print("revoke_all", type(e).__name__)
after = state2.read_json(P.GRANTS, None)
print("revoke_all untouched", after["good"]["status"] == "active")

d3 = tempfile.mkdtemp()
state3 = StateDir(os.path.join(d3, "state"))
state3.create()
state3.write_json(P.GRANTS, {"bad": "not-a-dict", "good": {"principal": "agent-1", "status": "active"}})
pol3 = P.Policy(state3)
try:
    pol3.revoke_grants_of("agent-1")
    print("revoke_grants_of OK")
except Exception as e:
    print("revoke_grants_of", type(e).__name__)
"#;
    let out = run_python(script);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "authenticate KeyError");
    // `entry["status"]` on a non-dict `entry` (a plain string) is a raw
    // index, which raises `TypeError` for a string (not `AttributeError`,
    // which is what a `.get()` call on a non-dict would raise instead).
    assert_eq!(lines[1], "revoke_all TypeError");
    assert_eq!(lines[2], "revoke_all untouched True");
    assert_eq!(lines[3], "revoke_grants_of AttributeError");

    // `authenticate`: a principal document with an earlier, malformed
    // entry aborts the whole scan even though a later entry would match.
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let mut principals = serde_json::Map::new();
    principals.insert(
        "bad".into(),
        serde_json::json!({"status": "active", "created_at": ""}),
    );
    principals.insert(
        "good".into(),
        serde_json::json!({
            "token_hash": policy::hash_token("zpwc_abc"), "status": "active", "created_at": "",
        }),
    );
    state
        .write_json(policy::PRINCIPALS, &serde_json::Value::Object(principals))
        .unwrap();
    let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
    assert!(
        pol.authenticate("zpwc_abc")
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    // `revoke_all`: a non-object grant entry aborts before anything is
    // written, not a partial write with the malformed entry skipped.
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let mut grants = serde_json::Map::new();
    grants.insert("bad".into(), serde_json::json!("not-a-dict"));
    grants.insert("good".into(), serde_json::json!({"status": "active"}));
    state
        .write_json(policy::GRANTS, &serde_json::Value::Object(grants))
        .unwrap();
    let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
    assert!(
        pol.revoke_all()
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );
    let after = state
        .read_json(policy::GRANTS, serde_json::json!({}))
        .unwrap();
    assert_eq!(after["good"]["status"], serde_json::json!("active"));

    // `revoke_grants_of`: a non-object entry also aborts (unlike a
    // well-formed entry missing a key, which is legitimately skipped).
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let mut grants = serde_json::Map::new();
    grants.insert("bad".into(), serde_json::json!("not-a-dict"));
    grants.insert(
        "good".into(),
        serde_json::json!({"principal": "agent-1", "status": "active"}),
    );
    state
        .write_json(policy::GRANTS, &serde_json::Value::Object(grants))
        .unwrap();
    let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
    assert!(
        pol.revoke_grants_of("agent-1")
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );
}
