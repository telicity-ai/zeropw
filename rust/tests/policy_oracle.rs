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
