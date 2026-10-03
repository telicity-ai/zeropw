//! Differential tests for the `policy` parity-closing work (2026-10-03):
//! every case runs the real `zeropw.policy` under the pinned CPython and the
//! same operation through `zeropw::policy`, then compares outcomes and the
//! persisted document bytes.
//!
//! Covered here:
//! - `Connection.secret_version` of every JSON shape (Python stores it
//!   untyped and verbatim);
//! - `Connection.policy_version` / approval `cycle` beyond `i64`
//!   (`int(...)` and `+ 1` on an unbounded Python `int`).

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use regex::Regex;
use serde_json::{Value, json};
use tempfile::TempDir;
use zeropw::clock;
use zeropw::errors::Error;
use zeropw::policy::{self, ConnectionChanges, Policy, Revocations};
use zeropw::store::StateDir;

const CLOCK: f64 = 1_700_000_000.0;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

/// Runs `script` under the pinned interpreter (fed over stdin) and returns
/// its stdout.
fn run_python(script: &str) -> String {
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".to_string());
    let mut child = Command::new(&interpreter)
        .arg("-")
        .env("PYTHONPATH", repo_root())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn python");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(script.as_bytes())
        .expect("write script");
    let output = child.wait_with_output().expect("wait python");
    assert!(
        output.status.success(),
        "python failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8")
}

/// Shared Python prelude: the baseline documents and the outcome encoding
/// (`{"ok": value}`, `{"err": [class, reason]}` for a `ZeroPWError`, or
/// `{"err": [class, null]}` for an uncaught built-in exception).
const PY_PRELUDE: &str = r#"
import json, os, re, tempfile
from zeropw.store import StateDir
from zeropw import policy as P

CLOCK = 1700000000.0

def connection(secret_version=None, policy_version=1):
    return {
        "id": "gh", "project": "demo", "environment": "dev", "service": "svc", "kind": "http",
        "secret_id": "gh-token", "secret_version": secret_version, "description": "d",
        "http_target": {"scheme": "http", "host": "127.0.0.1", "port": 8080, "ca_file": None,
                        "allow_private_network": False},
        "http_auth": {"mode": "bearer", "header_name": None, "value_prefix": None, "basic_username": None},
        "http_scope": {"methods": None, "path_prefixes": None, "confirm_methods": []},
        "ssh_target": None, "cli": None, "policy_version": policy_version, "status": "active",
        "created_at": "", "updated_at": "",
    }

def state_with(tmp, connections, grants=None, control=None):
    st = StateDir(os.path.join(tmp, "s"))
    st.create()
    st.write_json(P.PRINCIPALS, {"agent-1": {"token_hash": P.hash_token("zpwc_abc"), "status": "active",
                                             "created_at": "", "runtime": "default"}})
    st.write_json(P.CONNECTIONS, connections)
    st.write_json(P.GRANTS, grants if grants is not None else {})
    if control is not None:
        st.write_json(P.CONTROL, control)
    st.write_json(P.VAULT_SECRETS, {"secrets": {"gh-token": {"active_version": 1}}})
    return st

def outcome(fn):
    try:
        return {"ok": fn()}
    except Exception as e:
        return {"err": [type(e).__name__, getattr(e, "reason", None)]}

GRANT_ID = re.compile(r"g-[0-9a-f]{16}")

def doc(st, name):
    with open(os.path.join(st.path, name), encoding="utf-8") as f:
        return GRANT_ID.sub("g-NEW", f.read())
"#;

fn rust_outcome(r: Result<Value, Error>) -> Value {
    match r {
        Ok(v) => json!({"ok": v}),
        Err(e) => json!({"err": [e.class.class_name(), e.reason]}),
    }
}

/// Python's outcome against Rust's: equal, or both failed where Python's
/// failure was an uncaught built-in exception (PORTING.md §3.5).
fn outcomes_agree(py: &Value, rust: &Value) -> bool {
    if py == rust {
        return true;
    }
    py.get("err").is_some_and(|e| e[1].is_null()) && rust.get("err").is_some()
}

fn grant_id_normalized(text: &str) -> String {
    let re = Regex::new(r"g-[0-9a-f]{16}").unwrap();
    re.replace_all(text, "g-NEW").into_owned()
}

fn read_doc(state: &StateDir, name: &str) -> String {
    let text = std::fs::read_to_string(state.path.join(name)).unwrap();
    grant_id_normalized(&text)
}

fn connection_doc(secret_version: Value, policy_version: Value) -> Value {
    json!({
        "id": "gh", "project": "demo", "environment": "dev", "service": "svc", "kind": "http",
        "secret_id": "gh-token", "secret_version": secret_version, "description": "d",
        "http_target": {"scheme": "http", "host": "127.0.0.1", "port": 8080, "ca_file": null,
                        "allow_private_network": false},
        "http_auth": {"mode": "bearer", "header_name": null, "value_prefix": null, "basic_username": null},
        "http_scope": {"methods": null, "path_prefixes": null, "confirm_methods": []},
        "ssh_target": null, "cli": null, "policy_version": policy_version, "status": "active",
        "created_at": "", "updated_at": "",
    })
}

fn rust_state(tmp: &TempDir, connections: Value, grants: Value, control: Option<Value>) -> StateDir {
    let state = StateDir::new(tmp.path().join("s"));
    state.create().unwrap();
    state
        .write_json(
            policy::PRINCIPALS,
            &json!({"agent-1": {"token_hash": policy::hash_token("zpwc_abc"), "status": "active",
                                "created_at": "", "runtime": "default"}}),
        )
        .unwrap();
    state.write_json(policy::CONNECTIONS, &connections).unwrap();
    state.write_json(policy::GRANTS, &grants).unwrap();
    if let Some(control) = control {
        state.write_json(policy::CONTROL, &control).unwrap();
    }
    state
        .write_json(
            policy::VAULT_SECRETS,
            &json!({"secrets": {"gh-token": {"active_version": 1}}}),
        )
        .unwrap();
    state
}

/// The JSON literal texts of the `secret_version` shapes probed: every
/// one is a successful, verbatim-kept value in Python.
const SECRET_VERSION_SHAPES: &[&str] = &[
    "null",
    "5",
    "1180591620717411303424",
    "true",
    "false",
    "1.0",
    "1.5",
    "\"abc\"",
    "\"1\"",
    "\"\"",
    "[1]",
    "[]",
    "{\"a\": 1}",
    "{}",
];

#[test]
fn connection_secret_version_of_every_shape_loads_persists_and_binds_grants_like_python() {
    let shapes_json = serde_json::to_string(SECRET_VERSION_SHAPES).unwrap();
    let script = format!(
        r#"{PY_PRELUDE}
for text in json.loads({shapes_json:?}):
    value = json.loads(text)
    out = {{"shape": text}}
    with tempfile.TemporaryDirectory() as tmp:
        st = state_with(tmp, {{"gh": connection(value)}})
        pol = P.Policy(st, clock=lambda: CLOCK)
        out["get"] = outcome(lambda: pol.get_connection("gh").to_dict()["secret_version"])
        out["grant"] = outcome(lambda: P.asdict(pol.create_grant("agent-1", "gh", None, None))["credential_version"])
        out["update"] = outcome(lambda: [x if isinstance(x, bool) else x.to_dict()["secret_version"]
                                         for x in pol.update_connection("gh", description="x")])
        out["switch"] = outcome(lambda: pol.switch_credential("gh", None).to_dict()["secret_version"])
        out["connections"] = doc(st, P.CONNECTIONS)
        out["grants"] = doc(st, P.GRANTS)
    print(json.dumps(out, sort_keys=True))
"#
    );
    let python = run_python(&script);
    assert_eq!(python.lines().count(), SECRET_VERSION_SHAPES.len());
    let mut divergences = Vec::new();
    for (line, shape) in python.lines().zip(SECRET_VERSION_SHAPES) {
        let py: Value = serde_json::from_str(line).unwrap();
        assert_eq!(py["shape"], json!(shape));
        let value: Value = zeropw::pyjson::loads(shape).unwrap();
        let tmp = TempDir::new().unwrap();
        let state = rust_state(
            &tmp,
            json!({"gh": connection_doc(value, json!(1))}),
            json!({}),
            None,
        );
        let pol = Policy::new(&state, clock::fixed(CLOCK));
        let get = rust_outcome(
            pol.get_connection("gh")
                .map(|c| c.to_value()["secret_version"].clone()),
        );
        let grant = rust_outcome(pol.create_grant("agent-1", "gh", None, None).map(|_| {
            let grants = state.read_json(policy::GRANTS, json!({})).unwrap();
            grants
                .as_object()
                .unwrap()
                .values()
                .next()
                .unwrap()["credential_version"]
                .clone()
        }));
        let update = rust_outcome(
            pol.update_connection("gh", ConnectionChanges::new().description("x"))
                .map(|(c, widened)| json!([c.to_value()["secret_version"], widened])),
        );
        let switch = rust_outcome(
            pol.switch_credential("gh", None)
                .map(|c| c.to_value()["secret_version"].clone()),
        );
        for (key, rust) in [
            ("get", get),
            ("grant", grant),
            ("update", update),
            ("switch", switch),
        ] {
            if !outcomes_agree(&py[key], &rust) {
                divergences.push(format!("{shape} {key}: python={} rust={rust}", py[key]));
            }
        }
        for (key, name) in [
            ("connections", policy::CONNECTIONS),
            ("grants", policy::GRANTS),
        ] {
            let rust = read_doc(&state, name);
            if py[key].as_str() != Some(rust.as_str()) {
                divergences.push(format!(
                    "{shape} {key} bytes:\n  python: {}\n  rust:   {rust}",
                    py[key]
                ));
            }
        }
    }
    assert!(divergences.is_empty(), "{}", divergences.join("\n"));
}

/// The pinned version Python's `vault.resolve_version` /
/// `secret_for_trusted_use` receive, narrowed the way
/// `Connection::secret_version_for_resolve` / `_for_trusted_use` document:
/// Python's `item.version == version` against an integer vault version,
/// then `str(version)` as the record key.
#[test]
fn connection_secret_version_vault_narrowing_matches_python_comparisons() {
    let shapes_json = serde_json::to_string(SECRET_VERSION_SHAPES).unwrap();
    let script = format!(
        r#"import json
for text in json.loads({shapes_json:?}):
    value = json.loads(text)
    if value is None:
        print(json.dumps({{"resolve": None, "key": None}}))
        continue
    try:
        matches = [v for v in (0, 1, 5, 2**70) if v == value]
    except Exception:
        matches = []
    key = str(value) if matches else None
    print(json.dumps({{"resolve": matches[0] if matches else "not_found",
                      "key": key}}))
"#
    );
    let python = run_python(&script);
    assert_eq!(python.lines().count(), SECRET_VERSION_SHAPES.len());
    for (line, shape) in python.lines().zip(SECRET_VERSION_SHAPES) {
        let py: Value = serde_json::from_str(line).unwrap();
        let value: Value = zeropw::pyjson::loads(shape).unwrap();
        let mut doc = connection_doc(value, json!(1));
        doc["policy_version"] = json!(1);
        let connection = policy::Connection::from_value(&doc).unwrap();
        let resolve = match connection.secret_version_for_resolve() {
            Ok(None) => Value::Null,
            Ok(Some(v)) => v.value(),
            Err(e) => {
                assert_eq!(e.reason, "secret_version_not_found", "{shape}");
                json!("not_found")
            }
        };
        // Python resolved to the integer vault version (among the probed
        // 0, 1, 5, 2**70) the stored value compares equal to, or none.
        assert_eq!(resolve, py["resolve"], "{shape}");
        let trusted = connection.secret_version_for_trusted_use();
        match (&py["key"], trusted) {
            (Value::Null, Ok(None)) => {}
            (Value::Null, Err(e)) => assert_eq!(e.reason, "secret_version_not_found", "{shape}"),
            // `str(version)` is the integer's own decimal text only for a
            // plain JSON integer; `"True"`/`"1.0"` find no record.
            (Value::String(key), Ok(Some(v))) => assert_eq!(key, &v.to_string(), "{shape}"),
            (Value::String(key), Err(e)) => {
                assert_eq!(e.reason, "state_corrupt", "{shape}");
                assert!(key.parse::<i128>().is_err(), "{shape}: {key}");
            }
            (py_key, rust) => panic!("{shape}: python key {py_key} rust {rust:?}"),
        }
    }
}

/// `Connection.policy_version` / approval `cycle` at and past `i64`:
/// Python's `int(...)` and `+ 1` are unbounded.
#[test]
fn policy_version_and_cycle_past_i64_continue_like_python() {
    const VERSIONS: &[&str] = &[
        "9223372036854775807",
        "9223372036854775808",
        "-9223372036854775809",
        "1000000000000000000000000000000",
        "\" 1_000_000_000_000_000_000_000 \"",
        "1e30",
        "9.223372036854776e18",
        "true",
    ];
    let versions_json = serde_json::to_string(VERSIONS).unwrap();
    let script = format!(
        r#"{PY_PRELUDE}
for text in json.loads({versions_json:?}):
    value = json.loads(text)
    out = {{}}
    grant = {{"id": "g-1", "principal": "agent-1", "connection": "gh", "policy_version": value,
             "expires_at": None, "max_uses": None, "uses": 0, "status": "active", "created_at": "",
             "revoked_at": None, "credential_version": 1}}
    control = {{"stopped": False, "restore_pending": False, "approvals": {{
        "dg": {{"caller": "agent-1", "connection": "gh", "method": "GET", "path": "/", "status": "expired",
               "created_at": "", "expires_at": 0, "grant": None, "policy_version": 1, "cycle": value}}}}}}
    for op in ("get", "check", "update", "changed", "reapply", "request"):
        with tempfile.TemporaryDirectory() as tmp:
            st = state_with(tmp, {{"gh": connection(None, value)}}, {{"g-1": dict(grant)}}, control)
            pol = P.Policy(st, clock=lambda: CLOCK)
            if op == "get":
                r = outcome(lambda: pol.get_connection("gh").public_view())
            elif op == "check":
                r = outcome(lambda: [pol.check_grant("agent-1", "gh", "g-1").allowed,
                                     pol.check_grant("agent-1", "gh", "g-1").reason])
            elif op == "update":
                r = outcome(lambda: pol.update_connection("gh", description="x")[0].policy_version)
            elif op == "changed":
                st.write_json(P.VAULT_SECRETS, {{"secrets": {{"gh-token": {{"active_version": 2}}}}}})
                r = outcome(lambda: [c.policy_version for c in pol.credential_versions_changed("gh-token")])
            elif op == "reapply":
                r = outcome(lambda: pol.reapply_revocations(P.Revocations(connections={{"gh"}})))
            else:
                r = outcome(lambda: pol.request_approval("dg", "agent-1", "gh", "GET", "/"))
            out[op] = {{"outcome": r, "connections": doc(st, P.CONNECTIONS),
                       "grants": doc(st, P.GRANTS), "control": doc(st, P.CONTROL)}}
    print(json.dumps(out, sort_keys=True))
"#
    );
    let python = run_python(&script);
    assert_eq!(python.lines().count(), VERSIONS.len());
    let mut divergences = Vec::new();
    for (line, text) in python.lines().zip(VERSIONS) {
        let py: Value = serde_json::from_str(line).unwrap();
        let value: Value = zeropw::pyjson::loads(text).unwrap();
        let grant = json!({"id": "g-1", "principal": "agent-1", "connection": "gh",
            "policy_version": value, "expires_at": null, "max_uses": null, "uses": 0,
            "status": "active", "created_at": "", "revoked_at": null, "credential_version": 1});
        let control = json!({"stopped": false, "restore_pending": false, "approvals": {
            "dg": {"caller": "agent-1", "connection": "gh", "method": "GET", "path": "/",
                   "status": "expired", "created_at": "", "expires_at": 0, "grant": null,
                   "policy_version": 1, "cycle": value}}});
        for op in ["get", "check", "update", "changed", "reapply", "request"] {
            let tmp = TempDir::new().unwrap();
            let state = rust_state(
                &tmp,
                json!({"gh": connection_doc(Value::Null, value.clone())}),
                json!({"g-1": grant.clone()}),
                Some(control.clone()),
            );
            let pol = Policy::new(&state, clock::fixed(CLOCK));
            let rust = rust_outcome(match op {
                "get" => pol.get_connection("gh").map(|c| c.public_view()),
                "check" => pol
                    .check_grant("agent-1", "gh", "g-1")
                    .map(|d| json!([d.allowed, d.reason])),
                "update" => pol
                    .update_connection("gh", ConnectionChanges::new().description("x"))
                    .map(|(c, _)| c.policy_version.value()),
                "changed" => {
                    state
                        .write_json(
                            policy::VAULT_SECRETS,
                            &json!({"secrets": {"gh-token": {"active_version": 2}}}),
                        )
                        .unwrap();
                    pol.credential_versions_changed("gh-token").map(|cs| {
                        Value::Array(cs.iter().map(|c| c.policy_version.value()).collect())
                    })
                }
                "reapply" => pol
                    .reapply_revocations(&Revocations {
                        connections: ["gh".to_string()].into_iter().collect(),
                        ..Default::default()
                    })
                    .map(|counts| {
                        let mut m = serde_json::Map::new();
                        for key in ["grants", "principals", "connections"] {
                            m.insert(key.to_string(), json!(counts[key]));
                        }
                        Value::Object(m)
                    }),
                _ => pol.request_approval("dg", "agent-1", "gh", "GET", "/"),
            });
            let py_op = &py[op];
            if !outcomes_agree(&py_op["outcome"], &rust) {
                divergences.push(format!(
                    "{text} {op}: python={} rust={rust}",
                    py_op["outcome"]
                ));
                continue;
            }
            for (key, name) in [
                ("connections", policy::CONNECTIONS),
                ("grants", policy::GRANTS),
                ("control", policy::CONTROL),
            ] {
                let rust_doc = read_doc(&state, name);
                if py_op[key].as_str() != Some(rust_doc.as_str()) {
                    divergences.push(format!(
                        "{text} {op} {key} bytes:\n  python: {}\n  rust:   {rust_doc}",
                        py_op[key]
                    ));
                }
            }
        }
    }
    assert!(divergences.is_empty(), "{}", divergences.join("\n"));
}

/// `_validate_host`'s `host.strip().lower()` is CPython's `str.lower()`
/// (Unicode 15.0.0), observable through the stored host of an IPv6 literal
/// whose `%zone` suffix may hold any text. U+A7CB and U+10D50 gained
/// lowercase mappings after Unicode 15.0.0, so Rust's own `to_lowercase`
/// lowers them where CPython 3.12 does not.
#[test]
fn validate_host_lowers_like_cpython_str_lower() {
    const HOSTS: &[&str] = &[
        "EXAMPLE.COM",
        " Example.Com\u{85}",
        "FE80::1%ETH0",
        "fe80::1%\u{c9}TH0",
        "fe80::1%\u{130}",
        "fe80::1%A\u{3a3}",
        "fe80::1%A\u{3a3}B",
        "fe80::1%\u{a7cb}",
        "fe80::1%\u{10d50}",
        "fe80::1%\u{1e921}",
        "\u{212a}EY.example",
        "EXAMPLE.\u{a7cb}",
    ];
    // `ensure_ascii` JSON text, spliced into a raw Python string literal.
    let hosts_json =
        zeropw::pyjson::dumps(&json!(HOSTS), zeropw::pyjson::DumpOptions::plain()).unwrap();
    let script = format!(
        r#"import json
from zeropw import policy as P
for host in json.loads(r'''{hosts_json}'''):
    try:
        print(json.dumps({{"ok": P._validate_host(host)}}))
    except Exception as e:
        print(json.dumps({{"err": [type(e).__name__, getattr(e, "reason", None)]}}))
"#
    );
    let python = run_python(&script);
    assert_eq!(python.lines().count(), HOSTS.len());
    for (line, host) in python.lines().zip(HOSTS) {
        let py: Value = serde_json::from_str(line).unwrap();
        let rust = rust_outcome(
            policy::HttpTarget::from_stored("http", *host, 80, None, false).map(|t| json!(t.host)),
        );
        assert_eq!(py, rust, "{host:?}");
    }
}
