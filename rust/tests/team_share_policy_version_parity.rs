//! `zeropw/team/membership.py`'s `_force_grant_reevaluation_for_share`
//! bumps each converted local connection with `entry["policy_version"] =
//! int(entry.get("policy_version", 0)) + 1`: CPython's `int()` (a numeric
//! string, a truncated float and a bool are accepted) at unbounded
//! precision, and an `int()` failure aborts the share. Compared here with
//! states prepared by Python for both halves.
use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use tempfile::TempDir;
use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::team::membership;

fn python(script: &str) -> Value {
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".into());
    let mut child = Command::new(interpreter)
        .arg("-")
        .env("PYTHONPATH", format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

const CASES: &[&str] = &["int", "numeric_string", "float", "bool", "null"];

#[test]
fn share_policy_version_bump_matches_python_int() {
    let root = TempDir::new().unwrap();
    let rust_states: Vec<_> = CASES
        .iter()
        .map(|name| root.path().join(format!("rust-{name}")))
        .collect();
    let python_states: Vec<_> = CASES
        .iter()
        .map(|name| root.path().join(format!("python-{name}")))
        .collect();
    let script = format!(
        r#"
import json
from pathlib import Path
from zeropw import policy as P
from zeropw.context import Config, Context
from zeropw.team import membership as M

values = {{"int": 4, "numeric_string": " 7 ", "float": 2.9, "bool": True, "null": None}}

def prepare(path, name):
    ctx = Context.initialize(Path(path), "synthetic-admin", "synthetic-recovery", Config())
    ctx.projects.create("demo", ["dev"])
    ctx.vault.put_secret("secret", "api_key", b"synthetic-seed", "demo", "dev")
    ctx.policy.create_connection(P.Connection(
        id="connection", project="demo", environment="dev", service="synthetic", kind="http",
        secret_id="secret", secret_version=None, description="",
        http_target=P.HttpTarget("https", "example.com", 443), http_auth=P.HttpAuth("bearer"),
        http_scope=P.HttpScope(), ssh_target=None, cli=None, policy_version=0, status="active",
        created_at="", updated_at=""))
    connections = ctx.state.read_json(P.CONNECTIONS)
    connections["connection"]["policy_version"] = values[name]
    ctx.state.write_json(P.CONNECTIONS, connections)
    return ctx

out = {{}}
for name, rust_path, python_path in zip({names}, {rust}, {python}):
    prepare(rust_path, name).close()
    ctx = prepare(python_path, name)
    try:
        M.share_environment(ctx, None, "demo", "dev", "owner", "synthetic-admin")
        outcome = "OK"
    except Exception as exc:
        outcome = "ERR " + type(exc).__name__
    stored = ctx.state.read_json(P.CONNECTIONS)["connection"]
    out[name] = {{"outcome": outcome, "policy_version": stored["policy_version"],
                 "shared": stored.get("shared_env") is not None}}
print(json.dumps(out))
"#,
        names = serde_json::to_string(CASES).unwrap(),
        rust = serde_json::to_string(&rust_states).unwrap(),
        python = serde_json::to_string(&python_states).unwrap(),
    );
    let expected = python(&script);
    for (name, state) in CASES.iter().zip(&rust_states) {
        let ctx = Context::open(state, Config::default(), clock::system()).unwrap();
        let outcome = match membership::share_environment(
            &ctx,
            None,
            "demo",
            "dev",
            "owner",
            "synthetic-admin",
        ) {
            Ok(_) => "OK".to_string(),
            Err(_) => "ERR".to_string(),
        };
        let stored = ctx
            .state
            .read_json(zeropw::policy::CONNECTIONS, Value::Null)
            .unwrap()["connection"]
            .clone();
        let rust = json!({"outcome": outcome, "policy_version": stored["policy_version"],
            "shared": !stored["shared_env"].is_null()});
        let mut python = expected[*name].clone();
        if python["outcome"].as_str().unwrap().starts_with("ERR") {
            python["outcome"] = json!("ERR");
        }
        assert_eq!(rust, python, "{name}");
    }
    // `int(" 7 ")`, `int(2.9)` and `int(True)` are accepted (the share
    // then folds and derives the connection, bumping it further);
    // `int(None)` raises and aborts the share after the retag.
    assert_eq!(expected["numeric_string"]["outcome"], json!("OK"));
    assert_eq!(expected["float"]["outcome"], json!("OK"));
    assert_eq!(expected["bool"]["outcome"], json!("OK"));
    assert_eq!(expected["null"]["outcome"], json!("ERR TypeError"));
    assert_ne!(
        expected["numeric_string"]["policy_version"],
        expected["int"]["policy_version"]
    );
}
