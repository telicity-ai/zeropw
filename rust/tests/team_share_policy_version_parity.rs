//! `share_environment` bumps each converted local connection's
//! `policy_version` (`_force_grant_reevaluation_for_share`) so grants made
//! before the share are re-evaluated; a `policy_version` that is not a
//! number aborts the share after the retag. Outcomes were measured against
//! the Python prototype (`int(entry.get("policy_version", 0)) + 1`; `int(None)`
//! raised `TypeError`) and are pinned here.
use serde_json::{Value, json};
use tempfile::TempDir;
use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::policy::{CONNECTIONS, Connection, HttpAuth, HttpScope, HttpTarget};
use zeropw::team::membership;

const ADMIN: &str = "synthetic-admin";

/// A state with one active secret and one local connection whose stored
/// `policy_version` is `value`.
fn prepare(path: &std::path::Path, value: Value) {
    let ctx = Context::initialize(
        path,
        ADMIN,
        "synthetic-recovery",
        Config::default(),
        clock::system(),
    )
    .unwrap();
    ctx.projects.create("demo", &["dev"]).unwrap();
    ctx.vault
        .put_secret("secret", "api_key", b"synthetic-seed", "demo", "dev", true)
        .unwrap();
    let connection = Connection::new(
        "connection",
        "demo",
        "dev",
        "synthetic",
        "http",
        "secret",
        None,
        "",
        Some(HttpTarget::new("https", "example.com".to_string(), 443, None, false).unwrap()),
        Some(HttpAuth::bearer()),
        Some(HttpScope::new(Some(vec!["GET".into()]), None, vec![]).unwrap()),
        None,
        None,
        0,
        "active",
        "",
        "",
    )
    .unwrap();
    ctx.policy.create_connection(connection).unwrap();
    let mut connections = ctx.state.read_json(CONNECTIONS, json!({})).unwrap();
    connections["connection"]["policy_version"] = value;
    ctx.state.write_json(CONNECTIONS, &connections).unwrap();
}

#[test]
fn share_policy_version_bump() {
    let root = TempDir::new().unwrap();
    for (name, value, expected) in [
        // 4 + 1, then the share's own fold/derive bumps it further.
        (
            "int",
            json!(4),
            json!({"outcome": "OK", "policy_version": 7, "shared": true}),
        ),
        (
            "null",
            Value::Null,
            json!({"outcome": "ERR", "policy_version": null, "shared": true}),
        ),
    ] {
        let state = root.path().join(name);
        prepare(&state, value);
        let ctx = Context::open(&state, Config::default(), clock::system()).unwrap();
        let outcome = match membership::share_environment(&ctx, None, "demo", "dev", "owner", ADMIN)
        {
            Ok(_) => "OK",
            Err(_) => "ERR",
        };
        let stored = ctx.state.read_json(CONNECTIONS, Value::Null).unwrap()["connection"].clone();
        assert_eq!(
            json!({"outcome": outcome, "policy_version": stored["policy_version"],
                "shared": !stored["shared_env"].is_null()}),
            expected,
            "{name}"
        );
    }
}
