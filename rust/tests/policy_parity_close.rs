//! Policy behaviour pinned during the 2026-10-03 parity-closing work.
//!
//! The Python-differential matrices that used to live here compared
//! hand-edited, malformed documents against the retired prototype; they are
//! outside the compatibility contract (PORTING.md §0) and were removed. What
//! remains is the security-relevant memo scoping below, asserted against its
//! explicit expected outcome.

use serde_json::{Value, json};
use tempfile::TempDir;
use zeropw::clock;
use zeropw::errors::Error;
use zeropw::policy::{self, ConnectionChanges, Policy};
use zeropw::store::StateDir;

const CLOCK: f64 = 1_700_000_000.0;

fn rust_outcome(r: Result<Value, Error>) -> Value {
    match r {
        Ok(v) => json!({"ok": v}),
        Err(e) => json!({"err": [e.class.class_name(), e.reason]}),
    }
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

fn rust_state(
    tmp: &TempDir,
    connections: Value,
    grants: Value,
    control: Option<Value>,
) -> StateDir {
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

/// Row 78: the "last allowed evaluate" memo is scoped per `(Policy
/// instance, thread)`. Observable through `consume` without an explicit
/// policy version: after `evaluate`, a narrowing `update_connection` bumps
/// the policy version (grants re-evaluated in place), so the memo's stale
/// version refuses with `grant_stale`, while an instance or thread without
/// the memo consumes normally.
#[test]
fn evaluated_memo_is_scoped_per_instance_and_thread() {
    let expected = json!({
        "same": {"err": ["PolicyDenied", "grant_stale"]},
        "other_instance": {"ok": 1},
        "other_thread": {"ok": 1},
    });
    let grant = json!({"id": "g-1", "principal": "agent-1", "connection": "gh", "policy_version": 1,
        "expires_at": null, "max_uses": null, "uses": 0, "status": "active", "created_at": "",
        "revoked_at": null, "credential_version": 1});
    for case in ["same", "other_instance", "other_thread"] {
        let tmp = TempDir::new().unwrap();
        let state = rust_state(
            &tmp,
            json!({"gh": connection_doc(Value::Null, json!(1))}),
            json!({"g-1": grant.clone()}),
            None,
        );
        let p1 = Policy::new(&state, clock::fixed(CLOCK));
        let p2 = Policy::new(&state, clock::fixed(CLOCK));
        p1.evaluate(
            "agent-1",
            "gh",
            &policy::Action::http("GET", "/repos"),
            None,
        )
        .unwrap();
        p2.update_connection("gh", ConnectionChanges::new().description("x"))
            .unwrap();
        let consume = |p: &Policy| {
            rust_outcome(
                p.consume("g-1", None, None, None, None)
                    .map(|g| json!(g.uses)),
            )
        };
        let rust = match case {
            "same" => consume(&p1),
            "other_instance" => consume(&p2),
            _ => std::thread::scope(|s| s.spawn(|| consume(&p1)).join().unwrap()),
        };
        assert_eq!(expected[case], rust, "{case}");
    }
}
