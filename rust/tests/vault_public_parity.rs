//! `Vault::list_secrets`/`get_meta` over hand-edited `public` metadata: a
//! falsy value reads as `{}`, anything that is not a mapping fails closed
//! with `state_corrupt`, and neither path mutates the vault document. The
//! malformed documents are synthetic and contain no credentials.

use std::fs;

use serde_json::{Value, json};
use tempfile::TempDir;

use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::errors::ErrorClass;
use zeropw::projects;
use zeropw::vault::VAULT_DOC;

const NOW: f64 = 1_700_000_000.0;

#[test]
fn public_metadata_falsy_is_empty_and_malformed_fails_closed_without_mutating_state() {
    let cases = [
        ("missing", None, Some(json!({}))),
        ("null", Some(Value::Null), Some(json!({}))),
        ("false", Some(json!(false)), Some(json!({}))),
        ("zero", Some(json!(0)), Some(json!({}))),
        ("zero-float", Some(json!(0.0)), Some(json!({}))),
        ("empty-string", Some(json!("")), Some(json!({}))),
        ("empty-array", Some(json!([])), Some(json!({}))),
        ("empty-object", Some(json!({})), Some(json!({}))),
        ("truthy-number", Some(json!(1)), None),
        ("outer-string", Some(json!("ab")), None),
        ("short-pair", Some(json!([["a"]])), None),
        ("long-pair", Some(json!([["a", 1, 2]])), None),
        ("noniterable-item", Some(json!([true])), None),
        ("short-object-pair", Some(json!([{"a": 1}])), None),
        ("unhashable-key", Some(json!([[[], 1]])), None),
    ];

    for (name, public, expected) in cases {
        let tmp = TempDir::new().unwrap();
        let state = tmp.path().join("state");
        let config = Config {
            socket_dir: Some(tmp.path().join("sockets")),
            run_dir: Some(tmp.path().join("run")),
            ..Config::default()
        };
        let ctx = Context::initialize(
            &state,
            "admin-passphrase-1",
            "recovery-passphrase-1",
            config,
            clock::fixed(NOW),
        )
        .unwrap();
        ctx.projects
            .create("demo", projects::DEFAULT_ENVIRONMENTS)
            .unwrap();
        ctx.vault
            .put_secret("key", "api_key", b"synthetic", "demo", "dev", true)
            .unwrap();

        let mut document = ctx.state.read_json(VAULT_DOC, Value::Null).unwrap();
        let record = document["secrets"]["key"]["versions"]["1"]
            .as_object_mut()
            .unwrap();
        match public {
            Some(value) => {
                record.insert("public".into(), value);
            }
            None => {
                record.remove("public");
            }
        }
        ctx.state.write_json(VAULT_DOC, &document).unwrap();
        let path = state.join(VAULT_DOC);
        let before = fs::read(&path).unwrap();

        let rust = ctx.vault.get_meta("key");
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "Rust mutated state: {name}"
        );

        match expected {
            Some(expected) => {
                assert_eq!(rust.unwrap().versions[0].public, expected, "Rust: {name}");
            }
            None => {
                let error = rust.expect_err(name);
                assert_eq!(error.class, ErrorClass::StateError, "Rust: {name}");
                assert_eq!(error.reason, "state_corrupt", "Rust: {name}");
            }
        }
    }
}
