//! Differential coverage for `dict(r.get("public") or {})` in
//! `Vault.list_secrets`. The malformed documents are synthetic and contain
//! no credentials.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use tempfile::TempDir;

use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::errors::ErrorClass;
use zeropw::projects;
use zeropw::vault::VAULT_DOC;

const NOW: f64 = 1_700_000_000.0;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repository root")
        .to_path_buf()
}

fn py_str(value: &Path) -> String {
    format!("{:?}", value.to_str().expect("UTF-8 test path"))
}

fn python_public(state: &Path) -> Value {
    let script = format!(
        r#"
import json
from zeropw.context import Config, Context
ctx = Context.open({state}, Config(), lambda: {now})
try:
    value = ctx.vault.get_meta("key").versions[0].public
except (TypeError, ValueError) as exc:
    print(json.dumps(["error", type(exc).__name__]))
else:
    print(json.dumps(["ok", value], ensure_ascii=False, separators=(",", ":")))
"#,
        state = py_str(state),
        now = NOW,
    );
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".into());
    let output = Command::new(interpreter)
        .arg("-c")
        .arg(script)
        .env("PYTHONPATH", repo_root())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run Python oracle");
    assert!(
        output.status.success(),
        "Python stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("Python JSON result")
}

#[test]
fn public_pair_sequence_coercion_matches_python_without_mutating_state() {
    let cases = [
        ("missing", None, Some(json!({}))),
        ("null", Some(Value::Null), Some(json!({}))),
        ("false", Some(json!(false)), Some(json!({}))),
        ("zero", Some(json!(0)), Some(json!({}))),
        ("zero-float", Some(json!(0.0)), Some(json!({}))),
        ("empty-string", Some(json!("")), Some(json!({}))),
        ("empty-array", Some(json!([])), Some(json!({}))),
        ("empty-object", Some(json!({})), Some(json!({}))),
        (
            "array-pairs-duplicates",
            Some(json!([["a", 1], ["b", {"nested": [2]}], ["a", 3]])),
            Some(json!({"a": 3, "b": {"nested": [2]}})),
        ),
        (
            "two-character-pairs",
            Some(json!(["ab", "é🙂"])),
            Some(json!({"a": "b", "é": "🙂"})),
        ),
        (
            "two-key-object-pair",
            Some(json!([{"first": 0, "second": 0}])),
            Some(json!({"first": "second"})),
        ),
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
        let python = python_public(&state);
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "Python mutated state: {name}"
        );

        match expected {
            Some(expected) => {
                assert_eq!(rust.unwrap().versions[0].public, expected, "Rust: {name}");
                assert_eq!(python, json!(["ok", expected]), "Python: {name}");
            }
            None => {
                let error = rust.expect_err(name);
                assert_eq!(error.class, ErrorClass::StateError, "Rust: {name}");
                assert_eq!(error.reason, "state_corrupt", "Rust: {name}");
                assert!(
                    python == json!(["error", "TypeError"])
                        || python == json!(["error", "ValueError"]),
                    "Python: {name}: {python}"
                );
            }
        }
    }
}
