//! Differential coverage for snapshot `version_order` coercion and
//! preservation of non-string entries.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use serde_json::{Value, json};
use tempfile::TempDir;

use zeropw::pyjson::{self, DumpOptions};
use zeropw::store::StateDir;
use zeropw::team::commit;
use zeropw::team::fold;
use zeropw::team::identity::DeviceKey;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn py_str(value: &Path) -> String {
    format!("{:?}", value.to_str().unwrap())
}

#[test]
fn snapshot_version_order_successes_and_saved_bytes_match_python() {
    let cases = [
        (Value::Null, json!({"sid": [1, true, null, "v", 1.5]})),
        (Value::Null, json!({"sid": "a🙂"})),
        (Value::Null, json!({"sid": {"first": 1, "second": 2}})),
        // An existing document key wins over the separately supplied map.
        // Python only requires it to support `.setdefault` if an accepted
        // secret.put_version later appends; with no ops it is popped and
        // returned unchanged.
        (json!({"_version_order": 5}), json!({"ignored": ["v1"]})),
        // No op touches this deliberately incomplete/malformed document, so
        // Python returns it unchanged instead of eagerly validating fields.
        (
            json!({"env_id": "env", "connections": {"bad": {}}}),
            json!({}),
        ),
    ];
    for (index, (document, version_order)) in cases.into_iter().enumerate() {
        let tmp = TempDir::new().unwrap();
        let rust_path = tmp.path().join("rust");
        let python_path = tmp.path().join("python");
        let rust_state = StateDir::new(&rust_path);
        rust_state.create().unwrap();
        let snapshot = json!({"document": document, "vector": {}, "version_order": version_order});
        rust_state
            .write_json("team/env/snapshots/1.json", &snapshot)
            .unwrap();
        let rust_result = fold::fold_with_snapshot("env", vec![], &rust_state, None, None).unwrap();
        fold::save_snapshot(
            &rust_state,
            "env",
            &zeropw::pyint::PyInt::from(2),
            &rust_result,
        )
        .unwrap();
        let rust_bytes = fs::read(rust_path.join("team/env/snapshots/2.json")).unwrap();

        let snapshot_text = pyjson::dumps(&snapshot, DumpOptions::compact_sorted()).unwrap();
        let script = format!(
            r#"
import base64,json
from pathlib import Path
from zeropw.store import StateDir
from zeropw.team import fold as F
state=StateDir(Path({state}))
state.create()
state.write_json("team/env/snapshots/1.json", json.loads({snapshot:?}))
result=F.fold_with_snapshot("env", [], state)
F.save_snapshot(state, "env", 2, result)
print(json.dumps(result.version_order, ensure_ascii=False, separators=(",", ":")))
print(base64.b64encode((state.path/"team/env/snapshots/2.json").read_bytes()).decode("ascii"))
"#,
            state = py_str(&python_path),
            snapshot = snapshot_text,
        );
        let interpreter =
            std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".to_owned());
        let output = Command::new(interpreter)
            .arg("-c")
            .arg(script)
            .env("PYTHONPATH", repo_root())
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "case {index}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let lines: Vec<&str> = stdout.lines().collect();
        let python_order: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(
            serde_json::to_value(&rust_result.version_order).unwrap(),
            python_order,
            "case {index}"
        );
        let python_bytes = base64::engine::general_purpose::STANDARD
            .decode(lines[1])
            .unwrap();
        assert_eq!(
            rust_bytes, python_bytes,
            "saved snapshot bytes, case {index}"
        );
    }
}

#[test]
fn snapshot_categories_are_validated_only_when_an_operation_reaches_them() {
    let signer = DeviceKey::generate();
    let fingerprint = signer.fingerprint().unwrap();
    let cases = vec![
        (
            "unknown",
            json!({"opaque": {"connections": 5}, "settings": ["untouched"]}),
            json!({"op": "future.unknown", "id": "x"}),
            None,
        ),
        (
            "not_admin",
            json!({
                "env_id": "env",
                "owner": null,
                "members": {},
                "connections": 5,
                "secrets": ["untouched"],
                "dek": "untouched",
                "settings": 7,
            }),
            json!({"op": "settings.update", "sync_interval_seconds": 3}),
            None,
        ),
        (
            "settings_only",
            json!({
                "owner": fingerprint,
                "members": {(fingerprint.clone()): {"status": "active", "role": "admin"}},
                "connections": 5,
                "secrets": ["untouched"],
                "dek": "untouched",
                "settings": {"sync_interval_seconds": 1},
            }),
            json!({"op": "settings.update", "sync_interval_seconds": 3}),
            Some(json!(3)),
        ),
    ];
    for (index, (label, document, op, expected_setting)) in cases.into_iter().enumerate() {
        // Public fold accepts already-loaded commits. Construct this directly
        // so the deliberately unknown operation reaches fold instead of being
        // rejected by sign_commit's local authoring validation.
        let commit = commit::Commit {
            format: commit::COMMIT_FORMAT.to_owned(),
            env_id: "env".to_owned(),
            author: fingerprint.clone(),
            author_seq: zeropw::pyint::PyInt::from(1),
            hlc: "1000-0000".to_owned(),
            seen: BTreeMap::new(),
            ops: vec![op],
            sig: String::new(),
        };
        let snapshot = json!({"document": document, "vector": {}, "version_order": {}});
        let tmp = TempDir::new().unwrap();
        let rust_path = tmp.path().join("rust");
        let python_path = tmp.path().join("python");
        let rust_state = StateDir::new(&rust_path);
        rust_state.create().unwrap();
        rust_state
            .write_json("team/env/snapshots/1.json", &snapshot)
            .unwrap();
        let rust =
            fold::fold_with_snapshot("env", vec![commit.clone()], &rust_state, None, None).unwrap();

        let script = format!(
            r#"
import json
from pathlib import Path
from zeropw.store import StateDir
from zeropw.team import commit as C
from zeropw.team import fold as F
state=StateDir(Path({state}))
state.create()
state.write_json("team/env/snapshots/1.json", json.loads({snapshot:?}))
commit=C.Commit.from_dict(json.loads({commit:?}))
result=F.fold_with_snapshot("env", [commit], state)
print(json.dumps({{"document": result.document, "skipped": result.skipped,
                  "version_order": result.version_order}}, sort_keys=True, separators=(",", ":")))
"#,
            state = py_str(&python_path),
            snapshot = pyjson::dumps(&snapshot, DumpOptions::compact_sorted()).unwrap(),
            commit = pyjson::dumps(&commit.to_dict(), DumpOptions::compact_sorted()).unwrap(),
        );
        let interpreter =
            std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".to_owned());
        let output = Command::new(interpreter)
            .arg("-c")
            .arg(script)
            .env("PYTHONPATH", repo_root())
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let python: Value = serde_json::from_slice(&output.stdout).unwrap();
        let actual = json!({
            "document": rust.document,
            "skipped": rust.skipped,
            "version_order": rust.version_order,
        });
        assert_eq!(actual, python, "case {index}: {label}");
        if let Some(expected_setting) = expected_setting {
            assert_eq!(
                actual["document"]["settings"]["sync_interval_seconds"],
                expected_setting
            );
        } else {
            assert_eq!(actual["document"], snapshot["document"]);
        }
    }
}

#[test]
fn raw_version_order_valid_target_appends_without_touching_bad_sibling() {
    let signer = DeviceKey::generate();
    let fingerprint = signer.fingerprint().unwrap();
    let document = json!({
        "env_id": "env",
        "owner": fingerprint,
        "members": {(fingerprint.clone()): {"status": "active", "role": "admin"}},
        "connections": {},
        "secrets": {},
        "dek": {"current": "0000000000000000", "generations": {"0000000000000000": {"wraps": {}}}},
        "settings": {},
        "_version_order": {"bad-unrelated": 5, "existing": ["v0"]},
    });
    let op = json!({
        "op": "secret.put_version", "secret_id": "new", "kind": "api_key",
        "generation_id": "0000000000000000", "version_id": "1111111111111111",
        "ciphertext": {"nonce": "AA==", "ciphertext": "AA=="}, "public": {},
    });
    let commit =
        commit::sign_commit(&signer, "env", 1, "1000-0000", &BTreeMap::new(), vec![op]).unwrap();
    let snapshot = json!({"document": document, "vector": {}, "version_order": {"ignored": []}});
    let tmp = TempDir::new().unwrap();
    let rust_path = tmp.path().join("rust");
    let python_path = tmp.path().join("python");
    let rust_state = StateDir::new(&rust_path);
    rust_state.create().unwrap();
    rust_state
        .write_json("team/env/snapshots/1.json", &snapshot)
        .unwrap();
    let rust =
        fold::fold_with_snapshot("env", vec![commit.clone()], &rust_state, None, None).unwrap();

    let script = format!(
        r#"
import json
from pathlib import Path
from zeropw.store import StateDir
from zeropw.team import commit as C
from zeropw.team import fold as F
state=StateDir(Path({state}))
state.create()
state.write_json("team/env/snapshots/1.json", json.loads({snapshot:?}))
commit=C.Commit.from_dict(json.loads({commit:?}))
result=F.fold_with_snapshot("env", [commit], state)
print(json.dumps({{"document": result.document, "version_order": result.version_order}},
                 sort_keys=True, separators=(",", ":")))
"#,
        state = py_str(&python_path),
        snapshot = pyjson::dumps(&snapshot, DumpOptions::compact_sorted()).unwrap(),
        commit = pyjson::dumps(&commit.to_dict(), DumpOptions::compact_sorted()).unwrap(),
    );
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".to_owned());
    let output = Command::new(interpreter)
        .arg("-c")
        .arg(script)
        .env("PYTHONPATH", repo_root())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let python: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        json!({"document": rust.document, "version_order": rust.version_order}),
        python
    );
    assert_eq!(python["version_order"]["bad-unrelated"], json!(5));
    assert_eq!(python["version_order"]["new"], json!(["1111111111111111"]));
}
