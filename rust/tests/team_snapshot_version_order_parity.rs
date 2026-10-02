//! Differential coverage for snapshot `version_order` coercion and
//! preservation of non-string entries.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use serde_json::{Value, json};
use tempfile::TempDir;

use zeropw::pyjson::{self, DumpOptions};
use zeropw::store::StateDir;
use zeropw::team::fold;

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
        fold::save_snapshot(&rust_state, "env", 2, &rust_result).unwrap();
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
