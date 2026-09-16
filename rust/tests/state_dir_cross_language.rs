//! Integration test: a state directory written by Python's `zeropw.store`/
//! `zeropw.projects` must load through this port's `StateDir`/`Projects`,
//! and vice versa (rust/PORTING.md: "A state directory written by Python
//! must load in Rust and vice versa").
//!
//! Lives under `rust/tests/` as a standalone test binary (see
//! `store_cross_process_lock.rs` for why: `crate::oracle` is
//! `#[cfg(test)] pub(crate)` and not reachable from here), with its own
//! tiny run-to-completion Python helper.

use std::path::{Path, PathBuf};
use std::process::Command;

use zeropw::projects::Projects;
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

#[test]
fn projects_json_written_by_python_loads_in_rust() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state_path = tmp.path().join("state");

    run_python(&format!(
        r#"
from zeropw.store import StateDir
from zeropw.projects import Projects

state = StateDir({path})
state.create()
projects = Projects(state)
projects.create("acme", ("dev", "staging", "prod"))
projects.create("beta", ("dev",))
"#,
        path = py_str_literal(&state_path),
    ));

    let state = StateDir::new(&state_path);
    let projects = Projects::new(&state);
    let mut names: Vec<String> = projects
        .list()
        .unwrap()
        .into_iter()
        .map(|p| p.name)
        .collect();
    names.sort();
    assert_eq!(names, vec!["acme", "beta"]);
    let acme = projects.get("acme").unwrap();
    assert_eq!(acme.environments, vec!["dev", "staging", "prod"]);
    // created_at must be an iso() string Rust itself can also produce the
    // same shape for -- not byte-compared here since real-time timestamps
    // differ, but must parse without corruption.
    assert_eq!(acme.created_at.len(), "2023-11-14T22:13:20Z".len());
}

#[test]
fn projects_json_written_by_rust_loads_in_python() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state_path = tmp.path().join("state");

    let state = StateDir::new(&state_path);
    state.create().unwrap();
    let projects = Projects::new(&state);
    projects
        .create("acme", &["dev", "staging", "prod"])
        .unwrap();
    projects.create("beta", &["dev"]).unwrap();

    let out = run_python(&format!(
        r#"
from zeropw.store import StateDir
from zeropw.projects import Projects

state = StateDir({path})
projects = Projects(state)
for p in projects.list():
    print(p.name, ",".join(p.environments))
print(projects.get("acme").environments)
"#,
        path = py_str_literal(&state_path),
    ));
    let mut lines = out.lines();
    assert_eq!(lines.next().unwrap(), "acme dev,staging,prod");
    assert_eq!(lines.next().unwrap(), "beta dev");
    assert_eq!(lines.next().unwrap(), "('dev', 'staging', 'prod')");
}

#[test]
fn write_json_pretty_output_is_byte_identical_across_languages() {
    // Same document, written by both languages with StateDir's actual
    // on-disk contract (sort_keys=True, indent=2): files must be identical,
    // not just semantically equal, since other units hash/HMAC over this.
    let tmp = tempfile::TempDir::new().unwrap();
    let rust_path = tmp.path().join("rust_state");
    let python_path = tmp.path().join("python_state");

    let state = StateDir::new(&rust_path);
    state.create().unwrap();
    state
        .write_json(
            "doc.json",
            &serde_json::json!({"b": [1, 2, {"z": true, "a": null}], "a": "hello é", "n": 3.5}),
        )
        .unwrap();

    run_python(&format!(
        r#"
from zeropw.store import StateDir
state = StateDir({path})
state.create()
state.write_json("doc.json", {{"b": [1, 2, {{"z": True, "a": None}}], "a": "hello é", "n": 3.5}})
"#,
        path = py_str_literal(&python_path),
    ));

    let rust_bytes = std::fs::read(rust_path.join("doc.json")).unwrap();
    let python_bytes = std::fs::read(python_path.join("doc.json")).unwrap();
    assert_eq!(rust_bytes, python_bytes);
}
