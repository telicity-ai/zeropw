//! Integration test: state documents written by the Python prototype's
//! `zeropw.store`/`zeropw.projects` load through this crate's
//! `StateDir`/`Projects`, and what Rust writes is byte-identical (PORTING.md
//! §0 boundary 1). The prototype's files are golden fixtures
//! (`tests/fixtures/python/store/GENERATE.md`).

mod python_fixtures;

use serde_json::Value;
use zeropw::projects::Projects;
use zeropw::pyjson;
use zeropw::store::StateDir;

/// Replaces every `"created_at": "<iso>"` value (wall-clock time in both
/// writers) with a fixed placeholder.
fn without_created_at(text: &str) -> String {
    regex::Regex::new(r#""created_at": "[^"]*""#)
        .unwrap()
        .replace_all(text, r#""created_at": "<iso>""#)
        .into_owned()
}

#[test]
fn projects_json_written_by_python_loads_in_rust() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state_path = tmp.path().join("state");
    python_fixtures::copy_state("store/projects-state", &state_path);

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
    assert_eq!(
        acme.created_at.as_str().unwrap().len(),
        "2023-11-14T22:13:20Z".len()
    );
    projects.require_environment("acme", "staging").unwrap();
    assert!(projects.require_environment("beta", "prod").is_err());
}

#[test]
fn projects_json_written_by_rust_is_byte_identical_to_python() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state_path = tmp.path().join("state");

    let state = StateDir::new(&state_path);
    state.create().unwrap();
    let projects = Projects::new(&state);
    projects
        .create("acme", &["dev", "staging", "prod"])
        .unwrap();
    projects.create("beta", &["dev"]).unwrap();

    let ours = std::fs::read_to_string(state_path.join("projects.json")).unwrap();
    let theirs = python_fixtures::read("store/projects-state/projects.json");
    assert_eq!(without_created_at(&ours), without_created_at(&theirs));
    assert_eq!(
        python_fixtures::relative_files(&state_path),
        python_fixtures::relative_files(&python_fixtures::path("store/projects-state"))
    );
}

#[test]
fn write_json_pretty_output_is_byte_identical_across_languages() {
    // Same document as the prototype's `state.write_json("doc.json", ...)`,
    // with StateDir's on-disk contract (sort_keys=True, indent=2): the file
    // must be identical, not just semantically equal, since other units
    // hash/HMAC over this.
    let tmp = tempfile::TempDir::new().unwrap();
    let rust_path = tmp.path().join("rust_state");

    let state = StateDir::new(&rust_path);
    state.create().unwrap();
    state
        .write_json(
            "doc.json",
            &serde_json::json!({"b": [1, 2, {"z": true, "a": null}], "a": "hello é", "n": 3.5}),
        )
        .unwrap();

    let rust_bytes = std::fs::read(rust_path.join("doc.json")).unwrap();
    let python_bytes =
        std::fs::read(python_fixtures::path("store/write-json-state/doc.json")).unwrap();
    assert_eq!(rust_bytes, python_bytes);
}

// A-10: `StateDir.read_lines` used the prototype's default text mode, which
// applies universal newline translation ("\r\n", "\r", and "\n" all
// terminate a line). Write raw bytes with a mix of terminators (including a
// final line with none) directly to disk -- bypassing `append_line`, which
// forbids embedded "\n" -- and check how they split.
#[test]
fn read_lines_handles_universal_newlines() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state_path = tmp.path().join("state");
    std::fs::create_dir_all(&state_path).unwrap();
    std::fs::write(state_path.join("log.jsonl"), b"a\rb\nc\r\nd").unwrap();

    let state = StateDir::new(&state_path);
    let got = state.read_lines("log.jsonl", None).unwrap();
    assert_eq!(got, vec!["a", "b", "c", "d"]);
}

/// `json.dump(doc, sort_keys=True, indent=2)` of `1` wrapped in `n` lists.
fn nested_pretty(n: usize) -> String {
    let mut lines = Vec::with_capacity(2 * n + 1);
    for i in 0..n {
        lines.push(format!("{}[", "  ".repeat(i)));
    }
    lines.push(format!("{}1", "  ".repeat(n)));
    for i in (0..n).rev() {
        lines.push(format!("{}]", "  ".repeat(i)));
    }
    lines.join("\n")
}

// `pyjson::MAX_JSON_DEPTH` (990) sits below the deepest document the
// prototype's own `StateDir.write_json` could persist (996), so every
// document Rust persists is one the prototype could also have written.
// Depths at and below the cap round-trip with the prototype's exact layout;
// one level past it is refused cleanly, with no target or temp file left.
#[test]
fn write_json_boundary_at_the_depth_cap() {
    let cap = pyjson::MAX_JSON_DEPTH;

    for n in [cap - 1, cap] {
        let tmp = tempfile::TempDir::new().unwrap();
        let rust_path = tmp.path().join("rust_state");

        let state = StateDir::new(&rust_path);
        state.create().unwrap();
        let mut doc = serde_json::json!(1);
        for _ in 0..n {
            doc = Value::Array(vec![doc]);
        }
        state
            .write_json("deep.json", &doc)
            .unwrap_or_else(|e| panic!("Rust write_json should succeed at depth {n}: {e:?}"));
        let rust_text = std::fs::read_to_string(rust_path.join("deep.json")).unwrap();
        assert!(
            rust_text == nested_pretty(n),
            "depth {n} must use the prototype's indent=2 layout"
        );
    }

    let over = cap + 1;
    let tmp = tempfile::TempDir::new().unwrap();
    let rust_path = tmp.path().join("rust_state");

    let state = StateDir::new(&rust_path);
    state.create().unwrap();
    let mut doc = serde_json::json!(1);
    for _ in 0..over {
        doc = Value::Array(vec![doc]);
    }
    let err = state
        .write_json("deep.json", &doc)
        .expect_err("Rust write_json must refuse one level past MAX_JSON_DEPTH");
    assert_eq!(err.reason, "state_write_failed");
    assert!(
        !rust_path.join("deep.json").exists(),
        "a refused write_json must not leave a target file behind"
    );
    let leftover: Vec<_> = std::fs::read_dir(&rust_path)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        leftover.is_empty(),
        "a refused write_json must not leave a stale tmp file behind, found: {leftover:?}"
    );
}

// Depth 1,000 is past the prototype's own `StateDir.write_json` ceiling
// (it raised `RecursionError` from depth 997); Rust refuses it up front.
#[test]
fn write_json_past_the_prototype_ceiling_is_refused() {
    let tmp = tempfile::TempDir::new().unwrap();
    let rust_path = tmp.path().join("rust_state");

    let state = StateDir::new(&rust_path);
    state.create().unwrap();
    let mut doc = serde_json::json!(1);
    for _ in 0..1000 {
        doc = Value::Array(vec![doc]);
    }
    let err = state
        .write_json("deep.json", &doc)
        .expect_err("Rust write_json must refuse a document this deep");
    assert_eq!(err.reason, "state_write_failed");
    assert!(
        !rust_path.join("deep.json").exists(),
        "a refused Rust write_json must not leave a target file behind"
    );
}
