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

use serde_json::Value;
use zeropw::projects::Projects;
use zeropw::pyjson;
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

// A-10: `StateDir.read_lines` opens the file in Python's default text mode,
// which applies *universal newline* translation ("\r\n", "\r", and "\n" all
// terminate a line), not just "\n". Write raw bytes with a mix of
// terminators (including a final line with none) directly to disk --
// bypassing `append_line`, which forbids embedded "\n" in either language --
// and check both languages split it the same way.
#[test]
fn read_lines_handles_universal_newlines_like_python() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state_path = tmp.path().join("state");
    std::fs::create_dir_all(&state_path).unwrap();
    std::fs::write(state_path.join("log.jsonl"), b"a\rb\nc\r\nd").unwrap();

    let out = run_python(&format!(
        r#"
from zeropw.store import StateDir
state = StateDir({path})
for line in state.read_lines("log.jsonl", None):
    print(line)
"#,
        path = py_str_literal(&state_path),
    ));
    let want: Vec<&str> = out.lines().collect();

    let state = StateDir::new(&state_path);
    let got = state.read_lines("log.jsonl", None).unwrap();
    assert_eq!(got, want);
    assert_eq!(got, vec!["a", "b", "c", "d"]);
}

/// A Python expression that builds a value nested `n` levels deep at
/// *runtime* (`1` wrapped in a list `n` times via a loop), for use as one
/// argument in a larger script. Deliberately **not** a `n`-deep literal
/// source string (`"["*n + "1" + "]"*n`): CPython's own *compiler* refuses
/// more than 20-ish nested brackets in source text ("too many nested
/// parentheses", a syntax-level limit distinct from the `json`/pickle
/// runtime recursion limit this test is actually probing), so a deep
/// literal would fail to even parse as Python source long before reaching
/// any depth this test cares about.
fn nested_array_expr(n: usize) -> String {
    format!("__import__('functools').reduce(lambda a, _: [a], range({n}), 1)")
}

// A-R5-2/X-3: `pyjson::MAX_JSON_DEPTH` must be strictly below CPython's own
// real ceiling for the exact write path `StateDir::write_json` mirrors
// (`json.dump(doc, stream, sort_keys=True, indent=2)`, measured through the
// real `StateDir.write_json` API itself for finding X-3's fix: last
// accepted depth 996, `RecursionError` at 997 there -- see
// `rust/DEVIATIONS.md`'s pyjson row 14; that ceiling is caller-frame
// dependent, not a fixed language constant, so this port's own bound (990)
// keeps deliberate headroom below it rather than sitting flush against it),
// so every document this port ever persists is one Python's own
// `StateDir.write_json` could also have written. Walk the boundary in the
// WRITE direction at this port's own, lower cap: `pyjson::MAX_JSON_DEPTH -
// 1` and `pyjson::MAX_JSON_DEPTH` must succeed, byte-identically, through
// both languages' `write_json`; `pyjson::MAX_JSON_DEPTH + 1` must be
// refused by Rust's `write_json` (an intentional, documented,
// narrower-than-CPython cap -- CPython's own `StateDir.write_json` ceiling
// is nowhere near this low, so Python happily writes the same
// one-level-deeper document Rust refuses; that half of this test pins the
// divergence itself, not a bug). `write_json_past_pythons_own_ceiling_is_refused_by_both_languages`
// below pins the OTHER required direction: a depth genuinely past Python's
// own ceiling, where Rust must not overshoot into accepting what Python
// itself cannot persist.
#[test]
fn write_json_boundary_matches_python_state_dir_write_json_at_the_depth_cap() {
    let cap = pyjson::MAX_JSON_DEPTH;

    for n in [cap - 1, cap] {
        let tmp = tempfile::TempDir::new().unwrap();
        let rust_path = tmp.path().join("rust_state");
        let python_path = tmp.path().join("python_state");

        let state = StateDir::new(&rust_path);
        state.create().unwrap();
        let mut doc = serde_json::json!(1);
        for _ in 0..n {
            doc = Value::Array(vec![doc]);
        }
        state
            .write_json("deep.json", &doc)
            .unwrap_or_else(|e| panic!("Rust write_json should succeed at depth {n}: {e:?}"));

        run_python(&format!(
            r#"
from zeropw.store import StateDir
state = StateDir({path})
state.create()
state.write_json("deep.json", {doc})
"#,
            path = py_str_literal(&python_path),
            doc = nested_array_expr(n),
        ));

        let rust_bytes = std::fs::read(rust_path.join("deep.json")).unwrap();
        let python_bytes = std::fs::read(python_path.join("deep.json")).unwrap();
        assert_eq!(
            rust_bytes, python_bytes,
            "depth {n} (at/under the cap) must round-trip byte-identically"
        );
    }

    // One level past the cap: Rust's write_json must refuse cleanly (no
    // panic/abort, no partial/stale tmp file left in the target directory),
    // while real Python -- nowhere near its own, much higher ceiling at this
    // depth -- still writes it without complaint. An intentional,
    // documented divergence (rust/DEVIATIONS.md pyjson row 14), not a bug.
    let over = cap + 1;
    let tmp = tempfile::TempDir::new().unwrap();
    let rust_path = tmp.path().join("rust_state");
    let python_path = tmp.path().join("python_state");

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

    run_python(&format!(
        r#"
from zeropw.store import StateDir
state = StateDir({path})
state.create()
state.write_json("deep.json", {doc})
"#,
        path = py_str_literal(&python_path),
        doc = nested_array_expr(over),
    ));
    assert!(
        python_path.join("deep.json").exists(),
        "real python3.12's StateDir.write_json should still succeed one level past Rust's much lower cap"
    );
}

// Finding X-3 (HIGH): the required "no overshoot" check -- raising
// `MAX_JSON_DEPTH` must not push Rust's acceptance bound PAST what
// `StateDir.write_json` can actually persist in Python, or this port would
// start accepting a document Python itself cannot write, the opposite
// direction of PORTING.md #2's invariant. Depth 1,000 is comfortably past
// real `python3.12`'s own measured `StateDir.write_json` ceiling for this
// exact call shape (this fix's own probing, both standalone and through the
// real API: last accepted 996, `RecursionError` at 997 -- see
// `rust/DEVIATIONS.md`'s pyjson row 14) while still being one Rust rejects
// outright via its own, much cheaper up-front depth scan (no native
// recursion attempted at all, so no `RecursionError`/stack-overflow
// equivalent on the Rust side either). Confirm both languages refuse it,
// and neither leaves a stray file behind.
#[test]
fn write_json_past_pythons_own_ceiling_is_refused_by_both_languages() {
    let over_pythons_ceiling = 1000;

    let tmp = tempfile::TempDir::new().unwrap();
    let rust_path = tmp.path().join("rust_state");
    let python_path = tmp.path().join("python_state");

    let state = StateDir::new(&rust_path);
    state.create().unwrap();
    let mut doc = serde_json::json!(1);
    for _ in 0..over_pythons_ceiling {
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

    // Python's own real `StateDir.write_json`, at this same depth, must
    // ALSO fail -- with a `RecursionError` that `run_python` (which asserts
    // a zero exit code) turns into a panic, so a non-panicking run here
    // would itself mean Rust's cap had somehow drifted past what Python can
    // actually write. Confirmed via a script that catches exactly that
    // exception and reports it explicitly, rather than relying on the
    // process exit code alone to distinguish "Python raised" from some
    // other, unrelated script failure.
    let out = run_python(&format!(
        r#"
from zeropw.store import StateDir
state = StateDir({path})
state.create()
try:
    state.write_json("deep.json", {doc})
    print("WROTE")
except RecursionError:
    print("RECURSION_ERROR")
"#,
        path = py_str_literal(&python_path),
        doc = nested_array_expr(over_pythons_ceiling),
    ));
    assert_eq!(
        out.trim(),
        "RECURSION_ERROR",
        "python3.12's own StateDir.write_json must also refuse depth {over_pythons_ceiling} \
         (a depth Rust's raised MAX_JSON_DEPTH must not overshoot past)"
    );
    assert!(
        !python_path.join("deep.json").exists(),
        "python's own failed write_json must not leave a target file behind either"
    );
}
