//! CPython differential coverage for arbitrary-precision `grant create
//! --max-uses`. Only synthetic credentials are used.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::policy::{Connection, HttpAuth, HttpScope, HttpTarget};
use zeropw::projects;

const NOW: f64 = 1_700_000_000.0;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn prepare(state: &Path, scratch: &Path) {
    let ctx = Context::initialize(
        state,
        "admin-passphrase-1",
        "recovery-passphrase-1",
        Config {
            socket_dir: Some(scratch.join("sockets")),
            run_dir: Some(scratch.join("run")),
            ..Config::default()
        },
        clock::fixed(NOW),
    )
    .unwrap();
    ctx.projects
        .create("demo", projects::DEFAULT_ENVIRONMENTS)
        .unwrap();
    ctx.vault
        .put_secret("key", "api_key", b"synthetic", "demo", "dev", true)
        .unwrap();
    ctx.policy.create_principal("agent", "default").unwrap();
    ctx.policy
        .create_connection(
            Connection::new(
                "conn",
                "demo",
                "dev",
                "synthetic",
                "http",
                "key",
                None,
                "",
                Some(HttpTarget::new("http", "127.0.0.1", 1, None, false).unwrap()),
                Some(HttpAuth::bearer()),
                Some(HttpScope::new(None, None, Vec::new()).unwrap()),
                None,
                None,
                0,
                "active",
                "",
                "",
            )
            .unwrap(),
        )
        .unwrap();
}

fn run(native: bool, state: &Path, max_uses: &str, digit_limit: Option<&str>) -> Output {
    let mut command = if native {
        Command::new(env!("CARGO_BIN_EXE_zeropw-admin"))
    } else {
        let python = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".into());
        let mut command = Command::new(python);
        command.args(["-m", "zeropw.admin_cli"]);
        command.env("PYTHONPATH", repo_root());
        command
    };
    let command = command
        .args(["--state-dir", state.to_str().unwrap()])
        .args([
            "grant",
            "create",
            "--principal",
            "agent",
            "--connection",
            "conn",
            "--max-uses",
            max_uses,
        ])
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env_remove("PYTHONINTMAXSTRDIGITS");
    if let Some(limit) = digit_limit {
        command.env("PYTHONINTMAXSTRDIGITS", limit);
    }
    command.output().unwrap()
}

fn stored_max_uses(state: &Path) -> Value {
    let document: Value = serde_json::from_slice(
        &fs::read(state.join("policy/grants.json")).expect("persisted grants"),
    )
    .unwrap();
    document.as_object().unwrap().values().next().unwrap()["max_uses"].clone()
}

#[test]
fn huge_max_uses_matches_python_in_output_and_persisted_decimal_bytes() {
    let inputs = vec![
        "9223372036854775808".to_owned(),
        "+١_٠٠٠_٠٠٠_٠٠٠_٠٠٠_٠٠٠_٠٠٠_٠٠٠".to_owned(),
        "100000000000000000000000000000000000000000000000001".to_owned(),
        "1".repeat(4300),
    ];
    for input in inputs {
        let tmp = TempDir::new().unwrap();
        let rust_state = tmp.path().join("rust-state");
        let python_state = tmp.path().join("python-state");
        prepare(&rust_state, &tmp.path().join("rust-scratch"));
        prepare(&python_state, &tmp.path().join("python-scratch"));

        let rust = run(true, &rust_state, &input, None);
        let python = run(false, &python_state, &input, None);
        assert_eq!(rust.status.code(), python.status.code(), "{input}");
        assert!(
            rust.status.success(),
            "{}",
            String::from_utf8_lossy(&rust.stderr)
        );
        let rust_output: Value = serde_json::from_slice(&rust.stdout).unwrap();
        let python_output: Value = serde_json::from_slice(&python.stdout).unwrap();
        assert_eq!(
            rust_output["max_uses"], python_output["max_uses"],
            "{input}"
        );
        assert_eq!(
            stored_max_uses(&rust_state),
            stored_max_uses(&python_state),
            "{input}"
        );
        let expected = python_output["max_uses"].to_string();
        assert!(
            String::from_utf8(fs::read(rust_state.join("policy/grants.json")).unwrap())
                .unwrap()
                .contains(&format!("\"max_uses\": {expected}")),
            "persisted decimal missing for {input}"
        );
    }
}

#[test]
fn zero_negative_and_cpython_digit_limit_match_python() {
    for input in ["0".to_owned(), "-1".to_owned(), "1".repeat(4301)] {
        let tmp = TempDir::new().unwrap();
        let rust_state = tmp.path().join("rust-state");
        let python_state = tmp.path().join("python-state");
        prepare(&rust_state, &tmp.path().join("rust-scratch"));
        prepare(&python_state, &tmp.path().join("python-scratch"));
        let rust = run(true, &rust_state, &input, None);
        let python = run(false, &python_state, &input, None);
        assert_eq!(rust.status.code(), python.status.code(), "{input}");
        assert_eq!(
            rust.stdout,
            python.stdout,
            "stdout for {} digits",
            input.len()
        );
        assert_eq!(
            rust.stderr,
            python.stderr,
            "stderr for {} digits",
            input.len()
        );
    }
}

#[test]
fn python_int_max_str_digits_environment_override_is_honoured() {
    for (limit, input, succeeds) in [
        ("640", "1".repeat(641), false),
        ("0", "1".repeat(4301), true),
    ] {
        let tmp = TempDir::new().unwrap();
        let rust_state = tmp.path().join("rust-state");
        let python_state = tmp.path().join("python-state");
        prepare(&rust_state, &tmp.path().join("rust-scratch"));
        prepare(&python_state, &tmp.path().join("python-scratch"));
        let rust = run(true, &rust_state, &input, Some(limit));
        let python = run(false, &python_state, &input, Some(limit));
        assert_eq!(rust.status.code(), python.status.code(), "limit {limit}");
        assert_eq!(rust.status.success(), succeeds, "limit {limit}");
        if succeeds {
            assert_eq!(stored_max_uses(&rust_state), stored_max_uses(&python_state));
        } else {
            assert_eq!(rust.stdout, python.stdout);
            assert_eq!(rust.stderr, python.stderr);
        }
    }
}
