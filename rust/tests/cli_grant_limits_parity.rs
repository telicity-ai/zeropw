//! `grant create --max-uses`: positive integers, including values beyond
//! 64 bits that the original CLI accepted and persisted, are stored as exact
//! JSON decimals; zero and negative limits are refused. Expected outputs are
//! the ones the original Python CLI produced. Only synthetic credentials.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::policy::{Connection, HttpAuth, HttpScope, HttpTarget};
use zeropw::projects;

const NOW: f64 = 1_700_000_000.0;

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

fn run(state: &Path, max_uses: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zeropw-admin"))
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
        .output()
        .unwrap()
}

fn stored_max_uses(state: &Path) -> Value {
    let document: Value = serde_json::from_slice(
        &fs::read(state.join("policy/grants.json")).expect("persisted grants"),
    )
    .unwrap();
    document.as_object().unwrap().values().next().unwrap()["max_uses"].clone()
}

#[test]
fn large_max_uses_is_printed_and_persisted_as_the_exact_decimal() {
    for input in ["5", "10000000000", "9223372036854775808"] {
        let tmp = TempDir::new().unwrap();
        let state = tmp.path().join("state");
        prepare(&state, &tmp.path().join("scratch"));
        let output = run(&state, input);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let printed: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(printed["max_uses"].to_string(), input);
        assert_eq!(printed["uses"], 0);
        assert_eq!(stored_max_uses(&state).to_string(), input);
        assert!(
            String::from_utf8(fs::read(state.join("policy/grants.json")).unwrap())
                .unwrap()
                .contains(&format!("\"max_uses\": {input}")),
            "persisted decimal missing for {input}"
        );
    }
}

#[test]
fn zero_and_negative_limits_are_refused_without_a_grant() {
    for input in ["0", "-1"] {
        let tmp = TempDir::new().unwrap();
        let state = tmp.path().join("state");
        prepare(&state, &tmp.path().join("scratch"));
        let output = run(&state, input);
        assert_eq!(output.status.code(), Some(1), "{input}");
        assert!(output.stdout.is_empty(), "{input}");
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            "{\"error\": \"InvalidInput\", \"reason\": \"invalid_max_uses\"}\n",
            "{input}"
        );
        let grants = state.join("policy/grants.json");
        if grants.exists() {
            let document: Value = serde_json::from_slice(&fs::read(grants).unwrap()).unwrap();
            assert!(document.as_object().unwrap().is_empty(), "{input}");
        }
    }
}
