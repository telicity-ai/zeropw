//! Agent CLI help stays offline and keeps the original argparse surface: the
//! exact help text the original CLI printed is recorded in
//! `fixtures/python/cli/agent_help.json` (see its `GENERATE.md`).
use std::process::Command;

use serde_json::Value;

#[test]
fn root_and_each_subcommand_help_match_the_recorded_text_without_gateway_config() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/python/cli/agent_help.json")).unwrap();
    assert_eq!(cases.len(), 7);
    for case in cases {
        let args: Vec<&str> = case["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        let rust = Command::new(env!("CARGO_BIN_EXE_zeropw-agent"))
            .args(&args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();
        let expected_stdout = case["stdout"].as_str().unwrap();
        let expected_stderr = case["stderr"].as_str().unwrap();
        assert_eq!(rust.status.code(), case["code"].as_i64().map(|c| c as i32), "{args:?}");
        assert_eq!(String::from_utf8_lossy(&rust.stdout), expected_stdout, "{args:?}");
        assert_eq!(String::from_utf8_lossy(&rust.stderr), expected_stderr, "{args:?}");
    }
}

#[test]
fn unknown_command_still_fails_and_exec_tail_help_stays_literal() {
    let unknown = Command::new(env!("CARGO_BIN_EXE_zeropw-agent"))
        .args(["unknown", "--help"])
        .env_clear()
        .output()
        .unwrap();
    assert_eq!(unknown.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("invalid choice"));

    let literal = Command::new(env!("CARGO_BIN_EXE_zeropw-agent"))
        .args(["exec", "--connection", "synthetic", "--", "--help"])
        .env_clear()
        .output()
        .unwrap();
    assert_eq!(literal.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&literal.stderr).contains("gateway_url_unset"));
    assert!(literal.stdout.is_empty());
}
