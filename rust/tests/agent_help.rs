//! Agent CLI help stays offline and matches the original argparse surface.
use std::process::Command;

#[test]
fn root_and_each_subcommand_help_match_python_without_gateway_config() {
    for args in [
        vec!["-h"],
        vec!["--help"],
        vec!["list-connections", "--help"],
        vec!["request", "-h"],
        vec!["exec", "--help"],
        vec!["status", "--help"],
        vec!["cancel", "--help"],
    ] {
        let python = Command::new("python3.12")
            .args(["-m", "zeropw.agent_cli"])
            .args(&args)
            .env_clear()
            .env("PATH", "/Users/ys/.local/bin:/usr/bin:/bin")
            .env("PYTHONPATH", format!("{}/..", env!("CARGO_MANIFEST_DIR")))
            .output()
            .unwrap();
        let rust = Command::new(env!("CARGO_BIN_EXE_zeropw-agent"))
            .args(&args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();
        assert_eq!(rust.status.code(), python.status.code(), "{args:?}");
        assert_eq!(rust.stdout, python.stdout, "{args:?}");
        assert_eq!(rust.stderr, python.stderr, "{args:?}");
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
