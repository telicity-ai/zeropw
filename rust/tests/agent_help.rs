//! Agent CLI help stays offline and matches the original argparse surface.
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

fn python_oracle() -> PathBuf {
    let configured = std::env::var_os("ZEROPW_PYTHON").unwrap_or_else(|| "python3.12".into());
    let candidate = PathBuf::from(&configured);
    if candidate.components().count() > 1 {
        return candidate;
    }
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join(&candidate))
        .find(|path| {
            path.metadata().is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
        .unwrap_or_else(|| panic!("cannot resolve Python oracle {configured:?} before env_clear"))
}

#[test]
fn root_and_each_subcommand_help_match_python_without_gateway_config() {
    let python_oracle = python_oracle();
    for args in [
        vec!["-h"],
        vec!["--help"],
        vec!["list-connections", "--help"],
        vec!["request", "-h"],
        vec!["exec", "--help"],
        vec!["status", "--help"],
        vec!["cancel", "--help"],
    ] {
        let python = Command::new(&python_oracle)
            .args(["-m", "zeropw.agent_cli"])
            .args(&args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
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
