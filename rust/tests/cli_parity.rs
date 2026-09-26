//! The native administrator and agent binaries against the original Python
//! CLIs: parsing, help and usage text (argparse), error JSON, `~` expansion,
//! origin-only targets, audit records and state effects, case by case
//! (`cli_parity_cases.json`, driven by `cli_parity.py`).
use std::path::Path;
use std::process::Command;

#[test]
fn native_cli_matches_the_original_python_cli() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let python = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".into());
    let output = Command::new(python)
        .current_dir(root)
        .arg(root.join("rust/tests/cli_parity.py"))
        .args(["--admin", env!("CARGO_BIN_EXE_zeropw-admin")])
        .args(["--agent", env!("CARGO_BIN_EXE_zeropw-agent")])
        .arg(root.join("rust/tests/cli_parity_cases.json"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("{stdout}{}", String::from_utf8_lossy(&output.stderr));
    assert!(output.status.success(), "native CLI differs from Python");
    assert!(stdout.contains("CLI_PARITY "), "driver did not report");
}
