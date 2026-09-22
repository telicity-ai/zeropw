//! Original multi-process Python tests run against actual native binaries.
//! Python only drives assertions and controlled external test endpoints.
use std::{path::Path, process::Command};

fn original_case(name: &str) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output = Command::new("python3.12")
        .current_dir(root)
        .arg(root.join("rust/tests/native_cli_e2e.py"))
        .args(["--admin", env!("CARGO_BIN_EXE_zeropw-admin")])
        .args(["--agent", env!("CARGO_BIN_EXE_zeropw-agent")])
        .args(["--democli", env!("CARGO_BIN_EXE_zeropw-democli")])
        .arg(name)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("{stdout}{stderr}");
    assert!(output.status.success(), "native E2E {name} failed");
    assert!(stdout.contains("NATIVE_E2E_LAUNCHES="));
}

#[test]
fn original_http_cli_end_to_end_on_native_binaries() {
    original_case(
        "tests.test_cli_e2e.CliEndToEndTestCase.test_http_connection_through_admin_serve_and_agent_processes",
    );
}

#[test]
fn original_real_ssh_end_to_end_on_native_binaries() {
    original_case(
        "tests.test_cli_e2e.CliEndToEndTestCase.test_ssh_connection_through_admin_serve_agent_processes_and_real_sshd",
    );
}

#[test]
fn original_compromise_response_end_to_end_on_native_binaries() {
    original_case(
        "tests.test_cli_e2e.CompromiseResponseEndToEndTestCase.test_auto_lockdown_exposure_assessment_email_and_recovery",
    );
}

#[test]
fn original_team_end_to_end_on_native_binaries() {
    original_case("tests.test_team_e2e.TeamEndToEndTestCase");
}
