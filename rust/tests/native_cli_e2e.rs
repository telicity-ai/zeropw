//! Original multi-process Python tests run against actual native binaries.
//! Python only drives assertions and controlled external test endpoints.
use std::{path::Path, process::Command};

fn validate_original_case(success: bool, stdout: &str) -> Result<(), &'static str> {
    if !success {
        return Err("failed");
    }
    if stdout.contains("NATIVE_E2E_SKIPPED=") {
        return Err("skipped");
    }
    if !stdout.contains("NATIVE_E2E_LAUNCHES=") {
        return Err("did not report native launches");
    }
    Ok(())
}

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
    validate_original_case(output.status.success(), &stdout)
        .unwrap_or_else(|reason| panic!("native E2E {name} {reason}"));
}

#[test]
fn skipped_original_case_is_not_a_native_success() {
    let reported = "NATIVE_E2E_SKIPPED=1\nNATIVE_E2E_LAUNCHES={'zeropw.admin_cli': 0}\n";
    assert_eq!(validate_original_case(true, reported), Err("skipped"));
}

#[test]
fn successful_original_case_keeps_status_and_launch_guards() {
    let reported = "NATIVE_E2E_LAUNCHES={'zeropw.admin_cli': 1}\n";
    assert_eq!(validate_original_case(true, reported), Ok(()));
    assert_eq!(validate_original_case(false, reported), Err("failed"));
    assert_eq!(
        validate_original_case(true, "ordinary unittest output"),
        Err("did not report native launches")
    );
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

#[test]
fn original_agent_cli_contract_with_python_server_oracle() {
    original_case("tests.test_agent_cli.AgentCliTestCase");
}

#[test]
fn original_admin_cli_black_box_contract_on_native_binary() {
    original_case("native_admin_contract");
}

#[test]
fn original_response_cli_black_box_contract_on_native_binary() {
    original_case("native_response_cli_contract");
}

#[test]
fn response_polling_boundaries_in_native_processes() {
    original_case("native_response_process.NativeResponseProcessTests");
}
