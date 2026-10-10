//! Native ports of the compromise-response CLI tests that used to run
//! against the native binaries through the Python adapters:
//!
//! * `NativeResponseProcessTests` (`rust/tests/native_response_process.py`):
//!   live `serve` notification retry and widening, a separate-process manual
//!   incident cancelling live native executions, and a closed pending
//!   incident never retried. Every component is its own OS process
//!   (`zeropw-admin`, `zeropw-admin ... serve`, `zeropw-agent`, `/bin/sleep`
//!   and a `/bin/sh` stand-in SSH client).
//! * `AdminCliIncidentTests` (`tests/test_incident.py`, except the
//!   in-process-only `test_serve_applies_an_incident_declared_by_another_process`)
//!   and `NotifyTestCliTests` (`tests/test_notify.py`): incident and
//!   `notify-test` commands driven through the native administrator, with
//!   the `AdminCliTestCase` tearDown sweep (only `secret reveal` may print a
//!   value) on every output.
mod native_e2e;

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use native_e2e::{
    Admin, FakeSmtp, Processes, SMTP_PASSWORD, parse_message, until, write_notify_config,
};
use serde_json::Value;
use zeropw::context::{Config, Context};

/// `tests/test_cli_e2e.py`'s values, used by `NativeResponseProcessTests`.
const SYNTHETIC: &str = "synthetic-token-cli-e2e-0123456789";
const ADMIN: &str = "admin-passphrase-cli-e2e";
const RECOVERY: &str = "recovery-passphrase-cli-e2e";

/// `tests/test_admin_cli.py`'s `SYNTHETIC` (what `put_secret` stores).
const ADMIN_CLI_SYNTHETIC: &str = "synthetic-token-0123456789";
/// `tests/test_incident.py`'s `SYNTHETIC`.
const INCIDENT_SYNTHETIC: &str = "synthetic-incident-secret-0123456789";

const POLL: Duration = Duration::from_secs(10);

fn ctx(state: &Path) -> Context {
    Context::open(state, Config::default(), zeropw::clock::system()).unwrap()
}

fn reason(value: &Value) -> &str {
    value["reason"].as_str().unwrap_or_default()
}

fn id_of(value: &Value) -> String {
    value["id"].as_str().expect("id").to_owned()
}

// ===================================================== native processes

fn processes() -> Processes {
    Processes::new(SYNTHETIC, ADMIN, RECOVERY)
}

/// Two principals on one runtime, an HTTP connection whose CLI program is
/// `/bin/sleep`, and a grant for `agent-1` (whose token the agent uses).
fn seed(p: &mut Processes) {
    p.admin(&["init"], None, 0);
    p.admin(&["project", "create", "demo"], None, 0);
    let principal = p.admin(
        &[
            "principal",
            "create",
            "--id",
            "agent-1",
            "--runtime",
            "rt-shared",
        ],
        None,
        0,
    );
    p.token = principal["token"].as_str().unwrap().to_owned();
    p.admin(
        &[
            "principal",
            "create",
            "--id",
            "agent-2",
            "--runtime",
            "rt-shared",
        ],
        None,
        0,
    );
    p.admin(
        &[
            "secret",
            "put",
            "--id",
            "key",
            "--kind",
            "api_key",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--stdin",
        ],
        Some(SYNTHETIC.as_bytes()),
        0,
    );
    let target = format!("http://127.0.0.1:{}", p.upstream.port());
    p.admin(
        &[
            "connection",
            "create-http",
            "--id",
            "gh",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--service",
            "fake",
            "--secret-id",
            "key",
            "--auth",
            "bearer",
            "--target",
            &target,
            "--cli-program",
            "/bin/sleep",
        ],
        None,
        0,
    );
    p.admin(
        &[
            "grant",
            "create",
            "--principal",
            "agent-1",
            "--connection",
            "gh",
            "--ttl",
            "1h",
        ],
        None,
        0,
    );
}

/// An SMTP receiver with `notify.json` pointing at it, stopped again: the
/// first delivery attempt must go pending.
fn smtp_down(p: &Processes) -> FakeSmtp {
    let mut smtp = FakeSmtp::new();
    smtp.start();
    write_notify_config(&p.state, &p.root, &smtp);
    smtp.stop();
    smtp
}

#[test]
fn test_live_serve_retries_pending_then_widening_sends_new_scope() {
    let mut p = processes();
    seed(&mut p);
    let mut smtp = smtp_down(&p);
    p.start_serve();
    let declared = p.admin(
        &[
            "incident",
            "declare",
            "--scope",
            "principal",
            "--principal",
            "agent-1",
        ],
        None,
        0,
    );
    let incident_id = id_of(&declared);
    let shown = p.admin(&["incident", "show", "--id", &incident_id], None, 0);
    assert_eq!(shown["notification"]["status"], "pending");
    smtp.start();

    let delivered = until(Duration::from_secs(20), || {
        let latest = p.admin(&["incident", "show", "--id", &incident_id], None, 0);
        (latest["notification"]["status"] == "sent").then_some(latest)
    });
    assert!(
        delivered.is_some(),
        "live serve never retried the pending notification"
    );
    assert_eq!(smtp.messages().len(), 1);
    assert!(
        smtp.auth_attempts()
            .contains(&("smtpuser".to_owned(), SMTP_PASSWORD.to_owned()))
    );
    let (_, first_body) = parse_message(&smtp.messages()[0].data);
    assert!(!first_body.contains("rt-shared"));

    let widened = p.admin(
        &[
            "incident",
            "declare",
            "--scope",
            "runtime",
            "--runtime",
            "rt-shared",
        ],
        None,
        0,
    );
    assert_eq!(id_of(&widened), incident_id);
    assert_eq!(widened["widened"], true);
    let messages = smtp.messages();
    assert_eq!(messages.len(), 2);
    let (_, second_body) = parse_message(&messages[1].data);
    assert!(second_body.contains("rt-shared"));
    assert!(second_body.contains("runtime"));
    assert!(!second_body.contains(SYNTHETIC));
    assert!(!second_body.contains(SMTP_PASSWORD));
    let (code, _) = p.agent(&["list-connections"], None);
    assert_ne!(code, 0);
    assert_eq!(p.stop_serve().0, 0);
    p.assert_no_secret_anywhere(SYNTHETIC, None);
}

#[test]
fn test_external_manual_incident_cancels_live_native_execution() {
    let mut p = processes();
    seed(&mut p);
    // A controlled SSH client keeps the native signer binding live without
    // requiring sshd. It receives only the routing socket; all key handling
    // and binding lifetime belong to the native server/signer.
    let private = zeropw::sshwire::generate_ed25519_private_key("synthetic-response-client")
        .to_openssh_private_key();
    let host = zeropw::sshwire::generate_ed25519_private_key("synthetic-response-host")
        .public
        .to_authorized_key("")
        .unwrap();
    p.admin(
        &[
            "secret",
            "put",
            "--id",
            "box-key",
            "--kind",
            "ssh_private_key",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--stdin",
        ],
        Some(private.as_bytes()),
        0,
    );
    let socket_report = p.root.join("signer-socket");
    let client = p.root.join("controlled-ssh");
    std::fs::write(
        &client,
        format!(
            "#!/bin/sh\nprintf '%s' \"$SSH_AUTH_SOCK\" > '{}'\nexec /bin/sleep 30\n",
            socket_report.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o700)).unwrap();
    p.admin(
        &[
            "connection",
            "create-ssh",
            "--id",
            "box",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--service",
            "ssh-box",
            "--secret-id",
            "box-key",
            "--host",
            "127.0.0.1",
            "--username",
            "deploy",
            "--host-key",
            &host,
            "--cli-program",
            &client.to_string_lossy(),
        ],
        None,
        0,
    );
    p.admin(
        &[
            "grant",
            "create",
            "--principal",
            "agent-1",
            "--connection",
            "box",
            "--ttl",
            "1h",
        ],
        None,
        0,
    );
    p.start_serve();
    let (_, run) = p.agent(&["exec", "--connection", "gh", "--", "30"], Some(0));
    let run_id = run["run_id"].as_str().unwrap().to_owned();
    let (_, before) = p.agent(&["status", "--run", &run_id], Some(0));
    assert_eq!(before["state"], "running", "{before}");
    let (_, ssh_run) = p.agent(
        &["exec", "--connection", "box", "--", "controlled-operation"],
        Some(0),
    );
    let ssh_run_id = ssh_run["run_id"].as_str().unwrap().to_owned();
    assert!(
        until(POLL, || std::fs::metadata(&socket_report)
            .is_ok_and(|m| m.len() > 0)
            .then_some(()))
        .is_some(),
        "the controlled SSH client never reported its signer socket"
    );
    let binding_socket = PathBuf::from(std::fs::read_to_string(&socket_report).unwrap());
    assert!(
        std::fs::metadata(&binding_socket).is_ok_and(|m| m.file_type().is_socket()),
        "no native live signer binding before the incident"
    );
    UnixStream::connect(&binding_socket).expect("the live signer socket accepts a connection");
    let declared = p.admin(
        &[
            "incident",
            "declare",
            "--scope",
            "principal",
            "--principal",
            "agent-1",
        ],
        None,
        0,
    );

    let cancelled = until(POLL, || {
        let records = p.admin(&["audit", "tail", "--limit", "500"], None, 0);
        let cancelled_ids: Vec<&str> = records["records"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["event"] == "run_finish" && r["result"] == "cancelled")
            .filter_map(|r| r["run_id"].as_str())
            .collect();
        (cancelled_ids.contains(&run_id.as_str()) && cancelled_ids.contains(&ssh_run_id.as_str()))
            .then_some(())
    });
    assert!(
        cancelled.is_some(),
        "serve did not cancel both running children after a separate-process incident"
    );
    assert!(
        until(POLL, || (!binding_socket.exists()).then_some(())).is_some(),
        "separate-process incident did not release the native live signer socket"
    );
    let shown = p.admin(&["incident", "show", "--id", &id_of(&declared)], None, 0);
    assert_eq!(shown["status"], "open");
    assert!(
        shown["principals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "agent-1")
    );
    let (code, refused) = p.agent(&["list-connections"], None);
    assert_ne!(code, 0);
    assert_eq!(reason(&refused), "principal_disabled");
    assert_eq!(p.stop_serve().0, 0);
    p.assert_no_secret_anywhere(SYNTHETIC, Some(&private));
}

fn epoch_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

#[test]
fn test_closed_pending_incident_is_not_retried_by_live_serve() {
    let mut p = processes();
    seed(&mut p);
    let mut smtp = smtp_down(&p);
    let declared = p.admin(
        &[
            "incident",
            "declare",
            "--scope",
            "principal",
            "--principal",
            "agent-1",
        ],
        None,
        0,
    );
    let incident_id = id_of(&declared);
    let shown = p.admin(&["incident", "show", "--id", &incident_id], None, 0);
    assert_eq!(shown["notification"]["status"], "pending");
    p.admin(&["incident", "close", "--id", &incident_id], None, 0);
    smtp.start();
    p.start_serve();
    // Explicitly observe several 250 ms polls after the original retry due
    // time (an observation window for something that must not happen).
    let next_attempt_at = shown["notification"]["next_attempt_at"]
        .as_f64()
        .expect("a pending notification carries next_attempt_at");
    let deadline = (epoch_seconds() + 1.25).max(next_attempt_at + 1.0);
    while epoch_seconds() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(smtp.messages().is_empty());
    assert!(smtp.auth_attempts().is_empty());
    let (code, _) = p.agent(&["list-connections"], None);
    assert_ne!(code, 0);
    assert_eq!(p.stop_serve().0, 0);
    p.assert_no_secret_anywhere(SYNTHETIC, None);
}

// ============================================= AdminCliTestCase harness

/// `AdminCliTestCase.setUp`: a temporary root, the administrator with the
/// default passphrases, and the tearDown sweep needles (the synthetic
/// values via the `synthetic-...` pattern, plus a line of the generated SSH
/// private key).
fn admin_case() -> (tempfile::TempDir, Admin) {
    let tmp = tempfile::TempDir::new().unwrap();
    let admin = Admin::new(tmp.path());
    let ssh_pem = zeropw::sshwire::generate_ed25519_private_key("demo").to_openssh_private_key();
    admin.add_needle(ssh_pem.lines().nth(1).unwrap());
    (tmp, admin)
}

fn seed_project(admin: &Admin) {
    admin.ok(&["init"]);
    admin.ok(&["project", "create", "demo"]);
}

fn put_secret(admin: &Admin) -> Value {
    admin
        .cmd(&[
            "secret",
            "put",
            "--id",
            "gh-token",
            "--kind",
            "api_key",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--stdin",
        ])
        .stdin(format!("{ADMIN_CLI_SYNTHETIC}\n").as_bytes())
        .ok()
}

fn create_http(admin: &Admin, cid: &str) -> Value {
    admin.ok(&[
        "connection",
        "create-http",
        "--id",
        cid,
        "--project",
        "demo",
        "--environment",
        "dev",
        "--service",
        "fake-github",
        "--secret-id",
        "gh-token",
        "--target",
        "http://127.0.0.1:8080",
        "--auth",
        "bearer",
        "--methods",
        "GET,POST",
        "--path-prefixes",
        "/repos,/me",
        "--confirm-methods",
        "DELETE",
    ])
}

// ------------------------------------------------ AdminCliIncidentTests

#[test]
fn test_scope_all_without_the_admin_passphrase_is_refused() {
    let (_tmp, admin) = admin_case();
    seed_project(&admin);
    let error = admin
        .cmd(&["incident", "declare", "--scope", "all"])
        .env("ZEROPW_ADMIN_PASSPHRASE", "wrong-passphrase")
        .fail(1);
    assert_eq!(reason(&error), "admin_reauth_failed");
    assert_eq!(ctx(&admin.state).policy.open_incident_id().unwrap(), None);
    assert!(
        native_e2e::events(&admin.state)
            .iter()
            .any(|e| e == "auth_failed")
    );
}

#[test]
fn test_incident_close_requires_admin_reauth() {
    let (_tmp, admin) = admin_case();
    seed_project(&admin);
    admin.ok(&["principal", "create", "--id", "agent-1"]);
    let declared = admin.ok(&[
        "incident",
        "declare",
        "--scope",
        "principal",
        "--principal",
        "agent-1",
    ]);
    let incident_id = id_of(&declared);
    let error = admin
        .cmd(&["incident", "close", "--id", &incident_id])
        .env("ZEROPW_ADMIN_PASSPHRASE", "wrong-passphrase")
        .fail(1);
    assert_eq!(reason(&error), "admin_reauth_failed");
    let closed = admin.ok(&["incident", "close", "--id", &incident_id]);
    assert_eq!(closed["status"], "closed");
    // Closing does not resume by itself, but resume is no longer refused.
    admin.ok(&["resume"]);
}

#[test]
fn test_incident_show_and_list_carry_the_assessment_and_no_values() {
    let (_tmp, admin) = admin_case();
    seed_project(&admin);
    put_secret(&admin);
    create_http(&admin, "gh");
    admin.ok(&["principal", "create", "--id", "agent-1"]);
    admin.ok(&[
        "grant",
        "create",
        "--principal",
        "agent-1",
        "--connection",
        "gh",
    ]);
    let declared = admin.ok(&[
        "incident",
        "declare",
        "--scope",
        "principal",
        "--principal",
        "agent-1",
        "--reason",
        "synthetic test lockdown",
    ]);
    let incident_id = id_of(&declared);
    let shown = admin.ok(&["incident", "show", "--id", &incident_id]);
    assert!(shown.get("assessment").is_some(), "{shown}");
    assert_eq!(shown["detail"], "synthetic test lockdown");
    let listed = admin.ok(&["incident", "list"]);
    let ids: Vec<&str> = listed["incidents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [incident_id.as_str()]);
    // The Python test checked test_incident.py's SYNTHETIC; the value
    // `put_secret` actually stored is test_admin_cli.py's. Both are checked.
    for value in [INCIDENT_SYNTHETIC, ADMIN_CLI_SYNTHETIC] {
        assert!(!shown.to_string().contains(value));
        assert!(!listed.to_string().contains(value));
    }
}

#[test]
fn test_resume_reports_the_open_incident_id() {
    let (_tmp, admin) = admin_case();
    seed_project(&admin);
    admin.ok(&["principal", "create", "--id", "agent-1"]);
    let declared = admin.ok(&[
        "incident",
        "declare",
        "--scope",
        "principal",
        "--principal",
        "agent-1",
    ]);
    let error = admin.fail(&["resume"]);
    assert_eq!(
        (
            error["error"].as_str(),
            error["reason"].as_str(),
            error["detail"].as_str()
        ),
        (
            Some("InvalidInput"),
            Some("incident_open"),
            Some(id_of(&declared).as_str())
        )
    );
}

/// M1 branch 1: a second declare that is not wider than the open incident
/// changes nothing.
#[test]
fn test_declare_absorbs_a_narrower_or_equal_request_without_extra_lockdown() {
    let (_tmp, admin) = admin_case();
    seed_project(&admin);
    admin.ok(&["principal", "create", "--id", "agent-1"]);
    admin.ok(&["principal", "create", "--id", "agent-2"]);
    let first = admin.ok(&[
        "incident",
        "declare",
        "--scope",
        "principal",
        "--principal",
        "agent-1",
    ]);
    assert!(first.get("existing").is_none(), "{first}");
    let second = admin.ok(&[
        "incident",
        "declare",
        "--scope",
        "principal",
        "--principal",
        "agent-2",
    ]);
    assert_eq!(second["id"], first["id"]);
    assert_eq!(second["scope"], "principal");
    assert_eq!(second["existing"], true);
    assert_eq!(second["widened"], false);
    // agent-2 was named in the absorbed declare but never actually locked
    // down by it.
    assert_eq!(
        ctx(&admin.state)
            .policy
            .get_principal("agent-2")
            .unwrap()
            .status,
        "active"
    );
}

/// M1 branch 2: a wider declare on an open incident applies containment to
/// the new scope.
#[test]
fn test_declare_widens_an_open_incident_when_the_new_scope_is_wider() {
    let (_tmp, admin) = admin_case();
    seed_project(&admin);
    admin.ok(&[
        "principal",
        "create",
        "--id",
        "agent-1",
        "--runtime",
        "rt-a",
    ]);
    admin.ok(&[
        "principal",
        "create",
        "--id",
        "agent-2",
        "--runtime",
        "rt-a",
    ]);
    let first = admin.ok(&[
        "incident",
        "declare",
        "--scope",
        "principal",
        "--principal",
        "agent-1",
    ]);
    assert!(first.get("existing").is_none(), "{first}");
    let second = admin.ok(&[
        "incident",
        "declare",
        "--scope",
        "runtime",
        "--runtime",
        "rt-a",
    ]);
    assert_eq!(second["id"], first["id"]);
    assert_eq!(second["scope"], "runtime");
    assert_eq!(second["existing"], true);
    assert_eq!(second["widened"], true);
    assert_eq!(
        ctx(&admin.state)
            .policy
            .get_principal("agent-2")
            .unwrap()
            .status,
        "disabled"
    );
}

// --------------------------------------------------- NotifyTestCliTests

#[test]
fn test_notify_test_sends_through_the_configured_path() {
    let (_tmp, admin) = admin_case();
    seed_project(&admin);
    let mut smtp = FakeSmtp::new();
    smtp.start();
    write_notify_config(&admin.state, &admin.root, &smtp);

    let result = admin.ok(&["incident", "notify-test"]);
    assert_eq!(result["status"], "sent");
    assert_eq!(smtp.messages().len(), 1);

    let events: Vec<Value> = ctx(&admin.state)
        .audit
        .tail(50)
        .unwrap()
        .into_iter()
        .filter(|r| r["event"] == "incident_notify")
        .collect();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].get("kind").and_then(Value::as_str),
        Some("notify_test")
    );
    // Distinguishable without inventing a fake incident id.
    assert!(events[0].get("incident_id").is_none(), "{}", events[0]);
}

#[test]
fn test_notify_test_without_config_reports_not_configured() {
    let (_tmp, admin) = admin_case();
    seed_project(&admin);
    let result = admin.ok(&["incident", "notify-test"]);
    assert_eq!(result["status"], "not_configured");
}
