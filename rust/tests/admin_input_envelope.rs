//! `zeropw-admin --input-envelope`, its `--require-admin` re-auth gate and
//! the read-only `status` command (docs/desktop-app.md §3.1), driven through
//! the real binary.
//!
//! Every passphrase and value here is synthetic. The [`Admin`] drop sweep
//! already fails a test whose stdout (other than `secret reveal`) or stderr
//! carries a `synthetic-...` token; each test also scans the audit and alert
//! files, and the whole state directory, for every envelope value.
mod native_e2e;

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine as _;
use native_e2e::{Admin, events, find_secret_in_tree};
use serde_json::{Value, json};

const ENVELOPE_ADMIN: &str = "synthetic-envelope-admin-pass-0001";
const ENVELOPE_RECOVERY: &str = "synthetic-envelope-recovery-pass-0002";
const ENV_ADMIN: &str = "synthetic-environment-admin-pass-0003";
const VALUE: &str = "synthetic-envelope-secret-value-0004";
const WRONG_ADMIN: &str = "synthetic-wrong-admin-pass-0006";

fn b64(value: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(value)
}

fn envelope(fields: Value) -> Vec<u8> {
    serde_json::to_vec(&fields).unwrap()
}

/// An administrator with no passphrase in its environment.
fn bare_admin(root: &std::path::Path) -> Admin {
    let mut admin = Admin::new(root);
    admin.set_env("ZEROPW_ADMIN_PASSPHRASE", None);
    admin.set_env("ZEROPW_RECOVERY_PASSPHRASE", None);
    admin
}

/// `--input-envelope ARGS...` with `fields` on stdin.
fn with_envelope<'a>(admin: &'a Admin, args: &[&str], fields: Value) -> native_e2e::AdminCall<'a> {
    let mut argv = vec!["--input-envelope"];
    argv.extend_from_slice(args);
    admin.cmd(&argv).stdin(&envelope(fields))
}

fn init_with_envelope(admin: &Admin) -> Value {
    with_envelope(
        admin,
        &["init"],
        json!({"admin_passphrase": ENVELOPE_ADMIN, "recovery_passphrase": ENVELOPE_RECOVERY}),
    )
    .ok()
}

/// No audit/alert line, and no file anywhere in the state directory, holds
/// one of the envelope values in any encoding the leak scanner knows.
fn assert_values_absent_from_state(admin: &Admin, values: &[&str]) {
    let needles: Vec<Vec<u8>> = values.iter().map(|v| v.as_bytes().to_vec()).collect();
    for file in ["audit/audit.jsonl", "audit/alerts.jsonl"] {
        let text = std::fs::read_to_string(admin.state.join(file)).unwrap_or_default();
        for value in values {
            assert!(!text.contains(value), "{file} holds an envelope value");
        }
    }
    assert_eq!(find_secret_in_tree(&admin.state, &needles), None);
}

#[test]
fn envelope_passphrases_drive_init_reveal_incident_close_and_recover() {
    let tmp = tempfile::TempDir::new().unwrap();
    let admin = bare_admin(tmp.path());
    let init = init_with_envelope(&admin);
    assert!(init["kms_key_id"].is_string(), "{init}");
    admin.ok(&["project", "create", "demo"]);

    let put = with_envelope(
        &admin,
        &[
            "secret",
            "put",
            "--id",
            "api",
            "--kind",
            "api_key",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--stdin",
        ],
        json!({"value_b64": b64(VALUE.as_bytes())}),
    )
    .ok();
    assert_eq!(put["version"], 1, "{put}");
    assert_eq!(put["status"], "active");

    let reveal = with_envelope(
        &admin,
        &["secret", "reveal", "--id", "api"],
        json!({"admin_passphrase": ENVELOPE_ADMIN}),
    )
    .ok();
    assert_eq!(reveal["value"], VALUE);

    admin.ok(&["principal", "create", "--id", "agent-1"]);
    let declared = admin.ok(&[
        "incident",
        "declare",
        "--scope",
        "principal",
        "--principal",
        "agent-1",
    ]);
    let id = declared["id"].as_str().unwrap().to_owned();
    let closed = with_envelope(
        &admin,
        &["incident", "close", "--id", &id],
        json!({"admin_passphrase": ENVELOPE_ADMIN}),
    )
    .ok();
    assert_eq!(closed["status"], "closed");

    let recovered = with_envelope(
        &admin,
        &["recover"],
        json!({"recovery_passphrase": ENVELOPE_RECOVERY}),
    )
    .ok();
    assert_eq!(recovered["handles_invalidated"], true);
    assert_ne!(recovered["kms_key_id"], init["kms_key_id"]);

    assert_values_absent_from_state(&admin, &[ENVELOPE_ADMIN, ENVELOPE_RECOVERY, VALUE]);
}

#[test]
fn envelope_is_the_only_passphrase_source_when_given() {
    let tmp = tempfile::TempDir::new().unwrap();
    let mut admin = bare_admin(tmp.path());
    init_with_envelope(&admin);
    admin.ok(&["project", "create", "demo"]);
    with_envelope(
        &admin,
        &[
            "secret",
            "put",
            "--id",
            "api",
            "--kind",
            "api_key",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--stdin",
        ],
        json!({"value_b64": b64(VALUE.as_bytes())}),
    )
    .ok();
    // The environment now carries a (wrong) passphrase; with an envelope it is
    // never consulted, whether the envelope has the field or not.
    admin.set_env("ZEROPW_ADMIN_PASSPHRASE", Some(ENV_ADMIN));
    let missing = with_envelope(&admin, &["secret", "reveal", "--id", "api"], json!({})).fail(1);
    assert_eq!(missing["error"], "AuthFailed");
    assert_eq!(missing["reason"], "passphrase_missing");
    let blank = with_envelope(
        &admin,
        &["secret", "reveal", "--id", "api"],
        json!({"admin_passphrase": "", "recovery_passphrase": ENVELOPE_RECOVERY}),
    )
    .fail(1);
    assert_eq!(blank["reason"], "passphrase_missing");
    let revealed = with_envelope(
        &admin,
        &["secret", "reveal", "--id", "api"],
        json!({"admin_passphrase": ENVELOPE_ADMIN}),
    )
    .ok();
    assert_eq!(revealed["value"], VALUE);
    // The environment passphrase is the actual one: an envelope with a wrong
    // field still fails, so the environment really is ignored.
    admin.set_env("ZEROPW_ADMIN_PASSPHRASE", Some(ENVELOPE_ADMIN));
    let wrong = with_envelope(
        &admin,
        &["secret", "reveal", "--id", "api"],
        json!({"admin_passphrase": ENV_ADMIN}),
    )
    .fail(1);
    assert_eq!(wrong["reason"], "admin_reauth_failed");
    let no_recovery = with_envelope(
        &admin,
        &["recover"],
        json!({"admin_passphrase": ENVELOPE_ADMIN}),
    )
    .fail(1);
    assert_eq!(no_recovery["reason"], "passphrase_missing");
    // `init` needs both fields from the envelope.
    let other = tmp.path().join("other");
    let half = with_envelope(
        &admin,
        &["init"],
        json!({"admin_passphrase": ENVELOPE_ADMIN}),
    )
    .env("ZEROPW_RECOVERY_PASSPHRASE", ENVELOPE_RECOVERY)
    .state(&other)
    .fail(1);
    assert_eq!(half["reason"], "passphrase_missing");
    assert!(!other.join("admin.json").exists());
    // Without the flag the environment is used exactly as before.
    let plain = admin.ok(&["secret", "reveal", "--id", "api"]);
    assert_eq!(plain["value"], VALUE);
    assert_values_absent_from_state(
        &admin,
        &[ENVELOPE_ADMIN, ENVELOPE_RECOVERY, VALUE, ENV_ADMIN],
    );
}

#[test]
fn stdin_value_comes_from_value_b64_only() {
    let tmp = tempfile::TempDir::new().unwrap();
    let admin = bare_admin(tmp.path());
    init_with_envelope(&admin);
    admin.ok(&["project", "create", "demo"]);
    let put = |id: &str, fields: Value| {
        with_envelope(
            &admin,
            &[
                "secret",
                "put",
                "--id",
                id,
                "--kind",
                "api_key",
                "--project",
                "demo",
                "--environment",
                "dev",
                "--stdin",
            ],
            fields,
        )
    };
    let missing = put("none", json!({"admin_passphrase": ENVELOPE_ADMIN})).fail(1);
    assert_eq!(missing["error"], "InvalidInput");
    assert_eq!(missing["reason"], "secret_source_required");
    let empty = put("empty", json!({"value_b64": ""})).fail(1);
    assert_eq!(empty["reason"], "empty_secret_value");
    // Raw bytes that are not UTF-8 survive the base64 round trip.
    let binary = [0xff_u8, 0x00, 0x80, b's', b'y', b'n'];
    put("binary", json!({"value_b64": b64(&binary)})).ok();
    let revealed = with_envelope(
        &admin,
        &["secret", "reveal", "--id", "binary"],
        json!({"admin_passphrase": ENVELOPE_ADMIN}),
    )
    .ok();
    assert_eq!(revealed["value_base64"], b64(&binary));
    // Oversized values are refused by the vault bound, as from stdin.
    let large = vec![b'a'; zeropw::vault::MAX_SECRET_BYTES + 1];
    let too_large = put("large", json!({"value_b64": b64(&large)})).fail(1);
    assert_eq!(too_large["error"], "InvalidInput");
    // `rotation start --stdin` reads the same field.
    let staged = with_envelope(
        &admin,
        &["rotation", "start", "--secret-id", "binary", "--stdin"],
        json!({"value_b64": b64(VALUE.as_bytes())}),
    )
    .ok();
    assert_eq!(staged["status"], "staged");
    let listed = admin.ok(&["secret", "versions", "--id", "binary"]);
    assert_eq!(listed["versions"].as_array().unwrap().len(), 2);
    assert_values_absent_from_state(&admin, &[ENVELOPE_ADMIN, ENVELOPE_RECOVERY, VALUE]);
}

#[test]
fn malformed_envelopes_are_refused_without_echo() {
    let tmp = tempfile::TempDir::new().unwrap();
    let admin = bare_admin(tmp.path());
    init_with_envelope(&admin);
    let marker = "synthetic-malformed-marker-0005";
    let oversized = format!(
        "{{\"invite\":\"{marker}{}\"}}",
        "a".repeat(zeropw::input_envelope::MAX_ENVELOPE_BYTES)
    );
    let inputs: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"not json at all".to_vec(),
        marker.as_bytes().to_vec(),
        format!("[\"{marker}\"]").into_bytes(),
        format!("\"{marker}\"").into_bytes(),
        format!("{{\"admin_passphrase\":[\"{marker}\"]}}").into_bytes(),
        format!("{{\"admin_passphrase\":{{\"{marker}\":1}}}}").into_bytes(),
        b"{\"admin_passphrase\":12345678901234567890}".to_vec(),
        format!("{{\"{marker}\":\"{marker}\"}}").into_bytes(),
        format!("{{\"admin_passphrase\":\"{marker}\",\"admin_passphrase\":\"{marker}\"}}")
            .into_bytes(),
        format!("{{\"admin_passphrase\":\"{marker}\"}} trailing-{marker}").into_bytes(),
        format!("{{\"admin_passphrase\":\"{marker}").into_bytes(),
        format!("{{\"value_b64\":\"{marker}!\"}}").into_bytes(),
        vec![0xff, 0xfe, b'{'],
        oversized.into_bytes(),
    ];
    let before = events(&admin.state).len();
    for input in inputs {
        let (code, out, err) = admin
            .cmd(&["--input-envelope", "secret", "reveal", "--id", "api"])
            .stdin(&input)
            .run();
        assert_eq!(code, 2, "{err}");
        assert_eq!(out, "");
        assert!(!err.contains(marker), "the refusal echoed input: {err}");
        assert!(!err.contains("12345678901234567890"), "{err}");
        let error: Value = serde_json::from_str(err.trim()).unwrap();
        assert_eq!(error["error"], "UsageError");
        assert_eq!(error["reason"], "envelope_invalid");
    }
    // Nothing ran: no command opened the state or wrote an audit record.
    assert_eq!(events(&admin.state).len(), before);
    assert_values_absent_from_state(&admin, &[ENVELOPE_ADMIN, ENVELOPE_RECOVERY, marker]);
}

#[test]
fn status_reads_the_control_state_without_changing_it() {
    let tmp = tempfile::TempDir::new().unwrap();
    let admin = Admin::new(tmp.path());
    admin.ok(&["init"]);
    let audit = || std::fs::read_to_string(admin.state.join("audit/audit.jsonl")).unwrap();
    let before = audit();
    let status = admin.ok(&["status"]);
    assert_eq!(
        status,
        json!({"stopped": false, "restore_pending": false, "incident_open": null})
    );
    assert_eq!(audit(), before, "status wrote an audit record");
    let stopped = admin.ok(&["stop-all"]);
    let status = admin.cmd(&["--input-envelope", "status"]).stdin(b"{}").ok();
    assert_eq!(status, stopped);
    assert_eq!(status["stopped"], true);
    admin.ok(&["principal", "create", "--id", "agent-1"]);
    let declared = admin.ok(&[
        "incident",
        "declare",
        "--scope",
        "principal",
        "--principal",
        "agent-1",
    ]);
    let status = admin.ok(&["status"]);
    assert_eq!(status["incident_open"], declared["id"]);
    assert_eq!(status.as_object().unwrap().len(), 3);
    // A state directory that does not exist is an error, not a fresh state.
    let missing = admin
        .cmd(&["status"])
        .state(&tmp.path().join("absent"))
        .fail(1);
    assert_eq!(missing["error"], "StateError");
}

#[test]
fn help_and_usage_do_not_list_the_new_option_or_command() {
    let tmp = tempfile::TempDir::new().unwrap();
    let admin = Admin::new(tmp.path());
    let (code, out, _) = admin.cmd(&["--help"]).no_state().run();
    assert_eq!(code, 0);
    assert!(!out.contains("input-envelope"), "{out}");
    assert!(!out.contains("require-admin"), "{out}");
    assert!(!out.contains("status"), "{out}");
    let (code, _, err) = admin.cmd(&["bogus"]).run();
    assert_eq!(code, 2);
    assert!(!err.contains("input-envelope"), "{err}");
    assert!(!err.contains("require-admin"), "{err}");
    assert!(err.contains("(choose from init,"), "{err}");
    assert!(!err.contains("status"), "{err}");
    // Both are global options: after the command they are unknown.
    for option in ["--input-envelope", "--require-admin"] {
        let (code, _, err) = admin.cmd(&["status", option]).run();
        assert_eq!(code, 2, "{err}");
        assert!(err.contains("unrecognized arguments"), "{err}");
    }
}

// ------------------------------------------------------------ --require-admin

/// `--input-envelope --require-admin ARGS...` with `fields` on stdin.
fn gated<'a>(admin: &'a Admin, args: &[&str], fields: Value) -> native_e2e::AdminCall<'a> {
    let mut argv = vec!["--input-envelope", "--require-admin"];
    argv.extend_from_slice(args);
    admin.cmd(&argv).stdin(&envelope(fields))
}

fn right() -> Value {
    json!({"admin_passphrase": ENVELOPE_ADMIN})
}

/// Every file of the state directory outside `audit/`, by relative path.
fn state_files(state: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut dirs = vec![state.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let relative = path
                .strip_prefix(state)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if relative == "audit" {
                continue;
            }
            if path.is_dir() {
                dirs.push(path);
            } else {
                files.insert(relative, std::fs::read(&path).unwrap());
            }
        }
    }
    files
}

/// The `auth_failed` records of the audit log, oldest first.
fn auth_failures(admin: &Admin) -> Vec<Value> {
    std::fs::read_to_string(admin.state.join("audit/audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|record| record["event"] == "auth_failed")
        .collect()
}

/// The gate refuses `args` with a wrong and with a missing envelope
/// passphrase (the environment's, here the right one, is never a fallback):
/// the command does not run, no state file changes, and each refusal writes
/// exactly one `auth_failed` record.
fn assert_gate_refuses(admin: &Admin, args: &[&str]) {
    let before = state_files(&admin.state);
    let failures = auth_failures(admin).len();
    let wrong = gated(admin, args, json!({"admin_passphrase": WRONG_ADMIN})).fail(1);
    assert_eq!(wrong["error"], "AuthFailed", "{args:?}");
    assert_eq!(wrong["reason"], "admin_reauth_failed", "{args:?}");
    let missing = gated(
        admin,
        args,
        json!({"admin_passphrase": "", "recovery_passphrase": ENVELOPE_RECOVERY}),
    )
    .env("ZEROPW_ADMIN_PASSPHRASE", ENVELOPE_ADMIN)
    .fail(1);
    assert_eq!(missing["error"], "AuthFailed", "{args:?}");
    assert_eq!(missing["reason"], "passphrase_missing", "{args:?}");
    let absent = gated(admin, args, json!({})).fail(1);
    assert_eq!(absent["reason"], "passphrase_missing", "{args:?}");
    assert!(
        state_files(&admin.state) == before,
        "{args:?} changed the state"
    );
    let records = auth_failures(admin);
    assert_eq!(records.len(), failures + 3, "{args:?}");
    for (record, reason) in records[failures..].iter().zip([
        "admin_reauth_failed",
        "passphrase_missing",
        "passphrase_missing",
    ]) {
        assert_eq!(record["reason"], reason, "{args:?}");
        assert_eq!(record["state"], "require_admin", "{args:?}");
        assert_eq!(record["result"], "denied", "{args:?}");
        assert_eq!(record["caller"], "admin", "{args:?}");
    }
}

#[test]
fn require_admin_gates_commands_the_cli_does_not() {
    let tmp = tempfile::TempDir::new().unwrap();
    let admin = bare_admin(tmp.path());
    init_with_envelope(&admin);
    admin.ok(&["project", "create", "demo"]);
    with_envelope(
        &admin,
        &[
            "secret",
            "put",
            "--id",
            "api",
            "--kind",
            "api_key",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--stdin",
        ],
        json!({"value_b64": b64(VALUE.as_bytes())}),
    )
    .ok();
    admin.ok(&["principal", "create", "--id", "agent-1"]);
    let archive = tmp.path().join("backup.json");
    let archive = archive.to_str().unwrap();
    admin.ok(&["backup", "--out", archive]);
    admin.ok(&["stop-all"]);

    let create = [
        "connection",
        "create-http",
        "--id",
        "gh",
        "--project",
        "demo",
        "--environment",
        "dev",
        "--service",
        "fake-github",
        "--secret-id",
        "api",
        "--target",
        "http://127.0.0.1:8080",
        "--auth",
        "bearer",
        "--methods",
        "GET",
        "--path-prefixes",
        "/repos",
    ];
    assert_gate_refuses(&admin, &create);
    let created = gated(&admin, &create, right()).ok();
    assert_eq!(created["id"], "gh");

    let update = [
        "connection",
        "update",
        "--id",
        "gh",
        "--methods",
        "GET,POST",
    ];
    assert_gate_refuses(&admin, &update);
    gated(&admin, &update, right()).ok();
    let shown = admin.ok(&["connection", "show", "--id", "gh"]);
    let methods = shown["http_scope"]["methods"].as_array().unwrap();
    assert!(methods.contains(&json!("POST")), "{shown}");

    let grant = [
        "grant",
        "create",
        "--principal",
        "agent-1",
        "--connection",
        "gh",
    ];
    assert_gate_refuses(&admin, &grant);
    let granted = gated(&admin, &grant, right()).ok();
    assert_eq!(granted["status"], "active");

    assert_gate_refuses(&admin, &["resume"]);
    assert_eq!(admin.ok(&["status"])["stopped"], true);
    let resumed = gated(&admin, &["resume"], right()).ok();
    assert_eq!(resumed["stopped"], false);

    let restore = ["restore", "--in", archive];
    assert_gate_refuses(&admin, &restore);
    assert_eq!(admin.ok(&["status"])["restore_pending"], false);
    let restored = gated(&admin, &restore, right()).ok();
    assert_eq!(restored["restore_pending"], true);

    // A read-only command passes the gate too, and prints its own output.
    let listed = gated(&admin, &["principal", "list"], right()).ok();
    assert_eq!(listed, admin.ok(&["principal", "list"]));
    assert_values_absent_from_state(
        &admin,
        &[ENVELOPE_ADMIN, ENVELOPE_RECOVERY, VALUE, WRONG_ADMIN],
    );
}

#[test]
fn require_admin_gates_team_invite_and_serve() {
    let tmp = tempfile::TempDir::new().unwrap();
    let admin = bare_admin(tmp.path());
    init_with_envelope(&admin);
    admin.ok(&["project", "create", "demo"]);
    with_envelope(
        &admin,
        &["team", "share", "--project", "demo", "--environment", "dev"],
        right(),
    )
    .ok();
    let invite = [
        "team",
        "invite",
        "--env",
        "demo/dev",
        "--role",
        "user",
        "--name",
        "bob",
        "--address",
        "127.0.0.1:47001",
        "--link",
    ];
    let invites = || admin.ok(&["team", "invites", "--env", "demo/dev"])["invites"].clone();
    assert_gate_refuses(&admin, &invite);
    assert_eq!(invites(), json!([]));
    let created = gated(&admin, &invite, right()).ok();
    assert!(created["link"].is_string());
    assert_eq!(invites().as_array().unwrap().len(), 1);

    // `serve` is refused before it binds or prints its startup line (`fail`
    // checks that stdout is empty).
    assert_gate_refuses(&admin, &["serve", "--listen", "127.0.0.1:0", "--quiet"]);
    assert_values_absent_from_state(&admin, &[ENVELOPE_ADMIN, ENVELOPE_RECOVERY, WRONG_ADMIN]);
}

#[test]
fn require_admin_without_the_envelope_is_a_usage_error() {
    let tmp = tempfile::TempDir::new().unwrap();
    // The environment holds the right passphrase; it still does not count.
    let admin = Admin::new(tmp.path());
    admin.ok(&["init"]);
    admin.ok(&["stop-all"]);
    let before = state_files(&admin.state);
    let audit = || std::fs::read_to_string(admin.state.join("audit/audit.jsonl")).unwrap();
    let audit_before = audit();
    for args in [
        &["--require-admin", "resume"][..],
        &["--require-admin", "status"],
    ] {
        let (code, out, err) = admin.cmd(args).run();
        assert_eq!(code, 2, "{err}");
        assert_eq!(out, "");
        assert!(err.starts_with("usage: zeropw-admin"), "{err}");
        let usage = err.lines().next().unwrap();
        assert!(!usage.contains("require-admin"), "{err}");
        let error: Value = serde_json::from_str(err.lines().last().unwrap()).unwrap();
        assert_eq!(error["error"], "UsageError");
        assert_eq!(error["reason"], "usage");
        assert_eq!(
            error["detail"],
            "--require-admin is valid only with --input-envelope"
        );
    }
    assert!(state_files(&admin.state) == before);
    assert_eq!(audit(), audit_before, "a refused invocation wrote audit");
    assert_eq!(admin.ok(&["status"])["stopped"], true);
    // The two global options may come in either order.
    let resumed = admin
        .cmd(&["--require-admin", "--input-envelope", "resume"])
        .stdin(&envelope(
            json!({"admin_passphrase": native_e2e::ADMIN_PASSPHRASE}),
        ))
        .ok();
    assert_eq!(resumed["stopped"], false);
}

#[test]
fn require_admin_on_an_already_gated_command_still_closes_once() {
    let tmp = tempfile::TempDir::new().unwrap();
    let admin = bare_admin(tmp.path());
    init_with_envelope(&admin);
    admin.ok(&["principal", "create", "--id", "agent-1"]);
    let declared = admin.ok(&[
        "incident",
        "declare",
        "--scope",
        "principal",
        "--principal",
        "agent-1",
    ]);
    let id = declared["id"].as_str().unwrap().to_owned();
    let close = ["incident", "close", "--id", id.as_str()];
    // The gate refuses first, so the command's own re-auth never runs: one
    // `require_admin` record per refusal, none for `incident_close`.
    assert_gate_refuses(&admin, &close);
    assert_eq!(admin.ok(&["status"])["incident_open"], json!(id));
    // With the right passphrase both checks pass and the incident closes once.
    let closed = gated(&admin, &close, right()).ok();
    assert_eq!(closed["status"], "closed");
    assert_eq!(admin.ok(&["status"])["incident_open"], Value::Null);
    let closes = events(&admin.state)
        .into_iter()
        .filter(|event| event == "incident_close")
        .count();
    assert_eq!(closes, 1);
    assert_eq!(auth_failures(&admin).len(), 3);
    assert_values_absent_from_state(&admin, &[ENVELOPE_ADMIN, ENVELOPE_RECOVERY, WRONG_ADMIN]);
}
