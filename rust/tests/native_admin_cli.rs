//! Native port of the core `AdminCliTestCase` tests of
//! `tests/test_admin_cli.py` (init, usage errors, projects, secrets,
//! connections, principals, grants, stop/resume, approvals, rotation,
//! backup/restore and recover), formerly run against `zeropw-admin` through
//! the `native_admin_contract` adapter of `rust/tests/native_cli_e2e.py`.
//!
//! Every command is a subprocess of the native `zeropw-admin` binary with
//! `--state-dir`, the given stdin bytes (empty otherwise) and the synthetic
//! passphrases in the environment. State the Python tests inspected
//! in-process (`ctx().vault`, `ctx().policy`, the audit log) is read through
//! the Rust library. Dropping the [`Admin`] performs the tearDown sweep: no
//! synthetic value, private-key line or PEM marker in any output except
//! `secret reveal` stdout.
mod native_e2e;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde_json::{Value, json};
use zeropw::context::{Config, Context};
use zeropw::policy::{Action, Decision};
use zeropw::pyint::PyInt;
use zeropw::sshwire::{Ed25519PrivateKey, generate_ed25519_private_key};

use native_e2e::{ADMIN_PASSPHRASE, Admin, events};

const SYNTHETIC: &str = "synthetic-token-0123456789";
const SYNTHETIC_V2: &str = "synthetic-token-rotated-v2";
const ADMIN_ENV: &str = "ZEROPW_ADMIN_PASSPHRASE";
const RECOVERY_ENV: &str = "ZEROPW_RECOVERY_PASSPHRASE";

const CREATE_HTTP: &str = "connection create-http --project demo --environment dev";
const PUT_DEV: &str =
    "secret put --kind api_key --project demo --environment dev --id gh-token --stdin";

// ------------------------------------------------------------------ helpers

/// An argv from whitespace-separated words (none of these contain spaces).
fn words(line: &str) -> Vec<&str> {
    line.split_whitespace().collect()
}

/// `words(line)` followed by `extra` (paths, keys and other built values).
fn with<'a>(line: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut argv = words(line);
    argv.extend_from_slice(extra);
    argv
}

/// One test's temporary root and administrator (`setUp`).
fn setup() -> (tempfile::TempDir, Admin) {
    let tmp = tempfile::TempDir::new().unwrap();
    let admin = Admin::new(tmp.path());
    (tmp, admin)
}

/// An SSH key whose private-key line joins the leak sweep, as the Python
/// tearDown did; returns (key, OpenSSH PEM).
fn ssh_key(admin: &Admin, comment: &str) -> (Ed25519PrivateKey, String) {
    let key = generate_ed25519_private_key(comment);
    let pem = key.to_openssh_private_key();
    admin.add_needle(pem.lines().nth(1).unwrap());
    (key, pem)
}

fn host_key(comment: &str) -> String {
    generate_ed25519_private_key(comment)
        .public
        .to_authorized_key(comment)
        .unwrap()
}

fn init(admin: &Admin) -> Value {
    admin.ok(&["init"])
}

fn seed_project(admin: &Admin) {
    init(admin);
    admin.ok(&["project", "create", "demo"]);
}

fn put_secret(admin: &Admin, value: &str, secret_id: &str, environment: &str) -> Value {
    let line = format!(
        "secret put --id {secret_id} --kind api_key --project demo \
         --environment {environment} --stdin"
    );
    admin
        .cmd(&words(&line))
        .stdin(format!("{value}\n").as_bytes())
        .ok()
}

/// `secret put ... --stdin` of the box SSH key (dev).
fn put_ssh_key(admin: &Admin, pem: &str) {
    let line = "secret put --id box-key --kind ssh_private_key --project demo \
                --environment dev --stdin";
    admin.cmd(&words(line)).stdin(pem.as_bytes()).ok();
}

fn create_http(admin: &Admin, cid: &str, extra: &[&str]) -> Value {
    let line = format!(
        "connection create-http --id {cid} --project demo --environment dev \
         --service fake-github --secret-id gh-token --target http://127.0.0.1:8080 \
         --auth bearer --methods GET,POST --path-prefixes /repos,/me --confirm-methods DELETE"
    );
    admin.ok(&with(&line, extra))
}

/// `Context.open(state)`: a fresh view of the persisted state.
fn ctx(admin: &Admin) -> Context {
    Context::open(&admin.state, Config::default(), zeropw::clock::system()).unwrap()
}

/// `ctx().policy.evaluate("agent-1", "gh", Action("http", method, path), grant)`.
fn evaluate(admin: &Admin, method: &str, path: &str, grant: Option<&str>) -> Decision {
    ctx(admin)
        .policy
        .evaluate("agent-1", "gh", &Action::http(method, path), grant)
        .unwrap()
}

fn trusted_value(ctx: &Context, secret_id: &str, version: Option<i64>) -> Vec<u8> {
    ctx.vault
        .secret_for_trusted_use(secret_id, version.map(PyInt::from))
        .unwrap()
        .expose()
        .to_vec()
}

fn statuses(ctx: &Context, secret_id: &str) -> Vec<String> {
    ctx.vault
        .get_meta(secret_id)
        .unwrap()
        .versions
        .iter()
        .map(|v| v.status.as_str().unwrap_or_default().to_owned())
        .collect()
}

fn active_version(ctx: &Context, secret_id: &str) -> Option<Value> {
    ctx.vault
        .get_meta(secret_id)
        .unwrap()
        .active_version
        .map(|v| v.value())
}

fn reason(error: &Value) -> &str {
    error["reason"].as_str().unwrap_or_default()
}

/// The `reason` of `fail(...)` (exit 1) for a whitespace-separated argv.
fn fail_reason(admin: &Admin, line: &str) -> String {
    reason(&admin.fail(&words(line))).to_owned()
}

fn ids(items: &Value, key: &str) -> Vec<String> {
    items[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap().to_owned())
        .collect()
}

fn count(events: &[String], name: &str) -> usize {
    events.iter().filter(|e| *e == name).count()
}

fn has(events: &[String], name: &str) -> bool {
    events.iter().any(|e| e == name)
}

fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                files.push(entry.path());
            }
        }
    }
    files
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// --------------------------------------------------------------------- init

#[test]
fn init_creates_state_and_reports_kms_key() {
    let (_tmp, admin) = setup();
    let payload = init(&admin);
    assert_eq!(payload["state_dir"], json!(admin.state.to_string_lossy()));
    assert_eq!(payload["kms_key_id"], "local-dev-kms-1");
    let mode = std::fs::metadata(&admin.state)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);
    assert_eq!(reason(&admin.fail(&["init"])), "state_exists");
    assert!(has(&events(&admin.state), "init"));
}

#[test]
fn init_rejects_weak_or_missing_passphrases() {
    let (_tmp, admin) = setup();
    let short = admin.cmd(&["init"]).env(ADMIN_ENV, "short").fail(1);
    assert_eq!(reason(&short), "passphrase_too_short");
    let identical = admin
        .cmd(&["init"])
        .env(RECOVERY_ENV, ADMIN_PASSPHRASE)
        .fail(1);
    assert_eq!(reason(&identical), "passphrases_identical");
    // Stdin is a pipe, never a terminal: no prompt.
    let missing = admin.cmd(&["init"]).unset(ADMIN_ENV).fail(1);
    assert_eq!(reason(&missing), "passphrase_missing");
    assert!(!admin.state.exists());
}

// ------------------------------------------------------------- usage/errors

#[test]
fn usage_errors_exit_2_with_json() {
    let (tmp, admin) = setup();
    for line in [
        "",
        "bogus",
        "project",
        "secret put --id x --kind api_key --project demo --environment dev",
    ] {
        let error = admin.cmd(&words(line)).fail(2);
        assert_eq!(reason(&error), "usage", "{line:?}");
    }
    let value_file = tmp.path().join("f");
    let both = admin
        .cmd(&with(
            "secret put --id x --kind api_key --project demo --environment dev --stdin \
             --value-file",
            &[value_file.to_str().unwrap()],
        ))
        .fail(2);
    assert_eq!(reason(&both), "usage");
    // --state-dir is required.
    let (code, _out, err) = admin.cmd(&["project", "list"]).no_state().run();
    assert_eq!(code, 2);
    let last: Value = serde_json::from_str(err.lines().last().unwrap()).unwrap();
    assert!(reason(&last).contains("usage"), "{last}");
    let (code, out, _err) = admin.cmd(&["--help"]).no_state().run();
    assert_eq!(code, 0);
    assert!(out.contains("--state-dir"), "{out}");
}

#[test]
fn unknown_state_dir_exits_1() {
    let (tmp, admin) = setup();
    let missing = tmp.path().join("missing");
    let error = admin.cmd(&["project", "list"]).state(&missing).fail(1);
    assert_eq!(reason(&error), "state_missing");
    let error = admin.cmd(&["secret", "list"]).state(&missing).fail(1);
    assert_eq!(error["error"], "StateError");
}

#[test]
fn help_subprocess() {
    let (_tmp, admin) = setup();
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let (code, out, err) = admin.cmd(&["--help"]).no_state().cwd(repo_root).run();
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("serve"), "{out}");
}

// ----------------------------------------------------------------- projects

#[test]
fn project_create_and_list() {
    let (_tmp, admin) = setup();
    init(&admin);
    let created = admin.ok(&words("project create demo --environments dev,prod"));
    assert_eq!(created["environments"], json!(["dev", "prod"]));
    assert_eq!(
        admin.ok(&["project", "create", "other"])["environments"],
        json!(["dev", "staging", "prod"])
    );
    let listing = admin.ok(&["project", "list"]);
    let names: Vec<&str> = listing["projects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["demo", "other"]);
    assert_eq!(fail_reason(&admin, "project create demo"), "project_exists");
    let bad = admin.fail(&["project", "create", "Bad Name"]);
    assert_eq!(reason(&bad), "invalid_project");
    assert_eq!(count(&events(&admin.state), "project_create"), 2);
}

// ------------------------------------------------------------------ secrets

#[test]
fn secret_put_via_file_and_stdin_lists_metadata_only() {
    let (tmp, admin) = setup();
    seed_project(&admin);
    let value_file = tmp.path().join("value.txt");
    std::fs::write(&value_file, format!("{SYNTHETIC}\n")).unwrap();
    let put = admin.ok(&with(
        "secret put --id gh-token --kind api_key --project demo --environment dev --value-file",
        &[value_file.to_str().unwrap()],
    ));
    assert_eq!(
        (&put["version"], &put["status"]),
        (&json!(1), &json!("active"))
    );
    let staged = admin
        .cmd(&with(PUT_DEV, &["--staged"]))
        .stdin(SYNTHETIC_V2.as_bytes())
        .ok();
    assert_eq!(
        (&staged["version"], &staged["status"]),
        (&json!(2), &json!("staged"))
    );
    {
        let ctx = ctx(&admin);
        // The trailing newline is stripped.
        assert_eq!(
            trusted_value(&ctx, "gh-token", Some(1)),
            SYNTHETIC.as_bytes()
        );
        assert_eq!(
            trusted_value(&ctx, "gh-token", Some(2)),
            SYNTHETIC_V2.as_bytes()
        );
    }

    let listing = admin.ok(&words("secret list --project demo --environment dev"));
    assert_eq!(ids(&listing, "secrets"), ["gh-token"]);
    let versions = admin.ok(&words("secret versions --id gh-token"));
    assert_eq!(versions["active_version"], 1);
    let version_statuses: Vec<&str> = versions["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["status"].as_str().unwrap())
        .collect();
    assert_eq!(version_statuses, ["active", "staged"]);
    for text in [listing.to_string(), versions.to_string()] {
        assert!(!text.contains("ciphertext"), "{text}");
        assert!(!text.contains("nonce"), "{text}");
        assert!(!text.contains(SYNTHETIC), "{text}");
    }
    let prod = admin.ok(&words("secret list --environment prod"));
    assert_eq!(prod["secrets"], json!([]));
    assert_eq!(
        fail_reason(&admin, "secret versions --id nope"),
        "secret_not_found"
    );
    let missing = tmp.path().join("missing");
    let error = admin.fail(&with(
        "secret put --id x --kind api_key --project demo --environment dev --value-file",
        &[missing.to_str().unwrap()],
    ));
    assert_eq!(reason(&error), "file_not_found");
    let empty = admin
        .cmd(&words(
            "secret put --id x --kind api_key --project demo --environment dev --stdin",
        ))
        .stdin(b"\n")
        .fail(1);
    assert_eq!(reason(&empty), "empty_secret_value");
    // The value never lands anywhere in the state directory.
    for path in files_under(&admin.state) {
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !contains_bytes(&bytes, SYNTHETIC.as_bytes()),
            "{}",
            path.display()
        );
    }
}

#[test]
fn reveal_requires_passphrase_and_is_audited() {
    let (_tmp, admin) = setup();
    seed_project(&admin);
    put_secret(&admin, SYNTHETIC, "gh-token", "dev");
    let reveal = words("secret reveal --id gh-token");
    let revealed = admin.ok(&reveal);
    assert_eq!(
        revealed,
        json!({"id": "gh-token", "version": 1, "value": SYNTHETIC})
    );
    let wrong = admin
        .cmd(&reveal)
        .env(ADMIN_ENV, "wrong-passphrase")
        .fail(1);
    assert_eq!(reason(&wrong), "admin_reauth_failed");
    let missing = admin.cmd(&reveal).unset(ADMIN_ENV).fail(1);
    assert_eq!(reason(&missing), "passphrase_missing");
    assert_eq!(
        fail_reason(&admin, "secret reveal --id gh-token --version 9"),
        "secret_version_not_found"
    );
    let tail = admin.ok(&words("audit tail --limit 20"));
    let tail_events: Vec<String> = tail["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["event"].as_str().unwrap().to_owned())
        .collect();
    assert!(has(&tail_events, "secret_reveal"), "{tail_events:?}");
    assert!(has(&tail_events, "auth_failed"), "{tail_events:?}");
    assert_eq!(count(&tail_events, "secret_reveal"), 1);
    let alerts = admin.ok(&["alerts"]);
    assert!(
        alerts["alerts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["alert"] == "secret_reveal"),
        "{alerts}"
    );
}

#[test]
fn reveal_of_binary_value_uses_base64() {
    let (_tmp, admin) = setup();
    seed_project(&admin);
    let raw = b"\xff\xfe synthetic-binary \x00\x01";
    admin
        .cmd(&words(
            "secret put --id blob --kind password --project demo --environment dev --stdin",
        ))
        .stdin(raw)
        .ok();
    let revealed = admin.ok(&words("secret reveal --id blob"));
    assert_eq!(revealed["encoding"], "base64");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(revealed["value_base64"].as_str().unwrap())
        .unwrap();
    assert_eq!(decoded, raw);
}

#[test]
fn secret_retire_and_revoke() {
    let (_tmp, admin) = setup();
    seed_project(&admin);
    put_secret(&admin, SYNTHETIC, "gh-token", "dev");
    admin
        .cmd(&with(PUT_DEV, &["--staged"]))
        .stdin(SYNTHETIC_V2.as_bytes())
        .ok();
    create_http(&admin, "gh", &[]);
    // Staged versions are usable.
    admin.ok(&words("connection switch-credential --id gh --version 2"));
    assert_eq!(
        fail_reason(&admin, "secret retire --id gh-token --version 1"),
        "version_is_active"
    );
    assert_eq!(
        fail_reason(&admin, "secret retire --id gh-token --version 2"),
        "version_in_use"
    );
    admin.ok(&words("connection switch-credential --id gh --version 1"));
    let retired = admin.ok(&words("secret retire --id gh-token --version 2"));
    assert_eq!(retired["status"], "retired");
    let revoked = admin.ok(&words("secret revoke --id gh-token --version 1"));
    assert_eq!(revoked["affected_connections"], json!(["gh"]));
    assert_eq!(revoked["provider_revocation_required"], true);
    {
        let ctx = ctx(&admin);
        assert_eq!(active_version(&ctx, "gh-token"), None);
        assert_eq!(statuses(&ctx, "gh-token"), ["revoked", "retired"]);
        // Fails closed for the gateway.
        let revoked_use = ctx
            .vault
            .secret_for_trusted_use("gh-token", Some(PyInt::from(1)));
        assert!(revoked_use.is_err());
    }
    assert_eq!(
        fail_reason(&admin, "secret retire --id gh-token --version 7"),
        "secret_version_not_found"
    );
    let events = events(&admin.state);
    assert!(has(&events, "secret_retire"));
    assert!(has(&events, "secret_revoke"));
}

// -------------------------------------------------------------- connections

#[test]
fn connection_http_lifecycle_and_scope_changes() {
    let (_tmp, admin) = setup();
    seed_project(&admin);
    put_secret(&admin, SYNTHETIC, "gh-token", "dev");
    let created = create_http(
        &admin,
        "gh",
        &words(
            "--description demo --cli-program /usr/local/bin/democli \
             --cli-env DEMOCLI_COLOR=never",
        ),
    );
    assert_eq!(created["policy_version"], 1);
    assert_eq!(
        created["http_target"],
        json!({"scheme": "http", "host": "127.0.0.1", "port": 8080, "ca_file": null,
               "allow_private_network": false})
    );
    assert_eq!(created["http_scope"]["methods"], json!(["GET", "POST"]));
    assert_eq!(
        created["cli"]["extra_env"],
        json!({"DEMOCLI_COLOR": "never"})
    );
    assert_eq!(
        ids(&admin.ok(&["connection", "list"]), "connections"),
        ["gh"]
    );
    let shown = admin.ok(&words("connection show --id gh"));
    assert_eq!(shown["service"], "fake-github");
    assert_eq!(
        fail_reason(&admin, "connection show --id nope"),
        "connection_not_found"
    );
    assert_eq!(
        fail_reason(
            &admin,
            "connection create-http --id gh --project demo --environment dev --service x \
             --secret-id gh-token --target http://127.0.0.1:1 --auth bearer"
        ),
        "connection_exists"
    );

    admin.ok(&words("principal create --id agent-1"));
    let grant = admin.ok(&words("grant create --principal agent-1 --connection gh"));
    let grant_id = grant["id"].as_str().unwrap();
    let narrowed = admin.ok(&words("connection update-scope --id gh --methods GET"));
    assert_eq!(
        (&narrowed["widened"], &narrowed["policy_version"]),
        (&json!(false), &json!(2))
    );
    {
        let ctx = ctx(&admin);
        let stored = ctx.policy.get_grant(grant_id).unwrap();
        assert_eq!(stored.status, "active");
        assert_eq!(stored.policy_version, PyInt::from(2));
    }
    assert_eq!(
        evaluate(&admin, "POST", "/repos", None).reason,
        "method_not_allowed"
    );
    assert!(evaluate(&admin, "GET", "/repos", None).allowed);

    let widened = admin.ok(&words(
        "connection update-scope --id gh --methods GET,POST,PUT --path-prefixes /repos,/me,/orgs",
    ));
    assert_eq!(
        (&widened["widened"], &widened["policy_version"]),
        (&json!(true), &json!(3))
    );
    assert_eq!(widened["scope"]["methods"], json!(["GET", "POST", "PUT"]));
    let stored = ctx(&admin).policy.get_grant(grant_id).unwrap();
    assert_eq!(stored.status, "stale");
    assert_eq!(evaluate(&admin, "PUT", "/orgs", None).reason, "grant_stale");
    assert_eq!(
        fail_reason(&admin, "connection update-scope --id gh"),
        "no_scope_changes"
    );

    let every = admin.ok(&words(
        "connection update-scope --id gh --methods all --confirm-methods none",
    ));
    assert_eq!(every["widened"], true);
    assert_eq!(
        every["scope"],
        json!({"methods": "all", "path_prefixes": ["/repos", "/me", "/orgs"],
               "confirm_methods": []})
    );

    let disabled = admin.ok(&words("connection disable --id gh"));
    assert_eq!(disabled["status"], "disabled");
    assert_eq!(
        fail_reason(&admin, "grant create --principal agent-1 --connection gh"),
        "connection_disabled"
    );
    let events = events(&admin.state);
    assert_eq!(count(&events, "connection_create"), 1);
    assert_eq!(count(&events, "connection_update"), 3);
    assert_eq!(count(&events, "connection_disable"), 1);
}

#[test]
fn connection_create_http_validations_and_port_defaults() {
    let (tmp, admin) = setup();
    let (_key, pem) = ssh_key(&admin, "demo");
    seed_project(&admin);
    put_secret(&admin, SYNTHETIC, "gh-token", "dev");
    put_secret(&admin, SYNTHETIC, "prod-token", "prod");
    put_ssh_key(&admin, &pem);
    let base = format!("{CREATE_HTTP} --service svc --id a");
    let local = "--target http://127.0.0.1 --auth bearer";
    let no_ca = tmp.path().join("no.pem");
    let cases = [
        (
            "--secret-id gh-token --target http://127.0.0.1:8080/api --auth bearer".to_owned(),
            "target_must_be_origin",
        ),
        (
            "--secret-id gh-token --target ftp://127.0.0.1 --auth bearer".to_owned(),
            "invalid_scheme",
        ),
        (format!("--secret-id nope {local}"), "secret_not_found"),
        (
            format!("--secret-id prod-token {local}"),
            "secret_scope_mismatch",
        ),
        (
            format!("--secret-id box-key {local}"),
            "secret_kind_mismatch",
        ),
        (
            "--secret-id gh-token --target http://127.0.0.1 --auth basic".to_owned(),
            "invalid_basic_username",
        ),
        (
            "--secret-id gh-token --target http://127.0.0.1 --auth header".to_owned(),
            "invalid_header_name",
        ),
        (
            format!("--secret-id gh-token --secret-version 5 {local}"),
            "secret_version_not_found",
        ),
        (
            format!("--secret-id gh-token {local} --ca-file {}", no_ca.display()),
            "ca_file_missing",
        ),
        (
            format!("--secret-id gh-token {local} --cli-program x --cli-env novalue"),
            "invalid_cli_env",
        ),
    ];
    for (extra, expected) in cases {
        assert_eq!(
            fail_reason(&admin, &format!("{base} {extra}")),
            expected,
            "{extra}"
        );
    }
    assert_eq!(
        fail_reason(
            &admin,
            "connection create-http --project demo --environment qa --service svc --id a \
             --secret-id gh-token --target http://127.0.0.1 --auth bearer"
        ),
        "environment_not_found"
    );
    assert_eq!(admin.ok(&["connection", "list"])["connections"], json!([]));

    let https = admin.ok(&words(&format!(
        "{CREATE_HTTP} --service svc --id secure --secret-id gh-token \
         --target https://api.example.com --auth header --header-name X-Api-Key"
    )));
    assert_eq!(https["http_target"]["port"], 443);
    assert_eq!(
        https["http_scope"],
        json!({"methods": ["GET", "HEAD"], "path_prefixes": null, "confirm_methods": []})
    );
    let plain = admin.ok(&words(&format!(
        "{CREATE_HTTP} --service svc --id plain --secret-id gh-token \
         --target http://example.com --auth basic --basic-username bot --methods all \
         --secret-version 1"
    )));
    assert_eq!(
        (&plain["http_target"]["port"], &plain["secret_version"]),
        (&json!(80), &json!(1))
    );
    assert!(plain["http_scope"]["methods"].is_null());
}

#[test]
fn connection_create_ssh() {
    let (_tmp, admin) = setup();
    let (key, pem) = ssh_key(&admin, "demo");
    let host = host_key("host");
    seed_project(&admin);
    put_ssh_key(&admin, &pem);
    let second = host_key("host2");
    let created = admin.ok(&with(
        "connection create-ssh --id box --project demo --environment dev --service ssh-box \
         --secret-id box-key --host 127.0.0.1 --port 2222 --username deploy --cli-program ssh",
        &["--host-key", &host, "--host-key", &second],
    ));
    assert_eq!(created["kind"], "ssh");
    assert_eq!(created["ssh_target"]["host_keys"], json!([host, second]));
    assert_eq!(created["fingerprint"], json!(key.public.fingerprint()));
    let public_key = created["public_key"].as_str().unwrap();
    assert!(public_key.starts_with("ssh-ed25519 "), "{public_key}");
    assert_eq!(
        created["cli"],
        json!({"program": "ssh", "kind": "ssh", "base_url_env": "ZEROPW_API_BASE_URL",
               "extra_env": {}})
    );
    for bad_host_key in ["ssh-rsa AAAAB3Nza", "ssh-ed25519 not-base64!!"] {
        let error = admin.fail(&with(
            "connection create-ssh --id bad --project demo --environment dev --service s \
             --secret-id box-key --host 127.0.0.1 --username deploy --host-key",
            &[bad_host_key],
        ));
        assert_eq!(reason(&error), "invalid_host_key", "{bad_host_key}");
    }
    assert_eq!(
        fail_reason(&admin, "connection update-scope --id box --methods GET"),
        "scope_requires_http"
    );
    assert!(has(&events(&admin.state), "connection_create"));
}

/// F8 repair: an SSH connection created without an ssh (`cli: null`, which
/// `exec` refuses with `cli_not_supported`) gets one in place through
/// `connection update --cli-program`. Only a missing program on an active SSH
/// connection is filled; every refusal leaves the connection as it was. The
/// new program widens the connection, so its grants go stale.
#[test]
fn connection_update_gives_an_ssh_connection_without_one_its_ssh() {
    let (_tmp, admin) = setup();
    let (_key, pem) = ssh_key(&admin, "demo");
    let host = host_key("host");
    seed_project(&admin);
    put_ssh_key(&admin, &pem);
    put_secret(&admin, SYNTHETIC, "gh-token", "dev");
    create_http(&admin, "gh", &[]);
    let ssh = "connection create-ssh --project demo --environment dev --service ssh-box \
               --secret-id box-key --host 127.0.0.1 --username deploy";
    for id in ["box", "off"] {
        let created = admin.ok(&with(&format!("{ssh} --id {id}"), &["--host-key", &host]));
        assert!(created["cli"].is_null(), "{created}");
    }
    admin.ok(&with(
        &format!("{ssh} --id named --cli-program ssh"),
        &["--host-key", &host],
    ));
    admin.ok(&words("connection disable --id off"));
    admin.ok(&words("principal create --id agent-1"));
    let grant = admin.ok(&words("grant create --principal agent-1 --connection box"));
    let grant_id = grant["id"].as_str().unwrap();

    let program = "/usr/bin/ssh";
    let refused: [(Vec<&str>, &str); 7] = [
        (
            words("connection update --id gh --cli-program /usr/bin/ssh"),
            "cli_requires_ssh",
        ),
        (
            words("connection update-scope --id gh --cli-program /usr/bin/ssh"),
            "cli_requires_ssh",
        ),
        (
            words("connection update --id box --cli-program /usr/bin/ssh --methods GET"),
            "scope_requires_http",
        ),
        (
            words("connection update --id box --cli-program")
                .into_iter()
                .chain([""])
                .collect(),
            "invalid_cli_program",
        ),
        (
            words("connection update --id named --cli-program /usr/bin/ssh"),
            "cli_already_set",
        ),
        (
            words("connection update --id off --cli-program /usr/bin/ssh"),
            "connection_disabled",
        ),
        (
            words("connection update --id ghost --cli-program /usr/bin/ssh"),
            "connection_not_found",
        ),
    ];
    let before: Vec<Value> = ["gh", "box", "named", "off"]
        .iter()
        .map(|id| admin.ok(&["connection", "show", "--id", id]))
        .collect();
    for (argv, why) in &refused {
        assert_eq!(reason(&admin.fail(argv)), *why, "{argv:?}");
    }
    let unchanged: Vec<Value> = ["gh", "box", "named", "off"]
        .iter()
        .map(|id| admin.ok(&["connection", "show", "--id", id]))
        .collect();
    assert_eq!(unchanged, before);
    assert_eq!(
        ctx(&admin).policy.get_grant(grant_id).unwrap().status,
        "active"
    );
    assert!(!has(&events(&admin.state), "connection_update"));

    let filled = admin.ok(&words(
        "connection update --id box --cli-program /usr/bin/ssh",
    ));
    let cli = json!({"program": program, "kind": "ssh", "base_url_env": "ZEROPW_API_BASE_URL",
                     "extra_env": {}});
    assert_eq!(
        filled,
        json!({"id": "box", "widened": true, "policy_version": 2, "cli": cli,
               "note": "existing grants are stale and need regrant"})
    );
    let shown = admin.ok(&words("connection show --id box"));
    assert_eq!((&shown["cli"], &shown["policy_version"]), (&cli, &json!(2)));
    assert_eq!(shown["ssh_target"], before[1]["ssh_target"]);
    let ctx = ctx(&admin);
    assert_eq!(ctx.policy.get_grant(grant_id).unwrap().status, "stale");
    assert!(ctx.audit.tail(20).unwrap().iter().any(|r| {
        r["event"] == "connection_update"
            && r["connection"] == "box"
            && r["detail"] == "cli"
            && r["state"] == "widened"
            && r["policy_version"] == 2
    }));

    // Filled once: changing it stays disable and recreate.
    assert_eq!(
        fail_reason(
            &admin,
            "connection update --id box --cli-program /bin/false"
        ),
        "cli_already_set"
    );
    assert_eq!(admin.ok(&words("connection show --id box")), shown);
    // A new grant is usable against the new policy version.
    let regrant = admin.ok(&words("grant create --principal agent-1 --connection box"));
    assert_eq!(regrant["policy_version"], 2);
}

#[test]
fn switch_credential_validates_version_state() {
    let (_tmp, admin) = setup();
    seed_project(&admin);
    put_secret(&admin, SYNTHETIC, "gh-token", "dev");
    put_secret(&admin, SYNTHETIC_V2, "gh-token", "dev");
    create_http(&admin, "gh", &[]);
    assert_eq!(
        fail_reason(&admin, "connection switch-credential --id gh --version 3"),
        "secret_version_not_found"
    );
    assert_eq!(
        fail_reason(&admin, "connection switch-credential --id gh --version 1"),
        "secret_version_unusable"
    );
    let switched = admin.ok(&words("connection switch-credential --id gh --version 2"));
    assert_eq!(
        (&switched["secret_version"], &switched["policy_version"]),
        (&json!(2), &json!(2))
    );
    assert!(has(&events(&admin.state), "connection_switch_credential"));
}

// --------------------------------------------------------------- principals

#[test]
fn principal_create_prints_token_once_and_list_hides_it() {
    let (_tmp, admin) = setup();
    init(&admin);
    let created = admin.ok(&words("principal create --id agent-1"));
    let token = created["token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("zpwc_"));
    let principal = ctx(&admin).policy.authenticate(&token).unwrap();
    assert_eq!(principal.id, "agent-1");
    let listing = admin.ok(&["principal", "list"]);
    assert_eq!(
        listing["principals"],
        json!([{"id": "agent-1", "status": "active", "runtime": "default",
                "created_at": listing["principals"][0]["created_at"]}])
    );
    let text = listing.to_string();
    assert!(!text.contains(&token));
    assert!(!text.contains(&zeropw::policy::hash_token(&token)));
    assert_eq!(
        fail_reason(&admin, "principal create --id agent-1"),
        "principal_exists"
    );
    let disabled = admin.ok(&words("principal disable --id agent-1"));
    assert_eq!(disabled["status"], "disabled");
    assert_eq!(
        admin.ok(&["principal", "list"])["principals"][0]["status"],
        "disabled"
    );
    assert_eq!(
        fail_reason(&admin, "principal disable --id ghost"),
        "principal_not_found"
    );
    let events = events(&admin.state);
    assert!(has(&events, "principal_create"));
    assert!(has(&events, "principal_disable"));
    // The token appears in exactly one command output: the create.
    let outputs = admin.outputs.lock().unwrap();
    let printed = outputs.iter().filter(|r| r.stdout.contains(&token)).count();
    assert_eq!(printed, 1);
}

// ------------------------------------------------------------------- grants

#[test]
fn grant_lifecycle() {
    let (_tmp, admin) = setup();
    seed_project(&admin);
    put_secret(&admin, SYNTHETIC, "gh-token", "dev");
    create_http(&admin, "gh", &[]);
    admin.ok(&words("principal create --id agent-1"));
    let create = "grant create --principal agent-1 --connection gh";
    let grant = admin.ok(&words(&format!("{create} --ttl 30m --max-uses 3")));
    let grant_id = grant["id"].as_str().unwrap();
    assert_eq!(
        (
            &grant["status"],
            &grant["max_uses"],
            &grant["policy_version"]
        ),
        (&json!("active"), &json!(3), &json!(1))
    );
    assert!(grant["expires_at"].as_str().unwrap().ends_with('Z'));
    for ttl in ["soon", "31d"] {
        let error = fail_reason(&admin, &format!("{create} --ttl {ttl}"));
        assert_eq!(error, "invalid_ttl", "{ttl}");
    }
    assert_eq!(
        fail_reason(&admin, "grant create --principal ghost --connection gh"),
        "principal_not_found"
    );
    let listing = admin.ok(&words("grant list --principal agent-1"));
    assert_eq!(ids(&listing, "grants"), [grant_id]);
    let other = admin.ok(&words("grant list --principal other"));
    assert_eq!(other["grants"], json!([]));
    assert!(evaluate(&admin, "GET", "/repos", None).allowed);

    // Widening makes the grant stale.
    admin.ok(&words(
        "connection update-scope --id gh --methods GET,POST,PUT",
    ));
    assert_eq!(admin.ok(&["grant", "list"])["grants"][0]["status"], "stale");
    let fresh = admin.ok(&["grant", "regrant", "--id", grant_id]);
    assert_eq!(
        (
            &fresh["status"],
            &fresh["policy_version"],
            &fresh["replaces"]
        ),
        (&json!("active"), &json!(2), &json!(grant_id))
    );
    assert_eq!(fresh["max_uses"], 3);
    assert!(evaluate(&admin, "PUT", "/repos", None).allowed);
    let again = admin.fail(&["grant", "regrant", "--id", grant_id]);
    assert_eq!(reason(&again), "grant_not_regrantable");

    let revoked = admin.ok(&["grant", "revoke", "--id", fresh["id"].as_str().unwrap()]);
    assert_eq!(revoked["status"], "revoked");
    assert_eq!(
        evaluate(&admin, "GET", "/repos", None).reason,
        "grant_revoked"
    );
    assert_eq!(
        fail_reason(&admin, "grant revoke --id g-missing"),
        "grant_not_found"
    );
    let events = events(&admin.state);
    for event in ["grant_create", "grant_regrant", "grant_revoke"] {
        assert!(has(&events, event), "{event}");
    }
}

// -------------------------------------------------------------- stop/resume

#[test]
fn stop_all_and_resume_reflected_in_policy() {
    let (_tmp, admin) = setup();
    seed_project(&admin);
    put_secret(&admin, SYNTHETIC, "gh-token", "dev");
    create_http(&admin, "gh", &[]);
    admin.ok(&words("principal create --id agent-1"));
    admin.ok(&words("grant create --principal agent-1 --connection gh"));
    let stopped = admin.ok(&["stop-all"]);
    assert_eq!(
        stopped,
        json!({"stopped": true, "restore_pending": false, "incident_open": null})
    );
    {
        let ctx = ctx(&admin);
        assert!(ctx.policy.is_stopped().unwrap());
        let decision = ctx
            .policy
            .evaluate("agent-1", "gh", &Action::http("GET", "/repos"), None)
            .unwrap();
        assert_eq!(decision.reason, "global_stop");
        assert!(ctx.policy.usable_connections("agent-1").unwrap().is_empty());
    }
    let resumed = admin.ok(&["resume"]);
    assert_eq!(resumed["stopped"], false);
    assert!(evaluate(&admin, "GET", "/repos", None).allowed);
    let events = events(&admin.state);
    assert!(has(&events, "stop_all"));
    assert!(has(&events, "resume"));
}

// ---------------------------------------------------------------- approvals

#[test]
fn approvals_list_and_approve() {
    let (_tmp, admin) = setup();
    seed_project(&admin);
    put_secret(&admin, SYNTHETIC, "gh-token", "dev");
    create_http(&admin, "gh", &[]);
    admin.ok(&words("principal create --id agent-1"));
    assert_eq!(admin.ok(&["approvals", "list"])["approvals"], json!([]));
    let digest = zeropw::policy::approval_digest("agent-1", "gh", "DELETE", "/repos/demo", b"");
    // What the gateway does.
    ctx(&admin)
        .policy
        .request_approval(&digest, "agent-1", "gh", "DELETE", "/repos/demo")
        .unwrap();
    let pending = admin.ok(&["approvals", "list"]);
    let summary: Vec<(Value, Value, Value)> = pending["approvals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["digest"].clone(),
                a["status"].clone(),
                a["method"].clone(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [(json!(digest), json!("pending"), json!("DELETE"))]
    );
    let approve = ["approvals", "approve", "--digest", digest.as_str()];
    let approved = admin.ok(&approve);
    assert_eq!(approved["status"], "approved");
    assert_eq!(reason(&admin.fail(&approve)), "approval_not_pending");
    let unknown = "0".repeat(64);
    let error = admin.fail(&["approvals", "approve", "--digest", &unknown]);
    assert_eq!(reason(&error), "approval_not_found");
    let consumed = ctx(&admin)
        .policy
        .consume_approval(&digest, "agent-1", "gh", None, None)
        .unwrap();
    assert!(consumed);
    assert!(has(&events(&admin.state), "approval_grant"));
}

// ----------------------------------------------------------------- rotation

#[test]
fn rotation_start_activate_finish() {
    let (_tmp, admin) = setup();
    seed_project(&admin);
    put_secret(&admin, SYNTHETIC, "gh-token", "dev");
    create_http(&admin, "gh", &[]);
    admin.ok(&words("principal create --id agent-1"));
    let grant = admin.ok(&words("grant create --principal agent-1 --connection gh"));
    let grant_id = grant["id"].as_str().unwrap();

    let started = admin
        .cmd(&words("rotation start --secret-id gh-token --stdin"))
        .stdin(SYNTHETIC_V2.as_bytes())
        .ok();
    assert_eq!(
        (
            &started["version"],
            &started["status"],
            &started["previous_active"]
        ),
        (&json!(2), &json!("staged"), &json!(1))
    );
    {
        let ctx = ctx(&admin);
        assert_eq!(active_version(&ctx, "gh-token"), Some(json!(1)));
        assert_eq!(trusted_value(&ctx, "gh-token", None), SYNTHETIC.as_bytes());
        assert_eq!(
            trusted_value(&ctx, "gh-token", Some(2)),
            SYNTHETIC_V2.as_bytes()
        );
    }
    let unknown = admin
        .cmd(&words("rotation start --secret-id nope --stdin"))
        .stdin(b"x")
        .fail(1);
    assert_eq!(reason(&unknown), "secret_not_found");

    let activated = admin.ok(&words("rotation activate --connection gh --version 2"));
    assert_eq!(
        (
            &activated["version"],
            &activated["previous_active"],
            &activated["policy_version"]
        ),
        (&json!(2), &json!(1), &json!(2))
    );
    {
        let ctx = ctx(&admin);
        assert_eq!(active_version(&ctx, "gh-token"), Some(json!(2)));
        assert_eq!(statuses(&ctx, "gh-token"), ["retired", "active"]);
        let connection = ctx.policy.get_connection("gh").unwrap();
        assert_eq!(
            connection.secret_version.as_ref().unwrap().value(),
            &json!(2)
        );
        assert_eq!(connection.policy_version, PyInt::from(2));
        let value = ctx
            .vault
            .secret_for_trusted_use(
                &connection.secret_id,
                connection.secret_version_for_trusted_use().unwrap(),
            )
            .unwrap();
        assert_eq!(value.expose(), SYNTHETIC_V2.as_bytes());
        // Rotation is not widening.
        assert_eq!(ctx.policy.get_grant(grant_id).unwrap().status, "active");
        let decision = ctx
            .policy
            .evaluate("agent-1", "gh", &Action::http("GET", "/repos"), None)
            .unwrap();
        assert!(decision.allowed);
    }
    assert_eq!(
        fail_reason(&admin, "rotation activate --connection gh --version 9"),
        "secret_version_not_found"
    );

    let finished = admin.ok(&words("rotation finish --secret-id gh-token --version 1"));
    assert_eq!(finished["status"], "retired");
    assert_eq!(finished["provider_revocation_required"], true);
    assert!(finished["reminder"].as_str().unwrap().contains("provider"));
    assert_eq!(
        fail_reason(&admin, "rotation finish --secret-id gh-token --version 2"),
        "version_is_active"
    );
    let events = events(&admin.state);
    for event in ["rotation", "secret_retire", "connection_switch_credential"] {
        assert!(has(&events, event), "{event}");
    }
}

/// Issue #29: `rotation activate` pins the connection it switches. A later
/// `secret put` -- the update path the guide gives -- retires that version;
/// the pinned connection moves to the new active version instead of failing
/// with `credential_unavailable`, and the command reports it, while a
/// follower is rebound as before. `rotation activate` moves other connections
/// pinned to the version it retires the same way. `switch-credential
/// --follow-active` unpins a connection, but only while the secret has an
/// active version.
#[test]
fn rotation_then_secret_put_keeps_the_connection_working() {
    let (_tmp, admin) = setup();
    seed_project(&admin);
    put_secret(&admin, SYNTHETIC, "gh-token", "dev");
    create_http(&admin, "gh", &[]);
    create_http(&admin, "follower", &[]);
    create_http(&admin, "canary", &[]);
    admin
        .cmd(&words("rotation start --secret-id gh-token --stdin"))
        .stdin(SYNTHETIC_V2.as_bytes())
        .ok();
    admin.ok(&words("rotation activate --connection gh --version 2"));
    admin.ok(&words("rotation finish --secret-id gh-token --version 1"));
    let pinned = admin.ok(&words("connection show --id gh"));
    assert_eq!(
        (&pinned["secret_version"], &pinned["policy_version"]),
        (&json!(2), &json!(2))
    );

    const V3: &str = "synthetic-token-rotated-v3";
    let put = put_secret(&admin, V3, "gh-token", "dev");
    assert_eq!(put["moved_connections"], json!(["gh"]));
    {
        let ctx = ctx(&admin);
        assert_eq!(statuses(&ctx, "gh-token"), ["retired", "retired", "active"]);
        let connection = ctx.policy.get_connection("gh").unwrap();
        assert_eq!(
            connection.secret_version.as_ref().unwrap().value(),
            &json!(3)
        );
        assert_eq!(connection.policy_version, PyInt::from(3));
        let value = ctx
            .vault
            .secret_for_trusted_use(
                &connection.secret_id,
                connection.secret_version_for_trusted_use().unwrap(),
            )
            .unwrap();
        assert_eq!(value.expose(), V3.as_bytes());
        let followed = ctx
            .audit
            .tail(10)
            .unwrap()
            .into_iter()
            .rfind(|r| r["event"] == "connection_switch_credential")
            .unwrap();
        assert_eq!(
            (
                &followed["connection"],
                &followed["version"],
                &followed["state"]
            ),
            (&json!("gh"), &json!(3), &json!("followed_activation"))
        );
        let follower = ctx.policy.get_connection("follower").unwrap();
        assert!(follower.secret_version.is_none());
    }

    // `rotation activate` on one connection moves the others pinned to the
    // version it retires.
    let staged = admin
        .cmd(&words("rotation start --secret-id gh-token --stdin"))
        .stdin(b"synthetic-token-rotated-v3b")
        .ok();
    assert_eq!(staged["version"], json!(4));
    let activated = admin.ok(&words("rotation activate --connection canary --version 4"));
    assert_eq!(activated["moved_connections"], json!(["gh"]));
    let gh = admin.ok(&words("connection show --id gh"));
    assert_eq!(gh["secret_version"], json!(4));
    let reactivated = admin.ok(&words("rotation activate --connection canary --version 4"));
    assert!(
        reactivated.get("moved_connections").is_none(),
        "{reactivated}"
    );

    let unpinned = admin.ok(&words(
        "connection switch-credential --id gh --follow-active",
    ));
    assert_eq!(unpinned["secret_version"], Value::Null);
    const V4: &str = "synthetic-token-rotated-v4";
    let put = put_secret(&admin, V4, "gh-token", "dev");
    assert_eq!(put["moved_connections"], json!(["canary"]));
    {
        let ctx = ctx(&admin);
        let connection = ctx.policy.get_connection("gh").unwrap();
        assert!(connection.secret_version.is_none());
        let value = ctx
            .vault
            .secret_for_trusted_use(
                &connection.secret_id,
                connection.secret_version_for_trusted_use().unwrap(),
            )
            .unwrap();
        assert_eq!(value.expose(), V4.as_bytes());
    }
    // Exactly one of --version and --follow-active.
    admin
        .cmd(&words("connection switch-credential --id gh"))
        .fail(2);
    admin
        .cmd(&words(
            "connection switch-credential --id gh --version 5 --follow-active",
        ))
        .fail(2);
    // With no active version there is nothing to follow.
    admin.ok(&words("connection switch-credential --id gh --version 5"));
    ctx(&admin)
        .vault
        .set_version_status("gh-token", &PyInt::from(5), "retired")
        .unwrap();
    assert_eq!(
        fail_reason(
            &admin,
            "connection switch-credential --id gh --follow-active"
        ),
        "secret_version_unusable"
    );
}

// ---------------------------------------------------------- backup / restore

#[test]
fn backup_restore_and_restore_ack() {
    let (tmp, admin) = setup();
    seed_project(&admin);
    put_secret(&admin, SYNTHETIC, "gh-token", "dev");
    create_http(&admin, "gh", &[]);
    admin.ok(&words("principal create --id agent-1"));
    let create = words("grant create --principal agent-1 --connection gh");
    let grant = admin.ok(&create);
    let grant_id = grant["id"].as_str().unwrap();
    let archive = tmp.path().join("backup.json");
    let archive_arg = archive.to_str().unwrap();
    let backup = admin.ok(&["backup", "--out", archive_arg]);
    assert_eq!(backup["manifest"]["format"], "zeropw-backup-v1");
    assert!(archive.exists());
    assert!(
        !std::fs::read_to_string(&archive)
            .unwrap()
            .contains(SYNTHETIC)
    );
    let mode = std::fs::metadata(&archive).unwrap().permissions().mode();
    assert_eq!(mode & 0o077, 0);

    admin.ok(&["grant", "revoke", "--id", grant_id]);
    let restored = admin.ok(&["restore", "--in", archive_arg]);
    assert_eq!(restored["restore_pending"], true);
    assert_eq!(restored["reapplied"]["grants"], 1);
    {
        let ctx = ctx(&admin);
        assert!(ctx.policy.restore_pending().unwrap());
        let decision = ctx
            .policy
            .evaluate("agent-1", "gh", &Action::http("GET", "/repos"), None)
            .unwrap();
        assert_eq!(decision.reason, "restore_pending");
        // The post-backup revocation stays.
        assert_eq!(ctx.policy.get_grant(grant_id).unwrap().status, "revoked");
    }
    let nope = tmp.path().join("nope.json");
    let error = admin.fail(&["restore", "--in", nope.to_str().unwrap()]);
    assert_eq!(reason(&error), "backup_malformed");

    let wrong = admin
        .cmd(&["restore-ack"])
        .env(ADMIN_ENV, "wrong-passphrase")
        .fail(1);
    assert_eq!(reason(&wrong), "admin_reauth_failed");
    assert!(ctx(&admin).policy.restore_pending().unwrap());
    let acked = admin.ok(&["restore-ack"]);
    assert_eq!(
        (
            &acked["restore_pending"],
            &acked["active_grants"],
            &acked["active_grant_ids"]
        ),
        (&json!(false), &json!(0), &json!([]))
    );
    assert_eq!(acked["stopped"], false);
    assert_eq!(
        evaluate(&admin, "GET", "/repos", None).reason,
        "grant_revoked"
    );
    let fresh = admin.ok(&create);
    assert!(evaluate(&admin, "GET", "/repos", fresh["id"].as_str()).allowed);
    let events = events(&admin.state);
    for event in ["backup", "restore", "restore_ack", "auth_failed"] {
        assert!(has(&events, event), "{event}");
    }
}

#[test]
fn recover_rotates_kms_and_revokes_grants() {
    let (_tmp, admin) = setup();
    seed_project(&admin);
    put_secret(&admin, SYNTHETIC, "gh-token", "dev");
    create_http(&admin, "gh", &[]);
    admin.ok(&words("principal create --id agent-1"));
    let grant = admin.ok(&words("grant create --principal agent-1 --connection gh"));
    let grant_id = grant["id"].as_str().unwrap();
    let wrong = admin
        .cmd(&["recover"])
        .env(RECOVERY_ENV, "wrong-recovery-1")
        .fail(1);
    assert_eq!(reason(&wrong), "recovery_passphrase_invalid");
    let before = ctx(&admin).policy.get_grant(grant_id).unwrap();
    assert_eq!(before.status, "active");
    let recovered = admin.ok(&["recover"]);
    assert_ne!(recovered["kms_key_id"], "local-dev-kms-1");
    assert_eq!(recovered["grants_revoked"], 1);
    {
        let ctx = ctx(&admin);
        assert_eq!(json!(ctx.kms.key_id()), recovered["kms_key_id"]);
        assert_eq!(ctx.policy.get_grant(grant_id).unwrap().status, "revoked");
    }
    let revealed = admin.ok(&words("secret reveal --id gh-token"));
    assert_eq!(revealed["value"], SYNTHETIC);
    let events = events(&admin.state);
    assert!(has(&events, "recover"));
    assert!(has(&events, "auth_failed"));
}
