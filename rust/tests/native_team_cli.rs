//! Native port of `tests/test_admin_cli.py::TeamCliTestCase`: the `team`
//! commands and shared-environment awareness of `connection`/`secret` in the
//! native `zeropw-admin` binary (docs/team-sync.md section 12): commit/fact
//! output shape, value-free CLI output (json and yaml), and cross-process
//! pickup (the CLI as its own process, a second live `TeamSync` over the same
//! state directory standing in for a running `serve`).
//!
//! Every CLI call is a `zeropw-admin --state-dir ...` subprocess; what the
//! Python test did in-process (`share_environment`, `CommitStore`, the second
//! `TeamSync`) uses the library directly. Dropping each [`Admin`] performs
//! the original tearDown sweep: no output except `secret reveal` stdout may
//! carry a synthetic value.
mod native_e2e;

use std::sync::Arc;

use native_e2e::{ADMIN_PASSPHRASE, Admin};
use serde_json::{Value, json};
use zeropw::context::{Config, Context};
use zeropw::team::commit::{self, CommitStore};
use zeropw::team::identity::{DeviceKey, DeviceRecord};
use zeropw::team::membership;
use zeropw::team::sync::TeamSync;
use zeropw::team::transport::{InProcessTransport, MembershipCheck};

const SYNTHETIC: &str = "synthetic-token-0123456789";
const SYNTHETIC_V2: &str = "synthetic-token-rotated-v2";

struct Case {
    _tmp: tempfile::TempDir,
    admin: Admin,
}

impl Case {
    fn new() -> Case {
        let tmp = tempfile::TempDir::new().unwrap();
        let admin = Admin::new(tmp.path());
        Case { _tmp: tmp, admin }
    }

    fn ok(&self, args: &[&str]) -> Value {
        self.admin.ok(args)
    }

    fn fail(&self, args: &[&str]) -> Value {
        self.admin.fail(args)
    }

    fn ctx(&self) -> Context {
        Context::open(
            &self.admin.state,
            Config::default(),
            zeropw::clock::system(),
        )
        .unwrap()
    }

    fn seed_project(&self) {
        self.ok(&["init"]);
        self.ok(&["project", "create", "demo"]);
    }

    fn put_secret(&self, value: &str, secret_id: &str) -> Value {
        self.admin
            .cmd(&[
                "secret",
                "put",
                "--id",
                secret_id,
                "--kind",
                "api_key",
                "--project",
                "demo",
                "--environment",
                "dev",
                "--stdin",
            ])
            .stdin(format!("{value}\n").as_bytes())
            .ok()
    }

    fn create_http(&self) -> Value {
        self.ok(&[
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

    /// `_share`: a project with one secret and one connection, shared by the
    /// library (`team_membership.share_environment`); returns the env id.
    fn share(&self) -> String {
        self.seed_project();
        self.put_secret(SYNTHETIC, "gh-token");
        self.create_http();
        let shared = membership::share_environment(
            &self.ctx(),
            None,
            "demo",
            "dev",
            "owner",
            ADMIN_PASSPHRASE,
        )
        .unwrap();
        shared["env_id"].as_str().unwrap().to_owned()
    }
}

fn assert_absent(blob: &str, forbidden: &[&str]) {
    for needle in forbidden {
        assert!(!blob.contains(needle), "{needle:?} in {blob}");
    }
}

/// Number of entries of a JSON array or object.
fn count(value: &Value) -> usize {
    match value {
        Value::Array(items) => items.len(),
        Value::Object(map) => map.len(),
        other => panic!("not a collection: {other}"),
    }
}

#[test]
fn team_init_refuses_second_time() {
    let case = Case::new();
    case.ok(&["init"]);
    let payload = case.ok(&["team", "init"]);
    assert!(payload.get("fingerprint").is_some(), "{payload}");
    case.fail(&["team", "init"]);
}

/// H1 regression through the CLI: `team share` output surfaces a connection
/// left behind because its secret was not carried over, instead of silently
/// disabling it.
#[test]
fn team_share_cli_reports_not_shared_connection() {
    let case = Case::new();
    case.seed_project();
    case.put_secret(SYNTHETIC, "gh-token"); // active
    case.create_http(); // "gh", references gh-token: the happy path
    case.put_secret("synthetic-dead-token-value", "dead-token");
    case.ok(&[
        "connection",
        "create-http",
        "--id",
        "dead",
        "--project",
        "demo",
        "--environment",
        "dev",
        "--service",
        "deadsvc",
        "--secret-id",
        "dead-token",
        "--target",
        "https://dead.example.com",
        "--auth",
        "bearer",
    ]);
    // No active/staged version left.
    case.ok(&["secret", "revoke", "--id", "dead-token", "--version", "1"]);

    let payload = case.ok(&["team", "share", "--project", "demo", "--environment", "dev"]);
    assert_eq!(
        payload["not_shared"],
        json!([{"connection": "dead", "reason": "secret_not_shared"}])
    );
    let still_local = case.ok(&["connection", "show", "--id", "dead"]);
    assert_eq!(still_local["status"], "active");
    let raw = case
        .ctx()
        .state
        .read_json(zeropw::policy::CONNECTIONS, json!({}))
        .unwrap();
    assert!(raw["dead"].get("shared_env").is_none(), "{}", raw["dead"]);
    assert_eq!(raw["gh"]["shared_env"], payload["env_id"]);
}

#[test]
fn team_share_status_members_log_show() {
    let case = Case::new();
    let env_id = case.share();
    let status = case.ok(&["team", "status", "--env", "demo/dev"]);
    assert_eq!(status["env_id"], env_id.as_str());
    assert!(status["commits_folded"].as_i64().unwrap() >= 1, "{status}");
    assert_eq!(status["rejected_commits"], 0);

    let members = case.ok(&["team", "members", "--env", "demo/dev"]);
    let members = members["members"].as_array().unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0]["owner"], true);

    let log = case.ok(&["team", "log", "--env", "demo/dev"]);
    assert!(
        log["log"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["ops"]
                .as_array()
                .unwrap()
                .contains(&json!("env.init"))),
        "{log}"
    );

    let show = case.ok(&["team", "show", "--env", "demo/dev"]);
    assert_eq!(show["env_id"], env_id.as_str());
    assert_absent(
        &show.to_string(),
        &["ciphertext", "nonce", "\"sig\"", "wraps", SYNTHETIC],
    );
}

#[test]
fn team_show_yaml_has_no_ciphertext_or_wraps() {
    let case = Case::new();
    case.share();
    let (code, out, err) = case
        .admin
        .cmd(&["team", "show", "--env", "demo/dev", "--format", "yaml"])
        .run();
    assert_eq!(code, 0, "{err}");
    assert_eq!(err, "");
    assert_absent(&out, &["ciphertext", "nonce", "sig:", "wraps", SYNTHETIC]);
    assert!(out.contains("env_id:"), "{out}");
    // NOT valid JSON: proves this really is the YAML writer, not JSON under
    // another name.
    assert!(serde_json::from_str::<Value>(&out).is_err(), "{out}");
}

#[test]
fn team_invite_warns_and_join_rejects_malformed_invite() {
    let case = Case::new();
    case.share();
    let payload = case.ok(&[
        "team", "invite", "--env", "demo/dev", "--role", "user", "--name", "bob",
    ]);
    assert!(payload.get("warning").is_some(), "{payload}");
    assert!(payload.get("invite").is_some(), "{payload}");
    let error = case.fail(&["team", "join", "not-a-real-invite-string"]);
    assert_eq!(error["reason"], "invite_malformed");
}

#[test]
fn team_diff_between_two_commits() {
    let case = Case::new();
    let env_id = case.share();
    let log = case.ok(&["team", "log", "--env", "demo/dev"]);
    assert!(!log["log"].as_array().unwrap().is_empty());
    let ctx = case.ctx();
    let store = CommitStore::new(ctx.state, &env_id);
    let commits = commit::sort_total_order(store.all_commits().unwrap()).unwrap();
    let left = commits.first().unwrap().hash().unwrap()[..12].to_owned();
    let right = commits.last().unwrap().hash().unwrap()[..12].to_owned();
    let diff = case.ok(&["team", "diff", "--env", "demo/dev", &left, &right]);
    assert!(diff.get("left").is_some(), "{diff}");
    assert!(diff.get("right").is_some(), "{diff}");
    assert_absent(
        &diff.to_string(),
        &["ciphertext", "nonce", "\"sig\"", SYNTHETIC],
    );
}

#[test]
fn team_peers_add_and_list() {
    let case = Case::new();
    case.share();
    let fake_fp = "b".repeat(26);
    let added = case.ok(&[
        "team",
        "peers",
        "--env",
        "demo/dev",
        "--add",
        "127.0.0.1:9999",
        "--device",
        &fake_fp,
    ]);
    let peers = &added["peers"][fake_fp.as_str()];
    let listed = match peers {
        Value::Array(items) => items.contains(&json!("127.0.0.1:9999")),
        Value::Object(map) => map.contains_key("127.0.0.1:9999"),
        Value::String(text) => text.contains("127.0.0.1:9999"),
        _ => false,
    };
    assert!(listed, "{added}");
}

#[test]
fn team_compact_no_op_when_too_young() {
    let case = Case::new();
    case.share();
    let payload = case.ok(&["team", "compact", "--env", "demo/dev"]);
    assert_eq!(payload["removed"], 0);
}

#[test]
fn team_set_role_and_transfer_owner_are_commits() {
    let case = Case::new();
    case.share();
    let fake_fp = "c".repeat(26);
    let role_payload = case.ok(&[
        "team", "set-role", "--env", "demo/dev", "--device", &fake_fp, "--role", "admin",
    ]);
    assert!(role_payload.get("commit").is_some(), "{role_payload}");
    let transfer_payload = case.ok(&[
        "team",
        "transfer-owner",
        "--env",
        "demo/dev",
        "--device",
        &fake_fp,
    ]);
    assert!(
        transfer_payload.get("commit").is_some(),
        "{transfer_payload}"
    );
}

#[test]
fn connection_create_secret_put_are_commits_with_propagated_to() {
    let case = Case::new();
    case.share();
    let create_payload = case.ok(&[
        "connection",
        "create-http",
        "--id",
        "gh2",
        "--project",
        "demo",
        "--environment",
        "dev",
        "--service",
        "svc2",
        "--secret-id",
        "gh-token",
        "--target",
        "https://api.github.com",
        "--auth",
        "bearer",
    ]);
    assert!(create_payload.get("commit").is_some(), "{create_payload}");
    // This one-shot CLI holds no live session.
    assert_eq!(create_payload["propagated_to"], 0);
    let put_payload = case.put_secret(SYNTHETIC_V2, "gh-token");
    assert!(put_payload.get("commit").is_some(), "{put_payload}");
    // A shared secret is keyed by its version id, not a local int.
    assert!(put_payload.get("version").is_none(), "{put_payload}");
    assert!(put_payload.get("version_id").is_some(), "{put_payload}");
}

#[test]
fn connection_disable_and_secret_revoke_are_facts() {
    let case = Case::new();
    case.share();
    let disable_payload = case.ok(&["connection", "disable", "--id", "gh"]);
    assert!(disable_payload.get("fact").is_some(), "{disable_payload}");
    assert!(disable_payload.get("commit").is_none(), "{disable_payload}");
    let revoke_payload = case.ok(&["secret", "revoke", "--id", "gh-token", "--version", "1"]);
    assert!(revoke_payload.get("fact").is_some(), "{revoke_payload}");
    assert!(revoke_payload.get("commit").is_none(), "{revoke_payload}");
}

/// Stops the stand-in `serve` sync at the end of the test (`addCleanup`).
struct StopOnDrop(Arc<TeamSync>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.stop();
    }
}

/// docs/team-sync.md section 12: the admin CLI is a separate process from
/// `serve`. A second, independent `Context`/`TeamSync` over the SAME state
/// directory stands in for a separately-running `serve --team-listen`; on
/// its next `poll()` it must pick up both a commit (`secret put`) and a fact
/// (`connection disable`) the CLI wrote directly.
#[test]
fn cli_commits_and_facts_visible_on_second_node_after_poll() {
    let case = Case::new();
    let env_id = case.share();
    let serve_ctx = Arc::new(case.ctx());
    let device = DeviceKey::load_or_create(serve_ctx.state, serve_ctx.kms).unwrap();
    let nobody: MembershipCheck = Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None });
    let transport = Arc::new(InProcessTransport::new(device.clone(), nobody));
    let serve_sync = TeamSync::new(serve_ctx, transport, device);
    let serve_sync = StopOnDrop(serve_sync);
    serve_sync.0.register_env(&env_id).unwrap();

    let put_payload = case.put_secret(SYNTHETIC_V2, "gh-token");
    assert!(put_payload.get("commit").is_some(), "{put_payload}");
    let update_payload = case.ok(&[
        "connection",
        "update",
        "--id",
        "gh",
        "--methods",
        "GET,POST",
    ]);
    assert!(update_payload.get("commit").is_some(), "{update_payload}");

    serve_sync.0.poll().unwrap();
    let doc = serve_sync.0.document(&env_id).unwrap();
    assert_eq!(count(&doc["secrets"]["gh-token"]["versions"]), 2, "{doc}");
    let mut methods: Vec<&str> = doc["connections"]["gh"]["http_scope"]["methods"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m.as_str().unwrap())
        .collect();
    methods.sort_unstable();
    assert_eq!(methods, ["GET", "POST"]);

    let disable_payload = case.ok(&["connection", "disable", "--id", "gh"]);
    assert!(disable_payload.get("fact").is_some(), "{disable_payload}");
    serve_sync.0.poll().unwrap();
    // A bare fact-only disable (no accompanying commit) retroactively skips
    // "gh"'s own connection.create in every full refold from now on
    // (docs/team-sync.md section 5.3's "never let a disabled id (re)exist"
    // rule applied from the very start of the fold), so it is entirely ABSENT
    // from the raw folded document -- not present with status "disabled". The
    // derived local view is where "disabled" actually shows (the fold's
    // vanished-connection handling retains a disabled marker there).
    let doc = serve_sync.0.document(&env_id).unwrap();
    assert!(doc["connections"].get("gh").is_none(), "{doc}");
    assert_eq!(
        case.ok(&["connection", "show", "--id", "gh"])["status"],
        "disabled"
    );
}
