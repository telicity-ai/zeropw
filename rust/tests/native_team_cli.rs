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
use zeropw::pyint::PyInt;
use zeropw::team::commit::{self, CommitStore};
use zeropw::team::identity::{DeviceKey, DeviceRecord};
use zeropw::team::membership;
use zeropw::team::sync::TeamSync;
use zeropw::team::transport::{InProcessTransport, MembershipCheck, Transport};

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

    /// A shared environment whose one connection, `box`, is an SSH connection
    /// made without an ssh (`cli: null`, as the desktop app made them before
    /// it sent one); returns the env id.
    fn share_ssh(&self) -> String {
        self.seed_project();
        let key = zeropw::sshwire::generate_ed25519_private_key("team-box");
        let pem = key.to_openssh_private_key();
        self.admin.add_needle(pem.lines().nth(1).unwrap());
        self.admin
            .cmd(&[
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
            ])
            .stdin(pem.as_bytes())
            .ok();
        let host_key = zeropw::sshwire::generate_ed25519_private_key("host")
            .public
            .to_authorized_key("host")
            .unwrap();
        let created = self.ok(&[
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
            &host_key,
        ]);
        assert!(created["cli"].is_null(), "{created}");
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

/// A second device that joined the shared `demo/dev` as `role`, with its own
/// state directory and CLI; its local copy is `shared/dev`.
struct Member {
    admin: Admin,
    fp: String,
    _tmp: tempfile::TempDir,
}

fn join_member(case: &Case, env_id: &str, role: &str, address: &str) -> Member {
    let owner_ctx = Arc::new(case.ctx());
    let owner_device = DeviceKey::load_or_create(owner_ctx.state, owner_ctx.kms).unwrap();
    let nobody: MembershipCheck = Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None });
    let transport = Arc::new(InProcessTransport::new(owner_device.clone(), nobody));
    let owner_sync = StopOnDrop(TeamSync::new(owner_ctx.clone(), transport, owner_device));
    owner_sync.0.start(Some(address)).unwrap();
    let invite =
        membership::create_invite(&owner_ctx, env_id, role, "dave", 3600, &[address.into()])
            .unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let admin = Admin::new(tmp.path());
    admin.ok(&["init"]);
    let ctx =
        Arc::new(Context::open(&admin.state, Config::default(), zeropw::clock::system()).unwrap());
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let fp = device.fingerprint().unwrap();
    let nobody: MembershipCheck = Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None });
    let transport = Arc::new(InProcessTransport::new(device.clone(), nobody));
    let sync = StopOnDrop(TeamSync::new(ctx.clone(), transport.clone(), device));
    sync.0.start(None).unwrap();
    membership::join(
        &ctx,
        &invite,
        transport.as_ref() as &dyn Transport,
        &sync.0,
        Some("shared"),
        Some("dev"),
        10.0,
    )
    .unwrap();
    Member {
        admin,
        fp,
        _tmp: tmp,
    }
}

fn member_entry(admin: &Admin, env: &str, fp: &str) -> Value {
    let members = admin.ok(&["team", "members", "--env", env]);
    members["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["fingerprint"] == fp)
        .cloned()
        .unwrap_or_else(|| panic!("{fp} not in {members}"))
}

/// Issue #30: a change the fold would refuse its author fails before it is
/// stored, instead of reporting a commit no node applies.
#[test]
fn team_set_role_and_transfer_owner_are_commits() {
    let case = Case::new();
    let env_id = case.share();
    let member = join_member(&case, &env_id, "user", "native-cli-set-role:47301");
    let owner_fp = DeviceKey::load_or_create(case.ctx().state, case.ctx().kms)
        .unwrap()
        .fingerprint()
        .unwrap();
    let store = CommitStore::new(case.ctx().state, &env_id);
    let before = store.vector().unwrap();
    let fake_fp = "c".repeat(26);
    let refused = [
        (
            vec![
                "team", "set-role", "--env", "demo/dev", "--device", &fake_fp, "--role", "admin",
            ],
            "member_not_found",
        ),
        (
            vec![
                "team",
                "transfer-owner",
                "--env",
                "demo/dev",
                "--device",
                &fake_fp,
            ],
            "member_not_found",
        ),
        (
            vec![
                "team", "set-role", "--env", "demo/dev", "--device", &owner_fp, "--role", "user",
            ],
            "cannot_change_owner_role",
        ),
    ];
    for (args, reason) in refused {
        assert_eq!(case.fail(&args)["reason"], reason, "{args:?}");
    }
    assert_eq!(store.vector().unwrap(), before);
    let role_payload = case.ok(&[
        "team", "set-role", "--env", "demo/dev", "--device", &member.fp, "--role", "admin",
    ]);
    assert!(role_payload.get("commit").is_some(), "{role_payload}");
    assert_eq!(
        member_entry(&case.admin, "demo/dev", &member.fp)["role"],
        "admin"
    );
    let transfer_payload = case.ok(&[
        "team",
        "transfer-owner",
        "--env",
        "demo/dev",
        "--device",
        &member.fp,
    ]);
    assert!(
        transfer_payload.get("commit").is_some(),
        "{transfer_payload}"
    );
    assert_eq!(
        member_entry(&case.admin, "demo/dev", &member.fp)["owner"],
        true
    );
    assert_eq!(
        member_entry(&case.admin, "demo/dev", &owner_fp)["owner"],
        false
    );
    // No longer the owner, this device cannot hand ownership on again.
    let refused = case.fail(&[
        "team",
        "transfer-owner",
        "--env",
        "demo/dev",
        "--device",
        &member.fp,
    ]);
    assert_eq!(refused["reason"], "not_owner");
}

/// Issue #30: on a device that joined as `user`, every editing command fails
/// with `not_admin` and stores no commit; before, each reported success (or
/// failed only after storing its commit) while every node skipped it. The
/// user can still remove itself.
#[test]
fn user_device_editing_commands_fail_before_any_commit() {
    let case = Case::new();
    let env_id = case.share();
    let member = join_member(&case, &env_id, "user", "native-cli-user-role:47302");
    let user = &member.admin;
    let ctx = Context::open(&user.state, Config::default(), zeropw::clock::system()).unwrap();
    let store = CommitStore::new(ctx.state, &env_id);
    let before = store.vector().unwrap();
    let with_stdin = |args: &[&str]| {
        user.cmd(args)
            .stdin(format!("{SYNTHETIC_V2}\n").as_bytes())
            .fail(1)
    };
    let refusals = [
        with_stdin(&[
            "secret",
            "put",
            "--id",
            "gh-token",
            "--kind",
            "api_key",
            "--project",
            "shared",
            "--environment",
            "dev",
            "--stdin",
        ]),
        with_stdin(&["rotation", "start", "--secret-id", "gh-token", "--stdin"]),
        user.fail(&["connection", "update", "--id", "gh", "--methods", "GET"]),
        user.fail(&[
            "connection",
            "switch-credential",
            "--id",
            "gh",
            "--version",
            "1",
        ]),
        user.fail(&[
            "team",
            "set-role",
            "--env",
            "shared/dev",
            "--device",
            &member.fp,
            "--role",
            "admin",
        ]),
        user.fail(&[
            "connection",
            "create-http",
            "--id",
            "dave-conn",
            "--project",
            "shared",
            "--environment",
            "dev",
            "--service",
            "svc-dave",
            "--secret-id",
            "gh-token",
            "--target",
            "https://api.github.com",
            "--auth",
            "bearer",
        ]),
    ];
    for error in refusals {
        assert_eq!(error["reason"], "not_admin", "{error}");
    }
    assert_eq!(store.vector().unwrap(), before);
    // A member may still remove itself: one `member.remove` commit, then its fact.
    user.ok(&[
        "team",
        "remove",
        "--env",
        "shared/dev",
        "--device",
        &member.fp,
    ]);
    let own: Vec<_> = store
        .all_commits()
        .unwrap()
        .into_iter()
        .filter(|c| c.author == member.fp)
        .collect();
    assert_eq!(own.len(), 1, "{own:?}");
    assert_eq!(
        own[0].ops,
        vec![json!({"op":"member.remove","fingerprint":member.fp})]
    );
    assert_eq!(
        member_entry(user, "shared/dev", &member.fp)["status"],
        "removed"
    );
}

/// F8 repair in a shared environment: `connection update --cli-program` is a
/// `connection.update` commit carrying `cli`, the field every release since
/// v0.1.0 folds. Another admin's node derives the connection with its ssh;
/// its own grants on the connection go stale, and it refuses a second fill.
#[test]
fn shared_ssh_connection_gets_its_ssh_on_every_node() {
    let case = Case::new();
    let env_id = case.share_ssh();
    let config = Config {
        team_sync_interval_seconds: Some(0.1),
        team_dial_backoff: (0.05, 0.3),
        ..Config::default()
    };
    let address = "native-cli-ssh-fill:47304";
    let owner_ctx = Arc::new(
        Context::open(&case.admin.state, config.clone(), zeropw::clock::system()).unwrap(),
    );
    let owner_device = DeviceKey::load_or_create(owner_ctx.state, owner_ctx.kms).unwrap();
    let nobody: MembershipCheck = Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None });
    let transport = Arc::new(InProcessTransport::new(owner_device.clone(), nobody));
    let owner_sync = StopOnDrop(TeamSync::new(owner_ctx.clone(), transport, owner_device));
    owner_sync.0.start(Some(address)).unwrap();
    let invite = membership::create_invite(
        &owner_ctx,
        &env_id,
        "admin",
        "dave",
        3600,
        &[address.into()],
    )
    .unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let member = Admin::new(tmp.path());
    member.ok(&["init"]);
    let member_ctx =
        Arc::new(Context::open(&member.state, config, zeropw::clock::system()).unwrap());
    let device = DeviceKey::load_or_create(member_ctx.state, member_ctx.kms).unwrap();
    let nobody: MembershipCheck = Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None });
    let transport = Arc::new(InProcessTransport::new(device.clone(), nobody));
    let member_sync = StopOnDrop(TeamSync::new(member_ctx.clone(), transport.clone(), device));
    member_sync.0.start(None).unwrap();
    membership::join(
        &member_ctx,
        &invite,
        transport.as_ref() as &dyn Transport,
        &member_sync.0,
        Some("shared"),
        Some("dev"),
        10.0,
    )
    .unwrap();
    member.ok(&["principal", "create", "--id", "agent-1"]);
    let grant = member.ok(&[
        "grant",
        "create",
        "--principal",
        "agent-1",
        "--connection",
        "box",
    ]);
    let grant_id = grant["id"].as_str().unwrap();
    let before = member_ctx.policy.get_connection("box").unwrap();
    assert!(before.cli.is_none());

    let filled = case.ok(&[
        "connection",
        "update",
        "--id",
        "box",
        "--cli-program",
        "/usr/bin/ssh",
    ]);
    assert!(filled.get("commit").is_some(), "{filled}");
    assert_eq!(filled["propagated_to"], 0);
    assert_eq!(filled["cli"]["program"], "/usr/bin/ssh");
    let store = CommitStore::new(owner_ctx.state, &env_id);
    let last = store
        .all_commits()
        .unwrap()
        .into_iter()
        .max_by_key(|c| c.author_seq.clone())
        .unwrap();
    assert_eq!(
        last.ops,
        vec![json!({"op": "connection.update", "id": "box",
                    "cli": {"program": "/usr/bin/ssh", "kind": "ssh",
                            "base_url_env": "ZEROPW_API_BASE_URL", "extra_env": {}}})]
    );

    // The serve stand-in picks the CLI's commit up and sends it on.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let after = loop {
        let c = member_ctx.policy.get_connection("box").unwrap();
        if c.cli.is_some() {
            break c;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the fill did not reach the member"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    assert_eq!(after.cli.as_ref().unwrap().program, "/usr/bin/ssh");
    assert_eq!(after.cli.as_ref().unwrap().kind, "ssh");
    assert_eq!(after.ssh_target, before.ssh_target);
    assert_eq!(after.policy_version, &before.policy_version + 1);
    assert_eq!(
        member_ctx.policy.get_grant(grant_id).unwrap().status,
        "stale"
    );
    let refused = member.fail(&[
        "connection",
        "update",
        "--id",
        "box",
        "--cli-program",
        "/bin/false",
    ]);
    assert_eq!(refused["reason"], "cli_already_set");
    assert_eq!(
        member_ctx.policy.get_connection("box").unwrap().cli,
        after.cli
    );
}

/// A device that joined as `user` cannot fill a shared SSH connection's ssh:
/// `not_admin`, and no commit is stored.
#[test]
fn user_device_cannot_give_a_shared_ssh_connection_its_ssh() {
    let case = Case::new();
    let env_id = case.share_ssh();
    let member = join_member(&case, &env_id, "user", "native-cli-user-ssh:47305");
    let ctx = Context::open(
        &member.admin.state,
        Config::default(),
        zeropw::clock::system(),
    )
    .unwrap();
    let store = CommitStore::new(ctx.state, &env_id);
    let before = store.vector().unwrap();
    let refused = member.admin.fail(&[
        "connection",
        "update",
        "--id",
        "box",
        "--cli-program",
        "/usr/bin/ssh",
    ]);
    assert_eq!(refused["reason"], "not_admin", "{refused}");
    assert_eq!(store.vector().unwrap(), before);
    assert!(ctx.policy.get_connection("box").unwrap().cli.is_none());
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

/// Issue #29, shared environment: `rotation activate` pins the connection.
/// A later shared `secret put` retires that version and pins the connection
/// to the new one in the same commit, so it keeps working on every node.
/// Retiring the active version or a pinned one is refused as it is locally,
/// and `switch-credential --follow-active` commits a follow-active reference.
#[test]
fn shared_rotation_then_secret_put_keeps_the_connection_working() {
    let case = Case::new();
    let env_id = case.share();
    // A second shared connection pinned to the active version.
    case.ok(&[
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
    case.ok(&[
        "connection",
        "switch-credential",
        "--id",
        "gh2",
        "--version",
        "1",
    ]);
    let staged = case
        .admin
        .cmd(&["rotation", "start", "--secret-id", "gh-token", "--stdin"])
        .stdin(SYNTHETIC_V2.as_bytes())
        .ok();
    let version = staged["version"].to_string();
    let activated = case.ok(&[
        "rotation",
        "activate",
        "--connection",
        "gh",
        "--version",
        &version,
    ]);
    assert_eq!(activated["moved_connections"], json!(["gh2"]));
    assert_eq!(
        case.ok(&["connection", "show", "--id", "gh"])["secret_version"].to_string(),
        version
    );
    assert_eq!(
        case.ok(&["connection", "show", "--id", "gh2"])["secret_version"].to_string(),
        version
    );
    // One commit: pin the connection, activate, move the other pin.
    let store = CommitStore::new(case.ctx().state, &env_id);
    let last = commit::sort_total_order(store.all_commits().unwrap())
        .unwrap()
        .pop()
        .unwrap();
    let ops: Vec<(&str, &str)> = last
        .ops
        .iter()
        .map(|op| {
            (
                op["op"].as_str().unwrap(),
                op.get("id").and_then(Value::as_str).unwrap_or(""),
            )
        })
        .collect();
    assert_eq!(
        ops,
        [
            ("connection.switch_credential", "gh"),
            ("secret.activate", ""),
            ("connection.switch_credential", "gh2"),
        ]
    );
    // gh2 follows the active version from here on, as gh's later steps test.
    case.ok(&[
        "connection",
        "switch-credential",
        "--id",
        "gh2",
        "--follow-active",
    ]);
    let active = case.fail(&[
        "rotation",
        "finish",
        "--secret-id",
        "gh-token",
        "--version",
        &version,
    ]);
    assert_eq!(active["reason"], "version_is_active");

    let put = case.put_secret("synthetic-token-rotated-v3", "gh-token");
    assert_eq!(put["moved_connections"], json!(["gh"]));
    let store = CommitStore::new(case.ctx().state, &env_id);
    let last = commit::sort_total_order(store.all_commits().unwrap())
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        last.ops,
        vec![
            json!({"op":"secret.activate","secret_id":"gh-token","version_id":put["version_id"]}),
            json!({"op":"connection.switch_credential","id":"gh","secret_id":"gh-token","secret_version":put["version_id"]}),
        ]
    );
    let ctx = case.ctx();
    let connection = ctx.policy.get_connection("gh").unwrap();
    let value = ctx
        .vault
        .secret_for_trusted_use(
            &connection.secret_id,
            connection.secret_version_for_trusted_use().unwrap(),
        )
        .unwrap();
    assert_eq!(value.expose(), b"synthetic-token-rotated-v3");

    // A version a connection is pinned to cannot be retired.
    let next = case
        .admin
        .cmd(&["rotation", "start", "--secret-id", "gh-token", "--stdin"])
        .stdin(b"synthetic-token-rotated-v4")
        .ok();
    let next = next["version"].to_string();
    case.ok(&[
        "connection",
        "switch-credential",
        "--id",
        "gh",
        "--version",
        &next,
    ]);
    let in_use = case.fail(&["secret", "retire", "--id", "gh-token", "--version", &next]);
    assert_eq!(in_use["reason"], "version_in_use");
    let unpinned = case.ok(&[
        "connection",
        "switch-credential",
        "--id",
        "gh",
        "--follow-active",
    ]);
    assert!(unpinned.get("commit").is_some(), "{unpinned}");
    assert_eq!(unpinned["secret_version"], Value::Null);
    let last = commit::sort_total_order(store.all_commits().unwrap())
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        last.ops,
        vec![
            json!({"op":"connection.switch_credential","id":"gh","secret_id":"gh-token","secret_version":null})
        ]
    );
}

/// Issue #33: in a shared environment a new active version re-binds the
/// connections that follow it, as a local `secret put` does: the grant is
/// re-evaluated in place to the new credential version and the policy
/// version rises, which ends handles issued before.
#[test]
fn shared_secret_put_rebinds_following_connections() {
    let case = Case::new();
    let env_id = case.share();
    case.ok(&["principal", "create", "--id", "agent-1"]);
    let grant = case.ok(&[
        "grant",
        "create",
        "--principal",
        "agent-1",
        "--connection",
        "gh",
    ]);
    let grant_id = grant["id"].as_str().unwrap().to_owned();
    let before = case.ctx().policy.get_connection("gh").unwrap();
    assert!(before.secret_version.is_none());
    let recorded = case.ctx().policy.get_grant(&grant_id).unwrap();
    assert_eq!(recorded.credential_version, Some(PyInt::from(1)));
    case.put_secret(SYNTHETIC_V2, "gh-token");
    let ctx = case.ctx();
    let after = ctx.policy.get_connection("gh").unwrap();
    assert_eq!(after.policy_version, &before.policy_version + 1);
    // Still the shared environment's connection: a later fact applies to it.
    let raw = ctx
        .state
        .read_json(zeropw::policy::CONNECTIONS, json!({}))
        .unwrap();
    assert_eq!(raw["gh"]["shared_env"], env_id.as_str());
    let grant = ctx.policy.get_grant(&grant_id).unwrap();
    assert_eq!(grant.status, "active");
    assert_eq!(grant.credential_version, Some(PyInt::from(2)));
    assert_eq!(grant.policy_version, after.policy_version);
    assert!(ctx.audit.tail(20).unwrap().iter().any(|r| {
        r["event"] == "connection_update" && r["connection"] == "gh" && r["state"] == "reevaluated"
    }));
    let disabled = case.ok(&["connection", "disable", "--id", "gh"]);
    assert!(disabled.get("fact").is_some(), "{disabled}");
    assert_eq!(
        case.ok(&["connection", "show", "--id", "gh"])["status"],
        "disabled"
    );
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
