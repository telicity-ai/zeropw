//! Sync status for the UI (docs/remote-sync.md §3.3): the `sync_state.json`
//! a running `serve` writes, and `team sync-status`. Synthetic credentials
//! only.
mod native_e2e;

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use native_e2e::{ADMIN_PASSPHRASE, Admin, free_port};
use serde_json::{Value, json};
use tempfile::TempDir;
use zeropw::context::{Config, Context};
use zeropw::team::commit::CommitStore;
use zeropw::team::identity::DeviceKey;
use zeropw::team::membership;
use zeropw::team::sync::{self, TeamSync};
use zeropw::team::sync_status;
use zeropw::team::transport::{MembershipCheck, TcpTransport};

const SECRET: &[u8] = b"synthetic-sync-status-secret-0123456789";
const PEER_KEYS: [&str; 9] = [
    "dial_failures",
    "last_contact_at",
    "last_error",
    "next_attempt_at",
    "peer_vector",
    "session",
    "since",
    "transport",
    "vector_received_at",
];

fn config(sync_seconds: f64) -> Config {
    Config {
        team_sync_interval_seconds: Some(sync_seconds),
        team_dial_backoff: (0.5, 1.0),
        ..Config::default()
    }
}

fn context(root: &TempDir, name: &str, sync_seconds: f64) -> Arc<Context> {
    Arc::new(
        Context::initialize(
            root.path().join(name),
            "admin-passphrase",
            "recovery-passphrase",
            config(sync_seconds),
            zeropw::clock::system(),
        )
        .unwrap(),
    )
}

fn none() -> MembershipCheck {
    Arc::new(|_, _| None)
}

fn fingerprint(ctx: &Context) -> String {
    DeviceKey::load_or_create(ctx.state, ctx.kms)
        .unwrap()
        .fingerprint()
        .unwrap()
}

/// A shared `demo/dev` holding one synthetic secret, served on TCP with the
/// sync state enabled (what `serve --team-listen` runs).
fn serving(root: &TempDir, sync_seconds: f64) -> (Arc<Context>, Arc<TeamSync>, String, String) {
    let ctx = context(root, "a", sync_seconds);
    ctx.projects.create("demo", &["dev"]).unwrap();
    ctx.vault
        .put_secret("gh-token", "api_key", SECRET, "demo", "dev", true)
        .unwrap();
    let shared =
        membership::share_environment(&ctx, None, "demo", "dev", "owner", "admin-passphrase")
            .unwrap();
    let env = shared["env_id"].as_str().unwrap().to_owned();
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let transport = TcpTransport::new(device.clone(), none(), 8);
    let node = TeamSync::new(ctx.clone(), Arc::new(transport), device);
    node.enable_sync_state();
    let address = format!("127.0.0.1:{}", free_port());
    node.start(Some(&address)).unwrap();
    (ctx, node, env, address)
}

/// A device that joined through a normal invitation and keeps running.
fn joined(
    root: &TempDir,
    inviter: &Context,
    env: &str,
    address: &str,
    sync_seconds: f64,
) -> (Arc<Context>, Arc<TeamSync>, String, String) {
    let invite =
        membership::create_invite(inviter, env, "user", "laptop", 3600, &[address.to_owned()])
            .unwrap();
    let ctx = context(root, "b", sync_seconds);
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let transport = TcpTransport::new(device.clone(), none(), 8);
    let team = TeamSync::new(ctx.clone(), Arc::new(transport.clone()), device);
    team.start(None).unwrap();
    membership::join(
        &ctx,
        &invite,
        &transport,
        &team,
        Some("paired"),
        Some("dev"),
        10.0,
    )
    .unwrap();
    let fp = fingerprint(&ctx);
    (ctx, team, fp, invite)
}

fn state_file(ctx: &Context, env: &str) -> Value {
    ctx.state
        .read_json(&sync_status::path(env), Value::Null)
        .unwrap()
}

fn wait_for<T>(what: &str, mut check: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(value) = check() {
            return value;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn peer_of(status: &Value, fp: &str) -> Value {
    status["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["fingerprint"] == fp)
        .cloned()
        .unwrap_or_else(|| panic!("{fp} not in {status}"))
}

fn sorted_keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    keys
}

#[test]
fn serve_writes_metadata_only_and_states_follow_the_sessions() {
    let root = TempDir::new().unwrap();
    let (a, node, env, address) = serving(&root, 0.05);
    let a_fp = fingerprint(&a);
    let (b, b_team, b_fp, invite) = joined(&root, &a, &env, &address, 0.05);

    // Connected and caught up: up_to_date over TCP.
    let status = wait_for("up_to_date", || {
        let status = sync_status::status(&a, &env).unwrap();
        (peer_of(&status, &b_fp)["state"] == "up_to_date").then_some(status)
    });
    assert_eq!(status["self"], a_fp);
    assert!(status["serve_updated_at"].is_string());
    assert_eq!(status["conflicts"], 0);
    let peer = peer_of(&status, &b_fp);
    assert_eq!(peer["name"], "laptop");
    assert_eq!(peer["session"], true);
    assert_eq!(peer["transport"], "tcp");
    assert!(peer["last_contact_at"].is_string());
    assert!(peer["next_attempt_at"].is_null() && peer["last_error"].is_null());
    assert_eq!(
        sorted_keys(&peer),
        [
            "fingerprint",
            "last_contact_at",
            "last_error",
            "name",
            "next_attempt_at",
            "session",
            "state",
            "transport"
        ]
    );
    assert_eq!(
        sorted_keys(&status),
        ["conflicts", "env_id", "peers", "self", "serve_updated_at"]
    );

    // The file: exactly the specified fields, 0600, metadata only.
    let file = state_file(&a, &env);
    assert_eq!(sorted_keys(&file), ["peers", "self", "updated_at"]);
    assert_eq!(file["self"], a_fp);
    let entry = &file["peers"][&b_fp];
    assert_eq!(sorted_keys(entry), PEER_KEYS);
    assert_eq!(entry["session"], true);
    assert!(entry["since"].is_string() && entry["vector_received_at"].is_string());
    let local = CommitStore::new(a.state, &env).vector().unwrap();
    assert_eq!(entry["peer_vector"], json!(local));
    let path = a.state.path.join(sync_status::path(&env));
    let raw = std::fs::read_to_string(&path).unwrap();
    let secret_b64 = zeropw::pybase64::b64encode(SECRET);
    for needle in [
        std::str::from_utf8(SECRET).unwrap(),
        secret_b64.as_str(),
        invite.as_str(),
        "ciphertext",
        "wrap",
        "nonce",
        "eph_pub",
        "sign_pub",
        "agree_pub",
        "\"sig\"",
    ] {
        assert!(!raw.contains(needle), "sync_state.json carries {needle:?}");
    }
    // Every DEK generation's local key file stays out of it as well.
    let dek_dir = a.state.path.join(format!("team/{env}/dek"));
    for key_file in std::fs::read_dir(dek_dir).unwrap() {
        let key: Value =
            serde_json::from_str(&std::fs::read_to_string(key_file.unwrap().path()).unwrap())
                .unwrap();
        for value in key.as_object().unwrap().values() {
            if let Some(text) = value.as_str().filter(|t| t.len() >= 16) {
                assert!(!raw.contains(text), "a wrapped DEK field leaked");
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // Only serve writes it: the joiner's own node does not.
    assert!(state_file(&b, &env).is_null());

    // B goes away: no session, no address to dial, but known: offline.
    b_team.stop();
    let status = wait_for("offline", || {
        let status = sync_status::status(&a, &env).unwrap();
        (peer_of(&status, &b_fp)["state"] == "offline").then_some(status)
    });
    let peer = peer_of(&status, &b_fp);
    assert_eq!(peer["session"], false);
    assert!(peer["transport"].is_null());
    assert!(peer["last_contact_at"].is_string());

    // An address that refuses connections: retrying, with the reason code.
    let closed = format!("127.0.0.1:{}", free_port());
    node.set_peer_address(&env, &b_fp, &closed).unwrap();
    let status = wait_for("retrying", || {
        let status = sync_status::status(&a, &env).unwrap();
        (peer_of(&status, &b_fp)["state"] == "retrying").then_some(status)
    });
    let peer = peer_of(&status, &b_fp);
    assert_eq!(peer["last_error"], "team_dial_failed");
    assert!(peer["next_attempt_at"].is_string());
    let file = state_file(&a, &env);
    assert!(file["peers"][&b_fp]["dial_failures"].as_u64().unwrap() >= 1);

    // B comes back and dials A: up_to_date again, the failure cleared.
    let device = DeviceKey::load_or_create(b.state, b.kms).unwrap();
    let transport = TcpTransport::new(device.clone(), none(), 8);
    let b_team = TeamSync::new(b.clone(), Arc::new(transport), device);
    b_team.start(None).unwrap();
    let status = wait_for("up_to_date after reconnect", || {
        let status = sync_status::status(&a, &env).unwrap();
        (peer_of(&status, &b_fp)["state"] == "up_to_date").then_some(status)
    });
    let peer = peer_of(&status, &b_fp);
    assert!(peer["last_error"].is_null() && peer["next_attempt_at"].is_null());

    // Stopping serve leaves its last word: no session open.
    b_team.stop();
    node.stop();
    let file = state_file(&a, &env);
    assert_eq!(file["peers"][&b_fp]["session"], false);
    assert!(file["peers"][&b_fp]["since"].is_null());
}

/// `serve` keeps `last_contact_at` across a restart, so a peer it met
/// before is `offline`, not `never_connected`.
#[test]
fn a_restarted_serve_remembers_contact() {
    let root = TempDir::new().unwrap();
    let (a, node, env, address) = serving(&root, 0.05);
    let (_b, b_team, b_fp, _) = joined(&root, &a, &env, &address, 0.05);
    wait_for("session", || {
        let file = state_file(&a, &env);
        (file["peers"][&b_fp]["session"] == true).then_some(())
    });
    b_team.stop();
    node.stop();
    let device = DeviceKey::load_or_create(a.state, a.kms).unwrap();
    let transport = TcpTransport::new(device.clone(), none(), 8);
    let node = TeamSync::new(a.clone(), Arc::new(transport), device);
    node.enable_sync_state();
    node.start(Some(&format!("127.0.0.1:{}", free_port())))
        .unwrap();
    let status = wait_for("restarted file", || {
        let status = sync_status::status(&a, &env).unwrap();
        (peer_of(&status, &b_fp)["state"] == "offline").then_some(status)
    });
    assert!(peer_of(&status, &b_fp)["last_contact_at"].is_string());
    node.stop();
}

fn mtime(path: &std::path::Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// At most every 2 s, and only when something changed.
#[test]
fn writes_are_throttled_and_skipped_when_nothing_changed() {
    let root = TempDir::new().unwrap();
    // Busy: a VECTOR every 50 ms keeps `last_contact_at` moving.
    let (a, node, env, address) = serving(&root, 0.05);
    let (_b, b_team, b_fp, _) = joined(&root, &a, &env, &address, 0.05);
    let path = a.state.path.join(sync_status::path(&env));
    wait_for("session", || {
        (state_file(&a, &env)["peers"][&b_fp]["session"] == true).then_some(())
    });
    let mut seen: Vec<SystemTime> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(9);
    while Instant::now() < deadline {
        if let Some(time) = mtime(&path)
            && seen.last() != Some(&time)
        {
            seen.push(time);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        seen.len() >= 3,
        "a busy peer keeps changing the file: {seen:?}"
    );
    for pair in seen.windows(2) {
        let gap = pair[1].duration_since(pair[0]).unwrap();
        assert!(gap >= Duration::from_millis(1900), "written {gap:?} apart");
    }
    b_team.stop();
    node.stop();

    // Quiet: one VECTOR a minute, so once the session is up nothing changes
    // for a while and the file is left alone.
    let root = TempDir::new().unwrap();
    let (a, node, env, address) = serving(&root, 60.0);
    let (_b, b_team, b_fp, _) = joined(&root, &a, &env, &address, 60.0);
    let path = a.state.path.join(sync_status::path(&env));
    wait_for("session", || {
        (state_file(&a, &env)["peers"][&b_fp]["session"] == true).then_some(())
    });
    // Let the last-contact second settle into a written state.
    std::thread::sleep(Duration::from_millis(4500));
    let before = (mtime(&path), std::fs::read_to_string(&path).unwrap());
    std::thread::sleep(Duration::from_millis(5000));
    let after = (mtime(&path), std::fs::read_to_string(&path).unwrap());
    assert_eq!(before, after, "an unchanged state is not rewritten");
    b_team.stop();
    node.stop();
}

// ---------------------------------------------------------------- CLI

fn cli_shared(root: &std::path::Path) -> Admin {
    let admin = Admin::new(root);
    admin.ok(&["init"]);
    admin.ok(&["project", "create", "demo"]);
    let ctx = Context::open(&admin.state, Config::default(), zeropw::clock::system()).unwrap();
    membership::share_environment(&ctx, None, "demo", "dev", "owner", ADMIN_PASSPHRASE).unwrap();
    admin
}

#[test]
fn cli_sync_status_merges_the_file_with_the_store() {
    let tmp = TempDir::new().unwrap();
    let inviter = cli_shared(&tmp.path().join("inviter"));
    let alone = inviter.ok(&["team", "sync-status", "--env", "demo/dev"]);
    let env = alone["env_id"].as_str().unwrap().to_owned();
    assert_eq!(alone["peers"], json!([]));
    assert!(alone["serve_updated_at"].is_null());
    assert_eq!(alone["conflicts"], 0);
    // A member joins through a node that does not write the sync state.
    let ctx = Arc::new(
        Context::open(&inviter.state, Config::default(), zeropw::clock::system()).unwrap(),
    );
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let transport = TcpTransport::new(device.clone(), none(), 8);
    let node = sync::TeamSync::new(ctx.clone(), Arc::new(transport), device);
    let address = format!("127.0.0.1:{}", free_port());
    node.start(Some(&address)).unwrap();
    let created = inviter.ok(&[
        "team",
        "invite",
        "--env",
        "demo/dev",
        "--role",
        "user",
        "--name",
        "laptop",
        "--address",
        &address,
    ]);
    let joiner = Admin::new(&tmp.path().join("joiner"));
    joiner.ok(&["init"]);
    let joined = joiner.ok(&["team", "join", created["invite"].as_str().unwrap()]);
    let b_fp = joined["self_fingerprint"].as_str().unwrap().to_owned();
    node.stop();

    // No file: never_connected, serve_updated_at null.
    let status = inviter.ok(&["team", "sync-status", "--env", "demo/dev"]);
    assert_eq!(
        status["peers"],
        json!([{"fingerprint": b_fp, "name": "laptop", "state": "never_connected",
            "session": false, "transport": null, "last_contact_at": null,
            "next_attempt_at": null, "last_error": null}])
    );
    assert!(status["serve_updated_at"].is_null());

    let local = CommitStore::new(ctx.state, &env).vector().unwrap();
    let mut behind = local.clone();
    let first = behind.keys().next().unwrap().clone();
    behind.insert(first, zeropw::pyint::PyInt::from(0));
    let write = |peer: Value| {
        ctx.state
            .write_json(
                &sync_status::path(&env),
                &json!({"updated_at": "2026-11-06T10:00:00Z", "self": joined["inviter_fingerprint"],
                    "peers": {&b_fp: peer}}),
            )
            .unwrap();
        let status = inviter.ok(&["team", "sync-status", "--env", "demo/dev"]);
        assert_eq!(status["serve_updated_at"], "2026-11-06T10:00:00Z");
        peer_of(&status, &b_fp)
    };
    let open = |vector: Value| {
        json!({"session": true, "since": "2026-11-06T09:59:00Z", "peer_vector": vector,
            "vector_received_at": "2026-11-06T09:59:59Z", "transport": "link",
            "dial_failures": 0, "next_attempt_at": null, "last_error": null,
            "last_contact_at": "2026-11-06T09:59:59Z"})
    };
    let peer = write(open(json!(local)));
    assert_eq!(peer["state"], "up_to_date");
    assert_eq!(peer["transport"], "link");
    assert_eq!(write(open(json!(behind)))["state"], "syncing");
    assert_eq!(write(open(Value::Null))["state"], "syncing");
    let peer = write(
        json!({"session": false, "since": null, "peer_vector": local,
        "vector_received_at": null, "transport": null, "dial_failures": 3,
        "next_attempt_at": "2026-11-06T10:00:30Z", "last_error": "team_dial_failed",
        "last_contact_at": "2026-11-06T09:00:00Z"}),
    );
    assert_eq!(peer["state"], "retrying");
    assert_eq!(peer["last_error"], "team_dial_failed");
    assert_eq!(peer["next_attempt_at"], "2026-11-06T10:00:30Z");
    let peer = write(json!({"session": false, "since": null, "peer_vector": null,
        "vector_received_at": null, "transport": null, "dial_failures": 0,
        "next_attempt_at": null, "last_error": null,
        "last_contact_at": "2026-11-06T09:00:00Z"}));
    assert_eq!(peer["state"], "offline");
    assert!(peer["transport"].is_null());

    // Conflicts: this environment's unacknowledged override alerts.
    ctx.state
        .write_json(
            &format!("team/{env}/overridden_alerted.json"),
            &json!(["aa:bb", "cc:dd"]),
        )
        .unwrap();
    let status = inviter.ok(&["team", "sync-status", "--env", "demo/dev"]);
    assert_eq!(status["conflicts"], 2);

    // A file serve did not write fails closed, without echoing it.
    for bad in [
        json!([]),
        json!({"updated_at": "later", "peers": {}}),
        json!({"updated_at": "2026-11-06T10:00:00Z", "peers": {"not-a-fingerprint": {"session": false}}}),
        json!({"updated_at": "2026-11-06T10:00:00Z", "peers": {&b_fp: {"session": true, "last_error": "synthetic-leak value"}}}),
    ] {
        ctx.state
            .write_json(&sync_status::path(&env), &bad)
            .unwrap();
        let error = inviter.fail(&["team", "sync-status", "--env", "demo/dev"]);
        assert_eq!(error["reason"], "state_corrupt");
        assert_eq!(error["detail"], sync_status::path(&env));
    }
    ctx.state
        .write_json(&format!("team/{env}/overridden_alerted.json"), &json!(7))
        .unwrap();
    std::fs::remove_file(ctx.state.path.join(sync_status::path(&env))).unwrap();
    let error = inviter.fail(&["team", "sync-status", "--env", "demo/dev"]);
    assert_eq!(error["reason"], "state_corrupt");
    let missing = inviter.fail(&["team", "sync-status", "--env", "demo/missing"]);
    assert_eq!(missing["reason"], "team_env_not_found");
}
