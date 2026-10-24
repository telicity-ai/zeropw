use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tempfile::TempDir;
use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::team::identity::{DeviceKey, DeviceRecord};
use zeropw::team::transport::{InProcessTransport, MembershipCheck, Transport};
use zeropw::team::{commit, envelope};
use zeropw::team::{membership, sync};

const SECRET: &[u8] = b"synthetic-shared-secret-for-rust-test-0123456789";

fn new_context(root: &TempDir, name: &str) -> Arc<Context> {
    new_context_syncing_every(root, name, 0.1)
}

fn new_context_syncing_every(root: &TempDir, name: &str, seconds: f64) -> Arc<Context> {
    new_context_with(
        root,
        name,
        Config {
            team_sync_interval_seconds: Some(seconds),
            team_dial_backoff: (0.05, 0.3),
            ..Config::default()
        },
    )
}

fn new_context_with(root: &TempDir, name: &str, config: Config) -> Arc<Context> {
    Arc::new(
        Context::initialize(
            root.path().join(name),
            "admin-passphrase",
            "recovery-passphrase",
            config,
            clock::system(),
        )
        .unwrap(),
    )
}

fn wait_until(mut check: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if check() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("team state did not converge");
}

#[test]
fn share_invite_join_and_secret_derivation() {
    let root = TempDir::new().unwrap();
    let a = new_context(&root, "a");
    a.projects.create("demo", &["dev"]).unwrap();
    a.vault
        .put_secret("gh-token", "api_key", SECRET, "demo", "dev", true)
        .unwrap();
    let shared =
        membership::share_environment(&a, None, "demo", "dev", "alice", "admin-passphrase")
            .unwrap();
    let env_id = shared["env_id"].as_str().unwrap();
    let a_device = DeviceKey::load_or_create(a.state, a.kms).unwrap();
    let empty: MembershipCheck = Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None });
    let a_transport = Arc::new(InProcessTransport::new(a_device.clone(), empty));
    let a_sync = sync::TeamSync::new(a.clone(), a_transport.clone(), a_device);
    a_sync.start(Some("rust-team-node-a:47001")).unwrap();
    let invite = membership::create_invite(
        &a,
        env_id,
        "admin",
        "bob",
        3600,
        &["rust-team-node-a:47001".into()],
    )
    .unwrap();
    let parsed = membership::parse_invite(&invite).unwrap();
    assert_eq!(parsed.env_id, env_id);
    let b = new_context(&root, "b");
    let b_device = DeviceKey::load_or_create(b.state, b.kms).unwrap();
    let empty: MembershipCheck = Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None });
    let b_transport = Arc::new(InProcessTransport::new(b_device.clone(), empty));
    let b_sync = sync::TeamSync::new(b.clone(), b_transport.clone(), b_device);
    b_sync.start(None).unwrap();
    let join = membership::join(
        &b,
        &invite,
        b_transport.as_ref() as &dyn Transport,
        &b_sync,
        Some("shared-demo"),
        Some("dev"),
        5.0,
    )
    .unwrap();
    assert_eq!(join["env_id"], env_id);
    assert_eq!(
        b.vault
            .secret_for_trusted_use("gh-token", None)
            .unwrap()
            .expose(),
        SECRET
    );
    let incident = b_sync
        .send_incident(
            env_id,
            &json!({"incident_id":"0123456789abcdef","secret_ids_mandatory":["gh-token"],"uses":2}),
        )
        .unwrap();
    assert_eq!(incident["hash"].as_str().unwrap().len(), 64);
    wait_until(|| {
        a.state.exists(&format!(
            "team/{env_id}/incidents/{}-0123456789abcdef.json",
            b_sync.device.fingerprint().unwrap()
        ))
    });
    wait_until(|| {
        b.state
            .read_bytes(&format!("team/{env_id}/incident_outbox.jsonl"))
            .is_ok_and(|v| v.is_empty())
    });
    assert_eq!(
        a.state
            .read_json(&format!("team/{env_id}/rotation_flags.json"), json!({}))
            .unwrap()["gh-token"]["reason"],
        "rotation_required"
    );
    let fact = b_sync
        .publish_fact(
            env_id,
            "connection_disabled",
            json!({"connection_id":"test-connection"}),
        )
        .unwrap();
    wait_until(|| {
        a.state
            .read_lines(&format!("team/{env_id}/facts.jsonl"), None)
            .is_ok_and(|lines| {
                lines
                    .iter()
                    .any(|line| line.contains(fact["sig"].as_str().unwrap()))
            })
    });
    let c = new_context(&root, "c");
    let c_device = DeviceKey::load_or_create(c.state, c.kms).unwrap();
    let empty: MembershipCheck = Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None });
    let c_transport = Arc::new(InProcessTransport::new(c_device.clone(), empty));
    let c_sync = sync::TeamSync::new(c.clone(), c_transport.clone(), c_device);
    c_sync.start(None).unwrap();
    assert!(
        membership::join(
            &c,
            &invite,
            c_transport.as_ref() as &dyn Transport,
            &c_sync,
            Some("shared-demo"),
            Some("dev"),
            0.2
        )
        .is_err()
    );
    let b_fp = b_sync.device.fingerprint().unwrap();
    let removed = membership::remove_member(&b, Some(&b_sync), env_id, &b_fp).unwrap();
    assert_eq!(removed["dek_rotated"], false);
    wait_until(|| !a_sync.is_active_member(env_id, &b_fp));
    c_sync.stop();
    b_sync.stop();
    a_sync.stop();
}

/// Issue #28: a device that joins through an invitation receives the
/// inviter's history in order and quarantines nothing. The inviter used to
/// broadcast its `member.add` on the new session before the joiner had
/// `env.init`, so every join left a `team_author_unknown` rejection behind.
#[test]
fn join_leaves_no_rejected_commit_on_the_joiner() {
    let root = TempDir::new().unwrap();
    let a = new_context(&root, "a");
    a.projects.create("demo", &["dev"]).unwrap();
    a.vault
        .put_secret("gh-token", "api_key", SECRET, "demo", "dev", true)
        .unwrap();
    let shared =
        membership::share_environment(&a, None, "demo", "dev", "alice", "admin-passphrase")
            .unwrap();
    let env_id = shared["env_id"].as_str().unwrap();
    let a_device = DeviceKey::load_or_create(a.state, a.kms).unwrap();
    let empty: MembershipCheck = Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None });
    let a_transport = Arc::new(InProcessTransport::new(a_device.clone(), empty));
    let a_sync = sync::TeamSync::new(a.clone(), a_transport.clone(), a_device);
    a_sync.start(Some("rust-team-join-a:47001")).unwrap();
    let invite = membership::create_invite(
        &a,
        env_id,
        "user",
        "bob",
        3600,
        &["rust-team-join-a:47001".into()],
    )
    .unwrap();
    let b = new_context(&root, "b");
    let b_device = DeviceKey::load_or_create(b.state, b.kms).unwrap();
    let empty: MembershipCheck = Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None });
    let b_transport = Arc::new(InProcessTransport::new(b_device.clone(), empty));
    let b_sync = sync::TeamSync::new(b.clone(), b_transport.clone(), b_device);
    b_sync.start(None).unwrap();
    membership::join(
        &b,
        &invite,
        b_transport.as_ref() as &dyn Transport,
        &b_sync,
        Some("shared-demo"),
        Some("dev"),
        5.0,
    )
    .unwrap();
    let a_store = commit::CommitStore::new(a.state, env_id);
    let b_store = commit::CommitStore::new(b.state, env_id);
    wait_until(|| b_store.vector().unwrap() == a_store.vector().unwrap());
    let quarantined = quarantined_commits(&b, env_id);
    assert!(quarantined.is_empty(), "{quarantined:?}");
    assert!(
        b.audit
            .tail(500)
            .unwrap()
            .iter()
            .all(|record| record["event"] != "team_commit_rejected")
    );
    b_sync.stop();
    a_sync.stop();
}

fn quarantined_commits(ctx: &Context, env_id: &str) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(ctx.state.path.join(format!("team/{env_id}/rejected")))
        .map(|entries| entries.filter_map(|e| e.ok()).map(|e| e.path()).collect())
        .unwrap_or_default()
}

/// Issue #28 with two authors: the inviter is an administrator other than
/// the owner, and its fingerprint sorts before the owner's. The catch-up
/// must arrive in total order -- the owner's admission of the inviter before
/// the inviter's `member.add` of the joiner -- or the joiner drops the
/// inviter's commits and stays inactive until a periodic VECTOR, which the
/// 60-second interval puts far past the join timeout.
#[test]
fn join_through_a_second_admin_gets_history_in_total_order() {
    let root = TempDir::new().unwrap();
    // Two devices with random keys: the one whose fingerprint sorts first
    // becomes the administrator, the other the owner.
    let node = |name: &str| {
        let ctx = new_context_syncing_every(&root, name, 60.0);
        let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        (ctx, device)
    };
    let (first, second) = (node("node-a"), node("node-b"));
    let ((admin, admin_device), (owner, owner_device)) =
        if first.1.fingerprint().unwrap() < second.1.fingerprint().unwrap() {
            (first, second)
        } else {
            (second, first)
        };
    assert!(admin_device.fingerprint().unwrap() < owner_device.fingerprint().unwrap());
    owner.projects.create("demo", &["dev"]).unwrap();
    owner
        .vault
        .put_secret("gh-token", "api_key", SECRET, "demo", "dev", true)
        .unwrap();
    let shared =
        membership::share_environment(&owner, None, "demo", "dev", "alice", "admin-passphrase")
            .unwrap();
    let env_id = shared["env_id"].as_str().unwrap();
    let empty: MembershipCheck = Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None });
    let owner_transport = Arc::new(InProcessTransport::new(owner_device.clone(), empty));
    let owner_sync = sync::TeamSync::new(owner.clone(), owner_transport, owner_device);
    owner_sync.start(Some("rust-team-order-o:47101")).unwrap();

    let empty: MembershipCheck = Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None });
    let admin_transport = Arc::new(InProcessTransport::new(admin_device.clone(), empty));
    let admin_sync = sync::TeamSync::new(admin.clone(), admin_transport.clone(), admin_device);
    admin_sync.start(Some("rust-team-order-i:47102")).unwrap();
    let invite = membership::create_invite(
        &owner,
        env_id,
        "admin",
        "ivan",
        3600,
        &["rust-team-order-o:47101".into()],
    )
    .unwrap();
    membership::join(
        &admin,
        &invite,
        admin_transport.as_ref() as &dyn Transport,
        &admin_sync,
        Some("shared-demo"),
        Some("dev"),
        5.0,
    )
    .unwrap();

    let invite = membership::create_invite(
        &admin,
        env_id,
        "user",
        "bob",
        3600,
        &["rust-team-order-i:47102".into()],
    )
    .unwrap();
    let joiner = new_context_syncing_every(&root, "joiner", 60.0);
    let joiner_device = DeviceKey::load_or_create(joiner.state, joiner.kms).unwrap();
    let empty: MembershipCheck = Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None });
    let joiner_transport = Arc::new(InProcessTransport::new(joiner_device.clone(), empty));
    let joiner_sync = sync::TeamSync::new(joiner.clone(), joiner_transport.clone(), joiner_device);
    joiner_sync.start(None).unwrap();
    membership::join(
        &joiner,
        &invite,
        joiner_transport.as_ref() as &dyn Transport,
        &joiner_sync,
        Some("shared-demo"),
        Some("dev"),
        5.0,
    )
    .unwrap();
    assert_eq!(
        joiner
            .vault
            .secret_for_trusted_use("gh-token", None)
            .unwrap()
            .expose(),
        SECRET
    );
    let quarantined = quarantined_commits(&joiner, env_id);
    assert!(quarantined.is_empty(), "{quarantined:?}");
    assert!(
        joiner
            .audit
            .tail(500)
            .unwrap()
            .iter()
            .all(|record| record["event"] != "team_commit_rejected")
    );
    joiner_sync.stop();
    admin_sync.stop();
    owner_sync.stop();
}

/// Issue #14: a removed device keeps dialing its remover, which refuses it
/// only after the handshake has completed on the dialing side (at message
/// 3). Those refused dials back off instead of repeating on every 50 ms poll
/// tick, so the remover's audit does not fill with `team_handshake_failed`
/// and raises no `repeated_denials` alert.
#[test]
fn a_removed_device_backs_off_redialing_its_remover() {
    let root = TempDir::new().unwrap();
    let config = || Config {
        team_sync_interval_seconds: Some(0.1),
        team_dial_backoff: (1.0, 4.0),
        team_removed_drain_seconds: 0.2,
        ..Config::default()
    };
    let a = new_context_with(&root, "a", config());
    a.projects.create("demo", &["dev"]).unwrap();
    a.vault
        .put_secret("gh-token", "api_key", SECRET, "demo", "dev", true)
        .unwrap();
    let shared =
        membership::share_environment(&a, None, "demo", "dev", "alice", "admin-passphrase")
            .unwrap();
    let env_id = shared["env_id"].as_str().unwrap();
    let a_device = DeviceKey::load_or_create(a.state, a.kms).unwrap();
    let empty: MembershipCheck = Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None });
    let a_transport = Arc::new(InProcessTransport::new(a_device.clone(), empty));
    let a_sync = sync::TeamSync::new(a.clone(), a_transport, a_device);
    a_sync.start(Some("rust-team-redial-a:47301")).unwrap();
    let invite = membership::create_invite(
        &a,
        env_id,
        "user",
        "bob",
        3600,
        &["rust-team-redial-a:47301".into()],
    )
    .unwrap();
    let b = new_context_with(&root, "b", config());
    let b_device = DeviceKey::load_or_create(b.state, b.kms).unwrap();
    let b_fp = b_device.fingerprint().unwrap();
    let empty: MembershipCheck = Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None });
    let b_transport = Arc::new(InProcessTransport::new(b_device.clone(), empty));
    let b_sync = sync::TeamSync::new(b.clone(), b_transport.clone(), b_device);
    b_sync.start(None).unwrap();
    membership::join(
        &b,
        &invite,
        b_transport.as_ref() as &dyn Transport,
        &b_sync,
        Some("shared-demo"),
        Some("dev"),
        5.0,
    )
    .unwrap();
    membership::remove_member(&a, Some(&a_sync), env_id, &b_fp).unwrap();
    let refused = || {
        a.audit
            .tail(5000)
            .unwrap()
            .iter()
            .filter(|r| r["event"] == "team_handshake_failed")
            .count()
    };
    // Once the drained session is gone, b's dials to a are refused.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while refused() == 0 {
        assert!(std::time::Instant::now() < deadline, "b never redialed a");
        std::thread::sleep(Duration::from_millis(20));
    }
    let start = refused();
    std::thread::sleep(Duration::from_secs(4));
    let during = refused() - start;
    // Backoff 1 s, 2 s, 4 s: two or three more refused dials in four
    // seconds, where every 50 ms poll tick redialed before (about 80).
    assert!(during <= 6, "{during} refused dials in 4 s");
    // And it still redials: at least the dial due one second in.
    assert!(during >= 1, "no refused dial in 4 s");
    assert!(
        a.audit
            .alerts(200)
            .unwrap()
            .iter()
            .all(|alert| alert["alert"] != "repeated_denials")
    );
    b_sync.stop();
    a_sync.stop();
}

#[test]
fn fact_sign_verify_and_sanitize() {
    let key = DeviceKey::generate();
    let fact = sync::sign_fact(
        &key,
        "abc",
        "member_removed",
        json!({"fingerprint": key.fingerprint().unwrap()}),
        "1-0",
    )
    .unwrap();
    assert!(sync::verify_fact(&fact, &key.record().unwrap()));
    let mut forged = fact.clone();
    forged.target = json!({"fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaa"});
    assert!(!sync::verify_fact(&forged, &key.record().unwrap()));
    let clean = sync::sanitize_incident_summary(&json!({"incident_id":"0123456789abcdef","uses":2,"secret_ids_mandatory":["b","a","a"],"unknown":"secret"})).unwrap();
    assert_eq!(clean["secret_ids_mandatory"], json!(["a", "b"]));
    assert!(clean.get("unknown").is_none());
    assert!(sync::sanitize_incident_summary(&json!({"incident_id":"../bad"})).is_err());
}

#[test]
fn live_emergency_facts_each_record_one_apply_audit() {
    let root = TempDir::new().unwrap();
    let ctx = new_context(&root, "fact-audit");
    ctx.projects.create("demo", &["dev"]).unwrap();
    let shared =
        membership::share_environment(&ctx, None, "demo", "dev", "alice", "admin-passphrase")
            .unwrap();
    let env = shared["env_id"].as_str().unwrap();
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let fp = device.fingerprint().unwrap();
    let empty: MembershipCheck = Arc::new(|_, _| None);
    let transport = Arc::new(InProcessTransport::new(device.clone(), empty));
    let team = sync::TeamSync::new(ctx.clone(), transport, device);
    team.register_env(env).unwrap();
    for (kind, target) in [
        ("connection_disabled", json!({"connection_id":"synthetic"})),
        (
            "secret_version_revoked",
            json!({"secret_id":"synthetic","version_id":"0123456789abcdef"}),
        ),
        (
            "member_removed",
            json!({"fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaa"}),
        ),
    ] {
        team.publish_fact(env, kind, target).unwrap();
    }
    let events = ctx
        .state
        .read_lines(zeropw::audit::AUDIT_FILE, None)
        .unwrap();
    let matching: Vec<_> = events
        .iter()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|event| event["event"] == "team_fact_apply")
        .collect();
    assert_eq!(matching.len(), 3);
    for (event, kind) in matching.iter().zip([
        "connection_disabled",
        "secret_version_revoked",
        "member_removed",
    ]) {
        assert_eq!(event["kind"], kind);
        assert_eq!(event["fingerprint"], fp);
        assert_eq!(event["env_id"], env);
    }
}

/// A fact's signed canonical bytes and hash, byte-identical to what the
/// Python prototype's `Fact.canonical_json(True)`/`Fact.hash` produced for
/// the same fact (non-ASCII target text included).
#[test]
fn fact_canonical_bytes_and_hash_match_python() {
    let source = json!({"format":"zeropw-team-fact-v1","env_id":"owner-0123456789abcdef0123456789abcdef","kind":"connection_disabled","target":{"connection_id":"caf\u{e9}-1"},"author":"aaaaaaaaaaaaaaaaaaaaaaaaaa","hlc":"123-0001","sig":"AA=="});
    let fact = sync::Fact::from_dict(&source).unwrap();
    assert_eq!(
        String::from_utf8(fact.canonical_json(true).unwrap()).unwrap(),
        r#"{"author":"aaaaaaaaaaaaaaaaaaaaaaaaaa","env_id":"owner-0123456789abcdef0123456789abcdef","format":"zeropw-team-fact-v1","hlc":"123-0001","kind":"connection_disabled","sig":"AA==","target":{"connection_id":"caf\u00e9-1"}}"#
    );
    assert_eq!(
        fact.hash().unwrap(),
        "a957fdc833c02071d3519b54ee640da68b19c7cc158508d2f7c70f7583ef110e"
    );
}

#[test]
fn compact_preserves_membership_history_and_snapshot_document() {
    let root = TempDir::new().unwrap();
    let ctx = new_context(&root, "compact");
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let fp = device.fingerprint().unwrap();
    let env = commit::new_env_id(&fp).unwrap();
    let generation = "0123456789abcdef0123456789abcdef";
    let dek = [7u8; 32];
    let wrap = envelope::wrap_dek(&dek, &env, generation, &device.record().unwrap()).unwrap();
    let old = commit::now_ms() - 31 * 24 * 3600 * 1000;
    let init=commit::sign_commit(&device,&env,1,&format!("{old}-0000"),&BTreeMap::new(),vec![json!({"op":"env.init","owner_device":device.record().unwrap().to_dict(),"owner_name":"alice","generation_id":generation,"wraps":{fp.clone():wrap}})]).unwrap();
    let ct = envelope::encrypt_secret(&dek, &env, "s", "0011223344556677", SECRET).unwrap();
    let put=commit::sign_commit(&device,&env,2,&format!("{}-0000",old+1),&BTreeMap::from([(fp.clone(),zeropw::pyint::PyInt::from(1))]),vec![json!({"op":"secret.put_version","secret_id":"s","kind":"api_key","generation_id":generation,"version_id":"0011223344556677","ciphertext":ct,"public":{}})]).unwrap();
    let store = commit::CommitStore::new(ctx.state, &env);
    store.append(&init).unwrap();
    store.append(&put).unwrap();
    let empty: MembershipCheck = Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None });
    let transport = Arc::new(InProcessTransport::new(device.clone(), empty));
    let sync = sync::TeamSync::new(ctx.clone(), transport, device);
    sync.register_env(&env).unwrap();
    let before = sync.document(&env).unwrap();
    let outcome = sync.compact(&env).unwrap();
    assert_eq!(outcome["removed"], 1);
    assert!(ctx.state.exists(&format!("team/{env}/commits/{fp}/1.json")));
    assert!(!ctx.state.exists(&format!("team/{env}/commits/{fp}/2.json")));
    assert_eq!(sync.document(&env).unwrap(), before);
}

/// Issue #50: a second `team compact` builds on the first one's snapshot, so
/// what the first compacted stays in the document, now and after a restart.
#[test]
fn a_second_compact_keeps_what_the_first_compacted() {
    let root = TempDir::new().unwrap();
    let ctx = new_context(&root, "compact-twice");
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let fp = device.fingerprint().unwrap();
    let env = commit::new_env_id(&fp).unwrap();
    let generation = "0123456789abcdef0123456789abcdef";
    let dek = [7u8; 32];
    let wrap = envelope::wrap_dek(&dek, &env, generation, &device.record().unwrap()).unwrap();
    let old = commit::now_ms() - 40 * 24 * 3600 * 1000;
    let init=commit::sign_commit(&device,&env,1,&format!("{old}-0000"),&BTreeMap::new(),vec![json!({"op":"env.init","owner_device":device.record().unwrap().to_dict(),"owner_name":"alice","generation_id":generation,"wraps":{fp.clone():wrap}})]).unwrap();
    let put = |seq: i64, secret: &str, version: &str| {
        let ct = envelope::encrypt_secret(&dek, &env, secret, version, SECRET).unwrap();
        commit::sign_commit(&device,&env,seq,&format!("{}-0000",old+seq),&BTreeMap::from([(fp.clone(),zeropw::pyint::PyInt::from(seq - 1))]),vec![json!({"op":"secret.put_version","secret_id":secret,"kind":"api_key","generation_id":generation,"version_id":version,"ciphertext":ct,"public":{}})]).unwrap()
    };
    let store = commit::CommitStore::new(ctx.state, &env);
    store.append(&init).unwrap();
    store.append(&put(2, "first", "0011223344556677")).unwrap();
    let empty: MembershipCheck = Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None });
    let transport = Arc::new(InProcessTransport::new(device.clone(), empty.clone()));
    let sync = sync::TeamSync::new(ctx.clone(), transport, device.clone());
    sync.register_env(&env).unwrap();
    assert_eq!(sync.compact(&env).unwrap()["removed"], 1);
    store.append(&put(3, "second", "8899aabbccddeeff")).unwrap();
    sync.poll().unwrap();
    let before = sync.document(&env).unwrap();
    assert!(before["secrets"]["first"].is_object() && before["secrets"]["second"].is_object());
    assert_eq!(sync.compact(&env).unwrap()["removed"], 1);
    assert_eq!(sync.document(&env).unwrap(), before);
    sync.stop();
    let transport = Arc::new(InProcessTransport::new(device.clone(), empty));
    let restarted = sync::TeamSync::new(ctx.clone(), transport, device);
    restarted.register_env(&env).unwrap();
    assert_eq!(restarted.document(&env).unwrap(), before);
}

/// Issue #30: a `user` device cannot author editing commits. `author_commit`
/// (behind `secret put`, `rotation`, `connection update`, `switch-credential`
/// and `team set-role`) refuses with `not_admin` before storing anything,
/// instead of broadcasting a commit every node then skips; nor does it store
/// any other change the fold refuses its author.
#[test]
fn user_device_cannot_author_editing_commits() {
    let root = TempDir::new().unwrap();
    let a = new_context(&root, "a");
    a.projects.create("demo", &["dev"]).unwrap();
    a.vault
        .put_secret("gh-token", "api_key", SECRET, "demo", "dev", true)
        .unwrap();
    let shared =
        membership::share_environment(&a, None, "demo", "dev", "alice", "admin-passphrase")
            .unwrap();
    let env_id = shared["env_id"].as_str().unwrap();
    let a_device = DeviceKey::load_or_create(a.state, a.kms).unwrap();
    let empty: MembershipCheck = Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None });
    let a_transport = Arc::new(InProcessTransport::new(a_device.clone(), empty));
    let a_sync = sync::TeamSync::new(a.clone(), a_transport.clone(), a_device);
    a_sync.start(Some("rust-team-role-a:47001")).unwrap();
    let invite = membership::create_invite(
        &a,
        env_id,
        "user",
        "bob",
        3600,
        &["rust-team-role-a:47001".into()],
    )
    .unwrap();
    let b = new_context(&root, "b");
    let b_device = DeviceKey::load_or_create(b.state, b.kms).unwrap();
    let b_fp = b_device.fingerprint().unwrap();
    let empty: MembershipCheck = Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None });
    let b_transport = Arc::new(InProcessTransport::new(b_device.clone(), empty));
    let b_sync = sync::TeamSync::new(b.clone(), b_transport.clone(), b_device);
    b_sync.start(None).unwrap();
    membership::join(
        &b,
        &invite,
        b_transport.as_ref() as &dyn Transport,
        &b_sync,
        Some("shared-demo"),
        Some("dev"),
        5.0,
    )
    .unwrap();
    b_sync.stop();
    let store = commit::CommitStore::new(b.state, env_id);
    let before = store.vector().unwrap();
    let editing = [
        json!({"op":"secret.activate","secret_id":"gh-token","version_id":"0011223344556677"}),
        json!({"op":"member.set_role","fingerprint":b_fp,"role":"admin"}),
        json!({"op":"settings.update","sync_interval_seconds":5}),
    ];
    for op in editing {
        let error = membership::author_commit(&b, None, env_id, vec![op.clone()]).unwrap_err();
        assert_eq!(error.reason, "not_admin", "{op}");
    }
    assert_eq!(store.vector().unwrap(), before);
    // The owner still edits, but not with changes the fold would refuse it.
    a_sync.stop();
    membership::author_commit(
        &a,
        None,
        env_id,
        vec![json!({"op":"settings.update","sync_interval_seconds":5})],
    )
    .unwrap();
    let a_fp = DeviceKey::load_or_create(a.state, a.kms)
        .unwrap()
        .fingerprint()
        .unwrap();
    let a_store = commit::CommitStore::new(a.state, env_id);
    let a_before = a_store.vector().unwrap();
    let refused = [
        (
            json!({"op":"owner.transfer","fingerprint":"c".repeat(26)}),
            "member_not_found",
        ),
        (
            json!({"op":"member.set_role","fingerprint":"c".repeat(26),"role":"admin"}),
            "member_not_found",
        ),
        (
            json!({"op":"member.set_role","fingerprint":a_fp,"role":"user"}),
            "cannot_change_owner_role",
        ),
        (
            json!({"op":"member.remove","fingerprint":a_fp}),
            "cannot_remove_owner",
        ),
    ];
    for (op, reason) in refused {
        let error = membership::author_commit(&a, None, env_id, vec![op.clone()]).unwrap_err();
        assert_eq!(error.reason, reason, "{op}");
    }
    assert_eq!(a_store.vector().unwrap(), a_before);
    // Promoted, the device edits; only the owner transfers ownership.
    let promotion = membership::author_commit(
        &a,
        None,
        env_id,
        vec![json!({"op":"member.set_role","fingerprint":b_fp,"role":"admin"})],
    )
    .unwrap();
    for missing in a_store.all_commits().unwrap() {
        if store
            .get(&missing.author, &missing.author_seq)
            .unwrap()
            .is_none()
        {
            commit::receive_commit(&store, &missing, commit::now_ms(), None).unwrap();
        }
    }
    assert!(
        store
            .get(&promotion.author, &promotion.author_seq)
            .unwrap()
            .is_some()
    );
    let error = membership::author_commit(
        &b,
        None,
        env_id,
        vec![json!({"op":"owner.transfer","fingerprint":b_fp})],
    )
    .unwrap_err();
    assert_eq!(error.reason, "not_owner");
    membership::author_commit(
        &b,
        None,
        env_id,
        vec![json!({"op":"settings.update","sync_interval_seconds":7})],
    )
    .unwrap();
    // Removed by the owner's fact, the device authors nothing more, wherever
    // its next commit would sort.
    membership::remove_member(&a, None, env_id, &b_fp).unwrap();
    let facts = format!("team/{env_id}/facts.jsonl");
    for line in a.state.read_lines(&facts, None).unwrap() {
        b.state.append_line(&facts, &line).unwrap();
    }
    let b_before = store.vector().unwrap();
    let error = membership::author_commit(
        &b,
        None,
        env_id,
        vec![json!({"op":"settings.update","sync_interval_seconds":9})],
    )
    .unwrap_err();
    assert_eq!(error.reason, "member_removed");
    assert_eq!(store.vector().unwrap(), b_before);
}
