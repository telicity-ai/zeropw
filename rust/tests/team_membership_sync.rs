use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tempfile::TempDir;
use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::team::identity::{DeviceKey, DeviceRecord};
use zeropw::team::transport::{InProcessTransport, MembershipCheck, Transport};
use zeropw::team::{membership, sync};

const SECRET: &[u8] = b"synthetic-shared-secret-for-rust-test-0123456789";

fn new_context(root: &TempDir, name: &str) -> Arc<Context> {
    let config = Config {
        team_sync_interval_seconds: Some(0.1),
        team_dial_backoff: (0.05, 0.3),
        ..Config::default()
    };
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
    a_sync.start(Some("rust-team-node-a")).unwrap();
    let invite = membership::create_invite(
        &a,
        env_id,
        "admin",
        "bob",
        3600,
        &["rust-team-node-a".into()],
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
    c_sync.stop();
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
    std::thread::sleep(Duration::from_millis(1));
}
