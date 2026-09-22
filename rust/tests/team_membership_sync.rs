use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};
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
fn fact_canonical_bytes_and_hash_match_python() {
    let source = json!({"format":"zeropw-team-fact-v1","env_id":"owner-0123456789abcdef0123456789abcdef","kind":"connection_disabled","target":{"connection_id":"café-1"},"author":"aaaaaaaaaaaaaaaaaaaaaaaaaa","hlc":"123-0001","sig":"AA=="});
    let rust = sync::Fact::from_dict(&source).unwrap();
    let script = "import base64,json,sys\nfrom zeropw.team.sync import Fact\nf=Fact.from_dict(json.load(sys.stdin))\nprint(json.dumps({'canonical':base64.b64encode(f.canonical_json(True)).decode(),'hash':f.hash}))";
    let mut child = Command::new("python3.12")
        .arg("-c")
        .arg(script)
        .env("PYTHONPATH", format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(source.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    use base64::Engine;
    assert_eq!(
        base64::engine::general_purpose::STANDARD.encode(rust.canonical_json(true).unwrap()),
        result["canonical"]
    );
    assert_eq!(rust.hash().unwrap(), result["hash"]);
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
    let put=commit::sign_commit(&device,&env,2,&format!("{}-0000",old+1),&BTreeMap::from([(fp.clone(),1)]),vec![json!({"op":"secret.put_version","secret_id":"s","kind":"api_key","generation_id":generation,"version_id":"0011223344556677","ciphertext":ct,"public":{}})]).unwrap();
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
