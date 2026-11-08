//! Synthetic real-compactor tests. Literal slots/deletion sets/data order and
//! pre-compaction canonical bytes are separate oracles from signature/fold checks.
use std::collections::BTreeMap;
use std::fs;
use std::sync::Arc;

use serde_json::{Value, json};
use tempfile::TempDir;
use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::pyint::PyInt;
use zeropw::pyjson::{self, DumpOptions};
use zeropw::team::commit::{self, Commit, CommitStore};
use zeropw::team::identity::DeviceKey;
use zeropw::team::sync::{self, TeamSync};
use zeropw::team::transport::{InProcessTransport, MembershipCheck};
use zeropw::team::{envelope, fold, membership};

const OLD: i64 = 1_000_000;
const G: &str = "0123456789abcdef";
const V1: &str = "0011223344556677";
const V2: &str = "8899aabbccddeeff";
const VALUE: &[u8] = b"synthetic-compaction-value";

struct Fixture {
    _root: TempDir,
    ctx: Arc<Context>,
    device: DeviceKey,
    fp: String,
    env: String,
}
impl Fixture {
    fn new(wall: i64) -> Self {
        let root = TempDir::new().unwrap();
        let ctx = Arc::new(
            Context::initialize(
                root.path().join("state"),
                "synthetic-admin",
                "synthetic-recovery",
                Config::default(),
                clock::system(),
            )
            .unwrap(),
        );
        let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        let fp = device.fingerprint().unwrap();
        let env = format!("{fp}-0123456789abcdef0123456789abcdef");
        let wrap = envelope::wrap_dek(&[7; 32], &env, G, &device.record().unwrap()).unwrap();
        let init = commit::sign_commit(
            &device,
            &env,
            1,
            &format!("{wall}-0000"),
            &BTreeMap::new(),
            vec![
                json!({"op":"env.init","owner_device":device.record().unwrap().to_dict(),
                "owner_name":"synthetic-owner","generation_id":G,"wraps":{fp.clone():wrap}}),
            ],
        )
        .unwrap();
        CommitStore::new(ctx.state, &env).append(&init).unwrap();
        Self {
            _root: root,
            ctx,
            device,
            fp,
            env,
        }
    }
    fn append(&self, device: &DeviceKey, seq: i64, wall: i64, ops: Vec<Value>) -> Commit {
        let fp = device.fingerprint().unwrap();
        let seen = CommitStore::new(self.ctx.state, &self.env)
            .vector()
            .unwrap();
        let entry =
            commit::sign_commit(device, &self.env, seq, &format!("{wall}-0007"), &seen, ops)
                .unwrap();
        assert_eq!(entry.author, fp);
        let _lock = self.ctx.state.lock().unwrap();
        CommitStore::new(self.ctx.state, &self.env)
            .append(&entry)
            .unwrap();
        entry
    }
    fn put_op(&self, secret: &str, version: &str) -> Value {
        let ciphertext =
            envelope::encrypt_secret(&[7; 32], &self.env, secret, version, VALUE).unwrap();
        json!({"op":"secret.put_version","secret_id":secret,"version_id":version,
            "generation_id":G,"kind":"api_key","ciphertext":ciphertext,"public":{}})
    }
    fn put(&self, seq: i64, wall: i64, version: &str) -> Commit {
        self.append(&self.device, seq, wall, vec![self.put_op("s", version)])
    }
    fn sync(&self) -> Arc<TeamSync> {
        team(self.ctx.clone(), self.device.clone(), &self.env)
    }
    fn cache(&self) -> Value {
        self.ctx
            .state
            .read_json(&self.cache_name(), Value::Null)
            .unwrap()
    }
    fn cache_name(&self) -> String {
        format!("team/{}/compaction_heads.json", self.env)
    }
    fn path(&self, author: &str, seq: i64) -> std::path::PathBuf {
        self.ctx
            .state
            .path
            .join(format!("team/{}/commits/{author}/{seq}.json", self.env))
    }
    fn add(&self, peer: &DeviceKey, seq: i64, wall: i64) -> Commit {
        let wrap = envelope::wrap_dek(&[7; 32], &self.env, G, &peer.record().unwrap()).unwrap();
        self.append(
            &self.device,
            seq,
            wall,
            vec![json!({"op":"member.add",
            "device":peer.record().unwrap().to_dict(),"name":"synthetic-peer",
            "role":"admin","wraps":{G:wrap}})],
        )
    }
}
fn team(ctx: Arc<Context>, device: DeviceKey, env: &str) -> Arc<TeamSync> {
    let empty: MembershipCheck = Arc::new(|_, _| None);
    let transport = Arc::new(InProcessTransport::new(device.clone(), empty));
    let team = TeamSync::new(ctx, transport, device);
    team.register_env(env).unwrap();
    team
}
fn canon(value: &Value) -> Vec<u8> {
    pyjson::dumps(value, DumpOptions::compact_sorted())
        .unwrap()
        .into_bytes()
}
fn assert_head(cache: &Value, original: &Commit, signed: &[u8], hashed: &[u8]) {
    let heads = cache["heads"].as_array().unwrap();
    let head = heads
        .iter()
        .find(|head| head["author"] == original.author)
        .unwrap();
    assert_eq!(head["author_seq"], original.author_seq.value());
    assert_eq!(head["hlc"], original.hlc);
    assert_eq!(head["commit_hash"], original.hash().unwrap());
    let decoded = Commit::from_dict(&head["commit"]).unwrap();
    assert_eq!(decoded.canonical_json(false).unwrap(), signed);
    assert_eq!(decoded.canonical_json(true).unwrap(), hashed);
    assert_eq!(canon(&head["commit"]), hashed);
    let record = zeropw::team::identity::DeviceRecord::from_dict(&head["device"]).unwrap();
    assert!(record.verify());
    assert!(commit::verify_commit(&decoded, &record));
}
fn metadata(f: &Fixture) -> BTreeMap<String, Vec<u8>> {
    let mut result = BTreeMap::new();
    for directory in ["snapshots", "snapshot_records"] {
        let path = f.ctx.state.path.join(format!("team/{}/{directory}", f.env));
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_file() {
                    result.insert(
                        format!(
                            "{directory}/{}",
                            path.file_name().unwrap().to_str().unwrap()
                        ),
                        fs::read(path).unwrap(),
                    );
                }
            }
        }
    }
    let path = f.ctx.state.path.join(f.cache_name());
    if path.is_file() {
        result.insert("cache".into(), fs::read(path).unwrap());
    }
    result
}

#[test]
fn final_data_head_is_deleted_live_but_original_bytes_hlc_and_version_order_survive() {
    let f = Fixture::new(OLD);
    let put = f.put(2, OLD + 1, V1);
    let signed = put.canonical_json(false).unwrap();
    let hashed = put.canonical_json(true).unwrap();
    let team = f.sync();
    assert_eq!(
        team.compact(&f.env).unwrap(),
        json!({"env_id":f.env,"removed":1,"blocked_by":[]})
    );
    assert!(f.path(&f.fp, 1).is_file());
    assert!(!f.path(&f.fp, 2).exists());
    let cache = f.cache();
    assert_eq!(cache["format"], "zeropw-team-compaction-heads-v1");
    assert_eq!(cache["env_id"], f.env);
    assert_eq!(cache["vector"], json!({f.fp.clone():2}));
    assert_eq!(cache["heads"].as_array().unwrap().len(), 1);
    assert_eq!(
        cache["heads"][0]["device"],
        f.device.record().unwrap().to_dict()
    );
    assert_head(&cache, &put, &signed, &hashed);
    let loaded = membership::load_environment(&f.ctx, &f.env).unwrap();
    assert_eq!(loaded.vector, BTreeMap::from([(f.fp.clone(), 2.into())]));
    assert_eq!(loaded.version_order["s"], json!([V1]));
    assert_eq!(
        loaded.document["secrets"]["s"]["versions"][V1]["status"],
        "staged"
    );
    assert!(loaded.document["secrets"]["s"]["active_version"].is_null());
    assert_eq!(
        f.ctx
            .vault
            .secret_for_trusted_use("s", Some(1.into()))
            .unwrap()
            .expose(),
        VALUE
    );
    let raw = fs::read(f.ctx.state.path.join(f.cache_name())).unwrap();
    assert!(!raw.windows(VALUE.len()).any(|bytes| bytes == VALUE));
    for forbidden in ["sign_seed", "agree_private", "wrapped_dek", "receipt"] {
        assert!(!String::from_utf8_lossy(&raw).contains(forbidden));
    }
}

#[test]
fn newer_live_head_cannot_replace_the_exact_old_cutoff_slot() {
    let f = Fixture::new(OLD);
    let old = f.put(2, OLD + 1, V1);
    f.put(3, commit::now_ms(), V2);
    let signed = old.canonical_json(false).unwrap();
    let hashed = old.canonical_json(true).unwrap();
    let team = f.sync();
    assert_eq!(team.compact(&f.env).unwrap()["removed"], 1);
    assert_eq!(f.cache()["vector"], json!({f.fp.clone():2}));
    assert_head(&f.cache(), &old, &signed, &hashed);
    assert!(!f.path(&f.fp, 2).exists());
    assert!(f.path(&f.fp, 3).is_file());
    let loaded = membership::load_environment(&f.ctx, &f.env).unwrap();
    assert_eq!(loaded.version_order["s"], json!([V1, V2]));
    assert_eq!(
        loaded.document["secrets"]["s"]["versions"]
            .as_object()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn second_compaction_after_context_reopen_preserves_idle_removed_author_and_next_sequence() {
    let f = Fixture::new(OLD);
    let peer = DeviceKey::generate();
    let peer_fp = peer.fingerprint().unwrap();
    f.add(&peer, 2, OLD + 1);
    let idle = f.append(&peer, 1, OLD + 2, vec![f.put_op("idle", V1)]);
    let signed = idle.canonical_json(false).unwrap();
    let hashed = idle.canonical_json(true).unwrap();
    f.put(3, OLD + 3, V1);
    f.append(
        &f.device,
        4,
        OLD + 4,
        vec![json!({"op":"member.remove","fingerprint":peer_fp})],
    );
    let first = f.sync();
    assert_eq!(first.compact(&f.env).unwrap()["removed"], 2);
    assert_eq!(
        f.cache()["vector"],
        json!({f.fp.clone():4,peer_fp.clone():1})
    );
    drop(first);
    let reopened =
        Arc::new(Context::open(&f.ctx.state.path, Config::default(), clock::system()).unwrap());
    let restarted = team(reopened.clone(), f.device.clone(), &f.env);
    let advanced = f.put(5, OLD + 5, V2);
    assert_eq!(restarted.compact(&f.env).unwrap()["removed"], 1);
    let cache = f.cache();
    assert_eq!(cache["vector"], json!({f.fp.clone():5,peer_fp.clone():1}));
    assert_head(&cache, &idle, &signed, &hashed);
    assert_eq!(cache["heads"].as_array().unwrap().len(), 2);
    assert_eq!(
        cache["heads"]
            .as_array()
            .unwrap()
            .iter()
            .find(|head| head["author"] == peer_fp)
            .unwrap()["device"],
        peer.record().unwrap().to_dict()
    );
    assert_head(
        &cache,
        &advanced,
        &advanced.canonical_json(false).unwrap(),
        &advanced.canonical_json(true).unwrap(),
    );
    for (author, seq) in [(&peer_fp, 1), (&f.fp, 3), (&f.fp, 5)] {
        assert!(!f.path(author, seq).exists());
    }
    let loaded = membership::load_environment(&reopened, &f.env).unwrap();
    assert_eq!(loaded.document["members"][&peer_fp]["status"], "removed");
    assert_eq!(loaded.version_order["idle"], json!([V1]));
    assert_eq!(loaded.version_order["s"], json!([V1, V2]));
    let next = f.append(
        &f.device,
        6,
        OLD + 6,
        vec![json!({"op":"settings.update","sync_interval_seconds":19})],
    );
    assert_eq!(next.author_seq, PyInt::from(6));
    assert_eq!(
        membership::load_environment(&reopened, &f.env)
            .unwrap()
            .document["settings"]["sync_interval_seconds"],
        19
    );
}

#[test]
fn all_six_authority_kinds_and_mixed_commits_stay_byte_identical() {
    let f = Fixture::new(OLD);
    let peer = DeviceKey::generate();
    let fp = peer.fingerprint().unwrap();
    f.add(&peer, 2, OLD + 1);
    f.append(
        &f.device,
        3,
        OLD + 2,
        vec![json!({"op":"member.set_role","fingerprint":fp,"role":"admin"})],
    );
    f.append(
        &f.device,
        4,
        OLD + 3,
        vec![json!({"op":"owner.transfer","fingerprint":fp})],
    );
    let new_generation = "fedcba9876543210";
    let wrap =
        envelope::wrap_dek(&[8; 32], &f.env, new_generation, &peer.record().unwrap()).unwrap();
    f.append(
        &peer,
        1,
        OLD + 4,
        vec![json!({"op":"dek.rotate","generation_id":new_generation,"wraps":{fp.clone():wrap}})],
    );
    f.append(
        &f.device,
        5,
        OLD + 5,
        vec![json!({"op":"member.remove","fingerprint":f.fp})],
    );
    f.append(
        &peer,
        2,
        OLD + 6,
        vec![
            f.put_op("mixed", V1),
            json!({"op":"member.set_role","fingerprint":fp,"role":"admin"}),
        ],
    );
    f.append(
        &peer,
        3,
        OLD + 7,
        vec![json!({"op":"settings.update","sync_interval_seconds":23})],
    );
    let expected: BTreeMap<_, _> = [
        (&f.fp, 1),
        (&f.fp, 2),
        (&f.fp, 3),
        (&f.fp, 4),
        (&fp, 1),
        (&f.fp, 5),
        (&fp, 2),
    ]
    .into_iter()
    .map(|(author, seq)| {
        let path = f.path(author, seq);
        (path.clone(), fs::read(path).unwrap())
    })
    .collect();
    // The only active member is the peer; use its actual device for the gate.
    let team = team(f.ctx.clone(), peer, &f.env);
    assert_eq!(team.compact(&f.env).unwrap()["removed"], 1);
    assert!(!f.path(&fp, 3).exists());
    for (path, bytes) in expected {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    assert_eq!(f.cache()["vector"], json!({f.fp.clone():5,fp.clone():3}));
    let loaded = membership::load_environment(&f.ctx, &f.env).unwrap();
    assert_eq!(loaded.document["owner"], fp);
    assert_eq!(loaded.document["members"][&f.fp]["status"], "removed");
    assert_eq!(loaded.version_order["mixed"], json!([V1]));
    assert_eq!(loaded.document["settings"]["sync_interval_seconds"], 23);
}

#[test]
fn legacy_missing_idle_head_refuses_before_new_images_and_preserves_ordinary_reads() {
    let f = Fixture::new(OLD);
    let peer = DeviceKey::generate();
    let fp = peer.fingerprint().unwrap();
    f.add(&peer, 2, OLD + 1);
    f.append(&peer, 1, OLD + 2, vec![f.put_op("idle", V1)]);
    f.append(
        &f.device,
        3,
        OLD + 3,
        vec![json!({"op":"member.remove","fingerprint":fp})],
    );
    let all = CommitStore::new(f.ctx.state, &f.env).all_commits().unwrap();
    let snapshot =
        fold::snapshot_of_prefix(&f.env, all.clone(), f.ctx.state, None, &all, None).unwrap();
    fold::save_snapshot(f.ctx.state, &f.env, &4.into(), &snapshot).unwrap();
    fold::save_snapshot_record(
        f.ctx.state,
        &f.env,
        &4.into(),
        &fold::snapshot_record(None, &all),
    )
    .unwrap();
    fs::remove_file(f.path(&fp, 1)).unwrap();
    let team = f.sync();
    let before = metadata(&f);
    assert_eq!(
        team.compact(&f.env).unwrap_err().reason,
        "team_compaction_head_unavailable"
    );
    assert_eq!(metadata(&f), before);
    assert!(f.cache().is_null());
    assert_eq!(
        membership::load_environment(&f.ctx, &f.env)
            .unwrap()
            .version_order["idle"],
        json!([V1])
    );
    assert!(f.path(&f.fp, 1).exists() && f.path(&f.fp, 2).exists() && f.path(&f.fp, 3).exists());
}

#[test]
fn one_axis_cache_corruption_and_full_record_substitution_never_publish_or_prune() {
    let f = Fixture::new(OLD);
    f.put(2, OLD + 1, V1);
    let team = f.sync();
    team.compact(&f.env).unwrap();
    f.put(3, OLD + 2, V2);
    let original = f.cache();
    let alternative = DeviceKey {
        sign_seed: f.device.sign_seed.clone(),
        agree_private: DeviceKey::generate().agree_private,
    };
    assert_eq!(alternative.fingerprint().unwrap(), f.fp);
    let mut variants = Vec::new();
    for (key, value) in [
        ("author", json!("aaaaaaaaaaaaaaaaaaaaaaaaaa")),
        ("author_seq", json!(1)),
        ("hlc", json!("1-0000")),
        ("commit_hash", json!("0".repeat(64))),
        ("device", alternative.record().unwrap().to_dict()),
    ] {
        let mut changed = original.clone();
        changed["heads"][0][key] = value;
        variants.push(changed);
    }
    for (key, value) in [
        ("env_id", json!("wrong")),
        ("format", json!("unknown")),
        ("extra", json!(true)),
        ("heads", json!([])),
    ] {
        let mut changed = original.clone();
        changed[key] = value;
        variants.push(changed);
    }
    let mut signature = original.clone();
    signature["heads"][0]["commit"]["sig"] = json!("AA==");
    variants.push(signature);
    let mut negative = original.clone();
    negative["vector"][&f.fp] = json!(-1);
    variants.push(negative);
    for changed in variants {
        f.ctx.state.write_json(&f.cache_name(), &changed).unwrap();
        let before = metadata(&f);
        let error = team.compact(&f.env).unwrap_err();
        assert_eq!(error.reason, "team_compaction_head_invalid");
        assert!(error.detail.is_empty());
        assert_eq!(metadata(&f), before);
        assert!(f.path(&f.fp, 3).exists());
    }
    let raw = pyjson::dumps(&original, DumpOptions::pretty_sorted()).unwrap();
    for bytes in [
        format!("{raw}\n"),
        raw.replacen("{", "{\"format\":\"duplicate\",", 1),
    ] {
        fs::write(f.ctx.state.path.join(f.cache_name()), bytes).unwrap();
        let before = metadata(&f);
        assert_eq!(
            team.compact(&f.env).unwrap_err().reason,
            "team_compaction_head_invalid"
        );
        assert_eq!(metadata(&f), before);
    }
}

#[test]
fn conflicting_live_original_at_the_cached_slot_refuses_without_fallback() {
    let f = Fixture::new(OLD);
    f.put(2, OLD + 1, V1);
    let team = f.sync();
    team.compact(&f.env).unwrap();
    let conflicting = commit::sign_commit(
        &f.device,
        &f.env,
        2,
        &format!("{}-0007", OLD + 1),
        &BTreeMap::from([(f.fp.clone(), 1.into())]),
        vec![json!({"op":"settings.update","sync_interval_seconds":31})],
    )
    .unwrap();
    f.ctx
        .state
        .write_json(
            &format!("team/{}/commits/{}/2.json", f.env, f.fp),
            &conflicting.to_dict(),
        )
        .unwrap();
    let before = metadata(&f);
    assert_eq!(
        team.compact(&f.env).unwrap_err().reason,
        "team_compaction_head_invalid"
    );
    assert_eq!(metadata(&f), before);
    assert!(f.path(&f.fp, 2).exists());
}

#[test]
fn no_old_and_fresh_active_member_gate_keep_original_result_schema_and_no_cache() {
    let recent = Fixture::new(commit::now_ms());
    assert_eq!(
        recent.sync().compact(&recent.env).unwrap(),
        json!({"env_id":recent.env,"removed":0,"blocked_by":[],"reason":"no_commit_old_enough"})
    );
    assert!(recent.cache().is_null());
    let f = Fixture::new(OLD);
    f.put(2, OLD + 1, V1);
    let team = f.sync();
    let peer = DeviceKey::generate();
    let fp = peer.fingerprint().unwrap();
    f.add(&peer, 3, commit::now_ms());
    // TeamSync's cached document still predates the normal locked writer.
    assert!(team.document(&f.env).unwrap()["members"].get(&fp).is_none());
    let before = metadata(&f);
    assert_eq!(
        team.compact(&f.env).unwrap(),
        json!({"env_id":f.env,"removed":0,"blocked_by":[fp]})
    );
    assert_eq!(metadata(&f), before);
    assert!(f.path(&f.fp, 2).exists());
}

#[test]
fn legacy_float_opaque_and_deeper_than_checkpoint_values_preserve_original_bytes() {
    let f = Fixture::new(OLD);
    let mut deep = json!("synthetic-opaque");
    for _ in 0..70 {
        deep = json!([deep]);
    }
    let numbers = pyjson::loads(r#"[1.0,-0.0,1e-7,-1844674407370955161600000000001]"#).unwrap();
    let entry = f.append(&f.device, 2, OLD + 1, vec![json!({"op":"settings.update","sync_interval_seconds":17,"opaque":{"deep":deep,"numbers":numbers,"$serde_json::private::RawValue":"literal"}})]);
    let signed = entry.canonical_json(false).unwrap();
    let hashed = entry.canonical_json(true).unwrap();
    assert_eq!(f.sync().compact(&f.env).unwrap()["removed"], 1);
    assert_head(&f.cache(), &entry, &signed, &hashed);
}

#[test]
fn deletion_and_version_revocation_survive_real_compaction_restart_and_cache_loss() {
    let f = Fixture::new(OLD);
    f.put(2, OLD + 1, V1);
    f.put(3, OLD + 2, V2);
    f.append(&f.device, 4, OLD + 3, vec![f.put_op("keep", V1)]);
    let team = f.sync();
    team.publish_fact(
        &f.env,
        "secret_version_revoked",
        json!({"secret_id":"s","version_id":V1}),
    )
    .unwrap();
    team.publish_fact(&f.env, "secret_deleted", json!({"secret_id":"s"}))
        .unwrap();
    let (before_facts, _, _) = sync::load_facts(&f.ctx, &f.env).unwrap();
    let hashes: Vec<_> = before_facts.tombstone_facts.keys().cloned().collect();
    assert_eq!(hashes.len(), 1);
    assert_eq!(team.compact(&f.env).unwrap()["removed"], 3);
    let late = "abababababababab";
    f.put(5, OLD + 4, late);
    assert_eq!(team.compact(&f.env).unwrap()["removed"], 1);
    let reopened =
        Arc::new(Context::open(&f.ctx.state.path, Config::default(), clock::system()).unwrap());
    let restarted = team_with_device(&reopened, &f.device, &f.env);
    let loaded = membership::load_environment(&reopened, &f.env).unwrap();
    assert_eq!(loaded.version_order["s"], json!([V1, V2, late]));
    assert_eq!(loaded.document["secrets"]["s"]["deleted"], true);
    for version in [V1, V2, late] {
        assert_eq!(
            loaded.document["secrets"]["s"]["versions"][version]["status"],
            "revoked"
        );
    }
    assert_eq!(
        reopened
            .vault
            .secret_for_trusted_use("s", None)
            .unwrap_err()
            .reason,
        "secret_deleted"
    );
    assert_eq!(
        reopened
            .vault
            .secret_for_trusted_use("keep", Some(1.into()))
            .unwrap()
            .expose(),
        VALUE
    );
    assert!(
        !zeropw::vault::Vault::BACKUP_DOCS
            .iter()
            .any(|path| path.contains("compaction_heads"))
    );
    let backup = f._root.path().join("synthetic-backup.json");
    reopened.vault.backup(&backup).unwrap();
    let archive = pyjson::loads(&fs::read_to_string(backup).unwrap()).unwrap();
    assert!(
        !archive["documents"]
            .as_object()
            .unwrap()
            .keys()
            .any(|path| path.contains("compaction_heads"))
    );
    fs::remove_file(f.ctx.state.path.join(f.cache_name())).unwrap();
    assert_eq!(
        restarted.compact(&f.env).unwrap_err().reason,
        "team_compaction_head_unavailable"
    );
    let (after, _, _) = sync::load_facts(&reopened, &f.env).unwrap();
    assert_eq!(
        after.tombstone_facts.keys().cloned().collect::<Vec<_>>(),
        hashes
    );
    assert_eq!(
        reopened
            .vault
            .secret_for_trusted_use("s", None)
            .unwrap_err()
            .reason,
        "secret_deleted"
    );
}

#[test]
fn reserved_number_legacy_head_refuses_real_compaction_before_new_publication() {
    let f = Fixture::new(OLD);
    f.append(
        &f.device,
        2,
        OLD + 1,
        vec![json!({"op":"settings.update",
        "sync_interval_seconds":17,"opaque":{"$serde_json::private::Number":"123"}})],
    );
    let team = f.sync();
    let before = metadata(&f);
    assert_eq!(
        team.compact(&f.env).unwrap_err().reason,
        "team_compaction_head_invalid"
    );
    assert_eq!(metadata(&f), before);
    assert!(f.path(&f.fp, 2).exists());
}

#[cfg(unix)]
#[test]
fn symlinked_state_root_with_plain_slash_and_dot_spellings_refuses_before_publication() {
    for suffix in ["", "/", "/."] {
        let f = Fixture::new(OLD);
        f.put(2, OLD + 1, V1);
        let alias = f._root.path().join("state-link");
        std::os::unix::fs::symlink(&f.ctx.state.path, &alias).unwrap();
        let mut spelling = alias.as_os_str().to_os_string();
        spelling.push(suffix);
        let path = std::path::PathBuf::from(spelling);
        let ctx = Arc::new(Context::open(&path, Config::default(), clock::system()).unwrap());
        assert_eq!(ctx.state.path.as_os_str(), path.as_os_str());
        let team = team(ctx, f.device.clone(), &f.env);
        // Registration/refold is complete before the refusal baseline.
        let before = metadata(&f);
        let init = fs::read(f.path(&f.fp, 1)).unwrap();
        let data = fs::read(f.path(&f.fp, 2)).unwrap();
        let error = team.compact(&f.env).unwrap_err();
        assert_eq!(error.reason, "team_compaction_layout_unsupported");
        assert!(error.detail.is_empty());
        assert_eq!(metadata(&f), before);
        assert_eq!(fs::read(f.path(&f.fp, 1)).unwrap(), init);
        assert_eq!(fs::read(f.path(&f.fp, 2)).unwrap(), data);
        let loaded = membership::load_environment(&f.ctx, &f.env).unwrap();
        assert_eq!(loaded.version_order["s"], json!([V1]));
        assert_eq!(loaded.vector, BTreeMap::from([(f.fp.clone(), 2.into())]));
    }
}

#[cfg(unix)]
#[test]
fn symlinked_team_and_environment_directories_refuse_without_new_images_or_unlink() {
    for level in ["team", "env"] {
        let f = Fixture::new(OLD);
        f.put(2, OLD + 1, V1);
        let team = f.sync();
        let before = metadata(&f);
        let init = fs::read(f.path(&f.fp, 1)).unwrap();
        let data = fs::read(f.path(&f.fp, 2)).unwrap();
        let directory = if level == "team" {
            f.ctx.state.path.join("team")
        } else {
            f.ctx.state.path.join(format!("team/{}", f.env))
        };
        let retained = f._root.path().join("retained-environment-path");
        fs::rename(&directory, &retained).unwrap();
        std::os::unix::fs::symlink(&retained, &directory).unwrap();
        let error = team.compact(&f.env).unwrap_err();
        assert_eq!(error.reason, "team_compaction_layout_unsupported");
        assert!(error.detail.is_empty());
        assert_eq!(metadata(&f), before);
        assert_eq!(fs::read(f.path(&f.fp, 1)).unwrap(), init);
        assert_eq!(fs::read(f.path(&f.fp, 2)).unwrap(), data);
        assert_eq!(
            membership::load_environment(&f.ctx, &f.env)
                .unwrap()
                .version_order["s"],
            json!([V1])
        );
    }
}

#[test]
fn missing_prospective_paths_and_regular_repeat_destinations_compact_normally() {
    let f = Fixture::new(OLD);
    let put = f.put(2, OLD + 1, V1);
    let signed = put.canonical_json(false).unwrap();
    let hashed = put.canonical_json(true).unwrap();
    let team = f.sync();
    let directory = f.ctx.state.path.join(format!("team/{}", f.env));
    for name in ["snapshots", "snapshot_records"] {
        let path = directory.join(name);
        if path.exists() {
            fs::remove_dir_all(path).unwrap();
        }
    }
    assert!(!directory.join("compaction_heads.json").exists());
    assert_eq!(
        team.compact(&f.env).unwrap(),
        json!({"env_id":f.env,"removed":1,"blocked_by":[]})
    );
    assert!(!f.path(&f.fp, 2).exists());
    assert!(directory.join("snapshots/2.json").is_file());
    assert!(directory.join("snapshot_records/2.json").is_file());
    assert_head(&f.cache(), &put, &signed, &hashed);
    let before = metadata(&f);
    assert_eq!(
        team.compact(&f.env).unwrap(),
        json!({"env_id":f.env,"removed":0,"blocked_by":[]})
    );
    assert_eq!(f.cache()["vector"], json!({f.fp.clone():2}));
    assert_eq!(
        fs::read(directory.join("compaction_heads.json")).unwrap(),
        before["cache"]
    );
    assert_head(&f.cache(), &put, &signed, &hashed);
    assert_eq!(
        membership::load_environment(&f.ctx, &f.env)
            .unwrap()
            .version_order["s"],
        json!([V1])
    );
}
fn team_with_device(ctx: &Arc<Context>, device: &DeviceKey, env: &str) -> Arc<TeamSync> {
    team(ctx.clone(), device.clone(), env)
}

// New 01/02 fixtures use receipt for every original, including bootstrap.
fn received_fixture() -> Fixture {
    let root = TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            root.path().join("state"),
            "synthetic-admin",
            "synthetic-recovery",
            Config::default(),
            clock::system(),
        )
        .unwrap(),
    );
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let fp = device.fingerprint().unwrap();
    let env = format!("{fp}-0123456789abcdef0123456789abcdef");
    let wrap = envelope::wrap_dek(&[7; 32], &env, G, &device.record().unwrap()).unwrap();
    let init = commit::sign_commit(
        &device,
        &env,
        1,
        "1000000-0000",
        &BTreeMap::new(),
        vec![
            json!({"op":"env.init","owner_device":device.record().unwrap().to_dict(),
            "owner_name":"synthetic-owner","generation_id":G,"wraps":{fp.clone():wrap}}),
        ],
    )
    .unwrap();
    assert_eq!(
        commit::receive_commit(
            &CommitStore::new(ctx.state, &env),
            &init,
            OLD,
            Some(ctx.audit)
        )
        .unwrap(),
        "accepted"
    );
    Fixture {
        _root: root,
        ctx,
        device,
        fp,
        env,
    }
}

fn candidate(f: &Fixture, device: &DeviceKey, seq: i64, hlc: &str, ops: Vec<Value>) -> Commit {
    commit::sign_commit(
        device,
        &f.env,
        seq,
        hlc,
        &CommitStore::new(f.ctx.state, &f.env).vector().unwrap(),
        ops,
    )
    .unwrap()
}

fn received(f: &Fixture, device: &DeviceKey, seq: i64, hlc: &str, ops: Vec<Value>) -> Commit {
    let original = candidate(f, device, seq, hlc, ops);
    assert_eq!(
        commit::receive_commit(
            &CommitStore::new(f.ctx.state, &f.env),
            &original,
            OLD + 100,
            Some(f.ctx.audit),
        )
        .unwrap(),
        "accepted"
    );
    original
}

fn member_op(f: &Fixture, device: &DeviceKey, role: &str) -> Value {
    let wrap = envelope::wrap_dek(&[7; 32], &f.env, G, &device.record().unwrap()).unwrap();
    json!({"op":"member.add","device":device.record().unwrap().to_dict(),
        "name":"synthetic-peer","role":role,"wraps":{G:wrap}})
}

fn rejection_events(f: &Fixture) -> Vec<Value> {
    f.ctx
        .audit
        .iter_records()
        .unwrap()
        .into_iter()
        .filter(|entry| entry["event"] == "team_commit_rejected")
        .collect()
}

fn inventory(f: &Fixture, directory: &str) -> BTreeMap<String, Vec<u8>> {
    let root = f.ctx.state.path.join(format!("team/{}/{directory}", f.env));
    let mut files = BTreeMap::new();
    if root.is_dir() {
        for entry in fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            files.insert(
                path.file_name().unwrap().to_str().unwrap().to_owned(),
                fs::read(path).unwrap(),
            );
        }
    }
    files
}

fn receipt_compacted() -> (Fixture, Arc<TeamSync>, Commit) {
    let f = received_fixture();
    let head = received(&f, &f.device, 2, "1000001-0007", vec![f.put_op("s", V1)]);
    let team = f.sync();
    assert_eq!(team.compact(&f.env).unwrap()["removed"], 1);
    assert!(!f.path(&f.fp, 2).exists());
    assert_eq!(f.cache()["vector"], json!({f.fp.clone():2}));
    (f, team, head)
}

#[test]
fn compaction_heads_01_receipt_skipped_and_demoted_announcements_keep_exact_public_heads() {
    for demoted in [false, true] {
        let f = received_fixture();
        let b = DeviceKey::generate();
        let y = DeviceKey::generate();
        let bfp = b.fingerprint().unwrap();
        let yfp = y.fingerprint().unwrap();
        received(
            &f,
            &f.device,
            2,
            "1000001-0000",
            vec![member_op(&f, &b, if demoted { "admin" } else { "user" })],
        );
        if demoted {
            received(
                &f,
                &f.device,
                3,
                "1000002-0000",
                vec![json!({"op":"member.set_role","fingerprint":bfp,"role":"user"})],
            );
        }
        // Receipt normalizes public records; the original signed op keeps all
        // extra fields and legacy array/base64 coercions byte for byte.
        let mut announce = member_op(&f, &y, "admin");
        for field in ["sign_pub", "agree_pub", "sig"] {
            announce["device"][field] = json!([announce["device"][field].clone()]);
        }
        announce["device"]["extra"] = json!({"literal":"public-extra"});
        let skipped = received(
            &f,
            &b,
            1,
            if demoted {
                "1000003-0000"
            } else {
                "1000002-0000"
            },
            vec![announce],
        );
        let skipped_bytes = fs::read(f.path(&bfp, 1)).unwrap();
        let yhead = received(
            &f,
            &y,
            1,
            if demoted {
                "1000004-0000"
            } else {
                "1000003-0000"
            },
            vec![f.put_op("unadmitted", V1)],
        );
        let signed = yhead.canonical_json(false).unwrap();
        let hashed = yhead.canonical_json(true).unwrap();
        received(
            &f,
            &f.device,
            if demoted { 4 } else { 3 },
            if demoted {
                "1000005-0000"
            } else {
                "1000004-0000"
            },
            vec![f.put_op("s", V1)],
        );
        let remove = received(
            &f,
            &f.device,
            if demoted { 5 } else { 4 },
            if demoted {
                "1000006-0000"
            } else {
                "1000005-0000"
            },
            vec![json!({"op":"member.remove","fingerprint":bfp})],
        );
        let before = membership::load_environment(&f.ctx, &f.env).unwrap();
        assert!(
            before
                .skipped
                .iter()
                .any(|(hash, _, why)| hash == &skipped.hash().unwrap() && why == "not_admin")
        );
        assert!(before.document["members"].get(&yfp).is_none());
        let team = f.sync();
        assert_eq!(
            team.compact(&f.env).unwrap(),
            json!({"env_id":f.env,"removed":2,"blocked_by":[]})
        );
        assert_eq!(
            f.cache()["vector"],
            json!({f.fp.clone():if demoted {5} else {4},bfp.clone():1,yfp.clone():1})
        );
        assert_eq!(fs::read(f.path(&bfp, 1)).unwrap(), skipped_bytes);
        assert!(!f.path(&yfp, 1).exists());
        assert_head(&f.cache(), &yhead, &signed, &hashed);
        let yslot = f.cache()["heads"]
            .as_array()
            .unwrap()
            .iter()
            .find(|head| head["author"] == yfp)
            .unwrap()
            .clone();
        assert_eq!(yslot["device"], y.record().unwrap().to_dict());
        let loaded = membership::load_environment(&f.ctx, &f.env).unwrap();
        assert!(loaded.document["members"].get(&yfp).is_none());
        assert!(
            loaded.document["dek"]["generations"][G]["wraps"]
                .get(&yfp)
                .is_none()
        );
        assert!(loaded.document["secrets"].get("unadmitted").is_none());
        assert_eq!(loaded.version_order["s"], json!([V1]));
        assert!(
            f.ctx
                .vault
                .secret_for_trusted_use("unadmitted", None)
                .is_err()
        );
        // An actual unreceipted fact from Y is still refused by unchanged
        // fact admission; its cached public record supplies no authority.
        let fact = sync::sign_fact(
            &y,
            &f.env,
            "secret_deleted",
            json!({"secret_id":"s"}),
            "1000010-0000",
        )
        .unwrap();
        f.ctx
            .state
            .append_line(
                &format!("team/{}/facts.jsonl", f.env),
                &String::from_utf8(canon(&fact.to_dict())).unwrap(),
            )
            .unwrap();
        let (facts, hashes, _) = sync::load_facts(&f.ctx, &f.env).unwrap();
        assert!(!facts.deleted_secrets.contains("s"));
        assert!(!hashes.contains(&fact.hash().unwrap()));
        let reopened =
            Arc::new(Context::open(&f.ctx.state.path, Config::default(), clock::system()).unwrap());
        let restarted = team_with_device(&reopened, &f.device, &f.env);
        assert_eq!(restarted.compact(&f.env).unwrap()["removed"], 0);
        assert_head(&f.cache(), &yhead, &signed, &hashed);
        received(
            &f,
            &f.device,
            if demoted { 6 } else { 5 },
            "1000020-0000",
            vec![json!({"op":"settings.update","sync_interval_seconds":29})],
        );
        assert_eq!(restarted.compact(&f.env).unwrap()["removed"], 1);
        assert_head(&f.cache(), &yhead, &signed, &hashed);
        assert_eq!(
            fs::read(f.path(&f.fp, if demoted { 5 } else { 4 })).unwrap(),
            pyjson::dumps(&remove.to_dict(), DumpOptions::pretty_sorted())
                .unwrap()
                .into_bytes()
        );
    }
}

#[test]
fn compaction_heads_02_receipt_and_live_receipt_reject_deleted_predecessor_regression() {
    for live in [false, true] {
        for hlc in ["1000001-0007", "1000000-0009", "1000001-0008"] {
            let (f, team, original) = receipt_compacted();
            let original_signed = original.canonical_json(false).unwrap();
            let original_hashed = original.canonical_json(true).unwrap();
            let next = candidate(
                &f,
                &f.device,
                3,
                hlc,
                vec![json!({"op":"settings.update","sync_interval_seconds":31})],
            );
            let signed = next.canonical_json(false).unwrap();
            let hashed = next.canonical_json(true).unwrap();
            let before = metadata(&f);
            let store = CommitStore::new(f.ctx.state, &f.env);
            let outcome = if live {
                commit::receive_live_commit(&store, &next, OLD + 10, Some(f.ctx.audit))
            } else {
                commit::receive_commit(&store, &next, OLD + 10, Some(f.ctx.audit))
            }
            .unwrap();
            if hlc == "1000001-0008" {
                assert_eq!(outcome, "accepted");
                assert_eq!(store.last_seq(&f.fp).unwrap(), PyInt::from(3));
                assert!(rejection_events(&f).is_empty());
                assert_eq!(team.compact(&f.env).unwrap()["removed"], 1);
                assert_eq!(f.cache()["vector"], json!({f.fp.clone():3}));
                assert_head(&f.cache(), &next, &signed, &hashed);
                let reopened =
                    Context::open(&f.ctx.state.path, Config::default(), clock::system()).unwrap();
                assert_eq!(
                    membership::load_environment(&reopened, &f.env)
                        .unwrap()
                        .document["settings"]["sync_interval_seconds"],
                    31
                );
            } else {
                assert_eq!(outcome, "rejected");
                assert_eq!(store.last_seq(&f.fp).unwrap(), PyInt::from(2));
                assert!(!f.path(&f.fp, 3).exists());
                assert_eq!(metadata(&f), before);
                let rejected = inventory(&f, "rejected");
                assert_eq!(rejected.len(), 1);
                let mut quarantined =
                    pyjson::loads(std::str::from_utf8(rejected.values().next().unwrap()).unwrap())
                        .unwrap();
                assert_eq!(quarantined["rejected_reason"], "team_hlc_not_monotone");
                quarantined
                    .as_object_mut()
                    .unwrap()
                    .remove("rejected_reason");
                assert_eq!(canon(&quarantined), hashed);
                let events = rejection_events(&f);
                assert_eq!(events.len(), 1);
                assert_eq!(events[0]["reason"], "team_hlc_not_monotone");
                assert_eq!(events[0]["author_seq"], 3);
                assert_head(&f.cache(), &original, &original_signed, &original_hashed);
            }
            assert!(inventory(&f, "deferred").is_empty());
            assert_eq!(
                membership::load_environment(&f.ctx, &f.env)
                    .unwrap()
                    .version_order["s"],
                json!([V1])
            );
        }
    }
}

#[test]
fn compaction_heads_02_real_deferred_release_uses_cache_and_preserves_local_error_original() {
    for hlc in ["1000001-0007", "1000000-0009", "1000001-0008"] {
        let f = received_fixture();
        let next = candidate(
            &f,
            &f.device,
            3,
            hlc,
            vec![json!({"op":"settings.update","sync_interval_seconds":37})],
        );
        let store = CommitStore::new(f.ctx.state, &f.env);
        assert_eq!(
            commit::receive_commit(&store, &next, 0, Some(f.ctx.audit)).unwrap(),
            "deferred"
        );
        let deferred = inventory(&f, "deferred");
        assert!(
            store
                .release_deferred(OLD + 10, Some(f.ctx.audit))
                .unwrap()
                .is_empty()
        );
        assert_eq!(inventory(&f, "deferred"), deferred);
        received(&f, &f.device, 2, "1000001-0007", vec![f.put_op("s", V1)]);
        let team = f.sync();
        assert_eq!(team.compact(&f.env).unwrap()["removed"], 1);
        let saved = fs::read(f.ctx.state.path.join(f.cache_name())).unwrap();
        fs::write(
            f.ctx.state.path.join(f.cache_name()),
            b"{corrupt-local-cache",
        )
        .unwrap();
        let before = metadata(&f);
        let error = store
            .release_deferred(OLD + 10, Some(f.ctx.audit))
            .unwrap_err();
        assert_eq!(error.reason, "team_compaction_head_invalid");
        assert!(error.detail.is_empty());
        assert_eq!(metadata(&f), before);
        assert_eq!(inventory(&f, "deferred"), deferred);
        assert!(inventory(&f, "rejected").is_empty());
        assert!(rejection_events(&f).is_empty());
        // Synthetic restoration of exact saved fixture bytes, not a product
        // recovery operation or permission to discard bad evidence.
        fs::write(f.ctx.state.path.join(f.cache_name()), saved).unwrap();
        let reopened =
            Context::open(&f.ctx.state.path, Config::default(), clock::system()).unwrap();
        let reopened_store = CommitStore::new(reopened.state, &f.env);
        let released = reopened_store
            .release_deferred(OLD + 10, Some(reopened.audit))
            .unwrap();
        if hlc == "1000001-0008" {
            assert_eq!(released.len(), 1);
            assert_eq!(
                released[0].canonical_json(true).unwrap(),
                next.canonical_json(true).unwrap()
            );
            assert_eq!(reopened_store.last_seq(&f.fp).unwrap(), PyInt::from(3));
            assert!(rejection_events(&f).is_empty());
        } else {
            assert!(released.is_empty());
            assert_eq!(reopened_store.last_seq(&f.fp).unwrap(), PyInt::from(2));
            assert!(!f.path(&f.fp, 3).exists());
            let events = rejection_events(&f);
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["reason"], "team_hlc_not_monotone");
        }
        assert!(
            reopened_store
                .release_deferred(OLD + 10, Some(reopened.audit))
                .unwrap()
                .is_empty()
        );
        assert!(inventory(&f, "deferred").is_empty());
    }
}

#[test]
fn compaction_heads_02_existing_regression_is_preserved_and_new_receipt_exceeds_both_clocks() {
    let (f, team, _) = receipt_compacted();
    // Explicit pre-fix fixture: trusted sequence-only append can reproduce an
    // already accepted signed regression. It is not the receipt fix's oracle.
    let regressed = candidate(
        &f,
        &f.device,
        3,
        "1000000-0009",
        vec![json!({"op":"settings.update","sync_interval_seconds":41})],
    );
    CommitStore::new(f.ctx.state, &f.env)
        .append(&regressed)
        .unwrap();
    let bytes = fs::read(f.path(&f.fp, 3)).unwrap();
    let before = metadata(&f);
    for _ in 0..2 {
        assert_eq!(
            team.compact(&f.env).unwrap_err().reason,
            "team_compaction_head_invalid"
        );
        assert_eq!(metadata(&f), before);
        assert_eq!(fs::read(f.path(&f.fp, 3)).unwrap(), bytes);
    }
    let reopened =
        Arc::new(Context::open(&f.ctx.state.path, Config::default(), clock::system()).unwrap());
    let restarted = team_with_device(&reopened, &f.device, &f.env);
    assert_eq!(
        restarted.compact(&f.env).unwrap_err().reason,
        "team_compaction_head_invalid"
    );
    let insufficient = candidate(
        &f,
        &f.device,
        4,
        "1000001-0007",
        vec![json!({"op":"settings.update","sync_interval_seconds":43})],
    );
    assert_eq!(
        commit::receive_commit(
            &CommitStore::new(f.ctx.state, &f.env),
            &insufficient,
            OLD + 10,
            Some(f.ctx.audit)
        )
        .unwrap(),
        "rejected"
    );
    assert_eq!(fs::read(f.path(&f.fp, 3)).unwrap(), bytes);
    assert_eq!(metadata(&f), before);
    let valid = received(
        &f,
        &f.device,
        4,
        "1000001-0008",
        vec![json!({"op":"settings.update","sync_interval_seconds":47})],
    );
    let signed = valid.canonical_json(false).unwrap();
    let hashed = valid.canonical_json(true).unwrap();
    assert_eq!(restarted.compact(&f.env).unwrap()["removed"], 2);
    assert_eq!(f.cache()["vector"], json!({f.fp.clone():4}));
    assert_head(&f.cache(), &valid, &signed, &hashed);
}

#[test]
fn compaction_heads_02_evidence_failures_are_local_errors_without_peer_quarantine() {
    for mutation in [
        "json",
        "directory",
        "oversize",
        "record",
        "live_conflict",
        "missing_coverage",
        "ahead",
    ] {
        let (f, _team, _) = receipt_compacted();
        let next = candidate(
            &f,
            &f.device,
            3,
            "1000001-0008",
            vec![json!({"op":"settings.update","sync_interval_seconds":53})],
        );
        let cache_path = f.ctx.state.path.join(f.cache_name());
        match mutation {
            "json" => fs::write(&cache_path, b"{invalid-json").unwrap(),
            "directory" => {
                fs::remove_file(&cache_path).unwrap();
                fs::create_dir(&cache_path).unwrap();
            }
            "oversize" => fs::File::create(&cache_path)
                .unwrap()
                .set_len(16_777_217)
                .unwrap(),
            "record" => {
                let alternative = DeviceKey {
                    sign_seed: f.device.sign_seed.clone(),
                    agree_private: DeviceKey::generate().agree_private,
                };
                let mut cache = f.cache();
                cache["heads"][0]["device"] = alternative.record().unwrap().to_dict();
                f.ctx.state.write_json(&f.cache_name(), &cache).unwrap();
            }
            "live_conflict" => {
                let conflicting = candidate(
                    &f,
                    &f.device,
                    2,
                    "1000001-0007",
                    vec![json!({"op":"settings.update","sync_interval_seconds":59})],
                );
                f.ctx
                    .state
                    .write_json(
                        &format!("team/{}/commits/{}/2.json", f.env, f.fp),
                        &conflicting.to_dict(),
                    )
                    .unwrap();
            }
            "missing_coverage" => {
                // Leave ordinary vector2 in a newer regular snapshot while its
                // component is below cached2: no implicit cache sequence floor.
                let mut snapshot = f
                    .ctx
                    .state
                    .read_json(&format!("team/{}/snapshots/2.json", f.env), Value::Null)
                    .unwrap();
                snapshot["vector"][&f.fp] = json!(1);
                f.ctx
                    .state
                    .write_json(&format!("team/{}/snapshots/2.json", f.env), &snapshot)
                    .unwrap();
                // A real live2 keeps candidate3 exactly next despite S=1.
                let head = Commit::from_dict(&f.cache()["heads"][0]["commit"]).unwrap();
                f.ctx
                    .state
                    .write_json(
                        &format!("team/{}/commits/{}/2.json", f.env, f.fp),
                        &head.to_dict(),
                    )
                    .unwrap();
            }
            "ahead" => {
                let mut cache = f.cache();
                cache["vector"][&f.fp] = json!(3);
                cache["heads"][0]["author_seq"] = json!(3);
                cache["heads"][0]["hlc"] = json!(next.hlc);
                cache["heads"][0]["commit_hash"] = json!(next.hash().unwrap());
                cache["heads"][0]["commit"] = next.to_dict();
                f.ctx.state.write_json(&f.cache_name(), &cache).unwrap();
            }
            _ => unreachable!(),
        }
        let before = metadata(&f);
        let store = CommitStore::new(f.ctx.state, &f.env);
        let vector = store.vector().unwrap();
        let error = commit::receive_commit(&store, &next, OLD + 10, Some(f.ctx.audit)).unwrap_err();
        assert_eq!(
            error.reason,
            if mutation == "oversize" {
                "team_compaction_head_limit_exceeded"
            } else {
                "team_compaction_head_invalid"
            }
        );
        assert!(error.detail.is_empty());
        assert_eq!(metadata(&f), before);
        assert_eq!(store.vector().unwrap(), vector);
        assert!(!f.path(&f.fp, 3).exists());
        assert!(inventory(&f, "rejected").is_empty());
        assert!(inventory(&f, "deferred").is_empty());
        assert!(rejection_events(&f).is_empty());
        // Reads/derive deliberately do not consult cache validity.
        assert_eq!(
            membership::load_environment(&f.ctx, &f.env)
                .unwrap()
                .version_order["s"],
            json!([V1])
        );
        assert_eq!(
            f.ctx
                .vault
                .secret_for_trusted_use("s", Some(1.into()))
                .unwrap()
                .expose(),
            VALUE
        );
    }
}

#[test]
fn compaction_heads_02_older_cache_requires_live_exact_predecessor_and_preserves_legacy_absence() {
    for missing in [false, true] {
        let (f, _team, _) = receipt_compacted();
        received(
            &f,
            &f.device,
            3,
            "1000002-0007",
            vec![json!({"op":"settings.update","sync_interval_seconds":61})],
        );
        let all = CommitStore::new(f.ctx.state, &f.env).all_commits().unwrap();
        let snapshot =
            fold::snapshot_of_prefix(&f.env, all.clone(), f.ctx.state, None, &all, None).unwrap();
        fold::save_snapshot(f.ctx.state, &f.env, &3.into(), &snapshot).unwrap();
        if missing {
            fs::remove_file(f.path(&f.fp, 3)).unwrap();
        }
        let next = candidate(
            &f,
            &f.device,
            4,
            "1000003-0000",
            vec![json!({"op":"settings.update","sync_interval_seconds":67})],
        );
        let before = metadata(&f);
        let store = CommitStore::new(f.ctx.state, &f.env);
        if missing {
            let error =
                commit::receive_commit(&store, &next, OLD + 10, Some(f.ctx.audit)).unwrap_err();
            assert_eq!(error.reason, "team_compaction_head_unavailable");
            assert!(error.detail.is_empty());
            assert_eq!(metadata(&f), before);
            assert_eq!(store.last_seq(&f.fp).unwrap(), PyInt::from(3));
            assert!(rejection_events(&f).is_empty());
            // Actual cache loss is indistinguishable from genuine legacy
            // absence. Receipt keeps its previous live-only behavior.
            fs::remove_file(f.ctx.state.path.join(f.cache_name())).unwrap();
        }
        assert_eq!(
            commit::receive_commit(&store, &next, OLD + 10, Some(f.ctx.audit)).unwrap(),
            "accepted"
        );
        assert_eq!(store.last_seq(&f.fp).unwrap(), PyInt::from(4));
        assert_eq!(
            membership::load_environment(&f.ctx, &f.env)
                .unwrap()
                .version_order["s"],
            json!([V1])
        );
    }
}

#[test]
fn compaction_heads_02_cache_does_not_change_gap_unknown_duplicate_or_deferred_statuses() {
    let (f, _team, original) = receipt_compacted();
    let store = CommitStore::new(f.ctx.state, &f.env);
    let gap = candidate(
        &f,
        &f.device,
        4,
        "1000002-0000",
        vec![json!({"op":"settings.update","sync_interval_seconds":71})],
    );
    let unknown = DeviceKey::generate();
    let unknown_commit = candidate(
        &f,
        &unknown,
        1,
        "1000002-0000",
        vec![json!({"op":"settings.update","sync_interval_seconds":73})],
    );
    let before = metadata(&f);
    for original in [&gap, &unknown_commit] {
        assert_eq!(
            commit::receive_live_commit(&store, original, OLD + 10, Some(f.ctx.audit)).unwrap(),
            "early"
        );
    }
    assert!(inventory(&f, "rejected").is_empty());
    assert!(rejection_events(&f).is_empty());
    assert_eq!(metadata(&f), before);
    assert_eq!(
        commit::receive_commit(&store, &gap, OLD + 10, Some(f.ctx.audit)).unwrap(),
        "rejected"
    );
    assert_eq!(
        rejection_events(&f).last().unwrap()["reason"],
        "team_seq_gap"
    );
    assert_eq!(
        commit::receive_commit(&store, &unknown_commit, OLD + 10, Some(f.ctx.audit)).unwrap(),
        "rejected"
    );
    assert_eq!(
        rejection_events(&f).last().unwrap()["reason"],
        "team_author_unknown"
    );
    assert_eq!(
        commit::receive_commit(&store, &original, OLD + 10, Some(f.ctx.audit)).unwrap(),
        "rejected"
    );
    assert_eq!(
        rejection_events(&f).last().unwrap()["reason"],
        "team_author_equivocation"
    );
    // Original pruned deferred evidence is dropped, unlike pruned receipt.
    store.defer(&original).unwrap();
    let count = rejection_events(&f).len();
    assert!(
        store
            .release_deferred(OLD + 10, Some(f.ctx.audit))
            .unwrap()
            .is_empty()
    );
    assert_eq!(rejection_events(&f).len(), count);
    let future = candidate(
        &f,
        &f.device,
        4,
        "2000000-0000",
        vec![json!({"op":"settings.update","sync_interval_seconds":79})],
    );
    assert_eq!(
        commit::receive_live_commit(&store, &future, OLD, Some(f.ctx.audit)).unwrap(),
        "deferred"
    );
    let waits = candidate(
        &f,
        &f.device,
        5,
        "2000001-0000",
        vec![json!({"op":"settings.update","sync_interval_seconds":83})],
    );
    assert!(commit::waits_on_deferred(&store, &waits).unwrap());
    assert_eq!(store.last_seq(&f.fp).unwrap(), PyInt::from(2));
    let next = received(
        &f,
        &f.device,
        3,
        "1000001-0008",
        vec![json!({"op":"settings.update","sync_interval_seconds":89})],
    );
    assert_eq!(
        commit::receive_commit(&store, &next, OLD + 10, Some(f.ctx.audit)).unwrap(),
        "duplicate"
    );
    let conflict = candidate(
        &f,
        &f.device,
        3,
        "1000001-0008",
        vec![json!({"op":"settings.update","sync_interval_seconds":97})],
    );
    assert_eq!(
        commit::receive_commit(&store, &conflict, OLD + 10, Some(f.ctx.audit)).unwrap(),
        "rejected"
    );
    assert_eq!(
        rejection_events(&f).last().unwrap()["reason"],
        "team_author_equivocation"
    );
    // Matching deferred duplicate drops, conflicting duplicate quarantines.
    for deferred in [&next, &conflict] {
        store.defer(deferred).unwrap();
        assert!(
            store
                .release_deferred(OLD + 10, Some(f.ctx.audit))
                .unwrap()
                .is_empty()
        );
    }
    assert_eq!(
        store
            .get(&f.fp, 3)
            .unwrap()
            .unwrap()
            .canonical_json(true)
            .unwrap(),
        next.canonical_json(true).unwrap()
    );
    assert_eq!(metadata(&f), before);
}

#[test]
fn compaction_heads_01_later_conflicting_record_cannot_override_and_earlier_arrival_refuses() {
    for earlier in [false, true] {
        let f = received_fixture();
        let b = DeviceKey::generate();
        let x = DeviceKey::generate();
        let y = DeviceKey::generate();
        let alternative = DeviceKey {
            sign_seed: y.sign_seed.clone(),
            agree_private: DeviceKey::generate().agree_private,
        };
        let bfp = b.fingerprint().unwrap();
        let xfp = x.fingerprint().unwrap();
        let yfp = y.fingerprint().unwrap();
        assert_eq!(alternative.fingerprint().unwrap(), yfp);
        received(
            &f,
            &f.device,
            2,
            "1000001-0000",
            vec![member_op(&f, &b, "user"), member_op(&f, &x, "user")],
        );
        received(&f, &b, 1, "1000003-0000", vec![member_op(&f, &y, "admin")]);
        let head = received(&f, &y, 1, "1000004-0000", vec![f.put_op("unadmitted", V1)]);
        let signed = head.canonical_json(false).unwrap();
        let hashed = head.canonical_json(true).unwrap();
        received(
            &f,
            &f.device,
            3,
            "1000005-0000",
            vec![
                json!({"op":"member.remove","fingerprint":bfp}),
                json!({"op":"member.remove","fingerprint":xfp}),
            ],
        );
        let team = f.sync();
        assert_eq!(team.compact(&f.env).unwrap()["removed"], 1);
        assert_eq!(
            f.cache()["vector"],
            json!({f.fp.clone():3,bfp.clone():1,yfp.clone():1})
        );
        let first_cache = fs::read(f.ctx.state.path.join(f.cache_name())).unwrap();
        // X's first signed receipt can arrive after compaction with a lower
        // HLC than B's first Y announcement. Receipt still supplies no role.
        let incoming = received(
            &f,
            &x,
            1,
            if earlier {
                "1000002-0000"
            } else {
                "1000006-0000"
            },
            vec![member_op(&f, &alternative, "admin")],
        );
        let incoming_bytes = fs::read(f.path(&xfp, 1)).unwrap();
        let before = metadata(&f);
        if earlier {
            assert_eq!(
                team.compact(&f.env).unwrap_err().reason,
                "team_compaction_head_invalid"
            );
            assert_eq!(metadata(&f), before);
            assert_eq!(
                fs::read(f.ctx.state.path.join(f.cache_name())).unwrap(),
                first_cache
            );
            let next = candidate(
                &f,
                &y,
                2,
                "1000007-0000",
                vec![json!({"op":"settings.update","sync_interval_seconds":101})],
            );
            let error = commit::receive_commit(
                &CommitStore::new(f.ctx.state, &f.env),
                &next,
                OLD + 10,
                Some(f.ctx.audit),
            )
            .unwrap_err();
            assert_eq!(error.reason, "team_compaction_head_invalid");
            assert!(error.detail.is_empty());
            assert!(rejection_events(&f).is_empty());
            assert!(!f.path(&yfp, 2).exists());
        } else {
            assert_eq!(team.compact(&f.env).unwrap()["removed"], 0);
            assert_eq!(
                f.cache()["vector"],
                json!({f.fp.clone():3,bfp.clone():1,xfp.clone():1,yfp.clone():1})
            );
        }
        assert_eq!(fs::read(f.path(&xfp, 1)).unwrap(), incoming_bytes);
        assert_eq!(
            incoming.canonical_json(true).unwrap(),
            canon(&incoming.to_dict())
        );
        assert_head(&f.cache(), &head, &signed, &hashed);
        let cache = f.cache();
        let slot = cache["heads"]
            .as_array()
            .unwrap()
            .iter()
            .find(|slot| slot["author"] == yfp)
            .unwrap();
        assert_eq!(slot["device"], y.record().unwrap().to_dict());
    }
}

#[test]
fn compaction_heads_02_removed_author_receipt_preserves_status_and_cache_time_boundary() {
    let f = received_fixture();
    let peer = DeviceKey::generate();
    let fp = peer.fingerprint().unwrap();
    received(
        &f,
        &f.device,
        2,
        "1000001-0000",
        vec![member_op(&f, &peer, "admin")],
    );
    let peer_head = received(&f, &peer, 1, "1000002-0007", vec![f.put_op("idle", V1)]);
    let signed = peer_head.canonical_json(false).unwrap();
    let hashed = peer_head.canonical_json(true).unwrap();
    received(
        &f,
        &f.device,
        3,
        "1000003-0000",
        vec![json!({"op":"member.remove","fingerprint":fp})],
    );
    let team = f.sync();
    assert_eq!(team.compact(&f.env).unwrap()["removed"], 1);
    assert_eq!(f.cache()["vector"], json!({f.fp.clone():3,fp.clone():1}));
    let equal = candidate(
        &f,
        &peer,
        2,
        "1000002-0007",
        vec![json!({"op":"settings.update","sync_interval_seconds":103})],
    );
    assert_eq!(
        commit::receive_commit(
            &CommitStore::new(f.ctx.state, &f.env),
            &equal,
            OLD + 10,
            Some(f.ctx.audit)
        )
        .unwrap(),
        "rejected"
    );
    assert_eq!(rejection_events(&f)[0]["reason"], "team_hlc_not_monotone");
    assert_head(&f.cache(), &peer_head, &signed, &hashed);
    let next = received(
        &f,
        &peer,
        2,
        "1000004-0000",
        vec![json!({"op":"settings.update","sync_interval_seconds":107})],
    );
    let loaded = membership::load_environment(&f.ctx, &f.env).unwrap();
    assert_eq!(loaded.document["members"][&fp]["status"], "removed");
    assert_ne!(loaded.document["settings"]["sync_interval_seconds"], 107);
    assert_eq!(loaded.version_order["idle"], json!([V1]));
    assert_eq!(team.compact(&f.env).unwrap()["removed"], 1);
    assert_head(
        &f.cache(),
        &next,
        &next.canonical_json(false).unwrap(),
        &next.canonical_json(true).unwrap(),
    );
}

#[test]
fn compaction_heads_02_already_regressed_removed_idle_history_remains_an_explicit_refusal() {
    let f = received_fixture();
    let peer = DeviceKey::generate();
    let fp = peer.fingerprint().unwrap();
    received(
        &f,
        &f.device,
        2,
        "1000001-0000",
        vec![member_op(&f, &peer, "admin")],
    );
    received(&f, &peer, 1, "1000002-0007", vec![f.put_op("idle", V1)]);
    received(
        &f,
        &f.device,
        3,
        "1000003-0000",
        vec![json!({"op":"member.remove","fingerprint":fp})],
    );
    let team = f.sync();
    assert_eq!(team.compact(&f.env).unwrap()["removed"], 1);
    // Labeled pre-fix trusted append; no new receipt can create this history.
    let regressed = candidate(
        &f,
        &peer,
        2,
        "1000001-0009",
        vec![json!({"op":"settings.update","sync_interval_seconds":109})],
    );
    CommitStore::new(f.ctx.state, &f.env)
        .append(&regressed)
        .unwrap();
    let original = fs::read(f.path(&fp, 2)).unwrap();
    let before = metadata(&f);
    for _ in 0..2 {
        let reopened =
            Arc::new(Context::open(&f.ctx.state.path, Config::default(), clock::system()).unwrap());
        let restarted = team_with_device(&reopened, &f.device, &f.env);
        assert_eq!(
            restarted.compact(&f.env).unwrap_err().reason,
            "team_compaction_head_invalid"
        );
        assert_eq!(metadata(&f), before);
        assert_eq!(fs::read(f.path(&fp, 2)).unwrap(), original);
        let loaded = membership::load_environment(&reopened, &f.env).unwrap();
        assert_eq!(loaded.document["members"][&fp]["status"], "removed");
        assert_eq!(loaded.version_order["idle"], json!([V1]));
    }
    assert!(inventory(&f, "rejected").is_empty());
    assert!(rejection_events(&f).is_empty());
}

#[test]
fn compaction_heads_02_genuine_legacy_prune_without_cache_keeps_live_only_receipt() {
    let f = received_fixture();
    received(&f, &f.device, 2, "1000001-0007", vec![f.put_op("s", V1)]);
    let all = CommitStore::new(f.ctx.state, &f.env).all_commits().unwrap();
    let snapshot =
        fold::snapshot_of_prefix(&f.env, all.clone(), f.ctx.state, None, &all, None).unwrap();
    // Genuine pre-cache layout: this fixture never calls the new compactor.
    fold::save_snapshot(f.ctx.state, &f.env, &2.into(), &snapshot).unwrap();
    fold::save_snapshot_record(
        f.ctx.state,
        &f.env,
        &2.into(),
        &fold::snapshot_record(None, &all),
    )
    .unwrap();
    fs::remove_file(f.path(&f.fp, 2)).unwrap();
    assert!(f.cache().is_null());
    let next = received(
        &f,
        &f.device,
        3,
        "1000000-0009",
        vec![json!({"op":"settings.update","sync_interval_seconds":113})],
    );
    assert_eq!(next.author_seq, PyInt::from(3));
    let loaded = membership::load_environment(&f.ctx, &f.env).unwrap();
    assert_eq!(loaded.version_order["s"], json!([V1]));
    assert_eq!(loaded.document["settings"]["sync_interval_seconds"], 113);
    assert!(f.cache().is_null());
    assert!(rejection_events(&f).is_empty());
}

#[cfg(unix)]
#[test]
fn compaction_heads_02_receipt_refuses_identical_content_and_dangling_cache_symlinks() {
    for dangling in [false, true] {
        let (f, _team, _) = receipt_compacted();
        let path = f.ctx.state.path.join(f.cache_name());
        let target = f._root.path().join("synthetic-retained-cache");
        let original = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        if !dangling {
            fs::write(&target, &original).unwrap();
        }
        std::os::unix::fs::symlink(&target, &path).unwrap();
        let before = metadata(&f);
        let next = candidate(
            &f,
            &f.device,
            3,
            "1000001-0008",
            vec![json!({"op":"settings.update","sync_interval_seconds":127})],
        );
        let error = commit::receive_commit(
            &CommitStore::new(f.ctx.state, &f.env),
            &next,
            OLD + 10,
            Some(f.ctx.audit),
        )
        .unwrap_err();
        assert_eq!(error.reason, "team_compaction_head_invalid");
        assert!(error.detail.is_empty());
        assert!(
            fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(metadata(&f), before);
        assert!(!f.path(&f.fp, 3).exists());
        assert!(inventory(&f, "rejected").is_empty());
        assert!(rejection_events(&f).is_empty());
        if !dangling {
            assert_eq!(fs::read(target).unwrap(), original);
        }
    }
}

#[cfg(unix)]
#[test]
fn compaction_heads_02_unreadable_cache_requires_unprivileged_isolated_uid() {
    use std::os::unix::fs::PermissionsExt;

    struct RestorePermissions(std::path::PathBuf, fs::Permissions);
    impl Drop for RestorePermissions {
        fn drop(&mut self) {
            fs::set_permissions(&self.0, self.1.clone()).unwrap();
        }
    }
    let (f, team, _) = receipt_compacted();
    let store = CommitStore::new(f.ctx.state, &f.env);
    let next = candidate(
        &f,
        &f.device,
        3,
        "1000001-0008",
        vec![json!({"op":"settings.update","sync_interval_seconds":131})],
    );
    assert_eq!(
        commit::receive_commit(&store, &next, 0, Some(f.ctx.audit)).unwrap(),
        "deferred"
    );
    let deferred = inventory(&f, "deferred");
    let before = metadata(&f);
    let path = f.ctx.state.path.join(f.cache_name());
    let restore = RestorePermissions(path.clone(), fs::metadata(&path).unwrap().permissions());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o0)).unwrap();
    // Fail the resource precondition explicitly, never pass this axis without
    // an unreadable regular file. Root must allocate an unprivileged test UID.
    assert!(
        fs::File::open(&path).is_err(),
        "unreadable-cache fixture requires an unprivileged isolated UID"
    );
    let errors = [
        commit::receive_commit(&store, &next, OLD + 10, Some(f.ctx.audit)).unwrap_err(),
        store
            .release_deferred(OLD + 10, Some(f.ctx.audit))
            .unwrap_err(),
        membership::author_commit(
            &f.ctx,
            None,
            &f.env,
            vec![json!({"op":"settings.update","sync_interval_seconds":137})],
        )
        .unwrap_err(),
        membership::author_fact(
            &f.ctx,
            None,
            &f.env,
            "secret_deleted",
            json!({"secret_id":"s"}),
        )
        .unwrap_err(),
        team.publish_fact(&f.env, "secret_deleted", json!({"secret_id":"s"}))
            .unwrap_err(),
    ];
    for error in errors {
        assert_eq!(error.reason, "team_compaction_head_invalid");
        assert!(error.detail.is_empty());
    }
    assert_eq!(inventory(&f, "deferred"), deferred);
    assert!(inventory(&f, "rejected").is_empty());
    assert!(rejection_events(&f).is_empty());
    assert!(!f.path(&f.fp, 3).exists());
    assert_eq!(
        membership::load_environment(&f.ctx, &f.env)
            .unwrap()
            .version_order["s"],
        json!([V1])
    );
    assert_eq!(
        f.ctx
            .vault
            .secret_for_trusted_use("s", Some(1.into()))
            .unwrap()
            .expose(),
        VALUE
    );
    drop(restore);
    assert_eq!(metadata(&f), before);
}
