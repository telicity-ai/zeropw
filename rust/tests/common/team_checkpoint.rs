//! Synthetic checkpoint-v1 fixture generator and consistency checks ONLY.
//!
//! This is not an M2 parser, verifier, admission adapter, or runtime API. Call it
//! through the temporary example documented in the fixture README, in isolation.
//! All keys here are public deterministic test material. Never use them live.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeropw::crypto::{chacha20poly1305 as aead, ed25519, x25519};
use zeropw::pyint::PyInt;
use zeropw::pyjson::{self, DumpOptions};
use zeropw::team::commit::{self, Commit, Hlc};
use zeropw::team::envelope;
use zeropw::team::fold;
use zeropw::team::identity::{DeviceKey, DeviceRecord};
use zeropw::team::sync::{FACT_FORMAT, Fact};
use zeropw::{pybase64, secret::SecretBytes};

pub type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;
const BASE: &str = "ce796bdcf5069af8e6cd85ab3c953cc22e1bf1a4";
const PRODUCT_TREE: &str = "2882ba592e2204eb62723d95e240525e75196f64";
const DECISION: &str = "564bcf4c312b04507e815e35cc8eed9f5c6ae8f74ee539ccecf88cff8f0595b2";
const G: &str = "aaaaaaaaaaaaaaaa";
const V1: &str = "bbbbbbbbbbbbbbbb";
const V2: &str = "cccccccccccccccc";
const SECRET: &str = "retained-secret";
const NAMES: [&str; 6] = [
    "devices",
    "snapshot",
    "commits",
    "facts",
    "removals",
    "recipient_dek_wraps",
];
const PACKAGES: [&str; 5] = [
    "",
    "variants/deleted-empty",
    "variants/deleted-retained",
    "variants/changed-final-digest",
    "variants/invalid-inner-signature",
];

fn canonical(value: &Value) -> FixtureResult<Vec<u8>> {
    Ok(pyjson::dumps(value, DumpOptions::compact_sorted())?.into_bytes())
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn value_hash(value: &Value) -> FixtureResult<String> {
    Ok(hash(&canonical(value)?))
}

fn write(root: &Path, name: &str, bytes: &[u8]) -> FixtureResult<()> {
    let path = root.join(name);
    fs::create_dir_all(path.parent().ok_or("no parent")?)?;
    fs::write(path, bytes)?;
    Ok(())
}

fn write_json(root: &Path, name: &str, value: &Value) -> FixtureResult<()> {
    write(root, name, &canonical(value)?)
}

fn read_json(root: &Path, name: &str) -> FixtureResult<Value> {
    // Trusted generated fixture only. This does NOT test original-byte parsing.
    Ok(pyjson::loads(&fs::read_to_string(root.join(name))?)?)
}

fn key(seed: u8, scalar: u8) -> DeviceKey {
    // Existing public fields, synthetic-only; no product constructor is added.
    DeviceKey {
        sign_seed: SecretBytes::from_slice(&[seed; 32]),
        agree_private: SecretBytes::from_slice(&[scalar; 32]),
    }
}

fn fixed_wrap(env: &str, recipient: &DeviceRecord, eph: u8, nonce: u8) -> FixtureResult<Value> {
    let eph_pub = x25519::public_key(&[eph; 32])?;
    let shared = x25519::shared_secret(&[eph; 32], &recipient.agree_pub)?;
    let info = [
        envelope::DEK_INFO_PREFIX,
        env.as_bytes(),
        G.as_bytes(),
        recipient.fingerprint().as_bytes(),
    ]
    .concat();
    let wrapping_key = envelope::hkdf(b"", &shared, &info, 32)?;
    let ciphertext = aead::encrypt(&wrapping_key, &[nonce; 12], &[6; 32], &info)?;
    Ok(json!({"eph_pub":pybase64::b64encode(&eph_pub),
              "nonce":pybase64::b64encode(&[nonce;12]),
              "ciphertext":pybase64::b64encode(&ciphertext)}))
}

fn fixed_ciphertext(env: &str, version: &str, nonce: u8, value: &[u8]) -> FixtureResult<Value> {
    let aad = [
        env.as_bytes(),
        b"\0",
        SECRET.as_bytes(),
        b"\0",
        version.as_bytes(),
    ]
    .concat();
    let ciphertext = aead::encrypt(&[6; 32], &[nonce; 12], value, &aad)?;
    Ok(json!({"nonce":pybase64::b64encode(&[nonce;12]),
              "ciphertext":pybase64::b64encode(&ciphertext)}))
}

struct Baseline {
    keys: [DeviceKey; 3],
    fps: [String; 3],
    env: String,
    history: Vec<Commit>,
    document: Value,
    version_order: Value,
    vector: Value,
    heads: Value,
    components: Vec<Value>,
    approval: Value,
    context: Value,
}

fn baseline() -> FixtureResult<Baseline> {
    let keys = [key(0, 3), key(1, 4), key(2, 5)];
    let records = [keys[0].record()?, keys[1].record()?, keys[2].record()?];
    let fps = records.each_ref().map(|record| record.fingerprint());
    let [o, a, r] = &fps;
    let env = format!("{o}-0123456789abcdef0123456789abcdef");
    assert!(commit::valid_env_id(&env));
    let wraps = [
        fixed_wrap(&env, &records[0], 9, 12)?,
        fixed_wrap(&env, &records[1], 10, 13)?,
        fixed_wrap(&env, &records[2], 11, 14)?,
    ];
    for (wrap, device) in wraps.iter().zip(&keys) {
        assert_eq!(envelope::unwrap_dek(wrap, &env, G, device)?, [6; 32]);
    }
    let encrypted = [
        fixed_ciphertext(&env, V1, 7, b"synthetic-checkpoint-v1")?,
        fixed_ciphertext(&env, V2, 8, b"synthetic-checkpoint-v2")?,
    ];
    let seen = |entries: &[(&String, i64)]| -> BTreeMap<String, PyInt> {
        entries
            .iter()
            .map(|(fp, seq)| ((*fp).clone(), PyInt::from(*seq)))
            .collect()
    };
    let history = vec![
        commit::sign_commit(
            &keys[0],
            &env,
            1,
            "1000-0000",
            &seen(&[]),
            vec![json!({
            "op":"env.init", "owner_name":"owner", "owner_device":records[0].to_dict(),
            "generation_id":G, "wraps":{o:wraps[0]}})],
        )?,
        commit::sign_commit(
            &keys[0],
            &env,
            2,
            "2000-0000",
            &seen(&[(o, 1)]),
            vec![json!({
            "op":"member.add", "name":"admin", "device":records[1].to_dict(),
            "role":"admin", "wraps":{G:wraps[1]}})],
        )?,
        commit::sign_commit(
            &keys[1],
            &env,
            1,
            "3000-0000",
            &seen(&[(o, 2)]),
            vec![json!({
            "op":"member.add", "name":"recipient", "device":records[2].to_dict(),
            "role":"user", "wraps":{G:wraps[2]}})],
        )?,
        commit::sign_commit(
            &keys[0],
            &env,
            3,
            "4000-0000",
            &seen(&[(o, 2), (a, 1)]),
            vec![json!({
            "op":"secret.put_version", "secret_id":SECRET, "kind":"api_key",
            "generation_id":G, "version_id":V1, "ciphertext":encrypted[0], "public":{}})],
        )?,
        commit::sign_commit(
            &keys[0],
            &env,
            4,
            "5000-0000",
            &seen(&[(o, 3), (a, 1)]),
            vec![json!({
            "op":"secret.put_version", "secret_id":SECRET, "kind":"api_key",
            "generation_id":G, "version_id":V2, "ciphertext":encrypted[1], "public":{}})],
        )?,
        commit::sign_commit(
            &keys[1],
            &env,
            2,
            "6000-0000",
            &seen(&[(o, 4), (a, 1)]),
            vec![json!({
            "op":"secret.activate", "secret_id":SECRET, "version_id":V2})],
        )?,
    ];
    // No facts, no removals: reapply_facts/pending removal loops make no changes
    // (fold.rs). Therefore this pure full-history fold IS the unflushed document.
    // Do not fold the gapped retained subset or invent an M1 overlay.
    let folded = fold::fold(&env, history.clone(), None, None, None, None)?;
    assert!(
        folded.skipped.is_empty(),
        "frozen graph/API conflict: {:?}",
        folded.skipped
    );
    assert_eq!(folded.version_order, json!({SECRET:[V1,V2]}));
    assert_eq!(
        folded.document["secrets"][SECRET]["versions"][V1]["status"],
        "staged"
    );
    assert_eq!(
        folded.document["secrets"][SECRET]["versions"][V2]["status"],
        "active"
    );
    assert_eq!(folded.vector.get(o), Some(&PyInt::from(4)));
    assert_eq!(folded.vector.get(a), Some(&PyInt::from(2)));
    let vector = json!({o:4,a:2,r:0});
    let mut heads = vec![
        json!({"author":o,"author_seq":4,"commit_hash":history[4].hash()?,
               "hlc":{"wall_ms":5000,"counter":0}}),
        json!({"author":a,"author_seq":2,"commit_hash":history[5].hash()?,
               "hlc":{"wall_ms":6000,"counter":0}}),
    ];
    heads.sort_by(|left, right| left["author"].as_str().cmp(&right["author"].as_str()));
    let mut devices: Vec<Value> = records
        .iter()
        .map(|record| {
            json!({
        "fingerprint":record.fingerprint(), "record":record.to_dict()})
        })
        .collect();
    devices.sort_by(|left, right| {
        left["fingerprint"]
            .as_str()
            .cmp(&right["fingerprint"].as_str())
    });
    let mut retained: Vec<Value> = [0, 1, 2, 4, 5]
        .iter()
        .map(|&i| -> FixtureResult<Value> {
            Ok(json!({"hash":history[i].hash()?, "record":history[i].to_dict()}))
        })
        .collect::<FixtureResult<_>>()?;
    retained.sort_by(|left, right| left["hash"].as_str().cmp(&right["hash"].as_str()));
    let mut authority = vec![history[0].hash()?, history[1].hash()?, history[2].hash()?];
    authority.sort();
    let final_hash = value_hash(&folded.document)?;
    let components = vec![
        json!(devices),
        json!({"document":folded.document, "vector":vector, "version_order":folded.version_order,
               "expected_final_document_sha256":final_hash}),
        json!({"records":retained, "genesis_commit_hash":history[0].hash()?,
               "recipient_admission_commit_hash":history[2].hash()?,
               "authority_commit_hashes":authority}),
        json!({"records":[],"admitted_fact_hashes":[],"tombstone_fact_hashes":[]}),
        json!({"bounds":{},"pending":[],"self_placed":[],"witness_commit_hashes":[]}),
        json!({"entries":[{"generation_id":G,"recipient":r,
            "source_commit_hash":history[2].hash()?,"source_op_index":0,"wrap":wraps[2]}],
            "unavailable_generations":[]}),
    ];
    let approval = json!({"domain":"zeropw-team-bootstrap-local-approval-v1", "v":1,
        "trust_model":"administrator_attested", "approval_id":"20".repeat(16),
        "env_id":env, "signer":a, "signer_record":records[1].to_dict(),
        "recipient":r, "recipient_role":"user", "invite_id":"10".repeat(16),
        "invitation_expires_at_ms":1800003600000_u64});
    let context = json!({"approval":approval, "authenticated_peer_record":records[1].to_dict(),
        "session_env_id":env, "local_recipient":r, "session_nonce":"50".repeat(32),
        "onboarding_nonce":"60".repeat(32), "check_time_ms":1800000000001_u64});
    Ok(Baseline {
        keys,
        fps,
        env,
        history,
        document: folded.document,
        version_order: folded.version_order,
        vector,
        heads: json!(heads),
        components,
        approval,
        context,
    })
}

fn deletion(b: &Baseline, secret: &str, hlc: &str) -> FixtureResult<Fact> {
    // Pre-M1 sign_fact refuses this kind. Only the unchanged Fact canonical
    // representation and existing Ed25519 primitive are used; no admission.
    let mut fact = Fact {
        format: FACT_FORMAT.into(),
        env_id: b.env.clone(),
        kind: "secret_deleted".into(),
        target: json!({"secret_id":secret}),
        author: b.fps[1].clone(),
        hlc: hlc.into(),
        sig: String::new(),
    };
    fact.sig = pybase64::b64encode(&ed25519::sign(&[1; 32], &fact.canonical_json(false)?)?);
    Ok(fact)
}

fn package(root: &Path, b: &Baseline, variant: &str) -> FixtureResult<()> {
    let mut components = b.components.clone();
    let mut fact = None;
    let mut final_claim = value_hash(&b.document)?;
    let mut inner_signatures_valid = true;
    match variant {
        "" => {}
        "variants/deleted-empty" => fact = Some(deletion(b, "deleted-empty", "7000-0000")?),
        "variants/deleted-retained" => fact = Some(deletion(b, SECRET, "8000-0000")?),
        "variants/changed-final-digest" => final_claim = "f".repeat(64),
        "variants/invalid-inner-signature" => {
            inner_signatures_valid = false;
            let records = components[2]["records"].as_array_mut().ok_or("records")?;
            let record = records
                .iter_mut()
                .find(|entry| entry["record"]["hlc"] == "5000-0000")
                .ok_or("O:4")?;
            record["record"]["sig"] = json!(pybase64::b64encode(&[0; 64]));
            record["hash"] = json!(Commit::from_dict(&record["record"])?.hash()?);
            records.sort_by(|left, right| left["hash"].as_str().cmp(&right["hash"].as_str()));
        }
        _ => return Err("unknown synthetic package".into()),
    }
    let mut heads = b.heads.clone();
    if !inner_signatures_valid {
        let changed = components[2]["records"]
            .as_array()
            .ok_or("records")?
            .iter()
            .find(|entry| entry["record"]["hlc"] == "5000-0000")
            .ok_or("O:4")?;
        for head in heads.as_array_mut().ok_or("heads")? {
            if head["author"] == b.fps[0] {
                head["commit_hash"] = changed["hash"].clone();
            }
        }
    }
    if let Some(fact) = &fact {
        let h = fact.hash()?;
        components[3] = json!({"records":[{"hash":h,"record":fact.to_dict()}],
            "admitted_fact_hashes":[h],"tombstone_fact_hashes":[h]});
        write(
            root,
            "records/fact.unsigned.canon",
            &fact.canonical_json(false)?,
        )?;
        write(
            root,
            "records/fact.signed.canon",
            &fact.canonical_json(true)?,
        )?;
    }
    components[1]["expected_final_document_sha256"] = json!(final_claim);
    let counts = json!({"devices":3,"commits":5,"facts":usize::from(fact.is_some()),
        "versions":2,"recipient_wraps":1});
    let payload_value = json!({"format":"zeropw-team-bootstrap-payload-v1","v":1,
        "env_id":b.env, "components":NAMES.iter().zip(&components).map(|(name,data)|
            json!({"name":name,"data":data})).collect::<Vec<_>>()});
    let payload = canonical(&payload_value)?;
    let mut descriptors = Vec::new();
    let mut spans = Vec::new();
    for (i, (name, data)) in NAMES.iter().zip(&components).enumerate() {
        let bytes = canonical(data)?;
        let offsets: Vec<usize> = payload
            .windows(bytes.len())
            .enumerate()
            .filter_map(|(at, slice)| (slice == bytes).then_some(at))
            .collect();
        assert_eq!(offsets.len(), 1, "component must have one literal raw span");
        let item_count = [3, 1, 5, usize::from(fact.is_some()), 1, 1][i];
        descriptors.push(
            json!({"name":name,"byte_length":bytes.len(),"sha256":hash(&bytes),
                                "item_count":item_count}),
        );
        spans.push(
            json!({"name":name,"offset":offsets[0],"byte_length":bytes.len(),
                          "sha256":hash(&bytes)}),
        );
        write(root, &format!("components/{name}.json"), &bytes)?;
    }
    let chunk_descriptors: Vec<Value> = payload
        .chunks(65536)
        .enumerate()
        .map(|(i, bytes)| json!({"index":i,"byte_length":bytes.len(),"sha256":hash(bytes)}))
        .collect();
    let mut manifest = json!({"type":"BOOTSTRAP_MANIFEST","domain":"zeropw-team-bootstrap-v1",
        "v":1,"trust_model":"administrator_attested", "env_id":b.env,"signer":b.fps[1],
        "recipient":b.fps[2],"recipient_role":"user","invite_id":"10".repeat(16),
        "approval_id":"20".repeat(16),"approval_sha256":value_hash(&b.approval)?,
        "session_nonce":"50".repeat(32),"onboarding_nonce":"60".repeat(32),
        "transfer_id":"40".repeat(16),"recipient_authorization_id":"30".repeat(16),
        "recipient_admission_commit_hash":b.history[2].hash()?,
        "authorization_expires_at_ms":1800003600000_u64,"created_at_ms":1800000000000_u64,
        "expires_at_ms":1800000600000_u64,
        "required_features":["secret_tombstone_v1","snapshot_bootstrap_v1"],
        "vector":b.vector,"heads":heads,"counts":counts,"components":descriptors,
        "admitted_fact_hashes_sha256":value_hash(&components[3]["admitted_fact_hashes"])?,
        "tombstone_digest":value_hash(&components[3]["tombstone_fact_hashes"])?,
        "expected_final_document_sha256":final_claim,
        "payload":{"byte_length":payload.len(),"sha256":hash(&payload),"chunks":chunk_descriptors}});
    let unsigned = canonical(&manifest)?;
    manifest["sig"] = json!(pybase64::b64encode(&b.keys[1].sign(&unsigned)?));
    let signed = canonical(&manifest)?;
    let manifest_hash = hash(&signed);
    let mut candidate = json!({"format":"zeropw-team-checkpoint-candidate-v1","v":1,
        "trust_model":"administrator_attested","stage":"integrity_checked_not_admitted",
        "signer_record":b.keys[1].record()?.to_dict(),"payload_sha256":hash(&payload),
        "candidate_fact_bindings":components[3]["admitted_fact_hashes"].as_array().ok_or("facts")?
            .iter().map(|h| json!({"fact_hash":h,"manifest_hash":manifest_hash,
                "approved_signer":b.fps[1],"approval_sha256":manifest["approval_sha256"],
                "basis":"administrator_attested_candidate"})).collect::<Vec<_>>(),
        "candidate_tombstone_fact_hashes":components[3]["tombstone_fact_hashes"]});
    for name in [
        "env_id",
        "signer",
        "recipient",
        "recipient_role",
        "invite_id",
        "approval_id",
        "approval_sha256",
        "session_nonce",
        "onboarding_nonce",
        "transfer_id",
        "recipient_authorization_id",
        "recipient_admission_commit_hash",
        "vector",
        "heads",
        "components",
        "admitted_fact_hashes_sha256",
        "tombstone_digest",
        "expected_final_document_sha256",
    ] {
        candidate[name] = manifest[name].clone();
    }
    candidate["manifest_hash"] = json!(manifest_hash);
    write_json(root, "approval.json", &b.approval)?;
    write_json(root, "context.json", &b.context)?;
    write(root, "payload.json", &payload)?;
    write(root, "manifest.json", &signed)?;
    write(root, "manifest.unsigned.canon", &unsigned)?;
    write(root, "manifest.signed.canon", &signed)?;
    write_json(root, "candidate.json", &candidate)?;
    for (i, bytes) in payload.chunks(65536).enumerate() {
        write(root, &format!("chunks/{i:03}.bin"), bytes)?;
        write_json(
            root,
            &format!("chunk-{i:03}.json"),
            &json!({"type":"BOOTSTRAP_CHUNK","v":1,
            "transfer_id":manifest["transfer_id"],"manifest_hash":manifest_hash,"index":i,
            "data_b64":pybase64::b64encode(bytes)}),
        )?;
    }
    let record_expectations: Vec<Value> = components[2]["records"]
        .as_array()
        .ok_or("commits")?
        .iter()
        .map(|entry| -> FixtureResult<Value> {
            let c = Commit::from_dict(&entry["record"])?;
            Ok(
                json!({"hash":c.hash()?,"author":c.author,"author_seq":c.author_seq.value(),
                "hlc":c.hlc,"unsigned_sha256":hash(&c.canonical_json(false)?),"sig":c.sig}),
            )
        })
        .collect::<FixtureResult<_>>()?;
    write_json(
        root,
        "expected.json",
        &json!({"package":if variant.is_empty(){"baseline"}else{variant},
        "stage":"integrity_checked_not_admitted", "semantic_admission_tested":false,
        "inner_commit_signatures_valid":inner_signatures_valid,
        "final_document_claim_verified_from_complete_no_fact_history":variant.is_empty(),
        "manifest_hash":manifest_hash,"manifest_unsigned_sha256":hash(&unsigned),
        "manifest_signature":manifest["sig"],"payload":manifest["payload"],
        "components":descriptors,"component_spans":spans,"counts":counts,
        "approval_sha256":manifest["approval_sha256"],"vector":manifest["vector"],"heads":heads,
        "retained_commits":record_expectations,
        "admitted_fact_hashes":components[3]["admitted_fact_hashes"],
        "tombstone_fact_hashes":components[3]["tombstone_fact_hashes"],
        "admitted_fact_hashes_sha256":manifest["admitted_fact_hashes_sha256"],
        "tombstone_digest":manifest["tombstone_digest"],
        "expected_final_document_sha256":final_claim,"candidate_sha256":value_hash(&candidate)?}),
    )?;
    Ok(())
}

/// Generate only public synthetic files in the explicitly supplied directory.
pub fn generate(root: &Path) -> FixtureResult<()> {
    let b = baseline()?;
    for variant in PACKAGES {
        package(&root.join(variant), &b, variant)?;
    }
    let labels = ["O-1", "O-2", "A-1", "O-3-compacted", "O-4", "A-2"];
    let mut history_expected = Vec::new();
    for (label, c) in labels.into_iter().zip(&b.history) {
        write(
            root,
            &format!("history/{label}.unsigned.canon"),
            &c.canonical_json(false)?,
        )?;
        write(
            root,
            &format!("history/{label}.signed.canon"),
            &c.canonical_json(true)?,
        )?;
        history_expected.push(json!({"label":label,"hash":c.hash()?,
            "unsigned_sha256":hash(&c.canonical_json(false)?),"sig":c.sig}));
    }
    write_json(
        root,
        "history/expected.json",
        &json!({"commits":history_expected,
        "compacted_commit_hash":b.history[3].hash()?,"document_sha256":value_hash(&b.document)?,
        "version_order":b.version_order,"owner":b.fps[0],"admin":b.fps[1],"recipient":b.fps[2]}),
    )?;
    raw_cases(root)?;
    numeric_records(root, &b)?;
    let source_hash = hash(&fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/common/team_checkpoint.rs"),
    )?);
    let lock_hash = hash(&fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock"),
    )?);
    write(
        root,
        "README.md",
        readme(&source_hash, &lock_hash).as_bytes(),
    )?;
    let mut files = BTreeMap::new();
    collect(root, root, &mut files)?;
    files.remove("SHA256SUMS");
    let sums: String = files
        .iter()
        .map(|(name, bytes)| format!("{}  {name}\n", hash(bytes)))
        .collect();
    write(root, "SHA256SUMS", sums.as_bytes())?;
    Ok(())
}

fn collect(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) -> FixtureResult<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(root, &path, out)?;
        } else {
            assert!(path.is_file() && !path.is_symlink());
            out.insert(
                path.strip_prefix(root)?
                    .to_str()
                    .ok_or("path")?
                    .replace('\\', "/"),
                fs::read(path)?,
            );
        }
    }
    Ok(())
}

fn raw_cases(root: &Path) -> FixtureResult<()> {
    let mut cases = Vec::new();
    let mut add = |name: &str, bytes: Vec<u8>, intended: &str| -> FixtureResult<()> {
        write(root, &format!("raw-cases/{name}"), &bytes)?;
        cases.push(
            json!({"file":name,"byte_length":bytes.len(),"sha256":hash(&bytes),
            "intended_contract":intended,"parser_executed":false}),
        );
        Ok(())
    };
    for (name, text, intended) in [
        (
            "duplicate-top.json",
            r#"{"v":1,"v":1}"#,
            "duplicate decoded key: refuse",
        ),
        (
            "duplicate-nested.json",
            r#"{"snapshot":{"document":{"x":1,"x":2}}}"#,
            "nested duplicate: refuse",
        ),
        (
            "duplicate-target.json",
            r#"{"target":{"secret_id":"a","secret_id":"b"}}"#,
            "legacy target duplicate: refuse",
        ),
        (
            "duplicate-escaped.json",
            r#"{"x":1,"\u0078":2}"#,
            "escaped equivalent key: refuse",
        ),
        (
            "duplicate-reordered.json",
            r#"{"b":0,"a":1,"b":2}"#,
            "nonadjacent duplicate: refuse",
        ),
        (
            "duplicate-pair-key.json",
            "{\"😀\":0,\"\\ud83d\\ude00\":1}",
            "non-BMP equivalent key: refuse",
        ),
        (
            "surrogate-pair.json",
            r#"{"text":"\ud83d\ude00"}"#,
            "valid surrogate pair: syntax accepts",
        ),
        (
            "lone-high-surrogate.json",
            r#"{"text":"\ud800"}"#,
            "lone high surrogate: refuse",
        ),
        (
            "lone-low-surrogate-key.json",
            r#"{"\udfff":0}"#,
            "lone low surrogate key: refuse",
        ),
        ("trailing-json.json", "{} []", "trailing JSON: refuse"),
        (
            "string-delimiters.json",
            r#"{"text":"[ { ] } \" \\"}"#,
            "delimiters/escaped quotes inside strings add no depth",
        ),
        (
            "private-number-single.json",
            r#"{"$serde_json::private::Number":"9007199254740993"}"#,
            "literal object; canonical bytes equal file bytes",
        ),
        (
            "private-number-multi.json",
            r#"{"$serde_json::private::Number":"1","other":2}"#,
            "literal object; canonical bytes equal file bytes",
        ),
        (
            "private-raw-single.json",
            r#"{"$serde_json::private::RawValue":"[1]"}"#,
            "literal object; canonical bytes equal file bytes",
        ),
        (
            "private-raw-multi.json",
            r#"{"$serde_json::private::RawValue":"0","other":2}"#,
            "literal object; canonical bytes equal file bytes",
        ),
        (
            "private-number-duplicate.json",
            r#"{"$serde_json::private::Number":"1","\u0024serde_json::private::Number":"2"}"#,
            "escaped equivalent private Number key: refuse",
        ),
        (
            "private-raw-duplicate.json",
            r#"{"$serde_json::private::RawValue":"0","\u0024serde_json::private::RawValue":"1"}"#,
            "escaped equivalent private RawValue key: refuse",
        ),
        (
            "exact-headers.json",
            r#"{"author_seq":9007199254740993,"hlc":{"counter":1844674407370955161600000000000000000001,"wall_ms":9007199254740993},"vector":{"author":1844674407370955161600000000000000000001}}"#,
            "fragment only; exact header integers, not a schema-valid checkpoint",
        ),
        (
            "legacy-numbers.json",
            "[1.0,-0.0,1e-7,1.25e20,-1844674407370955161600000000000000000001]",
            "legacy numeric canonical golden; finite floats permitted",
        ),
        (
            "overflow-float.json",
            "[1e9999]",
            "overflowing finite representation: refuse",
        ),
        (
            "control-bool.json",
            r#"{"byte_length":true}"#,
            "UInt control: refuse bool",
        ),
        (
            "control-string.json",
            r#"{"byte_length":"1"}"#,
            "UInt control: refuse string",
        ),
        (
            "control-float.json",
            r#"{"byte_length":1.0}"#,
            "UInt control: refuse decimal",
        ),
        (
            "control-exponent.json",
            r#"{"byte_length":1e0}"#,
            "UInt control: refuse exponent",
        ),
        (
            "control-negative-zero.json",
            r#"{"byte_length":-0}"#,
            "UInt original-token control: refuse negative zero",
        ),
        (
            "control-negative.json",
            r#"{"byte_length":-1}"#,
            "UInt control: refuse negative size",
        ),
        (
            "control-huge-count.json",
            r#"{"commits":1844674407370955161600000000000000000001}"#,
            "bounded count: refuse without huge reservation",
        ),
    ] {
        add(name, text.as_bytes().to_vec(), intended)?;
    }
    add(
        "invalid-utf8.bin",
        vec![b'{', b'"', 0xff, b'"', b':', b'0', b'}'],
        "invalid UTF-8: refuse",
    )?;
    let depth = |n: usize| [vec![b'['; n], vec![b'0'], vec![b']'; n]].concat();
    add(
        "depth-64.json",
        depth(64),
        "D(64): syntax-depth guard accepts",
    )?;
    add(
        "depth-65.json",
        depth(65),
        "D(65): syntax-depth guard refuses",
    )?;
    add(
        "depth-4096.json",
        depth(4096),
        "small-stack early refusal; no recursive error/drop claim yet",
    )?;
    for (n, total) in [(62, 64), (63, 65)] {
        add(
            &format!("legacy-total-depth-{total}.json"),
            [
                b"{\"target\":{\"legacy\":".to_vec(),
                depth(n),
                b"}}".to_vec(),
            ]
            .concat(),
            if total == 64 {
                "total depth 64: syntax-depth guard accepts"
            } else {
                "total depth 65: syntax-depth guard refuses"
            },
        )?;
    }
    add(
        "duplicate-deep-second.json",
        [b"{\"x\":0,\"x\":".to_vec(), depth(66), b"}".to_vec()].concat(),
        "refuse before materializing duplicate value; preflight depth may refuse first",
    )?;
    add(
        "duplicate-large-second.json",
        [
            b"{\"x\":0,\"x\":\"".to_vec(),
            vec![b'a'; 4096],
            b"\"}".to_vec(),
        ]
        .concat(),
        "duplicate value refusal before materialization; small representative, not size-limit test",
    )?;
    // Small original-byte schema mutations. They intentionally retain an invalid
    // outer signature/hash: future tests must re-attest when targeting structure.
    let manifest = fs::read_to_string(root.join("manifest.json"))?;
    for (name, bytes, intent) in [
        (
            "manifest-missing-type.json",
            manifest.replacen("\"type\":\"BOOTSTRAP_MANIFEST\",", "", 1),
            "required field absent: refuse; not a crypto-stage test",
        ),
        (
            "manifest-extra-field.json",
            manifest.replacen('{', "{\"unknown\":0,", 1),
            "unknown manifest field: refuse; outer signature deliberately unchanged",
        ),
        (
            "manifest-unknown-feature.json",
            manifest.replace("snapshot_bootstrap_v1", "unknown_bootstrap_v1"),
            "unknown required feature: refuse; outer signature deliberately unchanged",
        ),
    ] {
        add(name, bytes.into_bytes(), intent)?;
    }
    let payload = fs::read_to_string(root.join("payload.json"))?;
    let empty_wrapper = "{\"data\":{},\"name\":\"unknown\"},";
    add(
        "payload-extra-component.json",
        payload
            .replacen(
                "\"components\":[",
                &format!("\"components\":[{empty_wrapper}"),
                1,
            )
            .into_bytes(),
        "extra component: refuse; outer hashes deliberately unchanged",
    )?;
    let wrapper = |name: &str| -> FixtureResult<String> {
        Ok(format!(
            "{{\"data\":{},\"name\":\"{name}\"}}",
            fs::read_to_string(root.join(format!("components/{name}.json")))?
        ))
    };
    let first = wrapper("devices")?;
    let second = wrapper("snapshot")?;
    let old = format!("{first},{second}");
    assert!(payload.contains(&old));
    add(
        "payload-reordered-components.json",
        payload
            .replacen(&old, &format!("{second},{first}"), 1)
            .into_bytes(),
        "component array reordering: refuse; outer hashes deliberately unchanged",
    )?;
    write_json(
        root,
        "raw-cases/index.json",
        &json!({"parser_validation_run":false,"cases":cases}),
    )?;
    // Literal oracle written separately from the canonical writer under check.
    write(
        root,
        "raw-cases/legacy-numbers.expected.canon",
        b"[1.0,-0.0,1e-07,1.25e+20,-1844674407370955161600000000000000000001]",
    )?;
    Ok(())
}

fn numeric_records(root: &Path, b: &Baseline) -> FixtureResult<()> {
    // Additional standalone canonical/hash oracles; never part of the fixed graph.
    let legacy =
        pyjson::loads("[1.0,-0.0,1e-7,1.25e20,-1844674407370955161600000000000000000001]")?;
    let large = pyjson::loads("1844674407370955161600000000000000000001")?;
    let exact = pyjson::loads("9007199254740993")?;
    let mut seen = BTreeMap::new();
    seen.insert(
        b.fps[0].clone(),
        PyInt::from_json_integer(&exact).ok_or("integer")?,
    );
    let hlc = "9007199254740993-1844674407370955161600000000000000000001";
    let commit = commit::sign_commit(
        &b.keys[0],
        &b.env,
        PyInt::from_json_integer(&large).ok_or("integer")?,
        hlc,
        &seen,
        vec![json!({
            "op":"secret.put_version","secret_id":SECRET,"kind":"api_key",
            "generation_id":G,"version_id":V1,"ciphertext":fixed_ciphertext(&b.env,V1,7,b"synthetic-checkpoint-v1")?,
            "public":{"legacy_numbers":legacy}})],
    )?;
    let mut fact = Fact {
        format: FACT_FORMAT.into(),
        env_id: b.env.clone(),
        kind: "incident".into(),
        target: json!({"legacy_numbers":legacy}),
        author: b.fps[1].clone(),
        hlc: hlc.into(),
        sig: String::new(),
    };
    fact.sig = pybase64::b64encode(&ed25519::sign(&[1; 32], &fact.canonical_json(false)?)?);
    write(
        root,
        "numeric-records/commit.signed.canon",
        &commit.canonical_json(true)?,
    )?;
    write(
        root,
        "numeric-records/commit.unsigned.canon",
        &commit.canonical_json(false)?,
    )?;
    write(
        root,
        "numeric-records/fact.signed.canon",
        &fact.canonical_json(true)?,
    )?;
    write(
        root,
        "numeric-records/fact.unsigned.canon",
        &fact.canonical_json(false)?,
    )?;
    write_json(
        root,
        "numeric-records/expected.json",
        &json!({
        "standalone_canonical_oracles_not_admitted":true,
        "commit_hash":commit.hash()?,"fact_hash":fact.hash()?,"commit_sig":commit.sig,"fact_sig":fact.sig,
        "commit_unsigned_sha256":hash(&commit.canonical_json(false)?),
        "fact_unsigned_sha256":hash(&fact.canonical_json(false)?),
        "author_seq":large,"vector":{b.fps[0].clone():exact},
        "hlc":{"wall_ms":exact,"counter":large}}),
    )?;
    Ok(())
}

fn readme(source_hash: &str, lock_hash: &str) -> String {
    format!(
        r#"# Synthetic checkpoint-v1 goldens

Actual author: gpt-6.1-sol, ultra reasoning effort, T3 Code/Codex harness.
No additional model version, temperature or sampling settings were exposed.
Input base {BASE}; original Rust tree {PRODUCT_TREE}.
Decision SHA-256 {DECISION}; narrow task SHA-256
8f89a1caa07c5c54afb24bcf14193889dd9d6fda241b98d532fc181b85e33272.
Generator: rust/tests/common/team_checkpoint.rs SHA-256 {source_hash}.
Unchanged product Cargo.lock SHA-256 {lock_hash}.

This package is fixture/crypto/golden consistency evidence, never semantic M2
admission or a parser PASS. Candidate JSON is an exact expected inert output,
constructed in test code. No production checkpoint verifier exists in this slice.
The pin is the non-owner admin A, independently supplied in approval/context.
context.json is test-only serialization, not a production deserializer contract.

All generation/crypto/test execution occurs in owned credential-free exports in
Lima zeropw-parity (Linux aarch64, kernel 6.8.0-147-generic), rustc 1.98.1
(48a229cea 2026-09-01), cargo 1.98.1 (797e8a9bc 2026-08-05). No host product
execution, native macOS/M1 runner, production keys, networking or runtime changes.
The exact VM scripts, command exits, source/driver manifests and before/after
tracked blob/mode manifests are retained in the external task evidence directory
/Users/ys/Code/zeropw-mlp-evidence/m2a-fixtures-sol-20261107/.

## Public deterministic material (synthetic ONLY)

O/A/R Ed25519 seeds: byte 00/01/02 repeated 32; X25519 private test scalars:
03/04/05 repeated 32. DEK: 06 repeated 32. Values: ASCII
synthetic-checkpoint-v1 and synthetic-checkpoint-v2. Version nonces: 07/08 repeated
12. Wrap ephemeral private test scalars: 09/0a/0b repeated 32; wrap nonces:
0c/0d/0e repeated 12. Existing X25519, envelope::hkdf and ChaCha20-Poly1305
primitives construct these; existing unwrap_dek/decrypt_secret check them.
These are intentionally public insecure test constants, never production examples.
No plaintext value or DEK/private key is embedded in a wire payload.

Suffix: 0123456789abcdef0123456789abcdef. G/V1/V2: a/b/c repeated 16.
Invite/approval/authorization/transfer IDs: 10/20/30/40 repeated 16.
Session/onboarding nonces: 50/60 repeated 32. Creation/check/expiry:
1800000000000/1800000000001/1800000600000 ms; authorization/invitation expiry:
1800003600000 ms. The exact six-commit graph is decision section 10. Original
whole records and signed/unsigned canonical bytes are in history/; O:3 is evidence
for generation only and is deliberately absent from the payload. Payload retains
O:1,O:2,O:4,A:1,A:2; vector O4/A2/R0, heads O4/A2, authority O1/O2/A1,
admission A1. Three devices, five commits, zero facts, two versions, one recipient
G wrap from A1 operation 0. No removals, explicit empty fact/tombstone arrays.

The snapshot comes from the unchanged pure fold of all six commits with no
facts/removals; its empty overlay changes nothing, so this IS the unflushed
full-cut document. V1 remains staged; V2 active; original version order [V1,V2].
No gapped-history fold, active-value summary or M1 overlay is invented.

## Files and limited variants

Root is the baseline. Each variants/ directory is a complete separately signed
manifest/payload/component/chunk/candidate/expected package using the same pin and
context. Raw payload, components and .canon files have no trailing newline.
expected.json contains literal hashes, counts, record signatures, heads and raw
span offsets. SHA256SUMS covers every fixture file except itself, including this
README and raw-case corpus. history/expected.json binds all six original commits.

- deleted-empty: A secret_deleted fact at 7000-0000 for deleted-empty, which has
  no snapshot secret/version entry; exact nonempty admitted/tombstone hash set.
- deleted-retained: A secret_deleted fact at 8000-0000 for retained-secret;
  snapshot retains BOTH original encrypted versions and original order.
- changed-final-digest: signed final-document claim is f repeated 64; same raw
  document. This explicitly false overlay claim remains unverified.
- invalid-inner-signature: O4 signature is zero bytes; original canonical/hash,
  head and all outer hashes/signature are coherently re-attested. Independent
  crypto check expects exactly one invalid original commit signature.

Deletion signatures use unchanged Fact canonical bytes plus existing Ed25519 in
test code because pre-M1 sign_fact refuses secret_deleted. They are NOT admitted
M1 facts. All variant final-overlay claims are explicitly UNVERIFIED, including
retained baseline claims. They are integrity-only candidate goldens, not proof
that a new parser accepts them. The invalid-inner-signature variant illustrates
that outer attestation cannot establish original signature validity.

raw-cases/ contains handcrafted original bytes, including duplicates, private
serde names, malformed Unicode/UTF-8, exact integers, legacy numbers, D64/D65,
total-depth64/65 and small very-deep/large-second-value representatives. Its index
states intended FUTURE contracts and parser_executed=false. No new parser runs
against it here. Large size/count boundaries must be generated in later verifier
tests; no tens-of-MiB checked-in bulk. The literal legacy numeric canonical
golden is checked using the unchanged canonical helper; private-name objects are
literal byte oracles, never passed through a map-deserializer that could collapse
their meaning. Parser choice amendment does not change these wire/hash contracts.
numeric-records/ adds separately signed Commit/Fact canonical oracles with exact
large headers and legacy finite floats/signed integers. They are not in the fixed
baseline graph and are not semantically admitted facts or checkpoint candidates.

## Reproduction and checks (isolated VM only)

The ONLY temporary driver addition to each owned source export is
rust/examples/checkpoint_fixture.rs (untracked/uncommitted in the VM export):

```rust
#[path = "../tests/common/team_checkpoint.rs"]
mod fixture;
fn main() -> fixture::FixtureResult<()> {{
    let args: Vec<String> = std::env::args().collect();
    let root = std::path::Path::new(&args[2]);
    match args[1].as_str() {{
        "generate" => fixture::generate(root),
        "validate" => fixture::validate(root),
        _ => Err("expected generate or validate".into()),
    }}
}}
```

Use the original product package/lock, never a separately resolved path package.
Copy ONLY product-lock registry packages and cached public index into an owned
Cargo home; no credentials/config. Exact shell orchestration is in external
evidence. VM command settings:

```sh
export CARGO_HOME=/home/parity/jobs/m2a-fixtures-sol-20261107/cargo-home
export CARGO_TARGET_DIR=/home/parity/jobs/m2a-fixtures-sol-20261107/target
export TMPDIR=/home/parity/jobs/m2a-fixtures-sol-20261107/tmp
export CARGO_BUILD_JOBS=1 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true
cargo run --offline --locked --manifest-path rust/Cargo.toml --example checkpoint_fixture -- generate rust/tests/fixtures/team_checkpoint_v1
cargo run --offline --locked --manifest-path rust/Cargo.toml --example checkpoint_fixture -- validate rust/tests/fixtures/team_checkpoint_v1
cargo test --offline --locked --manifest-path rust/Cargo.toml --example checkpoint_fixture
```

The helper validates stored literal expectations independently of generation:
device bindings, all baseline original signatures, manifest signature, original
Commit/Fact canonical/hash equality, exact raw spans/chunks/lengths/hashes,
counts/sets/vector/heads/source wraps, both ciphertexts and all three wraps via
existing readers, and exact candidate schema/metadata. A clean temporary output
is regenerated and compared byte-for-byte. A separate Python standard-library
inspection independently checks raw hashes/partition/canonical ASCII bytes and
literal candidate mapping without invoking the Rust builder or any M2 verifier.
Generation/validation/reproduction command results are reported in external logs.

No rust/verify.sh full matrix, native macOS, M1 admission, M2 implementation,
Opus review, physical two-Mac, OCI/capacity or release acceptance is claimed.
All original M2-G01 through M2-G10 remain OPEN: actual M1; retained signatures/
authority/fact/removal semantics; compaction/head evidence; required generations;
durable two-sided approvals/session/raw frames/budgets and renewal/receipt query;
finalize; coherent durable epoch import; committed provenance/ACK; full acceptance.
Snapshot onboarding remains unsupported. No original Opus finding IDs were
supplied for this fixture task. Old fixtures, source, lock and features are frozen.
"#
    )
}

/// Validate generated public fixture consistency, NOT M2 admission or strict parsing.
pub fn validate(root: &Path) -> FixtureResult<()> {
    let mut files = BTreeMap::new();
    collect(root, root, &mut files)?;
    let sums = String::from_utf8(files.remove("SHA256SUMS").ok_or("SHA256SUMS")?)?;
    let actual: String = files
        .iter()
        .map(|(name, bytes)| format!("{}  {name}\n", hash(bytes)))
        .collect();
    assert_eq!(sums, actual, "complete fixture file/hash inventory");
    for variant in PACKAGES {
        validate_package(&root.join(variant))?;
    }
    validate_history(root)?;
    validate_numeric_records(root)?;
    assert_eq!(
        canonical(&read_json(root, "raw-cases/legacy-numbers.json")?)?,
        fs::read(root.join("raw-cases/legacy-numbers.expected.canon"))?
    );
    Ok(())
}

fn validate_history(root: &Path) -> FixtureResult<()> {
    let expected = read_json(root, "history/expected.json")?;
    let mut history = Vec::new();
    for entry in expected["commits"].as_array().ok_or("history")? {
        let label = entry["label"].as_str().ok_or("label")?;
        let signed = fs::read(root.join(format!("history/{label}.signed.canon")))?;
        let unsigned = fs::read(root.join(format!("history/{label}.unsigned.canon")))?;
        let c = Commit::from_dict(&pyjson::loads(std::str::from_utf8(&signed)?)?)?;
        let device = if c.author == expected["owner"] {
            key(0, 3)
        } else {
            key(1, 4)
        };
        assert!(commit::verify_commit(&c, &device.record()?));
        assert_eq!(c.canonical_json(true)?, signed);
        assert_eq!(c.canonical_json(false)?, unsigned);
        assert_eq!(hash(&signed), entry["hash"]);
        assert_eq!(hash(&unsigned), entry["unsigned_sha256"]);
        assert_eq!(c.sig, entry["sig"]);
        history.push(c);
    }
    let result = fold::fold(
        history.first().ok_or("history")?.env_id.as_str(),
        history.clone(),
        None,
        None,
        None,
        None,
    )?;
    assert!(result.skipped.is_empty());
    let snapshot = read_json(root, "components/snapshot.json")?;
    assert_eq!(result.document, snapshot["document"]);
    assert_eq!(result.version_order, expected["version_order"]);
    assert_eq!(result.version_order, snapshot["version_order"]);
    assert_eq!(value_hash(&result.document)?, expected["document_sha256"]);
    assert_eq!(
        expected["document_sha256"],
        snapshot["expected_final_document_sha256"]
    );
    let retained = read_json(root, "components/commits.json")?;
    assert!(
        !retained["records"]
            .as_array()
            .ok_or("records")?
            .iter()
            .any(|entry| entry["hash"] == expected["compacted_commit_hash"])
    );
    Ok(())
}

fn validate_numeric_records(root: &Path) -> FixtureResult<()> {
    let e = read_json(root, "numeric-records/expected.json")?;
    let signed = fs::read(root.join("numeric-records/commit.signed.canon"))?;
    let c = Commit::from_dict(&pyjson::loads(std::str::from_utf8(&signed)?)?)?;
    assert_eq!(canonical(&c.to_dict())?, signed);
    assert_eq!(c.canonical_json(true)?, signed);
    assert_eq!(
        c.canonical_json(false)?,
        fs::read(root.join("numeric-records/commit.unsigned.canon"))?
    );
    assert_eq!(c.hash()?, e["commit_hash"]);
    assert_eq!(c.sig, e["commit_sig"]);
    assert_eq!(hash(&c.canonical_json(false)?), e["commit_unsigned_sha256"]);
    assert!(commit::verify_commit(&c, &key(0, 3).record()?));
    assert_eq!(c.author_seq.value(), e["author_seq"]);
    assert_eq!(
        c.seen.get(&c.author).ok_or("seen")?.value(),
        e["vector"][&c.author]
    );
    let hlc = Hlc::parse(&c.hlc)?;
    assert_eq!(
        json!({"wall_ms":hlc.0.value(),"counter":hlc.1.value()}),
        e["hlc"]
    );
    let signed = fs::read(root.join("numeric-records/fact.signed.canon"))?;
    let f = Fact::from_dict(&pyjson::loads(std::str::from_utf8(&signed)?)?)?;
    assert_eq!(canonical(&f.to_dict())?, signed);
    assert_eq!(f.canonical_json(true)?, signed);
    assert_eq!(
        f.canonical_json(false)?,
        fs::read(root.join("numeric-records/fact.unsigned.canon"))?
    );
    assert_eq!(f.hash()?, e["fact_hash"]);
    assert_eq!(f.sig, e["fact_sig"]);
    assert_eq!(hash(&f.canonical_json(false)?), e["fact_unsigned_sha256"]);
    assert!(ed25519::verify(
        &key(1, 4).record()?.sign_pub,
        &f.canonical_json(false)?,
        &pybase64::b64decode_strict(&f.sig)?
    ));
    let literal = fs::read(root.join("raw-cases/legacy-numbers.expected.canon"))?;
    assert_eq!(canonical(&c.ops[0]["public"]["legacy_numbers"])?, literal);
    assert_eq!(canonical(&f.target["legacy_numbers"])?, literal);
    Ok(())
}

fn validate_package(root: &Path) -> FixtureResult<()> {
    let m = read_json(root, "manifest.json")?;
    let expected = read_json(root, "expected.json")?;
    let approval = read_json(root, "approval.json")?;
    let context = read_json(root, "context.json")?;
    let signed = fs::read(root.join("manifest.signed.canon"))?;
    let unsigned = fs::read(root.join("manifest.unsigned.canon"))?;
    assert_eq!(canonical(&m)?, signed);
    assert_eq!(fs::read(root.join("manifest.json"))?, signed);
    let mut no_sig = m.clone();
    no_sig.as_object_mut().ok_or("manifest")?.remove("sig");
    assert_eq!(canonical(&no_sig)?, unsigned);
    assert_eq!(hash(&signed), expected["manifest_hash"]);
    assert_eq!(hash(&unsigned), expected["manifest_unsigned_sha256"]);
    assert_eq!(m["sig"], expected["manifest_signature"]);
    let pin = DeviceRecord::from_dict(&approval["signer_record"])?;
    assert!(pin.verify_uncached());
    assert_eq!(pin.fingerprint(), m["signer"]);
    assert_eq!(
        approval["signer_record"],
        context["authenticated_peer_record"]
    );
    assert_eq!(approval, context["approval"]);
    assert_eq!(value_hash(&approval)?, m["approval_sha256"]);
    assert_eq!(m["approval_sha256"], expected["approval_sha256"]);
    assert!(ed25519::verify(
        &pin.sign_pub,
        &unsigned,
        &pybase64::b64decode_strict(m["sig"].as_str().ok_or("sig")?)?
    ));
    for name in [
        "env_id",
        "signer",
        "recipient",
        "recipient_role",
        "invite_id",
        "approval_id",
    ] {
        assert_eq!(m[name], approval[name]);
    }
    for name in ["session_nonce", "onboarding_nonce"] {
        assert_eq!(m[name], context[name]);
    }
    assert_eq!(m["env_id"], context["session_env_id"]);
    assert_eq!(m["recipient"], context["local_recipient"]);
    assert_eq!(m["created_at_ms"], json!(1800000000000_u64));
    assert_eq!(context["check_time_ms"], json!(1800000000001_u64));
    assert_eq!(m["expires_at_ms"], json!(1800000600000_u64));
    assert_eq!(
        m["authorization_expires_at_ms"],
        approval["invitation_expires_at_ms"]
    );
    let payload = fs::read(root.join("payload.json"))?;
    assert_eq!(json!(payload.len()), m["payload"]["byte_length"]);
    assert_eq!(hash(&payload), m["payload"]["sha256"]);
    assert_eq!(m["payload"], expected["payload"]);
    let chunks = m["payload"]["chunks"].as_array().ok_or("chunks")?;
    assert_eq!(chunks.len(), payload.len().div_ceil(65536));
    let mut joined = Vec::new();
    for (index, (chunk, descriptor)) in payload.chunks(65536).zip(chunks).enumerate() {
        let stored = fs::read(root.join(format!("chunks/{index:03}.bin")))?;
        assert_eq!(stored, chunk);
        assert_eq!(descriptor["index"], json!(index));
        assert_eq!(descriptor["byte_length"], json!(chunk.len()));
        assert_eq!(descriptor["sha256"], json!(hash(chunk)));
        let frame = read_json(root, &format!("chunk-{index:03}.json"))?;
        assert_eq!(frame["type"], "BOOTSTRAP_CHUNK");
        assert_eq!(frame["v"], 1);
        assert_eq!(frame["index"], json!(index));
        assert_eq!(frame["manifest_hash"], expected["manifest_hash"]);
        assert_eq!(frame["transfer_id"], m["transfer_id"]);
        let text = frame["data_b64"].as_str().ok_or("b64")?;
        let decoded = pybase64::b64decode_strict(text)?;
        assert_eq!(pybase64::b64encode(&decoded), text);
        assert_eq!(decoded, chunk);
        joined.extend(decoded);
    }
    assert_eq!(joined, payload);
    let p = pyjson::loads(std::str::from_utf8(&payload)?)?;
    assert_eq!(p["format"], "zeropw-team-bootstrap-payload-v1");
    assert_eq!(p["env_id"], m["env_id"]);
    assert_eq!(p["components"].as_array().ok_or("components")?.len(), 6);
    let mut components = Vec::new();
    assert_eq!(m["components"], expected["components"]);
    for (i, name) in NAMES.iter().enumerate() {
        let bytes = fs::read(root.join(format!("components/{name}.json")))?;
        let span = &expected["component_spans"][i];
        let offset = usize::try_from(span["offset"].as_u64().ok_or("offset")?)?;
        assert_eq!(
            payload.get(offset..offset + bytes.len()),
            Some(bytes.as_slice())
        );
        assert_eq!(span["name"], *name);
        assert_eq!(span["byte_length"], json!(bytes.len()));
        assert_eq!(span["sha256"], hash(&bytes));
        assert_eq!(m["components"][i]["sha256"], hash(&bytes));
        assert_eq!(m["components"][i]["byte_length"], json!(bytes.len()));
        assert_eq!(m["components"][i]["name"], *name);
        assert_eq!(p["components"][i]["name"], *name);
        let data = pyjson::loads(std::str::from_utf8(&bytes)?)?;
        assert_eq!(data, p["components"][i]["data"]);
        assert_eq!(canonical(&data)?, bytes);
        components.push(data);
    }
    validate_records(root, &m, &expected, &components)?;
    validate_candidate(root, &m, &expected, &approval, &components[3])?;
    Ok(())
}

fn validate_records(root: &Path, m: &Value, expected: &Value, c: &[Value]) -> FixtureResult<()> {
    let mut devices = BTreeMap::new();
    let mut prior = String::new();
    for entry in c[0].as_array().ok_or("devices")? {
        let record = DeviceRecord::from_dict(&entry["record"])?;
        assert!(record.verify_uncached());
        let fp = record.fingerprint();
        assert_eq!(fp, entry["fingerprint"]);
        assert!(fp > prior);
        prior = fp.clone();
        assert!(devices.insert(fp, record).is_none());
    }
    assert_eq!(devices.len(), 3);
    let env = m["env_id"].as_str().ok_or("env")?;
    assert_eq!(c[1]["vector"], m["vector"]);
    assert_eq!(
        c[1]["expected_final_document_sha256"],
        m["expected_final_document_sha256"]
    );
    let mut records = BTreeMap::new();
    let mut identities = BTreeSet::new();
    let mut bad_signatures = 0;
    for (entry, golden) in c[2]["records"].as_array().ok_or("records")?.iter().zip(
        expected["retained_commits"]
            .as_array()
            .ok_or("expected records")?,
    ) {
        let record = Commit::from_dict(&entry["record"])?;
        assert_eq!(record.canonical_json(true)?, canonical(&entry["record"])?);
        assert_eq!(record.hash()?, entry["hash"]);
        assert_eq!(entry["hash"], golden["hash"]);
        assert_eq!(
            hash(&record.canonical_json(false)?),
            golden["unsigned_sha256"]
        );
        assert_eq!(record.sig, golden["sig"]);
        assert_eq!(record.env_id, env);
        assert_eq!(record.author, golden["author"]);
        assert_eq!(record.author_seq.value(), golden["author_seq"]);
        assert_eq!(record.hlc, golden["hlc"]);
        assert_eq!(record.ops.len(), 1);
        let device = devices.get(&record.author).ok_or("author")?;
        bad_signatures += usize::from(!commit::verify_commit(&record, device));
        assert!(identities.insert((record.author.clone(), record.author_seq.clone())));
        let bound = PyInt::from_json_integer(&m["vector"][&record.author]).ok_or("vector")?;
        assert!(record.author_seq <= bound);
        for fp in record.seen.keys() {
            assert!(devices.contains_key(fp));
        }
        assert!(records.insert(record.hash()?, record).is_none());
    }
    assert_eq!(records.len(), 5);
    assert_eq!(
        bad_signatures,
        if expected["inner_commit_signatures_valid"] == true {
            0
        } else {
            1
        }
    );
    for name in ["genesis_commit_hash", "recipient_admission_commit_hash"] {
        assert!(records.contains_key(c[2][name].as_str().ok_or("reference")?));
    }
    assert_eq!(
        c[2]["recipient_admission_commit_hash"],
        m["recipient_admission_commit_hash"]
    );
    let authority = c[2]["authority_commit_hashes"]
        .as_array()
        .ok_or("authority")?;
    assert_eq!(authority.len(), 3);
    for h in authority {
        assert!(records.contains_key(h.as_str().ok_or("hash")?));
    }
    let mut positive = BTreeSet::new();
    for (fp, seq) in m["vector"].as_object().ok_or("vector")? {
        assert!(devices.contains_key(fp));
        if PyInt::from_json_integer(seq).ok_or("seq")? > PyInt::zero() {
            positive.insert(fp.clone());
        }
    }
    let mut head_authors = BTreeSet::new();
    for head in m["heads"].as_array().ok_or("heads")? {
        let record = records
            .get(head["commit_hash"].as_str().ok_or("head hash")?)
            .ok_or("head")?;
        assert_eq!(record.author, head["author"]);
        assert_eq!(record.author_seq.value(), head["author_seq"]);
        assert_eq!(head["author_seq"], m["vector"][&record.author]);
        let hlc = Hlc::parse(&record.hlc)?;
        assert_eq!(
            json!({"wall_ms":hlc.0.value(),"counter":hlc.1.value()}),
            head["hlc"]
        );
        assert!(head_authors.insert(record.author.clone()));
        for other in records
            .values()
            .filter(|other| other.author == record.author)
        {
            assert!(Hlc::parse(&other.hlc)? <= hlc);
        }
    }
    assert_eq!(head_authors, positive);
    assert_eq!(m["heads"], expected["heads"]);
    assert_eq!(m["vector"], expected["vector"]);
    let mut fact_hashes = Vec::new();
    for entry in c[3]["records"].as_array().ok_or("facts")? {
        let fact = Fact::from_dict(&entry["record"])?;
        assert_eq!(fact.canonical_json(true)?, canonical(&entry["record"])?);
        assert_eq!(fact.hash()?, entry["hash"]);
        assert_eq!(fact.env_id, env);
        assert_eq!(fact.kind, "secret_deleted");
        let device = devices.get(&fact.author).ok_or("fact author")?;
        assert!(ed25519::verify(
            &device.sign_pub,
            &fact.canonical_json(false)?,
            &pybase64::b64decode_strict(&fact.sig)?
        ));
        assert_eq!(
            fact.canonical_json(false)?,
            fs::read(root.join("records/fact.unsigned.canon"))?
        );
        assert_eq!(
            fact.canonical_json(true)?,
            fs::read(root.join("records/fact.signed.canon"))?
        );
        fact_hashes.push(entry["hash"].clone());
    }
    assert_eq!(json!(fact_hashes), c[3]["admitted_fact_hashes"]);
    assert_eq!(json!(fact_hashes), c[3]["tombstone_fact_hashes"]);
    for (field, digest) in [
        ("admitted_fact_hashes", "admitted_fact_hashes_sha256"),
        ("tombstone_fact_hashes", "tombstone_digest"),
    ] {
        assert_eq!(c[3][field], expected[field]);
        assert_eq!(value_hash(&c[3][field])?, m[digest]);
        assert_eq!(m[digest], expected[digest]);
    }
    assert_eq!(
        c[4],
        json!({"bounds":{},"pending":[],"self_placed":[],"witness_commit_hashes":[]})
    );
    let recipient = key(2, 5);
    let wrap_entry = &c[5]["entries"][0];
    assert_eq!(wrap_entry["generation_id"], G);
    assert_eq!(wrap_entry["recipient"], m["recipient"]);
    assert_eq!(
        wrap_entry["source_commit_hash"],
        m["recipient_admission_commit_hash"]
    );
    assert_eq!(wrap_entry["source_op_index"], 0);
    assert_eq!(c[5]["unavailable_generations"], json!([]));
    let admission = records
        .get(wrap_entry["source_commit_hash"].as_str().ok_or("source")?)
        .ok_or("source")?;
    assert_eq!(
        canonical(&wrap_entry["wrap"])?,
        canonical(&admission.ops[0]["wraps"][G])?
    );
    assert_eq!(
        DeviceRecord::from_dict(&admission.ops[0]["device"])?.fingerprint(),
        m["recipient"]
    );
    let dek = envelope::unwrap_dek(&wrap_entry["wrap"], env, G, &recipient)?;
    assert_eq!(dek, [6; 32]);
    let generations = &c[1]["document"]["dek"]["generations"][G]["wraps"];
    for device in [key(0, 3), key(1, 4), key(2, 5)] {
        let fp = device.fingerprint()?;
        assert_eq!(
            envelope::unwrap_dek(&generations[fp], env, G, &device)?,
            [6; 32]
        );
    }
    let secrets = c[1]["document"]["secrets"].as_object().ok_or("secrets")?;
    assert!(!secrets.contains_key("deleted-empty"));
    let versions = secrets[SECRET]["versions"].as_object().ok_or("versions")?;
    assert_eq!(versions.len(), 2);
    for (version, plaintext) in [
        (V1, b"synthetic-checkpoint-v1"),
        (V2, b"synthetic-checkpoint-v2"),
    ] {
        assert_eq!(
            envelope::decrypt_secret(
                &dek,
                env,
                SECRET,
                version,
                versions[version].as_object().ok_or("version")?
            )?,
            plaintext
        );
    }
    assert_eq!(c[1]["version_order"], json!({SECRET:[V1,V2]}));
    assert_eq!(c[1]["document"]["secrets"][SECRET]["active_version"], V2);
    let counts = json!({"devices":devices.len(),"commits":records.len(),"facts":fact_hashes.len(),
                       "versions":versions.len(),"recipient_wraps":c[5]["entries"].as_array().ok_or("wraps")?.len()});
    assert_eq!(counts, m["counts"]);
    assert_eq!(counts, expected["counts"]);
    for (i, count) in [3, 1, 5, fact_hashes.len(), 1, 1].into_iter().enumerate() {
        assert_eq!(m["components"][i]["item_count"], json!(count));
    }
    Ok(())
}

fn validate_candidate(
    root: &Path,
    m: &Value,
    expected: &Value,
    approval: &Value,
    facts: &Value,
) -> FixtureResult<()> {
    let c = read_json(root, "candidate.json")?;
    assert_eq!(
        hash(&fs::read(root.join("candidate.json"))?),
        expected["candidate_sha256"]
    );
    assert_eq!(canonical(&c)?, fs::read(root.join("candidate.json"))?);
    // Explicit independent schema: no extra output fields or implied authority.
    let fields = [
        "format",
        "v",
        "trust_model",
        "stage",
        "env_id",
        "manifest_hash",
        "signer",
        "signer_record",
        "recipient",
        "recipient_role",
        "invite_id",
        "approval_id",
        "approval_sha256",
        "session_nonce",
        "onboarding_nonce",
        "transfer_id",
        "recipient_authorization_id",
        "recipient_admission_commit_hash",
        "vector",
        "heads",
        "components",
        "payload_sha256",
        "admitted_fact_hashes_sha256",
        "tombstone_digest",
        "expected_final_document_sha256",
        "candidate_fact_bindings",
        "candidate_tombstone_fact_hashes",
    ];
    assert_eq!(
        c.as_object()
            .ok_or("candidate")?
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        fields.into_iter().collect()
    );
    assert_eq!(c["format"], "zeropw-team-checkpoint-candidate-v1");
    assert_eq!(c["v"], 1);
    assert_eq!(c["trust_model"], "administrator_attested");
    assert_eq!(c["stage"], "integrity_checked_not_admitted");
    assert_eq!(c["signer_record"], approval["signer_record"]);
    assert_eq!(c["manifest_hash"], expected["manifest_hash"]);
    assert_eq!(c["payload_sha256"], m["payload"]["sha256"]);
    for name in [
        "env_id",
        "signer",
        "recipient",
        "recipient_role",
        "invite_id",
        "approval_id",
        "approval_sha256",
        "session_nonce",
        "onboarding_nonce",
        "transfer_id",
        "recipient_authorization_id",
        "recipient_admission_commit_hash",
        "vector",
        "heads",
        "components",
        "admitted_fact_hashes_sha256",
        "tombstone_digest",
        "expected_final_document_sha256",
    ] {
        assert_eq!(c[name], m[name]);
    }
    assert_eq!(
        c["candidate_tombstone_fact_hashes"],
        facts["tombstone_fact_hashes"]
    );
    let bindings = c["candidate_fact_bindings"].as_array().ok_or("bindings")?;
    let hashes = facts["admitted_fact_hashes"].as_array().ok_or("facts")?;
    assert_eq!(bindings.len(), hashes.len());
    for (binding, h) in bindings.iter().zip(hashes) {
        assert_eq!(
            binding,
            &json!({"fact_hash":h,"manifest_hash":expected["manifest_hash"],
            "approved_signer":approval["signer"],"approval_sha256":m["approval_sha256"],
            "basis":"administrator_attested_candidate"})
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/team_checkpoint_v1")
    }

    #[test]
    fn stored_crypto_and_literal_goldens() -> FixtureResult<()> {
        validate(&fixtures())
    }

    #[test]
    fn deterministic_regeneration_and_complete_inventory() -> FixtureResult<()> {
        let temp = tempfile::tempdir()?;
        generate(temp.path())?;
        let mut stored = BTreeMap::new();
        let mut regenerated = BTreeMap::new();
        collect(&fixtures(), &fixtures(), &mut stored)?;
        collect(temp.path(), temp.path(), &mut regenerated)?;
        assert_eq!(
            stored.keys().collect::<Vec<_>>(),
            regenerated.keys().collect::<Vec<_>>()
        );
        for (name, bytes) in stored {
            assert_eq!(bytes, regenerated[&name], "{name}");
        }
        Ok(())
    }

    #[test]
    fn deletion_variants_retain_unflushed_encrypted_versions() -> FixtureResult<()> {
        let root = fixtures();
        let base = read_json(&root, "components/snapshot.json")?;
        for variant in ["deleted-empty", "deleted-retained"] {
            let path = root.join("variants").join(variant);
            assert_eq!(read_json(&path, "components/snapshot.json")?, base);
            let facts = read_json(&path, "components/facts.json")?;
            assert_eq!(facts["records"].as_array().ok_or("records")?.len(), 1);
            assert_eq!(
                facts["tombstone_fact_hashes"]
                    .as_array()
                    .ok_or("hashes")?
                    .len(),
                1
            );
            assert_eq!(
                read_json(&path, "expected.json")?["final_document_claim_verified_from_complete_no_fact_history"],
                false
            );
        }
        let changed = read_json(
            &root.join("variants/changed-final-digest"),
            "components/snapshot.json",
        )?;
        assert_eq!(changed["document"], base["document"]);
        assert_eq!(changed["version_order"], base["version_order"]);
        assert_ne!(
            changed["expected_final_document_sha256"],
            value_hash(&changed["document"])?
        );
        Ok(())
    }

    #[test]
    fn byte_corruption_is_detected_by_consistency_check() -> FixtureResult<()> {
        let temp = tempfile::tempdir()?;
        generate(temp.path())?;
        let path = temp.path().join("payload.json");
        let mut bytes = fs::read(&path)?;
        bytes.push(b' ');
        fs::write(path, bytes)?;
        // Consistency assertions are test-only; this is not a product error API.
        assert!(std::panic::catch_unwind(|| validate(temp.path()).unwrap()).is_err());
        Ok(())
    }
}
