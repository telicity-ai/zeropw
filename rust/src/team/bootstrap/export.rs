//! Immutable complete admitted-state export. Never copies a local vault,
//! private device key, local admission receipt, KMS wrapper, or grant.
use super::{
    approval, bad, bytes, digest,
    protocol::{CHUNK_CAP, PAYLOAD_CAP},
    random, text,
};
use crate::{
    context::Context,
    errors::Result,
    team::{
        checkpoint::*,
        commit::{Commit, CommitStore, HistorySession, Hlc},
        fold,
        identity::{DeviceKey, DeviceRecord},
        sync,
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct Export {
    pub(crate) manifest: Value,
    pub(crate) payload: Vec<u8>,
    cut: String,
    admission: Commit,
    recipient: DeviceRecord,
}
struct Cut {
    snapshot: Value,
    final_digest: String,
    commits: Vec<Commit>,
    facts: BTreeMap<String, sync::Fact>,
    vector: BTreeMap<String, crate::pyint::PyInt>,
    tombstone: String,
    revision: String,
    semantic: String,
}

fn collect(
    ctx: &Context,
    env: &str,
    admission: &Commit,
    history: &HistorySession<'_>,
) -> Result<Cut> {
    approval::profile_with_input(ctx, env, Some(admission), history)?;
    let store = CommitStore::new(ctx.state, env);
    let (effects, admitted, _) = sync::load_facts_with_input(ctx, env, history)?;
    let input = history.acquire()?;
    let commits = input.commits()?;
    let mut facts = BTreeMap::new();
    for line in input.read_lines(&format!("team/{env}/facts.jsonl"))? {
        let v = history.parse_line(&line)?;
        let f = sync::Fact::from_dict(&v)?;
        let hash = f.hash()?;
        if !admitted.contains(&hash) {
            return Err(bad("team_bootstrap_state_invalid"));
        }
        facts.insert(hash, f);
    }
    for v in input.shared_facts()? {
        let f = sync::Fact::from_dict(&v)?;
        facts.insert(f.hash()?, f);
    }
    if facts.keys().collect::<BTreeSet<_>>() != admitted.iter().collect() {
        return Err(bad("team_bootstrap_state_invalid"));
    }
    let vector = input.vector()?;
    for (author, seq) in &vector {
        if *seq > 0 && store.get(author, seq.clone())?.is_none() {
            return Err(bad("team_checkpoint_history_required"));
        }
    }
    input.reserve_fold(&commits, Some(&effects), 1)?;
    let unflushed = fold::snapshot_of_prefix(
        env,
        commits.clone(),
        ctx.state,
        Some(&effects),
        &commits,
        None,
    )?;
    input.reserve_fold(&commits, Some(&effects), 1)?;
    let final_image = input.fold_with_snapshot(commits.clone(), &effects, None)?;
    if unflushed.vector != vector || final_image.vector != vector {
        return Err(bad("team_checkpoint_history_required"));
    }
    let snapshot = json!({"document":unflushed.document,"vector":vector,"version_order":unflushed.version_order});
    let final_digest = digest(&final_image.document)?;
    let semantic = digest(
        &json!({"snapshot":snapshot,"final":final_digest,"commits":commits.iter().map(Commit::to_dict).collect::<Vec<_>>(),"facts":facts.iter().map(|(h,f)|json!({"hash":h,"record":f.to_dict()})).collect::<Vec<_>>()}),
    )?;
    let revision =
        digest(&json!({"semantic":semantic,"raw_cut":history.acquire()?.cut_revision()?}))?;
    Ok(Cut {
        snapshot,
        final_digest,
        commits,
        facts,
        vector,
        tombstone: sync::personal_tombstone_digest(&effects)?,
        revision,
        semantic,
    })
}

pub(crate) fn create(
    ctx: &Context,
    env: &str,
    peer: &DeviceRecord,
    request: &Value,
    session_nonce: &str,
) -> Result<Export> {
    let history = HistorySession::open_runtime(ctx.state, env)?;
    history.preflight_inventory()?;
    crate::import_barrier::validate_environment_tree(ctx.state, env)?;
    history.check()?;
    let auth = approval::recover_admission(ctx, env, peer, &history)?;
    if auth["cancelled"] == true {
        return Err(bad("team_bootstrap_cancelled"));
    }
    let admission = Commit::from_dict(&auth["admission"])?;
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms)?;
    history.match_local_identity(&device.record()?)?;
    let owner = device.record()?;
    let receiver = &request["approval"];
    let mut signed = receiver.clone();
    let sig = signed
        .as_object_mut()
        .ok_or_else(|| bad("team_bootstrap_approval_changed"))?
        .remove("sig")
        .ok_or_else(|| bad("team_bootstrap_approval_changed"))?;
    let signature = crate::pybase64::b64decode_strict(
        sig.as_str()
            .ok_or_else(|| bad("team_bootstrap_approval_changed"))?,
    )
    .map_err(|_| bad("team_bootstrap_approval_changed"))?;
    if receiver["domain"] != "zeropw-personal-bootstrap-approval-v1"
        || receiver["state"] != "approved"
        || receiver["recipient_role"] != "admin"
        || receiver["trust_model"] != "administrator_attested"
        || receiver["recipient_record"] != peer.to_dict()
        || receiver["signer_record"] != owner.to_dict()
        || receiver["env_id"] != env
        || receiver["invite_id"] != auth["invite_id"]
        || !crate::crypto::ed25519::verify(&peer.sign_pub, &bytes(&signed)?, &signature)
    {
        return Err(bad("team_bootstrap_approval_changed"));
    }
    let expires = receiver["invitation_expires_at_ms"]
        .as_u64()
        .ok_or_else(|| bad("team_bootstrap_approval_changed"))?;
    if auth["expires_at_ms"].as_u64() != Some(expires) {
        return Err(bad("team_bootstrap_approval_changed"));
    }
    let expected = ExpectedContext::from_local_expectations(
        LocalApprovalDescription {
            approval_id: text(receiver, "approval_id")?.into(),
            env_id: env.into(),
            signer: owner.fingerprint(),
            signer_record: owner.clone(),
            recipient: peer.fingerprint(),
            recipient_role: RecipientRole::Admin,
            invite_id: text(receiver, "invite_id")?.into(),
            invitation_expires_at_ms: expires,
        },
        AuthenticatedSessionExpectations {
            peer_record: owner.clone(),
            env_id: env.into(),
            local_recipient: peer.fingerprint(),
            session_nonce: session_nonce.into(),
            onboarding_nonce: text(request, "onboarding_nonce")?.into(),
        },
    )
    .map_err(|e| bad(e.reason()))?;
    let cut = collect(ctx, env, &admission, &history)?;
    if cut
        .commits
        .len()
        .checked_add(cut.facts.len())
        .is_none_or(|n| n > 65_536)
    {
        return Err(bad("team_bootstrap_limit_exceeded"));
    }
    let devices = [
        (owner.fingerprint(), owner.to_dict()),
        (peer.fingerprint(), peer.to_dict()),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>()
    .into_iter()
    .map(|(fingerprint, record)| json!({"fingerprint":fingerprint,"record":record}))
    .collect::<Vec<_>>();
    let mut originals = BTreeMap::new();
    let mut authority = BTreeSet::new();
    let mut wraps = Vec::new();
    let mut genesis = None;
    for c in &cut.commits {
        let hash = c.hash()?;
        for (index, op) in c.ops.iter().enumerate() {
            if fold::checkpoint_authority_kind(op["op"].as_str().unwrap_or("")) {
                authority.insert(hash.clone());
            }
            if op["op"] == "env.init" {
                genesis = Some(hash.clone());
            }
            if op["op"] == "member.add" && op["device"] == peer.to_dict() {
                for (generation, wrap) in op["wraps"].as_object().into_iter().flatten() {
                    wraps.push(json!({"generation_id":generation,"recipient":peer.fingerprint(),"source_commit_hash":hash,"source_op_index":index,"wrap":wrap}));
                }
            }
            if op["op"] == "dek.rotate" {
                for (fp, wrap) in op["wraps"].as_object().into_iter().flatten() {
                    if fp == &peer.fingerprint() {
                        wraps.push(json!({"generation_id":op["generation_id"],"recipient":fp,"source_commit_hash":hash,"source_op_index":index,"wrap":wrap}));
                    }
                }
            }
        }
        originals.insert(hash.clone(), json!({"hash":hash,"record":c.to_dict()}));
    }
    let mut unavailable = Vec::new();
    for generation in cut.snapshot["document"]["dek"]["generations"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(k, _)| k)
    {
        if !wraps.iter().any(|v| v["generation_id"] == *generation) {
            unavailable.push(generation.clone());
        }
    }
    wraps.sort_by_key(|w| {
        (
            w["generation_id"].as_str().unwrap_or("").to_owned(),
            w["source_commit_hash"].as_str().unwrap_or("").to_owned(),
            w["source_op_index"].as_u64().unwrap_or(0),
        )
    });
    let version_count = cut.snapshot["document"]["secrets"]
        .as_object()
        .into_iter()
        .flatten()
        .try_fold(0usize, |n, (_, s)| {
            n.checked_add(s["versions"].as_object().map_or(0, |v| v.len()))
        })
        .ok_or_else(|| bad("team_bootstrap_limit_exceeded"))?;
    if originals
        .len()
        .checked_add(cut.facts.len())
        .and_then(|n| n.checked_add(version_count))
        .is_none_or(|n| n > 65_536)
    {
        return Err(bad("team_bootstrap_limit_exceeded"));
    }
    let names = [
        "devices",
        "snapshot",
        "commits",
        "facts",
        "removals",
        "recipient_dek_wraps",
    ];
    let mut snapshot = cut.snapshot.clone();
    snapshot["expected_final_document_sha256"] = json!(cut.final_digest);
    let data = [
        json!(devices),
        snapshot,
        json!({"records":originals.values().collect::<Vec<_>>(),"authority_commit_hashes":authority,"genesis_commit_hash":genesis.ok_or_else(||bad("team_bootstrap_authority_unproven"))?,"recipient_admission_commit_hash":admission.hash()?}),
        json!({"records":cut.facts.iter().map(|(hash,f)|json!({"hash":hash,"record":f.to_dict()})).collect::<Vec<_>>(),"admitted_fact_hashes":cut.facts.keys().collect::<Vec<_>>(),"tombstone_fact_hashes":cut.facts.iter().filter(|(_,f)|f.kind=="secret_deleted").map(|(h,_)|h).collect::<Vec<_>>()}),
        json!({"bounds":{},"pending":[],"self_placed":[],"witness_commit_hashes":[]}),
        json!({"entries":wraps,"unavailable_generations":unavailable}),
    ];
    let counts = [
        devices.len(),
        1,
        originals.len(),
        cut.facts.len(),
        1,
        wraps.len(),
    ];
    let components = names
        .iter()
        .zip(data)
        .map(|(name, data)| json!({"name":name,"data":data}))
        .collect::<Vec<_>>();
    let payload = bytes(
        &json!({"format":"zeropw-team-bootstrap-payload-v1","v":1,"env_id":env,"components":components}),
    )?;
    if payload.len() > PAYLOAD_CAP {
        return Err(bad("team_bootstrap_limit_exceeded"));
    }
    let mut heads = Vec::new();
    for (author, seq) in &cut.vector {
        if *seq > 0 {
            let c = CommitStore::new(ctx.state, env)
                .get(author, seq.clone())?
                .ok_or_else(|| bad("team_checkpoint_history_required"))?;
            let (wall, counter) = Hlc::parse(&c.hlc)?;
            heads.push(json!({"author":author,"author_seq":seq,"commit_hash":c.hash()?,"hlc":{"wall_ms":wall,"counter":counter}}));
        }
    }
    let now = ((ctx.clock)() * 1000.0) as u64;
    let mut manifest = json!({"type":"BOOTSTRAP_MANIFEST","domain":"zeropw-team-bootstrap-v1","v":1,"trust_model":"administrator_attested","env_id":env,"signer":owner.fingerprint(),"recipient":peer.fingerprint(),"recipient_role":"admin","invite_id":receiver["invite_id"],"approval_id":receiver["approval_id"],"approval_sha256":expected.approval_sha256(),"session_nonce":session_nonce,"onboarding_nonce":request["onboarding_nonce"],"transfer_id":random(16),"recipient_authorization_id":auth["authorization_id"],"recipient_admission_commit_hash":admission.hash()?,"created_at_ms":now,"expires_at_ms":now.saturating_add(600_000).min(expires),"authorization_expires_at_ms":expires,"required_features":["secret_tombstone_v1",super::FEATURE],"vector":cut.vector,"heads":heads,"admitted_fact_hashes_sha256":digest(&json!(cut.facts.keys().collect::<Vec<_>>()))?,"tombstone_digest":cut.tombstone,"expected_final_document_sha256":cut.final_digest,"counts":{"devices":devices.len(),"commits":originals.len(),"facts":cut.facts.len(),"versions":version_count,"recipient_wraps":wraps.len()},"components":components.iter().zip(counts).map(|(c,count)|{let b=bytes(&c["data"])?;Ok(json!({"name":c["name"],"byte_length":b.len(),"sha256":hex::encode(Sha256::digest(&b)),"item_count":count}))}).collect::<Result<Vec<_>>>()?,"payload":{"byte_length":payload.len(),"sha256":hex::encode(Sha256::digest(&payload)),"chunks":payload.chunks(CHUNK_CAP).enumerate().map(|(i,b)|json!({"index":i,"byte_length":b.len(),"sha256":hex::encode(Sha256::digest(b))})).collect::<Vec<_>>()}});
    history.check()?;
    manifest["sig"] = json!(crate::pybase64::b64encode(
        &device.sign(&bytes(&manifest)?)?
    ));
    verify_manifest_bytes(
        &bytes(&manifest)?,
        &expected,
        VerificationWallTime::from_millis(now).map_err(|e| bad(e.reason()))?,
    )
    .map_err(|e| bad(e.reason()))?;
    history.check()?;
    let ap = super::path(env, &format!("authorizations/{}.json", peer.fingerprint()))?;
    let mut recorded = ctx.state.read_json(&ap, Value::Null)?;
    recorded["last_manifest_hash"] = json!(digest(&manifest)?);
    recorded["last_manifest"] = manifest.clone();
    crate::import_barrier::json(ctx.state, &ap, &recorded)?;
    let recorded_cut = collect(ctx, env, &admission, &history)?;
    if recorded_cut.semantic != cut.semantic {
        return Err(bad("team_bootstrap_cut_changed"));
    }
    history.check()?;
    Ok(Export {
        manifest,
        payload,
        cut: recorded_cut.revision,
        admission,
        recipient: peer.clone(),
    })
}

impl Export {
    pub(crate) fn finalize(
        &self,
        ctx: &Context,
        session_nonce: &str,
        challenge: &str,
    ) -> Result<Value> {
        let env = text(&self.manifest, "env_id")?;
        let history = HistorySession::open_runtime(ctx.state, env)?;
        let auth = approval::recover_admission(ctx, env, &self.recipient, &history)?;
        if auth["cancelled"] == true {
            return Err(bad("team_bootstrap_cancelled"));
        }
        if auth["authorization_id"] != self.manifest["recipient_authorization_id"]
            || auth["expires_at_ms"]
                .as_u64()
                .is_none_or(|t| t <= ((ctx.clock)() * 1000.0) as u64)
            || collect(ctx, env, &self.admission, &history)?.revision != self.cut
        {
            return Err(bad("team_bootstrap_cut_changed"));
        }
        let mut ready = json!({"type":"BOOTSTRAP_READY","domain":"zeropw-team-bootstrap-ready-v1","env_id":env,"signer":self.manifest["signer"],"recipient":self.manifest["recipient"],"approval_id":self.manifest["approval_id"],"invite_id":self.manifest["invite_id"],"authorization_id":self.manifest["recipient_authorization_id"],"transfer_id":self.manifest["transfer_id"],"manifest_hash":digest(&self.manifest)?,"session_nonce":session_nonce,"onboarding_nonce":self.manifest["onboarding_nonce"],"challenge":challenge});
        let device = DeviceKey::load_or_create(ctx.state, ctx.kms)?;
        history.match_local_identity(&device.record()?)?;
        history.check()?;
        ready["sig"] = json!(crate::pybase64::b64encode(&device.sign(&bytes(&ready)?)?));
        history.check()?;
        Ok(ready)
    }
}
