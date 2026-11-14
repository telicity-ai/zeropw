//! Private runtime validation for the explicitly attested missing DATA prefix.
//! This never constructs complete-coverage or required-generation candidates.
use super::{
    VerificationWallTime,
    admission::*,
    document,
    manifest::{field, text, value_hash},
    originals::AuthenticatedOriginals,
    verify_manifest_bytes, verify_payload_bytes, verify_retained_authority,
};
use crate::{
    context::Context,
    errors::Result,
    team::{
        bootstrap::{self, approval::ReceiverApproval},
        commit::{self},
        fold,
        identity::DeviceKey,
        sync,
        transport::Session,
    },
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// An install plan can only be produced by this locked runtime validator.
/// Fields and construction remain private; there is no JSON or public-key API.
pub(crate) struct Plan {
    state: &'static crate::store::StateDir,
    budget: commit::HistoryResume<'static>,
    manifest: Value,
    manifest_bytes: Vec<u8>,
    payload: Vec<u8>,
    unflushed: Value,
    folded: fold::FoldResult,
    commits: Vec<commit::Commit>,
    facts: Vec<sync::Fact>,
    wrapped: BTreeMap<String, Value>,
    observation: String,
    mapping: LocalMapping,
    approval_hash: String,
    attestor: crate::team::identity::DeviceRecord,
}
impl Plan {
    pub(crate) fn manifest(&self) -> &Value {
        &self.manifest
    }
    pub(crate) fn originals(&self) -> (&[u8], &[u8]) {
        (&self.manifest_bytes, &self.payload)
    }
    pub(crate) fn snapshot(&self) -> &Value {
        &self.unflushed
    }
    pub(crate) fn folded(&self) -> &fold::FoldResult {
        &self.folded
    }
    pub(crate) fn commits(&self) -> &[commit::Commit] {
        &self.commits
    }
    pub(crate) fn facts(&self) -> &[sync::Fact] {
        &self.facts
    }
    pub(crate) fn wrapped(&self) -> &BTreeMap<String, Value> {
        &self.wrapped
    }
    pub(crate) fn mapping(&self) -> &LocalMapping {
        &self.mapping
    }
    pub(crate) fn resume(&self, ctx: &Context) -> Result<commit::HistorySession<'static>> {
        if !std::ptr::eq(self.state, ctx.state) {
            return Err(bootstrap::bad("team_bootstrap_local_state_changed"));
        }
        self.budget.resume()
    }
    pub(crate) fn recheck(&self, ctx: &Context) -> Result<()> {
        let history = self.resume(ctx)?;
        if !ctx.state.locked_by_current_thread()
            || observe(ctx, &self.mapping, &history)?.revision != self.observation
        {
            return Err(bootstrap::bad("team_bootstrap_local_state_changed"));
        }
        let approval = ReceiverApproval::load(ctx, &self.mapping.env_id, &self.attestor)?;
        if bootstrap::digest(approval.record())? != self.approval_hash {
            return Err(bootstrap::bad("team_bootstrap_approval_changed"));
        }
        Ok(())
    }
}

struct Observation {
    local: SemanticLocalInputs,
    revision: String,
}

fn phase(ctx: &Context, env: &str, value: &str) -> Result<()> {
    crate::import_barrier::json(
        ctx.state,
        &bootstrap::path(env, "validation-status.json")?,
        &json!({"phase":value}),
    )
}

fn observe(
    ctx: &Context,
    mapping: &LocalMapping,
    history: &commit::HistorySession<'_>,
) -> Result<Observation> {
    let state = ctx.state;
    let input = history.acquire()?;
    let env = &mapping.env_id;
    if !state.locked_by_current_thread() {
        return Err(bootstrap::bad("team_bootstrap_local_state_changed"));
    }
    crate::import_barrier::validate_inventory(state, env)?;
    // A PREPARED transaction is a public deny witness. The sealed preimage
    // observation reads the original index/mapping DATA under its parent;
    // it does not turn that unpublished journal into visibility authority.
    let io = history.import_io()?;
    let imports = crate::import_barrier::raw_index_in(&io)?;
    if imports.get(env).is_some()
        || imports.as_object().into_iter().flatten().any(|(_, r)| {
            r["project"] == mapping.project && r["environment"] == mapping.environment
        })
    {
        return Err(bootstrap::bad("team_bootstrap_existing_state_unsupported"));
    }
    let vault = state.read_json(crate::vault::VAULT_DOC, Value::Null)?;
    let connections = state.read_json(crate::policy::CONNECTIONS, json!({}))?;
    let ledger = crate::tombstone::load(state)?;
    let maps = io
        .json(sync::ENVS_MAP_PATH, 67_108_864)?
        .unwrap_or_else(|| json!({}));
    let projects = state.read_json(crate::projects::DOC, json!({}))?;
    let control = state.read_json(crate::policy::CONTROL, json!({}))?;
    let known = state.read_json(&bootstrap::path(env, "known-facts.json")?, json!({}))?;
    let commits = input.commits()?;
    let facts = state.read_lines_in(&io, &format!("team/{env}/facts.jsonl"), None)?;
    let mut checkpoints = 0;
    for name in ["snapshots", "snapshot_records"] {
        let p = state.path.join(format!("team/{env}/{name}"));
        if p.exists() {
            checkpoints += std::fs::read_dir(p)
                .map_err(|_| bootstrap::bad("team_bootstrap_local_state_changed"))?
                .count();
        }
    }
    for (id, v) in maps.as_object().into_iter().flatten() {
        if id != env && v["project"] == mapping.project && v["environment"] == mapping.environment {
            return Err(bootstrap::bad("team_bootstrap_existing_state_unsupported"));
        }
    }
    if projects
        .get(&mapping.project)
        .and_then(|p| p["environments"].as_array())
        .is_some_and(|e| e.contains(&json!(mapping.environment)))
    {
        return Err(bootstrap::bad("team_bootstrap_existing_state_unsupported"));
    }
    let mut occupied = Vec::new();
    let mut derived = 0;
    for (_, record) in imports.as_object().into_iter().flatten() {
        for (kind, field) in [
            (LocalIdKind::Secret, "secret_ids"),
            (LocalIdKind::Connection, "connection_ids"),
        ] {
            for id in record[field]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                occupied.push(OccupiedLocalId {
                    id: id.into(),
                    kind,
                    scope: LocalIdScope::Private {
                        project: record["project"].as_str().unwrap_or("").into(),
                        environment: record["environment"].as_str().unwrap_or("").into(),
                    },
                });
            }
        }
    }
    for (kind, entries) in [
        (LocalIdKind::Secret, &vault["secrets"]),
        (LocalIdKind::Connection, &connections),
    ] {
        for (id, v) in entries.as_object().into_iter().flatten() {
            if v["shared_env"] == *env {
                derived += 1;
            }
            occupied.push(OccupiedLocalId {
                id: id.clone(),
                kind,
                scope: LocalIdScope::Private {
                    project: v["project"].as_str().unwrap_or("").into(),
                    environment: v["environment"].as_str().unwrap_or("").into(),
                },
            });
        }
    }
    // A deleted local identity is still occupied even if its ciphertext vanished.
    for (id, entry) in ledger["local"].as_object().into_iter().flatten() {
        occupied.push(OccupiedLocalId {
            id: id.clone(),
            kind: LocalIdKind::Secret,
            scope: LocalIdScope::Private {
                project: entry["project"].as_str().unwrap_or("").into(),
                environment: entry["environment"].as_str().unwrap_or("").into(),
            },
        });
    }
    let existing_mapping = maps.get(env).map(|m| LocalMapping {
        project: m["project"].as_str().unwrap_or("").into(),
        environment: m["environment"].as_str().unwrap_or("").into(),
        env_id: env.clone(),
    });
    #[cfg(test)]
    for (label, value) in [
        ("imports", &imports),
        ("vault", &vault),
        ("connections", &connections),
        ("ledger", &ledger),
        ("maps", &maps),
        ("projects", &projects),
        ("control", &control),
        ("known", &known),
    ] {
        crate::import_barrier::opus_cost::note_hash(state, env, label, value);
    }
    let revision = bootstrap::digest(
        &json!({"imports":imports,"vault":vault,"connections":connections,"ledger":ledger,"maps":maps,"projects":projects,"control":control,"known_facts":known,"commits":commits.iter().map(commit::Commit::to_dict).collect::<Vec<_>>(),"facts":facts,"checkpoints":checkpoints}),
    )?;
    let device = DeviceKey::load_or_create(state, ctx.kms)?.record()?;
    let local = SemanticLocalInputs::from_local_observation(
        SemanticBindings {
            recipient_record: device,
            recipient_role: super::RecipientRole::Admin,
            env_id: env.clone(),
            manifest_hash: "00".repeat(32),
            approval_sha256: "00".repeat(32),
            session_nonce: "00".repeat(32),
            onboarding_nonce: "00".repeat(32),
            intended_mapping: mapping.clone(),
            observation_revision: revision.clone(),
        },
        ObservedInventory {
            admitted_commits: commits.len(),
            admitted_facts: facts.len(),
            checkpoints,
            derived_team_entries: derived,
            unsent_edits: 0,
            pending_imports: 0,
            completed_imports: usize::from(state.exists(&bootstrap::path(env, "receipt.json")?)),
            stale_restore: control["restore_pending"] == true,
            existing_mapping,
            own_staging_manifest_hash: None,
        },
        occupied,
        LocalRestrictions {
            known_original_facts: Vec::new(),
            deleted_secret_ids: BTreeSet::new(),
            revoked_versions: BTreeSet::new(),
            disabled_connection_ids: BTreeSet::new(),
            removed_members: BTreeSet::new(),
            restored_bindings: Vec::new(),
            required_tombstone_support: RequiredTombstoneSupport::NotObserved,
            backup_barrier: control["restore_pending"] == true,
        },
    )
    .map_err(|e| bootstrap::bad(e.reason()))?;
    let raw_targets = history.acquire()?.target_revision()?;
    #[cfg(test)]
    crate::import_barrier::opus_cost::note(state, env, &format!("raw_targets:{raw_targets}"));
    let revision = bootstrap::digest(&json!({"semantic":revision,"raw_targets":raw_targets}))?;
    Ok(Observation { local, revision })
}

fn reserve_import(
    history: &commit::HistorySession<'_>,
    payload: &super::IntegrityCheckedPayload<'_>,
    raw_bytes: u64,
) -> Result<()> {
    let c = payload.index.commits.len() as u64;
    let t = payload.index.facts.len() as u64;
    history.reserve_counts([c, 0, t, 0, 0, 1, raw_bytes])?;
    let mut o = 0u64;
    let mut f = 0u64;
    let mut d = 0u64;
    for span in &payload.index.commits {
        history.screen_original(span.bytes())?;
        let value = super::strict_json::materialize(span)
            .map_err(|e| bootstrap::bad(super::CheckpointError::from(e).reason()))?;
        let count = match &value["record"]["ops"] {
            Value::Array(v) => v.len(),
            Value::Object(v) => v.len(),
            Value::String(v) => v.len(),
            _ => 1,
        };
        o = o
            .checked_add(count as u64)
            .ok_or_else(|| bootstrap::bad("team_bootstrap_limit_exceeded"))?;
    }
    for span in &payload.index.facts {
        history.screen_original(span.bytes())?;
        let value = super::strict_json::materialize(span)
            .map_err(|e| bootstrap::bad(super::CheckpointError::from(e).reason()))?;
        if value["record"]["kind"] == "member_removed" {
            f = f
                .checked_add(1)
                .ok_or_else(|| bootstrap::bad("team_bootstrap_limit_exceeded"))?;
        }
    }
    let snapshot = super::strict_json::materialize(&payload.index.components[1])
        .map_err(|e| bootstrap::bad(super::CheckpointError::from(e).reason()))?;
    for value in [&snapshot["document"], &snapshot["version_order"]] {
        let mut pending = vec![value];
        while let Some(value) = pending.pop() {
            d = d
                .checked_add(1)
                .filter(|n| *n <= 1_048_576)
                .ok_or_else(|| bootstrap::bad("team_bootstrap_limit_exceeded"))?;
            match value {
                Value::Object(v) => pending.extend(v.values()),
                Value::Array(v) => pending.extend(v),
                _ => {}
            }
        }
    }
    history.reserve_counts([c, o, t, f, d, 1, raw_bytes])?;
    let signatures = c
        .checked_add(t)
        .and_then(|n| n.checked_add(2))
        .and_then(|n| n.checked_mul(4096))
        .ok_or_else(|| bootstrap::bad("team_bootstrap_limit_exceeded"))?;
    history.charge(
        signatures,
        raw_bytes
            .checked_mul(4)
            .ok_or_else(|| bootstrap::bad("team_bootstrap_limit_exceeded"))?,
    )?;
    history.check()
}

pub(crate) fn validate(
    ctx: &Context,
    raw_manifest: &[u8],
    raw_payload: &[u8],
    approval: &ReceiverApproval,
    session: &dyn Session,
    session_nonce: &str,
    onboarding_nonce: &str,
) -> Result<Plan> {
    let a = approval.record();
    let env = bootstrap::text(a, "env_id")?;
    let history = commit::HistorySession::open_probe(ctx, env, commit::ProbePurpose::Recipient)?;
    history.screen_original(raw_manifest)?;
    history.screen_original(raw_payload)?;
    if session.is_closed() || session.env_id() != env {
        return Err(bootstrap::bad("team_bootstrap_session_changed"));
    }
    let peer = session.peer();
    let fresh = ReceiverApproval::load(ctx, env, &peer)?;
    crate::import_barrier::validate_environment_tree(ctx.state, env)?;
    if bootstrap::digest(fresh.record())? != bootstrap::digest(a)? {
        return Err(bootstrap::bad("team_bootstrap_approval_changed"));
    }
    let expected = approval.expected(&peer, session_nonce, onboarding_nonce)?;
    let now = VerificationWallTime::from_millis(((ctx.clock)() * 1000.0) as u64)
        .map_err(|e| bootstrap::bad(e.reason()))?;
    let manifest = verify_manifest_bytes(raw_manifest, &expected, now)
        .map_err(|e| bootstrap::bad(e.reason()))?;
    let payload =
        verify_payload_bytes(&manifest, raw_payload).map_err(|e| bootstrap::bad(e.reason()))?;
    let mapping = LocalMapping {
        project: bootstrap::text(a, "project")?.into(),
        environment: bootstrap::text(a, "environment")?.into(),
        env_id: env.into(),
    };
    phase(ctx, env, "local_observation")?;
    let mut observation = observe(ctx, &mapping, &history)?;
    observation.local.bindings.manifest_hash = manifest.manifest_hash().into();
    observation.local.bindings.approval_sha256 = expected.approval_sha256().into();
    observation.local.bindings.session_nonce = session_nonce.into();
    observation.local.bindings.onboarding_nonce = onboarding_nonce.into();
    // Every learned signed deny is retained, deduplicated and reobserved at
    // publication. It cannot disappear when a different transfer is retried.
    let mut known = BTreeMap::new();
    for value in crate::tombstone::shared_facts(ctx.state, env)?
        .into_iter()
        .chain(
            ctx.state
                .read_json(&bootstrap::path(env, "known-facts.json")?, json!({}))?
                .as_object()
                .into_iter()
                .flatten()
                .map(|(_, v)| v.clone()),
        )
    {
        let fact = sync::Fact::from_dict(&value)?;
        sync::validate_fact_target(&fact.kind, &fact.target)?;
        if fact.env_id != env
            || fact.author != peer.fingerprint()
            || !sync::verify_fact(&fact, &peer)
        {
            return Err(bootstrap::bad("team_bootstrap_authority_unproven"));
        }
        if fact.kind == "member_removed" {
            return Err(bootstrap::bad("team_bootstrap_semantic_scope_unsupported"));
        }
        known.insert(fact.hash()?, fact);
    }
    if known.len() > 65_536 {
        return Err(bootstrap::bad("team_bootstrap_limit_exceeded"));
    }
    for (hash, fact) in known {
        match fact.kind.as_str() {
            "secret_deleted" => {
                observation
                    .local
                    .restrictions
                    .deleted_secret_ids
                    .insert(bootstrap::text(&fact.target, "secret_id")?.into());
            }
            "connection_disabled" => {
                observation
                    .local
                    .restrictions
                    .disabled_connection_ids
                    .insert(bootstrap::text(&fact.target, "connection_id")?.into());
            }
            "secret_version_revoked" => {
                observation.local.restrictions.revoked_versions.insert((
                    bootstrap::text(&fact.target, "secret_id")?.into(),
                    bootstrap::text(&fact.target, "version_id")?.into(),
                ));
            }
            _ => return Err(bootstrap::bad("team_bootstrap_semantic_scope_unsupported")),
        }
        observation
            .local
            .restrictions
            .known_original_facts
            .push(KnownOriginalFact {
                hash,
                original: fact,
                author_record: peer.clone(),
            });
    }
    phase(ctx, env, "retained_authority")?;
    let raw_bytes = (raw_manifest.len() as u64)
        .checked_add(raw_payload.len() as u64)
        .ok_or_else(|| bootstrap::bad("team_bootstrap_limit_exceeded"))?;
    reserve_import(&history, &payload, raw_bytes)?;
    let retained =
        verify_retained_authority(&manifest, &payload, &observation.local).map_err(|e| {
            // Bounded closed-label diagnostics only. The failed verifier still
            // determines the refusal; these observations confer no assurance.
            let label = (|| -> Result<&'static str> {
                if AuthenticatedOriginals::authenticate(&manifest, &payload, &observation.local)
                    .and_then(|o| o.check_history())
                    .is_err()
                {
                    return Ok("retained_history_originals");
                }
                let mut records = Vec::new();
                for index in 0..payload.index.commits.len() {
                    match original_commit(&payload, index) {
                        Ok(c) => records.push(c),
                        Err(_) => return Ok("retained_original_canonical"),
                    }
                }
                let records = commit::sort_total_order(records)?;
                let trace = fold::checkpoint_authority_trace(
                    env,
                    records
                        .into_iter()
                        .enumerate()
                        .map(|(i, c)| Ok((i, c.hash()?, c))),
                )?;
                let snapshot = super::strict_json::materialize(&payload.index.components[1])
                    .map_err(|e| bootstrap::bad(super::CheckpointError::from(e).reason()))?;
                for key in ["owner", "members", "dek"] {
                    if trace.projection[key] != snapshot["document"][key] {
                        return Ok(match key {
                            "owner" => "retained_projection_owner",
                            "members" => "retained_projection_members",
                            _ => "retained_projection_dek",
                        });
                    }
                }
                Ok("retained_wrap_effective")
            })()
            .unwrap_or("retained_diagnostic_refused");
            let _ = phase(ctx, env, label);
            bootstrap::bad(e.reason())
        })?;
    phase(ctx, env, "originals")?;
    history.check()?;
    reserve_import(&history, &payload, raw_bytes)?;
    let originals = AuthenticatedOriginals::authenticate(&manifest, &payload, &observation.local)
        .map_err(|e| bootstrap::bad(e.reason()))?;
    let owner = commit::env_owner_fingerprint(env)?;
    let recipient = DeviceKey::load_or_create(ctx.state, ctx.kms)?;
    if owner != peer.fingerprint()
        || originals.devices.len() != 2
        || originals.devices.get(&owner) != Some(&peer)
        || originals.devices.get(&recipient.fingerprint()?) != Some(&recipient.record()?)
        || manifest
            .vector()
            .iter()
            .any(|(fp, n)| fp != &owner && *n > 0)
    {
        return Err(bootstrap::bad("team_bootstrap_semantic_scope_unsupported"));
    }
    let mut commits = Vec::new();
    let mut addition = 0;
    let mut genesis = 0;
    for index in &originals.indices {
        let c = original_commit(&payload, index.original_index)
            .map_err(|e| bootstrap::bad(e.reason()))?;
        if c.author != owner {
            return Err(bootstrap::bad("team_bootstrap_semantic_scope_unsupported"));
        }
        for op in &c.ops {
            match op["op"].as_str() {
                Some("env.init") => {
                    genesis += 1;
                    if c.author_seq != 1 || op["owner_device"] != peer.to_dict() {
                        return Err(bootstrap::bad("team_bootstrap_authority_unproven"));
                    }
                }
                Some("member.add") => {
                    addition += 1;
                    if op["device"] != recipient.record()?.to_dict()
                        || op["role"] != "admin"
                        || c.hash()?
                            != bootstrap::text(
                                manifest.signed_metadata(),
                                "recipient_admission_commit_hash",
                            )?
                    {
                        return Err(bootstrap::bad("team_bootstrap_authority_unproven"));
                    }
                }
                Some("member.remove" | "member.set_role" | "owner.transfer") => {
                    return Err(bootstrap::bad("team_bootstrap_semantic_scope_unsupported"));
                }
                Some("dek.rotate") if op.get("removal_fact_hash").is_some() => {
                    return Err(bootstrap::bad("team_bootstrap_semantic_scope_unsupported"));
                }
                _ => {}
            }
        }
        commits.push(c);
    }
    if genesis != 1
        || addition != 1
        || originals
            .facts
            .values()
            .any(|f| f.author != owner || f.kind == "member_removed")
    {
        return Err(bootstrap::bad("team_bootstrap_semantic_scope_unsupported"));
    }
    // The indexed metadata intentionally omits bulk snapshot fields. Validate
    // the original, bounded component span, as the complete-cut path does.
    let snapshot = super::strict_json::materialize(
        payload
            .index
            .components
            .get(1)
            .ok_or_else(|| bootstrap::bad("team_bootstrap_semantic_mismatch"))?,
    )
    .map_err(|_| bootstrap::bad("team_bootstrap_semantic_mismatch"))?;
    let document = field(&snapshot, "document").map_err(|e| bootstrap::bad(e.reason()))?;
    let order = field(&snapshot, "version_order").map_err(|e| bootstrap::bad(e.reason()))?;
    phase(ctx, env, "document_shape")?;
    document::validate(document, order, env, &originals.devices, false)
        .map_err(|e| bootstrap::bad(e.reason()))?;
    phase(ctx, env, "retained_puts")?;
    document::check_puts(&commits, document).map_err(|e| bootstrap::bad(e.reason()))?;
    let mut effects = fold::Facts::default();
    for f in originals.facts.values() {
        sync::apply_fact(&mut effects, f);
    }
    phase(ctx, env, "final_overlay")?;
    let mut folded = fold::fold(
        env,
        Vec::new(),
        Some(&effects),
        Some(document.clone()),
        Some(fold::personal_version_order(order)?),
        None,
    )?;
    folded.vector = manifest.vector().clone();
    phase(ctx, env, "final_document_shape")?;
    document::validate(
        &folded.document,
        &folded.version_order,
        env,
        &originals.devices,
        true,
    )
    .map_err(|e| bootstrap::bad(e.reason()))?;
    phase(ctx, env, "final_digests")?;
    if value_hash(&folded.document).map_err(|e| bootstrap::bad(e.reason()))?
        != text(manifest.signed_metadata(), "expected_final_document_sha256")
            .map_err(|e| bootstrap::bad(e.reason()))?
        || retained.tombstone_digest() != sync::personal_tombstone_digest(&effects)?
    {
        return Err(bootstrap::bad("team_checkpoint_semantic_mismatch"));
    }
    let mut ordered = originals.indices.iter().collect::<Vec<_>>();
    ordered.sort_by(|a, b| (&a.hlc, &a.author).cmp(&(&b.hlc, &b.author)));
    let trace = fold::checkpoint_authority_trace(
        env,
        ordered.into_iter().map(|i| {
            Ok((
                i.original_index,
                i.hash.clone(),
                original_commit(&payload, i.original_index)
                    .map_err(|e| bootstrap::bad(e.reason()))?,
            ))
        }),
    )?;
    history.check()?;
    reserve_import(&history, &payload, raw_bytes)?;
    phase(ctx, env, "generation_crypto")?;
    let wrapped = Plan::check_keys(&folded.document, &payload, &trace, &recipient, ctx.kms)
        .map_err(|e| bootstrap::bad(e.reason()))?;
    let unflushed = json!({"document":document,"vector":manifest.vector(),"version_order":order});
    history.check()?;
    Ok(Plan {
        state: ctx.state,
        budget: history.into_resume()?,
        manifest: manifest.signed_metadata().clone(),
        manifest_bytes: raw_manifest.to_vec(),
        payload: raw_payload.to_vec(),
        unflushed,
        folded,
        commits,
        facts: originals.facts.into_values().collect(),
        wrapped,
        observation: observation.revision,
        mapping,
        approval_hash: bootstrap::digest(a)?,
        attestor: peer,
    })
}
