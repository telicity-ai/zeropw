//! Complete supplied cut analysis. No runtime authority is accepted or returned.
use std::collections::BTreeMap;

use serde_json::Value;

use super::admission::{
    LocalIdKind, RequiredTombstoneSupport, SemanticError as E, SemanticLocalInputs, component,
    original_commit,
};
use super::document::{self, GenerationReferences};
use super::manifest::{canonical, field, text, value_hash};
use super::originals::AuthenticatedOriginals;
use super::removal::RemovalProof;
use super::{IntegrityCheckedPayload, ManifestAttestation, strict_json};
use crate::pyint::PyInt;
use crate::team::{
    fold::{self, CheckpointCompleteRole, CheckpointCompleteTrace},
    sync, tombstone_gate,
};

type Result<T> = std::result::Result<T, E>;

enum FactBasis {
    Historical { _interval: CheckpointCompleteRole },
    Removal { _target: String },
}

/// Immutable, opaque, noninstallable and administrator attested. Completeness
/// means the supplied declared cut only. No key availability is established.
/// ```compile_fail
/// use zeropw::team::checkpoint::CompleteCutSemanticCandidate;
/// let p = CompleteCutSemanticCandidate {};
/// ```
/// ```compile_fail
/// use zeropw::team::checkpoint::CompleteCutSemanticCandidate;
/// let p: CompleteCutSemanticCandidate<'_, '_, '_> = serde_json::from_str("{}").unwrap();
/// ```
/// ```compile_fail
/// use zeropw::team::checkpoint::CompleteCutSemanticCandidate;
/// let p: CompleteCutSemanticCandidate<'_, '_, '_> = Default::default();
/// ```
/// ```compile_fail
/// use zeropw::team::checkpoint::CompleteCutSemanticCandidate;
/// let p: CompleteCutSemanticCandidate<'_, '_, '_> = serde_json::json!({}).into();
/// ```
/// ```compile_fail
/// use zeropw::team::{checkpoint::CompleteCutSemanticCandidate, fold::Facts};
/// fn facts(p: CompleteCutSemanticCandidate<'_, '_, '_>) -> Facts { p.into() }
/// ```
/// ```compile_fail
/// use zeropw::team::checkpoint::CompleteCutSemanticCandidate;
/// fn install(p: CompleteCutSemanticCandidate<'_, '_, '_>) { p.install(); }
/// ```
/// ```compile_fail
/// use zeropw::team::checkpoint::CompleteCutSemanticCandidate;
/// fn receipt(p: CompleteCutSemanticCandidate<'_, '_, '_>) { p.receipt_fact(); }
/// ```
/// ```compile_fail
/// use zeropw::team::checkpoint::CompleteCutSemanticCandidate;
/// fn mutate(p: &mut CompleteCutSemanticCandidate<'_, '_, '_>) { p.document = serde_json::json!({}); }
/// ```
pub struct CompleteCutSemanticCandidate<'m, 'p, 'b> {
    originals: AuthenticatedOriginals<'m, 'p, 'b>,
    removal: RemovalProof,
    trace: CheckpointCompleteTrace,
    _bases: BTreeMap<String, FactBasis>,
    _document: Value,
    _order: Value,
    generations: GenerationReferences,
    final_digest: String,
    cut_digest: String,
    tombstone_digest: String,
    admitted_digest: String,
}

impl CompleteCutSemanticCandidate<'_, '_, '_> {
    pub fn stage(&self) -> &'static str {
        "complete_supplied_cut_semantics_not_admitted"
    }
    pub fn trust_model(&self) -> &'static str {
        "administrator_attested"
    }
    pub fn manifest_hash(&self) -> &str {
        self.originals.manifest.manifest_hash()
    }
    pub fn observation_revision(&self) -> &str {
        &self.originals.local.bindings.observation_revision
    }
    pub fn covered_cut_sha256(&self) -> &str {
        &self.cut_digest
    }
    pub fn recomputed_final_document_sha256(&self) -> &str {
        &self.final_digest
    }
    pub fn admitted_fact_hashes_sha256(&self) -> &str {
        &self.admitted_digest
    }
    pub fn tombstone_digest(&self) -> &str {
        &self.tombstone_digest
    }
    pub fn original_fact_count(&self) -> usize {
        self.originals.facts.len()
    }
    pub fn original_tombstone_count(&self) -> usize {
        self.originals.payload.tombstones.len()
    }
    pub fn checked_operation_count(&self) -> usize {
        self.trace.operations.len()
    }
    pub fn removal_target_count(&self) -> usize {
        self.removal.groups.len()
    }
    pub fn removal_witness_count(&self) -> usize {
        self.removal.witnesses.len()
    }
    pub fn allowed_restrictive_skip_count(&self) -> usize {
        self.trace
            .operations
            .iter()
            .filter(|o| o.skipped.is_some())
            .count()
    }
    pub fn referenced_generation_ids(&self) -> impl Iterator<Item = &str> {
        self.generations.referenced.iter().map(String::as_str)
    }
    pub fn required_generation_ids(&self) -> impl Iterator<Item = &str> {
        self.generations.required.iter().map(String::as_str)
    }
    pub fn applied_wrap_source_count(&self) -> usize {
        self.trace.effective_wrap_sources.len()
    }
    pub fn contains_original_fact_hash(&self, hash: &str) -> bool {
        self.originals.facts.contains_key(hash)
    }
}
impl std::fmt::Debug for CompleteCutSemanticCandidate<'_, '_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CompleteCutSemanticCandidate([redacted])")
    }
}

/// Checks original authentication anew for this immutable binding, complete
/// author coverage, finite removal bases, actual from-genesis fold, complete
/// unflushed equality and final overlay. It consumes no earlier candidate.
/// ```compile_fail
/// use zeropw::team::checkpoint::{RetainedAuthorityCandidate, verify_complete_cut_semantics};
/// fn skip_auth(p: RetainedAuthorityCandidate<'_, '_, '_>) { verify_complete_cut_semantics(&p); }
/// ```
/// ```compile_fail
/// use zeropw::team::checkpoint::{CandidateProvenanceV1, verify_complete_cut_semantics};
/// fn json_proof(p: CandidateProvenanceV1) { verify_complete_cut_semantics(&p); }
/// ```
pub fn verify_complete_cut_semantics<'m, 'p, 'b>(
    manifest: &'m ManifestAttestation,
    payload: &'p IntegrityCheckedPayload<'b>,
    local: &'m SemanticLocalInputs,
) -> Result<CompleteCutSemanticCandidate<'m, 'p, 'b>> {
    let mut originals = AuthenticatedOriginals::authenticate(manifest, payload, local)?;
    originals.check_history()?;
    originals.complete_coverage()?;
    let signed = &manifest.data.signed;
    let env = text(signed, "env_id")?;
    let recipient = text(signed, "recipient")?;
    let mut effects = fold::Facts::default();
    for f in originals.facts.values() {
        sync::apply_fact(&mut effects, f);
    }
    if effects.tombstone_facts.keys().ne(payload.tombstones.iter())
        || originals.facts.keys().ne(payload.facts.iter())
    {
        return Err(E::FactContradicted);
    }
    let digest =
        tombstone_gate::digest(&effects.tombstone_facts).map_err(|_| E::FactContradicted)?;
    if digest != text(signed, "tombstone_digest")? {
        return Err(E::FactContradicted);
    }
    let admitted_digest = value_hash(&serde_json::json!(
        originals.facts.keys().collect::<Vec<_>>()
    ))?;
    if admitted_digest != text(signed, "admitted_fact_hashes_sha256")? {
        return Err(E::FactContradicted);
    }
    let mut records = Vec::new();
    let mut names = BTreeMap::new();
    let mut immutable_puts = BTreeMap::new();
    for i in &originals.indices {
        let c = original_commit(payload, i.original_index)?;
        for (j, op) in c.ops.iter().enumerate() {
            names.insert((i.hash.clone(), j), text(op, "op")?.to_owned());
            if op["op"] == "secret.put_version" {
                let empty = serde_json::json!({});
                let immutable = [
                    field(op, "kind")?,
                    field(op, "generation_id")?,
                    field(op, "ciphertext")?,
                    op.get("public").unwrap_or(&empty),
                ]
                .into_iter()
                .map(canonical)
                .collect::<std::result::Result<Vec<_>, _>>()?;
                let identity = (
                    text(op, "secret_id")?.to_owned(),
                    text(op, "version_id")?.to_owned(),
                );
                if let Some(previous) = immutable_puts.get(&identity) {
                    return Err(if previous == &immutable {
                        E::ScopeUnsupported
                    } else {
                        E::SemanticMismatch
                    });
                }
                immutable_puts.insert(identity, immutable);
            }
        }
        records.push(c);
    }
    drop(immutable_puts);
    let removal = RemovalProof::compute(&records, &originals.facts, &effects)?;
    removal.compare_claims(component(payload, 4)?, &manifest.data.vector)?;
    // Release the supplied tree before creating either computed image. Retain
    // canonical expected bytes, never use the sender image as a replay seed.
    let snapshot =
        strict_json::materialize(payload.index.components.get(1).ok_or(E::SemanticMismatch)?)?;
    let expected_document = field(&snapshot, "document")?;
    let expected_order = field(&snapshot, "version_order")?;
    document::validate(
        expected_document,
        expected_order,
        env,
        &originals.devices,
        false,
    )?;
    for (key, ids) in [
        ("secrets", &mut originals.secret_ids),
        ("connections", &mut originals.connection_ids),
    ] {
        ids.extend(
            field(expected_document, key)?
                .as_object()
                .ok_or(E::SemanticMismatch)?
                .keys()
                .cloned(),
        );
    }
    let expected_document_bytes = canonical(expected_document)?;
    let expected_order_bytes = canonical(expected_order)?;
    drop(snapshot);
    let computed =
        fold::checkpoint_complete_fold(env, records, &effects).map_err(|_| E::ScopeUnsupported)?;
    removal.check_basis(&computed.trace, &originals.facts)?;
    for op in &computed.trace.operations {
        if let Some(reason) = op.skipped.as_deref() {
            if op.authority || matches!(reason, "not_admin" | "not_authorized" | "member_removed") {
                return Err(E::AuthorityUnproven);
            }
            let name = names
                .get(&(op.position.hash.clone(), op.position.op_index))
                .ok_or(E::SemanticMismatch)?;
            if !((reason == "secret_deleted"
                && matches!(
                    name.as_str(),
                    "secret.put_version" | "secret.set_status" | "secret.activate"
                ))
                || (reason == "version_revoked"
                    && matches!(name.as_str(), "secret.set_status" | "secret.activate")))
            {
                return Err(E::ScopeUnsupported);
            }
        }
    }
    if canonical(&computed.unflushed)? != expected_document_bytes
        || canonical(&computed.result.version_order)? != expected_order_bytes
    {
        return Err(E::SemanticMismatch);
    }
    for (fp, seq) in &manifest.data.vector {
        if computed.result.vector.get(fp).unwrap_or(&PyInt::zero()) != seq {
            return Err(E::SemanticMismatch);
        }
    }
    document::validate(
        &computed.unflushed,
        &computed.result.version_order,
        env,
        &originals.devices,
        false,
    )?;
    // Immutable originals can be rematerialized only from their same private
    // ancestor-depth spans. No replacement record/value can reach this path.
    for i in &originals.indices {
        let c = original_commit(payload, i.original_index)?;
        document::check_puts(std::slice::from_ref(&c), &computed.unflushed)?;
    }
    let generations = document::validate(
        &computed.result.document,
        &computed.result.version_order,
        env,
        &originals.devices,
        true,
    )?;
    for generation in
        super::manifest::array(field(component(payload, 5)?, "unavailable_generations")?)?
    {
        if !generation
            .as_str()
            .is_some_and(|id| generations.referenced.contains(id))
        {
            return Err(E::SemanticMismatch);
        }
    }
    if !sync::is_admin(&computed.result.document, text(signed, "signer")?)
        || computed.result.document["members"][recipient]["status"] != "active"
        || computed.result.document["members"][recipient]["role"]
            != local.bindings.recipient_role.as_str()
    {
        return Err(E::AuthorityUnproven);
    }
    let applied: BTreeMap<_, _> = computed
        .trace
        .operations
        .iter()
        .map(|o| ((o.position.hash.as_str(), o.position.op_index), o))
        .collect();
    for span in &payload.index.wraps {
        let entry = strict_json::materialize(span)?;
        let generation = text(&entry, "generation_id")?;
        let source = text(&entry, "source_commit_hash")?;
        let index = super::manifest::bounded(field(&entry, "source_op_index")?, 16_777_216)?;
        let selector = (generation.to_owned(), recipient.to_owned());
        let op = applied
            .get(&(source, index))
            .ok_or(E::HistoryProofUnavailable)?;
        if !op.applicable_wraps.contains(&selector) {
            return Err(E::AuthorityUnproven);
        }
        if computed
            .trace
            .effective_wrap_sources
            .get(&selector)
            .is_some_and(|p| p.hash == source && p.op_index == index)
            && canonical(field(&entry, "wrap")?)?
                != canonical(
                    &computed.result.document["dek"]["generations"][generation]["wraps"][recipient],
                )?
        {
            return Err(E::SemanticMismatch);
        }
    }
    let mut bases = BTreeMap::new();
    for (hash, fact) in &originals.facts {
        let basis = if fact.kind == "member_removed" {
            FactBasis::Removal {
                _target: text(&fact.target, "fingerprint")?.into(),
            }
        } else {
            FactBasis::Historical {
                _interval: computed
                    .trace
                    .role_bases
                    .get(&(fact.author.clone(), fact.kind != "incident"))
                    .ok_or(E::FactContradicted)?
                    .clone(),
            }
        };
        bases.insert(hash.clone(), basis);
    }
    check_local(&originals, &effects, &computed.result.document, &digest)?;
    let final_digest = value_hash(&computed.result.document)?;
    if final_digest != text(signed, "expected_final_document_sha256")?
        || final_digest != text(component(payload, 1)?, "expected_final_document_sha256")?
    {
        return Err(E::SemanticMismatch);
    }
    let cut_digest = value_hash(
        &serde_json::json!({"vector":field(signed,"vector")?,"heads":field(signed,"heads")?}),
    )?;
    Ok(CompleteCutSemanticCandidate {
        originals,
        removal,
        trace: computed.trace,
        _bases: bases,
        _document: computed.result.document,
        _order: computed.result.version_order,
        generations,
        final_digest,
        cut_digest,
        tombstone_digest: digest,
        admitted_digest,
    })
}

fn check_local(
    originals: &AuthenticatedOriginals<'_, '_, '_>,
    effects: &fold::Facts,
    document: &Value,
    digest: &str,
) -> Result<()> {
    let local = originals.local;
    let restrictions = &local.restrictions;
    for known in &restrictions.known_original_facts {
        let f = originals
            .facts
            .get(&known.hash)
            .ok_or(E::FactContradicted)?;
        if canonical(&f.to_dict())? != canonical(&known.original.to_dict())?
            || originals.devices.get(&f.author) != Some(&known.author_record)
        {
            return Err(E::FactContradicted);
        }
    }
    if restrictions
        .deleted_secret_ids
        .iter()
        .any(|id| !effects.deleted_secrets.contains(id))
        || restrictions.revoked_versions.iter().any(|(s, v)| {
            !effects.revoked_versions.contains(&(s.clone(), v.clone()))
                && document["secrets"][s]["versions"][v]["status"] != "revoked"
        })
        || restrictions.disabled_connection_ids.iter().any(|id| {
            !effects.disabled_connections.contains(id)
                && document["connections"][id]["status"] != "disabled"
        })
        || restrictions
            .removed_members
            .iter()
            .any(|fp| document["members"][fp]["status"] != "removed")
    {
        return Err(E::FactContradicted);
    }
    if let RequiredTombstoneSupport::Required {
        known_tombstone_hashes,
        unresolved_nonempty_digests,
    } = &restrictions.required_tombstone_support
        && (known_tombstone_hashes
            .iter()
            .any(|h| !effects.tombstone_facts.contains_key(h))
            || unresolved_nonempty_digests
                .iter()
                .any(|h| h != digest || effects.tombstone_facts.is_empty()))
    {
        return Err(E::FactContradicted);
    }
    if local.occupied.iter().any(|e| match e.kind {
        LocalIdKind::Secret => originals.secret_ids.contains(&e.id),
        LocalIdKind::Connection => originals.connection_ids.contains(&e.id),
    }) || restrictions
        .restored_bindings
        .iter()
        .any(|b| originals.secret_ids.contains(&b.secret_id))
    {
        return Err(E::ExistingStateUnsupported);
    }
    Ok(())
}

#[cfg(test)]
mod literal_trace_tests {
    use super::*;
    use crate::team::{commit, identity::DeviceRecord, sync::Fact};
    use std::{collections::BTreeSet, path::Path};

    #[test]
    fn complete_shared_trace_matches_every_literal_original_operation_and_pre_cut_view() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/team_checkpoint_m2b2_v1");
        for case in [
            "C01-admin",
            "C02-owner",
            "C03-historical",
            "R01-other",
            "R02-multiple",
            "R03-self",
            "R04-pending",
            "D01-overlay",
            "D02-policy",
            "N01-reciprocal",
            "N02-cycle",
            "N03-same-commit",
        ] {
            let read = |name: &str| {
                crate::pyjson::loads(&std::fs::read_to_string(root.join(case).join(name)).unwrap())
                    .unwrap()
            };
            let payload = read("payload.json");
            let history = read("history.canon");
            let facts = read("facts.canon");
            let expected = read("literal-trace.json");
            let devices: BTreeMap<_, _> = payload["components"][0]["data"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| {
                    (
                        e["fingerprint"].as_str().unwrap().to_owned(),
                        DeviceRecord::from_dict(&e["record"]).unwrap(),
                    )
                })
                .collect();
            let commits: Vec<_> = history
                .as_array()
                .unwrap()
                .iter()
                .map(|v| commit::Commit::from_dict(v).unwrap())
                .collect();
            for c in &commits {
                assert!(commit::verify_commit(c, &devices[&c.author]));
            }
            let mut effects = fold::Facts::default();
            for v in facts.as_array().unwrap() {
                let f = Fact::from_dict(v).unwrap();
                assert!(sync::verify_fact(&f, &devices[&f.author]));
                sync::apply_fact(&mut effects, &f);
            }
            let computed = fold::checkpoint_complete_fold(
                payload["env_id"].as_str().unwrap(),
                commits,
                &effects,
            )
            .unwrap();
            if case == "C01-admin" {
                // General shape keeps legacy last-occurrence indices and
                // historical absent versions. Complete-cut equality separately
                // rejects this array because the originals did not produce it.
                let order = serde_json::json!({"retained-secret":["bbbbbbbbbbbbbbbb","9999999999999999","bbbbbbbbbbbbbbbb","cccccccccccccccc"]});
                document::validate(
                    &computed.unflushed,
                    &order,
                    payload["env_id"].as_str().unwrap(),
                    &devices,
                    false,
                )
                .unwrap();
                let indices = fold::version_index_from_order(&order).unwrap();
                assert_eq!(indices["retained-secret"]["bbbbbbbbbbbbbbbb"], 3);
                assert_eq!(indices["retained-secret"]["9999999999999999"], 2);
                assert_eq!(indices["retained-secret"]["cccccccccccccccc"], 4);
            }
            let rows = expected.as_array().unwrap();
            assert_eq!(computed.trace.operations.len(), rows.len(), "{case}");
            for (op, row) in computed.trace.operations.iter().zip(rows) {
                assert_eq!(op.position.hash, row["hash"], "{case}");
                assert_eq!(
                    op.position.op_index,
                    row["op_index"].as_u64().unwrap() as usize,
                    "{case}"
                );
                assert_eq!(op.skipped.as_deref(), row["skipped"].as_str(), "{case}");
                assert_eq!(op.owner_after.as_deref(), row["owner"].as_str(), "{case}");
                for (admin, key) in [(true, "active_admins"), (false, "active_members")] {
                    let actual: BTreeSet<_> = op
                        .roles_after
                        .iter()
                        .filter(|(_, a)| *a == admin)
                        .map(|(fp, _)| fp.as_str())
                        .collect();
                    let wanted: BTreeSet<_> = row[key]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap())
                        .collect();
                    assert_eq!(
                        actual, wanted,
                        "{case} {} op {} {key}",
                        op.position.hash, op.position.op_index
                    );
                }
            }
            assert_eq!(
                canonical(&computed.unflushed).unwrap(),
                canonical(&read("expected-unflushed.canon")).unwrap(),
                "{case}"
            );
            assert_eq!(
                canonical(&computed.result.document).unwrap(),
                canonical(&read("expected-final.canon")).unwrap(),
                "{case}"
            );
            let first_other = effects
                .removal_facts
                .values()
                .find(|f| f.author != f.target);
            if let Some(f) = first_other
                && case.starts_with('R')
            {
                let standing = &computed.trace.pending_standing[&f.target];
                assert!(standing.active.contains(&f.target));
                assert!(standing.admins.contains(&f.author));
                assert_ne!(standing.owner.as_ref(), Some(&f.target));
                assert_eq!(standing.active.len(), 4);
                assert_eq!(standing.admins.len(), 3);
            }
            if case == "R03-self" {
                assert_eq!(computed.trace.self_standing.len(), 1);
                let standing = computed.trace.self_standing.values().next().unwrap();
                assert_eq!(standing.active.len(), 4);
                assert_eq!(standing.admins.len(), 3);
            }
        }
    }
}
