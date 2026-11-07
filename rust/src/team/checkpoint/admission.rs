//! Pure retained-original analysis. Completeness and historical fact admission
//! are administrator attested. This stage cannot install, issue receipts, check
//! final data overlays, or confer runtime authority.
use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::manifest::{array, bounded, canonical, field, fingerprint, hex_text, record, text};
use super::{
    CheckpointError, IntegrityCheckedPayload, ManifestAttestation, RecipientRole, strict_json,
};
use crate::pyint::PyInt;
use crate::team::{
    commit::{self, Commit},
    fold::{self, CheckpointAuthorityTrace, CheckpointPosition},
    identity::DeviceRecord,
    sync::{self, Fact},
    tombstone_gate,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticError {
    Checkpoint(CheckpointError),
    AuthorityUnproven,
    HistoryProofUnavailable,
    FactContradicted,
    SemanticMismatch,
    ExistingStateUnsupported,
    GenerationUnavailable,
    ScopeUnsupported,
}

#[cfg(test)]
mod oracle_tests {
    use super::*;

    #[test]
    fn every_original_op_matches_the_literal_role_owner_and_skip_table() {
        const ROOT: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/team_checkpoint_semantics_v1/"
        );
        for case in ["P1", "P2", "P3", "P4", "P5", "P6-empty", "P6-nonempty"] {
            // Trusted, frozen test data only. No candidate or generator supplies
            // the expected transitions; literal-trace.json is hand specified.
            let history = crate::pyjson::loads(
                &std::fs::read_to_string(format!("{ROOT}{case}/history.canon")).unwrap(),
            )
            .unwrap();
            let literal = crate::pyjson::loads(
                &std::fs::read_to_string(format!("{ROOT}{case}/literal-trace.json")).unwrap(),
            )
            .unwrap();
            let payload = crate::pyjson::loads(
                &std::fs::read_to_string(format!("{ROOT}{case}/payload.json")).unwrap(),
            )
            .unwrap();
            let devices: BTreeMap<_, _> = payload["components"][0]["data"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| {
                    (
                        entry["fingerprint"].as_str().unwrap().to_owned(),
                        DeviceRecord::from_dict(&entry["record"]).unwrap(),
                    )
                })
                .collect();
            let commits: Vec<_> = history
                .as_array()
                .unwrap()
                .iter()
                .map(|v| Commit::from_dict(v).unwrap())
                .collect();
            for c in &commits {
                assert!(commit::verify_commit(c, &devices[&c.author]));
            }
            let ordered = commit::sort_total_order(commits).unwrap();
            let trace = fold::checkpoint_authority_trace(
                ordered[0].env_id.as_str(),
                ordered
                    .iter()
                    .cloned()
                    .enumerate()
                    .map(|(i, c)| Ok((i, c.hash().unwrap(), c))),
            )
            .unwrap();
            assert_eq!(
                trace.operations.len(),
                literal.as_array().unwrap().len(),
                "{case}"
            );
            for (op, expected) in trace.operations.iter().zip(literal.as_array().unwrap()) {
                assert_eq!(
                    op.owner_after.as_deref(),
                    expected["owner"].as_str(),
                    "{case}"
                );
                assert!(op.skipped.is_none());
                assert_eq!(expected["skipped"], serde_json::json!([]));
                let position = (op.position.total_order_index, op.position.op_index);
                for (admin, field) in [(true, "active_admins"), (false, "active_members")] {
                    let actual: BTreeSet<_> = trace
                        .intervals
                        .iter()
                        .filter(|r| {
                            r.admin == admin
                                && (r.start.total_order_index, r.start.op_index) <= position
                                && r.end.as_ref().is_none_or(|end| {
                                    position < (end.total_order_index, end.op_index)
                                })
                        })
                        .map(|r| r.fingerprint.as_str())
                        .collect();
                    let expected: BTreeSet<_> = expected[field]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap())
                        .collect();
                    assert_eq!(actual, expected, "{case} op {position:?} {field}");
                }
            }
        }
    }
}
impl SemanticError {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Checkpoint(e) => e.reason(),
            Self::AuthorityUnproven => "team_bootstrap_authority_unproven",
            Self::HistoryProofUnavailable => "team_bootstrap_history_proof_unavailable",
            Self::FactContradicted => "team_bootstrap_fact_contradicted",
            Self::SemanticMismatch => "team_bootstrap_semantic_mismatch",
            Self::ExistingStateUnsupported => "team_bootstrap_existing_state_unsupported",
            Self::GenerationUnavailable => "team_bootstrap_generation_unavailable",
            Self::ScopeUnsupported => "team_bootstrap_semantic_scope_unsupported",
        }
    }
}
impl std::fmt::Display for SemanticError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}
impl std::error::Error for SemanticError {}
impl From<CheckpointError> for SemanticError {
    fn from(value: CheckpointError) -> Self {
        Self::Checkpoint(value)
    }
}
impl From<strict_json::Error> for SemanticError {
    fn from(value: strict_json::Error) -> Self {
        Self::Checkpoint(value.into())
    }
}
type Result<T> = std::result::Result<T, SemanticError>;
use SemanticError as E;
const SCHEMA: E = E::Checkpoint(CheckpointError::SchemaUnsupported);
const SIGNATURE: E = E::Checkpoint(CheckpointError::SignatureInvalid);

/// Explicit caller observations; these are neither authenticated collection nor
/// persisted approval. A future trusted collector must repeat them under lock.
pub struct SemanticBindings {
    pub recipient_record: DeviceRecord,
    pub recipient_role: RecipientRole,
    pub env_id: String,
    pub manifest_hash: String,
    pub approval_sha256: String,
    pub session_nonce: String,
    pub onboarding_nonce: String,
    pub intended_mapping: LocalMapping,
    pub observation_revision: String,
}
#[derive(Clone, PartialEq, Eq)]
pub struct LocalMapping {
    pub project: String,
    pub environment: String,
    pub env_id: String,
}
pub struct ObservedInventory {
    pub admitted_commits: usize,
    pub admitted_facts: usize,
    pub checkpoints: usize,
    pub derived_team_entries: usize,
    pub unsent_edits: usize,
    pub pending_imports: usize,
    pub completed_imports: usize,
    pub stale_restore: bool,
    pub existing_mapping: Option<LocalMapping>,
    /// Only this attempt's unpublished staging is permissible.
    pub own_staging_manifest_hash: Option<String>,
}
#[derive(Clone, Copy)]
pub enum LocalIdKind {
    Secret,
    Connection,
}
pub enum LocalIdScope {
    Private {
        project: String,
        environment: String,
    },
    Shared {
        env_id: String,
    },
    Restored {
        env_id: String,
    },
}
pub struct OccupiedLocalId {
    pub id: String,
    pub kind: LocalIdKind,
    pub scope: LocalIdScope,
}
pub struct ObservedBinding {
    pub secret_id: String,
    pub mapping: LocalMapping,
}
pub struct KnownOriginalFact {
    pub hash: String,
    pub original: Fact,
    pub author_record: DeviceRecord,
}
pub enum RequiredTombstoneSupport {
    NotObserved,
    Required {
        known_tombstone_hashes: BTreeSet<String>,
        unresolved_nonempty_digests: BTreeSet<String>,
    },
}
pub struct LocalRestrictions {
    pub known_original_facts: Vec<KnownOriginalFact>,
    pub deleted_secret_ids: BTreeSet<String>,
    pub revoked_versions: BTreeSet<(String, String)>,
    pub disabled_connection_ids: BTreeSet<String>,
    pub removed_members: BTreeSet<String>,
    pub restored_bindings: Vec<ObservedBinding>,
    pub required_tombstone_support: RequiredTombstoneSupport,
    pub backup_barrier: bool,
}
pub struct SemanticLocalInputs {
    pub(super) bindings: SemanticBindings,
    pub(super) inventory: ObservedInventory,
    pub(super) occupied: Vec<OccupiedLocalId>,
    pub(super) restrictions: LocalRestrictions,
}
fn label(value: &str) -> bool {
    !value.is_empty() && value.len() <= 200 && !value.chars().any(char::is_control)
}
fn mapping(value: &LocalMapping) -> bool {
    label(&value.project) && label(&value.environment) && commit::valid_env_id(&value.env_id)
}
impl SemanticLocalInputs {
    /// Takes complete typed observations, with no remote JSON/default/approval
    /// Boolean. No production collector or runtime caller exists in M2b.1.
    pub fn from_local_observation(
        bindings: SemanticBindings,
        inventory: ObservedInventory,
        occupied: Vec<OccupiedLocalId>,
        restrictions: LocalRestrictions,
    ) -> Result<Self> {
        if !commit::valid_env_id(&bindings.env_id)
            || !mapping(&bindings.intended_mapping)
            || bindings.intended_mapping.env_id != bindings.env_id
            || [
                &bindings.manifest_hash,
                &bindings.approval_sha256,
                &bindings.session_nonce,
                &bindings.onboarding_nonce,
                &bindings.observation_revision,
            ]
            .iter()
            .any(|s| !hex_text(s, 64))
            || inventory
                .existing_mapping
                .as_ref()
                .is_some_and(|m| !mapping(m))
            || inventory
                .own_staging_manifest_hash
                .as_ref()
                .is_some_and(|h| !hex_text(h, 64))
        {
            return Err(SCHEMA);
        }
        if !bindings.recipient_record.verify_uncached() {
            return Err(SIGNATURE);
        }
        for entry in &occupied {
            let valid = match &entry.scope {
                LocalIdScope::Private {
                    project,
                    environment,
                } => label(project) && label(environment),
                LocalIdScope::Shared { env_id } | LocalIdScope::Restored { env_id } => {
                    commit::valid_env_id(env_id)
                }
            };
            if !label(&entry.id) || !valid {
                return Err(SCHEMA);
            }
        }
        if restrictions.known_original_facts.len() > 65_536 {
            return Err(SCHEMA);
        }
        let mut known = BTreeSet::new();
        for fact in &restrictions.known_original_facts {
            if !hex_text(&fact.hash, 64)
                || !known.insert(&fact.hash)
                || fact.original.env_id != bindings.env_id
                || fact.original.hash().map_err(|_| SCHEMA)? != fact.hash
            {
                return Err(SCHEMA);
            }
            if !fact.author_record.verify_uncached()
                || !sync::verify_fact(&fact.original, &fact.author_record)
            {
                return Err(SIGNATURE);
            }
        }
        if restrictions.deleted_secret_ids.iter().any(|s| !label(s))
            || restrictions
                .disabled_connection_ids
                .iter()
                .any(|s| !label(s))
            || restrictions
                .revoked_versions
                .iter()
                .any(|(s, v)| !label(s) || !(16..=64).contains(&v.len()) || !hex_text(v, v.len()))
            || restrictions
                .removed_members
                .iter()
                .any(|fp| !fingerprint(fp))
            || restrictions
                .restored_bindings
                .iter()
                .any(|b| !label(&b.secret_id) || !mapping(&b.mapping))
        {
            return Err(SCHEMA);
        }
        if let RequiredTombstoneSupport::Required {
            known_tombstone_hashes,
            unresolved_nonempty_digests,
        } = &restrictions.required_tombstone_support
            && known_tombstone_hashes
                .iter()
                .chain(unresolved_nonempty_digests)
                .any(|h| !hex_text(h, 64))
        {
            return Err(SCHEMA);
        }
        Ok(Self {
            bindings,
            inventory,
            occupied,
            restrictions,
        })
    }
}

enum HistoricalBasis {
    AdministratorAttestedHistorical,
}
struct AnalyzedFact {
    original: Fact,
    basis: HistoricalBasis,
    interval: usize,
}

/// Privately constructed, immutable, borrowed and noninstallable. Its historical
/// bases share the exact manifest/payload/approved full signer/approval binding
/// borrowed below. Original facts are owned once, never exported as live Facts.
/// ```compile_fail
/// use zeropw::team::checkpoint::RetainedAuthorityCandidate;
/// let p = RetainedAuthorityCandidate {};
/// ```
/// ```compile_fail
/// use zeropw::team::checkpoint::RetainedAuthorityCandidate;
/// let p: RetainedAuthorityCandidate<'_, '_, '_> = serde_json::from_str("{}").unwrap();
/// ```
pub struct RetainedAuthorityCandidate<'m, 'p, 'b> {
    manifest: &'m ManifestAttestation,
    payload: &'p IntegrityCheckedPayload<'b>,
    local: &'m SemanticLocalInputs,
    trace: CheckpointAuthorityTrace,
    facts: BTreeMap<String, AnalyzedFact>,
    tombstone_digest: String,
    authority_projection_hash: String,
    payload_hash: &'m str,
    cut_hash: String,
    cut_hlc: (PyInt, PyInt),
}
impl RetainedAuthorityCandidate<'_, '_, '_> {
    pub fn stage(&self) -> &'static str {
        "retained_authority_checked_not_admitted"
    }
    pub fn trust_model(&self) -> &'static str {
        "administrator_attested"
    }
    pub fn manifest_hash(&self) -> &str {
        self.manifest.manifest_hash()
    }
    pub fn payload_sha256(&self) -> &str {
        self.payload_hash
    }
    pub fn observation_revision(&self) -> &str {
        &self.local.bindings.observation_revision
    }
    pub fn original_fact_count(&self) -> usize {
        self.facts.len()
    }
    pub fn original_tombstone_count(&self) -> usize {
        self.payload.tombstones.len()
    }
    pub fn tombstone_digest(&self) -> &str {
        &self.tombstone_digest
    }
    pub fn authority_projection_sha256(&self) -> &str {
        &self.authority_projection_hash
    }
    pub fn checked_operation_count(&self) -> usize {
        self.trace.operations.len()
    }
    pub fn cut_original_hash(&self) -> &str {
        &self.cut_hash
    }
    pub fn cut_hlc(&self) -> (&PyInt, &PyInt) {
        (&self.cut_hlc.0, &self.cut_hlc.1)
    }
    pub fn contains_original_fact_hash(&self, hash: &str) -> bool {
        self.facts.contains_key(hash)
    }
    pub fn fact_basis(&self, hash: &str) -> Option<&'static str> {
        self.facts.get(hash).map(|f| match f.basis {
            HistoricalBasis::AdministratorAttestedHistorical => "administrator_attested_historical",
        })
    }
    /// One bounded hash/index inspection. Endpoints mean after start / before
    /// end, never a reconstructed admission time inferred from a fact's HLC.
    pub fn fact_role_interval(&self, hash: &str) -> Option<FactRoleInterval<'_>> {
        let interval = self.trace.intervals.get(self.facts.get(hash)?.interval)?;
        Some(FactRoleInterval {
            start: &interval.start,
            end: interval.end.as_ref(),
            admin: interval.admin,
        })
    }
    /// Position of one checked original operation; data entries establish only
    /// schema and role prerequisites, not execution of their data effects.
    pub fn operation_position(&self, index: usize) -> Option<(usize, usize, &str, usize, bool)> {
        let op = self.trace.operations.get(index)?;
        Some((
            op.position.total_order_index,
            op.position.record_index,
            &op.position.hash,
            op.position.op_index,
            op.authority,
        ))
    }
}
pub struct FactRoleInterval<'a> {
    start: &'a CheckpointPosition,
    end: Option<&'a CheckpointPosition>,
    admin: bool,
}
impl FactRoleInterval<'_> {
    pub fn requires_admin(&self) -> bool {
        self.admin
    }
    pub fn start(&self) -> (&str, usize) {
        (&self.start.hash, self.start.op_index)
    }
    pub fn end(&self) -> Option<(&str, usize)> {
        self.end.map(|p| (p.hash.as_str(), p.op_index))
    }
}
impl std::fmt::Debug for RetainedAuthorityCandidate<'_, '_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RetainedAuthorityCandidate([redacted])")
    }
}
impl std::fmt::Display for RetainedAuthorityCandidate<'_, '_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.stage())
    }
}
super::redacted_debug!(
    SemanticBindings,
    LocalMapping,
    ObservedInventory,
    LocalIdKind,
    LocalIdScope,
    OccupiedLocalId,
    ObservedBinding,
    KnownOriginalFact,
    RequiredTombstoneSupport,
    LocalRestrictions,
    SemanticLocalInputs,
    FactRoleInterval<'_>
);

pub(super) struct CommitIndex {
    pub(super) hash: String,
    pub(super) author: String,
    pub(super) hlc: (PyInt, PyInt),
    pub(super) original_index: usize,
}
pub(super) fn component<'a>(
    payload: &'a IntegrityCheckedPayload<'_>,
    i: usize,
) -> Result<&'a Value> {
    let components = array(field(&payload.index.metadata, "components")?)?;
    Ok(field(components.get(i).ok_or(SCHEMA)?, "data")?)
}
pub(super) fn original_commit(payload: &IntegrityCheckedPayload<'_>, i: usize) -> Result<Commit> {
    let value = strict_json::materialize(payload.index.commits.get(i).ok_or(SCHEMA)?)?;
    let original = field(&value, "record")?;
    let commit = Commit::from_dict(original).map_err(|_| SCHEMA)?;
    if canonical(original)? != commit.canonical_json(true).map_err(|_| SCHEMA)?
        || text(&value, "hash")? != commit.hash().map_err(|_| SCHEMA)?
    {
        return Err(E::SemanticMismatch);
    }
    Ok(commit)
}
pub(super) fn device_copy(
    value: &Value,
    devices: &BTreeMap<String, DeviceRecord>,
) -> Result<String> {
    let device = record(value)?;
    let fp = device.fingerprint();
    if canonical(value)? != canonical(&device.to_dict())? {
        return Err(SCHEMA);
    }
    if devices.get(&fp) != Some(&device) {
        return Err(E::AuthorityUnproven);
    }
    Ok(fp)
}
pub(super) fn require_device(devices: &BTreeMap<String, DeviceRecord>, fp: &str) -> Result<()> {
    if devices.contains_key(fp) {
        Ok(())
    } else {
        Err(E::AuthorityUnproven)
    }
}
pub(super) fn inventory_check(local: &SemanticLocalInputs) -> Result<()> {
    let i = &local.inventory;
    if [
        i.admitted_commits,
        i.admitted_facts,
        i.checkpoints,
        i.derived_team_entries,
        i.unsent_edits,
        i.pending_imports,
        i.completed_imports,
    ]
    .iter()
    .any(|n| *n != 0)
        || i.stale_restore
        || local.restrictions.backup_barrier
        || i.existing_mapping
            .as_ref()
            .is_some_and(|m| m != &local.bindings.intended_mapping)
        || i.own_staging_manifest_hash
            .as_ref()
            .is_some_and(|h| h != &local.bindings.manifest_hash)
    {
        return Err(E::ExistingStateUnsupported);
    }
    Ok(())
}

/// Authenticates all originals, then analyzes the retained authority and exact
/// non-removal fact set. No state or authority-bearing runtime handle is taken.
pub fn verify_retained_authority<'m, 'p, 'b>(
    manifest: &'m ManifestAttestation,
    payload: &'p IntegrityCheckedPayload<'b>,
    local: &'m SemanticLocalInputs,
) -> Result<RetainedAuthorityCandidate<'m, 'p, 'b>> {
    let originals =
        super::originals::AuthenticatedOriginals::authenticate(manifest, payload, local)?;
    let signed = &manifest.data.signed;
    let b = &local.bindings;
    let env = text(signed, "env_id")?;
    let recipient = text(signed, "recipient")?;
    let facts = &originals.facts;
    let removal_claim = originals.removal_claim;
    let removals = component(payload, 4)?;
    if removal_claim
        || facts.values().any(|f| f.kind == "member_removed")
        || ["bounds", "pending", "self_placed", "witness_commit_hashes"]
            .iter()
            .any(|k| {
                removals.get(k).is_none_or(|v| match v {
                    Value::Array(a) => !a.is_empty(),
                    Value::Object(m) => !m.is_empty(),
                    _ => true,
                })
            })
    {
        return Err(E::ScopeUnsupported);
    }
    originals.check_history()?;
    let super::originals::AuthenticatedOriginals {
        devices,
        mut indices,
        facts,
        mut secret_ids,
        mut connection_ids,
        ..
    } = originals;
    indices.sort_by(|a, b| (&a.hlc, &a.author).cmp(&(&b.hlc, &b.author)));
    let cut = indices.last().ok_or(E::HistoryProofUnavailable)?;
    let cut_hash = cut.hash.clone();
    let cut_hlc = cut.hlc.clone();
    let trace = fold::checkpoint_authority_trace(
        env,
        indices.iter().map(|i| {
            original_commit(payload, i.original_index)
                .map(|c| (i.original_index, i.hash.clone(), c))
                .map_err(|_| {
                    crate::errors::Error::invalid_input("team_checkpoint_structure_invalid")
                })
        }),
    )
    .map_err(|_| E::AuthorityUnproven)?;
    if trace.operations.iter().any(|op| op.skipped.is_some()) {
        return Err(E::AuthorityUnproven);
    }
    if !sync::is_admin(&trace.projection, text(signed, "signer")?)
        || trace.projection["members"][recipient]["status"] != "active"
        || trace.projection["members"][recipient]["role"] != b.recipient_role.as_str()
    {
        return Err(E::AuthorityUnproven);
    }
    // Materialize the checked snapshot exactly once, take only the authority
    // projection, collect IDs, and release the attested data tree.
    let mut snapshot = strict_json::materialize(payload.index.components.get(1).ok_or(SCHEMA)?)?;
    let document = snapshot
        .get_mut("document")
        .and_then(Value::as_object_mut)
        .ok_or(SCHEMA)?;
    for (key, ids) in [
        ("secrets", &mut secret_ids),
        ("connections", &mut connection_ids),
    ] {
        for id in document
            .get(key)
            .and_then(Value::as_object)
            .ok_or(SCHEMA)?
            .keys()
        {
            ids.insert(id.clone());
        }
    }
    let members = document
        .get("members")
        .and_then(Value::as_object)
        .ok_or(SCHEMA)?;
    for (fp, member) in members {
        if device_copy(field(member, "device")?, &devices)? != *fp {
            return Err(E::AuthorityUnproven);
        }
    }
    let mut projection = serde_json::Map::new();
    for key in ["owner", "members", "dek"] {
        projection.insert(key.into(), document.remove(key).ok_or(SCHEMA)?);
    }
    if canonical(&Value::Object(projection))? != canonical(&trace.projection)? {
        return Err(E::SemanticMismatch);
    }
    drop(snapshot);
    let applied: BTreeMap<_, _> = trace
        .operations
        .iter()
        .map(|o| ((o.position.hash.as_str(), o.position.op_index), o))
        .collect();
    for span in &payload.index.wraps {
        let value = strict_json::materialize(span)?;
        let generation = text(&value, "generation_id")?;
        let source = text(&value, "source_commit_hash")?;
        let op_index = bounded(field(&value, "source_op_index")?, 16_777_216)?;
        let selector = (generation.to_owned(), recipient.to_owned());
        let op = applied
            .get(&(source, op_index))
            .ok_or(E::HistoryProofUnavailable)?;
        if !op.applicable_wraps.contains(&selector) {
            return Err(E::AuthorityUnproven);
        }
        if trace
            .effective_wrap_sources
            .get(&selector)
            .is_some_and(|p| p.hash == source && p.op_index == op_index)
            && canonical(field(&value, "wrap")?)?
                != canonical(
                    &trace.projection["dek"]["generations"][generation]["wraps"][recipient],
                )?
        {
            return Err(E::SemanticMismatch);
        }
    }
    let mut effects = fold::Facts::default();
    let mut analyzed = BTreeMap::new();
    for (hash, fact) in facts {
        let needs_admin = fact.kind != "incident";
        let interval = trace
            .intervals
            .iter()
            .position(|r| r.fingerprint == fact.author && r.admin == needs_admin)
            .ok_or(E::AuthorityUnproven)?;
        sync::apply_fact(&mut effects, &fact);
        analyzed.insert(
            hash,
            AnalyzedFact {
                original: fact,
                basis: HistoricalBasis::AdministratorAttestedHistorical,
                interval,
            },
        );
    }
    if effects.tombstone_facts.keys().ne(payload.tombstones.iter())
        || analyzed.keys().ne(payload.facts.iter())
    {
        return Err(E::FactContradicted);
    }
    let digest =
        tombstone_gate::digest(&effects.tombstone_facts).map_err(|_| E::FactContradicted)?;
    if digest != text(signed, "tombstone_digest")? {
        return Err(E::FactContradicted);
    }
    for known in &local.restrictions.known_original_facts {
        let original = &analyzed
            .get(&known.hash)
            .ok_or(E::FactContradicted)?
            .original;
        if canonical(&original.to_dict())? != canonical(&known.original.to_dict())?
            || devices.get(&original.author) != Some(&known.author_record)
        {
            return Err(E::FactContradicted);
        }
    }
    let restrictions = &local.restrictions;
    if !restrictions
        .deleted_secret_ids
        .iter()
        .all(|id| effects.deleted_secrets.contains(id))
        || !restrictions
            .revoked_versions
            .iter()
            .all(|id| effects.revoked_versions.contains(id))
        || !restrictions
            .disabled_connection_ids
            .iter()
            .all(|id| effects.disabled_connections.contains(id))
        || restrictions
            .removed_members
            .iter()
            .any(|fp| trace.projection["members"][fp]["status"] != "removed")
    {
        return Err(E::FactContradicted);
    }
    if let RequiredTombstoneSupport::Required {
        known_tombstone_hashes,
        unresolved_nonempty_digests,
    } = &restrictions.required_tombstone_support
        && (!known_tombstone_hashes
            .iter()
            .all(|h| effects.tombstone_facts.contains_key(h))
            || unresolved_nonempty_digests
                .iter()
                .any(|h| h != &digest || effects.tombstone_facts.is_empty()))
    {
        return Err(E::FactContradicted);
    }
    if local.occupied.iter().any(|entry| match entry.kind {
        LocalIdKind::Secret => secret_ids.contains(&entry.id),
        LocalIdKind::Connection => connection_ids.contains(&entry.id),
    }) || restrictions
        .restored_bindings
        .iter()
        .any(|b| secret_ids.contains(&b.secret_id))
    {
        return Err(E::ExistingStateUnsupported);
    }
    let authority_projection_hash = super::manifest::value_hash(&trace.projection)?;
    Ok(RetainedAuthorityCandidate {
        manifest,
        payload,
        local,
        trace,
        facts: analyzed,
        tombstone_digest: digest,
        authority_projection_hash,
        payload_hash: text(field(signed, "payload")?, "sha256")?,
        cut_hash,
        cut_hlc,
    })
}
