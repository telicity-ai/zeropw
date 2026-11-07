//! Authentication of retrieval bytes for one immutable complete supplied cut.
//! This is trusted backend work, never an agent-facing secret operation.
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::{CompleteCutSemanticCandidate, E, Result, component};
use crate::secret::SecretBytes;
use crate::team::checkpoint::manifest::{array, bounded, canonical, field, text};
use crate::team::checkpoint::{CheckpointError, strict_json};
use crate::team::{envelope, identity::DeviceKey};

const RECORD_CAP: usize = 65_536;
const PAYLOAD_CAP: usize = 16_777_216;
const LIMIT: E = E::Checkpoint(CheckpointError::LimitExceeded);
const BINDING: E = E::Checkpoint(CheckpointError::BindingMismatch);

#[cfg(test)]
std::thread_local! {
    static CRYPTO_CALLS: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

/// Opaque and noninstallable. Owns required DEKs in zeroizing memory, never
/// credential plaintext. Authentication says nothing about provider syntax or
/// SSH signing readiness. Borrowed observations are not a freshness lock.
///
/// ```compile_fail
/// use zeropw::team::checkpoint::RequiredGenerationCandidate;
/// let p = RequiredGenerationCandidate {};
/// ```
/// ```compile_fail
/// use zeropw::team::checkpoint::RequiredGenerationCandidate;
/// let p: RequiredGenerationCandidate<'_, '_, '_, '_> = Default::default();
/// ```
/// ```compile_fail
/// use zeropw::team::checkpoint::RequiredGenerationCandidate;
/// let p: RequiredGenerationCandidate<'_, '_, '_, '_> = serde_json::from_str("{}").unwrap();
/// ```
/// ```compile_fail
/// use zeropw::team::checkpoint::RequiredGenerationCandidate;
/// fn serialize(p: &RequiredGenerationCandidate<'_, '_, '_, '_>) { serde_json::to_vec(p).unwrap(); }
/// ```
/// ```compile_fail
/// use zeropw::team::checkpoint::RequiredGenerationCandidate;
/// fn clone(p: RequiredGenerationCandidate<'_, '_, '_, '_>) { p.clone(); }
/// ```
/// ```compile_fail
/// use zeropw::team::checkpoint::RequiredGenerationCandidate;
/// let p: RequiredGenerationCandidate<'_, '_, '_, '_> = serde_json::json!({}).into();
/// ```
/// ```compile_fail
/// use zeropw::team::checkpoint::RequiredGenerationCandidate;
/// let p: RequiredGenerationCandidate<'_, '_, '_, '_> = b"proof".as_slice().into();
/// ```
/// ```compile_fail
/// use zeropw::team::checkpoint::RequiredGenerationCandidate;
/// fn bytes<'a>(p: &'a RequiredGenerationCandidate<'_, '_, '_, '_>) -> &'a [u8] { p.as_ref() }
/// ```
/// ```compile_fail
/// use zeropw::team::checkpoint::RequiredGenerationCandidate;
/// fn keys(p: RequiredGenerationCandidate<'_, '_, '_, '_>) { p.keys.clear(); }
/// ```
/// ```compile_fail
/// use zeropw::team::checkpoint::RequiredGenerationCandidate;
/// fn document(p: RequiredGenerationCandidate<'_, '_, '_, '_>) { p.document(); }
/// ```
/// ```compile_fail
/// use zeropw::team::checkpoint::RequiredGenerationCandidate;
/// fn plaintext(p: RequiredGenerationCandidate<'_, '_, '_, '_>) { p.plaintext(); }
/// ```
/// ```compile_fail
/// use zeropw::team::checkpoint::RequiredGenerationCandidate;
/// fn install(p: RequiredGenerationCandidate<'_, '_, '_, '_>) { p.install(); }
/// ```
/// ```compile_fail
/// use zeropw::team::checkpoint::RequiredGenerationCandidate;
/// fn receipt(p: RequiredGenerationCandidate<'_, '_, '_, '_>) { p.receipt_fact(); }
/// ```
/// ```compile_fail
/// use zeropw::team::{checkpoint::RequiredGenerationCandidate, fold::Facts};
/// fn facts(p: RequiredGenerationCandidate<'_, '_, '_, '_>) -> Facts { p.into() }
/// ```
/// ```compile_fail
/// use zeropw::team::checkpoint::{RequiredGenerationCandidate, CandidateProvenanceV1};
/// fn provenance(p: RequiredGenerationCandidate<'_, '_, '_, '_>) -> CandidateProvenanceV1 { p.into() }
/// ```
pub struct RequiredGenerationCandidate<'c, 'm, 'p, 'b> {
    candidate: &'c CompleteCutSemanticCandidate<'m, 'p, 'b>,
    keys: BTreeMap<&'c str, SecretBytes>,
    checked_ciphertexts: usize,
}
impl RequiredGenerationCandidate<'_, '_, '_, '_> {
    pub fn stage(&self) -> &'static str {
        "required_generation_ciphertexts_checked_not_admitted"
    }
    pub fn trust_model(&self) -> &'static str {
        "administrator_attested"
    }
    pub fn manifest_hash(&self) -> &str {
        self.candidate.manifest_hash()
    }
    pub fn observation_revision(&self) -> &str {
        self.candidate.observation_revision()
    }
    pub fn covered_cut_sha256(&self) -> &str {
        self.candidate.covered_cut_sha256()
    }
    pub fn recomputed_final_document_sha256(&self) -> &str {
        self.candidate.recomputed_final_document_sha256()
    }
    pub fn admitted_fact_hashes_sha256(&self) -> &str {
        self.candidate.admitted_fact_hashes_sha256()
    }
    pub fn tombstone_digest(&self) -> &str {
        self.candidate.tombstone_digest()
    }
    pub fn required_generation_count(&self) -> usize {
        self.keys.len()
    }
    pub fn checked_ciphertext_count(&self) -> usize {
        self.checked_ciphertexts
    }
}
impl std::fmt::Debug for RequiredGenerationCandidate<'_, '_, '_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RequiredGenerationCandidate([redacted])")
    }
}

fn object(v: &Value) -> Result<&Map<String, Value>> {
    v.as_object().ok_or(E::SemanticMismatch)
}
fn preflight_wrap(wrap: &Value) -> Result<()> {
    // The same legacy decoder as unwrap_dek, not manifest fixed_b64. One
    // field's temporary decoded buffer at a time; all released before unwrap.
    for (name, size) in [("eph_pub", 32), ("nonce", 12), ("ciphertext", 48)] {
        let encoded = text(wrap, name).map_err(|_| E::GenerationUnavailable)?;
        if encoded.len() > PAYLOAD_CAP {
            return Err(LIMIT);
        }
        let decoded = crate::pybase64::b64decode(encoded).map_err(|_| E::GenerationUnavailable)?;
        if decoded.len() != size {
            return Err(E::GenerationUnavailable);
        }
    }
    Ok(())
}

struct Version<'a> {
    secret: &'a str,
    version: &'a str,
    generation: &'a str,
    entry: &'a Map<String, Value>,
}
struct Selected<'a, 'b> {
    span: &'a strict_json::Span<'b>,
    effective: bool,
}

/// Check every selected required original wrap and every final active/staged
/// ciphertext, without loading state, exporting keys, or returning a prefix.
///
/// ```compile_fail
/// use zeropw::team::{checkpoint::{RetainedAuthorityCandidate, verify_required_generations}, identity::DeviceKey};
/// fn old(p: &RetainedAuthorityCandidate<'_, '_, '_>, k: &DeviceKey) { verify_required_generations(p, k); }
/// ```
/// ```compile_fail
/// use zeropw::team::{checkpoint::{CandidateProvenanceV1, verify_required_generations}, identity::DeviceKey};
/// fn json(p: &CandidateProvenanceV1, k: &DeviceKey) { verify_required_generations(p, k); }
/// ```
/// ```compile_fail
/// use zeropw::team::{checkpoint::{CompleteCutSemanticCandidate, verify_required_generations}, identity::DeviceKey};
/// fn replace(mut p: CompleteCutSemanticCandidate<'_, '_, '_>, k: &DeviceKey) {
///     let checked = verify_required_generations(&p, k).unwrap();
///     drop(p);
///     checked.stage();
/// }
/// ```
/// ```compile_fail
/// use zeropw::team::{checkpoint::*, identity::DeviceKey};
/// fn replace<'m, 'p, 'b>(mut c: CompleteCutSemanticCandidate<'m, 'p, 'b>, other: CompleteCutSemanticCandidate<'m, 'p, 'b>, k: &DeviceKey) {
///     let checked = verify_required_generations(&c, k).unwrap();
///     c = other;
///     checked.stage();
/// }
/// ```
/// ```compile_fail
/// use zeropw::team::{checkpoint::*, identity::DeviceKey};
/// fn payload(m: &ManifestAttestation, local: &SemanticLocalInputs, raw: &[u8], k: &DeviceKey) {
///     let payload = verify_payload_bytes(m, raw).unwrap();
///     let c = verify_complete_cut_semantics(m, &payload, local).unwrap();
///     let checked = verify_required_generations(&c, k).unwrap();
///     drop(payload);
///     checked.stage();
/// }
/// ```
/// ```compile_fail
/// use zeropw::team::{checkpoint::*, identity::DeviceKey};
/// fn mutate(m: &ManifestAttestation, local: &mut SemanticLocalInputs, p: &IntegrityCheckedPayload<'_>, k: &DeviceKey, replacement: SemanticLocalInputs) {
///     let c = verify_complete_cut_semantics(m, p, local).unwrap();
///     let checked = verify_required_generations(&c, k).unwrap();
///     *local = replacement;
///     checked.stage();
/// }
/// ```
pub fn verify_required_generations<'c, 'm, 'p, 'b>(
    candidate: &'c CompleteCutSemanticCandidate<'m, 'p, 'b>,
    recipient: &DeviceKey,
) -> Result<RequiredGenerationCandidate<'c, 'm, 'p, 'b>> {
    let signed = &candidate.originals.manifest.data.signed;
    let env = text(signed, "env_id")?;
    let fingerprint = text(signed, "recipient")?;
    let record = recipient.record().map_err(|_| BINDING)?;
    if record.fingerprint() != fingerprint
        || record != candidate.originals.local.bindings.recipient_record
        || candidate.originals.devices.get(fingerprint) != Some(&record)
    {
        return Err(BINDING);
    }
    let mut versions = Vec::new();
    let mut required = BTreeSet::new();
    for (sid, secret) in object(field(&candidate._document, "secrets")?)? {
        if secret.get("deleted").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        for (vid, entry) in object(field(secret, "versions")?)? {
            if matches!(text(entry, "status")?, "active" | "staged") {
                if versions.len() >= RECORD_CAP {
                    return Err(LIMIT);
                }
                let generation = text(entry, "generation")?;
                required.insert(generation);
                versions.try_reserve(1).map_err(|_| LIMIT)?;
                versions.push(Version {
                    secret: sid,
                    version: vid,
                    generation,
                    entry: object(entry)?,
                });
            }
        }
    }
    if required
        .iter()
        .copied()
        .ne(candidate.generations.required.iter().map(String::as_str))
    {
        return Err(E::SemanticMismatch);
    }
    let payload = candidate.originals.payload;
    for v in array(field(component(payload, 5)?, "unavailable_generations")?)? {
        if required.contains(v.as_str().ok_or(E::SemanticMismatch)?) {
            return Err(E::GenerationUnavailable);
        }
    }
    let operations: BTreeMap<_, _> = candidate
        .trace
        .operations
        .iter()
        .map(|op| ((op.position.hash.as_str(), op.position.op_index), op))
        .collect();
    let generations = field(field(&candidate._document, "dek")?, "generations")?;
    let mut selected: BTreeMap<String, Vec<Selected<'_, '_>>> = BTreeMap::new();
    // All nonsecret checks finish before the first unwrap. Keep only original
    // spans and a Boolean; never a materialized history of wraps.
    for span in &payload.index.wraps {
        let entry = strict_json::materialize(span)?;
        let generation = text(&entry, "generation_id")?;
        if !required.contains(generation) {
            continue;
        }
        let selector = (generation.to_owned(), fingerprint.to_owned());
        let effective = candidate
            .trace
            .effective_wrap_sources
            .get(&selector)
            .ok_or(E::GenerationUnavailable)?;
        let source = text(&entry, "source_commit_hash")?;
        let index = bounded(field(&entry, "source_op_index")?, PAYLOAD_CAP)?;
        let op = operations
            .get(&(source, index))
            .ok_or(E::GenerationUnavailable)?;
        if text(&entry, "recipient")? != fingerprint
            || op.skipped.is_some()
            || !op.applicable_wraps.contains(&selector)
        {
            return Err(E::GenerationUnavailable);
        }
        let is_effective = effective.hash == source && effective.op_index == index;
        let wrap = field(&entry, "wrap")?;
        if is_effective
            && canonical(wrap)?
                != canonical(
                    field(
                        field(
                            field(generations, generation).map_err(|_| E::GenerationUnavailable)?,
                            "wraps",
                        )?,
                        fingerprint,
                    )
                    .map_err(|_| E::GenerationUnavailable)?,
                )?
        {
            return Err(E::GenerationUnavailable);
        }
        preflight_wrap(wrap)?;
        let entries = selected.entry(generation.to_owned()).or_default();
        entries.try_reserve(1).map_err(|_| LIMIT)?;
        entries.push(Selected {
            span,
            effective: is_effective,
        });
    }
    for generation in &required {
        if !selected
            .get(*generation)
            .is_some_and(|entries| entries.iter().any(|e| e.effective))
        {
            return Err(E::GenerationUnavailable);
        }
    }
    let mut keys = BTreeMap::new();
    for generation in required {
        let entries = selected.get(generation).ok_or(E::GenerationUnavailable)?;
        let effective = entries
            .iter()
            .find(|e| e.effective)
            .ok_or(E::GenerationUnavailable)?;
        let key = unwrap(effective.span, env, generation, recipient)?;
        for other in entries.iter().filter(|e| !e.effective) {
            let recovered = unwrap(other.span, env, generation, recipient)?;
            if !key.ct_eq(recovered.expose()) {
                return Err(E::GenerationUnavailable);
            }
            drop(recovered);
        }
        keys.insert(generation, key);
    }
    let mut checked_ciphertexts = 0usize;
    for version in versions {
        let key = keys.get(version.generation).ok_or(E::SemanticMismatch)?;
        #[cfg(test)]
        CRYPTO_CALLS.with(|c| {
            let (w, d) = c.get();
            c.set((w, d + 1));
        });
        let plaintext = SecretBytes::new(
            envelope::decrypt_secret(
                key.expose(),
                env,
                version.secret,
                version.version,
                version.entry,
            )
            .map_err(|_| E::GenerationUnavailable)?,
        );
        // No value-dependent observation survives. Release before the next blob.
        drop(plaintext);
        checked_ciphertexts = checked_ciphertexts.checked_add(1).ok_or(LIMIT)?;
    }
    Ok(RequiredGenerationCandidate {
        candidate,
        keys,
        checked_ciphertexts,
    })
}

fn unwrap(
    span: &strict_json::Span<'_>,
    env: &str,
    generation: &str,
    recipient: &DeviceKey,
) -> Result<SecretBytes> {
    let entry = strict_json::materialize(span)?;
    #[cfg(test)]
    CRYPTO_CALLS.with(|c| {
        let (w, d) = c.get();
        c.set((w + 1, d));
    });
    let key = SecretBytes::new(
        envelope::unwrap_dek(field(&entry, "wrap")?, env, generation, recipient)
            .map_err(|_| E::GenerationUnavailable)?,
    );
    if key.len() != 32 {
        return Err(E::GenerationUnavailable);
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::team::checkpoint::*;

    fn key(seed: u8, scalar: u8) -> DeviceKey {
        DeviceKey {
            sign_seed: SecretBytes::new(vec![seed; 32]),
            agree_private: SecretBytes::new(vec![scalar; 32]),
        }
    }
    #[test]
    fn empty_required_does_no_unwrap_or_decrypt_and_nonempty_counts_every_blob() {
        for (name, expected) in [("G05-empty", (0, 0)), ("G01-multiple", (2, 4))] {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/team_checkpoint_required_generations_v1")
                .join(name);
            let raw = std::fs::read(root.join("payload.json")).unwrap();
            let manifest = std::fs::read(root.join("manifest.json")).unwrap();
            let value = crate::pyjson::loads(std::str::from_utf8(&manifest).unwrap()).unwrap();
            let env = value["env_id"].as_str().unwrap().to_owned();
            let signer = key(1, 4).record().unwrap();
            let recipient = key(2, 5);
            let context = ExpectedContext::from_local_expectations(
                LocalApprovalDescription {
                    approval_id: "20".repeat(16),
                    env_id: env.clone(),
                    signer: signer.fingerprint(),
                    signer_record: signer.clone(),
                    recipient: recipient.fingerprint().unwrap(),
                    recipient_role: RecipientRole::User,
                    invite_id: "10".repeat(16),
                    invitation_expires_at_ms: 1800003600000,
                },
                AuthenticatedSessionExpectations {
                    peer_record: signer,
                    env_id: env.clone(),
                    local_recipient: recipient.fingerprint().unwrap(),
                    session_nonce: "50".repeat(32),
                    onboarding_nonce: "60".repeat(32),
                },
            )
            .unwrap();
            let m = verify_manifest_bytes(
                &manifest,
                &context,
                VerificationWallTime::from_millis(1800000000001).unwrap(),
            )
            .unwrap();
            let payload = verify_payload_bytes(&m, &raw).unwrap();
            let local = SemanticLocalInputs::from_local_observation(
                SemanticBindings {
                    recipient_record: recipient.record().unwrap(),
                    recipient_role: RecipientRole::User,
                    env_id: env.clone(),
                    manifest_hash: m.manifest_hash().into(),
                    approval_sha256: context.approval_sha256().into(),
                    session_nonce: "50".repeat(32),
                    onboarding_nonce: "60".repeat(32),
                    intended_mapping: LocalMapping {
                        project: "synthetic".into(),
                        environment: "test".into(),
                        env_id: env,
                    },
                    observation_revision: "a1".repeat(32),
                },
                ObservedInventory {
                    admitted_commits: 0,
                    admitted_facts: 0,
                    checkpoints: 0,
                    derived_team_entries: 0,
                    unsent_edits: 0,
                    pending_imports: 0,
                    completed_imports: 0,
                    stale_restore: false,
                    existing_mapping: None,
                    own_staging_manifest_hash: None,
                },
                vec![],
                LocalRestrictions {
                    known_original_facts: vec![],
                    deleted_secret_ids: BTreeSet::new(),
                    revoked_versions: BTreeSet::new(),
                    disabled_connection_ids: BTreeSet::new(),
                    removed_members: BTreeSet::new(),
                    restored_bindings: vec![],
                    required_tombstone_support: RequiredTombstoneSupport::NotObserved,
                    backup_barrier: false,
                },
            )
            .unwrap();
            let candidate = verify_complete_cut_semantics(&m, &payload, &local).unwrap();
            for _ in 0..2 {
                CRYPTO_CALLS.with(|c| c.set((0, 0)));
                let result = verify_required_generations(&candidate, &recipient).unwrap();
                CRYPTO_CALLS.with(|c| assert_eq!(c.get(), expected));
                assert_eq!(result.checked_ciphertext_count(), expected.1);
                drop(result);
            }
        }
    }
}
