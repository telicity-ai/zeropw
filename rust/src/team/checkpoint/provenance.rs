use super::manifest::canonical;
use super::{
    CheckpointError as E, IntegrityCheckedPayload, ManifestAttestation, Result, redacted_debug,
};
use serde_json::{Value, json};

/// Inert inspection metadata, never an admission receipt or install ticket.
/// ```compile_fail
/// use zeropw::team::checkpoint::CandidateProvenanceV1;
/// let candidate = CandidateProvenanceV1 {};
/// ```
pub struct CandidateProvenanceV1 {
    value: Value,
}
impl CandidateProvenanceV1 {
    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        canonical(&self.value)
    }
}
redacted_debug!(CandidateProvenanceV1);

pub fn candidate_provenance(
    attestation: &ManifestAttestation,
    payload: &IntegrityCheckedPayload<'_>,
) -> Result<CandidateProvenanceV1> {
    let m = &attestation.data;
    if payload.manifest_hash != m.hash {
        return Err(E::BindingMismatch);
    }
    let mut value = serde_json::Map::new();
    for key in [
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
        value.insert(
            key.into(),
            m.signed.get(key).ok_or(E::StructureInvalid)?.clone(),
        );
    }
    value.insert(
        "format".into(),
        json!("zeropw-team-checkpoint-candidate-v1"),
    );
    value.insert("v".into(), json!(1));
    value.insert("trust_model".into(), json!("administrator_attested"));
    value.insert("stage".into(), json!("integrity_checked_not_admitted"));
    value.insert("signer_record".into(), m.pinned.to_dict());
    value.insert("manifest_hash".into(), json!(m.hash));
    value.insert(
        "payload_sha256".into(),
        m.signed
            .get("payload")
            .and_then(|p| p.get("sha256"))
            .ok_or(E::StructureInvalid)?
            .clone(),
    );
    let bindings=payload.facts.iter().map(|hash|json!({"fact_hash":hash,"manifest_hash":m.hash,"approved_signer":m.signed["signer"],"approval_sha256":m.signed["approval_sha256"],"basis":"administrator_attested_candidate"})).collect();
    value.insert("candidate_fact_bindings".into(), Value::Array(bindings));
    value.insert(
        "candidate_tombstone_fact_hashes".into(),
        json!(payload.tombstones),
    );
    Ok(CandidateProvenanceV1 {
        value: Value::Object(value),
    })
}
