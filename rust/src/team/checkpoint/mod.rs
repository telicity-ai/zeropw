//! Pure bounded checkpoint attestation and integrity checks.
//!
//! These results establish neither retained-history admission nor final-overlay
//! correctness. Snapshot onboarding remains unsupported; there is no runtime
//! caller, installer, receipt, or credential authority in this module.
//!
//! Proof fields are private and JSON inspection cannot manufacture authority.
//! ```compile_fail
//! use zeropw::team::checkpoint::ManifestAttestation;
//! let proof = ManifestAttestation {};
//! ```
//! ```compile_fail
//! use zeropw::team::checkpoint::CandidateProvenanceV1;
//! let proof: CandidateProvenanceV1 = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail
//! use zeropw::team::checkpoint::IntegrityCheckedPayload;
//! let proof = IntegrityCheckedPayload {};
//! ```
//! ```compile_fail
//! use zeropw::team::checkpoint::CandidateProvenanceV1;
//! fn activate(candidate: CandidateProvenanceV1) { candidate.install(); }
//! ```
//! ```compile_fail
//! use zeropw::team::checkpoint::CheckedChunk;
//! let chunk: CheckedChunk = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail
//! use zeropw::team::{checkpoint::CandidateProvenanceV1, sync::Fact};
//! fn admit(candidate: CandidateProvenanceV1) -> Fact { candidate.into() }
//! ```
//! ```compile_fail
//! use zeropw::team::checkpoint::RetainedAuthorityCandidate;
//! let proof: RetainedAuthorityCandidate<'_, '_, '_> = Default::default();
//! ```
//! ```compile_fail
//! use zeropw::team::{checkpoint::RetainedAuthorityCandidate, fold::Facts};
//! fn install(p: RetainedAuthorityCandidate<'_, '_, '_>) -> Facts { p.into() }
//! ```
//! ```compile_fail
//! use zeropw::team::checkpoint::RetainedAuthorityCandidate;
//! fn receipt(p: RetainedAuthorityCandidate<'_, '_, '_>) { p.receipt_fact(); }
//! ```
//! ```compile_fail
//! use zeropw::team::checkpoint::{CandidateProvenanceV1, verify_retained_authority};
//! fn check(p: CandidateProvenanceV1) { verify_retained_authority(&p); }
//! ```
//! ```compile_fail
//! use zeropw::team::checkpoint::RetainedAuthorityCandidate;
//! fn mutate(p: &mut RetainedAuthorityCandidate<'_, '_, '_>) { p.facts.clear(); }
//! ```

mod admission;
mod manifest;
mod payload;
mod provenance;
mod strict_json;

pub use admission::{
    FactRoleInterval, KnownOriginalFact, LocalIdKind, LocalIdScope, LocalMapping,
    LocalRestrictions, ObservedBinding, ObservedInventory, OccupiedLocalId,
    RequiredTombstoneSupport, RetainedAuthorityCandidate, SemanticBindings, SemanticError,
    SemanticLocalInputs, verify_retained_authority,
};
pub use manifest::{
    AuthenticatedSessionExpectations, AuthorHead, ChunkDescriptor, ComponentDescriptor,
    ExpectedContext, LocalApprovalDescription, ManifestAttestation, RecipientRole,
    VerificationWallTime, verify_manifest_bytes,
};
pub use payload::{
    CheckedChunk, ComponentSpan, IntegrityCheckedPayload, verify_chunk_frame_bytes,
    verify_payload_bytes,
};
pub use provenance::{CandidateProvenanceV1, candidate_provenance};

/// Closed, input-independent refusal reasons. No Serde or peer text escapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointError {
    JsonInvalid,
    DuplicateKey,
    LimitExceeded,
    SchemaUnsupported,
    BindingMismatch,
    Expired,
    SignatureInvalid,
    IntegrityMismatch,
    StructureInvalid,
}

impl CheckpointError {
    pub fn reason(self) -> &'static str {
        match self {
            Self::JsonInvalid => "team_checkpoint_json_invalid",
            Self::DuplicateKey => "team_checkpoint_duplicate_key",
            Self::LimitExceeded => "team_checkpoint_limit_exceeded",
            Self::SchemaUnsupported => "team_checkpoint_schema_unsupported",
            Self::BindingMismatch => "team_checkpoint_binding_mismatch",
            Self::Expired => "team_checkpoint_expired",
            Self::SignatureInvalid => "team_checkpoint_signature_invalid",
            Self::IntegrityMismatch => "team_checkpoint_integrity_mismatch",
            Self::StructureInvalid => "team_checkpoint_structure_invalid",
        }
    }
}
impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}
impl std::error::Error for CheckpointError {}
impl From<strict_json::Error> for CheckpointError {
    fn from(value: strict_json::Error) -> Self {
        match value {
            strict_json::Error::Json => Self::JsonInvalid,
            strict_json::Error::Duplicate => Self::DuplicateKey,
            strict_json::Error::Limit => Self::LimitExceeded,
            strict_json::Error::Schema => Self::SchemaUnsupported,
        }
    }
}

type Result<T> = std::result::Result<T, CheckpointError>;

macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => {$ (
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($ty), "([redacted])"))
            }
        }
    )+};
}
use redacted_debug;
