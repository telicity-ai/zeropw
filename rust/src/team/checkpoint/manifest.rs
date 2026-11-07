use std::collections::BTreeMap;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{CheckpointError as E, Result, redacted_debug, strict_json};
use crate::{
    crypto::ed25519,
    pybase64,
    pyint::PyInt,
    pyjson::{self, DumpOptions},
    team::{commit, identity::DeviceRecord},
};

pub(super) const NAMES: [&str; 6] = [
    "devices",
    "snapshot",
    "commits",
    "facts",
    "removals",
    "recipient_dek_wraps",
];
pub(super) const COUNT_NAMES: [&str; 5] =
    ["devices", "commits", "facts", "versions", "recipient_wraps"];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RecipientRole {
    Admin,
    User,
}
impl RecipientRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
        }
    }
    fn parse(text: &str) -> Result<Self> {
        match text {
            "admin" => Ok(Self::Admin),
            "user" => Ok(Self::User),
            _ => Err(E::SchemaUnsupported),
        }
    }
}

/// Caller-supplied public local metadata. This is not an approval proof.
#[derive(Clone)]
pub struct LocalApprovalDescription {
    pub approval_id: String,
    pub env_id: String,
    pub signer: String,
    pub signer_record: DeviceRecord,
    pub recipient: String,
    pub recipient_role: RecipientRole,
    pub invite_id: String,
    pub invitation_expires_at_ms: u64,
}
/// Independent values retained by the future trusted authenticated-session layer.
pub struct AuthenticatedSessionExpectations {
    pub peer_record: DeviceRecord,
    pub env_id: String,
    pub local_recipient: String,
    pub session_nonce: String,
    pub onboarding_nonce: String,
}

pub struct ExpectedContext {
    approval: LocalApprovalDescription,
    approval_hash: String,
    session: AuthenticatedSessionExpectations,
}
impl ExpectedContext {
    /// Checks shapes and equality only; it cannot authenticate a human, establish
    /// a live session, or prove persisted/unrevoked two-sided approval.
    pub fn from_local_expectations(
        approval: LocalApprovalDescription,
        session: AuthenticatedSessionExpectations,
    ) -> Result<Self> {
        if !hex_text(&approval.approval_id, 32)
            || !hex_text(&approval.invite_id, 32)
            || !commit::valid_env_id(&approval.env_id)
            || !fingerprint(&approval.signer)
            || !fingerprint(&approval.recipient)
            || !hex_text(&session.session_nonce, 64)
            || !hex_text(&session.onboarding_nonce, 64)
        {
            return Err(E::SchemaUnsupported);
        }
        VerificationWallTime::from_millis(approval.invitation_expires_at_ms)?;
        if !approval.signer_record.verify_uncached()
            || approval.signer_record.fingerprint() != approval.signer
        {
            return Err(E::SignatureInvalid);
        }
        if session.peer_record != approval.signer_record
            || session.env_id != approval.env_id
            || session.local_recipient != approval.recipient
        {
            return Err(E::BindingMismatch);
        }
        let description = json!({"domain":"zeropw-team-bootstrap-local-approval-v1","v":1,"trust_model":"administrator_attested",
            "approval_id":approval.approval_id,"env_id":approval.env_id,"signer":approval.signer,"signer_record":approval.signer_record.to_dict(),
            "recipient":approval.recipient,"recipient_role":approval.recipient_role.as_str(),"invite_id":approval.invite_id,"invitation_expires_at_ms":approval.invitation_expires_at_ms});
        let approval_hash = value_hash(&description)?;
        Ok(Self {
            approval,
            approval_hash,
            session,
        })
    }
    pub fn approval_sha256(&self) -> &str {
        &self.approval_hash
    }
}

/// Supplied wall time, never a system clock or monotonic deadline.
#[derive(Clone, Copy)]
pub struct VerificationWallTime(u64);
impl VerificationWallTime {
    pub fn from_millis(ms: u64) -> Result<Self> {
        if ms > i64::MAX as u64 {
            Err(E::LimitExceeded)
        } else {
            Ok(Self(ms))
        }
    }
    pub fn millis(self) -> u64 {
        self.0
    }
}

pub struct AuthorHead {
    pub(super) author: String,
    pub(super) sequence: PyInt,
    pub(super) hash: String,
    pub(super) hlc: (PyInt, PyInt),
}
impl AuthorHead {
    pub fn author(&self) -> &str {
        &self.author
    }
    pub fn author_seq(&self) -> &PyInt {
        &self.sequence
    }
    pub fn commit_hash(&self) -> &str {
        &self.hash
    }
    pub fn hlc(&self) -> (&PyInt, &PyInt) {
        (&self.hlc.0, &self.hlc.1)
    }
}
pub struct ComponentDescriptor {
    pub(super) name: String,
    pub(super) length: usize,
    pub(super) hash: String,
    pub(super) count: usize,
}
impl ComponentDescriptor {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn byte_length(&self) -> usize {
        self.length
    }
    pub fn sha256(&self) -> &str {
        &self.hash
    }
    pub fn item_count(&self) -> usize {
        self.count
    }
}
pub struct ChunkDescriptor {
    pub(super) index: usize,
    pub(super) length: usize,
    pub(super) hash: String,
}
impl ChunkDescriptor {
    pub fn index(&self) -> usize {
        self.index
    }
    pub fn byte_length(&self) -> usize {
        self.length
    }
    pub fn sha256(&self) -> &str {
        &self.hash
    }
}

/// Signature and supplied-context binding only; no role, history or admission proof.
/// ```compile_fail
/// use zeropw::team::checkpoint::ManifestAttestation;
/// let p: ManifestAttestation = serde_json::from_str("{}").unwrap();
/// ```
pub struct ManifestAttestation {
    pub(super) data: Box<ManifestData>,
}
pub(super) struct ManifestData {
    pub(super) signed: Value,
    pub(super) hash: String,
    pub(super) pinned: DeviceRecord,
    pub(super) vector: BTreeMap<String, PyInt>,
    pub(super) heads: Vec<AuthorHead>,
    pub(super) components: Vec<ComponentDescriptor>,
    pub(super) counts: [usize; 5],
    pub(super) length: usize,
    pub(super) chunks: Vec<ChunkDescriptor>,
}
impl ManifestAttestation {
    pub fn manifest_hash(&self) -> &str {
        &self.data.hash
    }
    pub fn vector(&self) -> &BTreeMap<String, PyInt> {
        &self.data.vector
    }
    pub fn heads(&self) -> &[AuthorHead] {
        &self.data.heads
    }
    pub fn components(&self) -> &[ComponentDescriptor] {
        &self.data.components
    }
    pub fn chunks(&self) -> &[ChunkDescriptor] {
        &self.data.chunks
    }
    /// devices, commits, facts, encrypted versions, recipient wraps.
    pub fn counts(&self) -> [usize; 5] {
        self.data.counts
    }
    pub fn signed_metadata(&self) -> &Value {
        &self.data.signed
    }
}
redacted_debug!(
    RecipientRole,
    LocalApprovalDescription,
    AuthenticatedSessionExpectations,
    ExpectedContext,
    VerificationWallTime,
    AuthorHead,
    ComponentDescriptor,
    ChunkDescriptor,
    ManifestAttestation
);

pub fn verify_manifest_bytes(
    original: &[u8],
    expected: &ExpectedContext,
    check_time: VerificationWallTime,
) -> Result<ManifestAttestation> {
    let signed = strict_json::manifest(original)?;
    for (key, value) in [
        ("type", "BOOTSTRAP_MANIFEST"),
        ("domain", "zeropw-team-bootstrap-v1"),
        ("trust_model", "administrator_attested"),
    ] {
        if text(&signed, key)? != value {
            return Err(E::SchemaUnsupported);
        }
    }
    if uint(field(&signed, "v")?)? != 1 {
        return Err(E::SchemaUnsupported);
    }
    let approval = &expected.approval;
    let session = &expected.session;
    for (key, value) in [
        ("env_id", approval.env_id.as_str()),
        ("signer", approval.signer.as_str()),
        ("recipient", approval.recipient.as_str()),
        ("recipient_role", approval.recipient_role.as_str()),
        ("invite_id", approval.invite_id.as_str()),
        ("approval_id", approval.approval_id.as_str()),
        ("approval_sha256", expected.approval_hash.as_str()),
        ("session_nonce", session.session_nonce.as_str()),
        ("onboarding_nonce", session.onboarding_nonce.as_str()),
    ] {
        if text(&signed, key)? != value {
            return Err(E::BindingMismatch);
        }
    }
    RecipientRole::parse(text(&signed, "recipient_role")?)?;
    for key in ["transfer_id", "recipient_authorization_id"] {
        if !hex_text(text(&signed, key)?, 32) {
            return Err(E::SchemaUnsupported);
        }
    }
    for key in [
        "recipient_admission_commit_hash",
        "admitted_fact_hashes_sha256",
        "tombstone_digest",
        "expected_final_document_sha256",
    ] {
        hash_text(text(&signed, key)?)?;
    }
    let created = wall(field(&signed, "created_at_ms")?)?;
    let expires = wall(field(&signed, "expires_at_ms")?)?;
    let authorization = wall(field(&signed, "authorization_expires_at_ms")?)?;
    if created >= expires
        || expires - created > 600_000
        || check_time.0 >= expires
        || created.saturating_sub(check_time.0) > 60_000
        || expires > authorization
        || authorization > approval.invitation_expires_at_ms
    {
        return Err(E::Expired);
    }
    let features = array(field(&signed, "required_features")?)?;
    if features.as_slice() != [json!("secret_tombstone_v1"), json!("snapshot_bootstrap_v1")] {
        return Err(E::SchemaUnsupported);
    }
    let vector = vector(field(&signed, "vector")?)?;
    let mut heads = Vec::new();
    let mut previous = "";
    for head in array(field(&signed, "heads")?)? {
        let author = text(head, "author")?;
        if !fingerprint(author) || author <= previous {
            return Err(E::StructureInvalid);
        }
        let sequence = uint(field(head, "author_seq")?)?;
        if sequence <= 0 || vector.get(author) != Some(&sequence) {
            return Err(E::StructureInvalid);
        }
        let hash = hash_text(text(head, "commit_hash")?)?.to_owned();
        let hlc = field(head, "hlc")?;
        heads.push(AuthorHead {
            author: author.into(),
            sequence,
            hash,
            hlc: (uint(field(hlc, "wall_ms")?)?, uint(field(hlc, "counter")?)?),
        });
        previous = author;
    }
    if heads.len() != vector.values().filter(|v| **v > 0).count() {
        return Err(E::StructureInvalid);
    }
    let count_value = field(&signed, "counts")?;
    let mut counts = [0; 5];
    for (i, key) in COUNT_NAMES.iter().enumerate() {
        counts[i] = bounded(
            field(count_value, key)?,
            if i == 0 {
                256
            } else if i < 4 {
                65_536
            } else {
                16_777_216
            },
        )?;
    }
    if counts[1]
        .checked_add(counts[2])
        .and_then(|n| n.checked_add(counts[3]))
        .is_none_or(|n| n > 65_536)
    {
        return Err(E::LimitExceeded);
    }
    let payload = field(&signed, "payload")?;
    let length = bounded(field(payload, "byte_length")?, 16_777_216)?;
    if length == 0 {
        return Err(E::LimitExceeded);
    }
    hash_text(text(payload, "sha256")?)?;
    let mut components = Vec::new();
    for (i, value) in array(field(&signed, "components")?)?.iter().enumerate() {
        let name = text(value, "name")?;
        if NAMES.get(i).copied() != Some(name) {
            return Err(E::SchemaUnsupported);
        }
        let component_length = bounded(field(value, "byte_length")?, length)?;
        let count = bounded(field(value, "item_count")?, 16_777_216)?;
        let expected_count = match i {
            0 => counts[0],
            1 | 4 => 1,
            2 => counts[1],
            3 => counts[2],
            5 => counts[4],
            _ => return Err(E::SchemaUnsupported),
        };
        if component_length == 0 || count != expected_count {
            return Err(E::StructureInvalid);
        }
        components.push(ComponentDescriptor {
            name: name.into(),
            length: component_length,
            hash: hash_text(text(value, "sha256")?)?.into(),
            count,
        });
    }
    let count = length.div_ceil(65_536);
    let chunk_values = array(field(payload, "chunks")?)?;
    if chunk_values.len() != count {
        return Err(E::StructureInvalid);
    }
    let mut chunks = Vec::new();
    for (i, value) in chunk_values.iter().enumerate() {
        let index = bounded(field(value, "index")?, 255)?;
        let chunk_length = bounded(field(value, "byte_length")?, 65_536)?;
        if index != i
            || chunk_length
                != if i + 1 == count {
                    length - 65_536 * (count - 1)
                } else {
                    65_536
                }
        {
            return Err(E::StructureInvalid);
        }
        chunks.push(ChunkDescriptor {
            index,
            length: chunk_length,
            hash: hash_text(text(value, "sha256")?)?.into(),
        });
    }
    let signature = fixed_b64(text(&signed, "sig")?, 64)?;
    let mut unsigned = signed.clone();
    unsigned
        .as_object_mut()
        .ok_or(E::SchemaUnsupported)?
        .remove("sig");
    if !ed25519::verify(
        &approval.signer_record.sign_pub,
        &canonical(&unsigned)?,
        &signature,
    ) {
        return Err(E::SignatureInvalid);
    }
    Ok(ManifestAttestation {
        data: Box::new(ManifestData {
            hash: value_hash(&signed)?,
            signed,
            pinned: approval.signer_record.clone(),
            vector,
            heads,
            components,
            counts,
            length,
            chunks,
        }),
    })
}

pub(super) fn canonical(value: &Value) -> Result<Vec<u8>> {
    pyjson::dumps(value, DumpOptions::compact_sorted())
        .map(String::into_bytes)
        .map_err(|_| E::StructureInvalid)
}
pub(super) fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub(super) fn value_hash(value: &Value) -> Result<String> {
    Ok(sha(&canonical(value)?))
}
pub(super) fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value
        .as_object()
        .and_then(|m| m.get(key))
        .ok_or(E::SchemaUnsupported)
}
pub(super) fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    field(value, key)?.as_str().ok_or(E::SchemaUnsupported)
}
pub(super) fn array(value: &Value) -> Result<&Vec<Value>> {
    value.as_array().ok_or(E::SchemaUnsupported)
}
pub(super) fn uint(value: &Value) -> Result<PyInt> {
    let result = PyInt::from_json_integer(value).ok_or(E::SchemaUnsupported)?;
    if result < 0 {
        Err(E::SchemaUnsupported)
    } else {
        Ok(result)
    }
}
pub(super) fn bounded(value: &Value, max: usize) -> Result<usize> {
    let result = uint(value)?
        .to_i64()
        .and_then(|v| usize::try_from(v).ok())
        .ok_or(E::LimitExceeded)?;
    if result > max {
        Err(E::LimitExceeded)
    } else {
        Ok(result)
    }
}
fn wall(value: &Value) -> Result<u64> {
    let result = uint(value)?.to_i64().ok_or(E::LimitExceeded)?;
    u64::try_from(result).map_err(|_| E::LimitExceeded)
}
pub(super) fn hex_text(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn hash_text(value: &str) -> Result<&str> {
    if hex_text(value, 64) {
        Ok(value)
    } else {
        Err(E::SchemaUnsupported)
    }
}
pub(super) fn fingerprint(value: &str) -> bool {
    value.len() == 26
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}
pub(super) fn vector(value: &Value) -> Result<BTreeMap<String, PyInt>> {
    let object = value.as_object().ok_or(E::SchemaUnsupported)?;
    if object.len() > 256 {
        return Err(E::LimitExceeded);
    }
    object
        .iter()
        .map(|(key, value)| {
            if !fingerprint(key) {
                return Err(E::SchemaUnsupported);
            }
            Ok((key.clone(), uint(value)?))
        })
        .collect()
}
pub(super) fn fixed_b64(value: &str, len: usize) -> Result<Vec<u8>> {
    if value.len() != len.div_ceil(3).checked_mul(4).ok_or(E::LimitExceeded)? {
        return Err(E::SchemaUnsupported);
    }
    let bytes = pybase64::b64decode_strict(value).map_err(|_| E::SchemaUnsupported)?;
    if bytes.len() != len || pybase64::b64encode(&bytes) != value {
        Err(E::SchemaUnsupported)
    } else {
        Ok(bytes)
    }
}
pub(super) fn record(value: &Value) -> Result<DeviceRecord> {
    for (key, length) in [("sign_pub", 32), ("agree_pub", 32), ("sig", 64)] {
        fixed_b64(text(value, key)?, length)?;
    }
    let record = DeviceRecord::from_dict(value).map_err(|_| E::StructureInvalid)?;
    if !record.verify_uncached() {
        return Err(E::SignatureInvalid);
    }
    Ok(record)
}
