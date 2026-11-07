use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use serde_json::Value;

use super::manifest::{
    NAMES, array, bounded, canonical, field, fingerprint, fixed_b64, hash_text, hex_text, record,
    sha, text, uint, value_hash, vector,
};
use super::{CheckpointError as E, ManifestAttestation, Result, redacted_debug, strict_json};
use crate::{
    pyint::PyInt,
    team::{
        commit::{Commit, Hlc},
        identity::DeviceRecord,
        sync::Fact,
    },
};

/// One statelessly checked encrypted chunk. No transfer-order or staging proof.
/// ```compile_fail
/// use zeropw::team::checkpoint::CheckedChunk;
/// let proof = CheckedChunk {};
/// ```
pub struct CheckedChunk {
    index: usize,
    bytes: Vec<u8>,
}
impl CheckedChunk {
    pub fn index(&self) -> usize {
        self.index
    }
    pub fn encrypted_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub struct ComponentSpan<'a> {
    name: &'static str,
    span: strict_json::Span<'a>,
}
impl ComponentSpan<'_> {
    pub fn name(&self) -> &str {
        self.name
    }
    pub fn range(&self) -> Range<usize> {
        self.span.range()
    }
    pub fn original_bytes(&self) -> &[u8] {
        self.span.bytes()
    }
}
/// Integrity and enumerated structural references only. Original signatures,
/// authority, M1 targets, final overlay and import eligibility remain unproven.
/// ```compile_fail
/// use zeropw::team::checkpoint::IntegrityCheckedPayload;
/// let p: IntegrityCheckedPayload<'_> = serde_json::from_str("{}").unwrap();
/// ```
pub struct IntegrityCheckedPayload<'a> {
    pub(super) manifest_hash: String,
    pub(super) facts: Vec<String>,
    pub(super) tombstones: Vec<String>,
    components: Vec<ComponentSpan<'a>>,
    commits: Vec<String>,
}
impl IntegrityCheckedPayload<'_> {
    pub fn components(&self) -> &[ComponentSpan<'_>] {
        &self.components
    }
    pub fn canonical_commit_hashes(&self) -> &[String] {
        &self.commits
    }
    pub fn candidate_fact_hashes(&self) -> &[String] {
        &self.facts
    }
    pub fn candidate_tombstone_fact_hashes(&self) -> &[String] {
        &self.tombstones
    }
}
redacted_debug!(CheckedChunk, ComponentSpan<'_>, IntegrityCheckedPayload<'_>);

pub fn verify_chunk_frame_bytes(
    attestation: &ManifestAttestation,
    original_frame: &[u8],
) -> Result<CheckedChunk> {
    let frame = strict_json::chunk_frame(original_frame)?;
    if text(&frame, "type")? != "BOOTSTRAP_CHUNK" || uint(field(&frame, "v")?)? != 1 {
        return Err(E::SchemaUnsupported);
    }
    if text(&frame, "transfer_id")? != text(&attestation.data.signed, "transfer_id")?
        || text(&frame, "manifest_hash")? != attestation.data.hash
    {
        return Err(E::BindingMismatch);
    }
    let index = bounded(field(&frame, "index")?, 255)?;
    let descriptor = attestation
        .data
        .chunks
        .get(index)
        .ok_or(E::StructureInvalid)?;
    // Encoded length is checked before expansion. Strict decoder and exact
    // re-encoding reject whitespace, URL alphabet and noncanonical padding bits.
    let bytes = fixed_b64(text(&frame, "data_b64")?, descriptor.length)?;
    if sha(&bytes) != descriptor.hash {
        return Err(E::IntegrityMismatch);
    }
    Ok(CheckedChunk { index, bytes })
}

struct CommitSummary {
    author: String,
    sequence: PyInt,
    hlc: (PyInt, PyInt),
    wraps: BTreeMap<(usize, String), Vec<u8>>,
}

pub fn verify_payload_bytes<'a>(
    attestation: &ManifestAttestation,
    original_payload: &'a [u8],
) -> Result<IntegrityCheckedPayload<'a>> {
    let m = &attestation.data;
    if original_payload.len() != m.length || original_payload.len() > 16_777_216 {
        return Err(E::IntegrityMismatch);
    }
    if sha(original_payload) != text(field(&m.signed, "payload")?, "sha256")? {
        return Err(E::IntegrityMismatch);
    }
    for descriptor in &m.chunks {
        let start = descriptor
            .index
            .checked_mul(65_536)
            .ok_or(E::LimitExceeded)?;
        let end = start
            .checked_add(descriptor.length)
            .ok_or(E::LimitExceeded)?;
        if sha(original_payload
            .get(start..end)
            .ok_or(E::IntegrityMismatch)?)
            != descriptor.hash
        {
            return Err(E::IntegrityMismatch);
        }
    }
    // No JSON decoder, owned payload copy or size-derived reserve precedes the
    // signed whole/chunk raw integrity prerequisites above.
    let index = strict_json::payload(original_payload)?;
    let metadata = &index.metadata;
    if text(metadata, "format")? != "zeropw-team-bootstrap-payload-v1"
        || uint(field(metadata, "v")?)? != 1
    {
        return Err(E::SchemaUnsupported);
    }
    let env = text(&m.signed, "env_id")?;
    let signer = text(&m.signed, "signer")?;
    let recipient = text(&m.signed, "recipient")?;
    if text(metadata, "env_id")? != env {
        return Err(E::BindingMismatch);
    }
    if index.counts != m.counts {
        return Err(E::StructureInvalid);
    }
    let component_values = array(field(metadata, "components")?)?;
    if component_values.len() != 6 || m.components.len() != 6 {
        return Err(E::SchemaUnsupported);
    }
    let mut data = Vec::new();
    for (i, component) in component_values.iter().enumerate() {
        if text(component, "name")? != NAMES.get(i).copied().ok_or(E::SchemaUnsupported)? {
            return Err(E::SchemaUnsupported);
        }
        let span = index.components.get(i).ok_or(E::StructureInvalid)?;
        let descriptor = m.components.get(i).ok_or(E::StructureInvalid)?;
        if span.bytes().len() != descriptor.length || sha(span.bytes()) != descriptor.hash {
            return Err(E::IntegrityMismatch);
        }
        data.push(field(component, "data")?);
    }
    let devices = devices(data.first().copied().ok_or(E::SchemaUnsupported)?)?;
    let known = |fp: &str| {
        if devices.contains_key(fp) {
            Ok(())
        } else {
            Err(E::StructureInvalid)
        }
    };
    for fp in [
        signer,
        recipient,
        env.split_once('-').ok_or(E::StructureInvalid)?.0,
    ] {
        known(fp)?;
    }
    if devices.get(signer) != Some(&m.pinned) {
        return Err(E::BindingMismatch);
    }
    for fp in m.vector.keys() {
        known(fp)?;
    }
    let snapshot = data.get(1).copied().ok_or(E::SchemaUnsupported)?;
    let document = field(snapshot, "document")?;
    if text(document, "format")? != "zeropw-team-env-v1" || text(document, "env_id")? != env {
        return Err(E::StructureInvalid);
    }
    if vector(field(snapshot, "vector")?)? != m.vector
        || text(snapshot, "expected_final_document_sha256")?
            != text(&m.signed, "expected_final_document_sha256")?
    {
        return Err(E::StructureInvalid);
    }
    // document.secrets/version records and version_order shape were validated
    // without constructing their trees. The original spans preserve all bytes.
    let commit_component = data.get(2).copied().ok_or(E::SchemaUnsupported)?;
    let fact_component = data.get(3).copied().ok_or(E::SchemaUnsupported)?;
    let mut commits = BTreeMap::new();
    let mut sequences = BTreeSet::new();
    let mut previous = String::new();
    for span in &index.commits {
        let envelope = strict_json::materialize(span)?;
        let hash = hash_text(text(&envelope, "hash")?)?;
        if hash <= previous.as_str() {
            return Err(E::StructureInvalid);
        }
        let value = field(&envelope, "record")?;
        if text(value, "format")? != "zeropw-team-commit-v1" || text(value, "env_id")? != env {
            return Err(E::StructureInvalid);
        }
        for key in ["author", "hlc", "sig"] {
            text(value, key)?;
        }
        let seq = uint(field(value, "author_seq")?)?;
        if seq <= 0 {
            return Err(E::StructureInvalid);
        }
        let seen = vector(field(value, "seen")?)?;
        for fp in seen.keys() {
            known(fp)?;
        }
        if array(field(value, "ops")?)?
            .iter()
            .any(|op| !op.is_object())
        {
            return Err(E::StructureInvalid);
        }
        let commit = Commit::from_dict(value).map_err(|_| E::StructureInvalid)?;
        if canonical(value)?
            != commit
                .canonical_json(true)
                .map_err(|_| E::StructureInvalid)?
            || commit.hash().map_err(|_| E::StructureInvalid)? != hash
        {
            return Err(E::IntegrityMismatch);
        }
        known(&commit.author)?;
        if !sequences.insert((commit.author.clone(), seq.clone())) {
            return Err(E::StructureInvalid);
        }
        let head = m
            .heads
            .iter()
            .find(|h| h.author == commit.author)
            .ok_or(E::StructureInvalid)?;
        let hlc = Hlc::parse(&commit.hlc).map_err(|_| E::StructureInvalid)?;
        if m.vector
            .get(&commit.author)
            .is_none_or(|limit| seq > *limit)
            || hlc > head.hlc
        {
            return Err(E::StructureInvalid);
        }
        let wraps = selected_wraps(&commit, recipient)?;
        commits.insert(
            hash.to_owned(),
            CommitSummary {
                author: commit.author,
                sequence: seq,
                hlc,
                wraps,
            },
        );
        previous = hash.into();
    }
    for head in &m.heads {
        let record = commits.get(&head.hash).ok_or(E::StructureInvalid)?;
        if record.author != head.author
            || record.sequence != head.sequence
            || record.hlc != head.hlc
        {
            return Err(E::StructureInvalid);
        }
    }
    for key in ["genesis_commit_hash", "recipient_admission_commit_hash"] {
        let hash = hash_text(text(commit_component, key)?)?;
        if !commits.contains_key(hash) {
            return Err(E::StructureInvalid);
        }
    }
    if text(commit_component, "recipient_admission_commit_hash")?
        != text(&m.signed, "recipient_admission_commit_hash")?
    {
        return Err(E::StructureInvalid);
    }
    for hash in hash_set(field(commit_component, "authority_commit_hashes")?)? {
        if !commits.contains_key(&hash) {
            return Err(E::StructureInvalid);
        }
    }
    let mut facts = Vec::new();
    let mut tombstones = Vec::new();
    previous.clear();
    for span in &index.facts {
        let envelope = strict_json::materialize(span)?;
        let hash = hash_text(text(&envelope, "hash")?)?;
        if hash <= previous.as_str() {
            return Err(E::StructureInvalid);
        }
        let value = field(&envelope, "record")?;
        if text(value, "format")? != "zeropw-team-fact-v1"
            || text(value, "env_id")? != env
            || !field(value, "target")?.is_object()
        {
            return Err(E::StructureInvalid);
        }
        for key in ["kind", "author", "hlc", "sig"] {
            text(value, key)?;
        }
        let kind = text(value, "kind")?;
        if ![
            "incident",
            "connection_disabled",
            "secret_version_revoked",
            "member_removed",
            "secret_deleted",
        ]
        .contains(&kind)
        {
            return Err(E::SchemaUnsupported);
        }
        known(text(value, "author")?)?;
        Hlc::parse(text(value, "hlc")?).map_err(|_| E::StructureInvalid)?;
        let fact = Fact::from_dict(value).map_err(|_| E::StructureInvalid)?;
        if canonical(value)? != fact.canonical_json(true).map_err(|_| E::StructureInvalid)?
            || fact.hash().map_err(|_| E::StructureInvalid)? != hash
        {
            return Err(E::IntegrityMismatch);
        }
        facts.push(hash.into());
        if kind == "secret_deleted" {
            tombstones.push(hash.into());
        }
        previous = hash.into();
    }
    if hash_set(field(fact_component, "admitted_fact_hashes")?)? != facts
        || hash_set(field(fact_component, "tombstone_fact_hashes")?)? != tombstones
    {
        return Err(E::StructureInvalid);
    }
    if value_hash(&Value::Array(
        facts.iter().cloned().map(Value::String).collect(),
    ))? != text(&m.signed, "admitted_fact_hashes_sha256")?
        || value_hash(&Value::Array(
            tombstones.iter().cloned().map(Value::String).collect(),
        ))? != text(&m.signed, "tombstone_digest")?
    {
        return Err(E::IntegrityMismatch);
    }
    removals(
        data.get(4).copied().ok_or(E::SchemaUnsupported)?,
        &devices,
        &commits,
    )?;
    recipient_wraps(
        data.get(5).copied().ok_or(E::SchemaUnsupported)?,
        &index.wraps,
        recipient,
        &commits,
    )?;
    Ok(IntegrityCheckedPayload {
        manifest_hash: m.hash.clone(),
        facts,
        tombstones,
        commits: commits.into_keys().collect(),
        components: index
            .components
            .into_iter()
            .enumerate()
            .map(|(i, span)| ComponentSpan {
                name: NAMES[i],
                span,
            })
            .collect(),
    })
}

fn devices(value: &Value) -> Result<BTreeMap<String, DeviceRecord>> {
    let values = array(value)?;
    if values.len() > 256 {
        return Err(E::LimitExceeded);
    }
    let mut devices = BTreeMap::new();
    let mut previous = "";
    for value in values {
        let fp = text(value, "fingerprint")?;
        if !fingerprint(fp) || fp <= previous {
            return Err(E::StructureInvalid);
        }
        let record = record(field(value, "record")?)?;
        if record.fingerprint() != fp {
            return Err(E::StructureInvalid);
        }
        devices.insert(fp.to_owned(), record);
        previous = fp;
    }
    Ok(devices)
}

pub(super) fn hash_set(value: &Value) -> Result<Vec<String>> {
    string_set(value, |s| hex_text(s, 64), usize::MAX)
}
fn string_set(value: &Value, valid: fn(&str) -> bool, max: usize) -> Result<Vec<String>> {
    let values = array(value)?;
    if values.len() > max {
        return Err(E::LimitExceeded);
    }
    let mut result = Vec::new();
    let mut previous = "";
    for value in values {
        let value = value.as_str().ok_or(E::SchemaUnsupported)?;
        if !valid(value) || value <= previous {
            return Err(E::StructureInvalid);
        }
        result.push(value.into());
        previous = value;
    }
    Ok(result)
}
fn token(value: &str) -> bool {
    (16..=64).contains(&value.len()) && hex_text(value, value.len())
}
fn removals(
    value: &Value,
    devices: &BTreeMap<String, DeviceRecord>,
    commits: &BTreeMap<String, CommitSummary>,
) -> Result<()> {
    for fp in vector(field(value, "bounds")?)?.keys() {
        if !devices.contains_key(fp) {
            return Err(E::StructureInvalid);
        }
    }
    let mut pending = BTreeSet::new();
    let mut previous = None;
    for item in array(field(value, "pending")?)? {
        let item = array(item)?;
        if item.len() != 3 {
            return Err(E::StructureInvalid);
        }
        let wall = uint(item.first().ok_or(E::StructureInvalid)?)?;
        let counter = uint(item.get(1).ok_or(E::StructureInvalid)?)?;
        let fp = item
            .get(2)
            .and_then(Value::as_str)
            .ok_or(E::StructureInvalid)?;
        let key = (wall, counter, fp.to_owned());
        if !devices.contains_key(fp)
            || !pending.insert(fp.to_owned())
            || previous.as_ref().is_some_and(|p| p >= &key)
        {
            return Err(E::StructureInvalid);
        }
        previous = Some(key);
    }
    for fp in string_set(field(value, "self_placed")?, fingerprint, 256)? {
        if !devices.contains_key(&fp) || pending.contains(&fp) {
            return Err(E::StructureInvalid);
        }
    }
    for hash in hash_set(field(value, "witness_commit_hashes")?)? {
        if !commits.contains_key(&hash) {
            return Err(E::StructureInvalid);
        }
    }
    Ok(())
}

fn selected_wraps(commit: &Commit, recipient: &str) -> Result<BTreeMap<(usize, String), Vec<u8>>> {
    let mut selected = BTreeMap::new();
    for (i, op) in commit.ops.iter().enumerate() {
        match op.get("op").and_then(Value::as_str) {
            Some("member.add") => {
                if let Some(device) = op
                    .get("device")
                    .and_then(|v| DeviceRecord::from_dict(v).ok())
                    && device.fingerprint() == recipient
                    && let Some(wraps) = op.get("wraps").and_then(Value::as_object)
                {
                    for (generation, wrap) in wraps {
                        selected.insert((i, generation.clone()), canonical(wrap)?);
                    }
                }
            }
            Some("env.init" | "dek.rotate") => {
                if let (Some(generation), Some(wrap)) = (
                    op.get("generation_id").and_then(Value::as_str),
                    op.get("wraps").and_then(|v| v.get(recipient)),
                ) {
                    selected.insert((i, generation.into()), canonical(wrap)?);
                }
            }
            _ => {}
        }
    }
    Ok(selected)
}
fn recipient_wraps(
    value: &Value,
    spans: &[strict_json::Span<'_>],
    recipient: &str,
    commits: &BTreeMap<String, CommitSummary>,
) -> Result<()> {
    let unavailable = string_set(field(value, "unavailable_generations")?, token, usize::MAX)?;
    let mut generations = BTreeSet::new();
    let mut previous = None;
    for span in spans {
        let value = strict_json::materialize(span)?;
        let generation = text(&value, "generation_id")?;
        let source = hash_text(text(&value, "source_commit_hash")?)?;
        let op_index = bounded(field(&value, "source_op_index")?, 16_777_216)?;
        if !token(generation) || text(&value, "recipient")? != recipient {
            return Err(E::StructureInvalid);
        }
        let key = (generation.to_owned(), source.to_owned(), op_index);
        if previous.as_ref().is_some_and(|p| p >= &key) {
            return Err(E::StructureInvalid);
        }
        let wrap = field(&value, "wrap")?;
        for name in ["eph_pub", "nonce", "ciphertext"] {
            text(wrap, name)?;
        }
        let source_wrap = commits
            .get(source)
            .and_then(|c| c.wraps.get(&(op_index, generation.to_owned())))
            .ok_or(E::StructureInvalid)?;
        if *source_wrap != canonical(wrap)? {
            return Err(E::StructureInvalid);
        }
        generations.insert(generation.to_owned());
        previous = Some(key);
    }
    if unavailable.iter().any(|g| generations.contains(g)) {
        return Err(E::StructureInvalid);
    }
    Ok(())
}
