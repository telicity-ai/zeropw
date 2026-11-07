//! Private checked originals, bound to immutable M2a spans and local observations.
//! Authentication and history checks are separate private phases solely to keep
//! the legacy API's early scope-error precedence unchanged.
use super::admission::{
    CommitIndex, SemanticError as E, SemanticLocalInputs, component, device_copy, inventory_check,
    original_commit, require_device,
};
use super::manifest::{array, canonical, field, record, text};
use super::{CheckpointError, IntegrityCheckedPayload, ManifestAttestation, strict_json};
use crate::pyint::PyInt;
use crate::team::{
    commit::{self, Hlc},
    fold,
    identity::DeviceRecord,
    sync::{self, Fact},
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
type Result<T> = std::result::Result<T, E>;
const SCHEMA: E = E::Checkpoint(CheckpointError::SchemaUnsupported);
const SIGNATURE: E = E::Checkpoint(CheckpointError::SignatureInvalid);
const BINDING: E = E::Checkpoint(CheckpointError::BindingMismatch);
pub(super) struct AuthenticatedOriginals<'m, 'p, 'b> {
    pub(super) manifest: &'m ManifestAttestation,
    pub(super) payload: &'p IntegrityCheckedPayload<'b>,
    pub(super) local: &'m SemanticLocalInputs,
    pub(super) devices: BTreeMap<String, DeviceRecord>,
    pub(super) indices: Vec<CommitIndex>,
    pub(super) facts: BTreeMap<String, Fact>,
    pub(super) secret_ids: BTreeSet<String>,
    pub(super) connection_ids: BTreeSet<String>,
    pub(super) removal_claim: bool,
    slots: BTreeMap<(String, PyInt), (String, (PyInt, PyInt))>,
    authority: BTreeSet<String>,
    inits: usize,
    admissions: Vec<(String, usize)>,
}
impl<'m, 'p, 'b> AuthenticatedOriginals<'m, 'p, 'b> {
    pub(super) fn authenticate(
        manifest: &'m ManifestAttestation,
        payload: &'p IntegrityCheckedPayload<'b>,
        local: &'m SemanticLocalInputs,
    ) -> Result<Self> {
        let signed = &manifest.data.signed;
        let b = &local.bindings;
        let env = text(signed, "env_id")?;
        let recipient = text(signed, "recipient")?;
        if payload.manifest_hash != manifest.data.hash
            || b.manifest_hash != manifest.data.hash
            || b.env_id != env
            || b.recipient_record.fingerprint() != recipient
            || b.recipient_role.as_str() != text(signed, "recipient_role")?
            || b.approval_sha256 != text(signed, "approval_sha256")?
            || b.session_nonce != text(signed, "session_nonce")?
            || b.onboarding_nonce != text(signed, "onboarding_nonce")?
        {
            return Err(BINDING);
        }
        inventory_check(local)?;
        let mut devices = BTreeMap::new();
        for entry in array(component(payload, 0)?)? {
            let value = field(entry, "record")?;
            let device = record(value)?;
            if canonical(value)? != canonical(&device.to_dict())? {
                return Err(SCHEMA);
            }
            let fp = device.fingerprint();
            if text(entry, "fingerprint")? != fp || devices.insert(fp, device).is_some() {
                return Err(SCHEMA);
            }
        }
        if devices.get(recipient) != Some(&b.recipient_record)
            || devices.get(text(signed, "signer")?) != Some(&manifest.data.pinned)
        {
            return Err(BINDING);
        }
        let commits_component = component(payload, 2)?;
        let genesis = text(commits_component, "genesis_commit_hash")?;
        let owner = commit::env_owner_fingerprint(env).map_err(|_| SCHEMA)?;
        let mut indices = Vec::new();
        let mut slots = BTreeMap::new();
        let mut authority = BTreeSet::new();
        let mut inits = 0;
        let mut admissions = Vec::new();
        let mut secret_ids = BTreeSet::new();
        let mut connection_ids = BTreeSet::new();
        let mut removal_claim = false;
        for i in 0..payload.index.commits.len() {
            let commit = original_commit(payload, i)?;
            let hash = commit.hash().map_err(|_| SCHEMA)?;
            let author = devices.get(&commit.author).ok_or(E::AuthorityUnproven)?;
            if commit.env_id != env {
                return Err(BINDING);
            }
            commit::validate_ops(&commit.ops).map_err(|_| SCHEMA)?;
            if !commit::verify_commit(&commit, author) {
                return Err(SIGNATURE);
            }
            let hlc = Hlc::parse(&commit.hlc).map_err(|_| SCHEMA)?;
            if commit.author_seq <= 0
                || manifest
                    .data
                    .vector
                    .get(&commit.author)
                    .is_none_or(|s| commit.author_seq > *s)
                || slots
                    .insert(
                        (commit.author.clone(), commit.author_seq.clone()),
                        (hash.clone(), hlc.clone()),
                    )
                    .is_some()
            {
                return Err(E::SemanticMismatch);
            }
            for (op_index, op) in commit.ops.iter().enumerate() {
                let name = text(op, "op")?;
                removal_claim |= op.get("removal_fact_hash").is_some();
                if fold::checkpoint_authority_kind(name) {
                    authority.insert(hash.clone());
                }
                match name {
                    "env.init" => {
                        inits += 1;
                        if hash != genesis
                            || op_index != 0
                            || commit.author != owner
                            || commit.author_seq != 1
                            || device_copy(field(op, "owner_device")?, &devices)? != owner
                        {
                            return Err(E::AuthorityUnproven);
                        }
                    }
                    "member.add" => {
                        let fp = device_copy(field(op, "device")?, &devices)?;
                        if fp == recipient {
                            if text(op, "role")? != b.recipient_role.as_str() {
                                return Err(E::AuthorityUnproven);
                            }
                            admissions.push((hash.clone(), op_index));
                        }
                    }
                    "member.set_role" | "member.remove" | "owner.transfer" => {
                        require_device(&devices, text(op, "fingerprint")?)?
                    }
                    _ => {}
                }
                if matches!(name, "env.init" | "dek.rotate") {
                    for fp in field(op, "wraps")?.as_object().ok_or(SCHEMA)?.keys() {
                        require_device(&devices, fp)?;
                    }
                }
                if let Some(id) = op.get("secret_id").and_then(Value::as_str) {
                    secret_ids.insert(id.to_owned());
                }
                if name.starts_with("connection.")
                    && let Some(id) = op.get("id").and_then(Value::as_str)
                {
                    connection_ids.insert(id.to_owned());
                }
            }
            indices.push(CommitIndex {
                hash,
                author: commit.author,
                hlc,
                original_index: i,
            });
        }
        // Authenticate every original fact before interpreting removal scope or
        // applying any effect, including unsupported-but-signed removal facts.
        let mut facts = BTreeMap::new();
        for span in &payload.index.facts {
            let value = strict_json::materialize(span)?;
            let original = field(&value, "record")?;
            let fact = Fact::from_dict(original).map_err(|_| SCHEMA)?;
            if fact.env_id != env {
                return Err(BINDING);
            }
            let author = devices.get(&fact.author).ok_or(E::AuthorityUnproven)?;
            sync::validate_fact_target(&fact.kind, &fact.target).map_err(|_| SCHEMA)?;
            if canonical(original)? != fact.canonical_json(true).map_err(|_| SCHEMA)?
                || fact.hash().map_err(|_| SCHEMA)? != text(&value, "hash")?
            {
                return Err(E::SemanticMismatch);
            }
            if !sync::verify_fact(&fact, author) {
                return Err(SIGNATURE);
            }
            if let Some(fp) = fact.target.get("fingerprint").and_then(Value::as_str) {
                require_device(&devices, fp)?;
            }
            if let Some(id) = fact.target.get("secret_id").and_then(Value::as_str) {
                secret_ids.insert(id.to_owned());
            }
            if let Some(id) = fact.target.get("connection_id").and_then(Value::as_str) {
                connection_ids.insert(id.to_owned());
            }
            facts.insert(text(&value, "hash")?.to_owned(), fact);
        }
        Ok(Self {
            manifest,
            payload,
            local,
            devices,
            indices,
            facts,
            secret_ids,
            connection_ids,
            removal_claim,
            slots,
            authority,
            inits,
            admissions,
        })
    }
    pub(super) fn check_history(&self) -> Result<()> {
        let Self {
            manifest,
            payload,
            devices,
            indices,
            slots,
            authority,
            inits,
            admissions,
            ..
        } = self;
        let commits_component = component(payload, 2)?;
        let admission = text(commits_component, "recipient_admission_commit_hash")?;
        if *inits != 1 {
            return Err(E::HistoryProofUnavailable);
        }
        let declared: BTreeSet<_> =
            super::payload::hash_set(field(commits_component, "authority_commit_hashes")?)?
                .into_iter()
                .collect();
        if *authority != declared {
            return Err(E::HistoryProofUnavailable);
        }
        if admissions.len() != 1 || admissions.first().is_none_or(|(h, _)| h != admission) {
            return Err(E::AuthorityUnproven);
        }
        let mut previous: BTreeMap<&str, &(PyInt, PyInt)> = BTreeMap::new();
        for ((author, _), (_, hlc)) in slots {
            if previous.insert(author, hlc).is_some_and(|p| p >= hlc) {
                return Err(E::SemanticMismatch);
            }
        }
        for head in &manifest.data.heads {
            if slots.get(&(head.author.clone(), head.sequence.clone()))
                != Some(&(head.hash.clone(), head.hlc.clone()))
            {
                return Err(E::HistoryProofUnavailable);
            }
        }
        for index in indices {
            let c = original_commit(payload, index.original_index)?;
            for (fp, seq) in &c.seen {
                require_device(devices, fp)?;
                if *seq < 0
                    || manifest.data.vector.get(fp).is_none_or(|v| seq > v)
                    || (fp == &c.author && seq >= &c.author_seq)
                    || slots
                        .get(&(fp.clone(), seq.clone()))
                        .is_some_and(|(_, h)| h > &index.hlc)
                {
                    return Err(E::SemanticMismatch);
                }
            }
        }
        Ok(())
    }
    pub(super) fn complete_coverage(&self) -> Result<()> {
        let mut expected = BTreeMap::<&str, PyInt>::new();
        for (author, seq) in self.slots.keys() {
            let next = expected.entry(author).or_insert_with(|| PyInt::from(1));
            if seq != next {
                return Err(E::HistoryProofUnavailable);
            }
            *next = &*next + 1;
        }
        for (author, seq) in &self.manifest.data.vector {
            if *seq > 0
                && expected
                    .get(author.as_str())
                    .is_none_or(|next| next != &(seq + 1))
            {
                return Err(E::HistoryProofUnavailable);
            }
        }
        Ok(())
    }
}
