//! Finite checkpoint eligibility, never ordinary fact-admission authority.
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::admission::SemanticError as E;
use super::manifest::{canonical, field, text};
use crate::pyint::PyInt;
use crate::team::{
    commit::{Commit, Hlc},
    fold::{CheckpointCompleteTrace, Facts},
    sync::Fact,
};

type Result<T> = std::result::Result<T, E>;

pub(super) struct RemovalProof {
    pub bounds: BTreeMap<String, PyInt>,
    pub pending: Vec<((PyInt, PyInt), String)>,
    pub self_placed: BTreeSet<String>,
    pub witnesses: BTreeSet<String>,
    pub placements: BTreeMap<String, (String, usize)>,
    pub groups: BTreeMap<String, Vec<String>>,
}

impl RemovalProof {
    pub(super) fn compute(
        commits: &[Commit],
        facts: &BTreeMap<String, Fact>,
        effects: &Facts,
    ) -> Result<Self> {
        let mut groups = BTreeMap::<String, Vec<String>>::new();
        for (hash, fact) in facts.iter().filter(|(_, f)| f.kind == "member_removed") {
            groups
                .entry(text(&fact.target, "fingerprint")?.into())
                .or_default()
                .push(hash.clone());
        }
        for (target, hashes) in &groups {
            let mut by_self = false;
            let mut by_other = false;
            for hash in hashes {
                let fact = facts.get(hash).ok_or(E::FactContradicted)?;
                if &fact.author == target {
                    by_self = true;
                } else {
                    by_other = true;
                    if groups.contains_key(&fact.author) {
                        return Err(E::ScopeUnsupported);
                    }
                }
            }
            if by_self && by_other {
                return Err(E::ScopeUnsupported);
            }
        }
        // One bounded pass over all original op locations. Earliest means
        // author sequence, never input/hash/HLC order or another admin's repair.
        let mut rotations = BTreeMap::<String, (PyInt, String)>::new();
        let mut self_ops = BTreeMap::<String, (PyInt, String, usize)>::new();
        let mut seen = BTreeMap::<String, BTreeMap<String, PyInt>>::new();
        for c in commits {
            let hash = c.hash().map_err(|_| E::SemanticMismatch)?;
            seen.insert(hash.clone(), c.seen.clone());
            for (index, op) in c.ops.iter().enumerate() {
                if let Some(link) = op.get("removal_fact_hash") {
                    let linked = link
                        .as_str()
                        .and_then(|h| facts.get(h))
                        .ok_or(E::FactContradicted)?;
                    if linked.kind != "member_removed" || op["op"] != "dek.rotate" {
                        return Err(E::FactContradicted);
                    }
                    let target = text(&linked.target, "fingerprint")?;
                    if field(op, "wraps")?.get(target).is_some() {
                        return Err(E::FactContradicted);
                    }
                    if linked.author == c.author {
                        let key = link.as_str().ok_or(E::FactContradicted)?.to_owned();
                        if rotations
                            .get(&key)
                            .is_none_or(|(seq, _)| c.author_seq < *seq)
                        {
                            rotations.insert(key, (c.author_seq.clone(), hash.clone()));
                        }
                    }
                }
                if op["op"] == "member.remove" && op["fingerprint"] == c.author {
                    let key = c.author.clone();
                    if self_ops
                        .get(&key)
                        .is_none_or(|(seq, _, _)| c.author_seq < *seq)
                    {
                        self_ops.insert(key, (c.author_seq.clone(), hash.clone(), index));
                    }
                }
            }
        }
        let mut proof = Self {
            bounds: BTreeMap::new(),
            pending: Vec::new(),
            self_placed: BTreeSet::new(),
            witnesses: BTreeSet::new(),
            placements: BTreeMap::new(),
            groups,
        };
        for (target, hashes) in &proof.groups {
            let first = facts
                .get(hashes.first().ok_or(E::FactContradicted)?)
                .ok_or(E::FactContradicted)?;
            if &first.author == target {
                let (seq, hash, index) = self_ops.get(target).ok_or(E::HistoryProofUnavailable)?;
                proof.bounds.insert(target.clone(), seq.clone());
                proof.self_placed.insert(target.clone());
                proof.witnesses.insert(hash.clone());
                proof
                    .placements
                    .insert(target.clone(), (hash.clone(), *index));
            } else {
                let mut cut = None;
                let mut bound = None;
                for h in hashes {
                    let fact = facts.get(h).ok_or(E::FactContradicted)?;
                    let hlc = Hlc::parse(&fact.hlc).map_err(|_| E::FactContradicted)?;
                    if cut.as_ref().is_none_or(|old| hlc < *old) {
                        cut = Some(hlc);
                    }
                    let (_, witness) = rotations.get(h).ok_or(E::HistoryProofUnavailable)?;
                    let seq = seen
                        .get(witness)
                        .ok_or(E::HistoryProofUnavailable)?
                        .get(target)
                        .cloned()
                        .unwrap_or_else(PyInt::zero);
                    if bound.as_ref().is_none_or(|old| seq < *old) {
                        bound = Some(seq);
                    }
                    proof.witnesses.insert(witness.clone());
                }
                proof
                    .bounds
                    .insert(target.clone(), bound.ok_or(E::HistoryProofUnavailable)?);
                proof
                    .pending
                    .push((cut.ok_or(E::HistoryProofUnavailable)?, target.clone()));
            }
        }
        if effects
            .removed_members
            .iter()
            .any(|fp| !proof.groups.contains_key(fp))
        {
            return Err(E::FactContradicted);
        }
        proof.pending.sort();
        Ok(proof)
    }

    pub(super) fn compare_claims(
        &self,
        claims: &Value,
        vector: &BTreeMap<String, PyInt>,
    ) -> Result<()> {
        for (fp, bound) in &self.bounds {
            if vector.get(fp).is_some_and(|head| head > bound) {
                return Err(E::FactContradicted);
            }
        }
        let bounds: serde_json::Map<_, _> = self
            .bounds
            .iter()
            .map(|(fp, seq)| (fp.clone(), seq.value()))
            .collect();
        let pending: Vec<_> = self
            .pending
            .iter()
            .map(|((w, n), fp)| json!([w.value(), n.value(), fp]))
            .collect();
        let expected = json!({"bounds": bounds,"pending":pending,"self_placed":self.self_placed,"witness_commit_hashes":self.witnesses});
        if canonical(claims)? != canonical(&expected)? {
            return Err(E::SemanticMismatch);
        }
        Ok(())
    }

    pub(super) fn check_basis(
        &self,
        trace: &CheckpointCompleteTrace,
        facts: &BTreeMap<String, Fact>,
    ) -> Result<()> {
        if trace.bounds != self.bounds
            || trace.pending != self.pending
            || trace.self_placed != self.self_placed
        {
            return Err(E::SemanticMismatch);
        }
        for (target, hashes) in &self.groups {
            let standing = if let Some(placement) = self.placements.get(target) {
                let op = trace
                    .operations
                    .iter()
                    .find(|o| {
                        (&o.position.hash, o.position.op_index) == (&placement.0, placement.1)
                    })
                    .ok_or(E::HistoryProofUnavailable)?;
                if op.skipped.is_some() {
                    return Err(E::AuthorityUnproven);
                }
                trace
                    .self_standing
                    .get(placement)
                    .ok_or(E::HistoryProofUnavailable)?
            } else {
                trace
                    .pending_standing
                    .get(target)
                    .ok_or(E::HistoryProofUnavailable)?
            };
            if !standing.active.contains(target) || standing.owner.as_ref() == Some(target) {
                return Err(E::FactContradicted);
            }
            for hash in hashes {
                let f = facts.get(hash).ok_or(E::FactContradicted)?;
                if &f.author != target && !standing.admins.contains(&f.author) {
                    return Err(E::FactContradicted);
                }
            }
        }
        Ok(())
    }
}
