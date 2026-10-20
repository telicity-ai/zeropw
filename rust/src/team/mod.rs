//! Port of `zeropw/team/`: the complete team-sharing stack.
//!
//! Data layer (docs/team-sync.md section 13, stage 1): device identity
//! (`identity`), DEK envelopes (`envelope`), signed commits (`commit`),
//! deterministic fold and local derivation (`fold`), human-readable rendering
//! (`humanview`). Networking and membership (later stages): the authenticated
//! session transport (`transport`, in-process and TCP), the replication /
//! monotone-fact runtime attached to a running context (`sync`), and
//! share/invite/join/remove flows (`membership`). Python behaviour is the
//! specification; recorded differences live in `rust/DEVIATIONS.md`.

pub mod commit;
pub mod envelope;
pub mod fold;
pub mod humanview;
pub mod identity;
pub mod membership;
pub mod sync;
pub mod transport;

use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};

use serde_json::Value;

/// Successful signature checks the team memo keeps before it starts over.
const VERIFIED_SIGNATURES_MAX: usize = 65_536;

/// Successful Ed25519 checks, keyed by a domain-separated, length-prefixed
/// SHA-256 of (key, message, signature). Failures are never stored, so
/// nothing that did not verify can read as verified; once `capacity`
/// successes are stored it starts over, which only costs a re-check.
struct VerifiedSignatures {
    capacity: usize,
    keys: Mutex<HashSet<[u8; 32]>>,
}

impl VerifiedSignatures {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            keys: Mutex::new(HashSet::new()),
        }
    }

    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        digest.update(b"zeropw-team-verified-signature-v1\0");
        for part in [public_key, message, signature] {
            digest.update((part.len() as u64).to_be_bytes());
            digest.update(part);
        }
        let key: [u8; 32] = digest.finalize().into();
        if self
            .keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&key)
        {
            return true;
        }
        if !crate::crypto::ed25519::verify(public_key, message, signature) {
            return false;
        }
        let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        if keys.len() >= self.capacity {
            keys.clear();
        }
        keys.insert(key);
        true
    }
}

/// Ed25519 verification for the device records and facts the team layer
/// checks again on every fold and fact load: receiving n facts verified
/// the same signatures O(n^2) times (issue #40). A success is remembered
/// for the exact (key, message, signature), so the outcome never differs
/// from [`crate::crypto::ed25519::verify`].
pub(crate) fn verify_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    static VERIFIED: LazyLock<VerifiedSignatures> =
        LazyLock::new(|| VerifiedSignatures::new(VERIFIED_SIGNATURES_MAX));
    VERIFIED.verify(public_key, message, signature)
}

/// Python truthiness of a parsed JSON value (`if not doc:` /
/// `entry.get("shared_env")` used as a condition, throughout `zeropw/team/`
/// and the modules it builds on): `None`, `false`, `0`/`0.0`, `""`, `[]`,
/// `{}` are all falsy. Mirrors `vault.rs`'s private `json_falsy` (not
/// reachable from here), duplicated because it is such a small, self
/// contained predicate that a cross-module `pub(crate)` seam would be more
/// machinery than the thing itself.
pub(crate) fn json_falsy(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_f64().map(|f| f == 0.0).unwrap_or(false),
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
    }
}

/// The environment ids that have a directory under `team/`, sorted.
pub(crate) fn local_env_ids(state: &crate::store::StateDir) -> crate::errors::Result<Vec<String>> {
    let listing_failed = |_| crate::errors::Error::state("state_corrupt");
    let team = state.path.join("team");
    if !team.is_dir() {
        return Ok(Vec::new());
    }
    let mut ids = Vec::new();
    for entry in std::fs::read_dir(&team).map_err(listing_failed)? {
        let entry = entry.map_err(listing_failed)?;
        let id = entry.file_name().to_string_lossy().into_owned();
        if commit::valid_env_id(&id) && entry.path().is_dir() {
            ids.push(id);
        }
    }
    ids.sort();
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::VerifiedSignatures;
    use crate::team::identity::DeviceKey;

    fn signing_key() -> (DeviceKey, Vec<u8>) {
        let key = DeviceKey::generate();
        let record = key.record().unwrap().to_dict();
        let public = crate::pybase64::b64decode_strict(record["sign_pub"].as_str().unwrap());
        (key, public.unwrap())
    }

    /// A remembered success never vouches for anything else, however often
    /// the other input is checked: another message, signature or key, the
    /// same bytes split differently between the inputs, or wrong lengths
    /// (issue #40).
    #[test]
    fn verified_signature_memo_is_exact() {
        let memo = VerifiedSignatures::new(16);
        let (key, public) = signing_key();
        let message = b"synthetic-team-message".to_vec();
        let signature = key.sign(&message).unwrap().to_vec();
        assert!(memo.verify(&public, &message, &signature));
        assert!(memo.verify(&public, &message, &signature));
        let flip = |bytes: &[u8]| {
            let mut out = bytes.to_vec();
            out[0] ^= 1;
            out
        };
        let joined = |a: &[u8], b: &[u8]| [a, b].concat();
        let (_, other) = signing_key();
        let (head, tail) = message.split_at(message.len() - 1);
        let rejected: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = vec![
            (public.clone(), flip(&message), signature.clone()),
            (public.clone(), message.clone(), flip(&signature)),
            (other, message.clone(), signature.clone()),
            (
                public.clone(),
                joined(&message, &signature[..1]),
                signature[1..].to_vec(),
            ),
            (public.clone(), head.to_vec(), joined(tail, &signature)),
            (public[..31].to_vec(), message.clone(), signature.clone()),
            (joined(&public, &[0]), message.clone(), signature.clone()),
            (public.clone(), message.clone(), signature[..63].to_vec()),
            (public.clone(), message.clone(), joined(&signature, &[0])),
        ];
        for (public, message, signature) in &rejected {
            for _ in 0..2 {
                assert!(!memo.verify(public, message, signature));
            }
        }
        assert_eq!(memo.keys.lock().unwrap().len(), 1);
    }

    /// Full, the memo starts over: every success is still a success.
    #[test]
    fn verified_signature_memo_starts_over_when_full() {
        let memo = VerifiedSignatures::new(2);
        let (key, public) = signing_key();
        let signed: Vec<(Vec<u8>, Vec<u8>)> = (0..3u8)
            .map(|n| {
                let message = vec![n; 8];
                let signature = key.sign(&message).unwrap().to_vec();
                (message, signature)
            })
            .collect();
        for (message, signature) in &signed {
            assert!(memo.verify(&public, message, signature));
        }
        assert_eq!(memo.keys.lock().unwrap().len(), 1);
        for (message, signature) in &signed {
            assert!(memo.verify(&public, message, signature));
        }
    }
}
