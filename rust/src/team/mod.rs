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
use std::sync::{Mutex, OnceLock};

use serde_json::Value;

/// Successful signature checks the memo below keeps before it starts over.
const VERIFIED_SIGNATURES_MAX: usize = 65_536;

/// Ed25519 verification for the team layer's device records, facts,
/// commits and fact admissions. Every fold re-checks each admitted device
/// record and every fact load each fact, so receiving n facts verified the
/// same signatures O(n^2) times (issue #40). A success for the exact same
/// (key, message, signature) is remembered for the life of the process;
/// failures are not, and the memo is keyed by a domain-separated SHA-256 of
/// all three inputs, so nothing that did not verify can ever read as
/// verified.
pub(crate) fn verify_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use sha2::{Digest, Sha256};
    static VERIFIED: OnceLock<Mutex<HashSet<[u8; 32]>>> = OnceLock::new();
    let mut digest = Sha256::new();
    digest.update(b"zeropw-team-verified-signature-v1\0");
    for part in [public_key, message, signature] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    let key: [u8; 32] = digest.finalize().into();
    let verified = VERIFIED.get_or_init(|| Mutex::new(HashSet::new()));
    if verified
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&key)
    {
        return true;
    }
    if !crate::crypto::ed25519::verify(public_key, message, signature) {
        return false;
    }
    let mut verified = verified.lock().unwrap_or_else(|e| e.into_inner());
    if verified.len() >= VERIFIED_SIGNATURES_MAX {
        verified.clear();
    }
    verified.insert(key);
    true
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

#[cfg(test)]
mod tests {
    use super::verify_signature;
    use crate::team::identity::DeviceKey;

    /// A remembered success never vouches for a different key, message or
    /// signature (issue #40).
    #[test]
    fn verified_signature_memo_is_exact() {
        let key = DeviceKey::generate();
        let record = key.record().unwrap();
        let message = b"synthetic-team-message".to_vec();
        let signature = key.sign(&message).unwrap();
        let public = record.to_dict()["sign_pub"].as_str().unwrap().to_owned();
        let public = crate::pybase64::b64decode_strict(&public).unwrap();
        assert!(verify_signature(&public, &message, &signature));
        assert!(verify_signature(&public, &message, &signature));
        let mut other_message = message.clone();
        other_message[0] ^= 1;
        assert!(!verify_signature(&public, &other_message, &signature));
        let mut other_signature = signature;
        other_signature[0] ^= 1;
        assert!(!verify_signature(&public, &message, &other_signature));
        let other = DeviceKey::generate().record().unwrap().to_dict();
        let other = crate::pybase64::b64decode_strict(other["sign_pub"].as_str().unwrap()).unwrap();
        assert!(!verify_signature(&other, &message, &signature));
    }
}
