//! Secret-holding byte buffers.
//!
//! The Python prototype documents that `bytes` cannot be zeroised. The Rust
//! port holds every raw secret (vault values, DEKs, KMS master key, Ed25519
//! seeds, admin-derived keys) in [`SecretBytes`]: memory is wiped on drop,
//! `Debug` is redacted, and there is deliberately no `Display` or
//! `Serialize`, so a secret cannot reach a log, error, JSON response or
//! audit record without an explicit, greppable `.expose()` call.

use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Clone, Default)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretBytes(Zeroizing::new(bytes))
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        SecretBytes::new(bytes.to_vec())
    }

    /// Borrow the raw secret. Every call site is a trust-boundary decision.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Constant-time equality.
    pub fn ct_eq(&self, other: &[u8]) -> bool {
        self.0.len() == other.len() && bool::from(self.0.as_slice().ct_eq(other))
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        SecretBytes::new(bytes)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(<redacted {} bytes>)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = SecretBytes::from_slice(b"hunter2");
        assert_eq!(format!("{s:?}"), "SecretBytes(<redacted 7 bytes>)");
        assert!(s.ct_eq(b"hunter2"));
        assert!(!s.ct_eq(b"hunter3"));
        assert!(!s.ct_eq(b"hunter"));
    }
}
