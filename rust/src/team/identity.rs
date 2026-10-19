//! Port of `zeropw/team/identity.py`: device identity (Ed25519 signing key +
//! X25519 agreement key), docs/team-sync.md section 4.1.
//!
//! A device key is the node's identity for team sync: an Ed25519 seed used
//! to sign commits, and an X25519 private scalar used to agree on
//! per-recipient DEK wraps (`zeropw/team/envelope.py`, `envelope.rs`). Both
//! secrets are wrapped by the local `Kms` (never stored in the clear) at
//! `team/device.key` (0600, via `StateDir`). There is no export function for
//! either private key: the only operations this module offers on a loaded
//! `DeviceKey` are deriving its public `DeviceRecord`, computing its
//! fingerprint, and signing/agreeing.

use serde_json::{Map, Value};

use crate::crypto::{ed25519, x25519};
use crate::errors::{Error, Result};
use crate::kms::{Kms, WrappedKey};
use crate::pybase64;
use crate::secret::SecretBytes;
use crate::store::StateDir;

use super::json_falsy;

/// `zeropw.team.identity.DEVICE_KEY_FILE`.
pub const DEVICE_KEY_FILE: &str = "team/device.key";

/// `zeropw.team.identity.DEVICE_RECORD_CONTEXT`: domain-separation context
/// for the device record signature -- the signing key signs "this X25519 key
/// belongs to me".
pub const DEVICE_RECORD_CONTEXT: &[u8] = b"zeropw-team-device-v1";

/// `zeropw.team.identity.FINGERPRINT_SOURCE_BYTES`: `SHA-256(sign_pub)[:16]`,
/// base32-encoded (docs/team-sync.md section 3).
pub const FINGERPRINT_SOURCE_BYTES: usize = 16;

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// `base64.b32encode(raw).decode("ascii").rstrip("=").lower()`: lowercase,
/// unpadded RFC 4648 base32. Implemented by hand (no `base32` crate
/// dependency) since this crate only ever needs the encode direction, for a
/// fixed 16-byte input, and the padding characters Python strips are simply
/// never emitted here rather than emitted-then-stripped.
fn b32_lower_unpadded(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    for &byte in data {
        bits = (bits << 8) | byte as u32;
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            let idx = ((bits >> bit_count) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bit_count > 0 {
        let idx = ((bits << (5 - bit_count)) & 0x1f) as usize;
        out.push(BASE32_ALPHABET[idx] as char);
    }
    out.make_ascii_lowercase();
    out
}

fn b64e(raw: &[u8]) -> String {
    pybase64::b64encode(raw)
}

fn b64d(text: &str) -> std::result::Result<Vec<u8>, ()> {
    pybase64::b64decode(text).map_err(|_| ())
}

/// The public half of a device key, plus the binding signature
/// (docs/team-sync.md section 4.1). Port of `zeropw.team.identity.DeviceRecord`.
///
/// `sig` is the Ed25519 signature by `sign_pub` over
/// `DEVICE_RECORD_CONTEXT + agree_pub`, binding the agreement key to the
/// signing identity so a third party cannot substitute their own X25519 key
/// under someone else's fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRecord {
    pub sign_pub: [u8; ed25519::PUBLIC_KEY_SIZE],
    pub agree_pub: [u8; x25519::POINT_SIZE],
    pub sig: [u8; ed25519::SIGNATURE_SIZE],
}

impl DeviceRecord {
    /// `DeviceRecord(sign_pub, agree_pub, sig)`: `__post_init__` validates
    /// the three lengths, all folded into one `device_record_malformed`
    /// reason exactly as Python's three separate `raise InvalidInput(...)`
    /// calls each do.
    pub fn new(sign_pub: &[u8], agree_pub: &[u8], sig: &[u8]) -> Result<Self> {
        let bad = || Error::invalid_input("device_record_malformed");
        let sign_pub: [u8; ed25519::PUBLIC_KEY_SIZE] = sign_pub.try_into().map_err(|_| bad())?;
        let agree_pub: [u8; x25519::POINT_SIZE] = agree_pub.try_into().map_err(|_| bad())?;
        let sig: [u8; ed25519::SIGNATURE_SIZE] = sig.try_into().map_err(|_| bad())?;
        Ok(DeviceRecord {
            sign_pub,
            agree_pub,
            sig,
        })
    }

    /// `DeviceRecord.verify`: true iff `sig` really binds `agree_pub` to
    /// `sign_pub`. Never raises (Ed25519 `verify` never raises either).
    pub fn verify(&self) -> bool {
        let mut message = Vec::with_capacity(DEVICE_RECORD_CONTEXT.len() + self.agree_pub.len());
        message.extend_from_slice(DEVICE_RECORD_CONTEXT);
        message.extend_from_slice(&self.agree_pub);
        super::verify_signature(&self.sign_pub, &message, &self.sig)
    }

    /// `DeviceRecord.fingerprint`: lowercase, unpadded base32 of
    /// `SHA-256(sign_pub)[:16]` (docs/team-sync.md section 3).
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(self.sign_pub);
        b32_lower_unpadded(&digest[..FINGERPRINT_SOURCE_BYTES])
    }

    /// `DeviceRecord.to_dict`.
    pub fn to_dict(&self) -> Value {
        let mut m = Map::new();
        m.insert("sign_pub".into(), Value::String(b64e(&self.sign_pub)));
        m.insert("agree_pub".into(), Value::String(b64e(&self.agree_pub)));
        m.insert("sig".into(), Value::String(b64e(&self.sig)));
        Value::Object(m)
    }

    /// `DeviceRecord.from_dict`: `KeyError | TypeError | ValueError` (a
    /// missing field, or invalid base64/wrong-length bytes after coercion)
    /// all become `InvalidInput("device_record_malformed")`.
    ///
    /// Finding H-R4-1: Python's `_b64d(str(data["sign_pub"]))` (and
    /// likewise for `agree_pub`/`sig`) applies `str(...)` to whatever JSON
    /// value is present -- not just an already-string one -- before the
    /// lenient `base64.b64decode`. A peer-supplied `sign_pub` shaped as a
    /// one-element array of the base64 text, `["<b64>"]`, therefore still
    /// decodes to the correct bytes in Python: `str(["<b64>"])` yields
    /// `"['<b64>']"`, and the lenient decoder discards the brackets/quotes
    /// as non-alphabet characters. Requiring `data[key]` to already be a
    /// JSON string (as this used to) rejects that op outright and then
    /// rejects every later commit from the same author as a permanent
    /// `team_seq_gap`, a real accept/reject divergence from a peer this
    /// node's own key never authenticated (§3.7 does not apply to commit
    /// fields -- coordinator ruling). [`python_str_coerce`] is the crate's
    /// one canonical `str(...)` coercion (PORTING.md §3b; shared with
    /// `commit.rs`'s `Commit::from_dict`), reused here rather than
    /// re-implemented.
    pub fn from_dict(data: &Value) -> Result<Self> {
        let bad = || Error::invalid_input("device_record_malformed");
        let obj = data.as_object().ok_or_else(bad)?;
        let field = |key: &str| -> Result<Vec<u8>> {
            let v = obj.get(key).ok_or_else(bad)?;
            let s = super::commit::python_str_coerce(v);
            b64d(&s).map_err(|_| bad())
        };
        let sign_pub = field("sign_pub")?;
        let agree_pub = field("agree_pub")?;
        let sig = field("sig")?;
        DeviceRecord::new(&sign_pub, &agree_pub, &sig)
    }
}

/// A node's private device identity. Never serialised or logged directly.
/// Port of `zeropw.team.identity.DeviceKey`.
///
/// Holds both secrets as `SecretBytes` (PORTING.md §3.2): this is where a
/// device's Ed25519 seed and X25519 private scalar live in memory, mirroring
/// how `crypto::ed25519::generate_seed` / `crypto::x25519::generate_private`
/// already return them wrapped.
///
/// `Debug` is derived, not banned: `sign_seed`/`agree_private`'s own `Debug`
/// (`SecretBytes`) is already redacted, so deriving here cannot leak either
/// key (mirrors `kms.rs`'s `LocalFileKms`, PORTING.md §3.2).
#[derive(Clone, Debug)]
pub struct DeviceKey {
    pub sign_seed: SecretBytes,
    pub agree_private: SecretBytes,
}

impl DeviceKey {
    /// `DeviceKey.generate`.
    pub fn generate() -> DeviceKey {
        DeviceKey {
            sign_seed: ed25519::generate_seed(),
            agree_private: x25519::generate_private(),
        }
    }

    /// `DeviceKey.record` (a property in Python). The only way this can fail
    /// is if `sign_seed`/`agree_private` are not exactly `SEED_SIZE`/
    /// `SCALAR_SIZE` bytes -- an invariant every constructor below already
    /// enforces, so this is unreachable in practice; it still returns a
    /// `Result` rather than panicking, per PORTING.md's engineering rules.
    pub fn record(&self) -> Result<DeviceRecord> {
        let corrupt = || Error::state("device_key_corrupt");
        let sign_pub =
            ed25519::public_key_from_seed(self.sign_seed.expose()).map_err(|_| corrupt())?;
        let agree_pub = x25519::public_key(self.agree_private.expose()).map_err(|_| corrupt())?;
        let mut message = Vec::with_capacity(DEVICE_RECORD_CONTEXT.len() + agree_pub.len());
        message.extend_from_slice(DEVICE_RECORD_CONTEXT);
        message.extend_from_slice(&agree_pub);
        let sig = ed25519::sign(self.sign_seed.expose(), &message).map_err(|_| corrupt())?;
        DeviceRecord::new(&sign_pub, &agree_pub, &sig)
    }

    /// `DeviceKey.fingerprint` (a property in Python: `self.record.fingerprint`).
    pub fn fingerprint(&self) -> Result<String> {
        Ok(self.record()?.fingerprint())
    }

    /// `DeviceKey.sign`.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; ed25519::SIGNATURE_SIZE]> {
        ed25519::sign(self.sign_seed.expose(), message)
            .map_err(|_| Error::state("device_key_corrupt"))
    }

    // --------------------------------------------------------- persistence
    /// `DeviceKey.create`: `team init` -- generate and persist a device key.
    /// Refuses if one already exists.
    pub fn create(state: &StateDir, kms: &(dyn Kms + Send + Sync)) -> Result<DeviceKey> {
        if state.exists(DEVICE_KEY_FILE) {
            return Err(Error::state("device_key_exists"));
        }
        let device = DeviceKey::generate();
        let _lock = state.lock()?;
        if state.exists(DEVICE_KEY_FILE) {
            return Err(Error::state("device_key_exists"));
        }
        let sign_wrapped = kms.wrap(device.sign_seed.expose())?;
        let agree_wrapped = kms.wrap(device.agree_private.expose())?;
        let mut doc = Map::new();
        doc.insert("sign_seed".into(), sign_wrapped.to_dict());
        doc.insert("agree_private".into(), agree_wrapped.to_dict());
        state.write_json(DEVICE_KEY_FILE, &Value::Object(doc))?;
        Ok(device)
    }

    /// `DeviceKey.load`.
    pub fn load(state: &StateDir, kms: &(dyn Kms + Send + Sync)) -> Result<DeviceKey> {
        let doc = state.read_json(DEVICE_KEY_FILE, Value::Null)?;
        if json_falsy(&doc) {
            return Err(Error::state("device_key_missing"));
        }
        let corrupt = || Error::state("device_key_corrupt");
        let obj = doc.as_object().ok_or_else(corrupt)?;
        let sign_wrap = WrappedKey::from_dict(obj.get("sign_seed").ok_or_else(corrupt)?)
            .map_err(|_| corrupt())?;
        let agree_wrap = WrappedKey::from_dict(obj.get("agree_private").ok_or_else(corrupt)?)
            .map_err(|_| corrupt())?;
        let sign_seed = kms.unwrap(&sign_wrap).map_err(|_| corrupt())?;
        let agree_private = kms.unwrap(&agree_wrap).map_err(|_| corrupt())?;
        if sign_seed.len() != ed25519::SEED_SIZE || agree_private.len() != x25519::SCALAR_SIZE {
            return Err(corrupt());
        }
        Ok(DeviceKey {
            sign_seed,
            agree_private,
        })
    }

    /// `DeviceKey.load_or_create`.
    pub fn load_or_create(state: &StateDir, kms: &(dyn Kms + Send + Sync)) -> Result<DeviceKey> {
        if state.exists(DEVICE_KEY_FILE) {
            DeviceKey::load(state, kms)
        } else {
            DeviceKey::create(state, kms)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorClass;
    use crate::kms::LocalFileKms;
    use tempfile::TempDir;

    fn new_state() -> (TempDir, StateDir) {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        (tmp, state)
    }

    fn new_kms(tmp: &TempDir) -> LocalFileKms {
        LocalFileKms::create_default(&tmp.path().join("state/kms/master.key")).unwrap()
    }

    #[test]
    fn generate_and_record_roundtrip() {
        let device = DeviceKey::generate();
        let record = device.record().unwrap();
        assert!(record.verify());
        assert_eq!(record.fingerprint(), device.fingerprint().unwrap());
        let fp = record.fingerprint();
        assert_eq!(fp, fp.to_lowercase());
        assert!(
            fp.chars()
                .all(|c| "abcdefghijklmnopqrstuvwxyz234567".contains(c))
        );
        assert_eq!(fp.len(), 26);
    }

    #[test]
    fn record_roundtrips_through_dict() {
        let device = DeviceKey::generate();
        let record = device.record().unwrap();
        let restored = DeviceRecord::from_dict(&record.to_dict()).unwrap();
        assert_eq!(restored, record);
        assert!(restored.verify());
    }

    #[test]
    fn tampered_agree_pub_fails_verification() {
        let device = DeviceKey::generate();
        let record = device.record().unwrap();
        let other_agree = DeviceKey::generate().record().unwrap().agree_pub;
        let forged = DeviceRecord {
            sign_pub: record.sign_pub,
            agree_pub: other_agree,
            sig: record.sig,
        };
        assert!(!forged.verify());
    }

    #[test]
    fn malformed_record_dict_rejected() {
        let bad1 = serde_json::json!({"sign_pub": "not-base64!!", "agree_pub": "x", "sig": "y"});
        assert!(DeviceRecord::from_dict(&bad1).is_err());
        let bad2 = serde_json::json!({"sign_pub": "AAAA", "agree_pub": "AAAA", "sig": "AAAA"});
        assert!(DeviceRecord::from_dict(&bad2).is_err());
    }

    #[test]
    fn create_persists_wrapped_and_no_export() {
        let (tmp, state) = new_state();
        let kms = new_kms(&tmp);
        let device = DeviceKey::create(&state, &kms).unwrap();
        let raw = std::fs::read_to_string(state.path.join("team/device.key")).unwrap();
        assert!(!raw.contains(&hex::encode(device.sign_seed.expose())));
        assert!(!raw.contains(&hex::encode(device.agree_private.expose())));
        let loaded = DeviceKey::load(&state, &kms).unwrap();
        assert_eq!(loaded.sign_seed.expose(), device.sign_seed.expose());
        assert_eq!(loaded.agree_private.expose(), device.agree_private.expose());
        assert_eq!(loaded.fingerprint().unwrap(), device.fingerprint().unwrap());
    }

    #[test]
    fn create_refuses_when_already_exists() {
        let (tmp, state) = new_state();
        let kms = new_kms(&tmp);
        DeviceKey::create(&state, &kms).unwrap();
        let err = DeviceKey::create(&state, &kms).unwrap_err();
        assert!(err.is(ErrorClass::StateError));
        assert_eq!(err.reason, "device_key_exists");
    }

    #[test]
    fn load_missing_raises() {
        let (tmp, state) = new_state();
        let kms = new_kms(&tmp);
        let err = DeviceKey::load(&state, &kms).unwrap_err();
        assert!(err.is(ErrorClass::StateError));
        assert_eq!(err.reason, "device_key_missing");
    }

    #[test]
    fn load_or_create_is_idempotent() {
        let (tmp, state) = new_state();
        let kms = new_kms(&tmp);
        let first = DeviceKey::load_or_create(&state, &kms).unwrap();
        let second = DeviceKey::load_or_create(&state, &kms).unwrap();
        assert_eq!(first.fingerprint().unwrap(), second.fingerprint().unwrap());
    }

    #[test]
    fn sign_produces_verifiable_signature() {
        let device = DeviceKey::generate();
        let message = b"zeropw-team-test-message";
        let sig = device.sign(message).unwrap();
        assert!(ed25519::verify(
            &device.record().unwrap().sign_pub,
            message,
            &sig
        ));
    }
}
