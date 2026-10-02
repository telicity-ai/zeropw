//! Port of `zeropw/team/envelope.py`: DEK generation wrapping and per-secret
//! encryption for shared environments (docs/team-sync.md section 4.2).
//!
//! Two independent envelopes live here:
//!
//! * [`wrap_dek`] / [`unwrap_dek`]: an environment DEK generation is handed
//!   to one recipient device by an ephemeral X25519 key agreement,
//!   HKDF-SHA256, and a ChaCha20-Poly1305 seal. This is the "one recipient"
//!   half of section 4.2; `dek.rotate` / `env.init` commits carry one such
//!   wrap per member.
//! * [`encrypt_secret`] / [`decrypt_secret`]: a secret version's ciphertext,
//!   once a generation's DEK is known, with AAD binding it to the
//!   environment, secret and version identifiers so a ciphertext cannot be
//!   replayed under a different secret or version.
//!
//! Nothing here ever has access to a passphrase or the local KMS; those live
//! in `kms.rs` and are only consulted by `team::fold` and `vault.rs` once a
//! generation's DEK has already been unwrapped.

use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;

use crate::crypto::chacha20poly1305 as aead;
use crate::crypto::x25519;
use crate::errors::{Error, Result};
use crate::pybase64;

use super::identity::{DeviceKey, DeviceRecord};

/// `zeropw.team.envelope.DEK_INFO_PREFIX`.
pub const DEK_INFO_PREFIX: &[u8] = b"zeropw-team-dek-v1";

const HKDF_LEN: usize = 32; // SHA-256 digest size

fn b64e(raw: &[u8]) -> String {
    pybase64::b64encode(raw)
}

fn b64d(text: &str) -> std::result::Result<Vec<u8>, ()> {
    pybase64::b64decode(text).map_err(|_| ())
}

/// Python's envelope readers apply `str(...)` before their lenient base64
/// decode. Strings therefore pass through without quotes, while every other
/// JSON value uses its Python representation (`None`, `True`, exact numeric
/// rendering, and list/dict repr syntax).
fn python_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        _ => crate::pystr::repr_value(value),
    }
}

fn random_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

// ------------------------------------------------------------------- HKDF
/// RFC 5869 HKDF-Extract with SHA-256. Port of `hkdf_extract`.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let zero_salt = [0u8; HKDF_LEN];
    let salt = if salt.is_empty() { &zero_salt } else { salt };
    // `hmac::new_from_slice` accepts any key length (HMAC key material is
    // hashed down if too long), matching Python's `hmac.new(salt, ikm, sha256)`.
    let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(ikm);
    mac.finalize().into_bytes().to_vec()
}

/// RFC 5869 HKDF-Expand with SHA-256. Port of `hkdf_expand`.
pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
    if length > 255 * HKDF_LEN {
        return Err(Error::invalid_input("hkdf_length_too_large"));
    }
    let mut output = Vec::with_capacity(length + HKDF_LEN);
    let mut block: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while output.len() < length {
        let mut mac = Hmac::<Sha256>::new_from_slice(prk).expect("HMAC accepts any key length");
        mac.update(&block);
        mac.update(info);
        mac.update(&[counter]);
        block = mac.finalize().into_bytes().to_vec();
        output.extend_from_slice(&block);
        counter = counter.wrapping_add(1);
    }
    output.truncate(length);
    Ok(output)
}

/// Port of `hkdf`.
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, length)
}

// -------------------------------------------------------------- DEK wraps
fn dek_info(env_id: &str, generation_id: &str, fingerprint: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        DEK_INFO_PREFIX.len() + env_id.len() + generation_id.len() + fingerprint.len(),
    );
    out.extend_from_slice(DEK_INFO_PREFIX);
    out.extend_from_slice(env_id.as_bytes());
    out.extend_from_slice(generation_id.as_bytes());
    out.extend_from_slice(fingerprint.as_bytes());
    out
}

/// Wrap `dek` for one recipient device (docs/team-sync.md section 4.2). Port
/// of `wrap_dek`.
///
/// An ephemeral X25519 key is generated for this wrap only; the shared
/// secret with the recipient's agreement key feeds HKDF-SHA256 (info =
/// `zeropw-team-dek-v1` + env id + generation id + recipient fingerprint) to
/// derive a one-time ChaCha20-Poly1305 key. Returns a JSON-safe object with
/// the ephemeral public key, nonce and ciphertext; never the DEK.
pub fn wrap_dek(
    dek: &[u8],
    env_id: &str,
    generation_id: &str,
    recipient: &DeviceRecord,
) -> Result<Value> {
    if dek.len() != aead::KEY_SIZE {
        return Err(Error::invalid_input("invalid_dek_size"));
    }
    let eph_private = x25519::generate_private();
    let eph_pub =
        x25519::public_key(eph_private.expose()).map_err(|_| Error::state("device_key_corrupt"))?;
    let shared = x25519::shared_secret(eph_private.expose(), &recipient.agree_pub)
        .map_err(shared_secret_error)?;
    let info = dek_info(env_id, generation_id, &recipient.fingerprint());
    let key = hkdf(b"", &shared, &info, aead::KEY_SIZE)?;
    let nonce = random_bytes(aead::NONCE_SIZE);
    let ciphertext = aead::encrypt(&key, &nonce, dek, &info)
        .map_err(|e| Error::state("dek_wrap_failed").with_detail(e.to_string()))?;
    let mut m = Map::new();
    m.insert("eph_pub".into(), Value::String(b64e(&eph_pub)));
    m.insert("nonce".into(), Value::String(b64e(&nonce)));
    m.insert("ciphertext".into(), Value::String(b64e(&ciphertext)));
    Ok(Value::Object(m))
}

fn shared_secret_error(err: x25519::SharedSecretError) -> Error {
    match err {
        x25519::SharedSecretError::LowOrderPoint(e) => e,
        // A-24: `x25519::shared_secret`'s `Size` arm can only be reached with
        // a wrong-length scalar/point; every caller in this module passes
        // sizes the type system / prior length checks already guarantee are
        // exactly 32 bytes, so this is unreachable in practice. Python has
        // no equivalent branch to diverge from (its `shared_secret` only
        // ever raises `InvalidInput("x25519_low_order_point")`); PORTING.md
        // §3.5 applies to this defensive fallback.
        x25519::SharedSecretError::Size(e) => {
            Error::invalid_input("x25519_invalid_point_size").with_detail(e.to_string())
        }
    }
}

/// Recover the DEK from a wrap addressed to `device`. Port of `unwrap_dek`.
/// Raises `InvalidInput` on any failure.
pub fn unwrap_dek(
    wrap: &Value,
    env_id: &str,
    generation_id: &str,
    device: &DeviceKey,
) -> Result<Vec<u8>> {
    let bad = || Error::invalid_input("dek_wrap_malformed");
    let obj = wrap.as_object().ok_or_else(bad)?;
    let field = |key: &str| -> Result<Vec<u8>> {
        let value = obj.get(key).ok_or_else(bad)?;
        b64d(&python_str(value)).map_err(|_| bad())
    };
    let eph_pub = field("eph_pub")?;
    let nonce = field("nonce")?;
    let ciphertext = field("ciphertext")?;
    if eph_pub.len() != x25519::POINT_SIZE {
        return Err(bad());
    }
    let shared = x25519::shared_secret(device.agree_private.expose(), &eph_pub)
        .map_err(shared_secret_error)?;
    let fingerprint = device.fingerprint()?;
    let info = dek_info(env_id, generation_id, &fingerprint);
    let key = hkdf(b"", &shared, &info, aead::KEY_SIZE)?;
    aead::decrypt(&key, &nonce, &ciphertext, &info)
        .map_err(|_| Error::invalid_input("dek_unwrap_failed"))
}

// ------------------------------------------------------------- secret values
/// AAD = environment id + secret id + version id (docs/team-sync.md section
/// 4.2), joined with a NUL separator (none of the three identifiers may
/// contain one -- fingerprints, project names and hex tokens never do) so
/// that `("a", "bc")` and `("ab", "c")` cannot collide. Port of `_secret_aad`.
fn secret_aad(env_id: &str, secret_id: &str, version_id: &str) -> Result<Vec<u8>> {
    for part in [env_id, secret_id, version_id] {
        if part.contains('\0') {
            return Err(Error::invalid_input("invalid_aad_component"));
        }
    }
    let mut out = Vec::new();
    out.extend_from_slice(env_id.as_bytes());
    out.push(0);
    out.extend_from_slice(secret_id.as_bytes());
    out.push(0);
    out.extend_from_slice(version_id.as_bytes());
    Ok(out)
}

/// Encrypt one secret version under a generation DEK. Port of
/// `encrypt_secret`. Returns `{"nonce", "ciphertext"}` (base64).
pub fn encrypt_secret(
    dek: &[u8],
    env_id: &str,
    secret_id: &str,
    version_id: &str,
    value: &[u8],
) -> Result<Map<String, Value>> {
    if dek.len() != aead::KEY_SIZE {
        return Err(Error::invalid_input("invalid_dek_size"));
    }
    let aad = secret_aad(env_id, secret_id, version_id)?;
    let nonce = random_bytes(aead::NONCE_SIZE);
    let ciphertext = aead::encrypt(dek, &nonce, value, &aad)
        .map_err(|e| Error::state("secret_encrypt_failed").with_detail(e.to_string()))?;
    let mut m = Map::new();
    m.insert("nonce".into(), Value::String(b64e(&nonce)));
    m.insert("ciphertext".into(), Value::String(b64e(&ciphertext)));
    Ok(m)
}

/// Decrypt one secret version. Port of `decrypt_secret`. Raises
/// `InvalidInput` for any malformed or unauthenticated input.
///
/// `entry` is the whole stored/wire record (it may carry extra fields such
/// as `status`, `generation`, `shared_env`, ...); only `nonce`/`ciphertext`
/// are read, exactly like Python's dict indexing.
pub fn decrypt_secret(
    dek: &[u8],
    env_id: &str,
    secret_id: &str,
    version_id: &str,
    entry: &Map<String, Value>,
) -> Result<Vec<u8>> {
    let aad = secret_aad(env_id, secret_id, version_id)?;
    let bad = || Error::invalid_input("secret_ciphertext_malformed");
    let field = |key: &str| -> Result<Vec<u8>> {
        let value = entry.get(key).ok_or_else(bad)?;
        b64d(&python_str(value)).map_err(|_| bad())
    };
    let nonce = field("nonce")?;
    let ciphertext = field("ciphertext")?;
    aead::decrypt(dek, &nonce, &ciphertext, &aad)
        .map_err(|_| Error::invalid_input("secret_ciphertext_invalid"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorClass;
    use crate::team::identity::DeviceKey;

    const ENV_ID: &str = "0123456789abcdef0123456789abcdef";
    const GENERATION_ID: &str = "deadbeefcafef00d";
    const SECRET_ID: &str = "gh-token";
    const VERSION_ID: &str = "abc123ef00112233";
    const SYNTHETIC: &[u8] = b"synthetic-secret-value-0123456789";

    #[test]
    fn rfc5869_case_1() {
        let ikm = hex::decode("0b".repeat(22)).unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let okm = hkdf(&salt, &ikm, &info, 42).unwrap();
        let expected = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();
        assert_eq!(okm, expected);
    }

    fn dek() -> Vec<u8> {
        (0..32u8).collect()
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let dek = dek();
        let device = DeviceKey::generate();
        let record = device.record().unwrap();
        let wrap = wrap_dek(&dek, ENV_ID, GENERATION_ID, &record).unwrap();
        assert!(!wrap.to_string().contains(&hex::encode(&dek)));
        let recovered = unwrap_dek(&wrap, ENV_ID, GENERATION_ID, &device).unwrap();
        assert_eq!(recovered, dek);
    }

    #[test]
    fn wrong_device_cannot_unwrap() {
        let dek = dek();
        let device = DeviceKey::generate();
        let other = DeviceKey::generate();
        let wrap = wrap_dek(&dek, ENV_ID, GENERATION_ID, &device.record().unwrap()).unwrap();
        assert!(unwrap_dek(&wrap, ENV_ID, GENERATION_ID, &other).is_err());
    }

    #[test]
    fn wrong_env_or_generation_id_fails() {
        let dek = dek();
        let device = DeviceKey::generate();
        let wrap = wrap_dek(&dek, ENV_ID, GENERATION_ID, &device.record().unwrap()).unwrap();
        assert!(unwrap_dek(&wrap, "other-env-id", GENERATION_ID, &device).is_err());
        assert!(unwrap_dek(&wrap, ENV_ID, "other-generation", &device).is_err());
    }

    #[test]
    fn two_wraps_use_independent_ephemeral_keys() {
        let dek = dek();
        let device = DeviceKey::generate();
        let record = device.record().unwrap();
        let a = wrap_dek(&dek, ENV_ID, GENERATION_ID, &record).unwrap();
        let b = wrap_dek(&dek, ENV_ID, GENERATION_ID, &record).unwrap();
        assert_ne!(a["eph_pub"], b["eph_pub"]);
        assert_ne!(a["ciphertext"], b["ciphertext"]);
    }

    #[test]
    fn malformed_wrap_rejected() {
        let device = DeviceKey::generate();
        let wrap = serde_json::json!({"eph_pub": "!!!", "nonce": "AAAA", "ciphertext": "AAAA"});
        assert!(unwrap_dek(&wrap, ENV_ID, GENERATION_ID, &device).is_err());
    }

    #[test]
    fn invalid_dek_size_rejected() {
        let device = DeviceKey::generate();
        let record = device.record().unwrap();
        assert!(wrap_dek(b"too-short", ENV_ID, GENERATION_ID, &record).is_err());
    }

    // F5: an all-zero agreement key is a low-order X25519 point.
    #[test]
    fn wrap_refuses_low_order_recipient_point() {
        let device = DeviceKey::generate();
        let record = device.record().unwrap();
        let low_order = DeviceRecord::new(&record.sign_pub, &[0u8; 32], &record.sig).unwrap();
        let err = wrap_dek(&dek(), ENV_ID, GENERATION_ID, &low_order).unwrap_err();
        assert!(err.is(ErrorClass::InvalidInput));
        assert_eq!(err.reason, "x25519_low_order_point");
    }

    #[test]
    fn unwrap_refuses_low_order_ephemeral_point() {
        let device = DeviceKey::generate();
        let forged = serde_json::json!({
            "eph_pub": b64e(&[0u8; 32]),
            "nonce": b64e(&[0u8; 12]),
            "ciphertext": b64e(&[0u8; 48]),
        });
        let err = unwrap_dek(&forged, ENV_ID, GENERATION_ID, &device).unwrap_err();
        assert!(err.is(ErrorClass::InvalidInput));
        assert_eq!(err.reason, "x25519_low_order_point");
    }

    fn sec_dek() -> Vec<u8> {
        (1..=32u8).collect()
    }

    #[test]
    fn secret_roundtrip() {
        let dek = sec_dek();
        let entry = encrypt_secret(&dek, ENV_ID, SECRET_ID, VERSION_ID, SYNTHETIC).unwrap();
        assert!(!format!("{entry:?}").contains(std::str::from_utf8(SYNTHETIC).unwrap()));
        let recovered = decrypt_secret(&dek, ENV_ID, SECRET_ID, VERSION_ID, &entry).unwrap();
        assert_eq!(recovered, SYNTHETIC);
    }

    #[test]
    fn wrong_version_id_fails_aad_check() {
        let dek = sec_dek();
        let entry = encrypt_secret(&dek, ENV_ID, SECRET_ID, VERSION_ID, SYNTHETIC).unwrap();
        assert!(decrypt_secret(&dek, ENV_ID, SECRET_ID, "other-version", &entry).is_err());
    }

    #[test]
    fn wrong_secret_id_fails_aad_check() {
        let dek = sec_dek();
        let entry = encrypt_secret(&dek, ENV_ID, SECRET_ID, VERSION_ID, SYNTHETIC).unwrap();
        assert!(decrypt_secret(&dek, ENV_ID, "other-secret", VERSION_ID, &entry).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let dek = sec_dek();
        let entry = encrypt_secret(&dek, ENV_ID, SECRET_ID, VERSION_ID, SYNTHETIC).unwrap();
        let other_dek: Vec<u8> = (0..32u8).rev().collect();
        assert!(decrypt_secret(&other_dek, ENV_ID, SECRET_ID, VERSION_ID, &entry).is_err());
    }
}
