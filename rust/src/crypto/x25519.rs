//! Port of `zeropw/crypto/x25519.py`: X25519 (RFC 7748 section 5), the
//! Montgomery-ladder Diffie-Hellman function used for ZeroPW team-sync
//! device agreement keys (`docs/team-sync.md` section 4.1).
//!
//! The Python prototype hand-rolls the RFC 7748 pseudocode in pure Python
//! because the standard library has no X25519 implementation, and documents
//! itself as "not constant-time" at the machine-instruction level. PORTING.md
//! §3.1 allows replacing that with an audited crate, provided the RFC 7748
//! test vectors still pass and the accept/reject and contributory-behaviour
//! boundaries match. `x25519_dalek::x25519` is exactly the RFC 7748 "bare,
//! byte-oriented x25519 function" (its own doc comment says so): it clamps
//! `k` via `clamp_integer` -- byte 0 masked with `0xF8`, byte 31 masked with
//! `0x7F` then ORed with `0x40`, matching this module's `clamp_scalar` and
//! Python's -- then runs the Montgomery ladder over `curve25519-dalek`'s
//! `MontgomeryPoint`, which decodes `u` the same way Python's
//! `_decode_u_coordinate` does (masking the unused top bit before reducing
//! mod p). See `curve25519-dalek-4.1.3/src/montgomery.rs` (`mul_clamped`,
//! `clamp_integer`) and `x25519-dalek-2.0.1/src/x25519.rs` (`x25519`).

use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

use crate::secret::SecretBytes;

/// `zeropw.crypto.x25519.SCALAR_SIZE`.
pub const SCALAR_SIZE: usize = 32;
/// `zeropw.crypto.x25519.POINT_SIZE`.
pub const POINT_SIZE: usize = 32;
/// `zeropw.crypto.x25519.BASE_POINT`: the X25519 base point `u = 9`,
/// little-endian over 32 bytes.
pub const BASE_POINT: [u8; POINT_SIZE] = X25519_BASEPOINT_BYTES;

/// A scalar or point that is too short for [`clamp_scalar`] or has the wrong
/// length for [`scalarmult`]. The message never contains the key material
/// itself. Python's `_as_bytes` gives `scalarmult` an exact-length
/// `ValueError`, while `clamp_scalar` lets an `IndexError` escape for fewer
/// than 32 bytes; PORTING.md section 3.5 permits Rust to return this closest
/// handled error for that built-in exception. Python additionally raises
/// `TypeError` for a non-bytes-like argument (e.g. a `str`); that case cannot
/// arise here, since every argument is already `&[u8]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SizeError(String);

impl std::fmt::Display for SizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SizeError {}

/// [`shared_secret`]'s error: either a malformed input (as [`scalarmult`]
/// would reject) or the RFC 7748 section 6.1 contributory-behaviour failure.
/// The latter carries a real [`crate::errors::Error`] (`InvalidInput`,
/// reason `x25519_low_order_point`) because Python raises the same
/// `zeropw.errors.InvalidInput` its callers already catch by class -- unlike
/// the plain-`ValueError` size checks, which stay a module-local mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedSecretError {
    Size(SizeError),
    LowOrderPoint(crate::errors::Error),
}

impl From<SizeError> for SharedSecretError {
    fn from(err: SizeError) -> Self {
        SharedSecretError::Size(err)
    }
}

impl std::fmt::Display for SharedSecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SharedSecretError::Size(err) => write!(f, "{err}"),
            SharedSecretError::LowOrderPoint(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for SharedSecretError {}

fn check_len(name: &str, data: &[u8]) -> Result<[u8; SCALAR_SIZE], SizeError> {
    data.try_into().map_err(|_| {
        SizeError(format!(
            "{name} must be exactly {SCALAR_SIZE} bytes, got {}",
            data.len()
        ))
    })
}

/// Port of `clamp_scalar`: apply the RFC 7748 section 5 clamping to bytes 0
/// and 31, then represent Python's `int.from_bytes(k, "little")` result as
/// secret, little-endian bytes.
///
/// Python accepts every input of at least 32 bytes and includes bytes beyond
/// index 31 in the arbitrary-precision integer. Keeping the full byte string
/// encodes the same integer while retaining its input width (including
/// harmless zero bytes at the most-significant end), and avoids exposing
/// scalar material through a public `Vec<u8>`. Inputs shorter than 32 bytes
/// return [`SizeError`] rather than allowing Python's built-in `IndexError`
/// to escape, as permitted by PORTING.md section 3.5.
pub fn clamp_scalar(raw: &[u8]) -> Result<SecretBytes, SizeError> {
    if raw.len() < SCALAR_SIZE {
        return Err(SizeError(format!(
            "raw must be at least {SCALAR_SIZE} bytes, got {}",
            raw.len()
        )));
    }
    let mut k = raw.to_vec();
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    Ok(SecretBytes::new(k))
}

/// Port of `scalarmult`: `X25519(k, u)`, the Diffie-Hellman function of RFC
/// 7748 section 5.
///
/// Both arguments are 32-byte little-endian encodings. `k` is clamped before
/// use (callers may pass either a raw random scalar or an already-clamped
/// one; clamping is idempotent). Returns [`SizeError`] for a wrong-length
/// `k` or `u`; never includes key material in the error.
pub fn scalarmult(k: &[u8], u: &[u8]) -> Result<[u8; POINT_SIZE], SizeError> {
    let k = check_len("k", k)?;
    let u = check_len("u", u)?;
    Ok(x25519(k, u))
}

/// Port of `shared_secret`: `X25519(private, peer_public)` with the RFC 7748
/// section 6.1 contributory check.
///
/// Returns [`SharedSecretError::LowOrderPoint`] (`InvalidInput`, reason
/// `x25519_low_order_point`) when the result is all-zero -- `peer_public`
/// encoded a point of small order (the all-zero u-coordinate is the
/// simplest example: it is fixed by the curve equation and independent of
/// the scalar, so it contributes no secrecy at all). Use this for every real
/// key agreement; [`scalarmult`] is the bare primitive the RFC test vectors
/// exercise directly.
pub fn shared_secret(
    private: &[u8],
    peer_public: &[u8],
) -> Result<[u8; POINT_SIZE], SharedSecretError> {
    let result = scalarmult(private, peer_public)?;
    // Constant-time all-zero check (PORTING.md §3.3: secret comparisons are
    // constant time); Python's plain `int.from_bytes(result, "little") == 0`
    // is not, but the value compared is either genuinely zero or a computed
    // shared secret, so this only strengthens the Python behaviour.
    use subtle::ConstantTimeEq;
    let is_zero: bool = result.ct_eq(&[0u8; POINT_SIZE]).into();
    if is_zero {
        return Err(SharedSecretError::LowOrderPoint(
            crate::errors::Error::invalid_input("x25519_low_order_point"),
        ));
    }
    Ok(result)
}

/// Port of `public_key`: derive the public u-coordinate for a 32-byte
/// private scalar.
pub fn public_key(private: &[u8]) -> Result<[u8; POINT_SIZE], SizeError> {
    scalarmult(private, &BASE_POINT)
}

/// Port of `generate_private`: a fresh, clamped 32-byte X25519 private
/// scalar from the OS CSPRNG.
///
/// Returns `SecretBytes` rather than Python's plain `bytes` (PORTING.md
/// §3.2): this is the point a fresh X25519 private key -- wrapped by the
/// local KMS at `team/device.key` alongside the Ed25519 seed
/// (`zeropw/team/identity.py`) -- comes into being, so it is handed back
/// already wrapped rather than as a naked `Vec<u8>`.
pub fn generate_private() -> SecretBytes {
    let mut raw = [0u8; SCALAR_SIZE];
    getrandom::getrandom(&mut raw).expect("OS CSPRNG must be available");
    raw[0] &= 248;
    raw[31] &= 127;
    raw[31] |= 64;
    let out = SecretBytes::from_slice(&raw);
    raw.iter_mut().for_each(|b| *b = 0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).expect("valid hex fixture")
    }

    #[test]
    fn sizes_and_base_point() {
        assert_eq!(SCALAR_SIZE, 32);
        assert_eq!(POINT_SIZE, 32);
        let mut expected = [0u8; 32];
        expected[0] = 9;
        assert_eq!(BASE_POINT, expected);
    }

    // RFC 7748 section 5.2, single-iteration test vectors.
    #[test]
    fn test_vector_1() {
        let scalar = h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let expected = h("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        assert_eq!(scalarmult(&scalar, &u).unwrap().to_vec(), expected);
    }

    #[test]
    fn test_vector_2() {
        let scalar = h("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = h("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        let expected = h("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
        assert_eq!(scalarmult(&scalar, &u).unwrap().to_vec(), expected);
    }

    #[test]
    fn test_iteration_1() {
        let k = h("0900000000000000000000000000000000000000000000000000000000000000");
        let u = k.clone();
        assert_eq!(k.len(), 32);
        let result = scalarmult(&k, &u).unwrap();
        assert_eq!(
            result.to_vec(),
            h("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
        );
    }

    #[test]
    fn test_iteration_1000() {
        let mut k = h("0900000000000000000000000000000000000000000000000000000000000000");
        let mut u = k.clone();
        for _ in 0..1000 {
            let next = scalarmult(&k, &u).unwrap().to_vec();
            u = k;
            k = next;
        }
        assert_eq!(
            k,
            h("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
        );
    }

    // The RFC's 1,000,000-iteration vector is skipped, as in
    // `tests/test_x25519.py`: too slow to be a useful unit test, and the 1-
    // and 1,000-iteration vectors above already exercise the same ladder.

    #[test]
    fn test_diffie_hellman_6_1() {
        let alice_private = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob_private = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let alice_public = public_key(&alice_private).unwrap();
        let bob_public = public_key(&bob_private).unwrap();
        assert_eq!(
            alice_public.to_vec(),
            h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            bob_public.to_vec(),
            h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let shared_alice = scalarmult(&alice_private, &bob_public).unwrap();
        let shared_bob = scalarmult(&bob_private, &alice_public).unwrap();
        assert_eq!(shared_alice, shared_bob);
        assert_eq!(
            shared_alice.to_vec(),
            h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        );
    }

    #[test]
    fn generate_private_is_clamped_and_usable() {
        let priv_key = generate_private();
        assert_eq!(priv_key.len(), 32);
        assert_eq!(priv_key.expose()[0] & 0x07, 0);
        assert_eq!(priv_key.expose()[31] & 0x80, 0);
        assert_eq!(priv_key.expose()[31] & 0x40, 0x40);
        let pub_key = public_key(priv_key.expose()).unwrap();
        assert_eq!(pub_key.len(), 32);
    }

    #[test]
    fn shared_secret_matches_both_directions() {
        let a = generate_private();
        let b = generate_private();
        let pa = public_key(a.expose()).unwrap();
        let pb = public_key(b.expose()).unwrap();
        assert_eq!(
            scalarmult(a.expose(), &pb).unwrap(),
            scalarmult(b.expose(), &pa).unwrap()
        );
    }

    /// F5: the all-zero u-coordinate is a small-order point (fixed by the
    /// curve equation, independent of the scalar) -- `shared_secret` must
    /// refuse it rather than return the all-zero "secret" every peer using
    /// it would derive too. `scalarmult` itself stays a bare primitive.
    #[test]
    fn shared_secret_refuses_all_zero_low_order_point() {
        let priv_key = generate_private();
        assert_eq!(
            scalarmult(priv_key.expose(), &[0u8; 32]).unwrap(),
            [0u8; 32]
        );
        let err = shared_secret(priv_key.expose(), &[0u8; 32]).unwrap_err();
        match err {
            SharedSecretError::LowOrderPoint(e) => {
                assert!(e.is(crate::errors::ErrorClass::InvalidInput));
                assert_eq!(e.reason, "x25519_low_order_point");
            }
            SharedSecretError::Size(_) => panic!("expected LowOrderPoint"),
        }
    }

    #[test]
    fn shared_secret_normal_case_matches_scalarmult() {
        let a = generate_private();
        let b = generate_private();
        let pb = public_key(b.expose()).unwrap();
        let expected = scalarmult(a.expose(), &pb).unwrap();
        assert_eq!(shared_secret(a.expose(), &pb).unwrap(), expected);
    }

    #[test]
    fn wrong_size_inputs_rejected() {
        assert!(scalarmult(b"short", &[0u8; 32]).is_err());
        assert!(scalarmult(&[0u8; 32], b"short").is_err());
        assert!(scalarmult(&[], &[]).is_err());
        // Rust's type system already rules out Python's `TypeError` case
        // (a non-bytes-like `k`/`u`, e.g. a `str`); see the module doc
        // comment and `DEVIATIONS.md`.
    }

    #[test]
    fn clamp_scalar_matches_generate_private_clamping() {
        let raw = [0xffu8; 32];
        let clamped = clamp_scalar(&raw).unwrap();
        assert_eq!(clamped.expose()[0] & 0x07, 0);
        assert_eq!(clamped.expose()[31] & 0x80, 0);
        assert_eq!(clamped.expose()[31] & 0x40, 0x40);
        // Applying the same bit masks again is idempotent.
        let reclamped = clamp_scalar(clamped.expose()).unwrap();
        assert!(reclamped.ct_eq(clamped.expose()));
    }

    #[test]
    fn clamp_scalar_short_errors_and_crypto_entrypoints_remain_strict() {
        for len in [0, 1, 31] {
            assert!(clamp_scalar(&vec![0u8; len]).is_err());
        }

        let long = [0u8; 33];
        assert!(clamp_scalar(&long).is_ok());
        assert!(scalarmult(&long, &BASE_POINT).is_err());
        assert!(scalarmult(&BASE_POINT, &long).is_err());
        assert!(public_key(&long).is_err());
        assert!(matches!(
            shared_secret(&long, &BASE_POINT),
            Err(SharedSecretError::Size(_))
        ));
        assert!(matches!(
            shared_secret(&BASE_POINT, &long),
            Err(SharedSecretError::Size(_))
        ));
    }

    #[test]
    fn oracle_clamp_scalar_matches_python_for_every_length_boundary() {
        let mut cases = vec![
            Vec::new(),
            vec![0xa5],
            vec![0xa5; 31],
            vec![0xff; 32],
            vec![0xff; 33],
            vec![0xff; 64],
            vec![0xff; 257],
        ];
        let mut high_tail_zero = vec![0xff; 64];
        high_tail_zero[32..].fill(0);
        cases.push(high_tail_zero);

        let encoded = cases
            .iter()
            .map(hex::encode)
            .map(|value| format!("'{value}'"))
            .collect::<Vec<_>>()
            .join(",");
        let script = format!(
            "from zeropw.crypto import x25519\n\
             for encoded in [{encoded}]:\n\
             \traw = bytes.fromhex(encoded)\n\
             \ttry:\n\
             \t\tvalue = x25519.clamp_scalar(raw)\n\
             \t\tprint(value.to_bytes(len(raw), 'little').hex())\n\
             \texcept Exception as exc:\n\
             \t\tprint(type(exc).__name__)"
        );
        let python = crate::oracle::python(&script);
        let python_results = python.lines().collect::<Vec<_>>();
        assert_eq!(python_results.len(), cases.len());

        for (raw, python_result) in cases.iter().zip(python_results) {
            match clamp_scalar(raw) {
                Ok(rust) => {
                    assert_eq!(hex::encode(rust.expose()), python_result);
                    let reclamped = clamp_scalar(rust.expose()).unwrap();
                    assert!(reclamped.ct_eq(rust.expose()));
                }
                Err(_) => assert_eq!(python_result, "IndexError"),
            }
        }
    }

    #[test]
    fn oracle_scalarmult_matches_python() {
        let k = h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let rust_result = scalarmult(&k, &u).unwrap();

        let script = format!(
            "from zeropw.crypto import x25519\n\
             k = bytes.fromhex('{}')\n\
             u = bytes.fromhex('{}')\n\
             print(x25519.scalarmult(k, u).hex())",
            hex::encode(&k),
            hex::encode(&u),
        );
        let python_result = crate::oracle::python(&script);
        assert_eq!(hex::encode(rust_result), python_result.trim());
    }

    #[test]
    fn oracle_public_key_and_shared_secret_match_python() {
        let a_priv = generate_private();
        let b_priv = generate_private();
        let a_pub = public_key(a_priv.expose()).unwrap();
        let b_pub = public_key(b_priv.expose()).unwrap();
        let rust_shared = shared_secret(a_priv.expose(), &b_pub).unwrap();

        let script = format!(
            "from zeropw.crypto import x25519\n\
             a_priv = bytes.fromhex('{}')\n\
             b_priv = bytes.fromhex('{}')\n\
             a_pub = x25519.public_key(a_priv)\n\
             b_pub = x25519.public_key(b_priv)\n\
             print(a_pub.hex())\n\
             print(b_pub.hex())\n\
             print(x25519.shared_secret(a_priv, b_pub).hex())\n\
             print(x25519.shared_secret(b_priv, a_pub).hex())",
            hex::encode(a_priv.expose()),
            hex::encode(b_priv.expose()),
        );
        let out = crate::oracle::python(&script);
        let mut lines = out.lines();
        let python_a_pub = lines.next().expect("a_pub line");
        let python_b_pub = lines.next().expect("b_pub line");
        let python_shared_ab = lines.next().expect("shared a->b line");
        let python_shared_ba = lines.next().expect("shared b->a line");

        assert_eq!(hex::encode(a_pub), python_a_pub);
        assert_eq!(hex::encode(b_pub), python_b_pub);
        assert_eq!(hex::encode(rust_shared), python_shared_ab);
        assert_eq!(python_shared_ab, python_shared_ba);
    }

    #[test]
    fn oracle_low_order_point_rejected_identically() {
        let priv_key = generate_private();
        let script = format!(
            "from zeropw.crypto import x25519\n\
             from zeropw.errors import InvalidInput\n\
             priv = bytes.fromhex('{}')\n\
             try:\n\
             \tx25519.shared_secret(priv, b'\\x00' * 32)\n\
             \tprint('accepted')\n\
             except InvalidInput as exc:\n\
             \tprint(f'rejected:{{exc.reason}}')",
            hex::encode(priv_key.expose()),
        );
        let python_out = crate::oracle::python(&script);
        assert_eq!(python_out.trim(), "rejected:x25519_low_order_point");

        let err = shared_secret(priv_key.expose(), &[0u8; 32]).unwrap_err();
        match err {
            SharedSecretError::LowOrderPoint(e) => assert_eq!(e.reason, "x25519_low_order_point"),
            SharedSecretError::Size(_) => panic!("expected LowOrderPoint"),
        }
    }
}
