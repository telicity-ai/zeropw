//! Port of `zeropw/crypto/ed25519.py`: pure Ed25519 (RFC 8032, PureEdDSA over
//! edwards25519, no prehash, empty context).
//!
//! The Python prototype hand-rolls RFC 8032 in pure Python because the
//! standard library has no Ed25519 implementation. PORTING.md §3.1 allows
//! replacing that with the audited `ed25519-dalek` crate, provided the RFC
//! 8032 test vectors still pass and `verify` keeps the same accept/reject
//! behaviour.
//!
//! `verify`'s accept/reject boundary matters for interop and was checked
//! against dalek 2.2.0's source (`~/.cargo/registry/.../ed25519-dalek-2.2.0`):
//! `VerifyingKey::verify` (used here, *not* `verify_strict`) rejects a
//! non-canonical scalar `S` (`S >= L`) via `Scalar::from_canonical_bytes`,
//! and recomputes `R` and compares *compressed* points byte-for-byte, which
//! (per that function's own doc comment) "does not accept non-canonically
//! encoded R values" -- matching `zeropw`'s hand-written `_point_decode`
//! rejecting `y >= p` and the `x == 0` / sign-bit-set encoding for `R`.
//! Critically, plain `verify` does *not* reject small-order public keys or
//! `R` values -- only `verify_strict` adds that `is_small_order()` check --
//! which matches the Python docstring: "Small-order or mixed-order public
//! keys and R values are not rejected beyond what the RFC requires". Using
//! `verify_strict` here would be *stricter* than Python and so would itself
//! be an undocumented deviation; plain `verify` is the correct match.
//!
//! `VerifyingKey::from_bytes` (the public-key decode `verify` starts from)
//! is a *different* story: unlike `R`, it is never checked against a
//! recomputed value, so `curve25519-dalek`'s lenient `decompress` (which
//! reduces `y` mod p and accepts `x == 0` with either sign bit) leaks
//! straight through, accepting encodings `_point_decode` rejects. `verify`
//! below adds an explicit canonical-encoding check (decompress, recompress,
//! compare) to close that gap; see its doc comment and `DEVIATIONS.md`
//! finding B-1.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::secret::SecretBytes;

/// `zeropw.crypto.ed25519.SEED_SIZE`.
pub const SEED_SIZE: usize = 32;
/// `zeropw.crypto.ed25519.PUBLIC_KEY_SIZE`.
pub const PUBLIC_KEY_SIZE: usize = 32;
/// `zeropw.crypto.ed25519.SIGNATURE_SIZE`.
pub const SIGNATURE_SIZE: usize = 64;

/// A malformed seed passed to `public_key_from_seed` or `sign`. Mirrors the
/// Python `ValueError` (the message never contains the seed value). Python
/// additionally raises `TypeError` for a non-bytes-like seed or message;
/// that case cannot arise here, since `seed`/`message` are `&[u8]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedError(String);

impl std::fmt::Display for SeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SeedError {}

fn check_seed(seed: &[u8]) -> Result<&[u8; SEED_SIZE], SeedError> {
    seed.try_into()
        .map_err(|_| SeedError(format!("seed must be exactly {SEED_SIZE} bytes")))
}

/// Port of `generate_seed`: a fresh 32-byte Ed25519 seed from the OS CSPRNG.
///
/// Returns `SecretBytes` rather than Python's plain `bytes` (PORTING.md
/// §3.2): this is the point a fresh Ed25519 seed -- explicitly named in
/// `secret.rs` alongside DEKs and the KMS master key -- comes into being, so
/// it is handed back already wrapped rather than as a naked `Vec<u8>`.
pub fn generate_seed() -> SecretBytes {
    let mut seed = [0u8; SEED_SIZE];
    getrandom::getrandom(&mut seed).expect("OS CSPRNG must be available");
    let out = SecretBytes::from_slice(&seed);
    seed.iter_mut().for_each(|b| *b = 0);
    out
}

/// Port of `public_key_from_seed`: derive the 32-byte public key from a
/// 32-byte seed (RFC 8032 section 5.1.5).
pub fn public_key_from_seed(seed: &[u8]) -> Result<[u8; PUBLIC_KEY_SIZE], SeedError> {
    let seed = check_seed(seed)?;
    let signing_key = SigningKey::from_bytes(seed);
    Ok(signing_key.verifying_key().to_bytes())
}

/// Port of `sign`: produce a 64-byte pure Ed25519 signature (RFC 8032
/// section 5.1.6). Signatures are deterministic: the same seed and message
/// always yield the same signature.
pub fn sign(seed: &[u8], message: &[u8]) -> Result<[u8; SIGNATURE_SIZE], SeedError> {
    let seed = check_seed(seed)?;
    let signing_key = SigningKey::from_bytes(seed);
    Ok(signing_key.sign(message).to_bytes())
}

/// Port of `verify`: verify a pure Ed25519 signature (RFC 8032 section
/// 5.1.7). Returns `true` only if every input is well formed and the
/// unbatched equation `[S]B == R + [k]A` holds; returns `false` (never
/// panics) for wrong lengths, an undecodable public key or `R`, or a
/// non-canonical scalar (`S >= L`).
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(public_key): Result<[u8; PUBLIC_KEY_SIZE], _> = public_key.try_into() else {
        return false;
    };
    let Ok(signature): Result<[u8; SIGNATURE_SIZE], _> = signature.try_into() else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&public_key) else {
        return false;
    };
    // Reject non-canonical public-key encodings. `VerifyingKey::from_bytes`
    // stores the input bytes verbatim (`compressed: CompressedEdwardsY(*bytes)`)
    // and merely checks the point decompresses (curve25519-dalek's
    // `decompress` reduces `y` mod p and silently accepts `x == 0` with
    // either sign bit), so it accepts encodings Python's `_point_decode`
    // rejects: `y >= p` and `x == 0` with the sign bit set. A canonical
    // encoding is exactly one that round-trips through decompress+recompress
    // unchanged (recompressing always produces the unique canonical bytes
    // for the point, i.e. the reduced `y` and the sign bit matching the
    // recovered `x`'s actual parity), so comparing against the original
    // bytes catches both cases in one check, and can never reject an
    // encoding Python would accept -- Python's own encoder only ever
    // produces canonical bytes for a valid point.
    if verifying_key.to_edwards().compress().to_bytes() != public_key {
        return false;
    }
    let signature = Signature::from_bytes(&signature);
    verifying_key.verify(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).expect("valid hex fixture")
    }

    fn flip_bit(data: &[u8], bit_index: usize) -> Vec<u8> {
        let mut out = data.to_vec();
        out[bit_index / 8] ^= 1 << (bit_index % 8);
        out
    }

    /// `_with_scalar`: replace the 32-byte S half of `signature` with `s`
    /// (little-endian), keeping the R half.
    fn with_scalar(signature: &[u8], s: &[u8; 32]) -> Vec<u8> {
        let mut out = signature[..32].to_vec();
        out.extend_from_slice(s);
        out
    }

    /// L = 2^252 + 27742317777372353535851937790883648493, little-endian.
    const L_BYTES: [u8; 32] = [
        237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 16,
    ];
    /// p = 2^255 - 19, little-endian.
    const P_BYTES: [u8; 32] = [
        237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
    ];
    /// p + 1, little-endian.
    const P_PLUS_1_BYTES: [u8; 32] = [
        238, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
    ];
    /// 2^255 - 1, little-endian.
    const TWO_255_MINUS_1_BYTES: [u8; 32] = [
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
    ];
    /// p - 1, little-endian: the order-2 point (0, -1).
    const P_MINUS_1_BYTES: [u8; 32] = [
        236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
    ];

    /// Adds L to a little-endian 253-ish-bit scalar `s` (< L), producing a
    /// value in `[L, 2L)`, which still fits in 32 bytes. Used to build the
    /// "S + L" malleability test case, mirroring Python's plain `int` `s + _L`.
    fn add_l(s: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = s[i] as u16 + L_BYTES[i] as u16 + carry;
            out[i] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "S + L overflowed 32 bytes");
        out
    }

    fn encode_y(y: &[u8; 32], sign_bit: bool) -> [u8; 32] {
        let mut out = *y;
        assert_eq!(
            out[31] & 0x80,
            0,
            "y must be < 2^255 before the sign bit is applied"
        );
        if sign_bit {
            out[31] |= 0x80;
        }
        out
    }

    fn small_y(value: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = value;
        out
    }

    struct Vector {
        name: &'static str,
        seed: &'static str,
        public: &'static str,
        message: &'static [u8],
        signature: &'static str,
    }

    // RFC 8032 section 7.1 test vectors, transcribed verbatim (including
    // TEST SHA(abc), whose message is SHA-512("abc")) from
    // `tests/test_crypto_ed25519.py::RFC_VECTORS`.
    fn vectors() -> Vec<Vector> {
        vec![
            Vector {
                name: "TEST 1",
                seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                public: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                message: &[],
                signature: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            },
            Vector {
                name: "TEST 2",
                seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                public: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                message: &[114],
                signature: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            },
            Vector {
                name: "TEST 3",
                seed: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                public: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                message: &[175, 130],
                signature: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            },
            Vector {
                name: "TEST SHA(abc)",
                seed: "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
                public: "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
                message: &[
                    221, 175, 53, 161, 147, 97, 122, 186, 204, 65, 115, 73, 174, 32, 65, 49, 18,
                    230, 250, 78, 137, 169, 126, 162, 10, 158, 238, 230, 75, 85, 211, 154, 33, 146,
                    153, 42, 39, 79, 193, 168, 54, 186, 60, 35, 163, 254, 235, 189, 69, 77, 68, 35,
                    100, 60, 232, 14, 42, 154, 201, 79, 165, 76, 164, 159,
                ],
                signature: "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
            },
        ]
    }

    #[test]
    fn sizes() {
        assert_eq!(SEED_SIZE, 32);
        assert_eq!(PUBLIC_KEY_SIZE, 32);
        assert_eq!(SIGNATURE_SIZE, 64);
    }

    #[test]
    fn public_key_derivation_matches_rfc_vectors() {
        for v in vectors() {
            let derived = public_key_from_seed(&hex(v.seed)).unwrap();
            assert_eq!(hex::encode(derived), v.public, "{}", v.name);
        }
    }

    #[test]
    fn signatures_match_rfc_vectors() {
        for v in vectors() {
            let signature = sign(&hex(v.seed), v.message).unwrap();
            assert_eq!(hex::encode(signature), v.signature, "{}", v.name);
        }
    }

    #[test]
    fn vector_signatures_verify() {
        for v in vectors() {
            assert!(
                verify(&hex(v.public), v.message, &hex(v.signature)),
                "{}",
                v.name
            );
        }
    }

    struct TamperFixture {
        seed: Vec<u8>,
        public_key: [u8; 32],
        message: Vec<u8>,
        signature: [u8; 64],
    }

    fn tamper_fixture() -> TamperFixture {
        let v = &vectors()[2];
        let seed = hex(v.seed);
        let public_key: [u8; 32] = hex(v.public).try_into().unwrap();
        let message = b"The quick brown fox jumps over the lazy dog".to_vec();
        let signature = sign(&seed, &message).unwrap();
        assert!(verify(&public_key, &message, &signature));
        TamperFixture {
            seed,
            public_key,
            message,
            signature,
        }
    }

    #[test]
    fn flipped_message_bit_rejected() {
        let f = tamper_fixture();
        for bit in [0, 7, 100, f.message.len() * 8 - 1] {
            let tampered = flip_bit(&f.message, bit);
            assert!(!verify(&f.public_key, &tampered, &f.signature));
        }
    }

    #[test]
    fn message_extension_and_truncation_rejected() {
        let f = tamper_fixture();
        let mut extended = f.message.clone();
        extended.push(0);
        assert!(!verify(&f.public_key, &extended, &f.signature));
        assert!(!verify(
            &f.public_key,
            &f.message[..f.message.len() - 1],
            &f.signature
        ));
        assert!(!verify(&f.public_key, b"", &f.signature));
    }

    #[test]
    fn flipped_signature_bits_rejected() {
        let f = tamper_fixture();
        for bit in [0, 100, 255, 256, 300, 511] {
            let tampered = flip_bit(&f.signature, bit);
            assert!(!verify(&f.public_key, &f.message, &tampered));
        }
    }

    #[test]
    fn wrong_public_key_rejected() {
        let f = tamper_fixture();
        let other = public_key_from_seed(&hex(vectors()[0].seed)).unwrap();
        assert!(!verify(&other, &f.message, &f.signature));
    }

    #[test]
    fn signature_swapped_between_messages_rejected() {
        let f = tamper_fixture();
        let other_sig = sign(&f.seed, b"another message").unwrap();
        assert!(!verify(&f.public_key, &f.message, &other_sig));
    }

    #[test]
    fn non_canonical_scalar_s_plus_l_rejected() {
        let f = tamper_fixture();
        let s: [u8; 32] = f.signature[32..].try_into().unwrap();
        // A lax verifier that reduces S mod L would accept this; RFC 8032
        // requires rejection.
        let malleable = with_scalar(&f.signature, &add_l(&s));
        assert!(!verify(&f.public_key, &f.message, &malleable));
    }

    #[test]
    fn scalar_equal_to_l_rejected() {
        let f = tamper_fixture();
        assert!(!verify(
            &f.public_key,
            &f.message,
            &with_scalar(&f.signature, &L_BYTES)
        ));
    }

    #[test]
    fn scalar_all_ones_rejected() {
        let f = tamper_fixture();
        assert!(!verify(
            &f.public_key,
            &f.message,
            &with_scalar(&f.signature, &[0xffu8; 32])
        ));
    }

    #[test]
    fn wrong_lengths_return_false() {
        let f = tamper_fixture();
        assert!(!verify(
            &f.public_key,
            &f.message,
            &f.signature[..f.signature.len() - 1]
        ));
        let mut extended_sig = f.signature.to_vec();
        extended_sig.push(0);
        assert!(!verify(&f.public_key, &f.message, &extended_sig));
        assert!(!verify(&f.public_key, &f.message, &[]));
        assert!(!verify(
            &f.public_key[..f.public_key.len() - 1],
            &f.message,
            &f.signature
        ));
        let mut extended_pk = f.public_key.to_vec();
        extended_pk.push(0);
        assert!(!verify(&extended_pk, &f.message, &f.signature));
        assert!(!verify(&[], &f.message, &f.signature));
        assert!(!verify(&[], &[], &[]));
    }

    #[test]
    fn verify_never_panics_on_random_garbage() {
        // Rust's type system already rules out Python's non-bytes-like /
        // released-memoryview cases (see the module doc comment and
        // DEVIATIONS.md); this keeps the fuzz-style robustness check for
        // arbitrary lengths and contents.
        let mut state: u64 = 0x2545F4914F6CDD1D;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..200 {
            let pk_len = [0usize, 31, 32, 32, 32, 33, 64][(next() % 7) as usize];
            let msg_len = (next() % 40) as usize;
            let sig_len = [0usize, 63, 64, 64, 64, 65][(next() % 6) as usize];
            let pk: Vec<u8> = (0..pk_len).map(|_| next() as u8).collect();
            let msg: Vec<u8> = (0..msg_len).map(|_| next() as u8).collect();
            let sig: Vec<u8> = (0..sig_len).map(|_| next() as u8).collect();
            // Must return, never panic.
            let _ = verify(&pk, &msg, &sig);
        }
    }

    #[test]
    fn public_key_y_not_below_p_rejected() {
        let f = tamper_fixture();
        for y in [P_BYTES, P_PLUS_1_BYTES, TWO_255_MINUS_1_BYTES] {
            for sign_bit in [false, true] {
                let bad_key = encode_y(&y, sign_bit);
                assert!(!verify(&bad_key, &f.message, &f.signature));
            }
        }
        // The check above uses `tamper_fixture`'s signature, which was made
        // under an unrelated key and so would never satisfy the group
        // equation for *any* of these bad keys -- it would pass even if
        // `verify` didn't reject non-canonical encodings at all, so on its
        // own it doesn't prove the canonicality check does anything.
        // `P_PLUS_1_BYTES` (y = p + 1) reduces mod p to y = 1, i.e. the
        // *identity* point: for the identity, `[S]B == R + [k]*O == R`
        // holds for *any* message and *any* `k`, so `(R, S) = ([5]B, 5)` is
        // a signature that genuinely satisfies the equation for the
        // point this bad encoding decodes to. Confirm both that Python
        // rejects it (oracle) and that our `verify` does too.
        forged_non_canonical_identity_rejected();
    }

    /// See the comment in `public_key_y_not_below_p_rejected`: builds a
    /// signature that satisfies the Ed25519 equation for the identity point
    /// -- `(R, S) = (encode([5]B), 5)`, valid for identity for any message
    /// -- via the Python prototype's own internal point-arithmetic helpers
    /// (`_scalar_mult`, `_point_encode`), and confirms:
    /// - it verifies under the *canonical* identity encoding (`y = 1`,
    ///   sign clear) in both implementations (not a bug: small-order keys
    ///   are accepted per the module doc comment);
    /// - it is rejected under every non-canonical encoding that decodes to
    ///   the same point (`y = 1` with the sign bit set; `y = p + 1`, sign
    ///   clear or set) -- the exact forged-signature evidence from
    ///   `DEVIATIONS.md` finding B-1.
    fn forged_non_canonical_identity_rejected() {
        let script = r#"
from zeropw.crypto import ed25519 as m

P = m._P
B = m._B


def encode_y(y_int, sign):
    b = bytearray(y_int.to_bytes(32, "little"))
    assert b[31] & 0x80 == 0
    if sign:
        b[31] |= 0x80
    return bytes(b)


R = m._point_encode(m._scalar_mult(5, B))
S = (5).to_bytes(32, "little")
sig = R + S
message = b"forged under a non-canonical identity encoding"

pk_canonical = (1).to_bytes(32, "little")
pk_signbit = encode_y(1, True)
pk_p_plus_1 = encode_y(P + 1, False)
pk_p_plus_1_signbit = encode_y(P + 1, True)

assert m.verify(pk_canonical, message, sig) is True
assert m.verify(pk_signbit, message, sig) is False
assert m.verify(pk_p_plus_1, message, sig) is False
assert m.verify(pk_p_plus_1_signbit, message, sig) is False

for value in (sig, message, pk_canonical, pk_signbit, pk_p_plus_1, pk_p_plus_1_signbit):
    print(value.hex())
"#;
        let out = crate::oracle::python(script);
        let mut lines = out.lines();
        let mut next_hex = move || hex(lines.next().expect("oracle line"));
        let sig = next_hex();
        let message = next_hex();
        let pk_canonical = next_hex();
        let pk_signbit = next_hex();
        let pk_p_plus_1 = next_hex();
        let pk_p_plus_1_signbit = next_hex();

        assert!(
            verify(&pk_canonical, &message, &sig),
            "canonical identity must still verify (small-order keys are accepted)"
        );
        assert!(
            !verify(&pk_signbit, &message, &sig),
            "y=1 with sign bit set (non-canonical identity) must be rejected"
        );
        assert!(
            !verify(&pk_p_plus_1, &message, &sig),
            "y=p+1 (non-canonical identity) must be rejected"
        );
        assert!(
            !verify(&pk_p_plus_1_signbit, &message, &sig),
            "y=p+1 with sign bit set must be rejected"
        );
    }

    #[test]
    fn r_y_not_below_p_rejected() {
        let f = tamper_fixture();
        let mut bad_sig = encode_y(&P_BYTES, false).to_vec();
        bad_sig.extend_from_slice(&f.signature[32..]);
        assert!(!verify(&f.public_key, &f.message, &bad_sig));
    }

    #[test]
    fn x_zero_with_sign_bit_rejected() {
        let f = tamper_fixture();
        // y = 1 is the identity (x = 0); the sign bit must then be clear.
        assert!(!verify(
            &encode_y(&small_y(1), true),
            &f.message,
            &f.signature
        ));
        let mut bad_sig = encode_y(&small_y(1), true).to_vec();
        bad_sig.extend_from_slice(&f.signature[32..]);
        assert!(!verify(&f.public_key, &f.message, &bad_sig));
        // y = p - 1 gives the order-2 point (0, -1); same rule applies.
        assert!(!verify(
            &encode_y(&P_MINUS_1_BYTES, true),
            &f.message,
            &f.signature
        ));
        // As in `public_key_y_not_below_p_rejected`, the assertions above use
        // a signature made under an unrelated key, so they pass regardless
        // of whether the canonicality check exists. Prove it actually does
        // something with signatures that genuinely satisfy the equation for
        // the *specific* points these bad encodings decode to.
        forged_non_canonical_identity_rejected();
        forged_non_canonical_order2_point_rejected();
    }

    /// Companion to `forged_non_canonical_identity_rejected`, for the order-2
    /// point (0, -1) (encoded as `y = p - 1`, `x = 0`). Unlike the identity,
    /// `[k]*A` only vanishes for this `A` when `k` is *even* (since `2*A ==
    /// O`), so a signature can't be built for an arbitrary message the way
    /// the identity one can -- the Python oracle fixes `R = encode(B)`,
    /// `S = 1` and searches short synthetic messages for one whose
    /// `_sha512_mod_l(R, bad_pk, message)` challenge happens to be even
    /// (~50% of messages qualify, so this terminates immediately).
    fn forged_non_canonical_order2_point_rejected() {
        let script = r#"
from zeropw.crypto import ed25519 as m

P = m._P
B = m._B


def encode_y(y_int, sign):
    b = bytearray(y_int.to_bytes(32, "little"))
    assert b[31] & 0x80 == 0
    if sign:
        b[31] |= 0x80
    return bytes(b)


p_minus_1 = P - 1
pk_canonical = encode_y(p_minus_1, False)
pk_signbit = encode_y(p_minus_1, True)

R = m._point_encode(B)
S = (1).to_bytes(32, "little")

message = None
for i in range(10_000):
    candidate = f"order2-forge-{i}".encode()
    k = m._sha512_mod_l(R, pk_signbit, candidate)
    if k % 2 == 0:
        message = candidate
        break
assert message is not None, "no even-challenge message found"
sig = R + S

assert m.verify(pk_canonical, message, sig) is True
assert m.verify(pk_signbit, message, sig) is False

for value in (sig, message, pk_canonical, pk_signbit):
    print(value.hex())
"#;
        let out = crate::oracle::python(script);
        let mut lines = out.lines();
        let mut next_hex = move || hex(lines.next().expect("oracle line"));
        let sig = next_hex();
        let message = next_hex();
        let pk_canonical = next_hex();
        let pk_signbit = next_hex();

        assert!(
            verify(&pk_canonical, &message, &sig),
            "canonical order-2 point must still verify (small-order keys are accepted)"
        );
        assert!(
            !verify(&pk_signbit, &message, &sig),
            "y=p-1 with sign bit set (non-canonical order-2 point) must be rejected"
        );
    }

    #[test]
    fn point_not_on_curve_rejected() {
        let f = tamper_fixture();
        // y = 2 has no matching x on edwards25519 (x^2 candidate is a non-residue).
        assert!(!verify(
            &encode_y(&small_y(2), false),
            &f.message,
            &f.signature
        ));
        let mut bad_sig = encode_y(&small_y(2), false).to_vec();
        bad_sig.extend_from_slice(&f.signature[32..]);
        assert!(!verify(&f.public_key, &f.message, &bad_sig));
    }

    #[test]
    fn small_order_public_key_does_not_panic() {
        let f = tamper_fixture();
        // The identity (y = 1, x = 0) decodes but cannot satisfy the
        // equation for a real signature.
        assert!(!verify(
            &encode_y(&small_y(1), false),
            &f.message,
            &f.signature
        ));
    }

    #[test]
    fn generate_seed_is_random() {
        let a = generate_seed();
        let b = generate_seed();
        assert_eq!(a.len(), 32);
        assert_eq!(b.len(), 32);
        assert!(!a.ct_eq(b.expose()));
    }

    #[test]
    fn random_round_trips() {
        for i in 0..12usize {
            let seed = generate_seed();
            let public_key = public_key_from_seed(seed.expose()).unwrap();
            let message: Vec<u8> = (0..i * 37).map(|j| (j % 251) as u8).collect();
            let signature = sign(seed.expose(), &message).unwrap();
            assert!(verify(&public_key, &message, &signature));
            let mut tampered = message.clone();
            tampered.push(b'x');
            assert!(!verify(&public_key, &tampered, &signature));
        }
    }

    #[test]
    fn signatures_are_deterministic() {
        let seed = generate_seed();
        assert_eq!(
            sign(seed.expose(), b"m").unwrap(),
            sign(seed.expose(), b"m").unwrap()
        );
        assert_ne!(
            sign(seed.expose(), b"m").unwrap(),
            sign(seed.expose(), b"n").unwrap()
        );
    }

    #[test]
    fn large_message() {
        let seed = generate_seed();
        let message: Vec<u8> = (0..200_000usize).map(|i| (i % 251) as u8).collect();
        let signature = sign(seed.expose(), &message).unwrap();
        let public_key = public_key_from_seed(seed.expose()).unwrap();
        assert!(verify(&public_key, &message, &signature));
    }

    #[test]
    fn bad_seed_errors_do_not_leak_seed() {
        let short = [0x5au8; 31];
        let err = sign(&short, b"m").unwrap_err();
        let short_hex = hex::encode(short);
        assert!(!err.to_string().contains(&short_hex));
        assert!(public_key_from_seed(&[0u8; 33]).is_err());
    }

    #[test]
    fn oracle_signature_matches_python() {
        let seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let message = b"zeropw rust/python ed25519 oracle check";
        let rust_sig = sign(&seed, message).unwrap();
        let rust_pub = public_key_from_seed(&seed).unwrap();

        let script = format!(
            "from zeropw.crypto import ed25519\n\
             seed = bytes.fromhex('{}')\n\
             message = bytes.fromhex('{}')\n\
             print(ed25519.sign(seed, message).hex())\n\
             print(ed25519.public_key_from_seed(seed).hex())",
            hex::encode(&seed),
            hex::encode(message),
        );
        let out = crate::oracle::python(&script);
        let mut lines = out.lines();
        let python_sig = lines.next().expect("signature line");
        let python_pub = lines.next().expect("public key line");
        assert_eq!(hex::encode(rust_sig), python_sig);
        assert_eq!(hex::encode(rust_pub), python_pub);

        // Cross-verify: Python must accept the Rust-produced signature, and
        // Rust must accept a signature produced entirely by Python.
        let verify_script = format!(
            "from zeropw.crypto import ed25519\n\
             pk = bytes.fromhex('{}')\n\
             message = bytes.fromhex('{}')\n\
             sig = bytes.fromhex('{}')\n\
             print(ed25519.verify(pk, message, sig))",
            python_pub,
            hex::encode(message),
            hex::encode(rust_sig),
        );
        assert_eq!(crate::oracle::python(&verify_script).trim(), "True");
    }

    /// Port of `tests/test_crypto_ed25519.py::OpenSSHInteropTests` (and its
    /// module-local wire helpers, lines 69-218 and 487-558): interop with
    /// OpenSSH's `ssh-keygen` in both directions. Skipped (like the Python
    /// `unittest.skipIf`) when `ssh-keygen` is not on `PATH`.
    ///
    /// These helpers deliberately re-implement just enough of the
    /// openssh-key-v1 and SSHSIG wire formats to drive `ssh-keygen`, rather
    /// than using `crate::sshwire` -- same rationale as the Python test's
    /// own module doc comment: this suite stays independent of sibling
    /// modules/work units.
    mod openssh_interop {
        use std::io::Write as _;
        use std::path::Path;
        use std::process::{Command, Output, Stdio};

        use sha2::{Digest, Sha256, Sha512};

        use super::*;

        const NAMESPACE: &[u8] = b"zeropw-test";

        fn ssh_keygen_available() -> bool {
            Command::new("ssh-keygen").arg("-h").output().is_ok()
        }

        fn ssh_uint32(n: u32) -> [u8; 4] {
            n.to_be_bytes()
        }

        fn ssh_string(data: &[u8]) -> Vec<u8> {
            let mut out = ssh_uint32(data.len() as u32).to_vec();
            out.extend_from_slice(data);
            out
        }

        /// Strict big-endian SSH wire reader, matching the Python test's `_Reader`.
        struct Reader<'a> {
            data: &'a [u8],
            pos: usize,
        }

        impl<'a> Reader<'a> {
            fn new(data: &'a [u8]) -> Self {
                Reader { data, pos: 0 }
            }

            fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
                if self.pos + n > self.data.len() {
                    return Err("truncated SSH wire data".to_string());
                }
                let chunk = &self.data[self.pos..self.pos + n];
                self.pos += n;
                Ok(chunk)
            }

            fn uint32(&mut self) -> Result<u32, String> {
                let bytes = self.take(4)?;
                Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
            }

            fn string(&mut self) -> Result<&'a [u8], String> {
                let n = self.uint32()? as usize;
                self.take(n)
            }

            fn rest(&self) -> &'a [u8] {
                &self.data[self.pos..]
            }
        }

        fn dearmor(text: &str, label: &str) -> Result<Vec<u8>, String> {
            use base64::Engine as _;
            let lines: Vec<&str> = text.trim().lines().map(str::trim).collect();
            let begin = format!("-----BEGIN {label}-----");
            let end = format!("-----END {label}-----");
            if lines.first() != Some(&begin.as_str()) || lines.last() != Some(&end.as_str()) {
                return Err(format!("not a {label} block"));
            }
            let joined: String = lines[1..lines.len() - 1].concat();
            // Python's `_dearmor` passes `validate=True`: a strict decode,
            // matching the `base64` crate's default (unlike `pybase64`,
            // which is deliberately lenient for KMS's own use).
            base64::engine::general_purpose::STANDARD
                .decode(joined)
                .map_err(|e| e.to_string())
        }

        fn armor(blob: &[u8], label: &str) -> String {
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD.encode(blob);
            let mut body = String::new();
            for chunk in b64.as_bytes().chunks(70) {
                if !body.is_empty() {
                    body.push('\n');
                }
                body.push_str(std::str::from_utf8(chunk).unwrap());
            }
            format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
        }

        fn parse_ed25519_public_blob(blob: &[u8]) -> Result<[u8; 32], String> {
            let mut reader = Reader::new(blob);
            if reader.string()? != b"ssh-ed25519" {
                return Err("not an ssh-ed25519 blob".to_string());
            }
            let key = reader.string()?;
            if key.len() != 32 || !reader.rest().is_empty() {
                return Err("malformed ssh-ed25519 blob".to_string());
            }
            Ok(key.try_into().unwrap())
        }

        /// Returns `(seed, public_key)` from an unencrypted openssh-key-v1
        /// ed25519 key.
        fn parse_openssh_private_key(pem: &str) -> Result<([u8; 32], [u8; 32]), String> {
            let blob = dearmor(pem, "OPENSSH PRIVATE KEY")?;
            let magic = b"openssh-key-v1\x00";
            if !blob.starts_with(magic) {
                return Err("bad openssh-key-v1 magic".to_string());
            }
            let mut reader = Reader::new(&blob[magic.len()..]);
            let cipher = reader.string()?.to_vec();
            let kdf = reader.string()?.to_vec();
            let _kdf_options = reader.string()?;
            if cipher != b"none" || kdf != b"none" {
                return Err("encrypted keys are not supported by this test parser".to_string());
            }
            if reader.uint32()? != 1 {
                return Err("expected exactly one key".to_string());
            }
            let public_from_header = parse_ed25519_public_blob(reader.string()?)?;
            let mut private = Reader::new(reader.string()?);
            let c1 = private.uint32()?;
            let c2 = private.uint32()?;
            if c1 != c2 {
                return Err("checkint mismatch".to_string());
            }
            if private.string()? != b"ssh-ed25519" {
                return Err("not an ed25519 private key".to_string());
            }
            let public = private.string()?.to_vec();
            let secret = private.string()?.to_vec();
            let _comment = private.string()?;
            let padding = private.rest();
            let expected_padding: Vec<u8> = (1..=padding.len() as u32).map(|i| i as u8).collect();
            if padding != expected_padding.as_slice() {
                return Err("bad private section padding".to_string());
            }
            if public.len() != 32 || secret.len() != 64 || secret[32..] != public[..] {
                return Err("malformed ed25519 private section".to_string());
            }
            if public != public_from_header {
                return Err("public key mismatch between header and private section".to_string());
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&secret[..32]);
            Ok((seed, public_from_header))
        }

        fn hash_digest(name: &[u8], message: &[u8]) -> Vec<u8> {
            match name {
                b"sha256" => {
                    let mut h = Sha256::new();
                    h.update(message);
                    h.finalize().to_vec()
                }
                b"sha512" => {
                    let mut h = Sha512::new();
                    h.update(message);
                    h.finalize().to_vec()
                }
                other => panic!(
                    "unsupported hash algorithm: {:?}",
                    String::from_utf8_lossy(other)
                ),
            }
        }

        fn sshsig_signed_data(namespace: &[u8], hash_algorithm: &[u8], message: &[u8]) -> Vec<u8> {
            let digest = hash_digest(hash_algorithm, message);
            let mut out = b"SSHSIG".to_vec();
            out.extend(ssh_string(namespace));
            out.extend(ssh_string(b""));
            out.extend(ssh_string(hash_algorithm));
            out.extend(ssh_string(&digest));
            out
        }

        /// `(public_key, namespace, hash_algorithm, raw_signature64)`.
        type SshsigParts = ([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>);

        fn parse_sshsig(text: &str) -> Result<SshsigParts, String> {
            let blob = dearmor(text, "SSH SIGNATURE")?;
            if !blob.starts_with(b"SSHSIG") {
                return Err("bad SSHSIG magic".to_string());
            }
            let mut reader = Reader::new(&blob[6..]);
            if reader.uint32()? != 1 {
                return Err("unsupported SSHSIG version".to_string());
            }
            let public_key = parse_ed25519_public_blob(reader.string()?)?;
            let namespace = reader.string()?.to_vec();
            let reserved = reader.string()?.to_vec();
            let hash_algorithm = reader.string()?.to_vec();
            let mut sig_reader = Reader::new(reader.string()?);
            if !reserved.is_empty() || !reader.rest().is_empty() {
                return Err("malformed SSHSIG".to_string());
            }
            if sig_reader.string()? != b"ssh-ed25519" {
                return Err("SSHSIG inner signature is not ssh-ed25519".to_string());
            }
            let raw_signature = sig_reader.string()?.to_vec();
            if !sig_reader.rest().is_empty() {
                return Err("trailing data in SSHSIG signature".to_string());
            }
            Ok((public_key, namespace, hash_algorithm, raw_signature))
        }

        fn build_sshsig(
            public_key: &[u8],
            namespace: &[u8],
            hash_algorithm: &[u8],
            raw_signature: &[u8],
        ) -> String {
            let mut key_blob = ssh_string(b"ssh-ed25519");
            key_blob.extend(ssh_string(public_key));
            let mut sig_blob = ssh_string(b"ssh-ed25519");
            sig_blob.extend(ssh_string(raw_signature));

            let mut blob = b"SSHSIG".to_vec();
            blob.extend(ssh_uint32(1));
            blob.extend(ssh_string(&key_blob));
            blob.extend(ssh_string(namespace));
            blob.extend(ssh_string(b""));
            blob.extend(ssh_string(hash_algorithm));
            blob.extend(ssh_string(&sig_blob));
            armor(&blob, "SSH SIGNATURE")
        }

        fn run_ssh_keygen(args: &[&str], cwd: &Path, stdin: Option<&[u8]>) -> Output {
            let mut command = Command::new("ssh-keygen");
            command.args(args).current_dir(cwd);
            if stdin.is_some() {
                command.stdin(Stdio::piped());
            }
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
            let mut child = command.spawn().expect("spawn ssh-keygen");
            if let Some(data) = stdin {
                child
                    .stdin
                    .take()
                    .expect("stdin pipe")
                    .write_all(data)
                    .expect("write ssh-keygen stdin");
            }
            child.wait_with_output().expect("wait for ssh-keygen")
        }

        struct Fixture {
            dir: tempfile::TempDir,
            key_path: std::path::PathBuf,
            seed: [u8; 32],
            public_key: [u8; 32],
        }

        fn setup() -> Fixture {
            let dir = tempfile::Builder::new()
                .prefix("zeropw-ed25519-")
                .tempdir()
                .expect("tempdir");
            let key_path = dir.path().join("key");
            let out = run_ssh_keygen(
                &[
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    "zeropw interop",
                    "-f",
                    key_path.to_str().unwrap(),
                ],
                dir.path(),
                None,
            );
            assert!(
                out.status.success(),
                "ssh-keygen key generation failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let pem = std::fs::read_to_string(&key_path).expect("read generated key");
            let (seed, public_key) = parse_openssh_private_key(&pem).expect("parse generated key");
            Fixture {
                dir,
                key_path,
                seed,
                public_key,
            }
        }

        #[test]
        fn derived_public_key_matches_openssh() {
            if !ssh_keygen_available() {
                eprintln!("skipping: ssh-keygen not installed");
                return;
            }
            let f = setup();
            use base64::Engine as _;
            let pub_text =
                std::fs::read_to_string(f.dir.path().join("key.pub")).expect("read key.pub");
            let mut fields = pub_text.split_whitespace();
            assert_eq!(fields.next(), Some("ssh-ed25519"));
            let blob = base64::engine::general_purpose::STANDARD
                .decode(fields.next().expect("public key field"))
                .expect("valid base64");
            let pub_from_file = parse_ed25519_public_blob(&blob).expect("valid public blob");
            assert_eq!(pub_from_file, f.public_key);
            assert_eq!(public_key_from_seed(&f.seed).unwrap(), f.public_key);
        }

        #[test]
        fn verify_signature_made_by_ssh_keygen() {
            if !ssh_keygen_available() {
                eprintln!("skipping: ssh-keygen not installed");
                return;
            }
            let f = setup();
            let data_path = f.dir.path().join("data");
            let mut message = b"zeropw ed25519 interop message\n".to_vec();
            let mut extra = [0u8; 100];
            getrandom::getrandom(&mut extra).expect("OS CSPRNG must be available");
            message.extend_from_slice(&extra);
            std::fs::write(&data_path, &message).expect("write data file");

            let namespace = std::str::from_utf8(NAMESPACE).unwrap();
            let out = run_ssh_keygen(
                &[
                    "-Y",
                    "sign",
                    "-f",
                    f.key_path.to_str().unwrap(),
                    "-n",
                    namespace,
                    data_path.to_str().unwrap(),
                ],
                f.dir.path(),
                None,
            );
            assert!(
                out.status.success(),
                "ssh-keygen -Y sign failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let sig_text =
                std::fs::read_to_string(f.dir.path().join("data.sig")).expect("read data.sig");
            let (public_key, namespace_out, hash_algorithm, raw_signature) =
                parse_sshsig(&sig_text).expect("parse SSHSIG armor");
            assert_eq!(public_key, f.public_key);
            assert_eq!(namespace_out, NAMESPACE);
            assert!(hash_algorithm == b"sha512" || hash_algorithm == b"sha256");
            assert_eq!(raw_signature.len(), 64);

            let signed = sshsig_signed_data(&namespace_out, &hash_algorithm, &message);
            assert!(verify(&public_key, &signed, &raw_signature));

            let mut tampered_message = message.clone();
            tampered_message.push(b'!');
            let tampered_signed =
                sshsig_signed_data(&namespace_out, &hash_algorithm, &tampered_message);
            assert!(!verify(&public_key, &tampered_signed, &raw_signature));

            let other_namespace_signed = sshsig_signed_data(b"other", &hash_algorithm, &message);
            assert!(!verify(
                &public_key,
                &other_namespace_signed,
                &raw_signature
            ));

            let tampered_sig = flip_bit(&raw_signature, 3);
            assert!(!verify(&public_key, &signed, &tampered_sig));
        }

        #[test]
        fn ssh_keygen_accepts_our_signature() {
            if !ssh_keygen_available() {
                eprintln!("skipping: ssh-keygen not installed");
                return;
            }
            let f = setup();
            let message = b"signed by zeropw's pure-python ed25519\n".to_vec();
            let signed = sshsig_signed_data(NAMESPACE, b"sha512", &message);
            let raw_signature = sign(&f.seed, &signed).unwrap();
            let sig_path = f.dir.path().join("ours.sig");
            std::fs::write(
                &sig_path,
                build_sshsig(&f.public_key, NAMESPACE, b"sha512", &raw_signature),
            )
            .expect("write signature armor");

            let namespace = std::str::from_utf8(NAMESPACE).unwrap();
            let good = run_ssh_keygen(
                &[
                    "-Y",
                    "check-novalidate",
                    "-n",
                    namespace,
                    "-s",
                    sig_path.to_str().unwrap(),
                ],
                f.dir.path(),
                Some(&message),
            );
            assert!(
                good.status.success(),
                "check-novalidate rejected our signature: {}",
                String::from_utf8_lossy(&good.stderr)
            );

            let mut bad_message = message.clone();
            bad_message.push(b'x');
            let bad_message_result = run_ssh_keygen(
                &[
                    "-Y",
                    "check-novalidate",
                    "-n",
                    namespace,
                    "-s",
                    sig_path.to_str().unwrap(),
                ],
                f.dir.path(),
                Some(&bad_message),
            );
            assert!(!bad_message_result.status.success());

            let bad_namespace_result = run_ssh_keygen(
                &[
                    "-Y",
                    "check-novalidate",
                    "-n",
                    "wrong-namespace",
                    "-s",
                    sig_path.to_str().unwrap(),
                ],
                f.dir.path(),
                Some(&message),
            );
            assert!(!bad_namespace_result.status.success());
        }
    }
}
