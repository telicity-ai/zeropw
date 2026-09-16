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
//! rejecting `y >= p` and the `x == 0` / sign-bit-set encoding. Critically,
//! plain `verify` does *not* reject small-order public keys or `R` values --
//! only `verify_strict` adds that `is_small_order()` check -- which matches
//! the Python docstring: "Small-order or mixed-order public keys and R
//! values are not rejected beyond what the RFC requires". Using
//! `verify_strict` here would be *stricter* than Python and so would itself
//! be an undocumented deviation; plain `verify` is the correct match.

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
}
