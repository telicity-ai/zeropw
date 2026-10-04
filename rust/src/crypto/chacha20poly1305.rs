//! Port of `zeropw/crypto/chacha20poly1305.py`: RFC 8439 ChaCha20-Poly1305 AEAD.
//!
//! The Python prototype hand-rolls RFC 8439 in pure Python because the
//! standard library has no AEAD primitive. PORTING.md §3.1 allows replacing
//! that with the audited `chacha20poly1305` crate (and, for the low-level
//! primitives the Python module also exposes, the `chacha20` and `poly1305`
//! crates it is built from) as long as the RFC 8439 test vectors still pass
//! and the public API keeps the same shape.
//!
//! Function names mirror the Python module (`chacha20_block`,
//! `chacha20_encrypt`, `poly1305_mac`, `poly1305_key_gen`, `encrypt`,
//! `decrypt`) so a reviewer can map each item back to `chacha20poly1305.py`.

use std::fmt;

use chacha20::ChaChaCore;
use chacha20::cipher::{KeyIvInit, StreamCipherCore, StreamCipherSeekCore};
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit as AeadKeyInit, Payload};
use poly1305::Poly1305;
use typenum::U10;

/// The 20-round ChaCha core (`chacha20::ChaCha20` is this wrapped in a
/// buffering `StreamCipherCoreWrapper`). Used directly, rather than through
/// the wrapper's `StreamCipherSeek`/`StreamCipher` traits, because the
/// wrapper's `remaining_blocks()` is `u32::MAX - counter` (not `+ 1`) and so
/// refuses to generate the block at counter == `u32::MAX` even though RFC
/// 8439 permits counters through `2**32 - 1` inclusive -- confirmed by
/// running into exactly that panic while testing the boundary. `ChaChaCore`
/// itself has no such check (its `write_keystream_block` is documented as
/// not checking remaining blocks), so using it directly keeps the full RFC
/// range and avoids a narrower-than-Python behaviour that would otherwise
/// need a `DEVIATIONS.md` row.
type Core = ChaChaCore<U10>;

/// `zeropw.crypto.chacha20poly1305.KEY_SIZE`.
pub const KEY_SIZE: usize = 32;
/// `zeropw.crypto.chacha20poly1305.NONCE_SIZE`.
pub const NONCE_SIZE: usize = 12;
/// `zeropw.crypto.chacha20poly1305.TAG_SIZE`.
pub const TAG_SIZE: usize = 16;

const BLOCK_SIZE: u64 = 64;
/// The AEAD construction starts the stream at counter 1 (counter 0 derives
/// the Poly1305 key), so at most 2**32 - 1 blocks are available per (key, nonce).
const MAX_COUNTER: u32 = u32::MAX;
const MAX_AEAD_MESSAGE: u64 = MAX_COUNTER as u64 * BLOCK_SIZE;

/// A key/nonce/data size error from `chacha20_block`, `chacha20_encrypt` or
/// `encrypt`. Mirrors the plain `ValueError` the Python functions raise for
/// bad sizes (as opposed to `AuthenticationError`, which only `decrypt` raises).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SizeError(String);

impl SizeError {
    fn invalid_size(name: &str, expected: usize, got: usize) -> Self {
        SizeError(format!(
            "{name} must be exactly {expected} bytes, got {got}"
        ))
    }
    fn message(message: impl Into<String>) -> Self {
        SizeError(message.into())
    }
}

impl fmt::Display for SizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SizeError {}

/// Port of `zeropw.crypto.chacha20poly1305.AuthenticationError`.
///
/// Python raises this single exception type (a `ValueError` subclass) for
/// *every* failure of `decrypt`: a tag that does not verify, a wrong key,
/// nonce or associated data, a too-short input, wrong key/nonce sizes, or a
/// non-bytes-like argument. The last case (non-bytes-like / released
/// memoryview) cannot occur in Rust, whose `decrypt` takes `&[u8]` directly;
/// see `DEVIATIONS.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationError(String);

impl AuthenticationError {
    fn new(message: impl Into<String>) -> Self {
        AuthenticationError(message.into())
    }
}

impl fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AuthenticationError {}

fn require_len<'a>(name: &str, data: &'a [u8], expected: usize) -> Result<&'a [u8], SizeError> {
    if data.len() != expected {
        return Err(SizeError::invalid_size(name, expected, data.len()));
    }
    Ok(data)
}

fn require_len_auth<'a>(
    name: &str,
    data: &'a [u8],
    expected: usize,
) -> Result<&'a [u8], AuthenticationError> {
    if data.len() != expected {
        return Err(AuthenticationError::new(format!(
            "{name} must be exactly {expected} bytes, got {}",
            data.len()
        )));
    }
    Ok(data)
}

// ---------------------------------------------------------------------------
// ChaCha20 (RFC 8439 sections 2.1 - 2.4)
// ---------------------------------------------------------------------------

/// Port of `chacha20_block`: the ChaCha20 block function (RFC 8439 section
/// 2.3), returning 64 keystream bytes for block `counter`.
///
/// `key` must be `KEY_SIZE` bytes and `nonce` `NONCE_SIZE` bytes; wrong sizes
/// return `SizeError`. Unlike Python, `counter` is a `u32`, so the
/// out-of-range / non-integer counter checks Python performs at runtime
/// cannot occur here (see `DEVIATIONS.md`).
pub fn chacha20_block(key: &[u8], counter: u32, nonce: &[u8]) -> Result<[u8; 64], SizeError> {
    let key = require_len("key", key, KEY_SIZE)?;
    let nonce = require_len("nonce", nonce, NONCE_SIZE)?;
    let mut core = Core::new(
        chacha20::Key::from_slice(key),
        chacha20::Nonce::from_slice(nonce),
    );
    core.set_block_pos(counter);
    let mut block = chacha20::cipher::Block::<Core>::default();
    core.write_keystream_block(&mut block);
    let mut out = [0u8; 64];
    out.copy_from_slice(&block);
    Ok(out)
}

/// Port of `chacha20_encrypt`: the ChaCha20 stream cipher (RFC 8439 section
/// 2.4). XORs `data` with the keystream starting at block `counter`.
/// Encryption and decryption are the same operation.
pub fn chacha20_encrypt(
    key: &[u8],
    counter: u32,
    nonce: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, SizeError> {
    let key = require_len("key", key, KEY_SIZE)?;
    let nonce = require_len("nonce", nonce, NONCE_SIZE)?;
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let n_blocks = (data.len() as u64).div_ceil(BLOCK_SIZE);
    if u64::from(counter) + n_blocks - 1 > u64::from(MAX_COUNTER) {
        return Err(SizeError::message(
            "data is too long for the 32-bit block counter",
        ));
    }
    let mut core = Core::new(
        chacha20::Key::from_slice(key),
        chacha20::Nonce::from_slice(nonce),
    );
    core.set_block_pos(counter);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(BLOCK_SIZE as usize) {
        let mut block = chacha20::cipher::Block::<Core>::default();
        core.write_keystream_block(&mut block);
        out.extend(chunk.iter().zip(block.iter()).map(|(&d, &k)| d ^ k));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Poly1305 (RFC 8439 sections 2.5 and 2.6)
// ---------------------------------------------------------------------------

/// Port of `poly1305_mac`: the Poly1305 one-time authenticator (RFC 8439
/// section 2.5), returning a 16-byte tag. `key` is the 32-byte one-time key
/// `r || s`, which must never be reused across messages.
pub fn poly1305_mac(key: &[u8], msg: &[u8]) -> Result<[u8; 16], SizeError> {
    let key = require_len("key", key, 32)?;
    let mac = Poly1305::new(poly1305::Key::from_slice(key));
    let tag = mac.compute_unpadded(msg);
    Ok(tag.into())
}

/// Port of `poly1305_key_gen`: derive the 32-byte Poly1305 one-time key (RFC
/// 8439 section 2.6) as the first 32 bytes of the ChaCha20 block with counter 0.
pub fn poly1305_key_gen(key: &[u8], nonce: &[u8]) -> Result<[u8; 32], SizeError> {
    let block = chacha20_block(key, 0, nonce)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&block[..32]);
    Ok(out)
}

// ---------------------------------------------------------------------------
// AEAD_CHACHA20_POLY1305 (RFC 8439 section 2.8)
// ---------------------------------------------------------------------------

/// Port of `encrypt`: AEAD encryption; returns `ciphertext || tag`.
///
/// `key` must be `KEY_SIZE` bytes and `nonce` `NONCE_SIZE` bytes; other sizes
/// return `SizeError`. `aad` is authenticated but not encrypted. The nonce
/// must never repeat under the same key.
pub fn encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SizeError> {
    let key = require_len("key", key, KEY_SIZE)?;
    let nonce = require_len("nonce", nonce, NONCE_SIZE)?;
    if plaintext.len() as u64 > MAX_AEAD_MESSAGE {
        return Err(SizeError::message(
            "plaintext is too long for the 32-bit block counter",
        ));
    }
    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    let nonce = chacha20poly1305::Nonce::from_slice(nonce);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SizeError::message("plaintext is too long for the 32-bit block counter"))
}

/// Port of `decrypt`: AEAD decryption of `ciphertext || tag`.
///
/// Raises `AuthenticationError` for every failure: bad tag, wrong key, nonce
/// or `aad`, an input shorter than the tag, or wrong key/nonce sizes. The tag
/// is verified before any decryption happens (the underlying crate rejects
/// the ciphertext outright on a bad tag), so no plaintext is ever produced
/// for unauthenticated input.
pub fn decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AuthenticationError> {
    let key = require_len_auth("key", key, KEY_SIZE)?;
    let nonce = require_len_auth("nonce", nonce, NONCE_SIZE)?;
    if ciphertext_and_tag.len() < TAG_SIZE {
        return Err(AuthenticationError::new(
            "input is shorter than the authentication tag",
        ));
    }
    if (ciphertext_and_tag.len() - TAG_SIZE) as u64 > MAX_AEAD_MESSAGE {
        return Err(AuthenticationError::new(
            "ciphertext is too long for the 32-bit block counter",
        ));
    }
    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    let nonce = chacha20poly1305::Nonce::from_slice(nonce);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext_and_tag,
                aad,
            },
        )
        .map_err(|_| AuthenticationError::new("authentication failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let cleaned: String = text
            .chars()
            .filter(|c| !c.is_whitespace() && *c != ':')
            .collect();
        hex::decode(cleaned).expect("valid hex fixture")
    }

    // --- RFC 8439 section 2.4.2 / 2.8.2 plaintext ("sunscreen") -----------
    fn sunscreen() -> Vec<u8> {
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one \
tip for the future, sunscreen would be it."
            .to_vec()
    }

    // --- RFC 8439 section 2.3.2: block function test vector ---------------
    fn block_key() -> Vec<u8> {
        hex(
            "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f",
        )
    }
    fn block_nonce() -> Vec<u8> {
        hex("00:00:00:09:00:00:00:4a:00:00:00:00")
    }
    fn block_output() -> Vec<u8> {
        hex("10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4
             c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e
             d2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2
             b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e")
    }

    // --- RFC 8439 appendix A.1 test vector #1: all-zero key and nonce -----
    fn zero_block_output() -> Vec<u8> {
        hex("76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28
             bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7
             da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37
             6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86")
    }

    // --- RFC 8439 section 2.4.2: encryption test vector --------------------
    fn enc_nonce() -> Vec<u8> {
        hex("00:00:00:00:00:00:00:4a:00:00:00:00")
    }
    fn enc_ciphertext() -> Vec<u8> {
        hex("6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81
             e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b
             f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57
             16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8
             07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e
             52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36
             5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42
             87 4d")
    }

    // --- RFC 8439 section 2.5.2: Poly1305 test vector -----------------------
    fn poly_key() -> Vec<u8> {
        hex(
            "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b",
        )
    }
    fn poly_message() -> Vec<u8> {
        b"Cryptographic Forum Research Group".to_vec()
    }
    fn poly_tag() -> Vec<u8> {
        hex("a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9")
    }

    // --- RFC 8439 section 2.6.2: Poly1305 key generation test vector -------
    fn keygen_key() -> Vec<u8> {
        hex(
            "80:81:82:83:84:85:86:87:88:89:8a:8b:8c:8d:8e:8f:90:91:92:93:94:95:96:97:98:99:9a:9b:9c:9d:9e:9f",
        )
    }
    fn keygen_nonce() -> Vec<u8> {
        hex("00:00:00:00:00:01:02:03:04:05:06:07")
    }
    fn keygen_output() -> Vec<u8> {
        hex(
            "8a d5 a0 8b 90 5f 81 cc 81 50 40 27 4a b2 94 71 a8 33 b6 37 e3 fd 0d a5 08 db b8 e2 fd d1 a6 46",
        )
    }

    // --- RFC 8439 section 2.8.2: AEAD encryption test vector ---------------
    fn aead_aad() -> Vec<u8> {
        hex("50:51:52:53:c0:c1:c2:c3:c4:c5:c6:c7")
    }
    fn aead_nonce() -> Vec<u8> {
        hex("07:00:00:00:40:41:42:43:44:45:46:47")
    }
    fn aead_one_time_key() -> Vec<u8> {
        hex(
            "7b:ac:2b:25:2d:b4:47:af:09:b6:7a:55:a4:e9:55:84:0a:e1:d6:73:10:75:d9:eb:2a:93:75:78:3e:d5:53:ff",
        )
    }
    fn aead_ciphertext() -> Vec<u8> {
        hex("d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2
             a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6
             3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b
             1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36
             92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58
             fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc
             3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b
             61 16")
    }
    fn aead_tag() -> Vec<u8> {
        hex("1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91")
    }

    // --- RFC 8439 appendix A.5: AEAD decryption test vector ----------------
    fn a5_key() -> Vec<u8> {
        hex("1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0
             47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0")
    }
    fn a5_ciphertext() -> Vec<u8> {
        hex("64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd
             5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2
             4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0
             bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf
             33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81
             14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55
             97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38
             36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4
             b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9
             90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e
             af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a
             0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a
             0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e
             ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10
             49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30
             30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29
             a6 ad 5c b4 02 2b 02 70 9b")
    }
    fn a5_nonce() -> Vec<u8> {
        hex("00 00 00 00 01 02 03 04 05 06 07 08")
    }
    fn a5_aad() -> Vec<u8> {
        hex("f3 33 88 86 00 00 00 00 00 00 4e 91")
    }
    fn a5_tag() -> Vec<u8> {
        hex("ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38")
    }
    fn a5_plaintext() -> Vec<u8> {
        "Internet-Drafts are draft documents valid for a maximum of six months \
and may be updated, replaced, or obsoleted by other documents at any \
time. It is inappropriate to use Internet-Drafts as reference material \
or to cite them other than as /\u{201c}work in progress./\u{201d}"
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn sizes_match_rfc() {
        assert_eq!(KEY_SIZE, 32);
        assert_eq!(NONCE_SIZE, 12);
        assert_eq!(TAG_SIZE, 16);
    }

    #[test]
    fn block_function_rfc_2_3_2() {
        assert_eq!(block_output().len(), 64);
        assert_eq!(
            chacha20_block(&block_key(), 1, &block_nonce())
                .unwrap()
                .to_vec(),
            block_output()
        );
    }

    #[test]
    fn block_function_zero_key_appendix_a1() {
        assert_eq!(
            chacha20_block(&[0u8; 32], 0, &[0u8; 12]).unwrap().to_vec(),
            zero_block_output()
        );
    }

    #[test]
    fn block_counter_changes_output() {
        let first = chacha20_block(&block_key(), 0, &block_nonce()).unwrap();
        let second = chacha20_block(&block_key(), 1, &block_nonce()).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn block_rejects_bad_sizes() {
        // Counter out-of-range / non-integer checks Python performs at
        // runtime cannot occur here: `counter` is `u32`. See DEVIATIONS.md.
        assert!(chacha20_block(&[0u8; 31], 0, &[0u8; 12]).is_err());
        assert!(chacha20_block(&[0u8; 33], 0, &[0u8; 12]).is_err());
        assert!(chacha20_block(&[0u8; 32], 0, &[0u8; 11]).is_err());
        assert!(chacha20_block(&[0u8; 32], 0, &[0u8; 16]).is_err());
    }

    #[test]
    fn block_accepts_max_counter() {
        assert_eq!(
            chacha20_block(&[0u8; 32], 0xFFFF_FFFF, &[0u8; 12])
                .unwrap()
                .len(),
            64
        );
    }

    #[test]
    fn sunscreen_plaintext_length() {
        assert_eq!(sunscreen().len(), 114);
    }

    #[test]
    fn encrypt_stream_rfc_2_4_2() {
        assert_eq!(enc_ciphertext().len(), 114);
        assert_eq!(
            chacha20_encrypt(&block_key(), 1, &enc_nonce(), &sunscreen()).unwrap(),
            enc_ciphertext()
        );
    }

    #[test]
    fn decrypt_stream_rfc_2_4_2_is_symmetric() {
        assert_eq!(
            chacha20_encrypt(&block_key(), 1, &enc_nonce(), &enc_ciphertext()).unwrap(),
            sunscreen()
        );
    }

    #[test]
    fn zero_key_appendix_a2() {
        assert_eq!(
            chacha20_encrypt(&[0u8; 32], 0, &[0u8; 12], &[0u8; 64]).unwrap(),
            zero_block_output()
        );
    }

    #[test]
    fn empty_data() {
        assert_eq!(
            chacha20_encrypt(&block_key(), 1, &enc_nonce(), &[]).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn partial_block_matches_prefix_of_keystream() {
        let full = chacha20_encrypt(&block_key(), 1, &enc_nonce(), &[0u8; 128]).unwrap();
        assert_eq!(
            chacha20_encrypt(&block_key(), 1, &enc_nonce(), &[0u8; 70]).unwrap(),
            full[..70]
        );
        assert_eq!(
            full[..64],
            chacha20_block(&block_key(), 1, &enc_nonce()).unwrap()
        );
        assert_eq!(
            full[64..],
            chacha20_block(&block_key(), 2, &enc_nonce()).unwrap()
        );
    }

    #[test]
    fn counter_overflow_rejected() {
        assert!(chacha20_encrypt(&block_key(), 0xFFFF_FFFF, &enc_nonce(), &[0u8; 65]).is_err());
        assert_eq!(
            chacha20_encrypt(&block_key(), 0xFFFF_FFFF, &enc_nonce(), &[0u8; 64])
                .unwrap()
                .len(),
            64
        );
    }

    #[test]
    fn mac_rfc_2_5_2() {
        assert_eq!(poly_message().len(), 34);
        assert_eq!(
            poly1305_mac(&poly_key(), &poly_message()).unwrap().to_vec(),
            poly_tag()
        );
    }

    #[test]
    fn mac_all_zero_key_appendix_a3_vector_1() {
        assert_eq!(
            poly1305_mac(&[0u8; 32], &[0u8; 64]).unwrap().to_vec(),
            vec![0u8; 16]
        );
    }

    #[test]
    fn mac_with_r_zero_returns_s_appendix_a3_vector_2() {
        let s = hex("36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e");
        let mut key = vec![0u8; 16];
        key.extend_from_slice(&s);
        assert_eq!(
            poly1305_mac(&key, b"any message at all").unwrap().to_vec(),
            s
        );
        assert_eq!(poly1305_mac(&key, b"").unwrap().to_vec(), s);
    }

    #[test]
    fn mac_empty_message() {
        assert_eq!(
            poly1305_mac(&poly_key(), b"").unwrap().to_vec(),
            poly_key()[16..]
        );
    }

    #[test]
    fn mac_rejects_wrong_key_size() {
        let key = poly_key();
        assert!(poly1305_mac(&key[..31], &poly_message()).is_err());
        let mut too_long = key.clone();
        too_long.push(0);
        assert!(poly1305_mac(&too_long, &poly_message()).is_err());
    }

    #[test]
    fn key_gen_rfc_2_6_2() {
        assert_eq!(
            poly1305_key_gen(&keygen_key(), &keygen_nonce())
                .unwrap()
                .to_vec(),
            keygen_output()
        );
    }

    #[test]
    fn key_gen_zero_appendix_a4() {
        assert_eq!(
            poly1305_key_gen(&[0u8; 32], &[0u8; 12]).unwrap().to_vec(),
            zero_block_output()[..32]
        );
    }

    #[test]
    fn key_gen_rfc_2_8_2_one_time_key() {
        assert_eq!(
            poly1305_key_gen(&aead_aad_key(), &aead_nonce())
                .unwrap()
                .to_vec(),
            aead_one_time_key()
        );
    }

    fn aead_aad_key() -> Vec<u8> {
        keygen_key()
    }

    #[test]
    fn encrypt_rfc_2_8_2() {
        let out = encrypt(&aead_aad_key(), &aead_nonce(), &sunscreen(), &aead_aad()).unwrap();
        assert_eq!(out.len(), sunscreen().len() + TAG_SIZE);
        assert_eq!(out[..out.len() - TAG_SIZE], aead_ciphertext());
        assert_eq!(out[out.len() - TAG_SIZE..], aead_tag());
    }

    #[test]
    fn decrypt_rfc_2_8_2() {
        let mut sealed = aead_ciphertext();
        sealed.extend_from_slice(&aead_tag());
        assert_eq!(
            decrypt(&aead_aad_key(), &aead_nonce(), &sealed, &aead_aad()).unwrap(),
            sunscreen()
        );
    }

    #[test]
    fn decrypt_appendix_a5() {
        assert_eq!(a5_ciphertext().len(), 265);
        assert_eq!(a5_plaintext().len(), 265);
        let mut sealed = a5_ciphertext();
        sealed.extend_from_slice(&a5_tag());
        assert_eq!(
            decrypt(&a5_key(), &a5_nonce(), &sealed, &a5_aad()).unwrap(),
            a5_plaintext()
        );
    }

    #[test]
    fn encrypt_appendix_a5_reproduces_vector() {
        let mut expected = a5_ciphertext();
        expected.extend_from_slice(&a5_tag());
        assert_eq!(
            encrypt(&a5_key(), &a5_nonce(), &a5_plaintext(), &a5_aad()).unwrap(),
            expected
        );
    }

    fn sealed_aead() -> Vec<u8> {
        let mut sealed = aead_ciphertext();
        sealed.extend_from_slice(&aead_tag());
        sealed
    }

    #[test]
    fn ciphertext_bit_flip_rejected() {
        let sealed = sealed_aead();
        for position in [0usize, 1, 63, 64, aead_ciphertext().len() - 1] {
            for bit in [0u8, 7] {
                let mut tampered = sealed.clone();
                tampered[position] ^= 1 << bit;
                assert!(decrypt(&aead_aad_key(), &aead_nonce(), &tampered, &aead_aad()).is_err());
            }
        }
    }

    #[test]
    fn every_tag_bit_flip_rejected() {
        let sealed = sealed_aead();
        let ct_len = aead_ciphertext().len();
        for bit in 0..TAG_SIZE * 8 {
            let mut tampered = sealed.clone();
            tampered[ct_len + bit / 8] ^= 1 << (bit % 8);
            assert!(decrypt(&aead_aad_key(), &aead_nonce(), &tampered, &aead_aad()).is_err());
        }
    }

    #[test]
    fn aad_mismatch_rejected() {
        let sealed = sealed_aead();
        assert!(decrypt(&aead_aad_key(), &aead_nonce(), &sealed, b"").is_err());
        let mut longer = aead_aad();
        longer.push(0);
        assert!(decrypt(&aead_aad_key(), &aead_nonce(), &sealed, &longer).is_err());
        assert!(
            decrypt(
                &aead_aad_key(),
                &aead_nonce(),
                &sealed,
                &aead_aad()[..aead_aad().len() - 1]
            )
            .is_err()
        );
        let mut flipped = aead_aad();
        flipped[0] ^= 0x01;
        assert!(decrypt(&aead_aad_key(), &aead_nonce(), &sealed, &flipped).is_err());
    }

    #[test]
    fn nonce_mismatch_rejected() {
        let sealed = sealed_aead();
        let mut other = aead_nonce();
        *other.last_mut().unwrap() ^= 0x01;
        assert!(decrypt(&aead_aad_key(), &other, &sealed, &aead_aad()).is_err());
        assert!(decrypt(&aead_aad_key(), &[0u8; NONCE_SIZE], &sealed, &aead_aad()).is_err());
    }

    #[test]
    fn key_mismatch_rejected() {
        let sealed = sealed_aead();
        let mut other = aead_aad_key();
        other[0] ^= 0x80;
        assert!(decrypt(&other, &aead_nonce(), &sealed, &aead_aad()).is_err());
        assert!(decrypt(&[0u8; KEY_SIZE], &aead_nonce(), &sealed, &aead_aad()).is_err());
    }

    #[test]
    fn truncated_ciphertext_rejected() {
        let sealed = sealed_aead();
        assert!(decrypt(&aead_aad_key(), &aead_nonce(), &sealed[1..], &aead_aad()).is_err());
        assert!(
            decrypt(
                &aead_aad_key(),
                &aead_nonce(),
                &sealed[..sealed.len() - 1],
                &aead_aad()
            )
            .is_err()
        );
        let mut extended = sealed.clone();
        extended.push(0);
        assert!(decrypt(&aead_aad_key(), &aead_nonce(), &extended, &aead_aad()).is_err());
    }

    #[test]
    fn input_shorter_than_tag_rejected() {
        let sealed = sealed_aead();
        for length in 0..TAG_SIZE {
            assert!(
                decrypt(
                    &aead_aad_key(),
                    &aead_nonce(),
                    &sealed[..length],
                    &aead_aad()
                )
                .is_err()
            );
        }
        assert!(decrypt(&aead_aad_key(), &aead_nonce(), &[], &aead_aad()).is_err());
    }

    #[test]
    fn swapped_ciphertext_and_tag_rejected() {
        let mut swapped = aead_tag();
        swapped.extend_from_slice(&aead_ciphertext());
        assert!(decrypt(&aead_aad_key(), &aead_nonce(), &swapped, &aead_aad()).is_err());
    }

    #[test]
    fn tag_only_input_rejected_when_plaintext_was_not_empty() {
        assert!(decrypt(&aead_aad_key(), &aead_nonce(), &aead_tag(), &aead_aad()).is_err());
    }

    #[test]
    fn encrypt_rejects_wrong_key_size() {
        for bad in [
            vec![],
            vec![0u8; 16],
            vec![0u8; 31],
            vec![0u8; 33],
            vec![0u8; 64],
        ] {
            assert!(encrypt(&bad, &aead_nonce(), b"x", b"").is_err());
        }
    }

    #[test]
    fn encrypt_rejects_wrong_nonce_size() {
        for bad in [
            vec![],
            vec![0u8; 8],
            vec![0u8; 11],
            vec![0u8; 13],
            vec![0u8; 16],
            vec![0u8; 24],
        ] {
            assert!(encrypt(&aead_aad_key(), &bad, b"x", b"").is_err());
        }
    }

    #[test]
    fn decrypt_rejects_wrong_key_size_with_authentication_error() {
        let sealed = sealed_aead();
        for bad in [
            vec![],
            aead_aad_key()[..31].to_vec(),
            [aead_aad_key(), vec![0]].concat(),
        ] {
            assert!(decrypt(&bad, &aead_nonce(), &sealed, &aead_aad()).is_err());
        }
    }

    #[test]
    fn decrypt_rejects_wrong_nonce_size_with_authentication_error() {
        let sealed = sealed_aead();
        for bad in [
            vec![],
            aead_nonce()[..11].to_vec(),
            [aead_nonce(), vec![0]].concat(),
            vec![0u8; 16],
        ] {
            assert!(decrypt(&aead_aad_key(), &bad, &sealed, &aead_aad()).is_err());
        }
    }

    #[test]
    fn round_trip_various_lengths_with_aad() {
        let key = vec![0x42u8; KEY_SIZE];
        let aad = b"synthetic-associated-data";
        for length in [0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 1000, 4096 + 3] {
            let nonce = {
                let mut n = vec![0u8; NONCE_SIZE];
                n[0] = length as u8;
                n
            };
            let plaintext = vec![0x24u8; length];
            let sealed = encrypt(&key, &nonce, &plaintext, aad).unwrap();
            assert_eq!(sealed.len(), length + TAG_SIZE);
            assert_eq!(decrypt(&key, &nonce, &sealed, aad).unwrap(), plaintext);
        }
    }

    #[test]
    fn round_trip_empty_plaintext() {
        let key = vec![0x11u8; KEY_SIZE];
        let nonce = vec![0x22u8; NONCE_SIZE];
        let sealed = encrypt(&key, &nonce, b"", b"aad").unwrap();
        assert_eq!(sealed.len(), TAG_SIZE);
        assert_eq!(
            decrypt(&key, &nonce, &sealed, b"aad").unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn round_trip_empty_aad_default() {
        let key = vec![0x33u8; KEY_SIZE];
        let nonce = vec![0x44u8; NONCE_SIZE];
        let plaintext = b"synthetic secret value";
        let sealed = encrypt(&key, &nonce, plaintext, b"").unwrap();
        assert_eq!(decrypt(&key, &nonce, &sealed, b"").unwrap(), plaintext);
    }

    /// Port of `tests/test_crypto_chacha20poly1305.py::
    /// test_round_trip_empty_plaintext_and_empty_aad`.
    #[test]
    fn round_trip_empty_plaintext_and_empty_aad() {
        let key = vec![0xabu8; KEY_SIZE];
        let nonce = vec![0xcdu8; NONCE_SIZE];
        let sealed = encrypt(&key, &nonce, b"", b"").unwrap();
        assert_eq!(sealed.len(), TAG_SIZE);
        assert_eq!(
            decrypt(&key, &nonce, &sealed, b"").unwrap(),
            Vec::<u8>::new()
        );
    }

    /// Port of `tests/test_crypto_chacha20poly1305.py::
    /// PerformanceTests::test_one_mebibyte_encrypts_in_reasonable_time`,
    /// minus its timing budget (finding B-6): this crate's encrypt/decrypt
    /// are backed by audited, non-Python-interpreted crates, so the
    /// "reasonable time" assertion the Python prototype needs (to catch its
    /// pure-Python implementation going quadratic) has no equivalent
    /// failure mode here. The multi-block correctness check on a large
    /// message is kept.
    ///
    /// This is the only test in `PerformanceTests` on the Python side for
    /// this module (`test_crypto_chacha20poly1305.py`'s `PerformanceTests`
    /// has exactly one test method), so this one port is the complete
    /// mapping for it; ed25519's own `PerformanceTests` test
    /// (`test_sign_and_verify_under_50ms`) is a separate Python class in a
    /// separate file and is ported in `crypto/ed25519.rs` instead (finding
    /// B-R2-2) -- a small-payload chacha encrypt/decrypt loop does not
    /// stand in for it.
    #[test]
    fn one_mebibyte_round_trips() {
        let key = vec![0x5au8; KEY_SIZE];
        let nonce = vec![0xa5u8; NONCE_SIZE];
        let plaintext = vec![0x99u8; 1024 * 1024];
        let sealed = encrypt(&key, &nonce, &plaintext, b"aad").unwrap();
        assert_eq!(sealed.len(), plaintext.len() + TAG_SIZE);
        assert_eq!(decrypt(&key, &nonce, &sealed, b"aad").unwrap(), plaintext);
    }

    #[test]
    fn encryption_is_deterministic_and_nonce_dependent() {
        let key = vec![0x55u8; KEY_SIZE];
        let nonce_a = vec![0x01u8; NONCE_SIZE];
        let nonce_b = vec![0x02u8; NONCE_SIZE];
        let plaintext = b"same plaintext";
        assert_eq!(
            encrypt(&key, &nonce_a, plaintext, b"").unwrap(),
            encrypt(&key, &nonce_a, plaintext, b"").unwrap()
        );
        assert_ne!(
            encrypt(&key, &nonce_a, plaintext, b"").unwrap(),
            encrypt(&key, &nonce_b, plaintext, b"").unwrap()
        );
    }

    #[test]
    fn ciphertext_differs_from_plaintext() {
        let key = vec![0x66u8; KEY_SIZE];
        let nonce = vec![0x77u8; NONCE_SIZE];
        let plaintext = vec![0u8; 200];
        let sealed = encrypt(&key, &nonce, &plaintext, b"").unwrap();
        assert_ne!(sealed[..200], plaintext[..]);
    }

    #[test]
    fn aad_is_not_included_in_output() {
        let key = vec![0x88u8; KEY_SIZE];
        let nonce = vec![0x99u8; NONCE_SIZE];
        let aad = b"synthetic-aad-marker-that-must-not-appear";
        let sealed = encrypt(&key, &nonce, b"hello", aad).unwrap();
        assert_eq!(sealed.len(), 5 + TAG_SIZE);
        assert!(!sealed.windows(aad.len()).any(|w| w == &aad[..]));
    }

    /// Wire/storage format: ciphertext the Python prototype produced (golden
    /// vector, `tests/fixtures/python/crypto/GENERATE.md`) decrypts here, and
    /// this implementation produces the identical bytes for the same
    /// key/nonce/aad/plaintext.
    #[test]
    fn oracle_ciphertext_round_trips_both_directions() {
        let vectors: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/python/crypto/vectors.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let v = &vectors["chacha20poly1305"];
        let field = |name: &str| hex::decode(v[name].as_str().unwrap()).unwrap();
        let (key, nonce, aad, plaintext) = (
            field("key"),
            field("nonce"),
            field("aad"),
            field("plaintext"),
        );
        assert_eq!(key, vec![0x12u8; KEY_SIZE]);
        assert_eq!(nonce, vec![0x34u8; NONCE_SIZE]);
        let python_sealed = field("sealed");

        let rust_sealed = encrypt(&key, &nonce, &plaintext, &aad).unwrap();
        assert_eq!(rust_sealed, python_sealed);
        assert_eq!(
            decrypt(&key, &nonce, &python_sealed, &aad).unwrap(),
            plaintext
        );
    }
}
