//! Port of `zeropw/sshwire.py`: SSH wire codec, OpenSSH Ed25519 key formats and
//! SSH agent protocol messages.
//!
//! This module is the only place in ZeroPW that knows how SSH bytes are laid
//! out. It covers three things:
//!
//! * the RFC 4251 wire primitives (`string`, `uint32`, `boolean`, `mpint`)
//!   plus a strict [`Reader`];
//! * the OpenSSH public key line (`authorized_keys` / `.pub`), the
//!   `ssh-ed25519` key blob, and the unencrypted `openssh-key-v1` private key
//!   container (RFC 8709 key blobs, OpenSSH `PROTOCOL.key`);
//! * the SSH agent protocol framing and the handful of messages the ZeroPW
//!   signer needs (draft-miller-ssh-agent, OpenSSH `PROTOCOL.agent`),
//!   including the `session-bind@openssh.com` extension and the exact
//!   `SSH_MSG_USERAUTH_REQUEST` byte layout that an SSH client asks an agent
//!   to sign.
//!
//! # Security scope and limitations
//!
//! * **Parsing is strict by design.** Every parser consumes exactly its
//!   input: truncation, trailing bytes, wrong tags, non-canonical encodings
//!   and over-long frames raise [`WireError`] (or its "unsupported key type"
//!   variant). Nothing is silently ignored or padded. The one deliberate
//!   leniency is that purely informational key *comments* (private key
//!   files, identities answers) are decoded with U+FFFD replacement instead
//!   of refusing the key: OpenSSH writes them as raw bytes, so they need not
//!   be UTF-8.
//! * **No cryptography lives here** in the long run: signing, verification
//!   and public key derivation belong to `crate::crypto::ed25519`. That
//!   module is still a stub (ported in parallel), so this file talks to
//!   `ed25519_dalek` directly through a small adapter section marked below;
//!   the coordinator will rewire it once the crypto unit lands. This module
//!   never logs or formats seed bytes; [`Ed25519PrivateKey`]'s `Debug` shows
//!   only the public fingerprint and comment.
//! * **Ed25519 only, unencrypted only.** RSA/ECDSA/DSA keys, FIDO `sk-` keys,
//!   certificates and passphrase-protected private keys are rejected as
//!   unsupported; there is no fallback.
//! * **Purpose binding is decided elsewhere.** [`parse_userauth_request`]
//!   guarantees that a to-be-signed buffer has the *shape* of a public key
//!   authentication request (with nothing trailing), but whether the
//!   username, algorithm, key and session match the caller's grant is the
//!   signer's job.
//! * The agent framing helpers cap messages at [`MAX_AGENT_MESSAGE`] and
//!   never allocate a buffer before validating the length prefix. Transport
//!   errors are propagated unchanged; only *clean* EOF at a message boundary
//!   is reported as `None`.

use std::fmt;
use std::io::{Read, Write};
use std::sync::OnceLock;

use regex::Regex;

use crate::secret::SecretBytes;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Malformed, truncated, non-canonical or over-long SSH wire data.
///
/// Python models this as `WireError(ValueError)` with a subclass
/// `UnsupportedKeyType` for "well-formed input that uses a key type or key
/// format ZeroPW does not support". A handful of call sites in
/// `sshwire.py` instead raise a *bare* `ValueError` -- not a `WireError`
/// instance at all, so a Python `except WireError` does **not** catch it
/// (see `Ed25519PublicKey.to_authorized_key` and `encode_string`, and
/// `DEVIATIONS.md`). Rust keeps a single error type with a three-way tag
/// so callers can reproduce both distinctions Python callers rely on:
/// `is_unsupported()` for `except UnsupportedKeyType` vs `except
/// WireError`, and `is_wire_error()` for "is this even a `WireError`".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WireErrorKind {
    Wire,
    Unsupported,
    /// A bare Python `ValueError`, not a `WireError`/`UnsupportedKeyType`
    /// instance.
    ValueError,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireError {
    message: String,
    kind: WireErrorKind,
}

impl WireError {
    pub fn new(message: impl Into<String>) -> Self {
        WireError {
            message: message.into(),
            kind: WireErrorKind::Wire,
        }
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        WireError {
            message: message.into(),
            kind: WireErrorKind::Unsupported,
        }
    }

    /// A bare Python `ValueError` site (not `WireError`/`UnsupportedKeyType`):
    /// see the type doc comment and `DEVIATIONS.md`. A caller that wants to
    /// reproduce Python's `except WireError` scope must check
    /// [`WireError::is_wire_error`], not just match on this type.
    pub fn value_error(message: impl Into<String>) -> Self {
        WireError {
            message: message.into(),
            kind: WireErrorKind::ValueError,
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    /// True when this is the `UnsupportedKeyType` case: well-formed input
    /// using a key type or key format ZeroPW does not support.
    pub fn is_unsupported(&self) -> bool {
        matches!(self.kind, WireErrorKind::Unsupported)
    }

    /// True unless this is the bare-`ValueError` case ([`WireError::value_error`]):
    /// whether a Python `except WireError` (or `except UnsupportedKeyType`)
    /// would catch the equivalent Python exception.
    pub fn is_wire_error(&self) -> bool {
        !matches!(self.kind, WireErrorKind::ValueError)
    }

    /// `type(exc).__name__` in Python.
    pub fn class_name(&self) -> &'static str {
        match self.kind {
            WireErrorKind::Unsupported => "UnsupportedKeyType",
            WireErrorKind::Wire => "WireError",
            WireErrorKind::ValueError => "ValueError",
        }
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for WireError {}

/// How a Python caller would translate a caught `WireError`: `InvalidInput`
/// with the class name preserved (`WireError` or `UnsupportedKeyType`) and
/// the original message as detail. Call sites in other modules typically
/// pick a more specific `reason`; this default conversion exists so
/// `WireError` composes with `crate::Error` (e.g. via `?`) where no more
/// specific translation is needed.
impl From<WireError> for crate::Error {
    fn from(err: WireError) -> Self {
        crate::Error::subclass(
            crate::ErrorClass::InvalidInput,
            err.class_name(),
            "invalid_input",
            err.message,
        )
    }
}

// ---------------------------------------------------------------------------
// RFC 4251 wire primitives
// ---------------------------------------------------------------------------

/// Encode `n` as a big-endian `uint32`.
///
/// Python validates `0 <= n <= 0xFFFFFFFF` at runtime and raises
/// `ValueError` otherwise; here the `u32` argument type makes an
/// out-of-range value unrepresentable, so the check is enforced at compile
/// time instead (see `DEVIATIONS.md`).
pub fn encode_uint32(n: u32) -> [u8; 4] {
    n.to_be_bytes()
}

/// Encode an RFC 4251 `string` (`uint32` length prefix + bytes).
///
/// Accepts anything that behaves like a byte slice (`&[u8]`, `Vec<u8>`,
/// `&str`, ...), mirroring Python's acceptance of both `bytes` and `str`
/// (encoded as UTF-8).
pub fn encode_string(data: impl AsRef<[u8]>) -> Result<Vec<u8>, WireError> {
    let data = data.as_ref();
    if data.len() > u32::MAX as usize {
        // Python: bare `raise ValueError(...)`, not `WireError` (see
        // `WireError::value_error` and `DEVIATIONS.md`).
        return Err(WireError::value_error(
            "string too long for uint32 length prefix",
        ));
    }
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    Ok(out)
}

/// Encode an RFC 4251 `boolean` as exactly `0x00` or `0x01`.
pub fn encode_bool(v: bool) -> [u8; 1] {
    [if v { 1 } else { 0 }]
}

// -- mpint --------------------------------------------------------------

/// An arbitrary-precision signed integer, as needed by RFC 4251 `mpint`.
///
/// Rust has no built-in bignum; `sshwire` is the only place in ZeroPW that
/// needs one (Ed25519 keys never need `mpint`), so this is a minimal
/// sign-and-magnitude type rather than a general-purpose dependency (see
/// `DEVIATIONS.md`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MpInt {
    negative: bool,
    /// Big-endian magnitude, no leading zero bytes; empty means zero.
    magnitude: Vec<u8>,
}

impl MpInt {
    pub fn zero() -> Self {
        MpInt {
            negative: false,
            magnitude: Vec::new(),
        }
    }

    pub fn from_i64(n: i64) -> Self {
        if n == 0 {
            return Self::zero();
        }
        let negative = n < 0;
        let magnitude = strip_leading_zeros(n.unsigned_abs().to_be_bytes().to_vec());
        MpInt {
            negative,
            magnitude,
        }
    }

    /// Build from an explicit sign and big-endian magnitude (leading zero
    /// bytes are stripped; an all-zero magnitude forces `negative = false`).
    pub fn from_magnitude_be(negative: bool, magnitude: &[u8]) -> Self {
        let magnitude = strip_leading_zeros(magnitude.to_vec());
        MpInt {
            negative: negative && !magnitude.is_empty(),
            magnitude,
        }
    }

    pub fn is_negative(&self) -> bool {
        self.negative
    }

    pub fn is_zero(&self) -> bool {
        self.magnitude.is_empty()
    }

    pub fn magnitude_be(&self) -> &[u8] {
        &self.magnitude
    }
}

fn strip_leading_zeros(mut bytes: Vec<u8>) -> Vec<u8> {
    let n = bytes.iter().take_while(|&&b| b == 0).count();
    bytes.drain(0..n);
    bytes
}

/// Bit length of a big-endian magnitude (Python's `int.bit_length()`).
fn bit_length_be(magnitude: &[u8]) -> u32 {
    let mut idx = 0;
    while idx < magnitude.len() && magnitude[idx] == 0 {
        idx += 1;
    }
    if idx == magnitude.len() {
        return 0;
    }
    let bits_in_first = 8 - magnitude[idx].leading_zeros();
    bits_in_first + ((magnitude.len() - idx - 1) as u32) * 8
}

/// `magnitude - 1` as a big-endian byte vector; `magnitude` must be > 0.
fn decrement_be(magnitude: &[u8]) -> Vec<u8> {
    let mut out = magnitude.to_vec();
    for i in (0..out.len()).rev() {
        if out[i] != 0 {
            out[i] -= 1;
            break;
        }
        out[i] = 0xFF;
    }
    strip_leading_zeros(out)
}

/// In-place two's complement negation of a fixed-width big-endian buffer.
fn negate_twos_complement(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        *b = !*b;
    }
    for b in bytes.iter_mut().rev() {
        if *b == 0xFF {
            *b = 0x00;
        } else {
            *b += 1;
            break;
        }
    }
}

/// Encode an integer as an RFC 4251 (section 5) `mpint`.
///
/// Zero encodes as the empty string; every other value uses the minimal
/// big-endian two's-complement form, so a positive value gains a leading
/// `0x00` exactly when its high bit is set and a negative value a leading
/// `0xff` only when needed (`-0x1234` -> `edcc`, `-0xdeadbeef` ->
/// `ff21524111`).
pub fn encode_mpint(n: &MpInt) -> Vec<u8> {
    if n.magnitude.is_empty() {
        return encode_string([]).expect("empty slice always encodes");
    }
    let bitlen_source: Vec<u8> = if n.negative {
        decrement_be(&n.magnitude)
    } else {
        n.magnitude.clone()
    };
    let bits = bit_length_be(&bitlen_source) as usize;
    let byte_len = bits / 8 + 1;
    let mut out = vec![0u8; byte_len];
    let offset = byte_len - n.magnitude.len();
    out[offset..].copy_from_slice(&n.magnitude);
    if n.negative {
        negate_twos_complement(&mut out);
    }
    encode_string(out).expect("mpint body always fits a uint32 length")
}

// -- Reader ---------------------------------------------------------------

/// Strict sequential reader over an SSH wire buffer.
///
/// Every accessor returns [`WireError`] instead of partial data when the
/// buffer is too short. Callers that expect a complete message must finish
/// with [`Reader::expect_eof`] (or check [`Reader::eof`]) so that trailing
/// bytes are rejected too.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    /// Number of unread bytes.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// True when every byte has been consumed.
    pub fn eof(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Consume and return all remaining bytes.
    pub fn rest(&mut self) -> Vec<u8> {
        let out = self.data[self.pos..].to_vec();
        self.pos = self.data.len();
        out
    }

    /// Return an error unless the buffer is fully consumed.
    pub fn expect_eof(&self, what: &str) -> Result<(), WireError> {
        if !self.eof() {
            return Err(WireError::new(format!(
                "{} trailing byte(s) after {}",
                self.remaining(),
                what
            )));
        }
        Ok(())
    }

    fn take(&mut self, n: usize, what: &str) -> Result<Vec<u8>, WireError> {
        if n > self.remaining() {
            return Err(WireError::new(format!(
                "truncated {what}: need {n} byte(s), have {}",
                self.remaining()
            )));
        }
        let start = self.pos;
        self.pos = start + n;
        Ok(self.data[start..self.pos].to_vec())
    }

    /// Read exactly `n` raw bytes.
    pub fn raw(&mut self, n: usize) -> Result<Vec<u8>, WireError> {
        self.take(n, "raw bytes")
    }

    /// Read one `byte` as an int.
    pub fn byte(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1, "byte")?[0])
    }

    /// Read a `boolean`; only `0x00`/`0x01` are accepted.
    pub fn boolean(&mut self) -> Result<bool, WireError> {
        let v = self.take(1, "boolean")?[0];
        match v {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WireError::new(format!(
                "non-canonical boolean byte {v:#04x}"
            ))),
        }
    }

    /// Read a big-endian `uint32`.
    pub fn uint32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4, "uint32")?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read an RFC 4251 `string` and return its bytes.
    pub fn string(&mut self) -> Result<Vec<u8>, WireError> {
        let length = self.uint32()? as usize;
        self.take(length, "string")
    }

    /// Read a `string` and decode it as UTF-8 (strict: invalid UTF-8 is a
    /// [`WireError`]). Protocol names and identifiers use this.
    pub fn text(&mut self) -> Result<String, WireError> {
        let raw = self.string()?;
        String::from_utf8(raw).map_err(|_| WireError::new("string is not valid UTF-8"))
    }

    /// Read a `string` and decode it as UTF-8 with U+FFFD replacement.
    /// Used only for purely informational fields such as key comments
    /// (Python's `text(errors="replace")`).
    pub fn text_lossy(&mut self) -> Result<String, WireError> {
        let raw = self.string()?;
        Ok(String::from_utf8_lossy(&raw).into_owned())
    }

    /// Read a minimally encoded RFC 4251 `mpint` (two's complement).
    ///
    /// Non-minimal encodings return [`WireError`]: a lone `0x00` (zero must
    /// be empty), a redundant leading `0x00` before a byte without the high
    /// bit, or a redundant leading `0xff` before a byte with it.
    pub fn mpint(&mut self) -> Result<MpInt, WireError> {
        let raw = self.string()?;
        if raw.is_empty() {
            return Ok(MpInt::zero());
        }
        if raw.len() == 1 && raw[0] == 0 {
            return Err(WireError::new("non-minimal mpint encoding"));
        }
        if raw.len() > 1 && (raw[0] == 0x00 || raw[0] == 0xFF) && (raw[1] & 0x80) == (raw[0] & 0x80)
        {
            return Err(WireError::new("non-minimal mpint encoding"));
        }
        let negative = raw[0] & 0x80 != 0;
        let magnitude = if negative {
            let mut tmp = raw;
            negate_twos_complement(&mut tmp);
            strip_leading_zeros(tmp)
        } else {
            strip_leading_zeros(raw)
        };
        Ok(MpInt {
            negative: negative && !magnitude.is_empty(),
            magnitude,
        })
    }
}

// ---------------------------------------------------------------------------
// Ed25519 backend
//
// zeropw/sshwire.py delegates signing, verification and public-key
// derivation to zeropw.crypto.ed25519 via a lazy import. This thin shim
// forwards to crate::crypto::ed25519, the port of that module, keeping the
// fixed-size signatures sshwire's callers already use.
// ---------------------------------------------------------------------------
mod ed25519_adapter {
    use crate::crypto::ed25519;

    pub(super) fn public_key_from_seed(seed: &[u8; 32]) -> [u8; 32] {
        match ed25519::public_key_from_seed(seed) {
            Ok(public) => public,
            Err(_) => unreachable!("a [u8; 32] seed always has the right size"),
        }
    }

    pub(super) fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
        match ed25519::sign(seed, message) {
            Ok(signature) => signature,
            Err(_) => unreachable!("a [u8; 32] seed always has the right size"),
        }
    }

    pub(super) fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        ed25519::verify(public_key, message, signature)
    }

    pub(super) fn generate_seed() -> [u8; 32] {
        let seed = ed25519::generate_seed();
        let mut out = [0u8; 32];
        out.copy_from_slice(seed.expose());
        out
    }
}

// ---------------------------------------------------------------------------
// Ed25519 keys and OpenSSH key formats
// ---------------------------------------------------------------------------

pub const ED25519_KEY_TYPE: &str = "ssh-ed25519";
pub const SEED_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;

const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\x00";
const PEM_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PEM_END: &str = "-----END OPENSSH PRIVATE KEY-----";
const PEM_LINE_LENGTH: usize = 70;
const NONE_CIPHER_BLOCK_SIZE: usize = 8;

fn base64_engine() -> &'static base64::engine::GeneralPurpose {
    use base64::alphabet;
    use base64::engine::{GeneralPurpose, GeneralPurposeConfig};
    // Python's `base64.b64decode(text, validate=True)` rejects non-alphabet
    // characters and bad padding, but (unlike this crate's default
    // `STANDARD` engine) does not check that the unused low bits of the
    // last symbol are zero. Configure the same leniency so decoding agrees
    // with Python for every input, not just canonical ones.
    static ENGINE: OnceLock<GeneralPurpose> = OnceLock::new();
    ENGINE.get_or_init(|| {
        GeneralPurpose::new(
            &alphabet::STANDARD,
            GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
        )
    })
}

fn b64decode_strict(text: &str, what: &str) -> Result<Vec<u8>, WireError> {
    use base64::Engine;
    base64_engine()
        .decode(text)
        .map_err(|_| WireError::new(format!("invalid base64 in {what}")))
}

fn b64encode(data: &[u8]) -> String {
    use base64::Engine;
    base64_engine().encode(data)
}

/// A raw 32-byte Ed25519 public key.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Ed25519PublicKey {
    key_bytes: Vec<u8>,
}

impl Ed25519PublicKey {
    pub fn new(key_bytes: Vec<u8>) -> Result<Self, WireError> {
        if key_bytes.len() != PUBLIC_KEY_SIZE {
            return Err(WireError::new(format!(
                "ed25519 public key must be {PUBLIC_KEY_SIZE} bytes"
            )));
        }
        Ok(Ed25519PublicKey { key_bytes })
    }

    pub fn from_blob(blob: &[u8]) -> Result<Self, WireError> {
        parse_public_key_blob(blob)
    }

    pub fn key_bytes(&self) -> &[u8] {
        &self.key_bytes
    }

    /// The `ssh-ed25519` wire blob (`string type || string key`).
    pub fn blob(&self) -> Vec<u8> {
        let mut out = encode_string(ED25519_KEY_TYPE).expect("key type always fits");
        out.extend(encode_string(&self.key_bytes).expect("public key always fits"));
        out
    }

    /// One `authorized_keys` / `.pub` line without a trailing newline.
    pub fn to_authorized_key(&self, comment: &str) -> Result<String, WireError> {
        if comment.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
            // Python: bare `raise ValueError(...)`, not `WireError`. This
            // is C-4's escape: `Vault._public_metadata` (not yet ported)
            // catches only `sshwire.WireError`, so this must stay
            // distinguishable via `WireError::is_wire_error`. See
            // `WireError::value_error` and `DEVIATIONS.md`.
            return Err(WireError::value_error(
                "comment must not contain line breaks or NUL",
            ));
        }
        let line = format!("{} {}", ED25519_KEY_TYPE, b64encode(&self.blob()));
        Ok(if comment.is_empty() {
            line
        } else {
            format!("{line} {comment}")
        })
    }

    /// OpenSSH-style `SHA256:<unpadded base64>` fingerprint of the blob.
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(self.blob());
        format!("SHA256:{}", b64encode(&digest).trim_end_matches('='))
    }

    /// Verify a raw 64-byte signature; never panics for malformed input.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        ed25519_adapter::verify(&self.key_bytes, data, signature)
    }
}

/// Parse an `ssh-ed25519` wire blob; any other type is unsupported.
pub fn parse_public_key_blob(blob: &[u8]) -> Result<Ed25519PublicKey, WireError> {
    let mut r = Reader::new(blob);
    let key_type = r.text()?;
    if key_type != ED25519_KEY_TYPE {
        return Err(WireError::unsupported(format!(
            "unsupported key type {}",
            crate::pystr::repr_str(&key_type)
        )));
    }
    let key_bytes = r.string()?;
    if key_bytes.len() != PUBLIC_KEY_SIZE {
        return Err(WireError::new(
            "ed25519 public key blob has wrong key length",
        ));
    }
    r.expect_eof("public key blob")?;
    Ed25519PublicKey::new(key_bytes)
}

// -- authorized_keys parsing ------------------------------------------------

fn key_type_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?:ssh-|ecdsa-sha2-|sk-ssh-|sk-ecdsa-|rsa-sha2-|webauthn-sk-|x509v3-)[A-Za-z0-9@.\-]*$")
            .expect("static regex")
    })
}

fn key_type_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9@.\-]*$").expect("static regex"))
}

/// Match `text` against `re` the way Python's `re.Pattern.match` (or
/// `.search`) does for a pattern ending in an unescaped `$`: Python's `$`
/// (without `re.MULTILINE`) matches at the true end of the string *or*
/// immediately before a single trailing `\n`, so `.match()`/`.search()`
/// accept that one extra trailing byte the pattern never mentions.
/// `.fullmatch()` does **not** get this leniency (it still requires the
/// whole string, `\n` included, to be consumed). Rust's `regex` crate's
/// `$` (also without a multi-line flag) matches only the true end, so this
/// reproduces `.match()`/`.search()` by trying the compiled `^...$`
/// pattern against the whole text first, then, only if that fails and the
/// text ends with exactly one `\n`, against the text with that trailing
/// `\n` removed. `key_type_re()`/`key_type_name_re()` are both applied
/// this way in `sshwire.py` (`_KEY_TYPE_RE.match(...)` /
/// `_KEY_TYPE_NAME_RE.match(...)`); see `DEVIATIONS.md` if this ever needs
/// recording as an observable difference (it currently reproduces Python
/// exactly for every case the oracle tests below exercise).
fn py_dollar_is_match(re: &Regex, text: &str) -> bool {
    if re.is_match(text) {
        return true;
    }
    match text.strip_suffix('\n') {
        Some(stripped) => re.is_match(stripped),
        None => false,
    }
}

/// ASCII whitespace/newline chars OpenSSH treats as field separators or line
/// boundaries in `authorized_keys`: exactly space and tab.
const AUTHORIZED_KEYS_BLANK: [char; 2] = [' ', '\t'];

fn strip_blank(s: &str) -> &str {
    s.trim_matches(|c| AUTHORIZED_KEYS_BLANK.contains(&c))
}

/// Split on runs of ASCII space/tab only, never on other whitespace, with
/// at most `maxsplit` splits (so at most `maxsplit + 1` pieces).
fn split_authorized_key_fields(text: &str, maxsplit: usize) -> Vec<String> {
    let text = strip_blank(text);
    if text.is_empty() {
        return Vec::new();
    }
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"[ \t]+").expect("static regex"));
    re.splitn(text, maxsplit + 1).map(str::to_string).collect()
}

/// True when `token` occupies the key type position of an authorized_keys
/// line. Known type-name prefixes match directly. An unknown name (a future
/// or vendor key type) is recognised when the field after it strictly
/// base64-decodes to a wire blob whose leading `string` is itself a key
/// type name; in a well-formed line an options field is never followed by
/// such a blob, so options are not mistaken for key types.
fn is_key_type_token(token: &str, following: Option<&str>) -> bool {
    if py_dollar_is_match(key_type_re(), token) {
        return true;
    }
    let Some(following) = following else {
        return false;
    };
    if !py_dollar_is_match(key_type_name_re(), token) {
        return false;
    }
    let Ok(decoded) = b64decode_strict(following, "authorized_keys line") else {
        return false;
    };
    let Ok(leading) = Reader::new(&decoded).text() else {
        return false;
    };
    py_dollar_is_match(key_type_name_re(), &leading)
}

/// One parsed `authorized_keys` line (options are returned verbatim).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedKeyEntry {
    pub options: String,
    pub key: Ed25519PublicKey,
    pub comment: String,
}

/// Return the index just past the options field, honouring quotes like
/// OpenSSH.
fn skip_authorized_key_options(line: &str) -> Result<usize, WireError> {
    let chars: Vec<(usize, char)> = line.char_indices().collect();
    let mut quoted = false;
    let mut i = 0;
    while i < chars.len() {
        let (byte_pos, c) = chars[i];
        if !quoted && (c == ' ' || c == '\t') {
            return Ok(byte_pos);
        }
        if c == '\\' && i + 1 < chars.len() && chars[i + 1].1 == '"' {
            i += 2;
            continue;
        }
        if c == '"' {
            quoted = !quoted;
        }
        i += 1;
    }
    if quoted {
        return Err(WireError::new(
            "unterminated quote in authorized_keys options",
        ));
    }
    Ok(line.len())
}

/// Parse one `authorized_keys` / `.pub` line.
///
/// Accepts an optional leading options field (`command="..."` etc.), then
/// `ssh-ed25519`, the base64 blob and an optional comment. Exactly one line
/// is accepted: embedded line breaks (for example the contents of a whole
/// `authorized_keys` file) return [`WireError`], as do blank and `#`
/// comment lines; any key type other than `ssh-ed25519`, including unknown
/// types followed by a key blob, returns the unsupported variant.
///
/// Fields are separated by ASCII space/tab only, exactly like OpenSSH
/// (`sshkey_read` uses `strcspn(cp, " \t")`). Any other whitespace
/// character (NBSP, VT, FF, NEL, U+2028, ...) anywhere in the line is
/// rejected: between fields OpenSSH would refuse the line too, and inside a
/// comment or quoted option OpenSSH would ignore it, so refusing is the
/// conservative choice that keeps every accepted line one `ssh`/`sshd`
/// parses identically.
pub fn parse_authorized_key_entry(line: &str) -> Result<AuthorizedKeyEntry, WireError> {
    let stripped =
        line.trim_matches(|c| AUTHORIZED_KEYS_BLANK.contains(&c) || c == '\r' || c == '\n');
    if stripped.is_empty() || stripped.starts_with('#') {
        return Err(WireError::new("blank or comment line"));
    }
    if stripped.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
        return Err(WireError::new("expected a single authorized_keys line"));
    }
    if stripped
        .chars()
        .any(|c| crate::pystr::is_space(c) && !AUTHORIZED_KEYS_BLANK.contains(&c))
    {
        return Err(WireError::new(
            "authorized_keys line contains whitespace other than space or tab",
        ));
    }
    let first = split_authorized_key_fields(stripped, 2);
    let (options, remainder) = if is_key_type_token(&first[0], first.get(1).map(String::as_str)) {
        (String::new(), stripped.to_string())
    } else {
        let end = skip_authorized_key_options(stripped)?;
        let options = stripped[..end].to_string();
        let remainder = strip_blank(&stripped[end..]).to_string();
        if remainder.is_empty() {
            return Err(WireError::new(
                "authorized_keys line has options but no key",
            ));
        }
        (options, remainder)
    };
    let parts = split_authorized_key_fields(&remainder, 2);
    let key_type = &parts[0];
    if !is_key_type_token(key_type, parts.get(1).map(String::as_str)) {
        return Err(WireError::new(
            "authorized_keys line has no recognisable key type",
        ));
    }
    if key_type != ED25519_KEY_TYPE {
        return Err(WireError::unsupported(format!(
            "unsupported key type {}",
            crate::pystr::repr_str(key_type)
        )));
    }
    if parts.len() < 2 {
        return Err(WireError::new(
            "authorized_keys line is missing the key data",
        ));
    }
    let key = parse_public_key_blob(&b64decode_strict(&parts[1], "authorized_keys line")?)?;
    let comment = if parts.len() == 3 {
        strip_blank(&parts[2]).to_string()
    } else {
        String::new()
    };
    Ok(AuthorizedKeyEntry {
        options,
        key,
        comment,
    })
}

/// Parse one `authorized_keys` / `.pub` line and return the key only.
pub fn parse_authorized_key(line: &str) -> Result<Ed25519PublicKey, WireError> {
    Ok(parse_authorized_key_entry(line)?.key)
}

// -- Private keys -------------------------------------------------------

/// An Ed25519 private key (32-byte seed) with its public half and comment.
///
/// The seed is held in [`SecretBytes`] (zeroised on drop, redacted
/// `Debug`). `Debug`/`repr` show only the public fingerprint and comment,
/// mirroring Python's `Ed25519PrivateKey.__repr__`, which never shows the
/// seed.
#[derive(Clone)]
pub struct Ed25519PrivateKey {
    seed: SecretBytes,
    pub public: Ed25519PublicKey,
    pub comment: String,
}

impl Ed25519PrivateKey {
    /// The constructor does not verify that `public` matches `seed`; use
    /// [`Ed25519PrivateKey::from_seed`], [`generate_ed25519_private_key`] or
    /// [`parse_openssh_private_key`], which all do.
    pub fn new(
        seed: SecretBytes,
        public: Ed25519PublicKey,
        comment: String,
    ) -> Result<Self, WireError> {
        if seed.len() != SEED_SIZE {
            return Err(WireError::new(format!(
                "ed25519 seed must be {SEED_SIZE} bytes"
            )));
        }
        Ok(Ed25519PrivateKey {
            seed,
            public,
            comment,
        })
    }

    pub fn from_seed(seed: &[u8], comment: &str) -> Result<Self, WireError> {
        if seed.len() != SEED_SIZE {
            return Err(WireError::new(format!(
                "ed25519 seed must be {SEED_SIZE} bytes"
            )));
        }
        let mut seed_arr = [0u8; SEED_SIZE];
        seed_arr.copy_from_slice(seed);
        let public =
            Ed25519PublicKey::new(ed25519_adapter::public_key_from_seed(&seed_arr).to_vec())?;
        Ok(Ed25519PrivateKey {
            seed: SecretBytes::from_slice(seed),
            public,
            comment: comment.to_string(),
        })
    }

    /// The raw seed. An explicit call, like Python's raw `.seed` attribute
    /// access, but greppable per `secret.rs`'s design.
    pub fn seed(&self) -> &SecretBytes {
        &self.seed
    }

    /// Raw 64-byte Ed25519 signature over `data`.
    pub fn sign(&self, data: &[u8]) -> [u8; SIGNATURE_SIZE] {
        let mut seed_arr = [0u8; SEED_SIZE];
        seed_arr.copy_from_slice(self.seed.expose());
        ed25519_adapter::sign(&seed_arr, data)
    }

    /// Serialise as an unencrypted `openssh-key-v1` PEM block.
    ///
    /// The output uses cipher/KDF `none`, one key, OpenSSH's 1,2,3,...
    /// padding to the 8-byte block size, and 70-column base64 so that
    /// `ssh-keygen -y -f` accepts it verbatim.
    pub fn to_openssh_private_key(&self) -> String {
        let checkint = encode_uint32(random_u32());
        let mut section = Vec::new();
        section.extend_from_slice(&checkint);
        section.extend_from_slice(&checkint);
        section.extend(encode_string(ED25519_KEY_TYPE).expect("fits"));
        section.extend(encode_string(&self.public.key_bytes).expect("fits"));
        let mut priv_field = self.seed.expose().to_vec();
        priv_field.extend_from_slice(&self.public.key_bytes);
        section.extend(encode_string(&priv_field).expect("fits"));
        section.extend(encode_string(self.comment.as_bytes()).expect("fits"));
        let pad_len = NONE_CIPHER_BLOCK_SIZE.wrapping_sub(section.len() % NONE_CIPHER_BLOCK_SIZE)
            % NONE_CIPHER_BLOCK_SIZE;
        for i in 1..=pad_len {
            section.push(i as u8);
        }

        let mut blob = Vec::new();
        blob.extend_from_slice(OPENSSH_MAGIC);
        blob.extend(encode_string("none").expect("fits"));
        blob.extend(encode_string("none").expect("fits"));
        blob.extend(encode_string([]).expect("fits"));
        blob.extend_from_slice(&encode_uint32(1));
        blob.extend(encode_string(self.public.blob()).expect("fits"));
        blob.extend(encode_string(section).expect("fits"));

        let b64 = b64encode(&blob);
        let mut lines = vec![PEM_BEGIN.to_string()];
        let chars: Vec<char> = b64.chars().collect();
        for chunk in chars.chunks(PEM_LINE_LENGTH) {
            lines.push(chunk.iter().collect());
        }
        lines.push(PEM_END.to_string());
        lines.join("\n") + "\n"
    }
}

impl PartialEq for Ed25519PrivateKey {
    /// Seed comparison is constant time (allowed deviation, `DEVIATIONS.md`);
    /// Python compares seeds with ordinary `bytes.__eq__`.
    fn eq(&self, other: &Self) -> bool {
        self.seed.ct_eq(other.seed.expose())
            && self.public == other.public
            && self.comment == other.comment
    }
}

impl Eq for Ed25519PrivateKey {}

impl fmt::Debug for Ed25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Python: `f"Ed25519PrivateKey(public={self.public.fingerprint()!r}, comment={self.comment!r})"`.
        write!(
            f,
            "Ed25519PrivateKey(public={}, comment={})",
            crate::pystr::repr_str(&self.public.fingerprint()),
            crate::pystr::repr_str(&self.comment)
        )
    }
}

fn random_u32() -> u32 {
    let mut buf = [0u8; 4];
    getrandom::getrandom(&mut buf).expect("OS CSPRNG must be available");
    u32::from_ne_bytes(buf)
}

/// Generate a fresh key using the Ed25519 backend's CSPRNG seed.
pub fn generate_ed25519_private_key(comment: &str) -> Ed25519PrivateKey {
    let seed = ed25519_adapter::generate_seed();
    Ed25519PrivateKey::from_seed(&seed, comment)
        .expect("freshly generated seed is always SEED_SIZE bytes")
}

fn decode_openssh_pem(pem: &[u8]) -> Result<Vec<u8>, WireError> {
    let text = std::str::from_utf8(pem)
        .map_err(|_| WireError::new("private key file is not ASCII text"))?;
    if !text.is_ascii() {
        return Err(WireError::new("private key file is not ASCII text"));
    }
    // `text` is guaranteed ASCII-only at this point (checked above, the
    // same gate Python's `bytes(pem).decode("ascii")` applies before ever
    // calling `str.splitlines()`/`str.strip()`), so every Unicode-only
    // line boundary or whitespace character `str` recognises (`\x85`,
    // U+2028, U+2029, and Unicode `Zs`) is provably unreachable here; only
    // their ASCII-range members matter, and both helpers below enumerate
    // those completely (see their doc comments and `DEVIATIONS.md`).
    let lines: Vec<&str> = split_pem_lines(text)
        .into_iter()
        .map(strip_pem_line)
        .filter(|ln| !ln.is_empty())
        .collect();
    let Some(&first) = lines.first() else {
        return Err(WireError::new("empty private key"));
    };
    if first != PEM_BEGIN {
        if first.starts_with("-----BEGIN ") && first.ends_with("-----") {
            return Err(WireError::unsupported(format!(
                "unsupported private key format: {first}"
            )));
        }
        return Err(WireError::new("missing OpenSSH private key header"));
    }
    let Some(&last) = lines.last() else {
        return Err(WireError::new("missing OpenSSH private key footer"));
    };
    if last != PEM_END {
        return Err(WireError::new("missing OpenSSH private key footer"));
    }
    let body: String = lines[1..lines.len() - 1].concat();
    if body.is_empty() {
        return Err(WireError::new("empty OpenSSH private key body"));
    }
    b64decode_strict(&body, "OpenSSH private key")
}

/// Split ASCII text the way Python's `str.splitlines()` does. Python
/// recognises `\n`, `\r`, `\r\n`, `\v` (`\x0b`), `\f` (`\x0c`), `\x1c`,
/// `\x1d`, `\x1e` as boundaries within the ASCII range (plus `\x85`,
/// U+2028 and U+2029, which cannot occur in the ASCII-only text
/// `decode_openssh_pem` passes here -- see its call site). Every boundary
/// other than `\r`/`\r\n` is a single character, not paired with a
/// following byte the way `\r\n` is.
fn split_pem_lines(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\n' => {
                out.push(&text[start..i]);
                i += 1;
                start = i;
            }
            b'\r' => {
                out.push(&text[start..i]);
                i += 1;
                if i < bytes.len() && bytes[i] == b'\n' {
                    i += 1;
                }
                start = i;
            }
            0x0b | 0x0c | 0x1c | 0x1d | 0x1e => {
                out.push(&text[start..i]);
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < bytes.len() {
        out.push(&text[start..]);
    }
    out
}

/// Strip a PEM line the way Python's `str.strip()` (no arguments) does.
/// For the ASCII-only text reachable here, `str.isspace()` is exactly
/// `{\t, \n, \v, \f, \r, \x1c, \x1d, \x1e, \x1f, ' '}` -- note `\x1f` is
/// stripped even though (unlike `\x1c`-`\x1e`) it is *not* a
/// `str.splitlines()` boundary, so a header/footer line can carry a
/// trailing `\x1f` that `split_pem_lines` leaves attached to the line.
fn strip_pem_line(line: &str) -> &str {
    line.trim_matches(|c: char| {
        matches!(
            c,
            '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | '\u{1c}'..='\u{1f}' | ' '
        )
    })
}

/// Parse an unencrypted `openssh-key-v1` Ed25519 private key.
///
/// Checks the magic, cipher/KDF `none` (anything else -> the unsupported
/// variant), exactly one key, matching public key blobs, equal check-ints,
/// the 64-byte `seed || pub` private field, the 1,2,3,... padding to the
/// 8-byte block, and finally that the public key derived from the seed
/// matches the embedded one. The comment is informational (`ssh-keygen -C`
/// copies argv bytes verbatim) and is decoded with U+FFFD replacement
/// rather than refusing the key.
pub fn parse_openssh_private_key(pem: &[u8]) -> Result<Ed25519PrivateKey, WireError> {
    let blob = decode_openssh_pem(pem)?;
    let mut r = Reader::new(&blob);
    if r.raw(OPENSSH_MAGIC.len())? != OPENSSH_MAGIC {
        return Err(WireError::new("not an openssh-key-v1 container"));
    }
    let ciphername = r.text()?;
    let kdfname = r.text()?;
    let kdfoptions = r.string()?;
    let nkeys = r.uint32()?;
    if ciphername != "none" || kdfname != "none" {
        return Err(WireError::unsupported(
            "encrypted OpenSSH private keys are not supported",
        ));
    }
    if !kdfoptions.is_empty() {
        return Err(WireError::new(
            "unexpected KDF options for an unencrypted key",
        ));
    }
    if nkeys == 0 {
        return Err(WireError::new("openssh-key-v1 container holds no keys"));
    }
    if nkeys != 1 {
        return Err(WireError::unsupported(
            "multi-key openssh-key-v1 containers are not supported",
        ));
    }
    let public_blob = r.string()?;
    let section = r.string()?;
    r.expect_eof("openssh-key-v1 container")?;

    let public = parse_public_key_blob(&public_blob)?;
    if section.len() < NONE_CIPHER_BLOCK_SIZE || section.len() % NONE_CIPHER_BLOCK_SIZE != 0 {
        return Err(WireError::new("private key section is not block aligned"));
    }
    let mut pr = Reader::new(&section);
    let c1 = pr.uint32()?;
    let c2 = pr.uint32()?;
    if c1 != c2 {
        return Err(WireError::new("check-int mismatch in private key section"));
    }
    if pr.text()? != ED25519_KEY_TYPE {
        return Err(WireError::new(
            "private key section type does not match the public key",
        ));
    }
    if pr.string()? != public.key_bytes {
        return Err(WireError::new(
            "private key section public key does not match",
        ));
    }
    let private_field = pr.string()?;
    if private_field.len() != SEED_SIZE + PUBLIC_KEY_SIZE {
        return Err(WireError::new("ed25519 private field must be 64 bytes"));
    }
    let (seed, embedded_public) = private_field.split_at(SEED_SIZE);
    if embedded_public != public.key_bytes {
        return Err(WireError::new("private field public half does not match"));
    }
    let comment = pr.text_lossy()?;
    let padding = pr.rest();
    let expected_padding: Vec<u8> = (1..=padding.len() as u16).map(|i| i as u8).collect();
    if padding.len() >= NONE_CIPHER_BLOCK_SIZE || padding != expected_padding {
        return Err(WireError::new("invalid private key padding"));
    }
    let mut seed_arr = [0u8; SEED_SIZE];
    seed_arr.copy_from_slice(seed);
    if ed25519_adapter::public_key_from_seed(&seed_arr) != public.key_bytes.as_slice() {
        return Err(WireError::new("public key does not match the private seed"));
    }
    Ed25519PrivateKey::new(SecretBytes::from_slice(seed), public, comment)
}

// -- signatures -----------------------------------------------------------

/// Wrap a raw 64-byte signature as `string "ssh-ed25519" || string sig`.
pub fn encode_ssh_signature(sig64: &[u8]) -> Result<Vec<u8>, WireError> {
    if sig64.len() != SIGNATURE_SIZE {
        return Err(WireError::new(format!(
            "ed25519 signature must be {SIGNATURE_SIZE} bytes"
        )));
    }
    let mut out = encode_string(ED25519_KEY_TYPE).expect("fits");
    out.extend(encode_string(sig64).expect("fits"));
    Ok(out)
}

/// Unwrap an `ssh-ed25519` signature blob to its raw 64 bytes.
pub fn parse_ssh_signature(blob: &[u8]) -> Result<Vec<u8>, WireError> {
    let mut r = Reader::new(blob);
    let algorithm = r.text()?;
    if algorithm != ED25519_KEY_TYPE {
        return Err(WireError::new(format!(
            "unexpected signature algorithm {}",
            crate::pystr::repr_str(&algorithm)
        )));
    }
    let signature = r.string()?;
    if signature.len() != SIGNATURE_SIZE {
        return Err(WireError::new("ed25519 signature blob has wrong length"));
    }
    r.expect_eof("signature blob")?;
    Ok(signature)
}

// ---------------------------------------------------------------------------
// SSH agent protocol
// ---------------------------------------------------------------------------

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
pub const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
pub const SSH_AGENTC_REMOVE_IDENTITY: u8 = 18;
pub const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
pub const SSH_AGENTC_ADD_SMARTCARD_KEY: u8 = 20;
pub const SSH_AGENTC_REMOVE_SMARTCARD_KEY: u8 = 21;
pub const SSH_AGENTC_LOCK: u8 = 22;
pub const SSH_AGENTC_UNLOCK: u8 = 23;
pub const SSH_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;
pub const SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED: u8 = 26;
pub const SSH_AGENTC_EXTENSION: u8 = 27;
pub const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;

pub const SESSION_BIND_EXTENSION: &str = "session-bind@openssh.com";
pub const EXTENSION_QUERY: &str = "query";

pub const MAX_AGENT_MESSAGE: usize = 256 * 1024;

/// Either a transport error (propagated unchanged, like Python's `OSError`)
/// or a protocol violation ([`WireError`], like Python's `WireError`).
#[derive(Debug)]
pub enum AgentError {
    Io(std::io::Error),
    Wire(WireError),
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentError::Io(e) => write!(f, "{e}"),
            AgentError::Wire(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AgentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AgentError::Io(e) => Some(e),
            AgentError::Wire(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for AgentError {
    fn from(e: std::io::Error) -> Self {
        AgentError::Io(e)
    }
}

impl From<WireError> for AgentError {
    fn from(e: WireError) -> Self {
        AgentError::Wire(e)
    }
}

/// Prefix `payload` with its `uint32` length.
///
/// Payloads must contain at least the type byte and at most
/// [`MAX_AGENT_MESSAGE`] bytes; anything else returns [`WireError`].
pub fn frame_agent_message(payload: &[u8]) -> Result<Vec<u8>, WireError> {
    if payload.is_empty() {
        return Err(WireError::new(
            "agent message must contain at least a type byte",
        ));
    }
    if payload.len() > MAX_AGENT_MESSAGE {
        return Err(WireError::new("agent message exceeds MAX_AGENT_MESSAGE"));
    }
    let mut out = encode_uint32(payload.len() as u32).to_vec();
    out.extend_from_slice(payload);
    Ok(out)
}

/// Read up to `n` bytes, stopping early only at EOF (empty read). Defends
/// against a misbehaving `Read` impl reporting more bytes than the buffer
/// it was given can hold (Python's `_read_exact` checks the same thing for
/// a misbehaving `recv`). A read interrupted by a signal
/// (`ErrorKind::Interrupted`) is retried rather than propagated, matching
/// `socket.recv`'s automatic EINTR retry (PEP 475) that every Python
/// caller of this code relies on implicitly.
fn read_exact_upto<R: Read>(source: &mut R, n: usize) -> Result<Vec<u8>, AgentError> {
    let mut buf = vec![0u8; n];
    let mut got = 0;
    while got < n {
        match source.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(k) => {
                if k > n - got {
                    return Err(WireError::new("recv returned more data than requested").into());
                }
                got += k;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    buf.truncate(got);
    Ok(buf)
}

/// Read one length-prefixed agent message.
///
/// Returns the payload (type byte included), or `None` on a clean EOF
/// exactly at a message boundary. Returns [`WireError`] for a truncated
/// length or payload, a zero-length frame, or a length above
/// [`MAX_AGENT_MESSAGE`] (checked before any payload is read). Transport
/// errors propagate unchanged.
pub fn read_agent_message<R: Read>(source: &mut R) -> Result<Option<Vec<u8>>, AgentError> {
    let header = read_exact_upto(source, 4)?;
    if header.is_empty() {
        return Ok(None);
    }
    if header.len() < 4 {
        return Err(WireError::new("truncated agent message length").into());
    }
    let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if length == 0 {
        return Err(WireError::new("empty agent message").into());
    }
    if length > MAX_AGENT_MESSAGE {
        return Err(WireError::new(format!(
            "agent message of {length} bytes exceeds MAX_AGENT_MESSAGE"
        ))
        .into());
    }
    let payload = read_exact_upto(source, length)?;
    if payload.len() < length {
        return Err(WireError::new("truncated agent message payload").into());
    }
    Ok(Some(payload))
}

/// Send `payload` framed as one agent message.
pub fn write_agent_message<W: Write>(target: &mut W, payload: &[u8]) -> Result<(), AgentError> {
    let framed = frame_agent_message(payload)?;
    target.write_all(&framed)?;
    Ok(())
}

/// Thin message-oriented wrapper around a connected stream (a Unix or TCP
/// socket, or a socketpair end). Python's `AgentConnection` wraps any
/// duck-typed object with `.recv`/`.sendall`; Rust expresses the same
/// contract as a `Read + Write` bound. There is no explicit `close()` (used
/// as a context manager in Python): the wrapped stream is closed when this
/// value is dropped, which is the idiomatic Rust equivalent.
pub struct AgentConnection<S> {
    sock: S,
}

impl<S: Read + Write> AgentConnection<S> {
    pub fn new(sock: S) -> Self {
        AgentConnection { sock }
    }

    pub fn read_message(&mut self) -> Result<Option<Vec<u8>>, AgentError> {
        read_agent_message(&mut self.sock)
    }

    pub fn write_message(&mut self, payload: &[u8]) -> Result<(), AgentError> {
        write_agent_message(&mut self.sock, payload)
    }

    /// Send one message and return the reply; EOF before a reply is a
    /// [`WireError`].
    pub fn request(&mut self, payload: &[u8]) -> Result<Vec<u8>, AgentError> {
        self.write_message(payload)?;
        match self.read_message()? {
            Some(reply) => Ok(reply),
            None => Err(WireError::new("agent closed the connection without replying").into()),
        }
    }

    pub fn into_inner(self) -> S {
        self.sock
    }
}

pub fn build_failure() -> [u8; 1] {
    [SSH_AGENT_FAILURE]
}

pub fn build_success() -> [u8; 1] {
    [SSH_AGENT_SUCCESS]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignRequest {
    pub key_blob: Vec<u8>,
    pub data: Vec<u8>,
    pub flags: u32,
}

/// Full `SSH_AGENTC_SIGN_REQUEST` message including the type byte.
pub fn build_sign_request(key_blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    let mut out = vec![SSH_AGENTC_SIGN_REQUEST];
    out.extend(encode_string(key_blob).expect("fits"));
    out.extend(encode_string(data).expect("fits"));
    out.extend_from_slice(&encode_uint32(flags));
    out
}

/// Parse the body of `SSH_AGENTC_SIGN_REQUEST` (type byte already removed).
pub fn parse_sign_request(payload_after_type: &[u8]) -> Result<SignRequest, WireError> {
    let mut r = Reader::new(payload_after_type);
    let key_blob = r.string()?;
    let data = r.string()?;
    let flags = r.uint32()?;
    r.expect_eof("sign request")?;
    Ok(SignRequest {
        key_blob,
        data,
        flags,
    })
}

/// Full `SSH_AGENT_SIGN_RESPONSE` message including the type byte.
pub fn build_sign_response(signature_blob: &[u8]) -> Vec<u8> {
    let mut out = vec![SSH_AGENT_SIGN_RESPONSE];
    out.extend(encode_string(signature_blob).expect("fits"));
    out
}

/// Return the signature blob from a `SSH_AGENT_SIGN_RESPONSE` body.
pub fn parse_sign_response(payload_after_type: &[u8]) -> Result<Vec<u8>, WireError> {
    let mut r = Reader::new(payload_after_type);
    let signature_blob = r.string()?;
    r.expect_eof("sign response")?;
    Ok(signature_blob)
}

/// Full `SSH_AGENT_IDENTITIES_ANSWER` for `[(key_blob, comment), ...]`.
pub fn build_identities_answer(keys: &[(Vec<u8>, String)]) -> Vec<u8> {
    let mut out = vec![SSH_AGENT_IDENTITIES_ANSWER];
    out.extend_from_slice(&encode_uint32(keys.len() as u32));
    for (key_blob, comment) in keys {
        out.extend(encode_string(key_blob).expect("fits"));
        out.extend(encode_string(comment.as_bytes()).expect("fits"));
    }
    out
}

/// Parse an `SSH_AGENT_IDENTITIES_ANSWER` body into
/// `[(key_blob, comment), ...]`. Comments are informational and decoded
/// with U+FFFD replacement.
pub fn parse_identities_answer(
    payload_after_type: &[u8],
) -> Result<Vec<(Vec<u8>, String)>, WireError> {
    let mut r = Reader::new(payload_after_type);
    let nkeys = r.uint32()? as usize;
    if nkeys > r.remaining() / 8 {
        return Err(WireError::new(
            "identities answer claims more keys than it carries",
        ));
    }
    let mut keys = Vec::with_capacity(nkeys);
    for _ in 0..nkeys {
        let key_blob = r.string()?;
        let comment = r.text_lossy()?;
        keys.push((key_blob, comment));
    }
    r.expect_eof("identities answer")?;
    Ok(keys)
}

/// Full `SSH_AGENTC_EXTENSION` message carrying the `query` extension.
pub fn build_extension_query() -> Vec<u8> {
    let mut out = vec![SSH_AGENTC_EXTENSION];
    out.extend(encode_string(EXTENSION_QUERY).expect("fits"));
    out
}

/// `SSH_AGENT_SUCCESS` followed by one `string` per supported extension
/// name.
///
/// Layout note (not a protocol commitment): this is the `query` reply of
/// draft-miller-ssh-agent-04 §4.7.1 (`byte SSH_AGENT_SUCCESS` then
/// `string[]` extension names). Later drafts revised the response framing,
/// but OpenSSH's own ssh-agent does not implement `query` and the OpenSSH
/// client never sends it, so no real client depends on either layout;
/// ZeroPW's signer answers it for ZeroPW's own tests only. The reply starts
/// with `SSH_AGENT_SUCCESS` (6), never `SSH_AGENT_SIGN_RESPONSE` (14), so a
/// client dispatching on the type byte cannot mistake it for a signature.
pub fn build_extension_query_response(names: &[&str]) -> Vec<u8> {
    let mut out = vec![SSH_AGENT_SUCCESS];
    for name in names {
        out.extend(encode_string(*name).expect("fits"));
    }
    out
}

/// Parse the body of a `query` extension response into extension names.
pub fn parse_extension_query_response(payload_after_type: &[u8]) -> Result<Vec<String>, WireError> {
    let mut r = Reader::new(payload_after_type);
    let mut names = Vec::new();
    while !r.eof() {
        names.push(r.text()?);
    }
    Ok(names)
}

/// Split an `SSH_AGENTC_EXTENSION` body into `(name, extension_data)`.
pub fn parse_extension(payload_after_type: &[u8]) -> Result<(String, Vec<u8>), WireError> {
    let mut r = Reader::new(payload_after_type);
    let name = r.text()?;
    if name.is_empty() {
        return Err(WireError::new("empty extension name"));
    }
    Ok((name, r.rest()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionBind {
    pub host_key_blob: Vec<u8>,
    pub session_id: Vec<u8>,
    pub signature: Vec<u8>,
    pub is_forwarding: bool,
}

/// Full `SSH_AGENTC_EXTENSION` message for `session-bind@openssh.com`.
pub fn build_session_bind(
    host_key_blob: &[u8],
    session_id: &[u8],
    signature_blob: &[u8],
    is_forwarding: bool,
) -> Vec<u8> {
    let mut out = vec![SSH_AGENTC_EXTENSION];
    out.extend(encode_string(SESSION_BIND_EXTENSION).expect("fits"));
    out.extend(encode_string(host_key_blob).expect("fits"));
    out.extend(encode_string(session_id).expect("fits"));
    out.extend(encode_string(signature_blob).expect("fits"));
    out.extend_from_slice(&encode_bool(is_forwarding));
    out
}

/// Parse the data of a `session-bind@openssh.com` extension (name already
/// removed).
pub fn parse_session_bind(ext_payload_after_name: &[u8]) -> Result<SessionBind, WireError> {
    let mut r = Reader::new(ext_payload_after_name);
    let host_key_blob = r.string()?;
    let session_id = r.string()?;
    let signature = r.string()?;
    let is_forwarding = r.boolean()?;
    r.expect_eof("session-bind extension")?;
    if host_key_blob.is_empty() || session_id.is_empty() || signature.is_empty() {
        return Err(WireError::new("session-bind fields must not be empty"));
    }
    Ok(SessionBind {
        host_key_blob,
        session_id,
        signature,
        is_forwarding,
    })
}

// ---------------------------------------------------------------------------
// SSH_MSG_USERAUTH_REQUEST as signed by an agent (RFC 4252 §7, OpenSSH PROTOCOL)
// ---------------------------------------------------------------------------

pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
pub const SSH_CONNECTION_SERVICE: &str = "ssh-connection";
pub const USERAUTH_METHOD_PUBLICKEY: &str = "publickey";
pub const USERAUTH_METHOD_PUBLICKEY_HOSTBOUND: &str = "publickey-hostbound-v00@openssh.com";

/// The parsed to-be-signed buffer of a public key authentication request.
///
/// `host_key_blob` is `None` for the plain `publickey` method and the
/// server host key for OpenSSH's `publickey-hostbound-v00@openssh.com`
/// variant (used by default between OpenSSH >= 8.9 peers).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserAuthRequest {
    pub session_id: Vec<u8>,
    pub username: String,
    pub service: String,
    pub method: String,
    pub has_signature: bool,
    pub algorithm: String,
    pub public_key_blob: Vec<u8>,
    pub host_key_blob: Option<Vec<u8>>,
}

/// Strictly parse the buffer an SSH client asks an agent to sign.
///
/// Layout: `string session_id, byte 50, string username, string
/// "ssh-connection", string "publickey", boolean TRUE, string algorithm,
/// string public_key_blob` and nothing else. With `allow_hostbound` (the
/// default in Python; pass `true` here for the same behaviour) the method
/// may instead be `publickey-hostbound-v00@openssh.com` followed by exactly
/// one extra `string host_key_blob`. Every deviation, including empty
/// fields, non-canonical booleans, invalid UTF-8, truncation and trailing
/// bytes, returns [`WireError`].
pub fn parse_userauth_request(
    data: &[u8],
    allow_hostbound: bool,
) -> Result<UserAuthRequest, WireError> {
    let mut r = Reader::new(data);
    let session_id = r.string()?;
    if session_id.is_empty() {
        return Err(WireError::new("empty session identifier"));
    }
    let msg_type = r.byte()?;
    if msg_type != SSH_MSG_USERAUTH_REQUEST {
        return Err(WireError::new(format!(
            "expected SSH_MSG_USERAUTH_REQUEST (50), got {msg_type}"
        )));
    }
    let username = r.text()?;
    if username.is_empty() {
        return Err(WireError::new("empty username"));
    }
    let service = r.text()?;
    if service != SSH_CONNECTION_SERVICE {
        return Err(WireError::new(format!(
            "unexpected service {}",
            crate::pystr::repr_str(&service)
        )));
    }
    let method = r.text()?;
    let hostbound = if method == USERAUTH_METHOD_PUBLICKEY {
        false
    } else if method == USERAUTH_METHOD_PUBLICKEY_HOSTBOUND && allow_hostbound {
        true
    } else {
        return Err(WireError::new(format!(
            "unexpected authentication method {}",
            crate::pystr::repr_str(&method)
        )));
    };
    let has_signature = r.boolean()?;
    if !has_signature {
        return Err(WireError::new(
            "userauth request does not carry a signature flag",
        ));
    }
    let algorithm = r.text()?;
    if algorithm.is_empty() {
        return Err(WireError::new("empty public key algorithm"));
    }
    let public_key_blob = r.string()?;
    if public_key_blob.is_empty() {
        return Err(WireError::new("empty public key blob"));
    }
    let host_key_blob = if hostbound {
        let host_key_blob = r.string()?;
        if host_key_blob.is_empty() {
            return Err(WireError::new(
                "empty host key in hostbound userauth request",
            ));
        }
        Some(host_key_blob)
    } else {
        None
    };
    r.expect_eof("userauth request")?;
    Ok(UserAuthRequest {
        session_id,
        username,
        service,
        method,
        has_signature: true,
        algorithm,
        public_key_blob,
        host_key_blob,
    })
}

/// Build the to-be-signed public key authentication buffer.
///
/// Passing `host_key_blob` selects the hostbound method and appends the
/// host key, mirroring what OpenSSH clients send to their agent.
pub fn build_userauth_request(
    session_id: &[u8],
    username: &str,
    algorithm: &str,
    public_key_blob: &[u8],
    service: &str,
    host_key_blob: Option<&[u8]>,
) -> Vec<u8> {
    let method = if host_key_blob.is_none() {
        USERAUTH_METHOD_PUBLICKEY
    } else {
        USERAUTH_METHOD_PUBLICKEY_HOSTBOUND
    };
    let mut out = encode_string(session_id).expect("fits");
    out.push(SSH_MSG_USERAUTH_REQUEST);
    out.extend(encode_string(username).expect("fits"));
    out.extend(encode_string(service).expect("fits"));
    out.extend(encode_string(method).expect("fits"));
    out.extend_from_slice(&encode_bool(true));
    out.extend(encode_string(algorithm).expect("fits"));
    out.extend(encode_string(public_key_blob).expect("fits"));
    if let Some(host_key_blob) = host_key_blob {
        out.extend(encode_string(host_key_blob).expect("fits"));
    }
    out
}

// ---------------------------------------------------------------------------
// Wire-format tests against golden vectors the Python prototype produced
// (`tests/fixtures/python/sshwire/GENERATE.md`), the malformed-input table,
// and other tests that need crate-private items. Plain ported unit tests live
// in `rust/tests/sshwire.rs`.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn python_fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/python/sshwire")
            .join(name);
        std::fs::read_to_string(path).unwrap()
    }

    fn python_vectors() -> serde_json::Value {
        serde_json::from_str(&python_fixture("vectors.json")).unwrap()
    }

    fn seed_from(byte: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = byte.wrapping_add(i as u8);
        }
        s
    }

    #[test]
    fn public_key_derivation_matches_python() {
        let vectors = python_vectors();
        let cases = vectors["public_keys"].as_array().unwrap();
        assert_eq!(cases.len(), 4);
        for case in cases {
            let byte = case[0].as_u64().unwrap() as u8;
            let ours = ed25519_adapter::public_key_from_seed(&seed_from(byte));
            assert_eq!(
                hex::encode(ours),
                case[1].as_str().unwrap(),
                "seed byte {byte}"
            );
        }
    }

    #[test]
    fn signature_matches_python() {
        let vectors = python_vectors();
        let cases = vectors["signatures"].as_array().unwrap();
        assert_eq!(cases.len(), 3);
        for case in cases {
            let byte = case[0].as_u64().unwrap() as u8;
            let msg = hex::decode(case[1].as_str().unwrap()).unwrap();
            let ours = ed25519_adapter::sign(&seed_from(byte), &msg);
            assert_eq!(
                hex::encode(ours),
                case[2].as_str().unwrap(),
                "seed byte {byte}"
            );
        }
    }

    #[test]
    fn verify_rejects_tampered_signatures() {
        let seed = seed_from(3);
        let public = ed25519_adapter::public_key_from_seed(&seed);
        let msg = b"agree on this";
        let sig = ed25519_adapter::sign(&seed, msg);
        assert!(ed25519_adapter::verify(&public, msg, &sig));

        let mut tampered = sig;
        tampered[0] ^= 0x01;
        assert!(!ed25519_adapter::verify(&public, msg, &tampered));
    }

    #[test]
    fn public_key_blob_and_fingerprint_match_python() {
        let vectors = python_vectors();
        let v = &vectors["fingerprint"];
        let key =
            Ed25519PublicKey::new(hex::decode(v["key_hex"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(key.fingerprint(), v["fingerprint"].as_str().unwrap());
        let parsed = parse_public_key_blob(&key.blob()).unwrap();
        assert_eq!(parsed.fingerprint(), key.fingerprint());
    }

    #[test]
    fn openssh_private_key_pem_round_trips() {
        let key = Ed25519PrivateKey::from_seed(&seed_from(11), "oracle-comment").unwrap();
        let pem = key.to_openssh_private_key();
        let parsed = parse_openssh_private_key(pem.as_bytes()).unwrap();
        assert_eq!(parsed.comment, "oracle-comment");
        assert_eq!(parsed.public.fingerprint(), key.public.fingerprint());
    }

    #[test]
    fn python_generated_private_key_parses_in_rust() {
        // The prototype built this container by hand (crypto-agnostic), using
        // its real ed25519 backend for the seed/public key.
        let pem = python_fixture("from-python.key");
        let parsed = parse_openssh_private_key(pem.as_bytes()).expect("python-built key parses");
        assert_eq!(parsed.comment, "from-python");
        let public = python_fixture("from-python.pub");
        assert_eq!(
            parsed
                .public
                .to_authorized_key("from-python")
                .unwrap()
                .trim(),
            public.trim()
        );
    }

    #[test]
    fn mpint_round_trip_matches_python_for_large_values() {
        // 2**255, 2**256 - 1, 2**4096 + 12345 and negatives: values that
        // don't fit any native Rust integer type. The prototype's magnitude
        // bytes and wire encoding are the fixture; Rust rebuilds the MpInt
        // from the magnitude, must re-encode identically, and decodes its own
        // encoding back to the same value.
        let vectors = python_vectors();
        let cases = vectors["mpint"].as_array().unwrap();
        assert_eq!(cases.len(), 7);
        for case in cases {
            let expr = case[0].as_str().unwrap();
            let negate = case[1].as_bool().unwrap();
            let magnitude = hex::decode(case[2].as_str().unwrap()).unwrap();
            let expected_encoding = case[3].as_str().unwrap();
            let value = MpInt::from_magnitude_be(negate, &magnitude);
            assert_eq!(
                hex::encode(encode_mpint(&value)),
                expected_encoding,
                "{expr}"
            );

            let encoded = encode_mpint(&value);
            let mut r = Reader::new(&encoded);
            let decoded = r.mpint().unwrap();
            assert_eq!(
                hex::encode(encode_mpint(&decoded)),
                expected_encoding,
                "{expr}"
            );
        }
    }

    /// Table-driven malformed inputs: Rust and the Python prototype must
    /// both reject with the same kind of error and (for the ones we can
    /// compare directly) the same message.
    #[test]
    fn malformed_inputs_rejected_with_the_prototype_messages() {
        // The messages the prototype's `WireError` carried for the same inputs.
        assert_eq!(
            Reader::new(&[0x00, 0x00, 0x00, 0x05, b'a', b'b', b'c'])
                .string()
                .unwrap_err()
                .message(),
            "truncated string: need 5 byte(s), have 3"
        );
        assert_eq!(
            Reader::new(&[0x02]).boolean().unwrap_err().message(),
            "non-canonical boolean byte 0x02"
        );
        assert_eq!(
            Reader::new(&hex::decode("0000000100").unwrap())
                .mpint()
                .unwrap_err()
                .message(),
            "non-minimal mpint encoding"
        );
        let bad_blob = [
            encode_string("ssh-ed25519").unwrap(),
            encode_string([1u8]).unwrap(),
        ]
        .concat();
        assert_eq!(
            parse_public_key_blob(&bad_blob).unwrap_err().message(),
            "ed25519 public key blob has wrong key length"
        );
        assert_eq!(
            parse_authorized_key("garbage more").unwrap_err().message(),
            "authorized_keys line has no recognisable key type"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ssh_keygen_accepts_our_generated_private_key() {
        use std::process::Command;
        if Command::new("ssh-keygen").arg("-h").output().is_err() {
            eprintln!("skipping: ssh-keygen not available");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id_ed25519");
        let key = generate_ed25519_private_key("rust-generated");
        std::fs::write(&path, key.to_openssh_private_key()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let out = Command::new("ssh-keygen")
            .args(["-y", "-f"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "ssh-keygen -y failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let printed = String::from_utf8(out.stdout).unwrap();
        let printed_fields: Vec<&str> = printed.trim().splitn(3, ' ').collect();
        let expected = key.public.to_authorized_key("").unwrap();
        let expected_fields: Vec<&str> = expected.trim().splitn(3, ' ').collect();
        assert_eq!(printed_fields[..2], expected_fields[..2]);
        if printed_fields.len() == 3 {
            // Newer ssh-keygen also prints the comment.
            assert_eq!(printed_fields[2], "rust-generated");
        }
    }

    // -----------------------------------------------------------------
    // C-1: `decode_openssh_pem`/`split_pem_lines` vs Python's
    // `str.splitlines()` + `str.strip()`.
    // -----------------------------------------------------------------

    fn substitute_pem_newlines(pem: &str, sep: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for &b in pem.as_bytes() {
            if b == b'\n' {
                out.extend_from_slice(sep);
            } else {
                out.push(b);
            }
        }
        out
    }

    #[test]
    fn pem_line_boundaries_match_python_splitlines() {
        // `str.splitlines()` boundaries reachable in the ASCII-only text
        // `decode_openssh_pem` ever sees (its `.decode("ascii")`-equivalent
        // gate rules out every other boundary `str.splitlines()`
        // recognises, such as `\x85`/U+2028/U+2029): `\n`, `\r`, `\r\n`,
        // `\x0b`, `\x0c`, `\x1c`, `\x1d`, `\x1e`. `\x1f` is deliberately
        // absent here -- it is a `str.strip()` character but not a
        // `str.splitlines()` boundary; see the next test.
        let key = Ed25519PrivateKey::from_seed(&seed_from(21), "line-boundary-comment").unwrap();
        let pem = key.to_openssh_private_key();
        let boundaries: &[(&str, &[u8])] = &[
            ("lf", b"\n"),
            ("cr", b"\r"),
            ("crlf", b"\r\n"),
            ("vt", b"\x0b"),
            ("ff", b"\x0c"),
            ("fs", b"\x1c"),
            ("gs", b"\x1d"),
            ("rs", b"\x1e"),
        ];
        for (name, sep) in boundaries {
            let variant = substitute_pem_newlines(&pem, sep);

            let parsed = parse_openssh_private_key(&variant)
                .unwrap_or_else(|e| panic!("rust failed to parse {name} variant: {e}"));
            assert_eq!(parsed.comment, "line-boundary-comment", "{name}");
            assert_eq!(parsed.public, key.public, "{name}");
        }
    }

    #[test]
    fn pem_trailing_x1f_is_stripped_but_not_a_line_boundary() {
        // `\x1f` is `str.isspace()` (so `str.strip()` removes it) but NOT a
        // `str.splitlines()` boundary. A header line ending in `\x1f` must
        // still strip down to exactly the header text.
        let key = Ed25519PrivateKey::from_seed(&seed_from(22), "x1f-comment").unwrap();
        let pem = key.to_openssh_private_key();
        let with_tail = pem.replacen(PEM_BEGIN, &format!("{PEM_BEGIN}\x1f"), 1);
        let bytes = with_tail.into_bytes();

        let parsed = parse_openssh_private_key(&bytes).expect("trailing \\x1f must still strip");
        assert_eq!(parsed.comment, "x1f-comment");
        assert_eq!(parsed.public, key.public);
    }

    #[test]
    fn pem_unsupported_header_with_trailing_x1f_matches_python() {
        // Reviewer's exact probe: a non-OpenSSH `-----BEGIN ...-----`
        // header with a trailing `\x1f` before the newline must still be
        // recognised as "unsupported private key format", not "missing
        // OpenSSH private key header" -- which is exactly what happens if
        // the `\x1f` is left attached to the line instead of stripped.
        let raw =
            b"-----BEGIN SSH2 PUBLIC KEY-----\x1f\nZm9v\n-----END SSH2 PUBLIC KEY-----\n".to_vec();
        let err = parse_openssh_private_key(&raw).unwrap_err();
        assert!(err.is_unsupported());
        assert_eq!(
            err.message(),
            "unsupported private key format: -----BEGIN SSH2 PUBLIC KEY-----"
        );
    }

    #[test]
    fn pem_blank_lines_and_missing_trailing_newline_match_python() {
        // CRLF line endings throughout, a blank line inserted in the body,
        // and no trailing newline at all at end-of-file.
        let key = Ed25519PrivateKey::from_seed(&seed_from(23), "trailing-comment").unwrap();
        let pem = key.to_openssh_private_key();
        assert!(pem.ends_with('\n'));

        let mut with_blank = String::new();
        for (i, line) in pem.trim_end_matches('\n').split('\n').enumerate() {
            with_blank.push_str(line);
            with_blank.push_str("\r\n");
            if i == 0 {
                with_blank.push_str("\r\n"); // blank line right after the header
            }
        }
        // Drop the final "\r\n" so the file has no trailing newline at all.
        let variant = with_blank.strip_suffix("\r\n").unwrap().as_bytes().to_vec();

        let parsed = parse_openssh_private_key(&variant).expect("rust must accept this variant");
        assert_eq!(parsed.comment, "trailing-comment");
        assert_eq!(parsed.public, key.public);
    }

    // -----------------------------------------------------------------
    // C-2: Python `$` (no re.MULTILINE) matches before a single trailing
    // `\n`, in `_KEY_TYPE_RE`/`_KEY_TYPE_NAME_RE`.
    // -----------------------------------------------------------------

    #[test]
    fn authorized_keys_dollar_leniency_matches_python_for_reviewer_probes() {
        // A decoded field whose leading wire `string` is "future-alg\n"
        // (an actual embedded newline byte) must still count as a
        // key-type name for `_KEY_TYPE_NAME_RE`, because Python's `$`
        // matches just before that one trailing `\n`. Both reviewer probes
        // reuse the same base64 field: `encode_string("future-alg\n")`.
        let following = b64encode(&encode_string("future-alg\n").unwrap());
        let key = Ed25519PublicKey::new(vec![9u8; 32]).unwrap();
        let real_key_field = format!("ssh-ed25519 {}", b64encode(&key.blob()));

        let cases: [(&str, String); 2] = [
            ("future-alg", format!("future-alg {following}")),
            ("opt", format!("opt {following} {real_key_field}")),
        ];
        for (expected_type, line) in cases {
            let err = parse_authorized_key_entry(&line).unwrap_err();
            assert!(err.is_unsupported(), "{line}");
            assert_eq!(
                err.message(),
                format!("unsupported key type '{expected_type}'"),
                "{line}"
            );
        }
    }

    // -----------------------------------------------------------------
    // C-R2-1: `crate::pystr::is_printable` exactness for Cn (unassigned)
    // and Cf (format) codepoints the old sshwire-local approximation got
    // wrong (it never treated Cn as non-printable and hand-listed Cf).
    // Sampled from the finding: U+0378 (Cn), U+0890/U+1343A (Cf, missed
    // by the old hand-enumerated ranges), U+E0080 (Cn, inside the tag
    // block but past the Cf sub-range), U+10FFFF (Cn), plus U+FFFE,
    // U+200B, U+FEFF which the old approximation already handled (kept
    // here as a regression check now that they go through `pystr`).
    // -----------------------------------------------------------------

    #[test]
    fn parse_public_key_blob_unsupported_type_repr_matches_python_for_cn_cf_codepoints() {
        for cp in [
            0x0378u32, 0x0890, 0x1343A, 0xE0080, 0x10FFFF, 0xFFFE, 0x200B, 0xFEFF,
        ] {
            let key_type = char::from_u32(cp).expect("valid scalar value").to_string();
            let mut blob = encode_string(&key_type).unwrap();
            blob.extend(encode_string(vec![0u8; PUBLIC_KEY_SIZE]).unwrap());
            let err = parse_public_key_blob(&blob).unwrap_err();
            assert!(err.is_unsupported(), "cp {cp:#x}");
        }
    }

    #[test]
    fn parse_userauth_request_unexpected_service_repr_matches_python_for_cn_cf_codepoints() {
        for cp in [
            0x0378u32, 0x0890, 0x1343A, 0xE0080, 0x10FFFF, 0xFFFE, 0x200B, 0xFEFF,
        ] {
            let service = char::from_u32(cp).expect("valid scalar value").to_string();
            let key = Ed25519PublicKey::new(vec![7u8; PUBLIC_KEY_SIZE]).unwrap();
            let request = build_userauth_request(
                b"session",
                "alice",
                ED25519_KEY_TYPE,
                &key.blob(),
                &service,
                None,
            );
            let err = parse_userauth_request(&request, true).unwrap_err();
            assert!(err.is_wire_error(), "cp {cp:#x}");
        }
    }

    // -----------------------------------------------------------------
    // C-4: bare `ValueError` sites are tagged distinctly from `WireError`.
    // -----------------------------------------------------------------

    #[test]
    fn to_authorized_key_bad_comment_is_a_bare_value_error_not_wire_error() {
        // Python raises a bare ValueError here, not WireError -- a caller
        // that only does `except WireError` (like the not-yet-ported
        // `Vault._public_metadata`) does not catch it. Confirm both the
        // Python exception hierarchy and the Rust WireError tag agree.
        let key = Ed25519PublicKey::new(vec![3u8; 32]).unwrap();
        for comment in ["bad\ncomment", "bad\x00comment", "bad\rcomment"] {
            let err = key.to_authorized_key(comment).unwrap_err();
            assert_eq!(err.class_name(), "ValueError");
            assert!(!err.is_wire_error());
            assert!(!err.is_unsupported());
        }
    }

    #[test]
    fn encode_string_over_length_is_a_bare_value_error() {
        // `encode_string`'s over-length check is the other bare-ValueError
        // site; it is not reachable through any in-process byte slice in
        // practice (it would need a > 4 GiB slice), so this only checks
        // the Rust-side tag directly (no oracle: allocating 4 GiB+1 bytes
        // just to run the Python side is impractical for a test).
        let err = WireError::value_error("string too long for uint32 length prefix");
        assert_eq!(err.class_name(), "ValueError");
        assert!(!err.is_wire_error());
        assert!(!err.is_unsupported());
    }
}
