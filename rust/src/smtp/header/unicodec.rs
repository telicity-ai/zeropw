//! CPython 3.12.14's algorithmic text codecs, as `bytes.decode(charset[,
//! errors])` runs them: the UTF-16/UTF-32/UTF-7 and (raw-)unicode-escape
//! decoders of `Objects/unicodeobject.c` (with `stringlib/codecs.h`'s
//! `utf16_decode`), and the pure-Python `encodings.punycode` and
//! `encodings.idna` codecs (with `stringprep`'s nameprep tables and
//! `unicodedata.ucd_3_2_0.normalize("NFKC", ...)` from
//! `Modules/unicodedata.c`).
//!
//! Every decoder reports errors at the positions CPython does and resumes
//! where the error handler says, because `surrogateescape` escapes only the
//! leading non-ASCII bytes of a reported range.

use super::unicode_tables as t;
use super::{DecodeFail, Errors, Text, decode_error};
use std::collections::HashMap;
use std::sync::OnceLock;

/// The byte order of a UTF-16/UTF-32 codec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Endian {
    /// `utf_16`/`utf_32`: a leading BOM picks the order, else native
    /// (little-endian on every platform this port runs on).
    Bom,
    Little,
    Big,
}

fn is_surrogate(c: u32) -> bool {
    (0xD800..=0xDFFF).contains(&c)
}

// ----------------------------------------------------------------- UTF-16

/// `PyUnicode_DecodeUTF16Stateful(s, size, errors, &byteorder, NULL)`.
pub(super) fn decode_utf16(
    bytes: &[u8],
    endian: Endian,
    errors: Errors,
) -> Result<Text, DecodeFail> {
    let e = bytes.len();
    let mut q = 0;
    let mut bo = match endian {
        Endian::Bom => 0,
        Endian::Little => -1,
        Endian::Big => 1,
    };
    let at = |i: usize| bytes.get(i).copied().map_or(0, u32::from);
    if bo == 0 && e >= 2 {
        match (at(1) << 8) | at(0) {
            0xFEFF => {
                q = 2;
                bo = -1;
            }
            0xFFFE => {
                q = 2;
                bo = 1;
            }
            _ => {}
        }
    }
    let mut out = Text::with_capacity(e / 2);
    if q == e {
        return Ok(out);
    }
    let native = bo <= 0;
    let unit = |i: usize| {
        if native {
            (at(i + 1) << 8) | at(i)
        } else {
            (at(i) << 8) | at(i + 1)
        }
    };
    loop {
        // `utf16_decode`: 0 ran out, 1 unexpected end, 2 illegal encoding,
        // 3 illegal surrogate.
        let mut status = 0;
        while q + 1 < e {
            let ch = unit(q);
            q += 2;
            if !is_surrogate(ch) {
                out.push(ch);
                continue;
            }
            if ch >= 0xDC00 {
                status = 2;
                break;
            }
            if q + 1 >= e {
                status = 1;
                break;
            }
            let ch2 = unit(q);
            q += 2;
            if !(0xDC00..=0xDFFF).contains(&ch2) {
                status = 3;
                break;
            }
            out.push(0x10000 + (((ch & 0x3FF) << 10) | (ch2 & 0x3FF)));
        }
        let (start, end) = match status {
            0 => {
                if q == e {
                    break;
                }
                (q, e) // truncated data
            }
            1 => {
                q -= 2;
                (q, e) // unexpected end of data
            }
            2 => (q - 2, q),     // illegal encoding
            _ => (q - 4, q - 2), // illegal UTF-16 surrogate
        };
        q = decode_error(errors, bytes, start, end, &mut out)?;
    }
    Ok(out)
}

// ----------------------------------------------------------------- UTF-32

/// `PyUnicode_DecodeUTF32Stateful(s, size, errors, &byteorder, NULL)`.
pub(super) fn decode_utf32(
    bytes: &[u8],
    endian: Endian,
    errors: Errors,
) -> Result<Text, DecodeFail> {
    let e = bytes.len();
    let mut q = 0;
    let mut bo = match endian {
        Endian::Bom => 0,
        Endian::Little => -1,
        Endian::Big => 1,
    };
    let at = |i: usize| bytes.get(i).copied().map_or(0, u32::from);
    if bo == 0 && e >= 4 {
        match (at(3) << 24) | (at(2) << 16) | (at(1) << 8) | at(0) {
            0x0000_FEFF => {
                bo = -1;
                q = 4;
            }
            0xFFFE_0000 => {
                bo = 1;
                q = 4;
            }
            _ => {}
        }
    }
    let mut out = Text::with_capacity(e / 4);
    if q == e {
        return Ok(out);
    }
    let le = bo <= 0;
    loop {
        let mut range = None;
        while e - q >= 4 {
            let ch = if le {
                (at(q + 3) << 24) | (at(q + 2) << 16) | (at(q + 1) << 8) | at(q)
            } else {
                (at(q) << 24) | (at(q + 1) << 16) | (at(q + 2) << 8) | at(q + 3)
            };
            if is_surrogate(ch) || ch >= 0x110000 {
                range = Some((q, q + 4));
                break;
            }
            out.push(ch);
            q += 4;
        }
        let (start, end) = match range {
            Some(range) => range,
            None if q == e => break,
            None => (q, e), // truncated data
        };
        q = decode_error(errors, bytes, start, end, &mut out)?;
    }
    Ok(out)
}

// ------------------------------------------------------------------ UTF-7

fn is_base64(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'+' || c == b'/'
}

fn from_base64(c: u8) -> u64 {
    u64::from(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        _ => 63,
    })
}

/// `PyUnicode_DecodeUTF7Stateful(s, size, errors, NULL)`.
pub(super) fn decode_utf7(bytes: &[u8], errors: Errors) -> Result<Text, DecodeFail> {
    let e = bytes.len();
    let mut out = Text::with_capacity(e);
    let mut s = 0;
    let mut in_shift = false;
    let mut base64bits: u32 = 0;
    let mut base64buffer: u64 = 0;
    let mut surrogate: u32 = 0;
    let mut startinpos = 0;
    loop {
        while s < e {
            let ch = bytes[s];
            let failed_at = if in_shift {
                // in a base-64 section
                if is_base64(ch) {
                    base64buffer = (base64buffer << 6) | from_base64(ch);
                    base64bits += 6;
                    s += 1;
                    if base64bits >= 16 {
                        // we have enough bits for a UTF-16 value
                        let out_ch = u32::try_from(base64buffer >> (base64bits - 16)).unwrap_or(0);
                        base64bits -= 16;
                        base64buffer &= (1 << base64bits) - 1;
                        if surrogate != 0 {
                            // expecting a second surrogate
                            if (0xDC00..=0xDFFF).contains(&out_ch) {
                                out.push(
                                    0x10000 + (((surrogate & 0x3FF) << 10) | (out_ch & 0x3FF)),
                                );
                                surrogate = 0;
                                continue;
                            }
                            out.push(surrogate);
                            surrogate = 0;
                        }
                        if (0xD800..=0xDBFF).contains(&out_ch) {
                            surrogate = out_ch; // first surrogate
                        } else {
                            out.push(out_ch);
                        }
                    }
                    None
                } else {
                    // now leaving a base-64 section
                    in_shift = false;
                    if base64bits > 0 && (base64bits >= 6 || base64buffer != 0) {
                        // partial character / non-zero padding bits
                        s += 1;
                        Some(startinpos)
                    } else {
                        if surrogate != 0 && ch <= 127 && ch != b'+' {
                            out.push(surrogate);
                        }
                        surrogate = 0;
                        if ch == b'-' {
                            // '-' is absorbed; other terminating characters
                            // are preserved
                            s += 1;
                        }
                        None
                    }
                }
            } else if ch == b'+' {
                startinpos = s;
                s += 1; // consume '+'
                if s < e && bytes[s] == b'-' {
                    // '+-' encodes '+'
                    s += 1;
                    out.push(u32::from(b'+'));
                    None
                } else if s < e && !is_base64(bytes[s]) {
                    s += 1;
                    Some(startinpos) // ill-formed sequence
                } else {
                    // begin base64-encoded section
                    in_shift = true;
                    surrogate = 0;
                    base64bits = 0;
                    base64buffer = 0;
                    None
                }
            } else if ch <= 127 {
                // character decodes as itself
                s += 1;
                out.push(u32::from(ch));
                None
            } else {
                startinpos = s;
                s += 1;
                Some(startinpos) // unexpected special character
            };
            if let Some(start) = failed_at {
                s = decode_error(errors, bytes, start, s, &mut out)?;
            }
        }
        // end of string
        if in_shift {
            // in shift sequence, no more to follow
            in_shift = false;
            if surrogate != 0 || base64bits >= 6 || (base64bits > 0 && base64buffer != 0) {
                // unterminated shift sequence
                s = decode_error(errors, bytes, startinpos, e, &mut out)?;
                if s < e {
                    continue;
                }
            }
        }
        break;
    }
    Ok(out)
}

// ------------------------------------------------- (raw-)unicode-escape

fn hex_value(c: u8) -> Option<u32> {
    char::from(c).to_digit(16)
}

/// `_PyUnicode_DecodeUnicodeEscapeStateful(s, size, errors, NULL)`: the
/// `DeprecationWarning` for an invalid escape is ignored under the default
/// warning filters (it is attributed to `email._encoded_words`).
pub(super) fn decode_unicode_escape(bytes: &[u8], errors: Errors) -> Result<Text, DecodeFail> {
    let end = bytes.len();
    let mut out = Text::with_capacity(end);
    let mut s = 0;
    while s < end {
        let c = bytes[s];
        s += 1;
        // Non-escape characters are interpreted as Unicode ordinals.
        if c != b'\\' {
            out.push(u32::from(c));
            continue;
        }
        let startinpos = s - 1;
        let Some(&c) = bytes.get(s) else {
            // \ at end of string
            s = decode_error(errors, bytes, startinpos, s, &mut out)?;
            continue;
        };
        s += 1;
        let simple = match c {
            b'\n' => Some(None),
            b'\\' => Some(Some(u32::from(b'\\'))),
            b'\'' => Some(Some(u32::from(b'\''))),
            b'"' => Some(Some(u32::from(b'"'))),
            b'b' => Some(Some(0x08)),
            b'f' => Some(Some(0x0C)),
            b't' => Some(Some(0x09)),
            b'n' => Some(Some(0x0A)),
            b'r' => Some(Some(0x0D)),
            b'v' => Some(Some(0x0B)),
            b'a' => Some(Some(0x07)),
            _ => None,
        };
        if let Some(ch) = simple {
            out.extend(ch);
            continue;
        }
        match c {
            b'0'..=b'7' => {
                // \OOO (octal) escapes
                let mut ch = u32::from(c - b'0');
                for _ in 0..2 {
                    match bytes.get(s) {
                        Some(&d @ b'0'..=b'7') => {
                            ch = (ch << 3) + u32::from(d - b'0');
                            s += 1;
                        }
                        _ => break,
                    }
                }
                out.push(ch);
            }
            b'x' | b'u' | b'U' => {
                // hex escapes
                let count = match c {
                    b'x' => 2,
                    b'u' => 4,
                    _ => 8,
                };
                let mut ch: u32 = 0;
                let mut ok = true;
                for _ in 0..count {
                    match bytes.get(s).copied().and_then(hex_value) {
                        Some(digit) => {
                            ch = (ch << 4) + digit;
                            s += 1;
                        }
                        // truncated escape: incomplete at the end of input,
                        // an error at a non-hex digit; both end at `s`.
                        None => {
                            ok = false;
                            break;
                        }
                    }
                }
                if ok && ch <= 0x10FFFF {
                    out.push(ch);
                } else {
                    // ... or "illegal Unicode character"
                    s = decode_error(errors, bytes, startinpos, s, &mut out)?;
                }
            }
            b'N' => {
                // \N{name}
                let mut decoded = None;
                if bytes.get(s) == Some(&b'{') {
                    s += 1;
                    let start = s;
                    while s < end && bytes[s] != b'}' {
                        s += 1;
                    }
                    if s < end {
                        let name = &bytes[start..s];
                        if !name.is_empty() {
                            s += 1;
                            decoded = lookup_name(name);
                        }
                    }
                }
                match decoded {
                    Some(ch) => out.push(ch),
                    None => s = decode_error(errors, bytes, startinpos, s, &mut out)?,
                }
            }
            _ => {
                out.push(u32::from(b'\\'));
                out.push(u32::from(c));
            }
        }
    }
    Ok(out)
}

/// `_PyUnicode_DecodeRawUnicodeEscapeStateful(s, size, errors, NULL)`.
pub(super) fn decode_raw_unicode_escape(bytes: &[u8], errors: Errors) -> Result<Text, DecodeFail> {
    let end = bytes.len();
    let mut out = Text::with_capacity(end);
    let mut s = 0;
    while s < end {
        let c = bytes[s];
        s += 1;
        // Non-escape characters are interpreted as Unicode ordinals.
        if c != b'\\' || s >= end {
            out.push(u32::from(c));
            continue;
        }
        let startinpos = s - 1;
        let c = bytes[s];
        s += 1;
        let count = match c {
            b'u' => 4,
            b'U' => 8,
            _ => {
                out.push(u32::from(b'\\'));
                out.push(u32::from(c));
                continue;
            }
        };
        let mut ch: u32 = 0;
        let mut ok = true;
        for _ in 0..count {
            match bytes.get(s).copied().and_then(hex_value) {
                Some(digit) => {
                    ch = (ch << 4) + digit;
                    s += 1;
                }
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if ok && ch <= 0x10FFFF {
            out.push(ch);
        } else {
            s = decode_error(errors, bytes, startinpos, s, &mut out)?;
        }
    }
    Ok(out)
}

// ------------------------------------------------- Unicode name lookup

const S_BASE: u32 = 0xAC00;
const L_BASE: u32 = 0x1100;
const V_BASE: u32 = 0x1161;
const T_BASE: u32 = 0x11A7;
const L_COUNT: u32 = 19;
const V_COUNT: u32 = 21;
const T_COUNT: u32 = 28;
const N_COUNT: u32 = V_COUNT * T_COUNT;
const S_COUNT: u32 = L_COUNT * N_COUNT;

/// `hangul_syllables` (`Modules/unicodedata.c`), by column.
const HANGUL_L: [&str; 19] = [
    "G", "GG", "N", "D", "DD", "R", "M", "B", "BB", "S", "SS", "", "J", "JJ", "C", "K", "T", "P",
    "H",
];
const HANGUL_V: [&str; 21] = [
    "A", "AE", "YA", "YAE", "EO", "E", "YEO", "YE", "O", "WA", "WAE", "OE", "YO", "U", "WEO", "WE",
    "WI", "YU", "EU", "YI", "I",
];
const HANGUL_T: [&str; 28] = [
    "", "G", "GG", "GS", "N", "NJ", "NH", "D", "L", "LG", "LM", "LB", "LS", "LT", "LP", "LH", "M",
    "B", "BS", "S", "SS", "NG", "J", "C", "K", "T", "P", "H",
];

/// `find_syllable`: the longest component (first of equal length) that
/// starts `s`, as `(length, index)`.
fn find_syllable(s: &[u8], column: &[&str]) -> (usize, Option<u32>) {
    let mut len: Option<usize> = None;
    let mut pos = None;
    for (index, component) in (0u32..).zip(column) {
        let len1 = component.len();
        if len.is_some_and(|len| len1 <= len) {
            continue;
        }
        if s.starts_with(component.as_bytes()) {
            len = Some(len1);
            pos = Some(index);
        }
    }
    (len.unwrap_or(0), pos)
}

/// A reader over `NAME_DATA`'s bytes.
struct Cursor {
    data: Vec<u8>,
    pos: usize,
}

impl Cursor {
    fn byte(&mut self) -> Option<u8> {
        let byte = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    fn leb128(&mut self) -> Option<usize> {
        let mut value = 0usize;
        let mut shift = 0u32;
        loop {
            let byte = self.byte()?;
            value |= usize::from(byte & 0x7F).checked_shl(shift)?;
            if byte & 0x80 == 0 {
                return Some(value);
            }
            shift += 7;
        }
    }

    /// One record header: `(gap, shared, fresh)`.
    fn header(&mut self) -> Option<(usize, usize, usize)> {
        match self.byte()? {
            0xFF => Some((self.leb128()?, self.leb128()?, self.leb128()?)),
            byte => Some((0, usize::from(byte >> 4), usize::from(byte & 0x0F))),
        }
    }
}

/// Every name `code_hash` can find, upper case -> code point (aliases
/// resolved).
fn names() -> &'static HashMap<Vec<u8>, u32> {
    static NAMES: OnceLock<HashMap<Vec<u8>, u32>> = OnceLock::new();
    NAMES.get_or_init(|| {
        let words: Vec<&str> = t::NAME_WORDS.split(' ').collect();
        let mut cursor = Cursor {
            data: crate::pybase64::b64decode_bytes(t::NAME_DATA.as_bytes()).unwrap_or_default(),
            pos: 0,
        };
        let mut map = HashMap::with_capacity(t::NAME_COUNT + t::NAME_ALIASES.len());
        let mut next_code: usize = 0;
        let mut name: Vec<&str> = Vec::new();
        while let Some((gap, shared, fresh)) = cursor.header() {
            let code = next_code + gap;
            next_code = code + 1;
            name.truncate(shared);
            for _ in 0..fresh {
                if let Some(word) = cursor.leb128().and_then(|i| words.get(i)) {
                    name.push(word);
                }
            }
            if let Ok(code) = u32::try_from(code) {
                map.insert(name.join(" ").into_bytes(), code);
            }
        }
        for (alias, code) in t::NAME_ALIASES {
            map.insert(alias.as_bytes().to_vec(), *code);
        }
        map
    })
}

/// `_getcode(NULL, name, namelen, &code, 0)` (`Modules/unicodedata.c`).
pub(super) fn lookup_name(name: &[u8]) -> Option<u32> {
    // Check for hangul syllables.
    if let Some(rest) = name.strip_prefix(b"HANGUL SYLLABLE ") {
        let (len, l) = find_syllable(rest, &HANGUL_L);
        let rest = &rest[len..];
        let (len, v) = find_syllable(rest, &HANGUL_V);
        let rest = &rest[len..];
        let (len, t) = find_syllable(rest, &HANGUL_T);
        let rest = &rest[len..];
        return match (l, v, t) {
            (Some(l), Some(v), Some(t)) if rest.is_empty() => {
                Some(S_BASE + (l * V_COUNT + v) * T_COUNT + t)
            }
            // Otherwise, it's an illegal syllable name.
            _ => None,
        };
    }
    // Check for unified ideographs.
    if let Some(hex) = name.strip_prefix(b"CJK UNIFIED IDEOGRAPH-") {
        // Four or five hexdigits must follow.
        if hex.len() != 4 && hex.len() != 5 {
            return None;
        }
        let mut v: u32 = 0;
        for &c in hex {
            let digit = match c {
                b'0'..=b'9' => c - b'0',
                b'A'..=b'F' => c - b'A' + 10,
                _ => return None,
            };
            v = v * 16 + u32::from(digit);
        }
        return t::CJK_UNIFIED_IDEOGRAPHS
            .iter()
            .any(|(lo, hi)| (*lo..=*hi).contains(&v))
            .then_some(v);
    }
    // The `code_hash` lookup compares `Py_TOUPPER(name[i])` with the stored
    // (upper-case ASCII) name.
    names().get(&name.to_ascii_uppercase()).copied()
}

// ------------------------------------------------------------- punycode

/// `punycode.T(j, bias)`.
fn punycode_t(j: u128, bias: u128) -> u128 {
    (36 * (j + 1)).saturating_sub(bias).clamp(1, 26)
}

/// `punycode.adapt(delta, first, numchars)`.
fn adapt(delta: u128, first: bool, numchars: u128) -> u128 {
    let mut delta = if first { delta / 700 } else { delta / 2 };
    delta += delta / numchars.max(1);
    let mut divisions = 0;
    while delta > 455 {
        delta /= 35; // base - tmin
        divisions += 36;
    }
    divisions + (36 * delta / (delta + 38))
}

/// Why `punycode_decode` raised.
enum PunyError {
    /// `UnicodeDecodeError` from `str(..., "ascii")`.
    Decode,
    /// `UnicodeError` (or an exact-arithmetic overflow that ends in one).
    Value,
}

/// `punycode.punycode_decode(text, "strict")`.
///
/// Python's integers are unbounded; here a `u128` overflow stands for the
/// `UnicodeError` the decode necessarily ends in.  An overflow needs a
/// generalized number above 2**123 (its value is at least the last weight
/// over 35), and `insertion_sort` then computes `char >= 0x80 + delta /
/// (len(base) + 1)`, far above 0x10FFFF for any input that fits in memory,
/// so it raises "Invalid character" if nothing raised earlier.
fn punycode_decode(text: &[u8]) -> Result<Text, PunyError> {
    let ascii = |bytes: &[u8]| -> Result<Text, PunyError> {
        if bytes.is_ascii() {
            Ok(bytes.iter().map(|b| u32::from(*b)).collect())
        } else {
            Err(PunyError::Decode)
        }
    };
    let (mut base, extended) = match text.iter().rposition(|b| *b == b'-') {
        None => (Text::new(), ascii(text)?),
        Some(pos) => (ascii(&text[..pos])?, ascii(&text[pos + 1..])?),
    };
    let extended: Vec<u8> = extended
        .iter()
        .map(|c| u8::try_from(*c).unwrap_or(0).to_ascii_uppercase())
        .collect();
    // insertion_sort
    let mut char_: u128 = 0x80;
    let mut pos: u128 = 0;
    let mut first_pos = true; // `pos = -1` before the first `pos += delta + 1`
    let mut bias: u128 = 72;
    let mut extpos = 0usize;
    while extpos < extended.len() {
        // decode_generalized_number
        let mut newpos = extpos;
        let mut result: u128 = 0;
        let mut w: u128 = 1;
        let mut j: u128 = 0;
        let delta = loop {
            let Some(&ch) = extended.get(newpos) else {
                return Err(PunyError::Value); // incomplete punicode string
            };
            newpos += 1;
            let digit = match ch {
                b'A'..=b'Z' => u128::from(ch - b'A'),
                b'0'..=b'9' => u128::from(ch) - 22,
                _ => return Err(PunyError::Value), // Invalid extended code point
            };
            let t = punycode_t(j, bias);
            result = digit
                .checked_mul(w)
                .and_then(|x| result.checked_add(x))
                .ok_or(PunyError::Value)?;
            if digit < t {
                break result;
            }
            w = w.checked_mul(36 - t).ok_or(PunyError::Value)?;
            j += 1;
        };
        let n = base.len() as u128 + 1;
        pos = if first_pos {
            delta
        } else {
            pos.checked_add(delta)
                .and_then(|p| p.checked_add(1))
                .ok_or(PunyError::Value)?
        };
        first_pos = false;
        char_ = char_.checked_add(pos / n).ok_or(PunyError::Value)?;
        if char_ > 0x10FFFF {
            return Err(PunyError::Value); // Invalid character
        }
        pos %= n;
        let at = usize::try_from(pos).map_err(|_| PunyError::Value)?;
        base.insert(at, u32::try_from(char_).map_err(|_| PunyError::Value)?);
        bias = adapt(delta, extpos == 0, base.len() as u128);
        extpos = newpos;
    }
    Ok(base)
}

/// `encodings.punycode.Codec.decode(input, errors)`.
pub(super) fn decode_punycode(bytes: &[u8], errors: Errors) -> Result<Text, DecodeFail> {
    if errors != Errors::Strict {
        // UnicodeError("Unsupported error handling ...")
        return Err(DecodeFail::Value);
    }
    punycode_decode(bytes).map_err(|e| match e {
        PunyError::Decode => DecodeFail::Decode,
        PunyError::Value => DecodeFail::Value,
    })
}

/// `punycode.punycode_encode(text)`.
fn punycode_encode(text: &[u32]) -> Vec<u8> {
    const DIGITS: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    // segregate
    let base: Vec<u8> = text
        .iter()
        .filter_map(|c| u8::try_from(*c).ok().filter(u8::is_ascii))
        .collect();
    let mut extended: Vec<u32> = text.iter().copied().filter(|c| *c >= 128).collect();
    extended.sort_unstable();
    extended.dedup();
    // insertion_unsort
    let mut deltas: Vec<u128> = Vec::new();
    let mut oldchar: u128 = 0x80;
    let mut oldindex: i128 = -1;
    for &c in &extended {
        let char_ = u128::from(c);
        let curlen = text.iter().filter(|x| **x < c).count() as u128;
        let mut delta: i128 = ((curlen + 1) * (char_ - oldchar)) as i128;
        let mut index: i128 = -1;
        let mut pos: i128 = -1;
        loop {
            // selective_find
            let mut found = None;
            loop {
                pos += 1;
                let Some(&x) = usize::try_from(pos).ok().and_then(|p| text.get(p)) else {
                    break;
                };
                if x == c {
                    found = Some(index + 1);
                    break;
                } else if x < c {
                    index += 1;
                }
            }
            let Some(found) = found else {
                break;
            };
            index = found;
            delta += index - oldindex;
            deltas.push(u128::try_from(delta - 1).unwrap_or(0));
            oldindex = index;
            delta = 0;
        }
        oldchar = char_;
    }
    // generate_integers
    let mut result = Vec::new();
    let mut bias: u128 = 72;
    for (points, &delta) in deltas.iter().enumerate() {
        let mut n = delta;
        let mut j = 0;
        loop {
            let t = punycode_t(j, bias);
            if n < t {
                result.push(DIGITS[usize::try_from(n).unwrap_or(0)]);
                break;
            }
            let digit = t + (n - t) % (36 - t);
            result.push(DIGITS[usize::try_from(digit).unwrap_or(0)]);
            n = (n - t) / (36 - t);
            j += 1;
        }
        bias = adapt(delta, points == 0, (base.len() + points + 1) as u128);
    }
    if base.is_empty() {
        result
    } else {
        let mut out = base;
        out.push(b'-');
        out.extend(result);
        out
    }
}

// ------------------------------------------------------------ nameprep

fn in_ranges(ranges: &[(u32, u32)], c: u32) -> bool {
    ranges
        .binary_search_by(|(lo, hi)| {
            if *hi < c {
                std::cmp::Ordering::Less
            } else if *lo > c {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// `_getrecord_ex(c)->combining`.
fn combining(c: u32) -> u8 {
    t::COMBINING
        .binary_search_by(|(lo, hi, _)| {
            if *hi < c {
                std::cmp::Ordering::Less
            } else if *lo > c {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .map_or(0, |i| t::COMBINING[i].2)
}

/// `nfc_first`/`nfc_last`/`comp_data`: the composite of `(first, last)`.
fn compose(first: u32, last: u32) -> Option<u32> {
    t::COMPOSITIONS
        .binary_search_by(|(f, l, _)| (*f, *l).cmp(&(first, last)))
        .ok()
        .map(|i| t::COMPOSITIONS[i].2)
}

/// `find_nfc_index(nfc_first, code) != -1`.
fn is_first(code: u32) -> bool {
    let i = t::COMPOSITIONS.partition_point(|(f, _, _)| *f < code);
    t::COMPOSITIONS.get(i).is_some_and(|(f, _, _)| *f == code)
}

/// `unicodedata.ucd_3_2_0.normalize("NFKC", s)` (`nfc_nfkc(self, input, 1)`).
fn nfkc_3_2(input: &[u32]) -> Text {
    // nfd_nfkd
    let mut data = Text::with_capacity(input.len());
    for &code in input {
        if (S_BASE..S_BASE + S_COUNT).contains(&code) {
            let s_index = code - S_BASE;
            data.push(L_BASE + s_index / N_COUNT);
            data.push(V_BASE + (s_index % N_COUNT) / T_COUNT);
            let t = T_BASE + s_index % T_COUNT;
            if t != T_BASE {
                data.push(t);
            }
            continue;
        }
        match t::NFKD_3_2_0.binary_search_by(|(c, _)| c.cmp(&code)) {
            Ok(i) => data.extend(t::NFKD_3_2_0[i].1.chars().map(u32::from)),
            Err(_) => data.push(code),
        }
    }
    // Sort each consecutive combining-character run canonically (stably).
    let mut i = 0;
    while i < data.len() {
        if combining(data[i]) == 0 {
            i += 1;
            continue;
        }
        let start = i;
        while i < data.len() && combining(data[i]) != 0 {
            i += 1;
        }
        data[start..i].sort_by_key(|c| combining(*c));
    }
    // nfc_nfkc
    let len = data.len();
    let mut output = Text::with_capacity(len);
    let mut skipped: Vec<usize> = Vec::new();
    let mut i = 0;
    while i < len {
        if let Some(index) = skipped.iter().position(|s| *s == i) {
            skipped.swap_remove(index);
            i += 1;
            continue;
        }
        // Hangul Composition.
        let code = data[i];
        if (L_BASE..L_BASE + L_COUNT).contains(&code)
            && i + 1 < len
            && (V_BASE..V_BASE + V_COUNT).contains(&data[i + 1])
        {
            let l_index = code - L_BASE;
            let v_index = data[i + 1] - V_BASE;
            let mut code = S_BASE + (l_index * V_COUNT + v_index) * T_COUNT;
            i += 2;
            if i < len && T_BASE < data[i] && data[i] < T_BASE + T_COUNT {
                code += data[i] - T_BASE;
                i += 1;
            }
            output.push(code);
            continue;
        }
        if !is_first(code) {
            output.push(code);
            i += 1;
            continue;
        }
        // Find next unblocked character.
        let mut i1 = i + 1;
        let mut comb = 0;
        let mut composed = code;
        while i1 < len {
            let code1 = data[i1];
            let comb1 = combining(code1);
            if comb != 0 {
                if comb1 == 0 {
                    break;
                }
                if comb >= comb1 {
                    // Character is blocked.
                    i1 += 1;
                    continue;
                }
            }
            match compose(composed, code1) {
                Some(code) => {
                    composed = code;
                    skipped.push(i1);
                    i1 += 1;
                    if !is_first(composed) {
                        break;
                    }
                }
                None => {
                    if comb1 == 0 {
                        break;
                    }
                    comb = comb1;
                    i1 += 1;
                }
            }
        }
        output.push(composed);
        i += 1;
    }
    output
}

/// `encodings.idna.nameprep(label)`; `None` is `UnicodeError`.
fn nameprep(label: &[u32]) -> Option<Text> {
    let mut mapped = Text::with_capacity(label.len());
    for &c in label {
        if t::STRINGPREP_B1.contains(&c) {
            continue; // Map to nothing
        }
        match t::STRINGPREP_B2.binary_search_by(|(k, _)| k.cmp(&c)) {
            Ok(i) => mapped.extend(t::STRINGPREP_B2[i].1.chars().map(u32::from)),
            Err(_) => mapped.push(c),
        }
    }
    let label = nfkc_3_2(&mapped);
    if label
        .iter()
        .any(|c| in_ranges(t::STRINGPREP_PROHIBITED, *c))
    {
        return None;
    }
    let rand_al: Vec<bool> = label
        .iter()
        .map(|c| in_ranges(t::STRINGPREP_D1, *c))
        .collect();
    if rand_al.iter().any(|x| *x) {
        if label.iter().any(|c| in_ranges(t::STRINGPREP_D2, *c)) {
            return None;
        }
        if rand_al.first() != Some(&true) || rand_al.last() != Some(&true) {
            return None;
        }
    }
    Some(label)
}

fn ascii_bytes(text: &[u32]) -> Option<Vec<u8>> {
    text.iter()
        .map(|c| u8::try_from(*c).ok().filter(u8::is_ascii))
        .collect()
}

/// `encodings.idna.ToASCII(label)`; `None` is `UnicodeError`.
fn to_ascii(label: &[u32]) -> Option<Vec<u8>> {
    let fits = |label: Vec<u8>| (!label.is_empty() && label.len() < 64).then_some(label);
    if let Some(label) = ascii_bytes(label) {
        return fits(label);
    }
    let label = nameprep(label)?;
    if let Some(label) = ascii_bytes(&label) {
        return fits(label);
    }
    if label.starts_with(&[0x78, 0x6E, 0x2D, 0x2D]) {
        return None; // Label starts with ACE prefix
    }
    let mut out = b"xn--".to_vec();
    out.extend(punycode_encode(&label));
    fits(out)
}

/// `encodings.idna.ToUnicode(label)` for a `bytes` label.
fn to_unicode(label: &[u8]) -> Result<Text, DecodeFail> {
    if label.len() > 1024 {
        return Err(DecodeFail::Value); // label way too long
    }
    let Some(label1) = label.strip_prefix(b"xn--") else {
        return if label.is_ascii() {
            Ok(label.iter().map(|b| u32::from(*b)).collect())
        } else {
            Err(DecodeFail::Decode)
        };
    };
    let result = punycode_decode(label1).map_err(|e| match e {
        PunyError::Decode => DecodeFail::Decode,
        PunyError::Value => DecodeFail::Value,
    })?;
    let label2 = to_ascii(&result).ok_or(DecodeFail::Value)?;
    // `label` is ASCII here: punycode_decode rejected anything else.
    if label.to_ascii_lowercase() != label2 {
        return Err(DecodeFail::Value); // IDNA does not round-trip
    }
    Ok(result)
}

/// `encodings.idna.Codec.decode(input, errors)`.
pub(super) fn decode_idna(bytes: &[u8], errors: Errors) -> Result<Text, DecodeFail> {
    if errors != Errors::Strict {
        return Err(DecodeFail::Value); // Unsupported error handling
    }
    if bytes.is_empty() {
        return Ok(Text::new());
    }
    if !bytes.windows(4).any(|w| w == b"xn--") && bytes.is_ascii() {
        // Fast path
        return Ok(bytes.iter().map(|b| u32::from(*b)).collect());
    }
    let mut labels: Vec<&[u8]> = bytes.split(|b| *b == b'.').collect();
    let trailing_dot = labels.last().is_some_and(|l| l.is_empty());
    if trailing_dot {
        labels.pop();
    }
    let mut out = Text::new();
    for (index, label) in labels.iter().enumerate() {
        if index > 0 {
            out.push(u32::from(b'.'));
        }
        out.extend(to_unicode(label)?);
    }
    if trailing_dot {
        out.push(u32::from(b'.'));
    }
    Ok(out)
}

#[cfg(test)]
pub(super) fn nfkc_3_2_for_test(input: &[u32]) -> Text {
    nfkc_3_2(input)
}

#[cfg(test)]
pub(super) fn nameprep_for_test(label: &[u32]) -> Option<Text> {
    nameprep(label)
}
