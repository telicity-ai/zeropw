//! The administrator CLI's input envelope (`zeropw-admin --input-envelope`,
//! docs/desktop-app.md §3.1).
//!
//! A trusted caller such as the desktop app hands passphrases, a new secret
//! value or an invite to one `zeropw-admin` process on standard input instead
//! of argv or environment variables. The envelope is one JSON object holding
//! only the string fields named here; anything else is refused without
//! repeating a byte of the input. Every value is decoded straight from the
//! (zeroizing) input into a [`Zeroizing`] buffer sized up front, so no
//! decoded copy is left in a parser's scratch space or a reallocated buffer,
//! and every value is wiped when the envelope is dropped.

use std::io::Read;

use base64::Engine as _;
use zeroize::Zeroizing;

use crate::errors::{Error, ErrorClass};

/// The most standard input the envelope reader takes (256 KiB).
pub const MAX_ENVELOPE_BYTES: usize = 256 * 1024;

const INVALID_DETAIL: &str = "the input envelope must be one JSON object of known string fields (admin_passphrase, recovery_passphrase, value_b64, invite) of at most 256 KiB; values are not echoed";

/// The `UsageError`/`envelope_invalid` refusal. Its detail is fixed text.
pub fn envelope_invalid() -> Error {
    Error::subclass(
        ErrorClass::InvalidInput,
        "UsageError",
        "envelope_invalid",
        INVALID_DETAIL,
    )
}

/// The parsed envelope. It deliberately implements neither `Debug` nor
/// `Clone`: its values never reach a log line or a second copy by accident.
#[derive(Default)]
pub struct InputEnvelope {
    admin_passphrase: Option<Zeroizing<String>>,
    recovery_passphrase: Option<Zeroizing<String>>,
    value: Option<Zeroizing<Vec<u8>>>,
    invite: Option<Zeroizing<String>>,
}

impl InputEnvelope {
    /// Read standard input once (at most [`MAX_ENVELOPE_BYTES`]) and parse it.
    pub fn read_from(input: impl Read) -> Result<InputEnvelope, Error> {
        // Sized up front so reading never reallocates (and leaves) a copy.
        let mut raw = Zeroizing::new(Vec::with_capacity(MAX_ENVELOPE_BYTES + 1));
        input
            .take(MAX_ENVELOPE_BYTES as u64 + 1)
            .read_to_end(&mut raw)
            .map_err(|_| envelope_invalid())?;
        if raw.len() > MAX_ENVELOPE_BYTES {
            return Err(envelope_invalid());
        }
        Self::parse(&raw)
    }

    /// Parse one envelope document. Unknown or repeated fields, non-string
    /// values, a document that is not an object, trailing data, malformed
    /// JSON (RFC 8259: bad escapes, unpaired surrogates, raw control
    /// characters, invalid UTF-8) and a `value_b64` that is not standard
    /// padded base64 are all `envelope_invalid`, with fixed text only.
    pub fn parse(raw: &[u8]) -> Result<InputEnvelope, Error> {
        if raw.len() > MAX_ENVELOPE_BYTES {
            return Err(envelope_invalid());
        }
        let fields = read_fields(raw).ok_or_else(envelope_invalid)?;
        let value = match fields.value_b64 {
            Some(text) => {
                // Decoded into a wiped buffer sized up front: a refused value
                // leaves no partly decoded copy behind.
                let estimate = base64::decoded_len_estimate(text.len());
                let mut decoded = Zeroizing::new(Vec::with_capacity(estimate));
                base64::engine::general_purpose::STANDARD
                    .decode_vec(text.as_bytes(), &mut decoded)
                    .map_err(|_| envelope_invalid())?;
                Some(decoded)
            }
            None => None,
        };
        Ok(InputEnvelope {
            admin_passphrase: fields.admin_passphrase,
            recovery_passphrase: fields.recovery_passphrase,
            value,
            invite: fields.invite,
        })
    }

    /// The passphrase a CLI would read from the environment variable `name`
    /// (`ZEROPW_ADMIN_PASSPHRASE` or `ZEROPW_RECOVERY_PASSPHRASE`). An empty
    /// field counts as missing, as an empty variable does.
    pub fn passphrase_for(&self, name: &str) -> Option<Zeroizing<String>> {
        let field = if name == "ZEROPW_RECOVERY_PASSPHRASE" {
            &self.recovery_passphrase
        } else {
            &self.admin_passphrase
        };
        field
            .as_ref()
            .filter(|value| !value.is_empty())
            .map(|value| Zeroizing::new(value.as_str().to_owned()))
    }

    /// The decoded `value_b64` bytes.
    pub fn value(&self) -> Option<Zeroizing<Vec<u8>>> {
        self.value
            .as_ref()
            .map(|value| Zeroizing::new(value.as_slice().to_vec()))
    }

    /// The `invite` text (an invite string or a `zeropw://join#...` link).
    pub fn invite(&self) -> Option<Zeroizing<String>> {
        self.invite
            .as_ref()
            .map(|value| Zeroizing::new(value.as_str().to_owned()))
    }

    /// Field-name presence only, for value-free diagnostics and tests.
    pub fn has_field(&self, field: &str) -> bool {
        match field {
            "admin_passphrase" => self.admin_passphrase.is_some(),
            "recovery_passphrase" => self.recovery_passphrase.is_some(),
            "value_b64" => self.value.is_some(),
            "invite" => self.invite.is_some(),
            _ => false,
        }
    }
}

#[derive(Default)]
struct Fields {
    admin_passphrase: Option<Zeroizing<String>>,
    recovery_passphrase: Option<Zeroizing<String>>,
    value_b64: Option<Zeroizing<String>>,
    invite: Option<Zeroizing<String>>,
}

/// The envelope's whole grammar: optional whitespace, one JSON object whose
/// members are known string fields with string values, each at most once,
/// and optional whitespace. A hand-written reader rather than `serde_json`:
/// serde_json unescapes a string that holds an escape (`\"`, `\\`, `\n`,
/// `\uXXXX`) into its own reusable scratch `Vec`, which is cleared but never
/// wiped. Here every string is decoded once, straight into its
/// [`Zeroizing`] buffer.
fn read_fields(raw: &[u8]) -> Option<Fields> {
    let mut reader = Reader { raw, at: 0 };
    let mut fields = Fields::default();
    reader.skip_whitespace();
    if !reader.eat(b'{') {
        return None;
    }
    reader.skip_whitespace();
    if !reader.eat(b'}') {
        loop {
            let key = reader.string()?;
            let slot = match key.as_str() {
                "admin_passphrase" => &mut fields.admin_passphrase,
                "recovery_passphrase" => &mut fields.recovery_passphrase,
                "value_b64" => &mut fields.value_b64,
                "invite" => &mut fields.invite,
                _ => return None,
            };
            if slot.is_some() {
                return None;
            }
            reader.skip_whitespace();
            if !reader.eat(b':') {
                return None;
            }
            reader.skip_whitespace();
            *slot = Some(reader.string()?);
            reader.skip_whitespace();
            if reader.eat(b'}') {
                break;
            }
            if !reader.eat(b',') {
                return None;
            }
            reader.skip_whitespace();
        }
    }
    reader.skip_whitespace();
    (reader.at == raw.len()).then_some(fields)
}

struct Reader<'a> {
    raw: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    /// RFC 8259 whitespace: space, tab, line feed, carriage return.
    fn skip_whitespace(&mut self) {
        while matches!(self.raw.get(self.at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn eat(&mut self, byte: u8) -> bool {
        let found = self.raw.get(self.at) == Some(&byte);
        if found {
            self.at += 1;
        }
        found
    }

    /// The JSON string starting here, decoded. Its raw text must be valid
    /// UTF-8 without control characters; [`unescape`] checks the escapes.
    fn string(&mut self) -> Option<Zeroizing<String>> {
        if !self.eat(b'"') {
            return None;
        }
        let start = self.at;
        loop {
            match *self.raw.get(self.at)? {
                b'"' => break,
                b'\\' => self.at += 2,
                byte if byte < 0x20 => return None,
                _ => self.at += 1,
            }
        }
        let body = std::str::from_utf8(&self.raw[start..self.at]).ok()?;
        self.at += 1;
        unescape(body)
    }
}

/// Decode the body of a JSON string (the text between its quotes) into a
/// [`Zeroizing`] string sized up front: a decoded string is never longer than
/// its escaped form, so the buffer never reallocates. Escapes follow RFC 8259
/// and, as for serde_json's `String`, a `\u` surrogate must be one half of a
/// high-low pair.
fn unescape(body: &str) -> Option<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::with_capacity(body.len()));
    let capacity = out.capacity();
    let mut rest = body;
    while let Some(index) = rest.find('\\') {
        out.push_str(&rest[..index]);
        let (decoded, used) = match *rest.as_bytes().get(index + 1)? {
            b'"' => ('"', 2),
            b'\\' => ('\\', 2),
            b'/' => ('/', 2),
            b'b' => ('\u{8}', 2),
            b'f' => ('\u{c}', 2),
            b'n' => ('\n', 2),
            b'r' => ('\r', 2),
            b't' => ('\t', 2),
            b'u' => {
                let unit = hex_unit(rest.get(index + 2..index + 6)?)?;
                match unit {
                    0xD800..=0xDBFF => {
                        if rest.get(index + 6..index + 8)? != "\\u" {
                            return None;
                        }
                        let low = hex_unit(rest.get(index + 8..index + 12)?)?;
                        if !(0xDC00..=0xDFFF).contains(&low) {
                            return None;
                        }
                        let code = 0x1_0000
                            + ((u32::from(unit) - 0xD800) << 10)
                            + (u32::from(low) - 0xDC00);
                        (char::from_u32(code)?, 12)
                    }
                    0xDC00..=0xDFFF => return None,
                    _ => (char::from_u32(u32::from(unit))?, 6),
                }
            }
            _ => return None,
        };
        out.push(decoded);
        rest = &rest[index + used..];
    }
    out.push_str(rest);
    debug_assert_eq!(out.capacity(), capacity, "decoding never reallocates");
    Some(out)
}

/// Four hexadecimal digits (either case) as one UTF-16 code unit.
fn hex_unit(digits: &str) -> Option<u16> {
    digits.bytes().try_fold(0u16, |unit, byte| {
        let digit = char::from(byte).to_digit(16)?;
        Some((unit << 4) | digit as u16)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(raw: &[u8]) {
        match InputEnvelope::parse(raw) {
            Ok(_) => panic!("accepted an invalid envelope"),
            Err(error) => {
                assert_eq!(error.reason, "envelope_invalid");
                assert_eq!(error.to_dict()["error"], "UsageError");
                assert_eq!(error.detail, INVALID_DETAIL);
            }
        }
    }

    #[test]
    fn known_string_fields_parse_and_values_decode() {
        let envelope = InputEnvelope::parse(
            br#" {"admin_passphrase":"synthetic-admin","recovery_passphrase":"synthetic-recovery","value_b64":"c3ludGhldGljLXZhbHVl","invite":"zeropw://join#abc"} "#,
        )
        .unwrap();
        assert_eq!(
            envelope
                .passphrase_for("ZEROPW_ADMIN_PASSPHRASE")
                .unwrap()
                .as_str(),
            "synthetic-admin"
        );
        assert_eq!(
            envelope
                .passphrase_for("ZEROPW_RECOVERY_PASSPHRASE")
                .unwrap()
                .as_str(),
            "synthetic-recovery"
        );
        assert_eq!(envelope.value().unwrap().as_slice(), b"synthetic-value");
        assert_eq!(envelope.invite().unwrap().as_str(), "zeropw://join#abc");
        let empty = InputEnvelope::parse(b"{}").unwrap();
        assert!(empty.passphrase_for("ZEROPW_ADMIN_PASSPHRASE").is_none());
        assert!(empty.value().is_none() && empty.invite().is_none());
        let blank = InputEnvelope::parse(br#"{"admin_passphrase":""}"#).unwrap();
        assert!(blank.passphrase_for("ZEROPW_ADMIN_PASSPHRASE").is_none());
        assert!(blank.has_field("admin_passphrase"));
    }

    /// Escaped values (what `serde_json::to_vec` writes for a passphrase
    /// holding `"`, `\` or a control character) decode exactly, in every
    /// field, and so do escaped field names.
    #[test]
    fn escaped_values_decode_exactly() {
        let passphrase = "pa\"ss\\word/\u{8}\u{c}\n\r\t\u{1}\u{7f}\u{e9}\u{1f600}-synthetic";
        let document = serde_json::to_vec(&serde_json::json!({
            "admin_passphrase": passphrase,
            "recovery_passphrase": "synthetic-\u{2028}\u{fffd}",
        }))
        .unwrap();
        assert!(document.windows(2).any(|pair| pair == br#"\""#));
        let envelope = InputEnvelope::parse(&document).unwrap();
        assert_eq!(
            envelope
                .passphrase_for("ZEROPW_ADMIN_PASSPHRASE")
                .unwrap()
                .as_str(),
            passphrase
        );
        assert_eq!(
            envelope
                .passphrase_for("ZEROPW_RECOVERY_PASSPHRASE")
                .unwrap()
                .as_str(),
            "synthetic-\u{2028}\u{fffd}"
        );
        // `\/`, every short escape, upper- and lower-case `\u`, a surrogate
        // pair, and escaped field names.
        let envelope = InputEnvelope::parse(
            br#"{"admin\u005fpassphrase":"a\/b\"c\\d\be\ff\ng\rh\ti\u00E9\u00e9\uD83D\ude00\u0000",
                "value\u005Fb64":"c3ludGhldGlj\u004cXZhbHVl","invite":"zeropw:\/\/join#abc"}"#,
        )
        .unwrap();
        assert_eq!(
            envelope
                .passphrase_for("ZEROPW_ADMIN_PASSPHRASE")
                .unwrap()
                .as_str(),
            "a/b\"c\\d\u{8}e\u{c}f\ng\rh\ti\u{e9}\u{e9}\u{1f600}\u{0}"
        );
        assert_eq!(envelope.value().unwrap().as_slice(), b"synthetic-value");
        assert_eq!(envelope.invite().unwrap().as_str(), "zeropw://join#abc");
        // The same field twice, once escaped, is still a repeated field.
        refused(br#"{"invite":"a","\u0069nvite":"b"}"#);
    }

    #[test]
    fn anything_but_an_object_of_known_strings_is_refused() {
        for raw in [
            &b""[..],
            b"   ",
            b"null",
            b"[]",
            br#"["synthetic-a","synthetic-b"]"#,
            br#""synthetic-string""#,
            br#"{"admin_passphrase":1}"#,
            br#"{"admin_passphrase":null}"#,
            br#"{"admin_passphrase":["synthetic"]}"#,
            br#"{"admin_passphrase":{"x":"synthetic"}}"#,
            br#"{"admin_passphrase":true}"#,
            br#"{"other":"synthetic"}"#,
            br#"{"admin_passphrase":"a","admin_passphrase":"b"}"#,
            br#"{"admin_passphrase":"synthetic"} {}"#,
            br#"{"admin_passphrase":"synthetic"}x"#,
            br#"{"admin_passphrase":"synthetic""#,
            br#"{"value_b64":"not base64!"}"#,
            br#"{"value_b64":"c3ludGhldGlj"}x"#,
            br#"{"value_b64":"c3ludGhldGljLXZhbHVl="}"#,
            b"\xff\xfe",
            // Malformed strings: bad or cut escapes, unpaired surrogates, raw
            // control characters and invalid UTF-8.
            br#"{"invite":"\x"}"#,
            br#"{"invite":"\u12"}"#,
            br#"{"invite":"\u12g4"}"#,
            br#"{"invite":"\u+123"}"#,
            br#"{"invite":"\ud800"}"#,
            br#"{"invite":"\udc00"}"#,
            br#"{"invite":"\ud800x"}"#,
            br#"{"invite":"\ud800\n"}"#,
            br#"{"invite":"\ud800\u0041"}"#,
            br#"{"invite":"\ud800\ud800"}"#,
            br#"{"invite":"\"}"#,
            br#"{"invite":"a\"#,
            b"{\"invite\":\"a\x01b\"}",
            b"{\"invite\":\"a\nb\"}",
            b"{\"invite\":\"a\xc3\"}",
            b"{\"invite\":\"\xed\xa0\x80\"}",
            b"{\"in\\vite\":\"a\"}",
            // Not JSON whitespace, a trailing comma, a missing colon.
            b"\x0c{}",
            b"{\"invite\":\"a\"}\x0b",
            br#"{"invite":"a",}"#,
            br#"{"invite" "a"}"#,
            br#"{,}"#,
            br#"{"invite":"a""admin_passphrase":"b"}"#,
            b"\xef\xbb\xbf{}",
        ] {
            refused(raw);
        }
        let mut oversized = br#"{"invite":""#.to_vec();
        oversized.extend(std::iter::repeat_n(b'a', MAX_ENVELOPE_BYTES));
        oversized.extend(br#""}"#);
        refused(&oversized);
        assert!(
            InputEnvelope::read_from(&oversized[..])
                .err()
                .is_some_and(|e| e.reason == "envelope_invalid")
        );
    }

    /// The serde_json reader this module used before (each value read as a
    /// `String`), kept as the oracle for which documents are accepted and
    /// what they decode to.
    fn oracle(raw: &[u8]) -> Option<[Option<String>; 4]> {
        use serde::de::{self, Deserializer as _, MapAccess, Visitor};
        struct Oracle;
        impl<'de> Visitor<'de> for Oracle {
            type Value = [Option<String>; 4];
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an object of string fields")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut fields: [Option<String>; 4] = Default::default();
                while let Some(key) = map.next_key::<String>()? {
                    let slot = match key.as_str() {
                        "admin_passphrase" => &mut fields[0],
                        "recovery_passphrase" => &mut fields[1],
                        "value_b64" => &mut fields[2],
                        "invite" => &mut fields[3],
                        _ => return Err(de::Error::custom("unknown field")),
                    };
                    if slot.is_some() {
                        return Err(de::Error::custom("duplicate field"));
                    }
                    *slot = Some(map.next_value::<String>()?);
                }
                Ok(fields)
            }
        }
        let mut deserializer = serde_json::Deserializer::from_slice(raw);
        let fields = deserializer.deserialize_map(Oracle).ok()?;
        deserializer.end().ok()?;
        Some(fields)
    }

    fn fields_of(raw: &[u8]) -> Option<[Option<String>; 4]> {
        read_fields(raw).map(|fields| {
            [
                fields.admin_passphrase,
                fields.recovery_passphrase,
                fields.value_b64,
                fields.invite,
            ]
            .map(|field| field.map(|value| value.as_str().to_owned()))
        })
    }

    /// Deterministic generated documents, mostly well-formed and some
    /// mutated: the reader accepts exactly what serde_json accepted and
    /// decodes every value the same way.
    #[test]
    fn reader_matches_serde_json_on_generated_documents() {
        const PIECES: [&str; 34] = [
            "a",
            "Z9",
            " ",
            "-",
            "\u{e9}",
            "\u{1f600}",
            "\u{2028}",
            "\u{7f}",
            "\\\"",
            "\\\\",
            "\\/",
            "\\b",
            "\\f",
            "\\n",
            "\\r",
            "\\t",
            "\\u0041",
            "\\u00e9",
            "\\u00E9",
            "\\u0000",
            "\\uffff",
            "\\ud83d\\ude00",
            "\\uD83D\\uDE00",
            "\\ud800",
            "\\udc00",
            "\\ud800\\u0041",
            "\\x",
            "\\u12",
            "\\u0g00",
            "\\",
            "\u{1}",
            "\n",
            "\"",
            "\\ud800\\",
        ];
        const KEYS: [&str; 7] = [
            "\"admin_passphrase\"",
            "\"recovery_passphrase\"",
            "\"value_b64\"",
            "\"invite\"",
            "\"\\u0069nvite\"",
            "\"other\"",
            "\"invite\\u0000\"",
        ];
        const SPACES: [&str; 10] = ["", "", "", "", " ", " ", "\n\t", "\r", "\r\n ", "\u{c}"];
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move |bound: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % bound as u64) as usize
        };
        let (mut accepted, mut refused) = (0, 0);
        for round in 0..20_000 {
            let mut doc = String::new();
            doc.push_str(SPACES[next(SPACES.len())]);
            doc.push('{');
            for member in 0..next(4) {
                if member > 0 {
                    doc.push(',');
                }
                doc.push_str(SPACES[next(SPACES.len())]);
                doc.push_str(KEYS[next(KEYS.len())]);
                doc.push_str(SPACES[next(SPACES.len())]);
                doc.push(':');
                doc.push_str(SPACES[next(SPACES.len())]);
                doc.push('"');
                for _ in 0..next(6) {
                    // Well-formed pieces most of the time.
                    let piece = if next(4) == 0 {
                        PIECES[next(PIECES.len())]
                    } else {
                        PIECES[next(22)]
                    };
                    doc.push_str(piece);
                }
                doc.push('"');
                doc.push_str(SPACES[next(SPACES.len())]);
            }
            doc.push('}');
            doc.push_str(SPACES[next(SPACES.len())]);
            let mut raw = doc.into_bytes();
            if round % 5 == 0 && !raw.is_empty() {
                // One byte replaced, dropped or inserted.
                let at = next(raw.len());
                let bytes = b"{}[]:,\"\\ u0a\x01\xff\xc3";
                let byte = bytes[next(bytes.len())];
                match next(3) {
                    0 => raw[at] = byte,
                    1 => {
                        raw.remove(at);
                    }
                    _ => raw.insert(at, byte),
                }
            }
            let expected = oracle(&raw);
            assert_eq!(
                fields_of(&raw),
                expected,
                "{:?}",
                String::from_utf8_lossy(&raw)
            );
            if expected.is_some() {
                accepted += 1;
            } else {
                refused += 1;
            }
        }
        assert!(accepted > 1_000 && refused > 1_000, "{accepted}/{refused}");
    }
}
