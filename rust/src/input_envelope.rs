//! The administrator CLI's input envelope (`zeropw-admin --input-envelope`,
//! docs/desktop-app.md §3.1).
//!
//! A trusted caller such as the desktop app hands passphrases, a new secret
//! value or an invite to one `zeropw-admin` process on standard input instead
//! of argv or environment variables. The envelope is one JSON object holding
//! only the string fields named here; anything else is refused without
//! repeating a byte of the input. Every value is held in [`Zeroizing`]
//! buffers and wiped when the envelope is dropped.

use std::io::Read;

use base64::Engine as _;
use serde::de::{self, Deserializer as _, MapAccess, Visitor};
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
    /// values, a document that is not an object, trailing data and a
    /// `value_b64` that is not standard padded base64 are all
    /// `envelope_invalid`; the parser's own message (which may quote input)
    /// is discarded.
    pub fn parse(raw: &[u8]) -> Result<InputEnvelope, Error> {
        if raw.len() > MAX_ENVELOPE_BYTES {
            return Err(envelope_invalid());
        }
        let mut deserializer = serde_json::Deserializer::from_slice(raw);
        let fields = deserializer
            .deserialize_map(FieldsVisitor)
            .map_err(|_| envelope_invalid())?;
        deserializer.end().map_err(|_| envelope_invalid())?;
        let value = match fields.value_b64 {
            Some(text) => {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(text.as_bytes())
                    .map_err(|_| envelope_invalid())?;
                Some(Zeroizing::new(decoded))
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

/// Accepts a JSON object only (`deserialize_map` refuses arrays, which a
/// derived struct visitor would read positionally).
struct FieldsVisitor;

impl<'de> Visitor<'de> for FieldsVisitor {
    type Value = Fields;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an object of string fields")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Fields, A::Error> {
        let mut fields = Fields::default();
        while let Some(key) = map.next_key::<String>()? {
            let slot = match key.as_str() {
                "admin_passphrase" => &mut fields.admin_passphrase,
                "recovery_passphrase" => &mut fields.recovery_passphrase,
                "value_b64" => &mut fields.value_b64,
                "invite" => &mut fields.invite,
                _ => return Err(de::Error::custom("unknown field")),
            };
            if slot.is_some() {
                return Err(de::Error::custom("duplicate field"));
            }
            let value: String = map.next_value()?;
            *slot = Some(Zeroizing::new(value));
        }
        Ok(fields)
    }
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
}
