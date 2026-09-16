//! Port of `zeropw/handles.py`: opaque connection handles given to
//! secret-free execution environments.
//!
//! A handle is *not* the upstream credential. It is a short-lived,
//! HMAC-signed capability that names a caller, a connection, a grant and the
//! policy version the grant was evaluated against. The gateway verifies the
//! signature, then re-checks the live grant (expiry, usage, revocation,
//! global stop) on every request. Leaking a handle lets the holder use the
//! connection within the granted scope until expiry or revocation; it never
//! reveals a vault value.

use std::fmt::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use serde_json::{Value, json};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::errors::Error;
use crate::pyjson::{self, DumpOptions};
use crate::secret::SecretBytes;
use crate::store;

pub const PREFIX: &str = "zpw1";
pub const HANDLE_KEY_SIZE: usize = 32;
pub const MAX_TOKEN_LENGTH: usize = 2048;

fn b64e(raw: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(raw)
}

fn b64d(text: &str) -> Result<Vec<u8>, ()> {
    URL_SAFE_NO_PAD.decode(text).map_err(|_| ())
}

/// `handles.Handle`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handle {
    pub caller: String,
    pub connection: String,
    pub grant: String,
    pub policy_version: i64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub handle_id: String,
}

/// Port of `handles.HandleIssuer`.
#[derive(Debug)]
pub struct HandleIssuer {
    key: SecretBytes,
}

impl HandleIssuer {
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        if key.len() < HANDLE_KEY_SIZE {
            return Err(Error::invalid_input("handle_key_too_short"));
        }
        Ok(HandleIssuer {
            key: SecretBytes::from_slice(key),
        })
    }

    /// `HandleIssuer.generate_key`.
    pub fn generate_key() -> SecretBytes {
        let mut buf = vec![0u8; HANDLE_KEY_SIZE];
        OsRng.fill_bytes(&mut buf);
        SecretBytes::new(buf)
    }

    fn sign(&self, body: &str) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.key.expose()).expect("HMAC accepts any key length");
        mac.update(body.as_bytes());
        b64e(&mac.finalize().into_bytes())
    }

    /// `HandleIssuer.issue`. `now` mirrors Python's `now: float | None`
    /// (seconds since the epoch); `int(now)` truncates toward zero, which is
    /// exactly what a plain `as i64` cast does in Rust for a finite,
    /// in-`i64`-range float.
    pub fn issue(
        &self,
        caller: &str,
        connection: &str,
        grant: &str,
        policy_version: i64,
        ttl_seconds: i64,
        now: Option<f64>,
    ) -> Result<String, Error> {
        if ttl_seconds <= 0 || ttl_seconds > 86400 {
            return Err(Error::invalid_input("handle_ttl"));
        }
        let issued = now.unwrap_or_else(store::now) as i64;
        let mut jti_raw = [0u8; 12];
        OsRng.fill_bytes(&mut jti_raw);
        let payload = json!({
            "v": 1,
            "c": caller,
            "n": connection,
            "g": grant,
            "pv": policy_version,
            "iat": issued,
            "exp": issued + ttl_seconds,
            "jti": b64e(&jti_raw),
        });
        let payload_json = pyjson::dumps(&payload, DumpOptions::compact_sorted())?;
        let body = format!("{PREFIX}.{}", b64e(payload_json.as_bytes()));
        let sig = self.sign(&body);
        Ok(format!("{body}.{sig}"))
    }

    /// `HandleIssuer.verify`.
    pub fn verify(&self, token: &str, now: Option<f64>) -> Result<Handle, Error> {
        // Python's `len(token)` counts Unicode code points, not UTF-8 bytes;
        // `chars().count()` matches that (only observable for an adversarial,
        // non-ASCII, near-the-limit forged token -- a well-formed token is
        // pure ASCII, where the two counts agree).
        if token.chars().count() > MAX_TOKEN_LENGTH {
            return Err(Error::auth_failed("handle_malformed"));
        }
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 || parts[0] != PREFIX {
            return Err(Error::auth_failed("handle_malformed"));
        }
        let body = format!("{}.{}", parts[0], parts[1]);
        let expected = self.sign(&body);
        let ok = expected.len() == parts[2].len()
            && bool::from(expected.as_bytes().ct_eq(parts[2].as_bytes()));
        if !ok {
            return Err(Error::auth_failed("handle_signature"));
        }
        let handle = parse_payload(parts[1])?;
        let current = now.unwrap_or_else(store::now);
        if current >= handle.expires_at as f64 {
            return Err(Error::auth_failed("handle_expired"));
        }
        Ok(handle)
    }
}

/// Python `str(value)` on a JSON-decoded scalar/container, as
/// `HandleIssuer.verify` applies via `str(payload["c"])` etc. Never fails:
/// `str()` succeeds for every Python object. For `str`, this is the value
/// itself; for everything else it is `repr(value)` (`None`/`True`/`False`,
/// the canonical number form, or a Python-style `repr` of a list/dict).
fn python_str_coerce(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => python_repr_value(other),
    }
}

/// `repr(value)` for a JSON-decoded value, used both by [`python_str_coerce`]
/// for non-`str` top-level values and recursively for list/dict elements.
fn python_repr_value(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::String(s) => python_repr_str(s),
        Value::Number(n) => {
            if n.is_f64() {
                pyjson::python_float_repr(n.as_f64().unwrap_or(0.0))
            } else {
                n.as_str().to_string()
            }
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(python_repr_value).collect();
            format!("[{}]", parts.join(", "))
        }
        Value::Object(map) => {
            let parts: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{}: {}", python_repr_str(k), python_repr_value(v)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
    }
}

/// `repr(str)`: single-quoted unless the string has a `'` and no `"`, in
/// which case double-quoted; backslash/quote/`\n`/`\r`/`\t` get short
/// escapes, other C0 controls and DEL get `\xNN`. Approximates CPython's
/// full `unicodedata`-driven printable-character check (everything else is
/// emitted literally); no field this port ever `repr()`s exercises that gap.
fn python_repr_str(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Python `int(value)` coercion, as `HandleIssuer.verify` applies via
/// `int(payload["pv"])` etc. `Err` covers every case Python's `int()` would
/// raise `TypeError`/`ValueError` for (both caught by `verify`'s
/// `except (KeyError, TypeError, ValueError)` and mapped to
/// `handle_malformed`) -- `None`, a list/dict, or a non-numeric string.
///
/// Two narrow residual gaps versus CPython, neither reachable except via a
/// hand-crafted token from someone who already holds the HMAC signing key:
/// a magnitude that doesn't fit `i64` (Python `int` is unbounded; this
/// port's `Handle` fields are `i64`) is rejected here instead of succeeding,
/// and only ASCII `0`-`9` are accepted as digits in a numeric string (Python
/// also accepts other Unicode decimal-digit characters). A float that is
/// `inf`/`-inf` makes Python's `int()` raise `OverflowError`, which is *not*
/// one of `TypeError`/`ValueError`/`KeyError` and so escapes `verify`
/// uncaught -- PORTING.md §3.5 applies and this is folded into the same
/// `handle_malformed` result as the other coercion failures. In practice a
/// non-finite float payload cannot even reach this function: [`pyjson::loads`]
/// already rejects the bare `Infinity`/`-Infinity` JSON tokens Python's
/// decoder would have accepted (`rust/DEVIATIONS.md`, pyjson row).
fn python_int_coerce(value: &Value) -> Result<i64, ()> {
    match value {
        Value::Bool(b) => Ok(i64::from(*b)),
        Value::Number(n) => {
            if n.is_f64() {
                let f = n.as_f64().ok_or(())?;
                if !f.is_finite() {
                    return Err(());
                }
                let truncated = f.trunc();
                if truncated > i64::MAX as f64 || truncated < i64::MIN as f64 {
                    return Err(());
                }
                Ok(truncated as i64)
            } else {
                n.as_str().parse::<i64>().map_err(|_| ())
            }
        }
        Value::String(s) => python_int_from_str(s),
        Value::Null | Value::Array(_) | Value::Object(_) => Err(()),
    }
}

/// Python `int(str)` (base 10, the implicit base `int(x)` uses): strips
/// surrounding whitespace, an optional leading `+`/`-`, ASCII digits with
/// single underscores allowed only strictly between two digits (`"1_000"`
/// ok; `"_1"`, `"1_"`, `"1__0"` are not).
fn python_int_from_str(s: &str) -> Result<i64, ()> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(());
    }
    let (neg, digits_part) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    if digits_part.is_empty() {
        return Err(());
    }
    let chars: Vec<char> = digits_part.chars().collect();
    let mut digits = String::new();
    let mut prev_was_digit = false;
    for (i, &c) in chars.iter().enumerate() {
        if c == '_' {
            let next_is_digit = chars.get(i + 1).is_some_and(|c| c.is_ascii_digit());
            if !prev_was_digit || !next_is_digit {
                return Err(());
            }
            prev_was_digit = false;
            continue;
        }
        if !c.is_ascii_digit() {
            return Err(());
        }
        digits.push(c);
        prev_was_digit = true;
    }
    if digits.is_empty() {
        return Err(());
    }
    let magnitude: i64 = digits.parse().map_err(|_| ())?;
    Ok(if neg { -magnitude } else { magnitude })
}

/// Parses and validates the handle payload (the `parts[1]` base64 segment),
/// reproducing `HandleIssuer.verify`'s `str(payload["c"])` / `int(payload["pv"])`
/// coercions exactly (see [`python_str_coerce`]/[`python_int_coerce`]) rather
/// than requiring the exact expected JSON type.
fn parse_payload(encoded: &str) -> Result<Handle, Error> {
    let malformed = || Error::auth_failed("handle_malformed");
    let raw = b64d(encoded).map_err(|_| malformed())?;
    let text = String::from_utf8(raw).map_err(|_| malformed())?;
    let payload: Value = pyjson::loads(&text).map_err(|_| malformed())?;
    // A non-dict payload (list/string/number/...) makes every `payload["c"]`
    // subscript raise `TypeError` in Python -- caught, `handle_malformed`.
    let obj = payload.as_object().ok_or_else(malformed)?;

    let str_field = |name: &str| -> Result<String, Error> {
        // Missing key: Python's `payload["c"]` raises `KeyError` -- caught,
        // `handle_malformed`. Present: `str()` never fails.
        obj.get(name).map(python_str_coerce).ok_or_else(malformed)
    };
    let int_field = |name: &str| -> Result<i64, Error> {
        let v = obj.get(name).ok_or_else(malformed)?;
        python_int_coerce(v).map_err(|_| malformed())
    };

    let caller = str_field("c")?;
    let connection = str_field("n")?;
    let grant = str_field("g")?;
    let policy_version = int_field("pv")?;
    let issued_at = int_field("iat")?;
    let expires_at = int_field("exp")?;
    let handle_id = str_field("jti")?;

    // Python: `payload.get("v") != 1` -- equality, not identity, so
    // `True` (`True == 1`) and `1.0` (`1.0 == 1`) both pass.
    let v_matches_1 = match obj.get("v") {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => {
            if n.is_f64() {
                n.as_f64() == Some(1.0)
            } else {
                n.as_str() == "1"
            }
        }
        _ => false,
    };
    if !v_matches_1 {
        return Err(Error::auth_failed("handle_version"));
    }

    Ok(Handle {
        caller,
        connection,
        grant,
        policy_version,
        issued_at,
        expires_at,
        handle_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorClass;
    use std::collections::HashSet;

    // Port of test_core_audit_handles.py::HandleTestCase::test_issue_and_verify
    #[test]
    fn issue_and_verify() {
        let key = HandleIssuer::generate_key();
        let issuer = HandleIssuer::new(key.expose()).unwrap();
        let now = 1_700_000_000.0;
        let token = issuer
            .issue("agent-1", "gh", "g-1", 4, 300, Some(now))
            .unwrap();
        assert!(token.starts_with("zpw1."));
        let handle = issuer.verify(&token, Some(now + 10.0)).unwrap();
        assert_eq!(
            (
                handle.caller.as_str(),
                handle.connection.as_str(),
                handle.grant.as_str(),
                handle.policy_version
            ),
            ("agent-1", "gh", "g-1", 4)
        );
        assert_eq!(handle.expires_at, now as i64 + 300);
    }

    // Port of test_core_audit_handles.py::HandleTestCase::test_expiry_signature_and_format
    #[test]
    fn expiry_signature_and_format() {
        let key = HandleIssuer::generate_key();
        let issuer = HandleIssuer::new(key.expose()).unwrap();
        let now = 1_700_000_000.0;
        let token = issuer
            .issue("agent-1", "gh", "g-1", 4, 300, Some(now))
            .unwrap();

        let err = issuer.verify(&token, Some(now + 300.0)).unwrap_err();
        assert_eq!(err.reason, "handle_expired");

        let parts: Vec<&str> = token.split('.').collect();
        let (head, payload, sig) = (parts[0], parts[1], parts[2]);
        let forged_payload = {
            let mut p = payload[..payload.len() - 2].to_string();
            p.push_str(if &payload[payload.len() - 2..] != "AA" {
                "AA"
            } else {
                "BB"
            });
            p
        };
        assert!(
            issuer
                .verify(&format!("{head}.{forged_payload}.{sig}"), Some(now))
                .is_err()
        );
        assert!(
            issuer
                .verify(
                    &format!("{head}.{payload}.{}x", &sig[..sig.len() - 1]),
                    Some(now)
                )
                .is_err()
        );

        let other = HandleIssuer::new(HandleIssuer::generate_key().expose()).unwrap();
        assert!(other.verify(&token, Some(now)).is_err());

        for bad in ["", "zpw1", "zpw1.a", "zpw0.a.b", &"x".repeat(5000)] {
            let err = issuer.verify(bad, Some(now)).unwrap_err();
            assert!(err.is(ErrorClass::AuthFailed));
        }

        let err = issuer.issue("a", "b", "c", 1, 0, None).unwrap_err();
        assert!(err.is(ErrorClass::InvalidInput));
        let err = HandleIssuer::new(b"short").unwrap_err();
        assert!(err.is(ErrorClass::InvalidInput));
    }

    // Port of test_core_audit_handles.py::HandleTestCase::test_handle_carries_no_secret_material
    #[test]
    fn handle_carries_no_secret_material() {
        let key = HandleIssuer::generate_key();
        let issuer = HandleIssuer::new(key.expose()).unwrap();
        let now = 1_700_000_000.0;
        let token = issuer
            .issue("agent-1", "gh", "g-1", 4, 300, Some(now))
            .unwrap();
        let key_hex = key
            .expose()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert!(!token.contains(&key_hex));
        let tokens: HashSet<String> = (0..3)
            .map(|_| {
                issuer
                    .issue("agent-1", "gh", "g-1", 4, 300, Some(now))
                    .unwrap()
            })
            .collect();
        assert!(
            tokens.len() > 1,
            "issue() must be randomised (jti) even with identical arguments"
        );
    }

    #[test]
    fn verify_rejects_wrong_version() {
        // Same shape `issue` produces, but with v=2: must fail as
        // `handle_version`, distinctly from a malformed/tampered token.
        let key = HandleIssuer::generate_key();
        let issuer = HandleIssuer::new(key.expose()).unwrap();
        let now = 1_700_000_000.0;
        let payload = json!({"v": 2, "c": "agent-1", "n": "gh", "g": "g-1", "pv": 4, "iat": now as i64,
                              "exp": now as i64 + 300, "jti": "abc"});
        let payload_json = pyjson::dumps(&payload, DumpOptions::compact_sorted()).unwrap();
        let body = format!("{PREFIX}.{}", b64e(payload_json.as_bytes()));
        let sig = issuer.sign(&body);
        let token = format!("{body}.{sig}");
        let err = issuer.verify(&token, Some(now)).unwrap_err();
        assert_eq!(err.reason, "handle_version");
    }

    // A-9: Python's `_sign` calls `body.encode("ascii")` on the dot-joined
    // `f"{parts[0]}.{parts[1]}"`; a non-ASCII `parts[1]` makes that raise an
    // uncaught `UnicodeEncodeError` (coordinator ruling, PORTING.md §3.5).
    // Rust's `sign` has no ASCII restriction, so it always computes some
    // HMAC; pin that a non-ASCII payload segment still surfaces as an
    // ordinary `handle_signature` failure, not a panic or a different
    // reason.
    #[test]
    fn non_ascii_payload_segment_fails_as_signature_mismatch() {
        let key = HandleIssuer::generate_key();
        let issuer = HandleIssuer::new(key.expose()).unwrap();
        let token = "zpw1.café-not-base64.deadbeef";
        let err = issuer
            .verify(token, Some(1_700_000_000.0))
            .expect_err("non-ASCII payload segment must not verify");
        assert!(err.is(ErrorClass::AuthFailed));
        assert_eq!(err.reason, "handle_signature");
    }
}

/// Cross-language differential tests: a handle issued by one language must
/// verify in the other, using the same key and clock, and the two issuers
/// must produce byte-identical tokens for the same `now`/`jti` (the only
/// non-deterministic input, which the Python side is told to hold fixed via
/// monkeypatching `secrets.token_bytes`).
#[cfg(test)]
mod oracle_tests {
    use super::*;
    use crate::oracle;

    const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn key_bytes() -> Vec<u8> {
        hex::decode(KEY_HEX).unwrap()
    }

    #[test]
    fn token_issued_by_rust_verifies_in_python() {
        let issuer = HandleIssuer::new(&key_bytes()).unwrap();
        let now = 1_700_000_000.0;
        let token = issuer
            .issue("agent-1", "gh", "g-1", 4, 300, Some(now))
            .unwrap();

        let script = format!(
            r#"
from zeropw.handles import HandleIssuer
issuer = HandleIssuer(bytes.fromhex("{KEY_HEX}"))
handle = issuer.verify("{token}", now={now} + 10)
print(handle.caller, handle.connection, handle.grant, handle.policy_version, handle.expires_at)
"#
        );
        let out = oracle::python(&script);
        assert_eq!(out.trim(), format!("agent-1 gh g-1 4 {}", now as i64 + 300));
    }

    #[test]
    fn token_issued_by_python_verifies_in_rust() {
        let now = 1_700_000_000.0;
        let script = format!(
            r#"
from zeropw.handles import HandleIssuer
issuer = HandleIssuer(bytes.fromhex("{KEY_HEX}"))
print(issuer.issue("agent-1", "gh", "g-1", 4, 300, now={now}))
"#
        );
        let token = oracle::python(&script).trim().to_string();

        let issuer = HandleIssuer::new(&key_bytes()).unwrap();
        let handle = issuer.verify(&token, Some(now + 10.0)).unwrap();
        assert_eq!(
            (
                handle.caller.as_str(),
                handle.connection.as_str(),
                handle.grant.as_str(),
                handle.policy_version,
                handle.expires_at
            ),
            ("agent-1", "gh", "g-1", 4, now as i64 + 300)
        );
    }

    #[test]
    fn issue_output_is_byte_identical_with_same_jti() {
        // Freeze `secrets.token_bytes` on the Python side to the same 12
        // bytes Rust's test drives through a stubbed jti, so the two
        // encoders can be compared byte-for-byte instead of just
        // cross-verified.
        let now = 1_700_000_000.0;
        let jti_hex = "0102030405060708090a0b0c";
        let script = format!(
            r#"
import secrets
from unittest import mock
from zeropw.handles import HandleIssuer
issuer = HandleIssuer(bytes.fromhex("{KEY_HEX}"))
with mock.patch.object(secrets, "token_bytes", return_value=bytes.fromhex("{jti_hex}")):
    print(issuer.issue("agent-1", "gh", "g-1", 4, 300, now={now}))
"#
        );
        let py_token = oracle::python(&script).trim().to_string();

        // Reproduce the same token by hand on the Rust side (bypassing the
        // random `jti` in `issue`) using the same payload-building logic.
        let payload = json!({
            "v": 1, "c": "agent-1", "n": "gh", "g": "g-1", "pv": 4,
            "iat": now as i64, "exp": now as i64 + 300,
            "jti": crate::pyjson::dumps(&json!(hex_to_b64url(jti_hex)), DumpOptions::plain()).unwrap().trim_matches('"'),
        });
        let payload_json = pyjson::dumps(&payload, DumpOptions::compact_sorted()).unwrap();
        let body = format!("{PREFIX}.{}", b64e(payload_json.as_bytes()));
        let issuer = HandleIssuer::new(&key_bytes()).unwrap();
        let sig = issuer.sign(&body);
        let rust_token = format!("{body}.{sig}");

        assert_eq!(rust_token, py_token);
    }

    fn hex_to_b64url(hex_str: &str) -> String {
        b64e(&hex::decode(hex_str).unwrap())
    }

    // A-12: `HandleIssuer.verify`'s `str(payload["c"])` / `int(payload["pv"])`
    // coercions, exercised end-to-end. Python signs a battery of
    // deliberately odd-typed payloads with the shared key (bypassing
    // `issue`, which never emits anything but well-typed payloads) and
    // prints what `verify` did with each; Rust verifies the exact same
    // tokens with the same key and the results/reasons must match line for
    // line.
    #[test]
    fn payload_coercion_matches_python_for_crafted_tokens() {
        let script = format!(
            r#"
import base64, hashlib, hmac, json
from zeropw.handles import HandleIssuer

KEY = bytes.fromhex("{KEY_HEX}")

def b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

def sign(body):
    return b64e(hmac.new(KEY, body.encode("ascii"), hashlib.sha256).digest())

def make_token(payload):
    body = "zpw1." + b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    return body + "." + sign(body)

base = {{"v": 1, "c": "agent-1", "n": "gh", "g": "g-1", "pv": 4, "iat": 1700000000, "exp": 1700000300, "jti": "abc"}}

def variant(**overrides):
    p = dict(base)
    p.update(overrides)
    return p

cases = [
    variant(),
    variant(c=None),
    variant(c=True),
    variant(c=[1, 2]),
    variant(c={{"x": 1}}),
    variant(n=4.0),
    variant(n=4),
    variant(pv=True),
    variant(pv=False),
    variant(pv=4.9),
    variant(pv=-4.9),
    variant(pv="42"),
    variant(pv=" 4_2 "),
    variant(pv="+7"),
    variant(pv="-7"),
    variant(pv="abc"),
    variant(pv=None),
    variant(pv=[1]),
    variant(v=True),
    variant(v=1.0),
    variant(v=2),
    variant(v=False),
]
missing_c = dict(base)
del missing_c["c"]
cases.append(missing_c)

issuer = HandleIssuer(KEY)
for payload in cases:
    token = make_token(payload)
    print("TOKEN", token)
    try:
        h = issuer.verify(token, now=1700000000.0 + 10)
        print("OK", h.caller, "|", h.connection, "|", h.grant, "|", h.policy_version, "|",
              h.issued_at, "|", h.expires_at, "|", h.handle_id)
    except Exception as exc:
        print("ERR", getattr(exc, "reason", type(exc).__name__))
"#
        );
        let py_out = oracle::python(&script);
        let lines: Vec<&str> = py_out.lines().collect();
        assert!(
            !lines.is_empty() && lines.len().is_multiple_of(2),
            "unexpected oracle output shape"
        );

        let issuer = HandleIssuer::new(&key_bytes()).unwrap();
        let now = 1_700_000_000.0 + 10.0;
        let mut i = 0;
        let mut checked = 0;
        while i < lines.len() {
            let token = lines[i]
                .strip_prefix("TOKEN ")
                .expect("expected a TOKEN line");
            let result_line = lines[i + 1];
            i += 2;
            let rust_result = issuer.verify(token, Some(now));
            if let Some(rest) = result_line.strip_prefix("OK ") {
                let parts: Vec<&str> = rest.split(" | ").collect();
                let handle = rust_result.unwrap_or_else(|e| {
                    panic!("rust rejected a token python accepted: token={token} err={e:?}")
                });
                assert_eq!(handle.caller, parts[0], "caller mismatch for token {token}");
                assert_eq!(
                    handle.connection, parts[1],
                    "connection mismatch for token {token}"
                );
                assert_eq!(handle.grant, parts[2], "grant mismatch for token {token}");
                assert_eq!(
                    handle.policy_version.to_string(),
                    parts[3],
                    "policy_version mismatch for token {token}"
                );
                assert_eq!(
                    handle.issued_at.to_string(),
                    parts[4],
                    "issued_at mismatch for token {token}"
                );
                assert_eq!(
                    handle.expires_at.to_string(),
                    parts[5],
                    "expires_at mismatch for token {token}"
                );
                assert_eq!(
                    handle.handle_id, parts[6],
                    "handle_id mismatch for token {token}"
                );
            } else if let Some(reason) = result_line.strip_prefix("ERR ") {
                let err = rust_result.unwrap_err();
                assert_eq!(err.reason, reason, "reason mismatch for token {token}");
            } else {
                panic!("unexpected oracle line: {result_line}");
            }
            checked += 1;
        }
        assert_eq!(checked, 23, "expected exactly 23 crafted-token cases");
    }
}
