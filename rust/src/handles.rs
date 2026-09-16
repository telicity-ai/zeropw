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

/// Parses and validates the handle payload (the `parts[1]` base64 segment).
/// Python's version does `str(payload["c"])` / `int(payload["pv"])`, which
/// coerces almost any JSON scalar (e.g. a `null` "c" field stringifies to
/// `"None"`, a float "pv" coerces via `int()`); this port requires the exact
/// expected JSON type (string for `c`/`n`/`g`/`jti`, integer for
/// `v`/`pv`/`iat`/`exp`) and treats anything else as `handle_malformed`. A
/// payload that would rely on that leniency can only be produced by someone
/// who already holds the HMAC signing key (the signature is verified before
/// the payload is ever parsed), so this narrows Python's forged-token
/// behaviour without weakening the security boundary -- recorded in
/// `rust/DEVIATIONS.md`.
fn parse_payload(encoded: &str) -> Result<Handle, Error> {
    let malformed = || Error::auth_failed("handle_malformed");
    let raw = b64d(encoded).map_err(|_| malformed())?;
    let text = String::from_utf8(raw).map_err(|_| malformed())?;
    let payload: Value = pyjson::loads(&text).map_err(|_| malformed())?;
    let obj = payload.as_object().ok_or_else(malformed)?;

    let str_field = |name: &str| -> Result<String, Error> {
        obj.get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(malformed)
    };
    let int_field = |name: &str| -> Result<i64, Error> {
        obj.get(name).and_then(Value::as_i64).ok_or_else(malformed)
    };

    let caller = str_field("c")?;
    let connection = str_field("n")?;
    let grant = str_field("g")?;
    let policy_version = int_field("pv")?;
    let issued_at = int_field("iat")?;
    let expires_at = int_field("exp")?;
    let handle_id = str_field("jti")?;

    if obj.get("v").and_then(Value::as_i64) != Some(1) {
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
}
