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
use std::sync::RwLock;
use subtle::ConstantTimeEq;

use crate::errors::{Error, ErrorClass};
use crate::pybase64;
use crate::pyjson::{self, DumpOptions};
use crate::pystr;
use crate::secret::SecretBytes;
use crate::store;

pub const PREFIX: &str = "zpw1";
pub const HANDLE_KEY_SIZE: usize = 32;
pub const MAX_TOKEN_LENGTH: usize = 2048;

fn b64e(raw: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(raw)
}

/// Port of `handles._b64d`: re-pads `text` to a multiple of 4 with `=`
/// (`"=" * (-len(text) % 4)`, replicated as `(4 - len % 4) % 4`, counting
/// Unicode code points as Python's `len()` does) and then decodes with
/// Python's lenient `base64.urlsafe_b64decode` (ASCII-only precheck,
/// `-`/`_` translated to `+`/`/`, then the non-strict `binascii` scan) --
/// see `crate::pybase64` for the exact algorithm. A-R2-3: this used to be a
/// strict `URL_SAFE_NO_PAD` decode, which rejected inputs (embedded junk,
/// `+`/`/`, non-canonical padding) Python accepts.
fn b64d(text: &str) -> Result<Vec<u8>, ()> {
    let pad_len = (4 - (text.chars().count() % 4)) % 4;
    let padded = format!("{text}{}", "=".repeat(pad_len));
    pybase64::urlsafe_b64decode(&padded).map_err(|_| ())
}

/// `handles.Handle`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handle {
    pub caller: String,
    pub connection: String,
    pub grant: String,
    pub policy_version: crate::pyint::PyInt,
    pub issued_at: crate::pyint::PyInt,
    pub expires_at: crate::pyint::PyInt,
    pub handle_id: String,
}

/// Port of `handles.HandleIssuer`.
#[derive(Debug)]
pub struct HandleIssuer {
    key: RwLock<SecretBytes>,
}

impl HandleIssuer {
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        if key.len() < HANDLE_KEY_SIZE {
            return Err(Error::invalid_input("handle_key_too_short"));
        }
        Ok(HandleIssuer {
            key: RwLock::new(SecretBytes::from_slice(key)),
        })
    }

    /// `HandleIssuer.generate_key`.
    pub fn generate_key() -> SecretBytes {
        let mut buf = vec![0u8; HANDLE_KEY_SIZE];
        OsRng.fill_bytes(&mut buf);
        SecretBytes::new(buf)
    }

    /// Atomically invalidate old handles after incident containment or recovery.
    pub fn replace_key(&self, key: &[u8]) -> Result<(), Error> {
        if key.len() < HANDLE_KEY_SIZE {
            return Err(Error::invalid_input("handle_key_too_short"));
        }
        *self.key.write().unwrap_or_else(|e| e.into_inner()) = SecretBytes::from_slice(key);
        Ok(())
    }

    fn sign(&self, body: &str) -> String {
        let key = self.key.read().unwrap_or_else(|e| e.into_inner());
        let mut mac =
            Hmac::<Sha256>::new_from_slice(key.expose()).expect("HMAC accepts any key length");
        mac.update(body.as_bytes());
        b64e(&mac.finalize().into_bytes())
    }

    /// `HandleIssuer.issue`. Python applies unbounded `int(now)` and then
    /// adds the bounded TTL. `PyInt::coerce_from_json` reproduces the exact
    /// finite binary64 truncation, including values far beyond `i64`.
    /// `int(policy_version)` is unbounded too: the payload carries the exact
    /// integer the caller's grant holds, whatever its magnitude.
    pub fn issue(
        &self,
        caller: &str,
        connection: &str,
        grant: &str,
        policy_version: impl Into<crate::pyint::PyInt>,
        ttl_seconds: i64,
        now: Option<f64>,
    ) -> Result<String, Error> {
        if ttl_seconds <= 0 || ttl_seconds > 86400 {
            return Err(Error::invalid_input("handle_ttl"));
        }
        let now = now.unwrap_or_else(store::now);
        if !now.is_finite() {
            return Err(Error::invalid_input("handle_clock"));
        }
        let issued = crate::pyint::PyInt::coerce_from_json(&json!(now))
            .ok_or_else(|| Error::invalid_input("handle_clock"))?;
        let exp = crate::pyint::PyInt(&issued.0 + num_bigint::BigInt::from(ttl_seconds));
        let policy_version: crate::pyint::PyInt = policy_version.into();
        let mut jti_raw = [0u8; 12];
        OsRng.fill_bytes(&mut jti_raw);
        let payload = json!({
            "v": 1,
            "c": caller,
            "n": connection,
            "g": grant,
            "pv": policy_version.value(),
            "iat": issued.value(),
            "exp": exp.value(),
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
        // `_sign(body)` encodes the body as ASCII and `hmac.compare_digest`
        // refuses a non-ASCII `str`: both raise built-in exceptions that
        // escape `verify` and `gateway.relay` uncaught, so the HTTP server's
        // catch-all answers 500 `internal_error` without an audit record
        // (measured on CPython 3.12.14). An agent controls both segments
        // without the key, so the outcome is reproduced, in Python's order.
        if !parts[1].is_ascii() {
            return Err(uncaught_builtin("UnicodeEncodeError"));
        }
        let expected = self.sign(&body);
        if !parts[2].is_ascii() {
            return Err(uncaught_builtin("TypeError"));
        }
        let ok = expected.len() == parts[2].len()
            && bool::from(expected.as_bytes().ct_eq(parts[2].as_bytes()));
        if !ok {
            return Err(Error::auth_failed("handle_signature"));
        }
        let handle = parse_payload(parts[1])?;
        let current = now.unwrap_or_else(store::now);
        if matches!(
            crate::pyint::cmp_bigint_f64(&handle.expires_at.0, current),
            Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
        ) {
            return Err(Error::auth_failed("handle_expired"));
        }
        Ok(handle)
    }
}

/// A built-in exception (`type(exc).__name__ == name`) that Python lets
/// escape `HandleIssuer.verify`. It is not a `ZeroPWError`, so it carries
/// [`ErrorClass::ZeroPW`] under the built-in's name; the only caller,
/// `gateway::relay`, turns any non-`AuthFailed` verify error into the
/// server's fixed 500 `internal_error` reply, as Python's `_dispatch` does.
fn uncaught_builtin(name: &'static str) -> Error {
    Error::subclass(ErrorClass::ZeroPW, name, "internal_error", "")
}

/// Python `str(value)` on a JSON-decoded scalar/container, as
/// `HandleIssuer.verify` applies via `str(payload["c"])` etc. Never fails:
/// `str()` succeeds for every Python object. For `str`, this is the value
/// itself; for everything else it is `repr(value)` (`None`/`True`/`False`,
/// the canonical number form, or a Python-style `repr` of a list/dict) via
/// [`pystr::repr_value`], the crate's one canonical container-`repr`
/// implementation (PORTING.md §3b).
fn python_str_coerce(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => pystr::repr_value(other),
    }
}

/// Python `int(value)` coercion, as `HandleIssuer.verify` applies via
/// `int(payload["pv"])`/`int(payload["iat"])`/`int(payload["exp"])`. `None`
/// covers every case Python's `int()` would raise `TypeError`/`ValueError`
/// for (both caught by `verify`'s `except (KeyError, TypeError, ValueError)`
/// and mapped to `handle_malformed`) -- `None`, a list/dict, a non-numeric
/// string, or a decimal string beyond CPython's integer-string digit limit.
/// Every accepted value is kept exact and unbounded ([`crate::pyint::PyInt`]),
/// including Unicode `Nd` digit strings and magnitudes far beyond `i64`.
///
/// A float that is `inf`/`-inf` makes Python's `int()` raise `OverflowError`,
/// which is *not* one of `TypeError`/`ValueError`/`KeyError` and so escapes
/// `verify` uncaught -- PORTING.md §3.5 applies and this is folded into the
/// same `handle_malformed` result as the other coercion failures. In practice
/// a non-finite float payload cannot even reach this function:
/// [`pyjson::loads`] already rejects the bare `Infinity`/`-Infinity` JSON
/// tokens Python's decoder would have accepted (`rust/DEVIATIONS.md`, pyjson
/// row).
fn python_int_coerce(value: &Value) -> Option<crate::pyint::PyInt> {
    crate::pyint::PyInt::coerce_from_json(value)
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
    let int_field = |name: &str| -> Result<crate::pyint::PyInt, Error> {
        let v = obj.get(name).ok_or_else(malformed)?;
        python_int_coerce(v).ok_or_else(malformed)
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

    #[test]
    fn shared_issuer_rotation_invalidates_existing_handles() {
        let issuer = std::sync::Arc::new(HandleIssuer::new(&[1; 32]).unwrap());
        let token = issuer.issue("p", "c", "g", 1, 60, Some(100.0)).unwrap();
        let shared = issuer.clone();
        std::thread::spawn(move || shared.replace_key(&[2; 32]).unwrap())
            .join()
            .unwrap();
        assert_eq!(
            issuer.verify(&token, Some(101.0)).unwrap_err().reason,
            "handle_signature"
        );
        let fresh = issuer.issue("p", "c", "g", 1, 60, Some(100.0)).unwrap();
        assert!(issuer.replace_key(&[3; 4]).is_err());
        assert!(issuer.verify(&fresh, Some(101.0)).is_ok());
    }
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
            ),
            ("agent-1", "gh", "g-1")
        );
        assert_eq!(handle.policy_version, 4);
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

    // X-8/X-12: a non-finite `now` must be rejected, not silently coerced.
    // Measured against live `python3.12`: `issuer.issue(..., now=float(
    // "inf"))`/`now=float("-inf")` raise uncaught `OverflowError`
    // ("cannot convert float infinity to integer"); `now=float("nan")`
    // raises uncaught `ValueError` ("cannot convert float NaN to
    // integer") -- all three escape `issue` uncaught (no `try`/`except`
    // there), so PORTING.md §3.5 applies. Before this fix, none of these
    // panicked OR errored: `now as i64` silently produced `i64::MAX`,
    // `i64::MIN`, and `0` respectively, and `0` (from NaN) let `issue`
    // *succeed* with a validly-signed token dated to the Unix epoch --
    // the fail-open direction on exactly the input Python refuses.
    #[test]
    fn issue_rejects_non_finite_now() {
        let key = HandleIssuer::generate_key();
        let issuer = HandleIssuer::new(key.expose()).unwrap();
        for now in [f64::INFINITY, f64::NEG_INFINITY, f64::NAN] {
            let err = issuer
                .issue("a", "b", "c", 1, 300, Some(now))
                .expect_err("non-finite now must not panic or silently succeed");
            assert!(err.is(ErrorClass::InvalidInput));
            assert_eq!(err.reason, "handle_clock");
        }
    }

    // Python's `int(float)` is unbounded. Every token issued at a finite
    // huge clock must retain that exact integer and verify successfully.
    #[test]
    fn issue_and_verify_accept_now_beyond_i64() {
        let key = HandleIssuer::generate_key();
        let issuer = HandleIssuer::new(key.expose()).unwrap();
        for now in [1e30, 9.223372036854776e18_f64] {
            let token = issuer
                .issue("a", "b", "c", 1, 300, Some(now))
                .expect("finite Python float must convert to an unbounded int");
            let handle = issuer.verify(&token, Some(now - 1.0)).unwrap();
            let expected = crate::pyint::PyInt::coerce_from_json(&json!(now)).unwrap();
            assert_eq!(handle.issued_at, expected);
            assert_eq!(
                handle.expires_at.0,
                expected.0 + num_bigint::BigInt::from(300)
            );
        }
    }

    // The TTL addition is unbounded too: this value starts below 2**63 but
    // expires above it. Python succeeds and preserves the exact sum.
    #[test]
    fn issue_widens_when_issued_plus_ttl_exceeds_i64() {
        let key = HandleIssuer::generate_key();
        let issuer = HandleIssuer::new(key.expose()).unwrap();
        let now = 9223372036854774784.0_f64;
        let token = issuer
            .issue("a", "b", "c", 1, 86400, Some(now))
            .expect("Python integer addition cannot overflow");
        let handle = issuer.verify(&token, Some(now - 1.0)).unwrap();
        assert_eq!(handle.expires_at.to_string(), "9223372036854861184");
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

    /// Rows 39/40: a non-ASCII payload segment makes Python's `_sign` raise
    /// `UnicodeEncodeError` (checked before the signature), and a non-ASCII
    /// signature segment with an ASCII payload makes `hmac.compare_digest`
    /// raise `TypeError`. Each class is compared with the real
    /// `HandleIssuer.verify`, in Python's evaluation order.
    #[test]
    fn non_ascii_segments_raise_the_python_builtin_in_python_order() {
        let issuer = HandleIssuer::new(&[7u8; 32]).unwrap();
        let now = 1_700_000_000.0;
        let token = issuer
            .issue("agent-1", "gh", "g-1", 4, 300, Some(now))
            .unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        let tokens = [
            "zpw1.caf\u{e9}-not-base64.deadbeef".to_string(),
            "zpw1.caf\u{e9}.si\u{e9}".to_string(),
            format!("{}.{}.caf\u{e9}-not-hex", parts[0], parts[1]),
            format!("{}.{}.{}", parts[0], parts[1], "A".repeat(43)),
        ];
        // What the prototype's `HandleIssuer.verify` raised for each token
        // (the first two escaped as built-ins); Rust fails closed for all.
        let python = [
            "UnicodeEncodeError ",
            "UnicodeEncodeError ",
            "TypeError ",
            "AuthFailed handle_signature",
        ];
        for (token, want) in tokens.iter().zip(python) {
            let err = issuer.verify(token, Some(now)).unwrap_err();
            let got = if err.is(ErrorClass::AuthFailed) {
                format!("AuthFailed {}", err.reason)
            } else {
                assert!(err.is(ErrorClass::ZeroPW));
                format!("{} ", err.name)
            };
            assert_eq!(got, want, "{token:?}");
        }
    }

    // Python's `int(payload["pv"])` is unbounded and accepts every Unicode
    // `Nd` digit string, so a signed payload carrying such a `pv` verifies
    // with the exact integer.
    #[test]
    fn signed_payload_with_unbounded_policy_version_keeps_the_exact_integer() {
        let key = HandleIssuer::generate_key();
        let issuer = HandleIssuer::new(key.expose()).unwrap();
        let now = 1_700_000_000.0;
        for (pv, expected) in [
            (json!("9".repeat(25)), "9".repeat(25)),
            (
                json!("999999999999999999999999999999999"),
                "999999999999999999999999999999999".to_owned(),
            ),
            (json!("\u{664}\u{662}"), "42".to_owned()),
            (
                json!("-9223372036854775809"),
                "-9223372036854775809".to_owned(),
            ),
        ] {
            let payload = json!({
                "v": 1, "c": "agent-1", "n": "gh", "g": "g-1", "pv": pv,
                "iat": now as i64, "exp": now as i64 + 300, "jti": "abc",
            });
            let payload_json = pyjson::dumps(&payload, DumpOptions::compact_sorted()).unwrap();
            let body = format!("{PREFIX}.{}", b64e(payload_json.as_bytes()));
            let sig = issuer.sign(&body);
            let token = format!("{body}.{sig}");
            let handle = issuer.verify(&token, Some(now)).unwrap();
            assert_eq!(handle.policy_version.to_string(), expected);
        }
    }

    // `issue` emits `int(policy_version)` exactly, beyond every machine width.
    #[test]
    fn issue_round_trips_an_unbounded_policy_version() {
        let key = HandleIssuer::generate_key();
        let issuer = HandleIssuer::new(key.expose()).unwrap();
        let pv = crate::pyint::PyInt("1".repeat(40).parse().unwrap());
        let token = issuer
            .issue(
                "agent-1",
                "gh",
                "g-1",
                pv.clone(),
                300,
                Some(1_700_000_000.0),
            )
            .unwrap();
        let handle = issuer.verify(&token, Some(1_700_000_001.0)).unwrap();
        assert_eq!(handle.policy_version, pv);
    }

    // `int(2**63 as float)` and an integer JSON literal at 2**63 produce
    // the same unbounded Python integer during verification.
    #[test]
    fn float_exp_exactly_two_pow_63_matches_the_integer_literal() {
        let key = HandleIssuer::generate_key();
        let issuer = HandleIssuer::new(key.expose()).unwrap();
        let now = 1_700_000_000.0;
        for exp in [
            json!(9223372036854775808.0_f64), // == 2^63, exactly representable
            json!(9223372036854775808_u64),   // the equivalent integer literal
        ] {
            let payload = json!({
                "v": 1, "c": "agent-1", "n": "gh", "g": "g-1", "pv": 4,
                "iat": now as i64, "exp": exp, "jti": "abc",
            });
            let payload_json = pyjson::dumps(&payload, DumpOptions::compact_sorted()).unwrap();
            let body = format!("{PREFIX}.{}", b64e(payload_json.as_bytes()));
            let sig = issuer.sign(&body);
            let token = format!("{body}.{sig}");
            let handle = issuer.verify(&token, Some(now)).unwrap();
            assert_eq!(handle.expires_at.to_string(), "9223372036854775808");
        }
    }
}

/// Wire-format tests against tokens the Python prototype issued (golden
/// fixtures, `tests/fixtures/python/handles/GENERATE.md`): they verify here,
/// and this issuer produces the identical token for the same key, clock and
/// `jti`, so the prototype verifies Rust-issued tokens as well.
#[cfg(test)]
mod oracle_tests {
    use super::*;

    fn fixture() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/python/handles/tokens.json");
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn key_bytes() -> Vec<u8> {
        hex::decode(fixture()["key_hex"].as_str().unwrap()).unwrap()
    }

    fn hex_to_b64url(hex_str: &str) -> String {
        b64e(&hex::decode(hex_str).unwrap())
    }

    /// The token `issue()` would produce for `case` with the fixture's
    /// fixed `jti` (bypassing the random `jti` in `issue`).
    fn rust_token_for(case: &Value) -> String {
        let fixture = fixture();
        let now = case["now"].as_f64().unwrap();
        let issued = crate::pyint::PyInt::coerce_from_json(&json!(now)).unwrap();
        let expires = crate::pyint::PyInt(&issued.0 + num_bigint::BigInt::from(300));
        let payload = json!({
            "v": 1, "c": case["caller"], "n": case["connection"], "g": case["grant"],
            "pv": case["policy_version"], "iat": issued.value(), "exp": expires.value(),
            "jti": hex_to_b64url(fixture["jti_hex"].as_str().unwrap()),
        });
        let payload_json = pyjson::dumps(&payload, DumpOptions::compact_sorted()).unwrap();
        let body = format!("{PREFIX}.{}", b64e(payload_json.as_bytes()));
        let issuer = HandleIssuer::new(&key_bytes()).unwrap();
        format!("{body}.{}", issuer.sign(&body))
    }

    #[test]
    fn token_issued_by_python_verifies_in_rust() {
        let fixture = fixture();
        let case = &fixture["tokens"][0];
        let now = case["now"].as_f64().unwrap();
        assert_eq!(now, 1_700_000_000.0);
        let issuer = HandleIssuer::new(&key_bytes()).unwrap();
        let handle = issuer
            .verify(case["token"].as_str().unwrap(), Some(now + 10.0))
            .unwrap();
        let want = &case["verified"];
        assert_eq!(handle.caller, want["caller"].as_str().unwrap());
        assert_eq!(handle.connection, want["connection"].as_str().unwrap());
        assert_eq!(handle.grant, want["grant"].as_str().unwrap());
        assert_eq!(
            handle.policy_version.to_string(),
            want["policy_version"].as_str().unwrap()
        );
        assert_eq!(
            handle.issued_at.to_string(),
            want["issued_at"].as_str().unwrap()
        );
        assert_eq!(
            handle.expires_at.to_string(),
            want["expires_at"].as_str().unwrap()
        );
        assert_eq!(handle.handle_id, want["handle_id"].as_str().unwrap());
    }

    #[test]
    fn token_issued_by_rust_has_the_python_payload() {
        let fixture = fixture();
        let case = &fixture["tokens"][0];
        let now = case["now"].as_f64().unwrap();
        let issuer = HandleIssuer::new(&key_bytes()).unwrap();
        let token = issuer
            .issue("agent-1", "gh", "g-1", 4, 300, Some(now))
            .unwrap();
        let payload = |token: &str| -> Value {
            let segment = token.split('.').nth(1).unwrap();
            let mut value: Value = serde_json::from_slice(&b64d(segment).unwrap()).unwrap();
            value.as_object_mut().unwrap().remove("jti");
            value
        };
        assert_eq!(payload(&token), payload(case["token"].as_str().unwrap()));
        let handle = issuer.verify(&token, Some(now + 10.0)).unwrap();
        assert_eq!(handle.expires_at, now as i64 + 300);
    }

    #[test]
    fn huge_finite_issue_round_trips_both_directions() {
        let fixture = fixture();
        let case = &fixture["tokens"][1];
        let now = case["now"].as_f64().unwrap();
        assert_eq!(now, 1e30);
        let issuer = HandleIssuer::new(&key_bytes()).unwrap();
        let python_token = case["token"].as_str().unwrap();
        let rust_handle = issuer.verify(python_token, Some(now)).unwrap();
        assert_eq!(
            rust_handle.issued_at.to_string(),
            case["verified"]["issued_at"].as_str().unwrap()
        );
        assert_eq!(
            rust_handle.expires_at.to_string(),
            case["verified"]["expires_at"].as_str().unwrap()
        );
        assert_eq!(rust_token_for(case), python_token);
        // A Rust-issued token at the same clock verifies to the same values.
        let rust_token = issuer
            .issue("agent-1", "gh", "g-1", 4, 300, Some(now))
            .unwrap();
        let again = issuer.verify(&rust_token, Some(now)).unwrap();
        assert_eq!(again.issued_at, rust_handle.issued_at);
        assert_eq!(again.expires_at, rust_handle.expires_at);
    }

    #[test]
    fn issue_output_is_byte_identical_with_same_jti() {
        let fixture = fixture();
        let case = &fixture["tokens"][0];
        assert_eq!(rust_token_for(case), case["token"].as_str().unwrap());
    }
}
