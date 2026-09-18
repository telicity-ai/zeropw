//! Port of `zeropw/vault.py`: encrypted vault with versioned secrets,
//! rotation, backup, restore and recovery.
//!
//! Envelope: every secret version is encrypted with the vault
//! data-encryption key (DEK) using ChaCha20-Poly1305 (random nonce, AAD =
//! secret id + version). The DEK is wrapped twice: by the KMS (normal
//! operation) and by a key derived from an independent recovery passphrase
//! (disaster recovery).
//!
//! Value access:
//!
//! * [`Vault::secret_for_trusted_use`] returns plaintext to *in-process*
//!   trusted components only (gateway, signer). It is never exposed over the
//!   tools API.
//! * [`Vault::reveal`] is the administrator's single-secret read. It
//!   requires a fresh administrator re-authentication and always writes an
//!   audit record first. There is no bulk plaintext export.
//!
//! ## Uncaught-exception escapes (`DEVIATIONS.md`, PORTING.md §3.5)
//!
//! `zeropw/vault.py` reads its own stored JSON documents (`vault/secrets.json`)
//! with no defensive type checking: `doc["secrets"][secret_id]["versions"][...]`
//! etc. A malformed document (never produced by this module's own writers,
//! only reachable via a hand-edited or bit-rotted state file) raises an
//! uncaught `KeyError`/`TypeError` in Python. Every such access in this port
//! returns `StateError("state_corrupt")` instead (the closest handled error a
//! caller of a `Vault` method already expects for corrupted state), recorded
//! once here rather than at each call site (same pattern as the `policy`,
//! `audit` and `handles` rows in `DEVIATIONS.md`). This also covers
//! `int(v)` over a `versions` object's own keys (`put_secret`,
//! `list_secrets`, `values_for_trusted_scan`): a key `int()` cannot parse
//! raises an uncaught `ValueError`, matched here by [`parse_version_key`]
//! (finding E-R3-4 -- a previous version of this port silently *dropped*
//! such a key instead of erroring, via `.parse::<i64>().ok()` inside a
//! `filter_map`, which is neither Python's behaviour nor this module's own
//! documented `state_corrupt` convention for exactly this class of error).

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde_json::{Map, Value, json};

use crate::audit::{Audit, RecordArgs};
use crate::crypto::chacha20poly1305 as aead;
use crate::errors::Error;
use crate::kms::{Kms, WrappedKey};
use crate::projects::{Projects, validate_name};
use crate::pybase64;
use crate::pyjson::{self, DumpOptions};
use crate::secret::SecretBytes;
use crate::store::{StateDir, iso};

pub const VAULT_DOC: &str = "vault/secrets.json";
pub const ADMIN_DOC: &str = "admin.json";
pub const SECRET_KINDS: &[&str] = &["api_key", "password", "env_var", "ssh_private_key"];
pub const VERSION_STATES: &[&str] = &["staged", "active", "retired", "revoked"];
pub const MAX_SECRET_BYTES: usize = 64 * 1024;
pub const REAUTH_WINDOW_SECONDS: f64 = 60.0;
pub const SCRYPT_LOG_N: u8 = 14; // N = 2**14
pub const SCRYPT_R: u32 = 8;
pub const SCRYPT_P: u32 = 1;

fn random_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).to_vec()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Python truthiness of a JSON-decoded value (`if not doc: ...`, `x or {}`,
/// `record.get("caller")` etc.): `None`, `false`, `0`/`0.0`, `""`, `[]`, `{}`
/// are all falsy.
fn json_falsy(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_f64().map(|f| f == 0.0).unwrap_or(false),
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
    }
}

fn as_obj(v: &Value) -> Result<&Map<String, Value>, Error> {
    v.as_object()
        .ok_or_else(|| Error::state("state_corrupt").with_detail("vault"))
}

fn as_obj_mut(v: &mut Value) -> Result<&mut Map<String, Value>, Error> {
    v.as_object_mut()
        .ok_or_else(|| Error::state("state_corrupt").with_detail("vault"))
}

fn get_or_null<'v>(m: &'v Map<String, Value>, key: &str) -> &'v Value {
    m.get(key).unwrap_or(&Value::Null)
}

/// Python `str()` on a JSON value, used where `vault.py` coerces a stored
/// field with `str(...)` (`manifest.get("sha256")`, `manifest.get(
/// "backup_id")`). A well-formed manifest this crate's own `backup()` writes
/// never puts an array/object in either field, but the manifest is
/// completely attacker-controlled in an otherwise digest-valid archive (the
/// digest only covers `documents`, never `manifest`) -- so `restore` must
/// still produce Python's exact `str()` output for that case, not merely
/// something plausible: `str()` on a `dict`/`list` falls back to `repr()`
/// (`str({'a': 1}) == "{'a': 1}"`, `str([1, 2]) == "[1, 2]"`), so the
/// catch-all here defers to [`python_repr_value`] instead of a compact JSON
/// rendering (finding E-R3-3; the previous version used `Value::to_string()`
/// here, e.g. `{"a":1}`, which is not what Python's `str()` produces).
fn python_str_scalar(v: &Value) -> String {
    match v {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::String(s) => s.clone(),
        Value::Number(n) => {
            if n.is_f64() {
                pyjson::python_float_repr(n.as_f64().unwrap_or(0.0))
            } else {
                n.as_str().to_string()
            }
        }
        Value::Array(_) | Value::Object(_) => python_repr_value(v),
    }
}

/// Python `repr()` of a value parsed by `json.loads`. `str()` on a
/// `dict`/`list` (see [`python_str_scalar`]) falls back to `__repr__`, which
/// renders every *nested* element with, in turn, its own `repr()` --
/// `str({'a': 1}) == "{'a': 1}"`, `str([1, 'x', None, True]) == "[1, 'x',
/// None, True]"`. Dict/list iteration order matches Python's own (both
/// preserve JSON document insertion order; this crate's `serde_json` is
/// built with the `preserve_order` feature for exactly this reason). Nested
/// strings reuse [`crate::pystr::repr_str`] (dict keys are always JSON
/// strings, and Python's `dict.__repr__` reprs its keys the same as any
/// other value).
fn python_repr_value(v: &Value) -> String {
    match v {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::String(s) => crate::pystr::repr_str(s),
        Value::Number(n) => {
            if n.is_f64() {
                pyjson::python_float_repr(n.as_f64().unwrap_or(0.0))
            } else {
                n.as_str().to_string()
            }
        }
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(python_repr_value).collect();
            format!("[{}]", inner.join(", "))
        }
        Value::Object(map) => {
            let inner: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{}: {}", crate::pystr::repr_str(k), python_repr_value(v)))
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
    }
}

/// Unicode decimal-digit (category Nd) block starts, Unicode Character
/// Database version 15.0.0 -- the version CPython 3.12 bundles, matching
/// `pystr.rs`'s own tables. Every Nd block is exactly 10 consecutive
/// codepoints representing digits 0-9 in that order (a structural guarantee
/// of the Unicode Standard, verified directly against `python3.12`'s
/// `unicodedata` module for every block below): `unicode_decimal_digit_
/// value` finds the block containing a codepoint and returns its offset
/// within it. Used by [`python_int_from_str`] (finding E-R3-4) to match
/// CPython's `int(str)`, which accepts *any* script's decimal digits, not
/// just ASCII (`int("１") == 1`, the fullwidth digit one).
const DECIMAL_DIGIT_BLOCK_STARTS: &[u32] = &[
    0x30, 0x660, 0x6f0, 0x7c0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66,
    0xde6, 0xe50, 0xed0, 0xf20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90,
    0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xa9f0, 0xaa50, 0xabf0, 0xff10,
    0x104a0, 0x10d30, 0x11066, 0x110f0, 0x11136, 0x111d0, 0x112f0, 0x11450, 0x114d0, 0x11650,
    0x116c0, 0x11730, 0x118e0, 0x11950, 0x11c50, 0x11d50, 0x11da0, 0x11f50, 0x16a60, 0x16ac0,
    0x16b50, 0x1d7ce, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6, 0x1e140, 0x1e2f0, 0x1e4f0, 0x1e950,
    0x1fbf0,
];

/// The decimal digit value (0-9) of `c` per CPython 3.12's Unicode decimal
/// digit (Nd) classification, or `None` if `c` is not a decimal digit in any
/// script.
fn unicode_decimal_digit_value(c: char) -> Option<u32> {
    let cp = c as u32;
    match DECIMAL_DIGIT_BLOCK_STARTS.binary_search(&cp) {
        Ok(_) => Some(0),
        Err(0) => None,
        Err(idx) => {
            let start = DECIMAL_DIGIT_BLOCK_STARTS[idx - 1];
            let offset = cp - start;
            if offset < 10 { Some(offset) } else { None }
        }
    }
}

/// `str.strip()` with CPython's exact `str.isspace()` predicate (see
/// `crate::pystr::is_space`), not Rust's narrower `char::is_whitespace()`.
fn python_strip(s: &str) -> &str {
    s.trim_matches(crate::pystr::is_space)
}

/// `int(str)` matching CPython 3.12 exactly: optional `str.isspace()`
/// padding, an optional `+`/`-` sign, then one or more Unicode decimal
/// digits (any script -- `int("１") == 1`, not just ASCII `0`-`9`) with
/// single, non-leading/trailing underscores allowed between them
/// (`"1_000"`, not `"_1"`/`"1_"`/`"1__0"`). Returns `None` for anything
/// `int()` would raise `ValueError` on, *and* for a magnitude Python's
/// arbitrary-precision `int` can hold but Rust's `i64` cannot.
///
/// Used for `vault.py`'s `int(v)` over a `versions` object's own keys
/// (finding E-R3-4: `put_secret`'s `max(int(v) for v in entry["versions"])`,
/// `list_secrets`/`values_for_trusted_scan`'s `sorted(..., key=lambda item:
/// int(item[0]))`). Unlike `handles.rs`'s deliberately ASCII-only
/// `python_int_coerce` (PORTING.md §3.7 -- reachable only via a payload
/// already authenticated with the HMAC signing key), a vault `versions` key
/// is state-file content, not signed input, so this port must accept
/// exactly what Python's own `int()` accepts, not a stricter subset.
fn python_int_from_str(s: &str) -> Option<i64> {
    let trimmed = python_strip(s);
    let (negative, digits_part) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    if digits_part.is_empty() || digits_part.starts_with('_') || digits_part.ends_with('_') {
        return None;
    }
    let mut cleaned = String::with_capacity(digits_part.len());
    let mut prev_underscore = false;
    for c in digits_part.chars() {
        if c == '_' {
            if prev_underscore {
                return None;
            }
            prev_underscore = true;
            continue;
        }
        let digit = unicode_decimal_digit_value(c)?;
        prev_underscore = false;
        cleaned.push((b'0' + digit as u8) as char);
    }
    let magnitude: i64 = cleaned.parse().ok()?;
    Some(if negative { -magnitude } else { magnitude })
}

/// A `versions` object key, parsed exactly like Python's `int(v)` (finding
/// E-R3-4). `vault.py` never guards this conversion with a `try`/`except`,
/// so a version key `int()` cannot parse raises an uncaught `ValueError`
/// there; the closest handled error a caller of a `Vault` method already
/// expects for corrupted state is `StateError("state_corrupt")` (this
/// module's own top-of-file DEVIATIONS note, PORTING.md §3.5).
fn parse_version_key(k: &str) -> Result<i64, Error> {
    python_int_from_str(k).ok_or_else(|| Error::state("state_corrupt").with_detail("vault"))
}

/// `vault.derive_key`: scrypt(N=2**14, r=8, p=1, dklen=32). `len(passphrase)`
/// in Python counts Unicode code points, matched here with `chars().count()`
/// rather than a UTF-8 byte length.
pub fn derive_key(passphrase: &str, salt: &[u8]) -> Result<SecretBytes, Error> {
    if passphrase.chars().count() < 8 {
        return Err(Error::invalid_input("passphrase_too_short"));
    }
    let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, 32)
        .expect("fixed scrypt parameters are always valid");
    let mut out = [0u8; 32];
    scrypt::scrypt(passphrase.as_bytes(), salt, &params, &mut out)
        .expect("fixed scrypt parameters/output length are always valid");
    Ok(SecretBytes::new(out.to_vec()))
}

// ------------------------------------------------------------------ admin auth
/// Proof of a recent administrator re-authentication. Port of `AdminAuth`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AdminAuth {
    pub verified_at: f64,
}

impl AdminAuth {
    pub fn new(verified_at: f64) -> Self {
        AdminAuth { verified_at }
    }

    pub fn fresh(&self, now: Option<f64>) -> bool {
        let current = now.unwrap_or_else(crate::store::now);
        let delta = current - self.verified_at;
        (0.0..=REAUTH_WINDOW_SECONDS).contains(&delta)
    }
}

/// Administrator passphrase (separate from any agent identity). Port of
/// `AdminCredential`.
pub struct AdminCredential<'a> {
    state: &'a StateDir,
}

impl<'a> AdminCredential<'a> {
    pub fn new(state: &'a StateDir) -> Self {
        AdminCredential { state }
    }

    pub fn initialize(&self, passphrase: &str) -> Result<(), Error> {
        if self.state.exists(ADMIN_DOC) {
            return Err(Error::state("admin_exists"));
        }
        let salt = random_bytes(16);
        let key = derive_key(passphrase, &salt)?;
        let hash = sha256(key.expose());
        self.state.write_json(
            ADMIN_DOC,
            &json!({
                "salt": pybase64::b64encode(&salt),
                "hash": pybase64::b64encode(&hash),
                "created_at": iso(None),
            }),
        )
    }

    /// `AdminCredential.verify`. A malformed `admin.json` (missing/invalid
    /// `salt`/`hash`) makes Python's `_b64d(doc["salt"])` raise an uncaught
    /// `KeyError`/`binascii.Error` -- outside the `except InvalidInput` that
    /// only guards the short-passphrase case in `derive_key`. Per §3.5 the
    /// closest handled error is this method's own `AuthFailed`
    /// (`admin_reauth_failed`); `AdminCredential::initialize` never writes a
    /// document that could trigger this.
    pub fn verify(&self, passphrase: &str, now: Option<f64>) -> Result<AdminAuth, Error> {
        let doc = self.state.read_json(ADMIN_DOC, Value::Null)?;
        if json_falsy(&doc) {
            return Err(Error::state("admin_missing"));
        }
        let reauth_failed = || Error::auth_failed("admin_reauth_failed");
        let salt = doc
            .get("salt")
            .and_then(Value::as_str)
            .and_then(|s| pybase64::b64decode(s).ok())
            .ok_or_else(reauth_failed)?;
        let key = derive_key(passphrase, &salt).map_err(|_| reauth_failed())?;
        let expected_hash = doc
            .get("hash")
            .and_then(Value::as_str)
            .and_then(|s| pybase64::b64decode(s).ok())
            .ok_or_else(reauth_failed)?;
        if !constant_time_eq(&sha256(key.expose()), &expected_hash) {
            return Err(reauth_failed());
        }
        Ok(AdminAuth::new(now.unwrap_or_else(crate::store::now)))
    }
}

// ------------------------------------------------------------------------ vault
/// Port of `vault.VersionMeta`.
#[derive(Clone, Debug, PartialEq)]
pub struct VersionMeta {
    pub secret_id: String,
    pub version: i64,
    pub status: String,
    pub created_at: String,
    /// Non-secret metadata derived from the value (e.g. the SSH public key);
    /// `{}` for every other kind. See [`Vault::public_metadata`].
    pub public: Value,
}

/// Port of `vault.SecretMeta`.
#[derive(Clone, Debug, PartialEq)]
pub struct SecretMeta {
    pub id: String,
    pub project: String,
    pub environment: String,
    pub kind: String,
    pub active_version: Option<i64>,
    pub versions: Vec<VersionMeta>,
}

/// Port of `vault.Vault`. `kms`/`audit`/`projects` are borrowed, not owned:
/// `Context` (the only constructor of these in this crate) leaks their
/// backing allocations to get a `'static` lifetime so several fields can
/// share the same referenced objects, mirroring Python's plain object
/// identity sharing (`ctx.vault.kms is ctx.kms`). See `context.rs`'s module
/// doc comment for the full rationale.
pub struct Vault<'a> {
    state: &'a StateDir,
    kms: &'a (dyn Kms + Send + Sync),
    dek: SecretBytes,
    audit: &'a Audit<'a>,
    projects: &'a Projects<'a>,
}

impl<'a> Vault<'a> {
    // lifecycle -----------------------------------------------------------
    pub fn initialize(
        state: &'a StateDir,
        kms: &'a (dyn Kms + Send + Sync),
        audit: &'a Audit<'a>,
        projects: &'a Projects<'a>,
        recovery_passphrase: &str,
    ) -> Result<Vault<'a>, Error> {
        if state.exists(VAULT_DOC) {
            return Err(Error::state("vault_exists"));
        }
        let dek_bytes = random_bytes(aead::KEY_SIZE);
        let salt = random_bytes(16);
        let recovery_key = derive_key(recovery_passphrase, &salt)?;
        let nonce = random_bytes(aead::NONCE_SIZE);
        let recovery_ciphertext = aead::encrypt(
            recovery_key.expose(),
            &nonce,
            &dek_bytes,
            b"zeropw-recovery",
        )
        .map_err(|e| Error::state("vault_init_failed").with_detail(e.to_string()))?;
        let wrapped = kms.wrap(&dek_bytes)?;
        let doc = json!({
            "dek": wrapped.to_dict(),
            "recovery": {
                "salt": pybase64::b64encode(&salt),
                "nonce": pybase64::b64encode(&nonce),
                "ciphertext": pybase64::b64encode(&recovery_ciphertext),
            },
            "secrets": {},
            "created_at": iso(None),
        });
        state.write_json(VAULT_DOC, &doc)?;
        Ok(Vault {
            state,
            kms,
            dek: SecretBytes::new(dek_bytes),
            audit,
            projects,
        })
    }

    pub fn open(
        state: &'a StateDir,
        kms: &'a (dyn Kms + Send + Sync),
        audit: &'a Audit<'a>,
        projects: &'a Projects<'a>,
    ) -> Result<Vault<'a>, Error> {
        let doc = state.read_json(VAULT_DOC, Value::Null)?;
        if json_falsy(&doc) {
            return Err(Error::state("vault_missing"));
        }
        let dek_dict = doc
            .get("dek")
            .ok_or_else(|| Error::state("state_corrupt").with_detail("vault"))?;
        let wrapped = WrappedKey::from_dict(dek_dict)?;
        let dek = kms.unwrap(&wrapped)?;
        Ok(Vault {
            state,
            kms,
            dek,
            audit,
            projects,
        })
    }

    /// Unwrap the DEK with the recovery passphrase and re-wrap it under a
    /// new KMS key.
    pub fn recover(
        state: &'a StateDir,
        new_kms: &'a (dyn Kms + Send + Sync),
        audit: &'a Audit<'a>,
        projects: &'a Projects<'a>,
        recovery_passphrase: &str,
    ) -> Result<Vault<'a>, Error> {
        let doc = state.read_json(VAULT_DOC, Value::Null)?;
        if json_falsy(&doc) {
            return Err(Error::state("vault_missing"));
        }
        let corrupt = || Error::state("state_corrupt").with_detail("vault");
        let rec = doc
            .get("recovery")
            .and_then(Value::as_object)
            .ok_or_else(corrupt)?;
        let salt = rec
            .get("salt")
            .and_then(Value::as_str)
            .and_then(|s| pybase64::b64decode(s).ok())
            .ok_or_else(corrupt)?;
        // Not wrapped in a try/except in Python: a too-short recovery
        // passphrase surfaces as `InvalidInput`, uncaught by this method.
        let key = derive_key(recovery_passphrase, &salt)?;
        let nonce = rec
            .get("nonce")
            .and_then(Value::as_str)
            .and_then(|s| pybase64::b64decode(s).ok())
            .ok_or_else(corrupt)?;
        let ciphertext = rec
            .get("ciphertext")
            .and_then(Value::as_str)
            .and_then(|s| pybase64::b64decode(s).ok())
            .ok_or_else(corrupt)?;
        let dek_bytes = aead::decrypt(key.expose(), &nonce, &ciphertext, b"zeropw-recovery")
            .map_err(|_| Error::auth_failed("recovery_passphrase_invalid"))?;
        {
            let _lock = state.lock()?;
            let mut doc2 = state.read_json(VAULT_DOC, Value::Null)?;
            let wrapped = new_kms.wrap(&dek_bytes)?;
            as_obj_mut(&mut doc2)?.insert("dek".into(), wrapped.to_dict());
            state.write_json(VAULT_DOC, &doc2)?;
        }
        Ok(Vault {
            state,
            kms: new_kms,
            dek: SecretBytes::new(dek_bytes),
            audit,
            projects,
        })
    }

    // helpers -------------------------------------------------------------
    fn doc(&self) -> Result<Value, Error> {
        let v = self.state.read_json(VAULT_DOC, Value::Null)?;
        if json_falsy(&v) {
            return Err(Error::state("vault_missing"));
        }
        Ok(v)
    }

    fn secrets_obj(doc: &Value) -> Result<&Map<String, Value>, Error> {
        doc.get("secrets")
            .and_then(Value::as_object)
            .ok_or_else(|| Error::state("state_corrupt").with_detail("vault"))
    }

    fn aad(secret_id: &str, version: i64) -> Vec<u8> {
        format!("zeropw-secret:{secret_id}:{version}").into_bytes()
    }

    fn encrypt(
        &self,
        secret_id: &str,
        version: i64,
        value: &[u8],
    ) -> Result<Map<String, Value>, Error> {
        let nonce = random_bytes(aead::NONCE_SIZE);
        let ciphertext = aead::encrypt(
            self.dek.expose(),
            &nonce,
            value,
            &Self::aad(secret_id, version),
        )
        .map_err(|e| Error::state("secret_encrypt_failed").with_detail(e.to_string()))?;
        let mut m = Map::new();
        m.insert("nonce".into(), json!(pybase64::b64encode(&nonce)));
        m.insert("ciphertext".into(), json!(pybase64::b64encode(&ciphertext)));
        Ok(m)
    }

    fn decrypt(
        &self,
        secret_id: &str,
        version: i64,
        entry: &Map<String, Value>,
    ) -> Result<SecretBytes, Error> {
        if entry.get("shared_env").is_some_and(|v| !json_falsy(v)) {
            return self.decrypt_shared(secret_id, entry);
        }
        let corrupt = || Error::state("secret_corrupt").with_detail(secret_id);
        let nonce = entry
            .get("nonce")
            .and_then(Value::as_str)
            .and_then(|s| pybase64::b64decode(s).ok())
            .ok_or_else(corrupt)?;
        let ciphertext = entry
            .get("ciphertext")
            .and_then(Value::as_str)
            .and_then(|s| pybase64::b64decode(s).ok())
            .ok_or_else(corrupt)?;
        aead::decrypt(
            self.dek.expose(),
            &nonce,
            &ciphertext,
            &Self::aad(secret_id, version),
        )
        .map(SecretBytes::new)
        .map_err(|_| corrupt())
    }

    /// Decrypt a team-sync shared-environment secret version (docs/team-sync.md
    /// sections 4.2, 6.5).
    ///
    /// Shared secrets are encrypted under the environment DEK generation
    /// that was active when the version was written, not the local vault
    /// DEK. The generation key was unwrapped once (`zeropw.team.fold`'s
    /// `_derive_dek_generations`, `team::fold::derive_local` here) and
    /// re-wrapped under this node's own KMS at
    /// `team/<env-id>/dek/<generation-id>.json`; it is looked up again here
    /// on every decrypt rather than cached. `entry` is passed straight
    /// through to `team::envelope::decrypt_secret` as the ciphertext
    /// record: that function only reads its own `nonce`/`ciphertext`
    /// fields, ignoring the rest (`status`, `generation`, `shared_env`,
    /// ...), exactly like Python's `envelope.decrypt_secret(key, env_id,
    /// secret_id, version_id, entry)` passing the same dict along
    /// unfiltered. Wired here (rather than left as unit H's own seam)
    /// because `team::envelope::decrypt_secret`'s signature is a drop-in
    /// match for this call site; no write path in this crate's scope
    /// (`Vault::put_secret`) ever creates a `shared_env` version --
    /// only `team::fold` does -- so this path is exercised by unit H's own
    /// tests, not `tests/test_core_vault.py`.
    fn decrypt_shared(
        &self,
        secret_id: &str,
        entry: &Map<String, Value>,
    ) -> Result<SecretBytes, Error> {
        // Python: `env_id = str(entry["shared_env"]); generation_id = str(entry["generation"]);
        // version_id = str(entry["version_id"])`, catching only `KeyError` (a missing key) as
        // `secret_corrupt` -- a *present* field of any other JSON type (e.g. the number `5`) is
        // coerced with `str(...)`, not rejected. `Value::as_str` required the field to already be
        // a JSON string (finding E-R2-4), rejecting a well-typed-but-non-string field Python
        // would happily stringify; `python_str_scalar` applies the same `str()` coercion.
        let corrupt = || Error::state("secret_corrupt").with_detail(secret_id);
        let env_id = python_str_scalar(entry.get("shared_env").ok_or_else(corrupt)?);
        let generation_id = python_str_scalar(entry.get("generation").ok_or_else(corrupt)?);
        let version_id = python_str_scalar(entry.get("version_id").ok_or_else(corrupt)?);
        let generation_key = self.generation_key(&env_id, &generation_id)?;
        crate::team::envelope::decrypt_secret(
            generation_key.expose(),
            &env_id,
            secret_id,
            &version_id,
            entry,
        )
        .map(SecretBytes::new)
        .map_err(|_| corrupt())
    }

    /// Port of `vault.py`'s `Vault._generation_key`.
    fn generation_key(&self, env_id: &str, generation_id: &str) -> Result<SecretBytes, Error> {
        let path = format!("team/{env_id}/dek/{generation_id}.json");
        let doc = self.state.read_json(&path, Value::Null)?;
        if json_falsy(&doc) {
            return Err(Error::state("team_dek_generation_missing"));
        }
        let wrapped = WrappedKey::from_dict(&doc)?;
        self.kms.unwrap(&wrapped)
    }

    /// Non-secret metadata derived from the value (public key for SSH keys).
    /// Port of `vault.Vault._public_metadata`, public here because
    /// `admin_cli.py` and the test suite call it directly on the class.
    ///
    /// `to_authorized_key`'s comment-contains-newline/NUL check raises a
    /// bare (untagged) `ValueError` in Python, outside the
    /// `except sshwire.WireError` that only wraps the parse call --
    /// `WireError::is_wire_error()` is `false` for it (`sshwire.rs`,
    /// `DEVIATIONS.md`). Per §3.5 this is folded into the same
    /// `ssh_private_key_invalid` `InvalidInput` `put_secret` already raises
    /// for an unparseable key, since that is the closest error a caller of
    /// `put_secret` (the only caller of this metadata step) already handles.
    pub fn public_metadata(kind: &str, value: &[u8]) -> Result<Value, Error> {
        if kind == "ssh_private_key" {
            let key = crate::sshwire::parse_openssh_private_key(value).map_err(|e| {
                Error::invalid_input("ssh_private_key_invalid").with_detail(e.class_name())
            })?;
            let public_key = key.public.to_authorized_key(&key.comment).map_err(|e| {
                Error::invalid_input("ssh_private_key_invalid").with_detail(e.class_name())
            })?;
            return Ok(json!({
                "public_key": public_key,
                "fingerprint": key.public.fingerprint(),
                "algorithm": "ssh-ed25519",
            }));
        }
        Ok(json!({}))
    }

    // writes --------------------------------------------------------------
    #[allow(clippy::too_many_arguments)]
    pub fn put_secret(
        &self,
        secret_id: &str,
        kind: &str,
        value: &[u8],
        project: &str,
        environment: &str,
        activate: bool,
    ) -> Result<i64, Error> {
        let secret_id = validate_name(secret_id, "secret_id")?;
        if !SECRET_KINDS.contains(&kind) {
            return Err(Error::invalid_input("invalid_secret_kind"));
        }
        if value.is_empty() || value.len() > MAX_SECRET_BYTES {
            return Err(Error::invalid_input("invalid_secret_value"));
        }
        self.projects.require_environment(project, environment)?;
        let public = Vault::public_metadata(kind, value)?;

        let version;
        let rebound;
        {
            let _lock = self.state.lock()?;
            let mut doc_val = self.doc()?;
            let doc_obj = as_obj_mut(&mut doc_val)?;
            let secrets_entry = doc_obj
                .entry("secrets".to_string())
                .or_insert_with(|| json!({}));
            let secrets_obj = as_obj_mut(secrets_entry)?;

            let mut entry: Map<String, Value> = match secrets_obj.get(&secret_id) {
                Some(existing) => {
                    let existing_obj = as_obj(existing)?;
                    let matches = existing_obj.get("project").and_then(Value::as_str)
                        == Some(project)
                        && existing_obj.get("environment").and_then(Value::as_str)
                            == Some(environment)
                        && existing_obj.get("kind").and_then(Value::as_str) == Some(kind);
                    if !matches {
                        return Err(Error::invalid_input("secret_identity_mismatch"));
                    }
                    existing_obj.clone()
                }
                None => {
                    let mut m = Map::new();
                    m.insert("project".into(), json!(project));
                    m.insert("environment".into(), json!(environment));
                    m.insert("kind".into(), json!(kind));
                    m.insert("created_at".into(), json!(iso(None)));
                    m.insert("active_version".into(), Value::Null);
                    m.insert("versions".into(), json!({}));
                    m
                }
            };

            let mut versions_obj = entry
                .get("versions")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let next_version = versions_obj
                .keys()
                .map(|k| parse_version_key(k))
                .collect::<Result<Vec<i64>, Error>>()?
                .into_iter()
                .max()
                .unwrap_or(0)
                + 1;
            let mut record = self.encrypt(&secret_id, next_version, value)?;
            record.insert("created_at".into(), json!(iso(None)));
            record.insert(
                "status".into(),
                json!(if activate { "active" } else { "staged" }),
            );
            record.insert("public".into(), public);
            versions_obj.insert(next_version.to_string(), Value::Object(record));

            if activate {
                let previous = entry.get("active_version").and_then(Value::as_i64);
                entry.insert("active_version".into(), json!(next_version));
                if let Some(prev) = previous {
                    let mut retire = false;
                    if let Some(prev_rec) = versions_obj
                        .get(&prev.to_string())
                        .and_then(Value::as_object)
                        && prev_rec.get("status").and_then(Value::as_str) == Some("active")
                    {
                        retire = true;
                    }
                    if retire {
                        let prev_rec = versions_obj
                            .get_mut(&prev.to_string())
                            .and_then(Value::as_object_mut)
                            .expect("checked above");
                        prev_rec.insert("status".into(), json!("retired"));
                    }
                }
            }
            entry.insert("versions".into(), Value::Object(versions_obj));
            secrets_obj.insert(secret_id.clone(), Value::Object(entry));

            self.state.write_json(VAULT_DOC, &doc_val)?;
            version = next_version;
            rebound = if activate {
                self.rebind_connections(&secret_id)?
            } else {
                Vec::new()
            };
        }
        self.audit.record(
            "secret_put",
            RecordArgs {
                result: Some("ok"),
                extra: vec![
                    ("secret_id", json!(secret_id)),
                    ("version", json!(version)),
                    ("kind", json!(kind)),
                    ("project", json!(project)),
                    ("environment", json!(environment)),
                ],
                ..Default::default()
            },
        )?;
        self.audit_rebound(&secret_id, &rebound)?;
        Ok(version)
    }

    fn rebind_connections(&self, secret_id: &str) -> Result<Vec<crate::policy::Connection>, Error> {
        let policy = crate::policy::Policy::new(self.state, crate::clock::system());
        policy.credential_versions_changed(secret_id)
    }

    fn audit_rebound(
        &self,
        secret_id: &str,
        connections: &[crate::policy::Connection],
    ) -> Result<(), Error> {
        for c in connections {
            self.audit.record(
                "connection_update",
                RecordArgs {
                    connection: Some(&c.id),
                    result: Some("ok"),
                    policy_version: Some(c.policy_version),
                    extra: vec![
                        ("detail", json!("credential_version")),
                        ("secret_id", json!(secret_id)),
                        ("state", json!("reevaluated")),
                    ],
                    ..Default::default()
                },
            )?;
        }
        Ok(())
    }

    pub fn set_version_status(
        &self,
        secret_id: &str,
        version: i64,
        status: &str,
    ) -> Result<(), Error> {
        if !VERSION_STATES.contains(&status) {
            return Err(Error::invalid_input("invalid_version_status"));
        }
        let rebound;
        {
            let _lock = self.state.lock()?;
            let mut doc_val = self.doc()?;
            let doc_obj = as_obj_mut(&mut doc_val)?;
            let secrets_obj = doc_obj
                .get_mut("secrets")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| Error::state("state_corrupt").with_detail("vault"))?;
            let Some(entry_val) = secrets_obj.get(secret_id).cloned() else {
                return Err(Error::not_found("secret_version_not_found"));
            };
            let mut entry = as_obj(&entry_val)?.clone();
            let mut versions = entry
                .get("versions")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let key = version.to_string();
            if !versions.contains_key(&key) {
                return Err(Error::not_found("secret_version_not_found"));
            }
            {
                let record = as_obj(versions.get(&key).expect("checked above"))?;
                if record.get("status").and_then(Value::as_str) == Some("revoked")
                    && status != "revoked"
                {
                    return Err(Error::invalid_input("version_revoked"));
                }
            }
            if status == "revoked" {
                let mut fields = Map::new();
                fields.insert("secret_id".into(), json!(secret_id));
                fields.insert("version".into(), json!(version));
                crate::policy::append_revocation(self.state, "secret_version", fields);
            }
            {
                let record = versions
                    .get_mut(&key)
                    .and_then(Value::as_object_mut)
                    .expect("checked above");
                record.insert("status".into(), json!(status));
            }
            let before_active = entry.get("active_version").and_then(Value::as_i64);
            if status == "active" {
                entry.insert("active_version".into(), json!(version));
                if let Some(prev) = before_active
                    && prev != version
                {
                    let mut retire = false;
                    if let Some(prev_rec) =
                        versions.get(&prev.to_string()).and_then(Value::as_object)
                        && prev_rec.get("status").and_then(Value::as_str) == Some("active")
                    {
                        retire = true;
                    }
                    if retire {
                        let prev_rec = versions
                            .get_mut(&prev.to_string())
                            .and_then(Value::as_object_mut)
                            .expect("checked above");
                        prev_rec.insert("status".into(), json!("retired"));
                    }
                }
            } else if before_active == Some(version) {
                entry.insert("active_version".into(), Value::Null);
            }
            entry.insert("versions".into(), Value::Object(versions));
            let after_active = entry.get("active_version").and_then(Value::as_i64);
            secrets_obj.insert(secret_id.to_string(), Value::Object(entry));
            self.state.write_json(VAULT_DOC, &doc_val)?;
            rebound = if after_active != before_active {
                self.rebind_connections(secret_id)?
            } else {
                Vec::new()
            };
        }
        let event = match status {
            "retired" => "secret_retire",
            "revoked" => "secret_revoke",
            _ => "rotation",
        };
        self.audit.record(
            event,
            RecordArgs {
                result: Some("ok"),
                extra: vec![
                    ("secret_id", json!(secret_id)),
                    ("version", json!(version)),
                    ("state", json!(status)),
                ],
                ..Default::default()
            },
        )?;
        self.audit_rebound(secret_id, &rebound)?;
        Ok(())
    }

    // reads ---------------------------------------------------------------
    pub fn list_secrets(
        &self,
        project: Option<&str>,
        environment: Option<&str>,
    ) -> Result<Vec<SecretMeta>, Error> {
        let project = project.filter(|s| !s.is_empty());
        let environment = environment.filter(|s| !s.is_empty());
        let doc = self.doc()?;
        let secrets_obj = Vault::secrets_obj(&doc)?;
        let mut ids: Vec<String> = secrets_obj.keys().cloned().collect();
        ids.sort();
        let mut result = Vec::new();
        for secret_id in ids {
            let entry = as_obj(secrets_obj.get(&secret_id).expect("from keys"))?;
            let p = entry.get("project").and_then(Value::as_str).unwrap_or("");
            let e = entry
                .get("environment")
                .and_then(Value::as_str)
                .unwrap_or("");
            if let Some(pf) = project
                && pf != p
            {
                continue;
            }
            if let Some(ef) = environment
                && ef != e
            {
                continue;
            }
            let versions_obj = entry
                .get("versions")
                .and_then(Value::as_object)
                .ok_or_else(|| Error::state("state_corrupt").with_detail("vault"))?;
            let mut vkeys: Vec<(i64, &String)> = versions_obj
                .keys()
                .map(|k| parse_version_key(k).map(|n| (n, k)))
                .collect::<Result<Vec<_>, Error>>()?;
            vkeys.sort_by_key(|(n, _)| *n);
            let mut versions = Vec::new();
            for (n, k) in vkeys {
                let r = as_obj(versions_obj.get(k).expect("from keys"))?;
                versions.push(VersionMeta {
                    secret_id: secret_id.clone(),
                    version: n,
                    status: r
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    created_at: r
                        .get("created_at")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    public: r
                        .get("public")
                        .cloned()
                        .filter(|v| !json_falsy(v))
                        .unwrap_or_else(|| json!({})),
                });
            }
            result.push(SecretMeta {
                id: secret_id.clone(),
                project: p.to_string(),
                environment: e.to_string(),
                kind: entry
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                active_version: entry.get("active_version").and_then(Value::as_i64),
                versions,
            });
        }
        Ok(result)
    }

    pub fn get_meta(&self, secret_id: &str) -> Result<SecretMeta, Error> {
        self.list_secrets(None, None)?
            .into_iter()
            .find(|m| m.id == secret_id)
            .ok_or_else(|| Error::not_found("secret_not_found"))
    }

    pub fn resolve_version(&self, secret_id: &str, version: Option<i64>) -> Result<i64, Error> {
        let meta = self.get_meta(secret_id)?;
        match version {
            None => meta
                .active_version
                .ok_or_else(|| Error::not_found("secret_no_active_version")),
            Some(v) => {
                if meta.versions.iter().any(|item| item.version == v) {
                    Ok(v)
                } else {
                    Err(Error::not_found("secret_version_not_found"))
                }
            }
        }
    }

    /// Plaintext for in-process trusted components. Never exposed to agents.
    pub fn secret_for_trusted_use(
        &self,
        secret_id: &str,
        version: Option<i64>,
    ) -> Result<SecretBytes, Error> {
        let doc = self.doc()?;
        let secrets_obj = Vault::secrets_obj(&doc)?;
        // Python: `entry = self._doc()["secrets"].get(secret_id); if entry is None: raise
        // NotFound(...)`. `dict.get` returns `None` both when the key is absent *and* when it
        // maps to a JSON `null`, so a `"secrets": {"ghost": null}` entry must be treated as
        // absent here too -- `contains_key` alone (finding E-R2-4) is `true` for the null case,
        // which used to fall through into the version-record lookups below and surface as
        // `state_corrupt` instead of the documented `NotFound("secret_not_found")`.
        let present = secrets_obj
            .get(secret_id)
            .is_some_and(|entry| !entry.is_null());
        if !present {
            return Err(Error::not_found("secret_not_found"));
        }
        let resolved = self.resolve_version(secret_id, version)?;
        let entry = as_obj(secrets_obj.get(secret_id).expect("checked above"))?;
        let versions_obj = entry
            .get("versions")
            .and_then(Value::as_object)
            .ok_or_else(|| Error::state("state_corrupt").with_detail("vault"))?;
        let record = as_obj(
            versions_obj
                .get(&resolved.to_string())
                .ok_or_else(|| Error::state("state_corrupt").with_detail("vault"))?,
        )?;
        let status = record.get("status").and_then(Value::as_str).unwrap_or("");
        if status != "active" && status != "staged" {
            return Err(Error::not_found("secret_version_unusable").with_detail(status));
        }
        self.decrypt(secret_id, resolved, record)
    }

    /// Plaintext of every version of every secret (any status), for
    /// in-process leak comparisons only. Never returned to a caller outside
    /// the trusted process.
    pub fn values_for_trusted_scan(&self) -> Result<Vec<SecretBytes>, Error> {
        let doc = self.doc()?;
        let secrets_obj = Vault::secrets_obj(&doc)?;
        let mut ids: Vec<String> = secrets_obj.keys().cloned().collect();
        ids.sort();
        let mut values = Vec::new();
        for secret_id in ids {
            let entry = as_obj(secrets_obj.get(&secret_id).expect("from keys"))?;
            let versions_obj = entry
                .get("versions")
                .and_then(Value::as_object)
                .ok_or_else(|| Error::state("state_corrupt").with_detail("vault"))?;
            let mut vkeys: Vec<(i64, &String)> = versions_obj
                .keys()
                .map(|k| parse_version_key(k).map(|n| (n, k)))
                .collect::<Result<Vec<_>, Error>>()?;
            vkeys.sort_by_key(|(n, _)| *n);
            for (n, k) in vkeys {
                let record = as_obj(versions_obj.get(k).expect("from keys"))?;
                values.push(self.decrypt(&secret_id, n, record)?);
            }
        }
        Ok(values)
    }

    /// Administrator single-secret read: fresh re-auth + audit first, then
    /// decrypt.
    pub fn reveal(
        &self,
        secret_id: &str,
        version: Option<i64>,
        admin: &AdminAuth,
        now: Option<f64>,
    ) -> Result<SecretBytes, Error> {
        if !admin.fresh(now) {
            self.audit.record(
                "secret_reveal_denied",
                RecordArgs {
                    result: Some("denied"),
                    reason: Some("admin_reauth_stale"),
                    extra: vec![("secret_id", json!(secret_id))],
                    ..Default::default()
                },
            )?;
            return Err(Error::auth_failed("admin_reauth_stale"));
        }
        let resolved = self.resolve_version(secret_id, version)?;
        self.audit.record(
            "secret_reveal",
            RecordArgs {
                result: Some("ok"),
                extra: vec![
                    ("secret_id", json!(secret_id)),
                    ("version", json!(resolved)),
                ],
                ..Default::default()
            },
        )?;
        let doc = self.doc()?;
        let secrets_obj = Vault::secrets_obj(&doc)?;
        let entry = as_obj(
            secrets_obj
                .get(secret_id)
                .ok_or_else(|| Error::state("state_corrupt").with_detail("vault"))?,
        )?;
        let versions_obj = entry
            .get("versions")
            .and_then(Value::as_object)
            .ok_or_else(|| Error::state("state_corrupt").with_detail("vault"))?;
        let record = as_obj(
            versions_obj
                .get(&resolved.to_string())
                .ok_or_else(|| Error::state("state_corrupt").with_detail("vault"))?,
        )?;
        self.decrypt(secret_id, resolved, record)
    }

    // backup / restore ------------------------------------------------------
    pub const BACKUP_DOCS: &'static [&'static str] = &[
        VAULT_DOC,
        crate::projects::DOC,
        crate::policy::PRINCIPALS,
        crate::policy::CONNECTIONS,
        crate::policy::GRANTS,
        crate::policy::CONTROL,
    ];

    /// Encrypted backup: ciphertexts plus the KMS- and recovery-wrapped DEK.
    /// The archive contains no plaintext.
    pub fn backup(&self, out_path: &Path) -> Result<Value, Error> {
        let mut documents = Map::new();
        {
            let _lock = self.state.lock()?;
            for name in Vault::BACKUP_DOCS {
                documents.insert(
                    (*name).to_string(),
                    self.state.read_json(name, Value::Null)?,
                );
            }
        }
        let payload = pyjson::dumps(
            &Value::Object(documents.clone()),
            DumpOptions::compact_sorted(),
        )?;
        let digest = hex::encode(sha256(payload.as_bytes()));
        let backup_id = hex::encode(random_bytes(8));
        let manifest = json!({
            "format": "zeropw-backup-v1",
            "created_at": iso(None),
            "sha256": digest,
            "kms_key_id": self.kms.key_id(),
            "backup_id": backup_id,
        });
        let archive = json!({"manifest": manifest, "documents": Value::Object(documents)});
        let text = pyjson::dumps(&archive, DumpOptions::default_sorted())?;
        write_backup_atomic(out_path, &text)?;
        self.audit.record(
            "backup",
            RecordArgs {
                result: Some("ok"),
                extra: vec![
                    ("backup_id", manifest["backup_id"].clone()),
                    ("digest", json!(digest)),
                ],
                ..Default::default()
            },
        )?;
        Ok(manifest)
    }

    /// Re-apply every known revocation to the current state (idempotent).
    /// Port of the `@staticmethod Vault.reapply_revocations`.
    pub fn reapply_revocations(state: &StateDir) -> Result<HashMap<&'static str, usize>, Error> {
        let lines = state.read_lines(crate::audit::AUDIT_FILE, None)?;
        let mut records: Vec<Value> = Vec::new();
        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(v) = pyjson::loads(&line) {
                records.push(v);
            }
        }
        let revocations = crate::policy::collect_revocations(state, records.iter());
        let _lock = state.lock()?;
        let policy = crate::policy::Policy::new(state, crate::clock::system());
        let mut counts = policy.reapply_revocations(&revocations)?;
        let mut changed = 0usize;
        if let Value::Object(mut doc_obj) = state.read_json(VAULT_DOC, Value::Null)? {
            let mut secret_versions: Vec<(String, i64)> =
                revocations.secret_versions.iter().cloned().collect();
            secret_versions.sort();
            let mut touched = false;
            if let Some(Value::Object(secrets_obj)) = doc_obj.get_mut("secrets") {
                for (secret_id, version) in &secret_versions {
                    let Some(entry) = secrets_obj
                        .get_mut(secret_id)
                        .and_then(Value::as_object_mut)
                    else {
                        continue;
                    };
                    let mut was_revoked = false;
                    if let Some(versions_obj) =
                        entry.get_mut("versions").and_then(Value::as_object_mut)
                        && let Some(record) = versions_obj
                            .get_mut(&version.to_string())
                            .and_then(Value::as_object_mut)
                        && record.get("status").and_then(Value::as_str) != Some("revoked")
                    {
                        record.insert("status".into(), json!("revoked"));
                        was_revoked = true;
                    }
                    if was_revoked {
                        touched = true;
                        changed += 1;
                        if entry.get("active_version").and_then(Value::as_i64) == Some(*version) {
                            entry.insert("active_version".into(), Value::Null);
                        }
                    }
                }
            }
            if touched {
                state.write_json(VAULT_DOC, &Value::Object(doc_obj))?;
            }
        }
        counts.insert("secret_versions", changed);
        Ok(counts)
    }

    /// Approvals after a restore: the current entries win; the archive never
    /// reopens one.
    fn merge_restored_approvals(current: &Value, archived: &Value) -> (Map<String, Value>, usize) {
        let mut merged: Map<String, Value> = match current {
            Value::Object(m) => m.clone(),
            _ => Map::new(),
        };
        let mut dropped = 0usize;
        if let Value::Object(archived_obj) = archived {
            for (digest, entry) in archived_obj {
                if merged.contains_key(digest) {
                    continue;
                }
                let Some(entry_obj) = entry.as_object() else {
                    continue;
                };
                let status = entry_obj
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if status == "pending" || status == "approved" {
                    dropped += 1;
                    continue;
                }
                merged.insert(digest.clone(), entry.clone());
            }
        }
        (merged, dropped)
    }

    /// Restore documents and leave the system closed until `restore_ack`.
    /// Port of the `@staticmethod Vault.restore`.
    pub fn restore(
        state: &StateDir,
        in_path: &Path,
        audit: &Audit,
        kms: Option<&(dyn Kms + Send + Sync)>,
    ) -> Result<Value, Error> {
        let malformed = || Error::state("backup_malformed");
        let text = fs::read_to_string(in_path).map_err(|_| malformed())?;
        let archive: Value = pyjson::loads(&text).map_err(|_| malformed())?;
        let manifest = archive.get("manifest").cloned().ok_or_else(malformed)?;
        let documents = archive.get("documents").cloned().ok_or_else(malformed)?;
        if !manifest.is_object() || !documents.is_object() {
            return Err(malformed());
        }
        if manifest.get("format").and_then(Value::as_str) != Some("zeropw-backup-v1") {
            return Err(Error::state("backup_format"));
        }
        let payload = pyjson::dumps(&documents, DumpOptions::compact_sorted())?;
        let digest = hex::encode(sha256(payload.as_bytes()));
        let manifest_digest = python_str_scalar(get_or_null(
            manifest.as_object().expect("checked"),
            "sha256",
        ));
        if !constant_time_eq(digest.as_bytes(), manifest_digest.as_bytes()) {
            return Err(Error::state("backup_digest_mismatch"));
        }
        let backup_id = python_str_scalar(get_or_null(
            manifest.as_object().expect("checked"),
            "backup_id",
        ));
        let documents_obj = documents.as_object().expect("checked is_object");
        // Python's `documents.get(VAULT_DOC)` treats an explicit JSON `null`
        // the same as a missing key (`json.loads` maps both to `None`), so
        // an archive with `"vault/secrets.json": null` skips the KMS
        // pre-check just like one that omits the key entirely (finding E-4).
        let vault_doc = documents_obj.get(VAULT_DOC).filter(|v| !v.is_null());
        if let (Some(kms), Some(vault_doc)) = (kms, vault_doc) {
            let dek_val = vault_doc.as_object().and_then(|o| o.get("dek"));
            let wrapped = match dek_val {
                Some(d) if d.is_object() => {
                    Some(WrappedKey::from_dict(d).map_err(|_| malformed())?)
                }
                _ => None,
            };
            let Some(wrapped) = wrapped else {
                return Err(malformed());
            };
            if kms.unwrap(&wrapped).is_err() {
                audit.record(
                    "restore",
                    RecordArgs {
                        result: Some("denied"),
                        reason: Some("backup_kms_mismatch"),
                        extra: vec![("backup_id", json!(backup_id))],
                        ..Default::default()
                    },
                )?;
                return Err(Error::state("backup_kms_mismatch"));
            }
        }

        let control_doc = crate::policy::CONTROL;
        let reapplied_sum;
        {
            let _lock = state.lock()?;
            let current_val = state.read_json(control_doc, Value::Null)?;
            let current = match &current_val {
                Value::Object(m) if !m.is_empty() => m.clone(),
                _ => Map::new(),
            };
            let mut first_write = current.clone();
            first_write.insert("restore_pending".into(), json!(true));
            state.write_json(control_doc, &Value::Object(first_write))?;

            for name in Vault::BACKUP_DOCS {
                if *name == control_doc {
                    continue;
                }
                if let Some(v) = documents_obj.get(*name)
                    && !v.is_null()
                {
                    state.write_json(name, v)?;
                }
            }
            let archived_control = documents_obj.get(control_doc);
            let mut control = match archived_control {
                Some(Value::Object(m)) => m.clone(),
                _ => Map::new(),
            };
            let current_stopped = current.get("stopped").is_some_and(|v| !json_falsy(v));
            if current_stopped {
                control.insert("stopped".into(), json!(true));
                control.insert(
                    "stopped_at".into(),
                    get_or_null(&current, "stopped_at").clone(),
                );
            }
            let (merged_approvals, dropped) = Vault::merge_restored_approvals(
                get_or_null(&current, "approvals"),
                get_or_null(&control, "approvals"),
            );
            control.insert("approvals".into(), Value::Object(merged_approvals));
            let approval_history = match current.get("approval_history") {
                Some(Value::Array(a)) => a.clone(),
                _ => Vec::new(),
            };
            control.insert("approval_history".into(), Value::Array(approval_history));
            control.insert("restore_pending".into(), json!(true));
            control.insert(
                "restored_from".into(),
                manifest.get("backup_id").cloned().unwrap_or(Value::Null),
            );
            control.insert("restored_at".into(), json!(iso(None)));
            state.write_json(control_doc, &Value::Object(control))?;

            let mut reapplied = Vault::reapply_revocations(state)?;
            let mut reapplied_obj: Map<String, Value> = reapplied
                .drain()
                .map(|(k, v)| (k.to_string(), json!(v)))
                .collect();
            reapplied_obj.insert("approvals_dropped".into(), json!(dropped));
            reapplied_sum = reapplied_obj
                .values()
                .filter_map(Value::as_u64)
                .sum::<u64>();
            let mut control2 = match state.read_json(control_doc, Value::Null)? {
                Value::Object(m) if !m.is_empty() => m,
                _ => Map::new(),
            };
            control2.insert("restore_reapplied".into(), Value::Object(reapplied_obj));
            state.write_json(control_doc, &Value::Object(control2))?;
            state.write_bytes(
                crate::context::HANDLE_KEY,
                crate::handles::HandleIssuer::generate_key().expose(),
            )?;
        }
        audit.record(
            "restore",
            RecordArgs {
                result: Some("ok"),
                extra: vec![
                    ("backup_id", json!(backup_id)),
                    ("state", json!("restore_pending")),
                    ("count", json!(reapplied_sum)),
                ],
                ..Default::default()
            },
        )?;
        Ok(manifest)
    }
}

/// Writes `contents` to `out_path` atomically: a fresh, randomly-named,
/// `O_CREAT|O_EXCL` 0600 temp file in `out_path`'s parent directory,
/// `fsync`ed, then renamed into place. Port of `vault.py`'s `Vault.backup`
/// temp-file dance (`tempfile.mkstemp(prefix=..., suffix=".tmp", dir=...)`);
/// implemented by hand (not the `tempfile` crate, a dev-only dependency of
/// this workspace) since `out_path` is caller-chosen and not necessarily
/// inside any `StateDir`, so `StateDir::write_json`/`write_bytes` (which use
/// a PID+thread-based name and a different JSON format) do not apply here.
///
/// Python's failure path here (`except BaseException: os.unlink(tmp); raise`)
/// re-raises the *original*, uncaught `OSError` -- per §3.5, the closest
/// handled error is `StateError`.
fn write_backup_atomic(out_path: &Path, contents: &str) -> Result<(), Error> {
    use std::fs::OpenOptions;
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    let parent = out_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = out_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("backup");
    let mut tmp_path = parent.join(format!(".{file_name}.tmp"));
    for _ in 0..64 {
        let suffix = hex::encode(random_bytes(8));
        tmp_path = parent.join(format!(".{file_name}.{suffix}.tmp"));
        if !tmp_path.exists() {
            break;
        }
    }
    let result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        file.write_all(contents.as_bytes())?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp_path, out_path)?;
        Ok(())
    })();
    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            Err(Error::state("backup_write_failed").with_detail(e.to_string()))
        }
    }
}
