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

use std::fs;
use std::path::Path;

use serde::{Serialize, Serializer};
use serde_json::{Map, Value, json};

use crate::audit::{Audit, RecordArgs};
use crate::crypto::chacha20poly1305 as aead;
use crate::errors::Error;
use crate::kms::{Kms, WrappedKey};
use crate::projects::{Projects, validate_name};
use crate::pybase64;
use crate::pyint::PyInt;
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

/// `type(exc).__name__` of the built-in exceptions `vault.py` lets escape on a
/// malformed stored document. `binascii.Error` reports itself as `Error`.
const KEY_ERROR: &str = "KeyError";
const TYPE_ERROR: &str = "TypeError";
const VALUE_ERROR: &str = "ValueError";
const ATTRIBUTE_ERROR: &str = "AttributeError";
const BINASCII_ERROR: &str = "Error";

/// A built-in exception `vault.py` lets escape (PORTING.md §3.5): the closest
/// error a `Vault` caller already handles, `StateError("state_corrupt")`,
/// carrying the Python exception class name. The administrator CLI catches
/// exactly these classes and prints `state_corrupt` with that name, so the
/// native CLI output is identical.
fn escaped(class: &'static str) -> Error {
    Error::state("state_corrupt").with_detail(class)
}

/// `container[key]` on a decoded JSON value: a dict lookup (a missing key is
/// `KeyError`); every other JSON shape rejects a `str` subscript (`TypeError`).
fn index<'v>(container: &'v Value, key: &str) -> Result<&'v Value, Error> {
    match container {
        Value::Object(map) => map.get(key).ok_or_else(|| escaped(KEY_ERROR)),
        _ => Err(escaped(TYPE_ERROR)),
    }
}

/// Mutable [`index`].
fn index_mut<'v>(container: &'v mut Value, key: &str) -> Result<&'v mut Value, Error> {
    match container {
        Value::Object(map) => map.get_mut(key).ok_or_else(|| escaped(KEY_ERROR)),
        _ => Err(escaped(TYPE_ERROR)),
    }
}

/// The receiver of `.get(...)`/`.items()`: only a dict has those methods, every
/// other JSON shape raises `AttributeError`.
fn dict_methods(value: &Value) -> Result<&Map<String, Value>, Error> {
    value.as_object().ok_or_else(|| escaped(ATTRIBUTE_ERROR))
}

/// Mutable [`dict_methods`].
fn dict_methods_mut(value: &mut Value) -> Result<&mut Map<String, Value>, Error> {
    value
        .as_object_mut()
        .ok_or_else(|| escaped(ATTRIBUTE_ERROR))
}

/// `base64.b64decode(value)` (`vault._b64d`) on a stored JSON value: a
/// non-`str` raises `TypeError`, a non-ASCII `str` `ValueError`, and malformed
/// base64 `binascii.Error`. Returns the class name on failure.
fn b64d_value(value: &Value) -> Result<Vec<u8>, &'static str> {
    let Value::String(text) = value else {
        return Err(TYPE_ERROR);
    };
    if !text.is_ascii() {
        return Err(VALUE_ERROR);
    }
    pybase64::b64decode(text).map_err(|_| BINASCII_ERROR)
}

/// `entry["active_version"]`: a missing key is corrupt, JSON `null` is no
/// active version, and every other JSON value is preserved exactly. Python's
/// dataclass annotation is not enforced at runtime; later consumers apply
/// numeric equality or `str(version)` according to their own operation.
fn require_active_version(m: &Map<String, Value>) -> Result<Option<ResolvedVersion>, Error> {
    match m.get("active_version") {
        None => Err(escaped(KEY_ERROR)),
        Some(Value::Null) => Ok(None),
        Some(v) => Ok(Some(
            PyInt::from_json_integer(v)
                .map(ResolvedVersion::Integer)
                .unwrap_or_else(|| ResolvedVersion::Raw(v.clone())),
        )),
    }
}

/// `entry["active_version"]` (or the [`PyInt`] version it's compared against)
/// reduced to Python's own numeric identity: `Int` for anything CPython
/// treats as an exact integer (a `bool`, or an integer-*shaped* JSON
/// literal -- no `.`/`e`/`E`, per [`crate::pyjson::is_float_literal`],
/// PORTING.md §3b), `Float` for a genuinely float-shaped literal.
///
/// X-16 (equivalence review, round 8): [`active_version_numeric`] used to
/// return `Option<f64>` unconditionally (`bool` as `0.0`/`1.0`, a JSON
/// number via `Number::as_f64()`), and [`active_version_values_equal`]
/// compared both sides as `f64`. CPython's `int.__eq__`/`__eq__` between an
/// `int` and another `int` (or a `bool`, itself an `int` subclass) is
/// *exact* -- it never routes through `float` at all -- so two distinct
/// integers that happen to collide once rounded to the nearest `f64` (the
/// classic case: `9007199254740993 == 9007199254740992` is `False` in
/// CPython, `True` once both are cast to `f64`) took the wrong branch here.
/// Measured directly on a doctored `vault/secrets.json`:
/// `set_version_status(2**53, "retired")` **cleared** `active_version` from
/// `9007199254740993` to `null` (Python leaves it: `entry["active_version"]
/// == version` is `False`, so the retire-match branch is never taken); and
/// `set_version_status(2**53, "active")` returned `Ok` while **skipping**
/// the retire step for the previously-active version, leaving it wrongly
/// still `"active"` (Python's `previous != version` reads as `True`, takes
/// the branch, and then raises `KeyError` on the version-status lookup,
/// committing nothing at all -- a fail-open in the exact opposite direction
/// this code silently produced). This collision is not confined to `2**53`:
/// `2**63` vs. `i64::MAX` collide the same way in `f64`, and `i64::MAX` is
/// exactly the `active_version` this crate's own `put_secret` writes when
/// the largest existing key is `i64::MAX` (a real, reachable value, not a
/// hypothetical one).
enum ActiveVersionNumeric {
    Int(PyInt),
    Float(f64),
}

/// Python `==` between two JSON-decoded values, restricted to the shapes
/// `entry["active_version"]` can hold (`null`, a `bool`, a number, or --
/// after finding E-R6-3's fix below -- any other JSON shape too): `null` is
/// equal only to `null`; when at least one side is a `bool`/number, CPython
/// compares
/// numerically (`bool` as 0/1, an integral `float` as its integer) rather
/// than by JSON shape -- `True == 1`, `1.0 == 1`; a string, array or object
/// paired with a `bool`/number is never numerically equal to it and compares
/// unequal without raising (finding E-R5-4). Used everywhere
/// `set_version_status`/`reapply_revocations` compare a stored
/// `active_version` against a version number (`active_version_matches`) or
/// against each other (the `entry["active_version"] != before_active` rebind
/// trigger).
fn active_version_numeric(v: &Value) -> Option<ActiveVersionNumeric> {
    match v {
        Value::Bool(b) => Some(ActiveVersionNumeric::Int(PyInt::from(i64::from(*b)))),
        Value::Number(n) => {
            let raw = n.as_str();
            if crate::pyjson::is_float_literal(raw) {
                n.as_f64().map(ActiveVersionNumeric::Float)
            } else {
                PyInt::from_json_integer(v).map(ActiveVersionNumeric::Int)
            }
        }
        _ => None,
    }
}

/// Exact `int == float` (or `float == int`) the way CPython actually
/// computes it. [`cmp_bigint_f64`] compares the arbitrary-precision integer
/// directly with the finite binary64 value, including integral floats beyond
/// `i128`; non-integral and non-finite floats compare unequal, matching
/// CPython without a lossy float-only conversion.
fn int_equals_float(i: &PyInt, f: f64) -> bool {
    crate::pyint::cmp_bigint_f64(&i.0, f) == Some(std::cmp::Ordering::Equal)
}

/// See [`active_version_numeric`]'s doc comment. When *neither* side is
/// numerically comparable (both non-numeric, or a mix `active_version_numeric`
/// can't reconcile), Python's `==` does not raise and does not simply
/// return `false` either -- it falls through to ordinary structural
/// equality, which two equal non-numeric values (`"abc" == "abc"`, `[1] ==
/// [1]`) satisfy (finding E-R6-3, correcting this function's own previous
/// unconditional `_ => false` fallback arm, which made Rust call no rebind
/// where Python's `==` said the two values were equal). A mismatched
/// non-numeric shape (a string vs. an array, or a number vs. a string)
/// still compares unequal via the same structural check, matching Python's
/// `==` there too (never `true`, never raises).
fn active_version_values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Null, _) | (_, Value::Null) => false,
        _ => match (active_version_numeric(a), active_version_numeric(b)) {
            (Some(ActiveVersionNumeric::Int(x)), Some(ActiveVersionNumeric::Int(y))) => x == y,
            (Some(ActiveVersionNumeric::Float(x)), Some(ActiveVersionNumeric::Float(y))) => x == y,
            (Some(ActiveVersionNumeric::Int(i)), Some(ActiveVersionNumeric::Float(f)))
            | (Some(ActiveVersionNumeric::Float(f)), Some(ActiveVersionNumeric::Int(i))) => {
                int_equals_float(&i, f)
            }
            _ => match (a, b) {
                // `list.__eq__`/`dict.__eq__`: element-wise Python `==`, so numeric
                // cross-type equality applies inside containers too (`[1] == [1.0]`).
                (Value::Array(x), Value::Array(y)) => {
                    x.len() == y.len()
                        && x.iter()
                            .zip(y)
                            .all(|(p, q)| active_version_values_equal(p, q))
                }
                (Value::Object(x), Value::Object(y)) => {
                    x.len() == y.len()
                        && x.iter().all(|(k, v)| {
                            y.get(k).is_some_and(|w| active_version_values_equal(v, w))
                        })
                }
                _ => a == b,
            },
        },
    }
}

/// Python `==` between two JSON-decoded values of any shape (see
/// [`active_version_values_equal`]).
pub(crate) fn python_eq(a: &Value, b: &Value) -> bool {
    active_version_values_equal(a, b)
}

/// `value == version` (Python numeric equality, see
/// [`active_version_values_equal`]) for a stored `active_version` compared
/// against a plain [`PyInt`] version, e.g. `set_version_status`'s
/// `previous != version`/`entry["active_version"] == version` and
/// `reapply_revocations`'s `entry.get("active_version") == version`
/// (finding E-R5-4).
fn active_version_matches(value: &Value, version: &PyInt) -> bool {
    active_version_values_equal(value, &version.value())
}

/// `dict.get(key)`: the stored value, or `None` (JSON `null`) when absent.
fn get_or_null<'v>(m: &'v Map<String, Value>, key: &str) -> &'v Value {
    m.get(key).unwrap_or(&Value::Null)
}

/// A Python `dict` built by `dict(r.get("public") or {})` for
/// [`VersionMeta::public`]. Its keys may be any hashable JSON scalar, not only
/// strings: `dict([[1, "a"], [True, "b"], [None, "c"], ["1", "d"]])` is
/// `{1: 'b', None: 'c', '1': 'd'}`. Entries keep Python's insertion order and
/// its key identity rules: `==`-equal keys (`1`, `1.0`, `True`) are one key that
/// keeps its first position and spelling and takes the last value, while a
/// string key never equals a non-string one. [`PublicMetadata::get`] is the
/// `str`-keyed lookup every product consumer performs.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PublicMetadata {
    entries: Vec<(Value, Value)>,
}

impl PublicMetadata {
    /// `public.get(key)` for a `str` key.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries
            .iter()
            .find(|(candidate, _)| candidate.as_str() == Some(key))
            .map(|(_, value)| value)
    }

    /// `key in public` for a `str` key.
    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Every `(key, value)` pair in Python's iteration order. A key is a JSON
    /// string, number, boolean or `null`.
    pub fn entries(&self) -> &[(Value, Value)] {
        &self.entries
    }

    /// `len(public) == 0`.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// `d[key] = value` with Python's hashable-key equality.
    fn insert(&mut self, key: Value, value: Value) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|(existing, _)| python_key_equal(existing, &key))
        {
            entry.1 = value;
        } else {
            self.entries.push((key, value));
        }
    }
}

/// `public[key]`: the stored value, or `null` for an absent `str` key (the
/// same convenience `serde_json::Value` indexing offers).
impl std::ops::Index<&str> for PublicMetadata {
    type Output = Value;

    fn index(&self, key: &str) -> &Value {
        self.get(key).unwrap_or(&Value::Null)
    }
}

/// Equal to a JSON object exactly when every key is a string and the
/// key/value sets agree (a JSON object cannot hold a non-string key).
impl PartialEq<Value> for PublicMetadata {
    fn eq(&self, other: &Value) -> bool {
        let Value::Object(map) = other else {
            return false;
        };
        map.len() == self.entries.len()
            && self
                .entries
                .iter()
                .all(|(key, value)| key.as_str().is_some_and(|key| map.get(key) == Some(value)))
    }
}

/// Python `==` between two hashable dict keys decoded from JSON (`None`,
/// `bool`, `int`, `float`, `str`): numeric types compare by exact value
/// across `bool`/`int`/`float`, a `str` equals only an equal `str`.
fn python_key_equal(a: &Value, b: &Value) -> bool {
    active_version_values_equal(a, b)
}

/// `dict(r.get("public") or {})`: Python's `or` first replaces any *falsy*
/// value (`None`/missing, `false`, `0`, `""`, `[]`, `{}`) with `{}`, then
/// `dict(...)` copies a mapping or consumes an iterable of pairs (finding
/// E-R4-3). A pair element may itself be any two-item JSON iterable: an array,
/// a two-character string, or a two-key object (whose iteration yields its
/// keys). The pair's key may be any hashable JSON value (see
/// [`PublicMetadata`]). Python's failures escape uncaught (PORTING.md §3.5)
/// with their own class: a non-iterable value or element, or an unhashable
/// (array/object) key, is `TypeError`; an element of the wrong length is
/// `ValueError` -- including every character of a non-empty string value.
pub(crate) fn coerce_public_field(v: Option<&Value>) -> Result<PublicMetadata, Error> {
    let mut result = PublicMetadata::default();
    match v {
        None => Ok(result),
        Some(val) if json_falsy(val) => Ok(result),
        Some(Value::Object(m)) => {
            for (key, value) in m {
                result.insert(Value::String(key.clone()), value.clone());
            }
            Ok(result)
        }
        Some(Value::Array(items)) => {
            for item in items {
                let (key, value) = match item {
                    Value::Array(pair) => match pair.as_slice() {
                        [key, value] => (key.clone(), value.clone()),
                        _ => return Err(escaped(VALUE_ERROR)),
                    },
                    Value::String(pair) => {
                        let mut chars = pair.chars();
                        match (chars.next(), chars.next(), chars.next()) {
                            (Some(key), Some(value), None) => (
                                Value::String(key.to_string()),
                                Value::String(value.to_string()),
                            ),
                            _ => return Err(escaped(VALUE_ERROR)),
                        }
                    }
                    Value::Object(pair) => {
                        let mut keys = pair.keys();
                        match (keys.next(), keys.next(), keys.next()) {
                            (Some(key), Some(value), None) => {
                                (Value::String(key.clone()), Value::String(value.clone()))
                            }
                            _ => return Err(escaped(VALUE_ERROR)),
                        }
                    }
                    _ => return Err(escaped(TYPE_ERROR)),
                };
                if matches!(key, Value::Array(_) | Value::Object(_)) {
                    return Err(escaped(TYPE_ERROR));
                }
                result.insert(key, value);
            }
            Ok(result)
        }
        Some(Value::String(_)) => Err(escaped(VALUE_ERROR)),
        Some(_) => Err(escaped(TYPE_ERROR)),
    }
}

/// `list(current.get("approval_history") or [])` (`Vault.restore`, finding
/// E-R5-9). Python's `or` first replaces a *falsy* `approval_history`
/// (missing/`null`, `false`, `0`/`0.0`, `""`, `[]`, `{}`) with `[]`, then
/// `list(...)` iterates whatever remains: a `list` is shallow-copied
/// unchanged, a non-empty `str` yields its individual Unicode characters
/// (`list("ab") == ["a", "b"]`), and a non-empty `dict` yields its *keys*
/// (`list({"x": 1}) == ["x"]`, insertion order -- matching Python's own
/// `dict` iteration order and this crate's `preserve_order` `serde_json`
/// build). A truthy non-iterable scalar (a nonzero number, `true`) makes
/// `list(...)` raise an uncaught `TypeError`, closest handled error
/// `state_corrupt` (PORTING.md §3.5) -- reachable only *after* every backup
/// document has already been written (Python's own control-flow: this call
/// happens partway through the same `with state.lock()` block, after the
/// other archive documents are restored). A previous version of this port
/// silently substituted `[]` for any non-array value here, including a
/// truthy one Python does not silently discard.
fn python_list_over_value(v: &Value) -> Result<Vec<Value>, Error> {
    if json_falsy(v) {
        return Ok(Vec::new());
    }
    match v {
        Value::Array(a) => Ok(a.clone()),
        Value::String(s) => Ok(s.chars().map(|c| Value::String(c.to_string())).collect()),
        Value::Object(m) => Ok(m.keys().map(|k| Value::String(k.clone())).collect()),
        _ => Err(escaped(TYPE_ERROR)),
    }
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
/// catch-all here defers to [`crate::pystr::repr_value`] (the crate's one
/// canonical container-`repr` implementation, PORTING.md §3b) instead of a
/// compact JSON rendering (finding E-R3-3; the previous version used
/// `Value::to_string()` here, e.g. `{"a":1}`, which is not what Python's
/// `str()` produces).
///
/// X-10 (equivalence review, round 8): the `Number` arm used to keep its
/// own copy of the integer/float split, and got it wrong the same way the
/// (since-fixed) `repr_value` promotion did -- branching on
/// `Number::is_f64()`, which is `false` for a literal that overflows to a
/// non-finite `f64` under `arbitrary_precision`, silently echoing the raw
/// literal text back instead of CPython's `"inf"`/`"-inf"`. This function
/// itself is kept (not deleted wholesale in favour of `repr_value`, despite
/// what that finding's fix text suggests): `repr_value` is Python's
/// `repr()`, which quotes a `str`, while this function is Python's
/// `str()`, which does not (`str("x") == "x"`, not `"'x'"`) -- every call
/// site here stringifies a field that is ordinarily a plain string (an env
/// id, a generation id, a status, ...), so substituting `repr_value`
/// wholesale would wrongly quote it. Only the `Number` arm duplicated
/// `repr_value`'s bug and is real dead weight; it now delegates to
/// [`crate::pystr::repr_number`], the single canonical implementation
/// (str() and repr() agree for numbers in Python, so the same function
/// serves both).
pub(crate) fn python_str_scalar(v: &Value) -> String {
    match v {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::String(s) => s.clone(),
        Value::Number(n) => crate::pystr::repr_number(n),
        Value::Array(_) | Value::Object(_) => crate::pystr::repr_value(v),
    }
}

/// A `versions` object key, parsed exactly like Python's `int(v)` (finding
/// E-R3-4). `vault.py` never guards this conversion with a `try`/`except`,
/// so a version key `int()` cannot parse raises an uncaught `ValueError`
/// there; the closest handled error a caller of a `Vault` method already
/// expects for corrupted state is `StateError("state_corrupt")` (this
/// module's own top-of-file DEVIATIONS note, PORTING.md §3.5).
///
/// The canonical decimal grammar and CPython digit bound live in
/// [`crate::pystr::int_from_str_decimal_limited`]. The resulting digits are
/// parsed into an arbitrary-precision [`PyInt`], so a valid stored version is
/// never narrowed to a machine integer.
fn parse_version_key(k: &str) -> Result<PyInt, Error> {
    crate::pystr::int_from_str_decimal_limited(k)
        .and_then(|value| value.parse().ok())
        .map(PyInt)
        .ok_or_else(|| escaped(VALUE_ERROR))
}

/// `put_secret` on a `versions` value that is not a dict. Python still runs
/// `max(int(v) for v in versions)`: a `null`/number/bool is not iterable
/// (`TypeError`); a list iterates its elements and a string its characters,
/// where `int()` of a non-numeric string is `ValueError` and of a `null`/list/
/// dict `TypeError` (the first failing element decides). When every element
/// converts, `versions[str(version)] = record` then fails as item assignment on
/// a list/str (`TypeError`). Nothing is committed in any case.
fn non_dict_versions_error(versions: &Value) -> Error {
    let items: Vec<Value> = match versions {
        Value::Array(items) => items.clone(),
        Value::String(text) => text.chars().map(|c| Value::String(c.to_string())).collect(),
        _ => return escaped(TYPE_ERROR),
    };
    for item in &items {
        match item {
            Value::String(text) => {
                if crate::pystr::int_from_str_decimal_limited(text).is_none() {
                    return escaped(VALUE_ERROR);
                }
            }
            Value::Number(_) | Value::Bool(_) => {}
            Value::Null | Value::Array(_) | Value::Object(_) => return escaped(TYPE_ERROR),
        }
    }
    escaped(TYPE_ERROR)
}

/// `key not in versions` (Python's `in` operator), used by
/// `set_version_status`'s `str(version) not in entry["versions"]` existence
/// check (finding E-R5-7). A `dict` checks membership among its *keys*; a
/// `list` checks membership among its *elements* via `==` (so a list of
/// numbers never contains a Python `str`); a `str` checks *substring*
/// containment. A missing `versions` key, or a present value that is not
/// iterable at all (`null`, a number, a bool), makes Python's `in` itself
/// raise an uncaught `KeyError`/`TypeError` -- `state_corrupt`
/// (PORTING.md §3.5).
fn versions_contains(versions: Option<&Value>, key: &str) -> Result<bool, Error> {
    match versions {
        Some(Value::Object(m)) => Ok(m.contains_key(key)),
        Some(Value::Array(a)) => Ok(a.iter().any(|v| v.as_str() == Some(key))),
        Some(Value::String(s)) => Ok(s.contains(key)),
        None => Err(escaped(KEY_ERROR)),
        Some(_) => Err(escaped(TYPE_ERROR)),
    }
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

    /// `AdminCredential.verify`. Only `derive_key`'s short-passphrase
    /// `InvalidInput` is caught (as `admin_reauth_failed`); a malformed
    /// `admin.json` makes `doc["salt"]`/`doc["hash"]` or `_b64d(...)` raise a
    /// built-in exception that escapes (PORTING.md §3.5), reported with its
    /// class name like every other escaped exception in this module -- in
    /// Python's order: the salt first, then the passphrase length, then the
    /// hash.
    pub fn verify(&self, passphrase: &str, now: Option<f64>) -> Result<AdminAuth, Error> {
        let doc = self.state.read_json(ADMIN_DOC, Value::Null)?;
        if json_falsy(&doc) {
            return Err(Error::state("admin_missing"));
        }
        let reauth_failed = || Error::auth_failed("admin_reauth_failed");
        let salt = b64d_value(index(&doc, "salt")?).map_err(escaped)?;
        let key = derive_key(passphrase, &salt).map_err(|_| reauth_failed())?;
        let expected_hash = b64d_value(index(&doc, "hash")?).map_err(escaped)?;
        if !constant_time_eq(&sha256(key.expose()), &expected_hash) {
            return Err(reauth_failed());
        }
        Ok(AdminAuth::new(now.unwrap_or_else(crate::store::now)))
    }
}

/// The built-in exception `name` escaping a `vault.py` method, in the
/// `StateError("state_corrupt", <class>)` shape the administrator CLI's
/// `except (KeyError, TypeError, AttributeError, ValueError)` prints.
fn escaped_builtin(name: &str) -> Error {
    Error::state("state_corrupt").with_detail(name)
}

// ------------------------------------------------------------------------ vault
/// Port of `vault.VersionMeta`.
#[derive(Clone, Debug, PartialEq)]
pub struct VersionMeta {
    pub secret_id: String,
    pub version: PyInt,
    /// `r["status"]` exactly as stored: Python's `str` annotation is not
    /// enforced, so a hand-edited document's number/list/... is returned as-is.
    pub status: Value,
    /// `r["created_at"]` exactly as stored (see `status`).
    pub created_at: Value,
    /// Non-secret metadata derived from the value (e.g. the SSH public key);
    /// empty for every other kind. See [`Vault::public_metadata`].
    pub public: PublicMetadata,
}

/// A Python version value after `resolve_version`. Stored metadata does not
/// enforce its `int | None` annotation, so preserve every non-null JSON shape
/// until Python's later `str(version)` lookup/AAD boundary.
#[derive(Clone, Debug, PartialEq)]
pub enum ResolvedVersion {
    Integer(PyInt),
    Raw(Value),
}

impl ResolvedVersion {
    pub fn value(&self) -> Value {
        match self {
            Self::Integer(value) => value.value(),
            Self::Raw(value) => value.clone(),
        }
    }

    pub fn equals_integer(&self, integer: &PyInt) -> bool {
        match self {
            Self::Integer(value) => value == integer,
            Self::Raw(value) => {
                if let Some(value) = PyInt::from_python_int(value) {
                    &value == integer
                } else {
                    match value {
                        Value::Number(number) => number.as_f64().is_some_and(|float| {
                            crate::pyint::cmp_bigint_f64(&integer.0, float)
                                == Some(std::cmp::Ordering::Equal)
                        }),
                        _ => false,
                    }
                }
            }
        }
    }

    fn key(&self) -> String {
        match self {
            Self::Integer(value) => value.to_string(),
            Self::Raw(value) => python_str_scalar(value),
        }
    }
}

impl std::fmt::Display for ResolvedVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.key())
    }
}

impl Serialize for ResolvedVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.value().serialize(serializer)
    }
}

impl From<PyInt> for ResolvedVersion {
    fn from(value: PyInt) -> Self {
        Self::Integer(value)
    }
}

impl From<i32> for ResolvedVersion {
    fn from(value: i32) -> Self {
        Self::Integer(value.into())
    }
}

impl From<i64> for ResolvedVersion {
    fn from(value: i64) -> Self {
        Self::Integer(value.into())
    }
}

impl PartialEq<ResolvedVersion> for PyInt {
    fn eq(&self, other: &ResolvedVersion) -> bool {
        other.equals_integer(self)
    }
}

/// Port of `vault.SecretMeta`.
#[derive(Clone, Debug, PartialEq)]
pub struct SecretMeta {
    pub id: String,
    /// `entry["project"]`, `entry["environment"]` and `entry["kind"]` exactly
    /// as stored: Python's `str` annotations are not enforced at runtime.
    pub project: Value,
    pub environment: Value,
    pub kind: Value,
    pub active_version: Option<ResolvedVersion>,
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
        let wrapped = WrappedKey::from_dict(index(&doc, "dek")?)?;
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
        // Python: `rec = doc["recovery"]`, then `_b64d(rec["salt"])` (evaluated before
        // `derive_key`'s own passphrase check), `_b64d(rec["nonce"])`, `_b64d(rec["ciphertext"])`;
        // each lookup or decode failure is a built-in exception that escapes.
        let rec = index(&doc, "recovery")?;
        let salt = b64d_value(index(rec, "salt")?).map_err(escaped)?;
        let key = derive_key(recovery_passphrase, &salt)?;
        let nonce = b64d_value(index(rec, "nonce")?).map_err(escaped)?;
        let ciphertext = b64d_value(index(rec, "ciphertext")?).map_err(escaped)?;
        let dek_bytes = aead::decrypt(key.expose(), &nonce, &ciphertext, b"zeropw-recovery")
            .map_err(|_| Error::auth_failed("recovery_passphrase_invalid"))?;
        {
            let _lock = state.lock()?;
            let mut doc2 = state.read_json(VAULT_DOC, Value::Null)?;
            let wrapped = new_kms.wrap(&dek_bytes)?;
            // `doc["dek"] = ...`: item assignment needs a dict (`TypeError` otherwise).
            doc2.as_object_mut()
                .ok_or_else(|| escaped(TYPE_ERROR))?
                .insert("dek".into(), wrapped.to_dict());
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

    /// `self._doc()["secrets"]` as the receiver of `.items()`/`.get(...)`.
    fn secrets_obj(doc: &Value) -> Result<&Map<String, Value>, Error> {
        dict_methods(index(doc, "secrets")?)
    }

    fn aad(secret_id: &str, version: &ResolvedVersion) -> Vec<u8> {
        format!("zeropw-secret:{secret_id}:{version}").into_bytes()
    }

    fn encrypt(
        &self,
        secret_id: &str,
        version: &PyInt,
        value: &[u8],
    ) -> Result<Map<String, Value>, Error> {
        let nonce = random_bytes(aead::NONCE_SIZE);
        let ciphertext = aead::encrypt(
            self.dek.expose(),
            &nonce,
            value,
            &Self::aad(secret_id, &ResolvedVersion::Integer(version.clone())),
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
        version: &ResolvedVersion,
        entry: &Map<String, Value>,
    ) -> Result<SecretBytes, Error> {
        if entry.get("shared_env").is_some_and(|v| !json_falsy(v)) {
            return self.decrypt_shared(secret_id, entry);
        }
        // Python catches `KeyError`/`ValueError` (including `binascii.Error`) around
        // `_b64d(entry["nonce"])`/`_b64d(entry["ciphertext"])` as `secret_corrupt`; a present
        // non-`str` field makes `b64decode` raise `TypeError`, which escapes.
        let corrupt = || Error::state("secret_corrupt").with_detail(secret_id);
        let field = |key: &str| -> Result<Vec<u8>, Error> {
            let value = entry.get(key).ok_or_else(corrupt)?;
            b64d_value(value).map_err(|class| {
                if class == TYPE_ERROR {
                    escaped(TYPE_ERROR)
                } else {
                    corrupt()
                }
            })
        };
        let nonce = field("nonce")?;
        let ciphertext = field("ciphertext")?;
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
            // Only the parse sits inside `except sshwire.WireError`; the
            // bare `ValueError` `to_authorized_key` raises for a comment with
            // a line break or NUL (and anything else that is not a
            // `WireError`) escapes `put_secret` before anything is written.
            let key = crate::sshwire::parse_openssh_private_key(value).map_err(|e| {
                if e.is_wire_error() {
                    Error::invalid_input("ssh_private_key_invalid").with_detail(e.class_name())
                } else {
                    escaped_builtin(e.class_name())
                }
            })?;
            let public_key = key
                .public
                .to_authorized_key(&key.comment)
                .map_err(|e| escaped_builtin(e.class_name()))?;
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
    ) -> Result<PyInt, Error> {
        self.put_secret_values(
            secret_id,
            &json!(kind),
            value,
            &json!(project),
            &json!(environment),
            activate,
        )
    }

    /// `Vault.put_secret` for arguments that are stored JSON values rather than
    /// CLI strings (e.g. `rotation start` passes a [`SecretMeta`]'s raw
    /// `kind`/`project`/`environment`). `kind not in SECRET_KINDS` admits only
    /// one of those strings; `project`/`environment` reach
    /// `Projects.require_environment` and the stored entry unchanged, compared
    /// with Python `==`.
    pub fn put_secret_values(
        &self,
        secret_id: &str,
        kind: &Value,
        value: &[u8],
        project: &Value,
        environment: &Value,
        activate: bool,
    ) -> Result<PyInt, Error> {
        let secret_id = validate_name(secret_id, "secret_id")?;
        let Some(kind) = kind.as_str().filter(|kind| SECRET_KINDS.contains(kind)) else {
            return Err(Error::invalid_input("invalid_secret_kind"));
        };
        if value.is_empty() || value.len() > MAX_SECRET_BYTES {
            return Err(Error::invalid_input("invalid_secret_value"));
        }
        self.projects
            .require_environment_value(project, environment)?;
        let public = Vault::public_metadata(kind, value)?;

        let version;
        let rebound;
        {
            let _lock = self.state.lock()?;
            let mut doc_val = self.doc()?;
            // Python: `doc["secrets"].get(secret_id)` -- a non-dict document cannot be subscripted
            // (`TypeError`), a missing `secrets` is `KeyError`, and a non-dict `secrets` has no
            // `.get` (`AttributeError`); nothing is committed (finding E-R5-1).
            let secrets_obj = dict_methods_mut(index_mut(&mut doc_val, "secrets")?)?;

            // Python: `entry = doc["secrets"].get(secret_id); if entry is None: entry = {...}`.
            // `dict.get` returns `None` both when the key is absent *and* when it maps to a JSON
            // `null` (finding E-R4-2), so a `"secrets": {"ghost": null}` entry takes the
            // fresh-entry branch.
            let mut entry: Value = match secrets_obj.get(&secret_id).filter(|v| !v.is_null()) {
                Some(existing) => {
                    // Python: `(entry["project"], entry["environment"], entry["kind"]) != (project,
                    // environment, kind)`: the whole tuple is built first, so any missing field is
                    // `KeyError` (a non-dict entry `TypeError`) even when an earlier field already
                    // differs; a present field of another type simply compares unequal.
                    let fields = [
                        index(existing, "project")?,
                        index(existing, "environment")?,
                        index(existing, "kind")?,
                    ];
                    let expected = [project, environment, &json!(kind)];
                    if fields
                        .iter()
                        .zip(expected)
                        .any(|(field, expected)| !python_eq(field, expected))
                    {
                        return Err(Error::invalid_input("secret_identity_mismatch"));
                    }
                    existing.clone()
                }
                None => json!({
                    "project": project,
                    "environment": environment,
                    "kind": kind,
                    "created_at": iso(None),
                    "active_version": null,
                    "versions": {},
                }),
            };

            // Python: `max((int(v) for v in entry["versions"]), default=0) + 1` is arbitrary
            // precision, so the parsed keys and the increment stay exact beyond every
            // machine-integer boundary. A non-dict `versions` fails as Python's iteration,
            // `int()` and item assignment do ([`non_dict_versions_error`]).
            let mut versions_obj = match index(&entry, "versions")? {
                Value::Object(map) => map.clone(),
                other => return Err(non_dict_versions_error(other)),
            };
            let next_version = versions_obj
                .keys()
                .map(|k| parse_version_key(k))
                .collect::<Result<Vec<PyInt>, Error>>()?
                .into_iter()
                .max()
                .unwrap_or_else(|| PyInt::from(0_i64));
            let next_version = PyInt(next_version.0 + 1);
            let mut record = self.encrypt(&secret_id, &next_version, value)?;
            record.insert("created_at".into(), json!(iso(None)));
            record.insert(
                "status".into(),
                json!(if activate { "active" } else { "staged" }),
            );
            record.insert("public".into(), public);
            versions_obj.insert(next_version.to_string(), Value::Object(record));

            if activate {
                // Python: `previous = entry["active_version"]` (`KeyError` when missing); then, for
                // a non-`None` previous, `entry["versions"][str(previous)]["status"] == "active"`.
                // `str(previous)` is computed from whatever raw JSON value `active_version` holds;
                // a key naming no version (`7`, or `1.0` -> `"1.0"`) is `KeyError`, a non-dict
                // record `TypeError`, a missing status `KeyError` -- all before `write_json`, so
                // nothing is committed (finding E-R4-4). A present status of another type just
                // compares unequal to `"active"`.
                let entry_obj = entry.as_object_mut().ok_or_else(|| escaped(TYPE_ERROR))?;
                let previous = entry_obj
                    .get("active_version")
                    .cloned()
                    .ok_or_else(|| escaped(KEY_ERROR))?;
                entry_obj.insert("active_version".into(), next_version.value());
                if !previous.is_null() {
                    let prev_rec = versions_obj
                        .get_mut(&python_str_scalar(&previous))
                        .ok_or_else(|| escaped(KEY_ERROR))?;
                    if index(prev_rec, "status")?.as_str() == Some("active") {
                        index_mut(prev_rec, "status")?.clone_from(&json!("retired"));
                    }
                }
            }
            entry
                .as_object_mut()
                .ok_or_else(|| escaped(TYPE_ERROR))?
                .insert("versions".into(), Value::Object(versions_obj));
            secrets_obj.insert(secret_id.clone(), entry);

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
                    ("version", version.value()),
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
                    policy_version: Some(c.policy_version.clone()),
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
        version: &PyInt,
        status: &str,
    ) -> Result<(), Error> {
        if !VERSION_STATES.contains(&status) {
            return Err(Error::invalid_input("invalid_version_status"));
        }
        let rebound;
        {
            let _lock = self.state.lock()?;
            let mut doc_val = self.doc()?;
            let secrets_obj = dict_methods_mut(index_mut(&mut doc_val, "secrets")?)?;
            // Python: `entry = doc["secrets"].get(secret_id); if entry is None or str(version) not
            // in entry["versions"]: raise NotFound(...)`. `dict.get` returns `None` both when the
            // key is absent *and* when it maps to a JSON `null` (finding E-R4-2), so both are the
            // documented `NotFound("secret_version_not_found")`; any other non-dict entry cannot
            // be subscripted (`TypeError`).
            let entry_val = secrets_obj.get(secret_id).filter(|v| !v.is_null()).cloned();
            let Some(entry_val) = entry_val else {
                return Err(Error::not_found("secret_version_not_found"));
            };
            let Value::Object(mut entry) = entry_val else {
                return Err(escaped(TYPE_ERROR));
            };
            // Python: `str(version) not in entry["versions"]` is an ordinary membership test,
            // evaluated as a *separate* statement from the `entry["versions"][str(version)]`
            // indexing below (finding E-R5-7): a missing `versions` is `KeyError` and a
            // non-iterable one (`null`, a number, a bool) `TypeError`, but a `list`/`str`
            // `versions` checks element membership / substring containment and only raises the
            // documented `NotFound` when the key isn't found that way; if it *is* found, the
            // next line's string subscript of a list/str is `TypeError`.
            let key = version.to_string();
            if !versions_contains(entry.get("versions"), &key)? {
                return Err(Error::not_found("secret_version_not_found"));
            }
            let mut versions = match entry.get("versions") {
                Some(Value::Object(m)) => m.clone(),
                _ => return Err(escaped(TYPE_ERROR)),
            };
            // Python: `record["status"] == "revoked"` -- a non-dict record is `TypeError`, a
            // missing status `KeyError`; a present status of another type just compares unequal.
            let record_status = index(
                versions.get(&key).ok_or_else(|| escaped(KEY_ERROR))?,
                "status",
            )?;
            if record_status.as_str() == Some("revoked") && status != "revoked" {
                return Err(Error::invalid_input("version_revoked"));
            }
            if status == "revoked" {
                let mut fields = Map::new();
                fields.insert("secret_id".into(), json!(secret_id));
                fields.insert("version".into(), version.value());
                crate::policy::append_revocation(self.state, "secret_version", fields);
            }
            *index_mut(
                versions.get_mut(&key).ok_or_else(|| escaped(KEY_ERROR))?,
                "status",
            )? = json!(status);
            // Python: `before_active = entry["active_version"]`, a raw JSON value (not narrowed to
            // `int`), used both for the `!= version` skip and, via `str(previous)`, as a `versions`
            // key (finding E-R4-4: `entry["versions"][str(previous)]["status"]` is unguarded, so a
            // `previous` naming a missing version or a non-canonical-int form like `1.0` raises an
            // uncaught `KeyError`/`TypeError` and commits nothing). The previous
            // `.and_then(Value::as_i64)` here silently treated any non-i64 `active_version` as "no
            // previous version", skipping the retire step and still committing the write.
            //
            // Every comparison below against `version`/`before_active`/`after_active` uses Python's
            // numeric `==` (`active_version_matches`/`active_version_values_equal`), not JSON-shape
            // equality (finding E-R5-4): Python's `bool`/`int`/`float` compare by value (`True == 1`,
            // `1.0 == 1`), so a stored `active_version: true` or `1.0` is the *same* version as `1`.
            // A previous version of this port compared `serde_json::Value`s directly, so an
            // `active_version` of `true` (meaning version 1) being re-activated at version 1 wrongly
            // took the retire branch below and failed with `state_corrupt` (Python: `previous != 1`
            // is `False`, retire is skipped, the call succeeds with no rebind), and the same
            // `active_version: true` being explicitly retired wrongly *stayed* `true` instead of
            // being cleared to `null` (Python: `entry["active_version"] == version` is `True`, so it
            // clears) -- a fail-open gap on a revocation-adjacent path.
            // Python: `before_active = entry["active_version"]` -- `KeyError` when missing, after
            // `append_revocation` above but before anything is written to the vault document.
            let before_active = entry
                .get("active_version")
                .cloned()
                .ok_or_else(|| escaped(KEY_ERROR))?;
            if status == "active" {
                entry.insert("active_version".into(), json!(version));
                if !before_active.is_null() && !active_version_matches(&before_active, version) {
                    // Python: `entry["versions"][str(previous)]["status"]` -- a key naming no
                    // version is `KeyError`, a non-dict record `TypeError`, a missing status
                    // `KeyError`; a present status of another type compares unequal (skip).
                    let prev_rec = versions
                        .get_mut(&python_str_scalar(&before_active))
                        .ok_or_else(|| escaped(KEY_ERROR))?;
                    if index(prev_rec, "status")?.as_str() == Some("active") {
                        *index_mut(prev_rec, "status")? = json!("retired");
                    }
                }
            } else if active_version_matches(&before_active, version) {
                entry.insert("active_version".into(), Value::Null);
            }
            entry.insert("versions".into(), Value::Object(versions));
            let after_active = get_or_null(&entry, "active_version").clone();
            secrets_obj.insert(secret_id.to_string(), Value::Object(entry));
            self.state.write_json(VAULT_DOC, &doc_val)?;
            rebound = if !active_version_values_equal(&after_active, &before_active) {
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
                    ("version", version.value()),
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
            let Some(entry) = secrets_obj.get(&secret_id) else {
                continue;
            };
            // Python: `if project and entry["project"] != project: continue`, then the same for
            // `environment` -- each field is read only when its filter is given, and an entry a
            // filter skips is never read further. Every value keeps its stored JSON type.
            if let Some(pf) = project
                && index(entry, "project")?.as_str() != Some(pf)
            {
                continue;
            }
            if let Some(ef) = environment
                && index(entry, "environment")?.as_str() != Some(ef)
            {
                continue;
            }
            // Python: `sorted(entry["versions"].items(), key=lambda item: int(item[0]))`.
            let versions_obj = dict_methods(index(entry, "versions")?)?;
            let mut vkeys: Vec<(PyInt, &Value)> = versions_obj
                .iter()
                .map(|(k, r)| parse_version_key(k).map(|n| (n, r)))
                .collect::<Result<Vec<_>, Error>>()?;
            vkeys.sort_by(|(a, _), (b, _)| a.cmp(b));
            let mut versions = Vec::new();
            for (n, r) in vkeys {
                // Python: `VersionMeta(secret_id, int(v), r["status"], r["created_at"],
                // dict(r.get("public") or {}))` keeps each stored value as-is (finding E-R4-3);
                // the dataclass annotations are never enforced.
                let status = index(r, "status")?.clone();
                let created_at = index(r, "created_at")?.clone();
                let public = coerce_public_field(dict_methods(r)?.get("public"))?;
                versions.push(VersionMeta {
                    secret_id: secret_id.clone(),
                    version: n,
                    status,
                    created_at,
                    public,
                });
            }
            let entry_obj = entry.as_object().ok_or_else(|| escaped(TYPE_ERROR))?;
            result.push(SecretMeta {
                id: secret_id.clone(),
                project: index(entry, "project")?.clone(),
                environment: index(entry, "environment")?.clone(),
                kind: index(entry, "kind")?.clone(),
                active_version: require_active_version(entry_obj)?,
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

    pub fn resolve_version(
        &self,
        secret_id: &str,
        version: Option<PyInt>,
    ) -> Result<ResolvedVersion, Error> {
        let meta = self.get_meta(secret_id)?;
        match version {
            None => meta
                .active_version
                .ok_or_else(|| Error::not_found("secret_no_active_version")),
            Some(v) => {
                if meta.versions.iter().any(|item| item.version == v) {
                    Ok(ResolvedVersion::Integer(v))
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
        version: Option<PyInt>,
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
        // Python: `record = entry["versions"][str(resolved)]` (`KeyError` for an active
        // version naming no stored key), then `record["status"] not in ("active", "staged")`:
        // a present status of any type is compared (and, if unusable, carried as the
        // documented `NotFound`'s detail, finding E-R4-3).
        let entry = secrets_obj.get(secret_id).unwrap_or(&Value::Null);
        let record = index(index(entry, "versions")?, &resolved.key())?;
        let status_value = index(record, "status")?;
        if status_value.as_str() != Some("active") && status_value.as_str() != Some("staged") {
            // `ZeroPWError.__init__` suppresses a *falsy* `detail` (`0`, `false`, `null`, `[]`,
            // `{}`): `str(exc)` is just the reason and `to_dict()` omits `detail` entirely --
            // `json_falsy` is the same Python-truthiness check this module already uses elsewhere
            // (finding E-R5-6, completing E-R4-3: a status of `0`/`false`/`null`/`[]`/`{}`
            // previously still rendered as the literal string `"0"`/`"False"`/`"None"`/`"[]"`/
            // `"{}"` in this error's `detail`, where Python's own `NotFound(..., 0)` etc. carries
            // no visible detail at all).
            let detail = if json_falsy(status_value) {
                String::new()
            } else {
                python_str_scalar(status_value)
            };
            return Err(Error::not_found("secret_version_unusable").with_detail(detail));
        }
        self.decrypt(secret_id, &resolved, dict_methods(record)?)
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
            let Some(entry) = secrets_obj.get(&secret_id) else {
                continue;
            };
            // Python: `sorted(entry["versions"].items(), key=int)`, then
            // `self._decrypt(secret_id, int(version), record)`, whose `record.get(...)` needs a
            // dict (`AttributeError`).
            let versions_obj = dict_methods(index(entry, "versions")?)?;
            let mut vkeys: Vec<(PyInt, &Value)> = versions_obj
                .iter()
                .map(|(k, r)| parse_version_key(k).map(|n| (n, r)))
                .collect::<Result<Vec<_>, Error>>()?;
            vkeys.sort_by(|(a, _), (b, _)| a.cmp(b));
            for (n, record) in vkeys {
                values.push(self.decrypt(
                    &secret_id,
                    &ResolvedVersion::Integer(n),
                    dict_methods(record)?,
                )?);
            }
        }
        Ok(values)
    }

    /// Administrator single-secret read: fresh re-auth + audit first, then
    /// decrypt.
    pub fn reveal(
        &self,
        secret_id: &str,
        version: Option<PyInt>,
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
                    ("version", resolved.value()),
                ],
                ..Default::default()
            },
        )?;
        // Python: `entry = self._doc()["secrets"][secret_id]`, then
        // `self._decrypt(secret_id, resolved, entry["versions"][str(resolved)])`.
        let doc = self.doc()?;
        let entry = index(index(&doc, "secrets")?, secret_id)?;
        let record = index(index(entry, "versions")?, &resolved.key())?;
        self.decrypt(secret_id, &resolved, dict_methods(record)?)
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
    ///
    /// Finding E-R5-8: the archive nests every document two levels deeper
    /// than `StateDir` itself does (`{"manifest": ..., "documents": {name:
    /// <document>, ...}}`), so a document at or near `pyjson`'s
    /// `MAX_JSON_DEPTH` (500) -- which `StateDir::write_json`/`read_json`
    /// happily wrote/read -- can push `pyjson::dumps` here past that same
    /// cap. `pyjson::dumps`'s only failure mode is exactly this depth check
    /// (`InvalidInput("pyjson_max_depth_exceeded")`), an error class no
    /// caller of `backup` otherwise ever sees from it (every other failure
    /// in this function is a `StateError`); both call sites below map that
    /// failure to `StateError("backup_too_deep")` instead of letting it
    /// escape as-is, per the `DEVIATIONS.md` `vault (Vault::backup, finding
    /// E-R5-8)` row (not reproducing Python's unlimited depth here, for the
    /// same fail-closed reasoning already applied to `Vault::restore`'s own
    /// depth handling, finding E-R4-5).
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
        )
        .map_err(|_| Error::state("backup_too_deep"))?;
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
        let text = pyjson::dumps(&archive, DumpOptions::default_sorted())
            .map_err(|_| Error::state("backup_too_deep"))?;
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
    ///
    /// Returns an insertion-ordered `grants`, `principals`, `connections`, `secret_versions`
    /// sequence, matching the Python dict `Policy.reapply_revocations` returns (built as
    /// `{"grants": 0, "principals": 0, "connections": 0}` -- a literal, so exactly that key
    /// order -- with values only ever mutated in place, never re-inserted) plus this function's
    /// own `counts["secret_versions"] = changed` appended last. `Policy::reapply_revocations`
    /// (owned by unit D, `policy.rs:4783`) still returns a `HashMap` internally -- its three keys
    /// are read back out here in that fixed, known order rather than relying on the `HashMap`'s
    /// own non-deterministic iteration order, which `Vault::restore` used to do via
    /// `HashMap::drain()` (finding E-R7-4: not observable in the *written* JSON, since
    /// `StateDir::write_json` sorts keys, but observable in the `Vec`/`Map` this function itself
    /// returns to any future caller that iterates or prints it, e.g. a second-half `admin_cli`).
    pub fn reapply_revocations(state: &StateDir) -> Result<Vec<(&'static str, usize)>, Error> {
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
        let policy_counts = policy.reapply_revocations(&revocations)?;
        let mut counts: Vec<(&'static str, usize)> = ["grants", "principals", "connections"]
            .into_iter()
            .map(|k| (k, policy_counts.get(k).copied().unwrap_or(0)))
            .collect();
        let mut changed = 0usize;
        if let Value::Object(mut doc_obj) = state.read_json(VAULT_DOC, Value::Null)? {
            let mut secret_versions: Vec<(String, PyInt)> =
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
                    // Python: `entry.get("versions", {}).get(str(version))` -- a *missing*
                    // `versions` key falls back to `{}`, whose `.get(...)` is `None` (skip, no
                    // error), but a *present* `versions` value that isn't a dict has no `.get`
                    // method at all, so Python's own `.get(str(version))` call raises an uncaught
                    // `AttributeError` there -- aborting this whole `reapply_revocations` call (and
                    // therefore `Vault::restore`) rather than reporting success with the revocation
                    // silently un-applied (finding E-R5-2, correcting DEVIATIONS.md row 52's claim
                    // that this path already fails closed like every other raw-indexed `versions`
                    // read in this module: a previous version of this port treated a non-object
                    // `versions` the same as a missing one here, fail-*open* on a revocation-reapply
                    // path).
                    let mut was_revoked = false;
                    match entry.get_mut("versions") {
                        None => {}
                        Some(Value::Object(versions_obj)) => {
                            if let Some(record) = versions_obj
                                .get_mut(&version.to_string())
                                .and_then(Value::as_object_mut)
                                && record.get("status").and_then(Value::as_str) != Some("revoked")
                            {
                                record.insert("status".into(), json!("revoked"));
                                was_revoked = true;
                            }
                        }
                        Some(_) => return Err(escaped(ATTRIBUTE_ERROR)),
                    }
                    if was_revoked {
                        touched = true;
                        changed += 1;
                        // Python `==`: numeric equality, not JSON-shape equality (finding E-R5-4;
                        // see `active_version_matches`'s doc comment) -- an `active_version` of
                        // `true`/`1.0` naming this same revoked version must still be cleared.
                        if entry
                            .get("active_version")
                            .is_some_and(|v| active_version_matches(v, version))
                        {
                            entry.insert("active_version".into(), Value::Null);
                        }
                    }
                }
            }
            if touched {
                state.write_json(VAULT_DOC, &Value::Object(doc_obj))?;
            }
        }
        counts.push(("secret_versions", changed));
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
    ///
    /// Finding E-R5-8: a real Python-written archive can legitimately
    /// contain a document up to `pyjson`'s `MAX_JSON_DEPTH` (Python's own
    /// `json` has no such limit at all), but the archive's own two levels of
    /// wrapping (`manifest`/`documents`) put such a document past this
    /// port's parse-time depth cap, so `pyjson::loads` below already fails
    /// closed on it as an ordinary parse error -- mapped, like every other
    /// unparseable archive, to the handled `StateError("backup_malformed")`
    /// rather than a class no caller of `restore` expects. See the
    /// `DEVIATIONS.md` `vault (Vault::backup, finding E-R5-8)` row.
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
        // `hmac.compare_digest(str, str)` raises `TypeError` for a non-ASCII
        // `str`; it escapes `restore` (the CLI prints `state_corrupt`).
        if !manifest_digest.is_ascii() {
            return Err(escaped_builtin("TypeError"));
        }
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
            // The open incident is current state, like the stop: `incidents/` is not in the
            // archive, so the archived pointer is either absent (an incident opened after the
            // backup would stop blocking `resume`) or names one closed since (which no
            // `incident close` could clear again).
            match current.get("incident_open") {
                Some(open) => control.insert("incident_open".into(), open.clone()),
                None => control.remove("incident_open"),
            };
            let (merged_approvals, dropped) = Vault::merge_restored_approvals(
                get_or_null(&current, "approvals"),
                get_or_null(&control, "approvals"),
            );
            control.insert("approvals".into(), Value::Object(merged_approvals));
            let approval_history =
                python_list_over_value(get_or_null(&current, "approval_history"))?;
            control.insert("approval_history".into(), Value::Array(approval_history));
            control.insert("restore_pending".into(), json!(true));
            control.insert(
                "restored_from".into(),
                manifest.get("backup_id").cloned().unwrap_or(Value::Null),
            );
            control.insert("restored_at".into(), json!(iso(None)));
            state.write_json(control_doc, &Value::Object(control))?;

            let reapplied = Vault::reapply_revocations(state)?;
            // `Map` (`serde_json`'s `preserve_order`-backed map) preserves the insertion order
            // below, matching Python's `reapplied["approvals_dropped"] = dropped` appending a
            // fifth key after `reapply_revocations`'s own `grants`/`principals`/`connections`/
            // `secret_versions` (finding E-R7-4) -- `reapply_revocations` now returns that
            // ordered sequence directly instead of a `HashMap` whose iteration order this used to
            // scramble via `.drain()`.
            let mut reapplied_obj: Map<String, Value> = reapplied
                .into_iter()
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
/// re-raises the *original*, uncaught `OSError`, which the administrator CLI
/// prints by class and `strerror`; [`crate::store::uncaught_os_error`]
/// reproduces it (the temp file is removed first, as in Python).
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
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    // `tempfile.mkstemp(prefix=f".{name}.", suffix=".tmp", dir=parent)`:
    // `O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW`, retrying only on `FileExistsError`
    // (`TMP_MAX` times); any other `os.open` failure is raised as is.
    let mut opened = None;
    for _ in 0..TMP_MAX {
        let tmp_path = parent.join(format!(
            ".{file_name}.{}.tmp",
            crate::store::tempfile_random_name()
        ));
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&tmp_path)
        {
            Ok(file) => {
                opened = Some((file, tmp_path));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(crate::store::uncaught_os_error(&e)),
        }
    }
    let Some((mut file, tmp_path)) = opened else {
        return Err(Error::subclass(
            crate::errors::ErrorClass::ZeroPW,
            "FileExistsError",
            "io_error",
            "No usable temporary file name found",
        ));
    };
    let result = (|| -> std::io::Result<()> {
        file.write_all(contents.as_bytes())?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp_path, out_path)?;
        Ok(())
    })();
    result.map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        crate::store::uncaught_os_error(&e)
    })
}

/// `os.TMP_MAX`: the number of names `tempfile.mkstemp`/`mkdtemp` try
/// before giving up (glibc's value; Darwin's `<stdio.h>` says 308915776).
#[cfg(target_os = "linux")]
pub(crate) const TMP_MAX: u32 = 238_328;
#[cfg(not(target_os = "linux"))]
pub(crate) const TMP_MAX: u32 = 308_915_776;

#[cfg(test)]
mod tests {
    use super::*;

    /// E-R6-3: two non-numeric `active_version` shapes that are
    /// structurally equal (Python's `"abc" == "abc"`) must compare equal
    /// here too -- the previous unconditional `_ => false` fallback arm
    /// said they never did, so `set_version_status`'s `rebound = if
    /// !active_version_values_equal(&after_active, &before_active) { ... }`
    /// read a non-"active" call, whose `before_active`/`after_active` are
    /// both left as the same corrupted, non-numeric value (that branch
    /// only *reads* `active_version`, via `active_version_matches`, never
    /// writes it unless the value numerically matches the version being
    /// retired/revoked), as "the active version changed" and called
    /// `rebind_connections` where Python's own `entry["active_version"] !=
    /// before_active` is `False` and triggers no rebind at all. Masked in
    /// practice today because `policy.rs`'s `resolved_credential_version`
    /// already treats a non-numeric `active_version` as "no credential" and
    /// writes nothing either way an unpinned connection's credential
    /// version resolves to -- but the equality helper itself was still
    /// wrong, and this pins it directly rather than relying on that
    /// downstream masking to stay true forever.
    #[test]
    fn active_version_values_equal_uses_structural_equality_for_non_numeric_shapes() {
        assert!(active_version_values_equal(&json!("abc"), &json!("abc")));
        assert!(active_version_values_equal(&json!([1]), &json!([1])));
        assert!(active_version_values_equal(
            &json!({"a": 1}),
            &json!({"a": 1})
        ));
        assert!(!active_version_values_equal(&json!("abc"), &json!("xyz")));
        assert!(!active_version_values_equal(&json!("1"), &json!(1))); // string vs number: never numerically equal, never structurally equal
        assert!(!active_version_values_equal(&json!([1]), &json!("x")));

        // The exact `set_version_status` non-"active"-branch shape this
        // finding is about: a stored `active_version` of `"abc"` does not
        // numerically match a plain `PyInt` version being retired/revoked
        // (so it is left untouched, `before_active == after_active ==
        // "abc"`), and comparing that unchanged value against itself must
        // not spuriously read as "changed".
        assert!(!active_version_matches(&json!("abc"), &1.into()));
        assert!(active_version_values_equal(&json!("abc"), &json!("abc")));
    }

    /// X-10 (equivalence review, round 8) pinning test: `python_str_scalar`'s
    /// `Number` arm used to branch on `Number::is_f64()`, which is `false`
    /// for a literal that overflows to a non-finite `f64` under
    /// `arbitrary_precision`, so an overflowing literal fell into the
    /// integer arm and echoed its raw text back (`"1e+400"`) instead of
    /// CPython's `"inf"`. Built directly via `serde_json::from_str`
    /// (bypassing `pyjson::loads`, which rejects an overflowing literal
    /// outright) since a hand-crafted or foreign-written `manifest.json`
    /// inside an otherwise digest-valid backup archive can still hold one
    /// (see this function's own doc comment on why `restore` must handle
    /// it).
    #[test]
    fn python_str_scalar_overflowing_number_matches_python_inf() {
        let overflow: Value = serde_json::from_str("1E400").unwrap();
        let neg_overflow: Value = serde_json::from_str("-1E400").unwrap();
        assert_eq!(python_str_scalar(&overflow), "inf");
        assert_eq!(python_str_scalar(&neg_overflow), "-inf");
        // A plain string field (the common case for every real call site)
        // must stay unquoted -- str(), not repr() -- confirming this fix
        // did not accidentally widen the function into `repr_value`.
        assert_eq!(python_str_scalar(&json!("prod")), "prod");
    }

    /// X-16 pinning test, unit level: exact `i64`-pair collisions in `f64`,
    /// both measured against `python3.12`'s exact `int.__eq__`
    /// (`9007199254740993 == 9007199254740992` is `False`;
    /// `9223372036854775808 == 9223372036854775807` is `False`) that a
    /// naive `as f64` comparison would say `True` for --
    /// `9007199254740993.0f64 == 9007199254740992.0f64` and
    /// `(i64::MAX as f64) == 2f64.powi(63)` both hold in IEEE 754 double
    /// precision. `i64::MAX` vs. `2**63` matters beyond being a round
    /// number: `2**63` is exactly the `active_version` this crate's own
    /// `put_secret` writes when the largest existing key is `i64::MAX`
    /// (row 54's own probe, `DEVIATIONS.md`).
    #[test]
    fn active_version_values_equal_uses_exact_integer_comparison_not_f64() {
        let a = json!(9007199254740993i64); // 2**53 + 1
        let b = json!(9007199254740992i64); // 2**53
        assert_ne!(a, b);
        assert!(
            (a.as_i64().unwrap() as f64) == (b.as_i64().unwrap() as f64),
            "sanity: these two i64s really do collide once cast to f64"
        );
        assert!(!active_version_values_equal(&a, &b));
        assert!(!active_version_matches(&a, &9007199254740992_i64.into()));

        let i64_max = json!(i64::MAX);
        let two_pow_63 = Value::Number(serde_json::from_str("9223372036854775808").unwrap());
        assert!(
            (i64::MAX as f64) == 9223372036854775808.0f64,
            "sanity: i64::MAX and 2**63 also collide once cast to f64"
        );
        assert!(!active_version_values_equal(&i64_max, &two_pow_63));
    }

    /// Companion to the above: an *equal* integer pair (including a `bool`,
    /// itself an `int` subclass in Python) must still compare equal, and an
    /// integral `float` must still numerically equal the same-valued
    /// integer -- the fix must not overcorrect into rejecting genuine
    /// equality, only the false-positive collision case.
    #[test]
    fn active_version_values_equal_still_treats_true_equality_as_equal() {
        assert!(active_version_values_equal(
            &json!(9007199254740993i64),
            &json!(9007199254740993i64)
        ));
        assert!(active_version_values_equal(&json!(true), &json!(1)));
        assert!(active_version_values_equal(&json!(1.0), &json!(1)));
        assert!(active_version_values_equal(
            &json!(9007199254740992i64),
            &json!(9007199254740992.0)
        ));
        assert!(!active_version_values_equal(&json!(1.5), &json!(1)));
    }
}
