//! Port of `zeropw/team/commit.py`: commit model (signing, format
//! validation, hybrid logical clock, per-author commit store),
//! docs/team-sync.md sections 5.2-5.4.
//!
//! A commit is one node's signed batch of operations against a shared
//! environment. This module covers everything that is true of a commit on
//! its own, independent of the rest of the environment's history:
//!
//! * [`Hlc`] -- the hybrid logical clock used to give every commit a total
//!   order (section 5.2, section 7.1).
//! * [`Commit`] -- the canonical-JSON shape, its hash, and Ed25519
//!   sign/verify (section 5.2).
//! * [`validate_ops`] -- format-only validation of every operation shape
//!   (section 5.3, section 5.4 point 4). State-dependent checks (role,
//!   target existence, ...) are done during folding (`team::fold`, section
//!   7.2), not here.
//! * [`CommitStore`] -- the on-disk, per-author-sequence commit log, plus
//!   the deferred-commit holding area for clock-skewed commits (section 5.4
//!   point 3).
//! * [`receive_commit`] -- the section 5.4 receipt pipeline: signature,
//!   sequence and clock checks, in that order, before a commit is trusted
//!   enough to fold.
//!
//! Version identifiers (docs/team-sync.md section 5.1 says a secret version
//! id "is the hash of the commit that added it") are, in this
//! implementation, a random 128-bit hex token chosen by the writer and
//! carried in the `secret.put_version` op itself, not literally recomputed
//! from the finished commit hash -- see `zeropw/team/commit.py`'s module
//! doc comment for why the literal reading is circular. This is a
//! deliberate, documented resolution of that ambiguity in the Python
//! prototype, carried through unchanged here.
//!
//! ## Op shapes: `serde_json::Value`, not typed structs
//!
//! Every op is `dict[str, Any]` in Python -- untyped JSON all the way
//! through signing, storage and folding. This port keeps that shape
//! (`Commit::ops: Vec<Value>`, each a JSON object) rather than inventing a
//! typed enum per op kind: the canonical/signed bytes are exactly
//! `pyjson::dumps(..., DumpOptions::compact_sorted())` of that JSON tree
//! (sorted recursively), so an op's field *order* never affects the
//! signature or hash, only its *shape* (checked by [`validate_ops`]) and
//! *values* do.
//!
//! ## Reimplemented connection-field builders
//!
//! [`build_connection_fields`] validates a connection op's nested shapes
//! (`http_target`, `http_auth`, `http_scope`, `ssh_target`, `cli`) using
//! `policy::HttpTarget`/`HttpAuth`/`HttpScope`/`SshTarget`/`CliProfile`'s
//! public constructors for the actual validation, then serialises the
//! result BY HAND (`http_target_value` etc. below) rather than through
//! `policy::Connection`/its private `to_value()`/`from_value()` helpers.
//! Two independent reasons force this, not just style:
//!
//! 1. `policy::{HttpTarget,HttpAuth,HttpScope,SshTarget,CliProfile}::to_value`
//!    /`from_value` are module-private in `policy.rs` (not `pub`), so they
//!    are not reachable from here at all -- a gap worth fixing upstream
//!    (reported in this work unit's final report) so a future caller does
//!    not have to re-derive the same shape by hand again.
//! 2. Even with access, `policy::Connection::secret_version` is typed
//!    `Option<i64>` (the node-*local* integer version), but a connection op
//!    here carries the *document*'s string `version_id` token
//!    (`build_connection_fields` in Python constructs a `P.Connection` with
//!    a `str` in that field purely because Python dataclasses do not
//!    validate field types at runtime -- `Connection.__post_init__` never
//!    checks `secret_version`'s type). Rust's `Connection` cannot represent
//!    that at all, so this port never constructs one here; it validates the
//!    same fields directly and returns a plain JSON object shaped like
//!    `Connection.to_dict()` minus `id`/`policy_version`/`status`/the
//!    timestamps, exactly like the Python function's own doc comment says
//!    it returns.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::{Map, Value, json};

use crate::audit::{Audit, RecordArgs};
use crate::crypto::ed25519;
use crate::errors::{Error, ErrorClass, Result};
use crate::policy;
use crate::projects;
use crate::pybase64;
use crate::pyint::PyInt;
use crate::pyjson::{self, DumpOptions};
use crate::store::StateDir;
use crate::vault;

use super::identity::{DeviceKey, DeviceRecord};
use super::json_falsy;

/// `zeropw.team.commit.COMMIT_FORMAT`.
pub const COMMIT_FORMAT: &str = "zeropw-team-commit-v1";

/// `zeropw.team.commit.MAX_CLOCK_SKEW_MS` (docs/team-sync.md section 5.4
/// point 3 / section 14 item 1).
pub const MAX_CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;

/// `zeropw.team.commit.MAX_NAME_LENGTH` (docs/team-sync.md section 6.3: same
/// bound as the audit log).
pub const MAX_NAME_LENGTH: usize = 200;

/// `zeropw.team.commit.ENV_ID_RANDOM_HEX_LEN`.
pub const ENV_ID_RANDOM_HEX_LEN: usize = 32;

fn random_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

fn control_re_search(s: &str) -> bool {
    s.chars().any(|c| (c as u32) <= 0x1f || c as u32 == 0x7f)
}

fn is_fingerprint(s: &str) -> bool {
    s.len() == 26 && s.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
}

fn is_token(s: &str) -> bool {
    let n = s.len();
    (16..=64).contains(&n) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Every code point where CPython 3.12's `str.isdigit()` is `True` but
/// `unicodedata.decimal()` raises `ValueError` -- i.e. `Numeric_Type=Digit`
/// (superscripts like `"\u{b2}"`, circled digits, ...) rather than
/// `Numeric_Type=Decimal`/`Nd`. `str.isdigit()` is a strictly WIDER test
/// than the digit grammar `int(str)` actually accepts (finding H-R3-9):
/// `"\u{b2}".isdigit()` is `True` but `int("\u{b2}")` raises `ValueError`.
/// Sorted, for [`is_python_isdigit_char`]'s binary search. Generated by
/// `rust/tools/gen_digit_table.py` (run it and repaste if this crate ever
/// moves to a newer `python3.12`/UCD version; do not hand-edit).
const UNICODE_DIGIT_NOT_DECIMAL: &[u32] = &[
    0xB2, 0xB3, 0xB9, 0x1369, 0x136A, 0x136B, 0x136C, 0x136D, 0x136E, 0x136F, 0x1370, 0x1371,
    0x19DA, 0x2070, 0x2074, 0x2075, 0x2076, 0x2077, 0x2078, 0x2079, 0x2080, 0x2081, 0x2082, 0x2083,
    0x2084, 0x2085, 0x2086, 0x2087, 0x2088, 0x2089, 0x2460, 0x2461, 0x2462, 0x2463, 0x2464, 0x2465,
    0x2466, 0x2467, 0x2468, 0x2474, 0x2475, 0x2476, 0x2477, 0x2478, 0x2479, 0x247A, 0x247B, 0x247C,
    0x2488, 0x2489, 0x248A, 0x248B, 0x248C, 0x248D, 0x248E, 0x248F, 0x2490, 0x24EA, 0x24F5, 0x24F6,
    0x24F7, 0x24F8, 0x24F9, 0x24FA, 0x24FB, 0x24FC, 0x24FD, 0x24FF, 0x2776, 0x2777, 0x2778, 0x2779,
    0x277A, 0x277B, 0x277C, 0x277D, 0x277E, 0x2780, 0x2781, 0x2782, 0x2783, 0x2784, 0x2785, 0x2786,
    0x2787, 0x2788, 0x278A, 0x278B, 0x278C, 0x278D, 0x278E, 0x278F, 0x2790, 0x2791, 0x2792,
    0x10A40, 0x10A41, 0x10A42, 0x10A43, 0x10E60, 0x10E61, 0x10E62, 0x10E63, 0x10E64, 0x10E65,
    0x10E66, 0x10E67, 0x10E68, 0x11052, 0x11053, 0x11054, 0x11055, 0x11056, 0x11057, 0x11058,
    0x11059, 0x1105A, 0x1F100, 0x1F101, 0x1F102, 0x1F103, 0x1F104, 0x1F105, 0x1F106, 0x1F107,
    0x1F108, 0x1F109, 0x1F10A,
];

/// `str.isdigit()` for a single character (finding H-R3-9): true for any
/// Unicode decimal digit (`crate::pystr::unicode_decimal_digit` -- the
/// canonical per-codepoint `Nd`-value primitive behind `int(str)`'s own
/// digit grammar, PORTING.md §3b; this module previously kept its own copy
/// of that table, generated the same way, now deleted in favour of the
/// shared one -- see `rust/DEVIATIONS.md`), the only kind `int(str)` can
/// actually parse, OR one of [`UNICODE_DIGIT_NOT_DECIMAL`]'s
/// `isdigit()`-but-not-decimal code points, which `int(str)` cannot.
fn is_python_isdigit_char(c: char) -> bool {
    crate::pystr::unicode_decimal_digit(c).is_some()
        || UNICODE_DIGIT_NOT_DECIMAL.binary_search(&(c as u32)).is_ok()
}

/// `str.isdigit()` for a whole filename stem (finding H-R3-9): non-empty,
/// every character a digit under [`is_python_isdigit_char`]. Mirrors
/// `Path.stem.isdigit()`.
fn python_stem_isdigit(stem: &str) -> bool {
    !stem.is_empty() && stem.chars().all(is_python_isdigit_char)
}

/// A CPython built-in exception (`AttributeError`, `TypeError`, `ValueError`)
/// that escapes `Commit.from_dict`'s caller, `validate_op` or
/// `build_connection_fields` uncaught (PORTING.md §3.5). It is deliberately
/// not `InvalidInput`, so its SCOPE matches Python's (§3d):
/// [`receive_commit`] propagates it instead of recording a rejection (the
/// exception leaves `receive_commit` before `_reject`: no rejected record,
/// no audit, and `TeamSync`'s receive loop ends the session), and `fold`
/// aborts instead of skipping the op (its `except InvalidInput` does not
/// catch it). `detail` names the Python exception.
pub(crate) fn uncaught_builtin(exception: &'static str) -> Error {
    Error::state("team_uncaught_exception").with_detail(exception)
}

/// Whether a [`Commit::from_dict`] error stands for Python's LATER
/// `canonical_json` `TypeError` (an op with a non-string key): Python's
/// `from_dict` itself succeeded, so a caller that inspects the commit before
/// hashing it (`_handle_commit`'s env-id check) still runs first.
pub(crate) fn raises_only_when_canonicalized(error: &Error) -> bool {
    error.reason == "team_uncaught_exception" && error.detail == "TypeError"
}

/// `int(value)` for a decoded commit field (`author_seq`, a `seen` value):
/// CPython's grammar and unbounded precision ([`PyInt::coerce_from_json`]);
/// `ValueError`/`TypeError` are `commit_malformed` (caught by `from_dict`),
/// while `int(float("inf"))`'s `OverflowError` -- a JSON literal such as
/// `1e400` decodes to infinity -- escapes `from_dict` uncaught.
fn python_int_field(value: &Value) -> Result<PyInt> {
    if let Value::Number(n) = value
        && pyjson::is_float_literal(n.as_str())
        && n.as_str().parse::<f64>().is_ok_and(f64::is_infinite)
    {
        return Err(uncaught_builtin("OverflowError"));
    }
    PyInt::coerce_from_json(value).ok_or_else(|| Error::invalid_input("commit_malformed"))
}

/// CPython 3.12 `int(str)` for one `Hlc` half: the canonical grammar
/// (`crate::pystr::int_from_str_decimal_limited`, PORTING.md §3b --
/// `int()`-specific whitespace, sign, `_` separators, Unicode `Nd` digits and
/// the interpreter's 4300-digit conversion limit), at Python's unbounded
/// precision. `None` is CPython's `ValueError`.
fn python_int_parse(raw: &str) -> Option<PyInt> {
    let decimal = crate::pystr::int_from_str_decimal_limited(raw)?;
    decimal.parse::<num_bigint::BigInt>().ok().map(PyInt)
}

fn b64decode_strict(text: &str) -> std::result::Result<Vec<u8>, ()> {
    use base64::Engine;
    use base64::alphabet;
    use base64::engine::{GeneralPurpose, GeneralPurposeConfig};
    use std::sync::OnceLock;
    // Same leniency as `sshwire.rs`'s strict engine (PORTING.md task note):
    // Python's `base64.b64decode(s, validate=True)` rejects non-alphabet
    // characters and bad padding, but does not check that the unused low
    // bits of the last symbol are zero.
    static ENGINE: OnceLock<GeneralPurpose> = OnceLock::new();
    let engine = ENGINE.get_or_init(|| {
        GeneralPurpose::new(
            &alphabet::STANDARD,
            GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
        )
    });
    engine.decode(text).map_err(|_| ())
}

// ------------------------------------------------------------------------ HLC
/// Hybrid logical clock (docs/team-sync.md section 5.2). Port of
/// `zeropw.team.commit.Hlc`.
///
/// `tick` is called when this node authors a new commit; `observe` is
/// called whenever a commit (local or remote) with a given `hlc` string is
/// learned about, so a later `tick` always sorts after everything this node
/// has seen. The rendered form is `"<wall_ms>-<counter:04d>"`; total order
/// (section 7.1) compares the *parsed* `(wall_ms, counter)` pair, not the
/// string, since a wall-clock component can exceed 9999 and would then sort
/// incorrectly as text.
///
/// `wall_ms`/`counter` are exact Python integers ([`PyInt`]): `Hlc.parse`'s
/// `int()` has no magnitude bound, `tick`'s `self.counter += 1` never
/// overflows, and every comparison is exact at any magnitude.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hlc {
    pub wall_ms: PyInt,
    pub counter: PyInt,
}

impl Default for Hlc {
    fn default() -> Self {
        Hlc::new(0, 0)
    }
}

impl Hlc {
    pub fn new(wall_ms: impl Into<PyInt>, counter: impl Into<PyInt>) -> Self {
        Hlc {
            wall_ms: wall_ms.into(),
            counter: counter.into(),
        }
    }

    /// `Hlc.parse` (a `@staticmethod` in Python): `value.split("-")` into
    /// exactly two halves, each through CPython's `int(str)` grammar
    /// ([`python_int_parse`]), then `wall_ms < 0 or counter < 0` rejected.
    pub fn parse(value: &str) -> Result<(PyInt, PyInt)> {
        let bad = || Error::invalid_input("hlc_malformed");
        let parts: Vec<&str> = value.split('-').collect();
        if parts.len() != 2 {
            return Err(bad());
        }
        let wall_ms = python_int_parse(parts[0]).ok_or_else(bad)?;
        let counter = python_int_parse(parts[1]).ok_or_else(bad)?;
        if wall_ms < 0 || counter < 0 {
            return Err(bad());
        }
        Ok((wall_ms, counter))
    }

    /// `Hlc.render`: `f"{self.wall_ms}-{self.counter:04d}"`.
    pub fn render(&self) -> String {
        format!("{}-{:04}", self.wall_ms, self.counter)
    }

    /// `Hlc.observe`: raise this clock to at least `remote` (section 5.2).
    pub fn observe(&mut self, remote: &str) -> Result<()> {
        let (remote_wall, remote_counter) = Hlc::parse(remote)?;
        if remote_wall > self.wall_ms {
            self.wall_ms = remote_wall;
            self.counter = remote_counter;
        } else if remote_wall == self.wall_ms {
            self.counter = self.counter.clone().max(remote_counter);
        }
        Ok(())
    }

    /// `Hlc.tick`: advance the clock for a new local commit and return its
    /// rendered `hlc`. `now_ms=None` uses the system clock, like Python's
    /// `int(time.time() * 1000)`. `self.counter += 1` is exact at any
    /// magnitude, as Python's `int` is.
    pub fn tick(&mut self, now_ms_value: Option<i64>) -> String {
        let now_ms_value = PyInt::from(now_ms_value.unwrap_or_else(now_ms));
        if now_ms_value > self.wall_ms {
            self.wall_ms = now_ms_value;
            self.counter = PyInt::zero();
        } else {
            self.counter = &self.counter + 1;
        }
        self.render()
    }
}

/// `zeropw.team.commit.now_ms` with the default `clock=time.time`.
pub fn now_ms() -> i64 {
    (crate::store::now() * 1000.0) as i64
}

/// Total order key (docs/team-sync.md section 7.1): `(hlc, author)` as a
/// numeric/text tuple. Port of `order_key`.
pub fn order_key(commit: &Commit) -> Result<(PyInt, PyInt, String)> {
    let (wall_ms, counter) = Hlc::parse(&commit.hlc)?;
    Ok((wall_ms, counter, commit.author.clone()))
}

/// Port of `sort_total_order`.
pub fn sort_total_order(commits: Vec<Commit>) -> Result<Vec<Commit>> {
    let mut keyed: Vec<((PyInt, PyInt, String), Commit)> = Vec::with_capacity(commits.len());
    for commit in commits {
        let key = order_key(&commit)?;
        keyed.push((key, commit));
    }
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(keyed.into_iter().map(|(_, c)| c).collect())
}

// --------------------------------------------------------------------- Commit
/// Port of `zeropw.team.commit.Commit`.
#[derive(Clone, Debug, PartialEq)]
pub struct Commit {
    pub format: String,
    pub env_id: String,
    pub author: String,
    /// Python's `int(data["author_seq"])`, exact at any magnitude.
    pub author_seq: PyInt,
    pub hlc: String,
    pub seen: BTreeMap<String, PyInt>,
    pub ops: Vec<Value>,
    /// Base64 Ed25519 signature, empty until signed.
    pub sig: String,
}

impl Commit {
    fn canonical_dict(&self, include_sig: bool) -> Value {
        let mut m = Map::new();
        m.insert("format".into(), Value::String(self.format.clone()));
        m.insert("env_id".into(), Value::String(self.env_id.clone()));
        m.insert("author".into(), Value::String(self.author.clone()));
        m.insert("author_seq".into(), self.author_seq.value());
        m.insert("hlc".into(), Value::String(self.hlc.clone()));
        let seen: Map<String, Value> = self
            .seen
            .iter()
            .map(|(k, v)| (k.clone(), v.value()))
            .collect();
        m.insert("seen".into(), Value::Object(seen));
        m.insert("ops".into(), Value::Array(self.ops.clone()));
        if include_sig {
            m.insert("sig".into(), Value::String(self.sig.clone()));
        }
        Value::Object(m)
    }

    /// `Commit.canonical_json`: the exact bytes that get signed
    /// (`include_sig=False`) and hashed (`include_sig=True`).
    pub fn canonical_json(&self, include_sig: bool) -> Result<Vec<u8>> {
        Ok(pyjson::dumps(
            &self.canonical_dict(include_sig),
            DumpOptions::compact_sorted(),
        )?
        .into_bytes())
    }

    /// `Commit.hash` (a property in Python): SHA-256 hex of the canonical
    /// JSON *including* `sig` (section 5.2).
    pub fn hash(&self) -> Result<String> {
        use sha2::{Digest, Sha256};
        let bytes = self.canonical_json(true)?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    /// `Commit.to_dict`.
    pub fn to_dict(&self) -> Value {
        self.canonical_dict(true)
    }

    /// `Commit.from_dict`. `KeyError | TypeError | ValueError` all become
    /// `InvalidInput("commit_malformed")`. `format`/`env_id`/`author`/`hlc`/
    /// `sig` go through [`python_str_coerce`], matching Python's
    /// `str(data["..."])`: a *missing* key still raises (`commit_malformed`,
    /// Python's `KeyError`), but a present non-string value (a number,
    /// `true`/`false`, `null`, ...) is coerced to text rather than rejected
    /// (finding H-6's peer-key ruling: this port's own writers never emit a
    /// non-string value for these fields, but a peer's own signer is not
    /// required to route through this crate's `sign_commit` at all, so the
    /// shape it emits is not something the receiving node's key ever
    /// authenticates).
    pub fn from_dict(data: &Value) -> Result<Commit> {
        let bad = || Error::invalid_input("commit_malformed");
        let obj = data.as_object().ok_or_else(bad)?;
        // `ops = tuple(dict(op) for op in data["ops"])` runs before every
        // other field. `data["ops"]` may be any iterable (a string yields
        // its characters, a dict its keys -- so `""`/`{}` are an empty
        // tuple), and each element goes through `dict(...)`; every failure
        // there is a caught `TypeError`/`ValueError`.
        //
        // Finding H-R3-3: a hashable non-string pair key is kept by
        // `dict()`, so `from_dict` still succeeds in Python once the other
        // fields parse; the `TypeError` comes later, from every
        // `canonical_json`/`hash` of the commit. It is reported after the
        // remaining fields as [`uncaught_builtin`] (see
        // [`raises_only_when_canonicalized`]) rather than `commit_malformed`.
        let raw_ops: Vec<Value> = match obj.get("ops").ok_or_else(bad)? {
            Value::Array(items) => items.clone(),
            Value::String(text) => text.chars().map(|c| Value::String(c.to_string())).collect(),
            Value::Object(map) => map.keys().cloned().map(Value::String).collect(),
            Value::Null | Value::Bool(_) | Value::Number(_) => return Err(bad()),
        };
        let mut non_string_op_key = false;
        let mut ops: Vec<Value> = Vec::with_capacity(raw_ops.len());
        for op in &raw_ops {
            let pairs = python_dict_pairs_checked(op).map_err(|_| bad())?;
            let mut out = Map::new();
            for (k, v) in pairs {
                match k {
                    Value::String(s) => {
                        out.insert(s, v);
                    }
                    _ => non_string_op_key = true,
                }
            }
            ops.push(Value::Object(out));
        }
        let str_field =
            |key: &str| -> Result<String> { obj.get(key).map(python_str_coerce).ok_or_else(bad) };
        let format = str_field("format")?;
        let env_id = str_field("env_id")?;
        let author = str_field("author")?;
        let author_seq = python_int_field(obj.get("author_seq").ok_or_else(bad)?)?;
        let hlc = str_field("hlc")?;
        // `dict(data.get("seen") or {})`: a *falsy* `seen` (absent, `null`,
        // `0`, `""`, `[]`, `{}`, `false`) is treated as `{}` with no error;
        // otherwise `dict(x)` accepts a mapping directly or any iterable of
        // two-element pairs (finding H-6) -- [`python_dict_pairs`].
        let seen = match obj.get("seen") {
            None => BTreeMap::new(),
            Some(v) if json_falsy(v) => BTreeMap::new(),
            Some(v) => {
                let pairs = python_dict_pairs(v).ok_or_else(bad)?;
                // `seen={str(k): int(v) for k, v in dict(pairs).items()}`:
                // `dict(pairs)` runs FIRST and completely on its own
                // (finding H-R5-5) -- a `list`/`dict` key is Python's own
                // UNHASHABLE type, an uncaught `TypeError` from `dict()`
                // itself (`commit_malformed` per PORTING.md §3.5, not the
                // silent string-coercion this used to give every key
                // regardless of type); a hashable key collides with any
                // other Python-equal one (`bool`/`int`/`float` compare and
                // hash purely by NUMERIC value -- confirmed against real
                // `python3.12`: `dict([(True, 1), (1, 2)]) == {True: 2}`,
                // one entry, keeping the FIRST key's representation but the
                // LAST value written for it). Only once THAT merge is
                // fully resolved does `str(k)`/`int(v)` run, once per
                // SURVIVING pair -- a value on a pair some later pair's
                // same key discards is never passed through `int()` at
                // all, so it cannot fail validation either (this also
                // fixes a related pre-existing bug: the previous
                // per-pair-in-arrival-order `python_int_coerce` call could
                // wrongly reject a `seen` value that Python's real
                // `dict()`-first order would have discarded before ever
                // looking at it).
                let mut merged: Vec<(Value, Value)> = Vec::new();
                for (k, v) in pairs {
                    if !dict_key_is_hashable(&k) {
                        return Err(bad());
                    }
                    match merged.iter_mut().find(|(ek, _)| dict_keys_equal(ek, &k)) {
                        Some(existing) => existing.1 = v,
                        None => merged.push((k, v)),
                    }
                }
                let mut out = BTreeMap::new();
                for (k, v) in merged {
                    let key = python_str_coerce(&k);
                    let n = python_int_field(&v)?;
                    out.insert(key, n);
                }
                out
            }
        };
        let sig = str_field("sig")?;
        if non_string_op_key {
            return Err(uncaught_builtin("TypeError"));
        }
        Ok(Commit {
            format,
            env_id,
            author,
            author_seq,
            hlc,
            seen,
            ops,
            sig,
        })
    }
}

/// `str(k)` for a JSON value used as a `seen`-pair key (finding H-6): a
/// string is used as-is; the other JSON scalars use CPython's `str()` text.
/// A list/dict value renders as CPython's actual `repr()` text via
/// [`crate::pystr::repr_value`] (finding H-R5-1: `[`/`]`/`{`/`}`
/// delimiters, `, ` / `: ` separators, **insertion** order, single-quoted
/// strings, `None`/`True`/`False`) -- NOT `pyjson`'s compact/sorted JSON
/// form, which this function used to fall back to. That distinction is
/// observable, not academic: a peer-signed `agree_pub` (etc.) shaped as a
/// dict whose *JSON key order* differs from its *Python insertion order*
/// (dicts built by non-literal code, e.g. from a prior key deletion and
/// re-insertion, keep insertion order while `json.dumps`'s wire form need
/// not reflect it in the way a hand-built Rust equivalent would guess) can
/// `repr()` to valid lenient base64 in Python while the sorted-JSON
/// approximation decoded to different bytes in Rust; and a value containing
/// a literal non-ASCII character `repr()`s with that character copied
/// through literally (Python `str.encode('ascii')`-equivalent then fails
/// inside `b64decode`), whereas `ensure_ascii` JSON escaping made the same
/// input silently ASCII-safe and thus wrongly acceptable in Rust. See
/// `rust/DEVIATIONS.md`'s corrected H-R4-1 row.
///
/// Exposed crate-wide (not just within this module) because
/// `identity.rs`'s `DeviceRecord::from_dict` needs the identical `str(...)`
/// coercion Python applies to `sign_pub`/`agree_pub`/`sig` before its own
/// lenient base64 decode (finding H-R4-1); per PORTING.md §3b this is the
/// one canonical place for that coercion (which itself defers to
/// [`crate::pystr::repr_value`], the crate's one canonical container-`repr`,
/// for the `Array`/`Object` cases), reused rather than copied.
pub(crate) fn python_str_coerce(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Bool(b) => (if *b { "True" } else { "False" }).to_string(),
        Value::Null => "None".to_string(),
        Value::Number(n) => {
            if pyjson::is_float_literal(n.as_str()) {
                n.as_f64()
                    .map(pyjson::python_float_repr)
                    .unwrap_or_else(|| n.to_string())
            } else {
                n.to_string()
            }
        }
        Value::Array(_) | Value::Object(_) => crate::pystr::repr_value(value),
    }
}

/// `dict(x)` for the shapes actually reachable through a signed commit's
/// `seen` field (finding H-6): a JSON object (used directly, matching
/// Python's `dict(mapping)`), or a JSON array of two-element iterables
/// (matching Python's `dict(iterable_of_pairs)`, e.g. `[["<fp>", 3]]`).
/// Each pair can be an array, a two-character string (`dict(["ab"]) ==
/// {"a": "b"}`), or a two-key object (iteration yields its keys). Anything
/// else that is not iterable at all in Python (`dict(5)`) raises `TypeError`
/// (uncaught, `commit_malformed` per PORTING.md §3.5), returning `None`.
pub(crate) fn python_dict_pairs(value: &Value) -> Option<Vec<(Value, Value)>> {
    match value {
        Value::Object(m) => Some(
            m.iter()
                .map(|(k, v)| (Value::String(k.clone()), v.clone()))
                .collect(),
        ),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::Array(pair) if pair.len() == 2 => {
                        out.push((pair[0].clone(), pair[1].clone()));
                    }
                    Value::String(s) if s.chars().count() == 2 => {
                        let mut chars = s.chars();
                        let k = chars.next().expect("len 2").to_string();
                        let v = chars.next().expect("len 2").to_string();
                        out.push((Value::String(k), Value::String(v)));
                    }
                    Value::Object(map) if map.len() == 2 => {
                        let mut keys = map.keys();
                        out.push((
                            Value::String(keys.next()?.clone()),
                            Value::String(keys.next()?.clone()),
                        ));
                    }
                    _ => return None,
                }
            }
            Some(out)
        }
        _ => None,
    }
}

/// Which built-in exception CPython's `dict(x)` raises for a JSON value it
/// cannot build a dict from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DictError {
    /// `x`, or one of its elements, is not iterable; or a key is
    /// unhashable.
    TypeError,
    /// An element is iterable but not of length 2 (a non-empty string `x`
    /// iterates one-character elements).
    ValueError,
}

/// `dict(x)` with CPython's exact failure classification, element by
/// element in order (the first failing element decides): a non-iterable
/// element is `TypeError`, an element of the wrong length `ValueError`, and
/// an unhashable key `TypeError`.
pub(crate) fn python_dict_pairs_checked(
    value: &Value,
) -> std::result::Result<Vec<(Value, Value)>, DictError> {
    match value {
        Value::Object(m) => Ok(m
            .iter()
            .map(|(k, v)| (Value::String(k.clone()), v.clone()))
            .collect()),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let pair = match item {
                    Value::Array(pair) if pair.len() == 2 => (pair[0].clone(), pair[1].clone()),
                    Value::String(s) if s.chars().count() == 2 => {
                        let mut chars = s.chars().map(|c| Value::String(c.to_string()));
                        match (chars.next(), chars.next()) {
                            (Some(k), Some(v)) => (k, v),
                            _ => return Err(DictError::ValueError),
                        }
                    }
                    Value::Object(map) if map.len() == 2 => {
                        let mut keys = map.keys().map(|k| Value::String(k.clone()));
                        match (keys.next(), keys.next()) {
                            (Some(k), Some(v)) => (k, v),
                            _ => return Err(DictError::ValueError),
                        }
                    }
                    Value::Array(_) | Value::String(_) | Value::Object(_) => {
                        return Err(DictError::ValueError);
                    }
                    Value::Null | Value::Bool(_) | Value::Number(_) => {
                        return Err(DictError::TypeError);
                    }
                };
                if !dict_key_is_hashable(&pair.0) {
                    return Err(DictError::TypeError);
                }
                out.push(pair);
            }
            Ok(out)
        }
        Value::String(s) if s.is_empty() => Ok(Vec::new()),
        Value::String(_) => Err(DictError::ValueError),
        Value::Null | Value::Bool(_) | Value::Number(_) => Err(DictError::TypeError),
    }
}

/// Whether a JSON value is Python-HASHABLE when used as a `dict`/`seen`-pair
/// key (finding H-R5-5): everything except a `list`/`dict` (Python's own
/// unhashable types -- confirmed against real `python3.12`:
/// `dict([([1], 1)])` raises `TypeError: unhashable type: 'list'`).
pub(crate) fn dict_key_is_hashable(v: &Value) -> bool {
    !matches!(v, Value::Array(_) | Value::Object(_))
}

/// Python `==`/hash identity for two `dict` keys (finding H-R5-5): `None`
/// only equals `None`; a `str` only equals an identical `str`; a
/// `bool`/`int`/`float` all compare (and hash) by pure NUMERIC value, so
/// they collide across type -- confirmed against real `python3.12`:
/// `True == 1 == 1.0` and `False == 0 == 0.0`. A `list`/`dict` never
/// reaches this function (see [`dict_key_is_hashable`], checked first).
pub(crate) fn dict_keys_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::String(x), Value::String(y)) => x == y,
        _ => match (dict_key_numeric_value(a), dict_key_numeric_value(b)) {
            (Some(KeyNumber::Integer(x)), Some(KeyNumber::Integer(y))) => x == y,
            (Some(KeyNumber::Float(x)), Some(KeyNumber::Float(y))) => x == y,
            (Some(KeyNumber::Integer(x)), Some(KeyNumber::Float(y)))
            | (Some(KeyNumber::Float(y)), Some(KeyNumber::Integer(x))) => {
                float_exact_integer(y).is_some_and(|integer| x == integer)
            }
            _ => false,
        },
    }
}

enum KeyNumber {
    Integer(num_bigint::BigInt),
    Float(f64),
}

/// Preserve Python's arbitrary-precision integer keys rather than rounding
/// both operands through f64 (which merges distinct keys above 2^53).
fn dict_key_numeric_value(v: &Value) -> Option<KeyNumber> {
    match v {
        Value::Bool(b) => Some(KeyNumber::Integer(num_bigint::BigInt::from(u8::from(*b)))),
        Value::Number(n) if crate::pyjson::is_float_literal(n.as_str()) => {
            n.as_str().parse().ok().map(KeyNumber::Float)
        }
        Value::Number(n) => {
            num_bigint::BigInt::parse_bytes(n.as_str().as_bytes(), 10).map(KeyNumber::Integer)
        }
        _ => None,
    }
}

/// The exact integer represented by a finite binary64 float, if integral.
/// This mirrors Python int/float equality without lossy integer conversion.
fn float_exact_integer(value: f64) -> Option<num_bigint::BigInt> {
    if !value.is_finite() || value.fract() != 0.0 {
        return None;
    }
    if value == 0.0 {
        return Some(num_bigint::BigInt::from(0));
    }
    let bits = value.to_bits();
    let exponent = ((bits >> 52) & 0x7ff) as i32 - 1023 - 52;
    let mantissa = (bits & ((1_u64 << 52) - 1)) | (1_u64 << 52);
    let mut integer = num_bigint::BigInt::from(mantissa);
    if exponent >= 0 {
        integer <<= exponent as usize;
    } else {
        integer >>= (-exponent) as usize;
    }
    if bits >> 63 != 0 {
        integer = -integer;
    }
    Some(integer)
}

/// `zeropw.team.commit.sign_commit`: build, format-validate and sign a new
/// commit (docs/team-sync.md section 5.2). An op that folding would skip
/// for its depth or connection id is refused (issue #54).
pub fn sign_commit(
    device: &DeviceKey,
    env_id: &str,
    author_seq: impl Into<PyInt>,
    hlc: &str,
    seen: &BTreeMap<String, PyInt>,
    ops: Vec<Value>,
) -> Result<Commit> {
    for op in &ops {
        check_authored_op(op)?;
    }
    validate_ops(&ops)?;
    let author_seq = author_seq.into();
    let author = device.fingerprint()?;
    let unsigned = Commit {
        format: COMMIT_FORMAT.to_string(),
        env_id: env_id.to_string(),
        author,
        author_seq,
        hlc: hlc.to_string(),
        seen: seen.clone(),
        ops,
        sig: String::new(),
    };
    let to_sign = unsigned.canonical_json(false)?;
    let sig = device.sign(&to_sign)?;
    Ok(Commit {
        sig: pybase64::b64encode(&sig),
        ..unsigned
    })
}

/// `zeropw.team.commit.verify_commit`: true iff `commit` is well-formed and
/// validly signed by `author_record`. Never raises.
pub fn verify_commit(commit: &Commit, author_record: &DeviceRecord) -> bool {
    if commit.format != COMMIT_FORMAT {
        return false;
    }
    if author_record.fingerprint() != commit.author {
        return false;
    }
    let sig = match b64decode_strict(&commit.sig) {
        Ok(s) => s,
        Err(()) => return false,
    };
    if Hlc::parse(&commit.hlc).is_err() {
        return false;
    }
    if validate_ops(&commit.ops).is_err() {
        return false;
    }
    let to_verify = match commit.canonical_json(false) {
        Ok(b) => b,
        Err(_) => return false,
    };
    // Not memoized: a commit is verified once, on receipt.
    ed25519::verify(&author_record.sign_pub, &to_verify, &sig)
}

// -------------------------------------------------------------- env ids
fn env_root(env_id: &str) -> String {
    format!("team/{env_id}")
}

/// `zeropw.team.commit.new_env_id`.
pub fn new_env_id(owner_fingerprint: &str) -> Result<String> {
    if !is_fingerprint(owner_fingerprint) {
        return Err(Error::invalid_input("invalid_fingerprint"));
    }
    let random = random_bytes(ENV_ID_RANDOM_HEX_LEN / 2);
    Ok(format!("{owner_fingerprint}-{}", hex::encode(random)))
}

/// `zeropw.team.commit.env_owner_fingerprint`: the fingerprint bound into
/// `env_id` at creation, or `InvalidInput` if malformed.
pub fn env_owner_fingerprint(env_id: &str) -> Result<String> {
    let bad = || Error::invalid_input("invalid_env_id");
    if !env_id.is_ascii() {
        return Err(bad());
    }
    let bytes = env_id.as_bytes();
    if bytes.len() != 26 + 1 + ENV_ID_RANDOM_HEX_LEN {
        return Err(bad());
    }
    let fp_part = &bytes[..26];
    if bytes[26] != b'-' {
        return Err(bad());
    }
    let hex_part = &bytes[27..];
    if !fp_part
        .iter()
        .all(|&b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
    {
        return Err(bad());
    }
    if !hex_part
        .iter()
        .all(|&b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(bad());
    }
    // Safe: `env_id.is_ascii()` was checked above, so every byte offset is a
    // char boundary.
    Ok(env_id[..26].to_string())
}

/// `zeropw.team.commit.valid_env_id`.
pub fn valid_env_id(env_id: &str) -> bool {
    env_owner_fingerprint(env_id).is_ok()
}

// ------------------------------------------------------------------- op shapes
fn valid_name_field(value: Option<&Value>, max_len: usize) -> bool {
    matches!(value, Some(Value::String(s)) if !s.is_empty() && s.chars().count() <= max_len && !control_re_search(s))
}

fn valid_fingerprint(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::String(s)) if is_fingerprint(s))
}

fn valid_token(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::String(s)) if is_token(s))
}

fn valid_wrap(value: &Value) -> bool {
    match value.as_object() {
        Some(obj) => ["eph_pub", "nonce", "ciphertext"]
            .iter()
            .all(|k| matches!(obj.get(*k), Some(Value::String(_)))),
        None => false,
    }
}

fn valid_wraps(value: Option<&Value>) -> bool {
    match value.and_then(Value::as_object) {
        Some(obj) if !obj.is_empty() => obj
            .iter()
            .all(|(fp, wrap)| is_fingerprint(fp) && valid_wrap(wrap)),
        _ => false,
    }
}

/// A JSON array's items as strings, with any non-string item replaced by a
/// sentinel that cannot equal any real value (`HTTP_METHODS`, path
/// prefixes, ...) -- Python's `tuple(value)` never raises here (only a
/// non-iterable `value` would), and the *type* check on each item then
/// happens later, inside the target policy dataclass's own validation
/// (e.g. `method not in HTTP_METHODS` is `True`, hence rejected, for any
/// non-string `method`). The sentinel reproduces that "never matches"
/// outcome without needing a parallel `Vec<Value>` item type everywhere.
fn json_strings_lossy(items: &[Value]) -> Vec<String> {
    items
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .unwrap_or_else(|| "\u{0}non-string-item".to_string())
        })
        .collect()
}

/// Python `tuple(x)` for the JSON shapes `_build_http_scope`/
/// `_build_ssh_target` can hand it (finding H-5): a list is iterated
/// element-by-element (non-string elements become a sentinel that can never
/// match a valid method/prefix/host-key line, matching Python's `tuple`
/// preserving whatever non-string element it held -- see
/// [`json_strings_lossy`]); a *string* is iterated character-by-character
/// (Python iterates a `str` by codepoint); a JSON object is iterated over
/// its keys (Python `dict` iteration, insertion order). Anything else
/// (a number, a bool) is not iterable in Python and `tuple(x)` raises
/// `TypeError` -- `None` here, for the caller to map to its own wrapped
/// reason (`invalid_http_scope`/`invalid_ssh_target`), matching the
/// `except (KeyError, TypeError)` around the real Python call site.
fn python_iterable_strings(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::Array(items) => Some(json_strings_lossy(items)),
        Value::String(s) => Some(s.chars().map(|c| c.to_string()).collect()),
        Value::Object(m) => Some(m.keys().cloned().collect()),
        Value::Number(_) | Value::Bool(_) | Value::Null => None,
    }
}

fn opt_string(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

/// `raw_ca_file` is the op's own `http_target.ca_file` JSON value verbatim
/// (finding H-4): `HttpTarget.ca_file` has no `isinstance` check in Python,
/// so a non-string value (an int, a list, ...) validates and is stored
/// exactly as given -- `t.ca_file` (`Option<String>`) can't hold that, so
/// the caller reads the raw value back off the original op instead of
/// going through the validated, `String`-typed field.
fn http_target_value(t: &policy::HttpTarget, raw_ca_file: &Value) -> Value {
    json!({"scheme": t.scheme, "host": t.host, "port": t.port, "ca_file": raw_ca_file,
          "allow_private_network": t.allow_private_network})
}
/// `raw_value_prefix`: see [`http_target_value`]'s doc comment --
/// `HttpAuth.value_prefix` is the same kind of unchecked-optional-field
/// case (finding H-4). `raw_basic_username` is the analogous raw
/// passthrough for `basic_username` (finding H-R5-3): Python keeps
/// whatever value the op provided verbatim (a validated string, or an
/// accepted colon-free list/dict when `mode == "basic"`, or an entirely
/// unchecked value when `mode != "basic"`), which the typed
/// `HttpAuth::basic_username: Option<String>` field cannot hold for a
/// container -- so the document is built from the original JSON value,
/// not from `a.basic_username`.
///
/// `raw_header_name` (finding X-4, correcting this row's previous
/// `a.header_name`-only rendering): Python's `HttpAuth.__post_init__` only
/// ever inspects `header_name` when `mode == "header"`
/// (`if self.mode == "header": ...`), so for every other mode it is kept
/// completely verbatim -- confirmed against real `python3.12`,
/// `build_connection_fields` with `{"mode": "bearer", "header_name":
/// ["X-Foo"]}` returns `header_name: ["X-Foo"]`, not `None`. `build_http_auth`
/// (below) uses the local `opt_string`, which collapses any non-string
/// `header_name` to `None` regardless of mode -- correct for the
/// `mode == "header"` case (`HttpAuth::new` then raises the documented
/// `invalid_header_name` there, matching Python's own uncaught `TypeError`
/// substitution, PORTING.md §3.5) but WRONG for every other mode, where
/// Python never touches the field at all. `a.header_name` (the typed,
/// `opt_string`-collapsed field) is therefore only trustworthy when
/// `mode == "header"` -- exactly when it equals the raw JSON value anyway,
/// since a non-`mode == "header"` divergence would already have made
/// `build_http_auth` reject the op before reaching here. So, like the other
/// three raw fields, the document is built from the original JSON value
/// unconditionally, not from `a.header_name`.
fn http_auth_value(
    raw_header_name: &Value,
    raw_value_prefix: &Value,
    raw_basic_username: &Value,
    a: &policy::HttpAuth,
) -> Value {
    json!({"mode": a.mode, "header_name": raw_header_name, "value_prefix": raw_value_prefix,
          "basic_username": raw_basic_username})
}
fn http_scope_value(s: &policy::HttpScope) -> Value {
    json!({"methods": s.methods, "path_prefixes": s.path_prefixes, "confirm_methods": s.confirm_methods})
}
fn ssh_target_value(t: &policy::SshTarget) -> Value {
    json!({"host": t.host, "port": t.port, "username": t.username, "host_keys": t.host_keys})
}
/// `raw_program`: see [`http_target_value`]'s doc comment for the general
/// pattern -- `CliProfile.program` can be a peer-accepted truthy list/dict
/// (finding H-R5-2), which the typed `CliProfile::program: String` field
/// cannot hold, so the document is built from the op's original JSON value.
fn cli_profile_value(c: &policy::CliProfile, raw_program: &Value) -> Value {
    json!({"program": raw_program, "kind": c.kind, "base_url_env": c.base_url_env, "extra_env": c.extra_env})
}

/// `zeropw.team.commit._build_http_target`: `P.HttpTarget(scheme=...,
/// host=..., port=..., ca_file=value.get("ca_file"),
/// allow_private_network=value.get("allow_private_network", False))`.
///
/// `HttpTarget.__post_init__` (`policy.py`) checks, in order: `scheme`,
/// then `host` (format), then `port` (range), then `allow_private_network`
/// (must be a `bool`), then -- only once all of those pass -- whether the
/// resolved literal is blocked. Finding H-5: this builder used to check
/// `allow_private_network`'s type *before* the real scheme/host/port
/// validation ran (that only happened inside `policy::HttpTarget::new`
/// afterwards), so a bad scheme *and* a non-bool `allow_private_network`
/// wrongly surfaced as `invalid_allow_private_network` instead of Python's
/// `invalid_scheme`. Fixed by validating scheme/host/port and the address
/// block (via `HttpTarget::from_stored` + `require_allowed_literal`, in
/// that Python order) with a placeholder `allow_private_network`, *then*
/// checking the real value's type -- safe because
/// `HttpTarget::literal_block_reason` never actually reads
/// `allow_private_network` (see its doc comment in `policy.rs`), so the
/// placeholder cannot change which literal-block error (if any) surfaces.
///
/// Finding H-R2-3: `value.get("allow_private_network", False)` only
/// substitutes the default for an *absent* key -- a *present* `null`
/// (`value.get(...)` returns `None`, not the default) reaches
/// `HttpTarget.__post_init__`'s `isinstance(self.allow_private_network,
/// bool)` check and raises the documented `invalid_allow_private_network`
/// (confirmed against real `python3.12`). The round-1 fix collapsed `None`
/// (absent key) and `Some(Value::Null)` (present `null`) onto the same
/// `false` default, so a `connection.create`/`connection.update` op with
/// `"allow_private_network": null` was wrongly ACCEPTED and folded by this
/// port while Python rejected the whole commit
/// (`team_op_format_invalid_allow_private_network`) -- a permanent
/// document split from one admin peer op. Only `None` (the key is genuinely
/// absent from the JSON object) still defaults to `false`.
fn build_http_target(value: Option<&Value>) -> Result<Option<policy::HttpTarget>> {
    let value = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(v) => v,
    };
    let obj = value
        .as_object()
        .ok_or_else(|| Error::invalid_input("invalid_http_target"))?;
    if !(obj.contains_key("scheme") && obj.contains_key("host") && obj.contains_key("port")) {
        return Err(Error::invalid_input("invalid_http_target"));
    }
    let scheme = obj
        .get("scheme")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::invalid_input("invalid_scheme"))?;
    let host = obj
        .get("host")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::invalid_input("invalid_host"))?;
    let port = obj
        .get("port")
        .and_then(Value::as_i64)
        .ok_or_else(|| Error::invalid_input("invalid_port"))?;
    // Finding H-4: `HttpTarget.ca_file` has no `isinstance` check in Python,
    // so a non-string value validates and is stored verbatim; carried
    // through as the raw JSON value by the caller (`build_connection_fields`
    // reads it back off `args` directly), not lost here the way `opt_string`
    // would lose it.
    let ca_file = opt_string(obj.get("ca_file"));
    // Scheme/host/port only, in Python's `__post_init__` order, with no
    // literal-block check yet (`check_address=false`/`from_stored`).
    let mut target = policy::HttpTarget::from_stored(scheme, host, port, ca_file, false)?;
    let allow_private_network = match obj.get("allow_private_network") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(Error::invalid_input("invalid_allow_private_network")),
    };
    target.allow_private_network = allow_private_network;
    target.require_allowed_literal()?;
    Ok(Some(target))
}

/// `zeropw.team.commit._build_http_auth`.
fn build_http_auth(value: Option<&Value>) -> Result<Option<policy::HttpAuth>> {
    let value = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(v) => v,
    };
    let obj = value
        .as_object()
        .ok_or_else(|| Error::invalid_input("invalid_http_auth"))?;
    if !obj.contains_key("mode") {
        return Err(Error::invalid_input("invalid_http_auth"));
    }
    let mode = obj
        .get("mode")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::invalid_input("unsupported_auth_mode"))?;
    // `HttpAuth.__post_init__` after its mode check: `HEADER_NAME_RE.match(
    // header_name)` (mode "header") and `":" in basic_username` (mode
    // "basic") raise an uncaught `TypeError` for a truthy value of the
    // wrong type -- a non-string `header_name`, a non-iterable scalar
    // `basic_username` -- which `_build_http_auth`'s `except KeyError` does
    // not catch (findings H-R2-9b, H-R5-3).
    let truthy = |name: &str| obj.get(name).filter(|v| !json_falsy(v));
    match mode.as_str() {
        "header" if truthy("header_name").is_some_and(|v| !v.is_string()) => {
            return Err(uncaught_builtin("TypeError"));
        }
        "basic"
            if truthy("basic_username")
                .is_some_and(|v| matches!(v, Value::Number(_) | Value::Bool(_))) =>
        {
            return Err(uncaught_builtin("TypeError"));
        }
        _ => {}
    }
    // Finding H-R5-3: `basic_username` goes through
    // `policy::basic_username_decision` rather than `opt_string`, which
    // used to collapse ANY non-string value -- including a truthy,
    // colon-free list/dict, which Python accepts and folds verbatim -- to
    // `None` and so always rejected it as `invalid_basic_username`, a
    // permanent peer-reachable divergence under the coordinator's
    // commit-fields ruling (same shape as H-R5-2's `program`). The final
    // document's `basic_username` field is filled in from the RAW op value
    // by the caller (`build_connection_fields`), not from the placeholder
    // `HttpAuth::basic_username` this produces (PORTING.md §3b's
    // typed-field limit -- see `basic_username_decision`'s doc comment).
    Ok(Some(policy::HttpAuth::new(
        mode,
        opt_string(obj.get("header_name")),
        opt_string(obj.get("value_prefix")),
        policy::basic_username_decision(obj.get("basic_username")),
    )?))
}

/// `zeropw.team.commit._build_http_scope`:
/// `methods=tuple(value["methods"]) if value.get("methods") is not None
/// else None`, same for `path_prefixes`; `confirm_methods=tuple(value.get
/// ("confirm_methods") or ())`.
///
/// Finding H-5: a `methods`/`path_prefixes` that is present but not a JSON
/// array (a string, say) used to be rejected outright as
/// `invalid_http_scope`; Python instead runs `tuple(...)` on it (see
/// [`python_iterable_strings`]) and only *that* raises `TypeError` -> the
/// wrapped reason -- a string or object is iterable, so it becomes a tuple
/// of characters/keys that reaches `HttpScope.__post_init__`'s own checks
/// and fails with *their* reason (`invalid_method`/`invalid_path_prefix`),
/// not the wrapper's.
fn build_http_scope(value: Option<&Value>) -> Result<Option<policy::HttpScope>> {
    let value = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(v) => v,
    };
    let obj = value
        .as_object()
        .ok_or_else(|| Error::invalid_input("invalid_http_scope"))?;
    let wrap_err = || Error::invalid_input("invalid_http_scope");
    let methods = match obj.get("methods") {
        None | Some(Value::Null) => None,
        Some(v) => Some(python_iterable_strings(v).ok_or_else(wrap_err)?),
    };
    let path_prefixes = match obj.get("path_prefixes") {
        None | Some(Value::Null) => None,
        Some(v) => Some(python_iterable_strings(v).ok_or_else(wrap_err)?),
    };
    // `value.get("confirm_methods") or ()`: a *falsy* present value (`""`,
    // `[]`, `{}`, `0`, `false`) short-circuits to `()` without ever calling
    // `tuple()` on it, so (unlike `methods`/`path_prefixes`) a falsy
    // non-iterable like `0`/`false` is fine, not a `TypeError`.
    let confirm_methods = match obj.get("confirm_methods") {
        None => Vec::new(),
        Some(v) if json_falsy(v) => Vec::new(),
        Some(v) => python_iterable_strings(v).ok_or_else(wrap_err)?,
    };
    match policy::HttpScope::new(methods, path_prefixes, confirm_methods) {
        Ok(scope) => Ok(Some(scope)),
        // `prefix.startswith("/")` on the first prefix that does not pass
        // (finding H-R2-9a): a non-string one raises an uncaught
        // `AttributeError` (`_build_http_scope` catches only `KeyError`/
        // `TypeError`) instead of `invalid_path_prefix`.
        Err(error) if error.reason == "invalid_path_prefix" => {
            let first_bad = obj
                .get("path_prefixes")
                .and_then(Value::as_array)
                .and_then(|items| {
                    items.iter().find(|item| match item.as_str() {
                        Some(p) => !p.starts_with('/') || p.contains("..") || p.contains('?'),
                        None => true,
                    })
                });
            if first_bad.is_some_and(|item| !item.is_string()) {
                return Err(uncaught_builtin("AttributeError"));
            }
            Err(error)
        }
        Err(error) => Err(error),
    }
}

/// `zeropw.team.commit._build_ssh_target`.
fn build_ssh_target(value: Option<&Value>) -> Result<Option<policy::SshTarget>> {
    let value = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(v) => v,
    };
    let obj = value
        .as_object()
        .ok_or_else(|| Error::invalid_input("invalid_ssh_target"))?;
    if !(obj.contains_key("host")
        && obj.contains_key("port")
        && obj.contains_key("username")
        && obj.contains_key("host_keys"))
    {
        return Err(Error::invalid_input("invalid_ssh_target"));
    }
    let host = obj
        .get("host")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::invalid_input("invalid_host"))?;
    let port = obj
        .get("port")
        .and_then(Value::as_i64)
        .ok_or_else(|| Error::invalid_input("invalid_port"))?;
    let username = obj
        .get("username")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::invalid_input("invalid_ssh_username"))?;
    // `host_keys=tuple(value["host_keys"])`, unconditionally (finding H-5):
    // a non-array iterable (a string -> one-character elements, an object
    // -> its keys) is not rejected here the way it used to be; it reaches
    // `SshTarget::new`'s own per-element check and fails with *its* reason
    // (`unsupported_host_key`/`ssh_host_keys_required`), matching Python's
    // `tuple(str)`/`tuple(dict)` behaviour. Only a genuinely non-iterable
    // value (a number, a bool) is a Python `TypeError`, wrapped here as
    // `invalid_ssh_target`.
    let host_keys = python_iterable_strings(
        obj.get("host_keys")
            .ok_or_else(|| Error::invalid_input("invalid_ssh_target"))?,
    )
    .ok_or_else(|| Error::invalid_input("invalid_ssh_target"))?;
    Ok(Some(policy::SshTarget::new(
        host, port, username, host_keys,
    )?))
}

/// `zeropw.team.commit._build_cli_profile`.
///
/// Finding H-R4-3: Python's `_build_cli_profile` has two phases, and a
/// 2,925-case sweep found 1,507 cases where the ROUND-3 version of this
/// function picked a different `InvalidInput` reason than Python for the
/// exact same malformed op, because it checked fields in a different order:
///
/// 1. Constructor-argument evaluation (`value["program"]`, `value["kind"]`,
///    `value.get("base_url_env", ...)`, `dict(value.get("extra_env") or
///    {})`), left to right: a missing `"program"`/`"kind"` key, or a truthy
///    `extra_env` `dict(...)` cannot turn into pairs, all raise
///    `invalid_cli_profile` -- pre-empting EVERYTHING below, including an
///    otherwise-invalid `kind`/`program`, because Python evaluates every
///    argument before `CliProfile.__post_init__` (phase 2) ever runs
///    (confirmed against real `python3.12`: `kind="ftp", extra_env=5` is
///    `invalid_cli_profile` from `dict(5)`, not `invalid_cli_kind`).
/// 2. `__post_init__`, only once phase 1 fully succeeds, in this exact
///    order: `kind` membership, then `program` (falsy-or-NUL), then
///    `base_url_env` (`re.match`, an uncaught `TypeError` -- no
///    `isinstance` guard at all -- for ANY non-string value, unlike
///    `kind`/`program`, which tolerate a non-string via plain
///    membership/falsiness checks that never raise), then `extra_env`'s
///    per-entry key-then-value checks in document order (finding H-R3-5),
///    where a non-string KEY is `re.match`'s same uncaught `TypeError` --
///    but only once every entry before it has already passed, since
///    `dict()` itself accepts a non-string key just fine (finding H-6):
///    confirmed `kind="ftp", extra_env=[[1,"x"]]` is `invalid_cli_kind`
///    (kind fails before the entries loop is ever reached), but
///    `kind="http", extra_env=[[1,"x"],["A","y"]]` is `invalid_cli_profile`
///    (kind/program/base_url_env all pass, so `__post_init__` reaches the
///    entries loop and its first entry's non-string key raises there).
///
/// This mirrors [`policy::CliProfile::from_value`]'s already-reviewed fix
/// for the same two phases on the stored-document loading path (findings
/// D-R3-5/D-R3-6) as closely as this path's types allow, ending with the
/// same [`policy::CliProfile::new_ordered`] call as the single source of
/// truth for the entries loop's own key-format/value-NUL checks -- a
/// non-string key can't be handed to it directly (its `Vec<(String,
/// String)>` has no non-string-key case), so that one case is resolved by
/// first confirming the *prefix* of already-string-shaped entries before it
/// passes `new_ordered` on its own (one extra call, only taken on that
/// path), then reporting the non-string key itself as `invalid_cli_profile`
/// -- exactly the point in Python's order where its `TypeError` fires.
fn build_cli_profile(value: Option<&Value>) -> Result<Option<policy::CliProfile>> {
    let value = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(v) => v,
    };
    let bad = || Error::invalid_input("invalid_cli_profile");
    let obj = value.as_object().ok_or_else(bad)?;

    // Phase 1.
    let program_raw = obj.get("program").cloned().ok_or_else(bad)?;
    let kind_raw = obj.get("kind").cloned().ok_or_else(bad)?;
    let base_url_env_raw = obj.get("base_url_env").cloned();
    let pairs: Vec<(Value, Value)> = match obj.get("extra_env") {
        None => Vec::new(),
        Some(v) if json_falsy(v) => Vec::new(),
        // `dict(x)` for a truthy `extra_env`: a JSON object is used
        // directly; any other shape goes through [`python_dict_pairs`]
        // (finding H-R2-9(c) for why a shape it can't turn into pairs at
        // all -- including a truthy plain string, Python's own uncaught
        // `ValueError` there -- folds into this same `invalid_cli_profile`
        // reason, per PORTING.md §3.5).
        Some(Value::Object(m)) => m
            .iter()
            .map(|(k, v)| (Value::String(k.clone()), v.clone()))
            .collect(),
        // `dict(...)`'s `TypeError` is caught (`invalid_cli_profile`); its
        // `ValueError` (an element of the wrong length, e.g. a truthy plain
        // string) escapes `_build_cli_profile` (finding H-R2-9c).
        Some(v) => match python_dict_pairs_checked(v) {
            Ok(pairs) => pairs,
            Err(DictError::TypeError) => return Err(bad()),
            Err(DictError::ValueError) => return Err(uncaught_builtin("ValueError")),
        },
    };
    // `dict(pairs)` itself never raises for a bad key/value type -- it just
    // does last-write-wins per key (JSON equality, matching Python's own
    // hashable-key equality for the shapes reachable here); only
    // `__post_init__`'s later loop over the FINAL dict's entries checks
    // types, so an earlier pair's bad key/value that a later pair with the
    // same key overwrites is never actually seen by Python and must not be
    // rejected here either.
    let mut merged: Vec<(Value, Value)> = Vec::new();
    for (k, v) in pairs {
        match merged.iter_mut().find(|(ek, _)| dict_keys_equal(ek, &k)) {
            Some(existing) => existing.1 = v,
            None => merged.push((k, v)),
        }
    }

    // Phase 2, in Python's exact order: kind -> program -> base_url_env ->
    // entries.
    //
    // `self.kind not in CONNECTION_KINDS`: a plain membership check, no
    // `isinstance` guard, so a non-string `kind` (the `""` placeholder)
    // simply never matches and gets the same documented reason a
    // wrong-but-string `kind` would.
    let kind = kind_raw.as_str().unwrap_or("").to_string();
    if !policy::CONNECTION_KINDS.contains(&kind.as_str()) {
        return Err(Error::invalid_input("invalid_cli_kind"));
    }
    // `if not self.program or "\x00" in self.program`: Python's `or`
    // short-circuits on a FALSY `program` (`""`, `0`, `False`, `None`,
    // `[]`, `{}`) straight to `invalid_cli_program` without ever evaluating
    // `"\x00" in self.program` -- reached here only now that `kind` is
    // already confirmed valid, matching Python's order (finding H-R2-8's
    // reason merge is corrected: the two Python outcomes are different
    // reasons, not one).
    //
    // Finding H-R5-4: this check now raises EAGERLY, right here, instead
    // of being deferred into `new_ordered`'s own check at the very end of
    // this function -- deferring it let `base_url_env`'s check (below)
    // fire first and report its own reason whenever BOTH were invalid,
    // which is the wrong order: Python's `__post_init__` checks `program`
    // before ever looking at `base_url_env`.
    //
    // Finding H-R5-2: a TRUTHY value then only fails via `"\x00" in
    // self.program`. For a `str` this is `contains('\0')` (unchanged). For
    // a `list`/`dict`, Python's `in` is a plain MEMBERSHIP test -- true iff
    // an element (list) or key (dict) equals the exact string `"\x00"` --
    // so an ordinary truthy list/dict does NOT raise, and Python folds it
    // into the document verbatim: confirmed against real `python3.12`,
    // `CliProfile(program=["curl"], kind="http")` succeeds and keeps the
    // list, while `CliProfile(program={"\x00": 1}, kind="http")` raises
    // the documented `invalid_cli_program`. Only a truthy *non-iterable*
    // scalar (`int`/`float`/`bool`) still hits Python's uncaught
    // `TypeError` on `in`, substituted with `invalid_cli_profile` (`bad()`)
    // as before -- this function previously treated EVERY non-string
    // `program`, container or not, as that same scalar case, wrongly
    // rejecting the whole op for a shape Python accepts.
    let program_contains_nul = match &program_raw {
        Value::String(s) => s.contains('\0'),
        Value::Array(items) => items.iter().any(|v| v.as_str() == Some("\u{0}")),
        Value::Object(map) => map.keys().any(|k| k == "\u{0}"),
        Value::Number(_) | Value::Bool(_) | Value::Null => false,
    };
    if json_falsy(&program_raw) || program_contains_nul {
        return Err(Error::invalid_input("invalid_cli_program"));
    }
    let program_is_container = matches!(&program_raw, Value::Array(_) | Value::Object(_));
    let program = match program_raw.as_str() {
        Some(s) => s.to_string(),
        // Placeholder for the typed `CliProfile::program: String` field
        // (PORTING.md §3b's typed-field limit, same as `ca_file`/
        // `value_prefix`/`basic_username`): the final document is built
        // from `program_raw` directly (`cli_profile_value`'s
        // `raw_program`), never from this placeholder, and it is
        // guaranteed non-empty/NUL-free so `new_ordered`'s own
        // (redundant, already-passed) program check below never
        // re-rejects it.
        None if program_is_container => "\u{1}container-program".to_string(),
        // Truthy non-iterable scalar (int/float/bool): Python's uncaught
        // `TypeError` from `"\x00" in <scalar>`.
        None => return Err(bad()),
    };
    // `re.match(pattern, self.base_url_env)` has no `isinstance` guard at
    // all: ANY non-string value, falsy or truthy, is the same uncaught
    // `TypeError` -- unlike `kind`/`program` above, there is no tolerant
    // membership/falsiness check to fall back on first (finding H-5 is what
    // a wrong-but-*string* `base_url_env` gets, from the regex actually
    // failing to match).
    let base_url_env = match base_url_env_raw {
        None => None,
        Some(Value::String(s)) => Some(s),
        Some(_) => return Err(bad()),
    };
    // Entries loop, in document order (finding H-R3-5), extended to a
    // non-string KEY (finding H-R4-3): `new_ordered` has no way to express
    // "fail via `invalid_cli_profile`" for an entry it can only accept as
    // `(String, String)`, so the *prefix* of already-string-shaped entries
    // strictly before the first non-string key is checked on its own first
    // -- if Python would already have stopped at one of THOSE entries
    // (`invalid_env_name`/`invalid_env_value`), that is reported instead,
    // exactly matching Python's "first failing entry, in order" rule.
    let mut extra_env_ordered: Vec<(String, String)> = Vec::with_capacity(merged.len());
    for (k, v) in merged {
        let key = match k {
            Value::String(s) => s,
            _ => {
                policy::CliProfile::new_ordered(
                    program.clone(),
                    kind.clone(),
                    base_url_env.clone(),
                    extra_env_ordered.clone(),
                )?;
                return Err(bad());
            }
        };
        extra_env_ordered.push((key, env_value_or_nul_sentinel(&v)));
    }
    Ok(Some(policy::CliProfile::new_ordered(
        program,
        kind,
        base_url_env,
        extra_env_ordered,
    )?))
}

/// An `extra_env` value already known to be a JSON string, as-is; any other
/// JSON value becomes the sentinel `"\0"` -- see the `extra_env_ordered`
/// comment above for why this is exact, not approximate: whichever check
/// [`policy::CliProfile::new_ordered`]'s per-entry loop reaches for THIS
/// value (key format, then value NUL), the sentinel behaves exactly like
/// Python's real non-string value would at that same point (a non-string
/// value's `isinstance` check always fails in Python, and
/// `"\0".contains('\0')` always fails the NUL check in Rust, both
/// resolving to `invalid_env_value`).
fn env_value_or_nul_sentinel(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        _ => "\0".to_string(),
    }
}

/// `zeropw.team.commit.build_connection_fields`: validate and normalize
/// `connection.create`/`connection.update` args. See the module doc comment
/// for why this does not construct a `policy::Connection`.
pub fn build_connection_fields(args: &Map<String, Value>) -> Result<Map<String, Value>> {
    let kind = args.get("kind").and_then(Value::as_str).unwrap_or("");
    if !policy::CONNECTION_KINDS.contains(&kind) {
        return Err(Error::invalid_input("invalid_connection_kind"));
    }
    let project = projects::validate_name(
        args.get("project").and_then(Value::as_str).unwrap_or(""),
        "project",
    )?;
    let environment = projects::validate_name(
        args.get("environment")
            .and_then(Value::as_str)
            .unwrap_or(""),
        "environment",
    )?;
    if !valid_name_field(args.get("service"), 200) {
        return Err(Error::invalid_input("invalid_service"));
    }
    let service = args
        .get("service")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let secret_id = projects::validate_name(
        args.get("secret_id").and_then(Value::as_str).unwrap_or(""),
        "secret_id",
    )?;
    let secret_version = match args.get("secret_version") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(Error::invalid_input("invalid_secret_version")),
    };
    let description = match args.get("description") {
        None => String::new(),
        Some(Value::String(s)) if s.chars().count() <= MAX_NAME_LENGTH && !control_re_search(s) => {
            s.clone()
        }
        _ => return Err(Error::invalid_input("invalid_description")),
    };
    let http_target = build_http_target(args.get("http_target"))?;
    let http_auth = build_http_auth(args.get("http_auth"))?;
    let http_scope = build_http_scope(args.get("http_scope"))?;
    let ssh_target = build_ssh_target(args.get("ssh_target"))?;
    let cli = build_cli_profile(args.get("cli"))?;
    if kind == "http" && !(http_target.is_some() && http_auth.is_some() && http_scope.is_some()) {
        return Err(Error::invalid_input("http_connection_incomplete"));
    }
    if kind == "ssh" && ssh_target.is_none() {
        return Err(Error::invalid_input("ssh_connection_incomplete"));
    }
    if let Some(c) = &cli
        && c.kind != kind
    {
        return Err(Error::invalid_input("cli_kind_mismatch"));
    }
    let mut out = Map::new();
    out.insert("project".into(), Value::String(project));
    out.insert("environment".into(), Value::String(environment));
    out.insert("service".into(), Value::String(service));
    out.insert("kind".into(), Value::String(kind.to_string()));
    out.insert("secret_id".into(), Value::String(secret_id));
    out.insert(
        "secret_version".into(),
        secret_version.map(Value::String).unwrap_or(Value::Null),
    );
    out.insert("description".into(), Value::String(description));
    let raw_ca_file = args
        .get("http_target")
        .and_then(Value::as_object)
        .and_then(|o| o.get("ca_file"))
        .cloned()
        .unwrap_or(Value::Null);
    let raw_header_name = args
        .get("http_auth")
        .and_then(Value::as_object)
        .and_then(|o| o.get("header_name"))
        .cloned()
        .unwrap_or(Value::Null);
    let raw_value_prefix = args
        .get("http_auth")
        .and_then(Value::as_object)
        .and_then(|o| o.get("value_prefix"))
        .cloned()
        .unwrap_or(Value::Null);
    let raw_basic_username = args
        .get("http_auth")
        .and_then(Value::as_object)
        .and_then(|o| o.get("basic_username"))
        .cloned()
        .unwrap_or(Value::Null);
    out.insert(
        "http_target".into(),
        http_target
            .as_ref()
            .map(|t| http_target_value(t, &raw_ca_file))
            .unwrap_or(Value::Null),
    );
    out.insert(
        "http_auth".into(),
        http_auth
            .as_ref()
            .map(|a| http_auth_value(&raw_header_name, &raw_value_prefix, &raw_basic_username, a))
            .unwrap_or(Value::Null),
    );
    out.insert(
        "http_scope".into(),
        http_scope
            .as_ref()
            .map(http_scope_value)
            .unwrap_or(Value::Null),
    );
    out.insert(
        "ssh_target".into(),
        ssh_target
            .as_ref()
            .map(ssh_target_value)
            .unwrap_or(Value::Null),
    );
    let raw_program = args
        .get("cli")
        .and_then(Value::as_object)
        .and_then(|o| o.get("program"))
        .cloned()
        .unwrap_or(Value::Null);
    out.insert(
        "cli".into(),
        cli.as_ref()
            .map(|c| cli_profile_value(c, &raw_program))
            .unwrap_or(Value::Null),
    );
    Ok(out)
}

// ------------------------------------------------------------- op validators
fn validate_connection_create(op: &Map<String, Value>) -> Result<()> {
    if !valid_name_field(op.get("id"), 64) {
        return Err(Error::invalid_input("invalid_connection_id"));
    }
    build_connection_fields(op)?;
    Ok(())
}

const CONNECTION_UPDATE_FIELDS: &[&str] = &[
    "description",
    "http_target",
    "http_auth",
    "http_scope",
    "ssh_target",
    "cli",
];

fn validate_connection_update(op: &Map<String, Value>) -> Result<()> {
    if !valid_name_field(op.get("id"), 64) {
        return Err(Error::invalid_input("invalid_connection_id"));
    }
    let extra_present = op
        .keys()
        .any(|k| k != "op" && k != "id" && !CONNECTION_UPDATE_FIELDS.contains(&k.as_str()));
    if extra_present {
        return Err(Error::invalid_input("connection_update_field_not_allowed"));
    }
    let any_present = op
        .keys()
        .any(|k| CONNECTION_UPDATE_FIELDS.contains(&k.as_str()));
    if !any_present {
        return Err(Error::invalid_input("connection_update_empty"));
    }
    if let Some(v) = op.get("http_target")
        && !v.is_null()
    {
        build_http_target(Some(v))?;
    }
    if let Some(v) = op.get("http_auth")
        && !v.is_null()
    {
        build_http_auth(Some(v))?;
    }
    if let Some(v) = op.get("http_scope")
        && !v.is_null()
    {
        build_http_scope(Some(v))?;
    }
    if let Some(v) = op.get("ssh_target")
        && !v.is_null()
    {
        build_ssh_target(Some(v))?;
    }
    if let Some(v) = op.get("cli")
        && !v.is_null()
    {
        build_cli_profile(Some(v))?;
    }
    if let Some(v) = op.get("description")
        && !matches!(v, Value::String(s) if s.chars().count() <= MAX_NAME_LENGTH && !control_re_search(s))
    {
        return Err(Error::invalid_input("invalid_description"));
    }
    Ok(())
}

fn validate_connection_switch_credential(op: &Map<String, Value>) -> Result<()> {
    if !valid_name_field(op.get("id"), 64) {
        return Err(Error::invalid_input("invalid_connection_id"));
    }
    if op.contains_key("secret_id") && !valid_name_field(op.get("secret_id"), 64) {
        return Err(Error::invalid_input("invalid_secret_id"));
    }
    match op.get("secret_version") {
        None | Some(Value::Null) => {}
        Some(Value::String(_)) => {}
        Some(_) => return Err(Error::invalid_input("invalid_secret_version")),
    }
    Ok(())
}

fn validate_connection_disable(op: &Map<String, Value>) -> Result<()> {
    if !valid_name_field(op.get("id"), 64) {
        return Err(Error::invalid_input("invalid_connection_id"));
    }
    Ok(())
}

fn validate_secret_put_version(op: &Map<String, Value>) -> Result<()> {
    if !valid_name_field(op.get("secret_id"), 64) {
        return Err(Error::invalid_input("invalid_secret_id"));
    }
    let kind_ok = matches!(op.get("kind"), Some(Value::String(s)) if vault::SECRET_KINDS.contains(&s.as_str()));
    if !kind_ok {
        return Err(Error::invalid_input("invalid_secret_kind"));
    }
    if !valid_token(op.get("generation_id")) {
        return Err(Error::invalid_input("invalid_generation_id"));
    }
    if !valid_token(op.get("version_id")) {
        return Err(Error::invalid_input("invalid_version_id"));
    }
    let ciphertext_ok = match op.get("ciphertext") {
        Some(Value::Object(c)) => {
            matches!(c.get("nonce"), Some(Value::String(_)))
                && matches!(c.get("ciphertext"), Some(Value::String(_)))
        }
        _ => false,
    };
    if !ciphertext_ok {
        return Err(Error::invalid_input("invalid_ciphertext"));
    }
    match op.get("public") {
        None | Some(Value::Object(_)) => {}
        _ => return Err(Error::invalid_input("invalid_public_metadata")),
    }
    Ok(())
}

fn validate_secret_set_status(op: &Map<String, Value>) -> Result<()> {
    if !valid_name_field(op.get("secret_id"), 64) {
        return Err(Error::invalid_input("invalid_secret_id"));
    }
    if !valid_token(op.get("version_id")) {
        return Err(Error::invalid_input("invalid_version_id"));
    }
    let status_ok =
        matches!(op.get("status"), Some(Value::String(s)) if s == "active" || s == "retired");
    if !status_ok {
        return Err(Error::invalid_input("invalid_version_status"));
    }
    Ok(())
}

fn validate_secret_activate(op: &Map<String, Value>) -> Result<()> {
    if !valid_name_field(op.get("secret_id"), 64) {
        return Err(Error::invalid_input("invalid_secret_id"));
    }
    if !valid_token(op.get("version_id")) {
        return Err(Error::invalid_input("invalid_version_id"));
    }
    Ok(())
}

fn valid_member_add_wraps(value: &Value) -> bool {
    match value.as_object() {
        Some(obj) => obj
            .iter()
            .all(|(gen_id, wrap)| is_token(gen_id) && valid_wrap(wrap)),
        None => false,
    }
}

fn validate_member_add(op: &Map<String, Value>) -> Result<()> {
    let device = op.get("device");
    if !matches!(device, Some(Value::Object(_))) {
        return Err(Error::invalid_input("invalid_device_record"));
    }
    DeviceRecord::from_dict(device.expect("checked above"))?;
    if !valid_name_field(op.get("name"), 200) {
        return Err(Error::invalid_input("invalid_member_name"));
    }
    let role_ok = matches!(op.get("role"), Some(Value::String(s)) if s == "admin" || s == "user");
    if !role_ok {
        return Err(Error::invalid_input("invalid_role"));
    }
    if let Some(w) = op.get("wraps")
        && !valid_member_add_wraps(w)
    {
        return Err(Error::invalid_input("invalid_wraps"));
    }
    Ok(())
}

fn validate_member_set_role(op: &Map<String, Value>) -> Result<()> {
    if !valid_fingerprint(op.get("fingerprint")) {
        return Err(Error::invalid_input("invalid_fingerprint"));
    }
    let role_ok = matches!(op.get("role"), Some(Value::String(s)) if s == "admin" || s == "user");
    if !role_ok {
        return Err(Error::invalid_input("invalid_role"));
    }
    Ok(())
}

fn validate_member_remove(op: &Map<String, Value>) -> Result<()> {
    if !valid_fingerprint(op.get("fingerprint")) {
        return Err(Error::invalid_input("invalid_fingerprint"));
    }
    Ok(())
}

fn validate_owner_transfer(op: &Map<String, Value>) -> Result<()> {
    if !valid_fingerprint(op.get("fingerprint")) {
        return Err(Error::invalid_input("invalid_fingerprint"));
    }
    Ok(())
}

fn validate_dek_rotate(op: &Map<String, Value>) -> Result<()> {
    if !valid_token(op.get("generation_id")) {
        return Err(Error::invalid_input("invalid_generation_id"));
    }
    if !valid_wraps(op.get("wraps")) {
        return Err(Error::invalid_input("invalid_wraps"));
    }
    if let Some(hash) = op.get("removal_fact_hash")
        && !hash
            .as_str()
            .is_some_and(|value| value.len() == 64 && value.bytes().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(Error::invalid_input("invalid_removal_fact_hash"));
    }
    Ok(())
}

/// `_validate_settings_update`: `not isinstance(value, int) or
/// isinstance(value, bool) or value <= 0`. Python's `int` is arbitrary
/// precision, so any positive integer literal -- including one far outside
/// `i64` (`10**30`) -- is valid; this checks the raw JSON literal's *shape*
/// (no `.`/`e`/`E`, no leading `-`, not exactly `"0"`) rather than going
/// through `as_i64()`, so it never rejects a magnitude Rust's integer types
/// can't hold (finding H-3: the old `as_i64()`-bounded check made
/// `receive_commit` reject a whole commit `fold()` itself handles fine).
fn validate_settings_update(op: &Map<String, Value>) -> Result<()> {
    let ok = match op.get("sync_interval_seconds") {
        Some(Value::Number(n)) => {
            let raw = n.as_str();
            !pyjson::is_float_literal(raw) && !raw.starts_with('-') && raw != "0"
        }
        _ => false,
    };
    if !ok {
        return Err(Error::invalid_input("invalid_settings"));
    }
    Ok(())
}

fn validate_env_init(op: &Map<String, Value>) -> Result<()> {
    let device = op.get("owner_device");
    if !matches!(device, Some(Value::Object(_))) {
        return Err(Error::invalid_input("invalid_device_record"));
    }
    DeviceRecord::from_dict(device.expect("checked above"))?;
    if !valid_name_field(op.get("owner_name"), 200) {
        return Err(Error::invalid_input("invalid_member_name"));
    }
    if !valid_token(op.get("generation_id")) {
        return Err(Error::invalid_input("invalid_generation_id"));
    }
    if !valid_wraps(op.get("wraps")) {
        return Err(Error::invalid_input("invalid_wraps"));
    }
    Ok(())
}

fn dispatch_validator(name: &str, op: &Map<String, Value>) -> Result<()> {
    match name {
        "env.init" => validate_env_init(op),
        "connection.create" => validate_connection_create(op),
        "connection.update" => validate_connection_update(op),
        "connection.switch_credential" => validate_connection_switch_credential(op),
        "connection.disable" => validate_connection_disable(op),
        "secret.put_version" => validate_secret_put_version(op),
        "secret.set_status" => validate_secret_set_status(op),
        "secret.activate" => validate_secret_activate(op),
        "member.add" => validate_member_add(op),
        "member.set_role" => validate_member_set_role(op),
        "member.remove" => validate_member_remove(op),
        "owner.transfer" => validate_owner_transfer(op),
        "dek.rotate" => validate_dek_rotate(op),
        "settings.update" => validate_settings_update(op),
        _ => Err(Error::invalid_input("op_unknown")),
    }
}

/// The deepest an op may nest, the op itself being one level (issue #54).
/// A backup archive holds a `secret.put_version` op's `public` metadata six
/// levels below where the op does (the archive's documents, the vault
/// document, its secrets, the secret, its versions, the version), the
/// deepest any op content is written.
pub const MAX_OP_DEPTH: usize = pyjson::MAX_JSON_DEPTH - 6;

/// `op` nests deeper than [`MAX_OP_DEPTH`].
pub fn op_too_deep(op: &Map<String, Value>) -> bool {
    op.values()
        .any(|value| pyjson::value_depth_within(value, MAX_OP_DEPTH - 1).is_none())
}

/// `op` creates a connection whose id is outside the name rule every
/// derived connection is built with.
pub fn creates_misnamed_connection(op: &Map<String, Value>) -> bool {
    op.get("op").and_then(Value::as_str) == Some("connection.create")
        && op
            .get("id")
            .and_then(Value::as_str)
            .is_none_or(|id| projects::validate_name(id, "connection_id").is_err())
}

/// The two rules folding enforces by skipping an op (issue #54). Receipt
/// does not check them, since earlier builds stored such ops and refusing
/// them now would split the nodes that did from the nodes that did not;
/// this build only refuses to author one.
fn check_authored_op(op: &Value) -> Result<()> {
    let Some(obj) = op.as_object() else {
        return Ok(());
    };
    if op_too_deep(obj) {
        return Err(Error::invalid_input("op_too_deep"));
    }
    if creates_misnamed_connection(obj) {
        return Err(Error::invalid_input("invalid_connection_id"));
    }
    Ok(())
}

/// `zeropw.team.commit.validate_op`.
pub fn validate_op(op: &Value) -> Result<()> {
    let obj = op
        .as_object()
        .ok_or_else(|| Error::invalid_input("op_malformed"))?;
    let name = obj.get("op").and_then(Value::as_str).unwrap_or("");
    dispatch_validator(name, obj)
}

/// `zeropw.team.commit.validate_ops`.
pub fn validate_ops(ops: &[Value]) -> Result<()> {
    if ops.is_empty() {
        return Err(Error::invalid_input("ops_empty"));
    }
    for op in ops {
        validate_op(op)?;
    }
    Ok(())
}

// --------------------------------------------------------------- CommitStore
/// The per-author-sequence commit log for one shared environment (section
/// 5.2, 5.4). Port of `zeropw.team.commit.CommitStore`.
pub struct CommitStore<'a> {
    pub state: &'a StateDir,
    pub env_id: String,
    pub root: String,
}

impl<'a> CommitStore<'a> {
    pub fn new(state: &'a StateDir, env_id: impl Into<String>) -> Self {
        let env_id = env_id.into();
        let root = env_root(&env_id);
        CommitStore {
            state,
            env_id,
            root,
        }
    }

    fn commit_path(&self, fingerprint: &str, seq: &PyInt) -> String {
        format!("{}/commits/{}/{}.json", self.root, fingerprint, seq)
    }

    fn dir(&self, suffix: &str) -> PathBuf {
        self.state.path.join(&self.root).join(suffix)
    }

    /// The vector of the newest snapshot on disk, or `{}` if there is none
    /// (section 7.3). Port of `CommitStore._snapshot_floor`:
    ///
    /// `vector = (data or {}).get("vector") or {}` then `{str(k): int(v) for
    /// k, v in vector.items() if isinstance(v, int) and not isinstance(v,
    /// bool)}`. Integer entries are exact Python ints at any magnitude
    /// ([`PyInt`]); float, bool and non-number entries are skipped. A truthy
    /// non-object snapshot document or `vector` has no `.get`/`.items`: the
    /// `AttributeError` CPython lets escape is `state_corrupt` here
    /// (PORTING.md §3.5), at the same point, aborting the same caller.
    pub(super) fn snapshot_floor(&self) -> Result<BTreeMap<String, PyInt>> {
        let directory = self.dir("snapshots");
        if !directory.is_dir() {
            return Ok(BTreeMap::new());
        }
        let numbers = digit_stems(&directory)?;
        let Some(top) = numbers.iter().max() else {
            return Ok(BTreeMap::new());
        };
        let path = format!("{}/snapshots/{}.json", self.root, top);
        let data = self.state.read_json(&path, Value::Null)?;
        let corrupt = || Error::state("state_corrupt").with_detail(path.clone());
        let vector = if json_falsy(&data) {
            None
        } else {
            data.as_object().ok_or_else(corrupt)?.get("vector")
        };
        let mut result = BTreeMap::new();
        match vector {
            None => {}
            Some(v) if json_falsy(v) => {}
            Some(Value::Object(vector)) => {
                for (k, v) in vector {
                    if let Some(i) = PyInt::from_json_integer(v) {
                        result.insert(k.clone(), i);
                    }
                }
            }
            Some(_) => return Err(corrupt()),
        }
        Ok(result)
    }

    /// Version vector: fingerprint -> highest `author_seq` stored (section
    /// 6.3). Port of `CommitStore.vector`.
    pub fn vector(&self) -> Result<BTreeMap<String, PyInt>> {
        let mut result = self.snapshot_floor()?;
        let commits_dir = self.dir("commits");
        if !commits_dir.is_dir() {
            return Ok(result);
        }
        let mut device_dirs: Vec<PathBuf> = std::fs::read_dir(&commits_dir)
            .map_err(|_| Error::state("state_corrupt").with_detail(self.root.clone()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        device_dirs.sort();
        for device_dir in device_dirs {
            let name = device_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            let seqs = digit_stems(&device_dir)?;
            if let Some(max_seq) = seqs.into_iter().max() {
                let entry = result.entry(name).or_insert_with(PyInt::zero);
                if max_seq > *entry {
                    *entry = max_seq;
                }
            }
        }
        Ok(result)
    }

    pub fn last_seq(&self, fingerprint: &str) -> Result<PyInt> {
        Ok(self
            .vector()?
            .remove(fingerprint)
            .unwrap_or_else(PyInt::zero))
    }

    /// Store a commit, enforcing contiguous per-author sequence (no gaps,
    /// no duplicates). Port of `CommitStore.append`.
    pub fn append(&self, commit: &Commit) -> Result<()> {
        if let Some(history) = retained_history::selected_store(self)? {
            return retained_history::append_with_input(self, commit, now_ms(), &history, None)
                .map_err(retained_history::AppendFailure::into_error);
        }
        if commit.env_id != self.env_id {
            return Err(Error::invalid_input("team_env_id_mismatch"));
        }
        let last = self.last_seq(&commit.author)?;
        if commit.author_seq <= last {
            return Err(Error::invalid_input("team_seq_duplicate"));
        }
        if commit.author_seq > &last + 1 {
            return Err(Error::invalid_input("team_seq_gap"));
        }
        self.state.write_json(
            &self.commit_path(&commit.author, &commit.author_seq),
            &commit.to_dict(),
        )?;
        Ok(())
    }

    pub fn get(&self, fingerprint: &str, seq: impl Into<PyInt>) -> Result<Option<Commit>> {
        let data = self
            .state
            .read_json(&self.commit_path(fingerprint, &seq.into()), Value::Null)?;
        if json_falsy(&data) {
            return Ok(None);
        }
        Ok(Some(Commit::from_dict(&data)?))
    }

    /// `for seq in range(1, last + 1): self.get(fingerprint, seq)` per
    /// vector entry, at Python's unbounded integer precision.
    pub fn all_commits(&self) -> Result<Vec<Commit>> {
        let mut commits = Vec::new();
        for (fingerprint, last) in self.vector()? {
            let mut seq = PyInt::from(1);
            while seq <= last {
                if let Some(commit) = self.get(&fingerprint, &seq)? {
                    commits.push(commit);
                }
                seq = &seq + 1;
            }
        }
        sort_total_order(commits)
    }

    /// Receipt's public records, walking actual retained filenames only.
    /// Canonical get() deliberately ignores alternate Unicode/zero-padded paths.
    pub(super) fn retained_device_registry(
        &self,
    ) -> Result<std::collections::HashMap<String, DeviceRecord>> {
        if !self.state.locked_by_current_thread() {
            return Err(Error::state("team_compaction_lock_required"));
        }
        let commits_dir = self.dir("commits");
        let mut retained = Vec::new();
        if commits_dir.is_dir() {
            let mut directories: Vec<PathBuf> = std::fs::read_dir(&commits_dir)
                .map_err(|_| Error::state("state_corrupt"))?
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path())
                .filter(|path| path.is_dir())
                .collect();
            directories.sort();
            for directory in directories {
                let author = directory
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("");
                let mut seqs = digit_stems(&directory)?;
                seqs.sort();
                seqs.dedup();
                for seq in seqs.into_iter().filter(|seq| *seq > 0) {
                    if let Some(commit) = self.get(author, seq)? {
                        retained.push(commit);
                    }
                }
            }
        }
        Ok(device_registry(&sort_total_order(retained)?))
    }

    /// Exact public announcements in actual retained files, never sequence ranges.
    pub(super) fn retained_matching_device_records(
        &self,
        expected: &std::collections::HashMap<String, DeviceRecord>,
    ) -> Result<std::collections::HashSet<String>> {
        if !self.state.locked_by_current_thread() {
            return Err(Error::state("team_compaction_lock_required"));
        }
        let commits_dir = self.dir("commits");
        let mut retained = Vec::new();
        if commits_dir.is_dir() {
            let mut directories: Vec<PathBuf> = std::fs::read_dir(&commits_dir)
                .map_err(|_| Error::state("state_corrupt"))?
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path())
                .filter(|path| path.is_dir())
                .collect();
            directories.sort();
            for directory in directories {
                let author = directory
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("");
                let mut seqs = digit_stems(&directory)?;
                seqs.sort();
                seqs.dedup();
                for seq in seqs.into_iter().filter(|seq| *seq > 0) {
                    if let Some(commit) = self.get(author, seq)? {
                        retained.push(commit);
                    }
                }
            }
        }
        // Complete the same parsing/HLC validation even after finding a match.
        Ok(matching_device_records(
            &sort_total_order(retained)?,
            expected,
        ))
    }

    // -------------------------------------------------------- reject / defer
    pub fn reject(&self, commit: &Commit, reason: &str) -> Result<()> {
        let hash = commit.hash()?;
        let prefix = &hash[..hash.len().min(12)];
        let path = format!(
            "{}/rejected/{}-{:010}-{}.json",
            self.root, commit.author, commit.author_seq, prefix
        );
        let mut doc = match commit.to_dict() {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        doc.insert("rejected_reason".into(), Value::String(reason.to_string()));
        self.state.write_json(&path, &Value::Object(doc))?;
        Ok(())
    }

    fn deferred_path(&self, commit: &Commit) -> String {
        format!(
            "{}/deferred/{}-{:010}.json",
            self.root, commit.author, commit.author_seq
        )
    }

    pub fn defer(&self, commit: &Commit) -> Result<()> {
        self.state
            .write_json(&self.deferred_path(commit), &commit.to_dict())?;
        Ok(())
    }

    pub fn deferred_commits(&self) -> Result<Vec<Commit>> {
        let deferred_dir = self.dir("deferred");
        if !deferred_dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut names: Vec<String> = std::fs::read_dir(&deferred_dir)
            .map_err(|_| Error::state("state_corrupt").with_detail(self.root.clone()))?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .filter(|n| n.ends_with(".json"))
            .collect();
        names.sort();
        let mut commits = Vec::new();
        for name in names {
            let data = self
                .state
                .read_json(&format!("{}/deferred/{}", self.root, name), Value::Null)?;
            if !json_falsy(&data) {
                commits.push(Commit::from_dict(&data)?);
            }
        }
        Ok(commits)
    }

    /// Check both retained and cached predecessor clocks under the state lock.
    fn hlc_not_above_previous(&self, commit: &Commit, live: Option<&[Commit]>) -> Result<bool> {
        super::compaction_heads::cached_hlc_not_above_previous(self, commit, live)
    }

    /// Move every deferred commit whose wall clock is no longer too far
    /// ahead into the store. Port of `CommitStore.release_deferred`.
    ///
    /// Receipt compares a commit with its author's previous sequence only
    /// when that one is stored, which it is not for a commit deferred behind
    /// another of its author's (issue #52). So a released commit is checked
    /// again: one whose HLC is not above the previous sequence's is rejected
    /// as `team_hlc_not_monotone`, and one whose sequence was stored since it
    /// was deferred is dropped, unless another commit holds that sequence:
    /// that is rejected as `team_author_equivocation`. Both are audited as
    /// on receipt. Each is decided under the state lock, as on receipt; one
    /// that still waits for the sequence before it is passed over without
    /// taking the lock.
    pub fn release_deferred(
        &self,
        now_ms_value: i64,
        audit: Option<&Audit>,
    ) -> Result<Vec<Commit>> {
        if let Some(history) = retained_history::selected_store(self)? {
            let operation = history.lease()?;
            drop(history);
            return self.release_deferred_common(now_ms_value, audit, Some(&operation), None);
        }
        self.release_deferred_common(now_ms_value, audit, None, None)
    }
    pub(crate) fn release_deferred_runtime(
        &self,
        ctx: &crate::context::Context,
        now_ms_value: i64,
        audit: Option<&Audit>,
    ) -> Result<(Vec<Commit>, Option<HistoryResume<'a>>)> {
        if !std::ptr::eq(ctx.state, self.state) {
            return Err(Error::state("team_bootstrap_local_state_changed"));
        }
        if let Some(history) = retained_history::selected_store(self)? {
            let operation = history.lease()?;
            drop(history);
            let released =
                self.release_deferred_common(now_ms_value, audit, Some(&operation), Some(ctx))?;
            return Ok((released, Some(operation)));
        }
        Ok((
            self.release_deferred_common(now_ms_value, audit, None, None)?,
            None,
        ))
    }
    fn append_deferred_with_input(
        &self,
        commit: &Commit,
        now: i64,
        history: Option<&HistorySession<'_>>,
        runtime: Option<&crate::context::Context>,
    ) -> Result<()> {
        if let Some(history) = history {
            let settled = runtime
                .map(|ctx| {
                    super::sync::load_facts_core(history, super::sync::FactServices::Runtime(ctx))
                })
                .transpose()?;
            return retained_history::append_with_input(
                self,
                commit,
                now,
                history,
                settled.as_ref(),
            )
            .map_err(retained_history::AppendFailure::into_error);
        }
        self.append(commit)
    }
    fn release_deferred_common(
        &self,
        now_ms_value: i64,
        audit: Option<&Audit>,
        operation: Option<&HistoryResume<'_>>,
        runtime: Option<&crate::context::Context>,
    ) -> Result<Vec<Commit>> {
        let preflight = operation.map(HistoryResume::resume).transpose()?;
        if let Some(history) = &preflight {
            history.preflight_inventory()?;
            let input = history.acquire()?;
            let commits = input.commits()?;
            input.reserve_fold(&commits, None, 0)?;
            input.reserve_deferred_walk()?;
        }
        let deferred = self.deferred_commits()?;
        if let Some(history) = &preflight {
            history.check()?;
        }
        drop(preflight);
        let mut due = Vec::new();
        for commit in deferred {
            if let Some(operation) = operation {
                operation.check_unlocked()?;
            }
            let (wall_ms, _) = Hlc::parse(&commit.hlc)?;
            if wall_ms <= &PyInt::from(now_ms_value) + MAX_CLOCK_SKEW_MS {
                due.push(commit);
            }
        }
        if due.is_empty() {
            if let Some(operation) = operation {
                operation.check_unlocked()?;
            }
            return Ok(Vec::new());
        }
        // Read without the lock, only to pass over what waits; whatever it
        // lets through is checked again under the lock.
        let mut vector = self.vector()?;
        let mut released = Vec::new();
        for commit in due {
            if let Some(operation) = operation {
                operation.check_unlocked()?;
            }
            let last = vector
                .get(&commit.author)
                .cloned()
                .unwrap_or_else(PyInt::zero);
            if commit.author_seq > &last + 1 {
                continue; // waits for the sequence before it
            }
            #[cfg(test)]
            super::compaction_heads::testing::hit_scoped(
                super::compaction_heads::testing::Boundary::DeferredPrefilterPassed,
                self.state,
                &self.env_id,
            )?;
            let history = operation.map(HistoryResume::resume).transpose()?;
            let _lock = if history.is_none() {
                Some(self.state.lock()?)
            } else {
                None
            };
            if let Some(history) = &history {
                let input = history.acquire()?;
                let commits = input.commits()?;
                input.reserve_fold(&commits, None, 0)?;
            }
            let fresh_last = self.last_seq(&commit.author)?;
            if commit.author_seq > &fresh_last + 1 {
                continue;
            }
            let target = self.state.path.join(self.deferred_path(&commit));
            if commit.author_seq <= fresh_last {
                if let Some(stored) = self.get(&commit.author, &commit.author_seq)?
                    && stored.hash()? != commit.hash()?
                {
                    reject_commit(self, &commit, "team_author_equivocation", audit)?;
                }
            } else if self.hlc_not_above_previous(&commit, None)? {
                reject_commit(self, &commit, "team_hlc_not_monotone", audit)?;
            } else if self
                .append_deferred_with_input(&commit, now_ms_value, history.as_ref(), runtime)
                .is_err()
            {
                continue; // still out of sequence; leave it deferred
            } else {
                vector.insert(commit.author.clone(), commit.author_seq.clone());
                released.push(commit);
            }
            if let Some(history) = &history {
                history.invalidate()?;
            }
            let _ = std::fs::remove_file(&target);
        }
        if let Some(operation) = operation {
            operation.check_unlocked()?;
        }
        Ok(released)
    }
}

/// Numeric (`str.isdigit()`) `.json` filename stems directly inside
/// `directory`, mirroring Python's `[int(p.stem) for p in
/// directory.glob("*.json") if p.stem.isdigit()]`. `pub(super)`:
/// `team::fold`'s snapshot lookup (`load_latest_snapshot`) reuses the exact
/// same scan.
///
/// The filter is `str.isdigit()` exactly ([`python_stem_isdigit`]), which is
/// WIDER than the grammar `int(str)` accepts (finding H-R3-9): a stem of
/// `Numeric_Type=Digit` code points (`"\u{b2}"`) passes the filter and then
/// makes `int()` raise `ValueError`, as does a stem longer than CPython's
/// 4300-digit conversion limit. That `ValueError` escapes the list
/// comprehension uncaught in Python (aborting `_snapshot_floor`/`vector`/
/// `load_latest_snapshot` entirely), so it is `state_corrupt` here at the
/// same point (PORTING.md §3.5). Every stem `int()` accepts is converted at
/// Python's unbounded precision through the canonical
/// `crate::pystr::int_from_str_decimal_limited`.
pub(super) fn digit_stems(directory: &std::path::Path) -> Result<Vec<PyInt>> {
    let corrupt =
        || Error::state("state_corrupt").with_detail(directory.to_string_lossy().into_owned());
    let entries = std::fs::read_dir(directory).map_err(|_| corrupt())?;
    let mut out = Vec::new();
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name();
        let name = match name.to_str() {
            Some(n) => n,
            None => continue,
        };
        let stem = match name.strip_suffix(".json") {
            Some(s) => s,
            None => continue,
        };
        if !python_stem_isdigit(stem) {
            continue;
        }
        out.push(python_int_parse(stem).ok_or_else(corrupt)?);
    }
    Ok(out)
}

// ------------------------------------------------------------- receipt pipeline
/// Every device record announced so far, keyed by fingerprint (for
/// signature checks only, never membership or wrap authority). First verified
/// full normalized record wins in the supplied total order, then original op
/// order; fold-skipped and removed authors still supply signature material.
/// Port of `_device_registry`.
pub(super) fn device_registry(
    commits: &[Commit],
) -> std::collections::HashMap<String, DeviceRecord> {
    let mut registry = std::collections::HashMap::new();
    for commit in commits {
        for op in &commit.ops {
            let obj = match op.as_object() {
                Some(o) => o,
                None => continue,
            };
            let op_name = obj.get("op").and_then(Value::as_str);
            let record_dict = match op_name {
                Some("env.init") => obj.get("owner_device"),
                Some("member.add") => obj.get("device"),
                _ => None,
            };
            let record_dict = match record_dict {
                Some(v) if v.is_object() => v,
                _ => continue,
            };
            let record = match DeviceRecord::from_dict(record_dict) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if record.verify() {
                registry.entry(record.fingerprint()).or_insert(record);
            }
        }
    }
    registry
}

/// Equal verified full public records, including nonfirst announcements.
/// This is signature evidence only; it grants no membership or wrap authority.
pub(super) fn matching_device_records(
    commits: &[Commit],
    expected: &std::collections::HashMap<String, DeviceRecord>,
) -> std::collections::HashSet<String> {
    let mut matching = std::collections::HashSet::new();
    for commit in commits {
        for op in &commit.ops {
            let Some(object) = op.as_object() else {
                continue;
            };
            let record_dict = match object.get("op").and_then(Value::as_str) {
                Some("env.init") => object.get("owner_device"),
                Some("member.add") => object.get("device"),
                _ => None,
            };
            let Some(record_dict) = record_dict.filter(|value| value.is_object()) else {
                continue;
            };
            let Ok(record) = DeviceRecord::from_dict(record_dict) else {
                continue;
            };
            if record.verify() {
                let fingerprint = record.fingerprint();
                if expected.get(&fingerprint) == Some(&record) {
                    matching.insert(fingerprint);
                }
            }
        }
    }
    matching
}

/// `zeropw.team.commit.receive_commit`: validate and store one incoming
/// commit (docs/team-sync.md section 5.4). Returns one of `"accepted"`,
/// `"deferred"`, `"duplicate"` or `"rejected"`.
pub fn receive_commit(
    store: &CommitStore,
    commit: &Commit,
    now_ms_value: i64,
    audit: Option<&Audit>,
) -> Result<&'static str> {
    receive(store, commit, now_ms_value, audit, true)
}

/// [`receive_commit`] for a commit a peer sends live: one that arrives
/// before the history it builds on -- a sequence gap, or an author whose
/// admission this store has not received yet -- is `"early"`: nothing is
/// stored, rejected or audited. The caller asks the peer for the missing
/// range, which delivers it again in total order, and quarantines it with
/// [`receive_commit`] if that peer still cannot (issue #28).
pub fn receive_live_commit(
    store: &CommitStore,
    commit: &Commit,
    now_ms_value: i64,
    audit: Option<&Audit>,
) -> Result<&'static str> {
    receive(store, commit, now_ms_value, audit, false)
}

/// Whether `commit` builds on a commit this store holds in `deferred/` (a
/// future-dated HLC): its author's earlier sequence, or a `member.add` of its
/// author. Such a commit waits for the deferral instead of being quarantined
/// as early (issue #28).
pub fn waits_on_deferred(store: &CommitStore, commit: &Commit) -> Result<bool> {
    for deferred in store.deferred_commits()? {
        if deferred.author == commit.author && deferred.author_seq < commit.author_seq {
            return Ok(true);
        }
        let admits = deferred.ops.iter().any(|op| {
            op["op"] == "member.add"
                && DeviceRecord::from_dict(&op["device"])
                    .is_ok_and(|device| device.fingerprint() == commit.author)
        });
        if admits {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Store `commit` under `rejected/` and audit it as `team_commit_rejected`
/// (section 5.4).
fn reject_commit(
    store: &CommitStore,
    commit: &Commit,
    reason: &str,
    audit: Option<&Audit>,
) -> Result<()> {
    store.reject(commit, reason)?;
    if let Some(audit) = audit {
        audit.record(
            "team_commit_rejected",
            RecordArgs {
                result: Some("denied"),
                reason: Some(reason),
                extra: vec![
                    ("env_id", json!(commit.env_id)),
                    ("fingerprint", json!(commit.author)),
                    ("author_seq", json!(commit.author_seq)),
                ],
                ..Default::default()
            },
        )?;
    }
    Ok(())
}

fn receive(
    store: &CommitStore,
    commit: &Commit,
    now_ms_value: i64,
    audit: Option<&Audit>,
    quarantine_early: bool,
) -> Result<&'static str> {
    let history = HistorySession::open_runtime(store.state, &store.env_id)?;
    receive_with_input(
        store,
        commit,
        now_ms_value,
        audit,
        quarantine_early,
        &history,
    )
}
pub(crate) fn receive_with_input(
    store: &CommitStore,
    commit: &Commit,
    now_ms_value: i64,
    audit: Option<&Audit>,
    quarantine_early: bool,
    history: &HistorySession<'_>,
) -> Result<&'static str> {
    receive_with_services(
        store,
        commit,
        now_ms_value,
        audit,
        quarantine_early,
        history,
        None,
    )
}
pub(crate) fn receive_runtime_with_input<'a>(
    store: &CommitStore<'a>,
    commit: &Commit,
    now_ms_value: i64,
    audit: Option<&Audit>,
    quarantine_early: bool,
    history: &HistorySession<'a>,
    ctx: &crate::context::Context,
) -> Result<&'static str> {
    receive_with_services(
        store,
        commit,
        now_ms_value,
        audit,
        quarantine_early,
        history,
        Some(ctx),
    )
}
fn receive_with_services<'a>(
    store: &CommitStore<'a>,
    commit: &Commit,
    now_ms_value: i64,
    audit: Option<&Audit>,
    quarantine_early: bool,
    history: &HistorySession<'a>,
    runtime: Option<&crate::context::Context>,
) -> Result<&'static str> {
    if !std::ptr::eq(store.state, history.state())
        || store.env_id != history.env()
        || (history.is_scoped() && store.root != env_root(&store.env_id))
    {
        return Err(Error::state("team_bootstrap_local_state_changed"));
    }
    if history.is_scoped() {
        history.preflight_candidate(commit)?;
    }
    let reject = |reason: &str| -> Result<&'static str> {
        reject_commit(store, commit, reason, audit)?;
        Ok("rejected")
    };

    if commit.format != COMMIT_FORMAT {
        return reject("team_format_unknown");
    }
    if commit.env_id != store.env_id {
        return reject("team_env_id_mismatch");
    }
    if let Err(exc) = validate_ops(&commit.ops) {
        if !exc.is(ErrorClass::InvalidInput) {
            // A built-in exception escaping `validate_ops` leaves
            // `receive_commit` before `_reject` (see `uncaught_builtin`).
            return Err(exc);
        }
        return reject(&format!("team_op_format_{}", exc.reason));
    }

    let is_bootstrap = commit.author_seq == 1
        && !commit.ops.is_empty()
        && commit.ops[0]
            .as_object()
            .and_then(|o| o.get("op"))
            .and_then(Value::as_str)
            == Some("env.init");
    if is_bootstrap {
        let expected_owner = match env_owner_fingerprint(&commit.env_id) {
            Ok(o) => o,
            Err(_) => return reject("team_env_id_malformed"),
        };
        if commit.author != expected_owner {
            return reject("team_bootstrap_wrong_owner");
        }
    }

    let input = history.acquire()?;
    let existing = if history.is_scoped() {
        input.commits()?
    } else {
        store.all_commits()?
    };
    let mut registry = device_registry(&existing);
    if is_bootstrap && !registry.contains_key(&commit.author) {
        let owner_device = commit.ops[0]
            .as_object()
            .and_then(|o| o.get("owner_device"));
        let owner_record = match owner_device.and_then(|v| DeviceRecord::from_dict(v).ok()) {
            Some(r) => r,
            None => return reject("team_bootstrap_malformed"),
        };
        if owner_record.fingerprint() != commit.author || !owner_record.verify() {
            return reject("team_bootstrap_malformed");
        }
        registry.insert(commit.author.clone(), owner_record);
    }

    let record = match registry.get(&commit.author) {
        Some(r) => r,
        None if !quarantine_early => return Ok("early"),
        None => return reject("team_author_unknown"),
    };
    if !verify_commit(commit, record) {
        return reject("team_signature_invalid");
    }

    if let Some(manifest) = crate::import_barrier::personal_manifest(store.state, &commit.env_id)? {
        let floor = PyInt::from_json_integer(&manifest["vector"][&commit.author])
            .unwrap_or_else(PyInt::zero);
        let retained = store.get(&commit.author, &commit.author_seq)?;
        let cut = manifest["heads"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|h| {
                Some((
                    PyInt::from_json_integer(&h["hlc"]["wall_ms"])?,
                    PyInt::from_json_integer(&h["hlc"]["counter"])?,
                ))
            })
            .max();
        if (commit.author_seq <= floor
            && retained
                .as_ref()
                .is_none_or(|c| c.hash().ok() != commit.hash().ok()))
            || (commit.author_seq > floor
                && cut.is_some_and(|cut| Hlc::parse(&commit.hlc).is_ok_and(|h| h <= cut)))
        {
            return Err(crate::import_barrier::history_required(
                store.state,
                &commit.env_id,
                &commit.to_dict(),
            )?);
        }
    }

    let last_seq = store.last_seq(&commit.author)?;
    if commit.author_seq <= last_seq {
        let previously_stored = store.get(&commit.author, &commit.author_seq)?;
        if let Some(prev) = &previously_stored
            && prev.hash()? == commit.hash()?
        {
            return Ok("duplicate");
        }
        return reject("team_author_equivocation");
    }

    if store.hlc_not_above_previous(commit, Some(&existing))? {
        return reject("team_hlc_not_monotone");
    }

    let (wall_ms, _) = Hlc::parse(&commit.hlc)?;
    if wall_ms > &PyInt::from(now_ms_value) + MAX_CLOCK_SKEW_MS {
        store.defer(commit)?;
        return Ok("deferred");
    }

    history.check()?;
    let settled = if history.is_scoped() {
        runtime
            .map(|ctx| {
                super::sync::load_facts_core(history, super::sync::FactServices::Runtime(ctx))
            })
            .transpose()?
    } else {
        None
    };
    let append = if history.is_scoped() {
        retained_history::append_with_input(store, commit, now_ms_value, history, settled.as_ref())
    } else {
        store
            .append(commit)
            .map_err(retained_history::AppendFailure::Invalid)
    };
    if let Err(failure) = append {
        match failure {
            retained_history::AppendFailure::Local(error) => return Err(error),
            retained_history::AppendFailure::Invalid(exc) => {
                if !quarantine_early && exc.reason == "team_seq_gap" {
                    return Ok("early");
                }
                return reject(&exc.reason);
            }
        }
    }
    Ok("accepted")
}

#[cfg(test)]
mod compaction_heads_tests {
    use super::*;
    use crate::secret::SecretBytes;
    use tempfile::TempDir;

    fn key(seed: u8, agreement: u8) -> DeviceKey {
        DeviceKey {
            sign_seed: SecretBytes::new(vec![seed; 32]),
            agree_private: SecretBytes::new(vec![agreement; 32]),
        }
    }

    fn announcement(
        author: &DeviceKey,
        env: &str,
        seq: PyInt,
        hlc: &str,
        records: Vec<Value>,
    ) -> Commit {
        sign_commit(
            author,
            env,
            seq,
            hlc,
            &BTreeMap::new(),
            records
                .into_iter()
                .map(|device| {
                    json!({"op":"member.add","device":device,
                "name":"synthetic-record","role":"user","wraps":{}})
                })
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn compaction_heads_registry_literal_numeric_author_stable_sequence_and_op_order() {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        let _lock = state.lock().unwrap();
        let mut authors = [key(11, 12), key(13, 14)];
        authors.sort_by_key(|device| device.fingerprint().unwrap());
        let env = format!(
            "{}-0123456789abcdef0123456789abcdef",
            authors[0].fingerprint().unwrap()
        );
        let first = key(15, 16);
        let other = key(15, 17);
        let fp = first.fingerprint().unwrap();
        assert_eq!(other.fingerprint().unwrap(), fp);
        let mut raw = first.record().unwrap().to_dict();
        for field in ["sign_pub", "agree_pub", "sig"] {
            raw[field] = json!([raw[field].clone()]);
        }
        raw["extra"] = json!(["public-ignored-field"]);
        let a1 = announcement(
            &authors[0],
            &env,
            1.into(),
            "1000-0000",
            vec![raw, other.record().unwrap().to_dict()],
        );
        let a2 = announcement(
            &authors[0],
            &env,
            2.into(),
            "1000-0000",
            vec![other.record().unwrap().to_dict()],
        );
        let b1 = announcement(
            &authors[1],
            &env,
            1.into(),
            "1000-0000",
            vec![other.record().unwrap().to_dict()],
        );
        let store = CommitStore::new(&state, &env);
        for entry in [&b1, &a1, &a2] {
            store.append(entry).unwrap();
        }
        // Literal first record: numeric HLC tie -> author -> stable ascending
        // sequence traversal -> original op order. Not a fold/member rule.
        assert_eq!(
            store.retained_device_registry().unwrap()[&fp],
            first.record().unwrap()
        );
        let earlier = announcement(
            &authors[1],
            &env,
            1.into(),
            "999-9999",
            vec![other.record().unwrap().to_dict()],
        );
        state
            .write_json(
                &store.commit_path(&earlier.author, &1.into()),
                &earlier.to_dict(),
            )
            .unwrap();
        assert_eq!(
            store.retained_device_registry().unwrap()[&fp],
            other.record().unwrap()
        );
        // Finite-history parity is secondary to the literal expectations.
        assert_eq!(
            store.retained_device_registry().unwrap(),
            device_registry(&store.all_commits().unwrap())
        );
    }

    #[test]
    fn compaction_heads_direct_receipt_holds_entry_lock_through_rejection_audit() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let tmp = TempDir::new().unwrap();
        let state = Arc::new(StateDir::new(tmp.path().join("state")));
        state.create().unwrap();
        let author = key(27, 28);
        let env = format!(
            "{}-0123456789abcdef0123456789abcdef",
            author.fingerprint().unwrap()
        );
        let mut incoming = announcement(
            &author,
            &env,
            1.into(),
            "1000-0000",
            vec![author.record().unwrap().to_dict()],
        );
        incoming.format = "synthetic-unknown-format".into();
        let audit = Audit::new(&state, crate::clock::system());
        let held = Arc::new(AtomicBool::new(false));
        let listener_state = state.clone();
        let listener_held = held.clone();
        audit.subscribe(move |entry| {
            if entry.get("event").and_then(Value::as_str) == Some("team_commit_rejected") {
                listener_held.store(listener_state.locked_by_current_thread(), Ordering::SeqCst);
            }
        });
        assert_eq!(
            receive_commit(
                &CommitStore::new(&state, &env),
                &incoming,
                1000,
                Some(&audit)
            )
            .unwrap(),
            "rejected"
        );
        assert!(held.load(Ordering::SeqCst));
        assert!(!state.locked_by_current_thread());
    }

    #[test]
    fn compaction_heads_retained_registry_sparse_huge_and_alternate_stems_use_only_canonical_files()
    {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        let _lock = state.lock().unwrap();
        let author = key(21, 22);
        let target = key(23, 24);
        let alternate = key(23, 25);
        let fp = author.fingerprint().unwrap();
        let target_fp = target.fingerprint().unwrap();
        let env = format!("{fp}-0123456789abcdef0123456789abcdef");
        let store = CommitStore::new(&state, &env);
        let huge = PyInt::from_json_integer(
            &pyjson::loads("1844674407370955161600000000000000000001").unwrap(),
        )
        .unwrap();
        let original = announcement(
            &author,
            &env,
            huge.clone(),
            "1000-0000",
            vec![target.record().unwrap().to_dict()],
        );
        // Synthetic sparse retained history: never call legacy all_commits on
        // this vector, and never construct 1..huge as part of the new walker.
        state
            .write_json(&store.commit_path(&fp, &huge), &original.to_dict())
            .unwrap();
        let ignored = announcement(
            &author,
            &env,
            1.into(),
            "1-0000",
            vec![alternate.record().unwrap().to_dict()],
        );
        for stem in ["01", "١", "0"] {
            state
                .write_json(
                    &format!("{}/commits/{fp}/{stem}.json", store.root),
                    &ignored.to_dict(),
                )
                .unwrap();
        }
        state
            .write_json(&format!("{}/commits/{fp}/2.json", store.root), &Value::Null)
            .unwrap();
        assert_eq!(
            store.retained_device_registry().unwrap()[&target_fp],
            target.record().unwrap()
        );
        // A padded alias cannot override an existing canonical slot either.
        state
            .write_json(&store.commit_path(&fp, &1.into()), &original.to_dict())
            .unwrap();
        assert_eq!(
            store.retained_device_registry().unwrap()[&target_fp],
            target.record().unwrap()
        );
        state
            .write_json(&format!("{}/commits/{fp}/².json", store.root), &Value::Null)
            .unwrap();
        assert_eq!(
            store.retained_device_registry().unwrap_err().reason,
            "state_corrupt"
        );
    }
    #[test]
    fn compaction_heads_r1_exact_announcements_include_nonfirst_ops() {
        use std::collections::{HashMap, HashSet};
        let author = key(81, 82);
        let expected_key = key(83, 84);
        let different = key(83, 85);
        let unrelated = key(86, 87);
        let fp = expected_key.fingerprint().unwrap();
        let env = format!(
            "{}-0123456789abcdef0123456789abcdef",
            author.fingerprint().unwrap()
        );
        let equal = expected_key.record().unwrap();
        let other = different.record().unwrap();
        assert_eq!(different.fingerprint().unwrap(), fp);
        assert_ne!(equal, other);
        assert!(equal.verify() && other.verify());
        let expected = HashMap::from([(fp.clone(), equal.clone())]);
        let wanted = HashSet::from([fp.clone()]);
        for records in [
            vec![other.to_dict(), equal.to_dict()],
            vec![equal.to_dict(), other.to_dict()],
        ] {
            let original = announcement(&author, &env, 1.into(), "1-0000", records.clone());
            let before = original.canonical_json(true).unwrap();
            assert_eq!(
                matching_device_records(std::slice::from_ref(&original), &expected),
                wanted
            );
            assert_eq!(
                device_registry(std::slice::from_ref(&original))[&fp],
                DeviceRecord::from_dict(&records[0]).unwrap()
            );
            assert_eq!(original.canonical_json(true).unwrap(), before);
        }
        let first = announcement(&author, &env, 1.into(), "1-0000", vec![other.to_dict()]);
        let later = announcement(&author, &env, 2.into(), "2-0000", vec![equal.to_dict()]);
        let ordered = vec![first, later];
        assert_eq!(device_registry(&ordered)[&fp], other);
        assert_eq!(matching_device_records(&ordered, &expected), wanted);
        let mut normalized = equal.to_dict();
        for field in ["sign_pub", "agree_pub", "sig"] {
            normalized[field] = json!([normalized[field].clone()]);
        }
        normalized["ignored_extra"] = json!("public");
        let matching_env = format!("{fp}-0123456789abcdef0123456789abcdef");
        let wrap =
            crate::team::envelope::wrap_dek(&[7; 32], &matching_env, "0123456789abcdef", &equal)
                .unwrap();
        for op in [
            json!({"op":"env.init","owner_device":normalized,
                "owner_name":"synthetic-record","generation_id":"0123456789abcdef","wraps":{fp.clone():wrap}}),
            json!({"op":"member.add","device":normalized,
                "name":"synthetic-record","role":"user","wraps":{}}),
        ] {
            let original = sign_commit(
                &expected_key,
                &matching_env,
                1,
                "1-0000",
                &BTreeMap::new(),
                vec![op],
            )
            .unwrap();
            let signed = original.canonical_json(false).unwrap();
            let hashed = original.canonical_json(true).unwrap();
            assert_eq!(
                matching_device_records(std::slice::from_ref(&original), &expected),
                wanted
            );
            assert_eq!(device_registry(std::slice::from_ref(&original))[&fp], equal);
            assert_eq!(original.canonical_json(false).unwrap(), signed);
            assert_eq!(original.canonical_json(true).unwrap(), hashed);
        }
        let mut bad_record = equal.clone();
        bad_record.sig[0] ^= 1;
        assert!(!bad_record.verify());
        let invalid_expected = HashMap::from([(fp.clone(), bad_record.clone())]);
        let invalid = announcement(
            &author,
            &env,
            1.into(),
            "1-0000",
            vec![bad_record.to_dict()],
        );
        assert_eq!(
            matching_device_records(&[invalid], &invalid_expected),
            HashSet::new()
        );
        let bad = bad_record.to_dict();
        for record in [
            other.to_dict(),
            bad,
            unrelated.record().unwrap().to_dict(),
            json!({}),
        ] {
            let mut original =
                announcement(&author, &env, 1.into(), "1-0000", vec![equal.to_dict()]);
            // Malformed retained op DATA is tested independently of admission.
            original.ops[0]["device"] = record;
            assert_eq!(
                matching_device_records(&[original], &expected),
                HashSet::new()
            );
        }
    }

    #[test]
    fn compaction_heads_r1_retained_matches_use_canonical_sparse_files() {
        use std::collections::{HashMap, HashSet};
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        let author = key(88, 89);
        let target = key(90, 91);
        let different = key(90, 92);
        let fp = author.fingerprint().unwrap();
        let target_fp = target.fingerprint().unwrap();
        let env = format!("{fp}-0123456789abcdef0123456789abcdef");
        let store = CommitStore::new(&state, &env);
        let expected = HashMap::from([(target_fp.clone(), target.record().unwrap())]);
        assert_eq!(
            store
                .retained_matching_device_records(&expected)
                .unwrap_err()
                .reason,
            "team_compaction_lock_required"
        );
        let _lock = state.lock().unwrap();
        assert_eq!(
            store.retained_matching_device_records(&expected).unwrap(),
            HashSet::new()
        );
        let huge = PyInt::from_json_integer(
            &pyjson::loads("1844674407370955161600000000000000000001").unwrap(),
        )
        .unwrap();
        let original = announcement(
            &author,
            &env,
            huge.clone(),
            "2-0000",
            vec![
                different.record().unwrap().to_dict(),
                target.record().unwrap().to_dict(),
            ],
        );
        let canonical = store.commit_path(&fp, &huge);
        let nonmatch = announcement(
            &author,
            &env,
            1.into(),
            "1-0000",
            vec![different.record().unwrap().to_dict()],
        );
        state
            .write_json(&store.commit_path(&fp, &1.into()), &nonmatch.to_dict())
            .unwrap();
        for name in ["01", "١", "0", "-1"] {
            state
                .write_json(
                    &format!("{}/commits/{fp}/{name}.json", store.root),
                    &original.to_dict(),
                )
                .unwrap();
        }
        assert_eq!(
            store.retained_matching_device_records(&expected).unwrap(),
            HashSet::new()
        );
        state.write_json(&canonical, &original.to_dict()).unwrap();
        let wanted = HashSet::from([target_fp]);
        assert_eq!(
            store.retained_matching_device_records(&expected).unwrap(),
            wanted
        );
        assert_eq!(
            matching_device_records(&[nonmatch, original.clone()], &expected),
            wanted
        );
        let saved = state.read_bytes(&canonical).unwrap();
        let mut corrupt = original.to_dict();
        corrupt["hlc"] = json!("malformed");
        state
            .write_json(
                &format!(
                    "{}/commits/{fp}/9999999999999999999999999999999999999999.json",
                    store.root
                ),
                &corrupt,
            )
            .unwrap();
        assert_eq!(
            store
                .retained_matching_device_records(&expected)
                .unwrap_err()
                .reason,
            "hlc_malformed"
        );
        std::fs::remove_file(state.path.join(format!(
            "{}/commits/{fp}/9999999999999999999999999999999999999999.json",
            store.root
        )))
        .unwrap();
        state
            .write_bytes(
                &format!("{}/commits/{fp}/3.json", store.root),
                b"{bad-owned-json",
            )
            .unwrap();
        assert_eq!(
            store
                .retained_matching_device_records(&expected)
                .unwrap_err()
                .reason,
            "state_corrupt"
        );
        assert_eq!(state.read_bytes(&canonical).unwrap(), saved);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::StateDir;
    use crate::team::identity::DeviceKey;
    use tempfile::TempDir;

    const ENV_ID: &str = "env-0123456789abcdef";

    fn env_init_op(owner: &DeviceKey, name: &str, generation_id: &str) -> Value {
        let record = owner.record().unwrap();
        let mut wraps = Map::new();
        wraps.insert(
            owner.fingerprint().unwrap(),
            json!({"eph_pub": "AAAA", "nonce": "AAAA", "ciphertext": "AAAA"}),
        );
        json!({"op": "env.init", "owner_device": record.to_dict(), "owner_name": name,
              "generation_id": generation_id, "wraps": wraps})
    }

    fn connection_create_op(conn_id: &str) -> Value {
        json!({"op": "connection.create", "id": conn_id, "project": "demo", "environment": "dev",
              "service": "github", "kind": "http", "secret_id": "gh-token", "secret_version": null,
              "description": "", "http_target": {"scheme": "https", "host": "api.github.com", "port": 443},
              "http_auth": {"mode": "bearer"}, "http_scope": {"methods": ["GET"], "path_prefixes": ["/repos"]}})
    }

    // ---------------------------------------------------------------- HLC
    #[test]
    fn tick_advances_and_zeroes_counter_on_wall_advance() {
        let mut hlc = Hlc::default();
        let first = hlc.tick(Some(1000));
        let second = hlc.tick(Some(2000));
        assert_eq!(first, "1000-0000");
        assert_eq!(second, "2000-0000");
    }

    #[test]
    fn tick_increments_counter_when_wall_does_not_advance() {
        let mut hlc = Hlc::default();
        hlc.tick(Some(1000));
        let second = hlc.tick(Some(1000));
        let third = hlc.tick(Some(500));
        assert_eq!(second, "1000-0001");
        assert_eq!(third, "1000-0002");
    }

    /// Finding H-R3-8, closed: `Hlc.tick`'s `self.counter += 1` and
    /// `Hlc.parse`/`observe` are exact (unbounded) integers, so a
    /// peer-chosen counter far beyond any fixed width keeps incrementing
    /// (no saturation, no panic) and renders in full decimal.
    #[test]
    fn tick_increments_beyond_any_fixed_width() {
        let big = "170141183460469231731687303715884105727"; // 2**127 - 1
        let huge = format!("{big}{big}");
        let mut hlc = Hlc::new(1000, 0);
        hlc.observe(&format!("1000-{huge}")).unwrap();
        // The wall clock does not advance, so the counter increments.
        assert_eq!(
            hlc.tick(Some(500)),
            format!("1000-{big}170141183460469231731687303715884105728")
        );
        assert_eq!(
            hlc.tick(Some(500)),
            format!("1000-{big}170141183460469231731687303715884105729")
        );
        let (wall, counter) = Hlc::parse(&format!("{huge}-{huge}")).unwrap();
        assert_eq!(wall.to_string(), huge);
        assert_eq!(counter.to_string(), huge);
    }

    #[test]
    fn observe_raises_clock_and_causal_tick_sorts_after() {
        let mut hlc = Hlc::default();
        let remote = "5000-0003";
        hlc.observe(remote).unwrap();
        let nxt = hlc.tick(Some(1000));
        assert_eq!(
            Hlc::parse(&nxt).unwrap(),
            (PyInt::from(5000), PyInt::from(4))
        );
        assert!(Hlc::parse(&nxt).unwrap() > Hlc::parse(remote).unwrap());
    }

    #[test]
    fn observe_tie_takes_max_counter() {
        let mut hlc = Hlc::new(5000, 1);
        hlc.observe("5000-0007").unwrap();
        assert_eq!(hlc.counter, 7);
    }

    #[test]
    fn parse_rejects_malformed() {
        assert!(Hlc::parse("not-an-hlc").is_err());
        assert!(Hlc::parse("1000").is_err());
    }

    #[test]
    fn total_order_numeric_not_lexicographic() {
        let low = Hlc::parse("999-0000").unwrap();
        let high = Hlc::parse("1000-0000").unwrap();
        assert!(low < high);
    }

    // ----------------------------------------------------- sign/verify
    #[test]
    fn sign_then_verify() {
        let owner = DeviceKey::generate();
        let c1 = sign_commit(
            &owner,
            ENV_ID,
            1,
            "1000-0000",
            &BTreeMap::new(),
            vec![env_init_op(&owner, "alice-laptop", &"0".repeat(16))],
        )
        .unwrap();
        assert!(verify_commit(&c1, &owner.record().unwrap()));
    }

    #[test]
    fn tampered_op_fails_verification() {
        let owner = DeviceKey::generate();
        let c1 = sign_commit(
            &owner,
            ENV_ID,
            1,
            "1000-0000",
            &BTreeMap::new(),
            vec![env_init_op(&owner, "alice-laptop", &"0".repeat(16))],
        )
        .unwrap();
        let mut tampered_op = c1.ops[0].as_object().unwrap().clone();
        tampered_op.insert("owner_name".into(), json!("mallory"));
        let tampered = Commit {
            ops: vec![Value::Object(tampered_op)],
            ..c1
        };
        assert!(!verify_commit(&tampered, &owner.record().unwrap()));
    }

    #[test]
    fn wrong_signer_fails_verification() {
        let owner = DeviceKey::generate();
        let c1 = sign_commit(
            &owner,
            ENV_ID,
            1,
            "1000-0000",
            &BTreeMap::new(),
            vec![env_init_op(&owner, "alice-laptop", &"0".repeat(16))],
        )
        .unwrap();
        let other = DeviceKey::generate();
        assert!(!verify_commit(&c1, &other.record().unwrap()));
    }

    #[test]
    fn hash_changes_with_sig() {
        let owner = DeviceKey::generate();
        let c1 = sign_commit(
            &owner,
            ENV_ID,
            1,
            "1000-0000",
            &BTreeMap::new(),
            vec![env_init_op(&owner, "alice-laptop", &"0".repeat(16))],
        )
        .unwrap();
        let c2 = Commit {
            sig: String::new(),
            ..c1.clone()
        };
        assert_ne!(c1.hash().unwrap(), c2.hash().unwrap());
    }

    #[test]
    fn malformed_ops_refused_at_sign_time() {
        let owner = DeviceKey::generate();
        assert!(
            sign_commit(
                &owner,
                ENV_ID,
                1,
                "1000-0000",
                &BTreeMap::new(),
                vec![json!({"op": "no.such.op"})]
            )
            .is_err()
        );
        assert!(sign_commit(&owner, ENV_ID, 1, "1000-0000", &BTreeMap::new(), vec![]).is_err());
    }

    #[test]
    fn to_dict_from_dict_roundtrip() {
        let owner = DeviceKey::generate();
        let c1 = sign_commit(
            &owner,
            ENV_ID,
            1,
            "1000-0000",
            &BTreeMap::new(),
            vec![connection_create_op("gh")],
        )
        .unwrap();
        let restored = Commit::from_dict(&c1.to_dict()).unwrap();
        assert_eq!(restored.hash().unwrap(), c1.hash().unwrap());
        assert!(verify_commit(&restored, &owner.record().unwrap()));
    }

    /// Finding H-R3-3: an `ops` element reshaped as a pair list whose key
    /// is a hashable non-string (`[["op", "settings.update"], [1, "x"]]`)
    /// passes Python's `Commit.from_dict` (`dict()` keeps the key) but every
    /// later `canonical_json` raises an uncaught `TypeError`; it is the
    /// non-`InvalidInput` [`uncaught_builtin`] here, raised only once every
    /// other field parsed (a missing `sig` is still `commit_malformed`). An
    /// unhashable key is `dict()`'s own caught `TypeError`. See
    /// `rust/tests/team_oracle.rs`'s
    /// `commit_ops_element_with_non_string_pair_key_is_pythons_uncaught_typeerror`.
    #[test]
    fn from_dict_reports_a_non_string_op_key_as_the_later_uncaught_typeerror() {
        let mut data = json!({
            "format": COMMIT_FORMAT, "env_id": ENV_ID, "author": "a", "author_seq": 1,
            "hlc": "1000-0000", "seen": {}, "sig": "",
            "ops": [[["op", "settings.update"], [1, "x"]]],
        });
        let err = Commit::from_dict(&data).expect_err("never hashable in Python");
        assert!(!err.is(ErrorClass::InvalidInput));
        assert_eq!(err.reason, "team_uncaught_exception");
        assert_eq!(err.detail, "TypeError");
        data["ops"] = json!([[["op", "settings.update"], [[1], "x"]]]);
        assert_eq!(
            Commit::from_dict(&data).unwrap_err().reason,
            "commit_malformed"
        );
        data["ops"] = json!([[["op", "settings.update"], [1, "x"]]]);
        data.as_object_mut().unwrap().remove("sig");
        assert_eq!(
            Commit::from_dict(&data).unwrap_err().reason,
            "commit_malformed"
        );
    }

    // ----------------------------------------------------- op validation
    #[test]
    fn connection_create_accepts_valid_shape() {
        validate_op(&connection_create_op("gh")).unwrap();
    }

    #[test]
    fn connection_create_rejects_bad_host() {
        let mut op = connection_create_op("gh");
        op["http_target"]["host"] = json!("not a host!!");
        assert!(validate_op(&op).is_err());
    }

    #[test]
    fn connection_update_rejects_unknown_field() {
        let op = json!({"op": "connection.update", "id": "gh", "status": "disabled"});
        assert!(validate_op(&op).is_err());
    }

    #[test]
    fn connection_update_requires_a_field() {
        let op = json!({"op": "connection.update", "id": "gh"});
        assert!(validate_op(&op).is_err());
    }

    #[test]
    fn secret_put_version_shape() {
        let op = json!({"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
                        "generation_id": "0".repeat(16), "version_id": "1".repeat(16),
                        "ciphertext": {"nonce": "AAAA", "ciphertext": "BBBB"}, "public": {}});
        validate_op(&op).unwrap();
        let mut bad = op.clone();
        bad["version_id"] = json!("not-hex");
        assert!(validate_op(&bad).is_err());
    }

    #[test]
    fn member_add_shape() {
        let device = DeviceKey::generate();
        let op = json!({"op": "member.add", "device": device.record().unwrap().to_dict(),
                        "name": "bob", "role": "user"});
        validate_op(&op).unwrap();
        let mut bad = op.clone();
        bad["role"] = json!("superadmin");
        assert!(validate_op(&bad).is_err());
    }

    #[test]
    fn unknown_op_rejected() {
        assert!(validate_op(&json!({"op": "delete.everything"})).is_err());
    }

    #[test]
    fn non_dict_op_rejected() {
        assert!(validate_op(&json!("connection.create")).is_err());
    }

    #[test]
    fn dek_rotate_shape() {
        let fp = DeviceKey::generate().fingerprint().unwrap();
        let op = json!({"op": "dek.rotate", "generation_id": "a".repeat(16),
                        "wraps": {fp: {"eph_pub": "AA", "nonce": "AA", "ciphertext": "AA"}}});
        validate_op(&op).unwrap();
        let bad = json!({"op": "dek.rotate", "generation_id": "a".repeat(16), "wraps": {}});
        assert!(validate_op(&bad).is_err());
    }

    // ----------------------------------------------------- CommitStore
    struct Fixture {
        _tmp: TempDir,
        state: StateDir,
        owner: DeviceKey,
        env_id: String,
    }

    fn fixture() -> Fixture {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        let owner = DeviceKey::generate();
        let env_id = new_env_id(&owner.fingerprint().unwrap()).unwrap();
        Fixture {
            _tmp: tmp,
            state,
            owner,
            env_id,
        }
    }

    fn bootstrap(f: &Fixture, store: &CommitStore) -> Commit {
        let mut hlc = Hlc::default();
        let c1 = sign_commit(
            &f.owner,
            &f.env_id,
            1,
            &hlc.tick(Some(1_000_000)),
            &BTreeMap::new(),
            vec![env_init_op(&f.owner, "alice", &"0".repeat(16))],
        )
        .unwrap();
        assert_eq!(
            receive_commit(store, &c1, 1_000_000, None).unwrap(),
            "accepted"
        );
        c1
    }

    #[test]
    fn append_enforces_contiguous_sequence() {
        let f = fixture();
        let store = CommitStore::new(&f.state, f.env_id.clone());
        let c1 = bootstrap(&f, &store);
        assert!(store.append(&c1).is_err());
        let gap = sign_commit(
            &f.owner,
            &f.env_id,
            3,
            &Hlc::default().tick(Some(1_000_100)),
            &BTreeMap::new(),
            vec![connection_create_op("gh")],
        )
        .unwrap();
        assert!(store.append(&gap).is_err());
    }

    #[test]
    fn vector_and_all_commits() {
        let f = fixture();
        let store = CommitStore::new(&f.state, f.env_id.clone());
        bootstrap(&f, &store);
        let c2 = sign_commit(
            &f.owner,
            &f.env_id,
            2,
            &Hlc::default().tick(Some(1_000_100)),
            &store.vector().unwrap(),
            vec![connection_create_op("gh")],
        )
        .unwrap();
        store.append(&c2).unwrap();
        let vector = store.vector().unwrap();
        assert_eq!(
            vector.get(&f.owner.fingerprint().unwrap()),
            Some(&PyInt::from(2))
        );
        let seqs: Vec<PyInt> = store
            .all_commits()
            .unwrap()
            .iter()
            .map(|c| c.author_seq.clone())
            .collect();
        assert_eq!(seqs, vec![PyInt::from(1), PyInt::from(2)]);
    }

    #[test]
    fn receive_commit_rejects_env_id_mismatch() {
        let f = fixture();
        let store = CommitStore::new(&f.state, f.env_id.clone());
        bootstrap(&f, &store);
        let other_env = sign_commit(
            &f.owner,
            "different-env",
            2,
            &Hlc::default().tick(Some(2_000_000)),
            &BTreeMap::new(),
            vec![connection_create_op("gh")],
        )
        .unwrap();
        assert_eq!(
            receive_commit(&store, &other_env, 2_000_000, None).unwrap(),
            "rejected"
        );
    }

    /// Signs `ops` as [`sign_commit`] does but without checking them, as a
    /// client other than this build can.
    fn sign_unchecked(
        device: &DeviceKey,
        env_id: &str,
        seq: i64,
        hlc: &str,
        ops: Vec<Value>,
    ) -> Commit {
        let unsigned = Commit {
            format: COMMIT_FORMAT.to_string(),
            env_id: env_id.to_string(),
            author: device.fingerprint().unwrap(),
            author_seq: PyInt::from(seq),
            hlc: hlc.to_string(),
            seen: BTreeMap::new(),
            ops,
            sig: String::new(),
        };
        let sig = device
            .sign(&unsigned.canonical_json(false).unwrap())
            .unwrap();
        Commit {
            sig: pybase64::b64encode(&sig),
            ..unsigned
        }
    }

    /// Issue #54: a `connection.create` whose id fails the name rule derived
    /// connections are built with is not signed by this build, but one
    /// received is stored, as earlier builds stored it, and so are its
    /// author's later commits: refusing it would cut the author off on this
    /// node only.
    #[test]
    fn a_connection_id_derive_refuses_is_stored_but_not_signed() {
        let f = fixture();
        let store = CommitStore::new(&f.state, f.env_id.clone());
        bootstrap(&f, &store);
        let hlc = |wall| Hlc::default().tick(Some(wall));
        for (seq, id) in (2i64..).zip(["GH", "gh/x", ".gh"]) {
            validate_op(&connection_create_op(id)).unwrap();
            assert_eq!(
                sign_commit(
                    &f.owner,
                    &f.env_id,
                    seq,
                    &hlc(1_000_000 * seq),
                    &store.vector().unwrap(),
                    vec![connection_create_op(id)]
                )
                .unwrap_err()
                .reason,
                "invalid_connection_id",
                "{id}"
            );
            let commit = sign_unchecked(
                &f.owner,
                &f.env_id,
                seq,
                &hlc(1_000_000 * seq),
                vec![connection_create_op(id)],
            );
            assert_eq!(
                receive_commit(&store, &commit, 1_000_000 * seq, None).unwrap(),
                "accepted",
                "{id}"
            );
        }
        let later = sign_commit(
            &f.owner,
            &f.env_id,
            5,
            &hlc(5_000_000),
            &store.vector().unwrap(),
            vec![connection_create_op("gh.x-1_y")],
        )
        .unwrap();
        assert_eq!(
            receive_commit(&store, &later, 5_000_000, None).unwrap(),
            "accepted"
        );
        assert_eq!(store.all_commits().unwrap().len(), 5);
        assert!(!store.dir("rejected").exists());
    }

    /// A `secret.put_version` op nesting `depth` levels, its `public`
    /// metadata one fewer.
    fn put_version_nested(depth: usize) -> Value {
        let mut public = json!({});
        for _ in 1..depth - 1 {
            public = json!({"a": public});
        }
        json!({"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
               "generation_id": "0".repeat(16), "version_id": "1".repeat(16),
               "ciphertext": {"nonce": "AAAA", "ciphertext": "BBBB"}, "public": public})
    }

    /// Issue #54: this build signs an op nesting 984 levels, the most a
    /// backup can hold, and no deeper one; but it stores one received as
    /// deep as a COMMIT frame can carry, as earlier builds did, and its
    /// author's later commits.
    #[test]
    fn an_op_nested_too_deep_is_stored_but_not_signed() {
        // Hashing the deepest op recurses once per level, with several
        // times a release build's stack per level in a debug build.
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let f = fixture();
                let store = CommitStore::new(&f.state, f.env_id.clone());
                bootstrap(&f, &store);
                let hlc = |wall| Hlc::default().tick(Some(wall));
                let deepest = put_version_nested(pyjson::MAX_JSON_DEPTH - 6);
                assert_eq!(pyjson::value_depth_within(&deepest, usize::MAX), Some(984));
                let signed = sign_commit(
                    &f.owner,
                    &f.env_id,
                    2,
                    &hlc(2_000_000),
                    &store.vector().unwrap(),
                    vec![deepest],
                )
                .unwrap();
                assert_eq!(
                    receive_commit(&store, &signed, 2_000_000, None).unwrap(),
                    "accepted"
                );
                let too_deep = put_version_nested(pyjson::MAX_JSON_DEPTH - 5);
                validate_op(&too_deep).unwrap();
                assert_eq!(
                    sign_commit(
                        &f.owner,
                        &f.env_id,
                        3,
                        &hlc(3_000_000),
                        &store.vector().unwrap(),
                        vec![too_deep]
                    )
                    .unwrap_err()
                    .reason,
                    "op_too_deep"
                );
                // A COMMIT frame holds its ops three levels down.
                let delivered = put_version_nested(pyjson::MAX_JSON_DEPTH - 3);
                let received =
                    sign_unchecked(&f.owner, &f.env_id, 3, &hlc(3_000_000), vec![delivered]);
                assert_eq!(
                    receive_commit(&store, &received, 3_000_000, None).unwrap(),
                    "accepted"
                );
                let later = sign_commit(
                    &f.owner,
                    &f.env_id,
                    4,
                    &hlc(4_000_000),
                    &store.vector().unwrap(),
                    vec![connection_create_op("gh")],
                )
                .unwrap();
                assert_eq!(
                    receive_commit(&store, &later, 4_000_000, None).unwrap(),
                    "accepted"
                );
                assert_eq!(store.all_commits().unwrap().len(), 4);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn receive_commit_rejects_unknown_author() {
        let f = fixture();
        let store = CommitStore::new(&f.state, f.env_id.clone());
        let stranger = DeviceKey::generate();
        let c1 = sign_commit(
            &stranger,
            &f.env_id,
            1,
            &Hlc::default().tick(Some(1_000_000)),
            &BTreeMap::new(),
            vec![connection_create_op("gh")],
        )
        .unwrap();
        assert_eq!(
            receive_commit(&store, &c1, 1_000_000, None).unwrap(),
            "rejected"
        );
    }

    #[test]
    fn receive_commit_rejects_bad_signature() {
        let f = fixture();
        let store = CommitStore::new(&f.state, f.env_id.clone());
        let c1 = sign_commit(
            &f.owner,
            &f.env_id,
            1,
            &Hlc::default().tick(Some(1_000_000)),
            &BTreeMap::new(),
            vec![env_init_op(&f.owner, "alice", &"0".repeat(16))],
        )
        .unwrap();
        let forged = Commit {
            sig: pybase64::b64encode(&[0u8; 64]),
            ..c1
        };
        assert_eq!(
            receive_commit(&store, &forged, 1_000_000, None).unwrap(),
            "rejected"
        );
    }

    #[test]
    fn receive_commit_rejects_replayed_seq_after_bootstrap() {
        let f = fixture();
        let store = CommitStore::new(&f.state, f.env_id.clone());
        bootstrap(&f, &store);
        let replay = sign_commit(
            &f.owner,
            &f.env_id,
            1,
            &Hlc::default().tick(Some(2_000_000)),
            &BTreeMap::new(),
            vec![env_init_op(&f.owner, "alice", &"0".repeat(16))],
        )
        .unwrap();
        assert_eq!(
            receive_commit(&store, &replay, 2_000_000, None).unwrap(),
            "rejected"
        );
    }

    #[test]
    fn clock_skew_defers_then_releases() {
        let f = fixture();
        let store = CommitStore::new(&f.state, f.env_id.clone());
        bootstrap(&f, &store);
        let far_future_ms = 1_000_000 + MAX_CLOCK_SKEW_MS + 60_000;
        let skewed = sign_commit(
            &f.owner,
            &f.env_id,
            2,
            &Hlc::default().tick(Some(far_future_ms)),
            &store.vector().unwrap(),
            vec![connection_create_op("gh")],
        )
        .unwrap();
        let result = receive_commit(&store, &skewed, 1_000_000, None).unwrap();
        assert_eq!(result, "deferred");
        assert_eq!(
            store.vector().unwrap().get(&f.owner.fingerprint().unwrap()),
            Some(&PyInt::from(1))
        );
        assert_eq!(store.release_deferred(1_000_000, None).unwrap(), vec![]);
        let released = store.release_deferred(far_future_ms, None).unwrap();
        assert_eq!(
            released
                .iter()
                .map(|c| c.hash().unwrap())
                .collect::<Vec<_>>(),
            vec![skewed.hash().unwrap()]
        );
        assert_eq!(
            store.vector().unwrap().get(&f.owner.fingerprint().unwrap()),
            Some(&PyInt::from(2))
        );
    }

    fn rejections(audit: &Audit) -> Vec<Value> {
        audit
            .iter_records()
            .unwrap()
            .into_iter()
            .filter(|record| record["event"] == "team_commit_rejected")
            .collect()
    }

    /// Issue #52: a commit deferred behind its author's previous sequence,
    /// whose HLC is not above that one's, is rejected when it is released
    /// (`team_hlc_not_monotone`, audited as on receipt) rather than stored
    /// out of HLC order.
    #[test]
    fn a_released_commit_keeps_its_authors_hlc_order() {
        let f = fixture();
        let store = CommitStore::new(&f.state, f.env_id.clone());
        bootstrap(&f, &store);
        let audit = Audit::new(&f.state, crate::clock::fixed(1_700_000_000.0));
        let (now, minute) = (1_000_000, 60_000);
        let signed = |seq: i64, wall: i64| {
            sign_commit(
                &f.owner,
                &f.env_id,
                seq,
                &format!("{wall}-0000"),
                &BTreeMap::new(),
                vec![connection_create_op(&format!("c{seq}"))],
            )
            .unwrap()
        };
        let later = signed(2, now + 20 * minute);
        let earlier = signed(3, now + 10 * minute);
        for commit in [&later, &earlier] {
            assert_eq!(
                receive_commit(&store, commit, now, Some(&audit)).unwrap(),
                "deferred"
            );
        }
        // Due first, `earlier` waits for the sequence before it.
        let none: Vec<Commit> = vec![];
        assert_eq!(
            store
                .release_deferred(now + 10 * minute, Some(&audit))
                .unwrap(),
            none
        );
        let released = store
            .release_deferred(now + 20 * minute, Some(&audit))
            .unwrap();
        assert_eq!(released, vec![later]);
        assert_eq!(
            store.last_seq(&f.owner.fingerprint().unwrap()).unwrap(),
            PyInt::from(2)
        );
        assert!(store.deferred_commits().unwrap().is_empty());
        assert_eq!(std::fs::read_dir(store.dir("rejected")).unwrap().count(), 1);
        let rejected = rejections(&audit);
        assert_eq!(rejected.len(), 1, "{rejected:?}");
        assert_eq!(rejected[0]["reason"], "team_hlc_not_monotone");
        assert_eq!(rejected[0]["author_seq"], 3);
    }

    /// Section 5.4: a commit whose HLC is not above its author's previous
    /// one is rejected on receipt and audited.
    #[test]
    fn receive_commit_rejects_an_hlc_not_above_the_previous_one() {
        let f = fixture();
        let store = CommitStore::new(&f.state, f.env_id.clone());
        let c1 = bootstrap(&f, &store);
        let audit = Audit::new(&f.state, crate::clock::fixed(1_700_000_000.0));
        let behind = sign_commit(
            &f.owner,
            &f.env_id,
            2,
            &c1.hlc,
            &store.vector().unwrap(),
            vec![connection_create_op("gh")],
        )
        .unwrap();
        assert_eq!(
            receive_commit(&store, &behind, 1_000_000, Some(&audit)).unwrap(),
            "rejected"
        );
        assert_eq!(
            store.last_seq(&f.owner.fingerprint().unwrap()).unwrap(),
            PyInt::from(1)
        );
        let rejected = rejections(&audit);
        assert_eq!(rejected.len(), 1, "{rejected:?}");
        assert_eq!(rejected[0]["reason"], "team_hlc_not_monotone");
    }

    /// Issue #52: a deferred commit stored meanwhile -- received again once
    /// its time came -- is dropped from `deferred/` when it is released.
    #[test]
    fn a_deferred_commit_stored_since_is_dropped() {
        let f = fixture();
        let store = CommitStore::new(&f.state, f.env_id.clone());
        bootstrap(&f, &store);
        let audit = Audit::new(&f.state, crate::clock::fixed(1_700_000_000.0));
        let due = 1_000_000 + MAX_CLOCK_SKEW_MS + 60_000;
        let skewed = sign_commit(
            &f.owner,
            &f.env_id,
            2,
            &Hlc::default().tick(Some(due)),
            &store.vector().unwrap(),
            vec![connection_create_op("gh")],
        )
        .unwrap();
        assert_eq!(
            receive_commit(&store, &skewed, 1_000_000, Some(&audit)).unwrap(),
            "deferred"
        );
        assert_eq!(
            receive_commit(&store, &skewed, due, Some(&audit)).unwrap(),
            "accepted"
        );
        let none: Vec<Commit> = vec![];
        assert_eq!(store.release_deferred(due, Some(&audit)).unwrap(), none);
        assert!(store.deferred_commits().unwrap().is_empty());
        assert!(!store.dir("rejected").exists());
        assert!(rejections(&audit).is_empty());
    }

    /// Issue #52: a deferred commit whose sequence another commit of its
    /// author took meanwhile is rejected as `team_author_equivocation` when
    /// it is released, audited as on receipt; the stored one stays.
    #[test]
    fn a_deferred_commit_another_took_the_sequence_of_is_rejected() {
        let f = fixture();
        let store = CommitStore::new(&f.state, f.env_id.clone());
        bootstrap(&f, &store);
        let audit = Audit::new(&f.state, crate::clock::fixed(1_700_000_000.0));
        let due = 1_000_000 + MAX_CLOCK_SKEW_MS + 60_000;
        let signed = |wall: i64, conn_id: &str| {
            sign_commit(
                &f.owner,
                &f.env_id,
                2,
                &Hlc::default().tick(Some(wall)),
                &store.vector().unwrap(),
                vec![connection_create_op(conn_id)],
            )
            .unwrap()
        };
        let skewed = signed(due, "gh");
        let other = signed(1_000_100, "gl");
        assert_eq!(
            receive_commit(&store, &skewed, 1_000_000, Some(&audit)).unwrap(),
            "deferred"
        );
        assert_eq!(
            receive_commit(&store, &other, 1_000_000, Some(&audit)).unwrap(),
            "accepted"
        );
        let none: Vec<Commit> = vec![];
        assert_eq!(store.release_deferred(due, Some(&audit)).unwrap(), none);
        assert!(store.deferred_commits().unwrap().is_empty());
        let owner = f.owner.fingerprint().unwrap();
        assert_eq!(store.get(&owner, 2).unwrap(), Some(other));
        let rejected = rejections(&audit);
        assert_eq!(rejected.len(), 1, "{rejected:?}");
        assert_eq!(rejected[0]["reason"], "team_author_equivocation");
        assert_eq!(rejected[0]["author_seq"], 2);
    }

    /// Issue #52: a deferred commit that waits for the sequence before it is
    /// passed over without taking the state lock, so commits that never
    /// become storable do not hold the lock on every poll.
    #[test]
    fn a_deferred_commit_waiting_for_its_sequence_takes_no_lock() {
        let f = fixture();
        let store = CommitStore::new(&f.state, f.env_id.clone());
        bootstrap(&f, &store);
        let due = 1_000_000 + MAX_CLOCK_SKEW_MS + 60_000;
        let waiting = sign_commit(
            &f.owner,
            &f.env_id,
            3,
            &Hlc::default().tick(Some(due)),
            &BTreeMap::new(),
            vec![connection_create_op("gh")],
        )
        .unwrap();
        assert_eq!(
            receive_commit(&store, &waiting, 1_000_000, None).unwrap(),
            "deferred"
        );
        let held = f.state.lock().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let released = store.release_deferred(due, None).unwrap();
                sender.send(released).unwrap();
            });
            let released = receiver.recv_timeout(std::time::Duration::from_secs(20));
            drop(held);
            assert_eq!(released.expect("released without the lock"), vec![]);
        });
        assert_eq!(store.deferred_commits().unwrap(), vec![waiting]);
    }

    /// Issue #52: a deferred commit is decided under the state lock, as on
    /// receipt. One released while receipt stores another commit at its
    /// sequence waits for that, and is then rejected as an equivocation
    /// instead of taking the sequence.
    #[test]
    fn a_released_commit_is_decided_under_the_state_lock() {
        let f = fixture();
        let store = CommitStore::new(&f.state, f.env_id.clone());
        bootstrap(&f, &store);
        let audit = Audit::new(&f.state, crate::clock::fixed(1_700_000_000.0));
        let due = 1_000_000 + MAX_CLOCK_SKEW_MS + 60_000;
        let signed = |wall: i64, conn_id: &str| {
            sign_commit(
                &f.owner,
                &f.env_id,
                2,
                &Hlc::default().tick(Some(wall)),
                &store.vector().unwrap(),
                vec![connection_create_op(conn_id)],
            )
            .unwrap()
        };
        let skewed = signed(due, "gh");
        let other = signed(1_000_100, "gl");
        assert_eq!(
            receive_commit(&store, &skewed, 1_000_000, Some(&audit)).unwrap(),
            "deferred"
        );
        let held = f.state.lock().unwrap();
        std::thread::scope(|scope| {
            let releasing = scope.spawn(|| store.release_deferred(due, Some(&audit)).unwrap());
            std::thread::sleep(std::time::Duration::from_millis(200));
            // Receipt, under the lock the release waits for.
            assert_eq!(
                receive_commit(&store, &other, 1_000_000, Some(&audit)).unwrap(),
                "accepted"
            );
            drop(held);
            let none: Vec<Commit> = vec![];
            assert_eq!(releasing.join().unwrap(), none);
        });
        let owner = f.owner.fingerprint().unwrap();
        assert_eq!(store.get(&owner, 2).unwrap(), Some(other));
        let rejected = rejections(&audit);
        assert_eq!(rejected.len(), 1, "{rejected:?}");
        assert_eq!(rejected[0]["reason"], "team_author_equivocation");
    }

    #[test]
    fn second_bootstrap_from_same_author_rejected_by_sequence() {
        let f = fixture();
        let store = CommitStore::new(&f.state, f.env_id.clone());
        bootstrap(&f, &store);
        let again = sign_commit(
            &f.owner,
            &f.env_id,
            1,
            &Hlc::default().tick(Some(3_000_000)),
            &BTreeMap::new(),
            vec![env_init_op(&f.owner, "alice", &"0".repeat(16))],
        )
        .unwrap();
        assert_eq!(
            receive_commit(&store, &again, 3_000_000, None).unwrap(),
            "rejected"
        );
    }

    #[test]
    fn forged_early_bootstrap_from_non_owner_rejected() {
        let f = fixture();
        let store = CommitStore::new(&f.state, f.env_id.clone());
        let forger = DeviceKey::generate();
        let forged = sign_commit(
            &forger,
            &f.env_id,
            1,
            "0-0000",
            &BTreeMap::new(),
            vec![env_init_op(&forger, "alice", &"0".repeat(16))],
        )
        .unwrap();
        assert_eq!(
            receive_commit(&store, &forged, 1_000_000, None).unwrap(),
            "rejected"
        );
        assert!(store.vector().unwrap().is_empty());
        bootstrap(&f, &store);
        assert_eq!(
            store.vector().unwrap().get(&f.owner.fingerprint().unwrap()),
            Some(&PyInt::from(1))
        );
    }

    #[test]
    fn non_monotone_hlc_rejected() {
        let f = fixture();
        let store = CommitStore::new(&f.state, f.env_id.clone());
        bootstrap(&f, &store);
        let c2 = sign_commit(
            &f.owner,
            &f.env_id,
            2,
            &Hlc::default().tick(Some(1_000_100)),
            &BTreeMap::new(),
            vec![connection_create_op("gh")],
        )
        .unwrap();
        assert_eq!(
            receive_commit(&store, &c2, 1_000_100, None).unwrap(),
            "accepted"
        );
        let non_monotone = sign_commit(
            &f.owner,
            &f.env_id,
            3,
            "1000100-0000",
            &BTreeMap::new(),
            vec![connection_create_op("gitlab")],
        )
        .unwrap();
        assert_eq!(
            receive_commit(&store, &non_monotone, 1_000_100, None).unwrap(),
            "rejected"
        );
        assert_eq!(
            store.vector().unwrap().get(&f.owner.fingerprint().unwrap()),
            Some(&PyInt::from(2))
        );
    }

    #[test]
    fn exact_duplicate_is_silently_accepted_as_duplicate() {
        let f = fixture();
        let store = CommitStore::new(&f.state, f.env_id.clone());
        let c1 = bootstrap(&f, &store);
        assert_eq!(
            receive_commit(&store, &c1, 1_000_000, None).unwrap(),
            "duplicate"
        );
        let rejected_dir = f.state.path.join(&store.root).join("rejected");
        assert!(
            !rejected_dir.exists() || std::fs::read_dir(&rejected_dir).unwrap().next().is_none()
        );
    }

    #[test]
    fn conflicting_commit_at_same_slot_is_equivocation() {
        let f = fixture();
        let store = CommitStore::new(&f.state, f.env_id.clone());
        bootstrap(&f, &store);
        let c2 = sign_commit(
            &f.owner,
            &f.env_id,
            2,
            &Hlc::default().tick(Some(1_000_100)),
            &BTreeMap::new(),
            vec![connection_create_op("gh")],
        )
        .unwrap();
        assert_eq!(
            receive_commit(&store, &c2, 1_000_100, None).unwrap(),
            "accepted"
        );
        let conflicting = sign_commit(
            &f.owner,
            &f.env_id,
            2,
            &Hlc::default().tick(Some(1_000_200)),
            &BTreeMap::new(),
            vec![connection_create_op("gitlab")],
        )
        .unwrap();
        assert_eq!(
            receive_commit(&store, &conflicting, 1_000_200, None).unwrap(),
            "rejected"
        );
        let rejected_dir = f.state.path.join(&store.root).join("rejected");
        let found = std::fs::read_dir(&rejected_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| {
                std::fs::read_to_string(e.path())
                    .map(|s| s.contains("team_author_equivocation"))
                    .unwrap_or(false)
            });
        assert!(found);
    }

    // ------------------------------------------------------------ H-R2-1/H-R2-2
    // Round-2 equivalence-review fixes. `python_int_parse` no longer has
    // any hand/generated-table logic of its own to pin here (PORTING.md §3b,
    // finding E-R6-1 round 6: it now delegates entirely to
    // `crate::pystr::int_from_str_checked`), but this probe through
    // `python_int_parse` itself is kept as a regression pin for this
    // call site.

    /// Finding H-R2-1: CPython 3.12's `int(str)` strips only 25 of
    /// `str.isspace()`'s 29 code points -- U+001C..U+001F (`Bidi_Class=B`)
    /// are `isspace()`-true but rejected. Pins [`python_int_parse`]'s
    /// accept/reject decision for those four and for ordinary whitespace.
    #[test]
    fn int_strip_space_rejects_the_four_separator_controls() {
        assert!(python_int_parse("\u{1c}1000-0000".split('-').next().unwrap()).is_none());
        for cp in [0x1Cu32, 0x1D, 0x1E, 0x1F] {
            let c = char::from_u32(cp).unwrap();
            assert!(
                python_int_parse(&format!("{c}1000")).is_none(),
                "U+{cp:04X} must not be stripped by int()"
            );
        }
        assert_eq!(python_int_parse(" 1000 "), Some(PyInt::from(1000)));
        assert_eq!(python_int_parse("\u{a0}1000"), Some(PyInt::from(1000))); // NBSP: isspace() and int()-strippable
    }

    /// Finding H-R2-2 (historical) / E-R6-1 (round 6): this module's own
    /// `UNICODE_DECIMAL_DIGIT_BLOCKS` table and `unicode_digit_value`
    /// function -- previously pinned here by a full-enumeration digest
    /// match against `python3.12`'s `unicodedata.decimal` -- are deleted;
    /// `is_python_isdigit_char`/`digit_stems` now call
    /// `crate::pystr::unicode_decimal_digit` directly, whose own
    /// `oracle_digit_value_matches_python_for_every_codepoint` test
    /// (`pystr.rs`) already provides the identical full-enumeration proof,
    /// including the two Unicode 15.0 blocks (Dives Akuru `0x11950`, Kawi
    /// `0x11F50`) this table was once missing.
    #[test]
    fn unicode_decimal_digit_matches_python_for_the_previously_missing_blocks() {
        assert_eq!(crate::pystr::unicode_decimal_digit('\u{11950}'), Some(0)); // Dives Akuru ZERO
        assert_eq!(crate::pystr::unicode_decimal_digit('\u{11959}'), Some(9)); // Dives Akuru NINE
        assert_eq!(crate::pystr::unicode_decimal_digit('\u{11F50}'), Some(0)); // Kawi ZERO
        assert_eq!(crate::pystr::unicode_decimal_digit('\u{11F59}'), Some(9)); // Kawi NINE
    }
}

// Personal retained-input facility. This module's fields are deliberately
// inaccessible to callers: raw DATA and a held reentrant lock alone confer no
// history or authorization assurance.
mod retained_history {
    use super::*;
    use crate::{
        store::StateLock,
        team::{checkpoint, fold},
    };
    use sha2::{Digest, Sha256};
    use std::{
        cell::{Cell, RefCell},
        collections::BTreeSet,
        fs::{self},
        io::Read,
        marker::PhantomData,
        os::unix::fs::MetadataExt,
        rc::Rc,
        time::{Duration, Instant},
    };
    const ENTRIES: usize = 65_536;
    const INVENTORY: u64 = 67_108_864;
    const BULK: u64 = 16_777_216;
    const NODES: u64 = 1_048_576;
    const WORK: u64 = 67_108_864;
    const BYTES: u64 = 1_073_741_824;
    fn invalid() -> Error {
        Error::state("team_bootstrap_state_invalid")
    }
    fn limit() -> Error {
        Error::state("team_bootstrap_limit_exceeded")
    }
    fn stale() -> Error {
        Error::state("team_bootstrap_local_state_changed")
    }
    #[derive(Clone, Copy)]
    pub(crate) enum ProbePurpose {
        Invite,
        Recipient,
    }
    #[derive(Clone, Copy)]
    enum Selection {
        Ordinary,
        Probe(ProbePurpose),
        Owner,
        Recipient,
    }
    struct Counters {
        work: u64,
        bytes: u64,
    }
    #[derive(Clone, Copy)]
    enum BudgetFailure {
        Limit,
        Timeout,
    }
    pub(crate) struct HistoryBudget {
        began: Instant,
        byte_cap: u64,
        counters: RefCell<Counters>,
        failure: Cell<Option<BudgetFailure>>,
    }
    impl HistoryBudget {
        pub(crate) fn new() -> Self {
            Self {
                began: Instant::now(),
                byte_cap: BYTES,
                counters: RefCell::new(Counters { work: 0, bytes: 0 }),
                failure: Cell::new(None),
            }
        }
        pub(crate) fn new_guard() -> Self {
            Self {
                byte_cap: 268_435_456,
                ..Self::new()
            }
        }
        pub(crate) fn check(&self) -> Result<()> {
            if self.failure.get().is_none() && self.began.elapsed() >= Duration::from_secs(5) {
                self.failure.set(Some(BudgetFailure::Timeout));
            }
            match self.failure.get() {
                Some(BudgetFailure::Limit) => Err(limit()),
                Some(BudgetFailure::Timeout) => Err(Error::state("team_bootstrap_timeout")),
                None => Ok(()),
            }
        }
        pub(crate) fn charge(&self, work: u64, bytes: u64) -> Result<()> {
            self.check()?;
            let mut c = self.counters.borrow_mut();
            let w = c.work.checked_add(work).filter(|n| *n <= WORK);
            let b = c.bytes.checked_add(bytes).filter(|n| *n <= self.byte_cap);
            let (Some(w), Some(b)) = (w, b) else {
                self.failure.set(Some(BudgetFailure::Limit));
                return Err(limit());
            };
            c.work = w;
            c.bytes = b;
            Ok(())
        }
    }
    struct FileImage {
        raw: Vec<u8>,
    }
    struct Inventory {
        stamps: BTreeMap<String, Option<Vec<u64>>>,
        root: crate::import_barrier::ImportRootObservation,
        files: BTreeMap<String, FileImage>,
        layout: BTreeSet<(String, bool)>,
        revision: [u8; 32],
        entries: usize,
        bytes: u64,
    }
    struct RetainedOriginal {
        path: String,
        raw: Vec<u8>,
        parsed: Commit,
    }
    // Original DATA only, owned by this explicit operation. No authorization,
    // settled facts or readiness result is retained. Semantic boundaries still
    // recompare the complete raw revision; every getter checks held-lock/root,
    // generation and all captured path revisions before using these originals.
    struct CapturedHistory {
        generation: u64,
        inventory: Rc<Inventory>,
        originals: Rc<Vec<RetainedOriginal>>,
        vector: Rc<BTreeMap<String, PyInt>>,
        floor: Rc<BTreeMap<String, PyInt>>,
    }
    pub(crate) struct HistoryOperation<'a> {
        state: &'a StateDir,
        env: String,
        selection: Selection,
        identity: Option<DeviceRecord>,
        root: Option<crate::store::ImportRootRevision>,
        root_observation: RefCell<Option<crate::store::ImportRootRevision>>,
        budget: Rc<HistoryBudget>,
        generation: Rc<Cell<u64>>,
        paths: Rc<crate::import_barrier::ImportPathCache>,
        retained: RefCell<Option<CapturedHistory>>,
        _thread: PhantomData<Rc<()>>,
    }
    pub(crate) struct HistorySession<'a> {
        state: &'a StateDir,
        env: String,
        selection: Selection,
        identity: Option<DeviceRecord>,
        _lock: StateLock<'a>,
        budget: Rc<HistoryBudget>,
        generation: Rc<Cell<u64>>,
        operation: Rc<HistoryOperation<'a>>,
        _thread: PhantomData<Rc<()>>,
    }
    pub(crate) struct HistoryResume<'a> {
        operation: Rc<HistoryOperation<'a>>,
        selection: Selection,
        _thread: PhantomData<Rc<()>>,
    }
    pub(crate) struct FactSeal<'a> {
        operation: Rc<HistoryOperation<'a>>,
        generation: u64,
        revision: String,
        vector: BTreeMap<String, PyInt>,
    }
    impl<'a> HistoryOperation<'a> {
        fn lock_session(self: &Rc<Self>) -> Result<HistorySession<'a>> {
            if !self.state.locked_by_current_thread() {
                self.generation
                    .set(self.generation.get().checked_add(1).ok_or_else(limit)?);
            }
            let lock = self.state.lock()?;
            let session = HistorySession::from_operation(self.clone(), lock);
            session.check()?;
            Ok(session)
        }
        fn resume(self: &Rc<Self>, selection: Selection) -> Result<HistorySession<'a>> {
            let mut session = self.lock_session()?;
            session.selection = selection;
            if session.is_scoped() {
                session.acquire()?;
            } else if raw_witness_with_budget(self.state, &self.env, Some(&session))?.0 {
                // An ordinary lease cannot cross publication of a selected
                // route and retain the legacy history contract.
                return Err(stale());
            }
            Ok(session)
        }
    }
    impl<'a> HistoryResume<'a> {
        pub(crate) fn resume(&self) -> Result<HistorySession<'a>> {
            self.operation.resume(self.selection)
        }
        pub(crate) fn check_unlocked(&self) -> Result<()> {
            if !matches!(self.selection, Selection::Ordinary) {
                self.operation.budget.check()?;
            }
            Ok(())
        }
    }
    impl FactSeal<'_> {
        pub(crate) fn current_vector(
            &self,
            history: &HistorySession<'_>,
        ) -> Result<BTreeMap<String, PyInt>> {
            self.check(history)?;
            let size = self
                .vector
                .iter()
                .try_fold(0u64, |sum, (author, sequence)| {
                    sum.checked_add(author.len() as u64)
                        .and_then(|value| value.checked_add(sequence.0.bits()))
                        .ok_or_else(limit)
                })?;
            history.charge(size, size.checked_mul(8).ok_or_else(limit)?)?;
            Ok(self.vector.clone())
        }
        pub(crate) fn check(&self, history: &HistorySession<'_>) -> Result<()> {
            history.check()?;
            if !Rc::ptr_eq(&self.operation, &history.operation)
                || self.generation != history.generation.get()
                || hex::encode(history.collect()?.revision) != self.revision
            {
                return Err(stale());
            }
            Ok(())
        }
    }
    pub(crate) struct RetainedInput<'s, 'a> {
        session: &'s HistorySession<'a>,
        generation: u64,
        inventory: Option<Rc<Inventory>>,
        originals: Rc<Vec<RetainedOriginal>>,
        vector: Rc<BTreeMap<String, PyInt>>,
        floor: Rc<BTreeMap<String, PyInt>>,
        _thread: PhantomData<Rc<()>>,
    }
    impl<'a> HistorySession<'a> {
        fn from_operation(operation: Rc<HistoryOperation<'a>>, lock: StateLock<'a>) -> Self {
            Self {
                state: operation.state,
                env: operation.env.clone(),
                selection: operation.selection,
                identity: operation.identity.clone(),
                budget: operation.budget.clone(),
                generation: operation.generation.clone(),
                operation,
                _lock: lock,
                _thread: PhantomData,
            }
        }
        fn new_locked(
            state: &'a StateDir,
            env: &str,
            selection: Selection,
            lock: StateLock<'a>,
            budget: Rc<HistoryBudget>,
        ) -> Result<Self> {
            Self::new_locked_seeded(
                state,
                env,
                selection,
                lock,
                budget,
                Rc::new(Cell::new(0)),
                Rc::new(crate::import_barrier::ImportPathCache::empty()),
            )
        }
        fn new_locked_seeded(
            state: &'a StateDir,
            env: &str,
            selection: Selection,
            lock: StateLock<'a>,
            budget: Rc<HistoryBudget>,
            generation: Rc<Cell<u64>>,
            paths: Rc<crate::import_barrier::ImportPathCache>,
        ) -> Result<Self> {
            let root = if matches!(selection, Selection::Ordinary) {
                None
            } else {
                state.checked_import_root()?;
                Some(state.import_root_revision()?)
            };
            let operation = Rc::new(HistoryOperation {
                state,
                env: env.into(),
                selection,
                identity: state.import_identity().cloned(),
                root_observation: RefCell::new(root.clone()),
                root,
                budget,
                generation,
                paths,
                retained: RefCell::new(None),
                _thread: PhantomData,
            });
            let session = Self::from_operation(operation, lock);
            session.check()?;
            Ok(session)
        }
        pub(crate) fn open_runtime(state: &'a StateDir, env: &str) -> Result<Self> {
            Self::open_runtime_routed(state, env, 0, 0)
        }
        fn open_runtime_routed(
            state: &'a StateDir,
            env: &str,
            route_work: u64,
            route_bytes: u64,
        ) -> Result<Self> {
            #[cfg(test)]
            let _stage = testing::span(state, "history_open");
            let already_locked = state.locked_by_current_thread();
            let lock = state.lock()?;
            let budget = Rc::new(HistoryBudget::new());
            budget.charge(route_work, route_bytes)?;
            let mut result =
                Self::new_locked(state, env, Selection::Ordinary, lock, budget.clone())?;
            if !valid_env_id(env) {
                return Ok(result);
            }
            let mut witnessed =
                match fs::symlink_metadata(state.path.join(format!("team/{env}/bootstrap"))) {
                    Ok(_) => true,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                    Err(_) => return Err(invalid()),
                };
            // The signed visibility index is also a routing witness when the
            // entire environment bootstrap directory has been lost. Probe it
            // as bounded untrusted DATA; never turn damaged provenance into an
            // ordinary numeric fallback. Ordinary layout semantics stay lazy.
            match fs::symlink_metadata(state.path.join(crate::import_barrier::INDEX)) {
                Ok(metadata) => {
                    if metadata.len() > 1_048_576 {
                        return Err(limit());
                    }
                    crate::import_barrier::private_relative(state, crate::import_barrier::INDEX)?;
                    result.budget.charge(
                        metadata.len(),
                        metadata.len().checked_mul(4).ok_or_else(limit)?,
                    )?;
                    let file = anchored_file(state, crate::import_barrier::INDEX)?;
                    if stamp(&file.metadata().map_err(|_| invalid())?) != stamp(&metadata) {
                        return Err(stale());
                    }
                    let mut raw = Vec::new();
                    (&file)
                        .take(metadata.len().checked_add(1).ok_or_else(limit)?)
                        .read_to_end(&mut raw)
                        .map_err(|_| invalid())?;
                    if raw.len() as u64 != metadata.len()
                        || stamp(&file.metadata().map_err(|_| invalid())?) != stamp(&metadata)
                        || stamp(
                            &fs::symlink_metadata(state.path.join(crate::import_barrier::INDEX))
                                .map_err(|_| invalid())?,
                        ) != stamp(&metadata)
                    {
                        return Err(stale());
                    }
                    // This read selects a route only. All selected content is
                    // subsequently parsed strictly and authenticated afresh.
                    result.budget.charge(
                        raw.len() as u64,
                        (raw.len() as u64).checked_mul(64).ok_or_else(limit)?,
                    )?;
                    result.screen(&raw, 1_048_576)?;
                    let value = pyjson::loads(std::str::from_utf8(&raw).map_err(|_| invalid())?)
                        .map_err(|_| Error::state("team_bootstrap_storage_failed"))?;
                    if !value.is_object() {
                        return Err(invalid());
                    }
                    witnessed |= value.get(env).is_some();
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(invalid()),
            }
            if witnessed {
                if already_locked {
                    return Err(stale());
                }
                let selection = if env_owner_fingerprint(env)?
                    == result.identity.as_ref().ok_or_else(invalid)?.fingerprint()
                {
                    Selection::Owner
                } else {
                    Selection::Recipient
                };
                result = Self::new_locked(state, env, selection, result._lock, budget)?;
                result.acquire()?;
            }
            Ok(result)
        }
        pub(crate) fn open_recovery_entry(
            ctx: &crate::context::Context,
            env: &str,
        ) -> Result<Self> {
            let (witnessed, work, bytes) = raw_witness(ctx.state, env)?;
            if !witnessed {
                return Self::open_runtime(ctx.state, env);
            }
            if ctx.state.locked_by_current_thread() {
                return Err(stale());
            }
            let history = Self::open_probe(ctx, env, ProbePurpose::Recipient)?;
            history.charge(work, bytes)?;
            Ok(history)
        }
        pub(crate) fn continue_runtime(&self) -> Result<Self> {
            let result = (|| {
                self.check()?;
                let (witnessed, _, _) = raw_witness_with_budget(self.state, &self.env, Some(self))?;
                let selection = if witnessed {
                    if env_owner_fingerprint(&self.env)? == self.local_record()?.fingerprint() {
                        Selection::Owner
                    } else {
                        Selection::Recipient
                    }
                } else {
                    Selection::Ordinary
                };
                self.invalidate()?;
                let mut session = self.operation.lock_session()?;
                session.selection = selection;
                if session.is_scoped() {
                    session.acquire()?;
                }
                Ok(session)
            })();
            self.resource_result(result)
        }
        pub(crate) fn open_probe(
            ctx: &crate::context::Context,
            env: &str,
            purpose: ProbePurpose,
        ) -> Result<Self> {
            let state = ctx.state;
            if state.locked_by_current_thread() {
                return Err(stale());
            }
            let lock = state.lock()?;
            let budget = Rc::new(HistoryBudget::new());
            if !valid_env_id(env) {
                return Err(invalid());
            }
            // A Context just initialized in this process has not reopened its
            // device file. Bind the actual KMS-loaded full local record here;
            // cached labels or caller-created StateDir objects are not proof.
            let io = crate::import_barrier::ImportIo::bootstrap(state, budget.clone())?;
            let (_, source) = DeviceKey::load_or_create_in(&io, ctx.kms)?;
            state.bind_import_identity(&source)?;
            let generation = io.shared_generation();
            let paths = io.shared_paths();
            drop(source);
            drop(io);
            budget.check()?;
            Self::new_locked_seeded(
                state,
                env,
                Selection::Probe(purpose),
                lock,
                budget,
                generation,
                paths,
            )
        }
        pub(crate) fn nested(&self, state: &'a StateDir, env: &str) -> Result<Self> {
            self.check()?;
            if !std::ptr::eq(state, self.state) || env != self.env {
                return Err(stale());
            }
            let mut session = self.operation.lock_session()?;
            session.selection = self.selection;
            session.check()?;
            Ok(session)
        }
        pub(crate) fn into_resume(self) -> Result<HistoryResume<'a>> {
            self.check()?;
            Ok(HistoryResume {
                operation: self.operation.clone(),
                selection: self.selection,
                _thread: PhantomData,
            })
        }
        pub(crate) fn lease(&self) -> Result<HistoryResume<'a>> {
            self.check()?;
            Ok(HistoryResume {
                operation: self.operation.clone(),
                selection: self.selection,
                _thread: PhantomData,
            })
        }
        pub(crate) fn effect_boundary(&self, name: &str, point: &str) -> Result<()> {
            self.check()?;
            #[cfg(test)]
            crate::import_barrier::testing::hit(self.state, name, point)?;
            #[cfg(not(test))]
            let _ = (name, point);
            self.check()
        }
        pub(crate) fn invalidate(&self) -> Result<()> {
            let result = (|| {
                let generation = self.generation.get().checked_add(1).ok_or_else(limit)?;
                self.generation.set(generation);
                self.check()
            })();
            self.resource_result(result)
        }
        pub(crate) fn load_device(&self, ctx: &crate::context::Context) -> Result<DeviceKey> {
            if !std::ptr::eq(ctx.state, self.state) {
                return Err(stale());
            }
            let io = self.import_io()?;
            let (device, source) = if self.is_scoped() {
                DeviceKey::load_in(&io, ctx.kms)?
            } else {
                // Ordinary sharing can create its device before a Context has
                // an import binding. Keep that legacy contract within the
                // same finite I/O parent; it grants no imported authority.
                DeviceKey::load_or_create_in(&io, ctx.kms)?
            };
            source.check(self.state)?;
            self.match_local_identity(source.record())?;
            if self.is_scoped() && self.state.import_key_hash()? != Some(source.raw_hash()) {
                return Err(stale());
            }
            self.check()?;
            Ok(device)
        }
        pub(crate) fn local_record(&self) -> Result<&DeviceRecord> {
            self.check()?;
            self.identity.as_ref().ok_or_else(invalid)
        }
        fn preflight_value(&self, value: &Value) -> Result<(u64, u64)> {
            let result = (|| {
                let mut pending = vec![(value, 1usize)];
                let mut nodes = 0u64;
                let mut bytes = 0u64;
                while let Some((value, depth)) = pending.pop() {
                    nodes = nodes
                        .checked_add(1)
                        .filter(|n| *n <= NODES)
                        .ok_or_else(limit)?;
                    if depth > 64 {
                        return Err(limit());
                    }
                    let length = match value {
                        Value::String(text) => text.len() as u64,
                        Value::Number(number) => number.as_str().len() as u64,
                        _ => 1,
                    };
                    bytes = bytes
                        .checked_add(length.checked_mul(6).ok_or_else(limit)?)
                        .filter(|n| *n <= BULK)
                        .ok_or_else(limit)?;
                    match value {
                        Value::Array(values) => {
                            if pending
                                .len()
                                .checked_add(values.len())
                                .is_none_or(|n| n > NODES as usize)
                            {
                                return Err(limit());
                            }
                            self.charge(
                                values.len() as u64,
                                (values.len() as u64).checked_mul(32).ok_or_else(limit)?,
                            )?;
                            pending.extend(values.iter().map(|value| (value, depth + 1)));
                        }
                        Value::Object(values) => {
                            nodes = nodes
                                .checked_add(values.len() as u64)
                                .filter(|n| *n <= NODES)
                                .ok_or_else(limit)?;
                            if pending
                                .len()
                                .checked_add(values.len())
                                .is_none_or(|n| n > NODES as usize)
                            {
                                return Err(limit());
                            }
                            for (key, value) in values {
                                bytes = bytes
                                    .checked_add(
                                        (key.len() as u64).checked_mul(6).ok_or_else(limit)?,
                                    )
                                    .filter(|n| *n <= BULK)
                                    .ok_or_else(limit)?;
                                self.charge(1, 32)?;
                                pending.push((value, depth + 1));
                            }
                        }
                        _ => {}
                    }
                }
                self.charge(
                    nodes.checked_add(bytes).ok_or_else(limit)?,
                    nodes
                        .checked_mul(64)
                        .and_then(|n| n.checked_add(bytes))
                        .ok_or_else(limit)?,
                )?;
                self.check()?;
                Ok((nodes, bytes))
            })();
            self.resource_result(result)
        }
        fn encode_image(&self, value: &Value) -> Result<Vec<u8>> {
            let result = (|| {
                self.preflight_value(value)?;
                let mut pending = vec![value];
                let mut nonempty = 0u64;
                while let Some(value) = pending.pop() {
                    match value {
                        Value::Object(values) if !values.is_empty() => {
                            nonempty += 1;
                            pending.extend(values.values());
                        }
                        Value::Array(values) if !values.is_empty() => {
                            nonempty += 1;
                            pending.extend(values);
                        }
                        _ => {}
                    }
                }
                // encoded_len is a conservative existing counter: each nonempty
                // container reserves one trailing separator byte that dumps omits.
                let size = (crate::import_barrier::encoded_len(value)? as u64)
                    .checked_sub(nonempty)
                    .ok_or_else(limit)?;
                if size > BULK {
                    return Err(limit());
                }
                self.charge(
                    size.checked_mul(8).ok_or_else(limit)?,
                    size.checked_mul(8).ok_or_else(limit)?,
                )?;
                let bytes = pyjson::dumps(value, DumpOptions::pretty_sorted())?.into_bytes();
                if bytes.len() as u64 != size {
                    return Err(invalid());
                }
                self.screen(&bytes, BULK)?;
                self.check()?;
                Ok(bytes)
            })();
            self.resource_result(result)
        }
        fn measure_import_record(&self, value: &Value) -> Result<(u64, u64, u64)> {
            let mut pending = vec![(value, 0u64)];
            let (mut nodes, mut nonempty, mut sort) = (0u64, 0u64, 0u64);
            while let Some((value, depth)) = pending.pop() {
                self.charge_import(1, 64)?;
                nodes = nodes
                    .checked_add(1)
                    .filter(|n| *n <= NODES)
                    .ok_or_else(limit)?;
                if depth > 64 {
                    return Err(limit());
                }
                let scalar = match value {
                    Value::String(text) => text.len() as u64,
                    Value::Number(number) => number.as_str().len() as u64,
                    _ => 0,
                };
                // This reserves the unchanged encoded_len UTF-8/numeric walk
                // before that helper executes; its output is only a size.
                self.charge_import(
                    scalar.checked_mul(2).ok_or_else(limit)?,
                    scalar.checked_mul(4).ok_or_else(limit)?,
                )?;
                match value {
                    Value::Array(values) => {
                        if !values.is_empty() {
                            nonempty += 1;
                        }
                        self.charge_import(
                            values.len() as u64,
                            (values.len() as u64).checked_mul(64).ok_or_else(limit)?,
                        )?;
                        if pending
                            .len()
                            .checked_add(values.len())
                            .is_none_or(|n| n > NODES as usize)
                        {
                            return Err(limit());
                        }
                        pending.extend(values.iter().map(|value| (value, depth + 1)));
                    }
                    Value::Object(values) => {
                        if !values.is_empty() {
                            nonempty += 1;
                        }
                        let count = values.len() as u64;
                        nodes = nodes
                            .checked_add(count)
                            .filter(|n| *n <= NODES)
                            .ok_or_else(limit)?;
                        let width = values
                            .keys()
                            .map(|key| key.len() as u64 + 1)
                            .max()
                            .unwrap_or(1);
                        sort = sort
                            .checked_add(
                                count
                                    .checked_mul(count)
                                    .and_then(|n| n.checked_mul(width))
                                    .ok_or_else(limit)?,
                            )
                            .ok_or_else(limit)?;
                        if pending
                            .len()
                            .checked_add(values.len())
                            .is_none_or(|n| n > NODES as usize)
                        {
                            return Err(limit());
                        }
                        for (key, value) in values {
                            self.charge_import(
                                1 + 2 * key.len() as u64,
                                64 + 4 * key.len() as u64,
                            )?;
                            pending.push((value, depth + 1));
                        }
                    }
                    _ => {}
                }
            }
            let size = (crate::import_barrier::encoded_len(value)? as u64)
                .checked_sub(nonempty)
                .ok_or_else(limit)?;
            self.check_import_deadline()?;
            Ok((size, nodes, sort))
        }
        pub(crate) fn clone_import_record(&self, value: &Value) -> Result<Value> {
            let (size, nodes, _) = self.measure_import_record(value)?;
            self.charge_import(
                size.checked_add(nodes).ok_or_else(limit)?,
                size.checked_add(nodes.checked_mul(64).ok_or_else(limit)?)
                    .ok_or_else(limit)?,
            )?;
            let value = value.clone();
            self.check_import_deadline()?;
            Ok(value)
        }
        pub(crate) fn encode_import_record(&self, value: &Value) -> Result<Vec<u8>> {
            let (size, nodes, sort) = self.measure_import_record(value)?;
            self.charge_import(
                size.checked_mul(4)
                    .and_then(|n| n.checked_add(sort))
                    .ok_or_else(limit)?,
                size.checked_mul(4)
                    .and_then(|n| n.checked_add(nodes.checked_mul(64)?))
                    .ok_or_else(limit)?,
            )?;
            let raw = pyjson::dumps(value, DumpOptions::pretty_sorted())?.into_bytes();
            if raw.len() as u64 != size {
                return Err(invalid());
            }
            self.check_import_deadline()?;
            Ok(raw)
        }
        pub(crate) fn reserve_import_signature(&self, value: &Value) -> Result<()> {
            let (size, nodes, sort) = self.measure_import_record(value)?;
            // Canonical encoding, message hashing and the bounded signature
            // primitive; verification additionally clones its unsigned record.
            self.charge_import(
                size.checked_mul(6)
                    .and_then(|n| n.checked_add(sort))
                    .and_then(|n| n.checked_add(4096 + nodes))
                    .ok_or_else(limit)?,
                size.checked_mul(8)
                    .and_then(|n| n.checked_add(nodes.checked_mul(128)?))
                    .ok_or_else(limit)?,
            )
        }
        pub(crate) fn preflight_operations(&self, ops: &[Value]) -> Result<()> {
            let result = (|| {
                if !self.is_scoped() {
                    return Ok(());
                }
                let mut nodes = 0u64;
                let mut bytes = 0u64;
                for op in ops {
                    let (n, b) = self.preflight_value(op)?;
                    nodes = nodes
                        .checked_add(n)
                        .filter(|n| *n <= NODES)
                        .ok_or_else(limit)?;
                    bytes = bytes
                        .checked_add(b)
                        .filter(|n| *n <= BULK)
                        .ok_or_else(limit)?;
                }
                self.check()
            })();
            self.resource_result(result)
        }
        pub(super) fn preflight_candidate(&self, candidate: &Commit) -> Result<()> {
            let result = (|| {
                if candidate.seen.len() > 256 || candidate.ops.len() > NODES as usize {
                    return Err(limit());
                }
                let header = candidate.format.len()
                    + candidate.env_id.len()
                    + candidate.author.len()
                    + candidate.hlc.len()
                    + candidate.sig.len();
                self.charge(
                    header as u64,
                    (header as u64).checked_mul(8).ok_or_else(limit)?,
                )?;
                let mut nodes = 16u64;
                let mut bytes = header as u64;
                for op in &candidate.ops {
                    let (n, b) = self.preflight_value(op)?;
                    nodes = nodes
                        .checked_add(n)
                        .filter(|n| *n <= NODES)
                        .ok_or_else(limit)?;
                    bytes = bytes
                        .checked_add(b)
                        .filter(|n| *n <= BULK)
                        .ok_or_else(limit)?;
                }
                self.charge(
                    nodes,
                    nodes
                        .checked_mul(128)
                        .and_then(|n| n.checked_add(bytes.checked_mul(8)?))
                        .ok_or_else(limit)?,
                )?;
                for (author, seq) in &candidate.seen {
                    let size = seq
                        .0
                        .bits()
                        .checked_add(author.len() as u64)
                        .ok_or_else(limit)?;
                    self.charge(size, size.checked_mul(8).ok_or_else(limit)?)?;
                }
                let size = candidate.author_seq.0.bits();
                self.charge(size, size.checked_mul(8).ok_or_else(limit)?)?;
                self.check()
            })();
            self.resource_result(result)
        }
        pub(crate) fn reserve_writer(&self, name: &str, length: u64) -> Result<()> {
            let result = (|| {
                if length > BULK {
                    return Err(limit());
                }
                let mut path_bytes = self.state.path.as_os_str().len() as u64;
                let mut path = self.state.path.clone();
                for component in std::path::Path::new(name).components() {
                    path.push(component);
                    path_bytes = path_bytes
                        .checked_add(path.as_os_str().len() as u64)
                        .ok_or_else(limit)?;
                }
                let cost = length
                    .checked_add(path_bytes)
                    .and_then(|n| n.checked_add(1))
                    .and_then(|n| n.checked_mul(16))
                    .ok_or_else(limit)?;
                self.charge(cost, cost)
            })();
            self.resource_result(result)
        }
        pub(crate) fn screen_original(&self, raw: &[u8]) -> Result<()> {
            self.screen(raw, BULK)
        }
        pub(crate) fn preflight_inventory(&self) -> Result<()> {
            if self.is_scoped() {
                self.collect()?;
            }
            self.check()
        }
        pub(crate) fn journal_record(&self, raw: &[u8]) -> Result<Value> {
            self.screen(raw, INVENTORY)?;
            let n = raw.len() as u64;
            self.charge_import(
                n.checked_mul(5).ok_or_else(limit)?,
                n.checked_mul(96).ok_or_else(limit)?,
            )?;
            let value =
                checkpoint::retained_original(raw).map_err(|error| Error::state(error.reason()))?;
            self.check()?;
            Ok(value)
        }

        pub(crate) fn reserve_counts(&self, [c, o, t, f, d, s, b]: [u64; 7]) -> Result<()> {
            let result = (|| {
                let q = 1u64
                    .checked_add(c)
                    .and_then(|n| n.checked_add(o))
                    .and_then(|n| n.checked_add(t))
                    .and_then(|n| n.checked_add(d))
                    .ok_or_else(limit)?;
                let ff = f.checked_mul(f).ok_or_else(limit)?;
                let scale = 8u64
                    .checked_mul(s.checked_add(2).ok_or_else(limit)?)
                    .ok_or_else(limit)?;
                let work = q
                    .checked_mul(q)
                    .and_then(|n| {
                        ff.checked_mul(c.checked_add(o)?.checked_add(1)?)
                            .and_then(|v| n.checked_add(v))
                    })
                    .and_then(|n| n.checked_mul(scale))
                    .ok_or_else(limit)?;
                let bytes = c
                    .checked_add(o)
                    .and_then(|n| n.checked_add(t))
                    .and_then(|n| n.checked_add(ff))
                    .and_then(|n| n.checked_add(1))
                    .and_then(|n| n.checked_mul(b.checked_add(1)?))
                    .and_then(|n| n.checked_mul(scale))
                    .ok_or_else(limit)?;
                self.charge(work, bytes)
            })();
            self.resource_result(result)
        }
        pub(crate) fn match_local_identity(&self, record: &DeviceRecord) -> Result<()> {
            self.check()?;
            if self.is_scoped() && self.identity.as_ref() != Some(record) {
                return Err(stale());
            }
            Ok(())
        }
        fn resource_result<T>(&self, result: Result<T>) -> Result<T> {
            if self.is_scoped()
                && self.budget.failure.get().is_none()
                && let Err(error) = &result
            {
                match error.reason.as_ref() {
                    "team_bootstrap_limit_exceeded" => {
                        self.budget.failure.set(Some(BudgetFailure::Limit))
                    }
                    "team_bootstrap_timeout" => {
                        self.budget.failure.set(Some(BudgetFailure::Timeout))
                    }
                    _ => {}
                }
            }
            result
        }
        pub(crate) fn state(&self) -> &'a StateDir {
            self.state
        }
        pub(crate) fn mutation_generation(&self) -> Result<u64> {
            self.check_import_deadline()?;
            Ok(self.generation.get())
        }
        pub(crate) fn check_import_deadline(&self) -> Result<()> {
            self.budget.check()?;
            if !self.state.locked_by_current_thread() {
                return Err(stale());
            }
            Ok(())
        }
        pub(crate) fn charge_import(&self, work: u64, bytes: u64) -> Result<()> {
            self.budget.charge(work, bytes)?;
            #[cfg(test)]
            {
                let counters = self.budget.counters.borrow();
                testing::charge(self.state, work, bytes, counters.work, counters.bytes);
            }
            Ok(())
        }
        pub(crate) fn import_io(&self) -> Result<crate::import_barrier::ImportIo<'_, 'a>> {
            crate::import_barrier::ImportIo::with_history(self)
        }
        pub(crate) fn import_budget(&self) -> Rc<HistoryBudget> {
            self.budget.clone()
        }
        pub(crate) fn import_paths(&self) -> Rc<crate::import_barrier::ImportPathCache> {
            self.operation.paths.clone()
        }
        pub(crate) fn env(&self) -> &str {
            &self.env
        }
        // Routing only. This flag cannot construct a sealed input or proof.
        pub(crate) fn is_scoped(&self) -> bool {
            !matches!(self.selection, Selection::Ordinary)
        }
        pub(crate) fn check_deadline(&self) -> Result<()> {
            if self.is_scoped() {
                self.budget.check()?;
            }
            Ok(())
        }
        pub(crate) fn check(&self) -> Result<()> {
            if !self.state.locked_by_current_thread() {
                return Err(stale());
            }
            if self.is_scoped() {
                // Reserve the bounded descriptor/root reobservation before its
                // syscalls. ACL/private-path validation belongs to this held
                // operation; a complete changed root/lock revision refuses.
                self.budget.charge(
                    64 + 4 * self.state.path.as_os_str().len() as u64,
                    256 + 4 * self.state.path.as_os_str().len() as u64,
                )?;
                let current_root = self.state.import_root_revision()?;
                if self.state.import_identity() != self.identity.as_ref()
                    || self
                        .operation
                        .root
                        .as_ref()
                        .is_none_or(|root| !root.same_anchor(&current_root))
                {
                    #[cfg(test)]
                    crate::import_barrier::opus_cost::note(
                        self.state,
                        &self.env,
                        &format!(
                            "root_revision_changed:{:x}",
                            self.operation
                                .root
                                .as_ref()
                                .map_or(0, |old| old.changed_fields(&current_root))
                        ),
                    );
                    return Err(stale());
                }
                if self.operation.root_observation.borrow().as_ref() != Some(&current_root) {
                    self.budget.charge(
                        4096 + 8 * self.state.path.as_os_str().len() as u64,
                        4096 + 8 * self.state.path.as_os_str().len() as u64,
                    )?;
                    self.state.checked_import_root()?;
                    if self.state.import_root_revision()? != current_root {
                        return Err(stale());
                    }
                    *self.operation.root_observation.borrow_mut() = Some(current_root);
                }
            }
            Ok(())
        }
        pub(crate) fn charge(&self, work: u64, bytes: u64) -> Result<()> {
            if self.is_scoped() {
                self.budget.charge(work, bytes)?;
                #[cfg(test)]
                {
                    let counters = self.budget.counters.borrow();
                    testing::charge(self.state, work, bytes, counters.work, counters.bytes);
                }
            }
            Ok(())
        }
        pub(crate) fn acquire(&self) -> Result<RetainedInput<'_, 'a>> {
            let result = (|| {
                self.check()?;
                let generation = self.generation.get();
                if !self.is_scoped() {
                    return Ok(RetainedInput {
                        session: self,
                        generation,
                        inventory: None,
                        originals: Rc::new(Vec::new()),
                        vector: Rc::new(BTreeMap::new()),
                        floor: Rc::new(BTreeMap::new()),
                        _thread: PhantomData,
                    });
                }
                let cached = {
                    let retained = self.operation.retained.borrow();
                    retained
                        .as_ref()
                        .filter(|captured| captured.generation == generation)
                        .map(|captured| RetainedInput {
                            session: self,
                            generation,
                            inventory: Some(captured.inventory.clone()),
                            originals: captured.originals.clone(),
                            vector: captured.vector.clone(),
                            floor: captured.floor.clone(),
                            _thread: PhantomData,
                        })
                };
                if let Some(input) = cached {
                    self.charge(4, 256)?;
                    // authenticate_selection already checks the complete raw
                    // revision both before and after its pure validation.
                    let checked =
                        if matches!(self.selection, Selection::Owner | Selection::Recipient) {
                            input.authenticate_selection()
                        } else {
                            input.current()
                        };
                    match checked {
                        Ok(()) => return Ok(input),
                        Err(error) if error.reason == "team_bootstrap_local_state_changed" => {
                            // A fresh acquisition may follow an observed local
                            // writer. Invalidate all older sealed generations,
                            // then recapture the complete originals on the SAME
                            // budget. No stale input or settled fact survives.
                            self.check()?;
                            self.invalidate()?;
                            self.operation.retained.borrow_mut().take();
                        }
                        Err(error) => return Err(error),
                    }
                }
                let generation = self.generation.get();
                let inventory = self.collect()?;
                #[cfg(test)]
                testing::acquired(self.state, inventory.entries as u64);
                let mut originals = Vec::new();
                let mut slots = BTreeSet::new();
                for (path, file) in &inventory.files {
                    let suffix = path.strip_prefix(&format!("team/{}/commits/", self.env));
                    let Some(suffix) = suffix else { continue };
                    let pieces = suffix.split('/').collect::<Vec<_>>();
                    if pieces.len() != 2 || !is_fingerprint(pieces[0]) {
                        return Err(invalid());
                    }
                    let seq = canonical_number(self, pieces[1], true)?;
                    #[cfg(test)]
                    testing::slot(self.state);
                    if !slots.insert((pieces[0].to_owned(), seq.clone())) {
                        return Err(invalid());
                    }
                    // Reserve the conversion/equality/raw and parsed copies before
                    // any of them materializes: at most sixteen byte/node walks
                    // and sixty-four charged heap bytes per original source byte.
                    self.charge(
                        (file.raw.len() as u64).checked_mul(16).ok_or_else(limit)?,
                        (file.raw.len() as u64).checked_mul(64).ok_or_else(limit)?,
                    )?;
                    let value = self.parse(&file.raw)?;
                    if value["seen"].as_object().is_some_and(|m| m.len() > 256) {
                        return Err(limit());
                    }
                    let seen = value["seen"].as_object().ok_or_else(invalid)?;
                    let mut conversion_work = 0u64;
                    for integer in std::iter::once(&value["author_seq"]).chain(seen.values()) {
                        let Value::Number(number) = integer else {
                            return Err(invalid());
                        };
                        let length = number.as_str().len() as u64;
                        conversion_work = conversion_work
                            .checked_add(length.checked_mul(length).ok_or_else(limit)?)
                            .ok_or_else(limit)?;
                    }
                    for part in value["hlc"].as_str().ok_or_else(invalid)?.split('-') {
                        let length = part.len() as u64;
                        conversion_work = conversion_work
                            .checked_add(length.checked_mul(length).ok_or_else(limit)?)
                            .ok_or_else(limit)?;
                    }
                    self.charge(conversion_work, 0)?;
                    let op_count = match &value["ops"] {
                        Value::Array(v) => v.len(),
                        Value::Object(v) => v.len(),
                        Value::String(v) => v.len(),
                        _ => 1,
                    };
                    self.charge(
                        op_count as u64,
                        (op_count as u64).checked_mul(64).ok_or_else(limit)?,
                    )?;
                    let commit = Commit::from_dict(&value)?;
                    if commit.to_dict() != value
                        || commit.format != COMMIT_FORMAT
                        || commit.env_id != self.env
                        || commit.author != pieces[0]
                        || commit.author_seq != seq
                    {
                        return Err(invalid());
                    }
                    validate_ops(&commit.ops)?;
                    Hlc::parse(&commit.hlc)?;
                    self.charge(1, file.raw.len() as u64)?;
                    originals.push(RetainedOriginal {
                        path: path.clone(),
                        raw: file.raw.clone(),
                        parsed: commit,
                    });
                    if originals.len() > ENTRIES {
                        return Err(limit());
                    }
                }
                // Both stable sorts compare encoded arbitrary-precision integers.
                // Reserve their worst-case comparisons before either sort; numeric
                // magnitude never controls a walk or is cast to an index.
                let width = originals
                    .iter()
                    .map(|o| {
                        o.parsed.author.len()
                            + o.parsed.author_seq.to_string().len()
                            + o.parsed.hlc.len()
                    })
                    .max()
                    .unwrap_or(1) as u64;
                let count = originals.len() as u64;
                self.charge(
                    count
                        .checked_mul(count)
                        .and_then(|n| n.checked_mul(width))
                        .and_then(|n| n.checked_mul(2))
                        .ok_or_else(limit)?,
                    0,
                )?;
                originals.sort_by(|a, b| {
                    a.parsed
                        .author
                        .cmp(&b.parsed.author)
                        .then(a.parsed.author_seq.cmp(&b.parsed.author_seq))
                });
                let mut keyed = Vec::with_capacity(originals.len());
                for original in originals {
                    self.charge(1, 0)?;
                    keyed.push((order_key(&original.parsed)?, original));
                }
                keyed.sort_by(|a, b| a.0.cmp(&b.0));
                let originals = keyed.into_iter().map(|(_, o)| o).collect::<Vec<_>>();
                let commits = originals
                    .iter()
                    .map(|o| o.parsed.clone())
                    .collect::<Vec<_>>();
                let mut public_records = BTreeMap::new();
                for commit in &commits {
                    for op in &commit.ops {
                        let value = match op["op"].as_str() {
                            Some("env.init") => Some(&op["owner_device"]),
                            Some("member.add") => Some(&op["device"]),
                            _ => None,
                        };
                        if let Some(value) = value {
                            let record = DeviceRecord::from_dict(value)?;
                            let fp = record.fingerprint();
                            if !public_records.contains_key(&fp) && public_records.len() >= 256 {
                                return Err(limit());
                            }
                            self.charge(4096, 256)?;
                            self.check()?;
                            if !record.verify() {
                                return Err(invalid());
                            }
                            self.check()?;
                            if public_records
                                .get(&fp)
                                .is_some_and(|previous| previous != &record)
                            {
                                return Err(invalid());
                            }
                            public_records.insert(fp, record);
                        }
                    }
                }
                // The existing first-verified registry and signature checks remain
                // the consumers. Preflight above bounds their physical record walk.
                let registry = device_registry(&commits);
                for original in &originals {
                    self.charge(4096, original.raw.len() as u64)?;
                    self.check()?;
                    if !registry
                        .get(&original.parsed.author)
                        .is_some_and(|r| verify_commit(&original.parsed, r))
                    {
                        return Err(invalid());
                    }
                    self.check()?;
                }
                let mut snapshots = Vec::new();
                for path in inventory.files.keys() {
                    if let Some(name) = path.strip_prefix(&format!("team/{}/snapshots/", self.env))
                    {
                        snapshots.push((canonical_number(self, name, false)?, path));
                    }
                }
                let count = snapshots.len() as u64;
                let width = snapshots
                    .iter()
                    .map(|(_, path)| path.len())
                    .max()
                    .unwrap_or(1) as u64;
                self.charge(
                    count
                        .checked_mul(count)
                        .and_then(|n| n.checked_mul(width))
                        .ok_or_else(limit)?,
                    0,
                )?;
                snapshots.sort_by(|a, b| a.0.cmp(&b.0));
                let mut vector = BTreeMap::new();
                if let Some((_, path)) = snapshots.last() {
                    let snapshot = self.parse(&inventory.files[*path].raw)?;
                    let values = snapshot["vector"].as_object().ok_or_else(invalid)?;
                    if values.len() > 256 {
                        return Err(limit());
                    }
                    for (author, value) in values {
                        let n = PyInt::from_json_integer(value)
                            .filter(|n| *n >= 0)
                            .ok_or_else(invalid)?;
                        if !is_fingerprint(author) {
                            return Err(invalid());
                        }
                        vector.insert(author.clone(), n);
                    }
                }
                let floor = vector.clone();
                for (author, seq) in slots {
                    let previous = vector.entry(author.clone()).or_insert_with(PyInt::zero);
                    if seq > *previous {
                        if seq != &*previous + 1 {
                            return Err(Error::state("team_checkpoint_history_required"));
                        }
                        *previous = seq;
                    }
                    if !floor.contains_key(&author) && *previous < 0 {
                        return Err(invalid());
                    }
                }
                self.check()?;
                let input = RetainedInput {
                    session: self,
                    generation,
                    inventory: Some(Rc::new(inventory)),
                    originals: Rc::new(originals),
                    vector: Rc::new(vector),
                    floor: Rc::new(floor),
                    _thread: PhantomData,
                };
                if matches!(self.selection, Selection::Owner | Selection::Recipient) {
                    input.authenticate_selection()?;
                } else {
                    input.current()?;
                }
                *self.operation.retained.borrow_mut() = Some(CapturedHistory {
                    generation,
                    inventory: input.inventory.as_ref().ok_or_else(invalid)?.clone(),
                    originals: input.originals.clone(),
                    vector: input.vector.clone(),
                    floor: input.floor.clone(),
                });
                Ok(input)
            })();
            self.resource_result(result)
        }
        fn screen(&self, raw: &[u8], cap: u64) -> Result<()> {
            let result = (|| {
                // Reserve before any tree is built. The syntax engine does not
                // supply resource, signed-record, or authority assurance.
                if raw.len() as u64 > cap {
                    return Err(limit());
                }
                let mut nodes = 0u64;
                let mut depth = 0u64;
                let mut quoted = false;
                let mut escaped = false;
                let mut scalar = false;
                self.charge(
                    raw.len() as u64,
                    (raw.len() as u64).checked_mul(4).ok_or_else(limit)?,
                )?;
                for byte in raw {
                    if quoted {
                        if escaped {
                            escaped = false;
                        } else if *byte == b'\\' {
                            escaped = true;
                        } else if *byte == b'"' {
                            quoted = false;
                        }
                        continue;
                    }
                    match *byte {
                        b'"' => {
                            quoted = true;
                            scalar = false;
                            nodes = nodes.checked_add(1).ok_or_else(limit)?;
                        }
                        b'{' | b'[' => {
                            depth = depth.checked_add(1).ok_or_else(limit)?;
                            if depth > 64 {
                                return Err(limit());
                            }
                            nodes = nodes.checked_add(1).ok_or_else(limit)?;
                            scalar = false;
                        }
                        b'}' | b']' => {
                            depth = depth.checked_sub(1).ok_or_else(invalid)?;
                            scalar = false;
                        }
                        b' ' | b'\n' | b'\r' | b'\t' | b',' | b':' => scalar = false,
                        _ => {
                            if !scalar {
                                nodes = nodes.checked_add(1).ok_or_else(limit)?;
                            }
                            scalar = true;
                        }
                    }
                    if nodes > NODES {
                        return Err(limit());
                    }
                }
                self.charge(nodes, nodes.checked_mul(64).ok_or_else(limit)?)?;
                self.check()
            })();
            self.resource_result(result)
        }
        fn parse(&self, raw: &[u8]) -> Result<Value> {
            self.screen(raw, BULK)?;
            let value = checkpoint::retained_original(raw).map_err(|e| Error::state(e.reason()))?;
            self.check()?;
            Ok(value)
        }
        pub(crate) fn parse_line(&self, line: &str) -> Result<Value> {
            self.check()?;
            if self.is_scoped() {
                let parsed = self.parse(line.as_bytes()).and_then(|value| {
                    if let Some(hlc) = value["hlc"].as_str() {
                        let work = hlc.split('-').try_fold(hlc.len() as u64, |sum, part| {
                            let length = part.len() as u64;
                            sum.checked_add(length.checked_mul(length).ok_or_else(limit)?)
                                .ok_or_else(limit)
                        })?;
                        self.charge(work, 0)?;
                    }
                    self.check()?;
                    Ok(value)
                });
                // Legacy fact predicates intentionally discard syntax-invalid
                // lines. Resource refusal is sticky across those predicates:
                // it can never become a quarantine/rewrite or partial allow.
                if let Err(error) = &parsed {
                    match error.reason.as_ref() {
                        "team_bootstrap_limit_exceeded" => {
                            self.budget.failure.set(Some(BudgetFailure::Limit))
                        }
                        "team_bootstrap_timeout" => {
                            self.budget.failure.set(Some(BudgetFailure::Timeout))
                        }
                        _ => {}
                    }
                }
                parsed
            } else {
                pyjson::loads(line).map_err(|_| Error::state("state_corrupt"))
            }
        }
        fn collect(&self) -> Result<Inventory> {
            let result = (|| {
                #[cfg(test)]
                let _stage = testing::span(self.state, "history_collect");
                let io = self.import_io()?;
                let root = io.anchor_revision()?;
                let mut files = BTreeMap::new();
                let mut stamps = BTreeMap::new();
                let mut layout = BTreeSet::new();
                let mut hash = Sha256::new();
                self.charge(176, 176)?;
                root.visit_words(|word| hash.update(word.to_be_bytes()));
                let mut entries = 0usize;
                let mut bytes = 0u64;
                let envroot = format!("team/{}", self.env);
                let mut pending = vec![(envroot, 0usize)];
                while let Some((name, depth)) = pending.pop() {
                    self.check()?;
                    if depth > 64 {
                        return Err(limit());
                    }
                    let path = self.state.path.join(&name);
                    let metadata = match fs::symlink_metadata(&path) {
                        Ok(v) => v,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            stamps.insert(name.clone(), None);
                            continue;
                        }
                        Err(_) => return Err(invalid()),
                    };
                    stamps.insert(name.clone(), Some(stamp(&metadata)));
                    layout.insert((name.clone(), metadata.is_dir()));
                    io.validate_relative(&name, metadata.is_dir())?;
                    self.charge(name.len() as u64, name.len() as u64)?;
                    hash.update((name.len() as u64).to_be_bytes());
                    hash.update(name.as_bytes());
                    let stamp = stamp(&metadata);
                    for item in &stamp {
                        hash.update(item.to_be_bytes());
                    }
                    if metadata.is_dir() {
                        if name == format!("team/{}/commits", self.env)
                            || name.starts_with(&format!("team/{}/commits/", self.env))
                        {
                            let suffix = name
                                .strip_prefix(&format!("team/{}/commits", self.env))
                                .unwrap();
                            if !suffix.is_empty()
                                && (suffix.len() != 27
                                    || !suffix.starts_with('/')
                                    || !is_fingerprint(&suffix[1..]))
                            {
                                return Err(invalid());
                            }
                        }
                        let directory = fs::read_dir(path).map_err(|_| invalid())?;
                        for entry in directory {
                            let entry = entry.map_err(|_| invalid())?;
                            entries = entries
                                .checked_add(1)
                                .filter(|n| *n <= ENTRIES)
                                .ok_or_else(limit)?;
                            self.charge(1, 256)?;
                            let leaf = entry.file_name().into_string().map_err(|_| invalid())?;
                            if leaf.is_empty() || leaf == "." || leaf == ".." {
                                return Err(invalid());
                            }
                            pending.push((format!("{name}/{leaf}"), depth + 1));
                        }
                        self.charge(
                            (pending.len() as u64)
                                .checked_mul(pending.len() as u64)
                                .ok_or_else(limit)?,
                            0,
                        )?;
                        pending.sort_by(|a, b| b.0.cmp(&a.0));
                    } else {
                        if !metadata.is_file() {
                            return Err(invalid());
                        }
                        if name.starts_with(&format!("team/{}/commits/", self.env)) {
                            let suffix = name
                                .strip_prefix(&format!("team/{}/commits/", self.env))
                                .unwrap();
                            let parts = suffix.split('/').collect::<Vec<_>>();
                            if parts.len() != 2 || !is_fingerprint(parts[0]) {
                                return Err(invalid());
                            }
                            canonical_number(self, parts[1], true)?;
                        }
                        for directory in ["snapshots", "snapshot_records"] {
                            if let Some(leaf) =
                                name.strip_prefix(&format!("team/{}/{directory}/", self.env))
                            {
                                canonical_number(self, leaf, false)?;
                            }
                        }
                        let cap = if name.ends_with("/journal.json") || name.ends_with(".jsonl") {
                            INVENTORY
                        } else if name.contains("/bootstrap/")
                            && !name.ends_with("/payload.json")
                            && name
                                != format!("team/{}/bootstrap/local-removal-denial.json", self.env)
                            && !name.contains("/staging/")
                        {
                            65_536
                        } else {
                            BULK
                        };
                        bytes = bytes
                            .checked_add(metadata.len())
                            .filter(|n| *n <= INVENTORY)
                            .ok_or_else(limit)?;
                        // Cold evidence is inventory, never a hot history/fold
                        // input. Payload integrity is streamed by the borrowed
                        // visibility epoch before use, without materialization.
                        if name
                            == format!(
                                "team/{}/bootstrap/provenance/install-journal.json",
                                self.env
                            )
                            || name
                                == format!("team/{}/bootstrap/provenance/payload.json", self.env)
                        {
                            let cold_cap = if name.ends_with("/install-journal.json") {
                                INVENTORY
                            } else {
                                BULK
                            };
                            if metadata.len() > cold_cap {
                                return Err(limit());
                            }
                            self.charge(1, 256)?;
                            continue;
                        }
                        let raw = self.read_file(&io, &name, cap, &metadata)?;
                        if name.ends_with(".json") {
                            self.screen(&raw, cap)?;
                        }
                        for aux in ["deferred", "rejected"] {
                            if let Some(leaf) =
                                name.strip_prefix(&format!("team/{}/{aux}/", self.env))
                            {
                                if leaf.contains('/') {
                                    return Err(invalid());
                                }
                                let value = self.parse(&raw)?;
                                let commit = Commit::from_dict(&value)?;
                                if !is_fingerprint(&commit.author) || commit.env_id != self.env {
                                    return Err(invalid());
                                }
                                let expected = if aux == "deferred" {
                                    format!("{}-{:010}.json", commit.author, commit.author_seq)
                                } else {
                                    let digest = commit.hash()?;
                                    format!(
                                        "{}-{:010}-{}.json",
                                        commit.author,
                                        commit.author_seq,
                                        &digest[..12]
                                    )
                                };
                                if leaf != expected {
                                    return Err(invalid());
                                }
                            }
                        }
                        hash.update(Sha256::digest(&raw));
                        files.insert(name, FileImage { raw });
                    }
                }
                // Bound global import discovery before the existing authenticated
                // index walker can read any journal from another environment.
                let mut discovered = BTreeSet::new();
                let mut listed = 0usize;
                let mut journal_bytes = 0u64;
                let team = self.state.path.join("team");
                self.charge(1, 256)?;
                stamps.insert(
                    "team".into(),
                    Some(stamp(&fs::symlink_metadata(&team).map_err(|_| invalid())?)),
                );
                let mut global_names = Vec::new();
                for entry in fs::read_dir(&team).map_err(|_| invalid())? {
                    listed = listed
                        .checked_add(1)
                        .filter(|n| *n <= ENTRIES)
                        .ok_or_else(limit)?;
                    self.charge(1, 256)?;
                    let leaf = entry
                        .map_err(|_| invalid())?
                        .file_name()
                        .into_string()
                        .map_err(|_| invalid())?;
                    global_names.push(leaf);
                }
                let count = global_names.len() as u64;
                let width = global_names.iter().map(String::len).max().unwrap_or(1) as u64;
                self.charge(
                    count
                        .checked_mul(count)
                        .and_then(|n| n.checked_mul(width))
                        .ok_or_else(limit)?,
                    0,
                )?;
                global_names.sort();
                for leaf in global_names {
                    let directory =
                        fs::symlink_metadata(team.join(&leaf)).map_err(|_| invalid())?;
                    stamps.insert(format!("team/{leaf}"), Some(stamp(&directory)));
                    hash.update(leaf.as_bytes());
                    for item in stamp(&directory) {
                        hash.update(item.to_be_bytes());
                    }
                    if !valid_env_id(&leaf) {
                        continue;
                    }
                    if !directory.is_dir() {
                        return Err(invalid());
                    }
                    io.validate_relative(&format!("team/{leaf}"), true)?;
                    discovered.insert(leaf.clone());
                    if discovered.len() > 256 {
                        return Err(limit());
                    }
                    let name = format!("team/{leaf}/bootstrap/journal.json");
                    let metadata = match fs::symlink_metadata(self.state.path.join(&name)) {
                        Ok(v) => v,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            stamps.insert(name.clone(), None);
                            continue;
                        }
                        Err(_) => return Err(invalid()),
                    };
                    stamps.insert(name.clone(), Some(stamp(&metadata)));
                    journal_bytes = journal_bytes
                        .checked_add(metadata.len())
                        .filter(|n| *n <= INVENTORY)
                        .ok_or_else(limit)?;
                    if let std::collections::btree_map::Entry::Vacant(slot) =
                        files.entry(name.clone())
                    {
                        io.validate_relative(&name, false)?;
                        let raw = self.read_file(&io, &name, INVENTORY, &metadata)?;
                        self.screen(&raw, INVENTORY)?;
                        // Existing journals are signed local records. Reserve the
                        // bounded opaque index/parser walk before calling it.
                        self.charge(
                            (raw.len() as u64).checked_mul(8).ok_or_else(limit)?,
                            (raw.len() as u64).checked_mul(8).ok_or_else(limit)?,
                        )?;
                        layout.insert((name.clone(), false));
                        hash.update(name.as_bytes());
                        for item in stamp(&metadata) {
                            hash.update(item.to_be_bytes());
                        }
                        hash.update(Sha256::digest(&raw));
                        slot.insert(FileImage { raw });
                    }
                }
                // These mutable shared inventories participate in every revision.
                let mut shared = 0u64;
                for name in [
                    crate::vault::VAULT_DOC,
                    crate::policy::CONNECTIONS,
                    crate::projects::DOC,
                    crate::policy::CONTROL,
                    crate::tombstone::PATH,
                    super::super::sync::ENVS_MAP_PATH,
                    crate::import_barrier::INDEX,
                ] {
                    let metadata = match fs::symlink_metadata(self.state.path.join(name)) {
                        Ok(v) => v,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            stamps.insert(name.into(), None);
                            hash.update(name.as_bytes());
                            hash.update([0]);
                            continue;
                        }
                        Err(_) => return Err(invalid()),
                    };
                    stamps.insert(name.into(), Some(stamp(&metadata)));
                    shared = shared
                        .checked_add(metadata.len())
                        .filter(|n| *n <= INVENTORY)
                        .ok_or_else(limit)?;
                    io.validate_relative(name, false)?;
                    let raw = self.read_file(&io, name, INVENTORY, &metadata)?;
                    self.screen(&raw, INVENTORY)?;
                    if [
                        crate::import_barrier::INDEX,
                        super::super::sync::ENVS_MAP_PATH,
                    ]
                    .contains(&name)
                    {
                        journal_bytes = journal_bytes
                            .checked_add(raw.len() as u64)
                            .filter(|n| *n <= INVENTORY)
                            .ok_or_else(limit)?;
                        let value = self.parse(&raw)?;
                        let environments = value.as_object().ok_or_else(invalid)?;
                        for env in environments.keys() {
                            self.charge(env.len() as u64, env.len() as u64)?;
                            if !valid_env_id(env) {
                                return Err(invalid());
                            }
                            discovered.insert(env.clone());
                            if discovered.len() > 256 {
                                return Err(limit());
                            }
                        }
                    }
                    layout.insert((name.into(), false));
                    hash.update(name.as_bytes());
                    let stamp = stamp(&metadata);
                    for item in &stamp {
                        hash.update(item.to_be_bytes());
                    }
                    hash.update(Sha256::digest(&raw));
                    files.insert(name.into(), FileImage { raw });
                }
                // Bind local identity without reading or retaining wrapped private
                // device-key material. Any same-thread key-file rewrite changes its
                // inode/ctime revision; signing also compares the loaded full record.
                let identity_path = crate::team::identity::DEVICE_KEY_FILE;
                io.validate_relative(identity_path, false)?;
                let metadata = fs::symlink_metadata(self.state.path.join(identity_path))
                    .map_err(|_| invalid())?;
                stamps.insert(identity_path.into(), Some(stamp(&metadata)));
                layout.insert((identity_path.into(), false));
                self.charge(1, 256)?;
                hash.update(identity_path.as_bytes());
                for item in stamp(&metadata) {
                    hash.update(item.to_be_bytes());
                }
                if let Some(record) = &self.identity {
                    let public = pyjson::dumps(&record.to_dict(), DumpOptions::compact_sorted())?;
                    self.charge(public.len() as u64, public.len() as u64)?;
                    hash.update(public.as_bytes());
                }
                // Fold reservations include every captured raw fact/document/
                // snapshot input, including shared deny-ledger and import records.
                let bytes = files.values().try_fold(0u64, |sum, image| {
                    sum.checked_add(image.raw.len() as u64).ok_or_else(limit)
                })?;
                self.check()?;
                if io.anchor_revision()? != root {
                    return Err(stale());
                }
                Ok(Inventory {
                    stamps,
                    root,
                    files,
                    layout,
                    revision: hash.finalize().into(),
                    entries,
                    bytes,
                })
            })();
            self.resource_result(result)
        }
        fn read_file(
            &self,
            io: &crate::import_barrier::ImportIo<'_, '_>,
            name: &str,
            cap: u64,
            before: &fs::Metadata,
        ) -> Result<Vec<u8>> {
            let raw = io.read(name, cap)?.ok_or_else(invalid)?;
            if raw.len() as u64 != before.len()
                || stamp(&fs::symlink_metadata(self.state.path.join(name)).map_err(|_| invalid())?)
                    != stamp(before)
            {
                return Err(stale());
            }
            self.check()?;
            Ok(raw)
        }
    }

    fn anchored_file(state: &StateDir, name: &str) -> Result<std::fs::File> {
        use rustix::fs::{Mode, OFlags, open, openat};
        let mut directory = open(
            &state.path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| invalid())?;
        let parts = std::path::Path::new(name).components().collect::<Vec<_>>();
        for (i, part) in parts.iter().enumerate() {
            let std::path::Component::Normal(part) = part else {
                return Err(invalid());
            };
            let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            if i + 1 < parts.len() {
                flags |= OFlags::DIRECTORY;
            }
            let next = openat(&directory, *part, flags, Mode::empty()).map_err(|_| invalid())?;
            if i + 1 == parts.len() {
                return Ok(std::fs::File::from(next));
            }
            directory = next;
        }
        Err(invalid())
    }
    fn stamp(m: &fs::Metadata) -> Vec<u64> {
        vec![
            m.dev(),
            m.ino(),
            m.mode() as u64,
            m.uid() as u64,
            m.gid() as u64,
            m.nlink(),
            m.len(),
            m.mtime() as u64,
            m.mtime_nsec() as u64,
            m.ctime() as u64,
            m.ctime_nsec() as u64,
        ]
    }
    fn canonical_number(session: &HistorySession<'_>, name: &str, positive: bool) -> Result<PyInt> {
        let length = name.len() as u64;
        session.charge(length.checked_mul(length).ok_or_else(limit)?, length)?;
        let stem = name.strip_suffix(".json").ok_or_else(invalid)?;
        if stem.is_empty()
            || stem.len() > 4300
            || !stem.bytes().all(|b| b.is_ascii_digit())
            || (stem.len() > 1 && stem.starts_with('0'))
            || (positive && stem == "0")
        {
            return Err(invalid());
        }
        let seq = crate::pystr::int_from_str_decimal_limited(stem).ok_or_else(invalid)?;
        Ok(PyInt(seq.parse().map_err(|_| invalid())?))
    }
    impl<'a> RetainedInput<'_, 'a> {
        fn current(&self) -> Result<()> {
            self.session.check()?;
            if self.generation != self.session.generation.get() {
                return Err(stale());
            }
            if let Some(inventory) = &self.inventory {
                let io = self.session.import_io()?;
                if io.anchor_revision()? != inventory.root {
                    return Err(stale());
                }
                for (name, expected) in &inventory.stamps {
                    self.session
                        .charge(1 + name.len() as u64, 256 + name.len() as u64)?;
                    let observed = match fs::symlink_metadata(self.session.state.path.join(name)) {
                        Ok(metadata) => Some(stamp(&metadata)),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                        Err(_) => return Err(stale()),
                    };
                    if &observed != expected {
                        return Err(stale());
                    }
                }
            }
            // Metadata stamps are a cheap negative check, never freshness
            // authority. A new canonical slot can appear within the same
            // directory timestamp quantum. Re-enumerate and hash the complete
            // bounded raw inventory on the SAME operation budget before any
            // retained DATA is reused.
            if let Some(before) = &self.inventory
                && self.session.collect()?.revision != before.revision
            {
                return Err(stale());
            }
            Ok(())
        }
        pub(crate) fn recheck(&self) -> Result<()> {
            self.current()
        }
        pub(crate) fn commits(&self) -> Result<Vec<Commit>> {
            self.current()?;
            self.observed_commits()
        }
        fn observed_commits(&self) -> Result<Vec<Commit>> {
            self.session.check()?;
            if self.inventory.is_none() {
                return CommitStore::new(self.session.state, &self.session.env).all_commits();
            }
            let size = self.originals.iter().try_fold(0u64, |sum, o| {
                sum.checked_add(o.raw.len() as u64).ok_or_else(limit)
            })?;
            self.session.charge(
                size.checked_mul(2).ok_or_else(limit)?,
                size.checked_mul(64).ok_or_else(limit)?,
            )?;
            Ok(self.originals.iter().map(|o| o.parsed.clone()).collect())
        }
        pub(crate) fn vector(&self) -> Result<BTreeMap<String, PyInt>> {
            self.current()?;
            if self.inventory.is_none() {
                CommitStore::new(self.session.state, &self.session.env).vector()
            } else {
                let size = self.vector.iter().try_fold(0u64, |sum, (author, seq)| {
                    sum.checked_add(author.len() as u64)
                        .and_then(|n| n.checked_add(seq.0.bits()))
                        .and_then(|n| n.checked_add(32))
                        .ok_or_else(limit)
                })?;
                self.session
                    .charge(size, size.checked_mul(8).ok_or_else(limit)?)?;
                Ok(self.vector.as_ref().clone())
            }
        }
        pub(crate) fn replication_after(
            &self,
            peer: &BTreeMap<String, PyInt>,
        ) -> Result<Vec<Commit>> {
            self.current()?;
            if self.inventory.is_none() {
                return Err(invalid());
            }
            for (author, floor) in self.floor.iter() {
                if peer.get(author).cloned().unwrap_or_else(PyInt::zero) < *floor {
                    return Err(Error::state("team_checkpoint_history_required"));
                }
            }
            let size = self.originals.iter().try_fold(0u64, |sum, original| {
                sum.checked_add(original.raw.len() as u64).ok_or_else(limit)
            })?;
            self.session.charge(
                size.checked_mul(2).ok_or_else(limit)?,
                size.checked_mul(64).ok_or_else(limit)?,
            )?;
            Ok(self
                .originals
                .iter()
                .filter(|o| {
                    peer.get(&o.parsed.author)
                        .is_none_or(|known| o.parsed.author_seq > *known)
                        && self
                            .vector
                            .get(&o.parsed.author)
                            .is_some_and(|captured| o.parsed.author_seq <= *captured)
                })
                .map(|o| o.parsed.clone())
                .collect())
        }
        pub(crate) fn read_json(&self, name: &str, default: Value) -> Result<Value> {
            self.current()?;
            self.observed_json(name, default)
        }
        fn observed_json(&self, name: &str, default: Value) -> Result<Value> {
            self.session.check()?;
            if let Some(inventory) = &self.inventory {
                match inventory.files.get(name) {
                    None => Ok(default),
                    Some(file) => self.session.parse(&file.raw),
                }
            } else {
                self.session.state.read_json(name, default)
            }
        }
        pub(crate) fn read_lines(&self, name: &str) -> Result<Vec<String>> {
            self.current()?;
            self.observed_lines(name)
        }
        fn observed_lines(&self, name: &str) -> Result<Vec<String>> {
            self.session.check()?;
            if let Some(inventory) = &self.inventory {
                let Some(file) = inventory.files.get(name) else {
                    return Ok(Vec::new());
                };
                if file.raw.len() as u64 > INVENTORY {
                    return Err(limit());
                }
                self.session.charge(
                    file.raw.len() as u64,
                    (file.raw.len() as u64).checked_mul(4).ok_or_else(limit)?,
                )?;
                let text = std::str::from_utf8(&file.raw).map_err(|_| invalid())?;
                let mut lines = Vec::new();
                for line in text
                    .replace("\r\n", "\n")
                    .replace('\r', "\n")
                    .split_terminator('\n')
                {
                    if lines.len() >= ENTRIES || line.len() as u64 > BULK {
                        return Err(limit());
                    }
                    lines.push(line.to_owned());
                }
                Ok(lines)
            } else {
                self.session.state.read_lines(name, None)
            }
        }
        pub(crate) fn shared_facts(&self) -> Result<Vec<Value>> {
            self.current()?;
            self.observed_shared_facts()
        }
        fn observed_shared_facts(&self) -> Result<Vec<Value>> {
            self.session.check()?;
            if let Some(inventory) = &self.inventory
                && let Some(file) = inventory.files.get(crate::tombstone::PATH)
            {
                self.session.parse(&file.raw)?;
                self.session.charge(
                    file.raw.len() as u64,
                    (file.raw.len() as u64).checked_mul(4).ok_or_else(limit)?,
                )?;
            }
            let values = crate::tombstone::shared_facts(self.session.state, &self.session.env)?;
            self.session.check()?;
            Ok(values)
        }
        // These batches are untrusted DATA for the one fact engine. Their
        // public entry/final checks validate the complete raw revision under
        // the actual held lock. Private observed_* copies only check the SAME
        // session budget/root/generation: there is no callback, filesystem
        // mutation or authority return between those bounded copies. All fact
        // and selection seals still close with a complete raw recheck. Avoid
        // repeating the identical inventory scan inside each copy; no spent
        // work is refunded and no nested operation gains a fresh budget.
        // Ordinary acquisition order stays lazy.
        pub(crate) fn fact_sources(&self) -> Result<(Vec<String>, Vec<Value>)> {
            self.recheck()?;
            let lines = self.observed_lines(&format!("team/{}/facts.jsonl", self.session.env))?;
            let shared = self.observed_shared_facts()?;
            self.current()?;
            Ok((lines, shared))
        }
        pub(crate) fn fact_admissions(&self) -> Result<(Value, Vec<String>)> {
            self.recheck()?;
            let receipts = self.observed_json(
                &format!("team/{}/fact_admissions.json", self.session.env),
                json!({}),
            )?;
            let lines =
                self.observed_lines(&format!("team/{}/fact_admissions.jsonl", self.session.env))?;
            self.current()?;
            Ok((receipts, lines))
        }
        pub(crate) fn shared_fact_seal(&self) -> Result<(Vec<Value>, FactSeal<'a>)> {
            self.current()?;
            let values = self.observed_shared_facts()?;
            let seal = self.fact_seal()?;
            Ok((values, seal))
        }
        pub(crate) fn fact_seal(&self) -> Result<FactSeal<'a>> {
            self.recheck()?;
            let revision = self
                .inventory
                .as_ref()
                .map(|value| hex::encode(value.revision))
                .unwrap_or_default();
            let size = self
                .vector
                .iter()
                .try_fold(0u64, |sum, (author, sequence)| {
                    sum.checked_add(author.len() as u64)
                        .and_then(|value| value.checked_add(sequence.0.bits()))
                        .ok_or_else(limit)
                })?;
            self.session
                .charge(size, size.checked_mul(8).ok_or_else(limit)?)?;
            Ok(FactSeal {
                operation: self.session.operation.clone(),
                generation: self.generation,
                revision,
                vector: self.vector.as_ref().clone(),
            })
        }
        pub(crate) fn target_revision(&self) -> Result<String> {
            self.recheck()?;
            let Some(inventory) = &self.inventory else {
                return Ok(String::new());
            };
            let prefix = format!("team/{}/bootstrap", self.session.env);
            let pins = ["receiver.json", "observed.json", "known-facts.json"]
                .map(|leaf| format!("{prefix}/{leaf}"));
            let volatile = ["sync_state.json", "peers.json", "peer_vectors.json"]
                .map(|leaf| format!("team/{}/{leaf}", self.session.env));
            let mut hash = Sha256::new();
            self.session.charge(176, 176)?;
            inventory
                .root
                .visit_words(|word| hash.update(word.to_be_bytes()));
            for (name, directory) in &inventory.layout {
                if (name == &prefix || name.starts_with(&format!("{prefix}/")))
                    && !pins.contains(name)
                {
                    continue;
                }
                if volatile.contains(name) {
                    continue;
                }
                self.session.charge(name.len() as u64, name.len() as u64)?;
                hash.update((name.len() as u64).to_be_bytes());
                hash.update(name.as_bytes());
                hash.update([u8::from(*directory)]);
                if let Some(image) = inventory.files.get(name) {
                    self.session.charge(image.raw.len() as u64, 0)?;
                    hash.update(Sha256::digest(&image.raw));
                }
            }
            self.session.check()?;
            Ok(hex::encode(hash.finalize()))
        }
        pub(crate) fn cut_revision(&self) -> Result<String> {
            self.recheck()?;
            let Some(inventory) = &self.inventory else {
                return Ok(String::new());
            };
            // Transport hints/status do not enter the exported cut. Every
            // original, snapshot, fact/receipt/ledger, approval, import witness
            // and shared target/mapping is bound by raw path/type/content.
            let volatile = ["sync_state.json", "peers.json", "peer_vectors.json"]
                .map(|leaf| format!("team/{}/{leaf}", self.session.env));
            let mut hash = Sha256::new();
            self.session.charge(176, 176)?;
            inventory
                .root
                .visit_words(|word| hash.update(word.to_be_bytes()));
            for (name, directory) in &inventory.layout {
                if volatile.contains(name) {
                    continue;
                }
                self.session.charge(name.len() as u64, name.len() as u64)?;
                hash.update((name.len() as u64).to_be_bytes());
                hash.update(name.as_bytes());
                hash.update([u8::from(*directory)]);
                if let Some(image) = inventory.files.get(name) {
                    self.session.charge(image.raw.len() as u64, 0)?;
                    hash.update(Sha256::digest(&image.raw));
                }
            }
            if let Some(identity) = &self.session.identity {
                let record = pyjson::dumps(&identity.to_dict(), DumpOptions::compact_sorted())?;
                self.session
                    .charge(record.len() as u64, record.len() as u64)?;
                hash.update(record.as_bytes());
            }
            self.session.check()?;
            Ok(hex::encode(hash.finalize()))
        }
        pub(crate) fn revision(&self) -> Result<String> {
            self.recheck()?;
            if let Some(inventory) = &self.inventory {
                let paths = self.originals.iter().try_fold(0u64, |n, o| {
                    n.checked_add(o.path.len() as u64).ok_or_else(limit)
                })?;
                self.session.charge(inventory.entries as u64, paths)?;
                for original in self.originals.iter() {
                    if inventory
                        .files
                        .get(&original.path)
                        .is_none_or(|f| f.raw != original.raw)
                    {
                        return Err(stale());
                    }
                }
                Ok(hex::encode(inventory.revision))
            } else {
                Ok(String::new())
            }
        }
        pub(crate) fn fold_with_snapshot(
            &self,
            commits: Vec<Commit>,
            facts: &fold::Facts,
            audit: Option<&Audit>,
        ) -> Result<fold::FoldResult> {
            self.reserve_fold(&commits, Some(facts), 1)?;
            if !self.session.is_scoped() {
                return fold::fold_with_snapshot(
                    &self.session.env,
                    commits,
                    self.session.state,
                    Some(facts),
                    audit,
                );
            }
            let result = fold::fold_with_snapshot(
                &self.session.env,
                commits.clone(),
                self.session.state,
                Some(facts),
                audit,
            )?;
            self.verify_folded_authority(&commits, facts, &result)?;
            Ok(result)
        }
        pub(crate) fn verify_folded_authority(
            &self,
            commits: &[Commit],
            facts: &fold::Facts,
            result: &fold::FoldResult,
        ) -> Result<()> {
            if !self.session.is_scoped() {
                return Ok(());
            }
            verify_authority_projection(self.session, self, commits, facts, result)
        }
        pub(crate) fn pending_deferred_count(&self) -> Result<usize> {
            self.recheck()?;
            self.reserve_deferred_walk()?;
            let count = CommitStore::new(self.session.state, &self.session.env)
                .deferred_commits()?
                .len();
            self.session.check()?;
            Ok(count)
        }
        pub(super) fn reserve_deferred_walk(&self) -> Result<()> {
            self.current()?;
            let Some(inventory) = &self.inventory else {
                return Ok(());
            };
            let entries = inventory.entries as u64;
            let width = inventory
                .files
                .keys()
                .map(|path| path.len() as u64)
                .max()
                .unwrap_or(1);
            let work = entries
                .checked_mul(entries)
                .and_then(|n| n.checked_mul(width))
                .and_then(|n| n.checked_add(inventory.bytes.checked_mul(16)?))
                .ok_or_else(limit)?;
            self.session
                .charge(work, inventory.bytes.checked_mul(16).ok_or_else(limit)?)
        }
        pub(crate) fn reserve_fold(
            &self,
            commits: &[Commit],
            facts: Option<&fold::Facts>,
            snapshots: u64,
        ) -> Result<()> {
            self.current()?;
            if self.inventory.is_none() {
                return Ok(());
            }
            let c = commits.len() as u64;
            let o = commits.iter().try_fold(0u64, |a, c| {
                a.checked_add(c.ops.len() as u64).ok_or_else(limit)
            })?;
            let t = facts.map_or(0, |f| {
                f.tombstone_facts.len()
                    + f.removal_facts.len()
                    + f.revoked_versions.len()
                    + f.disabled_connections.len()
                    + f.deleted_secrets.len()
                    + f.removed_members.len()
            }) as u64;
            let f = facts.map_or(0, |f| f.removal_facts.len()) as u64;
            let inventory = self.inventory.as_ref().unwrap();
            let snapshots = if snapshots == 0 {
                0
            } else {
                inventory
                    .files
                    .keys()
                    .filter(|path| {
                        path.starts_with(&format!("team/{}/snapshots/", self.session.env))
                    })
                    .count() as u64
            };
            let mut d = 0u64;
            if snapshots > 0 {
                for (path, file) in &inventory.files {
                    if path.starts_with(&format!("team/{}/snapshots/", self.session.env)) {
                        let value = self.session.parse(&file.raw)?;
                        for root in [&value["document"], &value["version_order"]] {
                            let mut pending = vec![root];
                            while let Some(value) = pending.pop() {
                                d = d.checked_add(1).filter(|n| *n <= NODES).ok_or_else(limit)?;
                                match value {
                                    Value::Object(m) => pending.extend(m.values()),
                                    Value::Array(a) => pending.extend(a),
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
            // D counts input document/version-order nodes; a pure fold has no
            // document seed. Every conservative prefix reservation is charged.
            let prefix = format!("team/{}/", self.session.env);
            let fold_bytes = inventory
                .files
                .iter()
                .try_fold(0u64, |sum, (path, image)| {
                    if path == crate::tombstone::PATH
                        || path == &format!("{prefix}facts.jsonl")
                        || ["commits/", "snapshots/", "snapshot_records/"]
                            .iter()
                            .any(|directory| path.starts_with(&format!("{prefix}{directory}")))
                    {
                        sum.checked_add(image.raw.len() as u64).ok_or_else(limit)
                    } else {
                        Ok(sum)
                    }
                })?;
            self.session
                .reserve_counts([c, o, t, f, d, snapshots, fold_bytes])
        }
        fn authenticate_selection(&self) -> Result<()> {
            self.current()?;
            let local = self.session.identity.as_ref().ok_or_else(invalid)?;
            let genesis = self
                .originals
                .iter()
                .find(|o| {
                    o.parsed.author_seq == 1
                        && o.parsed
                            .ops
                            .first()
                            .is_some_and(|op| op["op"] == "env.init")
                })
                .ok_or_else(invalid)?;
            let owner = DeviceRecord::from_dict(&genesis.parsed.ops[0]["owner_device"])?;
            if owner.fingerprint() != env_owner_fingerprint(&self.session.env)?
                || genesis.parsed.author != owner.fingerprint()
                || !verify_commit(&genesis.parsed, &owner)
            {
                return Err(invalid());
            }
            match &self.session.selection {
                Selection::Owner => {
                    if &owner != local {
                        return Err(invalid());
                    }
                    let inventory = self.inventory.as_ref().ok_or_else(invalid)?;
                    let prefix = format!("team/{}/bootstrap/invites/", self.session.env);
                    let mut found = false;
                    for (path, file) in &inventory.files {
                        if path.starts_with(&prefix) {
                            let witness = self.session.parse(&file.raw)?;
                            if witness["owner_record"] != owner.to_dict()
                                || witness["genesis_hash"] != genesis.parsed.hash()?
                                || !witness["initial_revision"].is_string()
                            {
                                return Err(invalid());
                            }
                            found = true;
                        }
                    }
                    if !found {
                        return Err(invalid());
                    }
                    let prefix = format!("team/{}/bootstrap/authorizations/", self.session.env);
                    let mut admissions = 0;
                    for (path, file) in &inventory.files {
                        if path.starts_with(&prefix) {
                            admissions += 1;
                            if admissions > 1 {
                                return Err(invalid());
                            }
                            let auth = self.session.parse(&file.raw)?;
                            let admission = Commit::from_dict(&auth["admission"])?;
                            let peer = DeviceRecord::from_dict(&auth["device_record"])?;
                            let stored = self.originals.iter().any(|o| o.parsed == admission);
                            let prepared = auth["state"] == "admission_intent"
                                && admission.author_seq
                                    == self
                                        .vector
                                        .get(&owner.fingerprint())
                                        .cloned()
                                        .unwrap_or_else(PyInt::zero)
                                        + 1;
                            if !verify_commit(&admission, &owner)
                                || admission.author != owner.fingerprint()
                                || admission.ops.len() != 1
                                || admission.ops[0]["op"] != "member.add"
                                || admission.ops[0]["role"] != "admin"
                                || admission.ops[0]["device"] != peer.to_dict()
                                || (!stored && !prepared)
                            {
                                return Err(invalid());
                            }
                            let request_path =
                                format!("team/{}/bootstrap/requests.json", self.session.env);
                            let requests =
                                inventory.files.get(&request_path).ok_or_else(invalid)?;
                            let requests = self.session.parse(&requests.raw)?;
                            let request_id = auth["request_id"].as_str().ok_or_else(invalid)?;
                            let request = &requests[request_id];
                            for field in [
                                "env_id",
                                "invite_id",
                                "device_record",
                                "record_binding",
                                "authorization_id",
                                "expires_at_ms",
                            ] {
                                if auth[field] != request[field] {
                                    return Err(invalid());
                                }
                            }
                            if request["env_id"] != self.session.env
                                || request["device_record"] != peer.to_dict()
                                || auth["record_binding"]
                                    != super::super::bootstrap::digest(&peer.to_dict())?
                            {
                                return Err(invalid());
                            }
                            if !auth["last_manifest"].is_null()
                                || !auth["last_manifest_hash"].is_null()
                            {
                                let manifest = &auth["last_manifest"];
                                let mut unsigned = manifest.clone();
                                let signature = unsigned
                                    .as_object_mut()
                                    .ok_or_else(invalid)?
                                    .remove("sig")
                                    .ok_or_else(invalid)?;
                                let signature = pybase64::b64decode_strict(
                                    signature.as_str().ok_or_else(invalid)?,
                                )
                                .map_err(|_| invalid())?;
                                self.session.charge(4096, file.raw.len() as u64)?;
                                self.session.check()?;
                                if manifest["domain"] != "zeropw-team-bootstrap-v1"
                                    || manifest["env_id"] != self.session.env
                                    || manifest["signer"] != owner.fingerprint()
                                    || manifest["recipient"] != peer.fingerprint()
                                    || manifest["recipient_role"] != "admin"
                                    || manifest["invite_id"] != auth["invite_id"]
                                    || manifest["recipient_authorization_id"]
                                        != auth["authorization_id"]
                                    || manifest["recipient_admission_commit_hash"]
                                        != admission.hash()?
                                    || super::super::bootstrap::digest(manifest)?
                                        != auth["last_manifest_hash"]
                                    || !ed25519::verify(
                                        &owner.sign_pub,
                                        &super::super::bootstrap::bytes(&unsigned)?,
                                        &signature,
                                    )
                                {
                                    return Err(invalid());
                                }
                                self.session.check()?;
                            }
                        }
                    }
                }
                Selection::Recipient => {
                    // B's authentic committed index+journal and immutable
                    // receipt/manifest/payload are independent of attempt flags.
                    let index = crate::import_barrier::index_in(&self.session.import_io()?)?;
                    if index[&self.session.env]["state"] != "committed" {
                        return Err(Error::state(
                            if index[&self.session.env]["reason"]
                                == "team_checkpoint_history_required"
                            {
                                "team_checkpoint_history_required"
                            } else {
                                "team_bootstrap_recovery_required"
                            },
                        ));
                    }
                    let journal = self.observed_json(
                        &super::super::bootstrap::path(&self.session.env, "journal.json")?,
                        Value::Null,
                    )?;
                    let receipt = self.observed_json(
                        &super::super::bootstrap::path(&self.session.env, "receipt.json")?,
                        Value::Null,
                    )?;
                    for (value, domain, signer) in [
                        (&journal, "zeropw-personal-import-journal-v1", local),
                        (&receipt, "zeropw-team-bootstrap-receipt-v1", local),
                        (&journal["ready"], "zeropw-team-bootstrap-ready-v1", &owner),
                    ] {
                        let mut unsigned = value.clone();
                        let signature = unsigned
                            .as_object_mut()
                            .ok_or_else(invalid)?
                            .remove("sig")
                            .ok_or_else(invalid)?;
                        let signature =
                            pybase64::b64decode_strict(signature.as_str().ok_or_else(invalid)?)
                                .map_err(|_| invalid())?;
                        self.session.charge(4096, 0)?;
                        if value["domain"] != domain
                            || value["env_id"] != self.session.env
                            || !ed25519::verify(
                                &signer.sign_pub,
                                &super::super::bootstrap::bytes(&unsigned)?,
                                &signature,
                            )
                        {
                            return Err(invalid());
                        }
                    }
                    if journal["state"] != "COMMITTED"
                        || journal["layout"] != "compact_committed_v1"
                        || journal["signer_record"] != owner.to_dict()
                        || journal["recipient_record"] != local.to_dict()
                        || journal["genesis_hash"] != genesis.parsed.hash()?
                        || journal["epoch"] != index[&self.session.env]["epoch"]
                        || journal["receipt"] != receipt
                        || journal["manifest_hash"] != index[&self.session.env]["manifest_hash"]
                        || journal["visibility"]["epoch"] != journal["epoch"]
                        || receipt["epoch"] != journal["epoch"]
                        || super::super::bootstrap::digest(&receipt)?
                            != index[&self.session.env]["receipt_sha256"]
                        || receipt["ready_sha256"]
                            != super::super::bootstrap::digest(&journal["ready"])?
                        || journal["ready"]["manifest_hash"] != journal["manifest_hash"]
                        || journal["ready"]["recipient"] != local.fingerprint()
                    {
                        return Err(invalid());
                    }
                    let manifest = self.observed_json(
                        &format!(
                            "team/{}/bootstrap/provenance/manifest.json",
                            self.session.env
                        ),
                        Value::Null,
                    )?;
                    let mut unsigned = manifest.clone();
                    let sig = unsigned
                        .as_object_mut()
                        .ok_or_else(invalid)?
                        .remove("sig")
                        .ok_or_else(invalid)?;
                    let sig = pybase64::b64decode_strict(sig.as_str().ok_or_else(invalid)?)
                        .map_err(|_| invalid())?;
                    if manifest["env_id"] != self.session.env
                        || manifest["recipient"] != local.fingerprint()
                        || manifest["signer"] != owner.fingerprint()
                        || !ed25519::verify(
                            &owner.sign_pub,
                            &super::super::bootstrap::bytes(&unsigned)?,
                            &sig,
                        )
                    {
                        return Err(invalid());
                    }
                    let hash = manifest["recipient_admission_commit_hash"]
                        .as_str()
                        .ok_or_else(invalid)?;
                    if !self.originals.iter().any(|o| {
                        o.parsed.hash().ok().as_deref() == Some(hash)
                            && o.parsed.ops.iter().any(|op| {
                                op["op"] == "member.add"
                                    && op["device"] == local.to_dict()
                                    && op["role"] == "admin"
                            })
                    }) {
                        return Err(invalid());
                    }
                }
                Selection::Ordinary | Selection::Probe(_) => {}
            }
            self.recheck()?;
            self.session.check()
        }
    }

    fn raw_witness(state: &StateDir, env: &str) -> Result<(bool, u64, u64)> {
        raw_witness_with_budget(state, env, None)
    }
    fn raw_witness_with_budget(
        state: &StateDir,
        env: &str,
        parent: Option<&HistorySession<'_>>,
    ) -> Result<(bool, u64, u64)> {
        if let Some(parent) = parent {
            if !std::ptr::eq(parent.state(), state) || parent.env() != env {
                return Err(stale());
            }
            parent.check()?;
            parent.charge(4, 0)?;
        }
        if !valid_env_id(env) {
            return Ok((false, 0, 0));
        }
        let path = state.path.join(format!("team/{env}/bootstrap"));
        match fs::symlink_metadata(path) {
            Ok(_) => return Ok((true, 1, 0)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(stale()),
        }
        let name = crate::import_barrier::INDEX;
        let metadata = match fs::symlink_metadata(state.path.join(name)) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((false, 1, 0)),
            Err(_) => return Err(stale()),
        };
        if metadata.len() > 1_048_576 {
            return Err(limit());
        }
        if let Some(parent) = parent {
            // Read/copy and syntax work are charged before allocation, then
            // the exact node/materialization reservation precedes the bridge.
            parent.charge(
                metadata.len().checked_mul(4).ok_or_else(limit)?,
                metadata.len().checked_mul(4).ok_or_else(limit)?,
            )?;
            parent.check()?;
        }
        crate::import_barrier::private_relative(state, name)?;
        let file = anchored_file(state, name)?;
        if stamp(&file.metadata().map_err(|_| invalid())?) != stamp(&metadata) {
            return Err(stale());
        }
        let mut raw = Vec::new();
        (&file)
            .take(metadata.len().checked_add(1).ok_or_else(limit)?)
            .read_to_end(&mut raw)
            .map_err(|_| invalid())?;
        if raw.len() as u64 != metadata.len()
            || stamp(&file.metadata().map_err(|_| invalid())?) != stamp(&metadata)
            || stamp(&fs::symlink_metadata(state.path.join(name)).map_err(|_| invalid())?)
                != stamp(&metadata)
        {
            return Err(stale());
        }
        // Unlocked, bounded DATA routing only. It establishes no authority.
        // Its conservative resources are carried into the selected operation
        // before any locked acquisition; ordinary append takes no new lock.
        let mut depth = 0u64;
        let mut quoted = false;
        let mut escaped = false;
        let mut nodes = 0u64;
        for byte in &raw {
            if quoted {
                if escaped {
                    escaped = false;
                } else if *byte == b'\\' {
                    escaped = true;
                } else if *byte == b'"' {
                    quoted = false;
                }
                continue;
            }
            match *byte {
                b'"' => {
                    quoted = true;
                    nodes += 1;
                }
                b'{' | b'[' => {
                    depth = depth
                        .checked_add(1)
                        .filter(|n| *n <= 64)
                        .ok_or_else(limit)?;
                    nodes += 1;
                }
                b'}' | b']' => depth = depth.checked_sub(1).ok_or_else(invalid)?,
                b',' | b':' => nodes = nodes.checked_add(1).ok_or_else(limit)?,
                _ => {}
            }
            if nodes > NODES {
                return Err(limit());
            }
        }
        let cost = (raw.len() as u64)
            .checked_mul(128)
            .and_then(|n| n.checked_add(nodes.checked_mul(64)?))
            .ok_or_else(limit)?;
        if cost > BYTES {
            return Err(limit());
        }
        if let Some(parent) = parent {
            parent.charge(raw.len() as u64 + nodes, cost)?;
            parent.check()?;
        }
        let value = checkpoint::retained_original(&raw).map_err(|_| invalid())?;
        if let Some(parent) = parent {
            parent.check()?;
        }
        if !value.is_object() {
            return Err(invalid());
        }
        Ok((value.get(env).is_some(), raw.len() as u64 + nodes, cost))
    }
    fn normalized_absolute(path: &std::path::Path) -> Result<std::path::PathBuf> {
        let absolute = std::path::absolute(path).map_err(|_| invalid())?;
        let mut normalized = std::path::PathBuf::new();
        for part in absolute.components() {
            match part {
                std::path::Component::ParentDir => {
                    normalized.pop();
                }
                std::path::Component::CurDir => {}
                other => normalized.push(other),
            }
        }
        Ok(normalized)
    }
    pub(super) fn selected_store<'a>(
        store: &CommitStore<'a>,
    ) -> Result<Option<HistorySession<'a>>> {
        let (logical, mut work, mut bytes) = raw_witness(store.state, &store.env_id)?;
        let target = store.state.path.join(&store.root);
        let target = fs::canonicalize(&target).unwrap_or(normalized_absolute(&target)?);
        let base =
            fs::canonicalize(&store.state.path).unwrap_or(normalized_absolute(&store.state.path)?);
        let mut physical = false;
        if let Ok(relative) = target.strip_prefix(&base) {
            let parts = relative.components().collect::<Vec<_>>();
            if parts.first().is_some_and(|part| part.as_os_str() == "team")
                && let Some(env) = parts.get(1).and_then(|part| part.as_os_str().to_str())
            {
                let (witness, w, b) = raw_witness(store.state, env)?;
                work = work.checked_add(w).ok_or_else(limit)?;
                bytes = bytes.checked_add(b).ok_or_else(limit)?;
                physical = witness;
                if witness
                    && (env != store.env_id || store.root != env_root(env) || parts.len() != 2)
                {
                    return Err(stale());
                }
            }
        } else if !matches!(fs::symlink_metadata(target.join("bootstrap")),Err(error) if error.kind()==std::io::ErrorKind::NotFound)
        {
            return Err(stale());
        }
        if !logical && !physical {
            return Ok(None);
        }
        if store.root != env_root(&store.env_id) {
            return Err(stale());
        }
        let history = HistorySession::open_runtime_routed(store.state, &store.env_id, work, bytes)?;
        if !history.is_scoped() {
            return Err(stale());
        }
        Ok(Some(history))
    }

    pub(super) enum AppendFailure {
        Invalid(Error),
        Local(Error),
    }
    impl AppendFailure {
        pub(super) fn into_error(self) -> Error {
            match self {
                Self::Invalid(error) | Self::Local(error) => error,
            }
        }
    }
    pub(super) struct PreparedAppend<'s, 'a> {
        history: &'s HistorySession<'a>,
        store: &'s CommitStore<'a>,
        _lock: StateLock<'a>,
        candidate: Commit,
        encoded: Vec<u8>,
        hash: String,
        before: Rc<Inventory>,
        metadata: BTreeMap<String, Vec<u64>>,
        global_names: BTreeSet<String>,
        denial: Option<(String, Vec<u8>)>,
        existing_denial: Option<String>,
    }
    fn input_error(reason: &'static str) -> AppendFailure {
        AppendFailure::Invalid(Error::invalid_input(reason))
    }
    impl<'s, 'a> PreparedAppend<'s, 'a> {
        pub(super) fn prepare(
            store: &'s CommitStore<'a>,
            candidate: &Commit,
            observed_now: i64,
            history: &'s HistorySession<'a>,
            settled: Option<&super::super::sync::SettledFacts<'a>>,
        ) -> std::result::Result<Self, AppendFailure> {
            let local = AppendFailure::Local;
            history.check().map_err(local)?;
            if !std::ptr::eq(store.state, history.state)
                || store.env_id != history.env
                || store.root != env_root(&history.env)
            {
                return Err(local(stale()));
            }
            match history.selection {
                Selection::Owner | Selection::Recipient => {}
                Selection::Probe(ProbePurpose::Invite) => {
                    return Err(local(Error::state(
                        "team_bootstrap_semantic_scope_unsupported",
                    )));
                }
                Selection::Probe(ProbePurpose::Recipient) => {
                    return Err(local(Error::state("team_bootstrap_recovery_required")));
                }
                Selection::Ordinary => return Err(local(invalid())),
            }
            let lock = history.state.lock().map_err(local)?;
            history.preflight_candidate(candidate).map_err(local)?;
            if candidate.format != COMMIT_FORMAT {
                return Err(input_error("team_format_unknown"));
            }
            if candidate.env_id != store.env_id {
                return Err(input_error("team_env_id_mismatch"));
            }
            validate_ops(&candidate.ops).map_err(AppendFailure::Invalid)?;
            Hlc::parse(&candidate.hlc).map_err(AppendFailure::Invalid)?;
            let original_input = history.acquire().map_err(local)?;
            let original_commits = original_input.commits().map_err(local)?;
            let registry = device_registry(&original_commits);
            for op in &candidate.ops {
                let announced = match op["op"].as_str() {
                    Some("env.init") => Some(&op["owner_device"]),
                    Some("member.add") => Some(&op["device"]),
                    _ => None,
                };
                if let Some(value) = announced {
                    let record = DeviceRecord::from_dict(value).map_err(AppendFailure::Invalid)?;
                    history.charge(4096, 256).map_err(local)?;
                    if !record.verify_uncached()
                        || registry
                            .get(&record.fingerprint())
                            .is_some_and(|existing| existing != &record)
                    {
                        return Err(local(Error::state(
                            "team_bootstrap_semantic_scope_unsupported",
                        )));
                    }
                }
            }
            history.charge(4096, 0).map_err(local)?;
            if !registry
                .get(&candidate.author)
                .is_some_and(|record| verify_commit(candidate, record))
            {
                return Err(input_error("team_signature_invalid"));
            }
            let last = store.last_seq(&candidate.author).map_err(local)?;
            if candidate.author_seq <= last {
                return Err(input_error("team_seq_duplicate"));
            }
            if candidate.author_seq > &last + 1 {
                return Err(input_error("team_seq_gap"));
            }
            if store
                .hlc_not_above_previous(candidate, Some(&original_commits))
                .map_err(local)?
            {
                return Err(input_error("team_hlc_not_monotone"));
            }
            let (wall, _) = Hlc::parse(&candidate.hlc).map_err(AppendFailure::Invalid)?;
            if wall > PyInt::from(observed_now.min(now_ms())) + MAX_CLOCK_SKEW_MS {
                return Err(local(Error::state("team_bootstrap_state_invalid")));
            }
            let verified;
            let settled = match settled {
                Some(settled) => settled,
                None => {
                    verified = super::super::sync::load_facts_core(
                        history,
                        super::super::sync::FactServices::VerifySettled,
                    )
                    .map_err(local)?;
                    &verified
                }
            };
            let facts = settled.checked(history).map_err(local)?;
            let facts_digest = settled.digest(history).map_err(local)?;
            let mut input = history.acquire().map_err(local)?;
            let commits = input.commits().map_err(local)?;
            input
                .reserve_fold(&commits, Some(facts), 1)
                .map_err(local)?;
            let before_fold = fold::fold_with_snapshot(
                &history.env,
                commits.clone(),
                history.state,
                Some(facts),
                None,
            )
            .map_err(local)?;
            verify_authority_projection(history, &input, &commits, facts, &before_fold)
                .map_err(local)?;
            history.check().map_err(local)?;
            history
                .charge(
                    commits.len() as u64,
                    input
                        .inventory
                        .as_ref()
                        .ok_or_else(|| local(invalid()))?
                        .bytes,
                )
                .map_err(local)?;
            let mut after_commits = commits;
            after_commits.push(candidate.clone());
            input
                .reserve_fold(&after_commits, Some(facts), 1)
                .map_err(local)?;
            let after_fold = fold::fold_with_snapshot(
                &history.env,
                after_commits.clone(),
                history.state,
                Some(facts),
                None,
            )
            .map_err(local)?;
            verify_authority_projection(history, &input, &after_commits, facts, &after_fold)
                .map_err(local)?;
            history.check().map_err(local)?;
            let value = candidate.to_dict();
            let encoded = history.encode_image(&value).map_err(local)?;
            history.screen(&encoded, BULK).map_err(local)?;
            if history.parse(&encoded).map_err(local)? != value {
                return Err(local(invalid()));
            }
            let hash = candidate.hash().map_err(local)?;
            let revision = input.revision().map_err(local)?;
            let mut denial = None;
            let mut existing_denial = None;
            if matches!(history.selection, Selection::Recipient) {
                let recipient = history.local_record().map_err(local)?;
                let fingerprint = recipient.fingerprint();
                for result in [&before_fold, &after_fold] {
                    if result.document["members"][&fingerprint]["device"] != recipient.to_dict() {
                        return Err(local(invalid()));
                    }
                }
                let before_removed = before_fold.document["members"][&fingerprint]["status"]
                    == "removed"
                    && before_fold.document["owner"] != fingerprint;
                let after_removed = after_fold.document["members"][&fingerprint]["status"]
                    == "removed"
                    && after_fold.document["owner"] != fingerprint;
                let name = super::super::bootstrap::path(
                    &history.env,
                    crate::import_barrier::LOCAL_REMOVAL_DENIAL,
                )
                .map_err(local)?;
                let imports = crate::import_barrier::index(history.state).map_err(local)?;
                let epoch = &imports[&history.env];
                let receipt = input
                    .read_json(
                        &super::super::bootstrap::path(&history.env, "receipt.json")
                            .map_err(local)?,
                        Value::Null,
                    )
                    .map_err(local)?;
                if let Some(image) = input
                    .inventory
                    .as_ref()
                    .and_then(|inventory| inventory.files.get(&name))
                {
                    let record = history.parse(&image.raw).map_err(local)?;
                    validate_denial(history, &record, epoch, &receipt, &registry).map_err(local)?;
                    existing_denial = Some(name);
                } else if before_removed || after_removed {
                    let mut record = json!({"v":1,"kind":"local-removal-denial","env_id":history.env,"epoch":epoch["epoch"],"recipient_record":recipient.to_dict(),"manifest_hash":epoch["manifest_hash"],"receipt_sha256":epoch["receipt_sha256"],"payload_sha256":receipt["payload_sha256"],"cause":if before_removed{"committed_history"}else{"candidate"},"basis_revision":revision,"facts_digest":facts_digest,"result_digest":super::super::bootstrap::digest(if before_removed{&before_fold.document}else{&after_fold.document}).map_err(local)?});
                    if !before_removed {
                        record["commit"] = value.clone();
                        record["commit_hash"] = json!(hash);
                    }
                    history.preflight_value(&record).map_err(local)?;
                    let bytes = history.encode_image(&record).map_err(local)?;
                    validate_denial(
                        history,
                        &history.parse(&bytes).map_err(local)?,
                        epoch,
                        &receipt,
                        &registry,
                    )
                    .map_err(local)?;
                    history
                        .reserve_writer(&name, bytes.len() as u64)
                        .map_err(local)?;
                    denial = Some((name, bytes));
                }
            }
            let path = format!(
                "{}/commits/{}/{}.json",
                store.root, candidate.author, candidate.author_seq
            );
            history
                .reserve_writer(&path, encoded.len() as u64)
                .map_err(local)?;
            let before = input.inventory.take().ok_or_else(|| local(invalid()))?;
            let mut metadata = BTreeMap::new();
            for (name, _) in &before.layout {
                history.charge(1, 128).map_err(local)?;
                let value = fs::symlink_metadata(history.state.path.join(name))
                    .map_err(|_| local(stale()))?;
                metadata.insert(name.clone(), stamp(&value));
            }
            let global_names = global_names(history).map_err(local)?;
            for name in &global_names {
                let path = format!("team/{name}");
                history.charge(1, 128).map_err(local)?;
                metadata.insert(
                    path.clone(),
                    stamp(
                        &fs::symlink_metadata(history.state.path.join(&path))
                            .map_err(|_| local(stale()))?,
                    ),
                );
            }
            history.check().map_err(local)?;
            if history.collect().map_err(local)?.revision != before.revision {
                return Err(local(stale()));
            }
            Ok(Self {
                history,
                store,
                _lock: lock,
                candidate: candidate.clone(),
                encoded,
                hash,
                before,
                metadata,
                global_names,
                denial,
                existing_denial,
            })
        }
        pub(super) fn publish(self) -> std::result::Result<(), AppendFailure> {
            let local = AppendFailure::Local;
            let history = self.history;
            history.check().map_err(local)?;
            if history.collect().map_err(local)?.revision != self.before.revision {
                return Err(local(stale()));
            }
            if let Some(name) = &self.existing_denial {
                crate::import_barrier::confirm_denial_durable(history, name).map_err(local)?;
                if history.collect().map_err(local)?.revision != self.before.revision {
                    return Err(local(stale()));
                }
            }
            if let Some((name, bytes)) = &self.denial {
                crate::import_barrier::write_with_history(history, name, bytes).map_err(local)?;
                let after = history.collect().map_err(local)?;
                if !self
                    .only_expected_denial(&after, name, bytes)
                    .map_err(local)?
                {
                    return Err(local(stale()));
                }
            }
            history.check().map_err(local)?;
            let fresh = history.acquire().map_err(local)?;
            let commits = fresh.commits().map_err(local)?;
            if self.candidate.hash().map_err(local)? != self.hash
                || self.store.last_seq(&self.candidate.author).map_err(local)? + 1
                    != self.candidate.author_seq
                || self
                    .store
                    .hlc_not_above_previous(&self.candidate, Some(&commits))
                    .map_err(local)?
            {
                return Err(local(stale()));
            }
            let registry = device_registry(&commits);
            history.charge(4096, 0).map_err(local)?;
            if !registry
                .get(&self.candidate.author)
                .is_some_and(|record| verify_commit(&self.candidate, record))
            {
                return Err(local(stale()));
            }
            fresh.recheck().map_err(local)?;
            history.check().map_err(local)?;
            let name = format!(
                "{}/commits/{}/{}.json",
                self.store.root, self.candidate.author, self.candidate.author_seq
            );
            crate::import_barrier::write_with_history(history, &name, &self.encoded)
                .map_err(|_| local(Error::state("team_local_removal_outcome_uncertain")))?;
            history
                .invalidate()
                .map_err(|_| local(Error::state("team_local_removal_outcome_uncertain")))?;
            let stored = self
                .store
                .get(&self.candidate.author, self.candidate.author_seq.clone())
                .map_err(|_| local(Error::state("team_local_removal_outcome_uncertain")))?;
            if stored.as_ref() != Some(&self.candidate) {
                return Err(local(Error::state("team_local_removal_outcome_uncertain")));
            }
            history
                .check()
                .map_err(|_| local(Error::state("team_local_removal_outcome_uncertain")))?;
            Ok(())
        }
        fn only_expected_denial(
            &self,
            after: &Inventory,
            name: &str,
            bytes: &[u8],
        ) -> Result<bool> {
            let history = self.history;
            history.check()?;
            if after.files.len() != self.before.files.len() + 1
                || after.files.get(name).is_none_or(|image| image.raw != bytes)
                || global_names(history)? != self.global_names
            {
                return Ok(false);
            }
            for (path, image) in &self.before.files {
                if after
                    .files
                    .get(path)
                    .is_none_or(|current| current.raw != image.raw)
                {
                    return Ok(false);
                }
            }
            let mut expected = self.before.layout.clone();
            expected.insert((name.into(), false));
            if expected != after.layout {
                return Ok(false);
            }
            let parent = std::path::Path::new(name).parent().ok_or_else(invalid)?;
            for (path, before) in &self.metadata {
                let now = stamp(
                    &fs::symlink_metadata(history.state.path.join(path)).map_err(|_| stale())?,
                );
                if std::path::Path::new(path) == parent {
                    if before[..6] != now[..6] {
                        return Ok(false);
                    }
                } else if before != &now {
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }
    pub(super) fn append_with_input<'a>(
        store: &CommitStore<'a>,
        candidate: &Commit,
        observed_now: i64,
        history: &HistorySession<'a>,
        settled: Option<&super::super::sync::SettledFacts<'a>>,
    ) -> std::result::Result<(), AppendFailure> {
        PreparedAppend::prepare(store, candidate, observed_now, history, settled)?.publish()
    }
    fn global_names(history: &HistorySession<'_>) -> Result<BTreeSet<String>> {
        let mut names = BTreeSet::new();
        for entry in fs::read_dir(history.state.path.join("team")).map_err(|_| invalid())? {
            history.charge(1, 256)?;
            if names.len() >= ENTRIES {
                return Err(limit());
            }
            names.insert(
                entry
                    .map_err(|_| invalid())?
                    .file_name()
                    .into_string()
                    .map_err(|_| invalid())?,
            );
        }
        Ok(names)
    }
    fn verify_authority_projection(
        history: &HistorySession<'_>,
        input: &RetainedInput<'_, '_>,
        commits: &[Commit],
        facts: &fold::Facts,
        folded: &fold::FoldResult,
    ) -> Result<()> {
        // Snapshot DATA is not membership authority. Every authority original
        // is retained; compare only the authority fields, with the unchanged
        // full fact/removal semantics. Missing DATA is still attested, not
        // promoted into a complete-history proof.
        input.reserve_fold(commits, Some(facts), 0)?;
        let retained = fold::fold(
            &history.env,
            commits.to_vec(),
            Some(facts),
            None,
            None,
            None,
        )?;
        for field in ["owner", "members", "dek"] {
            if retained.document[field] != folded.document[field] {
                return Err(Error::state("team_bootstrap_authority_unproven"));
            }
        }
        history.check()
    }
    fn validate_denial(
        history: &HistorySession<'_>,
        record: &Value,
        epoch: &Value,
        receipt: &Value,
        registry: &std::collections::HashMap<String, DeviceRecord>,
    ) -> Result<()> {
        let object = record.as_object().ok_or_else(invalid)?;
        let base = [
            "v",
            "kind",
            "env_id",
            "epoch",
            "recipient_record",
            "manifest_hash",
            "receipt_sha256",
            "payload_sha256",
            "cause",
            "basis_revision",
            "facts_digest",
            "result_digest",
        ];
        let candidate = record["cause"] == "candidate";
        if object.len() != base.len() + if candidate { 2 } else { 0 }
            || base.iter().any(|key| !object.contains_key(*key))
            || (!candidate && record["cause"] != "committed_history")
        {
            return Err(invalid());
        }
        if record["v"] != 1
            || record["kind"] != "local-removal-denial"
            || record["env_id"] != history.env
            || record["epoch"] != epoch["epoch"]
            || record["recipient_record"] != history.local_record()?.to_dict()
            || record["manifest_hash"] != epoch["manifest_hash"]
            || record["receipt_sha256"] != epoch["receipt_sha256"]
            || record["payload_sha256"] != receipt["payload_sha256"]
        {
            return Err(invalid());
        }
        for key in [
            "basis_revision",
            "facts_digest",
            "result_digest",
            "manifest_hash",
            "receipt_sha256",
            "payload_sha256",
        ] {
            if !record[key].as_str().is_some_and(|text| {
                text.len() == 64
                    && text
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            }) {
                return Err(invalid());
            }
        }
        if candidate {
            if !object.contains_key("commit") || !object.contains_key("commit_hash") {
                return Err(invalid());
            }
            let commit = Commit::from_dict(&record["commit"])?;
            history.charge(4096, 0)?;
            if commit.to_dict() != record["commit"]
                || commit.env_id != history.env
                || commit.hash()? != record["commit_hash"]
                || !registry
                    .get(&commit.author)
                    .is_some_and(|author| verify_commit(&commit, author))
            {
                return Err(invalid());
            }
        }
        history.check()
    }

    #[cfg(test)]
    mod opus_epoch_budget_tests {
        use super::*;
        #[test]
        fn ordinary_share_and_authoring_keep_unbound_context_and_finite_parent() {
            let root = tempfile::tempdir().unwrap();
            let ctx = crate::context::Context::initialize(
                root.path().join("state"),
                "synthetic-admin",
                "synthetic-recovery",
                crate::context::Config::default(),
                crate::clock::system(),
            )
            .unwrap();
            ctx.projects.create("demo", &["dev"]).unwrap();
            assert!(ctx.state.import_identity().is_none());
            let shared = crate::team::membership::share_environment(
                &ctx,
                None,
                "demo",
                "dev",
                "owner",
                "synthetic-admin",
            )
            .unwrap();
            let env = shared["env_id"].as_str().unwrap();
            let history = HistorySession::open_runtime(ctx.state, env).unwrap();
            assert!(!history.is_scoped());
            let device = history.load_device(&ctx).unwrap();
            assert!(device.record().unwrap().verify_uncached());
            assert!(ctx.state.import_identity().is_none());
            assert!(ctx.state.import_key_hash().unwrap().is_none());
            let counters = history.budget.counters.borrow();
            assert!(counters.work > 0 && counters.bytes > 0);
            drop(counters);
            drop(history);
            let edited = crate::team::membership::author_commit(
                &ctx,
                None,
                env,
                vec![serde_json::json!({"op":"settings.update","sync_interval_seconds":31})],
            )
            .unwrap();
            assert_eq!(edited.author_seq, 2);
            assert_eq!(edited.author, device.fingerprint().unwrap());
            assert_eq!(
                CommitStore::new(ctx.state, env)
                    .get(&edited.author, &edited.author_seq)
                    .unwrap(),
                Some(edited)
            );
            assert!(ctx.state.import_identity().is_none());
            assert!(!ctx.state.exists(crate::import_barrier::INDEX));
        }

        #[test]
        fn actual_identity_loading_debits_parent_before_first_acquisition() {
            let fixture = crate::team::bootstrap::install::tests::pending();
            let history =
                HistorySession::open_probe(&fixture.a, &fixture.env, ProbePurpose::Invite).unwrap();
            let (work, bytes) = {
                let counters = history.budget.counters.borrow();
                (counters.work, counters.bytes)
            };
            assert!(work > 0 && bytes > 3);
            eprintln!("PVBOOT_INITIAL_PARENT_CHARGE work={work} bytes={bytes}");
            // Pin the actual conflict with an absolute-from-zero fill: this
            // must refuse now that actual identity I/O belongs to the parent.
            assert_eq!(
                history.charge(0, BYTES - 3).unwrap_err().reason,
                "team_bootstrap_limit_exceeded"
            );
        }
    }

    // Keep private-access tests in their original expansion scope; their
    // definitions live in a top-level test-only module, like other suites.
    #[cfg(test)]
    super::retained_history_test_bodies::define!();

    /// Metadata counters only: no control over selection, predicates, budgets,
    /// originals, clocks or outcomes. Entire module is syntactically test-only.
    #[cfg(test)]
    pub(crate) mod testing {
        use super::*;
        use std::sync::{LazyLock, Mutex};
        #[derive(Clone, Default)]
        struct Stats {
            acquired: u64,
            entries: u64,
            slots: u64,
            work: u64,
            bytes: u64,
            max_work: u64,
            max_bytes: u64,
            stages: BTreeMap<&'static str, (u64, u64, u64)>,
        }
        static SCOPES: LazyLock<Mutex<BTreeMap<std::path::PathBuf, Stats>>> =
            LazyLock::new(|| Mutex::new(BTreeMap::new()));
        pub(crate) struct Scope {
            root: std::path::PathBuf,
            _thread: PhantomData<Rc<()>>,
        }
        impl Scope {
            pub(crate) fn owned(state: &StateDir) -> Self {
                assert!(state.path.is_dir());
                let mut scopes = SCOPES.lock().unwrap_or_else(|e| e.into_inner());
                assert!(scopes.len() < 8);
                assert!(
                    scopes
                        .insert(state.path.clone(), Stats::default())
                        .is_none()
                );
                Self {
                    root: state.path.clone(),
                    _thread: PhantomData,
                }
            }
            pub(crate) fn snapshot(&self) -> Value {
                let scopes = SCOPES.lock().unwrap_or_else(|e| e.into_inner());
                let s = &scopes[&self.root];
                json!({"acquisitions":s.acquired,"physical_entries_visited":s.entries,"canonical_slots_visited":s.slots,"charged_work_total":s.work,"charged_bytes_total":s.bytes,"max_operation_work":s.max_work,"max_operation_bytes":s.max_bytes,"stages":s.stages.iter().map(|(name,(count,total,max))|(*name,json!({"count":count,"total_us":total,"max_us":max}))).collect::<BTreeMap<_,_>>()})
            }
        }
        impl Drop for Scope {
            fn drop(&mut self) {
                SCOPES
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&self.root);
            }
        }
        fn update(state: &StateDir, f: impl FnOnce(&mut Stats)) {
            if let Some(s) = SCOPES
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_mut(&state.path)
            {
                f(s)
            }
        }
        pub(crate) struct Span<'a> {
            state: &'a StateDir,
            name: &'static str,
            began: Instant,
        }
        impl Drop for Span<'_> {
            fn drop(&mut self) {
                let elapsed = u64::try_from(self.began.elapsed().as_micros()).unwrap();
                update(self.state, |stats| {
                    let value = stats.stages.entry(self.name).or_default();
                    value.0 = value.0.checked_add(1).unwrap();
                    value.1 = value.1.checked_add(elapsed).unwrap();
                    value.2 = value.2.max(elapsed);
                });
            }
        }
        pub(crate) fn span<'a>(state: &'a StateDir, name: &'static str) -> Option<Span<'a>> {
            SCOPES
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .contains_key(&state.path)
                .then(|| Span {
                    state,
                    name,
                    began: Instant::now(),
                })
        }
        pub(super) fn charge(
            state: &StateDir,
            work: u64,
            bytes: u64,
            total_work: u64,
            total_bytes: u64,
        ) {
            update(state, |s| {
                s.work = s.work.checked_add(work).unwrap();
                s.bytes = s.bytes.checked_add(bytes).unwrap();
                s.max_work = s.max_work.max(total_work);
                s.max_bytes = s.max_bytes.max(total_bytes);
            });
        }
        pub(super) fn acquired(state: &StateDir, entries: u64) {
            update(state, |s| {
                s.acquired = s.acquired.checked_add(1).unwrap();
                s.entries = s.entries.checked_add(entries).unwrap();
            });
        }
        pub(super) fn slot(state: &StateDir) {
            update(state, |s| s.slots = s.slots.checked_add(1).unwrap());
        }
    }
}
#[cfg(test)]
pub(crate) use retained_history::testing as history_testing;
pub(crate) use retained_history::{
    FactSeal, HistoryBudget as ImportHistoryBudget, HistoryResume, HistorySession, ProbePurpose,
};

// Syntax only. ImportIo reserves the raw walk and materialization before this
// bridge; signed records and retained-history authority are checked separately.
pub(crate) fn retained_import_json(raw: &[u8]) -> Result<Value> {
    super::checkpoint::retained_original(raw).map_err(|error| Error::state(error.reason()))
}

// Both suites expand inside retained_history, retaining private field access
// and exact test selectors. No production item is defined by this macro.
#[cfg(test)]
mod retained_history_test_bodies {
    macro_rules! define {
        () => {
    #[cfg(test)]
    mod personal_removal_tests {
        use super::*;
        use crate::{
            clock,
            context::{Config, Context},
            team::{bootstrap::install, identity::DeviceKey, membership},
        };
        use std::{
            os::unix::fs::{DirBuilderExt, PermissionsExt},
            path::Path,
            process::{Command, Stdio},
            sync::Arc,
        };
        fn copy(source: &Path, target: &Path) {
            let metadata = fs::symlink_metadata(source).unwrap();
            assert!(metadata.is_dir());
            fs::DirBuilder::new()
                .mode(metadata.permissions().mode() & 0o777)
                .create(target)
                .unwrap();
            for entry in fs::read_dir(source).unwrap() {
                let entry = entry.unwrap();
                let metadata = fs::symlink_metadata(entry.path()).unwrap();
                let target = target.join(entry.file_name());
                if metadata.is_dir() {
                    copy(&entry.path(), &target);
                } else {
                    assert!(metadata.is_file());
                    fs::copy(entry.path(), &target).unwrap();
                    fs::set_permissions(target, metadata.permissions()).unwrap();
                }
            }
        }
        fn cloned(source: &StateDir) -> (tempfile::TempDir, Arc<Context>) {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("b");
            copy(&source.path, &path);
            let ctx = Arc::new(Context::open(path, Config::default(), clock::system()).unwrap());
            (root, ctx)
        }
        fn signed(ctx: &Context, env: &str, key: &DeviceKey, ops: Vec<Value>) -> Commit {
            let store = CommitStore::new(ctx.state, env);
            let mut hlc = Hlc::new(0, 0);
            for c in store.all_commits().unwrap() {
                hlc.observe(&c.hlc).unwrap();
            }
            sign_commit(
                key,
                env,
                store.last_seq(&key.fingerprint().unwrap()).unwrap() + 1,
                &hlc.tick(None),
                &store.vector().unwrap(),
                ops,
            )
            .unwrap()
        }
        fn denial(env: &str) -> String {
            super::super::super::bootstrap::path(env, crate::import_barrier::LOCAL_REMOVAL_DENIAL)
                .unwrap()
        }
        fn denied(ctx: &Context) {
            assert!(ctx.vault.secret_for_trusted_use("alpha", None).is_err());
            assert!(
                ctx.vault
                    .list_secrets(None, None)
                    .unwrap()
                    .iter()
                    .all(|entry| entry.id != "alpha")
            );
            assert!(ctx.vault.secret_for_trusted_use("unrelated", None).is_ok());
        }
        fn accept(ctx: &Context, env: &str, c: &Commit) {
            assert_eq!(
                receive_commit(
                    &CommitStore::new(ctx.state, env),
                    c,
                    now_ms(),
                    Some(ctx.audit)
                )
                .unwrap(),
                "accepted"
            );
        }
        #[test]
        fn personal_removal_whole_effect_ignored_mixed_owner_transfer_and_self_user() {
            let fixture = install::tests::installed();
            let ak = DeviceKey::load_or_create(fixture.a.state, fixture.a.kms).unwrap();
            let bk = DeviceKey::load_or_create(fixture.b.state, fixture.b.kms).unwrap();
            let a = ak.fingerprint().unwrap();
            let b = bk.fingerprint().unwrap();
            let cases: Vec<(Vec<Value>, bool)> = vec![
                (vec![json!({"op":"member.remove","fingerprint":a})], false),
                (
                    vec![json!({"op":"member.remove","fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaa"})],
                    false,
                ),
                (
                    vec![
                        json!({"op":"member.remove","fingerprint":a}),
                        json!({"op":"member.remove","fingerprint":b}),
                    ],
                    true,
                ),
                (
                    vec![
                        json!({"op":"member.remove","fingerprint":b}),
                        json!({"op":"member.remove","fingerprint":a}),
                    ],
                    true,
                ),
            ];
            for (ops, effective) in cases {
                let (_root, ctx) = cloned(fixture.b.state);
                let c = signed(&ctx, &fixture.env, &bk, ops);
                accept(&ctx, &fixture.env, &c);
                assert_eq!(ctx.state.exists(&denial(&fixture.env)), effective);
                assert_eq!(
                    CommitStore::new(ctx.state, &fixture.env)
                        .get(&b, &c.author_seq)
                        .unwrap(),
                    Some(c.clone())
                );
                if effective {
                    denied(&ctx);
                } else {
                    assert!(ctx.vault.secret_for_trusted_use("alpha", None).is_ok());
                }
                assert_eq!(
                    receive_commit(
                        &CommitStore::new(ctx.state, &fixture.env),
                        &c,
                        now_ms(),
                        None
                    )
                    .unwrap(),
                    "duplicate"
                );
            }
            // The old author helper still refuses the whole mixed commit.
            let (_root, ctx) = cloned(fixture.b.state);
            assert!(
                membership::author_commit(
                    &ctx,
                    None,
                    &fixture.env,
                    vec![
                        json!({"op":"member.remove","fingerprint":a}),
                        json!({"op":"member.remove","fingerprint":b})
                    ]
                )
                .is_err()
            );
            assert!(!ctx.state.exists(&denial(&fixture.env)));
            // A current owner cannot be removed, including after a real transfer.
            let (_root, ctx) = cloned(fixture.b.state);
            let transfer = signed(
                &ctx,
                &fixture.env,
                &ak,
                vec![json!({"op":"owner.transfer","fingerprint":b})],
            );
            accept(&ctx, &fixture.env, &transfer);
            let ignored = signed(
                &ctx,
                &fixture.env,
                &bk,
                vec![json!({"op":"member.remove","fingerprint":b})],
            );
            accept(&ctx, &fixture.env, &ignored);
            assert!(!ctx.state.exists(&denial(&fixture.env)));
            assert!(ctx.vault.secret_for_trusted_use("alpha", None).is_ok());
            // Self-removal remains effective for an actual demoted user.
            let (_root, ctx) = cloned(fixture.b.state);
            let demote = signed(
                &ctx,
                &fixture.env,
                &ak,
                vec![json!({"op":"member.set_role","fingerprint":b,"role":"user"})],
            );
            accept(&ctx, &fixture.env, &demote);
            let removal = signed(
                &ctx,
                &fixture.env,
                &bk,
                vec![json!({"op":"member.remove","fingerprint":b})],
            );
            accept(&ctx, &fixture.env, &removal);
            denied(&ctx);
            println!(
                "PVBOOT_WHOLE_EFFECT_CASES {}",
                json!({"receive_cases":6,"author_refusal":1,"self_user":true,"owner_protected":true,"one_admission":true})
            );
        }
        #[test]
        fn personal_removal_delayed_role_change_enables_retained_removal() {
            let fixture = install::tests::installed();
            let (_a_root, sender) = cloned(fixture.a.state);
            let (_b_root, receiver) = cloned(fixture.b.state);
            let a = DeviceKey::load_or_create(sender.state, sender.kms).unwrap();
            let b = DeviceKey::load_or_create(receiver.state, receiver.kms).unwrap();
            let third = DeviceKey::generate();
            let third_fp = third.fingerprint().unwrap();
            let bfp = b.fingerprint().unwrap();
            // A real post-cut signed admission gives this author a user role.
            let admission = membership::author_commit(&sender, None, &fixture.env,
                vec![json!({"op":"member.add","device":third.record().unwrap().to_dict(),"name":"post-cut user","role":"user"})]).unwrap();
            accept(&receiver, &fixture.env, &admission);
            // A authors the promotion offline, before seeing the user's next
            // original. Its actual HLC is earlier; delivery is delayed.
            let promotion = membership::author_commit(
                &sender,
                None,
                &fixture.env,
                vec![json!({"op":"member.set_role","fingerprint":third_fp,"role":"admin"})],
            )
            .unwrap();
            let (wall, counter) = Hlc::parse(&promotion.hlc).unwrap();
            let attempted = sign_commit(
                &third,
                &fixture.env,
                1,
                &Hlc::new(wall, counter + 1).render(),
                &CommitStore::new(receiver.state, &fixture.env)
                    .vector()
                    .unwrap(),
                vec![json!({"op":"member.remove","fingerprint":bfp})],
            )
            .unwrap();
            accept(&receiver, &fixture.env, &attempted);
            let before = membership::load_environment(&receiver, &fixture.env).unwrap();
            assert_eq!(before.document["members"][&third_fp]["role"], "user");
            assert_eq!(before.document["members"][&bfp]["status"], "active");
            assert!(!receiver.state.exists(&denial(&fixture.env)));
            assert!(receiver.vault.secret_for_trusted_use("alpha", None).is_ok());
            assert!(!promotion.ops.iter().any(|op| op["op"] == "member.remove"));
            // The whole fold now places the promotion before the retained
            // removal. The candidate has no removal op of its own.
            accept(&receiver, &fixture.env, &promotion);
            let after = membership::load_environment(&receiver, &fixture.env).unwrap();
            assert_eq!(after.document["members"][&third_fp]["role"], "admin");
            assert_eq!(after.document["members"][&bfp]["status"], "removed");
            let witness = receiver
                .state
                .read_json(&denial(&fixture.env), Value::Null)
                .unwrap();
            assert_eq!(witness["cause"], "candidate");
            assert_eq!(witness["commit_hash"], promotion.hash().unwrap());
            assert_eq!(witness["commit"], promotion.to_dict());
            assert_eq!(
                CommitStore::new(receiver.state, &fixture.env)
                    .get(&third_fp, 1)
                    .unwrap(),
                Some(attempted)
            );
            assert!(!receiver.state.exists(
                &crate::team::bootstrap::path(&fixture.env, "member-removed.json").unwrap()
            ));
            denied(&receiver);
            assert_eq!(
                a.fingerprint().unwrap(),
                before.document["owner"].as_str().unwrap()
            );
            println!(
                "PVBOOT_INDIRECT_REMOVAL_WHOLE_FOLD {{\"real_admission\":true,\"ignored_user_original_retained\":true,\"delayed_promotion_has_no_removal_op\":true,\"denial_before_FACT\":true}}"
            );
        }
        #[test]
        fn personal_removal_retained_removed_author_and_inactive_target_are_ignored() {
            let fixture = install::tests::installed();
            let (_root, ctx) = cloned(fixture.b.state);
            let a = DeviceKey::load_or_create(fixture.a.state, fixture.a.kms).unwrap();
            let b = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
            let third = DeviceKey::generate();
            let third_fp = third.fingerprint().unwrap();
            let bfp = b.fingerprint().unwrap();
            let add = signed(
                &ctx,
                &fixture.env,
                &a,
                vec![
                    json!({"op":"member.add","device":third.record().unwrap().to_dict(),"name":"post-cut user","role":"user"}),
                ],
            );
            accept(&ctx, &fixture.env, &add);
            let remove = signed(
                &ctx,
                &fixture.env,
                &a,
                vec![json!({"op":"member.remove","fingerprint":third_fp})],
            );
            accept(&ctx, &fixture.env, &remove);
            assert_eq!(
                membership::load_environment(&ctx, &fixture.env)
                    .unwrap()
                    .document["members"][&third_fp]["status"],
                "removed"
            );
            let removed_author = signed(
                &ctx,
                &fixture.env,
                &third,
                vec![json!({"op":"member.remove","fingerprint":bfp})],
            );
            accept(&ctx, &fixture.env, &removed_author);
            let inactive_target = signed(
                &ctx,
                &fixture.env,
                &b,
                vec![json!({"op":"member.remove","fingerprint":third_fp})],
            );
            accept(&ctx, &fixture.env, &inactive_target);
            let store = CommitStore::new(ctx.state, &fixture.env);
            assert_eq!(store.get(&third_fp, 1).unwrap(), Some(removed_author));
            assert_eq!(
                store.get(&bfp, &inactive_target.author_seq).unwrap(),
                Some(inactive_target)
            );
            let result = membership::load_environment(&ctx, &fixture.env).unwrap();
            assert_eq!(result.document["members"][&bfp]["status"], "active");
            assert_eq!(result.document["members"][&third_fp]["status"], "removed");
            assert!(!ctx.state.exists(&denial(&fixture.env)));
            assert!(ctx.vault.secret_for_trusted_use("alpha", None).is_ok());
            assert_eq!(
                store
                    .all_commits()
                    .unwrap()
                    .iter()
                    .flat_map(|c| &c.ops)
                    .filter(|op| op["op"] == "member.add"
                        && op["device"] == b.record().unwrap().to_dict())
                    .count(),
                1
            );
            println!(
                "PVBOOT_IGNORED_REMOVAL_AUTHORITY {{\"removed_author_stored\":true,\"inactive_target_stored\":true,\"no_new_denial\":true,\"local_recipient_active\":true}}"
            );
        }
        #[test]
        fn personal_removal_committed_history_repair_revalidates_candidate_and_never_autoappends() {
            let fixture = install::tests::installed();
            let (_root, ctx) = cloned(fixture.b.state);
            let a = DeviceKey::load_or_create(fixture.a.state, fixture.a.kms).unwrap();
            let bfp = DeviceKey::load_or_create(ctx.state, ctx.kms)
                .unwrap()
                .fingerprint()
                .unwrap();
            let removal = signed(
                &ctx,
                &fixture.env,
                &a,
                vec![json!({"op":"member.remove","fingerprint":bfp})],
            );
            accept(&ctx, &fixture.env, &removal);
            let store = CommitStore::new(ctx.state, &fixture.env);
            // Test-only loss of this DATA leaf leaves the independently signed
            // committed original. No migration/all-evidence rollback promise.
            fs::remove_file(ctx.state.path.join(denial(&fixture.env))).unwrap();
            let metadata = signed(
                &ctx,
                &fixture.env,
                &a,
                vec![json!({"op":"settings.update","sync_interval_seconds":17})],
            );
            let mut invalid = metadata.clone();
            invalid.sig = "invalid".into();
            assert!(store.append(&invalid).is_err());
            assert!(!ctx.state.exists(&denial(&fixture.env)));
            assert!(
                store
                    .get(&a.fingerprint().unwrap(), &metadata.author_seq)
                    .unwrap()
                    .is_none()
            );
            accept(&ctx, &fixture.env, &metadata);
            let witness = ctx
                .state
                .read_json(&denial(&fixture.env), Value::Null)
                .unwrap();
            assert_eq!(witness["cause"], "committed_history");
            assert!(witness.get("commit").is_none());
            assert!(witness.get("commit_hash").is_none());
            assert_eq!(
                store.get(&removal.author, &removal.author_seq).unwrap(),
                Some(removal)
            );
            assert_eq!(
                store.get(&metadata.author, &metadata.author_seq).unwrap(),
                Some(metadata.clone())
            );
            denied(&ctx);
            let witness_bytes = ctx.state.read_bytes(&denial(&fixture.env)).unwrap();
            assert_eq!(
                receive_commit(&store, &metadata, now_ms(), None).unwrap(),
                "duplicate"
            );
            assert_eq!(
                ctx.state.read_bytes(&denial(&fixture.env)).unwrap(),
                witness_bytes
            );
            let reopened =
                Context::open(&ctx.state.path, Config::default(), clock::system()).unwrap();
            assert_eq!(
                CommitStore::new(reopened.state, &fixture.env)
                    .last_seq(&metadata.author)
                    .unwrap(),
                metadata.author_seq
            );
            denied(&reopened);
            println!(
                "PVBOOT_COMMITTED_HISTORY_REPAIR {{\"independent_signed_original\":true,\"invalid_candidate_no_marker\":true,\"same_original_retry\":true,\"no_candidate_JSON_authority\":true,\"no_autoappend_on_reopen\":true}}"
            );
        }
        #[test]
        fn personal_removal_raw_invalid_routing_retry_and_true_deferred() {
            let fixture = install::tests::installed();
            let predecessor = membership::author_commit(
                &fixture.b,
                None,
                &fixture.env,
                vec![json!({"op":"settings.update","sync_interval_seconds":21})],
            )
            .unwrap();
            assert_eq!(predecessor.author_seq, 1);
            let bk = DeviceKey::load_or_create(fixture.b.state, fixture.b.kms).unwrap();
            let b = bk.fingerprint().unwrap();
            let original = signed(
                &fixture.b,
                &fixture.env,
                &bk,
                vec![json!({"op":"member.remove","fingerprint":b})],
            );
            for kind in [
                "signature",
                "format",
                "env",
                "gap",
                "clock",
                "floor",
                "equal_clock",
                "lower_clock",
                "unknown_author",
                "custom",
                "alias",
                "absolute",
                "state",
                "nested",
            ] {
                let (_root, ctx) = cloned(fixture.b.state);
                let store = CommitStore::new(ctx.state, &fixture.env);
                let mut c = original.clone();
                let result = match kind {
                    "signature" => {
                        c.sig = "invalid".into();
                        store.append(&c)
                    }
                    "format" => {
                        c.format = "unknown".into();
                        store.append(&c)
                    }
                    "env" => {
                        c.env_id = "other".into();
                        store.append(&c)
                    }
                    "gap" => {
                        c = sign_commit(
                            &bk,
                            &fixture.env,
                            &c.author_seq + 1,
                            &c.hlc,
                            &c.seen,
                            c.ops.clone(),
                        )
                        .unwrap();
                        store.append(&c)
                    }
                    "clock" => {
                        c = sign_commit(
                            &bk,
                            &fixture.env,
                            c.author_seq.clone(),
                            &format!("{}-0000", now_ms() + MAX_CLOCK_SKEW_MS + 10_000),
                            &c.seen,
                            c.ops.clone(),
                        )
                        .unwrap();
                        store.append(&c)
                    }
                    "floor" => {
                        c = sign_commit(
                            &bk,
                            &fixture.env,
                            c.author_seq.clone(),
                            "1-0000",
                            &c.seen,
                            c.ops.clone(),
                        )
                        .unwrap();
                        store.append(&c)
                    }
                    "equal_clock" | "lower_clock" => {
                        let previous = store.get(&b, &original.author_seq - 1).unwrap().unwrap();
                        let hlc = if kind == "equal_clock" {
                            previous.hlc
                        } else {
                            let (wall, _) = Hlc::parse(&previous.hlc).unwrap();
                            Hlc::new(wall - 1, 0).render()
                        };
                        c = sign_commit(
                            &bk,
                            &fixture.env,
                            c.author_seq.clone(),
                            &hlc,
                            &c.seen,
                            c.ops.clone(),
                        )
                        .unwrap();
                        store.append(&c)
                    }
                    "unknown_author" => {
                        c = sign_commit(
                            &DeviceKey::generate(),
                            &fixture.env,
                            1,
                            &c.hlc,
                            &c.seen,
                            c.ops.clone(),
                        )
                        .unwrap();
                        store.append(&c)
                    }
                    "custom" => CommitStore {
                        state: ctx.state,
                        env_id: fixture.env.clone(),
                        root: format!("team/{}/commits/..", fixture.env),
                    }
                    .append(&c),
                    "alias" => CommitStore {
                        state: ctx.state,
                        env_id: "wrong".into(),
                        root: format!("team/{}", fixture.env),
                    }
                    .append(&c),
                    "absolute" => CommitStore {
                        state: ctx.state,
                        env_id: fixture.env.clone(),
                        root: ctx
                            .state
                            .path
                            .join(format!("team/{}", fixture.env))
                            .to_str()
                            .unwrap()
                            .into(),
                    }
                    .append(&c),
                    "state" => {
                        let state = StateDir::new(&ctx.state.path);
                        CommitStore::new(&state, &fixture.env).append(&c)
                    }
                    "nested" => {
                        let _lock = ctx.state.lock().unwrap();
                        store.append(&c)
                    }
                    _ => unreachable!(),
                };
                assert!(result.is_err(), "invalid case {kind}");
                assert!(
                    !ctx.state.exists(&denial(&fixture.env)),
                    "invalid minted denial {kind}"
                );
                assert!(store.get(&b, &original.author_seq).unwrap().is_none());
                assert!(ctx.vault.secret_for_trusted_use("alpha", None).is_ok());
            }
            let (_root, ctx) = cloned(fixture.b.state);
            let store = CommitStore::new(ctx.state, &fixture.env);
            store.append(&original).unwrap();
            let witness = ctx.state.read_bytes(&denial(&fixture.env)).unwrap();
            assert!(store.append(&original).is_err());
            assert_eq!(
                receive_commit(&store, &original, now_ms(), None).unwrap(),
                "duplicate"
            );
            assert_eq!(
                ctx.state.read_bytes(&denial(&fixture.env)).unwrap(),
                witness
            );
            denied(&ctx);
            let (_root, ctx) = cloned(fixture.b.state);
            let store = CommitStore::new(ctx.state, &fixture.env);
            let future = sign_commit(
                &bk,
                &fixture.env,
                original.author_seq.clone(),
                &format!("{}-0000", now_ms() + MAX_CLOCK_SKEW_MS + 100),
                &original.seen,
                original.ops.clone(),
            )
            .unwrap();
            assert_eq!(
                receive_commit(&store, &future, now_ms(), None).unwrap(),
                "deferred"
            );
            assert!(!ctx.state.exists(&denial(&fixture.env)));
            assert!(store.release_deferred(now_ms(), None).unwrap().is_empty());
            std::thread::sleep(Duration::from_millis(150));
            assert_eq!(
                store.release_deferred(now_ms(), None).unwrap(),
                vec![future.clone()]
            );
            assert!(store.deferred_commits().unwrap().is_empty());
            assert_eq!(store.get(&b, &future.author_seq).unwrap(), Some(future));
            denied(&ctx);
            println!(
                "PVBOOT_RAW_DENIAL_CASES {}",
                json!({"invalid_cases":14,"raw_append":true,"exact_retry":true,"true_deferred_due":true})
            );
        }
        #[test]
        fn personal_removal_every_writer_io_edge_retains_monotone_denial() {
            let fixture = install::tests::installed();
            let bk = DeviceKey::load_or_create(fixture.b.state, fixture.b.kms).unwrap();
            let b = bk.fingerprint().unwrap();
            let c = signed(
                &fixture.b,
                &fixture.env,
                &bk,
                vec![json!({"op":"member.remove","fingerprint":b})],
            );
            let (_root, baseline) = cloned(fixture.b.state);
            let scope = crate::import_barrier::testing::Scope::track(baseline.state, None);
            CommitStore::new(baseline.state, &fixture.env)
                .append(&c)
                .unwrap();
            let hits = scope.hits();
            drop(scope);
            assert!(
                hits.iter()
                    .any(|(name, point)| name.ends_with("local-removal-denial.json")
                        && point == "parent-fsync-after")
            );
            assert!(
                hits.iter()
                    .any(|(name, point)| name.contains("/commits/")
                        && point == "final-readback-after")
            );
            for index in 0..hits.len() {
                let (_root, ctx) = cloned(fixture.b.state);
                let scope = crate::import_barrier::testing::Scope::track(ctx.state, Some(index));
                let result = CommitStore::new(ctx.state, &fixture.env).append(&c);
                assert!(scope.fired(), "edge {index}");
                assert!(result.is_err(), "edge {index}");
                drop(scope);
                let marker = ctx.state.exists(&denial(&fixture.env));
                let stored = CommitStore::new(ctx.state, &fixture.env)
                    .get(&b, &c.author_seq)
                    .unwrap();
                assert!(
                    stored.is_none() || marker,
                    "commit without denial at {index}"
                );
                let reopened =
                    Context::open(&ctx.state.path, Config::default(), clock::system()).unwrap();
                if marker {
                    denied(&reopened);
                } else {
                    assert!(stored.is_none());
                    assert!(reopened.vault.secret_for_trusted_use("alpha", None).is_ok());
                }
            }
            println!(
                "PVBOOT_DENIAL_IO_EDGES {}",
                json!({"edges":hits.len(),"before_commit_denial":true,"uncertainty_preserved":true})
            );
        }
        #[test]
        fn personal_removal_crash_child() {
            let Some(path) = std::env::var_os("PVBOOT_DENIAL_OWN_STATE") else {
                return;
            };
            let env = std::env::var("PVBOOT_DENIAL_OWN_ENV").unwrap();
            let edge: usize = std::env::var("PVBOOT_DENIAL_OWN_EDGE")
                .unwrap()
                .parse()
                .unwrap();
            let ctx = Context::open(path, Config::default(), clock::system()).unwrap();
            let key = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
            let b = key.fingerprint().unwrap();
            let c = signed(
                &ctx,
                &env,
                &key,
                vec![json!({"op":"member.remove","fingerprint":b})],
            );
            let _scope = crate::import_barrier::testing::Scope::crash(ctx.state, edge);
            if std::env::var_os("PVBOOT_DENIAL_OWN_FACT").is_some() {
                membership::remove_member(&ctx, None, &env, &b).unwrap();
            } else {
                CommitStore::new(ctx.state, &env).append(&c).unwrap();
            }
            panic!("crash edge not reached");
        }
        #[test]
        fn personal_removal_independent_process_death_at_every_writer_edge() {
            let fixture = install::tests::installed();
            let bk = DeviceKey::load_or_create(fixture.b.state, fixture.b.kms).unwrap();
            let b = bk.fingerprint().unwrap();
            let c = signed(
                &fixture.b,
                &fixture.env,
                &bk,
                vec![json!({"op":"member.remove","fingerprint":b})],
            );
            let (_root, baseline) = cloned(fixture.b.state);
            let scope = crate::import_barrier::testing::Scope::track(baseline.state, None);
            CommitStore::new(baseline.state, &fixture.env)
                .append(&c)
                .unwrap();
            let count = scope.hits().len();
            drop(scope);
            for edge in 0..count {
                let (_root, ctx) = cloned(fixture.b.state);
                let status=Command::new(std::env::current_exe().unwrap()).args(["--exact","team::commit::retained_history::personal_removal_tests::personal_removal_crash_child","--nocapture"]).env("PVBOOT_DENIAL_OWN_STATE",&ctx.state.path).env("PVBOOT_DENIAL_OWN_ENV",&fixture.env).env("PVBOOT_DENIAL_OWN_EDGE",edge.to_string()).stdout(Stdio::null()).stderr(Stdio::inherit()).status().unwrap();
                assert_eq!(status.code(), Some(86), "crash edge {edge}");
                let reopened =
                    Context::open(&ctx.state.path, Config::default(), clock::system()).unwrap();
                let marker = reopened.state.exists(&denial(&fixture.env));
                let stored = CommitStore::new(reopened.state, &fixture.env)
                    .get(&b, &c.author_seq)
                    .unwrap();
                assert!(stored.is_none() || marker);
                if marker {
                    denied(&reopened);
                } else {
                    assert!(reopened.vault.secret_for_trusted_use("alpha", None).is_ok());
                }
            }
            println!(
                "PVBOOT_DENIAL_PROCESS_DEATH {}",
                json!({"edges":count,"hardware_power_loss_proof":false})
            );
        }

        #[test]
        fn personal_removal_complete_fact_io_and_child_death_keep_denial() {
            let fixture = install::tests::installed();
            let key = DeviceKey::load_or_create(fixture.b.state, fixture.b.kms).unwrap();
            let b = key.fingerprint().unwrap();
            let next = CommitStore::new(fixture.b.state, &fixture.env)
                .last_seq(&b)
                .unwrap()
                + 1;
            let (_root, baseline) = cloned(fixture.b.state);
            let scope = crate::import_barrier::testing::Scope::track(baseline.state, None);
            membership::remove_member(&baseline, None, &fixture.env, &b).unwrap();
            let hits = scope.hits();
            drop(scope);
            assert!(hits.iter().any(|(_, point)| point == "fact-receipt-after"));
            assert!(hits.iter().any(|(_, point)| point == "fact-refold-after"));
            for edge in 0..hits.len() {
                let (_root, ctx) = cloned(fixture.b.state);
                let scope = crate::import_barrier::testing::Scope::track(ctx.state, Some(edge));
                assert!(
                    membership::remove_member(&ctx, None, &fixture.env, &b).is_err(),
                    "FACT IO edge {edge}"
                );
                assert!(scope.fired());
                drop(scope);
                let stored = CommitStore::new(ctx.state, &fixture.env)
                    .get(&b, &next)
                    .unwrap();
                let marker = ctx.state.exists(&denial(&fixture.env));
                assert!(stored.is_none() || marker);
                if marker {
                    denied(&ctx);
                }
                let reopened =
                    Context::open(&ctx.state.path, Config::default(), clock::system()).unwrap();
                if marker {
                    denied(&reopened);
                }
                let (_root, child_ctx) = cloned(fixture.b.state);
                let status=Command::new(std::env::current_exe().unwrap()).args(["--exact","team::commit::retained_history::personal_removal_tests::personal_removal_crash_child","--nocapture"]).env("PVBOOT_DENIAL_OWN_STATE",&child_ctx.state.path).env("PVBOOT_DENIAL_OWN_ENV",&fixture.env).env("PVBOOT_DENIAL_OWN_EDGE",edge.to_string()).env("PVBOOT_DENIAL_OWN_FACT","1").stdout(Stdio::null()).stderr(Stdio::inherit()).status().unwrap();
                assert_eq!(status.code(), Some(86), "FACT crash edge {edge}");
                let reopened =
                    Context::open(&child_ctx.state.path, Config::default(), clock::system())
                        .unwrap();
                let stored = CommitStore::new(reopened.state, &fixture.env)
                    .get(&b, &next)
                    .unwrap();
                let marker = reopened.state.exists(&denial(&fixture.env));
                assert!(stored.is_none() || marker);
                if marker {
                    denied(&reopened);
                }
            }
            println!(
                "PVBOOT_REMOVAL_FACT_FAULT_MATRIX {}",
                json!({"io_edges":hits.len(),"process_death_edges":hits.len(),"audit_refold_receipt_retention_original_fact":true})
            );
        }
        #[test]
        fn personal_removal_raw_settled_facts_require_real_receipts_and_retention() {
            let fixture = install::tests::installed();
            let bk = DeviceKey::load_or_create(fixture.b.state, fixture.b.kms).unwrap();
            let b = bk.fingerprint().unwrap();
            let (_root, settled) = cloned(fixture.b.state);
            let fact = membership::author_fact(
                &settled,
                None,
                &fixture.env,
                "secret_deleted",
                json!({"secret_id":"alpha"}),
            )
            .unwrap();
            assert!(crate::team::sync::Fact::from_dict(&fact).is_ok());
            let (_root, raw) = cloned(settled.state);
            let c = signed(
                &raw,
                &fixture.env,
                &bk,
                vec![json!({"op":"member.remove","fingerprint":b})],
            );
            CommitStore::new(raw.state, &fixture.env)
                .append(&c)
                .unwrap();
            denied(&raw);
            for missing in ["receipt", "binding"] {
                let (_root, ctx) = cloned(settled.state);
                if missing == "receipt" {
                    for leaf in ["fact_admissions.json", "fact_admissions.jsonl"] {
                        let name = format!("team/{}/{leaf}", fixture.env);
                        if ctx.state.exists(&name) {
                            fs::remove_file(ctx.state.path.join(name)).unwrap();
                        }
                    }
                } else {
                    let mut ledger = ctx
                        .state
                        .read_json(crate::tombstone::PATH, json!({}))
                        .unwrap();
                    ledger.as_object_mut().unwrap().remove("bindings");
                    ctx.state
                        .write_json(crate::tombstone::PATH, &ledger)
                        .unwrap();
                }
                let c = signed(
                    &ctx,
                    &fixture.env,
                    &bk,
                    vec![json!({"op":"member.remove","fingerprint":b})],
                );
                let store = CommitStore::new(ctx.state, &fixture.env);
                assert!(store.append(&c).is_err(), "raw unsettled {missing}");
                assert!(!ctx.state.exists(&denial(&fixture.env)));
                assert!(store.get(&b, &c.author_seq).unwrap().is_none());
                // Context service may settle precisely the existing real fact;
                // the raw service never acquired signing authority.
                let history = HistorySession::open_runtime(ctx.state, &fixture.env).unwrap();
                assert_eq!(
                    receive_runtime_with_input(&store, &c, now_ms(), None, true, &history, &ctx)
                        .unwrap(),
                    "accepted"
                );
                drop(history);
                denied(&ctx);
            }
            println!(
                "PVBOOT_VERIFY_SETTLED_FACTS {}",
                json!({"existing_real_fact":true,"raw_settled":true,"missing_receipt_refused":true,"missing_binding_refused":true,"runtime_same_parent_settlement":true})
            );
        }
        #[test]
        fn personal_removal_projection_collision_backup_restore_and_witness_union() {
            use crate::vault::Vault;
            let fixture = install::tests::installed();
            let ak = DeviceKey::load_or_create(fixture.a.state, fixture.a.kms).unwrap();
            let bk = DeviceKey::load_or_create(fixture.b.state, fixture.b.kms).unwrap();
            let b = bk.fingerprint().unwrap();
            let (_root, ctx) = cloned(fixture.b.state);
            let before = ctx.state.read_bytes(crate::vault::VAULT_DOC).unwrap();
            let connections = ctx.state.read_bytes(crate::policy::CONNECTIONS).unwrap();
            let cipher = crate::team::envelope::encrypt_secret(
                &[7; 32],
                &fixture.env,
                "unrelated",
                "7777777777777777",
                b"synthetic-hidden-collision",
            )
            .unwrap();
            let c = signed(
                &ctx,
                &fixture.env,
                &ak,
                vec![
                    json!({"op":"secret.put_version","secret_id":"unrelated","version_id":"7777777777777777","generation_id":"0123456789abcdef","kind":"api_key","ciphertext":cipher,"public":{}}),
                    json!({"op":"secret.activate","secret_id":"unrelated","version_id":"7777777777777777"}),
                    json!({"op":"member.remove","fingerprint":b}),
                ],
            );
            accept(&ctx, &fixture.env, &c);
            let folded = membership::refold_and_derive(&ctx, &fixture.env).unwrap();
            assert!(folded.document["secrets"].get("unrelated").is_some());
            assert!(folded.version_order.get("unrelated").is_some());
            assert_eq!(
                ctx.state.read_bytes(crate::vault::VAULT_DOC).unwrap(),
                before
            );
            assert_eq!(
                ctx.state.read_bytes(crate::policy::CONNECTIONS).unwrap(),
                connections
            );
            denied(&ctx);
            let pre = fixture.root.path().join("denial-pre.json");
            fixture.b.vault.backup(&pre).unwrap();
            let post = fixture.root.path().join("denial-post.json");
            ctx.vault.backup(&post).unwrap();
            let witness = ctx.state.read_bytes(&denial(&fixture.env)).unwrap();
            assert!(Vault::restore(ctx.state, &pre, ctx.audit, Some(ctx.kms)).is_err());
            assert_eq!(
                ctx.state.read_bytes(crate::vault::VAULT_DOC).unwrap(),
                before
            );
            assert_eq!(
                ctx.state.read_bytes(&denial(&fixture.env)).unwrap(),
                witness
            );
            assert!(ctx.policy.restore_pending().unwrap());
            denied(&ctx);
            Vault::restore(ctx.state, &post, ctx.audit, Some(ctx.kms)).unwrap();
            assert_eq!(
                ctx.state.read_bytes(&denial(&fixture.env)).unwrap(),
                witness
            );
            denied(&ctx);
            // A real v1 archive with its optional bootstrap field removed is a
            // legacy archive. Recompute only its ordinary DATA checksum.
            let mut legacy = pyjson::loads(&fs::read_to_string(&post).unwrap()).unwrap();
            legacy["documents"]
                .as_object_mut()
                .unwrap()
                .remove(crate::import_barrier::BACKUP);
            let payload =
                pyjson::dumps(&legacy["documents"], DumpOptions::compact_sorted()).unwrap();
            legacy["manifest"]["sha256"] = json!(hex::encode(Sha256::digest(payload.as_bytes())));
            let legacy_path = fixture.root.path().join("denial-legacy.json");
            fs::write(
                &legacy_path,
                pyjson::dumps(&legacy, DumpOptions::default_sorted()).unwrap(),
            )
            .unwrap();
            Vault::restore(ctx.state, &legacy_path, ctx.audit, Some(ctx.kms)).unwrap();
            assert_eq!(
                ctx.state.read_bytes(&denial(&fixture.env)).unwrap(),
                witness
            );
            denied(&ctx);
            for damage in ["truncated", "wrong_epoch", "directory", "symlink", "mode"] {
                let (_root, copy) = cloned(ctx.state);
                let path = copy.state.path.join(denial(&fixture.env));
                match damage {
                    "truncated" => fs::write(&path, b"{").unwrap(),
                    "wrong_epoch" => {
                        let mut value =
                            pyjson::loads(std::str::from_utf8(&witness).unwrap()).unwrap();
                        value["epoch"] = json!("wrong");
                        fs::write(
                            &path,
                            pyjson::dumps(&value, DumpOptions::pretty_sorted()).unwrap(),
                        )
                        .unwrap();
                    }
                    "directory" => {
                        fs::remove_file(&path).unwrap();
                        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
                    }
                    "symlink" => {
                        fs::remove_file(&path).unwrap();
                        std::os::unix::fs::symlink("receipt.json", &path).unwrap();
                    }
                    "mode" => {
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap()
                    }
                    _ => unreachable!(),
                };
                denied(&copy);
                assert!(
                    crate::import_barrier::backup_provenance(copy.state).is_err()
                        || damage == "truncated"
                        || damage == "wrong_epoch"
                );
            }
            let (_root, both) = cloned(fixture.b.state);
            membership::remove_member(&both, None, &fixture.env, &b).unwrap();
            let fact =
                super::super::super::bootstrap::path(&fixture.env, "member-removed.json").unwrap();
            assert!(both.state.exists(&fact));
            assert!(both.state.exists(&denial(&fixture.env)));
            for removed in [&fact, &denial(&fixture.env)] {
                let (_root, one) = cloned(both.state);
                fs::remove_file(one.state.path.join(removed)).unwrap();
                denied(&one);
                assert!(Vault::restore(one.state, &post, one.audit, Some(one.kms)).is_err());
                denied(&one);
            }
            println!(
                "PVBOOT_DENIAL_RESTORE_PROJECTION {}",
                json!({"raw_projection_unchanged":true,"hidden_collision":true,"real_backups":2,"legacy_restore_denied":true,"damaged_witness_cases":5,"single_surviving_proofs":2})
            );
        }

        #[test]
        fn personal_removal_deferred_parent_deadline_independent() {
            let fixture = install::tests::installed();
            let bk = DeviceKey::load_or_create(fixture.b.state, fixture.b.kms).unwrap();
            let b = bk.fingerprint().unwrap();
            let (_root, ctx) = cloned(fixture.b.state);
            let store = CommitStore::new(ctx.state, &fixture.env);
            let first = signed(
                &ctx,
                &fixture.env,
                &bk,
                vec![json!({"op":"settings.update","sync_interval_seconds":21})],
            );
            let mut clock = Hlc::new(0, 0);
            clock.observe(&first.hlc).unwrap();
            let second = sign_commit(
                &bk,
                &fixture.env,
                &first.author_seq + 1,
                &clock.tick(None),
                &first.seen,
                vec![json!({"op":"member.remove","fingerprint":b})],
            )
            .unwrap();
            store.defer(&first).unwrap();
            store.defer(&second).unwrap();
            let (scope, pause) = crate::import_barrier::testing::Scope::pause(
                ctx.state,
                &format!("/{}.json", second.author_seq),
                "rename-before",
            );
            let release = std::thread::spawn(move || {
                pause.wait();
                std::thread::sleep(Duration::from_millis(5_020));
                pause.release();
            });
            assert!(store.release_deferred(now_ms(), None).is_err());
            release.join().unwrap();
            assert!(scope.fired());
            drop(scope);
            assert_eq!(store.get(&b, &first.author_seq).unwrap(), Some(first));
            assert!(store.get(&b, &second.author_seq).unwrap().is_none());
            assert_eq!(store.deferred_commits().unwrap(), vec![second]);
            denied(&ctx);
            eprintln!("PVBOOT_DENIAL_DEFERRED_DEADLINE independent=true first_committed=true second_blocked=true original_budget=true permanent_denial=true");
        }

        #[test]
        fn personal_removal_real_root_lock_replacement_and_deferred_parent_deadline() {
            let fixture = install::tests::installed();
            let bk = DeviceKey::load_or_create(fixture.b.state, fixture.b.kms).unwrap();
            let b = bk.fingerprint().unwrap();
            let c = signed(
                &fixture.b,
                &fixture.env,
                &bk,
                vec![json!({"op":"member.remove","fingerprint":b})],
            );
            for replace_root in [false, true] {
                let (_root, ctx) = cloned(fixture.b.state);
                let h = HistorySession::open_runtime(ctx.state, &fixture.env).unwrap();
                let store = CommitStore::new(ctx.state, &fixture.env);
                let prepared = PreparedAppend::prepare(&store, &c, now_ms(), &h, None)
                    .unwrap_or_else(|failure| panic!("{}", failure.into_error().reason));
                if replace_root {
                    let moved = ctx.state.path.with_file_name("old-root");
                    fs::rename(&ctx.state.path, &moved).unwrap();
                    copy(&moved, &ctx.state.path);
                } else {
                    let lock = ctx.state.path.join(".lock");
                    fs::rename(&lock, ctx.state.path.join(".old-lock")).unwrap();
                    fs::write(&lock, b"").unwrap();
                    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
                }
                assert!(prepared.publish().is_err());
                assert!(!ctx.state.exists(&denial(&fixture.env)));
                assert_eq!(
                    CommitStore::new(ctx.state, &fixture.env)
                        .get(&b, &c.author_seq)
                        .unwrap_err()
                        .reason,
                    "team_bootstrap_local_state_changed"
                );
                assert_eq!(
                    fs::symlink_metadata(ctx.state.path.join(store.commit_path(&b, &c.author_seq)))
                        .unwrap_err()
                        .kind(),
                    std::io::ErrorKind::NotFound
                );
                drop(h);
            }
            let (_root, ctx) = cloned(fixture.b.state);
            let store = CommitStore::new(ctx.state, &fixture.env);
            let first = signed(
                &ctx,
                &fixture.env,
                &bk,
                vec![json!({"op":"settings.update","sync_interval_seconds":21})],
            );
            let mut clock = Hlc::new(0, 0);
            clock.observe(&first.hlc).unwrap();
            let second = sign_commit(
                &bk,
                &fixture.env,
                &first.author_seq + 1,
                &clock.tick(None),
                &first.seen,
                vec![json!({"op":"member.remove","fingerprint":b})],
            )
            .unwrap();
            store.defer(&first).unwrap();
            store.defer(&second).unwrap();
            let (scope, pause) = crate::import_barrier::testing::Scope::pause(
                ctx.state,
                &format!("/{}.json", second.author_seq),
                "rename-before",
            );
            let release = std::thread::spawn(move || {
                pause.wait();
                std::thread::sleep(Duration::from_millis(5_020));
                pause.release();
            });
            assert!(store.release_deferred(now_ms(), None).is_err());
            release.join().unwrap();
            assert!(scope.fired());
            drop(scope);
            assert_eq!(store.get(&b, &first.author_seq).unwrap(), Some(first));
            assert!(store.get(&b, &second.author_seq).unwrap().is_none());
            assert_eq!(store.deferred_commits().unwrap(), vec![second]);
            denied(&ctx);
            println!(
                "PVBOOT_DENIAL_ROOT_AND_DEFERRED {}",
                json!({"root_replacement_refused":true,"lock_replacement_refused":true,"one_budget_across_two_records":true,"later_deferred_retained":true,"permanent_denial":true})
            );
        }
        #[test]
        fn personal_removal_parent_limits_staleness_and_expiry_before_renames() {
            let fixture = install::tests::installed();
            let bk = DeviceKey::load_or_create(fixture.b.state, fixture.b.kms).unwrap();
            let b = bk.fingerprint().unwrap();
            let c = signed(
                &fixture.b,
                &fixture.env,
                &bk,
                vec![json!({"op":"member.remove","fingerprint":b})],
            );
            for bytes in [false, true] {
                let (_root, ctx) = cloned(fixture.b.state);
                let h = HistorySession::open_runtime(ctx.state, &fixture.env).unwrap();
                assert!(
                    h.charge(if bytes { 0 } else { WORK }, if bytes { BYTES } else { 0 })
                        .is_err()
                );
                assert!(h.nested(ctx.state, &fixture.env).is_err());
                assert!(
                    append_with_input(
                        &CommitStore::new(ctx.state, &fixture.env),
                        &c,
                        now_ms(),
                        &h,
                        None
                    )
                    .is_err()
                );
                assert!(!ctx.state.exists(&denial(&fixture.env)));
            }
            let (_root, ctx) = cloned(fixture.b.state);
            let h = HistorySession::open_runtime(ctx.state, &fixture.env).unwrap();
            let store = CommitStore::new(ctx.state, &fixture.env);
            let prepared = PreparedAppend::prepare(&store, &c, now_ms(), &h, None)
                .unwrap_or_else(|failure| panic!("{}", failure.into_error().reason));
            let name = super::super::super::bootstrap::path(&fixture.env, "receipt.json").unwrap();
            let bytes = ctx.state.read_bytes(&name).unwrap();
            ctx.state.write_bytes(&name, &bytes).unwrap();
            assert!(prepared.publish().is_err());
            assert!(!ctx.state.exists(&denial(&fixture.env)));
            drop(h);
            for suffix in [
                "local-removal-denial.json".to_string(),
                format!("/{}.json", c.author_seq),
            ] {
                let (_root, ctx) = cloned(fixture.b.state);
                let (scope, pause) = crate::import_barrier::testing::Scope::pause(
                    ctx.state,
                    &suffix,
                    "rename-before",
                );
                let release = std::thread::spawn(move || {
                    pause.wait();
                    std::thread::sleep(Duration::from_millis(5_020));
                    pause.release();
                });
                assert!(
                    CommitStore::new(ctx.state, &fixture.env)
                        .append(&c)
                        .is_err()
                );
                release.join().unwrap();
                assert!(scope.fired());
                drop(scope);
                assert!(
                    CommitStore::new(ctx.state, &fixture.env)
                        .get(&b, &c.author_seq)
                        .unwrap()
                        .is_none()
                );
                if suffix == "local-removal-denial.json" {
                    assert!(!ctx.state.exists(&denial(&fixture.env)));
                } else {
                    denied(&ctx);
                }
            }
            println!(
                "PVBOOT_DENIAL_PARENT_LIMITS {}",
                json!({"work":WORK,"charged_bytes":BYTES,"deadline_ms":5000,"rename_expiry_cases":2,"same_bytes_receipt_stale":true})
            );
        }
    }

    #[cfg(test)]
    mod boundary_tests {
        use super::*;
        use crate::{
            context::{Config, Context},
            team::envelope,
        };
        use std::{
            os::unix::{
                ffi::OsStringExt,
                fs::{PermissionsExt, symlink},
            },
            sync::mpsc,
            time::Duration,
        };
        use tempfile::TempDir;
        struct Fixture {
            _root: TempDir,
            ctx: Context,
            env: String,
            key: DeviceKey,
            genesis: Commit,
        }
        fn fixture() -> Fixture {
            let root = TempDir::new().unwrap();
            let ctx = Context::initialize(
                root.path().join("state"),
                "synthetic-history-admin",
                "synthetic-history-recovery",
                Config::default(),
                crate::clock::system(),
            )
            .unwrap();
            let key = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
            let fp = key.fingerprint().unwrap();
            let env = new_env_id(&fp).unwrap();
            let wrap =
                envelope::wrap_dek(&[9; 32], &env, "0123456789abcdef", &key.record().unwrap())
                    .unwrap();
            let genesis=sign_commit(&key,&env,1,"1000000-0000",&BTreeMap::new(),vec![json!({"op":"env.init","owner_device":key.record().unwrap().to_dict(),"owner_name":"synthetic-owner","generation_id":"0123456789abcdef","wraps":{fp:wrap}})]).unwrap();
            assert_eq!(
                receive_commit(
                    &CommitStore::new(ctx.state, &env),
                    &genesis,
                    1_000_001,
                    Some(ctx.audit)
                )
                .unwrap(),
                "accepted"
            );
            Fixture {
                _root: root,
                ctx,
                env,
                key,
                genesis,
            }
        }
        fn probe(f: &Fixture) -> HistorySession<'_> {
            HistorySession::open_probe(&f.ctx, &f.env, ProbePurpose::Invite).unwrap()
        }
        fn next(f: &Fixture, seq: i64, hlc: &str) -> Commit {
            sign_commit(
                &f.key,
                &f.env,
                seq,
                hlc,
                &BTreeMap::new(),
                vec![json!({"op":"settings.update","sync_interval_seconds":3})],
            )
            .unwrap()
        }
        fn put(f: &Fixture, c: &Commit) {
            f.ctx
                .state
                .write_json(
                    &format!("team/{}/commits/{}/{}.json", f.env, c.author, c.author_seq),
                    &c.to_dict(),
                )
                .unwrap();
        }
        fn reason<T>(result: Result<T>) -> String {
            match result {
                Ok(_) => panic!("expected refusal"),
                Err(e) => e.reason.into_owned(),
            }
        }

        #[test]
        fn personal_history_ordinary_provider_keeps_legacy_lazy_falsy_layout() {
            let root = TempDir::new().unwrap();
            let state = StateDir::new(root.path().join("state"));
            state.create().unwrap();
            let env = "legacy-test-env";
            let history = HistorySession::open_runtime(&state, env).unwrap();
            assert!(!history.is_scoped());
            assert!(history.acquire().unwrap().commits().unwrap().is_empty());
            state
                .write_json(
                    "team/legacy-test-env/commits/legacy-author/1.json",
                    &Value::Null,
                )
                .unwrap();
            let expected = CommitStore::new(&state, env).all_commits().unwrap();
            assert!(expected.is_empty());
            assert_eq!(history.acquire().unwrap().commits().unwrap(), expected);
        }

        #[test]
        fn personal_history_ordinary_resume_keeps_legacy_without_selected_deadline() {
            let f = fixture();
            let history = HistorySession::open_runtime(f.ctx.state, &f.env).unwrap();
            assert!(!history.is_scoped());
            let operation = history.into_resume().unwrap();
            std::thread::sleep(Duration::from_millis(5_020));
            operation.check_unlocked().unwrap();
            let resumed = operation.resume().unwrap();
            assert!(!resumed.is_scoped());
            assert_eq!(
                resumed.acquire().unwrap().commits().unwrap(),
                vec![f.genesis.clone()]
            );
        }
        #[test]
        fn personal_history_route_transition_and_nested_parse_keep_parent_limits() {
            let f = fixture();
            let ordinary = HistorySession::open_runtime(f.ctx.state, &f.env).unwrap();
            assert!(!ordinary.is_scoped());
            let operation = ordinary.into_resume().unwrap();
            f.ctx
                .state
                .write_json(
                    &format!("team/{}/bootstrap/untrusted-route.json", f.env),
                    &json!({}),
                )
                .unwrap();
            assert_eq!(
                reason(operation.resume()),
                "team_bootstrap_local_state_changed"
            );
            // DATA can force refusal, never authenticate an owner/recipient.
            assert!(HistorySession::open_runtime(f.ctx.state, &f.env).is_err());
            let other = fixture();
            let parent = probe(&other);
            other
                .ctx
                .state
                .write_bytes(crate::import_barrier::INDEX, b"{}")
                .unwrap();
            parent.invalidate().unwrap();
            let charged_bytes = parent.budget.counters.borrow().bytes;
            parent.charge(0, BYTES - charged_bytes - 3).unwrap();
            assert_eq!(
                reason(raw_witness_with_budget(
                    other.ctx.state,
                    &other.env,
                    Some(&parent)
                )),
                "team_bootstrap_limit_exceeded"
            );
            assert_eq!(parent.budget.counters.borrow().bytes, BYTES - 3);
            assert!(
                !other
                    .ctx
                    .state
                    .exists(&format!("team/{}/bootstrap/receipt.json", other.env))
            );
        }
        #[test]
        fn personal_history_bridge_lossless_numbers_reserved_keys_duplicates_depth_and_trailing() {
            let f = fixture();
            let h = probe(&f);
            let raw=br#"{"n":100000000000000000000000000000000000000000000000000000000000000000000000000000000,"$serde_json::private::Number":"123","$serde_json::private::RawValue":"{\"x\":7}"}"#;
            let value = h.parse(raw).unwrap();
            assert_eq!(
                value["n"].to_string(),
                "100000000000000000000000000000000000000000000000000000000000000000000000000000000"
            );
            assert_eq!(value["$serde_json::private::Number"], "123");
            assert_eq!(value["$serde_json::private::RawValue"], "{\"x\":7}");
            assert_eq!(
                reason(h.parse(br#"{"x":0,"\u0078":1}"#)),
                "team_checkpoint_duplicate_key"
            );
            for raw in [b"{}[]".as_slice(), b"[]garbage", b"{\"x\":}"] {
                assert!(h.parse(raw).is_err());
            }
            let deep64 = format!("{}0{}", "[".repeat(64), "]".repeat(64));
            assert!(h.parse(deep64.as_bytes()).is_ok());
            let deep65 = format!("{}0{}", "[".repeat(65), "]".repeat(65));
            assert_eq!(
                reason(h.parse(deep65.as_bytes())),
                "team_bootstrap_limit_exceeded"
            );
        }
        #[test]
        fn personal_history_budget_before_materialization_and_checked_shared_reservations() {
            let f = fixture();
            {
                let h = probe(&f);
                let charged_bytes = h.budget.counters.borrow().bytes;
                h.charge(0, BYTES - charged_bytes - 3).unwrap();
                // The invalid JSON would fail syntax if the bridge ran. The
                // byte reservation refuses first, without building a tree.
                assert_eq!(reason(h.parse(b"{")), "team_bootstrap_limit_exceeded");
                assert_eq!(h.budget.counters.borrow().bytes, BYTES - 3);
            }
            {
                let h = probe(&f);
                let nested = h.nested(f.ctx.state, &f.env).unwrap();
                let charged_work = h.budget.counters.borrow().work;
                h.charge(WORK - charged_work - 1, 0).unwrap();
                nested.charge(1, 0).unwrap();
                assert_eq!(reason(h.charge(1, 0)), "team_bootstrap_limit_exceeded");
                assert_eq!(
                    reason(nested.reserve_counts([u64::MAX, 1, 1, 1, 1, 1, 1])),
                    "team_bootstrap_limit_exceeded"
                );
                assert_eq!(h.budget.counters.borrow().work, WORK);
            }
            {
                let h = probe(&f);
                h.charge(17, 31).unwrap();
                let before_resume = {
                    let counters = h.budget.counters.borrow();
                    (counters.work, counters.bytes)
                };
                let original_budget = Rc::clone(&h.budget);
                let resume = h.into_resume().unwrap();
                let resumed = resume.resume().unwrap();
                assert!(Rc::ptr_eq(&resumed.budget, &original_budget));
                let charged = resumed.budget.counters.borrow().work;
                assert!(charged > before_resume.0, "resume must charge its full revalidation");
                assert!(resumed.budget.counters.borrow().bytes > before_resume.1);
                resumed.charge(WORK - charged, 0).unwrap();
                assert_eq!(original_budget.counters.borrow().work, WORK);
                assert_eq!(
                    reason(resumed.charge(1, 0)),
                    "team_bootstrap_limit_exceeded"
                );
                assert_eq!(
                    reason(resumed.charge(0, u64::MAX)),
                    "team_bootstrap_limit_exceeded"
                );
            }
        }
        #[test]
        fn personal_history_original_copy_reserves_work_and_heap_before_clone() {
            let f = fixture();
            for bytes in [false, true] {
                let history = probe(&f);
                let input = history.acquire().unwrap();
                let before = history.budget.counters.borrow();
                let work = before.work;
                let charged = before.bytes;
                drop(before);
                if bytes {
                    history.charge(0, BYTES - charged - 1).unwrap();
                } else {
                    history.charge(WORK - work - 1, 0).unwrap();
                }
                assert_eq!(
                    reason(input.observed_commits()),
                    "team_bootstrap_limit_exceeded"
                );
                assert_eq!(reason(history.check()), "team_bootstrap_limit_exceeded");
                if bytes {
                    assert_eq!(history.budget.counters.borrow().bytes, BYTES - 1);
                } else {
                    assert_eq!(history.budget.counters.borrow().work, WORK - 1);
                }
            }
            assert_eq!(
                CommitStore::new(f.ctx.state, &f.env)
                    .get(&f.genesis.author, 1)
                    .unwrap(),
                Some(f.genesis.clone())
            );
        }
        #[test]
        fn personal_history_overflow_and_integer_conversion_failures_stay_on_parent() {
            let f = fixture();
            {
                let history = probe(&f);
                assert_eq!(
                    reason(history.reserve_counts([u64::MAX, 1, 1, 1, 1, 1, 1])),
                    "team_bootstrap_limit_exceeded"
                );
                assert_eq!(reason(history.check()), "team_bootstrap_limit_exceeded");
                assert_eq!(
                    reason(history.charge(0, 0)),
                    "team_bootstrap_limit_exceeded"
                );
            }
            {
                let history = probe(&f);
                assert_eq!(
                    reason(history.reserve_writer("team/bounded-test.json", BULK + 1)),
                    "team_bootstrap_limit_exceeded"
                );
                assert_eq!(reason(history.check()), "team_bootstrap_limit_exceeded");
            }
            {
                let history = probe(&f);
                let line = format!("{{\"hlc\":\"{}-{}\"}}", "9".repeat(4000), "8".repeat(4000));
                assert!(history.parse_line(&line).is_ok());
                assert!(history.parse_line(&line).is_ok());
                assert_eq!(
                    reason(history.parse_line(&line)),
                    "team_bootstrap_limit_exceeded"
                );
                assert_eq!(reason(history.check()), "team_bootstrap_limit_exceeded");
            }
            let base = serde_json::to_string(&f.genesis.to_dict()).unwrap();
            assert_eq!(base.matches("\"seen\":{}").count(), 1);
            let seen = (b'a'..=b'e')
                .map(|letter| {
                    format!(
                        "\"{}\":{}",
                        (letter as char).to_string().repeat(26),
                        "9".repeat(4000)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            let raw = base.replacen("\"seen\":{}", &format!("\"seen\":{{{seen}}}"), 1);
            let name = format!("team/{}/commits/{}/1.json", f.env, f.genesis.author);
            f.ctx.state.write_bytes(&name, raw.as_bytes()).unwrap();
            let history = probe(&f);
            assert_eq!(reason(history.acquire()), "team_bootstrap_limit_exceeded");
            assert_eq!(reason(history.check()), "team_bootstrap_limit_exceeded");
            assert_eq!(f.ctx.state.read_bytes(&name).unwrap(), raw.as_bytes());
            assert!(
                !f.ctx
                    .state
                    .exists(&format!("team/{}/bootstrap/receipt.json", f.env))
            );
        }
        #[test]
        fn personal_history_discarded_fact_limit_cannot_quarantine_or_reset_budget() {
            let f = fixture();
            let h = probe(&f);
            let nested = h.nested(f.ctx.state, &f.env).unwrap();
            let over_depth = format!("{}0{}", "[".repeat(65), "]".repeat(65));
            assert!(nested.parse_line(&over_depth).ok().is_none());
            assert_eq!(reason(h.check()), "team_bootstrap_limit_exceeded");
            assert_eq!(reason(h.charge(0, 0)), "team_bootstrap_limit_exceeded");
            assert!(
                !f.ctx
                    .state
                    .exists(&format!("team/{}/rejected_facts.jsonl", f.env))
            );
            drop(nested);
            drop(h);
            let path = format!("team/{}/facts.jsonl", f.env);
            let stored = format!("{over_depth}\n");
            f.ctx.state.write_bytes(&path, stored.as_bytes()).unwrap();
            let h = probe(&f);
            assert_eq!(
                reason(super::super::super::sync::load_facts_with_input(
                    &f.ctx, &f.env, &h
                )),
                "team_bootstrap_limit_exceeded"
            );
            assert_eq!(
                fs::read(f.ctx.state.path.join(&path)).unwrap(),
                stored.as_bytes()
            );
            assert!(
                !f.ctx
                    .state
                    .exists(&format!("team/{}/rejected_facts.jsonl", f.env))
            );
        }
        #[test]
        fn personal_history_node_and_jsonl_bounds_preserve_raw_inputs() {
            let f = fixture();
            let mut raw = String::with_capacity(NODES as usize * 2 + 1);
            raw.push('[');
            for i in 0..NODES {
                if i != 0 {
                    raw.push(',');
                }
                raw.push('0');
            }
            raw.push(']');
            {
                let h = probe(&f);
                assert_eq!(
                    reason(h.parse(raw.as_bytes())),
                    "team_bootstrap_limit_exceeded"
                );
            }
            let name = format!("team/{}/facts.jsonl", f.env);
            let lines = "0\n".repeat(ENTRIES + 1);
            f.ctx.state.write_bytes(&name, lines.as_bytes()).unwrap();
            let h = probe(&f);
            let input = h.acquire().unwrap();
            assert_eq!(
                reason(input.read_lines(&name)),
                "team_bootstrap_limit_exceeded"
            );
            assert_eq!(
                fs::read(f.ctx.state.path.join(&name)).unwrap(),
                lines.as_bytes()
            );
        }
        #[test]
        fn personal_history_layout_aliases_types_utf8_and_oversize_refuse_without_dropping() {
            let f = fixture();
            let dir = f
                .ctx
                .state
                .path
                .join(format!("team/{}/commits/{}", f.env, f.genesis.author));
            let canonical = dir.join("1.json");
            let bytes = fs::read(&canonical).unwrap();
            for alias in [
                "01.json", "+1.json", "-1.json", "0.json", "١.json", "１.json", "².json",
            ] {
                let path = dir.join(alias);
                fs::rename(&canonical, &path).unwrap();
                {
                    let h = probe(&f);
                    assert!(h.acquire().is_err(), "alias {alias}");
                }
                assert_eq!(fs::read(&path).unwrap(), bytes);
                fs::rename(path, &canonical).unwrap();
            }
            let alias = dir.join("01.json");
            fs::copy(&canonical, &alias).unwrap();
            {
                let h = probe(&f);
                assert!(h.acquire().is_err());
            }
            fs::remove_file(alias).unwrap();
            let nonutf = dir.join(std::ffi::OsString::from_vec(vec![
                0xff, b'.', b'j', b's', b'o', b'n',
            ]));
            match fs::copy(&canonical, &nonutf) {
                Ok(_) => {
                    let h = probe(&f);
                    assert!(h.acquire().is_err());
                    drop(h);
                    fs::remove_file(&nonutf).unwrap();
                }
                #[cfg(target_os = "macos")]
                Err(error) if error.raw_os_error() == Some(92) => {
                    // APFS rejects this name before it can enter the store.
                    assert!(fs::read_dir(&dir).unwrap().all(|entry| {
                        entry.unwrap().file_name().as_os_str() != nonutf.file_name().unwrap()
                    }));
                    assert_eq!(fs::read(&canonical).unwrap(), bytes);
                    let h = probe(&f);
                    assert!(h.acquire().is_ok());
                }
                Err(error) => panic!("invalid UTF-8 fixture creation failed: {error}"),
            }
            let link = dir.join("2.json");
            symlink(&canonical, &link).unwrap();
            {
                let h = probe(&f);
                assert!(h.acquire().is_err());
            }
            fs::remove_file(&link).unwrap();
            fs::create_dir(&link).unwrap();
            fs::set_permissions(&link, fs::Permissions::from_mode(0o700)).unwrap();
            {
                let h = probe(&f);
                assert!(h.acquire().is_err());
            }
            fs::remove_dir(&link).unwrap();
            f.ctx
                .state
                .write_bytes(
                    &format!("team/{}/commits/{}/2.json", f.env, f.genesis.author),
                    b"",
                )
                .unwrap();
            let file = fs::OpenOptions::new().write(true).open(&link).unwrap();
            file.set_len(BULK + 1).unwrap();
            drop(file);
            {
                let h = probe(&f);
                assert_eq!(reason(h.acquire()), "team_bootstrap_limit_exceeded");
            }
            assert_eq!(fs::metadata(&link).unwrap().len(), BULK + 1);
            assert_eq!(fs::read(&canonical).unwrap(), bytes);
        }
        #[test]
        fn personal_history_falsy_corrupt_duplicate_and_slot_mismatch_are_not_omissions() {
            let f = fixture();
            let name = format!("team/{}/commits/{}/1.json", f.env, f.genesis.author);
            let saved = fs::read(f.ctx.state.path.join(&name)).unwrap();
            let mut duplicate = br#"{"env_id":"duplicate","#.to_vec();
            duplicate
                .extend_from_slice(&saved[saved.iter().position(|b| *b == b'{').unwrap() + 1..]);
            for raw in [
                b"null".as_slice(),
                b"false",
                b"{}",
                b"[]",
                b"0",
                b"{",
                duplicate.as_slice(),
            ] {
                f.ctx.state.write_bytes(&name, raw).unwrap();
                let h = probe(&f);
                assert!(h.acquire().is_err());
                assert_eq!(fs::read(f.ctx.state.path.join(&name)).unwrap(), raw);
            }
            f.ctx.state.write_bytes(&name, &saved).unwrap();
            let c = next(&f, 2, "1000001-0000");
            f.ctx
                .state
                .write_json(
                    &format!("team/{}/commits/{}/3.json", f.env, c.author),
                    &c.to_dict(),
                )
                .unwrap();
            assert!(probe(&f).acquire().is_err());
        }
        #[test]
        fn personal_history_floor_retains_all_originals_and_stable_numeric_ties() {
            let f = fixture();
            let two = next(&f, 2, "2000000-0000");
            let ten = next(&f, 10, "2000000-0000");
            put(&f, &ten);
            put(&f, &two);
            // Literal retained DATA fixture, not a complete-cut claim. The
            // snapshot carries the ordinary fold's actual document/order;
            // floor-covered signed originals must all remain in the input.
            let all = vec![f.genesis.clone(), two.clone(), ten.clone()];
            let folded = fold::fold(&f.env, all, None, None, None, None).unwrap();
            f.ctx.state.write_json(&format!("team/{}/snapshots/10.json",f.env),&json!({"document":folded.document,"version_order":folded.version_order,"vector":{f.genesis.author.clone():10}})).unwrap();
            let h = probe(&f);
            let input = h.acquire().unwrap();
            assert_eq!(
                input
                    .commits()
                    .unwrap()
                    .iter()
                    .map(|c| c.author_seq.clone())
                    .collect::<Vec<_>>(),
                vec![PyInt::from(1), PyInt::from(2), PyInt::from(10)]
            );
            assert_eq!(input.vector().unwrap()[&f.genesis.author], PyInt::from(10));
            // Ordinary finite acquisition is an independent legacy parity
            // check; the literal sequence assertion above remains the oracle.
            assert_eq!(
                CommitStore::new(f.ctx.state, &f.env).all_commits().unwrap(),
                input.commits().unwrap()
            );
            assert_eq!(
                input
                    .originals
                    .iter()
                    .map(|o| o.raw.clone())
                    .collect::<Vec<_>>(),
                [&f.genesis, &two, &ten]
                    .iter()
                    .map(|c| fs::read(f.ctx.state.path.join(format!(
                        "team/{}/commits/{}/{}.json",
                        f.env, c.author, c.author_seq
                    )))
                    .unwrap())
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                reason(input.replication_after(&BTreeMap::new())),
                "team_checkpoint_history_required"
            );
            assert!(
                input
                    .replication_after(&BTreeMap::from([(
                        f.genesis.author.clone(),
                        PyInt::from(10)
                    )]))
                    .unwrap()
                    .is_empty()
            );
        }
        #[test]
        fn personal_history_bad_signature_unknown_author_and_full_record_conflict_preserve_evidence()
         {
            let f = fixture();
            let mut forged = next(&f, 2, "1000001-0000");
            forged.sig = pybase64::b64encode(&[0; 64]);
            put(&f, &forged);
            let path = f
                .ctx
                .state
                .path
                .join(format!("team/{}/commits/{}/2.json", f.env, forged.author));
            let saved = fs::read(&path).unwrap();
            assert!(probe(&f).acquire().is_err());
            assert_eq!(fs::read(&path).unwrap(), saved);
            fs::remove_file(&path).unwrap();
            let stranger = DeviceKey::generate();
            let unknown = sign_commit(
                &stranger,
                &f.env,
                1,
                "1000001-0000",
                &BTreeMap::new(),
                vec![json!({"op":"settings.update","sync_interval_seconds":7})],
            )
            .unwrap();
            put(&f, &unknown);
            let unknown_path = f
                .ctx
                .state
                .path
                .join(format!("team/{}/commits/{}/1.json", f.env, unknown.author));
            let saved = fs::read(&unknown_path).unwrap();
            assert!(probe(&f).acquire().is_err());
            assert_eq!(fs::read(&unknown_path).unwrap(), saved);
            fs::remove_file(unknown_path).unwrap();
            let original = f.key.record().unwrap();
            let agree = DeviceKey::generate().record().unwrap().agree_pub;
            let mut message = crate::team::identity::DEVICE_RECORD_CONTEXT.to_vec();
            message.extend_from_slice(&agree);
            let conflicting =
                DeviceRecord::new(&original.sign_pub, &agree, &f.key.sign(&message).unwrap())
                    .unwrap();
            assert!(conflicting.verify_uncached());
            assert_eq!(conflicting.fingerprint(), original.fingerprint());
            assert_ne!(conflicting, original);
            let announcement=sign_commit(&f.key,&f.env,2,"1000001-0000",&BTreeMap::new(),vec![json!({"op":"member.add","device":conflicting.to_dict(),"name":"synthetic-conflicting-record","role":"admin","wraps":{}})]).unwrap();
            put(&f, &announcement);
            let saved = fs::read(&path).unwrap();
            assert!(probe(&f).acquire().is_err());
            assert_eq!(fs::read(path).unwrap(), saved);
        }

        #[test]
        fn personal_history_sealed_vector_rejects_raw_receipt_generation_and_wrong_parent() {
            let f = fixture();
            let other = fixture();
            let h = probe(&f);
            let input = h.acquire().unwrap();
            let seal = input.fact_seal().unwrap();
            assert_eq!(
                seal.current_vector(&h).unwrap()[&f.genesis.author],
                PyInt::from(1)
            );
            f.ctx
                .state
                .write_json(
                    &format!("team/{}/fact_admissions.json", f.env),
                    &json!({"changed":"original-data"}),
                )
                .unwrap();
            assert_eq!(
                reason(seal.current_vector(&h)),
                "team_bootstrap_local_state_changed"
            );
            let fresh = h.acquire().unwrap().fact_seal().unwrap();
            h.invalidate().unwrap();
            assert_eq!(
                reason(fresh.current_vector(&h)),
                "team_bootstrap_local_state_changed"
            );
            let fresh = h.acquire().unwrap().fact_seal().unwrap();
            let wrong = probe(&other);
            assert_eq!(
                reason(fresh.current_vector(&wrong)),
                "team_bootstrap_local_state_changed"
            );
            assert!(h.charge(WORK, 0).is_err());
            assert_eq!(
                reason(fresh.current_vector(&h)),
                "team_bootstrap_limit_exceeded"
            );
        }
        #[test]
        fn personal_history_same_thread_full_revision_and_wrong_bindings() {
            let f = fixture();
            let h = probe(&f);
            let old = h.acquire().unwrap();
            let c = next(&f, 2, "1000001-0000");
            put(&f, &c);
            assert_eq!(reason(old.commits()), "team_bootstrap_local_state_changed");
            let fresh = h.acquire().unwrap();
            assert_eq!(fresh.vector().unwrap()[&c.author], PyInt::from(2));
            let raw = fs::read(
                f.ctx
                    .state
                    .path
                    .join(format!("team/{}/commits/{}/2.json", f.env, c.author)),
            )
            .unwrap();
            f.ctx
                .state
                .write_bytes(&format!("team/{}/commits/{}/2.json", f.env, c.author), &raw)
                .unwrap();
            assert_eq!(
                reason(fresh.recheck()),
                "team_bootstrap_local_state_changed"
            );
            let fresh = h.acquire().unwrap();
            f.ctx
                .state
                .write_json(
                    &format!("team/{}/fact_admissions.json", f.env),
                    &json!({"synthetic-forged-receipt":"invalid-signature"}),
                )
                .unwrap();
            assert_eq!(
                reason(fresh.recheck()),
                "team_bootstrap_local_state_changed"
            );
            let same_path = StateDir::new(&f.ctx.state.path);
            assert_eq!(
                reason(h.nested(&same_path, &f.env)),
                "team_bootstrap_local_state_changed"
            );
            let other = new_env_id(&f.genesis.author).unwrap();
            assert_eq!(
                reason(h.nested(f.ctx.state, &other)),
                "team_bootstrap_local_state_changed"
            );
            let custom = CommitStore {
                state: f.ctx.state,
                env_id: f.env.clone(),
                root: format!("team/{}/other", f.env),
            };
            assert_eq!(
                reason(receive_with_input(&custom, &c, 1_000_002, None, true, &h)),
                "team_bootstrap_local_state_changed"
            );
        }
        #[test]
        fn personal_history_same_thread_revision_stage_regression() {
            fn stage_reason<T>(stage: &str, result: Result<T>) -> String {
                match result {
                    Ok(_) => panic!("expected refusal at {stage}"),
                    Err(error) => error.reason.into_owned(),
                }
            }
            for _ in 0..32 {
            let f = fixture();
            let h = probe(&f);
            let old = h.acquire().unwrap();
            let c = next(&f, 2, "1000001-0000");
            put(&f, &c);
            assert_eq!(stage_reason("old_input_after_append", old.commits()), "team_bootstrap_local_state_changed");
            let fresh = h.acquire().unwrap();
            assert_eq!(fresh.vector().unwrap()[&c.author], PyInt::from(2));
            let raw = fs::read(
                f.ctx
                    .state
                    .path
                    .join(format!("team/{}/commits/{}/2.json", f.env, c.author)),
            )
            .unwrap();
            f.ctx
                .state
                .write_bytes(&format!("team/{}/commits/{}/2.json", f.env, c.author), &raw)
                .unwrap();
            let replacement = fresh.recheck();
            if replacement.is_ok() {
                let before = fresh.inventory.as_ref().unwrap();
                let after = h.collect().unwrap();
                let changed_stamps = before.stamps.iter().filter(|(name, stamp)| after.stamps.get(*name) != Some(*stamp)).count();
                eprintln!("PVBOOT_REVISION_UNEXPECTED_ACCEPT {}", json!({"same_raw_rewrite":true,"changed_stamps":changed_stamps,"root_same":before.root==after.root,"full_revision_same":before.revision==after.revision}));
            }
            assert_eq!(
                stage_reason("same_bytes_atomic_replacement", replacement),
                "team_bootstrap_local_state_changed"
            );
            let fresh = h.acquire().unwrap();
            f.ctx
                .state
                .write_json(
                    &format!("team/{}/fact_admissions.json", f.env),
                    &json!({"synthetic-forged-receipt":"invalid-signature"}),
                )
                .unwrap();
            assert_eq!(
                stage_reason("fact_admission_write", fresh.recheck()),
                "team_bootstrap_local_state_changed"
            );
            let same_path = StateDir::new(&f.ctx.state.path);
            assert_eq!(
                stage_reason("different_state_object", h.nested(&same_path, &f.env)),
                "team_bootstrap_local_state_changed"
            );
            let other = new_env_id(&f.genesis.author).unwrap();
            assert_eq!(
                stage_reason("different_env", h.nested(f.ctx.state, &other)),
                "team_bootstrap_local_state_changed"
            );
            let custom = CommitStore {
                state: f.ctx.state,
                env_id: f.env.clone(),
                root: format!("team/{}/other", f.env),
            };
            assert_eq!(
                stage_reason("different_store_root", receive_with_input(&custom, &c, 1_000_002, None, true, &h)),
                "team_bootstrap_local_state_changed"
            );
            }
        }
        #[test]
        fn personal_history_global_discovery_counts_mapping_union_before_walkers() {
            let f = fixture();
            let owner = f.genesis.author.clone();
            let mut mapping = Map::new();
            for n in 0..256 {
                mapping.insert(
                    format!("{owner}-{n:032x}"),
                    json!({"project":"synthetic","environment":"unit"}),
                );
            }
            f.ctx
                .state
                .write_json(
                    super::super::super::sync::ENVS_MAP_PATH,
                    &Value::Object(mapping),
                )
                .unwrap();
            assert_eq!(reason(probe(&f).acquire()), "team_bootstrap_limit_exceeded");
            assert!(
                f.ctx
                    .state
                    .path
                    .join(format!("team/{}/commits/{}/1.json", f.env, owner))
                    .is_file()
            );
        }
        #[test]
        fn personal_history_deadline_is_shared_through_resume_and_blocks_publication_guard() {
            let f = fixture();
            let h = probe(&f);
            let started = h.budget.began;
            let resume = h.into_resume().unwrap();
            let remaining = Duration::from_secs(5).saturating_sub(started.elapsed());
            std::thread::sleep(remaining + Duration::from_millis(10));
            assert_eq!(reason(resume.resume()), "team_bootstrap_timeout");
            assert!(
                !f.ctx
                    .state
                    .exists(&format!("team/{}/bootstrap/receipt.json", f.env))
            );
        }
        #[test]
        fn personal_history_writer_child() {
            let Some(root) = std::env::var_os("PVBOOT_HISTORY_TEST_WRITER_ROOT") else {
                return;
            };
            use std::io::Write;
            // libtest may print its test-name prefix without a newline.
            println!("\nPVBOOT_HISTORY_WRITER_WAITING");
            std::io::stdout().flush().unwrap();
            let state = StateDir::new(std::path::PathBuf::from(root));
            let _lock = state.lock().unwrap();
            state
                .write_json(
                    "team/history-independent-writer.json",
                    &json!({"written":true}),
                )
                .unwrap();
        }
        #[test]
        fn personal_history_actual_lock_serializes_independent_process_writer() {
            use std::{
                io::{BufRead, BufReader},
                process::{Child, Command, Stdio},
                time::Instant,
            };
            struct OwnedChild(Child);
            impl Drop for OwnedChild {
                fn drop(&mut self) {
                    if self.0.try_wait().ok().flatten().is_none() {
                        let _ = self.0.kill();
                    }
                    let _ = self.0.wait();
                }
            }
            let f = fixture();
            let h = probe(&f);
            let input = h.acquire().unwrap();
            let selector =
                "team::commit::retained_history::boundary_tests::personal_history_writer_child";
            let mut child = OwnedChild(
                Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", selector, "--nocapture"])
                    .env("PVBOOT_HISTORY_TEST_WRITER_ROOT", &f.ctx.state.path)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
            let output = child.0.stdout.take().unwrap();
            let (tx, rx) = mpsc::channel();
            let reader = std::thread::spawn(move || {
                for line in BufReader::new(output).lines() {
                    if line.unwrap() == "PVBOOT_HISTORY_WRITER_WAITING" {
                        tx.send(()).unwrap();
                    }
                }
            });
            rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(child.0.try_wait().unwrap().is_none());
            assert!(!f.ctx.state.exists("team/history-independent-writer.json"));
            input.recheck().unwrap();
            drop(input);
            drop(h);
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "owned writer did not acquire released lock"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            reader.join().unwrap();
            assert_eq!(
                f.ctx
                    .state
                    .read_json("team/history-independent-writer.json", Value::Null)
                    .unwrap()["written"],
                true
            );
        }
    }

        };
    }
    pub(super) use define;
}
