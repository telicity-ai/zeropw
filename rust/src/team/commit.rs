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
use crate::errors::{Error, Result};
use crate::policy;
use crate::projects;
use crate::pybase64;
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

/// CPython 3.12 `int(str)`'s full numeric-literal grammar (surrounding
/// `int()`-specific whitespace -- not `str.isspace()` -- an optional
/// `+`/`-` sign, then one or more decimal digits, ASCII or any Unicode `Nd`
/// code point, with single, non-leading/trailing underscores allowed
/// between them) is `crate::pystr::int_from_str_checked`, the one canonical
/// home for CPython's `int(str)` semantics (PORTING.md §3b; a former
/// private copy of this whole grammar -- including its own
/// `is_int_strip_space`, fixed independently for the identical
/// U+001C-U+001F whitespace bug `vault.rs`'s and `policy.rs`'s copies also
/// had, finding H-R2-1 -- lived here, see `rust/DEVIATIONS.md`).
///
/// The *checked* (non-saturating) variant is used deliberately, not the
/// plain saturating `int_from_str`: unlike `policy.rs`'s narrower
/// `python_int_from_str` (ASCII-digit-only, bounded to `i64`, where the
/// final `i64::try_from` narrowing step makes the saturating/checked choice
/// unobservable either way), `Hlc`/`Commit`'s `i128` fields store and
/// re-serialize the parsed magnitude itself with no further narrowing --
/// silently substituting a saturated `i128::MAX`/`MIN` sentinel for a
/// magnitude that overflows would be a *different*, worse wrong answer than
/// this port's existing, documented "reject past `i128`" gap (see
/// `rust/DEVIATIONS.md` for the residual, practically-unreachable gap
/// beyond `i128::MAX`/`MIN` that remains).
fn python_int_parse_i128(raw: &str) -> Option<i128> {
    crate::pystr::int_from_str_checked(raw)
}

/// Build a `serde_json::Value` integer from an `i128`, preserving the exact
/// decimal digits (`serde_json`'s `arbitrary_precision` feature backs
/// `Number` with the literal text, so this round-trips byte-identically
/// through `pyjson::dumps`, matching Python's arbitrary-precision `int`).
pub(super) fn json_int128(v: i128) -> Value {
    Value::Number(v.into())
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
/// `wall_ms`/`counter` are `i128`, unlike Python's arbitrary-precision
/// `int`; see `rust/DEVIATIONS.md` for the (practically unreachable, beyond
/// `i128::MAX`) bound this implies on [`Hlc::parse`]. `i128` is wide enough
/// that every value this port's own [`Hlc::tick`] ever produces, and every
/// value a reviewer's or peer's hand-crafted `hlc` string can plausibly
/// exercise, parses and compares exactly as Python's `int` would (finding
/// H-2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hlc {
    pub wall_ms: i128,
    pub counter: i128,
}

impl Hlc {
    pub fn new(wall_ms: i128, counter: i128) -> Self {
        Hlc { wall_ms, counter }
    }

    /// `Hlc.parse` (a `@staticmethod` in Python). `wall_str`/`counter_str`
    /// are parsed with [`python_int_parse_i128`], matching CPython's
    /// `int(str)` grammar (whitespace, `+`/`-` sign, `_` digit separators,
    /// Unicode decimal digits, arbitrary precision up to `i128`) rather
    /// than Rust's strict `str::parse`.
    pub fn parse(value: &str) -> Result<(i128, i128)> {
        let bad = || Error::invalid_input("hlc_malformed");
        let parts: Vec<&str> = value.split('-').collect();
        if parts.len() != 2 {
            return Err(bad());
        }
        let wall_ms = python_int_parse_i128(parts[0]).ok_or_else(bad)?;
        let counter = python_int_parse_i128(parts[1]).ok_or_else(bad)?;
        if wall_ms < 0 || counter < 0 {
            return Err(bad());
        }
        Ok((wall_ms, counter))
    }

    /// `Hlc.render`.
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
            self.counter = self.counter.max(remote_counter);
        }
        Ok(())
    }

    /// `Hlc.tick`: advance the clock for a new local commit and return its
    /// rendered `hlc`. `now_ms=None` uses the system clock, like Python's
    /// `int(time.time() * 1000)`.
    pub fn tick(&mut self, now_ms_value: Option<i64>) -> String {
        let now_ms_value = i128::from(now_ms_value.unwrap_or_else(now_ms));
        let candidate = now_ms_value.max(self.wall_ms);
        if candidate > self.wall_ms {
            self.wall_ms = candidate;
            self.counter = 0;
        } else {
            // Finding H-R3-8: Python's `int` never overflows, so
            // `self.counter += 1` there is always exact. `Hlc::parse`
            // accepts a peer-supplied `counter` up to `i128::MAX` (only
            // `wall_ms` is separately bounded, by `receive_commit`), and
            // `observe`-then-`tick` -- exactly the sequence this type's own
            // `observe` doc comment and docs/team-sync.md §5.2 prescribe for
            // every incoming commit -- can raise this clock's `counter` to
            // that peer-chosen value before a later local `tick()` (wall
            // clock not yet advanced) increments it, panicking
            // (`attempt to add with overflow`) on `i128::MAX`.
            // `saturating_add` removes the panic; the resulting bound
            // (`counter` sticks at `i128::MAX` rather than continuing to
            // climb) is recorded in `rust/DEVIATIONS.md`.
            self.counter = self.counter.saturating_add(1);
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
pub fn order_key(commit: &Commit) -> Result<(i128, i128, String)> {
    let (wall_ms, counter) = Hlc::parse(&commit.hlc)?;
    Ok((wall_ms, counter, commit.author.clone()))
}

/// Port of `sort_total_order`.
pub fn sort_total_order(commits: Vec<Commit>) -> Result<Vec<Commit>> {
    let mut keyed: Vec<((i128, i128, String), Commit)> = Vec::with_capacity(commits.len());
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
    /// `i128`, unlike Python's arbitrary-precision `int`; see
    /// `rust/DEVIATIONS.md` (finding H-6).
    pub author_seq: i128,
    pub hlc: String,
    pub seen: BTreeMap<String, i128>,
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
        m.insert("author_seq".into(), json_int128(self.author_seq));
        m.insert("hlc".into(), Value::String(self.hlc.clone()));
        let seen: Map<String, Value> = self
            .seen
            .iter()
            .map(|(k, v)| (k.clone(), json_int128(*v)))
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
        let str_field =
            |key: &str| -> Result<String> { obj.get(key).map(python_str_coerce).ok_or_else(bad) };
        let format = str_field("format")?;
        let env_id = str_field("env_id")?;
        let author = str_field("author")?;
        let author_seq = obj
            .get("author_seq")
            .and_then(python_int_coerce)
            .ok_or_else(bad)?;
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
                let mut out = BTreeMap::new();
                for (k, v) in pairs {
                    let key = python_str_coerce(&k);
                    let n = python_int_coerce(&v).ok_or_else(bad)?;
                    out.insert(key, n);
                }
                out
            }
        };
        // `tuple(dict(op) for op in data["ops"])`: each element of `ops`
        // goes through `dict(op)`, which accepts a mapping directly OR any
        // iterable of two-element pairs (e.g. an on-disk op reshaped as
        // `[["op", "settings.update"], ["sync_interval_seconds", 1]]`) --
        // the same normalisation `seen` already gets, via
        // [`python_dict_pairs`], rather than requiring every element
        // already be a literal JSON object (finding H-R2-5).
        //
        // Finding H-R3-3 (correcting H-R2-5's own reasoning): a pair whose
        // key is not a JSON string, e.g.
        // `[["op", "settings.update"], [1, "x"]]`, is NOT actually inert in
        // Python just because no op handler looks it up by name --
        // `dict()` keeps the `1` key exactly like any other, and
        // `Commit.canonical_json`'s `json.dumps(..., sort_keys=True)` (the
        // exact bytes that get signed/hashed) recurses into `ops` and, to
        // sort THIS op's dict keys, compares `1 < "op"` -- an uncaught
        // `TypeError: '<' not supported between instances of 'int' and
        // 'str'` that propagates out of `canonical_json`, `hash`,
        // `sign_commit` and `receive_commit` entirely. A commit whose `ops`
        // holds such an entry can therefore never actually be signed,
        // hashed, or accepted by any real Python caller -- the previous
        // round's "drop the bad-keyed pair and keep the rest of the op"
        // fix was itself wrong: it made this port ACCEPT and FOLD a signed
        // commit Python can never even construct, let alone verify. Reject
        // the whole commit as malformed here instead, matching "every real
        // caller's canonicalization step raises" (PORTING.md §3.5; see
        // `rust/DEVIATIONS.md`).
        let ops: Vec<Value> = obj
            .get("ops")
            .and_then(Value::as_array)
            .ok_or_else(bad)?
            .iter()
            .map(|op| {
                let pairs = python_dict_pairs(op).ok_or_else(bad)?;
                let mut out = Map::new();
                for (k, v) in pairs {
                    match k {
                        Value::String(s) => {
                            out.insert(s, v);
                        }
                        _ => return Err(bad()),
                    }
                }
                Ok(Value::Object(out))
            })
            .collect::<Result<_>>()?;
        let sig = str_field("sig")?;
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

/// Python `int(x)` for a parsed JSON value (bool/int/float-truncating/
/// numeric-string), used by [`Commit::from_dict`] for `author_seq`/`seen`
/// values -- a `Value::String` goes through [`python_int_parse_i128`], so
/// this accepts CPython's full `int(str)` grammar (whitespace, `+`/`-`
/// sign, `_` separators, Unicode decimal digits) and any magnitude up to
/// `i128`, not just plain ASCII digits bounded to `i64` (finding H-2/H-6).
/// A wider duplicate of `handles.rs`'s/`policy.rs`'s private
/// `python_int_coerce` (not reachable from here, and narrower: those stay
/// `i64`/ASCII-only) -- the residual gap beyond `i128` is recorded in
/// `rust/DEVIATIONS.md`.
fn python_int_coerce(value: &Value) -> Option<i128> {
    match value {
        Value::Bool(b) => Some(i128::from(*b)),
        Value::Number(n) => {
            if pyjson::is_float_literal(n.as_str()) {
                let f: f64 = n.as_str().parse().ok()?;
                if !f.is_finite() {
                    return None;
                }
                let truncated = f.trunc();
                if truncated > i128::MAX as f64 || truncated < i128::MIN as f64 {
                    return None;
                }
                Some(truncated as i128)
            } else {
                // Beyond `i128` but still integer-shaped: `None` (see
                // `rust/DEVIATIONS.md`).
                n.as_str().parse::<i128>().ok()
            }
        }
        Value::String(s) => python_int_parse_i128(s),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

/// `str(k)` for a JSON value used as a `seen`-pair key (finding H-6): a
/// string is used as-is; the other JSON scalars use CPython's `str()` text.
/// A list/dict key is vanishingly unlikely to appear in a real `seen` pair
/// (there is no writer that could produce one merely by mis-shaping
/// `seen`), so it falls back to `pyjson`'s compact JSON form rather than
/// CPython's `repr`-style container text -- a difference only observable
/// for that unreachable shape (e.g. a Python `str` container containing a
/// quote or backslash would `repr()` differently than `pyjson` renders it;
/// the base64-alphabet-preserving case `identity.rs`'s `DeviceRecord::
/// from_dict` needs, finding H-R4-1, is unaffected either way since every
/// non-base64-alphabet character -- quotes, brackets, whichever style --
/// is discarded identically by the lenient decoder).
///
/// Exposed crate-wide (not just within this module) because
/// `identity.rs`'s `DeviceRecord::from_dict` needs the identical `str(...)`
/// coercion Python applies to `sign_pub`/`agree_pub`/`sig` before its own
/// lenient base64 decode (finding H-R4-1); per PORTING.md §3b this is the
/// one canonical place for that coercion, reused rather than copied.
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
        Value::Array(_) | Value::Object(_) => {
            pyjson::dumps(value, DumpOptions::compact_sorted()).unwrap_or_default()
        }
    }
}

/// `dict(x)` for the shapes actually reachable through a signed commit's
/// `seen` field (finding H-6): a JSON object (used directly, matching
/// Python's `dict(mapping)`), or a JSON array of two-element arrays
/// (matching Python's `dict(iterable_of_pairs)`, e.g. `[["<fp>", 3]]`).
/// Python's `dict()` also accepts an iterable of *any* two-element
/// sequence, including a two-character string (`dict(["ab"]) ==
/// {"a": "b"}`) -- included here too since it costs nothing extra. Anything
/// else that is not iterable at all in Python (`dict(5)`) raises `TypeError`
/// (uncaught, `commit_malformed` per PORTING.md §3.5), returning `None`.
fn python_dict_pairs(value: &Value) -> Option<Vec<(Value, Value)>> {
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
                    _ => return None,
                }
            }
            Some(out)
        }
        _ => None,
    }
}

/// `zeropw.team.commit.sign_commit`: build, format-validate and sign a new
/// commit (docs/team-sync.md section 5.2).
pub fn sign_commit(
    device: &DeviceKey,
    env_id: &str,
    author_seq: i128,
    hlc: &str,
    seen: &BTreeMap<String, i128>,
    ops: Vec<Value>,
) -> Result<Commit> {
    validate_ops(&ops)?;
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
/// case (finding H-4).
fn http_auth_value(a: &policy::HttpAuth, raw_value_prefix: &Value) -> Value {
    json!({"mode": a.mode, "header_name": a.header_name, "value_prefix": raw_value_prefix,
          "basic_username": a.basic_username})
}
fn http_scope_value(s: &policy::HttpScope) -> Value {
    json!({"methods": s.methods, "path_prefixes": s.path_prefixes, "confirm_methods": s.confirm_methods})
}
fn ssh_target_value(t: &policy::SshTarget) -> Value {
    json!({"host": t.host, "port": t.port, "username": t.username, "host_keys": t.host_keys})
}
fn cli_profile_value(c: &policy::CliProfile) -> Value {
    json!({"program": c.program, "kind": c.kind, "base_url_env": c.base_url_env, "extra_env": c.extra_env})
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
    Ok(Some(policy::HttpAuth::new(
        mode,
        opt_string(obj.get("header_name")),
        opt_string(obj.get("value_prefix")),
        opt_string(obj.get("basic_username")),
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
    Ok(Some(policy::HttpScope::new(
        methods,
        path_prefixes,
        confirm_methods,
    )?))
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
        Some(v) => python_dict_pairs(v).ok_or_else(bad)?,
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
        match merged.iter_mut().find(|(ek, _)| *ek == k) {
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
    // `"\x00" in self.program`; only a TRUTHY non-string `program` reaches
    // that `in` check, an uncaught `TypeError` for a non-iterable value
    // that resolves to `invalid_cli_profile` -- reached here only now that
    // `kind` is already confirmed valid, matching Python's order (finding
    // H-R2-8's reason merge is corrected: the two Python outcomes are
    // different reasons, not one).
    let program = if json_falsy(&program_raw) {
        String::new() // placeholder; the emptiness check below raises the documented reason
    } else {
        match program_raw.as_str() {
            Some(s) => s.to_string(),
            None => return Err(bad()),
        }
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
    let raw_value_prefix = args
        .get("http_auth")
        .and_then(Value::as_object)
        .and_then(|o| o.get("value_prefix"))
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
            .map(|a| http_auth_value(a, &raw_value_prefix))
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
    out.insert(
        "cli".into(),
        cli.as_ref().map(cli_profile_value).unwrap_or(Value::Null),
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

    fn commit_path(&self, fingerprint: &str, seq: i128) -> String {
        format!("{}/commits/{}/{}.json", self.root, fingerprint, seq)
    }

    fn dir(&self, suffix: &str) -> PathBuf {
        self.state.path.join(&self.root).join(suffix)
    }

    /// The vector of the newest snapshot on disk, or `{}` if there is none
    /// (section 7.3). Port of `CommitStore._snapshot_floor`.
    ///
    /// Finding H-R2-6: Python's `{str(k): int(v) for k, v in vector.items()
    /// if isinstance(v, int) and not isinstance(v, bool)}` keeps an
    /// arbitrary-precision `int` verbatim; this used to parse each entry
    /// with `Number::as_i64`, silently DROPPING (not clamping) any entry
    /// outside `i64` -- so a snapshot vector holding `10**30` for some
    /// author disappeared from the map entirely instead of being retained
    /// as a (large but real) floor, letting a replayed `author_seq=1`
    /// commit from that author be re-accepted (`append`'s duplicate check
    /// compared against a floor of `0`, not `10**30`). Widened to `i128` --
    /// the same bound `Commit::author_seq` itself uses (see
    /// `rust/DEVIATIONS.md`), not full arbitrary precision.
    fn snapshot_floor(&self) -> Result<BTreeMap<String, i128>> {
        let directory = self.dir("snapshots");
        if !directory.is_dir() {
            return Ok(BTreeMap::new());
        }
        let mut numbers: Vec<i128> = digit_stems(&directory)?;
        if numbers.is_empty() {
            return Ok(BTreeMap::new());
        }
        numbers.sort_unstable_by(|a, b| b.cmp(a));
        let top = numbers[0];
        let data = self.state.read_json(
            &format!("{}/snapshots/{}.json", self.root, top),
            Value::Null,
        )?;
        let mut result = BTreeMap::new();
        if let Some(vector) = data
            .as_object()
            .and_then(|o| o.get("vector"))
            .and_then(Value::as_object)
        {
            for (k, v) in vector {
                if let Value::Number(n) = v
                    && !pyjson::is_float_literal(n.as_str())
                    && let Some(i) = n.as_i128()
                {
                    result.insert(k.clone(), i);
                }
            }
        }
        Ok(result)
    }

    /// Version vector: fingerprint -> highest `author_seq` stored (section
    /// 6.3). Port of `CommitStore.vector`.
    pub fn vector(&self) -> Result<BTreeMap<String, i128>> {
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
            let seqs: Vec<i128> = digit_stems(&device_dir)?;
            if let Some(&max_seq) = seqs.iter().max() {
                let entry = result.entry(name).or_insert(0);
                *entry = (*entry).max(max_seq);
            }
        }
        Ok(result)
    }

    pub fn last_seq(&self, fingerprint: &str) -> Result<i128> {
        Ok(*self.vector()?.get(fingerprint).unwrap_or(&0))
    }

    /// Store a commit, enforcing contiguous per-author sequence (no gaps,
    /// no duplicates). Port of `CommitStore.append`.
    pub fn append(&self, commit: &Commit) -> Result<()> {
        if commit.env_id != self.env_id {
            return Err(Error::invalid_input("team_env_id_mismatch"));
        }
        let last = self.last_seq(&commit.author)?;
        if commit.author_seq <= last {
            return Err(Error::invalid_input("team_seq_duplicate"));
        }
        // `saturating_add`: `last` can only reach `i128::MAX` via a
        // hand-crafted snapshot floor claiming that exact value, in which
        // case no real `commit.author_seq` (itself bounded to `i128`) can
        // ever be `> last`, so this arm is never taken there anyway --
        // avoids a theoretical overflow panic on untrusted snapshot data
        // rather than relying on that reachability argument alone.
        if commit.author_seq > last.saturating_add(1) {
            return Err(Error::invalid_input("team_seq_gap"));
        }
        // `commit.author_seq` is proven `== last + 1` by the two checks
        // above.
        self.state.write_json(
            &self.commit_path(&commit.author, last + 1),
            &commit.to_dict(),
        )?;
        Ok(())
    }

    pub fn get(&self, fingerprint: &str, seq: i128) -> Result<Option<Commit>> {
        let data = self
            .state
            .read_json(&self.commit_path(fingerprint, seq), Value::Null)?;
        if json_falsy(&data) {
            return Ok(None);
        }
        Ok(Some(Commit::from_dict(&data)?))
    }

    pub fn all_commits(&self) -> Result<Vec<Commit>> {
        let mut commits = Vec::new();
        for (fingerprint, last) in self.vector()? {
            // `last` only exceeds the count of real on-disk files through a
            // hand-crafted/bit-rotted snapshot (`rust/DEVIATIONS.md`'s
            // `fold`/`validate_document_shape` row makes the same
            // reachability argument for a malformed `base_document`):
            // `append()`'s contiguity check means a real environment's
            // on-disk sequence numbers are always a gap-free `1..=last`
            // run. Python's own `for seq in range(1, last + 1): self.get(...)`
            // would iterate exactly as far for the same pathological input
            // (a `10**30` floor is as impractical to loop over in Python as
            // in Rust) -- this is not a new Rust/Python divergence, just
            // inherited from the prototype's own design.
            let mut seq: i128 = 1;
            while seq <= last {
                if let Some(commit) = self.get(&fingerprint, seq)? {
                    commits.push(commit);
                }
                seq += 1;
            }
        }
        sort_total_order(commits)
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

    /// Move every deferred commit whose wall clock is no longer too far
    /// ahead into the store. Port of `CommitStore.release_deferred`.
    pub fn release_deferred(&self, now_ms_value: i64) -> Result<Vec<Commit>> {
        let mut released = Vec::new();
        for commit in self.deferred_commits()? {
            let (wall_ms, _) = Hlc::parse(&commit.hlc)?;
            if wall_ms > i128::from(now_ms_value) + i128::from(MAX_CLOCK_SKEW_MS) {
                continue;
            }
            let path = self.deferred_path(&commit);
            if self.append(&commit).is_err() {
                continue; // still out of sequence; leave it deferred
            }
            let target = self.state.path.join(&path);
            let _ = std::fs::remove_file(&target);
            released.push(commit);
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
/// Finding H-R3-9: Python's `str.isdigit()` (the filter) and `int(str)`
/// (the conversion) are NOT the same grammar -- `isdigit()` is strictly
/// WIDER (see [`UNICODE_DIGIT_NOT_DECIMAL`]). The previous version filtered
/// on `stem.bytes().all(|b| b.is_ascii_digit())`, narrower than Python's
/// `isdigit()` in the OTHER direction (ASCII-only), so:
///  - a stem like `"٣.json"` (U+0663, an `Nd` digit `int()` DOES accept)
///    was silently IGNORED here (`vector()`/`snapshot_floor` missing that
///    entry entirely) where Python reads it as `3` -- letting a REPLAYED
///    commit/snapshot floor Python would refuse (`team_seq_duplicate`) be
///    silently re-accepted by this port instead;
///  - a stem like `"².json"` (`isdigit()` true, `int()` raises
///    `ValueError`) was ALSO silently ignored here, but Python's own
///    `[int(p.stem) ...]` list comprehension raises that `ValueError`
///    UNCAUGHT, aborting `_snapshot_floor`/`CommitStore.vector` entirely --
///    a genuine accept/crash divergence, not just a missed entry.
///
/// Fixed to match `isdigit()` exactly ([`python_stem_isdigit`]) for the
/// filter, then fail closed (`state_corrupt`, PORTING.md §3.5) for a stem
/// that passes `isdigit()` but hits a non-decimal digit (mirroring Python's
/// uncaught `ValueError`) or overflows `i128` (this crate's own bound on
/// every other `author_seq`/snapshot-number field, `rust/DEVIATIONS.md`)
/// rather than silently dropping either case as if the filename had never
/// matched `isdigit()` at all.
pub(super) fn digit_stems(directory: &std::path::Path) -> Result<Vec<i128>> {
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
        let mut value: i128 = 0;
        for c in stem.chars() {
            let digit = crate::pystr::unicode_decimal_digit(c).ok_or_else(corrupt)?;
            value = value
                .checked_mul(10)
                .and_then(|v| v.checked_add(digit as i128))
                .ok_or_else(corrupt)?;
        }
        out.push(value);
    }
    Ok(out)
}

// ------------------------------------------------------------- receipt pipeline
/// Every device record announced so far, keyed by fingerprint (for
/// signature checks only). Port of `_device_registry`.
fn device_registry(commits: &[Commit]) -> std::collections::HashMap<String, DeviceRecord> {
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

/// `zeropw.team.commit.receive_commit`: validate and store one incoming
/// commit (docs/team-sync.md section 5.4). Returns one of `"accepted"`,
/// `"deferred"`, `"duplicate"` or `"rejected"`.
pub fn receive_commit(
    store: &CommitStore,
    commit: &Commit,
    now_ms_value: i64,
    audit: Option<&Audit>,
) -> Result<&'static str> {
    let reject = |reason: &str| -> Result<&'static str> {
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
        Ok("rejected")
    };

    if commit.format != COMMIT_FORMAT {
        return reject("team_format_unknown");
    }
    if commit.env_id != store.env_id {
        return reject("team_env_id_mismatch");
    }
    if let Err(exc) = validate_ops(&commit.ops) {
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

    let existing = store.all_commits()?;
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
        None => return reject("team_author_unknown"),
    };
    if !verify_commit(commit, record) {
        return reject("team_signature_invalid");
    }

    let last_seq = store.last_seq(&commit.author)?;
    if commit.author_seq <= last_seq {
        let previously_stored = store.get(&commit.author, commit.author_seq)?;
        if let Some(prev) = &previously_stored
            && prev.hash()? == commit.hash()?
        {
            return Ok("duplicate");
        }
        return reject("team_author_equivocation");
    }

    if commit.author_seq > 1 {
        // `commit.author_seq - 1` cannot underflow: the branch above already
        // proved `commit.author_seq > last_seq >= 0`, and this `if` proves
        // `commit.author_seq > 1`, so `commit.author_seq - 1 >= 1`.
        let previous = store.get(&commit.author, commit.author_seq - 1)?;
        if let Some(previous) = previous
            && Hlc::parse(&commit.hlc)? <= Hlc::parse(&previous.hlc)?
        {
            return reject("team_hlc_not_monotone");
        }
    }

    let (wall_ms, _) = Hlc::parse(&commit.hlc)?;
    if wall_ms > i128::from(now_ms_value) + i128::from(MAX_CLOCK_SKEW_MS) {
        store.defer(commit)?;
        return Ok("deferred");
    }

    if let Err(exc) = store.append(commit) {
        return reject(&exc.reason);
    }
    Ok("accepted")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::StateDir;
    use crate::team::identity::DeviceKey;
    use tempfile::TempDir;

    const ENV_ID: &str = "env-0123456789abcdef";

    /// A valid single-quoted Python string literal for `s`, escaping every
    /// character via Python's own `\xNN`/`\uNNNN`/`\UNNNNNNNN` string syntax
    /// (never a raw byte) so a control character or line-separator-like
    /// codepoint can never be misread by Python's tokenizer as ending the
    /// literal early, and never via Rust's `{:?}` debug format, which emits
    /// `\u{NN}` -- not valid Python syntax.
    fn py_str_literal(s: &str) -> String {
        let mut out = String::from("'");
        for c in s.chars() {
            let cp = c as u32;
            match c {
                '\\' => out.push_str("\\\\"),
                '\'' => out.push_str("\\'"),
                _ if cp < 0x20 || cp == 0x7f => out.push_str(&format!("\\x{cp:02x}")),
                _ if cp > 0x7e && cp <= 0xffff => out.push_str(&format!("\\u{cp:04x}")),
                _ if cp > 0xffff => out.push_str(&format!("\\U{cp:08x}")),
                _ => out.push(c),
            }
        }
        out.push('\'');
        out
    }

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

    /// Finding H-R3-8: `Hlc::tick`'s `self.counter += 1` PANICKED
    /// (`attempt to add with overflow`) once `counter == i128::MAX` --
    /// reachable via `observe(remote_hlc)` (raising this clock's own
    /// `counter` to a peer-chosen value up to `i128::MAX`, which
    /// `Hlc::parse` accepts) followed by a local `tick()` whose wall clock
    /// has not advanced past `remote_hlc`'s -- exactly the sequence this
    /// type's own `observe` doc comment and docs/team-sync.md §5.2
    /// prescribe for every incoming commit. Must saturate, not panic.
    #[test]
    fn tick_saturates_instead_of_panicking_at_i128_max_counter() {
        let mut hlc = Hlc::new(1000, i128::MAX);
        let remote = format!("1000-{}", i128::MAX);
        hlc.observe(&remote).unwrap();
        assert_eq!(hlc.counter, i128::MAX);
        let rendered = hlc.tick(Some(500)); // wall clock does not advance
        assert_eq!(hlc.counter, i128::MAX, "must saturate, not wrap or panic");
        assert_eq!(rendered, format!("1000-{}", i128::MAX));
    }

    #[test]
    fn observe_raises_clock_and_causal_tick_sorts_after() {
        let mut hlc = Hlc::default();
        let remote = "5000-0003";
        hlc.observe(remote).unwrap();
        let nxt = hlc.tick(Some(1000));
        assert_eq!(Hlc::parse(&nxt).unwrap(), (5000, 4));
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
    /// isn't a JSON string (`[["op", "settings.update"], [1, "x"]]`) must
    /// be rejected as `commit_malformed`, not silently accepted with the
    /// `1` key dropped -- see `rust/tests/team_oracle.rs`'s
    /// `commit_ops_element_with_non_string_pair_key_is_pythons_uncaught_typeerror`
    /// for the full cross-language pin (Python's `canonical_json` raises an
    /// uncaught `TypeError` for this exact shape).
    #[test]
    fn from_dict_rejects_ops_pair_with_non_string_key() {
        let data = json!({
            "format": COMMIT_FORMAT, "env_id": ENV_ID, "author": "a", "author_seq": 1,
            "hlc": "1000-0000", "seen": {}, "sig": "",
            "ops": [[["op", "settings.update"], [1, "x"]]],
        });
        let err = Commit::from_dict(&data)
            .expect_err("a non-string pair key must reject the whole commit");
        assert_eq!(err.reason, "commit_malformed");
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
        assert_eq!(vector.get(&f.owner.fingerprint().unwrap()), Some(&2));
        let seqs: Vec<i128> = store
            .all_commits()
            .unwrap()
            .iter()
            .map(|c| c.author_seq)
            .collect();
        assert_eq!(seqs, vec![1, 2]);
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
            Some(&1)
        );
        assert_eq!(store.release_deferred(1_000_000).unwrap(), vec![]);
        let released = store.release_deferred(far_future_ms).unwrap();
        assert_eq!(
            released
                .iter()
                .map(|c| c.hash().unwrap())
                .collect::<Vec<_>>(),
            vec![skewed.hash().unwrap()]
        );
        assert_eq!(
            store.vector().unwrap().get(&f.owner.fingerprint().unwrap()),
            Some(&2)
        );
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
            Some(&1)
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
            Some(&2)
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
    // Round-2 equivalence-review fixes. `python_int_parse_i128` no longer has
    // any hand/generated-table logic of its own to pin here (PORTING.md §3b,
    // finding E-R6-1 round 6: it now delegates entirely to
    // `crate::pystr::int_from_str_checked`, whose own full-enumeration oracle
    // tests live in `pystr.rs`), but this end-to-end probe through
    // `python_int_parse_i128` itself is kept as a regression pin for this
    // call site.

    /// Finding H-R2-1: CPython 3.12's `int(str)` strips only 25 of
    /// `str.isspace()`'s 29 code points -- U+001C..U+001F
    /// (`Bidi_Class=B`) are `isspace()`-true but rejected by `int()`.
    /// Enumerates every `str.isspace()` code point (`crate::pystr::is_space`,
    /// itself already oracle-proven against `python3.12` in `pystr.rs`) and
    /// checks [`python_int_parse_i128`]'s accept/reject decision, in both
    /// leading and trailing position, against real `python3.12` `int()`.
    #[test]
    fn int_strip_space_matches_python_over_every_isspace_codepoint() {
        let isspace_codepoints: Vec<u32> = (0..=0x10FFFFu32)
            .filter(|&cp| {
                char::from_u32(cp)
                    .map(crate::pystr::is_space)
                    .unwrap_or(false)
            })
            .collect();
        // Sanity: matches the finding's own count (25 accepted + 4 rejected).
        assert_eq!(
            isspace_codepoints.len(),
            29,
            "str.isspace() should have exactly 29 code points"
        );

        let mut probes: Vec<(String, bool)> = Vec::new(); // (numeral string, leading?)
        for &cp in &isspace_codepoints {
            let c = char::from_u32(cp).unwrap();
            probes.push((format!("{c}1000"), true));
            probes.push((format!("1000{c}"), false));
        }

        // One python3.12 subprocess for the whole table, not one per probe.
        // Every character is escaped via Python's own `\xNN`/`\uNNNN` string
        // syntax (not Rust's `{:?}`, which emits `\u{NN}` -- invalid Python,
        // and not raw bytes, which risk a control character the tokenizer
        // reads as a physical line break inside a plain quoted string).
        let mut script = String::from("import json\nresults = []\n");
        for (s, _) in &probes {
            script.push_str(&format!(
                "try:\n    int({})\n    results.append(True)\nexcept ValueError:\n    results.append(False)\n",
                py_str_literal(s)
            ));
        }
        script.push_str("print(json.dumps(results))\n");
        let out = crate::oracle::python(&script);
        let py_results: Vec<bool> = pyjson::loads(out.trim())
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_bool().unwrap())
            .collect();

        assert_eq!(py_results.len(), probes.len());
        for ((s, leading), py_ok) in probes.iter().zip(py_results.iter()) {
            let rust_ok = python_int_parse_i128(s).is_some();
            assert_eq!(
                rust_ok, *py_ok,
                "int({s:?}) accept/reject mismatch (leading={leading}): rust={rust_ok} python={py_ok}"
            );
        }

        // Concrete pin for the four rejected exceptions and one accepted
        // case, independent of the full sweep above.
        assert!(python_int_parse_i128("\u{1c}1000-0000".split('-').next().unwrap()).is_none());
        for cp in [0x1Cu32, 0x1D, 0x1E, 0x1F] {
            let c = char::from_u32(cp).unwrap();
            assert!(
                python_int_parse_i128(&format!("{c}1000")).is_none(),
                "U+{cp:04X} must not be stripped by int()"
            );
        }
        assert_eq!(python_int_parse_i128(" 1000 "), Some(1000));
        assert_eq!(python_int_parse_i128("\u{a0}1000"), Some(1000)); // NBSP: isspace() and int()-strippable
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
