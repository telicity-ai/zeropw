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

fn is_float_literal(raw: &str) -> bool {
    raw.contains(['.', 'e', 'E'])
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
/// `wall_ms`/`counter` are `i64`, unlike Python's arbitrary-precision `int`;
/// see `rust/DEVIATIONS.md` for the (practically unreachable) bound this
/// implies on [`Hlc::parse`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hlc {
    pub wall_ms: i64,
    pub counter: i64,
}

impl Hlc {
    pub fn new(wall_ms: i64, counter: i64) -> Self {
        Hlc { wall_ms, counter }
    }

    /// `Hlc.parse` (a `@staticmethod` in Python).
    pub fn parse(value: &str) -> Result<(i64, i64)> {
        let bad = || Error::invalid_input("hlc_malformed");
        let parts: Vec<&str> = value.split('-').collect();
        if parts.len() != 2 {
            return Err(bad());
        }
        let wall_ms: i64 = parts[0].parse().map_err(|_| bad())?;
        let counter: i64 = parts[1].parse().map_err(|_| bad())?;
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
        let now_ms_value = now_ms_value.unwrap_or_else(now_ms);
        let candidate = now_ms_value.max(self.wall_ms);
        if candidate > self.wall_ms {
            self.wall_ms = candidate;
            self.counter = 0;
        } else {
            self.counter += 1;
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
pub fn order_key(commit: &Commit) -> Result<(i64, i64, String)> {
    let (wall_ms, counter) = Hlc::parse(&commit.hlc)?;
    Ok((wall_ms, counter, commit.author.clone()))
}

/// Port of `sort_total_order`.
pub fn sort_total_order(commits: Vec<Commit>) -> Result<Vec<Commit>> {
    let mut keyed: Vec<((i64, i64, String), Commit)> = Vec::with_capacity(commits.len());
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
    pub author_seq: i64,
    pub hlc: String,
    pub seen: BTreeMap<String, i64>,
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
        m.insert("author_seq".into(), json!(self.author_seq));
        m.insert("hlc".into(), Value::String(self.hlc.clone()));
        let seen: Map<String, Value> = self
            .seen
            .iter()
            .map(|(k, v)| (k.clone(), json!(v)))
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
    /// `InvalidInput("commit_malformed")`. As documented on the module:
    /// `format`/`env_id`/`author`/`hlc`/`sig` must already be JSON strings
    /// here (Python's `str(x)` coerces any value; this port does not) --
    /// see `rust/DEVIATIONS.md`.
    pub fn from_dict(data: &Value) -> Result<Commit> {
        let bad = || Error::invalid_input("commit_malformed");
        let obj = data.as_object().ok_or_else(bad)?;
        let str_field = |key: &str| -> Result<String> {
            obj.get(key)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(bad)
        };
        let format = str_field("format")?;
        let env_id = str_field("env_id")?;
        let author = str_field("author")?;
        let author_seq = obj
            .get("author_seq")
            .and_then(python_int_coerce)
            .ok_or_else(bad)?;
        let hlc = str_field("hlc")?;
        let seen = match obj.get("seen") {
            None | Some(Value::Null) => BTreeMap::new(),
            Some(Value::Object(m)) if m.is_empty() => BTreeMap::new(),
            Some(Value::Object(m)) => {
                let mut out = BTreeMap::new();
                for (k, v) in m {
                    let n = python_int_coerce(v).ok_or_else(bad)?;
                    out.insert(k.clone(), n);
                }
                out
            }
            _ => return Err(bad()),
        };
        let ops: Vec<Value> = obj
            .get("ops")
            .and_then(Value::as_array)
            .ok_or_else(bad)?
            .iter()
            .map(|op| {
                op.as_object()
                    .map(|o| Value::Object(o.clone()))
                    .ok_or_else(bad)
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
/// values. A narrower duplicate of `handles.rs`'s private
/// `python_int_coerce` (not reachable from here): see that function's doc
/// comment for the residual gaps versus CPython (bounded to `i64`, ASCII
/// digits only) -- recorded again here in `rust/DEVIATIONS.md`.
fn python_int_coerce(value: &Value) -> Option<i64> {
    match value {
        Value::Bool(b) => Some(i64::from(*b)),
        Value::Number(n) => {
            if is_float_literal(n.as_str()) {
                let f: f64 = n.as_str().parse().ok()?;
                if !f.is_finite() {
                    return None;
                }
                let truncated = f.trunc();
                if truncated > i64::MAX as f64 || truncated < i64::MIN as f64 {
                    return None;
                }
                Some(truncated as i64)
            } else {
                n.as_str().parse::<i64>().ok()
            }
        }
        Value::String(s) => {
            let t = s.trim();
            t.parse::<i64>().ok()
        }
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

/// `zeropw.team.commit.sign_commit`: build, format-validate and sign a new
/// commit (docs/team-sync.md section 5.2).
pub fn sign_commit(
    device: &DeviceKey,
    env_id: &str,
    author_seq: i64,
    hlc: &str,
    seen: &BTreeMap<String, i64>,
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

fn opt_string(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

fn http_target_value(t: &policy::HttpTarget) -> Value {
    json!({"scheme": t.scheme, "host": t.host, "port": t.port, "ca_file": t.ca_file,
          "allow_private_network": t.allow_private_network})
}
fn http_auth_value(a: &policy::HttpAuth) -> Value {
    json!({"mode": a.mode, "header_name": a.header_name, "value_prefix": a.value_prefix,
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

/// `zeropw.team.commit._build_http_target`.
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
    let ca_file = opt_string(obj.get("ca_file"));
    let allow_private_network = match obj.get("allow_private_network") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(Error::invalid_input("invalid_allow_private_network")),
    };
    Ok(Some(policy::HttpTarget::new(
        scheme,
        host,
        port,
        ca_file,
        allow_private_network,
    )?))
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

/// `zeropw.team.commit._build_http_scope`.
fn build_http_scope(value: Option<&Value>) -> Result<Option<policy::HttpScope>> {
    let value = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(v) => v,
    };
    let obj = value
        .as_object()
        .ok_or_else(|| Error::invalid_input("invalid_http_scope"))?;
    let methods = match obj.get("methods") {
        None | Some(Value::Null) => None,
        Some(Value::Array(items)) => Some(json_strings_lossy(items)),
        Some(_) => return Err(Error::invalid_input("invalid_http_scope")),
    };
    let path_prefixes = match obj.get("path_prefixes") {
        None | Some(Value::Null) => None,
        Some(Value::Array(items)) => Some(json_strings_lossy(items)),
        Some(_) => return Err(Error::invalid_input("invalid_http_scope")),
    };
    let confirm_methods = match obj.get("confirm_methods") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => json_strings_lossy(items),
        Some(_) => return Err(Error::invalid_input("invalid_http_scope")),
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
    let host_keys = match obj.get("host_keys") {
        Some(Value::Array(items)) => json_strings_lossy(items),
        _ => return Err(Error::invalid_input("invalid_ssh_target")),
    };
    Ok(Some(policy::SshTarget::new(
        host, port, username, host_keys,
    )?))
}

/// `zeropw.team.commit._build_cli_profile`.
fn build_cli_profile(value: Option<&Value>) -> Result<Option<policy::CliProfile>> {
    let value = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(v) => v,
    };
    let obj = value
        .as_object()
        .ok_or_else(|| Error::invalid_input("invalid_cli_profile"))?;
    if !(obj.contains_key("program") && obj.contains_key("kind")) {
        return Err(Error::invalid_input("invalid_cli_profile"));
    }
    let program = obj
        .get("program")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::invalid_input("invalid_cli_program"))?;
    let kind = obj
        .get("kind")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::invalid_input("invalid_cli_kind"))?;
    let base_url_env = match obj.get("base_url_env") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(Error::invalid_input("invalid_env_name")),
    };
    let extra_env = match obj.get("extra_env") {
        None | Some(Value::Null) => BTreeMap::new(),
        Some(Value::Object(m)) => {
            let mut out = BTreeMap::new();
            for (k, v) in m {
                let s = v
                    .as_str()
                    .ok_or_else(|| Error::invalid_input("invalid_env_value"))?;
                out.insert(k.clone(), s.to_string());
            }
            out
        }
        Some(_) => return Err(Error::invalid_input("invalid_cli_profile")),
    };
    Ok(Some(policy::CliProfile::new(
        program,
        kind,
        base_url_env,
        extra_env,
    )?))
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
    out.insert(
        "http_target".into(),
        http_target
            .as_ref()
            .map(http_target_value)
            .unwrap_or(Value::Null),
    );
    out.insert(
        "http_auth".into(),
        http_auth
            .as_ref()
            .map(http_auth_value)
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

fn validate_settings_update(op: &Map<String, Value>) -> Result<()> {
    let ok = match op.get("sync_interval_seconds") {
        Some(Value::Number(n)) => {
            !is_float_literal(n.as_str()) && n.as_i64().is_some_and(|v| v > 0)
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

    fn commit_path(&self, fingerprint: &str, seq: i64) -> String {
        format!("{}/commits/{}/{}.json", self.root, fingerprint, seq)
    }

    fn dir(&self, suffix: &str) -> PathBuf {
        self.state.path.join(&self.root).join(suffix)
    }

    /// The vector of the newest snapshot on disk, or `{}` if there is none
    /// (section 7.3). Port of `CommitStore._snapshot_floor`.
    fn snapshot_floor(&self) -> Result<BTreeMap<String, i64>> {
        let directory = self.dir("snapshots");
        if !directory.is_dir() {
            return Ok(BTreeMap::new());
        }
        let mut numbers: Vec<i64> = digit_stems(&directory)?;
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
                    && !is_float_literal(n.as_str())
                    && let Some(i) = n.as_i64()
                {
                    result.insert(k.clone(), i);
                }
            }
        }
        Ok(result)
    }

    /// Version vector: fingerprint -> highest `author_seq` stored (section
    /// 6.3). Port of `CommitStore.vector`.
    pub fn vector(&self) -> Result<BTreeMap<String, i64>> {
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
            if let Some(&max_seq) = seqs.iter().max() {
                let entry = result.entry(name).or_insert(0);
                *entry = (*entry).max(max_seq);
            }
        }
        Ok(result)
    }

    pub fn last_seq(&self, fingerprint: &str) -> Result<i64> {
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
        if commit.author_seq > last + 1 {
            return Err(Error::invalid_input("team_seq_gap"));
        }
        self.state.write_json(
            &self.commit_path(&commit.author, commit.author_seq),
            &commit.to_dict(),
        )?;
        Ok(())
    }

    pub fn get(&self, fingerprint: &str, seq: i64) -> Result<Option<Commit>> {
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
            for seq in 1..=last {
                if let Some(commit) = self.get(&fingerprint, seq)? {
                    commits.push(commit);
                }
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
            if wall_ms > now_ms_value + MAX_CLOCK_SKEW_MS {
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

/// Numeric (all-ASCII-digit) `.json` filename stems directly inside
/// `directory`, mirroring Python's `[int(p.stem) for p in directory.glob("*.json")
/// if p.stem.isdigit()]`. `pub(super)`: `team::fold`'s snapshot lookup
/// (`load_latest_snapshot`) reuses the exact same scan.
pub(super) fn digit_stems(directory: &std::path::Path) -> Result<Vec<i64>> {
    let entries = std::fs::read_dir(directory).map_err(|_| {
        Error::state("state_corrupt").with_detail(directory.to_string_lossy().into_owned())
    })?;
    Ok(entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name();
            let name = name.to_str()?;
            let stem = name.strip_suffix(".json")?;
            if !stem.is_empty() && stem.bytes().all(|b| b.is_ascii_digit()) {
                stem.parse::<i64>().ok()
            } else {
                None
            }
        })
        .collect())
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
        let previous = store.get(&commit.author, commit.author_seq - 1)?;
        if let Some(previous) = previous
            && Hlc::parse(&commit.hlc)? <= Hlc::parse(&previous.hlc)?
        {
            return reject("team_hlc_not_monotone");
        }
    }

    let (wall_ms, _) = Hlc::parse(&commit.hlc)?;
    if wall_ms > now_ms_value + MAX_CLOCK_SKEW_MS {
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
        let seqs: Vec<i64> = store
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
}
