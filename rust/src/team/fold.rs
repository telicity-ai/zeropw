//! Port of `zeropw/team/fold.py`: deterministic total-order fold into an
//! environment document, plus derivation into node-local policy/vault
//! state (docs/team-sync.md sections 5.1, 7.2, 7.3, 7.4, 6.5).
//!
//! [`fold`] applies every known commit, in the total order of section 7.1,
//! to build the environment document of section 5.1. State-dependent
//! checks (author role, target existence, ...) happen here, one commit at a
//! time, in order; an op that fails one is *skipped*, never aborts the
//! fold -- with one deliberate exception, matching Python: a
//! `connection.create`/`update`/`switch_credential`/`disable` op whose
//! commit's peer-supplied `hlc` renders a timestamp real `python3.12`'s
//! `time.gmtime` cannot represent aborts the whole fold with an `Err`, the
//! same way Python's own uncaught `OverflowError`/`OSError` from `_commit_time`
//! propagates out of `fold()` entirely rather than just skipping that one op
//! (finding A-R5-3; see [`commit_time`]'s doc and `rust/DEVIATIONS.md`'s
//! `iso` row). Facts (section 7.4: connection disabled, secret version
//! revoked, member removed) are a second, order-independent input that is
//! consulted throughout the fold and re-applied once more at the end, so
//! they always win regardless of where in the total order the corresponding
//! commit (if any) falls.
//!
//! [`derive_local`] then writes the parts of the document this node cares
//! about into its own `policy/connections.json` and `vault/secrets.json`,
//! tagged `shared_env`, reusing `policy::Policy::widens`/`reevaluate_grants`/
//! `invalidate_approvals` for exactly the same policy-version-bump and
//! stale/re-evaluate rules a local connection change gets (section 3.1,
//! 6.5). It is idempotent and recomputed from scratch on every call.
//!
//! ## The document is `serde_json::Value`, not a typed struct
//!
//! Like `Commit::ops` (see `commit.rs`'s module doc comment), the folded
//! environment document is kept as a JSON tree (`Map<String, Value>`
//! internally, `Value::Object` in [`FoldResult::document`]) rather than a
//! typed struct: `fold()`'s whole contract is "the same commit set always
//! yields byte-identical output (as JSON)" (Python's own doc comment,
//! carried over verbatim above), and the ported test suite checks that
//! literally (`json.dumps(result.document, sort_keys=True, ...)` equality
//! across shuffled arrival orders and all permutations of a small commit
//! set) -- a JSON tree is the natural, direct representation of that
//! contract, and avoids a second, parallel schema to keep in lock-step with
//! every op handler's dict-literal shape in the Python source.
//!
//! ## `derive_local`'s signature: `kms`, not `vault`
//!
//! Python's `derive_local(fold_result, state, vault, policy, audit=None, *,
//! device=None, project=None, environment=None)` takes a whole `Vault`
//! object but only ever reads one attribute off it: `vault.kms`, passed to
//! `_derive_dek_generations`. `vault::Vault::kms` is a private field in
//! `vault.rs` (owned by a different work unit; not reachable from here), so
//! this port's [`derive_local`] takes `kms: Option<&(dyn Kms + Send +
//! Sync)>` directly instead of a `&Vault` -- exactly the value Python's
//! `vault.kms` would have evaluated to, sourced from `Context::kms` (a
//! public field) rather than `Context::vault` at call sites. This changes
//! nothing observable: every write `_derive_vault`/`_derive_connections`
//! make goes straight through `state.read_json`/`write_json`, never through
//! any other `Vault` method.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde_json::{Map, Value, json};

use crate::audit::{Audit, RecordArgs};
use crate::errors::{Error, Result};
use crate::kms::Kms;
use crate::policy;
use crate::store::StateDir;
use crate::vault;

use super::commit::{self, Commit, Hlc, env_owner_fingerprint, json_int128, sort_total_order};
use super::envelope;
use super::identity::{DeviceKey, DeviceRecord};
use super::json_falsy;

/// `zeropw.team.fold.ENV_FORMAT`.
pub const ENV_FORMAT: &str = "zeropw-team-env-v1";
/// `zeropw.team.fold.DEFAULT_SYNC_INTERVAL_SECONDS`.
pub const DEFAULT_SYNC_INTERVAL_SECONDS: i64 = 10;

// ------------------------------------------------------------------------ facts
/// Monotone, order-independent facts (docs/team-sync.md section 7.4). Port
/// of `zeropw.team.fold.Facts`.
///
/// Not derived from folding commits: a real node also learns these from
/// out-of-band `FACT` messages (later stages). This first half takes them
/// as a plain argument to [`fold`] so the "facts win regardless of order"
/// property can be exercised without a transport.
#[derive(Clone, Debug, Default)]
pub struct Facts {
    pub disabled_connections: HashSet<String>,
    pub revoked_versions: HashSet<(String, String)>,
    pub removed_members: HashSet<String>,
    pub incidents: Vec<Value>,
}

// --------------------------------------------------------------------- document
/// `zeropw.team.fold.new_document`.
pub fn new_document(env_id: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("env_id".into(), json!(env_id));
    m.insert("format".into(), json!(ENV_FORMAT));
    m.insert("owner".into(), Value::Null);
    m.insert("members".into(), json!({}));
    m.insert("dek".into(), json!({"current": null, "generations": {}}));
    m.insert("connections".into(), json!({}));
    m.insert("secrets".into(), json!({}));
    m.insert(
        "settings".into(),
        json!({"sync_interval_seconds": DEFAULT_SYNC_INTERVAL_SECONDS}),
    );
    m
}

/// Validates that a document tree (freshly built by [`new_document`], or
/// supplied as `base_document` to [`fold`]) has the shape every op handler
/// assumes. Python has no equivalent check -- an unexpected shape there
/// surfaces as an uncaught `KeyError`/`AttributeError`/`TypeError` partway
/// through folding (PORTING.md §3.5) -- this port instead fails once, up
/// front, with a single `state_corrupt` error (`rust/DEVIATIONS.md`), so
/// every handler below can assume the shape without repeating this check.
///
/// Finding H-R3-4: round 1 only checked the TOP-level container types
/// (`members`/`connections`/`secrets`/`settings`/`dek.generations` are
/// objects), which left every handler's assumption about a nested,
/// *pre-existing* entry's shape unguarded -- a `base_document` with
/// `secrets.s1 = 5` or `secrets.s1.versions = 5` passed this check and then
/// PANICKED at `op_secret_put_version`'s
/// `entry.as_object_mut().expect("secret entry is always an object")`
/// (fold.rs, this module), where Python's `entry["kind"]`/`entry["versions"]`
/// raises an uncaught `TypeError` on the same input.
///
/// Finding H-R4-6: round 3's version above still stopped one field short in
/// several places -- it walked one level into every nested entry's SHAPE
/// (object vs. not) but not into which FIELDS an op handler indexes on that
/// entry unconditionally (a Python dict/attribute subscript, not a `.get`),
/// so seven further shapes still passed this check and then let the fold
/// complete SUCCESSFULLY with a different document than Python's own
/// uncaught `KeyError`/`TypeError` produces (a real fail-open, not merely a
/// panic-vs-error difference): a connection missing `status` or
/// `created_at` (`_op_connection_disable`'s `current["status"]`,
/// `_op_connection_update`'s `current["created_at"]`); a TRUTHY `members`
/// entry missing `status` (`_is_active_member`'s `bool(member) and
/// member["status"] == "active"` short-circuits on an EMPTY entry without
/// ever touching `"status"`, but does not for a non-empty one); a `secrets`
/// entry missing `kind` or `active_version` (`_op_secret_put_version`'s
/// `entry["kind"]`, `_set_secret_status`'s `entry["active_version"]`); a
/// `versions` entry whose RECORD (not the `versions` container itself) is
/// not an object (`_set_secret_status`'s `version["status"] = status`); and
/// a `dek.generations` entry missing `wraps` entirely, not just malformed
/// WHEN PRESENT (`_op_member_add`'s `generation["wraps"][fp] = wrap`, run
/// unconditionally once `generation is not None` -- unlike `secrets`/
/// `versions` above, there is no missing-key tolerance to mirror here at
/// all). This now also walks into every one of those unconditionally-
/// indexed fields. A brand-new entry a handler *creates* during the fold (a
/// fresh `json!({...})` literal, e.g. `op_secret_put_version`'s
/// `secrets.entry(...).or_insert_with(...)`) is always well-shaped by
/// construction regardless of this check -- only a shape carried over
/// unchanged from `base_document` can violate it.
fn validate_document_shape(doc: &Value) -> Result<Map<String, Value>> {
    let corrupt = || Error::state("state_corrupt").with_detail("team_document");
    let obj = doc.as_object().ok_or_else(corrupt)?.clone();
    for key in [
        "env_id",
        "format",
        "owner",
        "members",
        "dek",
        "connections",
        "secrets",
        "settings",
    ] {
        if !obj.contains_key(key) {
            return Err(corrupt());
        }
    }
    let members = obj
        .get("members")
        .and_then(Value::as_object)
        .ok_or_else(corrupt)?;
    for entry in members.values() {
        let entry_obj = entry.as_object().ok_or_else(corrupt)?;
        // `bool(member) and member["status"] == "active"`: an EMPTY entry
        // (`{}`, falsy) never even evaluates the subscript, so only a
        // TRUTHY (non-empty) entry needs `"status"` here.
        if !entry_obj.is_empty() && !entry_obj.contains_key("status") {
            return Err(corrupt());
        }
    }
    let connections = obj
        .get("connections")
        .and_then(Value::as_object)
        .ok_or_else(corrupt)?;
    for entry in connections.values() {
        let entry_obj = entry.as_object().ok_or_else(corrupt)?;
        // `current["status"]`/`current["created_at"]`: both unconditional
        // subscripts, in `_op_connection_disable`/`_op_connection_update`.
        if !entry_obj.contains_key("status") || !entry_obj.contains_key("created_at") {
            return Err(corrupt());
        }
    }
    let secrets = obj
        .get("secrets")
        .and_then(Value::as_object)
        .ok_or_else(corrupt)?;
    for entry in secrets.values() {
        let entry_obj = entry.as_object().ok_or_else(corrupt)?;
        // `entry["kind"]` (`_op_secret_put_version`), `entry["active_version"]`
        // (`_set_secret_status`): both unconditional subscripts on a
        // pre-existing entry.
        if !entry_obj.contains_key("kind") || !entry_obj.contains_key("active_version") {
            return Err(corrupt());
        }
        // `entry["versions"]`, used unconditionally by both handlers above;
        // every value in it is later itself subscripted
        // (`version["status"] = status`), so it must already be an object,
        // not merely present.
        let versions = entry_obj
            .get("versions")
            .and_then(Value::as_object)
            .ok_or_else(corrupt)?;
        for version in versions.values() {
            if !matches!(version, Value::Object(_)) {
                return Err(corrupt());
            }
        }
    }
    if !matches!(obj.get("settings"), Some(Value::Object(_))) {
        return Err(corrupt());
    }
    let dek = obj
        .get("dek")
        .and_then(Value::as_object)
        .ok_or_else(corrupt)?;
    if !dek.contains_key("current") || !matches!(dek.get("generations"), Some(Value::Object(_))) {
        return Err(corrupt());
    }
    let generations = dek
        .get("generations")
        .and_then(Value::as_object)
        .ok_or_else(corrupt)?;
    for generation in generations.values() {
        let generation_obj = generation.as_object().ok_or_else(corrupt)?;
        // `generation["wraps"][fp] = wrap` (`_op_member_add`): unconditional,
        // not "if present" -- every generation entry needs an object
        // `wraps`, always, not just a well-shaped one when it happens to be
        // there.
        if !matches!(generation_obj.get("wraps"), Some(Value::Object(_))) {
            return Err(corrupt());
        }
    }
    Ok(obj)
}

/// Port of `zeropw.team.fold.FoldResult`.
#[derive(Clone, Debug)]
pub struct FoldResult {
    pub document: Value,
    /// One entry per skipped op: `(commit_hash, op_index, reason)`.
    pub skipped: Vec<(String, usize, String)>,
    pub version_order: BTreeMap<String, Vec<String>>,
    /// Widened to `i128` (finding H-R2-6): `commit.author_seq` is `i128`
    /// (see `commit.rs`'s `Commit` and `rust/DEVIATIONS.md`), and Python's
    /// own `vector[commit.author] = max(vector.get(commit.author, 0),
    /// commit.author_seq)` is arbitrary-precision `int` arithmetic that
    /// never clamps. The previous `i64` field, filled via
    /// `i64::try_from(commit.author_seq).unwrap_or(i64::MAX)`, silently
    /// clamped an out-of-`i64` `author_seq` to `i64::MAX` instead of
    /// keeping its real value.
    pub vector: BTreeMap<String, i128>,
    /// Section 7.2's "same target, later wins" transitions this fold
    /// observed, each a `{"author","author_seq","hash","target_kind",
    /// "target_id","by_author","by_seq","by_hash"}` object.
    pub overridden: Vec<Value>,
    /// Connection ids for which `connection.create`/`connection.update`
    /// executed successfully during THIS `fold()` call (finding H-R2-7).
    ///
    /// Not part of Python's `FoldResult` -- a pure Rust bookkeeping seam
    /// needed because `serde_json::Value` conflates Python's `tuple` and
    /// `list`. Python's `build_connection_fields` returns
    /// `dataclasses.asdict(Connection(...))`, which keeps
    /// `HttpScope.methods`/`path_prefixes`/`confirm_methods` and
    /// `SshTarget.host_keys` as real `tuple`s; a connection freshly built by
    /// an op THIS fold call therefore renders via `to_yaml`'s `str(tuple)`
    /// path. A connection carried over untouched from `base_document` (a
    /// `fold_with_snapshot` seed, round-tripped through `json.dump`/
    /// `json.load`) is a plain `list` in that same field and renders as a
    /// normal multi-line YAML sequence instead -- the SAME document key can
    /// legitimately need either rendering depending on fold history, which
    /// no per-key-name rule can capture. `humanview::to_yaml` takes this set
    /// so it can reproduce the distinction explicitly instead of guessing
    /// from the key name (the round-1 fix's bug).
    pub fresh_connections: BTreeSet<String>,
}

/// Largest whole-second Unix timestamp this port has directly confirmed
/// real `python3.12`'s `time.gmtime` accepts on the platform this was probed
/// on (finding A-R5-3). Python's actual `_commit_time` pipeline is `wall_ms
/// / 1000` (an `int` divided by an `int`, which Python 3 computes as a
/// **float** division, not integer floor division) fed to `store.iso`,
/// i.e. `time.gmtime(...)` *followed by* `time.strftime(fmt, ...)` on the
/// result -- both steps matter: `time.gmtime` alone can succeed with a
/// nonsensical *wrapped* year (this platform's C library overflows `tm_year`
/// as a 32-bit int well before `gmtime` itself refuses the input outright),
/// and it is the subsequent `time.strftime` call that then raises on that
/// wrapped year. A bound probed against `time.gmtime` in isolation (an
/// earlier draft of this constant did exactly that) is therefore wrong --
/// measurably so, by about 60 million ms here -- because it misses this
/// second failure point entirely; the real cliff can only be found by
/// probing `store.iso` itself (or, equivalently, `gmtime` immediately
/// followed by `strftime`), which is what was actually done here: probing
/// `python3.12` directly, `wall_ms = 67_767_976_233_532_795_999` still
/// succeeds through the real `zeropw.store.iso(wall_ms / 1000)` call, while
/// `wall_ms = 67_767_976_233_532_796_000` (a mere 1ms more -- and, not
/// coincidentally, the exact reviewer-supplied repro value for this finding)
/// already raises `OverflowError: year out of range` from `time.strftime`. A
/// wide randomized scan (200,000 samples) between that boundary and 1,000x
/// it found no `wall_ms` past it that succeeds through `iso`, i.e. a real,
/// stable cliff on this platform, not a spot check. This is the platform's
/// `gmtime`/`strftime`/`struct tm` ceiling combined with `f64`'s precision
/// limit at this magnitude, not a value derived from any bound this crate
/// itself imposes (`Hlc`'s `wall_ms` is `i128` since work unit H's fix,
/// comfortably able to represent values on both sides of this boundary), and
/// it is inherently libc/platform-dependent the way every other `iso`/
/// `gmtime` boundary in this crate's tests already is documented to be
/// (`rust/DEVIATIONS.md`'s `iso` row) -- it is not asserted to be portable to
/// a different OS/libc, only confirmed on the one this port's own test suite
/// runs on. Only an upper bound is needed here: [`Hlc::parse`] already
/// rejects a negative `wall_ms`/`counter` exactly like Python's `Hlc.parse`
/// does (`wall_ms < 0` raises `InvalidInput("hlc_malformed")` in both
/// languages, checked before [`commit_time`] is ever reached, since
/// [`sort_total_order`] already calls `Hlc::parse` on every commit up
/// front), so `wall_ms` here is always non-negative.
const WALL_MS_GMTIME_FAILS_AT: i128 = 67_767_976_233_532_796_000;

/// Port of `zeropw.team.fold._commit_time` (fold.py:87-89).
///
/// Python computes `iso(wall_ms / 1000)` unconditionally, with no
/// `try`/`except` anywhere between it and `fold()`'s own top level: if the
/// resulting timestamp is outside what the platform's `time.gmtime` can
/// represent, the uncaught `OverflowError`/`OSError` propagates out of
/// `_commit_time`, out of `_apply_op`, and out of `fold()`'s whole commit
/// loop entirely -- aborting the fold outright, not just skipping the one
/// op. `wall_ms` comes straight from `Hlc.parse(commit.hlc)`, a **peer**-
/// supplied value (§3.7 does not apply: team commits are signed by peer
/// device keys, not the trusted issuer this crate's own HMAC-signed tokens
/// are), so a single active admin peer's `connection.create`/`update`/
/// `switch_credential`/`disable` op with a deliberately out-of-range `hlc`
/// can crash any node's fold of that commit -- finding A-R5-3, live now
/// that work unit H widened `Hlc`'s `wall_ms`/`counter` from `i64` to `i128`
/// (the previous DEVIATIONS.md `iso` row's "unreachable because `Hlc` was
/// `i64`" reasoning no longer holds: a `wall_ms` far outside `gmtime`'s
/// range fits comfortably in `i128`).
///
/// `crate::store::iso`'s own `fn(Option<f64>) -> String` signature must stay
/// infallible (other work units' callers depend on it unconditionally --
/// see `rust/DEVIATIONS.md`'s `iso` row), so this reproduces Python's crash
/// *before* ever calling it, via [`WALL_MS_GMTIME_FAILS_AT`], rather than
/// changing `iso` itself.
fn commit_time(commit: &Commit) -> Result<String> {
    let (wall_ms, _) = Hlc::parse(&commit.hlc)?;
    if wall_ms >= WALL_MS_GMTIME_FAILS_AT {
        return Err(Error::state("team_commit_time_out_of_range").with_detail(commit.hlc.as_str()));
    }
    Ok(crate::store::iso(Some(divide_by_1000_like_python(wall_ms))))
}

/// `wall_ms / 1000` exactly as CPython 3.12 computes an `int / int` true
/// division: a single, correctly-rounded (round-to-nearest, ties-to-even)
/// conversion of the exact rational value to `f64` (finding H-R3-1).
///
/// `wall_ms as f64 / 1000.0` -- what this used to be -- is TWO roundings,
/// not one: `wall_ms as f64` alone already rounds to the nearest `f64` (an
/// exact operation only below `2^53`; `wall_ms` here can be as large as
/// [`WALL_MS_GMTIME_FAILS_AT`], around `2^66`), and then dividing that
/// already-rounded value by the exact `1000.0` rounds *again* -- so the
/// final result is the correctly-rounded quotient of an ALREADY-ROUNDED
/// numerator, which is not always the same `f64` as correctly rounding the
/// true numerator once. Confirmed to actually differ on real input: for
/// `hlc = "9999999999999999-0000"`, real `python3.12`'s
/// `iso(9999999999999999 / 1000)` renders `...T17:46:39Z`, but the old
/// double-rounded computation rendered `...T17:46:40Z` -- a byte-different
/// folded environment document for the very same peer-signed commit, and not
/// a rare corner case: a 200,000-sample randomized scan of `wall_ms` above
/// `2^53` found many such mismatches.
///
/// `wall_ms` is non-negative here (see the module doc comment) and bounded
/// below [`WALL_MS_GMTIME_FAILS_AT`] (comfortably under `2^66`), which is
/// all this needs: it left-shifts `wall_ms` by however many bits keep the
/// shifted numerator's own bit width at a fixed budget (120 bits --
/// comfortably inside `u128`'s 128 for every `x_bits` up to 66, and
/// comfortably more than the ~63 bits `/ 1000`'s exact integer division
/// leaves for the final 53-bit mantissa to round against), divides that by
/// `1000` with ordinary EXACT integer division (no rounding at all, unlike
/// float division), and then rounds the resulting big quotient to the
/// nearest 53-bit mantissa BY HAND -- using the division's own exact integer
/// remainder as the sticky bit for round-to-nearest-even -- exactly
/// mirroring what a single correctly-rounded IEEE 754 division does,
/// without ever converting `wall_ms` (or any intermediate value) to `f64`
/// before this final, single rounding step. Verified (not merely argued)
/// against real `python3.12`'s own `int / int` true division across every
/// boundary value plus 200,000 random samples up to
/// [`WALL_MS_GMTIME_FAILS_AT`] while developing this fix, with zero
/// mismatches -- see
/// `divide_by_1000_like_python_matches_python_true_division` (this module's
/// tests) for the pinned, in-crate oracle version of that same check.
fn divide_by_1000_like_python(wall_ms: i128) -> f64 {
    debug_assert!(wall_ms >= 0, "wall_ms is non-negative by construction");
    if wall_ms <= 0 {
        return 0.0;
    }
    let x = wall_ms as u128;
    let x_bits = (u128::BITS - x.leading_zeros()) as i32;
    // Comfortably inside `u128`'s 128 bits for every `x_bits` up to 66 (this
    // function's only real caller already guarantees that upper bound), and
    // defensively clamped to never shift by a negative amount even if some
    // future caller ever passed a wider value.
    const TARGET_BITS: i32 = 120;
    let shift = (TARGET_BITS - x_bits).max(0) as u32;
    let shifted = x << shift;
    let q = shifted / 1000;
    let r = shifted % 1000;
    let q_bits = u128::BITS - q.leading_zeros();
    if q_bits <= 53 {
        // Only reachable for a far wider `x` than this function is ever
        // actually called with (see the doc comment); `q` is already
        // exactly representable in `f64`, and the true value's fractional
        // remainder `r / 1000` is negligible at this magnitude either way.
        return (q as f64) / (1u128 << shift) as f64;
    }
    let drop = q_bits - 53;
    let mut mantissa = q >> drop;
    let round_bit = (q >> (drop - 1)) & 1;
    let lower_mask: u128 = (1u128 << (drop - 1)) - 1;
    let sticky = (q & lower_mask) != 0 || r != 0;
    if round_bit == 1 && (sticky || mantissa & 1 == 1) {
        mantissa += 1; // carry can produce exactly 2^53, itself exact in `f64`
    }
    let exponent = drop as i32 - shift as i32;
    (mantissa as f64) * 2f64.powi(exponent)
}

fn is_active_member(doc: &Map<String, Value>, fp: &str) -> bool {
    doc.get("members")
        .and_then(Value::as_object)
        .and_then(|m| m.get(fp))
        .and_then(Value::as_object)
        .and_then(|m| m.get("status"))
        .and_then(Value::as_str)
        == Some("active")
}

fn is_admin(doc: &Map<String, Value>, fp: &str) -> bool {
    if !is_active_member(doc, fp) {
        return false;
    }
    if doc.get("owner").and_then(Value::as_str) == Some(fp) {
        return true;
    }
    doc.get("members")
        .and_then(Value::as_object)
        .and_then(|m| m.get(fp))
        .and_then(Value::as_object)
        .and_then(|m| m.get("role"))
        .and_then(Value::as_str)
        == Some("admin")
}

fn is_owner(doc: &Map<String, Value>, fp: &str) -> bool {
    doc.get("owner").and_then(Value::as_str) == Some(fp) && is_active_member(doc, fp)
}

// ------------------------------------------------------------- connection ops
fn connection_entry(
    conn_id: &str,
    args: &Map<String, Value>,
    status: &str,
    timestamp: &str,
    created_at: Option<&str>,
) -> Result<Map<String, Value>> {
    let mut fields = commit::build_connection_fields(args)?;
    fields.insert("id".into(), json!(conn_id));
    fields.insert("status".into(), json!(status));
    fields.insert("created_at".into(), json!(created_at.unwrap_or(timestamp)));
    fields.insert("updated_at".into(), json!(timestamp));
    Ok(fields)
}

fn op_connection_create(
    doc: &mut Map<String, Value>,
    commit: &Commit,
    facts: &mut Facts,
    _vo: &mut BTreeMap<String, Vec<String>>,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &commit.author) {
        return Ok(Some("not_admin".into()));
    }
    let conn_id = op
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let already = doc
        .get("connections")
        .and_then(Value::as_object)
        .map(|c| c.contains_key(&conn_id))
        .unwrap_or(false);
    if already || facts.disabled_connections.contains(&conn_id) {
        return Ok(Some("connection_id_taken".into()));
    }
    let secret_id = op
        .get("secret_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let has_secret = doc
        .get("secrets")
        .and_then(Value::as_object)
        .map(|s| s.contains_key(&secret_id))
        .unwrap_or(false);
    if !has_secret {
        return Ok(Some("secret_not_found".into()));
    }
    let timestamp = commit_time(commit)?;
    Ok(
        match connection_entry(&conn_id, op, "active", &timestamp, None) {
            Ok(entry) => {
                doc.get_mut("connections")
                    .and_then(Value::as_object_mut)
                    .expect("document shape validated at fold() entry")
                    .insert(conn_id, Value::Object(entry));
                None
            }
            Err(exc) => Some(exc.reason.to_string()),
        },
    )
}

fn op_connection_update(
    doc: &mut Map<String, Value>,
    commit: &Commit,
    facts: &mut Facts,
    _vo: &mut BTreeMap<String, Vec<String>>,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &commit.author) {
        return Ok(Some("not_admin".into()));
    }
    let conn_id = op
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let current = doc
        .get("connections")
        .and_then(Value::as_object)
        .and_then(|c| c.get(&conn_id))
        .and_then(Value::as_object)
        .cloned();
    let current = match current {
        Some(c) => c,
        None => return Ok(Some("connection_not_found".into())),
    };
    let status = current
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if status == "disabled" || facts.disabled_connections.contains(&conn_id) {
        return Ok(Some("connection_not_found".into()));
    }
    let mut merged = current.clone();
    for name in [
        "description",
        "http_target",
        "http_auth",
        "http_scope",
        "ssh_target",
        "cli",
    ] {
        if let Some(v) = op.get(name) {
            merged.insert(name.to_string(), v.clone());
        }
    }
    let timestamp = commit_time(commit)?;
    let created_at = current
        .get("created_at")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(
        match connection_entry(
            &conn_id,
            &merged,
            &status,
            &timestamp,
            created_at.as_deref(),
        ) {
            Ok(entry) => {
                doc.get_mut("connections")
                    .and_then(Value::as_object_mut)
                    .expect("document shape validated at fold() entry")
                    .insert(conn_id, Value::Object(entry));
                None
            }
            Err(exc) => Some(exc.reason.to_string()),
        },
    )
}

fn op_connection_switch_credential(
    doc: &mut Map<String, Value>,
    commit: &Commit,
    facts: &mut Facts,
    _vo: &mut BTreeMap<String, Vec<String>>,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &commit.author) {
        return Ok(Some("not_admin".into()));
    }
    let conn_id = op
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let current = doc
        .get("connections")
        .and_then(Value::as_object)
        .and_then(|c| c.get(&conn_id))
        .and_then(Value::as_object)
        .cloned();
    let current = match current {
        Some(c) => c,
        None => return Ok(Some("connection_not_found".into())),
    };
    if current.get("status").and_then(Value::as_str) == Some("disabled")
        || facts.disabled_connections.contains(&conn_id)
    {
        return Ok(Some("connection_not_found".into()));
    }
    let secret_id = op
        .get("secret_id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| {
            current
                .get("secret_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        });
    let has_secret = doc
        .get("secrets")
        .and_then(Value::as_object)
        .map(|s| s.contains_key(&secret_id))
        .unwrap_or(false);
    if !has_secret {
        return Ok(Some("secret_not_found".into()));
    }
    let mut merged = current;
    merged.insert("secret_id".into(), json!(secret_id));
    merged.insert(
        "secret_version".into(),
        op.get("secret_version").cloned().unwrap_or(Value::Null),
    );
    merged.insert("updated_at".into(), json!(commit_time(commit)?));
    doc.get_mut("connections")
        .and_then(Value::as_object_mut)
        .expect("document shape validated at fold() entry")
        .insert(conn_id, Value::Object(merged));
    Ok(None)
}

fn op_connection_disable(
    doc: &mut Map<String, Value>,
    commit: &Commit,
    facts: &mut Facts,
    _vo: &mut BTreeMap<String, Vec<String>>,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &commit.author) {
        return Ok(Some("not_admin".into()));
    }
    let conn_id = op
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let connections = doc
        .get_mut("connections")
        .and_then(Value::as_object_mut)
        .expect("document shape validated at fold() entry");
    let current = match connections.get_mut(&conn_id).and_then(Value::as_object_mut) {
        Some(c) => c,
        None => return Ok(Some("connection_not_found".into())),
    };
    if current.get("status").and_then(Value::as_str) == Some("disabled") {
        return Ok(Some("already_disabled".into()));
    }
    // Finding H-R3-2: Python's `_op_connection_disable` only calls
    // `_commit_time(commit)` here, AFTER the not-admin, connection-not-found
    // and already-disabled checks above -- this used to call `commit_time`
    // before even looking the connection up, so a `connection.disable` for a
    // non-existent id whose commit's `hlc` is past `gmtime`'s range aborted
    // the WHOLE fold (`commit_time`'s `Err`) where Python just skips the op
    // with `connection_not_found` (never reaching `_commit_time` at all) and
    // folds fine -- a single peer commit stopping every node.
    let timestamp = commit_time(commit)?;
    current.insert("status".into(), json!("disabled"));
    current.insert("updated_at".into(), json!(timestamp));
    facts.disabled_connections.insert(conn_id);
    Ok(None)
}

// ------------------------------------------------------------------ secret ops
fn op_secret_put_version(
    doc: &mut Map<String, Value>,
    commit: &Commit,
    _facts: &mut Facts,
    vo: &mut BTreeMap<String, Vec<String>>,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &commit.author) {
        return Ok(Some("not_admin".into()));
    }
    let secret_id = op
        .get("secret_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let version_id = op
        .get("version_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let generation_id = op
        .get("generation_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let kind = op
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let generation_known = doc
        .get("dek")
        .and_then(Value::as_object)
        .and_then(|d| d.get("generations"))
        .and_then(Value::as_object)
        .map(|g| g.contains_key(&generation_id))
        .unwrap_or(false);
    if !generation_known {
        return Ok(Some("generation_unknown".into()));
    }
    let secrets = doc
        .get_mut("secrets")
        .and_then(Value::as_object_mut)
        .expect("document shape validated at fold() entry");
    let entry = secrets
        .entry(secret_id.clone())
        .or_insert_with(|| json!({"kind": kind, "active_version": null, "versions": {}}));
    // Finding H-R3-4: safe now that `validate_document_shape` (called once
    // at `fold()`'s entry) has already rejected any `base_document` whose
    // `secrets` entry for `secret_id` was not itself an object -- if this
    // entry is new (`or_insert_with` just ran), it is the literal object
    // above; if it pre-existed, `validate_document_shape` already proved it.
    let entry_obj = entry
        .as_object_mut()
        .expect("secret entry is always an object (validate_document_shape)");
    if entry_obj.get("kind").and_then(Value::as_str) != Some(kind.as_str()) {
        return Ok(Some("secret_kind_mismatch".into()));
    }
    // Same reasoning: `validate_document_shape` already proved a
    // pre-existing `versions` field is an object, and a freshly-inserted one
    // is the literal `{}` above.
    let versions = entry_obj
        .entry("versions".to_string())
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .expect("secret entry always has a versions object (validate_document_shape)");
    if versions.contains_key(&version_id) {
        return Ok(Some("version_id_taken".into()));
    }
    let ciphertext = op.get("ciphertext").and_then(Value::as_object);
    let nonce = ciphertext
        .and_then(|c| c.get("nonce"))
        .cloned()
        .unwrap_or(Value::Null);
    let ct = ciphertext
        .and_then(|c| c.get("ciphertext"))
        .cloned()
        .unwrap_or(Value::Null);
    let public = op
        .get("public")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    versions.insert(
        version_id.clone(),
        json!({
            "status": "staged", "generation": generation_id, "nonce": nonce, "ciphertext": ct,
            "public": Value::Object(public),
        }),
    );
    vo.entry(secret_id).or_default().push(version_id);
    Ok(None)
}

fn set_secret_status(
    doc: &mut Map<String, Value>,
    facts: &Facts,
    secret_id: &str,
    version_id: &str,
    status: &str,
) -> Option<String> {
    let secrets = doc
        .get_mut("secrets")
        .and_then(Value::as_object_mut)
        .expect("document shape validated at fold() entry");
    let entry = match secrets.get_mut(secret_id).and_then(Value::as_object_mut) {
        Some(e) => e,
        None => return Some("version_not_found".into()),
    };
    let version_status = entry
        .get("versions")
        .and_then(Value::as_object)
        .and_then(|v| v.get(version_id))
        .and_then(Value::as_object)
        .and_then(|v| v.get("status"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let version_status = match version_status {
        Some(s) => s,
        None => return Some("version_not_found".into()),
    };
    if version_status == "revoked"
        || facts
            .revoked_versions
            .contains(&(secret_id.to_string(), version_id.to_string()))
    {
        return Some("version_revoked".into());
    }
    if let Some(v) = entry
        .get_mut("versions")
        .and_then(Value::as_object_mut)
        .and_then(|v| v.get_mut(version_id))
        .and_then(Value::as_object_mut)
    {
        v.insert("status".into(), json!(status));
    }
    if status == "active" {
        let previous = entry
            .get("active_version")
            .and_then(Value::as_str)
            .map(str::to_string);
        if let Some(previous) = previous.clone()
            && previous != version_id
        {
            let prev_active = entry
                .get("versions")
                .and_then(Value::as_object)
                .and_then(|v| v.get(&previous))
                .and_then(Value::as_object)
                .and_then(|v| v.get("status"))
                .and_then(Value::as_str)
                == Some("active");
            if prev_active
                && let Some(v) = entry
                    .get_mut("versions")
                    .and_then(Value::as_object_mut)
                    .and_then(|v| v.get_mut(&previous))
                    .and_then(Value::as_object_mut)
            {
                v.insert("status".into(), json!("retired"));
            }
        }
        entry.insert("active_version".into(), json!(version_id));
    } else if entry.get("active_version").and_then(Value::as_str) == Some(version_id) {
        entry.insert("active_version".into(), Value::Null);
    }
    None
}

fn op_secret_set_status(
    doc: &mut Map<String, Value>,
    commit: &Commit,
    facts: &mut Facts,
    _vo: &mut BTreeMap<String, Vec<String>>,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &commit.author) {
        return Ok(Some("not_admin".into()));
    }
    let secret_id = op.get("secret_id").and_then(Value::as_str).unwrap_or("");
    let version_id = op.get("version_id").and_then(Value::as_str).unwrap_or("");
    let status = op.get("status").and_then(Value::as_str).unwrap_or("");
    Ok(set_secret_status(doc, facts, secret_id, version_id, status))
}

fn op_secret_activate(
    doc: &mut Map<String, Value>,
    commit: &Commit,
    facts: &mut Facts,
    _vo: &mut BTreeMap<String, Vec<String>>,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &commit.author) {
        return Ok(Some("not_admin".into()));
    }
    let secret_id = op.get("secret_id").and_then(Value::as_str).unwrap_or("");
    let version_id = op.get("version_id").and_then(Value::as_str).unwrap_or("");
    Ok(set_secret_status(
        doc, facts, secret_id, version_id, "active",
    ))
}

// ------------------------------------------------------------------ member ops
fn op_member_add(
    doc: &mut Map<String, Value>,
    commit: &Commit,
    facts: &mut Facts,
    _vo: &mut BTreeMap<String, Vec<String>>,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &commit.author) {
        return Ok(Some("not_admin".into()));
    }
    let device_val = op.get("device").cloned().unwrap_or(Value::Null);
    let record = match DeviceRecord::from_dict(&device_val) {
        Ok(r) => r,
        Err(_) => return Ok(Some("member_add_malformed".into())),
    };
    if !record.verify() {
        return Ok(Some("member_add_malformed".into()));
    }
    let fp = record.fingerprint();
    if facts.removed_members.contains(&fp) {
        return Ok(Some("member_removed".into()));
    }
    let existing_status = doc
        .get("members")
        .and_then(Value::as_object)
        .and_then(|m| m.get(&fp))
        .and_then(Value::as_object)
        .and_then(|m| m.get("status"))
        .and_then(Value::as_str)
        .map(str::to_string);
    if let Some(status) = existing_status {
        if status == "removed" {
            return Ok(Some("member_removed".into()));
        }
        return Ok(Some("member_exists".into()));
    }
    let name = op.get("name").cloned().unwrap_or(Value::Null);
    let role = op.get("role").cloned().unwrap_or(Value::Null);
    let member_entry =
        json!({"name": name, "role": role, "status": "active", "device": record.to_dict()});
    doc.get_mut("members")
        .and_then(Value::as_object_mut)
        .expect("document shape validated at fold() entry")
        .insert(fp.clone(), member_entry);
    if let Some(wraps) = op.get("wraps").and_then(Value::as_object)
        && let Some(generations) = doc
            .get_mut("dek")
            .and_then(Value::as_object_mut)
            .and_then(|d| d.get_mut("generations"))
            .and_then(Value::as_object_mut)
    {
        for (gen_id, wrap) in wraps {
            if let Some(generation) = generations.get_mut(gen_id).and_then(Value::as_object_mut) {
                let wraps_obj = generation
                    .entry("wraps".to_string())
                    .or_insert_with(|| json!({}));
                if let Some(wraps_obj) = wraps_obj.as_object_mut() {
                    wraps_obj.insert(fp.clone(), wrap.clone());
                }
            }
        }
    }
    Ok(None)
}

fn op_member_set_role(
    doc: &mut Map<String, Value>,
    commit: &Commit,
    _facts: &mut Facts,
    _vo: &mut BTreeMap<String, Vec<String>>,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &commit.author) {
        return Ok(Some("not_admin".into()));
    }
    let fp = op
        .get("fingerprint")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if doc.get("owner").and_then(Value::as_str) == Some(fp.as_str()) {
        return Ok(Some("cannot_change_owner_role".into()));
    }
    if !is_active_member(doc, &fp) {
        return Ok(Some("member_not_found".into()));
    }
    let role = op.get("role").cloned().unwrap_or(Value::Null);
    if let Some(m) = doc
        .get_mut("members")
        .and_then(Value::as_object_mut)
        .and_then(|m| m.get_mut(&fp))
        .and_then(Value::as_object_mut)
    {
        m.insert("role".into(), role);
    }
    Ok(None)
}

fn op_member_remove(
    doc: &mut Map<String, Value>,
    commit: &Commit,
    facts: &mut Facts,
    _vo: &mut BTreeMap<String, Vec<String>>,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    let fp = op
        .get("fingerprint")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if !(is_admin(doc, &commit.author) || commit.author == fp) {
        return Ok(Some("not_authorized".into()));
    }
    if doc.get("owner").and_then(Value::as_str) == Some(fp.as_str()) {
        return Ok(Some("cannot_remove_owner".into()));
    }
    if !is_active_member(doc, &fp) {
        return Ok(Some("member_not_found".into()));
    }
    if let Some(m) = doc
        .get_mut("members")
        .and_then(Value::as_object_mut)
        .and_then(|m| m.get_mut(&fp))
        .and_then(Value::as_object_mut)
    {
        m.insert("status".into(), json!("removed"));
    }
    facts.removed_members.insert(fp);
    Ok(None)
}

fn op_owner_transfer(
    doc: &mut Map<String, Value>,
    commit: &Commit,
    _facts: &mut Facts,
    _vo: &mut BTreeMap<String, Vec<String>>,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_owner(doc, &commit.author) {
        return Ok(Some("not_owner".into()));
    }
    let fp = op
        .get("fingerprint")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if !is_active_member(doc, &fp) {
        return Ok(Some("member_not_found".into()));
    }
    doc.insert("owner".into(), json!(fp));
    if let Some(m) = doc
        .get_mut("members")
        .and_then(Value::as_object_mut)
        .and_then(|m| m.get_mut(&fp))
        .and_then(Value::as_object_mut)
    {
        m.insert("role".into(), json!("admin"));
    }
    Ok(None)
}

// --------------------------------------------------------------------- dek/settings
fn op_dek_rotate(
    doc: &mut Map<String, Value>,
    commit: &Commit,
    _facts: &mut Facts,
    _vo: &mut BTreeMap<String, Vec<String>>,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &commit.author) {
        return Ok(Some("not_admin".into()));
    }
    let gen_id = op
        .get("generation_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let dek = doc
        .get_mut("dek")
        .and_then(Value::as_object_mut)
        .expect("document shape validated at fold() entry");
    let generations = dek
        .get_mut("generations")
        .and_then(Value::as_object_mut)
        .expect("dek.generations is always an object");
    if generations.contains_key(&gen_id) {
        return Ok(Some("generation_exists".into()));
    }
    let wraps = op.get("wraps").cloned().unwrap_or_else(|| json!({}));
    generations.insert(gen_id.clone(), json!({"wraps": wraps}));
    dek.insert("current".into(), json!(gen_id));
    Ok(None)
}

fn op_settings_update(
    doc: &mut Map<String, Value>,
    commit: &Commit,
    _facts: &mut Facts,
    _vo: &mut BTreeMap<String, Vec<String>>,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &commit.author) {
        return Ok(Some("not_admin".into()));
    }
    let value = op
        .get("sync_interval_seconds")
        .cloned()
        .unwrap_or(Value::Null);
    doc.get_mut("settings")
        .and_then(Value::as_object_mut)
        .expect("document shape validated at fold() entry")
        .insert("sync_interval_seconds".into(), value);
    Ok(None)
}

// --------------------------------------------------------------------- env.init
fn op_env_init(
    doc: &mut Map<String, Value>,
    commit: &Commit,
    _facts: &mut Facts,
    _vo: &mut BTreeMap<String, Vec<String>>,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !matches!(doc.get("owner"), None | Some(Value::Null)) {
        return Ok(Some("env_already_initialized".into()));
    }
    if commit.author_seq != 1 {
        return Ok(Some("env_init_not_first".into()));
    }
    let expected_owner = match env_owner_fingerprint(&commit.env_id) {
        Ok(o) => o,
        Err(_) => return Ok(Some("env_id_malformed".into())),
    };
    if commit.author != expected_owner {
        return Ok(Some("env_init_wrong_owner".into()));
    }
    let device_val = op.get("owner_device").cloned().unwrap_or(Value::Null);
    let owner_record = match DeviceRecord::from_dict(&device_val) {
        Ok(r) => r,
        Err(_) => return Ok(Some("env_init_malformed".into())),
    };
    if owner_record.fingerprint() != commit.author || !owner_record.verify() {
        return Ok(Some("env_init_malformed".into()));
    }
    doc.insert("owner".into(), json!(commit.author));
    let owner_name = op.get("owner_name").cloned().unwrap_or(Value::Null);
    let member_entry = json!({"name": owner_name, "role": "admin", "status": "active",
                              "device": owner_record.to_dict()});
    doc.get_mut("members")
        .and_then(Value::as_object_mut)
        .expect("document shape validated at fold() entry")
        .insert(commit.author.clone(), member_entry);
    let generation_id = op.get("generation_id").cloned().unwrap_or(Value::Null);
    let wraps = op.get("wraps").cloned().unwrap_or_else(|| json!({}));
    let gen_key = generation_id.as_str().unwrap_or("").to_string();
    let dek = doc
        .get_mut("dek")
        .and_then(Value::as_object_mut)
        .expect("document shape validated at fold() entry");
    dek.insert("current".into(), generation_id);
    dek.get_mut("generations")
        .and_then(Value::as_object_mut)
        .expect("dek.generations is always an object")
        .insert(gen_key, json!({"wraps": wraps}));
    Ok(None)
}

type OpHandler = fn(
    &mut Map<String, Value>,
    &Commit,
    &mut Facts,
    &mut BTreeMap<String, Vec<String>>,
    &Map<String, Value>,
) -> Result<Option<String>>;

fn op_handler(name: &str) -> Option<OpHandler> {
    Some(match name {
        "env.init" => op_env_init,
        "connection.create" => op_connection_create,
        "connection.update" => op_connection_update,
        "connection.switch_credential" => op_connection_switch_credential,
        "connection.disable" => op_connection_disable,
        "secret.put_version" => op_secret_put_version,
        "secret.set_status" => op_secret_set_status,
        "secret.activate" => op_secret_activate,
        "member.add" => op_member_add,
        "member.set_role" => op_member_set_role,
        "member.remove" => op_member_remove,
        "owner.transfer" => op_owner_transfer,
        "dek.rotate" => op_dek_rotate,
        "settings.update" => op_settings_update,
        _ => return None,
    })
}

fn apply_op(
    doc: &mut Map<String, Value>,
    commit: &Commit,
    facts: &mut Facts,
    vo: &mut BTreeMap<String, Vec<String>>,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    let name = op.get("op").and_then(Value::as_str).unwrap_or("");
    match op_handler(name) {
        Some(handler) => handler(doc, commit, facts, vo, op),
        None => Ok(Some("unknown_op".into())),
    }
}

/// Ops eligible for section 7.2's "same target, later wins" override alert.
/// Port of `_override_target`.
#[derive(Clone, PartialEq, Eq, Hash)]
enum TargetKind {
    Connection,
    MemberRole,
    SecretActive,
}

impl TargetKind {
    fn as_str(&self) -> &'static str {
        match self {
            TargetKind::Connection => "connection",
            TargetKind::MemberRole => "member_role",
            TargetKind::SecretActive => "secret_active",
        }
    }
}

fn override_target(op: &Map<String, Value>) -> Option<(TargetKind, String)> {
    let kind = op.get("op").and_then(Value::as_str)?;
    match kind {
        "connection.update" | "connection.switch_credential" => Some((
            TargetKind::Connection,
            op.get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        )),
        "member.set_role" => Some((
            TargetKind::MemberRole,
            op.get("fingerprint")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        )),
        "secret.activate" => Some((
            TargetKind::SecretActive,
            op.get("secret_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        )),
        _ => None,
    }
}

fn reapply_facts(doc: &mut Map<String, Value>, facts: &Facts) {
    if let Some(connections) = doc.get_mut("connections").and_then(Value::as_object_mut) {
        for conn_id in &facts.disabled_connections {
            if let Some(entry) = connections.get_mut(conn_id).and_then(Value::as_object_mut) {
                entry.insert("status".into(), json!("disabled"));
            }
        }
    }
    if let Some(secrets) = doc.get_mut("secrets").and_then(Value::as_object_mut) {
        for (secret_id, version_id) in &facts.revoked_versions {
            if let Some(entry) = secrets.get_mut(secret_id).and_then(Value::as_object_mut) {
                let active_matches = entry.get("active_version").and_then(Value::as_str)
                    == Some(version_id.as_str());
                if let Some(version) = entry
                    .get_mut("versions")
                    .and_then(Value::as_object_mut)
                    .and_then(|v| v.get_mut(version_id))
                    .and_then(Value::as_object_mut)
                {
                    version.insert("status".into(), json!("revoked"));
                    if active_matches {
                        entry.insert("active_version".into(), Value::Null);
                    }
                }
            }
        }
    }
    if let Some(members) = doc.get_mut("members").and_then(Value::as_object_mut) {
        for fp in &facts.removed_members {
            if let Some(member) = members.get_mut(fp).and_then(Value::as_object_mut) {
                member.insert("status".into(), json!("removed"));
            }
        }
    }
}

/// Python's `{k: list(v) for k, v in stray.items()}` for a `_version_order`
/// key found already sitting INSIDE a `base_document` (finding H-R4-5,
/// [`fold`]'s own doc comment): every real writer of this key
/// (`op_secret_put_version`'s `.setdefault(...).setdefault(secret_id,
/// []).append(version_id)`, the only place across both languages that ever
/// touches it) only ever produces a JSON object of arrays of strings, so
/// this requires exactly that shape -- `state_corrupt` (the same fail-closed
/// posture [`validate_document_shape`]'s neighbouring checks use, PORTING.md
/// §3.5) for a non-object `stray`, a non-array value, or a non-string
/// element, rather than reproducing Python's own `TypeError` on
/// `list(<non-iterable>)`/a hypothetical non-string entry at whatever
/// specific later point it would surface.
fn parse_stray_version_order(value: &Value) -> Result<BTreeMap<String, Vec<String>>> {
    let corrupt = || Error::state("state_corrupt").with_detail("team_document");
    let obj = value.as_object().ok_or_else(corrupt)?;
    let mut out = BTreeMap::new();
    for (k, v) in obj {
        let arr = v.as_array().ok_or_else(corrupt)?;
        let mut list = Vec::with_capacity(arr.len());
        for item in arr {
            list.push(item.as_str().ok_or_else(corrupt)?.to_string());
        }
        out.insert(k.clone(), list);
    }
    Ok(out)
}

/// `zeropw.team.fold.fold`: fold `commits` (any arrival order) into the
/// environment document (section 7.2).
///
/// Deterministic: the same commit set always yields byte-identical output
/// (as JSON), whatever order the commits are passed in, because they are
/// always re-sorted into the total order of section 7.1 before anything is
/// applied. `base_document`/`base_version_order` let a snapshot
/// ([`save_snapshot`]/loaded via [`load_latest_snapshot`]) seed the fold
/// instead of starting from an empty environment; the caller is responsible
/// for only passing commits that are not already reflected in the snapshot.
///
/// Finding H-R4-5: Python keeps `_version_order` INSIDE `doc` for the
/// duration of the fold (`doc.setdefault("_version_order", {k: list(v) for
/// k, v in (base_version_order or {}).items()})`, appended to by
/// `_op_secret_put_version`), then `doc.pop("_version_order")`s it back out
/// before returning `FoldResult`. `setdefault` only installs its default
/// when the key is ABSENT -- so if `base_document` itself ALREADY carries a
/// `_version_order` key (only reachable via a hand-edited or bit-rotted
/// snapshot: `save_snapshot` never writes one, since `fold()` always pops it
/// first), THAT value wins over the separate `base_version_order` argument
/// entirely, and the `.pop()` at the end means the returned document never
/// contains the key either way. This crate's `version_order` has always
/// lived in its own variable alongside `doc` rather than embedded in it,
/// which already reproduces the common case (`base_document` never carries
/// the key, since it is always this crate's own prior, already-popped
/// `FoldResult::document`) correctly -- but silently ignored a stray key,
/// leaving it to ride along unmodified into the returned document (a bogus
/// extra field Python's `.pop()` never leaves behind) while still using
/// `base_version_order` instead of it (an accept-with-different-vector
/// divergence, not just a cosmetic extra key: `derive_local`'s
/// `version_index` is keyed off exactly this map).
pub fn fold(
    env_id: &str,
    commits: Vec<Commit>,
    facts: Option<&Facts>,
    base_document: Option<Value>,
    base_version_order: Option<BTreeMap<String, Vec<String>>>,
    audit: Option<&Audit>,
) -> Result<FoldResult> {
    // Finding H-R4-7: Python's `copy.deepcopy(base_document) if
    // base_document is not None else new_document(env_id)` is an identity
    // check against Python's `None`, which JSON `null` decodes to -- so a
    // `base_document` of `Value::Null` (e.g. `fold_with_snapshot` passing
    // through a snapshot's `{"document": null, ...}`) must fold from a
    // FRESH document, exactly like an absent `base_document`, not fail
    // `validate_document_shape`'s `.as_object()` check as `state_corrupt`.
    let mut doc = match base_document {
        Some(Value::Null) | None => new_document(env_id),
        Some(v) => validate_document_shape(&v)?,
    };
    let mut version_order = match doc.remove("_version_order") {
        Some(stray) => parse_stray_version_order(&stray)?,
        None => base_version_order.unwrap_or_default(),
    };
    let mut working_facts = facts.cloned().unwrap_or_default();
    let mut skipped: Vec<(String, usize, String)> = Vec::new();
    let relevant: Vec<Commit> = commits.into_iter().filter(|c| c.env_id == env_id).collect();
    let ordered = sort_total_order(relevant)?;
    let mut last_target_author: HashMap<(TargetKind, String), (String, i128, String)> =
        HashMap::new();
    let mut overridden: Vec<Value> = Vec::new();
    let mut fresh_connections: BTreeSet<String> = BTreeSet::new();
    for commit in &ordered {
        for (index, op) in commit.ops.iter().enumerate() {
            let op_obj = match op.as_object() {
                Some(o) => o,
                None => continue,
            };
            let reason = apply_op(
                &mut doc,
                commit,
                &mut working_facts,
                &mut version_order,
                op_obj,
            )?;
            if let Some(reason) = reason {
                let hash = commit.hash()?;
                skipped.push((hash, index, reason.clone()));
                if let Some(audit) = audit {
                    let op_name: String = op_obj
                        .get("op")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .chars()
                        .take(64)
                        .collect();
                    audit.record(
                        "team_op_skipped",
                        RecordArgs {
                            result: Some("skipped"),
                            reason: Some(&reason),
                            extra: vec![
                                ("env_id", json!(env_id)),
                                ("fingerprint", json!(commit.author)),
                                ("author_seq", json!(commit.author_seq)),
                                ("op", json!(op_name)),
                            ],
                            ..Default::default()
                        },
                    )?;
                }
                continue;
            }
            // Finding H-R2-7: `connection.create`/`connection.update` both
            // route through `connection_entry`/`build_connection_fields`,
            // which always rebuilds `http_scope`/`ssh_target` as fresh
            // Python tuples (`policy::HttpScope::new`/`SshTarget::new` via
            // `tuple(...)`, mirrored here) -- regardless of whether the
            // fields being merged in came from a snapshot-seeded (list) or
            // freshly-built (tuple) prior value. Record every connection id
            // an op *successfully* creates/updates this fold call so
            // `humanview::to_yaml` can render exactly those as tuples and
            // everything else (carried over untouched from `base_document`)
            // as plain YAML lists.
            let op_name = op_obj.get("op").and_then(Value::as_str);
            if matches!(
                op_name,
                Some("connection.create") | Some("connection.update")
            ) && let Some(id) = op_obj.get("id").and_then(Value::as_str)
            {
                fresh_connections.insert(id.to_string());
            }
            let target = match override_target(op_obj) {
                Some(t) => t,
                None => continue,
            };
            let hash = commit.hash()?;
            if let Some(previous) = last_target_author.get(&target)
                && previous.0 != commit.author
            {
                overridden.push(json!({
                    "author": previous.0, "author_seq": previous.1, "hash": previous.2,
                    "target_kind": target.0.as_str(), "target_id": target.1,
                    "by_author": commit.author, "by_seq": commit.author_seq, "by_hash": hash,
                }));
            }
            last_target_author.insert(target, (commit.author.clone(), commit.author_seq, hash));
        }
    }
    reapply_facts(&mut doc, &working_facts);
    let mut vector: BTreeMap<String, i128> = BTreeMap::new();
    for commit in &ordered {
        let entry = vector.entry(commit.author.clone()).or_insert(0);
        *entry = (*entry).max(commit.author_seq);
    }
    Ok(FoldResult {
        document: Value::Object(doc),
        skipped,
        version_order,
        vector,
        overridden,
        fresh_connections,
    })
}

// --------------------------------------------------------------------- snapshots
fn snapshot_dir(env_id: &str) -> String {
    format!("team/{env_id}/snapshots")
}

/// `zeropw.team.fold.save_snapshot`.
pub fn save_snapshot(
    state: &StateDir,
    env_id: &str,
    number: i64,
    result: &FoldResult,
) -> Result<()> {
    let version_order: Map<String, Value> = result
        .version_order
        .iter()
        .map(|(k, v)| (k.clone(), json!(v)))
        .collect();
    let vector: Map<String, Value> = result
        .vector
        .iter()
        .map(|(k, v)| (k.clone(), json_int128(*v)))
        .collect();
    let doc = json!({"document": result.document, "version_order": Value::Object(version_order),
                     "vector": Value::Object(vector)});
    state.write_json(&format!("{}/{}.json", snapshot_dir(env_id), number), &doc)?;
    Ok(())
}

/// `zeropw.team.fold.load_latest_snapshot`.
pub fn load_latest_snapshot(state: &StateDir, env_id: &str) -> Result<Option<Value>> {
    let directory = state.path.join(snapshot_dir(env_id));
    if !directory.is_dir() {
        return Ok(None);
    }
    let mut numbers = commit::digit_stems(&directory)?;
    if numbers.is_empty() {
        return Ok(None);
    }
    numbers.sort_unstable_by(|a, b| b.cmp(a));
    let data = state.read_json(
        &format!("{}/{}.json", snapshot_dir(env_id), numbers[0]),
        Value::Null,
    )?;
    Ok(Some(data))
}

/// Python's `commit.author_seq > base_vector.get(commit.author, 0)`
/// (finding H-R4-7): the right operand defaults to the plain `int` `0` for
/// an absent author, but otherwise is whatever raw JSON value a snapshot's
/// `vector` entry holds. Python's `>` between an `int` and another value
/// compares NUMERICALLY (not merely checks JSON type) for a JSON number --
/// integer or float, `3 > 3.0` by real value -- or a JSON bool (`bool` is a
/// Python `int` subclass: `True == 1`, `False == 0`); every other shape --
/// string, null, array, object -- is an uncaught `TypeError`, `state_corrupt`
/// here (PORTING.md §3.5) rather than silently substituting `0` and
/// refolding history the snapshot already covered (a hand-crafted/bit-rotted
/// snapshot's numeric-STRING floor used to do exactly that; a float or bool
/// floor used to silently become `0` too, rather than the `3`/`1` real
/// Python arithmetic gives them).
fn author_seq_is_later(author_seq: i128, floor: Option<&Value>) -> Result<bool> {
    let corrupt = || Error::state("state_corrupt").with_detail("team_snapshot");
    match floor {
        None => Ok(true), // `author_seq` is always >= 1; the implicit floor is 0.
        Some(Value::Bool(b)) => Ok(author_seq > i128::from(*b)),
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i128() {
                Ok(author_seq > i)
            } else if let Some(f) = n.as_f64() {
                Ok((author_seq as f64) > f)
            } else {
                Err(corrupt())
            }
        }
        Some(_) => Err(corrupt()),
    }
}

/// `{k: list(v) for k, v in (base_version_order or {}).items()}`, as
/// `fold_with_snapshot` hands `snapshot.get("version_order")` to `fold()`'s
/// `base_version_order` parameter (finding H-R4-7). `fold()`'s own Rust
/// signature requires an already-typed `BTreeMap<String, Vec<String>>` --
/// there is no raw-`Value` overload for it to defer this check to, unlike
/// Python's untyped parameter -- so the conversion, and its failure modes,
/// must live here instead:
///
/// - A FALSY `version_order` (absent, `null`, `0`, `""`, `[]`, `{}`) becomes
///   `{}`, matching Python's `(x or {})` short-circuit -- no error.
/// - A TRUTHY value that is not a JSON object has no Python `.items()`
///   equivalent: an uncaught `AttributeError`, `state_corrupt` here.
/// - Each entry's value must be a JSON array whose every element is a
///   string: Python's `list(v)` copies whatever `v` already held VERBATIM
///   -- a non-iterable value (a number, bool, `null`) is `TypeError`, but a
///   string or object value is a perfectly ordinary (if unlikely) success
///   in Python, which this crate's `Vec<String>` simply cannot represent
///   either way -- fails closed instead of silently DROPPING non-string
///   elements the way this used to, which shifted every later element's
///   1-based position and so corrupted `derive_vault`'s node-local version
///   integers silently rather than visibly.
fn parse_snapshot_version_order(
    value: Option<&Value>,
) -> Result<Option<BTreeMap<String, Vec<String>>>> {
    let corrupt = || Error::state("state_corrupt").with_detail("team_snapshot");
    let value = match value {
        None => return Ok(None),
        Some(v) if json_falsy(v) => return Ok(Some(BTreeMap::new())),
        Some(v) => v,
    };
    let obj = value.as_object().ok_or_else(corrupt)?;
    let mut out = BTreeMap::new();
    for (k, v) in obj {
        let arr = v.as_array().ok_or_else(corrupt)?;
        let mut list = Vec::with_capacity(arr.len());
        for item in arr {
            list.push(item.as_str().ok_or_else(corrupt)?.to_string());
        }
        out.insert(k.clone(), list);
    }
    Ok(Some(out))
}

/// `zeropw.team.fold.fold_with_snapshot`: fold using the latest snapshot as
/// a base, applying only later commits.
///
/// Only correct when no commit older (in total order) than the snapshot's
/// vector has newly appeared -- exactly the condition `team compact`
/// (later stage, out of scope here) is responsible for guaranteeing before
/// it ever deletes history. A caller that suspects a late-arriving commit
/// should call [`fold`] directly instead.
///
/// Finding H-R4-7: this used to only widen the vector-floor comparison to
/// `i128` (finding H-R2-6) and otherwise silently tolerate every malformed
/// snapshot shape by falling back to an empty/default value -- a
/// fail-open divergence from Python's own uncaught exceptions for several
/// of those same shapes. Now: a snapshot whose content is literal JSON
/// `null` (Python's `state.read_json(path, None)` maps this to the exact
/// same `None` a MISSING snapshot file gets) folds every commit fresh with
/// no vector filtering at all, matching `fold_with_snapshot`'s own `if
/// snapshot is None:` branch; any OTHER non-object snapshot (Python's
/// `snapshot.get(...)` on a non-`None`, non-`dict` value -- an array,
/// string, number or bool -- is an uncaught `AttributeError`) fails closed
/// instead of silently ignoring the whole snapshot; each vector entry and
/// each `version_order` entry is validated per [`author_seq_is_later`] /
/// [`parse_snapshot_version_order`] above.
pub fn fold_with_snapshot(
    env_id: &str,
    all_commits: Vec<Commit>,
    state: &StateDir,
    facts: Option<&Facts>,
    audit: Option<&Audit>,
) -> Result<FoldResult> {
    let snapshot = load_latest_snapshot(state, env_id)?;
    let snapshot = match snapshot {
        None | Some(Value::Null) => return fold(env_id, all_commits, facts, None, None, audit),
        Some(s) => s,
    };
    let corrupt = || Error::state("state_corrupt").with_detail("team_snapshot");
    let snapshot_obj = snapshot.as_object().ok_or_else(corrupt)?;
    // `base_vector = snapshot.get("vector") or {}`: a FALSY "vector" field
    // (absent, `null`, `0`, `""`, `[]`, `{}`) is `{}`, no error; a TRUTHY
    // one that isn't a JSON object has no Python `.get` equivalent
    // (`AttributeError`) -- but Python's list comprehension only ever
    // evaluates `base_vector.get(...)` once there is at least one commit to
    // check, so this mirrors that laziness rather than erroring up front
    // for an `all_commits` that happens to be empty.
    let vector_field = snapshot_obj.get("vector");
    let mut later: Vec<Commit> = Vec::with_capacity(all_commits.len());
    for c in all_commits {
        let floor = match vector_field {
            None => None,
            Some(v) if json_falsy(v) => None,
            Some(Value::Object(m)) => m.get(&c.author),
            Some(_) => return Err(corrupt()),
        };
        if author_seq_is_later(c.author_seq, floor)? {
            later.push(c);
        }
    }
    let base_document = snapshot_obj.get("document").cloned();
    let base_version_order = parse_snapshot_version_order(snapshot_obj.get("version_order"))?;
    fold(
        env_id,
        later,
        facts,
        base_document,
        base_version_order,
        audit,
    )
}

// --------------------------------------------------------------------- derive
fn document_connection_object(
    entry: &Map<String, Value>,
    secret_version: Option<i64>,
) -> Result<policy::Connection> {
    let mut data = entry.clone();
    data.insert("policy_version".into(), json!(0));
    data.insert(
        "secret_version".into(),
        match secret_version {
            Some(v) => json!(v),
            None => Value::Null,
        },
    );
    policy::Connection::from_value(&Value::Object(data))
}

fn connection_changed(before: &policy::Connection, after: &policy::Connection) -> bool {
    before.project != after.project
        || before.environment != after.environment
        || before.service != after.service
        || before.kind != after.kind
        || before.secret_id != after.secret_id
        || before.secret_version != after.secret_version
        || before.description != after.description
        || before.http_target != after.http_target
        || before.http_auth != after.http_auth
        || before.http_scope != after.http_scope
        || before.ssh_target != after.ssh_target
        || before.cli != after.cli
        || before.status != after.status
}

/// A copy of `c` with `policy_version`/`status`/`created_at`/`updated_at`
/// replaced (`status=None` keeps the existing one), re-validated through
/// `policy::Connection::new` exactly like Python's `dataclasses.replace` on
/// a frozen dataclass re-runs `__post_init__`. `policy::Connection`'s
/// private `with_changes` is not reachable from here (see the module doc
/// comment on the `build_connection_fields` reimplementation in `commit.rs`
/// for the analogous, already-reported visibility gap), so this rebuilds
/// through the public constructor instead.
#[allow(clippy::too_many_arguments)]
fn connection_with(
    c: &policy::Connection,
    policy_version: i64,
    status: Option<&str>,
    created_at: &str,
    updated_at: &str,
) -> Result<policy::Connection> {
    policy::Connection::new(
        c.id.clone(),
        c.project.clone(),
        c.environment.clone(),
        c.service.clone(),
        c.kind.clone(),
        c.secret_id.clone(),
        c.secret_version,
        c.description.clone(),
        c.http_target.clone(),
        c.http_auth.clone(),
        c.http_scope.clone(),
        c.ssh_target.clone(),
        c.cli.clone(),
        policy_version,
        status.unwrap_or(&c.status).to_string(),
        created_at.to_string(),
        updated_at.to_string(),
    )
}

fn derive_connections(
    document: &Map<String, Value>,
    state: &StateDir,
    env_id: &str,
    version_index: &BTreeMap<String, BTreeMap<String, i64>>,
    policy: &policy::Policy,
    audit: Option<&Audit>,
) -> Result<()> {
    let mut local: Map<String, Value> = match state.read_json(policy::CONNECTIONS, json!({}))? {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    let now_iso = crate::store::iso(None);
    let mut seen_ids: HashSet<String> = HashSet::new();
    let connections = document
        .get("connections")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (conn_id, entry_val) in &connections {
        seen_ids.insert(conn_id.clone());
        let entry = match entry_val.as_object() {
            Some(e) => e,
            None => continue,
        };
        let existing_raw = local.get(conn_id).and_then(Value::as_object).cloned();
        if let Some(existing) = &existing_raw
            && existing.get("shared_env").and_then(Value::as_str) != Some(env_id)
        {
            if let Some(audit) = audit {
                audit.record(
                    "team_op_skipped",
                    RecordArgs {
                        result: Some("skipped"),
                        reason: Some("local_id_conflict"),
                        extra: vec![("env_id", json!(env_id)), ("detail", json!("connection"))],
                        ..Default::default()
                    },
                )?;
            }
            continue;
        }
        let secret_id = entry
            .get("secret_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let raw_version = entry.get("secret_version").and_then(Value::as_str);
        let local_version = raw_version.and_then(|v| {
            version_index
                .get(&secret_id)
                .and_then(|m| m.get(v))
                .copied()
        });
        let mut after = document_connection_object(entry, local_version)?;
        if let Some(existing) = &existing_raw {
            let before = policy::Connection::from_value(&Value::Object(existing.clone()))?;
            if connection_changed(&before, &after) {
                let widened = policy::Policy::widens(&before, &after)
                    || (after.status == "disabled" && before.status == "active");
                // Panic sweep: `before.policy_version` is read straight back
                // off `policy/connections.json` (`policy::Connection::
                // from_value`, a local STATE FILE this crate must treat as
                // untrusted per PORTING.md §4), not something this crate's
                // own writers ever push near `i64::MAX` in practice -- but a
                // hand-edited/bit-rotted file claiming exactly that value
                // would otherwise panic here (`attempt to add with
                // overflow`) the next time this connection's definition
                // changes. `saturating_add` avoids that unconditionally.
                let new_version = before.policy_version.saturating_add(1);
                after = connection_with(&after, new_version, None, &before.created_at, &now_iso)?;
                policy.reevaluate_grants(conn_id, new_version, widened, local_version)?;
                let reason = if after.status == "disabled" {
                    "connection_disabled"
                } else {
                    "policy_changed"
                };
                let cid = conn_id.clone();
                policy.invalidate_approvals(
                    move |e| e.get("connection").and_then(Value::as_str) == Some(cid.as_str()),
                    reason,
                )?;
            } else {
                after = connection_with(
                    &after,
                    before.policy_version,
                    None,
                    &before.created_at,
                    &before.updated_at,
                )?;
            }
        } else {
            let created_at = entry
                .get("created_at")
                .and_then(Value::as_str)
                .unwrap_or(&now_iso)
                .to_string();
            after = connection_with(&after, 1, None, &created_at, &now_iso)?;
        }
        let mut raw = after.to_value();
        if let Value::Object(o) = &mut raw {
            o.insert("shared_env".into(), json!(env_id));
        }
        local.insert(conn_id.clone(), raw);
    }
    // A connection this node previously derived from THIS environment can
    // vanish from the folded document on a later fold even though nothing
    // removed it directly (an out-of-band `connection_disabled` FACT):
    // treat that exactly like an ordinary disable.
    let stale_ids: Vec<String> = local
        .iter()
        .filter(|(conn_id, existing_raw)| {
            let obj = match existing_raw.as_object() {
                Some(o) => o,
                None => return false,
            };
            obj.get("shared_env").and_then(Value::as_str) == Some(env_id)
                && !seen_ids.contains(conn_id.as_str())
                && obj.get("status").and_then(Value::as_str) != Some("disabled")
        })
        .map(|(k, _)| k.clone())
        .collect();
    for conn_id in stale_ids {
        let existing_raw = local
            .get(&conn_id)
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let before = policy::Connection::from_value(&Value::Object(existing_raw))?;
        let after = connection_with(
            &before,
            // Panic sweep: same `saturating_add` reasoning as the sibling
            // call above (a state-file-supplied `policy_version` near
            // `i64::MAX` must not panic).
            before.policy_version.saturating_add(1),
            Some("disabled"),
            &before.created_at,
            &now_iso,
        )?;
        policy.reevaluate_grants(&conn_id, after.policy_version, true, None)?;
        let cid = conn_id.clone();
        policy.invalidate_approvals(
            move |e| e.get("connection").and_then(Value::as_str) == Some(cid.as_str()),
            "connection_disabled",
        )?;
        let mut raw = after.to_value();
        if let Value::Object(o) = &mut raw {
            o.insert("shared_env".into(), json!(env_id));
        }
        local.insert(conn_id, raw);
    }
    state.write_json(policy::CONNECTIONS, &Value::Object(local))?;
    Ok(())
}

fn derive_vault(
    document: &Map<String, Value>,
    state: &StateDir,
    env_id: &str,
    version_index: &BTreeMap<String, BTreeMap<String, i64>>,
    audit: Option<&Audit>,
    project: Option<&str>,
    environment: Option<&str>,
) -> Result<()> {
    let doc_val = state.read_json(vault::VAULT_DOC, Value::Null)?;
    if json_falsy(&doc_val) {
        return Ok(()); // local vault not initialized; nothing to derive into
    }
    let mut doc = match doc_val {
        Value::Object(m) => m,
        _ => return Ok(()),
    };
    // F7: must satisfy projects.NAME_RE (no ":") so `secret list --project`
    // and friends work on derived entries.
    let after_dash = match env_id.split_once('-') {
        Some((_, rest)) => rest,
        None => env_id,
    };
    let default_project: String =
        format!("shared-{}", after_dash.chars().take(8).collect::<String>());
    let project = project
        .filter(|p| !p.is_empty())
        .unwrap_or(&default_project);
    let environment = environment.filter(|e| !e.is_empty()).unwrap_or("shared");
    // Finding H-R4-8: Python's `secrets_doc = doc.setdefault("secrets", {})`
    // only installs the `{}` default when the key is ABSENT -- a PRESENT
    // but non-dict value (a corrupt `vault/secrets.json`'s "secrets" field:
    // a string, number, bool, array or null) is returned AS-IS, and the
    // very next line's `secrets_doc.get(secret_id)` then raises an
    // uncaught `AttributeError` (only a dict has `.get`) BEFORE this
    // function ever reaches its `state.write_json` call at the end -- the
    // local vault file is left completely untouched. This used to
    // silently substitute an empty `Map` for ANY non-object value
    // (present-and-wrong-typed included, not just genuinely absent), so
    // `doc.insert("secrets", ...)` at the end OVERWROTE the corrupt field
    // with a fresh object built from only THIS environment's secrets --
    // destroying whatever the field held instead of leaving it alone the
    // way Python's uncaught exception does.
    let mut secrets_doc: Map<String, Value> = match doc.get("secrets") {
        None => Map::new(),
        Some(Value::Object(m)) => m.clone(),
        Some(_) => return Err(Error::state("state_corrupt").with_detail("vault_secrets")),
    };
    let secrets = document
        .get("secrets")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (secret_id, entry_val) in &secrets {
        let entry = match entry_val.as_object() {
            Some(e) => e,
            None => continue,
        };
        let existing = secrets_doc
            .get(secret_id)
            .and_then(Value::as_object)
            .cloned();
        if let Some(existing) = &existing
            && existing.get("shared_env").and_then(Value::as_str) != Some(env_id)
        {
            if let Some(audit) = audit {
                audit.record(
                    "team_op_skipped",
                    RecordArgs {
                        result: Some("skipped"),
                        reason: Some("local_id_conflict"),
                        extra: vec![("env_id", json!(env_id)), ("secret_id", json!(secret_id))],
                        ..Default::default()
                    },
                )?;
            }
            continue;
        }
        let vindex = version_index.get(secret_id).cloned().unwrap_or_default();
        let mut local_versions: Map<String, Value> = Map::new();
        let versions = entry
            .get("versions")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        for (version_id, record_val) in &versions {
            let record = match record_val.as_object() {
                Some(r) => r,
                None => continue,
            };
            let local_number = match vindex.get(version_id) {
                Some(n) => *n,
                None => continue,
            };
            let generation = record
                .get("generation")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !state.exists(&format!("team/{env_id}/dek/{generation}.json")) {
                if let Some(audit) = audit {
                    audit.record(
                        "team_op_skipped",
                        RecordArgs {
                            result: Some("skipped"),
                            reason: Some("generation_unavailable"),
                            extra: vec![("env_id", json!(env_id)), ("secret_id", json!(secret_id))],
                            ..Default::default()
                        },
                    )?;
                }
                continue;
            }
            let existing_created_at = existing
                .as_ref()
                .and_then(|e| e.get("versions"))
                .and_then(Value::as_object)
                .and_then(|v| v.get(&local_number.to_string()))
                .and_then(Value::as_object)
                .and_then(|v| v.get("created_at"))
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| crate::store::iso(None));
            local_versions.insert(
                local_number.to_string(),
                json!({
                    "nonce": record.get("nonce").cloned().unwrap_or(Value::Null),
                    "ciphertext": record.get("ciphertext").cloned().unwrap_or(Value::Null),
                    "created_at": existing_created_at,
                    "status": record.get("status").cloned().unwrap_or(Value::Null),
                    "public": record.get("public").and_then(Value::as_object).cloned().unwrap_or_default(),
                    "shared_env": env_id, "generation": generation, "version_id": version_id,
                }),
            );
        }
        let active_version_id = entry.get("active_version").and_then(Value::as_str);
        let mut active_number = active_version_id.and_then(|v| vindex.get(v).copied());
        if let Some(n) = active_number
            && !local_versions.contains_key(&n.to_string())
        {
            active_number = None;
        }
        let created_at = existing
            .as_ref()
            .and_then(|e| e.get("created_at"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| crate::store::iso(None));
        secrets_doc.insert(
            secret_id.clone(),
            json!({
                "project": project, "environment": environment,
                "kind": entry.get("kind").cloned().unwrap_or(Value::Null),
                "created_at": created_at,
                "active_version": active_number,
                "versions": local_versions,
                "shared_env": env_id,
            }),
        );
    }
    doc.insert("secrets".into(), Value::Object(secrets_doc));
    state.write_json(vault::VAULT_DOC, &Value::Object(doc))?;
    Ok(())
}

fn derive_dek_generations(
    document: &Map<String, Value>,
    state: &StateDir,
    kms: &(dyn Kms + Send + Sync),
    device: &DeviceKey,
    env_id: &str,
) -> Result<()> {
    let fp = device.fingerprint()?;
    let generations = document
        .get("dek")
        .and_then(Value::as_object)
        .and_then(|d| d.get("generations"))
        .and_then(Value::as_object);
    let generations = match generations {
        Some(g) => g,
        None => return Ok(()),
    };
    for (gen_id, generation) in generations {
        let my_wrap = generation
            .as_object()
            .and_then(|g| g.get("wraps"))
            .and_then(Value::as_object)
            .and_then(|w| w.get(&fp));
        let my_wrap = match my_wrap {
            Some(w) => w,
            None => continue,
        };
        let local_path = format!("team/{env_id}/dek/{gen_id}.json");
        if state.exists(&local_path) {
            continue;
        }
        let dek = match envelope::unwrap_dek(my_wrap, env_id, gen_id, device) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let wrapped = kms.wrap(&dek)?;
        state.write_json(&local_path, &wrapped.to_dict())?;
    }
    Ok(())
}

/// `zeropw.team.fold.derive_local`: write this node's derived
/// connections/vault entries for one shared environment (section 6.5). See
/// the module doc comment for why this takes `kms` rather than `vault`.
///
/// Always recomputed from `fold_result.document` in fold order; never reads
/// back anything it wrote on a previous call except to decide whether a
/// connection's *effective* definition changed (for the policy-version bump
/// and stale/re-evaluate decision). Returns the `{secret_id: {version_id:
/// local_int}}` map used to translate document version ids into the
/// node-local integer versions `Vault`/`Connection` already use everywhere
/// else.
#[allow(clippy::too_many_arguments)]
pub fn derive_local(
    fold_result: &FoldResult,
    state: &StateDir,
    policy: &policy::Policy,
    audit: Option<&Audit>,
    device: Option<&DeviceKey>,
    kms: Option<&(dyn Kms + Send + Sync)>,
    project: Option<&str>,
    environment: Option<&str>,
) -> Result<BTreeMap<String, BTreeMap<String, i64>>> {
    let document = fold_result
        .document
        .as_object()
        .ok_or_else(|| Error::state("state_corrupt").with_detail("team_document"))?;
    let env_id = document
        .get("env_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let mut version_index: BTreeMap<String, BTreeMap<String, i64>> = BTreeMap::new();
    for (sid, order) in &fold_result.version_order {
        let mut m = BTreeMap::new();
        for (i, vid) in order.iter().enumerate() {
            m.insert(vid.clone(), (i + 1) as i64);
        }
        version_index.insert(sid.clone(), m);
    }
    {
        let _lock = state.lock()?;
        // F1: derive this node's local copies of every DEK generation it
        // can unwrap BEFORE deriving vault entries, so `derive_vault` can
        // tell (by the presence of that file) which shared secret versions
        // it is actually able to decrypt.
        if let (Some(device), Some(kms)) = (device, kms) {
            derive_dek_generations(document, state, kms, device, &env_id)?;
        }
        derive_vault(
            document,
            state,
            &env_id,
            &version_index,
            audit,
            project,
            environment,
        )?;
        derive_connections(document, state, &env_id, &version_index, policy, audit)?;
    }
    if let Some(audit) = audit {
        // F6: count commits folded, not ops skipped (which get their own
        // `team_op_skipped` records). Finding H-R2-6 (round 2): Python's
        // `sum(fold_result.vector.values())` is arbitrary-precision and
        // never overflows; summing `FoldResult::vector`'s now-`i128`
        // entries into an `i64` PANICKED (`attempt to add with overflow`)
        // for as few as two authors each holding a large `author_seq` --
        // a panic on file-supplied data (an `all_commits()`-read
        // `author_seq`, or a snapshot `vector` entry), which PORTING.md
        // forbids. Widened `count` to `i128` to fix it.
        //
        // **Round-3 correction (finding H-R3-7):** that fix was incomplete,
        // and its own reasoning above ("the sum cannot overflow for any
        // input this crate's own `i128`-bounded `author_seq` can produce")
        // was wrong: TWO values that are each individually within `i128`
        // can still overflow `i128` when ADDED together -- two authors each
        // at `author_seq == i128::MAX` (reachable from two real commit
        // files, since `author_seq` is read verbatim at `i128` width) still
        // panicked on `.sum()`'s plain `+`. The round-2 test only probed
        // `i64::MAX`-sized values, which fit comfortably in `i128` and never
        // exercised this. `saturating_add` (via `fold`, not `.sum()`)
        // removes the panic unconditionally; the audited `count` saturates
        // at `i128::MAX` in the (astronomically unrealistic) case where the
        // true arbitrary-precision sum would exceed it, same as every other
        // `i128`-bounded field in this crate.
        let count: i128 = fold_result
            .vector
            .values()
            .fold(0i128, |acc, v| acc.saturating_add(*v));
        audit.record(
            "team_commit_apply",
            RecordArgs {
                result: Some("ok"),
                extra: vec![("env_id", json!(env_id)), ("count", json_int128(count))],
                ..Default::default()
            },
        )?;
    }
    Ok(version_index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pyjson;
    use crate::team::envelope;
    use crate::team::identity::DeviceKey;
    use std::collections::BTreeMap as Map2;
    use tempfile::TempDir;

    const GEN0: &str = "0000000000000000";
    const BOOTSTRAP_SECRET_VALUE: &[u8] = b"synthetic-bootstrap-placeholder-secret";
    const SYNTHETIC_SECRET: &[u8] = b"synthetic-shared-secret-0123456789";

    fn random_hex(n: usize) -> String {
        use rand::RngCore;
        let mut buf = vec![0u8; n];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        hex::encode(buf)
    }

    fn env_init_commit(
        env_id: &str,
        owner: &DeviceKey,
        dek: &[u8],
        hlc: &str,
        name: &str,
        bootstrap_secret_id: Option<&str>,
    ) -> Commit {
        let record = owner.record().unwrap();
        let wrap = envelope::wrap_dek(dek, env_id, GEN0, &record).unwrap();
        let mut wraps = Map::new();
        wraps.insert(owner.fingerprint().unwrap(), wrap);
        let op_init = json!({"op": "env.init", "owner_device": record.to_dict(), "owner_name": name,
                            "generation_id": GEN0, "wraps": wraps});
        let mut ops = vec![op_init];
        if let Some(secret_id) = bootstrap_secret_id {
            let version_id = random_hex(8);
            let ct = envelope::encrypt_secret(
                dek,
                env_id,
                secret_id,
                &version_id,
                BOOTSTRAP_SECRET_VALUE,
            )
            .unwrap();
            ops.push(json!({"op": "secret.put_version", "secret_id": secret_id, "kind": "api_key",
                            "generation_id": GEN0, "version_id": version_id, "ciphertext": ct, "public": {}}));
        }
        commit::sign_commit(owner, env_id, 1, hlc, &Map2::new(), ops).unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn connection_create_commit_full(
        env_id: &str,
        author: &DeviceKey,
        seq: i128,
        hlc: &str,
        conn_id: &str,
        methods: Option<&[&str]>,
        paths: Option<&[&str]>,
        secret_id: &str,
    ) -> Commit {
        let scope = json!({
            "methods": methods.map(|m| m.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
            "path_prefixes": paths.map(|p| p.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
        });
        let op = json!({"op": "connection.create", "id": conn_id, "project": "demo", "environment": "dev",
                        "service": "github", "kind": "http", "secret_id": secret_id, "secret_version": null,
                        "description": "", "http_target": {"scheme": "https", "host": "api.github.com", "port": 443},
                        "http_auth": {"mode": "bearer"}, "http_scope": scope});
        commit::sign_commit(author, env_id, seq, hlc, &Map2::new(), vec![op]).unwrap()
    }

    fn connection_create_commit(
        env_id: &str,
        author: &DeviceKey,
        seq: i128,
        hlc: &str,
        conn_id: &str,
    ) -> Commit {
        connection_create_commit_full(
            env_id,
            author,
            seq,
            hlc,
            conn_id,
            Some(&["GET"]),
            Some(&["/repos"]),
            "gh-token",
        )
    }

    fn member_add_commit(
        env_id: &str,
        author: &DeviceKey,
        seq: i128,
        hlc: &str,
        new_device: &DeviceKey,
        role: &str,
    ) -> Commit {
        let op = json!({"op": "member.add", "device": new_device.record().unwrap().to_dict(),
                        "name": "bob", "role": role});
        commit::sign_commit(author, env_id, seq, hlc, &Map2::new(), vec![op]).unwrap()
    }

    fn doc_obj(result: &FoldResult) -> &Map<String, Value> {
        result.document.as_object().unwrap()
    }

    fn new_env(bootstrap_secret_id: Option<&str>) -> (DeviceKey, String, Vec<u8>, Commit) {
        let owner = DeviceKey::generate();
        let env_id = commit::new_env_id(&owner.fingerprint().unwrap()).unwrap();
        let dek: Vec<u8> = (0..32u8).collect();
        let c1 = env_init_commit(
            &env_id,
            &owner,
            &dek,
            "1000-0000",
            "alice",
            bootstrap_secret_id,
        );
        (owner, env_id, dek, c1)
    }

    // ------------------------------------------------------------- BasicFold
    #[test]
    fn env_init_sets_owner_and_generation() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let result = fold(&env_id, vec![c1], None, None, None, None).unwrap();
        let doc = doc_obj(&result);
        let fp = owner.fingerprint().unwrap();
        assert_eq!(doc.get("owner").unwrap(), &json!(fp));
        let members = doc.get("members").unwrap().as_object().unwrap();
        assert_eq!(members[&fp]["role"], json!("admin"));
        assert_eq!(doc["dek"]["current"], json!(GEN0));
        assert!(result.skipped.is_empty());
    }

    #[test]
    fn connection_create_by_admin_applies() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let c2 = connection_create_commit(&env_id, &owner, 2, "2000-0000", "gh");
        let result = fold(&env_id, vec![c1, c2], None, None, None, None).unwrap();
        let doc = doc_obj(&result);
        assert!(doc["connections"].as_object().unwrap().contains_key("gh"));
        assert!(result.skipped.is_empty());
    }

    // A-R5-3: a peer-supplied `hlc` on a `connection.create`/`update`/
    // `switch_credential`/`disable` commit whose `wall_ms / 1000` exceeds
    // what real `python3.12`'s `time.gmtime` can represent must abort the
    // whole `fold()` call with an `Err`, exactly like Python's own uncaught
    // `OverflowError`/`OSError` from `_commit_time` propagating out of
    // `fold()` (fold.py has no `try`/`except` anywhere between them) --
    // never silently fold in a fabricated date the way `Hlc::parse(...)
    // .unwrap_or(0) -> iso` used to before this fix. Live since work unit
    // H widened `Hlc`'s `wall_ms`/`counter` from `i64` to `i128` (a value
    // this far out of range no longer fails to parse at all, so it reaches
    // `commit_time` as a validly-parsed, merely astronomical, `wall_ms`).
    #[test]
    fn connection_create_with_hlc_past_gmtime_range_aborts_the_whole_fold() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let hlc = format!("{WALL_MS_GMTIME_FAILS_AT}-0000");
        let c2 = connection_create_commit(&env_id, &owner, 2, &hlc, "gh");
        let err = fold(&env_id, vec![c1, c2], None, None, None, None)
            .expect_err("a commit whose hlc python3.12 can't gmtime() must abort the whole fold");
        assert!(err.is(crate::errors::ErrorClass::StateError));
        assert_eq!(err.reason, "team_commit_time_out_of_range");
    }

    // A-R5-3 counterpart: the largest `wall_ms` real `python3.12`'s actual
    // `_commit_time` pipeline (`int(wall_ms) / 1000` as a float, then
    // `time.gmtime`) still accepts -- one millisecond under
    // `WALL_MS_GMTIME_FAILS_AT` -- must still fold successfully; the fix
    // must not be so conservative it rejects values Python itself renders
    // without complaint.
    #[test]
    fn connection_create_with_hlc_at_gmtime_range_boundary_still_folds() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let boundary_wall_ms = WALL_MS_GMTIME_FAILS_AT - 1;
        let hlc = format!("{boundary_wall_ms}-0000");
        let c2 = connection_create_commit(&env_id, &owner, 2, &hlc, "gh");
        let result = fold(&env_id, vec![c1, c2], None, None, None, None)
            .expect("a wall_ms at the real gmtime boundary must still fold");
        let doc = doc_obj(&result);
        assert!(doc["connections"].as_object().unwrap().contains_key("gh"));
        assert!(result.skipped.is_empty());
    }

    /// Finding H-R3-2: `op_connection_disable` used to call `commit_time`
    /// BEFORE looking the connection up, so a `connection.disable` op for a
    /// non-existent id, from a commit whose `hlc` is past
    /// `WALL_MS_GMTIME_FAILS_AT`, aborted the WHOLE fold via `commit_time`'s
    /// `Err` -- where Python's `_op_connection_disable` only calls
    /// `_commit_time` after its `not _is_admin`/`connection_not_found`
    /// checks, so it never even reaches `_commit_time` for this op and
    /// simply skips it with `connection_not_found`, folding fine. A single
    /// peer commit could stop every node. This confirms real `python3.12`'s
    /// `_op_connection_disable` really does return `"connection_not_found"`
    /// (not raise) for exactly this shape, then confirms Rust's fold
    /// (through the public `fold()` entry point, not the private handler)
    /// now agrees: skips the op, does not abort.
    #[test]
    fn connection_disable_for_missing_id_skips_even_with_hlc_past_gmtime_range() {
        let huge_wall_ms = WALL_MS_GMTIME_FAILS_AT + 12345;
        let script = format!(
            r#"
from types import SimpleNamespace
from zeropw.team import fold as F

doc = F.new_document("env")
doc["owner"] = "owner-fp"
doc["members"]["owner-fp"] = {{"name": "o", "role": "admin", "status": "active", "device": {{}}}}
commit = SimpleNamespace(author="owner-fp", hlc="{huge_wall_ms}-0000")
facts = F.Facts()
op = {{"op": "connection.disable", "id": "missing"}}
print(F._op_connection_disable(doc, commit, facts, op))
"#
        );
        let py_reason = crate::oracle::python(&script);
        assert_eq!(
            py_reason.trim(),
            "connection_not_found",
            "real python3.12 must skip (not raise) for a connection.disable of a missing id, \
             even with an hlc past gmtime's range"
        );

        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let hlc = format!("{huge_wall_ms}-0000");
        let op = json!({"op": "connection.disable", "id": "missing"});
        let c2 = commit::sign_commit(&owner, &env_id, 2, &hlc, &BTreeMap::new(), vec![op]).unwrap();
        let result = fold(&env_id, vec![c1, c2], None, None, None, None)
            .expect("must skip the op and fold successfully, not abort the whole fold");
        assert_eq!(result.skipped.len(), 1);
        assert_eq!(result.skipped[0].2, "connection_not_found");
    }

    /// Finding H-R3-4: `validate_document_shape` used to check only the
    /// TOP-level container types, so a `base_document` with `secrets.s1 = 5`
    /// (an object where the value isn't even an object at all) passed it
    /// and then PANICKED at `op_secret_put_version`'s
    /// `entry.as_object_mut().expect("secret entry is always an object")` --
    /// a panic on file-supplied (snapshot) data, which PORTING.md §4
    /// forbids. Confirms real `python3.12`'s equivalent -- `_op_secret_put_
    /// version` touching that same pre-existing, wrongly-shaped entry --
    /// really does raise an uncaught `TypeError` (not merely return a
    /// documented reason), then confirms `fold()` now returns a clean
    /// `state_corrupt` error instead of panicking, for both this shape and
    /// the sibling `secrets.s1.versions = 5` shape the same finding named.
    #[test]
    fn malformed_secret_entry_shapes_fail_closed_instead_of_panicking() {
        let confirm_python_raises = |doc_secrets_s1: &str| {
            let script = format!(
                r#"
from types import SimpleNamespace
from zeropw.team import fold as F

doc = F.new_document("env")
doc["owner"] = "owner-fp"
doc["members"]["owner-fp"] = {{"name": "o", "role": "admin", "status": "active", "device": {{}}}}
doc["dek"]["generations"]["g0"] = {{"wraps": {{}}}}
doc["dek"]["current"] = "g0"
doc["secrets"]["s1"] = {doc_secrets_s1}
commit = SimpleNamespace(author="owner-fp")
facts = F.Facts()
op = {{"op": "secret.put_version", "secret_id": "s1", "version_id": "v1",
      "generation_id": "g0", "kind": "api_key",
      "ciphertext": {{"nonce": "n", "ciphertext": "c"}}}}
try:
    F._op_secret_put_version(doc, commit, facts, op)
    print("OK")
except Exception as e:
    print(f"ERR {{type(e).__name__}}")
"#
            );
            let out = crate::oracle::python(&script);
            assert_eq!(
                out.trim(),
                "ERR TypeError",
                "real python3.12 must raise an uncaught TypeError for doc[\"secrets\"][\"s1\"] = {doc_secrets_s1}"
            );
        };
        confirm_python_raises("5");
        confirm_python_raises(r#"{"kind": "api_key", "active_version": None, "versions": 5}"#);

        let mut base = new_document("env");
        base.insert("owner".into(), json!("owner-fp"));
        base.insert(
            "members".into(),
            json!({"owner-fp": {"name": "o", "role": "admin", "status": "active", "device": {}}}),
        );

        let mut doc_bad_entry = Value::Object(base.clone());
        doc_bad_entry["secrets"]["s1"] = json!(5);
        let err = fold("env", vec![], None, Some(doc_bad_entry), None, None)
            .expect_err("a non-object secrets.s1 must fail closed, not panic");
        assert!(err.is(crate::errors::ErrorClass::StateError));
        assert_eq!(err.reason, "state_corrupt");

        let mut doc_bad_versions = Value::Object(base);
        doc_bad_versions["secrets"]["s1"] =
            json!({"kind": "api_key", "active_version": null, "versions": 5});
        let err = fold("env", vec![], None, Some(doc_bad_versions), None, None)
            .expect_err("a non-object secrets.s1.versions must fail closed, not panic");
        assert!(err.is(crate::errors::ErrorClass::StateError));
        assert_eq!(err.reason, "state_corrupt");
    }

    /// Finding H-R4-6: round 3's `validate_document_shape` fix above still
    /// missed seven further shapes that an op handler indexes
    /// UNCONDITIONALLY (a Python dict subscript, not `.get`), so each of
    /// these seven still passed validation and then let `fold()` complete
    /// SUCCESSFULLY with a wrong document, where Python raises an uncaught
    /// exception from the equivalent handler. For each case: (1) confirm
    /// real `python3.12`'s own handler, called directly against the exact
    /// same document (round-tripped through JSON so both languages parse
    /// byte-identical input), really does raise the claimed exception --
    /// not merely assumed from reading the source; (2) confirm `fold()` now
    /// returns `state_corrupt` up front (zero commits needed: the malformed
    /// shape is caught before any op is ever applied, same posture as the
    /// `malformed_secret_entry_shapes_fail_closed_instead_of_panicking` test
    /// above).
    #[test]
    fn seven_more_unconditionally_indexed_fields_fail_closed_instead_of_fail_open() {
        fn base_doc() -> Map<String, Value> {
            let mut doc = new_document("env");
            doc.insert("owner".into(), json!("owner-fp"));
            doc.insert(
                "members".into(),
                json!({"owner-fp": {"name": "o", "role": "admin", "status": "active", "device": {}}}),
            );
            doc.insert(
                "dek".into(),
                json!({"current": "g0", "generations": {"g0": {"wraps": {}}}}),
            );
            doc
        }

        let new_member_record = DeviceKey::generate().record().unwrap().to_dict();

        struct Case {
            label: &'static str,
            doc: Value,
            handler: &'static str,
            author: &'static str,
            op: Value,
            expected_python_exception: &'static str,
        }
        let cases: Vec<Case> = vec![
            {
                let mut doc = base_doc();
                doc.insert("connections".into(), json!({"c1": {}}));
                Case {
                    label: "connections.c1={} + connection.disable",
                    doc: Value::Object(doc),
                    handler: "_op_connection_disable",
                    author: "owner-fp",
                    op: json!({"op": "connection.disable", "id": "c1"}),
                    expected_python_exception: "KeyError",
                }
            },
            {
                let mut doc = base_doc();
                doc.insert("connections".into(), json!({"c1": {"status": "active"}}));
                Case {
                    label: "connection without created_at + connection.update",
                    doc: Value::Object(doc),
                    handler: "_op_connection_update",
                    author: "owner-fp",
                    op: json!({"op": "connection.update", "id": "c1"}),
                    expected_python_exception: "KeyError",
                }
            },
            {
                let mut doc = base_doc();
                doc.insert(
                    "members".into(),
                    json!({
                        "owner-fp": {"name": "o", "role": "admin", "status": "active", "device": {}},
                        "m2": {"name": "x"},
                    }),
                );
                Case {
                    label: "truthy members entry without status + settings.update",
                    doc: Value::Object(doc),
                    handler: "_op_settings_update",
                    author: "m2",
                    op: json!({"op": "settings.update", "sync_interval_seconds": 5}),
                    expected_python_exception: "KeyError",
                }
            },
            {
                let mut doc = base_doc();
                doc.insert("secrets".into(), json!({"s1": {"versions": {}}}));
                Case {
                    label: "secrets.s1={\"versions\":{}} + secret.put_version",
                    doc: Value::Object(doc),
                    handler: "_op_secret_put_version",
                    author: "owner-fp",
                    op: json!({"op": "secret.put_version", "secret_id": "s1", "version_id": "v1",
                               "generation_id": "g0", "kind": "api_key",
                               "ciphertext": {"nonce": "n", "ciphertext": "c"}}),
                    expected_python_exception: "KeyError",
                }
            },
            {
                let mut doc = base_doc();
                doc.insert(
                    "secrets".into(),
                    json!({"s1": {"kind": "api_key", "active_version": null, "versions": {"v1": 5}}}),
                );
                Case {
                    label: "secrets.s1.versions.v=5 + secret.activate",
                    doc: Value::Object(doc),
                    handler: "_op_secret_activate",
                    author: "owner-fp",
                    op: json!({"op": "secret.activate", "secret_id": "s1", "version_id": "v1"}),
                    expected_python_exception: "TypeError",
                }
            },
            {
                let mut doc = base_doc();
                doc.insert(
                    "secrets".into(),
                    json!({"s1": {"kind": "api_key", "versions": {"v1": {"status": "staged"}}}}),
                );
                Case {
                    label: "secret without active_version + secret.activate",
                    doc: Value::Object(doc),
                    handler: "_op_secret_activate",
                    author: "owner-fp",
                    op: json!({"op": "secret.activate", "secret_id": "s1", "version_id": "v1"}),
                    expected_python_exception: "KeyError",
                }
            },
            {
                let mut doc = base_doc();
                doc.insert(
                    "dek".into(),
                    json!({"current": "g0", "generations": {"g0": {}}}),
                );
                Case {
                    label: "dek.generations.g={} + member.add with wraps",
                    doc: Value::Object(doc),
                    handler: "_op_member_add",
                    author: "owner-fp",
                    op: json!({"op": "member.add", "device": new_member_record.clone(),
                               "name": "bob", "role": "user",
                               "wraps": {"g0": {"eph_pub": "a", "nonce": "b", "ciphertext": "c"}}}),
                    expected_python_exception: "KeyError",
                }
            },
        ];

        for case in &cases {
            let doc_text = pyjson::dumps(&case.doc, pyjson::DumpOptions::compact_sorted()).unwrap();
            let op_text = pyjson::dumps(&case.op, pyjson::DumpOptions::compact_sorted()).unwrap();
            let script = format!(
                r#"
import json
from types import SimpleNamespace
from zeropw.team import fold as F

doc = json.loads({doc_text:?})
commit = SimpleNamespace(author={author:?}, hlc="1000-0000")
facts = F.Facts()
op = json.loads({op_text:?})
try:
    F.{handler}(doc, commit, facts, op)
    print("OK")
except Exception as e:
    print(f"ERR {{type(e).__name__}}")
"#,
                doc_text = doc_text,
                author = case.author,
                op_text = op_text,
                handler = case.handler,
            );
            let out = crate::oracle::python(&script);
            assert_eq!(
                out.trim(),
                format!("ERR {}", case.expected_python_exception),
                "real python3.12's {} must raise an uncaught {} for case {:?}",
                case.handler,
                case.expected_python_exception,
                case.label,
            );

            let err = fold("env", vec![], None, Some(case.doc.clone()), None, None).expect_err(
                &format!("case {:?} must fail closed, not fold open", case.label),
            );
            assert!(
                err.is(crate::errors::ErrorClass::StateError),
                "case {:?}: expected StateError, got {:?}",
                case.label,
                err
            );
            assert_eq!(
                err.reason, "state_corrupt",
                "case {:?}: expected state_corrupt",
                case.label
            );
        }
    }

    /// Finding H-R4-5: Python's `fold()` keeps `_version_order` INSIDE `doc`
    /// while folding (`doc.setdefault("_version_order", {k: list(v) for k,
    /// v in (base_version_order or {}).items()})`), so if `base_document`
    /// ITSELF already carries a `_version_order` key (only reachable via a
    /// hand-edited or bit-rotted snapshot -- `save_snapshot` never writes
    /// one, since `fold()` always pops it first), `setdefault` sees the key
    /// already present and uses THAT value INSTEAD of the separate
    /// `base_version_order` argument entirely -- then `.pop()`s it back out
    /// before returning, so the returned document never contains it either
    /// way. This builds a `base_document` whose own stray `_version_order`
    /// deliberately DISAGREES with a separately-passed `base_version_order`
    /// argument, folds a `secret.put_version` commit that appends to it, and
    /// confirms against real `python3.12`'s own `fold()` on the identical
    /// input that (a) the DOCUMENT's value -- not the argument's -- is what
    /// gets appended to, and (b) `_version_order` never appears in either
    /// language's returned document.
    #[test]
    fn base_documents_own_version_order_wins_over_the_argument_and_is_popped_from_the_result() {
        let (owner, env_id, _dek, c1) = new_env(None);
        let base = fold(&env_id, vec![c1], None, None, None, None).unwrap();
        let mut doc = base.document.as_object().unwrap().clone();
        doc.insert(
            "secrets".into(),
            json!({"gh-token": {"kind": "api_key", "active_version": null,
                                "versions": {"v0": {"status": "staged", "generation": GEN0,
                                                     "nonce": "n0", "ciphertext": "c0", "public": {}}}}}),
        );
        doc.insert("_version_order".into(), json!({"gh-token": ["stray-v0"]}));
        let base_document = Value::Object(doc);

        let op = json!({"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
                        "generation_id": GEN0, "version_id": "2222222222222222",
                        "ciphertext": {"nonce": "n2", "ciphertext": "c2"}, "public": {}});
        let c2 =
            commit::sign_commit(&owner, &env_id, 2, "2000-0000", &Map2::new(), vec![op]).unwrap();

        let base_version_order_arg: BTreeMap<String, Vec<String>> =
            [("gh-token".to_string(), vec!["arg-v0".to_string()])]
                .into_iter()
                .collect();

        let result = fold(
            &env_id,
            vec![c2.clone()],
            None,
            Some(base_document.clone()),
            Some(base_version_order_arg),
            None,
        )
        .expect("must fold successfully, using the document's own _version_order");

        // The document's OWN `_version_order` must win over the separate
        // argument: appended-to `["stray-v0", "2222222222222222"]`, not
        // `["arg-v0", "2222222222222222"]`.
        assert_eq!(
            result.version_order.get("gh-token"),
            Some(&vec![
                "stray-v0".to_string(),
                "2222222222222222".to_string()
            ])
        );
        // The returned document must never contain `_version_order`.
        assert!(
            result
                .document
                .as_object()
                .unwrap()
                .get("_version_order")
                .is_none()
        );

        let base_text =
            pyjson::dumps(&base_document, pyjson::DumpOptions::compact_sorted()).unwrap();
        let c2_text = pyjson::dumps(&c2.to_dict(), pyjson::DumpOptions::compact_sorted()).unwrap();
        let script = format!(
            r#"
import json
from zeropw.team import commit as C
from zeropw.team import fold as F

base_document = json.loads({base_text:?})
c2 = C.Commit.from_dict(json.loads({c2_text:?}))
result = F.fold({env_id:?}, [c2], base_document=base_document,
                base_version_order={{"gh-token": ["arg-v0"]}})
print(json.dumps({{
    "version_order": result.version_order,
    "has_stray_key": "_version_order" in result.document,
}}, sort_keys=True))
"#,
        );
        let out = crate::oracle::python(&script);
        let py: Value = pyjson::loads(out.trim()).unwrap();
        assert_eq!(
            py["has_stray_key"],
            json!(false),
            "python3.12's own returned document must not contain _version_order either"
        );
        assert_eq!(
            py["version_order"]["gh-token"],
            json!(["stray-v0", "2222222222222222"]),
            "python3.12 itself must prefer the document's own _version_order over the separate argument"
        );
    }

    // A-R5-3: probes real `python3.12`'s `zeropw.team.fold._commit_time`
    // directly (not just `time.gmtime` in isolation) end to end for the
    // three cases this finding is about, and confirms Rust's `commit_time`
    // agrees on the accept/reject decision (and, where both accept, on the
    // exact rendered string) for the first two. `_commit_time` only ever
    // reads `commit.hlc`, so a `SimpleNamespace` stands in for a real
    // `Commit` here -- no signing/device-key machinery needed to exercise
    // this one function directly.
    #[test]
    fn commit_time_matches_python_end_to_end_for_the_gmtime_boundary() {
        let script = format!(
            r#"
from types import SimpleNamespace
from zeropw.team.fold import _commit_time

def probe(hlc):
    c = SimpleNamespace(hlc=hlc)
    try:
        return "OK " + _commit_time(c)
    except Exception as e:
        return "ERR " + type(e).__name__

print(probe("{boundary}-0000"))
print(probe("{over}-0000"))
print(probe("{huge}-0000"))
"#,
            boundary = WALL_MS_GMTIME_FAILS_AT - 1,
            over = WALL_MS_GMTIME_FAILS_AT,
            huge = "9".repeat(45),
        );
        let out = crate::oracle::python(&script);
        let mut lines = out.lines();

        // Case 1: one millisecond under the real cliff -- Python succeeds.
        let want_boundary = lines.next().unwrap();
        assert!(
            want_boundary.starts_with("OK "),
            "python3.12 should still accept wall_ms = WALL_MS_GMTIME_FAILS_AT - 1, got: {want_boundary}"
        );
        let want_rendered = want_boundary.strip_prefix("OK ").unwrap();
        let commit = Commit {
            format: String::new(),
            env_id: String::new(),
            author: String::new(),
            author_seq: 0,
            hlc: format!("{}-0000", WALL_MS_GMTIME_FAILS_AT - 1),
            ops: Vec::new(),
            seen: BTreeMap::new(),
            sig: String::new(),
        };
        let got_rendered = commit_time(&commit).expect("Rust should also accept this wall_ms");
        assert_eq!(
            got_rendered, want_rendered,
            "Rust and Python must render the identical timestamp at the real boundary"
        );

        // Case 2: exactly at the real cliff -- Python raises (OSError on
        // this platform), Rust must also refuse (not silently format a
        // bogus date).
        let want_over = lines.next().unwrap();
        assert!(
            want_over.starts_with("ERR "),
            "python3.12 should raise for wall_ms = WALL_MS_GMTIME_FAILS_AT, got: {want_over}"
        );
        let commit_over = Commit {
            hlc: format!("{WALL_MS_GMTIME_FAILS_AT}-0000"),
            ..commit
        };
        commit_time(&commit_over)
            .expect_err("Rust must also refuse wall_ms = WALL_MS_GMTIME_FAILS_AT");

        // Case 3: a wall_ms literal too large even for i128 -- Python's own
        // int()/1000 float division overflows (a different exception,
        // OverflowError, but still an uncaught one Python never recovers
        // from); Rust's Hlc::parse already refuses this literal outright.
        let want_huge = lines.next().unwrap();
        assert!(
            want_huge.starts_with("ERR "),
            "python3.12 should also raise for a wall_ms literal beyond i128, got: {want_huge}"
        );
        let commit_huge = Commit {
            hlc: format!("{}-0000", "9".repeat(45)),
            ..commit_over
        };
        commit_time(&commit_huge).expect_err("Rust must also refuse a wall_ms literal beyond i128");
    }

    /// Finding H-R3-1: `commit_time`'s `wall_ms as f64 / 1000.0` was TWO
    /// roundings (round `wall_ms` to the nearest `f64`, then divide by the
    /// exact `1000.0`), not Python's ONE correctly-rounded `int / int`
    /// division -- byte-different for many `wall_ms` values above `2^53`
    /// (where `wall_ms as f64` first loses precision), not just the one
    /// reviewer-supplied repro (`hlc = "9999999999999999-0000"`, where
    /// Python renders `...T17:46:39Z` and the old code rendered
    /// `...T17:46:40Z`). This pins the fix ([`divide_by_1000_like_python`])
    /// against real `python3.12`'s actual `_commit_time` at that repro
    /// value, at both ends of the `WALL_MS_GMTIME_FAILS_AT` boundary, and
    /// over 2,000 random `wall_ms` values spanning `2^53` up to the
    /// boundary (batched into a single Python subprocess call for speed).
    #[test]
    fn commit_time_matches_python_true_division_at_boundary_and_random_wall_ms() {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut wall_ms_values: Vec<i128> = vec![
            9_999_999_999_999_999, // the exact reviewer-supplied repro value
            (1u128 << 53) as i128,
            (1u128 << 53) as i128 + 1,
            WALL_MS_GMTIME_FAILS_AT - 1, // largest value Python still accepts
        ];
        for _ in 0..2000 {
            let low = 1u128 << 53;
            let high = WALL_MS_GMTIME_FAILS_AT as u128;
            let sample = rng.gen_range(low..high);
            wall_ms_values.push(sample as i128);
        }

        let py_list = wall_ms_values
            .iter()
            .map(|w| w.to_string())
            .collect::<Vec<_>>()
            .join(",\n");
        let script = format!(
            r#"
from zeropw.store import iso
values = [
{py_list}
]
for w in values:
    print(iso(w / 1000))
"#
        );
        let out = crate::oracle::python(&script);
        let py_lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            py_lines.len(),
            wall_ms_values.len(),
            "python3.12 must accept every one of these wall_ms values (all below the boundary)"
        );
        for (wall_ms, want) in wall_ms_values.iter().zip(py_lines.iter()) {
            let commit = Commit {
                format: String::new(),
                env_id: String::new(),
                author: String::new(),
                author_seq: 0,
                hlc: format!("{wall_ms}-0000"),
                ops: Vec::new(),
                seen: BTreeMap::new(),
                sig: String::new(),
            };
            let got = commit_time(&commit)
                .unwrap_or_else(|e| panic!("Rust must also accept wall_ms={wall_ms}: {e:?}"));
            assert_eq!(
                &got, want,
                "wall_ms={wall_ms}: Rust and Python must render the identical timestamp \
                 (single correctly-rounded division), not merely both succeed"
            );
        }
    }

    // A-R5-3, the other reachable shape of the same underlying hazard: a
    // `wall_ms` literal too large even for `i128` (which `Hlc::parse` is
    // now bounded to, per work unit H) can't be represented by Python's
    // `Hlc.parse` either in a way that reaches `_commit_time` cleanly --
    // Python's `int(wall_str)` parses it fine (arbitrary precision), but
    // `wall_ms / 1000` then raises `OverflowError: integer division result
    // too large for a float` before `_commit_time` ever calls `iso()` --
    // an uncaught exception that also aborts `fold()` in Python, just via a
    // different (still uncaught) exception. `fold()` already aborts for
    // this shape today (via `sort_total_order`'s own `Hlc::parse` call,
    // before the per-op loop ever starts, since `Hlc::parse` rejects a
    // literal beyond `i128`'s range as malformed) -- confirmed here as
    // already-correct behaviour, not a new code path this fix adds.
    #[test]
    fn connection_create_with_hlc_wall_ms_beyond_i128_also_aborts_the_whole_fold() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        // 45 digits: comfortably beyond i128::MAX (39 digits).
        let huge = "9".repeat(45);
        let hlc = format!("{huge}-0000");
        let c2 = connection_create_commit(&env_id, &owner, 2, &hlc, "gh");
        let err = fold(&env_id, vec![c1, c2], None, None, None, None).expect_err(
            "a wall_ms literal too large for i128 must also abort the whole fold, like Python's own OverflowError",
        );
        assert!(err.is(crate::errors::ErrorClass::InvalidInput));
        assert_eq!(err.reason, "hlc_malformed");
    }

    #[test]
    fn env_init_only_valid_as_first_commit() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let c2 = connection_create_commit(&env_id, &owner, 2, "2000-0000", "gh");
        let forged_init = commit::sign_commit(
            &owner,
            &env_id,
            3,
            "3000-0000",
            &Map2::new(),
            vec![json!({"op": "env.init", "owner_device": owner.record().unwrap().to_dict(),
                        "owner_name": "mallory", "generation_id": "1".repeat(16),
                        "wraps": {owner.fingerprint().unwrap(): {"eph_pub": "AA", "nonce": "AA", "ciphertext": "AA"}}})],
        )
        .unwrap();
        let result2 = fold(&env_id, vec![c1, c2, forged_init], None, None, None, None).unwrap();
        assert_eq!(doc_obj(&result2)["dek"]["current"], json!(GEN0));
        assert!(
            result2
                .skipped
                .iter()
                .any(|(_, _, r)| r == "env_already_initialized")
        );
    }

    #[test]
    fn env_init_from_wrong_owner_skipped() {
        let (owner, env_id, dek, c1) = new_env(Some("gh-token"));
        let forger = DeviceKey::generate();
        let forger_record = forger.record().unwrap();
        let wrap = envelope::wrap_dek(&dek, &env_id, GEN0, &forger_record).unwrap();
        let mut wraps = Map::new();
        wraps.insert(forger.fingerprint().unwrap(), wrap);
        let forged = commit::sign_commit(
            &forger,
            &env_id,
            1,
            "0-0000",
            &Map2::new(),
            vec![json!({"op": "env.init", "owner_device": forger_record.to_dict(), "owner_name": "mallory",
                        "generation_id": GEN0, "wraps": wraps})],
        )
        .unwrap();
        let result = fold(&env_id, vec![forged, c1], None, None, None, None).unwrap();
        assert_eq!(
            doc_obj(&result)["owner"],
            json!(owner.fingerprint().unwrap())
        );
        assert!(
            result
                .skipped
                .iter()
                .any(|(_, _, r)| r == "env_init_wrong_owner")
        );
    }

    // --------------------------------------------------------- RoleBasedOps
    struct RoleFixture {
        owner: DeviceKey,
        env_id: String,
        user_device: DeviceKey,
        c1: Commit,
        c2: Commit,
    }

    fn role_fixture() -> RoleFixture {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let user_device = DeviceKey::generate();
        let c2 = member_add_commit(&env_id, &owner, 2, "2000-0000", &user_device, "user");
        RoleFixture {
            owner,
            env_id,
            user_device,
            c1,
            c2,
        }
    }

    fn role_fold(f: &RoleFixture, extra: Vec<Commit>) -> FoldResult {
        let mut commits = vec![f.c1.clone(), f.c2.clone()];
        commits.extend(extra);
        fold(&f.env_id, commits, None, None, None, None).unwrap()
    }

    #[test]
    fn user_cannot_create_connection() {
        let f = role_fixture();
        let bad = connection_create_commit(&f.env_id, &f.user_device, 1, "3000-0000", "gh");
        let result = role_fold(&f, vec![bad]);
        assert!(
            !doc_obj(&result)["connections"]
                .as_object()
                .unwrap()
                .contains_key("gh")
        );
        assert!(result.skipped.iter().any(|(_, _, r)| r == "not_admin"));
    }

    #[test]
    fn admin_can_create_connection() {
        let f = role_fixture();
        let good = connection_create_commit(&f.env_id, &f.owner, 3, "3000-0000", "gh");
        let result = role_fold(&f, vec![good]);
        assert!(
            doc_obj(&result)["connections"]
                .as_object()
                .unwrap()
                .contains_key("gh")
        );
    }

    #[test]
    fn user_cannot_add_member() {
        let f = role_fixture();
        let third = DeviceKey::generate();
        let bad = member_add_commit(&f.env_id, &f.user_device, 1, "3000-0000", &third, "user");
        let result = role_fold(&f, vec![bad]);
        assert!(
            !doc_obj(&result)["members"]
                .as_object()
                .unwrap()
                .contains_key(&third.fingerprint().unwrap())
        );
    }

    #[test]
    fn user_can_remove_self() {
        let f = role_fixture();
        let self_remove = commit::sign_commit(
            &f.user_device,
            &f.env_id,
            1,
            "3000-0000",
            &Map2::new(),
            vec![
                json!({"op": "member.remove", "fingerprint": f.user_device.fingerprint().unwrap()}),
            ],
        )
        .unwrap();
        let result = role_fold(&f, vec![self_remove]);
        assert_eq!(
            doc_obj(&result)["members"][&f.user_device.fingerprint().unwrap()]["status"],
            json!("removed")
        );
    }

    #[test]
    fn owner_cannot_be_removed_by_admin() {
        let f = role_fixture();
        let admin_device = DeviceKey::generate();
        let add_admin =
            member_add_commit(&f.env_id, &f.owner, 3, "3000-0000", &admin_device, "admin");
        let remove_owner = commit::sign_commit(
            &admin_device,
            &f.env_id,
            1,
            "4000-0000",
            &Map2::new(),
            vec![json!({"op": "member.remove", "fingerprint": f.owner.fingerprint().unwrap()})],
        )
        .unwrap();
        let result = role_fold(&f, vec![add_admin, remove_owner]);
        assert_eq!(
            doc_obj(&result)["members"][&f.owner.fingerprint().unwrap()]["status"],
            json!("active")
        );
        assert!(
            result
                .skipped
                .iter()
                .any(|(_, _, r)| r == "cannot_remove_owner")
        );
    }

    #[test]
    fn owner_transfer_only_by_owner() {
        let f = role_fixture();
        let admin_device = DeviceKey::generate();
        let add_admin =
            member_add_commit(&f.env_id, &f.owner, 3, "3000-0000", &admin_device, "admin");
        let bad_transfer = commit::sign_commit(
            &admin_device,
            &f.env_id,
            1,
            "4000-0000",
            &Map2::new(),
            vec![
                json!({"op": "owner.transfer", "fingerprint": admin_device.fingerprint().unwrap()}),
            ],
        )
        .unwrap();
        let result = role_fold(&f, vec![add_admin.clone(), bad_transfer]);
        assert_eq!(
            doc_obj(&result)["owner"],
            json!(f.owner.fingerprint().unwrap())
        );
        let good_transfer = commit::sign_commit(
            &f.owner,
            &f.env_id,
            3,
            "4000-0000",
            &Map2::new(),
            vec![
                json!({"op": "owner.transfer", "fingerprint": admin_device.fingerprint().unwrap()}),
            ],
        )
        .unwrap();
        let result2 = fold(
            &f.env_id,
            vec![f.c1.clone(), f.c2.clone(), add_admin, good_transfer],
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            doc_obj(&result2)["owner"],
            json!(admin_device.fingerprint().unwrap())
        );
    }

    // ------------------------------------------------------------- ClockSkew
    #[test]
    fn far_future_commit_deferred_then_released() {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        let owner = DeviceKey::generate();
        let env_id = commit::new_env_id(&owner.fingerprint().unwrap()).unwrap();
        let store = commit::CommitStore::new(&state, env_id.clone());
        let dek: Vec<u8> = (0..32u8).collect();
        let mut hlc = Hlc::default();
        let c1 = env_init_commit(
            &env_id,
            &owner,
            &dek,
            &hlc.tick(Some(1_000_000)),
            "alice",
            Some("gh-token"),
        );
        assert_eq!(
            commit::receive_commit(&store, &c1, 1_000_000, None).unwrap(),
            "accepted"
        );
        let far_future = 1_000_000 + commit::MAX_CLOCK_SKEW_MS + 30_000;
        let c2 = connection_create_commit(
            &env_id,
            &owner,
            2,
            &Hlc::default().tick(Some(far_future)),
            "gh",
        );
        assert_eq!(
            commit::receive_commit(&store, &c2, 1_000_000, None).unwrap(),
            "deferred"
        );
        assert_eq!(store.all_commits().unwrap(), vec![c1.clone()]);
        let released = store.release_deferred(far_future).unwrap();
        assert_eq!(
            released
                .iter()
                .map(|c| c.hash().unwrap())
                .collect::<Vec<_>>(),
            vec![c2.hash().unwrap()]
        );
        let result = fold(
            &env_id,
            store.all_commits().unwrap(),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(
            doc_obj(&result)["connections"]
                .as_object()
                .unwrap()
                .contains_key("gh")
        );
    }

    // ---------------------------------------------------- TotalOrderDeterminism
    fn build_total_order_commits() -> (String, Vec<Commit>) {
        let owner = DeviceKey::generate();
        let second = DeviceKey::generate();
        let env_id = commit::new_env_id(&owner.fingerprint().unwrap()).unwrap();
        let dek: Vec<u8> = (0..32u8).collect();
        let c1 = env_init_commit(
            &env_id,
            &owner,
            &dek,
            "1000-0000",
            "alice",
            Some("gh-token"),
        );
        let c2 = member_add_commit(&env_id, &owner, 2, "2000-0000", &second, "admin");
        let c3 = connection_create_commit(&env_id, &owner, 3, "3000-0000", "gh");
        let c4 = connection_create_commit(&env_id, &second, 1, "3000-0000", "gitlab");
        let c5 = commit::sign_commit(
            &owner,
            &env_id,
            4,
            "4000-0000",
            &Map2::new(),
            vec![json!({"op": "connection.disable", "id": "gh"})],
        )
        .unwrap();
        let c6 = commit::sign_commit(
            &second,
            &env_id,
            2,
            "5000-0000",
            &Map2::new(),
            vec![json!({"op": "settings.update", "sync_interval_seconds": 42})],
        )
        .unwrap();
        (env_id, vec![c1, c2, c3, c4, c5, c6])
    }

    #[test]
    fn random_arrival_orders_converge() {
        let (env_id, commits) = build_total_order_commits();
        let canonical_result = fold(&env_id, commits.clone(), None, None, None, None).unwrap();
        let canonical = pyjson::dumps(
            &canonical_result.document,
            pyjson::DumpOptions::compact_sorted(),
        )
        .unwrap();
        let canonical_skips: std::collections::HashSet<(String, usize, String)> =
            canonical_result.skipped.into_iter().collect();
        // A handful of deterministic pseudo-random shuffles (xorshift-based
        // Fisher-Yates; no external shuffling dependency needed for a fixed,
        // small permutation check like this).
        let mut seeds = [0x1u64, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];
        for seed in seeds.iter_mut() {
            let mut shuffled = commits.clone();
            for i in (1..shuffled.len()).rev() {
                *seed ^= *seed << 13;
                *seed ^= *seed >> 7;
                *seed ^= *seed << 17;
                let j = (*seed as usize) % (i + 1);
                shuffled.swap(i, j);
            }
            let result = fold(&env_id, shuffled, None, None, None, None).unwrap();
            let as_json =
                pyjson::dumps(&result.document, pyjson::DumpOptions::compact_sorted()).unwrap();
            assert_eq!(as_json, canonical, "shuffle diverged");
            let skips: std::collections::HashSet<(String, usize, String)> =
                result.skipped.into_iter().collect();
            assert_eq!(skips, canonical_skips);
        }
    }

    /// The 6 permutations of a 3-element `Vec`, hand-rolled rather than
    /// pulling in `itertools` for one small, fixed-size test.
    fn permutations3<T: Clone>(items: [T; 3]) -> Vec<Vec<T>> {
        let [a, b, c] = items;
        vec![
            vec![a.clone(), b.clone(), c.clone()],
            vec![a.clone(), c.clone(), b.clone()],
            vec![b.clone(), a.clone(), c.clone()],
            vec![b.clone(), c.clone(), a.clone()],
            vec![c.clone(), a.clone(), b.clone()],
            vec![c, b, a],
        ]
    }

    #[test]
    fn all_permutations_small_set_converge() {
        let owner = DeviceKey::generate();
        let env_id = commit::new_env_id(&owner.fingerprint().unwrap()).unwrap();
        let dek: Vec<u8> = (0..32u8).collect();
        let c1 = env_init_commit(
            &env_id,
            &owner,
            &dek,
            "1000-0000",
            "alice",
            Some("gh-token"),
        );
        let c2 = connection_create_commit(&env_id, &owner, 2, "2000-0000", "a");
        let c3 = connection_create_commit(&env_id, &owner, 3, "3000-0000", "b");
        let mut results = std::collections::HashSet::new();
        for perm in permutations3([c1, c2, c3]) {
            let result = fold(&env_id, perm, None, None, None, None).unwrap();
            results.insert(
                pyjson::dumps(&result.document, pyjson::DumpOptions::compact_sorted()).unwrap(),
            );
        }
        assert_eq!(results.len(), 1);
    }

    // ------------------------------------------------------------- FactsWin
    #[test]
    fn disabled_fact_blocks_create_regardless_of_order() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let c2 = connection_create_commit(&env_id, &owner, 2, "9999999999-0000", "gh");
        let facts = Facts {
            disabled_connections: ["gh".to_string()].into_iter().collect(),
            ..Default::default()
        };
        let result = fold(&env_id, vec![c1, c2], Some(&facts), None, None, None).unwrap();
        assert!(
            !doc_obj(&result)["connections"]
                .as_object()
                .unwrap()
                .contains_key("gh")
        );
    }

    #[test]
    fn member_removed_fact_blocks_readd() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let target = DeviceKey::generate();
        let c2 = member_add_commit(&env_id, &owner, 2, "2000-0000", &target, "user");
        let facts = Facts {
            removed_members: [target.fingerprint().unwrap()].into_iter().collect(),
            ..Default::default()
        };
        let result = fold(&env_id, vec![c1, c2], Some(&facts), None, None, None).unwrap();
        assert!(
            !doc_obj(&result)["members"]
                .as_object()
                .unwrap()
                .contains_key(&target.fingerprint().unwrap())
        );
    }

    #[test]
    fn revoked_version_fact_blocks_activate() {
        let (owner, env_id, dek, c1) = new_env(None);
        let version_id = "a".repeat(16);
        let ct = envelope::encrypt_secret(&dek, &env_id, "gh-token", &version_id, SYNTHETIC_SECRET)
            .unwrap();
        let c2 = commit::sign_commit(
            &owner,
            &env_id,
            2,
            "2000-0000",
            &Map2::new(),
            vec![json!({"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
                        "generation_id": GEN0, "version_id": version_id, "ciphertext": ct, "public": {}})],
        )
        .unwrap();
        let c3 = commit::sign_commit(
            &owner,
            &env_id,
            3,
            "3000-0000",
            &Map2::new(),
            vec![
                json!({"op": "secret.activate", "secret_id": "gh-token", "version_id": version_id}),
            ],
        )
        .unwrap();
        let facts = Facts {
            revoked_versions: [("gh-token".to_string(), version_id.clone())]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let result = fold(&env_id, vec![c1, c2, c3], Some(&facts), None, None, None).unwrap();
        let doc = doc_obj(&result);
        assert_eq!(
            doc["secrets"]["gh-token"]["versions"][&version_id]["status"],
            json!("revoked")
        );
        assert_eq!(doc["secrets"]["gh-token"]["active_version"], Value::Null);
        assert!(
            result
                .skipped
                .iter()
                .any(|(_, _, r)| r == "version_revoked")
        );
    }

    #[test]
    fn disable_then_later_create_same_id_skipped_within_one_fold() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let c2 = connection_create_commit(&env_id, &owner, 2, "2000-0000", "gh");
        let c3 = commit::sign_commit(
            &owner,
            &env_id,
            3,
            "3000-0000",
            &Map2::new(),
            vec![json!({"op": "connection.disable", "id": "gh"})],
        )
        .unwrap();
        let c4 = connection_create_commit(&env_id, &owner, 4, "4000-0000", "gh");
        let result = fold(&env_id, vec![c1, c2, c3, c4], None, None, None, None).unwrap();
        assert_eq!(
            doc_obj(&result)["connections"]["gh"]["status"],
            json!("disabled")
        );
        assert!(
            result
                .skipped
                .iter()
                .any(|(_, _, r)| r == "connection_id_taken")
        );
    }

    // ------------------------------------------------------------- Snapshot
    #[test]
    fn fold_from_snapshot_matches_full_fold() {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let c2 = connection_create_commit(&env_id, &owner, 2, "2000-0000", "a");
        let full_before = fold(
            &env_id,
            vec![c1.clone(), c2.clone()],
            None,
            None,
            None,
            None,
        )
        .unwrap();
        save_snapshot(&state, &env_id, 1, &full_before).unwrap();

        let c3 = connection_create_commit(&env_id, &owner, 3, "3000-0000", "b");
        let full = fold(
            &env_id,
            vec![c1.clone(), c2.clone(), c3.clone()],
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let from_snapshot =
            fold_with_snapshot(&env_id, vec![c1, c2, c3], &state, None, None).unwrap();

        assert_eq!(
            pyjson::dumps(&full.document, pyjson::DumpOptions::compact_sorted()).unwrap(),
            pyjson::dumps(
                &from_snapshot.document,
                pyjson::DumpOptions::compact_sorted()
            )
            .unwrap()
        );
        assert_eq!(full.version_order, from_snapshot.version_order);
    }

    /// Writes a hand-crafted `{directory}/1.json` snapshot file directly
    /// (bypassing [`save_snapshot`], which always writes a well-formed
    /// snapshot) so a test can control every field's shape independently.
    fn write_raw_snapshot(state: &StateDir, env_id: &str, content: &Value) {
        state
            .write_json(&format!("{}/1.json", snapshot_dir(env_id)), content)
            .unwrap();
    }

    fn new_state() -> (TempDir, StateDir) {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        (tmp, state)
    }

    /// Finding H-R4-7 (`document: null`): a snapshot object of the form
    /// `{"document": null, "vector": {...}, "version_order": {...}}` must
    /// fold from a FRESH document (`Value::Null` is Python's `None`, and
    /// `fold()`'s own `if base_document is not None` treats that exactly
    /// like an absent `base_document`) -- not fail `validate_document_
    /// shape`'s `.as_object()` check as `state_corrupt`. The snapshot's
    /// `vector` still applies (so `c1`, already reflected there, is
    /// filtered out of `later`): the result must equal folding ONLY `c2`
    /// from scratch, confirmed both directly and against real `python3.12`.
    #[test]
    fn snapshot_document_null_folds_from_a_fresh_document() {
        let (_tmp, state) = new_state();
        let (owner, env_id, _dek, c1) = new_env(None);
        let owner_fp = owner.fingerprint().unwrap();
        let snapshot = json!({"document": null, "vector": {owner_fp: 1}, "version_order": {}});
        write_raw_snapshot(&state, &env_id, &snapshot);

        let op = json!({"op": "settings.update", "sync_interval_seconds": 7});
        let c2 =
            commit::sign_commit(&owner, &env_id, 2, "2000-0000", &Map2::new(), vec![op]).unwrap();

        let from_snapshot =
            fold_with_snapshot(&env_id, vec![c1.clone(), c2.clone()], &state, None, None).unwrap();
        // Starting fresh, `c2` alone (no `env.init`) has no admin to apply
        // `settings.update` as, so it is silently skipped and the document
        // is the untouched default -- exactly what folding `[c2]` fresh
        // (no snapshot at all) produces too.
        let expected = fold(&env_id, vec![c2.clone()], None, None, None, None).unwrap();
        let from_snapshot_text = pyjson::dumps(
            &from_snapshot.document,
            pyjson::DumpOptions::compact_sorted(),
        )
        .unwrap();
        assert_eq!(
            pyjson::dumps(&expected.document, pyjson::DumpOptions::compact_sorted()).unwrap(),
            from_snapshot_text,
        );

        let script = format!(
            r#"
import json, tempfile
from pathlib import Path
from zeropw.store import StateDir
from zeropw.team import commit as C
from zeropw.team import fold as F

with tempfile.TemporaryDirectory() as tmp:
    state = StateDir(Path(tmp) / "state")
    state.create()
    state.write_json("team/{env_id}/snapshots/1.json", json.loads({snapshot_text:?}))
    c1 = C.Commit.from_dict(json.loads({c1_text:?}))
    c2 = C.Commit.from_dict(json.loads({c2_text:?}))
    result = F.fold_with_snapshot({env_id:?}, [c1, c2], state)
    print(json.dumps(result.document, sort_keys=True, separators=(",", ":")))
"#,
            env_id = env_id,
            snapshot_text =
                pyjson::dumps(&snapshot, pyjson::DumpOptions::compact_sorted()).unwrap(),
            c1_text = pyjson::dumps(&c1.to_dict(), pyjson::DumpOptions::compact_sorted()).unwrap(),
            c2_text = pyjson::dumps(&c2.to_dict(), pyjson::DumpOptions::compact_sorted()).unwrap(),
        );
        let py_document_text = crate::oracle::python(&script);
        assert_eq!(py_document_text.trim(), from_snapshot_text);
    }

    /// Finding H-R4-7 (non-object snapshot): Python's `snapshot.get(...)`
    /// raises `AttributeError` for a snapshot whose top-level content is
    /// not a dict -- confirmed here for an array -- and is NOT `None`
    /// (`fold_with_snapshot`'s own `if snapshot is None:` only intercepts
    /// the exact JSON `null` case). `fold()` used to silently ignore the
    /// whole snapshot (every field defaulted) and fold successfully with a
    /// wrong document; now it fails closed with `state_corrupt`.
    #[test]
    fn snapshot_non_object_fails_closed_matching_pythons_attributeerror() {
        let (_tmp, state) = new_state();
        let (_owner, env_id, _dek, c1) = new_env(None);
        write_raw_snapshot(&state, &env_id, &json!([1, 2, 3]));

        let err = fold_with_snapshot(&env_id, vec![c1.clone()], &state, None, None)
            .expect_err("a non-object snapshot must fail closed, not silently fold");
        assert!(err.is(crate::errors::ErrorClass::StateError));
        assert_eq!(err.reason, "state_corrupt");

        let script = format!(
            r#"
import json, tempfile
from pathlib import Path
from zeropw.store import StateDir
from zeropw.team import commit as C
from zeropw.team import fold as F

with tempfile.TemporaryDirectory() as tmp:
    state = StateDir(Path(tmp) / "state")
    state.create()
    state.write_json("team/{env_id}/snapshots/1.json", [1, 2, 3])
    c1 = C.Commit.from_dict(json.loads({c1_text:?}))
    try:
        F.fold_with_snapshot({env_id:?}, [c1], state)
        print("OK")
    except Exception as e:
        print(f"ERR {{type(e).__name__}}")
"#,
            env_id = env_id,
            c1_text = pyjson::dumps(&c1.to_dict(), pyjson::DumpOptions::compact_sorted()).unwrap(),
        );
        let out = crate::oracle::python(&script);
        assert_eq!(
            out.trim(),
            "ERR AttributeError",
            "real python3.12 must raise an uncaught AttributeError for a non-dict snapshot"
        );
    }

    /// Finding H-R4-7 (`version_order[sid]` shapes): a non-array entry
    /// value (Python's `list(v)` on a non-iterable, e.g. a plain number,
    /// raises `TypeError`) and a non-object `version_order` field entirely
    /// (Python's `.items()` on a non-dict raises `AttributeError`) both
    /// used to be silently dropped/ignored; now both fail closed.
    #[test]
    fn snapshot_version_order_bad_shapes_fail_closed() {
        let (_tmp, state) = new_state();
        let (_owner, env_id, _dek, c1) = new_env(None);

        // `version_order["sid"]` is a plain number, not an array.
        let snapshot = json!({"document": null, "vector": {}, "version_order": {"sid": 5}});
        write_raw_snapshot(&state, &env_id, &snapshot);
        let err = fold_with_snapshot(&env_id, vec![c1.clone()], &state, None, None)
            .expect_err("a non-array version_order entry must fail closed");
        assert!(err.is(crate::errors::ErrorClass::StateError));
        assert_eq!(err.reason, "state_corrupt");
        let script = format!(
            r#"
import json, tempfile
from pathlib import Path
from zeropw.store import StateDir
from zeropw.team import commit as C
from zeropw.team import fold as F

with tempfile.TemporaryDirectory() as tmp:
    state = StateDir(Path(tmp) / "state")
    state.create()
    state.write_json("team/{env_id}/snapshots/1.json", json.loads({snapshot_text:?}))
    c1 = C.Commit.from_dict(json.loads({c1_text:?}))
    try:
        F.fold_with_snapshot({env_id:?}, [c1], state)
        print("OK")
    except Exception as e:
        print(f"ERR {{type(e).__name__}}")
"#,
            env_id = env_id,
            snapshot_text =
                pyjson::dumps(&snapshot, pyjson::DumpOptions::compact_sorted()).unwrap(),
            c1_text = pyjson::dumps(&c1.to_dict(), pyjson::DumpOptions::compact_sorted()).unwrap(),
        );
        let out = crate::oracle::python(&script);
        assert_eq!(
            out.trim(),
            "ERR TypeError",
            "real python3.12 must raise an uncaught TypeError for list(5)"
        );

        // `version_order` itself is a truthy non-object (an array).
        let snapshot2 = json!({"document": null, "vector": {}, "version_order": [1, 2]});
        write_raw_snapshot(&state, &env_id, &snapshot2);
        let err = fold_with_snapshot(&env_id, vec![c1.clone()], &state, None, None)
            .expect_err("a non-object version_order must fail closed");
        assert!(err.is(crate::errors::ErrorClass::StateError));
        assert_eq!(err.reason, "state_corrupt");
        let script2 = format!(
            r#"
import json, tempfile
from pathlib import Path
from zeropw.store import StateDir
from zeropw.team import commit as C
from zeropw.team import fold as F

with tempfile.TemporaryDirectory() as tmp:
    state = StateDir(Path(tmp) / "state")
    state.create()
    state.write_json("team/{env_id}/snapshots/1.json", json.loads({snapshot_text:?}))
    c1 = C.Commit.from_dict(json.loads({c1_text:?}))
    try:
        F.fold_with_snapshot({env_id:?}, [c1], state)
        print("OK")
    except Exception as e:
        print(f"ERR {{type(e).__name__}}")
"#,
            env_id = env_id,
            snapshot_text =
                pyjson::dumps(&snapshot2, pyjson::DumpOptions::compact_sorted()).unwrap(),
            c1_text = pyjson::dumps(&c1.to_dict(), pyjson::DumpOptions::compact_sorted()).unwrap(),
        );
        let out2 = crate::oracle::python(&script2);
        assert_eq!(
            out2.trim(),
            "ERR AttributeError",
            "real python3.12 must raise an uncaught AttributeError for a non-dict version_order"
        );
    }

    /// Finding H-R4-7 (vector entry types): Python's `commit.author_seq >
    /// base_vector.get(commit.author, 0)` compares NUMERICALLY against a
    /// bool (`True == 1`) or a float (`1.5`, real value), and raises an
    /// uncaught `TypeError` for a numeric-STRING entry. All three used to
    /// silently become a floor of `0`, letting a replayed/duplicate commit
    /// through as if the snapshot had never covered it.
    #[test]
    fn snapshot_vector_entry_types_match_pythons_numeric_comparison() {
        let (_tmp, state) = new_state();
        let (owner, env_id, _dek, c1) = new_env(None);
        let base = fold(&env_id, vec![c1.clone()], None, None, None, None).unwrap();
        let base_document = base.document.clone();
        let owner_fp = owner.fingerprint().unwrap();
        let op = |n: i64| json!({"op": "settings.update", "sync_interval_seconds": n});
        let c2 = commit::sign_commit(&owner, &env_id, 2, "2000-0000", &Map2::new(), vec![op(2)])
            .unwrap();
        let c3 = commit::sign_commit(&owner, &env_id, 3, "3000-0000", &Map2::new(), vec![op(3)])
            .unwrap();

        // A bool floor of `true` (== 1): only `c2`/`c3` (seq 2, 3) are
        // later (`1 > True` is `1 > 1`, false); a floor of `false` (== 0)
        // lets `c1` back in too, but `c1` carries no `settings.update` op
        // so the observable last-applied value is unaffected either way.
        for (floor, expect_last) in [(json!(true), 3), (json!(false), 3)] {
            let snapshot = json!({"document": base_document, "vector": {owner_fp.clone(): floor},
                                  "version_order": {}});
            write_raw_snapshot(&state, &env_id, &snapshot);
            let result = fold_with_snapshot(
                &env_id,
                vec![c1.clone(), c2.clone(), c3.clone()],
                &state,
                None,
                None,
            )
            .expect("a bool vector floor must fold, not fail closed");
            let settings = result.document["settings"]["sync_interval_seconds"]
                .as_i64()
                .unwrap();
            assert_eq!(
                settings, expect_last,
                "bool floor {floor:?} must still apply the settings.update ops"
            );
        }

        // A float floor of `2.5`: `c2` (seq 2) is NOT later (`2 > 2.5` is
        // false), only `c3` (seq 3) is -- the settings value must be `3`
        // even though `c2`'s own op (value `2`) is excluded from this
        // fold, not merely overwritten by `c3`'s.
        let snapshot = json!({"document": base_document, "vector": {owner_fp.clone(): 2.5},
                              "version_order": {}});
        write_raw_snapshot(&state, &env_id, &snapshot);
        let result = fold_with_snapshot(
            &env_id,
            vec![c1.clone(), c2.clone(), c3.clone()],
            &state,
            None,
            None,
        )
        .expect("a float vector floor must fold, not fail closed");
        assert_eq!(
            result.document["settings"]["sync_interval_seconds"]
                .as_i64()
                .unwrap(),
            3
        );
        assert_eq!(
            result.skipped.len(),
            0,
            "c2 must be excluded by the floor, not included-then-skipped"
        );

        // A numeric-STRING floor: Python's `int > str` raises uncaught
        // `TypeError`, so this must fail closed instead of silently
        // treating it as `0`.
        let snapshot = json!({"document": base_document, "vector": {owner_fp.clone(): "1"},
                              "version_order": {}});
        write_raw_snapshot(&state, &env_id, &snapshot);
        let err = fold_with_snapshot(&env_id, vec![c1.clone()], &state, None, None)
            .expect_err("a numeric-string vector floor must fail closed");
        assert!(err.is(crate::errors::ErrorClass::StateError));
        assert_eq!(err.reason, "state_corrupt");

        // Cross-check all four (true/false/2.5/"1") against real
        // python3.12 in one subprocess.
        let cases = [
            ("true", json!(true)),
            ("false", json!(false)),
            ("2.5", json!(2.5)),
            ("\"1\"", json!("1")),
        ];
        for (label, floor) in cases {
            let snapshot = json!({"document": base_document, "vector": {owner_fp.clone(): floor},
                                  "version_order": {}});
            let script = format!(
                r#"
import json, tempfile
from pathlib import Path
from zeropw.store import StateDir
from zeropw.team import commit as C
from zeropw.team import fold as F

with tempfile.TemporaryDirectory() as tmp:
    state = StateDir(Path(tmp) / "state")
    state.create()
    state.write_json("team/{env_id}/snapshots/1.json", json.loads({snapshot_text:?}))
    c1 = C.Commit.from_dict(json.loads({c1_text:?}))
    c2 = C.Commit.from_dict(json.loads({c2_text:?}))
    c3 = C.Commit.from_dict(json.loads({c3_text:?}))
    try:
        result = F.fold_with_snapshot({env_id:?}, [c1, c2, c3], state)
        print("OK " + str(result.document["settings"]["sync_interval_seconds"]))
    except Exception as e:
        print(f"ERR {{type(e).__name__}}")
"#,
                env_id = env_id,
                snapshot_text =
                    pyjson::dumps(&snapshot, pyjson::DumpOptions::compact_sorted()).unwrap(),
                c1_text =
                    pyjson::dumps(&c1.to_dict(), pyjson::DumpOptions::compact_sorted()).unwrap(),
                c2_text =
                    pyjson::dumps(&c2.to_dict(), pyjson::DumpOptions::compact_sorted()).unwrap(),
                c3_text =
                    pyjson::dumps(&c3.to_dict(), pyjson::DumpOptions::compact_sorted()).unwrap(),
            );
            let out = crate::oracle::python(&script);
            let py_result = out.trim().to_string();
            write_raw_snapshot(&state, &env_id, &snapshot);
            let rust_result = match fold_with_snapshot(
                &env_id,
                vec![c1.clone(), c2.clone(), c3.clone()],
                &state,
                None,
                None,
            ) {
                Ok(r) => format!(
                    "OK {}",
                    r.document["settings"]["sync_interval_seconds"]
                        .as_i64()
                        .unwrap()
                ),
                Err(_) => "ERR StateError".to_string(),
            };
            match label {
                "\"1\"" => {
                    assert_eq!(py_result, "ERR TypeError", "python for floor {label}");
                    assert_eq!(rust_result, "ERR StateError", "rust for floor {label}");
                }
                _ => {
                    assert_eq!(
                        py_result, rust_result,
                        "rust/python must agree for vector floor {label}"
                    );
                }
            }
        }
    }
}
