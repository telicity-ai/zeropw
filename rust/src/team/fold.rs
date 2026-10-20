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
//! commit (if any) falls. A member removal is the exception to "from the
//! start": it takes effect at its own place in the total order
//! (`RemovalSchedule`, issue #27), so the removed member's earlier work
//! stands.
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
use crate::errors::{Error, ErrorClass, Result};
use crate::kms::Kms;
use crate::policy;
use crate::pyint::PyInt;
use crate::secret::SecretBytes;
use crate::store::StateDir;
use crate::vault;

use super::commit::{self, Commit, Hlc, env_owner_fingerprint, sort_total_order};
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
    /// The signed `member_removed` facts behind `removed_members`, by fact
    /// hash. [`fold`] applies each removal at its own place in the total
    /// order. A removed member with no fact here (a hand-built `Facts`) is
    /// removed from the start of the fold.
    pub removal_facts: BTreeMap<String, RemovalFact>,
}

/// One signed `member_removed` fact: who removed whom, and when.
#[derive(Clone, Debug)]
pub struct RemovalFact {
    pub author: String,
    pub target: String,
    pub hlc: String,
}

/// Where each fact-removed member stops being a member of the fold (issue
/// #27). The member's commits before that point stand as the work of the
/// member it then was; its later commits fail the usual membership and role
/// checks.
///
/// - Removed by another device: the cut is the earliest such fact's HLC. The
///   remover's first `dek.rotate` commit for its fact (`removal_fact_hash`,
///   written by the same `team remove`) signs the vector the remover had
///   seen; the member's commits past the lowest such sequence are skipped
///   wherever they sort, so backdating cannot put new work in front of the
///   cut. The member's own facts never move it.
/// - Removed only by itself: its earliest own `member.remove` commit
///   places the removal in its own sequence. Its commits past that one are
///   skipped wherever they sort, so neither backdating nor a placing op
///   the fold skips (signed before the device's admission, say) leaves it
///   any authority. Its self-removal facts never move the placement,
///   whatever their HLC.
/// - Neither (a hand-built `Facts`, or a bare self-removal fact): removed
///   from the start of the fold, as before.
struct RemovalSchedule {
    /// `(cut HLC, fingerprint)`, earliest first.
    pending: Vec<((PyInt, PyInt), String)>,
    /// Each member's last `author_seq` that can count: the lowest attested
    /// one for a member removed by others, its placing commit's for one
    /// removed by itself.
    bounds: BTreeMap<String, PyInt>,
    /// Members whose own `member.remove` commit places their removal.
    self_placed: BTreeSet<String>,
}

impl RemovalSchedule {
    fn new(facts: &Facts, commits: &[Commit]) -> RemovalSchedule {
        let mut pending = Vec::new();
        let mut bounds: BTreeMap<String, PyInt> = BTreeMap::new();
        let mut self_placed = BTreeSet::new();
        for fp in &facts.removed_members {
            let mut cut: Option<(PyInt, PyInt)> = None;
            let mut bound: Option<PyInt> = None;
            let mut by_itself = false;
            let mut positioned = true;
            for (hash, fact) in facts.removal_facts.iter().filter(|(_, f)| &f.target == fp) {
                if &fact.author == fp {
                    by_itself = true;
                    continue;
                }
                let Ok(hlc) = Hlc::parse(&fact.hlc) else {
                    positioned = false;
                    break;
                };
                if cut.as_ref().is_none_or(|earliest| hlc < *earliest) {
                    cut = Some(hlc);
                }
                let attestation = commits
                    .iter()
                    .filter(|c| {
                        c.author == fact.author
                            && c.ops.iter().any(|op| {
                                op["op"] == "dek.rotate" && op["removal_fact_hash"] == hash.as_str()
                            })
                    })
                    .min_by(|a, b| a.author_seq.cmp(&b.author_seq));
                if let Some(commit) = attestation {
                    let seen = commit.seen.get(fp).cloned().unwrap_or_else(PyInt::zero);
                    if bound.as_ref().is_none_or(|lowest| seen < *lowest) {
                        bound = Some(seen);
                    }
                }
            }
            if !positioned {
                continue;
            }
            if let Some(cut) = cut {
                pending.push((cut, fp.clone()));
                if let Some(bound) = bound {
                    bounds.insert(fp.clone(), bound);
                }
            } else if by_itself
                && let Some(leave) = commits
                    .iter()
                    .filter(|c| {
                        &c.author == fp
                            && c.ops.iter().any(|op| {
                                op["op"] == "member.remove" && op["fingerprint"] == fp.as_str()
                            })
                    })
                    .map(|c| c.author_seq.clone())
                    .min()
            {
                self_placed.insert(fp.clone());
                bounds.insert(fp.clone(), leave);
            }
        }
        pending.sort();
        RemovalSchedule {
            pending,
            bounds,
            self_placed,
        }
    }

    /// Members that are not removed when the fold starts.
    fn placed(&self) -> impl Iterator<Item = &String> {
        self.pending
            .iter()
            .map(|(_, fp)| fp)
            .chain(self.self_placed.iter())
    }

    /// The commit lies past the last one its author can count: what its
    /// remover attested, or its own placing `member.remove`.
    fn past_bound(&self, commit: &Commit) -> bool {
        self.bounds
            .get(&commit.author)
            .is_some_and(|bound| commit.author_seq > *bound)
    }
}

/// Make `fp` a removed member from this point of the fold on.
fn remove_member_now(doc: &mut Value, facts: &mut Facts, fp: &str) -> Result<()> {
    facts.removed_members.insert(fp.to_string());
    let members = py_getitem_mut(doc, "members")?;
    if let Some(member) = py_dict_get_mut(members, &json!(fp))? {
        py_setitem(member, &json!("status"), json!("removed"))?;
    }
    Ok(())
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

/// Port of `zeropw.team.fold.FoldResult`.
#[derive(Clone, Debug)]
pub struct FoldResult {
    pub document: Value,
    /// One entry per skipped op: `(commit_hash, op_index, reason)`.
    pub skipped: Vec<(String, usize, String)>,
    pub version_order: Value,
    /// `vector[commit.author] = max(vector.get(commit.author, 0),
    /// commit.author_seq)`: exact Python ints (finding H-R2-6).
    pub vector: BTreeMap<String, PyInt>,
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

enum VersionOrderState {
    Map(BTreeMap<String, Vec<Value>>),
    Raw(Value),
}

impl VersionOrderState {
    fn append(&mut self, secret_id: String, version_id: String) -> Result<()> {
        match self {
            Self::Map(order) => {
                order.entry(secret_id).or_default().push(json!(version_id));
                Ok(())
            }
            Self::Raw(value) => {
                let order = value
                    .as_object_mut()
                    .ok_or_else(|| Error::state("state_corrupt").with_detail("team_document"))?;
                let target = order.entry(secret_id).or_insert_with(|| json!([]));
                target
                    .as_array_mut()
                    .ok_or_else(|| Error::state("state_corrupt").with_detail("team_document"))?
                    .push(json!(version_id));
                Ok(())
            }
        }
    }

    fn into_value(self) -> Value {
        match self {
            Self::Map(order) => json!(order),
            Self::Raw(value) => value,
        }
    }
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
    let out_of_range =
        || Error::state("team_commit_time_out_of_range").with_detail(commit.hlc.as_str());
    if wall_ms >= WALL_MS_GMTIME_FAILS_AT {
        return Err(out_of_range());
    }
    // Below the bound, so it fits; `Hlc::parse` already rejected negatives.
    let wall_ms = i128::try_from(&wall_ms.0).map_err(|_| out_of_range())?;
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

// ------------------------------------------------------- Python dict access
//
// `fold()` performs no up-front document validation in Python (PORTING.md
// §3d): `copy.deepcopy(base_document)` is folded as-is, and each op handler
// touches exactly the entries it subscripts, in its own order. The helpers
// below reproduce those accesses over the JSON document. Where CPython raises
// a built-in exception (`KeyError`, `TypeError`, `AttributeError`) that
// nothing in `fold()` catches, they return `state_corrupt` (§3.5): the error
// aborts the whole fold, as the exception escapes `fold()` in Python, after
// any `team_op_skipped` audit records for earlier ops were already written.

fn doc_corrupt() -> Error {
    Error::state("state_corrupt").with_detail("team_document")
}

/// `container[key]` (read): `KeyError` for a dict without `key`,
/// `TypeError` for every non-dict container.
fn py_getitem<'a>(container: &'a Value, key: &str) -> Result<&'a Value> {
    container
        .as_object()
        .and_then(|map| map.get(key))
        .ok_or_else(doc_corrupt)
}

fn py_getitem_mut<'a>(container: &'a mut Value, key: &str) -> Result<&'a mut Value> {
    container
        .as_object_mut()
        .and_then(|map| map.get_mut(key))
        .ok_or_else(doc_corrupt)
}

/// A JSON value used as a Python dict key: `Ok(Some(text))` for a string,
/// `Ok(None)` for a hashable non-string (it can never equal a JSON object's
/// string keys), `Err` for an unhashable list/dict (`TypeError`).
fn py_key(key: &Value) -> Result<Option<&str>> {
    match key {
        Value::String(text) => Ok(Some(text)),
        Value::Array(_) | Value::Object(_) => Err(doc_corrupt()),
        _ => Ok(None),
    }
}

/// `container.get(key)`: `AttributeError` for a non-dict container. A JSON
/// `null` value is Python's `None`, the same as an absent key.
fn py_dict_get<'a>(container: &'a Value, key: &Value) -> Result<Option<&'a Value>> {
    let map = container.as_object().ok_or_else(doc_corrupt)?;
    Ok(py_key(key)?
        .and_then(|key| map.get(key))
        .filter(|value| !value.is_null()))
}

fn py_dict_get_mut<'a>(container: &'a mut Value, key: &Value) -> Result<Option<&'a mut Value>> {
    let key = py_key(key)?;
    let map = container.as_object_mut().ok_or_else(doc_corrupt)?;
    Ok(key
        .and_then(|key| map.get_mut(key))
        .filter(|value| !value.is_null()))
}

/// `container[key] = value`: only a dict supports item assignment with a
/// string key. A non-string key would create a key no JSON document (and so
/// no snapshot `json.dump(..., sort_keys=True)`) can hold; it is reachable
/// only through an operation that never passed `validate_op` and is mapped
/// to the same failure.
fn py_setitem(container: &mut Value, key: &Value, value: Value) -> Result<()> {
    let key = py_key(key)?.ok_or_else(doc_corrupt)?.to_string();
    container
        .as_object_mut()
        .ok_or_else(doc_corrupt)?
        .insert(key, value);
    Ok(())
}

/// Python `a == b` for two `json.load`-decoded values: numbers and bools
/// compare numerically across type, containers element-wise.
fn py_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(l, r)| py_eq(l, r))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|other| py_eq(v, other)))
        }
        (Value::Array(_) | Value::Object(_), _) | (_, Value::Array(_) | Value::Object(_)) => false,
        _ => commit::dict_keys_equal(a, b),
    }
}

/// `key in container`: a dict tests its keys (an unhashable key raises
/// `TypeError`), a list its elements by `==`, a string its substrings (a
/// non-string left operand raises `TypeError`); any other container raises
/// `TypeError`.
fn py_contains(container: &Value, key: &Value) -> Result<bool> {
    match container {
        Value::Object(map) => Ok(py_key(key)?.is_some_and(|key| map.contains_key(key))),
        Value::Array(items) => Ok(items.iter().any(|item| py_eq(item, key))),
        Value::String(text) => match key {
            Value::String(key) => Ok(text.contains(key.as_str())),
            _ => Err(doc_corrupt()),
        },
        _ => Err(doc_corrupt()),
    }
}

/// `key in <set of str>` (the `Facts` sets).
fn py_set_contains(set: &HashSet<String>, key: &Value) -> Result<bool> {
    Ok(py_key(key)?.is_some_and(|key| set.contains(key)))
}

/// `op[name]`: the op dict's own `KeyError`.
fn op_item<'a>(op: &'a Map<String, Value>, name: &str) -> Result<&'a Value> {
    op.get(name).ok_or_else(doc_corrupt)
}

fn is_str(value: &Value, text: &str) -> bool {
    value.as_str() == Some(text)
}

/// `_is_active_member`: `member = doc["members"].get(fp)`, then `bool(member)
/// and member["status"] == "active"`.
fn is_active_member(doc: &Value, fp: &Value) -> Result<bool> {
    let member = py_dict_get(py_getitem(doc, "members")?, fp)?;
    match member {
        None => Ok(false),
        Some(member) if json_falsy(member) => Ok(false),
        Some(member) => Ok(is_str(py_getitem(member, "status")?, "active")),
    }
}

/// `_is_admin`: active, then `fp == doc["owner"]`, then
/// `doc["members"][fp]["role"] == "admin"`.
fn is_admin(doc: &Value, fp: &Value) -> Result<bool> {
    if !is_active_member(doc, fp)? {
        return Ok(false);
    }
    if py_eq(fp, py_getitem(doc, "owner")?) {
        return Ok(true);
    }
    let key = py_key(fp)?.ok_or_else(doc_corrupt)?;
    let member = py_getitem(py_getitem(doc, "members")?, key)?;
    Ok(is_str(py_getitem(member, "role")?, "admin"))
}

/// `_is_owner`: `doc["owner"] == fp and _is_active_member(doc, fp)`.
fn is_owner(doc: &Value, fp: &Value) -> Result<bool> {
    Ok(py_eq(py_getitem(doc, "owner")?, fp) && is_active_member(doc, fp)?)
}

fn author_value(commit: &Commit) -> Value {
    Value::String(commit.author.clone())
}

/// `build_connection_fields` outcome inside a fold handler: its documented
/// `InvalidInput` is the skip reason (`except InvalidInput as exc: return
/// exc.reason`); anything else (the built-in exceptions `commit.rs` maps for
/// `validate_op`) escapes the fold, as in Python.
fn skip_reason_or_abort(error: Error) -> Result<Option<String>> {
    if error.is(ErrorClass::InvalidInput) {
        Ok(Some(error.reason.to_string()))
    } else {
        Err(error)
    }
}

// ------------------------------------------------------------- connection ops
/// `_connection_entry`: `fields["created_at"] = created_at or timestamp`
/// keeps a truthy stored value verbatim, whatever its JSON type.
fn connection_entry(
    conn_id: &Value,
    args: &Map<String, Value>,
    status: Value,
    timestamp: &str,
    created_at: Option<Value>,
) -> Result<Map<String, Value>> {
    let mut fields = commit::build_connection_fields(args)?;
    fields.insert("id".into(), conn_id.clone());
    fields.insert("status".into(), status);
    let created_at = match created_at {
        Some(value) if !json_falsy(&value) => value,
        _ => json!(timestamp),
    };
    fields.insert("created_at".into(), created_at);
    fields.insert("updated_at".into(), json!(timestamp));
    Ok(fields)
}

fn op_connection_create(
    doc: &mut Value,
    commit: &Commit,
    facts: &mut Facts,
    _vo: &mut VersionOrderState,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &author_value(commit))? {
        return Ok(Some("not_admin".into()));
    }
    let conn_id = op_item(op, "id")?;
    // Deriving such an id would fail every refold (issue #54). This build
    // does not author one, but receipt stores one as earlier builds did.
    if commit::creates_misnamed_connection(op) {
        return Ok(Some("invalid_connection_id".into()));
    }
    if py_contains(py_getitem(doc, "connections")?, conn_id)?
        || py_set_contains(&facts.disabled_connections, conn_id)?
    {
        return Ok(Some("connection_id_taken".into()));
    }
    if !py_contains(py_getitem(doc, "secrets")?, op_item(op, "secret_id")?)? {
        return Ok(Some("secret_not_found".into()));
    }
    let timestamp = commit_time(commit)?;
    let entry = match connection_entry(conn_id, op, json!("active"), &timestamp, None) {
        Ok(entry) => entry,
        Err(error) => return skip_reason_or_abort(error),
    };
    py_setitem(
        py_getitem_mut(doc, "connections")?,
        conn_id,
        Value::Object(entry),
    )?;
    Ok(None)
}

/// `current = doc["connections"].get(conn_id)`, then `current is None or
/// current["status"] == "disabled" or conn_id in facts.disabled_connections`.
fn live_connection(doc: &Value, facts: &Facts, conn_id: &Value) -> Result<Option<Value>> {
    let Some(current) = py_dict_get(py_getitem(doc, "connections")?, conn_id)? else {
        return Ok(None);
    };
    if is_str(py_getitem(current, "status")?, "disabled")
        || py_set_contains(&facts.disabled_connections, conn_id)?
    {
        return Ok(None);
    }
    Ok(Some(current.clone()))
}

fn op_connection_update(
    doc: &mut Value,
    commit: &Commit,
    facts: &mut Facts,
    _vo: &mut VersionOrderState,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &author_value(commit))? {
        return Ok(Some("not_admin".into()));
    }
    let conn_id = op_item(op, "id")?;
    let Some(current) = live_connection(doc, facts, conn_id)? else {
        return Ok(Some("connection_not_found".into()));
    };
    // `current["status"]` succeeded above, so `current` is a dict.
    let mut merged = current.as_object().cloned().ok_or_else(doc_corrupt)?;
    for name in [
        "description",
        "http_target",
        "http_auth",
        "http_scope",
        "ssh_target",
        "cli",
    ] {
        if let Some(value) = op.get(name) {
            merged.insert(name.to_string(), value.clone());
        }
    }
    // Argument order: `current["status"]`, `_commit_time(commit)`, then
    // `created_at=current["created_at"]`.
    let status = py_getitem(&current, "status")?.clone();
    let timestamp = commit_time(commit)?;
    let created_at = py_getitem(&current, "created_at")?.clone();
    let entry = match connection_entry(conn_id, &merged, status, &timestamp, Some(created_at)) {
        Ok(entry) => entry,
        Err(error) => return skip_reason_or_abort(error),
    };
    py_setitem(
        py_getitem_mut(doc, "connections")?,
        conn_id,
        Value::Object(entry),
    )?;
    Ok(None)
}

fn op_connection_switch_credential(
    doc: &mut Value,
    commit: &Commit,
    facts: &mut Facts,
    _vo: &mut VersionOrderState,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &author_value(commit))? {
        return Ok(Some("not_admin".into()));
    }
    let conn_id = op_item(op, "id")?;
    let Some(current) = live_connection(doc, facts, conn_id)? else {
        return Ok(Some("connection_not_found".into()));
    };
    // `op.get("secret_id", current["secret_id"])`: the default is evaluated
    // (and must exist) even when the op carries its own `secret_id`.
    let stored_secret_id = py_getitem(&current, "secret_id")?;
    let secret_id = op.get("secret_id").unwrap_or(stored_secret_id).clone();
    if !py_contains(py_getitem(doc, "secrets")?, &secret_id)? {
        return Ok(Some("secret_not_found".into()));
    }
    let mut merged = current.as_object().cloned().ok_or_else(doc_corrupt)?;
    merged.insert("secret_id".into(), secret_id);
    merged.insert(
        "secret_version".into(),
        op.get("secret_version").cloned().unwrap_or(Value::Null),
    );
    merged.insert("updated_at".into(), json!(commit_time(commit)?));
    py_setitem(
        py_getitem_mut(doc, "connections")?,
        conn_id,
        Value::Object(merged),
    )?;
    Ok(None)
}

fn op_connection_disable(
    doc: &mut Value,
    commit: &Commit,
    facts: &mut Facts,
    _vo: &mut VersionOrderState,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &author_value(commit))? {
        return Ok(Some("not_admin".into()));
    }
    let conn_id = op_item(op, "id")?;
    let Some(current) = py_dict_get(py_getitem(doc, "connections")?, conn_id)? else {
        return Ok(Some("connection_not_found".into()));
    };
    if is_str(py_getitem(current, "status")?, "disabled") {
        return Ok(Some("already_disabled".into()));
    }
    // Finding H-R3-2: `_commit_time` only after the three checks above.
    let timestamp = commit_time(commit)?;
    let current =
        py_dict_get_mut(py_getitem_mut(doc, "connections")?, conn_id)?.ok_or_else(doc_corrupt)?;
    py_setitem(current, &json!("status"), json!("disabled"))?;
    py_setitem(current, &json!("updated_at"), json!(timestamp))?;
    let key = py_key(conn_id)?.ok_or_else(doc_corrupt)?;
    facts.disabled_connections.insert(key.to_string());
    Ok(None)
}

// ------------------------------------------------------------------ secret ops
fn op_secret_put_version(
    doc: &mut Value,
    commit: &Commit,
    _facts: &mut Facts,
    vo: &mut VersionOrderState,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &author_value(commit))? {
        return Ok(Some("not_admin".into()));
    }
    let secret_id = op_item(op, "secret_id")?;
    let version_id = op_item(op, "version_id")?;
    // F1: checked before touching `doc["secrets"]`.
    let generations = py_getitem(py_getitem(doc, "dek")?, "generations")?;
    if !py_contains(generations, op_item(op, "generation_id")?)? {
        return Ok(Some("generation_unknown".into()));
    }
    // `doc["secrets"].setdefault(secret_id, {"kind": op["kind"], ...})`:
    // the default is built (so `op["kind"]` must exist) before the call, and
    // only an ABSENT key receives it -- an existing value of any shape,
    // `null` included, is returned as-is.
    let kind = op_item(op, "kind")?.clone();
    let secrets = py_getitem_mut(doc, "secrets")?
        .as_object_mut()
        .ok_or_else(doc_corrupt)?;
    let secret_key = py_key(secret_id)?.ok_or_else(doc_corrupt)?;
    let entry = secrets
        .entry(secret_key.to_string())
        .or_insert_with(|| json!({"kind": kind.clone(), "active_version": null, "versions": {}}));
    if !py_eq(py_getitem(entry, "kind")?, &kind) {
        return Ok(Some("secret_kind_mismatch".into()));
    }
    if py_contains(py_getitem(entry, "versions")?, version_id)? {
        return Ok(Some("version_id_taken".into()));
    }
    let generation_id = op_item(op, "generation_id")?.clone();
    let ciphertext = op_item(op, "ciphertext")?;
    let nonce = py_getitem(ciphertext, "nonce")?.clone();
    let ct = py_getitem(ciphertext, "ciphertext")?.clone();
    // `dict(op.get("public") or {})`; `validate_op` admits only a dict.
    let public = match op.get("public") {
        None => Map::new(),
        Some(value) if json_falsy(value) => Map::new(),
        Some(Value::Object(map)) => map.clone(),
        Some(_) => return Err(doc_corrupt()),
    };
    py_setitem(
        py_getitem_mut(entry, "versions")?,
        version_id,
        json!({
            "status": "staged", "generation": generation_id, "nonce": nonce, "ciphertext": ct,
            "public": Value::Object(public),
        }),
    )?;
    let version_key = py_key(version_id)?.ok_or_else(doc_corrupt)?;
    vo.append(secret_key.to_string(), version_key.to_string())?;
    Ok(None)
}

fn set_secret_status(
    doc: &mut Value,
    facts: &Facts,
    secret_id: &Value,
    version_id: &Value,
    status: &Value,
) -> Result<Option<String>> {
    // `entry = doc["secrets"].get(secret_id)`; `version =
    // entry["versions"].get(version_id) if entry else None`.
    let entry = py_dict_get(py_getitem(doc, "secrets")?, secret_id)?;
    let version = match entry {
        Some(entry) if !json_falsy(entry) => {
            py_dict_get(py_getitem(entry, "versions")?, version_id)?
        }
        _ => None,
    };
    let Some(version) = version else {
        return Ok(Some("version_not_found".into()));
    };
    let revoked_fact = match (py_key(secret_id)?, py_key(version_id)?) {
        (Some(s), Some(v)) => facts
            .revoked_versions
            .contains(&(s.to_string(), v.to_string())),
        _ => false,
    };
    if is_str(py_getitem(version, "status")?, "revoked") || revoked_fact {
        return Ok(Some("version_revoked".into()));
    }
    let entry =
        py_dict_get_mut(py_getitem_mut(doc, "secrets")?, secret_id)?.ok_or_else(doc_corrupt)?;
    let version =
        py_dict_get_mut(py_getitem_mut(entry, "versions")?, version_id)?.ok_or_else(doc_corrupt)?;
    py_setitem(version, &json!("status"), status.clone())?;
    if is_str(status, "active") {
        let previous = py_getitem(entry, "active_version")?.clone();
        if !previous.is_null() && !py_eq(&previous, version_id) {
            let previous_key = py_key(&previous)?;
            let versions = py_getitem(entry, "versions")?;
            let previous_record = previous_key
                .and_then(|key| versions.as_object().and_then(|map| map.get(key)))
                .ok_or_else(doc_corrupt)?;
            if is_str(py_getitem(previous_record, "status")?, "active") {
                let versions = py_getitem_mut(entry, "versions")?;
                let previous_record = py_getitem_mut(versions, previous_key.unwrap_or_default())?;
                py_setitem(previous_record, &json!("status"), json!("retired"))?;
            }
        }
        py_setitem(entry, &json!("active_version"), version_id.clone())?;
    } else if py_eq(py_getitem(entry, "active_version")?, version_id) {
        py_setitem(entry, &json!("active_version"), Value::Null)?;
    }
    Ok(None)
}

fn op_secret_set_status(
    doc: &mut Value,
    commit: &Commit,
    facts: &mut Facts,
    _vo: &mut VersionOrderState,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &author_value(commit))? {
        return Ok(Some("not_admin".into()));
    }
    let secret_id = op_item(op, "secret_id")?;
    let version_id = op_item(op, "version_id")?;
    let status = op_item(op, "status")?;
    set_secret_status(doc, facts, secret_id, version_id, status)
}

fn op_secret_activate(
    doc: &mut Value,
    commit: &Commit,
    facts: &mut Facts,
    _vo: &mut VersionOrderState,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &author_value(commit))? {
        return Ok(Some("not_admin".into()));
    }
    let secret_id = op_item(op, "secret_id")?;
    let version_id = op_item(op, "version_id")?;
    set_secret_status(doc, facts, secret_id, version_id, &json!("active"))
}

// ------------------------------------------------------------------ member ops
fn op_member_add(
    doc: &mut Value,
    commit: &Commit,
    facts: &mut Facts,
    _vo: &mut VersionOrderState,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &author_value(commit))? {
        return Ok(Some("not_admin".into()));
    }
    // `op["device"]`'s `KeyError` is outside the `except InvalidInput`.
    let record = match DeviceRecord::from_dict(op_item(op, "device")?) {
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
    let fp_value = json!(fp);
    if let Some(existing) = py_dict_get(py_getitem(doc, "members")?, &fp_value)? {
        if is_str(py_getitem(existing, "status")?, "removed") {
            return Ok(Some("member_removed".into()));
        }
        return Ok(Some("member_exists".into()));
    }
    let name = op_item(op, "name")?.clone();
    let role = op_item(op, "role")?.clone();
    let member_entry =
        json!({"name": name, "role": role, "status": "active", "device": record.to_dict()});
    py_setitem(py_getitem_mut(doc, "members")?, &fp_value, member_entry)?;
    // `for gen_id, wrap in (op.get("wraps") or {}).items()`.
    let wraps = match op.get("wraps") {
        None => Map::new(),
        Some(value) if json_falsy(value) => Map::new(),
        Some(Value::Object(map)) => map.clone(),
        Some(_) => return Err(doc_corrupt()),
    };
    for (gen_id, wrap) in wraps {
        let generations = py_getitem_mut(py_getitem_mut(doc, "dek")?, "generations")?;
        if let Some(generation) = py_dict_get_mut(generations, &json!(gen_id))? {
            py_setitem(py_getitem_mut(generation, "wraps")?, &fp_value, wrap)?;
        }
    }
    Ok(None)
}

fn op_member_set_role(
    doc: &mut Value,
    commit: &Commit,
    _facts: &mut Facts,
    _vo: &mut VersionOrderState,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &author_value(commit))? {
        return Ok(Some("not_admin".into()));
    }
    let fp = op_item(op, "fingerprint")?;
    if py_eq(fp, py_getitem(doc, "owner")?) {
        return Ok(Some("cannot_change_owner_role".into()));
    }
    if !is_active_member(doc, fp)? {
        return Ok(Some("member_not_found".into()));
    }
    let role = op_item(op, "role")?.clone();
    let member = py_dict_get_mut(py_getitem_mut(doc, "members")?, fp)?.ok_or_else(doc_corrupt)?;
    py_setitem(member, &json!("role"), role)?;
    Ok(None)
}

fn op_member_remove(
    doc: &mut Value,
    commit: &Commit,
    facts: &mut Facts,
    _vo: &mut VersionOrderState,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    let fp = op_item(op, "fingerprint")?;
    if !(is_admin(doc, &author_value(commit))? || is_str(fp, &commit.author)) {
        return Ok(Some("not_authorized".into()));
    }
    if py_eq(fp, py_getitem(doc, "owner")?) {
        return Ok(Some("cannot_remove_owner".into()));
    }
    if !is_active_member(doc, fp)? {
        return Ok(Some("member_not_found".into()));
    }
    let member = py_dict_get_mut(py_getitem_mut(doc, "members")?, fp)?.ok_or_else(doc_corrupt)?;
    py_setitem(member, &json!("status"), json!("removed"))?;
    let key = py_key(fp)?.ok_or_else(doc_corrupt)?;
    facts.removed_members.insert(key.to_string());
    Ok(None)
}

fn op_owner_transfer(
    doc: &mut Value,
    commit: &Commit,
    _facts: &mut Facts,
    _vo: &mut VersionOrderState,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_owner(doc, &author_value(commit))? {
        return Ok(Some("not_owner".into()));
    }
    let fp = op_item(op, "fingerprint")?.clone();
    if !is_active_member(doc, &fp)? {
        return Ok(Some("member_not_found".into()));
    }
    py_setitem(doc, &json!("owner"), fp.clone())?;
    let member = py_dict_get_mut(py_getitem_mut(doc, "members")?, &fp)?.ok_or_else(doc_corrupt)?;
    py_setitem(member, &json!("role"), json!("admin"))?;
    Ok(None)
}

// --------------------------------------------------------------------- dek/settings
/// `dict(op["wraps"])`; `validate_op` admits only a non-empty dict.
fn op_wraps_dict(op: &Map<String, Value>) -> Result<Value> {
    match op_item(op, "wraps")? {
        Value::Object(map) => Ok(Value::Object(map.clone())),
        _ => Err(doc_corrupt()),
    }
}

fn op_dek_rotate(
    doc: &mut Value,
    commit: &Commit,
    _facts: &mut Facts,
    _vo: &mut VersionOrderState,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &author_value(commit))? {
        return Ok(Some("not_admin".into()));
    }
    let gen_id = op_item(op, "generation_id")?;
    if py_contains(py_getitem(py_getitem(doc, "dek")?, "generations")?, gen_id)? {
        return Ok(Some("generation_exists".into()));
    }
    let wraps = op_wraps_dict(op)?;
    let dek = py_getitem_mut(doc, "dek")?;
    py_setitem(
        py_getitem_mut(dek, "generations")?,
        gen_id,
        json!({"wraps": wraps}),
    )?;
    if let Some(hash) = op.get("removal_fact_hash") {
        py_setitem(
            py_getitem_mut(
                py_getitem_mut(dek, "generations")?,
                gen_id.as_str().ok_or_else(doc_corrupt)?,
            )?,
            &json!("removal_fact_hash"),
            hash.clone(),
        )?;
    }
    py_setitem(dek, &json!("current"), gen_id.clone())?;
    Ok(None)
}

fn op_settings_update(
    doc: &mut Value,
    commit: &Commit,
    _facts: &mut Facts,
    _vo: &mut VersionOrderState,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !is_admin(doc, &author_value(commit))? {
        return Ok(Some("not_admin".into()));
    }
    let value = op_item(op, "sync_interval_seconds")?.clone();
    py_setitem(
        py_getitem_mut(doc, "settings")?,
        &json!("sync_interval_seconds"),
        value,
    )?;
    Ok(None)
}

// --------------------------------------------------------------------- env.init
fn op_env_init(
    doc: &mut Value,
    commit: &Commit,
    _facts: &mut Facts,
    _vo: &mut VersionOrderState,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    if !py_getitem(doc, "owner")?.is_null() {
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
    let owner_record = match DeviceRecord::from_dict(op_item(op, "owner_device")?) {
        Ok(r) => r,
        Err(_) => return Ok(Some("env_init_malformed".into())),
    };
    if owner_record.fingerprint() != commit.author || !owner_record.verify() {
        return Ok(Some("env_init_malformed".into()));
    }
    let author = author_value(commit);
    py_setitem(doc, &json!("owner"), author.clone())?;
    let owner_name = op_item(op, "owner_name")?.clone();
    let member_entry = json!({"name": owner_name, "role": "admin", "status": "active",
                              "device": owner_record.to_dict()});
    py_setitem(py_getitem_mut(doc, "members")?, &author, member_entry)?;
    let generation_id = op_item(op, "generation_id")?.clone();
    py_setitem(
        py_getitem_mut(doc, "dek")?,
        &json!("current"),
        generation_id.clone(),
    )?;
    let wraps = op_wraps_dict(op)?;
    let generations = py_getitem_mut(py_getitem_mut(doc, "dek")?, "generations")?;
    py_setitem(generations, &generation_id, json!({"wraps": wraps}))?;
    Ok(None)
}

type OpHandler = fn(
    &mut Value,
    &Commit,
    &mut Facts,
    &mut VersionOrderState,
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

/// `_apply_op`: `_OP_HANDLERS.get(op.get("op"))` -- an unhashable op name
/// raises `TypeError`; any other unknown name is `unknown_op`.
fn apply_op(
    doc: &mut Value,
    commit: &Commit,
    facts: &mut Facts,
    vo: &mut VersionOrderState,
    op: &Map<String, Value>,
) -> Result<Option<String>> {
    // An op nested this deep can fail every refold, snapshot or backup
    // (issue #54). It is skipped whatever part of it is deep, so every node
    // on this build folds it alike. This build does not author one, but
    // receipt stores one as earlier builds did.
    if commit::op_too_deep(op) {
        return Ok(Some("op_too_deep".into()));
    }
    let name = match op.get("op") {
        Some(value) => py_key(value)?,
        None => None,
    };
    match name.and_then(op_handler) {
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

/// `_override_target`: `(kind, op.get(<field>))`. The target id is kept as
/// the raw value (Python's `None` for an absent field); `validate_op` only
/// ever admits a string there.
type OverrideTarget = (TargetKind, Value);

fn override_target(op: &Map<String, Value>) -> Option<OverrideTarget> {
    let field = |name: &str| op.get(name).cloned().unwrap_or(Value::Null);
    match op.get("op").and_then(Value::as_str)? {
        "connection.update" | "connection.switch_credential" => {
            Some((TargetKind::Connection, field("id")))
        }
        "member.set_role" => Some((TargetKind::MemberRole, field("fingerprint"))),
        "secret.activate" => Some((TargetKind::SecretActive, field("secret_id"))),
        _ => None,
    }
}

/// `_reapply_facts`: each loop only touches the document when its fact set
/// is non-empty, with the same subscripts (and so the same failures) as
/// Python.
fn reapply_facts(doc: &mut Value, facts: &Facts) -> Result<()> {
    for conn_id in &facts.disabled_connections {
        let connections = py_getitem_mut(doc, "connections")?;
        if let Some(entry) = py_dict_get_mut(connections, &json!(conn_id))? {
            py_setitem(entry, &json!("status"), json!("disabled"))?;
        }
    }
    for (secret_id, version_id) in &facts.revoked_versions {
        let secrets = py_getitem_mut(doc, "secrets")?;
        let Some(entry) = py_dict_get_mut(secrets, &json!(secret_id))? else {
            continue;
        };
        if json_falsy(entry) {
            continue;
        }
        let versions = py_getitem_mut(entry, "versions")?;
        let Some(version) = py_dict_get_mut(versions, &json!(version_id))? else {
            continue;
        };
        py_setitem(version, &json!("status"), json!("revoked"))?;
        if is_str(py_getitem(entry, "active_version")?, version_id) {
            py_setitem(entry, &json!("active_version"), Value::Null)?;
        }
    }
    for fp in &facts.removed_members {
        let members = py_getitem_mut(doc, "members")?;
        if let Some(member) = py_dict_get_mut(members, &json!(fp))? {
            py_setitem(member, &json!("status"), json!("removed"))?;
        }
    }
    Ok(())
}

/// A `_version_order` key already inside `base_document` (finding H-R4-5)
/// wins over `base_version_order` through `setdefault` and is used exactly
/// as stored: Python checks nothing until `_op_secret_put_version` appends
/// to it (`VersionOrderState::Raw` reproduces those lazy failures).
fn parse_stray_version_order(value: &Value) -> Option<BTreeMap<String, Vec<Value>>> {
    let obj = value.as_object()?;
    let mut out = BTreeMap::new();
    for (k, v) in obj {
        out.insert(k.clone(), v.as_array()?.clone());
    }
    Some(out)
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
/// The base document is not validated (Python's `copy.deepcopy` is not
/// either): only its top level must be a dict for `doc.setdefault(...)`.
/// Each handler then fails at the entry it actually subscripts, aborting
/// the whole fold as Python's escaping exception does (PORTING.md §3d).
///
/// Finding H-R4-5: `doc.setdefault("_version_order", ...)` keeps a stray
/// `_version_order` already inside `base_document` (it wins over the
/// separate `base_version_order` argument), and the final
/// `doc.pop("_version_order")` means the returned document never carries
/// the key.
pub fn fold(
    env_id: &str,
    commits: Vec<Commit>,
    facts: Option<&Facts>,
    base_document: Option<Value>,
    base_version_order: Option<BTreeMap<String, Vec<Value>>>,
    audit: Option<&Audit>,
) -> Result<FoldResult> {
    Ok(fold_scheduled(
        env_id,
        commits,
        facts,
        base_document,
        base_version_order,
        audit,
        None,
        false,
        None,
    )?
    .0)
}

/// [`fold`] of `commits` (a prefix of history, for compaction), placing
/// removals from every stored commit in `history`.
pub fn fold_with_history(
    env_id: &str,
    commits: Vec<Commit>,
    facts: Option<&Facts>,
    history: &[Commit],
    audit: Option<&Audit>,
) -> Result<FoldResult> {
    Ok(fold_scheduled(
        env_id,
        commits,
        facts,
        None,
        None,
        audit,
        Some(history),
        false,
        None,
    )?
    .0)
}

/// What `team compact` stores for `commits`, the stored prefix of
/// `history` (every stored commit) up to its cutoff: their fold with
/// removals placed from all of `history`, stopped before the end-of-fold
/// removals placed past the prefix and the facts overlay. The folds that
/// continue from it apply those, so a member removed after the prefix
/// keeps the work it did before its removal (issue #35). It builds on the
/// newest snapshot that covers no commit past the prefix, as a refold
/// would: after an earlier compaction, that one holds what the deleted
/// commits did, and its vector the authors left with none (issue #50).
pub fn snapshot_of_prefix(
    env_id: &str,
    commits: Vec<Commit>,
    state: &StateDir,
    facts: Option<&Facts>,
    history: &[Commit],
    audit: Option<&Audit>,
) -> Result<FoldResult> {
    let fold = fold_from_snapshots_in(env_id, commits, Some(history), state, facts, audit, true)?;
    Ok(FoldResult {
        document: fold.unflushed.ok_or_else(doc_corrupt)?,
        ..fold.result
    })
}

/// [`fold`], placing removals from `history` (every stored commit, when
/// `commits` is only what a snapshot does not cover) instead of `commits`.
/// With `keep_unflushed`, also the document as it stood after the last
/// commit, before the removals placed past it and the facts overlay: what
/// a snapshot stores. With `audited_up_to` (a snapshot vector), skips in
/// the commits it covers are not audited again.
#[allow(clippy::too_many_arguments)]
fn fold_scheduled(
    env_id: &str,
    commits: Vec<Commit>,
    facts: Option<&Facts>,
    base_document: Option<Value>,
    base_version_order: Option<BTreeMap<String, Vec<Value>>>,
    audit: Option<&Audit>,
    history: Option<&[Commit]>,
    keep_unflushed: bool,
    audited_up_to: Option<&Value>,
) -> Result<(FoldResult, Option<Value>)> {
    // `copy.deepcopy(base_document) if base_document is not None else
    // new_document(env_id)`, then `doc.setdefault` (a dict-only method).
    let mut doc = match base_document {
        Some(Value::Null) | None => Value::Object(new_document(env_id)),
        Some(value @ Value::Object(_)) => value,
        Some(_) => return Err(doc_corrupt()),
    };
    let mut version_order = match doc
        .as_object_mut()
        .and_then(|map| map.remove("_version_order"))
    {
        Some(stray) => match parse_stray_version_order(&stray) {
            Some(order) => VersionOrderState::Map(order),
            None => VersionOrderState::Raw(stray),
        },
        None => VersionOrderState::Map(base_version_order.unwrap_or_default()),
    };
    let relevant: Vec<Commit> = commits.into_iter().filter(|c| c.env_id == env_id).collect();
    let ordered = sort_total_order(relevant)?;
    let mut working_facts = facts.cloned().unwrap_or_default();
    // A fact-removed member stays a member until its removal's place in the
    // total order (`RemovalSchedule`).
    let removed_by_fact = working_facts.removed_members.clone();
    let schedule = RemovalSchedule::new(&working_facts, history.unwrap_or(&ordered));
    for fp in schedule.placed() {
        working_facts.removed_members.remove(fp);
    }
    let mut pending_removals = schedule.pending.iter().peekable();
    let mut skipped: Vec<(String, usize, String)> = Vec::new();
    let mut last_target_author: Vec<(OverrideTarget, (String, PyInt, String))> = Vec::new();
    let mut overridden: Vec<Value> = Vec::new();
    let mut fresh_connections: BTreeSet<String> = BTreeSet::new();
    for commit in &ordered {
        let position = Hlc::parse(&commit.hlc)?;
        while let Some((_, fp)) = pending_removals.next_if(|(cutoff, _)| *cutoff <= position) {
            remove_member_now(&mut doc, &mut working_facts, fp)?;
        }
        let past_bound = schedule.past_bound(commit);
        for (index, op) in commit.ops.iter().enumerate() {
            let op_obj = match op.as_object() {
                Some(o) => o,
                None => continue,
            };
            // Facts win over commits: ownership never passes to a member an
            // admitted fact removes, wherever the transfer sorts.
            let to_removed = op_obj.get("op").and_then(Value::as_str) == Some("owner.transfer")
                && op_obj
                    .get("fingerprint")
                    .and_then(Value::as_str)
                    .is_some_and(|fp| removed_by_fact.contains(fp));
            let reason = if past_bound || to_removed {
                Some("member_removed".to_string())
            } else {
                apply_op(
                    &mut doc,
                    commit,
                    &mut working_facts,
                    &mut version_order,
                    op_obj,
                )?
            };
            if let Some(reason) = reason {
                let hash = commit.hash()?;
                skipped.push((hash, index, reason.clone()));
                if let Some(audit) = audit
                    && audited_up_to.is_none_or(|floor| {
                        author_seq_is_later(
                            &commit.author_seq,
                            floor.as_object().and_then(|m| m.get(&commit.author)),
                        )
                        .unwrap_or(true)
                    })
                {
                    // `str(op.get("op", ""))[:64]`.
                    let op_name: String = commit::python_str_coerce(
                        op_obj.get("op").unwrap_or(&Value::String(String::new())),
                    )
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
                                ("author_seq", commit.author_seq.value()),
                                ("op", json!(op_name)),
                            ],
                            ..Default::default()
                        },
                    )?;
                }
                continue;
            }
            // Finding H-R2-7: record every connection id an op
            // successfully creates/updates in this fold call so
            // `humanview::to_yaml` can render exactly those with Python's
            // fresh-tuple rendering.
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
            // `last_target_author.get(target)`: the id must be hashable.
            if matches!(target.1, Value::Array(_) | Value::Object(_)) {
                return Err(doc_corrupt());
            }
            let hash = commit.hash()?;
            let slot = last_target_author
                .iter()
                .position(|((kind, id), _)| *kind == target.0 && py_eq(id, &target.1));
            if let Some(slot) = slot {
                let previous = &last_target_author[slot].1;
                if previous.0 != commit.author {
                    overridden.push(json!({
                        "author": previous.0, "author_seq": previous.1.value(), "hash": previous.2,
                        "target_kind": target.0.as_str(), "target_id": target.1,
                        "by_author": commit.author, "by_seq": commit.author_seq.value(),
                        "by_hash": hash,
                    }));
                }
                last_target_author[slot].1 =
                    (commit.author.clone(), commit.author_seq.clone(), hash);
            } else {
                last_target_author.push((
                    target,
                    (commit.author.clone(), commit.author_seq.clone(), hash),
                ));
            }
        }
    }
    let unflushed = keep_unflushed.then(|| doc.clone());
    for (_, fp) in pending_removals {
        remove_member_now(&mut doc, &mut working_facts, fp)?;
    }
    working_facts.removed_members.extend(removed_by_fact);
    reapply_facts(&mut doc, &working_facts)?;
    let mut vector: BTreeMap<String, PyInt> = BTreeMap::new();
    for commit in &ordered {
        let entry = vector
            .entry(commit.author.clone())
            .or_insert_with(PyInt::zero);
        if commit.author_seq > *entry {
            *entry = commit.author_seq.clone();
        }
    }
    Ok((
        FoldResult {
            document: doc,
            skipped,
            version_order: version_order.into_value(),
            vector,
            overridden,
            fresh_connections,
        },
        unflushed,
    ))
}

// --------------------------------------------------------------------- snapshots
fn snapshot_dir(env_id: &str) -> String {
    format!("team/{env_id}/snapshots")
}

/// `zeropw.team.fold.save_snapshot`.
pub fn save_snapshot(
    state: &StateDir,
    env_id: &str,
    number: &PyInt,
    result: &FoldResult,
) -> Result<()> {
    let vector: Map<String, Value> = result
        .vector
        .iter()
        .map(|(k, v)| (k.clone(), v.value()))
        .collect();
    let doc = json!({"document": result.document, "version_order": result.version_order,
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
    let numbers = commit::digit_stems(&directory)?;
    let Some(top) = numbers.iter().max() else {
        return Ok(None);
    };
    let data = state.read_json(
        &format!("{}/{}.json", snapshot_dir(env_id), top),
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
fn author_seq_is_later(author_seq: &PyInt, floor: Option<&Value>) -> Result<bool> {
    let corrupt = || Error::state("state_corrupt").with_detail("team_snapshot");
    match floor {
        // The `0` default: a stored commit's own `author_seq` need not be
        // positive (the file name is not checked against it).
        None => Ok(*author_seq > 0),
        Some(Value::Bool(b)) => Ok(*author_seq > i32::from(*b)),
        Some(Value::Number(n)) => {
            if let Some(floor) = PyInt::from_json_integer(&Value::Number(n.clone())) {
                Ok(*author_seq > floor)
            } else if let Some(f) = n.as_f64() {
                Ok(crate::pyint::cmp_bigint_f64(&author_seq.0, f)
                    == Some(std::cmp::Ordering::Greater))
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
/// signature requires an already-typed `BTreeMap<String, Vec<Value>>`, so
/// Python's `list(v)` coercion lives here:
///
/// - A FALSY `version_order` (absent, `null`, `0`, `""`, `[]`, `{}`) becomes
///   `{}`, matching Python's `(x or {})` short-circuit -- no error.
/// - A TRUTHY value that is not a JSON object has no Python `.items()`
///   equivalent: an uncaught `AttributeError`, `state_corrupt` here.
/// - An array is copied verbatim, including non-string elements; a string
///   becomes its Unicode scalar strings and an object becomes its insertion-
///   ordered keys. A number, bool or `null` is non-iterable and fails closed
///   for Python's uncaught `TypeError`.
fn parse_snapshot_version_order(
    value: Option<&Value>,
) -> Result<Option<BTreeMap<String, Vec<Value>>>> {
    let corrupt = || Error::state("state_corrupt").with_detail("team_snapshot");
    let value = match value {
        None => return Ok(None),
        Some(v) if json_falsy(v) => return Ok(Some(BTreeMap::new())),
        Some(v) => v,
    };
    let obj = value.as_object().ok_or_else(corrupt)?;
    let mut out = BTreeMap::new();
    for (k, v) in obj {
        let list = match v {
            Value::Array(items) => items.clone(),
            Value::String(text) => text.chars().map(|c| Value::String(c.to_string())).collect(),
            Value::Object(map) => map.keys().cloned().map(Value::String).collect(),
            Value::Null | Value::Bool(_) | Value::Number(_) => return Err(corrupt()),
        };
        out.insert(k.clone(), list);
    }
    Ok(Some(out))
}

/// `zeropw.team.fold.fold_with_snapshot`: fold using the latest snapshot as
/// a base, applying only later commits.
///
/// A snapshot is a base only while it matches a fold from scratch at its
/// vector: no commit it does not cover sorts in front of one it does, and
/// it was folded with the same facts and removal schedule
/// ([`save_snapshot_record`]) or, without a record, equals the fold of the
/// commits it covers. Otherwise
/// the next older snapshot is tried, then a fold from scratch (issue #35).
/// A snapshot whose covered commits are no longer all stored -- `team
/// compact` deleted them -- cannot be checked and is used as it is. The
/// result's vector covers the snapshot's too.
///
/// Finding H-R4-7: this used to only widen the vector-floor comparison to
/// `i128` (finding H-R2-6) and otherwise silently tolerate every malformed
/// snapshot shape by falling back to an empty/default value -- a
/// fail-open divergence from Python's own uncaught exceptions for several
/// of those same shapes. Now: a snapshot whose content is literal JSON
/// `null` (Python's `state.read_json(path, None)` maps this to the exact
/// same `None` a MISSING snapshot file gets) is passed by as if it were
/// missing -- the next older snapshot is tried, and with none every commit
/// folds fresh, matching `fold_with_snapshot`'s own `if snapshot is None:`
/// branch; any OTHER non-object snapshot (Python's
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
    Ok(fold_from_snapshots(env_id, all_commits, state, facts, audit, false)?.result)
}

/// What [`fold_for_refold`] folded.
pub struct Refold {
    /// As [`fold_with_snapshot`] returns it.
    pub result: FoldResult,
    /// `result` as it stood after its last commit, before the removals
    /// placed past it and the facts overlay: what a new snapshot stores, so
    /// the fold continuing from it places those removals itself (issue
    /// #35).
    pub snapshot: FoldResult,
    /// What to record with `snapshot` ([`save_snapshot_record`]).
    pub record: Value,
    /// Snapshots, newest first, that no longer matched a fold from scratch
    /// and were passed over: store `snapshot` and drop them
    /// ([`remove_snapshot`]), so the next refold need not pass them over
    /// again.
    pub stale_snapshots: Vec<PyInt>,
    /// The snapshot the fold built on when it had no record (the
    /// prototype's, an earlier build's, or one whose record was never
    /// stored) and matched the fold of the commits it covers: store `record`
    /// for it, so the next fold need not fold those commits again.
    pub unrecorded_snapshot: Option<PyInt>,
}

/// [`fold_with_snapshot`] for `TeamSync::refold`, with what a new snapshot
/// of the result stores.
pub fn fold_for_refold(
    env_id: &str,
    all_commits: Vec<Commit>,
    state: &StateDir,
    facts: Option<&Facts>,
    audit: Option<&Audit>,
) -> Result<Refold> {
    let record = snapshot_record(facts, &all_commits);
    let fold = fold_from_snapshots(env_id, all_commits, state, facts, audit, true)?;
    let snapshot = FoldResult {
        document: fold.unflushed.ok_or_else(doc_corrupt)?,
        ..fold.result.clone()
    };
    Ok(Refold {
        result: fold.result,
        snapshot,
        record,
        stale_snapshots: fold.passed_over,
        unrecorded_snapshot: fold.unrecorded,
    })
}

/// Delete snapshot `number` and its record, once a newer snapshot
/// stands in for it. Best effort: a file left behind is only passed over
/// again.
pub fn remove_snapshot(state: &StateDir, env_id: &str, number: &PyInt) {
    let _ = std::fs::remove_file(state.path.join(format!(
        "{}/{}.json",
        snapshot_dir(env_id),
        number
    )));
    let _ = std::fs::remove_file(state.path.join(snapshot_record_path(env_id, number)));
}

struct SnapshotFold {
    result: FoldResult,
    unflushed: Option<Value>,
    /// Newer snapshots that did not match, so the fold built on an older one
    /// or on nothing.
    passed_over: Vec<PyInt>,
    /// The snapshot built on, when it matched without a record.
    unrecorded: Option<PyInt>,
}

/// The fold from the newest snapshot that still matches a fold from
/// scratch at its vector, or from scratch when none does. A snapshot whose
/// covered commits are no longer all stored (after `team compact`) cannot
/// be checked against a fold from scratch and is used as it is.
fn fold_from_snapshots(
    env_id: &str,
    all_commits: Vec<Commit>,
    state: &StateDir,
    facts: Option<&Facts>,
    audit: Option<&Audit>,
    keep_unflushed: bool,
) -> Result<SnapshotFold> {
    fold_from_snapshots_in(
        env_id,
        all_commits,
        None,
        state,
        facts,
        audit,
        keep_unflushed,
    )
}

/// [`fold_from_snapshots`] of `all_commits`, or, with `history`, of that
/// prefix of every stored commit: removals are then placed from all of
/// `history`, and a snapshot covering any commit past the prefix is no
/// base for it.
fn fold_from_snapshots_in(
    env_id: &str,
    all_commits: Vec<Commit>,
    history: Option<&[Commit]>,
    state: &StateDir,
    facts: Option<&Facts>,
    audit: Option<&Audit>,
    keep_unflushed: bool,
) -> Result<SnapshotFold> {
    let schedule = history.unwrap_or(&all_commits);
    let folded: BTreeSet<(&str, &PyInt)> = all_commits
        .iter()
        .map(|c| (c.author.as_str(), &c.author_seq))
        .collect();
    let beyond: Vec<&Commit> = history.map_or_else(Vec::new, |history| {
        history
            .iter()
            .filter(|c| !folded.contains(&(c.author.as_str(), &c.author_seq)))
            .collect()
    });
    let directory = state.path.join(snapshot_dir(env_id));
    let mut numbers = if directory.is_dir() {
        commit::digit_stems(&directory)?
    } else {
        Vec::new()
    };
    numbers.sort();
    let mut passed_over: Vec<PyInt> = Vec::new();
    // What the newest passed-over snapshot covers was audited when it was
    // folded.
    let mut audited_up_to: Option<Value> = None;
    // A snapshot without a record is checked by folding what it covers, at
    // most once per fold: past one that fails, older ones are passed over
    // unchecked, so a node upgraded from an earlier build does not fold its
    // history once per snapshot.
    let mut may_check_unrecorded = true;
    // What the snapshots not built on covered, per author.
    let mut named: BTreeMap<String, PyInt> = BTreeMap::new();
    for number in numbers.iter().rev() {
        let attempt = fold_on_snapshot(
            env_id,
            &all_commits,
            schedule,
            &beyond,
            state,
            number,
            facts,
            audit,
            keep_unflushed || !passed_over.is_empty(),
            audited_up_to.as_ref(),
            &mut may_check_unrecorded,
        );
        match attempt {
            Ok(Some((result, unflushed, unrecorded))) => {
                return Ok(SnapshotFold {
                    result,
                    unflushed,
                    passed_over,
                    unrecorded: unrecorded.then(|| number.clone()),
                });
            }
            // Null: as if missing, so a compaction's older snapshot still
            // stands in for the commits it deleted.
            Ok(None) => {}
            Err(SnapshotUnusable::Beyond(vector)) => name_commits(&mut named, &vector),
            Err(SnapshotUnusable::Stale(vector)) => {
                name_commits(&mut named, &vector);
                passed_over.push(number.clone());
                audited_up_to.get_or_insert(vector);
            }
            // Past a stale snapshot every covered commit is stored, so a fold
            // from scratch can stand in for one that does not load.
            Err(SnapshotUnusable::Failed(_)) if !passed_over.is_empty() => break,
            Err(SnapshotUnusable::Failed(error)) => return Err(error),
        }
    }
    // A fold from scratch needs every commit since the first, whether it
    // stands in for passed-over snapshots or no snapshot is there to build
    // on: one that a compaction deleted would be lost silently. A snapshot
    // not built on also names the commits it covered, of authors with no
    // commit left among them.
    if !stored_from_the_first(&all_commits) || !stores_every_named(schedule, &named) {
        return Err(Error::state("state_corrupt").with_detail("team_snapshot"));
    }
    drop(beyond);
    drop(folded);
    let (result, unflushed) = fold_scheduled(
        env_id,
        all_commits,
        facts,
        None,
        None,
        audit,
        history,
        keep_unflushed || !passed_over.is_empty(),
        audited_up_to.as_ref(),
    )?;
    Ok(SnapshotFold {
        result,
        unflushed,
        passed_over,
        unrecorded: None,
    })
}

enum SnapshotUnusable {
    /// It no longer matches a fold from scratch; its vector.
    Stale(Value),
    /// It covers commits past the prefix being folded; its vector.
    Beyond(Value),
    Failed(Error),
}

impl From<Error> for SnapshotUnusable {
    fn from(error: Error) -> Self {
        SnapshotUnusable::Failed(error)
    }
}

/// The fold of `all_commits` on snapshot `number`, with removals placed from
/// `schedule` (every stored commit), and whether the snapshot matched
/// without a record: `None` for a null snapshot, `Stale` for one that no
/// longer matches a fold from scratch, `Beyond` for one that covers a
/// commit of `beyond`.
#[allow(clippy::too_many_arguments)]
fn fold_on_snapshot(
    env_id: &str,
    all_commits: &[Commit],
    schedule: &[Commit],
    beyond: &[&Commit],
    state: &StateDir,
    number: &PyInt,
    facts: Option<&Facts>,
    audit: Option<&Audit>,
    keep_unflushed: bool,
    audited_up_to: Option<&Value>,
    may_check_unrecorded: &mut bool,
) -> std::result::Result<Option<(FoldResult, Option<Value>, bool)>, SnapshotUnusable> {
    {
        let snapshot = state.read_json(
            &format!("{}/{}.json", snapshot_dir(env_id), number),
            Value::Null,
        )?;
        if snapshot.is_null() {
            return Ok(None);
        }
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
        let floor_of = |c: &Commit| -> Result<Option<&Value>> {
            Ok(match vector_field {
                None => None,
                Some(v) if json_falsy(v) => None,
                Some(Value::Object(m)) => m.get(&c.author),
                Some(_) => return Err(corrupt()),
            })
        };
        let mut covered: Vec<Commit> = Vec::new();
        let mut later: Vec<Commit> = Vec::with_capacity(all_commits.len());
        for c in all_commits.iter().cloned() {
            if author_seq_is_later(&c.author_seq, floor_of(&c)?)? {
                later.push(c);
            } else {
                covered.push(c);
            }
        }
        for c in beyond {
            if !author_seq_is_later(&c.author_seq, floor_of(c)?)? {
                return Err(SnapshotUnusable::Beyond(
                    vector_field.cloned().unwrap_or(Value::Null),
                ));
            }
        }
        let base_document = snapshot_obj.get("document").cloned();
        let base_version_order = parse_snapshot_version_order(snapshot_obj.get("version_order"))?;
        // Only a document a build stored is checked; a hand-written null one
        // folds on a fresh document, as the prototype did.
        let stored = base_document.as_ref().is_some_and(Value::is_object);
        if stored && !later_is_contiguous(vector_field, &later) {
            return Err(SnapshotUnusable::Stale(
                vector_field.cloned().unwrap_or(Value::Null),
            ));
        }
        let mut unrecorded = false;
        if stored && history_is_complete(vector_field, &covered) {
            match check_snapshot(
                env_id,
                state,
                number,
                snapshot_obj,
                &covered,
                &later,
                facts,
                schedule,
                may_check_unrecorded,
            )? {
                Check::Matches => {}
                Check::MatchesUnrecorded => unrecorded = true,
                Check::Stale => {
                    return Err(SnapshotUnusable::Stale(
                        vector_field.cloned().unwrap_or(Value::Null),
                    ));
                }
            }
        }
        let (mut result, unflushed) = fold_scheduled(
            env_id,
            later,
            facts,
            base_document,
            base_version_order,
            audit,
            Some(schedule),
            keep_unflushed,
            audited_up_to,
        )?;
        // The snapshot's own vector stays covered: without it the next
        // snapshot would forget every author with nothing newer, and the
        // fold after that would apply their commits over it again.
        if let Some(Value::Object(floor)) = vector_field {
            for (author, value) in floor {
                if let Some(seq) = PyInt::from_json_integer(value)
                    .filter(|n| n.0.sign() != num_bigint::Sign::Minus)
                {
                    let entry = result
                        .vector
                        .entry(author.clone())
                        .or_insert_with(PyInt::zero);
                    if seq > *entry {
                        *entry = seq;
                    }
                }
            }
        }
        Ok(Some((result, unflushed, unrecorded)))
    }
}

/// Every author's commits past the snapshot vector are stored one after
/// another from the one right after it. Not so for a snapshot older than a
/// compaction, or one an earlier build's compaction left: a fold on it
/// would lose the deleted commits without a trace. An entry that is not a
/// sequence number is not checked, as before.
fn later_is_contiguous(vector: Option<&Value>, later: &[Commit]) -> bool {
    let mut seqs: BTreeMap<&str, Vec<&PyInt>> = BTreeMap::new();
    for commit in later {
        seqs.entry(commit.author.as_str())
            .or_default()
            .push(&commit.author_seq);
    }
    seqs.into_iter().all(|(author, mut seqs)| {
        let floor = match vector {
            Some(Value::Object(map)) => match map.get(author) {
                None => PyInt::zero(),
                Some(value) => match PyInt::from_json_integer(value)
                    .filter(|n| n.0.sign() != num_bigint::Sign::Minus)
                {
                    Some(n) => n,
                    None => return true,
                },
            },
            _ => PyInt::zero(),
        };
        seqs.sort();
        seqs.iter()
            .enumerate()
            .all(|(index, seq)| **seq == PyInt(&floor.0 + (index + 1)))
    })
}

/// Every commit the snapshot vector covers is still stored, so a fold from
/// scratch can stand in for the snapshot: false after compaction, and for a
/// vector that is not a map of sequence numbers.
fn history_is_complete(vector: Option<&Value>, covered: &[Commit]) -> bool {
    let Some(Value::Object(vector)) = vector else {
        return false;
    };
    if covered.is_empty() {
        return false;
    }
    let mut counts: BTreeMap<&str, PyInt> = BTreeMap::new();
    for commit in covered {
        let count = counts
            .entry(commit.author.as_str())
            .or_insert_with(PyInt::zero);
        *count = &*count + 1;
    }
    counts.keys().all(|author| vector.contains_key(*author))
        && vector.iter().all(|(author, value)| {
            PyInt::from_json_integer(value).is_some_and(|n| {
                n == counts
                    .get(author.as_str())
                    .cloned()
                    .unwrap_or_else(PyInt::zero)
            })
        })
}

/// How a snapshot compares with a fold from scratch at its vector.
enum Check {
    Matches,
    /// It has no record, and equals what this build stores for the commits
    /// it covers.
    MatchesUnrecorded,
    Stale,
}

/// Whether the snapshot still matches a fold from scratch at its vector. It
/// does not when a commit it does not cover sorts in front of one it does,
/// or when its record differs from what these facts and commits give --
/// other facts, or a removal placed or bounded differently by a commit that
/// arrived since (issue #35). A snapshot without a record (the prototype's,
/// an earlier build's, or one whose record was never stored) may have been
/// folded out of order, or past removals and facts it applied early: it
/// matches only if it equals the fold of the commits it covers that this
/// build would store, which is folded only while `may_fold` is set (and
/// clears it).
#[allow(clippy::too_many_arguments)]
fn check_snapshot(
    env_id: &str,
    state: &StateDir,
    number: &PyInt,
    snapshot: &Map<String, Value>,
    covered: &[Commit],
    later: &[Commit],
    facts: Option<&Facts>,
    all_commits: &[Commit],
    may_fold: &mut bool,
) -> Result<Check> {
    let mut last = None;
    for commit in covered {
        let key = commit::order_key(commit)?;
        if last.as_ref().is_none_or(|l| key > *l) {
            last = Some(key);
        }
    }
    let Some(last) = last else {
        return Ok(Check::Matches);
    };
    for commit in later {
        if commit::order_key(commit)? < last {
            return Ok(Check::Stale);
        }
    }
    let recorded = state
        .read_json(&snapshot_record_path(env_id, number), Value::Null)
        .unwrap_or(Value::Null);
    if !recorded.is_null() {
        return Ok(if recorded == snapshot_record(facts, all_commits) {
            Check::Matches
        } else {
            Check::Stale
        });
    }
    if !std::mem::replace(may_fold, false) {
        return Ok(Check::Stale);
    }
    let (fresh, unflushed) = fold_scheduled(
        env_id,
        covered.to_vec(),
        facts,
        None,
        None,
        None,
        Some(all_commits),
        true,
        None,
    )?;
    Ok(
        if unflushed.as_ref() == snapshot.get("document")
            && Some(&fresh.version_order) == snapshot.get("version_order")
        {
            Check::MatchesUnrecorded
        } else {
            Check::Stale
        },
    )
}

/// Raise `named` to what `vector`, a snapshot's, covers per author.
fn name_commits(named: &mut BTreeMap<String, PyInt>, vector: &Value) {
    let Some(vector) = vector.as_object() else {
        return;
    };
    for (author, value) in vector {
        if let Some(seq) =
            PyInt::from_json_integer(value).filter(|n| n.0.sign() != num_bigint::Sign::Minus)
        {
            let entry = named.entry(author.clone()).or_insert_with(PyInt::zero);
            if seq > *entry {
                *entry = seq;
            }
        }
    }
}

/// Every commit up to what `named` gives each author is stored.
fn stores_every_named(commits: &[Commit], named: &BTreeMap<String, PyInt>) -> bool {
    named.iter().all(|(author, top)| {
        let stored = commits
            .iter()
            .filter(|c| &c.author == author && c.author_seq <= *top)
            .count();
        *top == stored
    })
}

/// Every author's commits are stored from its first one on.
fn stored_from_the_first(commits: &[Commit]) -> bool {
    let mut seqs: BTreeMap<&str, Vec<&PyInt>> = BTreeMap::new();
    for commit in commits {
        seqs.entry(commit.author.as_str())
            .or_default()
            .push(&commit.author_seq);
    }
    seqs.values_mut().all(|seqs| {
        seqs.sort();
        seqs.iter()
            .enumerate()
            .all(|(index, seq)| **seq == index + 1)
    })
}

fn snapshot_record_path(env_id: &str, number: &PyInt) -> String {
    format!("team/{env_id}/snapshot_records/{number}.json")
}

/// The facts a fold used, sorted: a removal by its fact hash (its author
/// and HLC place it), every other fact by what it targets.
fn fact_keys(facts: Option<&Facts>) -> Vec<Value> {
    let Some(facts) = facts else {
        return Vec::new();
    };
    let mut keys: Vec<Value> = Vec::new();
    keys.extend(
        facts
            .removed_members
            .iter()
            .map(|fp| json!(["removed", fp])),
    );
    keys.extend(
        facts
            .removal_facts
            .keys()
            .map(|hash| json!(["removal", hash])),
    );
    keys.extend(
        facts
            .disabled_connections
            .iter()
            .map(|id| json!(["disabled", id])),
    );
    keys.extend(
        facts
            .revoked_versions
            .iter()
            .map(|(secret, version)| json!(["revoked", secret, version])),
    );
    keys.sort_by_key(|key| key.to_string());
    keys.dedup();
    keys
}

/// What a fold over `commits` with `facts` depends on beyond the commits it
/// covers: the facts, and the removal schedule they and every stored
/// commit give (cuts, attested bounds, self-placed removals).
pub fn snapshot_record(facts: Option<&Facts>, commits: &[Commit]) -> Value {
    let none = Facts::default();
    let schedule = RemovalSchedule::new(facts.unwrap_or(&none), commits);
    let pending: Vec<Value> = schedule
        .pending
        .iter()
        .map(|((wall, counter), fp)| json!([wall.value(), counter.value(), fp]))
        .collect();
    let bounds: Map<String, Value> = schedule
        .bounds
        .iter()
        .map(|(fp, seq)| (fp.clone(), seq.value()))
        .collect();
    json!({
        "facts": fact_keys(facts),
        "pending": pending,
        "bounds": bounds,
        "self_placed": schedule.self_placed.iter().collect::<Vec<_>>(),
    })
}

/// Store the record of snapshot `number` ([`snapshot_record`]), so a fold
/// that would depend on anything else does not build on it (issue #35).
/// Kept outside `snapshots/`, whose files keep the prototype's layout.
pub fn save_snapshot_record(
    state: &StateDir,
    env_id: &str,
    number: &PyInt,
    record: &Value,
) -> Result<()> {
    state.write_json(&snapshot_record_path(env_id, number), record)
}

// --------------------------------------------------------------------- derive
fn document_connection_object(
    entry: &Map<String, Value>,
    secret_version: Option<crate::pyint::PyInt>,
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
    before.derive_fields_differ(after)
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
    policy_version: crate::pyint::PyInt,
    status: Option<&str>,
    created_at: Value,
    updated_at: Value,
) -> Result<policy::Connection> {
    c.replaced_bookkeeping(policy_version, status, created_at, updated_at)
}

fn derive_connections(
    document: &Map<String, Value>,
    state: &StateDir,
    env_id: &str,
    version_index: &BTreeMap<String, BTreeMap<String, i64>>,
    previous_ids: &BTreeMap<String, BTreeMap<String, String>>,
    policy: &policy::Policy,
    audit: Option<&Audit>,
) -> Result<()> {
    // `local = state.read_json(P.CONNECTIONS, {}) or {}`: a truthy non-dict
    // has no `.get`/`.items` -- an `AttributeError` before anything is
    // audited or written (both loops below reach it).
    let mut local: Map<String, Value> = match state.read_json(policy::CONNECTIONS, json!({}))? {
        Value::Object(m) => m,
        v if json_falsy(&v) => Map::new(),
        _ => return Err(Error::state("state_corrupt").with_detail("policy_connections")),
    };
    let now_iso = crate::store::iso(None);
    let mut seen_ids: HashSet<String> = HashSet::new();
    // `for conn_id, entry in document["connections"].items()`.
    let connections = py_getitem_map(document, "connections")?
        .as_object()
        .ok_or_else(doc_corrupt)?
        .clone();
    for (conn_id, entry_val) in &connections {
        // An id no derived connection can carry -- only in a document an
        // earlier build folded, such as a compaction snapshot -- is skipped
        // rather than failing the whole derive (issue #54).
        if crate::projects::validate_name(conn_id, "connection_id").is_err() {
            if let Some(audit) = audit {
                audit.record(
                    "team_op_skipped",
                    RecordArgs {
                        result: Some("skipped"),
                        reason: Some("invalid_connection_id"),
                        connection: Some(conn_id),
                        extra: vec![("env_id", json!(env_id)), ("detail", json!("connection"))],
                        ..Default::default()
                    },
                )?;
            }
            continue;
        }
        seen_ids.insert(conn_id.clone());
        // `existing_raw = local.get(conn_id)`; `if existing_raw and
        // existing_raw.get("shared_env") != env_id` (a truthy non-dict has
        // no `.get`).
        let existing_raw =
            match local.get(conn_id) {
                Some(v) if !json_falsy(v) => Some(v.as_object().cloned().ok_or_else(|| {
                    Error::state("state_corrupt").with_detail("policy_connections")
                })?),
                _ => None,
            };
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
        // `secret_id = entry["secret_id"]`; `raw_version =
        // entry.get("secret_version")`; `version_index.get(secret_id,
        // {}).get(raw_version) if raw_version is not None else None` (both
        // lookups hash their key: an unhashable one raises `TypeError`).
        let secret_id = py_getitem(entry_val, "secret_id")?;
        let entry = entry_val.as_object().ok_or_else(doc_corrupt)?;
        let local_version = match entry.get("secret_version") {
            None | Some(Value::Null) => None,
            Some(raw_version) => {
                let versions = py_key(secret_id)?.and_then(|sid| version_index.get(sid));
                let raw_version = py_key(raw_version)?;
                match (versions, raw_version) {
                    (Some(versions), Some(v)) => versions.get(v).copied(),
                    _ => None,
                }
            }
        };
        // `HttpTarget::from_value` preserves Python's unchecked `ca_file`
        // JSON through `raw_ca_file`, so every connection that folded can
        // now be represented and derived locally byte-for-byte as well.
        let mut after =
            document_connection_object(entry, local_version.map(crate::pyint::PyInt::from))?;
        if let Some(existing) = &existing_raw {
            let before = policy::Connection::from_value(&Value::Object(existing.clone()))?;
            // A pin to a different credential is a change even when local
            // renumbering left its version number equal (issue #33).
            let pin_moved = match (&before.secret_version, entry.get("secret_version")) {
                (Some(old), Some(Value::String(new_id))) => previous_ids
                    .get(&before.secret_id)
                    .and_then(|ids| ids.get(&crate::vault::python_str_scalar(old.value())))
                    .is_some_and(|old_id| old_id != new_id),
                _ => false,
            };
            if pin_moved || connection_changed(&before, &after) {
                let widened = policy::Policy::widens(&before, &after)
                    || (after.status == "disabled" && before.status == "active");
                // `before.policy_version + 1`: an unbounded Python `int`.
                let new_version = crate::pyint::PyInt(&before.policy_version.0 + 1);
                after = connection_with(
                    &after,
                    new_version.clone(),
                    None,
                    before.text_value("created_at"),
                    json!(now_iso),
                )?;
                policy.reevaluate_grants(
                    conn_id,
                    &new_version,
                    widened,
                    local_version.map(crate::pyint::PyInt::from),
                )?;
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
                    before.policy_version.clone(),
                    None,
                    before.text_value("created_at"),
                    before.text_value("updated_at"),
                )?;
            }
        } else {
            // `entry.get("created_at", now_iso)`, verbatim.
            let created_at = entry
                .get("created_at")
                .cloned()
                .unwrap_or_else(|| json!(now_iso));
            after = connection_with(&after, 1.into(), None, created_at, json!(now_iso))?;
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
    // `for conn_id, existing_raw in local.items(): if
    // existing_raw.get("shared_env") != env_id or conn_id in seen_ids or
    // existing_raw.get("status") == "disabled": continue` -- in order, so a
    // non-dict entry raises after every earlier stale entry was already
    // disabled (and its grants re-evaluated).
    let keys: Vec<String> = local.keys().cloned().collect();
    for conn_id in keys {
        let Some(existing_raw) = local.get(&conn_id) else {
            continue;
        };
        let obj = existing_raw
            .as_object()
            .ok_or_else(|| Error::state("state_corrupt").with_detail("policy_connections"))?;
        if obj.get("shared_env").and_then(Value::as_str) != Some(env_id)
            || seen_ids.contains(conn_id.as_str())
            || obj.get("status").and_then(Value::as_str) == Some("disabled")
        {
            continue;
        }
        let before = policy::Connection::from_value(existing_raw)?;
        let after = connection_with(
            &before,
            crate::pyint::PyInt(&before.policy_version.0 + 1),
            Some("disabled"),
            before.text_value("created_at"),
            json!(now_iso),
        )?;
        policy.reevaluate_grants(&conn_id, &after.policy_version, true, None)?;
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

/// `container.get(key)` returning a present JSON `null` as `Some`
/// (Python's stored `None`, distinct from the `.get(key, default)`
/// default); `AttributeError` for a non-dict container.
fn py_dict_get_raw<'a>(container: &'a Value, key: &str) -> Result<Option<&'a Value>> {
    Ok(container.as_object().ok_or_else(doc_corrupt)?.get(key))
}

/// `document[key]` for the folded document's top level.
fn py_getitem_map<'a>(document: &'a Map<String, Value>, key: &str) -> Result<&'a Value> {
    document.get(key).ok_or_else(doc_corrupt)
}

/// `secrets_doc.get(secret_id, {})` (then `.get("versions", {}).get(n,
/// {})` for a version) then `.get("created_at", iso())`, each `.get`
/// raising for a non-dict receiver exactly as Python's does.
fn local_created_at(secrets_doc: &Value, secret_id: &str, version: Option<&str>) -> Result<Value> {
    let empty = json!({});
    let mut cursor = py_dict_get_raw(secrets_doc, secret_id)?.unwrap_or(&empty);
    if let Some(number) = version {
        cursor = py_dict_get_raw(cursor, "versions")?.unwrap_or(&empty);
        cursor = py_dict_get_raw(cursor, number)?.unwrap_or(&empty);
    }
    Ok(py_dict_get_raw(cursor, "created_at")?
        .cloned()
        .unwrap_or_else(|| json!(crate::store::iso(None))))
}

/// `dict(record.get("public") or {})`, as a JSON object. `validate_op`
/// only admits a dict; another shape reaches here only from a hand-edited
/// snapshot, and every `dict()` failure escapes `derive_local` (a
/// non-string key cannot be persisted as JSON at all).
fn python_dict_object(value: Option<&Value>) -> Result<Map<String, Value>> {
    let value = match value {
        None => return Ok(Map::new()),
        Some(v) if json_falsy(v) => return Ok(Map::new()),
        Some(v) => v,
    };
    let pairs = commit::python_dict_pairs_checked(value).map_err(|_| doc_corrupt())?;
    let mut out = Map::new();
    for (k, v) in pairs {
        match k {
            Value::String(k) => {
                out.insert(k, v);
            }
            _ => return Err(doc_corrupt()),
        }
    }
    Ok(out)
}

/// The generation key in the file at `dek_path`, unwrapped once per derive
/// into `keys`, as `Vault` reads it to decrypt a shared version. `None` when
/// the file holds no key this node unwraps (empty, malformed, or wrapped
/// under another KMS key): its versions are left underived, like those of a
/// missing file, so one unusable local file holds up no other version. A
/// file that cannot be read fails the derive, as the vault document does,
/// and the refold is retried (section 6.4).
fn generation_key<'k>(
    state: &StateDir,
    kms: &(dyn Kms + Send + Sync),
    dek_path: &str,
    keys: &'k mut HashMap<String, Option<SecretBytes>>,
) -> Result<Option<&'k SecretBytes>> {
    if !keys.contains_key(dek_path) {
        let bytes = state.read_bytes(dek_path)?;
        let key = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| crate::pyjson::loads(text).ok())
            .filter(|doc| !json_falsy(doc))
            .and_then(|doc| crate::kms::WrappedKey::from_dict(&doc).ok())
            .and_then(|wrapped| kms.unwrap(&wrapped).ok());
        keys.insert(dek_path.to_owned(), key);
    }
    Ok(keys.get(dek_path).and_then(Option::as_ref))
}

/// Port of `_derive_vault`. Every subscript and `.get` reproduces Python's
/// (an uncaught built-in exception aborts `derive_local` before this
/// function's own `write_json`, after the DEK files `derive_dek_generations`
/// already wrote).
#[allow(clippy::too_many_arguments)]
fn derive_vault(
    document: &Map<String, Value>,
    state: &StateDir,
    env_id: &str,
    version_index: &BTreeMap<String, BTreeMap<String, i64>>,
    audit: Option<&Audit>,
    kms: Option<&(dyn Kms + Send + Sync)>,
    project: Option<&str>,
    environment: Option<&str>,
) -> Result<()> {
    let vault_corrupt = || Error::state("state_corrupt").with_detail("vault_secrets");
    let doc_val = state.read_json(vault::VAULT_DOC, Value::Null)?;
    if json_falsy(&doc_val) {
        return Ok(()); // local vault not initialized; nothing to derive into
    }
    // `doc.setdefault("secrets", {})`: only a dict has `setdefault`.
    let mut doc = match doc_val {
        Value::Object(m) => m,
        _ => return Err(vault_corrupt()),
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
    // Finding H-R4-8/H-R5-7: `setdefault` inserts `{}` only for an ABSENT
    // key; a present value of any shape is used (and written back) as-is,
    // and only fails once the loop below calls `.get` on it.
    let mut secrets_doc = doc
        .entry("secrets".to_string())
        .or_insert_with(|| json!({}))
        .clone();
    // Each generation's key, unwrapped once; zeroized when dropped.
    let mut generation_keys: HashMap<String, Option<SecretBytes>> = HashMap::new();
    // `for secret_id, entry in document["secrets"].items()`.
    let secrets = py_getitem_map(document, "secrets")?
        .as_object()
        .ok_or_else(doc_corrupt)?;
    for (secret_id, entry) in secrets {
        // `existing = secrets_doc.get(secret_id)`; `if existing and
        // existing.get("shared_env") != env_id`.
        let existing = py_dict_get_raw(&secrets_doc, secret_id)
            .map_err(|_| vault_corrupt())?
            .cloned();
        if let Some(existing) = existing.filter(|v| !json_falsy(v)) {
            let shared_env = existing
                .as_object()
                .ok_or_else(vault_corrupt)?
                .get("shared_env");
            if shared_env.and_then(Value::as_str) != Some(env_id) {
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
        }
        let vindex = version_index.get(secret_id).cloned().unwrap_or_default();
        let mut local_versions: Map<String, Value> = Map::new();
        // `for version_id, record in entry["versions"].items()`.
        let versions = py_getitem(entry, "versions")?
            .as_object()
            .ok_or_else(doc_corrupt)?;
        for (version_id, record) in versions {
            let Some(local_number) = vindex.get(version_id).copied() else {
                continue;
            };
            // `f"team/{env_id}/dek/{record['generation']}.json"`.
            let generation = py_getitem(record, "generation")?.clone();
            let dek_path = format!(
                "team/{env_id}/dek/{}.json",
                commit::python_str_coerce(&generation)
            );
            if !state.exists(&dek_path) {
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
            let number = local_number.to_string();
            let nonce = py_getitem(record, "nonce")?.clone();
            let ciphertext = py_getitem(record, "ciphertext")?.clone();
            let created_at = local_created_at(&secrets_doc, secret_id, Some(&number))?;
            let status = py_getitem(record, "status")?.clone();
            let public = python_dict_object(record.as_object().and_then(|r| r.get("public")))?;
            // Nor one this node cannot decrypt, which every all-vault scan
            // would fail on (issue #57). Checked after Python's subscripts,
            // so a malformed record still fails where Python raised.
            if let Some(kms) = kms {
                let skipped = match generation_key(state, kms, &dek_path, &mut generation_keys)? {
                    None => Some("generation_unavailable"),
                    Some(key) => {
                        let decrypts = record.as_object().is_some_and(|entry| {
                            envelope::decrypt_secret(
                                key.expose(),
                                env_id,
                                secret_id,
                                version_id,
                                entry,
                            )
                            .map(SecretBytes::new)
                            .is_ok()
                        });
                        (!decrypts).then_some("ciphertext_invalid")
                    }
                };
                if let Some(reason) = skipped {
                    if let Some(audit) = audit {
                        audit.record(
                            "team_op_skipped",
                            RecordArgs {
                                result: Some("skipped"),
                                reason: Some(reason),
                                extra: vec![
                                    ("env_id", json!(env_id)),
                                    ("secret_id", json!(secret_id)),
                                ],
                                ..Default::default()
                            },
                        )?;
                    }
                    continue;
                }
            }
            local_versions.insert(
                number,
                json!({
                    "nonce": nonce, "ciphertext": ciphertext, "created_at": created_at,
                    "status": status, "public": public, "shared_env": env_id,
                    "generation": generation, "version_id": version_id,
                }),
            );
        }
        // `active_version_id = entry.get("active_version")`;
        // `vindex.get(active_version_id) if active_version_id else None`.
        let active_version_id = entry.as_object().and_then(|e| e.get("active_version"));
        let mut active_number = match active_version_id {
            Some(v) if !json_falsy(v) => py_key(v)?.and_then(|k| vindex.get(k).copied()),
            _ => None,
        };
        if let Some(n) = active_number
            && !local_versions.contains_key(&n.to_string())
        {
            active_number = None;
        }
        // X-15: `entry["kind"]` is a direct subscript; a missing one aborts
        // the whole derive before anything is written.
        let kind = py_getitem(entry, "kind")?.clone();
        let created_at = local_created_at(&secrets_doc, secret_id, None)?;
        py_setitem(
            &mut secrets_doc,
            &json!(secret_id),
            json!({
                "project": project, "environment": environment,
                "kind": kind,
                "created_at": created_at,
                "active_version": active_number,
                "versions": local_versions,
                "shared_env": env_id,
            }),
        )?;
    }
    doc.insert("secrets".into(), secrets_doc);
    state.write_json(vault::VAULT_DOC, &Value::Object(doc))?;
    Ok(())
}

/// Port of `_derive_dek_generations`: `document["dek"]["generations"]
/// .items()`, `generation.get("wraps", {})`, `wraps.get(fp)` -- each with
/// Python's own failure for a wrong shape.
fn derive_dek_generations(
    document: &Map<String, Value>,
    state: &StateDir,
    kms: &(dyn Kms + Send + Sync),
    device: &DeviceKey,
    env_id: &str,
) -> Result<()> {
    let fp = device.fingerprint()?;
    let generations = py_getitem(py_getitem_map(document, "dek")?, "generations")?
        .as_object()
        .ok_or_else(doc_corrupt)?;
    for (gen_id, generation) in generations {
        let my_wrap = match py_dict_get_raw(generation, "wraps")? {
            None => None,
            Some(wraps) => py_dict_get_raw(wraps, &fp)?.filter(|w| !w.is_null()),
        };
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
            Err(error) if error.is(ErrorClass::InvalidInput) => continue,
            Err(error) => return Err(error),
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
    // `env_id = document["env_id"]`. A non-string value (reachable only from
    // a hand-edited snapshot `document`) is not representable in the
    // string paths below and is refused here.
    let env_id = py_getitem_map(document, "env_id")?
        .as_str()
        .ok_or_else(doc_corrupt)?
        .to_string();
    let version_index = version_index_from_order(&fold_result.version_order)?;
    let mut rebound = Vec::new();
    {
        let _lock = state.lock()?;
        // F1: derive this node's local copies of every DEK generation it
        // can unwrap BEFORE deriving vault entries, so `derive_vault` can
        // tell (by the presence of that file) which shared secret versions
        // it is actually able to decrypt.
        if let (Some(device), Some(kms)) = (device, kms) {
            derive_dek_generations(document, state, kms, device, &env_id)?;
        }
        let before = shared_active_version_ids(state, &env_id)?;
        let previous_ids = shared_version_ids(state, &env_id)?;
        let existed = shared_connection_ids(state, &env_id)?;
        derive_vault(
            document,
            state,
            &env_id,
            &version_index,
            audit,
            kms,
            project,
            environment,
        )?;
        derive_connections(
            document,
            state,
            &env_id,
            &version_index,
            &previous_ids,
            policy,
            audit,
        )?;
        // Issue #33: as a local activation does (`Vault::rebind_connections`),
        // a new active credential re-binds the connections that follow it.
        // Compared by version id: local version numbers can be renumbered by
        // a late commit while naming a different credential.
        let changed: Vec<String> = shared_active_version_ids(state, &env_id)?
            .into_iter()
            .filter(|(secret_id, version_id)| before.get(secret_id) != Some(version_id))
            .map(|(secret_id, _)| secret_id)
            .collect();
        if !changed.is_empty() {
            rebound = rebind_following(state, policy, &env_id, &changed, &existed)?;
        }
    }
    if let Some(audit) = audit {
        for (conn_id, secret_id, version) in &rebound {
            audit.record(
                "connection_update",
                RecordArgs {
                    connection: Some(conn_id),
                    result: Some("ok"),
                    policy_version: Some(version.clone()),
                    extra: vec![
                        ("detail", json!("credential_version")),
                        ("secret_id", json!(secret_id)),
                        ("state", json!("reevaluated")),
                    ],
                    ..Default::default()
                },
            )?;
        }
    }
    if let Some(audit) = audit {
        // F6: `sum(fold_result.vector.values())`, an exact Python int sum
        // of the folded commits per author.
        let count = fold_result
            .vector
            .values()
            .fold(PyInt::zero(), |acc, v| PyInt(acc.0 + &v.0));
        audit.record(
            "team_commit_apply",
            RecordArgs {
                result: Some("ok"),
                extra: vec![("env_id", json!(env_id)), ("count", count.value())],
                ..Default::default()
            },
        )?;
    }
    Ok(version_index)
}

/// The version id of the active version of each local secret shared through
/// `env_id`, as derived into the vault document.
fn shared_active_version_ids(state: &StateDir, env_id: &str) -> Result<BTreeMap<String, String>> {
    let doc = state.read_json(vault::VAULT_DOC, Value::Null)?;
    let mut active = BTreeMap::new();
    for (secret_id, entry) in doc["secrets"].as_object().into_iter().flatten() {
        if entry["shared_env"].as_str() != Some(env_id) {
            continue;
        }
        let version = match &entry["active_version"] {
            Value::Null => continue,
            other => vault::python_str_scalar(other),
        };
        if let Some(version_id) = entry["versions"][version.as_str()]["version_id"].as_str() {
            active.insert(secret_id.clone(), version_id.to_owned());
        }
    }
    Ok(active)
}

/// For each local secret shared through `env_id`, the version id behind
/// each of its local version numbers, before a derive renumbers them.
fn shared_version_ids(
    state: &StateDir,
    env_id: &str,
) -> Result<BTreeMap<String, BTreeMap<String, String>>> {
    let doc = state.read_json(vault::VAULT_DOC, Value::Null)?;
    let mut ids = BTreeMap::new();
    for (secret_id, entry) in doc["secrets"].as_object().into_iter().flatten() {
        if entry["shared_env"].as_str() != Some(env_id) {
            continue;
        }
        let versions = entry["versions"]
            .as_object()
            .into_iter()
            .flatten()
            .filter_map(|(number, record)| {
                record["version_id"]
                    .as_str()
                    .map(|id| (number.clone(), id.to_owned()))
            })
            .collect();
        ids.insert(secret_id.clone(), versions);
    }
    Ok(ids)
}

/// The local connections derived from `env_id` before this derive.
fn shared_connection_ids(state: &StateDir, env_id: &str) -> Result<BTreeSet<String>> {
    let doc = state.read_json(policy::CONNECTIONS, json!({}))?;
    Ok(doc
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, entry)| entry["shared_env"].as_str() == Some(env_id))
        .map(|(id, _)| id.clone())
        .collect())
}

/// Issue #33: each active connection of `env_id` that follows the active
/// version of one of `secrets` gets a policy-version bump that ends old
/// handles, its grants re-evaluated in place to the new credential version,
/// and its approvals invalidated -- whatever version number the grants
/// recorded. The derived entries are edited in place, so `shared_env` and
/// every other derived key stay as `derive_connections` wrote them.
fn rebind_following(
    state: &StateDir,
    policy: &policy::Policy,
    env_id: &str,
    secrets: &[String],
    existed: &BTreeSet<String>,
) -> Result<Vec<(String, String, crate::pyint::PyInt)>> {
    let corrupt = || Error::state("state_corrupt").with_detail("policy_connections");
    let mut connections = state.read_json(policy::CONNECTIONS, json!({}))?;
    let vault_doc = state.read_json(vault::VAULT_DOC, Value::Null)?;
    let now_iso = crate::store::iso(None);
    let mut rebound = Vec::new();
    for (conn_id, entry) in connections.as_object_mut().ok_or_else(corrupt)?.iter_mut() {
        let Some(entry) = entry.as_object_mut() else {
            continue;
        };
        let secret_id = entry.get("secret_id").and_then(Value::as_str).unwrap_or("");
        // A connection this derive created starts at its first policy
        // version; nothing was bound to it yet.
        if !existed.contains(conn_id)
            || entry.get("shared_env").and_then(Value::as_str) != Some(env_id)
            || entry.get("status").and_then(Value::as_str) != Some("active")
            || !matches!(entry.get("secret_version"), None | Some(Value::Null))
            || !secrets.iter().any(|s| s == secret_id)
        {
            continue;
        }
        let secret_id = secret_id.to_owned();
        let current = match entry.get("policy_version") {
            None => crate::pyint::PyInt::zero(),
            Some(value) => crate::pyint::PyInt::coerce_from_json(value).ok_or_else(corrupt)?,
        };
        let next = crate::pyint::PyInt(&current.0 + 1);
        entry.insert("policy_version".into(), next.value());
        entry.insert("updated_at".into(), json!(now_iso));
        rebound.push((conn_id.clone(), secret_id, next));
    }
    if rebound.is_empty() {
        return Ok(rebound);
    }
    state.write_json(policy::CONNECTIONS, &connections)?;
    for (conn_id, secret_id, version) in &rebound {
        let resolved = crate::pyint::PyInt::coerce_from_json(
            &vault_doc["secrets"][secret_id]["active_version"],
        );
        policy.reevaluate_grants(conn_id, version, false, resolved)?;
        let cid = conn_id.clone();
        policy.invalidate_approvals(
            move |e| e.get("connection").and_then(Value::as_str) == Some(cid.as_str()),
            "policy_changed",
        )?;
    }
    Ok(rebound)
}

fn version_index_from_order(raw: &Value) -> Result<BTreeMap<String, BTreeMap<String, i64>>> {
    let mut version_index = BTreeMap::new();
    let version_order = raw
        .as_object()
        .ok_or_else(|| Error::state("state_corrupt").with_detail("team_version_order"))?;
    for (sid, order) in version_order {
        // Python enumerates any iterable here: arrays yield their elements,
        // strings yield Unicode characters, and dicts yield keys. Only
        // non-iterable scalar values fail at this later derive boundary.
        let order: Vec<Value> = match order {
            Value::Array(items) => items.clone(),
            Value::String(text) => text.chars().map(|c| json!(c.to_string())).collect(),
            Value::Object(map) => map.keys().cloned().map(Value::String).collect(),
            Value::Null | Value::Bool(_) | Value::Number(_) => {
                return Err(Error::state("state_corrupt").with_detail("team_version_order"));
            }
        };
        let mut m = BTreeMap::new();
        for (i, vid) in order.iter().enumerate() {
            match vid {
                Value::String(vid) => {
                    m.insert(vid.clone(), (i + 1) as i64);
                }
                Value::Array(_) | Value::Object(_) => {
                    // Python's dict comprehension uses each item as a key;
                    // list/dict keys are unhashable and abort derive before
                    // its state lock or any persisted write.
                    return Err(Error::state("state_corrupt").with_detail("team_version_order"));
                }
                // Numeric/bool/null keys are hashable in Python. Product
                // version ids are strings, so these entries affect later
                // indices but can never match a document version id.
                Value::Null | Value::Bool(_) | Value::Number(_) => {}
            }
        }
        version_index.insert(sid.clone(), m);
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
            .expect_err("a commit whose hlc is past gmtime range must abort the whole fold");
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
    /// peer commit could stop every node. Rust's fold (through the public
    /// `fold()` entry point) must skip the op, not abort.
    #[test]
    fn connection_disable_for_missing_id_skips_even_with_hlc_past_gmtime_range() {
        let huge_wall_ms = WALL_MS_GMTIME_FAILS_AT + 12345;
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
    /// forbids. Python's equivalent handler raised an uncaught `TypeError`
    /// there; `fold()` must return a clean `state_corrupt` error instead of
    /// panicking, for both this shape and the sibling
    /// `secrets.s1.versions = 5` shape the same finding named.
    #[test]
    fn malformed_secret_entry_shapes_fail_closed_instead_of_panicking() {
        // Finding H-R5-6: `secrets.s1 = 5` alone -- with NO op in this
        // `fold()` call ever targeting `"s1"` -- is no longer eagerly
        // rejected: `validate_document_shape` only requires a `secrets`
        // ENTRY be an object when it already is one (see that function's
        // own doc comment), and Python's `fold()` never validates this up
        // front either, confirmed against real `python3.12`:
        // `F.fold("env", [], base_document=doc)` with `doc["secrets"]["s1"]
        // = 5` returns `OK`, the document -- `secrets` included --
        // completely unchanged.
        let (owner, env_id, _dek, c1) = new_env(None);
        let base_result = fold(&env_id, vec![c1], None, None, None, None).unwrap();
        let mut malformed_doc = base_result.document.as_object().unwrap().clone();
        malformed_doc.insert("secrets".into(), json!({"s1": 5}));
        let malformed_doc = Value::Object(malformed_doc);

        let untouched = fold(
            &env_id,
            vec![],
            None,
            Some(malformed_doc.clone()),
            None,
            None,
        )
        .expect("zero commits never touch secrets.s1 -- must fold successfully");
        assert_eq!(
            untouched.document.as_object().unwrap().get("secrets"),
            malformed_doc.as_object().unwrap().get("secrets"),
            "an untouched malformed secrets entry must pass through unchanged, matching Python"
        );
        // The panic risk this test originally guarded against only exists
        // once a real op actually TARGETS the malformed entry (Python's
        // handler raised an uncaught `TypeError` there). Build a real signed
        // `secret.put_version` commit for `"s1"` and fold it against the
        // SAME malformed document: this must now fail closed
        // (`state_corrupt`, not a panic), matching Python's own uncaught
        // `TypeError` from that exact op handler.
        let op = json!({"op": "secret.put_version", "secret_id": "s1", "version_id": random_hex(8),
                        "generation_id": GEN0, "kind": "api_key",
                        "ciphertext": {"nonce": "n", "ciphertext": "c"}});
        let c2 =
            commit::sign_commit(&owner, &env_id, 2, "2000-0000", &Map2::new(), vec![op]).unwrap();
        let err = fold(&env_id, vec![c2], None, Some(malformed_doc), None, None).expect_err(
            "an op that actually targets a non-object secrets.s1 must fail closed, not panic",
        );
        assert!(err.is(crate::errors::ErrorClass::StateError));
        assert_eq!(err.reason, "state_corrupt");

        let (owner, env_id, _dek, c1) = new_env(None);
        let mut doc_bad_versions = fold(&env_id, vec![c1], None, None, None, None)
            .unwrap()
            .document;
        doc_bad_versions["secrets"]["s1"] =
            json!({"kind": "api_key", "active_version": null, "versions": 5});
        let op = json!({"op": "secret.put_version", "secret_id": "s1", "version_id": random_hex(8),
                        "generation_id": GEN0, "kind": "api_key",
                        "ciphertext": {"nonce": "n", "ciphertext": "c"}});
        let c2 =
            commit::sign_commit(&owner, &env_id, 2, "2000-0000", &Map2::new(), vec![op]).unwrap();
        let err = fold(&env_id, vec![c2], None, Some(doc_bad_versions), None, None)
            .expect_err("a non-object secrets.s1.versions must fail closed, not panic");
        assert!(err.is(crate::errors::ErrorClass::StateError));
        assert_eq!(err.reason, "state_corrupt");
    }

    /// Finding H-R4-6: round 3's `validate_document_shape` fix above still
    /// missed seven further shapes that an op handler indexes
    /// UNCONDITIONALLY (a Python dict subscript, not `.get`), so each of
    /// these seven still passed validation and then let `fold()` complete
    /// SUCCESSFULLY with a wrong document, where Python raises an uncaught
    /// exception from the equivalent handler (`KeyError` for all but the
    /// `secrets.s1.versions.v=5` case, a `TypeError`). `fold()` must return
    /// `state_corrupt` when the corresponding op actually accesses that
    /// malformed shape. A no-op fold deliberately preserves malformed
    /// data untouched, matching Python's lazy access semantics.
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
            author: &'static str,
            op: Value,
        }
        let cases: Vec<Case> = vec![
            {
                let mut doc = base_doc();
                doc.insert("connections".into(), json!({"c1": {}}));
                Case {
                    label: "connections.c1={} + connection.disable",
                    doc: Value::Object(doc),
                    author: "owner-fp",
                    op: json!({"op": "connection.disable", "id": "c1"}),
                }
            },
            {
                let mut doc = base_doc();
                doc.insert("connections".into(), json!({"c1": {"status": "active"}}));
                Case {
                    label: "connection without created_at + connection.update",
                    doc: Value::Object(doc),
                    author: "owner-fp",
                    op: json!({"op": "connection.update", "id": "c1"}),
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
                    author: "m2",
                    op: json!({"op": "settings.update", "sync_interval_seconds": 5}),
                }
            },
            {
                let mut doc = base_doc();
                doc.insert("secrets".into(), json!({"s1": {"versions": {}}}));
                Case {
                    label: "secrets.s1={\"versions\":{}} + secret.put_version",
                    doc: Value::Object(doc),
                    author: "owner-fp",
                    op: json!({"op": "secret.put_version", "secret_id": "s1", "version_id": "v1",
                               "generation_id": "g0", "kind": "api_key",
                               "ciphertext": {"nonce": "n", "ciphertext": "c"}}),
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
                    author: "owner-fp",
                    op: json!({"op": "secret.activate", "secret_id": "s1", "version_id": "v1"}),
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
                    author: "owner-fp",
                    op: json!({"op": "secret.activate", "secret_id": "s1", "version_id": "v1"}),
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
                    author: "owner-fp",
                    op: json!({"op": "member.add", "device": new_member_record.clone(),
                               "name": "bob", "role": "user",
                               "wraps": {"g0": {"eph_pub": "a", "nonce": "b", "ciphertext": "c"}}}),
                }
            },
        ];

        for case in &cases {
            let commit = Commit {
                format: "zeropw-team-commit-v1".into(),
                env_id: "env".into(),
                author: case.author.into(),
                author_seq: PyInt::from(1),
                hlc: "1000-0000".into(),
                seen: BTreeMap::new(),
                ops: vec![case.op.clone()],
                sig: String::new(),
            };
            let err = fold(
                "env",
                vec![commit],
                None,
                Some(case.doc.clone()),
                None,
                None,
            )
            .expect_err(&format!(
                "case {:?} must fail closed, not fold open",
                case.label
            ));
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

    /// Finding H-R5-6: `validate_document_shape` used to reject nine
    /// document shapes Python's `fold()` folded without error: with zero
    /// commits nothing is ever dereferenced, so the document passes through
    /// unchanged for every one of these.
    #[test]
    fn nine_over_strict_shapes_now_fold_successfully() {
        fn base(patch: &[(&str, Value)]) -> Value {
            let mut doc: Map<String, Value> = serde_json::from_str(
                r#"{"env_id":"env","format":"zeropw-team-env-v1","owner":"owner-fp",
                    "members":{},"dek":{"current":null,"generations":{}},
                    "connections":{},"secrets":{},
                    "settings":{"sync_interval_seconds":10}}"#,
            )
            .unwrap();
            for (k, v) in patch {
                doc.insert((*k).to_string(), v.clone());
            }
            Value::Object(doc)
        }

        struct Case {
            label: &'static str,
            doc: Value,
        }
        let cases: Vec<Case> = vec![
            Case {
                label: "members null entry",
                doc: base(&[("members", json!({"fp": null}))]),
            },
            Case {
                label: "members zero entry",
                doc: base(&[("members", json!({"fp": 0}))]),
            },
            Case {
                label: "members empty-list entry",
                doc: base(&[("members", json!({"fp": []}))]),
            },
            Case {
                label: "members empty-string entry",
                doc: base(&[("members", json!({"fp": ""}))]),
            },
            Case {
                label: "connections null entry",
                doc: base(&[("connections", json!({"c1": null}))]),
            },
            Case {
                label: "connections zero entry",
                doc: base(&[("connections", json!({"c1": 0}))]),
            },
            Case {
                label: "secrets null entry",
                doc: base(&[("secrets", json!({"s1": null}))]),
            },
            Case {
                label: "format missing",
                doc: {
                    let mut d = base(&[]);
                    d.as_object_mut().unwrap().remove("format");
                    d
                },
            },
            Case {
                label: "owner missing",
                doc: {
                    let mut d = base(&[]);
                    d.as_object_mut().unwrap().remove("owner");
                    d
                },
            },
        ];
        assert_eq!(cases.len(), 9, "must cover exactly the nine shapes");

        for case in &cases {
            let result = fold("env", vec![], None, Some(case.doc.clone()), None, None)
                .unwrap_or_else(|e| panic!("case {:?} must fold successfully: {e:?}", case.label));
            assert_eq!(
                &result.document, &case.doc,
                "case {:?}: an untouched document must pass through unchanged",
                case.label
            );
        }
    }

    /// Finding H-R5-6: `parse_stray_version_order` (used only when a
    /// `base_document` ITSELF already carries a stray `_version_order` key
    /// -- see [`fold`]'s own H-R4-5 doc comment) had no `DEVIATIONS.md`
    /// row. Python preserves a non-object `_version_order`, or a per-secret
    /// value that isn't an array, until a later operation touches it. At that
    /// point `.setdefault`/`.append` raises an uncaught `AttributeError`,
    /// mapped here to `state_corrupt`. Arrays with non-string elements are
    /// retained verbatim; the differential snapshot test pins their bytes.
    #[test]
    fn parse_stray_version_order_fails_closed_matching_pythons_touched_behaviour() {
        fn base_doc(owner: &str) -> Map<String, Value> {
            let mut doc = new_document("env");
            doc.insert("owner".into(), json!(owner));
            doc.insert(
                "members".into(),
                json!({owner: {"name": "o", "role": "admin", "status": "active", "device": {}}}),
            );
            doc.insert(
                "dek".into(),
                json!({"current": GEN0, "generations": {"0000000000000000": {"wraps": {}}}}),
            );
            doc.insert(
                "secrets".into(),
                json!({"s1": {"kind": "api_key", "active_version": null, "versions": {}}}),
            );
            doc
        }

        // A non-object `_version_order` (Python: `.setdefault` on an int
        // raises `AttributeError` once an op actually appends) and a
        // per-key non-array value (Python: `.append` on an int raises)
        // both fail closed here, confirmed against a real touching op.
        let owner = DeviceKey::generate();
        let owner_fp = owner.fingerprint().unwrap();
        for stray in [json!(5), json!({"s1": 5})] {
            let mut doc = base_doc(&owner_fp);
            doc.insert("_version_order".into(), stray.clone());
            let untouched = fold(
                "env",
                vec![],
                None,
                Some(Value::Object(doc.clone())),
                None,
                None,
            )
            .expect("untouched raw order must be preserved");
            assert_eq!(untouched.version_order, stray);
            assert!(untouched.document.get("_version_order").is_none());

            let op = json!({"op": "secret.put_version", "secret_id": "s1", "version_id": "1111111111111111",
                            "generation_id": GEN0, "kind": "api_key",
                            "ciphertext": {"nonce": "n", "ciphertext": "c"}});
            let commit =
                commit::sign_commit(&owner, "env", 1, "1000-0000", &Map2::new(), vec![op]).unwrap();
            let err = fold(
                "env",
                vec![commit.clone()],
                None,
                Some(Value::Object(doc.clone())),
                None,
                None,
            )
            .expect_err(&format!("stray _version_order={stray:?} must fail closed"));
            assert!(err.is(crate::errors::ErrorClass::StateError));
            assert_eq!(err.reason, "state_corrupt");
        }
    }

    /// A raw snapshot `version_order` entry is iterated like Python did:
    /// a string by character, an object by key in document order.
    #[test]
    fn derive_version_index_iterates_raw_strings_and_objects() {
        let cases = [
            (
                json!({"sid": "a\u{1f642}"}),
                json!({"sid": {"a": 1, "\u{1f642}": 2}}),
            ),
            (
                json!({"sid": {"second": 2, "first": 1}}),
                json!({"sid": {"first": 2, "second": 1}}),
            ),
        ];
        for (raw, expected) in cases {
            let rust = version_index_from_order(&raw).unwrap();
            assert_eq!(json!(rust), expected, "raw version_order={raw}");
        }
    }

    /// Finding H-R5-7 (`derive_vault`'s non-object `secrets` check vs
    /// `zeropw/team/fold.py` `_derive_vault`): `secrets_doc = doc.
    /// setdefault("secrets", {})` only gets DEREFERENCED
    /// (`secrets_doc.get(secret_id)`) inside the loop over `document
    /// ["secrets"]` -- for a document with NO secrets to derive, that loop
    /// never runs, so a malformed local `vault/secrets.json` `"secrets"`
    /// field is never touched and `derive_local` succeeds, the local vault
    /// file left completely unchanged.
    #[test]
    fn derive_vault_skips_the_secrets_type_check_when_there_is_nothing_to_derive() {
        use crate::audit::Audit;
        use crate::secret::SecretBytes;

        let (_tmp, state) = new_state();
        // A malformed local vault: "secrets" is a plain number, not a dict.
        state
            .write_json(vault::VAULT_DOC, &json!({"secrets": 5, "other": "keepme"}))
            .unwrap();

        let document: Map<String, Value> = json!({"secrets": {}}).as_object().unwrap().clone();
        let version_index: BTreeMap<String, BTreeMap<String, i64>> = BTreeMap::new();
        let audit: Option<&Audit> = None;
        let result = derive_vault(
            &document,
            &state,
            "env",
            &version_index,
            audit,
            None,
            None,
            None,
        );
        assert!(
            result.is_ok(),
            "derive_vault must succeed when document[\"secrets\"] is empty, matching python: {result:?}"
        );
        let after: Value = state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
        assert_eq!(
            after,
            json!({"secrets": 5, "other": "keepme"}),
            "the malformed local secrets field must be left completely untouched"
        );
        let _ = SecretBytes::new(vec![]); // keep the import used even if unrelated code shifts
    }

    /// X-15 (equivalence review, round 8): `_derive_vault`'s `"kind":
    /// entry["kind"]` is direct indexing, so a team document `secrets`
    /// entry with no `kind` key raises an uncaught `KeyError` from INSIDE
    /// the `for secret_id, entry in document["secrets"].items():` loop --
    /// which is the whole function's body, so nothing after it (including
    /// the trailing `state.write_json`) ever runs. A document with TWO
    /// entries (one well-formed, one missing `kind`) confirms the scope is
    /// the WHOLE derive, not just the malformed entry: even the
    /// well-formed sibling must not be written, matching Python raising
    /// before `state.write_json` ever fires for either.
    #[test]
    fn derive_vault_missing_kind_aborts_the_whole_derive_like_pythons_keyerror() {
        use crate::audit::Audit;

        let (_tmp, state) = new_state();
        let before = json!({"secrets": {}, "other": "keepme"});
        state.write_json(vault::VAULT_DOC, &before).unwrap();

        let document: Map<String, Value> = json!({
            "secrets": {
                "good-secret": {"kind": "api_key", "versions": {}},
                "bad-secret": {"versions": {}},
            }
        })
        .as_object()
        .unwrap()
        .clone();
        let version_index: BTreeMap<String, BTreeMap<String, i64>> = BTreeMap::new();
        let audit: Option<&Audit> = None;
        let result = derive_vault(
            &document,
            &state,
            "env",
            &version_index,
            audit,
            None,
            None,
            None,
        );
        assert!(
            result.is_err(),
            "a secrets entry with no \"kind\" must abort the whole derive, not substitute null"
        );

        let after: Value = state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
        assert_eq!(
            after, before,
            "the local vault file must be left completely untouched -- not even the \
             well-formed \"good-secret\" entry should have been written"
        );
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
    /// checks that (a) the DOCUMENT's value -- not the argument's -- is what
    /// gets appended to, and (b) `_version_order` never appears in the
    /// returned document (both as Python's `fold()` behaved).
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

        let base_version_order_arg: BTreeMap<String, Vec<Value>> =
            [("gh-token".to_string(), vec![json!("arg-v0")])]
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
            Some(&json!(["stray-v0", "2222222222222222"]))
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
    }

    // A-R5-3: `commit_time` at the gmtime boundary. One millisecond under
    // `WALL_MS_GMTIME_FAILS_AT` still renders (the expected string is what
    // the retired Python prototype's `_commit_time` rendered); exactly at
    // it, and for a wall_ms literal beyond i128, it must refuse (Python's
    // uncaught `OverflowError`) rather than format a bogus date.
    #[test]
    fn commit_time_at_the_gmtime_boundary() {
        let commit = Commit {
            format: String::new(),
            env_id: String::new(),
            author: String::new(),
            author_seq: PyInt::from(0),
            hlc: format!("{}-0000", WALL_MS_GMTIME_FAILS_AT - 1),
            ops: Vec::new(),
            seen: BTreeMap::new(),
            sig: String::new(),
        };
        assert_eq!(
            commit_time(&commit).expect("one millisecond under the boundary renders"),
            "2147483647-12-31T23:59:52Z"
        );
        let commit_over = Commit {
            hlc: format!("{WALL_MS_GMTIME_FAILS_AT}-0000"),
            ..commit
        };
        commit_time(&commit_over).expect_err("wall_ms = WALL_MS_GMTIME_FAILS_AT must be refused");
        let commit_huge = Commit {
            hlc: format!("{}-0000", "9".repeat(45)),
            ..commit_over
        };
        commit_time(&commit_huge).expect_err("a wall_ms literal beyond i128 must be refused");
    }

    /// Finding H-R3-1: `commit_time` divides `wall_ms` by 1000 with ONE
    /// correctly-rounded `int / int` division ([`divide_by_1000_like_python`]),
    /// not two roundings (`wall_ms as f64 / 1000.0`), which renders a
    /// different second for many `wall_ms` values above `2^53` (the reviewer
    /// repro `9999999999999999` renders `...T17:46:39Z`, the old code
    /// `...T17:46:40Z`). Expected strings were rendered once by the retired
    /// Python prototype (`iso(wall_ms / 1000)`), including samples between
    /// `2^53` and the `WALL_MS_GMTIME_FAILS_AT` boundary.
    #[test]
    fn commit_time_uses_one_correctly_rounded_division() {
        let cases: [(i128, &str); 8] = [
            (9_999_999_999_999_999, "318857-05-20T17:46:39Z"),
            (9_007_199_254_740_992, "287396-10-12T08:59:00Z"),
            (9_007_199_254_740_993, "287396-10-12T08:59:00Z"),
            (WALL_MS_GMTIME_FAILS_AT - 1, "2147483647-12-31T23:59:52Z"),
            (9_433_176_290_256_686_317, "298927426-10-02T05:31:26Z"),
            (57_391_318_262_068_824_561, "1818660446-12-19T22:40:24Z"),
            (61_437_908_793_891_721_711, "1946891796-03-04T17:02:00Z"),
            (64_763_969_344_647_292_417, "2052290459-03-24T00:14:56Z"),
        ];
        for (wall_ms, want) in cases {
            let commit = Commit {
                format: String::new(),
                env_id: String::new(),
                author: String::new(),
                author_seq: PyInt::from(0),
                hlc: format!("{wall_ms}-0000"),
                ops: Vec::new(),
                seen: BTreeMap::new(),
                sig: String::new(),
            };
            let got = commit_time(&commit)
                .unwrap_or_else(|e| panic!("wall_ms={wall_ms} must render: {e:?}"));
            assert_eq!(got, want, "wall_ms={wall_ms}");
        }
    }

    /// A `wall_ms` literal beyond every fixed width: `Hlc.parse` accepts it
    /// (Python ints are unbounded), `sort_total_order` orders it, and the
    /// fold aborts only when an op actually reaches `_commit_time`
    /// (`wall_ms / 1000` overflows a float / `gmtime` rejects it), exactly
    /// as the uncaught Python exception escapes `fold()`.
    #[test]
    fn connection_create_with_hlc_wall_ms_beyond_i128_also_aborts_the_whole_fold() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        // 45 digits: comfortably beyond i128::MAX (39 digits).
        let huge = "9".repeat(45);
        let hlc = format!("{huge}-0000");
        assert!(Hlc::parse(&hlc).is_ok());
        let c2 = connection_create_commit(&env_id, &owner, 2, &hlc, "gh");
        let err = fold(
            &env_id,
            vec![c1.clone(), c2.clone()],
            None,
            None,
            None,
            None,
        )
        .expect_err("the whole fold must abort, like Python's own OverflowError");
        assert_eq!(err.reason, "team_commit_time_out_of_range");
        // The same commit never touching `_commit_time` folds fine (an op
        // that is skipped before it): an unknown op from the same author.
        let c3 = Commit {
            ops: vec![json!({"op": "nope"})],
            ..c2.clone()
        };
        let folded = fold(
            &env_id,
            vec![c1.clone(), c3.clone()],
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(folded.skipped.len(), 1);
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
        let released = store.release_deferred(far_future, None).unwrap();
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

    // ------------------------------------------- issue #27: removal in order
    const REMOVAL_HASH: &str = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";

    /// `remover` removed `target` by a signed fact at `hlc`.
    fn removal(remover: &DeviceKey, target: &DeviceKey, hlc: &str) -> Facts {
        let target = target.fingerprint().unwrap();
        let mut facts = Facts {
            removed_members: [target.clone()].into_iter().collect(),
            ..Default::default()
        };
        facts.removal_facts.insert(
            REMOVAL_HASH.into(),
            RemovalFact {
                author: remover.fingerprint().unwrap(),
                target,
                hlc: hlc.into(),
            },
        );
        facts
    }

    /// The `dek.rotate` commit `team remove` writes after its fact, signing
    /// the remover's view of every author's sequence.
    fn removal_rotation(
        env_id: &str,
        remover: &DeviceKey,
        seq: i128,
        hlc: &str,
        dek: &[u8],
        seen: &[(&DeviceKey, i128)],
    ) -> Commit {
        let generation = "1111111111111111";
        let record = remover.record().unwrap();
        let mut wraps = Map::new();
        wraps.insert(
            remover.fingerprint().unwrap(),
            envelope::wrap_dek(dek, env_id, generation, &record).unwrap(),
        );
        let seen: Map2<String, PyInt> = seen
            .iter()
            .map(|(device, n)| (device.fingerprint().unwrap(), PyInt::from(*n)))
            .collect();
        let op = json!({"op": "dek.rotate", "generation_id": generation, "wraps": wraps,
                        "removal_fact_hash": REMOVAL_HASH});
        commit::sign_commit(remover, env_id, seq, hlc, &seen, vec![op]).unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn removal_rotation_for(
        env_id: &str,
        remover: &DeviceKey,
        seq: i128,
        hlc: &str,
        dek: &[u8],
        seen: &[(&DeviceKey, i128)],
        hash: &str,
    ) -> Commit {
        let generation = format!("{:016x}", seq + 0x2222);
        let record = remover.record().unwrap();
        let mut wraps = Map::new();
        wraps.insert(
            remover.fingerprint().unwrap(),
            envelope::wrap_dek(dek, env_id, &generation, &record).unwrap(),
        );
        let seen: Map2<String, PyInt> = seen
            .iter()
            .map(|(device, n)| (device.fingerprint().unwrap(), PyInt::from(*n)))
            .collect();
        let op = json!({"op": "dek.rotate", "generation_id": generation, "wraps": wraps,
                        "removal_fact_hash": hash});
        commit::sign_commit(remover, env_id, seq, hlc, &seen, vec![op]).unwrap()
    }

    fn skip_reasons(result: &FoldResult, commit: &Commit) -> Vec<String> {
        let hash = commit.hash().unwrap();
        result
            .skipped
            .iter()
            .filter(|(h, _, _)| *h == hash)
            .map(|(_, _, reason)| reason.clone())
            .collect()
    }

    /// Issue #27: removing an admin keeps what it did while it was one --
    /// its connection, its role change and the member it invited -- and
    /// lists it as removed instead of erasing it.
    #[test]
    fn removal_keeps_the_removed_admins_earlier_work() {
        let (owner, env_id, dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let invited = DeviceKey::generate();
        let add_admin = member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin");
        let create = connection_create_commit(&env_id, &admin, 1, "3000-0000", "gh");
        let add_invited = member_add_commit(&env_id, &admin, 2, "3100-0000", &invited, "user");
        let rotation = removal_rotation(&env_id, &owner, 3, "4001-0000", &dek, &[(&admin, 2)]);
        let commits = vec![c1, add_admin, create, add_invited, rotation];
        let facts = removal(&owner, &admin, "4000-0000");
        let result = fold(&env_id, commits, Some(&facts), None, None, None).unwrap();
        let doc = doc_obj(&result);
        assert!(result.skipped.is_empty(), "{:?}", result.skipped);
        assert!(doc["connections"].as_object().unwrap().contains_key("gh"));
        let members = doc["members"].as_object().unwrap();
        assert_eq!(
            members[&admin.fingerprint().unwrap()]["status"],
            json!("removed")
        );
        assert_eq!(
            members[&invited.fingerprint().unwrap()]["status"],
            json!("active")
        );
        assert_eq!(doc["dek"]["current"], json!("1111111111111111"));
    }

    /// Work the removed member authors after its removal, or backdates in
    /// front of it past what the remover had seen, is skipped.
    #[test]
    fn removed_members_later_or_backdated_work_is_skipped() {
        let (owner, env_id, dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let add_admin = member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin");
        let before = connection_create_commit(&env_id, &admin, 1, "3000-0000", "before");
        let backdated = connection_create_commit(&env_id, &admin, 2, "3500-0000", "backdated");
        let after = connection_create_commit(&env_id, &admin, 3, "5000-0000", "after");
        let rotation = removal_rotation(&env_id, &owner, 3, "4001-0000", &dek, &[(&admin, 1)]);
        let commits = vec![
            c1,
            add_admin,
            before,
            backdated.clone(),
            after.clone(),
            rotation,
        ];
        let facts = removal(&owner, &admin, "4000-0000");
        let result = fold(&env_id, commits, Some(&facts), None, None, None).unwrap();
        let connections = doc_obj(&result)["connections"].as_object().unwrap().clone();
        assert!(connections.contains_key("before"));
        assert!(!connections.contains_key("backdated"));
        assert!(!connections.contains_key("after"));
        assert_eq!(skip_reasons(&result, &backdated), ["member_removed"]);
        assert_eq!(skip_reasons(&result, &after), ["member_removed"]);
    }

    /// Before the remover's rotation commit arrives, the fact's own HLC is
    /// the cut: earlier work stands, later work does not.
    #[test]
    fn removal_without_its_rotation_cuts_at_the_fact() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let add_admin = member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin");
        let before = connection_create_commit(&env_id, &admin, 1, "3000-0000", "before");
        let after = connection_create_commit(&env_id, &admin, 2, "5000-0000", "after");
        let commits = vec![c1, add_admin, before, after.clone()];
        let facts = removal(&owner, &admin, "4000-0000");
        let result = fold(&env_id, commits, Some(&facts), None, None, None).unwrap();
        let connections = doc_obj(&result)["connections"].as_object().unwrap().clone();
        assert!(connections.contains_key("before"));
        assert!(!connections.contains_key("after"));
        assert_eq!(skip_reasons(&result, &after), ["not_admin"]);
    }

    /// The removed fingerprint cannot be admitted again after its removal.
    #[test]
    fn removed_member_is_not_readmitted_after_its_removal() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let member = DeviceKey::generate();
        let add = member_add_commit(&env_id, &owner, 2, "2000-0000", &member, "user");
        let readd = member_add_commit(&env_id, &owner, 3, "5000-0000", &member, "admin");
        let commits = vec![c1, add, readd.clone()];
        let facts = removal(&owner, &member, "4000-0000");
        let result = fold(&env_id, commits, Some(&facts), None, None, None).unwrap();
        let member = &doc_obj(&result)["members"][&member.fingerprint().unwrap()];
        assert_eq!(member["status"], json!("removed"));
        assert_eq!(member["role"], json!("user"));
        assert_eq!(skip_reasons(&result, &readd), ["member_removed"]);
    }

    fn self_removal_fact(target: &DeviceKey, hash: &str, hlc: &str) -> (String, RemovalFact) {
        let fp = target.fingerprint().unwrap();
        (
            hash.into(),
            RemovalFact {
                author: fp.clone(),
                target: fp,
                hlc: hlc.into(),
            },
        )
    }

    fn signed(device: &DeviceKey, env_id: &str, seq: i128, hlc: &str, op: Value) -> Commit {
        commit::sign_commit(device, env_id, seq, hlc, &Map2::new(), vec![op]).unwrap()
    }

    fn connection_ids(result: &FoldResult) -> Vec<String> {
        doc_obj(result)["connections"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }

    /// A removed admin cannot undo its own earlier work with a backdated
    /// self-removal fact: only removals by other devices place the cut,
    /// with or without the remover's attestation.
    #[test]
    fn backdated_self_removal_fact_does_not_move_the_cut() {
        let (owner, env_id, dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let add_admin = member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin");
        let kept = connection_create_commit(&env_id, &admin, 1, "3000-0000", "kept");
        let rotation = removal_rotation(&env_id, &owner, 3, "4001-0000", &dek, &[(&admin, 1)]);
        let mut facts = removal(&owner, &admin, "4000-0000");
        let (hash, fact) = self_removal_fact(&admin, &"6".repeat(64), "2500-0000");
        facts.removal_facts.insert(hash, fact);
        for commits in [
            vec![c1.clone(), add_admin.clone(), kept.clone(), rotation],
            vec![c1, add_admin, kept],
        ] {
            let result = fold(&env_id, commits, Some(&facts), None, None, None).unwrap();
            assert_eq!(connection_ids(&result), ["kept"]);
        }
    }

    /// Removed only by itself, a device is placed by its own `member.remove`
    /// commit: what it did before stands, nothing it signs later counts,
    /// and further self-removal facts change nothing, whatever their HLC. A
    /// bare self-removal fact without that commit keeps the old
    /// from-the-start removal.
    #[test]
    fn self_removal_is_placed_by_its_own_commit() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let fp = admin.fingerprint().unwrap();
        let add_admin = member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin");
        let before = connection_create_commit(&env_id, &admin, 1, "3000-0000", "before");
        let leave = signed(
            &admin,
            &env_id,
            2,
            "4000-0000",
            json!({"op": "member.remove", "fingerprint": fp}),
        );
        let after = connection_create_commit(&env_id, &admin, 3, "5000-0000", "after");
        let mut facts = Facts {
            removed_members: [fp.clone()].into_iter().collect(),
            ..Default::default()
        };
        for (hash, hlc) in [("7".repeat(64), "4000-0001"), ("8".repeat(64), "1500-0000")] {
            let (hash, fact) = self_removal_fact(&admin, &hash, hlc);
            facts.removal_facts.insert(hash, fact);
        }
        let commits = vec![c1, add_admin, before, leave, after.clone()];
        let result = fold(&env_id, commits.clone(), Some(&facts), None, None, None).unwrap();
        assert_eq!(connection_ids(&result), ["before"]);
        assert_eq!(skip_reasons(&result, &after), ["member_removed"]);
        assert_eq!(doc_obj(&result)["members"][&fp]["status"], json!("removed"));
        // Without its own commit the self-removal applies from the start.
        let bare: Vec<Commit> = commits
            .into_iter()
            .filter(|c| c.author_seq != 2 || c.author != fp)
            .collect();
        let result = fold(&env_id, bare, Some(&facts), None, None, None).unwrap();
        assert!(connection_ids(&result).is_empty());
    }

    fn self_removed(device: &DeviceKey, hlc: &str) -> Facts {
        let fp = device.fingerprint().unwrap();
        let mut facts = Facts {
            removed_members: [fp].into_iter().collect(),
            ..Default::default()
        };
        let (hash, fact) = self_removal_fact(device, &"7".repeat(64), hlc);
        facts.removal_facts.insert(hash, fact);
        facts
    }

    fn leave_commit(device: &DeviceKey, env_id: &str, seq: i128, hlc: &str) -> Commit {
        let fp = device.fingerprint().unwrap();
        signed(
            device,
            env_id,
            seq,
            hlc,
            json!({"op": "member.remove", "fingerprint": fp}),
        )
    }

    /// A key that left properly cannot erase what it did as a member with a
    /// self-removal fact dated before its own commit: the device, the member
    /// it admitted and that member's work all stay.
    #[test]
    fn a_backdated_self_removal_fact_erases_nothing() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let admitted = DeviceKey::generate();
        let fp = admin.fingerprint().unwrap();
        let commits = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin"),
            member_add_commit(&env_id, &admin, 1, "2500-0000", &admitted, "admin"),
            connection_create_commit(&env_id, &admitted, 1, "2600-0000", "kept"),
            leave_commit(&admin, &env_id, 2, "3000-0000"),
        ];
        let mut facts = self_removed(&admin, "3000-0001");
        let (hash, fact) = self_removal_fact(&admin, &"8".repeat(64), "1500-0000");
        facts.removal_facts.insert(hash, fact);
        let result = fold(&env_id, commits, Some(&facts), None, None, None).unwrap();
        let members = &doc_obj(&result)["members"];
        assert_eq!(members[&fp]["status"], json!("removed"));
        assert_eq!(
            members[&admitted.fingerprint().unwrap()]["status"],
            json!("active")
        );
        assert_eq!(connection_ids(&result), ["kept"]);
    }

    /// A self-removal commit that cannot apply -- signed before the device
    /// was admitted -- still bounds the device: nothing it signs afterwards
    /// counts, so it cannot keep authority while listed as removed.
    #[test]
    fn a_self_removal_commit_that_cannot_apply_still_bounds_the_device() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let planted = DeviceKey::generate();
        let early_leave = leave_commit(&admin, &env_id, 1, "1500-0000");
        let later_add = member_add_commit(&env_id, &admin, 2, "9000-0000", &planted, "admin");
        let later_conn = connection_create_commit(&env_id, &admin, 3, "9500-0000", "planted");
        let commits = vec![
            c1,
            early_leave.clone(),
            member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin"),
            later_add.clone(),
            later_conn.clone(),
        ];
        let result = fold(
            &env_id,
            commits,
            Some(&self_removed(&admin, "4000-0000")),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(skip_reasons(&result, &early_leave), ["member_not_found"]);
        assert_eq!(skip_reasons(&result, &later_add), ["member_removed"]);
        assert_eq!(skip_reasons(&result, &later_conn), ["member_removed"]);
        let members = &doc_obj(&result)["members"];
        assert!(members.get(planted.fingerprint().unwrap()).is_none());
        assert_eq!(
            members[&admin.fingerprint().unwrap()]["status"],
            json!("removed")
        );
        assert!(connection_ids(&result).is_empty());
    }

    /// The earliest self-removal commit places the removal: a later one
    /// cannot move it back, and work signed after the first counts nowhere,
    /// even dated before it (as a node whose history was compacted could
    /// accept).
    #[test]
    fn the_earliest_self_removal_commit_places_it() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let backdated = connection_create_commit(&env_id, &admin, 3, "3500-0000", "backdated");
        let between = connection_create_commit(&env_id, &admin, 4, "4500-0000", "between");
        let commits = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin"),
            connection_create_commit(&env_id, &admin, 1, "3000-0000", "before"),
            leave_commit(&admin, &env_id, 2, "4000-0000"),
            backdated.clone(),
            between.clone(),
            leave_commit(&admin, &env_id, 5, "5000-0000"),
        ];
        let result = fold(
            &env_id,
            commits,
            Some(&self_removed(&admin, "4000-0001")),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(connection_ids(&result), ["before"]);
        assert_eq!(skip_reasons(&result, &backdated), ["member_removed"]);
        assert_eq!(skip_reasons(&result, &between), ["member_removed"]);
    }

    /// The owner cannot leave, so its self-removal commit is skipped; it
    /// still bounds the owner, so nothing it signs after it counts, a
    /// handover included.
    #[test]
    fn an_owner_signs_nothing_after_its_skipped_self_removal() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let heir = DeviceKey::generate();
        let fp = owner.fingerprint().unwrap();
        let leave = leave_commit(&owner, &env_id, 3, "3000-0000");
        let handover = signed(
            &owner,
            &env_id,
            4,
            "4000-0000",
            json!({"op": "owner.transfer", "fingerprint": heir.fingerprint().unwrap()}),
        );
        let commits = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "2000-0000", &heir, "admin"),
            leave.clone(),
            handover.clone(),
        ];
        let result = fold(
            &env_id,
            commits,
            Some(&self_removed(&owner, "6000-0000")),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(skip_reasons(&result, &leave), ["cannot_remove_owner"]);
        assert_eq!(skip_reasons(&result, &handover), ["member_removed"]);
        assert_eq!(doc_obj(&result)["owner"], json!(fp));
    }

    /// A self-removal folds the same from a snapshot that already covers
    /// its placing commit as from scratch: the bound is taken from every
    /// stored commit, so nothing it excludes comes back on the suffix.
    #[test]
    fn self_removal_folds_the_same_from_a_snapshot() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let planted = DeviceKey::generate();
        let commits = vec![
            c1,
            leave_commit(&admin, &env_id, 1, "1500-0000"),
            member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin"),
            connection_create_commit(&env_id, &owner, 3, "2500-0000", "owners"),
            member_add_commit(&env_id, &admin, 2, "9000-0000", &planted, "admin"),
            connection_create_commit(&env_id, &admin, 3, "9500-0000", "planted"),
        ];
        let facts = self_removed(&admin, "4000-0000");
        let full = fold(&env_id, commits.clone(), Some(&facts), None, None, None).unwrap();
        assert_eq!(connection_ids(&full), ["owners"]);
        for covered in 2..commits.len() {
            let (_tmp, state) = snapshot_state();
            refold_saving(&state, &env_id, &commits[..covered], Some(&facts));
            let refold =
                fold_for_refold(&env_id, commits.clone(), &state, Some(&facts), None).unwrap();
            assert!(refold.stale_snapshots.is_empty(), "covered {covered}");
            assert_eq!(refold.result.document, full.document, "covered {covered}");
        }
    }

    /// Two removals by other devices: the earliest places the cut and the
    /// lowest attested sequence bounds the removed member, so a later
    /// re-issued removal cannot admit work the first one excluded.
    #[test]
    fn lowest_attestation_bounds_a_member_removed_twice() {
        let (owner, env_id, dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let other = DeviceKey::generate();
        let commits = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin"),
            member_add_commit(&env_id, &owner, 3, "2100-0000", &other, "admin"),
            connection_create_commit(&env_id, &admin, 1, "3000-0000", "kept"),
            connection_create_commit(&env_id, &admin, 2, "3500-0000", "relayed"),
            removal_rotation(&env_id, &owner, 4, "4001-0000", &dek, &[(&admin, 1)]),
            removal_rotation_for(
                &env_id,
                &other,
                1,
                "6001-0000",
                &dek,
                &[(&admin, 2)],
                &"9".repeat(64),
            ),
        ];
        let mut facts = removal(&owner, &admin, "4000-0000");
        facts.removal_facts.insert(
            "9".repeat(64),
            RemovalFact {
                author: other.fingerprint().unwrap(),
                target: admin.fingerprint().unwrap(),
                hlc: "6000-0000".into(),
            },
        );
        let result = fold(&env_id, commits, Some(&facts), None, None, None).unwrap();
        assert_eq!(connection_ids(&result), ["kept"]);
    }

    /// Only the remover's own rotation attests: a repair rotation another
    /// admin wrote for the fact bounds nothing, and the fact's HLC alone is
    /// the cut.
    #[test]
    fn another_admins_rotation_does_not_attest_a_removal() {
        let (owner, env_id, dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let other = DeviceKey::generate();
        let commits = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin"),
            member_add_commit(&env_id, &owner, 3, "2100-0000", &other, "admin"),
            connection_create_commit(&env_id, &admin, 1, "3000-0000", "kept"),
            connection_create_commit(&env_id, &admin, 2, "3500-0000", "unbounded"),
            removal_rotation_for(
                &env_id,
                &other,
                1,
                "4001-0000",
                &dek,
                &[(&admin, 1)],
                REMOVAL_HASH,
            ),
        ];
        let facts = removal(&owner, &admin, "4000-0000");
        let result = fold(&env_id, commits, Some(&facts), None, None, None).unwrap();
        assert_eq!(connection_ids(&result), ["kept", "unbounded"]);
    }

    /// Ownership never passes to a member an admitted fact removes, even
    /// when the transfer sorts before the removal: the owner stays active.
    #[test]
    fn ownership_does_not_pass_to_a_removed_member() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let fp = admin.fingerprint().unwrap();
        let transfer = signed(
            &owner,
            &env_id,
            3,
            "3000-0000",
            json!({"op": "owner.transfer", "fingerprint": fp}),
        );
        let commits = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin"),
            transfer.clone(),
        ];
        let facts = removal(&owner, &admin, "4000-0000");
        let result = fold(&env_id, commits, Some(&facts), None, None, None).unwrap();
        let doc = doc_obj(&result);
        assert_eq!(doc["owner"], json!(owner.fingerprint().unwrap()));
        assert_eq!(skip_reasons(&result, &transfer), ["member_removed"]);
        assert_eq!(doc["members"][&fp]["status"], json!("removed"));
    }

    /// The issue #27 headline: the password a removed admin rotated stays
    /// the active version after its removal.
    #[test]
    fn removed_admins_password_rotation_stays_active() {
        let (owner, env_id, dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let version_id = "b".repeat(16);
        let ct = envelope::encrypt_secret(&dek, &env_id, "gh-token", &version_id, SYNTHETIC_SECRET)
            .unwrap();
        let commits = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin"),
            signed(
                &admin,
                &env_id,
                1,
                "3000-0000",
                json!({"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
                       "generation_id": GEN0, "version_id": version_id, "ciphertext": ct,
                       "public": {}}),
            ),
            signed(
                &admin,
                &env_id,
                2,
                "3001-0000",
                json!({"op": "secret.activate", "secret_id": "gh-token", "version_id": version_id}),
            ),
            removal_rotation(&env_id, &owner, 3, "4001-0000", &dek, &[(&admin, 2)]),
        ];
        let facts = removal(&owner, &admin, "4000-0000");
        let result = fold(&env_id, commits, Some(&facts), None, None, None).unwrap();
        assert!(result.skipped.is_empty(), "{:?}", result.skipped);
        assert_eq!(
            doc_obj(&result)["secrets"]["gh-token"]["active_version"],
            json!(version_id)
        );
    }

    /// A snapshot fold places removals from all of history: a removed
    /// admin's commit dated after the snapshot but before the removal fact
    /// is skipped as past the sequence its remover attested in a commit the
    /// snapshot covers, as in a fold from scratch.
    #[test]
    fn snapshot_fold_places_removals_like_a_full_fold() {
        let (owner, env_id, dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let mut commits = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin"),
            connection_create_commit(&env_id, &admin, 1, "3000-0000", "kept"),
            removal_rotation(&env_id, &owner, 3, "4001-0000", &dek, &[(&admin, 1)]),
        ];
        let facts = removal(&owner, &admin, "4002-0000");
        let (_tmp, state) = snapshot_state();
        refold_saving(&state, &env_id, &commits, Some(&facts));
        commits.push(connection_create_commit(
            &env_id,
            &admin,
            2,
            "4001-0005",
            "late",
        ));
        let refold = fold_for_refold(&env_id, commits.clone(), &state, Some(&facts), None).unwrap();
        assert!(
            refold.stale_snapshots.is_empty(),
            "the snapshot is built on"
        );
        let full = fold(&env_id, commits, Some(&facts), None, None, None).unwrap();
        assert_eq!(refold.result.document, full.document);
        assert_eq!(connection_ids(&full), ["kept"]);
    }

    /// What `TeamSync::refold` does when a snapshot is due: fold from the
    /// newest usable snapshot, then store the new one with its facts.
    fn refold_saving(state: &StateDir, env_id: &str, commits: &[Commit], facts: Option<&Facts>) {
        let refold = fold_for_refold(env_id, commits.to_vec(), state, facts, None).unwrap();
        let total = refold
            .result
            .vector
            .values()
            .fold(PyInt::zero(), |acc, v| PyInt(acc.0 + &v.0));
        save_snapshot(state, env_id, &total, &refold.snapshot).unwrap();
        save_snapshot_record(state, env_id, &total, &refold.record).unwrap();
    }

    fn snapshot_state() -> (TempDir, StateDir) {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        (tmp, state)
    }

    fn put_and_activate(
        env_id: &str,
        author: &DeviceKey,
        dek: &[u8],
        seq: i128,
        hlc: &str,
        version_id: &str,
    ) -> Commit {
        let ct = envelope::encrypt_secret(dek, env_id, "s1", version_id, SYNTHETIC_SECRET).unwrap();
        commit::sign_commit(
            author,
            env_id,
            seq,
            hlc,
            &Map2::new(),
            vec![
                json!({"op": "secret.put_version", "secret_id": "s1", "kind": "api_key",
                       "generation_id": GEN0, "version_id": version_id, "ciphertext": ct, "public": {}}),
                json!({"op": "secret.activate", "secret_id": "s1", "version_id": version_id}),
            ],
        )
        .unwrap()
    }

    fn update_commit(env_id: &str, author: &DeviceKey, seq: i128, hlc: &str, text: &str) -> Commit {
        signed(
            author,
            env_id,
            seq,
            hlc,
            json!({"op": "connection.update", "id": "gh", "description": text}),
        )
    }

    /// A snapshot taken when only one author wrote after the previous one
    /// still covers the others: before, the fold after it applied their
    /// commits again over the snapshot, so an older activation came back.
    #[test]
    fn a_second_snapshot_still_covers_idle_authors() {
        let (_tmp, state) = snapshot_state();
        let (owner, env_id, dek, c1) = new_env(None);
        let admin = DeviceKey::generate();
        let commits = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin"),
            put_and_activate(&env_id, &admin, &dek, 1, "3000-0000", "1111111111111111"),
            put_and_activate(&env_id, &owner, &dek, 3, "4000-0000", "2222222222222222"),
        ];
        refold_saving(&state, &env_id, &commits[..3], None);
        refold_saving(&state, &env_id, &commits, None);
        let latest = load_latest_snapshot(&state, &env_id).unwrap().unwrap();
        assert_eq!(latest["vector"][admin.fingerprint().unwrap()], json!(1));
        let from_snapshot =
            fold_with_snapshot(&env_id, commits.clone(), &state, None, None).unwrap();
        let full = fold(&env_id, commits, None, None, None, None).unwrap();
        assert_eq!(from_snapshot.document, full.document);
        assert!(
            from_snapshot.skipped.is_empty(),
            "{:?}",
            from_snapshot.skipped
        );
        assert_eq!(
            full.document["secrets"]["s1"]["active_version"],
            json!("2222222222222222")
        );
    }

    /// Issue #35: a snapshot taken while a removal is known but not yet
    /// reached keeps the member a member, so its work in front of the cut
    /// that arrives later still counts. (The removal here has no
    /// attestation, so nothing else that arrives changes its schedule.) One
    /// stored by an earlier build (the removal already applied, no record)
    /// is passed over.
    #[test]
    fn a_snapshot_does_not_remove_a_member_ahead_of_its_cut() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let commits = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin"),
            connection_create_commit(&env_id, &admin, 1, "3000-0000", "early"),
            connection_create_commit(&env_id, &admin, 2, "3500-0000", "late"),
        ];
        let facts = removal(&owner, &admin, "4000-0000");
        let full = fold(&env_id, commits.clone(), Some(&facts), None, None, None).unwrap();
        assert_eq!(connection_ids(&full), ["early", "late"]);

        let (_tmp, state) = snapshot_state();
        refold_saving(&state, &env_id, &commits[..3], Some(&facts));
        let refold = fold_for_refold(&env_id, commits.clone(), &state, Some(&facts), None).unwrap();
        assert!(refold.stale_snapshots.is_empty());
        assert_eq!(refold.result.document, full.document);

        let (_tmp, state) = snapshot_state();
        let flushed = fold(
            &env_id,
            commits[..3].to_vec(),
            Some(&facts),
            None,
            None,
            None,
        )
        .unwrap();
        save_snapshot(&state, &env_id, &PyInt::from(3), &flushed).unwrap();
        let refold = fold_for_refold(&env_id, commits, &state, Some(&facts), None).unwrap();
        assert!(!refold.stale_snapshots.is_empty());
        assert_eq!(refold.result.document, full.document);
    }

    /// A removal learned after the snapshot, placed inside it, refolds from
    /// scratch: the work the snapshot kept past the cut does not stand.
    #[test]
    fn a_removal_learned_after_the_snapshot_refolds_from_scratch() {
        let (owner, env_id, dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let commits = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin"),
            connection_create_commit(&env_id, &admin, 1, "3000-0000", "kept"),
            connection_create_commit(&env_id, &admin, 2, "3500-0000", "after-cut"),
        ];
        let (_tmp, state) = snapshot_state();
        refold_saving(&state, &env_id, &commits, None);
        let mut all = commits;
        all.push(removal_rotation(
            &env_id,
            &owner,
            3,
            "3201-0000",
            &dek,
            &[(&admin, 1)],
        ));
        let facts = removal(&owner, &admin, "3200-0000");
        let full = fold(&env_id, all.clone(), Some(&facts), None, None, None).unwrap();
        assert_eq!(connection_ids(&full), ["kept"]);
        let refold = fold_for_refold(&env_id, all, &state, Some(&facts), None).unwrap();
        assert!(!refold.stale_snapshots.is_empty());
        assert_eq!(refold.result.document, full.document);
    }

    /// A commit that arrives after the snapshot but sorts inside it refolds
    /// from scratch, so the later of two edits still wins.
    #[test]
    fn a_commit_sorting_inside_the_snapshot_refolds_from_scratch() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let commits = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "1500-0000", &admin, "admin"),
            connection_create_commit(&env_id, &owner, 3, "2000-0000", "gh"),
            update_commit(&env_id, &owner, 4, "3000-0000", "owner-later"),
        ];
        let (_tmp, state) = snapshot_state();
        refold_saving(&state, &env_id, &commits, None);
        let mut all = commits;
        all.push(update_commit(
            &env_id,
            &admin,
            1,
            "2500-0000",
            "admin-earlier",
        ));
        let full = fold(&env_id, all.clone(), None, None, None, None).unwrap();
        assert_eq!(
            full.document["connections"]["gh"]["description"],
            json!("owner-later")
        );
        let refold = fold_for_refold(&env_id, all, &state, None, None).unwrap();
        assert!(!refold.stale_snapshots.is_empty());
        assert_eq!(refold.result.document, full.document);
    }

    /// Past a stale snapshot every covered commit is stored, so an older
    /// one that does not load gives way to a fold from scratch instead of
    /// failing the fold.
    #[test]
    fn a_broken_older_snapshot_gives_way_to_a_fold_from_scratch() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let commits = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "1500-0000", &admin, "admin"),
            connection_create_commit(&env_id, &owner, 3, "2000-0000", "gh"),
            update_commit(&env_id, &owner, 4, "3000-0000", "owner-later"),
        ];
        let (_tmp, state) = snapshot_state();
        refold_saving(&state, &env_id, &commits, None);
        state
            .write_bytes(&format!("{}/1.json", snapshot_dir(&env_id)), b"{broken")
            .unwrap();
        let mut all = commits;
        all.push(update_commit(
            &env_id,
            &admin,
            1,
            "2500-0000",
            "admin-earlier",
        ));
        let full = fold(&env_id, all.clone(), None, None, None, None).unwrap();
        let refold = fold_for_refold(&env_id, all, &state, None, None).unwrap();
        assert_eq!(refold.stale_snapshots, [PyInt::from(4)]);
        assert_eq!(refold.result.document, full.document);
    }

    /// What `TeamSync::refold` does: fold, then store a new snapshot when
    /// one is due or one was passed over, and drop the passed-over ones.
    fn refold_like_teamsync(
        state: &StateDir,
        env_id: &str,
        commits: &[Commit],
        facts: Option<&Facts>,
        due: bool,
    ) -> FoldResult {
        let refold = fold_for_refold(env_id, commits.to_vec(), state, facts, None).unwrap();
        let total = refold
            .result
            .vector
            .values()
            .fold(PyInt::zero(), |acc, v| PyInt(acc.0 + &v.0));
        if due || !refold.stale_snapshots.is_empty() {
            save_snapshot(state, env_id, &total, &refold.snapshot).unwrap();
            save_snapshot_record(state, env_id, &total, &refold.record).unwrap();
            for number in refold.stale_snapshots.iter().filter(|n| **n != total) {
                remove_snapshot(state, env_id, number);
            }
        }
        if let Some(number) = &refold.unrecorded_snapshot {
            save_snapshot_record(state, env_id, number, &refold.record).unwrap();
        }
        refold.result
    }

    /// A removal fact can arrive before its remover's attestation (deferred
    /// for clock skew, or early on a gap). The snapshot the refold stores
    /// then has no bound; when the attestation arrives, the work it excludes
    /// -- here an admin device the removed admin planted -- must go.
    #[test]
    fn an_attestation_after_its_removal_fact_refolds_from_scratch() {
        let (owner, env_id, dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let planted = DeviceKey::generate();
        let mut commits = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin"),
            connection_create_commit(&env_id, &admin, 1, "3000-0000", "early"),
        ];
        let (_tmp, state) = snapshot_state();
        refold_like_teamsync(&state, &env_id, &commits, None, true);
        // The admin's last work, which the remover never sees.
        commits.push(member_add_commit(
            &env_id,
            &admin,
            2,
            "3500-0000",
            &planted,
            "admin",
        ));
        refold_like_teamsync(&state, &env_id, &commits, None, false);
        let facts = removal(&owner, &admin, "4000-0000");
        refold_like_teamsync(&state, &env_id, &commits, Some(&facts), false);
        commits.push(removal_rotation(
            &env_id,
            &owner,
            3,
            "4001-0000",
            &dek,
            &[(&admin, 1)],
        ));
        refold_like_teamsync(&state, &env_id, &commits, Some(&facts), false);
        commits.push(connection_create_commit(
            &env_id,
            &planted,
            1,
            "5000-0000",
            "planted",
        ));
        let node = refold_like_teamsync(&state, &env_id, &commits, Some(&facts), false);
        let full = fold(&env_id, commits, Some(&facts), None, None, None).unwrap();
        assert_eq!(connection_ids(&full), ["early"]);
        assert_eq!(node.document, full.document);
    }

    /// An honest leave signs its `member.remove` before its fact, but a node
    /// can get the fact first: the snapshot it stores then removes the
    /// device from the start, and the leave commit, once it arrives, must
    /// bring back what the device did while a member.
    #[test]
    fn a_leave_commit_after_its_fact_refolds_from_scratch() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let invited = DeviceKey::generate();
        let mut commits = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin"),
            connection_create_commit(&env_id, &admin, 1, "3000-0000", "admins"),
            member_add_commit(&env_id, &admin, 2, "3100-0000", &invited, "user"),
        ];
        let (_tmp, state) = snapshot_state();
        refold_like_teamsync(&state, &env_id, &commits, None, true);
        let facts = self_removed(&admin, "4000-0001");
        refold_like_teamsync(&state, &env_id, &commits, Some(&facts), false);
        commits.push(leave_commit(&admin, &env_id, 3, "4000-0000"));
        let node = refold_like_teamsync(&state, &env_id, &commits, Some(&facts), false);
        let full = fold(&env_id, commits, Some(&facts), None, None, None).unwrap();
        assert_eq!(connection_ids(&full), ["admins"]);
        assert_eq!(
            full.document["members"][invited.fingerprint().unwrap()]["status"],
            json!("active")
        );
        assert_eq!(node.document, full.document);
    }

    /// A snapshot stored by an earlier build has no record and may have been
    /// folded out of order (a late commit applied on top of an older
    /// snapshot): it no longer equals the fold of the commits it covers, so
    /// it is passed over even without facts.
    #[test]
    fn a_snapshot_without_a_record_refolds_from_scratch() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let first = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "1500-0000", &admin, "admin"),
            connection_create_commit(&env_id, &owner, 3, "2000-0000", "gh"),
            update_commit(&env_id, &owner, 4, "3000-0000", "owner-later"),
        ];
        let base = fold(&env_id, first.clone(), None, None, None, None).unwrap();
        let late = update_commit(&env_id, &admin, 1, "2500-0000", "admin-earlier");
        let owner5 = signed(
            &owner,
            &env_id,
            5,
            "5000-0000",
            json!({"op": "settings.update", "sync_interval_seconds": 11}),
        );
        // What an earlier refold stored: the late commit folded over the base.
        let earlier = fold(
            &env_id,
            vec![late.clone(), owner5.clone()],
            None,
            Some(base.document.clone()),
            None,
            None,
        )
        .unwrap();
        let (_tmp, state) = snapshot_state();
        save_snapshot(&state, &env_id, &PyInt::from(6), &earlier).unwrap();
        let mut all = first;
        all.push(late);
        all.push(owner5);
        let full = fold(&env_id, all.clone(), None, None, None, None).unwrap();
        assert_eq!(
            full.document["connections"]["gh"]["description"],
            json!("owner-later")
        );
        let refold = fold_for_refold(&env_id, all, &state, None, None).unwrap();
        assert_eq!(refold.stale_snapshots, [PyInt::from(6)]);
        assert_eq!(refold.unrecorded_snapshot, None);
        assert_eq!(refold.result.document, full.document);
    }

    /// A snapshot whose record was never stored -- a refold stopped between
    /// the two files, here with a fact in force -- is built on once it
    /// equals the fold of the commits it covers, and the refold records it.
    #[test]
    fn an_unrecorded_snapshot_that_matches_is_used_and_recorded() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let mut commits = vec![
            c1,
            connection_create_commit(&env_id, &owner, 2, "2000-0000", "gh"),
            update_commit(&env_id, &owner, 3, "3000-0000", "first"),
        ];
        let facts = Facts {
            disabled_connections: ["old".to_string()].into_iter().collect(),
            ..Default::default()
        };
        let (_tmp, state) = snapshot_state();
        let refold = fold_for_refold(&env_id, commits.clone(), &state, Some(&facts), None).unwrap();
        save_snapshot(&state, &env_id, &PyInt::from(3), &refold.snapshot).unwrap();
        commits.push(update_commit(&env_id, &owner, 4, "4000-0000", "second"));
        let full = fold(&env_id, commits.clone(), Some(&facts), None, None, None).unwrap();
        let refold = fold_for_refold(&env_id, commits.clone(), &state, Some(&facts), None).unwrap();
        assert!(refold.stale_snapshots.is_empty());
        assert_eq!(refold.unrecorded_snapshot, Some(PyInt::from(3)));
        assert_eq!(refold.result.document, full.document);
        refold_like_teamsync(&state, &env_id, &commits, Some(&facts), false);
        assert_eq!(
            state
                .read_json(&snapshot_record_path(&env_id, &PyInt::from(3)), Value::Null)
                .unwrap(),
            snapshot_record(Some(&facts), &commits)
        );
        let refold = fold_for_refold(&env_id, commits, &state, Some(&facts), None).unwrap();
        assert!(refold.stale_snapshots.is_empty());
        assert_eq!(refold.unrecorded_snapshot, None);
    }

    /// The same check folds the commits an unrecorded snapshot covers with
    /// the removal schedule every stored commit gives: an attestation that
    /// arrived after the snapshot still excludes the removed admin's last
    /// work, here a device it planted.
    #[test]
    fn an_attestation_after_an_unrecorded_snapshot_refolds_from_scratch() {
        let (owner, env_id, dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let planted = DeviceKey::generate();
        let mut commits = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin"),
            connection_create_commit(&env_id, &admin, 1, "3000-0000", "early"),
            member_add_commit(&env_id, &admin, 2, "3500-0000", &planted, "admin"),
        ];
        let (_tmp, state) = snapshot_state();
        let facts = removal(&owner, &admin, "4000-0000");
        refold_like_teamsync(&state, &env_id, &commits, Some(&facts), true);
        std::fs::remove_dir_all(state.path.join(format!("team/{env_id}/snapshot_records")))
            .unwrap();
        commits.push(removal_rotation(
            &env_id,
            &owner,
            3,
            "4001-0000",
            &dek,
            &[(&admin, 1)],
        ));
        commits.push(connection_create_commit(
            &env_id,
            &planted,
            1,
            "5000-0000",
            "planted",
        ));
        let refold = fold_for_refold(&env_id, commits.clone(), &state, Some(&facts), None).unwrap();
        assert!(!refold.stale_snapshots.is_empty());
        let full = fold(&env_id, commits, Some(&facts), None, None, None).unwrap();
        assert_eq!(connection_ids(&full), ["early"]);
        assert_eq!(refold.result.document, full.document);
    }

    /// An unrecorded snapshot whose version order differs from that fold's
    /// is passed over too: the fold continuing from it would order versions
    /// by it.
    #[test]
    fn an_unrecorded_snapshot_with_another_version_order_is_passed_over() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let mut commits = vec![
            c1,
            connection_create_commit(&env_id, &owner, 2, "2000-0000", "gh"),
        ];
        let (_tmp, state) = snapshot_state();
        let mut refold = fold_for_refold(&env_id, commits.clone(), &state, None, None).unwrap();
        assert_ne!(refold.snapshot.version_order, json!({}));
        refold.snapshot.version_order = json!({});
        save_snapshot(&state, &env_id, &PyInt::from(2), &refold.snapshot).unwrap();
        commits.push(update_commit(&env_id, &owner, 3, "3000-0000", "later"));
        let refold = fold_for_refold(&env_id, commits.clone(), &state, None, None).unwrap();
        assert_eq!(refold.stale_snapshots, [PyInt::from(2)]);
        let full = fold(&env_id, commits, None, None, None, None).unwrap();
        assert_eq!(refold.result.version_order, full.version_order);
    }

    /// Past two snapshots, the newer one's vector bounds what is not audited
    /// again: the skips between the older one and it were audited when the
    /// newer one was folded.
    #[test]
    fn a_fallback_past_two_snapshots_audits_no_covered_skip_again() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let user = DeviceKey::generate();
        let admin = DeviceKey::generate();
        let mut commits = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "1500-0000", &user, "user"),
            member_add_commit(&env_id, &owner, 3, "1600-0000", &admin, "admin"),
        ];
        let settings = |seq: i128, hlc: &str| {
            signed(
                &owner,
                &env_id,
                seq,
                hlc,
                json!({"op": "settings.update", "sync_interval_seconds": 11}),
            )
        };
        let (_tmp, state) = snapshot_state();
        let audit = Audit::new(&state, crate::clock::fixed(1_700_000_000.0));
        let skips = || {
            state
                .read_lines(crate::audit::AUDIT_FILE, None)
                .unwrap()
                .iter()
                .filter(|line| line.contains("team_op_skipped"))
                .count()
        };
        let refold_saving_audited = |commits: &[Commit]| {
            let refold =
                fold_for_refold(&env_id, commits.to_vec(), &state, None, Some(&audit)).unwrap();
            assert!(refold.stale_snapshots.is_empty());
            let total = refold
                .result
                .vector
                .values()
                .fold(PyInt::zero(), |acc, v| PyInt(acc.0 + &v.0));
            save_snapshot(&state, &env_id, &total, &refold.snapshot).unwrap();
            save_snapshot_record(&state, &env_id, &total, &refold.record).unwrap();
        };
        for seq in 1..=3 {
            commits.push(connection_create_commit(
                &env_id,
                &user,
                seq,
                &format!("3000-{seq:04}"),
                &format!("u{seq}"),
            ));
        }
        commits.push(settings(4, "4000-0000"));
        refold_saving_audited(&commits);
        for seq in 4..=5 {
            commits.push(connection_create_commit(
                &env_id,
                &user,
                seq,
                &format!("5000-{seq:04}"),
                &format!("u{seq}"),
            ));
        }
        commits.push(settings(5, "6000-0000"));
        refold_saving_audited(&commits);
        let before = skips();
        assert_eq!(before, 5);
        // The admin's first commit, dated in front of both snapshots' last.
        commits.push(connection_create_commit(
            &env_id,
            &admin,
            1,
            "3500-0000",
            "a1",
        ));
        let refold = fold_for_refold(&env_id, commits, &state, None, Some(&audit)).unwrap();
        assert_eq!(refold.stale_snapshots.len(), 2);
        assert!(connection_ids(&refold.result).contains(&"a1".to_string()));
        assert_eq!(skips(), before);
    }

    /// A refold that passes a snapshot over does not audit again the skips
    /// in the commits that snapshot covered.
    #[test]
    fn a_fallback_does_not_audit_covered_skips_again() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let user = DeviceKey::generate();
        let mut commits = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "1500-0000", &user, "user"),
        ];
        for seq in 1..=5 {
            commits.push(connection_create_commit(
                &env_id,
                &user,
                seq,
                &format!("2000-{seq:04}"),
                &format!("u{seq}"),
            ));
        }
        commits.push(signed(
            &owner,
            &env_id,
            3,
            "9000-0000",
            json!({"op": "settings.update", "sync_interval_seconds": 11}),
        ));
        let (_tmp, state) = snapshot_state();
        let audit = Audit::new(&state, crate::clock::fixed(1_700_000_000.0));
        let skips = || {
            state
                .read_lines(crate::audit::AUDIT_FILE, None)
                .unwrap()
                .iter()
                .filter(|line| line.contains("team_op_skipped"))
                .count()
        };
        let refold = fold_for_refold(&env_id, commits.clone(), &state, None, Some(&audit)).unwrap();
        let total = refold
            .result
            .vector
            .values()
            .fold(PyInt::zero(), |acc, v| PyInt(acc.0 + &v.0));
        save_snapshot(&state, &env_id, &total, &refold.snapshot).unwrap();
        save_snapshot_record(&state, &env_id, &total, &refold.record).unwrap();
        let before = skips();
        assert_eq!(before, 5);
        // A user commit dated in front of the snapshot's last commit.
        commits.push(connection_create_commit(
            &env_id,
            &user,
            6,
            "2000-0006",
            "u6",
        ));
        let refold = fold_for_refold(&env_id, commits, &state, None, Some(&audit)).unwrap();
        assert!(!refold.stale_snapshots.is_empty());
        assert_eq!(skips() - before, 1);
    }

    /// Past a stale snapshot a fold from scratch needs every commit since
    /// each author's first; with one compacted away it fails closed rather
    /// than drop it.
    #[test]
    fn a_fallback_needs_every_commit_since_the_first() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let first = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "1500-0000", &admin, "admin"),
        ];
        // An earlier build's snapshot whose vector names only the owner; the
        // admin's first commit has since been compacted away, and its second
        // sorts in front of what the snapshot covers.
        let base = fold(&env_id, first.clone(), None, None, None, None).unwrap();
        let (_tmp, state) = snapshot_state();
        save_snapshot(&state, &env_id, &PyInt::from(2), &base).unwrap();
        let mut stored = first;
        stored.push(connection_create_commit(
            &env_id,
            &admin,
            2,
            "1400-0000",
            "kept",
        ));
        let err = fold_for_refold(&env_id, stored, &state, None, None)
            .err()
            .expect("fails closed");
        assert_eq!(err.reason, "state_corrupt");
    }

    /// A snapshot is passed over when an author's commits past its vector
    /// are not stored from the one right after it: here the admin's first
    /// was compacted away and the snapshot does not cover it. With nothing
    /// older to stand in, the fold fails closed instead of losing that
    /// commit, with or without facts.
    #[test]
    fn a_snapshot_missing_a_compacted_commit_it_does_not_cover_fails_closed() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let first = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "1500-0000", &admin, "admin"),
        ];
        let base = fold(&env_id, first.clone(), None, None, None, None).unwrap();
        let (_tmp, state) = snapshot_state();
        save_snapshot(&state, &env_id, &PyInt::from(2), &base).unwrap();
        let mut stored = first;
        stored.push(connection_create_commit(
            &env_id,
            &admin,
            2,
            "3000-0000",
            "kept",
        ));
        let disabled = Facts {
            disabled_connections: ["kept".to_string()].into_iter().collect(),
            ..Default::default()
        };
        for facts in [None, Some(&disabled)] {
            let err = fold_for_refold(&env_id, stored.clone(), &state, facts, None)
                .err()
                .expect("fails closed");
            assert_eq!(err.reason, "state_corrupt");
        }
    }

    /// A fold checks at most one snapshot without a record by folding what
    /// it covers: past one that fails, an older one is passed over
    /// unchecked, even one that would have matched.
    #[test]
    fn a_fold_checks_one_unrecorded_snapshot_at_most() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let first = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "1500-0000", &admin, "admin"),
            connection_create_commit(&env_id, &owner, 3, "2000-0000", "gh"),
        ];
        let (_tmp, state) = snapshot_state();
        // An older snapshot that matches, stored without its record.
        let older = fold_for_refold(&env_id, first.clone(), &state, None, None).unwrap();
        save_snapshot(&state, &env_id, &PyInt::from(3), &older.snapshot).unwrap();
        // A newer one an earlier build folded out of order.
        let mut all = first;
        all.push(update_commit(
            &env_id,
            &owner,
            4,
            "3000-0000",
            "owner-later",
        ));
        let base = fold(&env_id, all.clone(), None, None, None, None).unwrap();
        let late = update_commit(&env_id, &admin, 1, "2500-0000", "admin-earlier");
        let owner5 = signed(
            &owner,
            &env_id,
            5,
            "5000-0000",
            json!({"op": "settings.update", "sync_interval_seconds": 11}),
        );
        let earlier = fold(
            &env_id,
            vec![late.clone(), owner5.clone()],
            None,
            Some(base.document.clone()),
            None,
            None,
        )
        .unwrap();
        save_snapshot(&state, &env_id, &PyInt::from(6), &earlier).unwrap();
        all.push(late);
        all.push(owner5);
        let refold = fold_for_refold(&env_id, all.clone(), &state, None, None).unwrap();
        assert_eq!(refold.stale_snapshots, [PyInt::from(6), PyInt::from(3)]);
        assert_eq!(refold.unrecorded_snapshot, None);
        let full = fold(&env_id, all, None, None, None, None).unwrap();
        assert_eq!(refold.result.document, full.document);
    }

    /// A compaction snapshot ending before a member's removal keeps the
    /// member a member, so what it did after the snapshot and before its
    /// removal still counts once the compacted commits are gone.
    #[test]
    fn compaction_keeps_work_before_a_later_removal() {
        let (owner, env_id, dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let old = connection_create_commit(&env_id, &admin, 1, "2500-0000", "old");
        let commits = vec![
            c1.clone(),
            member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin"),
            old.clone(),
            connection_create_commit(&env_id, &admin, 2, "9000-0000", "recent"),
            removal_rotation(&env_id, &owner, 3, "9601-0000", &dek, &[(&admin, 2)]),
        ];
        let facts = removal(&owner, &admin, "9600-0000");
        let full = fold(&env_id, commits.clone(), Some(&facts), None, None, None).unwrap();
        assert_eq!(connection_ids(&full), ["old", "recent"]);
        let (_tmp, state) = snapshot_state();
        let prefix = sort_total_order(commits.clone()).unwrap()[..3].to_vec();
        let snapshot =
            snapshot_of_prefix(&env_id, prefix, &state, Some(&facts), &commits, None).unwrap();
        save_snapshot(&state, &env_id, &PyInt::from(3), &snapshot).unwrap();
        save_snapshot_record(
            &state,
            &env_id,
            &PyInt::from(3),
            &snapshot_record(Some(&facts), &commits),
        )
        .unwrap();
        // Compaction deletes the prefix's connection commit.
        let kept: Vec<Commit> = commits.into_iter().filter(|c| *c != old).collect();
        let from_snapshot =
            fold_with_snapshot(&env_id, kept.clone(), &state, Some(&facts), None).unwrap();
        assert_eq!(from_snapshot.document, full.document);
        // With history gone, a fact the snapshot did not know cannot send the
        // fold back to scratch: that would drop what was compacted.
        let mut later_facts = facts.clone();
        later_facts.disabled_connections.insert("old".into());
        let from_snapshot =
            fold_with_snapshot(&env_id, kept, &state, Some(&later_facts), None).unwrap();
        assert_eq!(connection_ids(&from_snapshot), ["old", "recent"]);
        assert_eq!(
            from_snapshot.document["connections"]["old"]["status"],
            json!("disabled")
        );
    }

    /// What `TeamSync::compact` does with `stored` up to `cutoff` (an index
    /// in total order): store the prefix's snapshot and record, numbered by
    /// what it covers, then drop the prefix's commits that are not identity
    /// history.
    fn compact_like_teamsync(
        state: &StateDir,
        env_id: &str,
        stored: &mut Vec<Commit>,
        cutoff: usize,
        facts: Option<&Facts>,
    ) -> FoldResult {
        let ordered = sort_total_order(stored.clone()).unwrap();
        let prefix = ordered[..=cutoff].to_vec();
        let snapshot =
            snapshot_of_prefix(env_id, prefix.clone(), state, facts, &ordered, None).unwrap();
        let total = snapshot
            .vector
            .values()
            .fold(PyInt::zero(), |acc, v| PyInt(acc.0 + &v.0));
        save_snapshot(state, env_id, &total, &snapshot).unwrap();
        save_snapshot_record(state, env_id, &total, &snapshot_record(facts, &ordered)).unwrap();
        let identity = [
            "env.init",
            "member.add",
            "member.set_role",
            "member.remove",
            "owner.transfer",
            "dek.rotate",
        ];
        stored.retain(|c| {
            !prefix.contains(c)
                || c.ops
                    .iter()
                    .any(|op| identity.contains(&op["op"].as_str().unwrap_or("")))
        });
        snapshot
    }

    /// Issue #50: a second compaction builds on the first one's snapshot, so
    /// what the first compacted stays, and an admin all of whose commits it
    /// compacted is still covered: its next commit folds instead of leaving
    /// a gap that would fail the fold closed.
    #[test]
    fn a_second_compaction_builds_on_the_first() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let settings = |seq: i128, hlc: &str, interval: i64| {
            signed(
                &owner,
                &env_id,
                seq,
                hlc,
                json!({"op": "settings.update", "sync_interval_seconds": interval}),
            )
        };
        let mut history = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "1500-0000", &admin, "admin"),
            connection_create_commit(&env_id, &admin, 1, "2500-0000", "x"),
            settings(3, "3000-0000", 11),
        ];
        let (_tmp, state) = snapshot_state();
        let mut stored = history.clone();
        compact_like_teamsync(&state, &env_id, &mut stored, 2, None);
        for commit in [settings(4, "4000-0000", 12), settings(5, "4500-0000", 99)] {
            history.push(commit.clone());
            stored.push(commit);
        }
        // A refold's snapshot covering a commit past the next cutoff is no
        // base for that compaction.
        refold_saving(&state, &env_id, &stored, None);
        let second = compact_like_teamsync(&state, &env_id, &mut stored, 3, None);
        assert_eq!(connection_ids(&second), ["x"]);
        assert_eq!(
            second.document["settings"]["sync_interval_seconds"],
            json!(12)
        );
        assert_eq!(
            second.vector.get(&admin.fingerprint().unwrap()),
            Some(&PyInt::from(1))
        );
        for commit in [
            connection_create_commit(&env_id, &admin, 2, "5000-0000", "y"),
            settings(6, "6000-0000", 13),
        ] {
            history.push(commit.clone());
            stored.push(commit);
        }
        let refold = fold_for_refold(&env_id, stored, &state, None, None).unwrap();
        let full = fold(&env_id, history, None, None, None, None).unwrap();
        assert_eq!(connection_ids(&full), ["x", "y"]);
        assert_eq!(refold.result.document, full.document);
    }

    /// The usual first compaction: the only snapshot, a refold's, covers
    /// commits past the cutoff, so the prefix folds from scratch -- which
    /// every stored commit allows, counting those past the cutoff that the
    /// snapshot names -- and the document stays as it was.
    #[test]
    fn a_first_compaction_past_a_refold_snapshot_folds_its_prefix() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let history = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin"),
            connection_create_commit(&env_id, &admin, 1, "2500-0000", "x"),
            signed(
                &owner,
                &env_id,
                3,
                "3000-0000",
                json!({"op": "settings.update", "sync_interval_seconds": 11}),
            ),
            connection_create_commit(&env_id, &admin, 2, "4000-0000", "y"),
        ];
        let (_tmp, state) = snapshot_state();
        refold_saving(&state, &env_id, &history, None);
        let mut stored = history.clone();
        let snapshot = compact_like_teamsync(&state, &env_id, &mut stored, 3, None);
        assert_eq!(connection_ids(&snapshot), ["x"]);
        let refold = fold_for_refold(&env_id, stored, &state, None, None).unwrap();
        let full = fold(&env_id, history, None, None, None, None).unwrap();
        assert_eq!(refold.result.document, full.document);
    }

    /// A second compaction on the first one's snapshot places removals from
    /// every stored commit too: a removed admin's commit inside its prefix,
    /// past the sequence the remover attested after its cutoff, stays
    /// skipped.
    #[test]
    fn a_second_compaction_places_removals_from_every_stored_commit() {
        let (owner, env_id, dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let settings = |seq: i128, hlc: &str, interval: i64| {
            signed(
                &owner,
                &env_id,
                seq,
                hlc,
                json!({"op": "settings.update", "sync_interval_seconds": interval}),
            )
        };
        let mut history = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin"),
            connection_create_commit(&env_id, &admin, 1, "2500-0000", "kept"),
            settings(3, "2600-0000", 11),
        ];
        let facts = removal(&owner, &admin, "5000-0000");
        let (_tmp, state) = snapshot_state();
        let mut stored = history.clone();
        compact_like_teamsync(&state, &env_id, &mut stored, 3, Some(&facts));
        for commit in [
            connection_create_commit(&env_id, &admin, 2, "3000-0000", "late"),
            settings(4, "3100-0000", 12),
            removal_rotation(&env_id, &owner, 5, "6000-0000", &dek, &[(&admin, 1)]),
        ] {
            history.push(commit.clone());
            stored.push(commit);
        }
        let second = compact_like_teamsync(&state, &env_id, &mut stored, 3, Some(&facts));
        assert_eq!(connection_ids(&second), ["kept"]);
        let refold = fold_for_refold(&env_id, stored, &state, Some(&facts), None).unwrap();
        let full = fold(&env_id, history, Some(&facts), None, None, None).unwrap();
        assert_eq!(refold.result.document, full.document);
    }

    /// A member admitted after the first compaction has no entry in its
    /// snapshot's vector; that snapshot still covers none of its commits, so
    /// it remains the base of the second compaction.
    #[test]
    fn a_second_compaction_builds_on_a_base_without_a_later_member() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let newcomer = DeviceKey::generate();
        let settings = |seq: i128, hlc: &str, interval: i64| {
            signed(
                &owner,
                &env_id,
                seq,
                hlc,
                json!({"op": "settings.update", "sync_interval_seconds": interval}),
            )
        };
        let mut history = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin"),
            connection_create_commit(&env_id, &admin, 1, "2500-0000", "x"),
            settings(3, "2600-0000", 11),
        ];
        let (_tmp, state) = snapshot_state();
        let mut stored = history.clone();
        compact_like_teamsync(&state, &env_id, &mut stored, 3, None);
        for commit in [
            member_add_commit(&env_id, &owner, 4, "3000-0000", &newcomer, "admin"),
            settings(5, "3100-0000", 12),
            connection_create_commit(&env_id, &newcomer, 1, "4000-0000", "n1"),
        ] {
            history.push(commit.clone());
            stored.push(commit);
        }
        let second = compact_like_teamsync(&state, &env_id, &mut stored, 3, None);
        assert_eq!(connection_ids(&second), ["x"]);
        let refold = fold_for_refold(&env_id, stored, &state, None, None).unwrap();
        let full = fold(&env_id, history, None, None, None, None).unwrap();
        assert_eq!(connection_ids(&full), ["x", "n1"]);
        assert_eq!(refold.result.document, full.document);
    }

    /// A null snapshot file counts as missing: the compaction snapshot older
    /// than it still stands in for what it compacted, for the next
    /// compaction and for a refold alike.
    #[test]
    fn a_null_snapshot_gives_way_to_an_older_one() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let history = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin"),
            connection_create_commit(&env_id, &admin, 1, "2500-0000", "x"),
            signed(
                &owner,
                &env_id,
                3,
                "2600-0000",
                json!({"op": "settings.update", "sync_interval_seconds": 11}),
            ),
        ];
        let (_tmp, state) = snapshot_state();
        let mut stored = history.clone();
        compact_like_teamsync(&state, &env_id, &mut stored, 2, None);
        state
            .write_json(&format!("team/{env_id}/snapshots/99.json"), &Value::Null)
            .unwrap();
        let ordered = sort_total_order(stored.clone()).unwrap();
        let snapshot =
            snapshot_of_prefix(&env_id, ordered.clone(), &state, None, &ordered, None).unwrap();
        assert_eq!(connection_ids(&snapshot), ["x"]);
        let refold = fold_for_refold(&env_id, stored, &state, None, None).unwrap();
        let full = fold(&env_id, history, None, None, None, None).unwrap();
        assert_eq!(refold.result.document, full.document);
    }

    /// With the compaction snapshot deleted by hand, nothing stands in for
    /// the commits it compacted, and no snapshot is passed over: the refold
    /// fails closed rather than fold the gap from scratch.
    #[test]
    fn a_compacted_history_without_its_snapshot_fails_closed() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let settings = |seq: i128, hlc: &str, interval: i64| {
            signed(
                &owner,
                &env_id,
                seq,
                hlc,
                json!({"op": "settings.update", "sync_interval_seconds": interval}),
            )
        };
        let history = vec![
            c1,
            settings(2, "2000-0000", 11),
            settings(3, "3000-0000", 12),
        ];
        let (_tmp, state) = snapshot_state();
        let mut stored = history.clone();
        let compacted = compact_like_teamsync(&state, &env_id, &mut stored, 1, None);
        let number = compacted
            .vector
            .values()
            .fold(PyInt::zero(), |acc, v| PyInt(acc.0 + &v.0));
        remove_snapshot(&state, &env_id, &number);
        let err = fold_for_refold(&env_id, stored, &state, None, None)
            .err()
            .expect("fails closed");
        assert_eq!(err.reason, "state_corrupt");
    }

    /// A compaction cut before an earlier one (a clock set back) finds every
    /// snapshot covering commits past its cutoff. It does not fold from
    /// scratch over what the earlier compaction deleted -- an owner commit,
    /// and the admin's only one -- but fails closed.
    #[test]
    fn a_compaction_cut_before_an_earlier_one_fails_closed() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let user = DeviceKey::generate();
        let history = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "1200-0000", &admin, "admin"),
            connection_create_commit(&env_id, &admin, 1, "1500-0000", "x"),
            member_add_commit(&env_id, &owner, 3, "2000-0000", &user, "user"),
            signed(
                &owner,
                &env_id,
                4,
                "2500-0000",
                json!({"op": "settings.update", "sync_interval_seconds": 11}),
            ),
        ];
        let (_tmp, state) = snapshot_state();
        let mut stored = history.clone();
        compact_like_teamsync(&state, &env_id, &mut stored, 4, None);
        let ordered = sort_total_order(stored).unwrap();
        let err = snapshot_of_prefix(&env_id, ordered[..2].to_vec(), &state, None, &ordered, None)
            .expect_err("fails closed");
        assert_eq!(err.reason, "state_corrupt");
    }

    /// A compaction places removals from every stored commit, also those past
    /// its cutoff: a removed admin's commit dated inside the prefix, before
    /// the removal fact but past the sequence its remover attested after the
    /// cutoff, stays skipped in the compaction snapshot.
    #[test]
    fn a_compaction_places_removals_from_every_stored_commit() {
        let (owner, env_id, dek, c1) = new_env(Some("gh-token"));
        let admin = DeviceKey::generate();
        let history = vec![
            c1,
            member_add_commit(&env_id, &owner, 2, "2000-0000", &admin, "admin"),
            connection_create_commit(&env_id, &admin, 1, "2500-0000", "kept"),
            connection_create_commit(&env_id, &admin, 2, "3000-0000", "backdated"),
            removal_rotation(&env_id, &owner, 3, "9601-0000", &dek, &[(&admin, 1)]),
        ];
        let facts = removal(&owner, &admin, "5000-0000");
        let (_tmp, state) = snapshot_state();
        // Stored before the attestation arrived: no base for the compaction.
        refold_saving(&state, &env_id, &history[..2], Some(&facts));
        let mut stored = history.clone();
        let snapshot = compact_like_teamsync(&state, &env_id, &mut stored, 3, Some(&facts));
        assert_eq!(connection_ids(&snapshot), ["kept"]);
        let refold = fold_for_refold(&env_id, stored, &state, Some(&facts), None).unwrap();
        let full = fold(&env_id, history, Some(&facts), None, None, None).unwrap();
        assert_eq!(connection_ids(&full), ["kept"]);
        assert_eq!(refold.result.document, full.document);
    }

    /// A snapshot whose later commits leave a gap past the first of them is
    /// passed over too -- also one with a record, and one whose covered
    /// commits were compacted -- so with nothing to stand in the fold fails
    /// closed instead of folding over the gap.
    #[test]
    fn a_gap_anywhere_past_a_snapshot_passes_it_over() {
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let settings = |seq: i128, hlc: &str, interval: i64| {
            signed(
                &owner,
                &env_id,
                seq,
                hlc,
                json!({"op": "settings.update", "sync_interval_seconds": interval}),
            )
        };
        let history = [
            c1.clone(),
            settings(2, "2000-0000", 11),
            settings(3, "3000-0000", 12),
            settings(4, "4000-0000", 13),
            settings(5, "5000-0000", 14),
        ];
        let (_tmp, state) = snapshot_state();
        refold_saving(&state, &env_id, &history[..2], None);
        // The snapshot's second commit and one past its third are gone.
        let stored = vec![c1, history[2].clone(), history[4].clone()];
        let err = fold_for_refold(&env_id, stored, &state, None, None)
            .err()
            .expect("fails closed");
        assert_eq!(err.reason, "state_corrupt");
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
        save_snapshot(&state, &env_id, &PyInt::from(1), &full_before).unwrap();

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
    /// from scratch.
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
    }

    #[test]
    fn unrelated_op_does_not_eagerly_validate_an_untouched_bad_entry() {
        let (owner, env_id, _dek, c1) = new_env(None);
        let base = fold(&env_id, vec![c1], None, None, None, None).unwrap();
        let mut document = base.document;
        document["connections"]
            .as_object_mut()
            .unwrap()
            .insert("untouched-bad".into(), json!({}));
        let c2 = commit::sign_commit(
            &owner,
            &env_id,
            2,
            "2000-0000",
            &Map2::new(),
            vec![json!({"op":"settings.update","sync_interval_seconds":7})],
        )
        .unwrap();
        let base_version_order = parse_snapshot_version_order(Some(&base.version_order)).unwrap();
        let rust = fold(
            &env_id,
            vec![c2.clone()],
            None,
            Some(document.clone()),
            base_version_order,
            None,
        )
        .unwrap();
        let mut expected = document;
        expected["settings"]["sync_interval_seconds"] = json!(7);
        assert_eq!(rust.document, expected);
    }

    /// Finding H-R4-7 (non-object snapshot): Python's `snapshot.get(...)`
    /// raises `AttributeError` for a snapshot whose top-level content is
    /// not a dict -- confirmed here for an array -- and is NOT `None`
    /// (`fold_with_snapshot`'s own `if snapshot is None:` only intercepts
    /// the exact JSON `null` case). `fold()` used to silently ignore the
    /// whole snapshot (every field defaulted) and fold successfully with a
    /// wrong document; now it fails closed with `state_corrupt`.
    #[test]
    fn snapshot_non_object_fails_closed() {
        let (_tmp, state) = new_state();
        let (_owner, env_id, _dek, c1) = new_env(None);
        write_raw_snapshot(&state, &env_id, &json!([1, 2, 3]));

        let err = fold_with_snapshot(&env_id, vec![c1.clone()], &state, None, None)
            .expect_err("a non-object snapshot must fail closed, not silently fold");
        assert!(err.is(crate::errors::ErrorClass::StateError));
        assert_eq!(err.reason, "state_corrupt");
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

        // `version_order` itself is a truthy non-object (an array).
        let snapshot2 = json!({"document": null, "vector": {}, "version_order": [1, 2]});
        write_raw_snapshot(&state, &env_id, &snapshot2);
        let err = fold_with_snapshot(&env_id, vec![c1.clone()], &state, None, None)
            .expect_err("a non-object version_order must fail closed");
        assert!(err.is(crate::errors::ErrorClass::StateError));
        assert_eq!(err.reason, "state_corrupt");
    }

    #[test]
    fn snapshot_author_sequence_compares_integer_to_float_exactly() {
        let rounded_down: Value = serde_json::from_str("9007199254740992.0").unwrap();
        assert!(
            author_seq_is_later(&PyInt::from(9_007_199_254_740_993_i64), Some(&rounded_down))
                .unwrap()
        );
        let rounded_up: Value = serde_json::from_str("9007199254740994.0").unwrap();
        assert!(
            !author_seq_is_later(&PyInt::from(9_007_199_254_740_993_i64), Some(&rounded_up))
                .unwrap()
        );
        let negative_fraction: Value = serde_json::from_str("-1.5").unwrap();
        assert!(author_seq_is_later(&PyInt::from(1), Some(&negative_fraction)).unwrap());
    }

    /// Finding H-R4-7 (vector entry types): Python's `commit.author_seq >
    /// base_vector.get(commit.author, 0)` compares NUMERICALLY against a
    /// bool (`True == 1`) or a float (`1.5`, real value), and raises an
    /// uncaught `TypeError` for a numeric-STRING entry. All three used to
    /// silently become a floor of `0`, letting a replayed/duplicate commit
    /// through as if the snapshot had never covered it.
    #[test]
    fn snapshot_vector_entry_types_compare_numerically() {
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
    }
}
