//! Byte-identical replacement for Python's `json.dumps`/`json.dump`/`json.load`,
//! for the argument combinations the prototype uses. There is no single Python
//! source module for this (every module calls the stdlib `json` directly), so
//! the contract here is derived from grepping `zeropw/` for every `json.dump`,
//! `json.dumps` and `json.load`/`json.loads` call:
//!
//! - `store.py` `write_json`: `json.dump(value, stream, sort_keys=True, indent=2)`
//!   -> [`DumpOptions::pretty_sorted`].
//! - `audit.py` (`record`, `_alert`), `handles.py` (`issue`), `policy.py`
//!   (revocations), `team/membership.py` (facts): `json.dumps(x, sort_keys=True,
//!   separators=(",", ":"))` -> [`DumpOptions::compact_sorted`].
//! - `vault.py` backup archive (`json.dump(archive, stream, sort_keys=True)`,
//!   no `indent`, no `separators`): sort_keys with the *default* separators
//!   `(", ", ": ")` -> [`DumpOptions::default_sorted`].
//! - `gateway.py`/`server.py`/`fake_upstream.py` response payloads
//!   (`json.dumps(payload, sort_keys=True)`): same as `default_sorted`.
//! - `agent_cli.py` (`json.dumps(payload)`, no `sort_keys`): insertion-order,
//!   default separators -> [`DumpOptions::plain`].
//! - `gateway.py` pattern building (`json.dumps(text)[1:-1]` and
//!   `json.dumps(text, ensure_ascii=False)[1:-1]`): encoding a single string
//!   value with `ensure_ascii` True/False -> [`encode_str`].
//!
//! ## Key order
//!
//! `serde_json`'s `preserve_order` feature is enabled, so `Map` is
//! `indexmap`-backed and iterates in insertion order -- matching Python
//! `dict`. [`DumpOptions::sort_keys`] controls output order explicitly:
//! `write_object` sorts a snapshot of the entries by key (`str::cmp`, which
//! orders valid UTF-8 the same way Python's `sorted()` orders `str` by code
//! point) when `true`, exactly Python's `json.dumps(x, sort_keys=True)`
//! (`sorted(dct.items())`), and otherwise writes entries in the `Map`'s
//! existing (insertion) order, exactly Python's `json.dumps(x)`.
//!
//! ## Numbers
//!
//! `serde_json`'s `arbitrary_precision` feature is enabled so integers of any
//! size round-trip exactly (Python `int` is unbounded) and so a parsed value
//! keeps knowing whether it was written as a JSON integer or a JSON float
//! (`3` vs `3.0`). Floats are always re-rendered through [`python_float_repr`],
//! which reimplements `Python/pystrtod.c`'s `format_float_short` (the `'r'`
//! / `repr()` mode `json.dumps` uses for floats): the shortest decimal digit
//! string that round-trips back to the same `f64`, laid out fixed or
//! exponential using CPython's own thresholds. **Finding H-R4-2 (fixed
//! here):** earlier revisions took that shortest digit string directly from
//! Rust's own `{:e}` formatter and assumed it always agreed with CPython's
//! `_Py_dg_dtoa` mode 0 -- false. Both produce *a* correct shortest
//! round-tripping digit string, but the two are independent implementations
//! that can and do disagree on which one to produce in the rare case where
//! two adjacent same-length decimal strings both round-trip to the same
//! `f64` (an exact tie, which happens whenever the double's true value is
//! exactly halfway between them -- typically because the double is itself an
//! exact, terminating binary fraction whose decimal expansion happens to end
//! in a `5` right at the digit position the shortest representation cuts
//! off). CPython's dtoa breaks such ties with round-half-to-even on the
//! digit string; Rust's formatter breaks them the other way.
//! [`python_float_repr`] now detects this exact situation (by literally
//! constructing both same-length neighbours and checking, via Rust's own
//! correctly-rounded string-to-`f64` parser, whether either also round-trips)
//! and picks the even-last-digit candidate when it does, matching CPython
//! byte-for-byte in both the tied and untied cases -- see that function's
//! doc comment for the full algorithm and why no arbitrary-precision
//! arithmetic is needed to get this exactly right.
//!
//! ## NaN / Infinity
//!
//! Python's encoder (`allow_nan=True` by default) can write bare `NaN`,
//! `Infinity`, `-Infinity` tokens, and its decoder accepts them back.
//! Separately, CPython's `float()` silently *overflows* rather than erroring
//! -- a numeric literal like `1e400` parses to `inf` with no exception. No
//! writer in `zeropw/` ever produces a non-finite float or an overflowing
//! literal: audit fields are `round(time.time(), 3)`-derived, and
//! `policy/grants.json` (`Grant.expires_at`, `policy.py:920`) and
//! `policy/control.json` (`approvals[*].expires_at`, `policy.py:1142`/
//! `:1164`) *do* persist a raw `time.time()`-derived float (`now +
//! ttl_seconds` / `now + APPROVAL_TTL_SECONDS`) -- always finite and
//! comfortably in `f64` range, since `self.clock()` never returns a
//! non-finite value. So a non-finite float stays unreachable *through this
//! module's own JSON path*, but this makes [`python_float_repr`]'s CPython
//! byte-identity a **state-file compatibility requirement**, not merely a
//! cosmetic one -- exactly the property round 4's H-R4-2 broke, for these
//! same two documents. On the JSON path itself this port does not
//! special-case non-finite floats: [`dumps`] returns an error for one
//! (defensive, should be unreachable), and [`loads`] rejects the bare
//! tokens *and* any literal that would overflow to a non-finite `f64` as a
//! parse error, like any other malformed JSON. A state file that somehow
//! contained one would be `state_corrupt` in Rust but would silently parse
//! in Python -- recorded in `DEVIATIONS.md`.
//!
//! **Finding X-9 (fixed):** [`python_float_repr`] itself, however, is a
//! `pub fn` with callers outside this module's own JSON path -- and
//! "unreachable through `loads`/`dumps`" is not the same claim as
//! "unreachable, full stop". `team/humanview.rs`'s `number_display` reached
//! it with a non-finite `f64` by re-parsing a `Number`'s raw literal text
//! directly (`"1e400".parse::<f64>()` is `Ok(f64::INFINITY)` -- Rust's
//! parser saturates rather than erroring), bypassing the
//! `Number::as_f64()`-based finiteness filter every *other* float-display
//! call site in this crate already goes through. [`python_float_repr`]
//! used to assume its input was always finite and panicked on one (measured
//! at this function's old first line for `inf`, `-inf` and `NaN` alike);
//! fixed two ways, independently of each other, on the belt-and-suspenders
//! principle a `pub fn` with unenforceable preconditions deserves:
//! [`python_float_repr`] now handles a non-finite input directly (CPython's
//! `repr`/`str`, not `json`'s separate token spelling -- see its own doc
//! comment), and `number_display` no longer re-parses the literal.
//!
//! ## Recursion / nesting depth
//!
//! `serde_json`'s `Value` deserializer refuses more than a hardcoded 128
//! levels of array/object nesting by default (`RECURSION_LIMIT`), a limit
//! CPython's `json` module does not share: probing `python3.12` directly
//! shows `json.loads` happily parsing depths of 128, 129, 200 and 500 (this
//! port's own accepted range -- pinned by
//! `oracle_tests::loads_matches_python_for_probed_nesting_depths`; Python
//! itself keeps going for several thousand more levels past that, an
//! intentional, documented divergence -- see below). A document Python
//! parses without complaint was, before A-R3-1, silently turned into
//! `state_corrupt` (`StateDir::read_json`, `Audit::tail`/`alerts`), a silent
//! skip (`Audit::iter_records`), or a malformed-input error (handle
//! payloads, peer/agent JSON bodies) in this port -- for anything past a
//! mere 128 levels.
//!
//! Simply disabling `serde_json`'s limit and picking one higher fixed bound
//! is not enough, because a `Value` tree is walked by native call-stack
//! recursion on *several* separate operations, not just the parse
//! (`serde_json`'s recursive-descent deserializer for
//! **building** it), and every one of them can run on an
//! arbitrary, possibly small-stack thread the caller chose, not one this
//! module controls -- and, as finding A-R5-1 established, "an ordinary 2
//! MiB stack" is not one fixed number of *available* levels: a real
//! request-handling thread has already used some of that 2 MiB for its own
//! call chain before it ever reaches this module, so the safe depth is
//! whatever fits in the stack *remaining* after that, not the whole 2 MiB.
//! Measured (unoptimized/debug build, this port's own dev-profile probes;
//! all four numbers below are for a stack with *nothing else* on it yet --
//! see A-R5-1's note underneath on why that alone is not sufficient for
//! [`dumps`]):
//!
//! - **Building**/parsing it (`serde_json`'s deserializer): overflows a 2
//!   MiB stack somewhere between 800 and 900 levels of nesting.
//! - **Serializing** it back out ([`dumps`]/[`write_value`]'s own
//!   recursion, this crate's code, exercised on the real state-write path
//!   through `StateDir::write_json`): roughly 1.8-2.0 KiB of stack per
//!   level (finding A-R5-1: 1,000 levels measured at 1.835-1.966 MiB),
//!   overflowing a *fully idle* 2 MiB stack between roughly 1,100 and 1,150
//!   levels -- but finding A-R5-1's actual repro is that this per-level cost
//!   means depth 1,000 also aborts on a 2 MiB stack that had merely 262,144
//!   bytes *already* spent by the caller before ever calling [`dumps`] (800
//!   and 900 levels were still fine at that same pre-used amount): every
//!   request-handling thread in this crate (`fake_upstream.rs`, `signer.rs`)
//!   uses the platform default 2 MiB stack and does real work of its own
//!   before reaching a `dumps`/`write_json` call, so "the old
//!   `MAX_JSON_DEPTH` of 1,000 has margin below the ~1,100-1,150 hazard"
//!   was never the right test -- the previous module doc's "always safe to
//!   render inline" / "comfortably under every one of the measured hazards"
//!   claims here were false, because they only ever accounted for an
//!   otherwise-empty stack.
//! - **Cloning** it (`Value`'s derived, recursively-generated `Clone`):
//!   overflows a 2 MiB stack around 1,800-1,805 levels (probed).
//! - **Comparing** it (`Value`'s derived `PartialEq`, `==`): overflows a 2
//!   MiB stack around 4,876-4,877 levels (probed).
//! - **Dropping** it (`Value`'s derived `Drop` glue, once the caller lets it
//!   go out of scope on whatever thread that happens to be, at a time this
//!   module cannot control): overflows a 2 MiB stack around 8,780-8,781
//!   levels (probed; A-R3-1's original ad hoc measurement put this at
//!   8,000-9,000, consistent).
//!
//! [`loads`] can steer *building* onto a dedicated large-stack thread from
//! inside this module, because it is the one operation [`loads`] fully owns
//! start to finish; since A-R5-1, [`dumps`] does the exact same thing for
//! *serializing* above [`SAFE_INLINE_DEPTH`] (see below) -- the operation
//! whose per-level cost is high enough that a partly-used caller stack can
//! push it over the edge well below [`MAX_JSON_DEPTH`]. `clone`/`==`/drop
//! are not something this module can reroute: clone/compare/drop happen
//! wherever and whenever a caller elsewhere in the crate (or a future one)
//! touches a `Value` it already has in hand, on whatever thread that is --
//! there is no seam here to intercept that and hand it a bigger stack. The
//! only lever this module has over *those* three is [`MAX_JSON_DEPTH`]
//! itself: capping every `Value` this crate ever constructs (via [`loads`])
//! or accepts for output (via [`dumps`]'s own explicit check, see below) low
//! enough that even a caller thread with several hundred KiB already spent
//! still has a wide margin left before the *tightest* of the three -- cloning,
//! at ~1,800 -- ever becomes a risk, without needing a dedicated stack for
//! them at all.
//!
//! [`MAX_JSON_DEPTH`] is **990** (raised from 500 by finding X-3, a HIGH
//! whole-scope cross-unit review finding -- see below for why 500 was
//! wrong; lowered from 1,000 to 500 in the first place by finding A-R5-1,
//! which also closed finding A-R5-2). Comfortably above the 128-500 range
//! this port's own tests require (see above), and strictly below CPython's
//! own tightest real ceiling for the exact write path this product's
//! persistence relies on: probing `python3.12` directly (via the real
//! `StateDir.write_json` API, not just `json.dump` in isolation, since the
//! ceiling is caller-frame-dependent -- confirmed by measuring it two ways)
//! for finding X-3, `json.loads`/compact `json.dumps` both raise
//! `RecursionError` around depth 9,997-9,998 (last accepted 9,996-9,997),
//! while `StateDir.write_json` -- exactly
//! `json.dump(doc, stream, sort_keys=True, indent=2)`, the call this port's
//! own `StateDir::write_json` mirrors -- has a much lower ceiling that
//! genuinely moves with the caller's own stack depth: a bare, minimal-frame
//! call accepts up to depth 996 (raises at 997), while the real production
//! call chain a peer-supplied commit actually drives (`validate_op` ->
//! `sign_commit` -> `CommitStore.append` -> `fold` -> `derive_local` ->
//! `StateDir.write_json`, measured end-to-end against a real `Context`)
//! accepts only up to depth 987 before `derive_local` itself hits
//! `RecursionError` first (`store.py`'s own `except OSError` around the
//! write/rename does not catch `RecursionError`, which is not an `OSError`
//! subclass, so a failure here leaves a stale tmp file and no target file
//! behind). **This is, contrary to what this module's doc used to claim, a
//! document a writer in the matching Python prototype genuinely produces**:
//! `_validate_secret_put_version` places no depth limit at all on
//! `secret.put_version`'s `public` field (only `isinstance(public, dict)`),
//! so an ordinary signed peer commit can carry `public` nested arbitrarily
//! deep and `derive_local` will persist it into `vault/secrets.json`
//! verbatim -- measured end-to-end at depth 600 (comfortably under both
//! ceilings above). 990 sits below BOTH measured `write_json` ceilings
//! (996 bare, 987 via the real attack path), so every document Python's own
//! real call chain can persist is one this port can also read, with
//! deliberate headroom left below `write_json`'s own ceiling rather than
//! flush against it -- an intentional, narrower divergence from CPython's
//! own (considerably higher for `loads`/compact `dumps`) practical ceiling,
//! recorded in `rust/DEVIATIONS.md`.
//!
//! Given that bound, [`loads`] uses a two-tier strategy for *parsing* (so a
//! rare deep document doesn't risk overflowing whatever stack a caller
//! happens to be on, while the overwhelming majority of calls -- a handful
//! of levels deep at most -- pay no extra cost), and (since A-R5-1)
//! [`dumps`] uses the identical two-tier strategy for *serializing*:
//!
//! 1. [`scan_nesting_depth`] (for [`loads`]) / [`value_depth_within`] (for
//!    [`dumps`]) find the maximum `{`/`[` nesting depth up front, rejecting
//!    outright anything past [`MAX_JSON_DEPTH`] before any recursion at all.
//! 2. A document at or below [`SAFE_INLINE_DEPTH`] (200) is parsed/rendered
//!    directly on the calling thread. 200 levels of *building* or
//!    *serializing* is safe even on a small, partly-used stack -- roughly
//!    400 KiB at [`write_value`]'s own measured ~2 KiB/level, leaving well
//!    over 1 MiB of margin on a 2 MiB stack even after several hundred KiB
//!    of prior use -- with a wide margin below the 800-900 build danger zone
//!    and the serializing danger zone alike. Pinned by
//!    `tests::inline_path_is_safe_on_a_small_stack_thread` (parsing) and
//!    covered on the writer side by the at-cap tests below (which exercise
//!    both tiers together).
//! 3. A deeper document (up to [`MAX_JSON_DEPTH`]) is instead *built*
//!    ([`parse_on_dedicated_stack`]) or *rendered*
//!    ([`render_on_dedicated_stack`]) on a freshly spawned thread with an
//!    explicit large stack (64 MiB), so the operation's own stack use is
//!    never at the mercy of how much of the *caller's* stack is already
//!    spent -- closing finding A-R5-1's actual hazard directly, rather than
//!    only relying on a lower [`MAX_JSON_DEPTH`] to leave margin on the
//!    caller's own stack. **A-R7-4 correction:** an earlier version of
//!    [`dumps`] cloned the input `Value` first and moved the owned clone
//!    into a plain `thread::spawn` closure -- but building that clone is
//!    itself a recursive `Value::clone()` that ran on the *calling* thread,
//!    before the spawned thread even started, quietly reintroducing the
//!    exact caller-stack dependency this dedicated-stack tier exists to
//!    remove (the doc comment here called the clone "cheap and safe at this
//!    depth -- ~1,800 levels of headroom", a figure derived from an *idle*
//!    2 MiB stack -- the same reasoning error finding A-R5-1 itself was
//!    raised about, just with a larger margin). Measured with a harness
//!    that genuinely *holds* the caller's stack (recurses, does the work at
//!    the bottom, unwinds after -- not one that burns stack and returns
//!    before calling in): the clone-based `dumps` of a depth-500 document
//!    **aborted the process** with `fatal runtime error: stack overflow` on
//!    a 2 MiB caller stack once ≥1.5 MiB of it was already held, because
//!    `clone` alone needs >512 KiB at that depth (`loads` and `drop` only
//!    need 256 KiB at the same depth). [`render_on_dedicated_stack`] now
//!    uses `std::thread::scope` so the spawned closure can borrow
//!    `value: &Value` directly -- no clone, no caller-stack recursion of
//!    any kind, regardless of how much of the caller's stack is already
//!    spent.
//!
//! A document at or below [`MAX_JSON_DEPTH`] is therefore never rendered by
//! [`dumps`] in a way that depends on how much of the calling thread's own
//! stack is already spent: at or below [`SAFE_INLINE_DEPTH`] the inline
//! render's own footprint is small enough to tolerate realistic prior use,
//! and above it the render happens on a fresh 64 MiB stack instead, reached
//! by reference with no caller-side clone.
//!
//! Tests: `tests::inline_path_is_safe_on_a_small_stack_thread`,
//! `tests::dedicated_stack_path_parses_up_to_max_json_depth`,
//! `tests::depth_past_max_json_depth_is_rejected`, and
//! `tests::dedicated_stack_result_is_safe_to_drop_on_a_small_stack` pin the
//! parsing side; `tests::max_depth_document_is_safe_to_dump_clone_compare_and_drop_on_a_small_stack`,
//! `tests::max_depth_document_is_safe_to_dump_clone_compare_and_drop_on_a_stack_with_prior_usage`
//! (finding A-R5-1's own repro shape: a small stack with several hundred
//! KiB *already spent* before the deep-document operations run -- mirroring
//! the reviewer's exact measurement method) and
//! `tests::dumps_rejects_one_level_past_max_json_depth_without_aborting`
//! pin the writer/clone/compare/drop side -- all three re-run automatically
//! at [`MAX_JSON_DEPTH`]'s new, higher value and still pass, which is the
//! actual proof finding X-3's raised bound does not reopen the A-R5-1/
//! A-R7-4 stack-overflow hazard, not just an arithmetic margin claim.
//! `oracle_tests::loads_matches_python_for_probed_nesting_depths` pins the
//! required probe depths against real `python3.12`,
//! `oracle_tests::python_accepts_depths_past_max_json_depth_that_rust_now_rejects`
//! pins the intentional, narrower-than-CPython divergence past
//! [`MAX_JSON_DEPTH`] (depth 1,000 since finding X-3, with a genuine
//! `json.loads` call on the Python side); and
//! `crate::store::tests::write_json_then_read_json_round_trips_at_max_json_depth`
//! (`rust/src/store.rs`) pins the real `StateDir::read_json`/`write_json`
//! round trip this finding's real-world repro used, and
//! `rust/tests/state_dir_cross_language.rs`'s
//! `write_json_boundary_matches_python_state_dir_write_json_at_the_depth_cap`
//! pins finding A-R5-2's write-direction boundary against real
//! `StateDir.write_json` -- with finding X-3's own
//! `write_json_past_pythons_own_ceiling_is_refused_by_both_languages`
//! (same file) pinning the required *other* direction, that the raised
//! bound still refuses a depth Python's own `write_json` cannot persist
//! either. `rust/tests/team_fold.rs`'s
//! `python_written_state_dir_with_deeply_nested_secret_public_field_opens_in_rust`
//! is finding X-3's own end-to-end repro: a state directory built entirely
//! by real `python3.12` through the actual attack path (`validate_op` ->
//! `sign_commit` -> `CommitStore.append` -> `fold` -> `derive_local`, no
//! Rust code writing anything), with `public` nested 600 deep, then opened
//! by this port's own `Context::open` + `Vault::list_secrets` +
//! `CommitStore::all_commits`.
//!
//! ## Lone surrogates
//!
//! A JSON string may contain an unpaired UTF-16 surrogate `\u` escape (e.g.
//! `"\ud800"` with no following low surrogate) -- the JSON grammar allows
//! any `\uXXXX`, and CPython's decoder accepts it, producing a `str` with a
//! lone surrogate code point. A Rust `String` cannot represent that (it is
//! not a valid Unicode scalar value), and `serde_json` itself silently
//! substitutes U+FFFD instead of erroring, so [`loads`] pre-scans for this
//! case and rejects it (PORTING.md §3.6, `DEVIATIONS.md`).

use std::fmt::Write as _;

use serde::Deserialize as _;
use serde_json::{Number, Value};

use crate::errors::{Error, Result};

/// Maximum array/object nesting depth [`loads`] accepts, and [`dumps`]
/// will render, at all. See the module doc's "Recursion / nesting depth"
/// section for the full reasoning (findings A-R4-1, A-R5-1, A-R5-2, X-3):
/// this bound is shared by both directions specifically so that every
/// `Value` this crate ever builds or accepts stays low enough that
/// cloning/comparing/dropping it (the three operations no dedicated-stack
/// thread can help with, see below) stay safe with a wide margin on an
/// ordinary, partly-used small-stack thread — not just `serde_json`'s own
/// built-in 128-level default, which this value also replaces.
///
/// Lowered from 1,000 to 500 by finding A-R5-1 (closing finding A-R5-2);
/// **raised from 500 to 990 by finding X-3** (HIGH): 500 was chosen purely
/// for `dumps`'s own inline-render stack safety, a concern the dedicated
/// 64 MiB-stack tier below already fully covers past [`SAFE_INLINE_DEPTH`]
/// — but this same constant is also [`loads`]'s acceptance bound, and 500
/// silently rejected a real, unauthenticated-peer-reachable state directory
/// Python's own `derive_local` writes (`secret.put_version`'s `public`
/// field has no depth check in Python at all), taking down `Context::open`
/// for the WHOLE node. 990 is chosen from Python's own measured
/// `StateDir.write_json` ceiling (996 for a bare call, 987 through the real
/// attack's own call chain — both measured for this fix, see the module
/// doc) with deliberate headroom below it, so every document Python's real
/// code can persist is one this port can read back, without accepting
/// anything Python itself cannot write. `clone`/`==`/drop safety at 990
/// (the one genuinely bound-sensitive concern left, since those three can't
/// be routed to a dedicated stack) is re-confirmed, not assumed, by the
/// existing held-caller-stack tests re-run at the new value.
pub const MAX_JSON_DEPTH: usize = 990;

/// Maximum nesting depth [`loads`] parses, and [`dumps`] renders, directly
/// on the calling thread; anything deeper (up to [`MAX_JSON_DEPTH`]) is
/// instead built/rendered on a dedicated large-stack thread. See the module
/// doc's "Recursion / nesting depth" section. Shared by both directions
/// since finding A-R5-1: before that fix, only [`loads`] used this tier —
/// [`dumps`] rendered everything up to [`MAX_JSON_DEPTH`] inline, which is
/// exactly what let a partly-used caller stack push a deep render over the
/// edge.
const SAFE_INLINE_DEPTH: usize = 200;

/// Stack size for the dedicated thread [`parse_on_dedicated_stack`] spawns
/// for a document deeper than [`SAFE_INLINE_DEPTH`]. See the module doc's
/// "Recursion / nesting depth" section for the empirical test backing this
/// number.
const LARGE_PARSE_STACK_BYTES: usize = 64 * 1024 * 1024;

/// Stack size for the dedicated thread [`render_on_dedicated_stack`] spawns
/// for a document deeper than [`SAFE_INLINE_DEPTH`] (finding A-R5-1). Same
/// size as [`LARGE_PARSE_STACK_BYTES`] (kept as a separate constant since
/// the two serve conceptually distinct call sites -- building vs
/// serializing -- even though the number happens to match); either is
/// enormously larger than [`MAX_JSON_DEPTH`] levels of native recursion
/// could ever need at either operation's measured per-level cost.
const LARGE_RENDER_STACK_BYTES: usize = 64 * 1024 * 1024;

/// How to render a [`Value`] tree, mirroring one Python `json.dumps`/`dump`
/// call's keyword arguments.
#[derive(Clone, Copy, Debug)]
pub struct DumpOptions {
    /// `sort_keys=`. See the "Key order" note on the module: `write_object`
    /// sorts a snapshot of the entries by key when this is `true` (Python
    /// `json.dumps(x, sort_keys=True)`), and otherwise writes them in the
    /// `Map`'s existing insertion order (Python `json.dumps(x)`) -- this
    /// crate's `Map` is `indexmap`-backed and does *not* sort on its own, so
    /// `false` genuinely differs from `true` in output, not just intent
    /// (see [`DumpOptions::plain`], the one preset that sets it `false`).
    pub sort_keys: bool,
    /// `separators[0]`: printed between items (after a trailing `\n` +
    /// indent, when `indent` is set).
    pub item_sep: &'static str,
    /// `separators[1]`: printed between an object key and its value.
    pub kv_sep: &'static str,
    /// `indent=`. `None` matches Python's `indent=None` (single-line output).
    pub indent: Option<usize>,
    /// `ensure_ascii=`.
    pub ensure_ascii: bool,
}

impl DumpOptions {
    /// `json.dumps(x, sort_keys=True, separators=(",", ":"))` -- audit
    /// records/alerts, handle payloads, policy revocations, team facts.
    pub const fn compact_sorted() -> Self {
        DumpOptions {
            sort_keys: true,
            item_sep: ",",
            kv_sep: ":",
            indent: None,
            ensure_ascii: true,
        }
    }

    /// `json.dump(x, stream, sort_keys=True, indent=2)` -- `StateDir::write_json`.
    pub const fn pretty_sorted() -> Self {
        DumpOptions {
            sort_keys: true,
            item_sep: ",",
            kv_sep: ": ",
            indent: Some(2),
            ensure_ascii: true,
        }
    }

    /// `json.dumps(x, sort_keys=True)` / `json.dump(x, stream, sort_keys=True)`
    /// -- default separators `(", ", ": ")`, no indent.
    pub const fn default_sorted() -> Self {
        DumpOptions {
            sort_keys: true,
            item_sep: ", ",
            kv_sep: ": ",
            indent: None,
            ensure_ascii: true,
        }
    }

    /// `json.dumps(x)` with none of `sort_keys`/`separators`/`indent` given.
    pub const fn plain() -> Self {
        DumpOptions {
            sort_keys: false,
            item_sep: ", ",
            kv_sep: ": ",
            indent: None,
            ensure_ascii: true,
        }
    }

    /// `ensure_ascii=False`.
    pub const fn ascii(mut self, ensure_ascii: bool) -> Self {
        self.ensure_ascii = ensure_ascii;
        self
    }
}

/// `json.dumps(value, **opts)`.
///
/// A-R4-1: rejects a `value` nested deeper than [`MAX_JSON_DEPTH`] with a
/// clean error *before* recursing into [`write_value`] to render it — see
/// the module doc's "Recursion / nesting depth" section. A-R5-1: like
/// [`loads`], a document deeper than [`SAFE_INLINE_DEPTH`] is rendered on a
/// dedicated large-stack thread ([`render_on_dedicated_stack`]) instead of
/// inline, so [`dumps`] can never abort the process regardless of how much
/// of the *calling* thread's stack is already spent -- round 4's fix (a
/// depth cap chosen to leave margin on an otherwise-empty 2 MiB stack) was
/// not enough on its own, since a real caller thread has already used part
/// of its stack by the time it calls this.
///
/// A-R7-4: `render_on_dedicated_stack` takes `value` **by reference**, via
/// `std::thread::scope`, not by owned clone. An earlier version passed
/// `value.clone()` to a plain `thread::spawn` closure, which forced the
/// recursive `Value::clone()` (needed to produce that owned copy) to run on
/// the *calling* thread before the spawned thread ever started -- silently
/// reintroducing the exact caller-stack dependency this whole
/// dedicated-stack mechanism exists to remove. Measured with a harness that
/// genuinely holds the caller's stack (not just burns and returns it): the
/// clone-based version aborted a depth-500 `dumps` with `fatal runtime
/// error: stack overflow` on a 2 MiB caller stack once ≥1.5 MiB of it was
/// already held. `thread::scope`'s borrowed closure needs no clone at all,
/// so the calling thread does only the fixed, shallow work of setting up
/// the scope — see [`render_on_dedicated_stack`].
pub fn dumps(value: &Value, opts: DumpOptions) -> Result<String> {
    let depth = value_depth_within(value, MAX_JSON_DEPTH)
        .ok_or_else(|| Error::invalid_input("pyjson_max_depth_exceeded").with_detail("dumps"))?;
    if depth <= SAFE_INLINE_DEPTH {
        let mut out = String::new();
        write_value(value, &opts, 0, &mut out)?;
        Ok(out)
    } else {
        render_on_dedicated_stack(value, &opts)
    }
}

/// Renders `value` (already confirmed to be at most [`MAX_JSON_DEPTH`] deep,
/// and deeper than [`SAFE_INLINE_DEPTH`], by [`dumps`]) on a freshly spawned
/// thread with an explicit [`LARGE_RENDER_STACK_BYTES`]-sized stack, so a
/// deep-but-within-bound document is never rendered in a way that depends on
/// how much of the *calling* thread's (possibly small, possibly
/// already-partly-used) stack remains — finding A-R5-1.
///
/// A-R7-4: uses `std::thread::scope` (not `thread::Builder::spawn`) so the
/// spawned closure can borrow `value: &Value` directly instead of requiring
/// an owned `Value` produced by a caller-stack-recursive `.clone()` first.
/// `write_value`'s own recursion — the only stack-heavy work here — now runs
/// exclusively on the new thread's large stack; the calling thread's
/// contribution is the fixed, shallow cost of `thread::scope` itself,
/// regardless of `value`'s depth.
fn render_on_dedicated_stack(value: &Value, opts: &DumpOptions) -> Result<String> {
    std::thread::scope(|scope| {
        let handle = std::thread::Builder::new()
            .stack_size(LARGE_RENDER_STACK_BYTES)
            .spawn_scoped(scope, move || -> Result<String> {
                let mut out = String::new();
                write_value(value, opts, 0, &mut out)?;
                Ok(out)
            })
            .map_err(|_| Error::state("pyjson_render_thread_spawn_failed"))?;
        handle
            .join()
            .unwrap_or_else(|_| Err(Error::state("pyjson_render_thread_panicked")))
    })
}

/// `json.dumps(text)` (or `ensure_ascii=False`): encode a single JSON string,
/// quotes included. Callers reproducing `json.dumps(text)[1:-1]` slice the
/// surrounding quotes off themselves.
pub fn encode_str(s: &str, ensure_ascii: bool) -> String {
    let mut out = String::new();
    write_string(s, ensure_ascii, &mut out);
    out
}

/// `json.load`/`json.loads`. Rejects the bare `NaN`/`Infinity`/`-Infinity`
/// tokens Python's decoder accepts by default, any numeric literal that
/// would overflow to a non-finite `f64` the way CPython's `float()` silently
/// overflows to `inf`/`-inf` (`pyjson_non_finite_float`; see the module doc's
/// "NaN / Infinity" note and `rust/DEVIATIONS.md`), any lone (unpaired)
/// UTF-16 surrogate `\u` escape in a string (PORTING.md §3.6;
/// `rust/DEVIATIONS.md`), and any document nested deeper than
/// [`MAX_JSON_DEPTH`] (module doc's "Recursion / nesting depth" note;
/// `rust/DEVIATIONS.md`) -- `serde_json`'s own built-in recursion limit is
/// disabled (see [`MAX_JSON_DEPTH`]'s doc for why) in favour of that
/// pre-scanned bound.
pub fn loads(text: &str) -> serde_json::Result<Value> {
    reject_lone_surrogate_escapes(text)?;
    let depth = scan_nesting_depth(text, MAX_JSON_DEPTH)?;
    if depth <= SAFE_INLINE_DEPTH {
        parse_and_validate(text)
    } else {
        parse_on_dedicated_stack(text)
    }
}

/// The actual parse plus the (also-recursive, over the same depth)
/// non-finite-number check, run together so both stay on whichever thread
/// [`loads`] decided is safe for this document's depth -- see that
/// function's callers ([`parse_on_dedicated_stack`] in particular) for why
/// running only the parse there and the validation back on the original
/// thread would defeat the whole point of picking a safe stack.
///
/// `disable_recursion_limit` lifts `serde_json`'s own hardcoded 128-level
/// check; for `Value` specifically this also requires the crate's
/// `unbounded_depth` Cargo feature (enabled in `Cargo.toml`) -- without it,
/// `Value`'s deserialization keeps enforcing the 128-level limit on its own
/// regardless of this call. [`scan_nesting_depth`] is this port's real depth
/// bound; disabling the built-in one just lets a document past 128 levels
/// reach it. `end()` reproduces `serde_json::from_str`'s own
/// trailing-garbage check (its internal `from_trait` calls it right after
/// `Deserialize::deserialize`).
fn parse_and_validate(text: &str) -> serde_json::Result<Value> {
    let mut de = serde_json::Deserializer::from_str(text);
    de.disable_recursion_limit();
    let value = Value::deserialize(&mut de)?;
    de.end()?;
    reject_non_finite_numbers(&value)?;
    Ok(value)
}

/// Parses `text` (already confirmed to be at most [`MAX_JSON_DEPTH`] deep by
/// [`scan_nesting_depth`]) on a freshly spawned thread with an explicit
/// [`LARGE_PARSE_STACK_BYTES`]-sized stack, so a deep-but-within-bound
/// document never risks overflowing whatever (possibly small) stack the
/// calling thread happens to have. See the module doc's "Recursion / nesting
/// depth" section.
fn parse_on_dedicated_stack(text: &str) -> serde_json::Result<Value> {
    let owned = text.to_string();
    let handle = std::thread::Builder::new()
        .stack_size(LARGE_PARSE_STACK_BYTES)
        .spawn(move || parse_and_validate(&owned))
        .map_err(|_| {
            <serde_json::Error as serde::de::Error>::custom(
                "failed to spawn the depth-safe JSON parser thread",
            )
        })?;
    handle.join().unwrap_or_else(|_| {
        Err(<serde_json::Error as serde::de::Error>::custom(
            "the depth-safe JSON parser thread panicked",
        ))
    })
}

/// Pre-scan for a lone (unpaired) surrogate `\u` escape inside a JSON string
/// literal, before handing the text to `serde_json`: `serde_json` itself
/// does not error on one, it silently substitutes U+FFFD (it must -- a Rust
/// `String` cannot hold an unpaired surrogate), which this port must instead
/// treat as malformed input (§3.6). Minimal hand-rolled scan: track
/// "inside a string literal" state (respecting backslash escapes) and,
/// within a string, validate every `\uXXXX` escape's surrogate-ness against
/// what immediately follows it. Byte-level scanning is safe here because
/// every UTF-8 continuation byte is `>= 0x80` and therefore never equals any
/// of the ASCII bytes (`"`, `\`, hex digits) this scan compares against.
fn reject_lone_surrogate_escapes(text: &str) -> serde_json::Result<()> {
    fn hex4(bytes: &[u8]) -> Option<u32> {
        if bytes.len() < 4 {
            return None;
        }
        std::str::from_utf8(&bytes[..4])
            .ok()
            .and_then(|s| u32::from_str_radix(s, 16).ok())
    }

    let bytes = text.as_bytes();
    let mut i = 0;
    let mut in_string = false;
    while i < bytes.len() {
        let b = bytes[i];
        if !in_string {
            if b == b'"' {
                in_string = true;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' => {
                in_string = false;
                i += 1;
            }
            b'\\' if i + 1 < bytes.len() && bytes[i + 1] == b'u' => {
                let code = hex4(&bytes[i + 2..]).ok_or_else(|| {
                    <serde_json::Error as serde::de::Error>::custom("malformed \\u escape")
                })?;
                if (0xD800..=0xDBFF).contains(&code) {
                    // High surrogate: valid only immediately followed by a
                    // low surrogate escape.
                    let paired = bytes.get(i + 6) == Some(&b'\\')
                        && bytes.get(i + 7) == Some(&b'u')
                        && hex4(&bytes[i + 8..]).is_some_and(|c2| (0xDC00..=0xDFFF).contains(&c2));
                    if !paired {
                        return Err(<serde_json::Error as serde::de::Error>::custom(
                            "lone surrogate in \\u escape",
                        ));
                    }
                    i += 12; // both escapes consumed as a pair
                } else if (0xDC00..=0xDFFF).contains(&code) {
                    // A low surrogate reached on its own (any low surrogate
                    // that was part of a valid pair was already consumed
                    // above together with its high surrogate) is lone.
                    return Err(<serde_json::Error as serde::de::Error>::custom(
                        "lone surrogate in \\u escape",
                    ));
                } else {
                    i += 6;
                }
            }
            b'\\' => {
                // Any other escape (`\\`, `\"`, `\n`, ...): skip the
                // backslash and the one char after it.
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }
    Ok(())
}

/// Pre-scans `text` for its maximum array/object nesting depth, before
/// handing it to `serde_json` -- see [`MAX_JSON_DEPTH`]'s doc (the module's
/// "Recursion / nesting depth" section) for why this exists at all instead
/// of relying on `serde_json`'s own (now disabled, for depths past 128)
/// built-in limit, and for how the returned depth picks between the inline
/// and dedicated-stack parse paths in [`loads`]. Tracks "inside a string
/// literal" state exactly like [`reject_lone_surrogate_escapes`] (respecting
/// backslash escapes, and safe to scan byte-at-a-time for the same reason:
/// every UTF-8 continuation byte is `>= 0x80` and so never collides with the
/// ASCII bytes compared against here), and counts `{`/`[` against `}`/`]`
/// outside of strings. This does not itself validate that the JSON is
/// well-formed (unbalanced or malformed brackets are left for `serde_json`
/// to reject as a syntax error) -- it only ever needs to *reject early* on
/// depth, never accept early on syntax.
fn scan_nesting_depth(text: &str, max_depth: usize) -> serde_json::Result<usize> {
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut in_string = false;
    let mut depth: usize = 0;
    let mut max_seen: usize = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            match b {
                b'"' => {
                    in_string = false;
                    i += 1;
                }
                b'\\' => {
                    // Skip the backslash and the one byte after it (the
                    // escaped character, always ASCII in valid JSON).
                    i += 2;
                }
                _ => i += 1,
            }
            continue;
        }
        match b {
            b'"' => {
                in_string = true;
                i += 1;
            }
            b'{' | b'[' => {
                depth += 1;
                max_seen = max_seen.max(depth);
                if depth > max_depth {
                    return Err(<serde_json::Error as serde::de::Error>::custom(
                        "json nesting exceeds the maximum supported depth",
                    ));
                }
                i += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            _ => i += 1,
        }
    }
    Ok(max_seen)
}

/// Rejects any `Number` in the tree that is a `.`/exponent-bearing literal
/// whose value overflows to a non-finite `f64` -- see [`loads`]'s doc.
///
/// Deliberately does *not* use `Number::is_f64()`/`as_f64()`: with
/// `arbitrary_precision`, both of those already silently treat an
/// overflowing literal as "not an f64 at all" (`is_f64()` parses and checks
/// `is_finite()` itself, so it's `false` for `"1e400"`), which is exactly
/// backwards for this check -- we need to know "this was syntactically a
/// float literal" independent of whether it turned out finite. So classify
/// by the raw literal text via `as_str()` instead: it looks like a float
/// (has `.`/`e`/`E`) or it doesn't (a plain, possibly huge, integer, which
/// Python's `int` is unbounded for and this never rejects).
fn reject_non_finite_numbers(value: &Value) -> serde_json::Result<()> {
    match value {
        Value::Number(n) if is_float_literal(n.as_str()) => {
            if n.as_str().parse::<f64>().is_ok_and(f64::is_finite) {
                Ok(())
            } else {
                Err(<serde_json::Error as serde::de::Error>::custom(
                    "number literal overflows to a non-finite float",
                ))
            }
        }
        Value::Number(_) => Ok(()),
        Value::Array(items) => items.iter().try_for_each(reject_non_finite_numbers),
        Value::Object(map) => map.values().try_for_each(reject_non_finite_numbers),
        _ => Ok(()),
    }
}

/// True when `raw` -- a `serde_json::Number`'s own literal text
/// (`arbitrary_precision`'s raw-text backing) -- is syntactically a float
/// literal (has a `.`/`e`/`E`) rather than a plain, possibly huge, integer
/// literal. `pub(crate)`, not just a local helper: `team/commit.rs`'s
/// `python_int_coerce`/its `ops` numeric-value coercion previously kept its
/// own byte-identical copy of this one-line check (PORTING.md §3b, finding
/// E-R6-1 round 6) -- deleted in favour of this one.
pub(crate) fn is_float_literal(raw: &str) -> bool {
    raw.contains(['.', 'e', 'E'])
}

/// A-R4-1: [`dumps`]'s own depth guard, over an already-*parsed* `Value`
/// tree rather than raw text (contrast [`scan_nesting_depth`], which scans
/// text for [`loads`]). Deliberately walks the tree with an explicit
/// heap-allocated stack (`Vec`), never native call-stack recursion, so this
/// check itself cannot overflow no matter how deep a caller-constructed
/// `Value` might be — including one built without ever going through
/// `loads` (this crate's own audit records, handle payloads, ...), which is
/// exactly the case `loads`'s own pre-scan cannot cover. Returns `None` as
/// soon as any branch would exceed `max_depth` (bailing out before walking
/// the rest of that branch, and without needing to visit sibling branches
/// first), `Some(deepest)` otherwise.
fn value_depth_within(value: &Value, max_depth: usize) -> Option<usize> {
    let mut stack: Vec<(&Value, usize)> = vec![(value, 0)];
    let mut deepest = 0usize;
    while let Some((v, depth)) = stack.pop() {
        let child_depth = depth + 1;
        match v {
            Value::Array(items) => {
                if child_depth > max_depth {
                    return None;
                }
                deepest = deepest.max(child_depth);
                stack.extend(items.iter().map(|item| (item, child_depth)));
            }
            Value::Object(map) => {
                if child_depth > max_depth {
                    return None;
                }
                deepest = deepest.max(child_depth);
                stack.extend(map.values().map(|item| (item, child_depth)));
            }
            _ => {}
        }
    }
    Some(deepest)
}

fn write_value(value: &Value, opts: &DumpOptions, depth: usize, out: &mut String) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => write_number(n, out)?,
        Value::String(s) => write_string(s, opts.ensure_ascii, out),
        Value::Array(items) => write_array(items, opts, depth, out)?,
        Value::Object(map) => write_object(map, opts, depth, out)?,
    }
    Ok(())
}

fn write_array(items: &[Value], opts: &DumpOptions, depth: usize, out: &mut String) -> Result<()> {
    if items.is_empty() {
        out.push_str("[]");
        return Ok(());
    }
    out.push('[');
    let inner = depth + 1;
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(opts.item_sep);
        }
        indent_newline(opts, inner, out);
        write_value(item, opts, inner, out)?;
    }
    indent_newline(opts, depth, out);
    out.push(']');
    Ok(())
}

fn write_object(
    map: &serde_json::Map<String, Value>,
    opts: &DumpOptions,
    depth: usize,
    out: &mut String,
) -> Result<()> {
    if map.is_empty() {
        out.push_str("{}");
        return Ok(());
    }
    out.push('{');
    let inner = depth + 1;
    // `sort_keys=True` in Python is `sorted(dct.items())`, i.e. sorted by
    // key in code-point order; `str::cmp` on valid UTF-8 agrees with that.
    // Otherwise Python emits `dict` insertion order, which `Map::iter`
    // already gives us with `preserve_order` enabled.
    let mut entries: Vec<(&String, &Value)> = map.iter().collect();
    if opts.sort_keys {
        entries.sort_by(|a, b| a.0.cmp(b.0));
    }
    for (i, (key, val)) in entries.into_iter().enumerate() {
        if i > 0 {
            out.push_str(opts.item_sep);
        }
        indent_newline(opts, inner, out);
        write_string(key, opts.ensure_ascii, out);
        out.push_str(opts.kv_sep);
        write_value(val, opts, inner, out)?;
    }
    indent_newline(opts, depth, out);
    out.push('}');
    Ok(())
}

fn indent_newline(opts: &DumpOptions, depth: usize, out: &mut String) {
    if let Some(width) = opts.indent {
        out.push('\n');
        for _ in 0..(width * depth) {
            out.push(' ');
        }
    }
}

/// Escaping rules from CPython's `json/encoder.py` `py_encode_basestring`
/// (`ensure_ascii=False`) and `py_encode_basestring_ascii` (`ensure_ascii=True`),
/// which the C accelerator (`_json`, used by default) matches byte-for-byte:
/// always escape `\`, `"` and control characters `\x00`-`\x1f` (with short
/// forms for `\b \f \n \r \t`, `\u00xx` otherwise); with `ensure_ascii=True`,
/// additionally escape every character outside `\x20`-`\x7e` (so `\x7f` and
/// anything non-ASCII), using a UTF-16 surrogate pair for non-BMP code points.
fn write_string(s: &str, ensure_ascii: bool, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c if ensure_ascii && (c as u32) > 0x7e => {
                let n = c as u32;
                if n < 0x10000 {
                    let _ = write!(out, "\\u{:04x}", n);
                } else {
                    let n2 = n - 0x10000;
                    let s1 = 0xd800 | ((n2 >> 10) & 0x3ff);
                    let s2 = 0xdc00 | (n2 & 0x3ff);
                    let _ = write!(out, "\\u{:04x}\\u{:04x}", s1, s2);
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_number(n: &Number, out: &mut String) -> Result<()> {
    let raw = n.as_str();
    // Classify by the raw literal text, not `Number::is_f64()`: with
    // `arbitrary_precision`, `is_f64()` parses the literal and checks
    // `is_finite()` itself, so it is *already false* for an overflowing
    // literal like `"1e400"` -- using it here would silently fall through
    // to the integer branch below and echo the raw (non-finite-valued)
    // literal back out unchanged, exactly the bug this guards against.
    if is_float_literal(raw) {
        let f = raw
            .parse::<f64>()
            .ok()
            .filter(|f| f.is_finite())
            .ok_or_else(|| Error::invalid_input("pyjson_non_finite_float").with_detail("number"))?;
        out.push_str(&python_float_repr(f));
    } else {
        // Integer (any size, thanks to `arbitrary_precision`): Python ints
        // have a unique canonical decimal form, which `as_str()` already is.
        out.push_str(raw);
    }
    Ok(())
}

/// `repr(float)`, i.e. what `json.dumps` writes for a finite float
/// (`floatstr` in `json/encoder.py` calls `float.__repr__` directly).
///
/// Reimplements CPython's `format_float_short` (`Python/pystrtod.c`) in its
/// `'r'` (repr) mode: take the shortest decimal digit string that round-trips
/// to `f`, then lay it out fixed or exponential using the same thresholds
/// CPython uses: exponential when the decimal point would fall at or before
/// position -4, or after position 16.
///
/// **Getting the digit string itself to match CPython (finding H-R4-2).**
/// Rust's own `{:e}` formatter already computes *a* shortest round-tripping
/// digit string -- same class of algorithm as CPython's David Gay `dtoa`
/// mode 0 -- and the two agree on both the digit count and every digit
/// whenever the shortest round-tripping representation at that length is
/// unique, which is true generically. They can disagree only in the
/// genuinely ambiguous case: `f`'s exact value sits *precisely* halfway
/// between two adjacent same-length decimal strings (this only arises when
/// `f` is itself an exact, finite binary fraction whose decimal expansion
/// terminates with a `5` right at the digit position being cut). CPython's
/// dtoa resolves that specific case with round-half-to-even on the digit
/// string; Rust's formatter does not always agree.
///
/// Rather than reimplementing dtoa's arbitrary-precision digit generation
/// from scratch, this takes Rust's candidate digit string and *checks* for
/// exactly this situation: construct the two same-length neighbouring digit
/// strings (candidate literal value ±1 in the last digit, with borrow/carry
/// propagated across the whole string) and test each with **two** separate
/// conditions, both required:
///
/// 1. The neighbour must itself be a *valid* representation of `f` --
///    parsing it back (Rust's `str::parse`, correctly-rounded) must yield
///    exactly `f`'s bit pattern. This is not implied by condition 2: at a
///    power-of-two `f`, the gap down to the next-smaller float is only half
///    the gap up to the next-larger one (the implicit mantissa bit shifts
///    down a binade), so a decimal that is exactly `0.5` decimal-ULPs below
///    `f` can still parse to the *next float down*, not to `f` -- e.g. for
///    `f = 2f64.powi(-24)`, `"5.960464477539062e-8"` is exactly halfway
///    between the two adjacent 16-digit decimals in real-number terms, yet
///    it parses to the float *below* `f`, not to `f` itself, so it is never
///    a legitimate alternative rendering of `f` no matter how the tie
///    question is framed. (This also means round-trip agreement alone,
///    condition 1 without condition 2, is not sufficient either: a double
///    needing close to the maximum ~17 significant digits routinely has
///    several neighbouring same-length decimals that all satisfy condition
///    1 while Rust's original candidate remains unambiguously nearest --
///    confirmed against real `python3.12`, which agrees with Rust's
///    original candidate in exactly these cases.)
/// 2. `f`'s exact value must be the precise arithmetic midpoint between the
///    candidate and its neighbour -- checked exactly via
///    [`decimal_equals_exact`] (arbitrary-precision integer comparison, not
///    a re-parse), since that is the actual definition of "tied" (neither
///    candidate is closer to `f` than the other).
///
/// If neither neighbour satisfies both conditions, Rust's candidate is
/// already correct and matches CPython. If exactly one does, `f`'s value is
/// a genuine tie: pick whichever of the pair has an even last digit,
/// matching CPython's tie-break (the two candidates differ by 1 in their
/// last digit, so exactly one of them is even). Both neighbours satisfying
/// both conditions simultaneously is unreachable for a binary `f64`: that
/// would need `f`'s exact value to equal both `candidate - 0.5` and
/// `candidate + 0.5` (in units of the last digit) at once, a contradiction.
/// Pinned against real `python3.12` by
/// `oracle_tests::float_repr_matches_python_extensive_fuzz` (deliberately
/// constructed exact ties, every power of two across the exponent range and
/// its immediate neighbours, >200,000 random bit patterns, subnormals) and
/// `tests::float_repr_known_values` (the finding's own reported values).
pub fn python_float_repr(f: f64) -> String {
    // Finding X-9: this function used to assume its input was always
    // finite -- true for every call reachable *through* this crate's own
    // JSON writer (`write_number` above filters non-finite before ever
    // calling here, returning `pyjson_non_finite_float` instead) but not
    // for a caller elsewhere in the crate that reaches a `Number` some
    // other way. `team/humanview.rs`'s `number_display` was exactly that
    // caller (fixed alongside this, see its doc comment): Rust's `f64`
    // parser *saturates* on an overflowing literal like `"1e400"`
    // (`Ok(f64::INFINITY)`, not an error), so a value built by re-parsing
    // raw literal text -- rather than going through `Number::as_f64()`,
    // which already filters non-finite to `None` -- could carry a
    // non-finite `f64` into this function. `format!("{af:e}", ...)` for an
    // infinite or NaN `af` produces the literal text `"inf"`/`"NaN"`, which
    // contains no `'e'`, so the `split_once('e').expect(...)` a few lines
    // below panicked (measured: `python_float_repr(f64::INFINITY)`,
    // `(f64::NEG_INFINITY)` and `(f64::NAN)` all panicked at this
    // function's old first line, before this guard existed) -- aborting the
    // whole process for any input, trusted or not, that reached it. Rather
    // than rely on every current and future caller upholding "never pass a
    // non-finite value" as an unstated precondition, handle it here
    // directly: CPython's `repr(float)`/`str(float)` (this function's own
    // documented contract -- *not* `json.dumps`'s separate `Infinity`/
    // `-Infinity`/`NaN` token spelling, which is a `json.encoder`-only
    // special case this function was never responsible for) print `"inf"`,
    // `"-inf"` and `"nan"` for these three values -- measured directly
    // against `python3.12`: `repr(float("inf"))` == `str(float("inf"))` ==
    // `"inf"`, `repr(float("-inf"))` == `"-inf"`, `repr(float("nan"))` ==
    // `"nan"`. Pinned by `tests::float_repr_non_finite_does_not_panic`.
    if f.is_nan() {
        return "nan".to_string();
    }
    if f.is_infinite() {
        return if f.is_sign_negative() {
            "-inf".to_string()
        } else {
            "inf".to_string()
        };
    }
    if f == 0.0 {
        return if f.is_sign_negative() {
            "-0.0".to_string()
        } else {
            "0.0".to_string()
        };
    }
    let neg = f.is_sign_negative();
    let af = f.abs();
    // "{:e}" gives *a* shortest round-trip mantissa (1 <= mantissa < 10) and
    // decimal exponent: af == mantissa * 10^exp. `shortest_digits_matching_cpython`
    // corrects it, if needed, to the exact digit string CPython's dtoa would
    // produce (see this function's doc comment).
    let sci = format!("{af:e}");
    let (mantissa, exp_str) = sci.split_once('e').expect("LowerExp always contains 'e'");
    let exp: i32 = exp_str.parse().expect("LowerExp exponent is an integer");
    let raw_digits: Vec<u8> = mantissa.bytes().filter(|b| *b != b'.').collect();
    // value == 0.d1 d2 ... dn * 10^decpt
    let decpt = exp + 1;
    let (digit_bytes, decpt) = shortest_digits_matching_cpython(raw_digits, decpt, af);
    let digits = String::from_utf8(digit_bytes).expect("ASCII digit bytes are valid UTF-8");
    let n = digits.len() as i32;

    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if decpt <= -4 || decpt > 16 {
        out.push_str(&digits[0..1]);
        if n > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let e = decpt - 1;
        out.push('e');
        out.push(if e >= 0 { '+' } else { '-' });
        let eabs = e.unsigned_abs();
        if eabs < 10 {
            out.push('0');
        }
        let _ = write!(out, "{eabs}");
    } else if decpt <= 0 {
        out.push_str("0.");
        for _ in 0..(-decpt) {
            out.push('0');
        }
        out.push_str(&digits);
    } else if (decpt as usize) >= digits.len() {
        out.push_str(&digits);
        for _ in 0..(decpt as usize - digits.len()) {
            out.push('0');
        }
        out.push_str(".0");
    } else {
        out.push_str(&digits[..decpt as usize]);
        out.push('.');
        out.push_str(&digits[decpt as usize..]);
    }
    out
}

/// Given `digits` (a shortest round-tripping ASCII-digit string for `target`,
/// as produced by Rust's own `{:e}` formatter, with implied decimal point
/// `decpt`: `target == 0.d1 d2 ... dn * 10^decpt`), corrects it if necessary
/// to the exact digit string CPython's `_Py_dg_dtoa` mode 0 would produce.
/// See [`python_float_repr`]'s doc comment for the reasoning; this returns
/// `(digits, decpt)` since the corrected string can, in principle, gain a
/// leading `0` that must be trimmed (adjusting `decpt` down by one to
/// compensate) to keep the invariant that `digits[0]` is the first
/// significant (nonzero) digit, as the rest of [`python_float_repr`] assumes.
///
/// A genuinely ambiguous tie -- where CPython's round-half-to-even rule
/// actually applies -- is *not* "some other same-length digit string also
/// happens to parse back to `target`": for a double whose exact value needs
/// close to the maximum ~17 significant digits, the valid round-trip range
/// can be several representable-length steps wide, so both `digits - 1` and
/// `digits + 1` routinely round-trip too even though `digits` is
/// unambiguously the *closest* one (confirmed against real `python3.12`,
/// which agrees with Rust's original candidate in exactly these cases). A
/// real tie means `target`'s exact value sits precisely halfway between
/// `digits` and one neighbour -- checked here exactly, via
/// [`decimal_equals_exact`] comparing `target`'s exact binary value against
/// the exact decimal midpoint, not via a round-trip re-parse.
fn shortest_digits_matching_cpython(digits: Vec<u8>, decpt: i32, target: f64) -> (Vec<u8>, i32) {
    let minus = decrement_last_digit(&digits);
    let plus = increment_last_digit(&digits);

    // Two conditions, both required, not one or the other:
    //
    // 1. The candidate must actually be a *valid* representation of
    //    `target` -- i.e. parsing it back (correctly rounded) must yield
    //    `target`'s exact bit pattern, not some other float. This is *not*
    //    implied by the exact-midpoint check below: at a power-of-two `target`
    //    the gap to the float just below is only half the gap to the float
    //    just above (the mantissa's implicit leading bit shifts down a
    //    binade), so the decimal exactly at "target - 0.5*ulp" can be exact
    //    real-number-wise while still parsing (correctly!) to the *lower*
    //    neighbour float, not to `target` -- confirmed against real
    //    `python3.12`/Rust `str::parse` for `target = 2f64.powi(-24)`, where
    //    "5.960464477539062e-8" parses to the float below `target`, even
    //    though it is exactly 0.5*ulp (in decimal terms) away from `target`.
    // 2. `target`'s exact value must be the precise arithmetic midpoint
    //    between the candidate and `digits` (checked exactly via
    //    [`decimal_equals_exact`]) -- otherwise `digits` (or the other
    //    neighbour) is simply closer and there is no real ambiguity, no
    //    matter how wide `target`'s own valid-round-trip interval happens to
    //    be (see the note on the "extensive fuzz" test below: this shows up
    //    routinely for doubles near the ~17-significant-digit limit, where
    //    the interval is wide enough that several neighbouring decimals all
    //    satisfy condition 1 even though `digits` is unambiguously nearest).
    let tie_with_minus = if let Some(m) = &minus {
        digits_round_trip(m, decpt, target) && {
            let mut midpoint = m.clone();
            midpoint.push(b'5'); // m + 0.5*ulp == the exact midpoint between m and digits
            decimal_equals_exact(&midpoint, decpt, target)
        }
    } else {
        false
    };
    let tie_with_plus = if let Some(p) = &plus {
        digits_round_trip(p, decpt, target) && {
            let mut midpoint = digits.clone();
            midpoint.push(b'5'); // digits + 0.5*ulp == the exact midpoint between digits and plus
            decimal_equals_exact(&midpoint, decpt, target)
        }
    } else {
        false
    };

    // Both can't hold at once: that would need target's exact value to
    // equal both (digits - 0.5) and (digits + 0.5) simultaneously --
    // contradictory unless 0.5 == -0.5. See the doc comment above.
    debug_assert!(
        !(tie_with_minus && tie_with_plus),
        "unreachable simultaneous tie on both sides for {target}"
    );

    let chosen = if tie_with_minus {
        // Tied between `digits` (last digit d) and `minus` (last digit
        // d-1): these have opposite parity, so exactly one is even.
        if is_even_last_digit(&digits) {
            digits
        } else {
            minus.expect("tie_with_minus implies minus is Some")
        }
    } else if tie_with_plus {
        // Tied between `digits` (last digit d) and `plus` (last digit d+1):
        // same reasoning, opposite parity.
        if is_even_last_digit(&digits) {
            digits
        } else {
            plus.expect("tie_with_plus implies plus is Some")
        }
    } else {
        digits
    };

    // `decrement_last_digit` can turn a leading digit '1' into '0' (when
    // every digit after it was '0', so the borrow cascades all the way to
    // the front) -- trim it back to a normalized (nonzero leading digit)
    // form, the invariant `python_float_repr`'s layout code relies on.
    if chosen.len() > 1 && chosen[0] == b'0' {
        (chosen[1..].to_vec(), decpt - 1)
    } else {
        (chosen, decpt)
    }
}

fn is_even_last_digit(digits: &[u8]) -> bool {
    let last = *digits.last().expect("digit string is never empty");
    (last - b'0').is_multiple_of(2)
}

/// `digits` minus 1 in its last decimal place, propagating the borrow
/// leftward across the whole string; keeps the same length (a leading '1'
/// can become a leading '0', which the caller normalizes away -- see
/// [`shortest_digits_matching_cpython`]). Returns `None` only if `digits` is
/// all zeros to begin with, which never happens here (a shortest
/// round-trip digit string's leading digit is always 1-9).
fn decrement_last_digit(digits: &[u8]) -> Option<Vec<u8>> {
    let mut out = digits.to_vec();
    for b in out.iter_mut().rev() {
        if *b == b'0' {
            *b = b'9';
        } else {
            *b -= 1;
            return Some(out);
        }
    }
    None // all zeros -- unreachable for a normalized digit string
}

/// `digits` plus 1 in its last decimal place, propagating the carry
/// leftward. Returns `None` if the carry propagates past the first digit
/// (all digits were '9'): that would need an extra leading digit, i.e. a
/// *longer* string, which is not a same-length neighbour and so is never a
/// same-length shortest-round-trip tie candidate.
fn increment_last_digit(digits: &[u8]) -> Option<Vec<u8>> {
    let mut out = digits.to_vec();
    for b in out.iter_mut().rev() {
        if *b == b'9' {
            *b = b'0';
        } else {
            *b += 1;
            return Some(out);
        }
    }
    None // carry out of the leading digit -- would need one more digit
}

/// Does the digit string `digits`, laid out as `d1.d2...dn * 10^(decpt-1)`
/// (scientific notation -- the fixed-vs-exponential display choice in
/// [`python_float_repr`] never affects the *value* a string parses to),
/// parse back to exactly `target`'s bit pattern? Relies only on Rust's
/// `str::parse::<f64>` being correctly-rounded (round-to-nearest-even,
/// including the asymmetric-boundary handling a power-of-two `target`
/// needs), which it is. Necessary but *not* sufficient on its own for a
/// genuine dtoa tie -- see the "two conditions" note on
/// [`shortest_digits_matching_cpython`] for why the exact-midpoint check
/// alone is not sufficient either, and both are required together. A
/// leading `0` digit (from `decrement_last_digit`'s borrow cascade) parses
/// correctly too: `f64::from_str` does not care whether the digit before the
/// decimal point is zero.
fn digits_round_trip(digits: &[u8], decpt: i32, target: f64) -> bool {
    let mut literal = String::with_capacity(digits.len() + 8);
    literal.push(digits[0] as char);
    if digits.len() > 1 {
        literal.push('.');
        literal.push_str(std::str::from_utf8(&digits[1..]).expect("ASCII digits"));
    }
    literal.push('e');
    let _ = write!(literal, "{}", decpt - 1);
    literal
        .parse::<f64>()
        .is_ok_and(|v| v.to_bits() == target.to_bits())
}

/// Decodes a finite, positive, nonzero `f64` into its exact value
/// `mantissa * 2^exp2` (`mantissa` a `u64` of at most 53 significant bits,
/// `exp2` the binary exponent) -- every `f64` value is exactly this, with no
/// rounding, whether normal or subnormal. This is the standard IEEE 754
/// binary64 decomposition (bias 1023, 52 explicit fraction bits, implicit
/// leading 1 bit for normals).
fn decode_f64_exact(f: f64) -> (u64, i32) {
    let bits = f.to_bits();
    let exp_bits = ((bits >> 52) & 0x7ff) as i32;
    let frac = bits & 0x000f_ffff_ffff_ffff;
    if exp_bits == 0 {
        // Subnormal: value == frac * 2^-1074 (no implicit leading bit).
        (frac, -1074)
    } else {
        // Normal: value == (2^52 + frac) * 2^(exp_bits - 1023 - 52).
        (frac | (1u64 << 52), exp_bits - 1075)
    }
}

/// Is the decimal number represented by `digits` (ASCII `'0'..='9'`, at most
/// ~19 of them here) laid out as `(digits as integer) * 10^(decpt -
/// digits.len())` *exactly* equal (as real numbers, not merely "round-trips
/// to") to `target` (finite, positive, nonzero)? Used only for the tie check
/// in [`shortest_digits_matching_cpython`] -- an exact equality test, not a
/// closeness/rounding test, so a leading `'0'` digit in `digits` (from a
/// borrow cascade) is harmless: it scales the same integer value regardless.
///
/// Compares exactly via arbitrary-precision integer arithmetic
/// ([`BigUint`]): `target == mantissa * 2^exp2` (exact by construction, see
/// [`decode_f64_exact`]) and the decimal candidate is `dnum * 10^p == dnum *
/// 2^p * 5^p` for `p = decpt - digits.len()`. Scaling both sides by whichever
/// factors of 2 and 5 they are *missing* relative to the other turns the
/// comparison into one between two plain nonnegative integers -- multiplying
/// two equal (or unequal) reals by the same positive factor preserves
/// equality (or inequality), so this is exact, not an approximation.
fn decimal_equals_exact(digits: &[u8], decpt: i32, target: f64) -> bool {
    let dnum: u64 = std::str::from_utf8(digits)
        .expect("ASCII digits")
        .parse()
        .expect("digit string fits u64 (at most ~19 digits)");
    let p = decpt - digits.len() as i32;
    let (mantissa, exp2) = decode_f64_exact(target);

    // target == mantissa * 2^exp2 * 5^0
    // decimal == dnum     * 2^p    * 5^p
    let min_pow2 = exp2.min(p);
    let min_pow5 = 0i32.min(p);
    let target_shift2 = (exp2 - min_pow2) as u32;
    let target_shift5 = (0 - min_pow5) as u32;
    let decimal_shift2 = (p - min_pow2) as u32;
    let decimal_shift5 = (p - min_pow5) as u32;

    let target_big = BigUint::from_u64(mantissa)
        .mul_pow5(target_shift5)
        .shl(target_shift2);
    let decimal_big = BigUint::from_u64(dnum)
        .mul_pow5(decimal_shift5)
        .shl(decimal_shift2);
    target_big == decimal_big
}

/// Minimal arbitrary-precision unsigned integer (little-endian base-2^32
/// limbs; no leading zero limbs except the canonical representation of zero
/// itself, `[0]`). Exists solely to make [`decimal_equals_exact`]'s
/// tie-check exact regardless of magnitude -- `f64` exponents range roughly
/// ±1074, and `5^341`-ish factors, both routinely too large for any built-in
/// integer type. Not a general-purpose bignum: only the handful of
/// operations that function needs.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BigUint(Vec<u32>);

impl BigUint {
    fn from_u64(v: u64) -> Self {
        let mut limbs = vec![(v & 0xffff_ffff) as u32, (v >> 32) as u32];
        Self::trim(&mut limbs);
        BigUint(limbs)
    }

    fn trim(limbs: &mut Vec<u32>) {
        while limbs.len() > 1 && *limbs.last().expect("non-empty") == 0 {
            limbs.pop();
        }
    }

    fn is_zero(&self) -> bool {
        self.0.len() == 1 && self.0[0] == 0
    }

    /// Schoolbook long multiplication, `O(len(self) * len(other))`; more
    /// than adequate for the few-hundred-bit operands this module ever
    /// produces.
    fn mul(&self, other: &BigUint) -> Self {
        let mut out = vec![0u32; self.0.len() + other.0.len()];
        for (i, &a) in self.0.iter().enumerate() {
            let mut carry: u64 = 0;
            for (j, &b) in other.0.iter().enumerate() {
                let sum = out[i + j] as u64 + (a as u64) * (b as u64) + carry;
                out[i + j] = (sum & 0xffff_ffff) as u32;
                carry = sum >> 32;
            }
            let mut k = i + other.0.len();
            while carry > 0 {
                let sum = out[k] as u64 + carry;
                out[k] = (sum & 0xffff_ffff) as u32;
                carry = sum >> 32;
                k += 1;
            }
        }
        Self::trim(&mut out);
        BigUint(out)
    }

    /// Multiplies by `5^exp` using binary exponentiation (`O(log exp)`
    /// multiplications), rather than `exp` sequential multiplications by 5 --
    /// `exp` can be in the low hundreds here.
    fn mul_pow5(&self, mut exp: u32) -> Self {
        if self.is_zero() || exp == 0 {
            return self.clone();
        }
        let mut base = BigUint::from_u64(5);
        let mut acc = self.clone();
        // Standard square-and-multiply: consume `exp`'s bits from the
        // bottom, squaring `base` each round and folding it into `acc`
        // whenever the current bit is set.
        loop {
            if exp & 1 == 1 {
                acc = acc.mul(&base);
            }
            exp >>= 1;
            if exp == 0 {
                break;
            }
            base = base.mul(&base);
        }
        acc
    }

    /// Multiplies by `2^bits` (a pure bit shift).
    fn shl(&self, bits: u32) -> Self {
        if self.is_zero() || bits == 0 {
            return self.clone();
        }
        let limb_shift = (bits / 32) as usize;
        let bit_shift = bits % 32;
        let mut out = vec![0u32; self.0.len() + limb_shift + 1];
        for (i, &limb) in self.0.iter().enumerate() {
            let widened = (limb as u64) << bit_shift;
            out[i + limb_shift] |= (widened & 0xffff_ffff) as u32;
            let overflow = (widened >> 32) as u32;
            if overflow != 0 {
                out[i + limb_shift + 1] |= overflow;
            }
        }
        Self::trim(&mut out);
        BigUint(out)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Builds a JSON document nested `n` levels deep: `n` open brackets, a
    /// scalar, `n` close brackets (e.g. `n=2` -> `"[[1]]"`). `pub(super)` so
    /// `oracle_tests` (a sibling test module below) can reuse it.
    pub(super) fn nested_array(n: usize) -> String {
        let mut s = String::with_capacity(n * 2 + 2);
        for _ in 0..n {
            s.push('[');
        }
        s.push('1');
        for _ in 0..n {
            s.push(']');
        }
        s
    }

    // A-R3-1: `loads`' inline path (depth <= `SAFE_INLINE_DEPTH`) must not
    // risk a stack overflow even on a thread with a small stack -- run it on
    // a deliberately small (2 MiB) stack, at exactly the inline threshold.
    #[test]
    fn inline_path_is_safe_on_a_small_stack_thread() {
        let doc = nested_array(SAFE_INLINE_DEPTH);
        let handle = std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(move || loads(&doc).map(|_| ()))
            .unwrap();
        assert!(handle.join().unwrap().is_ok());
    }

    // A-R3-1: a document deeper than `SAFE_INLINE_DEPTH` must still parse
    // successfully, all the way out to `MAX_JSON_DEPTH`, via the
    // dedicated-stack path.
    #[test]
    fn dedicated_stack_path_parses_up_to_max_json_depth() {
        for n in [
            SAFE_INLINE_DEPTH + 1,
            (SAFE_INLINE_DEPTH + MAX_JSON_DEPTH) / 2,
            MAX_JSON_DEPTH,
        ] {
            let doc = nested_array(n);
            assert!(loads(&doc).is_ok(), "depth {n} should parse");
        }
    }

    // A-R3-1: anything past `MAX_JSON_DEPTH` is rejected outright (by the
    // cheap pre-scan, before any parsing is attempted), not silently
    // accepted and not a stack overflow.
    #[test]
    fn depth_past_max_json_depth_is_rejected() {
        let doc = nested_array(MAX_JSON_DEPTH + 1);
        assert!(loads(&doc).is_err());
    }

    // A-R3-1: the hazard the module doc's "Recursion / nesting depth"
    // section calls out -- building a deep `Value` on a dedicated
    // large-stack thread only solves half the problem, because the result
    // crosses back to the caller's own thread and is dropped there. Confirm
    // the *whole* round trip -- `loads` a `MAX_JSON_DEPTH` document, then
    // drop the result -- is safe even when driven from a small (2 MiB)
    // stack throughout.
    #[test]
    fn dedicated_stack_result_is_safe_to_drop_on_a_small_stack() {
        let doc = nested_array(MAX_JSON_DEPTH);
        let handle = std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(move || {
                let value = loads(&doc).expect("MAX_JSON_DEPTH should parse");
                drop(value); // the hazard under test: must not overflow
            })
            .unwrap();
        handle.join().unwrap();
    }

    // A-R4-1 (HIGH, regression fix): round 3 only proved *parsing* and
    // *dropping* a `MAX_JSON_DEPTH` document safe on a small stack --
    // `dumps`, `clone` and `==` were left unbounded and could abort the
    // whole process (see the module doc's "Recursion / nesting depth"
    // section for the measured hazard zones). Confirm every one of these
    // operations succeeds, together, at the maximum accepted depth, driven
    // entirely from a deliberately small (2 MiB) stack thread -- matching
    // the real shape of the finding's repro (a trusted-process thread, not
    // a dedicated large-stack one, ends up holding a deep `Value`).
    #[test]
    fn max_depth_document_is_safe_to_dump_clone_compare_and_drop_on_a_small_stack() {
        let doc = nested_array(MAX_JSON_DEPTH);
        let handle = std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(move || -> Result<()> {
                // Parsing itself always safe here regardless of thread size:
                // `loads` already routes anything past `SAFE_INLINE_DEPTH`
                // through its own dedicated large-stack thread.
                let value = loads(&doc).expect("MAX_JSON_DEPTH should parse");

                // Serializing: the writer side this finding is actually
                // about (reached for real via `StateDir::write_json`).
                let rendered = dumps(&value, DumpOptions::pretty_sorted())?;
                assert!(!rendered.is_empty());

                // Cloning: `serde_json::Value`'s derived recursive `Clone`.
                let cloned = value.clone();

                // Comparing: `serde_json::Value`'s derived recursive `PartialEq`.
                assert_eq!(value, cloned);

                // Dropping: both values go out of scope at the end of this
                // closure, on this same small stack.
                Ok(())
            })
            .unwrap();
        handle
            .join()
            .unwrap()
            .expect("all ops should succeed at MAX_JSON_DEPTH");
    }

    /// Consumes (at least) `bytes` of the current stack before calling `f`,
    /// by recursing in fixed-size chunks and keeping each chunk's buffer
    /// alive (via a use *after* the recursive call returns, so nothing can
    /// be optimized away or reused early) until `f` has already run.
    /// Mirrors the equivalence reviewer's own measurement method for finding
    /// A-R5-1 ("a 2 MiB thread where the caller had already consumed
    /// 262,144 bytes"): a real caller thread never starts a `dumps`/
    /// `write_json` call with a fully empty stack, so a fix that is only
    /// ever pinned on an empty stack (as every pre-A-R5-1 test in this
    /// module was) does not actually prove the hazard is closed.
    fn with_burned_stack<T>(bytes: usize, f: impl FnOnce() -> T) -> T {
        const CHUNK: usize = 4096;
        if bytes >= CHUNK {
            let buf = [0u8; CHUNK];
            let result = with_burned_stack(bytes - CHUNK, f);
            std::hint::black_box(&buf);
            result
        } else {
            f()
        }
    }

    // A-R5-1 (HIGH, regression fix): round 4's test above only proved
    // `dumps`/clone/`==`/drop safe at `MAX_JSON_DEPTH` on a small stack that
    // starts *completely empty* -- exactly the gap the equivalence reviewer
    // found: a real request-handling thread (`fake_upstream.rs`, `signer.rs`)
    // has already spent part of its 2 MiB stack on its own call chain before
    // ever reaching a `dumps`/`write_json` call. Re-run the identical
    // dump/clone/compare sequence, but only after `with_burned_stack` has
    // already consumed 262,144 bytes (the reviewer's own measured amount) of
    // the same 2 MiB stack -- mirroring the reviewer's method exactly. Before
    // this fix (native recursion straight into `write_value` for every
    // accepted depth), this configuration is exactly what made depth 1,000
    // abort the whole process; since the fix, `dumps` routes anything past
    // `SAFE_INLINE_DEPTH` onto its own fresh 64 MiB thread, so the amount
    // already spent on the *caller's* stack no longer matters at all.
    #[test]
    fn max_depth_document_is_safe_to_dump_clone_compare_and_drop_on_a_stack_with_prior_usage() {
        let doc = nested_array(MAX_JSON_DEPTH);
        let handle = std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(move || -> Result<()> {
                with_burned_stack(262_144, || {
                    let value = loads(&doc).expect("MAX_JSON_DEPTH should parse");
                    let rendered = dumps(&value, DumpOptions::pretty_sorted())?;
                    assert!(!rendered.is_empty());
                    let cloned = value.clone();
                    assert_eq!(value, cloned);
                    Ok(())
                })
            })
            .unwrap();
        handle
            .join()
            .unwrap()
            .expect("all ops should succeed at MAX_JSON_DEPTH with prior stack usage");
    }

    // A-R7-4 (regression fix): the equivalence reviewer's own repro for this
    // finding -- a harness that genuinely *holds* the caller's stack around
    // the call (recurse, do the work at the bottom, unwind after -- not
    // burn-and-return) -- found that the *previous* `dumps`
    // (`render_on_dedicated_stack(value.clone(), opts)`, a plain
    // `thread::spawn` fed by a caller-side `Value::clone()`) aborted the
    // process with `fatal runtime error: stack overflow` rendering a
    // depth-500 document on a 2 MiB caller stack once >=1.5 MiB of it was
    // already held (clone alone needs >512 KiB at that depth). This test
    // holds well past that threshold -- 1,700,000 bytes of a 2 MiB stack --
    // around a `dumps`-only call (no `loads`/clone/compare, isolating
    // exactly the operation the finding was about) at `MAX_JSON_DEPTH`.
    // `render_on_dedicated_stack` now borrows `value: &Value` across
    // `std::thread::scope` instead of cloning it, so the calling thread's
    // own stack use is fixed and shallow regardless of how much of it is
    // already held -- this must no longer abort.
    #[test]
    fn dumps_at_max_json_depth_does_not_abort_with_1_7mib_of_caller_stack_already_held() {
        let doc = nested_array(MAX_JSON_DEPTH);
        let value = loads(&doc).expect("MAX_JSON_DEPTH should parse");
        let handle = std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(move || -> Result<()> {
                with_burned_stack(1_700_000, || {
                    let rendered = dumps(&value, DumpOptions::pretty_sorted())?;
                    assert!(!rendered.is_empty());
                    Ok(())
                })
            })
            .unwrap();
        handle.join().unwrap().expect(
            "dumps at MAX_JSON_DEPTH must not abort with most of a 2 MiB caller stack already held",
        );
    }

    // A-R4-1: `dumps` must reject a document one level past `MAX_JSON_DEPTH`
    // with a clean error -- not a panic or an abort -- even though nothing
    // about *parsing* is involved here (the `Value` is built directly,
    // bypassing `loads`'s own pre-scan entirely, the same way this crate's
    // own audit/handle/policy code builds values that never went through
    // `loads`).
    #[test]
    fn dumps_rejects_one_level_past_max_json_depth_without_aborting() {
        let mut value = json!(1);
        for _ in 0..(MAX_JSON_DEPTH + 1) {
            value = Value::Array(vec![value]);
        }
        let err = dumps(&value, DumpOptions::compact_sorted())
            .expect_err("one level past MAX_JSON_DEPTH must be a clean error");
        assert!(err.is(crate::errors::ErrorClass::InvalidInput));

        // A document at exactly the limit must still succeed.
        let mut at_limit = json!(1);
        for _ in 0..MAX_JSON_DEPTH {
            at_limit = Value::Array(vec![at_limit]);
        }
        assert!(dumps(&at_limit, DumpOptions::compact_sorted()).is_ok());
    }

    #[test]
    fn compact_sorted_matches_audit_style() {
        let v = json!({"b": 1, "a": "x", "c": null});
        assert_eq!(
            dumps(&v, DumpOptions::compact_sorted()).unwrap(),
            r#"{"a":"x","b":1,"c":null}"#
        );
    }

    #[test]
    fn pretty_sorted_matches_store_style() {
        let v = json!({"b": 1, "a": [1, 2]});
        let out = dumps(&v, DumpOptions::pretty_sorted()).unwrap();
        assert_eq!(out, "{\n  \"a\": [\n    1,\n    2\n  ],\n  \"b\": 1\n}");
    }

    #[test]
    fn default_sorted_has_spaces() {
        let v = json!({"b": 1, "a": 2});
        assert_eq!(
            dumps(&v, DumpOptions::default_sorted()).unwrap(),
            r#"{"a": 2, "b": 1}"#
        );
    }

    #[test]
    fn empty_containers_are_compact_even_with_indent() {
        let v = json!({"a": [], "b": {}});
        assert_eq!(
            dumps(&v, DumpOptions::pretty_sorted()).unwrap(),
            "{\n  \"a\": [],\n  \"b\": {}\n}"
        );
    }

    // The finding's exact-tie test values (and 2^-24 below) are
    // deliberately written with every significant digit: clippy's
    // "excessive precision" suggestion would round them to a *different*
    // (and, for the tie cases, exactly the pre-fix *wrong*) `f64` value,
    // silently defeating the point of the test.
    #[allow(clippy::excessive_precision)]
    #[test]
    fn float_repr_known_values() {
        let cases: &[(f64, &str)] = &[
            (1726000000.5, "1726000000.5"),
            (1e16, "1e+16"),
            (1e-05, "1e-05"),
            (0.1, "0.1"),
            (3.0, "3.0"),
            (-0.0, "-0.0"),
            (0.0, "0.0"),
            (100.0, "100.0"),
            (1e15, "1000000000000000.0"),
            (9999999999999998.0, "9999999999999998.0"),
            (-1.5, "-1.5"),
            (1.5e-5, "1.5e-05"),
            // Finding H-R4-2's three reported values: CPython's dtoa mode 0
            // breaks the exact shortest-round-trip tie with round-half-to-
            // even, which the pre-fix `{:e}`-derived rendering did not.
            (270784837363767.125, "270784837363767.12"),
            (599995984171052.25, "599995984171052.2"),
            (275078784986996.625, "275078784986996.62"),
            // A power-of-two "false positive" this fix's tie-detection had
            // to be corrected to *not* flip: `2^-24`'s exact value is also
            // precisely the arithmetic midpoint between two adjacent
            // 16-digit decimals, but the lower one does not actually parse
            // back to `2^-24` at all (a power of two's gap to the float just
            // below is half its gap to the float just above), so there is no
            // real tie here and the original (already-correct, matching
            // Rust's own `{:e}`) digit string must be kept unchanged.
            (0.000000059604644775390625, "5.960464477539063e-08"),
        ];
        for (f, expected) in cases {
            assert_eq!(python_float_repr(*f), *expected, "for {f}");
        }
    }

    // Finding X-9 (regression fix): `python_float_repr` used to assume its
    // input was always finite and panicked on `inf`/`-inf`/`NaN` (measured,
    // pre-fix: all three panicked at the `split_once('e')` line, because
    // `format!("{:e}", f64::INFINITY)` is the literal text `"inf"`, which
    // contains no `'e'`). Values match CPython's `repr(float)`/`str(float)`
    // (measured directly against `python3.12`: `repr(float("inf"))` ==
    // `"inf"`, `repr(float("-inf"))` == `"-inf"`, `repr(float("nan"))` ==
    // `"nan"`) -- not `json.dumps`'s separate `Infinity`/`-Infinity`/`NaN`
    // token spelling, which is a `json.encoder`-only special case this
    // function was never responsible for and which `write_number` (this
    // module's own JSON writer) never reaches it for in the first place
    // (non-finite is filtered and turned into an error before the call).
    #[test]
    fn float_repr_non_finite_does_not_panic() {
        assert_eq!(python_float_repr(f64::INFINITY), "inf");
        assert_eq!(python_float_repr(f64::NEG_INFINITY), "-inf");
        assert_eq!(python_float_repr(f64::NAN), "nan");
        // NaN has no canonical sign in IEEE 754 comparison terms, but
        // CPython's `repr` never prints `-nan` for the *negative* NaN bit
        // pattern either (`math.copysign(float("nan"), -1)` still `repr`s
        // as `"nan"`) -- confirm this holds for the bit pattern Rust's own
        // `-f64::NAN` produces too, not just the default NaN.
        assert_eq!(python_float_repr(-f64::NAN), "nan");
    }

    #[test]
    fn big_int_round_trips() {
        let text = "12345678901234567890123456789012345678901234567890";
        let v: Value = loads(text).unwrap();
        assert_eq!(dumps(&v, DumpOptions::plain()).unwrap(), text);
    }

    #[test]
    fn float_vs_int_distinction_round_trips() {
        let v: Value = loads("3.0").unwrap();
        assert_eq!(dumps(&v, DumpOptions::plain()).unwrap(), "3.0");
        let v: Value = loads("3").unwrap();
        assert_eq!(dumps(&v, DumpOptions::plain()).unwrap(), "3");
    }

    #[test]
    fn ensure_ascii_escapes_non_bmp_as_surrogate_pair() {
        let s = "\u{1F600}"; // outside BMP
        assert_eq!(encode_str(s, true), "\"\\ud83d\\ude00\"");
        assert_eq!(encode_str(s, false), "\"\u{1F600}\"");
    }

    #[test]
    fn control_chars_and_quotes_are_escaped() {
        assert_eq!(encode_str("a\nb\tc\"d\\e", true), r#""a\nb\tc\"d\\e""#);
        assert_eq!(
            encode_str("\x00\x1f\x7f", false),
            "\"\\u0000\\u001f\u{7f}\""
        );
        assert_eq!(
            encode_str("\x00\x1f\x7f", true),
            "\"\\u0000\\u001f\\u007f\""
        );
    }

    // A-11(a), coordinator ruling PORTING.md §3.6.
    #[test]
    fn loads_rejects_lone_surrogate_escapes() {
        assert!(loads("\"\\ud800\"").is_err(), "lone high surrogate");
        assert!(loads("\"\\udc00\"").is_err(), "lone low surrogate");
        assert!(loads("\"a\\ud800b\"").is_err(), "lone surrogate mid-string");
        assert!(
            loads("{\"k\": \"\\ud800\"}").is_err(),
            "lone surrogate in an object value"
        );
        // A valid surrogate pair (U+1F600) must still parse.
        assert_eq!(loads("\"\\ud83d\\ude00\"").unwrap(), json!("\u{1F600}"));
        // An escaped backslash right before a quote must not desynchronise
        // the "inside a string literal" tracking.
        assert_eq!(loads(r#""a\\""#).unwrap(), json!("a\\"));
        assert_eq!(
            loads(r#"["a\\", "\ud83d\ude00"]"#).unwrap(),
            json!(["a\\", "\u{1F600}"])
        );
    }

    // A-11(b): a numeric literal whose magnitude overflows `f64` (CPython's
    // `float()` silently returns `inf`/`-inf` for these) must be rejected by
    // `loads`, and `dumps` must refuse to write a `Number` that is already
    // non-finite.
    #[test]
    fn loads_and_dumps_reject_overflowing_float_literals() {
        assert!(loads("1e400").is_err());
        assert!(loads("-1e400").is_err());
        assert!(loads("[1, 1e400]").is_err());
        assert!(loads("{\"a\": 1e400}").is_err());
        // Underflow to zero is not an error: Python's `float("1e-400")` is
        // `0.0`, not an exception.
        assert_eq!(loads("1e-400").unwrap().as_f64(), Some(0.0));
        // A huge *integer* literal (no '.'/exponent) is untouched: Python
        // `int` is unbounded and this is not a `float` at all.
        assert!(loads(&"9".repeat(400)).is_ok());

        // `Number::is_f64()` is itself `false` for an overflowing literal
        // (see `reject_non_finite_numbers`'s doc comment) -- constructing
        // one directly via `serde_json::from_str::<Number>` (bypassing this
        // module's `loads`, which already rejects it at the text level) is
        // the only way to get one to exercise `write_number`'s own guard.
        let overflowing_number: serde_json::Number = serde_json::from_str("1e400").unwrap();
        assert!(!overflowing_number.is_f64());
        assert!(is_float_literal(overflowing_number.as_str()));
        let v = Value::Number(overflowing_number);
        assert!(dumps(&v, DumpOptions::compact_sorted()).is_err());
    }
}

/// Wire/persisted-format tests against output the Python prototype's `json`
/// module produced (golden fixtures, `tests/fixtures/python/pyjson/
/// GENERATE.md`): canonical JSON is signed, hashed and used as AEAD
/// associated data, so these bytes must not drift.
#[cfg(test)]
mod oracle_tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/python/pyjson/cases.json");
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn f64_from_hex(bits: &str) -> f64 {
        f64::from_bits(u64::from_str_radix(bits, 16).unwrap())
    }

    // A-R3-1: depths the prototype's `json.loads` parsed (128-500) must
    // parse here too and keep their value.
    #[test]
    fn loads_matches_python_for_probed_nesting_depths() {
        for n in [128, 129, 200, 500] {
            let doc = super::tests::nested_array(n);
            assert_eq!(doc, format!("{}1{}", "[".repeat(n), "]".repeat(n)));
            let mut value =
                loads(&doc).unwrap_or_else(|e| panic!("depth {n} failed to parse in Rust: {e}"));
            for _ in 0..n {
                let mut arr = match value {
                    Value::Array(arr) if arr.len() == 1 => arr,
                    other => panic!("depth {n}: expected a single-element array, got {other:?}"),
                };
                value = arr.pop().unwrap();
            }
            assert_eq!(value, json!(1), "depth {n} should unwrap to the scalar 1");
        }
    }

    // Depth 1,000 is past `MAX_JSON_DEPTH` (990, below the deepest document
    // the prototype could persist): a clean rejection, never a truncation or
    // abort (`rust/DEVIATIONS.md` pyjson row 14).
    #[test]
    fn python_accepts_depths_past_max_json_depth_that_rust_now_rejects() {
        let n = 1000;
        assert!(n > MAX_JSON_DEPTH);
        let doc = super::tests::nested_array(n);
        let err = loads(&doc).expect_err("depth past MAX_JSON_DEPTH must be a clean rejection");
        assert!(
            err.to_string().contains("depth"),
            "expected a depth-related parse error, got: {err}"
        );
    }

    /// Finding H-R4-2: [`python_float_repr`] against the prototype's
    /// `repr(float)` over a representative sample -- the finding's own
    /// values, exact ties, powers of two (and neighbours) across the whole
    /// exponent range, subnormals and random bit patterns.
    #[test]
    fn float_repr_matches_python_for_a_representative_sample() {
        let fixture = fixture();
        let cases = fixture["float_repr"].as_array().unwrap();
        assert!(cases.len() > 900, "{}", cases.len());
        let mismatches: Vec<_> = cases
            .iter()
            .filter_map(|case| {
                let f = f64_from_hex(case[0].as_str().unwrap());
                let want = case[1].as_str().unwrap();
                let got = python_float_repr(f);
                (got != want).then(|| (case[0].clone(), got, want.to_string()))
            })
            .collect();
        assert!(mismatches.is_empty(), "{mismatches:#?}");
    }

    /// Finding H-R4-2's real-world consequence: `team/commit.rs` signs
    /// `Commit::canonical_json`, so any digit mismatch in a float's rendering
    /// breaks Ed25519 signature verification across implementations. Every
    /// [`DumpOptions`] preset this crate uses, byte for byte.
    #[test]
    fn dumps_matches_python_json_dumps_for_finding_values_in_every_option_combination() {
        let fixture = fixture();
        let docs = &fixture["float_documents"];
        let values: Vec<f64> = docs["values"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| f64_from_hex(v.as_str().unwrap()))
            .collect();
        assert_eq!(values.len(), 7);
        let presets: [(&str, DumpOptions); 4] = [
            ("compact_sorted", DumpOptions::compact_sorted()),
            ("pretty_sorted", DumpOptions::pretty_sorted()),
            ("default_sorted", DumpOptions::default_sorted()),
            ("plain", DumpOptions::plain()),
        ];
        for (name, opts) in presets {
            let want = docs["outputs"][name].as_array().unwrap();
            assert_eq!(want.len(), values.len());
            for (f, want) in values.iter().zip(want) {
                let doc = json!({"value": f, "list": [f, 1, "x"], "count": 3});
                assert_eq!(
                    dumps(&doc, opts).unwrap(),
                    want.as_str().unwrap(),
                    "preset {name} mismatch for value {f}"
                );
            }
        }
    }

    #[test]
    fn compact_sorted_matches_python_json_dumps_for_audit_style_records() {
        let fixture = fixture();
        let records = [
            json!({"b": 1, "a": "x\ny", "c": null, "d": true, "e": 3.5}),
            json!({"ts": "2023-11-14T22:13:20Z", "event": "http_relay", "reason": null, "policy_version": 3}),
            json!({"unicode": "caf\u{e9} \u{30c6}\u{30b9}\u{30c8} \u{1F600}", "empty_list": [], "empty_obj": {}}),
            json!({"nested": {"z": [1, 2, {"y": 3}], "a": -0.0}}),
        ];
        let want = fixture["compact_sorted_records"].as_array().unwrap();
        assert_eq!(want.len(), records.len());
        for (record, want) in records.iter().zip(want) {
            let got = dumps(record, DumpOptions::compact_sorted()).unwrap();
            assert_eq!(got, want.as_str().unwrap());
        }
    }

    #[test]
    fn pretty_sorted_matches_python_json_dump_indent_2() {
        let doc = json!({"z": [1, 2, 3], "a": {"nested": true, "b": null}, "empty": {}});
        let got = dumps(&doc, DumpOptions::pretty_sorted()).unwrap();
        assert_eq!(got, fixture()["pretty_sorted"].as_str().unwrap());
    }

    #[test]
    fn big_int_matches_python_str() {
        let a = loads("1267650600228229401496703205376").unwrap();
        assert_eq!(
            dumps(&a, DumpOptions::plain()).unwrap(),
            "1267650600228229401496703205376" // 2**100
        );
        let b = loads("-1606938044258990275541962092341162602522202993782792835301376").unwrap();
        assert_eq!(
            dumps(&b, DumpOptions::plain()).unwrap(),
            "-1606938044258990275541962092341162602522202993782792835301376" // -(2**200)
        );
    }

    #[test]
    fn ensure_ascii_matches_python_for_non_bmp_and_control_chars() {
        let fixture = fixture();
        let v = &fixture["ensure_ascii"];
        let s = "caf\u{e9} \u{1F600} \u{0}\u{1f}\u{7f} \\ \" \n\t";
        assert_eq!(v["input"].as_str().unwrap(), s);
        assert_eq!(encode_str(s, true), v["ascii"].as_str().unwrap());
        assert_eq!(encode_str(s, false), v["unicode"].as_str().unwrap());
    }

    // A-2: with `preserve_order` enabled, `DumpOptions::plain()` (no
    // `sort_keys`) emits keys in insertion order, matching `json.dumps` on a
    // plain `dict` -- e.g. `ZeroPWError.to_dict()`'s `{"error", "reason",
    // "detail"}` shape that agents parse.
    #[test]
    fn plain_preserves_insertion_order_matching_python_error_to_dict_shape() {
        let mut error_shape = serde_json::Map::new();
        error_shape.insert("error".to_string(), json!("InvalidInput"));
        error_shape.insert("reason".to_string(), json!("invalid_input"));
        error_shape.insert("detail".to_string(), json!("bad name"));
        assert_eq!(
            dumps(&Value::Object(error_shape), DumpOptions::plain()).unwrap(),
            r#"{"error": "InvalidInput", "reason": "invalid_input", "detail": "bad name"}"#
        );

        let mut unsorted = serde_json::Map::new();
        unsorted.insert("z".to_string(), json!(1));
        unsorted.insert("a".to_string(), json!(2));
        unsorted.insert("m".to_string(), json!(3));
        assert_eq!(
            dumps(&Value::Object(unsorted), DumpOptions::plain()).unwrap(),
            r#"{"z": 1, "a": 2, "m": 3}"#
        );
    }

    #[test]
    fn loads_matches_python_json_loads_round_trip() {
        // A state-directory-shaped document pretty-printed by the prototype
        // parses here and re-serializes byte-identically (StateDir's
        // contract).
        let python_text = fixture()["state_document"].as_str().unwrap().to_string();
        let value = loads(&python_text).unwrap();
        let rust_text = dumps(&value, DumpOptions::pretty_sorted()).unwrap();
        assert_eq!(rust_text, python_text);
    }

    // A-11 (PORTING.md §3.6): a lone surrogate escape and an overflowing
    // numeric literal (both accepted by CPython's `json.loads`) are rejected
    // as malformed here.
    #[test]
    fn python_accepts_what_rust_rejects_lone_surrogate_and_overflow_literal() {
        assert!(loads("\"\\ud800\"").is_err());
        assert!(loads("1e400").is_err());
    }
}
