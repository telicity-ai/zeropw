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
//! / `repr()` mode `json.dumps` uses for floats) from the shortest
//! round-trip digits Rust's own float formatter produces -- so the output
//! matches Python byte-for-byte regardless of whether the `Number` came from
//! parsing Python's JSON or from Rust arithmetic.
//!
//! ## NaN / Infinity
//!
//! Python's encoder (`allow_nan=True` by default) can write bare `NaN`,
//! `Infinity`, `-Infinity` tokens, and its decoder accepts them back.
//! Separately, CPython's `float()` silently *overflows* rather than erroring
//! -- a numeric literal like `1e400` parses to `inf` with no exception. No
//! writer in `zeropw/` ever produces a non-finite float or an overflowing
//! literal (audit fields are `round(time.time(), 3)`-derived; vault/policy
//! documents hold no floats at all), so this port does not special-case
//! them: [`dumps`] returns an error for a non-finite float (defensive,
//! should be unreachable), and [`loads`] rejects the bare tokens *and* any
//! literal that would overflow to a non-finite `f64` as a parse error, like
//! any other malformed JSON. A state file that somehow contained one would
//! be `state_corrupt` in Rust but would silently parse in Python -- recorded
//! in `DEVIATIONS.md`.
//!
//! ## Recursion / nesting depth
//!
//! `serde_json`'s `Value` deserializer refuses more than a hardcoded 128
//! levels of array/object nesting by default (`RECURSION_LIMIT`), a limit
//! CPython's `json` module does not share: probing `python3.12` directly
//! shows `json.loads` happily parsing depths of 128, 129, 200, 500 and 900
//! (this port's specific reviewer-probed depths -- pinned by
//! `oracle_tests::loads_matches_python_for_probed_nesting_depths`), and
//! considerably deeper still before it exhausts the interpreter's own
//! recursion accounting. A document Python parses without complaint was,
//! before A-R3-1, silently turned into `state_corrupt`
//! (`StateDir::read_json`, `Audit::tail`/`alerts`), a silent skip
//! (`Audit::iter_records`), or a malformed-input error (handle payloads,
//! peer/agent JSON bodies) in this port -- for anything past a mere 128
//! levels.
//!
//! Simply disabling `serde_json`'s limit and picking one higher fixed bound
//! is not enough, because *two* separate operations recurse over a `Value`
//! tree's native stack frames, not just one:
//!
//! - **Building** it: `serde_json`'s recursive-descent parser, which (an ad
//!   hoc development-time probe found) overflows a 2 MiB stack somewhere
//!   between 800 and 900 levels of nesting in an unoptimized/debug build --
//!   uncomfortably close to this port's own required 900-level probe.
//! - **Dropping** it: once parsed, the returned `Value` crosses back to
//!   whatever thread [`loads`]'s caller runs on (this crate has no control
//!   over that, or over how long the caller holds onto it before it goes out
//!   of scope) and its ordinary recursive `Drop` glue then walks the same
//!   depth again, on *that* thread. Cheaper per level than parsing, but not
//!   free: the same kind of probe found a 2 MiB stack overflowing somewhere
//!   between 8,000 and 9,000 levels here.
//!
//! [`loads`] therefore uses a two-tier strategy for parsing (so a rare deep
//! document doesn't risk overflowing whatever stack a caller happens to be
//! on, while the overwhelming majority of calls -- a handful of levels deep
//! at most -- pay no extra cost), *and* keeps [`MAX_JSON_DEPTH`] itself
//! comfortably under the lower (drop) danger zone above, since that hazard
//! isn't something a dedicated parsing thread can fix:
//!
//! 1. [`scan_nesting_depth`] pre-scans the raw text (no parsing yet) for its
//!    maximum `{`/`[` nesting depth, rejecting outright anything past
//!    [`MAX_JSON_DEPTH`] (4,096) -- comfortably past every depth this
//!    product ever writes (state/audit/policy/handle documents are a
//!    handful of levels deep at most), past every depth this port's probes
//!    require (900), and still roughly 2x under the empirical 8,000-9,000
//!    level *drop* danger zone above, leaving real margin for a build or
//!    platform with tighter stack frames than the one this was measured on.
//!    A document this deep is not something any writer in this crate, or
//!    the matching Python prototype, ever produces; rejecting it is a
//!    residual, intentional divergence from CPython's own (considerably
//!    higher, and itself uncaught-`RecursionError`-bounded rather than a
//!    documented contract) practical ceiling, recorded in
//!    `rust/DEVIATIONS.md`.
//! 2. A document at or below [`SAFE_INLINE_DEPTH`] (200) parses directly on
//!    the calling thread: `serde_json`'s built-in limit is disabled
//!    (`Deserializer::disable_recursion_limit`, which additionally requires
//!    this crate's `unbounded_depth` Cargo feature to take effect for
//!    `Value` specifically -- see that method's own doc). 200 levels of
//!    *building* is safe on any thread's stack, including a freshly spawned
//!    `std::thread`'s small platform default -- pinned by
//!    `tests::inline_path_is_safe_on_a_small_stack_thread` -- with a wide
//!    margin below the 800-900 build danger zone above.
//! 3. A deeper document (up to [`MAX_JSON_DEPTH`]) is instead *built* on a
//!    dedicated thread with an explicit large stack
//!    (`LARGE_PARSE_STACK_BYTES`, 64 MiB) via [`parse_on_dedicated_stack`].
//!    The *drop* danger zone (8,000-9,000) is still comfortably above
//!    `MAX_JSON_DEPTH` itself, so the caller receiving the parsed `Value`
//!    back and eventually dropping it on its own (possibly small-stack)
//!    thread remains safe too --
//!    `tests::dedicated_stack_result_is_safe_to_drop_on_a_small_stack` pins
//!    exactly that end-to-end path (build on the dedicated thread, hand the
//!    deepest-allowed result back, drop it on a small one).
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

/// Maximum array/object nesting depth [`loads`] accepts at all. See the
/// module doc's "Recursion / nesting depth" section for why this value (and
/// not `serde_json`'s built-in 128-level default) was chosen.
pub const MAX_JSON_DEPTH: usize = 4096;

/// Maximum nesting depth [`loads`] will parse directly on the calling
/// thread; anything deeper (up to [`MAX_JSON_DEPTH`]) is instead parsed on a
/// dedicated large-stack thread. See the module doc's "Recursion / nesting
/// depth" section.
const SAFE_INLINE_DEPTH: usize = 200;

/// Stack size for the dedicated thread [`parse_on_dedicated_stack`] spawns
/// for a document deeper than [`SAFE_INLINE_DEPTH`]. See the module doc's
/// "Recursion / nesting depth" section for the empirical test backing this
/// number.
const LARGE_PARSE_STACK_BYTES: usize = 64 * 1024 * 1024;

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
pub fn dumps(value: &Value, opts: DumpOptions) -> Result<String> {
    let mut out = String::new();
    write_value(value, &opts, 0, &mut out)?;
    Ok(out)
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

fn is_float_literal(raw: &str) -> bool {
    raw.contains(['.', 'e', 'E'])
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
/// to `f` (Rust's own `{:e}` formatter already computes exactly this -- same
/// class of shortest-round-trip algorithm as CPython's David Gay `dtoa`
/// mode 0), then lay it out fixed or exponential using the same thresholds
/// CPython uses: exponential when the decimal point would fall at or before
/// position -4, or after position 16.
pub fn python_float_repr(f: f64) -> String {
    if f == 0.0 {
        return if f.is_sign_negative() {
            "-0.0".to_string()
        } else {
            "0.0".to_string()
        };
    }
    let neg = f.is_sign_negative();
    let af = f.abs();
    // "{:e}" gives the shortest round-trip mantissa (1 <= mantissa < 10) and
    // decimal exponent: af == mantissa * 10^exp.
    let sci = format!("{af:e}");
    let (mantissa, exp_str) = sci.split_once('e').expect("LowerExp always contains 'e'");
    let exp: i32 = exp_str.parse().expect("LowerExp exponent is an integer");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let n = digits.len() as i32;
    // value == 0.d1 d2 ... dn * 10^decpt
    let decpt = exp + 1;

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
        for n in [SAFE_INLINE_DEPTH + 1, 1000, MAX_JSON_DEPTH] {
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
        ];
        for (f, expected) in cases {
            assert_eq!(python_float_repr(*f), *expected, "for {f}");
        }
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

/// Differential tests against the CPython oracle (`crate::oracle`). Separate
/// module so the plain unit tests above stay fast and offline-only; these
/// shell out to `python3.12`.
#[cfg(test)]
mod oracle_tests {
    use super::*;
    use crate::oracle;
    use serde_json::json;

    // A-R3-1: the exact depths the equivalence review probed against
    // `python3.12` (all confirmed there to parse without error) must also
    // parse in Rust -- pinning the fix for the bug where anything past a
    // mere 128 levels of nesting became `state_corrupt`/a silent skip/a
    // malformed-input error in this port despite Python handling it fine.
    #[test]
    fn loads_matches_python_for_probed_nesting_depths() {
        let depths = [128, 129, 200, 500, 900];
        let script = format!("for n in {depths:?}:\n    print('[' * n + '1' + ']' * n)\n",);
        let output = oracle::python(&script);
        let py_lines: Vec<&str> = output.lines().collect();
        assert_eq!(py_lines.len(), depths.len());
        for (&n, py_doc) in depths.iter().zip(py_lines.iter()) {
            // Python parsed it without raising (otherwise the script above
            // would have thrown and `oracle::python` would have panicked on
            // the non-zero exit) -- confirm Rust parses the identical text
            // too, and that the two produce the same logical value.
            let rust_doc = super::tests::nested_array(n);
            assert_eq!(&rust_doc, py_doc, "depth {n} document text mismatch");
            let mut value = loads(py_doc).unwrap_or_else(|e| {
                panic!("depth {n} (confirmed OK in Python) failed to parse in Rust: {e}")
            });
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

    /// A small, deterministic xorshift64 PRNG -- good enough to fuzz float
    /// bit patterns reproducibly without pulling `rand` into a test that's
    /// meant to stay easy to re-run by hand.
    struct Xorshift64(u64);
    impl Xorshift64 {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    #[test]
    fn float_repr_matches_python_for_many_random_bit_patterns() {
        let mut rng = Xorshift64(0x9E3779B97F4A7C15);
        let mut bits = Vec::new();
        // A mix of fully random bit patterns (covers subnormals, huge
        // exponents, odd mantissas) and random-magnitude "nice" decimals
        // (covers the fixed/exponential threshold boundaries in practice).
        for _ in 0..400 {
            let b = rng.next();
            let f = f64::from_bits(b);
            if f.is_finite() {
                bits.push(b);
            }
        }
        for exp in -20..20 {
            for _ in 0..5 {
                let mantissa = (rng.next() % 1_000_000_000) as f64 / 1e6;
                let f = mantissa * 10f64.powi(exp);
                if f.is_finite() {
                    bits.push(f.to_bits());
                }
            }
        }
        // Known edge cases from CPython's format_float_short thresholds.
        for f in [
            0.0f64,
            -0.0,
            1e15,
            1e16,
            1e-4,
            1e-5,
            f64::MIN_POSITIVE,
            f64::MAX,
            -f64::MAX,
        ] {
            bits.push(f.to_bits());
        }

        let script = format!(
            "import struct\nfor b in {bits:?}:\n    print(repr(struct.unpack('>d', struct.pack('>Q', b))[0]))",
        );
        let output = oracle::python(&script);
        let expected: Vec<&str> = output.lines().collect();
        assert_eq!(expected.len(), bits.len());
        for (b, want) in bits.iter().zip(expected.iter()) {
            let f = f64::from_bits(*b);
            let got = python_float_repr(f);
            assert_eq!(&got, want, "float_repr mismatch for bits {b:#x} ({f})");
        }
    }

    #[test]
    fn compact_sorted_matches_python_json_dumps_for_audit_style_records() {
        let script = r#"
import json
records = [
    {"b": 1, "a": "x\ny", "c": None, "d": True, "e": 3.5},
    {"ts": "2023-11-14T22:13:20Z", "event": "http_relay", "reason": None, "policy_version": 3},
    {"unicode": "café テスト \U0001F600", "empty_list": [], "empty_obj": {}},
    {"nested": {"z": [1, 2, {"y": 3}], "a": -0.0}},
]
for r in records:
    print(json.dumps(r, sort_keys=True, separators=(",", ":")))
"#;
        let output = oracle::python(script);
        let py_lines: Vec<&str> = output.lines().collect();

        let records = [
            json!({"b": 1, "a": "x\ny", "c": null, "d": true, "e": 3.5}),
            json!({"ts": "2023-11-14T22:13:20Z", "event": "http_relay", "reason": null, "policy_version": 3}),
            json!({"unicode": "caf\u{e9} \u{30c6}\u{30b9}\u{30c8} \u{1F600}", "empty_list": [], "empty_obj": {}}),
            json!({"nested": {"z": [1, 2, {"y": 3}], "a": -0.0}}),
        ];
        assert_eq!(py_lines.len(), records.len());
        for (record, want) in records.iter().zip(py_lines.iter()) {
            let got = dumps(record, DumpOptions::compact_sorted()).unwrap();
            assert_eq!(&got, want);
        }
    }

    #[test]
    fn pretty_sorted_matches_python_json_dump_indent_2() {
        let script = r#"
import json
doc = {"z": [1, 2, 3], "a": {"nested": True, "b": None}, "empty": {}}
print(json.dumps(doc, sort_keys=True, indent=2))
"#;
        let want = oracle::python(script);
        let doc = json!({"z": [1, 2, 3], "a": {"nested": true, "b": null}, "empty": {}});
        let got = dumps(&doc, DumpOptions::pretty_sorted()).unwrap();
        assert_eq!(got, want.trim_end_matches('\n'));
    }

    #[test]
    fn big_int_matches_python_str() {
        let script = "print(2**100)\nprint(-(2**200))";
        let want = oracle::python(script);
        let mut lines = want.lines();
        let a = loads("1267650600228229401496703205376").unwrap();
        assert_eq!(
            dumps(&a, DumpOptions::plain()).unwrap(),
            lines.next().unwrap()
        );
        let b = loads("-1606938044258990275541962092341162602522202993782792835301376").unwrap();
        assert_eq!(
            dumps(&b, DumpOptions::plain()).unwrap(),
            lines.next().unwrap()
        );
    }

    #[test]
    fn ensure_ascii_matches_python_for_non_bmp_and_control_chars() {
        let script = r#"
import json
s = "café \U0001F600 \x00\x1f\x7f \\ \" \n\t"
print(json.dumps(s))
print(json.dumps(s, ensure_ascii=False))
"#;
        let want = oracle::python(script);
        let mut lines = want.lines();
        let s = "caf\u{e9} \u{1F600} \u{0}\u{1f}\u{7f} \\ \" \n\t";
        assert_eq!(encode_str(s, true), lines.next().unwrap());
        assert_eq!(encode_str(s, false), lines.next().unwrap());
    }

    // A-2: with `preserve_order` enabled, `DumpOptions::plain()` (no
    // `sort_keys`) must emit keys in insertion order, matching Python's
    // `json.dumps(payload)` on a plain `dict` -- e.g. `ZeroPWError.to_dict()`'s
    // `{"error": ..., "reason": ..., "detail": ...}` shape.
    #[test]
    fn plain_preserves_insertion_order_matching_python_error_to_dict_shape() {
        let script = r#"
import json
print(json.dumps({"error": "InvalidInput", "reason": "invalid_input", "detail": "bad name"}))
print(json.dumps({"z": 1, "a": 2, "m": 3}))
"#;
        let want = oracle::python(script);
        let mut lines = want.lines();

        let mut error_shape = serde_json::Map::new();
        error_shape.insert("error".to_string(), json!("InvalidInput"));
        error_shape.insert("reason".to_string(), json!("invalid_input"));
        error_shape.insert("detail".to_string(), json!("bad name"));
        assert_eq!(
            dumps(&Value::Object(error_shape), DumpOptions::plain()).unwrap(),
            lines.next().unwrap()
        );

        let mut unsorted = serde_json::Map::new();
        unsorted.insert("z".to_string(), json!(1));
        unsorted.insert("a".to_string(), json!(2));
        unsorted.insert("m".to_string(), json!(3));
        assert_eq!(
            dumps(&Value::Object(unsorted), DumpOptions::plain()).unwrap(),
            lines.next().unwrap()
        );
    }

    #[test]
    fn loads_matches_python_json_loads_round_trip() {
        // A state-directory-shaped document, pretty-printed by Python, must
        // parse in Rust to the same logical value `pyjson::dumps` then
        // re-serializes byte-identically (StateDir's actual contract).
        let script = r#"
import json
doc = {"secrets": {"s1": {"version": 3, "created_at": "2023-01-01T00:00:00Z"}}, "count": 5, "ratio": 0.1}
print(json.dumps(doc, sort_keys=True, indent=2))
"#;
        let python_text = oracle::python(script);
        let value = loads(python_text.trim_end_matches('\n')).unwrap();
        let rust_text = dumps(&value, DumpOptions::pretty_sorted()).unwrap();
        assert_eq!(rust_text, python_text.trim_end_matches('\n'));
    }

    // A-11: pins the actual CPython behaviour this port intentionally
    // diverges from (PORTING.md §3.6 and the pyjson DEVIATIONS.md rows) --
    // Python accepts a lone surrogate escape and an overflowing numeric
    // literal; this port rejects both as malformed.
    #[test]
    fn python_accepts_what_rust_rejects_lone_surrogate_and_overflow_literal() {
        let script = r#"
import json
print(repr(json.loads('"\ud800"')))
n = json.loads("1e400")
print(n)
print(json.dumps(n))
"#;
        let out = oracle::python(script);
        let mut lines = out.lines();
        assert_eq!(lines.next().unwrap(), r"'\ud800'");
        assert_eq!(lines.next().unwrap(), "inf");
        assert_eq!(lines.next().unwrap(), "Infinity");

        assert!(loads("\"\\ud800\"").is_err());
        assert!(loads("1e400").is_err());
    }
}
