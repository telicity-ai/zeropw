//! Structural guard: PORTING.md §3b names ONE canonical home for each
//! CPython-semantics emulation this crate needs (`pystr` for
//! `str.isspace`/`str.isprintable`/`repr(str)`/`int(str)`'s grammar,
//! `pybase64` for lenient `b64decode`/`urlsafe`/encode, `pyjson` for
//! `json.dump`/`load` byte compatibility) specifically because the same
//! mistake has been made more than once by re-implementing (or bypassing)
//! one of these semantics locally instead of reusing the canonical helper:
//! three separate work units independently got `int(str)`'s whitespace set
//! wrong (round 6, finding E-R6-1), two more had byte-identical private
//! copies of a `repr` helper, and this very round (F-R4-3/F-R4-5) found a
//! strict-base64 bypass and a float-rendering bypass in `gateway.rs` of
//! exactly this shape. Each instance gets fixed individually; the class of
//! defect keeps recurring. This file is a committed, `cargo test`-run guard
//! against the class, not just this round's two instances.
//!
//! It scans `rust/src/**/*.rs` at test time (not `include_str!`, so it sees
//! the real, current source on every run) for three narrow, high-precision
//! textual patterns -- deliberately narrow: a pattern broad enough to catch
//! every conceivable bypass would also flag every legitimate use in this
//! crate (base64 *encoding*, an `int`-shaped-literal source-text check, a
//! delegating wrapper), and "a test that cries wolf gets deleted by the
//! next agent" is a worse outcome than a narrower net. Legitimate existing
//! matches are named in an explicit allowlist below, each with a one-line
//! reason; nothing is allowlisted merely to make the test pass.
//!
//! Verified to actually catch a reintroduction of the exact bug each
//! pattern targets (see this file's own doc comments below for the specific
//! revert-and-rerun each check's author performed) -- and re-verifiable at
//! any time by temporarily reverting `gateway.rs`'s F-R4-3/F-R4-5 fixes.

use regex::Regex;
use std::path::{Path, PathBuf};

/// One line already known to be a legitimate match for one of the checks
/// below, identified by the source file (relative to `rust/src/`) and a
/// distinctive substring of the matched line (or, for the function-body
/// check, of the `fn` signature line). Matching by content rather than line
/// number survives the file being reformatted or gaining/losing unrelated
/// lines elsewhere.
struct Allow {
    file: &'static str,
    marker: &'static str,
    reason: &'static str,
}

/// Allowlist for the base64-decode check ([`check_base64_decode_bypass`]).
/// Every entry here decodes with the `base64` crate's own engines directly
/// instead of `crate::pybase64::b64decode` -- legitimate only because none
/// of them are modelling CPython's *lenient* (`validate=False`) default
/// `base64.b64decode`, the one behaviour `pybase64` exists to reproduce
/// (PORTING.md §3b: "base64 (lenient `b64decode`, urlsafe, encode)").
const BASE64_DECODE_ALLOWLIST: &[Allow] = &[
    Allow {
        file: "gateway.rs",
        marker: "entry[2].as_str().unwrap()",
        reason: "test-only oracle-comparison harness: decodes base64 that the Python \
                 oracle subprocess itself produced via its own trusted b64encode call, \
                 never agent/attacker input, so CPython's lenient-decode leniency is not \
                 being modelled here at all",
    },
    Allow {
        file: "crypto/ed25519.rs",
        marker: ".decode(joined)",
        reason: "kms.rs's `_dearmor` (PEM key armor) calls Python's `base64.b64decode(text, \
                 validate=True)` -- the STRICT variant, matching this crate's own strict \
                 `STANDARD` engine exactly; pybase64 only covers the lenient default \
                 (`validate=False`) used elsewhere (gateway.py, handles.py), a genuinely \
                 different Python function, not a bypass of it",
    },
    Allow {
        file: "crypto/ed25519.rs",
        marker: "public key field",
        reason: "test-only: decodes a real `ssh-keygen`-produced public key file's base64 \
                 field in a `#[test]`, not agent/attacker input",
    },
];

/// Allowlist for the float-rendering check
/// ([`check_number_to_string_float_bypass`]). Every entry here calls
/// `serde_json::Number`'s `Display`/`to_string()` directly (as `n.to_string()`,
/// this crate's consistent naming for a `serde_json::Number` binding)
/// outside `pyjson.rs`.
const NUMBER_TO_STRING_ALLOWLIST: &[Allow] = &[
    Allow {
        file: "gateway.rs",
        marker: "n.is_i64() || n.is_u64()",
        reason: "python_str_of's `Value::Number` arm (finding F-R4-5): both `n.to_string()` \
                 occurrences here are reached only inside this `is_i64()/is_u64()` guard's \
                 if/else (the TRUE-int branch, and a defensive fallback for the \
                 (unreachable) case `as_f64()` still fails on the float branch) -- Python \
                 `str(int)` is exactly the decimal digits, and the real float branch \
                 renders through the canonical `pyjson::python_float_repr`. The marker is \
                 the guard condition itself, not `n.to_string()` (too generic: it would \
                 also match a reintroduced, UNGUARDED `Value::Number(n) => n.to_string()` \
                 elsewhere in this file -- verified by literally reintroducing that exact \
                 line and confirming this check still fails on it).",
    },
    Allow {
        file: "policy.rs",
        marker: "let text = n.to_string();",
        reason: "number_literal_is_zero inspects the literal's own SOURCE TEXT (which \
                 digits appear before any exponent) to answer a yes/no question, never \
                 renders the number as output -- the exact 'inspecting source text rather \
                 than rendering a float' case PORTING.md's own guidance names as legitimate",
    },
    Allow {
        file: "policy.rs",
        marker: "n.to_string().starts_with('-')",
        reason: "number_literal_is_negative: same source-text inspection as \
                 number_literal_is_zero above, just checking the sign",
    },
    Allow {
        file: "policy.rs",
        marker: "!n.to_string().contains(['.', 'e', 'E'])",
        reason: "number_is_python_int: same source-text inspection (does the literal have \
                 int or float *shape*?), not a str()-coercion render",
    },
    Allow {
        file: "team/commit.rs",
        marker: "is_float_literal(n.as_str())",
        reason: "python_str_coerce's Number arm (the canonical str()-for-a-non-string-JSON-\
                 scalar coercion, PORTING.md §3b, finding H-R4-1): both `n.to_string()` \
                 occurrences here are inside this `is_float_literal` guard's if/else -- the \
                 defensive `.unwrap_or_else(|| n.to_string())` fallback for a float-shaped \
                 literal whose `as_f64()` somehow still fails, and the plain integer branch \
                 (`else { n.to_string() }`) -- Python str(int) is exactly the decimal \
                 digits, and the normal float path renders through the canonical \
                 pyjson::python_float_repr. The marker is the guard condition, not \
                 `n.to_string()` itself, for the same reason as the gateway.rs entry above.",
    },
    Allow {
        file: "team/fold.rs",
        marker: "!local_versions.contains_key(&n.to_string())",
        reason: "false positive from the `n` naming heuristic: this `n` is `i64` (from \
                 `if let Some(n) = active_number`, an Option<i64>), not a serde_json::Number \
                 at all -- there is no JSON literal spelling to preserve or lose here, \
                 just an integer being used as a map key",
    },
    Allow {
        file: "policy.rs",
        marker: "Value::Number(n) if number_is_python_int(n) => n.to_string() == \"0\",",
        reason: "grant_num_value_is_zero's Number arm: guarded by number_is_python_int, same \
                 shape as grant_num_max_with_zero's sibling `.starts_with('-')` entry above -- \
                 an integer-shaped literal is never the string \"0\" unless its decimal value \
                 genuinely is zero, and the very next arm handles the real float branch via \
                 exact `f64` equality, not a rendered string.",
    },
    Allow {
        file: "policy.rs",
        marker: "let Ok(secs) = n.to_string().parse::<i128>()",
        reason: "iso_for_raw_value's exact-integer fast path (finding D-R7-3): only reached \
                 once number_is_python_int has confirmed the literal is integer-shaped (the \
                 guard one line above, in the same `if let ... && ... &&` chain), so this \
                 parses the exact decimal digits into i128 to avoid numeric_value_as_f64's \
                 precision loss above 2**53 -- not a rendered string; the fallback path below \
                 goes through the ordinary f64/`store::iso` route for anything this doesn't \
                 catch.",
    },
    Allow {
        file: "policy.rs",
        marker: "let Ok(exp_i128) = n.to_string().parse::<i128>()",
        reason: "now_at_least_exact's exact-integer fast path (finding D-R7-3): same shape as \
                 iso_for_raw_value's entry above -- guarded by number_is_python_int one line \
                 up in the same let-chain, parses exact decimal digits into i128 for an exact \
                 `floor(now) >= exp` comparison, not a rendered string; anything else falls \
                 back to the existing f64 comparison.",
    },
    Allow {
        file: "policy.rs",
        marker: "Value::Number(n) if number_is_python_int(n) => n.to_string(),",
        reason: "python_str_for_error's Number arm (same guarded-int-branch shape as the \
                 gateway.rs/team/commit.rs entries above, and policy.rs's own \
                 python_numeric_eq_value entry): only reached once number_is_python_int has \
                 confirmed the literal is integer-shaped, so Python's str(int) is exactly \
                 the decimal digits -- the very next match arm renders the real float branch \
                 through the canonical pyjson::python_float_repr. This function previously \
                 had an UNGUARDED `Value::Number(n) => n.to_string(),` arm, recorded as real \
                 debt in a since-removed allowlist entry -- PORTING.md §3b's round-7 addendum \
                 names this exact gap (D-PO-1) as fixed by the SAME eb88e3a commit that never \
                 updated this guard's allowlist to match, so the guard was left failing on a \
                 stale marker describing debt the code no longer has. This entry replaces \
                 that stale one.",
    },
];

/// Allowlist for the `repr`/`str`-number-rendering `is_f64()` check
/// ([`no_number_is_f64_repr_bypass_outside_pystr`]). There are currently no
/// legitimate exceptions: number rendering belongs in `pystr::repr_number`.
const NUMBER_IS_F64_REPR_ALLOWLIST: &[Allow] = &[];

/// Recursively collects every `*.rs` file under `dir`.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn src_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// `path` relative to `rust/src/`, with forward slashes regardless of host
/// platform, matching how [`Allow::file`] entries above are spelled.
fn relative_slash(path: &Path, base: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Any `base64::engine`/`STANDARD`/`URL_SAFE` DECODE outside `pybase64.rs`
/// (PORTING.md §3b names `pybase64` the canonical home for lenient
/// `b64decode`). Detected as a `.decode(` call within a two-line window of
/// a `STANDARD`/`URL_SAFE` token -- narrow enough to leave every base64
/// *encode* call site alone (encoding has no leniency to reproduce, per
/// `pybase64.rs`'s own module doc) while still catching a chained or
/// `rustfmt`-broken-across-lines decode call, the exact shape of the
/// original finding F-R4-3 bug (`base64::engine::general_purpose::STANDARD`
/// on one line, `.decode(...)` on the next).
///
/// Verified to catch a reintroduction: temporarily replacing
/// `RequestLedger::replay`'s `crate::pybase64::b64decode(s)` call with
/// `base64::engine::general_purpose::STANDARD.decode(s).ok()` and re-running
/// this test fails it at `gateway.rs`, naming that exact line; reverting
/// restores a pass. (Re-run this revert-and-restore yourself with `git
/// stash`/a scratch edit if you doubt it -- do not trust this comment
/// alone.)
#[test]
fn no_base64_engine_decode_outside_pybase64() {
    let base = src_dir();
    let mut files = Vec::new();
    collect_rs_files(&base, &mut files);
    let mut violations = Vec::new();
    let mut used = vec![false; BASE64_DECODE_ALLOWLIST.len()];

    for path in &files {
        let rel = relative_slash(path, &base);
        if rel == "pybase64.rs" {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !line.contains(".decode(") {
                continue;
            }
            let window_start = i.saturating_sub(2);
            let window = lines[window_start..=i].join("\n");
            if !(window.contains("STANDARD") || window.contains("URL_SAFE")) {
                continue;
            }
            if let Some(idx) = BASE64_DECODE_ALLOWLIST
                .iter()
                .position(|a| rel.ends_with(a.file) && window.contains(a.marker))
            {
                used[idx] = true;
                continue;
            }
            violations.push(format!("{rel}:{}: {}", i + 1, line.trim()));
        }
    }

    for (allow, was_used) in BASE64_DECODE_ALLOWLIST.iter().zip(used.iter()) {
        assert!(
            *was_used,
            "canonical_helpers.rs's BASE64_DECODE_ALLOWLIST entry for {} ({:?}, reason: {}) \
             no longer matches anything in the source -- remove it or update its marker, \
             don't leave a stale allowlist entry masking nothing",
            allow.file, allow.marker, allow.reason
        );
    }

    assert!(
        violations.is_empty(),
        "found base64 DECODE call(s) using the `base64` crate's own engine directly, \
         bypassing the canonical crate::pybase64::b64decode (PORTING.md §3b: pybase64 is \
         the one home for lenient b64decode). Either route through \
         crate::pybase64::b64decode, or, if this specific call is genuinely not modelling \
         CPython's lenient default b64decode (e.g. it deliberately reproduces \
         `validate=True`, or it decodes trusted test-harness-only data), add it to \
         BASE64_DECODE_ALLOWLIST in this file with a one-line reason:\n{}",
        violations.join("\n")
    );
}

/// A `serde_json::Number` rendered via `Display`/`to_string()` (this
/// crate's consistent spelling: `n.to_string()`, where `n` is a
/// `serde_json::Number`) outside `pyjson.rs`, in a way that is not merely
/// inspecting the literal's own source text. PORTING.md §3b names
/// `crate::pyjson::python_float_repr` the canonical CPython-`repr(float)`-
/// exact renderer; `Number::to_string()` instead preserves the JSON
/// literal's own spelling verbatim (`1e-7` stays `"1e-7"`, not `"1e-07"`),
/// which is only correct for values never actually rendered as a float
/// (an already-int-shaped literal, or a value only ever *inspected*, never
/// emitted).
///
/// This is necessarily a narrower net than "every float-rendering bypass
/// anywhere in the crate": it only catches this crate's own consistent
/// `n.to_string()` spelling (verified by grepping the whole crate for any
/// other spelling of a `Number`-to-`String` render -- none currently
/// exist), not a differently-named variable or a hand-rolled digit-by-digit
/// formatter. Every current match is catalogued in
/// `NUMBER_TO_STRING_ALLOWLIST` above; every entry is a guarded int-shaped
/// branch or a source-text inspection, not a live "known debt" render (the
/// one entry that used to record real debt, `policy.rs`'s
/// `python_str_for_error`, was fixed by PORTING.md §3b's D-PO-1 and its
/// entry updated to match the fix, rather than left describing code that no
/// longer exists).
///
/// Verified to catch a reintroduction, two ways: (1) temporarily replacing
/// `python_str_of`'s whole `Value::Number` arm with the pre-F-R4-5 bug
/// (`Value::Number(n) => n.to_string(),`, no `is_i64`/`is_u64` guard at
/// all) fails this test -- the `gateway.rs` allowlist entry's own marker
/// (the guard condition, not `n.to_string()` itself) no longer appears
/// anywhere in the file, so the entry is reported stale rather than
/// silently absorbing the regression; (2) adding a brand new, unguarded
/// `fn rogue_number_render(n: &serde_json::Number) -> String { n.to_string()
/// }` anywhere in `gateway.rs`, alongside the existing legitimate code
/// (not replacing it), is caught directly as a violation naming that new
/// line. Reverting either change restores a pass.
#[test]
fn no_number_to_string_outside_pyjson() {
    // `\bn\.to_string\(\)`: a WORD-BOUNDARY-anchored `n`, so this matches a
    // standalone one-letter `serde_json::Number` binding named `n`
    // (`n.to_string()`, `(n.to_string())`, `=> n.to_string(),`, ...) and
    // NOT the same three characters appearing at the tail of a longer
    // identifier like `reason.to_string()` or `version.to_string()` (an
    // earlier, unanchored version of this check matched those too -- pure
    // noise, since `reason`/`version` are `String`/`u64` fields with
    // nothing to do with `serde_json::Number` at all). Note this is still a
    // name-based heuristic, not type information: a plain `i64`/`u32`
    // variable that happens to be named `n` also matches
    // (`team/fold.rs`'s allowlisted false positive below is exactly that).
    let number_to_string = Regex::new(r"\bn\.to_string\(\)").unwrap();
    // Matched against a small window (the flagged line plus up to 6 lines
    // before it), not just the flagged line alone, so an allowlist marker
    // can require the actual GUARD CONDITION that makes a `n.to_string()`
    // legitimate (e.g. `n.is_i64() || n.is_u64()`) rather than the
    // `n.to_string()` text itself -- which would also match a reintroduced,
    // unguarded copy of the exact bug elsewhere in the same file.
    const WINDOW: usize = 6;
    let base = src_dir();
    let mut files = Vec::new();
    collect_rs_files(&base, &mut files);
    let mut violations = Vec::new();
    let mut used = vec![false; NUMBER_TO_STRING_ALLOWLIST.len()];

    for path in &files {
        let rel = relative_slash(path, &base);
        if rel == "pyjson.rs" {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !number_to_string.is_match(line) {
                continue;
            }
            let window_start = i.saturating_sub(WINDOW);
            let window = lines[window_start..=i].join("\n");
            if let Some(idx) = NUMBER_TO_STRING_ALLOWLIST
                .iter()
                .position(|a| rel.ends_with(a.file) && window.contains(a.marker))
            {
                used[idx] = true;
                continue;
            }
            violations.push(format!("{rel}:{}: {}", i + 1, line.trim()));
        }
    }

    for (allow, was_used) in NUMBER_TO_STRING_ALLOWLIST.iter().zip(used.iter()) {
        assert!(
            *was_used,
            "canonical_helpers.rs's NUMBER_TO_STRING_ALLOWLIST entry for {} ({:?}, reason: \
             {}) no longer matches anything in the source -- remove it or update its \
             marker",
            allow.file, allow.marker, allow.reason
        );
    }

    assert!(
        violations.is_empty(),
        "found serde_json::Number rendered via to_string()/Display outside pyjson.rs. This \
         preserves the JSON literal's own source spelling instead of CPython's repr(float) \
         (`1e-7` stays `\"1e-7\"`, not `\"1e-07\"`). Render through \
         crate::pyjson::python_float_repr (PORTING.md §3b) if this is genuinely rendering a \
         float for output, or add it to NUMBER_TO_STRING_ALLOWLIST in this file with a \
         one-line reason if it is only inspecting the literal's source text (e.g. \"does \
         this have a decimal point\") or is already known, recorded debt:\n{}",
        violations.join("\n")
    );
}

/// A function whose name contains `int_from_str` (this crate's recurring
/// name for a hand-written `int(str)`-grammar parser -- the round-6 finding
/// E-R6-1 write-up: "Three separate units re-implemented CPython's
/// `int(str)` grammar and each got the same detail wrong") defined outside
/// `pystr.rs`, whose body does not delegate to `crate::pystr`/`pystr::`.
/// PORTING.md §3b names `crate::pystr::int_from_str`/`int_from_str_radix`
/// the one canonical home for this grammar (whitespace set, `_`
/// separators, sign, Unicode `Nd` digits).
///
/// The body is approximated as the next 60 lines after the `fn` line (or
/// fewer, if a later line is an unindented `}` closing a top-level item
/// first) -- a text-window approximation rather than real brace-depth
/// parsing, deliberately: every function this pattern currently matches
/// (`pystr::int_from_str`/`int_from_str_radix`/`..._checked` themselves,
/// and the two delegating wrappers in `handles.rs`/`policy.rs`) is well
/// under 15 lines, so 60 lines of margin does not risk spilling into an
/// unrelated neighbouring function and picking up a `pystr::` reference
/// that does not actually belong to this one.
///
/// Verified to catch a reintroduction: temporarily replacing
/// `policy.rs`'s `python_int_from_str` body with a hand-rolled digit loop
/// (no `crate::pystr` reference at all) and re-running this test fails it,
/// naming `policy.rs`'s `fn python_int_from_str`; reverting restores a
/// pass.
#[test]
fn no_int_from_str_reimplementation_outside_pystr() {
    // A function declaration whose NAME, once the `fn`/parameter-list
    // wrapper is stripped, ends with `int_from_str` optionally followed by
    // `_radix` and/or `_checked` -- i.e. it names one of the FOUR actual
    // parser shapes `pystr.rs` itself exports (`int_from_str`,
    // `int_from_str_radix`, `int_from_str_checked`,
    // `int_from_str_radix_checked`), not merely a name that happens to
    // CONTAIN that substring somewhere -- a plain substring match also
    // caught test functions like `python_int_from_str_accepts_i64_min`,
    // which is not itself a parser and legitimately has no `pystr::`
    // reference of its own (it just calls the real parser function and
    // asserts on the result).
    let fn_decl = Regex::new(r"^\s*(?:pub\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(").unwrap();
    let target_name = Regex::new(r"int_from_str(_radix)?(_checked)?$").unwrap();
    let base = src_dir();
    let mut files = Vec::new();
    collect_rs_files(&base, &mut files);
    let mut violations = Vec::new();

    for path in &files {
        let rel = relative_slash(path, &base);
        if rel == "pystr.rs" {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let Some(caps) = fn_decl.captures(line) else {
                continue;
            };
            let name = &caps[1];
            if !target_name.is_match(name) {
                continue;
            }
            let end = (i + 60).min(lines.len());
            let mut body_end = end;
            for (j, body_line) in lines[i + 1..end].iter().enumerate() {
                if body_line == &"}" {
                    body_end = i + 1 + j + 1;
                    break;
                }
            }
            let body = lines[i..body_end].join("\n");
            if !(body.contains("crate::pystr") || body.contains("pystr::")) {
                violations.push(format!("{rel}:{}: {}", i + 1, line.trim()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "found a function named like an int(str)-grammar parser (contains \
         \"int_from_str\") outside pystr.rs whose body does not reference \
         crate::pystr::int_from_str/int_from_str_radix. This crate has already had THREE \
         independent, subtly-wrong local re-implementations of this grammar (round-6 \
         finding E-R6-1) -- delegate to the canonical crate::pystr helper (PORTING.md §3b) \
         instead of writing another one:\n{}",
        violations.join("\n")
    );
}

/// `Number::is_f64()` used, outside `pystr.rs`, to decide whether a JSON
/// number is Python `int`- or `float`-shaped immediately before rendering
/// it through `python_float_repr` -- the exact bug shape finding X-10
/// (equivalence review round 8) fixed in `crate::pystr::repr_value`'s own
/// `Number` arm (promoted from two byte-identical local copies, but the
/// promotion itself adopted the LESS correct of the two candidate
/// implementations). PORTING.md §3b names `crate::pystr::repr_number` the
/// one canonical home for this render; `Number::is_f64()` is the wrong
/// classification test for it specifically because, under this crate's
/// `arbitrary_precision` feature, `is_f64()` parses the literal and checks
/// `f64::is_finite()` itself, so it is already `false` for a literal that
/// overflows to a non-finite `f64` (`"1E400"`) -- branching on it sends
/// that token down the *integer* arm and echoes the raw literal text back
/// unchanged instead of CPython's `"inf"`/`"-inf"`. The correct test is the
/// raw literal's own TEXT (`crate::pyjson::is_float_literal`), independent
/// of whether the value turns out finite -- see `kms.rs`'s own
/// `python_number_str` (now `crate::pystr::repr_number` itself) doc history
/// for the worked explanation.
///
/// Detected as `.is_f64()` on a line, within a small forward window (the
/// flagged line plus up to 3 lines after it) of a `python_float_repr` call
/// -- narrow by design, same reasoning as this file's other checks: it
/// deliberately does NOT flag every `is_f64()` call in the crate (several
/// are legitimate for a DIFFERENT purpose than rendering, e.g. `audit.rs`'s
/// `clean` deciding whether to apply banker's rounding, or `handles.rs`'s
/// `python_int_coerce`/`v_matches_1` deciding a numeric-coercion branch --
/// none of those call `python_float_repr` at all), only the specific
/// "classify-then-render" idiom this finding is about.
///
/// Verified to catch a reintroduction: temporarily reverting `vault.rs`'s
/// `python_str_scalar` Number arm from `crate::pystr::repr_number(n)` back
/// to its pre-fix body (`if n.is_f64() { pyjson::python_float_repr(n.as_f64()
/// .unwrap_or(0.0)) } else { n.as_str().to_string() }`) and re-running this
/// test fails it, naming `vault.rs`'s `python_str_scalar`; reverting the
/// revert restores a pass. (Re-run this yourself with a scratch edit if you
/// doubt it -- do not trust this comment alone.)
#[test]
fn no_number_is_f64_repr_bypass_outside_pystr() {
    let is_f64_call = Regex::new(r"\.is_f64\(\)").unwrap();
    const WINDOW: usize = 3;
    let base = src_dir();
    let mut files = Vec::new();
    collect_rs_files(&base, &mut files);
    let mut violations = Vec::new();
    let mut used = vec![false; NUMBER_IS_F64_REPR_ALLOWLIST.len()];

    for path in &files {
        let rel = relative_slash(path, &base);
        if rel == "pystr.rs" {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !is_f64_call.is_match(line) {
                continue;
            }
            let window_end = (i + WINDOW).min(lines.len().saturating_sub(1));
            let window = lines[i..=window_end].join("\n");
            if !window.contains("python_float_repr") {
                continue;
            }
            if let Some(idx) = NUMBER_IS_F64_REPR_ALLOWLIST
                .iter()
                .position(|a| rel.ends_with(a.file) && window.contains(a.marker))
            {
                used[idx] = true;
                continue;
            }
            violations.push(format!("{rel}:{}: {}", i + 1, line.trim()));
        }
    }

    for (allow, was_used) in NUMBER_IS_F64_REPR_ALLOWLIST.iter().zip(used.iter()) {
        assert!(
            *was_used,
            "canonical_helpers.rs's NUMBER_IS_F64_REPR_ALLOWLIST entry for {} ({:?}, reason: \
             {}) no longer matches anything in the source -- remove it or update its marker",
            allow.file, allow.marker, allow.reason
        );
    }

    assert!(
        violations.is_empty(),
        "found Number::is_f64() used to classify a JSON number immediately before rendering \
         it through python_float_repr, outside pystr.rs. Under this crate's arbitrary_precision \
         feature, is_f64() is FALSE for a literal that overflows to a non-finite f64, so this \
         sends an overflowing literal down the wrong (integer) branch instead of rendering \
         CPython's inf/-inf (finding X-10, PORTING.md §3b). Route through the canonical \
         crate::pystr::repr_number instead, or add a one-line reason to \
         NUMBER_IS_F64_REPR_ALLOWLIST in this file if is_f64() here genuinely serves a \
         different purpose than classify-then-render (e.g. deciding whether to round, or a \
         numeric-coercion branch that never calls python_float_repr):\n{}",
        violations.join("\n")
    );
}
