//! Python `str` semantics shared across the crate: exact reimplementations of
//! CPython 3.12's `str.isprintable()`, `str.isspace()`, and `repr(str)`.
//!
//! `is_printable`/`is_space` are table-driven, matching CPython 3.12 exactly
//! per Unicode scalar value. The tables were generated from CPython 3.12's
//! own `unicodedata` module -- Unicode Character Database version
//! `unicodedata.unidata_version` = **"15.0.0"** (the version CPython 3.12
//! bundles, independent of the host OS's own Unicode data or of any Unicode
//! version Rust's standard library happens to use) -- by
//! `rust/tools/gen_pystr_tables.py`. That script's output is pasted verbatim
//! below as `NON_PRINTABLE_RANGES`/`SPACE_RANGES`: the tables are committed
//! source, not regenerated at build time. Re-run the script and repaste if
//! this crate ever moves to a newer `python3.12`/UCD version.
//!
//! `is_printable` is `false` exactly for Unicode categories Cc, Cf, Cs, Co,
//! Cn (every codepoint CPython 3.12 has not assigned a category to), Zl, Zp,
//! and Zs other than U+0020 -- i.e. `NON_PRINTABLE_RANGES` is the complement
//! of `str.isprintable() == True`, brute-forced over every codepoint in
//! `0..=0x10FFFF` except the UTF-16 surrogate range `0xD800..=0xDFFF` (Rust's
//! `char` cannot represent a surrogate, and no `str`/`&[u8]` input reaching
//! this crate can decode to one either, per `pyjson`'s and `str::from_utf8`'s
//! own rejection of unpaired surrogates).
//!
//! `is_space` is `str.isspace()` (Unicode `White_Space` plus the
//! bidirectional-class-`B`/`S` ASCII separators CPython also treats as
//! space), brute-forced the same way into `SPACE_RANGES`.
//!
//! See `oracle_is_printable_and_is_space_match_python_for_every_codepoint`
//! below for the full-enumeration differential test against `python3.12`.

/// True when `c` is printable per CPython 3.12 `str.isprintable()`.
pub fn is_printable(c: char) -> bool {
    !in_ranges(c as u32, NON_PRINTABLE_RANGES)
}

/// True when `c` is whitespace per CPython 3.12 `str.isspace()`.
pub fn is_space(c: char) -> bool {
    in_ranges(c as u32, SPACE_RANGES)
}

/// Binary search `cp` against a sorted, disjoint, inclusive `(start, end)`
/// range table.
fn in_ranges(cp: u32, ranges: &[(u32, u32)]) -> bool {
    ranges
        .binary_search_by(|&(start, end)| {
            if cp < start {
                std::cmp::Ordering::Greater
            } else if cp > end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Emulate Python's `repr()` for a `str`: pick the quote character the way
/// CPython does (`'` unless the string contains `'` and not `"`, in which
/// case `"`), then escape backslash, the chosen quote, `\n`/`\r`/`\t`, and
/// every character `str.isprintable()` excludes, as `\xNN`/`\uNNNN`/
/// `\UNNNNNNNN` (2/4/8 lowercase hex digits, matching CPython's width choice
/// by codepoint size). Every other character -- including non-ASCII letters,
/// symbols and emoji -- is copied through literally, matching Python.
pub fn repr_str(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        if c == quote || c == '\\' {
            out.push('\\');
            out.push(c);
        } else if c == '\n' {
            out.push_str("\\n");
        } else if c == '\r' {
            out.push_str("\\r");
        } else if c == '\t' {
            out.push_str("\\t");
        } else if is_printable(c) {
            out.push(c);
        } else {
            let cp = c as u32;
            if cp <= 0xFF {
                out.push_str(&format!("\\x{cp:02x}"));
            } else if cp <= 0xFFFF {
                out.push_str(&format!("\\u{cp:04x}"));
            } else {
                out.push_str(&format!("\\U{cp:08x}"));
            }
        }
    }
    out.push(quote);
    out
}

/// Emulate CPython's `repr()` for a `json.loads`-decoded value (PORTING.md
/// §3b: the ONE canonical home for this, reused rather than copied). Also
/// what CPython's `str()` falls back to for a `list`/`dict` (`str(x)` calls
/// `type(x).__str__`, and neither `list` nor `dict` overrides `__str__`, so
/// it is `list.__repr__`/`dict.__repr__`) -- callers coercing a JSON value
/// with `str(...)` should use this for the `Array`/`Object` cases and their
/// own scalar rendering (`None`/`True`/`False`/number-as-text) for the rest.
///
/// `[`/`]` and `{`/`}` delimiters, `", "` element separator, `": "` key
/// separator, and **insertion order** (never sorted -- `serde_json` here is
/// built with the `preserve_order` feature so a `Value::Object`'s iteration
/// order already matches the JSON document's own key order, which is what
/// CPython's `dict` preserves). `None`/`True`/`False` for `null`/booleans;
/// [`repr_str`] for strings (including dict keys, which `dict.__repr__`
/// reprs exactly like any other value); an integer JSON number renders its
/// digits verbatim (arbitrary precision, matching `int.__repr__`), a float
/// one through [`crate::pyjson::python_float_repr`] (matching
/// `float.__repr__`); each container element recurses through this same
/// function.
pub fn repr_value(value: &serde_json::Value) -> String {
    use serde_json::Value;
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::String(s) => repr_str(s),
        Value::Number(n) => repr_number(n),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(repr_value).collect();
            format!("[{}]", parts.join(", "))
        }
        Value::Object(map) => {
            let parts: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{}: {}", repr_str(k), repr_value(v)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
    }
}

/// `str()`/`repr()` of a single JSON number token -- CPython's `str()` and
/// `repr()` agree for both `int` and `float`, so this one function serves
/// both [`repr_value`]'s `Number` arm and any caller coercing a bare
/// `serde_json::Number` with Python `str()` semantics (e.g. `kms.rs`'s
/// `WrappedKey::from_dict` key_id coercion, `vault.rs`'s best-effort scalar
/// stringification).
///
/// X-10 (equivalence review, round 8): this used to be duplicated, and the
/// copy promoted into [`repr_value`] itself got the classification test
/// backwards. Classify by the raw literal text via
/// [`crate::pyjson::is_float_literal`] (has a `.`/`e`/`E`?), **not**
/// `Number::is_f64()`: under this crate's `arbitrary_precision` feature,
/// `is_f64()` parses the token and checks `f64::is_finite()` itself, so it
/// is already `false` for a literal that overflows to a non-finite `f64`
/// (`"1E400"`) -- branching on it sends that token down the *integer* arm
/// and echoes the raw literal text back unchanged (`"1e+400"`) instead of
/// what CPython actually prints. Measured against a live `python3.12`:
/// `repr(json.loads("1E400")) == "inf"`, `repr(json.loads("-1E400")) ==
/// "-inf"` (`oracle_repr_number_matches_python_for_overflowing_literal`,
/// below).
///
/// - No `.`/`e`/`E`: a JSON integer token, already Python's canonical `int`
///   decimal string (any size, thanks to `arbitrary_precision`).
/// - Otherwise a float token, parsed as `f64`: finite -> [`crate::pyjson::python_float_repr`]
///   (this also covers *underflow* to `0.0`/`-0.0`, still finite); non-finite
///   -> `"inf"`/`"-inf"` by sign, matching `str(float("1E400")) == "inf"` /
///   `str(float("-1E400")) == "-inf"`.
///
/// This crate's own [`crate::pyjson::loads`] rejects an overflowing float
/// literal outright (so the non-finite branch is unreachable for JSON this
/// crate itself decoded), but a `serde_json::Value` can still hold one if
/// built another way (a hand-crafted `Value` in a test, or a JSON document
/// written by something other than this crate) -- reachability doesn't
/// change what the *function* must return.
pub(crate) fn repr_number(n: &serde_json::Number) -> String {
    let raw = n.as_str();
    if !crate::pyjson::is_float_literal(raw) {
        return raw.to_string();
    }
    match raw.parse::<f64>() {
        Ok(f) if f.is_finite() => crate::pyjson::python_float_repr(f),
        Ok(f) if f.is_sign_negative() => "-inf".to_string(),
        Ok(_) => "inf".to_string(),
        // Unreachable for any token that actually matches the JSON number
        // grammar (the only kind of input a `serde_json::Number` can hold);
        // a plain fallback instead of `.expect(...)` so a hypothetical
        // malformed token degrades to inert text rather than panicking.
        Err(_) => raw.to_string(),
    }
}

// ---------------------------------------------------------------------------
// `int(str)` grammar (PORTING.md §3b coordinator ruling): the ONE canonical
// home for CPython's `int(str)`/`int(str, base)` semantics. Three separate
// work units each hand-rolled a local copy of this and got the same detail
// wrong (`int()` strips only ASCII `" \t\n\v\f\r"`, not `str.isspace()`'s
// much larger set, and it accepts every Unicode `Nd` digit, not just ASCII
// `0-9`) -- a local variant of this logic anywhere else in the crate is a
// review finding; extend the functions below instead.
// ---------------------------------------------------------------------------

/// True when `c` is one of the six ASCII whitespace characters CPython's
/// `int(str)` grammar strips from both ends of its ASCII-transformed input
/// (`Py_ISSPACE`, the C-locale `ctype` table `_PyLong_FromString` uses) --
/// **not** [`is_space`]/`str.isspace()`'s much larger Unicode set, which
/// also matches U+001C-U+001F, the ASCII "information separator" controls:
/// `int("\x1c5")` raises `ValueError` in CPython even though
/// `"\x1c5".isspace()` considers `"\x1c"` whitespace, because U+001C is
/// itself ASCII and so is never touched by the Unicode-to-ASCII transform
/// stage [`int_from_str_radix`] runs first (verified against a live
/// `python3.12` in `gateway.rs`'s test suite via the `Content-Length`/chunk-
/// size probes from equivalence-review finding F-R3-2).
pub fn is_int_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r')
}

/// The value (0-9) of a Unicode decimal digit (general category `Nd`), or
/// `None` for anything else -- including ASCII `'0'..='9'`, which is itself
/// the first of the 68 ten-codepoint blocks [`DIGIT_BLOCK_STARTS`] holds. In
/// Unicode 15.0.0 (the UCD version CPython 3.12 bundles, matching
/// [`is_space`]'s own table -- see the module doc comment) every `Nd`
/// codepoint falls into one of these blocks, each exactly 10 consecutive
/// codepoints with `unicodedata.decimal` values `0..=9` in that order
/// (`rust/tools/gen_pystr_tables.py`'s `digit_block_starts()` asserts this
/// shape while generating the table and would raise if a newer UCD version
/// ever broke it), so a codepoint's value is simply its offset from the
/// block it falls in. Pinned per-codepoint by
/// `oracle_digit_value_matches_python_for_every_codepoint` below.
pub(crate) fn unicode_decimal_digit(c: char) -> Option<u32> {
    let cp = c as u32;
    DIGIT_BLOCK_STARTS
        .binary_search_by(|&start| {
            if cp < start {
                std::cmp::Ordering::Greater
            } else if cp > start + 9 {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .ok()
        .map(|idx| cp - DIGIT_BLOCK_STARTS[idx])
}

/// `int(s)` (base 10): shorthand for [`int_from_str_radix`] with `base =
/// 10`.
pub fn int_from_str(s: &str) -> Option<i128> {
    int_from_str_radix(s, 10)
}

/// CPython `int(text)`'s accepted grammar as an arbitrary-precision,
/// canonical base-10 string. Unlike [`int_from_str`], this never saturates;
/// callers that persist the integer can pass the result to an
/// arbitrary-precision JSON number or [`num_bigint::BigInt`] without losing
/// digits.
pub fn int_from_str_decimal(s: &str) -> Option<String> {
    let (negative, digits) = parse_int_grammar(s, 10)?;
    let magnitude = digits.trim_start_matches('0');
    if magnitude.is_empty() {
        return Some("0".to_owned());
    }
    Some(if negative {
        format!("-{magnitude}")
    } else {
        magnitude.to_owned()
    })
}

/// [`int_from_str_decimal`] plus CPython 3.12's integer-string digit guard.
/// The limit counts decimal digits in the original input, including leading
/// zeroes and Unicode Nd digits, but excludes signs, whitespace and
/// underscores. `PYTHONINTMAXSTRDIGITS=0` disables it; valid overrides are
/// at least 640, and an absent override uses CPython's default 4300. Rust's
/// fallback for an invalid override remains a known limitation: CPython
/// rejects that environment setting during interpreter startup.
pub fn int_from_str_decimal_limited(s: &str) -> Option<String> {
    let value = int_from_str_decimal(s)?;
    let limit = match std::env::var("PYTHONINTMAXSTRDIGITS") {
        Ok(raw) => match raw.parse::<usize>() {
            Ok(0) => 0,
            Ok(value) if value >= 640 => value,
            _ => 4300,
        },
        Err(_) => 4300,
    };
    let digits = s
        .chars()
        .filter(|&c| unicode_decimal_digit(c).is_some())
        .count();
    (limit == 0 || digits <= limit).then_some(value)
}

/// CPython `int(s, base)` for `base` 10 or 16 (the only bases this crate's
/// callers need: `http.client`'s own `int(status)`, `int(length)`, and
/// `int(chunk_size_text, 16)`), reproducing the exact two-stage grammar
/// `PyLong_FromUnicodeObject` implements -- not just its ASCII fast path:
///
/// 1. `_PyUnicode_TransformDecimalAndSpaceToASCII`: an already-ASCII
///    character passes through unchanged; a non-ASCII Unicode decimal digit
///    ([`unicode_decimal_digit`]) becomes its ASCII digit; a non-ASCII
///    `Py_UNICODE_ISSPACE` character (identical to [`is_space`] /
///    `str.isspace()`) becomes an ASCII space; anything else non-ASCII is
///    left as-is, which then fails the ASCII grammar below, exactly like
///    Python. This transform runs regardless of `base` (`int("١٥", 16) ==
///    0x15 == 21`, not merely `int("15", 16)` after transform coincidence --
///    verified in the oracle fuzz test below).
/// 2. `_PyLong_FromString` on that now-mostly-ASCII string: strip
///    [`is_int_space`] from both ends (not [`is_space`] -- see its doc
///    comment for why U+001C-U+001F survive this strip), an optional
///    leading `+`/`-`, an optional case-insensitive `0x`/`0X` prefix when
///    `base == 16` (after which one leading `_` is permitted, as if the
///    prefix were itself a digit -- `int("0x_10", 16) == 16`), then one or
///    more digits with single `_` separators permitted strictly between two
///    digits (`"1_000"` ok; `"_1"`, `"1_"`, `"1__0"` are not).
///
/// Returns `None` for anything CPython's `int()` would raise `ValueError`
/// for. A magnitude too large for `i128` saturates (with sign) rather than
/// erroring: this is the right choice for every caller that only ever
/// compares the result against a small range or a `usize` byte count and
/// never round-trips it back out -- for a caller that *does* store or
/// re-serialize the parsed value itself (where a saturated sentinel would
/// be silently wrong rather than merely out of range), use
/// [`int_from_str_radix_checked`] instead, which returns `None` at that same
/// boundary rather than substituting `i128::MAX`/`i128::MIN`.
///
/// See `oracle_digit_value_matches_python_for_every_codepoint` (pins
/// [`unicode_decimal_digit`] against every codepoint) and
/// `oracle_int_from_str_matches_python_fuzz` (a random/adversarial string
/// fuzz against a live `python3.12`) below, plus the `Content-Length`/chunk-
/// size/status oracle cases in `gateway.rs`'s test suite (finding F-R3-2).
pub fn int_from_str_radix(s: &str, base: u32) -> Option<i128> {
    let (neg, digits) = parse_int_grammar(s, base)?;
    Some(magnitude_to_signed(&digits, base, neg).unwrap_or(if neg { i128::MIN } else { i128::MAX }))
}

/// `int(s)` (base 10), like [`int_from_str`], but `None` (not a saturated
/// `i128::MAX`/`i128::MIN`) for a magnitude that does not fit `i128` -- see
/// [`int_from_str_radix_checked`].
pub fn int_from_str_checked(s: &str) -> Option<i128> {
    int_from_str_radix_checked(s, 10)
}

/// Like [`int_from_str_radix`] (same grammar, same doc comment), but `None`
/// instead of a saturated `i128::MAX`/`i128::MIN` when the magnitude does
/// not fit `i128` -- for a caller (like `team::commit`'s `Hlc`/`Commit`
/// numeric fields, which store and re-serialize the parsed `i128` itself
/// rather than merely bounds-checking it) where CPython's own arbitrary
/// precision has no equivalent "clamp to the nearest representable value"
/// behaviour at all: Python would keep going, an `i128`-typed field cannot,
/// and silently substituting the boundary value would be a different (and
/// worse) wrong answer than failing closed the same way this port already
/// does for every other over-wide numeral (`rust/DEVIATIONS.md`).
pub fn int_from_str_radix_checked(s: &str, base: u32) -> Option<i128> {
    let (neg, digits) = parse_int_grammar(s, base)?;
    magnitude_to_signed(&digits, base, neg)
}

/// Parses `digits` (an unsigned numeral, `base` 10 or 16, already validated
/// by [`parse_int_grammar`]) and applies `neg`, correctly across the full
/// `i128` range *including its own asymmetric boundary*: `i128::MIN`'s
/// magnitude is `2^127`, one past `i128::MAX` (`2^127 - 1`), so
/// `i128::from_str_radix` on the bare unsigned digit string can never
/// represent it at all (it parses into a *signed* `i128`, whose positive
/// range tops out at `i128::MAX`) -- the same "same-width unsigned-then-
/// negate step rejects the width's own MIN" shape as finding E-R4-1
/// (`vault.rs`, `i64::MIN`), just one level up. Parsing into `u128` first
/// (which comfortably holds `2^127`) and only *then* negating fixes it:
/// `None` here means the magnitude does not fit `i128` at all, for either
/// sign.
fn magnitude_to_signed(digits: &str, base: u32, neg: bool) -> Option<i128> {
    let magnitude: u128 = u128::from_str_radix(digits, base).ok()?;
    if neg {
        if magnitude == i128::MIN.unsigned_abs() {
            Some(i128::MIN)
        } else {
            i128::try_from(magnitude).ok().map(|m| -m)
        }
    } else {
        i128::try_from(magnitude).ok()
    }
}

/// Shared grammar core for [`int_from_str_radix`]/[`int_from_str_radix_checked`]:
/// everything CPython's `int(s, base)` grammar validates *except* the final
/// magnitude parse (which the two callers handle differently -- saturating
/// vs. `None` -- on overflow). Returns `(negative, unsigned_ascii_digits)`
/// with all `_` separators already removed (validated, not merely
/// stripped), ready for [`magnitude_to_signed`].
fn parse_int_grammar(s: &str, base: u32) -> Option<(bool, String)> {
    debug_assert!(base == 10 || base == 16, "only base 10/16 are needed");
    // Stage 1: `_PyUnicode_TransformDecimalAndSpaceToASCII`.
    let mut ascii = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii() {
            ascii.push(c);
        } else if let Some(d) = unicode_decimal_digit(c) {
            ascii.push(char::from_digit(d, 10).expect("0..=9 always converts"));
        } else if is_space(c) {
            ascii.push(' ');
        } else {
            ascii.push(c);
        }
    }
    // Stage 2: `_PyLong_FromString`'s ASCII grammar.
    let trimmed = ascii.trim_matches(is_int_space);
    if trimmed.is_empty() {
        return None;
    }
    let (neg, rest) = match trimmed.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let (rest, mut prev_was_digit) = if base == 16 {
        match rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
            Some(r) => (r, true),
            None => (rest, false),
        }
    } else {
        (rest, false)
    };
    if rest.is_empty() {
        return None;
    }
    let chars: Vec<char> = rest.chars().collect();
    let mut digits = String::with_capacity(chars.len());
    for (i, &c) in chars.iter().enumerate() {
        if c == '_' {
            let next_is_digit = chars.get(i + 1).is_some_and(|c| c.is_digit(base));
            if !prev_was_digit || !next_is_digit {
                return None;
            }
            prev_was_digit = false;
            continue;
        }
        c.to_digit(base)?;
        digits.push(c);
        prev_was_digit = true;
    }
    if digits.is_empty() {
        return None;
    }
    Some((neg, digits))
}

// ---------------------------------------------------------------------------
// Generated tables -- see rust/tools/gen_pystr_tables.py. Do not hand-edit.
// ---------------------------------------------------------------------------

pub(crate) static NON_PRINTABLE_RANGES: &[(u32, u32)] = &[
    (0x0, 0x1F),
    (0x7F, 0xA0),
    (0xAD, 0xAD),
    (0x378, 0x379),
    (0x380, 0x383),
    (0x38B, 0x38B),
    (0x38D, 0x38D),
    (0x3A2, 0x3A2),
    (0x530, 0x530),
    (0x557, 0x558),
    (0x58B, 0x58C),
    (0x590, 0x590),
    (0x5C8, 0x5CF),
    (0x5EB, 0x5EE),
    (0x5F5, 0x605),
    (0x61C, 0x61C),
    (0x6DD, 0x6DD),
    (0x70E, 0x70F),
    (0x74B, 0x74C),
    (0x7B2, 0x7BF),
    (0x7FB, 0x7FC),
    (0x82E, 0x82F),
    (0x83F, 0x83F),
    (0x85C, 0x85D),
    (0x85F, 0x85F),
    (0x86B, 0x86F),
    (0x88F, 0x897),
    (0x8E2, 0x8E2),
    (0x984, 0x984),
    (0x98D, 0x98E),
    (0x991, 0x992),
    (0x9A9, 0x9A9),
    (0x9B1, 0x9B1),
    (0x9B3, 0x9B5),
    (0x9BA, 0x9BB),
    (0x9C5, 0x9C6),
    (0x9C9, 0x9CA),
    (0x9CF, 0x9D6),
    (0x9D8, 0x9DB),
    (0x9DE, 0x9DE),
    (0x9E4, 0x9E5),
    (0x9FF, 0xA00),
    (0xA04, 0xA04),
    (0xA0B, 0xA0E),
    (0xA11, 0xA12),
    (0xA29, 0xA29),
    (0xA31, 0xA31),
    (0xA34, 0xA34),
    (0xA37, 0xA37),
    (0xA3A, 0xA3B),
    (0xA3D, 0xA3D),
    (0xA43, 0xA46),
    (0xA49, 0xA4A),
    (0xA4E, 0xA50),
    (0xA52, 0xA58),
    (0xA5D, 0xA5D),
    (0xA5F, 0xA65),
    (0xA77, 0xA80),
    (0xA84, 0xA84),
    (0xA8E, 0xA8E),
    (0xA92, 0xA92),
    (0xAA9, 0xAA9),
    (0xAB1, 0xAB1),
    (0xAB4, 0xAB4),
    (0xABA, 0xABB),
    (0xAC6, 0xAC6),
    (0xACA, 0xACA),
    (0xACE, 0xACF),
    (0xAD1, 0xADF),
    (0xAE4, 0xAE5),
    (0xAF2, 0xAF8),
    (0xB00, 0xB00),
    (0xB04, 0xB04),
    (0xB0D, 0xB0E),
    (0xB11, 0xB12),
    (0xB29, 0xB29),
    (0xB31, 0xB31),
    (0xB34, 0xB34),
    (0xB3A, 0xB3B),
    (0xB45, 0xB46),
    (0xB49, 0xB4A),
    (0xB4E, 0xB54),
    (0xB58, 0xB5B),
    (0xB5E, 0xB5E),
    (0xB64, 0xB65),
    (0xB78, 0xB81),
    (0xB84, 0xB84),
    (0xB8B, 0xB8D),
    (0xB91, 0xB91),
    (0xB96, 0xB98),
    (0xB9B, 0xB9B),
    (0xB9D, 0xB9D),
    (0xBA0, 0xBA2),
    (0xBA5, 0xBA7),
    (0xBAB, 0xBAD),
    (0xBBA, 0xBBD),
    (0xBC3, 0xBC5),
    (0xBC9, 0xBC9),
    (0xBCE, 0xBCF),
    (0xBD1, 0xBD6),
    (0xBD8, 0xBE5),
    (0xBFB, 0xBFF),
    (0xC0D, 0xC0D),
    (0xC11, 0xC11),
    (0xC29, 0xC29),
    (0xC3A, 0xC3B),
    (0xC45, 0xC45),
    (0xC49, 0xC49),
    (0xC4E, 0xC54),
    (0xC57, 0xC57),
    (0xC5B, 0xC5C),
    (0xC5E, 0xC5F),
    (0xC64, 0xC65),
    (0xC70, 0xC76),
    (0xC8D, 0xC8D),
    (0xC91, 0xC91),
    (0xCA9, 0xCA9),
    (0xCB4, 0xCB4),
    (0xCBA, 0xCBB),
    (0xCC5, 0xCC5),
    (0xCC9, 0xCC9),
    (0xCCE, 0xCD4),
    (0xCD7, 0xCDC),
    (0xCDF, 0xCDF),
    (0xCE4, 0xCE5),
    (0xCF0, 0xCF0),
    (0xCF4, 0xCFF),
    (0xD0D, 0xD0D),
    (0xD11, 0xD11),
    (0xD45, 0xD45),
    (0xD49, 0xD49),
    (0xD50, 0xD53),
    (0xD64, 0xD65),
    (0xD80, 0xD80),
    (0xD84, 0xD84),
    (0xD97, 0xD99),
    (0xDB2, 0xDB2),
    (0xDBC, 0xDBC),
    (0xDBE, 0xDBF),
    (0xDC7, 0xDC9),
    (0xDCB, 0xDCE),
    (0xDD5, 0xDD5),
    (0xDD7, 0xDD7),
    (0xDE0, 0xDE5),
    (0xDF0, 0xDF1),
    (0xDF5, 0xE00),
    (0xE3B, 0xE3E),
    (0xE5C, 0xE80),
    (0xE83, 0xE83),
    (0xE85, 0xE85),
    (0xE8B, 0xE8B),
    (0xEA4, 0xEA4),
    (0xEA6, 0xEA6),
    (0xEBE, 0xEBF),
    (0xEC5, 0xEC5),
    (0xEC7, 0xEC7),
    (0xECF, 0xECF),
    (0xEDA, 0xEDB),
    (0xEE0, 0xEFF),
    (0xF48, 0xF48),
    (0xF6D, 0xF70),
    (0xF98, 0xF98),
    (0xFBD, 0xFBD),
    (0xFCD, 0xFCD),
    (0xFDB, 0xFFF),
    (0x10C6, 0x10C6),
    (0x10C8, 0x10CC),
    (0x10CE, 0x10CF),
    (0x1249, 0x1249),
    (0x124E, 0x124F),
    (0x1257, 0x1257),
    (0x1259, 0x1259),
    (0x125E, 0x125F),
    (0x1289, 0x1289),
    (0x128E, 0x128F),
    (0x12B1, 0x12B1),
    (0x12B6, 0x12B7),
    (0x12BF, 0x12BF),
    (0x12C1, 0x12C1),
    (0x12C6, 0x12C7),
    (0x12D7, 0x12D7),
    (0x1311, 0x1311),
    (0x1316, 0x1317),
    (0x135B, 0x135C),
    (0x137D, 0x137F),
    (0x139A, 0x139F),
    (0x13F6, 0x13F7),
    (0x13FE, 0x13FF),
    (0x1680, 0x1680),
    (0x169D, 0x169F),
    (0x16F9, 0x16FF),
    (0x1716, 0x171E),
    (0x1737, 0x173F),
    (0x1754, 0x175F),
    (0x176D, 0x176D),
    (0x1771, 0x1771),
    (0x1774, 0x177F),
    (0x17DE, 0x17DF),
    (0x17EA, 0x17EF),
    (0x17FA, 0x17FF),
    (0x180E, 0x180E),
    (0x181A, 0x181F),
    (0x1879, 0x187F),
    (0x18AB, 0x18AF),
    (0x18F6, 0x18FF),
    (0x191F, 0x191F),
    (0x192C, 0x192F),
    (0x193C, 0x193F),
    (0x1941, 0x1943),
    (0x196E, 0x196F),
    (0x1975, 0x197F),
    (0x19AC, 0x19AF),
    (0x19CA, 0x19CF),
    (0x19DB, 0x19DD),
    (0x1A1C, 0x1A1D),
    (0x1A5F, 0x1A5F),
    (0x1A7D, 0x1A7E),
    (0x1A8A, 0x1A8F),
    (0x1A9A, 0x1A9F),
    (0x1AAE, 0x1AAF),
    (0x1ACF, 0x1AFF),
    (0x1B4D, 0x1B4F),
    (0x1B7F, 0x1B7F),
    (0x1BF4, 0x1BFB),
    (0x1C38, 0x1C3A),
    (0x1C4A, 0x1C4C),
    (0x1C89, 0x1C8F),
    (0x1CBB, 0x1CBC),
    (0x1CC8, 0x1CCF),
    (0x1CFB, 0x1CFF),
    (0x1F16, 0x1F17),
    (0x1F1E, 0x1F1F),
    (0x1F46, 0x1F47),
    (0x1F4E, 0x1F4F),
    (0x1F58, 0x1F58),
    (0x1F5A, 0x1F5A),
    (0x1F5C, 0x1F5C),
    (0x1F5E, 0x1F5E),
    (0x1F7E, 0x1F7F),
    (0x1FB5, 0x1FB5),
    (0x1FC5, 0x1FC5),
    (0x1FD4, 0x1FD5),
    (0x1FDC, 0x1FDC),
    (0x1FF0, 0x1FF1),
    (0x1FF5, 0x1FF5),
    (0x1FFF, 0x200F),
    (0x2028, 0x202F),
    (0x205F, 0x206F),
    (0x2072, 0x2073),
    (0x208F, 0x208F),
    (0x209D, 0x209F),
    (0x20C1, 0x20CF),
    (0x20F1, 0x20FF),
    (0x218C, 0x218F),
    (0x2427, 0x243F),
    (0x244B, 0x245F),
    (0x2B74, 0x2B75),
    (0x2B96, 0x2B96),
    (0x2CF4, 0x2CF8),
    (0x2D26, 0x2D26),
    (0x2D28, 0x2D2C),
    (0x2D2E, 0x2D2F),
    (0x2D68, 0x2D6E),
    (0x2D71, 0x2D7E),
    (0x2D97, 0x2D9F),
    (0x2DA7, 0x2DA7),
    (0x2DAF, 0x2DAF),
    (0x2DB7, 0x2DB7),
    (0x2DBF, 0x2DBF),
    (0x2DC7, 0x2DC7),
    (0x2DCF, 0x2DCF),
    (0x2DD7, 0x2DD7),
    (0x2DDF, 0x2DDF),
    (0x2E5E, 0x2E7F),
    (0x2E9A, 0x2E9A),
    (0x2EF4, 0x2EFF),
    (0x2FD6, 0x2FEF),
    (0x2FFC, 0x3000),
    (0x3040, 0x3040),
    (0x3097, 0x3098),
    (0x3100, 0x3104),
    (0x3130, 0x3130),
    (0x318F, 0x318F),
    (0x31E4, 0x31EF),
    (0x321F, 0x321F),
    (0xA48D, 0xA48F),
    (0xA4C7, 0xA4CF),
    (0xA62C, 0xA63F),
    (0xA6F8, 0xA6FF),
    (0xA7CB, 0xA7CF),
    (0xA7D2, 0xA7D2),
    (0xA7D4, 0xA7D4),
    (0xA7DA, 0xA7F1),
    (0xA82D, 0xA82F),
    (0xA83A, 0xA83F),
    (0xA878, 0xA87F),
    (0xA8C6, 0xA8CD),
    (0xA8DA, 0xA8DF),
    (0xA954, 0xA95E),
    (0xA97D, 0xA97F),
    (0xA9CE, 0xA9CE),
    (0xA9DA, 0xA9DD),
    (0xA9FF, 0xA9FF),
    (0xAA37, 0xAA3F),
    (0xAA4E, 0xAA4F),
    (0xAA5A, 0xAA5B),
    (0xAAC3, 0xAADA),
    (0xAAF7, 0xAB00),
    (0xAB07, 0xAB08),
    (0xAB0F, 0xAB10),
    (0xAB17, 0xAB1F),
    (0xAB27, 0xAB27),
    (0xAB2F, 0xAB2F),
    (0xAB6C, 0xAB6F),
    (0xABEE, 0xABEF),
    (0xABFA, 0xABFF),
    (0xD7A4, 0xD7AF),
    (0xD7C7, 0xD7CA),
    (0xD7FC, 0xD7FF),
    (0xE000, 0xF8FF),
    (0xFA6E, 0xFA6F),
    (0xFADA, 0xFAFF),
    (0xFB07, 0xFB12),
    (0xFB18, 0xFB1C),
    (0xFB37, 0xFB37),
    (0xFB3D, 0xFB3D),
    (0xFB3F, 0xFB3F),
    (0xFB42, 0xFB42),
    (0xFB45, 0xFB45),
    (0xFBC3, 0xFBD2),
    (0xFD90, 0xFD91),
    (0xFDC8, 0xFDCE),
    (0xFDD0, 0xFDEF),
    (0xFE1A, 0xFE1F),
    (0xFE53, 0xFE53),
    (0xFE67, 0xFE67),
    (0xFE6C, 0xFE6F),
    (0xFE75, 0xFE75),
    (0xFEFD, 0xFF00),
    (0xFFBF, 0xFFC1),
    (0xFFC8, 0xFFC9),
    (0xFFD0, 0xFFD1),
    (0xFFD8, 0xFFD9),
    (0xFFDD, 0xFFDF),
    (0xFFE7, 0xFFE7),
    (0xFFEF, 0xFFFB),
    (0xFFFE, 0xFFFF),
    (0x1000C, 0x1000C),
    (0x10027, 0x10027),
    (0x1003B, 0x1003B),
    (0x1003E, 0x1003E),
    (0x1004E, 0x1004F),
    (0x1005E, 0x1007F),
    (0x100FB, 0x100FF),
    (0x10103, 0x10106),
    (0x10134, 0x10136),
    (0x1018F, 0x1018F),
    (0x1019D, 0x1019F),
    (0x101A1, 0x101CF),
    (0x101FE, 0x1027F),
    (0x1029D, 0x1029F),
    (0x102D1, 0x102DF),
    (0x102FC, 0x102FF),
    (0x10324, 0x1032C),
    (0x1034B, 0x1034F),
    (0x1037B, 0x1037F),
    (0x1039E, 0x1039E),
    (0x103C4, 0x103C7),
    (0x103D6, 0x103FF),
    (0x1049E, 0x1049F),
    (0x104AA, 0x104AF),
    (0x104D4, 0x104D7),
    (0x104FC, 0x104FF),
    (0x10528, 0x1052F),
    (0x10564, 0x1056E),
    (0x1057B, 0x1057B),
    (0x1058B, 0x1058B),
    (0x10593, 0x10593),
    (0x10596, 0x10596),
    (0x105A2, 0x105A2),
    (0x105B2, 0x105B2),
    (0x105BA, 0x105BA),
    (0x105BD, 0x105FF),
    (0x10737, 0x1073F),
    (0x10756, 0x1075F),
    (0x10768, 0x1077F),
    (0x10786, 0x10786),
    (0x107B1, 0x107B1),
    (0x107BB, 0x107FF),
    (0x10806, 0x10807),
    (0x10809, 0x10809),
    (0x10836, 0x10836),
    (0x10839, 0x1083B),
    (0x1083D, 0x1083E),
    (0x10856, 0x10856),
    (0x1089F, 0x108A6),
    (0x108B0, 0x108DF),
    (0x108F3, 0x108F3),
    (0x108F6, 0x108FA),
    (0x1091C, 0x1091E),
    (0x1093A, 0x1093E),
    (0x10940, 0x1097F),
    (0x109B8, 0x109BB),
    (0x109D0, 0x109D1),
    (0x10A04, 0x10A04),
    (0x10A07, 0x10A0B),
    (0x10A14, 0x10A14),
    (0x10A18, 0x10A18),
    (0x10A36, 0x10A37),
    (0x10A3B, 0x10A3E),
    (0x10A49, 0x10A4F),
    (0x10A59, 0x10A5F),
    (0x10AA0, 0x10ABF),
    (0x10AE7, 0x10AEA),
    (0x10AF7, 0x10AFF),
    (0x10B36, 0x10B38),
    (0x10B56, 0x10B57),
    (0x10B73, 0x10B77),
    (0x10B92, 0x10B98),
    (0x10B9D, 0x10BA8),
    (0x10BB0, 0x10BFF),
    (0x10C49, 0x10C7F),
    (0x10CB3, 0x10CBF),
    (0x10CF3, 0x10CF9),
    (0x10D28, 0x10D2F),
    (0x10D3A, 0x10E5F),
    (0x10E7F, 0x10E7F),
    (0x10EAA, 0x10EAA),
    (0x10EAE, 0x10EAF),
    (0x10EB2, 0x10EFC),
    (0x10F28, 0x10F2F),
    (0x10F5A, 0x10F6F),
    (0x10F8A, 0x10FAF),
    (0x10FCC, 0x10FDF),
    (0x10FF7, 0x10FFF),
    (0x1104E, 0x11051),
    (0x11076, 0x1107E),
    (0x110BD, 0x110BD),
    (0x110C3, 0x110CF),
    (0x110E9, 0x110EF),
    (0x110FA, 0x110FF),
    (0x11135, 0x11135),
    (0x11148, 0x1114F),
    (0x11177, 0x1117F),
    (0x111E0, 0x111E0),
    (0x111F5, 0x111FF),
    (0x11212, 0x11212),
    (0x11242, 0x1127F),
    (0x11287, 0x11287),
    (0x11289, 0x11289),
    (0x1128E, 0x1128E),
    (0x1129E, 0x1129E),
    (0x112AA, 0x112AF),
    (0x112EB, 0x112EF),
    (0x112FA, 0x112FF),
    (0x11304, 0x11304),
    (0x1130D, 0x1130E),
    (0x11311, 0x11312),
    (0x11329, 0x11329),
    (0x11331, 0x11331),
    (0x11334, 0x11334),
    (0x1133A, 0x1133A),
    (0x11345, 0x11346),
    (0x11349, 0x1134A),
    (0x1134E, 0x1134F),
    (0x11351, 0x11356),
    (0x11358, 0x1135C),
    (0x11364, 0x11365),
    (0x1136D, 0x1136F),
    (0x11375, 0x113FF),
    (0x1145C, 0x1145C),
    (0x11462, 0x1147F),
    (0x114C8, 0x114CF),
    (0x114DA, 0x1157F),
    (0x115B6, 0x115B7),
    (0x115DE, 0x115FF),
    (0x11645, 0x1164F),
    (0x1165A, 0x1165F),
    (0x1166D, 0x1167F),
    (0x116BA, 0x116BF),
    (0x116CA, 0x116FF),
    (0x1171B, 0x1171C),
    (0x1172C, 0x1172F),
    (0x11747, 0x117FF),
    (0x1183C, 0x1189F),
    (0x118F3, 0x118FE),
    (0x11907, 0x11908),
    (0x1190A, 0x1190B),
    (0x11914, 0x11914),
    (0x11917, 0x11917),
    (0x11936, 0x11936),
    (0x11939, 0x1193A),
    (0x11947, 0x1194F),
    (0x1195A, 0x1199F),
    (0x119A8, 0x119A9),
    (0x119D8, 0x119D9),
    (0x119E5, 0x119FF),
    (0x11A48, 0x11A4F),
    (0x11AA3, 0x11AAF),
    (0x11AF9, 0x11AFF),
    (0x11B0A, 0x11BFF),
    (0x11C09, 0x11C09),
    (0x11C37, 0x11C37),
    (0x11C46, 0x11C4F),
    (0x11C6D, 0x11C6F),
    (0x11C90, 0x11C91),
    (0x11CA8, 0x11CA8),
    (0x11CB7, 0x11CFF),
    (0x11D07, 0x11D07),
    (0x11D0A, 0x11D0A),
    (0x11D37, 0x11D39),
    (0x11D3B, 0x11D3B),
    (0x11D3E, 0x11D3E),
    (0x11D48, 0x11D4F),
    (0x11D5A, 0x11D5F),
    (0x11D66, 0x11D66),
    (0x11D69, 0x11D69),
    (0x11D8F, 0x11D8F),
    (0x11D92, 0x11D92),
    (0x11D99, 0x11D9F),
    (0x11DAA, 0x11EDF),
    (0x11EF9, 0x11EFF),
    (0x11F11, 0x11F11),
    (0x11F3B, 0x11F3D),
    (0x11F5A, 0x11FAF),
    (0x11FB1, 0x11FBF),
    (0x11FF2, 0x11FFE),
    (0x1239A, 0x123FF),
    (0x1246F, 0x1246F),
    (0x12475, 0x1247F),
    (0x12544, 0x12F8F),
    (0x12FF3, 0x12FFF),
    (0x13430, 0x1343F),
    (0x13456, 0x143FF),
    (0x14647, 0x167FF),
    (0x16A39, 0x16A3F),
    (0x16A5F, 0x16A5F),
    (0x16A6A, 0x16A6D),
    (0x16ABF, 0x16ABF),
    (0x16ACA, 0x16ACF),
    (0x16AEE, 0x16AEF),
    (0x16AF6, 0x16AFF),
    (0x16B46, 0x16B4F),
    (0x16B5A, 0x16B5A),
    (0x16B62, 0x16B62),
    (0x16B78, 0x16B7C),
    (0x16B90, 0x16E3F),
    (0x16E9B, 0x16EFF),
    (0x16F4B, 0x16F4E),
    (0x16F88, 0x16F8E),
    (0x16FA0, 0x16FDF),
    (0x16FE5, 0x16FEF),
    (0x16FF2, 0x16FFF),
    (0x187F8, 0x187FF),
    (0x18CD6, 0x18CFF),
    (0x18D09, 0x1AFEF),
    (0x1AFF4, 0x1AFF4),
    (0x1AFFC, 0x1AFFC),
    (0x1AFFF, 0x1AFFF),
    (0x1B123, 0x1B131),
    (0x1B133, 0x1B14F),
    (0x1B153, 0x1B154),
    (0x1B156, 0x1B163),
    (0x1B168, 0x1B16F),
    (0x1B2FC, 0x1BBFF),
    (0x1BC6B, 0x1BC6F),
    (0x1BC7D, 0x1BC7F),
    (0x1BC89, 0x1BC8F),
    (0x1BC9A, 0x1BC9B),
    (0x1BCA0, 0x1CEFF),
    (0x1CF2E, 0x1CF2F),
    (0x1CF47, 0x1CF4F),
    (0x1CFC4, 0x1CFFF),
    (0x1D0F6, 0x1D0FF),
    (0x1D127, 0x1D128),
    (0x1D173, 0x1D17A),
    (0x1D1EB, 0x1D1FF),
    (0x1D246, 0x1D2BF),
    (0x1D2D4, 0x1D2DF),
    (0x1D2F4, 0x1D2FF),
    (0x1D357, 0x1D35F),
    (0x1D379, 0x1D3FF),
    (0x1D455, 0x1D455),
    (0x1D49D, 0x1D49D),
    (0x1D4A0, 0x1D4A1),
    (0x1D4A3, 0x1D4A4),
    (0x1D4A7, 0x1D4A8),
    (0x1D4AD, 0x1D4AD),
    (0x1D4BA, 0x1D4BA),
    (0x1D4BC, 0x1D4BC),
    (0x1D4C4, 0x1D4C4),
    (0x1D506, 0x1D506),
    (0x1D50B, 0x1D50C),
    (0x1D515, 0x1D515),
    (0x1D51D, 0x1D51D),
    (0x1D53A, 0x1D53A),
    (0x1D53F, 0x1D53F),
    (0x1D545, 0x1D545),
    (0x1D547, 0x1D549),
    (0x1D551, 0x1D551),
    (0x1D6A6, 0x1D6A7),
    (0x1D7CC, 0x1D7CD),
    (0x1DA8C, 0x1DA9A),
    (0x1DAA0, 0x1DAA0),
    (0x1DAB0, 0x1DEFF),
    (0x1DF1F, 0x1DF24),
    (0x1DF2B, 0x1DFFF),
    (0x1E007, 0x1E007),
    (0x1E019, 0x1E01A),
    (0x1E022, 0x1E022),
    (0x1E025, 0x1E025),
    (0x1E02B, 0x1E02F),
    (0x1E06E, 0x1E08E),
    (0x1E090, 0x1E0FF),
    (0x1E12D, 0x1E12F),
    (0x1E13E, 0x1E13F),
    (0x1E14A, 0x1E14D),
    (0x1E150, 0x1E28F),
    (0x1E2AF, 0x1E2BF),
    (0x1E2FA, 0x1E2FE),
    (0x1E300, 0x1E4CF),
    (0x1E4FA, 0x1E7DF),
    (0x1E7E7, 0x1E7E7),
    (0x1E7EC, 0x1E7EC),
    (0x1E7EF, 0x1E7EF),
    (0x1E7FF, 0x1E7FF),
    (0x1E8C5, 0x1E8C6),
    (0x1E8D7, 0x1E8FF),
    (0x1E94C, 0x1E94F),
    (0x1E95A, 0x1E95D),
    (0x1E960, 0x1EC70),
    (0x1ECB5, 0x1ED00),
    (0x1ED3E, 0x1EDFF),
    (0x1EE04, 0x1EE04),
    (0x1EE20, 0x1EE20),
    (0x1EE23, 0x1EE23),
    (0x1EE25, 0x1EE26),
    (0x1EE28, 0x1EE28),
    (0x1EE33, 0x1EE33),
    (0x1EE38, 0x1EE38),
    (0x1EE3A, 0x1EE3A),
    (0x1EE3C, 0x1EE41),
    (0x1EE43, 0x1EE46),
    (0x1EE48, 0x1EE48),
    (0x1EE4A, 0x1EE4A),
    (0x1EE4C, 0x1EE4C),
    (0x1EE50, 0x1EE50),
    (0x1EE53, 0x1EE53),
    (0x1EE55, 0x1EE56),
    (0x1EE58, 0x1EE58),
    (0x1EE5A, 0x1EE5A),
    (0x1EE5C, 0x1EE5C),
    (0x1EE5E, 0x1EE5E),
    (0x1EE60, 0x1EE60),
    (0x1EE63, 0x1EE63),
    (0x1EE65, 0x1EE66),
    (0x1EE6B, 0x1EE6B),
    (0x1EE73, 0x1EE73),
    (0x1EE78, 0x1EE78),
    (0x1EE7D, 0x1EE7D),
    (0x1EE7F, 0x1EE7F),
    (0x1EE8A, 0x1EE8A),
    (0x1EE9C, 0x1EEA0),
    (0x1EEA4, 0x1EEA4),
    (0x1EEAA, 0x1EEAA),
    (0x1EEBC, 0x1EEEF),
    (0x1EEF2, 0x1EFFF),
    (0x1F02C, 0x1F02F),
    (0x1F094, 0x1F09F),
    (0x1F0AF, 0x1F0B0),
    (0x1F0C0, 0x1F0C0),
    (0x1F0D0, 0x1F0D0),
    (0x1F0F6, 0x1F0FF),
    (0x1F1AE, 0x1F1E5),
    (0x1F203, 0x1F20F),
    (0x1F23C, 0x1F23F),
    (0x1F249, 0x1F24F),
    (0x1F252, 0x1F25F),
    (0x1F266, 0x1F2FF),
    (0x1F6D8, 0x1F6DB),
    (0x1F6ED, 0x1F6EF),
    (0x1F6FD, 0x1F6FF),
    (0x1F777, 0x1F77A),
    (0x1F7DA, 0x1F7DF),
    (0x1F7EC, 0x1F7EF),
    (0x1F7F1, 0x1F7FF),
    (0x1F80C, 0x1F80F),
    (0x1F848, 0x1F84F),
    (0x1F85A, 0x1F85F),
    (0x1F888, 0x1F88F),
    (0x1F8AE, 0x1F8AF),
    (0x1F8B2, 0x1F8FF),
    (0x1FA54, 0x1FA5F),
    (0x1FA6E, 0x1FA6F),
    (0x1FA7D, 0x1FA7F),
    (0x1FA89, 0x1FA8F),
    (0x1FABE, 0x1FABE),
    (0x1FAC6, 0x1FACD),
    (0x1FADC, 0x1FADF),
    (0x1FAE9, 0x1FAEF),
    (0x1FAF9, 0x1FAFF),
    (0x1FB93, 0x1FB93),
    (0x1FBCB, 0x1FBEF),
    (0x1FBFA, 0x1FFFF),
    (0x2A6E0, 0x2A6FF),
    (0x2B73A, 0x2B73F),
    (0x2B81E, 0x2B81F),
    (0x2CEA2, 0x2CEAF),
    (0x2EBE1, 0x2F7FF),
    (0x2FA1E, 0x2FFFF),
    (0x3134B, 0x3134F),
    (0x323B0, 0xE00FF),
    (0xE01F0, 0x10FFFF),
];

pub(crate) static SPACE_RANGES: &[(u32, u32)] = &[
    (0x9, 0xD),
    (0x1C, 0x20),
    (0x85, 0x85),
    (0xA0, 0xA0),
    (0x1680, 0x1680),
    (0x2000, 0x200A),
    (0x2028, 0x2029),
    (0x202F, 0x202F),
    (0x205F, 0x205F),
    (0x3000, 0x3000),
];

/// 68 blocks of 10 consecutive codepoints each, values `0..=9` in order --
/// see [`unicode_decimal_digit`]'s doc comment.
pub(crate) static DIGIT_BLOCK_STARTS: &[u32] = &[
    0x30, 0x660, 0x6F0, 0x7C0, 0x966, 0x9E6, 0xA66, 0xAE6, 0xB66, 0xBE6, 0xC66, 0xCE6, 0xD66,
    0xDE6, 0xE50, 0xED0, 0xF20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90,
    0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10,
    0x104A0, 0x10D30, 0x11066, 0x110F0, 0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0, 0x11650,
    0x116C0, 0x11730, 0x118E0, 0x11950, 0x11C50, 0x11D50, 0x11DA0, 0x11F50, 0x16A60, 0x16AC0,
    0x16B50, 0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0, 0x1E4F0, 0x1E950,
    0x1FBF0,
];

// ---------------------------------------------------------------------------
// `urllib.parse.unquote` (PORTING.md §3b): the ONE canonical home for
// CPython's percent-decoding algorithm.
// ---------------------------------------------------------------------------

/// Port of `urllib.parse.unquote(s)` with the default (`errors="replace"`)
/// UTF-8 decoding of percent-triplets, exactly as CPython actually
/// implements it (`_unquote_impl`): `s` is split into maximal runs of ASCII
/// (U+0000-U+007F) and non-ASCII characters (`urllib.parse._asciire =
/// re.compile("[\x00-\x7f]+")`) *before* any `%XX` decoding happens. A `%XX`
/// escape is decoded only inside an ASCII run -- collected as raw bytes,
/// then the whole run is lossily UTF-8-decoded in one `bytes.decode(
/// "utf-8", "replace")` call, so adjacent escapes within the SAME run can
/// combine into one multi-byte character exactly as CPython's single
/// `decode` call does (`%E4%B8%AD` -> `中`). A non-ASCII run is copied
/// through unchanged, character for character, and is NEVER merged with a
/// `%`-decoded byte sequence from an adjacent run, even one immediately
/// next to it -- measured against live `python3.12`: `unquote("%E4\x80")`
/// is `"�\x80"` (one U+FFFD replacement character for the dangling
/// `%E4`, then the raw `\x80` untouched), not the single, differently-
/// decoded character a byte-level merge across the run boundary would
/// produce.
///
/// Callers whose input may hold an arbitrary wire byte per `char` (e.g. a
/// `latin1`-decoded HTTP header, one Rust `char` per original byte, never
/// part of a multi-byte UTF-8 encoding already) must operate char-by-char
/// rather than on raw UTF-8 byte offsets -- see [`unquote_ascii_run`]'s doc
/// comment.
///
/// Promoted here from two near-identical copies (PORTING.md §3b, finding
/// X-7 fixer's handover, equivalence review round 8): `fake_upstream.rs`'s
/// `unquote_plus` (`+` -> space, then this algorithm -- CPython's
/// `parse_qsl`/`urllib.parse.unquote_plus`) and `gateway.rs`'s
/// `percent_decode_lossy`, which implemented a simpler whole-string
/// byte-buffer merge instead of this run-splitting algorithm. That
/// simplification is NOT generally equivalent (a non-ASCII character
/// produced by one decode pass can, in principle, sit next to a
/// freshly-`%`-decoded byte from a *later* pass), but for `gateway.rs`'s
/// specific two-pass call site it produces byte-identical output to this
/// function regardless, because UTF-8 is self-synchronizing: every pass
/// already runs its own `String::from_utf8_lossy` before the next pass
/// starts, so by the time a later pass sees a non-ASCII character, that
/// character's bytes are already a COMPLETE, valid encoding (a leading byte
/// is never a continuation byte, and a complete sequence never needs
/// continuation from outside itself) -- there is no partial byte sequence
/// left dangling for a later pass's freshly-decoded escape byte to
/// (mis)complete. Confirmed by a differential test over representative
/// double-decode-pass inputs, `gateway.rs`'s
/// `normalize_path_percent_decode_matches_canonical_unquote_over_the_double_decode_pass_corpus`,
/// comparing this function against the prior whole-buffer implementation
/// byte-for-byte -- not merely asserted from this reasoning alone.
pub fn unquote(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
        if (chars[i] as u32) > 0x7F {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && (chars[i] as u32) <= 0x7F {
            i += 1;
        }
        out.push_str(&unquote_ascii_run(&chars[start..i]));
    }
    out
}

/// Decodes `%XX` triplets within a pure-ASCII run of characters
/// (`urllib.parse._unquote_impl` followed by one `bytes.decode("utf-8",
/// "replace")` over the whole run) -- see [`unquote`]. Every character here
/// is ASCII, so casting it to `u8` is exactly its one raw byte; no slicing
/// of a `str` by byte offset is ever needed (the bug this function's
/// promotion fixed a second copy of, finding X-7: indexing `&s[i+1..i+3]`
/// on the `str` itself panics whenever a multi-byte-encoded character puts
/// a slice boundary out of alignment with the raw byte offsets a naive
/// `i` would be counting).
fn unquote_ascii_run(run: &[char]) -> String {
    let mut decoded: Vec<u8> = Vec::with_capacity(run.len());
    let mut i = 0;
    while i < run.len() {
        if run[i] == '%' && i + 2 < run.len() {
            let hi = run[i + 1].to_digit(16);
            let lo = run[i + 2].to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                decoded.push(((hi << 4) | lo) as u8);
                i += 3;
                continue;
            }
        }
        decoded.push(run[i] as u8);
        i += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// `type(exc).__name__` of the `OSError` CPython raises for `error`: the
/// PEP 3151 errno-to-subclass map (`Objects/exceptions.c`), `OSError` for
/// any other errno or an error with no errno.
pub fn os_error_class(error: &std::io::Error) -> &'static str {
    match error.raw_os_error() {
        // A timeout Rust reports without an errno is CPython's `socket.timeout`.
        None if error.kind() == std::io::ErrorKind::TimedOut => "TimeoutError",
        Some(libc::EAGAIN | libc::EALREADY | libc::EINPROGRESS) => "BlockingIOError",
        #[allow(unreachable_patterns)]
        Some(libc::EWOULDBLOCK) => "BlockingIOError",
        Some(libc::ECHILD) => "ChildProcessError",
        Some(libc::EPIPE | libc::ESHUTDOWN) => "BrokenPipeError",
        Some(libc::ECONNABORTED) => "ConnectionAbortedError",
        Some(libc::ECONNREFUSED) => "ConnectionRefusedError",
        Some(libc::ECONNRESET) => "ConnectionResetError",
        Some(libc::EEXIST) => "FileExistsError",
        Some(libc::ENOENT) => "FileNotFoundError",
        Some(libc::EISDIR) => "IsADirectoryError",
        Some(libc::ENOTDIR) => "NotADirectoryError",
        Some(libc::EINTR) => "InterruptedError",
        Some(libc::EACCES | libc::EPERM) => "PermissionError",
        Some(libc::ESRCH) => "ProcessLookupError",
        Some(libc::ETIMEDOUT) => "TimeoutError",
        _ => "OSError",
    }
}

/// `exc.strerror` of that `OSError` (the C library's `strerror` text), or
/// `None` for an error with no errno.
pub fn os_error_strerror(error: &std::io::Error) -> Option<String> {
    let code = error.raw_os_error()?;
    let text = error.to_string();
    Some(
        text.strip_suffix(&format!(" (os error {code})"))
            .unwrap_or(&text)
            .to_owned(),
    )
}

/// `(EAI code, gai_strerror text)` pairs of glibc and the BSD/macOS
/// resolver, used to recover the `socket.gaierror` errno that
/// `std::net::ToSocketAddrs` folds into its message.
const GAI_MESSAGES: [(i32, &str); 20] = [
    (libc::EAI_BADFLAGS, "Bad value for ai_flags"),
    (libc::EAI_BADFLAGS, "Invalid value for ai_flags"),
    (libc::EAI_NONAME, "Name or service not known"),
    (
        libc::EAI_NONAME,
        "nodename nor servname provided, or not known",
    ),
    (libc::EAI_AGAIN, "Temporary failure in name resolution"),
    (libc::EAI_FAIL, "Non-recoverable failure in name resolution"),
    (libc::EAI_NODATA, "No address associated with hostname"),
    (libc::EAI_NODATA, "No address associated with nodename"),
    (libc::EAI_FAMILY, "ai_family not supported"),
    (libc::EAI_SOCKTYPE, "ai_socktype not supported"),
    (libc::EAI_SERVICE, "Servname not supported for ai_socktype"),
    (libc::EAI_SERVICE, "servname not supported for ai_socktype"),
    (libc::EAI_MEMORY, "Memory allocation failure"),
    (libc::EAI_SYSTEM, "System error"),
    (libc::EAI_OVERFLOW, "Argument buffer overflow"),
    (libc::EAI_OVERFLOW, "argument buffer overflow"),
    (libc::EAI_NONAME, "Name does not resolve"),
    (libc::EAI_AGAIN, "Try again"),
    (libc::EAI_FAIL, "Non-recoverable error"),
    (libc::EAI_NODATA, "Address not available"),
];

/// `str(exc)` for the `OSError` a socket connect or name lookup raises in
/// CPython: `[Errno N] strerror`, `[Errno EAI] gai_strerror` for a
/// resolver failure, or `timed out` for a socket timeout.
pub fn socket_error_text(error: &std::io::Error) -> String {
    if let Some(code) = error.raw_os_error() {
        let text = os_error_strerror(error).unwrap_or_default();
        return format!("[Errno {code}] {text}");
    }
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        return "timed out".to_owned();
    }
    let text = error.to_string();
    if let Some(message) = text.strip_prefix("failed to lookup address information: ")
        && let Some((code, _)) = GAI_MESSAGES.iter().find(|(_, m)| *m == message)
    {
        return format!("[Errno {code}] {message}");
    }
    text
}

/// Non-ASCII code points whose NFKC form contains one of `/?#@:` (Unicode
/// 15.0.0, the UCD CPython 3.12 bundles). `urllib.parse._checknetloc`
/// rejects a netloc when normalization would introduce such a delimiter;
/// NFKC of a single character is exactly its decomposition here because
/// these ASCII delimiters are never produced by canonical composition.
/// Generated with `unicodedata.normalize("NFKC", chr(cp))` over every code
/// point; pinned by `urlsplit_matches_python` below.
const NFKC_NETLOC_DELIMITERS: [u32; 19] = [
    0x2047, 0x2048, 0x2049, 0x2100, 0x2101, 0x2105, 0x2106, 0x2a74, 0xfe13, 0xfe16, 0xfe55, 0xfe56,
    0xfe5f, 0xfe6b, 0xff03, 0xff0f, 0xff1a, 0xff1f, 0xff20,
];

/// A `ValueError` raised by an emulated CPython function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueError;

/// `urllib.parse.SplitResult` (CPython 3.12) with the netloc accessors
/// callers need.
#[derive(Clone, Debug, PartialEq)]
pub struct SplitResult {
    pub scheme: String,
    pub netloc: String,
    pub path: String,
    pub query: String,
    pub fragment: String,
}

impl SplitResult {
    /// `_hostinfo`: `(hostname, port)` text before any conversion.
    fn hostinfo(&self) -> (&str, Option<&str>) {
        let hostinfo = self
            .netloc
            .rsplit_once('@')
            .map_or(self.netloc.as_str(), |(_, h)| h);
        let (hostname, port) = match hostinfo.split_once('[') {
            Some((_, bracketed)) => {
                let (hostname, rest) = bracketed.split_once(']').unwrap_or((bracketed, ""));
                (hostname, rest.split_once(':').map_or("", |(_, p)| p))
            }
            None => hostinfo.split_once(':').unwrap_or((hostinfo, "")),
        };
        (hostname, (!port.is_empty()).then_some(port))
    }

    /// `.hostname`: lower-cased (except a `%zone`), `None` when empty.
    pub fn hostname(&self) -> Option<String> {
        let (hostname, _) = self.hostinfo();
        if hostname.is_empty() {
            return None;
        }
        Some(match hostname.split_once('%') {
            Some((host, zone)) => format!("{}%{zone}", host.to_lowercase()),
            None => hostname.to_lowercase(),
        })
    }

    /// `.port`: `Err` where CPython raises `ValueError`.
    pub fn port(&self) -> Result<Option<u16>, ValueError> {
        match self.hostinfo().1 {
            None => Ok(None),
            Some(port) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
                // Arbitrarily long digit strings are still "out of range".
                let value = port.trim_start_matches('0');
                if value.len() > 5 {
                    return Err(ValueError);
                }
                u16::try_from(value.parse::<u32>().unwrap_or(0))
                    .map(Some)
                    .map_err(|_| ValueError)
            }
            Some(_) => Err(ValueError),
        }
    }

    /// `(.username, .password)`.
    pub fn userinfo(&self) -> (Option<&str>, Option<&str>) {
        match self.netloc.rsplit_once('@') {
            Some((userinfo, _)) => match userinfo.split_once(':') {
                Some((user, password)) => (Some(user), Some(password)),
                None => (Some(userinfo), None),
            },
            None => (None, None),
        }
    }
}

/// `ipaddress.ip_address(text)` succeeds; `Some(true)` for IPv4.
fn python_ip_address(text: &str) -> Option<bool> {
    if text.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(true);
    }
    // IPv6Address accepts one non-empty `%scope` suffix.
    let address = match text.split_once('%') {
        Some((address, scope)) if !scope.is_empty() && !scope.contains('%') => address,
        Some(_) => return None,
        None => text,
    };
    address.parse::<std::net::Ipv6Addr>().ok().map(|_| false)
}

/// `urllib.parse.urlsplit(url)` (CPython 3.12, default arguments):
/// `Err` where it raises `ValueError`.
pub fn urlsplit(url: &str) -> Result<SplitResult, ValueError> {
    let mut url: String = url
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut scheme = String::new();
    if let Some(i) = url.find(':')
        && i > 0
        && url.as_bytes()[0].is_ascii_alphabetic()
        && url[..i]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        scheme = url[..i].to_ascii_lowercase();
        url = url[i + 1..].to_owned();
    }
    let mut netloc = String::new();
    if let Some(rest) = url.strip_prefix("//") {
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        netloc = rest[..end].to_owned();
        url = rest[end..].to_owned();
        if netloc.contains('[') != netloc.contains(']') {
            return Err(ValueError);
        }
        if netloc.contains('[') {
            // `_check_bracketed_netloc`, then `_check_bracketed_host`.
            let host_port = netloc.rsplit_once('@').map_or(netloc.as_str(), |(_, h)| h);
            let hostname = match host_port.split_once('[') {
                Some((before, bracketed)) => {
                    if !before.is_empty() {
                        return Err(ValueError);
                    }
                    let (hostname, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
                    if !port.is_empty() && !port.starts_with(':') {
                        return Err(ValueError);
                    }
                    hostname
                }
                None => host_port.split_once(':').map_or(host_port, |(h, _)| h),
            };
            if let Some(future) = hostname.strip_prefix('v') {
                let digits = future.bytes().take_while(u8::is_ascii_hexdigit).count();
                if digits == 0
                    || !future[digits..].starts_with('.')
                    || future[digits + 1..].is_empty()
                    || future[digits + 1..].contains('\n')
                {
                    return Err(ValueError);
                }
            } else if python_ip_address(hostname) != Some(false) {
                return Err(ValueError);
            }
        }
    }
    let mut fragment = String::new();
    if let Some((before, after)) = url.split_once('#') {
        fragment = after.to_owned();
        url = before.to_owned();
    }
    let mut query = String::new();
    if let Some((before, after)) = url.split_once('?') {
        query = after.to_owned();
        url = before.to_owned();
    }
    // `_checknetloc`.
    if netloc
        .chars()
        .any(|c| NFKC_NETLOC_DELIMITERS.contains(&(c as u32)))
    {
        return Err(ValueError);
    }
    Ok(SplitResult {
        scheme,
        netloc,
        path: url,
        query,
        fragment,
    })
}

/// `surrogateescape` text carried through `String`-typed code.
///
/// CPython decodes a command-line argument or environment value that is not
/// valid UTF-8 with `surrogateescape`: each undecodable byte `b` becomes the
/// lone surrogate `U+DC00 + b`, which a Rust `String` cannot hold.  This maps
/// each such byte to a code point of one 128-code-point block of the
/// supplementary private-use planes, chosen so that no input uses any code
/// point of the block and no input contains the literal `repr()` or JSON
/// escape text of one.  Within that invocation the mapping is therefore
/// injective, `encode` recovers the original bytes (`os.fsencode`), and the
/// rewrite helpers turn the block's code points back into exactly what
/// CPython prints for the surrogates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SurrogateEscape {
    base: u32,
}

impl SurrogateEscape {
    /// The block avoiding every code point and escape spelling in `inputs`;
    /// `None` only when the inputs occupy all 1020 candidate blocks.
    pub fn avoiding<'a>(inputs: impl IntoIterator<Item = &'a [u8]>) -> Option<Self> {
        const BLOCKS: u32 = 1020;
        let block_of = |cp: u32| -> Option<u32> {
            let index = match cp {
                0xF0000..=0xFFF7F => (cp - 0xF0000) / 128,
                0x100000..=0x10FF7F => 510 + (cp - 0x100000) / 128,
                _ => return None,
            };
            (index < BLOCKS).then_some(index)
        };
        let mut used = vec![false; BLOCKS as usize];
        let mut mark = |cp: u32| {
            if let Some(index) = block_of(cp) {
                used[index as usize] = true;
            }
        };
        for input in inputs {
            let text = String::from_utf8_lossy(input);
            for c in text.chars() {
                mark(c as u32);
            }
            // `\UXXXXXXXX` (repr) and `\udXXX\udXXX` (JSON) spellings.
            let chars: Vec<char> = text.chars().collect();
            for (i, &c) in chars.iter().enumerate() {
                if c != '\\' {
                    continue;
                }
                let hex = |from: usize, len: usize| -> Option<u32> {
                    let digits: String = chars.get(from..from + len)?.iter().collect();
                    u32::from_str_radix(&digits, 16).ok()
                };
                if chars.get(i + 1) == Some(&'U')
                    && let Some(cp) = hex(i + 2, 8)
                {
                    mark(cp);
                }
                if chars.get(i + 1) == Some(&'u')
                    && let Some(high) = hex(i + 2, 4)
                    && (0xD800..=0xDBFF).contains(&high)
                {
                    // Any low half: mark the whole range the high half spans.
                    let first = 0x10000 + ((high - 0xD800) << 10);
                    for cp in (first..first + 0x400).step_by(128) {
                        mark(cp);
                    }
                }
            }
        }
        let index = used.iter().position(|u| !*u)? as u32;
        let base = if index < 510 {
            0xF0000 + index * 128
        } else {
            0x100000 + (index - 510) * 128
        };
        Some(SurrogateEscape { base })
    }

    /// `bytes.decode('utf-8', 'surrogateescape')`.
    pub fn decode(&self, bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len());
        for chunk in bytes.utf8_chunks() {
            out.push_str(chunk.valid());
            for &b in chunk.invalid() {
                out.push(self.escape_byte(b));
            }
        }
        out
    }

    fn escape_byte(&self, b: u8) -> char {
        // Undecodable UTF-8 bytes are always 0x80..=0xFF.
        char::from_u32(self.base + u32::from(b & 0x7F)).unwrap_or('\u{FFFD}')
    }

    /// The surrogate `c` stands for (`0xDC80..=0xDCFF`), if it is one.
    pub fn surrogate(&self, c: char) -> Option<u32> {
        let cp = c as u32;
        (self.base..self.base + 128)
            .contains(&cp)
            .then(|| 0xDC80 + (cp - self.base))
    }

    /// Whether `text` holds any escaped byte.
    pub fn contains_escape(&self, text: &str) -> bool {
        text.chars().any(|c| self.surrogate(c).is_some())
    }

    /// `str.encode('utf-8', 'surrogateescape')` (`os.fsencode`).
    pub fn encode(&self, text: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(text.len());
        for c in text.chars() {
            match self.surrogate(c) {
                Some(surrogate) => out.push((surrogate - 0xDC00) as u8),
                None => {
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
            }
        }
        out
    }

    /// Text containing escaped bytes raw and inside `repr()`s (as
    /// [`repr_str`] spells them), as CPython writes it to `sys.stderr`
    /// (`backslashreplace`): every escaped byte becomes `\udcXX`.
    pub fn stderr_text(&self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(c) = rest.chars().next() {
            if let Some(surrogate) = self.surrogate(c) {
                out.push_str(&format!("\\u{surrogate:04x}"));
                rest = &rest[c.len_utf8()..];
                continue;
            }
            if let Some(escape) = rest.strip_prefix("\\U").and_then(|r| r.get(..8))
                && let Ok(cp) = u32::from_str_radix(escape, 16)
                && let Some(surrogate) = char::from_u32(cp).and_then(|c| self.surrogate(c))
                && escape
                    .chars()
                    .all(|d| d.is_ascii_digit() || d.is_ascii_lowercase())
            {
                out.push_str(&format!("\\u{surrogate:04x}"));
                rest = &rest[10..];
                continue;
            }
            out.push(c);
            rest = &rest[c.len_utf8()..];
        }
        out
    }

    /// `json.dumps` (`ensure_ascii=True`) output of strings holding escaped
    /// bytes: each escaped byte's surrogate-pair escape becomes the lone
    /// `\udcXX` CPython writes.
    pub fn json_text(&self, dumped: &str) -> String {
        let mut out = String::with_capacity(dumped.len());
        let mut rest = dumped;
        while !rest.is_empty() {
            if let Some(pair) = rest.get(..12)
                && pair.starts_with("\\u")
                && pair[6..].starts_with("\\u")
                && let (Ok(high), Ok(low)) = (
                    u32::from_str_radix(&pair[2..6], 16),
                    u32::from_str_radix(&pair[8..12], 16),
                )
                && (0xD800..=0xDBFF).contains(&high)
                && (0xDC00..=0xDFFF).contains(&low)
                && let Some(surrogate) =
                    char::from_u32(0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00))
                        .and_then(|c| self.surrogate(c))
            {
                out.push_str(&format!("\\u{surrogate:04x}"));
                rest = &rest[12..];
                continue;
            }
            let c = rest.chars().next().unwrap_or_default();
            out.push(c);
            rest = &rest[c.len_utf8()..];
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle::python;

    /// C-R2-1: full-enumeration differential test. Hashes `is_printable`/
    /// `is_space` over every `char` (`0..=0x10FFFF` minus surrogates, which
    /// `char::from_u32` already excludes) and compares against the same
    /// computation done by `python3.12` live, so this catches any table
    /// mistake *and* any future drift from a different Python patch version.
    #[test]
    fn oracle_is_printable_and_is_space_match_python_for_every_codepoint() {
        use sha2::{Digest, Sha256};

        let mut printable_hasher = Sha256::new();
        let mut space_hasher = Sha256::new();
        for cp in 0u32..=0x10FFFF {
            let Some(c) = char::from_u32(cp) else {
                continue; // surrogate range: not a valid `char`, skipped both sides
            };
            printable_hasher.update([is_printable(c) as u8]);
            space_hasher.update([is_space(c) as u8]);
        }
        let our_printable = hex::encode(printable_hasher.finalize());
        let our_space = hex::encode(space_hasher.finalize());

        let script = r#"
import hashlib
hp = hashlib.sha256()
hs = hashlib.sha256()
for cp in range(0, 0x110000):
    if 0xD800 <= cp <= 0xDFFF:
        continue
    ch = chr(cp)
    hp.update(b"\x01" if ch.isprintable() else b"\x00")
    hs.update(b"\x01" if ch.isspace() else b"\x00")
print(hp.hexdigest())
print(hs.hexdigest())
"#;
        let out = python(script);
        let mut lines = out.lines();
        let their_printable = lines.next().expect("printable digest line").trim();
        let their_space = lines.next().expect("space digest line").trim();

        assert_eq!(
            our_printable, their_printable,
            "is_printable digest mismatch"
        );
        assert_eq!(our_space, their_space, "is_space digest mismatch");
    }

    #[test]
    fn is_printable_matches_known_categories() {
        assert!(is_printable(' ')); // Zs, the one exception
        assert!(is_printable('a'));
        assert!(is_printable("café".chars().last().unwrap()));
        assert!(!is_printable('\u{0}')); // Cc
        assert!(!is_printable('\u{a0}')); // Zs, not space
        assert!(!is_printable('\u{2028}')); // Zl
        assert!(!is_printable('\u{2029}')); // Zp
        assert!(!is_printable('\u{200b}')); // Cf
        assert!(!is_printable('\u{feff}')); // Cf
        assert!(!is_printable('\u{e000}')); // Co (private use)
        assert!(!is_printable('\u{378}')); // Cn (unassigned)
        assert!(!is_printable('\u{890}')); // Cf
        assert!(!is_printable('\u{13439}')); // Cf
        assert!(!is_printable('\u{10ffff}')); // Cn
        assert!(is_printable('\u{1d11e}')); // musical symbol, assigned + printable
    }

    #[test]
    fn is_space_matches_known_cases() {
        assert!(is_space(' '));
        assert!(is_space('\t'));
        assert!(is_space('\n'));
        assert!(is_space('\u{1c}')); // ASCII info separator, bidi class B
        assert!(is_space('\u{a0}'));
        assert!(is_space('\u{3000}'));
        assert!(!is_space('a'));
        assert!(!is_space('\u{200b}')); // ZWSP is Cf, not space
    }

    #[test]
    fn repr_str_oracle_tricky_strings() {
        let cases = [
            "it's",
            "say \"hi\"",
            "both ' and \" here",
            "line\nbreak",
            "back\\slash",
            "\u{1}control",
            "\u{7f}del",
            "\u{85}nel",
            "café",
            "no\u{a0}break\u{a0}space",
            "musical\u{1D11E}clef",
            "unassigned\u{378}here",
            "format\u{890}char",
            "cuneiform-fmt\u{1343A}",
            "tag\u{e0080}space",
            "max\u{10FFFF}cp",
            "bom\u{feff}here",
            "zwsp\u{200b}here",
        ];
        for s in cases {
            let ours = repr_str(s);
            let byte_list: Vec<u8> = s.as_bytes().to_vec();
            let script = format!("s = bytes({byte_list:?}).decode('utf-8')\nprint(repr(s))");
            let theirs = python(&script).trim().to_string();
            assert_eq!(ours, theirs, "input {s:?}");
        }
    }

    /// Finding H-R5-1 (PORTING.md §3b): pins [`repr_value`], the crate's
    /// ONE canonical `repr()` for a `json.loads`-decoded value, against
    /// real `python3.12`'s own `repr()`/`str()` for a table covering
    /// everything its doc comment promises: nested containers, dict KEY
    /// ORDER (insertion, never sorted), non-ASCII strings copied through
    /// literally (not escaped the way JSON's `ensure_ascii` would), floats
    /// (including a tie-breaking case where the shortest round-tripping
    /// decimal representation matters), and a large (beyond-`i64`) integer
    /// rendered verbatim. Each case is round-tripped through `pyjson` so
    /// both languages parse the identical JSON text, then both languages'
    /// `repr()`/`str()` outputs are compared.
    #[test]
    fn repr_value_oracle_table() {
        use serde_json::json;

        let cases: Vec<serde_json::Value> = vec![
            json!(null),
            json!(true),
            json!(false),
            json!(0),
            json!(-17),
            json!(170141183460469231731687303715884105727i128), // beyond i64::MAX
            json!(-170141183460469231731687303715884105728i128), // beyond i64::MIN
            json!(2.5),
            json!(0.1),
            json!(1.0),
            json!(100.0),
            // Tie-breaking case: the float closest to 0.1 + 0.2 needs its
            // shortest round-tripping repr, not a naive fixed-precision one.
            json!(0.30000000000000004),
            json!(""),
            json!("plain"),
            json!("café \u{00e9} non-ascii"),
            json!("emoji \u{1F600}"),
            json!("quote's and \"quotes\""),
            json!([]),
            json!({}),
            json!([1, "two", 3.0, null, true, false]),
            // Dict key order: JSON object insertion order, NOT sorted --
            // `serde_json` here is built with `preserve_order` for exactly
            // this reason.
            json!({"b": 1, "a": 2, "z": 3}),
            // Nested containers, mixed.
            json!({"list": [1, {"k": "v"}, [2, 3]], "s": "x"}),
            json!([{"b": 1, "a": 2}, {"y": [1, 2], "x": null}]),
            json!(["café", {"emoji": "\u{1F600}", "b": 1, "a": 2}]),
        ];

        for value in &cases {
            let ours = repr_value(value);
            // `DumpOptions::plain()` (insertion order, matching Python's own
            // `dict`) -- NOT `compact_sorted()`, which would reorder the
            // "b"/"a"/"z" case's keys in the JSON text itself before either
            // language ever sees them, defeating the dict-key-order case
            // this table exists to cover.
            let json_text =
                crate::pyjson::dumps(value, crate::pyjson::DumpOptions::plain()).unwrap();
            let script = format!("import json\nv = json.loads({json_text:?})\nprint(repr(v))");
            let theirs = python(&script).trim().to_string();
            assert_eq!(ours, theirs, "input {value:?}");
        }
    }

    /// X-10 (equivalence review, round 8) pinning test: before the fix,
    /// `repr_value`'s `Number` arm branched on `Number::is_f64()`, which is
    /// `false` for a literal that overflows to a non-finite `f64` under
    /// `arbitrary_precision`, so this fell into the *integer* arm and
    /// returned the raw literal text (`"1e+400"`) unchanged instead of
    /// Python's `"inf"`. Built via `serde_json::from_str` directly (not the
    /// `json!` macro, and not round-tripped through
    /// [`crate::pyjson::dumps`], which rejects a non-finite literal
    /// outright per its own contract) -- exactly `kms.rs`'s
    /// `number_literal` test helper, since this crate's own parser can
    /// never hand `repr_value` one, but a hand-crafted or foreign-written
    /// JSON document still can. The Python side is measured directly
    /// against a live `python3.12`, not assumed from this test's own doc
    /// comment.
    #[test]
    fn oracle_repr_number_matches_python_for_overflowing_literal() {
        fn number_literal(raw: &str) -> serde_json::Value {
            serde_json::Value::Number(serde_json::from_str(raw).expect("valid JSON number literal"))
        }

        for raw in ["1E400", "-1E400", "1E-400", "-1E-400"] {
            let ours = repr_value(&number_literal(raw));
            let theirs = python(&format!("import json\nprint(repr(json.loads({raw:?})))"))
                .trim()
                .to_string();
            assert_eq!(ours, theirs, "input {raw}");
        }

        // Also nested inside a container, exercising the Array/Object
        // recursion path through the same fixed Number arm.
        let nested = serde_json::json!([number_literal("1E400"), number_literal("-1E400")]);
        let ours = repr_value(&nested);
        assert_eq!(ours, "[inf, -inf]");
    }

    // --------------------------------------------------------- int(str)

    #[test]
    fn is_int_space_is_the_narrow_ascii_set() {
        for c in [' ', '\t', '\n', '\u{0b}', '\u{0c}', '\r'] {
            assert!(is_int_space(c), "{c:?} must be int-whitespace");
        }
        // U+001C-U+001F are `str.isspace()` but NOT `int()`-whitespace: the
        // whole reason this function exists separately from [`is_space`].
        for c in [
            '\u{1c}', '\u{1d}', '\u{1e}', '\u{1f}', 'a', '\u{a0}', '\u{3000}',
        ] {
            assert!(!is_int_space(c), "{c:?} must not be int-whitespace");
        }
    }

    #[test]
    fn oracle_digit_value_matches_python_for_every_codepoint() {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        for cp in 0u32..=0x10FFFF {
            let Some(c) = char::from_u32(cp) else {
                continue;
            };
            let v = unicode_decimal_digit(c).map(|d| d as i32).unwrap_or(-1);
            hasher.update([(v + 1) as u8]);
        }
        let ours = hex::encode(hasher.finalize());

        let script = r#"
import hashlib, unicodedata
h = hashlib.sha256()
for cp in range(0, 0x110000):
    if 0xD800 <= cp <= 0xDFFF:
        continue
    d = unicodedata.decimal(chr(cp), -1)
    h.update(bytes([(d + 1) & 0xFF]))
print(h.hexdigest())
"#;
        let theirs = python(script).trim().to_string();
        assert_eq!(ours, theirs, "unicode_decimal_digit digest mismatch");
    }

    #[test]
    fn int_from_str_known_cases() {
        // ASCII-only int() whitespace (finding F-R3-2): U+001C-U+001F are
        // NOT stripped and are not digits, so they make the whole parse
        // fail, unlike `str.strip()`/`is_space`.
        assert_eq!(int_from_str("\u{1c}5"), None);
        assert_eq!(int_from_str(" \u{1c}5"), None);
        assert_eq!(int_from_str("\u{1d}\u{1e}\u{1f}5"), None);
        assert_eq!(int_from_str(" 5 "), Some(5));
        assert_eq!(int_from_str("\t5\n"), Some(5));
        assert_eq!(int_from_str("\u{0b}5\u{0c}"), Some(5));
        assert_eq!(int_from_str("\r5\r"), Some(5));
        // Unicode decimal digits and Unicode whitespace ARE honoured by the
        // transform stage.
        assert_eq!(int_from_str("\u{665}"), Some(5)); // arabic-indic 5
        assert_eq!(int_from_str(" \u{665} "), Some(5));
        assert_eq!(int_from_str("\u{a0}\u{665}\u{a0}"), Some(5));
        assert_eq!(int_from_str("\u{ff11}\u{ff15}"), Some(15)); // fullwidth "15"
        assert_eq!(int_from_str("+\u{665}"), Some(5));
        assert_eq!(int_from_str("-\u{665}"), Some(-5));
        assert_eq!(int_from_str("\u{2460}"), None); // circled digit one: not Nd
        // PEP 515 underscores.
        assert_eq!(int_from_str("1_000"), Some(1000));
        assert_eq!(int_from_str("_1"), None);
        assert_eq!(int_from_str("1_"), None);
        assert_eq!(int_from_str("1__0"), None);
        // Base 16, including the Unicode-digit transform applying before
        // the hex grammar (not after) and the underscore-after-prefix rule.
        assert_eq!(int_from_str_radix("\u{661}\u{665}", 16), Some(0x15));
        assert_eq!(int_from_str_radix("0x_10", 16), Some(0x10));
        assert_eq!(int_from_str_radix("0X\u{661}\u{665}", 16), Some(0x15));
        assert_eq!(int_from_str_radix("", 10), None);
        assert_eq!(int_from_str_radix("   ", 10), None);
    }

    /// `int_from_str_radix_checked` shares every accept/reject decision with
    /// the saturating `int_from_str_radix` *except* right at the `i128`
    /// magnitude boundary, where CPython's own arbitrary precision has no
    /// analogue at all: `int_from_str_radix` clamps to `i128::MAX`/`MIN` (a
    /// deliberately wrong-but-in-range sentinel for callers that only ever
    /// bounds-check the result), while the checked variant returns `None`
    /// instead of ever returning that wrong value to a caller that would
    /// store or re-serialize it.
    #[test]
    fn int_from_str_radix_checked_matches_saturating_below_the_boundary_and_diverges_at_it() {
        // Ordinary, in-range grammar: identical on both sides, sign included.
        for s in ["0", "-0", "1_000", "-1_000", "١٥", " 42 ", "\u{a0}9\u{a0}"] {
            assert_eq!(
                int_from_str_checked(s),
                int_from_str(s),
                "input {s:?} must agree below the i128 boundary"
            );
        }
        // Exactly at the boundary: both sides agree (no overflow yet).
        let max_digits = i128::MAX.to_string();
        let min_digits = i128::MIN.to_string();
        assert_eq!(int_from_str_checked(&max_digits), Some(i128::MAX));
        assert_eq!(int_from_str(&max_digits), Some(i128::MAX));
        assert_eq!(int_from_str_checked(&min_digits), Some(i128::MIN));
        assert_eq!(int_from_str(&min_digits), Some(i128::MIN));
        // One past the boundary: the saturating variant clamps, the checked
        // variant refuses.
        let one_past_max = "170141183460469231731687303715884105728"; // i128::MAX + 1
        let one_past_min = "-170141183460469231731687303715884105729"; // i128::MIN - 1
        let way_past = "9".repeat(50);
        assert_eq!(int_from_str_checked(one_past_max), None);
        assert_eq!(int_from_str(one_past_max), Some(i128::MAX));
        assert_eq!(int_from_str_checked(one_past_min), None);
        assert_eq!(int_from_str(one_past_min), Some(i128::MIN));
        assert_eq!(int_from_str_checked(&way_past), None);
        assert_eq!(int_from_str(&way_past), Some(i128::MAX));
        // Grammar-invalid input is `None` on both sides regardless of
        // magnitude -- overflow handling must never mask a real syntax
        // rejection (e.g. a double underscore in an otherwise-huge numeral).
        assert_eq!(int_from_str_checked("9__9".repeat(20).as_str()), None);
        assert_eq!(int_from_str("9__9".repeat(20).as_str()), None);
    }

    /// Random/adversarial fuzz against a live `python3.12`, weighted toward
    /// the exact characters that distinguish `int()`-whitespace from
    /// `str.isspace()`, PEP 515 underscores, the `0x`/`0X` prefix, and
    /// Unicode decimal digits/whitespace -- the equivalence-review finding
    /// F-R3-2 fuzz (7,751 cases, 1,114 divergences) found every one of these
    /// dimensions mishandled by the old ad hoc `is_space`-based trim.
    #[test]
    fn oracle_int_from_str_matches_python_fuzz() {
        let alphabet: &[char] = &[
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'A',
            'B', 'C', 'D', 'E', 'F', 'x', 'X', '+', '-', '_', ' ', '\t', '\n', '\u{0b}', '\u{0c}',
            '\r', '\u{1c}', '\u{1d}', '\u{1e}', '\u{1f}', '\u{a0}', '\u{3000}', '\u{665}',
            '\u{ff15}', '\u{966}', '\u{2460}', 'z', '.',
        ];
        let mut state: u64 = 0xdead_beef_cafe_f00d;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut cases: Vec<(String, u32)> = Vec::new();
        for _ in 0..1500 {
            let len = (next() % 12) as usize;
            let s: String = (0..len)
                .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
                .collect();
            let base = if next() % 2 == 0 { 10 } else { 16 };
            cases.push((s, base));
        }
        for (s, base) in [
            ("\u{1c}5", 10),
            ("5\u{1c}", 10),
            (" \u{1c}5", 10),
            ("\u{1c} 5", 10),
            ("\u{1d}\u{1e}\u{1f}5", 10),
            ("0x_10", 16),
            ("_1", 10),
            ("1_", 10),
            ("1__0", 10),
            ("\u{661}\u{665}", 16),
            ("\u{ff11}\u{ff15}", 10),
            ("  \u{ff11}\u{ff15}  ", 10),
            ("+\u{665}", 10),
            ("-\u{665}", 10),
            ("\u{966}", 10),
            ("\u{e50}", 10),
            ("\u{2460}", 10),
            ("\u{a0}\u{665}\u{a0}", 10),
            ("", 10),
            ("   ", 10),
            ("+", 10),
            ("-", 10),
            ("0x", 16),
        ] {
            cases.push((s.to_string(), base));
        }

        let mut script = String::from("cases = [\n");
        for (s, base) in &cases {
            script.push_str(&format!(
                "    (bytes.fromhex({:?}).decode('utf-8'), {}),\n",
                hex::encode(s.as_bytes()),
                base
            ));
        }
        script.push_str(
            "]\nfor s, base in cases:\n    try:\n        print(int(s, base))\n    except Exception:\n        print('ERR')\n",
        );
        let out = python(&script);
        let their_lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            their_lines.len(),
            cases.len(),
            "python printed a different number of lines than cases submitted"
        );
        for ((s, base), line) in cases.iter().zip(their_lines.iter()) {
            let ours = int_from_str_radix(s, *base);
            if *line == "ERR" {
                assert_eq!(
                    ours, None,
                    "input {s:?} base {base}: rust returned {ours:?}, python raised"
                );
            } else {
                let expected: i128 = line
                    .parse()
                    .unwrap_or_else(|_| panic!("python printed a non-integer: {line:?}"));
                assert_eq!(ours, Some(expected), "input {s:?} base {base}");
            }
        }
    }

    #[test]
    fn urlsplit_matches_python() {
        let cases = [
            "http://host",
            "https://Host.Example:0443/",
            "http://host:",
            "http://host:+80",
            "http://host/?",
            "http://host#",
            "http:/host",
            "http://[::1",
            "http://[::1]:8080",
            "http://[fe80::1%25eth0]/",
            "http://[1.2.3.4]/",
            "http://[v1.x]/",
            "http://[vg.x]/",
            "http://u:p@h:1/p?q#f",
            "http://@h",
            " \x01http://h\t/x",
            "HTTP://h:99999",
            "http://h:00080",
            "ftp://h",
            "http://a\u{ff0f}b/",
            "http://a\u{2100}/",
            "x:y",
            "1http://h",
            "//h:5/p",
            "http://h:\u{0663}",
            "http://x[::1]/",
            "http://[::1]x/",
            "",
        ];
        let script = format!(
            "import json\nfrom urllib.parse import urlsplit\nout=[]\nfor u in {}:\n    try:\n        r=urlsplit(u)\n    except ValueError:\n        out.append(None); continue\n    try: port=r.port\n    except ValueError: port='ERR'\n    out.append([r.scheme,r.netloc,r.path,r.query,r.fragment,r.hostname,port,r.username,r.password])\nprint(json.dumps(out))",
            repr_value(&serde_json::json!(cases))
        );
        let expected: Vec<serde_json::Value> =
            serde_json::from_str(&crate::oracle::python(&script)).unwrap();
        for (case, expected) in cases.iter().zip(expected) {
            let actual = match urlsplit(case) {
                Err(ValueError) => serde_json::Value::Null,
                Ok(r) => {
                    let port = match r.port() {
                        Ok(p) => serde_json::json!(p),
                        Err(ValueError) => serde_json::json!("ERR"),
                    };
                    let (user, password) = r.userinfo();
                    serde_json::json!([
                        r.scheme,
                        r.netloc,
                        r.path,
                        r.query,
                        r.fragment,
                        r.hostname(),
                        port,
                        user,
                        password
                    ])
                }
            };
            assert_eq!(actual, expected, "{case:?}");
        }
    }

    /// `SurrogateEscape` against CPython's `surrogateescape`: the decoded
    /// text's `json.dumps` and `repr` spellings and the `os.fsencode` round
    /// trip, with inputs that occupy the first candidate blocks by code point
    /// and by literal escape text.
    #[test]
    fn surrogate_escape_matches_python_surrogateescape() {
        let inputs: Vec<&[u8]> = vec![
            b"plain",
            b"a\xffb\xfe",
            "\u{F0000}\u{F0001} pua".as_bytes(),
            b"literal \\U000f0081 and \\udb80\\udc00 escapes",
            b"\xed\xa0\x80 encoded surrogate",
            b"\xc3\x28 \xe2\x82 \xf0\x9f\x98",
            b"quote' \" \\ \x80",
        ];
        let esc = SurrogateEscape::avoiding(inputs.iter().copied()).unwrap();
        assert!(esc.base >= 0xF0000 + 2 * 128 && esc.base != 0xF0000);
        let encoded = crate::pybase64::b64encode(
            serde_json::to_string(
                &inputs
                    .iter()
                    .map(|i| crate::pybase64::b64encode(i))
                    .collect::<Vec<_>>(),
            )
            .unwrap()
            .as_bytes(),
        );
        let script = format!(
            r#"
import base64, json
for item in json.loads(base64.b64decode("{encoded}")):
    text = base64.b64decode(item).decode("utf-8", "surrogateescape")
    print(json.dumps([json.dumps(text), repr(text).encode("utf-8", "backslashreplace").decode()]))
"#
        );
        let expected: Vec<(String, String)> = crate::oracle::python(&script)
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        for (input, (json_text, repr_text)) in inputs.iter().zip(expected) {
            let text = esc.decode(input);
            assert_eq!(esc.encode(&text), *input);
            let dumped = crate::pyjson::dumps(
                &serde_json::Value::String(text.clone()),
                crate::pyjson::DumpOptions::plain(),
            )
            .unwrap();
            assert_eq!(esc.json_text(&dumped), json_text, "{input:?}");
            assert_eq!(esc.stderr_text(&repr_str(&text)), repr_text, "{input:?}");
        }
    }
}
