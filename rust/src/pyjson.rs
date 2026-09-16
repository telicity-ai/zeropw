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
//!   default separators -> [`DumpOptions::plain`]. See the "key order" note
//!   below: this crate cannot reproduce Python's dict insertion order.
//! - `gateway.py` pattern building (`json.dumps(text)[1:-1]` and
//!   `json.dumps(text, ensure_ascii=False)[1:-1]`): encoding a single string
//!   value with `ensure_ascii` True/False -> [`encode_str`].
//!
//! ## Key order
//!
//! `serde_json`'s `Map` is a `BTreeMap` in this crate (the `preserve_order`
//! feature needs the `indexmap` crate, which is not vendored for offline
//! builds -- see `rust/DEVIATIONS.md`). That means **object keys are always
//! emitted in sorted order**, even when [`DumpOptions::sort_keys`] is `false`.
//! For every call site above that already passes `sort_keys=True` this is
//! exactly Python's behaviour. For the few that do not (`agent_cli.py`'s
//! plain `json.dumps(payload)`), Rust's output has keys sorted where Python's
//! has insertion order; this is recorded in `DEVIATIONS.md` since it is a
//! whole-crate limitation, not specific to one module.
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
//! `Infinity`, `-Infinity` tokens, and its decoder accepts them back. No
//! writer in `zeropw/` ever produces a non-finite float (audit fields are
//! `round(time.time(), 3)`-derived; vault/policy documents hold no floats at
//! all), so this port does not special-case them: [`dumps`] returns an error
//! for a non-finite float (defensive, should be unreachable), and [`loads`]
//! rejects the bare tokens as a parse error like any other malformed JSON.
//! A state file that somehow contained them would be `state_corrupt` in Rust
//! but would silently parse in Python -- recorded in `DEVIATIONS.md`.

use std::fmt::Write as _;

use serde_json::{Number, Value};

use crate::errors::{Error, Result};

/// How to render a [`Value`] tree, mirroring one Python `json.dumps`/`dump`
/// call's keyword arguments.
#[derive(Clone, Copy, Debug)]
pub struct DumpOptions {
    /// `sort_keys=`. See the "Key order" note on the module: because this
    /// crate's `Map` is always sorted, `false` only differs from `true` in
    /// intent/documentation today, not in output.
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
/// tokens Python's decoder accepts by default -- see the module doc.
pub fn loads(text: &str) -> serde_json::Result<Value> {
    serde_json::from_str(text)
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
    // `Map` is BTreeMap-backed in this build (no `preserve_order`), so
    // iteration is already key-sorted regardless of `opts.sort_keys`; see
    // the module doc's "Key order" note.
    for (i, (key, val)) in map.iter().enumerate() {
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
    if n.is_f64() {
        let f = n
            .as_f64()
            .ok_or_else(|| Error::invalid_input("pyjson_non_finite_float").with_detail("number"))?;
        out.push_str(&python_float_repr(f));
    } else {
        // Integer (any size, thanks to `arbitrary_precision`): Python ints
        // have a unique canonical decimal form, which `as_str()` already is.
        out.push_str(n.as_str());
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
}

/// Differential tests against the CPython oracle (`crate::oracle`). Separate
/// module so the plain unit tests above stay fast and offline-only; these
/// shell out to `python3.12`.
#[cfg(test)]
mod oracle_tests {
    use super::*;
    use crate::oracle;
    use serde_json::json;

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
}
