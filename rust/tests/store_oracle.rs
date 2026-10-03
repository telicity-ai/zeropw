//! Differential test for `zeropw::store::iso` against the Python prototype's
//! `zeropw.store.iso` (`time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))`),
//! per the equivalence-review finding A-R3-3: `store.rs`'s `iso()` doc
//! comment claimed this verification existed ("verified against CPython ...
//! see `rust/tests/store_oracle.rs`") before this file did. Recorded here so
//! that claim is backed by an actual, committed test.
//!
//! Lives under `rust/tests/` as a standalone test binary (like
//! `state_dir_cross_language.rs`/`policy_oracle.rs`): `crate::oracle` is
//! `#[cfg(test)] pub(crate)` and not reachable from here, so this file has
//! its own tiny Python-running helper.

use std::path::{Path, PathBuf};
use std::process::Command;

use zeropw::store::iso;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn run_python(script: &str) -> String {
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".to_string());
    let output = Command::new(interpreter)
        .arg("-c")
        .arg(script)
        .env("PYTHONPATH", repo_root())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("failed to run python3.12 (see rust/PORTING.md: this port targets python3.12)");
    assert!(
        output.status.success(),
        "python3.12 failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("python stdout was not utf-8")
}

/// A small, deterministic xorshift64 PRNG -- avoids pulling `rand` into a
/// dev-dependency just for this table, and reruns identically every time.
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
    /// A signed timestamp roughly in the range of a plausible-ish
    /// year (but the whole point of this table is to also cover
    /// implausible years -- see the fixed cases below).
    fn timestamp(&mut self) -> f64 {
        let bits = self.next();
        // Scale to +/- ~1e11 seconds (~+/- 3000 years from the epoch),
        // exercising both far-future and far-past civil dates.
        ((bits as i64) as f64 / i64::MAX as f64) * 1e11
    }
}

#[test]
fn iso_matches_python_time_gmtime_over_a_timestamp_table() {
    // A-R3-3: epoch, negative, fractional, 2000-02-29 (leap day), year 1,
    // year 9999/10000 (four- vs five-digit year boundary), the i32
    // boundaries (2^31 and -2^31, historically relevant sizes for a Unix
    // timestamp), plus a batch of randomized values.
    let mut fixed: Vec<f64> = vec![
        0.0,               // epoch
        -1.0,              // one second before the epoch
        -86400.0,          // one day before the epoch
        1.5,               // fractional (must floor, not round)
        -0.5,              // fractional, negative
        1_700_000_000.75,  // fractional, "realistic" current-era timestamp
        951_782_400.0,     // 2000-02-29T00:00:00Z (leap day)
        -62_135_596_800.0, // 0001-01-01T00:00:00Z (year 1)
        253_402_300_799.0, // 9999-12-31T23:59:59Z (last 4-digit year)
        253_402_300_800.0, // 10000-01-01T00:00:00Z (rolls into 5 digits)
        2_147_483_647.0,   // i32::MAX (the classic Y2038 boundary)
        2_147_483_648.0,   // one past it
        -2_147_483_648.0,  // i32::MIN
        -2_147_483_649.0,  // one past it
        // A-R4-2: additional cases CPython's `gmtime` handles without
        // raising, previously uncovered by this table.
        -62_167_219_200.0, // 0000-01-01T00:00:00Z (year 0)
        -62_167_219_201.0, // -001-12-31T23:59:59Z (year -1, one second earlier)
        1e15,              // 31690708-07-05T01:46:40Z (an 8-digit year)
    ];
    let mut rng = Xorshift64(0xD1B54A32D192ED03);
    for _ in 0..200 {
        fixed.push(rng.timestamp());
    }

    let script = format!(
        "import time\nfor ts in {fixed:?}:\n    print(time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(ts)))\n",
    );
    let output = run_python(&script);
    let py_lines: Vec<&str> = output.lines().collect();
    assert_eq!(py_lines.len(), fixed.len());

    for (ts, want) in fixed.iter().zip(py_lines.iter()) {
        let got = iso(Some(*ts));
        assert_eq!(&got, want, "iso({ts}) mismatch");
    }
}

// A-R4-2: `store.iso`'s doc comment (and `rust/DEVIATIONS.md`'s `iso` row)
// claim Python's `time.gmtime` raises an uncaught exception for an
// out-of-range or non-finite timestamp, where this port's `iso` -- whose
// `fn iso(ts: Option<f64>) -> String` signature every caller across the
// crate (including modules outside this work unit) depends on unconditionally
// -- silently returns a computed string instead. Pin both halves of that
// claim: that `python3.12` really does raise for each of these inputs, with
// the exact exception type this file's own module doc/DEVIATIONS.md row
// cites, and the exact string this port's `iso` returns instead of raising.
#[test]
fn iso_matches_python_for_out_of_range_and_non_finite_timestamps_is_a_documented_divergence() {
    let script = r#"
import time

def probe(ts):
    try:
        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
        print("NO ERROR")
    except Exception as e:
        print(type(e).__name__)

probe(1e18)
probe(-1e18)
probe(6.7768e16)
probe(float("nan"))
probe(float("inf"))
probe(float("-inf"))
"#;
    let output = run_python(script);
    let py_errors: Vec<&str> = output.lines().collect();
    assert_eq!(
        py_errors,
        vec![
            "OSError",
            "OSError",
            "OverflowError",
            "ValueError",
            "OverflowError",
            "OverflowError",
        ],
        "python3.12 should raise for every one of these inputs"
    );

    // This port's `iso` never raises for any of them; pin the exact
    // (silently divergent) strings it returns instead.
    assert_eq!(iso(Some(1e18)), "31688740476-10-23T01:46:40Z");
    assert_eq!(iso(Some(-1e18)), "-31688736537-03-10T22:13:20Z");
    assert_eq!(iso(Some(6.7768e16)), "2147484401-02-16T20:26:40Z");
    assert_eq!(iso(Some(f64::NAN)), "1970-01-01T00:00:00Z");
    assert_eq!(iso(Some(f64::INFINITY)), "292277026596-12-04T15:30:07Z");
    assert_eq!(
        iso(Some(f64::NEG_INFINITY)),
        "-292277022657-01-27T08:29:52Z"
    );
}

/// `zeropw.store.iso(ts)` outcome lines for a list of float bit patterns or
/// Python ints: the string itself, or `Class: message` for the exception.
fn python_store_iso(values: &str, decode: &str) -> Vec<String> {
    let script = format!(
        "import struct\nfrom zeropw.store import iso\nfor v in {values}:\n    ts = {decode}\n    try:\n        print(iso(ts))\n    except Exception as e:\n        print(f'{{type(e).__name__}}: {{e}}')\n"
    );
    run_python(&script).lines().map(str::to_owned).collect()
}

fn rust_outcome(result: Result<String, zeropw::store::IsoError>) -> String {
    match result {
        Ok(text) => text,
        Err(error) => format!("{}: {}", error.class_name, error.message),
    }
}

/// Row 68 (A-R4-2): `store.iso` RETURNS a string across the whole range
/// `time.gmtime`/`time.strftime` accept and raises outside it. `try_iso`
/// must reproduce both: the exact string for every accepted value and the
/// exact exception class and message for every rejected one. The table
/// covers each boundary measured on CPython 3.12.14/glibc (time_t, the
/// `tm_year` C-int limits, the wrapped-year `year out of range` band, the
/// smallest year `gmtime` accepts) plus randomized values over the whole
/// `f64` exponent range.
#[test]
fn try_iso_matches_python_store_iso_including_exceptions() {
    let mut values: Vec<f64> = vec![
        0.0,
        -0.0,
        0.5,
        -0.5,
        5e-324,
        -5e-324,
        1e15,
        1e17,
        -1e17,
        1e18,
        -1e18,
        6.7768e16,
        67_767_976_233_532_799.0,
        67_767_976_233_532_800.0,
        67_768_036_191_676_799.0,
        67_768_036_191_676_800.0,
        -67_768_040_609_740_800.0,
        -67_768_040_609_740_808.0,
        9_223_372_036_854_775_807.0,
        -9_223_372_036_854_775_808.0,
        9_223_372_036_854_774_784.0,
        -9_223_372_036_854_777_856.0,
        f64::MAX,
        f64::MIN,
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        -62_167_219_200.0,
        -62_167_219_201.0,
        -62_135_596_800.0,
        253_402_300_800.0,
    ];
    let mut rng = Xorshift64(0x9E37_79B9_7F4A_7C15);
    for _ in 0..400 {
        // Uniform over bit patterns of finite doubles with |x| < 2**64, so
        // every magnitude band (sub-second through past time_t) is sampled.
        let bits = rng.next();
        let exponent = (bits >> 52) & 0x7ff;
        let value = f64::from_bits((bits & !(0x7ff << 52)) | ((exponent % 1087) << 52));
        values.push(value);
    }
    let bits: Vec<u64> = values.iter().map(|v| v.to_bits()).collect();
    let python = python_store_iso(
        &format!("{bits:?}"),
        "struct.unpack('<d', v.to_bytes(8, 'little'))[0]",
    );
    assert_eq!(python.len(), values.len());
    for (value, want) in values.iter().zip(&python) {
        let got = rust_outcome(zeropw::store::try_iso(Some(*value)));
        assert_eq!(&got, want, "try_iso({value:?})");
        if !want.contains(": ") {
            assert_eq!(&iso(Some(*value)), want, "iso({value:?})");
        }
    }
}

/// Row 68: the same contract for a Python `int` argument (a JSON integer in
/// a state document or peer message), where `iso` keeps every second exact
/// beyond `2**53` and rejects anything outside `time_t` with
/// `OverflowError` before `gmtime` is reached.
#[test]
fn try_iso_int_matches_python_store_iso_for_python_ints() {
    let values = [
        "0",
        "-1",
        "9007199254740993",
        "-9007199254740993",
        "67767976233532799",
        "67767976233532800",
        "67768036191676799",
        "67768036191676800",
        "-67768040609740800",
        "-67768040609740801",
        "9223372036854775807",
        "9223372036854775808",
        "-9223372036854775808",
        "-9223372036854775809",
        "1000000000000000000000000000000",
    ];
    let python = python_store_iso(&format!("[{}]", values.join(",")), "v");
    assert_eq!(python.len(), values.len());
    for (value, want) in values.iter().zip(&python) {
        let integer: num_bigint::BigInt = value.parse().unwrap();
        let got = rust_outcome(zeropw::store::try_iso_int(&integer));
        assert_eq!(&got, want, "try_iso_int({value})");
    }
}

/// `IsoError::to_error` renders each escaped `store.iso` exception the way
/// the administrator CLI's handlers print it (checked against the real
/// exception objects run through the same handler order as `admin_cli.main`).
#[test]
fn iso_error_to_error_matches_the_cli_rendering_of_the_python_exception() {
    let script = r#"
import json
from zeropw.store import iso
def render(exc):
    if isinstance(exc, FileNotFoundError):
        return {"error": "FileNotFoundError", "reason": "file_not_found"}
    if isinstance(exc, OSError):
        return {"error": type(exc).__name__, "reason": "io_error", "detail": exc.strerror or ""}
    if isinstance(exc, (KeyError, TypeError, AttributeError, ValueError)):
        return {"error": "StateError", "reason": "state_corrupt", "detail": type(exc).__name__}
    return {"error": type(exc).__name__, "reason": "internal_error"}
for ts in (1e18, float("nan"), float("inf"), 6.7768e16):
    try:
        iso(ts)
        print(json.dumps("ok"))
    except Exception as exc:
        print(json.dumps(render(exc), sort_keys=True))
"#;
    let python: Vec<serde_json::Value> = run_python(script)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let rust: Vec<serde_json::Value> = [1e18, f64::NAN, f64::INFINITY, 6.7768e16]
        .into_iter()
        .map(|ts| zeropw::store::try_iso(Some(ts)).unwrap_err().to_error().to_dict())
        .collect();
    assert_eq!(rust, python);
}
