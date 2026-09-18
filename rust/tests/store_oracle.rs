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
