//! Differential-test helper: run the Python prototype as the behavioural oracle.
//!
//! `python(script)` executes `script` with `python3.12` (override with the
//! `ZEROPW_PYTHON` env var) and the repository root on `PYTHONPATH`, so the
//! script can `import zeropw...`. It returns stdout and panics with stderr on a
//! non-zero exit. Tests use it to compare Rust output byte-for-byte with the
//! Python implementation (JSON bytes, wire bytes, digests, error reasons) and
//! to exchange state directories in both directions.

use std::path::PathBuf;
use std::process::Command;

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().expect("repo root").to_path_buf()
}

pub fn python(script: &str) -> String {
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".to_string());
    let output = Command::new(&interpreter)
        .arg("-c")
        .arg(script)
        .env("PYTHONPATH", repo_root())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .unwrap_or_else(|e| panic!("cannot run {interpreter}: {e}"));
    if !output.status.success() {
        panic!(
            "python oracle failed ({}):\n--- script ---\n{script}\n--- stderr ---\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout).expect("oracle stdout is UTF-8")
}

#[cfg(test)]
mod tests {
    #[test]
    fn oracle_imports_prototype() {
        let out = super::python("from zeropw.errors import NotFound\nprint(NotFound().to_dict())");
        assert_eq!(out.trim(), "{'error': 'NotFound', 'reason': 'not_found'}");
    }
}
