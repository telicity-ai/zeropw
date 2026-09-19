//! Differential-test helper: run the Python prototype as the behavioural oracle.
//!
//! `python(script)` executes `script` with `python3.12` (override with the
//! `ZEROPW_PYTHON` env var) and the repository root on `PYTHONPATH`, so the
//! script can `import zeropw...`. It returns stdout and panics with stderr on a
//! non-zero exit. Tests use it to compare Rust output byte-for-byte with the
//! Python implementation (JSON bytes, wire bytes, digests, error reasons) and
//! to exchange state directories in both directions.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

pub fn python(script: &str) -> String {
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".to_string());
    // Feed the script over stdin instead of argv. Large differential probes
    // can exceed Linux's ARG_MAX even though the same invocation fits on
    // macOS; `python -` has the same execution semantics without an
    // operating-system-dependent command-line ceiling.
    let mut child = Command::new(&interpreter)
        .arg("-")
        .env("PYTHONPATH", repo_root())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot run {interpreter}: {e}"));
    child
        .stdin
        .take()
        .expect("piped stdin is present")
        .write_all(script.as_bytes())
        .unwrap_or_else(|e| panic!("cannot write script to {interpreter}: {e}"));
    let output = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("cannot wait for {interpreter}: {e}"));
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

    #[test]
    fn oracle_accepts_a_script_larger_than_linux_arg_max() {
        let mut script = "#".repeat(300_000);
        script.push_str("\nprint('ok')\n");
        assert_eq!(super::python(&script), "ok\n");
    }
}
