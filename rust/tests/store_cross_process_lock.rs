//! Integration test: `StateDir::lock`'s `flock` must interoperate with a
//! Python process holding `fcntl.flock` on the same `<state>/.lock` file
//! (rust/PORTING.md requires proving this, not just asserting it).
//!
//! This lives under `rust/tests/` (a separate test binary) rather than
//! inline in `store.rs` because it needs to *overlap in time* with a live
//! Python subprocess holding the lock, unlike the oracle module's
//! run-to-completion-then-diff helper (`crate::oracle::python`, which is
//! `#[cfg(test)] pub(crate)` and so isn't reachable from here anyway).

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use zeropw::store::StateDir;

fn repo_root() -> PathBuf {
    // rust/tests/.. -> rust -> repo root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn python_interpreter() -> String {
    std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".to_string())
}

/// A Python single-quoted string literal for `p` (test paths are plain
/// tempdir paths with no quotes/backslashes, so this only needs to escape
/// what could plausibly show up, not be a general-purpose quoter).
fn py_str_literal(p: &Path) -> String {
    let s = p.to_str().expect("utf8 path");
    let escaped = s.replace('\\', "\\\\").replace('\'', "\\'");
    format!("'{escaped}'")
}

/// Spawns a Python process that acquires the `fcntl.flock` on `<state>/.lock`
/// (creating the state dir first, exactly like `StateDir.lock` does), prints
/// "locked" once it holds it, then holds it for `hold_secs` before releasing
/// and exiting. Returns the child so the caller can wait for it.
fn spawn_python_lock_holder(state_path: &Path, hold_secs: f64) -> std::process::Child {
    let script = format!(
        r#"
import fcntl, os, sys, time
path = {path}
os.makedirs(path, mode=0o700, exist_ok=True)
fd = os.open(os.path.join(path, ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
print("locked", flush=True)
time.sleep({hold_secs})
fcntl.flock(fd, fcntl.LOCK_UN)
os.close(fd)
"#,
        path = py_str_literal(state_path),
        hold_secs = hold_secs,
    );
    Command::new(python_interpreter())
        .arg("-c")
        .arg(script)
        .env("PYTHONPATH", repo_root())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn python lock holder")
}

#[test]
fn rust_lock_blocks_until_python_flock_releases() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state_path = tmp.path().join("state");

    let mut child = spawn_python_lock_holder(&state_path, 0.6);
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .expect("python signals it holds the lock");
    assert_eq!(line.trim(), "locked");

    // Python now holds the OS-level flock. StateDir::lock() must block until
    // it releases -- prove it by timing the acquisition.
    let state = StateDir::new(&state_path);
    let start = Instant::now();
    let guard = state.lock().expect("lock acquires after python releases");
    let waited = start.elapsed();
    drop(guard);

    let status = child.wait().expect("python exits cleanly");
    assert!(status.success());
    assert!(
        waited >= Duration::from_millis(400),
        "Rust acquired the lock after only {waited:?}; it should have blocked \
         for close to the 600ms Python held the flock (mutual exclusion did not hold)"
    );
}

#[test]
fn python_flock_blocks_until_rust_lock_releases() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state_path = tmp.path().join("state");

    // Rust takes the lock first and holds it in a background thread for a
    // fixed duration, signalling readiness over a channel.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let hold = Duration::from_millis(600);
    let state_path_for_thread = state_path.clone();
    let handle = std::thread::spawn(move || {
        let state = StateDir::new(&state_path_for_thread);
        let _guard = state.lock().unwrap();
        ready_tx.send(()).unwrap();
        std::thread::sleep(hold);
    });
    ready_rx
        .recv()
        .expect("rust thread signals it holds the lock");

    // Python tries to flock the same file: it must block until Rust's
    // thread above drops its guard (releasing the flock).
    let script = format!(
        r#"
import fcntl, os, time
path = {path}
os.makedirs(path, mode=0o700, exist_ok=True)
fd = os.open(os.path.join(path, ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
start = time.time()
fcntl.flock(fd, fcntl.LOCK_EX)
print(time.time() - start)
fcntl.flock(fd, fcntl.LOCK_UN)
os.close(fd)
"#,
        path = py_str_literal(&state_path),
    );
    let output = Command::new(python_interpreter())
        .arg("-c")
        .arg(&script)
        .env("PYTHONPATH", repo_root())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run python flock waiter");
    assert!(
        output.status.success(),
        "python stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let waited: f64 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("python prints a float");

    handle.join().unwrap();
    assert!(
        waited >= 0.4,
        "python's flock() returned after only {waited}s; it should have blocked for close to \
         the 600ms Rust held the lock (mutual exclusion did not hold)"
    );
}

// Also make sure a plain StateDir round trip (no lock contention) still
// exercises the state dir this file's `state` path helper builds, so a
// refactor that breaks `StateDir::create`/`lock` for a fresh directory
// fails here too, not just in unit tests.
#[test]
fn state_dir_lock_is_reusable_after_release() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    {
        let _g = state.lock().unwrap();
    }
    {
        let _g = state.lock().unwrap();
    }
}
