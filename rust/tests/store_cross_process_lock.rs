//! Integration test: `StateDir::lock` takes the same OS-level lock the Python
//! prototype took -- `flock(LOCK_EX)` on `<state>/.lock`, opened
//! `O_RDWR | O_CREAT` with mode 0600 -- so it excludes (and is excluded by) any
//! other process locking a state directory that way, including a prototype
//! process still running against the same directory during an upgrade.
//!
//! The other party is this test binary re-executed as a child process that
//! performs exactly the prototype's `os.open` + `fcntl.flock` sequence with
//! raw `flock(2)`; the two must overlap in time, so the child signals over
//! its stdout.

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rustix::fs::{FlockOperation, Mode, OFlags};
use zeropw::store::StateDir;

const CHILD_ENV: &str = "ZEROPW_FLOCK_CHILD";

/// The prototype's lock acquisition: `os.makedirs(path, 0o700,
/// exist_ok=True)`, `os.open(path/.lock, O_RDWR|O_CREAT, 0o600)`,
/// `fcntl.flock(fd, LOCK_EX)`.
fn raw_flock(state_path: &Path) -> rustix::fd::OwnedFd {
    std::fs::create_dir_all(state_path).unwrap();
    let fd = rustix::fs::open(
        state_path.join(".lock"),
        OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .unwrap();
    rustix::fs::flock(&fd, FlockOperation::LockExclusive).unwrap();
    fd
}

/// Runs in the re-executed child: `hold:<ms>:<path>` takes the lock, prints
/// `locked`, holds it for `<ms>`; `wait:<path>` measures how long taking the
/// lock blocks and prints `waited=<seconds>`.
fn child_main(spec: &str) {
    if let Some(rest) = spec.strip_prefix("hold:") {
        let (ms, path) = rest.split_once(':').unwrap();
        let fd = raw_flock(Path::new(path));
        println!("locked");
        std::thread::sleep(Duration::from_millis(ms.parse().unwrap()));
        rustix::fs::flock(&fd, FlockOperation::Unlock).unwrap();
    } else if let Some(path) = spec.strip_prefix("wait:") {
        let start = Instant::now();
        let fd = raw_flock(Path::new(path));
        println!("waited={}", start.elapsed().as_secs_f64());
        rustix::fs::flock(&fd, FlockOperation::Unlock).unwrap();
    } else {
        panic!("unknown child spec {spec}");
    }
}

fn spawn_child(test_name: &str, spec: String) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args([test_name, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, spec)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn lock child")
}

/// Reads child stdout lines until one contains `prefix` and returns what
/// follows it (libtest prints its own banner lines around the child's output).
fn read_until(reader: &mut impl BufRead, prefix: &str) -> String {
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).unwrap();
        assert!(n > 0, "child exited before printing {prefix:?}");
        // libtest may print `test <name> ... ` on the same line first.
        if let Some(at) = line.find(prefix) {
            return line[at + prefix.len()..].trim().to_string();
        }
    }
}

#[test]
fn rust_lock_blocks_until_a_raw_flock_holder_releases() {
    if let Ok(spec) = std::env::var(CHILD_ENV) {
        return child_main(&spec);
    }
    let tmp = tempfile::TempDir::new().unwrap();
    let state_path = tmp.path().join("state");

    let mut child = spawn_child(
        "rust_lock_blocks_until_a_raw_flock_holder_releases",
        format!("hold:600:{}", state_path.display()),
    );
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    read_until(&mut reader, "locked");

    // The child now holds the OS-level flock. StateDir::lock() must block
    // until it releases -- prove it by timing the acquisition.
    let state = StateDir::new(&state_path);
    let start = Instant::now();
    let guard = state
        .lock()
        .expect("lock acquires after the holder releases");
    let waited = start.elapsed();
    drop(guard);

    let status = child.wait().expect("child exits");
    assert!(status.success());
    assert!(
        waited >= Duration::from_millis(400),
        "Rust acquired the lock after only {waited:?}; it should have blocked \
         for close to the 600ms the other process held the flock"
    );
}

#[test]
fn raw_flock_blocks_until_rust_lock_releases() {
    if let Ok(spec) = std::env::var(CHILD_ENV) {
        return child_main(&spec);
    }
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

    let mut child = spawn_child(
        "raw_flock_blocks_until_rust_lock_releases",
        format!("wait:{}", state_path.display()),
    );
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let waited: f64 = read_until(&mut reader, "waited=").parse().unwrap();
    assert!(child.wait().unwrap().success());

    handle.join().unwrap();
    assert!(
        waited >= 0.4,
        "the other process's flock() returned after only {waited}s; it should have \
         blocked for close to the 600ms Rust held the lock"
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
