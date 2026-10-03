//! Independent SIGINT cleanup after opening synthetic Context state: the
//! interrupted command exits 130, silently, and removes the runtime and
//! socket directories its context created.

mod cli_pty;

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use cli_pty::{default_signals, kill, names, wait_child};

#[test]
fn ordinary_sigint_removes_context_owned_runtime_directories() {
    let temp = tempfile::TempDir::new().unwrap();
    let state = temp.path().join("state");
    cli_pty::init_state(&state, "synthetic-admin-cleanup", "synthetic-recovery-cleanup");
    let fifo = state.join("synthetic-input");
    cli_pty::mkfifo(&fifo);
    let anchor = cli_pty::fifo_anchor(&fifo);
    let owned = temp.path().join("owned");
    std::fs::create_dir(&owned).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_zeropw-admin"));
    command
        .arg("--state-dir")
        .arg(&state)
        .args([
            "secret", "put", "--id", "synthetic", "--kind", "api_key", "--project", "demo",
            "--environment", "dev", "--stdin",
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("ZEROPW_ADMIN_PASSPHRASE", "synthetic-admin-cleanup")
        .env("TMPDIR", &owned)
        .stdin(File::open(&fifo).unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = default_signals(&mut command).spawn().unwrap();
    let end = Instant::now() + Duration::from_secs(5);
    while names(&owned).len() != 2 {
        assert!(
            child.try_wait().unwrap().is_none() && Instant::now() < end,
            "no context dirs"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let before = names(&owned);
    assert!(before.iter().any(|x| x.starts_with("zeropw-runs-")), "{before:?}");
    assert!(before.iter().any(|x| x.starts_with("zeropw-sockets-")), "{before:?}");
    std::thread::sleep(Duration::from_millis(150));
    kill(child.id() as i32, libc::SIGINT);
    let status = wait_child(&mut child, Duration::from_secs(5));
    let output = child.wait_with_output().unwrap();
    drop(anchor);
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert_eq!(status.code(), Some(130));
    assert!(names(&owned).is_empty(), "{:?}", names(&owned));
}
