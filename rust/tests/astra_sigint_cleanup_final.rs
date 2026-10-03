//! Independent negative ownership boundary for the administrator cleanup fix.
mod cli_pty;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use cli_pty::{default_signals, kill, names, wait_child};

#[test]
fn interrupt_preserves_unowned_same_prefix_directories_and_their_contents() {
    let temp = tempfile::TempDir::new().unwrap();
    let state = temp.path().join("state");
    cli_pty::init_state(
        &state,
        "synthetic-admin-cleanup",
        "synthetic-recovery-cleanup",
    );
    let fifo = state.join("synthetic-input");
    cli_pty::mkfifo(&fifo);
    let anchor = cli_pty::fifo_anchor(&fifo);
    let owned = temp.path().join("owned");
    std::fs::create_dir(&owned).unwrap();
    let unowned = ["zeropw-runs-unowned", "zeropw-sockets-unowned"];
    for name in unowned {
        std::fs::create_dir(owned.join(name)).unwrap();
        std::fs::write(
            owned.join(name).join("sentinel"),
            b"synthetic-unowned-content",
        )
        .unwrap();
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_zeropw-admin"));
    command
        .arg("--state-dir")
        .arg(&state)
        .args([
            "secret",
            "put",
            "--id",
            "synthetic",
            "--kind",
            "api_key",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--stdin",
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("ZEROPW_ADMIN_PASSPHRASE", "synthetic-admin-cleanup")
        .env("TMPDIR", &owned)
        .stdin(std::fs::File::open(&fifo).unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = default_signals(&mut command).spawn().unwrap();
    let end = Instant::now() + Duration::from_secs(5);
    while names(&owned).len() != 4 {
        assert!(
            child.try_wait().unwrap().is_none() && Instant::now() < end,
            "no context dirs"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(Duration::from_millis(150));
    kill(child.id() as i32, libc::SIGINT);
    let status = wait_child(&mut child, Duration::from_secs(5));
    let output = child.wait_with_output().unwrap();
    drop(anchor);
    for name in unowned {
        assert_eq!(
            std::fs::read(owned.join(name).join("sentinel")).unwrap(),
            b"synthetic-unowned-content"
        );
    }
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert_eq!(status.code(), Some(130));
    assert_eq!(names(&owned), unowned);
}

#[test]
fn pre_context_validation_errors_do_not_create_owned_directories() {
    let temp = tempfile::TempDir::new().unwrap();
    let owned = temp.path().join("private-temp");
    std::fs::create_dir(&owned).unwrap();
    for args in [vec!["project", "list"], vec!["init"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_zeropw-admin"))
            .arg("--state-dir")
            .arg(temp.path().join("absent-state"))
            .args(&args)
            .env_clear()
            .env("TMPDIR", &owned)
            .env("ZEROPW_ADMIN_PASSPHRASE", "short")
            .env("ZEROPW_RECOVERY_PASSPHRASE", "synthetic-recovery")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(
            error["reason"],
            if args[0] == "init" {
                "passphrase_too_short"
            } else {
                "state_missing"
            }
        );
        assert_eq!(std::fs::read_dir(&owned).unwrap().count(), 0);
        assert!(!temp.path().join("absent-state").exists());
    }
}
