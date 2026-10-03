//! Owner-scoped administrator shutdown cleanup: on ordinary exit, error and
//! interrupt the CLI removes exactly the runtime directories its context
//! created under `TMPDIR`, never identically prefixed ones it did not create.

mod cli_pty;

use std::ffi::OsString;
use std::fs::File;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use cli_pty::{Inherited, default_signals, kill, names, wait_child};

const ADMIN: &str = env!("CARGO_BIN_EXE_zeropw-admin");
const SENTINELS: [&str; 2] = ["zeropw-runs-adopted", "zeropw-sockets-adopted"];

#[test]
fn ordinary_exit_and_interrupt_remove_only_owned_context_directories() {
    let temp = tempfile::TempDir::new().unwrap();
    for outcome in ["signal", "success", "error"] {
        let base = temp.path().join(outcome);
        std::fs::create_dir(&base).unwrap();
        let state = base.join("state");
        cli_pty::init_state(&state, "synthetic-admin-cleanup", "synthetic-recovery-cleanup");
        let owned = base.join("temp");
        std::fs::create_dir(&owned).unwrap();
        // Identically prefixed unowned paths must never be removed by a scan.
        for name in SENTINELS {
            std::fs::create_dir(owned.join(name)).unwrap();
        }
        let mut command = Command::new(ADMIN);
        command
            .arg("--state-dir")
            .arg(&state)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("TMPDIR", &owned)
            .env("ZEROPW_ADMIN_PASSPHRASE", "synthetic-admin-cleanup")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if outcome == "success" {
            command.args(["secret", "list"]);
        } else {
            command.args([
                "secret", "put", "--id", "synthetic", "--kind", "api_key", "--project", "demo",
                "--environment", "dev", "--stdin",
            ]);
        }
        let mut anchor = None;
        if outcome == "signal" {
            let fifo = base.join("input");
            cli_pty::mkfifo(&fifo);
            anchor = Some(cli_pty::fifo_anchor(&fifo));
            command.stdin(File::open(&fifo).unwrap());
        } else {
            command.stdin(Stdio::null());
        }
        let mut child = default_signals(&mut command).spawn().unwrap();
        if outcome == "signal" {
            let end = Instant::now() + Duration::from_secs(5);
            while names(&owned).len() != 4 {
                assert!(
                    child.try_wait().unwrap().is_none() && Instant::now() < end,
                    "context dirs missing"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            std::thread::sleep(Duration::from_millis(150));
            kill(child.id() as i32, libc::SIGINT);
        }
        let status = wait_child(&mut child, Duration::from_secs(5));
        drop(anchor);
        assert_eq!(names(&owned), SENTINELS, "{outcome}");
        let expected = match outcome {
            "signal" => 130,
            "success" => 0,
            _ => 1,
        };
        assert_eq!(status.code(), Some(expected), "{outcome}");
    }
}

#[test]
fn active_prompt_sigint_restores_terminal_and_removes_owned_context_directories() {
    let temp = tempfile::TempDir::new().unwrap();
    let state = temp.path().join("state");
    cli_pty::init_state(&state, "synthetic-admin-cleanup", "synthetic-recovery-cleanup");
    let owned = temp.path().join("temp");
    std::fs::create_dir(&owned).unwrap();
    for name in SENTINELS {
        std::fs::create_dir(owned.join(name)).unwrap();
    }
    let argv: Vec<OsString> = vec![
        ADMIN.into(),
        "--state-dir".into(),
        state.into(),
        "restore-ack".into(),
    ];
    let owned_text = owned.to_str().unwrap().to_owned();
    let mut session = cli_pty::start_keeper(
        &argv,
        &[("PATH", "/usr/bin:/bin"), ("TMPDIR", &owned_text)],
        4.0,
        Inherited::Default,
    );
    session.wait_for(
        &["Administrator passphrase:", "CHILD_PID="],
        Duration::from_secs(5),
    );
    assert!(!session.slave_echo(), "echo visible");
    assert_eq!(names(&owned).len(), 4, "owned dirs absent");
    kill(session.child_pid(), libc::SIGINT);
    let result = session.result(Duration::from_secs(7));
    session.wait_exit(Duration::from_secs(3));
    assert_eq!(result["code"], 130, "{result}");
    assert_eq!(result["restored"], true, "{result}");
    assert_eq!(names(&owned), SENTINELS);
}
