//! Process-level SIGINT/SIGTERM exit status of the administrator CLI, with a
//! surviving controlling-PTY keeper (see `cli_pty`). Synthetic state only.
//! The expected statuses are the original CLI's: 130 after SIGINT, death by
//! SIGTERM, and a graceful exit 0 for `serve`.

mod cli_pty;

use std::ffi::OsString;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;

use cli_pty::{Inherited, default_signals, kill, return_code, wait_child};

const ADMIN: &str = env!("CARGO_BIN_EXE_zeropw-admin");

fn expected_code(signal: i32) -> i64 {
    if signal == libc::SIGINT {
        130
    } else {
        -i64::from(signal)
    }
}

#[test]
fn administrator_prompt_signal_status_matches_the_original_and_restores_terminal() {
    let temp = tempfile::TempDir::new().unwrap();
    for phase in ["during", "after"] {
        for signal in [libc::SIGINT, libc::SIGTERM] {
            let state = temp.path().join(format!("{phase}-{signal}"));
            cli_pty::init_state(
                &state,
                "synthetic-admin-sigint",
                "synthetic-recovery-sigint",
            );
            let argv: Vec<OsString> = vec![
                ADMIN.into(),
                "--state-dir".into(),
                state.clone().into(),
                "restore-ack".into(),
            ];
            let mut session =
                cli_pty::start_keeper(&argv, &[("PATH", "/usr/bin:/bin")], 4.0, Inherited::Default);
            session.wait_for(
                &["Administrator passphrase:", "CHILD_PID="],
                Duration::from_secs(3),
            );
            let child = session.child_pid();
            assert!(!session.slave_echo(), "prompt has echo ({phase} {signal})");
            let mut anchor = None;
            if phase == "after" {
                // Keep the process alive after the password is consumed;
                // only the synthetic administrator verification read waits.
                std::fs::rename(state.join("admin.json"), state.join("admin.saved")).unwrap();
                cli_pty::mkfifo(&state.join("admin.json"));
                anchor = Some(cli_pty::fifo_anchor(&state.join("admin.json")));
                session.write(b"synthetic-admin-sigint\n");
                let end = std::time::Instant::now() + Duration::from_secs(3);
                while !session.slave_echo() {
                    assert!(std::time::Instant::now() < end, "echo not restored");
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            std::thread::sleep(Duration::from_millis(150));
            kill(child, signal);
            let result = session.result(Duration::from_secs(7));
            session.wait_exit(Duration::from_secs(3));
            drop(anchor);
            assert_eq!(result["terminated"], true, "{phase} {signal} {result}");
            assert_eq!(result["restored"], true, "{phase} {signal} {result}");
            assert_eq!(
                result["code"].as_i64(),
                Some(expected_code(signal)),
                "{phase} {signal} {result}"
            );
        }
    }
}

#[test]
fn administrator_serve_keeps_its_graceful_signal_stop() {
    let temp = tempfile::TempDir::new().unwrap();
    for signal in [libc::SIGINT, libc::SIGTERM] {
        let state = temp.path().join(format!("serve-{signal}"));
        cli_pty::init_state(&state, "synthetic-admin-serve", "synthetic-recovery-serve");
        let mut command = Command::new(ADMIN);
        command
            .arg("--state-dir")
            .arg(&state)
            .args(["serve", "--quiet"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = default_signals(&mut command).spawn().unwrap();
        let mut line = String::new();
        // The native banner follows the installation of both handlers.
        BufReader::new(child.stdout.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        let payload: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert!(
            payload["url"]
                .as_str()
                .unwrap()
                .starts_with("http://127.0.0.1:"),
            "{payload}"
        );
        kill(child.id() as i32, signal);
        let status = wait_child(&mut child, Duration::from_secs(5));
        let mut stderr = String::new();
        std::io::Read::read_to_string(child.stderr.as_mut().unwrap(), &mut stderr).unwrap();
        assert_eq!(status.code(), Some(0), "{signal}: {stderr}");
        assert!(stderr.is_empty(), "{signal}: {stderr}");
    }
}

#[test]
fn ordinary_non_prompt_command_catches_sigint_as_exit_130() {
    let temp = tempfile::TempDir::new().unwrap();
    for signal in [libc::SIGINT, libc::SIGTERM] {
        let state = temp.path().join(format!("fifo-{signal}"));
        cli_pty::init_state(&state, "synthetic-admin-fifo", "synthetic-recovery-fifo");
        let fifo = state.join("synthetic-secret-input");
        cli_pty::mkfifo(&fifo);
        let anchor = cli_pty::fifo_anchor(&fifo);
        let source = File::open(&fifo).unwrap();
        let mut command = Command::new(ADMIN);
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
            .env("ZEROPW_ADMIN_PASSPHRASE", "synthetic-admin-fifo")
            .stdin(source)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = default_signals(&mut command).spawn().unwrap();
        std::thread::sleep(Duration::from_secs(1));
        assert!(
            child.try_wait().unwrap().is_none(),
            "command did not block on FIFO"
        );
        kill(child.id() as i32, signal);
        let status = wait_child(&mut child, Duration::from_secs(5));
        drop(anchor);
        assert_eq!(return_code(status), expected_code(signal), "{signal}");
    }
}
