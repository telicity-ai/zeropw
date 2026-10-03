//! Independent gpt-6-astra lifecycle review of product fix d2c87eb at 76e4eed.
//! Synthetic state, controlled children, and real local PTYs only.
mod cli_pty;

use std::process::Command;
use std::time::Duration;

#[test]
fn terminal_prompt_completion_preserves_later_interrupt_and_termination() {
    check_terminal_signals("after");
}

#[test]
fn active_terminal_prompt_restores_modes_on_sigterm() {
    check_terminal_signals("during");
}

fn check_terminal_signals(phase: &str) {
    let temp = tempfile::TempDir::new().unwrap();
    let signals: &[i32] = if phase == "after" {
        &[libc::SIGINT, libc::SIGTERM]
    } else {
        &[libc::SIGTERM]
    };
    for &signal in signals {
        let state = temp.path().join(format!("{phase}-{signal}"));
        cli_pty::init_state(
            &state,
            "synthetic-admin-round4",
            "synthetic-recovery-round4",
        );
        let argv: Vec<std::ffi::OsString> = vec![
            env!("CARGO_BIN_EXE_zeropw-admin").into(),
            "--state-dir".into(),
            state.clone().into(),
            "restore-ack".into(),
        ];
        let mut session = cli_pty::start_keeper(
            &argv,
            &[("PATH", "/usr/bin:/bin")],
            4.0,
            cli_pty::Inherited::Default,
        );
        session.wait_for(
            &["Administrator passphrase:", "CHILD_PID="],
            Duration::from_secs(3),
        );
        let child = session.child_pid();
        assert!(!session.slave_echo(), "visible prompt had echo");
        let mut anchor = None;
        if phase == "after" {
            // Delay only the synthetic verification input after the prompt.
            std::fs::rename(state.join("admin.json"), state.join("admin.saved")).unwrap();
            cli_pty::mkfifo(&state.join("admin.json"));
            anchor = Some(cli_pty::fifo_anchor(&state.join("admin.json")));
            session.write(b"synthetic-admin-round4\n");
            let end = std::time::Instant::now() + Duration::from_secs(3);
            while !session.slave_echo() {
                assert!(
                    std::time::Instant::now() < end,
                    "prompt never restored echo"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        std::thread::sleep(Duration::from_millis(150));
        cli_pty::kill(child, signal);
        let result = session.result(Duration::from_secs(7));
        session.wait_exit(Duration::from_secs(3));
        drop(anchor);
        assert_eq!(result["terminated"], true, "{phase} {signal} {result}");
        assert_eq!(result["restored"], true, "{phase} {signal} {result}");
    }
}

#[test]
fn native_agent_help_is_a_successful_offline_operation() {
    for arguments in [vec!["--help"], vec!["-h"], vec!["request", "--help"]] {
        let native = Command::new(env!("CARGO_BIN_EXE_zeropw-agent"))
            .args(&arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();
        assert!(
            native.status.success(),
            "{arguments:?}: native code={:?} stderr={}",
            native.status.code(),
            String::from_utf8_lossy(&native.stderr)
        );
        assert!(native.stderr.is_empty());
        assert!(String::from_utf8_lossy(&native.stdout).contains("usage:"));
    }
}

#[test]
fn finish_audit_callback_can_cancel_another_live_run() {
    use std::{
        collections::HashMap,
        sync::{Arc, mpsc},
        time::Duration,
    };
    use zeropw::{
        context::{Config, Context},
        runs::RunRegistry,
    };
    let temp = tempfile::TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            temp.path().join("state"),
            "synthetic-admin",
            "synthetic-recovery",
            Config::default(),
            zeropw::clock::system(),
        )
        .unwrap(),
    );
    let registry = RunRegistry::new(ctx.clone(), 1024, 0.05);
    let sibling = registry.create(
        "alice", "service", "grant", "http", "sleep", None, "a", None, None,
    );
    registry
        .start(
            &sibling,
            &["/bin/sleep".into(), "20".into()],
            &HashMap::new(),
            temp.path(),
            &[],
            None,
            Some(30.0),
        )
        .unwrap();
    let finisher = registry.create(
        "alice", "service", "grant", "http", "printf", None, "b", None, None,
    );
    let finisher_id = finisher.id.clone();
    let weak = Arc::downgrade(&registry);
    let (tx, rx) = mpsc::channel();
    ctx.audit.subscribe(move |record| {
        if record.get("event").and_then(serde_json::Value::as_str) == Some("run_finish")
            && record.get("run_id").and_then(serde_json::Value::as_str) == Some(&finisher_id)
        {
            let registry = weak.upgrade().unwrap();
            let view = registry.get(&finisher_id, "alice").unwrap();
            let cancelled = registry.cancel_all("audit_peer_stop", None);
            tx.send((view, cancelled)).unwrap();
        }
    });
    registry
        .start(
            &finisher,
            &["/usr/bin/printf".into(), "business-output".into()],
            &HashMap::new(),
            temp.path(),
            &[],
            None,
            Some(3.0),
        )
        .unwrap();
    let observed = rx.recv_timeout(Duration::from_secs(5));
    let finished = registry.wait(&finisher, Some(5.0));
    let sibling_done = registry.wait(&sibling, Some(5.0));
    registry.cancel_all("test_cleanup", None);
    let (early, cancelled) = observed.unwrap();
    assert_eq!(early.state, "running");
    assert!(early.stdout.is_empty() && early.stderr.is_empty());
    assert_eq!(cancelled, 1);
    assert_eq!(sibling_done.state, "cancelled");
    assert_eq!(sibling_done.reason.as_deref(), Some("audit_peer_stop"));
    assert_eq!(finished.state, "completed");
    assert_eq!(finished.stdout, b"business-output");
}
