//! Independent Astra follow-up boundaries for the session and prompt fixes.
mod cli_pty;

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use zeropw::context::{Config, Context};
use zeropw::runs::{self, RunRegistry};

#[test]
fn ar_runtime_07_terminal_status_never_precedes_captured_output_publication() {
    let temp = TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            temp.path().join("state"),
            "synthetic-admin-passphrase",
            "synthetic-recovery-passphrase",
            Config::default(),
            zeropw::clock::system(),
        )
        .unwrap(),
    );
    let registry = RunRegistry::new(ctx.clone(), 1024, 0.05);
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let listener_gate = gate.clone();
    let (entered_tx, entered_rx) = mpsc::channel();
    ctx.audit.subscribe(move |record| {
        if record.get("event").and_then(serde_json::Value::as_str) == Some("run_finish") {
            entered_tx
                .send((
                    record.get("result").cloned(),
                    record.get("run_state").cloned(),
                    record.get("exit_code").cloned(),
                    record.get("bytes").cloned(),
                ))
                .unwrap();
            let (lock, cv) = &*listener_gate;
            let guard = lock.lock().unwrap();
            let _ = cv
                .wait_timeout_while(guard, Duration::from_secs(5), |released| !*released)
                .unwrap();
        }
    });
    let run = registry.create(
        "alice", "service", "grant", "http", "printf", None, "digest", None, None,
    );
    let run_start = Instant::now();
    let started_run = registry
        .start(
            &run,
            &["/usr/bin/printf".into(), "business-output".into()],
            &HashMap::new(),
            temp.path(),
            &[],
            None,
            Some(3.0),
        )
        .unwrap();
    let start_elapsed_ms = run_start.elapsed().as_millis();
    let audit_finish = entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    // A correct implementation may block this query until finalization is
    // complete, or expose a nonterminal state. Neither permits completed/empty.
    let (tx, rx) = mpsc::channel();
    let (query_registry, query_run) = (registry.clone(), run.clone());
    let query = std::thread::spawn(move || {
        tx.send(query_registry.get(&query_run.id, "alice").unwrap())
            .unwrap();
    });
    let early = rx.recv_timeout(Duration::from_millis(200)).ok();
    let (lock, cv) = &*gate;
    *lock.lock().unwrap() = true;
    cv.notify_all();
    query.join().unwrap();
    let final_result = registry.wait(&run, Some(5.0));
    assert_eq!(
        final_result.stdout,
        b"business-output",
        "start_state={}, start_reason={:?}, start_elapsed_ms={start_elapsed_ms}, state={}, reason={:?}, exit_code={:?}, timed_out={}, cancel_requested={}, stderr_bytes={}, stdout_truncated={}, stderr_truncated={}, audit_finish={audit_finish:?}, elapsed_ms={}",
        started_run.state,
        started_run.reason,
        final_result.state,
        final_result.reason,
        final_result.exit_code,
        final_result.timed_out,
        final_result.cancel_requested,
        final_result.stderr.len(),
        final_result.stdout_truncated,
        final_result.stderr_truncated,
        run_start.elapsed().as_millis(),
    );
    assert_eq!(final_result.state, "completed");
    if let Some(observed) = early {
        assert!(
            !runs::TERMINAL_STATES.contains(&observed.state.as_str())
                || observed.stdout == b"business-output",
            "terminal status was visible before the actual output: state={}, stdout={:?}",
            observed.state,
            observed.stdout
        );
    }
}

#[test]
fn ar_cli_02_interrupt_restores_original_terminal_modes() {
    cli_pty::check_admin_terminal_abort("interrupt", cli_pty::Inherited::Default);
}

#[test]
fn terminal_eof_restores_original_terminal_modes() {
    cli_pty::check_admin_terminal_abort("eof", cli_pty::Inherited::Default);
}

/// The keeper itself must notice a command that leaves the terminal changed
/// or does not finish; otherwise the restoration checks above prove nothing.
#[test]
fn terminal_keeper_detects_unrestored_modes_and_overstaying_commands() {
    let unrestored: Vec<std::ffi::OsString> =
        vec!["/bin/sh".into(), "-c".into(), "stty -echo".into()];
    let mut session = cli_pty::start_keeper(
        &unrestored,
        &[("PATH", "/usr/bin:/bin")],
        5.0,
        cli_pty::Inherited::Default,
    );
    let result = session.result(Duration::from_secs(10));
    session.wait_exit(Duration::from_secs(5));
    assert_eq!(result["terminated"], true, "{result}");
    assert_eq!(result["code"], 0, "{result}");
    assert_eq!(result["restored"], false, "{result}");

    let overstaying: Vec<std::ffi::OsString> = vec!["/bin/sleep".into(), "30".into()];
    let mut session = cli_pty::start_keeper(
        &overstaying,
        &[("PATH", "/usr/bin:/bin")],
        0.5,
        cli_pty::Inherited::Default,
    );
    let result = session.result(Duration::from_secs(10));
    session.wait_exit(Duration::from_secs(5));
    assert_eq!(result["terminated"], false, "{result}");
    assert_eq!(result["restored"], true, "{result}");
}
