//! Independent gpt-6-astra CLI/runtime round-two probes; all state is synthetic.
mod cli_pty;

use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use zeropw::context::{Config, Context};
use zeropw::runs::RunRegistry;

fn context() -> (TempDir, Arc<Context>) {
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
    (temp, ctx)
}

#[test]
fn ar_runtime_05_unrelated_inheritable_descriptor_is_closed_in_agent_child() {
    let (temp, ctx) = context();
    let synthetic_path = temp.path().join("trusted-synthetic-descriptor");
    std::fs::write(&synthetic_path, b"synthetic-trusted-fd-value-round2").unwrap();
    let file = std::fs::File::open(&synthetic_path).unwrap();
    rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::empty()).unwrap();
    let registry = RunRegistry::new(ctx, 1024, 0.05);
    let run = registry.create(
        "alice", "service", "grant", "http", "sh", None, "digest", None, None,
    );
    // The redirection fails (and `closed` is printed) only if the trusted
    // descriptor did not reach the child; an open one would print its value.
    let script = format!("/bin/cat <&{} 2>/dev/null || echo closed", file.as_raw_fd());
    registry
        .start(
            &run,
            &["/bin/sh".into(), "-c".into(), script],
            &HashMap::new(),
            temp.path(),
            &[],
            None,
            Some(3.0),
        )
        .unwrap();
    rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::CLOEXEC).unwrap();
    let result = registry.wait(&run, Some(5.0));
    assert_eq!(result.state, "completed");
    assert_eq!(
        result.stdout, b"closed\n",
        "an unrelated inheritable trusted descriptor must not reach the agent child (close_fds)"
    );
}

#[test]
fn ar_runtime_06_http_execution_accepts_uncreated_configured_socket_directory() {
    let temp = TempDir::new().unwrap();
    let socket_dir = temp.path().join("provided-sockets");
    let ctx = Arc::new(
        Context::initialize(
            temp.path().join("state"),
            "synthetic-admin-passphrase",
            "synthetic-recovery-passphrase",
            Config {
                socket_dir: Some(socket_dir.clone()),
                run_dir: Some(temp.path().join("provided-runs")),
                ..Config::default()
            },
            zeropw::clock::system(),
        )
        .unwrap(),
    );
    assert!(!socket_dir.exists());
    let registry = RunRegistry::new(ctx, 1024, 0.05);
    let run = registry.create(
        "alice", "service", "grant", "http", "true", None, "digest", None, None,
    );
    registry
        .start(
            &run,
            &["/usr/bin/true".into()],
            &HashMap::new(),
            temp.path(),
            &[],
            None,
            Some(3.0),
        )
        .unwrap();
    let result = registry.wait(&run, Some(5.0));
    assert_eq!(
        result.state, "completed",
        "HTTP-only child unexpectedly failed: {:?}",
        result.reason
    );
}

#[test]
fn ar_cli_01_terminal_prompts_hide_both_passphrases() {
    let temp = TempDir::new().unwrap();
    let argv: Vec<std::ffi::OsString> = vec![
        env!("CARGO_BIN_EXE_zeropw-admin").into(),
        "--state-dir".into(),
        temp.path().join("state").into(),
        "init".into(),
    ];
    let mut session = cli_pty::start_direct(&argv, &[("PATH", "/usr/bin:/bin")]);
    session.wait_for(&["Administrator passphrase:"], Duration::from_secs(10));
    session.write(b"synthetic-tty-admin-round2\n");
    session.wait_for(&["Recovery passphrase:"], Duration::from_secs(10));
    session.write(b"synthetic-tty-recovery-round2\n");
    let status = session.wait_exit(Duration::from_secs(15));
    let data = String::from_utf8_lossy(&session.data).into_owned();
    assert_eq!(status.code(), Some(0), "{data:?}");
    assert!(!data.contains("synthetic-tty-admin-round2"), "{data:?}");
    assert!(!data.contains("synthetic-tty-recovery-round2"), "{data:?}");
    assert!(data.contains("kms_key_id"), "{data:?}");
}
