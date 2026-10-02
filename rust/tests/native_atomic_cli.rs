//! Cross-process equivalent of the original CLI check/write race boundary.
use std::{
    io::Write,
    process::{Child, Command, Output, Stdio},
    time::Duration,
};
use zeropw::context::{Config, Context};

fn spawn(state: &str, args: &[&str], input: Option<&[u8]>) -> Child {
    let mut child = Command::new(env!("CARGO_BIN_EXE_zeropw-admin"))
        .args(["--state-dir", state])
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("ZEROPW_ADMIN_PASSPHRASE", "synthetic-admin-passphrase")
        .env(
            "ZEROPW_RECOVERY_PASSPHRASE",
            "synthetic-recovery-passphrase",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(bytes) = input {
        child.stdin.take().unwrap().write_all(bytes).unwrap();
    } else {
        drop(child.stdin.take());
    }
    child
}
fn ok(output: Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn native_connection_and_secret_writers_cannot_both_commit_a_vault_value_in_cli_env() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    let path = state.to_str().unwrap();
    ok(spawn(path, &["init"], None).wait_with_output().unwrap());
    ok(spawn(path, &["project", "create", "demo"], None)
        .wait_with_output()
        .unwrap());
    let put = [
        "secret",
        "put",
        "--id",
        "base",
        "--kind",
        "api_key",
        "--project",
        "demo",
        "--environment",
        "dev",
        "--stdin",
    ];
    ok(
        spawn(path, &put, Some(b"synthetic-initial-secret-0123456789"))
            .wait_with_output()
            .unwrap(),
    );
    let ctx = Context::open(&state, Config::default(), zeropw::clock::system()).unwrap();
    for attempt in 0..24 {
        let value = format!("synthetic-race-value-{attempt:02}-abcdef0123456789");
        let assignment = format!("PUBLIC_LABEL={value}");
        let id = format!("raced-{attempt}");
        let create = [
            "connection",
            "create-http",
            "--id",
            &id,
            "--project",
            "demo",
            "--environment",
            "dev",
            "--service",
            "local-test",
            "--secret-id",
            "base",
            "--target",
            "http://127.0.0.1:9",
            "--auth",
            "bearer",
            "--cli-program",
            "/usr/bin/true",
            "--cli-env",
            &assignment,
        ];
        // Start both independent native processes behind the same state lock.
        // Alternate launch order; neither writer may commit while it is held.
        let lock = ctx.state.lock().unwrap();
        let (mut a, mut b) = if attempt % 2 == 0 {
            (
                spawn(path, &create, None),
                spawn(path, &put, Some(value.as_bytes())),
            )
        } else {
            let b = spawn(path, &put, Some(value.as_bytes()));
            (spawn(path, &create, None), b)
        };
        std::thread::sleep(Duration::from_millis(20));
        assert!(a.try_wait().unwrap().is_none());
        assert!(b.try_wait().unwrap().is_none());
        drop(lock);
        let a = a.wait_with_output().unwrap();
        let b = b.wait_with_output().unwrap();
        let mut codes = [a.status.code().unwrap(), b.status.code().unwrap()];
        codes.sort();
        assert_eq!(
            codes,
            [0, 1],
            "exactly one writer may succeed in iteration {attempt}"
        );
        let in_policy = std::fs::read_to_string(state.join("policy/connections.json"))
            .unwrap_or_default()
            .contains(&value);
        let in_vault = ctx
            .vault
            .values_for_trusted_scan()
            .unwrap()
            .iter()
            .any(|v| v.expose() == value.as_bytes());
        assert!(!(in_policy && in_vault), "check/write was not atomic");
        for output in [a, b] {
            // If connection creation won, this is still ordinary public
            // configuration: the competing vault write was refused.
            if in_vault {
                assert!(!String::from_utf8_lossy(&output.stdout).contains(&value));
            }
            assert!(!String::from_utf8_lossy(&output.stderr).contains(&value));
        }
    }
}
