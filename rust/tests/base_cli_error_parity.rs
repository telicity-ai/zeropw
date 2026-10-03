//! Administrator CLI failures from the environment and from damaged state.
//!
//! Operational failures (an unwritable or missing output directory, a
//! read-only state directory, an unusable `TMPDIR`, a second `init`) keep the
//! exact JSON error the original Python CLI printed. Hand-edited or damaged
//! state (`admin.json`, backup manifests, the audit log, the lock file) only
//! has to fail closed: exit 1, nothing on stdout, a JSON error on stderr and
//! never a secret value.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::Value;

const SECRET: &str = "synthetic-base-cli-secret-value";

fn admin(state: &Path, args: &[&str], env: &[(&str, String)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_zeropw-admin"));
    command
        .arg("--state-dir")
        .arg(state)
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("LC_ALL", "C.UTF-8")
        .env("ZEROPW_ADMIN_PASSPHRASE", "admin-passphrase-1")
        .env("ZEROPW_RECOVERY_PASSPHRASE", "recovery-passphrase-1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in env {
        command.env(name, value);
    }
    let mut child = command.spawn().unwrap();
    drop(child.stdin.take());
    child.wait_with_output().unwrap()
}

fn checked(state: &Path, args: &[&str]) {
    let output = admin(state, args, &[]);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn prepared() -> (tempfile::TempDir, std::path::PathBuf) {
    let temp = tempfile::Builder::new()
        .prefix("zeropw-base-cli-")
        .tempdir()
        .unwrap();
    let state = temp.path().join("state");
    checked(&state, &["init"]);
    checked(&state, &["project", "create", "p"]);
    fs::write(temp.path().join("val"), SECRET).unwrap();
    let value = temp.path().join("val");
    checked(
        &state,
        &[
            "secret", "put", "--id", "x", "--kind", "api_key", "--project", "p",
            "--environment", "dev", "--value-file", value.to_str().unwrap(),
        ],
    );
    (temp, state)
}

fn restore_permissions(root: &Path) {
    for entry in walk(root) {
        if entry.is_dir() {
            fs::set_permissions(&entry, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
}

fn walk(root: &Path) -> Vec<std::path::PathBuf> {
    let mut out = vec![root.to_path_buf()];
    let mut index = 0;
    while index < out.len() {
        let path = out[index].clone();
        index += 1;
        if path.is_dir() && !path.is_symlink() {
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o700));
            for entry in fs::read_dir(&path).unwrap() {
                out.push(entry.unwrap().path());
            }
        }
    }
    out
}

fn assert_exact(output: &Output, tmp: &Path, code: i32, stdout: &str, stderr: &str) {
    let tmp = tmp.to_str().unwrap();
    assert_eq!(output.status.code(), Some(code));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).replace(tmp, "{tmp}"),
        stdout
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).replace(tmp, "{tmp}"),
        stderr
    );
}

fn assert_fails_closed(output: &Output, context: &str) {
    assert_eq!(output.status.code(), Some(1), "{context}");
    assert!(output.stdout.is_empty(), "{context}");
    let error: Value = serde_json::from_slice(&output.stderr)
        .unwrap_or_else(|_| panic!("{context}: {}", String::from_utf8_lossy(&output.stderr)));
    assert!(error["reason"].is_string(), "{context}: {error}");
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains(SECRET),
        "{context}"
    );
}

#[test]
fn operational_failures_keep_the_original_error_json() {
    let io = |detail: &str, class: &str| {
        format!("{{\"detail\": \"{detail}\", \"error\": \"{class}\", \"reason\": \"io_error\"}}\n")
    };
    let denied = io("Permission denied", "PermissionError");
    let cases: [(&str, &[&str], String); 5] = [
        ("kms", &["backup", "--out", "{tmp}/ro/b.json"], denied.clone()),
        (
            "kms",
            &["backup", "--out", "{tmp}/missing/b.json"],
            "{\"error\": \"FileNotFoundError\", \"reason\": \"file_not_found\"}\n".to_owned(),
        ),
        (
            "vault",
            &[
                "secret", "put", "--id", "s", "--kind", "api_key", "--project", "p",
                "--environment", "dev", "--value-file", "{tmp}/val",
            ],
            denied.clone(),
        ),
        ("kms", &["recover"], denied.clone()),
        (".", &["project", "create", "q"], denied.clone()),
    ];
    for (directory, argv, stderr) in cases {
        let (temp, state) = prepared();
        fs::create_dir(temp.path().join("ro")).unwrap();
        fs::set_permissions(temp.path().join("ro"), fs::Permissions::from_mode(0o500)).unwrap();
        fs::set_permissions(state.join(directory), fs::Permissions::from_mode(0o500)).unwrap();
        let tmp = temp.path().to_str().unwrap();
        let argv: Vec<String> = argv.iter().map(|a| a.replace("{tmp}", tmp)).collect();
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        let output = admin(&state, &argv, &[]);
        restore_permissions(temp.path());
        assert_exact(&output, temp.path(), 1, "", &stderr);
    }
}

#[test]
fn an_unusable_tmpdir_falls_back_and_a_second_init_is_refused() {
    let (temp, state) = prepared();
    let tmp = temp.path().to_str().unwrap().to_owned();
    for env in [
        vec![("TMPDIR", "/nonexistent-zeropw".to_owned())],
        vec![("TMPDIR", String::new())],
        vec![
            ("TMPDIR", format!("{tmp}/missing")),
            ("TEMP", tmp.clone()),
        ],
    ] {
        let output = admin(&state, &["secret", "list"], &env);
        assert_eq!(output.status.code(), Some(0), "{env:?}");
        let listed: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(listed["secrets"][0]["id"], "x", "{env:?}");
        assert!(output.stderr.is_empty(), "{env:?}");
    }
    let output = admin(&state, &["init"], &[]);
    assert_exact(
        &output,
        temp.path(),
        1,
        "",
        "{\"detail\": \"{tmp}/state\", \"error\": \"StateError\", \"reason\": \"state_exists\"}\n",
    );
}

#[test]
fn damaged_administrator_record_never_reveals_a_secret() {
    for doc in [
        "{}", "[]", "0", "\"\"", "{\"salt\":1,\"hash\":\"x\"}", "{\"hash\":\"x\"}",
        "{\"salt\":\"\\u00e9\",\"hash\":\"x\"}", "{\"salt\":\"abc\",\"hash\":\"x\"}",
        "{\"salt\":\"AAAA\"}", "{\"salt\":null,\"hash\":\"AAAA\"}", "[1]", "\"str\"", "5", "true",
        "{\"salt\":\"AAAA\",\"hash\":\"@@\"}", "{\"salt\":\"AAAA\",\"hash\":\"AAAA\"}",
        "{\"salt\":\"AAAA\",\"hash\":\"\\u00e9\"}",
    ] {
        let (_temp, state) = prepared();
        fs::write(state.join("admin.json"), doc).unwrap();
        let output = admin(&state, &["secret", "reveal", "--id", "x"], &[]);
        assert_fails_closed(&output, doc);
        let audit = fs::read_to_string(state.join("audit/audit.jsonl")).unwrap();
        assert!(!audit.contains(SECRET), "{doc}");
        assert!(!audit.contains("\"event\":\"secret_reveal\""), "{doc}");
    }
    let (_temp, state) = prepared();
    fs::write(state.join("admin.json"), "{\"salt\":\"abc\",\"hash\":\"x\"}").unwrap();
    assert_fails_closed(&admin(&state, &["restore-ack"], &[]), "restore-ack");
}

#[test]
fn tampered_backup_manifest_is_refused() {
    for sha in [
        Value::from("abc\u{e9}"),
        serde_json::json!(["\u{e9}"]),
        Value::from(5),
    ] {
        let (temp, state) = prepared();
        let archive_path = temp.path().join("b.json");
        checked(&state, &["backup", "--out", archive_path.to_str().unwrap()]);
        let mut archive: Value = serde_json::from_slice(&fs::read(&archive_path).unwrap()).unwrap();
        archive["manifest"]["sha256"] = sha.clone();
        let mut file = fs::File::create(&archive_path).unwrap();
        file.write_all(serde_json::to_string(&archive).unwrap().as_bytes())
            .unwrap();
        drop(file);
        let output = admin(
            &state,
            &["restore", "--in", archive_path.to_str().unwrap()],
            &[],
        );
        assert_fails_closed(&output, &sha.to_string());
    }
}

#[test]
fn damaged_audit_log_or_lock_file_fails_closed() {
    let (_temp, state) = prepared();
    fs::remove_file(state.join("audit/audit.jsonl")).unwrap();
    fs::create_dir(state.join("audit/audit.jsonl")).unwrap();
    assert_fails_closed(&admin(&state, &["audit", "tail"], &[]), "audit dir");

    let (_temp, state) = prepared();
    let mut audit = fs::OpenOptions::new()
        .append(true)
        .open(state.join("audit/audit.jsonl"))
        .unwrap();
    audit.write_all(b"\xff\xfe\n").unwrap();
    drop(audit);
    assert_fails_closed(&admin(&state, &["audit", "tail"], &[]), "audit utf-8");

    let (_temp, state) = prepared();
    let lock = state.join(".lock");
    if lock.exists() {
        fs::remove_file(&lock).unwrap();
    }
    fs::create_dir(&lock).unwrap();
    assert_fails_closed(
        &admin(&state, &["project", "create", "q"], &[]),
        "lock dir",
    );
}
