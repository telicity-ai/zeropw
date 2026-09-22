//! End-to-end CLI contract checks using only synthetic credentials and loopback sockets.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::thread;

use serde_json::Value;

fn admin(state: &str, args: &[&str], input: Option<&[u8]>) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_zeropw-admin"))
        .arg("--state-dir")
        .arg(state)
        .args(args)
        .env("ZEROPW_ADMIN_PASSPHRASE", "admin-passphrase-1")
        .env("ZEROPW_RECOVERY_PASSPHRASE", "recovery-passphrase-1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input).unwrap();
    }
    child.wait_with_output().unwrap()
}

fn json_output(out: &std::process::Output) -> Value {
    let raw = if out.status.success() {
        &out.stdout
    } else {
        &out.stderr
    };
    let text = std::str::from_utf8(raw).unwrap();
    if out.status.success() {
        serde_json::from_str(text).unwrap()
    } else {
        serde_json::from_str(text.lines().last().unwrap()).unwrap()
    }
}

#[test]
fn admin_local_flow_and_value_hygiene() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    let path = state.to_str().unwrap();
    let out = admin(path, &["init"], None);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(json_output(&out)["kms_key_id"], "local-dev-kms-1");
    assert!(
        admin(path, &["project", "create", "demo"], None)
            .status
            .success()
    );
    let secret = b"synthetic-token-0123456789abcdef\n";
    let out = admin(
        path,
        &[
            "secret",
            "put",
            "--id",
            "gh-token",
            "--kind",
            "api_key",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--stdin",
        ],
        Some(secret),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(json_output(&out)["version"], 1);
    let listed = admin(path, &["secret", "list"], None);
    assert!(listed.status.success());
    assert!(
        !listed
            .stdout
            .windows(secret.len() - 1)
            .any(|w| w == &secret[..secret.len() - 1])
    );
    let encoded=base64::Engine::encode(&base64::engine::general_purpose::STANDARD,&secret[..secret.len()-1]);
    let assignment=format!("X_TRACE={encoded}");
    let rejected=admin(path,&["connection","create-http","--id","gh-encoded","--project","demo","--environment","dev","--service","fake","--secret-id","gh-token","--target","http://127.0.0.1:9876","--auth","bearer","--cli-program","/bin/echo","--cli-env",&assignment],None);
    assert_eq!(rejected.status.code(),Some(1));
    assert_eq!(json_output(&rejected)["reason"],"cli_env_contains_credential");
    let out = admin(
        path,
        &[
            "connection",
            "create-http",
            "--id",
            "gh",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--service",
            "fake",
            "--secret-id",
            "gh-token",
            "--target",
            "http://127.0.0.1:9876",
            "--auth",
            "bearer",
        ],
        None,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        json_output(&out)["http_scope"]["methods"],
        serde_json::json!(["GET", "HEAD"])
    );
    let out = admin(path, &["principal", "create", "--id", "agent-1"], None);
    assert!(out.status.success());
    assert!(
        json_output(&out)["token"]
            .as_str()
            .unwrap()
            .starts_with("zpwc_")
    );
    let out = admin(
        path,
        &[
            "grant",
            "create",
            "--principal",
            "agent-1",
            "--connection",
            "gh",
        ],
        None,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(json_output(&out)["status"], "active");
    let out = admin(path, &["secret", "reveal", "--id", "gh-token"], None);
    assert!(out.status.success());
    assert_eq!(
        json_output(&out)["value"],
        "synthetic-token-0123456789abcdef"
    );
    let declared=admin(path,&["incident","declare","--scope","principal","--principal","agent-1"],None);
    assert!(declared.status.success(),"{}",String::from_utf8_lossy(&declared.stderr));
    let id=json_output(&declared)["id"].as_str().unwrap().to_owned();
    let shown=admin(path,&["incident","show","--id",&id],None);
    assert_eq!(json_output(&shown)["scope"],"principal");
    let closed=admin(path,&["incident","close","--id",&id],None);
    assert_eq!(json_output(&closed)["status"],"closed");
    let out = admin(
        path,
        &[
            "secret",
            "put",
            "--id",
            "bad",
            "--kind",
            "api_key",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--value",
            "synthetic-token-0123456789abcdef",
        ],
        None,
    );
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(json_output(&out)["reason"], "usage");
    assert_eq!(json_output(&out)["detail"],"unrecognized arguments: 2 (not accepted: --value); values are not echoed");
    assert!(
        !out.stderr
            .windows(secret.len() - 1)
            .any(|w| w == &secret[..secret.len() - 1])
    );
}

#[test]
fn agent_posts_json_without_redirect_or_token_echo() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = socket.read(&mut buf).unwrap();
        let request = String::from_utf8_lossy(&buf[..n]);
        assert!(request.starts_with("POST /v1/tools/list_connections HTTP/1.1"));
        assert!(request.contains("Authorization: Bearer zpwc_synthetic-caller"));
        let reply=b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 18\r\nConnection: close\r\n\r\n{\"connections\": []}";
        socket.write_all(reply).unwrap();
    });
    let out = Command::new(env!("CARGO_BIN_EXE_zeropw-agent"))
        .arg("list-connections")
        .env("ZEROPW_GATEWAY_URL", format!("http://127.0.0.1:{port}"))
        .env("ZEROPW_CALLER_TOKEN", "zpwc_synthetic-caller")
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(json_output(&out)["connections"], serde_json::json!([]));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("zpwc_synthetic-caller"));
}
