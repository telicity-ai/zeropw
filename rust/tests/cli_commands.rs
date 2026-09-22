//! End-to-end CLI contract checks using only synthetic credentials and loopback sockets.
use std::io::BufRead;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

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
    if let Ok(value) = serde_json::from_str(text) {
        value
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
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &secret[..secret.len() - 1],
    );
    let assignment = format!("X_TRACE={encoded}");
    let rejected = admin(
        path,
        &[
            "connection",
            "create-http",
            "--id",
            "gh-encoded",
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
            "--cli-program",
            "/bin/echo",
            "--cli-env",
            &assignment,
        ],
        None,
    );
    assert_eq!(rejected.status.code(), Some(1));
    assert_eq!(
        json_output(&rejected)["reason"],
        "cli_env_contains_credential"
    );
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
    let declared = admin(
        path,
        &[
            "incident",
            "declare",
            "--scope",
            "principal",
            "--principal",
            "agent-1",
        ],
        None,
    );
    assert!(
        declared.status.success(),
        "{}",
        String::from_utf8_lossy(&declared.stderr)
    );
    let id = json_output(&declared)["id"].as_str().unwrap().to_owned();
    let shown = admin(path, &["incident", "show", "--id", &id], None);
    assert_eq!(json_output(&shown)["scope"], "principal");
    let closed = admin(path, &["incident", "close", "--id", &id], None);
    assert_eq!(json_output(&closed)["status"], "closed");
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
    assert_eq!(
        json_output(&out)["detail"],
        "unrecognized arguments: 2 (not accepted: --value); values are not echoed"
    );
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
        let reply=b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 19\r\nConnection: close\r\n\r\n{\"connections\": []}";
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

#[test]
fn agent_finishes_content_length_response_before_keepalive_close() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = [0u8; 4096];
        let _read = socket.read(&mut request).unwrap();
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 19\r\nConnection: keep-alive\r\n\r\n{\"connections\": []}").unwrap();
        thread::sleep(Duration::from_secs(2));
    });
    let started = Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_zeropw-agent"))
        .arg("list-connections")
        .env("ZEROPW_GATEWAY_URL", format!("http://127.0.0.1:{port}"))
        .env("ZEROPW_CALLER_TOKEN", "zpwc_synthetic-caller")
        .output()
        .unwrap();
    let elapsed = started.elapsed();
    server.join().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        elapsed < Duration::from_millis(1800),
        "waited for socket close: {elapsed:?}"
    );
}

#[test]
fn admin_nonterminal_missing_passphrase_is_redacted() {
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_zeropw-admin"))
        .args([
            "--state-dir",
            temp.path().join("state").to_str().unwrap(),
            "init",
        ])
        .env_remove("ZEROPW_ADMIN_PASSPHRASE")
        .env_remove("ZEROPW_RECOVERY_PASSPHRASE")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(json_output(&output)["reason"], "passphrase_missing");
}

#[cfg(target_os = "macos")]
#[test]
fn admin_terminal_prompts_without_echo() {
    if !std::path::Path::new("/usr/bin/script").exists() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    let mut child = Command::new("/usr/bin/script")
        .args([
            "-q",
            "/dev/null",
            env!("CARGO_BIN_EXE_zeropw-admin"),
            "--state-dir",
            state.to_str().unwrap(),
            "init",
        ])
        .env_remove("ZEROPW_ADMIN_PASSPHRASE")
        .env_remove("ZEROPW_RECOVERY_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    let mut seen = Vec::new();
    let prompts = [
        (
            b"Administrator passphrase: ".as_slice(),
            b"pty-admin-passphrase-1\n".as_slice(),
        ),
        (
            b"Recovery passphrase: ".as_slice(),
            b"pty-recovery-passphrase-1\n".as_slice(),
        ),
    ];
    for (prompt, secret) in prompts {
        let mut one = [0u8; 1];
        while !seen.ends_with(prompt) {
            output.read_exact(&mut one).unwrap();
            seen.push(one[0]);
            assert!(seen.len() < 32_768, "terminal prompt not seen");
        }
        thread::sleep(Duration::from_millis(50));
        input.write_all(secret).unwrap();
    }
    drop(input);
    output.read_to_end(&mut seen).unwrap();
    assert!(child.wait().unwrap().success());
    assert!(state.exists());
    assert!(
        !seen
            .windows(b"pty-admin-passphrase-1".len())
            .any(|w| w == b"pty-admin-passphrase-1")
    );
    assert!(
        !seen
            .windows(b"pty-recovery-passphrase-1".len())
            .any(|w| w == b"pty-recovery-passphrase-1")
    );
}

#[test]
fn native_democli_matches_whoami_issue_and_exposure_contract() {
    for (args, path, response, expected) in [
        (
            vec!["whoami"],
            "/me",
            "{\"login\":\"synthetic-user\"}",
            "synthetic-user",
        ),
        (
            vec!["create-issue", "demo", "Hello issue"],
            "/repos/demo/issues",
            "{\"title\":\"Hello issue\"}",
            "Hello issue",
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let n = socket.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..n]);
            assert!(request.contains(&format!(" {path} HTTP/1.1")));
            assert!(request.contains("Authorization: Bearer democli-placeholder"));
            assert!(request.contains("User-Agent: democli/1"));
            if path.contains("issues") {
                assert!(request.contains("POST "));
                assert!(request.contains("\"title\":\"Hello issue\""));
            }
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                response.len()
            );
            socket.write_all(reply.as_bytes()).unwrap();
        });
        let out = Command::new(env!("CARGO_BIN_EXE_zeropw-democli"))
            .args(args)
            .env("ZEROPW_API_BASE_URL", format!("http://127.0.0.1:{port}"))
            .output()
            .unwrap();
        server.join().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
        let body: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(body["body"].to_string().contains(expected));
    }

    let temp = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_zeropw-democli"))
        .args(["steal", "--please"])
        .env("HOME", temp.path())
        .env(
            "ZEROPW_API_BASE_URL",
            "http://127.0.0.1:1/h/opaque-synthetic-handle",
        )
        .output()
        .unwrap();
    assert!(out.status.success());
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["argv"], serde_json::json!(["steal", "--please"]));
    assert_eq!(
        report["base_url"],
        "http://127.0.0.1:1/h/<opaque-handle-redacted>"
    );
    assert_eq!(report["home_entries"], serde_json::json!([]));
    assert_eq!(report["probes"].as_object().unwrap().len(), 8);
    assert!(!String::from_utf8_lossy(&out.stdout).contains("opaque-synthetic-handle"));

    let missing = Command::new(env!("CARGO_BIN_EXE_zeropw-democli"))
        .arg("whoami")
        .env_remove("ZEROPW_API_BASE_URL")
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&missing.stdout).unwrap()["error"],
        "base_url_unset"
    );
}

#[test]
fn agent_binary_body_and_refusal_go_to_stderr() {
    let temp = tempfile::tempdir().unwrap();
    let body = temp.path().join("body.bin");
    std::fs::write(&body, [0xff, 0x00, 0x41]).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut buf = [0u8; 8192];
        let n = socket.read(&mut buf).unwrap();
        let request = String::from_utf8_lossy(&buf[..n]);
        assert!(request.starts_with("POST /v1/tools/request HTTP/1.1"));
        assert!(request.contains("\"method\": \"POST\""));
        assert!(request.contains("\"body_base64\": \"/wBB\""));
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\nConnection: close\r\n\r\n{\"reason\":\"credential_header_unsafe\",\"status\":501}").unwrap();
    });
    let out = Command::new(env!("CARGO_BIN_EXE_zeropw-agent"))
        .args([
            "request",
            "--connection",
            "gh",
            "--method",
            "post",
            "--path",
            "/repos",
            "--body-file",
            body.to_str().unwrap(),
        ])
        .env("ZEROPW_GATEWAY_URL", format!("http://127.0.0.1:{port}"))
        .env("ZEROPW_CALLER_TOKEN", "zpwc_synthetic-caller")
        .output()
        .unwrap();
    server.join().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty(), "agent stderr empty");
    assert_eq!(json_output(&out)["reason"], "credential_header_unsafe");
}

#[test]
fn serve_and_agent_list_roundtrip() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    let path = state.to_str().unwrap();
    assert!(admin(path, &["init"], None).status.success());
    assert!(
        admin(path, &["project", "create", "demo"], None)
            .status
            .success()
    );
    assert!(
        admin(
            path,
            &[
                "secret",
                "put",
                "--id",
                "test-token",
                "--kind",
                "api_key",
                "--project",
                "demo",
                "--environment",
                "dev",
                "--stdin"
            ],
            Some(b"synthetic-test-token\n")
        )
        .status
        .success()
    );
    assert!(
        admin(
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
                "test-token",
                "--target",
                "http://127.0.0.1:9876",
                "--auth",
                "bearer"
            ],
            None
        )
        .status
        .success()
    );
    let principal = admin(path, &["principal", "create", "--id", "agent-1"], None);
    let token = json_output(&principal)["token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        admin(
            path,
            &[
                "grant",
                "create",
                "--principal",
                "agent-1",
                "--connection",
                "gh"
            ],
            None
        )
        .status
        .success()
    );
    let mut server = Command::new(env!("CARGO_BIN_EXE_zeropw-admin"))
        .args([
            "--state-dir",
            path,
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--quiet",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut reader = std::io::BufReader::new(server.stdout.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let startup: Value = serde_json::from_str(&line).unwrap();
    let url = startup["url"].as_str().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_zeropw-agent"))
        .arg("list-connections")
        .env("ZEROPW_GATEWAY_URL", url)
        .env("ZEROPW_CALLER_TOKEN", token)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(json_output(&out)["connections"][0]["id"], "gh");
    server.kill().unwrap();
    server.wait().unwrap();
}

#[test]
fn demo_passes_without_printing_credentials() {
    // Referencing both binary paths makes Cargo build the credential-free child CLI too.
    let _child_cli = env!("CARGO_BIN_EXE_zeropw-democli");
    let out = Command::new(env!("CARGO_BIN_EXE_zeropw-demo"))
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.matches("[PASS]").count() >= 25);
    for forbidden in [
        "[FAIL]",
        "zpwc_",
        "zpw1.",
        "PRIVATE KEY",
        "synthetic-token-",
    ] {
        assert!(!text.contains(forbidden), "demo leaked {forbidden}");
    }
}

#[test]
fn team_share_and_member_views_are_value_free() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    let path = state.to_str().unwrap();
    assert!(admin(path, &["init"], None).status.success());
    assert!(
        admin(path, &["project", "create", "demo"], None)
            .status
            .success()
    );
    let init = admin(path, &["team", "init"], None);
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    assert!(json_output(&init)["fingerprint"].as_str().is_some());
    let shared = admin(
        path,
        &["team", "share", "--project", "demo", "--environment", "dev"],
        None,
    );
    assert!(
        shared.status.success(),
        "{}",
        String::from_utf8_lossy(&shared.stderr)
    );
    let env_id = json_output(&shared)["env_id"].as_str().unwrap().to_owned();
    let members = admin(path, &["team", "members", "--env", "demo/dev"], None);
    assert!(
        members.status.success(),
        "{}",
        String::from_utf8_lossy(&members.stderr)
    );
    assert_eq!(json_output(&members)["env_id"], env_id);
    assert_eq!(json_output(&members)["members"][0]["role"], "admin");
    let shown = admin(path, &["team", "show", "--env", "demo/dev"], None);
    assert!(shown.status.success());
    assert!(!shown.stdout.windows(10).any(|w| w == b"ciphertext"));
    let status = admin(path, &["team", "status", "--env", "demo/dev"], None);
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
}
