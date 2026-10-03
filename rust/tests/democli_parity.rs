//! Contract for the sample business CLI: the native `zeropw-democli` prints
//! the bytes, exits with the status and sends the upstream request recorded
//! from the original `examples/democli.py` for the same arguments,
//! environment and upstream replies (`fixtures/python/cli/democli.json`,
//! see its `GENERATE.md`).
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

use regex::Regex;
use serde_json::{Value, json};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/python/cli/democli.json")).unwrap()
}

/// Serve one connection answering with `reply`; return the request line,
/// sorted lower-cased headers (without library framing) and body.
fn serve(reply: Vec<u8>) -> (u16, thread::JoinHandle<Value>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(socket.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let mut headers = Vec::new();
        let mut length = 0usize;
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).unwrap();
            let header = header.trim_end().to_owned();
            if header.is_empty() {
                break;
            }
            let (name, value) = header.split_once(':').unwrap();
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_owned();
            if name == "content-length" {
                length = value.parse().unwrap();
            }
            headers.push((name, value));
        }
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body).unwrap();
        let mut socket = socket;
        socket.write_all(&reply).unwrap();
        let _ = socket.shutdown(std::net::Shutdown::Both);
        // Library-specific framing headers are not part of the CLI contract.
        headers.retain(|(name, _)| {
            !matches!(name.as_str(), "accept-encoding" | "connection" | "host")
        });
        headers.sort();
        json!([{
            "line": line.trim_end(),
            "headers": headers.into_iter().map(|(n, v)| json!([n, v])).collect::<Vec<_>>(),
            "body": String::from_utf8(body).unwrap(),
        }])
    });
    (port, handle)
}

fn run(args: &[&str], env: &[(&str, String)]) -> (Option<i32>, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_zeropw-democli"));
    command
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("LC_ALL", "C.UTF-8")
        .current_dir(repo_root());
    for (name, value) in env {
        command.env(name, value);
    }
    let out = command.output().unwrap();
    (out.status.code(), String::from_utf8(out.stdout).unwrap())
}

fn args(case: &Value) -> Vec<&str> {
    case["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap())
        .collect()
}

fn code(case: &Value) -> Option<i32> {
    case["code"].as_i64().map(|c| c as i32)
}

#[test]
fn business_output_and_upstream_request_match_the_original_cli() {
    // Nested, unsorted keys and non-ASCII text exercise `sort_keys` and
    // `ensure_ascii`; a non-2xx business status is printed with exit 1.
    let fixture = fixture();
    let cases = fixture["upstream"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for case in cases {
        let body = case["reply_body"].as_str().unwrap().as_bytes();
        let mut reply = format!(
            "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            case["status"].as_str().unwrap(),
            body.len()
        )
        .into_bytes();
        reply.extend_from_slice(body);
        let (port, server) = serve(reply);
        let base = format!(
            "http://127.0.0.1:{port}{}",
            case["base_suffix"].as_str().unwrap()
        );
        let args = args(case);
        let (status, stdout) = run(&args, &[("ZEROPW_API_BASE_URL", base)]);
        let seen = server.join().unwrap();
        assert_eq!(status, code(case), "exit status for {args:?}");
        assert_eq!(
            stdout,
            case["stdout"].as_str().unwrap(),
            "stdout for {args:?}"
        );
        assert_eq!(seen, case["requests"], "upstream request for {args:?}");
    }
}

#[test]
fn usage_and_validation_errors_match_the_original_cli() {
    // The repository is validated before the base URL is read.
    let fixture = fixture();
    let cases = fixture["plain"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    for case in cases {
        let env: Vec<(&str, String)> = case["env"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str().unwrap().to_owned()))
            .collect();
        let args = args(case);
        let (status, stdout) = run(&args, &env);
        assert_eq!(status, code(case), "exit status for {args:?}");
        assert_eq!(
            stdout,
            case["stdout"].as_str().unwrap(),
            "stdout for {args:?}"
        );
    }
}

#[test]
fn unreachable_gateway_reports_the_socket_error_like_urllib() {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let fixture = fixture();
    let case = &fixture["unreachable"];
    let (status, stdout) = run(
        &args(case),
        &[("ZEROPW_API_BASE_URL", format!("http://127.0.0.1:{port}"))],
    );
    assert_eq!(status, code(case));
    assert!(stdout.contains("\"error\": \"unreachable\""), "{stdout}");
    // The socket error text is the platform's own.
    let errno = Regex::new(r#"\[Errno -?\d+\] [^"\\]*"#).unwrap();
    assert!(errno.is_match(&stdout), "{stdout}");
    assert_eq!(
        errno.replace_all(&stdout, "[Errno <N>] <MSG>"),
        case["stdout"].as_str().unwrap()
    );
}

#[test]
fn steal_report_matches_the_original_cli() {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join(".netrc"), b"machine example").unwrap();
    // `.ssh` is a file, so `.ssh/id_ed25519` is NotADirectoryError.
    std::fs::write(home.path().join(".ssh"), b"x").unwrap();
    std::fs::create_dir_all(home.path().join(".config/zeropw")).unwrap();
    let home_text = home.path().to_string_lossy().to_string();
    let fixture = fixture();
    let cases = fixture["steal"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for case in cases {
        let mut env = Vec::new();
        if let Some(base) = case["base"].as_str() {
            env.push(("HOME", home_text.clone()));
            if !base.is_empty() {
                env.push(("ZEROPW_API_BASE_URL", base.to_owned()));
            }
        }
        let args = args(case);
        let (status, stdout) = run(&args, &env);
        assert_eq!(status, code(case), "exit status for {args:?}");
        assert_eq!(
            stdout.replace(&home_text, "{home}"),
            case["stdout"].as_str().unwrap(),
            "stdout for {args:?}"
        );
        assert!(!stdout.contains("opaque-synthetic-handle"), "{stdout}");
    }
    let last = cases.last().unwrap()["stdout"].as_str().unwrap();
    assert!(last.contains("\"no home\""), "{last}");
}
