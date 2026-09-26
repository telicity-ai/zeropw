//! Differential contract for the sample business CLI: the native
//! `zeropw-democli` must print the same bytes and exit with the same status as
//! the original `examples/democli.py` for the same arguments, environment and
//! upstream replies. Python is only the oracle; both run as separate processes.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn python() -> String {
    std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".into())
}

/// One recorded request: request line, lower-cased header names, body.
#[derive(Debug, PartialEq)]
struct Seen {
    line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Serve `count` connections, answering each with `reply`; return what was received.
fn serve(count: usize, reply: Vec<u8>) -> (u16, thread::JoinHandle<Vec<Seen>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..count {
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
            headers.retain(|(name, _)| {
                // Library-specific framing headers are not part of the CLI contract.
                !matches!(name.as_str(), "accept-encoding" | "connection" | "host")
            });
            headers.sort();
            seen.push(Seen {
                line: line.trim_end().to_owned(),
                headers,
                body,
            });
        }
        seen
    });
    (port, handle)
}

struct Outcome {
    code: Option<i32>,
    stdout: String,
}

fn run(program: &[String], args: &[&str], env: &[(&str, String)]) -> Outcome {
    let mut command = Command::new(&program[0]);
    command
        .args(&program[1..])
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("LC_ALL", "C.UTF-8")
        .current_dir(repo_root());
    for (name, value) in env {
        command.env(name, value);
    }
    let out = command.output().unwrap();
    Outcome {
        code: out.status.code(),
        stdout: String::from_utf8(out.stdout).unwrap(),
    }
}

fn programs() -> [Vec<String>; 2] {
    [
        vec![
            python(),
            repo_root()
                .join("examples/democli.py")
                .to_string_lossy()
                .into(),
        ],
        vec![env!("CARGO_BIN_EXE_zeropw-democli").to_owned()],
    ]
}

/// Run the same case against both programs, each with a fresh upstream, and
/// require identical output, status and upstream request.
/// An HTTP/1.1 reply with a correct Content-Length.
fn reply(status: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn same_with_upstream(args: &[&str], reply: Vec<u8>, base_suffix: &str) {
    let mut results = Vec::new();
    for program in programs() {
        let (port, server) = serve(1, reply.clone());
        let env = [(
            "ZEROPW_API_BASE_URL",
            format!("http://127.0.0.1:{port}{base_suffix}"),
        )];
        let outcome = run(&program, args, &env);
        let seen = server.join().unwrap();
        results.push((outcome.code, outcome.stdout, seen));
    }
    let (native, original) = (results.pop().unwrap(), results.pop().unwrap());
    assert_eq!(native.0, original.0, "exit status for {args:?}");
    assert_eq!(native.1, original.1, "stdout for {args:?}");
    assert_eq!(native.2, original.2, "upstream request for {args:?}");
}

fn same_without_upstream(args: &[&str], env: &[(&str, String)]) -> String {
    let [original, native] = programs();
    let expected = run(&original, args, env);
    let actual = run(&native, args, env);
    assert_eq!(actual.code, expected.code, "exit status for {args:?}");
    assert_eq!(actual.stdout, expected.stdout, "stdout for {args:?}");
    actual.stdout
}

#[test]
fn business_output_is_byte_identical_to_the_original_cli() {
    // Nested, unsorted keys and non-ASCII text exercise `sort_keys` and `ensure_ascii`.
    same_with_upstream(
        &["whoami"],
        reply(
            "200 OK",
            "{\"z\": 1, \"login\": \"synthetic\", \"a\": {\"y\": [1.5, \"\u{e9}\"]}}".as_bytes(),
        ),
        "",
    );
    same_with_upstream(&["list-repos"], reply("200 OK", b"not json!"), "/h/opaque");
    same_with_upstream(
        &["create-issue", "demo", "Hello \u{c774}\u{c288}"],
        reply("201 Created", b"{\"number\": 7.0e0}"),
        "",
    );
    // A non-2xx business status is still printed, with exit status 1.
    same_with_upstream(
        &["whoami"],
        reply("404 Not Found", b"{\"error\": \"missing\"}"),
        "",
    );
}

#[test]
fn usage_and_validation_errors_match_the_original_cli() {
    let base = [("ZEROPW_API_BASE_URL", "http://127.0.0.1:9".to_owned())];
    same_without_upstream(&[], &base);
    same_without_upstream(&["delete-everything"], &base);
    same_without_upstream(&["create-issue", "demo"], &base);
    same_without_upstream(&["create-issue", "../x", "t"], &base);
    // The repository is validated before the base URL is read.
    same_without_upstream(&["create-issue", "a/b", "t"], &[]);
    same_without_upstream(&["whoami"], &[]);
    same_without_upstream(&["whoami"], &[("ZEROPW_API_BASE_URL", "   ".into())]);
}

#[test]
fn unreachable_gateway_reports_the_socket_error_like_urllib() {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let out = same_without_upstream(
        &["list-repos"],
        &[("ZEROPW_API_BASE_URL", format!("http://127.0.0.1:{port}"))],
    );
    assert!(out.contains("\"error\": \"unreachable\""), "{out}");
    assert!(out.contains("[Errno "), "{out}");
}

#[test]
fn steal_report_matches_the_original_cli() {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join(".netrc"), b"machine example").unwrap();
    // `.ssh` is a file, so `.ssh/id_ed25519` is NotADirectoryError.
    std::fs::write(home.path().join(".ssh"), b"x").unwrap();
    std::fs::create_dir_all(home.path().join(".config/zeropw")).unwrap();
    let home_text = home.path().to_string_lossy().to_string();
    for base in [
        "http://127.0.0.1:1/h/opaque-synthetic-handle".to_owned(),
        "http://127.0.0.1:1/other".to_owned(),
        String::new(),
    ] {
        let mut env = vec![("HOME", home_text.clone())];
        if !base.is_empty() {
            env.push(("ZEROPW_API_BASE_URL", base));
        }
        let out = same_without_upstream(&["steal", "--please"], &env);
        assert!(!out.contains("opaque-synthetic-handle"), "{out}");
    }
    let out = same_without_upstream(&["steal"], &[]);
    assert!(out.contains("\"no home\""), "{out}");
}
