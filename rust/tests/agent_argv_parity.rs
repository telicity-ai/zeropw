//! The native agent CLI and `python3.12 -m zeropw.agent_cli` given the same
//! raw argv and environment bytes, including bytes that are not UTF-8 (which
//! CPython decodes with `surrogateescape`): exit status, stdout, stderr and
//! the exact request bytes the gateway receives.
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

fn python() -> String {
    std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".into())
}

/// Records every request (raw bytes) and answers `200 {}` until stopped.
fn gateway() -> (u16, Arc<AtomicBool>, thread::JoinHandle<Vec<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        loop {
            let (mut socket, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(_) if flag.load(Ordering::SeqCst) => return requests,
                Err(_) => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&request[..end]).to_lowercase();
                    let length = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length: "))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
                match socket.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(&buf[..n]),
                }
            }
            let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
            let _ = socket.shutdown(std::net::Shutdown::Both);
            requests.push(request);
        }
    });
    (port, stop, handle)
}

type Outcome = (Option<i32>, String, String, Vec<String>);

fn run_both(argv: &[Vec<u8>], url: &[u8], token: &[u8]) -> (Outcome, Outcome) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut outcomes = Vec::new();
    for native in [false, true] {
        let (port, stop, server) = gateway();
        let mut url = url.to_vec();
        if let Some(at) = url.windows(6).position(|w| w == b"{port}") {
            url.splice(at..at + 6, port.to_string().into_bytes());
        }
        let mut command = if native {
            Command::new(env!("CARGO_BIN_EXE_zeropw-agent"))
        } else {
            let mut c = Command::new(python());
            c.args(["-m", "zeropw.agent_cli"]);
            c
        };
        let output = command
            .args(argv.iter().map(|a| OsString::from_vec(a.clone())))
            .current_dir(root)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("PYTHONPATH", root)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("LANG", "C.UTF-8")
            .env("ZEROPW_GATEWAY_URL", OsString::from_vec(url))
            .env("ZEROPW_CALLER_TOKEN", OsString::from_vec(token.to_vec()))
            .output()
            .unwrap();
        stop.store(true, Ordering::SeqCst);
        let requests = server
            .join()
            .unwrap()
            .iter()
            .map(|r| String::from_utf8_lossy(r).replace(&port.to_string(), "{port}"))
            .collect();
        outcomes.push((
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
            requests,
        ));
    }
    let rust = outcomes.pop().unwrap();
    let python = outcomes.pop().unwrap();
    (python, rust)
}

/// `(argv, ZEROPW_GATEWAY_URL, ZEROPW_CALLER_TOKEN)` bytes.
type Case<'a> = (Vec<Vec<u8>>, &'a [u8], &'a [u8]);

fn args(items: &[&[u8]]) -> Vec<Vec<u8>> {
    items.iter().map(|a| a.to_vec()).collect()
}

#[test]
fn non_utf8_arguments_and_environment_match_python() {
    let tmp = tempfile::TempDir::new().unwrap();
    let mut body_path = tmp.path().as_os_str().to_owned().into_vec();
    body_path.extend_from_slice(b"/body-\xff\xfe.txt");
    std::fs::write(
        OsString::from_vec(body_path.clone()),
        b"file \xe2\x9c\x93 body",
    )
    .unwrap();
    let url = b"http://127.0.0.1:{port}".as_slice();
    let token = b"zpwc_synthetic".as_slice();
    let cases: Vec<Case> = vec![
        (
            args(&[
                b"exec",
                b"--connection",
                b"c",
                b"--",
                b"\xff",
                b"arg",
                b"\xed\xa0\x80",
            ]),
            url,
            token,
        ),
        (
            args(&[
                b"request",
                b"--connection",
                b"c\xffx",
                b"--method",
                b"g\xfft",
                b"--path",
                b"/p\xff",
                b"--header",
                b"X\xff: v\xfe",
                b"--header",
                b"\x1cY : w\x1d",
                b"--body",
                b"b\xff",
                b"--request-id",
                b"r\xff",
            ]),
            url,
            token,
        ),
        (
            args(&[
                b"request",
                b"--connection",
                b"c",
                b"--method",
                b"get",
                b"--path",
                b"/",
                b"--body-file",
                &body_path,
            ]),
            url,
            token,
        ),
        (
            args(&[
                b"request",
                b"--connection",
                b"c",
                b"--method",
                b"get",
                b"--path",
                b"/",
                b"--body-file",
                b"/nonexistent-\xff",
            ]),
            url,
            token,
        ),
        (args(&[b"status", b"--run", b"\xff\\U000f0080"]), url, token),
        (args(&[b"\xff"]), url, token),
        (args(&[b"\xff", b"\\U000f0080"]), url, token),
        (args(&[b"list-connections", b"\xff", b"x\xfey"]), url, token),
        (
            args(&[b"list-connections"]),
            b"http://127.0.0.1:{port}/\xff",
            token,
        ),
        (args(&[b"list-connections"]), url, b"zpwc_\xff"),
        (args(&[b"list-connections"]), url, b"zpwc_\xc3\xa9"),
        (args(&[b"list-connections"]), url, b"zpwc_\xea\xb0\x80"),
        (args(&[b"list-connections"]), url, b"zpwc a\r\n b"),
        (args(&[b"list-connections"]), url, b"zpwc a\nb"),
        (
            args(&[b"list-connections"]),
            b"\x1chttp://127.0.0.1:{port}\x1f",
            b"\x1czpwc_x\x1e",
        ),
        (
            args(&[b"list-connections"]),
            b"http://127.0.0.1:{port}/\xc3\xbc",
            token,
        ),
        (
            args(&[b"list-connections"]),
            b"http://\xc3\xbc.invalid:{port}",
            token,
        ),
        (
            args(&[b"list-connections"]),
            b"http://\xea\xb0\x80.invalid:{port}",
            token,
        ),
        (args(&[b"list-connections"]), b"http://\xff:{port}", token),
    ];
    let mut mismatches = Vec::new();
    let (mut sent, mut usage) = (0, 0);
    for (argv, url, token) in cases {
        let (python, rust) = run_both(&argv, url, token);
        sent += usize::from(!python.3.is_empty());
        usage += usize::from(python.0 == Some(2));
        if python != rust {
            mismatches.push(format!(
                "argv {argv:?} url {url:?} token {token:?}\n python: {python:?}\n rust:   {rust:?}"
            ));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    assert!(sent >= 6 && usage >= 3, "sent {sent}, usage errors {usage}");
}
