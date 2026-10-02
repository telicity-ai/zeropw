//! The native agent CLI routes through environment proxies exactly like the
//! original `urllib` client: absolute-form requests and `Proxy-Authorization`
//! to an HTTP proxy, `CONNECT` tunnels for https gateways, `no_proxy`
//! bypass, and the same error text. Python is only the oracle.
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::thread;

fn python() -> String {
    std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".into())
}

/// A proxy that records one request's line and (sorted, selected) headers and
/// answers with `reply`.
fn proxy(reply: &'static str) -> (u16, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(socket.try_clone().unwrap());
        let mut seen = Vec::new();
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        seen.push(line.trim_end().to_owned());
        let mut headers = Vec::new();
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap() == 0 {
                break;
            }
            let header = header.trim_end().to_owned();
            if header.is_empty() {
                break;
            }
            let name = header.split(':').next().unwrap_or("").to_ascii_lowercase();
            if matches!(
                name.as_str(),
                "host"
                    | "proxy-authorization"
                    | "authorization"
                    | "content-type"
                    | "content-length"
                    | "accept"
                    | "accept-encoding"
                    | "user-agent"
                    | "connection"
            ) {
                headers.push(format!(
                    "{name}:{}",
                    header.split_once(':').unwrap().1.trim()
                ));
            }
        }
        headers.sort();
        seen.extend(headers);
        let mut socket = socket;
        socket.write_all(reply.as_bytes()).unwrap();
        let _ = socket.shutdown(std::net::Shutdown::Both);
        seen
    });
    (port, handle)
}

fn run(native: bool, env: &[(&str, String)]) -> (Option<i32>, String, String) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut command = if native {
        Command::new(env!("CARGO_BIN_EXE_zeropw-agent"))
    } else {
        let mut c = Command::new(python());
        c.args(["-m", "zeropw.agent_cli"]);
        c
    };
    command
        .arg("list-connections")
        .current_dir(root)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("PYTHONPATH", root)
        .env("ZEROPW_CALLER_TOKEN", "zpwc_synthetic-caller");
    for (name, value) in env {
        command.env(name, value);
    }
    let out = command.output().unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

const OK: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"connections\":[]}";

/// Record the complete request line and header block in wire order.
fn origin() -> (u16, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(socket.try_clone().unwrap());
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }
            let line = line.trim_end_matches(['\r', '\n']).to_owned();
            if line.is_empty() {
                break;
            }
            lines.push(line);
        }
        socket.write_all(OK.as_bytes()).unwrap();
        let _ = socket.shutdown(std::net::Shutdown::Both);
        lines
    });
    (port, handle)
}

#[test]
fn default_request_headers_match_urllib_value_order_and_multiplicity() {
    let mut results = Vec::new();
    for native in [false, true] {
        let (port, seen) = origin();
        let env = [("ZEROPW_GATEWAY_URL", format!("http://127.0.0.1:{port}"))];
        let outcome = run(native, &env);
        results.push((outcome, seen.join().unwrap(), port));
    }
    assert_eq!(results[1].0, results[0].0);
    let expected = |port| {
        vec![
            "POST /v1/tools/list_connections HTTP/1.1".to_owned(),
            "Accept-Encoding: identity".to_owned(),
            "Content-Length: 2".to_owned(),
            format!("Host: 127.0.0.1:{port}"),
            "User-Agent: Python-urllib/3.12".to_owned(),
            "Authorization: Bearer zpwc_synthetic-caller".to_owned(),
            "Content-Type: application/json".to_owned(),
            "Accept: application/json".to_owned(),
            "Connection: close".to_owned(),
        ]
    };
    assert_eq!(results[0].1, expected(results[0].2));
    assert_eq!(results[1].1, expected(results[1].2));
}

#[test]
fn http_gateway_goes_through_the_http_proxy_like_urllib() {
    let mut results = Vec::new();
    for native in [false, true] {
        let (port, seen) = proxy(OK);
        let env = [
            (
                "ZEROPW_GATEWAY_URL",
                "http://gateway.invalid:8080".to_owned(),
            ),
            (
                "http_proxy",
                format!("http://synthetic%40user:pa%3Ass@127.0.0.1:{port}"),
            ),
        ];
        let outcome = run(native, &env);
        results.push((outcome, seen.join().unwrap()));
    }
    assert_eq!(results[1], results[0]);
    let seen = &results[0].1;
    assert_eq!(
        seen[0],
        "POST http://gateway.invalid:8080/v1/tools/list_connections HTTP/1.1"
    );
    assert!(
        seen.iter()
            .any(|h| h.starts_with("proxy-authorization:Basic "))
    );
    for exact in [
        "accept-encoding:identity",
        "user-agent:Python-urllib/3.12",
        "connection:close",
    ] {
        assert_eq!(
            seen.iter()
                .filter(|header| header.as_str() == exact)
                .count(),
            1
        );
    }
}

#[test]
fn https_gateway_is_tunnelled_and_a_refused_tunnel_is_reported_like_urllib() {
    let mut results = Vec::new();
    for native in [false, true] {
        let (port, seen) =
            proxy("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n");
        let env = [
            ("ZEROPW_GATEWAY_URL", "https://gateway.invalid".to_owned()),
            ("HTTPS_PROXY", format!("127.0.0.1:{port}")),
        ];
        let outcome = run(native, &env);
        results.push((outcome, seen.join().unwrap()));
    }
    assert_eq!(results[1], results[0]);
    assert_eq!(results[0].1[0], "CONNECT gateway.invalid:443 HTTP/1.1");
    assert!(results[0].0.2.contains("Tunnel connection failed: 407"));
}

#[test]
fn no_proxy_bypasses_the_proxy_like_urllib() {
    // The proxy must not be contacted: the gateway port is closed, so both
    // implementations report the same direct connection failure.
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let mut outcomes = Vec::new();
    for native in [false, true] {
        let env = [
            ("ZEROPW_GATEWAY_URL", format!("http://127.0.0.1:{closed}")),
            ("HTTP_PROXY", "http://127.0.0.1:9".to_owned()),
            ("no_proxy", "localhost, .example, 127.0.0.1".to_owned()),
        ];
        outcomes.push(run(native, &env));
    }
    assert_eq!(outcomes[1], outcomes[0]);
    assert!(
        outcomes[0].2.contains("Connection refused"),
        "{:?}",
        outcomes[0]
    );
}
