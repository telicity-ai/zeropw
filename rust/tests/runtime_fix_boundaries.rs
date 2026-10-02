//! Additional boundaries for Astra runtime findings, using synthetic state.
use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
    time::Duration,
};
use tempfile::TempDir;
use zeropw::{
    clock,
    context::{Config, Context},
    server::ZeroPWServer,
};

fn context() -> (TempDir, Arc<Context>) {
    let temp = TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            temp.path().join("state"),
            "synthetic-admin-passphrase",
            "synthetic-recovery-passphrase",
            Config::default(),
            clock::system(),
        )
        .unwrap(),
    );
    (temp, ctx)
}

fn request(server: &ZeroPWServer, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(server.url().trim_start_matches("http://")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(request).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    response
}

#[test]
fn head_errors_after_a_valid_method_have_no_wire_body() {
    let (_temp, ctx) = context();
    let server = ZeroPWServer::new(ctx, None, None).unwrap();
    server.serve_in_thread().unwrap();
    for input in [
        b"HEAD /healthz HTTP/1.1\r\nBroken\r\n\r\n".as_slice(),
        b"HEAD /healthz HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n".as_slice(),
        b"HEAD /healthz HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
        b"HEAD http://example.invalid/ HTTP/1.1\r\n\r\n".as_slice(),
    ] {
        let response = request(&server, input);
        assert!(response.starts_with(b"HTTP/1.1 400"), "{response:?}");
        let body = response
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .unwrap()
            + 4;
        assert!(
            response[body..].is_empty(),
            "HEAD body leaked: {response:?}"
        );
    }
    server.stop();
}

#[test]
fn optional_logs_redact_handle_and_query_while_default_is_quiet() {
    let (_temp, ctx) = context();
    let quiet = ZeroPWServer::new(ctx.clone(), None, None).unwrap();
    quiet.serve_in_thread().unwrap();
    request(
        &quiet,
        b"GET /healthz?query-secret HTTP/1.1\r\nConnection: close\r\n\r\n",
    );
    assert!(quiet.log_lines().is_empty());
    quiet.stop();

    let server = ZeroPWServer::new_with_quiet(ctx, None, None, false).unwrap();
    server.serve_in_thread().unwrap();
    let handle = "zpw1.synthetic-handle-material";
    request(&server, format!("GET /h/{handle}/repos?token=synthetic-query-secret HTTP/1.1\r\nConnection: close\r\n\r\n").as_bytes());
    request(
        &server,
        b"GET /relay/me?x=synthetic-query-secret HTTP/1.1\r\nConnection: close\r\n\r\n",
    );
    let lines = server.log_lines();
    assert_eq!(lines, ["GET /h/<handle>/...", "GET /relay/me"]);
    let text = lines.join("\n");
    for sensitive in [
        handle,
        "synthetic-handle-material",
        "synthetic-query-secret",
        "token=",
        "?",
    ] {
        assert!(!text.contains(sensitive));
    }
    server.stop();
}
