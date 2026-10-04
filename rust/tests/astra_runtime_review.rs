//! Independent Astra runtime regression probes, synthetic state only.
mod session_probe;

use std::sync::Arc;
use std::{
    io::{Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};
use tempfile::TempDir;
use zeropw::server::ZeroPWServer;
use zeropw::{
    context::{Config, Context},
    runs::{self, RunRegistry},
    tools,
};

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
fn ar_runtime_01_installation_survives_discarded_return_value() {
    let (_temp, ctx) = context();
    tools::install(ctx.clone());
    assert!(
        runs::registry(&ctx).is_some(),
        "install must attach the registry to Context, as Python does"
    );
}

#[test]
fn ar_runtime_02_child_leads_a_new_session() {
    let (temp, ctx) = context();
    let registry = RunRegistry::new(ctx, 1024, 0.05);
    let argv = session_probe::argv();
    let run = registry.create(
        "alice", "service", "grant", "http", &argv[0], None, "digest", None, None,
    );
    registry
        .start(
            &run,
            &argv,
            &session_probe::env(None),
            temp.path(),
            &[],
            None,
            Some(10.0),
        )
        .unwrap();
    let result = registry.wait(&run, Some(15.0));
    assert_eq!(result.state, "completed");
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("PROBE true "),
        "start_new_session=True makes the child its own session leader: {:?}",
        String::from_utf8_lossy(&result.stdout)
    );
}

fn request(server: &ZeroPWServer, request: &[u8]) -> Vec<u8> {
    let mut socket = TcpStream::connect(server.url().trim_start_matches("http://")).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket.write_all(request).unwrap();
    let mut response = Vec::new();
    socket.read_to_end(&mut response).unwrap();
    response
}

#[test]
fn ar_runtime_03_head_framing_error_has_no_response_body() {
    let (_temp, ctx) = context();
    let server = ZeroPWServer::new(ctx, None, None).unwrap();
    server.serve_in_thread().unwrap();
    let response = request(
        &server,
        b"HEAD /healthz HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
    );
    server.stop();
    assert!(response.starts_with(b"HTTP/1.1 400"));
    let body_start = response.windows(4).position(|v| v == b"\r\n\r\n").unwrap() + 4;
    assert_eq!(
        &response[body_start..],
        b"",
        "HEAD must suppress even framing-error bodies, as Python does"
    );
}

#[test]
fn server_shutdown_closes_idle_keepalive_and_listener() {
    let (_temp, ctx) = context();
    let server = ZeroPWServer::new(ctx, None, None).unwrap();
    server.serve_in_thread().unwrap();
    let address = server.url().trim_start_matches("http://").to_string();
    let mut client = TcpStream::connect(&address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    client
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: local\r\n\r\n")
        .unwrap();
    let mut data = [0; 1024];
    assert!(client.read(&mut data).unwrap() > 0);
    let began = Instant::now();
    server.stop();
    assert!(began.elapsed() < Duration::from_secs(1));
    while client.read(&mut data).unwrap() != 0 {}
    assert!(TcpStream::connect(address).is_err());
}

#[test]
fn relay_filters_non_ascii_headers_before_server_serialization() {
    use zeropw::policy::{Connection, HttpAuth, HttpScope, HttpTarget};
    let (_temp, ctx) = context();
    ctx.projects
        .create("demo", zeropw::projects::DEFAULT_ENVIRONMENTS)
        .unwrap();
    ctx.vault
        .put_secret(
            "key",
            "api_key",
            b"synthetic-runtime-test-token",
            "demo",
            "dev",
            true,
        )
        .unwrap();
    ctx.policy.create_principal("alice", "test").unwrap();
    let upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = upstream.local_addr().unwrap().port();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nETag: \"caf\xe9\"\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
    });
    ctx.policy
        .create_connection(
            Connection::new(
                "service",
                "demo",
                "dev",
                "synthetic",
                "http",
                "key",
                None,
                "business API",
                Some(HttpTarget::new("http", "127.0.0.1", i64::from(port), None, false).unwrap()),
                Some(HttpAuth::bearer()),
                Some(
                    HttpScope::new(Some(vec!["GET".into()]), Some(vec!["/".into()]), Vec::new())
                        .unwrap(),
                ),
                None,
                None,
                0,
                "active",
                "",
                "",
            )
            .unwrap(),
        )
        .unwrap();
    let grant = ctx
        .policy
        .create_grant("alice", "service", Some(3600), None)
        .unwrap();
    let connection = ctx.policy.get_connection("service").unwrap();
    let handle = ctx
        .handles
        .issue(
            "alice",
            "service",
            &grant.id,
            connection.policy_version.to_i64().unwrap(),
            300,
            None,
        )
        .unwrap();
    let server = ZeroPWServer::new(ctx, None, None).unwrap();
    server.serve_in_thread().unwrap();
    let response = request(
        &server,
        format!("GET /h/{handle}/me HTTP/1.1\r\nConnection: close\r\n\r\n").as_bytes(),
    );
    worker.join().unwrap();
    server.stop();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(
        !String::from_utf8_lossy(&response)
            .to_ascii_lowercase()
            .contains("etag:")
    );
}
