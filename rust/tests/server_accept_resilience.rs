//! `socketserver.BaseServer.serve_forever` keeps serving after a failed
//! `accept` (`_handle_request_noblock` returns on `OSError`). This lowers the
//! process's descriptor limit, so it lives alone in its own test binary.
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeropw::context::{Config, Context};
use zeropw::server::ZeroPWServer;

fn healthz(address: &str) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect(address).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut out = Vec::new();
    stream.read_to_end(&mut out).ok()?;
    Some(out)
}

fn open_descriptors() -> Option<u64> {
    let directory = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    Some(std::fs::read_dir(directory).ok()?.count() as u64)
}

#[test]
fn accept_loop_keeps_serving_after_descriptor_exhaustion() {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
    let temp = tempfile::TempDir::new().unwrap();
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
    let server = ZeroPWServer::new(ctx, Some("127.0.0.1"), Some(0)).unwrap();
    server.serve_in_thread().unwrap();
    let address = server.url().trim_start_matches("http://").to_string();
    assert!(
        healthz(&address)
            .unwrap()
            .starts_with(b"HTTP/1.1 200 OK\r\n")
    );

    let original = getrlimit(Resource::Nofile);
    let open = open_descriptors().expect("descriptor count");
    setrlimit(
        Resource::Nofile,
        Rlimit {
            current: Some(open + 16),
            maximum: original.maximum,
        },
    )
    .unwrap();
    // Each admitted connection costs the server two descriptors and this
    // client one: the listener soon fails `accept` with EMFILE while the
    // kernel still completes handshakes into the backlog.
    let mut clients = Vec::new();
    for _ in 0..64 {
        match TcpStream::connect(&address) {
            Ok(stream) => clients.push(stream),
            Err(_) => break,
        }
    }
    std::thread::sleep(Duration::from_millis(300));
    drop(clients);
    setrlimit(Resource::Nofile, original).unwrap();

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if healthz(&address).is_some_and(|r| r.starts_with(b"HTTP/1.1 200 OK\r\n")) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the server stopped accepting after EMFILE"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    server.stop();
}
