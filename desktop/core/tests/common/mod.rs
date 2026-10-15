//! Shared test fixture: a temp app folder plus a bin folder holding the fake zeropw-admin
//! (tests/fixtures/fake-zeropw-admin.sh), and a loopback `/healthz` responder.
#![allow(dead_code)]

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::TempDir;
use zeropw_desktop_core::{AppError, AppPaths, Clipboard, CoreEvent, EventSink, SecretString};

pub struct Fixture {
    pub dir: TempDir,
    pub paths: AppPaths,
}

#[derive(Debug, Clone)]
pub struct Call {
    pub key: String,
    pub argv: Vec<String>,
    pub stdin: Option<String>,
    pub env: Vec<(String, String)>,
}

impl Call {
    pub fn stdin_json(&self) -> Value {
        serde_json::from_str(self.stdin.as_deref().expect("call had no envelope")).unwrap()
    }

    /// argv after `--state-dir=… --input-envelope`.
    pub fn args(&self) -> Vec<&str> {
        self.argv
            .iter()
            .map(String::as_str)
            .filter(|a| !a.starts_with("--state-dir=") && *a != "--input-envelope")
            .collect()
    }

    pub fn env_var(&self, key: &str) -> Option<&str> {
        self.env
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

impl Fixture {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        fs::create_dir_all(bin.join("responses")).unwrap();
        let script =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-zeropw-admin.sh");
        let admin = bin.join("zeropw-admin");
        fs::copy(&script, &admin).unwrap();
        fs::set_permissions(&admin, fs::Permissions::from_mode(0o755)).unwrap();
        let paths = AppPaths::new(dir.path().join("app"), bin);
        Self { dir, paths }
    }

    fn response(&self, key: &str, ext: &str) -> PathBuf {
        self.paths
            .bin_dir
            .join("responses")
            .join(format!("{key}.{ext}"))
    }

    pub fn respond(&self, key: &str, stdout: &str) {
        fs::write(self.response(key, "json"), stdout).unwrap();
    }

    pub fn respond_error(&self, key: &str, stderr: &str, exit: i32) {
        fs::write(self.response(key, "stderr"), stderr).unwrap();
        fs::write(self.response(key, "exit"), exit.to_string()).unwrap();
    }

    pub fn clear_response(&self, key: &str) {
        for ext in ["json", "stderr", "exit", "sleep"] {
            let _ = fs::remove_file(self.response(key, ext));
        }
    }

    pub fn respond_sleep(&self, key: &str, seconds: u32) {
        fs::write(self.response(key, "sleep"), seconds.to_string()).unwrap();
    }

    pub fn serve_ignores_sigterm(&self) {
        fs::write(self.paths.bin_dir.join("responses/serve.ignore_term"), "").unwrap();
    }

    pub fn calls(&self) -> Vec<Call> {
        let calls = self.paths.bin_dir.join("calls");
        let count: usize = fs::read_to_string(calls.join("count"))
            .map(|s| s.trim().parse().unwrap())
            .unwrap_or(0);
        (1..=count)
            .map(|n| {
                let read = |ext: &str| fs::read_to_string(calls.join(format!("{n}.{ext}"))).ok();
                Call {
                    key: read("key").unwrap_or_default().trim().to_owned(),
                    argv: read("argv")
                        .unwrap_or_default()
                        .lines()
                        .map(str::to_owned)
                        .collect(),
                    stdin: read("stdin"),
                    env: read("env")
                        .unwrap_or_default()
                        .lines()
                        .filter_map(|l| l.split_once('='))
                        .map(|(k, v)| (k.to_owned(), v.to_owned()))
                        .collect(),
                }
            })
            .collect()
    }

    pub fn last(&self, key: &str) -> Call {
        self.calls()
            .into_iter()
            .rev()
            .find(|c| c.key == key)
            .unwrap_or_else(|| panic!("no call with key {key}"))
    }

    pub fn count(&self, key: &str) -> usize {
        self.calls().iter().filter(|c| c.key == key).count()
    }

    pub fn state_dir_arg(&self) -> String {
        format!("--state-dir={}", self.paths.state_dir().display())
    }
}

/// A loopback server answering every request like zeropw serve's `/healthz`.
pub fn health_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut request = Vec::new();
                let mut buf = [0u8; 2048];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = stream.write_all(
                    b"HTTP/1.0 200 OK\r\nServer: zeropw-prototype \r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}",
                );
            });
        }
    });
    port
}

/// A port nothing listens on (bound then released).
pub fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

#[derive(Default)]
pub struct Events(pub Mutex<Vec<(String, Value)>>);

impl EventSink for Events {
    fn emit(&self, event: CoreEvent) {
        self.0
            .lock()
            .unwrap()
            .push((event.name().to_owned(), event.payload()));
    }
}

impl Events {
    pub fn named(&self, name: &str) -> Vec<Value> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
            .collect()
    }
}

#[derive(Default)]
pub struct FakeClipboard(pub Mutex<Option<String>>);

impl Clipboard for FakeClipboard {
    fn write_text(&self, text: &str) -> Result<(), AppError> {
        *self.0.lock().unwrap() = Some(text.to_owned());
        Ok(())
    }
    fn read_text(&self) -> Option<SecretString> {
        self.0.lock().unwrap().clone().map(SecretString::new)
    }
    fn clear(&self) -> Result<(), AppError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

pub fn wait_until(timeout: Duration, mut check: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if check() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    check()
}

pub fn arc_events() -> Arc<Events> {
    Arc::new(Events::default())
}

/// Unwrap an error from a result whose Ok type has no `Debug` (secret-bearing outputs).
pub fn err<T>(result: Result<T, AppError>) -> AppError {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    }
}

/// Unwrap a result whose Ok type has no `Debug`.
pub fn ok<T>(result: Result<T, AppError>) -> T {
    match result {
        Ok(v) => v,
        Err(e) => panic!("unexpected error: {e}"),
    }
}
