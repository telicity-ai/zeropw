//! Port of `zeropw/fake_upstream.py`: a controlled fake upstream API for
//! tests (and, eventually, the demo).
//!
//! This is a *test fixture*, not part of the trusted control plane: it
//! deliberately offers every leak path the gateway must block (header
//! reflection, credential in a redirect `Location`, a debug endpoint that
//! prints the token, base64/percent/hex/JSON/HTML encodings, oversized and
//! chunked bodies) so tests can prove the relay blocks them. It only ever
//! holds a synthetic credential, binds `127.0.0.1` on an ephemeral port, and
//! must not be used against real credentials.
//!
//! Unlike `http.server.BaseHTTPRequestHandler` (which supports keep-alive),
//! every response path here sets `Connection: close` and the connection is
//! closed after one request/response, exactly mirroring the Python fixture
//! (`_Handler._send`/`_send_chunked`/`_send_streamed` all set
//! `self.close_connection = True`), so this port does not need to implement
//! HTTP/1.1 keep-alive at all.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::pyjson::{self, DumpOptions};

pub const LARGE_BODY_SIZE: usize = 2 * 1024 * 1024;
pub const HUGE_BODY_SIZE: usize = 9 * 1024 * 1024;
pub const STREAM_PARTS: &[&[u8]] = &[b"part-1\n", b"part-2\n", b"part-3\n"];

/// Every encoding in which `GET /encoded-leak?form=<name>` reflects the
/// credential inside its body: one per form the gateway's reflection guard
/// scans.
pub const ENCODED_LEAK_FORMS: &[&str] = &[
    "raw",
    "base64",
    "base64-unpadded",
    "base64url",
    "base64url-unpadded",
    "percent-upper",
    "percent-lower",
    "percent-plus-upper",
    "percent-plus-lower",
    "hex-lower",
    "hex-upper",
    "json",
    "json-unicode",
    "html",
];
/// Forms that exist only in `basic` mode: `base64(basic_username:credential)`.
pub const BASIC_LEAK_FORMS: &[&str] = &["basic", "basic-unpadded", "basic-url"];

fn lower_percent_triplets(encoded: &str) -> String {
    let bytes = encoded.as_bytes();
    let mut out = String::with_capacity(encoded.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            out.push('%');
            out.push((bytes[i + 1] as char).to_ascii_lowercase());
            out.push((bytes[i + 2] as char).to_ascii_lowercase());
            i += 3;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn percent_encode_str(text: &str, plus: bool) -> String {
    let mut out = String::new();
    for &b in text.as_bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'~');
        if unreserved {
            out.push(b as char);
        } else if plus && b == b' ' {
            out.push('+');
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            other => out.push(other),
        }
    }
    out
}

/// Port of `fake_upstream.encoded_credential`: the fake's credential in one
/// named encoding, or `None` for an unknown form.
pub fn encoded_credential(fake: &FakeUpstream, form: &str) -> Option<String> {
    encoding_of(
        &fake.credential,
        &fake.mode,
        fake.basic_username.as_deref(),
        form,
    )
}

/// Shared implementation for [`encoded_credential`] and the `/encoded-leak`
/// route (`_Handler._dispatch`'s `encoded_credential(fake, ...)` call).
fn encoding_of(
    credential: &str,
    mode: &str,
    basic_username: Option<&str>,
    form: &str,
) -> Option<String> {
    use base64::Engine as _;
    let text = credential.to_string();
    let raw = text.as_bytes();
    let percent = percent_encode_str(&text, false);
    let percent_plus = percent_encode_str(&text, true);
    let value = match form {
        "raw" => text.clone(),
        "base64" => base64::engine::general_purpose::STANDARD.encode(raw),
        "base64-unpadded" => base64::engine::general_purpose::STANDARD_NO_PAD.encode(raw),
        "base64url" => base64::engine::general_purpose::URL_SAFE.encode(raw),
        "base64url-unpadded" => base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw),
        "percent-upper" => percent.clone(),
        "percent-lower" => lower_percent_triplets(&percent),
        "percent-plus-upper" => percent_plus.clone(),
        "percent-plus-lower" => lower_percent_triplets(&percent_plus),
        "hex-lower" => hex::encode(raw),
        "hex-upper" => hex::encode(raw).to_uppercase(),
        "json" => pyjson::encode_str(&text, true),
        "json-unicode" => pyjson::encode_str(&text, false),
        "html" => html_escape(&text),
        "basic" if mode == "basic" => {
            let pair = format!("{}:{}", basic_username.unwrap_or(""), text);
            base64::engine::general_purpose::STANDARD.encode(pair.as_bytes())
        }
        "basic-unpadded" if mode == "basic" => {
            let pair = format!("{}:{}", basic_username.unwrap_or(""), text);
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(pair.as_bytes())
        }
        "basic-url" if mode == "basic" => {
            let pair = format!("{}:{}", basic_username.unwrap_or(""), text);
            base64::engine::general_purpose::URL_SAFE.encode(pair.as_bytes())
        }
        _ => return None,
    };
    Some(value)
}

/// Port of `fake_upstream.embedded_base64_blob`.
pub fn embedded_base64_blob(credential: &str, offset: usize, wrap: usize, urlsafe: bool) -> String {
    use base64::Engine as _;
    let mut raw = vec![b'#'; offset];
    raw.extend_from_slice(b"token=");
    raw.extend_from_slice(credential.as_bytes());
    raw.extend_from_slice(b"\nnote=synthetic\n");
    let encoded = if urlsafe {
        base64::engine::general_purpose::URL_SAFE.encode(&raw)
    } else {
        base64::engine::general_purpose::STANDARD.encode(&raw)
    };
    if wrap > 0 {
        let mut out = String::new();
        let chars: Vec<char> = encoded.chars().collect();
        for chunk in chars.chunks(wrap) {
            out.extend(chunk);
            out.push('\n');
        }
        out
    } else {
        encoded
    }
}

// -------------------------------------------------------------- recording

/// One recorded request, as `fake.requests` holds in Python: method, raw
/// path (with query), lower-cased headers, and body.
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

// ------------------------------------------------------------------ config

/// Builder for [`FakeUpstream`], mirroring the keyword arguments of
/// Python's `FakeUpstream(credential, mode=..., basic_username=...,
/// ssl_context=..., header_name=..., value_prefix=...)` constructor.
pub struct FakeUpstream {
    credential: String,
    mode: String,
    basic_username: Option<String>,
    header_name: String,
    value_prefix: String,
    tls: Option<Arc<rustls::ServerConfig>>,
    state: Option<Arc<Server>>,
}

struct Server {
    credential: String,
    mode: String,
    basic_username: Option<String>,
    header_name: String,
    value_prefix: String,
    tls: Option<Arc<rustls::ServerConfig>>,
    requests: Mutex<Vec<RecordedRequest>>,
    issue_counter: AtomicI64,
    port: u16,
    stop: Arc<AtomicBool>,
    accept_thread: Mutex<Option<JoinHandle<()>>>,
}

impl FakeUpstream {
    pub fn new(credential: impl Into<String>) -> Self {
        FakeUpstream {
            credential: credential.into(),
            mode: "bearer".to_string(),
            basic_username: None,
            header_name: "X-Api-Key".to_string(),
            value_prefix: String::new(),
            tls: None,
            state: None,
        }
    }

    pub fn mode_basic(mut self, basic_username: impl Into<String>) -> Self {
        self.mode = "basic".to_string();
        self.basic_username = Some(basic_username.into());
        self
    }

    pub fn mode_header(
        mut self,
        header_name: impl Into<String>,
        value_prefix: impl Into<String>,
    ) -> Self {
        self.mode = "header".to_string();
        self.header_name = header_name.into();
        self.value_prefix = value_prefix.into();
        self
    }

    pub fn tls(mut self, config: Arc<rustls::ServerConfig>) -> Self {
        self.tls = Some(config);
        self
    }

    /// `FakeUpstream.start`.
    pub fn start(mut self) -> Self {
        if self.state.is_some() {
            return self;
        }
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let port = listener.local_addr().expect("local_addr").port();
        let stop = Arc::new(AtomicBool::new(false));
        let server = Arc::new(Server {
            credential: self.credential.clone(),
            mode: self.mode.clone(),
            basic_username: self.basic_username.clone(),
            header_name: self.header_name.clone(),
            value_prefix: self.value_prefix.clone(),
            tls: self.tls.clone(),
            requests: Mutex::new(Vec::new()),
            issue_counter: AtomicI64::new(0),
            port,
            stop: stop.clone(),
            accept_thread: Mutex::new(None),
        });
        let accept_server = server.clone();
        let handle = std::thread::spawn(move || accept_loop(listener, accept_server));
        *server.accept_thread.lock().unwrap() = Some(handle);
        self.state = Some(server);
        self
    }

    /// `FakeUpstream.stop`.
    pub fn stop(&mut self) {
        if let Some(server) = self.state.take() {
            server.stop.store(true, Ordering::SeqCst);
            if let Some(handle) = server.accept_thread.lock().unwrap().take() {
                let _ = handle.join();
            }
        }
    }

    pub fn host(&self) -> &'static str {
        "127.0.0.1"
    }

    pub fn port(&self) -> u16 {
        self.state.as_ref().expect("fake upstream not started").port
    }

    pub fn scheme(&self) -> &'static str {
        if self.tls.is_some() { "https" } else { "http" }
    }

    pub fn url(&self) -> String {
        format!("{}://{}:{}", self.scheme(), self.host(), self.port())
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.state
            .as_ref()
            .expect("fake upstream not started")
            .requests
            .lock()
            .unwrap()
            .clone()
    }

    pub fn reset(&self) {
        self.state
            .as_ref()
            .expect("fake upstream not started")
            .requests
            .lock()
            .unwrap()
            .clear();
    }
}

impl Drop for FakeUpstream {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept_loop(listener: TcpListener, server: Arc<Server>) {
    loop {
        if server.stop.load(Ordering::SeqCst) {
            return;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let server = server.clone();
                std::thread::spawn(move || {
                    let _ = handle_connection(stream, &server);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

// -------------------------------------------------------------- transport

enum IncomingStream {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ServerConnection, TcpStream>>),
}

impl Read for IncomingStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            IncomingStream::Plain(s) => s.read(buf),
            IncomingStream::Tls(s) => s.read(buf),
        }
    }
}
impl Write for IncomingStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            IncomingStream::Plain(s) => s.write(buf),
            IncomingStream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            IncomingStream::Plain(s) => s.flush(),
            IncomingStream::Tls(s) => s.flush(),
        }
    }
}

fn handle_connection(tcp: TcpStream, server: &Server) -> std::io::Result<()> {
    tcp.set_read_timeout(Some(Duration::from_secs(30)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(30)))?;
    let stream = if let Some(config) = &server.tls {
        let conn = rustls::ServerConnection::new(config.clone())
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        IncomingStream::Tls(Box::new(rustls::StreamOwned::new(conn, tcp)))
    } else {
        IncomingStream::Plain(tcp)
    };
    let mut reader = BufReader::new(stream);
    let request = match read_request(&mut reader) {
        Ok(Some(r)) => r,
        Ok(None) => return Ok(()),
        Err(_) => return Ok(()),
    };
    dispatch(reader.get_mut(), server, request);
    Ok(())
}

struct IncomingRequest {
    method: String,
    raw_path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn read_line(reader: &mut impl BufRead) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    let n = reader.read_until(b'\n', &mut line)?;
    if n == 0 {
        return Ok(None);
    }
    while line.last() == Some(&b'\n') || line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(Some(line))
}

fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

fn read_request(reader: &mut impl BufRead) -> std::io::Result<Option<IncomingRequest>> {
    let Some(line) = read_line(reader)? else {
        return Ok(None);
    };
    if line.is_empty() {
        return Ok(None);
    }
    let line = latin1(&line);
    let mut parts = line.splitn(3, ' ');
    let method = parts.next().unwrap_or("").to_string();
    let raw_path = parts.next().unwrap_or("").to_string();
    if method.is_empty() || raw_path.is_empty() {
        return Ok(None);
    }
    let mut headers = Vec::new();
    loop {
        let Some(header_line) = read_line(reader)? else {
            return Ok(None);
        };
        if header_line.is_empty() {
            break;
        }
        let header_line = latin1(&header_line);
        let Some((name, value)) = header_line.split_once(':') else {
            continue;
        };
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    let content_length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok());
    let body = match content_length {
        Some(size) if size > 0 => {
            let mut buf = vec![0u8; size];
            reader.read_exact(&mut buf)?;
            buf
        }
        _ => Vec::new(),
    };
    Ok(Some(IncomingRequest {
        method,
        raw_path,
        headers,
        body,
    }))
}

fn header_get<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "OK",
    }
}

struct Responder<'a> {
    stream: &'a mut IncomingStream,
    method: String,
}

/// `BaseHTTPRequestHandler.send_response(status)`: emitted first, before any
/// handler-chosen header, on every response (`_Handler.server_version =
/// "fake-upstream"`; `send_response` always adds `Server`/`Date`). A fixed
/// `Date` is fine here -- this is a test fixture (module doc: "Security
/// scope: none") -- but the headers must actually be present so the
/// response-header-allowlist assertion in `rust/tests/gateway.rs` proves
/// `gateway.rs`'s `RESPONSE_HEADER_ALLOWLIST` really does drop them, instead
/// of vacuously passing because this fixture never emitted them in the first
/// place (finding F-20).
const FAKE_SERVER_HEADER: &str = "fake-upstream";
const FAKE_DATE_HEADER: &str = "Wed, 01 Jan 2025 00:00:00 GMT";

impl Responder<'_> {
    fn write_status_and_boilerplate(&self, out: &mut Vec<u8>, status: u16) {
        out.extend_from_slice(
            format!("HTTP/1.1 {status} {}\r\n", status_reason(status)).as_bytes(),
        );
        out.extend_from_slice(format!("Server: {FAKE_SERVER_HEADER}\r\n").as_bytes());
        out.extend_from_slice(format!("Date: {FAKE_DATE_HEADER}\r\n").as_bytes());
    }

    /// `_Handler._send`.
    fn send(
        &mut self,
        status: u16,
        body: &[u8],
        content_type: &str,
        extra_headers: &[(&str, String)],
    ) {
        let mut out = Vec::new();
        self.write_status_and_boilerplate(&mut out, status);
        if !body.is_empty() || !matches!(status, 204 | 304) {
            out.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
        }
        out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        for (name, value) in extra_headers {
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        out.extend_from_slice(b"Connection: close\r\n\r\n");
        if self.method != "HEAD" && !body.is_empty() {
            out.extend_from_slice(body);
        }
        let _ = self.stream.write_all(&out);
        let _ = self.stream.flush();
    }

    fn send_json(&mut self, status: u16, payload: &Value, extra_headers: &[(&str, String)]) {
        let body = pyjson::dumps(payload, DumpOptions::default_sorted())
            .unwrap_or_default()
            .into_bytes();
        self.send(status, &body, "application/json", extra_headers);
    }

    /// `_Handler._send_chunked`.
    fn send_chunked(&mut self, parts: &[&[u8]]) {
        let mut out = Vec::new();
        self.write_status_and_boilerplate(&mut out, 200);
        out.extend_from_slice(b"Content-Type: text/plain\r\n");
        out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        out.extend_from_slice(b"Connection: close\r\n\r\n");
        if self.method != "HEAD" {
            for part in parts {
                out.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
                out.extend_from_slice(part);
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(b"0\r\n\r\n");
        }
        let _ = self.stream.write_all(&out);
        let _ = self.stream.flush();
    }

    /// `_Handler._send_streamed`.
    fn send_streamed(&mut self, total: usize) {
        let mut head = Vec::new();
        self.write_status_and_boilerplate(&mut head, 200);
        head.extend_from_slice(b"Content-Type: application/octet-stream\r\n");
        head.extend_from_slice(format!("Content-Length: {total}\r\n").as_bytes());
        head.extend_from_slice(b"Connection: close\r\n\r\n");
        let _ = self.stream.write_all(&head);
        if self.method != "HEAD" {
            let chunk = vec![b'y'; 64 * 1024];
            let mut sent = 0usize;
            while sent < total {
                let n = chunk.len().min(total - sent);
                if self.stream.write_all(&chunk[..n]).is_err() {
                    return;
                }
                sent += n;
            }
        }
        let _ = self.stream.flush();
    }
}

fn parse_query(query: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.push((unquote_plus(k), unquote_plus(v)));
    }
    out
}

fn unquote_plus(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(byte);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_get<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn authorized(server: &Server, headers: &[(String, String)]) -> bool {
    match server.mode.as_str() {
        "bearer" => {
            header_get(headers, "Authorization")
                == Some(format!("Bearer {}", server.credential).as_str())
        }
        "basic" => {
            use base64::Engine as _;
            let pair = format!(
                "{}:{}",
                server.basic_username.as_deref().unwrap_or(""),
                server.credential
            );
            let expected = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(pair.as_bytes())
            );
            header_get(headers, "Authorization") == Some(expected.as_str())
        }
        "header" => {
            let expected = format!("{}{}", server.value_prefix, server.credential);
            header_get(headers, &server.header_name) == Some(expected.as_str())
        }
        _ => false,
    }
}

/// Port of `_Handler._dispatch`.
fn dispatch(stream: &mut IncomingStream, server: &Server, request: IncomingRequest) {
    let method = request.method.clone();
    let headers_lower: HashMap<String, String> = request
        .headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();
    server.requests.lock().unwrap().push(RecordedRequest {
        method: method.clone(),
        path: request.raw_path.clone(),
        headers: headers_lower,
        body: request.body.clone(),
    });

    let mut responder = Responder {
        stream,
        method: method.clone(),
    };
    if !authorized(server, &request.headers) {
        let scheme = if server.mode == "basic" {
            "Basic"
        } else {
            "Bearer"
        };
        responder.send_json(
            401,
            &json!({"error": "unauthorized"}),
            &[(
                "WWW-Authenticate",
                format!("{scheme} realm=\"fake-upstream\""),
            )],
        );
        return;
    }

    let (path, query_str) = request
        .raw_path
        .split_once('?')
        .unwrap_or((request.raw_path.as_str(), ""));
    let query = parse_query(query_str);
    let is_get_or_head = method == "GET" || method == "HEAD";

    if is_get_or_head && path == "/repos" {
        responder.send_json(200, &json!([{"name": "demo"}, {"name": "tools"}]), &[]);
    } else if is_get_or_head && path == "/me" {
        responder.send_json(200, &json!({"login": "synthetic-user"}), &[]);
    } else if method == "POST" && path.starts_with("/repos/") && path.ends_with("/issues") {
        let name = &path[("/repos/".len())..path.len() - "/issues".len()];
        let payload: Option<Value> = if request.body.is_empty() {
            Some(json!({}))
        } else {
            std::str::from_utf8(&request.body)
                .ok()
                .and_then(|s| pyjson::loads(s).ok())
        };
        let Some(payload) = payload else {
            responder.send_json(400, &json!({"error": "invalid_json"}), &[]);
            return;
        };
        let title = payload.get("title").and_then(Value::as_str);
        let Some(title) = title else {
            responder.send_json(400, &json!({"error": "title_required"}), &[]);
            return;
        };
        let number = server.issue_counter.fetch_add(1, Ordering::SeqCst) + 1;
        responder.send_json(
            201,
            &json!({"number": number, "title": title, "repo": name}),
            &[],
        );
    } else if method == "DELETE" && path.starts_with("/repos/") && path.matches('/').count() == 2 {
        responder.send(204, &[], "application/json", &[]);
    } else if is_get_or_head && path == "/echo-headers" {
        let mut map = Map::new();
        for (k, v) in &request.headers {
            map.insert(k.clone(), json!(v));
        }
        responder.send_json(200, &json!({"headers": Value::Object(map)}), &[]);
    } else if is_get_or_head && path == "/redirect" {
        let location = format!(
            "/leak?auth={}",
            percent_encode_str(&server.credential, false)
        );
        let html = format!("<a href=\"{location}\">moved</a>").into_bytes();
        responder.send(302, &html, "text/html", &[("Location", location)]);
    } else if is_get_or_head && path == "/redirect-external" {
        responder.send(
            302,
            &[],
            "application/json",
            &[("Location", "http://evil.invalid/".to_string())],
        );
    } else if is_get_or_head && path == "/leak" {
        let leaked = query_get(&query, "auth").unwrap_or("");
        responder.send_json(200, &json!({"leaked": leaked}), &[]);
    } else if is_get_or_head && path == "/debug/token" {
        responder.send_json(200, &json!({"token": server.credential}), &[]);
    } else if is_get_or_head && path == "/base64-leak" {
        use base64::Engine as _;
        let blob = base64::engine::general_purpose::STANDARD.encode(server.credential.as_bytes());
        responder.send_json(200, &json!({"blob": blob}), &[]);
    } else if is_get_or_head && path == "/base64-embedded-leak" {
        let offset_raw = query_get(&query, "offset").unwrap_or("0").parse::<i64>();
        let wrap_raw = query_get(&query, "wrap").unwrap_or("0").parse::<i64>();
        let (Ok(offset_raw), Ok(wrap_raw)) = (offset_raw, wrap_raw) else {
            responder.send_json(400, &json!({"error": "invalid_query"}), &[]);
            return;
        };
        let offset = offset_raw.clamp(0, 8) as usize;
        let wrap = wrap_raw.clamp(0, 1024) as usize;
        let urlsafe = query_get(&query, "alphabet") == Some("url");
        let content = embedded_base64_blob(&server.credential, offset, wrap, urlsafe);
        responder.send_json(200, &json!({"encoding": "base64", "content": content}), &[]);
    } else if is_get_or_head && path == "/urlencoded-leak" {
        let mut encoded = percent_encode_str(&server.credential, false);
        if query_get(&query, "case") == Some("lower") {
            encoded = lower_percent_triplets(&encoded);
        }
        responder.send_json(200, &json!({"blob": encoded}), &[]);
    } else if is_get_or_head && path == "/encoded-leak" {
        let form = query_get(&query, "form").unwrap_or("");
        match encoded_credential_for(server, form) {
            Some(encoded) => {
                let body = format!("leak=[{encoded}]\n").into_bytes();
                responder.send(200, &body, "text/plain", &[]);
            }
            None => responder.send_json(400, &json!({"error": "unknown_form"}), &[]),
        }
    } else if is_get_or_head && path == "/set-cookie" {
        responder.send_json(
            200,
            &json!({"ok": true}),
            &[(
                "Set-Cookie",
                format!("session={}; Path=/; HttpOnly", server.credential),
            )],
        );
    } else if is_get_or_head && path == "/stream" {
        responder.send_chunked(STREAM_PARTS);
    } else if is_get_or_head && path == "/large" {
        responder.send(
            200,
            &vec![b'x'; LARGE_BODY_SIZE],
            "application/octet-stream",
            &[],
        );
    } else if is_get_or_head && path == "/huge" {
        responder.send_streamed(HUGE_BODY_SIZE);
    } else if is_get_or_head && path == "/slow" {
        // `seconds = min(float(query.get("seconds", ["1"])[0]), 30.0)`;
        // `time.sleep(max(seconds, 0.0))`; the response echoes the
        // `min`-only value, NOT the `max`-floored one (finding F-R4-6,
        // confirmed against live `python3.12`: `?seconds=-5` sleeps 0 but
        // echoes `{"slept": -5.0}`) -- the previous version applied
        // `.clamp(0.0, 30.0)` before both the sleep *and* the echo, so a
        // negative `seconds` wrongly echoed `0.0`.
        let seconds: f64 = query_get(&query, "seconds")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1.0);
        // Rust's `f64::min`/`max` ignore a NaN operand and return the
        // *other* one (`f64::NAN.min(30.0) == 30.0`), unlike Python's
        // comparison-based `min`/`max`, which propagate NaN (confirmed
        // against live `python3.12`: `min(float("nan"), 30.0)` is `nan`,
        // not `30.0`) -- so NaN must be handled before any clamping, not
        // silently normalized away by it.
        if seconds.is_nan() {
            // `time.sleep(nan)` raises `ValueError("Invalid value NaN (not
            // a number)")` inside the handler, uncaught: the connection
            // drops with no response written, and the gateway relay sees
            // `502 upstream_protocol_error`. `Duration::from_secs_f64(NaN)`
            // would instead PANIC -- a panic on agent-supplied relayed
            // input, which PORTING.md §4 forbids. Returning here without
            // writing a response reproduces the same "handler died before
            // responding" outcome without panicking.
            return;
        }
        let seconds = seconds.min(30.0);
        std::thread::sleep(Duration::from_secs_f64(seconds.max(0.0)));
        responder.send_json(200, &json!({"slept": seconds}), &[]);
    } else {
        responder.send_json(404, &json!({"error": "not_found"}), &[]);
    }
}

fn encoded_credential_for(server: &Server, form: &str) -> Option<String> {
    encoding_of(
        &server.credential,
        &server.mode,
        server.basic_username.as_deref(),
        form,
    )
}
