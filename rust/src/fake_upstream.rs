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

/// `_Handler` defines `do_GET`/`HEAD`/`POST`/`PUT`/`PATCH`/`DELETE`/`OPTIONS`.
const HANDLED_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
const MAX_LINE: usize = 65_536;
const MAX_HEADERS: usize = 100;

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

    /// `FakeUpstream(credential, mode=..., basic_username=...)`'s checks:
    /// `Err` with Python's `ValueError` message for an unsupported mode or a
    /// `basic` mode without a (truthy) `basic_username`.
    pub fn with_mode(
        credential: impl Into<String>,
        mode: &str,
        basic_username: Option<&str>,
    ) -> Result<Self, &'static str> {
        if !["bearer", "basic", "header"].contains(&mode) {
            return Err("unsupported fake upstream mode");
        }
        if mode == "basic" && basic_username.is_none_or(str::is_empty) {
            return Err("basic mode requires basic_username");
        }
        let mut fake = Self::new(credential);
        fake.mode = mode.to_string();
        fake.basic_username = basic_username.map(str::to_string);
        Ok(fake)
    }

    /// `mode="basic"`: an empty `basic_username` is Python's construction
    /// `ValueError`, raised here as a panic in the test that built it.
    pub fn mode_basic(mut self, basic_username: impl Into<String>) -> Self {
        let basic_username = basic_username.into();
        assert!(
            !basic_username.is_empty(),
            "basic mode requires basic_username"
        );
        self.mode = "basic".to_string();
        self.basic_username = Some(basic_username);
        self
    }

    /// `fake.credential`.
    pub fn credential(&self) -> &str {
        &self.credential
    }

    /// `fake.mode`.
    pub fn mode(&self) -> &str {
        &self.mode
    }

    /// `fake.basic_username`.
    pub fn basic_username(&self) -> Option<&str> {
        self.basic_username.as_deref()
    }

    /// `fake.header_name`.
    pub fn header_name(&self) -> &str {
        &self.header_name
    }

    /// `fake.value_prefix`.
    pub fn value_prefix(&self) -> &str {
        &self.value_prefix
    }

    /// `fake.issue_counter` (0 before the fake is started).
    pub fn issue_counter(&self) -> i64 {
        self.state
            .as_ref()
            .map_or(0, |server| server.issue_counter.load(Ordering::SeqCst))
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
        Err(ReadRequestError::Io) => return Ok(()),
        Err(ReadRequestError::Http(code, message, explain, headers, head)) => {
            send_parse_error(
                reader.get_mut(),
                code,
                message,
                explain.as_deref(),
                headers,
                head,
            );
            return Ok(());
        }
    };
    // Any other command is `send_error(501, ...)`, not recorded.
    if !HANDLED_METHODS.contains(&request.method.as_str()) {
        let message = format!(
            "Unsupported method ({})",
            crate::pystr::repr_str(&request.method)
        );
        let response_headers = request.response_headers;
        let head = request.method == "HEAD";
        send_parse_error(
            reader.get_mut(),
            501,
            Some(message),
            None,
            response_headers,
            head,
        );
        return Ok(());
    }
    dispatch(reader.get_mut(), server, request);
    Ok(())
}

struct IncomingRequest {
    method: String,
    raw_path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    response_headers: bool,
}

enum ReadRequestError {
    Io,
    Http(u16, Option<String>, Option<String>, bool, bool),
}

impl From<std::io::Error> for ReadRequestError {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

fn send_parse_error(
    stream: &mut IncomingStream,
    code: u16,
    message: Option<String>,
    explain: Option<&str>,
    headers: bool,
    head: bool,
) {
    let (message, body) = crate::server::error_page(code, message, explain);
    let mut out = Vec::new();
    if headers {
        out.extend_from_slice(format!("HTTP/1.1 {code} {message}\r\n").as_bytes());
        out.extend_from_slice(format!("Server: {FAKE_SERVER_HEADER}\r\n").as_bytes());
        out.extend_from_slice(format!("Date: {}\r\n", date_header()).as_bytes());
        out.extend_from_slice(
            format!(
                "Connection: close\r\nContent-Type: text/html;charset=utf-8\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        );
    }
    if !head {
        out.extend_from_slice(body.as_bytes());
    }
    let _ = stream.write_all(&out);
    let _ = stream.flush();
}

fn read_line(reader: &mut impl BufRead) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    let n = reader
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', &mut line)?;
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(line))
}

fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

/// `BaseHTTPRequestHandler.parse_request` for the requests this fixture
/// answers (three words; `//` paths reduced to one slash), then
/// `http.client.parse_headers`' header block as the `email` parser reads it
/// (see [`parse_header_block`]) and `_Handler._read_body`.
fn read_request(reader: &mut impl BufRead) -> Result<Option<IncomingRequest>, ReadRequestError> {
    let Some(line) = read_line(reader)? else {
        return Ok(None);
    };
    if line.len() > MAX_LINE {
        return Err(ReadRequestError::Http(414, None, None, true, false));
    }
    let line = latin1(&line);
    let requestline = line.trim_end_matches(['\r', '\n']);
    let words: Vec<&str> = requestline
        .split(crate::pystr::is_space)
        .filter(|w| !w.is_empty())
        .collect();
    let Some(method) = words.first().copied() else {
        return Ok(None);
    };
    let mut response_headers = false;
    if words.len() >= 3 {
        let version = words[words.len() - 1];
        let valid = version
            .strip_prefix("HTTP/")
            .and_then(|numbers| numbers.split_once('.'));
        let valid = valid.is_some_and(|(major, minor)| {
            !major.is_empty()
                && !minor.is_empty()
                && major.len() <= 10
                && minor.len() <= 10
                && major.bytes().all(|b| b.is_ascii_digit())
                && minor.bytes().all(|b| b.is_ascii_digit())
        });
        if !valid {
            return Err(ReadRequestError::Http(
                400,
                Some(format!(
                    "Bad request version ({})",
                    crate::pystr::repr_str(version)
                )),
                None,
                false,
                false,
            ));
        }
        let (major, minor) = version[5..].split_once('.').unwrap();
        response_headers = version != "HTTP/0.9";
        if (major.parse::<u64>().unwrap(), minor.parse::<u64>().unwrap()) >= (2, 0) {
            return Err(ReadRequestError::Http(
                505,
                Some(format!("Invalid HTTP version ({major}.{minor})")),
                None,
                false,
                false,
            ));
        }
    }
    if !(2..=3).contains(&words.len()) {
        return Err(ReadRequestError::Http(
            400,
            Some(format!(
                "Bad request syntax ({})",
                crate::pystr::repr_str(requestline)
            )),
            None,
            response_headers,
            false,
        ));
    }
    if words.len() == 2 && method != "GET" {
        return Err(ReadRequestError::Http(
            400,
            Some(format!(
                "Bad HTTP/0.9 request type ({})",
                crate::pystr::repr_str(method)
            )),
            None,
            false,
            false,
        ));
    }
    let raw_path = words[1];
    let method = method.to_string();
    let raw_path = if raw_path.starts_with("//") {
        format!("/{}", raw_path.trim_start_matches('/'))
    } else {
        raw_path.to_string()
    };
    // `_read_headers`: lines up to a blank one or the end of the stream.
    let mut block = Vec::new();
    let mut header_count = 0usize;
    while let Some(header_line) = read_line(reader)? {
        header_count += 1;
        if header_line.len() > MAX_LINE {
            return Err(ReadRequestError::Http(
                431,
                Some("Line too long".into()),
                Some("got more than 65536 bytes when reading header line".into()),
                response_headers,
                method == "HEAD",
            ));
        }
        if header_count > MAX_HEADERS {
            return Err(ReadRequestError::Http(
                431,
                Some("Too many headers".into()),
                Some("got more than 100 headers".into()),
                response_headers,
                method == "HEAD",
            ));
        }
        if header_line == b"\r\n" || header_line == b"\n" {
            break;
        }
        block.push(latin1(&header_line));
    }
    let headers = parse_header_block(&block);
    // An unsupported method is answered 501 before `_read_body` runs.
    let handled = HANDLED_METHODS.contains(&method.as_str());
    let body = match header_get(&headers, "Content-Length").map(crate::pystr::int_from_str) {
        // `rfile.read(size)`: everything up to `size` bytes, fewer if the
        // client stops sending first.
        Some(Some(size)) if size > 0 && handled => {
            let mut buf = Vec::new();
            reader
                .take(u64::try_from(size).unwrap_or(u64::MAX))
                .read_to_end(&mut buf)?;
            buf
        }
        _ => Vec::new(),
    };
    Ok(Some(IncomingRequest {
        method,
        raw_path,
        headers,
        body,
        response_headers,
    }))
}

/// The `email` parser's (compat32) view of a header block: a line is a
/// field when it matches `^[\041-\071\073-\176]*:` (an empty name is a
/// skipped defect); a line starting with a space or tab continues the
/// previous field; a `From ` envelope line is not a field; any other line
/// starts the body, so the fields after it are not headers. A field's value
/// is its first line after the colon with leading blanks removed, plus each
/// continuation line as sent, with trailing CR/LF removed.
fn parse_header_block(lines: &[String]) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut last: Option<usize> = None;
    for line in lines {
        if line.starts_with([' ', '\t']) {
            if let Some(index) = last
                && let Some((_, value)) = headers.get_mut(index)
            {
                value.push_str(line);
            }
            continue;
        }
        if line.starts_with("From ") {
            last = None;
            continue;
        }
        let Some(colon) = line.find(':') else {
            break;
        };
        let (name, value) = line.split_at(colon);
        if !name.chars().all(|c| ('\x21'..='\x7e').contains(&c)) {
            break;
        }
        if name.is_empty() {
            last = None;
            continue;
        }
        let value = value.get(1..).unwrap_or_default();
        headers.push((
            name.to_string(),
            value.trim_start_matches([' ', '\t']).to_string(),
        ));
        last = Some(headers.len() - 1);
    }
    for (_, value) in &mut headers {
        let trimmed = value.trim_end_matches(['\r', '\n']).len();
        value.truncate(trimmed);
    }
    headers
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
    response_headers: bool,
}

/// `BaseHTTPRequestHandler.send_response(status)`: emitted first, before any
/// handler-chosen header, on every response (`_Handler.server_version =
/// "fake-upstream"`; `send_response` always adds `Server`/`Date`). The
/// headers must actually be present so the
/// response-header-allowlist assertion in `rust/tests/gateway.rs` proves
/// `gateway.rs`'s `RESPONSE_HEADER_ALLOWLIST` really does drop them, instead
/// of vacuously passing because this fixture never emitted them in the first
/// place (finding F-20).
const FAKE_SERVER_HEADER: &str = "fake-upstream ";

fn date_header() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (seconds / 86_400) as i64;
    let second = seconds % 86_400;
    let hour = second / 3_600;
    let minute = second % 3_600 / 60;
    let second = second % 60;
    // Howard Hinnant's civil-from-days conversion, with day zero at the
    // Unix epoch.  `BaseHTTPRequestHandler.date_time_string` uses the same
    // current UTC second and IMF-fixdate layout.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let weekdays = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {day:02} {} {year:04} {hour:02}:{minute:02}:{second:02} GMT",
        weekdays[(days + 4).rem_euclid(7) as usize],
        months[(month - 1) as usize]
    )
}

impl Responder<'_> {
    fn write_status_and_boilerplate(&self, out: &mut Vec<u8>, status: u16) {
        if !self.response_headers {
            return;
        }
        out.extend_from_slice(
            format!("HTTP/1.1 {status} {}\r\n", status_reason(status)).as_bytes(),
        );
        out.extend_from_slice(format!("Server: {FAKE_SERVER_HEADER}\r\n").as_bytes());
        out.extend_from_slice(format!("Date: {}\r\n", date_header()).as_bytes());
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
        if self.response_headers {
            if !body.is_empty() || !matches!(status, 204 | 304) {
                out.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
            }
            out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
            for (name, value) in extra_headers {
                out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
            }
            out.extend_from_slice(b"Connection: close\r\n\r\n");
        }
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
        if self.response_headers {
            out.extend_from_slice(b"Content-Type: text/plain\r\n");
            out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
            out.extend_from_slice(b"Connection: close\r\n\r\n");
        }
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
        if self.response_headers {
            head.extend_from_slice(b"Content-Type: application/octet-stream\r\n");
            head.extend_from_slice(format!("Content-Length: {total}\r\n").as_bytes());
            head.extend_from_slice(b"Connection: close\r\n\r\n");
        }
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

/// `urllib.parse.parse_qs(query)` (as `(name, value)` pairs in order): a
/// field without `=` or with an empty value is dropped
/// (`keep_blank_values=False`).
fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter_map(|field| {
            let (name, value) = field.split_once('=')?;
            (!value.is_empty()).then(|| (unquote_plus(name), unquote_plus(value)))
        })
        .collect()
}

/// `float(text)` for a `str` (CPython 3.12 `PyFloat_FromString`): non-ASCII
/// whitespace becomes a space and non-ASCII decimal digits their ASCII
/// digit (any other non-ASCII character fails), PEP 515 underscores only
/// between digits, `Py_ISSPACE` stripped from both ends, then the float
/// literal grammar (`inf`/`infinity`/`nan` in any case, optional sign),
/// which Rust's `f64` parser shares.
fn python_float(text: &str) -> Option<f64> {
    let mut ascii = String::new();
    for c in text.chars() {
        if u32::from(c) < 127 {
            ascii.push(c);
        } else if crate::pystr::is_space(c) {
            ascii.push(' ');
        } else {
            ascii.push(char::from_digit(
                crate::pystr::unicode_decimal_digit(c)?,
                10,
            )?);
        }
    }
    let mut plain = String::new();
    let mut previous = '\0';
    for c in ascii.chars() {
        if c == '_' {
            if !previous.is_ascii_digit() {
                return None;
            }
        } else {
            if previous == '_' && !c.is_ascii_digit() {
                return None;
            }
            plain.push(c);
        }
        previous = c;
    }
    if previous == '_' || plain.contains('\0') {
        return None;
    }
    plain.trim_matches(crate::pystr::is_int_space).parse().ok()
}

/// Port of `urllib.parse.unquote_plus` (via `parse_qsl`'s `_unquote`): `+`
/// becomes a space, then [`crate::pystr::unquote`] (PORTING.md §3b's one
/// canonical home for CPython's `urllib.parse.unquote` run-splitting
/// algorithm -- see that function's doc comment for the full behaviour and
/// the ASCII/non-ASCII run-boundary semantics).
///
/// Every string this module passes here went through [`latin1`], so each
/// Rust `char` is exactly one Python code point / one original wire byte
/// (never part of a multi-byte UTF-8 encoding) -- `pystr::unquote` (and its
/// `unquote_ascii_run` helper) is written to that same char-by-char
/// contract, never raw UTF-8 byte offsets, which is what finding X-7 fixed
/// here: this module used to keep its own copy of the whole algorithm,
/// indexing `&s[i+1..i+3]` on the `str` itself, which panicked whenever a
/// multi-byte-encoded character (e.g. U+0080, encoded as two UTF-8 bytes)
/// put a slice boundary out of alignment with the raw byte offsets `i` was
/// counting -- a bug already fixed once in the sibling `gateway.rs`
/// (`percent_decode_lossy`, finding F-R2-1) and reintroduced here as a
/// byte-identical copy, the exact §3b duplication class this promotion
/// closes (equivalence review round 8).
fn unquote_plus(s: &str) -> String {
    let spaces_for_plus: String = s.chars().map(|c| if c == '+' { ' ' } else { c }).collect();
    crate::pystr::unquote(&spaces_for_plus)
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
        response_headers: request.response_headers,
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

    // `_Handler` accepts every request-target form that
    // `BaseHTTPRequestHandler` accepts and passes `self.path` directly to
    // `urllib.parse.urlsplit`, including absolute-form targets.
    let parsed = match crate::pystr::urlsplit(&request.raw_path) {
        Ok(parsed) => parsed,
        // `urlsplit` can reject malformed bracketed netlocs.  Python lets
        // that ValueError escape the handler, closing the connection without
        // another response.
        Err(_) => return,
    };
    let path = parsed.path.as_str();
    let query = parse_query(&parsed.query);
    let is_get_or_head = method == "GET" || method == "HEAD";

    if is_get_or_head && path == "/repos" {
        responder.send_json(200, &json!([{"name": "demo"}, {"name": "tools"}]), &[]);
    } else if is_get_or_head && path == "/me" {
        responder.send_json(200, &json!({"login": "synthetic-user"}), &[]);
    } else if method == "POST" && path.starts_with("/repos/") && path.ends_with("/issues") {
        // Python: `path[7:-7]` never errors, even when the computed start
        // exceeds the computed end. For `path == "/repos/issues"` (13
        // chars) the `/repos/` prefix (indices 0..7) and the `/issues`
        // suffix (13-7=6..13) overlap by one character -- the `/` at index
        // 6 -- so `path[7:6]` is a backwards slice, which Python clamps to
        // `''` rather than raising (finding X-6, measured over a raw socket
        // against live `python3.12`: `POST /repos/issues` with a JSON body
        // `{"title": "hi"}` answers `201 {"number": 1, "repo": "", "title":
        // "hi"}`). `&path[7..path.len() - 7]` panicked here with "byte
        // range starts at 7 but ends at 6"; `str::get` returns `None`
        // instead of panicking for a backwards range, which
        // `unwrap_or("")` turns into Python's clamp-to-empty.
        let end = path.len() - "/issues".len();
        let name = path.get("/repos/".len()..end).unwrap_or("");
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
        // `int(...)`: CPython's grammar (blanks, `_` separators, signs).
        let offset_raw = crate::pystr::int_from_str(query_get(&query, "offset").unwrap_or("0"));
        let wrap_raw = crate::pystr::int_from_str(query_get(&query, "wrap").unwrap_or("0"));
        let (Some(offset_raw), Some(wrap_raw)) = (offset_raw, wrap_raw) else {
            responder.send_json(400, &json!({"error": "invalid_query"}), &[]);
            return;
        };
        let offset = usize::try_from(offset_raw.clamp(0, 8)).unwrap_or(0);
        let wrap = usize::try_from(wrap_raw.clamp(0, 1024)).unwrap_or(0);
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
        let seconds: f64 = python_float(query_get(&query, "seconds").unwrap_or("1")).unwrap_or(1.0);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Finding X-7, unit-level: `unquote_plus` must never panic on a
    /// latin-1-decoded string (every character `<= U+00FF`) and must match
    /// `urllib.parse.unquote_plus` byte-for-byte, including the cases where
    /// a naive whole-string byte-buffer merge would silently disagree with
    /// Python (a raw non-ASCII character must never combine with an
    /// adjacent `%`-decoded byte sequence). Every expected value here was
    /// cross-checked directly against live `python3.12`:
    /// `urllib.parse.unquote_plus(bytes(...).decode("iso-8859-1"))`.
    #[test]
    fn unquote_plus_matches_python_for_probed_cases() {
        fn case(raw: &[u8], expected_code_points: &[u32]) {
            let s = latin1(raw);
            let got = unquote_plus(&s);
            let got_code_points: Vec<u32> = got.chars().map(|c| c as u32).collect();
            assert_eq!(
                got_code_points, expected_code_points,
                "mismatch for {raw:?} (decoded as {s:?})"
            );
        }
        // `%A` is not a valid `%XX` triplet (only one hex digit follows);
        // the raw non-ASCII byte 0x80 right after it must survive
        // untouched -- this exact input panicked the old byte-offset-slice
        // implementation.
        case(b"%A\x80", &[0x25, 0x41, 0x80]);
        // A dangling `%E4` (incomplete UTF-8 lead byte, no continuation
        // bytes decoded alongside it in the same ASCII run) becomes one
        // U+FFFD; the raw 0x80 that follows is a SEPARATE, non-ASCII run
        // and must NOT be consumed as a continuation byte of that same
        // multi-byte decode.
        case(b"%E4\x80", &[0xFFFD, 0x0080]);
        // Three escapes in one ASCII run combine into one multi-byte
        // character, exactly like CPython's single `bytes.decode` call.
        case(b"%E4%B8%AD", &[0x4E2D]);
        case(b"%E4\x80\xad", &[0xFFFD, 0x0080, 0x00AD]);
        case(
            b"hello+world%20%2Fx",
            &[
                0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x20, 0x2f, 0x78,
            ],
        );
        case(b"%zz%41", &[0x25, 0x7a, 0x7a, 0x41]);
        case(
            b"100%25done",
            &[0x31, 0x30, 0x30, 0x25, 0x64, 0x6f, 0x6e, 0x65],
        );
        case(b"\xff\xfe%41", &[0xff, 0xfe, 0x41]);
    }

    /// `python_float` against CPython's `float(str)` over the shapes the
    /// `/slow?seconds=` query can carry.
    #[test]
    fn python_float_matches_cpython() {
        let cases = [
            "1",
            " 1.5 ",
            "\t2\n",
            "1_0.5",
            "1__0",
            "_1",
            "1_",
            "1_e5",
            "1e_5",
            "1e5",
            "-0.25",
            "+.5",
            "5.",
            ".",
            "e5",
            "inf",
            "-Infinity",
            "INF",
            "nan",
            "+NaN",
            "infin",
            "0x10",
            "1e999",
            "\u{1c}1",
            "\u{a0}3\u{2003}",
            "\u{0663}.\u{0665}",
            "1\u{0}",
            "\u{7f}1",
            "\u{e9}",
            "",
            "  ",
            "1 2",
            "--1",
            "+-1",
            "1.5e+3",
            "1.5E-3",
            "١_٢",
        ];
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_string(&cases.to_vec()).unwrap());
        let script = format!(
            "import base64, json\nfor s in json.loads(base64.b64decode('{encoded}')):\n    try:\n        v = float(s)\n        print('nan' if v != v else repr(v))\n    except ValueError:\n        print('error')\n"
        );
        let expected = crate::oracle::python(&script);
        for (case, python) in cases.iter().zip(expected.lines()) {
            let rust = match python_float(case) {
                Some(v) if v.is_nan() => "nan".to_string(),
                Some(v) => crate::pyjson::python_float_repr(v),
                None => "error".to_string(),
            };
            assert_eq!(rust, python, "float({case:?})");
        }
    }

    /// Finding X-6, unit-level: the `/repos/` prefix and `/issues` suffix
    /// overlap at exactly `path == "/repos/issues"` (13 chars), making the
    /// computed slice bounds backwards. `path.get(7..6)` must return `None`
    /// (never panic), reproducing Python's `path[7:-7] == ''`.
    #[test]
    fn repos_issues_prefix_suffix_overlap_clamps_to_empty() {
        let path = "/repos/issues";
        assert!(path.starts_with("/repos/") && path.ends_with("/issues"));
        let end = path.len() - "/issues".len();
        assert_eq!(path.get("/repos/".len()..end).unwrap_or(""), "");
    }
}
