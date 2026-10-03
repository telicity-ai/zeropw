//! Trusted tools/relay HTTP listener, port of `zeropw.server`.
use crate::{
    audit::RecordArgs,
    context::Context,
    errors::{Error, ErrorClass},
    gateway,
    pyjson::{self, DumpOptions},
    pystr, tools,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

pub const HANDLE_HEADER: &str = "X-ZeroPW-Handle";
pub const REQUEST_ID_HEADER: &str = "X-ZeroPW-Request-Id";
pub const MAX_TOOL_BODY: usize = 1024 * 1024;
pub const SERVER_HEADER: &str = "zeropw-prototype";
pub const REQUEST_TIMEOUT_SECONDS: f64 = 15.0;
pub const REQUEST_READ_DEADLINE_SECONDS: f64 = 30.0;
pub const MAX_CONNECTIONS: usize = 128;
/// `http.client._MAXLINE` (also `handle_one_request`'s request-line limit).
const MAX_LINE: usize = 65536;
/// `http.client._MAXHEADERS`.
const MAX_HEADERS: usize = 100;
/// The commands `ZeroPWHandler` has a `do_<COMMAND>` method for; any other
/// is `send_error(501, "Unsupported method (%r)")`.
const HANDLED_METHODS: &[&str] = &[
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE",
];
/// A panic in one connection's worker must not poison the server's shared
/// state for every later connection (Python has no lock poisoning).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}
pub fn error_status(e: &Error) -> u16 {
    match e.class {
        ErrorClass::AuthFailed => 401,
        ErrorClass::PolicyDenied => 403,
        ErrorClass::NotFound => 404,
        ErrorClass::InvalidInput => 400,
        ErrorClass::Unsupported => 501,
        ErrorClass::AuditUnavailable | ErrorClass::StateError => 503,
        _ => 500,
    }
}
struct Client {
    stream: TcpStream,
    started: Option<Instant>,
    reaped: bool,
}
struct Inner {
    ctx: Arc<Context>,
    listener: Mutex<Option<Arc<TcpListener>>>,
    url: String,
    clients: Mutex<HashMap<u64, Client>>,
    next: AtomicU64,
    stop: AtomicBool,
    max_connections: AtomicUsize,
    timeout: Mutex<Duration>,
    deadline: Mutex<Duration>,
    thread: Mutex<Option<JoinHandle<()>>>,
    runs: Arc<crate::runs::RunRegistry>,
    signer: Arc<crate::signer::SignerManager>,
    quiet: AtomicBool,
    log_lines: Mutex<Vec<String>>,
}
pub struct ZeroPWServer {
    inner: Arc<Inner>,
}
impl ZeroPWServer {
    pub fn new(ctx: Arc<Context>, host: Option<&str>, port: Option<u16>) -> Result<Self, Error> {
        Self::new_with_quiet(ctx, host, port, true)
    }
    /// Python `ZeroPWServer(..., quiet=False)` equivalent.
    pub fn new_with_quiet(
        ctx: Arc<Context>,
        host: Option<&str>,
        port: Option<u16>,
        quiet: bool,
    ) -> Result<Self, Error> {
        let host = host.unwrap_or(&ctx.config.listen_host);
        let port = match port {
            Some(p) => p,
            None => u16::try_from(ctx.config.listen_port)
                .map_err(|_| Error::invalid_input("invalid_listen"))?,
        };
        let listener =
            Arc::new(TcpListener::bind((host, port)).map_err(|_| Error::state("listen_failed"))?);
        listener
            .set_nonblocking(true)
            .map_err(|_| Error::state("listen_failed"))?;
        let address = listener
            .local_addr()
            .map_err(|_| Error::state("listen_failed"))?;
        let url = format!("http://{address}");
        let runs = tools::install(ctx.clone());
        let signer = match tools::signer_manager(&ctx) {
            Some(s) => s,
            None => crate::signer::install(ctx.clone(), None)?,
        };
        tools::set_public_url(&ctx, &url)?;
        gateway::register_local_listener(&listener);
        Ok(Self {
            inner: Arc::new(Inner {
                ctx,
                listener: Mutex::new(Some(listener)),
                url,
                clients: Mutex::new(HashMap::new()),
                next: AtomicU64::new(1),
                stop: AtomicBool::new(false),
                max_connections: AtomicUsize::new(MAX_CONNECTIONS),
                timeout: Mutex::new(Duration::from_secs_f64(REQUEST_TIMEOUT_SECONDS)),
                deadline: Mutex::new(Duration::from_secs_f64(REQUEST_READ_DEADLINE_SECONDS)),
                thread: Mutex::new(None),
                runs,
                signer,
                quiet: AtomicBool::new(quiet),
                log_lines: Mutex::new(Vec::new()),
            }),
        })
    }
    pub fn url(&self) -> String {
        self.inner.url.clone()
    }
    pub fn log_lines(&self) -> Vec<String> {
        lock(&self.inner.log_lines).clone()
    }
    /// Remove and return the recorded request lines (`log_lines.pop(0)`
    /// until empty), so a long-running `serve` does not accumulate them.
    pub fn take_log_lines(&self) -> Vec<String> {
        std::mem::take(
            &mut *self
                .inner
                .log_lines
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        )
    }
    pub fn set_limits(&self, max_connections: usize, timeout: Duration, read_deadline: Duration) {
        self.inner
            .max_connections
            .store(max_connections, Ordering::Release);
        *lock(&self.inner.timeout) = timeout;
        *lock(&self.inner.deadline) = read_deadline;
    }
    pub fn serve_in_thread(&self) -> Result<(), Error> {
        let mut thread = lock(&self.inner.thread);
        if thread.is_some() {
            return Ok(());
        }
        let listener = lock(&self.inner.listener)
            .clone()
            .ok_or_else(|| Error::state("server_closed"))?;
        let inner = self.inner.clone();
        let handle = thread::Builder::new()
            .spawn(move || accept_loop(inner, listener))
            .map_err(|_| Error::state("server_thread_failed"))?;
        *thread = Some(handle);
        Ok(())
    }
    pub fn service_actions(&self) {
        reap(&self.inner);
    }
    pub fn reap_slow_clients(&self) -> usize {
        reap(&self.inner)
    }
    pub fn stop(&self) {
        self.inner.stop.store(true, Ordering::Release);
        if let Some(listener) = lock(&self.inner.listener).take() {
            gateway::unregister_local_listener(&listener);
        }
        for client in lock(&self.inner.clients).values() {
            if client.started.is_some() {
                let _ = client.stream.shutdown(Shutdown::Both);
            }
        }
        let handle = lock(&self.inner.thread).take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
        self.inner.runs.shutdown("shutdown");
        self.inner.signer.shutdown();
    }
    pub fn server_close(&self) {
        self.stop();
    }
}
impl Drop for ZeroPWServer {
    fn drop(&mut self) {
        self.stop();
    }
}
fn reap(inner: &Inner) -> usize {
    let deadline = *lock(&inner.deadline);
    let mut count = 0;
    for c in lock(&inner.clients).values_mut() {
        if !c.reaped && c.started.is_some_and(|t| t.elapsed() > deadline) {
            c.reaped = true;
            let _ = c.stream.shutdown(Shutdown::Both);
            count += 1;
        }
    }
    count
}
fn mark(inner: &Inner, id: u64, reading: bool) -> bool {
    let mut clients = lock(&inner.clients);
    if let Some(c) = clients.get_mut(&id) {
        if c.reaped {
            return false;
        }
        c.started = reading.then(Instant::now);
        true
    } else {
        false
    }
}
/// `ZeroPWServer._forget` in `process_request_thread`'s `finally`: the
/// connection slot is released however the worker ends, panics included.
struct Slot {
    inner: Arc<Inner>,
    id: u64,
}
impl Drop for Slot {
    fn drop(&mut self) {
        lock(&self.inner.clients).remove(&self.id);
    }
}
/// `serve_forever` keeps serving after a failed `accept` (descriptor
/// exhaustion, a client that reset before it was accepted) and after a
/// worker that could not be started (that one connection is dropped).
fn accept_loop(inner: Arc<Inner>, listener: Arc<TcpListener>) {
    while !inner.stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                // Accepted sockets inherit O_NONBLOCK on macOS, but not Linux.
                // Request workers use blocking reads with bounded deadlines.
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                let id = inner.next.fetch_add(1, Ordering::Relaxed);
                let timeout = *lock(&inner.timeout);
                let _ = stream.set_read_timeout(Some(timeout));
                let _ = stream.set_write_timeout(Some(timeout));
                let admitted = {
                    let mut clients = lock(&inner.clients);
                    if clients.len() >= inner.max_connections.load(Ordering::Acquire) {
                        false
                    } else if let Ok(copy) = stream.try_clone() {
                        clients.insert(
                            id,
                            Client {
                                stream: copy,
                                started: Some(Instant::now()),
                                reaped: false,
                            },
                        );
                        true
                    } else {
                        false
                    }
                };
                if !admitted {
                    let _ = stream.set_nonblocking(true);
                    // One write and a write-side shutdown match Python's
                    // _refuse_busy: no worker, no request read, no blocked
                    // admission loop, and the body accompanies its header.
                    let body = br#"{"error": "StateError", "reason": "too_many_connections"}"#;
                    let mut reply = format!("HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
                    reply.extend_from_slice(body);
                    let _ = stream.write(&reply);
                    let _ = stream.shutdown(Shutdown::Write);
                    continue;
                }
                let slot = Slot {
                    inner: inner.clone(),
                    id,
                };
                // If no thread can be started the closure is dropped here:
                // `slot` frees the place and both socket handles close.
                let _ = thread::Builder::new().spawn(move || {
                    // A panic that escapes the per-request guard still ends
                    // only this connection; `slot` frees its place either way.
                    let _ =
                        catch_unwind(AssertUnwindSafe(|| handle_client(&slot.inner, id, stream)));
                    drop(slot);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5))
            }
            // EMFILE/ENFILE leave the connection queued: back off, don't spin.
            Err(e) if matches!(e.raw_os_error(), Some(libc::EMFILE | libc::ENFILE)) => {
                thread::sleep(Duration::from_millis(50))
            }
            Err(_) => thread::sleep(Duration::from_millis(5)),
        }
        reap(&inner);
    }
}
struct Request {
    method: String,
    path: String,
    headers: gateway::Headers,
    length: u64,
    close: bool,
}
impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }
}
/// `email.message.Message.get(name)`: the first field with that name.
fn header<'a>(headers: &'a gateway::Headers, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}
/// What `BaseHTTPRequestHandler` knows when a reply is written, filled in
/// as `parse_request` proceeds: `command`, `path`, `request_version` and
/// `close_connection`.
struct Progress {
    command: Option<String>,
    path: Option<String>,
    version: String,
    close: bool,
}
impl Default for Progress {
    fn default() -> Self {
        Self {
            command: None,
            path: None,
            version: "HTTP/0.9".into(),
            close: true,
        }
    }
}
enum ParseError {
    /// No reply is possible (EOF, timeout, reset, blank request line).
    Gone,
    /// `send_error(code, message, explain)`: an HTML reply, then close.
    Error(u16, Option<String>, Option<&'static str>),
    /// `ZeroPWHandler._refuse_framing(reason)`.
    Framing(&'static str),
    /// `parse_request`'s absolute-URI refusal; `close` is whether the reply
    /// itself carries `Connection: close` (the connection closes anyway).
    AbsoluteUri { close: bool },
}
/// `rfile.readline(65537)`.
fn line(reader: &mut BufReader<TcpStream>) -> Result<Vec<u8>, ParseError> {
    let mut line = Vec::new();
    reader
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', &mut line)
        .map_err(|_| ParseError::Gone)?;
    Ok(line)
}
fn token(s: &[u8]) -> bool {
    !s.is_empty()
        && s.iter()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
}
fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|b| char::from(*b)).collect()
}
/// `parse_request`'s version check: `HTTP/<major>.<minor>`, each part
/// `str.isdigit()`, at most ten characters, then `int()` -- for latin-1
/// text only ASCII digits pass both.
fn parse_version(version: &str) -> Option<(u64, u64)> {
    let (major, minor) = version.strip_prefix("HTTP/")?.split_once('.')?;
    let number = |part: &str| {
        (!part.is_empty() && part.len() <= 10 && part.bytes().all(|b| b.is_ascii_digit()))
            .then(|| part.parse().ok())
            .flatten()
    };
    Some((number(major)?, number(minor)?))
}
/// `ZeroPWHandler.handle_one_request`/`parse_request`: CPython's
/// `BaseHTTPRequestHandler` request-line, version and header rules, the
/// strict header reader, `_check_framing` and the absolute-URI refusal, in
/// that order.
fn parse(reader: &mut BufReader<TcpStream>, p: &mut Progress) -> Result<Request, ParseError> {
    let raw = line(reader)?;
    if raw.len() > MAX_LINE {
        p.version = String::new();
        p.command = Some(String::new());
        return Err(ParseError::Error(414, None, None));
    }
    let text = latin1(&raw);
    let requestline = text.trim_end_matches(['\r', '\n']);
    let words: Vec<&str> = requestline
        .split(pystr::is_space)
        .filter(|w| !w.is_empty())
        .collect();
    let Some((&command, rest)) = words.split_first() else {
        return Err(ParseError::Gone);
    };
    if let [.., version] = words[..]
        && words.len() >= 3
    {
        let Some(number) = parse_version(version) else {
            let message = format!("Bad request version ({})", pystr::repr_str(version));
            return Err(ParseError::Error(400, Some(message), None));
        };
        if number >= (1, 1) {
            p.close = false;
        }
        if number >= (2, 0) {
            let message = format!(
                "Invalid HTTP version ({})",
                version.strip_prefix("HTTP/").unwrap_or(version)
            );
            return Err(ParseError::Error(505, Some(message), None));
        }
        p.version = version.to_string();
    }
    if !(2..=3).contains(&words.len()) {
        let message = format!("Bad request syntax ({})", pystr::repr_str(requestline));
        return Err(ParseError::Error(400, Some(message), None));
    }
    if words.len() == 2 {
        p.close = true;
        if command != "GET" {
            let message = format!("Bad HTTP/0.9 request type ({})", pystr::repr_str(command));
            return Err(ParseError::Error(400, Some(message), None));
        }
    }
    let mut path = rest.first().copied().unwrap_or_default().to_string();
    if path.starts_with("//") {
        path = format!("/{}", path.trim_start_matches('/'));
    }
    p.command = Some(command.to_string());
    p.path = Some(path.clone());
    let headers = read_headers(reader)?;
    match header(&headers, "Connection") {
        Some(v) if v.eq_ignore_ascii_case("close") => p.close = true,
        Some(v) if v.eq_ignore_ascii_case("keep-alive") => p.close = false,
        _ => (),
    }
    // `handle_expect_100`, before `_check_framing`, and only when the
    // request version compares (as text) at least "HTTP/1.1".
    if header(&headers, "Expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
        && p.version.as_str() >= "HTTP/1.1"
        && reader
            .get_mut()
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .is_err()
    {
        return Err(ParseError::Gone);
    }
    // `_check_framing`.
    let parts: Vec<_> = raw
        .strip_suffix(b"\r\n")
        .ok_or(ParseError::Framing("malformed_request_line"))?
        .split(|b| *b == b' ')
        .collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|p| p.is_empty() || p.contains(&b'\r') || p.contains(&b'\t'))
    {
        return Err(ParseError::Framing("malformed_request_line"));
    }
    if header(&headers, "Transfer-Encoding").is_some() {
        return Err(ParseError::Framing("transfer_encoding_unsupported"));
    }
    let lengths: Vec<_> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .collect();
    if lengths.len() > 1 {
        return Err(ParseError::Framing("invalid_content_length"));
    }
    let length = if let Some((_, s)) = lengths.first() {
        let s = s.trim_matches([' ', '\t']);
        if s.is_empty() || s.len() > 19 || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ParseError::Framing("invalid_content_length"));
        }
        s.parse()
            .map_err(|_| ParseError::Framing("invalid_content_length"))?
    } else {
        0
    };
    if path.split('?').next().unwrap_or("").contains("://") {
        return Err(ParseError::AbsoluteUri {
            close: p.close || length > 0,
        });
    }
    Ok(Request {
        method: command.to_string(),
        path,
        headers,
        length,
        close: p.close,
    })
}
/// `http.client.parse_headers(_StrictHeaderReader(rfile))`.
fn read_headers(reader: &mut BufReader<TcpStream>) -> Result<gateway::Headers, ParseError> {
    let mut headers = Vec::new();
    for count in 1.. {
        let raw = line(reader)?;
        // `_StrictHeaderReader.readline`: an over-long line goes back as is
        // (`http.client` raises `LineTooLong`); anything else must be the
        // blank terminator or a CRLF-terminated `token ":" value` line.
        let over_long = raw.len() > MAX_LINE && !raw.ends_with(b"\r\n");
        if !over_long && raw != b"\r\n" {
            let content = raw
                .strip_suffix(b"\r\n")
                .ok_or(ParseError::Framing("malformed_header"))?;
            if content.iter().any(|b| [0, b'\r', b'\n'].contains(b)) {
                return Err(ParseError::Framing("malformed_header"));
            }
            if content.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
                return Err(ParseError::Framing("obsolete_line_folding"));
            }
            let at = content
                .iter()
                .position(|b| *b == b':')
                .ok_or(ParseError::Framing("malformed_header"))?;
            let (name, value) = content.split_at(at);
            if !token(name) {
                return Err(ParseError::Framing("malformed_header"));
            }
            let value = value.get(1..).unwrap_or_default();
            let start = value
                .iter()
                .position(|b| !matches!(b, b' ' | b'\t'))
                .unwrap_or(value.len());
            headers.push((latin1(name), latin1(&value[start..])));
        }
        // `http.client._read_headers`: the terminator counts toward the limit.
        if raw.len() > MAX_LINE {
            let explain = "got more than 65536 bytes when reading header line";
            return Err(ParseError::Error(
                431,
                Some("Line too long".into()),
                Some(explain),
            ));
        }
        if count > MAX_HEADERS {
            let explain = "got more than 100 headers";
            return Err(ParseError::Error(
                431,
                Some("Too many headers".into()),
                Some(explain),
            ));
        }
        if raw == b"\r\n" {
            break;
        }
    }
    Ok(headers)
}
fn handle_client(inner: &Arc<Inner>, id: u64, stream: TcpStream) {
    let mut reader = BufReader::new(stream);
    while !inner.stop.load(Ordering::Acquire) {
        if !mark(inner, id, true) {
            break;
        }
        let mut progress = Progress::default();
        let parsed = parse(&mut reader, &mut progress);
        let stream = reader.get_mut();
        let request = match parsed {
            Ok(r) => r,
            Err(ParseError::Gone) => break,
            Err(ParseError::Error(code, message, explain)) => {
                mark(inner, id, false);
                let _ = send_error(inner, stream, &progress, code, message, explain);
                break;
            }
            Err(ParseError::Framing(reason)) => {
                mark(inner, id, false);
                let body = json_body(&json!({"error":"InvalidInput","reason":reason}));
                let _ = send(inner, stream, &progress, 400, &body, &json_type(), true);
                break;
            }
            Err(ParseError::AbsoluteUri { close }) => {
                mark(inner, id, false);
                let body =
                    json_body(&json!({"error":"Unsupported","reason":"absolute_uri_unsupported"}));
                let _ = send(inner, stream, &progress, 400, &body, &json_type(), close);
                break;
            }
        };
        if !HANDLED_METHODS.contains(&request.method.as_str()) {
            mark(inner, id, false);
            let message = format!("Unsupported method ({})", pystr::repr_str(&request.method));
            let _ = send_error(inner, stream, &progress, 501, Some(message), None);
            break;
        }
        let mut consumed = false;
        // `_dispatch`'s final `except Exception`: never leak internals;
        // answer the fixed 500 body instead of dropping the connection.
        let result = catch_unwind(AssertUnwindSafe(|| {
            dispatch(inner, id, &request, &mut reader, &mut consumed)
        }))
        .unwrap_or_else(|_| {
            json_reply(
                500,
                json!({"error":"InternalError","reason":"internal_error"}),
            )
        });
        let (status, body, headers) = match result {
            Ok(reply) => {
                if !mark(inner, id, false) {
                    break;
                }
                reply
            }
            Err(DispatchError::Gone) => break,
            Err(DispatchError::Error(e)) if gateway::is_escaped_builtin(&e) => {
                // `_dispatch`'s final `except Exception`: a CPython built-in
                // (not a `ZeroPWError`) gets the fixed internal-error reply.
                mark(inner, id, false);
                (
                    500.into(),
                    json_body(&json!({"error":"InternalError","reason":"internal_error"})),
                    json_type(),
                )
            }
            Err(DispatchError::Error(e)) => {
                mark(inner, id, false);
                (
                    error_status(&e).into(),
                    json_body(&e.to_dict()),
                    json_type(),
                )
            }
        };
        let close = request.close || (!consumed && request.length > 0);
        if send(
            inner,
            reader.get_mut(),
            &progress,
            status,
            &body,
            &headers,
            close,
        )
        .is_err()
            || close
        {
            break;
        }
    }
    let _ = reader.get_ref().shutdown(Shutdown::Both);
}
/// `ZeroPWHandler.log_message`, reached through `send_response`'s
/// `log_request`: the method and query-free path, `/h/` handles masked.
fn log_request(inner: &Inner, progress: &Progress) {
    if inner.quiet.load(Ordering::Acquire) {
        return;
    }
    let (Some(command), Some(path)) = (&progress.command, &progress.path) else {
        return;
    };
    let path = path.split('?').next().unwrap_or("");
    let path = if path.starts_with("/h/") {
        "/h/<handle>/..."
    } else {
        path
    };
    lock(&inner.log_lines).push(format!("{command} {path}"));
}
enum DispatchError {
    Gone,
    Error(Error),
}
impl From<Error> for DispatchError {
    fn from(e: Error) -> Self {
        Self::Error(e)
    }
}
type Reply = (crate::pyint::PyInt, Vec<u8>, gateway::Headers);
fn json_type() -> gateway::Headers {
    vec![("Content-Type".into(), "application/json".into())]
}
/// `json.dumps(payload, sort_keys=True)` of a fixed reply or error mapping.
fn json_body(value: &Value) -> Vec<u8> {
    pyjson::dumps(value, DumpOptions::default_sorted())
        .unwrap_or_else(|_| r#"{"error": "InternalError", "reason": "internal_error"}"#.into())
        .into_bytes()
}
fn json_reply(status: u16, value: Value) -> Result<Reply, DispatchError> {
    Ok((
        status.into(),
        pyjson::dumps(&value, DumpOptions::default_sorted())?.into_bytes(),
        json_type(),
    ))
}
fn read_body(
    inner: &Inner,
    id: u64,
    r: &Request,
    reader: &mut BufReader<TcpStream>,
    limit: i64,
    consumed: &mut bool,
) -> Result<Vec<u8>, DispatchError> {
    // `length > limit` on Python ints: a negative limit refuses every request.
    if i128::from(r.length) > i128::from(limit) {
        return Err(Error::invalid_input("request_body_too_large").into());
    }
    let mut data = vec![0; usize::try_from(r.length).map_err(|_| DispatchError::Gone)?];
    reader
        .read_exact(&mut data)
        .map_err(|_| DispatchError::Gone)?;
    *consumed = true;
    if !mark(inner, id, false) {
        return Err(DispatchError::Gone);
    }
    Ok(data)
}
fn authenticate(ctx: &Context, r: &Request, name: &str) -> Result<String, Error> {
    let token = r
        .header("Authorization")
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| v.trim_matches(pystr::is_space))
        .filter(|v| !v.is_empty());
    let result = token
        .ok_or_else(|| Error::auth_failed("caller_token_missing"))
        .and_then(|t| ctx.policy.authenticate(t));
    match result {
        Ok(p) => Ok(p.id),
        Err(e) if e.class == ErrorClass::AuthFailed => {
            let caller = if e.reason == "principal_disabled" {
                let digest = crate::policy::hash_token(token.unwrap_or(""));
                ctx.policy
                    .list_principals()?
                    .into_iter()
                    .find(|p| bool::from(p.token_hash.as_bytes().ct_eq(digest.as_bytes())))
                    .map(|p| p.id)
            } else {
                None
            };
            ctx.audit
                .record(
                    "auth_failed",
                    RecordArgs {
                        caller: caller.as_deref(),
                        action: tools::TOOL_NAMES.contains(&name).then_some(name),
                        result: Some("denied"),
                        reason: Some(&e.reason),
                        extra: vec![("kind", json!("caller_token"))],
                        ..Default::default()
                    },
                )
                .map_err(|_| Error::audit_unavailable("audit_unavailable"))?;
            Err(e)
        }
        Err(e) => Err(e),
    }
}
fn dispatch(
    inner: &Inner,
    id: u64,
    r: &Request,
    reader: &mut BufReader<TcpStream>,
    consumed: &mut bool,
) -> Result<Reply, DispatchError> {
    let ctx = &inner.ctx;
    if r.method == "CONNECT" {
        return json_reply(
            405,
            json!({"error":"Unsupported","reason":"connect_tunnel_unsupported"}),
        );
    }
    if r.method == "TRACE" {
        return json_reply(
            405,
            json!({"error":"Unsupported","reason":"method_not_supported"}),
        );
    }
    #[cfg(test)]
    if r.path == tests::PANIC_PATH {
        panic!("synthetic request handler failure");
    }
    let self_relay = r
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("via"))
        .any(|(_, v)| {
            v.split(',').any(|hop| {
                hop.split(pystr::is_space)
                    .filter(|w| !w.is_empty())
                    .nth(1)
                    .is_some_and(|name| name.eq_ignore_ascii_case(gateway::RELAY_PSEUDONYM))
            })
        });
    if self_relay {
        let _ = ctx.audit.record(
            "unsupported",
            RecordArgs {
                action: Some(&r.method),
                result: Some("denied"),
                reason: Some("self_referential_target"),
                ..Default::default()
            },
        );
        return json_reply(
            501,
            json!({"error":"Unsupported","reason":"self_referential_target"}),
        );
    }
    if let Some(name) = r.path.strip_prefix("/v1/tools/") {
        if r.method != "POST" {
            return Err(Error::invalid_input("tools_require_post").into());
        }
        let name = name.split('?').next().unwrap_or("");
        let caller = authenticate(ctx, r, name)?;
        let raw = read_body(inner, id, r, reader, MAX_TOOL_BODY as i64, consumed)?;
        let value = if raw.is_empty() {
            json!({})
        } else {
            pyjson::loads(
                std::str::from_utf8(&raw).map_err(|_| Error::invalid_input("invalid_json"))?,
            )
            .map_err(|_| Error::invalid_input("invalid_json"))?
        };
        if !value.is_object() {
            return Err(Error::invalid_input("invalid_json").into());
        }
        return json_reply(200, tools::dispatch(ctx, name, &caller, &value)?);
    }
    let relay = if let Some(rest) = r.path.strip_prefix("/h/") {
        let (handle, path) = rest.split_once('/').unwrap_or((rest, ""));
        Some((handle, format!("/{path}")))
    } else if r.path == "/relay" || r.path.starts_with("/relay/") {
        Some((
            r.header(HANDLE_HEADER).unwrap_or(""),
            r.path
                .strip_prefix("/relay")
                .filter(|s| !s.is_empty())
                .unwrap_or("/")
                .to_string(),
        ))
    } else {
        None
    };
    if let Some((handle, path)) = relay {
        let limit = ctx.config.max_request_body_bytes;
        let body = read_body(inner, id, r, reader, limit, consumed)?;
        // `{k: v for k, v in self.headers.items()}`: a repeated name (same
        // spelling) keeps its first position and its last value.
        let mut headers = gateway::Headers::new();
        for (name, value) in &r.headers {
            match headers.iter_mut().find(|(known, _)| known == name) {
                Some(entry) => entry.1.clone_from(value),
                None => headers.push((name.clone(), value.clone())),
            }
        }
        // `gateway.relay` raising propagates to `_dispatch`'s handlers,
        // exactly like any other exception from this route.
        let result = gateway::try_relay(
            ctx,
            handle,
            &r.method,
            &path,
            &headers,
            &body,
            r.header(REQUEST_ID_HEADER),
        )?;
        return Ok((result.status, result.body, result.headers));
    }
    if r.path == "/healthz" {
        json_reply(200, json!({"status":"ok"}))
    } else {
        json_reply(404, json!({"error":"NotFound","reason":"route_not_found"}))
    }
}
/// `BaseHTTPRequestHandler.responses[code][0]` (`''` for other codes).
fn reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Request Entity Too Large",
        414 => "Request-URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Requested Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a Teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Entity",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => "",
    }
}

fn exact_reason_phrase(status: &crate::pyint::PyInt) -> &'static str {
    status
        .to_string()
        .parse::<u16>()
        .ok()
        .map(reason_phrase)
        .unwrap_or("")
}
/// `BaseHTTPRequestHandler.responses[code][1]` for the codes `send_error`
/// is used with here.
fn explanation(code: u16) -> &'static str {
    match code {
        400 => "Bad request syntax or unsupported method",
        414 => "URI is too long",
        431 => {
            "The server is unwilling to process the request because its header fields are too large"
        }
        501 => "Server does not support this operation",
        505 => "Cannot fulfill request",
        _ => "",
    }
}
/// `html.escape(text, quote=False)`.
fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
/// `BaseHTTPRequestHandler.send_error`'s reason phrase (the message, or the
/// status's own phrase) and its `error_message_format` HTML body.
pub(crate) fn error_page(
    code: u16,
    message: Option<String>,
    explain: Option<&str>,
) -> (String, String) {
    let message = message.unwrap_or_else(|| reason_phrase(code).into());
    let body = format!(
        "<!DOCTYPE HTML>\n<html lang=\"en\">\n    <head>\n        <meta charset=\"utf-8\">\n        <title>Error response</title>\n    </head>\n    <body>\n        <h1>Error response</h1>\n        <p>Error code: {code}</p>\n        <p>Message: {}.</p>\n        <p>Error code explanation: {code} - {}.</p>\n    </body>\n</html>\n",
        html_escape(&message),
        html_escape(explain.unwrap_or(explanation(code)))
    );
    (message, body)
}
/// `BaseHTTPRequestHandler.send_error(code, message, explain)`.
fn send_error(
    inner: &Inner,
    stream: &mut TcpStream,
    progress: &Progress,
    code: u16,
    message: Option<String>,
    explain: Option<&str>,
) -> std::io::Result<()> {
    let (message, body) = error_page(code, message, explain);
    let headers = [
        ("Connection".into(), "close".into()),
        ("Content-Type".into(), "text/html;charset=utf-8".into()),
        ("Content-Length".into(), body.len().to_string()),
    ];
    log_request(inner, progress);
    let status = crate::pyint::PyInt::from(code);
    write_response(
        stream,
        progress,
        &status,
        &message,
        &headers,
        body.as_bytes(),
    )
}
/// `ZeroPWHandler._send`.
fn send(
    inner: &Inner,
    stream: &mut TcpStream,
    progress: &Progress,
    status: impl Into<crate::pyint::PyInt>,
    body: &[u8],
    headers: &gateway::Headers,
    close: bool,
) -> std::io::Result<()> {
    let status = status.into();
    let mut all = headers.clone();
    all.push(("Content-Length".into(), body.len().to_string()));
    all.push(("Cache-Control".into(), "no-store".into()));
    if close {
        all.push(("Connection".into(), "close".into()));
    }
    log_request(inner, progress);
    write_response(
        stream,
        progress,
        &status,
        exact_reason_phrase(&status),
        &all,
        body,
    )
}
/// `send_response` + `send_header`s + `end_headers` + body, latin-1 encoded
/// like CPython's header buffer. An HTTP/0.9 request gets the body alone;
/// a HEAD request gets no body.
fn write_response(
    stream: &mut TcpStream,
    progress: &Progress,
    status: &crate::pyint::PyInt,
    phrase: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> std::io::Result<()> {
    let mut out = Vec::new();
    if progress.version != "HTTP/0.9" {
        let mut head = format!(
            "HTTP/1.1 {status} {phrase}\r\nServer: {SERVER_HEADER} \r\nDate: {}\r\n",
            http_date()
        );
        for (k, v) in headers {
            if k.contains(['\r', '\n']) || v.contains(['\r', '\n']) {
                return Err(std::io::Error::other("invalid response header"));
            }
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str("\r\n");
        for c in head.chars() {
            out.push(u8::try_from(u32::from(c)).map_err(std::io::Error::other)?);
        }
    }
    if progress.command.as_deref() != Some("HEAD") {
        out.extend_from_slice(body);
    }
    stream.write_all(&out)?;
    stream.flush()
}
fn http_date() -> String {
    let now = crate::store::now();
    let iso = crate::store::iso(Some(now));
    let day = ((now as u64 / 86400) + 4) % 7;
    let month = iso
        .get(5..7)
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1);
    format!(
        "{}, {} {} {} {} GMT",
        ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][day as usize],
        iso.get(8..10).unwrap_or("01"),
        [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
        ][month.saturating_sub(1).min(11)],
        iso.get(..4).unwrap_or("1970"),
        iso.get(11..19).unwrap_or("00:00:00")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Config;

    /// Only this module's tests route a request here; production builds do
    /// not contain the branch.
    pub(super) const PANIC_PATH: &str = "/__synthetic_panic__";

    #[test]
    fn replay_status_line_keeps_unbounded_decimal_value() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let status = crate::pyint::PyInt(
            "18446744073709551816"
                .parse()
                .expect("synthetic bigint status"),
        );
        let progress = Progress {
            version: "HTTP/1.1".to_string(),
            ..Progress::default()
        };
        write_response(&mut server, &progress, &status, "", &[], b"").unwrap();
        server.shutdown(Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 18446744073709551816 \r\n"));
    }

    fn server() -> (tempfile::TempDir, ZeroPWServer) {
        let (temp, server) = idle_server();
        server.serve_in_thread().unwrap();
        (temp, server)
    }

    /// `ZeroPWServer(self.ctx)` without `serve_in_thread`: nothing reaps
    /// except an explicit `reap_slow_clients`.
    fn idle_server() -> (tempfile::TempDir, ZeroPWServer) {
        let temp = tempfile::TempDir::new().unwrap();
        let ctx = Arc::new(
            Context::initialize(
                temp.path().join("state"),
                "synthetic-admin-passphrase",
                "synthetic-recovery-passphrase",
                Config::default(),
                crate::clock::system(),
            )
            .unwrap(),
        );
        let server = ZeroPWServer::new(ctx, None, None).unwrap();
        (temp, server)
    }

    fn exchange(server: &ZeroPWServer, request: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect(server.url().trim_start_matches("http://")).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(request).unwrap();
        let mut out = Vec::new();
        let _ = stream.read_to_end(&mut out);
        out
    }

    /// `_dispatch`'s `except Exception` answers 500 with the fixed body,
    /// keeps the keep-alive framing, and `_forget` always frees the slot.
    #[test]
    fn handler_panic_answers_500_and_frees_the_connection_slot() {
        let (_temp, server) = server();
        server.set_limits(1, Duration::from_secs(5), Duration::from_secs(10));
        let request = format!(
            "GET {PANIC_PATH} HTTP/1.1\r\nHost: x\r\n\r\nGET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        );
        let response = String::from_utf8(exchange(&server, request.as_bytes())).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 500 Internal Server Error\r\n"),
            "{response}"
        );
        assert!(response.contains(
            "Content-Length: 54\r\nCache-Control: no-store\r\n\r\n{\"error\": \"InternalError\", \"reason\": \"internal_error\"}HTTP/1.1 200 OK\r\n"
        ), "{response}");
        // With a single slot, a leaked entry would refuse every later client.
        for _ in 0..3 {
            let deadline = Instant::now() + Duration::from_secs(3);
            let response = loop {
                let response = exchange(
                    &server,
                    format!("GET {PANIC_PATH} HTTP/1.1\r\nConnection: close\r\n\r\n").as_bytes(),
                );
                if response.starts_with(b"HTTP/1.1 500") || Instant::now() > deadline {
                    break response;
                }
                thread::sleep(Duration::from_millis(20));
            };
            assert!(
                response.starts_with(b"HTTP/1.1 500"),
                "{}",
                String::from_utf8_lossy(&response)
            );
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while !lock(&server.inner.clients).is_empty() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(lock(&server.inner.clients).is_empty());
        server.stop();
    }

    /// A poisoned server lock (a panic while holding it) does not take the
    /// server down with it.
    #[test]
    fn poisoned_server_locks_do_not_cascade() {
        let (_temp, server) = server();
        let inner = server.inner.clone();
        let _ = thread::spawn(move || {
            let _clients = inner.clients.lock();
            let _timeout = inner.timeout.lock();
            let _lines = inner.log_lines.lock();
            panic!("poison the server locks");
        })
        .join();
        assert!(server.inner.clients.is_poisoned());
        let response = exchange(
            &server,
            b"GET /healthz HTTP/1.1\r\nConnection: close\r\n\r\n",
        );
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        server.set_limits(4, Duration::from_secs(5), Duration::from_secs(10));
        let _ = server.log_lines();
        server.stop();
    }

    /// Port of `SlowClientTests.test_request_cut_at_the_deadline_is_never_acted_on`:
    /// only a connection still waiting for request bytes is reaped, and a
    /// reaped connection learns so when it next marks progress.
    #[test]
    fn request_cut_at_the_deadline_is_never_acted_on() {
        let (_temp, server) = idle_server();
        let inner = server.inner.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let slow_peer = TcpStream::connect(address).unwrap();
        let (slow, _) = listener.accept().unwrap();
        let busy_peer = TcpStream::connect(address).unwrap();
        let (busy, _) = listener.accept().unwrap();
        for (id, stream) in [(9001, slow), (9002, busy)] {
            lock(&inner.clients).insert(
                id,
                Client {
                    stream,
                    started: None,
                    reaped: false,
                },
            );
        }
        assert!(mark(&inner, 9001, true));
        assert!(mark(&inner, 9002, false)); // already processing: never reaped
        server.set_limits(MAX_CONNECTIONS, Duration::from_secs(5), Duration::ZERO);
        thread::sleep(Duration::from_millis(5));
        assert_eq!(server.reap_slow_clients(), 1);
        // The reaped socket was shut down in both directions; the busy one not.
        let mut buffer = [0u8; 1];
        slow_peer
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert_eq!((&slow_peer).read(&mut buffer).unwrap(), 0);
        busy_peer
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        assert!((&busy_peer).read(&mut buffer).is_err());
        // Even if the last body bytes were already buffered, the handler learns it was cut.
        assert!(!mark(&inner, 9001, false));
        assert!(mark(&inner, 9002, false));
        lock(&inner.clients).clear();
        server.stop();
    }
}
