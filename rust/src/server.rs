//! Trusted tools/relay HTTP listener, port of `zeropw.server`.
use crate::{
    audit::RecordArgs,
    context::Context,
    errors::{Error, ErrorClass},
    gateway,
    pyjson::{self, DumpOptions},
    tools,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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
        self.inner
            .log_lines
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    pub fn set_limits(&self, max_connections: usize, timeout: Duration, read_deadline: Duration) {
        self.inner
            .max_connections
            .store(max_connections, Ordering::Release);
        *self.inner.timeout.lock().unwrap() = timeout;
        *self.inner.deadline.lock().unwrap() = read_deadline;
    }
    pub fn serve_in_thread(&self) -> Result<(), Error> {
        let mut thread = self.inner.thread.lock().unwrap();
        if thread.is_some() {
            return Ok(());
        }
        let listener = self
            .inner
            .listener
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| Error::state("server_closed"))?;
        let inner = self.inner.clone();
        *thread = Some(thread::spawn(move || accept_loop(inner, listener)));
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
        if let Some(listener) = self.inner.listener.lock().unwrap().take() {
            gateway::unregister_local_listener(&listener);
        }
        for client in self.inner.clients.lock().unwrap().values() {
            if client.started.is_some() {
                let _ = client.stream.shutdown(Shutdown::Both);
            }
        }
        if let Some(handle) = self.inner.thread.lock().unwrap().take() {
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
    let deadline = *inner.deadline.lock().unwrap();
    let mut count = 0;
    for c in inner.clients.lock().unwrap().values_mut() {
        if !c.reaped && c.started.is_some_and(|t| t.elapsed() > deadline) {
            c.reaped = true;
            let _ = c.stream.shutdown(Shutdown::Both);
            count += 1;
        }
    }
    count
}
fn mark(inner: &Inner, id: u64, reading: bool) -> bool {
    let mut clients = inner.clients.lock().unwrap();
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
                let timeout = *inner.timeout.lock().unwrap();
                let _ = stream.set_read_timeout(Some(timeout));
                let _ = stream.set_write_timeout(Some(timeout));
                let admitted = {
                    let mut clients = inner.clients.lock().unwrap();
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
                let shared = inner.clone();
                thread::spawn(move || {
                    handle_client(&shared, id, stream);
                    shared.clients.lock().unwrap().remove(&id);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5))
            }
            Err(_) => break,
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
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}
enum ParseError {
    Gone,
    Framing(&'static str),
    Status(u16, &'static str),
}
fn line(reader: &mut BufReader<TcpStream>) -> Result<Vec<u8>, ParseError> {
    let mut line = Vec::new();
    reader
        .take(65537)
        .read_until(b'\n', &mut line)
        .map_err(|_| ParseError::Gone)?;
    if line.is_empty() {
        return Err(ParseError::Gone);
    }
    if line.len() > 65536 {
        return Err(ParseError::Status(431, "header_line_too_long"));
    }
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
fn parse(
    reader: &mut BufReader<TcpStream>,
    parsed_method: &mut Option<String>,
) -> Result<Request, ParseError> {
    let raw = line(reader)?;
    if !raw.ends_with(b"\r\n") {
        return Err(ParseError::Framing("malformed_request_line"));
    }
    let parts: Vec<_> = raw[..raw.len() - 2].split(|b| *b == b' ').collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|p| p.is_empty() || p.contains(&b'\r') || p.contains(&b'\t'))
    {
        return Err(ParseError::Framing("malformed_request_line"));
    }
    let method = latin1(parts[0]);
    *parsed_method = Some(method.clone());
    let mut path = latin1(parts[1]);
    if path.starts_with("//") {
        path = format!("/{}", path.trim_start_matches('/'));
    }
    let version = parts[2];
    if version != b"HTTP/1.1" && version != b"HTTP/1.0" {
        return Err(ParseError::Status(505, "http_version_unsupported"));
    }
    let mut headers = Vec::new();
    loop {
        let raw = line(reader)?;
        if raw == b"\r\n" {
            break;
        }
        if headers.len() >= 99 {
            return Err(ParseError::Status(431, "too_many_headers"));
        }
        if !raw.ends_with(b"\r\n") {
            return Err(ParseError::Framing("malformed_header"));
        }
        let content = &raw[..raw.len() - 2];
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
        if !token(&content[..at]) {
            return Err(ParseError::Framing("malformed_header"));
        }
        let value = &content[at + 1..];
        let start = value
            .iter()
            .position(|b| !matches!(b, b' ' | b'\t'))
            .unwrap_or(value.len());
        headers.push((latin1(&content[..at]), latin1(&value[start..])));
    }
    if headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"))
    {
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
    let close = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("connection"))
        .is_some_and(|(_, v)| v.eq_ignore_ascii_case("close"))
        || version == b"HTTP/1.0";
    if path.split('?').next().unwrap_or("").contains("://") {
        return Err(ParseError::Status(400, "absolute_uri_unsupported"));
    }
    Ok(Request {
        method,
        path,
        headers,
        length,
        close,
    })
}
fn handle_client(inner: &Arc<Inner>, id: u64, stream: TcpStream) {
    let mut reader = BufReader::new(stream);
    while !inner.stop.load(Ordering::Acquire) {
        if !mark(inner, id, true) {
            break;
        }
        let mut parsed_method = None;
        let request = match parse(&mut reader, &mut parsed_method) {
            Ok(r) => r,
            Err(ParseError::Gone) => break,
            Err(ParseError::Framing(reason)) => {
                let _ = send_json(
                    reader.get_mut(),
                    parsed_method.as_deref().unwrap_or("GET"),
                    400,
                    &json!({"error":"InvalidInput","reason":reason}),
                    true,
                );
                break;
            }
            Err(ParseError::Status(status, reason)) => {
                let _ = send_json(
                    reader.get_mut(),
                    parsed_method.as_deref().unwrap_or("GET"),
                    status,
                    &json!({"error":if reason=="absolute_uri_unsupported"{"Unsupported"}else{"InvalidInput"},"reason":reason}),
                    true,
                );
                break;
            }
        };
        log_request(inner, &request);
        if request
            .header("Expect")
            .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
            && reader
                .get_mut()
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .is_err()
        {
            break;
        }
        let mut consumed = false;
        let result = dispatch(inner, id, &request, &mut reader, &mut consumed);
        match result {
            Ok((status, body, headers)) => {
                if !mark(inner, id, false) {
                    break;
                }
                let close = request.close || (!consumed && request.length > 0);
                if send(
                    reader.get_mut(),
                    &request.method,
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
            Err(DispatchError::Gone) => break,
            Err(DispatchError::Error(e)) => {
                mark(inner, id, false);
                let close = request.close || (!consumed && request.length > 0);
                if send_json(
                    reader.get_mut(),
                    &request.method,
                    error_status(&e),
                    &e.to_dict(),
                    close,
                )
                .is_err()
                    || close
                {
                    break;
                }
            }
        }
    }
    let _ = reader.get_ref().shutdown(Shutdown::Both);
}
fn log_request(inner: &Inner, request: &Request) {
    if inner.quiet.load(Ordering::Acquire) {
        return;
    }
    let path = request.path.split('?').next().unwrap_or("");
    let path = if path.starts_with("/h/") {
        "/h/<handle>/..."
    } else {
        path
    };
    inner
        .log_lines
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(format!("{} {}", request.method, path));
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
type Reply = (u16, Vec<u8>, gateway::Headers);
fn json_reply(status: u16, value: Value) -> Result<Reply, DispatchError> {
    Ok((
        status,
        pyjson::dumps(&value, DumpOptions::default_sorted())?.into_bytes(),
        vec![("Content-Type".into(), "application/json".into())],
    ))
}
fn read_body(
    inner: &Inner,
    id: u64,
    r: &Request,
    reader: &mut BufReader<TcpStream>,
    limit: usize,
    consumed: &mut bool,
) -> Result<Vec<u8>, DispatchError> {
    if r.length > limit as u64 {
        return Err(Error::invalid_input("request_body_too_large").into());
    }
    let mut data = vec![0; r.length as usize];
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
        .map(str::trim)
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
    if !["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].contains(&r.method.as_str()) {
        return json_reply(
            501,
            json!({"error":"Unsupported","reason":"method_not_supported"}),
        );
    }
    let self_relay = r
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("via"))
        .any(|(_, v)| {
            v.split(',').any(|hop| {
                hop.split_whitespace()
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
        let raw = read_body(inner, id, r, reader, MAX_TOOL_BODY, consumed)?;
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
        let body = read_body(
            inner,
            id,
            r,
            reader,
            usize::try_from(ctx.config.max_request_body_bytes).unwrap_or(0),
            consumed,
        )?;
        let result = gateway::relay(
            ctx,
            handle,
            &r.method,
            &path,
            &r.headers,
            &body,
            r.header(REQUEST_ID_HEADER),
        );
        return Ok((result.status, result.body, result.headers));
    }
    if r.path == "/healthz" {
        json_reply(200, json!({"status":"ok"}))
    } else {
        json_reply(404, json!({"error":"NotFound","reason":"route_not_found"}))
    }
}
fn send_json(
    stream: &mut TcpStream,
    method: &str,
    status: u16,
    value: &Value,
    close: bool,
) -> std::io::Result<()> {
    let body =
        pyjson::dumps(value, DumpOptions::default_sorted()).map_err(std::io::Error::other)?;
    send(
        stream,
        method,
        status,
        body.as_bytes(),
        &vec![("Content-Type".into(), "application/json".into())],
        close,
    )
}
fn send(
    stream: &mut TcpStream,
    method: &str,
    status: u16,
    body: &[u8],
    headers: &gateway::Headers,
    close: bool,
) -> std::io::Result<()> {
    let label = match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Request Entity Too Large",
        414 => "Request-URI Too Long",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {label}\r\nServer: {SERVER_HEADER} \r\nDate: {}\r\n",
        http_date()
    );
    for (k, v) in headers {
        if k.contains(['\r', '\n']) || v.contains(['\r', '\n']) {
            return Err(std::io::Error::other("invalid response header"));
        }
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nCache-Control: no-store\r\n",
        body.len()
    ));
    if close {
        head.push_str("Connection: close\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    if method != "HEAD" {
        stream.write_all(body)?;
    }
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
