//! Port of `zeropw/gateway.py`: HTTP authentication relay, the only place an
//! upstream HTTP credential is used.
//!
//! See `zeropw/gateway.py`'s module docstring for the security scope and
//! documented limitations (docs/security-design.md §2, §4, §5, §6); this
//! port reproduces the same behaviour with blocking `std` I/O and threads
//! (no async runtime) and `rustls` for TLS, per `rust/PORTING.md`.
//!
//! ## Seams (PORTING.md §3.4)
//!
//! * `gateway._getaddrinfo` (a monkeypatched module global in the Python
//!   tests) becomes [`Resolver`], an explicit injectable function value.
//!   [`relay`]/[`relay_for_caller`] use [`default_resolver`] (the real OS
//!   resolver, via `std::net::ToSocketAddrs`, matching
//!   `socket.getaddrinfo(host, port, type=SOCK_STREAM)`);
//!   [`relay_with_resolver`]/[`relay_for_caller_with_resolver`] take the
//!   resolver explicitly so tests can substitute a fake answer without any
//!   process-global mutable state (racy under Rust's parallel test runner,
//!   unlike Python's `unittest`, which runs sequentially).
//! * `gateway._LOCAL_LISTENERS` (a `weakref.WeakSet[socket.socket]`) becomes
//!   a registry of `Weak<TcpListener>`: [`register_local_listener`] stores a
//!   weak reference to an `Arc<TcpListener>`; once every strong reference is
//!   dropped (the listener closes), the entry silently stops resolving,
//!   exactly like a `weakref.WeakSet` entry after the referent is garbage
//!   collected ("held weakly and ignored once closed" in the Python
//!   docstring).
//! * Dynamically-typed `Any` inputs (`method`/`path`/`headers`/`body`/
//!   `request_id` in Python, which accept any object and raise `_Invalid`
//!   for the wrong Python type) become concrete Rust types (`&str`,
//!   [`Headers`], `&[u8]`, `Option<&str>`): the type-mismatch branches of
//!   `_normalize_method`/`_normalize_body`/`_normalize_headers`/
//!   `_normalize_request_id` have no Rust equivalent (compile-time
//!   impossible), only their *value* validation is ported. See
//!   `DEVIATIONS.md`.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::Duration;

use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::audit::{RecordArgs, strip_query};
use crate::context::Context;
use crate::errors::{Error, ErrorClass};
use crate::policy::{self, Action, Connection, Grant, address_block_reason, approval_digest};
use crate::pyjson::{self, DumpOptions};

// --------------------------------------------------------------- constants

pub const REQUEST_ID_HEADER: &str = "x-zeropw-request-id";

static REQUEST_HEADER_ALLOWLIST: &[&str] = &[
    "accept",
    "content-type",
    "user-agent",
    "x-request-id",
    "if-none-match",
    "if-modified-since",
    "range",
];
static RESPONSE_HEADER_ALLOWLIST: &[&str] = &[
    "content-type",
    "cache-control",
    "etag",
    "last-modified",
    "x-request-id",
    "retry-after",
    "content-language",
    "vary",
];
static REDIRECT_STATUSES: &[u16] = &[301, 302, 303, 307, 308];
pub const MAX_PATH_LENGTH: usize = 8192;
pub const MAX_REQUEST_ID_LENGTH: usize = 128;
pub const LEDGER_DOC: &str = "gateway/requests.json";
pub const LEDGER_MAX_STORED_BODY: usize = 1024 * 1024;
pub const LEDGER_MAX_ENTRIES: usize = 512;
pub const LEDGER_TTL_SECONDS: f64 = 6.0 * 3600.0;
const READ_CHUNK: usize = 64 * 1024;
/// Derived base64 "core" patterns shorter than this are not used.
pub const MIN_ALIGNED_PATTERN_LENGTH: usize = 8;
const WRAP_FORMS: &[&[u8]] = &[b"\r", b"\n", b"\\r", b"\\n"];
pub const RELAY_PSEUDONYM: &str = "zeropw-relay";
pub const APPROVAL_PREVIEW_CHARS: usize = 256;

fn relay_via() -> String {
    format!("1.1 {RELAY_PSEUDONYM}")
}

static TARGET_CHARS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[\x21-\x7e]*$").unwrap());
static CONTROL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\x00-\x1f\x7f]").unwrap());
static HEADER_VALUE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[\x20-\x7e\t]*$").unwrap());
static HEADER_CREDENTIAL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$").unwrap());
static METHOD_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Z]{1,16}$").unwrap());
static REQUEST_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[\x21-\x7e]{1,128}$").unwrap());
static CUSTOM_HEADER_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9-]{1,64}$").unwrap());
static PERCENT_TRIPLET_RE: LazyLock<regex::bytes::Regex> =
    LazyLock::new(|| regex::bytes::Regex::new(r"%[0-9A-Fa-f]{2}").unwrap());
/// Prefixes of ZeroPW's own bearer authority (caller tokens and handles).
static ZEROPW_AUTHORITY_RE: LazyLock<regex::bytes::Regex> =
    LazyLock::new(|| regex::bytes::Regex::new(r"(?:^|[\s:=,;])(?:zpwc_|zpw1\.)").unwrap());

fn error_name_for_status(status: u16) -> &'static str {
    match status {
        400 => "InvalidInput",
        401 => "AuthFailed",
        403 => "PolicyDenied",
        409 => "Conflict",
        428 => "PolicyDenied",
        501 => "Unsupported",
        502 => "UpstreamError",
        503 => "StateError",
        _ => "RelayError",
    }
}

/// A header list: ordered pairs, exactly as received (a real HTTP request's
/// header order matters for byte-identical relayed requests -- see the
/// module doc's seam note; Python's `Mapping[str, str]` is an ordered
/// `dict` in practice, so this is the closer Rust equivalent, not a
/// `HashMap`).
pub type Headers = Vec<(String, String)>;

fn headers_get<'a>(headers: &'a Headers, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Dict-assignment semantics (`d[key] = value`): update in place if `key`
/// already exists (case-sensitively, like a Python `dict`), else append.
fn dict_set(pairs: &mut Headers, key: impl Into<String>, value: impl Into<String>) {
    let key = key.into();
    if let Some(slot) = pairs.iter_mut().find(|(k, _)| *k == key) {
        slot.1 = value.into();
    } else {
        pairs.push((key, value.into()));
    }
}

// ------------------------------------------------------------------- results

/// Port of `gateway.RelayResult`.
#[derive(Clone, Debug)]
pub struct RelayResult {
    pub status: u16,
    pub headers: Headers,
    pub body: Vec<u8>,
    pub reason: Option<String>,
}

impl RelayResult {
    pub fn blocked_reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
    pub fn relayed(&self) -> bool {
        self.reason.is_none()
    }
    /// `RelayResult.json()`.
    pub fn json(&self) -> Value {
        let text = std::str::from_utf8(&self.body).expect("body is UTF-8 JSON");
        pyjson::loads(text).expect("body is valid JSON")
    }
}

fn error_result(
    status: u16,
    reason: &str,
    error: Option<&str>,
    extra: Option<Map<String, Value>>,
) -> RelayResult {
    let mut payload = Map::new();
    payload.insert(
        "error".into(),
        Value::String(
            error
                .unwrap_or_else(|| error_name_for_status(status))
                .into(),
        ),
    );
    payload.insert("reason".into(), Value::String(reason.to_string()));
    if let Some(extra) = extra {
        for (k, v) in extra {
            payload.insert(k, v);
        }
    }
    let body = pyjson::dumps(&Value::Object(payload), DumpOptions::default_sorted())
        .expect("error payload is representable")
        .into_bytes();
    RelayResult {
        status,
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body,
        reason: Some(reason.to_string()),
    }
}

// ---------------------------------------------------------------- validation

/// `gateway._Invalid`: a fixed reason code from input validation.
struct Invalid(&'static str);

/// Port of `gateway.normalize_path`.
///
/// Returns `(path_without_query, forwarded_target)`. The forwarded target is
/// the original path plus query, untouched. Percent-decoding is used only to
/// detect smuggled `..` / `/` / control characters; the decoded form is
/// never forwarded and never used for the policy check.
pub fn normalize_path(raw: &str) -> Result<(String, String), &'static str> {
    normalize_path_inner(raw).map_err(|e| e.0)
}

fn normalize_path_inner(raw: &str) -> Result<(String, String), Invalid> {
    if !raw.starts_with('/') {
        return Err(Invalid("invalid_path"));
    }
    if raw.chars().count() > MAX_PATH_LENGTH || !TARGET_CHARS.is_match(raw) || raw.contains('#') {
        return Err(Invalid("invalid_path"));
    }
    let path = raw.split('?').next().unwrap_or("").to_string();
    let mut candidates = vec![path.clone()];
    let mut decoded = path.clone();
    for _ in 0..2 {
        decoded = percent_decode_lossy(&decoded);
        candidates.push(decoded.clone());
    }
    for candidate in &candidates {
        if candidate.contains('\\') || candidate.contains("://") || CONTROL_RE.is_match(candidate) {
            return Err(Invalid("invalid_path"));
        }
        let segments: Vec<&str> = candidate.split('/').skip(1).collect();
        let last = segments.len().wrapping_sub(1);
        for (index, segment) in segments.iter().enumerate() {
            if *segment == "." || *segment == ".." {
                return Err(Invalid("invalid_path"));
            }
            if segment.is_empty() && index != last {
                return Err(Invalid("invalid_path"));
            }
        }
    }
    Ok((path, raw.to_string()))
}

/// `urllib.parse.unquote(s)` with the default (`errors="replace"`) UTF-8
/// decoding of percent-triplets: a byte sequence that fails to decode as
/// UTF-8 is replaced with U+FFFD per invalid byte/sequence, matching
/// CPython's `bytes.decode("utf-8", "replace")` used internally by
/// `unquote`. Only `%XX` triplets are decoded; other bytes pass through.
fn percent_decode_lossy(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &s[i + 1..i + 3];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn normalize_method(method: &str) -> Result<String, Invalid> {
    let upper = method.trim().to_uppercase();
    if !METHOD_RE.is_match(&upper) {
        return Err(Invalid("invalid_method"));
    }
    Ok(upper)
}

fn normalize_request_id(
    request_id: Option<&str>,
    headers: &Headers,
) -> Result<Option<String>, Invalid> {
    let candidate = request_id
        .map(str::to_string)
        .or_else(|| headers_get(headers, REQUEST_ID_HEADER).map(str::to_string));
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    if candidate.is_empty() {
        return Ok(None);
    }
    if !REQUEST_ID_RE.is_match(&candidate) {
        return Err(Invalid("invalid_request_id"));
    }
    Ok(Some(candidate))
}

/// `gateway._normalize_headers`: lowercase names, last-value-wins.
fn normalize_headers(headers: &Headers) -> Headers {
    let mut out: Headers = Vec::new();
    for (name, value) in headers {
        dict_set(&mut out, name.trim().to_lowercase(), value.clone());
    }
    out
}

fn forwardable_headers(headers: &Headers) -> Result<Headers, Invalid> {
    let mut forwarded = Headers::new();
    for (name, value) in headers {
        if !REQUEST_HEADER_ALLOWLIST.contains(&name.as_str()) {
            continue;
        }
        if !HEADER_VALUE_RE.is_match(value) {
            return Err(Invalid("invalid_header_value"));
        }
        dict_set(&mut forwarded, name.clone(), value.clone());
    }
    Ok(forwarded)
}

// ------------------------------------------------------------- credentials

/// Re-emit every `%XX` triplet in lower case; unreserved bytes are untouched.
fn lowercase_percent_triplets(encoded: &[u8]) -> Vec<u8> {
    PERCENT_TRIPLET_RE
        .replace_all(encoded, |m: &regex::bytes::Captures| {
            m[0].to_ascii_lowercase()
        })
        .into_owned()
}

/// Port of `gateway._base64_cores`.
pub fn base64_cores(data: &[u8]) -> Vec<Vec<u8>> {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE};
    let mut cores = Vec::new();
    for encoder in [&STANDARD, &URL_SAFE] {
        for shift in 0..3usize {
            let mut padded = vec![0u8; shift];
            padded.extend_from_slice(data);
            let encoded = encoder.encode(&padded);
            let encoded = encoded.trim_end_matches('=').as_bytes();
            let head = [0usize, 2, 3][shift];
            let tail = [0usize, 1, 1][(shift + data.len()) % 3];
            if encoded.len() < head + tail {
                continue;
            }
            let core = &encoded[head..encoded.len() - tail];
            if core.len() >= MIN_ALIGNED_PATTERN_LENGTH {
                cores.push(core.to_vec());
            }
        }
    }
    cores
}

/// Port of `gateway.credential_patterns`.
pub fn credential_patterns(secret: &[u8], basic_username: Option<&str>) -> Vec<Vec<u8>> {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE};
    let mut patterns: Vec<Vec<u8>> = vec![secret.to_vec()];
    patterns.push(
        STANDARD
            .encode(secret)
            .trim_end_matches('=')
            .as_bytes()
            .to_vec(),
    );
    patterns.push(
        URL_SAFE
            .encode(secret)
            .trim_end_matches('=')
            .as_bytes()
            .to_vec(),
    );
    patterns.extend(base64_cores(secret));
    patterns.push(hex::encode(secret).into_bytes());
    patterns.push(hex::encode(secret).to_uppercase().into_bytes());
    for quoted in [percent_encode(secret, false), percent_encode(secret, true)] {
        patterns.push(quoted.clone());
        patterns.push(lowercase_percent_triplets(&quoted));
    }
    if let Ok(text) = std::str::from_utf8(secret) {
        patterns.push(json_string_body(text, true));
        patterns.push(json_string_body(text, false));
        patterns.push(html_escape(text).into_bytes());
    }
    if let Some(username) = basic_username {
        let mut pair = username.as_bytes().to_vec();
        pair.push(b':');
        pair.extend_from_slice(secret);
        patterns.push(
            STANDARD
                .encode(&pair)
                .trim_end_matches('=')
                .as_bytes()
                .to_vec(),
        );
        patterns.push(
            URL_SAFE
                .encode(&pair)
                .trim_end_matches('=')
                .as_bytes()
                .to_vec(),
        );
        patterns.extend(base64_cores(&pair));
    }
    let mut unique: Vec<Vec<u8>> = Vec::new();
    for pattern in patterns {
        if !pattern.is_empty() && !unique.contains(&pattern) {
            unique.push(pattern);
        }
    }
    unique
}

/// `urllib.parse.quote(data, safe="")` (upper-case hex) and
/// `urllib.parse.quote_plus(data, safe="")` (space -> `+`, upper-case hex).
fn percent_encode(data: &[u8], plus: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 3);
    for &b in data {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'~');
        if unreserved {
            out.push(b);
        } else if plus && b == b' ' {
            out.push(b'+');
        } else {
            out.push(b'%');
            out.extend_from_slice(format!("{b:02X}").as_bytes());
        }
    }
    out
}

/// `json.dumps(text)[1:-1]` (or `ensure_ascii=False`): the JSON string
/// escaping of `text` with the surrounding quotes stripped, as raw bytes.
fn json_string_body(text: &str, ensure_ascii: bool) -> Vec<u8> {
    let quoted = pyjson::encode_str(text, ensure_ascii);
    let bytes = quoted.as_bytes();
    bytes[1..bytes.len() - 1].to_vec()
}

/// `html.escape(text, quote=True)`.
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

/// Port of `gateway._contains_credential`.
pub fn contains_credential(blob: &[u8], patterns: &[Vec<u8>]) -> bool {
    if patterns.iter().any(|p| contains_subslice(blob, p)) {
        return true;
    }
    let mut compact = blob.to_vec();
    for form in WRAP_FORMS {
        compact = replace_all_bytes(&compact, form, b"");
    }
    compact != blob && patterns.iter().any(|p| contains_subslice(&compact, p))
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn replace_all_bytes(haystack: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    if from.is_empty() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i..].starts_with(from) {
            out.extend_from_slice(to);
            i += from.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

fn auth_header(connection: &Connection, secret: &[u8]) -> Result<(String, String), Invalid> {
    let Some(auth) = &connection.http_auth else {
        return Err(Invalid("unsupported_auth_mode"));
    };
    if ZEROPW_AUTHORITY_RE.is_match(secret.trim_ascii()) {
        return Err(Invalid("self_referential_credential"));
    }
    if auth.mode == "basic" {
        let username = auth.basic_username.as_deref().unwrap_or("");
        if username.is_empty() || username.contains(':') {
            return Err(Invalid("unsupported_auth_mode"));
        }
        use base64::Engine as _;
        let mut pair = username.as_bytes().to_vec();
        pair.push(b':');
        pair.extend_from_slice(secret);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&pair);
        return Ok(("Authorization".to_string(), format!("Basic {encoded}")));
    }
    let Ok(text) = std::str::from_utf8(secret) else {
        return Err(Invalid("credential_not_text"));
    };
    if !HEADER_CREDENTIAL_RE.is_match(text) {
        return Err(Invalid("credential_header_unsafe"));
    }
    if auth.mode == "bearer" {
        return Ok(("Authorization".to_string(), format!("Bearer {text}")));
    }
    if auth.mode == "header" {
        let name = auth.header_name.as_deref().unwrap_or("");
        if name.is_empty() || !CUSTOM_HEADER_NAME_RE.is_match(name) {
            return Err(Invalid("unsupported_auth_mode"));
        }
        let prefix = auth.value_prefix.as_deref().unwrap_or("");
        if !HEADER_VALUE_RE.is_match(prefix) {
            return Err(Invalid("credential_header_unsafe"));
        }
        return Ok((name.to_string(), format!("{prefix}{text}")));
    }
    Err(Invalid("unsupported_auth_mode"))
}

// ---------------------------------------------------------- self-reference

/// Port of `gateway._LOCAL_LISTENERS` (a `weakref.WeakSet[socket.socket]`):
/// see the module doc's seam note. Held weakly (as `Weak<TcpListener>`) so a
/// closed listener whose owner forgot to `unregister_local_listener` is
/// still forgotten once its last `Arc` is dropped.
static LOCAL_LISTENERS: LazyLock<Mutex<Vec<Weak<TcpStreamListener>>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

/// The listener type this module registers: anything that can report its
/// bound local address. A thin alias so the registry does not depend on
/// `std::net::TcpListener` specifically (a future `server.rs` may wrap it).
pub type TcpStreamListener = std::net::TcpListener;

/// Port of `gateway.register_local_listener`.
pub fn register_local_listener(sock: &Arc<TcpStreamListener>) {
    LOCAL_LISTENERS.lock().unwrap().push(Arc::downgrade(sock));
}

/// Port of `gateway.unregister_local_listener`.
pub fn unregister_local_listener(sock: &Arc<TcpStreamListener>) {
    let target = Arc::as_ptr(sock);
    LOCAL_LISTENERS
        .lock()
        .unwrap()
        .retain(|w| w.as_ptr() != target);
}

/// Port of `gateway._listener_addresses`. `pub` (not `pub(crate)`) purely so
/// integration tests (a separate crate) can inspect the registry, mirroring
/// how the Python tests reach into `gateway._listener_addresses` directly.
pub fn listener_addresses() -> Vec<(IpAddr, u16)> {
    let listeners: Vec<Weak<TcpStreamListener>> = LOCAL_LISTENERS.lock().unwrap().clone();
    let mut out = Vec::new();
    for weak in listeners {
        let Some(listener) = weak.upgrade() else {
            continue;
        };
        let Ok(addr) = listener.local_addr() else {
            continue;
        };
        if let Some(ip) = normalize_ip(addr.ip()) {
            out.push((ip, addr.port()));
        }
    }
    out
}

/// `gateway._ip`: parse a literal (stripping `[]` and any `%zone` suffix)
/// and normalize an IPv4-mapped IPv6 address down to plain IPv4.
fn parse_ip(value: &str) -> Option<IpAddr> {
    let trimmed = value.trim_matches(|c| c == '[' || c == ']');
    let addr_part = trimmed.split('%').next().unwrap_or(trimmed);
    let addr: IpAddr = addr_part.parse().ok()?;
    Some(normalize_ip(addr).unwrap_or(addr))
}

fn normalize_ip(addr: IpAddr) -> Option<IpAddr> {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => Some(IpAddr::V4(v4)),
            None => Some(IpAddr::V6(v6)),
        },
        v4 => Some(v4),
    }
}

/// Port of `gateway._reaches_listener`.
fn reaches_listener(address: IpAddr, port: u16, local: Option<IpAddr>) -> bool {
    for (listen_ip, listen_port) in listener_addresses() {
        if port != listen_port {
            continue;
        }
        if address == listen_ip {
            return true;
        }
        if address.is_unspecified() || local == Some(address) {
            return true;
        }
        if (listen_ip.is_unspecified() || listen_ip.is_loopback()) && address.is_loopback() {
            return true;
        }
    }
    false
}

/// A minimal `urllib.parse.urlsplit(url)`-equivalent extracting just
/// `(hostname, port)`, with the same scheme-default port (`443` for
/// `https`, else `80`). Returns `None` for anything that does not parse as
/// `scheme://[user@]host[:port][/...]`, matching Python's `except
/// ValueError: pass` around `urlsplit`.
fn parse_authority(url: &str) -> Option<(String, i64)> {
    let (scheme, rest) = url.split_once("://")?;
    let default_port: i64 = if scheme.eq_ignore_ascii_case("https") {
        443
    } else {
        80
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(rest) = hostport.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) if !p.is_empty() => p.parse().ok()?,
            Some(_) => return None,
            None => default_port,
        };
        return Some((host.to_string(), port));
    }
    match hostport.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            Some((host.to_string(), port.parse().ok()?))
        }
        Some(_) => None,
        None => Some((hostport.to_string(), default_port)),
    }
}

/// Port of `gateway._self_referential_target`: cheap literal check before
/// any use is consumed; `_exchange`'s post-connect check re-checks the real
/// peer.
fn self_referential_target(ctx: &Context, connection: &Connection) -> bool {
    let target = connection.http_target.as_ref().expect("http connection");
    let host = target
        .host
        .trim_matches(|c| c == '[' || c == ']')
        .to_lowercase();
    let host = host.trim_end_matches('.');
    if let Some(Value::String(public_url)) = ctx.config.extra.get("public_url")
        && !public_url.is_empty()
        && let Some((url_host, public_port)) = parse_authority(public_url)
        && url_host.trim_end_matches('.') == host
        && public_port == target.port
    {
        return true;
    }
    let address = match parse_ip(host) {
        Some(a) => Some(a),
        None if host == "localhost" || host.ends_with(".localhost") => {
            Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        }
        None => None,
    };
    let Some(address) = address else {
        return false;
    };
    reaches_listener(address, target.port as u16, None)
}

/// Port of `gateway._peer_is_local_listener`.
fn peer_is_local_listener(stream: &TcpStream) -> bool {
    let Ok(peer) = stream.peer_addr() else {
        return false;
    };
    let Ok(local) = stream.local_addr() else {
        return false;
    };
    let Some(address) = parse_ip(&peer.ip().to_string()) else {
        return false;
    };
    let local_ip = parse_ip(&local.ip().to_string());
    reaches_listener(address, peer.port(), local_ip)
}

// ------------------------------------------------------------------- ledger

/// Port of `gateway.RequestLedger`.
pub struct RequestLedger<'a> {
    ctx: &'a Context,
}

impl<'a> RequestLedger<'a> {
    pub fn new(ctx: &'a Context) -> Self {
        RequestLedger { ctx }
    }

    fn load(&self) -> Map<String, Value> {
        match self.ctx.state.read_json(LEDGER_DOC, json!({})) {
            Ok(Value::Object(m)) => m,
            _ => Map::new(),
        }
    }

    fn save(&self, mut doc: Map<String, Value>) {
        let now = (self.ctx.clock)();
        let callers: Vec<String> = doc.keys().cloned().collect();
        for caller in callers {
            let Some(Value::Object(entries)) = doc.get_mut(&caller) else {
                continue;
            };
            let ids: Vec<String> = entries.keys().cloned().collect();
            for id in ids {
                let updated_at = entries
                    .get(&id)
                    .and_then(|e| e.get("updated_at"))
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0);
                if now - updated_at > LEDGER_TTL_SECONDS {
                    entries.remove(&id);
                }
            }
            if entries.is_empty() {
                doc.remove(&caller);
            }
        }
        let total: usize = doc
            .values()
            .filter_map(|v| v.as_object())
            .map(|m| m.len())
            .sum();
        if total > LEDGER_MAX_ENTRIES {
            let mut completed: Vec<(f64, String, String)> = Vec::new();
            for (caller, entries) in doc.iter() {
                let Some(entries) = entries.as_object() else {
                    continue;
                };
                for (rid, entry) in entries {
                    if entry.get("state").and_then(Value::as_str) == Some("completed") {
                        let updated_at = entry
                            .get("updated_at")
                            .and_then(Value::as_f64)
                            .unwrap_or(0.0);
                        completed.push((updated_at, caller.clone(), rid.clone()));
                    }
                }
            }
            completed.sort_by(|a, b| a.partial_cmp(b).unwrap());
            for (_, caller, rid) in completed.into_iter().take(total - LEDGER_MAX_ENTRIES) {
                if let Some(Value::Object(entries)) = doc.get_mut(&caller) {
                    entries.remove(&rid);
                    if entries.is_empty() {
                        doc.remove(&caller);
                    }
                }
            }
        }
        let _ = self.ctx.state.write_json(LEDGER_DOC, &Value::Object(doc));
    }

    /// `RequestLedger.digest`.
    pub fn digest(connection_id: &str, method: &str, target: &str, body: &[u8]) -> String {
        let mut hasher = Sha256::new();
        for part in [
            connection_id.as_bytes(),
            method.as_bytes(),
            target.as_bytes(),
            body,
        ] {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        hex::encode(hasher.finalize())
    }

    /// `RequestLedger.claim`.
    pub fn claim(
        &self,
        caller: &str,
        request_id: &str,
        digest: &str,
        connection_id: &str,
    ) -> Result<(&'static str, Option<Value>), Error> {
        let _lock = self.ctx.state.lock()?;
        let mut doc = self.load();
        let now = (self.ctx.clock)();
        let entry = doc
            .get(caller)
            .and_then(Value::as_object)
            .and_then(|m| m.get(request_id))
            .cloned();
        if let Some(entry) = &entry {
            let updated_at = entry
                .get("updated_at")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            if now - updated_at <= LEDGER_TTL_SECONDS {
                if entry.get("digest").and_then(Value::as_str) != Some(digest) {
                    return Ok(("reused", None));
                }
                return match entry.get("state").and_then(Value::as_str) {
                    Some("completed") => Ok(("replay", Some(entry.clone()))),
                    Some("uncertain") => Ok(("uncertain", None)),
                    _ => Ok(("in_flight", None)),
                };
            }
        }
        let caller_entries = doc
            .entry(caller.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(m) = caller_entries {
            m.insert(
                request_id.to_string(),
                json!({
                    "digest": digest, "state": "in_flight", "connection": connection_id,
                    "created_at": now, "updated_at": now, "response": Value::Null,
                }),
            );
        }
        self.save(doc);
        Ok(("new", None))
    }

    fn update(&self, caller: &str, request_id: &str, apply: impl FnOnce(&mut Map<String, Value>)) {
        let Ok(_lock) = self.ctx.state.lock() else {
            return;
        };
        let mut doc = self.load();
        let now = (self.ctx.clock)();
        let Some(Value::Object(entries)) = doc.get_mut(caller) else {
            return;
        };
        let Some(Value::Object(entry)) = entries.get_mut(request_id) else {
            return;
        };
        apply(entry);
        entry.insert("updated_at".into(), json!(now));
        self.save(doc);
    }

    /// `RequestLedger.release`.
    pub fn release(&self, caller: &str, request_id: &str) {
        let Ok(_lock) = self.ctx.state.lock() else {
            return;
        };
        let mut doc = self.load();
        if let Some(Value::Object(entries)) = doc.get_mut(caller)
            && entries.remove(request_id).is_some()
        {
            if entries.is_empty() {
                doc.remove(caller);
            }
            self.save(doc);
        }
    }

    pub fn mark_uncertain(&self, caller: &str, request_id: &str) {
        self.update(caller, request_id, |entry| {
            entry.insert("state".into(), json!("uncertain"));
        });
    }

    pub fn complete(&self, caller: &str, request_id: &str, result: &RelayResult) {
        use base64::Engine as _;
        let mut stored = Map::new();
        stored.insert("status".into(), json!(result.status));
        stored.insert(
            "headers".into(),
            Value::Array(result.headers.iter().map(|(k, v)| json!([k, v])).collect()),
        );
        stored.insert(
            "reason".into(),
            result
                .reason
                .as_ref()
                .map(|r| Value::String(r.clone()))
                .unwrap_or(Value::Null),
        );
        if result.body.len() <= LEDGER_MAX_STORED_BODY {
            stored.insert(
                "body_b64".into(),
                json!(base64::engine::general_purpose::STANDARD.encode(&result.body)),
            );
            stored.insert("body_stored".into(), json!(true));
        } else {
            stored.insert("body_b64".into(), Value::Null);
            stored.insert("body_stored".into(), json!(false));
        }
        self.update(caller, request_id, |entry| {
            entry.insert("state".into(), json!("completed"));
            entry.insert("response".into(), Value::Object(stored));
        });
    }

    /// `RequestLedger.replay`.
    pub fn replay(entry: &Value) -> RelayResult {
        use base64::Engine as _;
        let response = entry.get("response").cloned().unwrap_or(json!({}));
        let status = response
            .get("status")
            .and_then(Value::as_i64)
            .unwrap_or(502) as u16;
        let mut headers: Headers = response
            .get("headers")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| {
                        let pair = item.as_array()?;
                        Some((
                            pair.first()?.as_str()?.to_string(),
                            pair.get(1)?.as_str()?.to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        if response.get("body_stored").and_then(Value::as_bool) != Some(true) {
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-type"));
            let payload = pyjson::dumps(
                &json!({"error": "ReplayBodyUnavailable", "reason": "replay_body_unavailable"}),
                DumpOptions::plain(),
            )
            .unwrap_or_default()
            .into_bytes();
            headers.push(("Content-Type".to_string(), "application/json".to_string()));
            headers.push(("X-ZeroPW-Replay".to_string(), "true".to_string()));
            return RelayResult {
                status,
                headers,
                body: payload,
                reason: Some("replay_body_unavailable".to_string()),
            };
        }
        let body = response
            .get("body_b64")
            .and_then(Value::as_str)
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            .unwrap_or_default();
        headers.push(("X-ZeroPW-Replay".to_string(), "true".to_string()));
        RelayResult {
            status,
            headers,
            body,
            reason: response
                .get("reason")
                .and_then(Value::as_str)
                .map(str::to_string),
        }
    }
}

// --------------------------------------------------------------- upstream

/// Port of `gateway._UpstreamFailure`.
struct UpstreamFailure {
    reason: &'static str,
    result: &'static str,
    known_outcome: bool,
    upstream_status: Option<u16>,
}

impl UpstreamFailure {
    fn denied(reason: &'static str) -> Self {
        UpstreamFailure {
            reason,
            result: "denied",
            known_outcome: false,
            upstream_status: None,
        }
    }
    fn error(reason: &'static str) -> Self {
        UpstreamFailure {
            reason,
            result: "error",
            known_outcome: false,
            upstream_status: None,
        }
    }
    fn blocked(reason: &'static str, status: u16) -> Self {
        UpstreamFailure {
            reason,
            result: "blocked",
            known_outcome: true,
            upstream_status: Some(status),
        }
    }
}

struct UpstreamResponse {
    status: u16,
    headers: Headers,
    body: Vec<u8>,
}

/// Injectable seam replacing the monkeypatched `gateway._getaddrinfo`
/// module global; see the module doc.
pub type Resolver = Arc<dyn Fn(&str, u16) -> std::io::Result<Vec<IpAddr>> + Send + Sync>;

/// The real OS resolver, matching `socket.getaddrinfo(host, port,
/// type=socket.SOCK_STREAM)`.
pub fn default_resolver() -> Resolver {
    Arc::new(|host, port| {
        let addrs = (host, port).to_socket_addrs()?;
        Ok(addrs.map(|a| a.ip()).collect())
    })
}

/// Port of `gateway.resolve_pinned_address`.
fn resolve_pinned_address(
    connection: &Connection,
    resolver: &Resolver,
) -> Result<String, UpstreamFailure> {
    let target = connection.http_target.as_ref().expect("http connection");
    let host = target.host.trim_matches(|c| c == '[' || c == ']');
    if let Some(literal) = parse_ip(host) {
        return match address_block_reason(literal, true) {
            Some(reason) => Err(UpstreamFailure::denied(reason)),
            None => Ok(host.to_string()),
        };
    }
    let answers = resolver(&target.host, target.port as u16)
        .map_err(|_| UpstreamFailure::error("upstream_unreachable"))?;
    let mut pinned: Option<String> = None;
    for address in answers {
        let address = normalize_ip(address).unwrap_or(address);
        if let Some(reason) = address_block_reason(address, target.allow_private_network) {
            return Err(UpstreamFailure::denied(reason));
        }
        if pinned.is_none() {
            pinned = Some(address.to_string());
        }
    }
    pinned.ok_or_else(|| UpstreamFailure::error("upstream_unreachable"))
}

fn host_header(connection: &Connection) -> String {
    let target = connection.http_target.as_ref().expect("http connection");
    let default_port = if target.scheme == "https" { 443 } else { 80 };
    let host = if target.host.contains(':') {
        format!("[{}]", target.host)
    } else {
        target.host.clone()
    };
    if target.port == default_port {
        host
    } else {
        format!("{host}:{}", target.port)
    }
}

// ---------------------------------------------------------- HTTP transport

static PROVIDER_INIT: std::sync::Once = std::sync::Once::new();
fn ensure_crypto_provider() {
    PROVIDER_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

enum UpstreamStream {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl UpstreamStream {
    fn raw(&self) -> &TcpStream {
        match self {
            UpstreamStream::Plain(s) => s,
            UpstreamStream::Tls(s) => &s.sock,
        }
    }
    fn set_timeouts(&self, dur: Option<Duration>) {
        let _ = self.raw().set_read_timeout(dur);
        let _ = self.raw().set_write_timeout(dur);
    }
}

impl Read for UpstreamStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            UpstreamStream::Plain(s) => s.read(buf),
            UpstreamStream::Tls(s) => s.read(buf),
        }
    }
}
impl Write for UpstreamStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            UpstreamStream::Plain(s) => s.write(buf),
            UpstreamStream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            UpstreamStream::Plain(s) => s.flush(),
            UpstreamStream::Tls(s) => s.flush(),
        }
    }
}

fn classify_connect_error(e: &std::io::Error) -> &'static str {
    if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock {
        "upstream_timeout"
    } else {
        "upstream_unreachable"
    }
}

fn build_tls_config(ca_file: Option<&str>) -> Result<Arc<rustls::ClientConfig>, UpstreamFailure> {
    ensure_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    if let Some(path) = ca_file {
        let file =
            std::fs::File::open(path).map_err(|_| UpstreamFailure::error("ca_file_unavailable"))?;
        let mut reader = std::io::BufReader::new(file);
        let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| UpstreamFailure::error("ca_file_unavailable"))?;
        if certs.is_empty() {
            return Err(UpstreamFailure::error("ca_file_unavailable"));
        }
        for cert in certs {
            roots
                .add(cert)
                .map_err(|_| UpstreamFailure::error("ca_file_unavailable"))?;
        }
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn open_connection(
    connection: &Connection,
    timeout: Duration,
    pinned_address: &str,
) -> Result<UpstreamStream, UpstreamFailure> {
    let target = connection.http_target.as_ref().expect("http connection");
    let ip: IpAddr = pinned_address
        .parse()
        .map_err(|_| UpstreamFailure::error("upstream_unreachable"))?;
    let sockaddr = SocketAddr::new(ip, target.port as u16);
    let tcp = TcpStream::connect_timeout(&sockaddr, timeout)
        .map_err(|e| UpstreamFailure::error(classify_connect_error(&e)))?;
    let _ = tcp.set_nodelay(true);
    if target.scheme == "https" {
        let config = build_tls_config(target.ca_file.as_deref())?;
        let server_name = rustls_pki_types::ServerName::try_from(target.host.clone())
            .map_err(|_| UpstreamFailure::error("upstream_tls_failed"))?;
        let conn = rustls::ClientConnection::new(config, server_name)
            .map_err(|_| UpstreamFailure::error("upstream_tls_failed"))?;
        let mut stream = rustls::StreamOwned::new(conn, tcp);
        stream.sock.set_read_timeout(Some(timeout)).ok();
        stream.sock.set_write_timeout(Some(timeout)).ok();
        // Force the handshake now (Python's `wrap_socket` is eager), so the
        // self-referential peer check that follows sees the same state
        // Python does: TLS established, HTTP request not yet written.
        while stream.conn.is_handshaking() {
            if stream.conn.complete_io(&mut stream.sock).is_err() {
                return Err(UpstreamFailure::error("upstream_tls_failed"));
            }
        }
        return Ok(UpstreamStream::Tls(Box::new(stream)));
    }
    tcp.set_read_timeout(Some(timeout)).ok();
    tcp.set_write_timeout(Some(timeout)).ok();
    Ok(UpstreamStream::Plain(tcp))
}

const METHODS_EXPECTING_BODY: &[&str] = &["PATCH", "POST", "PUT"];

fn content_length_for(method: &str, body: &[u8]) -> Option<usize> {
    if !body.is_empty() {
        Some(body.len())
    } else if METHODS_EXPECTING_BODY.contains(&method) {
        Some(0)
    } else {
        None
    }
}

fn write_request(
    stream: &mut dyn Write,
    method: &str,
    target: &str,
    headers: &Headers,
    body: &[u8],
) -> std::io::Result<()> {
    let mut out = Vec::new();
    out.extend_from_slice(format!("{method} {target} HTTP/1.1\r\n").as_bytes());
    if let Some(len) = content_length_for(method, body) {
        out.extend_from_slice(format!("Content-Length: {len}\r\n").as_bytes());
    }
    for (name, value) in headers {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    if !body.is_empty() {
        out.extend_from_slice(body);
    }
    stream.write_all(&out)?;
    stream.flush()
}

struct StatusAndHeaders {
    status: u16,
    headers: Headers,
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

fn latin1_decode(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

fn read_status_and_headers(reader: &mut impl BufRead) -> Result<StatusAndHeaders, UpstreamFailure> {
    let status_line = read_line(reader)
        .map_err(|_| UpstreamFailure::error("upstream_connection_lost"))?
        .ok_or(UpstreamFailure::error("upstream_protocol_error"))?;
    let status_line = latin1_decode(&status_line);
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    let status_text = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/") {
        return Err(UpstreamFailure::error("upstream_protocol_error"));
    }
    let status: u16 = status_text
        .parse()
        .map_err(|_| UpstreamFailure::error("upstream_protocol_error"))?;
    let mut headers = Headers::new();
    loop {
        let line = read_line(reader)
            .map_err(|_| UpstreamFailure::error("upstream_connection_lost"))?
            .ok_or(UpstreamFailure::error("upstream_protocol_error"))?;
        if line.is_empty() {
            break;
        }
        let line = latin1_decode(&line);
        let Some((name, value)) = line.split_once(':') else {
            return Err(UpstreamFailure::error("upstream_protocol_error"));
        };
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    Ok(StatusAndHeaders { status, headers })
}

enum BodyMode {
    Empty,
    ContentLength(usize),
    Chunked,
    UntilClose,
}

fn body_mode(method: &str, status: u16, headers: &Headers) -> BodyMode {
    if method == "HEAD" || status == 204 || status == 304 || (100..200).contains(&status) {
        return BodyMode::Empty;
    }
    if let Some(te) = headers_get(headers, "transfer-encoding")
        && te.trim().eq_ignore_ascii_case("chunked")
    {
        return BodyMode::Chunked;
    }
    if let Some(cl) = headers_get(headers, "content-length")
        && let Ok(n) = cl.trim().parse::<usize>()
    {
        return BodyMode::ContentLength(n);
    }
    BodyMode::UntilClose
}

/// Reads up to `limit` bytes of the body, in `READ_CHUNK`-sized increments
/// (mirroring `resp.read(min(READ_CHUNK, limit + 1 - total))`), returning
/// `response_too_large` as soon as the running total exceeds `limit`.
fn read_body(
    reader: &mut impl BufRead,
    mode: BodyMode,
    limit: usize,
) -> Result<Vec<u8>, UpstreamFailure> {
    let mut out = Vec::new();
    match mode {
        BodyMode::Empty => Ok(out),
        BodyMode::ContentLength(mut remaining) => {
            let mut total = 0usize;
            while remaining > 0 {
                let want = READ_CHUNK.min(limit + 1 - total).min(remaining);
                let mut buf = vec![0u8; want];
                let n = reader
                    .read(&mut buf)
                    .map_err(|_| UpstreamFailure::error("upstream_connection_lost"))?;
                if n == 0 {
                    return Err(UpstreamFailure::error("upstream_protocol_error"));
                }
                out.extend_from_slice(&buf[..n]);
                total += n;
                remaining -= n;
                if total > limit {
                    return Err(UpstreamFailure::blocked("response_too_large", 0));
                }
            }
            Ok(out)
        }
        BodyMode::Chunked => {
            let mut total = 0usize;
            loop {
                let line = read_line(reader)
                    .map_err(|_| UpstreamFailure::error("upstream_connection_lost"))?
                    .ok_or(UpstreamFailure::error("upstream_protocol_error"))?;
                let line = latin1_decode(&line);
                let size_text = line.split(';').next().unwrap_or("").trim();
                let mut size = usize::from_str_radix(size_text, 16)
                    .map_err(|_| UpstreamFailure::error("upstream_connection_lost"))?;
                if size == 0 {
                    // Trailers, until the blank line.
                    loop {
                        let trailer = read_line(reader)
                            .map_err(|_| UpstreamFailure::error("upstream_connection_lost"))?
                            .ok_or(UpstreamFailure::error("upstream_protocol_error"))?;
                        if trailer.is_empty() {
                            break;
                        }
                    }
                    break;
                }
                while size > 0 {
                    let want = READ_CHUNK.min(limit + 1 - total).min(size);
                    let mut buf = vec![0u8; want];
                    let n = reader
                        .read(&mut buf)
                        .map_err(|_| UpstreamFailure::error("upstream_connection_lost"))?;
                    if n == 0 {
                        return Err(UpstreamFailure::error("upstream_protocol_error"));
                    }
                    out.extend_from_slice(&buf[..n]);
                    total += n;
                    size -= n;
                    if total > limit {
                        return Err(UpstreamFailure::blocked("response_too_large", 0));
                    }
                }
                let trailer = read_line(reader)
                    .map_err(|_| UpstreamFailure::error("upstream_connection_lost"))?
                    .ok_or(UpstreamFailure::error("upstream_protocol_error"))?;
                if !trailer.is_empty() {
                    return Err(UpstreamFailure::error("upstream_protocol_error"));
                }
            }
            Ok(out)
        }
        BodyMode::UntilClose => {
            let mut total = 0usize;
            loop {
                let want = READ_CHUNK.min(limit + 1 - total);
                let mut buf = vec![0u8; want];
                let n = reader
                    .read(&mut buf)
                    .map_err(|_| UpstreamFailure::error("upstream_connection_lost"))?;
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
                total += n;
                if total > limit {
                    return Err(UpstreamFailure::blocked("response_too_large", 0));
                }
            }
            Ok(out)
        }
    }
}

// ------------------------------------------------------------------ relay

struct Relay<'a> {
    ctx: &'a Context,
    caller: String,
    connection_id: String,
    grant_id: Option<String>,
    handle_policy_version: Option<i64>,
    raw_method: String,
    raw_path: String,
    raw_headers: Headers,
    raw_body: Vec<u8>,
    raw_request_id: Option<String>,
    resolver: Resolver,

    method: String,
    path: String,
    target: String,
    headers: Headers,
    body: Vec<u8>,
    request_id: Option<String>,
    connection: Option<Connection>,
    grant: Option<Grant>,
    origin: Option<String>,
    ledger: RequestLedger<'a>,
    claimed: bool,
    transmitted: bool,
}

impl<'a> Relay<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        ctx: &'a Context,
        caller: &str,
        connection_id: &str,
        grant_id: Option<&str>,
        handle_policy_version: Option<i64>,
        method: &str,
        path: &str,
        headers: &Headers,
        body: &[u8],
        request_id: Option<&str>,
        resolver: Resolver,
    ) -> Self {
        Relay {
            ctx,
            caller: caller.to_string(),
            connection_id: connection_id.to_string(),
            grant_id: grant_id.map(str::to_string),
            handle_policy_version,
            raw_method: method.to_string(),
            raw_path: path.to_string(),
            raw_headers: headers.clone(),
            raw_body: body.to_vec(),
            raw_request_id: request_id.map(str::to_string),
            resolver,
            method: "?".to_string(),
            path: String::new(),
            target: String::new(),
            headers: Headers::new(),
            body: Vec::new(),
            request_id: None,
            connection: None,
            grant: None,
            origin: None,
            ledger: RequestLedger::new(ctx),
            claimed: false,
            transmitted: false,
        }
    }

    fn audit(
        &self,
        result: &str,
        reason: Option<&str>,
        status: Option<u16>,
        extra: Vec<(&str, Value)>,
    ) -> Result<(), Error> {
        let mut fields: Vec<(&str, Value)> = vec![
            (
                "path",
                if self.path.is_empty() {
                    Value::Null
                } else {
                    Value::String(self.path.clone())
                },
            ),
            ("status", status.map(|s| json!(s)).unwrap_or(Value::Null)),
        ];
        if let Some(grant) = &self.grant {
            fields.push(("grant", json!(grant.id)));
        }
        fields.extend(extra);
        self.ctx.audit.record(
            "http_relay",
            RecordArgs {
                caller: Some(&self.caller),
                connection: Some(&self.connection_id),
                target: self.origin.as_deref(),
                action: Some(&self.method),
                result: Some(result),
                reason,
                policy_version: self.connection.as_ref().map(|c| c.policy_version),
                request_id: self.request_id.as_deref(),
                extra: fields,
                ..Default::default()
            },
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn refuse(
        &mut self,
        status: u16,
        reason: &str,
        result: &str,
        error: Option<&str>,
        extra_body: Option<Map<String, Value>>,
        audit_extra: Vec<(&str, Value)>,
        do_audit: bool,
    ) -> RelayResult {
        if self.claimed
            && let Some(request_id) = self.request_id.clone()
        {
            if self.transmitted {
                self.ledger.mark_uncertain(&self.caller, &request_id);
            } else {
                self.ledger.release(&self.caller, &request_id);
            }
            self.claimed = false;
        }
        if do_audit
            && let Err(e) = self.audit(result, Some(reason), None, audit_extra)
            && e.is(ErrorClass::AuditUnavailable)
        {
            return error_result(503, "audit_unavailable", Some("AuditUnavailable"), None);
        }
        error_result(status, reason, error, extra_body)
    }

    fn approval_subject(&self, content_type: Option<&str>) -> String {
        let connection = self.connection.as_ref().expect("checked");
        let value = json!({
            "origin": self.origin, "target": self.target,
            "policy_version": connection.policy_version, "content_type": content_type,
        });
        pyjson::dumps(&value, DumpOptions::compact_sorted()).expect("representable")
    }

    fn annotate_approval(&self, digest: &str, content_type: Option<&str>) {
        let connection = self.connection.as_ref().expect("checked");
        let (query, has_query) = match self.target.split_once('?') {
            Some((_, q)) => (Some(q.to_string()), true),
            None => (None, false),
        };
        let text = if self.body.is_empty() {
            None
        } else {
            std::str::from_utf8(&self.body).ok()
        };
        let mut details: Map<String, Value> = Map::new();
        details.insert(
            "origin".into(),
            self.origin
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        details.insert(
            "query".into(),
            if has_query {
                Value::String(query.unwrap_or_default())
            } else {
                Value::Null
            },
        );
        details.insert(
            "content_type".into(),
            content_type
                .map(|s| Value::String(s.to_string()))
                .unwrap_or(Value::Null),
        );
        details.insert("body_bytes".into(), json!(self.body.len()));
        details.insert(
            "body_sha256".into(),
            json!(hex::encode(Sha256::digest(&self.body))),
        );
        details.insert(
            "body_preview".into(),
            match text {
                Some(t) => Value::String(t.chars().take(APPROVAL_PREVIEW_CHARS).collect()),
                None => Value::Null,
            },
        );
        details.insert(
            "body_preview_truncated".into(),
            json!(text.is_some_and(|t| t.chars().count() > APPROVAL_PREVIEW_CHARS)),
        );
        details.insert("policy_version".into(), json!(connection.policy_version));

        let Ok(control) = self.ctx.state.read_json(policy::CONTROL, Value::Null) else {
            return;
        };
        let Value::Object(mut control) = control else {
            return;
        };
        let Some(entry) = control
            .get_mut("approvals")
            .and_then(Value::as_object_mut)
            .and_then(|a| a.get_mut(digest))
            .and_then(|e| e.as_object_mut())
        else {
            return;
        };
        let mut changed = false;
        for (key, value) in details {
            if !entry.contains_key(&key) {
                entry.insert(key, value);
                changed = true;
            }
        }
        if changed {
            let _ = self
                .ctx
                .state
                .write_json(policy::CONTROL, &Value::Object(control));
        }
    }

    fn refuse_failure(&mut self, failure: UpstreamFailure) -> RelayResult {
        if failure.reason == "self_referential_target" {
            return self.refuse(
                501,
                failure.reason,
                failure.result,
                Some("Unsupported"),
                None,
                Vec::new(),
                true,
            );
        }
        if failure.reason == "target_address_not_allowed"
            || failure.reason == "metadata_address_not_allowed"
        {
            return self.refuse(
                403,
                failure.reason,
                failure.result,
                Some("PolicyDenied"),
                None,
                Vec::new(),
                true,
            );
        }
        self.refuse(
            502,
            failure.reason,
            failure.result,
            None,
            None,
            Vec::new(),
            true,
        )
    }

    fn finish(
        &mut self,
        result: &mut RelayResult,
        outcome: &str,
        reason: Option<&str>,
        upstream_status: Option<u16>,
    ) {
        if self.claimed
            && let Some(request_id) = self.request_id.clone()
        {
            self.ledger.complete(&self.caller, &request_id, result);
            self.claimed = false;
        }
        let status = upstream_status.or(Some(result.status));
        if let Err(e) = self.audit(outcome, reason, status, Vec::new())
            && e.is(ErrorClass::AuditUnavailable)
        {
            result.status = 503;
            result.headers = vec![("Content-Type".to_string(), "application/json".to_string())];
            result.body = pyjson::dumps(
                &json!({"error": "AuditUnavailable", "reason": "audit_unavailable"}),
                DumpOptions::plain(),
            )
            .unwrap_or_default()
            .into_bytes();
            result.reason = Some("audit_unavailable".to_string());
        }
    }

    fn exchange(
        &mut self,
        upstream_headers: &Headers,
        pinned_address: &str,
    ) -> Result<UpstreamResponse, UpstreamFailure> {
        let connection = self.connection.as_ref().expect("checked").clone();
        let timeout = Duration::from_secs_f64(self.ctx.config.upstream_timeout.max(0.0));
        let limit = self.ctx.config.max_response_bytes.max(0) as usize;
        let mut stream = open_connection(&connection, timeout, pinned_address)?;
        stream.set_timeouts(Some(timeout));
        if peer_is_local_listener(stream.raw()) {
            return Err(UpstreamFailure::denied("self_referential_target"));
        }
        self.transmitted = true;
        write_request(
            &mut stream,
            &self.method,
            &self.target,
            upstream_headers,
            &self.body,
        )
        .map_err(|e| UpstreamFailure::error(classify_connect_error(&e)))?;
        let mut reader = BufReader::new(stream);
        let head = read_status_and_headers(&mut reader)?;
        if REDIRECT_STATUSES.contains(&head.status) {
            return Err(UpstreamFailure::blocked(
                "redirect_not_followed",
                head.status,
            ));
        }
        let encoding = headers_get(&head.headers, "content-encoding")
            .unwrap_or("identity")
            .trim()
            .to_lowercase();
        if !encoding.is_empty() && encoding != "identity" {
            return Err(UpstreamFailure::blocked(
                "response_encoding_unsupported",
                head.status,
            ));
        }
        let mode = body_mode(&self.method, head.status, &head.headers);
        let body = match read_body(&mut reader, mode, limit) {
            Ok(b) => b,
            Err(mut failure) => {
                if failure.reason == "response_too_large" {
                    failure.upstream_status = Some(head.status);
                }
                return Err(failure);
            }
        };
        Ok(UpstreamResponse {
            status: head.status,
            headers: head.headers,
            body,
        })
    }

    fn filter_response(response: UpstreamResponse, patterns: &[Vec<u8>]) -> RelayResult {
        let header_blob: Vec<u8> = response
            .headers
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join("\r\n")
            .into_bytes();
        if contains_credential(&header_blob, patterns)
            || contains_credential(&response.body, patterns)
        {
            return error_result(502, "credential_reflection_blocked", None, None);
        }
        let mut headers = Headers::new();
        for (name, value) in &response.headers {
            let lowered = name.to_lowercase();
            if !RESPONSE_HEADER_ALLOWLIST.contains(&lowered.as_str()) {
                continue;
            }
            if !HEADER_VALUE_RE.is_match(value) {
                continue;
            }
            headers.push((name.clone(), value.clone()));
        }
        RelayResult {
            status: response.status,
            headers,
            body: response.body,
            reason: None,
        }
    }

    fn run(mut self) -> RelayResult {
        match self.try_run() {
            Ok(result) => result,
            Err(e) => unexpected_error_result(e),
        }
    }

    fn try_run(&mut self) -> Result<RelayResult, Error> {
        let mut invalid: Option<Invalid> = None;
        let mut forwarded = Headers::new();
        match normalize_method(&self.raw_method) {
            Ok(m) => self.method = m,
            Err(e) => invalid = Some(e),
        }
        if invalid.is_none() {
            self.headers = normalize_headers(&self.raw_headers);
            match normalize_request_id(self.raw_request_id.as_deref(), &self.headers) {
                Ok(id) => self.request_id = id,
                Err(e) => invalid = Some(e),
            }
        }
        if invalid.is_none() {
            match normalize_path_inner(&self.raw_path) {
                Ok((path, target)) => {
                    self.path = path;
                    self.target = target;
                }
                Err(e) => invalid = Some(e),
            }
        }
        if invalid.is_none() {
            self.body = self.raw_body.clone();
            match forwardable_headers(&self.headers) {
                Ok(f) => forwarded = f,
                Err(e) => invalid = Some(e),
            }
        }
        if let Some(Invalid(reason)) = invalid {
            if self.path.is_empty() {
                self.path = self.raw_path.clone();
            }
            return Ok(self.refuse(
                400,
                reason,
                "denied",
                Some("InvalidInput"),
                None,
                Vec::new(),
                true,
            ));
        }

        let action = Action::http(self.method.clone(), self.path.clone());
        let decision = self.ctx.policy.evaluate(
            &self.caller,
            &self.connection_id,
            &action,
            self.grant_id.as_deref(),
        )?;
        self.connection = decision.connection.clone();
        if self.connection.is_none() {
            self.connection = self.ctx.policy.get_connection(&self.connection_id).ok();
        }
        if let Some(connection) = &self.connection
            && let Some(target) = &connection.http_target
        {
            self.origin = Some(target.origin());
        }
        if !decision.allowed {
            return Ok(self.refuse(403, decision.reason, "denied", None, None, Vec::new(), true));
        }
        let connection = self
            .connection
            .clone()
            .expect("allowed decision carries a connection");
        self.grant = decision.grant.clone();
        if connection.kind != "http"
            || connection.http_target.is_none()
            || connection.http_scope.is_none()
        {
            return Ok(self.refuse(
                403,
                "action_kind_mismatch",
                "denied",
                None,
                None,
                Vec::new(),
                true,
            ));
        }
        if let Some(handle_pv) = self.handle_policy_version
            && handle_pv != connection.policy_version
        {
            return Ok(self.refuse(403, "grant_stale", "denied", None, None, Vec::new(), true));
        }
        if self_referential_target(self.ctx, &connection) {
            return Ok(self.refuse(
                501,
                "self_referential_target",
                "denied",
                Some("Unsupported"),
                None,
                Vec::new(),
                true,
            ));
        }

        if let Some(request_id) = self.request_id.clone() {
            let digest =
                RequestLedger::digest(&connection.id, &self.method, &self.target, &self.body);
            let (state, entry) =
                self.ledger
                    .claim(&self.caller, &request_id, &digest, &connection.id)?;
            match state {
                "replay" => {
                    let replayed =
                        RequestLedger::replay(entry.as_ref().expect("replay carries entry"));
                    let result_kind = if replayed.reason.is_some() {
                        "blocked"
                    } else {
                        "ok"
                    };
                    if let Err(e) = self.audit(
                        result_kind,
                        Some("replayed"),
                        Some(replayed.status),
                        Vec::new(),
                    ) && e.is(ErrorClass::AuditUnavailable)
                    {
                        return Ok(error_result(
                            503,
                            "audit_unavailable",
                            Some("AuditUnavailable"),
                            None,
                        ));
                    }
                    return Ok(replayed);
                }
                "in_flight" => {
                    return Ok(self.refuse(
                        409,
                        "request_in_flight",
                        "denied",
                        Some("Conflict"),
                        None,
                        Vec::new(),
                        true,
                    ));
                }
                "uncertain" => {
                    return Ok(self.refuse(
                        409,
                        "outcome_uncertain",
                        "denied",
                        Some("Conflict"),
                        None,
                        Vec::new(),
                        true,
                    ));
                }
                "reused" => {
                    return Ok(self.refuse(
                        409,
                        "request_id_reused",
                        "denied",
                        Some("Conflict"),
                        None,
                        Vec::new(),
                        true,
                    ));
                }
                _ => {
                    self.claimed = true;
                }
            }
        }

        let pinned_address = match resolve_pinned_address(&connection, &self.resolver) {
            Ok(addr) => addr,
            Err(failure) => return Ok(self.refuse_failure(failure)),
        };

        let scope = connection.http_scope.as_ref().expect("http connection");
        if scope.confirm_methods.iter().any(|m| m == &self.method) {
            let content_type = headers_get(&forwarded, "content-type").map(str::to_string);
            let digest = approval_digest(
                &self.caller,
                &connection.id,
                &self.method,
                &self.approval_subject(content_type.as_deref()),
                &self.body,
            );
            let consumed = self.ctx.policy.consume_approval(
                &digest,
                &self.caller,
                &connection.id,
                None,
                None,
            )?;
            if !consumed {
                {
                    let _lock = self.ctx.state.lock()?;
                    self.ctx.policy.request_approval(
                        &digest,
                        &self.caller,
                        &connection.id,
                        &self.method,
                        &self.path,
                    )?;
                    self.annotate_approval(&digest, content_type.as_deref());
                }
                let mut extra_body = Map::new();
                extra_body.insert("approval_digest".into(), json!(digest));
                return Ok(self.refuse(
                    428,
                    "approval_required",
                    "denied",
                    None,
                    Some(extra_body),
                    vec![("digest", json!(digest))],
                    true,
                ));
            }
        }

        if let Err(e) = self.audit("attempt", None, None, Vec::new()) {
            if e.is(ErrorClass::AuditUnavailable) {
                return Ok(self.refuse(
                    503,
                    "audit_unavailable",
                    "denied",
                    Some("AuditUnavailable"),
                    None,
                    Vec::new(),
                    false,
                ));
            }
            return Err(e);
        }

        let grant_id = self.grant.as_ref().expect("checked").id.clone();
        match self.ctx.policy.consume(&grant_id, None, None, None, None) {
            Ok(g) => self.grant = Some(g),
            Err(e) if e.is(ErrorClass::PolicyDenied) => {
                return Ok(self.refuse(403, &e.reason, "denied", None, None, Vec::new(), true));
            }
            Err(e) => return Err(e),
        }

        let secret = match self
            .ctx
            .vault
            .secret_for_trusted_use(&connection.secret_id, connection.secret_version)
        {
            Ok(s) => s,
            Err(e)
                if e.is(ErrorClass::NotFound)
                    || e.is(ErrorClass::StateError)
                    || e.is(ErrorClass::InvalidInput) =>
            {
                return Ok(self.refuse(
                    503,
                    "credential_unavailable",
                    "error",
                    Some("StateError"),
                    None,
                    Vec::new(),
                    true,
                ));
            }
            Err(e) => return Err(e),
        };
        let (auth_name, auth_value) = match auth_header(&connection, &secret) {
            Ok(pair) => pair,
            Err(Invalid(reason)) => {
                return Ok(self.refuse(
                    501,
                    reason,
                    "denied",
                    Some("Unsupported"),
                    None,
                    Vec::new(),
                    true,
                ));
            }
        };
        let basic_username = connection
            .http_auth
            .as_ref()
            .filter(|a| a.mode == "basic")
            .and_then(|a| a.basic_username.clone());
        let patterns = credential_patterns(&secret, basic_username.as_deref());
        drop(secret);

        let mut upstream_headers = forwarded.clone();
        dict_set(&mut upstream_headers, "Host", host_header(&connection));
        dict_set(&mut upstream_headers, "Accept-Encoding", "identity");
        dict_set(&mut upstream_headers, "Connection", "close");
        dict_set(&mut upstream_headers, "Via", relay_via());
        dict_set(&mut upstream_headers, auth_name, auth_value);

        let response = match self.exchange(&upstream_headers, &pinned_address) {
            Ok(r) => r,
            Err(failure) => {
                if failure.known_outcome {
                    let mut result = error_result(502, failure.reason, None, None);
                    let outcome = failure.result;
                    let reason = failure.reason;
                    let upstream_status = failure.upstream_status;
                    self.finish(&mut result, outcome, Some(reason), upstream_status);
                    return Ok(result);
                }
                return Ok(self.refuse_failure(failure));
            }
        };

        // `_finish`'s `upstream_status` is the *original* upstream response
        // status even when the relayed result itself is a synthetic 502
        // (credential reflection blocked): capture it before `response` is
        // consumed by `filter_response`.
        let response_status = response.status;
        let mut result = Relay::filter_response(response, &patterns);
        let outcome = if result.reason.is_some() {
            "blocked"
        } else {
            "ok"
        };
        let reason = result.reason.clone();
        self.finish(
            &mut result,
            outcome,
            reason.as_deref(),
            Some(response_status),
        );
        Ok(result)
    }
}

/// Any internal `crate::errors::Error` that Python would let escape `relay`/
/// `relay_for_caller` uncaught (from `Policy`/`Audit`/`Vault` operations the
/// Python code does not wrap in a `try`/`except`) is converted to a
/// fail-closed `RelayResult` here instead of panicking, so `relay`'s Rust
/// signature can stay `-> RelayResult` like Python's declared return type.
/// See `DEVIATIONS.md`.
fn unexpected_error_result(e: Error) -> RelayResult {
    let status = match e.class {
        ErrorClass::InvalidInput => 400,
        ErrorClass::AuthFailed => 401,
        ErrorClass::PolicyDenied => 403,
        ErrorClass::NotFound => 404,
        ErrorClass::Unsupported => 501,
        ErrorClass::AuditUnavailable => 503,
        ErrorClass::StateError => 503,
        ErrorClass::ZeroPW => 500,
    };
    error_result(status, &e.reason, Some(&e.name), None)
}

fn refuse_unauthenticated(
    ctx: &Context,
    reason: &str,
    method: &str,
    path: &str,
    request_id: Option<&str>,
) -> RelayResult {
    let action = normalize_method(method).ok();
    let safe_path = normalize_path(path)
        .ok()
        .map(|(_, target)| strip_query(&target));
    let safe_request_id = request_id
        .filter(|r| REQUEST_ID_RE.is_match(r))
        .map(str::to_string);
    let result = ctx.audit.record(
        "http_relay",
        RecordArgs {
            caller: None,
            connection: None,
            target: None,
            action: action.as_deref(),
            result: Some("denied"),
            reason: Some(reason),
            request_id: safe_request_id.as_deref(),
            extra: vec![("path", safe_path.map(Value::String).unwrap_or(Value::Null))],
            ..Default::default()
        },
    );
    if let Err(e) = result
        && e.is(ErrorClass::AuditUnavailable)
    {
        return error_result(503, "audit_unavailable", Some("AuditUnavailable"), None);
    }
    error_result(401, reason, Some("AuthFailed"), None)
}

/// Port of `gateway.relay`: relay on behalf of a handle (URL prefix or
/// `X-ZeroPW-Handle` header).
pub fn relay(
    ctx: &Context,
    handle_token: &str,
    method: &str,
    path: &str,
    headers: &Headers,
    body: &[u8],
    request_id: Option<&str>,
) -> RelayResult {
    relay_with_resolver(
        ctx,
        handle_token,
        method,
        path,
        headers,
        body,
        request_id,
        default_resolver(),
    )
}

/// [`relay`] with an injectable [`Resolver`] (see the module doc's seam
/// note); used by tests to simulate DNS answers.
#[allow(clippy::too_many_arguments)]
pub fn relay_with_resolver(
    ctx: &Context,
    handle_token: &str,
    method: &str,
    path: &str,
    headers: &Headers,
    body: &[u8],
    request_id: Option<&str>,
    resolver: Resolver,
) -> RelayResult {
    let handle = match ctx.handles.verify(handle_token, Some((ctx.clock)())) {
        Ok(h) => h,
        Err(e) => return refuse_unauthenticated(ctx, &e.reason, method, path, request_id),
    };
    Relay::new(
        ctx,
        &handle.caller,
        &handle.connection,
        Some(&handle.grant),
        Some(handle.policy_version),
        method,
        path,
        headers,
        body,
        request_id,
        resolver,
    )
    .run()
}

/// Port of `gateway.relay_for_caller`: relay for an authenticated tools
/// caller, no handle, any usable grant.
#[allow(clippy::too_many_arguments)]
pub fn relay_for_caller(
    ctx: &Context,
    caller: &str,
    connection_id: &str,
    method: &str,
    path: &str,
    headers: &Headers,
    body: &[u8],
    request_id: Option<&str>,
) -> RelayResult {
    relay_for_caller_with_resolver(
        ctx,
        caller,
        connection_id,
        method,
        path,
        headers,
        body,
        request_id,
        default_resolver(),
    )
}

/// [`relay_for_caller`] with an injectable [`Resolver`].
#[allow(clippy::too_many_arguments)]
pub fn relay_for_caller_with_resolver(
    ctx: &Context,
    caller: &str,
    connection_id: &str,
    method: &str,
    path: &str,
    headers: &Headers,
    body: &[u8],
    request_id: Option<&str>,
    resolver: Resolver,
) -> RelayResult {
    Relay::new(
        ctx,
        caller,
        connection_id,
        None,
        None,
        method,
        path,
        headers,
        body,
        request_id,
        resolver,
    )
    .run()
}

#[allow(unused)]
fn unused_type_anchor(_: HashMap<(), ()>) {}
