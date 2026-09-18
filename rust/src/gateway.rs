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

/// `HTTPResponse.getheader(name)`: every occurrence of `name` (case
/// insensitive), joined with `", "` (`email.message.Message.get_all`), or
/// `None` if `name` is absent -- unlike [`headers_get`] (`Message.get`,
/// first value only).
fn headers_get_all_joined(headers: &Headers, name: &str) -> Option<String> {
    let values: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect();
    if values.is_empty() {
        None
    } else {
        Some(values.join(", "))
    }
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

/// `_TARGET_CHARS.match(raw)`: a `^...$` pattern with no other use of `$`,
/// no `re.MULTILINE`, and a body that cannot itself match `"\n"`, matched
/// with `.match()` in Python with no preceding `.strip()`. CPython's `$` in
/// that mode also matches immediately before a single trailing `"\n"`; the
/// `regex` crate's anchored `is_match` only accepts the true end of the
/// haystack, so it alone rejects a trailing-newline path Python would
/// accept (finding F-12; same technique as `policy.rs`'s
/// `matches_with_trailing_newline`).
fn matches_with_trailing_newline(re: &Regex, s: &str) -> bool {
    if re.is_match(s) {
        return true;
    }
    match s.strip_suffix('\n') {
        Some(rest) => re.is_match(rest),
        None => false,
    }
}

fn normalize_path_inner(raw: &str) -> Result<(String, String), Invalid> {
    if !raw.starts_with('/') {
        return Err(Invalid("invalid_path"));
    }
    if raw.chars().count() > MAX_PATH_LENGTH
        || !matches_with_trailing_newline(&TARGET_CHARS, raw)
        || raw.contains('#')
    {
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
    // finding F-R2-1: this used to index `&s[i+1..i+3]` on the *str*, which
    // panics whenever that slice boundary lands inside a multi-byte UTF-8
    // character -- reachable on the second decode pass (e.g. `/%25%E4%B8%AD`
    // first decodes to bytes `2f 25 e4 b8 ad`, and byte offset 4 is inside
    // `中`). Decode over the raw bytes throughout, reading the two hex
    // digits as bytes (never as a `str` slice), and only build the final
    // `String` once, lossily, at the end -- exactly mirroring
    // `bytes.decode("utf-8", "replace")`, which never panics on untrusted
    // input.
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push(((hi << 4) | lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `str.strip()` with CPython's exact `str.isspace()` predicate (which also
/// covers U+001C-U+001F, the "information separator" control characters --
/// Rust's `str::trim()` does not treat these as whitespace at all), matching
/// `policy.rs`'s own `python_strip` (finding F-11).
fn python_strip(s: &str) -> &str {
    s.trim_matches(crate::pystr::is_space)
}

fn normalize_method(method: &str) -> Result<String, Invalid> {
    let upper = python_strip(method).to_uppercase();
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
    // `_REQUEST_ID_RE.match(request_id)`: CPython's `$` matches just before
    // a single trailing `"\n"` too (finding F-R2-8) -- a request id ending
    // in `"\n"` is accepted here, and that exact string (newline included)
    // becomes the ledger key, matching Python's own `dict` key.
    if !matches_with_trailing_newline(&REQUEST_ID_RE, &candidate) {
        return Err(Invalid("invalid_request_id"));
    }
    Ok(Some(candidate))
}

/// `gateway._normalize_headers`: lowercase names, last-value-wins.
fn normalize_headers(headers: &Headers) -> Headers {
    let mut out: Headers = Vec::new();
    for (name, value) in headers {
        dict_set(&mut out, python_strip(name).to_lowercase(), value.clone());
    }
    out
}

fn forwardable_headers(headers: &Headers) -> Result<Headers, Invalid> {
    let mut forwarded = Headers::new();
    for (name, value) in headers {
        if !REQUEST_HEADER_ALLOWLIST.contains(&name.as_str()) {
            continue;
        }
        // `_HEADER_VALUE_RE.match(value)`: accepts a single trailing `"\n"`
        // (finding F-R2-8); a value that only matches this way is still
        // forwarded here, and fails later, downstream, when it is actually
        // written on the wire (`write_request`'s illegal-header-value
        // check, mirroring `putheader`'s `_is_illegal_header_value`).
        if !matches_with_trailing_newline(&HEADER_VALUE_RE, value) {
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
    // `_HEADER_CREDENTIAL_RE.match(text)`: accepts a single trailing `"\n"`
    // (finding F-R2-8) -- a credential ending in `"\n"` is accepted here and
    // only rejected later, downstream, when it is actually written on the
    // wire (`write_request`'s illegal-header-value check).
    if !matches_with_trailing_newline(&HEADER_CREDENTIAL_RE, text) {
        return Err(Invalid("credential_header_unsafe"));
    }
    if auth.mode == "bearer" {
        return Ok(("Authorization".to_string(), format!("Bearer {text}")));
    }
    if auth.mode == "header" {
        let name = auth.header_name.as_deref().unwrap_or("");
        // Same finding F-R2-8 trailing-newline allowance as above, for the
        // custom header's own name.
        if name.is_empty() || !matches_with_trailing_newline(&CUSTOM_HEADER_NAME_RE, name) {
            return Err(Invalid("unsupported_auth_mode"));
        }
        let prefix = auth.value_prefix.as_deref().unwrap_or("");
        if !matches_with_trailing_newline(&HEADER_VALUE_RE, prefix) {
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
/// ValueError: pass` around `urlsplit`. The returned host is lower-cased
/// (and, for a bracketed literal, bracket-stripped), matching
/// `SplitResult.hostname`'s own documented lower-casing (finding F-4: a
/// mixed-case `public_url` must still trigger the self-referential-target
/// check).
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
        return Some((host.to_lowercase(), port));
    }
    // `_hostinfo`'s unbracketed branch: `hostname, _, port =
    // hostinfo.partition(':')` -- `str.partition` splits on the *first*
    // occurrence, not the last, so `"::1:8443"` gives hostname `""` (not
    // `"::1"`) and port `"1:8443"` (not `"8443"`). An empty port (no colon,
    // or a colon with nothing after it) means "unspecified" and falls back
    // to `default_port` (`.port` returns `None` for that case, and
    // `parts.port or default` applies the default); a non-empty port that
    // isn't all-ASCII-digits, or is out of the `0..=65535` range accepted by
    // `SplitResult.port`, raises `ValueError` there, which the caller's
    // `except ValueError: pass` swallows -- so this returns `None`,
    // matching "no usable port, skip the comparison" rather than "no port,
    // use the default" (finding F-R2-10).
    match hostport.split_once(':') {
        Some((host, port)) => {
            if port.is_empty() {
                Some((host.to_lowercase(), default_port))
            } else if port.bytes().all(|b| b.is_ascii_digit()) {
                let port: i64 = port.parse().ok()?;
                if (0..=65535).contains(&port) {
                    Some((host.to_lowercase(), port))
                } else {
                    None
                }
            } else {
                None
            }
        }
        None => Some((hostport.to_lowercase(), default_port)),
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

    /// `RequestLedger._load`: any `state.read_json` failure (a `StateError`
    /// in Python) propagates uncaught out of every method that calls
    /// `_load`/`_save`, all the way out of `_Relay.run`/`relay`, refusing the
    /// request *before* the upstream is ever contacted. `Ok`-wrapped so
    /// callers can `?`-propagate the same way (finding F-1).
    fn load(&self) -> Result<Map<String, Value>, Error> {
        let doc = self.ctx.state.read_json(LEDGER_DOC, json!({}))?;
        Ok(match doc {
            Value::Object(m) => m,
            _ => Map::new(),
        })
    }

    /// `RequestLedger._save` (finding F-1: see `load` above).
    fn save(&self, mut doc: Map<String, Value>) -> Result<(), Error> {
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
        self.ctx.state.write_json(LEDGER_DOC, &Value::Object(doc))
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
        let mut doc = self.load()?;
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
        self.save(doc)?;
        Ok(("new", None))
    }

    /// `RequestLedger._update`: like `_load`/`_save`, `state.lock()` and the
    /// two calls above are unguarded in Python, so any failure (a
    /// `StateError`) propagates uncaught out of `mark_uncertain`/`complete`
    /// (finding F-1).
    fn update(
        &self,
        caller: &str,
        request_id: &str,
        apply: impl FnOnce(&mut Map<String, Value>),
    ) -> Result<(), Error> {
        let _lock = self.ctx.state.lock()?;
        let mut doc = self.load()?;
        let now = (self.ctx.clock)();
        let Some(Value::Object(entries)) = doc.get_mut(caller) else {
            return Ok(());
        };
        let Some(Value::Object(entry)) = entries.get_mut(request_id) else {
            return Ok(());
        };
        apply(entry);
        entry.insert("updated_at".into(), json!(now));
        self.save(doc)
    }

    /// `RequestLedger.release` (finding F-1).
    pub fn release(&self, caller: &str, request_id: &str) -> Result<(), Error> {
        let _lock = self.ctx.state.lock()?;
        let mut doc = self.load()?;
        if let Some(Value::Object(entries)) = doc.get_mut(caller)
            && entries.remove(request_id).is_some()
        {
            if entries.is_empty() {
                doc.remove(caller);
            }
            self.save(doc)?;
        }
        Ok(())
    }

    pub fn mark_uncertain(&self, caller: &str, request_id: &str) -> Result<(), Error> {
        self.update(caller, request_id, |entry| {
            entry.insert("state".into(), json!("uncertain"));
        })
    }

    pub fn complete(
        &self,
        caller: &str,
        request_id: &str,
        result: &RelayResult,
    ) -> Result<(), Error> {
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
        })
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

/// Port of `_Relay._exchange`'s exception mapping for everything from
/// `conn.request(...)` (writing the request) through `resp.read(...)`:
/// `except (socket.timeout, TimeoutError): upstream_timeout`, `except
/// (OSError, ValueError): upstream_connection_lost` -- distinct from
/// [`classify_connect_error`]'s `connect()`-only mapping (`OSError` ->
/// `upstream_unreachable`, never reached once the socket is connected;
/// finding F-5).
fn classify_read_write_error(e: &std::io::Error) -> &'static str {
    if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock {
        "upstream_timeout"
    } else {
        "upstream_connection_lost"
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
    // Python's `_open_connection` builds the `ssl.SSLContext` (including
    // `load_verify_locations(cafile=target.ca_file)`, which is where a bad
    // `ca_file` actually fails) *before* `_exchange` ever calls
    // `conn.connect()`; build the TLS config here, before the TCP connect,
    // so a bad `ca_file` for an otherwise-unreachable target still surfaces
    // as `ca_file_unavailable`, not `upstream_unreachable` (finding F-R2-9).
    let tls_config = if target.scheme == "https" {
        Some(build_tls_config(target.ca_file.as_deref())?)
    } else {
        None
    };
    let ip: IpAddr = pinned_address
        .parse()
        .map_err(|_| UpstreamFailure::error("upstream_unreachable"))?;
    let sockaddr = SocketAddr::new(ip, target.port as u16);
    let tcp = TcpStream::connect_timeout(&sockaddr, timeout)
        .map_err(|e| UpstreamFailure::error(classify_connect_error(&e)))?;
    let _ = tcp.set_nodelay(true);
    if let Some(config) = tls_config {
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

/// `http.client.HTTPConnection.putheader`'s illegal-value guard, as it
/// applies to the one shape of "illegal" value that can actually reach this
/// function: every header name/value here has already passed
/// [`forwardable_headers`]/[`auth_header`]'s own validation, which (per
/// finding F-R2-8) accepts a value ending in exactly one trailing `"\n"`
/// with no other `\r`/`\n` anywhere -- the only case CPython's own
/// `_is_legal_header_name`/`_is_illegal_header_value` regexes still reject
/// (a bare trailing `\n` with nothing after it fails
/// `\n(?![ \t])`/`[^:\r\n]*`'s fullmatch). Detecting a raw `'\n'` anywhere in
/// a name or value is therefore sufficient to reproduce that failure.
fn header_line_is_illegal(name: &str, value: &str) -> bool {
    name.contains('\n') || value.contains('\n')
}

fn write_request(
    stream: &mut dyn Write,
    method: &str,
    target: &str,
    headers: &Headers,
    body: &[u8],
) -> std::io::Result<()> {
    // `conn.request(...)` -> `putheader` raises `ValueError` for such a
    // header, *after* `self.transmitted = True` has already been set by the
    // caller (finding F-R2-8): map it to a plain I/O error so the caller's
    // existing `classify_read_write_error` turns it into
    // `upstream_connection_lost`, exactly like Python's `except (OSError,
    // ValueError)` clause around `conn.request(...)` does.
    for (name, value) in headers {
        if header_line_is_illegal(name, value) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "illegal header name or value",
            ));
        }
    }
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

/// `http.client._MAXLINE`: every physical line `HTTPResponse` reads off the
/// wire (status line, header line, chunk-size line, trailer line) is capped
/// at this many bytes; a longer line is `LineTooLong`, an
/// `http.client.HTTPException` -> `upstream_protocol_error` (finding
/// F-R2-2).
const HTTP_MAX_LINE: usize = 65536;
/// `http.client._MAXHEADERS`: the physical line count `_read_headers` allows
/// (status-line's own header block *and* the final response's headers
/// alike -- both call sites share `_read_headers`), counting the
/// terminating blank/EOF line too; line 101 raises `HTTPException` ->
/// `upstream_protocol_error` (finding F-R2-2).
const HTTP_MAX_HEADERS: usize = 100;

/// `fp.readline(_MAXLINE + 1)` plus the `len(line) > _MAXLINE` check shared
/// by every line-oriented read in `http.client` (finding F-R2-2): reads at
/// most `HTTP_MAX_LINE + 1` bytes looking for `\n` (never more, so a
/// pathological line cannot force an unbounded allocation), strips a
/// trailing `\r`/`\n`, and returns `Ok(None)` only on true EOF (zero bytes
/// read) -- callers that treat EOF as a protocol error do so themselves;
/// several (finding F-R2-3) instead treat it exactly like a blank line.
fn read_line(reader: &mut impl BufRead) -> Result<Option<Vec<u8>>, UpstreamFailure> {
    let mut line = Vec::new();
    {
        let mut limited = reader.by_ref().take(HTTP_MAX_LINE as u64 + 1);
        limited
            .read_until(b'\n', &mut line)
            .map_err(|e| UpstreamFailure::error(classify_read_write_error(&e)))?;
    }
    if line.is_empty() {
        return Ok(None);
    }
    if line.len() > HTTP_MAX_LINE {
        return Err(UpstreamFailure::error("upstream_protocol_error"));
    }
    while line.last() == Some(&b'\n') || line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(Some(line))
}

/// CPython `int(text)` / `int(text, base)` semantics for `base` 10 or 16, as
/// used by `http.client`'s own `int(status)`, `int(length)` and
/// `int(chunk_size_text, 16)` parses (finding F-R2-5): optional surrounding
/// whitespace (`str.strip()`'s predicate, [`crate::pystr::is_space`]), an
/// optional leading `+`/`-` sign, an optional case-insensitive `0x`/`0X`
/// prefix when `base == 16` (after which exactly one leading `_` is
/// permitted, as if the prefix itself were a digit -- `int("0x_10", 16) ==
/// 16`), and single underscores permitted strictly between two digits
/// (`"1_000"` ok; `"_1"`, `"1_"`, `"1__0"` are not). Returns `None` for
/// anything CPython's `int()` would raise `ValueError` for. A magnitude too
/// large for `i128` saturates (with sign) rather than erroring, since every
/// caller here only ever compares the result against a small range or a
/// `usize` byte count -- never round-trips it back to text.
fn python_int(text: &str, base: u32) -> Option<i128> {
    let trimmed = text.trim_matches(crate::pystr::is_space);
    if trimmed.is_empty() {
        return None;
    }
    let (neg, rest) = match trimmed.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let (rest, mut prev_was_digit) = if base == 16 {
        match rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
            Some(r) => (r, true),
            None => (rest, false),
        }
    } else {
        (rest, false)
    };
    if rest.is_empty() {
        return None;
    }
    let chars: Vec<char> = rest.chars().collect();
    let mut digits = String::with_capacity(chars.len());
    for (i, &c) in chars.iter().enumerate() {
        if c == '_' {
            let next_is_digit = chars.get(i + 1).is_some_and(|c| c.is_digit(base));
            if !prev_was_digit || !next_is_digit {
                return None;
            }
            prev_was_digit = false;
            continue;
        }
        c.to_digit(base)?;
        digits.push(c);
        prev_was_digit = true;
    }
    if digits.is_empty() {
        return None;
    }
    // Too many digits for `i128`: treat the magnitude as "very large" (every
    // caller only ever compares the result against a small range or uses it
    // as a byte count, never round-trips it back to text).
    let magnitude = i128::from_str_radix(&digits, base).unwrap_or(i128::MAX);
    Some(if neg { -magnitude } else { magnitude })
}

/// Saturating `i128` -> `usize` conversion for a parsed `Content-Length` (or
/// similar byte count): a magnitude that does not fit `usize` is clamped to
/// `usize::MAX`, which the caller's own `limit`-bytes cap turns into
/// `response_too_large` long before it could matter, exactly as Python's
/// unbounded `int` would still be bounded by the same explicit check.
fn i128_to_usize_saturating(v: i128) -> usize {
    if v < 0 {
        0
    } else if v > usize::MAX as i128 {
        usize::MAX
    } else {
        v as usize
    }
}

fn latin1_decode(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

/// `s.encode("latin-1", "replace")`: each `char` that fits a single Latin-1
/// byte (U+0000-U+00FF) round-trips to that byte; anything else becomes `?`
/// (0x3F), Python's `errors="replace"` substitution character.
fn latin1_encode_replace(s: &str) -> Vec<u8> {
    s.chars()
        .map(|c| if (c as u32) <= 0xFF { c as u8 } else { b'?' })
        .collect()
}

/// `line.split(None, 2)`: CPython's whitespace split with no separator
/// argument splits on runs of `str.isspace()` characters ([`pystr::is_space`]
/// is the exact per-codepoint predicate), discarding leading whitespace.
/// With `maxsplit=2` at most 3 elements come back; only the first two
/// (`version`, `status`) matter to `_read_status` (finding F-9: a
/// tab-separated status line must split the same way a space-separated one
/// does).
fn python_split_none_2(line: &str) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    let n = chars.len();
    let mut i = 0usize;
    let mut parts = Vec::new();
    while parts.len() < 2 {
        while i < n && crate::pystr::is_space(chars[i]) {
            i += 1;
        }
        if i >= n {
            return parts;
        }
        let start = i;
        while i < n && !crate::pystr::is_space(chars[i]) {
            i += 1;
        }
        parts.push(chars[start..i].iter().collect());
    }
    while i < n && crate::pystr::is_space(chars[i]) {
        i += 1;
    }
    if i < n {
        parts.push(chars[i..].iter().collect());
    }
    parts
}

/// One `_read_status()` call: the status line only, no headers. Returns
/// `(version, status)`; `version` feeds the strict `HTTPResponse.begin`
/// check in [`read_status_and_headers`] (finding F-R2-6), which only
/// applies to the *final* (non-100) status line, not to an interim `100
/// Continue`'s own version.
fn read_one_status_line(reader: &mut impl BufRead) -> Result<(String, u16), UpstreamFailure> {
    let raw = read_line(reader)?.ok_or(UpstreamFailure::error("upstream_protocol_error"))?;
    let line = latin1_decode(&raw);
    let parts = python_split_none_2(&line);
    let version = parts.first().cloned().unwrap_or_default();
    let status_text = parts.get(1).map(String::as_str).unwrap_or("");
    if !version.starts_with("HTTP/") {
        return Err(UpstreamFailure::error("upstream_protocol_error"));
    }
    // CPython's `int(status)` (arbitrary precision, PEP 515 underscores
    // allowed) followed by a `100 <= status <= 999` range check; a parse
    // failure (including magnitudes that don't fit) is folded into the same
    // `BadStatusLine` -> `upstream_protocol_error` outcome as an
    // out-of-range value (findings F-6, F-R2-5).
    let status =
        python_int(status_text, 10).ok_or(UpstreamFailure::error("upstream_protocol_error"))?;
    if !(100..=999).contains(&status) {
        return Err(UpstreamFailure::error("upstream_protocol_error"));
    }
    Ok((version, status as u16))
}

/// Port of `http.client._read_headers`' physical byte consumption with no
/// header recognition at all: reads and discards lines up to (and
/// including) the blank separator line -- or EOF, which ends the block just
/// as successfully (finding F-R2-3a: `b''` is one of `_read_headers`'
/// terminator values, `line in (b'\r\n', b'\n', b'')`). Used to skip a `100
/// Continue` interim response's headers (`HTTPResponse.begin`'s
/// `skipped_headers = _read_headers(self.fp)`, finding F-7). Every physical
/// line, including the terminator, counts against `HTTP_MAX_HEADERS`
/// (finding F-R2-2).
fn skip_header_block(reader: &mut impl BufRead) -> Result<(), UpstreamFailure> {
    let mut count = 0usize;
    loop {
        let line = read_line(reader)?;
        count += 1;
        if count > HTTP_MAX_HEADERS {
            return Err(UpstreamFailure::error("upstream_protocol_error"));
        }
        match line {
            None => return Ok(()),
            Some(l) if l.is_empty() => return Ok(()),
            Some(_) => continue,
        }
    }
}

fn read_status_and_headers(reader: &mut impl BufRead) -> Result<StatusAndHeaders, UpstreamFailure> {
    // `HTTPResponse.begin`: "read until we get a non-100 response", skipping
    // each `100 Continue`'s own header block and relaying whatever response
    // finally follows (finding F-7).
    let (version, status) = loop {
        let (version, status) = read_one_status_line(reader)?;
        if status == 100 {
            skip_header_block(reader)?;
            continue;
        }
        break (version, status);
    };
    // `HTTPResponse.begin`'s own strict version gate, separate from
    // `_read_status`'s loose `"HTTP/"`-prefix check: only `HTTP/1.0`,
    // `HTTP/0.9`, or anything starting `HTTP/1.` is accepted; anything else
    // (`HTTP/2`, `HTTP/2.0`, a bare `HTTP/`) is `UnknownProtocol` ->
    // `upstream_protocol_error` (finding F-R2-6). Applies only to the final
    // (non-100) status line's version.
    if version != "HTTP/0.9" && !version.starts_with("HTTP/1.") {
        return Err(UpstreamFailure::error("upstream_protocol_error"));
    }
    // Port of `email.feedparser`'s header leniency as exercised through
    // `http.client.parse_headers` (finding F-9): a continuation line (starts
    // with a space or tab) folds into the previous header's value; a line
    // with no colon that is not a continuation ends the *recognised* header
    // block without error (`_parsegen`'s `headerRE` mismatch just stops its
    // for-loop, no exception) -- but every line up to the blank line (or
    // EOF, finding F-R2-3a) is still physically read off the wire
    // (`_read_headers`' own, separate, colon-agnostic boundary), so
    // `recognizing` only gates what gets added to `headers`, never how many
    // lines we read. Every physical line, including the terminator, counts
    // against `HTTP_MAX_HEADERS` (finding F-R2-2).
    let mut headers = Headers::new();
    let mut recognizing = true;
    let mut count = 0usize;
    loop {
        let line = read_line(reader)?;
        count += 1;
        if count > HTTP_MAX_HEADERS {
            return Err(UpstreamFailure::error("upstream_protocol_error"));
        }
        let line = match line {
            None => break,
            Some(l) if l.is_empty() => break,
            Some(l) => l,
        };
        if !recognizing {
            continue;
        }
        let line = latin1_decode(&line);
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation: fold into the previous header (or ignore it, as
            // Python's `FirstHeaderLineIsContinuationDefect` does, if there
            // is no previous header to fold into yet).
            if let Some((_, value)) = headers.last_mut() {
                value.push('\n');
                value.push_str(&line);
            }
            continue;
        }
        let Some(colon) = line.find(':') else {
            recognizing = false;
            continue;
        };
        // `header_source_parse` (`email/_policybase.py`): the name is kept
        // verbatim (`line[:i]`, no stripping at all); the value has only
        // *leading* whitespace stripped (`.lstrip(' \t\r\n')`) -- trailing
        // whitespace survives (only a trailing `\r`/`\n`, already removed by
        // `read_line`, is stripped) (finding F-8's root cause: a trimmed
        // value here is what let `"chunked "` compare equal to `"chunked"`
        // downstream).
        let name = line[..colon].to_string();
        let value = line[colon + 1..]
            .trim_start_matches([' ', '\t'])
            .to_string();
        headers.push((name, value));
    }
    Ok(StatusAndHeaders { status, headers })
}

enum BodyMode {
    Empty,
    ContentLength(usize),
    Chunked,
    UntilClose,
}

/// Port of the body-framing decision `HTTPResponse.begin`/`read` make
/// together (finding F-R2-7): `read()` checks `self._method == "HEAD"`
/// first (always empty, regardless of everything else), *then*
/// `self.chunked` (set independently of the 204/304/1xx override below), and
/// only afterwards would fall into the `self.length` branch where
/// `begin()`'s `self.length = 0` override for `NO_CONTENT`/`NOT_MODIFIED`/1xx
/// actually applies. So a `204`/`304`/1xx response with `Transfer-Encoding:
/// chunked` still gets its chunked body decoded and relayed in Python --
/// the length-zero override is dead code on that path. `HEAD` must stay
/// first: `read()` short-circuits on it before ever consulting `chunked`.
fn body_mode(method: &str, status: u16, headers: &Headers) -> BodyMode {
    if method == "HEAD" {
        return BodyMode::Empty;
    }
    // `tr_enc.lower() == "chunked"`, no stripping: a trailing space (now
    // preserved by `read_status_and_headers`) makes this comparison fail,
    // matching Python (finding F-8).
    if let Some(te) = headers_get(headers, "transfer-encoding")
        && te.eq_ignore_ascii_case("chunked")
    {
        return BodyMode::Chunked;
    }
    if status == 204 || status == 304 || (100..200).contains(&status) {
        return BodyMode::Empty;
    }
    // CPython's `int(length)` (PEP 515 underscores allowed); a parse
    // failure *or* a negative result both make Python fall back to
    // `self.length = None` (finding F-R2-5).
    if let Some(cl) = headers_get(headers, "content-length")
        && let Some(n) = python_int(cl, 10)
        && n >= 0
    {
        return BodyMode::ContentLength(i128_to_usize_saturating(n));
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
                    .map_err(|e| UpstreamFailure::error(classify_read_write_error(&e)))?;
                if n == 0 {
                    // `HTTPResponse.read(amt)`'s amt-limited branch calls
                    // plain `self.fp.read(amt)`, not `_safe_read`: a short
                    // (or empty) read at EOF is returned as-is, not an
                    // `IncompleteRead` -- the caller's own loop just sees
                    // `piece == b""` and stops (finding F-R2-3c: a
                    // `Content-Length` bigger than the bytes actually sent
                    // still relays as a 200 with the short body).
                    break;
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
                let line =
                    read_line(reader)?.ok_or(UpstreamFailure::error("upstream_protocol_error"))?;
                let line = latin1_decode(&line);
                let size_text = line.split(';').next().unwrap_or("");
                // `_read_next_chunk_size`'s `int(line, 16)` `ValueError` is
                // caught by `_get_chunk_left` and re-raised as
                // `IncompleteRead(b"")` (an `http.client.HTTPException`),
                // not left as a bare `ValueError` -- so it maps to
                // `upstream_protocol_error`, not `upstream_connection_lost`
                // (finding F-9). PEP 515 underscores are accepted, and so is
                // an optional `0x`/`0X` prefix, matching CPython's
                // `int(text, 16)` (finding F-R2-5).
                let size = python_int(size_text, 16)
                    .filter(|n| *n >= 0)
                    .ok_or(UpstreamFailure::error("upstream_protocol_error"))?;
                let mut size = i128_to_usize_saturating(size);
                if size == 0 {
                    // Trailers, until the blank line -- or EOF, which ends
                    // the block just as successfully as a blank line would
                    // ("a vanishingly small number of sites EOF without
                    // sending the trailer", finding F-R2-3d). No
                    // `HTTP_MAX_HEADERS` count cap here: only
                    // `_read_headers` (status/header block) enforces one,
                    // `_read_and_discard_trailer` does not.
                    loop {
                        let trailer = read_line(reader)?;
                        match trailer {
                            None => break,
                            Some(t) if t.is_empty() => break,
                            Some(_) => continue,
                        }
                    }
                    break;
                }
                while size > 0 {
                    let want = READ_CHUNK.min(limit + 1 - total).min(size);
                    let mut buf = vec![0u8; want];
                    let n = reader
                        .read(&mut buf)
                        .map_err(|e| UpstreamFailure::error(classify_read_write_error(&e)))?;
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
                // `_get_chunk_left`'s `self._safe_read(2)`: unconditionally
                // consumes exactly 2 bytes (the chunk's trailing CRLF)
                // without ever validating their content -- erroring only if
                // fewer than 2 bytes are available before EOF (finding
                // F-R2-4; previously this read a whole line and required it
                // empty, which both rejected valid-but-unchecked terminators
                // and accepted an LF-only framing Python itself refuses).
                let mut crlf = [0u8; 2];
                if let Err(e) = reader.read_exact(&mut crlf) {
                    return Err(if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        UpstreamFailure::error("upstream_protocol_error")
                    } else {
                        UpstreamFailure::error(classify_read_write_error(&e))
                    });
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
                    .map_err(|e| UpstreamFailure::error(classify_read_write_error(&e)))?;
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
    ) -> Result<RelayResult, Error> {
        if self.claimed
            && let Some(request_id) = self.request_id.clone()
        {
            if self.transmitted {
                self.ledger.mark_uncertain(&self.caller, &request_id)?;
            } else {
                self.ledger.release(&self.caller, &request_id)?;
            }
            self.claimed = false;
        }
        if do_audit
            && let Err(e) = self.audit(result, Some(reason), None, audit_extra)
            && e.is(ErrorClass::AuditUnavailable)
        {
            return Ok(error_result(
                503,
                "audit_unavailable",
                Some("AuditUnavailable"),
                None,
            ));
        }
        Ok(error_result(status, reason, error, extra_body))
    }

    fn approval_subject(&self, content_type: Option<&str>) -> String {
        let connection = self.connection.as_ref().expect("checked");
        let value = json!({
            "origin": self.origin, "target": self.target,
            "policy_version": connection.policy_version, "content_type": content_type,
        });
        pyjson::dumps(&value, DumpOptions::compact_sorted()).expect("representable")
    }

    /// `_annotate_approval`: both `state.read_json`/`state.write_json` calls
    /// are unguarded in Python, so a `StateError` from either propagates
    /// uncaught out of `_annotate_approval`, out of `run`, to `relay`'s
    /// top-level fail-closed conversion (`DEVIATIONS.md`'s
    /// `unexpected_error_result` row). Previously this swallowed both
    /// failures (`let Ok(..) = .. else { return }` / `let _ = ..`), so a
    /// state failure still returned `428 approval_required` with an
    /// under-annotated approval entry instead of failing closed (finding
    /// F-R2-12).
    fn annotate_approval(&self, digest: &str, content_type: Option<&str>) -> Result<(), Error> {
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

        let control = self.ctx.state.read_json(policy::CONTROL, Value::Null)?;
        let Value::Object(mut control) = control else {
            return Ok(());
        };
        let Some(entry) = control
            .get_mut("approvals")
            .and_then(Value::as_object_mut)
            .and_then(|a| a.get_mut(digest))
            .and_then(|e| e.as_object_mut())
        else {
            return Ok(());
        };
        let mut changed = false;
        for (key, value) in details {
            if !entry.contains_key(&key) {
                entry.insert(key, value);
                changed = true;
            }
        }
        if changed {
            self.ctx
                .state
                .write_json(policy::CONTROL, &Value::Object(control))?;
        }
        Ok(())
    }

    fn refuse_failure(&mut self, failure: UpstreamFailure) -> Result<RelayResult, Error> {
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
    ) -> Result<(), Error> {
        if self.claimed
            && let Some(request_id) = self.request_id.clone()
        {
            self.ledger.complete(&self.caller, &request_id, result)?;
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
        Ok(())
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
        .map_err(|e| UpstreamFailure::error(classify_read_write_error(&e)))?;
        let mut reader = BufReader::new(stream);
        let head = read_status_and_headers(&mut reader)?;
        if REDIRECT_STATUSES.contains(&head.status) {
            return Err(UpstreamFailure::blocked(
                "redirect_not_followed",
                head.status,
            ));
        }
        // `HTTPResponse.getheader("Content-Encoding")` joins *every*
        // occurrence with `", "` (`Message.get_all`), unlike a plain
        // `Message.get` (first value only) -- so a duplicate
        // `Content-Encoding: identity` + `gzip` is seen as `"identity, gzip"`
        // and rejected, not silently treated as just `identity` (finding
        // F-3). `Transfer-Encoding`/`Content-Length` below still use
        // first-value semantics (`headers_get`), matching how
        // `http.client`'s own framing logic reads them via `Message.get`.
        let encoding = headers_get_all_joined(&head.headers, "content-encoding")
            .unwrap_or_else(|| "identity".to_string())
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
        // `f"{name}: {value}".encode("latin-1", "replace")` joined with
        // `b"\r\n"` (gateway.py:1032-1034): the *exact upstream bytes*, not
        // a UTF-8 re-encoding, so a credential byte >= 0x80 reflected in a
        // header is still caught (finding F-2). `response.headers` values
        // are already latin-1-decoded byte-for-byte by `latin1_decode` in
        // `read_status_and_headers`, so this round-trips exactly.
        let mut header_blob: Vec<u8> = Vec::new();
        for (index, (k, v)) in response.headers.iter().enumerate() {
            if index > 0 {
                header_blob.extend_from_slice(b"\r\n");
            }
            header_blob.extend(latin1_encode_replace(&format!("{k}: {v}")));
        }
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
            return self.refuse(
                400,
                reason,
                "denied",
                Some("InvalidInput"),
                None,
                Vec::new(),
                true,
            );
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
            return self.refuse(403, decision.reason, "denied", None, None, Vec::new(), true);
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
            return self.refuse(
                403,
                "action_kind_mismatch",
                "denied",
                None,
                None,
                Vec::new(),
                true,
            );
        }
        if let Some(handle_pv) = self.handle_policy_version
            && handle_pv != connection.policy_version
        {
            return self.refuse(403, "grant_stale", "denied", None, None, Vec::new(), true);
        }
        if self_referential_target(self.ctx, &connection) {
            return self.refuse(
                501,
                "self_referential_target",
                "denied",
                Some("Unsupported"),
                None,
                Vec::new(),
                true,
            );
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
                    return self.refuse(
                        409,
                        "request_in_flight",
                        "denied",
                        Some("Conflict"),
                        None,
                        Vec::new(),
                        true,
                    );
                }
                "uncertain" => {
                    return self.refuse(
                        409,
                        "outcome_uncertain",
                        "denied",
                        Some("Conflict"),
                        None,
                        Vec::new(),
                        true,
                    );
                }
                "reused" => {
                    return self.refuse(
                        409,
                        "request_id_reused",
                        "denied",
                        Some("Conflict"),
                        None,
                        Vec::new(),
                        true,
                    );
                }
                _ => {
                    self.claimed = true;
                }
            }
        }

        let pinned_address = match resolve_pinned_address(&connection, &self.resolver) {
            Ok(addr) => addr,
            Err(failure) => return self.refuse_failure(failure),
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
                    self.annotate_approval(&digest, content_type.as_deref())?;
                }
                let mut extra_body = Map::new();
                extra_body.insert("approval_digest".into(), json!(digest));
                return self.refuse(
                    428,
                    "approval_required",
                    "denied",
                    None,
                    Some(extra_body),
                    vec![("digest", json!(digest))],
                    true,
                );
            }
        }

        if let Err(e) = self.audit("attempt", None, None, Vec::new()) {
            if e.is(ErrorClass::AuditUnavailable) {
                return self.refuse(
                    503,
                    "audit_unavailable",
                    "denied",
                    Some("AuditUnavailable"),
                    None,
                    Vec::new(),
                    false,
                );
            }
            return Err(e);
        }

        let grant_id = self.grant.as_ref().expect("checked").id.clone();
        match self.ctx.policy.consume(&grant_id, None, None, None, None) {
            Ok(g) => self.grant = Some(g),
            Err(e) if e.is(ErrorClass::PolicyDenied) => {
                return self.refuse(403, &e.reason, "denied", None, None, Vec::new(), true);
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
                return self.refuse(
                    503,
                    "credential_unavailable",
                    "error",
                    Some("StateError"),
                    None,
                    Vec::new(),
                    true,
                );
            }
            Err(e) => return Err(e),
        };
        let (auth_name, auth_value) = match auth_header(&connection, secret.expose()) {
            Ok(pair) => pair,
            Err(Invalid(reason)) => {
                return self.refuse(
                    501,
                    reason,
                    "denied",
                    Some("Unsupported"),
                    None,
                    Vec::new(),
                    true,
                );
            }
        };
        let basic_username = connection
            .http_auth
            .as_ref()
            .filter(|a| a.mode == "basic")
            .and_then(|a| a.basic_username.clone());
        let patterns = credential_patterns(secret.expose(), basic_username.as_deref());
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
                    self.finish(&mut result, outcome, Some(reason), upstream_status)?;
                    return Ok(result);
                }
                return self.refuse_failure(failure);
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
        )?;
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
    // `_refuse_unauthenticated`: `action = method.upper() if
    // isinstance(method, str) and _METHOD_RE.match(method.upper()) else
    // None` -- matched against the *untrimmed* upper-cased method (unlike
    // `_normalize_method`'s own `.strip()`), and `safe_path =
    // strip_query(path) if isinstance(path, str) else None`, computed for
    // *any* string path with no `normalize_path` validation at all (finding
    // F-10): both `method`/`path` are always `str` here (a concrete `&str`
    // parameter, not Python's duck-typed `Any`), so the `isinstance` checks
    // always pass.
    let upper_method = method.to_uppercase();
    // Both regexes match here with CPython's `$`-before-trailing-`"\n"`
    // leniency (finding F-R2-8), unlike `_normalize_method`'s own use of
    // `_METHOD_RE` (which never sees a trailing newline at all, since
    // `.strip()` already removed it first).
    let action = matches_with_trailing_newline(&METHOD_RE, &upper_method).then_some(upper_method);
    let safe_path = strip_query(path);
    let safe_request_id = request_id
        .filter(|r| matches_with_trailing_newline(&REQUEST_ID_RE, r))
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
            extra: vec![("path", Value::String(safe_path))],
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

/// `annotate_approval` (finding F-R2-12) is private to this module, so this
/// direct-call regression test lives here rather than in `rust/tests/`,
/// which cannot see it. Testing it through the full `relay(...)` pipeline
/// would require the *first* `request_approval` write (which shares the
/// same `policy/control.json`) to succeed while a *later* one fails --
/// awkward to arrange with plain file permissions; calling
/// `annotate_approval` directly against an already-corrupt state file is
/// both simpler and more precise.
#[cfg(test)]
mod annotate_approval_tests {
    use super::*;
    use crate::clock;
    use crate::context::Config;
    use crate::policy::{Connection, HttpAuth, HttpScope, HttpTarget};

    #[test]
    fn annotate_approval_fails_closed_on_corrupt_state_instead_of_swallowing_the_error() {
        // Python's `_annotate_approval` has no `try`/`except` around either
        // `state.read_json(CONTROL, None)` or `state.write_json(CONTROL,
        // control)`: a `StateError` from either propagates uncaught out of
        // `_annotate_approval`, out of `run`, to `relay`'s top-level
        // fail-closed conversion (`DEVIATIONS.md`'s `unexpected_error_result`
        // row). This used to `let Ok(..) = .. else { return }` (silently
        // giving up) and `let _ = ..` (silently ignoring a write failure)
        // instead, so a state failure here still returned `428
        // approval_required` with an under-annotated approval entry.
        let tmp = tempfile::TempDir::new().unwrap();
        let ctx = Context::initialize(
            tmp.path().join("state"),
            "admin-passphrase-1",
            "recovery-passphrase-1",
            Config::default(),
            clock::fixed(1_700_000_000.0),
        )
        .unwrap();
        ctx.projects
            .create("demo", crate::projects::DEFAULT_ENVIRONMENTS)
            .unwrap();
        let target = HttpTarget::new("http", "127.0.0.1", 1, None, false).unwrap();
        let connection = Connection::new(
            "cid",
            "demo",
            "dev",
            "test",
            "http",
            "secret",
            None,
            "",
            Some(target),
            Some(HttpAuth::bearer()),
            Some(HttpScope::new(None, None, vec![]).unwrap()),
            None,
            None,
            0,
            "active",
            "",
            "",
        )
        .unwrap();

        // `policy/control.json` exists (created by `Context::initialize`'s
        // `state.subdir("policy")`) but is not valid JSON: `read_json` must
        // fail with a `StateError`.
        std::fs::write(ctx.state.path.join(policy::CONTROL), b"not json").unwrap();

        let mut relay = Relay::new(
            &ctx,
            "agent-1",
            "cid",
            None,
            None,
            "POST",
            "/x",
            &Headers::new(),
            b"",
            None,
            default_resolver(),
        );
        relay.connection = Some(connection);
        relay.target = "/x".to_string();

        let result = relay.annotate_approval("some-digest", None);
        assert!(
            result.is_err(),
            "annotate_approval must fail closed (propagate the StateError) on a \
             corrupt policy/control.json, not silently return Ok"
        );
    }
}

// ------------------------------------------------------- differential fuzzing
//
// Equivalence-review round 2, "Also:" item: fuzz `read_status_and_headers`/
// `body_mode`/`read_body` directly against real `python3.12` `http.client`,
// generating several thousand random and adversarial raw responses (status
// lines, header blocks, chunked framings, truncations) and asserting Rust
// never panics and always agrees with Python's outcome class and relayed
// body bytes. These three functions are private to this module, so the
// fuzzer lives here (a unit test module) rather than in `rust/tests/`, which
// cannot see them.
#[cfg(test)]
mod http_framing_fuzz {
    use super::*;
    use std::io::Cursor;

    /// Small, fast, seeded xorshift64* PRNG -- deterministic across runs (no
    /// `rand` dependency needed for this generator), so a failure is always
    /// reproducible from the seed printed in the panic/assert message.
    struct Lcg(u64);
    impl Lcg {
        fn new(seed: u64) -> Self {
            Lcg(seed | 1)
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: usize) -> usize {
            if n == 0 {
                0
            } else {
                (self.next_u64() % n as u64) as usize
            }
        }
        fn one_in(&mut self, n: usize) -> bool {
            self.below(n) == 0
        }
        fn choice<'a, T>(&mut self, items: &'a [T]) -> &'a T {
            &items[self.below(items.len())]
        }
    }

    const READ_CHUNK_FOR_FUZZ: usize = 65536;
    const FUZZ_LIMIT: usize = 200_000;

    #[derive(Debug, Clone, PartialEq)]
    enum FuzzOutcome {
        Ok(u16, Vec<u8>),
        ProtocolError,
        TooLarge,
    }

    /// Runs exactly the read sequence `_Relay._exchange` performs on a
    /// `conn.getresponse()` result (`begin()` via `read_status_and_headers`,
    /// then the `resp.read(min(READ_CHUNK, limit + 1 - total))` loop), over
    /// an in-memory `Cursor` standing in for the socket. A `Cursor` never
    /// produces a real I/O error, so the only failure category reachable
    /// here is `upstream_protocol_error` (never `upstream_timeout`/
    /// `upstream_connection_lost`, which only come from a genuine transport
    /// error) -- exactly mirroring a `python3.12` `http.client.HTTPResponse`
    /// fed the same bytes via an `io.BytesIO`-backed fake socket, which can
    /// only ever raise an `http.client.HTTPException` subclass here, never a
    /// real `OSError`.
    fn rust_outcome(method: &str, raw: &[u8]) -> FuzzOutcome {
        let mut reader = Cursor::new(raw);
        let head = match read_status_and_headers(&mut reader) {
            Ok(h) => h,
            Err(_) => return FuzzOutcome::ProtocolError,
        };
        let mode = body_mode(method, head.status, &head.headers);
        // `read_body` already loops internally in `READ_CHUNK`-sized steps
        // and applies the same running `> limit` check Python's own
        // per-`resp.read(amt)`-call loop does, so reading the whole body in
        // one call here is equivalent to replaying that loop by hand.
        match read_body(&mut reader, mode, FUZZ_LIMIT) {
            Ok(body) => FuzzOutcome::Ok(head.status, body),
            Err(f) if f.reason == "response_too_large" => FuzzOutcome::TooLarge,
            Err(_) => FuzzOutcome::ProtocolError,
        }
    }

    fn python_outcome(interpreter: &str, cases: &[(&'static str, Vec<u8>)]) -> Vec<FuzzOutcome> {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let payload: Vec<serde_json::Value> = cases
            .iter()
            .map(|(method, raw)| {
                use base64::Engine as _;
                json!({
                    "method": method,
                    "raw": base64::engine::general_purpose::STANDARD.encode(raw),
                })
            })
            .collect();
        let script = format!(
            r#"
import sys, io, json, base64, http.client

READ_CHUNK = {read_chunk}
LIMIT = {limit}

class FakeSock:
    def __init__(self, data):
        self._data = data
    def makefile(self, mode):
        return io.BytesIO(self._data)

def run_one(method, raw):
    resp = http.client.HTTPResponse(FakeSock(raw), method=method)
    try:
        resp.begin()
        chunks = []
        total = 0
        while True:
            piece = resp.read(min(READ_CHUNK, LIMIT + 1 - total))
            if not piece:
                break
            chunks.append(piece)
            total += len(piece)
            if total > LIMIT:
                return ["too_large"]
        body = b"".join(chunks)
        return ["ok", resp.status, base64.b64encode(body).decode("ascii")]
    except http.client.HTTPException:
        return ["protocol_error"]
    except (OSError, ValueError):
        return ["connection_lost"]
    except Exception as e:
        return ["other_error", type(e).__name__, str(e)]

cases = json.loads(sys.stdin.read())
out = []
for case in cases:
    raw = base64.b64decode(case["raw"])
    out.append(run_one(case["method"], raw))
sys.stdout.write(json.dumps(out))
"#,
            read_chunk = READ_CHUNK_FOR_FUZZ,
            limit = FUZZ_LIMIT,
        );
        let mut child = Command::new(interpreter)
            .arg("-c")
            .arg(&script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("cannot run {interpreter}: {e}"));
        child
            .stdin
            .take()
            .unwrap()
            .write_all(serde_json::to_string(&payload).unwrap().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "python oracle failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let raw_out = String::from_utf8(output.stdout).expect("utf8 stdout");
        let parsed: Vec<Vec<Value>> = serde_json::from_str(&raw_out).expect("json stdout");
        parsed
            .into_iter()
            .map(|entry| match entry[0].as_str().unwrap() {
                "ok" => {
                    use base64::Engine as _;
                    let status = entry[1].as_u64().unwrap() as u16;
                    let body = base64::engine::general_purpose::STANDARD
                        .decode(entry[2].as_str().unwrap())
                        .unwrap();
                    FuzzOutcome::Ok(status, body)
                }
                "too_large" => FuzzOutcome::TooLarge,
                "protocol_error" => FuzzOutcome::ProtocolError,
                other => panic!(
                    "python oracle produced an outcome this harness has no bucket for \
                     (findings F-R2-2..7 assume every failure here is an \
                     http.client.HTTPException, never a real OSError/ValueError, since \
                     the fake socket is an in-memory io.BytesIO): {other:?} / {entry:?}"
                ),
            })
            .collect()
    }

    // --------------------------------------------------------- generators

    fn random_status_line(rng: &mut Lcg) -> Vec<u8> {
        let version: &str = rng.choice(&[
            "HTTP/1.1",
            "HTTP/1.0",
            "HTTP/0.9",
            "HTTP/1.",
            "HTTP/2",
            "HTTP/2.0",
            "HTTP/",
            "http/1.1",
            "HTTP/1.100",
        ]);
        let status: String = if rng.one_in(4) {
            // PEP 515 underscore variant, e.g. "2_00".
            let digits: Vec<char> = format!("{}", 100 + rng.below(800)).chars().collect();
            let mut s = String::new();
            for (i, c) in digits.iter().enumerate() {
                s.push(*c);
                if i == 0 && digits.len() > 1 && rng.one_in(2) {
                    s.push('_');
                }
            }
            s
        } else if rng.one_in(6) {
            // Out of range / malformed.
            rng.choice(&["12", "1000", "-5", "abc", "", "99999999999999999999"])
                .to_string()
        } else {
            format!("{}", 100 + rng.below(800))
        };
        let sep: &str = rng.choice(&[" ", "\t", "  "]);
        let mut line = format!("{version}{sep}{status}{sep}OK\r\n").into_bytes();
        if rng.one_in(20) {
            // LF-only status line terminator.
            line = format!("{version}{sep}{status}{sep}OK\n").into_bytes();
        }
        line
    }

    fn random_header_name(rng: &mut Lcg) -> String {
        rng.choice(&[
            "Content-Length",
            "Transfer-Encoding",
            "Content-Type",
            "X-Custom",
            "ETag",
            "Cache-Control",
        ])
        .to_string()
    }

    fn random_header_value(rng: &mut Lcg) -> String {
        if rng.one_in(50) {
            // Oversized value, sometimes past HTTP_MAX_LINE.
            let n = if rng.one_in(2) {
                HTTP_MAX_LINE + 1 + rng.below(200)
            } else {
                rng.below(200)
            };
            "a".repeat(n)
        } else {
            let words: &[&str] = &[
                "chunked",
                "identity",
                "text/plain",
                "close",
                "keep-alive",
                "",
            ];
            rng.choice(words).to_string()
        }
    }

    /// Picks one of `candidates` by index (owned variant of `Lcg::choice`, for
    /// building a `Vec<String>` inline without fighting borrow lifetimes).
    fn pick_owned<T: Clone>(rng: &mut Lcg, candidates: &[T]) -> T {
        candidates[rng.below(candidates.len())].clone()
    }

    fn random_content_length_value(rng: &mut Lcg, actual_body_len: usize) -> String {
        let underscored = {
            let mut s = actual_body_len.to_string();
            if s.len() > 1 {
                s.insert(1, '_');
            }
            s
        };
        let candidates = [
            actual_body_len.to_string(),
            format!("{}", actual_body_len + 1 + rng.below(50)), // bigger than sent (F-R2-3c)
            underscored,                                        // underscore (F-R2-5)
            "-1".to_string(),
            "not-a-number".to_string(),
            "".to_string(),
        ];
        pick_owned(rng, &candidates)
    }

    fn random_chunk_size_text(rng: &mut Lcg, actual: usize) -> String {
        let hex = format!("{actual:x}");
        let underscored = {
            let mut s = hex.clone();
            if s.len() > 1 {
                s.insert(1, '_');
            }
            s
        };
        let mut candidates = vec![hex.clone(), "zz".to_string(), format!("{hex};ext=1")];
        if actual > 0 {
            candidates.push(underscored);
            candidates.push(format!("0x{hex}"));
            candidates.push(format!("0X{hex}"));
        }
        pick_owned(rng, &candidates)
    }

    fn random_body_bytes(rng: &mut Lcg) -> Vec<u8> {
        let n = rng.below(64);
        (0..n).map(|_| (rng.next_u64() % 256) as u8).collect()
    }

    /// Builds one full raw response: a status line, a random header block
    /// (possibly with a `Content-Length` or `Transfer-Encoding: chunked`
    /// framing, possibly with too many headers or an oversized line),
    /// and a body framed accordingly -- then, sometimes, truncates the
    /// whole thing at a random byte offset (simulating an early-closing
    /// connection, findings F-R2-3/F-R2-4).
    fn random_response(rng: &mut Lcg) -> (&'static str, Vec<u8>) {
        let method: &str = if rng.one_in(8) { "HEAD" } else { "GET" };
        let mut out = random_status_line(rng);

        let use_chunked = rng.one_in(3);
        let use_too_many_headers = rng.one_in(30);
        let header_count = if use_too_many_headers {
            HTTP_MAX_HEADERS + rng.below(20)
        } else {
            rng.below(6)
        };
        let body = random_body_bytes(rng);

        let mut wrote_framing_header = false;
        for _ in 0..header_count {
            let name = random_header_name(rng);
            let value = if name == "Content-Length" && !use_chunked && !wrote_framing_header {
                wrote_framing_header = true;
                random_content_length_value(rng, body.len())
            } else if name == "Transfer-Encoding" && use_chunked && !wrote_framing_header {
                wrote_framing_header = true;
                if rng.one_in(10) {
                    "chunked ".to_string() // trailing space: must NOT be treated as chunked
                } else {
                    "chunked".to_string()
                }
            } else {
                random_header_value(rng)
            };
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        if !wrote_framing_header && use_chunked {
            out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        } else if !wrote_framing_header && !use_chunked && rng.one_in(2) {
            out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        }

        let header_terminator: &[u8] = if rng.one_in(15) { b"" } else { b"\r\n" };
        out.extend_from_slice(header_terminator);

        if use_chunked && (wrote_framing_header || header_terminator == b"\r\n") {
            // Body framed as one or two chunks, with a randomized chunk-size
            // encoding and terminator (F-R2-4, F-R2-5).
            let mid = if body.len() > 1 && rng.one_in(2) {
                1 + rng.below(body.len() - 1)
            } else {
                body.len()
            };
            for piece in [&body[..mid], &body[mid..]] {
                if piece.is_empty() {
                    continue;
                }
                out.extend_from_slice(random_chunk_size_text(rng, piece.len()).as_bytes());
                out.extend_from_slice(b"\r\n");
                out.extend_from_slice(piece);
                if rng.one_in(10) {
                    out.extend_from_slice(b"\n"); // LF-only terminator (F-R2-4)
                } else {
                    out.extend_from_slice(b"\r\n");
                }
            }
            out.extend_from_slice(random_chunk_size_text(rng, 0).as_bytes());
            out.extend_from_slice(b"\r\n");
            if !rng.one_in(20) {
                out.extend_from_slice(b"\r\n"); // final trailer-block terminator
            }
            // else: leave it EOF-terminated (F-R2-3d).
        } else if !use_chunked {
            out.extend_from_slice(&body);
        }

        if rng.one_in(8) {
            // Truncate the whole response at a random point (including
            // possibly mid-header-block, mid-status-line, or mid-body).
            let cut = rng.below(out.len().max(1));
            out.truncate(cut);
        }

        (method, out)
    }

    #[test]
    fn read_status_and_headers_body_mode_read_body_match_http_client() {
        let interpreter =
            std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".to_string());
        let mut rng = Lcg::new(0xC0FF_EE12_3456_789A);
        let case_count = 4000usize;
        let mut cases: Vec<(&'static str, Vec<u8>)> = Vec::with_capacity(case_count);
        for _ in 0..case_count {
            cases.push(random_response(&mut rng));
        }

        // No panic: computing every Rust outcome up front is itself part of
        // the assertion (a panic here fails the test with a backtrace
        // pointing at the offending case's index).
        let rust_outcomes: Vec<FuzzOutcome> = cases
            .iter()
            .map(|(method, raw)| rust_outcome(method, raw))
            .collect();

        // One Python subprocess for the whole batch (thousands of separate
        // `python3.12 -c` invocations would dominate the test's runtime).
        let python_outcomes = python_outcome(&interpreter, &cases);
        assert_eq!(python_outcomes.len(), cases.len());

        let mut mismatches = Vec::new();
        for (i, ((method, raw), (rust, python))) in cases
            .iter()
            .zip(rust_outcomes.iter().zip(python_outcomes.iter()))
            .enumerate()
        {
            let same_class = match (rust, python) {
                (FuzzOutcome::Ok(rs, rb), FuzzOutcome::Ok(ps, pb)) => rs == ps && rb == pb,
                (FuzzOutcome::ProtocolError, FuzzOutcome::ProtocolError) => true,
                (FuzzOutcome::TooLarge, FuzzOutcome::TooLarge) => true,
                _ => false,
            };
            if !same_class {
                mismatches.push(format!(
                    "case {i} (method={method:?}, raw={raw:?}): rust={rust:?} python={python:?}"
                ));
            }
        }
        assert!(
            mismatches.is_empty(),
            "{} / {} cases diverged from python3.12 http.client:\n{}",
            mismatches.len(),
            cases.len(),
            mismatches.join("\n")
        );
        eprintln!(
            "read_status_and_headers/body_mode/read_body fuzz: {} cases, 0 divergences, 0 panics",
            cases.len()
        );
    }
}
