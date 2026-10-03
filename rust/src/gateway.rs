//! Port of `zeropw/gateway.py`: HTTP authentication relay, the only place an
//! upstream HTTP credential is used.
//!
//! See `zeropw/gateway.py`'s module docstring for the security scope and
//! documented limitations (docs/security-design.md §2, §4, §5, §6); this
//! port reproduces the same behaviour with blocking `std` I/O and threads
//! (no async runtime) and OpenSSL for the gateway TLS path, matching
//! Python's `ssl` provider and verification policy.
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
    pub status: crate::pyint::PyInt,
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
    /// `RelayResult.json()`: `json.loads(self.body.decode("utf-8"))`,
    /// raising a catchable `UnicodeDecodeError`/`json.JSONDecodeError` for a
    /// non-UTF-8 or non-JSON body.
    ///
    /// **Finding X-19.** `body` is upstream socket data -- untrusted input
    /// PORTING.md §4 forbids panicking on -- so a malformed body returns
    /// `None` here instead of the `.expect()`-panic this used to reach for
    /// both failure modes. Only this crate's own tests call this method
    /// within this half's scope (its real callers, `tools.request` and
    /// friends, are second-half), so nothing in this half's production path
    /// could trigger the panic today -- but §4 is a rule about what the
    /// method itself may do, not about which callers currently exist.
    pub fn json(&self) -> Option<Value> {
        let text = std::str::from_utf8(&self.body).ok()?;
        pyjson::loads(text).ok()
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
        status: status.into(),
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

/// `urllib.parse.unquote(s)`, via [`crate::pystr::unquote`] (PORTING.md
/// §3b's one canonical home for CPython's `unquote` run-splitting
/// algorithm -- see that function's doc comment for the full behaviour,
/// including why this module's OLD implementation here -- a simpler
/// whole-string byte-buffer merge, finding F-R2-1 -- stayed byte-identical
/// to it across `normalize_path_inner`'s own two-pass call site specifically,
/// even though the two algorithms are not generally equivalent).
///
/// Promoted to the canonical helper (equivalence review round 8, the X-7
/// fixer's handover): `fake_upstream.rs`'s `unquote_plus` had reintroduced
/// this exact algorithm as a byte-identical local copy (finding X-7) after
/// this function's own finding F-R2-1 fix, the recurring §3b duplication
/// class. No behaviour change at this call site: confirmed both by the
/// existing 6,000-case `python3.12`-oracle fuzz test
/// `normalize_path_percent_decoding_never_panics_and_matches_python`
/// (`rust/tests/gateway.rs`), which specifically includes double-percent-
/// encoded sequences chaining across both decode passes, and by the
/// dedicated old-vs-new differential test
/// `percent_decode_lossy_old_implementation_matches_canonical_unquote_over_the_double_decode_pass_corpus`
/// below, which keeps the prior whole-buffer implementation around
/// test-only for a direct byte-for-byte comparison.
fn percent_decode_lossy(s: &str) -> String {
    crate::pystr::unquote(s)
}

#[cfg(test)]
mod percent_decode_lossy_canonicalization_tests {
    /// Test-only copy of `percent_decode_lossy`'s PRE-promotion implementation
    /// (equivalence review round 8, finding X-10's sibling consolidation): a
    /// simpler whole-string byte-buffer merge, decoding `%XX` over the raw
    /// UTF-8 bytes of `s` in one pass and lossily UTF-8-decoding the result
    /// once at the end -- kept here, deliberately not deleted, purely so this
    /// module's differential test below has something concrete to compare
    /// the new canonical `crate::pystr::unquote` against, rather than relying
    /// on the promotion's own reasoning alone.
    fn old_percent_decode_lossy(s: &str) -> String {
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

    /// `normalize_path_inner`'s own two-pass decode loop, run with a given
    /// single-pass decoder, mirroring exactly how `normalize_path_inner`
    /// itself calls `percent_decode_lossy` twice in `for _ in 0..2 { decoded
    /// = percent_decode_lossy(&decoded); }`.
    fn two_pass(s: &str, decode_once: impl Fn(&str) -> String) -> [String; 2] {
        let pass1 = decode_once(s);
        let pass2 = decode_once(&pass1);
        [pass1, pass2]
    }

    /// The specific risk the promotion's own doc comment reasons through but
    /// does not merely assert: a non-ASCII character PRODUCED by the first
    /// decode pass sitting immediately next to a `%XX` escape that only gets
    /// decoded on the SECOND pass (the classic double-encoding-evasion
    /// shape `normalize_path`'s two-pass loop exists to catch). The old
    /// whole-buffer merge and the new canonical run-splitting algorithm
    /// implement genuinely different algorithms -- this test is the actual
    /// proof they agree at this call site, not a restatement of the
    /// reasoning.
    #[test]
    fn percent_decode_lossy_old_implementation_matches_canonical_unquote_over_the_double_decode_pass_corpus()
     {
        let cases = [
            // Non-ASCII char (from a single-pass escape) immediately
            // followed by a fresh escape that only resolves on pass 2.
            "%E4%B8%AD%2541",
            "%2541%E4%B8%AD",
            // A dangling/incomplete multi-byte escape (produces U+FFFD on
            // pass 1) immediately next to a pass-2-only escape.
            "%E4%2541",
            "%2541%E4",
            "%E4%80%2541",
            "%2541%E4%80",
            // Two adjacent multi-byte codepoints, one resolved each pass.
            "%E4%B8%AD%25E4%25B8%25AD",
            // A 4-byte codepoint (U+1F600) split across the pass boundary.
            "%F0%9F%98%80%2541",
            "%2541%F0%9F%98%80",
            // Malformed triplets adjacent to real multi-byte escapes.
            "%zz%E4%B8%AD%2541",
            "%E4%B8%AD%25zz",
            // Plain ASCII and the empty string, as a sanity baseline.
            "hello%2Bworld",
            "",
            // Literal '%' characters (from a decoded %2525) next to a
            // multi-byte escape on either side.
            "%2525%E4%B8%AD",
            "%E4%B8%AD%2525",
        ];
        for case in cases {
            let old = two_pass(case, old_percent_decode_lossy);
            let new = two_pass(case, crate::pystr::unquote);
            assert_eq!(
                old, new,
                "old vs. new percent-decode diverged for {case:?} (pass1={:?}, pass2 old={:?} new={:?})",
                old[0], old[1], new[1]
            );
        }
    }
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
        // Finding X-1: `auth.basic_username` only ever holds a faithful
        // string OR (per `HttpAuth::from_value`/`basic_username_decision`,
        // `policy.rs`) a colon-free placeholder standing in for a truthy
        // list/dict container that Python's `":" in self.basic_username`
        // accepted without raising. Python's own `_auth_header`, given that
        // same container, never reaches this branch's `":" in ...` check
        // successfully at all: `auth.basic_username.encode("utf-8")` raises
        // an uncaught `AttributeError: 'list' object has no attribute
        // 'encode'` (confirmed against real `python3.12`,
        // `HttpAuth(mode="basic", basic_username=["curl"])` constructs
        // fine, then `_auth_header` raises), which nothing up to `relay`
        // catches (`except _Invalid` does not match `AttributeError`), so NO
        // upstream request is made and no credential leaves the process.
        // Rendering the placeholder here instead would relay
        // `"\u{1}:<the real secret>"` on the wire -- spending the grant use
        // and leaking the credential where Python sends nothing. Fail
        // closed the same way PORTING.md §3.5 already treats an uncaught
        // built-in exception: the closest handled error this path already
        // uses for a rejected `basic_username`, `unsupported_auth_mode`.
        if auth.raw_basic_username.is_some() {
            return Err(Invalid("unsupported_auth_mode"));
        }
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
        // Finding X-2's sibling gap to X-1: `HttpAuth.value_prefix` has no
        // `__post_init__` check in Python for any mode, so
        // `HttpAuth::from_value` (`policy.rs`) now accepts a non-string
        // `value_prefix` verbatim via `raw_value_prefix`, keeping
        // `value_prefix` itself a colon/regex-safe placeholder. Python's
        // `_auth_header`, given that same real container, reaches
        // `_HEADER_VALUE_RE.match(prefix)` with `prefix` still the
        // container (`prefix = auth.value_prefix or ""` only substitutes
        // for a FALSY value) and raises an uncaught
        // `TypeError: expected string or bytes-like object` there
        // (confirmed against real `python3.12`) -- nothing up to `relay`
        // catches it, so no upstream request is made. Rendering the
        // placeholder's empty string here instead would silently relay the
        // credential with no prefix where Python sends nothing. Fail closed
        // with the same reason this branch already uses for a
        // prefix that fails the regex.
        if auth.raw_value_prefix.is_some() {
            return Err(Invalid("credential_header_unsafe"));
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
/// `https`, else `80`). Accepts both `scheme://[user@]host[:port][/...]`
/// and a scheme-relative `//[user@]host[:port][/...]` with no scheme at all
/// (`parts.scheme == ""`, still a `443`/`80` default the same way, since
/// `"" == "https"` is false) -- finding F-R3-6: the previous version
/// required a literal `"://"`, so a scheme-relative `public_url` skipped
/// the self-reference comparison in [`self_referential_target`] entirely,
/// failing that guard OPEN.
///
/// `None` is returned exactly where real `urlsplit(url)` raises `ValueError`
/// (swallowed by [`self_referential_target`]'s own `except ValueError: pass`
/// equivalent, which then skips the public-URL comparison) -- finding
/// F-R4-1 corrected the doc comment here, which previously and wrongly
/// claimed `None` was reserved for "no authority at all, or a syntactically
/// bad port": a *bracketed* host with a colon but an empty port after it
/// (`[::1]:`) is NOT an error (`urlsplit` treats the empty port as
/// "unspecified", exactly like the unbracketed branch below already does)
/// and must fall back to `default_port` so the comparison still runs; an
/// invalid bracketed authority (data before `[`, data between `]` and the
/// port delimiter, or a bracketed host that isn't a valid IPv6/IPvFuture
/// literal) genuinely does raise `ValueError` in `urlsplit` itself -- via
/// `_check_bracketed_netloc`/`_check_bracketed_host`, which run eagerly
/// during `urlsplit()`, before `.hostname`/`.port` are ever touched -- and
/// must return `None` here. The returned host is lower-cased (and, for a
/// bracketed literal, bracket-stripped), matching `SplitResult.hostname`'s
/// own documented lower-casing (finding F-4: a mixed-case `public_url` must
/// still trigger the self-referential-target check).
fn parse_authority(url: &str) -> Option<(String, i64)> {
    let (scheme, rest) = match url.strip_prefix("//") {
        Some(rest) => ("", rest),
        None => url.split_once("://")?,
    };
    let default_port: i64 = if scheme.eq_ignore_ascii_case("https") {
        443
    } else {
        80
    };
    // `parts.port or default`: Python's `or` treats `0` as falsy, so an
    // explicit `:0` in the URL is treated the same as no port at all
    // (finding F-R3-6) -- applied to whichever branch below produces a
    // parsed, in-range port.
    let use_default_if_zero = |port: i64| if port == 0 { default_port } else { port };
    let netloc = rest.split(['/', '?', '#']).next().unwrap_or(rest);

    // `urlsplit`'s own eager bracket-balance check, over the *whole*
    // netloc (i.e. including any `user@` prefix): `('[' in netloc) !=
    // (']' in netloc)` raises "Invalid IPv6 URL" immediately, before any
    // further splitting.
    let has_open = netloc.contains('[');
    let has_close = netloc.contains(']');
    if has_open != has_close {
        return None;
    }

    let hostport = netloc.rsplit('@').next().unwrap_or(netloc);

    if has_open {
        // `_check_bracketed_netloc(netloc)`, mirrored here on `hostport`
        // (`hostname_and_port = netloc.rpartition('@')[2]` in Python, the
        // same value as `hostport`): the bracket must be the very first
        // character (no data before it), and whatever follows the first
        // `]` must be empty or start with `:` (no data between the bracket
        // and the port delimiter).
        let (before_bracket, after_open) = hostport.split_once('[')?;
        if !before_bracket.is_empty() {
            return None;
        }
        let (host, after_close) = after_open.split_once(']')?;
        if !after_close.is_empty() && !after_close.starts_with(':') {
            return None;
        }
        // `_check_bracketed_host(hostname)`: an IPvFuture literal
        // (`v[hex]+\.[anything]+`), or a real IPv6 address -- an IPv4
        // address in brackets is explicitly rejected.
        if let Some(vfuture) = host.strip_prefix('v') {
            let hex_len = vfuture
                .bytes()
                .take_while(|b| b.is_ascii_hexdigit())
                .count();
            let valid =
                hex_len > 0 && vfuture[hex_len..].starts_with('.') && vfuture.len() > hex_len + 1;
            if !valid {
                return None;
            }
        } else {
            let ip: IpAddr = host.parse().ok()?;
            if ip.is_ipv4() {
                return None;
            }
        }
        // `_hostinfo`'s bracketed branch: `port = bracketed.partition(']')`
        // gives the text after `]`, then `port.partition(':')` keeps only
        // what follows a leading `:` (empty otherwise); an empty result
        // means "unspecified", falling back to `default_port` exactly like
        // the unbracketed branch below (finding F-R4-1: the previous
        // version treated this case as a hard error instead).
        let port_str = after_close.strip_prefix(':').unwrap_or("");
        return if port_str.is_empty() {
            Some((host.to_lowercase(), default_port))
        } else if port_str.bytes().all(|b| b.is_ascii_digit()) {
            let port: i64 = port_str.parse().ok()?;
            if (0..=65535).contains(&port) {
                Some((host.to_lowercase(), use_default_if_zero(port)))
            } else {
                None
            }
        } else {
            None
        };
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
                    Some((host.to_lowercase(), use_default_if_zero(port)))
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
    // Python reads `ctx.config.extra["public_url"]`, where `set_public_url`
    // stores it. A shared Rust `Context` cannot mutate `config`, so
    // `tools::set_public_url` (called once the server is bound) stores into
    // `ctx.public_url`, which wins; `config.extra["public_url"]` (seeded into
    // it at construction, or set on a not-yet-shared context) is the fallback.
    let public_url = ctx
        .public_url
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .or_else(|| match ctx.config.extra.get("public_url") {
            Some(Value::String(url)) => Some(url.clone()),
            _ => None,
        });
    if let Some(public_url) = public_url
        && !public_url.is_empty()
        && let Some((url_host, public_port)) = parse_authority(&public_url)
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

/// `float(v)` as applied to a value already parsed out of the ledger's JSON
/// document (finding F-R3-5, extended by F-R4-2): a JSON number converts
/// directly; a JSON bool converts the way `float(True) == 1.0` /
/// `float(False) == 0.0` does (confirmed against live `python3.12` --
/// Python `bool` is an `int` subclass, so `float()` never raises for one,
/// unlike the earlier version of this doc comment claimed); a JSON string
/// is parsed with the canonical [`crate::pystr::float_from_str`] (CPython's
/// `float(str)` grammar, PORTING.md §3b). Anything else
/// (`null`, an array, an object) has no non-panicking `float()` equivalent
/// and is treated as unconvertible; a JSON integer too large for a double
/// (`as_f64` rounds it to infinity and refuses it) is `float(10**400)`'s
/// `OverflowError`. Returns `None` exactly where Python's `float(v)` would
/// raise `TypeError`/`ValueError`/`OverflowError`.
fn python_float(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Value::String(s) => crate::pystr::float_from_str(s),
        _ => None,
    }
}

/// The built-in exception `float(v)` raises where [`python_float`] returns
/// `None`: `ValueError` for an unparsable `str`, `OverflowError` for a JSON
/// integer too large for a double (`float(10**400)`), `TypeError` for
/// `None`/`list`/`dict`.
fn float_error_class(v: &Value) -> &'static str {
    match v {
        Value::String(_) => "ValueError",
        Value::Number(_) => "OverflowError",
        _ => "TypeError",
    }
}

/// `float(v)` for a stored ledger value, raising the escaping built-in.
fn ledger_float(v: &Value) -> Result<f64, Error> {
    python_float(v).ok_or_else(|| escaped_builtin(float_error_class(v)))
}

/// `int(v)` as applied to a stored `response["status"]` value (finding
/// F-R3-5, `RequestLedger.replay`): a JSON integer converts directly; a
/// JSON float truncates towards zero (`int(200.9) == 200`, no error, unlike
/// `float()`); a JSON bool is `0`/`1` (Python bools are an `int` subclass);
/// a JSON string is parsed with the canonical
/// [`crate::pystr::int_from_str_checked`] (PORTING.md §3b) -- this crate's
/// own writer always stores a plain integer, so a string here only occurs
/// under deliberate corruption, but it is still exactly `int(str)` when it
/// does. `null`/array/object have no non-panicking `int()` equivalent and
/// are treated as unconvertible.
///
/// **Finding X-5.** Python's `int(v)` never raises for any of these shapes
/// -- CPython's arbitrary-precision `int` holds any magnitude, so
/// `int(1e300)` is a real (if absurd) 301-digit integer, `relayed=True`,
/// same as `int(65736)` or `int(" 65736_0 ")`. Measured against real
/// `python3.12`: `int(65736) == 65736`, `int(65536) == 65536`,
/// `int(1000000) == 1000000`, `int(1e300)` is exact to the last digit,
/// `int("18446744073709551816") == 18446744073709551816`,
/// `int(" 65736_0 ") == 657360` -- none of these raise.
///
/// [`RelayResult::status`] uses the crate's unbounded [`crate::pyint::PyInt`]
/// representation. This preserves the exact result through the direct API,
/// audit JSON, tools JSON, and the local server's decimal status line; fresh
/// upstream parsing remains bounded to the validated `u16` wire status used
/// by [`UpstreamResponse`].
fn python_int_status(v: &Value) -> Option<crate::pyint::PyInt> {
    crate::pyint::PyInt::coerce_from_json(v)
}

/// Python `str(x)` for a JSON value used as a stored header component or
/// replay reason. Strings are already Python strings and remain unquoted;
/// every other JSON shape uses the canonical recursive Python repr helper
/// (`str` and `repr` agree for these scalar/container types).
fn python_str_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => crate::pystr::repr_value(other),
    }
}

/// True for exactly the JSON values Python's own truthiness treats as
/// falsy (`None`, `False`, a numeric `0`, `""`, and an empty array/object) --
/// used only to reproduce `response.get("headers") or []`'s short-circuit
/// (finding F-R3-5).
fn is_json_falsy(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_f64() == Some(0.0),
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
    }
}

/// `[(str(k), str(v)) for k, v in response.get("headers") or []]` (finding
/// F-R3-5, `RequestLedger.replay`, corrected by F-R4-4(c)): a missing key
/// or any JSON-falsy stored value ([`is_json_falsy`]) short-circuits to no
/// headers, exactly like Python's `or []`. Each *element* of a non-empty
/// iterable is then unpacked the way a `for k, v in ...` loop unpacks any
/// 2-item sequence -- not only a 2-element JSON array (`["a", "b"]`), but
/// also a JSON string of exactly two Unicode characters (`"ab"` unpacks to
/// `k="a", v="b"`, confirmed directly against live `python3.12`: `for k, v
/// in ["ab"]` succeeds). A wrong-length array/string, or an element of any
/// other JSON type, is exactly where Python's own unpacking raises
/// (`ValueError`/`TypeError`), an exception that escapes `relay`
/// ([`escaped_builtin`]).
fn python_headers_from_json(v: Option<&Value>) -> Result<Headers, Error> {
    // A non-iterable (`TypeError`) or wrong-length (`ValueError`) element
    // is a built-in exception escaping `replay` and `relay`.
    fn bad_shape() -> Error {
        escaped_builtin("TypeError")
    }
    let Some(value) = v else {
        return Ok(Headers::new());
    };
    if is_json_falsy(value) {
        return Ok(Headers::new());
    }
    let iter = |value: &Value| -> Option<Vec<Value>> {
        match value {
            Value::Array(items) => Some(items.clone()),
            Value::Object(map) => Some(map.keys().cloned().map(Value::String).collect()),
            Value::String(text) => Some(
                text.chars()
                    .map(|character| Value::String(character.to_string()))
                    .collect(),
            ),
            _ => None,
        }
    };
    let mut out = Headers::new();
    for item in iter(value).ok_or_else(bad_shape)? {
        let pair = iter(&item).ok_or_else(bad_shape)?;
        if pair.len() != 2 {
            return Err(escaped_builtin("ValueError"));
        }
        out.push((python_str_of(&pair[0]), python_str_of(&pair[1])));
    }
    Ok(out)
}

#[cfg(test)]
mod stored_header_oracle_tests {
    use super::*;

    #[test]
    fn stored_header_comprehension_matches_python() {
        let cases = [
            "null",
            "false",
            "0",
            "\"\"",
            "[]",
            "{}",
            r#"[["X",184467440737095516160000000000000000000]]"#,
            r#"[[[1,2],{"b":2,"a":1}]]"#,
            r#"[{"first":0,"second":0}]"#,
            r#"{"ab":0,"😀x":1}"#,
            r#""ab""#,
            r#"["ab","😀x"]"#,
            r#"[["only-one"],[1,2,3]]"#,
            "true",
        ];
        let script = format!(
            r#"
import json
out=[]
for value in json.loads({cases:?}):
 try:
  out.append([True, [(str(k), str(v)) for k,v in (json.loads(value) or [])]])
 except Exception as exc:
  out.append([False, type(exc).__name__])
print(json.dumps(out, ensure_ascii=False))
"#,
            cases = serde_json::to_string(&cases).unwrap(),
        );
        let expected: Vec<Value> =
            serde_json::from_str(crate::oracle::python(&script).trim()).unwrap();
        for (source, expected) in cases.iter().zip(expected) {
            let value = pyjson::loads(source).unwrap();
            let actual = python_headers_from_json(Some(&value));
            assert_eq!(actual.is_ok(), expected[0] == true, "{source}");
            if let Ok(actual) = actual {
                let expected: Headers = expected[1]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|pair| {
                        (
                            pair[0].as_str().unwrap().to_owned(),
                            pair[1].as_str().unwrap().to_owned(),
                        )
                    })
                    .collect();
                assert_eq!(actual, expected, "{source}");
            }
        }
    }
}

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
    ///
    /// Finding F-R4-2: Python's `float(entries[request_id].get("updated_at",
    /// 0))` runs for *every* entry of *every* caller on *every* write (and
    /// again in the `LEDGER_MAX_ENTRIES` eviction sort below); a
    /// wrong-typed `updated_at` anywhere in the document raises an uncaught
    /// `ValueError`/`TypeError` out of `_save` -- out of `claim`/`_update`/
    /// `release` -- refusing the request before the upstream is ever
    /// contacted (PORTING.md §3.5, and, for a *parsable* string like
    /// `"1700000000"` which Python's `float()` happily converts, this is a
    /// case where Python *returns a value*, outside §3.5's own carve-out --
    /// so the correct behaviour is "parse it like `claim` already does via
    /// [`python_float`]", not "treat it as corrupt"). The previous version
    /// read `updated_at` with a plain `.as_f64()` and silently substituted
    /// `0.0` for anything else (including a parsable string), which made
    /// `now - 0.0 > LEDGER_TTL_SECONDS` true and deleted a live entry
    /// belonging to a *different* request id than the one being saved.
    /// Likewise, Python's `for request_id in list(entries)` /
    /// `entries[request_id]` raises `TypeError`/`AttributeError` for a
    /// non-dict caller value; the previous version silently `continue`d
    /// past it instead of failing closed.
    ///
    /// Every failure above is a CPython built-in exception escaping `_save`
    /// (and `relay`), so it is an [`escaped_builtin`], never a `StateError`.
    /// Measured on CPython 3.12.14: a caller value that is an EMPTY `str` or
    /// `list` iterates zero times and is then deleted by `if not entries:
    /// del doc[caller]` (a value is returned, the document is rewritten);
    /// every other non-dict caller value raises (`list(None)`/`list(5)` ->
    /// `TypeError`, `"ab"["a"]` -> `TypeError`, a non-empty list always
    /// reaches a `TypeError`/`AttributeError`/`IndexError` on one of its
    /// own elements); a non-dict entry raises `AttributeError` from
    /// `.get("updated_at", 0)`.
    fn save(&self, mut doc: Map<String, Value>) -> Result<(), Error> {
        let now = (self.ctx.clock)();
        let callers: Vec<String> = doc.keys().cloned().collect();
        for caller in callers {
            let Some(entries_value) = doc.get_mut(&caller) else {
                continue;
            };
            let entries = match entries_value {
                Value::Object(entries) => entries,
                Value::String(text) if text.is_empty() => {
                    doc.remove(&caller);
                    continue;
                }
                Value::Array(items) if items.is_empty() => {
                    doc.remove(&caller);
                    continue;
                }
                _ => return Err(escaped_builtin("TypeError")),
            };
            let ids: Vec<String> = entries.keys().cloned().collect();
            for id in ids {
                let Some(Value::Object(entry)) = entries.get(&id) else {
                    return Err(escaped_builtin("AttributeError"));
                };
                let updated_at = match entry.get("updated_at") {
                    None => 0.0,
                    Some(raw) => ledger_float(raw)?,
                };
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
                // Every surviving caller value is a dict whose entries are
                // dicts with a float-convertible `updated_at` (the sweep
                // above raised otherwise); kept fail-closed regardless.
                let Some(entries) = entries.as_object() else {
                    return Err(escaped_builtin("AttributeError"));
                };
                for (rid, entry) in entries {
                    if entry.get("state").and_then(Value::as_str) == Some("completed") {
                        let updated_at = match entry.get("updated_at") {
                            None => 0.0,
                            Some(raw) => ledger_float(raw)?,
                        };
                        completed.push((updated_at, caller.clone(), rid.clone()));
                    }
                }
            }
            // `sorted()` on `(float, str, str)` tuples never raises in
            // Python even when a `float("nan")`-derived value is present
            // (comparisons against NaN are simply always `False`, not an
            // error); mirror that here with a NaN-safe tuple comparator
            // instead of `partial_cmp(..).unwrap()`, which would panic on
            // agent-reachable corrupted input (PORTING.md §4).
            completed.sort_by(|a, b| {
                a.0.partial_cmp(&b.0)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.1.cmp(&b.1))
                    .then_with(|| a.2.cmp(&b.2))
            });
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
        // `doc.get(caller, {}).get(request_id)`: Python's `dict.get`
        // default only substitutes for a MISSING key, not a wrong-typed
        // *value* -- so a caller entry that exists but isn't itself a dict
        // (e.g. a corrupt ledger's `{"agent-1": "oops"}`) makes that
        // `.get(request_id)` call raise `AttributeError` (`str` has no
        // `.get`), an uncaught built-in exception, fail-closed per
        // PORTING.md §3.5 (finding F-R3-5). The previous version silently
        // treated this as "no entry", which not only masked the corruption
        // but -- because `doc.entry(caller).or_insert_with(..)` below finds
        // the caller key already occupied by that non-object value and
        // therefore never replaces it -- went on to relay the request AND
        // silently drop the claim, permanently disabling idempotency for
        // that caller while reporting success.
        //
        // These are built-in exceptions escaping `relay`
        // ([`escaped_builtin`]), not `StateError`s. A JSON `null` entry is
        // `entry is None` in Python -- the claim simply overwrites it.
        let entry = match doc.get(caller) {
            None => None,
            Some(Value::Object(m)) => m.get(request_id).filter(|e| !e.is_null()).cloned(),
            Some(_) => return Err(escaped_builtin("AttributeError")),
        };
        if let Some(entry) = &entry {
            // Likewise, `entry.get("updated_at", 0)` raises `AttributeError`
            // for a wrong-typed *entry* (`{"agent-1": {"rid-1": "oops"}}`,
            // finding F-R3-5) -- and `float(entry.get("updated_at", 0))`
            // raises `ValueError`/`TypeError`/`OverflowError` for an
            // `updated_at` that isn't float-convertible.
            let Value::Object(entry_obj) = entry else {
                return Err(escaped_builtin("AttributeError"));
            };
            let updated_at = match entry_obj.get("updated_at") {
                None => 0.0,
                Some(v) => ledger_float(v)?,
            };
            if now - updated_at <= LEDGER_TTL_SECONDS {
                if entry_obj.get("digest").and_then(Value::as_str) != Some(digest) {
                    return Ok(("reused", None));
                }
                return match entry_obj.get("state").and_then(Value::as_str) {
                    Some("completed") => Ok(("replay", Some(entry.clone()))),
                    Some("uncertain") => Ok(("uncertain", None)),
                    _ => Ok(("in_flight", None)),
                };
            }
        }
        let caller_entries = doc
            .entry(caller.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        let Value::Object(m) = caller_entries else {
            // Unreachable: a non-object caller value already raised above.
            // Kept fail-closed rather than `unreachable!()`.
            return Err(escaped_builtin("AttributeError"));
        };
        m.insert(
            request_id.to_string(),
            json!({
                "digest": digest, "state": "in_flight", "connection": connection_id,
                "created_at": now, "updated_at": now, "response": Value::Null,
            }),
        );
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
        // `entry = doc.get(caller, {}).get(request_id)`: a non-dict caller
        // value (even `null`) raises `AttributeError`; a missing or `null`
        // entry returns; `entry.update(changes)` on a non-dict entry raises
        // `AttributeError`.
        let entries = match doc.get_mut(caller) {
            None => return Ok(()),
            Some(Value::Object(entries)) => entries,
            Some(_) => return Err(escaped_builtin("AttributeError")),
        };
        let entry = match entries.get_mut(request_id) {
            None | Some(Value::Null) => return Ok(()),
            Some(Value::Object(entry)) => entry,
            Some(_) => return Err(escaped_builtin("AttributeError")),
        };
        apply(entry);
        entry.insert("updated_at".into(), json!(now));
        self.save(doc)
    }

    /// `RequestLedger.release` (finding F-1).
    pub fn release(&self, caller: &str, request_id: &str) -> Result<(), Error> {
        let _lock = self.ctx.state.lock()?;
        let mut doc = self.load()?;
        // `if request_id in doc.get(caller, {})`: a `str` caller value is a
        // substring test and a `list` a membership test -- either way a hit
        // then fails `del doc[caller][request_id]` with `TypeError`; a
        // number/bool/`null` value raises `TypeError` from `in` itself.
        match doc.get_mut(caller) {
            None => {}
            Some(Value::Object(entries)) => {
                if entries.remove(request_id).is_some() {
                    if entries.is_empty() {
                        doc.remove(caller);
                    }
                    self.save(doc)?;
                }
            }
            Some(Value::String(text)) => {
                if text.contains(request_id) {
                    return Err(escaped_builtin("TypeError"));
                }
            }
            Some(Value::Array(items)) => {
                if items.iter().any(|item| item.as_str() == Some(request_id)) {
                    return Err(escaped_builtin("TypeError"));
                }
            }
            Some(_) => return Err(escaped_builtin("TypeError")),
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
        stored.insert("status".into(), result.status.value());
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
    ///
    /// `status = int(response.get("status", 502))` and
    /// `headers = [(str(k), str(v)) for k, v in response.get("headers") or
    /// []]` both raise uncaught built-in exceptions for a wrong-typed
    /// stored `status`/`headers` (finding F-R3-5); they escape `relay`
    /// unchanged, so they are [`escaped_builtin`]s (finding X-5: `zeropw.server`
    /// answers them with its fixed `500 internal_error`, not a `StateError`).
    ///
    /// Finding F-R4-4 fixed four further truthiness/coercion divergences,
    /// none of which fall under §3.5's carve-out (Python *returns a value*
    /// in each): **(a)** `response = entry.get("response") or {}` uses
    /// Python truthiness, and a truthy *non-mapping* (`"oops"`, `[1, 2]`,
    /// `7`) makes the very next `response.get(...)` raise `AttributeError`
    /// -- fail closed for that shape, rather than the previous
    /// `unwrap_or(json!({}))`, which treated it as empty and produced a
    /// `502 replay_body_unavailable` instead of refusing outright.
    /// **(b)** `if not response.get("body_stored")` is Python truthiness,
    /// not an `== true` check -- any JSON-falsy value ([`is_json_falsy`])
    /// takes the stored-body-unavailable path, and any truthy value
    /// (including a non-bool like `"yes"`) takes the real-body path,
    /// exactly like the previous `.and_then(Value::as_bool) != Some(true)`
    /// did NOT (it treated every non-`true` JSON value, including a truthy
    /// string, as "not stored"). **(c)** `reason = response.get("reason")`
    /// keeps whatever is stored, coerced through [`python_str_of`] the way
    /// this crate's `Option<String>` field requires (Python's own field is
    /// duck-typed `Any`) -- `None`/missing stays [`Option::None`]
    /// (`RelayResult.relayed`'s `self.reason is None` check), any other
    /// JSON value becomes `Some(python_str_of(value))`, matching Python's
    /// identity-based `relayed` check exactly (confirmed against live
    /// `python3.12`: `reason=5` is present-but-non-`None`, so `relayed` is
    /// `False` and the caller's outcome is `"blocked"`, same as
    /// `Some("5")` here). **(d)** `body_b64` goes through the same
    /// truthiness (`response.get("body_b64") or ""`) before decoding.
    ///
    /// Finding F-R4-3: the stored body is decoded with the canonical
    /// [`crate::pybase64::b64decode`] (PORTING.md §3b) -- CPython's
    /// `base64.b64decode` is *lenient*, silently discarding any
    /// non-alphabet byte before decoding (`"YWJj\n"` -> `b"abc"`), not the
    /// `base64` crate's strict `STANDARD` engine this used before; a
    /// genuinely undecodable value raises (`binascii.Error`, an escaping
    /// built-in) instead of silently relaying a `200` with an emptied body.
    pub fn replay(entry: &Value) -> Result<RelayResult, Error> {
        let response: Map<String, Value> = match entry.get("response") {
            None => Map::new(),
            Some(value) if is_json_falsy(value) => Map::new(),
            Some(Value::Object(m)) => m.clone(),
            // `response.get(...)` on a truthy non-dict.
            Some(_) => return Err(escaped_builtin("AttributeError")),
        };
        let status = match response.get("status") {
            None => crate::pyint::PyInt::from(502i64),
            Some(v) => python_int_status(v).ok_or_else(|| {
                escaped_builtin(match v {
                    Value::String(_) => "ValueError",
                    Value::Number(_) => "OverflowError",
                    _ => "TypeError",
                })
            })?,
        };
        let mut headers: Headers = python_headers_from_json(response.get("headers"))?;
        let reason = match response.get("reason") {
            None | Some(Value::Null) => None,
            Some(v) => Some(python_str_of(v)),
        };
        let body_stored = response
            .get("body_stored")
            .map(|v| !is_json_falsy(v))
            .unwrap_or(false);
        if !body_stored {
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-type"));
            let payload = pyjson::dumps(
                &json!({"error": "ReplayBodyUnavailable", "reason": "replay_body_unavailable"}),
                DumpOptions::plain(),
            )
            .unwrap_or_default()
            .into_bytes();
            headers.push(("Content-Type".to_string(), "application/json".to_string()));
            headers.push(("X-ZeroPW-Replay".to_string(), "true".to_string()));
            return Ok(RelayResult {
                status,
                headers,
                body: payload,
                reason: Some("replay_body_unavailable".to_string()),
            });
        }
        let body = match response.get("body_b64") {
            None => Vec::new(),
            Some(value) if is_json_falsy(value) => Vec::new(),
            // `binascii.Error` (bad padding) or, for a truthy non-`str`,
            // `TypeError` -- both escape `relay`.
            Some(Value::String(s)) => {
                crate::pybase64::b64decode(s).map_err(|_| escaped_builtin("Error"))?
            }
            Some(_) => return Err(escaped_builtin("TypeError")),
        };
        headers.push(("X-ZeroPW-Replay".to_string(), "true".to_string()));
        Ok(RelayResult {
            status,
            headers,
            body,
            reason,
        })
    }
}

// --------------------------------------------------------------- upstream

/// Port of `gateway._UpstreamFailure`.
///
/// `escaped` is not part of Python's class: it carries a CPython built-in
/// exception (`ValueError`, `OverflowError`, `TypeError`) that Python raises
/// inside `_exchange`/`_open_connection` where none of `_exchange`'s
/// `except` clauses catch it. Such an exception is never an
/// `_UpstreamFailure` in Python; it escapes `_Relay.run` and `relay`
/// untouched, so [`Relay::try_run`] turns it into [`escaped_builtin`]
/// before any ledger or audit step `_UpstreamFailure` handling would take.
struct UpstreamFailure {
    reason: &'static str,
    result: &'static str,
    known_outcome: bool,
    upstream_status: Option<u16>,
    escaped: Option<&'static str>,
}

impl UpstreamFailure {
    fn denied(reason: &'static str) -> Self {
        UpstreamFailure {
            reason,
            result: "denied",
            known_outcome: false,
            upstream_status: None,
            escaped: None,
        }
    }
    fn error(reason: &'static str) -> Self {
        UpstreamFailure {
            reason,
            result: "error",
            known_outcome: false,
            upstream_status: None,
            escaped: None,
        }
    }
    fn blocked(reason: &'static str, status: u16) -> Self {
        UpstreamFailure {
            reason,
            result: "blocked",
            known_outcome: true,
            upstream_status: Some(status),
            escaped: None,
        }
    }
    /// A CPython built-in exception named `class` escapes `_exchange`
    /// uncaught (see the struct doc).
    fn escape(class: &'static str) -> Self {
        UpstreamFailure {
            reason: "internal_error",
            result: "error",
            known_outcome: false,
            upstream_status: None,
            escaped: Some(class),
        }
    }
}

/// A CPython built-in exception (`ValueError`, `OverflowError`,
/// `TypeError`, ...) that propagates out of `relay`/`relay_for_caller`
/// uncaught. Like `admin_cli`/`smtp`'s escaped built-ins it is an
/// [`ErrorClass::ZeroPW`] error whose `name` is the Python class name and
/// whose reason is `internal_error`; `server.rs` answers it with
/// `ZeroPWHandler._dispatch`'s final `except Exception` reply
/// (`500 {"error": "InternalError", "reason": "internal_error"}`), exactly
/// what CPython sends for the same escape, and `tools.request` propagates it
/// the same way `tools.py` does.
pub(crate) fn escaped_builtin(class: &'static str) -> Error {
    Error::subclass(ErrorClass::ZeroPW, class, "internal_error", "")
}

/// True for an [`escaped_builtin`] error: a ZeroPW-class error whose name is
/// not `ZeroPWError` itself. `zeropw/errors.py` defines no direct
/// `ZeroPWError` subclass besides the seven [`ErrorClass`] bases, so only a
/// built-in-exception stand-in can have this shape.
pub fn is_escaped_builtin(error: &Error) -> bool {
    error.class == ErrorClass::ZeroPW && error.name != ErrorClass::ZeroPW.class_name()
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

enum UpstreamStream {
    Plain(TcpStream),
    Tls(Box<openssl::ssl::SslStream<TcpStream>>),
}

impl UpstreamStream {
    fn raw(&self) -> &TcpStream {
        match self {
            UpstreamStream::Plain(s) => s,
            UpstreamStream::Tls(s) => s.get_ref(),
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

/// `_exchange`'s handshake mapping: `ssl.SSLError` (a TLS failure, or the
/// peer closing mid-handshake: `SSLEOFError`) is `upstream_tls_failed`, a
/// timeout is `upstream_timeout`, any other `OSError` (reset, broken pipe)
/// is `upstream_unreachable`.
fn classify_handshake_error(e: &std::io::Error) -> &'static str {
    match e.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => "upstream_timeout",
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof => {
            "upstream_tls_failed"
        }
        _ => "upstream_unreachable",
    }
}

/// Map OpenSSL's blocking handshake failures to the same public identities as
/// Python's eager `SSLContext.wrap_socket`.  Certificate/protocol failures and
/// an orderly EOF are SSL failures; socket timeouts and transport failures
/// retain the identities used by `_open_connection`.
fn classify_openssl_handshake_error(
    error: &openssl::ssl::HandshakeError<TcpStream>,
) -> &'static str {
    use openssl::ssl::{ErrorCode, HandshakeError};
    match error {
        HandshakeError::WouldBlock(_) => "upstream_timeout",
        HandshakeError::SetupFailure(_) => "upstream_tls_failed",
        HandshakeError::Failure(mid) => {
            let error = mid.error();
            if let Some(io) = error.io_error() {
                return classify_handshake_error(io);
            }
            match error.code() {
                ErrorCode::SSL | ErrorCode::ZERO_RETURN => "upstream_tls_failed",
                ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => "upstream_timeout",
                // OpenSSL reports a peer that closes without sending any TLS
                // record as SYSCALL with no underlying I/O error.  A real
                // reset retains its ConnectionReset `io_error` and returned
                // above as `upstream_unreachable`; the error-less form is
                // Python's `SSLEOFError` / `upstream_tls_failed` case.
                ErrorCode::SYSCALL => "upstream_tls_failed",
                _ => "upstream_unreachable",
            }
        }
    }
}

fn build_tls_connector(
    ca_file: Option<&str>,
) -> Result<openssl::ssl::SslConnector, UpstreamFailure> {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
    use openssl::x509::verify::X509VerifyFlags;

    // CPython 3.12's `_DEFAULT_CIPHERS` used by `create_default_context`.
    // TLS 1.3 ciphers are provider defaults on both paths and are not
    // controlled by this pre-1.3 cipher-list API.
    const PYTHON_DEFAULT_CIPHERS: &str = "@SECLEVEL=2:ECDH+AESGCM:ECDH+CHACHA20:\
        ECDH+AES:ECDH+CAMELLIA:DHE+AESGCM:DHE+CHACHA20:DHE+AES:\
        DHE+CAMELLIA:!aNULL:!eNULL:!MD5:!DSS";

    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .map_err(|_| UpstreamFailure::error("upstream_tls_failed"))?;
    builder.set_verify(SslVerifyMode::PEER);
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|_| UpstreamFailure::error("upstream_tls_failed"))?;
    builder
        .set_cipher_list(PYTHON_DEFAULT_CIPHERS)
        .map_err(|_| UpstreamFailure::error("upstream_tls_failed"))?;
    builder
        .verify_param_mut()
        .set_flags(X509VerifyFlags::TRUSTED_FIRST)
        .map_err(|_| UpstreamFailure::error("upstream_tls_failed"))?;
    // `ssl.create_default_context()` first loads OpenSSL's default trust
    // paths, then `load_verify_locations(cafile=...)` adds the connection's
    // anchors.  Use the same provider and operations instead of duplicating
    // X.509 purpose, hostname, algorithm and trust-store policy in Rust.
    builder
        .set_default_verify_paths()
        .map_err(|_| UpstreamFailure::error("upstream_tls_failed"))?;
    if let Some(path) = ca_file {
        builder
            .set_ca_file(path)
            .map_err(|_| UpstreamFailure::error("ca_file_unavailable"))?;
    }
    Ok(builder.build())
}

/// `socket.settimeout(timeout)` as `socket.create_connection` applies it
/// to `float(ctx.config.upstream_timeout)` (CPython 3.12
/// `socket_parse_timeout` -> `_PyTime_FromSecondsObject(...,
/// _PyTime_ROUND_TIMEOUT)`): NaN is `ValueError("Invalid value NaN (not a
/// number)")`; the value is scaled to nanoseconds and rounded away from
/// zero, and a result outside `[-2**63, 2**63)` is `OverflowError`; a
/// negative result is `ValueError("Timeout value out of range")`. Measured
/// against CPython 3.12.14 (`socket.create_connection` against a local
/// listener): `inf`/`-inf`/`9.3e9`/`1e30` -> `OverflowError`; `nan`,
/// `-1.0`, `-1e-300` -> `ValueError`; `-0.0`/`0.0` -> a non-blocking
/// connect (`BlockingIOError`, an `OSError`); `5e-324`/`1e-10` -> a 1ns
/// timeout; `2147483.648` -> accepted. `Err` names the escaping built-in.
fn python_socket_timeout(seconds: f64) -> Result<Duration, &'static str> {
    const TWO_POW_63: f64 = 9_223_372_036_854_775_808.0;
    if seconds.is_nan() {
        return Err("ValueError");
    }
    let scaled = seconds * 1e9;
    let rounded = if scaled >= 0.0 {
        scaled.ceil()
    } else {
        scaled.floor()
    };
    if !(-TWO_POW_63..TWO_POW_63).contains(&rounded) {
        return Err("OverflowError");
    }
    if rounded < 0.0 {
        return Err("ValueError");
    }
    // In range and non-negative: the cast is exact for this integral value.
    Ok(Duration::from_nanos(rounded as u64))
}

/// `_open_connection` + `conn.connect()`. Returns the connected stream and
/// the socket timeout it was opened with.
fn open_connection(
    connection: &Connection,
    timeout_seconds: f64,
    pinned_address: &str,
) -> Result<(UpstreamStream, Duration), UpstreamFailure> {
    let target = connection.http_target.as_ref().expect("http connection");
    // Python's `_open_connection` builds the `ssl.SSLContext` (including
    // `load_verify_locations(cafile=target.ca_file)`, which is where a bad
    // `ca_file` actually fails) *before* `_exchange` ever calls
    // `conn.connect()`; build the TLS config here, before the TCP connect,
    // so a bad `ca_file` for an otherwise-unreachable target still surfaces
    // as `ca_file_unavailable`, not `upstream_unreachable` (finding F-R2-9).
    let tls_connector = if target.scheme == "https" {
        let ca_file = match target.raw_ca_file.as_ref() {
            // `if target.ca_file:` -- an empty string loads nothing.
            None => target.ca_file.as_deref().filter(|path| !path.is_empty()),
            Some(value) if is_json_falsy(value) => None,
            // Python reaches `load_verify_locations(cafile=value)` here and
            // raises `TypeError("cafile should be a valid filesystem path")`
            // for every truthy non-`str` JSON value (number, bool, list,
            // dict; measured on CPython 3.12.14). It is not an `OSError` or
            // `ssl.SSLError`, so it escapes `relay` before any socket exists.
            Some(_) => return Err(UpstreamFailure::escape("TypeError")),
        };
        // `load_verify_locations(cafile="a\x00b")` raises `ValueError:
        // embedded null byte`, likewise uncaught.
        if ca_file.is_some_and(|path| path.contains('\0')) {
            return Err(UpstreamFailure::escape("ValueError"));
        }
        Some(build_tls_connector(ca_file)?)
    } else {
        None
    };
    let ip: IpAddr = pinned_address
        .parse()
        .map_err(|_| UpstreamFailure::error("upstream_unreachable"))?;
    // `socket.create_connection` calls `sock.settimeout(timeout)` before
    // `connect`; its `ValueError`/`OverflowError` is not an `OSError`, so
    // none of `_exchange`'s handlers around `conn.connect()` catch it.
    let timeout = python_socket_timeout(timeout_seconds).map_err(UpstreamFailure::escape)?;
    let sockaddr = SocketAddr::new(ip, target.port as u16);
    // A zero timeout is a non-blocking socket in CPython: `connect` raises
    // `BlockingIOError` (`upstream_unreachable`). `connect_timeout` refuses
    // a zero duration with an `io::Error`, mapped to the same reason.
    let tcp = TcpStream::connect_timeout(&sockaddr, timeout)
        .map_err(|e| UpstreamFailure::error(classify_connect_error(&e)))?;
    let _ = tcp.set_nodelay(true);
    if let Some(connector) = tls_connector {
        tcp.set_read_timeout(Some(timeout)).ok();
        tcp.set_write_timeout(Some(timeout)).ok();
        // `connect` performs the handshake eagerly and configures OpenSSL's
        // DNS/IP identity verification for the configured host while the
        // socket itself remains pinned to the address already authorised.
        let stream = connector
            .connect(&target.host, tcp)
            .map_err(|e| UpstreamFailure::error(classify_openssl_handshake_error(&e)))?;
        return Ok((UpstreamStream::Tls(Box::new(stream)), timeout));
    }
    tcp.set_read_timeout(Some(timeout)).ok();
    tcp.set_write_timeout(Some(timeout)).ok();
    Ok((UpstreamStream::Plain(tcp), timeout))
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

/// `HTTPConnection._validate_method`'s
/// `_contains_disallowed_method_pchar_re = re.compile('[\x00-\x1f]')`: a
/// control character anywhere in the method raises a plain `ValueError` in
/// Python (finding F-R3-1), confirmed against a live `python3.12`. That
/// `ValueError` is caught by `_Relay._exchange`'s `except (OSError,
/// ValueError): upstream_connection_lost` clause -- the SAME outcome as
/// [`header_line_is_illegal`]'s `putheader` guard just below, NOT
/// `upstream_protocol_error` (unlike [`path_contains_disallowed_pchar`],
/// whose exception type differs even though both guards run inside the
/// same `putrequest` call).
fn method_contains_disallowed_pchar(method: &str) -> bool {
    method.chars().any(|c| (c as u32) <= 0x1F)
}

/// `HTTPConnection._validate_path`'s `_contains_disallowed_url_pchar_re =
/// re.compile('[\x00-\x20\x7f]')`: a control character, space, or DEL
/// anywhere in the request target raises `InvalidURL`, an
/// `http.client.HTTPException` (finding F-R3-1) -- caught by
/// `_exchange`'s `except http.client.HTTPException:
/// upstream_protocol_error` clause. Runs on the target *after*
/// `normalize_path`'s own leniency (one trailing `"\n"` allowed, finding
/// F-R2-8): `normalize_path` (`gateway.py`) and `_validate_path`
/// (`http.client`) are two independent gates in Python, and a target the
/// former accepts -- like `"/x?y\n"`, whose trailing `\n` is exactly what
/// the latter rejects -- can still fail here, refusing the request instead
/// of writing an injected request line to the upstream (the reviewer's
/// probe for this finding: `"GET /repos?x\n HTTP/1.1\r\n..."` reaching the
/// upstream with the credential attached).
fn path_contains_disallowed_pchar(path: &str) -> bool {
    path.chars().any(|c| (c as u32) <= 0x20 || c as u32 == 0x7F)
}

fn write_request(
    stream: &mut dyn Write,
    method: &str,
    target: &str,
    headers: &Headers,
    body: &[u8],
) -> Result<(), UpstreamFailure> {
    // `HTTPConnection.putrequest` validates the method and the target
    // BEFORE writing a single byte (finding F-R3-1): `write_request` used
    // to skip both guards entirely, so a target `normalize_path` accepts
    // (e.g. one trailing `"\n"`, finding F-R2-8) went straight onto the
    // wire as part of the request line.
    if method_contains_disallowed_pchar(method) {
        return Err(UpstreamFailure::error("upstream_connection_lost"));
    }
    if path_contains_disallowed_pchar(target) {
        return Err(UpstreamFailure::error("upstream_protocol_error"));
    }
    // `conn.request(...)` -> `putheader` raises `ValueError` for such a
    // header, *after* `self.transmitted = True` has already been set by the
    // caller (finding F-R2-8): `upstream_connection_lost`, exactly like
    // Python's `except (OSError, ValueError)` clause around
    // `conn.request(...)` does.
    for (name, value) in headers {
        if header_line_is_illegal(name, value) {
            return Err(UpstreamFailure::error("upstream_connection_lost"));
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
    stream
        .write_all(&out)
        .and_then(|_| stream.flush())
        .map_err(|e| UpstreamFailure::error(classify_read_write_error(&e)))
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
/// pathological line cannot force an unbounded allocation). Returns the
/// bytes exactly as read -- including whatever terminator (or lack of one,
/// at EOF) they end with -- matching Python's own `readline`, which never
/// strips anything itself; an empty result means true EOF (`b''`). Used
/// directly wherever Python compares the raw line against `(b'\r\n', b'\n',
/// b'')` or feeds it, terminator and all, into further processing (the
/// header block, finding F-R3-4/F-R3-7); [`read_line`] below is the
/// single-strip convenience wrapper for the simpler call sites.
fn read_raw_line(reader: &mut impl BufRead) -> Result<Vec<u8>, UpstreamFailure> {
    let mut line = Vec::new();
    let mut limited = reader.by_ref().take(HTTP_MAX_LINE as u64 + 1);
    limited
        .read_until(b'\n', &mut line)
        .map_err(|e| UpstreamFailure::error(classify_read_write_error(&e)))?;
    if line.len() > HTTP_MAX_LINE {
        return Err(UpstreamFailure::error("upstream_protocol_error"));
    }
    Ok(line)
}

/// [`read_raw_line`], additionally stripping AT MOST one trailing `"\r\n"`
/// or lone `"\n"` (never more), and returning `Ok(None)` only on true EOF
/// (zero bytes read) -- callers that treat EOF as a protocol error do so
/// themselves; several (finding F-R2-3) instead treat it exactly like a
/// blank line.
///
/// Finding F-R3-3: this used to pop *every* trailing `\r`/`\n` in a loop, so
/// a line like `b"\r\r\n"` collapsed all the way to empty, which several
/// callers use as their "blank separator line" signal -- wrongly ending a
/// header or trailer block one line early and reading the real next header
/// as body. Stripping only one terminator makes "the stripped result is
/// empty" exactly equivalent to Python's own raw-bytes check `line in
/// (b'\r\n', b'\n', b'')` (`b"\r\r\n"` strips to `b"\r"`, non-empty, correctly
/// *not* recognised as the blank line -- matching Python, since `b"\r\r\n"`
/// is none of those three exact values).
fn read_line(reader: &mut impl BufRead) -> Result<Option<Vec<u8>>, UpstreamFailure> {
    let mut line = read_raw_line(reader)?;
    if line.is_empty() {
        return Ok(None);
    }
    if line.ends_with(b"\r\n") {
        line.truncate(line.len() - 2);
    } else if line.ends_with(b"\n") {
        line.pop();
    }
    Ok(Some(line))
}

/// CPython `int(text)` / `int(text, base)` semantics for `base` 10 or 16, as
/// used by `http.client`'s own `int(status)`, `int(length)` and
/// `int(chunk_size_text, 16)` parses (finding F-R2-5). Delegates entirely to
/// the canonical [`crate::pystr::int_from_str_radix`] (PORTING.md §3b): a
/// local reimplementation of this grammar here was itself finding F-R3-2 --
/// the previous local copy trimmed with [`crate::pystr::is_space`]
/// (`str.isspace()`'s predicate), which wrongly includes U+001C-U+001F
/// (`int()` does not strip these -- they are ASCII, so CPython's
/// Unicode-to-ASCII transform never touches them, and plain `Py_ISSPACE`
/// does not count them as whitespace either) and wrongly rejected every
/// non-ASCII Unicode decimal digit CPython's `int()` accepts. See
/// [`crate::pystr::int_from_str_radix`]'s doc comment for the full grammar
/// and its oracle/fuzz tests; see `rust/tests/gateway.rs`'s
/// `content_length_with_information_separator_control_char_is_not_a_valid_int`/
/// `chunk_size_of_only_information_separator_control_chars_is_a_protocol_error`/
/// `status_line_split_and_int_semantics_for_control_chars_match_python_oracle`
/// for the end-to-end `Content-Length`/chunk-size/status probes from
/// finding F-R3-2, and the `http_framing_fuzz` module below (its own
/// U+001C-prefixed `Content-Length`/chunk-size mutations) for a fuzzed
/// version of the same three call sites.
fn python_int(text: &str, base: u32) -> Option<i128> {
    crate::pystr::int_from_str_radix(text, base)
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
    let headers = read_headers_block(reader)?;
    Ok(StatusAndHeaders { status, headers })
}

/// Splits `blob` on `\r\n`, a lone `\r`, or a lone `\n`, keeping each
/// terminator attached to the text that precedes it (a final, unterminated
/// remainder becomes its own last element). Port of
/// `email.feedparser.BufferedSubFile.push`, which re-cracks its whole input
/// via `StringIO(newline='').readlines()` -- the universal-newlines split,
/// equivalent to `NLCRE_crack = re.compile(r'(\r\n|\r|\n)')` -- regardless
/// of how the caller's own physical lines were originally delimited
/// (finding F-R3-4: a bare `\r` embedded *inside* one physical line, e.g.
/// `"X-A: a\rContent-Type: foo\r\n"`, becomes TWO logical lines here,
/// `"X-A: a\r"` and `"Content-Type: foo\r\n"`, each then re-examined by
/// [`header_re_matches`] as if it were its own header line).
fn split_keep_terminators(blob: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut chars = blob.chars().peekable();
    while let Some(c) = chars.next() {
        current.push(c);
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                current.push(chars.next().expect("peeked"));
            }
            lines.push(std::mem::take(&mut current));
        } else if c == '\n' {
            lines.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// `email.feedparser.headerRE = re.compile(r'^(From |[\041-\071\073-\176]*:|[\t ])')`:
/// true when `line` starts with the literal `"From "`, or with a tab/space
/// (a continuation line), or with zero-or-more RFC 2822 `ftext` characters
/// (ASCII `0x21-0x39` or `0x3B-0x7E` -- every printable ASCII byte except
/// space and `:`) immediately followed by `:`. Since none of those `ftext`
/// characters is itself `:`, the greedy `*` has only one place it can ever
/// succeed: right where it stops (the first non-`ftext` character, or
/// end-of-string) -- so a single forward scan suffices, no backtracking.
fn header_re_matches(line: &str) -> bool {
    if line.starts_with("From ") {
        return true;
    }
    match line.chars().next() {
        Some(' ') | Some('\t') => return true,
        _ => {}
    }
    for c in line.chars() {
        if c == ':' {
            return true;
        }
        let cp = c as u32;
        let is_ftext = (0x21..=0x39).contains(&cp) || (0x3B..=0x7E).contains(&cp);
        if !is_ftext {
            return false;
        }
    }
    false
}

/// `email._policybase.Compat32.header_source_parse`: the header's name is
/// `sourcelines[0]` up to its own first `':'`, kept byte-for-byte verbatim
/// (no stripping at all -- header NAMES are never lower-cased or trimmed
/// here, unlike [`normalize_headers`]'s handling of the *client's own*
/// request headers). The value is every source line from the first
/// (starting just after that `':'`) through the last, concatenated WITH
/// each line's own original terminator still attached (finding F-R3-7: a
/// folded continuation therefore keeps whatever the wire actually sent --
/// `"\r\n"`, a lone `"\r"`, or a lone `"\n"` -- not a synthetic `"\n"`), then
/// only a LEADING run of `' '`/`'\t'`/`'\r'`/`'\n'` and a TRAILING run of
/// `'\r'`/`'\n'` are stripped (`.lstrip(' \t\r\n')` then `.rstrip('\r\n')`
/// -- two fixed literal-character-class strips, never
/// [`crate::pystr::is_space`] or any other Unicode-aware predicate).
fn header_source_parse(name: &str, first_line: &str, continuations: &[String]) -> (String, String) {
    let colon = first_line
        .find(':')
        .expect("group's first line has a colon");
    let mut value = String::new();
    value.push_str(&first_line[colon + 1..]);
    for line in continuations {
        value.push_str(line);
    }
    let value = value.trim_start_matches([' ', '\t', '\r', '\n']);
    let value = value.trim_end_matches(['\r', '\n']);
    (name.to_string(), value.to_string())
}

/// `email.feedparser.FeedParser._parse_headers`, run over the lines
/// `_parsegen`'s own loop already filtered through [`header_re_matches`]
/// (finding F-R3-4): folds continuation lines (ignoring one that appears
/// before any header has started -- `FirstHeaderLineIsContinuationDefect`),
/// treats a `"From "`-prefixed line as an envelope/misplaced-envelope line
/// that never becomes a header (every branch of Python's own handling for
/// it -- `lineno == 0`'s unixfrom, the last-line pushback, and the
/// middle-of-block defect -- ends up producing no header entry either way,
/// so they collapse to one case here), and drops a line whose colon sits at
/// index 0 (`InvalidHeaderDefect("Missing header name.")`) instead of
/// recording an empty header name.
fn parse_recognized_header_lines(lines: &[String]) -> Headers {
    let mut headers = Headers::new();
    let mut pending: Option<(String, String, Vec<String>)> = None; // (name, first_line, continuations)
    let n = lines.len();
    for (idx, line) in lines.iter().enumerate() {
        let starts_ws = matches!(line.chars().next(), Some(' ') | Some('\t'));
        if starts_ws {
            if let Some((_, _, continuations)) = pending.as_mut() {
                continuations.push(line.clone());
            }
            continue;
        }
        if let Some((name, first_line, continuations)) = pending.take() {
            headers.push(header_source_parse(&name, &first_line, &continuations));
        }
        if line.starts_with("From ") {
            if idx == n - 1 {
                break;
            }
            continue;
        }
        let Some(colon) = line.find(':') else {
            // Cannot happen: every line that reaches `recognized` matched
            // `headerRE`, and the only alternative that isn't "From " or a
            // continuation requires a literal `:`.
            continue;
        };
        if colon == 0 {
            continue;
        }
        pending = Some((line[..colon].to_string(), line.clone(), Vec::new()));
    }
    if let Some((name, first_line, continuations)) = pending {
        headers.push(header_source_parse(&name, &first_line, &continuations));
    }
    headers
}

/// Port of `http.client._read_headers` (the physical byte-level read) piped
/// straight into `email.parser.Parser().parsestr(...)` (`_parse_header_lines`
/// -> `FeedParser._parsegen`/`_parse_headers`), exactly as
/// `http.client.parse_headers` wires them together (finding F-R3-4):
///
/// 1. Physical read: raw lines (terminator untouched), stopping at -- and
///    including -- the first line that is exactly `b"\r\n"`, `b"\n"`, or
///    `b""` (EOF). Every physical line, including that terminator line,
///    counts against `HTTP_MAX_HEADERS` (finding F-R2-2).
/// 2. The physical lines are concatenated (terminators intact) and
///    RE-SPLIT on `\r\n|\r|\n` ([`split_keep_terminators`]) -- this can
///    produce MORE logical lines than physical ones when a physical line
///    contains a bare `\r` before its own trailing `\r\n`/`\n`.
/// 3. [`header_re_matches`] gates which logical lines are ever considered
///    headers at all (`_parsegen`'s loop: append while it matches, stop --
///    with no error -- at the first line that doesn't).
/// 4. [`parse_recognized_header_lines`] turns the recognised lines into
///    `(name, value)` pairs.
fn read_headers_block(reader: &mut impl BufRead) -> Result<Headers, UpstreamFailure> {
    let mut blob = String::new();
    let mut count = 0usize;
    loop {
        let raw = read_raw_line(reader)?;
        count += 1;
        if count > HTTP_MAX_HEADERS {
            return Err(UpstreamFailure::error("upstream_protocol_error"));
        }
        let is_terminator = raw.is_empty() || raw == b"\r\n" || raw == b"\n";
        blob.push_str(&latin1_decode(&raw));
        if is_terminator {
            break;
        }
    }
    Ok(parse_header_blob(&blob))
}

/// Steps 2-4 of [`read_headers_block`]: `email.parser.Parser().parsestr`'s
/// (compat32) header fields for the latin-1 text of a header block that
/// `http.client._read_headers` already read line by line. Shared with
/// `fake_upstream.rs`, whose `BaseHTTPRequestHandler` reads request headers
/// through the same `http.client.parse_headers`.
pub(crate) fn parse_header_blob(blob: &str) -> Headers {
    let logical_lines = split_keep_terminators(blob);
    let recognized: Vec<String> = logical_lines
        .into_iter()
        .take_while(|line| header_re_matches(line))
        .collect();
    parse_recognized_header_lines(&recognized)
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

/// `http.client` returns a negative chunk size from `_read_next_chunk_size`
/// unchanged, and `_read_chunked` hands it to `_safe_read`, whose
/// `self.fp.read(amt)` runs on the socket's `io.BufferedReader`
/// (`sock.makefile("rb")`). Measured against CPython 3.12.14:
///
/// * `-1` is "read to EOF": every remaining byte is read (a socket timeout
///   meanwhile is `upstream_timeout`, any other `OSError`
///   `upstream_connection_lost`), then the next `_safe_read(2)` finds EOF
///   and raises `IncompleteRead` -> `upstream_protocol_error`;
/// * `-2` down to `-2**63` raise `ValueError("read length must be
///   non-negative or -1")`, which `_exchange`'s `except (OSError,
///   ValueError)` maps to `upstream_connection_lost`;
/// * below `-2**63` the value does not fit `Py_ssize_t` and raises
///   `OverflowError`, which no `except` clause of `_exchange` catches: it
///   escapes `relay` ([`UpstreamFailure::escape`]).
fn negative_chunk_size(reader: &mut impl BufRead, size: i128) -> UpstreamFailure {
    if size == -1 {
        let mut sink = vec![0u8; READ_CHUNK];
        loop {
            match reader.read(&mut sink) {
                Ok(0) => return UpstreamFailure::error("upstream_protocol_error"),
                Ok(_) => continue,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return UpstreamFailure::error(classify_read_write_error(&e)),
            }
        }
    }
    if size >= i128::from(i64::MIN) {
        UpstreamFailure::error("upstream_connection_lost")
    } else {
        UpstreamFailure::escape("OverflowError")
    }
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
                //
                // `int(line, 16)` runs on the raw line BYTES, not on a
                // latin-1 `str`: CPython's bytes path accepts only ASCII
                // digits and ASCII whitespace, so a non-ASCII byte (even
                // 0x85/0xA0, which `str.isspace()` would strip) is a
                // `ValueError` -> `IncompleteRead` here.
                if !size_text.is_ascii() {
                    return Err(UpstreamFailure::error("upstream_protocol_error"));
                }
                let size = python_int(size_text, 16)
                    .ok_or(UpstreamFailure::error("upstream_protocol_error"))?;
                if size < 0 {
                    return Err(negative_chunk_size(reader, size));
                }
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
        status: Option<Value>,
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
            ("status", status.unwrap_or(Value::Null)),
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
        let status = upstream_status
            .map(|value| json!(value))
            .or_else(|| Some(result.status.value()));
        if let Err(e) = self.audit(outcome, reason, status, Vec::new())
            && e.is(ErrorClass::AuditUnavailable)
        {
            result.status = crate::pyint::PyInt::from(503i64);
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
        // Finding X-18: `timeout = float(self.ctx.config.upstream_timeout)`
        // never raises; `socket.create_connection`'s `settimeout` does, after
        // `_open_connection` built the TLS context (so `ca_file_unavailable`
        // still wins) -- see [`python_socket_timeout`].
        let limit = self.ctx.config.max_response_bytes.max(0) as usize;
        let (mut stream, timeout) = open_connection(
            &connection,
            self.ctx.config.upstream_timeout,
            pinned_address,
        )?;
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
        )?;
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
        // `.strip().lower()`: `str.strip()`'s predicate is
        // `crate::pystr::is_space`/`str.isspace()`, which (unlike Rust's
        // `str::trim()`) also strips U+001C-U+001F -- finding F-R3-8:
        // `Content-Encoding: \x1cidentity` must still be accepted, matching
        // the same `python_strip` helper `normalize_method`/
        // `normalize_headers` already use above.
        let encoding_raw = headers_get_all_joined(&head.headers, "content-encoding")
            .unwrap_or_else(|| "identity".to_string());
        let encoding = python_strip(&encoding_raw).to_lowercase();
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
            status: response.status.into(),
            headers,
            body: response.body,
            reason: None,
        }
    }

    /// `_Relay.run`: `Ok` for every `RelayResult` Python returns, `Err` for
    /// every exception Python lets escape (a `ZeroPWError` from
    /// `Policy`/`Audit`/`Vault`/ledger state, or an [`escaped_builtin`]).
    fn run(mut self) -> Result<RelayResult, Error> {
        self.try_run()
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
                        RequestLedger::replay(entry.as_ref().expect("replay carries entry"))?;
                    let result_kind = if replayed.reason.is_some() {
                        "blocked"
                    } else {
                        "ok"
                    };
                    if let Err(e) = self.audit(
                        result_kind,
                        Some("replayed"),
                        Some(replayed.status.value()),
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
            .secret_for_trusted_use(&connection.secret_id, connection.secret_version.clone())
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
        // Finding X-1: `auth_header` above already fails closed
        // (`unsupported_auth_mode`) whenever `mode == "basic"` and
        // `raw_basic_username` is set, so this point is only reached with a
        // faithful `basic_username` string. Guarded again here, defensively,
        // so a future reordering of these two calls cannot resurrect the
        // placeholder leaking into the response-scrubbing pattern list the
        // same way it once leaked onto the wire.
        if connection
            .http_auth
            .as_ref()
            .is_some_and(|a| a.mode == "basic" && a.raw_basic_username.is_some())
        {
            return self.refuse(
                501,
                "unsupported_auth_mode",
                "denied",
                Some("Unsupported"),
                None,
                Vec::new(),
                true,
            );
        }
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
                if let Some(class) = failure.escaped {
                    // Not an `_UpstreamFailure` in Python: the built-in
                    // exception leaves `_Relay.run` without `_finish` or
                    // `_refuse`, so the claimed ledger entry stays
                    // `in_flight` and no outcome audit record is written.
                    return Err(escaped_builtin(class));
                }
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

/// The reply `zeropw.server` sends when `relay`/`relay_for_caller` raises
/// instead of returning, as a `RelayResult`: `_dispatch`'s `except
/// ZeroPWError` answers `error_status(exc)` with `json.dumps(exc.to_dict(),
/// sort_keys=True)`, and its final `except Exception` answers a CPython
/// built-in ([`escaped_builtin`]) with `500 {"error": "InternalError",
/// "reason": "internal_error"}`. Only the infallible convenience wrappers
/// [`relay`]/[`relay_for_caller`] use this; the server and `tools.request`
/// call [`try_relay`]/[`try_relay_for_caller`] and propagate the error
/// exactly as Python's exception propagates.
fn unexpected_error_result(e: Error) -> RelayResult {
    let (status, payload) = if is_escaped_builtin(&e) {
        (
            500,
            json!({"error": "InternalError", "reason": "internal_error"}),
        )
    } else {
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
        (status, e.to_dict())
    };
    let reason = payload
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let body = pyjson::dumps(&payload, DumpOptions::default_sorted())
        .expect("error payload is representable")
        .into_bytes();
    RelayResult {
        status: status.into(),
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body,
        reason: Some(reason),
    }
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
/// `X-ZeroPW-Handle` header). `Err` is exactly the exception Python's
/// `relay` lets escape; `zeropw.server` (and `server.rs`) turn it into the
/// HTTP reply.
pub fn try_relay(
    ctx: &Context,
    handle_token: &str,
    method: &str,
    path: &str,
    headers: &Headers,
    body: &[u8],
    request_id: Option<&str>,
) -> Result<RelayResult, Error> {
    try_relay_with_resolver(
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

/// [`try_relay`], answering an escaped exception the way `zeropw.server`
/// does ([`unexpected_error_result`]) instead of returning it.
pub fn relay(
    ctx: &Context,
    handle_token: &str,
    method: &str,
    path: &str,
    headers: &Headers,
    body: &[u8],
    request_id: Option<&str>,
) -> RelayResult {
    try_relay(ctx, handle_token, method, path, headers, body, request_id)
        .unwrap_or_else(unexpected_error_result)
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
    try_relay_with_resolver(
        ctx,
        handle_token,
        method,
        path,
        headers,
        body,
        request_id,
        resolver,
    )
    .unwrap_or_else(unexpected_error_result)
}

/// [`try_relay`] with an injectable [`Resolver`].
#[allow(clippy::too_many_arguments)]
pub fn try_relay_with_resolver(
    ctx: &Context,
    handle_token: &str,
    method: &str,
    path: &str,
    headers: &Headers,
    body: &[u8],
    request_id: Option<&str>,
    resolver: Resolver,
) -> Result<RelayResult, Error> {
    let handle = match ctx.handles.verify(handle_token, Some((ctx.clock)())) {
        Ok(h) => h,
        Err(e) => {
            return Ok(refuse_unauthenticated(
                ctx, &e.reason, method, path, request_id,
            ));
        }
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
/// caller, no handle, any usable grant. `Err` is exactly the exception
/// Python's `relay_for_caller` lets escape (out of `tools.request` too).
#[allow(clippy::too_many_arguments)]
pub fn try_relay_for_caller(
    ctx: &Context,
    caller: &str,
    connection_id: &str,
    method: &str,
    path: &str,
    headers: &Headers,
    body: &[u8],
    request_id: Option<&str>,
) -> Result<RelayResult, Error> {
    try_relay_for_caller_with_resolver(
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

/// [`try_relay_for_caller`], answering an escaped exception the way
/// `zeropw.server` does ([`unexpected_error_result`]).
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
    try_relay_for_caller(
        ctx,
        caller,
        connection_id,
        method,
        path,
        headers,
        body,
        request_id,
    )
    .unwrap_or_else(unexpected_error_result)
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
    try_relay_for_caller_with_resolver(
        ctx,
        caller,
        connection_id,
        method,
        path,
        headers,
        body,
        request_id,
        resolver,
    )
    .unwrap_or_else(unexpected_error_result)
}

/// [`try_relay_for_caller`] with an injectable [`Resolver`].
#[allow(clippy::too_many_arguments)]
pub fn try_relay_for_caller_with_resolver(
    ctx: &Context,
    caller: &str,
    connection_id: &str,
    method: &str,
    path: &str,
    headers: &Headers,
    body: &[u8],
    request_id: Option<&str>,
    resolver: Resolver,
) -> Result<RelayResult, Error> {
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
mod socket_timeout_oracle_tests {
    use super::*;

    /// [`python_socket_timeout`] against CPython 3.12's own
    /// `socket.settimeout` (`gettimeout()` reports the stored nanosecond
    /// value as seconds; the error class is what escapes `relay`).
    #[test]
    fn python_socket_timeout_matches_cpython_settimeout() {
        let cases: &[f64] = &[
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
            -1.0,
            -1e-300,
            -0.0,
            0.0,
            5e-324,
            1e-10,
            1e-9,
            1.5e-9,
            0.001,
            30.0,
            2_147_483.648,
            9_223_372_036.0,
            9_223_372_036.854_775,
            9_223_372_037.0,
            9.3e9,
            1e30,
            -9.3e9,
        ];
        let literals: Vec<String> = cases
            .iter()
            .map(|v| {
                if v.is_nan() {
                    "float('nan')".to_string()
                } else if v.is_infinite() {
                    format!("float('{}inf')", if *v < 0.0 { "-" } else { "" })
                } else {
                    format!("float.fromhex('{}')", hex_float(*v))
                }
            })
            .collect();
        let script = format!(
            "import socket\nfor v in [{}]:\n    s = socket.socket()\n    try:\n        s.settimeout(v)\n        print(repr(s.gettimeout()))\n    except Exception as exc:\n        print(type(exc).__name__)\n    finally:\n        s.close()\n",
            literals.join(", ")
        );
        let expected = crate::oracle::python(&script);
        for (value, python) in cases.iter().zip(expected.lines()) {
            let rust = match python_socket_timeout(*value) {
                Ok(duration) => {
                    // `_PyTime_AsSecondsDouble`: whole seconds convert
                    // exactly, anything else is `(double)ns / 1e9`.
                    let ns = duration.as_nanos();
                    let seconds = if ns % 1_000_000_000 == 0 {
                        (ns / 1_000_000_000) as f64
                    } else {
                        ns as f64 / 1e9
                    };
                    pyjson::python_float_repr(seconds)
                }
                Err(class) => class.to_string(),
            };
            assert_eq!(rust, python, "settimeout({value:?})");
        }
    }

    /// `float.hex()` spelling, so the oracle sees the exact same double.
    fn hex_float(v: f64) -> String {
        if v == 0.0 {
            return if v.is_sign_negative() {
                "-0x0p+0"
            } else {
                "0x0p+0"
            }
            .to_string();
        }
        let bits = v.to_bits();
        let sign = if bits >> 63 == 1 { "-" } else { "" };
        let exponent = ((bits >> 52) & 0x7ff) as i64;
        let mantissa = bits & ((1u64 << 52) - 1);
        if exponent == 0 {
            format!("{sign}0x0.{mantissa:013x}p-1022")
        } else {
            format!("{sign}0x1.{mantissa:013x}p{:+}", exponent - 1023)
        }
    }
}

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

/// `read_headers_block` (and the `header_source_parse`/`header_re_matches`/
/// `split_keep_terminators`/`parse_recognized_header_lines` helpers it
/// composes) is private to this module, so these direct-call regression
/// tests for equivalence-review round-3 findings F-R3-4/F-R3-7 live here.
/// The end-to-end `rust/tests/gateway.rs` integration tests for the same
/// findings can only observe a header's *value* when that value survives
/// `Relay::filter_response`'s `HEADER_VALUE_RE` allowlist gate (which
/// rejects any embedded raw `\r`/`\n`, by design, before a value ever
/// reaches a `RelayResult`) -- so the one case that specifically needs an
/// embedded terminator to *survive* assembly (F-R3-7) can only be pinned at
/// this layer.
#[cfg(test)]
mod header_parsing_tests {
    use super::*;
    use std::io::Cursor;

    fn headers_from(raw: &[u8]) -> Headers {
        let mut reader = Cursor::new(raw);
        match read_headers_block(&mut reader) {
            Ok(h) => h,
            Err(e) => panic!("read_headers_block failed: {}", e.reason),
        }
    }

    #[test]
    fn folded_continuation_keeps_the_original_wire_terminator() {
        // Finding F-R3-7: `Compat32.header_source_parse` concatenates the
        // continuation line VERBATIM, terminator and all, then strips only
        // a leading `' '`/`'\t'`/`'\r'`/`'\n'` run and a trailing
        // `'\r'`/`'\n'` run -- an embedded fold therefore keeps the wire's
        // own `"\r\n"` in the middle of the assembled value, never a
        // synthetic `"\n"` (the old code folded with `value.push('\n')`).
        let headers = headers_from(b"ETag: AAAA\r\n\tBBBB\r\n\r\n");
        assert_eq!(
            headers,
            vec![("ETag".to_string(), "AAAA\r\n\tBBBB".to_string())]
        );
    }

    #[test]
    fn folded_continuation_with_lf_only_terminators_keeps_lf_not_crlf() {
        // Same finding: the fold must reproduce whatever terminator the
        // wire actually used, not always `"\r\n"` either.
        let headers = headers_from(b"ETag: AAAA\n\tBBBB\n\n");
        assert_eq!(
            headers,
            vec![("ETag".to_string(), "AAAA\n\tBBBB".to_string())]
        );
    }

    #[test]
    fn bad_header_name_drops_every_later_header() {
        // Finding F-R3-4: a space in the field name fails `headerRE`
        // entirely, ending recognition (not just dropping that one line).
        let headers = headers_from(b"X-Before: keep\r\nBad Name: x\r\nX-After: drop\r\n\r\n");
        assert_eq!(headers, vec![("X-Before".to_string(), "keep".to_string())]);
    }

    #[test]
    fn leading_colon_is_dropped_without_ending_recognition() {
        // Finding F-R3-4: `": value"` matches `headerRE` (an empty
        // field-name run is still zero-or-more), so recognition continues,
        // but the line itself is dropped rather than becoming an
        // empty-named header.
        let headers = headers_from(b": stray\r\nX-After: keep\r\n\r\n");
        assert_eq!(headers, vec![("X-After".to_string(), "keep".to_string())]);
    }

    #[test]
    fn from_envelope_line_is_skipped_without_ending_recognition() {
        // Finding F-R3-4: a `"From "`-prefixed line is always consumed
        // (never a header), but never ends recognition either.
        let headers = headers_from(b"From nobody\r\nX-After: keep\r\n\r\n");
        assert_eq!(headers, vec![("X-After".to_string(), "keep".to_string())]);
    }

    #[test]
    fn embedded_bare_cr_splits_one_physical_line_into_two_headers() {
        // Finding F-R3-4/F-R3-7: `_read_headers` reads by `\n` only, so
        // `"X-A: a\rX-B: b\r\n"` is ONE physical line -- but the header
        // block is re-split on `\r\n|\r|\n` before `headerRE` ever runs, so
        // the embedded bare `\r` produces two logical lines and therefore
        // two separate headers.
        let headers = headers_from(b"X-A: a\rX-B: b\r\n\r\n");
        assert_eq!(
            headers,
            vec![
                ("X-A".to_string(), "a".to_string()),
                ("X-B".to_string(), "b".to_string()),
            ]
        );
    }

    #[test]
    fn doubled_trailing_cr_does_not_end_the_header_block_early() {
        // Finding F-R3-3: `"\r\r\n"` is not `_read_headers`'s exact
        // blank-line value (`b"\r\n"`/`b"\n"`/`b""`), so it must not end
        // the header block; it re-splits into two headerRE-failing logical
        // lines instead, ending *recognition* (finding F-R3-4) without
        // losing any bytes to the body.
        let headers = headers_from(b"X-Before: keep\r\n\r\r\nX-After: drop\r\n\r\n");
        assert_eq!(headers, vec![("X-Before".to_string(), "keep".to_string())]);
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
        ConnectionLost,
        Escaped(String),
    }

    /// Runs exactly the read sequence `_Relay._exchange` performs on a
    /// `conn.getresponse()` result (`begin()` via `read_status_and_headers`,
    /// then the `resp.read(min(READ_CHUNK, limit + 1 - total))` loop), over
    /// an in-memory `Cursor` standing in for the socket. A `Cursor` never
    /// produces a real I/O error, so `upstream_timeout` is unreachable here;
    /// `upstream_connection_lost` and an escaped built-in still arise from
    /// a negative chunk size, exactly as in a `python3.12`
    /// `http.client.HTTPResponse` whose fake socket's `makefile("rb")`
    /// returns an `io.BufferedReader` like a real socket's does (a bare
    /// `io.BytesIO` would accept `read(-5)` and hide that `ValueError`).
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
            Err(f) if f.escaped.is_some() => {
                FuzzOutcome::Escaped(f.escaped.unwrap_or_default().to_string())
            }
            Err(f) if f.reason == "upstream_connection_lost" => FuzzOutcome::ConnectionLost,
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
        return io.BufferedReader(io.BytesIO(self._data))

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
        return ["escaped", type(e).__name__]

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
                "connection_lost" => FuzzOutcome::ConnectionLost,
                "escaped" => FuzzOutcome::Escaped(entry[1].as_str().unwrap().to_string()),
                other => panic!("unknown python oracle outcome {other:?} / {entry:?}"),
            })
            .collect()
    }

    // --------------------------------------------------------- generators

    fn random_status_line(rng: &mut Lcg) -> Vec<u8> {
        let version = *rng.choice(&[
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
        let sep = *rng.choice(&[" ", "\t", "  "]);
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
        // finding F-R3-2: U+001C-U+001F are `str.isspace()` but NOT
        // `int()`-whitespace -- a value like `"\x1c5"` must be a parse
        // failure (`self.length = None` -> `UntilClose` framing), not "5".
        let info_separator_prefixed = format!("\u{1c}{actual_body_len}");
        let info_separator_only = "\u{1d}\u{1e}\u{1f}".to_string();
        let candidates = [
            actual_body_len.to_string(),
            format!("{}", actual_body_len + 1 + rng.below(50)), // bigger than sent (F-R2-3c)
            underscored,                                        // underscore (F-R2-5)
            "-1".to_string(),
            "not-a-number".to_string(),
            "".to_string(),
            info_separator_prefixed,
            info_separator_only,
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
        // finding F-R3-2: a chunk-size line consisting only of ASCII
        // "information separator" control characters (U+001C-U+001F) must
        // be a protocol error, not a valid `int(..., 16)` parse.
        let mut candidates = vec![
            hex.clone(),
            "zz".to_string(),
            format!("{hex};ext=1"),
            "\u{1c}5".to_string(),
        ];
        if rng.one_in(4) {
            // Negative sizes reach `_safe_read` unchanged: `-1` reads to
            // EOF, `-2..=-2**63` are a `ValueError`, anything lower an
            // escaping `OverflowError` (finding F-R4-7 re-measured).
            candidates.push(
                pick_owned(
                    rng,
                    &[
                        "-1",
                        "-2",
                        "-a",
                        "-0",
                        "-7fffffffffffffff",
                        "-8000000000000000",
                        "-8000000000000001",
                        "-99999999999999999999999999999999",
                    ],
                )
                .to_string(),
            );
        }
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

    /// Occasionally replaces a well-formed `"{name}: {value}\r\n"` header
    /// line with an adversarial raw line exercising the `email.feedparser`
    /// leniency findings F-R3-4/F-R3-7 (a `headerRE`-violating name, a
    /// `"From "` envelope line, a leading colon, or a bare `\r` embedded
    /// inside one physical line that the `\r\n|\r|\n` re-split then turns
    /// into two logical header lines).
    fn maybe_corrupt_header_line(rng: &mut Lcg, name: &str, value: &str) -> Vec<u8> {
        if !rng.one_in(8) {
            return format!("{name}: {value}\r\n").into_bytes();
        }
        match rng.below(7) {
            0 => format!("Bad Name: {value}\r\n").into_bytes(),
            1 => format!("X\u{7f}A: {value}\r\n").into_bytes(),
            2 => format!(": {value}\r\n").into_bytes(),
            3 => b"From nobody\r\n".to_vec(),
            4 => format!("{name}: a\rContent-Type: c\r\n").into_bytes(),
            5 => format!(" {value}\r\n").into_bytes(), // stray leading continuation
            _ => format!("{name}: {value}\r\r\n").into_bytes(),
        }
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
            let is_framing_header;
            let value = if name == "Content-Length" && !use_chunked && !wrote_framing_header {
                wrote_framing_header = true;
                is_framing_header = true;
                random_content_length_value(rng, body.len())
            } else if name == "Transfer-Encoding" && use_chunked && !wrote_framing_header {
                wrote_framing_header = true;
                is_framing_header = true;
                if rng.one_in(10) {
                    "chunked ".to_string() // trailing space: must NOT be treated as chunked
                } else {
                    "chunked".to_string()
                }
            } else {
                is_framing_header = false;
                random_header_value(rng)
            };
            if is_framing_header {
                // Keep the framing header's own line well-formed (`"name:
                // value\r\n"`) so the adversarial *value* mutations added
                // to `random_content_length_value` above (U+001C-U+001F,
                // finding F-R3-2) are actually exercised as a
                // `Content-Length`/`Transfer-Encoding` value, rather than
                // sometimes being swallowed into an unrelated corrupt line.
                out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
            } else {
                out.extend_from_slice(&maybe_corrupt_header_line(rng, &name, &value));
            }
        }
        if !wrote_framing_header && use_chunked {
            out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        } else if !wrote_framing_header && !use_chunked && rng.one_in(2) {
            out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        }

        // finding F-R3-3: `"\r\r\n"` is neither of `_read_headers`'s exact
        // terminator values (`b"\r\n"`/`b"\n"`/`b""`), so it must NOT end
        // the header block -- it is just another (odd) header-block byte.
        let header_terminator: &[u8] = match rng.below(15) {
            0 => b"",
            1 => b"\r\r\n",
            _ => b"\r\n",
        };
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
                (FuzzOutcome::ConnectionLost, FuzzOutcome::ConnectionLost) => true,
                (FuzzOutcome::Escaped(r), FuzzOutcome::Escaped(p)) => r == p,
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
