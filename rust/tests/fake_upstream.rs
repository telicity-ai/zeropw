//! Port of `tests/test_fake_upstream.py`.
//!
//! `FakeUpstream(SECRET, mode="digest")` / `mode="basic"` with no
//! `basic_username` raising Python's `ValueError` at construction are ported
//! through `FakeUpstream::with_mode` (the `mode=` string form) and
//! `mode_basic("")` (which panics with the same message). The request
//! parsing and routing rules the fixture shares with `BaseHTTPRequestHandler`
//! and `urllib.parse` are compared byte-for-byte with the Python fixture in
//! `request_handling_matches_the_python_fixture`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use zeropw::fake_upstream::{
    BASIC_LEAK_FORMS, ENCODED_LEAK_FORMS, FakeUpstream, LARGE_BODY_SIZE, STREAM_PARTS,
    encoded_credential,
};

const SECRET: &str = "synthetic-token-fake-upstream-0123456789";
const SECRET_ENCODINGS: &str = "synthetic-token/enc+ode=chars:>>>?<&\"\\x-0123456789";

fn lower_percent_triplets(encoded: &str) -> String {
    let bytes = encoded.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
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

// ------------------------------------------------------------ raw HTTP client

struct Response {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn send_request(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> TcpStream {
    let mut stream = TcpStream::connect((host, port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut out = Vec::new();
    out.extend_from_slice(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
    out.extend_from_slice(format!("Host: {host}:{port}\r\n").as_bytes());
    if let Some(b) = body {
        out.extend_from_slice(format!("Content-Length: {}\r\n", b.len()).as_bytes());
    }
    for (name, value) in headers {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    if let Some(b) = body {
        out.extend_from_slice(b);
    }
    stream.write_all(&out).expect("write request");
    stream
}

/// Reads the status line and headers, returning them plus whatever body
/// bytes already arrived in the same reads (a small response's body often
/// rides along with the headers in one TCP segment) -- for tests that
/// deliberately "hang up early" like Python's `resp.read(1024)` on a 9 MiB
/// body, only the headers are consumed here; the leftover (usually empty
/// for a huge streamed body) is still returned so callers that DO want the
/// body don't lose it.
fn read_head(stream: &mut TcpStream) -> (u16, HashMap<String, String>, Vec<u8>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).expect("read head");
        assert!(n > 0, "connection closed before headers completed");
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).into_owned();
            let mut lines = head.split("\r\n");
            let status_line = lines.next().unwrap();
            let status: u16 = status_line.split(' ').nth(1).unwrap().parse().unwrap();
            let mut headers = HashMap::new();
            for line in lines {
                if let Some((name, value)) = line.split_once(':') {
                    headers.insert(name.trim().to_lowercase(), value.trim().to_string());
                }
            }
            let leftover = buf[pos + 4..].to_vec();
            return (status, headers, leftover);
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn read_body(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    leftover: Vec<u8>,
) -> Vec<u8> {
    if headers
        .get("transfer-encoding")
        .map(|v| v.eq_ignore_ascii_case("chunked"))
        == Some(true)
    {
        read_chunked(stream, leftover)
    } else {
        let mut body = leftover;
        stream.read_to_end(&mut body).expect("read body");
        if let Some(len) = headers
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok())
        {
            body.truncate(len);
        }
        body
    }
}

fn read_chunked(stream: &mut TcpStream, leftover: Vec<u8>) -> Vec<u8> {
    let mut buf = leftover;
    let mut chunk = [0u8; 4096];
    while !buf.ends_with(b"0\r\n\r\n") {
        let n = stream.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    // Decode chunked framing.
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let line_end = find(&buf[i..], b"\r\n").expect("chunk size line") + i;
        let size_text = std::str::from_utf8(&buf[i..line_end]).unwrap();
        let size = usize::from_str_radix(size_text.trim(), 16).expect("chunk size");
        i = line_end + 2;
        if size == 0 {
            break;
        }
        out.extend_from_slice(&buf[i..i + size]);
        i += size + 2; // skip trailing \r\n
    }
    out
}

fn request(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Response {
    let mut stream = send_request(host, port, method, path, headers, body);
    let (status, resp_headers, leftover) = read_head(&mut stream);
    let body = if method == "HEAD" {
        Vec::new()
    } else {
        read_body(&mut stream, &resp_headers, leftover)
    };
    Response {
        status,
        headers: resp_headers,
        body,
    }
}

fn json(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body).expect("valid json")
}

fn auth_header(secret: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {secret}"))
}

// ------------------------------------------------------------------- tests

#[test]
fn url_and_recording() {
    let fake = FakeUpstream::new(SECRET).start();
    assert!(fake.url().starts_with("http://127.0.0.1:"));
    assert_eq!(fake.host(), "127.0.0.1");
    let resp = request(
        fake.host(),
        fake.port(),
        "GET",
        "/repos?page=2",
        &[("Authorization", "Bearer wrong"), ("X-Test", "1")],
        None,
    );
    assert_eq!(resp.status, 401);
    assert!(resp.headers.contains_key("www-authenticate"));
    assert_eq!(
        json(&resp.body),
        serde_json::json!({"error": "unauthorized"})
    );
    let requests = fake.requests();
    assert_eq!(requests.len(), 1);
    let seen = &requests[0];
    assert_eq!(
        (
            seen.method.as_str(),
            seen.path.as_str(),
            seen.body.as_slice()
        ),
        ("GET", "/repos?page=2", b"".as_slice())
    );
    assert_eq!(seen.headers.get("authorization").unwrap(), "Bearer wrong");
    assert_eq!(seen.headers.get("x-test").unwrap(), "1");
    fake.reset();
    assert_eq!(fake.requests().len(), 0);
}

#[test]
fn every_response_carries_server_and_date_headers() {
    // `_Handler.send_response` (called by `_send`/`_send_chunked`/
    // `_send_streamed`) always emits `Server`/`Date` before any other
    // header; a previous version of this fixture emitted neither, which
    // made the corresponding assertion in `rust/tests/gateway.rs`'s
    // `response_header_filter_and_upstream_401` (that a relayed response
    // never carries `server`/`date`) vacuously true instead of actually
    // proving `gateway::RESPONSE_HEADER_ALLOWLIST` drops them (finding
    // F-20). Covers all three response paths: a plain JSON response
    // (`_send`), a chunked stream (`_send_chunked`), and a streamed body
    // (`_send_streamed`).
    let fake = FakeUpstream::new(SECRET).start();
    let (name, value) = auth_header(SECRET);

    let plain = request(
        fake.host(),
        fake.port(),
        "GET",
        "/me",
        &[(name, &value)],
        None,
    );
    assert_eq!(plain.status, 200);
    assert!(plain.headers.contains_key("server"));
    assert!(plain.headers.contains_key("date"));

    let chunked = request(
        fake.host(),
        fake.port(),
        "GET",
        "/stream",
        &[(name, &value)],
        None,
    );
    assert_eq!(chunked.status, 200);
    assert!(chunked.headers.contains_key("server"));
    assert!(chunked.headers.contains_key("date"));

    // `/huge` is the one route that goes through `_send_streamed`; only the
    // headers matter here, so read just those (its body is multiple MiB).
    let mut streamed_conn = send_request(
        fake.host(),
        fake.port(),
        "GET",
        "/huge",
        &[(name, &value)],
        None,
    );
    let (status, streamed_headers, _leftover) = read_head(&mut streamed_conn);
    assert_eq!(status, 200);
    assert!(streamed_headers.contains_key("server"));
    assert!(streamed_headers.contains_key("date"));
}

#[test]
fn business_endpoints() {
    let fake = FakeUpstream::new(SECRET).start();
    let (name, value) = auth_header(SECRET);
    let resp = request(
        fake.host(),
        fake.port(),
        "GET",
        "/repos",
        &[(name, &value)],
        None,
    );
    assert_eq!(
        (resp.status, json(&resp.body)),
        (
            200,
            serde_json::json!([{"name": "demo"}, {"name": "tools"}])
        )
    );
    let resp = request(
        fake.host(),
        fake.port(),
        "GET",
        "/me",
        &[(name, &value)],
        None,
    );
    assert_eq!(
        (resp.status, json(&resp.body)),
        (200, serde_json::json!({"login": "synthetic-user"}))
    );
    let payload = serde_json::to_vec(&serde_json::json!({"title": "first"})).unwrap();
    let resp = request(
        fake.host(),
        fake.port(),
        "POST",
        "/repos/demo/issues",
        &[(name, &value), ("Content-Type", "application/json")],
        Some(&payload),
    );
    assert_eq!(resp.status, 201);
    assert_eq!(
        json(&resp.body),
        serde_json::json!({"number": 1, "title": "first", "repo": "demo"})
    );
    let resp = request(
        fake.host(),
        fake.port(),
        "POST",
        "/repos/demo/issues",
        &[(name, &value)],
        Some(b"not json"),
    );
    assert_eq!(resp.status, 400);
    let resp = request(
        fake.host(),
        fake.port(),
        "DELETE",
        "/repos/demo",
        &[(name, &value)],
        None,
    );
    assert_eq!((resp.status, resp.body.clone()), (204, Vec::new()));
    let resp = request(
        fake.host(),
        fake.port(),
        "GET",
        "/nope",
        &[(name, &value)],
        None,
    );
    assert_eq!(resp.status, 404);
    let resp = request(fake.host(), fake.port(), "GET", "/repos", &[], None);
    assert_eq!(resp.status, 401);
}

#[test]
fn leak_endpoints_really_leak() {
    let fake = FakeUpstream::new(SECRET).start();
    let (name, value) = auth_header(SECRET);
    let resp = request(
        fake.host(),
        fake.port(),
        "GET",
        "/echo-headers",
        &[(name, &value), ("X-Extra", "v")],
        None,
    );
    assert_eq!(resp.status, 200);
    let echoed = &json(&resp.body)["headers"];
    assert_eq!(echoed["Authorization"], format!("Bearer {SECRET}"));
    let resp = request(
        fake.host(),
        fake.port(),
        "GET",
        "/redirect",
        &[(name, &value)],
        None,
    );
    assert_eq!(resp.status, 302);
    assert!(resp.headers.get("location").unwrap().contains(SECRET));
    assert!(String::from_utf8_lossy(&resp.body).contains(SECRET));
    let resp = request(
        fake.host(),
        fake.port(),
        "GET",
        "/redirect-external",
        &[(name, &value)],
        None,
    );
    assert_eq!(
        (resp.status, resp.headers.get("location").unwrap().as_str()),
        (302, "http://evil.invalid/")
    );
    let resp = request(
        fake.host(),
        fake.port(),
        "GET",
        "/debug/token",
        &[(name, &value)],
        None,
    );
    assert_eq!(json(&resp.body), serde_json::json!({"token": SECRET}));
    use base64::Engine as _;
    let resp = request(
        fake.host(),
        fake.port(),
        "GET",
        "/base64-leak",
        &[(name, &value)],
        None,
    );
    assert_eq!(
        json(&resp.body)["blob"],
        base64::engine::general_purpose::STANDARD.encode(SECRET.as_bytes())
    );
    let resp = request(
        fake.host(),
        fake.port(),
        "GET",
        "/set-cookie",
        &[(name, &value)],
        None,
    );
    assert!(resp.headers.get("set-cookie").unwrap().contains(SECRET));
    let resp = request(
        fake.host(),
        fake.port(),
        "GET",
        "/leak?auth=abc",
        &[(name, &value)],
        None,
    );
    assert_eq!(json(&resp.body), serde_json::json!({"leaked": "abc"}));
}

#[test]
fn urlencoded_leak_emits_both_hex_casings() {
    let reserved = "synthetic/token+reserved=chars:0123456789";
    let fake = FakeUpstream::new(reserved).start();
    let auth = format!("Bearer {reserved}");
    let resp = request(
        fake.host(),
        fake.port(),
        "GET",
        "/urlencoded-leak",
        &[("Authorization", &auth)],
        None,
    );
    assert_eq!(
        (resp.status, json(&resp.body)),
        (
            200,
            serde_json::json!({"blob": "synthetic%2Ftoken%2Breserved%3Dchars%3A0123456789"})
        )
    );
    let resp = request(
        fake.host(),
        fake.port(),
        "GET",
        "/urlencoded-leak?case=lower",
        &[("Authorization", &auth)],
        None,
    );
    assert_eq!(
        (resp.status, json(&resp.body)),
        (
            200,
            serde_json::json!({"blob": "synthetic%2ftoken%2breserved%3dchars%3a0123456789"})
        )
    );

    let fake2 = FakeUpstream::new(SECRET).start();
    let (name, value) = auth_header(SECRET);
    let resp = request(
        fake2.host(),
        fake2.port(),
        "GET",
        "/urlencoded-leak?case=lower",
        &[(name, &value)],
        None,
    );
    assert_eq!(
        (resp.status, json(&resp.body)),
        (200, serde_json::json!({"blob": SECRET}))
    );
}

#[test]
fn encoded_leak_emits_every_named_form() {
    use base64::Engine as _;
    let secret = SECRET_ENCODINGS;
    let raw = secret.as_bytes();
    let percent = zeropw_percent_encode(secret, false);
    let percent_plus = zeropw_percent_encode(secret, true);
    let mut expected: HashMap<&str, String> = HashMap::new();
    expected.insert("raw", secret.to_string());
    expected.insert(
        "base64",
        base64::engine::general_purpose::STANDARD.encode(raw),
    );
    expected.insert(
        "base64-unpadded",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(raw),
    );
    expected.insert(
        "base64url",
        base64::engine::general_purpose::URL_SAFE.encode(raw),
    );
    expected.insert(
        "base64url-unpadded",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw),
    );
    expected.insert("percent-upper", percent.clone());
    expected.insert("percent-lower", lower_percent_triplets(&percent));
    expected.insert("percent-plus-upper", percent_plus.clone());
    expected.insert("percent-plus-lower", lower_percent_triplets(&percent_plus));
    expected.insert("hex-lower", hex::encode(raw));
    expected.insert("hex-upper", hex::encode(raw).to_uppercase());
    expected.insert("json", zeropw::pyjson::encode_str(secret, true));
    expected.insert("json-unicode", zeropw::pyjson::encode_str(secret, false));
    expected.insert("html", zeropw_html_escape(secret));

    let expected_keys: std::collections::HashSet<&str> = expected.keys().copied().collect();
    let forms_set: std::collections::HashSet<&str> = ENCODED_LEAK_FORMS.iter().copied().collect();
    assert_eq!(expected_keys, forms_set);
    assert_ne!(expected["percent-upper"], expected["percent-lower"]);
    assert_eq!(expected["percent-upper"], expected["percent-plus-upper"]);
    assert_ne!(expected["base64"], expected["base64url"]);
    assert_ne!(expected["hex-lower"], expected["hex-upper"]);
    assert_ne!(expected["json"], format!("\"{secret}\""));
    assert_ne!(expected["html"], secret);
    for form in ENCODED_LEAK_FORMS {
        if *form != "raw" {
            assert!(!expected[form].contains(secret), "{form}");
        }
    }

    let fake = FakeUpstream::new(secret).start();
    let auth = format!("Bearer {secret}");
    for form in ENCODED_LEAK_FORMS {
        let resp = request(
            fake.host(),
            fake.port(),
            "GET",
            &format!("/encoded-leak?form={form}"),
            &[("Authorization", &auth)],
            None,
        );
        assert_eq!(
            (
                resp.status,
                resp.headers.get("content-type").unwrap().as_str()
            ),
            (200, "text/plain"),
            "{form}"
        );
        assert_eq!(
            resp.body,
            format!("leak=[{}]\n", expected[form]).into_bytes()
        );
        assert_eq!(
            encoded_credential(&fake, form).as_deref(),
            Some(expected[form].as_str())
        );
    }
    for path in [
        "/encoded-leak",
        "/encoded-leak?form=nope",
        "/encoded-leak?form=basic",
    ] {
        let resp = request(
            fake.host(),
            fake.port(),
            "GET",
            path,
            &[("Authorization", &auth)],
            None,
        );
        assert_eq!(
            (resp.status, json(&resp.body)),
            (400, serde_json::json!({"error": "unknown_form"})),
            "{path}"
        );
    }
    assert_eq!(encoded_credential(&fake, "basic"), None);

    let basic = FakeUpstream::new(secret)
        .mode_basic("synthetic-user")
        .start();
    let pair = format!("synthetic-user:{secret}");
    let basic_auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(pair.as_bytes())
    );
    let mut basic_expected: HashMap<&str, String> = HashMap::new();
    basic_expected.insert(
        "basic",
        base64::engine::general_purpose::STANDARD.encode(pair.as_bytes()),
    );
    basic_expected.insert(
        "basic-unpadded",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(pair.as_bytes()),
    );
    basic_expected.insert(
        "basic-url",
        base64::engine::general_purpose::URL_SAFE.encode(pair.as_bytes()),
    );
    let basic_keys: std::collections::HashSet<&str> = basic_expected.keys().copied().collect();
    let basic_forms_set: std::collections::HashSet<&str> =
        BASIC_LEAK_FORMS.iter().copied().collect();
    assert_eq!(basic_keys, basic_forms_set);
    let mut forms: Vec<&str> = BASIC_LEAK_FORMS.to_vec();
    forms.push("raw");
    forms.push("hex-upper");
    for form in forms {
        let resp = request(
            basic.host(),
            basic.port(),
            "GET",
            &format!("/encoded-leak?form={form}"),
            &[("Authorization", &basic_auth)],
            None,
        );
        let value = basic_expected
            .get(form)
            .cloned()
            .unwrap_or_else(|| expected[form].clone());
        assert_eq!(
            (resp.status, resp.body.clone()),
            (200, format!("leak=[{value}]\n").into_bytes()),
            "{form}"
        );
    }
}

fn zeropw_percent_encode(text: &str, plus: bool) -> String {
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

fn zeropw_html_escape(text: &str) -> String {
    let mut out = String::new();
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

#[test]
fn stream_large_and_slow() {
    let fake = FakeUpstream::new(SECRET).start();
    let (name, value) = auth_header(SECRET);
    let mut stream = send_request(
        fake.host(),
        fake.port(),
        "GET",
        "/stream",
        &[(name, &value)],
        None,
    );
    let (status, headers, leftover) = read_head(&mut stream);
    assert_eq!(status, 200);
    assert_eq!(headers.get("transfer-encoding").unwrap(), "chunked");
    let body = read_body(&mut stream, &headers, leftover);
    let expected: Vec<u8> = STREAM_PARTS.concat();
    assert_eq!(body, expected);

    let resp = request(
        fake.host(),
        fake.port(),
        "GET",
        "/large",
        &[(name, &value)],
        None,
    );
    assert_eq!((resp.status, resp.body.len()), (200, LARGE_BODY_SIZE));
    assert_eq!(
        resp.headers.get("content-length").unwrap(),
        &LARGE_BODY_SIZE.to_string()
    );

    let resp = request(
        fake.host(),
        fake.port(),
        "GET",
        "/slow?seconds=0.05",
        &[(name, &value)],
        None,
    );
    assert_eq!(
        (resp.status, json(&resp.body)),
        (200, serde_json::json!({"slept": 0.05}))
    );

    let resp = request(
        fake.host(),
        fake.port(),
        "HEAD",
        "/huge",
        &[(name, &value)],
        None,
    );
    assert_eq!(resp.status, 200);
}

#[test]
fn slow_endpoint_echoes_the_unclamped_min_only_seconds_value() {
    // Finding F-R4-6: Python computes `seconds = min(float(...), 30.0)`
    // and sleeps `max(seconds, 0.0)`, but echoes the *unclamped* `seconds`
    // -- confirmed against live `python3.12`: `?seconds=-5` sleeps 0 but
    // responds `{"slept": -5.0}`. The previous Rust version applied
    // `.clamp(0.0, 30.0)` before both the sleep and the echo, so a
    // negative value wrongly echoed `0.0`.
    let fake = FakeUpstream::new(SECRET).start();
    let (name, value) = auth_header(SECRET);
    let resp = request(
        fake.host(),
        fake.port(),
        "GET",
        "/slow?seconds=-5",
        &[(name, &value)],
        None,
    );
    assert_eq!(
        (resp.status, json(&resp.body)),
        (200, serde_json::json!({"slept": -5.0}))
    );
}

#[test]
fn slow_endpoint_does_not_panic_on_nan_seconds() {
    // Finding F-R4-6: `?seconds=nan` reaches `time.sleep(float("nan"))` in
    // Python, which raises `ValueError("Invalid value NaN (not a
    // number)")` inside the handler, uncaught -- the connection closes
    // with no response written, and the gateway relay reports `502
    // upstream_protocol_error` (both confirmed against a live end-to-end
    // probe). The previous Rust version let NaN survive `.clamp(0.0,
    // 30.0)` (a NaN input to `f64::clamp` returns `self`, i.e. NaN
    // unchanged, matching neither bound) and then called
    // `Duration::from_secs_f64(NaN)`, which PANICS in the fixture's
    // per-connection handler thread -- a panic on ordinary relayed input,
    // which PORTING.md §4 forbids. A closed, empty-bodied connection is
    // NOT enough to tell "panicked" apart from "returned early without
    // responding" (a panicking thread unwinds and drops the socket too, so
    // the client sees the exact same EOF either way) -- a temporary panic
    // hook is installed to observe whether any thread actually panicked
    // while this request was in flight.
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let panicked = Arc::new(AtomicBool::new(false));
    let observed = panicked.clone();
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |_info| {
        observed.store(true, Ordering::SeqCst);
    }));

    let fake = FakeUpstream::new(SECRET).start();
    let (name, value) = auth_header(SECRET);
    let mut stream = send_request(
        fake.host(),
        fake.port(),
        "GET",
        "/slow?seconds=nan",
        &[(name, &value)],
        None,
    );
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).unwrap_or(0);

    std::panic::set_hook(previous_hook);

    assert_eq!(
        n, 0,
        "the connection must close with no response bytes (matching Python's uncaught \
         ValueError), not hang"
    );
    assert!(
        !panicked.load(Ordering::SeqCst),
        "the /slow handler must not panic on NaN seconds (PORTING.md §4)"
    );
}

#[test]
fn huge_streams_more_than_eight_mib() {
    let fake = FakeUpstream::new(SECRET).start();
    let (name, value) = auth_header(SECRET);
    let mut stream = send_request(
        fake.host(),
        fake.port(),
        "GET",
        "/huge",
        &[(name, &value)],
        None,
    );
    let (status, headers, mut leftover) = read_head(&mut stream);
    assert_eq!(status, 200);
    let content_length: usize = headers.get("content-length").unwrap().parse().unwrap();
    assert!(content_length > 8 * 1024 * 1024);
    // Read up to 1024 bytes of body total (leftover already captured from
    // the same reads as the headers, plus more if needed), then hang up
    // early on purpose (drop `stream`) -- mirrors Python's `resp.read(1024)`.
    while leftover.len() < 1024 {
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).expect("read partial body");
        assert!(n > 0);
        leftover.extend_from_slice(&buf[..n]);
    }
    assert!(leftover.len() >= 1024);
}

#[test]
fn basic_and_header_modes() {
    let basic = FakeUpstream::new(SECRET)
        .mode_basic("synthetic-user")
        .start();
    use base64::Engine as _;
    let pair = base64::engine::general_purpose::STANDARD.encode(format!("synthetic-user:{SECRET}"));
    let resp = request(
        basic.host(),
        basic.port(),
        "GET",
        "/me",
        &[("Authorization", &format!("Basic {pair}"))],
        None,
    );
    assert_eq!(resp.status, 200);
    let resp = request(
        basic.host(),
        basic.port(),
        "GET",
        "/me",
        &[("Authorization", &format!("Bearer {SECRET}"))],
        None,
    );
    assert_eq!(resp.status, 401);
    assert!(
        resp.headers
            .get("www-authenticate")
            .unwrap()
            .starts_with("Basic ")
    );

    let custom = FakeUpstream::new(SECRET)
        .mode_header("X-Api-Key", "Key ")
        .start();
    let resp = request(
        custom.host(),
        custom.port(),
        "GET",
        "/me",
        &[("X-Api-Key", &format!("Key {SECRET}"))],
        None,
    );
    assert_eq!(resp.status, 200);
    let resp = request(
        custom.host(),
        custom.port(),
        "GET",
        "/me",
        &[("X-Api-Key", SECRET)],
        None,
    );
    assert_eq!(resp.status, 401);
}

#[test]
fn base64_embedded_leak_moves_the_credential_across_alignments() {
    use base64::Engine as _;
    let fake = FakeUpstream::new(SECRET).start();
    let (name, value) = auth_header(SECRET);
    let whole_groups = SECRET.len() - SECRET.len() % 3;
    let aligned =
        base64::engine::general_purpose::STANDARD.encode(&SECRET.as_bytes()[..whole_groups]);
    for alphabet in ["std", "url"] {
        for offset in 0..3 {
            for wrap in [0, 60] {
                let resp = request(
                    fake.host(),
                    fake.port(),
                    "GET",
                    &format!(
                        "/base64-embedded-leak?offset={offset}&wrap={wrap}&alphabet={alphabet}"
                    ),
                    &[(name, &value)],
                    None,
                );
                assert_eq!(
                    (
                        resp.status,
                        resp.headers.get("content-type").unwrap().as_str()
                    ),
                    (200, "application/json")
                );
                let content = json(&resp.body)["content"].as_str().unwrap().to_string();
                assert_eq!(content.contains('\n'), wrap > 0);
                let decoded = if alphabet == "url" {
                    base64::engine::general_purpose::URL_SAFE
                        .decode(content.replace('\n', ""))
                        .unwrap()
                } else {
                    base64::engine::general_purpose::STANDARD
                        .decode(content.replace('\n', ""))
                        .unwrap()
                };
                assert!(contains_subslice(&decoded, SECRET.as_bytes()));
                assert!(!String::from_utf8_lossy(&resp.body).contains(SECRET));
            }
        }
    }
    for offset in 0..3 {
        let resp = request(
            fake.host(),
            fake.port(),
            "GET",
            &format!("/base64-embedded-leak?offset={offset}"),
            &[(name, &value)],
            None,
        );
        let content = json(&resp.body)["content"].as_str().unwrap().to_string();
        assert_eq!(content.contains(&aligned), offset == 0, "offset={offset}");
    }
    let resp = request(
        fake.host(),
        fake.port(),
        "GET",
        "/base64-embedded-leak?offset=x",
        &[(name, &value)],
        None,
    );
    assert_eq!(
        (resp.status, json(&resp.body)),
        (400, serde_json::json!({"error": "invalid_query"}))
    );
    let resp = request(
        fake.host(),
        fake.port(),
        "GET",
        "/base64-embedded-leak?offset=1",
        &[],
        None,
    );
    assert_eq!(resp.status, 401);
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// Finding X-6: `POST /repos/issues` (no repo name at all) makes the
// `/repos/` prefix and the `/issues` suffix overlap by one character, so the
// computed slice bounds are backwards. Measured against live `python3.12`
// over a raw socket, this does NOT error -- Python's `path[7:-7]` clamps a
// backwards slice to `''` -- the fake answers `201 {"number": 1, "repo": "",
// "title": "hi"}`. Before the fix, `&path[7..path.len() - 7]` panicked the
// connection-handling thread instead (`byte range starts at 7 but ends at
// 6`), which the client observed as the connection closing with no
// response at all -- reachable through the real relay as
// `502 upstream_protocol_error` from an ordinary agent with a `POST` grant.
#[test]
fn post_repos_issues_with_no_repo_name_matches_python_clamp() {
    let fake = FakeUpstream::new(SECRET).start();
    let (name, value) = auth_header(SECRET);
    let payload = serde_json::to_vec(&serde_json::json!({"title": "hi"})).unwrap();
    let resp = request(
        fake.host(),
        fake.port(),
        "POST",
        "/repos/issues",
        &[(name, &value), ("Content-Type", "application/json")],
        Some(&payload),
    );
    assert_eq!(resp.status, 201);
    assert_eq!(
        json(&resp.body),
        serde_json::json!({"number": 1, "title": "hi", "repo": ""})
    );
}

// Finding X-7: `unquote_plus` used to slice a latin-1-decoded `String` at
// raw UTF-8 byte offsets, which panics whenever a multi-byte-encoded
// character (any original wire byte >= 0x80) lands across a slice boundary
// -- this is a fixed bug (`gateway.rs`'s `percent_decode_lossy`, finding
// F-R2-1) reintroduced as a byte-identical copy in this sibling file.
// `%A` followed by the raw byte 0x80 is exactly such a case: `%A` is not a
// valid `%XX` escape (only one hex digit follows the `%`), so the old code
// tried to decode past the raw high byte and sliced into the middle of its
// two-byte UTF-8 encoding. Measured against live `python3.12`,
// `parse_qs("auth=%A\x80")` never raises -- it returns
// `{"auth": ["%A\x80"]}` unchanged -- so the real relay reaching this route
// must answer normally too, not drop the connection. This request reaches
// `/leak` (which requires a valid `Authorization` header, checked before
// query parsing), so it is sent over a raw socket to embed the literal
// non-UTF8-safe byte 0x80 that the `request()`/`send_request()` helpers
// (which build the request line through a Rust `&str`) cannot carry.
#[test]
fn query_percent_followed_by_raw_high_byte_does_not_panic() {
    let fake = FakeUpstream::new(SECRET).start();
    let mut stream = TcpStream::connect((fake.host(), fake.port())).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut req = Vec::new();
    req.extend_from_slice(b"GET /leak?auth=%A\x80 HTTP/1.1\r\n");
    req.extend_from_slice(format!("Host: {}:{}\r\n", fake.host(), fake.port()).as_bytes());
    req.extend_from_slice(format!("Authorization: Bearer {SECRET}\r\n").as_bytes());
    req.extend_from_slice(b"\r\n");
    stream.write_all(&req).expect("write request");

    let (status, headers, leftover) = read_head(&mut stream);
    assert_eq!(
        status, 200,
        "connection must not die: handler must not panic"
    );
    let body = read_body(&mut stream, &headers, leftover);
    let leaked = json(&body)["leaked"].as_str().unwrap().to_string();
    // Python: `parse_qs("auth=%A\x80")["auth"][0] == "%A\x80"` -- the `%A`
    // is left completely undecoded (not even the literal `%` consumed
    // differently) and the raw high byte passes through unchanged.
    let expected: String = ['%', 'A', '\u{0080}'].iter().collect();
    assert_eq!(leaked, expected);
}

#[test]
fn stop_is_idempotent_and_reusable_after_restart() {
    let mut other = FakeUpstream::new(SECRET).start();
    let resp = request(
        other.host(),
        other.port(),
        "GET",
        "/me",
        &[("Authorization", &format!("Bearer {SECRET}"))],
        None,
    );
    assert_eq!(resp.status, 200);
    other.stop();
    other.stop(); // idempotent
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| other.port()));
    assert!(result.is_err());
}

#[test]
fn invalid_modes_are_refused_like_python() {
    // `with self.assertRaises(ValueError): FakeUpstream(SECRET, mode="digest")`
    assert_eq!(
        FakeUpstream::with_mode(SECRET, "digest", None).err(),
        Some("unsupported fake upstream mode")
    );
    // `with self.assertRaises(ValueError): FakeUpstream(SECRET, mode="basic")`
    for username in [None, Some("")] {
        assert_eq!(
            FakeUpstream::with_mode(SECRET, "basic", username).err(),
            Some("basic mode requires basic_username")
        );
    }
    // `mode_basic("")` panics like Python's constructor raises; checked in
    // a child process so no panic happens in this test process (another
    // test here watches for panics with a process-wide hook).
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "empty_basic_username_child",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ZEROPW_EMPTY_BASIC_CHILD", "1")
        .output()
        .unwrap();
    assert!(!child.status.success());
    assert!(String::from_utf8_lossy(&child.stderr).contains("basic mode requires basic_username"));
    let basic = FakeUpstream::with_mode(SECRET, "basic", Some("synthetic-user"))
        .unwrap()
        .start();
    assert_eq!(
        (basic.mode(), basic.basic_username(), basic.credential()),
        ("basic", Some("synthetic-user"), SECRET)
    );
    let custom = FakeUpstream::new(SECRET).mode_header("X-Api-Key", "Key ");
    assert_eq!(
        (custom.mode(), custom.header_name(), custom.value_prefix()),
        ("header", "X-Api-Key", "Key ")
    );
}

/// Runs only as the child of `invalid_modes_are_refused_like_python`.
#[test]
fn empty_basic_username_child() {
    if std::env::var_os("ZEROPW_EMPTY_BASIC_CHILD").is_some() {
        let _ = FakeUpstream::new(SECRET).mode_basic("");
    }
}

#[test]
fn issue_counter_counts_created_issues() {
    let fake = FakeUpstream::new(SECRET).start();
    assert_eq!(fake.issue_counter(), 0);
    let (name, value) = auth_header(SECRET);
    for expected in 1..=2 {
        let resp = request(
            fake.host(),
            fake.port(),
            "POST",
            "/repos/demo/issues",
            &[(name, &value)],
            Some(br#"{"title": "t"}"#),
        );
        assert_eq!(resp.status, 201);
        assert_eq!(fake.issue_counter(), expected);
    }
}

/// The Python prototype as the oracle (script on stdin, repository on
/// `PYTHONPATH`).
fn python(script: &str) -> String {
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".into());
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let mut child = std::process::Command::new(&interpreter)
        .arg("-")
        .env("PYTHONPATH", root)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot run {interpreter}: {e}"));
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "python oracle failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// Python's `FakeUpstream` answering each raw request in `CASES` (base64
/// JSON): send, half-close, read to EOF. Prints the replies, then what the
/// fixture recorded.
const PY_FAKE_EXCHANGE: &str = r#"
import base64, json, socket
from zeropw.fake_upstream import FakeUpstream
fake = FakeUpstream(SECRET).start()
replies = []
for raw in json.loads(base64.b64decode(CASES)):
    with socket.create_connection((fake.host, fake.port), timeout=10) as sock:
        sock.sendall(base64.b64decode(raw))
        sock.shutdown(socket.SHUT_WR)
        out = b""
        try:
            while chunk := sock.recv(65536):
                out += chunk
        except OSError:
            pass
    replies.append(base64.b64encode(out).decode())
print(json.dumps(replies))
print(json.dumps([[r["method"], r["path"], r["headers"], base64.b64encode(r["body"]).decode()]
                  for r in fake.requests], sort_keys=True))
fake.stop()
"#;

fn raw_exchange(port: u16, raw: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(raw).unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    out
}

/// The status line and body of a reply (`Server`/`Date` values are the
/// fixture's own boilerplate, pinned separately).
fn status_and_body(reply: &[u8]) -> (String, Vec<u8>) {
    let split = find(reply, b"\r\n\r\n").map_or(reply.len(), |i| i + 4);
    let head = String::from_utf8_lossy(&reply[..split]).into_owned();
    let status = head.lines().next().unwrap_or("").to_string();
    (status, reply[split..].to_vec())
}

/// Methods without a `do_` handler, `parse_qs` and `int()`/`float()` query
/// rules, a short body, folded and malformed header lines, `//` paths and
/// fragments -- reply status lines and bodies and the recorded requests
/// match Python's fixture.
#[test]
fn request_handling_matches_the_python_fixture() {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD;
    let auth = format!("Authorization: Bearer {SECRET}\r\n");
    let get = |target: &str| format!("GET {target} HTTP/1.1\r\n{auth}\r\n").into_bytes();
    let cases: Vec<Vec<u8>> = vec![
        format!("TRACE /me HTTP/1.1\r\n{auth}\r\n").into_bytes(),
        format!("PROPFIND /me HTTP/1.1\r\n{auth}Content-Length: 2\r\n\r\n{{}}").into_bytes(),
        get("/base64-embedded-leak?offset=&wrap=60"),
        get("/base64-embedded-leak?offset=%202%20&wrap=1_0"),
        get("/base64-embedded-leak?offset=%2B1&wrap"),
        get("/base64-embedded-leak?offset=x"),
        get("/base64-embedded-leak?offset=\u{663}"),
        get("/slow?seconds=0.0_5"),
        get("/slow?seconds=+0.01"),
        get("/slow?seconds=bogus"),
        get("/leak?auth=a&auth=b"),
        get("/leak?auth=&auth=c"),
        get("/leak?=x&auth"),
        get("//me"),
        get("/me#frag?x=1"),
        get("/encoded-leak?form=raw#frag"),
        format!("POST /repos/demo/issues HTTP/1.1\r\n{auth}Content-Length: 50\r\n\r\n{{\"title\"").into_bytes(),
        format!("POST /repos/demo/issues HTTP/1.1\r\n{auth}Content-Length:  1_4 \r\n\r\n{{\"title\": \"t\"}}").into_bytes(),
        format!("GET /echo-headers HTTP/1.1\r\n{auth}X-Folded: a\r\n b\r\n\tc\r\nX-Pad: v  \r\n\r\n").into_bytes(),
        format!("GET /echo-headers HTTP/1.1\r\nX-Before: 1\r\nNot a header\r\n{auth}\r\n").into_bytes(),
        format!("GET /echo-headers HTTP/1.1\r\n{auth}:empty-name\r\nX-After: 2\r\n\r\n").into_bytes(),
        format!("GET /echo-headers HTTP/1.1\r\n{auth}X-Last: end").into_bytes(),
    ];
    let encoded: Vec<String> = cases.iter().map(|c| engine.encode(c)).collect();
    let script = format!(
        "SECRET = {SECRET:?}\nCASES = '{}'\n{PY_FAKE_EXCHANGE}",
        engine.encode(serde_json::to_string(&encoded).unwrap())
    );
    let out = python(&script);
    let mut lines = out.lines();
    let python_replies: Vec<String> = serde_json::from_str(lines.next().unwrap()).unwrap();
    let python_recorded: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();

    let fake = FakeUpstream::new(SECRET).start();
    for (case, python) in cases.iter().zip(&python_replies) {
        let python = engine.decode(python).unwrap();
        let rust = raw_exchange(fake.port(), case);
        assert_eq!(
            status_and_body(&rust),
            status_and_body(&python),
            "request {:?}",
            String::from_utf8_lossy(case)
        );
    }
    let rust_recorded: Vec<serde_json::Value> = fake
        .requests()
        .into_iter()
        .map(|r| {
            let headers: serde_json::Map<String, serde_json::Value> = r
                .headers
                .into_iter()
                .map(|(k, v)| (k, serde_json::Value::String(v)))
                .collect();
            serde_json::json!([r.method, r.path, headers, engine.encode(&r.body)])
        })
        .collect();
    assert_eq!(serde_json::Value::from(rust_recorded), python_recorded);
    // The shapes the audit named, on Python's own replies.
    let status = |i: usize| status_and_body(&engine.decode(&python_replies[i]).unwrap()).0;
    assert_eq!(status(0), "HTTP/1.1 501 Unsupported method ('TRACE')");
    assert_eq!(status(2), "HTTP/1.1 200 OK");
    assert_eq!(status(16), "HTTP/1.1 400 Bad Request");
    assert_eq!(python_recorded.as_array().unwrap().len(), cases.len() - 2);
}
