//! Credential-free sample CLI; run only with an opaque gateway base URL.
use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use zeropw::pyjson::{self, DumpOptions};

const MAX_BODY: usize = 1024 * 1024;
const MAX_HEADER: usize = 64 * 1024;
const PROBES: [&str; 8] = [
    ".zeropw",
    ".zeropw.json",
    ".netrc",
    ".ssh/id_ed25519",
    ".ssh/id_rsa",
    ".config/zeropw",
    ".aws/credentials",
    ".git-credentials",
];

/// `print(json.dumps(value, sort_keys=True))`.
fn print_json(value: &Value) {
    match pyjson::dumps(value, DumpOptions::default_sorted()) {
        Ok(text) => println!("{text}"),
        Err(_) => println!("{{\"error\": \"unrenderable_output\"}}"),
    }
}

fn fail(reason: &str, detail: Option<&str>, code: i32) -> i32 {
    let mut payload = json!({"error":reason});
    if let Some(detail) = detail.filter(|d| !d.is_empty()) {
        payload["detail"] = json!(detail);
    }
    print_json(&payload);
    code
}

/// `str(URLError.reason)` for a socket error, e.g. `[Errno 111] Connection refused`.
fn os_error_reason(error: &std::io::Error) -> String {
    let text = error.to_string();
    match error.raw_os_error() {
        Some(code) => {
            let message = text
                .strip_suffix(&format!(" (os error {code})"))
                .unwrap_or(&text);
            format!("[Errno {code}] {message}")
        }
        None => text,
    }
}

enum Failure {
    /// `urllib.error.URLError`: `str(exc.reason)`.
    Unreachable(String),
    /// A base URL or reply this minimal client cannot use.
    Malformed,
}

/// `urllib.parse.urlsplit` of the base URL: scheme, host (brackets removed
/// from an IPv6 literal), port (scheme default when absent), Host header value
/// and base path.
struct BaseUrl {
    tls: bool,
    host: String,
    port: u16,
    host_header: String,
    path: String,
}

fn split_base(base: &str) -> Option<BaseUrl> {
    let (tls, rest) = if let Some(rest) = base.strip_prefix("https://") {
        (true, rest)
    } else {
        (false, base.strip_prefix("http://")?)
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (host, tail) = inner.split_once(']')?;
        match tail {
            "" => (host, None),
            _ => (host, Some(tail.strip_prefix(':')?)),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let port = match port {
        None | Some("") => {
            if tls {
                443
            } else {
                80
            }
        }
        Some(p) => p.parse().ok()?,
    };
    if host.is_empty() || host.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return None;
    }
    Some(BaseUrl {
        tls,
        host: host.to_owned(),
        port,
        host_header: authority.to_owned(),
        path: path.to_owned(),
    })
}

/// `ssl.create_default_context()`: the platform trust store, hostname checked.
fn tls_stream(
    tcp: TcpStream,
    host: &str,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, Failure> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name =
        rustls_pki_types::ServerName::try_from(host.to_owned()).map_err(|_| Failure::Malformed)?;
    let connection =
        rustls::ClientConnection::new(Arc::new(config), name).map_err(|_| Failure::Malformed)?;
    Ok(rustls::StreamOwned::new(connection, tcp))
}

fn request(
    base: &str,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<(u16, Value), Failure> {
    let url = split_base(base).ok_or(Failure::Malformed)?;
    let tcp = TcpStream::connect((url.host.as_str(), url.port))
        .map_err(|e| Failure::Unreachable(os_error_reason(&e)))?;
    let timeout = Some(Duration::from_secs(30));
    tcp.set_read_timeout(timeout)
        .map_err(|_| Failure::Malformed)?;
    tcp.set_write_timeout(timeout)
        .map_err(|_| Failure::Malformed)?;
    let target = format!("{}{path}", url.path);
    if url.tls {
        let mut stream = tls_stream(tcp, &url.host)?;
        exchange(&mut stream, &url.host_header, method, &target, body)
    } else {
        let mut stream = tcp;
        exchange(&mut stream, &url.host_header, method, &target, body)
    }
    .map_err(|()| Failure::Malformed)
}

fn exchange<S: Read + Write>(
    stream: &mut S,
    host_header: &str,
    method: &str,
    target: &str,
    body: Option<&Value>,
) -> Result<(u16, Value), ()> {
    // `json.dumps(body).encode("utf-8")`.
    let data = match body {
        Some(value) => pyjson::dumps(value, DumpOptions::plain()).map_err(|_| ())?,
        None => String::new(),
    };
    let mut message = format!(
        "{method} {target} HTTP/1.1\r\nHost: {host_header}\r\nAuthorization: Bearer democli-placeholder\r\nAccept: application/json\r\nUser-Agent: democli/1\r\nConnection: close\r\n"
    );
    if body.is_some() {
        message.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            data.len()
        ));
    }
    message.push_str("\r\n");
    message.push_str(&data);
    stream.write_all(message.as_bytes()).map_err(|_| ())?;
    stream.flush().map_err(|_| ())?;
    let mut raw = Vec::new();
    let mut limited = stream.take((MAX_HEADER + MAX_BODY) as u64);
    // A TLS peer that closes without close_notify still delivered its body.
    if let Err(error) = limited.read_to_end(&mut raw)
        && (raw.is_empty() || error.kind() != std::io::ErrorKind::UnexpectedEof)
    {
        return Err(());
    }
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or(())?;
    if split > MAX_HEADER {
        return Err(());
    }
    let header = std::str::from_utf8(&raw[..split]).map_err(|_| ())?;
    let status = header
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or(())?;
    let bytes = &raw[split + 4..];
    let bytes = &bytes[..bytes.len().min(MAX_BODY)];
    // `json.loads(raw.decode("utf-8"))`, else the replacement-decoded text.
    let parsed = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| pyjson::loads(text).ok())
        .unwrap_or_else(|| json!(String::from_utf8_lossy(bytes).into_owned()));
    Ok((status, parsed))
}

fn call(base: &str, method: &str, path: &str, body: Option<&Value>) -> i32 {
    match request(base, method, path, body) {
        Ok((status, body)) => {
            print_json(&json!({"status":status,"body":body}));
            if (200..300).contains(&status) { 0 } else { 1 }
        }
        Err(Failure::Unreachable(reason)) => fail(
            "unreachable",
            Some(&reason.chars().take(200).collect::<String>()),
            1,
        ),
        Err(Failure::Malformed) => fail("unreachable", Some("gateway unavailable"), 1),
    }
}

fn probe(home: &str, name: &str) -> String {
    if home.is_empty() {
        return "no home".to_owned();
    }
    let path = Path::new(home).join(name);
    let unreadable =
        |error: &std::io::Error| format!("unreadable ({})", zeropw::pystr::os_error_class(error));
    match File::open(path) {
        Ok(file) => {
            let mut buf = Vec::new();
            match file.take(4096).read_to_end(&mut buf) {
                Ok(n) => format!("present ({n} bytes read, not shown)"),
                Err(error) if error.raw_os_error() == Some(libc::EISDIR) => "directory".to_owned(),
                Err(error) => unreadable(&error),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "missing".to_owned(),
        Err(error) if error.raw_os_error() == Some(libc::EISDIR) => "directory".to_owned(),
        Err(error) => unreadable(&error),
    }
}

fn steal(argv: &[String], base: &str) -> i32 {
    let home = env::var("HOME").unwrap_or_default();
    let mut names = env::vars().map(|(name, _)| name).collect::<Vec<_>>();
    names.sort();
    let mut entries = if home.is_empty() {
        Vec::new()
    } else {
        fs::read_dir(&home)
            .map(|items| {
                items
                    .filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    entries.sort();
    let probes = PROBES
        .iter()
        .map(|name| ((*name).to_owned(), json!(probe(&home, name))))
        .collect::<serde_json::Map<String, Value>>();
    let redacted = if let Some((origin, _)) = base.split_once("/h/") {
        format!("{origin}/h/<opaque-handle-redacted>")
    } else if base.is_empty() {
        "<unset>".to_owned()
    } else {
        "<opaque>".to_owned()
    };
    print_json(&json!({
        "env_names":names,"argv":argv,"base_url":redacted,"home":home,
        "home_entries":entries,"probes":probes,
        "conclusion":"no credential in environment, arguments, home directory or credential files; only an opaque base URL that the gateway re-checks against policy"
    }));
    0
}

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let usage = "democli list-repos | create-issue <repo> <title> | whoami | steal";
    let Some(command) = args.first().map(String::as_str) else {
        std::process::exit(fail("usage", Some(usage), 2));
    };
    if command == "steal" {
        std::process::exit(steal(
            &args,
            &env::var("ZEROPW_API_BASE_URL").unwrap_or_default(),
        ));
    }
    if !["list-repos", "create-issue", "whoami"].contains(&command) {
        std::process::exit(fail(
            "unknown_command",
            Some(&command.chars().take(64).collect::<String>()),
            2,
        ));
    }
    if command == "create-issue" && args.len() != 3 {
        std::process::exit(fail("usage", Some("create-issue <repo> <title>"), 2));
    }
    // Python validates the repository before it reads the base URL.
    if command == "create-issue" {
        let repo = &args[1];
        if repo.is_empty()
            || repo.contains('/')
            || repo.contains("..")
            || repo.bytes().any(|b| b <= b' ' || b == 0x7f)
        {
            std::process::exit(fail("invalid_repo", None, 1));
        }
    }
    let base = env::var("ZEROPW_API_BASE_URL")
        .unwrap_or_default()
        .trim()
        .trim_end_matches('/')
        .to_owned();
    if base.is_empty() {
        std::process::exit(fail(
            "base_url_unset",
            Some("set ZEROPW_API_BASE_URL to the ZeroPW base URL"),
            2,
        ));
    }
    let code = match command {
        "list-repos" => call(&base, "GET", "/repos", None),
        "whoami" => call(&base, "GET", "/me", None),
        _ => call(
            &base,
            "POST",
            &format!("/repos/{}/issues", args[1]),
            Some(&json!({"title": args[2]})),
        ),
    };
    std::process::exit(code);
}
