//! Agent-side JSON CLI (`zeropw.agent_cli`). This module never opens the trusted state directory.

use std::collections::BTreeMap;
use std::env;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde_json::{Value, json};

use crate::argparse::{Arg, Outcome, Parser, Val};
use crate::pybase64;
use crate::pyjson::{self, DumpOptions};

const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_CHUNK_LINE_BYTES: usize = 8192;

/// `build_parser()`: plain `argparse` (abbreviations allowed, standard
/// `prog: error:` reporting), with the same tree and help text as
/// `zeropw/agent_cli.py`.
fn build_parser() -> Parser {
    let mut parser = Parser::new(
        "zeropw-agent",
        Some("ZeroPW agent tools client (JSON output)"),
        true,
    );
    parser.subparsers("command", None);
    parser.add_parser(
        "list-connections",
        Some("connections usable by this caller"),
        None,
    );
    let req = parser.add_parser(
        "request",
        Some("relay one HTTP request through the gateway"),
        None,
    );
    req.arg(Arg::opt("--connection").required())
        .arg(Arg::opt("--method").required())
        .arg(Arg::opt("--path").required());
    req.exclusive(
        false,
        vec![
            Arg::opt("--body-file").help("file whose bytes form the request body"),
            Arg::opt("--body").help("request body text (UTF-8)"),
        ],
    );
    req.arg(
        Arg::opt("--header")
            .append()
            .default(Val::List(Vec::new()))
            .metavar("'K: V'"),
    )
    .arg(Arg::opt("--request-id"));
    parser
        .add_parser(
            "exec",
            Some("run the connection's supported CLI; arguments follow '--'"),
            None,
        )
        .arg(Arg::opt("--connection").required())
        .arg(Arg::opt("--request-id"));
    parser
        .add_parser(
            "status",
            Some("state and captured output of one of your runs"),
            None,
        )
        .arg(Arg::opt("--run").required());
    parser
        .add_parser("cancel", Some("cancel one of your runs"), None)
        .arg(Arg::opt("--run").required());
    parser
}

#[derive(Default)]
struct Args {
    command: String,
    options: BTreeMap<String, Vec<String>>,
    extra: Vec<String>,
}

impl Args {
    fn get(&self, key: &str) -> Option<&str> {
        self.options
            .get(key)
            .and_then(|v| v.last())
            .map(String::as_str)
    }
}

/// Why argv did not produce [`Args`]: help printed (exit 0) or argparse's
/// `error()` (usage and `prog: error: message` on stderr, exit 2).
#[derive(Debug)]
enum ParseFail {
    Help(String),
    Usage(String),
}

/// `_split_exec_args` then `build_parser().parse_args(raw_argv)`.
fn parse(argv: &[String]) -> Result<Args, ParseFail> {
    let mut raw: Vec<String> = argv.to_vec();
    let mut extra = Vec::new();
    if raw.first().is_some_and(|c| c == "exec")
        && let Some(index) = raw.iter().position(|a| a == "--")
    {
        extra = raw.split_off(index + 1);
        raw.pop();
    }
    let parser = build_parser();
    let (namespace, extras) = match parser.parse_known_args(&raw) {
        Outcome::Parsed(namespace, extras) => (namespace, extras),
        Outcome::Help(text) => return Err(ParseFail::Help(text)),
        Outcome::Error {
            prog,
            usage,
            message,
        } => {
            return Err(ParseFail::Usage(format!(
                "{usage}{prog}: error: {message}\n"
            )));
        }
    };
    if !extras.is_empty() {
        return Err(ParseFail::Usage(format!(
            "{}zeropw-agent: error: unrecognized arguments: {}\n",
            parser.format_usage(),
            extras.join(" ")
        )));
    }
    let mut out = Args {
        extra,
        ..Args::default()
    };
    for (dest, value) in namespace {
        let values = match value {
            Val::Str(s) if dest == "command" => {
                out.command = s;
                continue;
            }
            Val::Str(s) => vec![s],
            Val::List(items) => items,
            _ => continue,
        };
        out.options.insert(dest.replace('_', "-"), values);
    }
    Ok(out)
}

fn payload(args: &Args) -> Result<Value, Value> {
    match args.command.as_str() {
        "list-connections" => Ok(json!({})),
        "status" | "cancel" => Ok(json!({"run_id": args.get("run")})),
        "exec" => {
            let mut v = json!({"connection": args.get("connection"), "argv": args.extra});
            if let Some(id) = args.get("request-id").filter(|s| !s.is_empty()) {
                v["request_id"] = json!(id);
            }
            Ok(v)
        }
        "request" => {
            let mut v = json!({"connection": args.get("connection"), "method": args.get("method").unwrap_or("").to_uppercase(), "path": args.get("path")});
            let mut headers = serde_json::Map::new();
            if let Some(items) = args.options.get("header") {
                for item in items {
                    let Some((name, value)) = item.split_once(':') else {
                        return Err(
                            json!({"error":"InvalidInput","reason":"invalid_arguments","detail":"ValueError"}),
                        );
                    };
                    if name.trim().is_empty() {
                        return Err(
                            json!({"error":"InvalidInput","reason":"invalid_arguments","detail":"ValueError"}),
                        );
                    }
                    headers.insert(name.trim().to_owned(), json!(value.trim()));
                }
            }
            if !headers.is_empty() {
                v["headers"] = Value::Object(headers);
            }
            if let Some(path) = args.get("body-file") {
                let raw = std::fs::read(path).map_err(|e| json!({"error":"InvalidInput","reason":"invalid_arguments","detail":crate::pystr::os_error_class(&e)}))?;
                match String::from_utf8(raw.clone()) {
                    Ok(s) => v["body"] = json!(s),
                    Err(_) => v["body_base64"] = json!(pybase64::b64encode(&raw)),
                }
            } else if let Some(body) = args.get("body") {
                v["body"] = json!(body);
            }
            if let Some(id) = args.get("request-id").filter(|s| !s.is_empty()) {
                v["request_id"] = json!(id);
            }
            Ok(v)
        }
        _ => unreachable!(),
    }
}

fn emit(v: &Value, stderr: bool) {
    let text = pyjson::dumps(v, DumpOptions::pretty_sorted()).unwrap_or_else(|_| "{}".to_owned());
    if stderr {
        eprintln!("{text}");
    } else {
        println!("{text}");
    }
}

fn gateway_unreachable(detail: &str) -> (u16, Value) {
    (
        0,
        json!({"error":"ConnectionError","reason":"gateway_unreachable","detail":detail}),
    )
}

/// `urllib.request.Request(url)`: `(tls, host, selector)` after `_splittag`,
/// `_splittype` and `_splithost`; `host` is percent-decoded and `None` when
/// the URL has no `//authority` (urllib's "no host given").
fn request_target(url: &str) -> Option<(bool, Option<String>, String)> {
    let url = url.rsplit_once('#').map_or(url, |(u, _)| u);
    let (scheme, rest) = url.split_once(':')?;
    let tls = match scheme.to_ascii_lowercase().as_str() {
        "http" => false,
        "https" => true,
        _ => return None,
    };
    let Some(rest) = rest.strip_prefix("//") else {
        return Some((tls, None, rest.to_owned()));
    };
    let end = rest.find(['/', '#', '?']).unwrap_or(rest.len());
    let (host, path) = rest.split_at(end);
    let path = if !path.is_empty() && !path.starts_with('/') {
        format!("/{path}")
    } else {
        path.to_owned()
    };
    let host = (!host.is_empty()).then(|| crate::pystr::unquote(host));
    Some((tls, host, path))
}

/// `http.client.HTTPConnection._get_hostport(host, None)` plus the port
/// range `socket` enforces: `Err` names the exception CPython raises.
fn host_port(host: &str, default_port: u16) -> Result<(String, u16), &'static str> {
    let colon = host.rfind(':');
    let bracket = host.rfind(']');
    let (host, port) = match colon {
        Some(i) if bracket.is_none_or(|j| i > j) => {
            let text = &host[i + 1..];
            let port = match crate::pystr::int_from_str_checked(text) {
                Some(port) => port,
                None if text.is_empty() => i128::from(default_port),
                None => return Err("InvalidURL"),
            };
            (&host[..i], port)
        }
        _ => (host, i128::from(default_port)),
    };
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let port = u16::try_from(port).map_err(|_| "OverflowError")?;
    Ok((host.to_owned(), port))
}

/// `socket.create_connection((host, port), timeout)`: every resolved address
/// in turn, raising the last error.
fn create_connection(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let mut last = io::Error::from(io::ErrorKind::AddrNotAvailable);
    for address in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => return Ok(stream),
            Err(error) => last = error,
        }
    }
    Err(last)
}

/// `str(URLError.reason)[:200]`.
fn url_error(error: &io::Error) -> (u16, Value) {
    let text: String = crate::pystr::socket_error_text(error)
        .chars()
        .take(200)
        .collect();
    gateway_unreachable(&text)
}

/// `urllib.request.getproxies_environment()`: `<scheme>_proxy` variables,
/// lowercase names preferred, `HTTP_PROXY` ignored under CGI.
fn env_proxies() -> BTreeMap<String, String> {
    let vars: Vec<(String, String)> = env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .collect();
    let mut proxies = BTreeMap::new();
    let mut environment = Vec::new();
    for (name, value) in &vars {
        let chars: Vec<char> = name.chars().collect();
        if chars.len() > 5
            && chars[chars.len() - 6] == '_'
            && chars[chars.len() - 5..]
                .iter()
                .collect::<String>()
                .to_lowercase()
                == "proxy"
        {
            let proxy_name: String = chars[..chars.len() - 6]
                .iter()
                .collect::<String>()
                .to_lowercase();
            environment.push((name.clone(), value.clone(), proxy_name.clone()));
            if !value.is_empty() {
                proxies.insert(proxy_name, value.clone());
            }
        }
    }
    if vars.iter().any(|(name, _)| name == "REQUEST_METHOD") {
        proxies.remove("http");
    }
    for (name, value, proxy_name) in environment {
        if name.ends_with("_proxy") {
            if value.is_empty() {
                proxies.remove(&proxy_name);
            } else {
                proxies.insert(proxy_name, value);
            }
        }
    }
    proxies
}

/// `urllib.parse._splitport` (`(.*):([0-9]*)`, full match).
fn split_port(host: &str) -> &str {
    match host.rsplit_once(':') {
        Some((head, port)) if port.bytes().all(|b| b.is_ascii_digit()) => head,
        _ => host,
    }
}

/// `urllib.request.proxy_bypass_environment(host)`.
fn proxy_bypass(host: &str, proxies: &BTreeMap<String, String>) -> bool {
    let Some(no_proxy) = proxies.get("no") else {
        return false;
    };
    if no_proxy == "*" {
        return true;
    }
    let host = host.to_lowercase();
    let hostonly = split_port(&host);
    for name in no_proxy.split(',') {
        let name = name.trim().trim_start_matches('.').to_lowercase();
        if name.is_empty() {
            continue;
        }
        if hostonly == name || host == name {
            return true;
        }
        let suffix = format!(".{name}");
        if hostonly.ends_with(&suffix) || host.ends_with(&suffix) {
            return true;
        }
    }
    false
}

/// `(scheme, user, password, hostport)` of a proxy URL.
type ParsedProxy = (Option<String>, Option<String>, Option<String>, String);

/// `urllib.request._parse_proxy(proxy)`.
fn parse_proxy(proxy: &str) -> Result<ParsedProxy, &'static str> {
    let split = proxy
        .split_once(':')
        .filter(|(scheme, _)| !scheme.is_empty() && !scheme.contains('/'));
    let (scheme, authority) = match split {
        Some((scheme, rest)) if rest.starts_with('/') => {
            let Some(after) = rest.strip_prefix("//") else {
                return Err("ValueError");
            };
            let end = match after.find('@') {
                Some(at) => after[at..].find('/').map(|i| i + at),
                None => after.find('/'),
            };
            (
                Some(scheme.to_lowercase()),
                end.map_or(after, |end| &after[..end]),
            )
        }
        _ => (None, proxy),
    };
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((userinfo, hostport)) => (Some(userinfo), hostport),
        None => (None, authority),
    };
    let (user, password) = match userinfo {
        Some(userinfo) => match userinfo.split_once(':') {
            Some((user, password)) => (Some(user.to_owned()), Some(password.to_owned())),
            None => (Some(userinfo.to_owned()), None),
        },
        None => (None, None),
    };
    Ok((scheme, user, password, hostport.to_owned()))
}

/// How `ProxyHandler` routes one request.
struct Route {
    /// Connect here (the proxy, or the target itself).
    connect: String,
    /// TLS to `connect`'s host (an `https` connection class).
    tls: bool,
    /// Request target: the selector, or the whole URL through an HTTP proxy.
    selector: String,
    /// `CONNECT` through the proxy to this `host[:port]` first (https targets).
    tunnel: Option<String>,
    proxy_authorization: Option<String>,
}

fn route(
    url_without_fragment: &str,
    tls: bool,
    host: Option<&str>,
    selector: &str,
) -> Result<Route, (u16, Value)> {
    let direct = || Route {
        connect: host.unwrap_or("").to_owned(),
        tls,
        selector: selector.to_owned(),
        tunnel: None,
        proxy_authorization: None,
    };
    let proxies = env_proxies();
    let Some(proxy) = proxies.get(if tls { "https" } else { "http" }) else {
        return Ok(direct());
    };
    let (scheme, user, password, hostport) = parse_proxy(proxy).map_err(gateway_unreachable)?;
    let orig_type = if tls { "https" } else { "http" };
    let proxy_type = scheme.unwrap_or_else(|| orig_type.to_owned());
    if host.is_some_and(|h| !h.is_empty() && proxy_bypass(h, &proxies)) {
        return Ok(direct());
    }
    let proxy_authorization = match (user, password) {
        (Some(user), Some(password)) if !user.is_empty() && !password.is_empty() => Some(format!(
            "Basic {}",
            pybase64::b64encode(
                format!(
                    "{}:{}",
                    crate::pystr::unquote(&user),
                    crate::pystr::unquote(&password)
                )
                .as_bytes()
            )
        )),
        _ => None,
    };
    let hostport = crate::pystr::unquote(&hostport);
    if tls {
        // `set_proxy` on an https request only records the tunnel host.
        return Ok(Route {
            connect: hostport,
            tls: true,
            selector: selector.to_owned(),
            tunnel: Some(host.unwrap_or("").to_owned()),
            proxy_authorization,
        });
    }
    match proxy_type.as_str() {
        "http" | "https" => Ok(Route {
            connect: hostport,
            tls: proxy_type == "https",
            selector: url_without_fragment.to_owned(),
            tunnel: None,
            proxy_authorization,
        }),
        other => Err(gateway_unreachable(&format!("unknown url type: {other}"))),
    }
}

/// `HTTPConnection._tunnel`: `CONNECT` and a `200` answer before TLS.
fn tunnel(
    stream: &mut TcpStream,
    target: &str,
    proxy_authorization: Option<&str>,
) -> Result<(), (u16, Value)> {
    let (host, port) = host_port(target, 443).map_err(gateway_unreachable)?;
    let wrapped = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    let mut request = format!("CONNECT {wrapped}:{port} HTTP/1.1\r\n");
    if let Some(value) = proxy_authorization {
        request.push_str(&format!("Proxy-Authorization: {value}\r\n"));
    }
    request.push_str(&format!("Host: {host}:{port}\r\n\r\n"));
    stream
        .write_all(request.as_bytes())
        .map_err(|e| url_error(&e))?;
    let status_line = read_line(stream, MAX_HEADER_BYTES)
        .map_err(|_| gateway_unreachable("RemoteDisconnected"))?;
    let status_text = String::from_utf8_lossy(&status_line);
    let mut fields = status_text.trim_end().splitn(3, ' ');
    let _version = fields.next();
    let code = fields.next().unwrap_or("");
    let message = fields.next().unwrap_or("").trim();
    loop {
        let line = read_line(stream, MAX_HEADER_BYTES)
            .map_err(|_| gateway_unreachable("RemoteDisconnected"))?;
        if line == b"\r\n" {
            break;
        }
    }
    if code != "200" {
        return Err(gateway_unreachable(
            &format!("Tunnel connection failed: {code} {message}")
                .chars()
                .take(200)
                .collect::<String>(),
        ));
    }
    Ok(())
}

/// Port of `agent_cli.call_tool`; refuses redirects and caps the response body.
pub fn call_tool(base_url: &str, token: &str, tool: &str, payload: &Value) -> (u16, Value) {
    let url = format!("{}/v1/tools/{tool}", base_url.trim_end_matches('/'));
    let Some((tls, host, selector)) = request_target(&url) else {
        return gateway_unreachable("ValueError");
    };
    let Some(host) = host else {
        return gateway_unreachable("no host given");
    };
    if token.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return gateway_unreachable("ValueError");
    }
    // http.client refuses control characters and spaces in the host and
    // request target (`InvalidURL`, which urllib does not catch).
    if host
        .bytes()
        .chain(selector.bytes())
        .any(|b| b <= b' ' || b == 0x7f)
    {
        return gateway_unreachable("InvalidURL");
    }
    let url_without_fragment = url.rsplit_once('#').map_or(url.as_str(), |(u, _)| u);
    let route = match route(url_without_fragment, tls, Some(&host), &selector) {
        Ok(route) => route,
        Err(failure) => return failure,
    };
    let (connect_host, port) = match host_port(&route.connect, if route.tls { 443 } else { 80 }) {
        Ok(target) => target,
        Err(name) => return gateway_unreachable(name),
    };
    let timeout = Duration::from_secs(120);
    let mut stream = match create_connection(&connect_host, port, timeout) {
        Ok(s) => s,
        Err(error) => return url_error(&error),
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let server_name = match &route.tunnel {
        Some(target) => {
            if let Err(failure) = tunnel(&mut stream, target, route.proxy_authorization.as_deref())
            {
                return failure;
            }
            match host_port(target, 443) {
                Ok((name, _)) => name,
                Err(name) => return gateway_unreachable(name),
            }
        }
        None => connect_host.clone(),
    };
    let body = pyjson::dumps(payload, DumpOptions::plain()).unwrap_or_else(|_| "{}".to_owned());
    // `urllib`'s request processors add Content-Length, Host and User-Agent
    // as unredirected headers before the Request's three explicit headers.
    // `http.client.putrequest` emits Accept-Encoding first; `do_open` appends
    // Connection last.  Keep that wire order as well as the values: header
    // order and duplicates are observable to an HTTP peer.
    let proxy_header = match (&route.proxy_authorization, &route.tunnel) {
        (Some(value), None) => format!("Proxy-Authorization: {value}\r\n"),
        _ => String::new(),
    };
    let request = format!(
        "POST {} HTTP/1.1\r\nAccept-Encoding: identity\r\nContent-Length: {}\r\nHost: {host}\r\nUser-Agent: Python-urllib/3.12\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nAccept: application/json\r\n{proxy_header}Connection: close\r\n\r\n{body}",
        route.selector,
        body.len()
    );
    if route.tls {
        // TLS validation is supplied by rustls and the host's certificate store.
        let roots = rustls_native_certs::load_native_certs();
        let mut store = rustls::RootCertStore::empty();
        for cert in roots.certs {
            let _ = store.add(cert);
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(store)
            .with_no_client_auth();
        let name = match rustls_pki_types::ServerName::try_from(server_name) {
            Ok(n) => n,
            Err(_) => return gateway_unreachable("InvalidURL"),
        };
        let connection = match rustls::ClientConnection::new(std::sync::Arc::new(config), name) {
            Ok(c) => c,
            Err(_) => return gateway_unreachable("SSLError"),
        };
        let mut io = rustls::StreamOwned::new(connection, stream);
        if let Err(error) = io.write_all(request.as_bytes()) {
            return url_error(&error);
        }
        read_response(&mut io)
    } else {
        let mut io = stream;
        if let Err(error) = io.write_all(request.as_bytes()) {
            return url_error(&error);
        }
        read_response(&mut io)
    }
}

fn read_line(io: &mut impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut one = [0u8; 1];
    loop {
        if line.len() >= limit {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "LineTooLong"));
        }
        io.read_exact(&mut one)?;
        line.push(one[0]);
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
    }
}

fn response_bytes(io: &mut impl Read) -> io::Result<(u16, Vec<u8>)> {
    let mut interim = 0;
    loop {
        let status_line = read_line(io, MAX_HEADER_BYTES).map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                io::Error::new(io::ErrorKind::ConnectionAborted, "RemoteDisconnected")
            } else {
                error
            }
        })?;
        let status_text = std::str::from_utf8(&status_line)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        let mut fields = status_text.split_whitespace();
        if !fields.next().is_some_and(|v| v.starts_with("HTTP/")) {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let status = fields
            .next()
            .and_then(|v| v.parse::<u16>().ok())
            .filter(|v| (100..=599).contains(v))
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        let mut header_bytes = status_line.len();
        let mut content_length = None;
        let mut transfer_encoding = String::new();
        loop {
            let line = read_line(io, MAX_HEADER_BYTES - header_bytes)?;
            header_bytes += line.len();
            if line == b"\r\n" {
                break;
            }
            let header = std::str::from_utf8(&line)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
            let (name, value) = header
                .split_once(':')
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
            let value = value.trim();
            if name.eq_ignore_ascii_case("content-length") {
                let length = value
                    .parse::<usize>()
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                if content_length.is_some_and(|previous| previous != length) {
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
                content_length = Some(length);
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                transfer_encoding.push_str(value);
                transfer_encoding.push(',');
            }
        }
        if status < 200 {
            interim += 1;
            if interim > 5 {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            continue;
        }
        if status == 204 || status == 304 {
            return Ok((status, Vec::new()));
        }
        let chunked = transfer_encoding
            .split(',')
            .map(str::trim)
            .any(|v| v.eq_ignore_ascii_case("chunked"));
        let body = if chunked {
            read_chunked(io)?
        } else {
            let limit = content_length
                .unwrap_or(MAX_RESPONSE_BYTES)
                .min(MAX_RESPONSE_BYTES);
            let mut body = Vec::new();
            io.take(limit as u64).read_to_end(&mut body)?;
            if content_length
                .is_some_and(|length| length <= MAX_RESPONSE_BYTES && body.len() != length)
            {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            body
        };
        return Ok((status, body));
    }
}

fn read_chunked(io: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line = read_line(io, MAX_CHUNK_LINE_BYTES)?;
        let text =
            std::str::from_utf8(&line).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        let size = text
            .trim()
            .split(';')
            .next()
            .and_then(|s| usize::from_str_radix(s, 16).ok())
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        if size == 0 {
            // The body is complete; trailers cannot affect the parsed JSON.
            return Ok(body);
        }
        let remaining = MAX_RESPONSE_BYTES - body.len();
        let copy = size.min(remaining);
        let previous = body.len();
        body.resize(previous + copy, 0);
        io.read_exact(&mut body[previous..])?;
        if copy < size || body.len() == MAX_RESPONSE_BYTES {
            return Ok(body);
        }
        let mut ending = [0u8; 2];
        io.read_exact(&mut ending)?;
        if ending != *b"\r\n" {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
    }
}

fn read_response(io: &mut impl Read) -> (u16, Value) {
    let (status, body) = match response_bytes(io) {
        Ok(result) => result,
        Err(error) => {
            // `type(exc).__name__` of what `getresponse()`/`read()` raises:
            // an OSError subclass (caught by `call_tool`) or an
            // `http.client.HTTPException` (which CPython leaves uncaught).
            let tag = error.get_ref().map(ToString::to_string).unwrap_or_default();
            let detail = match error.kind() {
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "TimeoutError",
                _ if tag == "RemoteDisconnected" || tag == "LineTooLong" => tag.as_str(),
                io::ErrorKind::InvalidData => "BadStatusLine",
                io::ErrorKind::UnexpectedEof => "IncompleteRead",
                _ => crate::pystr::os_error_class(&error),
            };
            return gateway_unreachable(detail);
        }
    };
    let text = match String::from_utf8(body) {
        Ok(t) => t,
        Err(_) => {
            return (
                status,
                json!({"error":"ProtocolError","reason":"non_json_response","status":status}),
            );
        }
    };
    match pyjson::loads(&text) {
        Ok(v) if v.is_object() => (status, v),
        Ok(_) => (
            status,
            json!({"error":"ProtocolError","reason":"non_object_response","status":status}),
        ),
        Err(_) => (
            status,
            json!({"error":"ProtocolError","reason":"non_json_response","status":status}),
        ),
    }
}

/// Entry point taking the raw OS arguments. Python keeps a non-UTF-8
/// argument as a `surrogateescape` string; a Rust `String` cannot hold it
/// (PORTING.md §3.6), so it is a usage error instead of a panic.
pub fn main_os(argv: Vec<std::ffi::OsString>) -> i32 {
    match argv
        .into_iter()
        .map(std::ffi::OsString::into_string)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(argv) => main(&argv),
        Err(_) => {
            eprintln!(
                "{}zeropw-agent: error: argument is not valid UTF-8",
                build_parser().format_usage()
            );
            2
        }
    }
}

/// Returns process exit code; caller supplies argv excluding program name.
pub fn main(argv: &[String]) -> i32 {
    let args = match parse(argv) {
        Ok(a) => a,
        Err(ParseFail::Help(text)) => {
            print!("{text}");
            let _ = io::stdout().flush();
            return 0;
        }
        Err(ParseFail::Usage(text)) => {
            eprint!("{text}");
            return 2;
        }
    };
    let base_url = env::var("ZEROPW_GATEWAY_URL")
        .unwrap_or_default()
        .trim()
        .to_owned();
    let token = env::var("ZEROPW_CALLER_TOKEN")
        .unwrap_or_default()
        .trim()
        .to_owned();
    if base_url.is_empty() {
        emit(
            &json!({"error":"ConfigError","reason":"gateway_url_unset","detail":"set ZEROPW_GATEWAY_URL"}),
            true,
        );
        return 1;
    }
    // Python checks only `urlsplit(base_url).scheme`; any other defect in the
    // URL surfaces as `gateway_unreachable` when the request is attempted.
    if !crate::pystr::urlsplit(&base_url).is_ok_and(|p| p.scheme == "http" || p.scheme == "https") {
        emit(
            &json!({"error":"ConfigError","reason":"gateway_url_invalid"}),
            true,
        );
        return 1;
    }
    if token.is_empty() {
        emit(
            &json!({"error":"ConfigError","reason":"caller_token_unset","detail":"set ZEROPW_CALLER_TOKEN"}),
            true,
        );
        return 1;
    }
    let payload = match payload(&args) {
        Ok(v) => v,
        Err(e) => {
            emit(&e, true);
            return 1;
        }
    };
    let tool = match args.command.as_str() {
        "list-connections" => "list_connections",
        other => other,
    };
    let (status, mut body) = call_tool(&base_url, &token, tool, &payload);
    if status == 200 && (args.command != "request" || body.get("reason").is_none_or(Value::is_null))
    {
        emit(&body, false);
        return 0;
    }
    if status != 0 && body.get("status").is_none() {
        body["status"] = json!(status);
    }
    emit(&body, true);
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn decoded(raw: &[u8]) -> (u16, Value) {
        read_response(&mut Cursor::new(raw))
    }

    #[test]
    fn response_framing_and_bounds() {
        assert_eq!(
            decoded(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n{\"x\":1}garbage").1["x"],
            1
        );
        assert_eq!(decoded(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n{\"x\r\n4;test=yes\r\n\":1}\r\n0\r\n\r\n").1["x"], 1);
        assert_eq!(decoded(b"HTTP/1.1 200 OK\r\n\r\n{\"x\":1}").1["x"], 1);
        assert_eq!(decoded(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n{\"x\":1}").1["x"], 1);
        assert_eq!(
            decoded(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n{\"x\":1}").1["reason"],
            "gateway_unreachable"
        );
        assert_eq!(
            decoded(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n").1["reason"],
            "gateway_unreachable"
        );
        assert_eq!(
            decoded(b"HTTP/1.1 200 OK\r\n\r\nnot json").1["reason"],
            "non_json_response"
        );
        let oversized_header = format!(
            "HTTP/1.1 200 OK\r\nX: {}\r\n\r\n",
            "a".repeat(MAX_HEADER_BYTES)
        );
        assert_eq!(
            decoded(oversized_header.as_bytes()).1["reason"],
            "gateway_unreachable"
        );
    }
    #[test]
    fn payloads_and_bad_args() {
        let req = parse(
            &[
                "request",
                "--connection",
                "gh",
                "--method",
                "post",
                "--path",
                "/repos",
                "--header",
                "Accept: json",
            ]
            .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(payload(&req).unwrap()["method"], "POST");
        assert_eq!(payload(&req).unwrap()["headers"]["Accept"], "json");
        assert!(parse(&["request", "--connection", "gh"].map(str::to_owned)).is_err());
        let ex = parse(&["exec", "--connection", "gh", "--", "--flag", "-x"].map(str::to_owned))
            .unwrap();
        assert_eq!(payload(&ex).unwrap()["argv"], json!(["--flag", "-x"]));
        let equals = parse(
            &[
                "request",
                "--connection=gh",
                "--method=GET",
                "--path=/x",
                "--header=A: 1",
                "--header=B: 2",
            ]
            .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(payload(&equals).unwrap()["headers"]["B"], "2");
    }
}
