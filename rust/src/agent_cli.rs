//! Agent-side JSON CLI (`zeropw.agent_cli`). This module never opens the trusted state directory.

use std::collections::BTreeMap;
use std::env;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde_json::{Value, json};

use crate::argparse::{Arg, Outcome, Parser, Val};
use crate::pybase64;
use crate::pyjson::{self, DumpOptions};

const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// `http.client._MAXLINE`.
const MAX_LINE: usize = 65536;
/// `http.client._MAXHEADERS`.
const MAX_HEADERS: usize = 100;
/// `http.client._MAXINTERIMRESPONSES`.
const MAX_INTERIM_RESPONSES: usize = 100;

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
    let environment_proxies = env_proxies();
    #[cfg(target_os = "macos")]
    let system_proxies = environment_proxies
        .is_empty()
        .then(|| crate::mac_proxies::load().unwrap_or_default());
    #[cfg(target_os = "macos")]
    let proxies = system_proxies
        .as_ref()
        .map_or(&environment_proxies, |settings| &settings.proxies);
    #[cfg(not(target_os = "macos"))]
    let proxies = &environment_proxies;
    let Some(proxy) = proxies.get(if tls { "https" } else { "http" }) else {
        return Ok(direct());
    };
    let (scheme, user, password, hostport) = parse_proxy(proxy).map_err(gateway_unreachable)?;
    let orig_type = if tls { "https" } else { "http" };
    let proxy_type = scheme.unwrap_or_else(|| orig_type.to_owned());
    let bypass = if let Some(host) = host.filter(|host| !host.is_empty()) {
        #[cfg(target_os = "macos")]
        if environment_proxies.is_empty() {
            // `urllib.proxy_bypass` asks `_scproxy` again rather than reusing
            // the dictionary returned by `getproxies()`.
            let settings = crate::mac_proxies::load().ok_or_else(|| {
                gateway_unreachable("SystemConfiguration proxy settings unavailable")
            })?;
            crate::mac_proxies::proxy_bypass(host, &settings)
        } else {
            proxy_bypass(host, &environment_proxies)
        }
        #[cfg(not(target_os = "macos"))]
        {
            proxy_bypass(host, &environment_proxies)
        }
    } else {
        false
    };
    if bypass {
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

/// `HTTPConnection._tunnel`: `CONNECT` and a `200` answer before TLS.  It
/// runs inside `h.request`, so an `OSError` is `URLError(err)` (`detail` is
/// `str(err)`), while an `http.client.HTTPException` escapes `call_tool`.
fn tunnel(
    stream: &mut TcpStream,
    target: &str,
    proxy_authorization: Option<&str>,
) -> Result<(), Failure> {
    let (host, port) =
        host_port(target, 443).map_err(|name| Failure::Caught(gateway_unreachable(name)))?;
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
        .map_err(|e| Failure::Caught(url_error(&e)))?;
    let mut reader = BufReader::new(stream);
    let url_error_of = |failure: HttpFailure| match failure {
        HttpFailure::Os(error) => Failure::Caught(url_error(&error)),
        HttpFailure::Disconnected => Failure::Caught(gateway_unreachable(
            "Remote end closed connection without response",
        )),
        HttpFailure::Value => Failure::Caught(gateway_unreachable("ValueError")),
        HttpFailure::Http(name) => Failure::Escaped(name),
    };
    let (_, code, message) = read_status(&mut reader).map_err(url_error_of)?;
    read_header_lines(&mut reader).map_err(url_error_of)?;
    if code != 200 {
        let message = message.trim_matches(crate::pystr::is_space);
        return Err(Failure::Caught(gateway_unreachable(
            &format!("Tunnel connection failed: {code} {message}")
                .chars()
                .take(200)
                .collect::<String>(),
        )));
    }
    Ok(())
}

/// Port of `agent_cli.call_tool`; refuses redirects and caps the response body.
/// An `http.client.HTTPException` that CPython lets escape `call_tool`
/// (a traceback, exit status 1) is reported as `gateway_unreachable` with
/// the exception's class name (PORTING.md §3.5).
pub fn call_tool(base_url: &str, token: &str, tool: &str, payload: &Value) -> (u16, Value) {
    match call_tool_outcome(base_url, token, tool, payload) {
        Ok(result) => result,
        Err(Failure::Caught(result)) => result,
        Err(Failure::Escaped(name)) => gateway_unreachable(name),
    }
}

/// How `call_tool` ends without a response: a value it returns (an
/// `OSError`/`ValueError`/`URLError` it catches) or an exception it lets
/// escape.
#[derive(Debug)]
enum Failure {
    Caught((u16, Value)),
    Escaped(&'static str),
}

fn call_tool_outcome(
    base_url: &str,
    token: &str,
    tool: &str,
    payload: &Value,
) -> Result<(u16, Value), Failure> {
    let url = format!("{}/v1/tools/{tool}", base_url.trim_end_matches('/'));
    let Some((tls, host, selector)) = request_target(&url) else {
        return Err(Failure::Caught(gateway_unreachable("ValueError")));
    };
    let Some(host) = host else {
        return Err(Failure::Caught(gateway_unreachable("no host given")));
    };
    if token.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(Failure::Caught(gateway_unreachable("ValueError")));
    }
    // http.client refuses control characters and spaces in the host and
    // request target (`InvalidURL`, a `ValueError`).
    if host
        .bytes()
        .chain(selector.bytes())
        .any(|b| b <= b' ' || b == 0x7f)
    {
        return Err(Failure::Caught(gateway_unreachable("InvalidURL")));
    }
    let url_without_fragment = url.rsplit_once('#').map_or(url.as_str(), |(u, _)| u);
    let route =
        route(url_without_fragment, tls, Some(&host), &selector).map_err(Failure::Caught)?;
    let (connect_host, port) = host_port(&route.connect, if route.tls { 443 } else { 80 })
        .map_err(|name| Failure::Caught(gateway_unreachable(name)))?;
    let timeout = Duration::from_secs(120);
    let mut stream = create_connection(&connect_host, port, timeout)
        .map_err(|error| Failure::Caught(url_error(&error)))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let server_name = match &route.tunnel {
        Some(target) => {
            tunnel(&mut stream, target, route.proxy_authorization.as_deref())?;
            host_port(target, 443)
                .map_err(|name| Failure::Caught(gateway_unreachable(name)))?
                .0
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
        let name = rustls_pki_types::ServerName::try_from(server_name)
            .map_err(|_| Failure::Caught(gateway_unreachable("InvalidURL")))?;
        let connection = rustls::ClientConnection::new(std::sync::Arc::new(config), name)
            .map_err(|_| Failure::Caught(gateway_unreachable("SSLError")))?;
        let mut io = rustls::StreamOwned::new(connection, stream);
        io.write_all(request.as_bytes())
            .map_err(|error| Failure::Caught(url_error(&error)))?;
        read_response(&mut BufReader::new(RaggedEof(io)), &url)
    } else {
        let mut io = stream;
        io.write_all(request.as_bytes())
            .map_err(|error| Failure::Caught(url_error(&error)))?;
        read_response(&mut BufReader::new(io), &url)
    }
}

/// `SSLSocket` with `suppress_ragged_eofs=True`: a TLS stream that ends
/// without `close_notify` reads as EOF.
struct RaggedEof<T>(T);

impl<T: Read> Read for RaggedEof<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.0.read(buf) {
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
            other => other,
        }
    }
}

/// A failure inside `HTTPResponse`.
#[derive(Debug)]
enum HttpFailure {
    /// An `OSError` from the socket.
    Os(io::Error),
    /// `RemoteDisconnected` (an `OSError` and a `BadStatusLine`).
    Disconnected,
    /// A `ValueError` (`call_tool` catches it).
    Value,
    /// An `http.client.HTTPException` subclass, by class name.
    Http(&'static str),
}

impl From<io::Error> for HttpFailure {
    fn from(error: io::Error) -> Self {
        HttpFailure::Os(error)
    }
}

/// `type(exc).__name__` of a socket error `call_tool` catches: a socket
/// timeout is `TimeoutError`, anything else its `OSError` subclass.
fn os_error_name(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => "TimeoutError",
        _ => crate::pystr::os_error_class(error),
    }
}

/// `fp.readline(limit)`: up to `limit` bytes, through the first `\n`.
fn readline(reader: &mut impl BufRead, limit: usize) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    reader
        .by_ref()
        .take(limit as u64)
        .read_until(b'\n', &mut line)?;
    Ok(line)
}

/// `str.split(None, 2)` over a status line.
fn split_none_2(line: &str) -> Vec<String> {
    let is_space = crate::pystr::is_space;
    let mut parts = Vec::new();
    let mut rest = line.trim_start_matches(is_space);
    while parts.len() < 2 && !rest.is_empty() {
        let end = rest.find(is_space).unwrap_or(rest.len());
        parts.push(rest[..end].to_owned());
        rest = rest[end..].trim_start_matches(is_space);
    }
    if !rest.is_empty() {
        parts.push(rest.to_owned());
    }
    parts
}

fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|b| char::from(*b)).collect()
}

/// `HTTPResponse._read_status()`: `(version, status, reason)`.
fn read_status(reader: &mut impl BufRead) -> Result<(String, i128, String), HttpFailure> {
    let raw = readline(reader, MAX_LINE + 1)?;
    if raw.len() > MAX_LINE {
        return Err(HttpFailure::Http("LineTooLong"));
    }
    if raw.is_empty() {
        return Err(HttpFailure::Disconnected);
    }
    let line = latin1(&raw);
    let parts = split_none_2(&line);
    let version = if parts.len() >= 2 {
        parts[0].clone()
    } else {
        String::new()
    };
    if !version.starts_with("HTTP/") {
        return Err(HttpFailure::Http("BadStatusLine"));
    }
    let status = crate::pystr::int_from_str(&parts[1])
        .filter(|status| (100..=999).contains(status))
        .ok_or(HttpFailure::Http("BadStatusLine"))?;
    Ok((version, status, parts.get(2).cloned().unwrap_or_default()))
}

/// `http.client._read_headers`: the raw header lines, terminator included.
fn read_header_lines(reader: &mut impl BufRead) -> Result<Vec<Vec<u8>>, HttpFailure> {
    let mut lines = Vec::new();
    loop {
        let line = readline(reader, MAX_LINE + 1)?;
        if line.len() > MAX_LINE {
            return Err(HttpFailure::Http("LineTooLong"));
        }
        let end = line.is_empty() || line == b"\r\n" || line == b"\n";
        lines.push(line);
        if lines.len() > MAX_HEADERS {
            return Err(HttpFailure::Http("HTTPException"));
        }
        if end {
            return Ok(lines);
        }
    }
}

/// `email.parser.Parser().parsestr(...)` over the header lines (compat32,
/// as `http.client.parse_headers` runs it): `(name, value)` pairs in order.
/// The text is re-split on `\r\n`, `\r` and `\n`; collection stops at the
/// first line that is not a header, continuation or `From ` line; a
/// continuation before any header and a name-less `:value` line are
/// dropped; a `From ` line is an envelope line, never a header.
fn parse_header_lines(lines: &[Vec<u8>]) -> Vec<(String, String)> {
    let text = latin1(&lines.concat());
    let mut logical = Vec::new();
    let mut current = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        current.push(c);
        if c == '\r' && chars.peek() == Some(&'\n') {
            current.push('\n');
            chars.next();
        }
        if c == '\r' || c == '\n' {
            logical.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        logical.push(current);
    }
    // `headerRE = ^(From |[\041-\071\073-\176]*:|[\t ])`.
    let header_re = |line: &str| {
        line.starts_with("From ")
            || line.starts_with([' ', '\t'])
            || line
                .find(|c: char| !matches!(c as u32, 0x21..=0x39 | 0x3B..=0x7E))
                .is_some_and(|i| line[i..].starts_with(':'))
    };
    let recognized: Vec<&String> = logical.iter().take_while(|l| header_re(l)).collect();
    let mut headers = Vec::new();
    let mut pending: Option<(String, Vec<String>)> = None;
    let finish = |pending: Option<(String, Vec<String>)>, headers: &mut Vec<(String, String)>| {
        if let Some((name, source)) = pending {
            // `Compat32.header_source_parse`.
            let joined = source.concat();
            let value = joined.split_once(':').map_or("", |(_, v)| v);
            let value = value
                .trim_start_matches([' ', '\t', '\r', '\n'])
                .trim_end_matches(['\r', '\n']);
            headers.push((name, value.to_owned()));
        }
    };
    let count = recognized.len();
    for (index, line) in recognized.into_iter().enumerate() {
        if line.starts_with([' ', '\t']) {
            if let Some((_, source)) = pending.as_mut() {
                source.push(line.clone());
            }
            continue;
        }
        finish(pending.take(), &mut headers);
        if line.starts_with("From ") {
            if index + 1 == count {
                break;
            }
            continue;
        }
        match line.find(':') {
            Some(0) | None => {}
            Some(i) => pending = Some((line[..i].to_owned(), vec![line.clone()])),
        }
    }
    finish(pending, &mut headers);
    headers
}

/// `HTTPMessage.get(name)`: the first value, names compared case-insensitively.
fn header_get<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.to_lowercase() == name)
        .map(|(_, v)| v.as_str())
}

/// `HTTPResponse` after `begin()`.
struct Response {
    status: i128,
    headers: Vec<(String, String)>,
    chunked: bool,
    length: Option<i128>,
}

/// `HTTPResponse.begin()`.
fn begin(reader: &mut impl BufRead) -> Result<Response, HttpFailure> {
    let mut last = None;
    for _ in 0..MAX_INTERIM_RESPONSES {
        let (version, status, _) = read_status(reader)?;
        if status != 100 {
            last = Some((version, status));
            break;
        }
        read_header_lines(reader)?;
    }
    let Some((version, status)) = last else {
        return Err(HttpFailure::Http("HTTPException"));
    };
    if !(version == "HTTP/1.0" || version == "HTTP/0.9" || version.starts_with("HTTP/1.")) {
        return Err(HttpFailure::Http("UnknownProtocol"));
    }
    let headers = parse_header_lines(&read_header_lines(reader)?);
    let chunked = header_get(&headers, "transfer-encoding")
        .is_some_and(|te| !te.is_empty() && te.to_lowercase() == "chunked");
    let mut length = match header_get(&headers, "content-length") {
        Some(text) if !text.is_empty() && !chunked => {
            crate::pystr::int_from_str(text).filter(|length| *length >= 0)
        }
        _ => None,
    };
    if status == 204 || status == 304 || (100..200).contains(&status) {
        length = Some(0);
    }
    Ok(Response {
        status,
        headers,
        chunked,
        length,
    })
}

/// `fp.read(amt)`: up to `amt` bytes, fewer at EOF.
fn read_up_to(reader: &mut impl BufRead, amt: usize) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    reader.by_ref().take(amt as u64).read_to_end(&mut data)?;
    Ok(data)
}

/// `HTTPResponse._safe_read(amt)`: exactly `amt` bytes or `IncompleteRead`.
/// A negative `amt` (a negative chunk size) reaches `fp.read(amt)`: `-1`
/// reads to EOF, anything lower is `ValueError`.
fn safe_read(reader: &mut impl BufRead, amt: i128) -> Result<Vec<u8>, HttpFailure> {
    if amt == -1 {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        return Ok(data);
    }
    if amt < 0 {
        return Err(HttpFailure::Value);
    }
    let amt = usize::try_from(amt).unwrap_or(usize::MAX);
    let data = read_up_to(reader, amt)?;
    if data.len() < amt {
        return Err(HttpFailure::Http("IncompleteRead"));
    }
    Ok(data)
}

/// `HTTPResponse._read_chunked(amt)`.
fn read_chunked(reader: &mut impl BufRead, amt: usize) -> Result<Vec<u8>, HttpFailure> {
    let mut amt = amt as i128;
    let mut value = Vec::new();
    let mut chunk_left: Option<i128> = None;
    loop {
        // `_get_chunk_left()`.
        let left = match chunk_left {
            Some(left) if left != 0 => left,
            current => {
                if current.is_some() {
                    safe_read(reader, 2)?;
                }
                let line = readline(reader, MAX_LINE + 1)?;
                if line.len() > MAX_LINE {
                    return Err(HttpFailure::Http("LineTooLong"));
                }
                let size = line.split(|b| *b == b';').next().unwrap_or_default();
                // `int(bytes, 16)`: ASCII only.
                let parsed = if size.iter().all(|b| b.is_ascii() && *b != 0) {
                    crate::pystr::int_from_str_radix(&latin1(size), 16)
                } else {
                    None
                };
                let Some(size) = parsed else {
                    return Err(HttpFailure::Http("IncompleteRead"));
                };
                if size == 0 {
                    discard_trailer(reader)?;
                    return Ok(value);
                }
                size
            }
        };
        if amt <= left {
            value.extend(safe_read(reader, amt)?);
            return Ok(value);
        }
        value.extend(safe_read(reader, left)?);
        amt -= left;
        chunk_left = Some(0);
    }
}

/// `HTTPResponse._read_and_discard_trailer()`.
fn discard_trailer(reader: &mut impl BufRead) -> Result<(), HttpFailure> {
    let mut trailers = 0;
    loop {
        let line = readline(reader, MAX_LINE + 1)?;
        if line.len() > MAX_LINE {
            return Err(HttpFailure::Http("LineTooLong"));
        }
        if line.is_empty() || line == b"\r\n" || line == b"\n" {
            return Ok(());
        }
        trailers += 1;
        if trailers > MAX_HEADERS {
            return Err(HttpFailure::Http("HTTPException"));
        }
    }
}

/// `opener.open(request)` from `getresponse()` on, then `read(MAX)` of the
/// response (or of the `HTTPError` urllib raises for a non-2xx status), then
/// `call_tool`'s JSON decoding.
fn read_response(reader: &mut impl BufRead, full_url: &str) -> Result<(u16, Value), Failure> {
    let caught = |failure: HttpFailure| match failure {
        HttpFailure::Os(error) => Failure::Caught(gateway_unreachable(os_error_name(&error))),
        HttpFailure::Disconnected => Failure::Caught(gateway_unreachable("RemoteDisconnected")),
        HttpFailure::Value => Failure::Caught(gateway_unreachable("ValueError")),
        HttpFailure::Http(name) => Failure::Escaped(name),
    };
    let response = begin(reader).map_err(caught)?;
    // `HTTPErrorProcessor`: a non-2xx status goes through the redirect
    // handler (`_NoRedirect` declines, but `http_error_302` parses the
    // first `Location`/`URI` header first) to `HTTPError`.
    if matches!(response.status, 301 | 302 | 303 | 307 | 308) {
        let target = header_get(&response.headers, "location")
            .or_else(|| header_get(&response.headers, "uri"));
        if let Some(target) = target
            && (crate::pystr::urlsplit(target).is_err()
                || crate::pystr::urlsplit(full_url).is_err())
        {
            return Err(Failure::Caught(gateway_unreachable("ValueError")));
        }
    }
    let raw = if response.chunked {
        read_chunked(reader, MAX_RESPONSE_BYTES).map_err(caught)?
    } else {
        let amt = match response.length {
            Some(length) if (length as u128) < MAX_RESPONSE_BYTES as u128 => length as usize,
            _ => MAX_RESPONSE_BYTES,
        };
        read_up_to(reader, amt).map_err(|error| caught(HttpFailure::Os(error)))?
    };
    let status = u16::try_from(response.status).unwrap_or_default();
    let body = match String::from_utf8(raw).ok().map(|text| pyjson::loads(&text)) {
        Some(Ok(value)) if value.is_object() => value,
        Some(Ok(_)) => {
            json!({"error":"ProtocolError","reason":"non_object_response","status":status})
        }
        _ => json!({"error":"ProtocolError","reason":"non_json_response","status":status}),
    };
    Ok((status, body))
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
    // `os.environ.get(name, "").strip()`: `str.strip()` whitespace.
    let base_url = env::var("ZEROPW_GATEWAY_URL")
        .unwrap_or_default()
        .trim_matches(crate::pystr::is_space)
        .to_owned();
    let token = env::var("ZEROPW_CALLER_TOKEN")
        .unwrap_or_default()
        .trim_matches(crate::pystr::is_space)
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

    /// Each canned HTTP response served to `zeropw.agent_cli.call_tool` and
    /// to this port: `(python, rust)` pairs of the request bytes sent and
    /// the outcome (the returned `[status, body]`, or the class of the
    /// exception that escapes `call_tool`).
    fn transport_outcomes(responses: &[Vec<u8>]) -> Vec<(Value, Value)> {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let canned = responses.to_vec();
        // Python's calls take the first `n` connections, this port's the next `n`.
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for response in canned.iter().chain(canned.iter()) {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&request[..end]).to_lowercase();
                        let length = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length: "))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = stream.write_all(response);
                let _ = stream.shutdown(std::net::Shutdown::Write);
                while stream.read(&mut buf).is_ok_and(|n| n > 0) {}
                requests.push(String::from_utf8_lossy(&request).into_owned());
            }
            requests
        });
        let url = format!("http://127.0.0.1:{port}/base/");
        let script = format!(
            r#"
import json
from zeropw.agent_cli import call_tool
for _ in range({count}):
    try:
        print(json.dumps({{"result": list(call_tool("{url}", "zpwc_synthetic", "status", {{"run_id": "r-1"}}))}}))
    except Exception as exc:
        print(json.dumps({{"escaped": type(exc).__name__}}))
"#,
            count = responses.len(),
        );
        let python: Vec<Value> = crate::oracle::python(&script)
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let rust: Vec<Value> = responses
            .iter()
            .map(|_| {
                match call_tool_outcome(&url, "zpwc_synthetic", "status", &json!({"run_id": "r-1"}))
                {
                    Ok((status, body)) | Err(Failure::Caught((status, body))) => {
                        json!({"result": [status, body]})
                    }
                    Err(Failure::Escaped(name)) => json!({"escaped": name}),
                }
            })
            .collect();
        let requests = server.join().unwrap();
        let (python_requests, rust_requests) = requests.split_at(responses.len());
        python
            .into_iter()
            .zip(python_requests)
            .zip(rust.into_iter().zip(rust_requests))
            .map(|((p, pr), (r, rr))| {
                (
                    json!({"outcome": p, "request": pr}),
                    json!({"outcome": r, "request": rr}),
                )
            })
            .collect()
    }

    /// `http.client.HTTPResponse` framing as urllib drives it (`begin`,
    /// `read(MAX_RESPONSE_BYTES)`, `HTTPErrorProcessor` and the declined
    /// redirect), every exception class `call_tool` catches or lets escape,
    /// and the request bytes urllib sends.
    #[test]
    fn transport_matches_python_urllib() {
        let many = |n: usize| -> String { (0..n).map(|i| format!("X-{i}: y\r\n")).collect() };
        let responses: Vec<Vec<u8>> = vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n{\"x\":1}garbage".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n{\"x\r\n4;test=yes\r\n\":1}\r\n0\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\n\r\n{\"x\":1}".to_vec(),
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n{\"x\":1}".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\n\r\nnot json".to_vec(),
            format!("HTTP/1.1 200 OK\r\nX: {}\r\n\r\n{{}}", "a".repeat(70000)).into_bytes(),
            format!("HTTP/1.1 200 OK\r\n{}\r\n{{}}", many(100)).into_bytes(),
            format!("HTTP/1.1 200 OK\r\n{}\r\n{{}}", many(99)).into_bytes(),
            b"GARBAGE\r\n\r\n".to_vec(),
            b"".to_vec(),
            b"{}".to_vec(),
            b"HTTP/2.0 200 OK\r\n\r\n{}".to_vec(),
            b"HTTP/1.1 +2_00 OK\r\n\r\n{}".to_vec(),
            b"HTTP/1.1 999 Odd\r\n\r\n{\"e\":1}".to_vec(),
            b"HTTP/1.1 1000 Odd\r\n\r\n{}".to_vec(),
            b"HTTP/1.1 101 Switching\r\n\r\n{}".to_vec(),
            b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n".to_vec(),
            b"HTTP/1.1 304 Not Modified\r\n\r\n{}".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked \r\n\r\n2\r\n{}\r\n0\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n{}".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 9\r\n\r\n{}xx".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 1_0\r\n\r\n{\"a\":\"bc\"}zz".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n{}".to_vec(),
            b"HTTP/1.1 200 OK\r\nBad Header\r\nContent-Length: 2\r\n\r\n{}xx".to_vec(),
            b"HTTP/1.1 200 OK\r\nX-A: a\rContent-Length: 2\r\n\r\n{}zz".to_vec(),
            b"HTTP/1.1 200 OK\r\nFrom x\r\nContent-Length: 2\r\n\r\n{}zz".to_vec(),
            b"HTTP/1.1 200 OK\r\n: nameless\r\n continuation\r\nContent-Length:\r\n 2\r\n\r\n{}zz".to_vec(),
            b"HTTP/1.1 302 Found\r\nLocation: http://[::1\r\n\r\n{}".to_vec(),
            b"HTTP/1.1 302 Found\r\nURI: http://example.invalid/\r\n\r\n{\"r\":1}".to_vec(),
            b"HTTP/1.1 307 Temp\r\nLocation: ftp://x/\r\n\r\n{}".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n-5\r\n{}".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\n{}".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0x2\r\n{}\r\n0\r\n\r\n".to_vec(),
            format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{{}}\r\n0\r\n{}\r\n", many(101)).into_bytes(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}XX0\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}".to_vec(),
            b"HTTP/1.1 200\r\n\r\n{}".to_vec(),
            b"HTTP/1.1 200OK\r\n\r\n{}".to_vec(),
            "HTTP/1.1 100 Continue\r\n\r\n".repeat(100).into_bytes(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n\xff\xfe".to_vec(),
            b"HTTP/1.1 200 OK\r\n\r\n[1]".to_vec(),
            b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        ];
        let mismatches: Vec<String> = transport_outcomes(&responses)
            .into_iter()
            .zip(&responses)
            .filter(|((python, rust), _)| python != rust)
            .map(|((python, rust), response)| {
                format!(
                    "response {:?}\n python: {python}\n rust:   {rust}",
                    String::from_utf8_lossy(&response[..response.len().min(120)])
                )
            })
            .collect();
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
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
