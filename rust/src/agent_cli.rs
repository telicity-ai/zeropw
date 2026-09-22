//! Agent-side JSON CLI (`zeropw.agent_cli`). This module never opens the trusted state directory.

use std::collections::BTreeMap;
use std::env;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde_json::{Value, json};

use crate::pybase64;
use crate::pyjson::{self, DumpOptions};

const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_CHUNK_LINE_BYTES: usize = 8192;
const ROOT_HELP: &str = "usage: zeropw-agent [-h] {list-connections,request,exec,status,cancel} ...\n\nZeroPW agent tools client (JSON output)\n\npositional arguments:\n  {list-connections,request,exec,status,cancel}\n    list-connections    connections usable by this caller\n    request             relay one HTTP request through the gateway\n    exec                run the connection's supported CLI; arguments follow\n                        '--'\n    status              state and captured output of one of your runs\n    cancel              cancel one of your runs\n\noptions:\n  -h, --help            show this help message and exit";

fn command_help(command: &str) -> Option<&'static str> {
    match command {
        "list-connections" => Some(
            "usage: zeropw-agent list-connections [-h]\n\noptions:\n  -h, --help  show this help message and exit",
        ),
        "request" => Some(
            "usage: zeropw-agent request [-h] --connection CONNECTION --method METHOD\n                            --path PATH [--body-file BODY_FILE | --body BODY]\n                            [--header 'K: V'] [--request-id REQUEST_ID]\n\noptions:\n  -h, --help            show this help message and exit\n  --connection CONNECTION\n  --method METHOD\n  --path PATH\n  --body-file BODY_FILE\n                        file whose bytes form the request body\n  --body BODY           request body text (UTF-8)\n  --header 'K: V'\n  --request-id REQUEST_ID",
        ),
        "exec" => Some(
            "usage: zeropw-agent exec [-h] --connection CONNECTION\n                         [--request-id REQUEST_ID]\n\noptions:\n  -h, --help            show this help message and exit\n  --connection CONNECTION\n  --request-id REQUEST_ID",
        ),
        "status" => Some(
            "usage: zeropw-agent status [-h] --run RUN\n\noptions:\n  -h, --help  show this help message and exit\n  --run RUN",
        ),
        "cancel" => Some(
            "usage: zeropw-agent cancel [-h] --run RUN\n\noptions:\n  -h, --help  show this help message and exit\n  --run RUN",
        ),
        _ => None,
    }
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
    fn required(&self, key: &str) -> Result<&str, String> {
        self.get(key)
            .ok_or_else(|| format!("the following arguments are required: --{key}"))
    }
}

fn parse(argv: &[String]) -> Result<Args, String> {
    let command = argv
        .first()
        .ok_or("the following arguments are required: command")?;
    let allowed: &[&str] = match command.as_str() {
        "list-connections" => &[],
        "request" => &[
            "connection",
            "method",
            "path",
            "body-file",
            "body",
            "header",
            "request-id",
        ],
        "exec" => &["connection", "request-id"],
        "status" | "cancel" => &["run"],
        _ => return Err(format!("invalid choice: {command}")),
    };
    let mut out = Args {
        command: command.clone(),
        ..Args::default()
    };
    let mut i = 1;
    while i < argv.len() {
        if command == "exec" && argv[i] == "--" {
            out.extra.extend_from_slice(&argv[i + 1..]);
            break;
        }
        let arg = &argv[i];
        let Some(raw) = arg.strip_prefix("--") else {
            return Err(format!("unrecognized arguments: {arg}"));
        };
        let (name, inline) = raw
            .split_once('=')
            .map_or((raw, None), |(k, v)| (k, Some(v)));
        if !allowed.contains(&name) {
            return Err(format!("unrecognized arguments: {arg}"));
        }
        let value = if let Some(inline) = inline {
            inline.to_owned()
        } else {
            i += 1;
            let value = argv
                .get(i)
                .ok_or_else(|| format!("argument {arg}: expected one argument"))?;
            if value.starts_with("--") {
                return Err(format!("argument {arg}: expected one argument"));
            }
            value.clone()
        };
        out.options.entry(name.to_owned()).or_default().push(value);
        i += 1;
    }
    match command.as_str() {
        "request" => {
            for key in ["connection", "method", "path"] {
                out.required(key)?;
            }
            if out.get("body-file").is_some() && out.get("body").is_some() {
                return Err("argument --body: not allowed with argument --body-file".to_owned());
            }
        }
        "exec" => {
            out.required("connection")?;
        }
        "status" | "cancel" => {
            out.required("run")?;
        }
        _ => {}
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
                let raw = std::fs::read(path).map_err(|_| json!({"error":"InvalidInput","reason":"invalid_arguments","detail":"FileNotFoundError"}))?;
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

fn split_url(url: &str) -> Option<(bool, String, u16, String)> {
    if url.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return None;
    }
    let (scheme, rest) = url.split_once("://")?;
    let tls = match scheme {
        "http" => false,
        "https" => true,
        _ => return None,
    };
    let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    if authority.is_empty()
        || authority.contains('@')
        || authority.contains('#')
        || authority.contains('?')
    {
        return None;
    }
    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']')?;
        let host = authority.get(1..end)?;
        let rem = authority.get(end + 1..)?;
        let port = if rem.is_empty() {
            if tls { 443 } else { 80 }
        } else {
            rem.strip_prefix(':')?.parse().ok()?
        };
        (host.to_owned(), port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        (h.to_owned(), p.parse().ok()?)
    } else {
        (authority.to_owned(), if tls { 443 } else { 80 })
    };
    if host.is_empty() {
        return None;
    }
    Some((
        tls,
        host,
        port,
        if path.is_empty() {
            String::new()
        } else {
            format!("/{path}")
        },
    ))
}

fn gateway_unreachable(detail: &str) -> (u16, Value) {
    (
        0,
        json!({"error":"ConnectionError","reason":"gateway_unreachable","detail":detail}),
    )
}

/// Port of `agent_cli.call_tool`; refuses redirects and caps the response body.
pub fn call_tool(base_url: &str, token: &str, tool: &str, payload: &Value) -> (u16, Value) {
    if token.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return gateway_unreachable("ValueError");
    }
    let Some((tls, host, port, base_path)) = split_url(base_url.trim_end_matches('/')) else {
        return gateway_unreachable("ValueError");
    };
    let address = match (host.as_str(), port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
    {
        Some(a) => a,
        None => return gateway_unreachable("gaierror"),
    };
    let timeout = Duration::from_secs(120);
    let stream = match TcpStream::connect_timeout(&address, timeout) {
        Ok(s) => s,
        Err(_) => return gateway_unreachable("ConnectionRefusedError"),
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let body = pyjson::dumps(payload, DumpOptions::plain()).unwrap_or_else(|_| "{}".to_owned());
    let path = format!("{base_path}/v1/tools/{tool}");
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    if tls {
        // TLS validation is supplied by rustls and the host's certificate store.
        let roots = rustls_native_certs::load_native_certs();
        let mut store = rustls::RootCertStore::empty();
        for cert in roots.certs {
            let _ = store.add(cert);
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(store)
            .with_no_client_auth();
        let name = match rustls_pki_types::ServerName::try_from(host.clone()) {
            Ok(n) => n,
            Err(_) => return gateway_unreachable("InvalidDnsNameError"),
        };
        let connection = match rustls::ClientConnection::new(std::sync::Arc::new(config), name) {
            Ok(c) => c,
            Err(_) => return gateway_unreachable("TLSError"),
        };
        let mut io = rustls::StreamOwned::new(connection, stream);
        if io.write_all(request.as_bytes()).is_err() {
            return gateway_unreachable("OSError");
        }
        read_response(&mut io)
    } else {
        let mut io = stream;
        if io.write_all(request.as_bytes()).is_err() {
            return gateway_unreachable("OSError");
        }
        read_response(&mut io)
    }
}

fn read_line(io: &mut impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut one = [0u8; 1];
    loop {
        if line.len() >= limit {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
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
        let status_line = read_line(io, MAX_HEADER_BYTES)?;
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
            let detail = if error.kind() == io::ErrorKind::TimedOut
                || error.kind() == io::ErrorKind::WouldBlock
            {
                "TimeoutError"
            } else {
                "OSError"
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

/// Returns process exit code; caller supplies argv excluding program name.
pub fn main(argv: &[String]) -> i32 {
    let is_help = |arg: &String| arg == "-h" || arg == "--help";
    if argv.first().is_some_and(is_help) {
        println!("{ROOT_HELP}");
        return 0;
    }
    if let Some(help) = argv.first().and_then(|command| command_help(command))
        && argv
            .iter()
            .skip(1)
            .take_while(|arg| *arg != "--")
            .any(is_help)
    {
        println!("{help}");
        return 0;
    }
    let args = match parse(argv) {
        Ok(a) => a,
        Err(detail) => {
            eprintln!("usage: zeropw-agent {{list-connections,request,exec,status,cancel}} ...");
            eprintln!("zeropw-agent: error: {detail}");
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
    if split_url(&base_url).is_none() {
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
