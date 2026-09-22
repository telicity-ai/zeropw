//! Agent-side JSON CLI (`zeropw.agent_cli`). This module never opens the trusted state directory.

use std::collections::BTreeMap;
use std::env;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde_json::{Value, json};

use crate::pybase64;
use crate::pyjson::{self, DumpOptions};

const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

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
        let Some(name) = arg.strip_prefix("--") else {
            return Err(format!("unrecognized arguments: {arg}"));
        };
        if !allowed.contains(&name) {
            return Err(format!("unrecognized arguments: {arg}"));
        }
        i += 1;
        let value = argv
            .get(i)
            .ok_or_else(|| format!("argument {arg}: expected one argument"))?;
        if value.starts_with("--") {
            return Err(format!("argument {arg}: expected one argument"));
        }
        if name != "header" && out.options.contains_key(name) {
            return Err(format!(
                "argument {arg}: not allowed with previous argument"
            ));
        }
        out.options
            .entry(name.to_owned())
            .or_default()
            .push(value.clone());
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

fn read_response(io: &mut impl Read) -> (u16, Value) {
    let mut raw = Vec::new();
    let _ = io
        .take((MAX_RESPONSE_BYTES + 65536) as u64)
        .read_to_end(&mut raw);
    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return gateway_unreachable("OSError");
    };
    let header = &raw[..split];
    let status = std::str::from_utf8(header)
        .ok()
        .and_then(|s| s.lines().next())
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|n| n.parse::<u16>().ok())
        .unwrap_or(0);
    let mut body = raw[split + 4..].to_vec();
    if body.len() > MAX_RESPONSE_BYTES {
        body.truncate(MAX_RESPONSE_BYTES);
    }
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
    }
}
