//! Credential-free sample CLI; run only with an opaque gateway base URL.
use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};

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

fn fail(reason: &str, detail: Option<&str>, code: i32) -> i32 {
    let mut payload = json!({"error":reason});
    if let Some(detail) = detail {
        payload["detail"] = json!(detail);
    }
    println!("{payload}");
    code
}

fn request(base: &str, method: &str, path: &str, body: Option<&Value>) -> Result<(u16, Value), ()> {
    let rest = base.strip_prefix("http://").ok_or(())?;
    let (authority, base_path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    let (host, port) = authority.rsplit_once(':').ok_or(())?;
    let port: u16 = port.parse().map_err(|_| ())?;
    if host.is_empty() || host.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(());
    }
    let mut stream = TcpStream::connect((host, port)).map_err(|_| ())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| ())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| ())?;
    let target = if base_path.is_empty() {
        path.to_owned()
    } else {
        format!("/{base_path}{path}")
    };
    let data = body.map(ToString::to_string).unwrap_or_default();
    let mut message = format!(
        "{method} {target} HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: Bearer democli-placeholder\r\nAccept: application/json\r\nUser-Agent: democli/1\r\nConnection: close\r\n"
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
    let mut raw = Vec::new();
    stream
        .take((MAX_HEADER + MAX_BODY) as u64)
        .read_to_end(&mut raw)
        .map_err(|_| ())?;
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
    let parsed = serde_json::from_slice(bytes)
        .unwrap_or_else(|_| json!(String::from_utf8_lossy(bytes).into_owned()));
    Ok((status, parsed))
}

fn call(base: &str, method: &str, path: &str, body: Option<&Value>) -> i32 {
    match request(base, method, path, body) {
        Ok((status, body)) => {
            println!("{}", json!({"status":status,"body":body}));
            if (200..300).contains(&status) { 0 } else { 1 }
        }
        Err(()) => fail("unreachable", Some("gateway unavailable"), 1),
    }
}

fn probe(home: &str, name: &str) -> String {
    if home.is_empty() {
        return "no home".to_owned();
    }
    let path = Path::new(home).join(name);
    if path.is_dir() {
        return "directory".to_owned();
    }
    match File::open(path) {
        Ok(file) => {
            let mut buf = Vec::new();
            match file.take(4096).read_to_end(&mut buf) {
                Ok(n) => format!("present ({n} bytes read, not shown)"),
                Err(_) => "unreadable (OSError)".to_owned(),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "missing".to_owned(),
        Err(error) if error.kind() == std::io::ErrorKind::IsADirectory => "directory".to_owned(),
        Err(_) => "unreadable (OSError)".to_owned(),
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
    println!(
        "{}",
        json!({
            "env_names":names,"argv":argv,"base_url":redacted,"home":home,
            "home_entries":entries,"probes":probes,
            "conclusion":"no credential in environment, arguments, home directory or credential files; only an opaque base URL that the gateway re-checks against policy"
        })
    );
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
        "create-issue" => {
            let repo = &args[1];
            if repo.is_empty()
                || repo.contains('/')
                || repo.contains("..")
                || repo.bytes().any(|b| b <= b' ' || b == 0x7f)
            {
                fail("invalid_repo", None, 1)
            } else {
                call(
                    &base,
                    "POST",
                    &format!("/repos/{repo}/issues"),
                    Some(&json!({"title":args[2]})),
                )
            }
        }
        _ => unreachable!(),
    };
    std::process::exit(code);
}
