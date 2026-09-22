//! Synthetic, credential-free CLI exercised by `zeropw-demo` through the gateway.
use std::io::{Read, Write};
use std::net::TcpStream;

fn request(base: &str, method: &str, path: &str, body: &str) -> Result<(u16, String), String> {
    let rest = base
        .strip_prefix("http://")
        .ok_or("base URL must be HTTP")?;
    let (authority, base_path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    let (host, port) = authority.rsplit_once(':').ok_or("invalid base URL")?;
    let port: u16 = port.parse().map_err(|_| "invalid port")?;
    let mut stream = TcpStream::connect((host, port)).map_err(|_| "gateway unavailable")?;
    let target = format!("/{base_path}{path}");
    let message = format!(
        "{method} {target} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(message.as_bytes())
        .map_err(|_| "gateway write failed")?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|_| "gateway read failed")?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("invalid response")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("invalid status")?;
    Ok((
        status,
        String::from_utf8_lossy(&raw[split + 4..]).into_owned(),
    ))
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(String::as_str) == Some("steal") {
        let names = std::env::vars().map(|(k, _)| k).collect::<Vec<_>>();
        println!("{}", serde_json::json!({"env_names":names}));
        return;
    }
    let base = std::env::var("ZEROPW_API_BASE_URL").unwrap_or_default();
    let result = match args.first().map(String::as_str) {
        Some("list-repos") => request(&base, "GET", "/repos", ""),
        Some("create-issue") => request(
            &base,
            "POST",
            "/repos/demo/issues",
            &serde_json::json!({"title":args.get(2).map(String::as_str).unwrap_or("demo")})
                .to_string(),
        ),
        _ => {
            eprintln!("unsupported demo operation");
            std::process::exit(2)
        }
    };
    match result {
        Ok((status, body)) => println!("{}", serde_json::json!({"status":status,"body":body})),
        Err(reason) => {
            eprintln!("{reason}");
            std::process::exit(1)
        }
    }
}
