//! SMTP transport for incident notifications. Byte-oriented replies and zeroizing auth buffers.
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use hmac::Mac;
use md5::Md5;

use crate::notify::NotifyConfig;
use crate::secret::SecretBytes;

type Wire = Box<dyn ReadWrite>;
trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}
const MAX_LINE: usize = 8192;
const MAX_CHALLENGES: usize = 5;
struct Reply {
    code: i32,
    message: Vec<u8>,
}
fn io_error(e: std::io::Error) -> String {
    if e.get_ref()
        .and_then(|source| source.downcast_ref::<rustls::Error>())
        .is_some_and(|source| matches!(source, rustls::Error::InvalidCertificate(_)))
    {
        return "SSLCertVerificationError".into();
    }
    match e.kind() {
        std::io::ErrorKind::ConnectionRefused => "ConnectionRefusedError",
        std::io::ErrorKind::ConnectionReset => "ConnectionResetError",
        std::io::ErrorKind::BrokenPipe => "BrokenPipeError",
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => "TimeoutError",
        std::io::ErrorKind::InvalidData => "SSLError",
        std::io::ErrorKind::NotFound => "FileNotFoundError",
        _ => "OSError",
    }
    .into()
}
fn exception(name: &str) -> String {
    name.into()
}

pub(crate) fn send(config: &NotifyConfig, subject: &str, body: &str) -> Result<(), String> {
    let timeout = Duration::from_secs_f64(config.timeout_seconds.min(86400.0));
    let mut last = "OSError".to_owned();
    let mut connected = None;
    for address in (config.host.as_str(), config.port)
        .to_socket_addrs()
        .map_err(io_error)?
    {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => {
                connected = Some(stream);
                break;
            }
            Err(e) => last = io_error(e),
        }
    }
    let tcp = connected.ok_or(last)?;
    tcp.set_read_timeout(Some(timeout)).map_err(io_error)?;
    tcp.set_write_timeout(Some(timeout)).map_err(io_error)?;
    let mut wire: Wire = if config.mode == "smtps" {
        tls(config, tcp.try_clone().map_err(io_error)?)?
    } else {
        Box::new(tcp.try_clone().map_err(io_error)?)
    };
    let greeting = reply(&mut wire)?;
    if greeting.code != 220 {
        return Err(exception("SMTPConnectError"));
    }
    let (mut caps, mut esmtp) = greet(&mut wire)?;
    if config.mode == "starttls" {
        if !has_cap(&caps, "STARTTLS") {
            return Err(exception("SMTPNotSupportedError"));
        }
        if command(&mut wire, b"STARTTLS\r\n")?.code != 220 {
            return Err(exception("SMTPResponseException"));
        }
        drop(wire);
        let mut secure = tls(config, tcp)?;
        (caps, esmtp) = greet(&mut secure)?;
        return transaction(&mut secure, config, subject, body, &caps, esmtp);
    }
    transaction(&mut wire, config, subject, body, &caps, esmtp)
}
fn transaction(
    wire: &mut Wire,
    config: &NotifyConfig,
    subject: &str,
    body: &str,
    caps: &[String],
    esmtp: bool,
) -> Result<(), String> {
    if let Some(user) = &config.username {
        let raw = config
            .password_file
            .as_ref()
            .map(fs::read)
            .transpose()
            .map_err(io_error)?
            .unwrap_or_default();
        let password = SecretBytes::new(raw);
        let pass = std::str::from_utf8(password.expose())
            .map_err(|_| exception("UnicodeDecodeError"))?
            .trim()
            .as_bytes();
        let auth = auth_methods(caps);
        if auth.is_empty() {
            return Err(exception("SMTPNotSupportedError"));
        }
        let mut tried = false;
        let mut authenticated = false;
        for method in ["CRAM-MD5", "PLAIN", "LOGIN"] {
            if !auth.iter().any(|m| m == method) {
                continue;
            }
            tried = true;
            match authenticate(wire, method, user.as_bytes(), pass) {
                Ok(()) => {
                    authenticated = true;
                    break;
                }
                Err(e) if e == "SMTPAuthenticationError" => (),
                Err(e) => return Err(e),
            }
        }
        if !tried {
            return Err(exception("SMTPException"));
        }
        if !authenticated {
            return Err(exception("SMTPAuthenticationError"));
        }
    }
    let sender = mailbox(&config.sender);
    let recipients: Vec<_> = config.recipients.iter().map(|r| mailbox(r)).collect();
    let international = std::iter::once(&sender)
        .chain(recipients.iter())
        .any(|s| !s.is_ascii());
    if international && !has_cap(caps, "SMTPUTF8") {
        return Err(exception("SMTPNotSupportedError"));
    }
    let message = mime_message(config, subject, body);
    let mail = if international {
        format!("MAIL FROM:<{sender}> SMTPUTF8 BODY=8BITMIME\r\n")
    } else if esmtp && has_cap(caps, "SIZE") {
        format!("MAIL FROM:<{sender}> size={}\r\n", message.len())
    } else {
        format!("MAIL FROM:<{sender}>\r\n")
    };
    if command(wire, mail.as_bytes())?.code != 250 {
        return Err(exception("SMTPSenderRefused"));
    }
    let mut accepted = 0;
    for recipient in &recipients {
        let code = command(wire, format!("RCPT TO:<{recipient}>\r\n").as_bytes())?.code;
        if code == 250 || code == 251 {
            accepted += 1
        } else if code == 421 {
            return Err(exception("SMTPRecipientsRefused"));
        }
    }
    if accepted == 0 {
        return Err(exception("SMTPRecipientsRefused"));
    }
    if command(wire, b"DATA\r\n")?.code != 354 {
        return Err(exception("SMTPDataError"));
    }
    wire.write_all(&message).map_err(io_error)?;
    wire.write_all(b".\r\n").map_err(io_error)?;
    wire.flush().map_err(io_error)?;
    if reply(wire)?.code != 250 {
        return Err(exception("SMTPDataError"));
    }
    match command(wire, b"QUIT\r\n") {
        Ok(Reply { code: 221, .. }) => (),
        Ok(_) => return Err(exception("SMTPResponseException")),
        Err(e) if e == "SMTPServerDisconnected" => (),
        Err(e) => return Err(e),
    }
    Ok(())
}
fn mime_message(config: &NotifyConfig, subject: &str, body: &str) -> Vec<u8> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(body);
    let mut msg=format!("Subject: =?utf-8?b?{}?=\r\nFrom: {}\r\nTo: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"utf-8\"\r\nContent-Transfer-Encoding: base64\r\n\r\n",base64::engine::general_purpose::STANDARD.encode(subject),config.sender,config.recipients.join(", ")).into_bytes();
    for chunk in encoded.as_bytes().chunks(76) {
        msg.extend_from_slice(chunk);
        msg.extend_from_slice(b"\r\n");
    }
    msg
}
fn mailbox(address: &str) -> String {
    // `email.utils.parseaddr` ignores RFC 5322 comments wherever they occur
    // outside a quoted string. Keep the configured header untouched; only
    // remove comments while deriving the SMTP envelope mailbox.
    let mut without_comments = String::with_capacity(address.len());
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for ch in address.chars() {
        if escaped {
            if depth == 0 {
                without_comments.push(ch);
            }
            escaped = false;
            continue;
        }
        if ch == '\\' {
            if depth == 0 {
                without_comments.push(ch);
            }
            escaped = true;
            continue;
        }
        if ch == '"' && depth == 0 {
            quoted = !quoted;
            without_comments.push(ch);
        } else if ch == '(' && !quoted {
            if depth == 0 {
                without_comments.push(' ');
            }
            depth += 1;
        } else if ch == ')' && depth > 0 && !quoted {
            depth -= 1;
        } else if depth == 0 {
            without_comments.push(ch);
        }
    }
    if let Some(start) = without_comments.rfind('<')
        && let Some(end) = without_comments[start + 1..].find('>')
    {
        return without_comments[start + 1..start + 1 + end].trim().into();
    }
    without_comments.trim().into()
}
fn has_cap(caps: &[String], name: &str) -> bool {
    caps.iter().any(|c| {
        c.eq_ignore_ascii_case(name) || c.to_ascii_uppercase().starts_with(&format!("{name} "))
    })
}
fn auth_methods(caps: &[String]) -> Vec<String> {
    caps.iter()
        .filter_map(|c| {
            let upper = c.to_ascii_uppercase();
            upper
                .strip_prefix("AUTH ")
                .or_else(|| upper.strip_prefix("AUTH="))
                .map(str::to_owned)
        })
        .flat_map(|s| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
        .collect()
}
fn greet(wire: &mut Wire) -> Result<(Vec<String>, bool), String> {
    let ehlo = command(wire, b"EHLO localhost\r\n")?;
    if (200..300).contains(&ehlo.code) {
        return Ok((
            ehlo.message
                .split(|b| *b == b'\n')
                .map(|s| String::from_utf8_lossy(s).trim().to_owned())
                .collect(),
            true,
        ));
    }
    let helo = command(wire, b"HELO localhost\r\n")?;
    if (200..300).contains(&helo.code) {
        return Ok((vec![], false));
    }
    Err(exception("SMTPHeloError"))
}
fn command(wire: &mut Wire, cmd: &[u8]) -> Result<Reply, String> {
    wire.write_all(cmd).map_err(io_error)?;
    wire.flush().map_err(io_error)?;
    reply(wire)
}
fn command_secret(wire: &mut Wire, cmd: &SecretBytes) -> Result<Reply, String> {
    command(wire, cmd.expose())
}
fn b64_secret(bytes: &[u8]) -> Result<SecretBytes, String> {
    let mut out = vec![
        0u8;
        base64::encoded_len(bytes.len(), true)
            .ok_or_else(|| exception("SMTPException"))?
    ];
    let n = base64::engine::general_purpose::STANDARD
        .encode_slice(bytes, &mut out)
        .map_err(|_| exception("SMTPException"))?;
    out.truncate(n);
    Ok(SecretBytes::new(out))
}
fn auth_command(prefix: &[u8], payload: &SecretBytes) -> SecretBytes {
    let mut cmd = Vec::with_capacity(prefix.len() + payload.len() + 2);
    cmd.extend_from_slice(prefix);
    cmd.extend_from_slice(payload.expose());
    cmd.extend_from_slice(b"\r\n");
    SecretBytes::new(cmd)
}
fn authenticate(wire: &mut Wire, method: &str, user: &[u8], password: &[u8]) -> Result<(), String> {
    let mut response = match method {
        "CRAM-MD5" => command(wire, b"AUTH CRAM-MD5\r\n")?,
        "PLAIN" => {
            let mut plain = Vec::with_capacity(user.len() + password.len() + 2);
            plain.push(0);
            plain.extend_from_slice(user);
            plain.push(0);
            plain.extend_from_slice(password);
            let encoded = b64_secret(SecretBytes::new(plain).expose())?;
            command_secret(wire, &auth_command(b"AUTH PLAIN ", &encoded))?
        }
        "LOGIN" => {
            let encoded = b64_secret(user)?;
            command_secret(wire, &auth_command(b"AUTH LOGIN ", &encoded))?
        }
        _ => return Err(exception("SMTPException")),
    };
    for _ in 0..MAX_CHALLENGES {
        if response.code == 235 || response.code == 503 {
            return Ok(());
        }
        if response.code != 334 {
            return Err(exception("SMTPAuthenticationError"));
        }
        let encoded = match method {
            "CRAM-MD5" => {
                let challenge = crate::pybase64::b64decode_bytes(&response.message)
                    .map_err(|_| exception("SMTPException"))?;
                let mut mac = hmac::Hmac::<Md5>::new_from_slice(password)
                    .map_err(|_| exception("SMTPException"))?;
                mac.update(&challenge);
                let digest = SecretBytes::new(mac.finalize().into_bytes().to_vec());
                let hex = SecretBytes::new(hex::encode(digest.expose()).into_bytes());
                let mut answer = Vec::with_capacity(user.len() + 1 + hex.len());
                answer.extend_from_slice(user);
                answer.push(b' ');
                answer.extend_from_slice(hex.expose());
                b64_secret(SecretBytes::new(answer).expose())?
            }
            "PLAIN" => {
                let mut plain = Vec::with_capacity(user.len() + password.len() + 2);
                plain.push(0);
                plain.extend_from_slice(user);
                plain.push(0);
                plain.extend_from_slice(password);
                b64_secret(SecretBytes::new(plain).expose())?
            }
            "LOGIN" => b64_secret(password)?,
            _ => return Err(exception("SMTPException")),
        };
        response = command_secret(wire, &auth_command(b"", &encoded))?;
    }
    Err(exception("SMTPException"))
}
fn reply(wire: &mut Wire) -> Result<Reply, String> {
    let mut parts = Vec::new();
    loop {
        let mut line = Vec::new();
        loop {
            let mut b = [0u8; 1];
            match wire.read(&mut b) {
                Ok(0) => return Err(exception("SMTPServerDisconnected")),
                Ok(_) => (),
                // `smtplib.SMTP.getreply` wraps every socket read failure,
                // including timeout and reset, as SMTPServerDisconnected.
                Err(_) => return Err(exception("SMTPServerDisconnected")),
            };
            line.push(b[0]);
            if line.len() > MAX_LINE {
                return Err(exception("SMTPResponseException"));
            }
            if b[0] == b'\n' {
                break;
            }
        }
        let code = if line.len() >= 3 && line[..3].iter().all(u8::is_ascii_digit) {
            i32::from(line[0] - b'0') * 100
                + i32::from(line[1] - b'0') * 10
                + i32::from(line[2] - b'0')
        } else {
            -1
        };
        let mut message = line.get(4..).unwrap_or(&[]).to_vec();
        while message.last().is_some_and(|b| b" \t\r\n".contains(b)) {
            message.pop();
        }
        parts.push(message);
        if line.get(3) != Some(&b'-') {
            return Ok(Reply {
                code,
                message: parts.join(&b'\n'),
            });
        }
    }
}
fn tls(config: &NotifyConfig, mut tcp: TcpStream) -> Result<Wire, String> {
    let mut roots = rustls::RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs();
    for cert in certs.certs {
        let _ = roots.add(cert);
    }
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(config.host.clone())
        .map_err(|_| exception("SSLError"))?;
    let mut conn =
        rustls::ClientConnection::new(Arc::new(cfg), name).map_err(|_| exception("SSLError"))?;
    // CPython's SMTP_SSL and STARTTLS perform the TLS handshake before
    // `getreply`. Do it here too, so certificate failures keep their SSL
    // identity while later SMTP reply-read errors use getreply's wrapper.
    conn.complete_io(&mut tcp).map_err(io_error)?;
    Ok(Box::new(rustls::StreamOwned::new(conn, tcp)))
}
