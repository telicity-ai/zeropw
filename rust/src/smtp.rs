//! SMTP transport for incident notifications: the `notify._send` path through
//! `smtplib.SMTP`/`SMTP_SSL` and `email.message.EmailMessage`, with
//! byte-oriented replies and zeroizing credential buffers.
//!
//! The session mirrors `smtplib`'s own command sequence and failure mapping
//! (`ehlo`, `mail FROM:`, `rcpt TO:`, `data`, `rset`, the context manager's
//! `QUIT` after any failure inside the `with` block, `_rset` after a refusal,
//! the AUTH challenge counter), and the message is built, addressed and
//! flattened by [`header`], a port of the `email` package's header parse,
//! fold and envelope extraction (`EmailMessage`, `BytesGenerator` with the
//! default `EmailPolicy`, `getaddresses`, `quoteaddr`).
use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use hmac::Mac;
use md5::Md5;

use crate::errors::{Error, ErrorClass};
use crate::notify::NotifyConfig;
use crate::secret::SecretBytes;
use crate::sys_hostent;

mod header;

const MAX_LINE: usize = 8192;
/// `smtplib._MAXCHALLENGE`.
const MAX_CHALLENGE: u32 = 5;
/// `EmailPolicy.max_line_length` (default policy).
const MAX_LINE_LENGTH: usize = 78;
const CRLF: &str = "\r\n";

/// How a failure leaves `notify._send`.
pub(crate) enum SendError {
    /// An `OSError` or `smtplib.SMTPException` subclass, by
    /// `type(exc).__name__`: caught by `deliver`/`send_test_message`.
    Caught(String),
    /// A built-in exception Python lets escape `deliver`/`send_test_message`
    /// (PORTING.md §3.5), rendered the way `admin_cli.main` reports it.
    Escaped(Error),
}

fn caught(name: &str) -> SendError {
    SendError::Caught(name.to_owned())
}

/// A `ValueError` subclass escaping `_send` (`UnicodeDecodeError`,
/// `UnicodeEncodeError`, `binascii.Error`, `ValueError`): `admin_cli.main`
/// reports it as `StateError`/`state_corrupt` with the class name.
fn escaped_value(name: &'static str) -> SendError {
    SendError::Escaped(Error::state("state_corrupt").with_detail(name))
}

/// Any other built-in escaping `_send` (`OverflowError`): `admin_cli.main`'s
/// last resort, `{"error": <class>, "reason": "internal_error"}`.
fn escaped_other(name: &'static str) -> SendError {
    SendError::Escaped(Error::subclass(
        ErrorClass::ZeroPW,
        name,
        "internal_error",
        "",
    ))
}

/// CPython's `OSError` constructor: the PEP 3151 subclass selected by
/// `errno`, `OSError` otherwise.
fn os_error_class(error: &io::Error) -> &'static str {
    crate::pystr::os_error_class(error)
}

/// A `getaddrinfo` failure: `socket.gaierror`, except `EAI_SYSTEM`, which
/// CPython raises as the errno's `OSError` subclass (std reports only that
/// case with an OS error code).
fn resolve_error_class(error: &io::Error) -> &'static str {
    if error.raw_os_error().is_some() {
        os_error_class(error)
    } else {
        "gaierror"
    }
}

/// A TLS handshake failure (`SSLContext.wrap_socket`).
fn tls_error_class(error: &io::Error) -> &'static str {
    if let Some(source) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<rustls::Error>())
    {
        return if matches!(source, rustls::Error::InvalidCertificate(_)) {
            "SSLCertVerificationError"
        } else {
            "SSLError"
        };
    }
    match error.kind() {
        // The socket timeout interrupts the handshake: `TimeoutError`.
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => "TimeoutError",
        // OpenSSL 3 `UNEXPECTED_EOF_WHILE_READING`: `ssl.SSLEOFError`.
        io::ErrorKind::UnexpectedEof => "SSLEOFError",
        io::ErrorKind::InvalidData => "SSLError",
        _ => os_error_class(error),
    }
}

/// `notify._send(config, subject, body)`.
pub(crate) fn send(config: &NotifyConfig, subject: &str, body: &str) -> Result<(), SendError> {
    let message = Message::new(config, subject, body)?;
    // Then the password file, read before any connection and whether or not
    // a username is configured.
    let password = match &config.password_file {
        Some(path) => Some(read_password(path)?),
        None => None,
    };
    let secure = config.mode == "smtps";
    let mut client = Client::connect(config, secure)?;
    let result = session(&mut client, config, &message, password.as_ref());
    client.exit(result)
}

/// The body of `notify._send`'s `with ... as client:` block.
fn session(
    client: &mut Client,
    config: &NotifyConfig,
    message: &Message,
    password: Option<&SecretBytes>,
) -> Result<(), SendError> {
    if config.mode == "starttls" {
        client.starttls(config)?;
    }
    if let Some(user) = &config.username {
        client.login(user, password.map_or(&[][..], SecretBytes::expose))?;
    }
    client.send_message(message)
}

/// `str.splitlines()` length, as `EmailPolicy.header_store_parse` counts it.
fn python_splitlines_count(value: &str) -> usize {
    let mut count = 0;
    let mut rest = value;
    while !rest.is_empty() {
        count += 1;
        match rest.find([
            '\n', '\r', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\u{85}', '\u{2028}', '\u{2029}',
        ]) {
            Some(index) => {
                let skip = if rest[index..].starts_with("\r\n") {
                    2
                } else {
                    rest[index..].chars().next().map_or(1, char::len_utf8)
                };
                rest = &rest[index + skip..];
            }
            None => break,
        }
    }
    count
}

/// `Path(password_file).read_text(encoding="utf-8").strip()`: universal
/// newlines, strict UTF-8 and `str.strip()` whitespace.
fn read_password(path: &std::path::Path) -> Result<SecretBytes, SendError> {
    let raw = SecretBytes::new(fs::read(path).map_err(|e| caught(os_error_class(&e)))?);
    if std::str::from_utf8(raw.expose()).is_err() {
        return Err(escaped_value("UnicodeDecodeError"));
    }
    let bytes = raw.expose();
    let mut translated = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'\r' {
            translated.push(b'\n');
            index += if bytes.get(index + 1) == Some(&b'\n') {
                2
            } else {
                1
            };
        } else {
            translated.push(byte);
            index += 1;
        }
    }
    let translated = SecretBytes::new(translated);
    let text = std::str::from_utf8(translated.expose())
        .map_err(|_| escaped_value("UnicodeDecodeError"))?;
    let stripped = text.trim_matches(crate::pystr::is_space);
    Ok(SecretBytes::new(stripped.as_bytes().to_vec()))
}

enum Wire {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for Wire {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Wire::Plain(stream) => stream.read(buf),
            Wire::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for Wire {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Wire::Plain(stream) => stream.write(buf),
            Wire::Tls(stream) => stream.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Wire::Plain(stream) => stream.flush(),
            Wire::Tls(stream) => stream.flush(),
        }
    }
}

/// `smtplib.SMTP` (and `SMTP_SSL`) state used by `notify._send`.
struct Client {
    /// `self.sock`; `None` after `close()` (or a failed STARTTLS wrap, which
    /// leaves smtplib holding a detached socket).
    wire: Option<Wire>,
    local_hostname: String,
    /// `esmtp_features`, lower-case keys in insertion order.
    features: Vec<(String, String)>,
    does_esmtp: bool,
    /// `helo_resp is not None or ehlo_resp is not None`.
    greeted: bool,
    command_utf8: bool,
    auth_challenge_count: u32,
}

impl Client {
    /// `SMTP(host, port, timeout=...)` / `SMTP_SSL(...)`: `connect()`
    /// (`socket.create_connection`, the TLS wrap for SMTP_SSL, greeting),
    /// then `local_hostname`.
    fn connect(config: &NotifyConfig, secure: bool) -> Result<Self, SendError> {
        // CPython's socket.getaddrinfo applies its IDNA codec before calling
        // the platform resolver.  Do this explicitly: Rust's ToSocketAddrs
        // otherwise passes the UTF-8 spelling through and reports gaierror
        // where Python either resolves the A-label or raises UnicodeError.
        let host = idna_hostname(&config.host)?;
        let addresses: Vec<_> = (host.as_str(), config.port)
            .to_socket_addrs()
            .map_err(|e| caught(resolve_error_class(&e)))?
            .collect();
        if addresses.is_empty() {
            return Err(caught("OSError"));
        }
        // `sock.settimeout(timeout)`: seconds to whole nanoseconds, rounded
        // up; outside `_PyTime_t` it raises OverflowError.
        let nanos = (config.timeout_seconds * 1e9).ceil();
        if nanos >= 9_223_372_036_854_775_808.0 {
            return Err(escaped_other("OverflowError"));
        }
        let timeout = Duration::from_nanos((nanos as u64).max(1));
        let mut last = "OSError";
        let mut connected = None;
        for address in addresses {
            match TcpStream::connect_timeout(&address, timeout) {
                Ok(stream) => {
                    connected = Some(stream);
                    break;
                }
                Err(e) => last = os_error_class(&e),
            }
        }
        let tcp = connected.ok_or_else(|| caught(last))?;
        tcp.set_read_timeout(Some(timeout))
            .and_then(|()| tcp.set_write_timeout(Some(timeout)))
            .map_err(|e| caught(os_error_class(&e)))?;
        let wire = if secure {
            Wire::Tls(tls(config, tcp)?)
        } else {
            Wire::Plain(tcp)
        };
        let mut client = Client {
            wire: Some(wire),
            local_hostname: String::new(),
            features: Vec::new(),
            does_esmtp: false,
            greeted: false,
            command_utf8: false,
            auth_challenge_count: 0,
        };
        let (code, _) = client.getreply()?;
        if code != 220 {
            client.close();
            return Err(caught("SMTPConnectError"));
        }
        client.local_hostname = local_hostname()?;
        Ok(client)
    }

    fn close(&mut self) {
        self.wire = None;
    }

    /// `SMTP.__exit__`: `QUIT`; a reply other than 221 raises
    /// `SMTPResponseException` (replacing any failure from the block), a
    /// disconnected server is ignored; then `close()`.
    fn exit(mut self, result: Result<(), SendError>) -> Result<(), SendError> {
        let quit = match self.docmd("QUIT", "") {
            Ok((221, _)) => Ok(()),
            Ok(_) => Err(caught("SMTPResponseException")),
            Err(SendError::Caught(name)) if name == "SMTPServerDisconnected" => Ok(()),
            Err(error) => Err(error),
        };
        self.close();
        quit.and(result)
    }

    /// `send(s)`.
    fn send(&mut self, data: &[u8], text: bool) -> Result<(), SendError> {
        let Some(wire) = self.wire.as_mut() else {
            return Err(caught("SMTPServerDisconnected"));
        };
        if text && !self.command_utf8 && !data.is_ascii() {
            return Err(escaped_value("UnicodeEncodeError"));
        }
        if wire.write_all(data).and_then(|()| wire.flush()).is_err() {
            self.close();
            return Err(caught("SMTPServerDisconnected"));
        }
        Ok(())
    }

    /// `putcmd(cmd, args)`.
    fn putcmd(&mut self, cmd: &str, args: &str) -> Result<(), SendError> {
        let line = if args.is_empty() {
            cmd.to_owned()
        } else {
            format!("{cmd} {args}")
        };
        if line.contains(['\r', '\n']) {
            return Err(escaped_value("ValueError"));
        }
        self.send(format!("{line}{CRLF}").as_bytes(), true)
    }

    /// `putcmd` for a line carrying credentials (base64, never logged).
    fn putcmd_secret(&mut self, line: &SecretBytes) -> Result<(), SendError> {
        let mut data = Vec::with_capacity(line.len() + 2);
        data.extend_from_slice(line.expose());
        data.extend_from_slice(CRLF.as_bytes());
        let data = SecretBytes::new(data);
        self.send(data.expose(), true)
    }

    /// `getreply()`.
    fn getreply(&mut self) -> Result<(i128, Vec<u8>), SendError> {
        let mut resp = Vec::new();
        let code = loop {
            let Some(wire) = self.wire.as_mut() else {
                return Err(caught("SMTPServerDisconnected"));
            };
            let line = match readline(wire, MAX_LINE + 1) {
                Ok(line) if !line.is_empty() => line,
                _ => {
                    self.close();
                    return Err(caught("SMTPServerDisconnected"));
                }
            };
            if line.len() > MAX_LINE {
                self.close();
                return Err(caught("SMTPResponseException"));
            }
            resp.push(strip_bytes(line.get(4..).unwrap_or_default(), b" \t\r\n").to_vec());
            let Some(code) = reply_code(&line[..line.len().min(3)]) else {
                break -1;
            };
            if line.get(3) != Some(&b'-') {
                break code;
            }
        };
        Ok((code, resp.join(&b'\n')))
    }

    fn docmd(&mut self, cmd: &str, args: &str) -> Result<(i128, Vec<u8>), SendError> {
        self.putcmd(cmd, args)?;
        self.getreply()
    }

    /// `ehlo()`.
    fn ehlo(&mut self) -> Result<i128, SendError> {
        self.features.clear();
        let name = self.local_hostname.clone();
        self.putcmd("ehlo", &name)?;
        let (code, msg) = self.getreply()?;
        if code == -1 && msg.is_empty() {
            self.close();
            return Err(caught("SMTPServerDisconnected"));
        }
        self.greeted = true;
        if code != 250 {
            return Ok(code);
        }
        self.does_esmtp = true;
        let text: String = msg.iter().map(|&b| char::from(b)).collect();
        for each in text.split('\n').skip(1) {
            if each.len() >= 5
                && each
                    .get(..5)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("auth="))
            {
                let params = &each[5..];
                self.extend_auth(params);
                continue;
            }
            let feature_len = each
                .char_indices()
                .take_while(|(i, c)| c.is_ascii_alphanumeric() || (*i > 0 && *c == '-'))
                .count();
            if feature_len == 0 {
                continue;
            }
            let feature = each[..feature_len].to_ascii_lowercase();
            let params = each[feature_len..]
                .trim_matches(crate::pystr::is_space)
                .to_owned();
            if feature == "auth" {
                self.extend_auth(&params);
            } else {
                self.set_feature(&feature, params);
            }
        }
        Ok(code)
    }

    fn extend_auth(&mut self, params: &str) {
        let current = self.feature("auth").unwrap_or_default().to_owned();
        self.set_feature("auth", format!("{current} {params}"));
    }

    fn set_feature(&mut self, key: &str, value: String) {
        match self.features.iter_mut().find(|(k, _)| k == key) {
            Some(entry) => entry.1 = value,
            None => self.features.push((key.to_owned(), value)),
        }
    }

    fn feature(&self, key: &str) -> Option<&str> {
        self.features
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// `has_extn(opt)`.
    fn has_extn(&self, opt: &str) -> bool {
        self.feature(&opt.to_ascii_lowercase()).is_some()
    }

    /// `ehlo_or_helo_if_needed()`.
    fn ehlo_or_helo_if_needed(&mut self) -> Result<(), SendError> {
        if self.greeted {
            return Ok(());
        }
        if !(200..=299).contains(&self.ehlo()?) {
            let name = self.local_hostname.clone();
            let (code, _) = self.docmd("helo", &name)?;
            self.greeted = true;
            if !(200..=299).contains(&code) {
                return Err(caught("SMTPHeloError"));
            }
        }
        Ok(())
    }

    /// `starttls(context=ssl.create_default_context())`.
    fn starttls(&mut self, config: &NotifyConfig) -> Result<(), SendError> {
        self.ehlo_or_helo_if_needed()?;
        if !self.has_extn("starttls") {
            return Err(caught("SMTPNotSupportedError"));
        }
        let (code, _) = self.docmd("STARTTLS", "")?;
        if code != 220 {
            return Err(caught("SMTPResponseException"));
        }
        // `wrap_socket` detaches smtplib's socket first, so after a failed
        // handshake every later command (the exit `QUIT`) is disconnected.
        let Some(Wire::Plain(tcp)) = self.wire.take() else {
            return Err(caught("SMTPServerDisconnected"));
        };
        self.wire = Some(Wire::Tls(tls(config, tcp)?));
        self.greeted = false;
        self.features.clear();
        self.does_esmtp = false;
        Ok(())
    }

    /// `login(user, password)`.
    fn login(&mut self, user: &str, password: &[u8]) -> Result<(), SendError> {
        self.ehlo_or_helo_if_needed()?;
        let Some(advertised) = self.feature("auth") else {
            return Err(caught("SMTPNotSupportedError"));
        };
        let advertised: Vec<String> = advertised
            .split(crate::pystr::is_space)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        let authlist: Vec<&str> = ["CRAM-MD5", "PLAIN", "LOGIN"]
            .into_iter()
            .filter(|method| advertised.iter().any(|a| a == method))
            .collect();
        if authlist.is_empty() {
            return Err(caught("SMTPException"));
        }
        let mut last = caught("SMTPAuthenticationError");
        for method in authlist {
            match self.auth(method, user, password) {
                Ok(()) => return Ok(()),
                Err(SendError::Caught(name)) if name == "SMTPAuthenticationError" => {
                    last = SendError::Caught(name);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last)
    }

    /// `auth(mechanism, authobject)` with `auth_cram_md5`/`auth_plain`/
    /// `auth_login`.
    fn auth(&mut self, mechanism: &str, user: &str, password: &[u8]) -> Result<(), SendError> {
        let initial = match mechanism {
            "CRAM-MD5" => None,
            "PLAIN" => Some(plain_response(user, password)?),
            _ => Some(ascii_secret(user.as_bytes())?),
        };
        let (mut code, mut resp) = match initial {
            Some(initial) => {
                let encoded = b64_secret(initial.expose())?;
                let mut line = format!("AUTH {mechanism} ").into_bytes();
                line.extend_from_slice(encoded.expose());
                let line = SecretBytes::new(line);
                self.putcmd_secret(&line)?;
                self.auth_challenge_count = 1;
                self.getreply()?
            }
            None => {
                let reply = self.docmd("AUTH", mechanism)?;
                self.auth_challenge_count = 0;
                reply
            }
        };
        while code == 334 {
            self.auth_challenge_count += 1;
            let challenge =
                crate::pybase64::b64decode_bytes(&resp).map_err(|_| escaped_value("Error"))?;
            let answer = match mechanism {
                "CRAM-MD5" => {
                    if !password.is_ascii() {
                        return Err(escaped_value("UnicodeEncodeError"));
                    }
                    let mut mac = hmac::Hmac::<Md5>::new_from_slice(password)
                        .map_err(|_| caught("SMTPException"))?;
                    mac.update(&challenge);
                    let digest = SecretBytes::new(mac.finalize().into_bytes().to_vec());
                    let hex = SecretBytes::new(hex::encode(digest.expose()).into_bytes());
                    let mut answer = Vec::with_capacity(user.len() + 1 + hex.len());
                    answer.extend_from_slice(user.as_bytes());
                    answer.push(b' ');
                    answer.extend_from_slice(hex.expose());
                    ascii_secret(SecretBytes::new(answer).expose())?
                }
                "PLAIN" => plain_response(user, password)?,
                _ if self.auth_challenge_count < 2 => ascii_secret(user.as_bytes())?,
                _ => ascii_secret(password)?,
            };
            let encoded = b64_secret(answer.expose())?;
            self.putcmd_secret(&encoded)?;
            (code, resp) = self.getreply()?;
            if self.auth_challenge_count > MAX_CHALLENGE {
                return Err(caught("SMTPException"));
            }
        }
        if code == 235 || code == 503 {
            Ok(())
        } else {
            Err(caught("SMTPAuthenticationError"))
        }
    }

    /// `send_message(message)` for `notify._send`'s message.
    fn send_message(&mut self, message: &Message) -> Result<(), SendError> {
        self.ehlo_or_helo_if_needed()?;
        let (from, to) = message.envelope()?;
        let international = !from.is_ascii() || to.iter().any(|r| !r.is_ascii());
        if international && !self.has_extn("smtputf8") {
            return Err(caught("SMTPNotSupportedError"));
        }
        let flat = message.flatten(international)?;
        let options: &[&str] = if international {
            &["SMTPUTF8", "BODY=8BITMIME"]
        } else {
            &[]
        };
        self.sendmail(&from, &to, &flat, options)
    }

    /// `sendmail(from_addr, to_addrs, msg, mail_options)`.
    fn sendmail(
        &mut self,
        from: &str,
        to: &[String],
        msg: &[u8],
        mail_options: &[&str],
    ) -> Result<(), SendError> {
        self.ehlo_or_helo_if_needed()?;
        let mut esmtp_opts = Vec::new();
        if self.does_esmtp {
            if self.has_extn("size") {
                esmtp_opts.push(format!("size={}", msg.len()));
            }
            esmtp_opts.extend(mail_options.iter().map(|o| (*o).to_owned()));
        }
        let (code, _) = self.mail(from, &esmtp_opts)?;
        if code != 250 {
            self.close_or_rset(code)?;
            return Err(caught("SMTPSenderRefused"));
        }
        let mut refused = HashSet::new();
        for each in to {
            let quoted = header::quoteaddr(each).map_err(email_error)?;
            let (code, _) = self.docmd("rcpt", &format!("TO:{quoted}"))?;
            if code != 250 && code != 251 {
                refused.insert(each.as_str());
            }
            if code == 421 {
                self.close();
                return Err(caught("SMTPRecipientsRefused"));
            }
        }
        if refused.len() == to.len() {
            self.rset_quietly()?;
            return Err(caught("SMTPRecipientsRefused"));
        }
        let code = self.data(msg)?;
        if code != 250 {
            self.close_or_rset(code)?;
            return Err(caught("SMTPDataError"));
        }
        Ok(())
    }

    fn close_or_rset(&mut self, code: i128) -> Result<(), SendError> {
        if code == 421 {
            self.close();
            Ok(())
        } else {
            self.rset_quietly()
        }
    }

    /// `mail(sender, options)`.
    fn mail(&mut self, sender: &str, options: &[String]) -> Result<(i128, Vec<u8>), SendError> {
        let mut optionlist = String::new();
        if !options.is_empty() && self.does_esmtp {
            if options.iter().any(|o| o.eq_ignore_ascii_case("smtputf8")) {
                if self.has_extn("smtputf8") {
                    self.command_utf8 = true;
                } else {
                    return Err(caught("SMTPNotSupportedError"));
                }
            }
            optionlist = format!(" {}", options.join(" "));
        }
        let quoted = header::quoteaddr(sender).map_err(email_error)?;
        self.docmd("mail", &format!("FROM:{quoted}{optionlist}"))
    }

    /// `data(msg)`: dot-stuffing and the terminating line.
    fn data(&mut self, msg: &[u8]) -> Result<i128, SendError> {
        let (code, _) = self.docmd("data", "")?;
        if code != 354 {
            return Err(caught("SMTPDataError"));
        }
        let mut quoted = Vec::with_capacity(msg.len() + 8);
        for (index, &byte) in msg.iter().enumerate() {
            if byte == b'.' && (index == 0 || msg[index - 1] == b'\n') {
                quoted.push(b'.');
            }
            quoted.push(byte);
        }
        if !quoted.ends_with(CRLF.as_bytes()) {
            quoted.extend_from_slice(CRLF.as_bytes());
        }
        quoted.extend_from_slice(b".\r\n");
        self.send(&quoted, false)?;
        Ok(self.getreply()?.0)
    }

    /// `_rset()`: `rset()`, ignoring a disconnected server.
    fn rset_quietly(&mut self) -> Result<(), SendError> {
        self.command_utf8 = false;
        match self.docmd("rset", "") {
            Ok(_) => Ok(()),
            Err(SendError::Caught(name)) if name == "SMTPServerDisconnected" => Ok(()),
            Err(error) => Err(error),
        }
    }
}

fn readline(wire: &mut Wire, limit: usize) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while line.len() < limit {
        if wire.read(&mut byte)? == 0 {
            break;
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    Ok(line)
}

/// `int(line[:3])` on bytes: ASCII only, Python's `int()` grammar.
fn reply_code(code: &[u8]) -> Option<i128> {
    if !code.is_ascii() {
        return None;
    }
    crate::pystr::int_from_str(std::str::from_utf8(code).ok()?)
}

fn strip_bytes<'a>(mut data: &'a [u8], chars: &[u8]) -> &'a [u8] {
    while let [first, rest @ ..] = data {
        if !chars.contains(first) {
            break;
        }
        data = rest;
    }
    while let [rest @ .., last] = data {
        if !chars.contains(last) {
            break;
        }
        data = rest;
    }
    data
}

/// `s.encode('ascii')` of a credential string.
fn ascii_secret(bytes: &[u8]) -> Result<SecretBytes, SendError> {
    if !bytes.is_ascii() {
        return Err(escaped_value("UnicodeEncodeError"));
    }
    Ok(SecretBytes::new(bytes.to_vec()))
}

/// `("\0%s\0%s" % (user, password)).encode('ascii')`.
fn plain_response(user: &str, password: &[u8]) -> Result<SecretBytes, SendError> {
    let mut plain = Vec::with_capacity(user.len() + password.len() + 2);
    plain.push(0);
    plain.extend_from_slice(user.as_bytes());
    plain.push(0);
    plain.extend_from_slice(password);
    ascii_secret(SecretBytes::new(plain).expose())
}

fn b64_secret(bytes: &[u8]) -> Result<SecretBytes, SendError> {
    let mut out =
        vec![0u8; base64::encoded_len(bytes.len(), true).ok_or_else(|| caught("SMTPException"))?];
    let n = base64::engine::general_purpose::STANDARD
        .encode_slice(bytes, &mut out)
        .map_err(|_| caught("SMTPException"))?;
    out.truncate(n);
    Ok(SecretBytes::new(out))
}

/// `smtplib.SMTP.__init__`'s default `local_hostname`: `socket.getfqdn()`
/// when it contains a dot, else `'[%s]' % gethostbyname(gethostname())`
/// (`127.0.0.1` when that lookup raises `gaierror`). Any other exception
/// escapes `SMTP()` the way it escapes the constructor in Python.
fn local_hostname() -> Result<String, SendError> {
    let fqdn = getfqdn("").map_err(|e| socket_exception(&e))?;
    if fqdn.contains('.') {
        return Ok(fqdn);
    }
    let address = match gethostname().and_then(|name| sys_hostent::gethostbyname(&name)) {
        Ok(address) => address.to_string(),
        Err(e) if sys_hostent::exception_class(&e) == "gaierror" => "127.0.0.1".to_owned(),
        Err(e) => return Err(socket_exception(&e)),
    };
    Ok(format!("[{address}]"))
}

/// How an exception from the socket name functions leaves `notify._send`:
/// `OSError` subclasses are caught by `deliver`/`send_test_message`; the
/// `ValueError` subclasses (`UnicodeError`, `UnicodeDecodeError`) and
/// `TypeError` escape.
fn socket_exception(error: &io::Error) -> SendError {
    match sys_hostent::exception_class(error) {
        class @ ("UnicodeError" | "UnicodeDecodeError") => escaped_value(class),
        "TypeError" => escaped_other("TypeError"),
        class => caught(class),
    }
}

/// The IDNA 2003 conversion performed by CPython's socket module.
fn idna_hostname(hostname: &str) -> Result<String, SendError> {
    crate::pyidna::encode(hostname).map_err(|_| escaped_value("UnicodeError"))
}

/// `socket.gethostname()`: `uname().nodename` on every POSIX platform,
/// decoded with the filesystem encoding (UTF-8, `surrogateescape`). A
/// name that is not valid UTF-8 decodes to lone surrogates, which the
/// `idna` codec of every function this module passes it to rejects with
/// `UnicodeError`; that error is reported here, before the lookup.
fn gethostname() -> io::Result<String> {
    rustix::system::uname()
        .nodename()
        .to_str()
        .map(str::to_owned)
        .map_err(|_| sys_hostent::HostError::Unicode.into())
}

/// `socket.getfqdn(name)` (Lib/socket.py): `gethostbyaddr(name)`, then the
/// first of `[hostname] + aliases` containing a dot, else `hostname`; the
/// name unchanged when the lookup raises `OSError`. Other exceptions
/// (`UnicodeError`, `TypeError`, `UnicodeDecodeError`) propagate.
fn getfqdn(name: &str) -> io::Result<String> {
    let mut name = name.trim_matches(crate::pystr::is_space).to_owned();
    if name.is_empty() || name == "0.0.0.0" || name == "::" {
        name = gethostname()?;
    }
    match sys_hostent::gethostbyaddr(&name) {
        Ok((hostname, aliases, _)) => Ok(std::iter::once(&hostname)
            .chain(aliases.iter())
            .find(|candidate| candidate.contains('.'))
            .unwrap_or(&hostname)
            .clone()),
        Err(e) if sys_hostent::is_os_error(&e) => Ok(name),
        Err(e) => Err(e),
    }
}

/// `EmailMessage` as built by `notify._send`: Subject, From, To, then
/// `set_content(body)` (Content-Type, Content-Transfer-Encoding,
/// MIME-Version).
struct Message {
    headers: [header::Header; 3],
    cte: &'static str,
    /// The payload, `\n`-terminated lines.
    payload: Vec<u8>,
}

/// A Python exception escaping the email package, the way
/// `deliver`/`send_test_message` and `admin_cli.main` see it.
fn email_error(error: header::Ex) -> SendError {
    match error {
        header::Ex::Parse | header::Ex::InvalidEw => escaped_other("HeaderParseError"),
        header::Ex::Builtin(name) => match name {
            "AttributeError" | "TypeError" | "KeyError" | "ValueError" | "UnicodeError"
            | "UnicodeEncodeError" | "UnicodeDecodeError" => escaped_value(name),
            name => escaped_other(name),
        },
    }
}

impl Message {
    /// `message["Subject"] = subject; message["From"] = config.sender;
    /// message["To"] = ", ".join(config.recipients); message.set_content(body)`.
    /// Each assignment is `EmailPolicy.header_store_parse`: a value that
    /// `str.splitlines()` splits is `ValueError`, then the header parses.
    fn new(config: &NotifyConfig, subject: &str, body: &str) -> Result<Self, SendError> {
        let to = config.recipients.join(", ");
        let store = |value: &str| {
            if python_splitlines_count(value) > 1 {
                Err(escaped_value("ValueError"))
            } else {
                Ok(())
            }
        };
        store(subject)?;
        let subject = header::unstructured_header("Subject", subject).map_err(email_error)?;
        store(&config.sender)?;
        let from = header::address_header("From", &config.sender).map_err(email_error)?;
        store(&to)?;
        let to = header::address_header("To", &to).map_err(email_error)?;
        let (cte, payload) = encode_text(body);
        Ok(Message {
            headers: [subject, from, to],
            cte,
            payload,
        })
    }

    /// `send_message`'s envelope: `getaddresses([msg["From"]])[0][1]` and
    /// `[a[1] for a in getaddresses([msg["To"]])]`.
    fn envelope(&self) -> Result<(String, Vec<String>), SendError> {
        let [_, from, to] = &self.headers;
        let from = header::getaddresses(&from.decoded)
            .map_err(email_error)?
            .into_iter()
            .next()
            .unwrap_or_default();
        let to = header::getaddresses(&to.decoded).map_err(email_error)?;
        Ok((from, to))
    }

    /// `BytesGenerator(policy).flatten(msg, linesep="\r\n")`, with
    /// `policy.utf8` for an internationalized envelope: each header is
    /// folded (`fold_binary`) and checked by `verify_generated_headers`
    /// (`HeaderWriteError`) in turn.
    fn flatten(&self, utf8: bool) -> Result<Vec<u8>, SendError> {
        let mut bytes = Vec::new();
        let fixed = [
            "Content-Type: text/plain; charset=\"utf-8\"\r\n".to_owned(),
            format!("Content-Transfer-Encoding: {}{CRLF}", self.cte),
            "MIME-Version: 1.0\r\n".to_owned(),
        ];
        let folded = self
            .headers
            .iter()
            .map(|h| h.fold_binary(utf8).map_err(email_error))
            .chain(fixed.into_iter().map(|h| Ok(h.into_bytes())));
        for folded in folded {
            let folded = folded?;
            if !verified_header(&folded) {
                return Err(escaped_other("HeaderWriteError"));
            }
            bytes.extend_from_slice(&folded);
        }
        bytes.extend_from_slice(CRLF.as_bytes());
        // `_write_lines`: every `\n`-terminated payload line ends in CRLF.
        for line in self.payload.split_inclusive(|b| *b == b'\n') {
            bytes.extend_from_slice(line.strip_suffix(b"\n").unwrap_or(line));
            bytes.extend_from_slice(CRLF.as_bytes());
        }
        Ok(bytes)
    }
}

/// `BytesGenerator._write_headers`' `verify_generated_headers` check
/// (CPython 3.12.14): the folded header ends with the line separator and
/// has no other line break that is not followed by `WSP`
/// (`NEWLINE_WITHOUT_FWSP_BYTES`).
fn verified_header(folded: &[u8]) -> bool {
    let Some(body) = folded.strip_suffix(CRLF.as_bytes()) else {
        return false;
    };
    let wsp = |at: usize| matches!(body.get(at), Some(b' ' | b'\t'));
    !body.iter().enumerate().any(|(i, byte)| match byte {
        b'\r' if body.get(i + 1) == Some(&b'\n') => i + 2 < body.len() && !wsp(i + 2),
        b'\r' => i + 1 < body.len() && !wsp(i + 1),
        b'\n' => i + 1 < body.len() && !wsp(i + 1),
        _ => false,
    })
}

/// `email.contentmanager._encode_text(body, "utf-8", None, policy.default)`.
fn encode_text(body: &str) -> (&'static str, Vec<u8>) {
    let lines = bytes_splitlines(body.as_bytes());
    // `normal_body`/`embedded_body` (the default policy's linesep is `\n`).
    let joined = |lines: &[&[u8]]| -> Vec<u8> {
        let mut out = lines.join(&b'\n');
        out.push(b'\n');
        out
    };
    let normal = joined(&lines);
    if lines.iter().map(|l| l.len()).max().unwrap_or(0) <= MAX_LINE_LENGTH {
        return (if normal.is_ascii() { "7bit" } else { "8bit" }, normal);
    }
    let sniff = joined(&lines[..lines.len().min(10)]);
    let sniff_qp = qp_body_encode(&sniff);
    // `binascii.b2a_base64(sniff)` including its newline.
    let sniff_base64 = sniff.len().div_ceil(3) * 4 + 1;
    if sniff_qp.len() > sniff_base64 {
        let mut payload = Vec::new();
        for chunk in normal.chunks(MAX_LINE_LENGTH / 4 * 3) {
            payload.extend_from_slice(crate::pybase64::b64encode(chunk).as_bytes());
            payload.push(b'\n');
        }
        return ("base64", payload);
    }
    if lines.len() <= 10 {
        return ("quoted-printable", sniff_qp);
    }
    ("quoted-printable", qp_body_encode(&normal))
}

/// `bytes.splitlines()`: `\r\n`, `\r` and `\n` end a line.
fn bytes_splitlines(data: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while let Some(&byte) = data.get(index) {
        if byte == b'\n' || byte == b'\r' {
            lines.push(&data[start..index]);
            index += if byte == b'\r' && data.get(index + 1) == Some(&b'\n') {
                2
            } else {
                1
            };
            start = index;
        } else {
            index += 1;
        }
    }
    if start < data.len() {
        lines.push(&data[start..]);
    }
    lines
}

/// `quoprimime.body_encode(data.decode('latin-1'), 78)` (`eol="\n"`).
fn qp_body_encode(data: &[u8]) -> Vec<u8> {
    const SAFE: &[u8] = b" !\"#$%&'()*+,-./0123456789:;<>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\t\r\n";
    if data.is_empty() {
        return Vec::new();
    }
    let mut translated = Vec::with_capacity(data.len() * 3);
    for &byte in data {
        if SAFE.contains(&byte) {
            translated.push(byte);
        } else {
            translated.extend_from_slice(format!("={byte:02X}").as_bytes());
        }
    }
    let quote = |byte: u8| format!("={byte:02X}").into_bytes();
    let maxlinelen1 = MAX_LINE_LENGTH - 1;
    let mut encoded: Vec<Vec<u8>> = Vec::new();
    for line in bytes_splitlines(&translated) {
        let mut start = 0usize;
        let laststart = line.len() as isize - 1 - MAX_LINE_LENGTH as isize;
        while start as isize <= laststart {
            let stop = start + maxlinelen1;
            if line.get(stop - 2) == Some(&b'=') {
                encoded.push(line[start..stop - 1].to_vec());
                start = stop - 2;
            } else if line.get(stop - 1) == Some(&b'=') {
                encoded.push(line[start..stop].to_vec());
                start = stop - 1;
            } else {
                let mut piece = line[start..stop].to_vec();
                piece.push(b'=');
                encoded.push(piece);
                start = stop;
            }
        }
        match line.last() {
            Some(&last) if last == b' ' || last == b'\t' => {
                let room = start as isize - laststart;
                let mut piece = line[start..line.len() - 1].to_vec();
                if room >= 3 {
                    piece.extend(quote(last));
                } else if room == 2 {
                    piece.push(last);
                    piece.extend_from_slice(b"=\n");
                } else {
                    piece.extend_from_slice(b"=\n");
                    piece.extend(quote(last));
                }
                encoded.push(piece);
            }
            _ => encoded.push(line[start..].to_vec()),
        }
    }
    if matches!(translated.last(), Some(b'\r' | b'\n')) {
        encoded.push(Vec::new());
    }
    encoded.join(&b'\n')
}

/// `SSLContext.wrap_socket(sock, server_hostname=host)` with the default
/// context, handshake included (`do_handshake_on_connect`).
fn tls(
    config: &NotifyConfig,
    mut tcp: TcpStream,
) -> Result<Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>, SendError> {
    let mut roots = rustls::RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs();
    for cert in certs.certs {
        let _ = roots.add(cert);
    }
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(config.host.clone())
        .map_err(|_| caught("SSLError"))?;
    let mut conn =
        rustls::ClientConnection::new(Arc::new(cfg), name).map_err(|_| caught("SSLError"))?;
    // CPython's SMTP_SSL and STARTTLS perform the TLS handshake before
    // `getreply`, so certificate failures keep their SSL identity while
    // later SMTP reply-read errors use getreply's wrapper.
    conn.complete_io(&mut tcp)
        .map_err(|e| caught(tls_error_class(&e)))?;
    Ok(Box::new(rustls::StreamOwned::new(conn, tcp)))
}

#[cfg(test)]
mod message_tests {
    use super::{Message, SendError, email_error, header};
    use crate::notify::NotifyConfig;
    use serde_json::{Value, json};

    fn config(sender: &str, recipients: &[String]) -> NotifyConfig {
        NotifyConfig {
            host: "127.0.0.1".into(),
            port: 25,
            mode: "plain".into(),
            sender: sender.into(),
            recipients: recipients.to_vec(),
            username: None,
            password_file: None,
            timeout_seconds: 20.0,
        }
    }

    /// The exception class a `SendError` stands for.
    fn class_name(error: SendError) -> String {
        match error {
            SendError::Caught(name) => name,
            SendError::Escaped(error) if error.reason == "state_corrupt" => error.detail,
            SendError::Escaped(error) => error.name.into_owned(),
        }
    }

    /// One `[subject, sender, recipients, body]` case through this port:
    /// the `EmailMessage` assignments, `send_message`'s envelope and
    /// `quoteaddr` spellings, the international decision, and the flattened
    /// bytes or the exception that stops each stage.
    fn rust_outcome(case: &Value) -> Value {
        let text = |index: usize| case[index].as_str().unwrap_or_default().to_owned();
        let recipients: Vec<String> = case[2]
            .as_array()
            .map(|list| {
                list.iter()
                    .map(|r| r.as_str().unwrap_or_default().to_owned())
                    .collect()
            })
            .unwrap_or_default();
        let message = match Message::new(&config(&text(1), &recipients), &text(0), &text(3)) {
            Ok(message) => message,
            Err(error) => return json!({"error": class_name(error), "stage": "build"}),
        };
        let (from, to) = match message.envelope() {
            Ok(envelope) => envelope,
            Err(error) => return json!({"error": class_name(error), "stage": "envelope"}),
        };
        let mut quoted = Vec::new();
        for address in std::iter::once(&from).chain(&to) {
            match header::quoteaddr(address) {
                Ok(spelling) => quoted.push(spelling),
                Err(error) => {
                    return json!({"error": class_name(email_error(error)), "stage": "envelope"});
                }
            }
        }
        let intl = !from.is_ascii() || to.iter().any(|r| !r.is_ascii());
        match message.flatten(intl) {
            Ok(bytes) => json!({
                "from": from, "to": to, "quoted": quoted, "intl": intl,
                "bytes": crate::pybase64::b64encode(&bytes),
            }),
            Err(error) => json!({
                "error": class_name(error), "stage": "flatten",
                "from": from, "to": to, "quoted": quoted, "intl": intl,
            }),
        }
    }

    /// The same pipeline in CPython: `notify._send`'s message, then
    /// `smtplib.send_message`'s envelope (`getaddresses`, `quoteaddr`) and
    /// `BytesGenerator` flatten.
    fn python_outcomes(cases: &[Value]) -> Vec<Value> {
        let encoded =
            crate::pybase64::b64encode(Value::Array(cases.to_vec()).to_string().as_bytes());
        let script = format!(
            r#"
import base64, email.generator, email.utils, io, json, smtplib
from email.message import EmailMessage
def run(subject, sender, recipients, body):
    try:
        m = EmailMessage()
        m["Subject"] = subject
        m["From"] = sender
        m["To"] = ", ".join(recipients)
        m.set_content(body)
    except Exception as e:
        return {{"error": type(e).__name__, "stage": "build"}}
    try:
        from_addr = email.utils.getaddresses([m["From"]])[0][1]
        to_addrs = [a[1] for a in email.utils.getaddresses([m["To"]])]
        quoted = [smtplib.quoteaddr(a) for a in [from_addr, *to_addrs]]
    except Exception as e:
        return {{"error": type(e).__name__, "stage": "envelope"}}
    try:
        "".join([from_addr, *to_addrs]).encode("ascii")
        intl = False
    except UnicodeEncodeError:
        intl = True
    b = io.BytesIO()
    g = email.generator.BytesGenerator(b, policy=m.policy.clone(utf8=True)) if intl else email.generator.BytesGenerator(b)
    try:
        g.flatten(m, linesep="\r\n")
    except Exception as e:
        return {{"error": type(e).__name__, "stage": "flatten", "from": from_addr, "to": to_addrs, "quoted": quoted, "intl": intl}}
    return {{"from": from_addr, "to": to_addrs, "quoted": quoted, "intl": intl, "bytes": base64.b64encode(b.getvalue()).decode()}}
out = [run(*case) for case in json.loads(base64.b64decode("{encoded}"))]
print(json.dumps(out))
"#
        );
        serde_json::from_str(crate::oracle::python(&script).trim()).unwrap()
    }

    /// Every case through both pipelines; returns the Python outcomes.
    fn assert_parity(cases: &[Value]) -> Vec<Value> {
        let expected = python_outcomes(cases);
        let mut mismatches = vec![];
        for (case, expected) in cases.iter().zip(&expected) {
            let actual = rust_outcome(case);
            if &actual != expected {
                mismatches.push(format!(
                    "case {case}\n python: {expected}\n rust:   {actual}"
                ));
            }
        }
        assert!(
            mismatches.is_empty(),
            "{} of {} cases differ:\n{}",
            mismatches.len(),
            cases.len(),
            mismatches.join("\n")
        );
        expected
    }

    fn case(subject: &str, sender: &str, recipients: &[&str]) -> Value {
        json!([subject, sender, recipients, "x\n"])
    }

    /// `notify._send`'s message flattened the way `send_message` does
    /// (`BytesGenerator`, `linesep="\r\n"`, `utf8` policy for an
    /// internationalized envelope), for generated subject/sender/recipient
    /// shapes including folding and RFC 2047 encoding, compared byte for
    /// byte with Python.
    #[test]
    fn flattened_message_matches_python_bytes() {
        let names = [
            "",
            "A",
            "ZeroPW",
            "ZeroPW 알림",
            "관리자",
            "Ünïcode Náme",
            "\"Doe, John\"",
            "Joe Q. Public",
            "\"관리자 (보안)\"",
            "\"quoted \\\"inner\\\" name\"",
            "Security Operations Response Team Distribution List For ZeroPW Incidents",
            "관리자 한국어 이름이 아주 길어서 한 줄에 다 들어가지 않는 경우를 시험합니다",
            "ZeroPW 보안 알림 수신자 목록 Security Notification Recipients",
        ];
        let addresses = [
            "a@example.com",
            "very.long.local.part.for.folding.checks@subdomain.example-domain.com",
            "사용자@example.com",
        ];
        let mailboxes: Vec<String> = names
            .iter()
            .flat_map(|name| {
                addresses.iter().map(move |address| {
                    if name.is_empty() {
                        (*address).to_owned()
                    } else {
                        format!("{name} <{address}>")
                    }
                })
            })
            .collect();
        let subjects = [
            "[ZeroPW] 침입 감지 — 서비스 정지, 자격증명 교체 필요 (사건 inc-20231114T221320Z-0123abcd)"
                .to_owned(),
            "[ZeroPW] 알림 설정 시험 메시지".to_owned(),
            "plain ascii subject".to_owned(),
            format!("[ZeroPW] {} (사건 inc-1)", "x".repeat(90)),
            format!("{} 끝", "가나다라마바사 ".repeat(12)),
            "a;b [c] (d), e: \"f\" g.h".to_owned(),
        ];
        let body = "ZeroPW 알림 설정을 확인하기 위한 시험 메시지입니다.\n실제 침입 사건이 아닙니다. 이 메시지가 도착했다면 SMTP 설정이 올바르게 동작합니다.\n";
        let mut cases = vec![];
        for (index, sender) in mailboxes.iter().enumerate() {
            let recipients: Vec<String> = (0..1 + index % 4)
                .map(|offset| mailboxes[(index * 7 + offset * 5) % mailboxes.len()].clone())
                .collect();
            let subject = &subjects[index % subjects.len()];
            cases.push(json!([subject, sender, recipients, body]));
        }
        for subject in &subjects {
            cases.push(json!([subject, "a@example.com", ["b@example.com"], body]));
        }
        assert_parity(&cases);
    }

    /// Encoded words in the subject and in display names, local parts and
    /// domains: every charset family CPython's codec registry resolves
    /// (UTF-8 with undecodable bytes as surrogates, `unknown-8bit`, unknown
    /// names, single-byte charmaps, non-text codecs, `undefined`).
    #[test]
    fn encoded_word_headers_match_python_bytes() {
        let subjects = [
            "=?utf-8?q?Hello_=E2=9C=93?=",
            "=?UTF-8?B?7ZWc6riA?=",
            "=?utf-8?b?SGVsbG8?=",
            "=?utf-8?b?SGVsbG8$?=",
            "=?utf-8?b?SGVsbG8x?=",
            "=?utf-8?b?SGVsb?=",
            "=?utf-8?q?bad=Z1=2?=",
            "=?utf-8?q?one?=   =?utf-8?q?two?=",
            "prefix=?utf-8?q?middle?=suffix",
            "=?iso-8859-1?q?caf=E9?=",
            "=?x-unknown?q?plain?=",
            "=?x-unknown?q?caf=E9?=",
            "=?unknown-8bit?q?caf=E9?=",
            "=?utf-8?q?unterminated",
            "=?utf-8?x?invalid?=",
            "=?utf-8?q?=FF=FE_invalid_utf8?=",
            "=?utf-8?q?=E2=9C?= truncated",
            "=?us-ascii?q?caf=E9?=",
            "=?windows-1252?q?=80uro_=93quoted=94?=",
            "=?koi8-r?b?8NLJ18XU?=",
            "=?cp424?q?=00=01=02?=",
            "=?cp424?q?=FF?=",
            "=?iso8859_15?q?=A4?=",
            "=?Latin_1?q?=E9?=",
            "=?utf-8-sig?q?=EF=BB=BFbom?=",
            "=?base64?q?abc?=",
            "=?undefined?q?abc?=",
            "=?utf.8?q?abc?=",
            "=?ut f-8?q?abc?=",
            "=?utf-8*en?q?lang?=",
            "=?utf-8?q?a=0Ab?=",
            "=?utf-8?q?tab=09here?=",
            "word =?utf-8?q?=E2=9C=93?= word =?utf-8?q?=E2=9C=93?=",
            "=?utf-8?q?=E2=9C=93?==?utf-8?q?=E2=9C=93?=",
        ];
        let mut cases: Vec<Value> = subjects
            .iter()
            .map(|subject| case(subject, "a@example.com", &["b@example.com"]))
            .collect();
        for sender in [
            "=?utf-8?q?Admin_=E2=9C=93?= <a@example.com>",
            "=?utf-8?b?7ZWc6riA?= <b@example.com>",
            "=?utf-8?q?one?= \t =?utf-8?q?two?= <b@example.com>",
            "=?utf-8?q?=FF?= <a@example.com>",
            "=?x-unknown?q?=FF?= <a@example.com>",
            "=?utf-8?q?a=0Ab?= <a@example.com>",
            "=?utf-8?q?a=40b?=@example.com",
            "=?utf-8?q?a=40b?= x@example.com",
            "=?utf-8?q?=FF?=@example.com",
            "a@=?utf-8?q?=FF?=",
            "a@=?utf-8?q?exa=E2=9C=93?=.com",
            "\"=?utf-8?q?quoted?=\" <a@example.com>",
            "\"x =?utf-8?q?one?= =?utf-8?q?two?= y\" <a@example.com>",
            "=?koi8-r?b?8NLJ18XU?= <a@example.com>",
        ] {
            cases.push(case("s", sender, &["b@example.com"]));
            cases.push(case("s", "a@example.com", &[sender]));
        }
        assert_parity(&cases);
    }

    #[test]
    fn groups_and_domain_literals_match_python_headers_and_envelopes() {
        let cases: Vec<Value> = [
            ["a@example.com", "undisclosed-recipients:;"],
            ["a@example.com", "Empty Team: (no recipients) ;"],
            [
                "a@example.com",
                "Team: Alpha <a@example.com>, b@[127.0.0.1];",
            ],
            ["a@example.com", "IPv6 User <v6@[IPv6:2001:db8::1]>"],
            [
                "a@example.com",
                "Literal <x@ (before) [ 127.0.0.1 ] (after)>",
            ],
            [
                "a@example.com",
                "G: a@example.com, b@[IPv6:::1];, c@[192.0.2.1]",
            ],
            [
                "Senders: first@[127.0.0.1], second@example.com;",
                "b@example.com",
            ],
            ["Nobody:;", "b@example.com"],
            ["a@example.com", "Empty:;, b@example.com"],
            ["a@example.com", "b@example.com, Empty:;"],
            ["A. B. <a@example.com>", "C. D. <b@example.com>"],
        ]
        .iter()
        .map(|[sender, recipient]| case("s", sender, &[recipient]))
        .collect();
        assert_parity(&cases);
    }

    /// `set_content(body)`'s transfer-encoding choice and payload (7bit,
    /// 8bit, quoted-printable with soft breaks and trailing whitespace,
    /// base64), for bodies around each heuristic boundary.
    #[test]
    fn body_transfer_encoding_matches_python_bytes() {
        let long_ascii = "x".repeat(79);
        let mut bodies: Vec<String> = vec![
            "short ascii\n".into(),
            "짧은 본문\n".into(),
            format!("{long_ascii}\n"),
            format!("{} \n{}\t\n", "y".repeat(76), "z".repeat(77)),
            format!("{}=abc\n{}=\n", "q".repeat(75), "r".repeat(76)),
            format!("{}\n한글 한 줄\n", "ascii ".repeat(40)),
            format!("{}끝\n", "ascii text line that is quite long indeed, ".repeat(3)),
            "no trailing newline".into(),
            "crlf line one\r\ncr line two\rlf line three\n".into(),
            ".leading dot line\n..two dots\n".into(),
            "안내 생성 시각: 2023-11-14T22:13:21Z\n\n1. 무슨 일이 있었나\n침해된 실행 환경(호스트)을 폐기하고 새로 구축하십시오. 기존 호출 주체의 토큰은 되살아나지 않습니다.\n".into(),
        ];
        let mut many = String::new();
        for index in 0..14 {
            many.push_str(&format!("line {index} {}\n", "w".repeat(70 + index)));
        }
        bodies.push(many);
        let mut mixed = String::new();
        for index in 0..12 {
            mixed.push_str(&format!("{} 한\n", "a".repeat(60 + index * 3)));
        }
        bodies.push(mixed);
        let cases: Vec<Value> = bodies
            .iter()
            .map(|body| json!(["s", "a@example.com", ["b@example.com"], body]))
            .collect();
        assert_parity(&cases);
        let recipients = ["b@example.com".to_owned()];
        let ctes: std::collections::BTreeSet<&str> = bodies
            .iter()
            .map(|body| {
                Message::new(&config("a@example.com", &recipients), "s", body)
                    .ok()
                    .expect("message builds")
                    .cte
            })
            .collect();
        assert_eq!(
            ctes.into_iter().collect::<Vec<_>>(),
            ["7bit", "8bit", "base64", "quoted-printable"]
        );
    }

    /// The shapes the earlier partial port wrote "as configured": routes,
    /// null and missing addresses, unterminated quoted strings, comments and
    /// domain literals, empty list elements, obsolete local parts and
    /// domains, invalid mailboxes and trailing garbage, and the shapes where
    /// CPython's own parser raises a built-in exception.
    #[test]
    fn former_unsupported_address_shapes_match_python() {
        let shapes = [
            "<@route.example:a@example.com>",
            "<@r1.example,@r2.example:a@example.com>",
            "Name <@route.example:a@example.com>",
            "<,@r.example:a@example.com>",
            "<@r.example a@example.com>",
            "<>",
            "Name <>",
            "admin",
            "first last",
            "\"unterminated <a@example.com>",
            "\"unterminated",
            "a@example.com,, b@example.com",
            ", a@example.com",
            "a@example.com,",
            " , ",
            "(comment only)",
            "(comment) , a@example.com",
            "first last@example.com",
            "first.last.@example.com",
            ".first@example.com",
            "first..last@example.com",
            "a\\b@example.com",
            "\\a@example.com",
            "\"quoted\".atom@example.com",
            "atom.\"quoted\"@example.com",
            "a (c) . b@example.com",
            "a@example .com",
            "a@example. com",
            "a@exa (c) .com",
            "a@ [127.0.0.1]",
            "a@[127.0.0.1",
            "a@[",
            "a@[ ",
            "a@[\\]]",
            "a@[a[b]",
            "Name <a@[127.0.0.1>",
            "a@b@c",
            "a@",
            "@example.com",
            "a@example.com junk",
            "Name <a@example.com> junk",
            "Name <a@example.com",
            "Name a@example.com>",
            "G: a@example.com; junk",
            "G: a@example.com junk;",
            "G: (c);",
            "G: , ,;",
            "G: a@example.com",
            " (c):;",
            "(c) G: a@example.com;",
            "G:: a@example.com;",
            "G: H: a@example.com;;",
            "<a@example.com> <b@example.com>",
            "a@example.com (unterminated comment",
            "a@example.com (nested (unterminated",
            "a@example.com \\(not a comment\\)",
            "(a\\)b) x@example.com",
            "x@example.com (a\\(b)",
            ". <a@example.com>",
            "Name. <a@example.com>",
            "\"a\" \"b\" <a@example.com>",
            "Name: <a@example.com>",
            "Na:me <a@example.com>",
            "Na;me <a@example.com>",
            "Na\"me <a@example.com>",
            "a@example.com;",
            "a;b@example.com",
            "<a@example.com>;",
            "\"\"@example.com",
            "\" \"@example.com",
            "\"a\\\"b\"@example.com",
            "x@[IPv6:::1] (c), \"q\"@[1.2.3.4]",
            "@",
            ";",
            ":",
            "<",
            ">",
            "]",
            "\\",
            "\"",
            "(",
            ")",
            "a\u{7f}b@example.com",
            "a\u{1}b@example.com",
            "Ünï <ünï@example.com>",
            "\"Ünï, Còde\" <a@example.com>",
            "사용자@도메인.example",
            "a@example.com\u{3000}b@example.com",
            "a@example.com\u{a0}junk",
        ];
        let mut cases = vec![];
        for shape in shapes {
            cases.push(case("s", shape, &["b@example.com"]));
            cases.push(case("s", "a@example.com", &[shape]));
            cases.push(case("s", "a@example.com", &[shape, "c@example.com"]));
            let long = format!(
                "{shape} {} {shape}",
                "padding-word-that-forces-a-fold ".repeat(3)
            );
            cases.push(case("s", "a@example.com", &[&long]));
        }
        let expected = assert_parity(&cases);
        let errors: std::collections::BTreeSet<&str> = expected
            .iter()
            .filter_map(|outcome| outcome["error"].as_str())
            .collect();
        for raised in ["AttributeError", "IndexError", "UnboundLocalError"] {
            assert!(
                errors.contains(raised),
                "{raised} not exercised: {errors:?}"
            );
        }
        let sent = expected.iter().filter(|o| o.get("bytes").is_some()).count();
        assert!(
            sent > cases.len() / 2,
            "only {sent} of {} cases flatten",
            cases.len()
        );
    }

    /// Deterministic pseudo-random subjects and address lists inside the
    /// RFC grammar (atoms, quoted strings with escapes and specials,
    /// obsolete dots, long words, ASCII and non-ASCII, internationalized
    /// addresses), compared with Python byte for byte.
    #[test]
    fn generated_header_shapes_match_python_bytes() {
        let mut seed: u64 = 0x5eed_2026_0926;
        let mut next = move |bound: usize| -> usize {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            ((seed >> 33) as usize) % bound
        };
        let words = [
            "a",
            "ZeroPW",
            "알림",
            "관리자",
            "보안-담당",
            "x-y.z",
            "[tag]",
            "(note)",
            "Ünï",
            "—",
            "averyveryveryverylongwordthatdoesnotfitonasinglefoldedheaderlineatallxxxxxxxx",
            "긴한국어단어긴한국어단어긴한국어단어긴한국어단어긴한국어단어",
            "a=b",
            "q?x",
            "_u_",
            "mix한글mix",
            "50%",
            "tab\tsep",
            "sp  ace",
        ];
        let atoms = [
            "Admin",
            "ZeroPW",
            "알림",
            "관리자",
            "Ünïcode",
            "Q.",
            "O'Neil",
            "x-y",
            "teamname",
            "averyveryveryverylongdisplaynameatomthatneedsfoldingbyitselfxxxxxxxxxxxxxx",
            "긴한국어이름긴한국어이름긴한국어이름긴한국어이름",
            "a+b",
            "Ops_Team",
            "anevenlongerdisplaynameatomthatexceedsthemaximumlinelengthoftheemailpolicyforsure",
            "Ops (team)",
            "관리자 (보안)",
        ];
        let quoted = [
            "\"Doe, John\"",
            "\"관리자 (보안)\"",
            "\"a;b:c\"",
            "\"esc \\\"q\\\" \\\\\"",
            "\"\"",
            "\"long quoted display name with, commas and (parens) that must fold\"",
            "\"한국어, 쉼표\"",
            "\"관리자, Admin; Ops\"",
            "\"a very long quoted display name, with specials; that cannot fit on one folded line at all\"",
            "\"긴 인용 이름, 특수문자; 포함 긴 인용 이름 긴 인용 이름 긴 인용 이름 긴 인용 이름 긴 인용 이름\"",
            "\"averyveryveryverylongquotedwordwithoutanyspacesthatcannotbefoldedanywhereatallxx\"",
        ];
        let locals = [
            "a",
            "admin",
            "first.last",
            "very.long.local.part.name.for.folding",
            "사용자",
            "x+tag",
            "anextremelylonglocalpartwithoutdotsthatexceedsthemaximumheaderlinelengthforsurexx",
            "\"quoted local\"",
        ];
        let domains = [
            "example.com",
            "sub.example-domain.org",
            "도메인.example",
            "an-extremely-long-domain-label-that-keeps-going-and-going.and-another-long-label.example",
        ];
        let mut cases = vec![];
        for _ in 0..400 {
            let subject: Vec<&str> = (0..1 + next(9)).map(|_| words[next(words.len())]).collect();
            let separators = [" ", " ", " ", "  ", "\t"];
            let mut text = String::new();
            for (index, word) in subject.iter().enumerate() {
                if index > 0 {
                    text.push_str(separators[next(separators.len())]);
                }
                text.push_str(word);
            }
            let mailbox = |next: &mut dyn FnMut(usize) -> usize| -> String {
                let local = locals[next(locals.len())];
                let domain = domains[next(domains.len())];
                let comments = [
                    "",
                    "",
                    "",
                    " (ops)",
                    " (보안팀)",
                    " (nested (inner) comment)",
                    " (escaped \\) paren, and; specials)",
                    " (a very long comment that goes on and on and on and on and on and on and on)",
                    "(tight)",
                ];
                let comment = comments[next(comments.len())];
                let address = match next(3) {
                    0 => format!("{local}{comment}@{domain}"),
                    _ => format!("{local}@{domain}{comment}"),
                };
                match next(4) {
                    0 => address,
                    1 => format!("{} <{address}>", quoted[next(quoted.len())]),
                    _ => {
                        let name: Vec<&str> =
                            (0..1 + next(4)).map(|_| atoms[next(atoms.len())]).collect();
                        format!("{} <{address}>", name.join(" "))
                    }
                }
            };
            let sender = mailbox(&mut next);
            let recipients: Vec<String> = (0..1 + next(5)).map(|_| mailbox(&mut next)).collect();
            cases.push(json!([text, sender, recipients, "짧은 본문\n"]));
        }
        let expected = assert_parity(&cases);
        // CPython 3.12.14 (the 3.12 release CI installs) refuses some of
        // these folds with `HeaderWriteError`; an older 3.12 writes them.
        let refused = expected
            .iter()
            .filter(|outcome| outcome["error"] == "HeaderWriteError")
            .count();
        assert!(
            refused > 0 && refused < cases.len(),
            "{refused} of {} cases refused: the oracle predates CPython 3.12.14's \
             verify_generated_headers in BytesGenerator",
            cases.len()
        );
    }

    /// Random strings over the characters every production branches on
    /// (specials, quotes, backslashes, parentheses, brackets, whitespace,
    /// encoded-word markers, non-ASCII), as subjects and as address lists.
    #[test]
    fn adversarial_header_fuzz_matches_python() {
        let mut seed: u64 = 0xadd0_2026_1003;
        let mut next = move |bound: usize| -> usize {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            ((seed >> 33) as usize) % bound
        };
        let pieces = [
            "a",
            "b",
            "xyz",
            "@",
            ".",
            ",",
            ";",
            ":",
            "<",
            ">",
            "(",
            ")",
            "[",
            "]",
            "\"",
            "\\",
            " ",
            "  ",
            "\t",
            "=?utf-8?q?",
            "?=",
            "=?",
            "=E2=9C=93",
            "=FF",
            "_",
            "한",
            "Ü",
            "example.com",
            "a@b.c",
            "\u{1}",
            "\u{7f}",
            "x".repeat(40).leak(),
            "가나다라마바사아자차카타파하",
            "IPv6:",
            "1.2.3.4",
            "=?utf-8?b?7ZWc6riA?=",
        ];
        let mut cases = vec![];
        for _ in 0..1500 {
            let mut value = String::new();
            for _ in 0..1 + next(14) {
                value.push_str(pieces[next(pieces.len())]);
            }
            match next(3) {
                0 => cases.push(case(&value, "a@example.com", &["b@example.com"])),
                1 => cases.push(case("s", &value, &["b@example.com"])),
                _ => cases.push(case("s", "a@example.com", &[&value, "c@d.example"])),
            }
        }
        let expected = assert_parity(&cases);
        let sent = expected.iter().filter(|o| o.get("bytes").is_some()).count();
        assert!(
            sent > cases.len() / 4,
            "only {sent} of {} cases flatten",
            cases.len()
        );
    }

    /// Comment placements around the local part, `@` and domain, with
    /// nested and escaped comments: the envelope (`getaddresses` then
    /// `quoteaddr`) and the folded headers.
    #[test]
    fn comment_envelopes_match_python() {
        let mut cases = vec![];
        for base in [
            "local+tag@domain.example",
            "loc.al@domain.example",
            "\"lo cal\"@domain.example",
            "Display <loc.al@domain.example>",
        ] {
            let chars: Vec<char> = base.chars().collect();
            for pos in 0..=chars.len() {
                for comment in ["(x)", "(nested(inner))", "(escaped\\)paren)"] {
                    let address: String = chars[..pos]
                        .iter()
                        .chain(comment.chars().collect::<Vec<_>>().iter())
                        .chain(chars[pos..].iter())
                        .collect();
                    cases.push(case("s", &address, &["recipient@example.com"]));
                }
            }
        }
        for before in ["@", "@exa", "@exa.", "@exa-", "@example.com"] {
            for after in ["example.com", "mple.com", "com", ".com", ""] {
                let address = format!("sender{before}(nested(inner)){after}");
                cases.push(case("s", &address, &["recipient@example.com"]));
            }
        }
        for address in [
            "sender(Internal)@example.com",
            "sender@(Internal)example.com",
            "(outer(inner)) sender@(one(two))example.com (tail)",
            "Display (a(b)) <sender(x)@(y)example.com>",
            "sender (x) @example.com",
            "sender@ (x) example.com",
            "sender (x) .foo@example.com",
            "sender@exa(comment)mple.com",
            "sen(comment)der@example.com",
            "sender.foo(comment)bar@example.com",
            "sender@(nested(inner)).com",
            "sender@exa.(nested(inner))",
            "\"loc(al)\"@(ignored)example.com",
            "\"lo\\\"c(a)\"@(ignored)example.com",
            "\"Display <literal>\" <\"lo(c)al\"@(x)example.com>",
            "sender(comment(with\\)escape))@example.com",
        ] {
            cases.push(case("s", address, &["recipient@example.com"]));
            cases.push(case("s", "a@example.com", &[address]));
        }
        assert_parity(&cases);
    }
}

#[cfg(test)]
mod hostname_tests {
    use serde_json::json;

    use crate::sys_hostent::tests::{assert_parity, cases, rust_error, rust_outcomes};

    /// `smtplib.SMTP().local_hostname` (`socket.getfqdn()` or the `[ip]`
    /// literal) is what EHLO/HELO send. Both implementations use the host
    /// platform's resolver through the same `gethostbyaddr` call, including
    /// its alias list.
    #[test]
    fn local_hostname_matches_smtplib() {
        let out = crate::oracle::python("import smtplib; print(smtplib.SMTP().local_hostname)");
        let Ok(rust) = super::local_hostname() else {
            panic!("local_hostname raised where smtplib returned {out:?}");
        };
        assert_eq!(rust, out.trim());
    }

    /// `socket.getfqdn(name)` over the `gethostbyaddr` cases (empty and
    /// whitespace names fall back to this host's name).
    #[test]
    fn getfqdn_matches_socket_getfqdn() {
        let cases = cases();
        let rust = rust_outcomes(&cases, |case| match super::getfqdn(case) {
            Ok(name) => json!({"ok": name}),
            Err(error) => rust_error(&error),
        });
        assert_parity("getfqdn", &cases, &rust);
    }

    /// `socket.gethostname()`.
    #[test]
    fn gethostname_matches_socket_gethostname() {
        let out = crate::oracle::python("import socket; print(socket.gethostname())");
        assert_eq!(
            super::gethostname().ok().as_deref(),
            Some(out.trim_end_matches('\n'))
        );
    }
}
