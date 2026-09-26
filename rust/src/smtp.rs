//! SMTP transport for incident notifications: the `notify._send` path through
//! `smtplib.SMTP`/`SMTP_SSL` and `email.message.EmailMessage`, with
//! byte-oriented replies and zeroizing credential buffers.
//!
//! The session mirrors `smtplib`'s own command sequence and failure mapping
//! (`ehlo`, `mail FROM:`, `rcpt TO:`, `data`, `rset`, the context manager's
//! `QUIT` after any failure inside the `with` block, `_rset` after a refusal,
//! the AUTH challenge counter), and the message is flattened like
//! `BytesGenerator` with the default `EmailPolicy` (RFC 2047 encoded words
//! and folding for the header shapes ZeroPW produces; see `DEVIATIONS.md`
//! for the residual shapes).
use std::collections::{HashSet, VecDeque};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use base64::Engine;
use hmac::Mac;
use md5::Md5;

use crate::errors::{Error, ErrorClass};
use crate::notify::NotifyConfig;
use crate::secret::SecretBytes;

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
// Mirrors CPython's errno table; delegate to `crate::pystr::os_error_class`
// once that canonical helper is available on this branch.
fn os_error_class(error: &io::Error) -> &'static str {
    let Some(errno) = error.raw_os_error() else {
        return match error.kind() {
            io::ErrorKind::TimedOut => "TimeoutError",
            _ => "OSError",
        };
    };
    match errno {
        libc::EAGAIN | libc::EALREADY | libc::EINPROGRESS => "BlockingIOError",
        #[allow(unreachable_patterns)]
        libc::EWOULDBLOCK => "BlockingIOError",
        libc::ECHILD => "ChildProcessError",
        libc::EPIPE | libc::ESHUTDOWN => "BrokenPipeError",
        libc::ECONNABORTED => "ConnectionAbortedError",
        libc::ECONNREFUSED => "ConnectionRefusedError",
        libc::ECONNRESET => "ConnectionResetError",
        libc::EEXIST => "FileExistsError",
        libc::ENOENT => "FileNotFoundError",
        libc::EISDIR => "IsADirectoryError",
        libc::ENOTDIR => "NotADirectoryError",
        libc::EINTR => "InterruptedError",
        libc::EACCES | libc::EPERM => "PermissionError",
        libc::ESRCH => "ProcessLookupError",
        libc::ETIMEDOUT => "TimeoutError",
        _ => "OSError",
    }
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
    // EmailMessage(): `message[...] = value` (header_store_parse) first.
    for value in [
        subject,
        config.sender.as_str(),
        &config.recipients.join(", "),
    ] {
        if python_splitlines_count(value) > 1 {
            return Err(escaped_value("ValueError"));
        }
    }
    let message = Message::new(config, subject, body);
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
    client.send_message(config, message)
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
        let addresses: Vec<_> = (config.host.as_str(), config.port)
            .to_socket_addrs()
            .map_err(|e| caught(resolve_error_class(&e)))?
            .collect();
        if addresses.is_empty() {
            return Err(caught("OSError"));
        }
        // `sock.settimeout(timeout)`: seconds to whole nanoseconds, rounded
        // up; outside `_PyTime_t` it raises OverflowError.
        let nanos = (config.timeout_seconds * 1e9).ceil();
        if !(nanos < 9_223_372_036_854_775_808.0) {
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
        client.local_hostname = local_hostname();
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
    fn send_message(&mut self, config: &NotifyConfig, message: &Message) -> Result<(), SendError> {
        self.ehlo_or_helo_if_needed()?;
        let from = mailbox(&config.sender);
        let to: Vec<String> = config.recipients.iter().map(|r| mailbox(r)).collect();
        let international = !from.is_ascii() || to.iter().any(|r| !r.is_ascii());
        if international && !self.has_extn("smtputf8") {
            return Err(caught("SMTPNotSupportedError"));
        }
        let flat = message.flatten(international);
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
            let (code, _) = self.docmd("rcpt", &format!("TO:<{each}>"))?;
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
        self.docmd("mail", &format!("FROM:<{sender}>{optionlist}"))
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

/// `self.file.readline(limit)`: up to `limit` bytes, through `\n`; a short
/// final line at end of file is returned as is.
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
/// (`127.0.0.1` when that lookup fails).
fn local_hostname() -> String {
    let hostname = gethostname();
    let fqdn = getfqdn(&hostname);
    if fqdn.contains('.') {
        return fqdn;
    }
    let address = (hostname.as_str(), 0)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addresses| addresses.find(std::net::SocketAddr::is_ipv4))
        .map_or_else(|| "127.0.0.1".to_owned(), |a| a.ip().to_string());
    format!("[{address}]")
}

/// `socket.gethostname()`: the kernel host name (Linux `uname().nodename`).
fn gethostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|name| name.trim_end_matches('\n').to_owned())
        .unwrap_or_else(|_| "localhost".to_owned())
}

/// `socket.getfqdn(hostname)`: `gethostbyaddr` of the host name's first
/// address, answered from the hosts database (NSS `files`); the first name
/// containing a dot among the canonical name and its aliases.
fn getfqdn(hostname: &str) -> String {
    let Some(address) = (hostname, 0)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addresses| addresses.next())
    else {
        return hostname.to_owned();
    };
    let Some((canonical, aliases)) = hosts_entry(address.ip()) else {
        return hostname.to_owned();
    };
    std::iter::once(&canonical)
        .chain(aliases.iter())
        .find(|name| name.contains('.'))
        .unwrap_or(&canonical)
        .clone()
}

fn hosts_entry(address: IpAddr) -> Option<(String, Vec<String>)> {
    let hosts = fs::read_to_string("/etc/hosts").ok()?;
    hosts.lines().find_map(|line| {
        let line = line.split('#').next().unwrap_or_default();
        let mut fields = line.split_ascii_whitespace();
        let entry: IpAddr = fields.next()?.parse().ok()?;
        if entry != address {
            return None;
        }
        let canonical = fields.next()?.to_owned();
        Some((canonical, fields.map(str::to_owned).collect()))
    })
}

/// `EmailMessage` as built by `notify._send`: Subject, From, To, then
/// `set_content(body)` (Content-Type, Content-Transfer-Encoding,
/// MIME-Version).
struct Message {
    subject: String,
    from: String,
    to: String,
    cte: &'static str,
    /// The payload, `\n`-terminated lines.
    payload: Vec<u8>,
}

impl Message {
    fn new(config: &NotifyConfig, subject: &str, body: &str) -> Self {
        let (cte, payload) = encode_text(body);
        Message {
            subject: subject.to_owned(),
            from: config.sender.clone(),
            to: config.recipients.join(", "),
            cte,
            payload,
        }
    }

    /// `BytesGenerator(policy).flatten(msg, linesep="\r\n")`, with
    /// `policy.utf8` for an internationalized envelope.
    fn flatten(&self, utf8: bool) -> Vec<u8> {
        let mut out = String::new();
        let subject = get_unstructured(&self.subject, false)
            .and_then(|tree| fold_header("Subject", tree, utf8));
        out.push_str(&subject.unwrap_or_else(|| format!("Subject: {}{CRLF}", self.subject)));
        for (name, value) in [("From", &self.from), ("To", &self.to)] {
            let folded = get_address_list(value)
                .and_then(|tree| fold_header(name, tree, utf8))
                .filter(|folded| utf8 || folded.is_ascii());
            out.push_str(&folded.unwrap_or_else(|| format!("{name}: {value}{CRLF}")));
        }
        out.push_str("Content-Type: text/plain; charset=\"utf-8\"\r\n");
        out.push_str(&format!("Content-Transfer-Encoding: {}{CRLF}", self.cte));
        out.push_str("MIME-Version: 1.0\r\n\r\n");
        let mut bytes = out.into_bytes();
        // `_write_lines`: every `\n`-terminated payload line ends in CRLF.
        for line in self.payload.split_inclusive(|b| *b == b'\n') {
            bytes.extend_from_slice(line.strip_suffix(b"\n").unwrap_or(line));
            bytes.extend_from_slice(CRLF.as_bytes());
        }
        bytes
    }
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

// ------------------------------------------------------------------------
// Header folding: `email._header_value_parser` for the header shapes this
// module writes (an unstructured Subject; From/To address lists of
// addr-specs and `display-name <addr-spec>` mailboxes, with atoms, quoted
// strings and obsolete dots in display names). `None` from a parser means
// "outside that subset": the caller then writes the configured value
// unfolded (`DEVIATIONS.md`).

const WSP: [char; 2] = [' ', '\t'];
const SPECIALS: &str = "()<>@,:;.\\\"[]";

fn is_wsp(c: char) -> bool {
    WSP.contains(&c)
}
fn is_cfws_leader(c: char) -> bool {
    is_wsp(c) || c == '('
}
fn is_special(c: char) -> bool {
    SPECIALS.contains(c)
}
fn is_atom_end(c: char) -> bool {
    is_special(c) || is_wsp(c)
}
/// `PHRASE_ENDS = SPECIALS - set('."(')`.
fn is_phrase_end(c: char) -> bool {
    is_special(c) && !matches!(c, '.' | '"' | '(')
}
fn first(value: &str) -> Option<char> {
    value.chars().next()
}
fn clen(value: &str) -> usize {
    value.chars().count()
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Space {
    Value,
    Fws,
    /// `EWWhiteSpaceTerminal`: whitespace between two encoded words.
    EwFws,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Header,
    HeaderLabel,
    Cfws,
    Unstructured,
    DisplayName,
    Atom,
    QuotedString,
    BareQuotedString,
    DotAtom,
    DotAtomText,
    LocalPart,
    Domain,
    AddrSpec,
    AngleAddr,
    NameAddr,
    Mailbox,
    Address,
    AddressList,
}

#[derive(Clone, Debug)]
enum Tok {
    /// A `Terminal`: text, `token_type`, whitespace class and whether it is
    /// the `ListSeparator` (`as_ew_allowed = syntactic_break = False`).
    Term(String, &'static str, Space, bool),
    List(Kind, Vec<Tok>),
}

impl Tok {
    fn value(text: impl Into<String>, token_type: &'static str) -> Tok {
        Tok::Term(text.into(), token_type, Space::Value, false)
    }
    fn fws(text: impl Into<String>) -> Tok {
        Tok::Term(text.into(), "fws", Space::Fws, false)
    }
    fn text(&self) -> String {
        match self {
            Tok::Term(_, _, Space::EwFws, _) => String::new(),
            Tok::Term(text, ..) => text.clone(),
            Tok::List(Kind::BareQuotedString, parts) => {
                quote_string(&parts.iter().map(Tok::text).collect::<String>())
            }
            Tok::List(_, parts) => parts.iter().map(Tok::text).collect(),
        }
    }
    fn token_type(&self) -> &'static str {
        match self {
            Tok::Term(_, token_type, ..) => token_type,
            Tok::List(Kind::BareQuotedString, _) => "bare-quoted-string",
            Tok::List(..) => "",
        }
    }
    fn as_ew_allowed(&self) -> bool {
        match self {
            Tok::Term(.., separator) => !separator,
            Tok::List(Kind::HeaderLabel | Kind::Domain | Kind::AddrSpec | Kind::LocalPart, _) => {
                false
            }
            Tok::List(Kind::DotAtomText, _) => true,
            Tok::List(_, parts) => parts.iter().all(Tok::as_ew_allowed),
        }
    }
    fn syntactic_break(&self) -> bool {
        !matches!(self, Tok::Term(.., true))
    }
    fn ew_combine_allowed(&self) -> bool {
        !matches!(self, Tok::List(Kind::DisplayName, _))
    }
    fn startswith_fws(&self) -> bool {
        match self {
            Tok::Term(_, _, space, _) => *space != Space::Value,
            Tok::List(_, parts) => parts.first().is_some_and(Tok::startswith_fws),
        }
    }
    fn prepend(&mut self, leader: Tok) {
        if let Tok::List(_, parts) = self {
            parts.insert(0, leader);
        }
    }
}

/// `make_quoted_pairs`/`quote_string`.
fn quote_string(value: &str) -> String {
    format!("\"{}\"", make_quoted_pairs(value))
}
fn make_quoted_pairs(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// A parse failure: `Header` is Python's `HeaderParseError` (the caller may
/// try another production), `Unsupported` leaves the subset.
#[derive(Debug)]
enum PErr {
    Header,
    Unsupported,
}
type Parsed<'a> = Result<(Tok, &'a str), PErr>;

/// `get_fws`: the leading run `str.lstrip()` removes.
fn get_fws(value: &str) -> (Tok, &str) {
    let rest = value.trim_start_matches(crate::pystr::is_space);
    (Tok::fws(&value[..value.len() - rest.len()]), rest)
}

/// `get_cfws` without comments.
fn get_cfws(mut value: &str) -> Parsed<'_> {
    let mut parts = Vec::new();
    while let Some(c) = first(value).filter(|c| is_cfws_leader(*c)) {
        if c == '(' {
            return Err(PErr::Unsupported);
        }
        let (token, rest) = get_fws(value);
        parts.push(token);
        value = rest;
    }
    Ok((Tok::List(Kind::Cfws, parts), value))
}

/// `get_atext`.
fn get_atext(value: &str) -> Parsed<'_> {
    let end = value
        .char_indices()
        .find(|(_, c)| is_atom_end(*c))
        .map_or(value.len(), |(i, _)| i);
    if end == 0 {
        return Err(PErr::Header);
    }
    Ok((Tok::value(&value[..end], "atext"), &value[end..]))
}

/// `get_atom` (no encoded words).
fn get_atom(mut value: &str) -> Parsed<'_> {
    let mut parts = Vec::new();
    if first(value).is_some_and(is_cfws_leader) {
        let (token, rest) = get_cfws(value)?;
        parts.push(token);
        value = rest;
    }
    if first(value).is_some_and(is_atom_end) {
        return Err(PErr::Header);
    }
    if value.starts_with("=?") {
        return Err(PErr::Unsupported);
    }
    let (token, rest) = get_atext(value)?;
    parts.push(token);
    value = rest;
    if first(value).is_some_and(is_cfws_leader) {
        let (token, rest) = get_cfws(value)?;
        parts.push(token);
        value = rest;
    }
    Ok((Tok::List(Kind::Atom, parts), value))
}

/// `get_dot_atom_text`.
fn get_dot_atom_text(mut value: &str) -> Parsed<'_> {
    if first(value).is_none_or(is_atom_end) {
        return Err(PErr::Header);
    }
    let mut parts = Vec::new();
    let mut last_dot = false;
    while first(value).is_some_and(|c| !is_atom_end(c)) {
        let (token, rest) = get_atext(value)?;
        parts.push(token);
        value = rest;
        last_dot = false;
        if let Some(rest) = value.strip_prefix('.') {
            parts.push(Tok::value(".", "dot"));
            value = rest;
            last_dot = true;
        }
    }
    if last_dot {
        return Err(PErr::Header);
    }
    Ok((Tok::List(Kind::DotAtomText, parts), value))
}

/// `get_dot_atom` (no encoded words).
fn get_dot_atom(mut value: &str) -> Parsed<'_> {
    let mut parts = Vec::new();
    if first(value).is_some_and(is_cfws_leader) {
        let (token, rest) = get_cfws(value)?;
        parts.push(token);
        value = rest;
    }
    if value.starts_with("=?") {
        return Err(PErr::Unsupported);
    }
    let (token, rest) = get_dot_atom_text(value)?;
    parts.push(token);
    value = rest;
    if first(value).is_some_and(is_cfws_leader) {
        let (token, rest) = get_cfws(value)?;
        parts.push(token);
        value = rest;
    }
    Ok((Tok::List(Kind::DotAtom, parts), value))
}

/// `_get_ptext_to_endchars(value, '"')` as used by `get_qcontent`.
fn get_qcontent(value: &str) -> (Tok, &str) {
    let fragment_end = value.find(WSP).unwrap_or(value.len());
    let fragment = &value[..fragment_end];
    let mut text = String::new();
    let mut escape = false;
    let mut stop = fragment.len();
    for (pos, c) in fragment.char_indices() {
        if c == '\\' {
            if escape {
                escape = false;
            } else {
                escape = true;
                continue;
            }
        }
        if escape {
            escape = false;
        } else if c == '"' {
            stop = pos;
            break;
        }
        text.push(c);
    }
    (Tok::value(text, "ptext"), &value[stop..])
}

/// `get_bare_quoted_string` (no encoded words, closed).
fn get_bare_quoted_string(value: &str) -> Parsed<'_> {
    let Some(mut value) = value.strip_prefix('"') else {
        return Err(PErr::Header);
    };
    let mut parts = Vec::new();
    if value.starts_with('"') {
        let (token, rest) = get_qcontent(value);
        parts.push(token);
        value = rest;
    }
    while let Some(c) = first(value).filter(|c| *c != '"') {
        let (token, rest) = if is_wsp(c) {
            get_fws(value)
        } else if value.starts_with("=?") {
            return Err(PErr::Unsupported);
        } else {
            get_qcontent(value)
        };
        parts.push(token);
        value = rest;
    }
    // Unterminated: an InvalidHeaderDefect.
    let Some(rest) = value.strip_prefix('"') else {
        return Err(PErr::Unsupported);
    };
    Ok((Tok::List(Kind::BareQuotedString, parts), rest))
}

/// `get_quoted_string`.
fn get_quoted_string(mut value: &str) -> Parsed<'_> {
    let mut parts = Vec::new();
    if first(value).is_some_and(is_cfws_leader) {
        let (token, rest) = get_cfws(value)?;
        parts.push(token);
        value = rest;
    }
    let (token, rest) = get_bare_quoted_string(value)?;
    parts.push(token);
    value = rest;
    if first(value).is_some_and(is_cfws_leader) {
        let (token, rest) = get_cfws(value)?;
        parts.push(token);
        value = rest;
    }
    Ok((Tok::List(Kind::QuotedString, parts), value))
}

/// `get_word`.
fn get_word(mut value: &str) -> Parsed<'_> {
    let mut leader = None;
    if first(value).is_some_and(is_cfws_leader) {
        let (token, rest) = get_cfws(value)?;
        leader = Some(token);
        value = rest;
    }
    let (mut token, rest) = match first(value) {
        None => return Err(PErr::Header),
        Some('"') => get_quoted_string(value)?,
        Some(c) if is_special(c) => return Err(PErr::Header),
        Some(_) => get_atom(value)?,
    };
    if let Some(leader) = leader {
        token.prepend(leader);
    }
    Ok((token, rest))
}

/// `get_phrase`; the flag reports an `InvalidHeaderDefect` (no leading
/// word).
fn get_phrase(mut value: &str) -> Result<(Vec<Tok>, bool, &str), PErr> {
    let mut parts = Vec::new();
    let mut invalid = false;
    match get_word(value) {
        Ok((token, rest)) => {
            parts.push(token);
            value = rest;
        }
        Err(PErr::Header) => invalid = true,
        Err(PErr::Unsupported) => return Err(PErr::Unsupported),
    }
    while let Some(c) = first(value).filter(|c| !is_phrase_end(*c)) {
        if c == '.' {
            parts.push(Tok::value(".", "dot"));
            value = &value[1..];
            continue;
        }
        match get_word(value) {
            Ok((token, rest)) => {
                parts.push(token);
                value = rest;
            }
            Err(PErr::Header) if is_cfws_leader(c) => {
                let (token, rest) = get_cfws(value)?;
                parts.push(token);
                value = rest;
            }
            Err(error) => return Err(error),
        }
    }
    Ok((parts, invalid, value))
}

/// `get_local_part` (dot-atom or quoted string).
fn get_local_part(mut value: &str) -> Parsed<'_> {
    let mut leader = None;
    if first(value).is_some_and(is_cfws_leader) {
        let (token, rest) = get_cfws(value)?;
        leader = Some(token);
        value = rest;
    }
    if value.is_empty() {
        return Err(PErr::Header);
    }
    let (mut token, rest) = match get_dot_atom(value) {
        Ok(parsed) => parsed,
        Err(PErr::Header) => match get_word(value) {
            Ok(parsed) => parsed,
            Err(PErr::Header) if first(value).is_some_and(|c| c != '\\' && is_phrase_end(c)) => {
                return Err(PErr::Header);
            }
            // An empty token followed by an obs-local-part.
            Err(_) => return Err(PErr::Unsupported),
        },
        Err(PErr::Unsupported) => return Err(PErr::Unsupported),
    };
    if let Some(leader) = leader {
        token.prepend(leader);
    }
    if first(rest).is_some_and(|c| c == '\\' || !is_phrase_end(c)) {
        return Err(PErr::Unsupported); // obs-local-part
    }
    Ok((Tok::List(Kind::LocalPart, vec![token]), rest))
}

/// `get_domain` (dot-atom or atom).
fn get_domain(mut value: &str) -> Parsed<'_> {
    let mut leader = None;
    if first(value).is_some_and(is_cfws_leader) {
        let (token, rest) = get_cfws(value)?;
        leader = Some(token);
        value = rest;
    }
    match first(value) {
        None => return Err(PErr::Header),
        Some('[') => return Err(PErr::Unsupported), // domain literal
        Some(_) => {}
    }
    let (mut token, rest) = match get_dot_atom(value) {
        Ok(parsed) => parsed,
        Err(PErr::Header) => get_atom(value)?,
        Err(PErr::Unsupported) => return Err(PErr::Unsupported),
    };
    if rest.starts_with('@') {
        return Err(PErr::Header);
    }
    if let Some(leader) = leader {
        token.prepend(leader);
    }
    if rest.starts_with('.') {
        return Err(PErr::Unsupported); // obs-domain
    }
    Ok((Tok::List(Kind::Domain, vec![token]), rest))
}

/// `get_addr_spec` (with a domain).
fn get_addr_spec(value: &str) -> Parsed<'_> {
    let (local, rest) = get_local_part(value)?;
    let Some(rest) = rest.strip_prefix('@') else {
        return Err(PErr::Unsupported); // InvalidHeaderDefect: no domain
    };
    let (domain, rest) = get_domain(rest)?;
    let parts = vec![local, Tok::value("@", "address-at-symbol"), domain];
    Ok((Tok::List(Kind::AddrSpec, parts), rest))
}

/// `get_angle_addr` (no obs-route, closed, not empty).
fn get_angle_addr(mut value: &str) -> Parsed<'_> {
    let mut parts = Vec::new();
    if first(value).is_some_and(is_cfws_leader) {
        let (token, rest) = get_cfws(value)?;
        parts.push(token);
        value = rest;
    }
    let Some(rest) = value.strip_prefix('<') else {
        return Err(PErr::Header);
    };
    parts.push(Tok::value("<", "angle-addr-start"));
    if rest.starts_with('>') {
        return Err(PErr::Unsupported);
    }
    let (token, rest) = match get_addr_spec(rest) {
        Ok(parsed) => parsed,
        Err(_) => return Err(PErr::Unsupported),
    };
    parts.push(token);
    let Some(mut value) = rest.strip_prefix('>') else {
        return Err(PErr::Unsupported);
    };
    parts.push(Tok::value(">", "angle-addr-end"));
    if first(value).is_some_and(is_cfws_leader) {
        let (token, rest) = get_cfws(value)?;
        parts.push(token);
        value = rest;
    }
    Ok((Tok::List(Kind::AngleAddr, parts), value))
}

/// `get_display_name`.
fn get_display_name(value: &str) -> Result<(Tok, bool, &str), PErr> {
    let (parts, invalid, rest) = get_phrase(value)?;
    Ok((Tok::List(Kind::DisplayName, parts), invalid, rest))
}

/// `get_name_addr`.
fn get_name_addr(mut value: &str) -> Parsed<'_> {
    if value.is_empty() {
        return Err(PErr::Header);
    }
    let mut leader = None;
    if first(value).is_some_and(is_cfws_leader) {
        let (token, rest) = get_cfws(value)?;
        leader = Some(token);
        value = rest;
        if value.is_empty() {
            return Err(PErr::Header);
        }
    }
    let mut parts = Vec::new();
    if !value.starts_with('<') {
        if first(value).is_some_and(is_phrase_end) {
            return Err(PErr::Header);
        }
        let (mut token, invalid, rest) = get_display_name(value)?;
        if rest.is_empty() {
            return Err(PErr::Header);
        }
        if invalid {
            return Err(PErr::Unsupported);
        }
        if let Some(leader) = leader.take() {
            match &mut token {
                Tok::List(_, display) if matches!(display.first(), Some(Tok::List(..))) => {
                    if let Some(first) = display.first_mut() {
                        first.prepend(leader);
                    }
                }
                _ => token.prepend(leader),
            }
        }
        parts.push(token);
        value = rest;
    }
    let (mut token, rest) = get_angle_addr(value)?;
    if let Some(leader) = leader {
        token.prepend(leader);
    }
    parts.push(token);
    Ok((Tok::List(Kind::NameAddr, parts), rest))
}

/// `get_mailbox`.
fn get_mailbox(value: &str) -> Parsed<'_> {
    let (token, rest) = match get_name_addr(value) {
        Ok(parsed) => parsed,
        Err(PErr::Header) => get_addr_spec(value)?,
        Err(PErr::Unsupported) => return Err(PErr::Unsupported),
    };
    Ok((Tok::List(Kind::Mailbox, vec![token]), rest))
}

/// `get_address` (a group is outside the subset).
fn get_address(value: &str) -> Parsed<'_> {
    match get_display_name(value) {
        Ok((_, _, rest)) if rest.starts_with(':') => return Err(PErr::Unsupported),
        Err(PErr::Unsupported) => return Err(PErr::Unsupported),
        _ => {}
    }
    let (mailbox, rest) = get_mailbox(value)?;
    Ok((Tok::List(Kind::Address, vec![mailbox]), rest))
}

/// `get_address_list` without its error-recovery productions.
fn get_address_list(mut value: &str) -> Option<Tok> {
    if value.contains("=?") {
        return None;
    }
    let mut parts = Vec::new();
    while !value.is_empty() {
        let (address, rest) = get_address(value).ok()?;
        parts.push(address);
        value = rest;
        if !value.is_empty() {
            value = value.strip_prefix(',')?;
            parts.push(Tok::Term(",".into(), "list-separator", Space::Value, true));
        }
    }
    Some(Tok::List(Kind::AddressList, parts))
}

/// `get_unstructured`; with `decode_ew`, encoded words are decoded (only
/// used on this module's own output while combining encoded words).
fn get_unstructured(mut value: &str, decode_ew: bool) -> Option<Tok> {
    let mut parts: Vec<Tok> = Vec::new();
    let mut kinds: Vec<bool> = Vec::new(); // true: encoded word
    while let Some(c) = first(value) {
        if is_wsp(c) {
            let (token, rest) = get_fws(value);
            parts.push(token);
            kinds.push(false);
            value = rest;
            continue;
        }
        let mut valid_ew = true;
        if decode_ew && value.starts_with("=?") {
            match get_encoded_word(value) {
                EwParse::Ok(text, rest) => {
                    let have_ws = parts.last().is_none_or(|last| last.token_type() == "fws");
                    let len = parts.len();
                    if have_ws && len > 1 && kinds[len - 2] {
                        if let Some(Tok::Term(_, _, space, _)) = parts.last_mut() {
                            *space = Space::EwFws;
                        }
                    }
                    parts.push(Tok::value(text, "encoded-word"));
                    kinds.push(true);
                    value = rest;
                    continue;
                }
                EwParse::Invalid => valid_ew = false,
                EwParse::NotEw => {}
                EwParse::Unsupported => return None,
            }
        }
        let split = value.find(WSP).unwrap_or(value.len());
        let (mut token, mut rest) = value.split_at(split);
        if valid_ew && decode_ew && rfc2047_matcher().is_match(token) {
            let index = value.find("=?").unwrap_or(0);
            (token, rest) = value.split_at(index);
        }
        if token.is_empty() {
            return None;
        }
        parts.push(Tok::value(token, "utext"));
        kinds.push(false);
        value = rest;
    }
    Some(Tok::List(Kind::Unstructured, parts))
}

fn rfc2047_matcher() -> &'static regex::Regex {
    static MATCHER: OnceLock<regex::Regex> = OnceLock::new();
    MATCHER.get_or_init(|| {
        regex::Regex::new(r"=\?[^?]*\?[qQbB]\?.*?\?=").expect("static pattern compiles")
    })
}

enum EwParse<'a> {
    Ok(String, &'a str),
    /// `_InvalidEwError`.
    Invalid,
    /// `HeaderParseError`: not an encoded word.
    NotEw,
    /// A charset or payload this module never writes.
    Unsupported,
}

/// `get_encoded_word` + `_encoded_words.decode` for UTF-8 words.
fn get_encoded_word(value: &str) -> EwParse<'_> {
    let Some(body) = value.strip_prefix("=?") else {
        return EwParse::NotEw;
    };
    let Some((head, mut remainder)) = body.split_once("?=") else {
        return EwParse::NotEw;
    };
    let mut token = head.to_owned();
    let mut chars = remainder.chars();
    if let (Some(a), Some(b)) = (chars.next(), chars.next())
        && a.is_ascii_hexdigit()
        && b.is_ascii_hexdigit()
        && token.matches('?').count() < 2
    {
        let (rest, after) = remainder.split_once("?=").unwrap_or((remainder, ""));
        token = format!("{token}?={rest}");
        remainder = after;
    }
    let fields: Vec<&str> = token.split('?').collect();
    let [charset, cte, text] = fields[..] else {
        return EwParse::Invalid;
    };
    if !charset.eq_ignore_ascii_case("utf-8") {
        return EwParse::Unsupported;
    }
    let bytes = match cte.to_ascii_lowercase().as_str() {
        "q" => {
            let raw = text.replace('_', " ").into_bytes();
            let mut out = Vec::with_capacity(raw.len());
            let mut index = 0;
            while let Some(&byte) = raw.get(index) {
                let pair = raw
                    .get(index + 1..index + 3)
                    .filter(|p| p.iter().all(u8::is_ascii_hexdigit));
                match (byte, pair) {
                    (b'=', Some(pair)) => {
                        let hex = std::str::from_utf8(pair).unwrap_or_default();
                        out.push(u8::from_str_radix(hex, 16).unwrap_or_default());
                        index += 3;
                    }
                    _ => {
                        out.push(byte);
                        index += 1;
                    }
                }
            }
            out
        }
        "b" => match crate::pybase64::b64decode_bytes(text.as_bytes()) {
            Ok(bytes) => bytes,
            Err(_) => return EwParse::Unsupported,
        },
        _ => return EwParse::Invalid,
    };
    match String::from_utf8(bytes) {
        Ok(decoded) => EwParse::Ok(decoded, remainder),
        Err(_) => EwParse::Unsupported,
    }
}

/// `BaseHeader.fold`: `Header([HeaderLabel, CFWSList(' '), parse_tree])`
/// through `_refold_parse_tree`.
fn fold_header(name: &str, tree: Tok, utf8: bool) -> Option<String> {
    let label = Tok::List(
        Kind::HeaderLabel,
        vec![
            Tok::value(name, "header-name"),
            Tok::value(":", "header-sep"),
        ],
    );
    let mut parts = vec![label];
    if matches!(&tree, Tok::List(_, children) if !children.is_empty()) {
        parts.push(Tok::List(Kind::Cfws, vec![Tok::fws(" ")]));
    }
    parts.push(tree);
    refold(Tok::List(Kind::Header, parts), utf8)
}

/// `_steal_trailing_WSP_if_exists`.
fn steal_trailing_wsp(lines: &mut [String]) -> String {
    match lines.last_mut() {
        Some(last) if last.ends_with(WSP) => last.pop().map(String::from).unwrap_or_default(),
        _ => String::new(),
    }
}

enum Item {
    Tok(Tok),
    /// `end_ew_not_allowed`.
    EndBlocked,
}

/// `_refold_parse_tree(parse_tree, policy=default.clone(linesep="\r\n"))`.
fn refold(tree: Tok, utf8: bool) -> Option<String> {
    let Tok::List(_, children) = tree else {
        return None;
    };
    let maxlen = MAX_LINE_LENGTH as isize;
    let mut lines = vec![String::new()];
    let mut leading_whitespace = String::new();
    let mut last_ew: Option<usize> = None;
    let mut last_charset: Option<&'static str> = None;
    let mut wrap_as_ew_blocked = 0usize;
    let mut want_encoding = false;
    let mut parts: VecDeque<Item> = children.into_iter().map(Item::Tok).collect();
    while let Some(item) = parts.pop_front() {
        let part = match item {
            Item::EndBlocked => {
                wrap_as_ew_blocked = wrap_as_ew_blocked.saturating_sub(1);
                continue;
            }
            Item::Tok(part) => part,
        };
        let tstr = part.text();
        if !want_encoding {
            want_encoding = if matches!(part.token_type(), "ptext" | "vtext") {
                tstr.chars()
                    .any(|c| is_special(c) || c == '\r' || c == '\n')
            } else {
                tstr.contains(['\r', '\n'])
            };
        }
        let charset = if utf8 {
            "utf-8"
        } else if tstr.is_ascii() {
            "us-ascii"
        } else {
            want_encoding = true;
            "utf-8"
        };
        let last_len = |lines: &[String]| lines.last().map_or(0, |l| clen(l)) as isize;
        if want_encoding && wrap_as_ew_blocked == 0 {
            if !part.as_ew_allowed() {
                want_encoding = false;
                last_ew = None;
                if part.syntactic_break() && matches!(part, Tok::List(..)) {
                    let folded = refold(part.clone(), utf8)?;
                    let encoded = folded.strip_suffix(CRLF).unwrap_or(&folded).to_owned();
                    if !encoded.contains(CRLF) {
                        if clen(&encoded) as isize > maxlen - last_len(&lines) {
                            let newline = steal_trailing_wsp(&mut lines);
                            lines.push(newline);
                        }
                        lines.last_mut()?.push_str(&encoded);
                        continue;
                    }
                }
            }
            match part {
                Tok::List(_, children) => {
                    for child in children.into_iter().rev() {
                        parts.push_front(Item::Tok(child));
                    }
                    want_encoding = false;
                    continue;
                }
                ref term if term.as_ew_allowed() => {
                    if last_ew.is_some()
                        && Some(charset) != last_charset
                        && (last_charset == Some("unknown-8bit")
                            || last_charset == Some("utf-8") && charset != "us-ascii")
                    {
                        last_ew = None;
                    }
                    last_ew = fold_as_ew(
                        &tstr,
                        &mut lines,
                        last_ew,
                        term.ew_combine_allowed(),
                        charset,
                        &leading_whitespace,
                    )?;
                    leading_whitespace.clear();
                    last_charset = Some(charset);
                    want_encoding = false;
                    continue;
                }
                _ => {
                    last_ew = None;
                    want_encoding = false;
                }
            }
        }
        if clen(&tstr) as isize <= maxlen - last_len(&lines) {
            lines.last_mut()?.push_str(&tstr);
            continue;
        }
        leading_whitespace.clear();
        if part.syntactic_break() && clen(&tstr) as isize + 1 <= maxlen {
            let newline = steal_trailing_wsp(&mut lines);
            if !newline.is_empty() || part.startswith_fws() {
                let line = newline + &tstr;
                leading_whitespace = line.chars().take_while(|c| is_wsp(*c)).collect();
                lines.push(line);
                last_ew = None;
                continue;
            }
        }
        if let Tok::List(kind, children) = &part {
            let mut newparts: Vec<Item> = if *kind == Kind::BareQuotedString {
                std::iter::once(Tok::value("\"", "ptext"))
                    .chain(
                        children
                            .iter()
                            .map(|p| Tok::value(make_quoted_pairs(&p.text()), "ptext")),
                    )
                    .chain(std::iter::once(Tok::value("\"", "ptext")))
                    .map(Item::Tok)
                    .collect()
            } else {
                children.iter().cloned().map(Item::Tok).collect()
            };
            if !part.as_ew_allowed() {
                wrap_as_ew_blocked += 1;
                newparts.push(Item::EndBlocked);
            }
            for item in newparts.into_iter().rev() {
                parts.push_front(item);
            }
            continue;
        }
        if part.as_ew_allowed() && wrap_as_ew_blocked == 0 {
            parts.push_front(Item::Tok(part));
            want_encoding = true;
            continue;
        }
        let newline = steal_trailing_wsp(&mut lines);
        if !newline.is_empty() || part.startswith_fws() {
            lines.push(newline + &tstr);
        } else {
            lines.last_mut()?.push_str(&tstr);
        }
    }
    Some(lines.join(CRLF) + CRLF)
}

/// `_fold_as_ew`. `None` where Python raises (an empty word).
fn fold_as_ew(
    to_encode: &str,
    lines: &mut Vec<String>,
    last_ew: Option<usize>,
    ew_combine_allowed: bool,
    charset: &'static str,
    leading_whitespace: &str,
) -> Option<Option<usize>> {
    let maxlen = MAX_LINE_LENGTH as isize;
    let mut to_encode: Vec<char> = to_encode.chars().collect();
    let mut leading_whitespace = leading_whitespace.to_owned();
    match last_ew {
        Some(position) if ew_combine_allowed => {
            let last = lines.last_mut()?;
            let tail: String = last.chars().skip(position).collect();
            let combined = format!("{tail}{}", to_encode.iter().collect::<String>());
            to_encode = get_unstructured(&combined, true)?.text().chars().collect();
            *last = last.chars().take(position).collect();
        }
        _ => {
            if is_wsp(*to_encode.first()?) {
                let leading = to_encode.remove(0);
                if lines.last().map_or(0, |l| clen(l)) == MAX_LINE_LENGTH {
                    let newline = steal_trailing_wsp(lines);
                    lines.push(newline);
                }
                lines.last_mut()?.push(leading);
            }
        }
    }
    let trailing = if is_wsp(*to_encode.last()?) {
        to_encode.pop()
    } else {
        None
    };
    let mut new_last_ew = last_ew.unwrap_or_else(|| lines.last().map_or(0, |l| clen(l)));
    let encode_as = if charset == "us-ascii" {
        "utf-8"
    } else {
        charset
    };
    let chrome_len = (encode_as.len() + 7) as isize;
    while !to_encode.is_empty() {
        let remaining_space = maxlen - lines.last().map_or(0, |l| clen(l)) as isize;
        let text_space = remaining_space - chrome_len - clen(&leading_whitespace) as isize;
        if text_space <= 0 {
            lines.push(" ".into());
            continue;
        }
        if lines.len() > 1
            && lines.last().map_or(0, |l| clen(l)) == 1
            && !leading_whitespace.is_empty()
        {
            let word = ew_encode(&leading_whitespace, encode_as);
            lines.last_mut()?.push_str(&word);
            leading_whitespace.clear();
        }
        let mut take = to_encode.len().min(text_space as usize);
        let mut encoded = ew_encode(&to_encode[..take].iter().collect::<String>(), encode_as);
        while clen(&encoded) as isize - remaining_space > 0 && take > 0 {
            take -= 1;
            encoded = ew_encode(&to_encode[..take].iter().collect::<String>(), encode_as);
        }
        lines.last_mut()?.push_str(&encoded);
        to_encode.drain(..take);
        leading_whitespace.clear();
        if !to_encode.is_empty() {
            lines.push(" ".into());
            new_last_ew = 1;
        }
    }
    if let Some(trailing) = trailing {
        lines.last_mut()?.push(trailing);
    }
    Some(ew_combine_allowed.then_some(new_last_ew))
}

/// `_encoded_words.encode(text, charset)`: the shorter of `q` and `b`, with
/// `q` preferred unless it is at least five characters longer.
fn ew_encode(text: &str, charset: &str) -> String {
    let bytes = text.as_bytes();
    let q_safe = |b: u8| b.is_ascii_alphanumeric() || b"-!*+/".contains(&b);
    let qlen: usize = bytes
        .iter()
        .map(|&b| if q_safe(b) || b == b' ' { 1 } else { 3 })
        .sum();
    let blen = bytes.len() / 3 * 4 + if bytes.len() % 3 == 0 { 0 } else { 4 };
    if (qlen as isize) - (blen as isize) < 5 {
        let encoded: String = bytes
            .iter()
            .map(|&b| match b {
                b' ' => "_".to_owned(),
                b if q_safe(b) => char::from(b).to_string(),
                b => format!("={b:02X}"),
            })
            .collect();
        format!("=?{charset}?q?{encoded}?=")
    } else {
        format!("=?{charset}?b?{}?=", crate::pybase64::b64encode(bytes))
    }
}
fn mailbox(address: &str) -> String {
    // Keep the configured header untouched. A comment is CFWS, not an address
    // character. Preserve its position so Python's domain-atom boundary can
    // be reproduced rather than silently joining two domain fragments.
    // This is deliberately only the supported mailbox subset,
    // not a general RFC 5322 address parser.
    let mut without_comments = String::with_capacity(address.len());
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut had_comment = false;
    let mut chars = address.chars().peekable();
    while let Some(ch) = chars.next() {
        if escaped {
            if depth == 0 {
                without_comments.push(ch);
            }
            escaped = false;
            continue;
        }
        if ch == '\\' {
            if depth == 0 && !(quoted && matches!(chars.peek(), Some('(' | ')'))) {
                without_comments.push(ch);
            }
            escaped = true;
            continue;
        }
        if ch == '"' && depth == 0 {
            quoted = !quoted;
            without_comments.push(ch);
        } else if ch == '(' && !quoted {
            had_comment = true;
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
    // Only structural angle brackets delimit a display-name mailbox. An
    // angle bracket inside a quoted display name or local part is literal.
    let mut start = None;
    quoted = false;
    escaped = false;
    for (index, ch) in without_comments.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            quoted = !quoted;
        } else if !quoted && ch == '<' {
            start = Some(index + ch.len_utf8());
        } else if !quoted
            && ch == '>'
            && let Some(start) = start
        {
            return envelope_cfws(&without_comments[start..index], had_comment);
        }
    }
    envelope_cfws(&without_comments, had_comment)
}

fn envelope_cfws(address: &str, had_comment: bool) -> String {
    if had_comment && address.ends_with(char::is_whitespace) {
        let prefix = address.trim_end();
        if prefix.ends_with(['@', '.']) {
            return String::new();
        }
    }
    let address = address.trim();
    if !had_comment {
        return address.into();
    }
    // Python's address extraction joins CFWS around unquoted atom separators.
    // Leave local-part word spaces alone (including quoted/escaped contents).
    let chars: Vec<char> = address.chars().collect();
    let mut result = String::with_capacity(address.len());
    let mut quoted = false;
    let mut escaped = false;
    let mut in_domain = false;
    for (index, &ch) in chars.iter().enumerate() {
        if escaped {
            result.push(ch);
            escaped = false;
        } else if ch == '\\' {
            result.push(ch);
            escaped = true;
        } else if ch == '"' {
            result.push(ch);
            quoted = !quoted;
        } else if !quoted && ch == '@' {
            while result.ends_with(char::is_whitespace) {
                result.pop();
            }
            result.push(ch);
            in_domain = true;
        } else if !quoted && ch.is_whitespace() {
            let next = chars[index + 1..].iter().find(|c| !c.is_whitespace());
            if in_domain
                && result.ends_with(['@', '.'])
                && (next.is_none() || matches!(next, Some('.')))
            {
                // EmailMessage selects an empty mailbox for these malformed
                // comment/dot positions; send_message emits MAIL FROM:<>.
                return String::new();
            }
            if in_domain
                && result.chars().last().is_some_and(|c| c != '@' && c != '.')
                && next.is_some_and(|c| c.is_alphanumeric())
            {
                break;
            }
            if in_domain || result.ends_with(['.', '@']) || matches!(next, Some('@' | '.')) {
                continue;
            }
            result.push(ch);
        } else if !quoted && ch == '.' {
            while result.ends_with(char::is_whitespace) {
                result.pop();
            }
            result.push(ch);
        } else {
            result.push(ch);
        }
    }
    if let Some((local, domain)) = result.split_once('@')
        && local.contains(char::is_whitespace)
        && !local.starts_with('"')
    {
        return format!("\"{local}\"@{domain}");
    }
    result
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
    use super::{Message, mailbox};
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
            cases.push(json!([subject, sender, recipients]));
        }
        for subject in &subjects {
            cases.push(json!([subject, "a@example.com", ["b@example.com"]]));
        }
        let script = format!(
            r#"
import base64, email.generator, email.utils, io, json
from email.message import EmailMessage
out = []
for subject, sender, recipients in json.loads({cases:?}):
    m = EmailMessage()
    m["Subject"] = subject
    m["From"] = sender
    m["To"] = ", ".join(recipients)
    m.set_content({body:?})
    from_addr = email.utils.getaddresses([m["From"]])[0][1]
    to_addrs = [a[1] for a in email.utils.getaddresses([m["To"]])]
    try:
        "".join([from_addr, *to_addrs]).encode("ascii")
        intl = False
    except UnicodeEncodeError:
        intl = True
    b = io.BytesIO()
    policy = m.policy.clone(utf8=True) if intl else None
    g = email.generator.BytesGenerator(b, policy=policy) if intl else email.generator.BytesGenerator(b)
    g.flatten(m, linesep="\r\n")
    out.append([intl, base64.b64encode(b.getvalue()).decode()])
print(json.dumps(out))
"#,
            cases = Value::Array(cases.clone()).to_string(),
        );
        let expected: Vec<(bool, String)> =
            serde_json::from_str(crate::oracle::python(&script).trim()).unwrap();
        let mut mismatches = vec![];
        for (case, (intl, flat)) in cases.iter().zip(expected) {
            let subject = case[0].as_str().unwrap();
            let sender = case[1].as_str().unwrap();
            let recipients: Vec<String> = case[2]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r.as_str().unwrap().to_owned())
                .collect();
            let rust_intl =
                !mailbox(sender).is_ascii() || recipients.iter().any(|r| !mailbox(r).is_ascii());
            let message = Message::new(&config(sender, &recipients), subject, body);
            let actual = message.flatten(rust_intl);
            let expected = crate::pybase64::b64decode(&flat).unwrap();
            if rust_intl != intl || actual != expected {
                mismatches.push(format!(
                    "case {case}\n python: {:?}\n rust:   {:?}",
                    String::from_utf8_lossy(&expected),
                    String::from_utf8_lossy(&actual)
                ));
            }
        }
        assert!(
            mismatches.is_empty(),
            "{} mismatches:\n{}",
            mismatches.len(),
            mismatches.join("\n")
        );
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
        let script = format!(
            r#"
import base64, email.generator, io, json
from email.message import EmailMessage
out = []
for body in json.loads({bodies:?}):
    m = EmailMessage()
    m["Subject"] = "s"
    m["From"] = "a@example.com"
    m["To"] = "b@example.com"
    m.set_content(body)
    b = io.BytesIO()
    email.generator.BytesGenerator(b).flatten(m, linesep="\r\n")
    out.append(base64.b64encode(b.getvalue()).decode())
print(json.dumps(out))
"#,
            bodies = serde_json::to_string(&bodies).unwrap(),
        );
        let expected: Vec<String> =
            serde_json::from_str(crate::oracle::python(&script).trim()).unwrap();
        let recipients = ["b@example.com".to_owned()];
        let mut ctes = std::collections::BTreeSet::new();
        for (body, flat) in bodies.iter().zip(expected) {
            let message = Message::new(&config("a@example.com", &recipients), "s", body);
            ctes.insert(message.cte);
            let actual = message.flatten(false);
            let expected = crate::pybase64::b64decode(&flat).unwrap();
            assert_eq!(
                String::from_utf8_lossy(&actual),
                String::from_utf8_lossy(&expected),
                "body {body:?}"
            );
        }
        assert_eq!(
            ctes.into_iter().collect::<Vec<_>>(),
            ["7bit", "8bit", "base64", "quoted-printable"]
        );
    }

    /// Deterministic pseudo-random subjects and address lists inside the
    /// supported grammar (atoms, quoted strings with escapes and specials,
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
        for _ in 0..240 {
            let subject: Vec<&str> = (0..1 + next(9)).map(|_| words[next(words.len())]).collect();
            let separators = [" ", " ", " ", "  ", "\t"];
            let mut text = String::new();
            for (index, word) in subject.iter().enumerate() {
                if index > 0 {
                    text.push_str(separators[next(separators.len())]);
                }
                text.push_str(word);
            }
            let subject = text.replace("\\t", "\t");
            let mut mailbox = |next: &mut dyn FnMut(usize) -> usize| -> String {
                let local = locals[next(locals.len())];
                let domain = domains[next(domains.len())];
                let address = format!("{local}@{domain}");
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
            cases.push(json!([subject, sender, recipients]));
        }
        let body = "짧은 본문\n";
        let script = format!(
            r#"
import base64, email.generator, email.utils, io, json
from email.message import EmailMessage
out = []
for subject, sender, recipients in json.loads({cases:?}):
    m = EmailMessage()
    m["Subject"] = subject
    m["From"] = sender
    m["To"] = ", ".join(recipients)
    m.set_content({body:?})
    from_addr = email.utils.getaddresses([m["From"]])[0][1]
    to_addrs = [a[1] for a in email.utils.getaddresses([m["To"]])]
    try:
        "".join([from_addr, *to_addrs]).encode("ascii")
        intl = False
    except UnicodeEncodeError:
        intl = True
    b = io.BytesIO()
    g = email.generator.BytesGenerator(b, policy=m.policy.clone(utf8=True)) if intl else email.generator.BytesGenerator(b)
    g.flatten(m, linesep="\r\n")
    out.append([intl, base64.b64encode(b.getvalue()).decode()])
print(json.dumps(out))
"#,
            cases = Value::Array(cases.clone()).to_string(),
        );
        let expected: Vec<(bool, String)> =
            serde_json::from_str(crate::oracle::python(&script).trim()).unwrap();
        let mut mismatches = vec![];
        let mut unsupported = 0;
        for (case, (intl, flat)) in cases.iter().zip(expected) {
            let subject = case[0].as_str().unwrap();
            let sender = case[1].as_str().unwrap();
            let recipients: Vec<String> = case[2]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r.as_str().unwrap().to_owned())
                .collect();
            if super::get_address_list(sender).is_none()
                || super::get_address_list(&recipients.join(", ")).is_none()
            {
                unsupported += 1;
            }
            let rust_intl =
                !mailbox(sender).is_ascii() || recipients.iter().any(|r| !mailbox(r).is_ascii());
            let message = Message::new(&config(sender, &recipients), subject, body);
            let actual = message.flatten(rust_intl);
            let expected = crate::pybase64::b64decode(&flat).unwrap();
            if rust_intl != intl || actual != expected {
                mismatches.push(format!(
                    "case {case}\n python: {:?}\n rust:   {:?}",
                    String::from_utf8_lossy(&expected),
                    String::from_utf8_lossy(&actual)
                ));
            }
        }
        assert_eq!(
            unsupported, 0,
            "generated shapes left the supported grammar"
        );
        assert!(
            mismatches.is_empty(),
            "{} mismatches:\n{}",
            mismatches.len(),
            mismatches.join("\n")
        );
    }
}

#[cfg(test)]
mod hostname_tests {
    /// `smtplib.SMTP().local_hostname` (`socket.getfqdn()` or the `[ip]`
    /// literal) is what EHLO/HELO send. The Rust lookup answers
    /// `gethostbyaddr` from the hosts database only, so the comparison is
    /// exact whenever Python's answer did not come from another NSS source
    /// (`DEVIATIONS.md`).
    #[test]
    fn local_hostname_matches_smtplib() {
        let script = r##"
import ipaddress, json, smtplib, socket
name = smtplib.SMTP().local_hostname
host = socket.gethostname()
try:
    address = socket.getaddrinfo(host, None)[0][4][0]
except socket.gaierror:
    address = None
comparable = address is None
if address is not None:
    for line in open("/etc/hosts"):
        fields = line.split("#")[0].split()
        try:
            if len(fields) > 1 and ipaddress.ip_address(fields[0]) == ipaddress.ip_address(address):
                comparable = True
                break
        except ValueError:
            pass
    if not comparable:
        try:
            socket.gethostbyaddr(address)
        except OSError:
            comparable = True
nsswitch = ""
try:
    nsswitch = next((l.split(":", 1)[1].split() for l in open("/etc/nsswitch.conf") if l.startswith("hosts:")), [""])[0]
except OSError:
    pass
print(json.dumps({"name": name, "comparable": comparable and nsswitch in ("", "files")}))
"##;
        let out: serde_json::Value =
            serde_json::from_str(crate::oracle::python(script).trim()).unwrap();
        let rust = super::local_hostname();
        if out["comparable"] == true {
            assert_eq!(rust, out["name"].as_str().unwrap());
        } else {
            println!(
                "Python local_hostname {} came from DNS; Rust {rust}",
                out["name"]
            );
            assert!(rust.contains('.') || (rust.starts_with('[') && rust.ends_with(']')));
        }
    }
}

#[cfg(test)]
mod mailbox_tests {
    use super::mailbox;
    use std::process::Command;

    #[test]
    fn supported_comment_forms_match_python_envelope_oracle() {
        // Expected mailboxes measured with Python 3.12 EmailMessage +
        // smtplib.send_message/quoteaddr. The configured header is not edited.
        for (input, expected) in [
            ("sender(Internal)@example.com", "sender@example.com"),
            ("sender@(Internal)example.com", "sender@example.com"),
            ("recipient(Internal)@example.com", "recipient@example.com"),
            ("recipient@(Internal)example.com", "recipient@example.com"),
            (
                "(outer(inner)) sender@(one(two))example.com (tail)",
                "sender@example.com",
            ),
            (
                "Display (a(b)) <sender(x)@(y)example.com>",
                "sender@example.com",
            ),
            ("sender (x) @example.com", "sender@example.com"),
            ("sender@ (x) example.com", "sender@example.com"),
            ("sender (x) .foo@example.com", "sender.foo@example.com"),
            // Measured via EmailMessage/getaddresses and actual send_message:
            // CFWS between domain atoms terminates the selected mailbox.
            ("sender@exa(comment)mple.com", "sender@exa"),
            ("sen(comment)der@example.com", "\"sen der\"@example.com"),
            (
                "sender.foo(comment)bar@example.com",
                "\"sender.foo bar\"@example.com",
            ),
            ("sender@(nested(inner)).com", ""),
            ("sender@exa.(nested(inner))", ""),
            (
                "\"loc(al)\"@(ignored)example.com",
                "\"loc(al)\"@example.com",
            ),
            (
                "\"lo\\\"c(a)\"@(ignored)example.com",
                "\"lo\\\"c(a)\"@example.com",
            ),
            (
                "\"Display <literal>\" <\"lo(c)al\"@(x)example.com>",
                "\"lo(c)al\"@example.com",
            ),
            (
                "sender(comment(with\\)escape))@example.com",
                "sender@example.com",
            ),
        ] {
            assert_eq!(mailbox(input), expected, "input={input:?}");
        }
    }

    #[test]
    fn generated_comment_boundaries_match_python_transport() {
        // Compute every expected envelope with the same parser and quoteaddr
        // that send_message uses, rather than copying Rust-derived fixtures.
        let script = r#"
import json
from email.message import EmailMessage
from email.utils import getaddresses
from smtplib import quoteaddr
cases=[]
for base in ('local+tag@domain.example', 'loc.al@domain.example',
             '"lo cal"@domain.example', 'Display <loc.al@domain.example>'):
 for pos in range(len(base)+1):
  for comment in ('(x)', '(nested(inner))', '(escaped\\)paren)'):
   address=base[:pos]+comment+base[pos:]
   msg=EmailMessage();msg['From']=address;msg['To']='recipient@example.com'
   parsed=getaddresses([msg['From']])
   assert parsed, address
   cases.append([address,quoteaddr(parsed[0][1])[1:-1]])
for before in ('@', '@exa', '@exa.', '@exa-', '@example.com'):
 for after in ('example.com', 'mple.com', 'com', '.com', ''):
  address='sender'+before+'(nested(inner))'+after
  msg=EmailMessage();msg['From']=address;msg['To']='recipient@example.com'
  parsed=getaddresses([msg['From']])
  assert parsed, address
  cases.append([address,quoteaddr(parsed[0][1])[1:-1]])
print(json.dumps(cases))
"#;
        let output = Command::new("python3.12")
            .args(["-c", script])
            .output()
            .expect("Python 3.12 oracle");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let cases: Vec<(String, String)> = serde_json::from_slice(&output.stdout).unwrap();
        for (input, expected) in cases {
            assert_eq!(mailbox(&input), expected, "input={input:?}");
        }
    }
}
