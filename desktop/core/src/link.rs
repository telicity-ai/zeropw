//! The zeropw-link daemon (docs/remote-sync.md §3.1, zeropw-link docs/protocol.md §5): a separate
//! sidecar that carries the encrypted team session between this user's Macs.
//!
//! - [`LinkClient`]: one connection per request to `<app data>/link/link.sock`. One JSON request
//!   line (at most [`MAX_REQUEST_BYTES`]) and one JSON response line. Invite codes and link
//!   tokens exist only in the request body, built in a wiped buffer; they never go into argv,
//!   the environment, an error or a log. Failures `{"ok":false,"error":CODE}` become
//!   `link_<CODE>` reasons; nothing the daemon wrote besides the code reaches the UI.
//! - [`LinkSupervisor`]: runs `zeropw-link daemon --state <app data>/link` (folder 0700) with
//!   the fixed child environment and stderr appended to `link.log` (0600). Single instance through
//!   `link.json` (pid, start time), adopting a daemon left by an earlier app run only when that
//!   pid runs `zeropw-link daemon --state <this folder>` and the socket answers `status`. The
//!   daemon counts as up when the socket answers `{"op":"status"}` with `ok`. An unexpected exit
//!   is restarted by [`LinkSupervisor::watch`] after a backoff that doubles per consecutive exit
//!   ([`Backoff`]); a daemon that stayed up for [`Backoff::stable`] resets it. Stop is SIGTERM,
//!   then SIGKILL after the grace period. A missing binary is not an error for the rest of the
//!   app: remote sync is then unavailable and says so.

use std::ffi::OsString;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::admin::{self, apply_child_env};
use crate::error::{AppError, is_code};
use crate::paths::{self, AppPaths};
use crate::secret::SecretString;
use crate::serve::{alive, ps_info, signalable, terminate_child, terminate_pid};

/// The link service the app enrols with when the user does not name another one. The only
/// place this address is written; the UI reads it from `link_status`. `.invalid` never
/// resolves (RFC 6761), so until the deployed service's address replaces it an enrolment
/// without an explicit service fails closed instead of reaching a host nobody vetted.
pub const DEFAULT_SERVICE_URL: &str = "https://link.zeropw.invalid";

/// zeropw-link protocol §5: a request line is at most 8 KiB.
pub const MAX_REQUEST_BYTES: usize = 8 * 1024;
/// A response line (the device list is the longest: at most a few devices).
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
/// `status`, `devices`, `revoke`, `link_token`: local, or one short service request.
pub const QUICK_TIMEOUT: Duration = Duration::from_secs(15);
/// `enroll` reaches the service (challenge, then enrolment).
pub const ENROLL_TIMEOUT: Duration = Duration::from_secs(45);
/// A health probe while starting or adopting.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// macOS `sun_path` holds 104 bytes including the terminating NUL.
pub const MAX_SOCKET_PATH_BYTES: usize = 103;

pub const START_TIMEOUT: Duration = Duration::from_secs(20);
pub const STOP_GRACE: Duration = Duration::from_secs(10);
pub const WATCH_INTERVAL: Duration = Duration::from_secs(2);
const MAX_PID_FILE_BYTES: u64 = 4096;
const MAX_LOG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_NAME_BYTES: usize = 64;
const MAX_TOKEN_CHARS: usize = 1024;

// ---------------------------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------------------------

/// A link device ID: lowercase unpadded base32 of 16 bytes, 26 characters `[a-z2-7]`.
pub fn is_device_id(text: &str) -> bool {
    text.len() == 26 && text.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
}

/// Display text sent to the service or shown on the other Mac: trimmed, at most 64 bytes, no
/// control characters, not empty.
pub fn check_display_name(name: &str) -> Result<String, AppError> {
    let name = name.trim();
    if name.is_empty() || name.len() > MAX_NAME_BYTES || name.chars().any(char::is_control) {
        return Err(AppError::invalid_input("invalid_name").with_detail("name"));
    }
    Ok(name.to_owned())
}

/// A display name received from elsewhere (the daemon, a pairing code): control characters
/// removed and bounded, never refused.
pub fn clean_name(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > MAX_NAME_BYTES {
            break;
        }
        out.push(c);
    }
    out.trim().to_owned()
}

/// This Mac's name for the service and the other Mac: the host name without `.local`.
pub fn default_device_name() -> String {
    let host = nix::unistd::gethostname()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_default();
    let host = host.strip_suffix(".local").unwrap_or(&host);
    let name = clean_name(host);
    if name.is_empty() {
        "mac".to_owned()
    } else {
        name
    }
}

/// A link service URL: `https://host[:port]` (a trailing `/` is dropped), or `http://` to a
/// loopback host for tests (zeropw-link protocol §2). No user info, path, query or fragment.
/// Returns the normalised URL.
pub fn check_service_url(url: &str) -> Result<String, AppError> {
    let bad = || AppError::invalid_input("link_service_invalid");
    let url = url.trim();
    if url.len() > 255 {
        return Err(bad());
    }
    let lower = url.to_ascii_lowercase();
    let (scheme, rest) = if let Some(rest) = lower.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = lower.strip_prefix("http://") {
        ("http", rest)
    } else {
        return Err(bad());
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty()
        || rest
            .bytes()
            .any(|b| matches!(b, b'/' | b'?' | b'#' | b'@' | b'\\' | b'%') || !b.is_ascii_graphic())
    {
        return Err(bad());
    }
    let (host, port) = split_host_port(rest).ok_or_else(bad)?;
    if let Some(port) = port
        && (port.is_empty()
            || port.len() > 5
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u32>().map_or(true, |p| p == 0 || p > 65535))
    {
        return Err(bad());
    }
    let loopback = matches!(host, "127.0.0.1" | "localhost" | "[::1]");
    let host_ok = if host.starts_with('[') {
        host.ends_with(']')
            && host[1..host.len() - 1]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
    } else {
        !host.starts_with('-')
            && !host.starts_with('.')
            && !host.ends_with('.')
            && !host.contains("..")
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    };
    if !host_ok || (scheme == "http" && !loopback) {
        return Err(bad());
    }
    Ok(format!("{scheme}://{rest}"))
}

fn split_host_port(rest: &str) -> Option<(&str, Option<&str>)> {
    if rest.starts_with('[') {
        let close = rest.find(']')?;
        let (host, tail) = rest.split_at(close + 1);
        match tail {
            "" => Some((host, None)),
            _ => tail.strip_prefix(':').map(|port| (host, Some(port))),
        }
    } else {
        match rest.split_once(':') {
            Some((host, port)) if !port.contains(':') => Some((host, Some(port))),
            Some(_) => None,
            None => Some((rest, None)),
        }
    }
}

/// `host[:port]` of a checked service URL, for display.
pub fn service_host(url: &str) -> String {
    url.split_once("://")
        .map(|(_, rest)| rest.trim_end_matches('/').to_owned())
        .unwrap_or_default()
}

/// A server invite code: `ZPL-` and 26 base32 characters, any case, spaces and dashes allowed
/// (zeropw-link protocol §2.2). The text goes to the daemon as typed (trimmed); the service
/// normalises it.
pub fn is_invite_code(code: &str) -> bool {
    let compact: String = code
        .chars()
        .filter(|c| !matches!(c, ' ' | '-'))
        .map(|c| c.to_ascii_uppercase())
        .collect();
    compact.len() == 29
        && compact.starts_with("ZPL")
        && compact[3..]
            .bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'2'..=b'7'))
        && code.trim().len() <= 64
}

/// A link token as the daemon issued it: printable ASCII without spaces, bounded.
pub fn is_link_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_CHARS
        && token.bytes().all(|b| b.is_ascii_graphic())
}

/// The daemon's error codes (zeropw-link protocol §5 and the daemon's fixed set) as fixed
/// `(class, reason)` pairs. A code outside the set is `link_failed`: the daemon's text is never
/// passed on, so nothing it wrote can reach the UI or a log.
fn link_error(code: &str) -> AppError {
    let (class, reason) = match code {
        "invalid_request" => ("InvalidInput", "link_invalid_request"),
        "not_enrolled" => ("StateError", "link_not_enrolled"),
        "already_enrolled" => ("StateError", "link_already_enrolled"),
        // this Mac was removed at the service: it cannot open sessions or enrol again
        "device_revoked" => ("PolicyDenied", "link_device_revoked"),
        // a server invite code that is unknown, used up, expired or revoked
        "invite_invalid" => ("PolicyDenied", "link_invite_invalid"),
        // a pairing code's link token that is unknown, used or older than 10 minutes
        "link_token_invalid" => ("PolicyDenied", "link_token_invalid"),
        // the account already has its most devices
        "device_limit" => ("PolicyDenied", "link_device_limit"),
        "peer_unknown" => ("NotFound", "link_peer_unknown"),
        "peer_revoked" => ("PolicyDenied", "link_peer_revoked"),
        "peer_offline" => ("Unavailable", "link_peer_offline"),
        "connect_failed" => ("Unavailable", "link_connect_failed"),
        "timeout" => ("Timeout", "link_timeout"),
        "service_unavailable" => ("Unavailable", "link_service_unavailable"),
        "rate_limited" => ("Unavailable", "link_rate_limited"),
        "busy" => ("Unavailable", "link_busy"),
        "shutting_down" => ("Unavailable", "link_unavailable"),
        _ => ("LinkError", "link_failed"),
    };
    AppError::new(class, reason)
}

/// A reason code from the daemon's status (a peer's last error), for the connection details
/// only: lowercase letters, digits and `_`, at most 48 characters, else `link_failed`.
fn daemon_code(code: String) -> String {
    let fine = !code.is_empty()
        && code.len() <= 48
        && code
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if fine { code } else { "link_failed".to_owned() }
}

// ---------------------------------------------------------------------------------------------
// Socket client
// ---------------------------------------------------------------------------------------------

/// A peer as `status` reports it. Values from the daemon are checked; a peer with a malformed ID
/// is dropped, unknown path labels become `None` and an unknown error text `link_failed`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkPeer {
    pub device_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub online: bool,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub rtt_ms: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
}

/// `{"op":"status"}`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct DaemonStatus {
    pub enrolled: bool,
    /// This Mac was removed at the link service (by another of the user's Macs, or the
    /// operator): it can no longer reach the others through the service.
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub online: bool,
    #[serde(default)]
    pub peers: Vec<LinkPeer>,
}

impl DaemonStatus {
    fn cleaned(mut self) -> Self {
        self.device_id = self.device_id.filter(|id| is_device_id(id));
        self.service = self.service.and_then(|s| check_service_url(&s).ok());
        self.account_id = self.account_id.filter(|a| is_code(a));
        self.peers = self
            .peers
            .into_iter()
            .filter(|p| is_device_id(&p.device_id))
            .map(|mut p| {
                p.name = clean_name(&p.name);
                p.path = p.path.filter(|path| {
                    matches!(
                        path.as_str(),
                        "direct" | "relay-udp" | "relay-tcp" | "relay-tls"
                    )
                });
                p.last_error = p.last_error.map(daemon_code);
                p
            })
            .collect();
        self
    }
}

/// A device of this account (zeropw-link protocol §2.4). Times are kept as the daemon gave
/// them (numbers or text) for display only.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LinkDevice {
    pub device_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub created_at: serde_json::Value,
    #[serde(default)]
    pub last_seen_at: serde_json::Value,
    #[serde(default)]
    pub online: bool,
    #[serde(default)]
    pub revoked_at: serde_json::Value,
}

impl LinkDevice {
    pub fn active(&self) -> bool {
        self.revoked_at.is_null()
    }

    /// `created_at` as unix seconds when it is a number or an RFC 3339 UTC time.
    pub fn created_unix(&self) -> Option<u64> {
        time_unix(&self.created_at)
    }
}

/// Unix seconds from a JSON number, or from `YYYY-MM-DDTHH:MM:SS[.frac]Z`.
pub fn time_unix(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::Number(n) => n.as_u64().or_else(|| n.as_f64().map(|f| f as u64)),
        serde_json::Value::String(s) => rfc3339_utc(s),
        _ => None,
    }
}

fn rfc3339_utc(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 || !s.ends_with('Z') || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<u64>().ok();
    let (y, mo, d, h, mi, se) = (
        num(0..4)?,
        num(5..7)?,
        num(8..10)?,
        num(11..13)?,
        num(14..16)?,
        num(17..19)?,
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 || y < 1970
    {
        return None;
    }
    // days from civil (Howard Hinnant)
    let (y, m) = if mo <= 2 {
        (y - 1, mo + 9)
    } else {
        (y, mo - 3)
    };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + se)
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct LinkDevices {
    #[serde(rename = "self", default)]
    pub self_id: Option<String>,
    #[serde(default)]
    pub devices: Vec<LinkDevice>,
}

impl LinkDevices {
    fn cleaned(mut self) -> Self {
        self.self_id = self.self_id.filter(|id| is_device_id(id));
        self.devices = self
            .devices
            .into_iter()
            .filter(|d| is_device_id(&d.device_id))
            .map(|mut d| {
                d.name = clean_name(&d.name);
                d
            })
            .collect();
        self
    }
}

#[derive(Deserialize)]
pub struct Enrolled {
    pub device_id: String,
    #[serde(default)]
    pub account_id: Option<String>,
}

/// `{"op":"link_token"}`: a one-time token that adds one device to this account (10 minutes).
#[derive(Deserialize)]
pub struct LinkToken {
    pub link_token: SecretString,
    #[serde(default)]
    pub expires_at: serde_json::Value,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
}

/// What an enrolment proves membership with: a server invite code or a link token.
pub enum Credential<'a> {
    InviteCode(&'a SecretString),
    LinkToken(&'a SecretString),
}

#[derive(Deserialize)]
struct Head {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
}

/// One request per connection to the daemon's socket.
#[derive(Clone, Debug)]
pub struct LinkClient {
    socket: PathBuf,
    quick: Duration,
    slow: Duration,
}

impl LinkClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            quick: QUICK_TIMEOUT,
            slow: ENROLL_TIMEOUT,
        }
    }

    /// Answer limits for local requests and for `enroll` (tests shorten them).
    pub fn with_timeouts(mut self, quick: Duration, slow: Duration) -> Self {
        self.quick = quick;
        self.slow = slow;
        self
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    pub fn status(&self) -> Result<DaemonStatus, AppError> {
        self.status_within(self.quick)
    }

    fn status_within(&self, timeout: Duration) -> Result<DaemonStatus, AppError> {
        let status: DaemonStatus = self.call(br#"{"op":"status"}"#, timeout.min(self.quick))?;
        Ok(status.cleaned())
    }

    pub fn enroll(
        &self,
        service: &str,
        name: &str,
        credential: Credential<'_>,
    ) -> Result<Enrolled, AppError> {
        #[derive(Serialize)]
        struct Request<'a> {
            op: &'static str,
            service: &'a str,
            name: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            invite_code: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            link_token: Option<&'a str>,
        }
        let (invite_code, link_token) = match credential {
            Credential::InviteCode(code) => (Some(code.expose().trim()), None),
            Credential::LinkToken(token) => (None, Some(token.expose())),
        };
        let body = encode(&Request {
            op: "enroll",
            service,
            name,
            invite_code,
            link_token,
        })?;
        let out: Enrolled = self.call(&body, self.slow)?;
        if !is_device_id(&out.device_id) {
            return Err(AppError::internal("link_output_invalid"));
        }
        Ok(out)
    }

    pub fn link_token(&self) -> Result<LinkToken, AppError> {
        let out: LinkToken = self.call(br#"{"op":"link_token"}"#, self.quick)?;
        if !is_link_token(out.link_token.expose()) {
            return Err(AppError::internal("link_output_invalid"));
        }
        Ok(out)
    }

    pub fn devices(&self) -> Result<LinkDevices, AppError> {
        let out: LinkDevices = self.call(br#"{"op":"devices"}"#, self.quick)?;
        Ok(out.cleaned())
    }

    pub fn revoke(&self, device_id: &str) -> Result<(), AppError> {
        if !is_device_id(device_id) {
            return Err(AppError::invalid_input("invalid_argument").with_detail("device_id"));
        }
        let body = encode(&serde_json::json!({"op": "revoke", "device_id": device_id}))?;
        let _: serde::de::IgnoredAny = self.call(&body, self.quick)?;
        Ok(())
    }

    /// Send one request line and parse the one response line. `ok: false` becomes a
    /// `link_<code>` error; a response that is not a JSON object with `ok` is
    /// `link_output_invalid`.
    fn call<T: DeserializeOwned>(&self, request: &[u8], timeout: Duration) -> Result<T, AppError> {
        let line = self.exchange(request, timeout)?;
        let head: Head =
            serde_json::from_slice(&line).map_err(|_| AppError::internal("link_output_invalid"))?;
        if !head.ok {
            return Err(link_error(head.error.as_deref().unwrap_or("")));
        }
        serde_json::from_slice(&line).map_err(|_| AppError::internal("link_output_invalid"))
    }

    fn exchange(&self, request: &[u8], timeout: Duration) -> Result<Zeroizing<Vec<u8>>, AppError> {
        if request.len() > MAX_REQUEST_BYTES {
            return Err(AppError::invalid_input("link_request_too_large"));
        }
        if self.socket.as_os_str().len() > MAX_SOCKET_PATH_BYTES {
            return Err(AppError::unavailable("link_socket_path_too_long"));
        }
        let mut stream = UnixStream::connect(&self.socket).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
                AppError::unavailable("link_unavailable")
            }
            _ => AppError::io("link_unavailable", &e),
        })?;
        let timed_out = |e: &io::Error| {
            matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            )
        };
        stream
            .set_read_timeout(Some(timeout))
            .and_then(|()| stream.set_write_timeout(Some(timeout)))
            .map_err(|e| AppError::io("link_unavailable", &e))?;
        let mut framed = Zeroizing::new(Vec::with_capacity(request.len() + 1));
        framed.extend_from_slice(request);
        framed.push(b'\n');
        stream.write_all(&framed).map_err(|e| {
            if timed_out(&e) {
                AppError::timeout("link_timeout")
            } else {
                AppError::io("link_unavailable", &e)
            }
        })?;
        drop(framed);
        let mut reader = BufReader::new((&stream).take(MAX_RESPONSE_BYTES as u64 + 1));
        let mut line = Zeroizing::new(Vec::with_capacity(4096));
        reader.read_until(b'\n', &mut line).map_err(|e| {
            if timed_out(&e) {
                AppError::timeout("link_timeout")
            } else {
                AppError::io("link_unavailable", &e)
            }
        })?;
        if line.len() > MAX_RESPONSE_BYTES {
            return Err(AppError::internal("link_output_too_large"));
        }
        if line.last() != Some(&b'\n') {
            return Err(AppError::unavailable("link_closed"));
        }
        line.pop();
        Ok(line)
    }
}

/// A request body in a wiped buffer, refused when longer than a request line may be.
fn encode<T: Serialize>(request: &T) -> Result<Zeroizing<Vec<u8>>, AppError> {
    let mut body = Zeroizing::new(Vec::with_capacity(512));
    serde_json::to_writer(&mut *body, request)
        .map_err(|_| AppError::internal("link_encode_failed"))?;
    if body.len() > MAX_REQUEST_BYTES {
        return Err(AppError::invalid_input("link_request_too_large"));
    }
    Ok(body)
}

// ---------------------------------------------------------------------------------------------
// Supervisor
// ---------------------------------------------------------------------------------------------

/// Restart delays after unexpected exits: `initial`, doubled per consecutive exit, at most
/// `max`; a daemon up for `stable` starts the count again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backoff {
    pub initial: Duration,
    pub max: Duration,
    pub stable: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(60),
            stable: Duration::from_secs(60),
        }
    }
}

impl Backoff {
    /// The wait before the restart that follows the `exits`-th consecutive exit (1-based).
    pub fn delay(&self, exits: u32) -> Duration {
        let shift = exits.saturating_sub(1).min(16);
        self.initial
            .checked_mul(1u32 << shift)
            .unwrap_or(self.max)
            .min(self.max)
    }
}

#[derive(Serialize, Deserialize)]
struct PidFile {
    pid: u32,
    started_at: u64,
}

enum Proc {
    Stopped,
    Owned { child: Child, since: Instant },
    Attached { pid: u32, since: Instant },
}

struct Run {
    proc: Proc,
    /// The app wants the daemon up: set by start or adoption, cleared by stop.
    wanted: bool,
    /// Consecutive unexpected exits.
    exits: u32,
    next_start: Option<Instant>,
    /// Why the daemon is not up, as a reason code (`link_binary_missing`, `link_exited`, ...).
    problem: Option<String>,
    spawns: u64,
}

/// What the supervisor knows about the daemon process (not whether it is enrolled).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LinkProcess {
    pub available: bool,
    pub running: bool,
    pub pid: Option<u32>,
    pub problem: Option<String>,
    pub restarts: u64,
}

pub struct LinkSupervisor {
    bin: PathBuf,
    state_dir: PathBuf,
    data_dir: PathBuf,
    pid_file: PathBuf,
    log_file: PathBuf,
    client: LinkClient,
    start_timeout: Duration,
    stop_grace: Duration,
    backoff: Backoff,
    run: Mutex<Run>,
}

impl LinkSupervisor {
    pub fn new(paths: &AppPaths) -> Self {
        Self {
            bin: paths.link_bin(),
            state_dir: paths.link_state_dir(),
            data_dir: paths.app_data_dir.clone(),
            pid_file: paths.link_pid_file(),
            log_file: paths.link_log_file(),
            client: LinkClient::new(paths.link_socket()),
            start_timeout: START_TIMEOUT,
            stop_grace: STOP_GRACE,
            backoff: Backoff::default(),
            run: Mutex::new(Run {
                proc: Proc::Stopped,
                wanted: false,
                exits: 0,
                next_start: None,
                problem: None,
                spawns: 0,
            }),
        }
    }

    pub fn with_timeouts(mut self, start: Duration, stop_grace: Duration) -> Self {
        self.start_timeout = start;
        self.stop_grace = stop_grace;
        self
    }

    pub fn with_backoff(mut self, backoff: Backoff) -> Self {
        self.backoff = backoff;
        self
    }

    pub fn client(&self) -> &LinkClient {
        &self.client
    }

    fn lock(&self) -> MutexGuard<'_, Run> {
        self.run.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The binary ships beside the app (absent in builds without remote sync).
    pub fn available(&self) -> bool {
        self.bin.is_file()
    }

    /// The process view; a daemon that died since the last look is noticed (not restarted).
    pub fn process(&self) -> LinkProcess {
        let mut run = self.lock();
        self.reap(&mut run);
        self.process_of(&run)
    }

    fn process_of(&self, run: &Run) -> LinkProcess {
        let pid = match &run.proc {
            Proc::Stopped => None,
            Proc::Owned { child, .. } => Some(child.id()),
            Proc::Attached { pid, .. } => Some(*pid),
        };
        LinkProcess {
            available: self.available(),
            running: pid.is_some(),
            pid,
            problem: run.problem.clone(),
            restarts: run.spawns.saturating_sub(1),
        }
    }

    /// The socket answers `status` now (the daemon is up).
    pub fn ready(&self) -> bool {
        self.client.status_within(PROBE_TIMEOUT).is_ok()
    }

    /// Adopt a daemon left by an earlier app run, or start one, and wait until its socket
    /// answers (at most the start timeout). The daemon stays wanted afterwards, so the watch
    /// restarts it if it exits.
    pub fn start(&self) -> Result<LinkProcess, AppError> {
        {
            let mut run = self.lock();
            run.wanted = true;
            self.reap(&mut run);
            if matches!(run.proc, Proc::Stopped) {
                if let Some(pid) = self.recorded() {
                    run.proc = Proc::Attached {
                        pid,
                        since: Instant::now(),
                    };
                    run.problem = None;
                } else {
                    self.spawn(&mut run)?;
                }
            }
        }
        self.wait_ready()?;
        let mut run = self.lock();
        run.problem = None;
        Ok(self.process_of(&run))
    }

    fn wait_ready(&self) -> Result<(), AppError> {
        let deadline = Instant::now() + self.start_timeout;
        loop {
            if self.ready() {
                return Ok(());
            }
            {
                let mut run = self.lock();
                self.reap(&mut run);
                if !run.wanted {
                    return Err(AppError::state("link_start_cancelled"));
                }
                if matches!(run.proc, Proc::Stopped) {
                    return Err(AppError::unavailable("link_exited"));
                }
            }
            if Instant::now() >= deadline {
                self.lock().problem = Some("link_start_timeout".into());
                return Err(AppError::timeout("link_start_timeout"));
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// SIGTERM, wait up to the grace period, then SIGKILL; the daemon is no longer wanted.
    pub fn stop(&self) {
        let mut run = self.lock();
        run.wanted = false;
        run.next_start = None;
        match std::mem::replace(&mut run.proc, Proc::Stopped) {
            Proc::Owned { mut child, .. } => terminate_child(&mut child, self.stop_grace),
            Proc::Attached { pid, .. } => {
                if self.is_our_daemon(pid) {
                    terminate_pid(pid, self.stop_grace);
                }
            }
            Proc::Stopped => {}
        }
        let _ = fs::remove_file(&self.pid_file);
    }

    /// One look for the core's watch thread, never waiting for a start or stop in progress:
    /// notice an exit, schedule its restart after the backoff, and start a wanted daemon whose
    /// time has come. Returns the process view, or `None` when another call held the state.
    pub fn watch(&self) -> Option<LinkProcess> {
        let mut run = match self.run.try_lock() {
            Ok(run) => run,
            Err(TryLockError::Poisoned(e)) => e.into_inner(),
            Err(TryLockError::WouldBlock) => return None,
        };
        self.reap(&mut run);
        if let Proc::Owned { since, .. } | Proc::Attached { since, .. } = &run.proc
            && since.elapsed() >= self.backoff.stable
        {
            run.exits = 0;
        }
        if run.wanted
            && matches!(run.proc, Proc::Stopped)
            && run.next_start.is_none_or(|at| Instant::now() >= at)
            && self.available()
        {
            // a failed spawn records its problem and is tried again after the next backoff
            let _ = self.spawn(&mut run);
        }
        Some(self.process_of(&run))
    }

    /// Forget a daemon that exited and schedule its restart.
    fn reap(&self, run: &mut Run) {
        let gone = match &mut run.proc {
            Proc::Stopped => false,
            Proc::Owned { child, .. } => !matches!(child.try_wait(), Ok(None)),
            // an adopted daemon's parent (an earlier app run) is gone, so it is reaped at once
            Proc::Attached { pid, .. } => !signalable(*pid),
        };
        if gone {
            run.proc = Proc::Stopped;
            let _ = fs::remove_file(&self.pid_file);
            run.problem = Some("link_exited".into());
            run.exits = run.exits.saturating_add(1);
            run.next_start = Some(Instant::now() + self.backoff.delay(run.exits));
        }
    }

    /// A pid recorded by an earlier app run that still runs our daemon with a socket answering.
    fn recorded(&self) -> Option<u32> {
        let meta = fs::metadata(&self.pid_file).ok()?;
        let file = (meta.len() <= MAX_PID_FILE_BYTES)
            .then(|| fs::read(&self.pid_file).ok())
            .flatten()
            .and_then(|bytes| serde_json::from_slice::<PidFile>(&bytes).ok())
            .filter(|f| f.pid > 1 && i32::try_from(f.pid).is_ok());
        let Some(file) = file else {
            let _ = fs::remove_file(&self.pid_file);
            return None;
        };
        if !alive(file.pid) || !self.is_our_daemon(file.pid) {
            let _ = fs::remove_file(&self.pid_file);
            return None;
        }
        if self.ready() {
            Some(file.pid)
        } else {
            // ours but not answering: replace it rather than share the socket with it
            terminate_pid(file.pid, self.stop_grace);
            let _ = fs::remove_file(&self.pid_file);
            None
        }
    }

    /// The pid runs `zeropw-link daemon --state <our folder>` (checked before any signal).
    fn is_our_daemon(&self, pid: u32) -> bool {
        let Some((_, command)) = ps_info(pid) else {
            return false;
        };
        command.contains(&*self.bin.to_string_lossy())
            && command.split_whitespace().any(|w| w == "daemon")
            && command.contains(&format!("--state {}", self.state_dir.to_string_lossy()))
    }

    fn spawn(&self, run: &mut Run) -> Result<(), AppError> {
        if !self.available() {
            run.problem = Some("link_binary_missing".into());
            return Err(AppError::unavailable("link_binary_missing"));
        }
        let result = self.spawn_child();
        match result {
            Ok(child) => {
                run.spawns += 1;
                run.problem = None;
                run.next_start = None;
                let record = PidFile {
                    pid: child.id(),
                    started_at: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                };
                if let Ok(bytes) = serde_json::to_vec(&record) {
                    let _ = paths::write_private_atomic(&self.pid_file, &bytes);
                }
                run.proc = Proc::Owned {
                    child,
                    since: Instant::now(),
                };
                Ok(())
            }
            Err(e) => {
                run.problem = Some(e.reason.clone());
                run.exits = run.exits.saturating_add(1);
                run.next_start = Some(Instant::now() + self.backoff.delay(run.exits));
                Err(e)
            }
        }
    }

    fn spawn_child(&self) -> Result<Child, AppError> {
        paths::ensure_private_dir(&self.data_dir)?;
        paths::ensure_private_dir(&self.state_dir)?;
        // the daemon keeps its device key here: the folder is private whatever made it
        fs::set_permissions(&self.state_dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| AppError::io("link_state_unavailable", &e))?;
        if self.client.socket().as_os_str().len() > MAX_SOCKET_PATH_BYTES {
            return Err(AppError::unavailable("link_socket_path_too_long"));
        }
        if fs::metadata(&self.log_file).is_ok_and(|m| m.len() > MAX_LOG_BYTES) {
            let _ = fs::rename(&self.log_file, self.log_file.with_extension("log.1"));
        }
        let log = paths::open_private_append(&self.log_file)
            .map_err(|e| AppError::io("link_log_unavailable", &e))?;
        let mut cmd = Command::new(&self.bin);
        cmd.arg("daemon")
            .arg("--state")
            .arg(OsString::from(self.state_dir.as_os_str()))
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .process_group(0);
        apply_child_env(&mut cmd);
        admin::spawn(&mut cmd).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => AppError::unavailable("link_binary_missing"),
            io::ErrorKind::PermissionDenied => AppError::unavailable("link_binary_not_executable"),
            _ => AppError::io("link_spawn_failed", &e),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_urls_are_https_or_loopback_http_without_extras() {
        assert_eq!(
            check_service_url("https://Link.Example.org/").unwrap(),
            "https://link.example.org"
        );
        assert_eq!(
            check_service_url(" https://link.example.org:8443 ").unwrap(),
            "https://link.example.org:8443"
        );
        assert_eq!(
            check_service_url("http://127.0.0.1:9000").unwrap(),
            "http://127.0.0.1:9000"
        );
        assert_eq!(
            check_service_url("http://[::1]:9").unwrap(),
            "http://[::1]:9"
        );
        assert_eq!(
            check_service_url(DEFAULT_SERVICE_URL).unwrap(),
            DEFAULT_SERVICE_URL
        );
        for bad in [
            "",
            "link.example.org",
            "ftp://link.example.org",
            "http://link.example.org",
            "http://10.0.0.1",
            "https://user@link.example.org",
            "https://link.example.org/v1",
            "https://link.example.org?x=1",
            "https://link.example.org#x",
            "https://link.example.org:0",
            "https://link.example.org:70000",
            "https://link.example.org:",
            "https://-bad.example",
            "https://bad..example",
            "https://exa mple.org",
            "https://exa%2fmple.org",
            "https://",
        ] {
            assert!(check_service_url(bad).is_err(), "{bad}");
        }
        assert_eq!(
            service_host("https://link.example.org:8443"),
            "link.example.org:8443"
        );
    }

    #[test]
    fn invite_codes_and_ids_have_their_shapes() {
        assert!(is_invite_code("ZPL-ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ"));
        assert!(is_invite_code("zpl abcd efgh ijkl mnop qrst uvwx yz"));
        assert!(!is_invite_code("ZPL-ABCD-EFGH-IJKL-MNOP-QRST-UVWX-Y"));
        assert!(!is_invite_code("ZPL-ABCD-EFGH-IJKL-MNOP-QRST-UVWX-Y1"));
        assert!(!is_invite_code("XYZ-ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ"));
        assert!(is_device_id("abcdefghijklmnopqrstuvwxyz"));
        assert!(!is_device_id("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
        assert!(!is_device_id("abcdefghijklmnopqrstuvwxy1"));
        assert!(is_link_token("zplt_synthetic-0123"));
        assert!(!is_link_token("has space"));
        assert!(!is_link_token(""));
    }

    #[test]
    fn names_are_bounded_and_control_free() {
        assert_eq!(check_display_name("  my mac ").unwrap(), "my mac");
        assert!(check_display_name("").is_err());
        assert!(check_display_name("a\nb").is_err());
        assert!(check_display_name(&"a".repeat(65)).is_err());
        assert_eq!(clean_name("a\u{1b}[31mb"), "a[31mb");
        assert_eq!(clean_name(&"é".repeat(40)).len(), 64);
        assert!(!default_device_name().is_empty());
    }

    #[test]
    fn daemon_errors_become_link_reasons_without_their_text() {
        let e = link_error("not_enrolled");
        assert_eq!(
            (e.error.as_str(), e.reason.as_str()),
            ("StateError", "link_not_enrolled")
        );
        assert_eq!(link_error("rate_limited").error, "Unavailable");
        assert_eq!(link_error("timeout").error, "Timeout");
        for (code, class, reason) in [
            ("link_token_invalid", "PolicyDenied", "link_token_invalid"),
            ("invite_invalid", "PolicyDenied", "link_invite_invalid"),
            ("device_revoked", "PolicyDenied", "link_device_revoked"),
            ("device_limit", "PolicyDenied", "link_device_limit"),
            ("peer_offline", "Unavailable", "link_peer_offline"),
            ("busy", "Unavailable", "link_busy"),
            ("shutting_down", "Unavailable", "link_unavailable"),
            ("internal", "LinkError", "link_failed"),
        ] {
            let e = link_error(code);
            assert_eq!(
                (e.error.as_str(), e.reason.as_str()),
                (class, reason),
                "{code}"
            );
        }
        // codes outside the daemon's set are never passed on, whatever their shape
        for code in [
            "token for zpl secret",
            "",
            "zplt_synthetic_token",
            "NOT_ENROLLED",
            "peer.offline",
        ] {
            assert_eq!(link_error(code).reason, "link_failed", "{code}");
        }
        assert_eq!(daemon_code("connect_failed".into()), "connect_failed");
        assert_eq!(daemon_code("a b".into()), "link_failed");
        assert_eq!(daemon_code("x".repeat(49)), "link_failed");
    }

    #[test]
    fn backoff_doubles_up_to_its_limit() {
        let b = Backoff {
            initial: Duration::from_millis(100),
            max: Duration::from_millis(1000),
            stable: Duration::from_secs(1),
        };
        assert_eq!(b.delay(1), Duration::from_millis(100));
        assert_eq!(b.delay(2), Duration::from_millis(200));
        assert_eq!(b.delay(4), Duration::from_millis(800));
        assert_eq!(b.delay(5), Duration::from_millis(1000));
        assert_eq!(b.delay(500), Duration::from_millis(1000));
        assert_eq!(Backoff::default().delay(0), Duration::from_secs(1));
    }

    #[test]
    fn times_parse_from_numbers_and_utc_text() {
        assert_eq!(
            time_unix(&serde_json::json!(1_700_000_000)),
            Some(1_700_000_000)
        );
        assert_eq!(
            time_unix(&serde_json::json!("1970-01-01T00:00:00Z")),
            Some(0)
        );
        assert_eq!(
            time_unix(&serde_json::json!("2026-11-06T12:00:00Z")),
            Some(1_793_966_400)
        );
        assert_eq!(
            time_unix(&serde_json::json!("2026-11-06T12:00:00.25Z")),
            Some(1_793_966_400)
        );
        assert_eq!(time_unix(&serde_json::json!("2026-11-06 12:00:00")), None);
        assert_eq!(time_unix(&serde_json::Value::Null), None);
    }

    #[test]
    fn status_values_from_the_daemon_are_checked() {
        let raw: DaemonStatus = serde_json::from_value(serde_json::json!({
            "ok": true, "enrolled": true, "service": "https://link.example.org",
            "device_id": "abcdefghijklmnopqrstuvwxyz", "account_id": "acct_1", "online": true,
            "revoked": false,
            "peers": [
                {"device_id": "bbbbbbbbbbbbbbbbbbbbbbbbbb", "name": "other\u{7}mac", "online": true,
                 "revoked": false, "path": "relay-tls", "rtt_ms": 40, "last_error": null},
                {"device_id": "not-an-id", "name": "x"},
                {"device_id": "cccccccccccccccccccccccccc", "path": "warp", "last_error": "a b c"}
            ]
        }))
        .unwrap();
        let s = raw.cleaned();
        assert_eq!(s.peers.len(), 2);
        assert_eq!(s.peers[0].name, "othermac");
        assert_eq!(s.peers[0].path.as_deref(), Some("relay-tls"));
        assert_eq!(s.peers[1].path, None);
        assert_eq!(s.peers[1].last_error.as_deref(), Some("link_failed"));
    }
}
