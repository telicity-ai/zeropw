//! The zeropw-link adapter (docs/remote-sync.md §3.1): team sessions to
//! `zpl:<device-id>` peers carried by the local `zeropw-link daemon`.
//!
//! The daemon is a separate process reached over its Unix socket
//! (zeropw-link protocol §5): each client connection sends one JSON request
//! line and reads one JSON reply line, both at most [`DAEMON_LINE_MAX_BYTES`]
//! and `\n` terminated; after a successful `dial` or `accept` reply the same
//! connection carries the peer's raw stream bytes both ways. Those bytes are
//! the unchanged team handshake and ChaCha20-Poly1305 frames of
//! [`super::transport`], length-prefixed exactly as over TCP, so the daemon
//! only ever sees what the team session already encrypted: no vault key,
//! DEK, plaintext secret or administrator passphrase crosses the socket.
//!
//! The daemon is not trusted for peer identity. The peer a `dial` reaches and
//! the peer an `accept` names are only routing: the team handshake decides
//! who the session is with, and an inbound peer's `zpl:` address is kept
//! only as a dial hint for the fingerprint that handshake authenticated.
//!
//! Every daemon failure maps to one fixed [`SessionClosed`] reason (see
//! [`daemon_error_reason`] and the `link_*` reasons below). Daemon text --
//! error codes outside the contract included -- is never echoed, logged or
//! returned.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::identity::DeviceKey;
use super::transport::{
    HandshakeFailedHook, InviteCheck, InviteProof, MembershipCheck, OnSession,
    SOCKET_OP_TIMEOUT_SECONDS, Session, SessionClosed, TcpTransport, Transport, socket_channel,
};
use crate::errors::{Error, Result};
use crate::pyjson::{self, DumpOptions};

/// The address scheme of a link peer: `zpl:` + its link device ID.
pub const LINK_SCHEME: &str = "zpl:";
/// The service label team streams use at the daemon (protocol §4.4).
pub const LINK_SERVICE: &str = "zeropw-team";
/// A link device ID: RFC 4648 base32 (lowercase, no padding) of 16 bytes.
pub const LINK_DEVICE_ID_LEN: usize = 26;
/// The longest daemon request or reply line, `\n` included (protocol §5).
pub const DAEMON_LINE_MAX_BYTES: usize = 8 * 1024;
/// How long the daemon may take to reach a peer (`dial`'s `timeout_ms`).
pub const DEFAULT_DIAL_TIMEOUT: Duration = Duration::from_secs(20);
/// Concurrent `accept` requests a listening transport keeps at the daemon.
pub const DEFAULT_ACCEPT_WORKERS: usize = 4;
/// Reconnect delay of an `accept` worker after a daemon failure: doubling
/// from the first value to the second, reset by a delivered stream.
pub const DEFAULT_ACCEPT_BACKOFF: (Duration, Duration) =
    (Duration::from_millis(250), Duration::from_secs(10));
/// The path labels a successful reply may carry (protocol §4).
pub const PATH_LABELS: [&str; 4] = ["direct", "relay-udp", "relay-tcp", "relay-tls"];

/// Beyond the daemon's own `timeout_ms`, how long a `dial` reply may take.
const DIAL_REPLY_MARGIN: Duration = Duration::from_secs(5);
/// How long an `accept` reply may take once its first byte arrived.
const REPLY_COMPLETION: Duration = Duration::from_secs(SOCKET_OP_TIMEOUT_SECONDS);
/// How often a blocked `accept` wakes up to notice a stop.
const ACCEPT_WAKE: Duration = Duration::from_millis(200);

/// No daemon at the socket path (missing, refused, not a socket, no
/// permission), or it hung up before replying.
pub const LINK_UNAVAILABLE: &str = "link_unavailable";
/// A reply that is not one well-formed contract line: oversized, cut off,
/// not UTF-8 or JSON, wrong types, unknown keys or an unknown path label.
pub const LINK_PROTOCOL_ERROR: &str = "link_protocol_error";
/// No complete reply within the deadline.
pub const LINK_TIMEOUT: &str = "link_timeout";
/// A `zpl:` address while no `--link-socket` is configured.
pub const LINK_SOCKET_REQUIRED: &str = "link_socket_required";
/// A `zpl:` address whose device ID is not 26 characters `[a-z2-7]`.
pub const LINK_ADDRESS_INVALID: &str = "link_address_invalid";
/// A daemon error code outside the contract.
pub const LINK_FAILED: &str = "link_failed";

/// Whether `id` is a link device ID: exactly 26 characters `[a-z2-7]`.
pub fn valid_link_device_id(id: &str) -> bool {
    id.len() == LINK_DEVICE_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}

/// Whether `address` is a well-formed link address `zpl:<device-id>`.
pub fn valid_link_address(address: &str) -> bool {
    address
        .strip_prefix(LINK_SCHEME)
        .is_some_and(valid_link_device_id)
}

/// Whether a [`LinkTransport`] routes `address` to the daemon: `zpl:`
/// followed by anything but a decimal port, so a malformed link address is
/// refused as one ([`LINK_ADDRESS_INVALID`]) while `zpl:47001` stays the
/// `HOST:PORT` of a host named `zpl`, as every `HOST:PORT` rule did before.
/// A well-formed link address is never a valid `HOST:PORT`: its 26
/// characters cannot be a port.
pub fn routes_to_link(address: &str) -> bool {
    address
        .strip_prefix(LINK_SCHEME)
        .is_some_and(|rest| rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()))
}

/// The fixed reason for a daemon error code. Codes outside the contract are
/// [`LINK_FAILED`]; the code itself is never passed on.
pub fn daemon_error_reason(code: &str) -> &'static str {
    match code {
        "not_enrolled" => "link_not_enrolled",
        "peer_unknown" => "link_peer_unknown",
        "peer_revoked" => "link_peer_revoked",
        "peer_offline" => "link_peer_offline",
        "connect_failed" => "link_connect_failed",
        "timeout" => LINK_TIMEOUT,
        "service_unavailable" => "link_service_unavailable",
        "rate_limited" => "link_rate_limited",
        "invalid_request" => "link_invalid_request",
        _ => LINK_FAILED,
    }
}

/// A stream the daemon connected: the socket now carrying the peer's raw
/// bytes, the path label it reported and, for `accept`, the peer's link
/// device ID.
pub struct LinkStream {
    pub stream: UnixStream,
    pub path: &'static str,
    pub peer: Option<String>,
}

/// A successful reply line: `{"ok":true,"path":...}` (`dial`), plus
/// `"peer"` (`accept`).
#[derive(Debug, PartialEq, Eq)]
pub struct Connected {
    pub path: &'static str,
    pub peer: Option<String>,
}

/// Parse one reply line (without its `\n`) strictly: a JSON object with a
/// boolean `ok`; on failure exactly `ok` and a string `error`, mapped by
/// [`daemon_error_reason`]; on success exactly `ok` and a known `path`, plus
/// a valid `peer` device ID when `accept` is set. Anything else is
/// [`LINK_PROTOCOL_ERROR`].
pub fn parse_reply(line: &[u8], accept: bool) -> std::result::Result<Connected, SessionClosed> {
    let protocol = SessionClosed(LINK_PROTOCOL_ERROR);
    let text = std::str::from_utf8(line).map_err(|_| protocol.clone())?;
    let value = pyjson::loads(text).map_err(|_| protocol.clone())?;
    let object = value.as_object().ok_or_else(|| protocol.clone())?;
    match object.get("ok") {
        Some(Value::Bool(false)) => {
            let code = object
                .get("error")
                .and_then(Value::as_str)
                .filter(|_| object.len() == 2)
                .ok_or_else(|| protocol.clone())?;
            Err(SessionClosed(daemon_error_reason(code)))
        }
        Some(Value::Bool(true)) => {
            if object.len() != if accept { 3 } else { 2 } {
                return Err(protocol);
            }
            let path = object
                .get("path")
                .and_then(Value::as_str)
                .and_then(|path| PATH_LABELS.iter().copied().find(|label| *label == path))
                .ok_or_else(|| protocol.clone())?;
            let peer = if accept {
                let peer = object
                    .get("peer")
                    .and_then(Value::as_str)
                    .filter(|peer| valid_link_device_id(peer))
                    .ok_or(protocol)?;
                Some(peer.to_owned())
            } else {
                None
            };
            Ok(Connected { path, peer })
        }
        _ => Err(protocol),
    }
}

/// When a reply line must have arrived.
#[derive(Clone, Copy)]
enum ReplyWait<'a> {
    /// The whole line by this instant (`dial`).
    Until(Instant),
    /// Whenever a peer arrives, polling `stop`; then the rest of the line
    /// within [`REPLY_COMPLETION`] (`accept`).
    Blocking(&'a AtomicBool),
}

/// Read one `\n`-terminated reply line of at most [`DAEMON_LINE_MAX_BYTES`]
/// (newline included), one byte at a time so none of the stream bytes that
/// may follow it at once are consumed.
fn read_reply_line(
    stream: &mut UnixStream,
    wait: ReplyWait<'_>,
) -> std::result::Result<Vec<u8>, SessionClosed> {
    let mut line = Vec::new();
    let mut deadline = match wait {
        ReplyWait::Until(at) => Some(at),
        ReplyWait::Blocking(_) => None,
    };
    loop {
        let slice = match deadline {
            Some(at) => at
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(SessionClosed(LINK_TIMEOUT))?
                .min(ACCEPT_WAKE),
            None => ACCEPT_WAKE,
        };
        if let ReplyWait::Blocking(stop) = wait
            && stop.load(Ordering::SeqCst)
        {
            return Err(SessionClosed(LINK_UNAVAILABLE));
        }
        stream
            .set_read_timeout(Some(slice))
            .map_err(|_| SessionClosed(LINK_UNAVAILABLE))?;
        let mut byte = [0u8; 1];
        match stream.read(&mut byte) {
            Ok(0) if line.is_empty() => return Err(SessionClosed(LINK_UNAVAILABLE)),
            Ok(0) => return Err(SessionClosed(LINK_PROTOCOL_ERROR)),
            Ok(_) if byte[0] == b'\n' => return Ok(line),
            Ok(_) => {
                if line.is_empty() && deadline.is_none() {
                    deadline = Some(Instant::now() + REPLY_COMPLETION);
                }
                line.push(byte[0]);
                if line.len() >= DAEMON_LINE_MAX_BYTES {
                    return Err(SessionClosed(LINK_PROTOCOL_ERROR));
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(_) if line.is_empty() => return Err(SessionClosed(LINK_UNAVAILABLE)),
            Err(_) => return Err(SessionClosed(LINK_PROTOCOL_ERROR)),
        }
    }
}

/// A client of one daemon socket.
#[derive(Clone, Debug)]
pub struct LinkClient {
    socket: PathBuf,
}

impl LinkClient {
    /// A client of the daemon socket at `socket`, which must be an absolute
    /// path (`invalid_link_socket` otherwise). Nothing is connected yet.
    pub fn new(socket: impl Into<PathBuf>) -> Result<Self> {
        let socket = socket.into();
        if !socket.is_absolute() {
            return Err(Error::invalid_input("invalid_link_socket")
                .with_detail("use the absolute path of the zeropw-link daemon socket"));
        }
        Ok(Self { socket })
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    fn connect(&self) -> std::result::Result<UnixStream, SessionClosed> {
        UnixStream::connect(&self.socket).map_err(|_| SessionClosed(LINK_UNAVAILABLE))
    }

    fn send_request(
        stream: &mut UnixStream,
        request: &Value,
    ) -> std::result::Result<(), SessionClosed> {
        let mut line = pyjson::dumps(request, DumpOptions::compact_sorted())
            .map_err(|_| SessionClosed("link_invalid_request"))?;
        line.push('\n');
        if line.len() > DAEMON_LINE_MAX_BYTES {
            return Err(SessionClosed("link_invalid_request"));
        }
        stream
            .set_write_timeout(Some(Duration::from_secs(SOCKET_OP_TIMEOUT_SECONDS)))
            .and_then(|_| stream.write_all(line.as_bytes()))
            .map_err(|_| SessionClosed(LINK_UNAVAILABLE))
    }

    /// `{"op":"dial","peer":ID,"svc":"zeropw-team","timeout_ms":N}`: a
    /// stream to link device `peer`, whose reply must arrive within
    /// `timeout` plus a margin.
    pub fn dial(
        &self,
        peer: &str,
        timeout: Duration,
    ) -> std::result::Result<LinkStream, SessionClosed> {
        if !valid_link_device_id(peer) {
            return Err(SessionClosed(LINK_ADDRESS_INVALID));
        }
        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        let mut stream = self.connect()?;
        Self::send_request(
            &mut stream,
            &json!({"op":"dial","peer":peer,"svc":LINK_SERVICE,"timeout_ms":timeout_ms}),
        )?;
        let deadline = Instant::now() + timeout.saturating_add(DIAL_REPLY_MARGIN);
        let line = read_reply_line(&mut stream, ReplyWait::Until(deadline))?;
        let Connected { path, peer } = parse_reply(&line, false)?;
        Ok(LinkStream { stream, path, peer })
    }

    /// `{"op":"accept","svc":"zeropw-team"}`: block until the daemon
    /// delivers an inbound stream, or `stop` is set. `connected` sees the
    /// request's socket first, so a closing transport can shut it down.
    pub fn accept(
        &self,
        stop: &AtomicBool,
        connected: impl FnOnce(&UnixStream),
    ) -> std::result::Result<LinkStream, SessionClosed> {
        let mut stream = self.connect()?;
        connected(&stream);
        Self::send_request(&mut stream, &json!({"op":"accept","svc":LINK_SERVICE}))?;
        let line = read_reply_line(&mut stream, ReplyWait::Blocking(stop))?;
        let Connected { path, peer } = parse_reply(&line, true)?;
        Ok(LinkStream { stream, path, peer })
    }
}

/// Tunables of a [`LinkTransport`]; tests shorten them.
#[derive(Clone, Debug)]
pub struct LinkConfig {
    pub accept_workers: usize,
    pub accept_backoff: (Duration, Duration),
    pub dial_timeout: Duration,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            accept_workers: DEFAULT_ACCEPT_WORKERS,
            accept_backoff: DEFAULT_ACCEPT_BACKOFF,
            dial_timeout: DEFAULT_DIAL_TIMEOUT,
        }
    }
}

/// What the `accept` workers of one listening transport share.
struct AcceptShared {
    stop: AtomicBool,
    /// Sockets of requests still waiting for a reply, shut down on close.
    waiting: Mutex<HashMap<u64, UnixStream>>,
    next_id: AtomicU64,
}

/// A [`Transport`] that routes `zpl:` addresses through the link daemon and
/// everything else through [`TcpTransport`], whose device, membership,
/// invitation and failure hooks and inbound connection cap both share.
///
/// `listen(address)` keeps TCP listening on `address` when it is not empty
/// and, with a daemon socket, also keeps [`LinkConfig::accept_workers`]
/// `accept` requests at the daemon, reconnecting with backoff when it is
/// absent or restarts. An empty `address` therefore listens on the link
/// only. Without a daemon socket, `zpl:` dials fail with
/// [`LINK_SOCKET_REQUIRED`] and `HOST:PORT` behaves exactly as over TCP.
pub struct LinkTransport {
    tcp: Arc<TcpTransport>,
    client: Option<LinkClient>,
    config: LinkConfig,
    shared: Arc<AcceptShared>,
    workers: Mutex<Vec<thread::JoinHandle<()>>>,
}

impl LinkTransport {
    pub fn new(
        device: DeviceKey,
        membership: MembershipCheck,
        max_connections: usize,
        socket: Option<PathBuf>,
    ) -> Result<Self> {
        Self::with_config(
            device,
            membership,
            max_connections,
            socket,
            LinkConfig::default(),
        )
    }

    pub fn with_config(
        device: DeviceKey,
        membership: MembershipCheck,
        max_connections: usize,
        socket: Option<PathBuf>,
        config: LinkConfig,
    ) -> Result<Self> {
        let client = socket.map(LinkClient::new).transpose()?;
        Ok(Self {
            tcp: TcpTransport::new(device, membership, max_connections),
            client,
            config,
            shared: Arc::new(AcceptShared {
                stop: AtomicBool::new(false),
                waiting: Mutex::new(HashMap::new()),
                next_id: AtomicU64::new(0),
            }),
            workers: Mutex::new(Vec::new()),
        })
    }

    /// The TCP side, for its bound listening address.
    pub fn tcp(&self) -> &Arc<TcpTransport> {
        &self.tcp
    }

    pub fn link_socket(&self) -> Option<&Path> {
        self.client.as_ref().map(LinkClient::socket)
    }

    fn dial_link(
        &self,
        address: &str,
        env_id: &str,
        invite_proof: Option<InviteProof>,
    ) -> std::result::Result<Arc<dyn Session>, SessionClosed> {
        let peer = address
            .strip_prefix(LINK_SCHEME)
            .filter(|id| valid_link_device_id(id))
            .ok_or(SessionClosed(LINK_ADDRESS_INVALID))?;
        let client = self
            .client
            .as_ref()
            .ok_or(SessionClosed(LINK_SOCKET_REQUIRED))?;
        let link = client.dial(peer, self.config.dial_timeout)?;
        let channel = socket_channel(link.stream).map_err(|_| SessionClosed(LINK_UNAVAILABLE))?;
        self.tcp
            .initiate_over(channel, env_id, invite_proof, Some(address.to_owned()))
    }

    /// Stop the `accept` workers (waiting requests are shut down, so none
    /// outlives this) and the TCP listener. Sessions already handed out stay
    /// open until their owner closes them.
    pub fn shutdown(&self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        for stream in self
            .shared
            .waiting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain()
            .map(|(_, stream)| stream)
        {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        let workers: Vec<_> = self
            .workers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .collect();
        for worker in workers {
            let _ = worker.join();
        }
        self.tcp.shutdown();
    }
}

/// Sleep `delay`, waking early when `stop` is set.
fn pause(stop: &AtomicBool, delay: Duration) {
    let until = Instant::now() + delay;
    while !stop.load(Ordering::SeqCst) {
        let Some(left) = until.checked_duration_since(Instant::now()) else {
            return;
        };
        thread::sleep(left.min(Duration::from_millis(50)));
    }
}

/// One `accept` worker: keep a request waiting at the daemon, hand each
/// delivered stream to the responder handshake under the shared connection
/// cap, and back off while the daemon is absent or failing.
fn accept_loop(
    client: LinkClient,
    tcp: Arc<TcpTransport>,
    shared: Arc<AcceptShared>,
    on_session: OnSession,
    backoff: (Duration, Duration),
) {
    let mut delay = backoff.0;
    while !shared.stop.load(Ordering::SeqCst) {
        let id = shared.next_id.fetch_add(1, Ordering::SeqCst);
        let accepted = client.accept(&shared.stop, |stream| {
            if let Ok(clone) = stream.try_clone() {
                shared
                    .waiting
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(id, clone);
            }
        });
        shared
            .waiting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
        match accepted {
            Ok(LinkStream {
                stream,
                peer: Some(peer),
                ..
            }) if !shared.stop.load(Ordering::SeqCst) => {
                delay = backoff.0;
                if !tcp.reserve_inbound() {
                    drop(stream);
                    continue;
                }
                let Ok(channel) = socket_channel(stream) else {
                    tcp.release_inbound();
                    continue;
                };
                let tcp = tcp.clone();
                let callback = on_session.clone();
                thread::spawn(move || {
                    tcp.respond_reserved(channel, &callback, Some(format!("{LINK_SCHEME}{peer}")));
                });
            }
            Ok(_) => {}
            Err(_) => {
                pause(&shared.stop, delay);
                delay = delay.saturating_mul(2).min(backoff.1);
            }
        }
    }
}

impl Transport for LinkTransport {
    fn set_membership(&self, cb: MembershipCheck) {
        self.tcp.set_membership(cb);
    }
    fn set_invite_check(&self, cb: Option<InviteCheck>) {
        self.tcp.set_invite_check(cb);
    }
    fn set_handshake_failed(&self, cb: Option<HandshakeFailedHook>) {
        self.tcp.set_handshake_failed(cb);
    }
    fn listen(&self, address: &str, on_session: OnSession) -> Result<()> {
        let mut workers = self.workers.lock().unwrap_or_else(|e| e.into_inner());
        if !workers.is_empty() {
            return Err(Error::invalid_input("team_already_listening"));
        }
        if address.is_empty() && self.client.is_none() {
            return Err(Error::invalid_input(LINK_SOCKET_REQUIRED));
        }
        if !address.is_empty() {
            self.tcp.listen_arc(address, on_session.clone())?;
        }
        if let Some(client) = &self.client {
            self.shared.stop.store(false, Ordering::SeqCst);
            for _ in 0..self.config.accept_workers.max(1) {
                let (client, tcp, shared, callback, backoff) = (
                    client.clone(),
                    self.tcp.clone(),
                    self.shared.clone(),
                    on_session.clone(),
                    self.config.accept_backoff,
                );
                workers.push(thread::spawn(move || {
                    accept_loop(client, tcp, shared, callback, backoff);
                }));
            }
        }
        Ok(())
    }
    fn dial(
        &self,
        address: &str,
        env_id: &str,
        invite_proof: Option<InviteProof>,
    ) -> std::result::Result<Arc<dyn Session>, SessionClosed> {
        if routes_to_link(address) {
            self.dial_link(address, env_id, invite_proof)
        } else {
            self.tcp.dial_session(address, env_id, invite_proof)
        }
    }
    fn close(&self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    const ID: &str = "abcdefghijklmnopqrstuvwxyz";

    #[test]
    fn link_addresses_are_zpl_and_26_base32_characters() {
        assert!(valid_link_address(&format!("zpl:{ID}")));
        assert!(valid_link_address("zpl:22222222223333333333777777"));
        for bad in [
            "zpl:",
            "zpl:abcdefghijklmnopqrstuvwxy",
            "zpl:abcdefghijklmnopqrstuvwxyza",
            "zpl:ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "zpl:abcdefghijklmnopqrstuvwxy0",
            "zpl:abcdefghijklmnopqrstuvwxy1",
            "zpl:abcdefghijklmnopqrstuvwxy8",
            "zpl:abcdefghijklmnopqrstuvwxy=",
            "ZPL:abcdefghijklmnopqrstuvwxyz",
            " zpl:abcdefghijklmnopqrstuvwxyz",
            "zpl:abcdefghijklmnopqrstuvwxyz ",
            "zpl:abcdefghijklmnopqrstuvwxyz:1",
            "zpl://abcdefghijklmnopqrstuvwxyz",
            "zpl:abcdefghijklmnopqrstuvwxy\u{e9}",
            "abcdefghijklmnopqrstuvwxyz",
        ] {
            assert!(!valid_link_address(bad), "{bad:?}");
        }
        for routed in [
            "zpl:",
            "zpl:bad",
            "zpl:abcdefghijklmnopqrstuvwxyz",
            "zpl:1a",
        ] {
            assert!(routes_to_link(routed), "{routed:?}");
        }
        for tcp in [
            "zpl:47001",
            "127.0.0.1:47001",
            "ZPL:abc",
            "node-zpl:1",
            "[::1]:1",
        ] {
            assert!(!routes_to_link(tcp), "{tcp:?}");
        }
    }

    #[test]
    fn replies_parse_strictly() {
        let ok_dial = |line: &str| parse_reply(line.as_bytes(), false);
        let ok_accept = |line: &str| parse_reply(line.as_bytes(), true);
        for label in PATH_LABELS {
            assert_eq!(
                ok_dial(&format!(r#"{{"ok":true,"path":"{label}"}}"#)),
                Ok(Connected {
                    path: label,
                    peer: None
                })
            );
        }
        assert_eq!(
            ok_accept(&format!(
                r#"{{"path":"relay-tls","peer":"{ID}","ok":true}}"#
            )),
            Ok(Connected {
                path: "relay-tls",
                peer: Some(ID.into())
            })
        );
        let protocol = Err(SessionClosed(LINK_PROTOCOL_ERROR));
        for line in [
            "",
            "not json",
            "[]",
            "null",
            "\"ok\"",
            "{}",
            r#"{"ok":"true","path":"direct"}"#,
            r#"{"ok":1,"path":"direct"}"#,
            r#"{"ok":true}"#,
            r#"{"ok":true,"path":"warp"}"#,
            r#"{"ok":true,"path":"Direct"}"#,
            r#"{"ok":true,"path":5}"#,
            r#"{"ok":true,"path":"direct","extra":1}"#,
            r#"{"ok":true,"path":"direct","peer":"abcdefghijklmnopqrstuvwxyz"}"#,
            r#"{"ok":false}"#,
            r#"{"ok":false,"error":5}"#,
            r#"{"ok":false,"error":null}"#,
            r#"{"ok":false,"error":"timeout","detail":"x"}"#,
            r#"{"ok":true,"path":"direct"} trailing"#,
            r#"{"ok":NaN,"path":"direct"}"#,
        ] {
            assert_eq!(ok_dial(line), protocol, "dial {line:?}");
        }
        for line in [
            r#"{"ok":true,"path":"direct"}"#,
            r#"{"ok":true,"path":"direct","peer":"short"}"#,
            r#"{"ok":true,"path":"direct","peer":"ABCDEFGHIJKLMNOPQRSTUVWXYZ"}"#,
            r#"{"ok":true,"path":"direct","peer":5}"#,
            r#"{"ok":true,"path":"direct","peer":"abcdefghijklmnopqrstuvwxyz","x":0}"#,
        ] {
            assert_eq!(ok_accept(line), protocol, "accept {line:?}");
        }
        assert_eq!(
            parse_reply(b"{\"ok\":true,\"path\":\"dir\xffect\"}", false),
            protocol
        );
    }

    #[test]
    fn daemon_errors_map_to_fixed_reasons_and_never_echo() {
        for (code, reason) in [
            ("not_enrolled", "link_not_enrolled"),
            ("peer_unknown", "link_peer_unknown"),
            ("peer_revoked", "link_peer_revoked"),
            ("peer_offline", "link_peer_offline"),
            ("connect_failed", "link_connect_failed"),
            ("timeout", "link_timeout"),
            ("service_unavailable", "link_service_unavailable"),
            ("rate_limited", "link_rate_limited"),
            ("invalid_request", "link_invalid_request"),
            ("synthetic-invite-ZPL-AAAA", "link_failed"),
            ("", "link_failed"),
        ] {
            let line = format!(r#"{{"ok":false,"error":"{code}"}}"#);
            assert_eq!(
                parse_reply(line.as_bytes(), false),
                Err(SessionClosed(reason))
            );
            assert_eq!(
                parse_reply(line.as_bytes(), true),
                Err(SessionClosed(reason))
            );
        }
    }

    #[test]
    fn a_reply_line_leaves_the_stream_bytes_after_it() {
        let (mut client, mut daemon) = UnixStream::pair().unwrap();
        daemon
            .write_all(b"{\"ok\":true,\"path\":\"direct\"}\n\x00\x00\x00\x03abc")
            .unwrap();
        let line = read_reply_line(
            &mut client,
            ReplyWait::Until(Instant::now() + Duration::from_secs(2)),
        )
        .unwrap();
        assert_eq!(line, b"{\"ok\":true,\"path\":\"direct\"}");
        let mut rest = [0u8; 7];
        client.read_exact(&mut rest).unwrap();
        assert_eq!(&rest, b"\x00\x00\x00\x03abc");
    }

    #[test]
    fn reply_lines_are_bounded_complete_and_timely() {
        let read = |bytes: &[u8], close: bool, wait: Duration| {
            let (mut client, mut daemon) = UnixStream::pair().unwrap();
            daemon.write_all(bytes).unwrap();
            if close {
                drop(daemon);
                read_reply_line(&mut client, ReplyWait::Until(Instant::now() + wait))
            } else {
                let result = read_reply_line(&mut client, ReplyWait::Until(Instant::now() + wait));
                drop(daemon);
                result
            }
        };
        let short = Duration::from_millis(300);
        let longest = vec![b'x'; DAEMON_LINE_MAX_BYTES - 1];
        let mut fits = longest.clone();
        fits.push(b'\n');
        assert_eq!(read(&fits, true, short), Ok(longest));
        let mut over = vec![b'x'; DAEMON_LINE_MAX_BYTES];
        over.push(b'\n');
        assert_eq!(
            read(&over, true, short),
            Err(SessionClosed(LINK_PROTOCOL_ERROR))
        );
        assert_eq!(
            read(b"{\"ok\":tr", true, short),
            Err(SessionClosed(LINK_PROTOCOL_ERROR))
        );
        assert_eq!(read(b"", true, short), Err(SessionClosed(LINK_UNAVAILABLE)));
        let started = Instant::now();
        assert_eq!(
            read(b"{\"ok\":tr", false, short),
            Err(SessionClosed(LINK_TIMEOUT))
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(read(b"", false, short), Err(SessionClosed(LINK_TIMEOUT)));
    }

    #[test]
    fn a_blocked_accept_ends_when_stopped() {
        let (mut client, _daemon) = UnixStream::pair().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let reader =
            thread::spawn(move || read_reply_line(&mut client, ReplyWait::Blocking(&flag)));
        thread::sleep(Duration::from_millis(300));
        assert!(!reader.is_finished());
        stop.store(true, Ordering::SeqCst);
        let started = Instant::now();
        assert_eq!(reader.join().unwrap(), Err(SessionClosed(LINK_UNAVAILABLE)));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn the_client_sends_one_contract_request_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("link.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let daemon = thread::spawn(move || {
            let mut lines = Vec::new();
            for reply in [
                "{\"ok\":true,\"path\":\"relay-udp\"}\n".to_owned(),
                format!("{{\"ok\":true,\"path\":\"direct\",\"peer\":\"{ID}\"}}\n"),
            ] {
                let (mut conn, _) = listener.accept().unwrap();
                let mut line = Vec::new();
                let mut byte = [0u8; 1];
                while conn.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' {
                    line.push(byte[0]);
                }
                lines.push(String::from_utf8(line).unwrap());
                conn.write_all(reply.as_bytes()).unwrap();
            }
            lines
        });
        let client = LinkClient::new(&path).unwrap();
        let dialed = client.dial(ID, Duration::from_millis(1500)).unwrap();
        assert_eq!((dialed.path, dialed.peer), ("relay-udp", None));
        let stop = AtomicBool::new(false);
        let accepted = client.accept(&stop, |_| {}).unwrap();
        assert_eq!((accepted.path, accepted.peer), ("direct", Some(ID.into())));
        assert_eq!(
            daemon.join().unwrap(),
            [
                format!(
                    "{{\"op\":\"dial\",\"peer\":\"{ID}\",\"svc\":\"zeropw-team\",\"timeout_ms\":1500}}"
                ),
                "{\"op\":\"accept\",\"svc\":\"zeropw-team\"}".to_owned(),
            ]
        );
    }

    #[test]
    fn a_missing_or_relative_socket_fails_closed() {
        assert_eq!(
            LinkClient::new("relative/link.sock").unwrap_err().reason,
            "invalid_link_socket"
        );
        assert_eq!(
            LinkClient::new("").unwrap_err().reason,
            "invalid_link_socket"
        );
        let dir = tempfile::tempdir().unwrap();
        let client = LinkClient::new(dir.path().join("absent.sock")).unwrap();
        assert_eq!(
            client.dial(ID, Duration::from_millis(200)).err(),
            Some(SessionClosed(LINK_UNAVAILABLE))
        );
        assert_eq!(
            client.dial("not-an-id", Duration::from_millis(200)).err(),
            Some(SessionClosed(LINK_ADDRESS_INVALID))
        );
        // A path that exists but is no socket.
        let file = dir.path().join("file");
        std::fs::write(&file, b"").unwrap();
        assert_eq!(
            LinkClient::new(&file)
                .unwrap()
                .dial(ID, Duration::from_millis(200))
                .err(),
            Some(SessionClosed(LINK_UNAVAILABLE))
        );
    }
}
