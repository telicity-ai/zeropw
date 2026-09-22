//! Authenticated team transport, port of `zeropw/team/transport.py`.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use rand::RngCore;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::commit::valid_env_id;
use super::envelope::hkdf;
use super::identity::{DeviceKey, DeviceRecord};
use crate::crypto::{chacha20poly1305 as aead, ed25519, x25519};
use crate::errors::{Error, Result};
use crate::pybase64;
use crate::pyjson::{self, DumpOptions};
use crate::secret::SecretBytes;

pub const PROTOCOL_VERSION: i64 = 1;
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
pub const SOCKET_OP_TIMEOUT_SECONDS: u64 = 15;
pub const HANDSHAKE_TIMEOUT_SECONDS: u64 = 15;
pub const DEFAULT_MAX_CONNECTIONS: usize = 64;
pub const SESSION_INFO: &[u8] = b"zeropw-team-session-v1";
pub const HANDSHAKE_RESPONDER_CONTEXT: &[u8] = b"zeropw-team-hs-responder-v1";
pub const HANDSHAKE_INITIATOR_CONTEXT: &[u8] = b"zeropw-team-hs-initiator-v1";
const WIRE_FRAME_LIMIT: usize = MAX_FRAME_BYTES + aead::TAG_SIZE + 4096;

pub type MembershipCheck = Arc<dyn Fn(&str, &str) -> Option<DeviceRecord> + Send + Sync>;
pub type InviteCheck = Arc<dyn Fn(&str, &DeviceRecord, &[u8], &[u8]) -> bool + Send + Sync>;
pub type HandshakeFailedHook = Arc<dyn Fn(&str, Option<&str>) + Send + Sync>;
pub type OnSession = Arc<dyn Fn(Arc<dyn Session>) + Send + Sync>;
pub type InviteProof = Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionClosed(pub &'static str);

#[derive(Debug, Clone)]
struct HandshakeFailed {
    reason: &'static str,
    fingerprint: Option<String>,
}
impl HandshakeFailed {
    fn new(reason: &'static str) -> Self {
        Self {
            reason,
            fingerprint: None,
        }
    }
    fn with_fp(reason: &'static str, fp: String) -> Self {
        Self {
            reason,
            fingerprint: Some(fp),
        }
    }
}

pub trait Session: Send + Sync {
    fn peer(&self) -> DeviceRecord;
    fn env_id(&self) -> &str;
    fn send(&self, message: &Value) -> Result<()>;
    fn recv(&self, timeout: Duration) -> std::result::Result<Option<Value>, SessionClosed>;
    fn close(&self);
    fn is_closed(&self) -> bool;
}

pub trait Transport: Send + Sync {
    fn listen(&self, address: &str, on_session: OnSession) -> Result<()>;
    fn dial(
        &self,
        address: &str,
        env_id: &str,
        invite_proof: Option<InviteProof>,
    ) -> std::result::Result<Arc<dyn Session>, SessionClosed>;
    fn close(&self);
}

fn canon(value: &Value) -> std::result::Result<Vec<u8>, HandshakeFailed> {
    pyjson::dumps(value, DumpOptions::compact_sorted())
        .map(|s| s.into_bytes())
        .map_err(|_| HandshakeFailed::new("handshake_malformed"))
}
fn b64d(value: Option<&Value>) -> std::result::Result<Vec<u8>, HandshakeFailed> {
    let s = value
        .and_then(Value::as_str)
        .ok_or_else(|| HandshakeFailed::new("handshake_malformed"))?;
    // Handshake uses `validate=True`, unlike general lenient pybase64 decoding.
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| HandshakeFailed::new("handshake_malformed"))
}
fn b64e(raw: &[u8]) -> String {
    pybase64::b64encode(raw)
}
fn parse_record(value: Option<&Value>) -> std::result::Result<DeviceRecord, HandshakeFailed> {
    let record = DeviceRecord::from_dict(value.unwrap_or(&Value::Null))
        .map_err(|_| HandshakeFailed::new("device_record_malformed"))?;
    if !record.verify() {
        return Err(HandshakeFailed::new("device_record_invalid"));
    }
    Ok(record)
}

trait ByteChannel: Send + Sync {
    fn send(&self, bytes: &[u8]) -> std::result::Result<(), SessionClosed>;
    fn recv(&self, timeout: Duration) -> std::result::Result<Option<Vec<u8>>, SessionClosed>;
    fn close(&self);
}

struct EncryptedSession {
    channel: Arc<dyn ByteChannel>,
    peer: DeviceRecord,
    env_id: String,
    send_key: SecretBytes,
    recv_key: SecretBytes,
    tag_out: [u8; 4],
    tag_in: [u8; 4],
    send_count: Mutex<u64>,
    recv_count: Mutex<u64>,
    closed: AtomicBool,
    on_close: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
impl EncryptedSession {
    fn new(
        channel: Arc<dyn ByteChannel>,
        peer: DeviceRecord,
        env_id: String,
        send_key: Vec<u8>,
        recv_key: Vec<u8>,
        tag_out: [u8; 4],
        tag_in: [u8; 4],
    ) -> Self {
        Self {
            channel,
            peer,
            env_id,
            send_key: SecretBytes::new(send_key),
            recv_key: SecretBytes::new(recv_key),
            tag_out,
            tag_in,
            send_count: Mutex::new(0),
            recv_count: Mutex::new(0),
            closed: AtomicBool::new(false),
            on_close: Mutex::new(None),
        }
    }
    fn set_on_close(&self, callback: Box<dyn FnOnce() + Send>) {
        *self.on_close.lock().unwrap_or_else(|e| e.into_inner()) = Some(callback);
    }
}
impl Session for EncryptedSession {
    fn peer(&self) -> DeviceRecord {
        self.peer.clone()
    }
    fn env_id(&self) -> &str {
        &self.env_id
    }
    fn send(&self, message: &Value) -> Result<()> {
        if !message.is_object() {
            return Err(Error::invalid_input("team_message_malformed"));
        }
        let payload = pyjson::dumps(message, DumpOptions::compact_sorted())
            .map_err(|_| Error::invalid_input("team_message_malformed"))?
            .into_bytes();
        if payload.len() > MAX_FRAME_BYTES {
            return Err(Error::invalid_input("team_frame_too_large"));
        }
        let mut count = self.send_count.lock().unwrap_or_else(|e| e.into_inner());
        if self.is_closed() {
            return Err(Error::state("session_closed"));
        }
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.tag_out);
        nonce[4..].copy_from_slice(&count.to_be_bytes());
        *count = count
            .checked_add(1)
            .ok_or_else(|| Error::state("session_closed"))?;
        let ciphertext = aead::encrypt(self.send_key.expose(), &nonce, &payload, b"")
            .map_err(|_| Error::state("send_failed"))?;
        self.channel.send(&ciphertext).map_err(|e| {
            self.close();
            Error::state(e.0)
        })
    }
    fn recv(&self, timeout: Duration) -> std::result::Result<Option<Value>, SessionClosed> {
        if self.is_closed() {
            return Err(SessionClosed("session_closed"));
        }
        let raw = match self.channel.recv(timeout) {
            Ok(None) => return Ok(None),
            Ok(Some(v)) => v,
            Err(e) => {
                self.close();
                return Err(e);
            }
        };
        let mut count = self.recv_count.lock().unwrap_or_else(|e| e.into_inner());
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.tag_in);
        nonce[4..].copy_from_slice(&count.to_be_bytes());
        let plaintext = aead::decrypt(self.recv_key.expose(), &nonce, &raw, b"").map_err(|_| {
            self.close();
            SessionClosed("frame_authentication_failed")
        })?;
        *count = count
            .checked_add(1)
            .ok_or(SessionClosed("session_closed"))?;
        let message: Value = serde_json::from_slice(&plaintext).map_err(|_| {
            self.close();
            SessionClosed("frame_malformed")
        })?;
        if !message.is_object() {
            self.close();
            return Err(SessionClosed("frame_malformed"));
        }
        Ok(Some(message))
    }
    fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.channel.close();
        if let Some(callback) = self
            .on_close
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            callback();
        }
    }
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

enum QueueItem {
    Data(Vec<u8>),
    Closed,
}
struct QueueChannel {
    inbox: Mutex<mpsc::Receiver<QueueItem>>,
    outbox: mpsc::Sender<QueueItem>,
    closed: AtomicBool,
}
impl ByteChannel for QueueChannel {
    fn send(&self, bytes: &[u8]) -> std::result::Result<(), SessionClosed> {
        if bytes.len() > WIRE_FRAME_LIMIT {
            return Err(SessionClosed("frame_too_large"));
        }
        if self.closed.load(Ordering::SeqCst) {
            return Err(SessionClosed("channel_closed"));
        }
        self.outbox
            .send(QueueItem::Data(bytes.to_vec()))
            .map_err(|_| SessionClosed("channel_closed"))
    }
    fn recv(&self, timeout: Duration) -> std::result::Result<Option<Vec<u8>>, SessionClosed> {
        match self
            .inbox
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .recv_timeout(timeout)
        {
            Ok(QueueItem::Data(data)) if data.len() <= WIRE_FRAME_LIMIT => Ok(Some(data)),
            Ok(QueueItem::Data(_)) => {
                self.close();
                Err(SessionClosed("frame_too_large"))
            }
            Ok(QueueItem::Closed) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.close();
                Err(SessionClosed("peer_closed"))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
        }
    }
    fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let _ = self.outbox.send(QueueItem::Closed);
        }
    }
}
fn queue_pair() -> (Arc<dyn ByteChannel>, Arc<dyn ByteChannel>) {
    let (a_tx, a_rx) = mpsc::channel();
    let (b_tx, b_rx) = mpsc::channel();
    (
        Arc::new(QueueChannel {
            inbox: Mutex::new(a_rx),
            outbox: b_tx,
            closed: AtomicBool::new(false),
        }),
        Arc::new(QueueChannel {
            inbox: Mutex::new(b_rx),
            outbox: a_tx,
            closed: AtomicBool::new(false),
        }),
    )
}

struct SocketChannel {
    reader: Mutex<TcpStream>,
    writer: Mutex<TcpStream>,
    shutdown: TcpStream,
    closed: AtomicBool,
}
impl SocketChannel {
    fn new(stream: TcpStream) -> std::io::Result<Self> {
        let _ = stream.set_nodelay(true);
        Ok(Self {
            reader: Mutex::new(stream.try_clone()?),
            writer: Mutex::new(stream.try_clone()?),
            shutdown: stream,
            closed: AtomicBool::new(false),
        })
    }
}
impl ByteChannel for SocketChannel {
    fn send(&self, bytes: &[u8]) -> std::result::Result<(), SessionClosed> {
        if bytes.len() > WIRE_FRAME_LIMIT {
            return Err(SessionClosed("frame_too_large"));
        }
        if self.closed.load(Ordering::SeqCst) {
            return Err(SessionClosed("channel_closed"));
        }
        let mut stream = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        stream
            .set_write_timeout(Some(Duration::from_secs(SOCKET_OP_TIMEOUT_SECONDS)))
            .and_then(|_| stream.write_all(&(bytes.len() as u32).to_be_bytes()))
            .and_then(|_| stream.write_all(bytes))
            .map_err(|_| {
                self.close();
                SessionClosed("send_failed")
            })
    }
    fn recv(&self, timeout: Duration) -> std::result::Result<Option<Vec<u8>>, SessionClosed> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SessionClosed("channel_closed"));
        }
        let mut stream = self.reader.lock().unwrap_or_else(|e| e.into_inner());
        stream
            .set_read_timeout(Some(timeout.max(Duration::from_millis(1))))
            .map_err(|_| SessionClosed("recv_failed"))?;
        let mut header = [0u8; 4];
        match stream.read_exact(&mut header) {
            Ok(()) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Ok(None);
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(SessionClosed("peer_closed"));
            }
            Err(_) => return Err(SessionClosed("recv_failed")),
        }
        let length = u32::from_be_bytes(header) as usize;
        if length > WIRE_FRAME_LIMIT {
            return Err(SessionClosed("frame_too_large"));
        }
        stream
            .set_read_timeout(Some(Duration::from_secs(SOCKET_OP_TIMEOUT_SECONDS)))
            .map_err(|_| SessionClosed("recv_failed"))?;
        let mut payload = vec![0; length];
        stream.read_exact(&mut payload).map_err(|e| {
            if matches!(
                e.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) {
                SessionClosed("frame_incomplete")
            } else if e.kind() == std::io::ErrorKind::UnexpectedEof {
                SessionClosed("peer_closed")
            } else {
                SessionClosed("recv_failed")
            }
        })?;
        Ok(Some(payload))
    }
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let _ = self.shutdown.shutdown(Shutdown::Both);
    }
}

fn recv_plain(
    channel: &dyn ByteChannel,
    deadline: Instant,
) -> std::result::Result<(Vec<u8>, Value), HandshakeFailed> {
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| HandshakeFailed::new("handshake_timeout"))?;
    let raw = channel
        .recv(timeout)
        .map_err(|_| HandshakeFailed::new("handshake_channel_closed"))?
        .ok_or_else(|| HandshakeFailed::new("handshake_timeout"))?;
    let value: Value =
        serde_json::from_slice(&raw).map_err(|_| HandshakeFailed::new("handshake_malformed"))?;
    if !value.is_object() {
        return Err(HandshakeFailed::new("handshake_malformed"));
    }
    Ok((raw, value))
}
fn transcript(
    msg1: &[u8],
    eb_pub: &[u8],
    responder: &DeviceRecord,
) -> std::result::Result<Vec<u8>, HandshakeFailed> {
    let mut t = msg1.to_vec();
    t.extend_from_slice(eb_pub);
    t.extend_from_slice(&canon(&responder.to_dict())?);
    Ok(t)
}
fn keys(shared: &[u8], hash: &[u8]) -> std::result::Result<(Vec<u8>, Vec<u8>), HandshakeFailed> {
    let mut info = SESSION_INFO.to_vec();
    info.extend_from_slice(b"i2r");
    let i2r = hkdf(hash, shared, &info, aead::KEY_SIZE)
        .map_err(|_| HandshakeFailed::new("handshake_malformed"))?;
    info.truncate(SESSION_INFO.len());
    info.extend_from_slice(b"r2i");
    let r2i = hkdf(hash, shared, &info, aead::KEY_SIZE)
        .map_err(|_| HandshakeFailed::new("handshake_malformed"))?;
    Ok((i2r, r2i))
}
fn respond(
    channel: Arc<dyn ByteChannel>,
    device: &DeviceKey,
    membership: &MembershipCheck,
    invite: Option<&InviteCheck>,
) -> std::result::Result<Arc<EncryptedSession>, HandshakeFailed> {
    let deadline = Instant::now() + Duration::from_secs(HANDSHAKE_TIMEOUT_SECONDS);
    let (msg1_raw, msg1) = recv_plain(channel.as_ref(), deadline)?;
    if msg1.get("version").and_then(Value::as_i64) != Some(PROTOCOL_VERSION) {
        return Err(HandshakeFailed::new("version_mismatch"));
    }
    let env_id = msg1
        .get("env_id")
        .and_then(Value::as_str)
        .ok_or_else(|| HandshakeFailed::new("invalid_env_id"))?;
    if !valid_env_id(env_id) {
        return Err(HandshakeFailed::new("invalid_env_id"));
    }
    let ea = b64d(msg1.get("ea"))?;
    let nonce = b64d(msg1.get("nonce"))?;
    if ea.len() != 32 || nonce.len() != 32 {
        return Err(HandshakeFailed::new("handshake_malformed"));
    }
    let initiator = parse_record(msg1.get("device"))?;
    let fp = initiator.fingerprint();
    let member = membership(env_id, &fp);
    if member.is_none() && invite.is_none() {
        return Err(HandshakeFailed::with_fp("not_member", fp));
    }
    let eb_priv = x25519::generate_private();
    let eb = x25519::public_key(eb_priv.expose())
        .map_err(|_| HandshakeFailed::new("handshake_malformed"))?;
    let shared = x25519::shared_secret(eb_priv.expose(), &ea)
        .map_err(|_| HandshakeFailed::with_fp("low_order_point", fp.clone()))?;
    let responder = device
        .record()
        .map_err(|_| HandshakeFailed::new("handshake_malformed"))?;
    let t = transcript(&msg1_raw, &eb, &responder)?;
    let mut signed = HANDSHAKE_RESPONDER_CONTEXT.to_vec();
    signed.extend_from_slice(&t);
    let sig = device
        .sign(&signed)
        .map_err(|_| HandshakeFailed::new("handshake_malformed"))?;
    channel
        .send(&canon(
            &json!({"eb": b64e(&eb), "device": responder.to_dict(), "sig": b64e(&sig)}),
        )?)
        .map_err(|_| HandshakeFailed::new("handshake_channel_closed"))?;
    let (_, msg3) = recv_plain(channel.as_ref(), deadline)?;
    let sig3 = b64d(msg3.get("sig"))?;
    let mut signed = HANDSHAKE_INITIATOR_CONTEXT.to_vec();
    signed.extend_from_slice(&t);
    if !ed25519::verify(&initiator.sign_pub, &signed, &sig3) {
        return Err(HandshakeFailed::with_fp("signature_invalid", fp));
    }
    let hash = Sha256::digest(&t);
    if member.is_none() {
        let proof = if msg3.get("invite_proof").is_some() {
            b64d(msg3.get("invite_proof"))?
        } else {
            vec![]
        };
        if !invite.is_some_and(|check| check(env_id, &initiator, &hash, &proof)) {
            return Err(HandshakeFailed::with_fp("invite_invalid", fp));
        }
    }
    let (i2r, r2i) = keys(&shared, &hash)?;
    Ok(Arc::new(EncryptedSession::new(
        channel,
        initiator,
        env_id.to_owned(),
        r2i,
        i2r,
        *b"R2I\0",
        *b"I2R\0",
    )))
}
fn initiate(
    channel: Arc<dyn ByteChannel>,
    device: &DeviceKey,
    env_id: &str,
    membership: &MembershipCheck,
    invite_proof: Option<&InviteProof>,
) -> std::result::Result<Arc<EncryptedSession>, HandshakeFailed> {
    let deadline = Instant::now() + Duration::from_secs(HANDSHAKE_TIMEOUT_SECONDS);
    let ea_priv = x25519::generate_private();
    let ea = x25519::public_key(ea_priv.expose())
        .map_err(|_| HandshakeFailed::new("handshake_malformed"))?;
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let msg1_raw = canon(
        &json!({"version": PROTOCOL_VERSION, "env_id": env_id, "ea": b64e(&ea), "device": device.record().map_err(|_| HandshakeFailed::new("handshake_malformed"))?.to_dict(), "nonce": b64e(&nonce)}),
    )?;
    channel
        .send(&msg1_raw)
        .map_err(|_| HandshakeFailed::new("handshake_channel_closed"))?;
    let (_, msg2) = recv_plain(channel.as_ref(), deadline)?;
    let responder = parse_record(msg2.get("device"))?;
    let eb = b64d(msg2.get("eb"))?;
    if eb.len() != 32 {
        return Err(HandshakeFailed::new("handshake_malformed"));
    }
    let t = transcript(&msg1_raw, &eb, &responder)?;
    let sig2 = b64d(msg2.get("sig"))?;
    let fp = responder.fingerprint();
    let mut signed = HANDSHAKE_RESPONDER_CONTEXT.to_vec();
    signed.extend_from_slice(&t);
    if !ed25519::verify(&responder.sign_pub, &signed, &sig2) {
        return Err(HandshakeFailed::with_fp("signature_invalid", fp));
    }
    if invite_proof.is_none() && membership(env_id, &fp).is_none() {
        return Err(HandshakeFailed::with_fp("responder_not_member", fp));
    }
    let shared = x25519::shared_secret(ea_priv.expose(), &eb)
        .map_err(|_| HandshakeFailed::with_fp("low_order_point", fp.clone()))?;
    let hash = Sha256::digest(&t);
    let mut signed = HANDSHAKE_INITIATOR_CONTEXT.to_vec();
    signed.extend_from_slice(&t);
    let sig3 = device
        .sign(&signed)
        .map_err(|_| HandshakeFailed::new("handshake_malformed"))?;
    let mut msg3 = json!({"sig": b64e(&sig3)});
    if let Some(make_proof) = invite_proof {
        msg3["invite_proof"] = Value::String(b64e(&make_proof(&hash)));
    }
    channel
        .send(&canon(&msg3)?)
        .map_err(|_| HandshakeFailed::new("handshake_channel_closed"))?;
    let (i2r, r2i) = keys(&shared, &hash)?;
    Ok(Arc::new(EncryptedSession::new(
        channel,
        responder,
        env_id.to_owned(),
        i2r,
        r2i,
        *b"I2R\0",
        *b"R2I\0",
    )))
}

struct InProcessInner {
    device: DeviceKey,
    membership: Mutex<MembershipCheck>,
    invite_check: Mutex<Option<InviteCheck>>,
    failed: Mutex<Option<HandshakeFailedHook>>,
    own: Mutex<HashSet<String>>,
}
pub struct InProcessTransport {
    inner: Arc<InProcessInner>,
}
type ListenerMap = HashMap<String, (Arc<InProcessInner>, OnSession)>;
static LISTENERS: OnceLock<Mutex<ListenerMap>> = OnceLock::new();
fn listeners() -> &'static Mutex<ListenerMap> {
    LISTENERS.get_or_init(|| Mutex::new(HashMap::new()))
}
impl InProcessTransport {
    pub fn new(device: DeviceKey, membership: MembershipCheck) -> Self {
        Self {
            inner: Arc::new(InProcessInner {
                device,
                membership: Mutex::new(membership),
                invite_check: Mutex::new(None),
                failed: Mutex::new(None),
                own: Mutex::new(HashSet::new()),
            }),
        }
    }
    pub fn set_membership(&self, cb: MembershipCheck) {
        *self
            .inner
            .membership
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = cb;
    }
    pub fn set_invite_check(&self, cb: Option<InviteCheck>) {
        *self
            .inner
            .invite_check
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = cb;
    }
    pub fn set_handshake_failed(&self, cb: Option<HandshakeFailedHook>) {
        *self.inner.failed.lock().unwrap_or_else(|e| e.into_inner()) = cb;
    }
    pub fn unlisten(&self, address: Option<&str>) {
        let mut map = listeners().lock().unwrap_or_else(|e| e.into_inner());
        let mut own = self.inner.own.lock().unwrap_or_else(|e| e.into_inner());
        let targets: Vec<String> = address
            .map(|v| vec![v.to_owned()])
            .unwrap_or_else(|| own.iter().cloned().collect());
        for target in targets {
            map.remove(&target);
            own.remove(&target);
        }
    }
}
impl Transport for InProcessTransport {
    fn listen(&self, address: &str, on_session: OnSession) -> Result<()> {
        let mut map = listeners().lock().unwrap_or_else(|e| e.into_inner());
        if map.contains_key(address) {
            return Err(Error::invalid_input("team_address_in_use"));
        }
        map.insert(address.to_owned(), (self.inner.clone(), on_session));
        self.inner
            .own
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(address.to_owned());
        Ok(())
    }
    fn dial(
        &self,
        address: &str,
        env_id: &str,
        invite_proof: Option<InviteProof>,
    ) -> std::result::Result<Arc<dyn Session>, SessionClosed> {
        let (responder, callback) = listeners()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(address)
            .cloned()
            .ok_or(SessionClosed("team_address_unreachable"))?;
        let (initiator_ch, responder_ch) = queue_pair();
        thread::spawn(move || {
            let membership = responder
                .membership
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            let invite = responder
                .invite_check
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            match respond(
                responder_ch.clone(),
                &responder.device,
                &membership,
                invite.as_ref(),
            ) {
                Ok(session) => callback(session),
                Err(e) => {
                    responder_ch.close();
                    if let Some(h) = responder
                        .failed
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .as_ref()
                    {
                        h(e.reason, e.fingerprint.as_deref());
                    }
                }
            }
        });
        let membership = self
            .inner
            .membership
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        initiate(
            initiator_ch.clone(),
            &self.inner.device,
            env_id,
            &membership,
            invite_proof.as_ref(),
        )
        .map(|s| s as Arc<dyn Session>)
        .map_err(|e| {
            initiator_ch.close();
            if let Some(h) = self
                .inner
                .failed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
            {
                h(e.reason, e.fingerprint.as_deref());
            }
            SessionClosed(e.reason)
        })
    }
    fn close(&self) {
        self.unlisten(None);
    }
}

pub struct TcpTransport {
    device: DeviceKey,
    membership: Mutex<MembershipCheck>,
    invite_check: Mutex<Option<InviteCheck>>,
    failed: Mutex<Option<HandshakeFailedHook>>,
    max_connections: usize,
    active: Arc<AtomicUsize>,
    listener: Mutex<Option<TcpListener>>,
    bound: Mutex<Option<String>>,
    stop: Arc<AtomicBool>,
    accept_thread: Mutex<Option<thread::JoinHandle<()>>>,
}
impl TcpTransport {
    pub fn new(
        device: DeviceKey,
        membership: MembershipCheck,
        max_connections: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            device,
            membership: Mutex::new(membership),
            invite_check: Mutex::new(None),
            failed: Mutex::new(None),
            max_connections,
            active: Arc::new(AtomicUsize::new(0)),
            listener: Mutex::new(None),
            bound: Mutex::new(None),
            stop: Arc::new(AtomicBool::new(false)),
            accept_thread: Mutex::new(None),
        })
    }
    pub fn set_membership(&self, cb: MembershipCheck) {
        *self.membership.lock().unwrap_or_else(|e| e.into_inner()) = cb;
    }
    pub fn set_invite_check(&self, cb: Option<InviteCheck>) {
        *self.invite_check.lock().unwrap_or_else(|e| e.into_inner()) = cb;
    }
    pub fn set_handshake_failed(&self, cb: Option<HandshakeFailedHook>) {
        *self.failed.lock().unwrap_or_else(|e| e.into_inner()) = cb;
    }
    pub fn bound_address(&self) -> Option<String> {
        self.bound.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn parse_address(address: &str) -> Result<(String, u16)> {
        let raw = address.trim();
        let (host, port) = raw
            .rsplit_once(':')
            .ok_or_else(|| Error::invalid_input("team_invalid_listen_address"))?;
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::invalid_input("team_invalid_listen_address"));
        }
        let port: u16 = port
            .parse()
            .map_err(|_| Error::invalid_input("team_invalid_listen_address"))?;
        let host = host.trim_matches(['[', ']']);
        Ok((
            if host.is_empty() {
                "0.0.0.0".to_owned()
            } else {
                host.to_owned()
            },
            port,
        ))
    }
    pub fn listen_arc(self: &Arc<Self>, address: &str, on_session: OnSession) -> Result<()> {
        let mut slot = self.listener.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return Err(Error::invalid_input("team_already_listening"));
        }
        let (host, port) = Self::parse_address(address)?;
        let listener = TcpListener::bind((host.as_str(), port))
            .map_err(|_| Error::invalid_input("team_invalid_listen_address"))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| Error::state("team_listen_failed"))?;
        let bound = listener
            .local_addr()
            .map_err(|_| Error::state("team_listen_failed"))?;
        *self.bound.lock().unwrap_or_else(|e| e.into_inner()) = Some(format!(
            "{}:{}",
            if bound.ip().is_unspecified() {
                "127.0.0.1".to_owned()
            } else {
                bound.ip().to_string()
            },
            bound.port()
        ));
        let loop_listener = listener
            .try_clone()
            .map_err(|_| Error::state("team_listen_failed"))?;
        *slot = Some(listener);
        self.stop.store(false, Ordering::SeqCst);
        let this = self.clone();
        let thread = thread::spawn(move || {
            while !this.stop.load(Ordering::SeqCst) {
                match loop_listener.accept() {
                    Ok((stream, _)) => {
                        if stream.set_nonblocking(false).is_err() {
                            drop(stream);
                            continue;
                        }
                        if this.active.fetch_add(1, Ordering::SeqCst) >= this.max_connections {
                            this.active.fetch_sub(1, Ordering::SeqCst);
                            drop(stream);
                            continue;
                        }
                        let node = this.clone();
                        let cb = on_session.clone();
                        thread::spawn(move || {
                            let channel: Arc<dyn ByteChannel> = match SocketChannel::new(stream) {
                                Ok(c) => Arc::new(c),
                                Err(_) => {
                                    node.active.fetch_sub(1, Ordering::SeqCst);
                                    return;
                                }
                            };
                            let membership = node
                                .membership
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .clone();
                            let invite = node
                                .invite_check
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .clone();
                            match respond(
                                channel.clone(),
                                &node.device,
                                &membership,
                                invite.as_ref(),
                            ) {
                                Ok(session) => {
                                    let active = node.active.clone();
                                    session.set_on_close(Box::new(move || {
                                        active.fetch_sub(1, Ordering::SeqCst);
                                    }));
                                    cb(session);
                                }
                                Err(e) => {
                                    channel.close();
                                    node.active.fetch_sub(1, Ordering::SeqCst);
                                    if let Some(h) = node
                                        .failed
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .as_ref()
                                    {
                                        h(e.reason, e.fingerprint.as_deref());
                                    }
                                }
                            }
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20))
                    }
                    Err(_) => break,
                }
            }
        });
        *self.accept_thread.lock().unwrap_or_else(|e| e.into_inner()) = Some(thread);
        Ok(())
    }
    pub fn dial_session(
        &self,
        address: &str,
        env_id: &str,
        invite_proof: Option<InviteProof>,
    ) -> std::result::Result<Arc<dyn Session>, SessionClosed> {
        let (host, port) = Self::parse_address(address)
            .map_err(|_| SessionClosed("team_invalid_listen_address"))?;
        let addrs = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|_| SessionClosed("team_dial_failed"))?;
        let stream = addrs
            .into_iter()
            .find_map(|a| {
                TcpStream::connect_timeout(&a, Duration::from_secs(SOCKET_OP_TIMEOUT_SECONDS)).ok()
            })
            .ok_or(SessionClosed("team_dial_failed"))?;
        let channel: Arc<dyn ByteChannel> =
            Arc::new(SocketChannel::new(stream).map_err(|_| SessionClosed("team_dial_failed"))?);
        let membership = self
            .membership
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        initiate(
            channel.clone(),
            &self.device,
            env_id,
            &membership,
            invite_proof.as_ref(),
        )
        .map(|s| s as Arc<dyn Session>)
        .map_err(|e| {
            channel.close();
            if let Some(h) = self
                .failed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
            {
                h(e.reason, e.fingerprint.as_deref());
            }
            SessionClosed(e.reason)
        })
    }
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.listener
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(t) = self
            .accept_thread
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = t.join();
        }
        self.bound.lock().unwrap_or_else(|e| e.into_inner()).take();
    }
}
impl Transport for Arc<TcpTransport> {
    fn listen(&self, address: &str, on_session: OnSession) -> Result<()> {
        self.listen_arc(address, on_session)
    }
    fn dial(
        &self,
        address: &str,
        env_id: &str,
        invite_proof: Option<InviteProof>,
    ) -> std::result::Result<Arc<dyn Session>, SessionClosed> {
        self.dial_session(address, env_id, invite_proof)
    }
    fn close(&self) {
        self.shutdown();
    }
}
