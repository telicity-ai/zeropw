//! A fake zeropw-link network for tests: one in-process "daemon" per
//! simulated device, each on its own Unix socket and speaking the local
//! daemon protocol (zeropw-link protocol §5). A `dial` at one daemon is
//! matched with an `accept` waiting at the target daemon, both get their
//! reply line and the two client connections are spliced, so what ZeroPW
//! writes on one side comes out on the other -- the role ICE and QUIC play
//! between real daemons. Every relayed byte is recorded for leak scans.
//!
//! Faults: [`Daemon::kill`] / [`Daemon::start`] (a daemon crash and
//! restart: the socket disappears and every connection through it ends),
//! and [`Daemon::set_fault`] (answer every request with fixed raw bytes,
//! never answer, or hang up). Only synthetic data passes through here.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// The longest request line the fake daemon reads, `\n` included.
const LINE_MAX: usize = 8 * 1024;
/// How long a `dial` waits at most for the target's `accept`.
const MATCH_WAIT: Duration = Duration::from_secs(3);

/// What a daemon does with a request instead of serving it.
#[derive(Clone, Debug)]
pub enum Fault {
    /// Reply with exactly these bytes, then hang up.
    Reply(Vec<u8>),
    /// Read the request and never answer (until killed).
    Hang,
    /// Hang up without answering.
    Close,
}

/// A set of fake daemons that can reach each other.
pub struct LinkNet {
    net: Arc<Net>,
    dir: tempfile::TempDir,
}

struct Net {
    daemons: Mutex<HashMap<String, Arc<Daemon>>>,
    /// One buffer per spliced direction, so each holds one contiguous
    /// byte stream.
    relayed: Mutex<Vec<Arc<Mutex<Vec<u8>>>>>,
}

pub struct Daemon {
    pub id: String,
    pub socket: PathBuf,
    net: Weak<Net>,
    running: AtomicBool,
    generation: AtomicUsize,
    listener: Mutex<Option<thread::JoinHandle<()>>>,
    waiting: Mutex<VecDeque<UnixStream>>,
    arrived: Condvar,
    live: Mutex<Vec<UnixStream>>,
    fault: Mutex<Option<Fault>>,
    /// Requests read (any op, faults included).
    pub requests: AtomicUsize,
    /// `accept` requests read (faults included).
    pub accept_requests: AtomicUsize,
    /// Streams this daemon delivered to one of its `accept` clients.
    pub delivered: AtomicUsize,
}

/// RFC 4648 base32 (lowercase, unpadded) of the first 16 bytes of
/// SHA-256(`seed`): a link device ID, as the real daemon derives it.
pub fn device_id(seed: &str) -> String {
    use sha2::{Digest, Sha256};
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let digest = Sha256::digest(seed.as_bytes());
    let (mut bits, mut count, mut out) = (0u32, 0u32, String::new());
    for &byte in &digest[..16] {
        bits = ((bits << 8) | u32::from(byte)) & 0xffff;
        count += 8;
        while count >= 5 {
            count -= 5;
            out.push(char::from(ALPHABET[((bits >> count) & 31) as usize]));
        }
    }
    if count > 0 {
        out.push(char::from(ALPHABET[((bits << (5 - count)) & 31) as usize]));
    }
    out
}

fn read_line(conn: &mut UnixStream) -> Option<Vec<u8>> {
    conn.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match conn.read(&mut byte) {
            Ok(1) if byte[0] == b'\n' => return Some(line),
            Ok(1) => {
                line.push(byte[0]);
                if line.len() >= LINE_MAX {
                    return None;
                }
            }
            _ => return None,
        }
    }
}

fn reply(conn: &mut UnixStream, value: &Value) -> bool {
    let mut line = serde_json::to_vec(value).unwrap();
    line.push(b'\n');
    conn.write_all(&line).is_ok()
}

impl LinkNet {
    pub fn new() -> Self {
        // Short socket paths: `sun_path` holds about 100 bytes.
        let dir = tempfile::Builder::new()
            .prefix("zpl-")
            .tempdir_in("/tmp")
            .unwrap();
        LinkNet {
            net: Arc::new(Net {
                daemons: Mutex::new(HashMap::new()),
                relayed: Mutex::new(Vec::new()),
            }),
            dir,
        }
    }

    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// A daemon for device `name`, listening.
    pub fn daemon(&self, name: &str) -> Arc<Daemon> {
        let daemon = self.stopped_daemon(name);
        daemon.start();
        daemon
    }

    /// A daemon for device `name` that is not running yet (no socket).
    pub fn stopped_daemon(&self, name: &str) -> Arc<Daemon> {
        let id = device_id(&format!("{}/{name}", self.dir.path().display()));
        let daemon = Arc::new(Daemon {
            id: id.clone(),
            socket: self.dir.path().join(format!("{name}.sock")),
            net: Arc::downgrade(&self.net),
            running: AtomicBool::new(false),
            generation: AtomicUsize::new(0),
            listener: Mutex::new(None),
            waiting: Mutex::new(VecDeque::new()),
            arrived: Condvar::new(),
            live: Mutex::new(Vec::new()),
            fault: Mutex::new(None),
            requests: AtomicUsize::new(0),
            accept_requests: AtomicUsize::new(0),
            delivered: AtomicUsize::new(0),
        });
        self.net.daemons.lock().unwrap().insert(id, daemon.clone());
        daemon
    }

    /// Every byte spliced between two clients so far: each direction's
    /// stream in one piece, the streams one after another.
    pub fn relayed(&self) -> Vec<u8> {
        self.net
            .relayed
            .lock()
            .unwrap()
            .iter()
            .flat_map(|stream| stream.lock().unwrap().clone())
            .collect()
    }
}

impl Drop for LinkNet {
    fn drop(&mut self) {
        let daemons: Vec<_> = self.net.daemons.lock().unwrap().values().cloned().collect();
        for daemon in daemons {
            daemon.kill();
        }
    }
}

impl Daemon {
    pub fn address(&self) -> String {
        format!("zpl:{}", self.id)
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Bind the socket and serve (again).
    pub fn start(self: &Arc<Self>) {
        let _ = std::fs::remove_file(&self.socket);
        let listener = UnixListener::bind(&self.socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        self.running.store(true, Ordering::SeqCst);
        let this = self.clone();
        let handle = thread::spawn(move || {
            while this.running.load(Ordering::SeqCst)
                && this.generation.load(Ordering::SeqCst) == generation
            {
                match listener.accept() {
                    Ok((conn, _)) => {
                        if conn.set_nonblocking(false).is_err() {
                            continue;
                        }
                        if let Ok(clone) = conn.try_clone() {
                            this.live.lock().unwrap().push(clone);
                        }
                        let daemon = this.clone();
                        thread::spawn(move || daemon.handle(conn));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        *self.listener.lock().unwrap() = Some(handle);
    }

    /// Crash: stop listening, remove the socket and end every connection
    /// through this daemon (waiting `accept`s and spliced streams alike).
    pub fn kill(&self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.listener.lock().unwrap().take() {
            let _ = handle.join();
        }
        let _ = std::fs::remove_file(&self.socket);
        for conn in self.live.lock().unwrap().drain(..) {
            let _ = conn.shutdown(Shutdown::Both);
        }
        self.waiting.lock().unwrap().clear();
    }

    pub fn set_fault(&self, fault: Option<Fault>) {
        *self.fault.lock().unwrap() = fault;
    }

    /// `accept` requests currently waiting here.
    pub fn waiting_accepts(&self) -> usize {
        self.waiting.lock().unwrap().len()
    }

    fn handle(self: Arc<Self>, mut conn: UnixStream) {
        let Some(line) = read_line(&mut conn) else {
            return;
        };
        self.requests.fetch_add(1, Ordering::SeqCst);
        let parsed: Option<Value> = serde_json::from_slice(&line).ok();
        if parsed.as_ref().is_some_and(|r| r["op"] == "accept") {
            self.accept_requests.fetch_add(1, Ordering::SeqCst);
        }
        let fault = self.fault.lock().unwrap().clone();
        match fault {
            Some(Fault::Reply(bytes)) => {
                let _ = conn.write_all(&bytes);
                let _ = conn.shutdown(Shutdown::Both);
                return;
            }
            Some(Fault::Hang) => {
                // Kept in `live` until the daemon is killed.
                return;
            }
            Some(Fault::Close) => {
                let _ = conn.shutdown(Shutdown::Both);
                return;
            }
            None => {}
        }
        let Some(request) = parsed else {
            reply(&mut conn, &json!({"ok":false,"error":"invalid_request"}));
            return;
        };
        let keys = request.as_object().map_or(0, |o| o.len());
        match request["op"].as_str() {
            Some("accept") if keys == 2 && request["svc"] == "zeropw-team" => {
                self.waiting.lock().unwrap().push_back(conn);
                self.arrived.notify_all();
            }
            Some("dial")
                if keys == 4
                    && request["svc"] == "zeropw-team"
                    && request["timeout_ms"].is_u64() =>
            {
                self.dial(conn, &request);
            }
            Some("status") if keys == 1 => {
                reply(
                    &mut conn,
                    &json!({"ok":true,"enrolled":true,"service":null,"device_id":self.id,
                            "account_id":"synthetic-account","online":true,"peers":[]}),
                );
            }
            _ => {
                reply(&mut conn, &json!({"ok":false,"error":"invalid_request"}));
            }
        }
    }

    fn dial(&self, mut conn: UnixStream, request: &Value) {
        let Some(net) = self.net.upgrade() else {
            return;
        };
        let target = request["peer"]
            .as_str()
            .and_then(|peer| net.daemons.lock().unwrap().get(peer).cloned());
        let Some(target) = target else {
            reply(&mut conn, &json!({"ok":false,"error":"peer_unknown"}));
            return;
        };
        let wait =
            Duration::from_millis(request["timeout_ms"].as_u64().unwrap_or(0)).min(MATCH_WAIT);
        let deadline = Instant::now() + wait;
        loop {
            let acceptor = if target.is_running() {
                target.take_waiting(deadline)
            } else {
                None
            };
            let Some(mut acceptor) = acceptor else {
                reply(&mut conn, &json!({"ok":false,"error":"peer_offline"}));
                return;
            };
            // A waiting request whose client has gone fails this write;
            // try the next one.
            if !reply(
                &mut acceptor,
                &json!({"ok":true,"path":"direct","peer":self.id}),
            ) {
                continue;
            }
            target.delivered.fetch_add(1, Ordering::SeqCst);
            if !reply(&mut conn, &json!({"ok":true,"path":"direct"})) {
                let _ = acceptor.shutdown(Shutdown::Both);
                return;
            }
            splice(&net, conn, acceptor);
            return;
        }
    }

    fn take_waiting(&self, deadline: Instant) -> Option<UnixStream> {
        let mut waiting = self.waiting.lock().unwrap();
        loop {
            if let Some(conn) = waiting.pop_front() {
                return Some(conn);
            }
            let left = deadline.checked_duration_since(Instant::now())?;
            waiting = self.arrived.wait_timeout(waiting, left).unwrap().0;
        }
    }
}

/// Copy both ways until either side ends, then end both.
fn splice(net: &Arc<Net>, a: UnixStream, b: UnixStream) {
    let pump = |mut from: UnixStream, mut to: UnixStream| {
        let record = Arc::new(Mutex::new(Vec::new()));
        net.relayed.lock().unwrap().push(record.clone());
        thread::spawn(move || {
            let _ = from.set_read_timeout(None);
            let mut buffer = [0u8; 16 * 1024];
            loop {
                match from.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        record.lock().unwrap().extend_from_slice(&buffer[..n]);
                        if to.write_all(&buffer[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = from.shutdown(Shutdown::Both);
            let _ = to.shutdown(Shutdown::Both);
        })
    };
    let (a2, b2) = (a.try_clone().unwrap(), b.try_clone().unwrap());
    pump(a, b2);
    pump(b, a2);
}
