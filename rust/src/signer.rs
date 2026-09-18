//! Port of `zeropw/signer.py`: SSH signing delegation over the OpenSSH agent
//! protocol.
//!
//! The signer speaks the OpenSSH agent protocol over a Unix socket. Each
//! socket is created for exactly one (caller, connection, grant) binding by
//! [`SignerManager::bind`] — the socket *is* the capability handed to the
//! secret-free execution environment via `SSH_AUTH_SOCK`.
//!
//! What the signer will do:
//! * list the single Ed25519 identity of the bound connection;
//! * accept one `session-bind@openssh.com` per client connection when the
//!   presented host key is one of the connection's configured destination
//!   host keys, the host key's signature over the session identifier
//!   verifies, and the binding is not a forwarding hop;
//! * sign exactly one shape of data: a strictly parsed
//!   `SSH_MSG_USERAUTH_REQUEST` for the connection's username, this key,
//!   `ssh-ed25519`, whose session identifier (and, for hostbound requests,
//!   host key) equals the bound session — after re-checking policy
//!   (revocation, expiry, usage, global stop, restore state) and writing the
//!   audit record.
//!
//! What it refuses (`SSH_AGENT_FAILURE`): any other message type — adding,
//! removing, locking or unlocking keys, smartcards, legacy protocol-1
//! requests — arbitrary-data signing (so `ssh-add -T` fails by design), sign
//! requests before a session bind, a second bind on the same client
//! connection, forwarding binds, unknown host keys, mismatched session
//! identifiers, other usernames, non-zero flags, and malformed input.
//! Private key export is not part of the agent protocol at all; the seed
//! only exists in this trusted process.
//!
//! # Deviations from the Python prototype (see `DEVIATIONS.md`)
//!
//! * Python's `MAX_AGENT_CLIENTS` is a mutable module-level global the test
//!   suite monkeypatches (`S.MAX_AGENT_CLIENTS = 3`). PORTING.md §3.4 turns
//!   that into an explicit seam: [`SignerManager::set_max_agent_clients`],
//!   backed by a value shared with every [`BindingServer`] this manager
//!   creates, scoped to one `SignerManager` instance rather than the whole
//!   process (so concurrent tests using different managers cannot interfere
//!   with each other, unlike the Python global).
//! * Python narrows the process umask around `socket.bind()` so the kernel
//!   creates the socket file with mode 0600 atomically, then `chmod`s
//!   redundantly. This crate forbids `unsafe` code everywhere except
//!   `store.rs`'s one `flock` call (`rust/PORTING.md` engineering rules), and
//!   narrowing umask needs an FFI call, so this port only `chmod`s after
//!   `bind()`. The socket directory is always created mode 0700
//!   ([`choose_socket_dir`]), so no other user on the host can even resolve
//!   the socket's path to exploit the brief window.
//! * `UnixListener::bind` uses the OS default backlog; std has no safe way
//!   to request Python's explicit `listen(16)` backlog without an `unsafe`
//!   FFI call. Not observable by anything in this crate's own tests
//!   ([`DEFAULT_MAX_AGENT_CLIENTS`] caps concurrent clients far below any
//!   platform's default backlog).
//! * Python's accept loop blocks in `accept()` with a 0.2s `settimeout`
//!   purely so `close()` can eventually notice `self._closed`; a genuine
//!   connection is always served the instant it arrives. `std` has no
//!   equivalent "blocking accept with a timeout" for `UnixListener`, so this
//!   port instead makes the listener non-blocking and polls it every
//!   [`ACCEPT_POLL_INTERVAL`] (1ms, comfortably under Python's own measured
//!   ~0.4-2.7ms per-connection accept latency) -- see `BindingServer::close`
//!   and `accept_loop` for why this needs no durable, connectable "wakeup"
//!   alias for the socket (finding G-R3-1).

use std::collections::HashMap;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::audit::RecordArgs;
use crate::context::Context;
use crate::crypto::ed25519;
use crate::errors::{Error, ErrorClass};
use crate::policy::Action;
use crate::sshwire;

/// Conservative: macOS `sun_path` is 104 bytes including the NUL.
pub const MAX_UNIX_PATH: usize = 100;
/// Default concurrent agent client connections per binding; see
/// [`SignerManager::set_max_agent_clients`] for the injectable override that
/// replaces Python's mutable `MAX_AGENT_CLIENTS` module global.
pub const DEFAULT_MAX_AGENT_CLIENTS: usize = 32;
const CLIENT_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound on waiting for the accept thread to notice `closed` and return, the
/// same 2s Python gives `self._accept_thread.join(timeout=2)`. With the
/// non-blocking accept loop below (finding G-R3-1) the accept thread should
/// always notice within one [`ACCEPT_POLL_INTERVAL`], so this bound is
/// defence in depth rather than the normal path.
const ACCEPT_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
/// How long `accept_loop` sleeps after a non-blocking `accept()` returns
/// `WouldBlock` before checking `closed` (and the listener) again and
/// retrying. This is the *only* thing that bounds how quickly `close()`'s
/// `closed = true` / listener removal is noticed -- it creates no filesystem
/// state (finding G-R3-1, replacing the round-2 hard-link "wakeup" design)
/// and, at 1ms, is far below Python's own per-connection accept latency
/// (~0.4-2.7ms measured against the real signer), so it does not regress
/// ordinary accept latency the way a fixed 200ms poll would have (finding
/// G-1).
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(1);

pub const SUPPORTED_EXTENSIONS: &[&str] = &[sshwire::SESSION_BIND_EXTENSION];
pub const SSH_ED25519: &str = "ssh-ed25519";

fn message_name(msg_type: u8) -> String {
    let name = match msg_type {
        sshwire::SSH_AGENTC_REQUEST_IDENTITIES => "request_identities",
        sshwire::SSH_AGENTC_SIGN_REQUEST => "sign_request",
        sshwire::SSH_AGENTC_ADD_IDENTITY => "add_identity",
        sshwire::SSH_AGENTC_REMOVE_IDENTITY => "remove_identity",
        sshwire::SSH_AGENTC_REMOVE_ALL_IDENTITIES => "remove_all_identities",
        sshwire::SSH_AGENTC_ADD_SMARTCARD_KEY => "add_smartcard_key",
        sshwire::SSH_AGENTC_REMOVE_SMARTCARD_KEY => "remove_smartcard_key",
        sshwire::SSH_AGENTC_LOCK => "lock",
        sshwire::SSH_AGENTC_UNLOCK => "unlock",
        sshwire::SSH_AGENTC_ADD_ID_CONSTRAINED => "add_id_constrained",
        sshwire::SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED => "add_smartcard_key_constrained",
        sshwire::SSH_AGENTC_EXTENSION => "extension",
        other => return format!("type_{other}"),
    };
    name.to_string()
}

// ---------------------------------------------------------------------------
// SignerBinding
// ---------------------------------------------------------------------------

/// One (caller, connection, grant) binding: the socket path the execution
/// environment is handed as `SSH_AUTH_SOCK`, plus the identity it was issued
/// for. Port of `signer.SignerBinding`.
#[derive(Clone)]
pub struct SignerBinding {
    pub socket_path: PathBuf,
    pub caller: String,
    pub connection_id: String,
    pub grant_id: String,
    manager: Option<Arc<SignerManager>>,
}

impl SignerBinding {
    /// Close the socket and end every client connection on it.
    pub fn close(&self) {
        if let Some(manager) = &self.manager {
            manager.release(self);
        }
    }
}

// ---------------------------------------------------------------------------
// Per client-connection state
// ---------------------------------------------------------------------------

/// Port of `signer._ClientState`: one accepted socket's state.
struct ClientState {
    bound: Option<sshwire::SessionBind>,
    /// Kept for parity with the Python prototype's field of the same name;
    /// like Python, nothing reads it back.
    #[allow(dead_code)]
    bind_attempts: u32,
}

impl ClientState {
    fn new() -> Self {
        ClientState {
            bound: None,
            bind_attempts: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// BindingServer: one Unix socket, one accept loop, many client threads
// ---------------------------------------------------------------------------

/// One admitted client connection's bookkeeping. Inserted under the same
/// `clients` lock that decides admission, *before* the serving thread is
/// spawned, and removed exactly once (by the serving thread itself, from
/// `serve_client`'s tail) -- so `clients` can never contain an entry nothing
/// will ever remove, and never has a handle inserted after the entry it
/// belongs to is already gone (finding G-R2-2). `handle`/`done` start empty
/// and are filled in by `handle_accepted` immediately after `spawn` returns
/// (a client that finishes before that late-bind runs simply finds its own
/// entry already gone when it looks, and `handle_accepted` then drops the
/// handle it can no longer place instead of leaking it into a stale slot).
struct ClientSlot {
    stream: UnixStream,
    handle: Option<JoinHandle<()>>,
    /// Signalled (by `serve_client` sending, right before it returns) once
    /// this client's thread has finished; `close()` waits on this with a
    /// bound shared across every live client instead of an untimed
    /// `JoinHandle::join()` (`std` has no timed join), so one client thread
    /// wedged inside `handle_message` (e.g. blocked taking the state
    /// `flock`) cannot itself block `close()` past the shared deadline
    /// (finding G-R2-5). `Option` so `close()` can take it out alongside
    /// `handle` without disturbing the rest of the slot.
    done: Option<Receiver<()>>,
}

/// Port of `signer._BindingServer`.
struct BindingServer {
    ctx: &'static Context,
    binding: SignerBinding,
    /// The listening socket, non-blocking (finding G-R3-1: `accept_loop`
    /// polls it rather than blocking, so no durable wakeup alias is ever
    /// needed to interrupt it). Wrapped so `close()` can `take()` and drop
    /// it, releasing the listening fd immediately and independently of
    /// whether some other `Arc<BindingServer>` clone (e.g. a client thread
    /// detached past its join deadline) keeps the rest of this struct alive
    /// (finding G-R3-3) -- Python's `close()` releases its listening fd
    /// unconditionally as its second statement (`self._sock.close()`),
    /// before any joins.
    listener: Mutex<Option<UnixListener>>,
    closed: AtomicBool,
    /// Live client connections, keyed by a monotonic per-connection id (not
    /// by `ThreadId`, so a client is registered — and admission is decided —
    /// atomically with respect to `MAX_AGENT_CLIENTS`, exactly like Python's
    /// `self._clients[thread] = client` under `self._clients_lock` before
    /// `thread.start()`).
    clients: Mutex<HashMap<u64, ClientSlot>>,
    next_client_id: AtomicU64,
    accept_handle: Mutex<Option<JoinHandle<()>>>,
    /// Signalled (by `accept_loop` sending, right before it returns) once the
    /// accept thread has finished; `close()` waits on this with a bound
    /// instead of an untimed `JoinHandle::join()` (`std` has no timed join),
    /// so a wedged accept thread cannot block `close()` forever (finding
    /// G-4).
    accept_done: Mutex<Option<Receiver<()>>>,
    max_agent_clients: Arc<AtomicUsize>,
}

impl BindingServer {
    fn start(
        ctx: &'static Context,
        binding: SignerBinding,
        max_agent_clients: Arc<AtomicUsize>,
    ) -> Result<Arc<Self>, Error> {
        let listener = bind_and_listen(&binding.socket_path)?;
        listener
            .set_nonblocking(true)
            .map_err(|e| Error::state("signer_socket_bind_failed").with_detail(e.to_string()))?;
        let server = Arc::new(BindingServer {
            ctx,
            binding,
            listener: Mutex::new(Some(listener)),
            closed: AtomicBool::new(false),
            clients: Mutex::new(HashMap::new()),
            next_client_id: AtomicU64::new(0),
            accept_handle: Mutex::new(None),
            accept_done: Mutex::new(None),
            max_agent_clients,
        });
        let accept_server = Arc::clone(&server);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let handle = thread::Builder::new()
            .name(format!("zeropw-signer-{}", server.binding.grant_id))
            .spawn(move || {
                accept_server.accept_loop();
                let _ = done_tx.send(());
            })
            .map_err(|e| Error::state("signer_thread_spawn_failed").with_detail(e.to_string()))?;
        *server
            .accept_handle
            .lock()
            .expect("accept_handle mutex poisoned") = Some(handle);
        *server
            .accept_done
            .lock()
            .expect("accept_done mutex poisoned") = Some(done_rx);
        Ok(server)
    }

    // ---------------------------------------------------------- lifecycle
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // Take and drop the listener immediately -- Python's `close()`
        // closes `self._sock` as its second statement, before any joins, so
        // the listening fd is released unconditionally rather than only
        // when the last `Arc<BindingServer>` clone drops (finding G-R3-3: a
        // client thread detached past its join deadline below used to keep
        // this whole struct, and therefore the listener fd, alive
        // indefinitely). This also wakes `accept_loop`: it re-locks
        // `listener` every polling iteration (at most `ACCEPT_POLL_INTERVAL`
        // apart -- see `accept_loop`) and exits as soon as it observes
        // `None`, without ever needing a durable, connectable alias to the
        // socket (finding G-R3-1 -- the round-2 hard-link "wakeup" design is
        // withdrawn: the reviewer showed that link was a second, fully
        // functional agent endpoint reachable even after the directory
        // holding the real socket was removed, widening the capability
        // boundary `SSH_AUTH_SOCK` is supposed to be).
        let listener = self
            .listener
            .lock()
            .expect("listener mutex poisoned")
            .take();
        drop(listener);
        // Bound the wait the way Python's `self._accept_thread.join(timeout=2)`
        // does: `JoinHandle::join` has no timeout, so wait on a completion
        // signal sent right before `accept_loop` returns, and give up
        // (detaching the handle) past the deadline instead of blocking
        // `close()` forever on a wedged accept thread. With the listener
        // gone, `accept_loop` should notice within one `ACCEPT_POLL_INTERVAL`
        // (a couple of milliseconds), so this bound is defence in depth.
        let done = self
            .accept_done
            .lock()
            .expect("accept_done mutex poisoned")
            .take();
        if let Some(done) = done {
            let _ = done.recv_timeout(ACCEPT_JOIN_TIMEOUT);
        }
        if let Some(handle) = self
            .accept_handle
            .lock()
            .expect("accept_handle mutex poisoned")
            .take()
        {
            // By the time `done` fired, the thread is finished or finishing;
            // if it never fired (deadline elapsed), detach rather than block
            // indefinitely -- matching Python's "move on past the deadline"
            // behaviour for a wedged thread.
            drop(handle);
        }
        let _ = std::fs::remove_file(&self.binding.socket_path);
        // Shut down every live client connection so a blocking read in a
        // serving thread returns at once; snapshot the ids under the same
        // lock, mirroring Python's `live = list(self._clients)`.
        let live_ids: Vec<u64> = {
            let clients = self.clients.lock().expect("clients mutex poisoned");
            for slot in clients.values() {
                let _ = slot.stream.shutdown(std::net::Shutdown::Both);
            }
            clients.keys().copied().collect()
        };
        let deadline = Instant::now() + CLIENT_JOIN_TIMEOUT; // one bound for all clients together
        let current = thread::current().id();
        for id in live_ids {
            // Take the lock only long enough to pull this one entry's handle
            // and completion receiver out of the slot (leaving the slot
            // itself for `serve_client`'s own tail to remove): a serving
            // thread's cleanup also locks `clients` to detach itself, and
            // would deadlock against a `close()` that held the lock across a
            // blocking `join`/`recv`.
            let taken = {
                let mut clients = self.clients.lock().expect("clients mutex poisoned");
                clients
                    .get_mut(&id)
                    .map(|slot| (slot.handle.take(), slot.done.take()))
            };
            let Some((handle, done)) = taken else {
                continue; // slot already fully removed by `serve_client`'s own tail
            };
            let Some(handle) = handle else {
                continue; // admitted but not yet late-bound; nothing to join here
            };
            if handle.thread().id() == current {
                continue; // registered but this *is* that thread (defensive, mirrors Python)
            }
            // Bound *this* client's wait against the one shared deadline,
            // exactly like Python's `thread.join(timeout=max(0.0, deadline -
            // now))`: unlike an untimed `JoinHandle::join()` (`std` has no
            // timed join), waiting on a completion signal first lets
            // `close()` move on to the next client at the deadline even if
            // this one is wedged inside `handle_message` rather than blocked
            // on socket I/O (finding G-R2-5) -- e.g. stuck in
            // `policy.consume` waiting on the state `flock` another thread
            // or process holds.
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                drop(handle); // detaches; give up waiting on the shared deadline
                continue;
            }
            let Some(done) = done else {
                // No completion channel (should not normally happen): there
                // is no bounded way to wait on a plain `JoinHandle`, so
                // detach rather than risk blocking past the deadline.
                drop(handle);
                continue;
            };
            match done.recv_timeout(remaining) {
                Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                    // The thread has sent its completion signal (or dropped
                    // the sender without sending, e.g. a panic) and is
                    // finished or finishing; joining now should return
                    // essentially immediately.
                    let _ = handle.join();
                }
                Err(RecvTimeoutError::Timeout) => {
                    drop(handle); // detaches; give up waiting on the shared deadline
                }
            }
        }
    }

    fn accept_loop(self: Arc<Self>) {
        // The listener is non-blocking (`BindingServer::start`): a genuine
        // connection is accepted and served the moment `accept()` sees it,
        // and a `WouldBlock` just means "nothing pending yet", so this loop
        // rechecks at most `ACCEPT_POLL_INTERVAL` (1ms) later. That interval
        // is the entire wakeup mechanism `close()` relies on -- there is no
        // durable, connectable alias for a blocked accept to wait on
        // (finding G-R3-1, replacing the round-2 hard-link "wakeup" design:
        // that link was a second, fully functional agent endpoint, not
        // merely a wakeup nudge, and stayed reachable even after the
        // directory holding the real socket was removed). `close()` sets
        // `closed` and takes the listener out from under this loop; both are
        // checked every iteration, so this thread exits within about one
        // `ACCEPT_POLL_INTERVAL` of either happening, with no fixed 200ms
        // poll (finding G-1) and no filesystem state created to make it
        // happen sooner.
        loop {
            if self.closed.load(Ordering::SeqCst) {
                break;
            }
            let accepted = {
                let guard = self.listener.lock().expect("listener mutex poisoned");
                guard.as_ref().map(UnixListener::accept)
            };
            match accepted {
                Some(Ok((stream, _addr))) => {
                    // On some platforms (observed on macOS/Darwin) a socket
                    // returned by `accept()` inherits the non-blocking flag
                    // of the *listening* socket, even though POSIX gives it
                    // a fresh open file description. `serve_client` (and
                    // Python's own `client.settimeout(30)`) needs ordinary
                    // blocking-with-timeout reads/writes, so force it back
                    // explicitly rather than relying on it starting that way.
                    let _ = stream.set_nonblocking(false);
                    self.handle_accepted(stream)
                }
                Some(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(ACCEPT_POLL_INTERVAL);
                    continue;
                }
                Some(Err(_)) => break,
                None => break, // `close()` already took the listener
            }
            if self.closed.load(Ordering::SeqCst) {
                break;
            }
        }
    }

    fn handle_accepted(self: &Arc<Self>, stream: UnixStream) {
        if self.closed.load(Ordering::SeqCst) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }
        let id = self.next_client_id.fetch_add(1, Ordering::SeqCst);
        let max = self.max_agent_clients.load(Ordering::SeqCst);
        let (admitted, done_tx) = {
            let mut clients = self.clients.lock().expect("clients mutex poisoned");
            if self.closed.load(Ordering::SeqCst) || clients.len() >= max {
                (false, None)
            } else {
                match stream.try_clone() {
                    Ok(dup) => {
                        // Register *before* the client can possibly be
                        // observed finishing: the `handle`/`done` slots are
                        // filled in below, but the entry itself -- and thus
                        // `close()`'s and `serve_client`'s own tail's view of
                        // which ids exist -- is created here, under the same
                        // lock that decided admission, strictly before
                        // `spawn` below can start the thread (finding
                        // G-R2-2; mirrors Python's `self._clients[thread] =
                        // client` before `thread.start()`).
                        let (done_tx, done_rx) = std::sync::mpsc::channel();
                        clients.insert(
                            id,
                            ClientSlot {
                                stream: dup,
                                handle: None,
                                done: Some(done_rx),
                            },
                        );
                        (true, Some(done_tx))
                    }
                    Err(_) => (false, None),
                }
            }
        };
        if !admitted {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            if !self.closed.load(Ordering::SeqCst) {
                // Never let auditing kill the accept loop.
                let _ = self.safe_audit(
                    "ssh_agent_refused",
                    "denied",
                    Some("too_many_agent_clients"),
                    None,
                    vec![("count", json!(max as i64))],
                );
            }
            return;
        }
        let done_tx = done_tx.expect("done_tx set whenever admitted is true");
        let worker = Arc::clone(self);
        match thread::Builder::new()
            .name(format!("zeropw-signer-client-{id}"))
            .spawn(move || worker.serve_client(id, stream, done_tx))
        {
            Ok(handle) => {
                // Late-bind the handle into the slot created above. If the
                // client already finished and removed its own entry (a
                // connect-then-disconnect can easily outrace this thread
                // getting the lock back), there is nothing left to bind it
                // into: just drop it rather than resurrect a stale entry
                // nothing will ever prune (finding G-R2-2) -- `JoinHandle`'s
                // `Drop` detaches, it does not block.
                let mut clients = self.clients.lock().expect("clients mutex poisoned");
                if let Some(slot) = clients.get_mut(&id) {
                    slot.handle = Some(handle);
                } else {
                    drop(handle);
                }
            }
            Err(_) => {
                self.clients
                    .lock()
                    .expect("clients mutex poisoned")
                    .remove(&id);
            }
        }
    }

    // ------------------------------------------------------------ serving
    fn serve_client(self: Arc<Self>, id: u64, client: UnixStream, done_tx: Sender<()>) {
        let _ = client.set_read_timeout(Some(CLIENT_IO_TIMEOUT));
        let _ = client.set_write_timeout(Some(CLIENT_IO_TIMEOUT));
        let mut conn = sshwire::AgentConnection::new(client);
        let mut state = ClientState::new();
        loop {
            if self.closed.load(Ordering::SeqCst) {
                break;
            }
            let message = match conn.read_message() {
                Ok(Some(m)) => m,
                Ok(None) => break,
                Err(sshwire::AgentError::Wire(_)) => {
                    let _ = self.safe_audit(
                        "ssh_agent_refused",
                        "denied",
                        Some("malformed_agent_message"),
                        None,
                        vec![],
                    );
                    break;
                }
                Err(sshwire::AgentError::Io(_)) => break,
            };
            if self.closed.load(Ordering::SeqCst) {
                break;
            }
            let reply = match self.handle_message(&mut state, &message) {
                Ok(bytes) => bytes,
                Err(_) => sshwire::build_failure().to_vec(),
            };
            if conn.write_message(&reply).is_err() {
                break;
            }
        }
        // Remove this client's whole slot (stream, handle-if-already-bound,
        // completion receiver) in one place: the single point that ever
        // removes a `clients` entry, so an id inserted at admission time
        // (finding G-R2-2) is always cleaned up exactly once, regardless of
        // whether `handle_accepted` had already late-bound the handle when
        // this runs.
        self.clients
            .lock()
            .expect("clients mutex poisoned")
            .remove(&id);
        // Signal completion *after* removing our own slot, right before
        // returning -- mirrors `accept_loop`'s `done_tx.send` -- so `close()`
        // never observes "done" for a slot that is not actually gone yet.
        let _ = done_tx.send(());
    }

    fn handle_message(&self, state: &mut ClientState, message: &[u8]) -> Result<Vec<u8>, Error> {
        let Some((&msg_type, rest)) = message.split_first() else {
            return Ok(sshwire::build_failure().to_vec());
        };
        match msg_type {
            sshwire::SSH_AGENTC_REQUEST_IDENTITIES => Ok(self.identities()),
            sshwire::SSH_AGENTC_EXTENSION => self.extension(state, rest),
            sshwire::SSH_AGENTC_SIGN_REQUEST => self.sign(state, rest),
            other => {
                let name = message_name(other);
                let _ = self.safe_audit(
                    "ssh_agent_refused",
                    "denied",
                    Some("unsupported_agent_message"),
                    None,
                    vec![("message_type", json!(name))],
                );
                Ok(sshwire::build_failure().to_vec())
            }
        }
    }

    // --------------------------------------------------------------- audit
    fn connection_labels(&self) -> (String, Option<i64>) {
        match self.ctx.policy.get_connection(&self.binding.connection_id) {
            Ok(conn) => {
                let target = match &conn.ssh_target {
                    Some(t) => format!("{}:{}", t.host, t.port),
                    None => "unknown".to_string(),
                };
                (target, Some(conn.policy_version))
            }
            Err(_) => ("unknown".to_string(), None),
        }
    }

    /// Port of `_BindingServer._audit`. `policy_version` is the version the
    /// decision was evaluated against; records written before a decision
    /// carry the bound connection's current version.
    fn audit(
        &self,
        event: &str,
        result: &str,
        reason: Option<&str>,
        policy_version: Option<i64>,
        extra: Vec<(&'static str, Value)>,
    ) -> Result<(), Error> {
        let (target, current_version) = self.connection_labels();
        let action = if event == "ssh_sign" {
            "ssh-sign".to_string()
        } else {
            event.to_string()
        };
        self.ctx.audit.record(
            event,
            RecordArgs {
                caller: Some(self.binding.caller.as_str()),
                connection: Some(self.binding.connection_id.as_str()),
                target: Some(target.as_str()),
                action: Some(action.as_str()),
                result: Some(result),
                reason,
                policy_version: policy_version.or(current_version),
                extra,
                ..Default::default()
            },
        )?;
        Ok(())
    }

    /// Port of `_BindingServer._safe_audit`: `Ok(true)` when written,
    /// `Ok(false)` when the audit log itself is unavailable (the only case
    /// Python's `except AuditUnavailable` catches), `Err(_)` for anything
    /// else (propagated, matching an uncaught Python exception).
    fn safe_audit(
        &self,
        event: &str,
        result: &str,
        reason: Option<&str>,
        policy_version: Option<i64>,
        extra: Vec<(&'static str, Value)>,
    ) -> Result<bool, Error> {
        match self.audit(event, result, reason, policy_version, extra) {
            Ok(()) => Ok(true),
            Err(e) if e.is(ErrorClass::AuditUnavailable) => Ok(false),
            Err(e) => Err(e),
        }
    }

    // ---------------------------------------------------------- identities
    fn connection(&self) -> Result<crate::policy::Connection, Error> {
        let conn = self
            .ctx
            .policy
            .get_connection(&self.binding.connection_id)?;
        if conn.kind != "ssh" || conn.ssh_target.is_none() {
            return Err(Error::unsupported("connection_not_ssh"));
        }
        Ok(conn)
    }

    /// Public key from vault metadata: no plaintext is touched to list
    /// identities.
    fn public_key(&self) -> Result<sshwire::Ed25519PublicKey, Error> {
        let conn = self.connection()?;
        let version = self
            .ctx
            .vault
            .resolve_version(&conn.secret_id, conn.secret_version)?;
        let meta = self.ctx.vault.get_meta(&conn.secret_id)?;
        for item in &meta.versions {
            if item.version == version {
                let line = item
                    .public
                    .get("public_key")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty());
                let Some(line) = line else {
                    return Err(Error::unsupported("ssh_key_metadata_missing"));
                };
                return Ok(sshwire::parse_authorized_key(line)?);
            }
        }
        Err(Error::not_found("secret_version_not_found"))
    }

    fn identities(&self) -> Vec<u8> {
        match self.public_key() {
            Ok(key) => sshwire::build_identities_answer(&[(
                key.blob(),
                format!("zeropw:{}", self.binding.connection_id),
            )]),
            Err(_) => sshwire::build_failure().to_vec(),
        }
    }

    // -------------------------------------------------------------- extension
    fn extension(&self, state: &mut ClientState, rest: &[u8]) -> Result<Vec<u8>, Error> {
        let (name, data) = match sshwire::parse_extension(rest) {
            Ok(v) => v,
            Err(_) => {
                let _ = self.safe_audit(
                    "ssh_agent_refused",
                    "denied",
                    Some("malformed_extension"),
                    None,
                    vec![],
                );
                return Ok(sshwire::build_failure().to_vec());
            }
        };
        if name == sshwire::EXTENSION_QUERY {
            return Ok(sshwire::build_extension_query_response(
                SUPPORTED_EXTENSIONS,
            ));
        }
        if name != sshwire::SESSION_BIND_EXTENSION {
            let truncated: String = name.chars().take(64).collect();
            let _ = self.safe_audit(
                "ssh_agent_refused",
                "denied",
                Some("unsupported_extension"),
                None,
                vec![("extension", json!(truncated))],
            );
            return Ok(sshwire::build_failure().to_vec());
        }
        self.session_bind(state, &data)
    }

    fn session_bind(&self, state: &mut ClientState, data: &[u8]) -> Result<Vec<u8>, Error> {
        state.bind_attempts += 1;
        let bind = match sshwire::parse_session_bind(data) {
            Ok(b) => b,
            Err(_) => {
                let _ = self.safe_audit(
                    "ssh_bind",
                    "denied",
                    Some("malformed_session_bind"),
                    None,
                    vec![],
                );
                return Ok(sshwire::build_failure().to_vec());
            }
        };
        if state.bound.is_some() {
            let _ = self.safe_audit(
                "ssh_bind",
                "denied",
                Some("session_already_bound"),
                None,
                vec![],
            );
            return Ok(sshwire::build_failure().to_vec());
        }
        if bind.is_forwarding {
            let _ = self.safe_audit(
                "ssh_bind",
                "denied",
                Some("agent_forwarding_not_allowed"),
                None,
                vec![],
            );
            return Ok(sshwire::build_failure().to_vec());
        }
        let conn = match self.connection() {
            Ok(c) => c,
            Err(_) => {
                let _ = self.safe_audit(
                    "ssh_bind",
                    "denied",
                    Some("host_key_unsupported"),
                    None,
                    vec![],
                );
                return Ok(sshwire::build_failure().to_vec());
            }
        };
        let host_key = match sshwire::parse_public_key_blob(&bind.host_key_blob) {
            Ok(k) => k,
            Err(_) => {
                let _ = self.safe_audit(
                    "ssh_bind",
                    "denied",
                    Some("host_key_unsupported"),
                    None,
                    vec![],
                );
                return Ok(sshwire::build_failure().to_vec());
            }
        };
        let ssh_target = conn
            .ssh_target
            .as_ref()
            .expect("connection() guarantees ssh_target for an ssh connection");
        let mut allowed = false;
        for line in &ssh_target.host_keys {
            if let Ok(entry_key) = sshwire::parse_authorized_key(line)
                && entry_key.key_bytes() == host_key.key_bytes()
            {
                allowed = true;
                break;
            }
        }
        if !allowed {
            let _ = self.safe_audit(
                "ssh_bind",
                "denied",
                Some("host_key_not_allowed"),
                None,
                vec![("fingerprint", json!(host_key.fingerprint()))],
            );
            return Ok(sshwire::build_failure().to_vec());
        }
        let raw_sig = match sshwire::parse_ssh_signature(&bind.signature) {
            Ok(s) => s,
            Err(_) => {
                let _ = self.safe_audit(
                    "ssh_bind",
                    "denied",
                    Some("host_signature_malformed"),
                    None,
                    vec![("fingerprint", json!(host_key.fingerprint()))],
                );
                return Ok(sshwire::build_failure().to_vec());
            }
        };
        if !ed25519::verify(host_key.key_bytes(), &bind.session_id, &raw_sig) {
            let _ = self.safe_audit(
                "ssh_bind",
                "denied",
                Some("host_signature_invalid"),
                None,
                vec![("fingerprint", json!(host_key.fingerprint()))],
            );
            return Ok(sshwire::build_failure().to_vec());
        }
        let decision = self.ctx.policy.evaluate(
            &self.binding.caller,
            &self.binding.connection_id,
            &Action::ssh(ssh_target.username.clone()),
            Some(&self.binding.grant_id),
        )?;
        if !decision.allowed {
            let _ = self.safe_audit(
                "ssh_bind",
                "denied",
                Some(decision.reason),
                decision.policy_version(),
                vec![("fingerprint", json!(host_key.fingerprint()))],
            );
            return Ok(sshwire::build_failure().to_vec());
        }
        if !self.safe_audit(
            "ssh_bind",
            "ok",
            None,
            decision.policy_version(),
            vec![
                ("fingerprint", json!(host_key.fingerprint())),
                ("username", json!(ssh_target.username)),
            ],
        )? {
            return Ok(sshwire::build_failure().to_vec());
        }
        state.bound = Some(bind);
        Ok(sshwire::build_success().to_vec())
    }

    // ------------------------------------------------------------------- sign
    fn sign(&self, state: &mut ClientState, rest: &[u8]) -> Result<Vec<u8>, Error> {
        let request = match sshwire::parse_sign_request(rest) {
            Ok(r) => r,
            Err(_) => {
                let _ = self.safe_audit(
                    "ssh_sign",
                    "denied",
                    Some("malformed_sign_request"),
                    None,
                    vec![],
                );
                return Ok(sshwire::build_failure().to_vec());
            }
        };
        if request.flags != 0 {
            let _ = self.safe_audit(
                "ssh_sign",
                "denied",
                Some("unsupported_sign_flags"),
                None,
                vec![],
            );
            return Ok(sshwire::build_failure().to_vec());
        }
        let conn = match self.connection() {
            Ok(c) => c,
            Err(_) => {
                let _ =
                    self.safe_audit("ssh_sign", "denied", Some("key_unavailable"), None, vec![]);
                return Ok(sshwire::build_failure().to_vec());
            }
        };
        let our_key = match self.public_key() {
            Ok(k) => k,
            Err(_) => {
                let _ =
                    self.safe_audit("ssh_sign", "denied", Some("key_unavailable"), None, vec![]);
                return Ok(sshwire::build_failure().to_vec());
            }
        };
        if request.key_blob != our_key.blob() {
            let _ = self.safe_audit("ssh_sign", "denied", Some("unknown_key"), None, vec![]);
            return Ok(sshwire::build_failure().to_vec());
        }
        let Some(bound) = state.bound.as_ref() else {
            let _ = self.safe_audit("ssh_sign", "denied", Some("no_session_bind"), None, vec![]);
            return Ok(sshwire::build_failure().to_vec());
        };
        let auth = match sshwire::parse_userauth_request(&request.data, true) {
            Ok(a) => a,
            Err(_) => {
                // Arbitrary data (including `ssh-add -T` probes) is never signed.
                let _ = self.safe_audit(
                    "ssh_sign",
                    "denied",
                    Some("not_userauth_request"),
                    None,
                    vec![],
                );
                return Ok(sshwire::build_failure().to_vec());
            }
        };
        if auth.session_id != bound.session_id {
            let _ = self.safe_audit("ssh_sign", "denied", Some("session_mismatch"), None, vec![]);
            return Ok(sshwire::build_failure().to_vec());
        }
        if let Some(host_blob) = &auth.host_key_blob
            && host_blob != &bound.host_key_blob
        {
            let _ = self.safe_audit(
                "ssh_sign",
                "denied",
                Some("hostbound_key_mismatch"),
                None,
                vec![],
            );
            return Ok(sshwire::build_failure().to_vec());
        }
        if auth.algorithm != SSH_ED25519 || auth.public_key_blob != our_key.blob() {
            let _ = self.safe_audit(
                "ssh_sign",
                "denied",
                Some("userauth_key_mismatch"),
                None,
                vec![],
            );
            return Ok(sshwire::build_failure().to_vec());
        }
        let ssh_target = conn
            .ssh_target
            .as_ref()
            .expect("connection() guarantees ssh_target for an ssh connection");
        if auth.username != ssh_target.username {
            let truncated: String = auth.username.chars().take(64).collect();
            let _ = self.safe_audit(
                "ssh_sign",
                "denied",
                Some("ssh_user_mismatch"),
                None,
                vec![("username", json!(truncated))],
            );
            return Ok(sshwire::build_failure().to_vec());
        }
        let decision = self.ctx.policy.evaluate(
            &self.binding.caller,
            &self.binding.connection_id,
            &Action::ssh(auth.username.clone()),
            Some(&self.binding.grant_id),
        )?;
        let pv = decision.policy_version();
        if !decision.allowed {
            let _ = self.safe_audit(
                "ssh_sign",
                "denied",
                Some(decision.reason),
                pv,
                vec![("username", json!(auth.username))],
            );
            return Ok(sshwire::build_failure().to_vec());
        }
        // Mandatory audit before the key is used; audit failure refuses the signature.
        if !self.safe_audit(
            "ssh_sign",
            "ok",
            None,
            pv,
            vec![
                ("username", json!(auth.username)),
                ("fingerprint", json!(our_key.fingerprint())),
                ("grant", json!(self.binding.grant_id)),
            ],
        )? {
            return Ok(sshwire::build_failure().to_vec());
        }
        match self
            .ctx
            .policy
            .consume(&self.binding.grant_id, None, None, None, None)
        {
            Ok(_) => {}
            Err(e) if e.is(ErrorClass::PolicyDenied) => {
                let reason = e.reason.to_string();
                let _ = self.safe_audit(
                    "ssh_sign",
                    "denied",
                    Some(&reason),
                    pv,
                    vec![("username", json!(auth.username))],
                );
                return Ok(sshwire::build_failure().to_vec());
            }
            Err(e) => return Err(e),
        }
        let pem = match self
            .ctx
            .vault
            .secret_for_trusted_use(&conn.secret_id, conn.secret_version)
        {
            Ok(v) => v,
            Err(_) => {
                let _ = self.safe_audit("ssh_sign", "denied", Some("key_unavailable"), pv, vec![]);
                return Ok(sshwire::build_failure().to_vec());
            }
        };
        // Already `SecretBytes` (zeroised on drop) straight from the vault.
        let private = match sshwire::parse_openssh_private_key(pem.expose()) {
            Ok(p) => p,
            Err(_) => {
                let _ = self.safe_audit("ssh_sign", "denied", Some("key_unavailable"), pv, vec![]);
                return Ok(sshwire::build_failure().to_vec());
            }
        };
        if private.public.key_bytes() != our_key.key_bytes() {
            let _ = self.safe_audit(
                "ssh_sign",
                "denied",
                Some("key_metadata_mismatch"),
                pv,
                vec![],
            );
            return Ok(sshwire::build_failure().to_vec());
        }
        let signature = private.sign(&request.data);
        let sig_blob = sshwire::encode_ssh_signature(&signature)
            .expect("a freshly produced 64-byte signature always encodes");
        Ok(sshwire::build_sign_response(&sig_blob))
    }

    /// Test-only probe for finding G-R3-3: whether `close()` has released the
    /// listening fd, independently of whether this `BindingServer` struct
    /// itself is still kept alive by some other `Arc` clone (e.g. a client
    /// thread detached past its join deadline).
    #[cfg(test)]
    fn listener_is_released(&self) -> bool {
        self.listener
            .lock()
            .expect("listener mutex poisoned")
            .is_none()
    }
}

// ---------------------------------------------------------------------------
// SignerManager
// ---------------------------------------------------------------------------

/// Insertion-ordered registry of live [`BindingServer`]s, keyed by socket
/// path. A plain `HashMap` iterates in an arbitrary (and, per Rust's
/// `RandomState`, per-process-random) order; Python's `dict` -- what
/// `SignerManager._servers` actually is -- preserves insertion order, and
/// `active_bindings`/`release_for_grant` both rely on iterating
/// `self._servers.values()` in that order (finding G-R2-4). `order` is the
/// source of truth for iteration order; `map` is the source of truth for
/// membership and lookup.
struct ServerRegistry {
    order: Vec<String>,
    map: HashMap<String, Arc<BindingServer>>,
}

impl ServerRegistry {
    fn new() -> Self {
        ServerRegistry {
            order: Vec::new(),
            map: HashMap::new(),
        }
    }

    /// Insert or replace. A replace (same key already present) does not move
    /// its position, matching Python `dict[key] = value`.
    fn insert(&mut self, key: String, server: Arc<BindingServer>) {
        if !self.map.contains_key(&key) {
            self.order.push(key.clone());
        }
        self.map.insert(key, server);
    }

    fn remove(&mut self, key: &str) -> Option<Arc<BindingServer>> {
        let removed = self.map.remove(key);
        if removed.is_some() {
            self.order.retain(|k| k != key);
        }
        removed
    }

    #[cfg(test)]
    fn get(&self, key: &str) -> Option<&Arc<BindingServer>> {
        self.map.get(key)
    }

    /// Servers in insertion order, matching Python's `dict.values()`.
    fn values_in_order(&self) -> impl Iterator<Item = &Arc<BindingServer>> {
        self.order.iter().filter_map(move |k| self.map.get(k))
    }

    /// Keys, in insertion order, whose server matches `grant_id` (`None`
    /// matches every key) -- the set `release_for_grant` closes, in the same
    /// order Python's `[s for s in self._servers.values() if ...]` would
    /// visit them.
    fn matching_keys(&self, grant_id: Option<&str>) -> Vec<String> {
        self.order
            .iter()
            .filter(|k| {
                self.map
                    .get(k.as_str())
                    .is_some_and(|s| grant_id.is_none_or(|g| s.binding.grant_id == g))
            })
            .cloned()
            .collect()
    }
}

/// Creates one dedicated agent socket per (caller, connection, grant)
/// binding. Port of `signer.SignerManager`.
pub struct SignerManager {
    ctx: &'static Context,
    socket_dir: PathBuf,
    servers: Mutex<ServerRegistry>,
    max_agent_clients: Arc<AtomicUsize>,
}

impl SignerManager {
    fn new(ctx: &'static Context, socket_dir: Option<PathBuf>) -> Result<Self, Error> {
        let preferred = socket_dir.or_else(|| ctx.config.socket_dir.clone());
        let socket_dir = choose_socket_dir(preferred)?;
        Ok(SignerManager {
            ctx,
            socket_dir,
            servers: Mutex::new(ServerRegistry::new()),
            max_agent_clients: Arc::new(AtomicUsize::new(DEFAULT_MAX_AGENT_CLIENTS)),
        })
    }

    pub fn socket_dir(&self) -> &Path {
        &self.socket_dir
    }

    /// Explicit seam replacing Python's mutable `MAX_AGENT_CLIENTS` module
    /// global (PORTING.md §3.4): scoped to this manager (and therefore to
    /// every socket it currently serves), not process-wide, so concurrent
    /// tests using separate managers cannot interfere with each other.
    pub fn set_max_agent_clients(&self, n: usize) {
        self.max_agent_clients.store(n, Ordering::SeqCst);
    }

    pub fn max_agent_clients(&self) -> usize {
        self.max_agent_clients.load(Ordering::SeqCst)
    }

    pub fn bind(
        self: &Arc<Self>,
        caller: &str,
        connection_id: &str,
        grant_id: &str,
    ) -> Result<SignerBinding, Error> {
        let conn = self.ctx.policy.get_connection(connection_id)?;
        if conn.kind != "ssh" {
            return Err(Error::unsupported("connection_not_ssh"));
        }
        let ssh_target = conn
            .ssh_target
            .as_ref()
            .expect("an ssh-kind connection always has ssh_target");
        let decision = self.ctx.policy.evaluate(
            caller,
            connection_id,
            &Action::ssh(ssh_target.username.clone()),
            Some(grant_id),
        )?;
        decision.require()?;
        let name = format!("a{}.sock", short_hex_id());
        let path = self.socket_dir.join(&name);
        // Measure *characters*, matching Python's `len(str(path))`: Python
        // `str` length counts Unicode code points, not encoded bytes.
        // `.to_string_lossy().len()` counts UTF-8 bytes instead, so a
        // non-ASCII `socket_dir` diverges from Python at exactly the
        // multi-byte characters that make the two counts differ (finding
        // G-R2-3).
        if path.to_string_lossy().chars().count() > MAX_UNIX_PATH + 3 {
            return Err(Error::unsupported("socket_path_too_long"));
        }
        let binding = SignerBinding {
            socket_path: path.clone(),
            caller: caller.to_string(),
            connection_id: connection_id.to_string(),
            grant_id: grant_id.to_string(),
            manager: Some(Arc::clone(self)),
        };
        let server = BindingServer::start(
            self.ctx,
            binding.clone(),
            Arc::clone(&self.max_agent_clients),
        )?;
        self.servers
            .lock()
            .expect("servers mutex poisoned")
            .insert(path.to_string_lossy().into_owned(), server);
        Ok(binding)
    }

    pub fn release(&self, binding: &SignerBinding) {
        let server = self
            .servers
            .lock()
            .expect("servers mutex poisoned")
            .remove(&binding.socket_path.to_string_lossy());
        if let Some(server) = server {
            server.close();
        }
    }

    pub fn active_bindings(&self) -> Vec<SignerBinding> {
        self.servers
            .lock()
            .expect("servers mutex poisoned")
            .values_in_order()
            .map(|s| s.binding.clone())
            .collect()
    }

    /// Close sockets for a revoked grant (or every socket when `grant_id` is
    /// `None`). Returns the number of sockets closed. Closes in the same
    /// (insertion) order the sockets were bound in, matching Python's `dict`
    /// iteration order (finding G-R2-4).
    pub fn release_for_grant(&self, grant_id: Option<&str>) -> usize {
        let victims: Vec<Arc<BindingServer>> = {
            let mut servers = self.servers.lock().expect("servers mutex poisoned");
            let keys = servers.matching_keys(grant_id);
            keys.iter().filter_map(|k| servers.remove(k)).collect()
        };
        for server in &victims {
            server.close();
        }
        victims.len()
    }

    pub fn shutdown(&self) {
        self.release_for_grant(None);
    }
}

/// Port of `signer.install`.
pub fn install(
    ctx: &'static Context,
    socket_dir: Option<PathBuf>,
) -> Result<Arc<SignerManager>, Error> {
    let manager = Arc::new(SignerManager::new(ctx, socket_dir)?);
    *ctx.signer_manager
        .lock()
        .expect("signer_manager mutex poisoned") = Some(Box::new(Arc::clone(&manager)));
    let listener_manager = Arc::clone(&manager);
    ctx.policy.on_revoke(move |kind, grant_id| {
        listener_manager.release_for_grant(if kind == "grant" { grant_id } else { None });
    });
    Ok(manager)
}

/// Port of `signer.socket_mode_ok`.
pub fn socket_mode_ok(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => meta.file_type().is_socket() && (meta.mode() & 0o077) == 0,
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Socket plumbing helpers
// ---------------------------------------------------------------------------

/// Port of `SignerManager._choose_socket_dir`. Both branches create their
/// leaf directory at mode 0700 atomically in the `mkdir` syscall itself (via
/// `DirBuilder::mode`, the same technique `context.rs`'s
/// `mkdir_private_0700`, `kms.rs` and `store.rs` already use), matching
/// Python's `Path.mkdir(mode=0o700, ...)` / `tempfile.mkdtemp` -- neither
/// leaves a window where the directory holding agent sockets is created at a
/// wider mode and only narrowed afterwards (finding G-2). Any *missing
/// parents* of the candidate path are still created at the process default
/// mode first, matching `Path.mkdir(parents=True)`'s own documented
/// behaviour of leaving intermediate parents at their default mode and only
/// applying the given `mode` to the final component.
fn choose_socket_dir(preferred: Option<PathBuf>) -> Result<PathBuf, Error> {
    if let Some(candidate) = preferred {
        let probe = candidate.join("s".repeat(24));
        // Characters, not UTF-8 bytes -- matches Python's `len(str(path))`
        // (finding G-R2-3; see `SignerManager::bind`'s identical fix).
        if probe.to_string_lossy().chars().count() <= MAX_UNIX_PATH {
            if let Some(parent) = candidate.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent).map_err(|e| {
                    Error::state("signer_socket_dir_failed").with_detail(e.to_string())
                })?;
            }
            mkdir_leaf_private_0700(&candidate)
                .map_err(|e| Error::state("signer_socket_dir_failed").with_detail(e.to_string()))?;
            // Defensive backstop against a masking umask, same as
            // `context.rs`'s `create_private_dir`; the `mkdir` syscall above
            // already requested 0700 directly, so this is redundant in the
            // common case, not the primary guarantee.
            std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| Error::state("signer_socket_dir_failed").with_detail(e.to_string()))?;
            return Ok(candidate);
        }
    }
    let short = make_temp_dir("zpws-")?;
    std::fs::set_permissions(&short, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::state("signer_socket_dir_failed").with_detail(e.to_string()))?;
    Ok(short)
}

/// Create `path` at mode 0700 atomically (`DirBuilder::mode`), treating an
/// already-existing *directory* at that path as success -- Python's
/// `exist_ok=True` -- while still erroring if something else (e.g. a
/// regular file) occupies it, since a bare `AlreadyExists` from a
/// non-recursive `DirBuilder::create` cannot itself distinguish the two.
fn mkdir_leaf_private_0700(path: &Path) -> std::io::Result<()> {
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if std::fs::metadata(path).is_ok_and(|m| m.is_dir()) {
                Ok(())
            } else {
                Err(e)
            }
        }
        Err(e) => Err(e),
    }
}

/// Port of the fallback branch of `SignerManager._choose_socket_dir`
/// (`tempfile.mkdtemp(prefix="zpws-")`). Python's `mkdtemp` names its
/// directory with an 8-character random suffix; this used to encode 8
/// random *bytes* as hex (16 characters), making the resulting path 8 bytes
/// longer than Python's and shifting exactly where the `MAX_UNIX_PATH`
/// length check trips relative to Python (finding G-3). Encoding 4 random
/// bytes as hex instead yields the same 8-character suffix length as
/// Python's (the alphabet differs -- hex vs. Python's own candidate
/// charset -- but no caller depends on anything beyond length and
/// uniqueness).
fn make_temp_dir(prefix: &str) -> Result<PathBuf, Error> {
    let base = std::env::temp_dir();
    for _ in 0..64 {
        let mut suffix = [0u8; 4];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut suffix);
        let path = base.join(format!("{prefix}{}", hex::encode(suffix)));
        match std::fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(Error::state("signer_socket_dir_failed").with_detail(e.to_string()));
            }
        }
    }
    Err(Error::state("signer_socket_dir_failed").with_detail("tempdir"))
}

fn short_hex_id() -> String {
    let mut buf = [0u8; 6];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Bind and chmod 0600. `BindingServer::start` sets the returned listener
/// non-blocking right after this returns (finding G-R3-1): `accept_loop`
/// polls it every `ACCEPT_POLL_INTERVAL` rather than blocking in `accept()`,
/// so `close()` can wake it by simply taking the listener away, with no
/// durable connectable alias needed. See the module doc comment for the
/// umask/backlog deviations from Python's `socket.bind`/`listen(16)`.
fn bind_and_listen(path: &Path) -> Result<UnixListener, Error> {
    let listener = UnixListener::bind(path)
        .map_err(|e| Error::state("signer_socket_bind_failed").with_detail(e.to_string()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::state("signer_socket_bind_failed").with_detail(e.to_string()))?;
    Ok(listener)
}

// ---------------------------------------------------------------------------
// Tests: port of tests/test_signer.py.
//
// These live as unit tests (not `rust/tests/*.rs`) because several Python
// cases inspect `_BindingServer`'s private `_threads`/`_clients` state
// directly (`server._threads`, `server._clients`); an integration test
// cannot reach private crate items. Oracle/differential tests and the real
// sshd/ssh end-to-end test live under `rust/tests/` instead.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::sync::Mutex as StdMutex;
    use std::time::{Duration, Instant};

    use tempfile::TempDir;

    use super::*;
    use crate::clock::Clock;
    use crate::context::Config;
    use crate::errors::ErrorClass;
    use crate::policy as P;
    use crate::projects::DEFAULT_ENVIRONMENTS;

    const ADMIN: &str = "admin-passphrase-1";
    const RECOVERY: &str = "recovery-passphrase-1";

    fn make_clock(val: &Arc<StdMutex<f64>>) -> Clock {
        let val = val.clone();
        Arc::new(move || *val.lock().unwrap())
    }

    struct Fixture {
        _tmp: TempDir,
        ctx: &'static Context,
        clock_val: Arc<StdMutex<f64>>,
        user_key: sshwire::Ed25519PrivateKey,
        host_key: sshwire::Ed25519PrivateKey,
        other_host_key: sshwire::Ed25519PrivateKey,
        grant: P::Grant,
        manager: Arc<SignerManager>,
        binding: SignerBinding,
        session_id: Vec<u8>,
    }

    /// Port of `tests/test_signer.py`'s `SignerTestCase.tearDown`, which
    /// calls `shutdown()` on every one of the 22 ported cases below (finding
    /// G-R3-4: this fixture used to call neither `shutdown()` nor anything
    /// else, so none of that teardown path -- `shutdown()` ->
    /// `release_for_grant(None)` -> `BindingServer::close()` for every socket
    /// a test bound, including ones beyond `binding` itself -- was ever
    /// exercised).
    ///
    /// Does not also call `Context::close()` on `ctx`: it is `Box::leak`ed
    /// to satisfy `signer::install`'s `&'static Context` requirement (itself
    /// forced by `BindingServer` capturing it in real OS threads via
    /// `thread::spawn`'s own 'static bound, not a choice this module makes),
    /// and safe Rust has no way to reclaim a `&mut Context` once a
    /// `&'static Context` derived from it has been shared that way -- that
    /// would need `unsafe` pointer reconstruction, which `rust/PORTING.md`
    /// forbids outside `store.rs`. `fixture()` gives `Context` explicit
    /// `socket_dir`/`run_dir` under `_tmp` instead, so it never allocates
    /// anything `close()` would have needed to remove; `_tmp`'s own
    /// ordinary `Drop` (which runs after this impl's body, since fields drop
    /// after a type's own `Drop::drop`) removes the state dir and every
    /// socket the signer created, closing the gap that left 229 leftover
    /// `zpws-ctl-*` directories (round 2's now-withdrawn `control_dir`) and
    /// unbounded `zeropw-sockets-*`/`zeropw-runs-*` directories (this
    /// fixture's own leaked `Context`) behind on this machine.
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.manager.shutdown();
        }
    }

    impl Fixture {
        fn advance(&self, delta: f64) {
            *self.clock_val.lock().unwrap() += delta;
        }

        fn connect(&self) -> sshwire::AgentConnection<UnixStream> {
            let sock =
                UnixStream::connect(&self.binding.socket_path).expect("connect to signer socket");
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            sock.set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            sshwire::AgentConnection::new(sock)
        }

        fn bind_message_for(
            &self,
            host_key: &sshwire::Ed25519PrivateKey,
            session_id: &[u8],
            forwarding: bool,
            bad_signature: bool,
        ) -> Vec<u8> {
            let mut sig = host_key.sign(session_id).to_vec();
            if bad_signature {
                sig[0] ^= 1;
            }
            sshwire::build_session_bind(
                &host_key.public.blob(),
                session_id,
                &sshwire::encode_ssh_signature(&sig).unwrap(),
                forwarding,
            )
        }

        fn bind_message(&self) -> Vec<u8> {
            self.bind_message_for(&self.host_key, &self.session_id, false, false)
        }

        fn userauth_for(
            &self,
            username: &str,
            session_id: &[u8],
            algorithm: &str,
            key_blob: &[u8],
            hostbound: Option<&[u8]>,
        ) -> Vec<u8> {
            sshwire::build_userauth_request(
                session_id,
                username,
                algorithm,
                key_blob,
                sshwire::SSH_CONNECTION_SERVICE,
                hostbound,
            )
        }

        fn userauth(&self) -> Vec<u8> {
            self.userauth_for(
                "deploy",
                &self.session_id,
                SSH_ED25519,
                &self.user_key.public.blob(),
                None,
            )
        }

        fn sign_req(
            &self,
            conn: &mut sshwire::AgentConnection<UnixStream>,
            data: &[u8],
            flags: u32,
            key_blob: Option<&[u8]>,
        ) -> Vec<u8> {
            let blob = key_blob.unwrap_or(&self.user_key.public.blob()).to_vec();
            conn.request(&sshwire::build_sign_request(&blob, data, flags))
                .expect("sign request round trip")
        }

        fn audit_reasons(&self) -> Vec<Option<String>> {
            self.ctx
                .audit
                .tail(200)
                .unwrap()
                .into_iter()
                .filter(|r| {
                    matches!(
                        r["event"].as_str(),
                        Some("ssh_sign") | Some("ssh_bind") | Some("ssh_agent_refused")
                    )
                })
                .map(|r| r.get("reason").and_then(|v| v.as_str()).map(str::to_string))
                .collect()
        }

        fn has_reason(&self, reason: &str) -> bool {
            self.audit_reasons()
                .iter()
                .any(|r| r.as_deref() == Some(reason))
        }

        fn server(&self) -> Arc<BindingServer> {
            self.manager
                .servers
                .lock()
                .unwrap()
                .get(&self.binding.socket_path.to_string_lossy())
                .cloned()
                .expect("server for current binding")
        }

        fn wait_until(&self, mut predicate: impl FnMut() -> bool, timeout: Duration) -> bool {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                if predicate() {
                    return true;
                }
                thread::sleep(Duration::from_millis(10));
            }
            predicate()
        }
    }

    fn fixture() -> Fixture {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().to_path_buf();
        let clock_val = Arc::new(StdMutex::new(1_700_000_000.0));
        let clock = make_clock(&clock_val);
        // Explicit `socket_dir`/`run_dir` under `root` (see `Drop for
        // Fixture` above, finding G-R3-4): otherwise `Context::initialize`
        // would default them to fresh private temp dirs under the *system*
        // temp dir that this leaked, never-`close()`-able `Context` would
        // then never clean up.
        let config = Config {
            socket_dir: Some(root.join("ctx-sockets")),
            run_dir: Some(root.join("ctx-run")),
            ..Config::default()
        };
        let ctx: &'static Context = Box::leak(Box::new(
            Context::initialize(root.join("state"), ADMIN, RECOVERY, config, clock).unwrap(),
        ));
        ctx.projects.create("demo", DEFAULT_ENVIRONMENTS).unwrap();
        let user_key = sshwire::generate_ed25519_private_key("agent-key");
        let host_key = sshwire::generate_ed25519_private_key("host");
        let other_host_key = sshwire::generate_ed25519_private_key("other-host");
        ctx.vault
            .put_secret(
                "box-key",
                "ssh_private_key",
                user_key.to_openssh_private_key().as_bytes(),
                "demo",
                "dev",
                true,
            )
            .unwrap();
        ctx.policy.create_principal("agent-1", "default").unwrap();
        ctx.policy
            .create_connection(
                P::Connection::new(
                    "box",
                    "demo",
                    "dev",
                    "ssh-box",
                    "ssh",
                    "box-key",
                    None,
                    "",
                    None,
                    None,
                    None,
                    Some(
                        P::SshTarget::new(
                            "127.0.0.1",
                            2222,
                            "deploy",
                            vec![host_key.public.to_authorized_key("host").unwrap()],
                        )
                        .unwrap(),
                    ),
                    None,
                    0,
                    "active",
                    "",
                    "",
                )
                .unwrap(),
            )
            .unwrap();
        let grant = ctx
            .policy
            .create_grant("agent-1", "box", Some(3600), Some(5))
            .unwrap();
        let manager = install(ctx, None).unwrap();
        let binding = manager.bind("agent-1", "box", &grant.id).unwrap();
        let session_id = {
            use rand::RngCore;
            let mut s = vec![0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut s);
            s
        };
        Fixture {
            _tmp: tmp,
            ctx,
            clock_val,
            user_key,
            host_key,
            other_host_key,
            grant,
            manager,
            binding,
            session_id,
        }
    }

    // Port of test_socket_is_private
    #[test]
    fn socket_is_private() {
        let f = fixture();
        assert!(socket_mode_ok(&f.binding.socket_path));
        assert_eq!(
            std::fs::metadata(f.manager.socket_dir()).unwrap().mode() & 0o077,
            0
        );
    }

    // Regression test for finding G-2: `choose_socket_dir`'s preferred-path
    // branch used to `create_dir_all` at the process default mode and only
    // `chmod` to 0700 afterwards, leaving a window where the directory
    // holding agent sockets was world-traversable. `mkdir_leaf_private_0700`
    // now requests mode 0700 in the `mkdir` syscall itself (`DirBuilder::mode`),
    // so the mode is correct immediately after creation, with no separate
    // narrowing step needed for it to already hold. Also exercises a missing
    // parent (`parents=True`'s job in Python), which stays at the process
    // default mode per `Path.mkdir(parents=True)`'s own documented
    // behaviour -- only the leaf gets 0700.
    #[test]
    fn choose_socket_dir_sets_leaf_mode_0700_immediately_after_creation() {
        // A short, literal `/tmp`-rooted base: `TempDir::new()` places its
        // directory under the platform `TMPDIR` (on macOS, a long
        // per-process path), which can itself already exceed the probe this
        // test needs room under (`MAX_UNIX_PATH`, the same bind-time length
        // budget `choose_socket_dir` itself enforces) once a nested missing
        // parent is appended.
        let base = PathBuf::from("/tmp").join(format!("zpws-test-{}", short_hex_id()));
        let candidate = base.join("missing-parent").join("sockdir");
        assert!(!candidate.parent().unwrap().exists());
        let dir = choose_socket_dir(Some(candidate.clone())).unwrap();
        assert_eq!(dir, candidate);
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "leaf directory mode immediately after creation"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    // Calling `choose_socket_dir` again for an already-existing directory
    // (the common case: a `SignerManager` re-created against the same
    // configured `socket_dir`) must still succeed, matching Python's
    // `exist_ok=True`.
    #[test]
    fn choose_socket_dir_is_idempotent_for_an_existing_directory() {
        let candidate = PathBuf::from("/tmp").join(format!("zpws-test-{}", short_hex_id()));
        choose_socket_dir(Some(candidate.clone())).unwrap();
        let dir = choose_socket_dir(Some(candidate.clone())).unwrap();
        assert_eq!(dir, candidate);
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        std::fs::remove_dir_all(&candidate).unwrap();
    }

    // Regression test for finding G-3: the fallback branch's random
    // directory suffix used to be 8 raw bytes hex-encoded (16 characters),
    // 8 bytes longer than Python's `tempfile.mkdtemp(prefix="zpws-")` own
    // 8-character suffix, which shifts exactly where the `MAX_UNIX_PATH`
    // bind-time length check trips relative to Python. Also covers G-2 for
    // this branch: mode 0700 immediately after creation.
    #[test]
    fn make_temp_dir_suffix_length_matches_python_mkdtemp() {
        let python_suffix_len: usize = crate::oracle::python(
            "import tempfile, os\n\
             path = tempfile.mkdtemp(prefix='zpws-')\n\
             print(len(os.path.basename(path)) - len('zpws-'))\n\
             os.rmdir(path)",
        )
        .trim()
        .parse()
        .expect("python prints an integer suffix length");
        let dir = choose_socket_dir(None).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "fallback directory mode immediately after creation"
        );
        let name = dir.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("zpws-"), "{name}");
        let rust_suffix_len = name.len() - "zpws-".len();
        assert_eq!(rust_suffix_len, python_suffix_len);
        std::fs::remove_dir(&dir).unwrap();
    }

    // Port of test_identities_lists_only_the_bound_key_without_touching_plaintext
    #[test]
    fn identities_lists_only_the_bound_key_without_touching_plaintext() {
        let f = fixture();
        let mut conn = f.connect();
        let reply = conn
            .request(&[sshwire::SSH_AGENTC_REQUEST_IDENTITIES])
            .unwrap();
        assert_eq!(reply[0], sshwire::SSH_AGENT_IDENTITIES_ANSWER);
        let keys = sshwire::parse_identities_answer(&reply[1..]).unwrap();
        assert_eq!(
            keys,
            vec![(f.user_key.public.blob(), "zeropw:box".to_string())]
        );
    }

    // Port of test_bind_then_sign_produces_valid_signature
    #[test]
    fn bind_then_sign_produces_valid_signature() {
        let f = fixture();
        {
            let mut conn = f.connect();
            assert_eq!(
                conn.request(&f.bind_message()).unwrap(),
                sshwire::build_success()
            );
            let data = f.userauth();
            let reply = f.sign_req(&mut conn, &data, 0, None);
            assert_eq!(reply[0], sshwire::SSH_AGENT_SIGN_RESPONSE);
            let sig =
                sshwire::parse_ssh_signature(&sshwire::parse_sign_response(&reply[1..]).unwrap())
                    .unwrap();
            assert!(ed25519::verify(f.user_key.public.key_bytes(), &data, &sig));
            let hostbound = f.userauth_for(
                "deploy",
                &f.session_id,
                SSH_ED25519,
                &f.user_key.public.blob(),
                Some(&f.host_key.public.blob()),
            );
            let reply = f.sign_req(&mut conn, &hostbound, 0, None);
            assert_eq!(reply[0], sshwire::SSH_AGENT_SIGN_RESPONSE);
        }
        assert_eq!(f.ctx.policy.get_grant(&f.grant.id).unwrap().uses, 2);
        let events: Vec<_> = f
            .ctx
            .audit
            .tail(50)
            .unwrap()
            .into_iter()
            .filter(|r| r["event"] == "ssh_sign" && r["result"] == "ok")
            .collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["username"], "deploy");
        let raw =
            std::fs::read_to_string(f.ctx.state.path.join("audit").join("audit.jsonl")).unwrap();
        assert!(!raw.contains(&hex::encode(f.user_key.seed().expose())));
        assert!(!raw.contains("PRIVATE KEY"));
    }

    // Port of test_extension_query_advertises_session_bind
    #[test]
    fn extension_query_advertises_session_bind() {
        let f = fixture();
        let mut conn = f.connect();
        let reply = conn.request(&sshwire::build_extension_query()).unwrap();
        assert_eq!(
            sshwire::parse_extension_query_response(&reply[1..]).unwrap(),
            vec![sshwire::SESSION_BIND_EXTENSION.to_string()]
        );
    }

    // Port of test_sign_without_bind_refused
    #[test]
    fn sign_without_bind_refused() {
        let f = fixture();
        let mut conn = f.connect();
        let data = f.userauth();
        assert_eq!(
            f.sign_req(&mut conn, &data, 0, None),
            sshwire::build_failure()
        );
        assert!(f.has_reason("no_session_bind"));
    }

    // Port of test_arbitrary_data_never_signed
    #[test]
    fn arbitrary_data_never_signed() {
        let f = fixture();
        let mut conn = f.connect();
        conn.request(&f.bind_message()).unwrap();
        assert_eq!(
            f.sign_req(&mut conn, b"please sign this arbitrary blob", 0, None),
            sshwire::build_failure()
        );
        let mut trailing = f.userauth();
        trailing.extend_from_slice(b"trailing");
        assert_eq!(
            f.sign_req(&mut conn, &trailing, 0, None),
            sshwire::build_failure()
        );
        assert_eq!(
            f.sign_req(&mut conn, b"", 0, None),
            sshwire::build_failure()
        );
        assert!(f.has_reason("not_userauth_request"));
    }

    // Port of test_destination_binding
    #[test]
    fn destination_binding() {
        let f = fixture();
        {
            let mut conn = f.connect();
            let msg = f.bind_message_for(&f.other_host_key, &f.session_id, false, false);
            assert_eq!(conn.request(&msg).unwrap(), sshwire::build_failure());
            let data = f.userauth();
            assert_eq!(
                f.sign_req(&mut conn, &data, 0, None),
                sshwire::build_failure()
            );
        }
        assert!(f.has_reason("host_key_not_allowed"));
        {
            let mut conn = f.connect();
            let msg = f.bind_message_for(&f.host_key, &f.session_id, false, true);
            assert_eq!(conn.request(&msg).unwrap(), sshwire::build_failure());
        }
        assert!(f.has_reason("host_signature_invalid"));
    }

    // Port of test_session_binding_and_reuse
    #[test]
    fn session_binding_and_reuse() {
        let f = fixture();
        {
            let mut conn = f.connect();
            conn.request(&f.bind_message()).unwrap();
            let other_session = {
                use rand::RngCore;
                let mut s = vec![0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut s);
                s
            };
            let data = f.userauth_for(
                "deploy",
                &other_session,
                SSH_ED25519,
                &f.user_key.public.blob(),
                None,
            );
            assert_eq!(
                f.sign_req(&mut conn, &data, 0, None),
                sshwire::build_failure()
            );
            let rebind = f.bind_message_for(&f.host_key, &other_session, false, false);
            assert_eq!(conn.request(&rebind).unwrap(), sshwire::build_failure());
            let hostbound = f.userauth_for(
                "deploy",
                &f.session_id,
                SSH_ED25519,
                &f.user_key.public.blob(),
                Some(&f.other_host_key.public.blob()),
            );
            assert_eq!(
                f.sign_req(&mut conn, &hostbound, 0, None),
                sshwire::build_failure()
            );
        }
        let reasons = f.audit_reasons();
        let has = |r: &str| reasons.iter().any(|x| x.as_deref() == Some(r));
        assert!(has("session_mismatch"));
        assert!(has("session_already_bound"));
        assert!(has("hostbound_key_mismatch"));
        {
            let mut conn = f.connect();
            let data = f.userauth();
            assert_eq!(
                f.sign_req(&mut conn, &data, 0, None),
                sshwire::build_failure()
            );
        }
    }

    // Port of test_forwarding_bind_refused
    #[test]
    fn forwarding_bind_refused() {
        let f = fixture();
        let mut conn = f.connect();
        let msg = f.bind_message_for(&f.host_key, &f.session_id, true, false);
        assert_eq!(conn.request(&msg).unwrap(), sshwire::build_failure());
        let data = f.userauth();
        assert_eq!(
            f.sign_req(&mut conn, &data, 0, None),
            sshwire::build_failure()
        );
        assert!(f.has_reason("agent_forwarding_not_allowed"));
    }

    // Port of test_username_algorithm_key_and_flags_bound
    #[test]
    fn username_algorithm_key_and_flags_bound() {
        let f = fixture();
        let other = sshwire::generate_ed25519_private_key("other");
        let mut conn = f.connect();
        conn.request(&f.bind_message()).unwrap();
        let bad_user = f.userauth_for(
            "root",
            &f.session_id,
            SSH_ED25519,
            &f.user_key.public.blob(),
            None,
        );
        assert_eq!(
            f.sign_req(&mut conn, &bad_user, 0, None),
            sshwire::build_failure()
        );
        let bad_alg = f.userauth_for(
            "deploy",
            &f.session_id,
            "ssh-rsa",
            &f.user_key.public.blob(),
            None,
        );
        assert_eq!(
            f.sign_req(&mut conn, &bad_alg, 0, None),
            sshwire::build_failure()
        );
        let bad_key = f.userauth_for(
            "deploy",
            &f.session_id,
            SSH_ED25519,
            &other.public.blob(),
            None,
        );
        assert_eq!(
            f.sign_req(&mut conn, &bad_key, 0, None),
            sshwire::build_failure()
        );
        let data = f.userauth();
        assert_eq!(
            f.sign_req(&mut conn, &data, 0, Some(&other.public.blob())),
            sshwire::build_failure()
        );
        assert_eq!(
            f.sign_req(&mut conn, &data, 2, None),
            sshwire::build_failure()
        );
        assert_eq!(
            f.sign_req(&mut conn, &data, 0, None)[0],
            sshwire::SSH_AGENT_SIGN_RESPONSE
        );
        let reasons = f.audit_reasons();
        for expected in [
            "ssh_user_mismatch",
            "userauth_key_mismatch",
            "unknown_key",
            "unsupported_sign_flags",
        ] {
            assert!(
                reasons.iter().any(|r| r.as_deref() == Some(expected)),
                "{expected}"
            );
        }
    }

    // Port of test_key_management_messages_refused
    #[test]
    fn key_management_messages_refused() {
        let f = fixture();
        let mut conn = f.connect();
        for msg_type in [
            sshwire::SSH_AGENTC_ADD_IDENTITY,
            sshwire::SSH_AGENTC_REMOVE_IDENTITY,
            sshwire::SSH_AGENTC_REMOVE_ALL_IDENTITIES,
            sshwire::SSH_AGENTC_LOCK,
            sshwire::SSH_AGENTC_UNLOCK,
            sshwire::SSH_AGENTC_ADD_ID_CONSTRAINED,
            sshwire::SSH_AGENTC_ADD_SMARTCARD_KEY,
            1,
            2,
            3,
            99,
        ] {
            let mut payload = vec![msg_type];
            payload.extend_from_slice(&[0u8; 8]);
            assert_eq!(
                conn.request(&payload).unwrap(),
                sshwire::build_failure(),
                "msg_type {msg_type}"
            );
        }
        let mut unknown_ext = vec![sshwire::SSH_AGENTC_EXTENSION];
        unknown_ext.extend(sshwire::encode_string("nope").unwrap());
        assert_eq!(
            conn.request(&unknown_ext).unwrap(),
            sshwire::build_failure()
        );
        assert_eq!(
            conn.request(&f.bind_message()).unwrap(),
            sshwire::build_success()
        );
    }

    // Port of test_malformed_and_oversized_messages_do_not_crash_server
    #[test]
    fn malformed_and_oversized_messages_do_not_crash_server() {
        let f = fixture();
        {
            let mut sock = UnixStream::connect(&f.binding.socket_path).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut payload =
                sshwire::encode_uint32((sshwire::MAX_AGENT_MESSAGE + 1) as u32).to_vec();
            payload.push(0x0d);
            sock.write_all(&payload).unwrap();
            let mut buf = [0u8; 1024];
            let reply = match sock.read(&mut buf) {
                Ok(n) => buf[..n].to_vec(),
                Err(_) => Vec::new(), // Linux reports a reset; macOS a clean EOF
            };
            assert!(reply.is_empty());
        }
        let mut conn = f.connect();
        let mut truncated = vec![sshwire::SSH_AGENTC_SIGN_REQUEST];
        truncated.extend_from_slice(&[0xff, 0xff]);
        assert_eq!(conn.request(&truncated).unwrap(), sshwire::build_failure());
        let mut half_ext = vec![sshwire::SSH_AGENTC_EXTENSION];
        half_ext.extend(sshwire::encode_string(sshwire::SESSION_BIND_EXTENSION).unwrap());
        half_ext.push(0x01);
        assert_eq!(conn.request(&half_ext).unwrap(), sshwire::build_failure());
        assert_eq!(
            conn.request(&f.bind_message()).unwrap(),
            sshwire::build_success()
        );
    }

    // Port of test_policy_checked_at_bind_and_sign_time
    #[test]
    fn policy_checked_at_bind_and_sign_time() {
        let mut f = fixture();
        {
            let mut conn = f.connect();
            conn.request(&f.bind_message()).unwrap();
            let data = f.userauth();
            assert_eq!(
                f.sign_req(&mut conn, &data, 0, None)[0],
                sshwire::SSH_AGENT_SIGN_RESPONSE
            );
            f.advance(3600.0);
            assert_eq!(
                f.sign_req(&mut conn, &data, 0, None),
                sshwire::build_failure()
            );
            assert!(f.has_reason("grant_expired"));
            f.advance(-3600.0);
            assert_eq!(
                f.sign_req(&mut conn, &data, 0, None)[0],
                sshwire::SSH_AGENT_SIGN_RESPONSE
            );
        }
        f.ctx.policy.stop_all().unwrap();
        assert!(!f.binding.socket_path.exists());
        assert!(UnixStream::connect(&f.binding.socket_path).is_err());
        assert!(
            f.manager
                .bind("agent-1", "box", &f.grant.id)
                .is_err_and(|e| e.is(ErrorClass::PolicyDenied))
        );
        f.ctx.policy.resume().unwrap();
        f.binding = f.manager.bind("agent-1", "box", &f.grant.id).unwrap();
        {
            let mut conn = f.connect();
            conn.request(&f.bind_message()).unwrap();
            let data = f.userauth();
            assert_eq!(
                f.sign_req(&mut conn, &data, 0, None)[0],
                sshwire::SSH_AGENT_SIGN_RESPONSE
            );
        }
        f.ctx.policy.revoke_grant(&f.grant.id).unwrap();
        assert!(!f.binding.socket_path.exists());
        assert!(UnixStream::connect(&f.binding.socket_path).is_err());
    }

    // Port of test_usage_cap_enforced_per_signature
    #[test]
    fn usage_cap_enforced_per_signature() {
        let f = fixture();
        let mut conn = f.connect();
        conn.request(&f.bind_message()).unwrap();
        let data = f.userauth();
        for _ in 0..5 {
            assert_eq!(
                f.sign_req(&mut conn, &data, 0, None)[0],
                sshwire::SSH_AGENT_SIGN_RESPONSE
            );
        }
        assert_eq!(
            f.sign_req(&mut conn, &data, 0, None),
            sshwire::build_failure()
        );
        assert!(f.has_reason("grant_exhausted"));
    }

    // Port of test_bind_refuses_non_ssh_connection_and_denied_grant
    #[test]
    fn bind_refuses_non_ssh_connection_and_denied_grant() {
        let f = fixture();
        f.ctx
            .policy
            .create_connection(
                P::Connection::new(
                    "web",
                    "demo",
                    "dev",
                    "fake",
                    "http",
                    "box-key",
                    None,
                    "",
                    Some(P::HttpTarget::new("http", "127.0.0.1", 1, None, false).unwrap()),
                    Some(P::HttpAuth::bearer()),
                    Some(P::HttpScope::new(None, None, vec![]).unwrap()),
                    None,
                    None,
                    0,
                    "active",
                    "",
                    "",
                )
                .unwrap(),
            )
            .unwrap();
        assert!(
            f.manager
                .bind("agent-1", "web", &f.grant.id)
                .is_err_and(|e| e.is(ErrorClass::Unsupported))
        );
        assert!(
            f.manager
                .bind("agent-2", "box", &f.grant.id)
                .is_err_and(|e| e.is(ErrorClass::PolicyDenied))
        );
        f.ctx.policy.stop_all().unwrap();
        assert!(
            f.manager
                .bind("agent-1", "box", &f.grant.id)
                .is_err_and(|e| e.is(ErrorClass::PolicyDenied))
        );
    }

    // Port of test_audit_failure_refuses_signature. Python monkeypatches
    // `StateDir.append_line`; that is not possible on a Rust struct, so this
    // points the audit log at a path a regular file occupies instead
    // (same technique as `audit::tests::write_failure_raises_audit_unavailable`).
    #[test]
    fn audit_failure_refuses_signature() {
        let f = fixture();
        let mut conn = f.connect();
        conn.request(&f.bind_message()).unwrap();
        let audit_dir = f.ctx.state.path.join("audit");
        let audit_file = audit_dir.join("audit.jsonl");
        std::fs::remove_file(&audit_file).unwrap();
        std::fs::remove_dir(&audit_dir).unwrap();
        std::fs::write(&audit_dir, b"blocking file").unwrap();
        let data = f.userauth();
        let result = f.sign_req(&mut conn, &data, 0, None);
        std::fs::remove_file(&audit_dir).unwrap();
        std::fs::create_dir_all(&audit_dir).unwrap();
        assert_eq!(result, sshwire::build_failure());
        assert_eq!(f.ctx.policy.get_grant(&f.grant.id).unwrap().uses, 0);
    }

    // Port of test_release_removes_socket
    #[test]
    fn release_removes_socket() {
        let f = fixture();
        let path = f.binding.socket_path.clone();
        f.binding.close();
        assert!(!path.exists());
        assert!(f.manager.active_bindings().is_empty());
    }

    // Regression test for finding G-R2-4: `SignerManager.servers` used to be
    // a plain `HashMap`, which iterates in an arbitrary (per-process-random)
    // order; Python's `dict` -- what `_servers` actually is -- preserves
    // insertion order, and `active_bindings`/`release_for_grant` both rely on
    // that order. Six bindings is the same scale the reviewer's probe used to
    // observe a random permutation.
    #[test]
    fn active_bindings_and_release_for_grant_preserve_insertion_order() {
        let f = fixture();
        let mut expected = vec![f.binding.socket_path.clone()];
        for _ in 0..5 {
            let b = f.manager.bind("agent-1", "box", &f.grant.id).unwrap();
            expected.push(b.socket_path.clone());
        }
        let active: Vec<PathBuf> = f
            .manager
            .active_bindings()
            .into_iter()
            .map(|b| b.socket_path)
            .collect();
        assert_eq!(
            active, expected,
            "active_bindings must return bindings in insertion (bind) order"
        );

        // `release_for_grant` filters and closes in that same insertion
        // order (matching Python's `[s for s in self._servers.values() if
        // ...]`, iterated over a `dict` -- see `ServerRegistry::matching_keys`);
        // closing every one of them and checking the count plus that every
        // socket is actually gone is the observable half of that guarantee.
        let closed = f.manager.release_for_grant(Some(&f.grant.id));
        assert_eq!(closed, expected.len());
        assert!(f.manager.active_bindings().is_empty());
        for path in &expected {
            assert!(!path.exists(), "{path:?} should have been removed");
        }
    }

    // Regression test for finding G-R2-1, re-pinned for the round-3 rewrite
    // (G-R3-1): a round-1 `close()` used to wake a thread parked in a
    // *blocking* `accept()` solely by connecting to `binding.socket_path`
    // itself. If that path was already gone (e.g. something outside this
    // module removed the directory holding it), every wakeup attempt failed
    // and the accept thread stayed parked forever, holding this
    // `Arc<BindingServer>` and the listener fd. Round 2 "fixed" this with a
    // hard-linked wakeup socket in a manager-owned `control_dir` -- withdrawn
    // in round 3 because that link was a second, fully functional agent
    // endpoint reachable even after the directory holding the real socket
    // was removed (findings G-R3-1). The replacement needs no wakeup target
    // at all: `accept_loop` never blocks (it polls a non-blocking listener
    // every `ACCEPT_POLL_INTERVAL`), so removing `binding.socket_path` out
    // from under it has no effect on `close()`'s ability to return promptly
    // and have the accept thread actually exit (its own `Arc<BindingServer>`
    // clone is dropped, so `strong_count` drops back to just this test's).
    #[test]
    fn close_after_socket_file_removed_returns_promptly_and_accept_thread_exits() {
        let f = fixture();
        let server = f.server();
        std::fs::remove_file(&f.binding.socket_path).unwrap();
        let started = Instant::now();
        f.manager.release(&f.binding);
        let elapsed = started.elapsed();
        eprintln!(
            "[G-R3-1] Rust close() latency (plain, socket file already removed): {elapsed:?} \
             (Python's own close() -- bounded by its accept thread's 0.2s socket settimeout, \
             not by anything the socket file's existence affects -- measured ~202ms for the \
             same plain case)"
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "close() took {elapsed:?} after its socket file was removed, expected well under \
             the old ~2s ACCEPT_JOIN_TIMEOUT-bound leak"
        );
        assert!(
            f.wait_until(|| Arc::strong_count(&server) == 1, Duration::from_secs(1)),
            "accept thread still holds a reference: strong_count={}",
            Arc::strong_count(&server)
        );
    }

    // Regression test for finding G-R2-1, re-pinned for G-R3-1: releasing
    // many bindings whose socket files were all removed out from under them
    // used to cost roughly `2 * ACCEPT_JOIN_TIMEOUT` seconds *per binding*
    // (each one burning the full accept-thread join timeout before
    // detaching), so `release_for_grant(None)` over N bindings (e.g.
    // `SignerManager::shutdown`) cost ~2N seconds and leaked N threads + N
    // fds. The non-blocking, no-wakeup-target accept loop (finding G-R3-1)
    // makes `binding.socket_path`'s existence irrelevant to `close()`
    // altogether, so this must complete promptly regardless of N.
    #[test]
    fn release_for_grant_bulk_after_socket_files_removed_completes_promptly() {
        let f = fixture();
        let n = 20;
        let mut sockets = vec![f.binding.socket_path.clone()];
        for _ in 0..n - 1 {
            let b = f.manager.bind("agent-1", "box", &f.grant.id).unwrap();
            sockets.push(b.socket_path);
        }
        for path in &sockets {
            std::fs::remove_file(path).unwrap();
        }
        let started = Instant::now();
        let closed = f.manager.release_for_grant(None);
        let elapsed = started.elapsed();
        assert_eq!(closed, n);
        assert!(
            elapsed < Duration::from_secs(2),
            "release_for_grant took {elapsed:?} for {n} bindings with their socket files \
             already removed, expected well under the old ~{}s (2 x {n})",
            2 * n
        );
    }

    // Regression test for finding G-1, re-measured for the round-3 rewrite
    // (G-R3-1): a round-1 accept loop set the listener non-blocking and slept
    // a fixed 200ms on every `WouldBlock`, so a *new* connection could wait
    // out nearly the whole poll interval before being accepted at all -- ten
    // sequential connect+request cycles measured ~1.85s (~205ms each)
    // instead of Python's own ~0.4-2.7ms per connection. Round 2 avoided
    // that regression with a *blocking* accept woken by a hard-linked
    // "wakeup" socket; round 3 withdraws that design (it was a second, fully
    // functional agent endpoint -- finding G-R3-1) in favour of a
    // non-blocking accept polled every `ACCEPT_POLL_INTERVAL` (1ms). Prints
    // per-connection latency under `--nocapture` so it can be compared
    // directly against the real Python signer's own numbers; the assertion
    // itself just needs to stay well clear of the old 200ms-per-connection
    // regression, with a generous margin so it is not flaky on a loaded CI
    // host.
    #[test]
    fn accept_latency_is_not_bound_by_a_fixed_poll_interval() {
        let f = fixture();
        let mut samples = Vec::with_capacity(10);
        let started = Instant::now();
        for _ in 0..10 {
            let cycle_started = Instant::now();
            let mut conn = f.connect();
            let reply = conn
                .request(&[sshwire::SSH_AGENTC_REQUEST_IDENTITIES])
                .unwrap();
            assert_eq!(reply[0], sshwire::SSH_AGENT_IDENTITIES_ANSWER);
            samples.push(cycle_started.elapsed());
        }
        let elapsed = started.elapsed();
        eprintln!(
            "[G-R3-1] Rust connect+REQUEST_IDENTITIES latency per cycle: {samples:?} (total \
             {elapsed:?})"
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "10 sequential connections took {elapsed:?}, expected well under the old \
             poll-bound ~2s (10 x 200ms)"
        );
    }

    // ------------------------------------------------- client tracking (SSH-3)

    // Port of test_finished_client_threads_are_pruned. Extended for finding
    // G-R2-2: `handle_accepted` used to insert a client's id into `clients`
    // (deciding admission) but only insert its `JoinHandle` into a *separate*
    // `handles` map *after* `spawn` returned. A client thread that connected
    // and disconnected fast enough to finish first (no message at all, like
    // every connection this test makes) would then remove an id from
    // `handles` that was not there yet, and the parent's later insert left a
    // handle nothing would ever remove -- `handles` grew unboundedly across
    // many short-lived connections even though `clients` stayed empty (the
    // reviewer's probe: 3710 connections -> `clients=0`, `handles=528`).
    // `clients`/`handles` are now one map (`ClientSlot`), inserted before
    // `spawn` and removed exactly once by the client thread itself, so this
    // is now structurally impossible; a few thousand iterations is what the
    // reviewer needed to reliably hit the original race's timing window.
    #[test]
    fn finished_client_threads_are_pruned() {
        let f = fixture();
        let server = f.server();
        for _ in 0..4000 {
            let mut conn = f.connect();
            let reply = conn
                .request(&[sshwire::SSH_AGENTC_REQUEST_IDENTITIES])
                .unwrap();
            assert_eq!(reply[0], sshwire::SSH_AGENT_IDENTITIES_ANSWER);
        }
        assert!(f.wait_until(
            || server.clients.lock().unwrap().is_empty(),
            Duration::from_secs(10)
        ));
        assert_eq!(
            server.clients.lock().unwrap().len(),
            0,
            "clients (which now also carries every client's JoinHandle) must not \
             accumulate stale entries across many short-lived connections"
        );
    }

    // Port of test_concurrent_clients_are_capped_and_refusal_audited
    #[test]
    fn concurrent_clients_are_capped_and_refusal_audited() {
        let f = fixture();
        let server = f.server();
        f.manager.set_max_agent_clients(3);
        let mut held: Vec<sshwire::AgentConnection<UnixStream>> = Vec::new();
        for _ in 0..3 {
            let mut conn = f.connect();
            assert_eq!(
                conn.request(&[sshwire::SSH_AGENTC_REQUEST_IDENTITIES])
                    .unwrap()[0],
                sshwire::SSH_AGENT_IDENTITIES_ANSWER
            );
            held.push(conn);
        }
        assert_eq!(server.clients.lock().unwrap().len(), 3);
        {
            let mut extra = f.connect();
            assert!(
                extra
                    .request(&[sshwire::SSH_AGENTC_REQUEST_IDENTITIES])
                    .is_err()
            );
        }
        assert!(server.clients.lock().unwrap().len() <= 3);
        assert!(f.wait_until(
            || f.has_reason("too_many_agent_clients"),
            Duration::from_secs(5)
        ));
        held.clear();
        assert!(f.wait_until(
            || server.clients.lock().unwrap().is_empty(),
            Duration::from_secs(5)
        ));
        let mut conn = f.connect();
        assert_eq!(
            conn.request(&f.bind_message()).unwrap(),
            sshwire::build_success()
        );
        let data = f.userauth();
        assert_eq!(
            f.sign_req(&mut conn, &data, 0, None)[0],
            sshwire::SSH_AGENT_SIGN_RESPONSE
        );
    }

    // Port of test_release_ends_live_client_connections
    #[test]
    fn release_ends_live_client_connections() {
        let f = fixture();
        let server = f.server();
        let mut conn = f.connect();
        assert_eq!(
            conn.request(&f.bind_message()).unwrap(),
            sshwire::build_success()
        );
        assert_eq!(server.clients.lock().unwrap().len(), 1);
        let started = Instant::now();
        f.binding.close();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(server.clients.lock().unwrap().is_empty());
        let data = f.userauth();
        assert!(
            conn.request(&sshwire::build_sign_request(
                &f.user_key.public.blob(),
                &data,
                0
            ))
            .is_err()
        );
        assert_eq!(f.ctx.policy.get_grant(&f.grant.id).unwrap().uses, 0);
    }

    // Regression test for finding G-R2-5: the client-join loop used to check
    // the shared deadline only *before* each `handle.join()`, then call it
    // unbounded (`std::thread::JoinHandle` cannot join with a timeout), so a
    // client thread wedged *inside* `handle_message` -- not blocked on socket
    // I/O, which `shutdown()` already unblocks -- could block `close()`
    // forever. Simulates a sign in progress stuck in `policy.consume` ->
    // `state.lock()` by holding `ctx.state`'s (re-entrant, in-process) lock
    // from an unrelated helper thread well past `CLIENT_JOIN_TIMEOUT`; since
    // `close()` runs on the revoke fan-out (`install`'s `on_revoke` ->
    // `release_for_grant` -> `close`), this same hang would otherwise reach
    // `Policy::revoke_grant`/`stop_all`, security operations Python bounds at
    // 2s (`thread.join(timeout=max(0.0, deadline - now))`).
    #[test]
    fn close_is_not_blocked_by_a_client_thread_wedged_on_the_state_lock() {
        let f = fixture();
        let mut conn = f.connect();
        assert_eq!(
            conn.request(&f.bind_message()).unwrap(),
            sshwire::build_success()
        );

        // Hold the state lock from an unrelated thread for far longer than
        // `CLIENT_JOIN_TIMEOUT`, simulating another thread (or, via the same
        // lock's `flock`, another process) already holding it.
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let ctx = f.ctx;
        let holder = thread::spawn(move || {
            let _guard = ctx.state.lock().expect("state lock");
            let _ = ready_tx.send(());
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
        });
        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("helper thread did not acquire the state lock in time");

        // Send a sign request but don't wait for its reply: the serving
        // thread will block inside `policy.consume` -> `state.lock()`, well
        // past `close()`'s own deadline.
        let data = f.userauth();
        conn.write_message(&sshwire::build_sign_request(
            &f.user_key.public.blob(),
            &data,
            0,
        ))
        .unwrap();
        thread::sleep(Duration::from_millis(200)); // let the server start handling it

        let started = Instant::now();
        f.binding.close();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "close() took {elapsed:?}, expected to return within roughly \
             CLIENT_JOIN_TIMEOUT even with a client thread wedged on the state lock"
        );

        let _ = release_tx.send(());
        holder.join().unwrap();
    }

    // Regression test for finding G-R3-3: `close()` never closed or dropped
    // the listener itself -- the listening fd was released only when the
    // last `Arc<BindingServer>` clone dropped, so on this same
    // bounded-detach path (a client thread wedged past `CLIENT_JOIN_TIMEOUT`)
    // the whole `BindingServer`, and therefore its listening socket fd,
    // stayed alive indefinitely (probe: `Arc::strong_count == 2`,
    // `clients.len() == 1`, after `close()` returned). Python's `close()`
    // releases its listening fd unconditionally as its second statement
    // (`self._sock.close()`), before any joins. The listener now lives
    // behind its own `Mutex<Option<UnixListener>>` that `close()` empties
    // regardless of what happens to any wedged client thread, so this
    // reproduces the exact wedge from the test above and additionally
    // asserts the listener is gone.
    #[test]
    fn close_releases_the_listener_even_with_a_client_thread_wedged_on_the_state_lock() {
        let f = fixture();
        let server = f.server();
        let mut conn = f.connect();
        assert_eq!(
            conn.request(&f.bind_message()).unwrap(),
            sshwire::build_success()
        );

        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let ctx = f.ctx;
        let holder = thread::spawn(move || {
            let _guard = ctx.state.lock().expect("state lock");
            let _ = ready_tx.send(());
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
        });
        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("helper thread did not acquire the state lock in time");

        let data = f.userauth();
        conn.write_message(&sshwire::build_sign_request(
            &f.user_key.public.blob(),
            &data,
            0,
        ))
        .unwrap();
        thread::sleep(Duration::from_millis(200)); // let the server start handling it

        let started = Instant::now();
        f.binding.close();
        let close_elapsed = started.elapsed();
        eprintln!("[G-R3-3] close() with a wedged client thread took {close_elapsed:?}");
        assert!(
            close_elapsed < Duration::from_secs(3),
            "close() took {close_elapsed:?}, expected to return within roughly \
             CLIENT_JOIN_TIMEOUT even with a client thread wedged on the state lock"
        );

        // The wedged client thread is detached (not joined), so it still
        // holds its own `Arc<BindingServer>` clone and its `ClientSlot` is
        // still in `clients` -- the struct itself is intentionally still
        // alive. The listener must be gone anyway.
        assert_eq!(
            Arc::strong_count(&server),
            2,
            "expected exactly this test's handle plus the detached wedged client thread's clone"
        );
        assert_eq!(
            server.clients.lock().unwrap().len(),
            1,
            "the wedged client's slot should still be present (its thread never finished)"
        );
        assert!(
            server.listener_is_released(),
            "close() must release the listening fd even though the BindingServer struct \
             itself is kept alive by the detached, wedged client thread"
        );

        let _ = release_tx.send(());
        holder.join().unwrap();
    }

    // --------------------------------------------- audit policy version (F8)

    // Port of test_ssh_audit_records_carry_policy_version
    #[test]
    fn ssh_audit_records_carry_policy_version() {
        let f = fixture();
        let version = f.ctx.policy.get_connection("box").unwrap().policy_version;
        let ssh_records = |limit| -> Vec<Value> {
            f.ctx
                .audit
                .tail(limit)
                .unwrap()
                .into_iter()
                .filter(|r| {
                    matches!(
                        r["event"].as_str(),
                        Some("ssh_sign") | Some("ssh_bind") | Some("ssh_agent_refused")
                    )
                })
                .collect()
        };
        {
            let mut conn = f.connect();
            let data = f.userauth();
            assert_eq!(
                f.sign_req(&mut conn, &data, 0, None),
                sshwire::build_failure()
            );
            assert_eq!(
                conn.request(&[sshwire::SSH_AGENTC_LOCK]).unwrap(),
                sshwire::build_failure()
            );
            assert_eq!(
                conn.request(&f.bind_message()).unwrap(),
                sshwire::build_success()
            );
            assert_eq!(
                f.sign_req(&mut conn, &data, 0, None)[0],
                sshwire::SSH_AGENT_SIGN_RESPONSE
            );
            let bad_user = f.userauth_for(
                "root",
                &f.session_id,
                SSH_ED25519,
                &f.user_key.public.blob(),
                None,
            );
            assert_eq!(
                f.sign_req(&mut conn, &bad_user, 0, None),
                sshwire::build_failure()
            );
        }
        let records = ssh_records(500);
        let kinds: std::collections::HashSet<(String, String)> = records
            .iter()
            .map(|r| {
                (
                    r["event"].as_str().unwrap().to_string(),
                    r["result"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        for expected in [
            ("ssh_bind", "ok"),
            ("ssh_sign", "ok"),
            ("ssh_sign", "denied"),
            ("ssh_agent_refused", "denied"),
        ] {
            assert!(
                kinds.contains(&(expected.0.to_string(), expected.1.to_string())),
                "{expected:?}"
            );
        }
        for record in &records {
            assert_eq!(record["policy_version"], json!(version), "{record}");
            assert_eq!(record["target"], json!("127.0.0.1:2222"));
        }
        f.ctx
            .policy
            .update_connection("box", P::ConnectionChanges::new().description("renamed"))
            .unwrap();
        let new_version = f.ctx.policy.get_connection("box").unwrap().policy_version;
        assert_ne!(new_version, version);
        let seen = records.len();
        {
            let mut conn = f.connect();
            let data = f.userauth();
            assert_eq!(
                f.sign_req(&mut conn, &data, 0, None),
                sshwire::build_failure()
            );
            assert_eq!(
                conn.request(&f.bind_message()).unwrap(),
                sshwire::build_success()
            );
            assert_eq!(
                f.sign_req(&mut conn, &data, 0, None)[0],
                sshwire::SSH_AGENT_SIGN_RESPONSE
            );
        }
        let later = &ssh_records(500)[seen..];
        let later_kinds: std::collections::HashSet<(String, String)> = later
            .iter()
            .map(|r| {
                (
                    r["event"].as_str().unwrap().to_string(),
                    r["result"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        let expected: std::collections::HashSet<(String, String)> = [
            ("ssh_sign", "denied"),
            ("ssh_bind", "ok"),
            ("ssh_sign", "ok"),
        ]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
        assert_eq!(later_kinds, expected);
        for record in later {
            assert_eq!(record["policy_version"], json!(new_version), "{record}");
        }
    }

    // ------------------------------------------------------------ OpenSSH interop

    // Port of test_ssh_add_lists_key_but_cannot_sign_random_data_or_delete.
    // Python uses a real `unittest.skipIf` here (visible as "skipped", never
    // "ok"); this test instead fails loudly when `ssh-add` is missing rather
    // than printing a message and returning, which `libtest` would otherwise
    // report as a silent, misleading pass (finding G-5).
    #[test]
    fn ssh_add_lists_key_but_cannot_sign_random_data_or_delete() {
        use std::process::Command;
        if Command::new("ssh-add").arg("-h").output().is_err() {
            panic!(
                "ssh-add is not available on PATH: this test requires OpenSSH client tools \
                 and must fail rather than silently report as passing when they are missing"
            );
        }
        let f = fixture();
        let env: Vec<(&str, String)> = vec![
            ("PATH", std::env::var("PATH").unwrap_or_default()),
            (
                "SSH_AUTH_SOCK",
                f.binding.socket_path.to_string_lossy().into_owned(),
            ),
        ];
        let listed = Command::new("ssh-add")
            .arg("-L")
            .env_clear()
            .envs(env.iter().cloned())
            .output()
            .unwrap();
        assert!(
            listed.status.success(),
            "{}",
            String::from_utf8_lossy(&listed.stderr)
        );
        let listed_stdout = String::from_utf8_lossy(&listed.stdout);
        let authorized = f.user_key.public.to_authorized_key("").unwrap();
        let field = authorized.split_whitespace().nth(1).unwrap();
        assert!(listed_stdout.contains(field));

        let pub_path = f._tmp.path().join("id.pub");
        std::fs::write(
            &pub_path,
            format!(
                "{}\n",
                f.user_key.public.to_authorized_key("agent-key").unwrap()
            ),
        )
        .unwrap();
        let probe = Command::new("ssh-add")
            .args(["-T", pub_path.to_str().unwrap()])
            .env_clear()
            .envs(env.iter().cloned())
            .output()
            .unwrap();
        assert!(
            !probe.status.success(),
            "random-data signing must be refused"
        );

        let deleted = Command::new("ssh-add")
            .arg("-D")
            .env_clear()
            .envs(env.iter().cloned())
            .output()
            .unwrap();
        assert!(!deleted.status.success());

        let mut conn = f.connect();
        let reply = conn
            .request(&[sshwire::SSH_AGENTC_REQUEST_IDENTITIES])
            .unwrap();
        assert_eq!(
            sshwire::parse_identities_answer(&reply[1..]).unwrap().len(),
            1
        );
        let reasons = f.audit_reasons();
        assert!(
            reasons
                .iter()
                .any(|r| r.as_deref() == Some("no_session_bind"))
                || reasons
                    .iter()
                    .any(|r| r.as_deref() == Some("not_userauth_request")),
            "{reasons:?}"
        );
        assert!(
            reasons
                .iter()
                .any(|r| r.as_deref() == Some("unsupported_agent_message"))
        );
    }

    // ------------------------------------------------- teardown (G-R3-4)

    // Regression test for finding G-R3-4: neither this module's `Fixture`
    // nor `signer_e2e.rs`'s used to call `manager.shutdown()` or implement
    // `Drop` at all, unlike Python's `SignerTestCase.tearDown`/
    // `SshEndToEndTestCase.setUp` (`addCleanup(self.manager.shutdown)`),
    // which is exactly what let a `Box::leak`ed `Context`'s default
    // `socket_dir`/`run_dir` (this crate's own G-R2-1 `control_dir`, plus
    // Python-shaped `zeropw-sockets-*`/`zeropw-runs-*` temp dirs) accumulate
    // unbounded (229 leftover `zpws-ctl-*` directories were found on this
    // machine). `Drop for Fixture` (added for this finding) now runs
    // `manager.shutdown()` before `_tmp`'s own `Drop` removes the directory
    // tree; this asserts every observable trace is actually gone afterward:
    // no socket file, no signer-created `socket_dir`, and -- via the
    // `BindingServer`'s own `Arc` dropping to zero once `shutdown()` and the
    // `Fixture`'s `manager: Arc<SignerManager>` are both gone -- no
    // remaining listener either (a live listener could only exist inside a
    // still-alive `BindingServer`).
    #[test]
    fn teardown_leaves_no_socket_file_listener_or_signer_created_directory() {
        let socket_path;
        let socket_dir;
        let server_weak;
        {
            let f = fixture();
            socket_path = f.binding.socket_path.clone();
            socket_dir = f.manager.socket_dir().to_path_buf();
            server_weak = Arc::downgrade(&f.server());
            assert!(
                socket_path.exists(),
                "sanity: socket should exist while bound"
            );
            assert!(
                socket_dir.exists(),
                "sanity: socket_dir should exist while bound"
            );
            // `f` drops at the end of this block: `Drop for Fixture` runs
            // `manager.shutdown()` (closing every `BindingServer`, which
            // removes the socket file and releases the listener -- finding
            // G-R3-3), then `_tmp`'s own ordinary `Drop` removes the whole
            // directory tree including `socket_dir`.
        }
        assert!(
            !socket_path.exists(),
            "socket file must not survive Fixture teardown"
        );
        assert!(
            !socket_dir.exists(),
            "signer-created socket_dir must not survive Fixture teardown"
        );
        assert!(
            server_weak.upgrade().is_none(),
            "BindingServer (and therefore its listener) must not survive Fixture teardown"
        );
    }
}
