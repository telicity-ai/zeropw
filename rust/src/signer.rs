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
//! * Python narrows the process umask to `0o177` around `socket.bind()` so
//!   the kernel creates the socket file with mode 0600 atomically, then
//!   `chmod`s redundantly. [`bind_and_listen`] reproduces the atomic 0600
//!   creation with safe `rustix` calls (see its doc comment), then makes the
//!   same `chmod`.
//! * An `OSError` (or a failed thread start) inside `SignerManager`/
//!   `_BindingServer` escapes Python uncaught; [`escaped_os_error`] models
//!   it the way this crate models every escaping CPython built-in, so the
//!   CLI prints Python's `OSError` mapping and the server/tools boundary
//!   answers `500 internal_error` with the run failed as
//!   `exec_setup_failed`.
//! * [`bind_and_listen`] matches Python's explicit `listen(16)` backlog
//!   exactly (finding G-R5-1): `std`'s `UnixListener::bind` has no safe way
//!   to request a specific backlog (only the OS default, 128 on this
//!   platform), so this port builds the socket with the audited
//!   `socket2` crate -- the same "audited safe wrapper" precedent already
//!   used for `mio` below -- calls its safe `Socket::listen(16)`, then
//!   converts it into a `std::os::unix::net::UnixListener` before handing
//!   it to the rest of this module exactly as `UnixListener::bind` used to.
//!   Pinned by `idle_listener_backlog_caps_pending_connects_like_python`.
//! * Python's accept loop blocks in `accept()` with a 0.2s `settimeout`
//!   purely so `close()` can eventually notice `self._closed`; a genuine
//!   connection is always served the instant it arrives. `std` has no
//!   equivalent "blocking accept with a timeout" for `UnixListener`, so this
//!   port makes the listener non-blocking and waits for it with a real
//!   OS-level readiness notification (`mio::Poll`, an epoll/kqueue wrapper)
//!   instead of a fixed poll interval: `accept_loop` blocks in
//!   `Poll::poll(..., None)` -- no timeout, no busy loop -- until either the
//!   listener becomes readable or `close()` signals a [`mio::Waker`]
//!   registered on the same `Poll`. See `BindingServer::close` and
//!   `accept_loop` for why this needs no durable, connectable "wakeup" alias
//!   for the socket (finding G-R3-1, still withdrawn) and no fixed poll
//!   interval (finding G-R4-1, replacing round 3's 1ms busy-poll, which a
//!   re-measurement against the real Python signer showed was both slower
//!   per accept and far more idle-CPU-hungry than Python -- see
//!   `DEVIATIONS.md` for the measured numbers).
//! * That same `mio::Poll`/[`mio::Waker`] pair costs 2 extra fds per binding
//!   beyond the listening socket itself (its own kqueue/epoll fd, plus a
//!   second kqueue-based fd `Waker::new` allocates on this platform) --
//!   3 fds/binding where Python's `_BindingServer.__init__` opens exactly 1
//!   (`self._sock`). Per-*client* cost matches Python exactly (1 fd, not 2:
//!   finding G-R6-1 fixed a `try_clone()`-based duplicate). See
//!   `DEVIATIONS.md` for the measured ratios and the `RLIMIT_NOFILE` sweep.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};
use serde_json::{Value, json};
use socket2::{Domain, SockAddr, Socket, Type};

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
/// Matches Python's `self._sock.listen(16)` in `_BindingServer.__init__`
/// (finding G-R5-1). See [`bind_and_listen`].
const SIGNER_LISTEN_BACKLOG: i32 = 16;
const CLIENT_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound on waiting for the accept thread to notice `closed` and return, the
/// same 2s Python gives `self._accept_thread.join(timeout=2)`. `close()`
/// wakes `accept_loop` with [`mio::Waker::wake`] (finding G-R4-1), which
/// interrupts a blocked `Poll::poll` immediately rather than relying on a
/// poll interval, so the accept thread should always notice essentially at
/// once; this bound is defence in depth rather than the normal path (e.g. a
/// wedged OS scheduler decision outside this process's control).
const ACCEPT_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
/// `Token` identifying the listening socket's readiness registration on this
/// binding's `mio::Poll` (finding G-R4-1).
const LISTENER_TOKEN: Token = Token(0);
/// `Token` identifying the [`mio::Waker`] registration `close()` uses to
/// interrupt a blocked `accept_loop` -- the event-driven replacement for
/// round 3's fixed 1ms busy-poll (finding G-R4-1: a re-measurement against
/// the real Python signer showed that poll interval regressed both
/// per-connection accept latency (~7x slower than Python, not "far below" as
/// a prior version of this module claimed) and idle CPU (each live binding's
/// accept thread woke 700-1000 times/second forever, 25-70x Python's own
/// idle CPU depending on binding count -- see `DEVIATIONS.md` for the full
/// measurements).
const WAKE_TOKEN: Token = Token(1);

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
    /// Shared with the serving thread's own [`SharedStream`] clone (finding
    /// G-R6-1): this used to be a *second*, independently `try_clone()`d
    /// `UnixStream` kept only so `close()` could `shutdown()` it while the
    /// worker thread read/wrote through its own separate fd, costing 2 fds
    /// per admitted client where Python's `self._clients[thread] = client`
    /// keeps exactly 1 (`self._sock.accept()`'s own return value, the same
    /// object both `close()` and the serving thread use). `Arc<UnixStream>`
    /// lets both sides share the one accepted fd instead: `shutdown()` here
    /// and `Read`/`Write` in the worker both go through `&UnixStream`, which
    /// `std` already implements for concurrent use from multiple owners.
    stream: Arc<UnixStream>,
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

/// `Read`/`Write` wrapper around a client socket shared (via `Arc`) between
/// `ClientSlot` (which only ever needs to `shutdown()` it from `close()`)
/// and the serving thread's `AgentConnection` (finding G-R6-1). `&UnixStream`
/// already implements `Read`/`Write` in `std` -- a `UnixStream` supports
/// concurrent use through a shared reference, the same guarantee a
/// `try_clone()`-ed second fd relied on -- so this just forwards to that impl
/// instead of needing a second, independently `try_clone()`-ed file
/// descriptor the way the previous version of this module did.
struct SharedStream(Arc<UnixStream>);

impl Read for SharedStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        (&*self.0).read(buf)
    }
}

impl Write for SharedStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (&*self.0).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        (&*self.0).flush()
    }
}

/// Port of `signer._BindingServer`.
struct BindingServer {
    ctx: Arc<Context>,
    binding: SignerBinding,
    /// The listening socket, non-blocking (finding G-R3-1/G-R4-1:
    /// `accept_loop` waits on it through `mio::Poll` rather than blocking in
    /// `accept()` directly, so no durable wakeup alias is ever needed to
    /// interrupt it). Wrapped so `close()` can `take()` and drop it,
    /// releasing the listening fd immediately and independently of whether
    /// some other `Arc<BindingServer>` clone (e.g. a client thread detached
    /// past its join deadline) keeps the rest of this struct alive (finding
    /// G-R3-3) -- Python's `close()` releases its listening fd
    /// unconditionally as its second statement (`self._sock.close()`),
    /// before any joins.
    listener: Mutex<Option<UnixListener>>,
    /// Wakes `accept_loop`'s blocking `Poll::poll` the instant `close()` sets
    /// `closed`, with no fixed poll interval and no filesystem state
    /// (finding G-R4-1, replacing round 3's `ACCEPT_POLL_INTERVAL` busy-poll,
    /// which a re-measurement against the real Python signer showed
    /// regressed both accept latency and idle CPU -- see `DEVIATIONS.md`).
    /// Registered on the same `Poll` instance `accept_loop` owns and blocks
    /// on, under [`WAKE_TOKEN`].
    waker: Waker,
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
        ctx: Arc<Context>,
        binding: SignerBinding,
        max_agent_clients: Arc<AtomicUsize>,
    ) -> Result<Arc<Self>, Error> {
        let listener = bind_and_listen(&binding.socket_path)?;
        listener
            .set_nonblocking(true)
            .map_err(|e| escaped_os_error(&e))?;
        // Event-driven accept wait (finding G-R4-1): one `mio::Poll` per
        // binding, set up here (before the accept thread starts) and then
        // handed to it by value. `SourceFd` only borrows the raw fd for the
        // duration of `register` -- it does not take ownership -- so the
        // listener itself stays in `listener: Mutex<Option<UnixListener>>`,
        // exactly as before, for `close()` to `take()` and drop
        // independently (finding G-R3-3). No `unsafe`: `mio::Registry`'s
        // `register`/`Waker::new` are safe functions (unlike e.g. the
        // `polling` crate's `Poller::add`, which is `unsafe fn` because it
        // requires the caller to `delete()` the source before dropping it).
        let poll = Poll::new().map_err(|e| escaped_os_error(&e))?;
        let listener_fd = listener.as_raw_fd();
        poll.registry()
            .register(
                &mut SourceFd(&listener_fd),
                LISTENER_TOKEN,
                Interest::READABLE,
            )
            .map_err(|e| escaped_os_error(&e))?;
        let waker = Waker::new(poll.registry(), WAKE_TOKEN).map_err(|e| escaped_os_error(&e))?;
        let server = Arc::new(BindingServer {
            ctx,
            binding,
            listener: Mutex::new(Some(listener)),
            waker,
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
                accept_server.accept_loop(poll);
                let _ = done_tx.send(());
            })
            .map_err(|_| escaped_thread_start_error())?;
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
        // Wake `accept_loop` immediately if it is blocked in `Poll::poll`
        // (finding G-R4-1): `closed` is stored first, so by the time the
        // accept thread wakes and re-checks it, there is no race where it
        // could go back to sleep. This replaces round 3's fixed
        // `ACCEPT_POLL_INTERVAL` busy-poll with a real event -- no polling
        // interval bounds how quickly `close()` is noticed, the OS wakes the
        // blocked thread directly, the same way Python's blocking
        // `accept()`+`settimeout` is woken by the socket itself becoming
        // ready or by the timeout elapsing, not by rechecking on a schedule.
        let _ = self.waker.wake();
        // Take and drop the listener immediately -- Python's `close()`
        // closes `self._sock` as its second statement, before any joins, so
        // the listening fd is released unconditionally rather than only
        // when the last `Arc<BindingServer>` clone drops (finding G-R3-3: a
        // client thread detached past its join deadline below used to keep
        // this whole struct, and therefore the listener fd, alive
        // indefinitely). `accept_loop` re-locks `listener` after every wakeup
        // and exits as soon as it observes `None`, without ever needing a
        // durable, connectable alias to the socket (finding G-R3-1 -- the
        // round-2 hard-link "wakeup" design is withdrawn: the reviewer showed
        // that link was a second, fully functional agent endpoint reachable
        // even after the directory holding the real socket was removed,
        // widening the capability boundary `SSH_AUTH_SOCK` is supposed to
        // be). Closing this fd also automatically drops any pending
        // epoll/kqueue registration for it (both remove a descriptor's
        // registrations synchronously on `close(2)`), so there is no window
        // where a reused fd number could be confused for this listener --
        // and even if the OS behaved otherwise, `accept_loop` never trusts
        // the poll event's identity for anything beyond "recheck now": it
        // always re-reads the actual accept result through this same
        // `Mutex<Option<UnixListener>>`.
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
        // `close()` forever on a wedged accept thread. With the waker above,
        // `accept_loop` should notice essentially at once; this bound is
        // defence in depth.
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

    /// `poll` is the `mio::Poll` `BindingServer::start` created and
    /// registered the listener (`LISTENER_TOKEN`) and `self.waker`
    /// (`WAKE_TOKEN`) on, moved here by value so this thread is the only one
    /// ever calling `Poll::poll` on it (finding G-R4-1).
    fn accept_loop(self: Arc<Self>, mut poll: Poll) {
        // Event-driven wait, no fixed poll interval and no busy loop: this
        // thread blocks in `Poll::poll(..., None)` (no timeout) until the OS
        // reports the listener readable or `close()` fires the waker, then
        // rechecks `closed`/the listener exactly once per real event -- the
        // direct replacement for round 3's `ACCEPT_POLL_INTERVAL` busy-poll,
        // which a re-measurement against the real Python signer showed was
        // both ~7x slower per accept and, far more seriously, kept every
        // live binding's thread waking 700-1000 times/second forever even
        // when fully idle (25-70x Python's own idle CPU -- see
        // `DEVIATIONS.md` for the measured numbers, finding G-R4-1). The
        // listener stays non-blocking (`BindingServer::start`) so a stray
        // wakeup with nothing pending (a spurious event, mio's own
        // documented possibility on every backend) just sees `WouldBlock`
        // and loops back to `poll.poll` instead of blocking in `accept()`.
        let mut events = Events::with_capacity(4);
        'outer: loop {
            if self.closed.load(Ordering::SeqCst) {
                break;
            }
            match poll.poll(&mut events, None) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break, // no sane way to keep waiting; exit like a fatal accept error
            }
            if self.closed.load(Ordering::SeqCst) {
                break;
            }
            // A readiness event only means "something may have changed", not
            // how many connections are queued (mio's own documented
            // contract, true on both epoll and kqueue): drain until
            // `WouldBlock` rather than accepting once per event. This also
            // means the loop never needs to inspect which token fired --
            // `WAKE_TOKEN` and `LISTENER_TOKEN` both just mean "go check
            // `closed` and the listener again", exactly like re-checking
            // both every `ACCEPT_POLL_INTERVAL` used to.
            loop {
                let accepted = {
                    let guard = self.listener.lock().expect("listener mutex poisoned");
                    guard.as_ref().map(UnixListener::accept)
                };
                match accepted {
                    Some(Ok((stream, _addr))) => {
                        // On some platforms (observed on macOS/Darwin) a
                        // socket returned by `accept()` inherits the
                        // non-blocking flag of the *listening* socket, even
                        // though POSIX gives it a fresh open file
                        // description. `serve_client` (and Python's own
                        // `client.settimeout(30)`) needs ordinary
                        // blocking-with-timeout reads/writes, so force it
                        // back explicitly rather than relying on it starting
                        // that way.
                        let _ = stream.set_nonblocking(false);
                        self.handle_accepted(stream);
                        if self.closed.load(Ordering::SeqCst) {
                            break 'outer;
                        }
                    }
                    Some(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Some(Err(_)) => break 'outer,
                    None => break 'outer, // `close()` already took the listener
                }
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
        // Wrap in `Arc` once, up front: one accepted fd shared by the
        // `ClientSlot` (which only ever `shutdown()`s it from `close()`) and
        // the serving thread's `AgentConnection` (via `SharedStream`), matching
        // Python's single `self._sock.accept()` return value used by both
        // `close()`'s `shutdown()` and the serving thread -- instead of a
        // second `try_clone()`-ed fd that used to exist solely for `close()`
        // to reach (finding G-R6-1). `Arc::new` cannot fail, so (unlike the
        // old `try_clone()`) there is no fallible step here that could ever
        // misreport a refusal as `too_many_agent_clients` when the real cause
        // was something else.
        let shared = Arc::new(stream);
        let (admitted, done_tx) = {
            let mut clients = self.clients.lock().expect("clients mutex poisoned");
            if self.closed.load(Ordering::SeqCst) || clients.len() >= max {
                (false, None)
            } else {
                // Register *before* the client can possibly be observed
                // finishing: the `handle`/`done` slots are filled in below,
                // but the entry itself -- and thus `close()`'s and
                // `serve_client`'s own tail's view of which ids exist -- is
                // created here, under the same lock that decided admission,
                // strictly before `spawn` below can start the thread
                // (finding G-R2-2; mirrors Python's `self._clients[thread] =
                // client` before `thread.start()`).
                let (done_tx, done_rx) = std::sync::mpsc::channel();
                clients.insert(
                    id,
                    ClientSlot {
                        stream: Arc::clone(&shared),
                        handle: None,
                        done: Some(done_rx),
                    },
                );
                (true, Some(done_tx))
            }
        };
        if !admitted {
            let _ = shared.shutdown(std::net::Shutdown::Both);
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
            .spawn(move || worker.serve_client(id, shared, done_tx))
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
    fn serve_client(self: Arc<Self>, id: u64, client: Arc<UnixStream>, done_tx: Sender<()>) {
        let _ = client.set_read_timeout(Some(CLIENT_IO_TIMEOUT));
        let _ = client.set_write_timeout(Some(CLIENT_IO_TIMEOUT));
        let mut conn = sshwire::AgentConnection::new(SharedStream(client));
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
            .resolve_version(&conn.secret_id, conn.secret_version.clone())?;
        let meta = self.ctx.vault.get_meta(&conn.secret_id)?;
        for item in &meta.versions {
            if version.equals_integer(&item.version) {
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
        // X-20: Python's `bind_attempts` is an unbounded `int`; `u32` is
        // not. Nothing reads this field back (`#[allow(dead_code)]` above)
        // and reaching `u32::MAX` needs 2^32 `session_bind` extension
        // messages on one connection, each one writing an audit record
        // first -- impractical, but `saturating_add` costs nothing and
        // removes the only realistic future hazard (a debug panic, or a
        // release-mode wrap back to 0) instead of leaving it merely
        // "unreached so far".
        state.bind_attempts = state.bind_attempts.saturating_add(1);
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
            .secret_for_trusted_use(&conn.secret_id, conn.secret_version.clone())
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
    ctx: Arc<Context>,
    socket_dir: PathBuf,
    servers: Mutex<ServerRegistry>,
    max_agent_clients: Arc<AtomicUsize>,
}

impl SignerManager {
    fn new(ctx: Arc<Context>, socket_dir: Option<PathBuf>) -> Result<Self, Error> {
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
        // `self.socket_dir` is already `choose_socket_dir`'s normalized
        // result (finding G-R6-2), and `name` has no `/`/`.` components of
        // its own, so this join cannot reintroduce anything a caller-supplied
        // `socket_dir` might have had normalized away -- this length check
        // and the `ServerRegistry` key below (`path.to_string_lossy()`) both
        // already operate on the normalized string with no further work
        // needed here.
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
            Arc::clone(&self.ctx),
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
///
/// Takes an owned `Arc<Context>` rather than `&'static Context` (finding E-R7-1): the previous
/// `&'static` bound could only be satisfied in safe Rust by `Box::leak`ing the `Context`, which
/// meant `Context::close()`/`Drop` -- the only thing that removes the `socket_dir`/`run_dir`
/// temp directories `Context::apply_config_defaults` creates -- could never run, on every real
/// caller of this function. `Arc<Context>` satisfies `thread::spawn`'s own `'static` bound just
/// as well (an owned, ref-counted clone has no borrow to outlive), and drops the `Context` once
/// every clone this module hands to a `SignerManager`/`BindingServer`/accept-thread/client-thread
/// is gone, reproducing Python's `atexit`-registered cleanup instead of leaking unboundedly.
///
/// `ctx.signer_manager` (`Context`'s own `AnySlot`, a second-half seam -- see `context.rs`) is
/// populated with a `Weak<SignerManager>`, not an `Arc<SignerManager>`: `SignerManager` already
/// holds its own `Arc<Context>` (`self.ctx`), so storing a *strong* `Arc<SignerManager>` back on
/// `ctx.signer_manager` would make `Context` and `SignerManager` keep each other alive forever
/// (`Context` -> `Arc<SignerManager>` -> `Context` -> ...), the exact reference cycle that defeats
/// this whole fix -- discovered by measurement: `signer_socket_dir_matches_configured_directory_
/// under_this_machines_default_tmpdir` (`vault_context.rs`) is the one test in this crate that
/// both uses `Context`'s *default* (non-explicit) `socket_dir`/`run_dir` and calls
/// `signer::install`, and it alone left a `zeropw-runs-*`/`zeropw-sockets-*` pair behind in an
/// otherwise-empty `TMPDIR` even after this `Arc<Context>` change. A `Weak` back-reference does
/// not count toward `SignerManager`'s strong refcount, so once every external strong
/// `Arc<SignerManager>` (the caller's own handle, any live `BindingServer`/accept-thread/client-
/// thread clone) drops, `SignerManager` itself drops, which drops its `Arc<Context>` clone too --
/// and since nothing else holds a strong `Arc<Context>` at that point, `Context` drops for real.
/// Nothing in this crate reads `ctx.signer_manager` back yet (second-half only), so this changes
/// no currently-observable behaviour, only what a future reader finds there (a `Weak` to
/// `.upgrade()`, matching Python's plain object-identity reference exactly as long as a second-
/// half consumer does not rely on it keeping the manager alive by itself).
///
/// The `ctx.policy.on_revoke(...)` listener below is the *second*, separate cycle this same fix
/// has to avoid: `Policy` (`ctx.policy`) is a plain field of `Context`, not behind an `Arc`, and
/// `Policy::on_revoke` has no unregister -- a listener lives in `Policy`'s own
/// `revoke_listeners: Vec<Arc<dyn Fn...>>` for as long as the `Policy` (i.e. the owning `Context`)
/// does. A listener closure that captured a *strong* `Arc<SignerManager>` would therefore keep
/// `SignerManager` alive as long as `Context` is, while `SignerManager::ctx` keeps `Context` alive
/// as long as `SignerManager` is -- `Context` -> `Policy` -> listener -> `Arc<SignerManager>` ->
/// `Arc<Context>` -> the same `Context`, a cycle neither refcount can ever break on its own
/// (measured: fixing only the `ctx.signer_manager` slot above to `Weak` was not enough by itself --
/// `signer_socket_dir_matches_configured_directory_under_this_machines_default_tmpdir` still left
/// its `zeropw-runs-*`/`zeropw-sockets-*` pair behind with that alone). The listener closure
/// therefore captures `Weak<SignerManager>` and `.upgrade()`s it on each call, silently doing
/// nothing once the manager is gone (there is nothing left to revoke sockets for by then) --
/// Python's `Policy._notify_revoke` has the identical no-op-once-gone behaviour for a duck-typed
/// listener whose referent has already been collected, since Python's own real cyclic GC (unlike
/// Rust's plain refcounting) would eventually collect this exact cycle regardless.
pub fn install(
    ctx: Arc<Context>,
    socket_dir: Option<PathBuf>,
) -> Result<Arc<SignerManager>, Error> {
    let manager = Arc::new(SignerManager::new(Arc::clone(&ctx), socket_dir)?);
    *ctx.signer_manager
        .lock()
        .expect("signer_manager mutex poisoned") = Some(Box::new(Arc::downgrade(&manager)));
    let listener_manager = Arc::downgrade(&manager);
    ctx.policy.on_revoke(move |kind, grant_id| {
        if let Some(manager) = listener_manager.upgrade() {
            manager.release_for_grant(if kind == "grant" { grant_id } else { None });
        }
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

/// Normalizes a path string the way CPython's `pathlib` does the instant a
/// `Path` is constructed from one (finding G-R6-2): collapses every run of
/// repeated `/` separators, drops every `.` component, and leaves `..`
/// components unresolved, exactly like `Path(s)`/`str(Path(s))`. Also
/// reproduces pathlib's POSIX "root" special case: a leading run of
/// *exactly* two slashes is preserved as-is (`"//foo"` stays `"//foo"`),
/// while a run of one or three-or-more collapses to a single leading `/`
/// (`"/foo"` stays `"/foo"`; `"///foo"` becomes `"/foo"`) -- measured
/// directly against `python3.12`:
/// `str(Path("//foo"))` == `"//foo"`, `str(Path("///foo"))` == `"/foo"`,
/// `str(Path("/tmp/zpw//aaa"))` == `"/tmp/zpw/aaa"` (12 chars, not 13),
/// `str(Path("/tmp/zpw/./aaa"))` == `"/tmp/zpw/aaa"`,
/// `str(Path("/tmp/zpw/aaa/"))` == `"/tmp/zpw/aaa"`, and
/// `str(Path("/tmp/zpw/b/../aaa"))` == `"/tmp/zpw/b/../aaa"` (`..` kept
/// literally, not resolved). `str(Path(""))` == `"."`, reproduced here too
/// for completeness even though `choose_socket_dir` never calls this with an
/// empty string.
///
/// `store.rs`'s `normalize_join_name` performs the same component-dropping
/// for the *relative* `name` half of `Path(base) / name`, but deliberately
/// returns an absolute `name` **unchanged** -- correct for its own caller,
/// since `Path::join`'s "an absolute joined path replaces the base" rule
/// means the join itself needs no further normalization of that half (the
/// leading-slash-run rule above never had to be implemented there). This
/// function normalizes `_choose_socket_dir`'s `preferred` candidate itself --
/// the base, not a name being joined onto one -- exactly mirroring Python's
/// own `candidate = Path(preferred)` (`signer.py`), which normalizes before
/// `candidate`'s length is ever measured or any directory is created.
/// Reusing `normalize_join_name` as-is would therefore return the candidate
/// untouched and reproduce the exact gap this fixes, so this is a separate,
/// small function rather than a copy of that one (`rust/PORTING.md` §3b).
fn normalize_pathlib_string(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let leading_slashes = path.chars().take_while(|&c| c == '/').count();
    let root = match leading_slashes {
        0 => "",
        2 => "//",
        _ => "/",
    };
    // All leading-slash chars are single-byte ASCII, so the byte offset
    // equals the char count counted above; slicing here is exact.
    let rest = &path[leading_slashes..];
    let components: Vec<&str> = rest
        .split('/')
        .filter(|component| !component.is_empty() && *component != ".")
        .collect();
    match (root.is_empty(), components.is_empty()) {
        (true, true) => ".".to_string(),
        (true, false) => components.join("/"),
        (false, true) => root.to_string(),
        (false, false) => format!("{root}{}", components.join("/")),
    }
}

/// [`normalize_pathlib_string`] applied to a [`Path`], round-tripped through
/// `PathBuf`.
fn normalize_pathlib_path(path: &Path) -> PathBuf {
    PathBuf::from(normalize_pathlib_string(&path.to_string_lossy()))
}

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
///
/// The `preferred` candidate is normalized first ([`normalize_pathlib_path`],
/// finding G-R6-2), exactly mirroring Python's own `candidate = Path(preferred)`
/// -- both the boundary length check below and the directory actually
/// created/returned use the normalized form, so a candidate containing
/// `//`/`/./` counts (and is created) the same, shorter length in Rust that
/// it already did in Python, instead of counting longer and silently falling
/// back to a fresh private temp directory below the true boundary.
fn choose_socket_dir(preferred: Option<PathBuf>) -> Result<PathBuf, Error> {
    if let Some(candidate) = preferred {
        let candidate = normalize_pathlib_path(&candidate);
        let probe = candidate.join("s".repeat(24));
        // Characters, not UTF-8 bytes -- matches Python's `len(str(path))`
        // (finding G-R2-3; see `SignerManager::bind`'s identical fix).
        if probe.to_string_lossy().chars().count() <= MAX_UNIX_PATH {
            if let Some(parent) = candidate.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent).map_err(|e| escaped_os_error(&e))?;
            }
            mkdir_leaf_private_0700(&candidate).map_err(|e| escaped_os_error(&e))?;
            // Defensive backstop against a masking umask, same as
            // `context.rs`'s `create_private_dir`; the `mkdir` syscall above
            // already requested 0700 directly, so this is redundant in the
            // common case, not the primary guarantee.
            std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| escaped_os_error(&e))?;
            return Ok(candidate);
        }
    }
    let short = make_temp_dir("zpws-")?;
    std::fs::set_permissions(&short, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| escaped_os_error(&e))?;
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
            Err(e) => return Err(escaped_os_error(&e)),
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

/// The `OSError` CPython raises for `error` inside `SignerManager` /
/// `_BindingServer` (`Path.mkdir`, `tempfile.mkdtemp`, `os.chmod`,
/// `socket.bind`/`listen`). Nothing in `signer.py` catches it, so it escapes
/// to the caller: `admin_cli.main` prints `{"error": "FileNotFoundError",
/// "reason": "file_not_found"}` or `{"error": <OSError subclass>, "reason":
/// "io_error", "detail": strerror}`, which is exactly this error's
/// `to_dict()`; `zeropw.server` answers it as an escaped built-in
/// ([`crate::gateway::is_escaped_builtin`]) and `tools.exec` fails the run
/// with `exec_setup_failed`.
fn escaped_os_error(error: &std::io::Error) -> Error {
    if error.raw_os_error() == Some(libc::ENOENT) {
        return Error::subclass(
            ErrorClass::ZeroPW,
            "FileNotFoundError",
            "file_not_found",
            "",
        );
    }
    Error::subclass(
        ErrorClass::ZeroPW,
        crate::pystr::os_error_class(error),
        "io_error",
        crate::pystr::os_error_strerror(error).unwrap_or_default(),
    )
}

/// `threading.Thread.start()` failing: `RuntimeError("can't start new
/// thread")`, escaping uncaught like [`escaped_os_error`].
fn escaped_thread_start_error() -> Error {
    Error::subclass(ErrorClass::ZeroPW, "RuntimeError", "internal_error", "")
}

/// Bind, chmod 0600, and listen with Python's explicit backlog.
/// `BindingServer::start` sets the returned listener non-blocking right
/// after this returns (finding G-R3-1/G-R4-1): `accept_loop` waits on it
/// through a per-binding `mio::Poll` (event-driven, no fixed poll interval)
/// rather than blocking in `accept()` directly, so `close()` can wake it
/// with `Waker::wake()` and by simply taking the listener away, with no
/// durable connectable alias needed. See the module doc comment for the
/// umask deviation from Python's `socket.bind`.
///
/// Finding G-R5-1: Python calls `self._sock.listen(16)`, an explicit
/// backlog, but `std::os::unix::net::UnixListener::bind` has no way to
/// request a specific backlog -- only the OS default (128 on this crate's
/// target platforms), well above Python's 16. Measured effect: an idle
/// listener cannot queue a burst above 16; Darwin reports `ECONNREFUSED`
/// and Linux reports `EAGAIN`/`WouldBlock` once the queue fills. The old
/// default-backlog Rust listener accepted the same 40-connection probe in
/// full. `socket2::Socket::listen` is a safe `fn`
/// (unlike the raw `listen(2)` FFI call `std` would need), so this builds
/// the socket explicitly with `socket2` -- the same "audited safe wrapper
/// crate" precedent already used for `mio` in this module -- binds it to
/// `path`, calls `listen(SIGNER_LISTEN_BACKLOG)`, and converts the result
/// into a `std::os::unix::net::UnixListener` via `socket2`'s `From` impl so
/// every caller of `bind_and_listen` sees the same std type as before.
/// Pinned by `idle_listener_backlog_caps_pending_connects_like_python`.
fn bind_and_listen(path: &Path) -> Result<UnixListener, Error> {
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None).map_err(|e| escaped_os_error(&e))?;
    let addr = SockAddr::unix(path).map_err(|e| escaped_os_error(&e))?;
    bind_private(&socket, &addr).map_err(|e| escaped_os_error(&e))?;
    // `os.chmod(path, 0o600)` comes before `listen(16)` in Python.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| escaped_os_error(&e))?;
    socket
        .listen(SIGNER_LISTEN_BACKLOG)
        .map_err(|e| escaped_os_error(&e))?;
    // `socket2::Socket -> UnixListener` directly is gated behind socket2's
    // "all" feature; going through the standard `OwnedFd` (which both
    // `Socket` and `UnixListener` convert with unconditionally) avoids
    // pulling that extra surface in for one conversion.
    let fd: std::os::fd::OwnedFd = socket.into();
    let listener = UnixListener::from(fd);
    Ok(listener)
}

/// `old_umask = os.umask(0o177); try: sock.bind(path) finally:
/// os.umask(old_umask)`: the socket file never exists with a mode wider than
/// 0600.
///
/// Linux derives the new socket inode's mode from the (unbound) socket's own
/// inode mode masked by the umask (`unix_bind_bsd`: `S_IFSOCK |
/// (SOCK_INODE(sock)->i_mode & ~current_umask())`), so a safe `fchmod(fd,
/// 0o600)` before `bind` creates the file at 0600 atomically without
/// touching process-wide state (measured: 0600 under umask 000, 022 and
/// 077; a plain bind under umask 022 gives 0755). Darwin rejects `fchmod`
/// on a socket (`EINVAL`) and always creates the file at `0777 & ~umask`,
/// so there this narrows the process umask around `bind` exactly like
/// Python does, with `rustix`'s safe `umask` wrapper.
#[cfg(target_os = "linux")]
fn bind_private(socket: &Socket, addr: &SockAddr) -> std::io::Result<()> {
    rustix::fs::fchmod(socket, rustix::fs::Mode::from_raw_mode(0o600))?;
    socket.bind(addr)
}

#[cfg(not(target_os = "linux"))]
fn bind_private(socket: &Socket, addr: &SockAddr) -> std::io::Result<()> {
    let previous = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o177));
    let bound = socket.bind(addr);
    rustix::process::umask(previous);
    bound
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
        ctx: Arc<Context>,
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
    /// Does not call `Context::close()` explicitly: `ctx` is an `Arc<Context>` (finding
    /// E-R7-1 -- `signer::install` no longer requires `&'static Context`/`Box::leak`), so once
    /// `shutdown()` above has dropped every `BindingServer`'s own clone (and joined the threads
    /// that held theirs), the only clones left are this field and `manager`'s internal one; both
    /// go when `Fixture`'s fields drop after this impl's body runs, which runs `Context::drop` ->
    /// `close()` for real. `fixture()` also gives `Context` explicit `socket_dir`/`run_dir` under
    /// `_tmp`, so it never allocates anything outside `_tmp` in the first place; `_tmp`'s own
    /// ordinary `Drop` removes the state dir and every socket the signer created, closing the gap
    /// that left 229 leftover `zpws-ctl-*` directories (round 2's now-withdrawn `control_dir`)
    /// and unbounded `zeropw-sockets-*`/`zeropw-runs-*` directories (this fixture's previously
    /// leaked `Context`) behind on this machine.
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
        // temp dir, which is harmless now that `ctx` is a properly-dropped
        // `Arc<Context>` (finding E-R7-1) but still worth keeping self-contained
        // under `_tmp` like every other fixture.
        let config = Config {
            socket_dir: Some(root.join("ctx-sockets")),
            run_dir: Some(root.join("ctx-run")),
            ..Config::default()
        };
        let ctx: Arc<Context> = Arc::new(
            Context::initialize(root.join("state"), ADMIN, RECOVERY, config, clock).unwrap(),
        );
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
        let manager = install(Arc::clone(&ctx), None).unwrap();
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

    /// Python's `os.umask(0o177)` around `bind` means the socket file is
    /// created at 0600 -- there is no moment where it exists wider. Checked
    /// on the file `bind_private` leaves BEFORE `bind_and_listen`'s own
    /// `chmod`; a plain `bind` under the usual 022 umask creates 0755.
    #[test]
    fn bind_private_creates_the_socket_file_at_0600_before_any_chmod() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("probe.sock");
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
        bind_private(&socket, &SockAddr::unix(&path).unwrap()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600, "socket file mode right after bind: {mode:o}");
        let plain = tmp.path().join("plain.sock");
        let plain_socket = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
        plain_socket.bind(&SockAddr::unix(&plain).unwrap()).unwrap();
        let plain_mode = std::fs::metadata(&plain).unwrap().permissions().mode() & 0o7777;
        assert_ne!(
            plain_mode & 0o077,
            0,
            "a plain bind must be wider than 0600 here, or this test proves nothing"
        );
    }

    /// The `OSError` escaping `_BindingServer.__init__` (here: binding inside
    /// a directory that does not exist) surfaces like Python's: the CLI
    /// mapping's `FileNotFoundError` shape, and an escaped built-in at the
    /// server/tools boundary.
    #[test]
    fn bind_failure_is_the_escaping_python_os_error() {
        let tmp = TempDir::new().unwrap();
        let error = bind_and_listen(&tmp.path().join("missing").join("s.sock")).unwrap_err();
        assert_eq!(
            error.to_dict(),
            json!({"error": "FileNotFoundError", "reason": "file_not_found"})
        );
        assert!(crate::gateway::is_escaped_builtin(&error));
        let output = crate::oracle::python(&format!(
            "import socket, os\ns = socket.socket(socket.AF_UNIX)\ntry:\n    s.bind({:?})\nexcept OSError as exc:\n    print(type(exc).__name__)\n",
            tmp.path().join("missing").join("s.sock").to_string_lossy()
        ));
        assert_eq!(output.trim(), "FileNotFoundError");
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

    // Regression test for finding G-R6-2: `normalize_pathlib_string` must
    // reproduce CPython's `pathlib` string normalization exactly --
    // collapsing repeated `/` separators and dropping `.` components (but
    // never resolving `..`), including pathlib's own leading-slash-run
    // special case (exactly two slashes preserved, one or three-or-more
    // collapsed to one). Compares directly against real `python3.12`'s
    // `str(pathlib.Path(x))` for the shapes the equivalence review named:
    // `//`, `/./`, a trailing slash, and `..`.
    #[test]
    fn normalize_pathlib_string_matches_python_pathlib_str() {
        let cases = [
            "/tmp/zpw//aaa",
            "/tmp/zpw/./aaa",
            "/tmp/zpw/aaa/",
            "/tmp/zpw/b/../aaa",
            "/tmp/zpw//",
            "/tmp/zpw///.",
            "//tmp/zpw",
            "///tmp/zpw",
            "////tmp/zpw",
            "/",
            "//",
            "///",
            "a//b",
            "a/./b",
            "./a/b",
            "../a/b",
            "",
        ];
        let script = format!(
            "from pathlib import Path\n\
             import json\n\
             cases = {cases:?}\n\
             print(json.dumps([str(Path(c)) for c in cases]))",
        );
        let python_json = crate::oracle::python(&script);
        let python_results: Vec<String> =
            serde_json::from_str(python_json.trim()).expect("python prints a JSON string array");
        assert_eq!(python_results.len(), cases.len());
        for (case, expected) in cases.iter().zip(python_results.iter()) {
            assert_eq!(&normalize_pathlib_string(case), expected, "input: {case:?}");
        }
    }

    // Regression test for finding G-R6-2: `choose_socket_dir` used to pass a
    // caller-supplied `preferred` candidate through unnormalized, so a
    // candidate containing a doubled separator (or `./`, or a trailing
    // slash) counted *longer* in Rust than Python's own `len(str(Path(...)))`
    // -- Python normalizes at `Path()` construction, before ever measuring or
    // creating anything. At exactly the `MAX_UNIX_PATH` boundary this shifted
    // where the length check trips: Python still used the operator's
    // configured directory while Rust silently fell back to a fresh private
    // temp directory instead. Picks a padding length so the *normalized*
    // probe sits exactly at the boundary while the *raw*, doubled-separator
    // probe is one character past it -- the exact shape the review measured.
    #[test]
    fn choose_socket_dir_normalizes_like_python_pathlib_at_the_boundary() {
        let base = format!("/tmp/g-r6-2-{}", short_hex_id());
        // probe = normalized_candidate + "/" + "s" * 24; want the
        // *normalized* probe length to land exactly at MAX_UNIX_PATH.
        let suffix_len = 24 + 1; // "/" + 24 "s" characters
        let clean_len = MAX_UNIX_PATH - suffix_len; // length of base + "/" + padding
        let padding_len = clean_len - base.chars().count() - 1;
        let padding = "d".repeat(padding_len);
        let normalized = format!("{base}/{padding}");

        for raw in [
            format!("{base}//{padding}"),   // doubled separator
            format!("{base}/./{padding}"),  // "." component
            format!("{base}/{padding}///"), // trailing separators
        ] {
            let script = format!(
                "import shutil\n\
                 from zeropw.signer import SignerManager\n\
                 d = SignerManager._choose_socket_dir({raw:?})\n\
                 print(str(d))\n\
                 shutil.rmtree(str(d), ignore_errors=True)\n",
            );
            let python_dir = crate::oracle::python(&script).trim().to_string();
            assert_eq!(
                python_dir, normalized,
                "python3.12 should normalize {raw:?} to the configured directory, \
                 not fall back to a temp dir"
            );

            let dir = choose_socket_dir(Some(PathBuf::from(&raw))).unwrap();
            assert_eq!(
                dir,
                PathBuf::from(&normalized),
                "rust should normalize {raw:?} to the configured directory, not \
                 fall back to a temp dir, matching python3.12 above"
            );
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
            std::fs::remove_dir_all(&normalized).unwrap();
        }
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
    // (G-R3-1), again for round 4 (G-R4-1), and again for round 5 (G-R5-1
    // documentation correction only -- no behaviour change here): a round-1
    // accept loop set the listener non-blocking and slept a fixed 200ms on
    // every `WouldBlock`, so a *new* connection could wait out nearly the
    // whole poll interval before being accepted at all -- ten sequential
    // connect+request cycles measured ~1.85s (~205ms each) instead of
    // Python's own real per-cycle latency. Round 2 avoided that regression
    // with a *blocking* accept woken by a hard-linked "wakeup" socket
    // (withdrawn: finding G-R3-1, a real second agent endpoint). Round 3's
    // replacement -- a non-blocking accept polled every fixed 1ms -- was
    // *itself* a regression the round-3 report's own (unreproducible)
    // Python numbers missed. This round replaces the fixed interval with
    // the event-driven `mio::Poll`/`Waker` wait in `accept_loop` (finding
    // G-R4-1): ten sequential cycles measure consistently in the low
    // single-digit milliseconds, no longer dominated by any fixed interval
    // at all.
    //
    // Round-5 re-measurement (finding G-R5-1's documentation correction:
    // the round-4 numbers below this comment, and the ones previously
    // quoted here and in `DEVIATIONS.md`, cited a Python baseline of
    // "6.8-22ms total" that this round could not reproduce and that
    // contradicted its own per-cycle figure; replaced with fresh
    // measurements, same method -- `time.monotonic()`/`Instant::now()`, ten
    // sequential connect+`REQUEST_IDENTITIES` cycles, five repeated runs
    // each -- in this environment):
    //   * Python (`python3.12`): total 4.17-6.37ms per run of 10 cycles
    //     (one outlier run measured 33.68ms, its first two cycles alone
    //     accounting for ~11.5ms -- the same one-off thread-startup jitter
    //     the round-4 text already called out); per-cycle typical
    //     0.26-0.94ms.
    //   * Rust, debug build (`cargo test`, unoptimized+debuginfo): total
    //     4.12-10.42ms per run; per-cycle 0.37-1.49ms -- the same order of
    //     magnitude as Python, sometimes above it (debug-build overhead,
    //     not a fixed interval: no run showed the round-3 busy-poll's
    //     ~1.5ms/cycle floor).
    //   * Rust, release build (`cargo test --release`): total 1.12-2.29ms
    //     per run; per-cycle 0.09-0.50ms -- consistently at or below
    //     Python's own real number.
    // Conclusion stands on these numbers: no fixed poll interval, and Rust
    // at or better than Python once built in release. Prints per-connection
    // latency under `--nocapture` so it can be compared directly against a
    // real Python signer's own numbers; the assertion pins a bound with
    // headroom above the debug-build range measured above (a loaded CI host
    // normally runs debug tests) but far tighter than the old, 35x-looser
    // 500ms bound (which would not have caught either the round-1 or the
    // round-3 regression).
    //
    // A fixed poll interval raises the floor of every run, so the pin is
    // on the fastest of up to three runs of the same ten cycles: one
    // scheduler stall while the rest of the library suite saturates the
    // host's CPUs (measured: one failing full `cargo test --lib` run in
    // three on a 4-CPU host, the test alone passing every time) cannot fail
    // it, while any fixed interval still fails all three.
    #[test]
    fn accept_latency_is_not_bound_by_a_fixed_poll_interval() {
        let f = fixture();
        let bound = Duration::from_millis(25);
        let mut runs = Vec::with_capacity(3);
        for _ in 0..3 {
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
                "[G-R5-1] Rust connect+REQUEST_IDENTITIES latency per cycle: {samples:?} (total \
                 {elapsed:?}; this session's own measurements in this environment: real \
                 python3.12 4.17-6.37ms total/10 cycles (0.26-0.94ms/cycle typical), Rust debug \
                 4.12-10.42ms total (0.37-1.49ms/cycle), Rust release 1.12-2.29ms total \
                 (0.09-0.50ms/cycle) -- see DEVIATIONS.md and the comment above this test)"
            );
            runs.push(elapsed);
            if elapsed < bound {
                break;
            }
        }
        let best = *runs.iter().min().expect("at least one run");
        assert!(
            best < bound,
            "10 sequential connections took {runs:?} in every run; this environment measures \
             4.12-10.42ms for a debug build of the same workload with the event-driven \
             accept wait (finding G-R4-1/G-R5-1) -- 25ms is a real, tight pin (not the old, \
             35x-loose 500ms) with headroom for a loaded CI host, and is still far below \
             round 3's own busy-poll regression"
        );
    }

    // Regression test for finding G-R5-1: Python's `_BindingServer.__init__`
    // calls `self._sock.listen(16)`, an explicit backlog. `bind_and_listen` used to
    // build the listener with `std::os::unix::net::UnixListener::bind`,
    // which has no way to request anything but the OS default backlog (128
    // on this crate's target platforms) -- comfortably above every burst
    // this crate's own tests exercised, so it silently accepted bursts
    // Python would have refused. `bind_and_listen` now uses
    // `socket2::Socket::listen(SIGNER_LISTEN_BACKLOG)` (16) instead, the
    // same audited-safe-wrapper-crate precedent already accepted for `mio`.
    //
    // Do not involve the accept loop here: if it drains fast enough (as it
    // did on Ubuntu CI), all 40 connects can succeed despite a backlog of
    // 16, making a scheduler race look like a product failure. Instead keep
    // the listener idle and issue non-blocking connects while retaining
    // every queued socket. Darwin reports `ECONNREFUSED` once full; Linux
    // reports `EAGAIN`/`WouldBlock`. Either is the same observable boundary:
    // the queue cannot admit the full burst while nothing accepts from it.
    #[test]
    fn idle_listener_backlog_caps_pending_connects_like_python() {
        const BURST: usize = 40;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("backlog.sock");
        let _listener = bind_and_listen(&path).unwrap();
        let addr = SockAddr::unix(&path).unwrap();
        let mut clients = Vec::with_capacity(BURST);
        let mut admitted = 0usize;

        for _ in 0..BURST {
            let socket = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
            socket.set_nonblocking(true).unwrap();
            if socket.connect(&addr).is_ok() {
                admitted += 1;
            }
            clients.push(socket);
        }

        assert!(
            admitted < BURST,
            "an idle backlog-{SIGNER_LISTEN_BACKLOG} listener admitted all {BURST} \
             non-blocking connects"
        );
        assert_eq!(
            clients.len(),
            BURST,
            "retain every client so the pending queue cannot shrink during the probe"
        );
    }

    // Measurement-only, not a correctness assertion: idle CPU with 1 and
    // with 9 live bindings, the second half of finding G-R4-2's ruling
    // (round 3's fixed 1ms busy-poll accept loop woke every live binding's
    // accept thread 700-1000 times/second forever, even fully idle --
    // measured at the time as 10ms/5s with 1 binding and 160ms/5s with 9,
    // 25-70x Python's own idle CPU). Ignored by default (measuring 2 x 5.3s
    // of real wall-clock idle time is not something an ordinary `cargo test`
    // run should pay for); run explicitly with `--ignored --nocapture` to
    // reproduce the numbers quoted in `DEVIATIONS.md`. Uses `ps -o time=`
    // (whole-process cumulative CPU time, centisecond resolution on macOS)
    // rather than `libc::getrusage`, since an FFI call would need `unsafe`,
    // which `rust/PORTING.md`'s engineering rules bar outside `store.rs`.
    #[test]
    #[ignore]
    fn idle_cpu_with_one_and_nine_live_bindings() {
        fn cpu_time_secs() -> f64 {
            let pid = std::process::id().to_string();
            let out = std::process::Command::new("ps")
                .args(["-o", "time=", "-p", &pid])
                .output()
                .expect("ps must be available to measure idle CPU");
            let text = String::from_utf8_lossy(&out.stdout);
            let text = text.trim();
            let mut fields: Vec<f64> = text
                .rsplit(':')
                .map(|f| f.parse::<f64>().expect("ps TIME field must be numeric"))
                .collect();
            fields.resize(3, 0.0); // [ss, mm, hh], missing higher fields default to 0
            fields[2] * 3600.0 + fields[1] * 60.0 + fields[0]
        }

        let f = fixture();
        thread::sleep(Duration::from_millis(300));
        let before = cpu_time_secs();
        thread::sleep(Duration::from_secs(5));
        let after = cpu_time_secs();
        eprintln!(
            "[G-R4-2] Rust idle CPU over 5s with 1 live binding: {:.4}s (real python3.12 \
             measured ~0.0006s for the same scenario)",
            after - before
        );

        let mut _extra = Vec::with_capacity(8);
        for _ in 0..8 {
            let grant = f
                .ctx
                .policy
                .create_grant("agent-1", "box", Some(3600), None)
                .unwrap();
            _extra.push(f.manager.bind("agent-1", "box", &grant.id).unwrap());
        }
        thread::sleep(Duration::from_millis(300));
        let before = cpu_time_secs();
        thread::sleep(Duration::from_secs(5));
        let after = cpu_time_secs();
        eprintln!(
            "[G-R4-2] Rust idle CPU over 5s with 9 live bindings: {:.4}s (real python3.12 \
             measured ~0.0037s for the same scenario)",
            after - before
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

    // Regression test for finding G-R6-1: `handle_accepted` used to
    // `try_clone()` a *second*, independent fd per admitted client purely so
    // `close()` could `shutdown()` it while the serving thread read/wrote
    // through its own separate fd -- 2 fds per client where Python's
    // `self._clients[thread] = client` keeps exactly 1 (`self._sock.accept()`'s
    // own return value, shared by both `close()` and the serving thread).
    // The reviewer's `RLIMIT_NOFILE` sweep showed this doubling roughly
    // halves how many clients a binding can serve before `accept()` starts
    // failing, and (worse) an accept-time `EMFILE` after that point kills the
    // accept loop for good with no audit record -- exactly matching Python's
    // own `except OSError: break` shape, just triggered twice as early.
    // `ClientSlot`/`SharedStream` now share one `Arc<UnixStream>` instead --
    // asserted directly here via `Arc::strong_count` rather than an fd count
    // (deterministic and immune to unrelated tests' own fd churn in the same
    // process, unlike the process-wide `/dev/fd` measurements below, which
    // are `#[ignore]`d for exactly that reason).
    #[test]
    fn client_slot_shares_the_accepted_stream_with_its_worker_thread() {
        let f = fixture();
        let server = f.server();
        let mut conn = f.connect();
        assert_eq!(
            conn.request(&[sshwire::SSH_AGENTC_REQUEST_IDENTITIES])
                .unwrap()[0],
            sshwire::SSH_AGENT_IDENTITIES_ANSWER
        );
        let clients = server.clients.lock().unwrap();
        let slot = clients.values().next().expect("one live client");
        // 2 = one clone in `ClientSlot::stream`, one in the serving
        // thread's `SharedStream` (still alive, blocked reading the next
        // message). Before the fix there was no `Arc` at all: `handle_accepted`
        // `try_clone()`d a wholly separate fd instead, so this assertion
        // could not even be expressed against the old code.
        assert_eq!(
            Arc::strong_count(&slot.stream),
            2,
            "ClientSlot and the serving thread must share one Arc<UnixStream> \
             (one accepted fd), not hold two independently opened streams"
        );
    }

    /// Counts this process's open file descriptors via `/dev/fd`, the same
    /// technique the equivalence review used `lsof` for (finding G-R6-1).
    /// Used by both `#[ignore]`d fd-ratio measurement tests below.
    fn open_fd_count() -> usize {
        std::fs::read_dir("/dev/fd").map(|d| d.count()).unwrap_or(0)
    }

    /// Serializes the two `#[ignore]`d fd-ratio measurement tests below
    /// against each other (both do process-wide before/after `/dev/fd`
    /// snapshots, so running them concurrently would have each one's fd
    /// churn pollute the other's count) when run together, e.g. `cargo test
    /// --offline -- --ignored fd_cost`. Does not, and cannot, protect against
    /// unrelated tests' own fd churn if run alongside the rest of the suite
    /// -- hence `#[ignore]`, matching `idle_cpu_with_one_and_nine_live_bindings`'s
    /// own convention for a process-wide measurement that only means
    /// anything with nothing else contending for the same process's fd table.
    static FD_MEASUREMENT_LOCK: StdMutex<()> = StdMutex::new(());

    // Measurement, not a correctness gate (see `FD_MEASUREMENT_LOCK`; the
    // real regression pin for this fix is
    // `client_slot_shares_the_accepted_stream_with_its_worker_thread` above).
    // Re-derives the fd-per-client ratio the reviewer measured with `lsof`
    // (1.00 for Python, 2.00 for the pre-fix Rust) directly against this
    // fix. Run explicitly: `cargo test --offline -- --ignored --nocapture
    // per_client_fd_cost`.
    #[test]
    #[ignore]
    fn per_client_fd_cost_matches_python_ratio_of_one() {
        let _guard = FD_MEASUREMENT_LOCK.lock().unwrap();
        let f = fixture();
        const N: usize = 30;
        let before = open_fd_count();
        let mut conns = Vec::with_capacity(N);
        for i in 0..N {
            // Admit one at a time (waiting for each to register before the
            // next `connect()`) rather than firing `N` connects back to
            // back: this binding's listener has Python's own backlog of 16
            // (`SIGNER_LISTEN_BACKLOG`, finding G-R5-1), and a tight connect
            // loop can outrun the accept loop's per-connection admission
            // work (lock, `accept()`, thread spawn) faster than that
            // backlog drains -- exactly what
            // `idle_listener_backlog_caps_pending_connects_like_python` deliberately
            // exercises. This test cares about steady-state fd cost per
            // admitted client, not backlog behaviour, so it avoids that
            // failure mode instead of racing it.
            conns.push(f.connect());
            assert!(f.wait_until(
                || f.server().clients.lock().unwrap().len() == i + 1,
                Duration::from_secs(5)
            ));
        }
        let after = open_fd_count();
        let delta = after.saturating_sub(before);
        let server_side_ratio = (delta as f64 / N as f64) - 1.0; // minus the 1 client-side fd/conn this test itself opens
        eprintln!(
            "[G-R6-1] {N} concurrent clients on one binding: {delta} new fds \
             total ({:.2} fds/client server-side; Python measured 1.00, the \
             pre-fix Rust measured 2.00)",
            server_side_ratio
        );
        drop(conns);
    }

    // Measurement, not a correctness gate (see `FD_MEASUREMENT_LOCK` and the
    // note on the test above). Documents the accepted per-binding fd-cost
    // deviation recorded in `DEVIATIONS.md` (finding G-R6-1): Python's
    // `_BindingServer.__init__` opens exactly 1 fd per binding (`self._sock`),
    // while this port's event-driven accept wait (finding G-R4-1) needs
    // `mio::Poll` (its own kqueue/epoll fd) plus a `mio::Waker` (a second
    // kqueue-based fd on this platform) in addition to the listening socket
    // itself -- 3 fds/binding. Run explicitly: `cargo test --offline --
    // --ignored --nocapture per_binding_fd_cost`.
    #[test]
    #[ignore]
    fn per_binding_fd_cost_matches_documented_ratio_of_three() {
        let _guard = FD_MEASUREMENT_LOCK.lock().unwrap();
        let f = fixture(); // already has 1 live binding
        const N: usize = 10;
        let before = open_fd_count();
        let mut _extra = Vec::with_capacity(N);
        for _ in 0..N {
            let grant = f
                .ctx
                .policy
                .create_grant("agent-1", "box", Some(3600), None)
                .unwrap();
            _extra.push(f.manager.bind("agent-1", "box", &grant.id).unwrap());
        }
        let after = open_fd_count();
        let delta = after.saturating_sub(before);
        eprintln!(
            "[G-R6-1] {N} new bindings (no clients): {delta} new fds ({:.2} \
             fds/binding; Python's own `_BindingServer.__init__` costs \
             exactly 1 fd/binding -- `self._sock`)",
            delta as f64 / N as f64
        );
    }

    // Reproduces the equivalence reviewer's `RLIMIT_NOFILE` sweep for this
    // process's *current* fd limit (report-only; cannot itself lower
    // `RLIMIT_NOFILE`, since that needs an `unsafe` `libc::setrlimit` call
    // this crate's engineering rules forbid outside `store.rs`). Driven
    // externally across several limits with `sh -c 'ulimit -n N && exec
    // cargo test ...'`, mirroring how the review varied the limit against
    // the real Python signer. `#[ignore]`d for the same reason as the fd-
    // ratio measurements above: a real fd-table probe, not a fast
    // deterministic unit test.
    #[test]
    #[ignore]
    fn rlimit_probe_served_clients_and_accept_loop_survival() {
        let f = fixture();
        f.manager.set_max_agent_clients(DEFAULT_MAX_AGENT_CLIENTS); // Python's own default cap
        let mut conns = Vec::new();
        for _ in 0..DEFAULT_MAX_AGENT_CLIENTS + 8 {
            match UnixStream::connect(&f.binding.socket_path) {
                Ok(s) => conns.push(s),
                Err(_) => break, // this process's own fd budget is exhausted too
            }
            // Give the accept loop a brief window to admit or refuse this
            // connection before firing the next one: this binding's listener
            // has Python's own backlog of 16 (`SIGNER_LISTEN_BACKLOG`), and
            // this probe is about the fd-limit boundary, not the separate,
            // already-covered backlog boundary (`idle_listener_backlog_caps_
            // pending_connects_like_python`) -- an unpaced burst would conflate the two.
            thread::sleep(Duration::from_millis(15));
        }
        thread::sleep(Duration::from_millis(300));
        let served = f.server().clients.lock().unwrap().len();
        let too_many_recorded = f.has_reason("too_many_agent_clients");
        conns.clear();
        // Wait for every admitted client's fd to actually be released
        // (server-side thread exit, not just this process's own closed
        // client-side handles) before judging whether the accept loop
        // survived -- a fixed sleep risks a false "dead" reading from this
        // probe's own reconnect attempt racing fd reclamation, not from the
        // accept loop itself.
        let _ = f.wait_until(
            || f.server().clients.lock().unwrap().is_empty(),
            Duration::from_secs(5),
        );
        let accept_loop_alive_after = match UnixStream::connect(&f.binding.socket_path) {
            Ok(sock) => {
                let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = sock.set_write_timeout(Some(Duration::from_secs(2)));
                let mut conn = sshwire::AgentConnection::new(sock);
                conn.request(&[sshwire::SSH_AGENTC_REQUEST_IDENTITIES])
                    .is_ok_and(|r| r[0] == sshwire::SSH_AGENT_IDENTITIES_ANSWER)
            }
            Err(_) => false,
        };
        eprintln!(
            "[G-R6-1 rlimit probe] RLIMIT_NOFILE={:?} served={served} \
             too_many_agent_clients_recorded={too_many_recorded} \
             accept_loop_alive_after={accept_loop_alive_after}",
            rlimit_nofile_soft_for_reporting()
        );
    }

    /// Best-effort, report-only: reads this process's own soft `RLIMIT_NOFILE`
    /// via `/proc`-free `getrlimit(2)` is unavailable without `unsafe` FFI
    /// (barred outside `store.rs`), so this shells out to `ulimit -n`
    /// instead -- purely to label the eprintln above, never used for any
    /// control-flow decision.
    fn rlimit_nofile_soft_for_reporting() -> String {
        std::process::Command::new("sh")
            .arg("-c")
            .arg("ulimit -n")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|| "?".to_string())
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
        let server = f.server();
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
        let ctx = Arc::clone(&f.ctx);
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

        // Finding G-R4-3: `close()` detaches (does not join) the client
        // thread that was wedged on `state.lock()` above, since it is well
        // past `CLIENT_JOIN_TIMEOUT` by the time `close()` gives up on it.
        // Once `release_tx` unblocks the holder thread, that detached
        // client thread resumes inside `policy.consume` -> `state.lock()`,
        // finishes handling the sign request, and writes an `ssh_sign`
        // audit record -- all *after* this test function would otherwise
        // have returned and let `f`'s `TempDir` be removed. A detached
        // thread that outlives the fixture and later recreates
        // `<tmp>/state/.lock`/`<tmp>/state/audit/audit.jsonl` under an
        // already-deleted path is exactly the leak this finding describes,
        // so wait for it to actually finish (it removes its own `ClientSlot`
        // from `clients`, right before returning, as the single point that
        // ever does so -- see `serve_client`) before letting `f` drop.
        assert!(
            f.wait_until(
                || server.clients.lock().unwrap().is_empty(),
                Duration::from_secs(5)
            ),
            "the wedged client thread must finish (and remove its own slot) before the test \
             ends, so it cannot outlive the fixture's TempDir and recreate state under a \
             deleted path"
        );
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
        let ctx = Arc::clone(&f.ctx);
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

        // Finding G-R4-3: as in the test above, releasing the holder thread
        // lets the detached, wedged client thread resume and finish its sign
        // request (writing an `ssh_sign` audit record) well after `close()`
        // already returned. Wait for it to remove its own `ClientSlot` from
        // `clients` (the single point that ever does so, right before it
        // returns) before this test ends and `f`'s `TempDir` is removed --
        // otherwise that thread can still be running when the directory it
        // writes state/audit files under is gone, recreating
        // `<tmp>/state/.lock`/`<tmp>/state/audit/audit.jsonl` under an
        // already-deleted path.
        assert!(
            f.wait_until(
                || server.clients.lock().unwrap().is_empty(),
                Duration::from_secs(5)
            ),
            "the wedged client thread must finish (and remove its own slot) before the test \
             ends, so it cannot outlive the fixture's TempDir and recreate state under a \
             deleted path"
        );
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
        let tmp_root;
        {
            let f = fixture();
            socket_path = f.binding.socket_path.clone();
            socket_dir = f.manager.socket_dir().to_path_buf();
            server_weak = Arc::downgrade(&f.server());
            tmp_root = f._tmp.path().to_path_buf();
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
        // Finding G-R4-3: checking only the socket file, `socket_dir` and the
        // `BindingServer` weak ref missed a detached client thread left
        // wedged on `state.lock()` by `close()` (finding G-R2-5's bounded
        // detach path) -- once whatever held that lock let go, the detached
        // thread would resume, finish handling its sign request, and
        // recreate `<tmp>/state/.lock`/`<tmp>/state/audit/audit.jsonl` under
        // this already-removed fixture root. Asserting the whole `TempDir`
        // root is gone catches that (and any other stray write under it)
        // regardless of which specific path it recreates.
        assert!(
            !tmp_root.exists(),
            "the fixture's whole TempDir root must not survive teardown -- a surviving \
             directory here means something (e.g. a detached client thread wedged past \
             close()'s deadline) wrote under it after the fixture was supposed to be gone"
        );
    }
}
