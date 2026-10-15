//! The in-app terminal (docs/desktop-app.md §4.4).
//!
//! - The user's login shell runs on a PTY. `ZEROPW_GATEWAY_URL`, `ZEROPW_CALLER_TOKEN` and
//!   `no_proxy=127.0.0.1,localhost` are placed in its environment and `PATH` starts with the
//!   bundled binaries' folder. The token is never typed into the PTY, so it is in neither the
//!   screen nor the shell history. It lives in the environment of the shell and of everything
//!   started from it, so closing the terminal stops all of those (below).
//! - The rest of the environment is an allowlist taken from the app process (`HOME`, `USER`,
//!   locale, …); anything else, including any `ZEROPW_*` variable, is dropped.
//! - Suggested commands are returned for the UI to place at the prompt; nothing runs until the
//!   user presses Enter. For another macOS account the first suggestion is
//!   `sudo --preserve-env=ZEROPW_GATEWAY_URL,ZEROPW_CALLER_TOKEN,no_proxy -u <account> -i`.
//! - Output goes to a [`TerminalSink`] (the Tauri layer wraps a `Channel<string>`).
//! - Terminals outlive the view that opened them: each session stays in the registry with a
//!   bounded output ring ([`RING_BYTES`]). [`TerminalManager::attach`] replays the ring into a
//!   new sink and then keeps streaming to it, so the Agents page (or a reopened window) can
//!   pick a running agent shell back up. An exited shell stays listed (not alive) until it is
//!   closed or its slot is needed.
//! - Keyboard input goes through a bounded per-terminal queue ([`MAX_QUEUED_INPUT`]) drained
//!   by that terminal's writer thread. A PTY write can block in the kernel for as long as the
//!   foreground program does not read (a long paste into a running build), so no write ever
//!   happens under the registry lock or on the caller's thread; a full queue answers
//!   `terminal_busy` instead of waiting.
//! - Closing a terminal (and quitting the app, which closes them all) stops the processes it
//!   started, not only the shell: every process group of the shell, its descendants and every
//!   process whose controlling terminal is this PTY gets SIGHUP (and SIGCONT), and whatever is
//!   left after [`CLOSE_GRACE`] gets SIGKILL. `close` returns once that is done. Out of reach:
//!   a process that left the terminal's session and process tree (`setsid` plus a double fork,
//!   a daemon), and processes running as another account (`sudo -u`), which the app may not
//!   signal; those only get the hang-up the kernel sends when the shell goes away.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use portable_pty::{ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system};
use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

use crate::error::AppError;
use crate::onetime::random_ref;
use crate::paths::AGENT_BIN;
use crate::secret::SecretString;

pub const GATEWAY_URL_VAR: &str = "ZEROPW_GATEWAY_URL";
pub const CALLER_TOKEN_VAR: &str = "ZEROPW_CALLER_TOKEN";
pub const NO_PROXY_VALUE: &str = "127.0.0.1,localhost";
const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";
/// Sessions kept in the registry, alive or exited.
const MAX_TERMINALS: usize = 8;
/// Output kept per terminal for reattaching.
pub const RING_BYTES: usize = 256 * 1024;
/// When the ring drops old output it also drops the rest of a cut line, looking this far.
const RING_LINE_SEEK: usize = 4096;
const MAX_WRITE_BYTES: usize = 64 * 1024;
/// Keyboard input a terminal may hold while its program is not reading; beyond it
/// `terminal_write` answers `terminal_busy`.
pub const MAX_QUEUED_INPUT: usize = 256 * 1024;
/// How long a closed terminal's processes get to exit on SIGHUP before they are killed.
pub const CLOSE_GRACE: Duration = Duration::from_secs(2);
const CLOSE_POLL: Duration = Duration::from_millis(25);

/// Variables copied from the app's own environment into the shell.
const INHERITED: [&str; 10] = [
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "TMPDIR",
    "TZ",
];

/// Receives terminal output. `data` gets UTF-8 text (split multi-byte sequences are held back
/// until complete); `exit` is called once when the shell has exited.
pub trait TerminalSink: Send + 'static {
    fn data(&mut self, chunk: &str);
    fn exit(&mut self, code: Option<u32>);
}

/// What to run in the PTY. `LoginShell` is the product behavior; `Program` exists for tests
/// and is never reachable from IPC input.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum TerminalProgram {
    #[default]
    LoginShell,
    Program {
        path: PathBuf,
        args: Vec<String>,
    },
}

/// One terminal's launch parameters.
pub struct TerminalRequest<'a> {
    pub gateway_url: &'a str,
    pub token: &'a SecretString,
    pub bin_dir: &'a Path,
    pub cols: u16,
    pub rows: u16,
    /// The principal whose caller token the shell holds (shown in `terminal_list`).
    pub principal: &'a str,
    /// The macOS account the first suggestion switches to, if any.
    pub as_user: Option<&'a str>,
}

/// A `terminal_list` row. Value-free: no token, no output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TerminalSummary {
    pub terminal_id: String,
    pub principal: String,
    pub as_user: Option<String>,
    pub alive: bool,
}

/// The last [`RING_BYTES`] of a terminal's output, cut only at UTF-8 character boundaries
/// (and, when one is near, at a line end). The buffer is allocated once and wiped on drop.
pub struct OutputRing {
    buf: VecDeque<u8>,
    cap: usize,
}

impl OutputRing {
    pub fn new(cap: usize) -> Self {
        Self {
            buf: VecDeque::with_capacity(cap),
            cap,
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Append `text`, dropping the oldest output beyond the capacity. Never grows the buffer.
    /// When output is cut, the rest of the cut line goes too if its end is near.
    pub fn push(&mut self, text: &str) {
        if self.cap == 0 || text.is_empty() {
            return;
        }
        let mut start = text.len().saturating_sub(self.cap);
        while !text.is_char_boundary(start) {
            start += 1;
        }
        let mut bytes = &text.as_bytes()[start..];
        let overflow = (self.buf.len() + bytes.len()).saturating_sub(self.cap);
        let cut_mid_line = if overflow > 0 {
            let drop = overflow.min(self.buf.len());
            let mid_line = drop > 0 && self.buf.get(drop - 1) != Some(&b'\n');
            self.buf.drain(..drop);
            mid_line || (start > 0 && text.as_bytes()[start - 1] != b'\n')
        } else {
            start > 0 && text.as_bytes()[start - 1] != b'\n'
        };
        if cut_mid_line {
            let old = self.buf.len();
            let newline = self
                .buf
                .iter()
                .chain(bytes.iter())
                .take(RING_LINE_SEEK)
                .position(|&b| b == b'\n');
            match newline {
                Some(end) if end < old => {
                    self.buf.drain(..=end);
                }
                Some(end) => {
                    self.buf.clear();
                    bytes = &bytes[end - old + 1..];
                }
                None => {
                    while self.buf.front().is_some_and(|b| b & 0xC0 == 0x80) {
                        self.buf.pop_front();
                    }
                }
            }
        }
        self.buf.extend(bytes);
    }

    /// Everything buffered, as text.
    pub fn text(&self) -> String {
        let (a, b) = self.buf.as_slices();
        let mut bytes = Vec::with_capacity(a.len() + b.len());
        bytes.extend_from_slice(a);
        bytes.extend_from_slice(b);
        match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
        }
    }
}

impl Drop for OutputRing {
    fn drop(&mut self) {
        // Fill the whole allocation (live and dropped slots) and wipe it.
        let capacity = self.buf.capacity();
        self.buf.resize(capacity, 0);
        let (a, b) = self.buf.as_mut_slices();
        a.zeroize();
        b.zeroize();
    }
}

/// The shell environment: allowlisted parent variables, terminal type, `PATH` with the bundle
/// folder first, and the three injected variables.
pub fn build_env<I>(parent: I, req: &TerminalRequest<'_>) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let mut parent_path = None;
    let mut env: Vec<(OsString, OsString)> = Vec::new();
    for (key, value) in parent {
        if key == OsStr::new("PATH") {
            parent_path = Some(value);
        } else if INHERITED.iter().any(|k| OsStr::new(k) == key) {
            env.push((key, value));
        }
    }
    let mut path = req.bin_dir.as_os_str().to_owned();
    path.push(":");
    match parent_path.filter(|p| !p.is_empty()) {
        Some(p) => path.push(p),
        None => path.push(DEFAULT_PATH),
    }
    env.push(("PATH".into(), path));
    // Apps started from Finder often have no locale; without one, Korean output breaks.
    let has_locale = env
        .iter()
        .any(|(k, v)| ["LANG", "LC_ALL", "LC_CTYPE"].iter().any(|n| k == n) && !v.is_empty());
    if !has_locale {
        let lang = if cfg!(target_os = "macos") {
            "en_US.UTF-8"
        } else {
            "C.UTF-8"
        };
        env.push(("LANG".into(), lang.into()));
    }
    env.push(("TERM".into(), "xterm-256color".into()));
    env.push(("COLORTERM".into(), "truecolor".into()));
    env.push((GATEWAY_URL_VAR.into(), req.gateway_url.into()));
    env.push((CALLER_TOKEN_VAR.into(), req.token.expose().into()));
    env.push(("no_proxy".into(), NO_PROXY_VALUE.into()));
    env.push(("NO_PROXY".into(), NO_PROXY_VALUE.into()));
    env
}

/// A macOS short account name the `sudo -u` suggestion may name.
pub fn is_account_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// Commands to place at the prompt, in order. Nothing here is executed by the core.
pub fn suggestions(bin_dir: &Path, as_user: Option<&str>) -> Result<Vec<String>, AppError> {
    let mut out = Vec::new();
    if let Some(user) = as_user {
        if !is_account_name(user) {
            return Err(AppError::invalid_input("invalid_account").with_detail("as_user"));
        }
        out.push(format!(
            "sudo --preserve-env={GATEWAY_URL_VAR},{CALLER_TOKEN_VAR},no_proxy -u {user} -i"
        ));
    }
    let agent = bin_dir.join(AGENT_BIN);
    out.push(format!(
        "{} list-connections",
        shell_quote(&agent.to_string_lossy())
    ));
    Ok(out)
}

/// POSIX shell quoting: bare when only safe characters, otherwise single-quoted.
pub fn shell_quote(text: &str) -> String {
    let safe = !text.is_empty()
        && text.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'/' | b'.' | b'_' | b'-' | b'+' | b':' | b'@' | b'%' | b',' | b'='
                )
        });
    if safe {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

/// Incremental UTF-8 decoding for PTY chunks: incomplete trailing sequences wait for the next
/// chunk; invalid bytes become U+FFFD.
#[derive(Default)]
pub struct Utf8Chunker {
    pending: Vec<u8>,
}

impl Utf8Chunker {
    pub fn push(&mut self, bytes: &[u8]) -> String {
        self.pending.extend_from_slice(bytes);
        let mut out = String::new();
        let mut rest: &[u8] = &self.pending;
        loop {
            match std::str::from_utf8(rest) {
                Ok(text) => {
                    out.push_str(text);
                    rest = &[];
                    break;
                }
                Err(e) => {
                    let (valid, after) = rest.split_at(e.valid_up_to());
                    out.push_str(std::str::from_utf8(valid).unwrap_or_default());
                    match e.error_len() {
                        Some(bad) => {
                            out.push('\u{FFFD}');
                            rest = &after[bad..];
                        }
                        None => {
                            rest = after;
                            break;
                        }
                    }
                }
            }
        }
        self.pending = rest.to_vec();
        out
    }

    /// Whatever is left at end of stream.
    pub fn finish(&mut self) -> String {
        let rest = std::mem::take(&mut self.pending);
        String::from_utf8_lossy(&rest).into_owned()
    }
}

/// What the reader thread and `attach` share: the ring, the current sink and the exit status.
/// Holding this lock while writing to the sink keeps replay and live output in order.
struct Output {
    ring: OutputRing,
    sink: Option<Box<dyn TerminalSink>>,
    /// `Some(code)` once the shell has exited.
    exit: Option<Option<u32>>,
}

/// Keyboard input on its way to one terminal. `terminal_write` only queues; the terminal's
/// writer thread ([`feed`]) does the PTY writes, which may block while the foreground program
/// is not reading. Queued input is wiped when it is written or dropped.
struct InputQueue {
    state: Mutex<InputState>,
    ready: Condvar,
}

#[derive(Default)]
struct InputState {
    chunks: VecDeque<Zeroizing<Vec<u8>>>,
    /// Bytes in `chunks` (the chunk being written no longer counts).
    bytes: usize,
    /// No more input: the terminal is closing or a write failed.
    closed: bool,
    /// Why a write failed (it closed the queue).
    failed: Option<std::io::ErrorKind>,
}

impl InputQueue {
    fn new() -> Self {
        Self {
            state: Mutex::new(InputState::default()),
            ready: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, InputState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn push(&self, data: &[u8]) -> Result<(), AppError> {
        let mut state = self.lock();
        if let Some(kind) = state.failed {
            return Err(write_failed().with_detail(format!("{kind:?}")));
        }
        if state.closed {
            return Err(unknown());
        }
        if data.is_empty() {
            return Ok(());
        }
        if state.bytes + data.len() > MAX_QUEUED_INPUT {
            return Err(AppError::unavailable("terminal_busy"));
        }
        state.bytes += data.len();
        state.chunks.push_back(Zeroizing::new(data.to_vec()));
        self.ready.notify_one();
        Ok(())
    }

    /// The next chunk to write, waiting for one; `None` once the queue is closed.
    fn next(&self) -> Option<Zeroizing<Vec<u8>>> {
        let mut state = self.lock();
        loop {
            if state.closed {
                return None;
            }
            if let Some(chunk) = state.chunks.pop_front() {
                state.bytes -= chunk.len();
                return Some(chunk);
            }
            state = self.ready.wait(state).unwrap_or_else(|e| e.into_inner());
        }
    }

    /// Stop taking input and drop (wipe) whatever is still queued.
    fn close(&self, failed: Option<std::io::ErrorKind>) {
        let mut state = self.lock();
        state.closed = true;
        if state.failed.is_none() {
            state.failed = failed;
        }
        state.chunks.clear();
        state.bytes = 0;
        self.ready.notify_all();
    }
}

/// A terminal's writer thread: PTY writes happen here and nowhere else, so one that blocks
/// holds up only this thread. It ends when the queue closes or a write fails. (Dropping
/// portable-pty's writer sends a final newline and EOF, which can block too; it happens here.)
fn feed(mut writer: Box<dyn Write + Send>, input: Arc<InputQueue>) {
    while let Some(chunk) = input.next() {
        if let Err(e) = writer.write_all(&chunk).and_then(|_| writer.flush()) {
            input.close(Some(e.kind()));
            break;
        }
    }
}

struct Session {
    master: Box<dyn MasterPty + Send>,
    input: Arc<InputQueue>,
    killer: Box<dyn ChildKiller + Send + Sync>,
    pid: Option<u32>,
    /// The PTY's slave as `ps` names it (`ttys012`, `pts/3`): the controlling terminal of every
    /// process still attached to this terminal.
    tty: Option<String>,
    exited: Arc<AtomicBool>,
    output: Arc<Mutex<Output>>,
    principal: String,
    as_user: Option<String>,
    /// Open order, for listing and for evicting the oldest exited session.
    seq: u64,
}

impl Drop for Session {
    fn drop(&mut self) {
        // Ends the writer thread (unless a write is stuck in the kernel; it then ends when
        // the PTY goes away or the app exits).
        self.input.close(None);
    }
}

/// What `attach` tells the caller about the terminal it reattached to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachedTerminal {
    pub principal: String,
    pub as_user: Option<String>,
    pub alive: bool,
}

/// Terminals by id: running shells and exited ones not yet closed.
pub struct TerminalManager {
    program: TerminalProgram,
    ring_bytes: usize,
    sessions: Mutex<HashMap<String, Session>>,
    next_seq: AtomicU64,
}

impl TerminalManager {
    pub fn new(program: TerminalProgram) -> Self {
        Self::with_ring_bytes(program, RING_BYTES)
    }

    /// A manager whose per-terminal ring holds `ring_bytes` (tests use a small one).
    pub fn with_ring_bytes(program: TerminalProgram, ring_bytes: usize) -> Self {
        Self {
            program,
            ring_bytes,
            sessions: Mutex::new(HashMap::new()),
            next_seq: AtomicU64::new(0),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Session>> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Make room for one more session: exited sessions go first, oldest first. The evicted
    /// sessions are returned so their leftover processes can be stopped outside the lock.
    fn reserve_slot(&self) -> Result<Vec<Session>, AppError> {
        let mut sessions = self.lock();
        let mut evicted = Vec::new();
        while sessions.len() >= MAX_TERMINALS {
            let oldest_exited = sessions
                .iter()
                .filter(|(_, s)| s.exited.load(Ordering::SeqCst))
                .min_by_key(|(_, s)| s.seq)
                .map(|(id, _)| id.clone());
            match oldest_exited.and_then(|id| sessions.remove(&id)) {
                Some(session) => evicted.push(session),
                None => {
                    drop(sessions);
                    stop_sessions(evicted);
                    return Err(AppError::unavailable("too_many_terminals"));
                }
            }
        }
        Ok(evicted)
    }

    /// Start a shell and stream its output to `sink`. Returns the terminal id.
    pub fn open(
        &self,
        req: &TerminalRequest<'_>,
        sink: Box<dyn TerminalSink>,
    ) -> Result<String, AppError> {
        stop_sessions(self.reserve_slot()?);
        let size = PtySize {
            rows: req.rows.clamp(2, 500),
            cols: req.cols.clamp(10, 1000),
            pixel_width: 0,
            pixel_height: 0,
        };
        let pair = native_pty_system()
            .openpty(size)
            .map_err(|_| AppError::unavailable("pty_unavailable"))?;

        let mut cmd = match &self.program {
            TerminalProgram::LoginShell => CommandBuilder::new_default_prog(),
            TerminalProgram::Program { path, args } => {
                let mut cmd = CommandBuilder::new(path);
                cmd.args(args);
                cmd
            }
        };
        cmd.env_clear();
        for (key, value) in build_env(std::env::vars_os(), req) {
            cmd.env(key, value);
        }
        if let Some(home) = crate::paths::home_dir().filter(|h| h.is_dir()) {
            cmd.cwd(home);
        }
        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|_| AppError::unavailable("shell_spawn_failed"))?;
        // Only the child may hold the slave side, so the reader sees EOF when the shell exits.
        drop(pair.slave);

        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|_| AppError::unavailable("pty_unavailable"))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|_| AppError::unavailable("pty_unavailable"))?;
        let killer = child.clone_killer();
        let pid = child.process_id();
        let tty = pair
            .master
            .tty_name()
            .map(|path| ps_tty_name(&path.to_string_lossy()));
        let exited = Arc::new(AtomicBool::new(false));
        let output = Arc::new(Mutex::new(Output {
            ring: OutputRing::new(self.ring_bytes),
            sink: Some(sink),
            exit: None,
        }));
        let input = Arc::new(InputQueue::new());
        let session = Session {
            master: pair.master,
            input: input.clone(),
            killer,
            pid,
            tty,
            exited: exited.clone(),
            output: output.clone(),
            principal: req.principal.to_owned(),
            as_user: req.as_user.map(str::to_owned),
            seq: self.next_seq.fetch_add(1, Ordering::SeqCst),
        };
        thread::spawn(move || pump(reader, child, output, exited));
        thread::spawn(move || feed(writer, input));
        let id = match random_ref() {
            Ok(id) => id,
            Err(e) => {
                stop_sessions(vec![session]);
                return Err(e);
            }
        };
        self.lock().insert(id.clone(), session);
        Ok(id)
    }

    /// Point a terminal's output at a new sink: the buffered output is replayed into it first
    /// (and its exit, if the shell is gone), then live output follows with nothing lost or
    /// repeated in between. The previous sink is dropped. Works for an exited terminal too.
    pub fn attach(
        &self,
        id: &str,
        mut sink: Box<dyn TerminalSink>,
    ) -> Result<AttachedTerminal, AppError> {
        let (output, mut attached) = {
            let sessions = self.lock();
            let session = sessions.get(id).ok_or_else(unknown)?;
            (
                session.output.clone(),
                AttachedTerminal {
                    principal: session.principal.clone(),
                    as_user: session.as_user.clone(),
                    alive: true,
                },
            )
        };
        let mut output = lock_output(&output);
        if !output.ring.is_empty() {
            sink.data(&output.ring.text());
        }
        if let Some(code) = output.exit {
            sink.exit(code);
            attached.alive = false;
        }
        output.sink = Some(sink);
        Ok(attached)
    }

    /// Every session in the registry, oldest first.
    pub fn list(&self) -> Vec<TerminalSummary> {
        let sessions = self.lock();
        let mut rows: Vec<(u64, TerminalSummary)> = sessions
            .iter()
            .map(|(id, s)| {
                (
                    s.seq,
                    TerminalSummary {
                        terminal_id: id.clone(),
                        principal: s.principal.clone(),
                        as_user: s.as_user.clone(),
                        alive: !s.exited.load(Ordering::SeqCst),
                    },
                )
            })
            .collect();
        rows.sort_by_key(|(seq, _)| *seq);
        rows.into_iter().map(|(_, row)| row).collect()
    }

    /// Keyboard input from xterm.js. It is queued for the terminal's writer thread and this
    /// returns at once: `terminal_busy` when the program has left more than
    /// [`MAX_QUEUED_INPUT`] unread, `terminal_write_failed` once the shell has exited.
    pub fn write(&self, id: &str, data: &str) -> Result<(), AppError> {
        if data.len() > MAX_WRITE_BYTES {
            return Err(AppError::invalid_input("terminal_write_too_large"));
        }
        let input = {
            let sessions = self.lock();
            let session = sessions.get(id).ok_or_else(unknown)?;
            if session.exited.load(Ordering::SeqCst) {
                return Err(write_failed());
            }
            session.input.clone()
        };
        input.push(data.as_bytes())
    }

    pub fn resize(&self, id: &str, cols: u16, rows: u16) -> Result<(), AppError> {
        let sessions = self.lock();
        let session = sessions.get(id).ok_or_else(unknown)?;
        session
            .master
            .resize(PtySize {
                rows: rows.clamp(2, 500),
                cols: cols.clamp(10, 1000),
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|_| AppError::unavailable("terminal_resize_failed"))
    }

    /// Forget the session and stop every process it started (SIGHUP, then SIGKILL after
    /// [`CLOSE_GRACE`]; see the module docs for what is out of reach). Returns when that is
    /// done. Closing an unknown or already closed id succeeds.
    pub fn close(&self, id: &str) {
        let session = self.lock().remove(id);
        stop_sessions(session.into_iter().collect());
    }

    /// [`Self::close`] for every terminal at once (app quit): one grace period for all.
    pub fn close_all(&self) {
        let sessions: Vec<Session> = self.lock().drain().map(|(_, s)| s).collect();
        stop_sessions(sessions);
    }

    /// Shells still running.
    pub fn open_count(&self) -> usize {
        self.lock()
            .values()
            .filter(|s| !s.exited.load(Ordering::SeqCst))
            .count()
    }
}

impl Drop for TerminalManager {
    fn drop(&mut self) {
        self.close_all();
    }
}

fn lock_output(output: &Mutex<Output>) -> MutexGuard<'_, Output> {
    output.lock().unwrap_or_else(|e| e.into_inner())
}

fn unknown() -> AppError {
    AppError::not_found("terminal_not_found")
}

fn write_failed() -> AppError {
    AppError::new("IoError", "terminal_write_failed")
}

/// One row of the process table: what [`stop_sessions`] needs to find a terminal's processes.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessRow {
    pid: i32,
    ppid: i32,
    pgid: i32,
    /// Controlling terminal as `ps` prints it; `?`/`??` for none.
    tty: String,
}

/// `ps -A -o pid= -o ppid= -o pgid= -o tty=` (the same on macOS and Linux). `None` when `ps`
/// cannot be run; the caller then falls back to the shell's own process groups.
fn process_table() -> Option<Vec<ProcessRow>> {
    let ps = ["/bin/ps", "/usr/bin/ps"]
        .into_iter()
        .find(|p| Path::new(p).is_file())?;
    let out = Command::new(ps)
        .args([
            "-A", "-o", "pid=", "-o", "ppid=", "-o", "pgid=", "-o", "tty=",
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    Some(parse_process_table(&String::from_utf8_lossy(&out.stdout)))
}

/// Parse `ps` rows of `pid ppid pgid tty`; malformed lines are skipped.
fn parse_process_table(text: &str) -> Vec<ProcessRow> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let mut number = || fields.next()?.parse::<i32>().ok();
            let (pid, ppid, pgid) = (number()?, number()?, number()?);
            let tty = fields.next()?.to_owned();
            Some(ProcessRow {
                pid,
                ppid,
                pgid,
                tty,
            })
        })
        .collect()
}

/// A PTY slave path as `ps` names it: `/dev/ttys012` → `ttys012`, `/dev/pts/3` → `pts/3`.
fn ps_tty_name(path: &str) -> String {
    path.strip_prefix("/dev/").unwrap_or(path).to_owned()
}

/// The process groups that belong to one terminal: the shell's own group and its
/// foreground group (while the shell runs), the groups of the shell's descendants, and the
/// groups of every process whose controlling terminal is `tty` (which also finds processes
/// whose parent has exited). Never group 0 or 1, nor `own` (the app's group).
fn terminal_groups(
    table: &[ProcessRow],
    shell: Option<i32>,
    foreground: Option<i32>,
    tty: Option<&str>,
    own: i32,
) -> BTreeSet<i32> {
    let mut groups: BTreeSet<i32> = shell.into_iter().chain(foreground).collect();
    if let Some(shell) = shell {
        let mut tree = BTreeSet::from([shell]);
        loop {
            let before = tree.len();
            for row in table {
                if tree.contains(&row.ppid) {
                    tree.insert(row.pid);
                }
            }
            if tree.len() == before {
                break;
            }
        }
        groups.extend(
            table
                .iter()
                .filter(|row| tree.contains(&row.pid))
                .map(|row| row.pgid),
        );
    }
    if let Some(tty) = tty {
        groups.extend(
            table
                .iter()
                .filter(|row| row.tty == tty)
                .map(|row| row.pgid),
        );
    }
    groups.retain(|&group| group > 1 && group != own);
    groups
}

fn signal_group(group: i32, signal: Option<Signal>) -> bool {
    killpg(Pid::from_raw(group), signal).is_ok()
}

/// Stop every process the given terminals started, then let the sessions (and their PTYs) go.
/// Blocks for at most [`CLOSE_GRACE`] plus two `ps` runs. The PTYs stay open until the end,
/// so their names cannot be reused by another terminal meanwhile.
fn stop_sessions(mut sessions: Vec<Session>) {
    if sessions.is_empty() {
        return;
    }
    let own = nix::unistd::getpgrp().as_raw();
    let table = process_table();
    let mut groups = BTreeSet::new();
    for session in &mut sessions {
        session.input.close(None);
        let running = !session.exited.load(Ordering::SeqCst);
        // A shell that has exited may have been reaped and its pid reused: only the terminal
        // itself identifies what is left of it then.
        let shell = session
            .pid
            .and_then(|pid| i32::try_from(pid).ok())
            .filter(|_| running);
        let foreground = session.master.process_group_leader().filter(|_| running);
        groups.extend(terminal_groups(
            table.as_deref().unwrap_or_default(),
            shell,
            foreground,
            session.tty.as_deref(),
            own,
        ));
        if running {
            let _ = session.killer.kill();
        }
    }
    for &group in &groups {
        signal_group(group, Some(Signal::SIGHUP));
        signal_group(group, Some(Signal::SIGCONT));
    }
    let deadline = Instant::now() + CLOSE_GRACE;
    while Instant::now() < deadline && groups.iter().any(|&g| signal_group(g, None)) {
        thread::sleep(CLOSE_POLL);
    }
    // Anything started on these terminals since the first look.
    if let Some(table) = process_table() {
        for session in &sessions {
            groups.extend(terminal_groups(
                &table,
                None,
                None,
                session.tty.as_deref(),
                own,
            ));
        }
    }
    for &group in &groups {
        signal_group(group, Some(Signal::SIGKILL));
    }
    drop(sessions);
}

fn pump(
    mut reader: Box<dyn Read + Send>,
    mut child: Box<dyn portable_pty::Child + Send + Sync>,
    output: Arc<Mutex<Output>>,
    exited: Arc<AtomicBool>,
) {
    let deliver = |text: &str| {
        let mut output = lock_output(&output);
        output.ring.push(text);
        if let Some(sink) = output.sink.as_mut() {
            sink.data(text);
        }
    };
    let mut decoder = Utf8Chunker::default();
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let text = decoder.push(&buf[..n]);
                if !text.is_empty() {
                    deliver(&text);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            // Linux reports EIO once the shell (the last slave holder) is gone.
            Err(_) => break,
        }
    }
    buf.zeroize();
    let rest = decoder.finish();
    if !rest.is_empty() {
        deliver(&rest);
    }
    let code = child.wait().ok().map(|s| s.exit_code());
    let mut output = lock_output(&output);
    output.exit = Some(code);
    exited.store(true, Ordering::SeqCst);
    if let Some(sink) = output.sink.as_mut() {
        sink.exit(code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req<'a>(token: &'a SecretString, bin: &'a Path) -> TerminalRequest<'a> {
        TerminalRequest {
            gateway_url: "http://127.0.0.1:47380",
            token,
            bin_dir: bin,
            cols: 80,
            rows: 24,
            principal: "agent-1",
            as_user: None,
        }
    }

    #[test]
    fn env_is_allowlisted_and_injected() {
        let token = SecretString::from("zpw_synthetic_token");
        let bin = Path::new("/Applications/ZeroPW.app/Contents/MacOS");
        let parent = vec![
            ("HOME".into(), "/Users/a".into()),
            ("PATH".into(), "/opt/homebrew/bin:/usr/bin".into()),
            ("ZEROPW_ADMIN_PASSPHRASE".into(), "synthetic-pass".into()),
            ("ZEROPW_CALLER_TOKEN".into(), "zpw_stale".into()),
            ("AWS_SECRET_ACCESS_KEY".into(), "synthetic".into()),
            ("LANG".into(), "ko_KR.UTF-8".into()),
        ];
        let env: HashMap<OsString, OsString> =
            build_env(parent, &req(&token, bin)).into_iter().collect();
        let get = |k: &str| {
            env.get(OsStr::new(k))
                .map(|v| v.to_string_lossy().into_owned())
        };
        assert_eq!(get("HOME").as_deref(), Some("/Users/a"));
        assert_eq!(get("LANG").as_deref(), Some("ko_KR.UTF-8"));
        assert_eq!(
            get("PATH").as_deref(),
            Some("/Applications/ZeroPW.app/Contents/MacOS:/opt/homebrew/bin:/usr/bin")
        );
        assert_eq!(
            get(CALLER_TOKEN_VAR).as_deref(),
            Some("zpw_synthetic_token")
        );
        assert_eq!(
            get(GATEWAY_URL_VAR).as_deref(),
            Some("http://127.0.0.1:47380")
        );
        assert_eq!(get("no_proxy").as_deref(), Some("127.0.0.1,localhost"));
        assert_eq!(get("ZEROPW_ADMIN_PASSPHRASE"), None);
        assert_eq!(get("AWS_SECRET_ACCESS_KEY"), None);
        // The stale token from the parent was replaced, not duplicated.
        let stale = build_env(
            vec![("ZEROPW_CALLER_TOKEN".into(), "zpw_stale".into())],
            &req(&token, bin),
        );
        assert_eq!(
            stale.iter().filter(|(k, _)| k == CALLER_TOKEN_VAR).count(),
            1
        );
        let no_path = build_env(Vec::new(), &req(&token, bin));
        assert!(no_path.iter().any(|(k, v)| k == "PATH"
            && v.to_string_lossy() == format!("{}:{DEFAULT_PATH}", bin.display())));
        // A UTF-8 locale is supplied when the app has none, and kept when it has one.
        assert!(
            no_path
                .iter()
                .any(|(k, v)| k == "LANG" && v.to_string_lossy().ends_with("UTF-8"))
        );
        let with_lang = build_env(
            vec![("LANG".into(), "ko_KR.UTF-8".into())],
            &req(&token, bin),
        );
        let langs: Vec<_> = with_lang.iter().filter(|(k, _)| k == "LANG").collect();
        assert_eq!(langs.len(), 1);
        assert_eq!(langs[0].1, "ko_KR.UTF-8");
    }

    #[test]
    fn suggestions_for_this_and_another_account() {
        let bin = Path::new("/Applications/ZeroPW.app/Contents/MacOS");
        assert_eq!(
            suggestions(bin, None).unwrap(),
            ["/Applications/ZeroPW.app/Contents/MacOS/zeropw-agent list-connections"]
        );
        assert_eq!(
            suggestions(bin, Some("agent")).unwrap(),
            [
                "sudo --preserve-env=ZEROPW_GATEWAY_URL,ZEROPW_CALLER_TOKEN,no_proxy -u agent -i",
                "/Applications/ZeroPW.app/Contents/MacOS/zeropw-agent list-connections",
            ]
        );
        for bad in ["", "-u", "a b", "a;rm", "$(id)", "1abc", "ä"] {
            assert_eq!(
                suggestions(bin, Some(bad)).unwrap_err().reason,
                "invalid_account"
            );
        }
        assert_eq!(
            suggestions(Path::new("/tmp/Zero PW"), None).unwrap(),
            ["'/tmp/Zero PW/zeropw-agent' list-connections"]
        );
    }

    #[test]
    fn shell_quoting() {
        assert_eq!(shell_quote("/a/b"), "/a/b");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn ring_keeps_the_newest_output_within_capacity() {
        let mut ring = OutputRing::new(16);
        ring.push("hello ");
        ring.push("world");
        assert_eq!(ring.text(), "hello world");
        // Overflow cuts the oldest output, and the rest of the cut line with it.
        ring.push("\nline two\n");
        assert_eq!(ring.text(), "line two\n");
        assert!(ring.len() <= 16);
        // A single chunk larger than the ring keeps only its tail.
        ring.push(&"x".repeat(40));
        assert_eq!(ring.text(), "x".repeat(16));
        let capacity = ring.buf.capacity();
        for _ in 0..100 {
            ring.push("0123456789");
        }
        assert!(ring.len() <= 16);
        assert_eq!(ring.buf.capacity(), capacity, "the ring never reallocates");
    }

    #[test]
    fn ring_cuts_only_at_character_boundaries() {
        // 12 bytes into 10: the first character is dropped whole.
        let mut ring = OutputRing::new(10);
        ring.push("가나다라");
        assert_eq!(ring.text(), "나다라");
        ring.push("마");
        assert_eq!(ring.text(), "다라마");
        let mut ring = OutputRing::new(8);
        ring.push("ab가나다");
        assert_eq!(ring.text(), "나다");
        let mut zero = OutputRing::new(0);
        zero.push("x");
        assert!(zero.is_empty());
    }

    #[test]
    fn utf8_chunks_are_reassembled() {
        let mut d = Utf8Chunker::default();
        let text = "가나다 abc";
        let bytes = text.as_bytes();
        let mut out = String::new();
        for b in bytes {
            out.push_str(&d.push(std::slice::from_ref(b)));
        }
        out.push_str(&d.finish());
        assert_eq!(out, text);
        assert_eq!(d.push(b"a\xffb"), "a\u{FFFD}b");
        assert_eq!(d.push(b"\xea\xb0"), "");
        assert_eq!(d.finish(), "\u{FFFD}");
    }

    #[test]
    fn input_queue_is_bounded_and_wiped_on_close() {
        let queue = InputQueue::new();
        queue.push(b"ls\r").unwrap();
        queue.push(b"").unwrap();
        assert_eq!(queue.next().unwrap().as_slice(), b"ls\r");
        let big = vec![b'x'; MAX_QUEUED_INPUT];
        queue.push(&big).unwrap();
        assert_eq!(queue.push(b"y").unwrap_err().reason, "terminal_busy");
        // The chunk being written no longer counts against the bound.
        assert_eq!(queue.next().unwrap().len(), MAX_QUEUED_INPUT);
        queue.push(b"y").unwrap();
        queue.close(None);
        assert_eq!(queue.lock().bytes, 0);
        assert!(queue.lock().chunks.is_empty());
        assert!(queue.next().is_none());
        assert_eq!(queue.push(b"z").unwrap_err().reason, "terminal_not_found");

        let failed = InputQueue::new();
        failed.close(Some(std::io::ErrorKind::BrokenPipe));
        let e = failed.push(b"z").unwrap_err();
        assert_eq!(e.reason, "terminal_write_failed");
        assert_eq!(e.detail.as_deref(), Some("BrokenPipe"));
    }

    #[test]
    fn process_table_rows_and_tty_names() {
        let rows = parse_process_table(
            "    1     0     1 ?\n  200     1   200 pts/3\n  201   200   201 ttys012 \nbad line\n 7 x 7 ?\n",
        );
        assert_eq!(
            rows,
            [
                ProcessRow {
                    pid: 1,
                    ppid: 0,
                    pgid: 1,
                    tty: "?".into()
                },
                ProcessRow {
                    pid: 200,
                    ppid: 1,
                    pgid: 200,
                    tty: "pts/3".into()
                },
                ProcessRow {
                    pid: 201,
                    ppid: 200,
                    pgid: 201,
                    tty: "ttys012".into()
                },
            ]
        );
        assert_eq!(ps_tty_name("/dev/ttys012"), "ttys012");
        assert_eq!(ps_tty_name("/dev/pts/3"), "pts/3");
    }

    #[test]
    fn terminal_groups_cover_the_tree_and_the_terminal() {
        let row = |pid, ppid, pgid, tty: &str| ProcessRow {
            pid,
            ppid,
            pgid,
            tty: tty.into(),
        };
        let table = [
            row(1, 0, 1, "?"),
            row(50, 1, 50, "?"),         // the app
            row(100, 50, 100, "pts/3"),  // the shell (session leader)
            row(110, 100, 110, "pts/3"), // a background job
            row(111, 110, 110, "pts/3"),
            row(120, 100, 120, "?"), // a descendant that detached from the terminal
            row(121, 120, 121, "?"), // ... and started its own group
            row(130, 1, 125, "pts/3"), // an orphan still on the terminal
            row(140, 1, 140, "pts/4"), // another terminal
            row(150, 1, 150, "?"),   // unrelated
            row(160, 100, 50, "pts/3"), // never the app's own group
        ];
        let all = terminal_groups(&table, Some(100), Some(110), Some("pts/3"), 50);
        assert_eq!(all, BTreeSet::from([100, 110, 120, 121, 125]));
        // An exited shell: only what is still on its terminal.
        let exited = terminal_groups(&table, None, None, Some("pts/3"), 50);
        assert_eq!(exited, BTreeSet::from([100, 110, 125]));
        // No process table: the shell's own groups only.
        assert_eq!(
            terminal_groups(&[], Some(100), Some(1), None, 50),
            BTreeSet::from([100])
        );
    }
}
