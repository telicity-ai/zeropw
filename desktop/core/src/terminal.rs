//! The in-app terminal (docs/desktop-app.md §4.4).
//!
//! - The user's login shell runs on a PTY. `ZEROPW_GATEWAY_URL`, `ZEROPW_CALLER_TOKEN` and
//!   `no_proxy=127.0.0.1,localhost` are placed in its environment and `PATH` starts with the
//!   bundled binaries' folder. The token is never typed into the PTY, so it is in neither the
//!   screen nor the shell history, and it goes away with the shell.
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

use std::collections::{HashMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use portable_pty::{ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system};
use serde::Serialize;
use zeroize::Zeroize;

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
/// How long a closed shell gets to exit on SIGHUP before its process group is killed.
const CLOSE_GRACE: Duration = Duration::from_secs(2);

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

struct Session {
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    killer: Box<dyn ChildKiller + Send + Sync>,
    pid: Option<u32>,
    exited: Arc<AtomicBool>,
    output: Arc<Mutex<Output>>,
    principal: String,
    as_user: Option<String>,
    /// Open order, for listing and for evicting the oldest exited session.
    seq: u64,
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

    /// Make room for one more session: exited sessions go first, oldest first.
    fn reserve_slot(&self) -> Result<(), AppError> {
        let mut sessions = self.lock();
        while sessions.len() >= MAX_TERMINALS {
            let oldest_exited = sessions
                .iter()
                .filter(|(_, s)| s.exited.load(Ordering::SeqCst))
                .min_by_key(|(_, s)| s.seq)
                .map(|(id, _)| id.clone());
            match oldest_exited {
                Some(id) => {
                    sessions.remove(&id);
                }
                None => return Err(AppError::unavailable("too_many_terminals")),
            }
        }
        Ok(())
    }

    /// Start a shell and stream its output to `sink`. Returns the terminal id.
    pub fn open(
        &self,
        req: &TerminalRequest<'_>,
        sink: Box<dyn TerminalSink>,
    ) -> Result<String, AppError> {
        self.reserve_slot()?;
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
        let exited = Arc::new(AtomicBool::new(false));
        let output = Arc::new(Mutex::new(Output {
            ring: OutputRing::new(self.ring_bytes),
            sink: Some(sink),
            exit: None,
        }));
        let id = random_ref()?;

        let exited_flag = exited.clone();
        let pump_output = output.clone();
        thread::spawn(move || pump(reader, child, pump_output, exited_flag));

        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        self.lock().insert(
            id.clone(),
            Session {
                master: pair.master,
                writer,
                killer,
                pid,
                exited,
                output,
                principal: req.principal.to_owned(),
                as_user: req.as_user.map(str::to_owned),
                seq,
            },
        );
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

    /// Keyboard input from xterm.js.
    pub fn write(&self, id: &str, data: &str) -> Result<(), AppError> {
        if data.len() > MAX_WRITE_BYTES {
            return Err(AppError::invalid_input("terminal_write_too_large"));
        }
        let mut sessions = self.lock();
        let session = sessions.get_mut(id).ok_or_else(unknown)?;
        session
            .writer
            .write_all(data.as_bytes())
            .and_then(|_| session.writer.flush())
            .map_err(|e| AppError::io("terminal_write_failed", &e))
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

    /// Hang up the shell (SIGHUP, then SIGKILL to its process group after a short grace) and
    /// forget the session. Closing an unknown or already closed id succeeds.
    pub fn close(&self, id: &str) {
        let session = self.lock().remove(id);
        if let Some(session) = session {
            hang_up(session);
        }
    }

    pub fn close_all(&self) {
        let sessions: Vec<Session> = self.lock().drain().map(|(_, s)| s).collect();
        for session in sessions {
            hang_up(session);
        }
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

fn hang_up(mut session: Session) {
    if session.exited.load(Ordering::SeqCst) {
        return;
    }
    let _ = session.killer.kill();
    let Session {
        master,
        writer,
        pid,
        exited,
        ..
    } = session;
    drop(writer);
    drop(master);
    if let Some(pid) = pid {
        thread::spawn(move || {
            thread::sleep(CLOSE_GRACE);
            if !exited.load(Ordering::SeqCst) {
                // The shell is a session leader (setsid), so its pid is its process group.
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        });
    }
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
}
