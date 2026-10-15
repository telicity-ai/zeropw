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

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use portable_pty::{ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system};

use crate::error::AppError;
use crate::onetime::random_ref;
use crate::paths::AGENT_BIN;
use crate::secret::SecretString;

pub const GATEWAY_URL_VAR: &str = "ZEROPW_GATEWAY_URL";
pub const CALLER_TOKEN_VAR: &str = "ZEROPW_CALLER_TOKEN";
pub const NO_PROXY_VALUE: &str = "127.0.0.1,localhost";
const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";
const MAX_TERMINALS: usize = 8;
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

struct Session {
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    killer: Box<dyn ChildKiller + Send + Sync>,
    pid: Option<u32>,
    exited: Arc<AtomicBool>,
}

/// Open terminals by id.
pub struct TerminalManager {
    program: TerminalProgram,
    sessions: Mutex<HashMap<String, Session>>,
}

impl TerminalManager {
    pub fn new(program: TerminalProgram) -> Self {
        Self {
            program,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Session>> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Start a shell and stream its output to `sink`. Returns the terminal id.
    pub fn open(
        &self,
        req: &TerminalRequest<'_>,
        sink: Box<dyn TerminalSink>,
    ) -> Result<String, AppError> {
        {
            let mut sessions = self.lock();
            sessions.retain(|_, s| !s.exited.load(Ordering::SeqCst));
            if sessions.len() >= MAX_TERMINALS {
                return Err(AppError::unavailable("too_many_terminals"));
            }
        }
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
        let id = random_ref()?;

        let exited_flag = exited.clone();
        thread::spawn(move || pump(reader, child, sink, exited_flag));

        self.lock().insert(
            id.clone(),
            Session {
                master: pair.master,
                writer,
                killer,
                pid,
                exited,
            },
        );
        Ok(id)
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

    /// Hang up the shell (SIGHUP, then SIGKILL to its process group after a short grace).
    /// Closing an unknown or already closed id succeeds.
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

    pub fn open_count(&self) -> usize {
        let mut sessions = self.lock();
        sessions.retain(|_, s| !s.exited.load(Ordering::SeqCst));
        sessions.len()
    }
}

impl Drop for TerminalManager {
    fn drop(&mut self) {
        self.close_all();
    }
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
    mut sink: Box<dyn TerminalSink>,
    exited: Arc<AtomicBool>,
) {
    let mut decoder = Utf8Chunker::default();
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let text = decoder.push(&buf[..n]);
                if !text.is_empty() {
                    sink.data(&text);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            // Linux reports EIO once the shell (the last slave holder) is gone.
            Err(_) => break,
        }
    }
    let rest = decoder.finish();
    if !rest.is_empty() {
        sink.data(&rest);
    }
    let code = child.wait().ok().map(|s| s.exit_code());
    exited.store(true, Ordering::SeqCst);
    sink.exit(code);
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
