//! [`AdminRunner`] (docs/desktop-app.md §4.1): every management call is one
//! `zeropw-admin --state-dir=<dir> --input-envelope <args…>` child process.
//!
//! - argv comes only from [`AdminArgs`]: fixed command words, `--flag=value` options (a value
//!   can never be taken for an option) and pre-validated positionals. Secrets never go in argv.
//! - Secrets travel in the stdin input envelope ([`Envelope`], §3.1), written once and closed.
//! - Commands the app re-authenticates but the CLI would run without a passphrase carry the
//!   hidden global `--require-admin` right after `--input-envelope` ([`AdminArgs::require_admin`]),
//!   so zeropw-admin checks the envelope's admin passphrase before running them.
//! - The environment is cleared; the child gets only `PATH=/usr/bin:/bin`, `HOME`,
//!   `LANG=C.UTF-8` and `TMPDIR`, so no `ZEROPW_*` passphrase variable can leak in.
//! - On success stdout is JSON; on failure the `{error, reason, detail}` line on stderr becomes
//!   an [`AppError`] (detail dropped if it contains an envelope secret). Other output is
//!   discarded. A call that outlives its timeout is killed with its process group.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::AppError;
use crate::paths::{self, ADMIN_BIN};
use crate::secret::SecretString;

/// Default per-call limit (§4.1).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
/// `team join` dials the inviter and may wait for the handshake (§4.1).
pub const JOIN_TIMEOUT: Duration = Duration::from_secs(90);
/// The CLI reads at most this much envelope (§3.1).
pub const MAX_ENVELOPE_BYTES: usize = 256 * 1024;
/// `vault.MAX_SECRET_BYTES` in the product crate.
pub const MAX_SECRET_BYTES: usize = 64 * 1024;

const MAX_STDOUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 256 * 1024;
const MAX_ARG_CHARS: usize = 4096;
const POLL: Duration = Duration::from_millis(10);

/// The fixed environment of every zeropw-admin child (§4.1).
pub(crate) fn child_env() -> Vec<(&'static str, OsString)> {
    let mut env = vec![
        ("PATH", OsString::from("/usr/bin:/bin")),
        ("LANG", OsString::from("C.UTF-8")),
        ("TMPDIR", paths::temp_dir()),
    ];
    if let Some(home) = paths::home_dir() {
        env.push(("HOME", home.into_os_string()));
    }
    env
}

pub(crate) fn apply_child_env(cmd: &mut Command) {
    cmd.env_clear();
    for (key, value) in child_env() {
        cmd.env(key, value);
    }
}

/// `spawn`, retrying `ETXTBSY`: on Linux an exec can briefly fail while another thread's
/// fork still holds a write descriptor to a freshly written executable.
pub(crate) fn spawn(cmd: &mut Command) -> std::io::Result<Child> {
    let mut attempt = 0;
    loop {
        match cmd.spawn() {
            Err(e)
                if e.raw_os_error() == Some(nix::errno::Errno::ETXTBSY as i32) && attempt < 20 =>
            {
                attempt += 1;
                thread::sleep(Duration::from_millis(25));
            }
            other => return other,
        }
    }
}

/// The stdin input envelope (§3.1): only these four string fields exist.
#[derive(Default)]
pub struct Envelope {
    admin_passphrase: Option<SecretString>,
    recovery_passphrase: Option<SecretString>,
    value_b64: Option<SecretString>,
    invite: Option<SecretString>,
    /// The raw value behind `value_b64`, kept only to redact it from error details.
    value_text: Option<SecretString>,
}

#[derive(Serialize)]
struct EnvelopeWire<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    admin_passphrase: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_passphrase: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value_b64: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    invite: Option<&'a str>,
}

impl Envelope {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn admin_passphrase(mut self, passphrase: &SecretString) -> Self {
        self.admin_passphrase = Some(passphrase.duplicate());
        self
    }

    pub fn recovery_passphrase(mut self, passphrase: &SecretString) -> Self {
        self.recovery_passphrase = Some(passphrase.duplicate());
        self
    }

    /// The secret value for `secret put --stdin` / `rotation start --stdin`, as standard base64.
    pub fn value(mut self, bytes: &[u8]) -> Result<Self, AppError> {
        if bytes.is_empty() {
            return Err(AppError::invalid_input("empty_secret_value"));
        }
        if bytes.len() > MAX_SECRET_BYTES {
            return Err(AppError::invalid_input("secret_too_large"));
        }
        let mut encoded = Zeroizing::new(String::with_capacity(bytes.len().div_ceil(3) * 4));
        base64::engine::general_purpose::STANDARD.encode_string(bytes, &mut encoded);
        self.value_b64 = Some(SecretString::new(std::mem::take(&mut *encoded)));
        self.value_text = std::str::from_utf8(bytes).ok().map(SecretString::from);
        Ok(self)
    }

    /// An invite string or `zeropw://join#…` link for `team join/invite-info --stdin`.
    pub fn invite(mut self, invite: &SecretString) -> Self {
        self.invite = Some(invite.duplicate());
        self
    }

    /// The envelope JSON, in a buffer that is wiped after it has been written to the child.
    pub(crate) fn to_json(&self) -> Result<Zeroizing<Vec<u8>>, AppError> {
        let wire = EnvelopeWire {
            admin_passphrase: self.admin_passphrase.as_ref().map(SecretString::expose),
            recovery_passphrase: self.recovery_passphrase.as_ref().map(SecretString::expose),
            value_b64: self.value_b64.as_ref().map(SecretString::expose),
            invite: self.invite.as_ref().map(SecretString::expose),
        };
        let estimate = 128
            + [
                &self.admin_passphrase,
                &self.recovery_passphrase,
                &self.value_b64,
                &self.invite,
            ]
            .iter()
            .map(|field| field.as_ref().map_or(0, |s| s.len() * 2))
            .sum::<usize>();
        let mut buffer = Zeroizing::new(Vec::with_capacity(estimate));
        serde_json::to_writer(&mut *buffer, &wire)
            .map_err(|_| AppError::internal("envelope_encode_failed"))?;
        if buffer.len() > MAX_ENVELOPE_BYTES {
            return Err(AppError::invalid_input("envelope_too_large"));
        }
        Ok(buffer)
    }

    /// Every secret string in this envelope, for redacting CLI error details.
    pub(crate) fn redactions(&self) -> Vec<&str> {
        [
            &self.admin_passphrase,
            &self.recovery_passphrase,
            &self.value_b64,
            &self.invite,
            &self.value_text,
        ]
        .into_iter()
        .filter_map(|field| field.as_ref().map(SecretString::expose))
        .filter(|s| !s.is_empty())
        .collect()
    }
}

/// A typed zeropw-admin argument list. Command words are `&'static str` from the core's own
/// code; option values are rendered as one `--flag=value` token; positionals must pass a
/// format check that, among other things, rejects a leading `-`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminArgs {
    argv: Vec<String>,
    timeout: Option<Duration>,
    require_admin: bool,
}

impl AdminArgs {
    pub fn command(words: &[&'static str]) -> Self {
        Self {
            argv: words.iter().map(|w| (*w).to_owned()).collect(),
            timeout: None,
            require_admin: false,
        }
    }

    /// Ask zeropw-admin to verify the envelope's admin passphrase before running a command
    /// it would otherwise run without one (the hidden global `--require-admin`, placed right
    /// after `--input-envelope`).
    pub fn require_admin(mut self) -> Self {
        self.require_admin = true;
        self
    }

    pub fn requires_admin(&self) -> bool {
        self.require_admin
    }

    /// `--name=value`. The value is checked (no control characters, bounded length); an
    /// error names the flag, never the value.
    pub fn opt(mut self, name: &'static str, value: &str) -> Result<Self, AppError> {
        check_arg_value(name, value)?;
        self.argv.push(format!("--{name}={value}"));
        Ok(self)
    }

    pub fn opt_if(self, name: &'static str, value: Option<&str>) -> Result<Self, AppError> {
        match value {
            Some(value) => self.opt(name, value),
            None => Ok(self),
        }
    }

    /// A non-empty optional value; empty strings are treated as absent.
    pub fn opt_nonempty(self, name: &'static str, value: Option<&str>) -> Result<Self, AppError> {
        self.opt_if(name, value.filter(|v| !v.is_empty()))
    }

    /// A boolean flag (`--stdin`, `--quiet`, `--link`).
    pub fn flag(mut self, name: &'static str) -> Self {
        self.argv.push(format!("--{name}"));
        self
    }

    pub fn flag_if(self, name: &'static str, on: bool) -> Self {
        if on { self.flag(name) } else { self }
    }

    /// A positional argument that `valid` accepts. `valid` must reject a leading `-`.
    pub fn positional(
        mut self,
        what: &'static str,
        value: &str,
        valid: fn(&str) -> bool,
    ) -> Result<Self, AppError> {
        if value.starts_with('-') || !valid(value) {
            return Err(AppError::invalid_input("invalid_argument").with_detail(what));
        }
        self.argv.push(value.to_owned());
        Ok(self)
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn argv(&self) -> &[String] {
        &self.argv
    }
}

fn check_arg_value(name: &str, value: &str) -> Result<(), AppError> {
    if value.chars().count() > MAX_ARG_CHARS || value.chars().any(char::is_control) {
        return Err(AppError::invalid_input("invalid_argument").with_detail(format!("--{name}")));
    }
    Ok(())
}

/// Runs zeropw-admin for one call at a time per thread; holds no state between calls.
#[derive(Clone, Debug)]
pub struct AdminRunner {
    admin_bin: PathBuf,
    state_dir: PathBuf,
    default_timeout: Duration,
}

impl AdminRunner {
    pub fn new(bin_dir: &Path, state_dir: &Path) -> Self {
        Self {
            admin_bin: bin_dir.join(ADMIN_BIN),
            state_dir: state_dir.to_path_buf(),
            default_timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn with_default_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    pub fn admin_bin(&self) -> &Path {
        &self.admin_bin
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Run and parse stdout as JSON.
    pub fn run(&self, args: &AdminArgs, envelope: &Envelope) -> Result<Value, AppError> {
        self.run_parsed(args, envelope)
    }

    /// Run and deserialize stdout into `T` straight from the wiped stdout buffer. Use a type
    /// with [`SecretString`] fields for outputs that carry a secret (token, invite, value).
    pub fn run_parsed<T: DeserializeOwned>(
        &self,
        args: &AdminArgs,
        envelope: &Envelope,
    ) -> Result<T, AppError> {
        let stdout = self.run_raw(args, envelope)?;
        serde_json::from_slice(&stdout).map_err(|_| AppError::internal("admin_output_invalid"))
    }

    /// Run and return stdout bytes (wiped on drop). Non-zero exit becomes an [`AppError`].
    pub fn run_raw(
        &self,
        args: &AdminArgs,
        envelope: &Envelope,
    ) -> Result<Zeroizing<Vec<u8>>, AppError> {
        let payload = envelope.to_json()?;
        let timeout = args.timeout.unwrap_or(self.default_timeout);
        let mut state_dir_arg = OsString::from("--state-dir=");
        state_dir_arg.push(self.state_dir.as_os_str());

        let mut cmd = Command::new(&self.admin_bin);
        cmd.arg(state_dir_arg).arg("--input-envelope");
        if args.require_admin {
            cmd.arg("--require-admin");
        }
        cmd.args(args.argv())
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        apply_child_env(&mut cmd);
        let mut child = spawn(&mut cmd).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => AppError::unavailable("admin_binary_missing"),
            std::io::ErrorKind::PermissionDenied => {
                AppError::unavailable("admin_binary_not_executable")
            }
            _ => AppError::io("admin_spawn_failed", &e),
        })?;

        let (tx, rx) = mpsc::channel::<Stream>();
        if let Some(mut stdin) = child.stdin.take() {
            thread::spawn(move || {
                // A child that exits before reading (a usage error) closes the pipe; ignore it.
                let _ = stdin.write_all(&payload);
                drop(stdin);
                drop(payload);
            });
        }
        if let Some(stdout) = child.stdout.take() {
            spawn_reader(stdout, MAX_STDOUT_BYTES, Which::Out, tx.clone());
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_reader(stderr, MAX_STDERR_BYTES, Which::Err, tx.clone());
        }
        drop(tx);

        let deadline = Instant::now() + timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() >= deadline => {
                    kill_group(&mut child);
                    return Err(AppError::timeout("admin_timeout")
                        .with_detail(format!("{}s", timeout.as_secs())));
                }
                Ok(None) => thread::sleep(POLL),
                Err(e) => {
                    kill_group(&mut child);
                    return Err(AppError::io("admin_wait_failed", &e));
                }
            }
        };

        let mut stdout = None;
        let mut stderr = None;
        while stdout.is_none() || stderr.is_none() {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left.max(Duration::from_millis(200))) {
                Ok(stream) => match stream.which {
                    Which::Out => stdout = Some(stream),
                    Which::Err => stderr = Some(stream),
                },
                // A grandchild still holding a pipe open: give up on that stream.
                Err(_) => {
                    let _ = nix::sys::signal::killpg(
                        nix::unistd::Pid::from_raw(child.id() as i32),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                    break;
                }
            }
        }

        if status.success() {
            let stdout = stdout.ok_or_else(|| AppError::internal("admin_output_missing"))?;
            if stdout.truncated {
                return Err(AppError::internal("admin_output_too_large"));
            }
            return Ok(stdout.bytes);
        }
        let stderr_bytes = stderr.map(|s| s.bytes).unwrap_or_default();
        if let Some(error) = AppError::from_admin_stderr(&stderr_bytes, &envelope.redactions()) {
            return Err(error);
        }
        Err(match (status.code(), status.signal()) {
            (Some(code), _) => {
                AppError::internal("admin_failed").with_detail(format!("exit status {code}"))
            }
            (None, Some(signal)) => {
                AppError::internal("admin_crashed").with_detail(format!("signal {signal}"))
            }
            (None, None) => AppError::internal("admin_failed"),
        })
    }
}

#[derive(Clone, Copy)]
enum Which {
    Out,
    Err,
}

struct Stream {
    which: Which,
    bytes: Zeroizing<Vec<u8>>,
    truncated: bool,
}

fn spawn_reader<R: Read + Send + 'static>(
    mut reader: R,
    cap: usize,
    which: Which,
    tx: mpsc::Sender<Stream>,
) {
    thread::spawn(move || {
        let mut bytes = Zeroizing::new(Vec::with_capacity(8192));
        let mut truncated = false;
        let mut chunk = Zeroizing::new([0u8; 8192]);
        loop {
            match reader.read(&mut chunk[..]) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let room = cap.saturating_sub(bytes.len());
                    if n > room {
                        truncated = true;
                    }
                    let take = n.min(room);
                    if bytes.capacity() - bytes.len() < take {
                        // Grow into a fresh wiped buffer instead of letting Vec reallocate,
                        // which would leave an unwiped copy of earlier output behind.
                        let mut grown =
                            Zeroizing::new(Vec::with_capacity((bytes.len() + take) * 2));
                        grown.extend_from_slice(&bytes);
                        bytes = grown;
                    }
                    bytes.extend_from_slice(&chunk[..take]);
                }
            }
        }
        let _ = tx.send(Stream {
            which,
            bytes,
            truncated,
        });
    });
}

fn kill_group(child: &mut Child) {
    let _ = nix::sys::signal::killpg(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGKILL,
    );
    let _ = child.kill();
    let _ = child.wait();
}

/// `projects.NAME_RE` (`^[a-z0-9][a-z0-9._-]{0,63}$`) for project and environment names.
pub fn is_project_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_are_single_flag_equals_value_tokens() {
        let args = AdminArgs::command(&["secret", "put"])
            .opt("id", "-rf")
            .unwrap()
            .opt("kind", "api_key")
            .unwrap()
            .flag("stdin");
        assert_eq!(
            args.argv(),
            ["secret", "put", "--id=-rf", "--kind=api_key", "--stdin"]
        );
    }

    #[test]
    fn require_admin_is_off_unless_asked_and_not_part_of_the_command() {
        let plain = AdminArgs::command(&["resume"]);
        assert!(!plain.requires_admin());
        let strict = AdminArgs::command(&["resume"]).require_admin();
        assert!(strict.requires_admin());
        assert_eq!(strict.argv(), ["resume"]);
    }

    #[test]
    fn values_with_control_characters_are_rejected_without_echo() {
        let err = AdminArgs::command(&["project", "list"])
            .opt("description", "a\nb-synthetic")
            .unwrap_err();
        assert_eq!(err.reason, "invalid_argument");
        assert_eq!(err.detail.as_deref(), Some("--description"));
        assert!(!err.to_string().contains("synthetic"));
        assert!(
            AdminArgs::command(&["x"])
                .opt("a", &"y".repeat(MAX_ARG_CHARS + 1))
                .is_err()
        );
    }

    #[test]
    fn positionals_are_format_checked() {
        let ok = AdminArgs::command(&["project", "create"])
            .positional("name", "demo-1", is_project_name)
            .unwrap();
        assert_eq!(ok.argv(), ["project", "create", "demo-1"]);
        for bad in ["-h", "--help", "", "Demo", "a b", ".x", &"a".repeat(65)] {
            let err = AdminArgs::command(&["project", "create"])
                .positional("name", bad, is_project_name)
                .unwrap_err();
            assert_eq!(err.detail.as_deref(), Some("name"));
        }
    }

    #[test]
    fn envelope_has_only_present_fields() {
        let env = Envelope::new()
            .admin_passphrase(&"synthetic-admin-1".into())
            .value(b"synthetic\x00value")
            .unwrap();
        let json: Value = serde_json::from_slice(&env.to_json().unwrap()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "admin_passphrase": "synthetic-admin-1",
                "value_b64": "c3ludGhldGljAHZhbHVl",
            })
        );
        assert_eq!(Envelope::new().to_json().unwrap().as_slice(), b"{}");
        let redactions = env.redactions();
        assert!(redactions.contains(&"synthetic-admin-1"));
        assert!(redactions.contains(&"c3ludGhldGljAHZhbHVl"));
        assert!(redactions.contains(&"synthetic\x00value"));
    }

    #[test]
    fn envelope_value_bounds() {
        assert_eq!(
            Envelope::new().value(b"").err().unwrap().reason,
            "empty_secret_value"
        );
        assert_eq!(
            Envelope::new()
                .value(&vec![b'a'; MAX_SECRET_BYTES + 1])
                .err()
                .unwrap()
                .reason,
            "secret_too_large"
        );
        let max = Envelope::new()
            .value(&vec![b'a'; MAX_SECRET_BYTES])
            .unwrap();
        assert!(max.to_json().unwrap().len() < MAX_ENVELOPE_BYTES);
    }

    #[test]
    fn child_env_is_the_fixed_allowlist() {
        let env = child_env();
        let keys: Vec<&str> = env.iter().map(|(k, _)| *k).collect();
        assert!(
            keys.iter()
                .all(|k| ["PATH", "HOME", "LANG", "TMPDIR"].contains(k))
        );
        assert!(env.contains(&("PATH", OsString::from("/usr/bin:/bin"))));
        assert!(env.contains(&("LANG", OsString::from("C.UTF-8"))));
    }

    #[test]
    fn missing_binary_is_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let runner = AdminRunner::new(tmp.path(), &tmp.path().join("state"));
        let err = runner
            .run(&AdminArgs::command(&["status"]), &Envelope::new())
            .unwrap_err();
        assert_eq!(err.reason, "admin_binary_missing");
    }
}
