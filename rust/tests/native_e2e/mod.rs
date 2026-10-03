//! Shared support for the native multi-process end-to-end tests (formerly
//! driven by the Python test suite through `rust/tests/native_cli_e2e.py`).
//!
//! Every product component runs as its own OS process from the native
//! binaries: the administrator (`zeropw-admin`), the trusted server
//! (`zeropw-admin ... serve`) and the agent client (`zeropw-agent`). The
//! controlled external endpoints are in-process test fixtures: the fake API
//! (`zeropw::fake_upstream::FakeUpstream`), a loopback SMTP receiver
//! ([`FakeSmtp`]) and a real `sshd` ([`Sshd`]). Only synthetic credentials
//! are used.
//!
//! Contents:
//! * [`Admin`] / [`AdminCall`]: run the administrator CLI with JSON helpers
//!   (`ok`, `fail`) and the "only `secret reveal` ever prints a value" sweep
//!   that `tests/test_admin_cli.py`'s tearDown performed.
//! * [`Processes`]: the `_CliProcessTestCase` harness of
//!   `tests/test_cli_e2e.py` (admin/agent/serve processes, a transcript of
//!   every captured output, run polling and the final leak sweep).
//! * [`find_secret`], [`find_secret_in_tree`], [`ssh_key_material`]: port of
//!   `tests/leakcheck.py`.
//! * [`FakeSmtp`] and [`parse_message`]: port of `tests/fake_smtp.py` and
//!   `tests.test_notify.parse_message`.
//! * [`Sshd`], [`write_ssh_inspector`] and
//!   [`assert_exec_children_held_no_key`]: real-`sshd` helpers of
//!   `tests/test_ssh_e2e.py`.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::{Value, json};

pub const ADMIN_BIN: &str = env!("CARGO_BIN_EXE_zeropw-admin");
pub const AGENT_BIN: &str = env!("CARGO_BIN_EXE_zeropw-agent");
pub const DEMOCLI_BIN: &str = env!("CARGO_BIN_EXE_zeropw-democli");

/// The passphrases `tests/test_admin_cli.py` used.
pub const ADMIN_PASSPHRASE: &str = "admin-passphrase-1";
pub const RECOVERY_PASSPHRASE: &str = "recovery-passphrase-1";
/// The SMTP password of `tests/test_notify.py`.
pub const SMTP_PASSWORD: &str = "smtp-secret-password-0123456789";

pub fn path_env() -> String {
    std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into())
}

/// Poll `predicate` every 200 ms until it returns `Some`, or `None` after
/// `timeout` (like the Python harness's `until`).
pub fn until<T>(timeout: Duration, mut predicate: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = predicate() {
            return Some(value);
        }
        if Instant::now() > deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(200));
    }
}

/// Parse the JSON the CLIs print: stdout on success, else the last
/// non-blank line of stderr; `{}` when there is nothing.
pub fn cli_json(code: i32, out: &str, err: &str) -> Value {
    let text = if code == 0 {
        out.to_owned()
    } else {
        err.lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("")
            .to_owned()
    };
    if text.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("not JSON ({e}): {text:?}"))
    }
}

// ------------------------------------------------------------------ admin

/// One recorded administrator invocation.
#[derive(Clone, Debug)]
pub struct Recorded {
    pub argv: Vec<String>,
    pub stdout: String,
    pub stderr: String,
}

/// The administrator CLI for one state directory, recording every output.
///
/// Dropping an `Admin` (when the test has not already failed) performs the
/// sweep of `tests/test_admin_cli.py`'s tearDown: no output of any command
/// may contain a synthetic value (`synthetic-...`, the private key line or
/// the PEM marker), except stdout of `secret reveal`.
pub struct Admin {
    pub state: PathBuf,
    pub root: PathBuf,
    env: Vec<(String, String)>,
    pub outputs: Mutex<Vec<Recorded>>,
    /// Extra needles for the sweep (e.g. a private-key line).
    pub needles: Mutex<Vec<String>>,
    pub sweep: AtomicBool,
}

impl Admin {
    /// `root/state` with the default passphrases in the environment.
    pub fn new(root: &Path) -> Self {
        Admin {
            state: root.join("state"),
            root: root.to_path_buf(),
            env: vec![
                ("PATH".into(), path_env()),
                ("HOME".into(), root.to_string_lossy().into_owned()),
                ("ZEROPW_ADMIN_PASSPHRASE".into(), ADMIN_PASSPHRASE.into()),
                (
                    "ZEROPW_RECOVERY_PASSPHRASE".into(),
                    RECOVERY_PASSPHRASE.into(),
                ),
            ],
            outputs: Mutex::new(Vec::new()),
            needles: Mutex::new(Vec::new()),
            sweep: AtomicBool::new(true),
        }
    }

    /// Replace (or with `None` remove) a default environment variable for
    /// every later call.
    pub fn set_env(&mut self, name: &str, value: Option<&str>) {
        self.env.retain(|(k, _)| k != name);
        if let Some(value) = value {
            self.env.push((name.into(), value.into()));
        }
    }

    pub fn cmd<'a>(&'a self, args: &[&str]) -> AdminCall<'a> {
        AdminCall {
            admin: self,
            args: args.iter().map(|a| (*a).to_owned()).collect(),
            stdin: None,
            env: self.env.clone(),
            state: self.state.clone(),
            cwd: None,
        }
    }

    /// `ok(...)`: exit 0, empty stderr, JSON on stdout.
    pub fn ok(&self, args: &[&str]) -> Value {
        self.cmd(args).ok()
    }

    /// `fail(..., code=1)`: exit `code`, empty stdout, JSON error on stderr.
    pub fn fail(&self, args: &[&str]) -> Value {
        self.cmd(args).fail(1)
    }

    pub fn add_needle(&self, needle: &str) {
        self.needles.lock().unwrap().push(needle.to_owned());
    }

    /// The tearDown sweep; also called on drop.
    pub fn assert_no_value_leaks(&self) {
        let synthetic = regex::Regex::new(r"synthetic-[A-Za-z0-9_.-]+").unwrap();
        let mut needles = vec!["BEGIN OPENSSH PRIVATE KEY".to_owned()];
        needles.extend(self.needles.lock().unwrap().iter().cloned());
        for record in self.outputs.lock().unwrap().iter() {
            let reveal = record.argv.iter().any(|a| a == "reveal");
            for needle in &needles {
                assert!(
                    !record.stderr.contains(needle.as_str()),
                    "stderr leaked a value: {:?}",
                    record.argv
                );
                if !reveal {
                    assert!(
                        !record.stdout.contains(needle.as_str()),
                        "stdout leaked a value: {:?}",
                        record.argv
                    );
                }
            }
            assert!(
                !synthetic.is_match(&record.stderr),
                "stderr leaked a value: {:?}",
                record.argv
            );
            if !reveal {
                assert!(
                    !synthetic.is_match(&record.stdout),
                    "stdout leaked a value: {:?}",
                    record.argv
                );
            }
        }
    }
}

impl Drop for Admin {
    fn drop(&mut self) {
        if !thread::panicking() && self.sweep.load(Ordering::SeqCst) {
            self.assert_no_value_leaks();
        }
    }
}

/// A pending administrator invocation (builder).
pub struct AdminCall<'a> {
    admin: &'a Admin,
    args: Vec<String>,
    stdin: Option<Vec<u8>>,
    env: Vec<(String, String)>,
    state: PathBuf,
    cwd: Option<PathBuf>,
}

impl AdminCall<'_> {
    pub fn stdin(mut self, bytes: &[u8]) -> Self {
        self.stdin = Some(bytes.to_vec());
        self
    }

    pub fn env(mut self, name: &str, value: &str) -> Self {
        self.env.retain(|(k, _)| k != name);
        self.env.push((name.into(), value.into()));
        self
    }

    pub fn unset(mut self, name: &str) -> Self {
        self.env.retain(|(k, _)| k != name);
        self
    }

    /// Run against another state directory.
    pub fn state(mut self, state: &Path) -> Self {
        self.state = state.to_path_buf();
        self
    }

    /// Run without `--state-dir` (the argv is used as given).
    pub fn no_state(mut self) -> Self {
        self.state = PathBuf::new();
        self
    }

    pub fn cwd(mut self, cwd: &Path) -> Self {
        self.cwd = Some(cwd.to_path_buf());
        self
    }

    /// Run; returns (exit code, stdout, stderr). Stdin is the given bytes,
    /// else empty (never a terminal, so no prompt).
    pub fn run(self) -> (i32, String, String) {
        let mut argv = Vec::new();
        if !self.state.as_os_str().is_empty() {
            argv.push("--state-dir".to_owned());
            argv.push(self.state.to_string_lossy().into_owned());
        }
        argv.extend(self.args.iter().cloned());
        let mut command = Command::new(ADMIN_BIN);
        command
            .args(&argv)
            .env_clear()
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(cwd) = &self.cwd {
            command.current_dir(cwd);
        }
        let mut child = command.spawn().expect("spawn zeropw-admin");
        let input = self.stdin.unwrap_or_default();
        let mut pipe = child.stdin.take().unwrap();
        let writer = thread::spawn(move || {
            let _ = pipe.write_all(&input);
        });
        let output = child.wait_with_output().unwrap();
        let _ = writer.join();
        let out = String::from_utf8_lossy(&output.stdout).into_owned();
        let err = String::from_utf8_lossy(&output.stderr).into_owned();
        self.admin.outputs.lock().unwrap().push(Recorded {
            argv: argv.clone(),
            stdout: out.clone(),
            stderr: err.clone(),
        });
        let code = output
            .status
            .code()
            .unwrap_or_else(|| panic!("zeropw-admin {argv:?} killed: {:?}", output.status));
        (code, out, err)
    }

    pub fn ok(self) -> Value {
        let args = self.args.clone();
        let (code, out, err) = self.run();
        assert_eq!(code, 0, "{args:?}: {err}");
        assert_eq!(err, "", "{args:?}");
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("{args:?}: not JSON ({e}): {out:?}"))
    }

    pub fn fail(self, expected: i32) -> Value {
        let args = self.args.clone();
        let (code, out, err) = self.run();
        assert_eq!(code, expected, "{args:?}: out={out:?} err={err:?}");
        assert_eq!(out, "", "{args:?}");
        let last = err
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .unwrap_or_else(|| panic!("{args:?}: empty stderr"));
        serde_json::from_str(last).unwrap_or_else(|e| panic!("{args:?}: not JSON ({e}): {last:?}"))
    }
}

/// Every audit event name, oldest first (`ctx().audit.tail(500)`).
pub fn events(state: &Path) -> Vec<String> {
    let ctx = zeropw::context::Context::open(
        state,
        zeropw::context::Config::default(),
        zeropw::clock::system(),
    )
    .unwrap();
    ctx.audit
        .tail(500)
        .unwrap()
        .into_iter()
        .map(|r| r["event"].as_str().unwrap_or_default().to_owned())
        .collect()
}

// ------------------------------------------------------------------ serve

/// A running `zeropw-admin ... serve` process. Stdout lines and stderr are
/// drained by background threads so the process never blocks on a pipe.
pub struct Serve {
    child: Option<Child>,
    pub url: String,
    pub startup: Value,
    stdout_rx: mpsc::Receiver<String>,
    stderr: Arc<Mutex<String>>,
    readers: Vec<thread::JoinHandle<()>>,
}

pub const SERVE_STARTUP: Duration = Duration::from_secs(60);

impl Serve {
    /// Start `serve --quiet` (plus `extra` arguments) with `env`, and read
    /// its JSON startup line within [`SERVE_STARTUP`].
    pub fn start(state: &Path, extra: &[&str], env: &[(&str, &str)]) -> Serve {
        let mut child = Command::new(ADMIN_BIN)
            .arg("--state-dir")
            .arg(state)
            .args(["serve", "--quiet"])
            .args(extra)
            .env_clear()
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn serve");
        let (tx, rx) = mpsc::channel();
        let stdout = child.stdout.take().unwrap();
        let out_reader = thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let stderr_text = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&stderr_text);
        let mut stderr = child.stderr.take().unwrap();
        let err_reader = thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while let Ok(n) = stderr.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                sink.lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buffer[..n]));
            }
        });
        let mut serve = Serve {
            child: Some(child),
            url: String::new(),
            startup: Value::Null,
            stdout_rx: rx,
            stderr: stderr_text,
            readers: vec![out_reader, err_reader],
        };
        let line = match serve.stdout_rx.recv_timeout(SERVE_STARTUP) {
            Ok(line) => line,
            Err(_) => {
                let (code, output) = serve.stop();
                panic!("serve printed no startup line (exit {code}): {output}");
            }
        };
        serve.startup = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("serve startup line is not JSON ({e}): {line:?}"));
        serve.url = serve.startup["url"].as_str().unwrap().to_owned();
        serve
    }

    pub fn pid(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }

    /// SIGTERM, wait up to 20 s, and return (exit code, all remaining
    /// stdout and stderr text).
    pub fn stop(&mut self) -> (i32, String) {
        let Some(mut child) = self.child.take() else {
            return (-1, String::new());
        };
        let _ = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                break child.wait().unwrap();
            }
            thread::sleep(Duration::from_millis(20));
        };
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        let mut output: Vec<String> = self.stdout_rx.try_iter().collect();
        output.push(self.stderr.lock().unwrap().clone());
        let code = status.code().unwrap_or_else(|| {
            use std::os::unix::process::ExitStatusExt;
            -status.signal().unwrap_or(0)
        });
        (code, output.join("\n"))
    }
}

impl Drop for Serve {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// ----------------------------------------------------- process e2e harness

/// The `_CliProcessTestCase` harness: one temporary root with `state/` and
/// an empty agent home, a fake upstream holding `credential`, every
/// captured output in `transcript`, and the serve process.
pub struct Processes {
    _tmp: tempfile::TempDir,
    pub root: PathBuf,
    pub state: PathBuf,
    pub agent_home: PathBuf,
    pub transcript: Mutex<Vec<(String, String)>>,
    pub upstream: zeropw::fake_upstream::FakeUpstream,
    pub serve: Option<Serve>,
    pub url: String,
    pub token: String,
    pub admin_passphrase: String,
    pub recovery_passphrase: String,
}

impl Processes {
    pub fn new(credential: &str, admin_passphrase: &str, recovery_passphrase: &str) -> Self {
        let tmp = tempfile::Builder::new().prefix("zpwc-").tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let agent_home = root.join("agent-home");
        std::fs::create_dir(&agent_home).unwrap();
        std::fs::set_permissions(&agent_home, std::fs::Permissions::from_mode(0o700)).unwrap();
        let upstream = zeropw::fake_upstream::FakeUpstream::new(credential).start();
        Processes {
            state: root.join("state"),
            root,
            _tmp: tmp,
            agent_home,
            transcript: Mutex::new(Vec::new()),
            upstream,
            serve: None,
            url: String::new(),
            token: String::new(),
            admin_passphrase: admin_passphrase.to_owned(),
            recovery_passphrase: recovery_passphrase.to_owned(),
        }
    }

    pub fn record(&self, who: &str, text: &str) {
        self.transcript
            .lock()
            .unwrap()
            .push((who.to_owned(), text.to_owned()));
    }

    /// Run the administrator; require exit `expect`; return its JSON
    /// (stdout on success, last stderr line on failure; `{}` if empty).
    pub fn admin(&self, args: &[&str], stdin: Option<&[u8]>, expect: i32) -> Value {
        let mut child = Command::new(ADMIN_BIN)
            .arg("--state-dir")
            .arg(&self.state)
            .args(args)
            .env_clear()
            .env("PATH", path_env())
            .env("HOME", &self.root)
            .env("ZEROPW_ADMIN_PASSPHRASE", &self.admin_passphrase)
            .env("ZEROPW_RECOVERY_PASSPHRASE", &self.recovery_passphrase)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = stdin.unwrap_or_default().to_vec();
        let mut pipe = child.stdin.take().unwrap();
        let writer = thread::spawn(move || {
            let _ = pipe.write_all(&input);
        });
        let output = child.wait_with_output().unwrap();
        let _ = writer.join();
        let out = String::from_utf8_lossy(&output.stdout).into_owned();
        let err = String::from_utf8_lossy(&output.stderr).into_owned();
        if !args.contains(&"reveal") {
            let who = format!(
                "admin {}",
                args.iter().take(2).copied().collect::<Vec<_>>().join(" ")
            );
            self.record(&who, &format!("{out}{err}"));
        }
        let code = output.status.code().expect("admin exit status");
        assert_eq!(code, expect, "admin {args:?}: {err}");
        cli_json(code, &out, &err)
    }

    /// Run the agent client with only the gateway URL and the caller token
    /// (and PATH/HOME); require exit `expect` when given.
    pub fn agent(&self, args: &[&str], expect: Option<i32>) -> (i32, Value) {
        self.agent_as(&self.token, args, expect)
    }

    pub fn agent_as(&self, token: &str, args: &[&str], expect: Option<i32>) -> (i32, Value) {
        let output = Command::new(AGENT_BIN)
            .args(args)
            .env_clear()
            .env("PATH", path_env())
            .env("HOME", &self.agent_home)
            .env("ZEROPW_GATEWAY_URL", &self.url)
            .env("ZEROPW_CALLER_TOKEN", token)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let out = String::from_utf8_lossy(&output.stdout).into_owned();
        let err = String::from_utf8_lossy(&output.stderr).into_owned();
        let who = format!(
            "agent {}",
            args.iter().take(3).copied().collect::<Vec<_>>().join(" ")
        );
        self.record(&who, &format!("{out}{err}"));
        let code = output.status.code().expect("agent exit status");
        if let Some(expect) = expect {
            assert_eq!(code, expect, "agent {args:?}: out={out} err={err}");
        }
        let payload = if out.trim().is_empty() { &err } else { &out };
        let value = if payload.trim().is_empty() {
            json!({})
        } else {
            serde_json::from_str(payload)
                .unwrap_or_else(|e| panic!("agent JSON ({e}): {payload:?}"))
        };
        (code, value)
    }

    /// Start `serve --quiet` with PATH, HOME and the admin passphrase.
    pub fn start_serve(&mut self) {
        let root = self.root.to_string_lossy().into_owned();
        let path = path_env();
        let serve = Serve::start(
            &self.state,
            &[],
            &[
                ("PATH", path.as_str()),
                ("HOME", root.as_str()),
                ("ZEROPW_ADMIN_PASSPHRASE", self.admin_passphrase.as_str()),
            ],
        );
        self.record("serve startup", &serve.startup.to_string());
        self.url = serve.url.clone();
        self.serve = Some(serve);
    }

    pub fn stop_serve(&mut self) -> (i32, String) {
        let mut serve = self.serve.take().expect("serve running");
        let (code, output) = serve.stop();
        self.record("serve exit", &output);
        (code, output)
    }

    /// Poll `status --run` until the run leaves queued/running.
    pub fn wait_run(&self, run_id: &str, timeout: Duration) -> Value {
        let deadline = Instant::now() + timeout;
        loop {
            let (_code, status) = self.agent(&["status", "--run", run_id], Some(0));
            let state = status["state"].as_str().unwrap_or_default();
            if state != "queued" && state != "running" {
                return status;
            }
            assert!(
                Instant::now() <= deadline,
                "run {run_id} did not finish: {status}"
            );
            thread::sleep(Duration::from_millis(200));
        }
    }

    /// No secret -- raw, in any scanned encoding, or inside a decoded
    /// base64/hex/percent token -- in any captured output or state file.
    pub fn assert_no_secret_anywhere(&self, credential: &str, private_key_pem: Option<&str>) {
        let mut secrets = vec![credential.as_bytes().to_vec()];
        if let Some(pem) = private_key_pem {
            secrets.extend(ssh_key_material(pem));
        }
        for (who, text) in self.transcript.lock().unwrap().iter() {
            assert!(
                find_secret(text.as_bytes(), &secrets).is_none(),
                "{who} output carried secret material"
            );
        }
        assert_eq!(
            find_secret_in_tree(&self.state, &secrets),
            None,
            "secret material in the state directory"
        );
    }

    pub fn agent_home_is_empty(&self) -> bool {
        std::fs::read_dir(&self.agent_home)
            .unwrap()
            .next()
            .is_none()
    }
}

impl Drop for Processes {
    fn drop(&mut self) {
        if let Some(mut serve) = self.serve.take() {
            serve.stop();
        }
        self.upstream.stop();
    }
}

pub fn pid_alive(pid: i32) -> bool {
    // SAFETY: signal 0 only checks for existence.
    let rc = unsafe { libc::kill(pid, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

// --------------------------------------------------------------- leakcheck

const MIN_DECODED_NEEDLE: usize = 16;

fn lenient_engine() -> base64::engine::GeneralPurpose {
    base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    )
}

/// `base64.b64decode`/`urlsafe_b64decode` without validation: characters
/// outside the (translated) alphabet are discarded.
fn python_b64decode(data: &[u8], urlsafe: bool) -> Option<Vec<u8>> {
    let filtered: Vec<u8> = data
        .iter()
        .map(|&b| match (urlsafe, b) {
            (true, b'-') => b'+',
            (true, b'_') => b'/',
            _ => b,
        })
        .filter(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
        .collect();
    if filtered.len() % 4 == 1 {
        return None;
    }
    lenient_engine().decode(&filtered).ok()
}

fn b64_decodings(token: &[u8]) -> Vec<Vec<u8>> {
    let mut body = token;
    while body.last() == Some(&b'=') {
        body = &body[..body.len() - 1];
    }
    let mut out = Vec::new();
    for offset in 0..4 {
        if offset > body.len() {
            break;
        }
        let chunk = &body[offset..];
        if chunk.len() < 8 {
            break;
        }
        for urlsafe in [false, true] {
            if let Some(decoded) = python_b64decode(chunk, urlsafe) {
                out.push(decoded);
            }
        }
    }
    out
}

fn hex_decodings(token: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for offset in 0..2 {
        if offset > token.len() {
            break;
        }
        let chunk = &token[offset..];
        let chunk = &chunk[..chunk.len() - chunk.len() % 2];
        if let Ok(decoded) = hex::decode(chunk) {
            out.push(decoded);
        }
    }
    out
}

/// `urllib.parse.unquote_to_bytes`.
fn unquote_to_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'%' && i + 2 < data.len() {
            let digits = std::str::from_utf8(&data[i + 1..i + 3]).unwrap_or("zz");
            if let Ok(byte) = u8::from_str_radix(digits, 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(data[i]);
        i += 1;
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Where (which encoding) one of `secrets` occurs in `data`, or `None`
/// (port of `tests/leakcheck.py::find_secret`).
pub fn find_secret(data: &[u8], secrets: &[Vec<u8>]) -> Option<String> {
    for (index, secret) in secrets.iter().enumerate() {
        for pattern in zeropw::runs::credential_patterns(secret) {
            if contains(data, &pattern) {
                return Some(format!("secret #{index} in a directly scanned encoding"));
            }
        }
    }
    let raw: Vec<(usize, &Vec<u8>)> = secrets
        .iter()
        .enumerate()
        .filter(|(_, s)| s.len() >= MIN_DECODED_NEEDLE)
        .collect();
    if raw.is_empty() {
        return None;
    }
    let hit = |decoded: &[u8], how: &str| -> Option<String> {
        raw.iter()
            .find(|(_, secret)| contains(decoded, secret))
            .map(|(index, _)| format!("secret #{index} inside decoded {how}"))
    };
    let plus_as_space: Vec<u8> = data
        .iter()
        .map(|&b| if b == b'+' { b' ' } else { b })
        .collect();
    let unquoted = unquote_to_bytes(&plus_as_space);
    if unquoted != data
        && let Some(found) = hit(&unquoted, "percent-encoding")
    {
        return Some(found);
    }
    let b64 = regex::bytes::Regex::new(r"[A-Za-z0-9+/_-]{16,}={0,2}").unwrap();
    for token in b64.find_iter(data) {
        for decoded in b64_decodings(token.as_bytes()) {
            if let Some(found) = hit(&decoded, "base64") {
                return Some(found);
            }
        }
    }
    let hexes = regex::bytes::Regex::new(r"[0-9A-Fa-f]{16,}").unwrap();
    for token in hexes.find_iter(data) {
        for decoded in hex_decodings(token.as_bytes()) {
            if let Some(found) = hit(&decoded, "hex") {
                return Some(found);
            }
        }
    }
    None
}

/// First file under `root` (relative path) that carries one of `secrets`.
pub fn find_secret_in_tree(root: &Path, secrets: &[Vec<u8>]) -> Option<String> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                files.push(path);
            }
        }
    }
    files.sort();
    for path in files {
        if let Ok(bytes) = std::fs::read(&path)
            && let Some(found) = find_secret(&bytes, secrets)
        {
            return Some(format!(
                "{}: {found}",
                path.strip_prefix(root).unwrap().display()
            ));
        }
    }
    None
}

/// Needles for an OpenSSH private key: the PEM text, the decoded
/// `openssh-key-v1` blob, the Ed25519 seed and the PEM marker.
pub fn ssh_key_material(private_key_pem: &str) -> Vec<Vec<u8>> {
    let body: String = private_key_pem
        .trim()
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let blob = base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap();
    let key = zeropw::sshwire::parse_openssh_private_key(private_key_pem.as_bytes()).unwrap();
    vec![
        private_key_pem.as_bytes().to_vec(),
        blob,
        key.seed().expose().to_vec(),
        b"BEGIN OPENSSH PRIVATE KEY".to_vec(),
    ]
}

// ---------------------------------------------------------------- FakeSmtp

/// One received message.
#[derive(Clone, Debug)]
pub struct SmtpMessage {
    pub sender: String,
    pub recipients: Vec<String>,
    pub data: Vec<u8>,
}

#[derive(Default)]
struct SmtpState {
    messages: Vec<SmtpMessage>,
    auth_attempts: Vec<(String, String)>,
}

/// Minimal loopback SMTP receiver (port of `tests/fake_smtp.py`): a 220
/// banner, EHLO/HELO advertising `AUTH PLAIN LOGIN` (no STARTTLS, no
/// 8BITMIME), AUTH PLAIN/LOGIN (decoded credentials recorded), MAIL, RCPT,
/// DATA, RSET, NOOP and QUIT. It can be stopped and restarted on the same
/// port.
pub struct FakeSmtp {
    state: Arc<Mutex<SmtpState>>,
    port: u16,
    stop: Arc<AtomicBool>,
    accept: Option<thread::JoinHandle<()>>,
}

impl Default for FakeSmtp {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeSmtp {
    pub fn new() -> Self {
        FakeSmtp {
            state: Arc::new(Mutex::new(SmtpState::default())),
            port: 0,
            stop: Arc::new(AtomicBool::new(false)),
            accept: None,
        }
    }

    pub fn start(&mut self) -> &mut Self {
        if self.accept.is_some() {
            return self;
        }
        let listener = TcpListener::bind(("127.0.0.1", self.port)).expect("bind fake smtp");
        self.port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        self.stop = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&self.stop);
        let state = Arc::clone(&self.state);
        self.accept = Some(thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((client, _)) => {
                        // BSD/macOS accepted sockets inherit the listener's
                        // O_NONBLOCK; the session reads with blocking I/O.
                        let _ = client.set_nonblocking(false);
                        let state = Arc::clone(&state);
                        thread::spawn(move || serve_smtp(client, &state));
                    }
                    Err(_) => thread::sleep(Duration::from_millis(20)),
                }
            }
        }));
        self
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
    }

    pub fn host(&self) -> &'static str {
        "127.0.0.1"
    }

    pub fn port(&self) -> u16 {
        assert_ne!(self.port, 0, "fake smtp never started");
        self.port
    }

    pub fn messages(&self) -> Vec<SmtpMessage> {
        self.state.lock().unwrap().messages.clone()
    }

    pub fn auth_attempts(&self) -> Vec<(String, String)> {
        self.state.lock().unwrap().auth_attempts.clone()
    }

    pub fn reset(&self) {
        let mut state = self.state.lock().unwrap();
        state.messages.clear();
        state.auth_attempts.clear();
    }
}

impl Drop for FakeSmtp {
    fn drop(&mut self) {
        self.stop();
    }
}

fn b64_text(text: &str) -> String {
    lenient_engine()
        .decode(text.trim())
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

fn serve_smtp(client: TcpStream, state: &Mutex<SmtpState>) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(10)));
    let mut writer = client.try_clone().unwrap();
    let mut reader = BufReader::new(client);
    let mut send = |text: &str| writer.write_all(text.as_bytes()).is_ok();
    let read_line = |reader: &mut BufReader<TcpStream>| -> Option<String> {
        let mut line = Vec::new();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(
                String::from_utf8_lossy(&line)
                    .trim_end_matches(['\r', '\n'])
                    .to_owned(),
            ),
        }
    };
    let record_plain = |blob: &str| {
        if let Ok(raw) = lenient_engine().decode(blob.trim()) {
            let parts: Vec<&[u8]> = raw.split(|&b| b == 0).collect();
            if parts.len() == 3 {
                state.lock().unwrap().auth_attempts.push((
                    String::from_utf8_lossy(parts[1]).into_owned(),
                    String::from_utf8_lossy(parts[2]).into_owned(),
                ));
            }
        }
    };
    if !send("220 fake-smtp ready\r\n") {
        return;
    }
    let mut mail_from: Option<String> = None;
    let mut rcpt_to: Vec<String> = Vec::new();
    while let Some(text) = read_line(&mut reader) {
        let upper = text.to_ascii_uppercase();
        let ok = if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            send("250-fake-smtp\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n")
        } else if upper.starts_with("AUTH PLAIN") {
            let parts: Vec<&str> = text.splitn(3, ' ').collect();
            if parts.len() == 3 {
                record_plain(parts[2]);
            } else {
                send("334 \r\n");
                let blob = read_line(&mut reader).unwrap_or_default();
                record_plain(&blob);
            }
            send("235 authenticated\r\n")
        } else if upper.starts_with("AUTH LOGIN") {
            let parts: Vec<&str> = text.splitn(3, ' ').collect();
            let username = if parts.len() >= 3 {
                b64_text(parts[2])
            } else {
                send("334 VXNlcm5hbWU6\r\n");
                b64_text(&read_line(&mut reader).unwrap_or_default())
            };
            send("334 UGFzc3dvcmQ6\r\n");
            let password = b64_text(&read_line(&mut reader).unwrap_or_default());
            state
                .lock()
                .unwrap()
                .auth_attempts
                .push((username, password));
            send("235 authenticated\r\n")
        } else if upper.starts_with("MAIL FROM") {
            mail_from = Some(text.split_once(':').unwrap().1.trim().to_owned());
            send("250 OK\r\n")
        } else if upper.starts_with("RCPT TO") {
            rcpt_to.push(text.split_once(':').unwrap().1.trim().to_owned());
            send("250 OK\r\n")
        } else if upper.starts_with("DATA") {
            send("354 end with <CRLF>.<CRLF>\r\n");
            let mut raw = Vec::new();
            loop {
                let mut line = Vec::new();
                match reader.read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                if line == b".\r\n" || line == b".\n" {
                    break;
                }
                if line.starts_with(b"..") {
                    line.remove(0);
                }
                raw.extend_from_slice(&line);
            }
            state.lock().unwrap().messages.push(SmtpMessage {
                sender: mail_from.take().unwrap_or_default(),
                recipients: std::mem::take(&mut rcpt_to),
                data: raw,
            });
            send("250 OK queued\r\n")
        } else if upper.starts_with("RSET") {
            mail_from = None;
            rcpt_to.clear();
            send("250 OK\r\n")
        } else if upper.starts_with("NOOP") {
            send("250 OK\r\n")
        } else if upper.starts_with("QUIT") {
            send("221 bye\r\n");
            break;
        } else {
            send("502 command not implemented\r\n")
        };
        if !ok {
            break;
        }
    }
}

/// Decode RFC 2047 encoded words (`=?charset?b|q?...?=`) in a header value
/// (UTF-8/ASCII charsets; whitespace between encoded words is dropped).
pub fn decode_header(value: &str) -> String {
    let re = regex::Regex::new(r"=\?([^?]+)\?([bBqQ])\?([^?]*)\?=").unwrap();
    let mut out = String::new();
    let mut last = 0;
    let mut previous_was_word = false;
    for m in re.captures_iter(value) {
        let whole = m.get(0).unwrap();
        let between = &value[last..whole.start()];
        if !(previous_was_word && between.trim().is_empty()) {
            out.push_str(between);
        }
        let bytes = if m[2].eq_ignore_ascii_case("b") {
            lenient_engine().decode(&m[3]).unwrap_or_default()
        } else {
            decode_quoted_printable(&m[3].replace('_', " "), false)
        };
        out.push_str(&String::from_utf8_lossy(&bytes));
        last = whole.end();
        previous_was_word = true;
    }
    out.push_str(&value[last..]);
    out
}

fn decode_quoted_printable(text: &str, body: bool) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' {
            if body && bytes.get(i + 1) == Some(&b'\r') && bytes.get(i + 2) == Some(&b'\n') {
                i += 3;
                continue;
            }
            if body && bytes.get(i + 1) == Some(&b'\n') {
                i += 2;
                continue;
            }
            if i + 2 < bytes.len() {
                let digits = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("zz");
                if let Ok(b) = u8::from_str_radix(digits, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// (subject, body) of a received message as a human would read them,
/// whatever Content-Transfer-Encoding was used on the wire.
pub fn parse_message(raw: &[u8]) -> (String, String) {
    let text = String::from_utf8_lossy(raw).replace("\r\n", "\n");
    let (head, body) = text.split_once("\n\n").unwrap_or((&text, ""));
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in head.lines() {
        if line.starts_with([' ', '\t']) {
            if let Some(last) = headers.last_mut() {
                last.1.push_str(line);
            }
        } else if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    let header = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    let subject = decode_header(&header("subject"));
    let encoding = header("content-transfer-encoding").to_ascii_lowercase();
    let payload = match encoding.as_str() {
        "base64" => {
            let joined: String = body.split_whitespace().collect();
            lenient_engine().decode(joined).unwrap_or_default()
        }
        "quoted-printable" => decode_quoted_printable(body, true),
        _ => body.as_bytes().to_vec(),
    };
    (subject, String::from_utf8_lossy(&payload).into_owned())
}

/// Write `notify.json` (mode 0600) for a [`FakeSmtp`] with the synthetic
/// SMTP password in `root/smtp.pass` (mode 0600).
pub fn write_notify_config(state: &Path, root: &Path, smtp: &FakeSmtp) -> PathBuf {
    let password = root.join("smtp.pass");
    std::fs::write(&password, format!("{SMTP_PASSWORD}\n")).unwrap();
    std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = state.join("notify.json");
    std::fs::write(
        &config,
        json!({
            "host": smtp.host(), "port": smtp.port(), "mode": "plain",
            "sender": "zeropw@example.com", "recipients": ["admin@example.com"],
            "username": "smtpuser", "password_file": password,
        })
        .to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    config
}

// --------------------------------------------------------------------- sshd

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// `sshd`, `ssh` and `ssh-keygen`. Panics (never a silent pass) when the
/// real OpenSSH tooling this coverage needs is missing.
pub fn ssh_tools() -> (PathBuf, PathBuf, PathBuf) {
    let sshd = which("sshd").or_else(|| {
        let fallback = PathBuf::from("/usr/sbin/sshd");
        fallback.is_file().then_some(fallback)
    });
    match (sshd, which("ssh"), which("ssh-keygen")) {
        (Some(sshd), Some(ssh), Some(keygen)) => (sshd, ssh, keygen),
        _ => panic!(
            "sshd, ssh, or ssh-keygen not available: this end-to-end SSH test requires real \
             OpenSSH tooling and must fail, not silently pass, when it is missing"
        ),
    }
}

pub fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn ssh_banner(port: u16) -> String {
    match TcpStream::connect(("127.0.0.1", port)) {
        Ok(sock) => {
            let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
            let mut line = String::new();
            let _ = BufReader::new(sock).read_line(&mut line);
            line
        }
        Err(_) => String::new(),
    }
}

/// A real `sshd` on 127.0.0.1 as the current (non-root) user, with a
/// generated host key and one authorized key; killed on drop.
pub struct Sshd {
    pub port: u16,
    pub host_key_line: String,
    child: Option<Child>,
}

impl Sshd {
    pub fn start(root: &Path, authorized_keys_line: &str) -> Sshd {
        let (sshd_bin, _ssh, keygen) = ssh_tools();
        let dir = root.join("sshd");
        std::fs::create_dir_all(&dir).unwrap();
        let host_key = dir.join("host_ed25519");
        let status = Command::new(&keygen)
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&host_key)
            .status()
            .unwrap();
        assert!(status.success(), "ssh-keygen failed");
        let host_key_line = std::fs::read_to_string(dir.join("host_ed25519.pub"))
            .unwrap()
            .trim()
            .to_owned();
        let authorized = dir.join("authorized_keys");
        std::fs::write(&authorized, format!("{authorized_keys_line}\n")).unwrap();
        std::fs::set_permissions(&authorized, std::fs::Permissions::from_mode(0o600)).unwrap();
        let config = dir.join("sshd_config");
        for _attempt in 0..3 {
            let port = free_port();
            std::fs::write(
                &config,
                format!(
                    "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile none\n\
                     AuthorizedKeysFile {}\nPubkeyAuthentication yes\nPasswordAuthentication no\n\
                     KbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nLogLevel ERROR\n\
                     AllowAgentForwarding no\nAllowTcpForwarding no\nX11Forwarding no\n\
                     PermitUserEnvironment no\n",
                    host_key.display(),
                    authorized.display()
                ),
            )
            .unwrap();
            let mut child = Command::new(&sshd_bin)
                .args(["-D", "-e", "-f"])
                .arg(&config)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut serving = false;
            while Instant::now() < deadline {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                if ssh_banner(port).starts_with("SSH-2.0-OpenSSH") {
                    thread::sleep(Duration::from_millis(200));
                    serving = child.try_wait().unwrap().is_none();
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
            if serving {
                return Sshd {
                    port,
                    host_key_line,
                    child: Some(child),
                };
            }
            let _ = child.kill();
            let mut stderr = String::new();
            if let Some(mut s) = child.stderr.take() {
                let _ = s.read_to_string(&mut stderr);
            }
            let _ = child.wait();
            if !(stderr.contains("Address already in use") || stderr.contains("Cannot bind")) {
                panic!("sshd could not start as a non-root user in this environment: {stderr}");
            }
        }
        panic!("sshd could not bind a free loopback port");
    }
}

impl Drop for Sshd {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// The current user's login name (what `getpass.getuser()` returned).
pub fn username() -> String {
    nix::unistd::User::from_uid(nix::unistd::Uid::current())
        .unwrap()
        .unwrap()
        .name
}

/// Variables the inspector's own `/bin/sh` may add to its environment.
const SHELL_ADDED_ENV: [&str; 4] = ["PWD", "OLDPWD", "SHLVL", "_"];

/// A `/bin/sh` inspector used as an SSH connection's CLI program: it records
/// what each exec child sees (argv, environment, the files of its working
/// directory) under `reports/<pid>/` and then `exec`s the real `ssh` (the
/// pid is kept). Returns (program path, reports directory).
pub fn write_ssh_inspector(root: &Path) -> (PathBuf, PathBuf) {
    let (_sshd, ssh, _keygen) = ssh_tools();
    let bin = root.join("inspector-bin");
    let reports = root.join("inspector-reports");
    for dir in [&bin, &reports] {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let program = bin.join("ssh-inspector");
    let script = format!(
        "#!/bin/sh\n\
         report='{reports}'/$$\n\
         mkdir \"$report\" \"$report/entries\" || exit 97\n\
         env > \"$report/env\"\n\
         for arg in \"$0\" \"$@\"; do printf '%s\\0' \"$arg\"; done > \"$report/argv\"\n\
         for name in * .[!.]* ..?*; do\n\
         \x20 [ -e \"$name\" ] || [ -L \"$name\" ] || continue\n\
         \x20 if [ -f \"$name\" ] && [ ! -L \"$name\" ]; then cat \"$name\" > \"$report/entries/$name\";\n\
         \x20 else : > \"$report/entries/$name.not-a-file\"; fi\n\
         done\n\
         : > \"$report/done\"\n\
         exec '{ssh}' \"$@\"\n",
        reports = reports.display(),
        ssh = ssh.display()
    );
    std::fs::write(&program, script).unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
    (program, reports)
}

/// One inspector report: (pid, argv, environment, working-directory files).
pub struct InspectorReport {
    pub pid: i32,
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub entries: BTreeMap<String, Option<Vec<u8>>>,
}

pub fn inspector_reports(reports: &Path) -> Vec<InspectorReport> {
    let mut out = Vec::new();
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(reports)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.join("done").exists())
        .collect();
    dirs.sort();
    for dir in dirs {
        let pid = dir.file_name().unwrap().to_str().unwrap().parse().unwrap();
        let argv = std::fs::read(dir.join("argv"))
            .unwrap()
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        let env = std::fs::read_to_string(dir.join("env"))
            .unwrap()
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        let mut entries = BTreeMap::new();
        for entry in std::fs::read_dir(dir.join("entries")).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            match name.strip_suffix(".not-a-file") {
                Some(base) => entries.insert(base.to_owned(), None),
                None => entries.insert(name, Some(std::fs::read(&path).unwrap())),
            };
        }
        out.push(InspectorReport {
            pid,
            argv,
            env,
            entries,
        });
    }
    out
}

/// Every recorded exec child: only `id.pub` and `known_hosts` in its working
/// directory, a fixed environment, and no key material in any file,
/// variable or argument.
pub fn assert_exec_children_held_no_key(reports: &Path, private_key_pem: &str, minimum: usize) {
    let material = ssh_key_material(private_key_pem);
    let reports = inspector_reports(reports);
    assert!(
        reports.len() >= minimum,
        "the inspector ran {} times",
        reports.len()
    );
    let expected_env: BTreeSet<&str> = [
        "PATH",
        "HOME",
        "LANG",
        "TMPDIR",
        "ZEROPW_RUN_ID",
        "SSH_AUTH_SOCK",
    ]
    .into();
    for report in reports {
        let files: BTreeSet<&str> = report.entries.keys().map(String::as_str).collect();
        assert_eq!(
            files,
            BTreeSet::from(["id.pub", "known_hosts"]),
            "files in the exec run directory"
        );
        for (name, content) in &report.entries {
            let content = content.as_ref().expect("regular file");
            assert!(
                find_secret(content, &material).is_none(),
                "run directory file {name}"
            );
        }
        // macOS CoreFoundation adds __CF_* inside the process; the
        // inspector's shell may add its own bookkeeping variables.
        let env: BTreeSet<&str> = report
            .env
            .keys()
            .map(String::as_str)
            .filter(|n| !n.starts_with("__CF_") && !SHELL_ADDED_ENV.contains(n))
            .collect();
        assert_eq!(env, expected_env, "exec child environment");
        for (name, value) in &report.env {
            assert!(
                find_secret(value.as_bytes(), &material).is_none(),
                "environment variable {name}"
            );
        }
        for item in &report.argv {
            assert!(
                find_secret(item.as_bytes(), &material).is_none(),
                "exec child argument"
            );
        }
    }
}

// ------------------------------------------------------------ self tests

#[test]
fn leakcheck_finds_raw_encoded_and_embedded_secrets() {
    let secret = b"synthetic-leakcheck-secret-0123".to_vec();
    let secrets = vec![secret.clone()];
    let b64 = base64::engine::general_purpose::STANDARD.encode(&secret);
    let embedded = base64::engine::general_purpose::STANDARD
        .encode([b"prefix-".as_slice(), &secret, b"-suffix"].concat());
    for data in [
        secret.clone(),
        b64.into_bytes(),
        hex::encode(&secret).into_bytes(),
        hex::encode([b"xx".as_slice(), &secret].concat()).into_bytes(),
        embedded.into_bytes(),
        percent_encoding::percent_encode(&secret, percent_encoding::NON_ALPHANUMERIC)
            .to_string()
            .into_bytes(),
    ] {
        assert!(
            find_secret(&data, &secrets).is_some(),
            "{:?}",
            String::from_utf8_lossy(&data)
        );
    }
    assert_eq!(
        find_secret(b"nothing to see here at all, really", &secrets),
        None
    );
}

#[test]
fn parse_message_decodes_encoded_subject_and_base64_body() {
    let raw = "Subject: [ZeroPW] =?utf-8?b?7JWM66a8?=\r\n =?utf-8?b?IOyEpOyglQ==?=\r\n\
               Content-Transfer-Encoding: base64\r\n\r\n7JWM66a8IOuzuOusuA==\r\n";
    let (subject, body) = parse_message(raw.as_bytes());
    assert_eq!(subject, "[ZeroPW] 알림 설정");
    assert_eq!(body, "알림 본문");
}
