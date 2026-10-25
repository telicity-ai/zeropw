//! [`ServeSupervisor`] (docs/desktop-app.md §4.2): runs `zeropw-admin serve` as a sidecar.
//!
//! - Start: `zeropw-admin --state-dir=D serve --listen=127.0.0.1:<port> [--team-listen=IP:PORT]
//!   --quiet` with the fixed child environment, stderr appended to a 0600 log in the app data
//!   folder. The first stdout line is JSON carrying `url`; the sidecar counts as up once
//!   `GET /healthz` answers 200 (60 s budget for both).
//! - A sidecar that exits while starting is reported with the CLI's own `{error, reason}` from
//!   that log. A failure to open an address names the setting it came from in `detail`
//!   (`gateway_port` or `team_listen`), so the UI can tell the two apart (docs/desktop-app.md
//!   §5); any other CLI detail is dropped when it contains either address.
//! - Single instance: `serve.json` (pid, url, start time) in the app data folder. A later app
//!   run attaches only when that pid is alive, its command line is `zeropw-admin … serve` for
//!   this state directory, and `/healthz` answers 200 with `Server: zeropw-prototype`.
//! - Stop: SIGTERM, then SIGKILL only after up to 25 s. A stop that arrives while a start is
//!   still waiting for the sidecar cancels that start (the half-started sidecar is stopped)
//!   instead of waiting out the 60 s start budget, so quitting the app is never held up.
//! - Watch: [`ServeSupervisor::watch`] looks without waiting for a start or stop in progress,
//!   so the core can check every [`WATCH_INTERVAL`] whether the sidecar is still there and tell
//!   the window when it is gone (docs/desktop-app.md §4.2). It reports what it saw before the
//!   state is unlocked, and so do the `*_reported` start, stop and attach, so the window is
//!   told about them in the order they happened.
//! - Closing the window does not stop it; the app calls [`ServeSupervisor::stop`] on quit.

use std::ffi::OsString;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::sys::signal::{Signal, kill, killpg};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};

use crate::admin::{self, apply_child_env};
use crate::error::AppError;
use crate::paths::{self, AppPaths};

pub const START_TIMEOUT: Duration = Duration::from_secs(60);
pub const STOP_GRACE: Duration = Duration::from_secs(25);
/// How often the core checks that a running sidecar is still there.
pub const WATCH_INTERVAL: Duration = Duration::from_secs(2);
/// `server.SERVER_HEADER` in the product crate.
pub const SERVER_HEADER: &str = "zeropw-prototype";

const HEALTH_IO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_PID_FILE_BYTES: u64 = 4096;
const MAX_LOG_TAIL_BYTES: u64 = 64 * 1024;
const MAX_LOG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_FIRST_LINE_BYTES: u64 = 64 * 1024;

/// `ServeStatus` in the IPC contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServeStatus {
    pub running: bool,
    pub url: Option<String>,
    pub pid: Option<u32>,
    pub team_listen: Option<String>,
}

impl ServeStatus {
    pub fn stopped() -> Self {
        Self {
            running: false,
            url: None,
            pid: None,
            team_listen: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServeConfig {
    pub port: u16,
    pub team_listen: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct PidFile {
    pid: u32,
    url: String,
    started_at: u64,
    #[serde(default)]
    team_listen: Option<String>,
}

enum Running {
    Stopped,
    Owned {
        child: Child,
        url: String,
        team_listen: Option<String>,
    },
    Attached {
        pid: u32,
        url: String,
        team_listen: Option<String>,
    },
}

pub struct ServeSupervisor {
    admin_bin: PathBuf,
    state_dir: PathBuf,
    data_dir: PathBuf,
    pid_file: PathBuf,
    log_file: PathBuf,
    start_timeout: Duration,
    stop_grace: Duration,
    running: Mutex<Running>,
    /// Set by `stop` so a start in progress gives up at its next check.
    cancel_start: AtomicBool,
}

impl ServeSupervisor {
    pub fn new(paths: &AppPaths) -> Self {
        Self {
            admin_bin: paths.admin_bin(),
            state_dir: paths.state_dir(),
            data_dir: paths.app_data_dir.clone(),
            pid_file: paths.serve_pid_file(),
            log_file: paths.serve_log_file(),
            start_timeout: START_TIMEOUT,
            stop_grace: STOP_GRACE,
            running: Mutex::new(Running::Stopped),
            cancel_start: AtomicBool::new(false),
        }
    }

    pub fn with_timeouts(mut self, start: Duration, stop_grace: Duration) -> Self {
        self.start_timeout = start;
        self.stop_grace = stop_grace;
        self
    }

    fn lock(&self) -> MutexGuard<'_, Running> {
        self.running.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Current state; a sidecar that died since the last look is forgotten (and its pid file
    /// removed).
    pub fn status(&self) -> ServeStatus {
        let mut running = self.lock();
        self.refresh(&mut running);
        status_of(&mut running)
    }

    /// Like [`status`](Self::status), for the core's watcher: never waits for a start or stop
    /// in progress (`None` then; that start or stop reports its own result). A sidecar that
    /// died is noticed here: an owned one by its exit status, an attached one by its pid.
    /// `report` runs before the state is unlocked, so no start or stop comes between this look
    /// and what the caller does with it.
    pub fn watch<R>(&self, report: impl FnOnce(ServeStatus) -> R) -> Option<R> {
        let mut running = match self.running.try_lock() {
            Ok(running) => running,
            Err(TryLockError::Poisoned(e)) => e.into_inner(),
            Err(TryLockError::WouldBlock) => return None,
        };
        self.refresh(&mut running);
        Some(report(status_of(&mut running)))
    }

    /// The gateway URL while running.
    pub fn url(&self) -> Option<String> {
        self.status().url
    }

    /// At app start: adopt a sidecar left by an earlier app run, without starting a new one.
    pub fn attach(&self) -> ServeStatus {
        self.attach_reported(|_| {})
    }

    /// [`attach`](Self::attach), with `report` run on the result before the state is unlocked,
    /// as [`watch`](Self::watch) does: no look comes between the two.
    pub fn attach_reported(&self, report: impl FnOnce(&ServeStatus)) -> ServeStatus {
        let mut running = self.lock();
        self.refresh(&mut running);
        if matches!(*running, Running::Stopped)
            && let Some(Recorded::Healthy(attached)) = self.recorded()
        {
            *running = attached;
        }
        let status = status_of(&mut running);
        report(&status);
        status
    }

    /// Start (or attach to) the sidecar. Already running: returns the current status.
    pub fn start(&self, config: &ServeConfig) -> Result<ServeStatus, AppError> {
        self.start_reported(config, |_| {})
    }

    /// [`start`](Self::start), with `report` run on a successful result before the state is
    /// unlocked, as [`watch`](Self::watch) does: no look comes between the start and its
    /// report, so a look made just before cannot be reported after it, nor the other way round.
    pub fn start_reported(
        &self,
        config: &ServeConfig,
        report: impl FnOnce(&ServeStatus),
    ) -> Result<ServeStatus, AppError> {
        if config.port == 0 {
            return Err(AppError::invalid_input("invalid_port").with_detail("gateway_port"));
        }
        let mut running = self.lock();
        self.cancel_start.store(false, Ordering::SeqCst);
        self.refresh(&mut running);
        if matches!(*running, Running::Stopped) {
            match self.recorded() {
                Some(Recorded::Healthy(attached)) => *running = attached,
                recorded => {
                    // Ours but not answering: replace it rather than fight it for the port.
                    if let Some(Recorded::Unhealthy(pid)) = recorded {
                        terminate_pid(pid, self.stop_grace);
                    }
                    self.remove_pid_file();
                    *running = self.spawn(config)?;
                }
            }
        }
        let status = status_of(&mut running);
        report(&status);
        Ok(status)
    }

    /// SIGTERM, wait up to the grace period, then SIGKILL. Also stops a sidecar recorded by an
    /// earlier app run that this run never attached to.
    pub fn stop(&self) -> ServeStatus {
        self.stop_reported(|_| {})
    }

    /// [`stop`](Self::stop), with `report` run on the result before the state is unlocked, as
    /// [`watch`](Self::watch) does: no look or start comes between the stop and its report.
    pub fn stop_reported(&self, report: impl FnOnce(&ServeStatus)) -> ServeStatus {
        // Before taking the lock: a start holding it notices and gives up.
        self.cancel_start.store(true, Ordering::SeqCst);
        let mut running = self.lock();
        match std::mem::replace(&mut *running, Running::Stopped) {
            Running::Owned { mut child, .. } => terminate_child(&mut child, self.stop_grace),
            Running::Attached { pid, .. } => {
                if self.is_our_serve(pid) {
                    terminate_pid(pid, self.stop_grace);
                }
            }
            Running::Stopped => match self.recorded() {
                Some(Recorded::Healthy(Running::Attached { pid, .. }))
                | Some(Recorded::Unhealthy(pid)) => terminate_pid(pid, self.stop_grace),
                _ => {}
            },
        }
        self.remove_pid_file();
        let status = ServeStatus::stopped();
        report(&status);
        status
    }

    fn refresh(&self, running: &mut Running) {
        let gone = match running {
            Running::Stopped => false,
            Running::Owned { child, .. } => !matches!(child.try_wait(), Ok(None)),
            Running::Attached { pid, .. } => !alive(*pid),
        };
        if gone {
            *running = Running::Stopped;
            self.remove_pid_file();
        }
    }

    fn remove_pid_file(&self) {
        let _ = fs::remove_file(&self.pid_file);
    }

    /// What `serve.json` points at, if it is still our sidecar.
    fn recorded(&self) -> Option<Recorded> {
        let file = read_pid_file(&self.pid_file)?;
        let Some(port) = loopback_port(&file.url) else {
            self.remove_pid_file();
            return None;
        };
        if !alive(file.pid) || !self.is_our_serve(file.pid) {
            self.remove_pid_file();
            return None;
        }
        match healthz(port, HEALTH_IO_TIMEOUT) {
            Ok(health) if health.is_zeropw() => Some(Recorded::Healthy(Running::Attached {
                pid: file.pid,
                url: file.url,
                team_listen: file.team_listen,
            })),
            _ => Some(Recorded::Unhealthy(file.pid)),
        }
    }

    /// The pid runs `zeropw-admin … serve` for this state directory (guards against a reused
    /// pid before any signal is sent).
    fn is_our_serve(&self, pid: u32) -> bool {
        let Some((_, command)) = ps_info(pid) else {
            return false;
        };
        let mut state_arg = OsString::from("--state-dir=");
        state_arg.push(self.state_dir.as_os_str());
        let state_arg = state_arg.to_string_lossy().into_owned();
        command.contains(&*self.admin_bin.to_string_lossy())
            && command.contains(&state_arg)
            && command.split_whitespace().any(|word| word == "serve")
    }

    fn spawn(&self, config: &ServeConfig) -> Result<Running, AppError> {
        paths::ensure_private_dir(&self.data_dir)?;
        // Keep one previous log; the sidecar is quiet, so this only bounds a pathological case.
        if fs::metadata(&self.log_file).is_ok_and(|m| m.len() > MAX_LOG_BYTES) {
            let _ = fs::rename(&self.log_file, self.log_file.with_extension("log.1"));
        }
        let log = paths::open_private_append(&self.log_file)
            .map_err(|e| AppError::io("serve_log_unavailable", &e))?;
        let log_offset = log.metadata().map(|m| m.len()).unwrap_or(0);
        let mut state_arg = OsString::from("--state-dir=");
        state_arg.push(self.state_dir.as_os_str());

        let mut cmd = Command::new(&self.admin_bin);
        cmd.arg(state_arg)
            .arg("serve")
            .arg(format!("--listen=127.0.0.1:{}", config.port));
        if let Some(team) = &config.team_listen {
            if team.chars().any(char::is_control) {
                return Err(AppError::invalid_input("invalid_listen").with_detail("team_listen"));
            }
            cmd.arg(format!("--team-listen={team}"));
        }
        cmd.arg("--quiet")
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(log))
            .process_group(0);
        apply_child_env(&mut cmd);
        let mut child = admin::spawn(&mut cmd).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => AppError::unavailable("admin_binary_missing"),
            _ => AppError::io("serve_spawn_failed", &e),
        })?;

        let stdout = child.stdout.take();
        let (tx, rx) = mpsc::channel::<io::Result<String>>();
        thread::spawn(move || {
            let Some(stdout) = stdout else {
                return;
            };
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            let first = (&mut reader)
                .take(MAX_FIRST_LINE_BYTES)
                .read_line(&mut line)
                .map(|_| line);
            let _ = tx.send(first);
            // Keep draining so the sidecar never blocks on (or dies writing to) its stdout.
            let _ = io::copy(&mut reader, &mut io::sink());
        });

        let deadline = Instant::now() + self.start_timeout;
        let line = loop {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(Ok(line)) if !line.trim().is_empty() => break line,
                Ok(_) | Err(RecvTimeoutError::Disconnected) => {
                    return Err(self.fail_start(&mut child, config, log_offset, false));
                }
                Err(RecvTimeoutError::Timeout) => {
                    if self.cancel_start.load(Ordering::SeqCst) {
                        return Err(self.cancelled_start(&mut child));
                    }
                    if !matches!(child.try_wait(), Ok(None)) {
                        return Err(self.fail_start(&mut child, config, log_offset, false));
                    }
                    if Instant::now() >= deadline {
                        return Err(self.fail_start(&mut child, config, log_offset, true));
                    }
                }
            }
        };
        let url = serde_json::from_str::<serde_json::Value>(line.trim())
            .ok()
            .and_then(|v| v.get("url").and_then(|u| u.as_str()).map(str::to_owned))
            .filter(|url| loopback_port(url).is_some());
        let Some(url) = url else {
            terminate_child(&mut child, Duration::from_secs(2));
            return Err(AppError::internal("serve_output_invalid"));
        };
        let port = loopback_port(&url).unwrap_or(config.port);
        loop {
            if healthz(port, HEALTH_IO_TIMEOUT).is_ok_and(|h| h.is_zeropw()) {
                break;
            }
            if self.cancel_start.load(Ordering::SeqCst) {
                return Err(self.cancelled_start(&mut child));
            }
            if !matches!(child.try_wait(), Ok(None)) {
                return Err(self.fail_start(&mut child, config, log_offset, false));
            }
            if Instant::now() >= deadline {
                return Err(self.fail_start(&mut child, config, log_offset, true));
            }
            thread::sleep(Duration::from_millis(100));
        }

        let record = PidFile {
            pid: child.id(),
            url: url.clone(),
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            team_listen: config.team_listen.clone(),
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| AppError::internal("pid_encode"))?;
        if let Err(e) = paths::write_private_atomic(&self.pid_file, &bytes) {
            terminate_child(&mut child, Duration::from_secs(2));
            return Err(AppError::io("serve_pid_file_unwritable", &e));
        }
        Ok(Running::Owned {
            child,
            url,
            team_listen: config.team_listen.clone(),
        })
    }

    /// A `stop` arrived while starting: stop the half-started sidecar.
    fn cancelled_start(&self, child: &mut Child) -> AppError {
        terminate_child(child, self.stop_grace);
        AppError::state("serve_start_cancelled")
    }

    /// Stop a failed start and report why: the CLI's own `{error, reason}` from the log when it
    /// printed one, otherwise a generic code. A listen failure carries the setting it came
    /// from as its `detail` ([`listen_setting`]); any other CLI detail is kept only when it
    /// contains neither address.
    fn fail_start(
        &self,
        child: &mut Child,
        config: &ServeConfig,
        log_offset: u64,
        timed_out: bool,
    ) -> AppError {
        terminate_child(child, Duration::from_secs(2));
        let tail = read_log_tail(&self.log_file, log_offset);
        let gateway = format!("127.0.0.1:{}", config.port);
        let mut addresses = vec![gateway.as_str()];
        if let Some(team) = config.team_listen.as_deref() {
            addresses.push(team);
            if let Some((host, _)) = team.rsplit_once(':') {
                addresses.push(host);
            }
        }
        if let Some(mut error) = AppError::from_admin_stderr(&tail, &addresses) {
            if let Some(setting) = listen_setting(&error.reason, config.team_listen.is_some()) {
                error.detail = Some(setting.to_owned());
            }
            return error;
        }
        if timed_out {
            AppError::timeout("serve_start_timeout")
        } else {
            AppError::unavailable("serve_exited")
        }
    }
}

enum Recorded {
    Healthy(Running),
    Unhealthy(u32),
}

/// Which setting a sidecar's failure to open an address comes from: `gateway_port` for the
/// loopback gateway, `team_listen` for the team sync listener. The gateway address is always
/// `127.0.0.1:<port>` built from a checked port, so a malformed address is the team one
/// whenever team sync is on. `None` for every other reason.
pub fn listen_setting(reason: &str, team_listen: bool) -> Option<&'static str> {
    match reason {
        "listen_failed" => Some("gateway_port"),
        "team_invalid_listen_address" | "team_listen_failed" | "team_address_in_use" => {
            Some("team_listen")
        }
        "invalid_listen" if team_listen => Some("team_listen"),
        "invalid_listen" => Some("gateway_port"),
        _ => None,
    }
}

fn status_of(running: &mut Running) -> ServeStatus {
    match running {
        Running::Stopped => ServeStatus::stopped(),
        Running::Owned {
            child,
            url,
            team_listen,
        } => ServeStatus {
            running: true,
            url: Some(url.clone()),
            pid: Some(child.id()),
            team_listen: team_listen.clone(),
        },
        Running::Attached {
            pid,
            url,
            team_listen,
        } => ServeStatus {
            running: true,
            url: Some(url.clone()),
            pid: Some(*pid),
            team_listen: team_listen.clone(),
        },
    }
}

fn read_pid_file(path: &Path) -> Option<PidFile> {
    let meta = fs::metadata(path).ok()?;
    if meta.len() > MAX_PID_FILE_BYTES {
        let _ = fs::remove_file(path);
        return None;
    }
    let bytes = fs::read(path).ok()?;
    match serde_json::from_slice::<PidFile>(&bytes) {
        Ok(file) if file.pid > 1 && i32::try_from(file.pid).is_ok() => Some(file),
        _ => {
            let _ = fs::remove_file(path);
            None
        }
    }
}

fn read_log_tail(path: &Path, offset: u64) -> Vec<u8> {
    let Ok(mut file) = fs::File::open(path) else {
        return Vec::new();
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let start = offset.max(len.saturating_sub(MAX_LOG_TAIL_BYTES));
    let mut out = Vec::new();
    if file.seek(SeekFrom::Start(start)).is_ok() {
        let _ = file.take(MAX_LOG_TAIL_BYTES).read_to_end(&mut out);
    }
    out
}

fn pid(pid: u32) -> Pid {
    Pid::from_raw(pid as i32)
}

/// Signalable by us and not a zombie.
fn alive(p: u32) -> bool {
    if kill(pid(p), None).is_err() {
        return false;
    }
    !ps_info(p).is_some_and(|(stat, _)| stat.starts_with('Z'))
}

/// `(stat, full command line)` from `ps`, or `None` when the pid does not exist.
fn ps_info(p: u32) -> Option<(String, String)> {
    let output = Command::new("/bin/ps")
        .args(["-ww", "-o", "stat=", "-o", "command=", "-p"])
        .arg(p.to_string())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.lines().find(|l| !l.trim().is_empty())?.trim_start();
    let (stat, command) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
    Some((stat.to_owned(), command.trim().to_owned()))
}

fn terminate_child(child: &mut Child, grace: Duration) {
    if !matches!(child.try_wait(), Ok(None)) {
        return;
    }
    let _ = kill(pid(child.id()), Signal::SIGTERM);
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        if !matches!(child.try_wait(), Ok(None)) {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = killpg(pid(child.id()), Signal::SIGKILL);
    let _ = child.kill();
    let _ = child.wait();
}

fn terminate_pid(p: u32, grace: Duration) {
    if kill(pid(p), Signal::SIGTERM).is_err() {
        return;
    }
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        if !alive(p) {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    // The sidecar leads its own process group (spawned with process_group(0)).
    let _ = killpg(pid(p), Signal::SIGKILL);
    let _ = kill(pid(p), Signal::SIGKILL);
}

/// The port of an `http://127.0.0.1:<port>` (or `localhost`) URL; anything else is refused,
/// so the core never probes a non-loopback address.
pub fn loopback_port(url: &str) -> Option<u16> {
    let rest = url.strip_prefix("http://")?;
    let host_port = rest.strip_suffix('/').unwrap_or(rest);
    let (host, port) = host_port.rsplit_once(':')?;
    if host != "127.0.0.1" && host != "localhost" {
        return None;
    }
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    port.parse::<u16>().ok().filter(|p| *p != 0)
}

/// The answer to `GET /healthz`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Health {
    pub status: u16,
    pub server: Option<String>,
}

impl Health {
    pub fn is_zeropw(&self) -> bool {
        self.status == 200
            && self
                .server
                .as_deref()
                .is_some_and(|s| s.trim().starts_with(SERVER_HEADER))
    }
}

/// `GET /healthz` on `127.0.0.1:<port>` with a plain `TcpStream`.
pub fn healthz(port: u16, timeout: Duration) -> io::Result<Health> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    // One write, so the server sees the whole request in one read.
    let request =
        format!("GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut head = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 16 * 1024 {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => head.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            // A reset after the status line arrived still leaves a usable answer.
            Err(_) if !head.is_empty() => break,
            Err(e) => return Err(e),
        }
    }
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|_| version.starts_with("HTTP/1."))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "not an HTTP response"))?;
    let server = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("server"))
        .map(|(_, value)| value.trim().to_owned());
    Ok(Health { status, server })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn loopback_urls_only() {
        assert_eq!(loopback_port("http://127.0.0.1:47380"), Some(47380));
        assert_eq!(loopback_port("http://127.0.0.1:47380/"), Some(47380));
        assert_eq!(loopback_port("http://localhost:1"), Some(1));
        for bad in [
            "https://127.0.0.1:47380",
            "http://10.0.0.1:47380",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:+80",
            "http://127.0.0.1:70000",
            "http://user@127.0.0.1:80",
            "http://127.0.0.1.evil:80",
        ] {
            assert_eq!(loopback_port(bad), None, "{bad}");
        }
    }

    fn one_shot_server(response: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = s.write_all(response.as_bytes());
            }
        });
        port
    }

    #[test]
    fn healthz_reads_status_and_server_header() {
        let port = one_shot_server(
            "HTTP/1.0 200 OK\r\nServer: zeropw-prototype \r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}",
        );
        let h = healthz(port, Duration::from_secs(2)).unwrap();
        assert_eq!(h.status, 200);
        assert!(h.is_zeropw());

        let port = one_shot_server("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n");
        assert!(!healthz(port, Duration::from_secs(2)).unwrap().is_zeropw());
        let port = one_shot_server("HTTP/1.1 503 Busy\r\nserver: zeropw-prototype\r\n\r\n");
        assert!(!healthz(port, Duration::from_secs(2)).unwrap().is_zeropw());
        let port = one_shot_server("SSH-2.0-OpenSSH\r\n\r\n");
        assert!(healthz(port, Duration::from_secs(2)).is_err());
    }

    #[test]
    fn healthz_on_a_closed_port_fails() {
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        assert!(healthz(port, Duration::from_millis(500)).is_err());
    }

    #[test]
    fn status_without_a_sidecar_is_stopped_and_stale_pid_files_are_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(dir.path(), dir.path().join("bin"));
        let sup = ServeSupervisor::new(&paths);
        assert_eq!(sup.status(), ServeStatus::stopped());
        // A pid file naming a process that is not our serve is ignored and removed.
        fs::write(
            paths.serve_pid_file(),
            format!(
                r#"{{"pid":{},"url":"http://127.0.0.1:9","started_at":0}}"#,
                std::process::id()
            ),
        )
        .unwrap();
        assert_eq!(sup.attach(), ServeStatus::stopped());
        assert!(!paths.serve_pid_file().exists());
        fs::write(paths.serve_pid_file(), b"garbage").unwrap();
        assert_eq!(sup.attach(), ServeStatus::stopped());
        assert!(!paths.serve_pid_file().exists());
        assert_eq!(sup.stop(), ServeStatus::stopped());
    }

    #[test]
    fn listen_failures_name_their_setting() {
        assert_eq!(listen_setting("listen_failed", true), Some("gateway_port"));
        assert_eq!(listen_setting("listen_failed", false), Some("gateway_port"));
        for team in [
            "team_invalid_listen_address",
            "team_listen_failed",
            "team_address_in_use",
        ] {
            assert_eq!(listen_setting(team, true), Some("team_listen"), "{team}");
        }
        assert_eq!(listen_setting("invalid_listen", true), Some("team_listen"));
        assert_eq!(
            listen_setting("invalid_listen", false),
            Some("gateway_port")
        );
        assert_eq!(listen_setting("state_missing", true), None);
        assert_eq!(listen_setting("serve_exited", true), None);
    }

    #[test]
    fn ps_info_sees_this_process() {
        let (stat, command) = ps_info(std::process::id()).unwrap();
        assert!(!stat.is_empty());
        assert!(!command.is_empty());
        assert!(alive(std::process::id()));
    }
}
