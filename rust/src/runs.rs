//! Secret-free execution registry; port of `zeropw.runs`.
//! Child processes receive only the explicitly supplied environment. Output is
//! bounded and withheld until the finish audit succeeds; cancellation targets
//! the child's own process group, never the coordinator's process group.

use crate::{audit::RecordArgs, context::Context, errors::Error, store::iso};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE},
};
use rand::RngCore;
use rustix::process::{Pid, Signal, kill_process, kill_process_group};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::io::{ErrorKind, Read};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

pub const CAPTURE_LIMIT: usize = 256 * 1024;
pub const READ_CHUNK: usize = 64 * 1024;
pub const TERMINATE_GRACE_SECONDS: f64 = 2.0;
pub const FINALIZE_WAIT_SECONDS: f64 = 10.0;
pub const MIN_PATTERN_LENGTH: usize = 8;
pub const MAX_RETAINED_RUNS: usize = 1000;
pub const BLOCKED_MARKER: &str = "[blocked: output contained authentication material]";
pub const QUEUED: &str = "queued";
pub const RUNNING: &str = "running";
pub const COMPLETED: &str = "completed";
pub const FAILED: &str = "failed";
pub const CANCELLED: &str = "cancelled";

// The helper is shipped alongside the trusted executable. During `cargo test`
// integration binaries live under `target/{debug,release}/deps`, so check
// their parent too. Never resolve it through the agent-controlled PATH.
fn session_helper() -> std::io::Result<PathBuf> {
    let executable = std::env::current_exe()?;
    let directory = executable
        .parent()
        .ok_or_else(|| std::io::Error::other("no executable directory"))?;
    let sibling = directory.join("zeropw_session");
    if sibling.is_file() {
        return Ok(sibling);
    }
    let parent = directory
        .parent()
        .ok_or_else(|| std::io::Error::other("no parent directory"))?;
    let nearby = parent.join("zeropw_session");
    if nearby.is_file() {
        return Ok(nearby);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "zeropw_session helper missing",
    ))
}

fn wait_for_session_exec(listener: &UnixListener) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                if stream.set_nonblocking(false).is_err() {
                    return false;
                }
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut byte = [0];
                // The helper confirms setsid before exec. CLOEXEC then closes
                // the socket on exec; macOS may report a reset rather than EOF
                // if the target exits before accept. An explicit F is failure.
                if !matches!(stream.read(&mut byte), Ok(1)) || byte != *b"R" {
                    return false;
                }
                return match stream.read(&mut byte) {
                    Ok(0) => true,
                    Err(e) if e.kind() == ErrorKind::ConnectionReset => true,
                    _ => false,
                };
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(_) => return false,
        }
    }
}
pub const BLOCKED: &str = "blocked";
pub const STATES: &[&str] = &[QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED, BLOCKED];
pub const ACTIVE_STATES: &[&str] = &[QUEUED, RUNNING];
pub const TERMINAL_STATES: &[&str] = &[COMPLETED, FAILED, CANCELLED, BLOCKED];

/// `runs.credential_patterns`, including all three base64 alignments.
pub fn credential_patterns(secret: &[u8]) -> Vec<Vec<u8>> {
    credential_patterns_with_minimum(secret, MIN_PATTERN_LENGTH)
}

pub fn credential_patterns_with_minimum(secret: &[u8], minimum: usize) -> Vec<Vec<u8>> {
    if secret.is_empty() {
        return Vec::new();
    }
    let mut patterns = vec![secret.to_vec()];
    let mut add = |value: Vec<u8>| {
        if value.len() >= minimum && !patterns.contains(&value) {
            patterns.push(value);
        }
    };
    // `bytes.strip()`: CPython's `Py_ISSPACE` set, which includes `\x0b`.
    let space = |b: &u8| crate::pystr::is_int_space(char::from(*b));
    let start = secret
        .iter()
        .position(|b| !space(b))
        .unwrap_or(secret.len());
    let end = secret
        .iter()
        .rposition(|b| !space(b))
        .map_or(start, |i| i + 1);
    let stripped = secret.get(start..end).unwrap_or_default();
    if !stripped.is_empty() && stripped != secret {
        add(stripped.to_vec());
    }
    for encoder in [&STANDARD, &URL_SAFE] {
        let exact = encoder.encode(secret);
        add(exact.as_bytes().to_vec());
        add(exact.trim_end_matches('=').as_bytes().to_vec());
        for shift in 0..3 {
            let mut shifted = vec![0; shift];
            shifted.extend_from_slice(secret);
            let encoded = encoder.encode(&shifted);
            shifted.zeroize();
            let encoded = encoded.trim_end_matches('=');
            let head = if shift == 0 { 0 } else { 4 };
            let tail = [0, 2, 3][(shift + secret.len()) % 3];
            let end = encoded.len().saturating_sub(tail);
            add(encoded
                .as_bytes()
                .get(head..end)
                .unwrap_or_default()
                .to_vec());
        }
    }
    let hexed = hex::encode(secret);
    add(hexed.as_bytes().to_vec());
    add(hexed.to_uppercase().into_bytes());
    let quote = |plus: bool| -> Vec<u8> {
        secret
            .iter()
            .flat_map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(b) {
                    vec![*b]
                } else if plus && *b == b' ' {
                    vec![b'+']
                } else {
                    format!("%{b:02X}").into_bytes()
                }
            })
            .collect()
    };
    add(quote(false));
    add(quote(true));
    let alnum: String = secret
        .iter()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                char::from(*b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    add(alnum.as_bytes().to_vec());
    add(alnum.to_ascii_lowercase().into_bytes());
    let full: String = secret.iter().map(|b| format!("%{b:02X}")).collect();
    add(full.as_bytes().to_vec());
    add(full.to_ascii_lowercase().into_bytes());
    patterns
}

pub fn contains_sensitive(data: &[u8], patterns: &[Vec<u8>]) -> bool {
    patterns
        .iter()
        .any(|p| !p.is_empty() && data.windows(p.len()).any(|w| w == p))
}

/// Snapshot of a run. Internal paths, arguments and environment are not retained.
#[derive(Clone)]
pub struct Run {
    pub id: String,
    pub caller: String,
    pub connection: String,
    pub grant: String,
    pub kind: String,
    pub program: String,
    pub request_id: Option<String>,
    pub input_digest: String,
    pub created_at: String,
    pub target: Option<String>,
    pub policy_version: Option<i64>,
    pub state: String,
    pub reason: Option<String>,
    pub exit_code: Option<i32>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub cancel_requested: bool,
    pub cancel_reason: Option<String>,
    pub timed_out: bool,
}
impl Run {
    pub fn public_view(&self) -> Value {
        json!({"run_id":self.id,"connection":self.connection,"state":self.state,"reason":self.reason,
        "exit_code":self.exit_code,"stdout":String::from_utf8_lossy(&self.stdout),"stderr":String::from_utf8_lossy(&self.stderr),
        "started_at":self.started_at,"finished_at":self.finished_at,"truncated":self.stdout_truncated || self.stderr_truncated,
        "stdout_truncated":self.stdout_truncated,"stderr_truncated":self.stderr_truncated})
    }
}
struct Entry {
    run: Mutex<Run>,
    child: Mutex<Option<Child>>,
    done: Mutex<bool>,
    changed: Condvar,
    // Finalization calls synchronous audit listeners. Keep the published run
    // active until that call returns, but do not allow a listener to cancel
    // and wait for the very finalization it is running inside.
    finalizing: AtomicBool,
    finalizer: Mutex<Option<thread::ThreadId>>,
    // `run.thread`: joined (bounded) by `shutdown`.
    supervisor: Mutex<Option<thread::JoinHandle<()>>>,
}
#[derive(Default)]
struct RegistryState {
    runs: HashMap<String, Arc<Entry>>,
    order: VecDeque<String>,
    by_request: HashMap<(String, String), String>,
}
pub type Cleanup = Box<dyn FnOnce() + Send + 'static>;
pub struct RunRegistry {
    // Context owns installed registries; a weak back-reference avoids a cycle.
    ctx: Weak<Context>,
    // A directly constructed registry owns its Context, matching Python's
    // `RunRegistry(ctx)`. Only a Context-installed registry omits this owner.
    _direct_context: Option<Arc<Context>>,
    clock: crate::clock::Clock,
    pub capture_limit: usize,
    pub grace_seconds: f64,
    state: Mutex<RegistryState>,
}

pub fn registry(ctx: &Context) -> Option<Arc<RunRegistry>> {
    ctx.runs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()?
        .downcast_ref::<Arc<RunRegistry>>()
        .cloned()
}
pub fn install(ctx: Arc<Context>) -> Arc<RunRegistry> {
    let mut slot = ctx.runs.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(r) = slot
        .as_ref()
        .and_then(|v| v.downcast_ref::<Arc<RunRegistry>>())
        .cloned()
    {
        return r;
    }
    let r = RunRegistry::new_installed(ctx.clone(), CAPTURE_LIMIT, TERMINATE_GRACE_SECONDS);
    *slot = Some(Box::new(r.clone()));
    let weak = Arc::downgrade(&r);
    ctx.policy.on_revoke(move |kind, grant| {
        if let Some(r) = weak.upgrade() {
            r.on_revoke(kind, grant);
        }
    });
    r
}
impl RunRegistry {
    pub fn new(ctx: Arc<Context>, capture_limit: usize, grace_seconds: f64) -> Arc<Self> {
        Self::build(ctx, capture_limit, grace_seconds, true)
    }
    fn new_installed(ctx: Arc<Context>, capture_limit: usize, grace_seconds: f64) -> Arc<Self> {
        Self::build(ctx, capture_limit, grace_seconds, false)
    }
    fn build(
        ctx: Arc<Context>,
        capture_limit: usize,
        grace_seconds: f64,
        direct: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            clock: ctx.clock.clone(),
            ctx: Arc::downgrade(&ctx),
            _direct_context: direct.then_some(ctx),
            capture_limit,
            grace_seconds,
            state: Mutex::new(RegistryState::default()),
        })
    }
    fn entry(&self, id: &str) -> Result<Arc<Entry>, Error> {
        self.state
            .lock()
            .unwrap()
            .runs
            .get(id)
            .cloned()
            .ok_or_else(|| Error::not_found("run_not_found"))
    }
    pub fn find_by_request(
        &self,
        caller: &str,
        request_id: &str,
        digest: &str,
    ) -> Result<Option<Run>, Error> {
        let state = self.state.lock().unwrap();
        let entry = state
            .by_request
            .get(&(caller.into(), request_id.into()))
            .and_then(|id| state.runs.get(id));
        match entry {
            Some(e) => {
                let run = e.run.lock().unwrap();
                if run.input_digest != digest {
                    return Err(Error::invalid_input("request_id_reused"));
                }
                Ok(Some(run.clone()))
            }
            None => Ok(None),
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &self,
        caller: &str,
        connection: &str,
        grant: &str,
        kind: &str,
        program: &str,
        request_id: Option<&str>,
        input_digest: &str,
        target: Option<&str>,
        policy_version: Option<i64>,
    ) -> Run {
        let mut state = self.state.lock().unwrap();
        self.create_locked(
            &mut state,
            caller,
            connection,
            grant,
            kind,
            program,
            request_id,
            input_digest,
            target,
            policy_version,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn find_or_create(
        &self,
        caller: &str,
        connection: &str,
        grant: &str,
        kind: &str,
        program: &str,
        request_id: Option<&str>,
        input_digest: &str,
        target: Option<&str>,
        policy_version: Option<i64>,
    ) -> Result<(Run, bool), Error> {
        let mut state = self.state.lock().unwrap();
        if let Some(request_id) = request_id
            && let Some(entry) = state
                .by_request
                .get(&(caller.into(), request_id.into()))
                .and_then(|id| state.runs.get(id))
        {
            let run = entry.run.lock().unwrap();
            if run.input_digest != input_digest {
                return Err(Error::invalid_input("request_id_reused"));
            }
            return Ok((run.clone(), false));
        }
        Ok((
            self.create_locked(
                &mut state,
                caller,
                connection,
                grant,
                kind,
                program,
                request_id,
                input_digest,
                target,
                policy_version,
            ),
            true,
        ))
    }
    #[allow(clippy::too_many_arguments)]
    fn create_locked(
        &self,
        state: &mut RegistryState,
        caller: &str,
        connection: &str,
        grant: &str,
        kind: &str,
        program: &str,
        request_id: Option<&str>,
        input_digest: &str,
        target: Option<&str>,
        policy_version: Option<i64>,
    ) -> Run {
        let id = loop {
            let mut bytes = [0; 8];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            let id = format!("r-{}", hex::encode(bytes));
            if !state.runs.contains_key(&id) {
                break id;
            }
        };
        let run = Run {
            id: id.clone(),
            caller: caller.into(),
            connection: connection.into(),
            grant: grant.into(),
            kind: kind.into(),
            program: program.into(),
            request_id: request_id.map(str::to_string),
            input_digest: input_digest.into(),
            created_at: iso(Some((self.clock)())),
            target: target.map(str::to_string),
            policy_version,
            state: QUEUED.into(),
            reason: None,
            exit_code: None,
            started_at: None,
            finished_at: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            cancel_requested: false,
            cancel_reason: None,
            timed_out: false,
        };
        state.runs.insert(
            id.clone(),
            Arc::new(Entry {
                run: Mutex::new(run.clone()),
                child: Mutex::new(None),
                done: Mutex::new(false),
                changed: Condvar::new(),
                finalizing: AtomicBool::new(false),
                finalizer: Mutex::new(None),
                supervisor: Mutex::new(None),
            }),
        );
        state.order.push_back(id.clone());
        if let Some(request_id) = request_id {
            state
                .by_request
                .insert((caller.into(), request_id.into()), id);
        }
        let candidates: Vec<_> = state.order.iter().cloned().collect();
        for id in candidates {
            if state.runs.len() <= MAX_RETAINED_RUNS {
                break;
            }
            let victim = state
                .runs
                .get(&id)
                .filter(|e| TERMINAL_STATES.contains(&e.run.lock().unwrap().state.as_str()))
                .cloned();
            if let Some(entry) = victim {
                let r = entry.run.lock().unwrap();
                if let Some(req) = &r.request_id {
                    let key = (r.caller.clone(), req.clone());
                    if state.by_request.get(&key) == Some(&id) {
                        state.by_request.remove(&key);
                    }
                }
                state.runs.remove(&id);
                state.order.retain(|v| v != &id);
            }
        }
        run
    }
    fn record(
        &self,
        event: &str,
        run: &Run,
        result: &str,
        reason: Option<&str>,
        extra: Vec<(&str, Value)>,
    ) -> Result<(), Error> {
        self.ctx
            .upgrade()
            .ok_or_else(|| Error::state("context_closed"))?
            .audit
            .record(
                event,
                RecordArgs {
                    caller: Some(&run.caller),
                    connection: Some(&run.connection),
                    target: run.target.as_deref(),
                    run_id: Some(&run.id),
                    request_id: run.request_id.as_deref(),
                    action: Some("exec"),
                    result: Some(result),
                    reason,
                    policy_version: run.policy_version,
                    extra,
                },
            )
            .map(|_| ())
    }
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        self: &Arc<Self>,
        run: &Run,
        argv: &[String],
        env: &HashMap<String, String>,
        cwd: &Path,
        sensitive: &[Vec<u8>],
        cleanup: Option<Cleanup>,
        timeout: Option<f64>,
    ) -> Result<Run, Error> {
        let entry = self.entry(&run.id)?;
        let before = entry.run.lock().unwrap().clone();
        if before.state != QUEUED {
            clean(cleanup);
            return Ok(before);
        }
        // Python's registry holds its context strongly. Hold it for the whole
        // start (and the supervisor) so a run is never left queued because
        // the last other owner dropped the context mid-start.
        let Some(ctx) = self.ctx.upgrade() else {
            self.finalize(&entry, Outcome::failed("audit_unavailable"), false);
            clean(cleanup);
            return Err(Error::state("context_closed"));
        };
        if let Err(e) = self.record(
            "run_start",
            &before,
            "ok",
            None,
            vec![
                ("program", json!(before.program)),
                ("kind", json!(before.kind)),
                ("grant", json!(before.grant)),
            ],
        ) {
            self.finalize(&entry, Outcome::failed("audit_unavailable"), false);
            clean(cleanup);
            return Err(e);
        }
        let mut current = entry.run.lock().unwrap();
        if current.state != QUEUED || current.cancel_requested {
            let out = current.clone();
            drop(current);
            clean(cleanup);
            return Ok(out);
        }
        let Some(_) = argv.first() else {
            drop(current);
            self.finalize(&entry, Outcome::failed("spawn_failed"), true);
            clean(cleanup);
            return self.get(&run.id, &run.caller);
        };
        // The ACK socket is an internal one-shot control channel, not the
        // configured SSH signer socket. Own a short private directory so a
        // missing or long user socket_dir cannot break HTTP-only exec runs.
        let setup = (|| -> std::io::Result<(PathBuf, tempfile::TempDir, UnixListener)> {
            let helper = session_helper()?;
            let ack_dir = tempfile::Builder::new()
                .prefix("zp-ack-")
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir_in("/tmp")?;
            let ack_path = ack_dir.path().join("ack");
            let listener = UnixListener::bind(&ack_path)?;
            listener.set_nonblocking(true)?;
            Ok((helper, ack_dir, listener))
        })();
        let (helper, ack_dir, listener) = match setup {
            Ok(parts) => parts,
            Err(_) => {
                drop(current);
                self.finalize(&entry, Outcome::failed("spawn_failed"), true);
                clean(cleanup);
                return self.get(&run.id, &run.caller);
            }
        };
        let ack_path = ack_dir.path().join("ack");
        let spawned = Command::new(helper)
            .arg(&ack_path)
            .args(argv)
            .env_clear()
            .envs(env)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        let mut child = match spawned {
            Ok(c) => c,
            Err(_) => {
                drop(current);
                self.finalize(&entry, Outcome::failed("spawn_failed"), true);
                clean(cleanup);
                return self.get(&run.id, &run.caller);
            }
        };
        let acknowledged = wait_for_session_exec(&listener);
        drop(listener);
        drop(ack_dir);
        if !acknowledged {
            // If exec happened but acknowledgement was lost, descendants may
            // already exist in the new group. Before setsid this group id
            // cannot identify the coordinator's group, so fallback is safe.
            if let Ok(raw) = i32::try_from(child.id())
                && let Some(pid) = Pid::from_raw(raw)
            {
                let _ = kill_process_group(pid, Signal::KILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            drop(current);
            self.finalize(&entry, Outcome::failed("spawn_failed"), true);
            clean(cleanup);
            return self.get(&run.id, &run.caller);
        }
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        *entry.child.lock().unwrap() = Some(child);
        current.state = RUNNING.into();
        current.started_at = Some(iso(Some((self.clock)())));
        drop(current);
        let patterns: Vec<_> = sensitive
            .iter()
            .flat_map(|v| credential_patterns(v))
            .collect();
        let registry = self.clone();
        let entry_thread = entry.clone();
        let timeout = timeout.unwrap_or(ctx.config.exec_timeout_seconds);
        let supervisor = thread::spawn(move || {
            let _keep_context_alive = ctx;
            registry.supervise(entry_thread, stdout, stderr, timeout, patterns, cleanup)
        });
        *entry.supervisor.lock().unwrap_or_else(|e| e.into_inner()) = Some(supervisor);
        self.get(&run.id, &run.caller)
    }
    fn supervise(
        self: Arc<Self>,
        entry: Arc<Entry>,
        stdout: Option<std::process::ChildStdout>,
        stderr: Option<std::process::ChildStderr>,
        timeout: f64,
        mut patterns: Vec<Vec<u8>>,
        cleanup: Option<Cleanup>,
    ) {
        let stop = Arc::new(AtomicBool::new(false));
        let out = pump(stdout, self.capture_limit, stop.clone());
        let err = pump(stderr, self.capture_limit, stop.clone());
        let began = Instant::now();
        let status = loop {
            let status = {
                let mut guard = entry.child.lock().unwrap();
                guard.as_mut().and_then(|c| c.try_wait().ok()).flatten()
            };
            if let Some(status) = status {
                break Some(status);
            }
            if timeout.is_finite() && timeout > 0.0 && began.elapsed().as_secs_f64() >= timeout {
                entry.run.lock().unwrap().timed_out = true;
                self.terminate(std::slice::from_ref(&entry));
                let mut child = entry.child.lock().unwrap();
                break child.as_mut().and_then(|c| c.wait().ok());
            }
            thread::sleep(Duration::from_millis(10));
        };
        // `for pump in pumps: pump.join(FINALIZE_WAIT_SECONDS)`: each reader
        // gets its own wait.
        let (stdout, out_trunc) = out
            .recv_timeout(seconds(FINALIZE_WAIT_SECONDS))
            .unwrap_or_default();
        let (stderr, err_trunc) = err
            .recv_timeout(seconds(FINALIZE_WAIT_SECONDS))
            .unwrap_or_default();
        stop.store(true, Ordering::Release);
        let snapshot = entry.run.lock().unwrap().clone();
        let (state, reason) =
            if contains_sensitive(&stdout, &patterns) || contains_sensitive(&stderr, &patterns) {
                (BLOCKED, Some("output_credential_blocked".to_string()))
            } else if snapshot.cancel_requested {
                (
                    CANCELLED,
                    Some(snapshot.cancel_reason.unwrap_or_else(|| "cancelled".into())),
                )
            } else if snapshot.timed_out {
                (FAILED, Some("timeout".into()))
            } else if status.is_none() {
                (FAILED, Some("internal_error".into()))
            } else {
                (COMPLETED, None)
            };
        let mut outcome = Outcome {
            state: state.into(),
            reason,
            exit_code: status.and_then(|s| s.code().or_else(|| s.signal().map(|v| -v))),
            stdout,
            stderr,
            out_trunc,
            err_trunc,
        };
        if state == BLOCKED {
            outcome.stdout.zeroize();
            outcome.stderr.zeroize();
            outcome.stdout = BLOCKED_MARKER.as_bytes().to_vec();
            outcome.stderr = outcome.stdout.clone();
            outcome.out_trunc = false;
            outcome.err_trunc = false;
        }
        patterns.zeroize();
        clean(cleanup);
        self.finalize(&entry, outcome, true);
    }
    fn finalize(&self, entry: &Entry, mut out: Outcome, record: bool) {
        let snapshot = {
            let run = entry.run.lock().unwrap();
            if TERMINAL_STATES.contains(&run.state.as_str()) {
                return;
            }
            if entry.finalizing.swap(true, Ordering::AcqRel) {
                return;
            }
            *entry.finalizer.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(thread::current().id());
            let mut staged = run.clone();
            staged.state = out.state.clone();
            staged.reason = out.reason.clone();
            staged.exit_code = out.exit_code;
            staged.finished_at = Some(iso(Some((self.clock)())));
            staged
        };
        let result = match out.state.as_str() {
            COMPLETED => "ok",
            CANCELLED => "cancelled",
            BLOCKED => "blocked",
            _ => "failed",
        };
        let audit_ok = !record
            || self
                .record(
                    "run_finish",
                    &snapshot,
                    result,
                    out.reason.as_deref(),
                    vec![
                        ("program", json!(snapshot.program)),
                        ("exit_code", json!(out.exit_code)),
                        ("run_state", json!(out.state)),
                        ("bytes", json!(out.stdout.len() + out.stderr.len())),
                    ],
                )
                .is_ok();
        {
            let mut run = entry.run.lock().unwrap();
            run.state = if audit_ok { out.state } else { FAILED.into() };
            run.reason = if audit_ok {
                out.reason
            } else {
                Some("audit_unavailable".into())
            };
            run.exit_code = out.exit_code;
            run.finished_at = snapshot.finished_at;
            if audit_ok {
                run.stdout = std::mem::take(&mut out.stdout);
                run.stderr = std::mem::take(&mut out.stderr);
                run.stdout_truncated = out.out_trunc;
                run.stderr_truncated = out.err_trunc;
            } else {
                out.stdout.zeroize();
                out.stderr.zeroize();
            }
        }
        *entry.child.lock().unwrap() = None;
        *entry.done.lock().unwrap() = true;
        entry.changed.notify_all();
    }
    pub fn fail(&self, run: &Run, reason: &str) -> Run {
        if let Ok(entry) = self.entry(&run.id) {
            self.finalize(&entry, Outcome::failed(reason), true);
            return entry.run.lock().unwrap().clone();
        }
        run.clone()
    }
    pub fn get(&self, id: &str, caller: &str) -> Result<Run, Error> {
        let e = self.entry(id)?;
        let run = e.run.lock().unwrap();
        if run.caller != caller {
            return Err(Error::not_found("run_not_found"));
        }
        Ok(run.clone())
    }
    pub fn view(&self, run: &Run) -> Value {
        self.get(&run.id, &run.caller)
            .unwrap_or_else(|_| run.clone())
            .public_view()
    }
    pub fn wait(&self, run: &Run, timeout: Option<f64>) -> Run {
        if let Ok(e) = self.entry(&run.id) {
            let done = e.done.lock().unwrap();
            if let Some(timeout) = timeout {
                let _ = e
                    .changed
                    .wait_timeout_while(done, seconds(timeout), |d| !*d)
                    .unwrap();
            } else {
                drop(e.changed.wait_while(done, |d| !*d).unwrap());
            }
            return e.run.lock().unwrap().clone();
        }
        run.clone()
    }
    pub fn active_runs(&self) -> Vec<Run> {
        let s = self.state.lock().unwrap();
        s.order
            .iter()
            .filter_map(|id| s.runs.get(id))
            .filter_map(|e| {
                let r = e.run.lock().unwrap();
                (ACTIVE_STATES.contains(&r.state.as_str()) && !e.finalizing.load(Ordering::Acquire))
                    .then(|| r.clone())
            })
            .collect()
    }
    pub fn cancel(&self, id: &str, caller: &str, reason: &str) -> Result<Run, Error> {
        let run = self.get(id, caller)?;
        self.cancel_runs(&[run], reason);
        self.get(id, caller)
    }
    pub fn cancel_all(&self, reason: &str, grant_id: Option<&str>) -> usize {
        let runs: Vec<_> = self
            .active_runs()
            .into_iter()
            .filter(|r| grant_id.is_none_or(|g| r.grant == g))
            .collect();
        let count = runs.len();
        self.cancel_runs(&runs, reason);
        count
    }
    pub fn on_revoke(&self, kind: &str, grant: Option<&str>) {
        let reason = match kind {
            "stop" => "global_stop",
            "restore" => "restore_pending",
            "connection" => "connection_changed",
            "principal" => "principal_disabled",
            _ => "grant_revoked",
        };
        // `if kind == "grant" and grant_id`: an empty id is falsy and cancels
        // every active run.
        let grant = grant.filter(|g| kind == "grant" && !g.is_empty());
        self.cancel_all(reason, grant);
    }
    fn cancel_runs(&self, runs: &[Run], reason: &str) {
        let mut running = Vec::new();
        for r in runs {
            if let Ok(e) = self.entry(&r.id) {
                let (run, fresh) = {
                    let mut run = e.run.lock().unwrap();
                    if !ACTIVE_STATES.contains(&run.state.as_str()) {
                        continue;
                    }
                    if e.finalizing.load(Ordering::Acquire) {
                        // Python publishes the terminal state before it
                        // records `run_finish`: a finishing run is not
                        // cancelled, and the caller then sees it terminal.
                        // Wait for that publication, except from inside the
                        // finalization itself (an audit listener).
                        let finalizer = *e.finalizer.lock().unwrap_or_else(|e| e.into_inner());
                        if finalizer != Some(thread::current().id()) {
                            running.push((e.clone(), false));
                        }
                        continue;
                    }
                    let fresh = !run.cancel_requested;
                    run.cancel_requested = true;
                    if fresh {
                        run.cancel_reason = Some(reason.into());
                    }
                    (run.clone(), fresh)
                };
                if fresh {
                    let _ = self.record(
                        "run_cancel",
                        &run,
                        "ok",
                        Some(reason),
                        vec![
                            ("program", json!(run.program)),
                            ("run_state", json!(run.state)),
                        ],
                    );
                }
                if run.state == QUEUED {
                    self.finalize(
                        &e,
                        Outcome {
                            state: CANCELLED.into(),
                            reason: Some(reason.into()),
                            ..Outcome::failed(reason)
                        },
                        true,
                    );
                } else {
                    running.push((e, true));
                }
            }
        }
        let signalled: Vec<_> = running
            .iter()
            .filter(|(_, signal)| *signal)
            .map(|(e, _)| e.clone())
            .collect();
        self.terminate(&signalled);
        for (e, _) in running {
            let done = e.done.lock().unwrap();
            let _ = e
                .changed
                .wait_timeout_while(done, seconds(FINALIZE_WAIT_SECONDS), |d| !*d)
                .unwrap();
        }
    }
    fn signal(entry: &Entry, signal: Signal) {
        let mut lock = entry.child.lock().unwrap();
        let Some(child) = lock.as_mut() else { return };
        if !matches!(child.try_wait(), Ok(None)) {
            return;
        }
        if let Ok(raw) = i32::try_from(child.id())
            && raw > 1
            && let Some(pid) = Pid::from_raw(raw)
            && kill_process_group(pid, signal).is_err()
        {
            let _ = kill_process(pid, signal);
        }
    }
    fn terminate(&self, entries: &[Arc<Entry>]) {
        for e in entries {
            Self::signal(e, Signal::TERM);
        }
        let start = Instant::now();
        loop {
            let alive = entries.iter().any(|e| {
                e.child
                    .lock()
                    .unwrap()
                    .as_mut()
                    .is_some_and(|c| matches!(c.try_wait(), Ok(None)))
            });
            if !alive {
                return;
            }
            if start.elapsed() >= seconds(self.grace_seconds) {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        for e in entries {
            Self::signal(e, Signal::KILL);
        }
    }
    /// `RunRegistry.shutdown`: cancel every active run, then join every
    /// supervisor (each for up to `FINALIZE_WAIT_SECONDS`), so runs that were
    /// already finishing are terminal and cleaned up when it returns.
    pub fn shutdown(&self, reason: &str) {
        self.cancel_all(reason, None);
        let entries: Vec<_> = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state
                .order
                .iter()
                .filter_map(|id| state.runs.get(id).cloned())
                .collect()
        };
        for entry in entries {
            let handle = entry
                .supervisor
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            let Some(handle) = handle else { continue };
            if handle.thread().id() == thread::current().id() {
                continue;
            }
            let deadline = Instant::now() + seconds(FINALIZE_WAIT_SECONDS);
            while !handle.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if handle.is_finished() {
                let _ = handle.join();
            }
        }
    }
}
struct Outcome {
    state: String,
    reason: Option<String>,
    exit_code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    out_trunc: bool,
    err_trunc: bool,
}
impl Outcome {
    fn failed(reason: &str) -> Self {
        Self {
            state: FAILED.into(),
            reason: Some(reason.into()),
            exit_code: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            out_trunc: false,
            err_trunc: false,
        }
    }
}
fn clean(cleanup: Option<Cleanup>) {
    if let Some(cleanup) = cleanup {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(cleanup));
    }
}
fn seconds(value: f64) -> Duration {
    Duration::try_from_secs_f64(value.max(0.0)).unwrap_or(Duration::from_secs(86400 * 365))
}
fn pump<T: Read + AsFd + Send + 'static>(
    stream: Option<T>,
    limit: usize,
    stop: Arc<AtomicBool>,
) -> mpsc::Receiver<(Vec<u8>, bool)> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let Some(mut stream) = stream else {
            let _ = sender.send((Vec::new(), false));
            return;
        };
        let nonblocking = rustix::fs::fcntl_getfl(&stream).and_then(|flags| {
            rustix::fs::fcntl_setfl(&stream, flags | rustix::fs::OFlags::NONBLOCK)
        });
        if nonblocking.is_err() {
            let _ = sender.send((Vec::new(), false));
            return;
        }
        let mut buffer = Vec::new();
        let mut truncated = false;
        let mut chunk = vec![0; READ_CHUNK];
        while !stop.load(Ordering::Acquire) {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let take = n.min(limit.saturating_sub(buffer.len()));
                    buffer.extend_from_slice(&chunk[..take]);
                    truncated |= take < n;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        chunk.zeroize();
        let _ = sender.send((buffer, truncated));
    });
    receiver
}
