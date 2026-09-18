//! Port of `zeropw/context.py`: trusted process context -- state, KMS,
//! vault, policy, audit, handles, config.
//!
//! Directory layout rule: the state directory holds only trusted material
//! (KMS master key, vault, policy documents, handle key, admin credential,
//! audit log). The two directories that agent-controlled programs touch --
//! `run_dir` (the exec child's cwd/HOME/TMPDIR) and `socket_dir` (per-run
//! signer sockets) -- are never located inside, or derived from, the state
//! directory: a child could otherwise walk up from its working directory to
//! `kms/master.key` and the path itself would reveal where the trusted store
//! lives.
//!
//! ## `'static` sharing: why this module leaks
//!
//! `zeropw/context.py`'s `Context` is a plain object graph: `ctx.vault.kms`
//! and `ctx.kms` are literally the same Python object, and `ctx.vault.audit`
//! / `ctx.audit` likewise. The already-ported sibling modules this crate
//! builds on fix that sharing pattern as a borrow: `Audit<'a>`,
//! `Policy<'a>`, `Projects<'a>` and (this module's own) `Vault<'a>` all hold
//! a `&'a StateDir` (see `audit.rs`, `policy.rs`, `projects.rs`). For one
//! `Context` value to *own* the `StateDir`/`Audit`/`Projects`/`Kms` **and**
//! hand out live references to them from its own fields is a
//! self-referential struct -- not expressible in safe Rust without either
//! unsafe pinning machinery or changing those already-landed modules' public
//! signatures (out of this work unit's scope; `PORTING.md` says not to edit
//! them).
//!
//! `Context::initialize`/`Context::open` therefore allocate the
//! `StateDir`/`Audit`/`Projects`/`Kms` with `Box::leak`, which is ordinary
//! safe Rust, to get a `'static` lifetime that every dependent field
//! (`Vault<'static>`, `Policy<'static>`, `AdminCredential<'static>`) can
//! borrow from independently, exactly reproducing Python's shared-object-
//! identity graph. This is the same idiom `audit.rs`'s own tests already use
//! (`Box::leak(Box::new(state))`) to get a `'static` `Audit` for a
//! same-thread-reentrancy test; here it is load-bearing rather than a test
//! convenience. The trade-off is a real one: opening (or recovering) a state
//! directory leaks a small, fixed amount of memory (the `StateDir`/`Audit`/
//! `Projects` structs, and on `recover()` a new `Kms`) for the rest of the
//! process's life. This matches how every real caller uses `Context` --
//! one `Context` per admin-CLI invocation (which exits shortly after) or one
//! long-lived `Context` per server process (matching Python's own one-
//! `Context`-per-process model) -- so it is not a practical leak. Only
//! `Context::recover`'s repeated-recovery case is even theoretically
//! unbounded, and disaster recovery is an infrequent, operator-driven event
//! matching Python's own file-level trade-off there (the old master key file
//! is *renamed* aside, not deleted, on every recovery).

use std::any::Any;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{Map, Value, json};

use crate::audit::{Audit, RecordArgs};
use crate::clock::{self, Clock};
use crate::errors::Error;
use crate::handles::HandleIssuer;
use crate::kms::{Kms, LocalFileKms};
use crate::policy::Policy;
use crate::projects::Projects;
use crate::store::StateDir;
use crate::vault::{AdminCredential, Vault};

pub const HANDLE_KEY: &str = "policy/handle.key";
pub const KMS_FILE: &str = "kms/master.key";

/// Port of `context.Config`. `socket_dir`/`run_dir` are handed to
/// agent-controlled programs (signer socket path, child cwd/HOME/TMPDIR).
/// Leave them `None` to get fresh private temporary directories outside the
/// state store; an explicit value inside the state directory is refused by
/// `Context`.
///
/// Python's `Config` is a mutable `@dataclass` passed *by reference*, and
/// `Context._apply_config_defaults` writes the freshly created
/// `socket_dir`/`run_dir` back onto the caller's own `Config` object. Two
/// `Context`s built from the *same* `Config` instance therefore end up
/// sharing one `socket_dir` and one `run_dir` -- owned (i.e. removed on
/// `close()`) only by whichever `Context` created them first -- which is
/// exactly what `tests/test_team_sync.py`'s
/// `RemoteWideningCancelsRunningExecTestCase.setUp` (lines 608-613) and
/// `SessionRekeyTestCase.test_old_session_is_closed_and_replaced` (lines
/// 917-920) rely on: both construct two simulated nodes from one shared
/// `cfg` object. `Context::initialize`/`Context::open` here take `Config`
/// by value (moved into the `Context`), so every `Context` always gets its
/// own private temp dirs -- there is no way to reproduce the Python sharing
/// from this crate's API without changing that signature to `&mut Config`,
/// which would ripple into every call site in the crate, including
/// `signer.rs` and several test files outside this work unit's editable
/// files. Recorded in `DEVIATIONS.md` (finding E-R2-3) instead of changed,
/// so a second-half port of `zeropw.team.sync`/`membership` (which is what
/// actually exercises the two `test_team_sync.py` setups above) does not
/// assume Rust's per-`Context` isolation matches Python's shared-`Config`
/// node setup.
#[derive(Clone, Debug)]
pub struct Config {
    pub listen_host: String,
    pub listen_port: i64,
    pub socket_dir: Option<PathBuf>,
    pub run_dir: Option<PathBuf>,
    pub max_response_bytes: i64,
    pub upstream_timeout: f64,
    pub handle_ttl_seconds: i64,
    pub max_request_body_bytes: i64,
    pub exec_timeout_seconds: f64,
    /// Team sync (docs/team-sync.md section 6.6, section 14 item 1): `None`
    /// means "use the folded environment document's own
    /// settings.sync_interval_seconds"; tests override it to a short
    /// interval.
    pub team_sync_interval_seconds: Option<f64>,
    pub team_session_max_age_seconds: f64,
    pub team_dial_backoff: (f64, f64),
    /// Section 9's incident outbox retry (`TeamSync._poll_incident_outbox`):
    /// same shape as `team_dial_backoff`, kept separate since redelivering a
    /// queued incident to an admin peer is a different concern from
    /// reconnecting a dropped session.
    pub team_incident_retry_backoff: (f64, f64),
    /// Sections 4.4/7.4: once a node learns of a member's removal it stops
    /// sending to that member's session at once, but keeps the session open,
    /// receive-only, for this many seconds.
    pub team_removed_drain_seconds: f64,
    /// Overrides for `zeropw.intrusion.DetectorConfig`
    /// (docs/compromise-response.md §4.2). `None` means "use
    /// `DetectorConfig`'s own defaults".
    pub intrusion: Option<Value>,
    pub extra: Map<String, Value>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen_host: "127.0.0.1".to_string(),
            listen_port: 0,
            socket_dir: None,
            run_dir: None,
            max_response_bytes: 8 * 1024 * 1024,
            upstream_timeout: 30.0,
            handle_ttl_seconds: 900,
            max_request_body_bytes: 8 * 1024 * 1024,
            exec_timeout_seconds: 600.0,
            team_sync_interval_seconds: None,
            team_session_max_age_seconds: 600.0,
            team_dial_backoff: (5.0, 300.0),
            team_incident_retry_backoff: (5.0, 300.0),
            team_removed_drain_seconds: 5.0,
            intrusion: None,
            extra: Map::new(),
        }
    }
}

/// A slot for a not-yet-ported second-half module to install its own state
/// into once it lands (`ctx.runs`/`ctx.signer_manager`/`ctx.intrusion` in
/// Python are duck-typed `Any`, `None` until the tools/signer/intrusion
/// modules attach a server). `PORTING.md` §3.4: a Python-only
/// `Any`-typed attribute becomes an explicit, typed seam.
pub type AnySlot = Mutex<Option<Box<dyn Any + Send + Sync>>>;

fn empty_slot() -> AnySlot {
    Mutex::new(None)
}

/// Port of `context.Context`.
pub struct Context {
    pub state: &'static StateDir,
    pub kms: &'static (dyn Kms + Send + Sync),
    pub vault: Vault<'static>,
    pub policy: Policy<'static>,
    pub audit: &'static Audit<'static>,
    pub handles: HandleIssuer,
    pub projects: &'static Projects<'static>,
    pub admin: AdminCredential<'static>,
    pub config: Config,
    pub clock: Clock,
    /// SECOND-HALF: set by the tools module when a server is running.
    pub runs: AnySlot,
    /// SECOND-HALF: set by the signer module when a server is running.
    pub signer_manager: AnySlot,
    /// SECOND-HALF: set by the intrusion-detection module when attached.
    pub intrusion: AnySlot,
    owned_dirs: Vec<PathBuf>,
}

impl Context {
    pub fn initialize(
        state_dir: impl AsRef<Path>,
        admin_passphrase: &str,
        recovery_passphrase: &str,
        config: Config,
        clock: Clock,
    ) -> Result<Context, Error> {
        let state: &'static StateDir =
            Box::leak(Box::new(StateDir::new(state_dir.as_ref().to_path_buf())));
        state.create()?;
        for name in ["kms", "vault", "policy", "audit"] {
            state.subdir(name)?;
        }
        let kms: &'static (dyn Kms + Send + Sync) = Box::leak(Box::new(
            LocalFileKms::create_default(&state.path.join(KMS_FILE))?,
        ));
        let audit: &'static Audit<'static> = Box::leak(Box::new(Audit::new(state, clock.clone())));
        audit.require_writable()?;
        let projects: &'static Projects<'static> = Box::leak(Box::new(Projects::new(state)));
        let vault = Vault::initialize(state, kms, audit, projects, recovery_passphrase)?;
        let admin = AdminCredential::new(state);
        admin.initialize(admin_passphrase)?;
        state.write_bytes(HANDLE_KEY, HandleIssuer::generate_key().expose())?;
        let policy = Policy::new(state, clock.clone());
        let handles = HandleIssuer::new(&state.read_bytes(HANDLE_KEY)?)?;
        let mut ctx = Context {
            state,
            kms,
            vault,
            policy,
            audit,
            handles,
            projects,
            admin,
            config,
            clock,
            runs: empty_slot(),
            signer_manager: empty_slot(),
            intrusion: empty_slot(),
            owned_dirs: Vec::new(),
        };
        ctx.apply_config_defaults()?;
        ctx.audit.record(
            "init",
            RecordArgs {
                result: Some("ok"),
                extra: vec![("kind", json!("state_initialized"))],
                ..Default::default()
            },
        )?;
        Ok(ctx)
    }

    pub fn open(
        state_dir: impl AsRef<Path>,
        config: Config,
        clock: Clock,
    ) -> Result<Context, Error> {
        let state: &'static StateDir =
            Box::leak(Box::new(StateDir::new(state_dir.as_ref().to_path_buf())));
        state.require()?;
        let kms: &'static (dyn Kms + Send + Sync) =
            Box::leak(Box::new(LocalFileKms::load(&state.path.join(KMS_FILE))?));
        let audit: &'static Audit<'static> = Box::leak(Box::new(Audit::new(state, clock.clone())));
        let projects: &'static Projects<'static> = Box::leak(Box::new(Projects::new(state)));
        let vault = Vault::open(state, kms, audit, projects)?;
        let admin = AdminCredential::new(state);
        if !state.exists(HANDLE_KEY) {
            return Err(Error::state("handle_key_missing"));
        }
        let policy = Policy::new(state, clock.clone());
        let handles = HandleIssuer::new(&state.read_bytes(HANDLE_KEY)?)?;
        let mut ctx = Context {
            state,
            kms,
            vault,
            policy,
            audit,
            handles,
            projects,
            admin,
            config,
            clock,
            runs: empty_slot(),
            signer_manager: empty_slot(),
            intrusion: empty_slot(),
            owned_dirs: Vec::new(),
        };
        ctx.apply_config_defaults()?;
        Ok(ctx)
    }

    /// Place the agent-facing directories OUTSIDE the state directory. The
    /// exec child runs with cwd/HOME/TMPDIR under `run_dir` and reaches the
    /// signer through a socket under `socket_dir`. Deriving either from the
    /// state path would hand an agent-chosen program a path into the
    /// trusted store. Unset values become fresh private (0700) temporary
    /// directories remembered on the config; explicitly configured values
    /// must not lie inside the store.
    fn apply_config_defaults(&mut self) -> Result<(), Error> {
        if self.config.socket_dir.is_none() {
            self.config.socket_dir = Some(self.private_tempdir("zeropw-sockets-")?);
        }
        if self.config.run_dir.is_none() {
            self.config.run_dir = Some(self.private_tempdir("zeropw-runs-")?);
        }
        let socket_dir = self.config.socket_dir.clone();
        let run_dir = self.config.run_dir.clone();
        for (name, path) in [("socket_dir", socket_dir), ("run_dir", run_dir)] {
            if let Some(path) = path
                && self.inside_state(&path)
            {
                self.close();
                return Err(Error::state(format!("{name}_inside_state_dir")));
            }
        }
        Ok(())
    }

    fn inside_state(&self, path: &Path) -> bool {
        let resolved = match resolve_lenient(path) {
            Ok(p) => p,
            Err(_) => return true, // fail closed: an unresolvable path is not acceptable either
        };
        let state = match resolve_lenient(&self.state.path) {
            Ok(p) => p,
            Err(_) => return true,
        };
        resolved.starts_with(&state)
    }

    fn private_tempdir(&mut self, prefix: &str) -> Result<PathBuf, Error> {
        let base = std::env::temp_dir();
        let path = create_private_dir(&base, prefix)?;
        self.owned_dirs.push(path.clone());
        Ok(path)
    }

    /// Remove the temporary directories this context created (never
    /// user-supplied ones). Idempotent (like Python's
    /// `shutil.rmtree(path, ignore_errors=True)`); also run on `Drop` so a
    /// dropped `Context` never leaves an owned temp dir behind even if the
    /// caller never calls this explicitly.
    ///
    /// X-17 (equivalence review, round 8): this doc comment used to claim
    /// this was "not a strict improvement" over Python's
    /// `atexit.register(shutil.rmtree, ...)`, since it would "never run at
    /// all for a `Context` lost to `std::process::exit`/abort", and that
    /// closing that gap "would need `libc::atexit`, an `unsafe` FFI call ...
    /// so this gap is recorded rather than closed with `unsafe`" --
    /// `DEVIATIONS.md` finding E-5. Round 7 (finding E-R7-1) measured both
    /// claims false and closed the gap in safe Rust: there are zero
    /// `std::process::exit`/`std::process::abort` call sites anywhere in
    /// this crate's `src/`/`tests/` (verify with `grep -rn
    /// 'process::exit\|process::abort' rust/src rust/tests`), so the
    /// "lost to `process::exit`" case this comment warned about was never
    /// actually reachable through this crate's own code; the real gap was
    /// `signer::install`'s old `&'static Context` parameter, satisfiable in
    /// safe Rust only via `Box::leak` -- fixed by taking an owned
    /// `Arc<Context>` instead, so a `Context` dropped at the end of scope
    /// (an `Arc` clone going out of scope on every exit path, including the
    /// signer's) removes both owned dirs through ordinary `Drop`, no
    /// `unsafe` involved. See `DEVIATIONS.md` row 68 (the corrected E-5
    /// row) for the full measurement and the one remaining, structurally
    /// matched gap (`std::process::exit`/abort skipping Rust destructors,
    /// the direct equivalent of Python's own `atexit` gap, `os._exit`) --
    /// this doc comment and that row must not drift apart again: a reader
    /// of this function alone should not be told the gap is unclosable in
    /// safe Rust when it already is closed, the exact invitation to
    /// reintroduce `Box::leak`/`&'static Context` that row exists to
    /// prevent.
    pub fn close(&mut self) {
        for dir in self.owned_dirs.drain(..) {
            let _ = fs::remove_dir_all(&dir);
        }
    }

    /// Invalidate every outstanding handle (used by recovery).
    pub fn rotate_handle_key(&mut self) -> Result<(), Error> {
        self.state
            .write_bytes(HANDLE_KEY, HandleIssuer::generate_key().expose())?;
        self.handles = HandleIssuer::new(&self.state.read_bytes(HANDLE_KEY)?)?;
        Ok(())
    }

    /// Disaster recovery: new KMS master key, re-wrapped DEK, all grants
    /// revoked, handles invalidated.
    pub fn recover(&mut self, recovery_passphrase: &str) -> Result<usize, Error> {
        let old = self.state.path.join(KMS_FILE);
        let rotated = self.state.path.join("kms").join(format!(
            "master.key.retired-{}",
            clock_now_i64(&self.clock)?
        ));
        fs::rename(&old, &rotated)
            .map_err(|e| Error::state("state_write_failed").with_detail(e.to_string()))?;

        let attempt = (|| -> Result<(&'static (dyn Kms + Send + Sync), Vault<'static>), Error> {
            let new_kms: &'static (dyn Kms + Send + Sync) =
                Box::leak(Box::new(LocalFileKms::create(
                    &old,
                    &format!("local-dev-kms-{}", clock_now_i64(&self.clock)?),
                )?));
            let vault = Vault::recover(
                self.state,
                new_kms,
                self.audit,
                self.projects,
                recovery_passphrase,
            )?;
            Ok((new_kms, vault))
        })();
        let (new_kms, vault) = match attempt {
            Ok(v) => v,
            Err(e) => {
                // Python: `except Exception: os.replace(rotated, old); raise` does not itself
                // guard that `os.replace` -- if the rename-back also fails, its `OSError`
                // propagates and *replaces* the original exception (the original becomes
                // `__context__`, not what the caller sees) rather than being swallowed.
                // `let _ = fs::rename(...)` used to discard that failure and always return the
                // original error `e` (finding E-R7-3); surface the rename-back failure instead,
                // matching Python's replacement semantics.
                if let Err(e2) = fs::rename(&rotated, &old) {
                    return Err(Error::state("state_write_failed").with_detail(e2.to_string()));
                }
                return Err(e);
            }
        };
        self.kms = new_kms;
        self.vault = vault;
        let revoked = self.policy.revoke_all()?;
        self.rotate_handle_key()?;
        self.audit.record(
            "recover",
            RecordArgs {
                result: Some("ok"),
                extra: vec![
                    ("count", json!(revoked)),
                    ("state", json!("grants_revoked_handles_rotated")),
                ],
                ..Default::default()
            },
        )?;
        Ok(revoked)
    }
}

/// `Context::recover` names its retired-master-key and new-KMS-key-id files with
/// `int(self.clock())` (`context.py:198,200`), evaluated *before* the filesystem operation that
/// immediately follows each call: `int(float('inf'))` raises `OverflowError` and
/// `int(float('nan'))` raises `ValueError`, so a non-finite clock value aborts `recover` at that
/// point rather than proceeding (PORTING.md §3.5: an uncaught built-in exception maps to the
/// closest ZeroPW error a caller of `recover` already handles -- `state_write_failed`, the same
/// reason every other local filesystem-write failure in this function already surfaces as).
/// `(self.clock)() as i64` alone would silently saturate instead (`inf` -> `i64::MAX`, `NaN` ->
/// `0`) and let `recover` rename the live master key aside on a broken clock (finding E-R7-6).
/// Only reachable via a caller-injected `Clock` returning a non-finite value -- trusted in-process
/// code, not any untrusted input.
fn clock_now_i64(clock: &Clock) -> Result<i64, Error> {
    let now = clock();
    if !now.is_finite() {
        return Err(Error::state("state_write_failed").with_detail("clock_not_finite"));
    }
    Ok(now as i64)
}

impl Drop for Context {
    fn drop(&mut self) {
        self.close();
    }
}

/// A convenience wrapper matching Python's `clock: Callable[[], float] |
/// None = None` defaulting to `time.time`.
pub fn default_clock() -> Clock {
    clock::system()
}

/// Create a fresh, randomly-named 0700 directory under `base` with `prefix`.
/// Port of `tempfile.mkdtemp`'s mode guarantee (`_private_tempdir` in
/// `context.py` calls `os.chmod(path, 0o700)` right after `mkdtemp`, but
/// `mkdtemp` itself already creates the directory at mode 0700 via a single
/// `os.mkdir(path, 0o700)` call -- there is no window where it exists at a
/// wider mode). `fs::create_dir` (this crate's previous implementation) has
/// no mode argument -- it always creates at the process default (`0o777`
/// masked by umask, typically `0o755`) and relied on a *separate*
/// `fs::set_permissions` call afterwards to narrow it to 0700, leaving that
/// window open to any other local user for the time between the two calls
/// (finding E-2). `mkdir_private_0700` uses `DirBuilder::mode` so the `mkdir`
/// syscall itself is issued with mode 0700, matching Python's atomicity; the
/// redundant `set_permissions` call is kept anyway as a defensive backstop
/// against a masking umask.
fn mkdir_private_0700(path: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)
}

/// Finding E-R3-2: this used to encode 8 raw random bytes as hex (16
/// characters), 8 characters longer than Python's `tempfile.mkdtemp`'s own
/// 8-character random suffix (`zeropw-sockets-`/`zeropw-runs-` basenames
/// ended up 8 bytes longer than Python's for the same prefix). That silently
/// defeated `signer.rs`'s own `MAX_UNIX_PATH` bind-time length check: a
/// `ctx.config.socket_dir` that Python's shorter basename keeps under the
/// limit could push Rust's longer one over it, making `choose_socket_dir`
/// discard the configured directory and fall back to a `zpws-` temp dir that
/// `Context` neither owns nor removes. 4 random bytes hex-encoded yields the
/// same 8-character suffix length as `mkdtemp`'s own alphabet (different
/// character set, same length), matching the fix already applied to
/// `signer.rs`'s `make_temp_dir` (findings G-2/G-3).
fn create_private_dir(base: &Path, prefix: &str) -> Result<PathBuf, Error> {
    for _ in 0..64 {
        let mut suffix = [0u8; 4];
        {
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut suffix);
        }
        let path = base.join(format!("{prefix}{}", hex::encode(suffix)));
        match mkdir_private_0700(&path) {
            Ok(()) => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|_| {
                    Error::state("state_write_failed").with_detail(path.display().to_string())
                })?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => {
                return Err(
                    Error::state("state_write_failed").with_detail(path.display().to_string())
                );
            }
        }
    }
    Err(Error::state("state_write_failed").with_detail("tempdir"))
}

/// Port of `pathlib.Path.resolve(strict=False)`: walks the path component by
/// component from the root, resolving `.`/`..` and any symlink encountered
/// along the way, but tolerating components that do not exist (they are
/// appended literally, exactly like CPython's `posixpath.realpath` catching
/// `OSError` from a failed `lstat` and treating the remainder as literal).
///
/// This must match Python closely because `Context::inside_state` (finding
/// E-1) uses it to decide whether a caller-supplied `socket_dir`/`run_dir`
/// escapes the trusted state directory -- a resolver that resolves fewer
/// symlinks than Python's is a fail-*open* gap (a path Python would refuse
/// as "inside the state dir" could be accepted by Rust). A previous version
/// of this function tried `fs::canonicalize` (which requires the *entire*
/// path to exist) and, only on failure, fell back to a purely lexical
/// `.`/`..` normalization with **no** symlink resolution at all -- so a
/// `socket_dir` that does not exist yet (the common case: every default
/// private tempdir exists, but any caller-supplied path typically does not)
/// skipped symlink resolution entirely, including for already-existing
/// ancestor directories (e.g. a `/tmp` that is itself a symlink to
/// `/private/tmp` on macOS). See `DEVIATIONS.md` for the fixed row and
/// `rust/tests/vault_context.rs`'s `inside_state_matches_python_*` tests,
/// oracle-compared against `Path.resolve(strict=False)` for the exact cases
/// that previously diverged.
///
/// This is a byte-identical reimplementation of CPython 3.12's
/// `posixpath._joinrealpath` short-circuit-on-cycle behaviour as of round 3
/// (finding E-R3-1; see [`resolve_components`]'s doc comment for the
/// remaining, deliberate simplification -- everything *before* a cycle is
/// hit walks component by component exactly like Python's loop, so the only
/// difference left is structural, not behavioural). A genuine symlink loop
/// is CPython's one case where `Path.resolve(strict=False)` still raises
/// (`RuntimeError("Symlink loop from ...")`, via a `stat()` call *after* the
/// lenient walk -- see the comment below); that escape is recorded in
/// `DEVIATIONS.md` (finding E-R2-2a) since Rust has no exception to let
/// propagate the same way.
fn resolve_lenient(path: &Path) -> std::io::Result<PathBuf> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut seen: HashMap<PathBuf, Option<PathBuf>> = HashMap::new();
    let comps: Vec<std::path::Component> = abs.components().collect();
    let resolved = match resolve_components(PathBuf::from("/"), &comps, &mut seen)? {
        Ok(resolved) => resolved,
        // A cycle short-circuited resolution somewhere in the walk: `resolve_components`
        // already appended every remaining component *literally* (unprocessed, exactly like
        // Python's plain string `join(newpath, rest)`), so the result can still contain
        // literal `.`/`..` segments that were never structurally interpreted. CPython's
        // `realpath()` unconditionally finishes with `abspath(path)` == `normpath(path)` for
        // an already-absolute path, which is a no-op on a fully-resolved path but is exactly
        // what cleans up this literal remainder -- reproduce that same final normalisation
        // here (finding E-R3-1).
        Err(literal) => posix_normpath_absolute(&literal),
    };
    // CPython's non-strict `os.path.realpath` (the engine `pathlib.Path.resolve(strict=False)`
    // delegates to) never raises for a symlink loop by itself -- `resolve_components`'s `seen`
    // map, just like `posixpath._joinrealpath`, leaves an unresolved cycle as a literal path
    // instead of erroring. But `Path.resolve()` then calls `stat()` on that result and turns an
    // `OSError(ELOOP)` from *that* call into `RuntimeError("Symlink loop from ...")`, which
    // propagates out of `Context._inside_state`/`Context.open`/`Context.initialize` uncaught
    // (finding E-R2-2a). Reproduce the same detection here so a genuine loop still surfaces as an
    // `Err`, which `Context::inside_state` already treats as fail-closed ("not acceptable").
    if let Err(e) = fs::metadata(&resolved)
        && e.raw_os_error() == Some(libc::ELOOP)
    {
        return Err(e);
    }
    // Any other `stat()` failure (not found, permission denied, ...) is ignored here, just
    // like Python's `except OSError as e: check_eloop(e)` only re-raises for `ELOOP`.
    Ok(resolved)
}

/// Port of `posixpath.normpath`, restricted to the absolute-path case (the
/// only one `resolve_lenient` ever needs): collapses `.`/empty segments and
/// structurally pops a `..` against whatever real segment precedes it,
/// silently dropping a leading `..` at the root exactly like Python (an
/// absolute path's `new_comps` starts empty, and popping an already-empty
/// `new_comps` is a no-op) -- matching `PathBuf::pop()`'s own no-op-at-root
/// behaviour. Purely lexical, no filesystem access, used only to clean up
/// the literal, unprocessed remainder [`resolve_components`] appends after a
/// symlink cycle short-circuits resolution (finding E-R3-1); a no-op on an
/// already-fully-resolved path.
fn posix_normpath_absolute(path: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    for comp in path.components() {
        match comp {
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {}
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::Normal(part) => {
                out.push(part);
            }
        }
    }
    out
}

/// One pass of the component walk described on [`resolve_lenient`], mirroring CPython 3.12's
/// `posixpath._joinrealpath` (the engine behind `os.path.realpath`, which `pathlib.Path.resolve`
/// delegates to since Python 3.10): `seen` maps each symlink's own resolved-so-far path to `None`
/// while it is in the middle of being resolved, and to `Some(resolved_target)` once resolved. A
/// chain of any length resolves in full -- there is no hop-count limit, matching CPython's own
/// `_joinrealpath` (`maxlinks = None`) -- and only a genuine cycle (a symlink reached again while
/// its own entry is still `None`) is left unresolved, exactly like Python's non-strict `realpath`.
///
/// A previous version of this function bounded recursion at a fixed depth of 40 and refused any
/// longer chain outright with an `Err` (finding E-R2-1): that was wrong on two counts. First, it
/// rejected long but perfectly acyclic chains that Python resolves without complaint (CPython has
/// no hop limit at all, so nothing here should either). Second, even for an actual cycle, erroring
/// out of the component walk itself was the wrong place to fail -- Python's non-strict `realpath`
/// does *not* raise there either; the loop only surfaces later, when `Path.resolve()` `stat()`s the
/// (still-literal) result (see `resolve_lenient`'s post-check, finding E-R2-2a). See
/// `DEVIATIONS.md` (findings E-R2-1, E-R2-2a) and `rust/tests/vault_context_oracle.rs`'s
/// `inside_state_matches_python_for_51_hop_symlink_chain*` / `*_self_symlink_loop` tests.
///
/// Round 3 (finding E-R3-1) fixed a remaining fail-*open* gap in the cycle
/// arm: it used to set `resolved = candidate` and `continue` the *same*
/// loop, so components *after* a detected cycle were still `lstat`'ed and
/// resolved as if nothing had happened, and the bogus result got cached in
/// `seen`. CPython's `_joinrealpath` does something stricter on a cycle: it
/// returns `(join(newpath, rest), False)` immediately, propagating `ok =
/// False` out of the *recursive* call used to resolve a symlink's target (if
/// any) and, from there, out of every enclosing frame in turn -- each frame
/// appends only its *own* remaining, unprocessed components (verbatim, not
/// even lexically normalised yet) before returning `False` itself. Nothing
/// past the cycle is ever `lstat`'ed, resolved, or written into `seen`. This
/// function now takes the remaining components as an explicit slice (so it
/// can slice off "everything after the cycle" the same way Python's `rest`
/// string does after `partition`) and returns `Ok(resolved)` on full success
/// or `Err(literal_path)` -- the short-circuited, not-yet-normalised path --
/// on a cycle, which every recursive caller re-propagates by appending its
/// *own* remaining components to the `Err` payload and returning `Err`
/// again, exactly mirroring Python's bubbling `(path, False)` returns.
/// [`resolve_lenient`] applies the final `posixpath.normpath`-equivalent
/// cleanup ([`posix_normpath_absolute`]) once resolution finishes, matching
/// `realpath()`'s own unconditional `abspath(path)` call. See
/// `rust/tests/vault_context_oracle.rs`'s
/// `inside_state_matches_python_for_loop_then_dotdot_then_symlink` (the
/// probe shape the equivalence reviewer gave: a self-loop followed by
/// `../<other-symlink>/../x`, which the previous version resolved into the
/// wrong directory).
fn resolve_components(
    start: PathBuf,
    comps: &[std::path::Component],
    seen: &mut HashMap<PathBuf, Option<PathBuf>>,
) -> std::io::Result<Result<PathBuf, PathBuf>> {
    let mut resolved = start;
    for (i, comp) in comps.iter().enumerate() {
        match comp {
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {}
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                resolved.pop();
            }
            std::path::Component::Normal(part) => {
                let candidate = resolved.join(part);
                match seen.get(&candidate) {
                    Some(Some(cached)) => {
                        // Already resolved earlier in this walk (e.g. the same symlink
                        // reached twice via different, non-cyclic routes): reuse it without
                        // re-touching the filesystem, exactly like Python's `path = seen[newpath]`.
                        resolved = cached.clone();
                        continue;
                    }
                    Some(None) => {
                        // This symlink is an ancestor of itself in the current resolution --
                        // a genuine cycle. Python's non-strict `_joinrealpath` does not raise
                        // here, but it does stop resolving immediately: `return join(newpath,
                        // rest), False`. Reproduce that exactly -- append every remaining
                        // component *literally* (not processed by this loop at all) and hand
                        // the short-circuit back to the caller instead of continuing.
                        let mut literal = candidate;
                        for rest in &comps[i + 1..] {
                            literal.push(rest.as_os_str());
                        }
                        return Ok(Err(literal));
                    }
                    None => {}
                }
                match fs::symlink_metadata(&candidate) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        seen.insert(candidate.clone(), None);
                        let target = fs::read_link(&candidate)?;
                        let target_comps: Vec<std::path::Component> = target.components().collect();
                        let base = if target.is_absolute() {
                            PathBuf::from("/")
                        } else {
                            // Python resolves a relative symlink target against `path` as it
                            // stood *before* this component (`newpath`'s own name is not part
                            // of the prefix passed into the recursive `_joinrealpath` call).
                            resolved.clone()
                        };
                        match resolve_components(base, &target_comps, seen)? {
                            Ok(resolved_target) => {
                                seen.insert(candidate.clone(), Some(resolved_target.clone()));
                                resolved = resolved_target;
                            }
                            Err(mut literal) => {
                                // The symlink's own target resolution hit a cycle further
                                // down: propagate the short-circuit, appending *this* frame's
                                // remaining components literally, same as Python's `if not
                                // ok: return join(path, rest), False`. No `seen` entry is
                                // written for `candidate` -- it stays `None` (unresolved).
                                for rest in &comps[i + 1..] {
                                    literal.push(rest.as_os_str());
                                }
                                return Ok(Err(literal));
                            }
                        }
                    }
                    // Exists but is not a symlink, or does not exist at all
                    // (or is otherwise unreadable): keep it literally, the
                    // same way Python's `OSError`-swallowing `lstat` does.
                    _ => resolved = candidate,
                }
            }
        }
    }
    Ok(Ok(resolved))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Finding E-2: `mkdir_private_0700` must set mode 0700 in the `mkdir`
    /// syscall itself (`DirBuilder::mode`), not via a separate `chmod`
    /// afterwards -- checked here by reading the mode back immediately after
    /// `mkdir_private_0700` returns, before `create_private_dir`'s own
    /// (redundant, defensive) follow-up `set_permissions` call would run.
    ///
    /// The mode asserted here is "no bits wider than 0700", not "exactly
    /// 0700": like `mkdir(2)`, `DirBuilder::mode` still gets masked by the
    /// process umask, so under a masking umask (e.g. `umask 0177` producing
    /// 0500) the resulting mode is narrower than 0700, not equal to it.
    /// Python's own equivalent (`mkdtemp`, which `Context._private_tempdir`
    /// calls) is masked the exact same way -- asserting equality here would
    /// therefore be a *stronger* claim than Python itself makes, and would
    /// fail spuriously under such a umask (round-2 review note).
    #[test]
    fn mkdir_private_0700_sets_mode_atomically_with_no_wider_window() {
        let base = std::env::temp_dir();
        let path = base.join(format!(
            "zeropw-test-atomic-mkdir-{}-{}",
            std::process::id(),
            {
                use rand::RngCore;
                rand::rngs::OsRng.next_u64()
            }
        ));
        mkdir_private_0700(&path).expect("mkdir_private_0700");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        fs::remove_dir(&path).expect("cleanup");
        assert_eq!(
            mode & !0o700,
            0,
            "directory must not be wider than 0700 right after mkdir, before any chmod (got {mode:o})"
        );
    }

    #[test]
    fn create_private_dir_result_is_0700() {
        let base = std::env::temp_dir();
        let path = create_private_dir(&base, "zeropw-test-create-private-dir-").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        fs::remove_dir(&path).unwrap();
        assert_eq!(mode, 0o700);
    }

    /// Finding E-R3-2: `create_private_dir`'s random suffix used to be 8 raw
    /// bytes hex-encoded (16 characters), 8 characters longer than Python's
    /// `tempfile.mkdtemp`'s own suffix for the same prefix -- oracle-compared
    /// here directly against real `python3.12`, mirroring `signer.rs`'s own
    /// `make_temp_dir_suffix_length_matches_python_mkdtemp` (the identical
    /// fix for the identical bug, findings G-2/G-3).
    #[test]
    fn create_private_dir_suffix_length_matches_python_mkdtemp() {
        let python_suffix_len: usize = crate::oracle::python(
            "import tempfile, os, shutil\n\
             path = tempfile.mkdtemp(prefix='zeropw-sockets-')\n\
             print(len(os.path.basename(path)) - len('zeropw-sockets-'))\n\
             shutil.rmtree(path, ignore_errors=True)\n",
        )
        .trim()
        .parse()
        .expect("python prints an integer suffix length");
        let base = std::env::temp_dir();
        let path = create_private_dir(&base, "zeropw-sockets-").unwrap();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf8 basename")
            .to_string();
        fs::remove_dir(&path).unwrap();
        assert!(name.starts_with("zeropw-sockets-"), "{name}");
        let rust_suffix_len = name.len() - "zeropw-sockets-".len();
        assert_eq!(rust_suffix_len, python_suffix_len);
    }

    /// Finding E-R3-1: the reviewer's probe shape for the fail-*open* cycle-handling gap.
    /// `base/L` is a **self-loop** symlink (`L -> L`); `base/M` is a symlink to a real,
    /// unrelated directory (`base/other/deep`). The candidate path walks *through* the loop
    /// first, then backs out of it with `..`, then through the unrelated symlink, then backs
    /// out of *that* too, landing on a fresh leaf `x`. CPython's `posixpath._joinrealpath`
    /// resolves this to `<base>/x`: once the self-loop is detected, it stops resolving
    /// entirely and appends every remaining component (`../M/../x`) *literally*, and only
    /// `normpath`-cleans the whole thing at the very end -- so the `M` symlink is never even
    /// looked at, because it comes *after* the point where resolution gave up. The previous
    /// Rust implementation kept resolving past the cycle, so it *did* follow `M`, giving the
    /// wrong answer `<base>/other/x`.
    #[test]
    fn resolve_lenient_matches_python_for_loop_then_dotdot_then_symlink() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let base = tmp.path().to_path_buf();
        let loop_path = base.join("L");
        std::os::unix::fs::symlink(&loop_path, &loop_path).expect("self-loop symlink");
        let other_deep = base.join("other").join("deep");
        fs::create_dir_all(&other_deep).expect("mkdir other/deep");
        let m_path = base.join("M");
        std::os::unix::fs::symlink(&other_deep, &m_path).expect("M symlink");
        let candidate = base.join("L").join("..").join("M").join("..").join("x");

        let rust_resolved = resolve_lenient(&candidate).expect("resolve_lenient");

        let python_resolved = crate::oracle::python(&format!(
            "import pathlib\n\
             print(pathlib.Path({candidate:?}).resolve(strict=False))\n",
        ));
        let python_resolved = PathBuf::from(python_resolved.trim());

        assert_eq!(
            rust_resolved, python_resolved,
            "rust={rust_resolved:?} python={python_resolved:?}"
        );
        assert_eq!(
            rust_resolved.file_name().and_then(|n| n.to_str()),
            Some("x"),
            "must land on the fresh leaf, not resolve through the M symlink: {rust_resolved:?}"
        );
        assert_eq!(
            rust_resolved.parent().and_then(|p| p.file_name()),
            base.file_name(),
            "must land directly under base, not base/other: {rust_resolved:?}"
        );
    }
}
