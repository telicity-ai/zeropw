//! Port of `zeropw/store.py`: the locked, atomic JSON state directory for the
//! trusted ZeroPW process.
//!
//! Concurrency: a single trusted process serves several threads (gateway,
//! signer, tools). [`StateDir::lock`] combines a re-entrant *in-process* lock
//! (Python: `threading.RLock`) with an `flock` *file* lock (Python: `fcntl`)
//! so a second administrative process (the admin CLI) also serialises
//! read-modify-write cycles against the same directory -- including a Python
//! process holding the same `.lock` file.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex};
use std::thread::{self, ThreadId};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::{Error, ErrorClass};
use crate::pyjson::{self, DumpOptions};
use crate::pystr;
use serde_json::Value;

pub const DIR_MODE: u32 = 0o700;
pub const FILE_MODE: u32 = 0o600;

struct LockState {
    owner: Option<ThreadId>,
    depth: u32,
}

/// A locked, atomic JSON state directory. Port of `zeropw.store.StateDir`.
pub struct StateDir {
    pub path: PathBuf,
    lock_state: Mutex<LockState>,
    lock_cond: Condvar,
    // The open, `flock`-held `.lock` file descriptor while `depth > 0`.
    // Only touched by the thread that holds the lock at the moment it
    // transitions depth 0 <-> 1, guarded here purely so the struct stays
    // `Sync`.
    lock_file: Mutex<Option<File>>,
}

impl StateDir {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        StateDir {
            path: path.into(),
            lock_state: Mutex::new(LockState {
                owner: None,
                depth: 0,
            }),
            lock_cond: Condvar::new(),
            lock_file: Mutex::new(None),
        }
    }

    /// Joins a caller-supplied `name` onto `self.path` the way Python's
    /// `self.path / name` (`pathlib.PurePath.__truediv__`) does, not the way
    /// `std::path::Path::join` does on its own (finding A-R7-2).
    ///
    /// `pathlib` normalizes the *right-hand* operand while composing a path:
    /// it drops any `.` component and any empty component produced by a
    /// leading/trailing/doubled `/`, but it does **not** resolve `..`
    /// components -- confirmed against real `python3.12`:
    /// `Path("/tmp/state") / "sub/"`, `.../ "sub//"`, `.../ "./sub"` all give
    /// `PosixPath("/tmp/state/sub")`, while `Path("/tmp/state") / ".."`
    /// gives the *unresolved* `PosixPath("/tmp/state/..")`.
    /// `Path::join`, by contrast, keeps a trailing/doubled `/` and any `.`
    /// verbatim in the resulting `PathBuf` -- which the kernel then
    /// interprets as "this must be a directory", diverging from every
    /// `StateDir` operation on a `name` that happens to end in `/` (see
    /// [`normalize_join_name`] for the measured fail-open consequence on
    /// `read_json`).
    ///
    /// An absolute `name` (leading `/`) is passed straight through:
    /// `Path::join` already reproduces pathlib's own "an absolute right-hand
    /// operand replaces the base entirely" behaviour with no help needed
    /// here, confirmed against both languages.
    fn join(&self, name: &str) -> PathBuf {
        self.path.join(normalize_join_name(name))
    }

    // ------------------------------------------------------------------ setup
    /// `StateDir.create`: `self.path.mkdir(mode=DIR_MODE, parents=True)` then
    /// an unconditional `os.chmod(self.path, DIR_MODE)`. Python only raises
    /// `StateError("state_exists")` from the initial `path.exists()` check;
    /// every later `mkdir`/`chmod` failure (a losing creation race included,
    /// which is `FileExistsError` because `exist_ok` is false) is the raw
    /// `OSError`, reproduced by [`uncaught_os_error`].
    pub fn create(&self) -> Result<(), Error> {
        if self.path.exists() {
            return Err(Error::state("state_exists").with_detail(path_str(&self.path)));
        }
        path_mkdir(&self.path, DIR_MODE, true, false).map_err(|e| uncaught_os_error(&e))?;
        // Python's follow-up `os.chmod` (unconditional, regardless of
        // whether the preceding `mkdir(mode=DIR_MODE)` already landed on
        // DIR_MODE): fixes the directory back to exactly DIR_MODE even
        // under a pathological owner-masking umask.
        set_mode(&self.path, DIR_MODE)?;
        Ok(())
    }

    /// `StateDir.require`.
    pub fn require(&self) -> Result<(), Error> {
        if !self.path.is_dir() {
            return Err(Error::state("state_missing").with_detail(path_str(&self.path)));
        }
        Ok(())
    }

    /// `StateDir.subdir`: `target.mkdir(mode=DIR_MODE, exist_ok=True)` --
    /// the one `mkdir` call site in `store.py` that omits `parents=True`. A
    /// missing parent (`FileNotFoundError`) or a non-directory occupying the
    /// target (`FileExistsError`) is the raw `OSError` Python raises, never a
    /// silently created parent.
    pub fn subdir(&self, name: &str) -> Result<PathBuf, Error> {
        let target = self.join(name);
        path_mkdir(&target, DIR_MODE, false, true).map_err(|e| uncaught_os_error(&e))?;
        Ok(target)
    }

    // ------------------------------------------------------------------- lock
    /// Exclusive, re-entrant lock across threads (in-process) and processes
    /// (`flock` on `<state>/.lock`). Port of `StateDir.lock`.
    pub fn lock(&self) -> Result<StateLock<'_>, Error> {
        let this = thread::current().id();
        let mut guard = self.lock_state.lock().expect("lock_state mutex poisoned");
        loop {
            match guard.owner {
                None => break,
                Some(id) if id == this => break,
                Some(_) => {
                    guard = self
                        .lock_cond
                        .wait(guard)
                        .expect("lock_state mutex poisoned");
                }
            }
        }
        let entering_fresh = guard.owner.is_none();
        guard.owner = Some(this);
        guard.depth += 1;
        drop(guard);

        if entering_fresh {
            match self.acquire_os_lock() {
                Ok(file) => {
                    *self.lock_file.lock().expect("lock_file mutex poisoned") = Some(file);
                }
                Err(err) => {
                    // Roll back the state we already took so a failed first
                    // acquisition does not wedge the directory forever.
                    let mut guard = self.lock_state.lock().expect("lock_state mutex poisoned");
                    guard.owner = None;
                    guard.depth = 0;
                    drop(guard);
                    self.lock_cond.notify_all();
                    return Err(err);
                }
            }
        }
        Ok(StateLock { dir: self })
    }

    /// `lock()`'s first-entry `mkdir(parents=True, exist_ok=True)`,
    /// `os.open(".lock")` and `fcntl.flock`: none is caught in Python (a
    /// failed `flock` only closes the fd before re-raising), so each failure
    /// is the raw `OSError` ([`uncaught_os_error`]).
    #[allow(unsafe_code)]
    fn acquire_os_lock(&self) -> Result<File, Error> {
        path_mkdir(&self.path, DIR_MODE, true, true).map_err(|e| uncaught_os_error(&e))?;
        let lock_path = self.path.join(".lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(FILE_MODE)
            .open(&lock_path)
            .map_err(|e| uncaught_os_error(&e))?;
        // SAFETY: `file` owns a valid, open file descriptor for the
        // lifetime of this call; `flock` only touches the kernel's lock
        // table for that fd and does not alias Rust-managed memory. This is
        // the crate's one allowed `unsafe` (rust/PORTING.md engineering rules).
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(uncaught_os_error(&std::io::Error::last_os_error()));
        }
        Ok(file)
    }

    #[allow(unsafe_code)]
    fn release_os_lock(&self) {
        if let Some(file) = self
            .lock_file
            .lock()
            .expect("lock_file mutex poisoned")
            .take()
        {
            // SAFETY: same fd this thread obtained from `acquire_os_lock`
            // and has not shared or closed since.
            unsafe {
                libc::flock(file.as_raw_fd(), libc::LOCK_UN);
            }
            drop(file); // closes the fd
        }
    }

    // ------------------------------------------------------------------- json
    /// `StateDir.read_json`.
    pub fn read_json(&self, name: &str, default: Value) -> Result<Value, Error> {
        let target = self.join(name);
        if !target.exists() {
            return Ok(default);
        }
        let text = fs::read_to_string(&target)
            .map_err(|_| Error::state("state_corrupt").with_detail(name))?;
        pyjson::loads(&text).map_err(|_| Error::state("state_corrupt").with_detail(name))
    }

    /// `StateDir.write_json`. Python's `try` wraps *both* the write and the
    /// final `os.replace`, and unlinks the tmp file on any `OSError` from
    /// either (store.py:104-110) -- so a failed rename leaves no tmp file
    /// behind, unlike [`StateDir::write_bytes`] (store.py:139-147, which
    /// has no such `except` clause and leaves the tmp file in place).
    ///
    /// The parent `mkdir` (store.py:96) and the temp-file `os.open`
    /// (store.py:98) sit before that `try`, so their failures are the raw
    /// `OSError` ([`uncaught_os_error`]), not `state_write_failed`.
    pub fn write_json(&self, name: &str, value: &Value) -> Result<(), Error> {
        let target = self.join(name);
        mkdir_parent(&target)?;
        let text = pyjson::dumps(value, DumpOptions::pretty_sorted())
            .map_err(|_| Error::state("state_write_failed").with_detail(name))?;
        let tmp = tmp_path_write_json(&target);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(FILE_MODE)
            .open(&tmp)
            .map_err(|e| uncaught_os_error(&e))?;
        let result = (|| -> std::io::Result<()> {
            file.write_all(text.as_bytes())?;
            file.flush()?;
            file.sync_all()?;
            drop(file);
            fs::rename(&tmp, &target)?;
            Ok(())
        })();
        result.map_err(|_| {
            let _ = fs::remove_file(&tmp);
            Error::state("state_write_failed").with_detail(name)
        })
    }

    /// Append one line and fsync. Port of `StateDir.append_line`, whose
    /// docstring documents "Raises OSError to the caller on failure": it has
    /// no `except` clause, so the `mkdir`, `os.open`, `os.write` and
    /// `os.fsync` failures are all the raw `OSError` ([`uncaught_os_error`]).
    pub fn append_line(&self, name: &str, line: &str) -> Result<(), Error> {
        if line.contains('\n') {
            return Err(Error::state("state_invalid_line").with_detail(name));
        }
        let target = self.join(name);
        mkdir_parent(&target)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(FILE_MODE)
            .open(&target)
            .map_err(|e| uncaught_os_error(&e))?;
        let mut buf = line.as_bytes().to_vec();
        buf.push(b'\n');
        file.write_all(&buf).map_err(|e| uncaught_os_error(&e))?;
        file.sync_all().map_err(|e| uncaught_os_error(&e))?;
        Ok(())
    }

    /// `StateDir.read_lines`. Python has no `try` here: an `open()`/read
    /// failure (a directory, no permission) is the raw `OSError`
    /// ([`uncaught_os_error`]) and undecodable UTF-8 is the built-in
    /// `UnicodeDecodeError`, which this crate carries as
    /// `StateError("state_corrupt", "UnicodeDecodeError")` -- the shape the
    /// administrator CLI's `except (..., ValueError)` handler prints.
    pub fn read_lines(&self, name: &str, limit: Option<usize>) -> Result<Vec<String>, Error> {
        let target = self.join(name);
        if !target.exists() {
            return Ok(Vec::new());
        }
        let mut raw = Vec::new();
        File::open(&target)
            .and_then(|mut f| f.read_to_end(&mut raw))
            .map_err(|e| uncaught_os_error(&e))?;
        let text = String::from_utf8(raw)
            .map_err(|_| Error::state("state_corrupt").with_detail("UnicodeDecodeError"))?;
        let mut lines = split_universal_newlines(&text);
        // Python: `lines[-limit:]`. `-0 == 0`, so `lines[-0:]` is `lines[0:]`
        // -- the *whole* list, not an empty one; only `limit > 0` actually
        // trims from the end.
        if let Some(limit) = limit
            && limit != 0
            && lines.len() > limit
        {
            lines = lines.split_off(lines.len() - limit);
        }
        Ok(lines)
    }

    /// `StateDir.write_bytes`. Unlike [`StateDir::write_json`], Python's
    /// `except OSError` here (store.py:139-147) has no `os.unlink(tmp)` --
    /// a failed write *or* a failed `os.replace` leaves the tmp file
    /// behind. Match that exactly (no cleanup on any failure path).
    /// The parent `mkdir` (store.py:137) and the temp-file `os.open`
    /// (store.py:139) precede that `try`: their failures are the raw
    /// `OSError` ([`uncaught_os_error`]).
    pub fn write_bytes(&self, name: &str, data: &[u8]) -> Result<(), Error> {
        let target = self.join(name);
        mkdir_parent(&target)?;
        let tmp = tmp_path_write_bytes(&target);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(FILE_MODE)
            .open(&tmp)
            .map_err(|e| uncaught_os_error(&e))?;
        let result = (|| -> std::io::Result<()> {
            file.write_all(data)?;
            file.flush()?;
            file.sync_all()?;
            drop(file);
            fs::rename(&tmp, &target)?;
            Ok(())
        })();
        result.map_err(|_| Error::state("state_write_failed").with_detail(name))
    }

    /// `StateDir.read_bytes`.
    pub fn read_bytes(&self, name: &str) -> Result<Vec<u8>, Error> {
        let target = self.join(name);
        let mut buf = Vec::new();
        File::open(&target)
            .and_then(|mut f| f.read_to_end(&mut buf))
            .map_err(|_| Error::state("state_missing").with_detail(name))?;
        Ok(buf)
    }

    /// `StateDir.exists`.
    pub fn exists(&self, name: &str) -> bool {
        self.join(name).exists()
    }
}

/// A held [`StateDir::lock`]; releases (and, at depth 0, unlocks the
/// underlying file) on drop.
pub struct StateLock<'a> {
    dir: &'a StateDir,
}

impl Drop for StateLock<'_> {
    fn drop(&mut self) {
        let mut guard = self
            .dir
            .lock_state
            .lock()
            .expect("lock_state mutex poisoned");
        guard.depth -= 1;
        let last = guard.depth == 0;
        if last {
            guard.owner = None;
        }
        drop(guard);
        if last {
            self.dir.release_os_lock();
            self.dir.lock_cond.notify_all();
        }
    }
}

/// Normalizes a `name` the way `pathlib` does before composing
/// `Path(base) / name`: splits on `/`, drops every empty component (from a
/// leading, trailing, or doubled `/`) and every `.` component, and rejoins
/// with a single `/` between the survivors -- without resolving `..`
/// components, exactly like pathlib. An absolute `name` (starts with `/`)
/// is returned unchanged; [`StateDir::join`] relies on `Path::join`'s own
/// existing "an absolute joined path replaces the base" behaviour for that
/// case, which already matches pathlib's.
///
/// This crate is Unix-only (`std::os::unix::fs::*` is used throughout
/// `store.rs`), so a plain byte-wise `/`-split is exact here -- no need for
/// `Path::components()`, which (unlike pathlib) keeps a *leading* `.`
/// component rather than dropping it.
fn normalize_join_name(name: &str) -> String {
    if name.starts_with('/') {
        return name.to_string();
    }
    name.split('/')
        .filter(|component| !component.is_empty() && *component != ".")
        .collect::<Vec<_>>()
        .join("/")
}

/// `open(target, "r", encoding="utf-8")` + `[line.rstrip("\n") for line in
/// stream]`: Python's text mode applies *universal newline* translation,
/// recognizing `"\r\n"`, `"\r"`, and `"\n"` as line terminators (not just
/// `"\n"`), and iterating a stream never yields a trailing empty line for
/// text that ends in a terminator, while a final line with no terminator is
/// still yielded (as a short last element).
fn split_universal_newlines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                lines.push(std::mem::take(&mut current));
            }
            '\n' => {
                lines.push(std::mem::take(&mut current));
            }
            other => current.push(other),
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// The raw `OSError` CPython lets escape a `store.py` call site that has no
/// `except` around it (PORTING.md §3.5, measured scope: the administrator
/// CLI's `except FileNotFoundError` / `except OSError` handlers print exactly
/// this mapping, and nothing between the store and the CLI catches it).
///
/// The error is not a `ZeroPWError` in Python, so it carries
/// [`ErrorClass::ZeroPW`] with `name` set to the PEP 3151 `OSError` subclass
/// ([`pystr::os_error_class`]); `to_dict()` then renders what the CLI prints:
/// `{"error": <class>, "reason": "io_error", "detail": <strerror>}`, or
/// `{"error": "FileNotFoundError", "reason": "file_not_found"}` for `ENOENT`.
pub fn uncaught_os_error(error: &std::io::Error) -> Error {
    let class = pystr::os_error_class(error);
    if class == "FileNotFoundError" {
        return Error::subclass(ErrorClass::ZeroPW, class, "file_not_found", "");
    }
    Error::subclass(
        ErrorClass::ZeroPW,
        class,
        "io_error",
        pystr::os_error_strerror(error).unwrap_or_default(),
    )
}

/// `pathlib.PurePath.parent` for the paths this module builds: the lexical
/// parent, `.` for a single relative component, and the path itself for the
/// root (where `self.parent == self` in pathlib).
fn pathlib_parent(path: &Path) -> PathBuf {
    match path.parent() {
        None => path.to_path_buf(),
        Some(parent) if parent.as_os_str().is_empty() => PathBuf::from("."),
        Some(parent) => parent.to_path_buf(),
    }
}

/// CPython 3.12 `pathlib.Path.mkdir(mode, parents, exist_ok)`, returning the
/// raw `OSError` it would raise:
///
/// ```python
/// try:
///     os.mkdir(self, mode)
/// except FileNotFoundError:
///     if not parents or self.parent == self:
///         raise
///     self.parent.mkdir(parents=True, exist_ok=True)
///     self.mkdir(mode, parents=False, exist_ok=exist_ok)
/// except OSError:
///     if not exist_ok or not self.is_dir():
///         raise
/// ```
///
/// `mode` is applied by the `mkdir(2)` call itself (masked by the umask), so
/// there is never a window with a wider mode; missing parents get pathlib's
/// default `0o777`. Trying the leaf first matters for the error identity: a
/// regular file in place of a parent gives `NotADirectoryError` from the
/// leaf, not a `FileExistsError` from re-creating the parent.
pub(crate) fn path_mkdir(
    path: &Path,
    mode: u32,
    parents: bool,
    exist_ok: bool,
) -> std::io::Result<()> {
    match DirBuilder::new().mode(mode).create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
            let parent = pathlib_parent(path);
            if !parents || parent == path {
                return Err(error);
            }
            path_mkdir(&parent, 0o777, true, true)?;
            path_mkdir(path, mode, false, exist_ok)
        }
        Err(error) => {
            if !exist_ok || !path.is_dir() {
                Err(error)
            } else {
                Ok(())
            }
        }
    }
}

/// `target.parent.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)`, the
/// uncaught first step of `write_json`, `append_line` and `write_bytes`.
fn mkdir_parent(target: &Path) -> Result<(), Error> {
    path_mkdir(&pathlib_parent(target), DIR_MODE, true, true).map_err(|e| uncaught_os_error(&e))
}

/// `os.chmod(path, mode)`, uncaught in `StateDir.create`.
fn set_mode(path: &Path, mode: u32) -> Result<(), Error> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| uncaught_os_error(&e))
}

/// `write_json`'s temp name (store.py:97: `.{name}.{pid}.{tid}.tmp`), pid
/// *and* thread-id qualified so two threads in the same process never
/// collide on one temp path.
fn tmp_path_write_json(target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("state");
    let tid = format!("{:?}", thread::current().id());
    let tid: String = tid.chars().filter(|c| c.is_ascii_digit()).collect();
    let tmp_name = format!(".{name}.{}.{tid}.tmp", std::process::id());
    target.with_file_name(tmp_name)
}

/// `write_bytes`' own temp name (store.py:138: `.{name}.{pid}.tmp`) --
/// A-R3-4: deliberately *pid-only*, unlike [`tmp_path_write_json`]'s
/// pid-and-thread-id name, so two threads in the same process calling
/// `write_bytes` on the same `name` concurrently share one temp path. That
/// also means the leftover tmp file `write_bytes` intentionally does not
/// clean up on failure (store.py has no `except` clause unlinking it; see
/// [`StateDir::write_bytes`]'s own doc) has exactly this pid-only name, not
/// a thread-qualified one -- pinned by
/// `tests::write_json_cleans_tmp_on_failure_but_write_bytes_does_not`, which
/// asserts the exact leftover filename rather than just a prefix match.
fn tmp_path_write_bytes(target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("state");
    let tmp_name = format!(".{name}.{}.tmp", std::process::id());
    target.with_file_name(tmp_name)
}

fn path_str(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// One name from `tempfile._RandomNameSequence`: eight characters drawn
/// uniformly from `"abcdefghijklmnopqrstuvwxyz0123456789_"`, the suffix
/// alphabet and length of every `tempfile.mkstemp`/`mkdtemp` name.
pub fn tempfile_random_name() -> String {
    use rand::RngCore;
    const CHARACTERS: &[u8; 37] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
    let mut name = String::with_capacity(8);
    while name.len() < 8 {
        let mut byte = [0u8; 1];
        rand::rngs::OsRng.fill_bytes(&mut byte);
        // Rejection sampling keeps the choice uniform (`37 * 6 == 222`).
        if byte[0] < 222 {
            name.push(char::from(CHARACTERS[usize::from(byte[0] % 37)]));
        }
    }
    name
}

/// `store.now()`: seconds since the Unix epoch, like `time.time()`.
pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// `store.iso(ts)`: `time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))`
/// for a timestamp Python formats. Inside that range this is exactly
/// [`try_iso`]. Outside it CPython raises (see [`try_iso`]); this
/// `-> String` form instead returns the proleptic-Gregorian rendering of the
/// saturated `i64` second (`NaN` as `0`). A caller whose timestamp can come
/// from a file, configuration or peer (rather than a `Clock` reading) must
/// call [`try_iso`]/[`try_iso_int`] to reproduce Python's exception; the
/// callers that still use this form are listed in `rust/DEVIATIONS.md`'s
/// `iso` row.
pub fn iso(ts: Option<f64>) -> String {
    let ts = ts.unwrap_or_else(now);
    try_iso(Some(ts)).unwrap_or_else(|_| format_civil(ts.floor() as i64))
}

/// The built-in exception CPython's `store.iso` lets escape for a timestamp
/// it cannot format: `class_name` is `type(exc).__name__` and `message` is
/// `str(exc)`, measured against CPython 3.12.14 on Linux/glibc (the macOS
/// `errno`/`strerror` text is spelled per the Darwin headers and has not been
/// re-measured in this pass).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IsoError {
    pub class_name: &'static str,
    pub message: String,
}

impl IsoError {
    fn time_t_overflow() -> Self {
        IsoError {
            class_name: "OverflowError",
            message: "timestamp out of range for platform time_t".into(),
        }
    }
}

impl std::fmt::Display for IsoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.class_name, self.message)
    }
}

impl std::error::Error for IsoError {}

/// `store.iso(ts)` for a Python `float` (or `None`), with CPython's own
/// failure cases:
///
/// * `NaN` -> `ValueError("Invalid value NaN (not a number)")`;
/// * `floor(ts)` outside `[-2**63, 2**63)` (both infinities included) ->
///   `OverflowError("timestamp out of range for platform time_t")`
///   (`_PyTime_ObjectToTime_t` with `_PyTime_ROUND_FLOOR`);
/// * otherwise exactly [`try_iso_int`] of that floored second.
pub fn try_iso(ts: Option<f64>) -> Result<String, IsoError> {
    let ts = ts.unwrap_or_else(now);
    if ts.is_nan() {
        return Err(IsoError {
            class_name: "ValueError",
            message: "Invalid value NaN (not a number)".into(),
        });
    }
    const TIME_T_BOUND: f64 = 9_223_372_036_854_775_808.0; // 2**63
    let floored = ts.floor();
    if !(-TIME_T_BOUND..TIME_T_BOUND).contains(&floored) {
        return Err(IsoError::time_t_overflow());
    }
    iso_from_time_t(floored as i64)
}

/// `store.iso(ts)` for a Python `int` of any size (no float rounding, so a
/// value above `2**53` keeps its exact second).
///
/// * outside `time_t` (`[-2**63, 2**63 - 1]`) ->
///   `OverflowError("timestamp out of range for platform time_t")`;
/// * a year whose `tm_year` (`year - 1900`) does not fit a C `int` ->
///   `gmtime` fails with `EOVERFLOW`: `OSError`;
/// * a year above `INT_MAX` that `gmtime` still accepted: CPython's
///   `tm_year + 1900` wraps negative in `struct_time`, and `strftime`'s
///   `gettmarg` then raises `OverflowError("year out of range")`;
/// * otherwise the formatted string, with `%Y` as the platform renders it
///   (glibc: no padding, `-1`, `0`, `1`; Darwin: width 4, `-001`, `0000`,
///   `0001`).
pub fn try_iso_int(secs: &num_bigint::BigInt) -> Result<String, IsoError> {
    let secs = i64::try_from(secs).map_err(|_| IsoError::time_t_overflow())?;
    iso_from_time_t(secs)
}

const C_INT_MAX: i64 = i32::MAX as i64;
const C_INT_MIN: i64 = i32::MIN as i64;

fn iso_from_time_t(secs: i64) -> Result<String, IsoError> {
    let (year, ..) = civil_from_unix(secs);
    let tm_year = year - 1900;
    if !(C_INT_MIN..=C_INT_MAX).contains(&tm_year) {
        return Err(gmtime_eoverflow());
    }
    if year > C_INT_MAX {
        return Err(IsoError {
            class_name: "OverflowError",
            message: "year out of range".into(),
        });
    }
    Ok(format_civil(secs))
}

#[cfg(target_os = "linux")]
fn gmtime_eoverflow() -> IsoError {
    IsoError {
        class_name: "OSError",
        message: "[Errno 75] Value too large for defined data type".into(),
    }
}

#[cfg(not(target_os = "linux"))]
fn gmtime_eoverflow() -> IsoError {
    IsoError {
        class_name: "OSError",
        message: "[Errno 84] Value too large to be stored in data type".into(),
    }
}

fn format_civil(secs: i64) -> String {
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    let year = strftime_year(y);
    format!("{year}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

#[cfg(target_os = "linux")]
fn strftime_year(year: i64) -> String {
    year.to_string()
}

#[cfg(not(target_os = "linux"))]
fn strftime_year(year: i64) -> String {
    format!("{year:04}")
}

/// Civil (Gregorian) UTC date/time from a Unix timestamp in whole seconds.
/// Howard Hinnant's `civil_from_days` algorithm (public domain), which is
/// exact for the full `i64` range and matches `time.gmtime` for any date it
/// can represent.
fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let mut days = secs.div_euclid(86400);
    let mut rem = secs.rem_euclid(86400);
    let h = (rem / 3600) as u32;
    rem -= (h as i64) * 3600;
    let mi = (rem / 60) as u32;
    let s = (rem - (mi as i64) * 60) as u32;

    days += 719_468; // shift epoch from 1970-01-01 to 0000-03-01
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let doe = days - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, h, mi, s)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::errors::ErrorClass;

    fn new_state() -> (TempDir, StateDir) {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        (tmp, state)
    }

    #[test]
    fn create_twice_is_state_exists() {
        let (_tmp, state) = new_state();
        let err = state.create().unwrap_err();
        assert!(err.is(ErrorClass::StateError));
        assert_eq!(err.reason, "state_exists");
    }

    #[test]
    fn require_missing_is_state_missing() {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("nope"));
        let err = state.require().unwrap_err();
        assert_eq!(err.reason, "state_missing");
    }

    #[test]
    fn dir_and_file_modes() {
        let (_tmp, state) = new_state();
        let mode = fs::metadata(&state.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, DIR_MODE);
        state.write_json("x.json", &json!({"a": 1})).unwrap();
        let mode = fs::metadata(state.path.join("x.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, FILE_MODE);
    }

    #[test]
    fn write_read_json_round_trip_and_default() {
        let (_tmp, state) = new_state();
        assert_eq!(
            state.read_json("missing.json", json!(null)).unwrap(),
            json!(null)
        );
        assert_eq!(
            state.read_json("missing.json", json!({"d": 1})).unwrap(),
            json!({"d": 1})
        );
        state
            .write_json("doc.json", &json!({"b": 2, "a": 1}))
            .unwrap();
        let text = fs::read_to_string(state.path.join("doc.json")).unwrap();
        assert_eq!(text, "{\n  \"a\": 1,\n  \"b\": 2\n}");
        assert_eq!(
            state.read_json("doc.json", json!(null)).unwrap(),
            json!({"a": 1, "b": 2})
        );
    }

    #[test]
    fn write_json_is_atomic_no_tmp_left_behind() {
        let (_tmp, state) = new_state();
        state.write_json("a/b/doc.json", &json!({"x": 1})).unwrap();
        let entries: Vec<_> = fs::read_dir(state.path.join("a")).unwrap().collect();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn read_json_corrupt_raises_state_corrupt() {
        let (_tmp, state) = new_state();
        fs::write(state.path.join("bad.json"), b"{not json").unwrap();
        let err = state.read_json("bad.json", json!(null)).unwrap_err();
        assert!(err.is(ErrorClass::StateError));
        assert_eq!(err.reason, "state_corrupt");
        assert_eq!(err.detail, "bad.json");
    }

    #[test]
    fn append_line_rejects_embedded_newline() {
        let (_tmp, state) = new_state();
        let err = state.append_line("log.jsonl", "a\nb").unwrap_err();
        assert_eq!(err.reason, "state_invalid_line");
    }

    #[test]
    fn append_and_read_lines_with_limit() {
        let (_tmp, state) = new_state();
        for i in 0..5 {
            state.append_line("log.jsonl", &format!("line{i}")).unwrap();
        }
        let all = state.read_lines("log.jsonl", None).unwrap();
        assert_eq!(all, vec!["line0", "line1", "line2", "line3", "line4"]);
        let last2 = state.read_lines("log.jsonl", Some(2)).unwrap();
        assert_eq!(last2, vec!["line3", "line4"]);
        assert_eq!(
            state.read_lines("nope.jsonl", None).unwrap(),
            Vec::<String>::new()
        );
    }

    // A-10: Python's text-mode `open()` treats "\r\n", "\r", and "\n" all as
    // line terminators (universal newlines), not just "\n".
    #[test]
    fn read_lines_splits_on_any_universal_newline_terminator() {
        let (_tmp, state) = new_state();
        fs::write(state.path.join("mixed.txt"), b"a\rb\nc\r\nd").unwrap();
        assert_eq!(
            state.read_lines("mixed.txt", None).unwrap(),
            vec!["a", "b", "c", "d"]
        );
        // A file ending in a terminator yields no trailing empty line; one
        // ending mid-line still yields that final partial line.
        fs::write(state.path.join("trailing.txt"), b"x\ny\n").unwrap();
        assert_eq!(
            state.read_lines("trailing.txt", None).unwrap(),
            vec!["x", "y"]
        );
        fs::write(state.path.join("no_trailing.txt"), b"x\ny").unwrap();
        assert_eq!(
            state.read_lines("no_trailing.txt", None).unwrap(),
            vec!["x", "y"]
        );
        assert_eq!(
            state.read_lines("empty_missing.txt", None).unwrap(),
            Vec::<String>::new()
        );
    }

    // A-4: Python's `lines[-limit:]` treats `limit == 0` as `lines[-0:]` ==
    // `lines[0:]` -- the whole list, not an empty slice.
    #[test]
    fn read_lines_limit_zero_returns_everything() {
        let (_tmp, state) = new_state();
        for i in 0..5 {
            state.append_line("log.jsonl", &format!("line{i}")).unwrap();
        }
        assert_eq!(
            state.read_lines("log.jsonl", Some(0)).unwrap(),
            vec!["line0", "line1", "line2", "line3", "line4"]
        );
    }

    /// The administrator CLI's rendering of whatever escaped a `StateDir`
    /// call in Python (`admin_cli.main`'s handlers, in order). Used to compare
    /// the observable outcome of an uncaught built-in exception, not merely
    /// its class.
    const PY_CLI_RENDER: &str = r#"
import json, os, tempfile
from zeropw.errors import ZeroPWError
from zeropw.store import StateDir
def render(exc):
    if isinstance(exc, ZeroPWError):
        return exc.to_dict()
    if isinstance(exc, FileNotFoundError):
        return {"error": "FileNotFoundError", "reason": "file_not_found"}
    if isinstance(exc, OSError):
        return {"error": type(exc).__name__, "reason": "io_error", "detail": exc.strerror or ""}
    if isinstance(exc, (KeyError, TypeError, AttributeError, ValueError)):
        return {"error": "StateError", "reason": "state_corrupt", "detail": type(exc).__name__}
    return {"error": type(exc).__name__, "reason": "internal_error"}
"#;

    type Setup = fn(&Path, &StateDir);
    type Op = fn(&Path, &StateDir) -> Result<(), Error>;

    /// (python setup, python op, rust setup, rust op). `d` is the temporary
    /// directory, `state` a created `StateDir` at `d/state`; the setup runs
    /// before the op and every mode change is undone before cleanup.
    #[allow(clippy::type_complexity)]
    const UNCAUGHT_CASES: &[(&str, &str, Setup, Op)] = &[
        (
            "",
            "state.subdir('a/b')",
            |_, _| {},
            |_, s| s.subdir("a/b").map(drop),
        ),
        (
            "open(os.path.join(state.path, 'occupied'), 'w').close()",
            "state.subdir('occupied')",
            |_, s| fs::write(s.path.join("occupied"), b"").unwrap(),
            |_, s| s.subdir("occupied").map(drop),
        ),
        (
            "os.mkdir(os.path.join(d, 'ro'), 0o500)",
            "StateDir(os.path.join(d, 'ro', 'state')).create()",
            |d, _| {
                fs::create_dir(d.join("ro")).unwrap();
                fs::set_permissions(d.join("ro"), fs::Permissions::from_mode(0o500)).unwrap();
            },
            |d, _| StateDir::new(d.join("ro").join("state")).create(),
        ),
        (
            "os.mkdir(os.path.join(state.path, '.lock'))",
            "state.lock().__enter__()",
            |_, s| fs::create_dir(s.path.join(".lock")).unwrap(),
            |_, s| s.lock().map(drop),
        ),
        (
            "os.chmod(state.path, 0o500)",
            "state.write_json('doc.json', {'a': 1})",
            |_, s| fs::set_permissions(&s.path, fs::Permissions::from_mode(0o500)).unwrap(),
            |_, s| s.write_json("doc.json", &json!({"a": 1})),
        ),
        (
            "open(os.path.join(state.path, 'occupied'), 'w').close()",
            "state.write_json('occupied/doc.json', {'a': 1})",
            |_, s| fs::write(s.path.join("occupied"), b"").unwrap(),
            |_, s| s.write_json("occupied/doc.json", &json!({"a": 1})),
        ),
        (
            "open(os.path.join(state.path, 'occupied'), 'w').close()",
            "state.write_json('occupied/sub/doc.json', {'a': 1})",
            |_, s| fs::write(s.path.join("occupied"), b"").unwrap(),
            |_, s| s.write_json("occupied/sub/doc.json", &json!({"a": 1})),
        ),
        (
            "os.mkdir(os.path.join(state.path, 'doc.json'))",
            "state.write_json('doc.json', {'a': 1})",
            |_, s| fs::create_dir(s.path.join("doc.json")).unwrap(),
            |_, s| s.write_json("doc.json", &json!({"a": 1})),
        ),
        (
            "os.chmod(state.path, 0o500)",
            "state.write_bytes('blob.bin', b'x')",
            |_, s| fs::set_permissions(&s.path, fs::Permissions::from_mode(0o500)).unwrap(),
            |_, s| s.write_bytes("blob.bin", b"x"),
        ),
        (
            "open(os.path.join(state.path, 'occupied'), 'w').close()",
            "state.write_bytes('occupied/blob.bin', b'x')",
            |_, s| fs::write(s.path.join("occupied"), b"").unwrap(),
            |_, s| s.write_bytes("occupied/blob.bin", b"x"),
        ),
        (
            "os.mkdir(os.path.join(state.path, 'blob.bin'))",
            "state.write_bytes('blob.bin', b'x')",
            |_, s| fs::create_dir(s.path.join("blob.bin")).unwrap(),
            |_, s| s.write_bytes("blob.bin", b"x"),
        ),
        (
            "os.chmod(state.path, 0o500)",
            "state.append_line('log.jsonl', 'hello')",
            |_, s| fs::set_permissions(&s.path, fs::Permissions::from_mode(0o500)).unwrap(),
            |_, s| s.append_line("log.jsonl", "hello"),
        ),
        (
            "open(os.path.join(state.path, 'occupied'), 'w').close()",
            "state.append_line('occupied/log.jsonl', 'hello')",
            |_, s| fs::write(s.path.join("occupied"), b"").unwrap(),
            |_, s| s.append_line("occupied/log.jsonl", "hello"),
        ),
        (
            "os.mkdir(os.path.join(state.path, 'log.jsonl'))",
            "state.append_line('log.jsonl', 'hello')",
            |_, s| fs::create_dir(s.path.join("log.jsonl")).unwrap(),
            |_, s| s.append_line("log.jsonl", "hello"),
        ),
        (
            "os.mkdir(os.path.join(state.path, 'adir'))",
            "state.read_lines('adir')",
            |_, s| fs::create_dir(s.path.join("adir")).unwrap(),
            |_, s| s.read_lines("adir", None).map(drop),
        ),
        (
            "open(os.path.join(state.path, 'bad.txt'), 'wb').write(b'line one\\n\\xffnot utf8\\n')",
            "state.read_lines('bad.txt')",
            |_, s| fs::write(s.path.join("bad.txt"), b"line one\n\xffnot utf8\n").unwrap(),
            |_, s| s.read_lines("bad.txt", None).map(drop),
        ),
        (
            "open(os.path.join(state.path, 'secret.txt'), 'w').close(); os.chmod(os.path.join(state.path, 'secret.txt'), 0)",
            "state.read_lines('secret.txt')",
            |_, s| {
                fs::write(s.path.join("secret.txt"), b"").unwrap();
                fs::set_permissions(s.path.join("secret.txt"), fs::Permissions::from_mode(0))
                    .unwrap();
            },
            |_, s| s.read_lines("secret.txt", None).map(drop),
        ),
    ];

    /// PORTING.md §3.5/§3c/§3d: every `store.py` call site without an
    /// `except` lets the raw `OSError` (or `UnicodeDecodeError`) escape to
    /// the administrator CLI, which prints a fixed rendering of it. The
    /// Rust error must render identically, so each case runs the real Python
    /// operation and compares the CLI-visible dictionary.
    #[test]
    fn uncaught_store_failures_render_like_python() {
        let mut script = String::from(PY_CLI_RENDER);
        for (setup, op, _, _) in UNCAUGHT_CASES {
            script.push_str(&format!(
                "with tempfile.TemporaryDirectory() as d:\n    state = StateDir(os.path.join(d, 'state'))\n    state.create()\n    {setup}\n    try:\n        {op}\n        out = 'ok'\n    except Exception as exc:\n        out = render(exc)\n    for root, dirs, files in os.walk(d):\n        for name in dirs + files:\n            os.chmod(os.path.join(root, name), 0o700)\n    print(json.dumps(out, sort_keys=True))\n"
            ));
        }
        let python = crate::oracle::python(&script);
        let python: Vec<Value> = python
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(python.len(), UNCAUGHT_CASES.len());
        for ((_, op, setup, run), expected) in UNCAUGHT_CASES.iter().zip(python) {
            let tmp = TempDir::new().unwrap();
            let state = StateDir::new(tmp.path().join("state"));
            state.create().unwrap();
            setup(tmp.path(), &state);
            let outcome = match run(tmp.path(), &state) {
                Ok(()) => json!("ok"),
                Err(error) => error.to_dict(),
            };
            for entry in walk(tmp.path()) {
                let _ = fs::set_permissions(entry, fs::Permissions::from_mode(0o700));
            }
            assert_ne!(expected, json!("ok"), "{op}: Python must fail here");
            assert_eq!(outcome, expected, "{op}");
        }
    }

    fn walk(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                out.push(path.clone());
                if path.is_dir() {
                    out.extend(walk(&path));
                }
            }
        }
        out
    }

    /// `subdir` has no `parents=True`: the missing parent is never created.
    #[test]
    fn subdir_with_missing_parent_does_not_create_it() {
        let (_tmp, state) = new_state();
        assert!(state.subdir("a/b").is_err());
        assert!(!state.path.join("a").exists());
    }

    // A-R2-5: `mkdir_p`'s leaf (via `create()` and `subdir()`) must land on
    // the requested mode atomically at the `mkdir(2)` syscall (masked by
    // umask, matching `os.mkdir(path, mode)`), not via a default-mode
    // create followed by a separate `chmod` that leaves a transient wider
    // window. Exercised under two umasks by re-executing this same test
    // binary in a child process with the umask set first via a wrapping
    // shell (never mutating the umask of the parent test process, which is
    // shared across every concurrently running test thread): `0o077` (a
    // realistic umask that leaves DIR_MODE's owner bits untouched -- both
    // `create()` and `subdir()` must land on exactly `DIR_MODE`) and the
    // pathological owner-masking `0o700` DEVIATIONS.md used to document as
    // a deliberate, more-restrictive-than-Python divergence -- this port now
    // matches Python byte-for-byte instead, including Python's own
    // `create()`-fixes-it-up-afterward-but-`subdir()`-does-not asymmetry.
    #[test]
    fn create_and_subdir_apply_dir_mode_under_various_umasks() {
        if std::env::var_os("ZEROPW_UMASK_CHILD_TEST").is_some() {
            run_umask_child_check();
            return;
        }
        let exe = std::env::current_exe().expect("current_exe");
        for umask in ["077", "700"] {
            let script = format!(
                "umask {umask} && exec \"$0\" store::tests::create_and_subdir_apply_dir_mode_under_various_umasks --exact --nocapture"
            );
            let output = std::process::Command::new("sh")
                .arg("-c")
                .arg(&script)
                .arg(&exe)
                .env("ZEROPW_UMASK_CHILD_TEST", "1")
                .output()
                .expect("failed to spawn umask child");
            assert!(
                output.status.success(),
                "umask {umask} child failed:\nstdout={}\nstderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    /// Runs inside the umask-sandboxed child process spawned by
    /// [`create_and_subdir_apply_dir_mode_under_various_umasks`]: creates a
    /// state dir (`create()`) and a subdirectory of it (`subdir()`) under
    /// whatever umask the parent's shell wrapper set, and cross-checks both
    /// resulting modes against `zeropw.store.StateDir` run under the same
    /// (inherited) umask.
    fn run_umask_child_check() {
        // `TempDir::new()`'s own directory creation is itself subject to the
        // umask we just set (POSIX `mkdir`/`mkdtemp` always masks the
        // requested mode by the process umask); under the pathological
        // `0o700` case that would otherwise leave the container itself with
        // mode `0`, making it impossible to create anything inside it. Fix
        // the container's own mode up front so only `StateDir::create`/
        // `subdir`'s behaviour -- the thing actually under test -- is
        // exercised by the umask.
        let tmp = TempDir::new().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let rust_state = StateDir::new(tmp.path().join("rust-state"));
        rust_state.create().unwrap();
        let rust_create_mode = dir_mode(&rust_state.path);
        let rust_sub = rust_state.subdir("audit").unwrap();
        let rust_subdir_mode = dir_mode(&rust_sub);

        // Both modes are captured above, so the directories have served their
        // purpose. Restore traversable modes before anything can return early:
        // under the pathological `umask 700` case `create()`/`subdir()`
        // legitimately produce mode `0`, and `TempDir`'s `Drop` cannot delete
        // a directory it cannot open -- it ignores the failure, which is what
        // left two `.tmp*` containers behind on every suite run.
        let _ = fs::set_permissions(&rust_sub, fs::Permissions::from_mode(0o700));
        let _ = fs::set_permissions(&rust_state.path, fs::Permissions::from_mode(0o700));

        let py_tmp = TempDir::new().unwrap();
        fs::set_permissions(py_tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let script = format!(
            r#"
from zeropw.store import StateDir
state = StateDir({:?})
state.create()
sub = state.subdir("audit")
import os
print(oct(os.stat(state.path).st_mode & 0o777))
print(oct(os.stat(sub).st_mode & 0o777))
"#,
            py_tmp.path().join("py-state").to_string_lossy()
        );
        let out = crate::oracle::python(&script);
        let mut lines = out.lines();
        let py_create_mode =
            u32::from_str_radix(lines.next().unwrap().trim_start_matches("0o"), 8).unwrap();
        let py_subdir_mode =
            u32::from_str_radix(lines.next().unwrap().trim_start_matches("0o"), 8).unwrap();

        // Same for the directories Python created under the same umask.
        let py_state = py_tmp.path().join("py-state");
        let _ = fs::set_permissions(py_state.join("audit"), fs::Permissions::from_mode(0o700));
        let _ = fs::set_permissions(&py_state, fs::Permissions::from_mode(0o700));

        assert_eq!(
            rust_create_mode, py_create_mode,
            "create() mode must match Python under this umask"
        );
        assert_eq!(
            rust_subdir_mode, py_subdir_mode,
            "subdir() mode must match Python under this umask"
        );
    }

    // A-8: Python's `write_json` unlinks its tmp file on any failure
    // (including a failed final `os.replace`), but `write_bytes` has no
    // such cleanup and leaves the tmp file behind. A write "to a name that
    // is an existing directory" makes the write itself succeed but the
    // rename fail (`EISDIR`/`ENOTDIR`), exercising exactly that path.
    #[test]
    fn write_json_cleans_tmp_on_failure_but_write_bytes_does_not() {
        let (_tmp, state) = new_state();

        fn tmp_leftovers(dir: &Path, stem: &str) -> Vec<String> {
            fs::read_dir(dir)
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with(&format!(".{stem}.")) && n.ends_with(".tmp"))
                .collect()
        }

        fs::create_dir(state.path.join("doc.json")).unwrap();
        let err = state.write_json("doc.json", &json!({"a": 1})).unwrap_err();
        assert_eq!(err.reason, "state_write_failed");
        assert!(
            tmp_leftovers(&state.path, "doc.json").is_empty(),
            "write_json must unlink its tmp file on failure"
        );

        fs::create_dir(state.path.join("blob.bin")).unwrap();
        let err = state.write_bytes("blob.bin", b"x").unwrap_err();
        assert_eq!(err.reason, "state_write_failed");
        // A-R3-4: not just "some tmp file was left behind" -- the exact
        // pid-only name Python's `write_bytes` uses (store.py:138), not the
        // pid-*and*-thread-id name `write_json` uses (store.py:97).
        assert_eq!(
            tmp_leftovers(&state.path, "blob.bin"),
            vec![format!(".blob.bin.{}.tmp", std::process::id())],
            "write_bytes must leave its tmp file behind on failure, with Python's pid-only name"
        );
    }

    #[test]
    fn write_read_bytes_round_trip_and_missing() {
        let (_tmp, state) = new_state();
        state.write_bytes("blob.bin", b"\x00\x01\xff").unwrap();
        assert_eq!(state.read_bytes("blob.bin").unwrap(), vec![0, 1, 255]);
        let err = state.read_bytes("missing.bin").unwrap_err();
        assert_eq!(err.reason, "state_missing");
    }

    #[test]
    fn exists_reflects_filesystem() {
        let (_tmp, state) = new_state();
        assert!(!state.exists("f"));
        state.write_bytes("f", b"x").unwrap();
        assert!(state.exists("f"));
    }

    #[test]
    fn subdir_creates_and_is_idempotent() {
        let (_tmp, state) = new_state();
        let p1 = state.subdir("audit").unwrap();
        let p2 = state.subdir("audit").unwrap();
        assert_eq!(p1, p2);
        assert!(p1.is_dir());
    }

    fn dir_mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    // A-7: Python's `Path.mkdir(mode=DIR_MODE, exist_ok=True)` never even
    // calls `os.mkdir` when the target already exists, so a pre-existing
    // directory's mode is left exactly as found -- it is not reset to
    // `DIR_MODE` on every `subdir`/`write_json`/`append_line`/`lock` call.
    #[test]
    fn mkdir_p_does_not_chmod_pre_existing_directories() {
        let (_tmp, state) = new_state();

        // The state root itself, pre-existing with a non-default mode.
        fs::set_permissions(&state.path, fs::Permissions::from_mode(0o750)).unwrap();
        assert_eq!(dir_mode(&state.path), 0o750);

        // `subdir` on an already-existing directory.
        let audit_dir = state.path.join("audit");
        fs::create_dir(&audit_dir).unwrap();
        fs::set_permissions(&audit_dir, fs::Permissions::from_mode(0o755)).unwrap();
        let got = state.subdir("audit").unwrap();
        assert_eq!(got, audit_dir);
        assert_eq!(dir_mode(&audit_dir), 0o755, "subdir must not re-chmod");

        // `write_json`'s parent-directory creation on an already-existing
        // directory.
        let sub_dir = state.path.join("sub");
        fs::create_dir(&sub_dir).unwrap();
        fs::set_permissions(&sub_dir, fs::Permissions::from_mode(0o750)).unwrap();
        state.write_json("sub/doc.json", &json!({"a": 1})).unwrap();
        assert_eq!(
            dir_mode(&sub_dir),
            0o750,
            "write_json must not re-chmod an existing parent dir"
        );

        // `append_line`'s parent-directory creation on an already-existing
        // directory.
        let log_dir = state.path.join("logs");
        fs::create_dir(&log_dir).unwrap();
        fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o755)).unwrap();
        state.append_line("logs/x.jsonl", "hello").unwrap();
        assert_eq!(
            dir_mode(&log_dir),
            0o755,
            "append_line must not re-chmod an existing parent dir"
        );

        // `lock()`'s mkdir_p on the (already-existing, re-chmodded) state
        // root must not reset it back to DIR_MODE either.
        let _g = state.lock().unwrap();
        drop(_g);
        assert_eq!(
            dir_mode(&state.path),
            0o750,
            "lock() must not re-chmod the pre-existing state root"
        );

        // A freshly created directory still gets DIR_MODE.
        let fresh = state.subdir("fresh").unwrap();
        assert_eq!(dir_mode(&fresh), DIR_MODE);
    }

    #[test]
    fn lock_is_reentrant_same_thread() {
        let (_tmp, state) = new_state();
        let _outer = state.lock().unwrap();
        let _inner = state.lock().unwrap(); // must not deadlock
    }

    #[test]
    fn lock_serialises_across_threads() {
        let (_tmp, state) = new_state();
        let state = Arc::new(state);
        let counter = Arc::new(AtomicU32::new(0));
        let overlap = Arc::new(AtomicU32::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let state = state.clone();
            let counter = counter.clone();
            let overlap = overlap.clone();
            handles.push(thread::spawn(move || {
                let _g = state.lock().unwrap();
                let before = counter.fetch_add(1, Ordering::SeqCst);
                if before != 0 {
                    overlap.fetch_add(1, Ordering::SeqCst);
                }
                thread::sleep(std::time::Duration::from_millis(5));
                counter.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(
            overlap.load(Ordering::SeqCst),
            0,
            "two threads held the lock at once"
        );
    }

    #[test]
    fn iso_formats_like_python_gmtime_and_floors_fractional_seconds() {
        assert_eq!(iso(Some(1_700_000_000.0)), "2023-11-14T22:13:20Z");
        assert_eq!(iso(Some(1.999)), "1970-01-01T00:00:01Z");
        assert_eq!(iso(Some(2.0)), "1970-01-01T00:00:02Z");
        assert_eq!(iso(Some(-0.5)), "1969-12-31T23:59:59Z");
        assert_eq!(iso(Some(0.0)), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn iso_matches_platform_strftime_year_width() {
        #[cfg(target_os = "linux")]
        {
            assert_eq!(iso(Some(-62_135_596_800.0)), "1-01-01T00:00:00Z");
            assert_eq!(iso(Some(-62_167_219_200.0)), "0-01-01T00:00:00Z");
            assert_eq!(iso(Some(-62_167_219_201.0)), "-1-12-31T23:59:59Z");
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(iso(Some(-62_135_596_800.0)), "0001-01-01T00:00:00Z");
            assert_eq!(iso(Some(-62_167_219_200.0)), "0000-01-01T00:00:00Z");
            assert_eq!(iso(Some(-62_167_219_201.0)), "-001-12-31T23:59:59Z");
        }
    }

    // A-R4-1 (HIGH, regression fix): the finding's real-world repro --
    // `write_json` a document nested at exactly `pyjson::MAX_JSON_DEPTH`,
    // then `read_json` it back -- driven entirely from a deliberately small
    // (2 MiB) stack thread, matching a real trusted-process thread (not a
    // dedicated large-stack one). Before this fix, `write_json`'s call into
    // `pyjson::dumps` (store.rs:222) had no depth guard of its own at all
    // and could abort the whole process (killing every other thread with
    // it) on exactly this path, even though `read_json`/`pyjson::loads`
    // already accepted the same depth safely since A-R3-1.
    #[test]
    fn write_json_then_read_json_round_trips_at_max_json_depth() {
        let (_tmp, state) = new_state();
        let state = Arc::new(state);
        let state2 = state.clone();
        let handle = std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(move || {
                let mut doc = json!(1);
                for _ in 0..pyjson::MAX_JSON_DEPTH {
                    doc = Value::Array(vec![doc]);
                }
                state2
                    .write_json("deep.json", &doc)
                    .expect("write_json at MAX_JSON_DEPTH should succeed");
                let read_back = state2
                    .read_json("deep.json", json!(null))
                    .expect("read_json at MAX_JSON_DEPTH should succeed");
                assert_eq!(read_back, doc);
            })
            .unwrap();
        handle.join().unwrap();
    }

    // A-R4-1: one level past `pyjson::MAX_JSON_DEPTH`, `write_json` must
    // return a clean `StateError`, not abort the process -- `pyjson::dumps`
    // now rejects the over-deep document before `write_json`'s own
    // `map_err` ever sees anything but a normal error value.
    #[test]
    fn write_json_one_level_past_max_json_depth_is_state_write_failed() {
        let (_tmp, state) = new_state();
        let mut doc = json!(1);
        for _ in 0..(pyjson::MAX_JSON_DEPTH + 1) {
            doc = Value::Array(vec![doc]);
        }
        let err = state.write_json("too_deep.json", &doc).unwrap_err();
        assert!(err.is(ErrorClass::StateError));
        assert_eq!(err.reason, "state_write_failed");
    }

    // A-R7-2: `normalize_join_name` must drop a trailing `/`, a doubled
    // `/`, and a `.` component exactly like `pathlib` does when composing
    // `Path(base) / name`, while leaving `..` components unresolved (see
    // the oracle test below for the real-`python3.12`-driven version of
    // this same table).
    #[test]
    fn normalize_join_name_matches_pathlib_shape() {
        let cases: &[(&str, &str)] = &[
            ("sub", "sub"),
            ("sub/", "sub"),
            ("sub//", "sub"),
            ("./sub", "sub"),
            ("sub/./x", "sub/x"),
            ("a//b", "a/b"),
            ("a/b/", "a/b"),
            ("a/./b/", "a/b"),
            ("..", ".."),
            ("../escape", "../escape"),
            ("sub/../other", "sub/../other"),
            (".", ""),
        ];
        for (input, want) in cases {
            assert_eq!(normalize_join_name(input), *want, "input: {input:?}");
        }
    }

    // A-R7-2: the reviewer's exact repro -- `<state>/sub` is an existing
    // regular file holding `{"k":1}`; every `StateDir` operation on the
    // trailing-slash name `"sub/"` must behave exactly as it would on
    // `"sub"`, not diverge the way `self.path.join("sub/")` did (a
    // `PathBuf` ending in `/`, which the kernel requires to name a
    // directory). Measured against real `python3.12`
    // (`pathlib_join_matches_python_for_normalization_cases` below) that
    // `read_json("sub/")`, `read_lines("sub/")`, `read_bytes("sub/")`,
    // `exists("sub/")`, `write_json("sub/", ...)`, and
    // `append_line("sub/", ...)` all succeed against the *same* file
    // `"sub"` names, in both languages -- this test pins the Rust side of
    // that equivalence directly (the fail-open direction the finding
    // flagged: before this fix, `read_json("sub/")` silently returned the
    // caller's default instead of the stored document).
    #[test]
    fn state_dir_operations_normalize_a_trailing_slash_like_pathlib() {
        let (_tmp, state) = new_state();
        state.write_json("sub", &json!({"k": 1})).unwrap();

        assert_eq!(
            state.read_json("sub/", json!(null)).unwrap(),
            json!({"k": 1}),
            "read_json must not silently fall back to the default"
        );
        assert!(state.exists("sub/"));
        let bytes = state.read_bytes("sub/").unwrap();
        assert!(String::from_utf8(bytes).unwrap().contains("\"k\""));

        // append_line/read_lines against a fresh trailing-slash name.
        state.append_line("lines/", "line one").unwrap();
        assert_eq!(state.read_lines("lines/", None).unwrap(), vec!["line one"]);
        assert_eq!(
            state.read_lines("lines", None).unwrap(),
            vec!["line one"],
            "the slash-free name must see the same file"
        );

        // write_json/write_bytes through a trailing-slash name land on the
        // slash-free file.
        state.write_json("written/", &json!({"v": 2})).unwrap();
        assert_eq!(
            state.read_json("written", json!(null)).unwrap(),
            json!({"v": 2})
        );

        // subdir: doubled slash and a leading "./" component (the parent
        // must already exist -- `subdir` has no `parents=True`, matching
        // Python's own `target.mkdir(mode=DIR_MODE, exist_ok=True)`).
        state.subdir("nested").unwrap();
        let dir = state.subdir("nested//dir").unwrap();
        assert!(dir.is_dir());
        assert_eq!(dir, state.path.join("nested/dir"));
        let dir2 = state.subdir("./nested/dir2").unwrap();
        assert!(dir2.is_dir());
        assert_eq!(dir2, state.path.join("nested/dir2"));
    }

    // A-R7-2: differential confirmation that `normalize_join_name`'s table
    // matches real `python3.12` `pathlib.Path.__truediv__` -- trailing
    // slash, doubled slash, a `./` component, and an unresolved `..`
    // component, as the finding specifically asked to pin.
    #[test]
    fn pathlib_join_matches_python_for_normalization_cases() {
        let names = [
            "sub",
            "sub/",
            "sub//",
            "./sub",
            "sub/./x",
            "a//b",
            "a/b/",
            "a/./b/",
            "..",
            "../escape",
            "sub/../other",
        ];
        let script = format!(
            r#"
from pathlib import Path
base = Path("/tmp/zpw-a-r7-2-base")
for name in {names:?}:
    print(base / name)
"#
        );
        let out = crate::oracle::python(&script);
        let want: Vec<&str> = out.lines().collect();
        assert_eq!(want.len(), names.len());
        for (name, want) in names.iter().zip(want.iter()) {
            let base = Path::new("/tmp/zpw-a-r7-2-base");
            let got = base.join(normalize_join_name(name));
            assert_eq!(got, Path::new(want), "name: {name:?}");
        }
    }
}
