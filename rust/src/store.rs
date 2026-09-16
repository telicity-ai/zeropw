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

use crate::errors::Error;
use crate::pyjson::{self, DumpOptions};
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

    // ------------------------------------------------------------------ setup
    /// `StateDir.create`: `self.path.mkdir(mode=DIR_MODE, parents=True)` then
    /// an unconditional `os.chmod(self.path, DIR_MODE)`. A-R2-7: Python only
    /// raises `StateError("state_exists")` from the initial `path.exists()`
    /// check above; any other `mkdir` failure (permission denied, disk full,
    /// ...) is an uncaught `OSError`, not `StateError("state_exists")` --
    /// PORTING.md §3.5 applies (`rust/DEVIATIONS.md`), so a non-EEXIST mkdir
    /// failure here gets a distinct reason (`state_write_failed`) instead of
    /// being folded into `state_exists`.
    pub fn create(&self) -> Result<(), Error> {
        if self.path.exists() {
            return Err(Error::state("state_exists").with_detail(path_str(&self.path)));
        }
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|_| {
                Error::state("state_write_failed").with_detail(path_str(&self.path))
            })?;
        }
        match mkdir_exact(&self.path, DIR_MODE) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(Error::state("state_exists").with_detail(path_str(&self.path)));
            }
            Err(_) => {
                return Err(Error::state("state_write_failed").with_detail(path_str(&self.path)));
            }
        }
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
    /// the one `mkdir` call site in `store.py` that omits `parents=True`.
    /// A-R2-7: a missing parent therefore makes Python's `os.mkdir` raise an
    /// uncaught `FileNotFoundError`, not a `StateError` -- fail *closed*
    /// here (PORTING.md §3.5, `rust/DEVIATIONS.md`) rather than the
    /// previous fail-*open* behaviour of silently creating the missing
    /// parent via `mkdir_p`.
    pub fn subdir(&self, name: &str) -> Result<PathBuf, Error> {
        let target = self.path.join(name);
        mkdir_leaf(&target)?;
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

    #[allow(unsafe_code)]
    fn acquire_os_lock(&self) -> Result<File, Error> {
        mkdir_p(&self.path)?;
        let lock_path = self.path.join(".lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(FILE_MODE)
            .open(&lock_path)
            .map_err(|e| {
                Error::state("state_lock_failed")
                    .with_detail(format!("{}: {e}", path_str(&lock_path)))
            })?;
        // SAFETY: `file` owns a valid, open file descriptor for the
        // lifetime of this call; `flock` only touches the kernel's lock
        // table for that fd and does not alias Rust-managed memory. This is
        // the crate's one allowed `unsafe` (rust/PORTING.md engineering rules).
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(Error::state("state_lock_failed").with_detail(path_str(&lock_path)));
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
        let target = self.path.join(name);
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
    pub fn write_json(&self, name: &str, value: &Value) -> Result<(), Error> {
        let target = self.path.join(name);
        if let Some(parent) = target.parent() {
            mkdir_p(parent)?;
        }
        let text = pyjson::dumps(value, DumpOptions::pretty_sorted())
            .map_err(|_| Error::state("state_write_failed").with_detail(name))?;
        let tmp = tmp_path(&target);
        let result = (|| -> std::io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(FILE_MODE)
                .open(&tmp)?;
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

    /// Append one line and fsync. Port of `StateDir.append_line`.
    pub fn append_line(&self, name: &str, line: &str) -> Result<(), Error> {
        if line.contains('\n') {
            return Err(Error::state("state_invalid_line").with_detail(name));
        }
        let target = self.path.join(name);
        if let Some(parent) = target.parent() {
            mkdir_p(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(FILE_MODE)
            .open(&target)
            .map_err(|_| Error::state("state_write_failed").with_detail(name))?;
        let mut buf = line.as_bytes().to_vec();
        buf.push(b'\n');
        file.write_all(&buf)
            .map_err(|_| Error::state("state_write_failed").with_detail(name))?;
        file.sync_all()
            .map_err(|_| Error::state("state_write_failed").with_detail(name))?;
        Ok(())
    }

    /// `StateDir.read_lines`.
    pub fn read_lines(&self, name: &str, limit: Option<usize>) -> Result<Vec<String>, Error> {
        let target = self.path.join(name);
        if !target.exists() {
            return Ok(Vec::new());
        }
        let text = fs::read_to_string(&target)
            .map_err(|_| Error::state("state_corrupt").with_detail(name))?;
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
    pub fn write_bytes(&self, name: &str, data: &[u8]) -> Result<(), Error> {
        let target = self.path.join(name);
        if let Some(parent) = target.parent() {
            mkdir_p(parent)?;
        }
        let tmp = tmp_path(&target);
        let result = (|| -> std::io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(FILE_MODE)
                .open(&tmp)?;
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
        let target = self.path.join(name);
        let mut buf = Vec::new();
        File::open(&target)
            .and_then(|mut f| f.read_to_end(&mut buf))
            .map_err(|_| Error::state("state_missing").with_detail(name))?;
        Ok(buf)
    }

    /// `StateDir.exists`.
    pub fn exists(&self, name: &str) -> bool {
        self.path.join(name).exists()
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

/// `DirBuilder::new().mode(mode).create(path)`: creates exactly `path` (no
/// parents) with `mode`, applied atomically at the `mkdir(2)` syscall level
/// (masked by the process umask) -- the direct equivalent of Python's
/// `os.mkdir(path, mode)` / `Path.mkdir(mode=mode)`. Unlike creating the
/// directory with a default mode and `chmod`-ing it afterward (the previous
/// approach here, A-R2-5), there is no window where the directory exists
/// with a wider mode than requested.
fn mkdir_exact(path: &Path, mode: u32) -> std::io::Result<()> {
    DirBuilder::new().mode(mode).create(path)
}

/// Port of `target.mkdir(mode=DIR_MODE, exist_ok=True)`: creates only the
/// leaf `path` (no missing parent is created) with `DIR_MODE`, applied
/// atomically per [`mkdir_exact`]. `exist_ok=True` means a pre-existing
/// directory is left with whatever mode it already had -- not re-chmod'd to
/// `DIR_MODE` -- matching Python's `os.mkdir` never even being attempted in
/// that case.
fn mkdir_leaf(path: &Path) -> Result<(), Error> {
    if path.is_dir() {
        return Ok(());
    }
    match mkdir_exact(path, DIR_MODE) {
        Ok(()) => Ok(()),
        // Lost a create race to another thread/process between the is_dir()
        // check above and here, or the parent already existed with a
        // pre-existing leaf: `exist_ok` semantics -- leave its mode alone.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => Ok(()),
        // A-R2-7: covers, among others, a missing parent (Python's
        // `os.mkdir` raises an uncaught `FileNotFoundError` here, since this
        // call site has no `parents=True`) -- PORTING.md §3.5 applies
        // (`rust/DEVIATIONS.md`), folded into the same reason `mkdir_p`
        // already uses for its own local mkdir failures.
        Err(_) => Err(Error::state("state_write_failed").with_detail(path_str(path))),
    }
}

/// Port of the `Path.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)`
/// calls in `store.py` (`lock`, `write_json`, `append_line`, `write_bytes`
/// -- every mkdir call site *except* `subdir`, which has no `parents=True`
/// and goes through [`mkdir_leaf`] directly instead). With `parents=True`,
/// CPython's recursive parent-creation call
/// (`self.parent.mkdir(parents=True, exist_ok=True)`) does not forward the
/// caller's `mode` -- only the leaf directory the caller actually asked for
/// is created with `mode=DIR_MODE`; any missing parents get the OS default
/// mode (`0o777`, masked by umask at the syscall, exactly like
/// `fs::create_dir_all`'s own default). The leaf itself is then created via
/// [`mkdir_leaf`], atomically at `DIR_MODE`.
fn mkdir_p(path: &Path) -> Result<(), Error> {
    if path.is_dir() {
        return Ok(());
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|_| Error::state("state_write_failed").with_detail(path_str(parent)))?;
    }
    mkdir_leaf(path)
}

fn set_mode(path: &Path, mode: u32) -> Result<(), Error> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|_| Error::state("state_write_failed").with_detail(path_str(path)))
}

fn tmp_path(target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("state");
    let tid = format!("{:?}", thread::current().id());
    let tid: String = tid.chars().filter(|c| c.is_ascii_digit()).collect();
    let tmp_name = format!(".{name}.{}.{tid}.tmp", std::process::id());
    target.with_file_name(tmp_name)
}

fn path_str(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// `store.now()`: seconds since the Unix epoch, like `time.time()`.
pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// `store.iso(ts)`: `time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))`.
/// `time.gmtime` floors a fractional timestamp to whole seconds (verified
/// against CPython, not just assumed -- see `rust/tests/store_oracle.rs`).
pub fn iso(ts: Option<f64>) -> String {
    let ts = ts.unwrap_or_else(now);
    let secs = ts.floor() as i64;
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
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

    // A-R2-7: `read_lines` has no `try`/`except` in Python at all -- a
    // target that is a directory (`IsADirectoryError`) or contains bytes
    // that are not valid UTF-8 (`UnicodeDecodeError`) makes Python's
    // `open(...)`/iteration raise an uncaught `OSError`/`ValueError`, not a
    // `StateError`. PORTING.md §3.5 applies (`rust/DEVIATIONS.md`): both map
    // to `state_corrupt`, the reason `read_json` already uses for its own
    // unreadable/malformed state files.
    #[test]
    fn read_lines_on_directory_is_state_corrupt() {
        let (_tmp, state) = new_state();
        fs::create_dir(state.path.join("adir")).unwrap();
        let err = state.read_lines("adir", None).unwrap_err();
        assert!(err.is(ErrorClass::StateError));
        assert_eq!(err.reason, "state_corrupt");
    }

    #[test]
    fn read_lines_on_non_utf8_file_is_state_corrupt() {
        let (_tmp, state) = new_state();
        fs::write(state.path.join("bad.txt"), b"line one\n\xffnot utf8\n").unwrap();
        let err = state.read_lines("bad.txt", None).unwrap_err();
        assert!(err.is(ErrorClass::StateError));
        assert_eq!(err.reason, "state_corrupt");
    }

    // A-R2-7: `subdir`'s Python source (`target.mkdir(mode=DIR_MODE,
    // exist_ok=True)`) has no `parents=True`, unlike every other `mkdir`
    // call site in `store.py`; a missing parent makes Python's `os.mkdir`
    // raise an uncaught `FileNotFoundError`. This used to fail *open* in
    // Rust (silently creating the missing parent via `mkdir_p`); it must
    // fail *closed* instead, per PORTING.md §3.5 (`rust/DEVIATIONS.md`).
    #[test]
    fn subdir_with_missing_parent_fails_instead_of_creating_it() {
        let (_tmp, state) = new_state();
        let err = state.subdir("a/b").unwrap_err();
        assert!(err.is(ErrorClass::StateError));
        assert_eq!(err.reason, "state_write_failed");
        assert!(
            !state.path.join("a").exists(),
            "subdir must not fail-open by creating the missing parent"
        );
    }

    // A-R2-7: `create()` only raises `StateError("state_exists")` from its
    // own initial `path.exists()` probe in Python -- any other `mkdir`
    // failure (e.g. a read-only parent directory) is an uncaught raw
    // `OSError` there, not `state_exists`. PORTING.md §3.5 applies
    // (`rust/DEVIATIONS.md`): give it a distinct reason instead of folding
    // every mkdir failure into `state_exists`.
    #[test]
    fn create_reports_distinct_reason_for_non_exists_mkdir_failure() {
        let tmp = TempDir::new().unwrap();
        let readonly_parent = tmp.path().join("readonly");
        fs::create_dir(&readonly_parent).unwrap();
        fs::set_permissions(&readonly_parent, fs::Permissions::from_mode(0o500)).unwrap();
        let state = StateDir::new(readonly_parent.join("state"));

        let err = state.create();

        // Restore write permission unconditionally (before asserting) so
        // `TempDir`'s own cleanup can still remove `readonly_parent`.
        fs::set_permissions(&readonly_parent, fs::Permissions::from_mode(0o700)).unwrap();

        let err = err.unwrap_err();
        assert!(err.is(ErrorClass::StateError));
        assert_ne!(err.reason, "state_exists");
        assert_eq!(err.reason, "state_write_failed");
    }

    // A-R2-7: Python's `lock()` lets a failed `os.open(self.path / ".lock",
    // ...)` escape as an uncaught `OSError`, not a `StateError`. PORTING.md
    // §3.5 applies (`rust/DEVIATIONS.md`): map it to `state_lock_failed`,
    // the reason this port already uses for a failed `flock`.
    #[test]
    fn lock_open_failure_is_state_lock_failed() {
        let (_tmp, state) = new_state();
        // A directory in place of the `.lock` file makes `OpenOptions::open`
        // fail (EISDIR) instead of `flock` itself.
        fs::create_dir(state.path.join(".lock")).unwrap();
        match state.lock() {
            Ok(_) => panic!("expected lock() to fail when .lock is a directory"),
            Err(err) => {
                assert!(err.is(ErrorClass::StateError));
                assert_eq!(err.reason, "state_lock_failed");
            }
        }
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
        assert_eq!(
            tmp_leftovers(&state.path, "blob.bin").len(),
            1,
            "write_bytes must leave its tmp file behind on failure, like Python"
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
}
