//! Port of `zeropw/store.py`: the locked, atomic JSON state directory for the
//! trusted ZeroPW process.
//!
//! Concurrency: a single trusted process serves several threads (gateway,
//! signer, tools). [`StateDir::lock`] combines a re-entrant *in-process* lock
//! (Python: `threading.RLock`) with an `flock` *file* lock (Python: `fcntl`)
//! so a second administrative process (the admin CLI) also serialises
//! read-modify-write cycles against the same directory -- including a Python
//! process holding the same `.lock` file.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
    /// `StateDir.create`.
    pub fn create(&self) -> Result<(), Error> {
        if self.path.exists() {
            return Err(Error::state("state_exists").with_detail(path_str(&self.path)));
        }
        fs::create_dir_all(&self.path)
            .map_err(|_| Error::state("state_exists").with_detail(path_str(&self.path)))?;
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

    /// `StateDir.subdir`.
    pub fn subdir(&self, name: &str) -> Result<PathBuf, Error> {
        let target = self.path.join(name);
        mkdir_p(&target)?;
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

    /// `StateDir.write_json`.
    pub fn write_json(&self, name: &str, value: &Value) -> Result<(), Error> {
        let target = self.path.join(name);
        if let Some(parent) = target.parent() {
            mkdir_p(parent)?;
        }
        let text = pyjson::dumps(value, DumpOptions::pretty_sorted())
            .map_err(|_| Error::state("state_write_failed").with_detail(name))?;
        let tmp = tmp_path(&target);
        let write_result = (|| -> std::io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(FILE_MODE)
                .open(&tmp)?;
            file.write_all(text.as_bytes())?;
            file.flush()?;
            file.sync_all()?;
            Ok(())
        })();
        match write_result {
            Ok(()) => {
                fs::rename(&tmp, &target)
                    .map_err(|_| Error::state("state_write_failed").with_detail(name))?;
                Ok(())
            }
            Err(_) => {
                let _ = fs::remove_file(&tmp);
                Err(Error::state("state_write_failed").with_detail(name))
            }
        }
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
        let mut lines: Vec<String> = if text.is_empty() {
            Vec::new()
        } else {
            text.split('\n').map(str::to_string).collect()
        };
        // `str::split('\n')` on text ending in '\n' yields a trailing "" —
        // Python's `for line in stream` never produces that.
        if lines.last().is_some_and(|l| l.is_empty()) {
            lines.pop();
        }
        if let Some(limit) = limit
            && lines.len() > limit
        {
            lines = lines.split_off(lines.len() - limit);
        }
        Ok(lines)
    }

    /// `StateDir.write_bytes`.
    pub fn write_bytes(&self, name: &str, data: &[u8]) -> Result<(), Error> {
        let target = self.path.join(name);
        if let Some(parent) = target.parent() {
            mkdir_p(parent)?;
        }
        let tmp = tmp_path(&target);
        let write_result = (|| -> std::io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(FILE_MODE)
                .open(&tmp)?;
            file.write_all(data)?;
            file.flush()?;
            file.sync_all()?;
            Ok(())
        })();
        match write_result {
            Ok(()) => {
                fs::rename(&tmp, &target)
                    .map_err(|_| Error::state("state_write_failed").with_detail(name))?;
                Ok(())
            }
            Err(_) => {
                let _ = fs::remove_file(&tmp);
                Err(Error::state("state_write_failed").with_detail(name))
            }
        }
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

fn mkdir_p(path: &Path) -> Result<(), Error> {
    fs::create_dir_all(path)
        .map_err(|_| Error::state("state_write_failed").with_detail(path_str(path)))?;
    set_mode(path, DIR_MODE)
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
