//! App data layout (docs/desktop-app.md §4.5) and private file helpers.
//!
//! ```text
//! <app data>/            0700  (macOS: ~/Library/Application Support/ZeroPW)
//!   state/               zeropw-admin --state-dir (created by `init`)
//!   settings.json        0600  app settings, never inside state/
//!   serve.json           0600  pid file of the serve sidecar
//!   serve.log            0600  serve's stderr
//! ```

use std::ffi::OsString;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::error::AppError;

pub const ADMIN_BIN: &str = "zeropw-admin";
pub const AGENT_BIN: &str = "zeropw-agent";
/// Development override for the folder holding zeropw-admin / zeropw-agent (§4.1).
pub const BIN_DIR_ENV: &str = "ZEROPW_BIN_DIR";

/// Where the core keeps its files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppPaths {
    pub app_data_dir: PathBuf,
    pub bin_dir: PathBuf,
}

impl AppPaths {
    pub fn new(app_data_dir: impl Into<PathBuf>, bin_dir: impl Into<PathBuf>) -> Self {
        Self {
            app_data_dir: app_data_dir.into(),
            bin_dir: bin_dir.into(),
        }
    }

    pub fn state_dir(&self) -> PathBuf {
        self.app_data_dir.join("state")
    }

    pub fn settings_file(&self) -> PathBuf {
        self.app_data_dir.join("settings.json")
    }

    pub fn serve_pid_file(&self) -> PathBuf {
        self.app_data_dir.join("serve.json")
    }

    pub fn serve_log_file(&self) -> PathBuf {
        self.app_data_dir.join("serve.log")
    }

    pub fn admin_bin(&self) -> PathBuf {
        self.bin_dir.join(ADMIN_BIN)
    }

    pub fn agent_bin(&self) -> PathBuf {
        self.bin_dir.join(AGENT_BIN)
    }
}

/// The platform app data folder: `~/Library/Application Support/ZeroPW` on macOS,
/// `$XDG_DATA_HOME/zeropw` (or `~/.local/share/zeropw`) elsewhere.
pub fn default_app_data_dir() -> Option<PathBuf> {
    let home = home_dir()?;
    if cfg!(target_os = "macos") {
        return Some(home.join("Library/Application Support/ZeroPW"));
    }
    match std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        Some(base) if Path::new(&base).is_absolute() => Some(PathBuf::from(base).join("zeropw")),
        _ => Some(home.join(".local/share/zeropw")),
    }
}

/// `ZEROPW_BIN_DIR` during development, otherwise the folder of the running executable
/// (the bundle's `Contents/MacOS`, where the binaries ship next to the app).
pub fn default_bin_dir() -> Option<PathBuf> {
    bin_dir(true)
}

/// The folder holding the shipped binaries: the running executable's folder, or
/// `ZEROPW_BIN_DIR` when `allow_override` is set and the variable is a non-empty absolute
/// path. Release builds of the app pass `false`, so the environment cannot point the app at
/// other binaries.
pub fn bin_dir(allow_override: bool) -> Option<PathBuf> {
    if allow_override
        && let Some(dir) = std::env::var_os(BIN_DIR_ENV).filter(|v| !v.is_empty())
        && Path::new(&dir).is_absolute()
    {
        return Some(PathBuf::from(dir));
    }
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
}

/// `$HOME`, or the passwd entry of the current user.
pub fn home_dir() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(home));
    }
    nix::unistd::User::from_uid(nix::unistd::Uid::current())
        .ok()
        .flatten()
        .map(|user| user.dir)
}

/// The temp folder handed to child processes.
pub(crate) fn temp_dir() -> OsString {
    std::env::var_os("TMPDIR")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| std::env::temp_dir().into_os_string())
}

/// Create `dir` (and parents) with mode 0700 when missing. An existing folder is left as is.
pub fn ensure_private_dir(dir: &Path) -> Result<(), AppError> {
    if dir.is_dir() {
        return Ok(());
    }
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| AppError::io("app_dir_unavailable", &e))
}

/// Write `bytes` to `path` with mode 0600 through a temp file and rename, so readers never see
/// a partial file and the file is never briefly world-readable.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Open `path` for appending with mode 0600 (tightening an existing file's mode).
pub fn open_private_append(path: &Path) -> io::Result<fs::File> {
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_keeps_settings_outside_state() {
        let p = AppPaths::new("/data/ZeroPW", "/bin/zp");
        assert_eq!(p.state_dir(), PathBuf::from("/data/ZeroPW/state"));
        assert_eq!(
            p.settings_file(),
            PathBuf::from("/data/ZeroPW/settings.json")
        );
        assert!(!p.settings_file().starts_with(p.state_dir()));
        assert_eq!(p.admin_bin(), PathBuf::from("/bin/zp/zeropw-admin"));
        assert_eq!(p.agent_bin(), PathBuf::from("/bin/zp/zeropw-agent"));
    }

    #[test]
    fn private_files_are_0600_and_dirs_0700() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("a/b");
        ensure_private_dir(&dir).unwrap();
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let file = dir.join("x.json");
        write_private_atomic(&file, b"{}").unwrap();
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read(&file).unwrap(), b"{}");
        write_private_atomic(&file, b"{\"a\":1}").unwrap();
        assert_eq!(fs::read(&file).unwrap(), b"{\"a\":1}");
        // No temp files left behind.
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);

        let log = dir.join("serve.log");
        fs::write(&log, b"old\n").unwrap();
        fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).unwrap();
        let mut f = open_private_append(&log).unwrap();
        f.write_all(b"new\n").unwrap();
        assert_eq!(
            fs::metadata(&log).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read(&log).unwrap(), b"old\nnew\n");
    }
}
