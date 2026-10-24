//! Seams the Tauri layer fills in: events to the webview, the clipboard, window content
//! protection ([`ScreenGuard`]) and native file dialogs (through [`FileTokens`]). The core
//! stays free of any Tauri dependency.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::commands::{Control, EnvFileDrop, InvitePreviewOut};
use crate::error::AppError;
use crate::onetime::random_ref;
use crate::secret::SecretString;
use crate::serve::ServeStatus;

/// Events the core emits (`Events` in contract.ts). Payloads never carry secret values.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum CoreEvent {
    InvitePreview(InvitePreviewOut),
    AuditRecords(Vec<Value>),
    ControlChanged(Control),
    ServeStatus(ServeStatus),
    /// A file is being dragged over the window (`true`) or no longer is.
    EnvFileHover(bool),
    /// A file dropped on the window was read for an import, or why it was not.
    EnvFileDropped(EnvFileDrop),
}

impl CoreEvent {
    pub fn name(&self) -> &'static str {
        match self {
            CoreEvent::InvitePreview(_) => "invite://preview",
            CoreEvent::AuditRecords(_) => "audit://records",
            CoreEvent::ControlChanged(_) => "control://changed",
            CoreEvent::ServeStatus(_) => "serve://status",
            CoreEvent::EnvFileHover(_) => "envfile://hover",
            CoreEvent::EnvFileDropped(_) => "envfile://dropped",
        }
    }

    pub fn payload(&self) -> Value {
        match self {
            CoreEvent::InvitePreview(preview) => serde_json::to_value(preview),
            CoreEvent::AuditRecords(records) => Ok(serde_json::json!({ "records": records })),
            CoreEvent::ControlChanged(control) => serde_json::to_value(control),
            CoreEvent::ServeStatus(status) => serde_json::to_value(status),
            CoreEvent::EnvFileHover(over) => Ok(serde_json::json!({ "over": over })),
            CoreEvent::EnvFileDropped(drop) => serde_json::to_value(drop),
        }
        .unwrap_or(Value::Null)
    }
}

/// Where events go (`AppHandle::emit` in the Tauri layer).
pub trait EventSink: Send + Sync {
    fn emit(&self, event: CoreEvent);
}

/// Drops every event.
pub struct NoEvents;

impl EventSink for NoEvents {
    fn emit(&self, _event: CoreEvent) {}
}

/// The system clipboard, written only from Rust (§8.7). `read_text` lets the core clear the
/// clipboard later only if it still holds what the core put there.
pub trait Clipboard: Send + Sync {
    fn write_text(&self, text: &str) -> Result<(), AppError>;
    fn read_text(&self) -> Option<SecretString>;
    fn clear(&self) -> Result<(), AppError>;
}

/// Window content protection (§8.8): while a one-time value (recovery code, caller token,
/// invite link, revealed secret) is on screen, the window asks to be left out of screen
/// capture. The Tauri layer sets the main window's content-protected flag (NSWindow
/// sharingType none on macOS). It is a best-effort request: capture APIs may ignore it, and
/// Linux has nothing comparable.
pub trait ScreenGuard: Send + Sync {
    /// Turn the request on or off. Returns whether the request is applied now: `Ok(false)`
    /// after `on = true` means the platform has no such request (Linux).
    fn set_protected(&self, on: bool) -> Result<bool, AppError>;
}

/// `file_pick` purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilePurpose {
    Secret,
    SshKey,
    Ca,
    /// A `.env` file for `env_file_load` (docs/env-import.md §8).
    EnvFile,
}

/// `file_pick` output: an opaque token and the file's display name; the path stays in Rust.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FilePick {
    pub file_token: String,
    pub name: String,
}

const FILE_TOKEN_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_FILE_TOKENS: usize = 64;

struct PickedFile {
    purpose: FilePurpose,
    path: PathBuf,
    expires_at: Instant,
}

/// Paths chosen in native dialogs, exchanged for opaque single-use tokens. The webview never
/// learns or supplies a path.
#[derive(Default)]
pub struct FileTokens {
    files: Mutex<HashMap<String, PickedFile>>,
}

impl FileTokens {
    pub fn new() -> Self {
        Self::default()
    }

    /// Called by the Tauri layer after the user picked `path` in a native dialog.
    pub fn register(&self, purpose: FilePurpose, path: &Path) -> Result<FilePick, AppError> {
        if !path.is_absolute() {
            return Err(AppError::invalid_input("file_path_invalid"));
        }
        let token = random_ref()?;
        let now = Instant::now();
        let mut files = self.files.lock().unwrap_or_else(|e| e.into_inner());
        files.retain(|_, f| f.expires_at > now);
        if files.len() >= MAX_FILE_TOKENS {
            return Err(AppError::unavailable("file_tokens_full"));
        }
        files.insert(
            token.clone(),
            PickedFile {
                purpose,
                path: path.to_path_buf(),
                expires_at: now + FILE_TOKEN_TTL,
            },
        );
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Ok(FilePick {
            file_token: token,
            name,
        })
    }

    /// Redeem a token picked for one of `purposes`. Single use.
    pub fn take(&self, token: &str, purposes: &[FilePurpose]) -> Result<PathBuf, AppError> {
        let now = Instant::now();
        let mut files = self.files.lock().unwrap_or_else(|e| e.into_inner());
        files.retain(|_, f| f.expires_at > now);
        match files.get(token) {
            Some(file) if purposes.contains(&file.purpose) => {}
            _ => return Err(AppError::not_found("file_token_unknown")),
        }
        files
            .remove(token)
            .map(|f| f.path)
            .ok_or_else(|| AppError::not_found("file_token_unknown"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_tokens_are_single_use_and_purpose_bound() {
        let tokens = FileTokens::new();
        let pick = tokens
            .register(FilePurpose::Ca, Path::new("/tmp/ca.pem"))
            .unwrap();
        assert_eq!(pick.name, "ca.pem");
        assert_eq!(pick.file_token.len(), 32);
        assert!(
            tokens
                .take(&pick.file_token, &[FilePurpose::Secret])
                .is_err()
        );
        assert_eq!(
            tokens.take(&pick.file_token, &[FilePurpose::Ca]).unwrap(),
            PathBuf::from("/tmp/ca.pem")
        );
        assert!(tokens.take(&pick.file_token, &[FilePurpose::Ca]).is_err());
        assert!(
            tokens
                .register(FilePurpose::Secret, Path::new("relative"))
                .is_err()
        );
    }

    #[test]
    fn event_names_match_the_contract() {
        let e = CoreEvent::ServeStatus(ServeStatus::stopped());
        assert_eq!(e.name(), "serve://status");
        assert_eq!(e.payload()["running"], false);
        let e = CoreEvent::AuditRecords(vec![serde_json::json!({"event":"x"})]);
        assert_eq!(e.name(), "audit://records");
        assert_eq!(e.payload()["records"][0]["event"], "x");
    }
}
