//! The core's seams filled with Tauri: events to the webview, the system clipboard, window
//! content protection and terminal output channels.

use std::sync::{Mutex, MutexGuard};

use tauri::ipc::Channel;
use tauri::{AppHandle, Emitter, WebviewWindow};
use zeropw_desktop_core::{
    AppError, Clipboard, CoreEvent, EventSink, ScreenGuard, SecretString, TerminalSink,
};

/// Core events go out as Tauri events with the contract's names (`Events` in contract.ts).
/// Payloads are value-free by construction (`CoreEvent`).
pub struct AppEvents {
    app: AppHandle,
}

impl AppEvents {
    pub fn new(app: AppHandle) -> Self {
        Self { app }
    }
}

impl EventSink for AppEvents {
    fn emit(&self, event: CoreEvent) {
        let _ = self.app.emit(event.name(), event.payload());
    }
}

/// The system clipboard, written only from Rust (§8.7); the webview has no clipboard
/// permission. One arboard instance lives as long as the app (on Linux this process serves
/// the copied text) and is released at exit, after the core's last clear.
///
/// Every value goes on the clipboard marked for exclusion from clipboard history, so history
/// tools that honour the markers do not keep it past the 60 s clear: on macOS
/// `org.nspasteboard.ConcealedType` (nspasteboard.org), on Linux the
/// `x-kde-passwordManagerHint` type. A tool that ignores the markers can still record it.
pub struct AppClipboard {
    inner: Mutex<Option<arboard::Clipboard>>,
}

impl Default for AppClipboard {
    fn default() -> Self {
        Self {
            inner: Mutex::new(arboard::Clipboard::new().ok()),
        }
    }
}

impl AppClipboard {
    fn lock(&self) -> MutexGuard<'_, Option<arboard::Clipboard>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn with<T>(
        &self,
        f: impl FnOnce(&mut arboard::Clipboard) -> Result<T, arboard::Error>,
    ) -> Result<T, AppError> {
        let mut inner = self.lock();
        if inner.is_none() {
            *inner = arboard::Clipboard::new().ok();
        }
        let clipboard = inner
            .as_mut()
            .ok_or_else(|| AppError::unavailable("clipboard_unavailable"))?;
        f(clipboard).map_err(|_| AppError::unavailable("clipboard_unavailable"))
    }

    /// App exit: let the clipboard connection go. Never waits: if a clipboard call is still
    /// running (the core gave up on it), the process exit drops the connection instead.
    pub fn release(&self) {
        let inner = match self.inner.try_lock() {
            Ok(inner) => Some(inner),
            Err(std::sync::TryLockError::Poisoned(e)) => Some(e.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => None,
        };
        if let Some(mut inner) = inner {
            inner.take();
        }
    }
}

impl Clipboard for AppClipboard {
    fn write_text(&self, text: &str) -> Result<(), AppError> {
        self.with(|c| exclude_from_history(c.set()).text(text))
    }

    fn read_text(&self) -> Option<SecretString> {
        self.with(|c| c.get_text()).ok().map(SecretString::new)
    }

    fn clear(&self) -> Result<(), AppError> {
        self.with(|c| c.clear())
    }
}

#[cfg(target_os = "macos")]
fn exclude_from_history(set: arboard::Set<'_>) -> arboard::Set<'_> {
    use arboard::SetExtApple;
    set.exclude_from_history()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn exclude_from_history(set: arboard::Set<'_>) -> arboard::Set<'_> {
    use arboard::SetExtLinux;
    set.exclude_from_history()
}

/// Whether this platform can keep a window out of screen capture. Linux window systems give
/// an app no such control, and Tauri's content-protected flag does nothing there.
pub const CONTENT_PROTECTION: bool = cfg!(any(target_os = "macos", target_os = "windows"));

/// Screen-capture protection on one window (§8.8), where the platform has it.
pub struct WindowScreenGuard {
    window: WebviewWindow,
}

impl WindowScreenGuard {
    pub fn new(window: WebviewWindow) -> Self {
        Self { window }
    }
}

impl ScreenGuard for WindowScreenGuard {
    fn set_protected(&self, on: bool) -> Result<bool, AppError> {
        if !CONTENT_PROTECTION {
            return Ok(false);
        }
        self.window
            .set_content_protected(on)
            .map_err(|_| AppError::unavailable("content_protection_failed"))?;
        Ok(on)
    }
}

/// Terminal output into the webview's `Channel<string>` (xterm.js). A send to a webview that
/// has gone away fails quietly; the core keeps buffering for the next `terminal_attach`.
pub struct ChannelSink {
    channel: Channel<String>,
}

impl ChannelSink {
    pub fn new(channel: Channel<String>) -> Self {
        Self { channel }
    }
}

impl TerminalSink for ChannelSink {
    fn data(&mut self, chunk: &str) {
        let _ = self.channel.send(chunk.to_owned());
    }

    /// The channel carries output only; the Agents page sees the exit in `terminal_list`.
    fn exit(&mut self, _code: Option<u32>) {}
}
