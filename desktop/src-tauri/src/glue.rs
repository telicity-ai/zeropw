//! The core's seams filled with Tauri: events to the webview, the system clipboard, window
//! content protection and terminal output channels.

use tauri::ipc::Channel;
use tauri::{AppHandle, Emitter, WebviewWindow};
use tauri_plugin_clipboard_manager::ClipboardExt;
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

/// The clipboard, written only from Rust (§8.7). The webview has no clipboard permission.
pub struct AppClipboard {
    app: AppHandle,
}

impl AppClipboard {
    pub fn new(app: AppHandle) -> Self {
        Self { app }
    }
}

impl Clipboard for AppClipboard {
    fn write_text(&self, text: &str) -> Result<(), AppError> {
        self.app
            .clipboard()
            .write_text(text)
            .map_err(|_| AppError::unavailable("clipboard_unavailable"))
    }

    fn read_text(&self) -> Option<SecretString> {
        self.app.clipboard().read_text().ok().map(SecretString::new)
    }

    fn clear(&self) -> Result<(), AppError> {
        self.app
            .clipboard()
            .clear()
            .map_err(|_| AppError::unavailable("clipboard_unavailable"))
    }
}

/// Screen-capture protection on one window (§8.8).
pub struct WindowScreenGuard {
    window: WebviewWindow,
}

impl WindowScreenGuard {
    pub fn new(window: WebviewWindow) -> Self {
        Self { window }
    }
}

impl ScreenGuard for WindowScreenGuard {
    fn set_protected(&self, on: bool) -> Result<(), AppError> {
        self.window
            .set_content_protected(on)
            .map_err(|_| AppError::unavailable("content_protection_failed"))
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
