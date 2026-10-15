//! ZeroPW desktop core (docs/desktop-app.md §4): everything the desktop app does that is not
//! Tauri glue. It never links the `zeropw` crate; it runs the `zeropw-admin` and
//! `zeropw-agent` binaries shipped next to the app.
//!
//! - [`admin`]: one `zeropw-admin --input-envelope` child per command, secrets on stdin only.
//! - [`serve`]: the `zeropw-admin serve` sidecar (start, attach, stop, status).
//! - [`onetime`]: single-use, short-lived values handed to the webview by reference.
//! - [`terminal`]: the in-app PTY terminals (caller token in the environment), kept in a
//!   registry with a bounded output ring so a view can reattach.
//! - [`commands`]: [`Core`], one method per IPC command in desktop/src/ipc/contract.ts.
//! - [`settings`], [`strength`], [`recovery`], [`sshkey`], [`netif`]: supporting pieces.

#![deny(unsafe_code)]

pub mod secret;

pub mod admin;
pub mod commands;
pub mod error;
pub mod hooks;
pub mod netif;
pub mod onetime;
pub mod paths;
pub mod recovery;
pub mod serve;
pub mod settings;
pub mod sshkey;
pub mod strength;
pub mod terminal;

pub use commands::{Control, Core, CoreConfig};
pub use error::AppError;
pub use hooks::{
    Clipboard, CoreEvent, EventSink, FilePick, FilePurpose, FileTokens, NoEvents, ScreenGuard,
};
pub use paths::AppPaths;
pub use secret::SecretString;
pub use serve::ServeStatus;
pub use settings::Settings;
pub use terminal::{TerminalProgram, TerminalSink, TerminalSummary};

const _: () = {
    const fn shared<T: Send + Sync>() {}
    shared::<Core>();
};
