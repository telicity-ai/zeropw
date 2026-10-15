//! ZeroPW desktop app (docs/desktop-app.md): the Tauri v2 shell around
//! `zeropw-desktop-core`. All product logic lives in the core; this crate only connects it to
//! the webview (typed IPC commands, events, channels) and to the OS (native dialogs, the
//! clipboard, window content protection, deep links, app lifecycle).
//!
//! - [`commands`]: one command per entry of desktop/src/ipc/contract.ts.
//! - [`glue`]: the core's event, clipboard, screen and terminal-output seams.
//! - [`shell`]: paths, plugins, the main window and the serve lifecycle.
//! - [`deeplink`]: invite links, `--quit`, and the navigation allowlist.

#![deny(unsafe_code)]

mod commands;
mod deeplink;
mod glue;
mod shell;

#[cfg(test)]
#[path = "../build/png.rs"]
mod png;

fn main() {
    shell::run();
}
