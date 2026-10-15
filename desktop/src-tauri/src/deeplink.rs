//! `zeropw://join#…` invite links (docs/desktop-app.md §3.2, §5) and the other bits of
//! untrusted input the shell sees outside IPC: process arguments and webview navigation.
//!
//! - A link is only previewed: the core runs `team invite-info` on it, keeps the invite in
//!   the one-time store and emits `invite://preview` with `{ref, preview}`; the window comes
//!   forward. Joining needs the user's confirmation (`team_join`). Any other URL is refused
//!   by the core and nothing else happens.
//! - When a link starts the app (or reopens its window) the page may not be listening yet,
//!   so the preview is announced again every second until the page has settled, for as long
//!   as the invite is still pending. The frontend treats a repeated `{ref, preview}` as the
//!   same invite.
//! - The deep-link plugin itself re-emits each link as the Tauri event `deep-link://new-url`,
//!   which reaches only JS code that listens for that name. The webview never does
//!   (scripts/check-tauri.mjs refuses the name in desktop/src), and it has no deep-link
//!   permission, so the raw link stays in Rust.

use std::ffi::OsStr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use tauri::{AppHandle, Manager, Url};
use zeropw_desktop_core::commands::InvitePreviewOut;
use zeropw_desktop_core::{Core, CoreEvent, EventSink, SecretString};

use crate::glue::AppEvents;
use crate::shell::{Shell, show_main_window};

const REANNOUNCE_EVERY: Duration = Duration::from_secs(1);
const REANNOUNCE_FOR: Duration = Duration::from_secs(60);

/// The only command-line flag the app acts on: quit a running instance.
pub const QUIT_FLAG: &str = "--quit";

/// `argv` (program name first) asks to quit.
pub fn wants_quit<I, S>(argv: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    argv.into_iter()
        .skip(1)
        .any(|arg| arg.as_ref() == OsStr::new(QUIT_FLAG))
}

/// Preview an invite link opened outside the app. Runs the CLI off the calling thread.
pub fn open(app: &AppHandle, url: &str) {
    let Some(shell) = app.try_state::<Shell>() else {
        return;
    };
    let core = shell.core();
    let events = shell.events();
    let settled = shell.page_settled();
    let link = SecretString::from(url);
    let app = app.clone();
    thread::spawn(move || match core.open_deep_link(link.expose()) {
        Ok(preview) => {
            drop(link);
            show_main_window(&app);
            if !settled {
                reannounce(&app, &core, &events, &preview);
            }
        }
        Err(e) => eprintln!("zeropw: invite link not opened ({}: {})", e.error, e.reason),
    });
}

fn reannounce(app: &AppHandle, core: &Arc<Core>, events: &AppEvents, preview: &InvitePreviewOut) {
    let deadline = Instant::now() + REANNOUNCE_FOR;
    loop {
        thread::sleep(REANNOUNCE_EVERY);
        if Instant::now() > deadline || !core.invite_pending(&preview.reference) {
            return;
        }
        events.emit(CoreEvent::InvitePreview(preview.clone()));
        if app
            .try_state::<Shell>()
            .is_some_and(|shell| shell.page_settled())
        {
            return;
        }
    }
}

/// Navigation the main window may make: the app's own assets (`tauri://localhost` on macOS
/// and Linux, `http(s)://tauri.localhost` on Windows) and, in a dev build, the dev server.
pub fn is_app_url(url: &Url, dev_origin: Option<&Url>) -> bool {
    match url.scheme() {
        "tauri" => url.host_str() == Some("localhost"),
        "http" | "https" => {
            url.host_str() == Some("tauri.localhost")
                || dev_origin.is_some_and(|dev| same_origin(url, dev))
        }
        _ => false,
    }
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    #[test]
    fn only_the_quit_flag_quits() {
        assert!(wants_quit(["zeropw-desktop", "--quit"]));
        assert!(!wants_quit(["--quit"]), "the program name is not a flag");
        assert!(!wants_quit(["zeropw-desktop"]));
        assert!(!wants_quit(["zeropw-desktop", "zeropw://join#--quit"]));
        assert!(!wants_quit(["zeropw-desktop", "--quit=1"]));
    }

    #[test]
    fn navigation_stays_inside_the_app() {
        let dev = url("http://localhost:5173");
        assert!(is_app_url(&url("tauri://localhost/index.html"), None));
        assert!(is_app_url(&url("http://tauri.localhost/"), None));
        assert!(is_app_url(
            &url("http://localhost:5173/src/main.tsx"),
            Some(&dev)
        ));
        for bad in [
            "http://localhost:5173/",
            "https://example.com/",
            "tauri://evil/",
            "file:///etc/passwd",
            "zeropw://join#X",
            "javascript:alert(1)",
            "http://tauri.localhost.evil.example/",
        ] {
            assert!(!is_app_url(&url(bad), None), "{bad}");
        }
        for bad in [
            "http://localhost:5174/",
            "https://localhost:5173/",
            "http://127.0.0.1:5173/",
        ] {
            assert!(!is_app_url(&url(bad), Some(&dev)), "{bad}");
        }
    }
}
