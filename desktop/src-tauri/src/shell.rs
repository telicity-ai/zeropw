//! App wiring and lifecycle (docs/desktop-app.md §2, §4).
//!
//! - Paths: state and settings live in the core's app data folder
//!   (`~/Library/Application Support/ZeroPW` on macOS). The zeropw binaries are the ones
//!   shipped next to this executable; debug builds may point elsewhere with `ZEROPW_BIN_DIR`.
//! - Launch: adopt a serve sidecar left by an earlier run, otherwise start one when a vault
//!   exists. Closing the window keeps the app (and so serve and the agent terminals) running;
//!   the window comes back from the Dock (macOS) or by launching the app again. Quitting the
//!   app (the app menu, or `zeropw-desktop --quit`) closes the terminals and SIGTERMs serve.
//! - The single main window is created here from tauri.conf.json. It may only navigate within
//!   the app's own origin and may not open new windows. Before any page script runs,
//!   `freeze_prototype.js` freezes `Object.prototype` with override taming. Tauri's own
//!   `app.security.freezePrototype` is off because its plain `Object.freeze` makes
//!   @xterm/xterm throw while the bundle loads (assigning `toString` on a plain object), which
//!   leaves the window blank; scripts/check-tauri.mjs checks the replacement in a fresh realm.
//! - Deep links are handled in [`crate::deeplink`].

use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use tauri::webview::{NewWindowResponse, PageLoadEvent};
use tauri::{
    App, AppHandle, Manager, RunEvent, Url, WebviewWindow, WebviewWindowBuilder, WindowEvent,
};
use tauri_plugin_deep_link::DeepLinkExt;
use zeropw_desktop_core::{AppPaths, Core, CoreConfig, paths};

use crate::deeplink;
use crate::glue::AppEvents;

/// The one window's label (tauri.conf.json, capabilities/default.json).
pub const MAIN: &str = "main";

/// Runs in the main window before any page script (after Tauri's own init scripts).
const FREEZE_PROTOTYPE: &str = include_str!("freeze_prototype.js");

/// How long after the page finished loading the frontend is assumed to have its event
/// listeners in place.
const PAGE_SETTLE: Duration = Duration::from_secs(2);

/// Shared app state behind every command.
pub struct Shell {
    core: Arc<Core>,
    events: Arc<AppEvents>,
    page_loaded_at: Mutex<Option<Instant>>,
    shut_down: AtomicBool,
}

impl Shell {
    fn new(core: Arc<Core>, events: Arc<AppEvents>) -> Self {
        Self {
            core,
            events,
            page_loaded_at: Mutex::new(None),
            shut_down: AtomicBool::new(false),
        }
    }

    pub fn core(&self) -> Arc<Core> {
        self.core.clone()
    }

    pub fn events(&self) -> Arc<AppEvents> {
        self.events.clone()
    }

    fn page(&self) -> MutexGuard<'_, Option<Instant>> {
        self.page_loaded_at
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn page_loaded(&self) {
        *self.page() = Some(Instant::now());
    }

    fn page_gone(&self) {
        *self.page() = None;
    }

    /// The main page has been loaded long enough to be listening for events.
    pub fn page_settled(&self) -> bool {
        self.page().is_some_and(|at| at.elapsed() >= PAGE_SETTLE)
    }

    /// Once per process: close terminals, forget one-time values, SIGTERM serve.
    fn shutdown(&self) {
        if !self.shut_down.swap(true, Ordering::SeqCst) {
            self.core.shutdown();
        }
    }
}

pub fn run() {
    let quit_only = deeplink::wants_quit(std::env::args_os());
    tauri::Builder::default()
        // First, so a second launch hands its argv to this process and exits before any
        // other setup. With the deep-link feature, a forwarded zeropw:// URL reaches the
        // deep-link plugin (and so `deeplink::open`) before this callback runs.
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            if deeplink::wants_quit(argv) {
                app.exit(0);
            } else {
                show_main_window(app);
            }
        }))
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .invoke_handler(crate::commands::handler())
        .on_page_load(|webview, payload| {
            if webview.label() == MAIN
                && payload.event() == PageLoadEvent::Finished
                && let Some(shell) = webview.try_state::<Shell>()
            {
                shell.page_loaded();
            }
        })
        .on_window_event(|window, event| {
            if window.label() == MAIN
                && matches!(event, WindowEvent::Destroyed)
                && let Some(shell) = window.try_state::<Shell>()
            {
                shell.page_gone();
            }
        })
        .setup(move |app| setup(app, quit_only))
        .build(tauri::generate_context!())
        .expect("ZeroPW could not start")
        .run(on_run_event);
}

fn setup(app: &mut App, quit_only: bool) -> Result<(), Box<dyn Error>> {
    if quit_only {
        // `--quit` with no running instance: nothing to stop.
        app.handle().exit(0);
        return Ok(());
    }
    let data_dir = paths::default_app_data_dir().ok_or("no app data folder")?;
    let bin_dir = paths::bin_dir(cfg!(debug_assertions)).ok_or("no folder for the binaries")?;
    let events = Arc::new(AppEvents::new(app.handle().clone()));
    let core = Arc::new(Core::new(
        CoreConfig::new(AppPaths::new(data_dir, bin_dir)),
        events.clone(),
    ));
    app.manage(Shell::new(core.clone(), events));

    // macOS delivers zeropw:// links as open-url events; Linux forwards them through the
    // single-instance argv. Both arrive here.
    let handle = app.handle().clone();
    app.deep_link().on_open_url(move |event| {
        for url in event.urls() {
            deeplink::open(&handle, url.as_str());
        }
    });
    // A link that launched this process (Linux argv) was seen before the listener existed.
    if let Ok(Some(urls)) = app.deep_link().get_current() {
        for url in urls {
            deeplink::open(app.handle(), url.as_str());
        }
    }

    create_main_window(app.handle())?;
    std::thread::spawn(move || start_serve(&core));
    Ok(())
}

/// Adopt a sidecar from an earlier run; otherwise start one if a vault exists. Failures are
/// left for the UI (`serve_status`, `serve_start`).
fn start_serve(core: &Core) {
    if core.startup().running || !core.initialized() {
        return;
    }
    if let Err(e) = core.serve_start() {
        eprintln!("zeropw: serve did not start ({}: {})", e.error, e.reason);
    }
}

fn on_run_event(app: &AppHandle, event: RunEvent) {
    match event {
        // The last window closed: keep running so serve and the agent terminals stay up.
        RunEvent::ExitRequested {
            code: None, api, ..
        } => api.prevent_exit(),
        RunEvent::Exit => {
            if let Some(shell) = app.try_state::<Shell>() {
                shell.shutdown();
            }
        }
        #[cfg(target_os = "macos")]
        RunEvent::Reopen { .. } => show_main_window(app),
        _ => {}
    }
}

/// Bring the main window forward, creating it again if it was closed. Runs on the main
/// thread.
pub fn show_main_window(app: &AppHandle) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        if let Some(window) = handle.get_webview_window(MAIN) {
            let _ = window.unminimize();
            let _ = window.show();
            let _ = window.set_focus();
        } else if create_main_window(&handle).is_err() {
            eprintln!("zeropw: the window could not be opened");
        }
    });
}

fn create_main_window(app: &AppHandle) -> tauri::Result<WebviewWindow> {
    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|w| w.label == MAIN)
        .cloned()
        .ok_or(tauri::Error::WindowNotFound)?;
    // Only a dev build loads the dev server; a bundled build serves its assets itself.
    let dev_origin: Option<Url> = if cfg!(dev) {
        app.config().build.dev_url.clone()
    } else {
        None
    };
    WebviewWindowBuilder::from_config(app, &config)?
        .on_navigation(move |url| deeplink::is_app_url(url, dev_origin.as_ref()))
        .on_new_window(|_, _| NewWindowResponse::Deny)
        .initialization_script(FREEZE_PROTOTYPE)
        .build()
}
