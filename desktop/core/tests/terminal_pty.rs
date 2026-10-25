//! The PTY terminal: the caller token reaches the child's environment without ever being
//! printed or typed (the child reports only whether it is set and its length), input and
//! resize reach the shell, and closing hangs it up.

mod common;

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::wait_until;
use zeropw_desktop_core::SecretString;
use zeropw_desktop_core::terminal::{
    TerminalManager, TerminalProgram, TerminalRequest, TerminalSink,
};

const TOKEN: &str = "zpw_synthetic_terminal_token_0123456789";

struct Collect {
    out: Arc<Mutex<String>>,
    exit: mpsc::Sender<Option<u32>>,
}

impl TerminalSink for Collect {
    fn data(&mut self, chunk: &str) {
        self.out.lock().unwrap().push_str(chunk);
    }
    fn exit(&mut self, code: Option<u32>) {
        let _ = self.exit.send(code);
    }
}

fn sh(script: &str) -> TerminalManager {
    TerminalManager::new(TerminalProgram::Program {
        path: PathBuf::from("/bin/sh"),
        args: vec!["-c".into(), script.into()],
    })
}

fn open(
    manager: &TerminalManager,
    bin_dir: &Path,
) -> (String, Arc<Mutex<String>>, mpsc::Receiver<Option<u32>>) {
    let token = SecretString::from(TOKEN);
    let out = Arc::new(Mutex::new(String::new()));
    let (tx, rx) = mpsc::channel();
    let id = manager
        .open(
            &TerminalRequest {
                gateway_url: "http://127.0.0.1:47380",
                token: &token,
                bin_dir,
                cols: 80,
                rows: 24,
                principal: "agent-1",
                as_user: None,
            },
            Box::new(Collect {
                out: out.clone(),
                exit: tx,
            }),
        )
        .unwrap();
    (id, out, rx)
}

#[test]
fn the_token_is_in_the_environment_and_never_on_screen() {
    let manager = sh(concat!(
        r#"if [ -n "${ZEROPW_CALLER_TOKEN:-}" ]; then echo "token_set=yes len=${#ZEROPW_CALLER_TOKEN}"; else echo token_set=no; fi; "#,
        r#"echo "url=$ZEROPW_GATEWAY_URL"; echo "no_proxy=$no_proxy"; echo "path_head=${PATH%%:*}"; "#,
        r#"if [ -z "${ZEROPW_ADMIN_PASSPHRASE:-}" ]; then echo admin_unset; fi; echo term=$TERM"#
    ));
    let bin = Path::new("/opt/zeropw-bundle");
    let (_id, out, exit) = open(&manager, bin);
    assert_eq!(exit.recv_timeout(Duration::from_secs(10)).unwrap(), Some(0));
    let text = out.lock().unwrap().clone();
    assert!(
        text.contains(&format!("token_set=yes len={}", TOKEN.len())),
        "{text}"
    );
    assert!(text.contains("url=http://127.0.0.1:47380"), "{text}");
    assert!(text.contains("no_proxy=127.0.0.1,localhost"), "{text}");
    assert!(text.contains("path_head=/opt/zeropw-bundle"), "{text}");
    assert!(text.contains("admin_unset"), "{text}");
    assert!(text.contains("term=xterm-256color"), "{text}");
    assert!(!text.contains(TOKEN), "token printed: {text}");
    assert!(wait_until(Duration::from_secs(2), || manager.open_count() == 0));
    // The exited shell is still listed (not alive) for reattaching until it is closed.
    let listed = manager.list();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].principal, "agent-1");
    assert!(!listed[0].alive);
}

#[test]
fn exited_terminals_give_way_when_the_registry_is_full() {
    let manager = sh("echo bye");
    let mut ids = Vec::new();
    for _ in 0..8 {
        let (id, _out, exit) = open(&manager, Path::new("/opt/zeropw-bundle"));
        assert!(exit.recv_timeout(Duration::from_secs(10)).is_ok());
        ids.push(id);
    }
    assert!(wait_until(Duration::from_secs(2), || manager.open_count() == 0));
    assert_eq!(manager.list().len(), 8);
    // A ninth terminal evicts the oldest exited one.
    let (newest, _out, _exit) = open(&manager, Path::new("/opt/zeropw-bundle"));
    let listed: Vec<String> = manager.list().into_iter().map(|t| t.terminal_id).collect();
    assert_eq!(listed.len(), 8);
    assert!(!listed.contains(&ids[0]));
    assert_eq!(listed.last(), Some(&newest));

    // Eight running shells fill the registry for real.
    let busy = sh("while :; do sleep 1; done");
    let running: Vec<String> = (0..8)
        .map(|_| open(&busy, Path::new("/opt/zeropw-bundle")).0)
        .collect();
    let token = SecretString::from(TOKEN);
    let refused = busy
        .open(
            &TerminalRequest {
                gateway_url: "http://127.0.0.1:47380",
                token: &token,
                bin_dir: Path::new("/opt/zeropw-bundle"),
                cols: 80,
                rows: 24,
                principal: "agent-1",
                as_user: None,
            },
            Box::new(Collect {
                out: Arc::new(Mutex::new(String::new())),
                exit: mpsc::channel().0,
            }),
        )
        .unwrap_err();
    assert_eq!(refused.reason, "too_many_terminals");
    for id in running {
        busy.close(&id);
    }
    assert!(busy.list().is_empty());
}

#[test]
fn keyboard_input_and_resize_reach_the_shell() {
    let manager = sh(r#"read line; echo "got:$line"; read again; stty size"#);
    let (id, out, exit) = open(&manager, Path::new("/opt/zeropw-bundle"));
    manager.write(&id, "hello 가나\n").unwrap();
    assert!(wait_until(Duration::from_secs(5), || out
        .lock()
        .unwrap()
        .contains("got:hello 가나")));
    manager.resize(&id, 100, 40).unwrap();
    manager.write(&id, "\n").unwrap();
    assert_eq!(exit.recv_timeout(Duration::from_secs(10)).unwrap(), Some(0));
    let text = out.lock().unwrap().clone();
    assert!(text.contains("40 100"), "{text}");
    manager.close(&id);
}

#[test]
fn close_hangs_up_a_running_shell() {
    let manager = sh("echo ready; while :; do sleep 1; done");
    let (id, out, exit) = open(&manager, Path::new("/opt/zeropw-bundle"));
    assert!(wait_until(Duration::from_secs(5), || out
        .lock()
        .unwrap()
        .contains("ready")));
    manager.close(&id);
    assert!(exit.recv_timeout(Duration::from_secs(10)).is_ok());
    assert_eq!(
        manager.write(&id, "x").unwrap_err().reason,
        "terminal_not_found"
    );
    // Closing again is harmless.
    manager.close(&id);
}

/// zsh, as `command -v` or the usual places find it. The test below must fail, not silently
/// pass, without it (the macOS host and the Linux verification VM have it).
fn zsh() -> PathBuf {
    std::process::Command::new("sh")
        .args(["-c", "command -v zsh"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()))
        .filter(|p| p.is_absolute())
        .or_else(|| {
            ["/bin/zsh", "/usr/bin/zsh"]
                .into_iter()
                .map(PathBuf::from)
                .find(|p| p.is_file())
        })
        .unwrap_or_else(|| panic!("zsh not available: this test needs zsh"))
}

/// What the shell printed after `<6*7><name>=` up to the end of the line (the echoed command
/// line has `$((6*7))` instead).
fn printed(text: &str, name: &str) -> String {
    let marker = format!("42{name}=");
    let at = text
        .find(&marker)
        .unwrap_or_else(|| panic!("no {marker} in {text:?}"));
    text[at + marker.len()..]
        .split(['\r', '\n'])
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// Write `files` (name, text) under `dir`.
fn write_files(dir: &Path, files: &[(&str, &str)]) {
    for (name, text) in files {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
}

/// The environment the app hands the shell: HOME, SHELL and a short PATH, all synthetic.
fn parent_env(home: &Path, shell: &Path) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    vec![
        ("HOME".into(), home.into()),
        ("SHELL".into(), shell.into()),
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("USER".into(), "zpw-synthetic".into()),
    ]
}

/// Typed at the zsh prompt: PATH, the user's marks, ZDOTDIR in the shell and as the programs
/// it starts see it, the history file, which helper variables are left, and what a program
/// the user's `.zshenv` started saw of them.
const ZSH_PROBE: &str = concat!(
    r#"print -r -- "$((6*7))P=$PATH"; print -r -- "$((6*7))M=${ZPW_MARKS-}"; "#,
    r#"print -r -- "$((6*7))Z=${ZDOTDIR-none}"; print -r -- "$((6*7))H=${HISTFILE-none}"; "#,
    r#"print -r -- "$((6*7))E=$(/bin/sh -c 'echo "${ZDOTDIR-none}"')"; "#,
    r#"print -r -- "$((6*7))X=${+ZEROPW_TERMINAL_BIN}${+ZEROPW_USER_ZDOTDIR}${+ZEROPW_ZDOTDIR}"; "#,
    r#"print -r -- "$((6*7))C=${ZPW_CHILD-unset}"; "#,
    "exit\n"
);

/// Desktop E2E F5: the login shell's startup files (macOS's /etc/zprofile, a `.zprofile` that
/// puts Homebrew first) rebuilt PATH after the app had put the bundle folder first, so
/// `zeropw-agent` ran another build. For zsh the app's own startup files run the user's and
/// then put the bundle folder first again, once; ZDOTDIR, history and the rest stay as the
/// user's files set them, and no helper variable is left behind, also when the user's
/// `.zshenv` stops zsh reading further files (`unsetopt rcs`) and when the app itself was
/// given a ZDOTDIR. A program the user's files start never sees the helpers. Another shell is
/// left alone.
#[test]
fn zsh_keeps_the_bundle_folder_first_after_the_user_startup_files() {
    use std::os::unix::fs::PermissionsExt;

    let zsh = zsh();
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("ZeroPW (1).app/Contents/MacOS");
    std::fs::create_dir_all(&bin).unwrap();
    let bin_text = bin.to_string_lossy().into_owned();
    let zsh_dir = dir.path().join("app/zsh");
    // What a program started from the user's `.zshenv` sees of the helpers.
    let child = "ZPW_CHILD=$(/bin/sh -c 'echo \"${ZEROPW_TERMINAL_BIN-none},${ZEROPW_USER_ZDOTDIR-none}\"')\n";

    // Startup files in HOME, the most common setup.
    let plain = dir.path().join("home plain");
    write_files(
        &plain,
        &[
            (".zshenv", &format!("ZPW_MARKS=env\n{child}")),
            (
                ".zprofile",
                "ZPW_MARKS+=,profile\nPATH=/synthetic/brew/bin:$PATH\n",
            ),
            (".zshrc", "ZPW_MARKS+=,rc\ntypeset -U path\n"),
            (".zlogin", "ZPW_MARKS+=,login\n"),
        ],
    );
    // A `.zshenv` that moves the rest to ~/.config/zsh; the `.zprofile` in HOME is not read.
    let xdg = dir.path().join("home-xdg");
    let xdg_zdotdir = xdg.join(".config/zsh");
    write_files(
        &xdg,
        &[
            (
                ".zshenv",
                &format!("ZPW_MARKS=env\n{child}export ZDOTDIR=$HOME/.config/zsh\n"),
            ),
            (".zprofile", "ZPW_MARKS+=,home-profile\n"),
            (
                ".config/zsh/.zprofile",
                "ZPW_MARKS+=,profile\nPATH=/synthetic/brew/bin:$PATH\n",
            ),
            (".config/zsh/.zshrc", "ZPW_MARKS+=,rc\n"),
            (
                ".config/zsh/.zlogin",
                "ZPW_MARKS+=,login\nPATH=/synthetic/login/bin:$PATH\n",
            ),
        ],
    );
    // A `.zshenv` that turns RCS off: zsh reads none of the later files, the app's included.
    let norcs = dir.path().join("home-norcs");
    write_files(
        &norcs,
        &[
            (".zshenv", &format!("ZPW_MARKS=env\n{child}unsetopt rcs\n")),
            (
                ".zprofile",
                "ZPW_MARKS+=,profile\nPATH=/synthetic/brew/bin:$PATH\n",
            ),
        ],
    );
    // ZDOTDIR already in the app's environment (set for the login session, not by a
    // `.zshenv`): every user file is read from there, the `.zshenv` too, none from HOME.
    let session = dir.path().join("home-session");
    let session_zdotdir = session.join(".config/zsh");
    write_files(
        &session,
        &[
            (".zshenv", "ZPW_MARKS=home-env\n"),
            (".zprofile", "ZPW_MARKS+=,home-profile\n"),
            (".config/zsh/.zshenv", &format!("ZPW_MARKS=env\n{child}")),
            (
                ".config/zsh/.zprofile",
                "ZPW_MARKS+=,profile\nPATH=/synthetic/brew/bin:$PATH\n",
            ),
            (".config/zsh/.zshrc", "ZPW_MARKS+=,rc\n"),
            (".config/zsh/.zlogin", "ZPW_MARKS+=,login\n"),
        ],
    );
    let (xdg_z, session_z, app_z) = (
        xdg_zdotdir.to_string_lossy(),
        session_zdotdir.to_string_lossy(),
        zsh_dir.to_string_lossy(),
    );

    let all = "env,profile,rc,login";
    for (home, app_zdotdir, zdotdir, marks, brew) in [
        (&plain, None, "none", all, true),
        (&xdg, None, &*xdg_z, all, true),
        (&norcs, None, "none", "env", false),
        (&session, Some(&*session_z), &*session_z, all, true),
        // An empty ZDOTDIR, or the app's own folder, is no ZDOTDIR of the user's.
        (&plain, Some(""), "none", all, true),
        (&plain, Some(&*app_z), "none", all, true),
    ] {
        let mut env = parent_env(home, &zsh);
        if let Some(value) = app_zdotdir {
            env.push(("ZDOTDIR".into(), value.into()));
        }
        let manager = TerminalManager::new(TerminalProgram::LoginShell)
            .with_zsh_dir(&zsh_dir)
            .with_parent_env(env);
        let (id, out, exit) = open(&manager, &bin);
        manager.write(&id, ZSH_PROBE).unwrap();
        let code = exit.recv_timeout(Duration::from_secs(20));
        let text = out.lock().unwrap().clone();
        assert_eq!(code, Ok(Some(0)), "{text}");

        let path = printed(&text, "P");
        let dirs: Vec<&str> = path.split(':').collect();
        assert_eq!(dirs[0], bin_text, "{path}");
        assert_eq!(dirs.iter().filter(|d| **d == bin_text).count(), 1, "{path}");
        assert_eq!(dirs.contains(&"/synthetic/brew/bin"), brew, "{path}");
        assert_eq!(printed(&text, "M"), marks);
        assert_eq!(printed(&text, "Z"), zdotdir);
        assert_eq!(printed(&text, "E"), zdotdir);
        let history = printed(&text, "H");
        assert!(
            !Path::new(&history).starts_with(&zsh_dir),
            "history in the app's folder: {history}"
        );
        assert_eq!(printed(&text, "X"), "000");
        assert_eq!(printed(&text, "C"), "none,none");
        assert!(!text.contains(TOKEN), "token printed: {text}");
    }

    // The app's folder is private and holds only folder-free, value-free startup files.
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&zsh_dir), 0o700);
    let mut names: Vec<String> = std::fs::read_dir(&zsh_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, [".zlogin", ".zprofile", ".zshenv", ".zshrc"]);
    for name in &names {
        let file = zsh_dir.join(name);
        assert_eq!(mode(&file), 0o600, "{name}");
        let text = std::fs::read_to_string(&file).unwrap();
        for value in [TOKEN, "127.0.0.1", bin_text.as_str()] {
            assert!(!text.contains(value), "{value} in {name}");
        }
    }

    // Another shell gets neither ZDOTDIR nor the helper variables.
    let sh = TerminalManager::new(TerminalProgram::LoginShell)
        .with_zsh_dir(&zsh_dir)
        .with_parent_env(parent_env(&plain, Path::new("/bin/sh")));
    let (id, out, exit) = open(&sh, &bin);
    sh.write(
        &id,
        "echo \"$((6*7))Z=${ZDOTDIR-none} ${ZEROPW_TERMINAL_BIN-none}\"; exit\n",
    )
    .unwrap();
    let code = exit.recv_timeout(Duration::from_secs(20));
    let text = out.lock().unwrap().clone();
    assert_eq!(code, Ok(Some(0)), "{text}");
    assert_eq!(printed(&text, "Z"), "none none");
}

/// zsh as a login shell in a terminal whose app startup folder, under `root`, cannot be
/// created (the place of its parent folder is taken by a file); what the probe printed.
fn zsh_with_an_unwritable_startup_folder(root: &Path) -> String {
    let bin = root.join("bundle");
    std::fs::create_dir_all(&bin).unwrap();
    let taken = root.join("app");
    std::fs::write(&taken, "synthetic").unwrap();
    let home = root.join("home");
    write_files(
        &home,
        &[
            (".zshenv", "ZPW_MARKS=env\n"),
            (
                ".zprofile",
                "ZPW_MARKS+=,profile\nPATH=/synthetic/brew/bin:$PATH\n",
            ),
            (".zshrc", "ZPW_MARKS+=,rc\n"),
            (".zlogin", "ZPW_MARKS+=,login\n"),
        ],
    );
    let manager = TerminalManager::new(TerminalProgram::LoginShell)
        .with_zsh_dir(taken.join("zsh"))
        .with_parent_env(parent_env(&home, &zsh()));
    let (id, out, exit) = open(&manager, &bin);
    manager.write(&id, ZSH_PROBE).unwrap();
    let code = exit.recv_timeout(Duration::from_secs(20));
    let text = out.lock().unwrap().clone();
    assert_eq!(code, Ok(Some(0)), "{text}");
    text
}

/// When the app's zsh startup files cannot be written, zsh still starts, as any other shell:
/// its own startup files run as zsh reads them, so the bundle folder is no longer first, and
/// nothing of the app's (ZDOTDIR, helper variables) is in its environment.
#[test]
fn zsh_starts_without_the_app_startup_files_when_they_cannot_be_written() {
    let root = tempfile::tempdir().unwrap();
    let text = zsh_with_an_unwritable_startup_folder(root.path());
    let path = printed(&text, "P");
    let dirs: Vec<&str> = path.split(':').collect();
    assert_eq!(dirs[0], "/synthetic/brew/bin", "{path}");
    let bin = root.path().join("bundle");
    assert!(dirs.iter().any(|d| Path::new(d) == bin), "{path}");
    assert_eq!(printed(&text, "M"), "env,profile,rc,login");
    assert_eq!(printed(&text, "Z"), "none");
    assert_eq!(printed(&text, "E"), "none");
    assert_eq!(printed(&text, "X"), "000");
    assert!(!root.path().join("app/zsh").exists());
    assert!(!text.contains(TOKEN), "token printed: {text}");
}

/// Run `f` on another thread; fail the test (instead of hanging it) if it takes longer than
/// `limit`.
fn within<T: Send + 'static>(
    limit: Duration,
    what: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(limit)
        .unwrap_or_else(|_| panic!("{what} did not return within {limit:?}"))
}

/// A process that still runs (gone and zombie both count as stopped).
fn running(pid: i32) -> bool {
    if nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_err() {
        return false;
    }
    let out = std::process::Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    let stat = String::from_utf8_lossy(&out.stdout);
    !stat.trim().is_empty() && !stat.trim_start().starts_with('Z')
}

/// `NAME=<digits>` printed by the shell (the echoed command line has `$` instead of digits).
fn printed_pid(text: &str, name: &str) -> Option<i32> {
    let marker = format!("{name}=");
    text.match_indices(&marker).find_map(|(at, _)| {
        let digits: String = text[at + marker.len()..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse().ok()
    })
}

/// CORE-1: a program that does not read its input makes PTY writes block once the kernel's
/// input buffer is full. That must not hold up `terminal_write` itself, listing, other
/// terminals or closing.
#[test]
fn a_program_that_does_not_read_input_blocks_nothing() {
    let manager = Arc::new(sh("echo ready; exec sleep 60"));
    let (id, out, _exit) = open(&manager, Path::new("/opt/zeropw-bundle"));
    assert!(wait_until(Duration::from_secs(5), || out
        .lock()
        .unwrap()
        .contains("ready")));
    let other = manager.clone();
    let (other_id, other_out, _other_exit) = open(&other, Path::new("/opt/zeropw-bundle"));

    // A multi-line paste far beyond the PTY's input buffer, in 64 KiB writes.
    let paste = "abcdefghi\n".repeat(6600);
    let writer = manager.clone();
    let writer_id = id.clone();
    let results = within(Duration::from_secs(10), "terminal_write", move || {
        (0..8)
            .map(|_| writer.write(&writer_id, &paste[..64 * 1024]))
            .collect::<Vec<_>>()
    });
    assert!(results[0].is_ok(), "{:?}", results[0]);
    let busy = results
        .iter()
        .filter_map(|r| r.as_ref().err())
        .map(|e| e.reason.as_str())
        .collect::<Vec<_>>();
    assert!(
        !busy.is_empty() && busy.iter().all(|r| *r == "terminal_busy"),
        "{busy:?}"
    );

    // Everything else still answers while the paste is stuck.
    let lister = manager.clone();
    let listed = within(Duration::from_secs(2), "terminal_list", move || {
        lister.list()
    });
    assert_eq!(listed.len(), 2);
    let resizer = manager.clone();
    let resize_id = id.clone();
    within(Duration::from_secs(2), "terminal_resize", move || {
        resizer.resize(&resize_id, 100, 30)
    })
    .unwrap();
    other.write(&other_id, "x").unwrap();
    let _ = other_out;

    let closer = manager.clone();
    let close_id = id.clone();
    within(Duration::from_secs(10), "terminal_close", move || {
        closer.close(&close_id)
    });
    assert_eq!(manager.list().len(), 1);
    let all = manager.clone();
    within(Duration::from_secs(10), "close_all", move || {
        all.close_all()
    });
    assert!(manager.list().is_empty());
}

/// CORE-2: closing a terminal stops what was started in it, including jobs in their own
/// process groups that ignore SIGHUP and processes whose parent already exited; app quit
/// (`close_all`) does the same before it returns.
#[test]
fn close_and_quit_stop_every_process_the_terminal_started() {
    let Some(bash) = ["/bin/bash", "/usr/bin/bash"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
    else {
        eprintln!("no bash; skipped");
        return;
    };
    for quit in [false, true] {
        let manager = TerminalManager::new(TerminalProgram::Program {
            path: PathBuf::from(bash),
            // `+H`: no history expansion, so the `$!` below is not rewritten from the history
            // file of whoever runs the test (bash 3.2 on macOS expands `!"`).
            args: vec![
                "--norc".into(),
                "--noprofile".into(),
                "+H".into(),
                "-i".into(),
            ],
        });
        let (id, out, _exit) = open(&manager, Path::new("/opt/zeropw-bundle"));
        // A background job (its own process group), an orphan still on the terminal, and a
        // foreground job, all ignoring SIGHUP.
        manager
            .write(
                &id,
                "sh -c 'trap \"\" HUP; exec sleep 120' & echo \"BG=$!\"\n\
                 sh -c '(trap \"\" HUP; exec sleep 120) & echo \"ORPHAN=$!\"'\n\
                 sh -c 'trap \"\" HUP; echo \"FG=$$\"; exec sleep 120'\n",
            )
            .unwrap();
        let mut pids = Vec::new();
        assert!(
            wait_until(Duration::from_secs(10), || {
                let text = out.lock().unwrap().clone();
                pids = ["BG", "ORPHAN", "FG"]
                    .iter()
                    .filter_map(|name| printed_pid(&text, name))
                    .collect();
                pids.len() == 3
            }),
            "{}",
            out.lock().unwrap()
        );
        assert!(wait_until(Duration::from_secs(5), || pids
            .iter()
            .all(|&p| running(p))));
        if quit {
            manager.close_all();
        } else {
            manager.close(&id);
        }
        // Signals are delivered by the time close returns; allow a moment for reaping.
        assert!(
            wait_until(Duration::from_secs(2), || pids.iter().all(|&p| !running(p))),
            "still running after {}: {:?}",
            if quit { "close_all" } else { "close" },
            pids.iter().filter(|&&p| running(p)).collect::<Vec<_>>()
        );
        assert!(manager.list().is_empty());
    }
}
