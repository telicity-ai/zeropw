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
