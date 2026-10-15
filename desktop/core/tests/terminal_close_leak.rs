//! R2N-2: closing a terminal whose paste is stuck behind a program that does not read its
//! input ends that terminal's reader and writer threads and closes every descriptor it opened
//! (PTY master copies, the stop pipe) before `close` returns. A test binary of its own with a
//! single test: it counts the whole process's threads and open descriptors, so nothing else
//! may run beside it.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::wait_until;
use zeropw_desktop_core::SecretString;
use zeropw_desktop_core::terminal::{
    MAX_QUEUED_INPUT, TerminalManager, TerminalProgram, TerminalRequest, TerminalSink,
};

const TOKEN: &str = "zpw_synthetic_terminal_token_0123456789";

struct Collect(Arc<Mutex<String>>);

impl TerminalSink for Collect {
    fn data(&mut self, chunk: &str) {
        self.0.lock().unwrap().push_str(chunk);
    }
    fn exit(&mut self, _code: Option<u32>) {}
}

/// Open descriptors of this process (the listing's own descriptor counts in every sample).
fn open_fds() -> usize {
    std::fs::read_dir("/dev/fd").unwrap().count()
}

/// Threads of this process where the platform lists them (Linux); elsewhere the descriptor
/// count stands in, since each terminal thread owns a descriptor until it ends.
fn threads() -> Option<usize> {
    std::fs::read_dir("/proc/self/task")
        .ok()
        .map(|tasks| tasks.count())
}

fn open(manager: &TerminalManager) -> (String, Arc<Mutex<String>>) {
    let token = SecretString::from(TOKEN);
    let out = Arc::new(Mutex::new(String::new()));
    let id = manager
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
            Box::new(Collect(out.clone())),
        )
        .unwrap();
    assert!(
        wait_until(Duration::from_secs(5), || out
            .lock()
            .unwrap()
            .contains("ready")),
        "{}",
        out.lock().unwrap()
    );
    (id, out)
}

#[test]
fn closing_a_terminal_with_a_stuck_paste_leaves_no_thread_or_descriptor_behind() {
    let manager = TerminalManager::new(TerminalProgram::Program {
        path: PathBuf::from("/bin/sh"),
        args: vec!["-c".into(), "echo ready; exec sleep 60".into()],
    });
    // One plain open and close first, so nothing set up once per process counts below.
    let (warm, _) = open(&manager);
    manager.close(&warm);

    let fds_before = open_fds();
    let threads_before = threads();
    let (id, _out) = open(&manager);

    // A newline-terminated multi-line paste that `sleep` never reads: once the PTY's input
    // buffer is full the writer thread is stuck mid-write, and the queue behind it fills up.
    let paste = "abcdefghi\n".repeat(64 * 1024 / 10);
    let mut queued = 0;
    let mut busy = false;
    while queued <= 2 * MAX_QUEUED_INPUT {
        match manager.write(&id, &paste) {
            Ok(()) => queued += paste.len(),
            Err(e) => {
                assert_eq!(e.reason, "terminal_busy");
                busy = true;
                break;
            }
        }
    }
    assert!(busy, "the paste never got stuck");
    assert!(open_fds() > fds_before);

    manager.close(&id);
    assert!(manager.list().is_empty());
    assert_eq!(open_fds(), fds_before, "descriptors left open after close");
    assert_eq!(
        threads(),
        threads_before,
        "threads left running after close"
    );
}
