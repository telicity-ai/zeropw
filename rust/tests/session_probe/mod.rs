//! A run child that reports its own session: this test binary re-executed
//! for `session_probe::session_probe_entry` with `ZEROPW_TEST_SESSION_PROBE`
//! set prints `PROBE <session leader> <group leader> <has /dev/tty>` (each
//! `true`/`false`), then optionally creates a marker file and stays alive.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::Path;

pub const ENV: &str = "ZEROPW_TEST_SESSION_PROBE";

/// argv for a run that executes the probe.
pub fn argv() -> Vec<String> {
    vec![
        std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        "--exact".into(),
        "session_probe::session_probe_entry".into(),
        "--nocapture".into(),
        "--test-threads=1".into(),
        "-q".into(),
    ]
}

/// Environment for the probe; with a marker it creates it and then sleeps.
pub fn env(marker: Option<&Path>) -> HashMap<String, String> {
    HashMap::from([(
        ENV.to_owned(),
        marker.map_or_else(String::new, |m| m.to_string_lossy().into_owned()),
    )])
}

#[test]
fn session_probe_entry() {
    let Ok(marker) = std::env::var(ENV) else {
        return;
    };
    // SAFETY: plain process-identity queries and an open/close of /dev/tty.
    let (pid, sid, pgrp, tty) = unsafe {
        let fd = libc::open(c"/dev/tty".as_ptr(), libc::O_RDONLY | libc::O_NOCTTY);
        if fd >= 0 {
            libc::close(fd);
        }
        (libc::getpid(), libc::getsid(0), libc::getpgrp(), fd >= 0)
    };
    println!("PROBE {} {} {tty}", sid == pid, pgrp == pid);
    if !marker.is_empty() {
        std::fs::write(&marker, b"").unwrap();
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
}
