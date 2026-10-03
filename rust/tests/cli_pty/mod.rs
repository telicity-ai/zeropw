//! Controlling-terminal fixture for administrator prompt tests (synthetic
//! state only).
//!
//! A test opens a pseudo-terminal and starts a *keeper* as the session leader
//! that owns it as its controlling terminal. The keeper is this same test
//! binary re-executed for the `cli_pty::keeper_entry` test with
//! `ZEROPW_TEST_PTY_KEEPER` set. It records the terminal modes, launches the
//! command under test as the terminal's foreground process group (with
//! SIGINT/SIGTERM at their default dispositions and unblocked, like an
//! ordinary interactive launch), prints `CHILD_PID=<pid>`, waits for it, and
//! prints `RESULT={"terminated","code","restored"}`: whether the command
//! exited in time, its status (negative for a signal), and whether it left
//! the terminal modes exactly as it found them (ignoring macOS' transient
//! PENDIN bit). The keeper then restores the terminal for the next user.
#![allow(dead_code)]

use std::ffi::{CString, OsString};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

pub const KEEPER_ENV: &str = "ZEROPW_TEST_PTY_KEEPER";

/// Create a synthetic state directory as the original `Context.initialize`.
pub fn init_state(state: &Path, admin: &str, recovery: &str) {
    zeropw::context::Context::initialize(
        state,
        admin,
        recovery,
        zeropw::context::Config::default(),
        zeropw::clock::system(),
    )
    .unwrap();
}

pub fn mkfifo(path: &Path) {
    let c = CString::new(path.to_str().unwrap()).unwrap();
    // SAFETY: valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo");
}

/// Open a FIFO read-write and non-blocking: a writer that keeps a reader of
/// the FIFO blocked (no data, no EOF) for as long as it is held.
pub fn fifo_anchor(path: &Path) -> OwnedFd {
    let c = CString::new(path.to_str().unwrap()).unwrap();
    // SAFETY: valid path; the returned descriptor is owned below.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    assert!(fd >= 0, "open fifo anchor");
    // SAFETY: freshly opened descriptor.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

pub fn termios(fd: RawFd) -> libc::termios {
    // SAFETY: zeroed termios is a valid out-parameter.
    let mut mode: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: fd is a terminal descriptor owned by the caller.
    assert_eq!(unsafe { libc::tcgetattr(fd, &mut mode) }, 0, "tcgetattr");
    mode
}

pub fn echo_on(fd: RawFd) -> bool {
    termios(fd).c_lflag & libc::ECHO != 0
}

fn same_modes(before: &libc::termios, after: &libc::termios) -> bool {
    // SAFETY: plain reads of a valid termios.
    let speeds = |t: &libc::termios| unsafe { (libc::cfgetispeed(t), libc::cfgetospeed(t)) };
    before.c_iflag == after.c_iflag
        && before.c_oflag == after.c_oflag
        && before.c_cflag == after.c_cflag
        && (before.c_lflag & !libc::PENDIN) == (after.c_lflag & !libc::PENDIN)
        && before.c_cc == after.c_cc
        && speeds(before) == speeds(after)
}

/// Disposition of SIGINT that the keeper inherits from its launcher.
#[derive(Clone, Copy, Debug)]
pub enum Inherited {
    Default,
    Ignored,
    Blocked,
}

pub struct Pty {
    pub master: OwnedFd,
    pub slave: OwnedFd,
}

pub fn open_pty() -> Pty {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: out-parameters are valid; name/termp/winp may be null.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(rc, 0, "openpty");
    for fd in [master, slave] {
        // SAFETY: valid descriptors just returned by openpty.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    // SAFETY: freshly opened descriptors, owned from here on.
    unsafe {
        Pty {
            master: OwnedFd::from_raw_fd(master),
            slave: OwnedFd::from_raw_fd(slave),
        }
    }
}

/// A process tree running on a controlling pseudo-terminal.
pub struct Session {
    pub pty: Pty,
    pub process: Child,
    pub data: Vec<u8>,
}

/// Start `argv` as the session leader of a new pseudo-terminal (no keeper).
pub fn start_direct(argv: &[OsString], env: &[(&str, &str)]) -> Session {
    let pty = open_pty();
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    spawn_on(pty, command, env, Inherited::Default)
}

/// Start a keeper that runs `argv` in the terminal's foreground group.
pub fn start_keeper(
    argv: &[OsString],
    env: &[(&str, &str)],
    timeout: f64,
    inherited: Inherited,
) -> Session {
    let pty = open_pty();
    let config = json!({
        "argv": argv.iter().map(|a| a.to_str().unwrap()).collect::<Vec<_>>(),
        "timeout": timeout,
    });
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args([
        "--exact",
        "cli_pty::keeper_entry",
        "--nocapture",
        "--test-threads",
        "1",
        "-q",
    ]);
    let config = config.to_string();
    let mut env = env.to_vec();
    env.push((KEEPER_ENV, &config));
    spawn_on(pty, command, &env, inherited)
}

fn spawn_on(pty: Pty, mut command: Command, env: &[(&str, &str)], inherited: Inherited) -> Session {
    let slave = pty.slave.as_raw_fd();
    // SAFETY: duplicates of a valid descriptor, each owned by one Stdio.
    let stdio = || unsafe { Stdio::from(OwnedFd::from_raw_fd(libc::dup(slave))) };
    command
        .env_clear()
        .envs(env.iter().copied())
        .stdin(stdio())
        .stdout(stdio())
        .stderr(stdio());
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGINT);
            match inherited {
                Inherited::Default => {
                    libc::signal(libc::SIGINT, libc::SIG_DFL);
                    libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
                }
                Inherited::Ignored => {
                    libc::signal(libc::SIGINT, libc::SIG_IGN);
                }
                Inherited::Blocked => {
                    libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
                }
            }
            Ok(())
        });
    }
    let process = command.spawn().unwrap();
    Session {
        pty,
        process,
        data: Vec::new(),
    }
}

impl Session {
    /// Read whatever arrives on the terminal within `wait`; false at EOF.
    pub fn pump(&mut self, wait: Duration) -> bool {
        let mut poll = libc::pollfd {
            fd: self.pty.master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = wait.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: one valid pollfd.
        let ready = unsafe { libc::poll(&mut poll, 1, millis) };
        if ready <= 0 {
            return true;
        }
        let mut buffer = [0u8; 4096];
        // SAFETY: valid buffer and descriptor.
        let n = unsafe {
            libc::read(
                self.pty.master.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        if n <= 0 {
            // Linux reports EIO once every slave descriptor is closed.
            std::thread::sleep(wait.min(Duration::from_millis(20)));
            return false;
        }
        self.data.extend_from_slice(&buffer[..n as usize]);
        true
    }

    pub fn contains(&self, marker: &str) -> bool {
        self.data
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
    }

    /// Read until every marker has appeared, or fail with the transcript.
    pub fn wait_for(&mut self, markers: &[&str], timeout: Duration) {
        let end = Instant::now() + timeout;
        while !markers.iter().all(|m| self.contains(m)) {
            assert!(
                Instant::now() < end,
                "timed out waiting for {markers:?}: {:?}",
                String::from_utf8_lossy(&self.data)
            );
            self.pump(Duration::from_millis(50));
        }
    }

    pub fn write(&self, bytes: &[u8]) {
        // SAFETY: valid buffer and descriptor.
        let n = unsafe {
            libc::write(
                self.pty.master.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
            )
        };
        assert_eq!(n, bytes.len() as isize, "write to terminal");
    }

    pub fn slave_echo(&self) -> bool {
        echo_on(self.pty.slave.as_raw_fd())
    }

    /// The command's PID as reported by the keeper.
    pub fn child_pid(&self) -> i32 {
        let text = String::from_utf8_lossy(&self.data);
        let start = text.find("CHILD_PID=").expect("CHILD_PID reported") + "CHILD_PID=".len();
        text[start..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse()
            .unwrap()
    }

    /// The keeper's `RESULT=` object.
    pub fn result(&mut self, timeout: Duration) -> Value {
        let end = Instant::now() + timeout;
        loop {
            let text = String::from_utf8_lossy(&self.data).into_owned();
            if let Some(start) = text.find("RESULT=") {
                let rest = &text[start + "RESULT=".len()..];
                if let Some(stop) = rest.find(['\r', '\n']) {
                    return serde_json::from_str(&rest[..stop]).unwrap();
                }
            }
            assert!(Instant::now() < end, "no RESULT line: {text:?}");
            self.pump(Duration::from_millis(50));
        }
    }

    /// Wait for the session leader (keeper or direct command) to exit, then
    /// collect its remaining terminal output.
    pub fn wait_exit(&mut self, timeout: Duration) -> std::process::ExitStatus {
        let end = Instant::now() + timeout;
        loop {
            if let Some(status) = self.process.try_wait().unwrap() {
                loop {
                    let before = self.data.len();
                    if !self.pump(Duration::from_millis(20)) || self.data.len() == before {
                        return status;
                    }
                }
            }
            assert!(
                Instant::now() < end,
                "session leader still running: {:?}",
                String::from_utf8_lossy(&self.data)
            );
            self.pump(Duration::from_millis(50));
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.process.try_wait().ok().flatten().is_none() {
            let _ = self.process.kill();
            let _ = self.process.wait();
        }
    }
}

pub fn kill(pid: i32, signal: i32) {
    // SAFETY: plain signal delivery to a process this test started.
    assert_eq!(unsafe { libc::kill(pid, signal) }, 0, "kill {pid} {signal}");
}

/// `subprocess`-style return code: the exit status, or minus the signal.
pub fn return_code(status: std::process::ExitStatus) -> i64 {
    match status.code() {
        Some(code) => code.into(),
        None => -i64::from(status.signal().unwrap()),
    }
}

/// The keeper: only active when re-executed with `ZEROPW_TEST_PTY_KEEPER`.
#[test]
fn keeper_entry() {
    let Some(config) = std::env::var_os(KEEPER_ENV) else {
        return;
    };
    let config: Value = serde_json::from_str(config.to_str().unwrap()).unwrap();
    let argv: Vec<String> = config["argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap().to_owned())
        .collect();
    let timeout = Duration::from_secs_f64(config["timeout"].as_f64().unwrap());
    // SAFETY: process-wide disposition change in the dedicated keeper.
    unsafe { libc::signal(libc::SIGTTOU, libc::SIG_IGN) };
    let original = termios(0);
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]).env_remove(KEEPER_ENV);
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        command.pre_exec(|| {
            for signal in [libc::SIGINT, libc::SIGTERM] {
                libc::signal(signal, libc::SIG_DFL);
            }
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGINT);
            libc::sigaddset(&mut set, libc::SIGTERM);
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            if libc::setpgid(0, 0) < 0 || libc::tcsetpgrp(0, libc::getpgrp()) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::signal(libc::SIGTTOU, libc::SIG_DFL);
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    let mut out = std::io::stdout();
    writeln!(out, "CHILD_PID={}", child.id()).unwrap();
    out.flush().unwrap();
    let end = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= end {
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let restored = same_modes(&original, &termios(0));
    let result = json!({
        "terminated": status.is_some(),
        "code": status.map(return_code),
        "restored": restored,
    });
    writeln!(out, "RESULT={result}").unwrap();
    if restored {
        writeln!(out, "terminal restored").unwrap();
    }
    out.flush().unwrap();
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    // SAFETY: give the terminal back to the keeper and restore its modes.
    unsafe {
        libc::tcsetpgrp(0, libc::getpgrp());
        libc::tcsetattr(0, libc::TCSANOW, &original);
    }
}

/// Launch with SIGINT/SIGTERM at their defaults and unblocked, independent
/// of a test runner's inherited disposition (like an interactive launch).
pub fn default_signals(command: &mut Command) -> &mut Command {
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        command.pre_exec(|| {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for signal in [libc::SIGINT, libc::SIGTERM] {
                libc::signal(signal, libc::SIG_DFL);
                libc::sigaddset(&mut set, signal);
            }
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            Ok(())
        })
    }
}

/// Wait for a child with a deadline; kill it and fail if it overstays.
pub fn wait_child(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let end = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= end {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child did not exit within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub fn names(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Run `init` on a controlling terminal behind a keeper, answer its first
/// prompt with Ctrl+C (`interrupt`) or Ctrl+D (`eof`), and require the
/// command to end with the original terminal modes restored.
pub fn check_admin_terminal_abort(input: &str, inherited: Inherited) {
    let temp = tempfile::TempDir::new().unwrap();
    let argv: Vec<std::ffi::OsString> = vec![
        env!("CARGO_BIN_EXE_zeropw-admin").into(),
        "--state-dir".into(),
        temp.path().join("state").into(),
        "init".into(),
    ];
    let mut session = start_keeper(&argv, &[("PATH", "/usr/bin:/bin")], 8.0, inherited);
    session.wait_for(
        &["Administrator passphrase:", "CHILD_PID="],
        Duration::from_secs(5),
    );
    let mode = termios(session.pty.slave.as_raw_fd());
    assert!(mode.c_lflag & libc::ISIG != 0, "{input}: ISIG off");
    assert!(mode.c_lflag & libc::ECHO == 0, "{input}: ECHO on");
    session.write(if input == "interrupt" {
        b"\x03"
    } else {
        b"\x04"
    });
    let result = session.result(Duration::from_secs(12));
    let status = session.wait_exit(Duration::from_secs(2));
    assert!(status.success(), "{input}: keeper {status:?}");
    assert_eq!(result["terminated"], true, "{input}: {result}");
    assert_eq!(result["restored"], true, "{input}: {result}");
    assert!(session.contains("terminal restored"));
}
