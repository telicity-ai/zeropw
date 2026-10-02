//! Trusted exec trampoline: establish the Python `start_new_session=True`
//! boundary with safe Rust before replacing ourselves with the fixed CLI.
use std::ffi::{CString, OsStr, OsString};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

/// The paths `_posixsubprocess` gives to `execve`: the name itself when it
/// contains a slash, otherwise every `os.get_exec_path(env)` candidate in
/// order. The kernel decides executable formats and interpreter rules.
fn executable_candidates(program: &OsStr) -> Vec<PathBuf> {
    if program.as_bytes().contains(&b'/') {
        return vec![PathBuf::from(program)];
    }
    let search = std::env::var_os("PATH").unwrap_or_else(|| OsString::from("/bin:/usr/bin"));
    search
        .as_bytes()
        .split(|b| *b == b':')
        .map(|directory| {
            // `os.path.join("", name)` is `name`, relative to the cwd.
            if directory.is_empty() {
                PathBuf::from(program)
            } else {
                Path::new(OsStr::from_bytes(directory)).join(program)
            }
        })
        .collect()
}

fn cstring(value: &OsStr) -> Option<CString> {
    CString::new(value.as_bytes()).ok()
}

fn main() {
    let mut args = std::env::args_os().skip(1);
    let Some(ack_path) = args.next() else {
        std::process::exit(127);
    };
    let Ok(mut ack) = UnixStream::connect(ack_path) else {
        std::process::exit(127);
    };
    // macOS `UnixStream` does not guarantee close-on-exec here. The parent
    // must see EOF at exec, not only after a long-running CLI exits.
    if rustix::io::fcntl_setfd(&ack, rustix::io::FdFlags::CLOEXEC).is_err() {
        let _ = ack.write_all(b"F");
        std::process::exit(127);
    }
    let Some(program) = args.next() else {
        let _ = ack.write_all(b"F");
        std::process::exit(127);
    };
    if rustix::process::setsid().is_err() {
        let _ = ack.write_all(b"F");
        std::process::exit(127);
    }
    // Python's subprocess(close_fds=True) must also hold when a trusted
    // component accidentally left an unrelated descriptor inheritable.
    // This is a fresh, single-threaded helper process. Marking (rather than
    // closing) preserves the ACK socket until exec succeeds or fails.
    close_fds::set_fds_cloexec(3, &[]);
    let argv = std::iter::once(program.clone())
        .chain(args)
        .map(|arg| cstring(&arg))
        .collect::<Option<Vec<_>>>();
    let envp = std::env::vars_os()
        .map(|(key, value)| {
            let mut entry = key;
            entry.push("=");
            entry.push(value);
            cstring(&entry)
        })
        .collect::<Option<Vec<_>>>();
    let (Some(argv), Some(envp)) = (argv, envp) else {
        let _ = ack.write_all(b"F");
        std::process::exit(127);
    };
    // R followed by CLOEXEC EOF means a candidate reached the kernel and
    // replaced this session leader. R followed by F means every `execve`
    // failed, preserving the parent's spawn_failed/null-exit contract.
    if ack.write_all(b"R").is_err() {
        std::process::exit(127);
    }
    for path in executable_candidates(&program) {
        let Some(path) = cstring(path.as_os_str()) else {
            continue;
        };
        let _ = nix::unistd::execve(&path, &argv, &envp);
    }
    let _ = ack.write_all(b"F");
    std::process::exit(127);
}
