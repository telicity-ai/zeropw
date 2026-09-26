//! Trusted exec trampoline: establish the Python `start_new_session=True`
//! boundary with safe Rust before replacing ourselves with the fixed CLI.
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Linux `BINPRM_BUF_SIZE`: how much of a file the kernel inspects to pick a
/// binary format, zero-padded when the file is shorter.
const HEADER_BYTES: usize = 256;
/// Bound on `#!` interpreter chains followed here. The kernel itself stops
/// with `ELOOP` (never `ENOEXEC`) after fewer rewrites than this, so a chain
/// this long fails either way.
const MAX_INTERPRETER_DEPTH: u8 = 8;

/// Whether `execve(path)` would run `path` rather than fail. Python's
/// `subprocess.Popen` calls `execve` itself, so a file in a format the kernel
/// does not recognise is `ENOEXEC`: a spawn failure. `Command::exec` goes
/// through libc `execvp`, which glibc and the BSD/macOS libcs retry through
/// `/bin/sh` on `ENOEXEC`. There is no safe direct `execve`, so every file
/// the kernel would refuse is refused here before exec instead.
///
/// Only a file this helper cannot read (execute-only permission) is left to
/// `exec` unexamined; libc's `/bin/sh` retry cannot read it either.
fn kernel_runs(path: &Path, depth: u8) -> bool {
    if depth > MAX_INTERPRETER_DEPTH {
        return true;
    }
    // O_NONBLOCK: opening a FIFO must not wait for a writer.
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(e) => {
            return e.kind() == std::io::ErrorKind::PermissionDenied && regular_executable(path);
        }
    };
    // `execve` needs a regular file with execute permission (`EACCES`).
    if !file.metadata().is_ok_and(|m| m.is_file()) || !regular_executable(path) {
        return false;
    }
    let mut header = [0u8; HEADER_BYTES];
    let mut filled = 0;
    let mut reader = file;
    while filled < HEADER_BYTES {
        match reader.read(&mut header[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
            Err(_) => return false,
        }
    }
    if header.starts_with(b"#!") {
        if depth > 0 && !NESTED_INTERPRETERS {
            return false;
        }
        return interpreter(&header)
            .is_some_and(|name| kernel_runs(Path::new(OsStr::from_bytes(name)), depth + 1));
    }
    native_object(&header)
}

fn regular_executable(path: &Path) -> bool {
    path.is_file() && rustix::fs::access(path, rustix::fs::Access::EXEC_OK).is_ok()
}

/// Linux `fs/binfmt_script.c` `load_script`: the interpreter path of a `#!`
/// header, or `None` where the kernel answers `ENOEXEC` (no name, or a name
/// that may have been truncated at the end of the buffer).
fn interpreter(header: &[u8; HEADER_BYTES]) -> Option<&[u8]> {
    let blank = |b: &u8| matches!(b, b' ' | b'\t');
    let last = HEADER_BYTES - 1;
    let mut end = match header.iter().position(|b| *b == b'\n') {
        Some(newline) => newline,
        None => {
            // No newline: the name must be followed by a blank or NUL inside
            // the buffer, else it is assumed truncated.
            let first = (2..=last).find(|&i| !blank(&header[i]))?;
            (first..=last).find(|&i| blank(&header[i]) || header[i] == 0)?;
            last
        }
    };
    while end > 2 && blank(&header[end - 1]) {
        end -= 1;
    }
    let name_start = (2..end).find(|&i| !blank(&header[i]))?;
    let name = header.get(name_start..end)?;
    let name_len = name
        .iter()
        .position(|b| blank(b) || *b == 0)
        .unwrap_or(name.len());
    name.get(..name_len).filter(|n| !n.is_empty())
}

/// Linux runs an interpreter that is itself a `#!` script; XNU's
/// `exec_shell_imgact` refuses a second level (`IMGPF_INTERPRET`).
const NESTED_INTERPRETERS: bool = cfg!(not(target_vendor = "apple"));

#[cfg(target_vendor = "apple")]
fn native_object(header: &[u8]) -> bool {
    // Mach-O thin (32/64-bit, either byte order) and universal ("fat") files;
    // a slice for another CPU is `EBADARCH`, which no libc retries.
    const MAGICS: [[u8; 4]; 8] = [
        [0xfe, 0xed, 0xfa, 0xce],
        [0xce, 0xfa, 0xed, 0xfe],
        [0xfe, 0xed, 0xfa, 0xcf],
        [0xcf, 0xfa, 0xed, 0xfe],
        [0xca, 0xfe, 0xba, 0xbe],
        [0xbe, 0xba, 0xfe, 0xca],
        [0xca, 0xfe, 0xba, 0xbf],
        [0xbf, 0xba, 0xfe, 0xca],
    ];
    header
        .get(..4)
        .is_some_and(|magic| MAGICS.iter().any(|known| known == magic))
}

/// ELF machines this host's kernel runs: native, plus the 32-bit compat ABI.
#[cfg(all(not(target_vendor = "apple"), target_arch = "x86_64"))]
const MACHINES: Option<&[(u8, u16)]> = Some(&[(2, 62), (1, 62), (1, 3)]);
#[cfg(all(not(target_vendor = "apple"), target_arch = "aarch64"))]
const MACHINES: Option<&[(u8, u16)]> = Some(&[(2, 183), (1, 40)]);
#[cfg(all(
    not(target_vendor = "apple"),
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
const MACHINES: Option<&[(u8, u16)]> = None;

/// Linux `fs/binfmt_elf.c` `load_elf_binary`'s header checks that answer
/// `ENOEXEC`: magic, `ET_EXEC`/`ET_DYN`, the host's machine and byte order,
/// the native program-header entry size and a sane program-header count.
#[cfg(not(target_vendor = "apple"))]
fn native_object(header: &[u8]) -> bool {
    let field = |at: usize| -> Option<u16> {
        let bytes = [*header.get(at)?, *header.get(at + 1)?];
        Some(if cfg!(target_endian = "little") {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        })
    };
    let host_data = if cfg!(target_endian = "little") { 1 } else { 2 };
    if header.get(..4) != Some(b"\x7fELF".as_slice()) || header.get(5) != Some(&host_data) {
        return false;
    }
    let (class, phentsize_at, phdr_size) = match header.get(4) {
        Some(1) => (1u8, 42, 32u16),
        Some(2) => (2u8, 54, 56u16),
        _ => return false,
    };
    let (Some(kind), Some(machine), Some(phentsize), Some(phnum)) = (
        field(16),
        field(18),
        field(phentsize_at),
        field(phentsize_at + 2),
    ) else {
        return false;
    };
    matches!(kind, 2 | 3)
        && MACHINES.is_none_or(|known| known.contains(&(class, machine)))
        && phentsize == phdr_size
        && phnum >= 1
        && u32::from(phnum) <= 65536 / u32::from(phdr_size)
}

/// The file `subprocess.Popen` would execute for `program`: the name itself
/// when it contains a slash, otherwise the first `os.get_exec_path(env)`
/// entry (default `/bin:/usr/bin`) whose `execve` succeeds; `_posixsubprocess`
/// moves on past `ENOEXEC` and `EACCES` just as past `ENOENT`.
fn executable_for(program: &OsStr) -> Option<PathBuf> {
    if program.as_bytes().contains(&b'/') {
        let path = PathBuf::from(program);
        return kernel_runs(&path, 0).then_some(path);
    }
    let search = std::env::var_os("PATH").unwrap_or_else(|| OsString::from("/bin:/usr/bin"));
    search
        .as_bytes()
        .split(|b| *b == b':')
        .map(|directory| {
            // `os.path.join("", name)` is `name`, relative to the cwd.
            let directory = if directory.is_empty() {
                Path::new(".")
            } else {
                Path::new(OsStr::from_bytes(directory))
            };
            directory.join(program)
        })
        .find(|candidate| kernel_runs(candidate, 0))
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
    // Exec exactly the file Python's `execve` would run (argv[0] unchanged),
    // or report the `ENOEXEC`/`ENOENT` spawn failure without ever letting
    // libc hand the file to `/bin/sh`.
    let Some(path) = executable_for(&program) else {
        let _ = ack.write_all(b"F");
        std::process::exit(127);
    };
    if ack.write_all(b"R").is_err() {
        std::process::exit(127);
    }
    let error = Command::new(path).arg0(program).args(args).exec();
    let _ = error;
    let _ = ack.write_all(b"F");
    std::process::exit(127);
}
