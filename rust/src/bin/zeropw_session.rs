//! Trusted exec trampoline: establish the Python `start_new_session=True`
//! boundary with safe Rust before replacing ourselves with the fixed CLI.
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;

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
    if ack.write_all(b"R").is_err() {
        std::process::exit(127);
    }
    let error = Command::new(program).args(args).exec();
    let _ = error;
    let _ = ack.write_all(b"F");
    std::process::exit(127);
}
