fn main() {
    // CPython refuses to start (exit status 1) for an invalid
    // `PYTHONINTMAXSTRDIGITS` before the original program runs at all.
    if let Err(message) = zeropw::pystr::python_startup_check() {
        eprint!("{message}");
        std::process::exit(1);
    }
    std::process::exit(zeropw::agent_cli::main_os(
        std::env::args_os().skip(1).collect(),
    ));
}
