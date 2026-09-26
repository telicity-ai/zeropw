fn main() {
    std::process::exit(zeropw::agent_cli::main_os(
        std::env::args_os().skip(1).collect(),
    ));
}
