fn main() {
    std::process::exit(zeropw::agent_cli::main(
        &std::env::args().skip(1).collect::<Vec<_>>(),
    ));
}
