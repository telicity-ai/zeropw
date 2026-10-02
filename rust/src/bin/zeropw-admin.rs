fn main() {
    std::process::exit(zeropw::admin_cli::main_os(
        std::env::args_os().skip(1).collect(),
    ));
}
