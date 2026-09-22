fn main() {
    std::process::exit(zeropw::admin_cli::main(
        &std::env::args().skip(1).collect::<Vec<_>>(),
    ));
}
