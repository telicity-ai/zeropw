//! Independent Astra final prompt boundaries, synthetic controlling PTYs only.
use std::process::Command;

#[test]
fn repeated_prompt_restores_terminal_on_eof_invalid_utf8_and_signals() {
    // Reuse the surviving-session fixture without changing its original tests.
    let source = include_str!("astra_cli_runtime_round3.rs");
    let script = source
        .split("let script = r#\"")
        .nth(1)
        .unwrap()
        .split("\"#;")
        .next()
        .unwrap();
    let script = script.replace(
        " os.write(master,b'\\x03' if sys.argv[5]=='interrupt' else b'\\x04')",
        r#" os.write(master,b'synthetic-first-passphrase-final\n')
 end=time.monotonic()+5
 while b'Recovery passphrase:' not in data:
  assert time.monotonic()<end,('second prompt timed out',data)
  if select.select([master],[],[],0.1)[0]:data+=os.read(master,4096)
 assert not (termios.tcgetattr(slave)[3]&termios.ECHO),data
 os.write(master,{'interrupt':b'\x03','eof':b'\x04','invalid':b'\xff\n'}[sys.argv[5]])"#,
    );
    // This is a derived fixture: fail loudly if the source keeper's wait is
    // reshaped, rather than silently losing the nonzero-exit assertion.
    let wait = " try:p.wait(timeout=8)";
    assert_eq!(
        script.matches(wait).count(),
        1,
        "keeper wait anchor changed"
    );
    let script = script.replacen(wait, " try:assert p.wait(timeout=8)!=0", 1);
    assert!(script.contains("second prompt timed out"));
    assert!(script.contains("try:assert p.wait(timeout=8)!=0"));
    #[cfg(target_os = "linux")]
    let read_syscall = libc::SYS_read.to_string();
    #[cfg(not(target_os = "linux"))]
    let read_syscall = "unsupported".to_owned();
    for input in ["interrupt", "eof", "invalid"] {
        let temp = tempfile::TempDir::new().unwrap();
        let output = Command::new("python3.12")
            .args(["-I", "-c", &script])
            .arg(env!("CARGO_BIN_EXE_zeropw-admin"))
            .arg(temp.path().join("state"))
            .arg("rust")
            .arg(format!("{}/..", env!("CARGO_MANIFEST_DIR")))
            .arg(input)
            .arg(&read_syscall)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{input}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
