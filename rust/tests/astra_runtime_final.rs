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
    let script = script.replace(" p.wait(timeout=8)", " assert p.wait(timeout=8)!=0");
    assert!(script.contains("second prompt timed out"));
    for input in ["interrupt", "eof", "invalid"] {
        let temp = tempfile::TempDir::new().unwrap();
        let output = Command::new("python3.12")
            .args(["-I", "-c", &script])
            .arg(env!("CARGO_BIN_EXE_zeropw-admin"))
            .arg(temp.path().join("state"))
            .arg("rust")
            .arg(format!("{}/..", env!("CARGO_MANIFEST_DIR")))
            .arg(input)
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
