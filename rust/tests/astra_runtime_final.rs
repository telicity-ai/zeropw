//! Independent Astra final prompt boundaries, synthetic controlling PTYs only.
mod cli_pty;

use std::time::Duration;

#[test]
fn repeated_prompt_restores_terminal_on_eof_invalid_utf8_and_signals() {
    for (input, bytes) in [
        ("interrupt", b"\x03".as_slice()),
        ("eof", b"\x04"),
        ("invalid", b"\xff\n"),
    ] {
        let temp = tempfile::TempDir::new().unwrap();
        let argv: Vec<std::ffi::OsString> = vec![
            env!("CARGO_BIN_EXE_zeropw-admin").into(),
            "--state-dir".into(),
            temp.path().join("state").into(),
            "init".into(),
        ];
        let mut session = cli_pty::start_keeper(
            &argv,
            &[("PATH", "/usr/bin:/bin")],
            8.0,
            cli_pty::Inherited::Default,
        );
        session.wait_for(
            &["Administrator passphrase:", "CHILD_PID="],
            Duration::from_secs(5),
        );
        session.write(b"synthetic-first-passphrase-final\n");
        session.wait_for(&["Recovery passphrase:"], Duration::from_secs(5));
        assert!(!session.slave_echo(), "{input}: second prompt echoes");
        session.write(bytes);
        let result = session.result(Duration::from_secs(12));
        session.wait_exit(Duration::from_secs(2));
        assert_eq!(result["terminated"], true, "{input}: {result}");
        assert_eq!(result["restored"], true, "{input}: {result}");
        assert_ne!(result["code"], 0, "{input}: {result}");
        assert!(
            !session.contains("synthetic-first-passphrase-final"),
            "{input}: passphrase echoed"
        );
        assert!(!temp.path().join("state").join("admin.json").exists());
    }
}
