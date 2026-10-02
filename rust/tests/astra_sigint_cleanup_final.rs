//! Independent negative ownership boundary for the administrator cleanup fix.
use std::process::Command;

#[test]
fn interrupt_preserves_unowned_same_prefix_directories_and_their_contents() {
    let source = include_str!("astra_sigint_cleanup.rs");
    let script = source
        .split("let script = r#\"")
        .nth(1)
        .unwrap()
        .split("\"#;")
        .next()
        .unwrap();
    let script = script.replace(
        "owned.mkdir()",
        "owned.mkdir()\n for name in ('zeropw-runs-unowned','zeropw-sockets-unowned'):\n  (owned/name).mkdir();(owned/name/'sentinel').write_bytes(b'synthetic-unowned-content')",
    ).replace("!=2:", "!=4:")
     .replace("  stdout,stderr=p.communicate(timeout=5)",
        "  stdout,stderr=p.communicate(timeout=5)\n  for name in ('zeropw-runs-unowned','zeropw-sockets-unowned'):\n   assert (owned/name/'sentinel').read_bytes()==b'synthetic-unowned-content'")
     .replace("not r['after']", "r['after']==['zeropw-runs-unowned','zeropw-sockets-unowned']");
    assert!(script.contains("!=4:"));
    assert!(script.contains("read_bytes()==b'synthetic-unowned-content'"));
    let temp = tempfile::TempDir::new().unwrap();
    let output = Command::new("python3.12")
        .args(["-c", &script])
        .arg(env!("CARGO_BIN_EXE_zeropw-admin"))
        .arg(temp.path())
        .arg(format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .env("PYTHONPATH", format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn pre_context_validation_errors_do_not_create_owned_directories() {
    let temp = tempfile::TempDir::new().unwrap();
    let owned = temp.path().join("private-temp");
    std::fs::create_dir(&owned).unwrap();
    for args in [vec!["project", "list"], vec!["init"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_zeropw-admin"))
            .arg("--state-dir")
            .arg(temp.path().join("absent-state"))
            .args(&args)
            .env_clear()
            .env("TMPDIR", &owned)
            .env("ZEROPW_ADMIN_PASSPHRASE", "short")
            .env("ZEROPW_RECOVERY_PASSPHRASE", "synthetic-recovery")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(
            error["reason"],
            if args[0] == "init" {
                "passphrase_too_short"
            } else {
                "state_missing"
            }
        );
        assert_eq!(std::fs::read_dir(&owned).unwrap().count(), 0);
        assert!(!temp.path().join("absent-state").exists());
    }
}
