//! The native administrator CLI and `python3.12 -m zeropw.admin_cli` given
//! the same raw argv and environment bytes. CPython decodes argv with
//! `surrogateescape`, so a state directory, value file or archive path that
//! is not UTF-8 reaches the file system unchanged and prints as lone
//! surrogate escapes; an undecodable byte in an argparse error prints the
//! same way. Non-path values with undecodable bytes are refused by the port
//! (PORTING.md §3.6), which this test pins next to Python's outcome.
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::process::Command;

fn python() -> String {
    std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".into())
}

/// `(exit status, stdout, stderr)` with this language's base directory
/// replaced by `{base}`.
fn run(
    native: bool,
    base: &[u8],
    argv: &[Vec<u8>],
    home: Option<&[u8]>,
) -> (Option<i32>, String, String) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut command = if native {
        Command::new(env!("CARGO_BIN_EXE_zeropw-admin"))
    } else {
        let mut c = Command::new(python());
        c.args(["-m", "zeropw.admin_cli"]);
        c
    };
    let argv: Vec<OsString> = argv
        .iter()
        .map(|a| {
            let mut bytes = Vec::new();
            let mut rest = a.as_slice();
            while let Some(at) = rest.windows(6).position(|w| w == b"{base}") {
                bytes.extend_from_slice(&rest[..at]);
                bytes.extend_from_slice(base);
                rest = &rest[at + 6..];
            }
            bytes.extend_from_slice(rest);
            OsString::from_vec(bytes)
        })
        .collect();
    command
        .args(argv)
        .current_dir(root)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("PYTHONPATH", root)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("LANG", "C.UTF-8")
        .env("ZEROPW_ADMIN_PASSPHRASE", "synthetic-admin-passphrase")
        .env(
            "ZEROPW_RECOVERY_PASSPHRASE",
            "synthetic-recovery-passphrase",
        );
    if let Some(home) = home {
        command.env("HOME", OsString::from_vec(home.to_vec()));
    }
    let output = command.output().unwrap();
    // The base directory as Python's JSON writes it (lone surrogate escapes).
    let escaped: String = base
        .iter()
        .map(|b| {
            if b.is_ascii() {
                char::from(*b).to_string()
            } else {
                format!("\\u{:04x}", 0xDC00 + u32::from(*b))
            }
        })
        .collect();
    let mask = |bytes: &[u8]| {
        String::from_utf8_lossy(bytes)
            .replace(&escaped, "{base}")
            .replace(&String::from_utf8_lossy(base).into_owned(), "{base}")
    };
    (
        output.status.code(),
        mask(&output.stdout),
        mask(&output.stderr),
    )
}

fn args(items: &[&[u8]]) -> Vec<Vec<u8>> {
    items.iter().map(|a| a.to_vec()).collect()
}

/// Removes the per-run parts (archive manifest, timestamps, server address)
/// of a JSON report. Lone surrogate escapes are kept as literal text so the
/// report still parses.
fn stable(text: &str) -> String {
    let literal = text.replace("\\udc", "\\\\udc");
    match serde_json::from_str::<serde_json::Value>(&literal) {
        Ok(mut value) => {
            if let Some(object) = value.as_object_mut() {
                for key in ["manifest", "pid", "url", "created_at"] {
                    object.remove(key);
                }
            }
            value.to_string()
        }
        Err(_) => text.to_owned(),
    }
}

#[test]
fn non_utf8_paths_match_python_and_other_values_are_refused() {
    let tmp = tempfile::TempDir::new().unwrap();
    let base_of = |language: &str| {
        let dir = tmp.path().join(language);
        std::fs::create_dir_all(&dir).unwrap();
        let mut bytes = dir.as_os_str().as_bytes().to_vec();
        bytes.extend_from_slice(b"/d\xff\xfe");
        std::fs::create_dir_all(OsString::from_vec(bytes.clone())).unwrap();
        let mut value = bytes.clone();
        value.extend_from_slice(b"/value-\xff.txt");
        std::fs::write(OsString::from_vec(value), b"synthetic-secret-value\n").unwrap();
        bytes
    };
    let bases = [base_of("python"), base_of("rust")];
    let state: &[u8] = b"{base}/state-\xff";
    let sequence: Vec<Vec<Vec<u8>>> = vec![
        vec![b"--state-dir".to_vec(), state.to_vec(), b"init".to_vec()],
        args(&[
            b"--state-dir",
            state,
            b"project",
            b"create",
            b"proj",
            b"--environments",
            b"dev",
        ]),
        args(&[
            b"--state-dir",
            state,
            b"secret",
            b"put",
            b"--env",
            b"proj/dev",
            b"--id",
            b"s1",
            b"--kind",
            b"api_key",
            b"--value-file",
            b"{base}/value-\xff.txt",
        ]),
        args(&[
            b"--state-dir",
            state,
            b"secret",
            b"put",
            b"--env",
            b"proj/dev",
            b"--id",
            b"s2",
            b"--kind",
            b"api_key",
            b"--value-file",
            b"{base}/missing-\xff.txt",
        ]),
        args(&[b"--state-dir", state, b"secret", b"list"]),
        args(&[
            b"--state-dir",
            state,
            b"backup",
            b"--out",
            b"{base}/archive-\xfe.zpw",
        ]),
        args(&[
            b"--state-dir",
            state,
            b"backup",
            b"--out",
            b"{base}/missing-\xfe/archive.zpw",
        ]),
        args(&[
            b"--state-dir",
            state,
            b"secret",
            b"put",
            b"--env",
            b"proj/dev",
            b"--id",
            b"s3",
            b"--kind",
            b"k\xff",
        ]),
        args(&[
            b"--state-dir",
            state,
            b"grant",
            b"create",
            b"--version",
            b"1\xff",
        ]),
        args(&[b"--state-dir", b"{base}/never-\xff", b"project", b"list"]),
    ];
    let mut mismatches = Vec::new();
    for argv in &sequence {
        let python = run(false, &bases[0], argv, None);
        let rust = run(true, &bases[1], argv, None);
        let (python, rust) = (
            (python.0, stable(&python.1), python.2),
            (rust.0, stable(&rust.1), rust.2),
        );
        if python != rust {
            mismatches.push(format!(
                "argv {argv:?}\n python: {python:?}\n rust:   {rust:?}"
            ));
        }
    }
    // `~` with a HOME that is not UTF-8, and a HOME pathlib cannot use.
    for (home, argv) in [
        (
            b"{base}".as_slice(),
            args(&[b"--state-dir", b"~/home-state", b"init"]),
        ),
        (
            b"~elsewhere".as_slice(),
            args(&[b"--state-dir", b"~/x", b"init"]),
        ),
    ] {
        let mut outcomes = Vec::new();
        for (native, base) in [(false, &bases[0]), (true, &bases[1])] {
            let home: Vec<u8> = if home == b"{base}" {
                base.clone()
            } else {
                home.to_vec()
            };
            outcomes.push(run(native, base, &argv, Some(&home)));
        }
        if outcomes[0] != outcomes[1] {
            mismatches.push(format!(
                "home {home:?} argv {argv:?}\n python: {:?}\n rust:   {:?}",
                outcomes[0], outcomes[1]
            ));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));

    // A non-path value with an undecodable byte: CPython stores or compares
    // the lone surrogate (here: `invalid_project`); the port refuses it.
    let argv = args(&[b"--state-dir", state, b"project", b"create", b"p\xff"]);
    let python = run(false, &bases[0], &argv, None);
    let rust = run(true, &bases[1], &argv, None);
    assert_eq!(python.0, Some(1), "{python:?}");
    assert!(
        python.2.contains("\"reason\": \"invalid_project\""),
        "{python:?}"
    );
    assert_eq!(rust.0, Some(2), "{rust:?}");
    assert!(
        rust.2
            .contains("argument is not valid UTF-8; values are not echoed"),
        "{rust:?}"
    );
}
