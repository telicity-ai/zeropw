//! Administrator `--state-dir` expansion: `~` and `~user` resolve through the
//! system user database (no `HOME` in the environment), other paths are used
//! as given, and an unknown user fails closed before any state is touched.
use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};

fn run(state_dir: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_zeropw-admin"))
        .args(["--state-dir", state_dir, "project", "list"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap()
}

fn missing(detail: &str) -> Value {
    json!({"detail": detail, "error": "StateError", "reason": "state_missing"})
}

#[test]
fn home_user_unknown_user_and_non_home_paths_expand_like_the_original_cli() {
    let current = nix::unistd::User::from_uid(nix::unistd::Uid::current())
        .expect("current-user NSS lookup failed")
        .expect("current uid has no NSS user");
    let home = current.dir.to_string_lossy().into_owned();
    let expanded = format!("{}/zeropw-expanduser-missing", home.trim_end_matches('/'));
    let named = format!("~{}/zeropw-expanduser-missing", current.name);
    for (state_dir, detail) in [
        ("~/zeropw-expanduser-missing", expanded.as_str()),
        (named.as_str(), expanded.as_str()),
        (
            "relative/zeropw-expanduser-missing",
            "relative/zeropw-expanduser-missing",
        ),
        ("/zeropw-expanduser-missing", "/zeropw-expanduser-missing"),
    ] {
        let output = run(state_dir);
        assert_eq!(output.status.code(), Some(1), "{state_dir}");
        assert!(output.stdout.is_empty(), "{state_dir}");
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error, missing(detail), "{state_dir}");
        assert_eq!(output.stderr.last(), Some(&b'\n'));
    }

    // An unknown `~user` cannot be expanded: the command fails closed with a
    // JSON error and never treats the literal text as a relative path.
    let unknown = format!(
        "~zeropw-user-that-must-not-exist-{}/state",
        std::process::id()
    );
    let output = run(&unknown);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["reason"], "internal_error", "{error}");
    assert!(!Path::new(&unknown).exists());
}
