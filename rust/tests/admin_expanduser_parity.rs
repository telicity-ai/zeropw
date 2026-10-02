//! Administrator path expansion follows pathlib/pwd through the system NSS.
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn python_oracle() -> PathBuf {
    let configured = std::env::var_os("ZEROPW_PYTHON").unwrap_or_else(|| "python3.12".into());
    let candidate = PathBuf::from(&configured);
    if candidate.components().count() > 1 {
        return candidate;
    }
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join(&candidate))
        .find(|path| {
            path.metadata().is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
        .unwrap_or_else(|| panic!("cannot resolve Python oracle {configured:?} before env_clear"))
}

fn run(program: &Path, module: Option<&str>, state_dir: &str) -> std::process::Output {
    let mut command = Command::new(program);
    if let Some(module) = module {
        command.args(["-m", module]);
    }
    command
        .args(["--state-dir", state_dir, "project", "list"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("PYTHONPATH", format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .output()
        .unwrap()
}

#[test]
fn home_user_unknown_user_and_non_home_paths_match_python() {
    let python = python_oracle();
    let rust = Path::new(env!("CARGO_BIN_EXE_zeropw-admin"));
    let current = nix::unistd::User::from_uid(nix::unistd::Uid::current())
        .expect("current-user NSS lookup failed")
        .expect("current uid has no NSS user");
    let named = format!("~{}/zeropw-expanduser-missing", current.name);
    let unknown = format!(
        "~zeropw-user-that-must-not-exist-{}/state",
        std::process::id()
    );
    for state_dir in [
        "~/zeropw-expanduser-missing",
        named.as_str(),
        unknown.as_str(),
        "relative/zeropw-expanduser-missing",
        "/zeropw-expanduser-missing",
    ] {
        let expected = run(&python, Some("zeropw.admin_cli"), state_dir);
        let actual = run(rust, None, state_dir);
        assert_eq!(actual.status.code(), expected.status.code(), "{state_dir}");
        assert_eq!(actual.stdout, expected.stdout, "{state_dir}");
        assert_eq!(actual.stderr, expected.stderr, "{state_dir}");
    }
}
