//! The native administrator and agent CLIs keep the original command-line
//! contract: argparse usage and help text, error JSON, `~` expansion,
//! origin-only targets, audit records and state effects, case by case.
//!
//! Each case in `fixtures/python/cli/cli_parity.json` carries the exit status,
//! stdout and stderr the original Python CLI produced for the same argv,
//! environment, stdin and synthetic state (masked for random tokens,
//! identifiers and timestamps; see `fixtures/python/cli/GENERATE.md`). Here
//! the native administrator prepares that state and the native binary must
//! reproduce the recorded outcome.
use std::path::Path;
use std::process::{Command, Stdio};
use std::io::Write;

use regex::Regex;
use serde_json::Value;

const PROGS: [&str; 4] = ["zeropw-admin", "admin_cli.py", "zeropw-agent", "agent_cli.py"];

fn masks() -> Vec<(Regex, &'static str)> {
    [
        (r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z", "<TS>"),
        (r"zpwc_[A-Za-z0-9_\-]+", "<TOKEN>"),
        (r"\b[0-9a-f]{64}\b", "<HEX64>"),
        (r"\b[a-z2-7]{26}-[0-9a-f]{32}\b", "<ENVID>"),
        (
            r#"ssh-ed25519 AAAA[A-Za-z0-9+/=]+ ([^\s@"]+@)"#,
            "ssh-ed25519 <KEY> ${1}",
        ),
        (r"\b[0-9a-f]{32}\b", "<HEX32>"),
        (r"inc-[0-9TZ]+-[0-9a-f]{8}", "<INC>"),
        (r"g-[0-9a-f]{8,}", "<GRANT>"),
        (r"SHA256:[A-Za-z0-9+/]+", "<FP>"),
        // Socket error text is the platform's, not part of the contract.
        (r#"\[Errno -?\d+\] [^"\\]*"#, "[Errno <N>] <MSG>"),
    ]
    .into_iter()
    .map(|(pattern, replacement)| (Regex::new(pattern).unwrap(), replacement))
    .collect()
}

/// `user@host`, the comment `ssh-keygen` gives a generated key.
fn user_at_host() -> String {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::current())
        .unwrap()
        .unwrap()
        .name;
    let mut buffer = [0u8; 256];
    // SAFETY: the buffer is valid for its full length.
    assert_eq!(
        unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) },
        0
    );
    let end = buffer.iter().position(|&b| b == 0).unwrap();
    format!("{user}@{}", String::from_utf8_lossy(&buffer[..end]))
}

struct Masker {
    masks: Vec<(Regex, &'static str)>,
    user_host: String,
}

impl Masker {
    fn mask(&self, text: &str, tmp: &str) -> String {
        let mut text = text
            .replace(tmp, "{tmp}")
            .replace(&self.user_host, "<USER@HOST>");
        for prog in PROGS {
            text = text.replace(prog, "PROG");
        }
        for (pattern, replacement) in &self.masks {
            text = pattern.replace_all(&text, *replacement).into_owned();
        }
        text
    }
}

fn run(program: &str, args: &[String], env: &[(String, String)], stdin: &[u8]) -> (i32, String, String) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let _ = input.write_all(stdin);
    drop(input);
    let output = child.wait_with_output().unwrap();
    (
        output.status.code().expect("exit status"),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_owned())
        .collect()
}

fn one(case: &Value, masker: &Masker) -> Value {
    let admin = env!("CARGO_BIN_EXE_zeropw-admin");
    let temp = tempfile::Builder::new()
        .prefix("zeropw-cli-parity-")
        .tempdir()
        .unwrap();
    let tmp = temp.path().to_str().unwrap().to_owned();
    let state = format!("{tmp}/state");
    let subst = |items: Vec<String>| -> Vec<String> {
        items
            .into_iter()
            .map(|item| item.replace("{state}", &state).replace("{tmp}", &tmp))
            .collect()
    };
    let env: Vec<(String, String)> = [
        ("PATH", std::env::var("PATH").unwrap_or_default()),
        ("HOME", tmp.clone()),
        ("LC_ALL", "C.UTF-8".to_owned()),
        ("COLUMNS", "80".to_owned()),
        ("ZEROPW_ADMIN_PASSPHRASE", "admin-passphrase-1".to_owned()),
        ("ZEROPW_RECOVERY_PASSPHRASE", "recovery-passphrase-1".to_owned()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect();
    let setup: Vec<Vec<String>> = case
        .get("setup")
        .and_then(Value::as_array)
        .map(|steps| steps.iter().map(strings).collect())
        .unwrap_or_default();
    for mut step in setup {
        if step.first().map(String::as_str) == Some("!sh") {
            let script = step[1].replace("{state}", &state).replace("{tmp}", &tmp);
            let status = Command::new("sh")
                .args(["-c", &script])
                .env_clear()
                .envs(env.iter().map(|(k, v)| (k, v)))
                .status()
                .unwrap();
            assert!(status.success(), "setup {script}");
            continue;
        }
        let mut stdin = Vec::new();
        if let Some(first) = step.first().and_then(|s| s.strip_prefix("!stdin=")) {
            stdin = first.as_bytes().to_vec();
            step.remove(0);
        }
        run(admin, &subst(step), &env, &stdin);
    }
    let mut case_env = env.clone();
    if let Some(extra) = case.get("env_extra").and_then(Value::as_object) {
        for (name, value) in extra {
            case_env.retain(|(k, _)| k != name);
            case_env.push((name.clone(), value.as_str().unwrap().to_owned()));
        }
    }
    let program = if case["kind"] == "admin" {
        admin
    } else {
        env!("CARGO_BIN_EXE_zeropw-agent")
    };
    let stdin = case.get("stdin").and_then(Value::as_str).unwrap_or("");
    let (code, mut out, err) = run(program, &subst(strings(&case["argv"])), &case_env, stdin.as_bytes());
    for step in case.get("after").map(|a| a.as_array().unwrap().clone()).unwrap_or_default() {
        let (_, after_out, after_err) = run(admin, &subst(strings(&step)), &env, b"");
        out.push_str("\n#after: ");
        out.push_str(&after_out);
        out.push_str(&after_err);
    }
    serde_json::json!({
        "code": code,
        "stdout": masker.mask(&out, &tmp),
        "stderr": masker.mask(&err, &tmp),
    })
}

#[test]
fn native_cli_reproduces_the_recorded_command_line_contract() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/python/cli/cli_parity.json")).unwrap();
    assert!(cases.len() >= 70, "fixture table is incomplete");
    let masker = Masker {
        masks: masks(),
        user_host: user_at_host(),
    };
    let mut failures = Vec::new();
    for case in &cases {
        let actual = one(case, &masker);
        if actual != case["expected"] {
            failures.push(format!(
                "DIFF {} {}\n--- expected\n{}\n--- native\n{}",
                case["kind"],
                case["argv"],
                serde_json::to_string_pretty(&case["expected"]).unwrap(),
                serde_json::to_string_pretty(&actual).unwrap()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases differ:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}
