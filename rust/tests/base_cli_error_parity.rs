//! The administrator CLI is where a built-in exception that escapes a store,
//! KMS, vault or context operation becomes observable: `admin_cli.main`
//! prints a fixed rendering per exception class and exits 1. These cases
//! (DEVIATIONS rows 35, 62-70, 87-89, 92, 96, 98) prepare the same synthetic
//! state with the original CLI, break it the same way, and require the native
//! binary to print the same thing, exit the same way and audit the same
//! records as `python -m zeropw.admin_cli`.

use std::path::Path;
use std::process::Command;

const DRIVER: &str = r#"
import json, os, re, shutil, subprocess, sys, tempfile
from pathlib import Path

ADMIN = sys.argv[1]
ROOT = sys.argv[2]
ENV = {"PATH": os.environ.get("PATH", ""), "LC_ALL": "C.UTF-8", "PYTHONPATH": ROOT,
       "ZEROPW_ADMIN_PASSPHRASE": "admin-passphrase-1",
       "ZEROPW_RECOVERY_PASSPHRASE": "recovery-passphrase-1"}
PY = [sys.executable, "-m", "zeropw.admin_cli"]

def py_cli(state, *args):
    subprocess.run(PY + ["--state-dir", state, *args], env=ENV, capture_output=True, check=True)

def make_key_file(t):
    from zeropw import sshwire
    Path(t, "k").write_text(sshwire.generate_ed25519_private_key("a\nb").to_openssh_private_key())

def tamper_backup(t, state, value):
    py_cli(state, "backup", "--out", os.path.join(t, "b.json"))
    p = os.path.join(t, "b.json")
    archive = json.load(open(p))
    archive["manifest"]["sha256"] = value
    json.dump(archive, open(p, "w"))

def setup(case, t, state):
    kind = case["setup"]
    if kind == "admin_json":
        Path(state, "admin.json").write_text(case["doc"])
    elif kind == "restore":
        tamper_backup(t, state, case["sha"])
    elif kind == "ssh_comment":
        py_cli(state, "project", "create", "p")
        make_key_file(t)
    elif kind == "readonly":
        py_cli(state, "project", "create", "p")
        os.mkdir(os.path.join(t, "ro"), 0o500)
        Path(t, "val").write_text("v")
        os.chmod(os.path.join(state, case["dir"]), 0o500)
    elif kind == "audit_dir":
        os.unlink(os.path.join(state, "audit", "audit.jsonl"))
        os.mkdir(os.path.join(state, "audit", "audit.jsonl"))
    elif kind == "audit_bad_utf8":
        with open(os.path.join(state, "audit", "audit.jsonl"), "ab") as f:
            f.write(b"\xff\xfe\n")
    elif kind == "lock_dir":
        lock = os.path.join(state, ".lock")
        if os.path.exists(lock):
            os.unlink(lock)
        os.mkdir(lock)

def run(case, impl):
    t = tempfile.mkdtemp(prefix="zeropw-base-cli-")
    try:
        state = os.path.join(t, "state")
        py_cli(state, "init")
        setup(case, t, state)
        argv = [a.replace("{state}", state).replace("{tmp}", t) for a in case["argv"]]
        env = dict(ENV)
        for key, value in case.get("env", {}).items():
            env[key] = value.replace("{tmp}", t)
        cmd = (PY if impl == "py" else [ADMIN]) + argv
        proc = subprocess.run(cmd, env=env, capture_output=True, stdin=subprocess.DEVNULL, timeout=120,
                              cwd=case.get("cwd", ROOT).replace("{tmp}", t))
        for root, dirs, files in os.walk(t):
            for name in dirs:
                os.chmod(os.path.join(root, name), 0o700)
        os.chmod(t, 0o700)
        audit = os.path.join(state, "audit", "audit.jsonl")
        last = ""
        if os.path.isfile(audit):
            lines = open(audit, "rb").read().splitlines()
            last = lines[-1].decode("utf-8", "replace") if lines else ""
        mask = lambda s: re.sub(r'"ts":"[^"]*"', '"ts":"<TS>"', s.replace(t, "{tmp}"))
        return {"rc": proc.returncode, "stdout": mask(proc.stdout.decode()),
                "stderr": mask(proc.stderr.decode()), "audit": mask(last)}
    finally:
        for root, dirs, files in os.walk(t):
            for name in dirs:
                os.chmod(os.path.join(root, name), 0o700)
        shutil.rmtree(t, ignore_errors=True)

def admin_case(doc):
    return {"setup": "admin_json", "doc": doc, "argv": ["--state-dir", "{state}", "secret", "reveal", "--id", "x"]}

CASES = [admin_case(d) for d in [
    '{}', '[]', '0', '""', '{"salt":1,"hash":"x"}', '{"hash":"x"}', '{"salt":"\\u00e9","hash":"x"}',
    '{"salt":"abc","hash":"x"}', '{"salt":"AAAA"}', '{"salt":null,"hash":"AAAA"}', '[1]', '"str"', '5', 'true',
    '{"salt":"AAAA","hash":"@@"}', '{"salt":"AAAA","hash":"AAAA"}', '{"salt":"AAAA","hash":"\\u00e9"}',
]] + [
    {"setup": "admin_json", "doc": '{"salt":"abc","hash":"x"}', "argv": ["--state-dir", "{state}", "restore-ack"]},
    {"setup": "restore", "sha": "abcé", "argv": ["--state-dir", "{state}", "restore", "--in", "{tmp}/b.json"]},
    {"setup": "restore", "sha": ["é"], "argv": ["--state-dir", "{state}", "restore", "--in", "{tmp}/b.json"]},
    {"setup": "restore", "sha": 5, "argv": ["--state-dir", "{state}", "restore", "--in", "{tmp}/b.json"]},
    {"setup": "ssh_comment", "argv": ["--state-dir", "{state}", "secret", "put", "--id", "k", "--kind",
                                      "ssh_private_key", "--project", "p", "--environment", "dev",
                                      "--value-file", "{tmp}/k"]},
    {"setup": "readonly", "dir": "kms", "argv": ["--state-dir", "{state}", "backup", "--out", "{tmp}/ro/b.json"]},
    {"setup": "readonly", "dir": "kms", "argv": ["--state-dir", "{state}", "backup", "--out", "{tmp}/missing/b.json"]},
    {"setup": "readonly", "dir": "vault", "argv": ["--state-dir", "{state}", "secret", "put", "--id", "s", "--kind",
                                                   "api_key", "--project", "p", "--environment", "dev",
                                                   "--value-file", "{tmp}/val"]},
    {"setup": "readonly", "dir": "kms", "argv": ["--state-dir", "{state}", "recover"]},
    {"setup": "readonly", "dir": ".", "argv": ["--state-dir", "{state}", "project", "create", "q"]},
    {"setup": "audit_dir", "argv": ["--state-dir", "{state}", "audit", "tail"]},
    {"setup": "audit_bad_utf8", "argv": ["--state-dir", "{state}", "audit", "tail"]},
    {"setup": "lock_dir", "argv": ["--state-dir", "{state}", "project", "create", "q"]},
    {"setup": "none", "argv": ["--state-dir", "{state}", "secret", "list"], "env": {"TMPDIR": "/nonexistent-zeropw"}},
    {"setup": "none", "argv": ["--state-dir", "{state}", "secret", "list"], "env": {"TMPDIR": ""}},
    {"setup": "none", "argv": ["--state-dir", "{state}", "secret", "list"],
     "env": {"TMPDIR": "{tmp}/missing", "TEMP": "{tmp}"}},
    {"setup": "none", "argv": ["--state-dir", "{state}", "init"]},
]

failures = 0
for case in CASES:
    py, rs = run(case, "py"), run(case, "rs")
    if py != rs:
        failures += 1
        print("MISMATCH", json.dumps(case), "\n  py:", json.dumps(py), "\n  rs:", json.dumps(rs))
print(f"BASE_CLI_PARITY cases={len(CASES)} failures={failures}")
sys.exit(1 if failures else 0)
"#;

#[test]
fn escaped_builtin_failures_match_the_python_administrator_cli() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let python = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".into());
    let output = Command::new(python)
        .current_dir(root)
        .arg("-c")
        .arg(DRIVER)
        .arg(env!("CARGO_BIN_EXE_zeropw-admin"))
        .arg(root)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("{stdout}{}", String::from_utf8_lossy(&output.stderr));
    assert!(stdout.contains("BASE_CLI_PARITY "), "driver did not report");
    assert!(output.status.success(), "native CLI differs from Python");
}
