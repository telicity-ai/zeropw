"""Differential oracle for the administrator and agent command-line contract.

Each case runs the original Python CLI (``python -m zeropw.admin_cli`` /
``zeropw.agent_cli``) and the native binary with the same argv, environment,
stdin and freshly prepared synthetic state (prepared by the original Python
CLI in both runs), then compares exit status, stdout and stderr after masking
random tokens, identifiers and timestamps. Python is only the oracle here.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MASKS = [
    (re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z"), "<TS>"),
    (re.compile(r"zpwc_[A-Za-z0-9_\-]+"), "<TOKEN>"),
    (re.compile(r"\b[0-9a-f]{64}\b"), "<HEX64>"),
    (re.compile(r"\b[a-z2-7]{26}-[0-9a-f]{32}\b"), "<ENVID>"),
    # A generated key: its comment is the invoking user@host, compared as is.
    (re.compile(r"ssh-ed25519 AAAA[A-Za-z0-9+/=]+ (?=[^\s@\"]+@)"), "ssh-ed25519 <KEY> "),
    (re.compile(r"\b[0-9a-f]{32}\b"), "<HEX32>"),
    (re.compile(r"inc-[0-9TZ]+-[0-9a-f]{8}"), "<INC>"),
    (re.compile(r"g-[0-9a-f]{8,}"), "<GRANT>"),
    (re.compile(r"SHA256:[A-Za-z0-9+/]+"), "<FP>"),
]
PROGS = ("zeropw-admin", "admin_cli.py", "zeropw-agent", "agent_cli.py")


def mask(text: str, tmp: str) -> str:
    text = text.replace(tmp, "{tmp}")
    for prog in PROGS:
        text = text.replace(prog, "PROG")
    for pattern, replacement in MASKS:
        text = pattern.sub(replacement, text)
    return text


def run(cmd: list[str], env: dict[str, str], stdin: bytes = b"") -> tuple[int, str, str]:
    proc = subprocess.run(cmd, input=stdin, capture_output=True, env=env, cwd=ROOT, timeout=120)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def one(case: dict, impl: str, binaries: dict[str, str]) -> tuple[int, str, str]:
    tmp = tempfile.mkdtemp(prefix="zeropw-cli-parity-")
    try:
        env = {"PATH": os.environ.get("PATH", ""), "HOME": tmp, "LC_ALL": "C.UTF-8", "PYTHONPATH": str(ROOT),
               "COLUMNS": "80", "ZEROPW_ADMIN_PASSPHRASE": "admin-passphrase-1",
               "ZEROPW_RECOVERY_PASSPHRASE": "recovery-passphrase-1"}
        state = os.path.join(tmp, "state")
        subst = lambda items: [x.replace("{state}", state).replace("{tmp}", tmp) for x in items]  # noqa: E731
        python_admin = [sys.executable, "-m", "zeropw.admin_cli"]
        for step in case.get("setup", []):
            if step and step[0] == "!sh":
                subprocess.run(step[1].replace("{state}", state).replace("{tmp}", tmp), shell=True, env=env,
                               cwd=ROOT, check=True)
                continue
            stdin = b""
            if step and step[0].startswith("!stdin="):
                stdin, step = step[0][len("!stdin="):].encode(), step[1:]
            run(python_admin + subst(step), env, stdin)
        case_env = dict(env)
        case_env.update(case.get("env_extra", {}))
        module = "zeropw.admin_cli" if case["kind"] == "admin" else "zeropw.agent_cli"
        program = [sys.executable, "-m", module] if impl == "python" else [binaries[case["kind"]]]
        code, out, err = run(program + subst(case["argv"]), case_env, case.get("stdin", "").encode())
        for step in case.get("after", []):
            _, after_out, after_err = run(python_admin + subst(step), env)
            out += "\n#after: " + after_out + after_err
        return code, mask(out, tmp), mask(err, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--admin", required=True)
    parser.add_argument("--agent", required=True)
    parser.add_argument("cases")
    options = parser.parse_args()
    binaries = {"admin": options.admin, "agent": options.agent}
    cases = json.loads(Path(options.cases).read_text())
    failures = 0
    for case in cases:
        expected = one(case, "python", binaries)
        actual = one(case, "native", binaries)
        if expected != actual:
            failures += 1
            print(f"DIFF {case['kind']} {case['argv']}")
            for label, (code, out, err) in (("python", expected), ("native", actual)):
                print(f"--- {label} exit={code}\nstdout: {out}\nstderr: {err}")
    print(f"CLI_PARITY {len(cases) - failures}/{len(cases)} identical", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
