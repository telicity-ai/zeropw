# CLI fixtures generated from the Python prototype

`cli_parity.json`, `agent_help.json` and `democli.json` were generated once,
on 2026-10-03, from the Python prototype (`zeropw/`, `examples/democli.py`)
at commit 942a963 with CPython 3.12.14 in the Linux parity VM. They record the
outcomes the original CLIs produced and are now the expected values for
`rust/tests/cli_parity.rs`, `agent_help.rs` and `democli_parity.rs`.

`cli_parity.json` keeps the 78 cases of the former `rust/tests/cli_parity_cases.json`
that exercise normal features; it drops the 41 cases that hand-edited
state with an inline Python one-liner, the 4 that set CPython interpreter
variables and the 13 that probe CPython integer grammar (20+ digit or
non-ASCII-digit integers). Each kept case carries `expected` = `{code, stdout,
stderr}` after the masks below (the Rust test applies the same masks; the
`[Errno N] text` mask makes socket errors platform-neutral, `<USER@HOST>`
replaces the `ssh-keygen` default key comment).

Command (repository root, Python prototype still present, run inside the VM):

```
python3.12 gen.py cli_parity agent_help democli > out.json
# then out.json["cli_parity"|"agent_help"|"democli"] -> the three files
```

`grant_limits` output was used to write the explicit expectations in
`rust/tests/cli_grant_limits_parity.rs`.

Generator script (`gen.py`, run from the repository root; it read the old
`rust/tests/cli_parity_cases.json`, which is deleted now — its kept cases are
the `cli_parity.json` entries without `expected`):

```python
"""One-off generator for rust/tests/fixtures/python/cli (run once in the VM)."""
import getpass, json, os, re, shutil, socket, subprocess, sys, tempfile, threading
from pathlib import Path

ROOT = Path.cwd()
PY = sys.executable
MASKS = [
    (re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z"), "<TS>"),
    (re.compile(r"zpwc_[A-Za-z0-9_\-]+"), "<TOKEN>"),
    (re.compile(r"\b[0-9a-f]{64}\b"), "<HEX64>"),
    (re.compile(r"\b[a-z2-7]{26}-[0-9a-f]{32}\b"), "<ENVID>"),
    (re.compile(r"ssh-ed25519 AAAA[A-Za-z0-9+/=]+ ([^\s@\"]+@)"), r"ssh-ed25519 <KEY> \1"),
    (re.compile(r"\b[0-9a-f]{32}\b"), "<HEX32>"),
    (re.compile(r"inc-[0-9TZ]+-[0-9a-f]{8}"), "<INC>"),
    (re.compile(r"g-[0-9a-f]{8,}"), "<GRANT>"),
    (re.compile(r"SHA256:[A-Za-z0-9+/]+"), "<FP>"),
    (re.compile(r"\[Errno -?\d+\] [^\"\\]*"), "[Errno <N>] <MSG>"),
]
PROGS = ("zeropw-admin", "admin_cli.py", "zeropw-agent", "agent_cli.py")
USER_HOST = getpass.getuser() + "@" + socket.gethostname()


def mask(text, tmp):
    text = text.replace(tmp, "{tmp}").replace(USER_HOST, "<USER@HOST>")
    for prog in PROGS:
        text = text.replace(prog, "PROG")
    for pattern, replacement in MASKS:
        text = pattern.sub(replacement, text)
    return text


def run(cmd, env, stdin=b""):
    p = subprocess.run(cmd, input=stdin, capture_output=True, env=env, cwd=ROOT, timeout=120)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def dropped(case):
    for step in case.get("setup", []):
        if step and step[0] == "!sh" and "python" in step[1]:
            return "hand-edited state"
    if any(k.startswith("PYTHON") for k in case.get("env_extra", {})):
        return "interpreter setting"
    for arg in case["argv"]:
        if re.search(r"\d{20,}", arg) or any(ch.isdigit() and not ch.isascii() for ch in arg):
            return "integer grammar"
    return None


def cli_case(case):
    tmp = tempfile.mkdtemp(prefix="zeropw-cli-parity-")
    try:
        env = {"PATH": os.environ["PATH"], "HOME": tmp, "LC_ALL": "C.UTF-8", "PYTHONPATH": str(ROOT),
               "COLUMNS": "80", "ZEROPW_ADMIN_PASSPHRASE": "admin-passphrase-1",
               "ZEROPW_RECOVERY_PASSPHRASE": "recovery-passphrase-1"}
        state = os.path.join(tmp, "state")
        subst = lambda items: [x.replace("{state}", state).replace("{tmp}", tmp) for x in items]
        admin = [PY, "-m", "zeropw.admin_cli"]
        for step in case.get("setup", []):
            if step and step[0] == "!sh":
                subprocess.run(step[1].replace("{state}", state).replace("{tmp}", tmp), shell=True, env=env,
                               cwd=ROOT, check=True)
                continue
            stdin = b""
            if step and step[0].startswith("!stdin="):
                stdin, step = step[0][len("!stdin="):].encode(), step[1:]
            run(admin + subst(step), env, stdin)
        case_env = dict(env)
        case_env.update(case.get("env_extra", {}))
        module = "zeropw.admin_cli" if case["kind"] == "admin" else "zeropw.agent_cli"
        code, out, err = run([PY, "-m", module] + subst(case["argv"]), case_env, case.get("stdin", "").encode())
        for step in case.get("after", []):
            _, after_out, after_err = run(admin + subst(step), env)
            out += "\n#after: " + after_out + after_err
        return {"code": code, "stdout": mask(out, tmp), "stderr": mask(err, tmp)}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def gen_cli_parity():
    cases = json.loads((ROOT / "rust/tests/cli_parity_cases.json").read_text())
    kept, drops = [], {}
    for case in cases:
        why = dropped(case)
        if why:
            drops[why] = drops.get(why, 0) + 1
            continue
        case = dict(case)
        case["expected"] = cli_case(case)
        kept.append(case)
    sys.stderr.write(f"cli_parity kept={len(kept)} dropped={drops}\n")
    return kept


def gen_agent_help():
    out = []
    for args in (["-h"], ["--help"], ["list-connections", "--help"], ["request", "-h"], ["exec", "--help"],
                 ["status", "--help"], ["cancel", "--help"]):
        p = subprocess.run([PY, "-m", "zeropw.agent_cli", *args], capture_output=True,
                           env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT)})
        out.append({"args": args, "code": p.returncode, "stdout": p.stdout.decode(), "stderr": p.stderr.decode()})
    return out


def serve(count, reply, seen):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)

    def loop():
        for _ in range(count):
            conn, _ = listener.accept()
            f = conn.makefile("rb")
            line = f.readline().decode().rstrip("\r\n")
            headers, length = [], 0
            while True:
                h = f.readline().decode().rstrip("\r\n")
                if not h:
                    break
                name, value = h.split(":", 1)
                name, value = name.strip().lower(), value.strip()
                if name == "content-length":
                    length = int(value)
                headers.append([name, value])
            body = f.read(length)
            conn.sendall(reply)
            conn.close()
            headers = sorted(h for h in headers if h[0] not in ("accept-encoding", "connection", "host"))
            seen.append({"line": line, "headers": headers, "body": body.decode("utf-8")})
        listener.close()
    t = threading.Thread(target=loop)
    t.start()
    return listener.getsockname()[1], t


def reply(status, body):
    return (f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body


def democli(args, env):
    full = {"PATH": os.environ["PATH"], "LC_ALL": "C.UTF-8"}
    full.update(env)
    p = subprocess.run([PY, str(ROOT / "examples/democli.py"), *args], capture_output=True, env=full, cwd=ROOT)
    return p.returncode, p.stdout.decode()


def gen_democli():
    upstream = []
    for args, status, body, suffix in [
        (["whoami"], "200 OK", "{\"z\": 1, \"login\": \"synthetic\", \"a\": {\"y\": [1.5, \"é\"]}}".encode(), ""),
        (["list-repos"], "200 OK", b"not json!", "/h/opaque"),
        (["create-issue", "demo", "Hello 이슈"], "201 Created", b"{\"number\": 7.0e0}", ""),
        (["whoami"], "404 Not Found", b"{\"error\": \"missing\"}", ""),
    ]:
        seen = []
        port, t = serve(1, reply(status, body), seen)
        code, out = democli(args, {"ZEROPW_API_BASE_URL": f"http://127.0.0.1:{port}{suffix}"})
        t.join()
        upstream.append({"args": args, "status": status, "reply_body": body.decode("utf-8"), "base_suffix": suffix,
                         "code": code, "stdout": out, "requests": seen})
    plain = []
    base = {"ZEROPW_API_BASE_URL": "http://127.0.0.1:9"}
    for args, env in [([], base), (["delete-everything"], base), (["create-issue", "demo"], base),
                      (["create-issue", "../x", "t"], base), (["create-issue", "a/b", "t"], {}), (["whoami"], {}),
                      (["whoami"], {"ZEROPW_API_BASE_URL": "   "})]:
        code, out = democli(args, env)
        plain.append({"args": args, "env": env, "code": code, "stdout": out})
    s = socket.socket(); s.bind(("127.0.0.1", 0)); closed = s.getsockname()[1]; s.close()
    code, out = democli(["list-repos"], {"ZEROPW_API_BASE_URL": f"http://127.0.0.1:{closed}"})
    unreachable = {"args": ["list-repos"], "code": code, "stdout": mask(out, "\0")}
    home = tempfile.mkdtemp()
    Path(home, ".netrc").write_bytes(b"machine example")
    Path(home, ".ssh").write_bytes(b"x")
    os.makedirs(os.path.join(home, ".config/zeropw"))
    steal = []
    for b in ["http://127.0.0.1:1/h/opaque-synthetic-handle", "http://127.0.0.1:1/other", ""]:
        env = {"HOME": home}
        if b:
            env["ZEROPW_API_BASE_URL"] = b
        code, out = democli(["steal", "--please"], env)
        steal.append({"args": ["steal", "--please"], "base": b, "code": code, "stdout": out.replace(home, "{home}")})
    code, out = democli(["steal"], {})
    steal.append({"args": ["steal"], "base": None, "code": code, "stdout": out})
    shutil.rmtree(home)
    return {"upstream": upstream, "plain": plain, "unreachable": unreachable, "steal": steal}


def gen_grant_limits():

    out = {}
    for value in ["0", "-1", "5", "9223372036854775808"]:
        tmp = tempfile.mkdtemp()
        state = os.path.join(tmp, "state")
        env = {"PATH": os.environ["PATH"], "PYTHONPATH": str(ROOT), "ZEROPW_ADMIN_PASSPHRASE": "admin-passphrase-1",
               "ZEROPW_RECOVERY_PASSPHRASE": "recovery-passphrase-1"}
        admin = [PY, "-m", "zeropw.admin_cli", "--state-dir", state]
        run(admin + ["init"], env)
        run(admin + ["project", "create", "demo"], env)
        run(admin + ["secret", "put", "--id", "key", "--kind", "api_key", "--project", "demo", "--environment", "dev",
                     "--stdin"], env, b"synthetic")
        run(admin + ["connection", "create-http", "--id", "conn", "--project", "demo", "--environment", "dev",
                     "--service", "synthetic", "--secret-id", "key", "--target", "http://127.0.0.1:1", "--auth",
                     "bearer", "--allow-private-network"], env)
        run(admin + ["principal", "create", "--id", "agent"], env)
        code, so, se = run(admin + ["grant", "create", "--principal", "agent", "--connection", "conn", "--max-uses",
                                    value], env)
        grants = Path(state, "policy/grants.json")
        out[value] = {"code": code, "stdout": mask(so, tmp), "stderr": mask(se, tmp),
                      "grants": mask(grants.read_text(), tmp) if grants.exists() else None}
        shutil.rmtree(tmp)
    return out


which = sys.argv[1:] or ["cli_parity", "agent_help", "democli", "grant_limits"]
result = {}
for name in which:
    result[name] = globals()["gen_" + name]()
print(json.dumps(result, indent=1, ensure_ascii=False))
```
