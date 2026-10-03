# Python-generated fixtures: `fake_upstream`

Generated once, on 2026-10-03, from the Python prototype at commit
`942a963` (CPython 3.12.14 linked against OpenSSL 3.0.13, Ubuntu 24.04
aarch64 in the isolated `zeropw-parity` VM), before the prototype was
deleted. Synthetic credentials and loopback endpoints only.

Files: `replies.json` (each well-formed request, the reply with `Date` values replaced by `<date>`, and what the fixture recorded).

Used by: `rust/tests/fake_upstream.rs`.

## Command

Run from the repository root of a checkout that still has `zeropw/`
(`vmrun.sh` streams the worktree into the VM and runs there with
`python3.12` first on `PATH`):

```sh
/Users/ys/Code/zeropw-parity-evidence-20261003/vmrun.sh <worktree> cvnet bash -c '
  set -e; out=$(mktemp -d)
  PYTHONPATH=$PWD PYTHONDONTWRITEBYTECODE=1 python3.12 - "$out" >&2 <<"PYGEN"
<the script below>
PYGEN
  cd "$out" && tar -cf - . | base64 -w0' \
  | base64 -d | tar -xf - -C rust/tests/fixtures/python/fake_upstream
```

## Script

```python
"""One-off generator for rust/tests/fixtures/python/fake_upstream: the Python
prototype's FakeUpstream answering well-formed requests. Each request is sent,
the write side half-closed, and the reply read to EOF; the Date header's value
is replaced by <date>. Writes replies.json into argv[1]."""
import base64
import json
import re
import socket
import sys
from pathlib import Path

from zeropw.fake_upstream import FakeUpstream

OUT = Path(sys.argv[1])
SECRET = "synthetic-token-fake-upstream-0123456789"
AUTH = f"Authorization: Bearer {SECRET}\r\n"


def get(target):
    return f"GET {target} HTTP/1.1\r\n{AUTH}\r\n"


REQUESTS = [
    get("/me"),
    get("/repos"),
    get("http://example.invalid/me?ignored=1"),
    get("https://example.invalid:8443/repos"),
    get("/stream"),
    get("/redirect"),
    get("/set-cookie"),
    f"HEAD /me HTTP/1.1\r\n{AUTH}\r\n",
    f"DELETE /repos/demo HTTP/1.1\r\n{AUTH}\r\n",
    "GET /me HTTP/1.1\r\n\r\n",
    f"POST /repos/demo/issues HTTP/1.1\r\n{AUTH}Content-Type: application/json\r\nContent-Length: 14\r\n\r\n"
    '{"title": "t"}',
    f"POST /repos/demo/issues HTTP/1.1\r\n{AUTH}Expect: 100-continue\r\nContent-Length: 14\r\n\r\n"
    '{"title": "t"}',
    f"POST /repos/demo/issues HTTP/1.0\r\n{AUTH}Expect: 100-continue\r\nContent-Length: 2\r\n\r\n{{}}",
    f"GET /echo-headers HTTP/1.1\r\n{AUTH}X-Test: value\r\nAccept: */*\r\n\r\n",
    f"GET /me HTTP/1.1\r\n{AUTH}Connection: keep-alive\r\n\r\nGET /me HTTP/1.1\r\n{AUTH}\r\n",
]
DATE = re.compile(rb"\r\nDate: [^\r\n]*\r\n")

fake = FakeUpstream(SECRET).start()
cases = []
for raw in REQUESTS:
    with socket.create_connection((fake.host, fake.port), timeout=10) as sock:
        sock.sendall(raw.encode("ascii"))
        sock.shutdown(socket.SHUT_WR)
        out = b""
        try:
            while chunk := sock.recv(65536):
                out += chunk
        except OSError:
            pass
    cases.append({"request": raw, "reply": DATE.sub(b"\r\nDate: <date>\r\n", out).decode("ascii")})
recorded = [[r["method"], r["path"], r["headers"], base64.b64encode(r["body"]).decode()] for r in fake.requests]
fake.stop()
(OUT / "replies.json").write_text(json.dumps({"secret": SECRET, "cases": cases, "recorded": recorded},
                                             indent=1, sort_keys=True) + "\n")
```
