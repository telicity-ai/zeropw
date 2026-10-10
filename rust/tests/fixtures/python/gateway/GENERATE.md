# Python-generated fixtures: `gateway`

Generated once, on 2026-10-03, from the Python prototype at commit
`942a963` (CPython 3.12.14 linked against OpenSSL 3.0.13, Ubuntu 24.04
aarch64 in the isolated `zeropw-parity` VM), before the prototype was
deleted. Synthetic credentials and loopback endpoints only.

Files: `credential_patterns.json` (patterns `gateway.credential_patterns` derived), `request_bytes.json` (the exact upstream request `gateway.relay_for_caller` wrote, port normalized to `PORT`), `client_hello.json` (the raw TLS ClientHello `ssl` sent for a DNS name and an IP literal, with the OpenSSL version).

Used by: `rust/tests/gateway_oracle.rs`, `rust/tests/gateway_tls_parity.rs`.

## Command

Run from the repository root of a checkout that still has `zeropw/`
(`vmrun.sh` streams the worktree into the VM and runs there with
`python3.12` first on `PATH`):

```sh
${HOME}/Code/zeropw-parity-evidence-20261003/vmrun.sh <worktree> cvnet bash -c '
  set -e; out=$(mktemp -d)
  PYTHONPATH=$PWD PYTHONDONTWRITEBYTECODE=1 python3.12 - "$out" >&2 <<"PYGEN"
<the script below>
PYGEN
  cd "$out" && tar -cf - . | base64 -w0' \
  | base64 -d | tar -xf - -C rust/tests/fixtures/python/gateway
```

## Script

```python
"""One-off generator for rust/tests/fixtures/python/gateway (run once with the
Python prototype on PYTHONPATH; writes into the directory given as argv[1])."""
import base64
import json
import socket
import sys
import tempfile
import threading
from pathlib import Path

from zeropw import gateway
from zeropw import policy as P
from zeropw.context import Config, Context

OUT = Path(sys.argv[1])
ADMIN = "admin-passphrase-1"
RECOVERY = "recovery-passphrase-1"
SECRET = "synthetic-token-oracle-cross-lang-0123456789"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# ------------------------------------------------------ credential_patterns
TABLE = [
    (b"synthetic-token-alpha-0123456789ABCDEFGHIJ", None),
    (b"synthetic-token-alpha-0123456789ABCDEFGHIJ", "synthetic-user"),
    (b"AKIA/secret+Key 9=abc", None),
    (b"synthetic pass word/+=", "synthetic-user"),
    (b"synthetic-token/enc+ode=chars:>>>?<&\"\\x-0123456789", "synthetic-user"),
    (b"Synthetic/TOKEN", None),
    (b"synthetic\x00\xff\xfe-binary-credential", "synthetic-user"),
]
patterns = [
    {
        "secret_b64": b64(secret),
        "username": username,
        "patterns_b64": [b64(p) for p in gateway.credential_patterns(secret, username)],
    }
    for secret, username in TABLE
]
(OUT / "credential_patterns.json").write_text(json.dumps(patterns, indent=1) + "\n")


# ------------------------------------------------------ upstream request bytes
def capture_one(listener: socket.socket) -> bytes:
    """Read one request head plus its Content-Length body, answer 200."""
    conn, _ = listener.accept()
    conn.settimeout(5)
    received = b""
    while True:
        end = received.find(b"\r\n\r\n")
        if end >= 0:
            head = received[:end].decode("latin-1").lower()
            length = 0
            for line in head.split("\r\n"):
                if line.startswith("content-length:"):
                    length = int(line[len("content-length:"):].strip())
            if len(received) >= end + 4 + length:
                break
        try:
            chunk = conn.recv(65536)
        except OSError:
            break
        if not chunk:
            break
        received += chunk
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    conn.close()
    return received


def request_bytes(method, target, headers, body, auth):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    captured = {}
    thread = threading.Thread(target=lambda: captured.setdefault("raw", capture_one(listener)))
    thread.start()
    with tempfile.TemporaryDirectory() as tmp:
        ctx = Context.initialize(Path(tmp) / "state", ADMIN, RECOVERY, Config(), lambda: 1700000000.0)
        ctx.projects.create("demo")
        ctx.vault.put_secret("gh-token", "api_key", SECRET.encode(), "demo", "dev")
        ctx.policy.create_principal("agent-1")
        mode, header_name, value_prefix, basic_username = auth
        ctx.policy.create_connection(P.Connection(
            id="gh", project="demo", environment="dev", service="svc", kind="http", secret_id="gh-token",
            secret_version=None, description="", http_target=P.HttpTarget("http", "127.0.0.1", port, None),
            http_auth=P.HttpAuth(mode, header_name=header_name, value_prefix=value_prefix,
                                 basic_username=basic_username),
            http_scope=P.HttpScope(), ssh_target=None, cli=None,
            policy_version=0, status="active", created_at="", updated_at=""))
        ctx.policy.create_grant("agent-1", "gh", 3600, None)
        gateway.relay_for_caller(ctx, "agent-1", "gh", method, target, dict(headers), body)
        ctx.close()
    thread.join()
    listener.close()
    return captured["raw"].decode("ascii").replace(f"127.0.0.1:{port}", "127.0.0.1:PORT")


BEARER = ("bearer", None, None, None)
SHAPES = [
    ("relay_for_caller post", "POST", "/repos/demo/issues",
     [("Accept", "application/json"), ("User-Agent", "oracle-test/1")], b'{"title":"from oracle"}', BEARER),
    ("get no body, caller order kept, case folded", "GET", "/repos?per_page=5&q=a%20b",
     [("User-Agent", "ua/1"), ("ACCEPT", "application/json"), ("Range", "bytes=0-1"),
      ("If-None-Match", "\"etag\"")], b"", BEARER),
    ("dropped and hop-by-hop headers", "GET", "/me",
     [("Authorization", "Bearer agent-placeholder"), ("Cookie", "a=b"), ("Connection", "keep-alive"),
      ("Host", "evil.invalid"), ("X-ZeroPW-Request-Id", "r-1"), ("x-request-id", "rid"),
      ("Content-Length", "99"), ("Accept-Encoding", "gzip")], b"", BEARER),
    ("same name in two spellings: first position, last value", "GET", "/me",
     [("accept", "text/plain"), ("User-Agent", "ua"), (" Accept ", "application/json")], b"", BEARER),
    ("post with body", "POST", "/repos/demo/issues", [("Content-Type", "application/json")],
     b'{"title":"t"}', BEARER),
    ("put with empty body sends Content-Length 0", "PUT", "/repos/demo", [], b"", BEARER),
    ("delete with body", "DELETE", "/repos/demo", [], b"x", BEARER),
    ("lower-case method normalised", " patch ", "/repos/demo", [], b"{}", BEARER),
    ("basic auth", "GET", "/me", [("Accept", "*/*")], b"", ("basic", None, None, "synthetic-user")),
    ("header auth with prefix", "GET", "/me", [("Accept", "*/*")], b"",
     ("header", "X-Api-Key", "Token ", None)),
    ("header auth named like a forwarded header (same spelling)", "GET", "/me",
     [("Accept", "*/*"), ("User-Agent", "ua")], b"", ("header", "accept", None, None)),
    ("header auth named like a relay header (Via)", "GET", "/me", [("User-Agent", "ua")], b"",
     ("header", "Via", None, None)),
    ("header auth differing only in case from a forwarded header", "GET", "/me",
     [("x-request-id", "rid")], b"", ("header", "X-Request-Id", None, None)),
]
shapes = []
for name, method, target, headers, body, auth in SHAPES:
    shapes.append({
        "name": name,
        "method": method,
        "target": target,
        "headers": [list(h) for h in headers],
        "body_b64": b64(body),
        "auth": list(auth),
        "request": request_bytes(method, target, headers, body, auth),
    })
(OUT / "request_bytes.json").write_text(json.dumps({"secret": SECRET, "cases": shapes}, indent=1) + "\n")


# ------------------------------------------------------ TLS ClientHello
def capture_hello(listener: socket.socket) -> bytes:
    conn, _ = listener.accept()
    conn.settimeout(5)
    message = b""

    def read_exact(n):
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                raise EOFError
            data += chunk
        return data

    try:
        while True:
            header = read_exact(5)
            if header[0] != 0x16:
                break
            message += read_exact(int.from_bytes(header[3:5], "big"))
            if len(message) >= 4:
                body = int.from_bytes(message[1:4], "big")
                if len(message) >= 4 + body:
                    message = message[:4 + body]
                    break
    except (EOFError, OSError):
        pass
    conn.close()
    return message


import ssl  # noqa: E402

hellos = {}
for host in ("upstream.example.test", "127.0.0.1"):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    captured = {}
    thread = threading.Thread(target=lambda: captured.setdefault("hello", capture_hello(listener)))
    thread.start()
    with tempfile.TemporaryDirectory() as tmp:
        ctx = Context.initialize(Path(tmp) / "state", "synthetic-admin-passphrase",
                                 "synthetic-recovery-passphrase", Config(upstream_timeout=1.0))
        ctx.projects.create("demo")
        ctx.vault.put_secret("key", "api_key", b"synthetic-tls-parity-token-0123456789", "demo", "dev")
        ctx.policy.create_principal("alice")
        target = P.HttpTarget("https", host, port, "", True)
        ctx.policy.create_connection(P.Connection(
            id="host-case", project="demo", environment="dev", service="api", kind="http",
            secret_id="key", secret_version=None, description="", http_target=target,
            http_auth=P.HttpAuth("bearer"), http_scope=P.HttpScope(), ssh_target=None, cli=None,
            policy_version=0, status="active", created_at="", updated_at=""))
        ctx.policy.create_grant("alice", "host-case", 3600, None)
        old = gateway._getaddrinfo
        gateway._getaddrinfo = lambda *args, **kwargs: [(2, 1, 6, "", ("127.0.0.1", port))]
        try:
            gateway.relay_for_caller(ctx, "alice", "host-case", "GET", "/me", {}, b"")
        finally:
            gateway._getaddrinfo = old
        ctx.close()
    thread.join()
    listener.close()
    hellos[host] = captured["hello"].hex()
(OUT / "client_hello.json").write_text(json.dumps({
    "openssl_version": ssl.OPENSSL_VERSION,
    "openssl_version_number": ssl.OPENSSL_VERSION_NUMBER,
    "hellos": hellos,
}, indent=1) + "\n")
```

## Expected values embedded in test sources

These expected values were measured in the same run with the script below
(output printed, then copied into the tests by hand) rather than kept as
fixture files: the strict base64 table in `rust/tests/tools_server.rs`
(`strict_base64_decodes_only_canonical_input`), the proxy-bypass table in
`rust/src/mac_proxies.rs` (`bypass_patterns_match_urllib`), the `pathlib`
table in `rust/src/signer.rs` (`normalize_pathlib_string_matches_pathlib_str`),
the `normalize_path` table in `rust/tests/gateway.rs`
(`normalize_path_representative_outcomes`), and the fixed server replies in
`rust/tests/escaped_builtin_http_parity.rs`.

```python
import base64, json, socket, sys, tempfile, urllib.request
from pathlib import Path
from zeropw import gateway as G
from zeropw.context import Context
from zeropw.server import ZeroPWServer

OUT = Path(sys.argv[1])
res = {}

cases = ["", "AA==", "AB==", "AAA=", "AAB=", "AAAA", "AAAA=", "AAAA====", "=", "=AAA", "A=AA",
         "AA=", "AA===", "AAA==", "AA==AA==", "AA A", "é"]
out = []
for s in cases:
    try:
        out.append(list(base64.b64decode(s, validate=True)))
    except (ValueError, TypeError):
        out.append(None)
res["b64"] = list(zip(cases, out))

settings = {"exclude_simple": True, "exceptions": ["*.local", "EXACT.example", "10.1", "172.16/12",
            "١٩٨.٥١.١٠٠/٢٤", "192.0.2.0/33", "host?.example", "node[0-3].example", "node[!0-3].example",
            "literal[.example"]}
hosts = ["printer", "a.local", "A.LOCAL", "EXACT.example", "exact.example", "10.1.2.3", "172.31.255.1:443",
         "198.51.100.42", "192.0.2.1", "host1.example", "node2.example", "node8.example", "literal[.example",
         "other.example"]
res["bypass"] = [[h, urllib.request._proxy_bypass_macosx_sysconf(h, settings)] for h in hosts]

pcases = ["/tmp/zpw//aaa", "/tmp/zpw/./aaa", "/tmp/zpw/aaa/", "/tmp/zpw/b/../aaa", "/tmp/zpw//", "/tmp/zpw///.",
          "//tmp/zpw", "///tmp/zpw", "////tmp/zpw", "/", "//", "///", "a//b", "a/./b", "./a/b", "../a/b", ""]
res["pathlib"] = [[c, str(Path(c))] for c in pcases]

ncases = ["/repos/demo/issues", "/repos?per_page=5&q=a%20b", "/a%2Fb/c", "/a/../b", "/a/./b", "/%2e%2e/x",
          "/%25%E4%B8%AD", "/%E4%B8%AD/x", "//x", "/a%00b", "/%zz", "/a?b\n", "/a\nb", "/a?b\n\n", "relative",
          "/a b", "/%41%42?x=%41", "/a#frag"]
nout = []
for raw in ncases:
    try:
        path, target = G.normalize_path(raw)
        nout.append([raw, "ok", path, target])
    except G._Invalid as e:
        nout.append([raw, "err", e.reason])
res["normalize_path"] = nout

# escaped built-ins at the server
def fetch(host, port, raw):
    s = socket.create_connection((host, port))
    s.sendall(raw)
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    return data

def norm(b):
    return "\r\n".join(l for l in b.decode("utf-8", "replace").split("\r\n") if not l.startswith("Date: "))

tokens = [b"zpw1.ab\xe9.sig", b"zpw1.abc.si\xe9", b"zpw1.abc.sig"]
reqs = []
for t in tokens:
    reqs.append(b"GET /relay/x HTTP/1.1\r\nHost: a\r\nX-ZeroPW-Handle: " + t + b"\r\nConnection: close\r\n\r\n")
    reqs.append(b"GET /h/" + t + b"/x HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
tmp = tempfile.mkdtemp()
ctx = Context.initialize(Path(tmp) / "state", "admin-passphrase-123456", "recovery-passphrase-123456")
srv = ZeroPWServer(ctx).serve_in_thread()
host, port = srv.server_address[:2]
before = len(ctx.audit.tail(10000))
res["escaped_responses"] = [norm(fetch(host, port, r)) for r in reqs]
res["escaped_events"] = [[r["event"], r.get("reason")] for r in ctx.audit.tail(10000)[before:]]
token = ctx.policy.create_principal("alice", "cli")
lock = Path(tmp) / "state" / ".lock"
if lock.exists():
    lock.unlink()
lock.mkdir()
res["os_error"] = norm(fetch(host, port, ("POST /v1/tools/list_connections HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer %s\r\n"
                                           "Content-Length: 2\r\nConnection: close\r\n\r\n{}" % token).encode()))
srv.shutdown(); srv.server_close()
(OUT / "values.json").write_text(json.dumps(res, indent=1, ensure_ascii=False))
```
