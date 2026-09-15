"""Controlled fake upstream API for tests and the demo.

This server stands in for an external HTTP service (a "fake GitHub").  It is
a *test fixture*, not part of the trusted control plane: it deliberately
offers every leak path the gateway must block (header reflection, credential
in a redirect ``Location``, a debug endpoint that prints the token, base64,
percent-encoded (upper- or lower-case hex) and cookie leaks, every named
encoding the reflection guard scans (``/encoded-leak?form=...``), the
credential embedded at any byte offset inside a larger, optionally
line-wrapped base64 "file content" blob (``/base64-embedded-leak``), oversized
and chunked bodies) so that tests can prove the relay blocks them.  It only
ever holds a synthetic credential.

Every request is recorded (method, path, lower-cased headers, body) so tests
can assert what actually reached the upstream: the injected credential and
never the agent's placeholder.

Security scope: none.  Binds 127.0.0.1 on an ephemeral port only, never logs,
and must not be used against real credentials.
"""

from __future__ import annotations

import base64
import html
import json
import re
import ssl
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

__all__ = ["FakeUpstream", "ENCODED_LEAK_FORMS", "BASIC_LEAK_FORMS", "encoded_credential", "embedded_base64_blob"]

LARGE_BODY_SIZE = 2 * 1024 * 1024
HUGE_BODY_SIZE = 9 * 1024 * 1024
STREAM_PARTS = (b"part-1\n", b"part-2\n", b"part-3\n")

# Every encoding in which ``GET /encoded-leak?form=<name>`` reflects the
# credential inside its body: one per form the gateway's reflection guard scans.
ENCODED_LEAK_FORMS = (
    "raw",
    "base64", "base64-unpadded", "base64url", "base64url-unpadded",
    "percent-upper", "percent-lower", "percent-plus-upper", "percent-plus-lower",
    "hex-lower", "hex-upper",
    "json", "json-unicode", "html",
)
# Forms that exist only in ``basic`` mode: base64(basic_username:credential).
BASIC_LEAK_FORMS = ("basic", "basic-unpadded", "basic-url")


def _lower_percent_triplets(encoded: str) -> str:
    """Re-emit ``%XX`` triplets in lower case (RFC 3986 §2.1 allows either case)."""
    return re.sub(r"%[0-9A-F]{2}", lambda match: match.group(0).lower(), encoded)


def encoded_credential(fake: "FakeUpstream", form: str) -> str | None:
    """The fake's credential in one named encoding, or ``None`` for an unknown form."""
    text = fake.credential
    raw = text.encode("utf-8")
    percent = urllib.parse.quote(text, safe="")
    percent_plus = urllib.parse.quote_plus(text, safe="")
    forms = {
        "raw": text,
        "base64": base64.b64encode(raw).decode("ascii"),
        "base64-unpadded": base64.b64encode(raw).decode("ascii").rstrip("="),
        "base64url": base64.urlsafe_b64encode(raw).decode("ascii"),
        "base64url-unpadded": base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        "percent-upper": percent,
        "percent-lower": _lower_percent_triplets(percent),
        "percent-plus-upper": percent_plus,
        "percent-plus-lower": _lower_percent_triplets(percent_plus),
        "hex-lower": raw.hex(),
        "hex-upper": raw.hex().upper(),
        "json": json.dumps(text),
        "json-unicode": json.dumps(text, ensure_ascii=False),
        "html": html.escape(text, quote=True),
    }
    if fake.mode == "basic":
        pair = f"{fake.basic_username}:{text}".encode("utf-8")
        forms["basic"] = base64.b64encode(pair).decode("ascii")
        forms["basic-unpadded"] = forms["basic"].rstrip("=")
        forms["basic-url"] = base64.urlsafe_b64encode(pair).decode("ascii")
    return forms.get(form)


def embedded_base64_blob(credential: str, offset: int, wrap: int = 0, urlsafe: bool = False) -> str:
    """Base64 of a small config file holding the credential, as a "file contents" API returns it.

    The credential starts at byte ``offset`` modulo 3 of the encoded stream
    (``offset`` filler bytes, then a 6-byte ``token=`` key), so offsets 0, 1
    and 2 cover every base64 alignment.  ``wrap`` > 0 inserts a newline every
    ``wrap`` characters (as GitHub's contents API does) so the encoded
    credential spans lines.
    """
    raw = b"#" * offset + b"token=" + credential.encode("utf-8") + b"\nnote=synthetic\n"
    encoded = (base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)).decode("ascii")
    if wrap > 0:
        encoded = "\n".join(encoded[i:i + wrap] for i in range(0, len(encoded), wrap)) + "\n"
    return encoded


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "fake-upstream"
    sys_version = ""

    # BaseHTTPRequestHandler logs to stderr by default; keep tests quiet.
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def log_error(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    @property
    def fake(self) -> "FakeUpstream":
        return self.server.fake  # type: ignore[attr-defined]

    # ------------------------------------------------------------ helpers
    def _read_body(self) -> bytes:
        length = self.headers.get("Content-Length")
        if not length:
            return b""
        try:
            size = int(length)
        except ValueError:
            return b""
        return self.rfile.read(size) if size > 0 else b""

    def _record(self, body: bytes) -> None:
        self.fake.requests.append({
            "method": self.command,
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body,
        })

    def _authorized(self) -> bool:
        fake = self.fake
        if fake.mode == "bearer":
            return self.headers.get("Authorization") == f"Bearer {fake.credential}"
        if fake.mode == "basic":
            pair = f"{fake.basic_username}:{fake.credential}".encode("utf-8")
            return self.headers.get("Authorization") == "Basic " + base64.b64encode(pair).decode("ascii")
        if fake.mode == "header":
            return self.headers.get(fake.header_name) == f"{fake.value_prefix}{fake.credential}"
        return False

    def _send(self, status: int, body: bytes = b"", content_type: str = "application/json",
              extra_headers: list[tuple[str, str]] | None = None) -> None:
        self.send_response(status)
        if body or status not in (204, 304):
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in extra_headers or []:
            self.send_header(name, value)
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)
        self.close_connection = True

    def _send_json(self, status: int, payload: Any, extra_headers: list[tuple[str, str]] | None = None) -> None:
        self._send(status, json.dumps(payload, sort_keys=True).encode("utf-8"), extra_headers=extra_headers)

    def _send_chunked(self, parts: tuple[bytes, ...]) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            for part in parts:
                self.wfile.write(f"{len(part):x}\r\n".encode("ascii") + part + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
        self.close_connection = True

    def _send_streamed(self, total: int) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(total))
        self.send_header("Connection", "close")
        self.end_headers()
        chunk = b"y" * (64 * 1024)
        sent = 0 if self.command != "HEAD" else total
        while sent < total:
            piece = chunk[: min(len(chunk), total - sent)]
            self.wfile.write(piece)
            sent += len(piece)
        self.close_connection = True

    # ------------------------------------------------------------ routing
    def _dispatch(self) -> None:
        body = self._read_body()
        self._record(body)
        fake = self.fake
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        if not self._authorized():
            scheme = "Basic" if fake.mode == "basic" else "Bearer"
            self._send_json(401, {"error": "unauthorized"},
                            extra_headers=[("WWW-Authenticate", f'{scheme} realm="fake-upstream"')])
            return
        method = self.command
        if method in ("GET", "HEAD") and path == "/repos":
            self._send_json(200, [{"name": "demo"}, {"name": "tools"}])
        elif method in ("GET", "HEAD") and path == "/me":
            self._send_json(200, {"login": "synthetic-user"})
        elif method == "POST" and path.startswith("/repos/") and path.endswith("/issues"):
            name = path[len("/repos/"):-len("/issues")]
            try:
                payload = json.loads(body.decode("utf-8")) if body else {}
            except (ValueError, UnicodeDecodeError):
                self._send_json(400, {"error": "invalid_json"})
                return
            if not isinstance(payload, dict) or not isinstance(payload.get("title"), str):
                self._send_json(400, {"error": "title_required"})
                return
            with fake._lock:
                fake.issue_counter += 1
                number = fake.issue_counter
            self._send_json(201, {"number": number, "title": payload["title"], "repo": name})
        elif method == "DELETE" and path.startswith("/repos/") and path.count("/") == 2:
            self._send(204)
        elif method in ("GET", "HEAD") and path == "/echo-headers":
            self._send_json(200, {"headers": {k: v for k, v in self.headers.items()}})
        elif method in ("GET", "HEAD") and path == "/redirect":
            location = "/leak?auth=" + urllib.parse.quote(fake.credential, safe="")
            html = f'<a href="{location}">moved</a>'.encode("utf-8")
            self._send(302, html, content_type="text/html", extra_headers=[("Location", location)])
        elif method in ("GET", "HEAD") and path == "/redirect-external":
            self._send(302, b"", extra_headers=[("Location", "http://evil.invalid/")])
        elif method in ("GET", "HEAD") and path == "/leak":
            self._send_json(200, {"leaked": query.get("auth", [""])[0]})
        elif method in ("GET", "HEAD") and path == "/debug/token":
            self._send_json(200, {"token": fake.credential})
        elif method in ("GET", "HEAD") and path == "/base64-leak":
            self._send_json(200, {"blob": base64.b64encode(fake.credential.encode("utf-8")).decode("ascii")})
        elif method in ("GET", "HEAD") and path == "/base64-embedded-leak":
            # ``?offset=<0-8>&wrap=<chars>&alphabet=url`` embeds the credential inside
            # a larger base64 blob at a chosen byte offset (all three alignments).
            try:
                offset = min(max(int(query.get("offset", ["0"])[0]), 0), 8)
                wrap = min(max(int(query.get("wrap", ["0"])[0]), 0), 1024)
            except ValueError:
                self._send_json(400, {"error": "invalid_query"})
                return
            urlsafe = query.get("alphabet", ["std"])[0] == "url"
            self._send_json(200, {"encoding": "base64",
                                  "content": embedded_base64_blob(fake.credential, offset, wrap, urlsafe)})
        elif method in ("GET", "HEAD") and path == "/urlencoded-leak":
            # ``?case=lower`` reflects the RFC 3986-valid lower-case hex form
            # (``%2f``) that many frameworks emit instead of ``quote()``'s ``%2F``.
            encoded = urllib.parse.quote(fake.credential, safe="")
            if query.get("case", ["upper"])[0] == "lower":
                encoded = _lower_percent_triplets(encoded)
            self._send_json(200, {"blob": encoded})
        elif method in ("GET", "HEAD") and path == "/encoded-leak":
            # ``?form=<name>`` embeds the credential in one named encoding
            # (ENCODED_LEAK_FORMS, plus BASIC_LEAK_FORMS in basic mode) inside
            # a plain-text body so tests can prove each form is caught.
            encoded = encoded_credential(fake, query.get("form", [""])[0])
            if encoded is None:
                self._send_json(400, {"error": "unknown_form"})
            else:
                self._send(200, f"leak=[{encoded}]\n".encode("utf-8"), content_type="text/plain")
        elif method in ("GET", "HEAD") and path == "/set-cookie":
            self._send_json(200, {"ok": True},
                            extra_headers=[("Set-Cookie", f"session={fake.credential}; Path=/; HttpOnly")])
        elif method in ("GET", "HEAD") and path == "/stream":
            self._send_chunked(STREAM_PARTS)
        elif method in ("GET", "HEAD") and path == "/large":
            self._send(200, b"x" * LARGE_BODY_SIZE, content_type="application/octet-stream")
        elif method in ("GET", "HEAD") and path == "/huge":
            self._send_streamed(HUGE_BODY_SIZE)
        elif method in ("GET", "HEAD") and path == "/slow":
            try:
                seconds = min(float(query.get("seconds", ["1"])[0]), 30.0)
            except ValueError:
                seconds = 1.0
            time.sleep(max(seconds, 0.0))
            self._send_json(200, {"slept": seconds})
        else:
            self._send_json(404, {"error": "not_found"})

    def handle_one_request(self) -> None:
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError):
            # The gateway closes early on oversized bodies; that is expected.
            self.close_connection = True

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_GET


class FakeUpstream:
    """Fake upstream API bound to 127.0.0.1:<ephemeral>.

    ``mode`` selects how the synthetic credential must arrive: ``bearer``
    (``Authorization: Bearer <credential>``), ``basic`` (``Authorization:
    Basic base64(basic_username:credential)``) or ``header``
    (``<header_name>: <value_prefix><credential>``).  Pass ``ssl_context`` to
    serve HTTPS with a test certificate.
    """

    def __init__(self, credential: str, mode: str = "bearer", basic_username: str | None = None,
                 ssl_context: ssl.SSLContext | None = None, header_name: str = "X-Api-Key",
                 value_prefix: str = "") -> None:
        if mode not in ("bearer", "basic", "header"):
            raise ValueError("unsupported fake upstream mode")
        if mode == "basic" and not basic_username:
            raise ValueError("basic mode requires basic_username")
        self.credential = credential
        self.mode = mode
        self.basic_username = basic_username
        self.header_name = header_name
        self.value_prefix = value_prefix
        self.ssl_context = ssl_context
        self.requests: list[dict[str, Any]] = []
        self.issue_counter = 0
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------ lifecycle
    def start(self) -> "FakeUpstream":
        if self._server is not None:
            return self
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        server.daemon_threads = True
        server.fake = self  # type: ignore[attr-defined]
        if self.ssl_context is not None:
            server.socket = self.ssl_context.wrap_socket(server.socket, server_side=True)
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        server, thread = self._server, self._thread
        self._server, self._thread = None, None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=5)

    def __enter__(self) -> "FakeUpstream":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    # ------------------------------------------------------------ address
    @property
    def host(self) -> str:
        return "127.0.0.1"

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("fake upstream not started")
        return int(self._server.server_address[1])

    @property
    def scheme(self) -> str:
        return "https" if self.ssl_context is not None else "http"

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def reset(self) -> None:
        with self._lock:
            self.requests.clear()
