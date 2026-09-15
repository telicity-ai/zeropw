"""Trusted HTTP surface: agent tools API and HTTP authentication relay.

Routes
------
``POST /v1/tools/<name>``      agent-native tools (JSON in/out).  Authenticated
                              with the caller's own token (``Authorization:
                              Bearer zpwc_...``), never with a vault value.
                              Every failed caller authentication is audited
                              (``auth_failed``) before the 401 is returned.
``ANY  /h/<handle>/<path>``    relay using a handle embedded in the URL prefix
                              (for CLIs that only accept a base URL).
``ANY  /relay/<path>``         relay using the ``X-ZeroPW-Handle`` header.
``CONNECT``                    refused: a CONNECT tunnel cannot inject
                              credentials into an encrypted request, so it is
                              never a supported delegation path.

Request framing is strict so that this server and any proxy in front of it
always agree where a request ends (no request smuggling): the request line
and every header line must end in CRLF, obsolete line folding, whitespace
before the colon and non-token field names are refused, any
``Transfer-Encoding`` is refused (chunked request bodies are unsupported), and
``Content-Length`` must be a single run of digits.  A body that is not read
(for example after an authentication failure) closes the connection.

Slow or idle clients cannot pin threads: each blocking socket operation times
out, a complete request must arrive within a deadline, and the number of
concurrent connections is capped.

Requests relayed by a ZeroPW gateway (``Via: 1.1 zeropw-relay``) are refused
with ``self_referential_target``: ZeroPW's own API is never reachable through
a business connection (docs/security-design.md §6).

The server never logs query strings, headers, or bodies.  Every error body is
a fixed reason code.  Upstream credentials are handled only inside
``zeropw.gateway``; this module moves bytes and maps errors.
"""

from __future__ import annotations

import hmac
import json
import re
import socket
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .context import Context
from .errors import (AuditUnavailable, AuthFailed, InvalidInput, NotFound, PolicyDenied, StateError,
                     Unsupported, ZeroPWError)

HANDLE_HEADER = "X-ZeroPW-Handle"
REQUEST_ID_HEADER = "X-ZeroPW-Request-Id"
MAX_TOOL_BODY = 1024 * 1024
SERVER_HEADER = "zeropw-prototype"
# Each blocking read or write on a client socket gives up after this long.
REQUEST_TIMEOUT_SECONDS = 15.0
# A complete request (line, headers and body) must arrive within this long,
# however slowly the client dribbles bytes.
REQUEST_READ_DEADLINE_SECONDS = 30.0
MAX_CONNECTIONS = 128
_REAPED = "reaped"      # connection state after it was cut at the read deadline

_TOKEN_RE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_CONTENT_LENGTH_RE = re.compile(r"^[0-9]{1,19}$")
_METHOD_RE = re.compile(r"^[A-Z]{1,16}$")

ERROR_STATUS = {
    AuthFailed: HTTPStatus.UNAUTHORIZED,
    PolicyDenied: HTTPStatus.FORBIDDEN,
    NotFound: HTTPStatus.NOT_FOUND,
    InvalidInput: HTTPStatus.BAD_REQUEST,
    Unsupported: HTTPStatus.NOT_IMPLEMENTED,
    AuditUnavailable: HTTPStatus.SERVICE_UNAVAILABLE,
    StateError: HTTPStatus.SERVICE_UNAVAILABLE,
}


def error_status(exc: ZeroPWError) -> int:
    for cls, status in ERROR_STATUS.items():
        if isinstance(exc, cls):
            return int(status)
    return int(HTTPStatus.INTERNAL_SERVER_ERROR)


class _FramingError(Exception):
    """The request cannot be framed unambiguously; refused with 400 and the connection closed."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _ClientGone(Exception):
    """The client stopped sending (timeout, deadline, or disconnect); no response is possible."""


class _StrictHeaderReader:
    """``rfile`` stand-in used only while ``http.client`` reads the header block.

    The stdlib parser accepts bare-LF line endings, obsolete line folding and
    malformed field names (a line such as ``Transfer-Encoding : chunked`` even
    silently ends the header block).  A proxy may frame such a request
    differently, so every one of them is refused here.
    """

    def __init__(self, raw: Any) -> None:
        self._raw = raw

    def readline(self, limit: int = -1) -> bytes:
        line = self._raw.readline(limit)
        if limit is not None and 0 <= limit <= len(line) and not line.endswith(b"\r\n"):
            return line     # over-long: http.client raises LineTooLong (431)
        if line == b"\r\n":
            return line
        if not line.endswith(b"\r\n"):
            raise _FramingError("malformed_header")     # bare LF, or the stream ended mid-headers
        content = line[:-2]
        if b"\r" in content or b"\n" in content or b"\x00" in content:
            raise _FramingError("malformed_header")
        if content[:1] in (b" ", b"\t"):
            raise _FramingError("obsolete_line_folding")
        name, separator, _ = content.partition(b":")
        if not separator or not _TOKEN_RE.match(name):
            raise _FramingError("malformed_header")
        return line

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw, name)


class ZeroPWHandler(BaseHTTPRequestHandler):
    server_version = SERVER_HEADER
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = REQUEST_TIMEOUT_SECONDS
    ctx: Context  # set on the server object

    _body_length = 0
    _body_pending = False

    def setup(self) -> None:
        timeout = getattr(self.server, "request_timeout", None)
        if timeout is not None:
            self.timeout = timeout
        super().setup()

    # ------------------------------------------------------------ logging
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - BaseHTTPRequestHandler signature
        # Only method and query-free path; never headers, bodies, or handles.
        try:
            path = (self.path or "").split("?", 1)[0]
            if path.startswith("/h/"):
                path = "/h/<handle>/..."
            if self.server.quiet:  # type: ignore[attr-defined]
                return
            self.server.log_lines.append(f"{self.command} {path}")  # type: ignore[attr-defined]
        except Exception:
            pass

    def log_error(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    # ------------------------------------------------------------ helpers
    @property
    def context(self) -> Context:
        return self.server.ctx  # type: ignore[attr-defined]

    def _mark_reading(self, reading: bool) -> bool:
        """Tell the server whether a request is arriving; False once it was cut at the read deadline."""
        mark = getattr(self.server, "mark_reading", None)
        return bool(mark(self.connection, reading)) if callable(mark) else True

    def _read_body(self, limit: int) -> bytes:
        if self.headers.get_all("Transfer-Encoding"):   # already refused while framing; never guess
            raise InvalidInput("transfer_encoding_unsupported")
        length = self._body_length
        if length > limit:
            raise InvalidInput("request_body_too_large")   # the unread body closes the connection
        data = b""
        if length:
            try:
                data = self.rfile.read(length)
            except OSError as exc:      # timeout, or the connection was cut at the read deadline
                self.close_connection = True
                raise _ClientGone() from exc
            if len(data) != length:
                self.close_connection = True
                raise _ClientGone()
        self._body_pending = False
        if not self._mark_reading(False):
            # Cut at the read deadline while the last bytes arrived: never act on it.
            self.close_connection = True
            raise _ClientGone()
        return data

    def _send(self, status: int, body: bytes, headers: list[tuple[str, str]] | None = None,
              content_type: str | None = None) -> None:
        self._mark_reading(False)
        if self._body_pending:
            # The declared body was never read; its bytes must not be parsed as a next request.
            self.close_connection = True
        self.send_response(status)
        sent_type = False
        for name, value in headers or []:
            if name.lower() == "content-type":
                sent_type = True
            self.send_header(name, value)
        if content_type and not sent_type:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        self._send(status, json.dumps(payload, sort_keys=True).encode("utf-8"), content_type="application/json")

    def _send_error(self, exc: ZeroPWError) -> None:
        self._send_json(error_status(exc), exc.to_dict())

    def _audit_action(self) -> str | None:
        command = self.command if isinstance(self.command, str) else ""
        return command if _METHOD_RE.match(command) else None

    # ----------------------------------------------------------- dispatch
    def _dispatch(self) -> None:
        try:
            if self._relayed_by_zeropw():
                self._refuse_self_reference()
                return
            path = self.path or "/"
            if path.startswith("/v1/tools/"):
                self._handle_tool(path[len("/v1/tools/"):].split("?", 1)[0])
            elif path.startswith("/h/"):
                rest = path[len("/h/"):]
                handle, _, sub_path = rest.partition("/")
                self._handle_relay(handle, "/" + sub_path)
            elif path.startswith("/relay/") or path == "/relay":
                handle = self.headers.get(HANDLE_HEADER, "")
                self._handle_relay(handle, path[len("/relay"):] or "/")
            elif path == "/healthz":
                self._send_json(200, {"status": "ok"})
            else:
                self._send_json(404, {"error": "NotFound", "reason": "route_not_found"})
        except _ClientGone:
            self.close_connection = True
        except ZeroPWError as exc:
            try:
                self._send_error(exc)
            except OSError:
                self.close_connection = True
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            self.close_connection = True
        except Exception:
            # Never leak internals.  Audit best-effort; refuse.
            try:
                self._send_json(500, {"error": "InternalError", "reason": "internal_error"})
            except Exception:
                pass

    def _relayed_by_zeropw(self) -> bool:
        from .gateway import RELAY_PSEUDONYM

        for value in self.headers.get_all("Via") or []:
            for hop in value.split(","):
                parts = hop.strip().split()
                if len(parts) >= 2 and parts[1].lower() == RELAY_PSEUDONYM:
                    return True
        return False

    def _refuse_self_reference(self) -> None:
        try:
            self.context.audit.record("unsupported", action=self._audit_action(), result="denied",
                                      reason="self_referential_target")
        except (AuditUnavailable, InvalidInput):
            pass    # refused either way; no credential is involved
        self._send_json(501, {"error": "Unsupported", "reason": "self_referential_target"})

    def _authenticate_tool_caller(self, name: str) -> Any:
        """Authenticate the tools caller; every failure is audited before the 401 (security-design §5/§6)."""
        from . import tools

        auth = self.headers.get("Authorization", "")
        token = auth[len("Bearer "):].strip() if auth.startswith("Bearer ") else None
        try:
            if not token:
                raise AuthFailed("caller_token_missing")
            return self.context.policy.authenticate(token)
        except AuthFailed as exc:
            caller = self._principal_for_token(token) if exc.reason == "principal_disabled" else None
            action = name if name in tools.TOOL_NAMES else None   # never agent-chosen free text
            try:
                self.context.audit.record("auth_failed", caller=caller, action=action, result="denied",
                                          reason=exc.reason, extra={"kind": "caller_token"})
            except AuditUnavailable:
                raise AuditUnavailable("audit_unavailable") from None
            raise

    def _principal_for_token(self, token: str | None) -> str | None:
        if not token:
            return None
        from .policy import hash_token

        digest = hash_token(token)
        for principal in self.context.policy.list_principals():
            if hmac.compare_digest(principal.token_hash, digest):
                return principal.id
        return None

    def _handle_tool(self, name: str) -> None:
        from . import tools

        if self.command != "POST":
            raise InvalidInput("tools_require_post")
        principal = self._authenticate_tool_caller(name)
        raw = self._read_body(MAX_TOOL_BODY)
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError) as exc:
            raise InvalidInput("invalid_json") from exc
        if not isinstance(payload, dict):
            raise InvalidInput("invalid_json")
        result = tools.dispatch(self.context, name, principal.id, payload)
        self._send_json(200, result)

    def _handle_relay(self, handle: str, sub_path: str) -> None:
        from . import gateway

        body = self._read_body(self.context.config.max_request_body_bytes)
        headers = {k: v for k, v in self.headers.items()}
        request_id = self.headers.get(REQUEST_ID_HEADER)
        result = gateway.relay(self.context, handle, self.command, sub_path, headers, body, request_id)
        self._send(result.status, result.body, result.headers)

    # ------------------------------------------------------------- verbs
    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_GET

    def do_CONNECT(self) -> None:  # noqa: N802
        self._send_json(405, {"error": "Unsupported", "reason": "connect_tunnel_unsupported"})

    def do_TRACE(self) -> None:  # noqa: N802
        self._send_json(405, {"error": "Unsupported", "reason": "method_not_supported"})

    def handle_one_request(self) -> None:
        self._body_length = 0
        self._body_pending = False
        self._mark_reading(True)
        try:
            super().handle_one_request()
        except OSError:     # reset, broken pipe, timeout, or cut at the read deadline
            self.close_connection = True
        finally:
            self._mark_reading(False)

    # ------------------------------------------------------------- framing
    def parse_request(self) -> bool:
        raw_rfile = self.rfile
        self.rfile = _StrictHeaderReader(raw_rfile)
        try:
            ok = super().parse_request()
        except _FramingError as exc:
            self.rfile = raw_rfile
            self._refuse_framing(exc.reason)
            return False
        finally:
            self.rfile = raw_rfile
        if not ok:
            return False
        try:
            self._check_framing()
        except _FramingError as exc:
            self._refuse_framing(exc.reason)
            return False
        # Absolute-URI request targets (proxy style) are refused before routing.
        if self.path and "://" in self.path.split("?", 1)[0]:
            self._send_json(400, {"error": "Unsupported", "reason": "absolute_uri_unsupported"})
            self.close_connection = True
            return False
        return True

    def _check_framing(self) -> None:
        line = self.raw_requestline or b""
        if not line.endswith(b"\r\n"):
            raise _FramingError("malformed_request_line")
        parts = line[:-2].split(b" ")
        if len(parts) != 3 or not all(parts) or any(b"\r" in p or b"\t" in p for p in parts):
            raise _FramingError("malformed_request_line")
        if self.headers.get_all("Transfer-Encoding"):
            raise _FramingError("transfer_encoding_unsupported")
        lengths = self.headers.get_all("Content-Length") or []
        if len(lengths) > 1:
            raise _FramingError("invalid_content_length")
        if lengths:
            value = lengths[0].strip(" \t")
            if not _CONTENT_LENGTH_RE.match(value):
                raise _FramingError("invalid_content_length")
            self._body_length = int(value)
            self._body_pending = self._body_length > 0

    def _refuse_framing(self, reason: str) -> None:
        self.close_connection = True
        self._body_pending = True
        try:
            self._send_json(400, {"error": "InvalidInput", "reason": reason})
        except OSError:
            pass


class ZeroPWServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_timeout: float = REQUEST_TIMEOUT_SECONDS
    request_read_deadline: float = REQUEST_READ_DEADLINE_SECONDS
    max_connections: int = MAX_CONNECTIONS

    def __init__(self, ctx: Context, host: str | None = None, port: int | None = None, quiet: bool = True) -> None:
        self.ctx = ctx
        self.quiet = quiet
        self.log_lines: list[str] = []
        # client socket -> monotonic time its current request started arriving, None while
        # processing, or _REAPED once cut at the read deadline
        self._connections: dict[Any, float | str | None] = {}
        self._connections_lock = threading.Lock()
        super().__init__((host or ctx.config.listen_host, port if port is not None else ctx.config.listen_port),
                         ZeroPWHandler)
        self._thread: threading.Thread | None = None
        from . import gateway

        gateway.register_local_listener(self.socket)

    @property
    def url(self) -> str:
        host, port = self.server_address[:2]
        return f"http://{host}:{port}"

    # ------------------------------------------------------- connections
    def process_request(self, request: Any, client_address: Any) -> None:
        with self._connections_lock:
            busy = len(self._connections) >= self.max_connections
            if not busy:
                self._connections[request] = time.monotonic()
        if busy:
            self._refuse_busy(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._forget(request)
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._forget(request)

    def _forget(self, request: Any) -> None:
        with self._connections_lock:
            self._connections.pop(request, None)

    def _refuse_busy(self, request: Any) -> None:
        body = json.dumps({"error": "StateError", "reason": "too_many_connections"}, sort_keys=True).encode()
        head = (f"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n").encode()
        try:
            request.setblocking(False)
            request.send(head + body)
        except OSError:
            pass
        self.shutdown_request(request)

    def mark_reading(self, request: Any, reading: bool) -> bool:
        """Record whether ``request`` is waiting for request bytes.  False if it was already reaped."""
        with self._connections_lock:
            state = self._connections.get(request)
            if state == _REAPED:
                return False
            if request in self._connections:
                self._connections[request] = time.monotonic() if reading else None
            return True

    def reap_slow_clients(self, now: float | None = None) -> int:
        """Cut connections whose request has not fully arrived within ``request_read_deadline``."""
        now = time.monotonic() if now is None else now
        with self._connections_lock:
            overdue = [sock for sock, started in self._connections.items()
                       if isinstance(started, float) and now - started > self.request_read_deadline]
            for sock in overdue:
                self._connections[sock] = _REAPED
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        return len(overdue)

    def service_actions(self) -> None:
        super().service_actions()
        self.reap_slow_clients()

    # ---------------------------------------------------------- lifecycle
    def serve_in_thread(self) -> "ZeroPWServer":
        self._thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        self._thread.start()
        return self

    def server_close(self) -> None:
        from . import gateway

        gateway.unregister_local_listener(self.socket)
        # Connections still waiting for (part of) a request are cut so closing
        # does not wait on idle keep-alive clients; requests being processed finish.
        with self._connections_lock:
            waiting = [sock for sock, started in self._connections.items() if isinstance(started, float)]
        for sock in waiting:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        super().server_close()

    def stop(self) -> None:
        self.shutdown()
        self.server_close()
        if self._thread:
            self._thread.join(timeout=5)
