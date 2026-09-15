"""HTTP authentication relay: the only place an upstream HTTP credential is used.

Security scope (docs/security-design.md §2, §4, §5)
---------------------------------------------------
* The agent never chooses the destination.  Scheme, host, port and TLS
  trust come from the connection record only.  The client's ``Host`` header,
  absolute-URI request targets and ``CONNECT`` tunnels are ignored or refused
  by ``zeropw.server``; here the relayed path is treated as untrusted data and
  rejected when it contains traversal, empty segments, control characters,
  a scheme separator, or percent-encoded forms of those.
* Every request re-evaluates policy (caller, connection, grant, method,
  path prefix, expiry, usage cap, revocation, global stop, restore-pending,
  policy version) before the credential is fetched.  A handle whose policy
  version no longer matches the connection is refused (``grant_stale``).
* Incoming authentication-bearing headers (``Authorization``,
  ``Proxy-Authorization``, ``Cookie``, ``X-ZeroPW-*``) and hop-by-hop headers
  are dropped; only a small allowlist is forwarded.  The credential is
  inserted by the connection's profile (``bearer``, ``basic``, ``header``).
  Any other profile fails closed with ``unsupported_auth_mode``.
* Self-referential configurations are refused (docs/security-design.md §6):
  a connection whose target is this ZeroPW server (its public URL, a
  registered listen socket, or a peer address that turns out to be one after
  connecting) fails with ``self_referential_target``, and a stored credential
  that is a ZeroPW caller token or handle fails with
  ``self_referential_credential``.  Every relayed request carries
  ``Via: 1.1 zeropw-relay`` and ``zeropw.server`` refuses requests that carry
  it, so ZeroPW's own authority cannot be reached through an alias either.
* Responses are buffered (bounded by ``ctx.config.max_response_bytes``),
  redirects are never followed and ``Location`` is never forwarded, response
  headers pass an allowlist, and the whole response (headers and body) is
  scanned for the credential in several encodings.  A hit blocks the entire
  response (``credential_reflection_blocked``): no partial bytes are returned.
* A mandatory audit record is written before the credential is fetched and a
  second one with the outcome afterwards.  If the audit log cannot be written
  the request is refused (``audit_unavailable``).
* A risky-method approval is bound to caller, connection, method, the
  server-resolved origin, the full target (path and query), the connection's
  policy version, the Content-Type and the body digest.  The pending approval
  entry (trusted state, shown only by ``admin_cli approvals list``) carries the
  origin, query string, Content-Type, body size, SHA-256 and a short text
  preview so the approver can see what the digest binds.
* Error bodies contain fixed reason codes only.  Query strings, headers,
  bodies and credentials are never logged or audited.

Limitations (honest statement for the prototype)
------------------------------------------------
* No streaming pass-through.  Chunked upstream responses are decoded and
  fully buffered before scanning; server-sent events and long-lived streams
  are unsupported and end with ``response_too_large`` once the bound is hit.
* The reflection guard covers raw, standard/URL-safe base64 (at every byte
  alignment, so a credential embedded in a larger base64 blob is found, also
  when the blob is wrapped with CR/LF or JSON ``\\n`` escapes), percent (upper-
  and lower-case hex triplets), hex, JSON- and HTML-escaped forms and the
  Basic ``user:password`` pair.  It does not detect arbitrary transformations
  (docs/security-design.md §4); services that transform credentials must be
  vetted before being listed as supported.
* Compressed upstream bodies are refused (``response_encoding_unsupported``)
  because they cannot be scanned; the relay asks for ``identity`` encoding.
* DNS changes (docs/security-design.md §4): a hostname target is resolved
  once per request, before any approval, usage or credential is spent on it.
  Every address in the answer is checked (metadata/link-local always refused;
  any non-public address refused unless the connection sets
  ``allow_private_network``; IPv6 forms that embed an IPv4 address -- NAT64,
  IPv4-compatible, SIIT, 6to4, Teredo -- are judged by that IPv4 address too),
  and the socket is opened to the checked address, never re-resolved.  What
  remains: the OS resolver's answer is trusted; ``allow_private_network``
  accepts any private answer; a change from one public address to another is
  not detected (only HTTPS server identity verification tells the upstreams
  apart); a translator using a non-standard NAT64 prefix is not recognised.
* The idempotency ledger is local JSON state.  It prevents blind retries of
  writes whose outcome is unknown (``outcome_uncertain``) but does not promise
  exactly-once execution at the upstream service.
"""

from __future__ import annotations

import base64
import hashlib
import html
import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import urllib.parse
import weakref
from dataclasses import dataclass, field
from typing import Any, Mapping

from .audit import strip_query
from .errors import AuditUnavailable, AuthFailed, InvalidInput, NotFound, PolicyDenied, StateError
from .policy import Action, Connection, Grant, address_block_reason, approval_digest

__all__ = ["RelayResult", "relay", "relay_for_caller", "normalize_path", "credential_patterns", "RequestLedger",
           "register_local_listener", "unregister_local_listener", "RELAY_PSEUDONYM"]

REQUEST_ID_HEADER = "x-zeropw-request-id"
# Client request headers that may reach the upstream.  Content-Length is not
# forwarded verbatim: http.client recomputes it from the body actually sent.
# Accept-Encoding is replaced with "identity" so the body stays scannable.
REQUEST_HEADER_ALLOWLIST = frozenset({
    "accept", "content-type", "user-agent", "x-request-id", "if-none-match", "if-modified-since", "range",
})
RESPONSE_HEADER_ALLOWLIST = frozenset({
    "content-type", "cache-control", "etag", "last-modified", "x-request-id", "retry-after",
    "content-language", "vary",
})
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_PATH_LENGTH = 8192
MAX_REQUEST_ID_LENGTH = 128
LEDGER_DOC = "gateway/requests.json"
LEDGER_MAX_STORED_BODY = 1024 * 1024
LEDGER_MAX_ENTRIES = 512
LEDGER_TTL_SECONDS = 6 * 3600
READ_CHUNK = 64 * 1024
# Derived base64 "core" patterns shorter than this are not used: they would
# match unrelated output.  Credentials are far longer in practice.
MIN_ALIGNED_PATTERN_LENGTH = 8
# Line-break forms removed from a body before a second scan, so a credential
# inside a wrapped base64 blob (MIME / "file content" APIs) is still found.
_WRAP_FORMS = (b"\r", b"\n", b"\\r", b"\\n")
# Marker added to every relayed request; zeropw.server refuses requests that
# carry it, so a connection can never reach ZeroPW's own API (security-design §6).
RELAY_PSEUDONYM = "zeropw-relay"
RELAY_VIA = f"1.1 {RELAY_PSEUDONYM}"
# Prefixes of ZeroPW's own bearer authority (caller tokens and handles).
_ZEROPW_AUTHORITY_RE = re.compile(rb"(?:^|[\s:=,;])(?:zpwc_|zpw1\.)")
APPROVAL_PREVIEW_CHARS = 256

_TARGET_CHARS = re.compile(r"^[\x21-\x7e]*$")           # printable ASCII, no space
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_HEADER_VALUE_RE = re.compile(r"^[\x20-\x7e\t]*$")
_HEADER_CREDENTIAL_RE = re.compile(r"^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$")
_METHOD_RE = re.compile(r"^[A-Z]{1,16}$")
_REQUEST_ID_RE = re.compile(r"^[\x21-\x7e]{1,128}$")
_PERCENT_TRIPLET_RE = re.compile(rb"%[0-9A-Fa-f]{2}")

_ERROR_NAMES = {
    400: "InvalidInput", 401: "AuthFailed", 403: "PolicyDenied", 409: "Conflict", 428: "PolicyDenied",
    501: "Unsupported", 502: "UpstreamError", 503: "StateError",
}


# ------------------------------------------------------------------- results
@dataclass
class RelayResult:
    """What the gateway returns to the server route or ``tools.request``.

    ``reason`` is ``None`` for a relayed upstream response and a fixed code for
    every refusal, block, or upstream failure.  ``body`` never contains
    credential material: refusals carry a small JSON document and blocked
    responses carry no upstream bytes at all.
    """

    status: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    reason: str | None = None

    @property
    def blocked_reason(self) -> str | None:
        return self.reason

    @property
    def relayed(self) -> bool:
        return self.reason is None

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


def _error_result(status: int, reason: str, error: str | None = None,
                  extra: dict[str, Any] | None = None) -> RelayResult:
    payload: dict[str, Any] = {"error": error or _ERROR_NAMES.get(status, "RelayError"), "reason": reason}
    if extra:
        payload.update(extra)
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    return RelayResult(status, [("Content-Type", "application/json")], body, reason)


# ---------------------------------------------------------------- validation
class _Invalid(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def normalize_path(raw: Any) -> tuple[str, str]:
    """Validate a client-supplied request target.

    Returns ``(path_without_query, forwarded_target)``.  The forwarded target
    is the original path plus query, untouched.  Percent-decoding is used only
    to detect smuggled ``..`` / ``/`` / control characters; the decoded form is
    never forwarded and never used for the policy check (the raw path is, so a
    disguised path can only fail closed).
    """
    if not isinstance(raw, str) or not raw.startswith("/"):
        raise _Invalid("invalid_path")
    if len(raw) > MAX_PATH_LENGTH or not _TARGET_CHARS.match(raw) or "#" in raw:
        raise _Invalid("invalid_path")
    path, _, _query = raw.partition("?")
    candidates = [path]
    decoded = path
    for _ in range(2):
        decoded = urllib.parse.unquote(decoded)
        candidates.append(decoded)
    for candidate in candidates:
        if "\\" in candidate or "://" in candidate or _CONTROL_RE.search(candidate):
            raise _Invalid("invalid_path")
        segments = candidate.split("/")[1:]
        for index, segment in enumerate(segments):
            if segment in (".", ".."):
                raise _Invalid("invalid_path")
            if segment == "" and index != len(segments) - 1:
                raise _Invalid("invalid_path")   # "//" anywhere but a trailing slash
    return path, raw


def _normalize_method(method: Any) -> str:
    if not isinstance(method, str):
        raise _Invalid("invalid_method")
    upper = method.strip().upper()
    if not _METHOD_RE.match(upper):
        raise _Invalid("invalid_method")
    return upper


def _normalize_body(body: Any) -> bytes:
    if body is None:
        return b""
    if isinstance(body, (bytes, bytearray, memoryview)):
        return bytes(body)
    if isinstance(body, str):
        return body.encode("utf-8")
    raise _Invalid("invalid_body")


def _normalize_headers(headers: Any) -> dict[str, str]:
    if headers is None:
        return {}
    if not isinstance(headers, Mapping):
        raise _Invalid("invalid_headers")
    result: dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise _Invalid("invalid_headers")
        result[name.strip().lower()] = value
    return result


def _normalize_request_id(request_id: Any, headers: Mapping[str, str]) -> str | None:
    if request_id is None:
        request_id = headers.get(REQUEST_ID_HEADER)
    if request_id is None or request_id == "":
        return None
    if not isinstance(request_id, str) or not _REQUEST_ID_RE.match(request_id):
        raise _Invalid("invalid_request_id")
    return request_id


def _forwardable_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Allowlist only.  Everything auth-bearing or hop-by-hop is dropped."""
    forwarded: dict[str, str] = {}
    for name, value in headers.items():
        if name not in REQUEST_HEADER_ALLOWLIST:
            continue
        if not _HEADER_VALUE_RE.match(value):
            raise _Invalid("invalid_header_value")
        forwarded[name] = value
    return forwarded


# ------------------------------------------------------------- credentials
def _lowercase_percent_triplets(encoded: bytes) -> bytes:
    """Re-emit every ``%XX`` triplet in lower case; unreserved bytes are untouched.

    RFC 3986 §2.1 allows either hex case in a percent-encoding and real
    services emit both, while ``urllib.parse.quote`` only ever produces the
    upper-case form.  Only the triplets are lower-cased: the credential's own
    letters must keep their case or the pattern would not match a real leak.
    """
    return _PERCENT_TRIPLET_RE.sub(lambda match: match.group(0).lower(), encoded)


def _base64_cores(data: bytes) -> list[bytes]:
    """Base64 forms of ``data`` that appear wherever it sits inside a larger encoded blob.

    Base64 encodes 3-byte groups, so the characters produced for ``data``
    depend on its offset modulo 3 in the surrounding byte stream.  For each
    of the three alignments (both alphabets) the characters that also encode
    neighbouring bytes are trimmed: 2 or 3 leading characters when ``data``
    does not start a group, and 1 trailing character when it does not end one.
    """
    cores: list[bytes] = []
    for encoder in (base64.b64encode, base64.urlsafe_b64encode):
        for shift in range(3):
            encoded = encoder(b"\x00" * shift + data).rstrip(b"=")
            head = (0, 2, 3)[shift]
            tail = (0, 1, 1)[(shift + len(data)) % 3]
            core = encoded[head:len(encoded) - tail]
            if len(core) >= MIN_ALIGNED_PATTERN_LENGTH:
                cores.append(core)
    return cores


def credential_patterns(secret: bytes, basic_username: str | None = None) -> tuple[bytes, ...]:
    """Byte patterns whose presence in a response means the credential leaked."""
    patterns: list[bytes] = [secret]
    patterns.append(base64.b64encode(secret).rstrip(b"="))
    patterns.append(base64.urlsafe_b64encode(secret).rstrip(b"="))
    patterns.extend(_base64_cores(secret))
    patterns.append(secret.hex().encode("ascii"))
    patterns.append(secret.hex().upper().encode("ascii"))
    for quoted in (urllib.parse.quote(secret, safe=""), urllib.parse.quote_plus(secret, safe="")):
        encoded = quoted.encode("ascii")
        patterns.append(encoded)                                # upper-case hex (what quote() emits)
        patterns.append(_lowercase_percent_triplets(encoded))   # lower-case hex, equally valid
    try:
        text = secret.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is not None:
        patterns.append(json.dumps(text)[1:-1].encode("utf-8"))
        patterns.append(json.dumps(text, ensure_ascii=False)[1:-1].encode("utf-8"))
        patterns.append(html.escape(text, quote=True).encode("utf-8"))
    if basic_username is not None:
        pair = basic_username.encode("utf-8") + b":" + secret
        patterns.append(base64.b64encode(pair).rstrip(b"="))
        patterns.append(base64.urlsafe_b64encode(pair).rstrip(b"="))
        patterns.extend(_base64_cores(pair))
    unique: list[bytes] = []
    for pattern in patterns:
        if pattern and pattern not in unique:
            unique.append(pattern)
    return tuple(unique)


def _contains_credential(blob: bytes, patterns: tuple[bytes, ...]) -> bool:
    if any(pattern in blob for pattern in patterns):
        return True
    compact = blob
    for form in _WRAP_FORMS:
        compact = compact.replace(form, b"")
    return compact != blob and any(pattern in compact for pattern in patterns)


def _auth_header(connection: Connection, secret: bytes) -> tuple[str, str]:
    """Build the single header that carries the credential.  Fail closed."""
    auth = connection.http_auth
    if auth is None:
        raise _Invalid("unsupported_auth_mode")
    if _ZEROPW_AUTHORITY_RE.search(secret.strip()):
        # A ZeroPW caller token or handle must never be a business credential (§6).
        raise _Invalid("self_referential_credential")
    if auth.mode == "basic":
        if not auth.basic_username or ":" in auth.basic_username:
            raise _Invalid("unsupported_auth_mode")
        pair = auth.basic_username.encode("utf-8") + b":" + secret
        return "Authorization", "Basic " + base64.b64encode(pair).decode("ascii")
    try:
        text = secret.decode("utf-8")
    except UnicodeDecodeError:
        raise _Invalid("credential_not_text") from None
    if not _HEADER_CREDENTIAL_RE.match(text):
        raise _Invalid("credential_header_unsafe")
    if auth.mode == "bearer":
        return "Authorization", "Bearer " + text
    if auth.mode == "header":
        if not auth.header_name or not re.match(r"^[A-Za-z0-9-]{1,64}$", auth.header_name):
            raise _Invalid("unsupported_auth_mode")
        prefix = auth.value_prefix or ""
        if not _HEADER_VALUE_RE.match(prefix):
            raise _Invalid("credential_header_unsafe")
        return auth.header_name, prefix + text
    raise _Invalid("unsupported_auth_mode")


# ---------------------------------------------------------- self-reference
_LOCAL_LISTENERS: "weakref.WeakSet[socket.socket]" = weakref.WeakSet()
_LOCAL_LISTENERS_LOCK = threading.Lock()


def register_local_listener(sock: socket.socket) -> None:
    """Record a listening socket of this process's ZeroPW server (``zeropw.server``).

    Held weakly and ignored once closed, so a stale entry can never refuse an
    unrelated upstream that later binds the same port.
    """
    with _LOCAL_LISTENERS_LOCK:
        _LOCAL_LISTENERS.add(sock)


def unregister_local_listener(sock: socket.socket) -> None:
    with _LOCAL_LISTENERS_LOCK:
        _LOCAL_LISTENERS.discard(sock)


def _ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(value.strip("[]").split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _listener_addresses() -> list[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]]:
    with _LOCAL_LISTENERS_LOCK:
        sockets = list(_LOCAL_LISTENERS)
    addresses = []
    for sock in sockets:
        try:
            if sock.fileno() == -1:
                continue
            host, port = sock.getsockname()[:2]
        except OSError:
            continue
        address = _ip(str(host))
        if address is not None:
            addresses.append((address, int(port)))
    return addresses


def _reaches_listener(address: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int,
                      local: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None) -> bool:
    for listen_ip, listen_port in _listener_addresses():
        if port != listen_port:
            continue
        if address == listen_ip:
            return True
        if address.is_unspecified or (local is not None and address == local):
            return True     # 0.0.0.0 / :: as a destination, or our own interface address
        if (listen_ip.is_unspecified or listen_ip.is_loopback) and address.is_loopback:
            return True
    return False


def _self_referential_target(ctx: Any, connection: Connection) -> bool:
    """Cheap literal check before any use is consumed; ``_exchange`` re-checks the real peer."""
    target = connection.http_target
    assert target is not None
    host = target.host.strip("[]").lower().rstrip(".")
    extra = getattr(getattr(ctx, "config", None), "extra", None)
    public_url = extra.get("public_url") if isinstance(extra, Mapping) else None
    if isinstance(public_url, str) and public_url:
        try:
            parts = urllib.parse.urlsplit(public_url)
            public_port = parts.port or (443 if parts.scheme == "https" else 80)
            if (parts.hostname or "").rstrip(".") == host and public_port == target.port:
                return True
        except ValueError:
            pass
    address = _ip(host)
    if address is None:
        if host == "localhost" or host.endswith(".localhost"):
            address = ipaddress.ip_address("127.0.0.1")
        else:
            return False
    return _reaches_listener(address, target.port)


def _peer_is_local_listener(sock: Any) -> bool:
    try:
        peer_host, peer_port = sock.getpeername()[:2]
        local_host = sock.getsockname()[0]
    except (OSError, AttributeError, TypeError, ValueError):
        return False
    address = _ip(str(peer_host))
    if address is None:
        return False
    return _reaches_listener(address, int(peer_port), _ip(str(local_host)))


# ------------------------------------------------------------------- ledger
class RequestLedger:
    """Per-caller request-id ledger (docs/security-design.md §5).

    Entries live in the trusted state directory.  A stored response is the
    already-filtered, already-scanned ``RelayResult`` (never raw upstream
    bytes that failed the guard), bounded to ``LEDGER_MAX_STORED_BODY``.
    """

    def __init__(self, ctx: Any) -> None:
        self.state = ctx.state
        self.clock = ctx.clock

    def _load(self) -> dict[str, dict[str, dict[str, Any]]]:
        doc = self.state.read_json(LEDGER_DOC, {}) or {}
        return doc if isinstance(doc, dict) else {}

    def _save(self, doc: dict[str, dict[str, dict[str, Any]]]) -> None:
        now = self.clock()
        for caller in list(doc):
            entries = doc[caller]
            for request_id in list(entries):
                if now - float(entries[request_id].get("updated_at", 0)) > LEDGER_TTL_SECONDS:
                    del entries[request_id]
            if not entries:
                del doc[caller]
        total = sum(len(v) for v in doc.values())
        if total > LEDGER_MAX_ENTRIES:
            completed = sorted(
                ((float(e.get("updated_at", 0)), caller, rid)
                 for caller, entries in doc.items() for rid, e in entries.items() if e.get("state") == "completed"),
            )
            for _, caller, rid in completed[: total - LEDGER_MAX_ENTRIES]:
                doc[caller].pop(rid, None)
                if not doc[caller]:
                    del doc[caller]
        self.state.write_json(LEDGER_DOC, doc)

    @staticmethod
    def digest(connection_id: str, method: str, target: str, body: bytes) -> str:
        hasher = hashlib.sha256()
        for part in (connection_id.encode("utf-8"), method.encode("ascii"), target.encode("ascii"), body):
            hasher.update(len(part).to_bytes(8, "big"))
            hasher.update(part)
        return hasher.hexdigest()

    def claim(self, caller: str, request_id: str, digest: str, connection_id: str) -> tuple[str, dict[str, Any] | None]:
        """Atomically look up and, when new, mark the request in flight.

        Returns one of ``("new", None)``, ``("replay", entry)``,
        ``("in_flight", None)``, ``("uncertain", None)``, ``("reused", None)``.
        """
        with self.state.lock():
            doc = self._load()
            entry = doc.get(caller, {}).get(request_id)
            now = self.clock()
            if entry is not None and now - float(entry.get("updated_at", 0)) <= LEDGER_TTL_SECONDS:
                if entry.get("digest") != digest:
                    return "reused", None
                state = entry.get("state")
                if state == "completed":
                    return "replay", entry
                if state == "uncertain":
                    return "uncertain", None
                return "in_flight", None
            doc.setdefault(caller, {})[request_id] = {
                "digest": digest, "state": "in_flight", "connection": connection_id,
                "created_at": now, "updated_at": now, "response": None,
            }
            self._save(doc)
            return "new", None

    def _update(self, caller: str, request_id: str, **changes: Any) -> None:
        with self.state.lock():
            doc = self._load()
            entry = doc.get(caller, {}).get(request_id)
            if entry is None:
                return
            entry.update(changes)
            entry["updated_at"] = self.clock()
            self._save(doc)

    def release(self, caller: str, request_id: str) -> None:
        """Forget a claim whose request never reached the upstream."""
        with self.state.lock():
            doc = self._load()
            if request_id in doc.get(caller, {}):
                del doc[caller][request_id]
                if not doc[caller]:
                    del doc[caller]
                self._save(doc)

    def mark_uncertain(self, caller: str, request_id: str) -> None:
        self._update(caller, request_id, state="uncertain")

    def complete(self, caller: str, request_id: str, result: RelayResult) -> None:
        stored: dict[str, Any] = {
            "status": result.status, "headers": [list(h) for h in result.headers], "reason": result.reason,
            "body_b64": None, "body_stored": False,
        }
        if len(result.body) <= LEDGER_MAX_STORED_BODY:
            stored["body_b64"] = base64.b64encode(result.body).decode("ascii")
            stored["body_stored"] = True
        self._update(caller, request_id, state="completed", response=stored)

    @staticmethod
    def replay(entry: dict[str, Any]) -> RelayResult:
        response = entry.get("response") or {}
        status = int(response.get("status", 502))
        headers = [(str(k), str(v)) for k, v in response.get("headers") or []]
        if not response.get("body_stored"):
            headers = [(k, v) for k, v in headers if k.lower() != "content-type"]
            payload = json.dumps({"error": "ReplayBodyUnavailable", "reason": "replay_body_unavailable"}).encode()
            headers.append(("Content-Type", "application/json"))
            headers.append(("X-ZeroPW-Replay", "true"))
            return RelayResult(status, headers, payload, "replay_body_unavailable")
        body = base64.b64decode(response.get("body_b64") or "")
        headers.append(("X-ZeroPW-Replay", "true"))
        return RelayResult(status, headers, body, response.get("reason"))


# --------------------------------------------------------------- upstream
class _UpstreamFailure(Exception):
    """An upstream exchange did not yield a relayable response.

    ``known_outcome`` is True when the upstream answered (so the request was
    processed) and False when we cannot tell (timeout, connection lost).
    """

    def __init__(self, reason: str, result: str, known_outcome: bool, upstream_status: int | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.result = result
        self.known_outcome = known_outcome
        self.upstream_status = upstream_status


@dataclass
class _UpstreamResponse:
    status: int
    headers: list[tuple[str, str]]
    body: bytes


# Indirection so tests can simulate DNS answers without touching the process-wide resolver.
_getaddrinfo = socket.getaddrinfo


def resolve_pinned_address(connection: Connection) -> str:
    """Resolve the target once, refuse forbidden addresses, return the address to connect to.

    docs/security-design.md §4: DNS changes must not route the credential to an
    internal, loopback or metadata address.  Every address in the answer is
    checked (one forbidden address refuses the request, so a mixed answer
    cannot win a race), and the socket is opened to the checked address, never
    re-resolved.  IP literals were chosen by the administrator and cannot be
    changed by DNS; only metadata/link-local literals are refused.
    """
    target = connection.http_target
    assert target is not None
    literal = _ip(target.host.strip("[]"))
    if literal is not None:
        reason = address_block_reason(literal, allow_private_network=True)
        if reason is not None:
            raise _UpstreamFailure(reason, "denied", False)
        return target.host.strip("[]")
    try:
        answers = _getaddrinfo(target.host, target.port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError, ValueError) as exc:
        raise _UpstreamFailure("upstream_unreachable", "error", False) from exc
    pinned: str | None = None
    for family, _type, _proto, _canon, sockaddr in answers:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        raw = str(sockaddr[0]).split("%", 1)[0]
        address = _ip(raw)
        if address is None:
            raise _UpstreamFailure("target_address_not_allowed", "denied", False)
        reason = address_block_reason(address, target.allow_private_network)
        if reason is not None:
            raise _UpstreamFailure(reason, "denied", False)
        if pinned is None:
            pinned = raw
    if pinned is None:
        raise _UpstreamFailure("upstream_unreachable", "error", False)
    return pinned


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connects to an already-checked address; ``host`` stays the configured name for the Host header."""

    def __init__(self, host: str, port: int, pinned_address: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._pinned_address = pinned_address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_address, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """TLS to an already-checked address; certificate and SNI are verified against the configured name."""

    def __init__(self, host: str, port: int, pinned_address: str, timeout: float, context: ssl.SSLContext) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_address = pinned_address
        self._tls_context = context

    def connect(self) -> None:
        raw = socket.create_connection((self._pinned_address, self.port), self.timeout)
        try:
            self.sock = self._tls_context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def _open_connection(connection: Connection, timeout: float, pinned_address: str | None = None) -> http.client.HTTPConnection:
    target = connection.http_target
    assert target is not None
    address = pinned_address if pinned_address is not None else target.host.strip("[]")
    if target.scheme == "https":
        tls = ssl.create_default_context()
        tls.check_hostname = True
        tls.verify_mode = ssl.CERT_REQUIRED
        if target.ca_file:
            try:
                tls.load_verify_locations(cafile=target.ca_file)
            except (OSError, ssl.SSLError) as exc:
                raise _UpstreamFailure("ca_file_unavailable", "error", False) from exc
        return _PinnedHTTPSConnection(target.host, target.port, address, timeout, tls)
    return _PinnedHTTPConnection(target.host, target.port, address, timeout)


def _host_header(connection: Connection) -> str:
    target = connection.http_target
    assert target is not None
    default = 443 if target.scheme == "https" else 80
    host = f"[{target.host}]" if ":" in target.host else target.host
    return host if target.port == default else f"{host}:{target.port}"


# ------------------------------------------------------------------ relay
class _Relay:
    def __init__(self, ctx: Any, caller: str, connection_id: str, grant_id: str | None,
                 handle_policy_version: int | None, method: Any, path: Any, headers: Any, body: Any,
                 request_id: Any) -> None:
        self.ctx = ctx
        self.caller = caller
        self.connection_id = connection_id
        self.grant_id = grant_id
        self.handle_policy_version = handle_policy_version
        self.raw_method = method
        self.raw_path = path
        self.raw_headers = headers
        self.raw_body = body
        self.raw_request_id = request_id
        # filled while running
        self.method = "?"
        self.path = ""
        self.target = ""
        self.headers: dict[str, str] = {}
        self.body = b""
        self.request_id: str | None = None
        self.connection: Connection | None = None
        self.grant: Grant | None = None
        self.origin: str | None = None
        self.ledger = RequestLedger(ctx)
        self.claimed = False
        self.transmitted = False

    # audit --------------------------------------------------------------
    def _audit(self, result: str, reason: str | None, status: int | None = None,
               extra: dict[str, Any] | None = None) -> None:
        fields: dict[str, Any] = {"path": strip_query(self.path) if self.path else None, "status": status}
        if self.grant is not None:
            fields["grant"] = self.grant.id
        if extra:
            fields.update(extra)
        self.ctx.audit.record(
            "http_relay", caller=self.caller, connection=self.connection_id, target=self.origin,
            action=self.method, result=result, reason=reason,
            policy_version=self.connection.policy_version if self.connection else None,
            request_id=self.request_id, extra=fields,
        )

    def _refuse(self, status: int, reason: str, *, result: str = "denied", error: str | None = None,
                extra_body: dict[str, Any] | None = None, audit_extra: dict[str, Any] | None = None,
                audit: bool = True) -> RelayResult:
        if self.claimed and self.request_id is not None:
            if self.transmitted:
                self.ledger.mark_uncertain(self.caller, self.request_id)
            else:
                self.ledger.release(self.caller, self.request_id)
            self.claimed = False
        if audit:
            try:
                self._audit(result, reason, extra=audit_extra)
            except AuditUnavailable:
                return _error_result(503, "audit_unavailable", "AuditUnavailable")
        return _error_result(status, reason, error, extra_body)

    # approvals ----------------------------------------------------------
    def _approval_subject(self, content_type: str | None) -> str:
        """What the approval digest binds besides caller, connection, method and body.

        The server-resolved origin and the connection's policy version are
        included, so an approval never survives a target or policy change
        (docs/security-design.md §5).  JSON keeps the rendering unambiguous.
        """
        assert self.connection is not None
        return json.dumps({"origin": self.origin, "target": self.target,
                           "policy_version": self.connection.policy_version, "content_type": content_type},
                          sort_keys=True, separators=(",", ":"))

    def _annotate_approval(self, digest: str, content_type: str | None) -> None:
        """Add the details the digest binds to the pending approval entry (admin-only state).

        Called under the state lock right after ``request_approval``.  Only
        missing keys are added; status fields owned by ``Policy`` are untouched.
        """
        from .policy import CONTROL

        assert self.connection is not None
        _, has_query, query = self.target.partition("?")
        try:
            text: str | None = self.body.decode("utf-8") if self.body else None
        except UnicodeDecodeError:
            text = None     # binary body: size and SHA-256 only
        details = {
            "origin": self.origin,
            "query": query if has_query else None,
            "content_type": content_type,
            "body_bytes": len(self.body),
            "body_sha256": hashlib.sha256(self.body).hexdigest(),
            "body_preview": text[:APPROVAL_PREVIEW_CHARS] if text is not None else None,
            "body_preview_truncated": text is not None and len(text) > APPROVAL_PREVIEW_CHARS,
            "policy_version": self.connection.policy_version,
        }
        state = self._approval_state()
        control = state.read_json(CONTROL, None)
        entry = control.get("approvals", {}).get(digest) if isinstance(control, dict) else None
        if not isinstance(entry, dict):
            return
        missing = {key: value for key, value in details.items() if key not in entry}
        if missing:
            entry.update(missing)
            state.write_json(CONTROL, control)

    def _approval_state(self) -> Any:
        """The state directory ``Policy`` keeps approvals in (its re-entrant lock must be shared)."""
        return getattr(self.ctx.policy, "state", None) or self.ctx.state

    # steps --------------------------------------------------------------
    def run(self) -> RelayResult:
        try:
            self.method = _normalize_method(self.raw_method)
            self.headers = _normalize_headers(self.raw_headers)
            self.request_id = _normalize_request_id(self.raw_request_id, self.headers)
            self.path, self.target = normalize_path(self.raw_path)
            self.body = _normalize_body(self.raw_body)
            forwarded = _forwardable_headers(self.headers)
        except _Invalid as exc:
            if isinstance(self.raw_path, str):
                self.path = self.raw_path
            return self._refuse(400, exc.reason, error="InvalidInput")

        decision = self.ctx.policy.evaluate(self.caller, self.connection_id,
                                            Action("http", self.method, self.path), self.grant_id)
        self.connection = decision.connection
        if self.connection is None:
            try:
                self.connection = self.ctx.policy.get_connection(self.connection_id)
            except (NotFound, InvalidInput, StateError):
                self.connection = None
        if self.connection is not None and self.connection.http_target is not None:
            self.origin = self.connection.http_target.origin
        if not decision.allowed:
            return self._refuse(403, decision.reason)
        assert self.connection is not None and decision.grant is not None
        self.grant = decision.grant
        if self.connection.kind != "http" or self.connection.http_target is None or self.connection.http_scope is None:
            return self._refuse(403, "action_kind_mismatch")
        if self.handle_policy_version is not None and self.handle_policy_version != self.connection.policy_version:
            return self._refuse(403, "grant_stale")
        if _self_referential_target(self.ctx, self.connection):
            return self._refuse(501, "self_referential_target", error="Unsupported")

        if self.request_id is not None:
            digest = RequestLedger.digest(self.connection.id, self.method, self.target, self.body)
            state, entry = self.ledger.claim(self.caller, self.request_id, digest, self.connection.id)
            if state == "replay":
                assert entry is not None
                replayed = RequestLedger.replay(entry)
                try:
                    self._audit("blocked" if replayed.reason else "ok", "replayed", status=replayed.status)
                except AuditUnavailable:
                    return _error_result(503, "audit_unavailable", "AuditUnavailable")
                return replayed
            if state == "in_flight":
                return self._refuse(409, "request_in_flight", error="Conflict")
            if state == "uncertain":
                return self._refuse(409, "outcome_uncertain", error="Conflict")
            if state == "reused":
                return self._refuse(409, "request_id_reused", error="Conflict")
            self.claimed = True

        # Resolve and check the destination before an approval, a use or the credential is spent on it
        # (docs/security-design.md §4).  The exchange dials exactly this address; it is never re-resolved.
        try:
            pinned_address = resolve_pinned_address(self.connection)
        except _UpstreamFailure as failure:
            return self._refuse_failure(failure)

        if self.method in self.connection.http_scope.confirm_methods:
            content_type = forwarded.get("content-type")
            digest = approval_digest(self.caller, self.connection.id, self.method,
                                     self._approval_subject(content_type), self.body)
            if not self.ctx.policy.consume_approval(digest, self.caller, self.connection.id):
                with self._approval_state().lock():
                    self.ctx.policy.request_approval(digest, self.caller, self.connection.id, self.method, self.path)
                    self._annotate_approval(digest, content_type)
                return self._refuse(428, "approval_required", extra_body={"approval_digest": digest},
                                    audit_extra={"digest": digest})

        # Mandatory audit record BEFORE the credential is fetched or used.
        try:
            self._audit("attempt", None)
        except AuditUnavailable:
            return self._refuse(503, "audit_unavailable", error="AuditUnavailable", audit=False)

        try:
            self.grant = self.ctx.policy.consume(self.grant.id)
        except PolicyDenied as exc:
            return self._refuse(403, exc.reason)

        try:
            secret = bytes(self.ctx.vault.secret_for_trusted_use(self.connection.secret_id, self.connection.secret_version))
        except (NotFound, StateError, InvalidInput):
            return self._refuse(503, "credential_unavailable", result="error", error="StateError")
        try:
            auth_name, auth_value = _auth_header(self.connection, secret)
        except _Invalid as exc:
            return self._refuse(501, exc.reason, error="Unsupported")
        basic_username = self.connection.http_auth.basic_username if self.connection.http_auth else None
        patterns = credential_patterns(secret, basic_username if self.connection.http_auth
                                       and self.connection.http_auth.mode == "basic" else None)
        del secret

        upstream_headers = dict(forwarded)
        upstream_headers["Host"] = _host_header(self.connection)
        upstream_headers["Accept-Encoding"] = "identity"
        upstream_headers["Connection"] = "close"
        upstream_headers["Via"] = RELAY_VIA
        upstream_headers[auth_name] = auth_value
        del auth_value

        try:
            response = self._exchange(upstream_headers, pinned_address)
        except _UpstreamFailure as failure:
            if failure.known_outcome:
                result = _error_result(502, failure.reason)
                self._finish(result, failure.result, failure.reason, upstream_status=failure.upstream_status)
                return result
            return self._refuse_failure(failure)
        finally:
            upstream_headers.clear()

        result = self._filter_response(response, patterns)
        outcome = "blocked" if result.reason else "ok"
        self._finish(result, outcome, result.reason, upstream_status=response.status)
        return result

    def _refuse_failure(self, failure: "_UpstreamFailure") -> RelayResult:
        """Refusal for an exchange failure whose upstream outcome is unknown (nothing relayable came back)."""
        if failure.reason == "self_referential_target":
            return self._refuse(501, failure.reason, result=failure.result, error="Unsupported")
        if failure.reason in ("target_address_not_allowed", "metadata_address_not_allowed"):
            return self._refuse(403, failure.reason, result=failure.result, error="PolicyDenied")
        return self._refuse(502, failure.reason, result=failure.result)

    def _finish(self, result: RelayResult, outcome: str, reason: str | None,
                upstream_status: int | None = None) -> None:
        if self.claimed and self.request_id is not None:
            self.ledger.complete(self.caller, self.request_id, result)
            self.claimed = False
        try:
            self._audit(outcome, reason, status=upstream_status if upstream_status is not None else result.status)
        except AuditUnavailable:
            # The outcome is persisted in the ledger (when a request id was
            # given); the response itself is withheld because the mandatory
            # record could not be written.
            result.status = 503
            result.headers = [("Content-Type", "application/json")]
            result.body = json.dumps({"error": "AuditUnavailable", "reason": "audit_unavailable"}).encode()
            result.reason = "audit_unavailable"

    def _exchange(self, upstream_headers: dict[str, str], pinned_address: str) -> _UpstreamResponse:
        assert self.connection is not None
        timeout = float(self.ctx.config.upstream_timeout)
        limit = int(self.ctx.config.max_response_bytes)
        conn = _open_connection(self.connection, timeout, pinned_address)
        try:
            try:
                conn.connect()
            except ssl.SSLError as exc:
                raise _UpstreamFailure("upstream_tls_failed", "error", False) from exc
            except (socket.timeout, TimeoutError) as exc:
                raise _UpstreamFailure("upstream_timeout", "error", False) from exc
            except OSError as exc:
                raise _UpstreamFailure("upstream_unreachable", "error", False) from exc
            if _peer_is_local_listener(conn.sock):
                # The resolved peer is this ZeroPW server (hostname alias, own
                # interface address): nothing has been sent yet.
                raise _UpstreamFailure("self_referential_target", "denied", False)
            # From here on the request may have reached the upstream.
            self.transmitted = True
            try:
                conn.request(self.method, self.target, body=self.body if self.body else None, headers=upstream_headers)
                resp = conn.getresponse()
                status = int(resp.status)
                raw_headers = [(str(k), str(v)) for k, v in resp.getheaders()]
                if status in REDIRECT_STATUSES:
                    raise _UpstreamFailure("redirect_not_followed", "blocked", True, status)
                encoding = (resp.getheader("Content-Encoding") or "identity").strip().lower()
                if encoding not in ("", "identity"):
                    raise _UpstreamFailure("response_encoding_unsupported", "blocked", True, status)
                chunks: list[bytes] = []
                total = 0
                while True:
                    piece = resp.read(min(READ_CHUNK, limit + 1 - total))
                    if not piece:
                        break
                    chunks.append(piece)
                    total += len(piece)
                    if total > limit:
                        raise _UpstreamFailure("response_too_large", "blocked", True, status)
                return _UpstreamResponse(status, raw_headers, b"".join(chunks))
            except _UpstreamFailure:
                raise
            except ssl.SSLError as exc:
                raise _UpstreamFailure("upstream_tls_failed", "error", False) from exc
            except (socket.timeout, TimeoutError) as exc:
                raise _UpstreamFailure("upstream_timeout", "error", False) from exc
            except http.client.HTTPException as exc:
                raise _UpstreamFailure("upstream_protocol_error", "error", False) from exc
            except (OSError, ValueError) as exc:
                raise _UpstreamFailure("upstream_connection_lost", "error", False) from exc
        finally:
            try:
                conn.close()
            except Exception:
                pass

    @staticmethod
    def _filter_response(response: _UpstreamResponse, patterns: tuple[bytes, ...]) -> RelayResult:
        header_blob = b"\r\n".join(
            f"{name}: {value}".encode("latin-1", "replace") for name, value in response.headers
        )
        if _contains_credential(header_blob, patterns) or _contains_credential(response.body, patterns):
            return _error_result(502, "credential_reflection_blocked")
        headers: list[tuple[str, str]] = []
        for name, value in response.headers:
            lowered = name.lower()
            if lowered not in RESPONSE_HEADER_ALLOWLIST:
                continue
            if not _HEADER_VALUE_RE.match(value):
                continue
            headers.append((name, value))
        return RelayResult(response.status, headers, response.body, None)


def _refuse_unauthenticated(ctx: Any, reason: str, method: Any, path: Any, request_id: Any) -> RelayResult:
    action = method.upper() if isinstance(method, str) and _METHOD_RE.match(method.upper()) else None
    safe_path = strip_query(path) if isinstance(path, str) else None
    safe_request_id = request_id if isinstance(request_id, str) and _REQUEST_ID_RE.match(request_id) else None
    try:
        ctx.audit.record("http_relay", caller=None, connection=None, target=None, action=action,
                         result="denied", reason=reason, request_id=safe_request_id, extra={"path": safe_path})
    except AuditUnavailable:
        return _error_result(503, "audit_unavailable", "AuditUnavailable")
    return _error_result(401, reason, "AuthFailed")


def relay(ctx: Any, handle_token: str, method: str, path: str, headers: Mapping[str, str], body: bytes,
          request_id: str | None = None) -> RelayResult:
    """Relay on behalf of a handle (URL prefix or ``X-ZeroPW-Handle`` header)."""
    try:
        handle = ctx.handles.verify(handle_token, now=ctx.clock())
    except AuthFailed as exc:
        return _refuse_unauthenticated(ctx, exc.reason, method, path, request_id)
    return _Relay(ctx, handle.caller, handle.connection, handle.grant, handle.policy_version,
                  method, path, headers, body, request_id).run()


def relay_for_caller(ctx: Any, caller: str, connection_id: str, method: str, path: str,
                     headers: Mapping[str, str], body: bytes, request_id: str | None = None) -> RelayResult:
    """Relay for an authenticated tools caller (``tools.request``): no handle, any usable grant."""
    return _Relay(ctx, caller, connection_id, None, None, method, path, headers, body, request_id).run()
