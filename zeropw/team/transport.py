"""Team sync transport: ``Session``/``Transport`` protocols, an in-process test
transport, and a stdlib-socket TCP reference transport, carrying the
SIGMA-style mutual handshake of docs/team-sync.md sections 6.1-6.2.

Interface (docs/team-sync.md section 6.1)
------------------------------------------
::

    class Transport(Protocol):
        def listen(self, address: str, on_session: Callable[[Session], None]) -> None: ...
        def dial(self, address: str, env_id: str) -> Session: ...

    class Session(Protocol):
        peer: DeviceRecord
        env_id: str
        def send(self, message: dict) -> None: ...
        def recv(self, timeout: float) -> dict | None: ...
        def close(self) -> None: ...

Resolved ambiguity: the design doc sketches ``dial(address) -> Session`` with
no environment argument, and a bare ``Session.peer``.  A real node runs a
*single* team listener for every shared environment it has (``serve
--team-listen`` takes one address), so one transport instance is shared
across environments and the wire handshake -- which does carry ``env_id`` in
its very first message -- is how a session gets attached to the right
environment's sync state.  ``Session`` therefore also carries ``env_id``, and
``dial`` takes one, so ``zeropw/team/sync.py`` can route an accepted inbound
session (whose environment is only known once the handshake decodes msg1) to
the right per-environment state, and so a dial can name which environment it
is opening a session for.  ``membership`` and ``invite_check`` below are
likewise keyed by ``env_id`` rather than being bound once per transport.

Handshake (docs/team-sync.md section 6.2)
------------------------------------------
Three plaintext (canonical JSON) messages, then every later message on that
session is a length-prefixed ChaCha20-Poly1305 frame:

1. initiator -> responder: protocol version, env id, ephemeral X25519 public
   key ``Ea``, the initiator's ``DeviceRecord``, a 32-byte nonce.
2. responder -> initiator: ephemeral ``Eb``, the responder's ``DeviceRecord``,
   an Ed25519 signature over ``HANDSHAKE_RESPONDER_CONTEXT + transcript``
   (transcript = msg1's raw bytes ‖ ``Eb`` ‖ the responder record's canonical
   JSON).  The responder only replies if the initiator's fingerprint is a
   currently active member of ``env_id`` (``membership``) or an invite might
   apply (``invite_check`` configured); any other reason to refuse closes the
   socket with **no bytes sent back**.
3. initiator -> responder: an Ed25519 signature over
   ``HANDSHAKE_INITIATOR_CONTEXT + transcript`` (the same transcript, a
   disjoint signature under a different fixed prefix -- see
   ``HANDSHAKE_RESPONDER_CONTEXT``/``HANDSHAKE_INITIATOR_CONTEXT`` below), and
   (only when joining) an invite proof.  The responder verifies this
   signature and, if the initiator is not yet a member, the invite proof
   before deriving session keys; the initiator independently verifies the
   responder is an active member before it ever sends msg3.  The role
   prefixes mean a responder's signature can never be mistaken for (or
   replayed as) an initiator's over the same transcript bytes, or vice versa.

Session keys are HKDF-SHA256(``x25519.shared_secret(ea, Eb)``, salt =
SHA-256(transcript), info = ``zeropw-team-session-v1`` + direction), one key
per direction, so replaying an old msg2/msg3 pair against a new handshake
attempt fails signature verification (the transcript embeds both fresh
ephemeral keys) and cannot be decrypted with a new session's keys either.
``x25519.shared_secret`` already rejects a low-order (contributory-failing)
ephemeral point by raising ``InvalidInput``; this module treats that exactly
like any other handshake failure -- silent close, no session, no DEK wrap
ever attempted with it.

The ``invite_check`` hook's exact call contract is left to stage 3 (which
owns the invite secret): here it is only ever ``None``, so no stage-2 code
path exercises it.  It is typed as
``Callable[[DeviceRecord, bytes, bytes], bool]`` (initiator record, transcript
hash, the raw ``invite_proof`` bytes from msg3) -- extended from the design
doc's illustrative two-argument sketch because verifying an HMAC needs both
the proof bytes and the exact transcript it must be computed over.

Every failure closes the connection without writing anything the peer can
read from it, and reports only a fixed reason code (and, when the peer's own
signed record was well-formed enough to compute a fingerprint, that
fingerprint) through the optional ``on_handshake_failed`` callback --
``zeropw/team/sync.py`` wires this to ``audit.record("team_handshake_failed", ...)``.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import queue
import secrets
import socket
import threading
import time
from typing import Any, Callable, Protocol

from ..crypto import chacha20poly1305 as aead
from ..crypto import ed25519, x25519
from ..errors import InvalidInput
from .commit import valid_env_id
from .envelope import hkdf
from .identity import DeviceKey, DeviceRecord

PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 4 * 1024 * 1024          # plaintext cap per frame (section 6.1)
_WIRE_FRAME_LIMIT = MAX_FRAME_BYTES + aead.TAG_SIZE + 4096   # ciphertext + slack for handshake JSON

# Test-only wire recorder (docs/team-sync.md section 13 stage 4's leak sweep needs raw bytes that
# actually crossed a real TCP socket, handshake plaintext included, not just the message dicts
# ``Session.send``/``recv`` see).  Off by default; a test sets this env var to a file path before
# starting a ``TcpTransport``, and every byte string ``_SocketChannel`` puts on or takes off the
# wire is appended there as one hex-encoded line (never raw bytes, so the file stays a clean
# newline-delimited text format for ``tests/leakcheck.py`` to scan).  Never wired into anything a
# production ``serve`` process sets on its own.
_WIRE_CAPTURE_ENV = "ZEROPW_TEAM_WIRE_CAPTURE"


def _capture_wire(direction: str, data: bytes) -> None:
    path = os.environ.get(_WIRE_CAPTURE_ENV)
    if not path:
        return
    try:
        with open(path, "a", encoding="ascii") as stream:
            stream.write(f"{direction} {data.hex()}\n")
    except OSError:
        pass  # a test-only recorder must never take a real session down
_LENGTH_BYTES = 4
SOCKET_OP_TIMEOUT_SECONDS = 15.0
HANDSHAKE_TIMEOUT_SECONDS = 15.0
DEFAULT_MAX_CONNECTIONS = 64
SESSION_INFO = b"zeropw-team-session-v1"
_DIR_I2R = b"i2r"
_DIR_R2I = b"r2i"
_NONCE_TAG_I2R = b"I2R\x00"
_NONCE_TAG_R2I = b"R2I\x00"

MembershipCheck = Callable[[str, str], "DeviceRecord | None"]
# Extended (stage 3) from the illustrative 3-argument sketch: the responder needs to know WHICH
# environment's invites to consult (one transport/TeamSync serves every shared environment a node
# has, section 6.1), so ``env_id`` is the first argument -- initiator record, transcript hash, and
# the raw ``invite_proof`` bytes from msg3 follow, unchanged.
InviteCheck = Callable[[str, DeviceRecord, bytes, bytes], bool]
HandshakeFailedHook = Callable[[str, "str | None"], None]


class SessionClosed(Exception):
    """The peer connection is gone, timed out irrecoverably, or a frame failed to authenticate."""


class HandshakeFailed(Exception):
    def __init__(self, reason: str, fingerprint: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.fingerprint = fingerprint


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: Any) -> bytes:
    if not isinstance(text, str):
        raise HandshakeFailed("handshake_malformed")
    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:
        raise HandshakeFailed("handshake_malformed") from exc


def _canon(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse_device_record(data: Any) -> DeviceRecord:
    try:
        record = DeviceRecord.from_dict(data)
    except InvalidInput as exc:
        raise HandshakeFailed("device_record_malformed") from exc
    if not record.verify():
        raise HandshakeFailed("device_record_invalid")
    return record


# ------------------------------------------------------------------ Session
class Session(Protocol):
    peer: DeviceRecord
    env_id: str

    def send(self, message: dict) -> None: ...

    def recv(self, timeout: float) -> dict | None: ...

    def close(self) -> None: ...


class _EncryptedSession:
    """A handshake-derived ``Session``: framed, ChaCha20-Poly1305-encrypted messages."""

    def __init__(self, channel: Any, peer: DeviceRecord, env_id: str, send_key: bytes, recv_key: bytes,
                tag_out: bytes, tag_in: bytes) -> None:
        self.peer = peer
        self.env_id = env_id
        self._channel = channel
        self._send_key = send_key
        self._recv_key = recv_key
        self._tag_out = tag_out
        self._tag_in = tag_in
        self._send_counter = 0
        self._recv_counter = 0
        self._lock = threading.Lock()
        self._closed = False
        self.created_at = time.monotonic()

    @property
    def closed(self) -> bool:
        return self._closed

    def send(self, message: dict) -> None:
        if not isinstance(message, dict):
            raise InvalidInput("team_message_malformed")
        payload = _canon(message)
        if len(payload) > MAX_FRAME_BYTES:
            raise InvalidInput("team_frame_too_large")
        with self._lock:
            if self._closed:
                raise SessionClosed("session_closed")
            nonce = self._tag_out + self._send_counter.to_bytes(8, "big")
            self._send_counter += 1
            ciphertext = aead.encrypt(self._send_key, nonce, payload, b"")
            try:
                self._channel.send(ciphertext)
            except SessionClosed:
                self._closed = True
                raise

    def recv(self, timeout: float) -> dict | None:
        with self._lock:
            if self._closed:
                raise SessionClosed("session_closed")
        try:
            raw = self._channel.recv(timeout)
        except SessionClosed:
            self.close()
            raise
        if raw is None:
            return None
        nonce = self._tag_in + self._recv_counter.to_bytes(8, "big")
        try:
            plaintext = aead.decrypt(self._recv_key, nonce, raw, b"")
        except aead.AuthenticationError:
            self.close()
            raise SessionClosed("frame_authentication_failed") from None
        self._recv_counter += 1
        try:
            message = json.loads(plaintext.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self.close()
            raise SessionClosed("frame_malformed") from None
        if not isinstance(message, dict):
            self.close()
            raise SessionClosed("frame_malformed")
        return message

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._channel.close()


# --------------------------------------------------------------- byte channels
_CLOSE_SENTINEL = object()


class _QueueChannel:
    """An in-process byte channel: two queues, one per direction."""

    def __init__(self, inbox: "queue.Queue[Any]", outbox: "queue.Queue[Any]") -> None:
        self._inbox = inbox
        self._outbox = outbox
        self._closed = False

    def send(self, data: bytes) -> None:
        if len(data) > _WIRE_FRAME_LIMIT:
            raise InvalidInput("team_frame_too_large")
        if self._closed:
            raise SessionClosed("channel_closed")
        self._outbox.put(data)

    def recv(self, timeout: float) -> bytes | None:
        try:
            item = self._inbox.get(timeout=max(0.0, timeout))
        except queue.Empty:
            return None
        if item is _CLOSE_SENTINEL:
            self._closed = True
            raise SessionClosed("peer_closed")
        if len(item) > _WIRE_FRAME_LIMIT:
            self.close()
            raise SessionClosed("frame_too_large")
        return item

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                self._outbox.put_nowait(_CLOSE_SENTINEL)
            except Exception:
                pass


class _Timeout(Exception):
    pass


class _SocketChannel:
    """A TCP byte channel: 4-byte big-endian length prefix + payload, one blocking op at a time."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._closed = False
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

    def send(self, data: bytes) -> None:
        if len(data) > _WIRE_FRAME_LIMIT:
            raise InvalidInput("team_frame_too_large")
        if self._closed:
            raise SessionClosed("channel_closed")
        _capture_wire("send", data)
        header = len(data).to_bytes(_LENGTH_BYTES, "big")
        # settimeout() itself (not just sendall()) can raise a raw OSError (EBADF) if a concurrent
        # receiver thread's close() (e.g. it just discovered the peer hung up) wins a race against
        # this call -- section 6.1's "one receive thread per session" means exactly this pair can
        # run at once, so both socket operations, not just sendall(), must fold into SessionClosed.
        try:
            self._sock.settimeout(SOCKET_OP_TIMEOUT_SECONDS)
            self._sock.sendall(header + data)
        except OSError as exc:
            self.close()
            raise SessionClosed("send_failed") from exc

    def _recv_exact(self, n: int, deadline: float) -> bytes:
        buf = b""
        while len(buf) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _Timeout()
            try:
                self._sock.settimeout(min(remaining, SOCKET_OP_TIMEOUT_SECONDS))
                chunk = self._sock.recv(n - len(buf))
            except socket.timeout:
                raise _Timeout()
            except OSError as exc:
                self.close()
                raise SessionClosed("recv_failed") from exc
            if not chunk:
                self.close()
                raise SessionClosed("peer_closed")
            buf += chunk
        return buf

    def recv(self, timeout: float) -> bytes | None:
        if self._closed:
            raise SessionClosed("channel_closed")
        deadline = time.monotonic() + max(0.0, timeout)
        try:
            header = self._recv_exact(_LENGTH_BYTES, deadline)
        except _Timeout:
            return None
        length = int.from_bytes(header, "big")
        if length > _WIRE_FRAME_LIMIT:
            self.close()
            raise SessionClosed("frame_too_large")
        try:
            payload = self._recv_exact(length, deadline + SOCKET_OP_TIMEOUT_SECONDS)
        except _Timeout:
            self.close()
            raise SessionClosed("frame_incomplete")
        _capture_wire("recv", payload)
        return payload

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass


# ------------------------------------------------------------------ handshake
# Role domain separation for msg2/msg3 (hygiene fix, phase 2 review item G2): both signatures
# would otherwise be computed over byte-identical transcript bytes, so a responder's signature
# could in principle be replayed as if it were an initiator's (and vice versa) whenever a single
# device key acts as both, or against a peer that only checks "is this transcript signed by the
# claimed fingerprint" without also checking which role produced it.  Prefixing each with a fixed,
# role-specific context string before signing/verifying makes the two signature spaces disjoint.
HANDSHAKE_RESPONDER_CONTEXT = b"zeropw-team-hs-responder-v1"
HANDSHAKE_INITIATOR_CONTEXT = b"zeropw-team-hs-initiator-v1"


def _transcript(msg1_raw: bytes, eb_pub: bytes, responder_record: DeviceRecord) -> bytes:
    return msg1_raw + eb_pub + _canon(responder_record.to_dict())


def _recv_plain(channel: Any, deadline: float) -> tuple[bytes, dict]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise HandshakeFailed("handshake_timeout")
    try:
        raw = channel.recv(remaining)
    except SessionClosed as exc:
        raise HandshakeFailed("handshake_channel_closed") from exc
    if raw is None:
        raise HandshakeFailed("handshake_timeout")
    try:
        message = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise HandshakeFailed("handshake_malformed") from exc
    if not isinstance(message, dict):
        raise HandshakeFailed("handshake_malformed")
    return raw, message


def _session_keys(shared: bytes, transcript_hash: bytes) -> tuple[bytes, bytes]:
    key_i2r = hkdf(transcript_hash, shared, SESSION_INFO + _DIR_I2R, aead.KEY_SIZE)
    key_r2i = hkdf(transcript_hash, shared, SESSION_INFO + _DIR_R2I, aead.KEY_SIZE)
    return key_i2r, key_r2i


def _respond(channel: Any, device: DeviceKey, membership: MembershipCheck,
            invite_check: InviteCheck | None) -> _EncryptedSession:
    """Run the responder side of the handshake to completion, or raise ``HandshakeFailed``."""
    deadline = time.monotonic() + HANDSHAKE_TIMEOUT_SECONDS
    msg1_raw, msg1 = _recv_plain(channel, deadline)
    if msg1.get("version") != PROTOCOL_VERSION:
        raise HandshakeFailed("version_mismatch")
    env_id = msg1.get("env_id")
    if not valid_env_id(env_id):
        raise HandshakeFailed("invalid_env_id")
    ea_pub = _b64d(msg1.get("ea"))
    nonce = _b64d(msg1.get("nonce"))
    if len(ea_pub) != x25519.POINT_SIZE or len(nonce) != 32:
        raise HandshakeFailed("handshake_malformed")
    initiator_record = _parse_device_record(msg1.get("device"))
    initiator_fp = initiator_record.fingerprint
    member = membership(env_id, initiator_fp)
    joining = member is None and invite_check is not None
    if member is None and not joining:
        raise HandshakeFailed("not_member", initiator_fp)
    eb_private = x25519.generate_private()
    eb_pub = x25519.public_key(eb_private)
    try:
        shared = x25519.shared_secret(eb_private, ea_pub)
    except InvalidInput as exc:
        raise HandshakeFailed("low_order_point", initiator_fp) from exc
    responder_record = device.record
    transcript = _transcript(msg1_raw, eb_pub, responder_record)
    sig2 = device.sign(HANDSHAKE_RESPONDER_CONTEXT + transcript)
    channel.send(_canon({"eb": _b64e(eb_pub), "device": responder_record.to_dict(), "sig": _b64e(sig2)}))
    _msg3_raw, msg3 = _recv_plain(channel, deadline)
    sig3 = _b64d(msg3.get("sig"))
    if not ed25519.verify(initiator_record.sign_pub, HANDSHAKE_INITIATOR_CONTEXT + transcript, sig3):
        raise HandshakeFailed("signature_invalid", initiator_fp)
    transcript_hash = hashlib.sha256(transcript).digest()
    if member is None:
        proof_raw = msg3.get("invite_proof")
        proof = _b64d(proof_raw) if proof_raw is not None else b""
        if invite_check is None or not invite_check(env_id, initiator_record, transcript_hash, proof):
            raise HandshakeFailed("invite_invalid", initiator_fp)
    key_i2r, key_r2i = _session_keys(shared, transcript_hash)
    return _EncryptedSession(channel, initiator_record, env_id, send_key=key_r2i, recv_key=key_i2r,
                             tag_out=_NONCE_TAG_R2I, tag_in=_NONCE_TAG_I2R)


def _initiate(channel: Any, device: DeviceKey, env_id: str, membership: MembershipCheck,
             invite_proof: "bytes | Callable[[bytes], bytes] | None" = None) -> _EncryptedSession:
    """Run the initiator side of the handshake to completion, or raise ``HandshakeFailed``.

    ``invite_proof`` is either the raw HMAC bytes (stage-2 callers that never
    join, or already know the transcript for some other reason) or -- as
    stage 3's ``zeropw.team.membership.join`` needs -- a callable taking the
    transcript hash and returning the proof.  The transcript (and therefore
    its hash) only exists once this function has received msg2, so a joining
    caller cannot compute ``HMAC(invite_secret, transcript_hash)`` ahead of
    time; the callable defers that computation to here, after ``transcript``
    is known but before msg3 is sent.
    """
    deadline = time.monotonic() + HANDSHAKE_TIMEOUT_SECONDS
    ea_private = x25519.generate_private()
    ea_pub = x25519.public_key(ea_private)
    nonce = secrets.token_bytes(32)
    msg1 = {"version": PROTOCOL_VERSION, "env_id": env_id, "ea": _b64e(ea_pub),
            "device": device.record.to_dict(), "nonce": _b64e(nonce)}
    msg1_raw = _canon(msg1)
    try:
        channel.send(msg1_raw)
    except SessionClosed as exc:
        raise HandshakeFailed("handshake_channel_closed") from exc
    _msg2_raw, msg2 = _recv_plain(channel, deadline)
    responder_record = _parse_device_record(msg2.get("device"))
    eb_pub = _b64d(msg2.get("eb"))
    if len(eb_pub) != x25519.POINT_SIZE:
        raise HandshakeFailed("handshake_malformed")
    transcript = _transcript(msg1_raw, eb_pub, responder_record)
    sig2 = _b64d(msg2.get("sig"))
    if not ed25519.verify(responder_record.sign_pub, HANDSHAKE_RESPONDER_CONTEXT + transcript, sig2):
        raise HandshakeFailed("signature_invalid", responder_record.fingerprint)
    joining = invite_proof is not None
    if not joining and membership(env_id, responder_record.fingerprint) is None:
        raise HandshakeFailed("responder_not_member", responder_record.fingerprint)
    try:
        shared = x25519.shared_secret(ea_private, eb_pub)
    except InvalidInput as exc:
        raise HandshakeFailed("low_order_point", responder_record.fingerprint) from exc
    transcript_hash = hashlib.sha256(transcript).digest()
    sig3 = device.sign(HANDSHAKE_INITIATOR_CONTEXT + transcript)
    msg3: dict[str, Any] = {"sig": _b64e(sig3)}
    if invite_proof is not None:
        proof = invite_proof(transcript_hash) if callable(invite_proof) else invite_proof
        msg3["invite_proof"] = _b64e(proof)
    try:
        channel.send(_canon(msg3))
    except SessionClosed as exc:
        raise HandshakeFailed("handshake_channel_closed") from exc
    key_i2r, key_r2i = _session_keys(shared, transcript_hash)
    return _EncryptedSession(channel, responder_record, env_id, send_key=key_i2r, recv_key=key_r2i,
                             tag_out=_NONCE_TAG_I2R, tag_in=_NONCE_TAG_R2I)


# ------------------------------------------------------------- InProcessTransport
class InProcessTransport:
    """Test transport: a process-wide registry of listeners keyed by an address string.

    ``dial`` still runs the real handshake (over a pair of queues standing in
    for a byte stream) so tests exercise the same mutual-authentication and
    framing code the TCP transport uses.
    """

    _listeners: dict[str, tuple["InProcessTransport", Callable[[Session], None]]] = {}
    _registry_lock = threading.Lock()

    def __init__(self, device: DeviceKey, membership: MembershipCheck | None = None, *,
                invite_check: InviteCheck | None = None,
                on_handshake_failed: HandshakeFailedHook | None = None) -> None:
        self.device = device
        self.membership = membership or (lambda env_id, fp: None)
        self.invite_check = invite_check
        self.on_handshake_failed = on_handshake_failed
        self._own_addresses: set[str] = set()

    def listen(self, address: str, on_session: Callable[[Session], None]) -> None:
        with InProcessTransport._registry_lock:
            if address in InProcessTransport._listeners:
                raise InvalidInput("team_address_in_use")
            InProcessTransport._listeners[address] = (self, on_session)
        self._own_addresses.add(address)

    def unlisten(self, address: str | None = None) -> None:
        with InProcessTransport._registry_lock:
            targets = [address] if address is not None else list(self._own_addresses)
            for target in targets:
                InProcessTransport._listeners.pop(target, None)
                self._own_addresses.discard(target)

    def dial(self, address: str, env_id: str,
            invite_proof: "bytes | Callable[[bytes], bytes] | None" = None) -> Session:
        with InProcessTransport._registry_lock:
            entry = InProcessTransport._listeners.get(address)
        if entry is None:
            raise SessionClosed("team_address_unreachable")
        responder_transport, on_session = entry
        to_responder: "queue.Queue[Any]" = queue.Queue()
        to_initiator: "queue.Queue[Any]" = queue.Queue()
        initiator_channel = _QueueChannel(inbox=to_initiator, outbox=to_responder)
        responder_channel = _QueueChannel(inbox=to_responder, outbox=to_initiator)

        def run_responder() -> None:
            try:
                session = _respond(responder_channel, responder_transport.device, responder_transport.membership,
                                   responder_transport.invite_check)
            except HandshakeFailed as exc:
                responder_channel.close()
                hook = responder_transport.on_handshake_failed
                if hook is not None:
                    hook(exc.reason, exc.fingerprint)
                return
            on_session(session)

        threading.Thread(target=run_responder, daemon=True, name="team-inprocess-responder").start()
        try:
            return _initiate(initiator_channel, self.device, env_id, self.membership, invite_proof)
        except HandshakeFailed as exc:
            initiator_channel.close()
            if self.on_handshake_failed is not None:
                self.on_handshake_failed(exc.reason, exc.fingerprint)
            raise SessionClosed(exc.reason) from exc


# ------------------------------------------------------------------- TcpTransport
class TcpTransport:
    """Reference transport: stdlib ``socket`` TCP with the section 6.1/6.2 handshake and framing.

    The team listener is a separate socket from the tools/relay listener and
    is only ever bound to the address given to ``listen`` -- never implicitly
    -- so it may sit on a LAN or VPN interface while the tools/relay listener
    stays loopback-only (``zeropw/admin_cli.py``'s ``_require_loopback``
    applies to that listener alone).
    """

    def __init__(self, device: DeviceKey, membership: MembershipCheck | None = None, *,
                invite_check: InviteCheck | None = None,
                on_handshake_failed: HandshakeFailedHook | None = None,
                max_connections: int = DEFAULT_MAX_CONNECTIONS) -> None:
        self.device = device
        self.membership = membership or (lambda env_id, fp: None)
        self.invite_check = invite_check
        self.on_handshake_failed = on_handshake_failed
        self.max_connections = max_connections
        self._sock: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._connection_semaphore = threading.Semaphore(max_connections)

    @staticmethod
    def _parse_address(address: str) -> tuple[str, int]:
        raw = address.strip()
        host, sep, port_text = raw.rpartition(":")
        if not sep or not port_text.isdigit():
            raise InvalidInput("team_invalid_listen_address")
        host = host.strip("[]") or "0.0.0.0"
        port = int(port_text)
        if not 0 <= port <= 65535:
            raise InvalidInput("team_invalid_listen_address")
        return host, port

    def listen(self, address: str, on_session: Callable[[Session], None]) -> None:
        if self._sock is not None:
            raise InvalidInput("team_already_listening")
        host, port = self._parse_address(address)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(128)
        sock.settimeout(0.5)
        self._sock = sock

        def accept_loop() -> None:
            while not self._stop.is_set():
                try:
                    client, _addr = sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                if not self._connection_semaphore.acquire(blocking=False):
                    try:
                        client.close()
                    except OSError:
                        pass
                    continue
                threading.Thread(target=self._handle_client, args=(client, on_session),
                                 daemon=True, name="team-tcp-responder").start()

        self._accept_thread = threading.Thread(target=accept_loop, daemon=True, name="team-tcp-accept")
        self._accept_thread.start()

    def _handle_client(self, client: socket.socket, on_session: Callable[[Session], None]) -> None:
        # The concurrency cap bounds live connections, not just in-flight handshakes: the permit
        # acquired in ``listen()`` is only released once this session actually closes (wrapping
        # ``close`` here), whether that is us on a handshake failure or the session's own owner
        # later on.
        channel = _SocketChannel(client)
        released = threading.Event()

        def release_once() -> None:
            if not released.is_set():
                released.set()
                self._connection_semaphore.release()

        try:
            session = _respond(channel, self.device, self.membership, self.invite_check)
        except HandshakeFailed as exc:
            channel.close()
            release_once()
            if self.on_handshake_failed is not None:
                self.on_handshake_failed(exc.reason, exc.fingerprint)
            return
        original_close = session.close

        def close_and_release() -> None:
            original_close()
            release_once()

        session.close = close_and_release  # type: ignore[method-assign]
        on_session(session)

    def dial(self, address: str, env_id: str,
            invite_proof: "bytes | Callable[[bytes], bytes] | None" = None) -> Session:
        host, port = self._parse_address(address)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_OP_TIMEOUT_SECONDS)
        try:
            sock.connect((host, port))
        except OSError as exc:
            try:
                sock.close()
            except OSError:
                pass
            raise SessionClosed("team_dial_failed") from exc
        channel = _SocketChannel(sock)
        try:
            return _initiate(channel, self.device, env_id, self.membership, invite_proof)
        except HandshakeFailed as exc:
            channel.close()
            if self.on_handshake_failed is not None:
                self.on_handshake_failed(exc.reason, exc.fingerprint)
            raise SessionClosed(exc.reason) from exc

    @property
    def bound_address(self) -> str | None:
        if self._sock is None:
            return None
        host, port = self._sock.getsockname()[:2]
        try:
            if ipaddress.ip_address(host).is_unspecified:
                host = "127.0.0.1"
        except ValueError:
            pass
        return f"{host}:{port}"

    def close(self) -> None:
        self._stop.set()
        sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        thread, self._accept_thread = self._accept_thread, None
        if thread is not None:
            thread.join(timeout=5)
