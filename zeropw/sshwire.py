"""SSH wire codec, OpenSSH Ed25519 key formats and SSH agent protocol messages.

This module is the only place in ZeroPW that knows how SSH bytes are laid
out.  It covers three things:

* the RFC 4251 wire primitives (``string``, ``uint32``, ``boolean``,
  ``mpint``) plus a strict :class:`Reader`;
* the OpenSSH public key line (``authorized_keys`` / ``.pub``), the
  ``ssh-ed25519`` key blob, and the unencrypted ``openssh-key-v1`` private key
  container (RFC 8709 key blobs, OpenSSH ``PROTOCOL.key``);
* the SSH agent protocol framing and the handful of messages the ZeroPW
  signer needs (draft-miller-ssh-agent, OpenSSH ``PROTOCOL.agent``),
  including the ``session-bind@openssh.com`` extension and the exact
  ``SSH_MSG_USERAUTH_REQUEST`` byte layout that an SSH client asks an agent to
  sign.

Security scope and limitations
------------------------------
* **Prototype quality.**  Nothing here is constant time, and Python ``bytes``
  cannot be zeroised, so seeds may linger in memory.  Equality on
  :class:`Ed25519PrivateKey` compares seeds with ordinary (non-constant-time)
  comparison.
* **Parsing is strict by design.**  Every parser consumes exactly its input:
  truncation, trailing bytes, wrong tags, non-canonical encodings and
  over-long frames raise :class:`WireError` (or its subclass
  :class:`UnsupportedKeyType`).  Nothing is silently ignored or padded.
  The one deliberate leniency is that purely informational key *comments*
  (private key files, identities answers) are decoded with U+FFFD
  replacement instead of refusing the key: OpenSSH writes them as raw
  bytes, so they need not be UTF-8.
* **No cryptography lives here.**  Signing, verification and public key
  derivation are delegated to :mod:`zeropw.crypto.ed25519`, imported lazily
  so this module can be loaded (and most of it tested) without it.  This
  module never inspects, logs or formats seed bytes; the private key
  ``repr`` shows only the public fingerprint and comment.
* **Ed25519 only, unencrypted only.**  RSA/ECDSA/DSA keys, FIDO ``sk-`` keys,
  certificates and passphrase-protected private keys are rejected with
  :class:`UnsupportedKeyType`; there is no fallback.
* **Purpose binding is decided elsewhere.**  :func:`parse_userauth_request`
  guarantees that a to-be-signed buffer has the *shape* of a public key
  authentication request (with nothing trailing), but whether the username,
  algorithm, key and session match the caller's grant is the signer's job.
* The agent framing helpers cap messages at :data:`MAX_AGENT_MESSAGE` and
  never allocate a buffer before validating the length prefix.  Transport
  errors (``OSError``) are propagated unchanged, only *clean* EOF at a
  message boundary is reported as ``None``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import importlib
import re
import secrets
import struct
from dataclasses import dataclass
from types import ModuleType
from typing import Any, Callable, Sequence

__all__ = [
    # errors
    "WireError",
    "UnsupportedKeyType",
    # wire primitives
    "encode_string",
    "encode_uint32",
    "encode_bool",
    "encode_mpint",
    "Reader",
    # keys
    "ED25519_KEY_TYPE",
    "SEED_SIZE",
    "PUBLIC_KEY_SIZE",
    "SIGNATURE_SIZE",
    "Ed25519PublicKey",
    "Ed25519PrivateKey",
    "AuthorizedKeyEntry",
    "parse_authorized_key",
    "parse_authorized_key_entry",
    "parse_public_key_blob",
    "parse_openssh_private_key",
    "generate_ed25519_private_key",
    "encode_ssh_signature",
    "parse_ssh_signature",
    # agent protocol
    "SSH_AGENT_FAILURE",
    "SSH_AGENT_SUCCESS",
    "SSH_AGENTC_REQUEST_IDENTITIES",
    "SSH_AGENT_IDENTITIES_ANSWER",
    "SSH_AGENTC_SIGN_REQUEST",
    "SSH_AGENT_SIGN_RESPONSE",
    "SSH_AGENTC_ADD_IDENTITY",
    "SSH_AGENTC_REMOVE_IDENTITY",
    "SSH_AGENTC_REMOVE_ALL_IDENTITIES",
    "SSH_AGENTC_ADD_SMARTCARD_KEY",
    "SSH_AGENTC_REMOVE_SMARTCARD_KEY",
    "SSH_AGENTC_LOCK",
    "SSH_AGENTC_UNLOCK",
    "SSH_AGENTC_ADD_ID_CONSTRAINED",
    "SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED",
    "SSH_AGENTC_EXTENSION",
    "SSH_AGENT_EXTENSION_FAILURE",
    "SESSION_BIND_EXTENSION",
    "EXTENSION_QUERY",
    "MAX_AGENT_MESSAGE",
    "read_agent_message",
    "write_agent_message",
    "frame_agent_message",
    "AgentConnection",
    "SignRequest",
    "parse_sign_request",
    "build_sign_request",
    "SessionBind",
    "parse_session_bind",
    "build_session_bind",
    "parse_extension",
    "build_extension_query",
    "build_extension_query_response",
    "parse_extension_query_response",
    "build_identities_answer",
    "parse_identities_answer",
    "build_sign_response",
    "parse_sign_response",
    "build_failure",
    "build_success",
    # userauth
    "SSH_MSG_USERAUTH_REQUEST",
    "SSH_CONNECTION_SERVICE",
    "USERAUTH_METHOD_PUBLICKEY",
    "USERAUTH_METHOD_PUBLICKEY_HOSTBOUND",
    "UserAuthRequest",
    "parse_userauth_request",
    "build_userauth_request",
]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class WireError(ValueError):
    """Malformed, truncated, non-canonical or over-long SSH wire data."""


class UnsupportedKeyType(WireError):
    """Well-formed input that uses a key type or key format ZeroPW does not support."""


# ---------------------------------------------------------------------------
# RFC 4251 wire primitives
# ---------------------------------------------------------------------------

_UINT32 = struct.Struct(">I")
_UINT32_MAX = 0xFFFF_FFFF


def encode_uint32(n: int) -> bytes:
    """Encode ``n`` as a big-endian ``uint32``; ``ValueError`` when out of range."""
    if not 0 <= n <= _UINT32_MAX:
        raise ValueError("uint32 out of range")
    return _UINT32.pack(n)


def encode_string(b: bytes | bytearray | memoryview | str) -> bytes:
    """Encode an RFC 4251 ``string`` (``uint32`` length prefix + bytes).

    ``str`` values are encoded as UTF-8 for convenience when writing
    protocol names.  Binary data must be passed as bytes.
    """
    if isinstance(b, str):
        data = b.encode("utf-8")
    elif isinstance(b, (bytes, bytearray, memoryview)):
        data = bytes(b)
    else:
        raise TypeError("encode_string expects bytes or str")
    if len(data) > _UINT32_MAX:
        raise ValueError("string too long for uint32 length prefix")
    return _UINT32.pack(len(data)) + data


def encode_bool(v: bool) -> bytes:
    """Encode an RFC 4251 ``boolean`` as exactly ``0x00`` or ``0x01``."""
    return b"\x01" if v else b"\x00"


def encode_mpint(n: int) -> bytes:
    """Encode an integer as an RFC 4251 (section 5) ``mpint``.

    Zero encodes as the empty string; every other value uses the minimal
    big-endian two's-complement form, so a positive value gains a leading
    ``0x00`` exactly when its high bit is set and a negative value a leading
    ``0xff`` only when needed (``-0x1234`` -> ``edcc``, ``-0xdeadbeef`` ->
    ``ff21524111``).
    """
    if n == 0:
        return encode_string(b"")
    # Bits of the magnitude (ones' complement for negatives) plus a sign bit,
    # rounded up to whole bytes, gives the minimal two's-complement length.
    magnitude = ~n if n < 0 else n
    return encode_string(n.to_bytes(magnitude.bit_length() // 8 + 1, "big", signed=True))


class Reader:
    """Strict sequential reader over an SSH wire buffer.

    Every accessor raises :class:`WireError` instead of returning partial
    data when the buffer is too short.  Callers that expect a complete
    message must finish with :meth:`expect_eof` (or check :meth:`eof`) so
    that trailing bytes are rejected too.
    """

    __slots__ = ("_data", "_pos")

    def __init__(self, data: bytes | bytearray | memoryview) -> None:
        self._data = bytes(data)
        self._pos = 0

    # -- position ---------------------------------------------------------
    def remaining(self) -> int:
        """Number of unread bytes."""
        return len(self._data) - self._pos

    def eof(self) -> bool:
        """True when every byte has been consumed."""
        return self._pos >= len(self._data)

    def rest(self) -> bytes:
        """Consume and return all remaining bytes."""
        out = self._data[self._pos :]
        self._pos = len(self._data)
        return out

    def expect_eof(self, what: str = "message") -> None:
        """Raise :class:`WireError` unless the buffer is fully consumed."""
        if not self.eof():
            raise WireError(f"{self.remaining()} trailing byte(s) after {what}")

    # -- primitives -------------------------------------------------------
    def _take(self, n: int, what: str) -> bytes:
        if n > self.remaining():
            raise WireError(f"truncated {what}: need {n} byte(s), have {self.remaining()}")
        start = self._pos
        self._pos = start + n
        return self._data[start : self._pos]

    def raw(self, n: int) -> bytes:
        """Read exactly ``n`` raw bytes."""
        if n < 0:
            raise ValueError("negative length")
        return self._take(n, "raw bytes")

    def byte(self) -> int:
        """Read one ``byte`` as an int."""
        return self._take(1, "byte")[0]

    def boolean(self) -> bool:
        """Read a ``boolean``; only ``0x00``/``0x01`` are accepted."""
        v = self._take(1, "boolean")[0]
        if v == 0:
            return False
        if v == 1:
            return True
        raise WireError(f"non-canonical boolean byte {v:#04x}")

    def uint32(self) -> int:
        """Read a big-endian ``uint32``."""
        return _UINT32.unpack(self._take(4, "uint32"))[0]

    def string(self) -> bytes:
        """Read an RFC 4251 ``string`` and return its bytes."""
        length = self.uint32()
        return self._take(length, "string")

    def text(self, *, errors: str = "strict") -> str:
        """Read a ``string`` and decode it as UTF-8.

        Protocol names and identifiers are decoded strictly (invalid UTF-8
        raises :class:`WireError`); callers pass ``errors="replace"`` only
        for purely informational fields such as key comments.
        """
        raw = self.string()
        try:
            return raw.decode("utf-8", errors)
        except UnicodeDecodeError as exc:
            raise WireError("string is not valid UTF-8") from exc

    def mpint(self) -> int:
        """Read a minimally encoded RFC 4251 ``mpint`` (two's complement).

        Non-minimal encodings raise :class:`WireError`: a lone ``0x00``
        (zero must be empty), a redundant leading ``0x00`` before a byte
        without the high bit, or a redundant leading ``0xff`` before a byte
        with it.
        """
        raw = self.string()
        if not raw:
            return 0
        if len(raw) == 1 and raw[0] == 0:
            raise WireError("non-minimal mpint encoding")
        if len(raw) > 1 and raw[0] in (0x00, 0xFF) and (raw[1] & 0x80) == (raw[0] & 0x80):
            raise WireError("non-minimal mpint encoding")
        return int.from_bytes(raw, "big", signed=True)


# ---------------------------------------------------------------------------
# Ed25519 keys and OpenSSH key formats
# ---------------------------------------------------------------------------

ED25519_KEY_TYPE = "ssh-ed25519"
SEED_SIZE = 32
PUBLIC_KEY_SIZE = 32
SIGNATURE_SIZE = 64

_OPENSSH_MAGIC = b"openssh-key-v1\x00"
_PEM_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----"
_PEM_END = "-----END OPENSSH PRIVATE KEY-----"
_PEM_LINE_LENGTH = 70
_NONE_CIPHER_BLOCK_SIZE = 8


def _ed25519() -> ModuleType:
    """Import the Ed25519 implementation lazily (see module docstring)."""
    return importlib.import_module("zeropw.crypto.ed25519")


def _b64decode_strict(text: str, what: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise WireError(f"invalid base64 in {what}") from exc


@dataclass(frozen=True)
class Ed25519PublicKey:
    """A raw 32-byte Ed25519 public key."""

    key_bytes: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.key_bytes, bytes):
            raise TypeError("key_bytes must be bytes")
        if len(self.key_bytes) != PUBLIC_KEY_SIZE:
            raise WireError(f"ed25519 public key must be {PUBLIC_KEY_SIZE} bytes")

    @classmethod
    def from_blob(cls, blob: bytes) -> Ed25519PublicKey:
        return parse_public_key_blob(blob)

    def blob(self) -> bytes:
        """The ``ssh-ed25519`` wire blob (``string type || string key``)."""
        return encode_string(ED25519_KEY_TYPE) + encode_string(self.key_bytes)

    def to_authorized_key(self, comment: str = "") -> str:
        """One ``authorized_keys`` / ``.pub`` line without a trailing newline."""
        if any(c in comment for c in "\r\n\x00"):
            raise ValueError("comment must not contain line breaks or NUL")
        line = f"{ED25519_KEY_TYPE} {base64.b64encode(self.blob()).decode('ascii')}"
        return f"{line} {comment}" if comment else line

    def fingerprint(self) -> str:
        """OpenSSH-style ``SHA256:<unpadded base64>`` fingerprint of the blob."""
        digest = hashlib.sha256(self.blob()).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify a raw 64-byte signature; never raises for malformed input."""
        return bool(_ed25519().verify(self.key_bytes, data, signature))


@dataclass(frozen=True, repr=False)
class Ed25519PrivateKey:
    """An Ed25519 private key (32-byte seed) with its public half and comment.

    The constructor does not verify that ``public`` matches ``seed``; use
    :meth:`from_seed`, :func:`generate_ed25519_private_key` or
    :func:`parse_openssh_private_key`, which all do.
    """

    seed: bytes
    public: Ed25519PublicKey
    comment: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.seed, bytes):
            raise TypeError("seed must be bytes")
        if len(self.seed) != SEED_SIZE:
            raise WireError(f"ed25519 seed must be {SEED_SIZE} bytes")
        if not isinstance(self.public, Ed25519PublicKey):
            raise TypeError("public must be an Ed25519PublicKey")
        if not isinstance(self.comment, str):
            raise TypeError("comment must be str")

    def __repr__(self) -> str:  # never show the seed
        return f"Ed25519PrivateKey(public={self.public.fingerprint()!r}, comment={self.comment!r})"

    @classmethod
    def from_seed(cls, seed: bytes, comment: str = "") -> Ed25519PrivateKey:
        seed = bytes(seed)
        if len(seed) != SEED_SIZE:
            raise WireError(f"ed25519 seed must be {SEED_SIZE} bytes")
        public = Ed25519PublicKey(bytes(_ed25519().public_key_from_seed(seed)))
        return cls(seed=seed, public=public, comment=comment)

    def sign(self, data: bytes) -> bytes:
        """Raw 64-byte Ed25519 signature over ``data``."""
        signature = bytes(_ed25519().sign(self.seed, bytes(data)))
        if len(signature) != SIGNATURE_SIZE:
            raise WireError("ed25519 backend returned a malformed signature")
        return signature

    def to_openssh_private_key(self) -> str:
        """Serialise as an unencrypted ``openssh-key-v1`` PEM block.

        The output uses cipher/KDF ``none``, one key, OpenSSH's 1,2,3,...
        padding to the 8-byte block size, and 70-column base64 so that
        ``ssh-keygen -y -f`` accepts it verbatim.
        """
        checkint = encode_uint32(secrets.randbits(32))
        section = (
            checkint
            + checkint
            + encode_string(ED25519_KEY_TYPE)
            + encode_string(self.public.key_bytes)
            + encode_string(self.seed + self.public.key_bytes)
            + encode_string(self.comment.encode("utf-8"))
        )
        pad_len = (-len(section)) % _NONE_CIPHER_BLOCK_SIZE
        section += bytes(range(1, pad_len + 1))
        blob = (
            _OPENSSH_MAGIC
            + encode_string("none")
            + encode_string("none")
            + encode_string(b"")
            + encode_uint32(1)
            + encode_string(self.public.blob())
            + encode_string(section)
        )
        b64 = base64.b64encode(blob).decode("ascii")
        lines = [b64[i : i + _PEM_LINE_LENGTH] for i in range(0, len(b64), _PEM_LINE_LENGTH)]
        return "\n".join([_PEM_BEGIN, *lines, _PEM_END]) + "\n"


def generate_ed25519_private_key(comment: str = "") -> Ed25519PrivateKey:
    """Generate a fresh key using the Ed25519 backend's CSPRNG seed."""
    ed = _ed25519()
    seed = bytes(ed.generate_seed())
    if len(seed) != SEED_SIZE:
        raise WireError("ed25519 backend returned a malformed seed")
    public = Ed25519PublicKey(bytes(ed.public_key_from_seed(seed)))
    return Ed25519PrivateKey(seed=seed, public=public, comment=comment)


def parse_public_key_blob(blob: bytes) -> Ed25519PublicKey:
    """Parse an ``ssh-ed25519`` wire blob; any other type is unsupported."""
    r = Reader(blob)
    key_type = r.text()
    if key_type != ED25519_KEY_TYPE:
        raise UnsupportedKeyType(f"unsupported key type {key_type!r}")
    key_bytes = r.string()
    if len(key_bytes) != PUBLIC_KEY_SIZE:
        raise WireError("ed25519 public key blob has wrong key length")
    r.expect_eof("public key blob")
    return Ed25519PublicKey(key_bytes)


# Key type tokens as they appear at the start of an authorized_keys entry.
_KEY_TYPE_RE = re.compile(
    r"^(?:ssh-|ecdsa-sha2-|sk-ssh-|sk-ecdsa-|rsa-sha2-|webauthn-sk-|x509v3-)[A-Za-z0-9@.\-]*$"
)
# Anything that could be a (possibly unknown) key type name: no quotes, '=' or ','.
_KEY_TYPE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@.\-]*$")
# OpenSSH delimits authorized_keys fields with ``strcspn(cp, " \t")``: ASCII
# space and tab are the only separators.  ``str.split()`` / ``str.strip()``
# would also split on NBSP, VT, FF, NEL, U+2028 and friends.
_AUTHORIZED_KEYS_BLANK = " \t"
_AUTHORIZED_KEYS_FIELD_RE = re.compile(r"[ \t]+")


def _split_authorized_key_fields(text: str, maxsplit: int) -> list[str]:
    """Split on runs of ASCII space/tab only, never on other whitespace."""
    text = text.strip(_AUTHORIZED_KEYS_BLANK)
    return _AUTHORIZED_KEYS_FIELD_RE.split(text, maxsplit=maxsplit) if text else []


def _is_key_type_token(token: str, following: str | None) -> bool:
    """True when ``token`` occupies the key type position of an authorized_keys line.

    Known type-name prefixes match directly.  An unknown name (a future or
    vendor key type) is recognised when the field after it strictly base64
    decodes to a wire blob whose leading ``string`` is itself a key type
    name; in a well-formed line an options field is never followed by such
    a blob, so options are not mistaken for key types.
    """
    if _KEY_TYPE_RE.match(token):
        return True
    if following is None or not _KEY_TYPE_NAME_RE.match(token):
        return False
    try:
        leading = Reader(base64.b64decode(following, validate=True)).text()
    except (binascii.Error, ValueError):  # WireError is a ValueError
        return False
    return bool(_KEY_TYPE_NAME_RE.match(leading))


@dataclass(frozen=True)
class AuthorizedKeyEntry:
    """One parsed ``authorized_keys`` line (options are returned verbatim)."""

    options: str
    key: Ed25519PublicKey
    comment: str


def _skip_authorized_key_options(line: str) -> int:
    """Return the index just past the options field, honouring quotes like OpenSSH."""
    quoted = False
    i = 0
    while i < len(line):
        c = line[i]
        if not quoted and c in " \t":
            break
        if c == "\\" and i + 1 < len(line) and line[i + 1] == '"':
            i += 2
            continue
        if c == '"':
            quoted = not quoted
        i += 1
    if quoted:
        raise WireError("unterminated quote in authorized_keys options")
    return i


def parse_authorized_key_entry(line: str) -> AuthorizedKeyEntry:
    """Parse one ``authorized_keys`` / ``.pub`` line.

    Accepts an optional leading options field (``command="..."`` etc.),
    then ``ssh-ed25519``, the base64 blob and an optional comment.  Exactly
    one line is accepted: embedded line breaks (for example the contents of
    a whole ``authorized_keys`` file) raise :class:`WireError`, as do blank
    and ``#`` comment lines; any key type other than ``ssh-ed25519``,
    including unknown types followed by a key blob, raises
    :class:`UnsupportedKeyType`.

    Fields are separated by ASCII space/tab only, exactly like OpenSSH
    (``sshkey_read`` uses ``strcspn(cp, " \\t")``).  Any other whitespace
    character (NBSP, VT, FF, NEL, U+2028, ...) anywhere in the line raises
    :class:`WireError`: between fields OpenSSH would refuse the line too, and
    inside a comment or quoted option OpenSSH would ignore it, so refusing is
    the conservative choice that keeps every accepted line one ``ssh``/``sshd``
    parses identically.
    """
    stripped = line.strip(_AUTHORIZED_KEYS_BLANK + "\r\n")
    if not stripped or stripped.startswith("#"):
        raise WireError("blank or comment line")
    if any(c in stripped for c in "\r\n\x00"):
        raise WireError("expected a single authorized_keys line")
    if any(c.isspace() and c not in _AUTHORIZED_KEYS_BLANK for c in stripped):
        raise WireError("authorized_keys line contains whitespace other than space or tab")
    first = _split_authorized_key_fields(stripped, 2)
    if _is_key_type_token(first[0], first[1] if len(first) > 1 else None):
        options, remainder = "", stripped
    else:
        end = _skip_authorized_key_options(stripped)
        options, remainder = stripped[:end], stripped[end:].strip(_AUTHORIZED_KEYS_BLANK)
        if not remainder:
            raise WireError("authorized_keys line has options but no key")
    parts = _split_authorized_key_fields(remainder, 2)
    key_type = parts[0]
    if not _is_key_type_token(key_type, parts[1] if len(parts) > 1 else None):
        raise WireError("authorized_keys line has no recognisable key type")
    if key_type != ED25519_KEY_TYPE:
        raise UnsupportedKeyType(f"unsupported key type {key_type!r}")
    if len(parts) < 2:
        raise WireError("authorized_keys line is missing the key data")
    key = parse_public_key_blob(_b64decode_strict(parts[1], "authorized_keys line"))
    comment = parts[2].strip(_AUTHORIZED_KEYS_BLANK) if len(parts) == 3 else ""
    return AuthorizedKeyEntry(options=options, key=key, comment=comment)


def parse_authorized_key(line: str) -> Ed25519PublicKey:
    """Parse one ``authorized_keys`` / ``.pub`` line and return the key only."""
    return parse_authorized_key_entry(line).key


def _decode_openssh_pem(pem: str | bytes) -> bytes:
    if isinstance(pem, (bytes, bytearray, memoryview)):
        try:
            text = bytes(pem).decode("ascii")
        except UnicodeDecodeError as exc:
            raise WireError("private key file is not ASCII text") from exc
    elif isinstance(pem, str):
        text = pem
    else:
        raise TypeError("pem must be str or bytes")
    lines = [ln.strip() for ln in text.splitlines()]
    lines = [ln for ln in lines if ln]
    if not lines:
        raise WireError("empty private key")
    if lines[0] != _PEM_BEGIN:
        if lines[0].startswith("-----BEGIN ") and lines[0].endswith("-----"):
            raise UnsupportedKeyType(f"unsupported private key format: {lines[0]}")
        raise WireError("missing OpenSSH private key header")
    if lines[-1] != _PEM_END:
        raise WireError("missing OpenSSH private key footer")
    body = "".join(lines[1:-1])
    if not body:
        raise WireError("empty OpenSSH private key body")
    return _b64decode_strict(body, "OpenSSH private key")


def parse_openssh_private_key(pem: str | bytes) -> Ed25519PrivateKey:
    """Parse an unencrypted ``openssh-key-v1`` Ed25519 private key.

    Checks the magic, cipher/KDF ``none`` (anything else ->
    :class:`UnsupportedKeyType`), exactly one key, matching public key
    blobs, equal check-ints, the 64-byte ``seed || pub`` private field, the
    1,2,3,... padding to the 8-byte block, and finally that the public key
    derived from the seed matches the embedded one.  The comment is
    informational (``ssh-keygen -C`` copies argv bytes verbatim) and is
    decoded with U+FFFD replacement rather than refusing the key.
    """
    blob = _decode_openssh_pem(pem)
    r = Reader(blob)
    if r.raw(len(_OPENSSH_MAGIC)) != _OPENSSH_MAGIC:
        raise WireError("not an openssh-key-v1 container")
    ciphername = r.text()
    kdfname = r.text()
    kdfoptions = r.string()
    nkeys = r.uint32()
    if ciphername != "none" or kdfname != "none":
        raise UnsupportedKeyType("encrypted OpenSSH private keys are not supported")
    if kdfoptions:
        raise WireError("unexpected KDF options for an unencrypted key")
    if nkeys == 0:
        raise WireError("openssh-key-v1 container holds no keys")
    if nkeys != 1:
        raise UnsupportedKeyType("multi-key openssh-key-v1 containers are not supported")
    public_blob = r.string()
    section = r.string()
    r.expect_eof("openssh-key-v1 container")

    public = parse_public_key_blob(public_blob)
    if len(section) < _NONE_CIPHER_BLOCK_SIZE or len(section) % _NONE_CIPHER_BLOCK_SIZE:
        raise WireError("private key section is not block aligned")
    pr = Reader(section)
    if pr.uint32() != pr.uint32():
        raise WireError("check-int mismatch in private key section")
    if pr.text() != ED25519_KEY_TYPE:
        raise WireError("private key section type does not match the public key")
    if pr.string() != public.key_bytes:
        raise WireError("private key section public key does not match")
    private_field = pr.string()
    if len(private_field) != SEED_SIZE + PUBLIC_KEY_SIZE:
        raise WireError("ed25519 private field must be 64 bytes")
    seed, embedded_public = private_field[:SEED_SIZE], private_field[SEED_SIZE:]
    if embedded_public != public.key_bytes:
        raise WireError("private field public half does not match")
    comment = pr.text(errors="replace")
    padding = pr.rest()
    if len(padding) >= _NONE_CIPHER_BLOCK_SIZE or padding != bytes(range(1, len(padding) + 1)):
        raise WireError("invalid private key padding")
    if bytes(_ed25519().public_key_from_seed(seed)) != public.key_bytes:
        raise WireError("public key does not match the private seed")
    return Ed25519PrivateKey(seed=seed, public=public, comment=comment)


def encode_ssh_signature(sig64: bytes) -> bytes:
    """Wrap a raw 64-byte signature as ``string "ssh-ed25519" || string sig``."""
    sig64 = bytes(sig64)
    if len(sig64) != SIGNATURE_SIZE:
        raise WireError(f"ed25519 signature must be {SIGNATURE_SIZE} bytes")
    return encode_string(ED25519_KEY_TYPE) + encode_string(sig64)


def parse_ssh_signature(blob: bytes) -> bytes:
    """Unwrap an ``ssh-ed25519`` signature blob to its raw 64 bytes."""
    r = Reader(blob)
    algorithm = r.text()
    if algorithm != ED25519_KEY_TYPE:
        raise WireError(f"unexpected signature algorithm {algorithm!r}")
    signature = r.string()
    if len(signature) != SIGNATURE_SIZE:
        raise WireError("ed25519 signature blob has wrong length")
    r.expect_eof("signature blob")
    return signature


# ---------------------------------------------------------------------------
# SSH agent protocol
# ---------------------------------------------------------------------------

SSH_AGENT_FAILURE = 5
SSH_AGENT_SUCCESS = 6
SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14
SSH_AGENTC_ADD_IDENTITY = 17
SSH_AGENTC_REMOVE_IDENTITY = 18
SSH_AGENTC_REMOVE_ALL_IDENTITIES = 19
SSH_AGENTC_ADD_SMARTCARD_KEY = 20
SSH_AGENTC_REMOVE_SMARTCARD_KEY = 21
SSH_AGENTC_LOCK = 22
SSH_AGENTC_UNLOCK = 23
SSH_AGENTC_ADD_ID_CONSTRAINED = 25
SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26
SSH_AGENTC_EXTENSION = 27
SSH_AGENT_EXTENSION_FAILURE = 28

SESSION_BIND_EXTENSION = "session-bind@openssh.com"
EXTENSION_QUERY = "query"

MAX_AGENT_MESSAGE = 256 * 1024

RecvFn = Callable[[int], bytes]
SendFn = Callable[[bytes], Any]


def frame_agent_message(payload: bytes) -> bytes:
    """Prefix ``payload`` with its ``uint32`` length.

    Payloads must contain at least the type byte and at most
    :data:`MAX_AGENT_MESSAGE` bytes; anything else raises :class:`WireError`.
    """
    payload = bytes(payload)
    if not payload:
        raise WireError("agent message must contain at least a type byte")
    if len(payload) > MAX_AGENT_MESSAGE:
        raise WireError("agent message exceeds MAX_AGENT_MESSAGE")
    return encode_uint32(len(payload)) + payload


def _recv_callable(source: Any) -> RecvFn:
    recv = getattr(source, "recv", None)
    if callable(recv):
        return recv
    if callable(source):
        return source
    raise TypeError("expected a socket-like object with .recv or a recv(n) callable")


def _sendall_callable(target: Any) -> SendFn:
    sendall = getattr(target, "sendall", None)
    if callable(sendall):
        return sendall
    if callable(target):
        return target
    raise TypeError("expected a socket-like object with .sendall or a sendall(data) callable")


def _read_exact(recv: RecvFn, n: int) -> bytes:
    """Read up to ``n`` bytes, stopping early only at EOF (empty read)."""
    chunks: list[bytes] = []
    got = 0
    while got < n:
        chunk = recv(n - got)
        if not chunk:
            break
        chunk = bytes(chunk)
        if len(chunk) > n - got:
            raise WireError("recv returned more data than requested")
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def read_agent_message(source: Any) -> bytes | None:
    """Read one length-prefixed agent message.

    ``source`` is a socket-like object with ``recv(n)`` or a bare
    ``recv(n) -> bytes`` callable that returns ``b""`` at EOF.  Returns the
    payload (type byte included), or ``None`` on a clean EOF exactly at a
    message boundary.  Raises :class:`WireError` for a truncated length or
    payload, a zero-length frame, or a length above
    :data:`MAX_AGENT_MESSAGE` (checked before any payload is read).
    Transport exceptions propagate unchanged.
    """
    recv = _recv_callable(source)
    header = _read_exact(recv, 4)
    if not header:
        return None
    if len(header) < 4:
        raise WireError("truncated agent message length")
    (length,) = _UINT32.unpack(header)
    if length == 0:
        raise WireError("empty agent message")
    if length > MAX_AGENT_MESSAGE:
        raise WireError(f"agent message of {length} bytes exceeds MAX_AGENT_MESSAGE")
    payload = _read_exact(recv, length)
    if len(payload) < length:
        raise WireError("truncated agent message payload")
    return payload


def write_agent_message(target: Any, payload: bytes) -> None:
    """Send ``payload`` framed as one agent message via ``target.sendall`` (or a callable)."""
    _sendall_callable(target)(frame_agent_message(payload))


class AgentConnection:
    """Thin message-oriented wrapper around a connected socket (or socket pair end)."""

    def __init__(self, sock: Any) -> None:
        self._sock = sock
        self._recv = _recv_callable(sock)
        self._send = _sendall_callable(sock)

    def read_message(self) -> bytes | None:
        return read_agent_message(self._recv)

    def write_message(self, payload: bytes) -> None:
        write_agent_message(self._send, payload)

    def request(self, payload: bytes) -> bytes:
        """Send one message and return the reply; EOF before a reply is a :class:`WireError`."""
        self.write_message(payload)
        reply = self.read_message()
        if reply is None:
            raise WireError("agent closed the connection without replying")
        return reply

    def close(self) -> None:
        close = getattr(self._sock, "close", None)
        if callable(close):
            close()

    def __enter__(self) -> AgentConnection:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def build_failure() -> bytes:
    return bytes([SSH_AGENT_FAILURE])


def build_success() -> bytes:
    return bytes([SSH_AGENT_SUCCESS])


@dataclass(frozen=True)
class SignRequest:
    key_blob: bytes
    data: bytes
    flags: int


def build_sign_request(key_blob: bytes, data: bytes, flags: int = 0) -> bytes:
    """Full ``SSH_AGENTC_SIGN_REQUEST`` message including the type byte."""
    return (
        bytes([SSH_AGENTC_SIGN_REQUEST])
        + encode_string(key_blob)
        + encode_string(data)
        + encode_uint32(flags)
    )


def parse_sign_request(payload_after_type: bytes) -> SignRequest:
    """Parse the body of ``SSH_AGENTC_SIGN_REQUEST`` (type byte already removed)."""
    r = Reader(payload_after_type)
    key_blob = r.string()
    data = r.string()
    flags = r.uint32()
    r.expect_eof("sign request")
    return SignRequest(key_blob=key_blob, data=data, flags=flags)


def build_sign_response(signature_blob: bytes) -> bytes:
    """Full ``SSH_AGENT_SIGN_RESPONSE`` message including the type byte."""
    return bytes([SSH_AGENT_SIGN_RESPONSE]) + encode_string(signature_blob)


def parse_sign_response(payload_after_type: bytes) -> bytes:
    """Return the signature blob from a ``SSH_AGENT_SIGN_RESPONSE`` body."""
    r = Reader(payload_after_type)
    signature_blob = r.string()
    r.expect_eof("sign response")
    return signature_blob


def build_identities_answer(keys: Sequence[tuple[bytes, str]]) -> bytes:
    """Full ``SSH_AGENT_IDENTITIES_ANSWER`` for ``[(key_blob, comment), ...]``."""
    out = bytearray([SSH_AGENT_IDENTITIES_ANSWER])
    out += encode_uint32(len(keys))
    for key_blob, comment in keys:
        out += encode_string(key_blob)
        out += encode_string(comment.encode("utf-8"))
    return bytes(out)


def parse_identities_answer(payload_after_type: bytes) -> list[tuple[bytes, str]]:
    """Parse an ``SSH_AGENT_IDENTITIES_ANSWER`` body into ``[(key_blob, comment), ...]``.

    Comments are informational and decoded with U+FFFD replacement.
    """
    r = Reader(payload_after_type)
    nkeys = r.uint32()
    if nkeys > r.remaining() // 8:  # each entry needs at least two length prefixes
        raise WireError("identities answer claims more keys than it carries")
    keys: list[tuple[bytes, str]] = []
    for _ in range(nkeys):
        key_blob = r.string()
        comment = r.text(errors="replace")
        keys.append((key_blob, comment))
    r.expect_eof("identities answer")
    return keys


def build_extension_query() -> bytes:
    """Full ``SSH_AGENTC_EXTENSION`` message carrying the ``query`` extension."""
    return bytes([SSH_AGENTC_EXTENSION]) + encode_string(EXTENSION_QUERY)


def build_extension_query_response(names: Sequence[str]) -> bytes:
    """``SSH_AGENT_SUCCESS`` followed by one ``string`` per supported extension name.

    Layout note (not a protocol commitment): this is the ``query`` reply of
    draft-miller-ssh-agent-04 §4.7.1 (``byte SSH_AGENT_SUCCESS`` then
    ``string[]`` extension names).  Later drafts revised the response
    framing, but OpenSSH's own ssh-agent does not implement ``query`` and the
    OpenSSH client never sends it, so no real client depends on either
    layout; ZeroPW's signer answers it for ZeroPW's own tests only.  The reply
    starts with ``SSH_AGENT_SUCCESS`` (6), never ``SSH_AGENT_SIGN_RESPONSE``
    (14), so a client dispatching on the type byte cannot mistake it for a
    signature.
    """
    out = bytearray([SSH_AGENT_SUCCESS])
    for name in names:
        out += encode_string(name)
    return bytes(out)


def parse_extension_query_response(payload_after_type: bytes) -> list[str]:
    """Parse the body of a ``query`` extension response into extension names.

    Expects the draft-miller-ssh-agent-04 layout produced by
    :func:`build_extension_query_response` (see its docstring); used by
    ZeroPW's own tests, not by any OpenSSH component.
    """
    r = Reader(payload_after_type)
    names: list[str] = []
    while not r.eof():
        names.append(r.text())
    return names


def parse_extension(payload_after_type: bytes) -> tuple[str, bytes]:
    """Split an ``SSH_AGENTC_EXTENSION`` body into ``(name, extension_data)``."""
    r = Reader(payload_after_type)
    name = r.text()
    if not name:
        raise WireError("empty extension name")
    return name, r.rest()


@dataclass(frozen=True)
class SessionBind:
    host_key_blob: bytes
    session_id: bytes
    signature: bytes
    is_forwarding: bool


def build_session_bind(
    host_key_blob: bytes, session_id: bytes, signature_blob: bytes, is_forwarding: bool
) -> bytes:
    """Full ``SSH_AGENTC_EXTENSION`` message for ``session-bind@openssh.com``."""
    return (
        bytes([SSH_AGENTC_EXTENSION])
        + encode_string(SESSION_BIND_EXTENSION)
        + encode_string(host_key_blob)
        + encode_string(session_id)
        + encode_string(signature_blob)
        + encode_bool(is_forwarding)
    )


def parse_session_bind(ext_payload_after_name: bytes) -> SessionBind:
    """Parse the data of a ``session-bind@openssh.com`` extension (name already removed)."""
    r = Reader(ext_payload_after_name)
    host_key_blob = r.string()
    session_id = r.string()
    signature = r.string()
    is_forwarding = r.boolean()
    r.expect_eof("session-bind extension")
    if not host_key_blob or not session_id or not signature:
        raise WireError("session-bind fields must not be empty")
    return SessionBind(
        host_key_blob=host_key_blob,
        session_id=session_id,
        signature=signature,
        is_forwarding=is_forwarding,
    )


# ---------------------------------------------------------------------------
# SSH_MSG_USERAUTH_REQUEST as signed by an agent (RFC 4252 §7, OpenSSH PROTOCOL)
# ---------------------------------------------------------------------------

SSH_MSG_USERAUTH_REQUEST = 50
SSH_CONNECTION_SERVICE = "ssh-connection"
USERAUTH_METHOD_PUBLICKEY = "publickey"
USERAUTH_METHOD_PUBLICKEY_HOSTBOUND = "publickey-hostbound-v00@openssh.com"


@dataclass(frozen=True)
class UserAuthRequest:
    """The parsed to-be-signed buffer of a public key authentication request.

    ``host_key_blob`` is ``None`` for the plain ``publickey`` method and the
    server host key for OpenSSH's ``publickey-hostbound-v00@openssh.com``
    variant (used by default between OpenSSH >= 8.9 peers).
    """

    session_id: bytes
    username: str
    service: str
    method: str
    has_signature: bool
    algorithm: str
    public_key_blob: bytes
    host_key_blob: bytes | None = None


def parse_userauth_request(data: bytes, *, allow_hostbound: bool = True) -> UserAuthRequest:
    """Strictly parse the buffer an SSH client asks an agent to sign.

    Layout: ``string session_id, byte 50, string username,
    string "ssh-connection", string "publickey", boolean TRUE,
    string algorithm, string public_key_blob`` and nothing else.  With
    ``allow_hostbound`` (the default) the method may instead be
    ``publickey-hostbound-v00@openssh.com`` followed by exactly one extra
    ``string host_key_blob``.  Every deviation, including empty fields,
    non-canonical booleans, invalid UTF-8, truncation and trailing bytes,
    raises :class:`WireError`.
    """
    r = Reader(data)
    session_id = r.string()
    if not session_id:
        raise WireError("empty session identifier")
    msg_type = r.byte()
    if msg_type != SSH_MSG_USERAUTH_REQUEST:
        raise WireError(f"expected SSH_MSG_USERAUTH_REQUEST (50), got {msg_type}")
    username = r.text()
    if not username:
        raise WireError("empty username")
    service = r.text()
    if service != SSH_CONNECTION_SERVICE:
        raise WireError(f"unexpected service {service!r}")
    method = r.text()
    if method == USERAUTH_METHOD_PUBLICKEY:
        hostbound = False
    elif method == USERAUTH_METHOD_PUBLICKEY_HOSTBOUND and allow_hostbound:
        hostbound = True
    else:
        raise WireError(f"unexpected authentication method {method!r}")
    has_signature = r.boolean()
    if not has_signature:
        raise WireError("userauth request does not carry a signature flag")
    algorithm = r.text()
    if not algorithm:
        raise WireError("empty public key algorithm")
    public_key_blob = r.string()
    if not public_key_blob:
        raise WireError("empty public key blob")
    host_key_blob: bytes | None = None
    if hostbound:
        host_key_blob = r.string()
        if not host_key_blob:
            raise WireError("empty host key in hostbound userauth request")
    r.expect_eof("userauth request")
    return UserAuthRequest(
        session_id=session_id,
        username=username,
        service=service,
        method=method,
        has_signature=True,
        algorithm=algorithm,
        public_key_blob=public_key_blob,
        host_key_blob=host_key_blob,
    )


def build_userauth_request(
    session_id: bytes,
    username: str,
    algorithm: str,
    public_key_blob: bytes,
    service: str = SSH_CONNECTION_SERVICE,
    *,
    host_key_blob: bytes | None = None,
) -> bytes:
    """Build the to-be-signed public key authentication buffer.

    Passing ``host_key_blob`` selects the hostbound method and appends the
    host key, mirroring what OpenSSH clients send to their agent.
    """
    method = USERAUTH_METHOD_PUBLICKEY if host_key_blob is None else USERAUTH_METHOD_PUBLICKEY_HOSTBOUND
    out = (
        encode_string(session_id)
        + bytes([SSH_MSG_USERAUTH_REQUEST])
        + encode_string(username)
        + encode_string(service)
        + encode_string(method)
        + encode_bool(True)
        + encode_string(algorithm)
        + encode_string(public_key_blob)
    )
    if host_key_blob is not None:
        out += encode_string(host_key_blob)
    return out
