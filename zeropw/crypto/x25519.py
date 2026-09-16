"""Pure-Python X25519 (RFC 7748 section 5), the Montgomery-ladder Diffie-Hellman
function used for ZeroPW team-sync device agreement keys (docs/team-sync.md
section 4.1).

This is a direct transcription of the RFC 7748 pseudocode for X25519
(``a24 = 121665``, prime ``p = 2**255 - 19``, 255-bit scalars).  It mirrors
``zeropw/crypto/ed25519.py`` in scope and limitations:

* **Prototype, not constant-time.**  The ladder still touches every bit of the
  scalar the same number of times (the RFC's ``cswap`` shape), which is the
  usual source of *some* timing resistance for Montgomery ladders, but Python
  bigint arithmetic is not constant-time at the machine-instruction level.  Do
  not rely on this for protection against a local timing/cache attacker.
* **No key hygiene.**  Scalars and shared secrets are ordinary Python
  ``bytes``/``int`` and cannot be zeroised.
* Error messages never include key material.
* ``scalarmult`` never rejects a low-order or otherwise degenerate public
  point (RFC 7748 does not require it to, and the section 5.2 test vectors
  themselves exercise the bare ladder); it stays a faithful primitive.  Real
  key agreement -- ZeroPW's DEK wraps (docs/team-sync.md section 4.2) and the
  stage-2 handshake -- must go through ``shared_secret`` instead, which adds
  the RFC 7748 section 6.1 contributory-behaviour check: an all-zero result
  means the peer's public value was a small-order point contributing no
  entropy, and is refused rather than silently used as a "shared secret"
  every peer could reproduce.
"""

from __future__ import annotations

import secrets

from ..errors import InvalidInput

__all__ = [
    "SCALAR_SIZE",
    "POINT_SIZE",
    "BASE_POINT",
    "clamp_scalar",
    "scalarmult",
    "shared_secret",
    "public_key",
    "generate_private",
]

SCALAR_SIZE = 32
POINT_SIZE = 32

_P = 2**255 - 19
_A24 = 121665
_BITS = 255

# The X25519 base point u = 9, encoded little-endian over 32 bytes.
BASE_POINT = (9).to_bytes(POINT_SIZE, "little")


def _as_bytes(name: str, value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be a bytes-like object, not {type(value).__name__}")
    try:
        data = memoryview(value).tobytes()
    except Exception as exc:  # noqa: BLE001 - a released buffer or hostile override
        raise ValueError(f"{name} is not a usable bytes-like object") from exc
    if len(data) != SCALAR_SIZE:
        raise ValueError(f"{name} must be exactly {SCALAR_SIZE} bytes, got {len(data)}")
    return data


def clamp_scalar(raw: bytes) -> int:
    """Apply the RFC 7748 section 5 clamping to a 32-byte scalar and decode it."""
    k = bytearray(raw)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(bytes(k), "little")


def _decode_u_coordinate(raw: bytes) -> int:
    """Decode a 32-byte little-endian u-coordinate, masking the unused top bit (bits=255)."""
    u = bytearray(raw)
    u[31] &= 0x7F
    return int.from_bytes(bytes(u), "little") % _P


def _encode_u_coordinate(u: int) -> bytes:
    return (u % _P).to_bytes(POINT_SIZE, "little")


def _cswap(swap: int, a: int, b: int) -> tuple[int, int]:
    """Constant-shape (not constant-time in Python) conditional swap."""
    mask = -swap & ((1 << 256) - 1)
    a ^= b
    b ^= a & mask
    a ^= b
    return a, b


def _x25519(k: int, u: int) -> int:
    """RFC 7748 section 5 Montgomery ladder.  ``k`` is an already-clamped scalar."""
    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0
    for t in range(_BITS - 1, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = k_t

        a = (x2 + z2) % _P
        aa = (a * a) % _P
        b = (x2 - z2) % _P
        bb = (b * b) % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = (d * a) % _P
        cb = (c * b) % _P
        x3 = (da + cb) % _P
        x3 = (x3 * x3) % _P
        z3 = (da - cb) % _P
        z3 = (x1 * (z3 * z3)) % _P
        x2 = (aa * bb) % _P
        z2 = (e * (aa + _A24 * e)) % _P

    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)
    return (x2 * pow(z2, _P - 2, _P)) % _P


def scalarmult(k: bytes, u: bytes) -> bytes:
    """X25519(k, u): the Diffie-Hellman function of RFC 7748 section 5.

    Both arguments are 32-byte little-endian encodings.  ``k`` is clamped
    before use (callers may pass either a raw random scalar or an already
    clamped one; clamping is idempotent).  Raises ``TypeError``/``ValueError``
    for malformed input; never includes key material in an error.
    """
    k_bytes = _as_bytes("k", k)
    u_bytes = _as_bytes("u", u)
    scalar = clamp_scalar(k_bytes)
    point = _decode_u_coordinate(u_bytes)
    return _encode_u_coordinate(_x25519(scalar, point))


def shared_secret(private: bytes, peer_public: bytes) -> bytes:
    """X25519(private, peer_public) with the RFC 7748 section 6.1 contributory check.

    Raises ``InvalidInput("x25519_low_order_point")`` when the result is
    all-zero -- ``peer_public`` encoded a point of small order (the all-zero
    u-coordinate is the simplest example: it is fixed by the curve equation
    and independent of the scalar, so it contributes no secrecy at all).
    Use this for every real key agreement; ``scalarmult`` is the bare
    primitive the RFC test vectors exercise directly.
    """
    result = scalarmult(private, peer_public)
    if int.from_bytes(result, "little") == 0:
        raise InvalidInput("x25519_low_order_point")
    return result


def public_key(private: bytes) -> bytes:
    """Derive the public u-coordinate for a 32-byte private scalar."""
    return scalarmult(private, BASE_POINT)


def generate_private() -> bytes:
    """Return a fresh, clamped 32-byte X25519 private scalar from the OS CSPRNG."""
    raw = secrets.token_bytes(SCALAR_SIZE)
    clamped = bytearray(raw)
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    return bytes(clamped)
