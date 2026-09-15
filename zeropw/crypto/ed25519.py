"""Pure-Python Ed25519 (RFC 8032, PureEdDSA over edwards25519).

This module implements key derivation, signing and verification exactly as
specified in RFC 8032 section 5.1 (no prehash, empty context), using only the
Python standard library (``hashlib.sha512`` and ``secrets``).

Security scope and limitations (read before relying on this code)
-----------------------------------------------------------------
* This is a **prototype** implementation written for clarity and portability.
  It is NOT constant-time: scalar multiplication is a plain double-and-add
  loop over Python integers, whose timing and memory behaviour depend on the
  secret scalar.  Do not use it where a local attacker can measure timing,
  cache or power side channels.
* Python integers and ``bytes`` are immutable and cannot be zeroised, so the
  expanded secret scalar and the SHA-512 prefix may linger in process memory
  after ``sign`` returns.
* No error message, exception argument or log line ever includes key or seed
  material; malformed-seed errors only describe the expected length.
* ``verify`` is strict about encodings: it rejects signatures whose scalar S
  is not fully reduced (S >= L), and rejects point encodings with y >= p, with
  a non-square x^2 candidate, or with x == 0 together with a set sign bit
  (RFC 8032 section 5.1.3).  It never raises for malformed input; it returns
  ``False``.
* Verification uses the unbatched group equation ``[S]B == R + [k]A`` (the
  RFC notes this is sufficient in place of the cofactored form).  Small-order
  or mixed-order public keys and R values are not rejected beyond what the RFC
  requires, so signatures are not "strongly unforgeable" against a malicious
  signer who chooses such keys; that is out of scope for this prototype.
* Only the pure (non-prehashed, context-free) Ed25519 variant is provided.

Performance: with extended twisted Edwards coordinates a signature or a
verification takes a few milliseconds on CPython 3.11+, comfortably under the
50 ms budget in the implementation contract.
"""

from __future__ import annotations

import hashlib
import secrets

__all__ = [
    "SEED_SIZE",
    "PUBLIC_KEY_SIZE",
    "SIGNATURE_SIZE",
    "public_key_from_seed",
    "sign",
    "verify",
    "generate_seed",
]

SEED_SIZE = 32
PUBLIC_KEY_SIZE = 32
SIGNATURE_SIZE = 64

# --- Curve parameters (RFC 8032 section 5.1) --------------------------------

# Field prime p = 2^255 - 19.
_P = 2**255 - 19

# Group order L = 2^252 + 27742317777372353535851937790883648493.
_L = 2**252 + 27742317777372353535851937790883648493

# Curve constant d = -121665 / 121666 (mod p).  The curve is
# -x^2 + y^2 = 1 + d x^2 y^2  (twisted Edwards form with a = -1).
_D = (-121665 * pow(121666, -1, _P)) % _P
_2D = (2 * _D) % _P

# sqrt(-1) mod p, used when recovering x from y during point decoding.
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

# Base point B = (x, 4/5) with x "positive" (even).
_B_X = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_B_Y = 46316835694926478169428394003475163141307993866256225615783033603165251855960

# Points are extended twisted Edwards coordinates (X, Y, Z, T) with
# x = X/Z, y = Y/Z and x*y = T/Z.
_Point = tuple[int, int, int, int]

_IDENTITY: _Point = (0, 1, 1, 0)
_B: _Point = (_B_X, _B_Y, 1, (_B_X * _B_Y) % _P)


# --- Group arithmetic --------------------------------------------------------


def _point_add(p1: _Point, p2: _Point) -> _Point:
    """Add two points ("add-2008-hwcd-3", complete for a = -1)."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * _2D % _P * t2 % _P
    d = 2 * z1 * z2 % _P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_double(p: _Point) -> _Point:
    """Double a point ("dbl-2008-hwcd" specialised to a = -1)."""
    x, y, z, _ = p
    a = x * x % _P
    b = y * y % _P
    c = 2 * z * z % _P
    e = ((x + y) * (x + y) - a - b) % _P
    g = (b - a) % _P
    f = (g - c) % _P
    h = (-a - b) % _P
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _scalar_mult(k: int, point: _Point) -> _Point:
    """Compute [k]point by right-to-left double-and-add (not constant-time)."""
    result = _IDENTITY
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_double(addend)
        k >>= 1
    return result


def _point_equal(p1: _Point, p2: _Point) -> bool:
    """Compare two projective points without inverting Z."""
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


# --- Point encoding (RFC 8032 sections 5.1.2 and 5.1.3) ---------------------


def _point_encode(p: _Point) -> bytes:
    """Encode a point as 32 bytes: little-endian y with the sign of x in bit 255."""
    x, y, z, _ = p
    z_inv = pow(z, _P - 2, _P)
    x = x * z_inv % _P
    y = y * z_inv % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _point_decode(encoded: bytes) -> _Point | None:
    """Decode 32 bytes into a point, or return None if the encoding is invalid.

    Rejects y >= p, candidates whose x^2 has no square root (point not on the
    curve) and the encoding of x == 0 with the sign bit set.
    """
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    y2 = y * y % _P
    u = (y2 - 1) % _P
    v = (_D * y2 + 1) % _P
    # x = (u/v)^((p+3)/8) = u * v^3 * (u * v^7)^((p-5)/8)  (mod p)
    v3 = v * v % _P * v % _P
    v7 = v3 * v3 % _P * v % _P
    x = u * v3 % _P * pow(u * v7 % _P, (_P - 5) // 8, _P) % _P
    vx2 = v * x % _P * x % _P
    if vx2 == u:
        pass
    elif vx2 == (-u) % _P:
        x = x * _SQRT_M1 % _P
    else:
        return None
    if x == 0 and sign == 1:
        return None
    if (x & 1) != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


# --- Input handling ------------------------------------------------------------


def _as_bytes(value: object) -> bytes | None:
    """Return a ``bytes`` copy of a usable bytes-like object, else ``None``.

    The copy is taken through the buffer protocol (``memoryview(...).tobytes()``)
    rather than ``bytes(value)``, so a ``bytes`` subclass cannot substitute or
    sabotage the data via a ``__bytes__`` override.  Any failure to read the
    buffer -- a released ``memoryview`` (``ValueError``), or a hostile
    ``__buffer__`` override raising an arbitrary exception -- is reported as
    unusable rather than propagated, so ``verify`` keeps its never-raises
    guarantee.
    """
    if not isinstance(value, (bytes, bytearray, memoryview)):
        return None
    try:
        return memoryview(value).tobytes()
    except Exception:  # noqa: BLE001 - any conversion failure means "unusable"
        return None


def _check_seed(seed: bytes) -> bytes:
    """Validate a seed without ever including its value in an error."""
    data = _as_bytes(seed)
    if data is None:
        raise TypeError("seed must be a usable bytes-like object")
    if len(data) != SEED_SIZE:
        raise ValueError(f"seed must be exactly {SEED_SIZE} bytes")
    return data


def _check_message(message: bytes) -> bytes:
    data = _as_bytes(message)
    if data is None:
        raise TypeError("message must be a usable bytes-like object")
    return data


def _expand_seed(seed: bytes) -> tuple[int, bytes]:
    """RFC 8032 section 5.1.5 steps 1-3: clamped scalar a and the nonce prefix."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def _sha512_mod_l(*parts: bytes) -> int:
    h = hashlib.sha512()
    for part in parts:
        h.update(part)
    return int.from_bytes(h.digest(), "little") % _L


# --- Public API ----------------------------------------------------------------


def generate_seed() -> bytes:
    """Return a fresh 32-byte Ed25519 seed from the OS CSPRNG."""
    return secrets.token_bytes(SEED_SIZE)


def public_key_from_seed(seed: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte seed (RFC 8032 section 5.1.5).

    Raises ``TypeError``/``ValueError`` for a malformed seed; the error never
    contains the seed bytes.
    """
    seed = _check_seed(seed)
    a, _ = _expand_seed(seed)
    return _point_encode(_scalar_mult(a, _B))


def sign(seed: bytes, message: bytes) -> bytes:
    """Produce a 64-byte pure Ed25519 signature (RFC 8032 section 5.1.6).

    Signatures are deterministic: the same seed and message always yield the
    same signature.  Raises ``TypeError``/``ValueError`` for a malformed seed
    or message; the error never contains key material.
    """
    seed = _check_seed(seed)
    message = _check_message(message)
    a, prefix = _expand_seed(seed)
    public_key = _point_encode(_scalar_mult(a, _B))
    r = _sha512_mod_l(prefix, message)
    r_encoded = _point_encode(_scalar_mult(r, _B))
    k = _sha512_mod_l(r_encoded, public_key, message)
    s = (r + k * a) % _L
    return r_encoded + s.to_bytes(32, "little")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a pure Ed25519 signature (RFC 8032 section 5.1.7).

    Returns ``True`` only if every input is well formed and the unbatched
    equation ``[S]B == R + [k]A`` holds.  Returns ``False`` (never raises) for
    non-bytes inputs, wrong lengths, an undecodable public key or R, a
    non-canonical scalar (S >= L), or a failed equation.  A bytes-like object
    that cannot be read (a released ``memoryview``) counts as malformed.
    """
    public_key = _as_bytes(public_key)
    message = _as_bytes(message)
    signature = _as_bytes(signature)
    if public_key is None or message is None or signature is None:
        return False
    if len(public_key) != PUBLIC_KEY_SIZE or len(signature) != SIGNATURE_SIZE:
        return False
    a_point = _point_decode(public_key)
    if a_point is None:
        return False
    r_encoded = signature[:32]
    r_point = _point_decode(r_encoded)
    if r_point is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = _sha512_mod_l(r_encoded, public_key, message)
    lhs = _scalar_mult(s, _B)
    rhs = _point_add(r_point, _scalar_mult(k, a_point))
    return _point_equal(lhs, rhs)
