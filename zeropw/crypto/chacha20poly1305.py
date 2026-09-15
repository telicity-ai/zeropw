"""Pure-Python ChaCha20-Poly1305 AEAD (RFC 8439).

The ZeroPW prototype must run on the Python standard library alone, which
offers hashing and HMAC but no authenticated encryption primitive.  This
module fills that gap with a direct transcription of RFC 8439:

* the ChaCha20 block function and stream cipher (sections 2.3 and 2.4),
* the Poly1305 one-time authenticator (section 2.5),
* the Poly1305 key derivation from ChaCha20 (section 2.6), and
* the AEAD_CHACHA20_POLY1305 construction (section 2.8): 32-byte key,
  96-bit nonce, 128-bit tag appended to the ciphertext.

Security scope and limitations
==============================

This is a **prototype** implementation.  Callers must understand:

* **Not constant-time.**  Pure Python cannot guarantee data-independent
  timing: integer arithmetic, byte slicing and loop control all take time
  that may depend on the values processed.  The one deliberately timing-safe
  step is the final tag comparison, which uses ``hmac.compare_digest`` so
  that a forged tag is not rejected faster or slower depending on how many
  leading bytes happen to match.  Do not deploy this where an attacker can
  take fine-grained timing measurements of the process.
* **No key hygiene.**  Keys, nonces, plaintexts and intermediate values are
  ordinary Python ``bytes`` and ``int`` objects.  Python provides no way to
  wipe them from memory once they are unreferenced.
* **Nonce management is the caller's responsibility.**  A 96-bit nonce must
  never be reused with the same key; reuse breaks both confidentiality and
  authenticity, exactly as with every other ChaCha20-Poly1305
  implementation.  This module does not generate nonces.
* **Throughput** is on the order of a few MiB/s on CPython.  That is fine
  for the small secrets ZeroPW stores; it is not a bulk-data cipher.
* **Message length** is bounded by the 32-bit block counter: at most
  (2**32 - 1) * 64 bytes per (key, nonce).  Longer inputs are rejected
  rather than silently wrapping the counter.

Error behaviour
===============

``encrypt`` raises ``ValueError`` for a key or nonce of the wrong size and
``TypeError`` for non-bytes arguments.  ``decrypt`` raises
``AuthenticationError`` (a ``ValueError`` subclass) for *every* failure: a
tag that does not verify, a wrong key, nonce or associated data, an input
shorter than the tag, a key or nonce of the wrong size, an argument that is
not bytes-like at all, or a memoryview that has already been released.  It
never returns partially decrypted data, and it
never raises anything other than ``AuthenticationError`` for its inputs, so
a caller's ``except AuthenticationError`` handles every rejected call.
"""

from __future__ import annotations

import hmac
import struct

__all__ = [
    "KEY_SIZE",
    "NONCE_SIZE",
    "TAG_SIZE",
    "AuthenticationError",
    "chacha20_block",
    "chacha20_encrypt",
    "decrypt",
    "encrypt",
    "poly1305_key_gen",
    "poly1305_mac",
]

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16

_BLOCK_SIZE = 64
_MAX_COUNTER = 0xFFFFFFFF
# The AEAD construction starts the stream at counter 1 (counter 0 derives the
# Poly1305 key), so at most 2**32 - 1 blocks are available per (key, nonce).
_MAX_AEAD_MESSAGE = _MAX_COUNTER * _BLOCK_SIZE

# "expand 32-byte k" as four little-endian words (RFC 8439 section 2.3).
_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)

_POLY1305_KEY_SIZE = 32
_POLY1305_P = (1 << 130) - 5
_POLY1305_R_CLAMP = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
_MASK128 = (1 << 128) - 1


class AuthenticationError(ValueError):
    """Raised by ``decrypt`` when the input cannot be authenticated.

    Every failure mode of ``decrypt`` maps to this single exception type so
    that callers cannot accidentally treat one class of rejected input
    differently from another.
    """


# ---------------------------------------------------------------------------
# Argument helpers
# ---------------------------------------------------------------------------


def _to_bytes(name: str, value: bytes | bytearray | memoryview) -> bytes:
    """Return ``value`` as immutable ``bytes``; reject anything not bytes-like."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    raise TypeError(f"{name} must be a bytes-like object, not {type(value).__name__}")


def _decrypt_bytes(name: str, value: bytes | bytearray | memoryview) -> bytes:
    """``_to_bytes`` for ``decrypt``: a non-bytes-like argument is an authentication failure.

    ``decrypt`` promises a single exception type for every rejected input, so
    every conversion failure from ``_to_bytes`` is mapped to
    ``AuthenticationError`` here: the ``TypeError`` for a non-bytes-like
    argument and the ``ValueError`` that ``bytes(memoryview)`` raises for a
    released memoryview.  The message carries only the argument name and type
    name (or the interpreter's description of the released buffer), never any
    key, nonce or data material.
    """
    try:
        return _to_bytes(name, value)
    except (TypeError, ValueError) as exc:
        raise AuthenticationError(str(exc)) from exc


def _exact_bytes(name: str, value: bytes | bytearray | memoryview, size: int) -> bytes:
    """Return ``value`` as ``bytes`` after checking it is exactly ``size`` long."""
    data = _to_bytes(name, value)
    if len(data) != size:
        raise ValueError(f"{name} must be exactly {size} bytes, got {len(data)}")
    return data


def _check_counter(counter: int) -> None:
    if isinstance(counter, bool) or not isinstance(counter, int):
        raise TypeError(f"counter must be an int, not {type(counter).__name__}")
    if not 0 <= counter <= _MAX_COUNTER:
        raise ValueError("counter must be an unsigned 32-bit integer")


def _xor(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte strings using one big-integer operation."""
    return (int.from_bytes(a, "little") ^ int.from_bytes(b, "little")).to_bytes(
        len(a), "little"
    )


# ---------------------------------------------------------------------------
# ChaCha20 (RFC 8439 sections 2.1 - 2.4)
# ---------------------------------------------------------------------------


def _quarter_round(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    """The ChaCha quarter round on four 32-bit words (RFC 8439 section 2.1)."""
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = ((d << 16) | (d >> 16)) & 0xFFFFFFFF
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = ((b << 12) | (b >> 20)) & 0xFFFFFFFF
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = ((d << 8) | (d >> 24)) & 0xFFFFFFFF
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = ((b << 7) | (b >> 25)) & 0xFFFFFFFF
    return a, b, c, d


def _block(key_words: tuple[int, ...], counter: int, nonce_words: tuple[int, ...]) -> bytes:
    """ChaCha20 block function on already-decoded state words; returns 64 bytes.

    ``key_words`` are the eight little-endian key words, ``nonce_words`` the
    three little-endian nonce words.  Sizes are validated by the callers.
    """
    s0, s1, s2, s3 = _CONSTANTS
    s4, s5, s6, s7, s8, s9, s10, s11 = key_words
    s12 = counter
    s13, s14, s15 = nonce_words

    x0, x1, x2, x3 = s0, s1, s2, s3
    x4, x5, x6, x7 = s4, s5, s6, s7
    x8, x9, x10, x11 = s8, s9, s10, s11
    x12, x13, x14, x15 = s12, s13, s14, s15

    qr = _quarter_round
    for _ in range(10):  # 10 double rounds = 20 rounds
        # Column round.
        x0, x4, x8, x12 = qr(x0, x4, x8, x12)
        x1, x5, x9, x13 = qr(x1, x5, x9, x13)
        x2, x6, x10, x14 = qr(x2, x6, x10, x14)
        x3, x7, x11, x15 = qr(x3, x7, x11, x15)
        # Diagonal round.
        x0, x5, x10, x15 = qr(x0, x5, x10, x15)
        x1, x6, x11, x12 = qr(x1, x6, x11, x12)
        x2, x7, x8, x13 = qr(x2, x7, x8, x13)
        x3, x4, x9, x14 = qr(x3, x4, x9, x14)

    return struct.pack(
        "<16I",
        (x0 + s0) & 0xFFFFFFFF,
        (x1 + s1) & 0xFFFFFFFF,
        (x2 + s2) & 0xFFFFFFFF,
        (x3 + s3) & 0xFFFFFFFF,
        (x4 + s4) & 0xFFFFFFFF,
        (x5 + s5) & 0xFFFFFFFF,
        (x6 + s6) & 0xFFFFFFFF,
        (x7 + s7) & 0xFFFFFFFF,
        (x8 + s8) & 0xFFFFFFFF,
        (x9 + s9) & 0xFFFFFFFF,
        (x10 + s10) & 0xFFFFFFFF,
        (x11 + s11) & 0xFFFFFFFF,
        (x12 + s12) & 0xFFFFFFFF,
        (x13 + s13) & 0xFFFFFFFF,
        (x14 + s14) & 0xFFFFFFFF,
        (x15 + s15) & 0xFFFFFFFF,
    )


def _key_words(key: bytes) -> tuple[int, ...]:
    return struct.unpack("<8I", key)


def _nonce_words(nonce: bytes) -> tuple[int, ...]:
    return struct.unpack("<3I", nonce)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """ChaCha20 block function (RFC 8439 section 2.3); returns 64 keystream bytes.

    ``key`` is 32 bytes, ``counter`` an unsigned 32-bit integer and ``nonce``
    12 bytes.  Wrong sizes raise ``ValueError``.
    """
    key = _exact_bytes("key", key, KEY_SIZE)
    nonce = _exact_bytes("nonce", nonce, NONCE_SIZE)
    _check_counter(counter)
    return _block(_key_words(key), counter, _nonce_words(nonce))


def chacha20_encrypt(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    """ChaCha20 stream cipher (RFC 8439 section 2.4).

    XORs ``data`` with the keystream that starts at block ``counter``.
    Encryption and decryption are the same operation.  Raises ``ValueError``
    for wrong key or nonce sizes, or when ``data`` needs more blocks than the
    32-bit counter can address from ``counter`` onwards.
    """
    key = _exact_bytes("key", key, KEY_SIZE)
    nonce = _exact_bytes("nonce", nonce, NONCE_SIZE)
    _check_counter(counter)
    data = _to_bytes("data", data)

    n_blocks = (len(data) + _BLOCK_SIZE - 1) // _BLOCK_SIZE
    if counter + n_blocks - 1 > _MAX_COUNTER:
        raise ValueError("data is too long for the 32-bit block counter")
    if n_blocks == 0:
        return b""

    key_words = _key_words(key)
    nonce_words = _nonce_words(nonce)
    keystream = b"".join(
        _block(key_words, block_counter, nonce_words)
        for block_counter in range(counter, counter + n_blocks)
    )
    return _xor(data, keystream[: len(data)])


# ---------------------------------------------------------------------------
# Poly1305 (RFC 8439 sections 2.5 and 2.6)
# ---------------------------------------------------------------------------


def poly1305_mac(key: bytes, msg: bytes) -> bytes:
    """Poly1305 one-time authenticator (RFC 8439 section 2.5); returns a 16-byte tag.

    ``key`` is the 32-byte one-time key ``r || s``.  The key must never be
    used for more than one message.  Raises ``ValueError`` for a wrong key size.
    """
    key = _exact_bytes("key", key, _POLY1305_KEY_SIZE)
    msg = _to_bytes("msg", msg)

    r = int.from_bytes(key[:16], "little") & _POLY1305_R_CLAMP
    s = int.from_bytes(key[16:], "little")
    p = _POLY1305_P
    acc = 0
    for offset in range(0, len(msg), 16):
        chunk = msg[offset : offset + 16]
        # Each 16-byte (or shorter final) chunk becomes a number with an extra
        # 0x01 byte appended, which is the same as setting bit 8*len(chunk).
        n = int.from_bytes(chunk, "little") | (1 << (8 * len(chunk)))
        acc = ((acc + n) * r) % p
    return ((acc + s) & _MASK128).to_bytes(16, "little")


def poly1305_key_gen(key: bytes, nonce: bytes) -> bytes:
    """Derive the 32-byte Poly1305 one-time key (RFC 8439 section 2.6).

    This is the first 32 bytes of the ChaCha20 block with counter 0.
    """
    return chacha20_block(key, 0, nonce)[:_POLY1305_KEY_SIZE]


# ---------------------------------------------------------------------------
# AEAD_CHACHA20_POLY1305 (RFC 8439 section 2.8)
# ---------------------------------------------------------------------------


def _pad16(data: bytes) -> bytes:
    return b"\x00" * (-len(data) % 16)


def _aead_tag(one_time_key: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    """Poly1305 tag over the RFC 8439 section 2.8 AEAD construction."""
    mac_data = b"".join(
        (
            aad,
            _pad16(aad),
            ciphertext,
            _pad16(ciphertext),
            struct.pack("<QQ", len(aad), len(ciphertext)),
        )
    )
    return poly1305_mac(one_time_key, mac_data)


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AEAD encryption; returns ``ciphertext || tag`` (RFC 8439 section 2.8).

    ``key`` must be ``KEY_SIZE`` bytes and ``nonce`` ``NONCE_SIZE`` bytes;
    other sizes raise ``ValueError``.  ``aad`` is authenticated but not
    encrypted.  The nonce must be unique per key; see the module docstring.
    """
    key = _exact_bytes("key", key, KEY_SIZE)
    nonce = _exact_bytes("nonce", nonce, NONCE_SIZE)
    plaintext = _to_bytes("plaintext", plaintext)
    aad = _to_bytes("aad", aad)
    if len(plaintext) > _MAX_AEAD_MESSAGE:
        raise ValueError("plaintext is too long for the 32-bit block counter")

    one_time_key = poly1305_key_gen(key, nonce)
    ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
    return ciphertext + _aead_tag(one_time_key, aad, ciphertext)


def decrypt(key: bytes, nonce: bytes, ciphertext_and_tag: bytes, aad: bytes = b"") -> bytes:
    """AEAD decryption of ``ciphertext || tag``; returns the plaintext.

    Raises ``AuthenticationError`` on any failure: bad tag, wrong key, nonce
    or ``aad``, input shorter than the tag, a key or nonce of the wrong
    size, or an argument that is not bytes-like.  The tag is verified before
    any decryption happens, so no plaintext is ever produced for
    unauthenticated input.
    """
    key = _decrypt_bytes("key", key)
    nonce = _decrypt_bytes("nonce", nonce)
    data = _decrypt_bytes("ciphertext_and_tag", ciphertext_and_tag)
    aad = _decrypt_bytes("aad", aad)

    if len(key) != KEY_SIZE:
        raise AuthenticationError(f"key must be exactly {KEY_SIZE} bytes, got {len(key)}")
    if len(nonce) != NONCE_SIZE:
        raise AuthenticationError(f"nonce must be exactly {NONCE_SIZE} bytes, got {len(nonce)}")
    if len(data) < TAG_SIZE:
        raise AuthenticationError("input is shorter than the authentication tag")
    if len(data) - TAG_SIZE > _MAX_AEAD_MESSAGE:
        raise AuthenticationError("ciphertext is too long for the 32-bit block counter")

    ciphertext = data[:-TAG_SIZE]
    tag = data[-TAG_SIZE:]
    expected_tag = _aead_tag(poly1305_key_gen(key, nonce), aad, ciphertext)
    if not hmac.compare_digest(expected_tag, tag):
        raise AuthenticationError("authentication failed")
    return chacha20_encrypt(key, 1, nonce, ciphertext)
