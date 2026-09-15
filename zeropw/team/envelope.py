"""DEK generation wrapping and per-secret encryption for shared environments
(docs/team-sync.md section 4.2).

Two independent envelopes live here:

* ``wrap_dek`` / ``unwrap_dek``: an environment DEK generation is handed to
  one recipient device by an ephemeral X25519 key agreement, HKDF-SHA256, and
  a ChaCha20-Poly1305 seal.  This is the "one recipient" half of section 4.2;
  ``dek.rotate`` / ``env.init`` commits carry one such wrap per member.
* ``encrypt_secret`` / ``decrypt_secret``: a secret version's ciphertext,
  once a generation's DEK is known, with AAD binding it to the environment,
  secret and version identifiers so a ciphertext cannot be replayed under a
  different secret or version.

Nothing here ever has access to a passphrase or the local KMS; those live in
``zeropw/kms.py`` and are only consulted by ``zeropw/team/fold.py`` and
``zeropw/vault.py`` once a generation's DEK has already been unwrapped.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Any

from ..crypto import chacha20poly1305 as aead
from ..crypto import x25519
from ..errors import InvalidInput
from .identity import DeviceKey, DeviceRecord

DEK_INFO_PREFIX = b"zeropw-team-dek-v1"
_HKDF_HASH = hashlib.sha256
_HKDF_LEN = _HKDF_HASH().digest_size  # 32


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text)


# --------------------------------------------------------------------- HKDF
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-Extract with SHA-256."""
    if not salt:
        salt = b"\x00" * _HKDF_LEN
    return hmac.new(salt, ikm, _HKDF_HASH).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand with SHA-256."""
    if length > 255 * _HKDF_LEN:
        raise InvalidInput("hkdf_length_too_large")
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), _HKDF_HASH).digest()
        output += block
        counter += 1
    return output[:length]


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


# ---------------------------------------------------------------- DEK wraps
def _dek_info(env_id: str, generation_id: str, fingerprint: str) -> bytes:
    return DEK_INFO_PREFIX + env_id.encode("utf-8") + generation_id.encode("utf-8") + fingerprint.encode("utf-8")


def wrap_dek(dek: bytes, env_id: str, generation_id: str, recipient: DeviceRecord) -> dict[str, Any]:
    """Wrap ``dek`` for one recipient device (docs/team-sync.md section 4.2).

    An ephemeral X25519 key is generated for this wrap only; the shared
    secret with the recipient's agreement key feeds HKDF-SHA256 (info =
    ``zeropw-team-dek-v1`` + env id + generation id + recipient fingerprint)
    to derive a one-time ChaCha20-Poly1305 key.  Returns a JSON-safe dict
    with the ephemeral public key, nonce and ciphertext; never the DEK.
    """
    if not isinstance(dek, (bytes, bytearray)) or len(dek) != aead.KEY_SIZE:
        raise InvalidInput("invalid_dek_size")
    eph_private = x25519.generate_private()
    eph_pub = x25519.public_key(eph_private)
    shared = x25519.shared_secret(eph_private, recipient.agree_pub)
    info = _dek_info(env_id, generation_id, recipient.fingerprint)
    key = hkdf(b"", shared, info, aead.KEY_SIZE)
    nonce = secrets.token_bytes(aead.NONCE_SIZE)
    ciphertext = aead.encrypt(key, nonce, bytes(dek), info)
    return {"eph_pub": _b64e(eph_pub), "nonce": _b64e(nonce), "ciphertext": _b64e(ciphertext)}


def unwrap_dek(wrap: dict[str, Any], env_id: str, generation_id: str, device: DeviceKey) -> bytes:
    """Recover the DEK from a wrap addressed to ``device``.  Raises ``InvalidInput`` on any failure."""
    try:
        eph_pub = _b64d(str(wrap["eph_pub"]))
        nonce = _b64d(str(wrap["nonce"]))
        ciphertext = _b64d(str(wrap["ciphertext"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise InvalidInput("dek_wrap_malformed") from exc
    if len(eph_pub) != x25519.POINT_SIZE:
        raise InvalidInput("dek_wrap_malformed")
    shared = x25519.shared_secret(device.agree_private, eph_pub)
    info = _dek_info(env_id, generation_id, device.fingerprint)
    key = hkdf(b"", shared, info, aead.KEY_SIZE)
    try:
        return aead.decrypt(key, nonce, ciphertext, info)
    except aead.AuthenticationError as exc:
        raise InvalidInput("dek_unwrap_failed") from exc


# ------------------------------------------------------------- secret values
def _secret_aad(env_id: str, secret_id: str, version_id: str) -> bytes:
    """AAD = environment id + secret id + version id (docs/team-sync.md section 4.2).

    Joined with a NUL separator (none of the three identifiers may contain
    one -- fingerprints, project names and hex tokens never do) so that
    ``("a", "bc")`` and ``("ab", "c")`` cannot collide.
    """
    for part in (env_id, secret_id, version_id):
        if not isinstance(part, str) or "\x00" in part:
            raise InvalidInput("invalid_aad_component")
    return b"\x00".join(part.encode("utf-8") for part in (env_id, secret_id, version_id))


def encrypt_secret(dek: bytes, env_id: str, secret_id: str, version_id: str, value: bytes) -> dict[str, str]:
    """Encrypt one secret version under a generation DEK.  Returns ``{"nonce", "ciphertext"}`` (base64)."""
    if not isinstance(dek, (bytes, bytearray)) or len(dek) != aead.KEY_SIZE:
        raise InvalidInput("invalid_dek_size")
    aad = _secret_aad(env_id, secret_id, version_id)
    nonce = secrets.token_bytes(aead.NONCE_SIZE)
    ciphertext = aead.encrypt(dek, nonce, bytes(value), aad)
    return {"nonce": _b64e(nonce), "ciphertext": _b64e(ciphertext)}


def decrypt_secret(dek: bytes, env_id: str, secret_id: str, version_id: str, entry: dict[str, Any]) -> bytes:
    """Decrypt one secret version.  Raises ``InvalidInput`` for any malformed or unauthenticated input."""
    aad = _secret_aad(env_id, secret_id, version_id)
    try:
        nonce = _b64d(str(entry["nonce"]))
        ciphertext = _b64d(str(entry["ciphertext"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise InvalidInput("secret_ciphertext_malformed") from exc
    try:
        return aead.decrypt(dek, nonce, ciphertext, aad)
    except aead.AuthenticationError as exc:
        raise InvalidInput("secret_ciphertext_invalid") from exc
