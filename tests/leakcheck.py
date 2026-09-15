"""Test helper: find a secret in captured output or state files, also when it is encoded.

``find_secret`` looks for every pattern ``zeropw.runs.credential_patterns``
derives (raw, standard/urlsafe base64 at every byte alignment with and without
padding, hex in both cases, percent-encoding), and additionally decodes
base64, hex and percent-encoded tokens found in the data and searches the
decoded bytes for the raw secret.  ``ssh_key_material`` expands an OpenSSH
private key into the pieces worth searching for: the PEM text, the decoded
key blob, the 32-byte seed and the PEM marker line.

Only a description of where a match was found is returned, never the value.
Not a test module (no ``test_`` prefix): imported by the end-to-end tests.
"""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from pathlib import Path
from typing import Iterable, Sequence

from zeropw.runs import credential_patterns

_BASE64_TOKEN = re.compile(rb"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_TOKEN = re.compile(rb"[0-9A-Fa-f]{16,}")
_MIN_DECODED_NEEDLE = 16


def ssh_key_material(private_key_pem: str | bytes) -> list[bytes]:
    """Needles for an OpenSSH private key: PEM text, decoded ``openssh-key-v1`` blob, Ed25519 seed, PEM marker.

    The ``BEGIN OPENSSH PRIVATE KEY`` marker is not secret by itself, but a
    fragment of the PEM (for example its first bytes, hex-encoded) carries it.
    """
    from zeropw import sshwire

    pem = private_key_pem.encode() if isinstance(private_key_pem, str) else bytes(private_key_pem)
    lines = pem.decode("ascii").strip().splitlines()
    blob = base64.b64decode("".join(line for line in lines if not line.startswith("-----")))
    key = sshwire.parse_openssh_private_key(pem)
    return [pem, blob, bytes(key.seed), b"BEGIN OPENSSH PRIVATE KEY"]


def _b64_decodings(token: bytes) -> Iterable[bytes]:
    body = token.rstrip(b"=")
    for offset in range(4):  # the token may start in the middle of an encoded group
        chunk = body[offset:]
        if len(chunk) < 8:
            break
        padded = chunk + b"=" * (-len(chunk) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                yield decoder(padded)
            except (binascii.Error, ValueError):
                continue


def _hex_decodings(token: bytes) -> Iterable[bytes]:
    for offset in (0, 1):
        chunk = token[offset:]
        chunk = chunk[: len(chunk) - len(chunk) % 2]
        try:
            yield binascii.unhexlify(chunk)
        except (binascii.Error, ValueError):
            continue


def find_secret(data: str | bytes, secrets: Sequence[bytes]) -> str | None:
    """Where (which encoding) one of ``secrets`` occurs in ``data``, or ``None``."""
    blob = data.encode("utf-8", "surrogateescape") if isinstance(data, str) else bytes(data)
    for index, secret in enumerate(secrets):
        for pattern in credential_patterns(secret):
            if pattern in blob:
                return f"secret #{index} in a directly scanned encoding"
    raw_needles = [(index, secret) for index, secret in enumerate(secrets) if len(secret) >= _MIN_DECODED_NEEDLE]
    if not raw_needles:
        return None

    def decoded_hit(decoded: bytes, how: str) -> str | None:
        for index, secret in raw_needles:
            if secret in decoded:
                return f"secret #{index} inside decoded {how}"
        return None

    unquoted = urllib.parse.unquote_to_bytes(blob.replace(b"+", b" "))
    if unquoted != blob and (hit := decoded_hit(unquoted, "percent-encoding")):
        return hit
    for match in _BASE64_TOKEN.finditer(blob):
        for decoded in _b64_decodings(match.group()):
            if hit := decoded_hit(decoded, "base64"):
                return hit
    for match in _HEX_TOKEN.finditer(blob):
        for decoded in _hex_decodings(match.group()):
            if hit := decoded_hit(decoded, "hex"):
                return hit
    return None


def find_secret_in_tree(root: Path, secrets: Sequence[bytes]) -> str | None:
    """First file under ``root`` (relative path) that carries one of ``secrets``, with the encoding found."""
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            hit = find_secret(path.read_bytes(), secrets)
            if hit:
                return f"{path.relative_to(root)}: {hit}"
    return None
