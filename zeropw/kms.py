"""Key-management abstraction with a local development stand-in.

The product design assumes a managed secret store and KMS.  The prototype
keeps the same envelope structure: a random data-encryption key (DEK) protects
the vault, and the DEK is wrapped by a KMS.  ``LocalFileKms`` stores a master
key in a 0600 file inside the trusted state directory.  It is a development
stand-in only: it offers no hardware protection, no separate KMS identity, and
no cloud audit trail.  Replace it with a managed KMS wrapper before any real
deployment; the ``Kms`` protocol is the seam.
"""

from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .crypto import chacha20poly1305 as aead
from .errors import StateError

MASTER_KEY_SIZE = 32


@dataclass(frozen=True)
class WrappedKey:
    key_id: str
    nonce: bytes
    ciphertext: bytes

    def to_dict(self) -> dict[str, str]:
        return {
            "key_id": self.key_id,
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, value: dict[str, str]) -> "WrappedKey":
        try:
            return cls(
                key_id=str(value["key_id"]),
                nonce=base64.b64decode(value["nonce"]),
                ciphertext=base64.b64decode(value["ciphertext"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StateError("wrapped_key_malformed") from exc


class Kms(Protocol):
    key_id: str

    def wrap(self, data_key: bytes) -> WrappedKey: ...

    def unwrap(self, wrapped: WrappedKey) -> bytes: ...


class KmsError(StateError):
    reason = "kms_error"


class LocalFileKms:
    """Development KMS: master key in a 0600 file.  Not for production."""

    def __init__(self, path: Path, key_id: str, master_key: bytes) -> None:
        if len(master_key) != MASTER_KEY_SIZE:
            raise KmsError("kms_master_key_size")
        self.path = path
        self.key_id = key_id
        self._master = master_key

    @classmethod
    def create(cls, path: Path, key_id: str = "local-dev-kms-1") -> "LocalFileKms":
        if path.exists():
            raise KmsError("kms_exists", str(path))
        master = secrets.token_bytes(MASTER_KEY_SIZE)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(key_id.encode("ascii") + b"\n" + base64.b64encode(master) + b"\n")
        return cls(path, key_id, master)

    @classmethod
    def load(cls, path: Path) -> "LocalFileKms":
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise KmsError("kms_missing", str(path)) from exc
        try:
            key_id_line, master_line = raw.split(b"\n")[:2]
            master = base64.b64decode(master_line)
            key_id = key_id_line.decode("ascii")
        except (ValueError, UnicodeDecodeError) as exc:
            raise KmsError("kms_corrupt", str(path)) from exc
        return cls(path, key_id, master)

    def wrap(self, data_key: bytes) -> WrappedKey:
        nonce = secrets.token_bytes(aead.NONCE_SIZE)
        ciphertext = aead.encrypt(self._master, nonce, data_key, self.key_id.encode("ascii"))
        return WrappedKey(self.key_id, nonce, ciphertext)

    def unwrap(self, wrapped: WrappedKey) -> bytes:
        if wrapped.key_id != self.key_id:
            raise KmsError("kms_key_id_mismatch")
        try:
            return aead.decrypt(self._master, wrapped.nonce, wrapped.ciphertext, self.key_id.encode("ascii"))
        except aead.AuthenticationError as exc:
            raise KmsError("kms_unwrap_failed") from exc
