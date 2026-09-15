"""Device identity: Ed25519 signing key + X25519 agreement key (docs/team-sync.md section 4.1).

A device key is the node's identity for team sync: an Ed25519 seed used to
sign commits, and an X25519 private scalar used to agree on per-recipient DEK
wraps (``zeropw/team/envelope.py``).  Both secrets are wrapped by the local
``Kms`` (never stored in the clear) at ``team/device.key`` (0600, via
``StateDir``).  There is no export function for either private key: the only
operations this module offers on a loaded ``DeviceKey`` are deriving its
public ``DeviceRecord``, computing its fingerprint, and signing/agreeing.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from ..crypto import ed25519, x25519
from ..errors import InvalidInput, StateError
from ..kms import Kms, WrappedKey
from ..store import StateDir

DEVICE_KEY_FILE = "team/device.key"

# Domain-separation context for the device record signature (docs/team-sync.md
# section 4.1): the signing key signs "this X25519 key belongs to me".
DEVICE_RECORD_CONTEXT = b"zeropw-team-device-v1"

FINGERPRINT_SOURCE_BYTES = 16  # SHA-256(sign_pub)[:16], base32-encoded (docs/team-sync.md section 3)


def _b32(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=").lower()


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text)


@dataclass(frozen=True)
class DeviceRecord:
    """The public half of a device key, plus the binding signature (docs/team-sync.md section 4.1).

    ``sig`` is the Ed25519 signature by ``sign_pub`` over
    ``DEVICE_RECORD_CONTEXT + agree_pub``, binding the agreement key to the
    signing identity so a third party cannot substitute their own X25519 key
    under someone else's fingerprint.
    """

    sign_pub: bytes
    agree_pub: bytes
    sig: bytes

    def __post_init__(self) -> None:
        if len(self.sign_pub) != ed25519.PUBLIC_KEY_SIZE:
            raise InvalidInput("device_record_malformed")
        if len(self.agree_pub) != x25519.POINT_SIZE:
            raise InvalidInput("device_record_malformed")
        if len(self.sig) != ed25519.SIGNATURE_SIZE:
            raise InvalidInput("device_record_malformed")

    def verify(self) -> bool:
        """True iff ``sig`` really binds ``agree_pub`` to ``sign_pub``."""
        return ed25519.verify(self.sign_pub, DEVICE_RECORD_CONTEXT + self.agree_pub, self.sig)

    @property
    def fingerprint(self) -> str:
        """Lowercase, unpadded base32 of SHA-256(sign_pub)[:16] (docs/team-sync.md section 3)."""
        digest = hashlib.sha256(self.sign_pub).digest()[:FINGERPRINT_SOURCE_BYTES]
        return _b32(digest)

    def to_dict(self) -> dict[str, str]:
        return {"sign_pub": _b64e(self.sign_pub), "agree_pub": _b64e(self.agree_pub), "sig": _b64e(self.sig)}

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "DeviceRecord":
        try:
            sign_pub = _b64d(str(data["sign_pub"]))
            agree_pub = _b64d(str(data["agree_pub"]))
            sig = _b64d(str(data["sig"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidInput("device_record_malformed") from exc
        return cls(sign_pub, agree_pub, sig)


@dataclass(frozen=True)
class DeviceKey:
    """A node's private device identity.  Never serialised or logged directly."""

    sign_seed: bytes
    agree_private: bytes

    @classmethod
    def generate(cls) -> "DeviceKey":
        return cls(ed25519.generate_seed(), x25519.generate_private())

    @property
    def record(self) -> DeviceRecord:
        sign_pub = ed25519.public_key_from_seed(self.sign_seed)
        agree_pub = x25519.public_key(self.agree_private)
        sig = ed25519.sign(self.sign_seed, DEVICE_RECORD_CONTEXT + agree_pub)
        return DeviceRecord(sign_pub, agree_pub, sig)

    @property
    def fingerprint(self) -> str:
        return self.record.fingerprint

    def sign(self, message: bytes) -> bytes:
        return ed25519.sign(self.sign_seed, message)

    # ------------------------------------------------------------- persistence
    @classmethod
    def create(cls, state: StateDir, kms: Kms) -> "DeviceKey":
        """``team init``: generate and persist a device key.  Refuses if one already exists."""
        if state.exists(DEVICE_KEY_FILE):
            raise StateError("device_key_exists")
        device = cls.generate()
        with state.lock():
            if state.exists(DEVICE_KEY_FILE):
                raise StateError("device_key_exists")
            state.write_json(DEVICE_KEY_FILE, {
                "sign_seed": kms.wrap(device.sign_seed).to_dict(),
                "agree_private": kms.wrap(device.agree_private).to_dict(),
            })
        return device

    @classmethod
    def load(cls, state: StateDir, kms: Kms) -> "DeviceKey":
        doc = state.read_json(DEVICE_KEY_FILE, None)
        if not doc:
            raise StateError("device_key_missing")
        try:
            sign_seed = kms.unwrap(WrappedKey.from_dict(doc["sign_seed"]))
            agree_private = kms.unwrap(WrappedKey.from_dict(doc["agree_private"]))
        except (KeyError, TypeError, StateError) as exc:
            raise StateError("device_key_corrupt") from exc
        if len(sign_seed) != ed25519.SEED_SIZE or len(agree_private) != x25519.SCALAR_SIZE:
            raise StateError("device_key_corrupt")
        return cls(sign_seed, agree_private)

    @classmethod
    def load_or_create(cls, state: StateDir, kms: Kms) -> "DeviceKey":
        if state.exists(DEVICE_KEY_FILE):
            return cls.load(state, kms)
        return cls.create(state, kms)
