"""Opaque connection handles given to secret-free execution environments.

A handle is *not* the upstream credential.  It is a short-lived, HMAC-signed
capability that names a caller, a connection, a grant and the policy version
the grant was evaluated against.  The gateway verifies the signature, then
re-checks the live grant (expiry, usage, revocation, global stop) on every
request.  Leaking a handle lets the holder use the connection within the
granted scope until expiry or revocation; it never reveals a vault value.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass

from .errors import AuthFailed, InvalidInput

PREFIX = "zpw1"
HANDLE_KEY_SIZE = 32
MAX_TOKEN_LENGTH = 2048


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


@dataclass(frozen=True)
class Handle:
    caller: str
    connection: str
    grant: str
    policy_version: int
    issued_at: int
    expires_at: int
    handle_id: str


class HandleIssuer:
    def __init__(self, key: bytes) -> None:
        if len(key) < HANDLE_KEY_SIZE:
            raise InvalidInput("handle_key_too_short")
        self._key = key

    @staticmethod
    def generate_key() -> bytes:
        return secrets.token_bytes(HANDLE_KEY_SIZE)

    def _sign(self, body: str) -> str:
        digest = hmac.new(self._key, body.encode("ascii"), hashlib.sha256).digest()
        return _b64e(digest)

    def issue(self, caller: str, connection: str, grant: str, policy_version: int,
              ttl_seconds: int, now: float | None = None) -> str:
        if ttl_seconds <= 0 or ttl_seconds > 86400:
            raise InvalidInput("handle_ttl")
        issued = int(now if now is not None else time.time())
        payload = {
            "v": 1,
            "c": caller,
            "n": connection,
            "g": grant,
            "pv": int(policy_version),
            "iat": issued,
            "exp": issued + int(ttl_seconds),
            "jti": _b64e(secrets.token_bytes(12)),
        }
        body = f"{PREFIX}.{_b64e(json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8'))}"
        return f"{body}.{self._sign(body)}"

    def verify(self, token: str, now: float | None = None) -> Handle:
        if not isinstance(token, str) or len(token) > MAX_TOKEN_LENGTH:
            raise AuthFailed("handle_malformed")
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != PREFIX:
            raise AuthFailed("handle_malformed")
        body = f"{parts[0]}.{parts[1]}"
        expected = self._sign(body)
        if not hmac.compare_digest(expected, parts[2]):
            raise AuthFailed("handle_signature")
        try:
            payload = json.loads(_b64d(parts[1]).decode("utf-8"))
            handle = Handle(
                caller=str(payload["c"]),
                connection=str(payload["n"]),
                grant=str(payload["g"]),
                policy_version=int(payload["pv"]),
                issued_at=int(payload["iat"]),
                expires_at=int(payload["exp"]),
                handle_id=str(payload["jti"]),
            )
            if payload.get("v") != 1:
                raise AuthFailed("handle_version")
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthFailed("handle_malformed") from exc
        current = now if now is not None else time.time()
        if current >= handle.expires_at:
            raise AuthFailed("handle_expired")
        return handle
