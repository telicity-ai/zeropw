"""Error types shared by the ZeroPW prototype.

Every error carries a short machine-readable ``reason`` code that is safe to
return to an agent.  Error messages never contain secret material: callers
construct them from fixed strings and identifiers only.
"""

from __future__ import annotations


class ZeroPWError(Exception):
    """Base class.  ``reason`` is a stable, value-free code."""

    reason: str = "zeropw_error"

    def __init__(self, reason: str | None = None, detail: str = "") -> None:
        if reason:
            self.reason = reason
        self.detail = detail
        message = self.reason if not detail else f"{self.reason}: {detail}"
        super().__init__(message)

    def to_dict(self) -> dict[str, str]:
        payload = {"error": type(self).__name__, "reason": self.reason}
        if self.detail:
            payload["detail"] = self.detail
        return payload


class InvalidInput(ZeroPWError):
    reason = "invalid_input"


class NotFound(ZeroPWError):
    reason = "not_found"


class AuthFailed(ZeroPWError):
    """Caller identity, handle, or administrator re-authentication failed."""

    reason = "auth_failed"


class PolicyDenied(ZeroPWError):
    """The policy engine refused the action (default deny)."""

    reason = "policy_denied"


class Unsupported(ZeroPWError):
    """The requested integration or mode is not supported.  Fail closed."""

    reason = "unsupported"


class AuditUnavailable(ZeroPWError):
    """A mandatory audit record could not be written; the operation must stop."""

    reason = "audit_unavailable"


class StateError(ZeroPWError):
    """Persistent state is missing, corrupt, or in a mode that blocks the action."""

    reason = "state_error"
