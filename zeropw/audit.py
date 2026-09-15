"""Value-free, append-only audit log with simple anomaly alerts.

Design rules (docs/security-design.md §6):

* Records name the caller, connection, target, action, result and policy
  version.  They never contain vault values, authentication headers, request
  bodies, query strings, or free text supplied by an agent.  Every field is
  whitelisted and bounded here, so a caller cannot smuggle a value in.
* The log is mandatory: if a record cannot be written, ``record`` raises
  ``AuditUnavailable`` and the caller must refuse the authenticated operation.
* Agents cannot read the log.  There is no tools endpoint for it; only the
  administrator CLI (which has state-directory access) reads it.
* Alerts (``audit/alerts.jsonl``): administrator secret reveal, credential
  reflection, other near-exposures (execution output carrying the credential
  or handle, blocked upstream redirects), failures of the authenticated path
  (TLS server identity, unavailable credential), use under revoked/stale/
  stopped policy, and repeated denials -- counted per caller, and per event
  and reason for unauthenticated requests such as forged handles.
"""

from __future__ import annotations

import json
import re
import time
from collections import deque
from typing import Any, Callable

from .errors import AuditUnavailable, InvalidInput
from .store import StateDir, iso

AUDIT_FILE = "audit/audit.jsonl"
ALERT_FILE = "audit/alerts.jsonl"

MAX_FIELD_LENGTH = 200
DENIAL_WINDOW_SECONDS = 60.0
DENIAL_THRESHOLD = 5

EVENTS = frozenset({
    "init", "principal_create", "principal_disable", "project_create",
    "secret_put", "secret_retire", "secret_revoke", "secret_reveal", "secret_reveal_denied",
    "connection_create", "connection_update", "connection_disable", "connection_switch_credential",
    "grant_create", "grant_revoke", "grant_regrant", "grant_stale",
    "stop_all", "resume", "approval_request", "approval_grant", "approval_consume",
    "handle_issue", "tools_list_connections", "tools_request", "tools_exec", "tools_status", "tools_cancel",
    "http_relay", "ssh_bind", "ssh_sign", "ssh_agent_refused", "run_start", "run_finish", "run_cancel",
    "backup", "restore", "restore_ack", "recover", "rotation", "unsupported", "auth_failed",
    "team_commit_apply", "team_commit_rejected", "team_op_skipped",
})

EXTRA_KEYS = frozenset({
    "method", "path", "status", "host", "port", "username", "fingerprint", "bytes", "count",
    "exit_code", "program", "secret_id", "version", "grant", "principal", "digest", "state",
    "kind", "detail", "message_type", "extension", "scheme", "project", "environment", "service",
    "backup_id", "reviewed_sha", "run_state", "uses", "max_uses", "expires_at", "reason_code",
    "author_seq", "op", "env_id",
})

# Anomalies that mean a credential or handle nearly left the trusted boundary (alerted every time).
CREDENTIAL_EXPOSURE_REASONS = {
    "output_credential_blocked": "execution output carried the credential or handle; output withheld",
    "redirect_not_followed": "upstream redirect was blocked; its Location may carry request or credential data",
    "target_address_not_allowed": "credential delivery to a non-public address was refused (possible DNS change)",
    "metadata_address_not_allowed": "credential delivery to a metadata or link-local address was refused",
}
# Failures of the authenticated path that the user must hear about (alerted every time).
FAILURE_ALERT_REASONS = {
    "upstream_tls_failed": "upstream TLS server identity could not be verified; request refused",
    "credential_unavailable": "the connection's credential is unavailable (revoked, retired or corrupt)",
    "local_id_conflict": "a shared environment tried to derive a connection or secret id already used locally",
}

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _clean(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return round(value, 3)
    if isinstance(value, str):
        value = _CONTROL_RE.sub("?", value)
        return value[:MAX_FIELD_LENGTH]
    raise InvalidInput("audit_field_type")


def strip_query(path: str) -> str:
    return path.split("?", 1)[0] if isinstance(path, str) else ""


class Audit:
    def __init__(self, state: StateDir, clock: Callable[[], float] = time.time) -> None:
        self.state = state
        self.clock = clock
        self._recent_denials: dict[str, deque] = {}

    # ---------------------------------------------------------------- record
    def record(self, event: str, *, caller: str | None = None, connection: str | None = None,
               target: str | None = None, action: str | None = None, result: str = "ok",
               reason: str | None = None, policy_version: int | None = None,
               run_id: str | None = None, request_id: str | None = None,
               extra: dict[str, Any] | None = None) -> dict[str, Any]:
        if event not in EVENTS:
            raise InvalidInput("audit_event_unknown")
        record: dict[str, Any] = {
            "ts": iso(self.clock()),
            "event": event,
            "caller": _clean(caller),
            "connection": _clean(connection),
            "target": _clean(target),
            "action": _clean(action),
            "result": _clean(result),
            "reason": _clean(reason),
            "policy_version": _clean(policy_version),
            "run_id": _clean(run_id),
            "request_id": _clean(request_id),
        }
        if extra:
            for key, value in extra.items():
                if key not in EXTRA_KEYS:
                    raise InvalidInput("audit_extra_key")
                if key == "path" and isinstance(value, str):
                    value = strip_query(value)  # query strings never enter the log
                record[key] = _clean(value)
        line = json.dumps(record, sort_keys=True, separators=(",", ":"))
        try:
            self.state.append_line(AUDIT_FILE, line)
        except Exception as exc:  # any failure to persist must stop the caller
            raise AuditUnavailable("audit_write_failed") from exc
        self._maybe_alert(record)
        return record

    def require_writable(self) -> None:
        """Probe that the audit file can be appended to before authenticating."""
        try:
            self.state.subdir("audit")
            self.state.append_line(AUDIT_FILE, "")
        except Exception as exc:
            raise AuditUnavailable("audit_write_failed") from exc

    # ---------------------------------------------------------------- alerts
    def _alert(self, kind: str, record: dict[str, Any], detail: str) -> None:
        alert = {
            "ts": record["ts"],
            "alert": kind,
            "caller": record.get("caller"),
            "connection": record.get("connection"),
            "event": record["event"],
            "reason": record.get("reason"),
            "detail": _clean(detail),
        }
        try:
            self.state.append_line(ALERT_FILE, json.dumps(alert, sort_keys=True, separators=(",", ":")))
        except Exception as exc:
            raise AuditUnavailable("alert_write_failed") from exc

    def _maybe_alert(self, record: dict[str, Any]) -> None:
        reason = record.get("reason")
        if record["event"] == "secret_reveal":
            self._alert("secret_reveal", record, "administrator revealed a single secret version")
        if reason == "credential_reflection_blocked":
            self._alert("credential_reflection", record, "upstream response reflected the credential; blocked")
        if reason in CREDENTIAL_EXPOSURE_REASONS:
            self._alert("credential_exposure", record, CREDENTIAL_EXPOSURE_REASONS[reason])
        if reason in FAILURE_ALERT_REASONS and record.get("result") != "attempt":
            self._alert("failure", record, FAILURE_ALERT_REASONS[reason])
        if reason in {"grant_revoked", "global_stop", "grant_stale", "principal_disabled", "restore_pending"}:
            self._alert("revoked_use_attempt", record, "use attempted under a revoked, stale, or stopped grant")
        if record.get("result") == "denied":
            # Authenticated denials count per caller.  Unauthenticated ones (forged or tampered
            # handles, unknown tokens) carry no caller, so they count per event and reason.
            key = (f"caller:{record['caller']}" if record.get("caller")
                   else f"unauthenticated:{record['event']}:{reason}")
            now = self.clock()
            window = self._recent_denials.setdefault(key, deque())
            window.append(now)
            while window and now - window[0] > DENIAL_WINDOW_SECONDS:
                window.popleft()
            if len(window) == DENIAL_THRESHOLD:
                self._alert("repeated_denials", record,
                            f"{DENIAL_THRESHOLD} denials within {int(DENIAL_WINDOW_SECONDS)}s")

    # ------------------------------------------------------------------ read
    def tail(self, limit: int = 50) -> list[dict[str, Any]]:
        lines = [l for l in self.state.read_lines(AUDIT_FILE, None) if l]
        return [json.loads(line) for line in lines[-limit:]]

    def alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        lines = [l for l in self.state.read_lines(ALERT_FILE, None) if l]
        return [json.loads(line) for line in lines[-limit:]]
