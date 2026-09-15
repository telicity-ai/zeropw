"""Compromise-response incidents: manual lockdown and exposure assessment.

Implements docs/compromise-response.md §4.4 (containment) and §5 (exposure
assessment) for stages 1-2 of §9's implementation plan: manual declaration
only (``open_incident`` / ``widen_incident`` / ``close_incident``).  The
automatic detector (stage 3) and the email notification (stage 4) are later
work; ``notification`` here is always left ``not_configured``.

Containment order (§4.4, steps 1-6, 9):

1. Write the incident file (status ``open``) and set ``incident_open`` on the
   control document.  While set, ``Policy.resume`` is refused.
2. ``stop_all`` when the scope is ``all``, or the scope is ``runtime`` and
   every currently *active* principal already belongs to that runtime
   (evaluated before anyone is disabled).
3. Disable every in-scope principal (``notify=False``: this module does its
   own precise per-principal cancellation instead of the fail-safe
   over-cancellation a principal-level revoke notification would trigger).
4. Revoke every in-scope principal's grants (``revoke_grants_of``, which
   notifies per grant -- precise, in-process cancellation when a server is
   attached to this ``Context``).
5. Rotate the handle key for ``runtime``/``all`` scope (never for
   ``principal``: that would break executions of principals outside the
   scope).
6. Precisely cancel runs and close signer sockets that belonged to in-scope
   principals at the moment the incident opened, counting them for the
   record.  When no server is attached to this ``Context`` (``ctx.runs`` /
   ``ctx.signer_manager`` are ``None`` -- the admin CLI's own process),
   nothing here can reach them; the counts stay 0 and ``applied_by_serve``
   is set, because a running ``serve`` process picks up the disabled
   principal / revoked grant on its next poll (``admin_cli._enforce_withdrawn_permissions``)
   regardless of which process declared the incident.
7. Build the exposure assessment (§5) and store it on the incident.
8. Leave ``notification`` as ``not_configured`` (stage 4 replaces this).
9. Audit ``incident_open`` (reason=trigger; alerted as ``intrusion``).

Every step is wrapped so a failure is recorded in ``actions.failed_steps``
and the next step still runs: containment is default-deny, so a failure to
record something must never leave a wider hole open.

Value-free guarantee: before every write, the incident is serialised and
scanned against every vault value (§5's final sentence) with the same
patterns ``zeropw.runs`` uses for output leak scanning.  A match (which
should be impossible -- nothing here ever reads a secret) redacts the
assessment instead of writing it.
"""

from __future__ import annotations

import json
import re
import secrets
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

from .errors import AuditUnavailable, InvalidInput, NotFound
from .runs import contains_sensitive, credential_patterns
from .store import iso

INCIDENTS_DIR = "incidents"
SCOPES = ("principal", "runtime", "all")
TRIGGERS = ("manual", "auto")
_SCOPE_ORDER = {"principal": 0, "runtime": 1, "all": 2}
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
MAX_DETAIL_LENGTH = 200

# Audit events whose "ok" record means the connection was actually used (§5).
_USE_EVENTS = ("http_relay", "ssh_sign", "run_start")


def _bound_text(value: str | None) -> str | None:
    """Admin-supplied free text (``--reason``, a future detector rule name): control-char
    stripped and length-bounded, the same shape ``audit._clean`` gives any string field."""
    if not isinstance(value, str):
        return None
    return _CONTROL_RE.sub("?", value)[:MAX_DETAIL_LENGTH]


def _path_for(incident_id: str) -> str:
    return f"{INCIDENTS_DIR}/{incident_id}.json"


def _new_incident_id(ctx: Any) -> str:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(ctx.clock()))
    return f"inc-{stamp}-{secrets.token_hex(4)}"


def _initial_actions() -> dict[str, Any]:
    return {
        "stopped": False, "principals_disabled": 0, "grants_revoked": 0, "handle_key_rotated": False,
        "runs_cancelled": 0, "sockets_closed": 0, "failed_steps": [],
    }


# --------------------------------------------------------------------- model
@dataclass
class Incident:
    id: str
    opened_at: str
    status: str
    scope: str
    runtime: str | None
    principals: list[str]
    trigger: str
    rule: str | None
    detail: str | None
    actions: dict[str, Any]
    assessment: dict[str, Any]
    notification: dict[str, Any]
    closed_at: str | None = None
    widened_from: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Incident":
        try:
            return cls(
                id=str(data["id"]), opened_at=str(data["opened_at"]), status=str(data["status"]),
                scope=str(data["scope"]), runtime=data.get("runtime"),
                principals=list(data.get("principals") or []), trigger=str(data.get("trigger", "manual")),
                rule=data.get("rule"), detail=data.get("detail"),
                actions=dict(data.get("actions") or {}), assessment=dict(data.get("assessment") or {}),
                notification=dict(data.get("notification") or {"status": "not_configured", "attempts": 0}),
                closed_at=data.get("closed_at"), widened_from=list(data.get("widened_from") or []),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise NotFound("incident_corrupt") from exc


# ---------------------------------------------------------------- value-free
def _sanitize_and_write(ctx: Any, incident: Incident) -> None:
    """Scan the serialised incident against every vault value; redact the assessment on a hit, then write."""
    payload = json.dumps(incident.to_dict(), sort_keys=True, default=str).encode("utf-8")
    try:
        values = ctx.vault.values_for_trusted_scan()
    except Exception:
        values = []
    patterns: list[bytes] = []
    for value in values:
        patterns.extend(credential_patterns(value))
    if patterns and contains_sensitive(payload, patterns):
        incident.assessment = {"redacted": True}
        failed = incident.actions.setdefault("failed_steps", [])
        if "assessment_redacted" not in failed:
            failed.append("assessment_redacted")
    ctx.state.write_json(_path_for(incident.id), incident.to_dict())


# ------------------------------------------------------------------- lookups
def get_incident(ctx: Any, incident_id: str) -> Incident:
    data = ctx.state.read_json(_path_for(incident_id), None)
    if data is None:
        raise NotFound("incident_not_found")
    return Incident.from_dict(data)


def list_incidents(ctx: Any) -> list[Incident]:
    directory = ctx.state.path / INCIDENTS_DIR
    if not directory.is_dir():
        return []
    result: list[Incident] = []
    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        try:
            result.append(Incident.from_dict(data))
        except NotFound:
            continue
    return result


# ---------------------------------------------------------------- resolving
def _resolve_principals(ctx: Any, scope: str, principals: Iterable[str] | None, runtime: str | None) -> list[str]:
    if scope == "principal":
        ids = list(principals or [])
        if not ids:
            raise InvalidInput("incident_principals_required")
        for pid in ids:
            ctx.policy.get_principal(pid)  # NotFound propagates: an unknown principal is a usage error
        return sorted(set(ids))
    if scope == "runtime":
        if not runtime:
            raise InvalidInput("incident_runtime_required")
        return sorted(p.id for p in ctx.policy.principals_in_runtime(runtime))
    if scope == "all":
        return sorted(p.id for p in ctx.policy.list_principals())
    raise InvalidInput("invalid_incident_scope")


def _runtime_covers_all_active(ctx: Any, runtime: str | None) -> bool:
    active = [p for p in ctx.policy.list_principals() if p.status == "active"]
    # all([]) is True: no active principals at all is vacuously "every active principal is in
    # this runtime", and stop_all is the fail-closed (over-, never under-) reading of that.
    return all(p.runtime == runtime for p in active)


# -------------------------------------------------------------- containment
def _cancel_runs_and_sockets(ctx: Any, runs_before: list[Any], bindings_before: list[Any],
                             actions: dict[str, Any], *, applied_by_serve: bool) -> None:
    """Force-cancel/release a snapshot taken before disabling anyone, counting it.

    The snapshot is taken *before* ``disable_principal``/``revoke_grants_of``
    so the count reflects everything that was actually active for these
    principals when the incident opened.  Calling ``cancel``/``release`` on
    something already cancelled/released by then (typically by the
    grant-level revoke notification fired a moment earlier, in the same
    process) is a documented no-op, so this is safe to call unconditionally
    -- it either does the job itself or confirms the notification already did.
    """
    registry = getattr(ctx, "runs", None)
    manager = getattr(ctx, "signer_manager", None)

    for run in runs_before:
        try:
            registry.cancel(run.id, run.caller, "incident_lockdown")
        except Exception:
            actions["failed_steps"].append("cancel_runs")
    if runs_before:
        actions["runs_cancelled"] = actions.get("runs_cancelled", 0) + len(runs_before)

    for binding in bindings_before:
        try:
            manager.release(binding)
        except Exception:
            actions["failed_steps"].append("close_sockets")
    if bindings_before:
        actions["sockets_closed"] = actions.get("sockets_closed", 0) + len(bindings_before)

    if applied_by_serve:
        actions["applied_by_serve"] = True


def _apply_lockdown(ctx: Any, incident: Incident, target_ids: list[str], *, scope: str,
                    runtime: str | None) -> None:
    """Steps 2-6 of §4.4, scoped to ``target_ids`` (every in-scope principal on ``open_incident``,
    only the newly-added ones on ``widen_incident``).  Idempotent: calling this twice with the same
    ``target_ids`` counts nothing a second time (see the per-step guards below)."""
    actions = incident.actions
    actions.setdefault("failed_steps", [])
    ids = set(target_ids)

    # Snapshot what is active for these principals *before* anyone is disabled -- see
    # ``_cancel_runs_and_sockets`` for why the count is taken here rather than afterwards.
    registry = getattr(ctx, "runs", None)
    manager = getattr(ctx, "signer_manager", None)
    try:
        runs_before = [run for run in registry.active_runs() if run.caller in ids] if registry is not None else []
    except Exception:
        actions["failed_steps"].append("cancel_runs")
        runs_before = []
    try:
        bindings_before = [b for b in manager.active_bindings() if b.caller in ids] if manager is not None else []
    except Exception:
        actions["failed_steps"].append("close_sockets")
        bindings_before = []

    if not actions.get("stopped"):
        stop_needed = scope == "all" or (scope == "runtime" and _runtime_covers_all_active(ctx, runtime))
        if stop_needed:
            try:
                ctx.policy.stop_all()
                actions["stopped"] = True
            except Exception:
                actions["failed_steps"].append("stop_all")

    disabled = 0
    revoked = 0
    for pid in target_ids:
        try:
            was_active = ctx.policy.get_principal(pid).status == "active"
        except Exception:
            was_active = False
        try:
            ctx.policy.disable_principal(pid, notify=False)
            if was_active:
                disabled += 1
        except Exception:
            actions["failed_steps"].append(f"disable_principal:{pid}")
        try:
            revoked += ctx.policy.revoke_grants_of(pid)
        except Exception:
            actions["failed_steps"].append(f"revoke_grants:{pid}")
    actions["principals_disabled"] = actions.get("principals_disabled", 0) + disabled
    actions["grants_revoked"] = actions.get("grants_revoked", 0) + revoked

    if scope in ("runtime", "all") and not actions.get("handle_key_rotated"):
        try:
            ctx.rotate_handle_key()
            actions["handle_key_rotated"] = True
        except Exception:
            actions["failed_steps"].append("rotate_handle_key")

    try:
        # Both being None means no server is attached to this Context at all (the admin CLI's
        # own process); either alone being None (e.g. the optional signer module unavailable)
        # is not that case, and the other side still gets cancelled/closed directly.
        _cancel_runs_and_sockets(ctx, runs_before, bindings_before, actions,
                                 applied_by_serve=registry is None and manager is None)
    except Exception:
        actions["failed_steps"].append("cancel_runs_and_sockets")


def _safe_assess(ctx: Any, incident: Incident, principals: list[str], scope: str) -> dict[str, Any]:
    try:
        # ``since`` is the incident's own opened_at, not each principal's created_at: by the
        # time this runs, step 4 has already revoked the very grants assess() needs to see as
        # "held" (see assess()'s docstring) -- opened_at is what tells a grant revoked_at by
        # *this* incident's own lockdown apart from one that was already gone beforehand.
        return assess(ctx, principals, scope, since=incident.opened_at)
    except Exception:
        incident.actions.setdefault("failed_steps", []).append("assess")
        return incident.assessment or {}


def _audit_incident(ctx: Any, event: str, incident: Incident, *, reason: str | None) -> None:
    try:
        ctx.audit.record(event, result="ok", reason=reason,
                         extra={"incident_id": incident.id, "scope": incident.scope, "runtime": incident.runtime,
                                "rule": incident.rule})
    except AuditUnavailable:
        # Containment already happened; a failure to log it must not undo it (§4.4 preamble).
        incident.actions.setdefault("failed_steps", []).append(f"audit_{event}")
        _sanitize_and_write(ctx, incident)


# --------------------------------------------------------------------- API
def open_incident(ctx: Any, *, scope: str, principals: Iterable[str] | None = None, runtime: str | None = None,
                  trigger: str, rule: str | None = None, detail: str | None = None) -> Incident:
    if scope not in SCOPES:
        raise InvalidInput("invalid_incident_scope")
    if trigger not in TRIGGERS:
        raise InvalidInput("invalid_incident_trigger")
    existing_id = ctx.policy.open_incident_id()
    if existing_id:
        try:
            existing = get_incident(ctx, existing_id)
        except NotFound:
            existing = None  # a stale pointer (incident file lost): fall through and open a fresh one
        if existing is not None:
            if _SCOPE_ORDER[scope] > _SCOPE_ORDER[existing.scope]:
                # A wider signal while an incident is already open must still apply §4.4
                # steps 3-6 to the new scope; silently keeping the narrower incident open
                # would leave the wider signal's principals/runtime unlocked.
                return widen_incident(ctx, existing.id, scope=scope, runtime=runtime, principals=principals,
                                      rule=rule)
            return existing
    resolved = _resolve_principals(ctx, scope, principals, runtime)

    incident = Incident(
        id=_new_incident_id(ctx), opened_at=iso(ctx.clock()), status="open", scope=scope, runtime=runtime,
        principals=resolved, trigger=trigger, rule=_bound_text(rule), detail=_bound_text(detail),
        actions=_initial_actions(), assessment={}, notification={"status": "not_configured", "attempts": 0},
        closed_at=None, widened_from=[],
    )
    _sanitize_and_write(ctx, incident)          # step 1a: incident file, status open
    ctx.policy.set_open_incident(incident.id)   # step 1b: resume() is now refused

    _apply_lockdown(ctx, incident, resolved, scope=scope, runtime=runtime)   # steps 2-6
    incident.assessment = _safe_assess(ctx, incident, resolved, scope)       # step 7
    # step 8: incident.notification stays {"status": "not_configured", ...} -- stage 4's job.
    _sanitize_and_write(ctx, incident)
    _audit_incident(ctx, "incident_open", incident, reason=incident.trigger)  # step 9
    return incident


def widen_incident(ctx: Any, incident_id: str, *, scope: str, runtime: str | None = None,
                   principals: Iterable[str] | None = None, rule: str | None = None) -> Incident:
    incident = get_incident(ctx, incident_id)
    if incident.status != "open":
        raise InvalidInput("incident_not_open")
    if scope not in _SCOPE_ORDER or _SCOPE_ORDER[scope] <= _SCOPE_ORDER[incident.scope]:
        raise InvalidInput("incident_scope_not_wider")

    resolved = _resolve_principals(ctx, scope, principals, runtime)
    new_ids = sorted(set(resolved) - set(incident.principals))

    incident.widened_from.append({"scope": incident.scope, "runtime": incident.runtime, "at": iso(ctx.clock())})
    incident.scope = scope
    incident.runtime = runtime
    if rule:
        incident.rule = _bound_text(rule)
    incident.principals = sorted(set(incident.principals) | set(resolved))

    _apply_lockdown(ctx, incident, new_ids, scope=scope, runtime=runtime)
    incident.assessment = _safe_assess(ctx, incident, incident.principals, scope)
    _sanitize_and_write(ctx, incident)
    _audit_incident(ctx, "incident_widen", incident, reason="widen")
    return incident


def close_incident(ctx: Any, incident_id: str) -> Incident:
    incident = get_incident(ctx, incident_id)
    if incident.status == "closed":
        raise InvalidInput("incident_already_closed")
    incident.status = "closed"
    incident.closed_at = iso(ctx.clock())
    _sanitize_and_write(ctx, incident)
    if ctx.policy.open_incident_id() == incident.id:
        ctx.policy.set_open_incident(None)   # does not resume -- stop_all, if any, stays until `resume`
    _audit_incident(ctx, "incident_close", incident, reason=None)
    return incident


# --------------------------------------------------------------- assessment
def _target_info(connection: Any) -> dict[str, Any]:
    if connection.kind == "http" and connection.http_target is not None:
        return {"host": connection.http_target.host, "port": connection.http_target.port}
    if connection.kind == "ssh" and connection.ssh_target is not None:
        return {"host": connection.ssh_target.host, "port": connection.ssh_target.port,
                "username": connection.ssh_target.username}
    return {}


def _fingerprint(meta: Any) -> str | None:
    for version in meta.versions:
        if version.version == meta.active_version:
            fingerprint = version.public.get("fingerprint")
            return fingerprint if isinstance(fingerprint, str) else None
    return None


def _new_secret_entry(meta: Any, service: str | None) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "secret_id": meta.id, "kind": meta.kind, "project": meta.project, "environment": meta.environment,
        "service": service, "connections": [], "targets": [],
        "first_used": None, "last_used": None, "use_count": 0, "active_version": meta.active_version,
        "tier": "none",
    }
    if meta.kind == "ssh_private_key":
        entry["fingerprint"] = _fingerprint(meta)
    return entry


def _merge_ts(current: str | None, candidate: str, *, newest: bool) -> str:
    if current is None:
        return candidate
    return max(current, candidate) if newest else min(current, candidate)


_TIER_RANK = {"none": 0, "recommended": 1, "mandatory": 2}


def assess(ctx: Any, principals: Iterable[str], scope: str, *, since: str) -> dict[str, Any]:
    """§5 exposure assessment: audit log only, never a vault value.

    The start point for each in-scope principal is its own token creation
    time; a connection is "used" once ``http_relay``/``ssh_sign`` (result
    ``ok``) or ``run_start`` names it at or after that point -- string
    comparison is correct because every timestamp uses the same fixed-width
    ISO-8601 UTC form (``zeropw.store.iso``).  "Recommended" covers a
    connection an in-scope principal held a grant for but never used: an
    ``active``/``stale`` grant, or one this same incident's own lockdown
    later revoked (``revoked_at >= since``, ``since`` being the incident's
    ``opened_at``).  Without the second half, calling this after
    ``open_incident``'s own step 4 (``revoke_grants_of``) has already run --
    which is exactly when it is called -- would see every grant as
    ``revoked`` and no connection could ever come out "recommended".  A
    grant revoked before the incident opened (unrelated to it) does not
    count as held.  For ``scope="all"`` every secret with an active version
    is "mandatory" plus ``recover_required``, regardless of any connection.
    """
    start_points: dict[str, str] = {}
    principal_views: list[dict[str, Any]] = []
    for pid in principals:
        try:
            principal = ctx.policy.get_principal(pid)
        except NotFound:
            continue
        start_points[pid] = principal.created_at
        principal_views.append({"id": principal.id, "created_at": principal.created_at,
                                "runtime": principal.runtime})

    connection_use: dict[str, dict[str, Any]] = {}
    for record in ctx.audit.iter_records():
        caller = record.get("caller")
        if not isinstance(caller, str) or caller not in start_points:
            continue
        if record.get("event") not in _USE_EVENTS or record.get("result") != "ok":
            continue
        ts = record.get("ts")
        connection_id = record.get("connection")
        if not isinstance(ts, str) or not isinstance(connection_id, str) or ts < start_points[caller]:
            continue
        stat = connection_use.setdefault(connection_id, {"first": ts, "last": ts, "count": 0})
        stat["first"] = _merge_ts(stat["first"], ts, newest=False)
        stat["last"] = _merge_ts(stat["last"], ts, newest=True)
        stat["count"] += 1

    connection_grant: set[str] = set()
    for pid in start_points:
        for grant in ctx.policy.list_grants(pid):
            held = grant.status in ("active", "stale") or (
                grant.status == "revoked" and isinstance(grant.revoked_at, str) and grant.revoked_at >= since)
            if held:
                connection_grant.add(grant.connection)

    secrets_out: dict[str, dict[str, Any]] = {}
    for connection_id in sorted(set(connection_use) | connection_grant):
        try:
            connection = ctx.policy.get_connection(connection_id)
        except NotFound:
            continue
        tier = "mandatory" if connection_id in connection_use else "recommended"
        if connection.secret_id not in secrets_out:
            secrets_out[connection.secret_id] = _new_secret_entry(ctx.vault.get_meta(connection.secret_id),
                                                                   connection.service)
        entry = secrets_out[connection.secret_id]
        entry["connections"].append(connection_id)
        entry["targets"].append(_target_info(connection))
        stat = connection_use.get(connection_id)
        if stat is not None:
            entry["first_used"] = _merge_ts(entry["first_used"], stat["first"], newest=False)
            entry["last_used"] = _merge_ts(entry["last_used"], stat["last"], newest=True)
            entry["use_count"] += stat["count"]
        if _TIER_RANK[tier] > _TIER_RANK[entry["tier"]]:
            entry["tier"] = tier

    result: dict[str, Any] = {"principals": principal_views, "secrets": []}
    if scope == "all":
        for meta in ctx.vault.list_secrets():
            if meta.active_version is None:
                continue
            entry = secrets_out.get(meta.id)
            if entry is None:
                entry = _new_secret_entry(meta, None)
                secrets_out[meta.id] = entry
            entry["tier"] = "mandatory"
            entry["recover_required"] = True
        # Top-level flag too, so the (later) email renderer does not have to scan every secret.
        result["recover_required"] = True

    result["secrets"] = [secrets_out[sid] for sid in sorted(secrets_out)]
    return result
