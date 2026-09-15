"""Compromise-response replacement-guidance email (docs/compromise-response.md §6, stage 4).

Delivery (§6.1) is direct ``smtplib`` from the trusted ``serve`` process.  SMTP host, port, mode,
sender and recipients live in ``<state>/notify.json`` (mode 0600, owned by the current user); the
SMTP password lives in a *separate* file named by ``password_file`` (same mode/ownership rule),
read only at send time and never retained past the call that sends.  Neither file is reachable by
an agent process (docs/product-intent.md §4's "ZeroPW's own foundational credential").  Missing
config is not an error: containment is complete without email (§6.1's own "이메일 없이도 봉쇄는
완전하다"); a missing/insecure/invalid config is recorded on the incident and audited, never
raised to a caller that would crash containment.

Rendering (``render_incident_email``, §6.2) is a pure function over the ``Incident``'s own
structured fields (id, scope, runtime, rule, principals, actions, assessment) -- never a vault
value, handle, token, request id, path, header, argv, or the detector's free-text ``detail``
beyond the bounded rule/count summary already on the incident.  Before a render is ever sent it is
scanned against ``ctx.vault.values_for_trusted_scan()`` with the same patterns
``zeropw.runs``/``zeropw.incident`` use for output-leak scanning (§6.2's closing sentence): a hit
blocks the send outright (``rendered_value_detected``), because nothing about this module is
supposed to ever see a value in the first place, so a match means something went wrong elsewhere.

Failure handling (§6.1): a transient send failure leaves ``notification`` ``pending`` with an
exponential backoff (1, 2, 4, ... capped at 300s); ``retry_pending`` (called every ``serve`` poll,
see ``admin_cli.run_serve``) retries every open incident whose backoff has elapsed.  Every
attempt -- sent, not_configured, pending, or the value-detected refusal -- is audited as
``incident_notify`` with a reason code and *no* address, host, or recipient (§6.1/§6.2: an
address is exactly the kind of admin-supplied-but-still-external data this module must not leak
into the value-free audit log).
"""

from __future__ import annotations

import ipaddress
import json
import os
import smtplib
import ssl
import stat
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from . import incident as I
from .errors import AuditUnavailable, InvalidInput, NotFound
from .runs import contains_sensitive, credential_patterns
from .store import iso

NOTIFY_FILE = "notify.json"
MODES = ("starttls", "smtps", "plain")
DEFAULT_TIMEOUT_SECONDS = 20.0
MAX_BACKOFF_SECONDS = 300.0
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

# §6.2 item 3's kind-specific replacement steps.  "api_key"/"env_var" ("env" in the design doc)
# share the same provider-rotation procedure; "password" adds active-session termination at the
# service instead of a provider console; "ssh_private_key" is entirely different (authorized_keys,
# not a vault rotation cycle, plus the server-side session check).
_KIND_STEPS: dict[str, tuple[str, ...]] = {
    "api_key": (
        "공급자 콘솔에서 이 자격증명을 폐기하고 재발급하십시오.",
        "`rotation start` -> `rotation activate` -> `rotation finish` 순서로 금고의 값을 교체하십시오.",
        "공급자 감사 로그에서 토큰 생성 시각 이후의 행위를 검토하십시오.",
    ),
    "env_var": (
        "공급자 콘솔에서 이 자격증명을 폐기하고 재발급하십시오.",
        "`rotation start` -> `rotation activate` -> `rotation finish` 순서로 금고의 값을 교체하십시오.",
        "공급자 감사 로그에서 토큰 생성 시각 이후의 행위를 검토하십시오.",
    ),
    "password": (
        "서비스에서 비밀번호를 변경하십시오.",
        "`rotation start` -> `rotation activate` -> `rotation finish` 순서로 금고의 값을 교체하십시오.",
        "해당 서비스의 활성 세션을 종료하십시오.",
    ),
    "ssh_private_key": (
        "새 키를 생성하십시오.",
        "대상 서버마다 authorized_keys에서 지문 {fingerprint}인 키를 제거하고 새 키로 교체하십시오.",
        "대상 서버에서 활성 세션을 확인하고 종료하십시오 (who, ss -tnp).",
        "`rotation start` -> `rotation activate` -> `rotation finish` 순서로 금고의 값을 교체하십시오.",
    ),
}


# ----------------------------------------------------------------- config
def _is_loopback(host: str) -> bool:
    if host in _LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _require_secure_file(path: Path) -> None:
    try:
        st = path.stat()
    except OSError as exc:
        raise InvalidInput("notify_config_insecure") from exc
    if stat.S_IMODE(st.st_mode) != 0o600:
        raise InvalidInput("notify_config_insecure")
    if st.st_uid != os.getuid():
        raise InvalidInput("notify_config_insecure")


@dataclass
class NotifyConfig:
    host: str
    port: int
    mode: str
    sender: str
    recipients: list[str]
    username: str | None = None
    password_file: str | None = None
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    @classmethod
    def load(cls, ctx: Any) -> "NotifyConfig | None":
        """``None`` means "not configured" (no ``notify.json``), which is not an error.  Any
        other problem -- wrong permissions/ownership, a malformed field, ``plain`` mode pointed
        at a non-loopback host -- raises ``InvalidInput`` so the caller can record *why*."""
        path = ctx.state.path / NOTIFY_FILE
        if not path.exists():
            return None
        _require_secure_file(path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise InvalidInput("notify_config_corrupt") from exc
        if not isinstance(data, dict):
            raise InvalidInput("notify_config_corrupt")

        host = data.get("host")
        if not isinstance(host, str) or not host:
            raise InvalidInput("notify_config_invalid")
        port = data.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
            raise InvalidInput("notify_config_invalid")
        mode = data.get("mode")
        if mode not in MODES:
            raise InvalidInput("notify_config_invalid")
        sender = data.get("sender")
        if not isinstance(sender, str) or not sender:
            raise InvalidInput("notify_config_invalid")
        recipients = data.get("recipients")
        if not isinstance(recipients, list) or not recipients \
                or not all(isinstance(r, str) and r for r in recipients):
            raise InvalidInput("notify_config_invalid")
        username = data.get("username")
        if username is not None and (not isinstance(username, str) or not username):
            raise InvalidInput("notify_config_invalid")
        password_file = data.get("password_file")
        if password_file is not None:
            if not isinstance(password_file, str) or not password_file:
                raise InvalidInput("notify_config_invalid")
            _require_secure_file(Path(password_file))
        timeout = data.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise InvalidInput("notify_config_invalid")

        if mode == "plain" and not _is_loopback(host):
            raise InvalidInput("notify_plain_requires_loopback")

        return cls(host=host, port=port, mode=mode, sender=sender, recipients=list(recipients),
                   username=username, password_file=password_file, timeout_seconds=float(timeout))


# ----------------------------------------------------------------- render
def _principal_lines(incident: "I.Incident") -> list[str]:
    lines = []
    for view in incident.assessment.get("principals", []):
        pid = view.get("id") if isinstance(view, dict) else None
        created = view.get("created_at") if isinstance(view, dict) else None
        if isinstance(pid, str):
            lines.append(f"  - {pid} (토큰 생성: {created or '알 수 없음'})")
    if not lines:
        lines = [f"  - {pid}" for pid in incident.principals]
    return lines


def _secret_block(secret: dict[str, Any], *, mandatory: bool) -> list[str]:
    lines = [
        f"* 비밀 ID: {secret.get('secret_id')}  (종류: {secret.get('kind')}, 서비스: {secret.get('service') or '알 수 없음'})",
        f"  프로젝트/환경: {secret.get('project')}/{secret.get('environment')}  "
        f"현재 활성 버전: {secret.get('active_version')}",
    ]
    connections = secret.get("connections") or []
    if connections:
        lines.append(f"  연결: {', '.join(str(c) for c in connections)}")
    targets = secret.get("targets") or []
    target_labels = []
    for target in targets:
        if not isinstance(target, dict):
            continue
        host, port = target.get("host"), target.get("port")
        if host is None:
            continue
        label = f"{host}:{port}" if port is not None else str(host)
        if target.get("username"):
            label = f"{target['username']}@{label}"
        target_labels.append(label)
    if target_labels:
        lines.append(f"  대상: {', '.join(target_labels)}")
    if mandatory:
        lines.append(f"  첫 사용: {secret.get('first_used') or '없음'}  마지막 사용: {secret.get('last_used') or '없음'}  "
                     f"사용 횟수: {secret.get('use_count', 0)}")
    steps = _KIND_STEPS.get(secret.get("kind"), ("공급자와 협의해 이 자격증명을 교체하십시오.",))
    fingerprint = secret.get("fingerprint") or "알 수 없음"
    for i, step in enumerate(steps, start=1):
        lines.append(f"  {i}. {step.format(fingerprint=fingerprint)}")
    return lines


def render_incident_email(incident: "I.Incident", *, now: str) -> tuple[str, str]:
    """§6.2: subject + plain-text Korean body, built only from the incident's own structured
    fields.  Deterministic and pure -- ``now`` is passed in rather than read from a clock so the
    same incident always renders identically."""
    subject = f"[ZeroPW] 침입 감지 — 서비스 정지, 자격증명 교체 필요 (사건 {incident.id})"

    assessment = incident.assessment or {}
    secrets = assessment.get("secrets", []) if isinstance(assessment, dict) else []
    mandatory = [s for s in secrets if isinstance(s, dict) and s.get("tier") == "mandatory"]
    recommended = [s for s in secrets if isinstance(s, dict) and s.get("tier") == "recommended"]

    lines: list[str] = []
    lines.append(f"안내 생성 시각: {now}")
    lines.append("")

    # 1. 무슨 일이 있었나
    lines.append("1. 무슨 일이 있었나")
    lines.append(f"사건 ID: {incident.id}")
    lines.append(f"사건 시각: {incident.opened_at}  (판정 방식: {incident.trigger})")
    scope_label = {"principal": "호출 주체", "runtime": "실행 환경", "all": "전체"}.get(incident.scope, incident.scope)
    lines.append(f"봉쇄 범위: {scope_label}" + (f" (실행 환경: {incident.runtime})" if incident.runtime else ""))
    if incident.rule:
        lines.append(f"판정 규칙: {incident.rule}")
    lines.append("침해된 호출 주체:")
    lines.extend(_principal_lines(incident))
    lines.append("")

    # 2. ZeroPW가 이미 한 것
    actions = incident.actions or {}
    lines.append("2. ZeroPW가 이미 한 것")
    lines.append(f"전체 정지: {'예' if actions.get('stopped') else '아니오'}")
    lines.append(f"비활성화된 호출 주체 수: {actions.get('principals_disabled', 0)}")
    lines.append(f"회수한 권한 수: {actions.get('grants_revoked', 0)}")
    lines.append(f"핸들 키 교체: {'예' if actions.get('handle_key_rotated') else '아니오'}")
    lines.append(f"취소한 실행 수: {actions.get('runs_cancelled', 0)}")
    lines.append(f"닫은 서명기 소켓 수: {actions.get('sockets_closed', 0)}")
    lines.append("")

    # 3. 지금 해야 할 것 -- 필수 교체
    lines.append("3. 지금 해야 할 것 — 필수 교체")
    if mandatory:
        for secret in mandatory:
            lines.extend(_secret_block(secret, mandatory=True))
            lines.append("")
    else:
        lines.append("필수 교체 대상이 없습니다.")
        lines.append("")

    # 4. 권장 교체
    lines.append("4. 권장 교체")
    if recommended:
        for secret in recommended:
            lines.append(f"* 비밀 ID: {secret.get('secret_id')}  (종류: {secret.get('kind')}) "
                         f"- 사용 기록 없이 권한만 보유")
        lines.append("")
    else:
        lines.append("권장 교체 대상이 없습니다.")
        lines.append("")

    # 5. 실행 환경
    lines.append("5. 실행 환경")
    if incident.scope in ("runtime", "all"):
        lines.append("침해된 실행 환경(호스트)을 폐기하고 새로 구축하십시오. 기존 호출 주체의 토큰은 되살아나지 않습니다.")
    else:
        lines.append("실행 환경 자체의 침해를 배제할 수 없다면, 같은 실행 환경에 새 호출 주체를 만들기 전에 "
                     "그 실행 환경을 재구축하고 다음 명령으로 범위를 넓히십시오:")
        lines.append(f"  incident escalate --id {incident.id} --scope runtime|all")
        lines.append("기존 호출 주체의 토큰은 되살아나지 않습니다.")
    lines.append("")

    # 6. 복구 명령
    lines.append("6. 복구 명령")
    lines.append(f"  incident show --id {incident.id}")
    lines.append("  (위 필수 교체를 모두 완료한 뒤)")
    lines.append(f"  incident close --id {incident.id}")
    lines.append("  principal create --runtime <실행 환경 ID>")
    lines.append("  grant create --principal <새 호출 주체 ID> --connection <연결 ID>")
    lines.append("  resume")
    if incident.scope == "all" or assessment.get("recover_required"):
        lines.append("")
        lines.append("이 사건은 금고 전체 노출로 판정되었습니다. `incident close` 전에 다음을 수행하십시오:")
        lines.append("  recover   (새 KMS 키, 권한 전부 회수, 핸들 키 교체)")
        lines.append("  관리자 패스프레이즈와 복구 패스프레이즈를 모두 변경하십시오.")

    body = "\n".join(lines) + "\n"
    return subject, body


# ---------------------------------------------------------------- delivery
def _audit_notify(ctx: Any, incident: "I.Incident", *, result: str, reason: str) -> None:
    try:
        ctx.audit.record("incident_notify", result=result, reason=reason,
                         extra={"incident_id": incident.id, "scope": incident.scope, "runtime": incident.runtime})
    except AuditUnavailable:
        failed = incident.actions.setdefault("failed_steps", [])
        if "audit_incident_notify" not in failed:
            failed.append("audit_incident_notify")


def _rendered_value_leak(ctx: Any, subject: str, body: str) -> bool:
    try:
        values = ctx.vault.values_for_trusted_scan()
    except Exception:
        values = []
    patterns: list[bytes] = []
    for value in values:
        patterns.extend(credential_patterns(value))
    if not patterns:
        return False
    return contains_sensitive((subject + "\n" + body).encode("utf-8"), patterns)


def _send(config: NotifyConfig, subject: str, body: str) -> None:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = config.sender
    message["To"] = ", ".join(config.recipients)
    message.set_content(body)

    password: str | None = None
    if config.password_file:
        password = Path(config.password_file).read_text(encoding="utf-8").strip()
    try:
        if config.mode == "smtps":
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(config.host, config.port, timeout=config.timeout_seconds,
                                  context=context) as client:
                if config.username:
                    client.login(config.username, password or "")
                client.send_message(message)
        elif config.mode == "starttls":
            context = ssl.create_default_context()
            with smtplib.SMTP(config.host, config.port, timeout=config.timeout_seconds) as client:
                client.starttls(context=context)
                if config.username:
                    client.login(config.username, password or "")
                client.send_message(message)
        else:  # plain
            with smtplib.SMTP(config.host, config.port, timeout=config.timeout_seconds) as client:
                if config.username:
                    client.login(config.username, password or "")
                client.send_message(message)
    finally:
        password = None  # never retained past this call, never logged


def _record_pending(ctx: Any, incident: "I.Incident", reason: str) -> "I.Incident":
    prev = dict(incident.notification or {})
    attempts = int(prev.get("attempts", 0)) if isinstance(prev.get("attempts"), int) else 0
    delay = min(2 ** attempts, MAX_BACKOFF_SECONDS)
    incident.notification = {
        "status": "pending", "attempts": attempts + 1, "last_error": reason,
        "next_attempt_at": ctx.clock() + delay,
    }
    _audit_notify(ctx, incident, result="denied", reason=reason)
    I.save_incident(ctx, incident)
    return incident


def _record_terminal_failure(ctx: Any, incident: "I.Incident", reason: str) -> "I.Incident":
    prev = dict(incident.notification or {})
    attempts = int(prev.get("attempts", 0)) if isinstance(prev.get("attempts"), int) else 0
    incident.notification = {"status": "failed", "reason": reason, "attempts": attempts}
    _audit_notify(ctx, incident, result="denied", reason=reason)
    I.save_incident(ctx, incident)
    return incident


def deliver(ctx: Any, incident: "I.Incident") -> "I.Incident":
    """Render, scan, and send the replacement-guidance email for ``incident`` (§6, §4.4 step 8).

    Mutates and persists ``incident.notification`` in place and returns the same object.  Never
    raises: every failure mode (unconfigured, insecure/invalid config, a rendered value, a
    transient SMTP/socket/TLS failure) is recorded on the incident and audited instead.
    """
    try:
        config = NotifyConfig.load(ctx)
    except InvalidInput as exc:
        return _record_pending(ctx, incident, exc.reason)

    if config is None:
        incident.notification = {"status": "not_configured",
                                 "attempts": (incident.notification or {}).get("attempts", 0)}
        _audit_notify(ctx, incident, result="ok", reason="not_configured")
        I.save_incident(ctx, incident)
        return incident

    subject, body = render_incident_email(incident, now=iso(ctx.clock()))
    if _rendered_value_leak(ctx, subject, body):
        return _record_terminal_failure(ctx, incident, "rendered_value_detected")

    try:
        _send(config, subject, body)
    except (OSError, smtplib.SMTPException) as exc:
        return _record_pending(ctx, incident, type(exc).__name__)

    incident.notification = {
        "status": "sent", "attempts": (incident.notification or {}).get("attempts", 0) + 1,
        "sent_at": iso(ctx.clock()),
    }
    _audit_notify(ctx, incident, result="ok", reason="sent")
    I.save_incident(ctx, incident)
    return incident


def retry_pending(ctx: Any, now: float) -> int:
    """Retry the open incident's ``notification`` if it is ``pending`` and due.  Called every
    ``serve`` poll (``admin_cli.run_serve``, every 0.25s) -- at most one incident can ever be open
    at a time (``Policy.open_incident_id``/``set_open_incident`` is a single pointer, not a set),
    so this reads that one pointer instead of scanning every incident file on every poll.  Returns
    how many deliveries were attempted (0 or 1)."""
    incident_id = ctx.policy.open_incident_id()
    if not incident_id:
        return 0
    try:
        inc = I.get_incident(ctx, incident_id)
    except NotFound:
        return 0  # a stale pointer (incident file lost); nothing to retry
    if inc.status != "open":
        return 0
    notification = inc.notification or {}
    if notification.get("status") != "pending":
        return 0
    next_attempt = notification.get("next_attempt_at")
    if not isinstance(next_attempt, (int, float)) or next_attempt > now:
        return 0
    deliver(ctx, inc)
    return 1


# ------------------------------------------------------------------- CLI hook
def send_test_message(ctx: Any) -> dict[str, Any]:
    """``incident notify-test``: send a short message through the same delivery path used for
    a real incident, so an operator can verify SMTP configuration without declaring one.  Always
    audited as ``incident_notify``."""
    try:
        config = NotifyConfig.load(ctx)
    except InvalidInput as exc:
        _audit_test(ctx, result="denied", reason=exc.reason)
        return {"status": "config_invalid", "reason": exc.reason}
    if config is None:
        _audit_test(ctx, result="ok", reason="not_configured")
        return {"status": "not_configured"}
    subject = "[ZeroPW] 알림 설정 시험 메시지"
    body = ("ZeroPW 알림 설정을 확인하기 위한 시험 메시지입니다.\n"
           "실제 침입 사건이 아닙니다. 이 메시지가 도착했다면 SMTP 설정이 올바르게 동작합니다.\n")
    try:
        _send(config, subject, body)
    except (OSError, smtplib.SMTPException) as exc:
        _audit_test(ctx, result="denied", reason=type(exc).__name__)
        return {"status": "failed", "error": type(exc).__name__}
    _audit_test(ctx, result="ok", reason="sent")
    return {"status": "sent"}


def _audit_test(ctx: Any, *, result: str, reason: str) -> None:
    try:
        # "kind": "notify_test" distinguishes this from a real incident's incident_notify record
        # (which always carries an incident_id) without inventing a fake incident id for one.
        ctx.audit.record("incident_notify", result=result, reason=reason, extra={"kind": "notify_test"})
    except AuditUnavailable:
        pass
