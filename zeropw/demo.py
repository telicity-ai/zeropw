"""One-command ZeroPW demonstration with synthetic credentials only.

``python3.12 -m zeropw.demo`` builds a throw-away state directory, starts a
controlled fake upstream API, the trusted ZeroPW process (gateway + tools +
SSH signer), configures one HTTP connection and one SSH connection, and then
acts as an agent that only holds a caller token.  It shows:

* one connection, many operations: two API requests and two CLI runs on the
  same connection with no per-operation registration;
* the placeholder credential sent by the sample CLI never reaches the
  upstream; the gateway inserts the real synthetic credential instead;
* extraction and reflection attempts fail closed (echoed headers, debug
  endpoints, redirects, cookies, method outside the scope, a risky method
  without approval);
* SSH: the signer signs only a bound authentication request and refuses
  arbitrary data, unknown destinations and forwarding;
* revocation and global stop take effect immediately;
* the synthetic credential appears nowhere the agent can see: tool
  responses, CLI output, the run environment, the audit log, server logs.

Everything runs on 127.0.0.1 and is deleted afterwards.  Exit status 0 means
every check passed.  This is a demonstration of the prototype's behaviour,
not a security certification.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import socket
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import Any

from . import agent_cli, policy as P, signer, sshwire, tools
from .context import Config, Context
from .crypto import ed25519
from .fake_upstream import FakeUpstream
from .server import ZeroPWServer

ADMIN_PASSPHRASE = "demo-admin-passphrase"
RECOVERY_PASSPHRASE = "demo-recovery-passphrase"
DEMOCLI = Path(__file__).resolve().parent.parent / "examples" / "democli.py"


class Demo:
    def __init__(self, out: Any = None) -> None:
        self.out = out or sys.stdout
        self.failures: list[str] = []
        self.checks = 0
        self.visible: list[str] = []  # everything the "agent" side ever saw

    # ------------------------------------------------------------ output
    def say(self, text: str) -> None:
        self.out.write(text + "\n")
        self.out.flush()

    def check(self, condition: bool, label: str) -> bool:
        self.checks += 1
        mark = "PASS" if condition else "FAIL"
        self.say(f"  [{mark}] {label}")
        if not condition:
            self.failures.append(label)
        return condition

    def seen(self, payload: Any) -> Any:
        self.visible.append(json.dumps(payload, sort_keys=True, default=str))
        return payload

    # ------------------------------------------------------------ helpers
    def call(self, tool: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        status, body = agent_cli.call_tool(self.server.url, self.caller_token, tool, payload)
        self.seen({"tool": tool, "status": status, "body": body})
        return status, body

    def wait_run(self, run_id: str, timeout: float = 30.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            _status, body = self.call("status", {"run_id": run_id})
            if body.get("state") in ("completed", "failed", "cancelled", "blocked"):
                return body
            if time.monotonic() > deadline:
                return body
            time.sleep(0.1)

    # ------------------------------------------------------------ phases
    def setup(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="zeropw-demo-"))
        self.say(f"[1] 상태 디렉터리와 신뢰 프로세스 준비: {self.root}")
        self.ctx = Context.initialize(self.root / "state", ADMIN_PASSPHRASE, RECOVERY_PASSPHRASE, Config(handle_ttl_seconds=300))
        self.ctx.projects.create("demo")
        self.synthetic = "synthetic-token-" + secrets.token_hex(12)
        self.ctx.vault.put_secret("gh-token", "api_key", self.synthetic.encode(), "demo", "dev")

        self.upstream = FakeUpstream(self.synthetic, "bearer").start()
        self.say(f"    시험용 외부 API: {self.upstream.url} (합성 토큰만 인증)")

        program_dir = self.root / "cli"
        program_dir.mkdir(mode=0o700)
        program = program_dir / "democli.py"
        shutil.copy(DEMOCLI, program)
        os.chmod(program, 0o700)
        self.ctx.policy.create_connection(P.Connection(
            id="gh", project="demo", environment="dev", service="fake-code-host", kind="http",
            secret_id="gh-token", secret_version=None, description="데모 코드 호스팅 API 연결",
            http_target=P.HttpTarget("http", "127.0.0.1", self.upstream.port),
            http_auth=P.HttpAuth("bearer"),
            http_scope=P.HttpScope(("GET", "POST", "DELETE"), None, ("DELETE",)),
            ssh_target=None, cli=P.CliProfile(str(program), "http"),
            policy_version=0, status="active", created_at="", updated_at=""))

        self.user_key = sshwire.generate_ed25519_private_key("demo-agent")
        self.host_key = sshwire.generate_ed25519_private_key("demo-box")
        self.ctx.vault.put_secret("box-key", "ssh_private_key", self.user_key.to_openssh_private_key().encode(), "demo", "dev")
        self.ctx.policy.create_connection(P.Connection(
            id="box", project="demo", environment="dev", service="ssh-box", kind="ssh",
            secret_id="box-key", secret_version=None, description="데모 SSH 목적지",
            http_target=None, http_auth=None, http_scope=None,
            ssh_target=P.SshTarget("demo-box.internal", 22, "deploy", (self.host_key.public.to_authorized_key("demo-box"),)),
            cli=None, policy_version=0, status="active", created_at="", updated_at=""))

        self.caller_token = self.ctx.policy.create_principal("agent-1")
        self.http_grant = self.ctx.policy.create_grant("agent-1", "gh", 600, 50)
        self.ssh_grant = self.ctx.policy.create_grant("agent-1", "box", 600, 10)

        self.server = ZeroPWServer(self.ctx).serve_in_thread()
        tools.install(self.ctx)
        tools.set_public_url(self.ctx, self.server.url)
        signer.install(self.ctx)
        self.say(f"    게이트웨이·도구 API: {self.server.url}")
        self.say("    에이전트가 받는 것: 게이트웨이 URL과 호출 토큰(zpwc_...)뿐. 금고 값은 없음.")

    def normal_flow(self) -> None:
        self.say("[2] 연결 한 번으로 여러 작업 (개별 등록 없음)")
        status, body = self.call("list_connections", {})
        ids = sorted(c["id"] for c in body.get("connections", []))
        self.check(status == 200 and ids == ["box", "gh"], f"list_connections -> {ids}")
        self.check("secret_id" not in json.dumps(body), "연결 목록에 비밀 참조·값 없음")

        status, body = self.call("request", {"connection": "gh", "method": "GET", "path": "/repos"})
        self.check(status == 200 and body["status"] == 200 and "demo" in (body.get("body") or ""), "request GET /repos -> 200")
        status, body = self.call("request", {"connection": "gh", "method": "POST", "path": "/repos/demo/issues",
                                             "body": json.dumps({"title": "hello from agent"})})
        self.check(status == 200 and body["status"] == 201, "request POST /repos/demo/issues -> 201")

        status, body = self.call("exec", {"connection": "gh", "argv": ["list-repos"]})
        run = self.wait_run(body.get("run_id", ""))
        self.seen(run)
        self.check(run.get("state") == "completed" and '"status": 200' in (run.get("stdout") or ""), "exec democli list-repos -> 200")
        status, body = self.call("exec", {"connection": "gh", "argv": ["create-issue", "demo", "issue via cli"]})
        run = self.wait_run(body.get("run_id", ""))
        self.seen(run)
        self.check(run.get("state") == "completed" and '"status": 201' in (run.get("stdout") or ""), "exec democli create-issue -> 201")

        auths = [r["headers"].get("authorization") for r in self.upstream.requests]
        self.check(all(a == f"Bearer {self.synthetic}" for a in auths) and len(auths) >= 4,
                   "업스트림은 매번 실제 합성 토큰만 받음 (자리표시자 democli-placeholder 없음)")

    def attacks(self) -> None:
        self.say("[3] 추출·반사·우회 시도")
        status, body = self.call("exec", {"connection": "gh", "argv": ["steal"]})
        run = self.wait_run(body.get("run_id", ""))
        self.seen(run)
        stdout = run.get("stdout") or ""
        self.check(run.get("state") == "completed" and self.synthetic not in stdout and "zpw1." not in stdout,
                   "democli steal: 환경·인자·홈 디렉터리에 비밀 없음 (핸들도 가려짐)")
        env_names = json.loads(stdout).get("env_names", []) if stdout.startswith("{") else []
        self.check("ZEROPW_API_BASE_URL" in env_names and not any(n.startswith("ZEROPW_STATE") for n in env_names),
                   f"자식 환경변수: {env_names}")

        cases = [
            ("GET", "/echo-headers", "credential_reflection_blocked", "헤더 반사 응답 차단"),
            ("GET", "/debug/token", "credential_reflection_blocked", "토큰 조회 엔드포인트 응답 차단"),
            ("GET", "/base64-leak", "credential_reflection_blocked", "base64 인코딩 반사 차단"),
            ("GET", "/set-cookie", "credential_reflection_blocked", "Set-Cookie 반사 차단"),
            ("GET", "/redirect", "redirect_not_followed", "리다이렉트 미추적 (Location 미전달)"),
            ("PUT", "/repos", "method_not_allowed", "허용 범위 밖 메서드 거부"),
        ]
        for method, path, reason, label in cases:
            status, body = self.call("request", {"connection": "gh", "method": method, "path": path})
            self.check(body.get("reason") == reason and self.synthetic not in json.dumps(body), f"{method} {path} -> {reason}: {label}")

        status, body = self.call("request", {"connection": "gh", "method": "DELETE", "path": "/repos/demo"})
        digest = body.get("approval_digest") or (json.loads(body["body"]).get("approval_digest") if body.get("body") else None)
        self.check(body.get("status") == 428 and bool(digest), "DELETE /repos/demo -> 428 승인 필요 (digest 발급)")
        if digest:
            self.ctx.policy.approve(digest)
            self.say("    관리자가 digest에 묶인 일회성 승인을 부여")
            status, body = self.call("request", {"connection": "gh", "method": "DELETE", "path": "/repos/demo"})
            self.check(body.get("status") == 204, "승인 후 같은 입력의 DELETE -> 204")
            status, body = self.call("request", {"connection": "gh", "method": "DELETE", "path": "/repos/demo"})
            self.check(body.get("status") == 428, "승인은 일회성: 재시도 -> 428")

        # A stolen handle cannot be pointed at another target; the connection fixes the target.
        handle = self.ctx.handles.issue("agent-1", "gh", self.http_grant.id, self.ctx.policy.get_connection("gh").policy_version, 60)
        conn = urllib.request.Request(f"{self.server.url}/h/{handle}/repos", headers={"Host": "evil.invalid"})
        with urllib.request.urlopen(conn, timeout=10) as response:
            self.check(response.status == 200, "Host 헤더 변조는 무시되고 고정 대상으로만 전달")
        raw = socket.create_connection(("127.0.0.1", self.server.server_address[1]), timeout=5)
        raw.sendall(b"CONNECT evil.invalid:443 HTTP/1.1\r\nHost: evil.invalid:443\r\n\r\n")
        reply = raw.recv(1024)
        raw.close()
        self.check(b" 405 " in reply.split(b"\r\n", 1)[0], "CONNECT 터널 거부")

    def ssh_demo(self) -> None:
        self.say("[4] SSH 서명 위임 (스크립트 클라이언트, sshd 없이)")
        binding = self.ctx.signer_manager.bind("agent-1", "box", self.ssh_grant.id)
        session_id = os.urandom(32)

        def connect() -> sshwire.AgentConnection:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(str(binding.socket_path))
            return sshwire.AgentConnection(sock)

        def bind_msg(host: sshwire.Ed25519PrivateKey, forwarding: bool = False) -> bytes:
            return sshwire.build_session_bind(host.public.blob(), session_id, sshwire.encode_ssh_signature(host.sign(session_id)), forwarding)

        userauth = sshwire.build_userauth_request(session_id, "deploy", "ssh-ed25519", self.user_key.public.blob())
        with connect() as conn:
            reply = conn.request(bytes([sshwire.SSH_AGENTC_REQUEST_IDENTITIES]))
            keys = sshwire.parse_identities_answer(reply[1:])
            self.check(len(keys) == 1 and keys[0][0] == self.user_key.public.blob(), "identities: 연결에 묶인 공개키 하나만 노출")
            self.check(conn.request(sshwire.build_sign_request(self.user_key.public.blob(), userauth)) == sshwire.build_failure(),
                       "세션 결합 전 서명 요청 거부")
            self.check(conn.request(bind_msg(self.host_key)) == sshwire.build_success(), "session-bind: 허용된 목적지 호스트 키 + 유효 서명")
            reply = conn.request(sshwire.build_sign_request(self.user_key.public.blob(), userauth))
            ok = reply[0] == sshwire.SSH_AGENT_SIGN_RESPONSE and ed25519.verify(
                self.user_key.public.key_bytes, userauth, sshwire.parse_ssh_signature(sshwire.parse_sign_response(reply[1:])))
            self.check(ok, "결합된 세션의 userauth 요청 서명 -> 유효")
            self.check(conn.request(sshwire.build_sign_request(self.user_key.public.blob(), b"arbitrary bytes")) == sshwire.build_failure(),
                       "임의 데이터 서명 거부")
            other_user = sshwire.build_userauth_request(session_id, "root", "ssh-ed25519", self.user_key.public.blob())
            self.check(conn.request(sshwire.build_sign_request(self.user_key.public.blob(), other_user)) == sshwire.build_failure(),
                       "다른 사용자 이름(root) 서명 거부")
            self.check(conn.request(bytes([sshwire.SSH_AGENTC_REMOVE_ALL_IDENTITIES])) == sshwire.build_failure(), "키 삭제 메시지 거부")
        impostor = sshwire.generate_ed25519_private_key("impostor")
        with connect() as conn:
            self.check(conn.request(bind_msg(impostor)) == sshwire.build_failure(), "다른 호스트 키로 session-bind 거부")
            self.check(conn.request(bind_msg(self.host_key, forwarding=True)) == sshwire.build_failure(), "agent forwarding 결합 거부")
        binding.close()
        self.say("    실제 sshd·ssh 종단 시험은 tests/test_ssh_e2e.py 참고")

    def revocation(self) -> None:
        self.say("[5] 회수와 전체 정지")
        self.ctx.policy.revoke_grant(self.http_grant.id)
        status, body = self.call("request", {"connection": "gh", "method": "GET", "path": "/repos"})
        self.check(body.get("reason") == "grant_revoked", "권한 회수 직후 request -> grant_revoked")
        self.ctx.policy.stop_all()
        status, body = self.call("list_connections", {})
        self.check(body.get("connections") == [], "전체 정지 중 list_connections -> 빈 목록")
        self.ctx.policy.resume()
        status, body = self.call("list_connections", {})
        self.check([c["id"] for c in body.get("connections", [])] == ["box"], "재개 후 남은 권한(box)만 보임")

    def sweep(self) -> None:
        self.say("[6] 유출 검사")
        encodings = {self.synthetic, base64.b64encode(self.synthetic.encode()).decode(), self.synthetic.encode().hex(),
                     urllib.parse.quote(self.synthetic, safe="")}
        visible = "\n".join(self.visible)
        self.check(not any(e in visible for e in encodings), "에이전트가 본 모든 도구 응답·실행 출력에 토큰 없음")
        state_text = "\n".join(p.read_text(errors="replace") for p in (self.root / "state").rglob("*") if p.is_file())
        self.check(not any(e in state_text for e in encodings), "상태 디렉터리 파일(감사 기록 포함)에 평문 토큰 없음")
        self.check(not any("zpw1." in line for line in self.server.log_lines), "서버 로그에 핸들 없음")
        raw_audit = (self.root / "state" / "audit" / "audit.jsonl").read_text()
        self.check("PRIVATE KEY" not in raw_audit and self.user_key.seed.hex() not in raw_audit, "감사 기록에 SSH 개인키 없음")
        self.say("    최근 감사 기록 (값 없음):")
        for record in self.ctx.audit.tail(12):
            self.say(f"      {record['ts']} {record['event']:<22} {record.get('result') or '':<8} {record.get('reason') or ''}")
        alerts = self.ctx.audit.alerts()
        self.say(f"    알림 {len(alerts)}건: {sorted(set(a['alert'] for a in alerts))}")

    def teardown(self) -> None:
        try:
            if getattr(self.ctx, "runs", None) is not None:
                self.ctx.runs.shutdown()
            if getattr(self.ctx, "signer_manager", None) is not None:
                self.ctx.signer_manager.shutdown()
            self.server.stop()
            self.upstream.stop()
        finally:
            shutil.rmtree(self.root, ignore_errors=True)
            for name in ("run_dir", "socket_dir"):
                path = getattr(self.ctx.config, name, None)
                if path and not str(path).startswith(str(self.root)):
                    shutil.rmtree(path, ignore_errors=True)

    def run(self) -> int:
        self.setup()
        try:
            self.normal_flow()
            self.attacks()
            self.ssh_demo()
            self.revocation()
            self.sweep()
        finally:
            self.teardown()
        if self.failures:
            self.say(f"\n{len(self.failures)}개 확인 실패 / 총 {self.checks}개:")
            for label in self.failures:
                self.say(f"  - {label}")
            return 1
        self.say(f"\n모든 확인 통과 ({self.checks}개). 합성 자격증명은 신뢰 프로세스 밖으로 나가지 않았다.")
        return 0


def main(argv: list[str] | None = None) -> int:
    return Demo().run()


if __name__ == "__main__":
    sys.exit(main())
