# ZeroPW v1 프로토타입 구현 현황

작성일: 2026-09-14 · 갱신 2026-09-16 (침해 대응: 자동 봉쇄·노출 판정·교체 안내 이메일 구현 반영) · 구현 기준 · 합성 자격증명과 통제된 시험용 서버만 사용

이 문서는 [제품 정의](product-intent.md)와 [인증 중계와 보안 경계](security-design.md)에 적힌 첫 버전 요구사항을 실제로 어디까지 실행 가능한 코드로 옮겼는지 기록한다. 제품 문서와 보안 기준 자체는 바꾸지 않았다. 여기 적힌 내용은 코드가 통과한 시험의 범위이며 보안 인증, Opus 리뷰 통과, 배포 준비 완료를 뜻하지 않는다.

## 1. 요약

`zeropw/` 패키지는 Python 3.11 이상 표준 라이브러리만으로 금고·정책·감사·HTTP 인증 중계기·SSH 서명기·에이전트 네이티브 도구·관리 CLI를 구현한다. 하나의 연결로 서로 다른 API 요청과 CLI 실행이 개별 등록 없이 동작하고, 원본 비밀은 신뢰 프로세스 밖으로 나가지 않는다. 에이전트 도구 `exec`가 실제 OpenSSH `ssh`를 띄워 서명기만으로 실제 `sshd`에 인증하는 종단 시험과, 관리 CLI·`serve`·에이전트 CLI를 각각 별도 OS 프로세스로 띄워 문서의 사용 흐름 전체를 도는 종단 시험(`tests/test_cli_e2e.py`)을 포함한다.

```sh
python3.12 -m unittest discover -s tests -p 'test_*.py' -v   # 전체 시험
python3.12 -m zeropw.demo                                       # 원커맨드 데모 (종료 코드 0 = 모든 확인 통과)
```

기존 CI의 "Run product tests when present" 단계가 `tests/`를 자동으로 실행한다. `sshd`를 일반 사용자로 띄울 수 없는 환경에서는 SSH 종단 시험을 건너뛰며 통과로 표시하지 않는다.

## 2. 구성 요소와 신뢰 영역

| 모듈 | 역할 | 신뢰 영역 |
| --- | --- | --- |
| `zeropw/crypto/chacha20poly1305.py`, `zeropw/crypto/ed25519.py` | RFC 8439 AEAD, RFC 8032 서명. 순수 Python, RFC 시험 벡터와 OpenSSH 상호운용으로 검증 | 신뢰 프로세스 |
| `zeropw/kms.py` | DEK 봉투 암호화. `LocalFileKms`는 관리형 KMS의 개발용 대체물 | 신뢰 프로세스 |
| `zeropw/vault.py` | 비밀 버전 관리, 신뢰 컴포넌트 전용 조회, 재인증이 필요한 단일 조회, 교체·백업·복원·복구 | 신뢰 프로세스 |
| `zeropw/policy.py` | 호출 주체, 연결, 권한(만료·사용량·정책 버전), 회수, 전체 정지, 위험 행위 승인 | 신뢰 프로세스 |
| `zeropw/audit.py` | 값 없는 감사 기록과 이상 사용 알림. 기록 실패 시 인증 거부 | 신뢰 프로세스 |
| `zeropw/handles.py` | 실행 환경에 주는 불투명 연결 핸들(HMAC 서명, 짧은 만료) | 발급은 신뢰 프로세스 |
| `zeropw/gateway.py` | HTTP 인증 중계기. 대상 고정, 자격증명 삽입, 응답 반사 차단, 중복 요청 원장 | 신뢰 프로세스 |
| `zeropw/signer.py`, `zeropw/sshwire.py` | SSH agent 프로토콜 서명기. session-bind 목적지 결합 | 신뢰 프로세스 |
| `zeropw/tools.py`, `zeropw/runs.py`, `zeropw/server.py` | `list_connections`·`request`·`exec`·`status`·`cancel` 도구 API와 실행 추적 | 신뢰 프로세스 |
| `zeropw/agent_cli.py`, `examples/democli.py` | 에이전트 쪽 얇은 클라이언트와 "지원 CLI" 예시 | 비밀 없는 실행 환경 |
| `zeropw/incident.py` | 침해 대응 사건 모델과 저장(`incidents/<id>.json`), 범위별 봉쇄(§4.4), 노출 판정(§5) | 신뢰 프로세스 |
| `zeropw/intrusion.py` | 감사 기록 스트림을 구독하는 자동 침입 탐지기. 강한·약한 신호 판정과 봉쇄 범위 결정(§4.2, §4.3) | 신뢰 프로세스 |
| `zeropw/notify.py` | 교체 안내 이메일 렌더링과 `smtplib` 발송, 실패 시 재시도(§6) | 신뢰 프로세스 |
| `zeropw/admin_cli.py` | 관리자 CLI (별도 신원, 패스프레이즈 재인증) | 관리자 |
| `zeropw/fake_upstream.py`, `zeropw/demo.py` | 합성 토큰을 검증하는 시험용 외부 API와 원커맨드 데모 | 시험·시연 전용 |

에이전트 프로세스가 받는 것은 게이트웨이 URL과 자기 호출 토큰(`zpwc_...`)이다. `exec`로 실행되는 CLI는 여기에 더해 연결 핸들이 들어간 base URL(`.../h/zpw1....`) 또는 서명기 소켓 경로를 받는다. 이 중 어느 것도 금고 값이 아니다. 핸들은 호출 주체·연결·권한·정책 버전에 묶인 짧은 수명의 사용 권한이며, 유출되면 회수 전까지 허용 범위 안에서 사용될 수 있다. 이는 제품 문서가 말한 "허용된 사용 권한과 원본 자격증명은 다르다"는 구분 그대로다.

## 3. 사용 흐름이 코드에서 어떻게 보이는가

1. 관리자가 `admin_cli init`으로 상태 디렉터리를 만든다. KMS 마스터 키, 금고 DEK, 관리자 패스프레이즈, 복구 패스프레이즈가 생긴다.
2. `project create`, `secret put`(값은 stdin 또는 파일로만), `connection create-http` 또는 `create-ssh`로 서비스·자격증명·대상·허용 범위를 연결 하나에 설정한다. 명령이나 API 작업을 등록하는 단계는 없다.
3. `principal create --runtime <id>`(기본 `default`)로 에이전트 신원을 만들고 `grant create`로 연결 사용 권한(만료, 사용량)을 준다. `--runtime`은 같은 실행 환경(호스트·컨테이너)에서 도는 호출 주체를 묶어, 침해 대응의 봉쇄 범위 판정에 쓰인다(§7).
4. `serve`로 신뢰 프로세스를 띄운다. 에이전트는 `agent_cli list-connections`로 쓸 수 있는 연결을 보고, `request`로 API를 호출하거나 `exec`로 지원 CLI를 실행한다.
5. 관리자는 `audit tail`, `alerts`로 사용을 보고 `grant revoke`, `principal disable`, `connection disable`, `stop-all`로 막는다. 관리 CLI는 `serve`와 별도 프로세스다. 변경은 상태 파일에 바로 기록되어 다음 중계·서명·실행에서 거부되고, 이미 진행 중인 실행과 열린 서명기 소켓에는 `serve`의 다음 폴링(0.25초 주기)에서 반영된다(§6).
6. `serve` 안의 탐지기가 침입 신호를 보면 스스로 사건을 열어 해당 범위를 봉쇄하거나(자동), 관리자가 `incident declare`로 직접 연다(수동). 사건이 열려 있는 동안 `resume`은 거부된다. 관리자는 `incident show`로 노출 판정을 보고 필수 교체를 마친 뒤 `incident close`(패스프레이즈 재인증)로 닫고, 새 `principal create`·`grant create`로 신원을 다시 만들어 `resume`으로 재개한다(§7).

## 4. HTTP 인증 중계

지원 프로토콜은 다음과 같다.

- 클라이언트는 상대 경로와 메서드, 본문만 보낸다. 대상 scheme·host·port는 연결에 고정되어 있고 클라이언트가 바꿀 수 없다. `Host` 헤더는 무시되고, 절대 URI 요청과 `CONNECT`는 거부된다.
- 경로에 `..`, `.`, 빈 세그먼트, 백슬래시, 제어 문자, 한두 단계 퍼센트 인코딩된 상위 경로 이동이 있으면 업스트림에 닿기 전에 거부한다. 쿼리 문자열은 전달하되 감사 기록과 로그에는 남기지 않는다.
- 요청 헤더는 허용 목록만 전달한다. `Authorization`, `Proxy-Authorization`, `Cookie`, `X-ZeroPW-*`, `Host`, hop-by-hop 헤더는 버린다. CLI가 보낸 자리표시자 토큰은 업스트림에 도달하지 않는다.
- 자격증명은 연결의 인증 방식(`bearer`, `basic`, 사용자 지정 `header`)에 따라 중계기 안에서만 삽입한다. 다른 방식, 또는 헤더에 넣을 수 없는 문자가 든 자격증명은 미지원 오류다.
- 리다이렉트는 따라가지 않고 `Location`을 돌려주지 않는다. 응답 헤더는 허용 목록만 통과하며 `Set-Cookie`, `WWW-Authenticate` 등은 제거한다. 압축 응답은 검사할 수 없으므로 거부한다.
- 응답 본문은 최대 8 MiB까지 버퍼링한다. 모든 응답 헤더와 본문에서 자격증명의 원문, base64(표준·URL 안전, 패딩 유무), 퍼센트 인코딩(대문자·소문자 16진수, 공백의 `+`·`%20`), 16진수(대·소문자), JSON 이스케이프, HTML 이스케이프, Basic 방식의 `base64(user:password)`를 찾는다. 발견되면 본문을 돌려주지 않고 `credential_reflection_blocked`로 막는다. 마스킹이 아니라 차단이다. 청크 응답은 버퍼링하며 스트리밍 통과는 지원하지 않는다.
- HTTPS는 서버 신원과 호스트 이름을 검증한다. 시험에서는 자체 서명 CA를 연결의 `ca_file`로 지정한다.
- 호스트 이름 대상은 요청마다 한 번 해석하고, 응답의 모든 주소를 검사한 뒤 검사한 주소로 직접 접속한다. 다시 해석하지 않으므로 검사와 접속 사이에 DNS 응답이 바뀌어도 소용없다. 해석과 검사는 일회성 승인 소비, 사용량 차감, 자격증명 조회보다 먼저 하므로, 거부되는 DNS 응답으로는 사용량·승인을 소모시키거나 자격증명을 복호화시키지 못한다. 루프백·사설망·CGNAT·사이트 로컬·예약·문서용 등 공인이 아닌 주소가 하나라도 섞이면 `target_address_not_allowed`로, 링크 로컬과 클라우드 메타데이터·자격증명 주소(AWS `fd00:ec2::/64`, GCP `fd20:ce::254`, OCI `fd00:c1::a9fe:a9fe`, Alibaba `100.100.100.200`, Azure `168.63.129.16` 포함)는 `metadata_address_not_allowed`로 전송 전에 거부하고 알림을 남긴다. IPv4 주소를 담는 IPv6 주소(NAT64 `64:ff9b::/96`·`64:ff9b:1::/48`, IPv4 호환 `::/96`, SIIT `::ffff:0:0:0/96`, 6to4, Teredo)는 담긴 IPv4 주소로도 같은 규칙을 적용하므로 `64:ff9b::169.254.169.254` 같은 응답도 거부된다. 공인 IPv4를 담은 잘 알려진 NAT64 주소는 허용한다. 내부 서비스처럼 사설 주소가 필요한 연결은 관리자가 `--allow-private-network`로 명시적으로 열며, 이 경우에도 메타데이터·링크 로컬 주소는 거부한다. 이 옵션을 켜는 변경은 권한 확대로 취급해 기존 권한을 `stale`로 만든다. IP 주소 대상은 관리자가 고른 값이라 DNS로 바뀌지 않으므로 메타데이터·링크 로컬·미지정·멀티캐스트 주소(IPv6 리터럴에 담긴 IPv4 주소 포함)만 설정 단계에서 거부한다. 이 검사가 생기기 전에 저장된 금지 리터럴 연결도 목록 조회와 비활성화가 되도록 읽히며, 사용할 때 전송 전에 거부되고 감사 기록이 남는다. HTTPS는 고정한 주소로 접속하면서 인증서와 SNI는 설정된 호스트 이름으로 검증한다. 대상이나 실제 접속 상대가 ZeroPW 자신이면 `self_referential_target`으로 거부한다.
- `X-ZeroPW-Request-Id`를 주면 호출 주체·요청 ID·입력 digest를 묶어 중복을 구분한다. 같은 ID에 다른 입력은 거부하고, 진행 중이거나 전송 뒤 결과가 불명확한 요청은 재시도하지 않고 409로 알린다. 완료된 요청은 저장된 결과를 재생한다.
- 연결의 `confirm_methods`에 든 메서드(예: `DELETE`)는 호출 주체·연결·메서드·경로·본문 digest에 묶인 일회성 승인이 필요하다. 승인 뒤 입력이 바뀌면 다시 승인해야 한다.
- 사용량은 정책 확인과 필수 감사 기록이 끝난 뒤, 자격증명을 꺼내기 전에 차감한다. 감사 기록에 실패하면 차감도 전송도 하지 않는다.

## 5. SSH 서명 위임

서명기는 OpenSSH agent 프로토콜을 Unix 소켓(0600)으로 제공한다. 소켓은 `exec` 실행마다 (호출 주체, 연결, 권한) 하나에 대해 새로 만들어지며 소켓 자체가 사용 권한이다.

- `REQUEST_IDENTITIES`는 연결에 묶인 Ed25519 공개키 하나만 돌려준다. 이때 평문 키는 읽지 않는다.
- OpenSSH 8.9 이상 클라이언트가 보내는 `session-bind@openssh.com`을 검증한다. 제시된 호스트 키가 연결의 목적지 호스트 키 목록에 있고, 그 호스트 키가 세션 ID에 한 서명이 유효하며, forwarding 표시가 아니고, 같은 클라이언트 연결에서 첫 결합일 때만 받아들인다.
- 서명은 정확히 한 종류의 데이터에만 한다. 엄격히 파싱된 `SSH_MSG_USERAUTH_REQUEST`로, 세션 ID(및 hostbound 변형의 호스트 키)가 결합된 세션과 같고, 사용자 이름이 연결의 사용자와 같고, 알고리즘과 키가 연결의 키와 같아야 한다. 서명 직전에 정책(회수·만료·사용량·전체 정지·복원 대기)을 다시 확인하고 감사 기록을 먼저 쓴다.
- 키 추가·삭제·잠금·스마트카드·프로토콜 1 메시지, 임의 데이터 서명(`ssh-add -T`), 결합 전 서명 요청, 두 번째 결합, forwarding 결합은 모두 `SSH_AGENT_FAILURE`다. 개인키 내보내기는 프로토콜에 존재하지 않는다.
- 권한 회수, 호출 주체·연결 비활성화, 전체 정지, 복원 대기는 해당 소켓을 닫는다. 같은 프로세스에서 `Policy`를 호출하면 회수 알림으로 바로 닫고, 별도 프로세스인 관리 CLI의 변경은 `serve`가 폴링 주기(`SERVE_POLL_SECONDS`, 0.25초)마다 열린 소켓의 (호출 주체, 연결, 권한)을 상태 파일로 다시 확인해 닫는다. 그 사이의 서명 요청은 서명 직전 정책 재확인에서 거부된다.
- `exec`는 SSH 연결에 대해 프로그램을 연결 프로필의 `ssh`로 고정하고 `-F /dev/null`로 사용자·시스템 설정을 무시한다. 실행 디렉터리에는 관리되는 `known_hosts`와 연결 키의 공개키 한 줄만 담긴 `id.pub`를 쓰고 `IdentitiesOnly=yes`, `IdentityAgent=<소켓>`, `ForwardAgent=no`, `StrictHostKeyChecking=yes`, `BatchMode=yes`로 실행한다. 에이전트는 원격 명령 인자만 정한다.
- `tests/test_ssh_e2e.py`는 실제 `sshd`를 일반 사용자로 127.0.0.1의 임시 포트에 띄운다. 실제 `ssh`가 서명기만으로 인증해 원격 명령 두 개를 실행하고, 에이전트 도구 `exec`로도 같은 연결에서 서로 다른 명령 두 개를 실행한다. `exec` 시험은 `ssh` 앞에 둔 기록용 래퍼로 자식이 본 실행 디렉터리의 파일(`id.pub`, `known_hosts`만)과 환경변수 전체를 기록해, 개인키(PEM, 디코딩한 키 블롭, 시드)가 어떤 인코딩으로도 없음을 확인한다. 연결에 다른 호스트 키를 설정하면 결합이 거부되어 인증이 실패하고, 권한을 회수하면 소켓이 사라지고 `exec`가 거부된다.

session-bind를 보내지 않는 클라이언트(OpenSSH 8.9 미만, 대부분의 비 OpenSSH 클라이언트)는 서명을 받지 못한다. 이는 문서의 "검증할 수 없는 클라이언트는 미지원" 규칙을 그대로 적용한 것이다.

## 6. 실행·정책·생명주기

- **실행 격리:** `exec` 자식의 작업 디렉터리·`HOME`·`TMPDIR`와 서명기 소켓 디렉터리는 상태 디렉터리 밖의 새 0700 임시 디렉터리에 둔다. 상태 디렉터리 안을 명시적으로 지정하면 `Context`가 거부한다. 자식 환경변수는 `PATH`, `HOME`, `LANG`, `TMPDIR`, `ZEROPW_RUN_ID`, 핸들이 든 base URL 변수(HTTP) 또는 `SSH_AUTH_SOCK`(SSH), 관리자가 연결 프로필에 지정한 추가 변수뿐이다.
- **CLI 프로필 환경변수 검사:** `exec`는 실행 디렉터리·핸들·서명기 소켓을 만들기 전에 프로필의 base URL 변수 이름과 추가 변수의 이름·값에 금고 값이 원문, base64(표준·URL 안전), 16진수, URL 인코딩 형태로 들어 있는지 검사한다. 대조 대상은 연결의 자격증명만이 아니라 금고에 있는 모든 비밀(다른 프로젝트 포함)의 모든 버전(은퇴·폐기 버전 포함)이다. 들어 있으면 감사 기록을 남기고 `cli_env_contains_credential`로 거부하며 자식을 띄우지 않는다. 관리 CLI도 같은 검사를 연결 생성 때(모든 비밀의 모든 버전과 대조)와 `secret put`·`rotation start`로 새 버전을 넣을 때(비밀 ID와 관계없이 모든 연결의 추가 변수와 대조) 수행해, 일치하면 저장 전에 거부한다. 검사와 저장은 상태 잠금 하나 안에서 일어나므로 동시에 실행된 연결 생성과 `secret put`이 서로의 검사를 비켜 가지 못한다. 오류에는 연결 ID만 담고 값은 담지 않는다.
- **실행 직전 재확인:** 실행은 먼저 등록되어 회수·정지 알림이 취소할 수 있고, 자식을 띄우기 직전에 정책을 다시 평가한다. 그 사이 회수·정지·사용량 소진이 일어나면 자식을 띄우지 않는다.
- **진행 중인 실행에 회수 반영:** 같은 프로세스에서 `Policy`로 회수·비활성화·범위 확대·전체 정지·복원 대기를 걸면 회수 알림이 실행 기록과 서명기에 바로 전달된다. 관리 CLI는 별도 프로세스라 이 알림이 닿지 않는다. 그래서 `serve`는 0.25초마다 상태 파일을 다시 읽어, 대기·진행 중인 실행과 열린 서명기 소켓마다 (호출 주체, 연결, 권한)이 아직 쓸 수 있는지 확인한다. 권한 회수, 범위 확대로 인한 `stale`, 호출 주체·연결 비활성화, 전체 정지, 복원 대기로 권한이 사라졌으면 그 실행을 취소(`run_cancel` 감사 기록)하고 그 소켓을 닫는다. SSH 실행의 취소는 로컬 `ssh` 클라이언트 프로세스를 끝내는 것이다. 원격 명령은 가상 터미널 없이 실행되므로 클라이언트가 끊겨도 `sshd`가 신호를 보내지 않고, 서버에서 이미 돌고 있는 원격 명령은 스스로 끝날 때까지 계속된다(보안 설계 §5의 한계). 만료와 사용량 소진은 진행 중인 실행을 취소하지 않고 다음 중계·서명에서 거부한다. 복원·복구로 핸들 키가 바뀌면 `serve`가 새 키를 읽어 이전 핸들을 무효로 만든다.
- **실행 출력 검사:** 자식의 출력에 자격증명이나 핸들이 알려진 인코딩(원문, 표준·URL 안전 base64, 16진수, URL 인코딩)으로 나오면 출력을 고정 문구로 바꾸고 `blocked`로 표시한다. 뒤집기·분할 같은 다른 변형은 잡지 못한다(§9). 자식은 애초에 자격증명을 갖지 않으므로 자격증명에 대해서는 보조 방어다.
- **중복 실행:** `exec`의 요청 ID 조회와 등록은 하나의 잠금 안에서 일어나 같은 요청의 동시 호출은 실행 하나로 합쳐진다.
- **기본값은 거부:** 권한은 호출 주체·연결·만료·사용량·정책 버전에 묶이고 모든 중계·서명·실행 직전에 다시 평가한다.
- **정책 변경:** 연결의 대상, 인증 방식, 허용 범위가 넓어지는 변경은 기존 권한을 `stale`로 만들어 자동 승계를 막는다. 범위 축소와 자격증명 교체는 권한을 제자리에서 재평가한다. 정책 버전이 바뀌면 이전 핸들은 무효다.
- **전체 정지:** `stop-all`은 새 중계·서명·실행을 거부하고 대기·진행 중인 실행을 취소하며 서명기 소켓을 닫는다. 이미 인증된 SSH 세션을 끊지는 못한다. 이는 보안 설계 §5의 한계 그대로다.
- **백업·복원:** 백업은 금고 문서(암호문, KMS와 복구 패스프레이즈로 이중 봉투된 DEK, SSH 키의 공개키 정보)와 프로젝트·정책 문서를 담는다. 비밀 값의 평문이나 해시는 담지 않는다. 다만 암호문 길이로 값의 길이가 드러난다. CLI 프로필 추가 변수는 비밀이 아닌 설정이라 정책 문서에 평문으로 들어가며, 관리 CLI는 자격증명과 일치하는 값을 저장 전에 거부한다(§6). 복원은 현재 KMS로 풀 수 없는 백업을 쓰기 전에 거부한다. 복원 뒤에는 `restore_pending`으로 모든 인증을 막고, 복원 시점에 켜져 있던 전체 정지는 유지한다. 관리자가 최신 회수 상태를 반영한 뒤 `restore-ack`로 복원 대기만 풀고, 정지는 `resume`으로 따로 푼다.
- **복구:** 복구 패스프레이즈로 DEK를 풀어 새 KMS 키로 다시 감싸고, 모든 권한을 회수하며 핸들 키를 교체한다. KMS 키와 복구 패스프레이즈를 모두 잃으면 복구할 수 없다.
- **단일 비밀 조회:** `secret reveal`은 관리자 패스프레이즈 재인증과 감사 기록을 요구하고 알림을 남긴다. 일괄 평문 내보내기는 없다. 비밀 목록에는 SSH 공개키 정보 외에 값에서 파생한 메타데이터가 없다.
- **교체:** 새 버전 등록(`rotation start`), 활성화와 연결 전환(`rotation activate`), 이전 버전 은퇴(`rotation finish`) 순서다. 외부 공급자 쪽 폐기는 금고가 대신하지 못하므로 CLI가 이를 상기시킨다.

## 7. 침해 대응

[침해 대응 설계](compromise-response.md) §9 단계 1-5를 구현한 것이다: 실행 환경이 완전히 장악됐다는 가정 아래 신뢰 프로세스가 스스로 침입을 판정해 봉쇄하고, 노출된 자격증명의 교체를 관리자에게 이메일로 안내한다. 아래는 코드가 실제로 하는 일과 그것을 증명하는 시험이며, §9의 한계대로 완전한 탐지나 보안 인증을 뜻하지 않는다.

- **사건 모델과 파일 (`zeropw/incident.py`).** 사건은 `<상태 디렉터리>/incidents/<id>.json`에 값 없는 JSON으로 저장된다: id, 시각, 상태(`open`/`closed`), 범위, 실행 환경, 범위 안 호출 주체 목록, 판정 트리거(`manual`/`auto`), 규칙, 조치 집계(`actions`), 노출 판정(`assessment`), 알림 상태(`notification`). 매 쓰기 전에 직렬화한 결과를 금고의 모든 비밀(모든 버전)과 대조하고, 값이 섞여 있으면(있어서는 안 되지만) 판정을 `{"redacted": true}`로 바꿔 대신 쓴다(`zeropw.runs`가 실행 출력에 쓰는 것과 같은 반사 검사 패턴). 사건이 열리면 정책 제어 문서에 `incident_open` 플래그가 켜지고(`Policy.set_open_incident`), 이 플래그가 있는 동안은 범위와 무관하게 `resume`이 `incident_open` 오류로 거부된다. 사건을 닫아도(`incident close`) 이 플래그만 내려갈 뿐 전체 정지 자체는 풀리지 않는다 — `resume`은 별도 명령이다.

- **범위와 봉쇄 (`open_incident`/`widen_incident`).** 범위는 `principal`(그 호출 주체만), `runtime`(같은 실행 환경의 모든 호출 주체), `all`(전체)이다. `stop_all`은 범위가 `all`이거나, 범위가 `runtime`이면서 그 실행 환경이 현재 활성 호출 주체 전부를 포함할 때만 실행된다 — 그 밖의 `runtime` 범위와 모든 `principal` 범위는 범위 밖 호출 주체를 막지 않는다. 범위 안 호출 주체는 모두 비활성화되고(`disable_principal`) 권한이 회수된다(`revoke_grants_of`). 핸들 키 교체(`rotate_handle_key`)는 `runtime`·`all` 범위에서만 한다 — 핸들 키는 하나뿐이라 교체가 범위 밖 호출 주체의 핸들까지 무효로 만들기 때문에 `principal` 범위에서는 하지 않는다. 진행 중인 실행 취소와 서명기 소켓 닫기는 호출 주체를 비활성화하기 *전에* 찍은 스냅숏을 기준으로 그 안의 각 실행·소켓에 정확히 `cancel`/`release`를 호출해 세므로, §6에서 말한 "회수 알림에 대상이 없어 전부 취소"하는 과잉 취소와 달리 정밀하다. `serve`가 붙어 있지 않은 프로세스(관리 CLI 자신의 `incident declare`)에서 사건이 선언되면 `ctx.runs`/`ctx.signer_manager`가 없어 이 스냅숏이 항상 비어 있고, 대신 조치 집계에 `applied_by_serve: true`가 남는다 — 실제 취소와 소켓 닫기는 그때 떠 있는 `serve`가 다음 폴링(`_enforce_withdrawn_permissions`, 0.25초 주기)에서 사라진 권한을 찾아 수행한다. 사건이 열린 뒤 더 넓은 범위에 해당하는 신호가 오면 `widen_incident`가 새로 추가된 호출 주체에만 봉쇄를 다시 적용하고 노출 판정을 새로 만들어 이메일을 한 통 더 보낸다; 범위를 좁히는 경로는 없다.

- **노출 판정 (`assess`).** 시작점은 범위 안 각 호출 주체 자신의 토큰 생성 시각이며 시간 창은 없다. 그 시각 이후 `http_relay`·`ssh_sign`이 `ok`였거나 `run_start`가 있었던 연결은 "필수 교체"(`mandatory`)다. 사용 기록은 없지만 침해된 호출 주체가 `active`·`stale` 권한을 가졌거나 이 사건 자신의 봉쇄가 사건이 열린 뒤(`revoked_at >= opened_at`) 회수한 권한을 가졌던 연결은 "권장 교체"(`recommended`)다. 후자의 기준을 사건이 열린 시각으로 두는 이유는, 노출 판정이 항상 4단계(권한 회수)가 이미 끝난 뒤 실행되어 기준이 없으면 모든 권한이 `revoked` 상태로만 보여 "권장"이 나올 수 없기 때문이다. `scope="all"`이면 연결 사용과 무관하게 활성 버전이 있는 금고의 모든 비밀이 "필수"가 되고 최상위 `recover_required` 플래그가 켜져(이메일이 `recover`와 패스프레이즈 교체를 추가로 안내) 신뢰 호스트 침해 전제를 반영한다. 판정은 감사 기록만 읽고 금고 값은 한 번도 열지 않는다; 그래도 직렬화한 결과를 금고의 모든 값과 대조해 값이 발견되면(있어서는 안 되지만) 기록 전에 판정을 `{"redacted": true}`로 바꾼다.

- **자동 탐지기 (`zeropw/intrusion.py`, `Detector`).** `Audit.subscribe`로 매 감사 기록 직후 동기 호출된다. 강한 신호(단독으로 봉쇄, 끌 수 있는 설정 없음)는 `unknown_tool`(`tools_unknown` 거부, 임계 2회), `handle_forgery`(`http_relay` 거부 사유 `handle_signature`/`handle_malformed`/`handle_version`, 임계 2회), `signer_misuse`(`ssh_agent_refused` 거부 `unsupported_agent_message`/`unsupported_extension`, `ssh_bind` 거부 `agent_forwarding_not_allowed`, `ssh_sign` 거부 `not_userauth_request`/`no_session_bind`/`unsupported_sign_flags`, 임계 1회), `output_exfiltration`(`run_finish` 결과 `blocked` 사유 `output_credential_blocked`, 임계 1회)다. 약한 신호(점수 누적, 기본 창 120초, 임계 8점)는 `revoked_use`(사유 `grant_revoked`/`grant_stale`/`principal_disabled`, 3점), `scope_violation`(`http_relay`·`tools_request`·`tools_exec` 거부 사유 `method_not_allowed`/`path_not_allowed`/`approval_required`, 1점), `unauthorized_connection`(`tools_request`·`tools_exec` 거부 사유 `no_grant`/`grant_unknown`/`connection_unknown`, 2점), `expired_handle`(`http_relay` 거부 `handle_expired`, 1점), `enumeration`(창 안에서 이 호출 주체가 *처음* 쓰는 연결 수가 4개 이상이면서 사용 가능한 연결의 절반 이상, 4점), `burst`(창 안 자격증명 요청 수 — `tools_request`·`tools_exec`·`http_relay`만이며 상태 조회·핸들 발급·실행 기록은 제외 — 60건 초과, 2점)다. `enumeration`·`burst`는 임계를 "넘을 때" 한 번만 가산하고(latch) 창이 지나 조건이 풀린 뒤에야 다시 가산해, 임계를 넘긴 채로 계속하는 사용이 점수를 무한히 쌓지 않게 한다. `global_stop`·`restore_pending`은 관리자가 한 번 걸면 이후 모든 호출 주체가 똑같이 거부되는 전역 상태라 개별 증거가 되지 못하므로 `revoked_use`에서 제외했다(`grant_revoked`/`grant_stale`/`principal_disabled`는 호출 주체별 증거이므로 포함). 호출 주체를 특정할 수 없는 신호(위조·변조·만료 핸들처럼 `caller` 없이 기록되는 거부)는 전역 버킷에 쌓이며, 그 임계 도달은 범위 `principal`로 *그 순간의 모든 활성 호출 주체*를 겨냥한다(`handle_forgery_unattributed`) — `all` 범위는 예약해 두지 않는다. 범위 판정은 트립한 규칙의 위치(`signer_misuse`·`output_exfiltration`는 실행 환경 자체 접근이 필요해 `runtime`, 나머지는 `http` 경로만으로 가능)를 보고, `http` 신호뿐이라도 같은 실행 환경의 다른 호출 주체가 창 안에서 함께 신호를 냈으면 `runtime`으로 올린다. 실제 봉쇄·확대는 항상 `open_incident`에 맡긴다(`widen_incident`를 직접 부르지 않는다): 이미 열린 사건이 같은 범위이거나 더 넓으면 아무 일도 하지 않는다. 동시성은 두 개의 락으로 다룬다 — 비재진입 `_lock`은 집계 딕셔너리만 보호하고 `open_incident` 호출 중에는 잡지 않으며, `open_incident` 자신이 감사를 남기며 재진입(`run_cancel` 등)하는 동안에는 스레드 로컬 플래그로 "집계는 하되 결정은 하지 않는다"를 지키고, 결정 단계 자체는 논블로킹 락으로 한 스레드만 수행해 동시에 트립한 두 신호가 사건을 두 번 열지 않게 한다.

- **알림 (`zeropw/notify.py`).** SMTP 설정은 `<상태 디렉터리>/notify.json`(0600, 현재 사용자 소유)에 `host`·`port`·`mode`(`starttls`·`smtps`·루프백 전용 시험 모드 `plain`)·`sender`·`recipients`·`username`·`password_file`·`timeout_seconds`로 담는다. 비밀번호는 별도 파일(0600, 같은 소유자 검사)에서 발송 시점에만 읽고 호출이 끝나면 버린다. `plain` 모드는 루프백 호스트(`127.0.0.1`·`::1`·`localhost`)에만 허용되고, 그 외 호스트에 `plain`을 쓰면 거부된다. `notify.json`이 없으면 "미설정"(`not_configured`)으로 봉쇄만 하고 이메일은 보내지 않는다; 권한·소유자·형식이 잘못됐거나 발송 자체가 실패하면 둘 다 `pending`으로 남겨 지수 백오프(1, 2, 4, ... 최대 300초)로 재시도하며, `serve`의 매 폴링이 열린 사건 하나(정책 제어 문서가 가리키는 포인터 하나뿐이므로 사건 파일을 훑지 않는다)의 대기 중인 알림만 확인해 보낸다. `render_incident_email`은 사건의 구조화된 필드만 읽는 순수 함수로 §6.2의 여섯 절(무슨 일이 있었나 / 이미 한 것 / 필수 교체 / 권장 교체 / 실행 환경 / 복구 명령)을 순서대로 만들고, 링크(`http://`·`https://`)를 넣지 않는다. 보내기 직전에 렌더링 결과를 금고 값과 대조해 값이 섞여 있으면(있어서는 안 되지만) 발송을 막고 사건을 `failed`로 남긴다(`rendered_value_detected`). 범위가 넓어질 때(`incident escalate` 또는 자동 확대)는 다시 보내지만 그 밖의 갱신은 새 이메일을 만들지 않는다. `incident notify-test`는 사건을 만들지 않고 같은 발송 경로로 짧은 확인 메시지만 보낸다. 모든 시도(성공·미설정·대기·값 검출 거부)는 수신자·주소 없이 `incident_notify` 감사 기록으로 남는다.

- **CLI.** `principal create --id <id> --runtime <id>`(기본 `default`)가 실행 환경 소속을 정한다. `incident declare --scope principal|runtime|all [--principal <id>] [--runtime <id>] [--reason TEXT]`로 수동 선언(`--scope all`은 관리자 패스프레이즈 재인증을 요구), `incident escalate --id <id> --scope runtime|all [--runtime <id>]`로 범위 확대(좁히는 방향은 없음), `incident list` / `incident show --id <id>`로 조회, `incident close --id <id>`(관리자 패스프레이즈 재인증; 정지 자체는 풀지 않음)로 닫기, `incident notify-test`로 SMTP 설정 확인을 한다.

## 8. 수용 시험 대응표

[보안 설계 §7](security-design.md)의 각 행이 어떤 시험으로 검증되는지 적는다.

| 검증할 행동 | 시험 |
| --- | --- |
| 연결 한 번으로 다양한 명령 실행 | `test_gateway` 정상 2요청 흐름, `test_tools`·`test_agent_cli`의 `exec`, `test_ssh_e2e`의 원격 명령 2개(직접 `ssh`와 `exec` 도구 모두), `test_cli_e2e`(별도 프로세스의 관리 CLI·`serve`·에이전트 CLI로 HTTP 요청 2종과 CLI 실행, 실제 `sshd`의 원격 명령 2개), `test_demo` |
| 에이전트의 원본 키 추출 시도 | `test_tools`(자식 환경·인자·작업 디렉터리·출력 검사, 상태 디렉터리 경로 비노출, 자격증명이 든 CLI 프로필 환경변수 거부 `test_cli_env_carrying_the_credential_is_refused_before_any_artefact`), `test_admin_cli`의 저장 시점 거부(`test_cli_env_holding_the_credential_is_refused_at_save_time`, `test_new_secret_version_matching_existing_cli_env_is_refused`), `examples/democli.py steal`, `test_cli_e2e`의 에이전트 출력·`serve` 출력·상태 디렉터리 전체 검사, `test_core_vault` 상태 파일 평문 부재 |
| 응답·오류·로그를 통한 유출 시도 | `test_gateway` 헤더·본문 반사, 인코딩 형태별 반사, Set-Cookie, 리다이렉트, 오류 본문, 감사 기록 검사, `test_runs` 출력 차단 |
| 다른 연결·대상 사용 시도 | `test_gateway` 핸들 변조·타 연결 핸들·Host 헤더·절대 URI·경로 이동, `test_gateway`의 `ResolvedAddressTests`(루프백·섞인 응답·메타데이터로 해석되는 호스트 이름 거부, 요청마다 한 번 해석, DNS 변경 반영, 고정 주소 접속과 호스트 이름 기준 TLS 검증), `test_signer` 세션·호스트 키 불일치, `test_ssh_e2e` 잘못된 목적지 |
| SSH 키 오용 시도 | `test_signer` 임의 데이터·forwarding·키 관리 메시지·`ssh-add -T`·`ssh-add -D` 거부 |
| 미지원 CLI 실행 | `test_tools` 프로필 없는 연결·없는 프로그램의 명시적 오류(`test_requires_cli_profile_and_existing_executable_program`), `test_gateway` 미지원 인증 방식의 명시적 오류(`test_unsupported_auth_mode_fails_closed`) |
| 권한 만료·회수·전체 정지 | `test_core_policy`, `test_gateway`, `test_signer`, `test_runs` 실행 취소, `test_tools` 실행 직전 재확인, `test_admin_cli`의 `test_serve_cancels_runs_and_closes_signer_sockets_revoked_by_another_process`(`serve`와 다른 `Context`로 실행한 관리 CLI의 권한 회수가 실행을 취소하고, 호출 주체 비활성화가 소켓을 닫고, 복원 뒤 `serve`가 새 핸들 키를 읽음), `test_cli_e2e`(별도 OS 프로세스의 `grant revoke`·`connection disable`·`stop-all`·`resume`이 떠 있는 `serve`에 반영되고, 실제 `sshd`로 원격 명령을 실행 중인 실행이 각각으로 취소됨. 취소는 로컬 `ssh` 클라이언트만 끝내며 서버의 원격 명령은 계속된다는 한계를 하트비트 파일로 확인함) |
| 운영·복구 경계 우회 시도 | `test_core_vault`·`test_admin_cli` 복원 대기·정지 유지·KMS 불일치 거부·복구, `test_tools`·`test_agent_cli` 목록 밖 도구(`reveal_secret` 등) 거부 |
| 침입 시 자동 봉쇄와 노출 판정 | `test_incident`(범위별 봉쇄와 다른 범위 밖 호출 주체 보존, 순서와 멱등성, `escalate`로 확대·축소 거부, 열린 사건에서 `resume` 거부, 별도 `Context`에서 선언 시 `serve`의 다음 폴링이 실행 취소·소켓 닫기를 대신함, 감사 실패에도 봉쇄 유지, 노출 등급 판정과 사건 파일의 금고 값 부재), `test_intrusion`(강한 신호별 단독 봉쇄, 약한 신호 누적과 임계, 정상 흐름은 트립하지 않음, 열거·속도급증의 1회 가산, 범위 판정과 자동 확대, 같은 감사 기록 호출 안에서 봉쇄 완료, 임계값 설정), `test_cli_e2e`(`CompromiseResponseEndToEndTestCase`: 별도 프로세스의 공격자가 가진 것은 게이트웨이 URL과 호출 토큰뿐이며 미제공 도구를 두 번 불러 `unknown_tool` 강한 신호로 자동 봉쇄, `incident list`/`show`가 별도 관리 CLI 프로세스에서 사건을 보여줌, 봉쇄된 호출 주체의 다음 `list-connections`·`request`가 `principal_disabled`로 거부, `resume`이 `incident_open`으로 거부, `incident close` 뒤 새 호출 주체로 재개), `test_demo`(데모 [7]단계) |
| 교체 안내 이메일 | `test_notify`(§6.2 절 순서와 종류별 안내, 필수·권장 등급 분리, 값·핸들·토큰 부재, 미설정 시 `not_configured`, 발송 실패 시 `pending`과 지수 백오프·재시도, 범위 확대 시 재발송, `notify-test`, `serve` 폴링의 재시도 반영), `test_cli_e2e`(`CompromiseResponseEndToEndTestCase`: 시험용 SMTP 서버(`tests.fake_smtp.FakeSmtp`)가 정확히 한 통을 받고 제목에 사건 id가 있으며 본문이 사용된 연결의 비밀을 필수 교체, granted되었지만 쓰지 않은 연결의 비밀을 권장 교체로 나누고, 합성 업스트림 자격증명·호출 토큰·SMTP 비밀번호가 이메일·`serve` 출력·감사 기록·알림·사건 파일 어디에도 없음을 확인) |

## 9. 남아 있는 경계와 한계

- 같은 개발 호스트에서 신뢰 프로세스와 실행 환경을 나누는 것은 디렉터리·소켓 권한(0700/0600), 상태 디렉터리 밖 실행 디렉터리, 깨끗한 환경변수뿐이다. 같은 OS 사용자로 도는 자식은 상태 디렉터리 경로를 알면 읽을 수 있다. 이는 제품 문서가 말한 격리가 아니다. 배포 시에는 신뢰 프로세스와 실행 환경을 다른 신원·호스트·네트워크에 둔다.
- `LocalFileKms`는 파일 하나의 마스터 키다. 관리형 KMS로 교체해야 하며 `Kms` 프로토콜이 그 자리다.
- 순수 Python 암호 구현은 상수 시간이 아니고 메모리를 지우지 못한다. 정확성은 RFC 벡터와 OpenSSH 상호운용으로 확인했지만 부채널 저항은 없다.
- Ed25519 검증은 RFC 8032 표준식을 따르며 작은 위수의 공개키를 거부하지 않는다. 서명기는 연결에 설정된 호스트 키로만 검증하므로 공격자가 고른 키로 검증하는 경로는 없다.
- 반사 검사는 알려진 인코딩만 찾는다. 임의로 변형·분할·암호화된 반사까지 보장하지 않으므로, 제품 문서대로 인증 정보를 반사하는 서비스 기능은 지원 목록에서 제외해야 한다.
- 실행 출력 검사도 원문, base64, 16진수, URL 인코딩만 찾는다. 자식이 핸들을 뒤집거나 나눠 출력하면 실행은 `completed`로 끝나고, 에이전트는 `status` 출력에서 유효한 핸들을 다시 조립할 수 있다. 핸들은 원본 비밀이 아니지만 만료(기본 900초), 회수, 정책 버전 변경 전까지 허용 범위 안에서 쓰일 수 있다.
- DNS 변경 차단(§4)은 OS 리졸버의 답을 믿고 주소 종류를 검사하는 방식이다. IPv4를 담는 IPv6 주소는 표준 형태(잘 알려진·로컬 사용 NAT64 접두사, IPv4 호환, SIIT, 6to4, Teredo)만 알아보며, 운영자가 정한 비표준 NAT64 접두사 뒤의 IPv4 주소는 알아보지 못한다. 메타데이터 주소 목록에 없는 공급자별 내부 서비스 주소도 막지 못한다. `--allow-private-network`를 켠 연결에서는 호스트 이름이 어떤 사설 주소로 바뀌어도 막지 않으며, 사설 IP 주소 대상도 관리자 선택으로 허용한다. 공인 주소끼리의 변경(다른 외부 호스트로의 전환)은 막지 않으므로 HTTP 대상에는 인증서 검증 같은 상대 확인이 없다. 배포 시에는 HTTPS 대상을 기본으로 하고, 신뢰 프로세스의 네트워크 출구도 별도로 제한해야 한다.
- CLI 프로필 환경변수의 저장 시점 검사는 관리 CLI에만 있다. 관리 CLI를 거치지 않고 `Policy` API로 연결을 만들면 검사하지 않고, 두 검사 모두 알려진 인코딩(원문, base64, 16진수, URL 인코딩)만 찾으므로 뒤집거나 나눈 값은 잡지 못한다. 관리자가 의도적으로 변형한 값을 넣는 경우까지 막지는 못하며, `exec`의 실행 시점 검사가 최종 방어선이다.
- 금고 상태 파일과 백업의 AEAD 암호문 길이는 값 길이에 16바이트를 더한 값이다. 값을 암호화 전에 채우지 않으므로 각 비밀 버전의 길이가 드러난다.
- 관리 CLI의 회수·비활성화·전체 정지·복원은 상태 파일에 기록된 즉시 다음 중계·서명·실행을 막지만, 진행 중인 실행과 열린 서명기 소켓에는 `serve`의 다음 폴링까지(0.25초 주기) 반영되지 않는다. 그 사이 자식이 끝낸 원격 작업은 되돌리지 못한다. 자동 시험(§8)은 같은 호스트의 다른 `Context`에서 온 권한 회수의 실행 취소, 호출 주체 비활성화의 소켓 닫기, 복원 뒤 핸들 키 교체와, 별도 OS 프로세스의 `grant revoke`·`connection disable`·`stop-all`·`resume`(실제 `sshd`로 진행 중인 실행의 취소 포함. 취소되는 것은 로컬 `ssh` 클라이언트이고 원격 명령은 계속된다)을 다룬다. `principal disable`·`restore`를 별도 OS 프로세스에서 걸었을 때의 실행 취소와 소켓 닫기는 2026-09-14에 합성 값으로 수동 확인했고 자동 시험은 없다. 같은 수동 확인에서 `connection disable`은 다른 연결의 실행을 취소하지 않았다.
- SSH `exec`의 취소·회수·전체 정지는 로컬 `ssh` 클라이언트를 끝내고 서명기 소켓을 닫을 뿐, 이미 인증된 세션에서 시작된 원격 명령을 끝내지 않는다. `exec`는 원격 명령을 터미널 없이 실행하므로, 연결이 끊겨도 원격 프로세스가 신호를 받지 못하고 서버에서 계속 돌 수 있다. 2026-09-14 검증에서 취소된 원격 `sleep 60`이 `sshd` 쪽에 남는 것을 재현했다. 보안 설계 §5대로 원격 작업의 강제 종료에는 대상 서버의 통제가 따로 필요하며, 종단 시험은 로컬 실행 상태가 `cancelled`가 되는 것만 확인하고 원격 명령은 스스로 끝나는 명령으로 대신한다.
- 같은 프로세스에서 `Policy`로 호출 주체·연결을 비활성화하거나 연결 범위를 넓히면, 회수 알림에 대상 식별자가 없어 해당 대상만이 아니라 진행 중인 모든 실행을 취소하고 모든 서명기 소켓을 닫는다. 안전 쪽으로 과하게 취소하는 선택이며 취소 사유는 감사 기록에 남는다. 관리 CLI에서 온 변경은 `serve`가 실행·소켓별로 권한을 다시 확인하므로 권한이 사라진 것만 취소한다.
- 실행 기록과 게이트웨이의 요청 원장은 신뢰 프로세스 메모리·상태 파일에 있고, 프로세스가 재시작되면 진행 중이던 실행은 추적되지 않는다.
- 스트리밍 응답 통과, 서비스별 실제 CLI 프로필, 관리 UI, 관리형 저장소, 공급자별 자동 교체, IPv6 수신은 구현하지 않았다.
- 각 서비스·CLI의 실제 지원 여부는 이 프로토타입으로 후보를 시험한 뒤 정한다. 여기서 검증한 CLI는 시험용 `examples/democli.py`와 OpenSSH `ssh`다.
- 침입 탐지기의 상태는 `serve` 프로세스 메모리에만 있다. `serve`가 재시작되면 슬라이딩 창의 누적 점수와 "처음 사용" 집합이 초기화된다 — 강한 신호는 재시작 뒤에도 즉시 걸리지만, 약한 점수와 열거 이력은 재시작 전 것이 이어지지 않는다.
- 핸들 키는 하나뿐이다. `runtime`·`all` 범위의 봉쇄가 하는 핸들 키 교체는 그 범위 밖 다른 실행 환경에서 발급된 핸들까지 함께 무효로 만든다.
- 만료된 핸들 신호(`expired_handle`)는 호출 주체를 알 수 없어 전역 버킷에 쌓인다. 15분(기본 핸들 만료)을 넘겨 오래 실행되는 `exec`의 CLI가 만료된 핸들로 여러 번 재시도하면 이 전역 임계에 닿을 수 있고, 그러면 범위 `principal`로 그 순간의 모든 활성 호출 주체가 한꺼번에 비활성화된다.
- 실행 환경이 장악됐어도 공격자가 HTTP·도구 경로만 쓰면(서명기 소켓이나 실행 출력에 손대지 않으면) 탐지기는 이를 `principal` 범위로 분류한다. 실제로는 `runtime` 범위여야 할 수 있으며, 이메일이 경고하지만 확대는 관리자의 수동 `incident escalate`에 달려 있다.
- 이메일은 사건 기록의 사본이지 인증 채널이 아니다. `pending` 상태는 사건이 닫힐 때까지 지수 백오프로 계속 재시도하며 스스로 포기하지 않는다.
- `notify.json`이 잘못됐거나(권한·소유자·형식) 발송 자체가 실패한 경우를 구분하지 않고, 둘 다 발송 실패와 같은 `pending` 재시도 경로로 다룬다. 설정 파일이 아예 없는 경우만 `not_configured`로 따로 구분한다.
- 호출 출처 기록(침해 대응 설계 §9 단계 6, 감사 기록의 `origin`, 호출 주체의 `first_origin`)은 구현하지 않았다. 현재 `serve`는 루프백만 받으므로 "외부 출처" 표시는 아직 의미가 없다.
- 노출 판정의 비밀별 `service` 값은 그 비밀을 쓰는 연결들 중 정렬 순서상 첫 번째 연결에서만 가져온다. 같은 비밀을 서로 다른 `service` 이름의 여러 연결이 쓰면 나머지 연결의 서비스 이름은 이메일에 나타나지 않는다.

## 10. 실행 예시

모든 명령은 저장소 루트에서 실행한다. `zeropw.fake_upstream`에는 명령행 진입점이 없고 127.0.0.1의 임시 포트에만 뜬다. 아래 첫 줄은 합성 토큰 `synthetic-token-1`만 받는 시험용 외부 API를 백그라운드로 띄우고 `http://127.0.0.1:<포트>`를 출력한다. 포트는 실행마다 달라지므로 출력된 url을 `--target`에 준다. 이 프로세스는 한 시간 뒤 스스로 끝난다.

관리자 쪽:

```sh
python3.12 -c 'import time; from zeropw.fake_upstream import FakeUpstream; f = FakeUpstream("synthetic-token-1").start(); print(f.url, flush=True); time.sleep(3600)' &
export ZEROPW_ADMIN_PASSPHRASE='admin-passphrase-1' ZEROPW_RECOVERY_PASSPHRASE='recovery-passphrase-1'
python3.12 -m zeropw.admin_cli --state-dir /tmp/zpw init
python3.12 -m zeropw.admin_cli --state-dir /tmp/zpw project create demo
printf 'synthetic-token-1' | python3.12 -m zeropw.admin_cli --state-dir /tmp/zpw secret put --id gh --kind api_key --project demo --environment dev --stdin
python3.12 -m zeropw.admin_cli --state-dir /tmp/zpw connection create-http --id gh --project demo --environment dev --service fake --secret-id gh --target '<시험용 외부 API가 출력한 url>' --auth bearer --methods GET,POST --path-prefixes /repos,/me --cli-program "$PWD/examples/democli.py"
python3.12 -m zeropw.admin_cli --state-dir /tmp/zpw principal create --id agent-1
python3.12 -m zeropw.admin_cli --state-dir /tmp/zpw grant create --principal agent-1 --connection gh --ttl 1h --max-uses 100
python3.12 -m zeropw.admin_cli --state-dir /tmp/zpw serve
```

`principal create`는 호출 토큰을 `token` 필드로 한 번만 출력한다. `serve`는 첫 줄에 `url`이 든 JSON을 출력하고 SIGINT·SIGTERM에 종료한다. `--cli-program`에는 절대 경로를 준다. 이 예시의 대상은 127.0.0.1 IP 주소라 그대로 동작한다. 호스트 이름 대상이 사설 주소로 해석되어야 하는 내부 서비스라면 `connection create-http`에 `--allow-private-network`를 더한다. `--cli-env`에는 비밀이 아닌 값만 주며, 자격증명과 일치하면 거부된다.

침해 대응(§7) 관련 예시. 실행 환경마다 다른 `--runtime`으로 호출 주체를 만든다:

```sh
python3.12 -m zeropw.admin_cli --state-dir /tmp/zpw principal create --id agent-2 --runtime box-1
```

자동 봉쇄가 교체 안내 이메일을 보내게 하려면 관리자가 `<상태 디렉터리>/notify.json`(0600, 현재 사용자 소유)과 비밀번호 파일(0600)을 직접 만든다 — 이 자격증명은 금고 비밀이나 업무용 연결로 등록하지 않는다:

```json
{
  "host": "smtp.example.com", "port": 587, "mode": "starttls",
  "sender": "zeropw@example.com", "recipients": ["admin@example.com"],
  "username": "zeropw-notify", "password_file": "/path/to/smtp-password-file"
}
```

사건을 수동으로 선언·확인·닫는 예시:

```sh
python3.12 -m zeropw.admin_cli --state-dir /tmp/zpw incident declare --scope principal --principal agent-2 --reason "토큰 유출 의심"
python3.12 -m zeropw.admin_cli --state-dir /tmp/zpw incident show --id <위 명령이 출력한 id>
python3.12 -m zeropw.admin_cli --state-dir /tmp/zpw incident close --id <id>
```

`incident close`(그리고 `--scope all`인 `incident declare`)는 `ZEROPW_ADMIN_PASSPHRASE`로 관리자 패스프레이즈 재인증을 한다. 자동 탐지기가 스스로 여는 사건은 이 명령 없이 `serve` 안에서 만들어지며, `incident list`·`incident show`로 같은 방식으로 조회한다.

에이전트 쪽:

```sh
export ZEROPW_GATEWAY_URL='<serve가 출력한 url>' ZEROPW_CALLER_TOKEN='<principal create가 출력한 token>'
python3.12 -m zeropw.agent_cli list-connections
python3.12 -m zeropw.agent_cli request --connection gh --method GET --path /repos
python3.12 -m zeropw.agent_cli exec --connection gh -- list-repos
python3.12 -m zeropw.agent_cli status --run '<exec가 출력한 run_id>'
```

사건이 열려 있는 동안(자동이든 수동이든) 같은 호출 주체의 모든 호출이 거부된다. 에이전트 쪽에서는 다음처럼 보인다(종료 코드 1):

```sh
$ python3.12 -m zeropw.agent_cli list-connections
{
  "error": "AuthFailed",
  "reason": "principal_disabled",
  "status": 401
}
```

위 흐름은 2026-09-14에 이 절의 명령을 그대로 쓰고 자리표시자와 상태 디렉터리 경로만 실제 값으로 바꿔 실행해 확인했고, 같은 흐름을 `tests/test_cli_e2e.py`가 별도 프로세스로 자동 시험한다. 전체 흐름을 한 번에 보려면 `python3.12 -m zeropw.demo`를 실행한다.
