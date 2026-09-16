# ZeroPW v1 프로토타입 구현 현황

작성일: 2026-09-14 · 구현 기준 · 합성 자격증명과 통제된 시험용 서버만 사용

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
| `zeropw/admin_cli.py` | 관리자 CLI (별도 신원, 패스프레이즈 재인증) | 관리자 |
| `zeropw/fake_upstream.py`, `zeropw/demo.py` | 합성 토큰을 검증하는 시험용 외부 API와 원커맨드 데모 | 시험·시연 전용 |
| `zeropw/crypto/x25519.py` | RFC 7748 X25519. 순수 Python, RFC 시험 벡터로 검증 | 신뢰 프로세스 |
| `zeropw/team/identity.py`, `zeropw/team/envelope.py` | 기기 키(서명+합의)와 지문, 환경 DEK 세대 감싸기·풀기(HKDF+ChaCha20-Poly1305) | 신뢰 프로세스 |
| `zeropw/team/commit.py`, `zeropw/team/fold.py` | 커밋 서명·검증·저장, 하이브리드 논리 시계, 전순서 접기와 노드 로컬 파생, 스냅샷 | 신뢰 프로세스 |
| `zeropw/team/transport.py` | 전송 인터페이스, 인프로세스 시험 전송, TCP 참조 전송(SIGMA류 핸드셰이크, 프레임) | 신뢰 프로세스 |
| `zeropw/team/sync.py` | 세션 관리, VECTOR·COMMIT·FACT·PEERS·INCIDENT·INCIDENT_ACK 메시지 루프, 접기 적용, 사건 공유 발신·수신 | 신뢰 프로세스 |
| `zeropw/team/membership.py` | 초대 생성·소진, 가입, 팀원 제거와 DEK 교체, `team share` | 신뢰 프로세스 |
| `zeropw/admin_cli.py`의 `team *` 명령군, `serve --team-listen` | 팀 공유 CLI([팀 공유](team-sync.md) §12)와 팀 리스너 | 관리자 / 신뢰 프로세스 |

에이전트 프로세스가 받는 것은 게이트웨이 URL과 자기 호출 토큰(`zpwc_...`)이다. `exec`로 실행되는 CLI는 여기에 더해 연결 핸들이 들어간 base URL(`.../h/zpw1....`) 또는 서명기 소켓 경로를 받는다. 이 중 어느 것도 금고 값이 아니다. 핸들은 호출 주체·연결·권한·정책 버전에 묶인 짧은 수명의 사용 권한이며, 유출되면 회수 전까지 허용 범위 안에서 사용될 수 있다. 이는 제품 문서가 말한 "허용된 사용 권한과 원본 자격증명은 다르다"는 구분 그대로다.

## 3. 사용 흐름이 코드에서 어떻게 보이는가

1. 관리자가 `admin_cli init`으로 상태 디렉터리를 만든다. KMS 마스터 키, 금고 DEK, 관리자 패스프레이즈, 복구 패스프레이즈가 생긴다.
2. `project create`, `secret put`(값은 stdin 또는 파일로만), `connection create-http` 또는 `create-ssh`로 서비스·자격증명·대상·허용 범위를 연결 하나에 설정한다. 명령이나 API 작업을 등록하는 단계는 없다.
3. `principal create`로 에이전트 신원을 만들고 `grant create`로 연결 사용 권한(만료, 사용량)을 준다.
4. `serve`로 신뢰 프로세스를 띄운다. 에이전트는 `agent_cli list-connections`로 쓸 수 있는 연결을 보고, `request`로 API를 호출하거나 `exec`로 지원 CLI를 실행한다.
5. 관리자는 `audit tail`, `alerts`로 사용을 보고 `grant revoke`, `principal disable`, `connection disable`, `stop-all`로 막는다. 관리 CLI는 `serve`와 별도 프로세스다. 변경은 상태 파일에 바로 기록되어 다음 중계·서명·실행에서 거부되고, 이미 진행 중인 실행과 열린 서명기 소켓에는 `serve`의 다음 폴링(0.25초 주기)에서 반영된다(§6).

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
- **실행 출력 검사:** 자식의 출력에 자격증명이나 핸들이 알려진 인코딩(원문, 표준·URL 안전 base64, 16진수, URL 인코딩)으로 나오면 출력을 고정 문구로 바꾸고 `blocked`로 표시한다. 뒤집기·분할 같은 다른 변형은 잡지 못한다(§8). 자식은 애초에 자격증명을 갖지 않으므로 자격증명에 대해서는 보조 방어다.
- **중복 실행:** `exec`의 요청 ID 조회와 등록은 하나의 잠금 안에서 일어나 같은 요청의 동시 호출은 실행 하나로 합쳐진다.
- **기본값은 거부:** 권한은 호출 주체·연결·만료·사용량·정책 버전에 묶이고 모든 중계·서명·실행 직전에 다시 평가한다.
- **정책 변경:** 연결의 대상, 인증 방식, 허용 범위가 넓어지는 변경은 기존 권한을 `stale`로 만들어 자동 승계를 막는다. 범위 축소와 자격증명 교체는 권한을 제자리에서 재평가한다. 정책 버전이 바뀌면 이전 핸들은 무효다.
- **전체 정지:** `stop-all`은 새 중계·서명·실행을 거부하고 대기·진행 중인 실행을 취소하며 서명기 소켓을 닫는다. 이미 인증된 SSH 세션을 끊지는 못한다. 이는 보안 설계 §5의 한계 그대로다.
- **백업·복원:** 백업은 금고 문서(암호문, KMS와 복구 패스프레이즈로 이중 봉투된 DEK, SSH 키의 공개키 정보)와 프로젝트·정책 문서를 담는다. 비밀 값의 평문이나 해시는 담지 않는다. 다만 암호문 길이로 값의 길이가 드러난다. CLI 프로필 추가 변수는 비밀이 아닌 설정이라 정책 문서에 평문으로 들어가며, 관리 CLI는 자격증명과 일치하는 값을 저장 전에 거부한다(§6). 복원은 현재 KMS로 풀 수 없는 백업을 쓰기 전에 거부한다. 복원 뒤에는 `restore_pending`으로 모든 인증을 막고, 복원 시점에 켜져 있던 전체 정지는 유지한다. 관리자가 최신 회수 상태를 반영한 뒤 `restore-ack`로 복원 대기만 풀고, 정지는 `resume`으로 따로 푼다.
- **복구:** 복구 패스프레이즈로 DEK를 풀어 새 KMS 키로 다시 감싸고, 모든 권한을 회수하며 핸들 키를 교체한다. KMS 키와 복구 패스프레이즈를 모두 잃으면 복구할 수 없다.
- **단일 비밀 조회:** `secret reveal`은 관리자 패스프레이즈 재인증과 감사 기록을 요구하고 알림을 남긴다. 일괄 평문 내보내기는 없다. 비밀 목록에는 SSH 공개키 정보 외에 값에서 파생한 메타데이터가 없다.
- **교체:** 새 버전 등록(`rotation start`), 활성화와 연결 전환(`rotation activate`), 이전 버전 은퇴(`rotation finish`) 순서다. 외부 공급자 쪽 폐기는 금고가 대신하지 못하므로 CLI가 이를 상기시킨다.

## 7. 수용 시험 대응표

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

## 8. 남아 있는 경계와 한계

- 같은 개발 호스트에서 신뢰 프로세스와 실행 환경을 나누는 것은 디렉터리·소켓 권한(0700/0600), 상태 디렉터리 밖 실행 디렉터리, 깨끗한 환경변수뿐이다. 같은 OS 사용자로 도는 자식은 상태 디렉터리 경로를 알면 읽을 수 있다. 이는 제품 문서가 말한 격리가 아니다. 배포 시에는 신뢰 프로세스와 실행 환경을 다른 신원·호스트·네트워크에 둔다.
- `LocalFileKms`는 파일 하나의 마스터 키다. 관리형 KMS로 교체해야 하며 `Kms` 프로토콜이 그 자리다.
- 순수 Python 암호 구현은 상수 시간이 아니고 메모리를 지우지 못한다. 정확성은 RFC 벡터와 OpenSSH 상호운용으로 확인했지만 부채널 저항은 없다.
- Ed25519 검증은 RFC 8032 표준식을 따르며 작은 위수의 공개키를 거부하지 않는다. 서명기는 연결에 설정된 호스트 키로만 검증하므로 공격자가 고른 키로 검증하는 경로는 없다.
- 반사 검사는 알려진 인코딩만 찾는다. 임의로 변형·분할·암호화된 반사까지 보장하지 않으므로, 제품 문서대로 인증 정보를 반사하는 서비스 기능은 지원 목록에서 제외해야 한다.
- 실행 출력 검사도 원문, base64, 16진수, URL 인코딩만 찾는다. 자식이 핸들을 뒤집거나 나눠 출력하면 실행은 `completed`로 끝나고, 에이전트는 `status` 출력에서 유효한 핸들을 다시 조립할 수 있다. 핸들은 원본 비밀이 아니지만 만료(기본 900초), 회수, 정책 버전 변경 전까지 허용 범위 안에서 쓰일 수 있다.
- DNS 변경 차단(§4)은 OS 리졸버의 답을 믿고 주소 종류를 검사하는 방식이다. IPv4를 담는 IPv6 주소는 표준 형태(잘 알려진·로컬 사용 NAT64 접두사, IPv4 호환, SIIT, 6to4, Teredo)만 알아보며, 운영자가 정한 비표준 NAT64 접두사 뒤의 IPv4 주소는 알아보지 못한다. 메타데이터 주소 목록에 없는 공급자별 내부 서비스 주소도 막지 못한다. `--allow-private-network`를 켠 연결에서는 호스트 이름이 어떤 사설 주소로 바뀌어도 막지 않으며, 사설 IP 주소 대상도 관리자 선택으로 허용한다. 공인 주소끼리의 변경(다른 외부 호스트로의 전환)은 막지 않으므로 HTTP 대상에는 인증서 검증 같은 상대 확인이 없다. 배포 시에는 HTTPS 대상을 기본으로 하고, 신뢰 프로세스의 네트워크 출구도 별도로 제한해야 한다.
- CLI 프로필 환경변수의 저장 시점 검사는 관리 CLI에만 있다. 관리 CLI를 거치지 않고 `Policy` API로 연결을 만들면 검사하지 않고, 두 검사 모두 알려진 인코딩(원문, base64, 16진수, URL 인코딩)만 찾으므로 뒤집거나 나눈 값은 잡지 못한다. 관리자가 의도적으로 변형한 값을 넣는 경우까지 막지는 못하며, `exec`의 실행 시점 검사가 최종 방어선이다.
- 금고 상태 파일과 백업의 AEAD 암호문 길이는 값 길이에 16바이트를 더한 값이다. 값을 암호화 전에 채우지 않으므로 각 비밀 버전의 길이가 드러난다.
- 관리 CLI의 회수·비활성화·전체 정지·복원은 상태 파일에 기록된 즉시 다음 중계·서명·실행을 막지만, 진행 중인 실행과 열린 서명기 소켓에는 `serve`의 다음 폴링까지(0.25초 주기) 반영되지 않는다. 그 사이 자식이 끝낸 원격 작업은 되돌리지 못한다. 자동 시험(§7)은 같은 호스트의 다른 `Context`에서 온 권한 회수의 실행 취소, 호출 주체 비활성화의 소켓 닫기, 복원 뒤 핸들 키 교체와, 별도 OS 프로세스의 `grant revoke`·`connection disable`·`stop-all`·`resume`(실제 `sshd`로 진행 중인 실행의 취소 포함. 취소되는 것은 로컬 `ssh` 클라이언트이고 원격 명령은 계속된다)을 다룬다. `principal disable`·`restore`를 별도 OS 프로세스에서 걸었을 때의 실행 취소와 소켓 닫기는 2026-09-14에 합성 값으로 수동 확인했고 자동 시험은 없다. 같은 수동 확인에서 `connection disable`은 다른 연결의 실행을 취소하지 않았다.
- SSH `exec`의 취소·회수·전체 정지는 로컬 `ssh` 클라이언트를 끝내고 서명기 소켓을 닫을 뿐, 이미 인증된 세션에서 시작된 원격 명령을 끝내지 않는다. `exec`는 원격 명령을 터미널 없이 실행하므로, 연결이 끊겨도 원격 프로세스가 신호를 받지 못하고 서버에서 계속 돌 수 있다. 2026-09-14 검증에서 취소된 원격 `sleep 60`이 `sshd` 쪽에 남는 것을 재현했다. 보안 설계 §5대로 원격 작업의 강제 종료에는 대상 서버의 통제가 따로 필요하며, 종단 시험은 로컬 실행 상태가 `cancelled`가 되는 것만 확인하고 원격 명령은 스스로 끝나는 명령으로 대신한다.
- 같은 프로세스에서 `Policy`로 호출 주체·연결을 비활성화하거나 연결 범위를 넓히면, 회수 알림에 대상 식별자가 없어 해당 대상만이 아니라 진행 중인 모든 실행을 취소하고 모든 서명기 소켓을 닫는다. 안전 쪽으로 과하게 취소하는 선택이며 취소 사유는 감사 기록에 남는다. 관리 CLI에서 온 변경은 `serve`가 실행·소켓별로 권한을 다시 확인하므로 권한이 사라진 것만 취소한다.
- 실행 기록과 게이트웨이의 요청 원장은 신뢰 프로세스 메모리·상태 파일에 있고, 프로세스가 재시작되면 진행 중이던 실행은 추적되지 않는다.
- 스트리밍 응답 통과, 서비스별 실제 CLI 프로필, 관리 UI, 관리형 저장소, 공급자별 자동 교체, IPv6 수신은 구현하지 않았다.
- 각 서비스·CLI의 실제 지원 여부는 이 프로토타입으로 후보를 시험한 뒤 정한다. 여기서 검증한 CLI는 시험용 `examples/democli.py`와 OpenSSH `ssh`다.

## 9. 실행 예시

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

에이전트 쪽:

```sh
export ZEROPW_GATEWAY_URL='<serve가 출력한 url>' ZEROPW_CALLER_TOKEN='<principal create가 출력한 token>'
python3.12 -m zeropw.agent_cli list-connections
python3.12 -m zeropw.agent_cli request --connection gh --method GET --path /repos
python3.12 -m zeropw.agent_cli exec --connection gh -- list-repos
python3.12 -m zeropw.agent_cli status --run '<exec가 출력한 run_id>'
```

위 흐름은 2026-09-14에 이 절의 명령을 그대로 쓰고 자리표시자와 상태 디렉터리 경로만 실제 값으로 바꿔 실행해 확인했고, 같은 흐름을 `tests/test_cli_e2e.py`가 별도 프로세스로 자동 시험한다. 전체 흐름을 한 번에 보려면 `python3.12 -m zeropw.demo`를 실행한다.

## 10. 팀 공유 (docs/team-sync.md)

작성일 2026-09-16. [팀 공유](team-sync.md) 명세의 4단계(§13) 모두 코드로 옮겼다. 이 절도 §1의 원칙 그대로 시험 통과 범위이며 Opus 리뷰 통과나 배포 준비를 뜻하지 않는다.

### 10.1 구현한 것과 시험

| 단계 | 구현 | 시험 |
| --- | --- | --- |
| 1 (§13 단계 1): 키·봉투·커밋·접기, 네트워크 없음 | `zeropw/crypto/x25519.py`, `zeropw/team/identity.py`, `zeropw/team/envelope.py`, `zeropw/team/commit.py`, `zeropw/team/fold.py` | `tests/test_team_envelope.py`, `tests/test_team_identity.py`, `tests/test_team_commit.py`, `tests/test_team_fold.py` |
| 2 (§13 단계 2): 전송과 동기화 | `zeropw/team/transport.py`(인프로세스·TCP), `zeropw/team/sync.py`의 세션·VECTOR/COMMIT/FACT/PEERS 루프, `serve --team-listen` | `tests/test_team_transport.py`, `tests/test_team_sync.py` |
| 3 (§13 단계 3): 초대·가입·제거, 긴급 사실, CLI | `zeropw/team/membership.py`, `zeropw/team/sync.py`의 `Fact`/`facts.jsonl`, `admin_cli.py`의 `team *`와 공유 환경의 `connection *`·`secret *`·`rotation *` | `tests/test_team_membership.py`, `tests/test_team_facts.py`, `tests/test_team_snapshot.py`(§7.3 압축), `tests/test_admin_cli.py::TeamCliTestCase` |
| 4 (§13 단계 4): 사건 공유와 종단 시험 | `zeropw/team/sync.py`의 `send_incident`/`send_incident_for_all_envs`(`on_incident_open`)·`INCIDENT`/`INCIDENT_ACK`·`incident_outbox.jsonl`, `admin_cli.py`의 `team incidents`, §7.2 `team_op_overridden` 알림(`zeropw/team/fold.py`의 `overridden` 감지 + `sync.py`의 알림) | `tests/test_team_sync.py::IncidentSharingTestCase`(정제·서명·admin 전용 전달·ack 큐잉·재시도·교체 표시), `tests/test_team_sync.py::OverrideAlertTestCase`(진 쪽 1회 알림, 이긴 쪽 알림 없음), `tests/test_team_e2e.py`(별도 OS 프로세스 3개, §1 흐름 전체) |

`team_op_overridden` 알림은 명세 §7.2에 있었으나 3단계까지 구현이 없었던 항목이라 이번에 `fold.py`(같은 대상에 대한 연속된 성공 연산 사이의 작성자 전환 감지)와 `sync.py`(이 기기가 진 경우만, 재접기마다 중복 없이 1회) 양쪽에 추가했다.

### 10.2 사건 공유 (§9)

`send_incident`는 요약을 `INCIDENT_ALLOWED_KEYS`(문자열·정수·문자열 목록만, 길이 제한, 제어 문자 없음)로 정제하고 `Fact`(종류 `incident`)로 서명해 `facts.jsonl`에 다른 사실처럼 남긴다. `incident_id`는 그대로 `team/<env-id>/incidents/<지문>-<사건 ID>.json` 경로의 일부가 되므로, 다른 필드보다 좁게 `version_id`·세대 ID와 같은 16진수 토큰 형식만 받는다(그 밖의 형식은 `sanitize_incident_summary`가 통째로 거부한다) — 자유 문자열을 그대로 받으면 `..`나 `/`가 든 값으로 경로를 벗어나는 구멍이 열리기 때문이다. 전달은 그 순간 세션이 열려 있는 admin 팀원에게만 하는 단발 메시지(`INCIDENT`)이며, 일반 `FACT`처럼 전체 메시로 재중계하지 않는다(admin에게만 전파한다는 §3.1/§9 그대로). 세션이 열려 있어도 유실될 수 있으므로 admin 하나가 `INCIDENT_ACK`(사실 해시)를 보낼 때까지 `team/<env-id>/incident_outbox.jsonl`에 남아 `poll()`이 지수 백오프로 재시도한다. 받은 admin 노드는 `team/<env-id>/incidents/<지문>-<사건 ID>.json`에 두고, 요약의 `secret_ids_mandatory`/`secret_ids_recommended`를 `team/<env-id>/rotation_flags.json`에 `rotation_required`/`rotation_recommended`로 남기며 `team_incident_received` 알림을 남긴다. admin이 아닌 노드는 조용히 무시한다(ack도 저장도 하지 않는다).

`zeropw/incident.py`의 `open_incident`(침해 대응 기능)가 사건을 열 때 `ctx.team.send_incident_for_all_envs(summary_by_env)`를 부르는 배선은 이 저장소에 아직 없다. 그 기능은 `feature/compromise-response-plan` 브랜치에 있고 이 작업의 바탕인 `main`에는 없기 때문이다. 그 브랜치가 병합되면 `open_incident`에서 `getattr(ctx, "team", None)`이 있을 때 그 호출을 추가하면 된다. `send_incident_for_all_envs`는 그 호출부를 위해 미리 만든 훅이며 지금은 시험 말고는 호출하는 곳이 없다.

`team incidents --env P/E`는 받은 사건 요약(값 없음)과 `rotation_flags.json`을 함께 보여 준다.

### 10.3 남은 한계

- **스냅샷 전송 없음.** §7.3의 압축(`team compact`)은 노드 로컬이며, 압축 뒤 처음 붙는 노드나 오래 떨어져 있던 노드에 스냅샷을 전송하는 메시지는 명세에도 이 구현에도 없다(§7.3 "스냅샷 전송 메시지는 이 명세에 없으며 후속 범위다"). 그런 노드는 지워진 커밋을 받지 못한다.
- **LAN 멀티캐스트 발견 없음.** §6.4의 UDP 멀티캐스트 신호(`239.192.47.42:47420`)는 구현하지 않았다. 주소는 초대의 `--address`와 `team peers --add`로만 전달되며, `PEERS` 메시지로 이미 연결된 팀원 사이에서만 더 퍼진다.
- **사건 발신 훅 배선 지연.** 위 §10.2대로 `zeropw/incident.py`가 병합되기 전까지 `send_incident_for_all_envs`는 실제 침해 대응 흐름에서 호출되지 않는다.
- **LAN·VPN 안 직접 연결만.** NAT 통과, 공개 인터넷, 중계 서버는 없다(§11).
- **모든 팀원 노드가 환경 DEK를 받는다.** admin/user 구분은 정책적 통제이지 암호학적 통제가 아니다(§10). user 역할 팀원도 자기 기기에서 값을 꺼낼 수 있다.
- **`INCIDENT`는 중계하지 않는다.** 명세 §6.3의 메시지 표가 `INCIDENT`를 "노드 → admin 노드"로만 적어, 이 구현은 admin과 직접 세션이 없는 노드의 사건 요약을 전달하지 못한다(재시도 큐는 세션이 나중에 열리는 경우만 돕는다). 팀 규모가 작고 전체 연결 그래프를 가정하는 §6.4의 전제 안에서는 대개 문제가 되지 않는다.
- **`team_op_overridden`은 연결 갱신·자격증명 전환, 팀원 역할 변경, 비밀 활성화 대상만 본다.** 생성·비활성화·폐기·제거처럼 그 자체로 긴급 사실이 되거나 재사용을 막는 연산은 "같은 대상의 뒤엣것이 이긴다"는 경합이 성립하지 않으므로 대상에서 뺐다(§7.2 참고).
