# ZeroPW 시작하기

ZeroPW는 팀의 비밀을 암호화해 동기화하고, 에이전트가 원본 키 없이 지원 API·SSH를 쓰게 합니다. 현재는 Rust CLI로 사용하는 배포 전 제품입니다.

## 먼저 선택하세요

| 하고 싶은 일 | 시작점 |
| --- | --- |
| 동작을 먼저 보기 | 아래 빌드와 데모 |
| 팀 환경을 처음 만들기 | 관리자 설정 → 팀 공유 |
| 팀에 가입하기 | 팀 공유의 팀원 단계 |
| 에이전트로 작업하기 | 에이전트 사용 → 스킬 설치 |
| 기존 앱에 `.env`를 그대로 주입하기 | 현재 미지원. 앱의 인증 경로를 먼저 확인 |

`.env` 파일 자체의 가져오기·내보내기는 제공하지 않습니다. API 키는 금고에, URL 같은 비밀이 아닌 설정은 앱 설정에 둡니다. 원본 키를 `process.env`로 읽어야 하는 앱, DB 비밀번호를 직접 받는 드라이버는 전용 통합 없이는 사용할 수 없습니다. 현재 검증한 CLI는 `zeropw-democli`와 OpenSSH입니다.

## 1. 빌드와 데모

저장소 루트에서 실행합니다. Rust 2024 edition 지원 toolchain과 OpenSSL 3 개발 헤더가 필요합니다. Linux에서는 배포판의 OpenSSL 개발 패키지와 pkg-config를 준비합니다. macOS에서 Homebrew `openssl@3`를 설치했다면 빌드 전에 다음을 실행합니다.

```sh
export OPENSSL_DIR="$(brew --prefix openssl@3)"
```

```sh
cargo build --locked --manifest-path rust/Cargo.toml --bins
export PATH="$PWD/rust/target/debug:$PATH"
zeropw-demo
```

데모는 합성 자격증명과 내장 시험 서버를 씁니다. 종료 코드 0이면 데모 확인이 통과한 것입니다. 제품 빌드·데모는 실제 금고나 조정기 권한이 없는 CI 러너·격리 VM에서 실행하세요. `exec`를 사용할 때는 `zeropw_session`을 `zeropw-admin` 옆에 함께 배포합니다.

## 2. 관리자 설정

이 단계는 **사람이 별도 신뢰 터미널에서** 수행합니다. 관리자·복구 패스프레이즈, 원본 키, `.env` 내용은 에이전트에게 전달하지 않습니다. 에이전트는 아래 관리 명령을 대신 실행하지 않습니다.

```sh
export ZPW_STATE="$HOME/.local/share/zeropw"
zeropw-admin --state-dir "$ZPW_STATE" init
zeropw-admin --state-dir "$ZPW_STATE" project create team-app
```

`init`의 터미널 프롬프트에서 관리자·복구 패스프레이즈를 정하고 별도로 보관합니다. 아래 경로와 대상은 예시이므로 **관리자가 검증한 값으로 바꾼 뒤** 실행합니다. 값 파일에는 키 하나만 담습니다. `.env` 전체를 값 파일로 넘기지 마세요.

```sh
zeropw-admin --state-dir "$ZPW_STATE" secret put \
  --id service-key --kind api_key --project team-app --environment dev \
  --value-file /trusted/path/service-key
zeropw-admin --state-dir "$ZPW_STATE" connection create-http \
  --id service-api --project team-app --environment dev --service team-service \
  --secret-id service-key --target https://api.example.com \
  --auth bearer --methods GET --path-prefixes /v1
```

임시 값 파일을 썼다면 등록 성공 후 관리자가 안전하게 정리합니다. 실제 서비스는 인증 정보 조회·반사 경로와 응답 처리를 검증한 뒤 연결해야 합니다. 위 명령만으로 해당 서비스의 지원이 인증되지는 않습니다. CLI 실행은 검증한 프로필을 별도로 연결하며, API 호출은 `--cli-program` 없이 가능합니다.

각 기기에서 호출 주체와 권한을 만듭니다. 호출 토큰은 한 번만 출력되며, 이 토큰도 제한된 사용 권한이므로 공개 문서·Git·채팅에 넣지 않습니다.

```sh
zeropw-admin --state-dir "$ZPW_STATE" principal create --id agent-1 --runtime dev-box
zeropw-admin --state-dir "$ZPW_STATE" grant create \
  --principal agent-1 --connection service-api --ttl 1h --max-uses 100
zeropw-admin --state-dir "$ZPW_STATE" serve
```

`serve`는 켜 둡니다. 첫 JSON의 `url`과 호출 토큰만 에이전트 환경에 전달합니다. 도구 리스너는 루프백 전용입니다. 같은 OS 사용자로 금고와 에이전트를 실행하는 개발 구성은 보안 격리가 아닙니다. 운영 격리는 별도로 준비해야 하며 실제 비밀로 온보딩을 시험하지 않습니다.

## 3. 팀 공유

같은 LAN 또는 팀 VPN 안에서 기기끼리 연결합니다. 중앙 서버는 필요 없지만 동기화할 각 기기의 `serve`는 실행 중이어야 합니다. 다음은 기기 A의 VPN IP가 `10.8.0.2`, B가 `10.8.0.3`인 예입니다. 실제 주소로 바꾸고 팀 리스너 포트만 팀 네트워크에 허용하세요.

**관리자 A:** 앞 단계에서 만든 `team-app/dev`를 공유합니다. 이미 실행한 일반 `serve`가 있으면 종료하고 팀 리스너를 켜서 다시 실행합니다.

```sh
zeropw-admin --state-dir "$ZPW_STATE" team init
zeropw-admin --state-dir "$ZPW_STATE" team share --project team-app --environment dev --name owner
zeropw-admin --state-dir "$ZPW_STATE" serve --team-listen 10.8.0.2:47420
```

다른 신뢰 터미널에서 같은 `ZPW_STATE`를 설정하고 초대합니다.

```sh
zeropw-admin --state-dir "$ZPW_STATE" team invite \
  --env team-app/dev --role user --name teammate --ttl 1h --address 10.8.0.2:47420
```

초대는 일회용 가입 권한입니다. 초대 문자열을 받는 팀원에게 별도 안전한 경로로 전달하고 에이전트·이슈·리뷰·채팅 로그에는 넣지 않습니다. 편집·초대가 필요한 팀원만 `admin`으로 초대합니다.

**팀원 B:** 자기 기기에서 빌드하고 자기 금고를 초기화한 뒤 기기 키를 만듭니다. 관리자 패스프레이즈는 공유하지 않습니다.

```sh
export ZPW_STATE="$HOME/.local/share/zeropw"
zeropw-admin --state-dir "$ZPW_STATE" init
zeropw-admin --state-dir "$ZPW_STATE" team init
zeropw-admin --state-dir "$ZPW_STATE" team join '<일회용 초대>' --project team-app --environment dev
zeropw-admin --state-dir "$ZPW_STATE" team status --env team-app/dev
zeropw-admin --state-dir "$ZPW_STATE" team members --env team-app/dev
zeropw-admin --state-dir "$ZPW_STATE" serve --team-listen 10.8.0.3:47420
```

`team join`은 현재 초대 문자열을 인자로 받습니다. B의 신뢰 터미널에서만 실행하고 셸 이력·프로세스 인자 노출을 관리하세요. A와 B에서 출력된 기기 지문과 멤버 목록을 확인합니다. 공유 전 A에서 만든 권한은 `stale`이 되므로 다시 발급하고, B도 자기 기기에서 `principal create`·`grant create`를 수행합니다. **호출 주체·권한·호출 토큰은 기기 간 공유되지 않습니다.**

admin의 비밀·연결 변경은 연결된 노드에 전파됩니다. 각자 `team status`로 마지막 동기화와 상태를 확인합니다. 오프라인 기기는 재연결 때 따라잡지만 그동안 회수되지 않은 이전 상태로 사용할 수 있습니다. 초기 온보딩 중에는 `team compact`를 실행하지 마세요. 압축된 이력을 새 기기에 전송하는 기능은 없습니다.

팀원을 제거하려면 관리자가 `team remove --env team-app/dev --device '<지문>'`을 실행합니다. 제거된 사람이 과거에 읽을 수 있었던 키는 공급자에서 교체해야 무효가 됩니다. `user` 역할도 기기의 신뢰 프로세스는 비밀을 복호화하므로 사람으로서 신뢰하는 팀원만 초대합니다.

## 4. 에이전트 사용

관리자가 에이전트 실행 환경에 `ZEROPW_GATEWAY_URL`과 `ZEROPW_CALLER_TOKEN`을 설정합니다. 에이전트는 토큰을 출력하거나 설정 파일 내용을 읽을 필요가 없습니다.

```sh
zeropw-agent list-connections
zeropw-agent request --connection service-api --method GET --path /v1/items
```

검증한 CLI 프로필 또는 SSH 연결을 관리자가 설정했다면:

```sh
zeropw-agent exec --connection '<연결 ID>' -- '<프로필의 명령 인자>'
zeropw-agent status --run '<반환된 run_id>'
zeropw-agent cancel --run '<반환된 run_id>'
```

`exec` 뒤에는 바이너리 경로 대신 연결 프로필의 인자를 줍니다. SSH 연결은 원격 명령 인자를 받습니다. SSH는 session-bind를 지원하는 OpenSSH 8.9 이상과 관리자가 검증한 서버 호스트 키가 필요하며, 개인키 파일을 에이전트에게 주지 않습니다. 같은 연결의 허용 범위 안에서는 작업마다 새 등록이 필요 없습니다.

## 5. 에이전트 스킬 설치

저장소의 [ZeroPW 에이전트 스킬](skills/zeropw-agent/SKILL.md)은 관리자 작업과 에이전트 작업을 구분하고, 연결 선택·API·CLI·상태 확인을 안내합니다. Codex 개인 스킬 디렉터리에 **사람이** 복사합니다. 같은 이름이 이미 있으면 먼저 내용을 비교하세요.

```sh
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
cp -R skills/zeropw-agent "${CODEX_HOME:-$HOME/.codex}/skills/"
```

스킬이 로드된 에이전트에 이렇게 요청합니다:

> $zeropw-agent 사용 가능한 연결을 확인하고 service-api로 /v1/items를 조회해 줘.

스킬에는 비밀, 관리자 상태 경로, 초대 문자열을 넣지 않습니다. 다른 에이전트에서도 `SKILL.md`의 지침을 해당 제품의 스킬 방식으로 등록할 수 있습니다.

## 문제가 생기면

| 증상 | 다음 행동 |
| --- | --- |
| `zeropw-agent`가 없음 | 빌드·배포와 PATH를 확인 |
| `gateway_unreachable` | 관리자가 `serve` 실행 여부와 루프백 접근 경로를 확인 |
| 연결이 목록에 없음 | 해당 기기의 호출 주체·grant와 동기화를 관리자가 확인 |
| `stale`, 만료, 회수, `principal_disabled` | 관리자에게 새 권한 또는 사건 상태 확인 요청. 에이전트가 재개·권한 확장하지 않음 |
| `spawn_failed` | 관리자가 CLI 프로필과 `zeropw_session` 배치를 확인 |
| 가입 연결 실패 | VPN·주소·포트·초대 만료를 관리자가 확인 |
| 쓰기 결과 불명확 | 같은 작업을 무조건 재실행하지 말고 상태·업무 결과부터 확인 |
| 미지원 인증 또는 인증 정보 반사 차단 | 평문 `.env`로 우회하지 않고 지원 통합을 확인 |

상세: [구현 현황](docs/implementation.md), [팀 동기화](docs/team-sync.md), [보안 경계](docs/security-design.md). 이 GUIDE는 온보딩 문서이며 운영 배포나 새 보안 리뷰 PASS를 선언하지 않습니다.
