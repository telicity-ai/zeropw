# ZeroPW

ZeroPW는 에이전트에게 원본 비밀값을 주지 않고 CLI와 API를 쓰게 하는 개인용 금고다. 서비스와 자격증명을 한 번 연결하면 작업별 등록 없이 지원하는 CLI·API를 쓸 수 있다. 신뢰 프로세스 안의 중계기가 HTTP 인증 정보를 넣고 별도 서명기가 SSH 인증을 맡는다. 그래서 원본 키는 에이전트가 실행하는 코드에 들어가지 않는다.

제품 코드는 `rust/`의 Rust 크레이트(`zeropw`)에 있다. v0.1.0은 첫 릴리스이며 합성 자격증명과 시험용 서버로 검증했다. 2026-10-03 Rust 전환을 마친 뒤 기존 Python 프로토타입을 저장소에서 제거했다. 코드는 git 이력에 남아 있다.

## 처음 사용한다면

[시작 안내](GUIDE.md)에 데모 실행부터 관리자 설정, 팀 가입, 에이전트 사용까지 필요한 절차를 적었다. 에이전트에는 [ZeroPW 스킬](skills/zeropw-agent/SKILL.md)을 설치할 수 있다.

팀원에게는 [한국어 HTML 매뉴얼](docs/team-onboarding.ko.html)이나 [영어 HTML 매뉴얼](docs/team-onboarding.en.html)을 전달하면 된다. 파일을 내려받아 브라우저에서 연다. 에이전트 검증 프롬프트도 [한국어](docs/team-agent-prompts.ko.txt)와 [영어](docs/team-agent-prompts.en.txt)로 제공한다.

팀원을 동시에 제거하면 기기마다 처리 결과가 달라질 수 있다. `team status`의 `rejected_removals`에 충돌이 표시되면 현재 관리자가 대상을 확인하고 의도한 제거를 다시 실행해야 한다. 팀원이 제거되기 전에 접근할 수 있었던 자격증명은 외부 서비스에서 교체해야 무효화된다.

## 구성

| 바이너리 | 역할 | 실행 위치 |
| --- | --- | --- |
| `zeropw-admin` | 관리 CLI. 상태 디렉터리 초기화, 프로젝트·비밀·연결·호출 주체·권한 관리, 감사·알림 조회, 침해 대응, 팀 공유, 신뢰 프로세스 `serve` | 관리자 / 신뢰 호스트 |
| `zeropw-agent` | 에이전트용 CLI. `list-connections`, `request`, `exec`, `status`, `cancel` | 비밀 없는 실행 환경 |
| `zeropw_session` | `exec` 실행 보조 바이너리. `serve` 바이너리와 같은 디렉터리에 둔다 | 신뢰 호스트 |
| `zeropw-demo` | 시험용 값으로 전체 사용 과정을 보여 주는 데모 (종료 코드 0 = 모든 확인 통과) | 시연 |
| `zeropw-democli` | `exec` 지원 CLI 예시. 연결 핸들이 든 base URL만 받는다 | 시험·시연 |

에이전트가 받는 것은 게이트웨이 URL(`ZEROPW_GATEWAY_URL`)과 자기 호출 토큰(`ZEROPW_CALLER_TOKEN`)뿐이다. 관리자 패스프레이즈나 원본 자격증명은 받지 않는다. `exec`를 쓰는 배포는 `zeropw_session`을 `serve` 바이너리 옆에 함께 둬야 한다. 없으면 `exec`가 `spawn_failed`로 실패하며, 평문 자격증명 경로로 대체하지 않는다.

## 설치

v0.1.0 바이너리는 Apple Silicon macOS와 ARM64 Linux를 지원한다. Linux 빌드 기준은 Ubuntu 24.04다. Intel macOS와 x86-64 Linux 바이너리는 이번 릴리스에 포함하지 않는다.

Apple Silicon macOS에서는 Homebrew로 설치한다. macOS 26.5에서 검증했으며 이전 버전은 아직 검증하지 않았다.

```sh
brew tap telicity-ai/zeropw https://github.com/telicity-ai/zeropw
brew install telicity-ai/zeropw/zeropw
brew test telicity-ai/zeropw/zeropw
zeropw-demo
```

ARM64 Linux에서는 [릴리스 안내](docs/releasing.md)의 아카이브 설치 절차를 따른다. Linux Homebrew 설치는 아직 검증하지 않았다. macOS Homebrew는 체크섬이 고정된 바이너리를 설치한다. 이 버전은 Rust나 Homebrew OpenSSL을 따로 설치할 필요가 없다. 자세한 검증 범위와 아카이브 설치 방법은 [릴리스 안내](docs/releasing.md)에 있다.

## 빌드와 실행

Rust 2024 edition을 지원하는 toolchain과 OpenSSL 3 개발 헤더가 필요하다. macOS에서는 Homebrew `openssl@3`를 쓰고 `OPENSSL_DIR=$(brew --prefix openssl@3)`를 지정한다.

```sh
cargo build --locked --manifest-path rust/Cargo.toml --bins
rust/target/debug/zeropw-demo
```

초기화부터 비밀과 연결 등록, 권한 설정, `serve` 실행, 에이전트 호출까지의 명령은 [구현 현황](docs/implementation.md) §10에도 있다.

## 데스크톱 앱 (미리 보기)

`desktop/`에는 관리 기능을 화면으로 옮긴 Tauri 데스크톱 앱의 미리 보기 버전이 있다. 금고 만들기, 키, 연결, 에이전트와 권한, 기록, 전체 정지, 사고 처리, 백업과 복구, 팀 초대 링크를 다룬다. 금고 코드를 링크하지 않고 함께 묶은 `zeropw-admin`을 명령마다 자식 프로세스로 실행한다. 이 앱을 담은 릴리스는 아직 없다. 소유자는 v0.2.0 릴리스에 이 앱을 Apple Silicon용 ad-hoc 서명 `.dmg` 미리 보기로 싣기로 정했다. 자세한 내용은 [데스크톱 앱 명세](docs/desktop-app.md)와 [디자인 규칙](DESIGN.md)에 있다.

알려진 한계:

- 화면은 한국어로만 나온다. 앱이 띄우는 macOS 로컬 네트워크 권한 창의 설명도 한국어이고, 영어판은 없다(소유자 결정).
- 같은 macOS 계정 안에서는 격리하지 않는다. 같은 사용자로 도는 프로그램은 에이전트를 포함해 개발용 기기 키 파일과 금고를 읽을 수 있다([#21](https://github.com/telicity-ai/zeropw/issues/21)). 앱은 에이전트를 다른 계정에서 실행하라고 권한다.
- 복구에 한계가 있다([#22](https://github.com/telicity-ai/zeropw/issues/22)). 복구 코드로 복구하려면 기존 기기 키 파일이 있어야 한다. 같은 데이터 키를 다시 감쌀 뿐이라 키 파일 유출 대책이 아니고, 복구 전에 만든 백업은 더 이상 복원할 수 없다.
- ad-hoc 서명한 미리 보기이고 공증하지 않았다. Developer ID 서명이 없어서 서명만으로는 누가 만들었는지 알 수 없다. 내려받은 이미지를 열어 ZeroPW를 응용 프로그램 폴더로 끌어다 놓고, 이미지를 꺼낸 뒤 응용 프로그램 폴더에서만 연다. 처음 열면 Gatekeeper가 막는다. 그다음 한 시간쯤 안에 시스템 설정의 개인정보 보호 및 보안에서 "그래도 열기"를 누르고 로그인 암호로 확인한다. 격리 속성을 지우거나 Gatekeeper를 끄지 않는다. 자세한 절차는 [릴리스 안내](docs/releasing.md#what-users-see-on-macos-15-and-later)에 있다.
- 자동 업데이트가 없다. 수정을 받으려면 앱을 직접 바꿔 넣어야 한다.
- macOS는 Apple Silicon(arm64)용만 있다. Intel이나 유니버설 빌드는 없다.
- 화면 캡처에서 빠진다고 기대하지 않는다. macOS에서는 복구 코드, 토큰, 초대 링크, 다시 본 키를 띄우는 동안 창을 캡처에서 빼 달라고 창 시스템에 요청할 뿐이다. macOS 15부터 ScreenCaptureKit을 쓰는 캡처, 녹화, 화면 공유 도구는 이 요청을 따르지 않는다는 보고가 있고, 배포 빌드에서는 시험하지 않았다. Linux에는 이런 요청이 없다. 화면을 공유하거나 녹화하는 동안에는 이런 값을 띄우지 않는다.

## 검증

```sh
rust/verify.sh              # fmt, 엄격한 Clippy, 라이브러리·바이너리 시험, 모든 통합 시험, 서명기 자원 측정, 문서 시험
rust/verify.sh --list       # 통합 시험 대상 목록
rust/verify.sh signer_e2e   # 특정 통합 시험만
```

`verify.sh`는 제품 코드를 빌드하고 실행한다. 게이트웨이·금고·서명기·관리자 자격증명이 있는 호스트가 아닌 CI 러너나 격리 VM에서 돌린다. SSH 종단 시험은 OpenSSH(`ssh`, `sshd`, `ssh-keygen`)와 `perl`을 쓴다. Python은 필요 없다.

Python 프로토타입을 제거하기 전에 만든 고정 시험 자료(`rust/tests/fixtures/python/`)로 호환성을 확인한다. 상태 디렉터리와 백업, 서명·다이제스트·통신 바이트를 비교하며 자료 생성 방법은 각 디렉터리의 `GENERATE.md`에 있다. 호환 범위는 [Rust 호환성 계약](rust/PORTING.md)을 따른다.

이 구현은 모든 CLI와의 호환, 운영 배포 준비, 서로 다른 OS 사용자 간 격리를 약속하지 않는다. 남은 경계와 한계는 [구현 현황](docs/implementation.md) §9에 있다.

## 문서

- [제품 정의](docs/product-intent.md)
- [인증 중계와 보안 경계](docs/security-design.md)
- [구현 현황](docs/implementation.md): 구성 요소, 사용 흐름, 보안 수용 시험 대응표, 한계, 실행 예시
- [실행 환경 침해 대응](docs/compromise-response.md): 자동 봉쇄, 노출 판정, 교체 안내 이메일
- [팀 공유](docs/team-sync.md): 서버 없는 환경 복제와 노드 간 P2P 동기화
- [Rust 호환성 계약](rust/PORTING.md)
- [데스크톱 앱 명세](docs/desktop-app.md)(미리 보기)와 [디자인 규칙](DESIGN.md)
- [Rust 전환 인수 기록](docs/rust-completion.md): 최종 검증 결과
- [개발 하네스](docs/harness.md), [하네스 안내](harness/README.md)
- [개정 반영 현황](docs/reviews/review-summary.md)
- [제품 정의 PDF](output/pdf/zeropw-product-definition.pdf): 2026-09-12 시점 스냅샷이다. 현행 기준은 Markdown이다.

`docs/archive/`와 `docs/reviews/`의 자료는 이전 설계와 검토의 이력이다. 현행 요구사항이나 새 검증 통과의 근거로 쓰지 않는다.
