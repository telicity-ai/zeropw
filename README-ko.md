# ZeroPW

ZeroPW는 에이전트에게 원본 비밀값을 주지 않고 CLI와 API를 쓰게 하는 개인용 금고다. 서비스와 자격증명을 한 번 연결하면 작업별 등록 없이 지원하는 CLI·API를 쓸 수 있다. 신뢰 프로세스 안의 중계기가 HTTP 인증 정보를 넣고 별도 서명기가 SSH 인증을 맡는다. 그래서 원본 키는 에이전트가 실행하는 코드에 들어가지 않는다.

제품 코드는 `rust/`의 Rust 크레이트(`zeropw`)에 있다. v0.2.0은 초기 릴리스이며 합성 자격증명과 시험용 서버로 검증했다. v0.2.0에는 Apple Silicon macOS용 데스크톱 앱 미리 보기도 들어 있다. 2026-10-03 Rust 전환을 마친 뒤 기존 Python 프로토타입을 저장소에서 제거했다. 코드는 git 이력에 남아 있다.

## 처음 사용한다면

[시작 안내](GUIDE.md)에 데모 실행부터 관리자 설정, 팀 가입, 에이전트 사용까지 필요한 절차를 적었다. 에이전트에는 [ZeroPW 스킬](skills/zeropw-agent/SKILL.md)을 설치할 수 있다.

팀원에게는 [한국어 HTML 매뉴얼](docs/team-onboarding.ko.html)이나 [영어 HTML 매뉴얼](docs/team-onboarding.en.html)을 전달하면 된다. 파일을 내려받아 브라우저에서 연다. 에이전트 검증 프롬프트도 [한국어](docs/team-agent-prompts.ko.txt)와 [영어](docs/team-agent-prompts.en.txt)로 제공한다. 매뉴얼과 프롬프트는 0.2.0 버전의 Homebrew 설치를 설명한다.

0.1.0은 초대 링크(`zeropw://join#…`)를 읽지 못한다. 초대 링크는 `team invite --link`가 출력하고, 데스크톱 앱은 초대를 링크로만 만든다. CLI로 합류하는 팀원도 0.2.0이 필요하다. Homebrew나 아래 설치 스크립트로 설치하고, Homebrew로 설치한 이전 버전은 `brew update`와 `brew upgrade telicity-ai/zeropw/zeropw`로 올린다. 0.1.0과 0.2.0 기기를 한 팀에 섞어 쓰는 경우는 시험하지 않았다.

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

v0.2.0 바이너리는 Apple Silicon macOS와 ARM64 Linux를 지원한다. Intel macOS와 x86-64 Linux 바이너리는 이번 릴리스에 포함하지 않는다. macOS 바이너리는 macOS 26.5에서 시험했으며 이전 버전은 검증하지 않았다. Linux 바이너리에는 glibc 2.39 이상(Ubuntu 24.04 이상)이 필요하다. `zeropw-admin`과 `zeropw-demo`가 GLIBC_2.39 심볼을 쓰므로 그보다 오래된 glibc에서는 실행되지 않는다.

릴리스 파일은 `zeropw-v0.2.0-aarch64-apple-darwin.tar.gz`와 `zeropw-v0.2.0-aarch64-unknown-linux-gnu.tar.gz`이고, 각각 `.tar.gz.sha256` 파일이 함께 있다. 압축 파일에는 바이너리 다섯 개와 `README.md`, `LICENSE`, `THIRD_PARTY_LICENSES.md`가 들어 있다. 0.2.0은 두 플랫폼 모두 v0.2.0 태그의 `scripts/install.sh`를 내려받아 내용을 읽어 본 뒤 실행해 설치한다.

```sh
curl -fsSLO https://raw.githubusercontent.com/telicity-ai/zeropw/v0.2.0/scripts/install.sh
bash install.sh --version v0.2.0 --prefix "$HOME/.local"
"$HOME/.local/bin/zeropw-demo"
```

설치 스크립트는 플랫폼에 맞는 압축 파일과 `.sha256` 파일을 v0.2.0 릴리스에서 받아 SHA-256과 압축 파일 항목을 확인한다. 그다음 바이너리는 `PREFIX/bin`에, 문서는 `PREFIX/share/doc/zeropw`에 설치한다. sudo를 쓰지 않고, 금고를 만들거나 서비스를 띄우거나 셸 설정 파일을 고치지 않으며, 받은 바이너리를 실행하지도 않는다. 이미 있는 파일은 덮어쓰지 않는다. 이전 설치를 바꾸려면 실행 중인 ZeroPW 프로세스를 멈추고 `--force`를 붙인다. 직접 내려받은 압축 파일은 `--version` 대신 `--archive FILE --sha256 HEX`로 설치한다. 체크섬은 파일 손상을 찾아낼 뿐 서명이 아니므로 릴리스 호스트와 게시자는 여전히 믿어야 한다. 자세한 내용은 [릴리스 안내](docs/releasing.md#packaging-tools)에 있다.

Apple Silicon macOS에서는 아래 명령으로 Homebrew에서 0.2.0을 설치한다. 설치된 버전은 `brew list --versions zeropw`로 확인한다. 이전 버전이 설치돼 있으면 실행 중인 ZeroPW 프로세스를 멈추고 `brew install` 대신 `brew update`와 `brew upgrade telicity-ai/zeropw/zeropw`를 실행한다.

```sh
brew tap telicity-ai/zeropw https://github.com/telicity-ai/zeropw
brew install telicity-ai/zeropw/zeropw
brew test telicity-ai/zeropw/zeropw
zeropw-demo
```

formula는 체크섬이 고정된 릴리스 압축 파일을 설치하므로 Rust나 Homebrew OpenSSL을 따로 설치할 필요가 없다. Linux Homebrew 설치는 검증하지 않았다. ARM64 Linux에서는 위의 설치 스크립트를 쓴다. Homebrew와 설치 스크립트로 모두 설치했다면 `PATH`에서 먼저 찾은 쪽이 실행된다. `command -v zeropw-admin`으로 확인한다.

## 빌드와 실행

Rust 2024 edition을 지원하는 toolchain과 OpenSSL 3 개발 헤더가 필요하다. macOS에서는 Homebrew `openssl@3`를 쓰고 `OPENSSL_DIR=$(brew --prefix openssl@3)`를 지정한다.

```sh
cargo build --locked --manifest-path rust/Cargo.toml --bins
rust/target/debug/zeropw-demo
```

초기화부터 비밀과 연결 등록, 권한 설정, `serve` 실행, 에이전트 호출까지의 명령은 [구현 현황](docs/implementation.md) §10에도 있다.

## 데스크톱 앱 (미리 보기)

`desktop/`에는 관리 기능을 화면으로 옮긴 Tauri 데스크톱 앱의 미리 보기 버전이 있다. 금고 만들기, 키, 연결, 에이전트와 권한, 기록, 전체 정지, 사고 처리, 백업과 복구, 팀 초대 링크를 다룬다. 금고 코드를 링크하지 않고 함께 묶은 `zeropw-admin`을 명령마다 자식 프로세스로 실행한다. v0.2.0 릴리스에는 이 앱이 Apple Silicon Mac용 ad-hoc 서명 미리 보기 디스크 이미지 `zeropw-desktop-v0.2.0-aarch64-apple-darwin.dmg`로 들어 있고, `.dmg.sha256` 파일이 함께 있다. 이 이미지는 macOS 26.5인 Mac 한 대에서 빌드했고 그 Mac에서만 실행해 봤다. 내려받은 파일에 붙는 격리 속성이 없는 상태였다. 다른 macOS 버전은 검증하지 않았고, 아래 Gatekeeper 절차는 시험하지 않았다. 자세한 내용은 [데스크톱 앱 명세](docs/desktop-app.md)와 [디자인 규칙](DESIGN.md)에 있다.

설치 방법:

1. [v0.2.0 릴리스](https://github.com/telicity-ai/zeropw/releases/tag/v0.2.0)에서 이미지와 `.dmg.sha256` 파일을 같은 폴더에 내려받고, 이미지를 열기 전에 체크섬을 확인한다. `zeropw-desktop-v0.2.0-aarch64-apple-darwin.dmg: OK`가 나와야 한다.

   ```sh
   shasum -a 256 -c zeropw-desktop-v0.2.0-aarch64-apple-darwin.dmg.sha256
   ```

2. 이미지를 열어 ZeroPW를 응용 프로그램 폴더로 끌어다 놓고 이미지를 꺼낸다. 앱은 응용 프로그램 폴더에서만 연다.
3. 응용 프로그램 폴더에서 ZeroPW를 연다. Apple이 ZeroPW에 악성 코드가 없는지 확인할 수 없다는 창이 뜨면 "완료"를 눌러 닫는다.
4. 한 시간쯤 안에 시스템 설정 › 개인정보 보호 및 보안을 열고 보안 항목까지 내려가 ZeroPW 메시지 옆의 "그래도 열기"를 누른다. 로그인 암호로 확인한 뒤 "열기"를 고른다. 버튼이 없어졌으면 3단계부터 다시 한다.

이 절차는 macOS 15 이후에 대한 Apple 문서를 따른 것이다. 이 이미지로 이 절차를 거쳐 본 Mac은 없다(아래 한계 참고). 격리 속성을 지우거나 Gatekeeper를 끄지 않는다. 응용 프로그램 폴더에서 열어야 하는 이유는 [릴리스 안내](docs/releasing.md#what-users-see-on-macos-15-and-later)에 있다.

알려진 한계:

- 화면은 한국어로만 나오고 영어판은 없다(소유자 결정). 앱이 macOS 로컬 네트워크 권한 창에 넣는 설명도 한국어다. 그 창의 제목과 버튼은 macOS가 정한다.
- macOS는 Apple Silicon(arm64)용만 있다. Intel이나 유니버설 빌드는 없다.
- ad-hoc 서명한 미리 보기이고 공증하지 않았다. Developer ID 서명이 없어서 서명만으로는 누가 만들었는지 알 수 없고, 위 절차로 허용하기 전까지 Gatekeeper가 처음 여는 것을 막는다.
- 이번 미리 보기에서 시험하지 않은 것이 있다. 위 Gatekeeper 절차는 이 이미지로 어느 Mac에서도 해 보지 않았다. 깨끗한 Mac에 내려받은 이미지를 설치하고 Gatekeeper를 거쳐 처음 여는 확인은 소유자가 면제했다. 소유자는 다른 확인 세 가지도 면제했다. 앱이 권하는 에이전트 명령을 다른 macOS 계정으로 실행하는 것, "그래도 열기" 뒤에 macOS가 앱의 ad-hoc 서명 보조 프로그램(`zeropw-admin`, `zeropw_session`, `zeropw-agent`)을 막거나 묻는지 보는 것, 앱 메뉴의 종료(Cmd+Q)로 앱을 끝내는 것이다.
- 자동 업데이트가 없다. 수정을 받으려면 앱을 직접 바꿔 넣어야 한다.
- 창을 닫아도 앱은 끝나지 않는다. 앱, 중계기, 에이전트 터미널이 계속 돈다. 창은 Dock에서 다시 열고, 앱은 Cmd+Q로 끝낸다. 강제 종료처럼 앱을 끝내지 않고 죽이면 중계기는 계속 돈다.
- 터미널보다 오래 사는 에이전트가 있다. 에이전트 터미널을 닫거나 앱을 끝내면 그 터미널에서 시작한 프로세스는 멈춘다. 하지만 앱이 권하는 대로 다른 계정으로 실행한 에이전트와 터미널에서 떨어져 나간 프로세스(`setsid`, tmux, screen, 데몬)는 멈추지 않고 호출 토큰을 든 채 계속 돈다. 그 토큰을 막는 방법은 앱에서 그 에이전트를 끄는 것뿐이다.
- 같은 macOS 계정 안에서는 격리하지 않는다. 같은 사용자로 도는 프로그램은 에이전트를 포함해 개발용 기기 키 파일과 금고를 읽을 수 있다([#21](https://github.com/telicity-ai/zeropw/issues/21)). 앱은 에이전트를 다른 계정에서 실행하라고 권한다.
- 복구에 한계가 있다([#22](https://github.com/telicity-ai/zeropw/issues/22)). 복구 코드로 복구하려면 기존 기기 키 파일이 있어야 한다. 같은 데이터 키를 다시 감쌀 뿐이라 키 파일 유출 대책이 아니고, 복구 전에 만든 백업은 더 이상 복원할 수 없다.
- 비밀번호를 바꿀 수 없다. 앱도 CLI도 관리 비밀번호와 복구 코드를 바꾸지 못한다. [침해 대응 절차](docs/compromise-response.md)는 전역 사고를 닫기 전에 둘 다 바꾸라고 하지만 이 버전에서는 바꿀 수 없다.
- 입력한 비밀번호의 사본이 메모리에 남을 수 있다. 앱 창에서 코어로 보낸 비밀번호는 Tauri IPC 버퍼에 사본이 남을 수 있다. 관리 비밀번호와 직접 정한 복구 코드는 강도를 확인하느라 입력이 바뀔 때마다 보내므로 사본이 여럿 남을 수 있다.
- 팀원도 0.2.0을 써야 한다. 앱은 초대를 링크로만 만드는데 0.1.0은 이 링크를 읽지 못한다(위 "처음 사용한다면" 참고).
- 복사한 값이 남을 수 있다. 앱은 복사한 토큰, 초대 링크, 다시 본 값이 60초 뒤에도 클립보드에 그대로 있으면 지우고, 클립보드 기록에서 빼 달라는 표시를 붙인다. 이 표시를 따르지 않는 기록 도구는 값을 남길 수 있고, 유니버설 클립보드는 값을 다른 Apple 기기로 보낼 수 있다.
- 화면 캡처에서 빠진다고 기대하지 않는다. macOS에서는 복구 코드, 토큰, 초대 링크, 다시 본 키를 띄우는 동안 창을 캡처에서 빼 달라고 창 시스템에 요청할 뿐이다. macOS 15부터 ScreenCaptureKit을 쓰는 캡처, 녹화, 화면 공유 도구는 이 요청을 따르지 않는다는 보고가 있고, 배포 빌드에서는 시험하지 않았다. Linux에는 이런 요청이 없다. 화면을 공유하거나 녹화하는 동안에는 이런 값을 띄우지 않는다.

## 검증

```sh
rust/verify.sh              # fmt, 엄격한 Clippy, 라이브러리·바이너리 시험, 모든 통합 시험, 서명기 자원 측정, 문서 시험
rust/verify.sh --list       # 통합 시험 대상 목록
rust/verify.sh signer_e2e   # 특정 통합 시험만
```

`verify.sh`는 제품 코드를 빌드하고 실행한다. 게이트웨이·금고·서명기·관리자 자격증명이 있는 호스트가 아닌 CI 러너나 격리 VM에서 돌린다. SSH 종단 시험은 OpenSSH(`ssh`, `sshd`, `ssh-keygen`)와 `perl`을 쓴다. Python은 필요 없다.

Python 프로토타입을 제거하기 전에 만든 고정 시험 자료(`rust/tests/fixtures/python/`)로 호환성을 확인한다. 상태 디렉터리와 백업, 서명·다이제스트·통신 바이트를 비교하며 자료 생성 방법은 각 디렉터리의 `GENERATE.md`에 있다. 호환 범위는 [Rust 호환성 계약](rust/PORTING.md)을 따른다.

이 구현은 모든 CLI와의 호환이나 운영 배포 준비를 약속하지 않는다. 로컬 개발 구성은 에이전트와 금고가 같은 OS 사용자로 돌 때 둘을 서로 격리하지 않는다. 남은 경계와 한계는 [구현 현황](docs/implementation.md) §9에 있다.

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
