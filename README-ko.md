# ZeroPW

ZeroPW는 에이전트에게 원본 비밀값을 주지 않고 CLI와 API를 쓰게 하는 개인용 금고다. 서비스와 자격증명을 한 번 연결하면 작업별 등록 없이 지원하는 CLI·API를 쓸 수 있다. 신뢰 프로세스 안의 중계기가 HTTP 인증 정보를 넣고 별도 서명기가 SSH 인증을 맡는다. 그래서 원본 키는 에이전트가 실행하는 코드에 들어가지 않는다.

제품 코드는 `rust/`의 Rust 크레이트(`zeropw`)에 있다. 합성 자격증명과 시험용 서버로만 검증했고 배포 전이다. 2026-10-03 Rust 전환을 마친 뒤 기존 Python 프로토타입을 저장소에서 제거했다. 코드는 git 이력에 남아 있다.

## 처음 사용한다면

[시작 안내](GUIDE.md)에 데모 실행부터 관리자 설정, 팀 가입, 에이전트 사용까지 필요한 절차를 적었다. 에이전트에는 [ZeroPW 스킬](skills/zeropw-agent/SKILL.md)을 설치할 수 있다.

팀원을 동시에 제거하면 기기마다 처리 결과가 달라질 수 있다. `team status`의 `rejected_removals`에 충돌이 표시되면 현재 관리자가 대상을 확인하고 의도한 제거를 다시 실행해야 한다. 제거된 팀원이 이미 읽은 자격증명은 외부 서비스에서 교체해야 무효화된다.

## 구성

| 바이너리 | 역할 | 실행 위치 |
| --- | --- | --- |
| `zeropw-admin` | 관리 CLI. 상태 디렉터리 초기화, 프로젝트·비밀·연결·호출 주체·권한 관리, 감사·알림 조회, 침해 대응, 팀 공유, 신뢰 프로세스 `serve` | 관리자 / 신뢰 호스트 |
| `zeropw-agent` | 에이전트용 CLI. `list-connections`, `request`, `exec`, `status`, `cancel` | 비밀 없는 실행 환경 |
| `zeropw_session` | `exec` 실행 보조 바이너리. `serve` 바이너리와 같은 디렉터리에 둔다 | 신뢰 호스트 |
| `zeropw-demo` | 시험용 값으로 전체 사용 과정을 보여 주는 데모 (종료 코드 0 = 모든 확인 통과) | 시연 |
| `zeropw-democli` | `exec` 지원 CLI 예시. 연결 핸들이 든 base URL만 받는다 | 시험·시연 |

에이전트가 받는 것은 게이트웨이 URL(`ZEROPW_GATEWAY_URL`)과 자기 호출 토큰(`ZEROPW_CALLER_TOKEN`)뿐이다. 관리자 패스프레이즈나 원본 자격증명은 받지 않는다. `exec`를 쓰는 배포는 `zeropw_session`을 `serve` 바이너리 옆에 함께 둬야 한다. 없으면 `exec`가 `spawn_failed`로 실패하며, 평문 자격증명 경로로 대체하지 않는다.

## 빌드와 실행

Rust 2024 edition을 지원하는 toolchain과 OpenSSL 3 개발 헤더가 필요하다. macOS에서는 Homebrew `openssl@3`를 쓰고 `OPENSSL_DIR=$(brew --prefix openssl@3)`를 지정한다.

```sh
cargo build --locked --manifest-path rust/Cargo.toml --bins
rust/target/debug/zeropw-demo
```

초기화부터 비밀과 연결 등록, 권한 설정, `serve` 실행, 에이전트 호출까지의 명령은 [구현 현황](docs/implementation.md) §10에도 있다.

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
- [Rust 전환 인수 기록](docs/rust-completion.md): 최종 검증 결과
- [개발 하네스](docs/harness.md), [하네스 안내](harness/README.md)
- [개정 반영 현황](docs/reviews/review-summary.md)
- [제품 정의 PDF](output/pdf/zeropw-product-definition.pdf): 2026-09-12 시점 스냅샷이다. 현행 기준은 Markdown이다.

`docs/archive/`와 `docs/reviews/`의 자료는 이전 설계와 검토의 이력이다. 현행 요구사항이나 새 검증 통과의 근거로 쓰지 않는다.
