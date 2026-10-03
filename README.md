# ZeroPW

에이전트에게 원본 비밀값을 주지 않고 CLI·API를 사용하게 하는 개인용 클라우드 금고다. 서비스와 자격증명을 한 번 연결하면 작업별 등록 없이 지원하는 CLI·API를 사용하며, 인증 중계와 SSH 서명 위임으로 원본 키를 실행 코드에서 분리한다.

제품 정의와 보안 기준은 확정 문서를 따르며, 제품 구현은 `rust/`의 Rust 크레이트다. 처음 만든 Python 프로토타입은 2026-10-03 Rust로 전환을 마치고 저장소에서 제거했다(마지막으로 포함한 커밋은 git 이력에 남아 있다). 합성 자격증명과 시험용 서버로만 검증했고 배포 전이다. 검증 상태는 [Rust 인수 기록](docs/rust-completion.md)을 따른다. 과거 클라우드/Opus 개발 하네스의 운영 설명은 [하네스 안내](harness/README.md)에 보존되어 있으며 현재 Rust 작업의 검증 완료를 뜻하지 않는다.

## Rust 빌드와 검증

Rust 2024 edition을 지원하는 toolchain이 필요하다. 시험은 Python 없이 돈다. 프로토타입과의 호환성(저장 상태, 서명·다이제스트·통신 바이트)은 프로토타입이 만든 고정 시험 자료 `rust/tests/fixtures/python/`로 확인한다. SSH 종단 시험은 OpenSSH(`ssh`, `sshd`, `ssh-keygen`)와 `perl`을 쓴다.

```sh
cargo build --locked --manifest-path rust/Cargo.toml --bins
cargo test --locked --manifest-path rust/Cargo.toml --all-targets
rust/target/debug/zeropw-demo
```

관리 명령은 `zeropw-admin --state-dir DIR COMMAND ...`, 에이전트 명령은 `zeropw-agent COMMAND ...`다. 에이전트는 `ZEROPW_GATEWAY_URL`과 자신의 제한된 `ZEROPW_CALLER_TOKEN`만 받고, 관리자 패스프레이즈나 원본 자격증명을 받지 않는다. `exec`를 사용하는 배포에는 신뢰하는 실행 보조 바이너리 `zeropw_session`을 서버/관리 바이너리 옆에 함께 두어야 한다. 없으면 `spawn_failed`로 실패하며 Python이나 평문 자격증명 경로로 대체하지 않는다.

이 구현은 프로토타입의 지원 범위를 유지한다. 모든 CLI 호환성, 운영 배포 준비 완료 또는 서로 다른 OS 사용자 간 격리를 약속하지 않는다. 프로토타입과 맞춰야 하는 경계(저장 상태, 통신·암호 형식, 기능, 보안)는 [Rust 호환성 계약](rust/PORTING.md) §0을 따른다.

## 현행 문서

- [제품 정의](docs/product-intent.md)
- [인증 중계와 보안 경계](docs/security-design.md)
- [클라우드 개발 하네스](docs/harness.md)
- [v1 구현 현황](docs/implementation.md) — 프로토타입 시기에 쓴 기능·시험 범위 기록. 실행 명령은 Rust 바이너리 기준
- [Rust 전체 기능 인수 기록](docs/rust-completion.md)
- [Rust 호환성 계약](rust/PORTING.md)
- [팀 공유: 서버 없는 환경 복제와 노드 간 동기화](docs/team-sync.md) — 리더 없는 P2P 커밋 전파. 설계 명세와 4단계(키·커밋·접기, 전송·동기화, 초대·제거·긴급 사실, 사건 공유·종단 시험) 구현. 구현 현황은 [v1 프로토타입 구현 현황](docs/implementation.md) §10 참고. Opus 리뷰 통과를 뜻하지 않는다
- [실행 환경 침해 대응 설계와 구현 계획](docs/compromise-response.md) — 자동 봉쇄와 교체 안내 이메일. 합성 자격증명으로 시험한 프로토타입 구현 포함
- [개정 반영 현황](docs/reviews/review-summary.md)
- [제품 정의 PDF](output/pdf/zeropw-product-definition.pdf) — 2026-09-12 세션 연계 하네스 결정 전의 제품 설명 스냅샷. 현재 개발 운영 방식은 Markdown을 따른다.

docs/archive의 자료와 2026-09-11 검토 기록은 이전 설계의 이력이다. 현행 요구사항이나 새 보안 검증 통과의 근거로 사용하지 않는다.
