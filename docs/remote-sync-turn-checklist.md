# 개인 기기 동기화: coturn 서비스 설계와 구현 체크리스트

작성: 2026-11-06 · Astra · 상태: 구현 통합 및 일부 Linux 검증, 출시 인수 미완료

갱신: 2026-11-07 · 아래 §0.1에 실제 소스·검증·미완료 상태를 추가했다. 사용자 결정은 §0, 설계는 [remote-sync.md](remote-sync.md), 실행 증거와 열린 리뷰는 [2026-11-07 검증 기록](remote-sync-validation-2026-11-07.md)에 구분한다. 부분 시험 통과는 전체 항목 완료가 아니다.

## 0. 2026-11-06 결정으로 달라진 범위

| 항목 | 이전 문서 | 2026-11-06 결정 |
| --- | --- | --- |
| 출시 검증 OS | macOS+Linux 권장, Windows 미정 | macOS만 MLP 출시 조건. Linux·Windows는 출시 조건 아님. 기존 Linux CI와 시험은 약화하거나 통과로 바꿔 표시하지 않는다 |
| 동기화 시점 | 제안 기본값 | 확정: 두 기기가 온라인일 때 버전별 동기화 |
| 서버 보관 | 제안 기본값 | 확정: 금고 원문·복호화 키·오프라인 전달용 금고 사본을 서버에 두지 않는다 |
| 등록 | 초대 코드 | 확정: 이메일 없이 초대 코드로 서버 이용 기기 등록 |
| 제한 네트워크 | 미정 | 확정: TURN TLS 5349로 시작. TCP 443 전용망 지원은 출시 조건 아님 |
| 저장소 | 이름·소유자 미정 | 연결 모듈·서비스 계층은 별도 저장소 `zeropw-link`(소유자는 기존 설정의 `telicity-ai`) |
| 목적 | 베타 | 개인 사용자·개인 개발자 대상 MLP로 실제 사용 경험과 오픈소스 반응을 확인 |
| 수용 인원 | 100명/200기기 제안 | 제안일 뿐 확정 아님. 측정 없이 보장하지 않는다 |
| 복구 | 미정 | 이메일 없는 복구를 이유로 운영자 복호화·우회 접근을 추가하지 않는다. 복구 코드+암호화 백업은 기존 로컬 기능 범위 |

아직 유효한 보안 요구는 §1~§4 그대로 둔다. §4의 E10은 macOS 출시 검증과 기존 Linux 검증을 구분해 기록하는 것으로 읽는다(Linux 실행을 생략했다면 생략했다고 쓴다). 기존 동기화·wire·암호화 계약을 재사용하는 구체 설계는 [remote-sync.md](remote-sync.md) §2–§3에 있다.

### 0.1. 2026-11-07 작업 상태와 항목별 근거

이번 문서 갱신 전 비교한 ZeroPW 소스는 `1f60bc2a3f2b91fa691dfa9f79c81bfb131aabe1`이다. Linux 검증
대상 `41d217f26a030042c9f0b1caac9417715470c0e1`과 Rust tree
`f2c67647fcba83ae78dd6fd10418b6f42a58a6f8`이 같다. 작업 중인 sidecar pin은 ACL 수정 커밋 `f544478a48cea66be816efbed50967bafcacc8ac`이며,
초기 리뷰는 이전 `bcdaaecd569a71bf4df07c738869e1e0c7a577e1`만 대상으로 했다.
통합 구현은 존재하지만 **출시 인수는 미완료**다. Linux desktop 검증의 336개
Vitest와 fake-daemon 페어링 2개 통과를 실제 네트워크나 물리 Mac 2대 시험으로
표시하지 않는다. Linux 전체 Rust 첫 실행은 디스크 부족으로 실패했으나 전체 재실행은
exit 0(100단계, 1,621통과)으로 끝났고 별도 signer probe도 통과했다. 실제 네트워크
E2E는 새 Rust `d77ce9e`+link `f544478`에서도 exit 0, 66/66 assertion과
**7개 합성 서비스 비밀을 대상으로 한 별도 로그 검사 1회**를 통과했다.
`desktop/package-f544478.log`의 패키징 도구 시험 61개도 exit 0이다.
격리 Tart macOS 26.6.2 arm64 VM의 고정 `1f60bc2` 전체 시험은 exit 1로 끝났다.
100단계 중 99통과/lib 단계 실패, 총 1,622통과/2실패/4ignored이며 signer probe도 실행했다. Darwin closed-peer
SO_RCVTIMEO errno 22에 대한 수정 `d77ce9ed7170f9e2689bc1ecf5244aa9602cc587`의
Rust tree는 `181f99ddbffedb3b7f5c158d7484afca37be8a8a`로 달라졌다. Linux strict
all-target Clippy와 244개 team 시험은 통과했으나 Linux 전체 matrix는 100단계,
1,621통과/1실패/4ignored로 끝났다. 실패는 team_link_transport의 송신 시도와
실제 수신 프레임을 동일시한 assertion이며 평문 누출 검사 실패가 아니다. 모든 비밀 검사와
수신 프레임의 relay 통과 증명을 유지하고 3개 초과 수신 guard를 추가한 test-only
`7f0421a`에서 Clippy/12개 target 시험을 통과한 뒤, 변경하지 않은 전체 검증도
exit 0으로 통과했다(100단계, 1,622통과/0실패, ordinary ignored 4개와 별도 signer probe 실행).
근거는 `integ/rust-verify-7f0421a-linux.log`와 [결과 manifest](evidence/2026-11-07-linux-rust-7f0421a.json)다.
Native d77 시험에서는 8,193바이트를 수신 전에 동기 송신하던 fixture가 Darwin의
8,192바이트 버퍼를 채워 멈췄다. 모든 경계 assertion을 유지한 concurrent-writer
test-only 수정 `d942263`의 Linux Clippy/8개 link 시험은 통과했다. 원래 driver는
증거를 보존하고 중단했으며 새 v2 driver는 d942 Rust/core와 f544 Go를 검증 중이다.
Native link 8개/frame 2개는 통과했지만 전체 Rust는 exit 1로 끝났다
(100단계, 1,621통과/4실패/4ignored). capture 실패와 signer directory/cleanup
assertion 3개 실패를 [native manifest](evidence/2026-11-07-macos-rust-d942263.json)에
보존했다. Go vet는 진행 중이며 native Go/ACL/core 결과는 아직 없다.
Native link integration은 strict capture 방향 검사에서 11통과/1실패였다.
동시 기록의 조각이 섞이는 문제를 2프로세스/8스레드/512개 기록으로 재현했고,
전체 기록에 file lock을 적용한 `945e6a6`에서 Linux Clippy·회귀시험·기존 전송
12개 시험을 통과했다. 형식·평문 누출 검사는 유지했다. `945e6a6` 전체 Linux
검증도 exit 0으로 통과했다(100단계, 1,623통과/0실패, ordinary ignored 4개와
별도 signer probe 실행). [결과 manifest](evidence/2026-11-07-linux-rust-945e6a6.json)는
해당 Rust tree와 로그를 연결한다. native v2의 고정 `d942263` Rust 실패는
보존하며 `945e6a6` native 수정 검증과 signer 실패 진단은 별도로 필요하다.
이전 Linux/E2E 통과를 새 전체 matrix 통과로 옮기지 않는다. 물리 Mac 2대 시험은 NOTRUN이다.

아래 표는 §4의 각 요구에 붙인 진행 기록이다. `부분`은 구현 또는 일부 시험
근거만 있다는 뜻이며 체크박스를 채우는 근거가 아니다. 상세 환경·로그·원래
리뷰 전문은 [날짜별 검증 기록](remote-sync-validation-2026-11-07.md)을 따른다.
§3의 Iroh/coturn 소스 조사는 여전히 조사이며 upstream 시험 통과 기록이 아니다.

| ID | 현재 근거와 남은 조건 |
| --- | --- |
| A01 | 부분: link 의존성 선택과 라이선스 수집 코드 존재. 최종 배포 산출물의 크기·합산 메모리·취약점 검증표 미완료 |
| A02 | 조사: §3은 upstream 참고 출처. 최종 산출물의 소스 재사용·고지 대조 완료 근거 미확정 |
| A03 | 부분: Linux link-core `49d6f8d`의 실제 coturn UDP/TCP/TLS 전송 로그. 현재 통합 head·macOS 인수는 별도 |
| A04 | 부분: QUIC/ICE 전송 및 이전 netns 시험. MTU·손실·열화 전체 행렬과 현재 통합 head의 완료 근거 없음 |
| A05 | 부분: 별도 link wire/stream 계약과 파서 시험 존재. 최종 고정 head와 전체 종료·취소 경계 검증 필요 |
| B01 | 부분: 초대 HMAC 저장·트랜잭션 소비 구현. 동시 실패 예산 ZPLINK-OPUS-02 수정·Linux 시험 통과, Opus 재인수 대기 |
| B02 | 부분: Ed25519 challenge/session 구현. 공용 challenge 고갈 ZPLINK-OPUS-01 수정·Linux 시험 통과, Opus 재인수 대기 |
| B03 | 부분: 명시적 fingerprint 승인과 desktop 흐름, fake-daemon 시험 2개 통과. 실제 Linux 네트워크 새 `d77ce9e`+`f544478` 통과; native 시험 진행 중/두 Mac 미검증 |
| B04 | 부분: 세션·등록 제한 구현. challenge 고갈/유실 응답 복구 수정·시험 통과. OPUS-03 orphan 회수/재시작/키 회전도 `858ddc` 시험 통과; Opus 재인수 대기 |
| B05 | 부분: link `docs/protocol.md`에 구현 API 계약 존재. 최종 수정 head의 통합 검증 필요 |
| B06 | 부분: 서명된 rendezvous와 replay 제한 구현 및 이전 link 단위시험. 최종 head·macOS 경로 검증 필요 |
| B07 | 부분: 서비스 계정 권한과 금고 승인 분리. TURN bearer 잔존·회수 보장은 실제 배포 시험과 구분 |
| B08 | 부분: LAN fallback과 상태/오류 UX 구현. 최종 두 Mac 환경에서 서버 장애 시나리오 미검증 |
| C01 | 부분: coturn 4.18.0 고정. 고유 build UID/non-root probe를 쓴 격리 VM 실제 빌드 통과; OCI 설치/인수 없음 |
| C02 | 부분: 서비스/coturn 전용 secret 구성 및 합성 로그 시험 이력. 운영 배포는 아직 없음 |
| C03 | 부분: 이전 Linux lab의 만료·Refresh·allocation 잔존 시험. 선택 배포 설정에서 재확인 필요 |
| C04 | 부분: coturn CLI 회수 구현과 이전 daemon lab의 종료 계측. Linux E2E 새 `d77ce9e`+`f544478`의 금고/서비스 기기 회수 통과; 실제 배포 인수 별도 |
| C05 | 부분: quota/대역폭 설정과 이전 lab 시험. timestamp별 우회·최종 합산 용량 보장 미완료 |
| C06 | 부분: 차단 목록 및 이전 coturn lab 존재. 실제 OCI 주소/방화벽 적용과 지원 주소 계열 인수 미완료 |
| C07 | 부분: TURN 오용 제한 설계·설정. 공용 배포 악용/경보 시험 미완료 |
| C08 | 부분: loopback 관리 포트/로그 제한 구성. OCI 외부 노출 검사 미실행; DOS-1과 운영 리뷰 미완료 |
| C09 | 부분: metrics 운영 정책 문서. 실제 배포의 label 수·메모리 장시간 계측 없음 |
| D01 | 미완료: 암호화 팀 세션/분리 daemon 구현. 프로세스 분리만으로 OS 격리 입증 불가; macOS ACL f544478 수정·Linux 시험/API probe 통과, native 제품 regression/Opus 대기로 ZPL-SEC-03 열림 |
| D02 | 부분: `zpl:` ZeroPW 어댑터 통합 및 PORTING 반영. Linux 945e6a6 전체 100단계/1,623통과. native baseline 2실패/Linux d77 capture 1실패 보존. d942 native 전체 4실패, 원인 진단/수정 인수 미완료 |
| D03 | **제품 공백**: 초기 snapshot 미구현. 현재 signed-history bootstrap은 compacted history 신규 기기 온보딩 불가 |
| D04 | 부분: 기존 서명 commit·vector·durable 저장 재사용. Linux 프로세스/coturn 재시작 E2E 통과. crash/ACK 유실/원자성 전체 인수와 snapshot 경로 없음 |
| D05 | 부분: link 프레임/큐 및 기존 팀 권한 검사. 최종 통합 head의 저장·자원 실패 경계 검증 미완료 |
| D06 | **미완료**: 버전 회수는 전체 secret 삭제가 아님. 이전 유효 버전이 활성화될 수 있어 tombstone/no-resurrection 별도 시험 필요; 디스크 부족·강제 종료도 별도 |
| E01 | 부분: handlecu/ap-chuncheon-1 Free Tier에서 zeropw-link-beta VM 생성 성공. 공인 IP 168.107.31.44/사설 IP 10.0.0.234 확인. DNS-only A zeropw-turn.telicity.ai 확인. NSG 7규칙 primary VNIC 연결과 인증서 발급 완료. OS 80 허용 저장/서비스 활성화 확인; 제품 배포·전체 방화벽 인수 미완료 |
| E02 | 설계/산출물: HTTPS 443와 TURN TLS 5349 분리. OCI 실제 bind/외부 도달 시험 없음; 443-only망 지원 주장 없음 |
| E03 | 부분: relay 포트 범위 산정/설정 존재. 실제 OCI allocation 용량 시험 없음 |
| E04 | 합산 부하시험 NOTRUN: OCI OS-only 메모리/디스크 baseline만 기록. coturn+서비스+OS 합산 자원/egress 측정 없음 |
| E05 | NOTRUN: 200기기·24시간·동시 초기 snapshot 시험 없음. 100명 수용 보장 없음 |
| E06 | 개발 시험은 합성 값/통제 endpoint. OCI 생성은 기존 공개 SSH 키만 사용; 이 기록에 운영 비밀 없음 |
| E07 | NOTRUN: 전체 시나리오 데이터 불일치·95%/60초 재접속 목표 측정 없음 |
| E08 | 부분: 재배포·복구·health/로그 운영 산출물 및 이전 nspawn 시험. OCI 적용/장애·경보 시험 없음 |
| E09 | 부분: 등록 DB와 revocation journal 복구 절차/이전 시험. 실제 OCI 백업·복원과 용량 인수 미완료 |
| E10 | **미완료**: Linux 945e6a6 전체 통과; native baseline 2실패/Linux d77 1실패 보존. d942 targeted native 8+2 통과/전체 4실패, native Go/core 대기, 두 Mac NOTRUN. 수정 후 Opus 대기; SEC03 열림, network/ops 리뷰 미완료, aggregate PASS 없음 |

초기 유효 리뷰와 검증은 실제 `claude-opus-5-5` 실행이다. 초기 구현 작업자도
실제 `claude-opus-5-5`였으며 Sol로 바꿔 기록하지 않는다. 현재 coordinator는
`gpt-6.1-sol`, 현재 실제 네트워크 E2E 작업자도 `gpt-6.1-sol`, 이 상태 기록 담당은
`gpt-6-astra`다. network 리뷰 로그에는
Opus 5.5와 4.8이 섞였고 결과가 잘려 완료 리뷰로 받지 않았다. Claude 제한의
확인된 해제 시각은 2026-11-07 12:50 KST이며 이 기록에서 재호출하지 않았다.
link 수정은 `cc733dc` 및 orphan 회수 후 복구 추가 `858ddc`로 커밋되어 비공개 저장소의 [draft PR #1](https://github.com/telicity-ai/zeropw-link/pull/1)에 있다.
Linux Go 전체/vet·server/daemon race·shell lint, 배포 단위시험 106개, 실제 coturn
빌드, Darwin cross-build, desktop 패키징 도구 시험 61개가 통과했다. macOS 실행이나
Opus 재인수는 아니다. 이전 Go 실패와 수정한 시험의 종료 조건도 검증 기록에 보존했다.
이전 pin `858ddc`에서 패키징 도구 61개, Darwin cross-build, 실제 네트워크
66/66+7개 합성 비밀 검사가 통과했다. Tart VM은 synthetic-only/no host mounts,
Rust 1.98.1/Go 1.27.3 환경이다. 기존 driver 7245는 fixture deadlock 증거를
보존한 뒤 중단했다. 대체 driver 8090은 고정 d942 Rust/core와 f544 Go를
`/Volumes/ZeroPWBuild/verification-20261107-v2/`에서 검증 중이다. 교체 기록은
`macos/v2-owned-replacement.log`에 있으며, 대기 중인 단계는 통과가 아니다.
Let’s Encrypt 인증서(만료 2027-02-05) 발급과 certbot.timer 활성화는 확인했지만
제품·HTTPS·TURN listener는 아직 없으며, endpoint 동작을 확인한 것은 아니다.
OS 80 허용은 netfilter-persistent 1.0.20으로 저장(exit 0)하고 활성화했다.
인증서 갱신 dry-run은 무작위 대기 중 중단한 첫 로그를 보존한 뒤,
`oracle-acme-renew-dryrun-no-jitter-20261107.log`에서 exit 0으로 통과했다.
초기 snapshot과 전체 secret 삭제의 [다음 마일스톤](remote-sync-next-milestones.md)은
실제 Rust 코드를 근거로 한 제안이며 구현 완료 근거가 아니다.
link ACL 수정 `f544478`은 Linux vet/Go 전체/server·daemon race와 CGO0 Darwin arm64
시험 cross-compile을 통과했다. 첫 실행은 wrapper TMPDIR 0775로 CA 경로 검사가
실패해 0700 환경으로 고친 뒤 재실행했으며 제품 검사는 바꾸지 않았다. macOS의
checked-fd `/bin/chmod -N` OS API probe는 통과했지만 native 제품 시험은 아니다.
사용자 지정 CA/상위 경로의 ACL 보호도 NOT VERIFIED(자체 점검, 외부 finding 아님)다.
SEC03은 native 제품 regression과 Opus 확인까지 열린다. `ca01275`는 그 뒤 README만
추가한 커밋이다. Linux 용량 확보는 비활성 MLP cache 하나만 대상으로 했고 먼저 제품
바이너리 5개와 SHA를 보존했다(`linux-cache-reclaim-20261107.log`, 이후 약 11GB 여유).
추가로 비활성 `integ-dverify`/`integ-desktop`/`desktop-core`의 정상 제품 바이너리를
inode 그대로 이동하고 SHA를 기록한 뒤 cache를 제거했다. 소스·로그·E2E 입력·실행 중인
target은 보존했으며 `linux-cache-reclaim-m1-capacity-20261107.log`에 약 18GiB 여유를 기록했다.
Tart guest의 `/bin/chmod` Apple-anchor 서명 확인은 통과했지만 SIP는 upstream
이미지에서 **disabled**다(`macos/acl-helper-platform-integrity.log`). 이 작업에서
보안 설정은 변경하지 않았다. 따라서 native 시험은 production OS 격리 증명이나
물리 Mac 2대 시험이 아니며, 이 환경 한계를 유지한다.
원래 severity와 반박 검증은
[partial archive](reviews/2026-11-07-link-initial.partial.json)에 그대로 보존했다.

## 1. 확정된 결정과 범위

사용자의 최신 결정이 이전 제품 문서의 개인 동기화·클라우드 전제보다 우선한다.

- 개인의 로그인 정보·비밀번호·API 키를 본인 기기 사이에서 암호화 동기화한다.
- 별도 저장소 `telicity-ai/zeropw-link`에서 재사용 가능한 연결 모듈과 서비스 계층을 관리한다(§0 결정).
- Iroh 전체 SDK를 제품 의존성으로 넣지 않는다. 소스와 테스트를 참고해 요구사항을 도출한다.
- 암호화·ICE·TURN 처리를 위한 필요한 소형 라이브러리는 허용한다. 암호 알고리즘이나 신뢰성 전송을 새로 발명하지 않는다.
- 서버 중계는 coturn, 운영 환경은 Oracle Cloud로 한다.
- 베타는 초대 코드로 기기를 등록하며 이메일 계정을 요구하지 않는다.
- 무료 VM으로 시작하며 일시적인 원격 동기화 중단을 허용한다. 유료 자원 자동 전환은 하지 않는다.
- 원본 비밀 비전달, 신뢰 금고·HTTP gateway·SSH signer 경계는 유지한다. 이번 결정은 SSH 서명 기능 제거가 아니다.

다음은 제안 기본값이며 사용자 확정과 구분한다: 100명/사용자당 2기기, 첨부파일 제외. 양쪽 온라인일 때 버전별 동기화하고 서버에 오프라인 금고 사본을 보관하지 않는 조건은 §0에서 확정했다. 이 문서는 TURN 기반 신규 구현의 인수 기준이며 모든 항목이 이미 지원·검증됐다는 뜻이 아니다.

## 2. 구성과 책임

```text
기기 A의 신뢰 금고 ─ 암호화 변경 묶음 ─ 연결 프로세스 A
                                       │
                              직접 연결 또는 coturn
                                       │
기기 B의 신뢰 금고 ─ 검증 후 원자적 반영 ─ 연결 프로세스 B

연결 프로세스 A/B ─ HTTPS ─ 서비스 계층
                           ├ 기기 등록·공개키·서버 이용 권한
                           ├ 일회용 연결 초대·단기 연결 정보 교환
                           └ 단기 TURN 자격증명 발급
```

coturn은 데이터 전달을 담당한다. 서비스 계층은 신원과 사용 자격, 연결 정보 교환을 담당한다. 서비스 계층은 금고 키·금고 원문을 받지 않는다. 서버 이용을 허용하는 베타 초대와 금고 공유를 허용하는 기기 페어링은 별개다. 운영자가 베타 초대를 발급할 수 있다는 이유로 금고에 기기를 추가할 수 없어야 한다.

Iroh relay 프로토콜과 coturn은 호환되지 않는다. Iroh의 QUIC 경로 전환 코드를 가져오면 TURN이 지원된다고 가정하지 않는다. ICE 후보 선택 + TURN UDP 및 TCP/TLS 경유 + 신뢰성 있는 암호화 스트림을 실제로 조합하는 기술 검증이 첫 마일스톤이다. QUIC 라이브러리를 선택할 경우 TURN allocation을 통해 전달되는 데이터그램을 QUIC I/O에 연결하는 어댑터와 경로 변경 동작을 검증해야 한다. 단순히 IP를 교체하는 구현은 금지한다.

베타에서는 경로 변경 시 세션을 다시 인증하고 변경 묶음을 이어받는 구현을 우선한다. Iroh 수준의 무중단 multipath를 약속하지 않는다. 연결 모듈은 불투명한 바이트를 다루고 ZeroPW의 환경·멤버십·금고 의미를 알지 않는다.

## 3. 조사한 소스와 요구사항 추출

읽기만 수행했으며 upstream 테스트를 실행하지 않았다. 아래 테스트 존재는 통과 증거가 아니다. 제외된 테스트도 함께 기록한다.

Iroh 기준 커밋: `a5e39c44d3d6dfaaff30b7292126e06ea0ab7a21`.
coturn 설정 조사 기준 커밋: `ad8885a54ac1d59a39f2cc49ae7662fc2d842c64`.
이는 조사 시점 식별자이며 출시 버전 선택이 아니다.

| ID | 확인한 구현·시험 | 우리 구현의 요구사항과 인수 시험 |
| --- | --- | --- |
| N01 | [NAT 행렬](https://github.com/n0-computer/iroh/blob/a5e39c44d3d6dfaaff30b7292126e06ea0ab7a21/iroh/tests/patchbay/nat.rs): None/Open/Moderate/Strict 조합. Moderate–Strict, 역방향, Strict–Strict 직접 연결 테스트는 ignore | NAT 조합별 직접 연결 또는 TURN 성공을 구분. 모든 NAT에서 직접 연결을 강제하지 않음. 역할 양방향 시험 |
| N02 | [relay 테스트](https://github.com/n0-computer/iroh/blob/a5e39c44d3d6dfaaff30b7292126e06ea0ab7a21/iroh/tests/patchbay/relay.rs): `relay_connect_ipv4`, `relay_connect_ipv6`, 한쪽/양쪽 UDP 차단 | TURN TCP/TLS 경로로 암호화 파일을 실제 전송. 단순 서버 ping은 합격 근거가 아님. IPv4/IPv6 및 혼합 경로의 지원 범위 표시 |
| N03 | 같은 파일의 `relay_reconnect_link_outage_client/server`, `relay_reconnect_relay_restart` | 5초 링크 중단과 coturn 재시작 후 재인증·allocation 재생성·중복 없는 재개. 직접 경로로 우연히 성공하지 않도록 강제 중계 |
| N04 | [LAN 주소 변경](https://github.com/n0-computer/iroh/blob/a5e39c44d3d6dfaaff30b7292126e06ea0ab7a21/iroh/tests/patchbay/network-switch-no-wan.rs): `lan_switch_advertises_new_addr_without_relay`, 연속 두 번 이동, 8초 제한 | WAN이 없어도 LAN 주소 갱신. 과거 주소 제거. 단발 이동뿐 아니라 반복 이동·절전 복귀 검증. 8초는 upstream 조건이며 제품 SLA가 아님 |
| N05 | [열화 테스트](https://github.com/n0-computer/iroh/blob/a5e39c44d3d6dfaaff30b7292126e06ea0ab7a21/iroh/tests/patchbay/degrade.rs): 대역폭·RTT·지터·버스트 손실의 단계별 조합, 일부 flaky/not passing으로 ignore | 양쪽 방향 열화, 무한 재시도·버퍼 증가 금지, 완료 digest 검증. 불가능한 경로는 제한 시간 뒤 명시적 실패. upstream 수치를 현실 성공률로 사용하지 않음 |
| N06 | [경로 선택](https://github.com/n0-computer/iroh/blob/a5e39c44d3d6dfaaff30b7292126e06ea0ab7a21/iroh/src/socket/biased_rtt_path_selector.rs): 직접 경로 primary, relay backup, 같은 등급 전환에 5ms 차이 요구 | 검증된 직접 경로 선호, 출렁임으로 경로를 반복 전환하지 않음. 연결 소실·빈 후보·동시 close 시험. 5ms 상수는 복사하지 않고 정책과 계측으로 결정 |
| S01 | [TLS verifier](https://github.com/n0-computer/iroh/blob/a5e39c44d3d6dfaaff30b7292126e06ea0ab7a21/iroh/src/tls/verifier.rs): TLS 1.3, 기대 공개키와 SPKI 대조, 서명 검증 | 상대 키 증명과 금고 접근 승인을 별개로 검사. 서버가 후보·공개키를 바꾸거나 다른 기기가 서명하면 거부. Iroh verifier를 그대로 복사하지 않음 |
| S02 | [실행 중 인증 변경](https://github.com/n0-computer/iroh/blob/a5e39c44d3d6dfaaff30b7292126e06ea0ab7a21/iroh-relay/tests/runtime_auth.rs): unknown token 거부, 추가, 회수, 동일 기기 다중 연결 종료, 재접속 거부, 인덱스 정리 | 서비스 자격 회수·TURN allocation 종료·금고 기기 권한 회수를 각각 시험. coturn의 단기 자격 만료가 기존 세션 즉시 종료를 보장한다고 가정하지 않음 |
| S03 | [단계별 timeout](https://github.com/n0-computer/iroh/blob/a5e39c44d3d6dfaaff30b7292126e06ea0ab7a21/iroh-relay/tests/timeouts.rs): 무응답 TCP/TLS, 일부 HTTP 헤더·인증 프레임 | 서버의 타이머 작동뿐 아니라 클라이언트가 실제 EOF/reset을 받는지 검사. 서비스 API와 선택한 coturn 버전 각각 slow client 자원 회수 시험 |
| S04 | [프레임 파서](https://github.com/n0-computer/iroh/blob/a5e39c44d3d6dfaaff30b7292126e06ea0ab7a21/iroh-relay/src/protos/relay.rs): 최소·최대 길이, 유한 큐, `regression_client_to_relay_undersized_datagram_rejected`, encode/decode·no-panic property tests | 단축·초대형·0 길이·잘못된 버전·변형 프레임, 길이 오버플로, 파서 무한 루프 검증. 수신·송신 큐 바이트 상한과 backpressure. Iroh의 64KiB 패킷/1MiB 프레임/512 큐 상수를 제품 기본값으로 복사하지 않음 |

## 4. 구현 체크리스트

모든 빈 체크박스는 아직 미구현 또는 미검증이다. 코드·테스트·실행 환경·커밋 증거를 붙여야 완료 처리한다.

### A. 의존성과 프로토콜

- [ ] A01: 별도 repo의 직접/전이 의존성, 유지보수 상태, 라이선스, 알려진 취약점, 설치 크기와 메모리 측정표 작성. 필요한 기능만 활성화.
- [ ] A02: Iroh 코드를 복사하는 경우 파일·커밋·라이선스·수정 부분 추적 및 고지 유지. 테스트 아이디어 참고와 소스 재사용을 구별.
- [ ] A03: ICE/STUN/TURN 라이브러리의 coturn 상호운용, UDP/TCP/TLS 지원 확인. raw UDP를 파일용 신뢰성 스트림으로 취급하지 않음.
- [ ] A04: MTU·단편화·재정렬·중복·손실·혼잡 제어를 선택한 전송 라이브러리와 통합 검증. 전체 암호화 파일을 UDP 한 패킷으로 보내지 않음.
- [ ] A05: wire 버전 협상, 지원하지 않는 버전 거부, 크기 제한, 취소 및 종료 계약 정의. 새 wire 형식은 기존 형식과 명시적으로 분리.

### B. 등록·페어링·서비스 API

- [ ] B01: 베타 초대는 충분한 무작위성·만료·사용 횟수 제한·원자적 소비·시도 제한. 원문 초대는 로그와 DB에 보관하지 않음.
- [ ] B02: 최초 기기가 생성한 키로 서버 challenge 서명. challenge는 일회용·단기 만료이고 요청 내용·서비스 목적에 결합. 영구 공용 앱 비밀로 인증하지 않음.
- [ ] B03: 두 번째 기기 추가는 기존 기기의 승인과 QR에 결합된 공개키/일회용 pairing secret 확인. 운영사 초대만으로 금고 키를 받지 못함.
- [ ] B04: 단기 인증 세션, 등록 기기 수 제한, 세션 도용·재전송·다른 그룹 식별자 대입 거부. 공개키 보유 증명만으로 다른 금고 접근을 승인하지 않음.
- [ ] B05: `POST /v1/enroll`, challenge/session, pairing, `POST /v1/turn-credentials`, 단기 rendezvous 계약 정의. 실제 API 이름은 구현 시 고정.
- [ ] B06: 연결 후보 교환은 승인한 상대에게만 허용하고 session ID·generation·만료에 결합. 가능한 경우 이미 페어링된 기기 사이에서 암호화. 서버의 후보 변조·재전송으로 신원을 바꾸지 못함.
- [ ] B07: TURN 서버 이용 권한은 금고 권한과 별도. 단기 TURN username/password는 bearer 성격이며 기기 ID를 username에 넣는 것만으로 기기에 암호학적으로 묶이지 않음.
- [ ] B08: 서비스 API 거부 시 기존 LAN 동기화·로컬 금고는 유지. 서버 부재가 새 원격 연결을 막는 한계를 UI에 표시.

### C. coturn 운영 정책

- [ ] C01: 검증한 안정 릴리스와 빌드/이미지 digest 고정. 보안 패치와 rollback 절차, coturn 버전별 설정 검증.
- [ ] C02: 시간 제한 자격증명 발급용 shared secret은 발급 서비스와 coturn만 보유. 앱·저장소·로그·에이전트 도구 결과에 노출 금지. coturn의 REST 인증 기능은 우리 HTTP API를 대신하지 않음.
- [ ] C03: credential TTL·allocation lifetime·permission/channel lifetime·clock skew·Refresh 동작을 따로 시험. 만료·회수 직전/직후 재연결과 이미 열린 allocation의 잔존 시간을 측정하고 사용자 보장에 반영.
- [ ] C04: 기기 회수 시 신규 발급 중단. 기존 allocation 강제 종료가 선택 버전에서 가능한지 검증하고, 불가능하면 잔존 상한을 문서화. 모든 상대의 금고 계층에서도 회수 적용.
- [ ] C05: `user-quota`, `total-quota`, `max-bps`, `bps-capacity` 명시. 단위 확인. timestamp가 바뀐 username으로 quota 우회가 가능한지 검증하고 서비스의 기기별 발급 제한 보완.
- [ ] C06: loopback·multicast·사설망·link-local·Oracle metadata 목적지 차단, IPv6와 mapped IPv4 우회도 시험. relay 자신의 주소로 재귀 중계 금지. 정책이 정상 relay-to-relay 경로를 막지 않는지 검증.
- [ ] C07: TURN 클라이언트 자격으로 임의 인터넷 peer에 트래픽을 보내는 악용도 고려. 표준 TURN 인증만으로 ZeroPW 페어링 상대만 강제한다고 약속하지 않음. 초대제·시간·대역폭·allocation 제한과 경보 적용.
- [ ] C08: 관리 CLI·metrics·웹 관리 포트를 공용망에 노출하지 않음. 비밀·초대·토큰·원본 후보 목록의 일반 로그 출력 금지.
- [ ] C09: 만료 사용자명을 metrics label로 무한 생성하지 않음. coturn 설정도 ephemeral username label의 높은 메모리 비용을 경고한다.

### D. ZeroPW 경계와 데이터 반영

- [ ] D01: 연결 프로세스에 원본 비밀·금고 복호화 키를 주지 않음. IPC 권한·파일/디버깅 접근도 제한. 프로세스 분리만으로 격리 완료라고 하지 않음.
- [ ] D02: 기존 `rust/src/team/transport.rs`의 `Transport`/`Session`에는 환경 ID와 멤버십 의미가 있으므로 일반 연결 SDK 위에 ZeroPW 어댑터를 둠. 기존 canonical/wire/crypto 계약은 `rust/PORTING.md` §1에 따라 보존.
- [ ] D03: 전송 대상은 변경 묶음과 초기 snapshot. 암호화 DB 전체를 동시 덮어쓰기하지 않음. 금고 키 전달은 페어링된 상대의 신뢰 프로세스 사이에서만 수행.
- [ ] D04: transfer ID·인증된 manifest·길이·digest 검증, 중복 적용 방지, 중단 후 재개, 최종 원자적 반영. ACK는 durable 반영 뒤 전송. ACK 유실 후 재시도는 안전해야 함.
- [ ] D05: 수신 권한 검사 이전 무제한 저장 금지. 임시 저장·최대 묶음·큐 용량 상한. hash 일치만으로 송신자 승인을 대신하지 않음.
- [ ] D06: 수정 충돌·삭제 tombstone·오래된 snapshot·재전송·회수된 기기·디스크 부족·프로세스 강제 종료 시험. 기존 sync 정책과 보안 요구를 약화하지 않음.

### E. Oracle와 베타 수용 시험

- [ ] E01: OCI 리전·shape·공인 IP/사설 IP 대응·도메인·DNS 권한 확인. Oracle NSG/security list와 OS 방화벽 모두 검증. `external-ip`는 배포 구조에 맞춰 설정.
- [ ] E02: API HTTPS와 TURN TLS가 동일 IP:443에 동시에 bind되지 않도록 포트 설계. 5349에서 TURN TLS를 운영하는 베타는 443만 허용하는 망까지 지원한다고 약속하지 않음. 443 지원은 별도 IP/VM 또는 검증한 L4 분기를 검토.
- [ ] E03: relay 포트 범위를 allocation 수·IPv4/IPv6·포트 예약 기준으로 산정. 200기기=200포트라고 단순 가정하지 않음. TCP/TLS client 경로와 UDP relay socket의 차이를 검증.
- [ ] E04: 무료 VM 한 대에서 coturn+서비스 계층+OS의 합산 RSS·CPU·소켓·큐·disk·egress 계측. 앞선 relay 전용 1GB 추정치를 그대로 서비스 계층 포함 용량으로 사용하지 않음.
- [ ] E05: 200기기 연결 24시간, 200기기 재접속, 전부 TURN 경유, 최초 snapshot 동시 전송 시험. 이를 통과하기 전 100명 수용 능력을 보장하지 않음.
- [ ] E06: 온보딩 가상 데이터와 통제된 endpoint만 사용. 실제 금고·OCI 관리자·배포 키를 테스트 작업자에게 주지 않음.
- [ ] E07: 제안 합격 기준: OOM/무한 CPU/지속 메모리 누수 없음, 정상 시험에서 데이터 불일치 0, 서버 정상화 후 60초 내 재접속 95% 이상. 보장 SLA가 아닌 초기 검증 목표이며 시나리오별 측정 필요.
- [ ] E08: 로그 순환, health check, allocation 실패·인증 실패·메모리·CPU·egress 경보, 재접속 backoff+jitter. 무료 VM 회수/장애 시 재배포와 등록 DB 복구 절차.
- [ ] E09: 서비스 등록 DB 백업은 금고 백업과 별개. 복원으로 회수 상태가 과거로 되돌아가지 않도록 정책 epoch/재등록 처리 설계. 무료 범위와 자원 quota 확인, 비용 경보를 지출 차단 장치라고 오해하지 않음.
- [ ] E10: 제품 변경은 격리된 Linux와 macOS에서 `rust/verify.sh` 및 신규 네트워크/서버 통합 시험. 기존 하네스·CI·리뷰 기준을 우회하지 않음. 구현 head에 대한 실제 외부 리뷰 없이 PASS 표기 금지.

## 5. 마일스톤

1. 기술 검증: 작은 의존성 후보를 비교하고, 동일 API에서 직접/강제 TURN UDP/TURN TLS 파일 전송과 양쪽 UDP 차단을 재현. 실패하면 스택을 확정하지 않음.
2. 서비스 계층: 초대 등록·기기 인증·rendezvous·단기 TURN 자격 발급·제한·회수와 합성 테스트.
3. ZeroPW 어댑터: 기존 인증된 동기화 메시지와 snapshot 전송, 페어링·오프라인·재개 UX 통합.
4. OCI 베타: 재현 가능한 배포 산출물, 1GB 합산 부하시험, 장애복구, 제한된 초대 배포.

## 6. 남은 사용자 결정 (2026-11-06 기준 대부분 §0에서 확정)

- ~~최초 지원 OS~~: §0에서 macOS만으로 확정.
- 베타 범위: 100명·기기 2대·비밀 텍스트만·양쪽 온라인일 때 동기화 제안. 첨부파일과 서버 보관은 후속.
- 복구 UX: 이메일 없이 모든 기기를 잃었을 때 복구 코드+암호화 백업을 지원할지. 운영자가 금고를 복호화하는 복구는 제공하지 않음.
- 배포 입력: `zeropw-turn.telicity.ai` DNS-only A 레코드 확인. NSG 연결과 인증서 발급은 완료했다. OS 80 허용의 저장/서비스 활성화도 확인했다. 갱신 dry-run도 통과했다. 제품 배포·listener TLS·전체 방화벽 인수는 아직 완료되지 않았다. OCI 리전/shape와 저장소 이름은 §0.1 및 검증 기록을 따른다. 비밀값은 채팅으로 받지 않음.
- ~~제한 네트워크~~: §0에서 5349 TURN TLS로 시작하기로 확정.
- 메타데이터 보관: 제안은 최소 기기 등록·회수 상태 영구 보관(서비스 탈퇴까지), rendezvous 최대 5분, 원본 IP 운영 로그 최대 24시간, 익명 집계 7일. 공개 전 실제 로그 설정과 사용자 안내에 일치시킬 것.

라이브러리·상태 머신·테스트 상세는 위 요구를 기준으로 엔지니어링에서 결정하며 사용자에게 개별 API 선택을 떠넘기지 않는다. 위 제안 기본값은 아직 사용자가 확정한 결정으로 기록하지 않는다.

## 7. 추가 근거

- [ICE RFC 8445](https://www.rfc-editor.org/rfc/rfc8445.html): 직접/중계 후보와 연결성 검사.
- [TURN RFC 8656](https://www.rfc-editor.org/rfc/rfc8656.html): allocation·permission·channel·refresh. TURN만으로 종단 간 암호화나 파일 전송을 제공하지 않음.
- [coturn 조사 설정](https://github.com/coturn/coturn/blob/ad8885a54ac1d59a39f2cc49ae7662fc2d842c64/examples/etc/turnserver.conf): 단기 자격, quota, 포트, 접근 제한, metrics 설정.
- [Oracle Always Free](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm): shape·네트워크·유휴 회수 정책. 배포 시 계정의 실제 할당량 재확인.

최초 작성(2026-11-06)은 조사·설계 문서만 추가했다. 이후 구현·시험·OCI VM 생성이 진행됐으므로 현재 상태는 §0.1과 날짜별 검증 기록을 따른다. VM 생성은 서비스 배포나 출시 인수를 뜻하지 않는다.
