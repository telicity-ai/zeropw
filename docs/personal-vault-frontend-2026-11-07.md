# Personal Vault 프런트엔드 교체 기록 (2026-11-07)

작성: 2026-11-07 · Claude Opus 5.5(`claude-opus-5-5`)가 구현하고 이 세션에서 검증했다. 독립 적대 리뷰(Opus 리뷰 러너)는 아직 하지 않았다. 이 기록은 구현과 검증 범위를 적을 뿐 출시 인수가 아니다.

## 1. 무엇을 바꿨나

사용자 요청(2026-11-07)에 따라 `desktop/`의 웹뷰 프런트엔드를 "Personal Vault" 정체성으로 처음부터 다시 만들었다. 화면 규칙은 [DESIGN.md](../DESIGN.md), 기능과 IPC는 [desktop-app.md](desktop-app.md) §5~§7에 있다.

- 새 디자인 시스템: `desktop/src/styles/tokens.css`(밝은·어두운 의미 토큰), `base.css`, `ui.css`, `shell.css`, 영역별 `styles/screens/*.css`. 날것의 색은 토큰 파일에만 있다(`test/design.test.ts`).
- 새 구성 요소: `desktop/src/ui/`(`controls`, `Dialog`, `feedback`, `layout`, `OneTime`, `icons`, `hooks`, `app`), 창과 전역 상태 `desktop/src/app/`(`App`, `OpenVault`, `Sidebar`, `LockScreen`, `shell`).
- 새 화면: `desktop/src/screens/{vault,devices,services,developer,activity,settings,onboarding}`.
- 문구: `desktop/src/copy/` 영역별 표. 코어 코드를 옮기는 기존 어휘는 `backend.ts`로 옮기고 "보관함"→"금고", "중계기"→"로컬 서비스", "키"→"항목"으로 바꿨다.
- 백엔드에 더한 것(모두 `desktop/`, Rust 금고 크레이트 `rust/`는 바꾸지 않았다):
  - `vault_unlock`: 잠금 화면. CLI의 재인증 경로(`status --require-admin`)로 관리 비밀번호만 확인한다. 틀리면 `auth_failed`가 기록되고 아무것도 바뀌지 않는다.
  - 설정 `link_service`(선택): 아직 등록하지 않은 Mac이 쓸 연결 서버 주소. 없으면 파일에서 빠지고, 기존 파일은 그대로 읽힌다. `link_enroll`과 `link_status.default_service`가 이 값을 쓴다.
  - 앱 아이콘(`src-tauri/build/png.rs`)을 새 표식으로 다시 그렸다. 창 최소 크기는 720×520.
- 개발용 모의 코어(`src/ipc/mock.ts`)는 Vite 개발 서버와 단위 시험에서만 동적으로 불러온다. 배포 번들에는 없고, Tauri 밖의 배포 빌드는 모든 호출을 `not_in_desktop`으로 거절한다(빌드한 `dist/assets/*.js`에서 모의 문자열이 없음을 확인).

금고 데이터, 암호화·권한·저장 형식, 기존 IPC 계약은 바꾸지 않았다(추가만 했다).

## 2. 제거한 구 UI

`desktop/src/App.tsx`, `Titlebar.tsx`, `copy.ts`, `dashboard/`(Home·Keys·Import·Connections·Agents·Logs·Team·Devices·Settings·pairJoin·Sheet·Confirm·ListenSetup 등), `onboarding/`, `field/`(픽셀 구체), `ui/{fields,form,pixels,context,disclosure}`, `styles/{components,dashboard,onboarding,window,terminal}.css`, `lib/sigil.ts`, `desktop/mockup/onboarding.html`, 구 화면 시험(`team-components`, `devices-components`, `render`, `field`, `onboarding-vault`)과 구 디자인 문서 내용. 기록은 Git에 남는다. 화면이 아닌 로직(`dashboard/watch.ts`, `relay.ts`, `invite.ts`, `pendingInvite.ts`)은 `src/lib/`로 옮겨 그대로 쓴다. npm 의존성은 모두 새 화면이 계속 쓰므로 뺄 것이 없었다(React, Tauri API, xterm, Pretendard, JetBrains Mono).

## 3. 기능 대응

구 화면 기능 목록(세션에서 만든 인벤토리, 화면별 IPC·이유 코드·폴링·일회용 값 처리)을 영역별 작업에 그대로 넘겼다. 구 홈 화면은 없앴다(상태는 사이드바, 최근 알림은 활동 › 알림). 구 에이전트 화면의 승인 대기열은 개발자 › 승인 요청 탭으로, 팀 화면은 개발자 › 공유 탭으로 옮겼다. 초대 미리 보기의 "그림 지문"은 네 글자씩 나눈 지문 글자로 바꿨다.

## 4. 아직 없는 백엔드 기능과 API 계약

| 기능 | 지금 화면 | 필요한 계약 |
| --- | --- | --- |
| 항목 전체 삭제(영구 tombstone) | 금고 상세의 "항목 삭제" 구역이 이 버전에서 지원하지 않는다고 쓰고, 버전 철회와의 차이를 설명한다. 단추는 없다. `SecretView.deleted`가 오면 영구 삭제된 항목으로 보이고 값 동작을 숨긴다 | 별도 작업 중인 브랜치 `t3/whole-secret-tombstones`의 `secret_delete {id, admin_passphrase}`(CLI `secret delete --id`, 재인증, 공유 위치는 관리자 기기만, 같은 요청 재시도 성공)와 `secret_list`·`secret_versions`의 `deleted: true`. 그 브랜치의 구 `Keys.tsx`·`Devices.tsx`·`copy.ts` 변경은 새 화면의 `screens/vault/ItemDetail.tsx` 삭제 구역과 `screens/devices/states.ts`로 옮겨야 한다 |
| 인증된 스냅숏으로 새 Mac 연결 | Mac 추가 대화상자가 오래된 기록을 정리한 금고에는 새 Mac을 연결할 수 없다고(스냅숏 전송 미지원) 짧게 알린다 | [remote-sync-next-milestones.md](remote-sync-next-milestones.md) M2. 구현되면 `pairing_join` 결과에 스냅숏 단계 상태가 필요하다 |
| 관리 비밀번호 바꾸기 | 설정이 아직 없다고 쓴다 | CLI 명령이 없다 |
| 자동 잠금 시간 바꾸기 | 15분 고정이라고 쓴다 | 설정 필드 하나(`desktop/core/src/settings.rs`) |
| 즐겨찾기·태그·폴더 | 만들지 않았다(저장할 곳이 없음). 정리는 종류·위치·검색·정렬로 한다 | 동기화되는 메타데이터를 둘지 정해야 한다 |

연결 서버 `https://zeropw-turn.telicity.ai`는 설정의 "배포 예정 주소 넣기"로만 들어가며 기본값이 아니다. 화면은 "서버 운영 여부를 확인하지 않았어요"라고 쓰고, 운영 중이라고 표시하지 않는다. 이 세션은 그 서버에 접속하지 않았다.

## 5. 검증

실행 환경을 구분한다.

- **macOS VM**: 이 작업용으로 새로 만든 Tart VM `zeropw-ui-redesign`(macOS 26.6.2, cirruslabs `macos-tahoe-base`, 4 CPU / 6 GB, 합성 데이터만, 호스트 폴더 마운트 없음). Rust 1.98.1, Node 26.13, Go(brew). 앱 데이터는 VM 계정의 `~/Library/Application Support/ZeroPW`이고 버리는 데이터다. 코디네이터 호스트에서는 제품 코드나 시험을 실행하지 않았다(정적 검사와 `tsc` 타입 검사만 호스트에서 했다).
- **물리 Mac 두 대, Linux**: 하지 않았다(§6).

| 확인 | 결과 |
| --- | --- |
| `vitest` 전체(25개 파일) | 324 통과, 0 실패(VM). 금고·내 Mac·서비스 연결·개발자·활동·설정·첫 실행·앱/잠금 화면 시험과 기존 로직 시험 포함 |
| `check-static`, `check-tauri`, `tsc`, `vite build` | 통과(VM). `check-tauri`는 79개 명령 일치 |
| 데스크톱 코어 대상 시험 | `settings` 5, `vault_unlock` 가짜 CLI 1, `remote_sync` 링크 7 통과. 실제 `zeropw-admin`으로 `vault_unlock`(틀린 비밀번호 → `AuthFailed`와 `auth_failed` 기록, 맞는 비밀번호 → 변화 없음) 통과 |
| `desktop/verify.sh` 전체 | **실패**(core-tests의 `e2e_remote_pairing` 2개, 이 작업 전 커밋에서도 같은 실패). 나머지 단계 통과. §5.1 |
| 앱 아이콘 시험 | 3 통과 |
| 실제 앱(디버그 빌드, 실제 `zeropw-admin` 사이드카, 고정 커밋 `f544478`의 `zeropw-link` 데몬) 조작 | 접근성 API 드라이버로 VM 안에서 직접 눌러 확인: 새 금고 만들기(관리 비밀번호 → 복구 코드 확인 → `vault_init` → `personal/main` → 로컬 서비스), 첫 항목 추가(API 키), 값 보기(틀린 비밀번호 거절, 맞는 비밀번호 뒤 30초 표시), 잠그기(⌘L), 앱 종료 뒤 다시 실행 → 잠금 화면 → 열기 → 항목·로컬 서비스 유지(사이드카에 다시 붙음), 서버 등록 실패(풀리지 않는 기본 주소 → "서버에 닿지 못했어요", 코드 지움), HTTP 서비스 연결 만들기(입력 오류 표시, 재인증), 에이전트 추가 → 앱 안 터미널 → `zeropw-agent list-connections`(권한 전 0개, 권한 준 뒤 `github-api`가 보이고 값은 없음), 활동 기록(값 없음), 설정 › 연결 서버 저장(`settings.json`에 다른 값 유지), 어두운 모드, 760×560 창(아이콘 줄, 한 칸 보기), 목록 화살표 키 이동 |
| 화면 캡처 제외 요청 | 복구 코드와 값 보기 화면에서 `screencapture`가 "could not create image from window"로 실패했다. 이 VM의 macOS 26.6.2에서 요청이 적용됐다는 관찰일 뿐, 모든 캡처 도구에 대한 보장은 아니다 |

조작 중 찾아 고친 결함: 긴 대화상자가 창보다 커서 확인 단추에 닿을 수 없었다(대화상자 높이 제한과 본문 스크롤로 고침). 아이콘 줄에서 신호등 단추가 칸 제목과 겹쳤다(제목 여백). 어두운 모드에서 고른 분할 단추가 잘 안 보였다(전용 토큰).

### 5.1 `desktop/verify.sh`

VM에서 `bash desktop/verify.sh`를 한 번 끝까지 돌렸다(`~/logs/desktop-verify.log`, VM 안). `npm ci`, 정적 검사, 단위 시험, 빌드, `cargo fmt --check`, `cargo clippy -D warnings`, 제품 바이너리 빌드는 모두 exit 0이었다. `core-tests`는 exit 101로 **실패**했다.

- 첫 실행의 실패 원인은 내 VM 준비였다. GUI 조작용으로 실제 `zeropw-link`를 `ZEROPW_BIN_DIR`에 넣어 두었더니, 가짜 데몬을 쓰는 `e2e_remote_pairing`이 실제 데몬을 띄워 `link_service_unavailable`로 멈췄다. 바이너리를 빼고 다시 돌렸다.
- 다시 돌린 결과: 앱 크레이트 9, 코어 라이브러리 88, `core_fake_admin` 35, `core_reauth_reattach` 8, `e2e_env_import` 1, `e2e_real_admin` 7(실제 `zeropw-admin`, 실제 OpenSSH `sshd`로 SSH 서명과 `exec`, `vault_unlock` 포함) 통과. `e2e_remote_pairing` 2개는 **실패**했다. 합류하는 Mac의 팀 핸드셰이크가 `team_join_failed`/`handshake_channel_closed`로 끝난다.
- 같은 VM에서 이 작업 전 커밋 `26e56b2`를 따로 풀어 따로 빌드하고 그 시험만 다른 작업 없이 다시 돌렸더니 같은 두 시험이 같은 이유로 실패했다. 이 작업이 만든 실패가 아니라, [2026-11-07 동기화 검증 기록](remote-sync-validation-2026-11-07.md)이 "native 단계 대기"로 남긴 macOS 고유 문제로 보인다. 고치지 않았고 통과로 바꿔 적지 않는다. 실패한 시험은 사이드카 `zeropw-admin serve`를 남겼고 정리했다.

### 5.2 스크린숏

`docs/evidence/personal-vault-2026-11-07/`에 VM의 실제 앱 화면을 두었다. 모든 값은 합성 값이다. 복구 코드와 드러낸 값 화면은 캡처 제외 요청 때문에 찍히지 않아 없다.

## 6. 하지 않은 것과 남은 일

- 물리 Mac 두 대의 페어링·동기화·충돌·오프라인 시험: 하지 않았다. 내 Mac 화면의 상태 구분은 단위 시험(가짜 데몬 응답)과 VM 한 대의 "서버 등록 전/등록 실패" 상태로만 확인했다. 실제 서버 등록, 연결 코드, 승인, 동기화는 이 세션에서 실행하지 않았다.
- HTTP 중계의 실제 외부 요청과 SSH 서명: 화면에서는 연결 만들기와 연결 목록까지만 했다. 통제된 서버를 쓰는 코어 시험(`e2e_real_admin`의 실제 sshd 시험 포함)은 `desktop/verify.sh`에서 통과했다(§5.1).
- Linux: `desktop/verify.sh`를 Linux에서 다시 돌리지 않았다. 기존 Linux 검증 VM의 디스크가 98% 차 있어서다. CI 정의와 Linux 검사는 바꾸지 않았다.
- `rust/verify.sh`: `rust/`를 바꾸지 않아 다시 돌리지 않았다.
- 독립 적대 리뷰(Opus 리뷰 러너): 하지 않았다. 미해결 리뷰가 없다는 뜻이 아니라 리뷰 자체가 없다.
- 배포 빌드(`npm run bundle`, 서명된 .dmg)와 Gatekeeper 경로: 하지 않았다.

## 7. 두 번째 디자인 요청: Apple 글래스모피즘과 필수 입력 우선 (2026-11-07)

사용자가 메일 앱 형태의 참고 이미지(반투명 사이드바, 떠 있는 카드, 유리 팝오버)를 주며 Apple의 글래스모피즘, 간결한 배치, 간단한 첫 실행, 입력에 꼭 필요한 정보만 먼저 보이는 화면으로 다시 작업하라고 요청했다. 첫 판의 "유리 효과를 쓰지 않는다" 원칙은 이 요청으로 바뀌었다.

- **창과 표면**: 창을 투명하게 하고 macOS 사이드바 비브런시를 켰다(`tauri.conf.json`의 `transparent`, `windowEffects: sidebar`, 상태는 늘 활성. `followsWindowActiveState`는 이 VM에서 창이 활성이어도 회색으로 그려졌다). Tauri 2.12.1은 투명 창에 기능 플래그가 필요 없어 tauri 의존성의 기능 목록은 그대로 비어 있다. 본문은 6px 들어간 둥근 불투명 패널, 상세는 옅은 바탕 위 흰 카드, 대화상자·메뉴·알림·잠금·첫 실행 카드는 유리다.
- **토큰**: 시스템 글꼴(SF Pro, Apple SD Gothic Neo), Apple 회색, 검은 주 버튼, 포커스와 선택에 시스템 파랑, 포커스가 있는 목록의 선택은 메일처럼 파랑. 토큰 이름은 그대로 두고 값을 바꿨다.
- **사이드바**: 금고 이름과 검색, "새 항목 ⌘N" 알약, 구역 이름은 작은 회색 글자, 선택은 흰 알약.
- **필수 입력 우선**: 공용 `More`("더 보기")와 `Menu`(… 유리 팝오버)를 더했다. 항목 추가는 종류·이름·값만, 서비스 연결은 종류·이름·주소(또는 호스트·사용자·호스트 키)·자격 증명·관리 비밀번호만 먼저 보인다. Mac 추가는 관리 비밀번호만, 권한 주기는 에이전트·연결·관리 비밀번호만, 초대는 이름·관리 비밀번호만, 사고 선언은 범위만 먼저 보인다. 나머지(위치, 인증 방식, 메서드, 경로, 포트, 기간, 횟수, 역할, 주소, 이유, 진단 세부)는 기본값을 두고 "더 보기" 뒤에 있으며, 그 안의 칸에 오류가 나면 저절로 열린다. 보조 동작(철회, 사용 중지, 연결 끄기, Mac 연결 해제, 에이전트 끄기, 터미널 끝내기)은 … 메뉴로 모았다.
- **첫 실행**: 유리 카드 하나, 단계마다 검은 주 버튼 하나, 점 세 개의 진행 표시. 시작은 "시작하기" 하나(다른 Mac과 연결은 조용한 글자 단추), 관리 비밀번호는 칸 하나에 강도 막대와 도움말 한 줄, 확인 칸은 앞 값이 기준을 넘은 뒤에 나온다. 복구 코드는 "적어 뒀어요"를 누르면 같은 카드에 확인 칸 두 개가 나온다(직접 정하기·새 코드는 더 보기). 금고를 다 만들면 따로 "계속" 없이 완료로 간다. 확인 단계와 모든 안전 처리는 그대로다.
- **바뀌지 않은 것**: IPC 호출, 이유 코드 처리, 폴링, 일회용 값, 재인증, 저장 형식.

검증(같은 VM): `vitest` 25개 파일 325개 통과, `check-static`·`check-tauri`·`tsc` 통과, 디버그 앱을 다시 빌드해 잠금·금고·항목 추가·서비스 연결·내 Mac·개발자·활동 화면과 새 첫 실행(관리 비밀번호 단계까지)을 실제로 띄워 찍었다. 녹색 바탕화면 위에서 잠금 화면과 첫 실행 카드가 비브런시 위에 놓이는 것을 확인했다. 이 판에서 데스크톱 코어 Rust는 바꾸지 않아 `desktop/verify.sh`의 Rust 단계는 다시 돌리지 않았다. 스크린숏은 `docs/evidence/personal-vault-2026-11-07/16-…24-…`에 있다.
