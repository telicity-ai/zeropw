# Personal Vault 한국어·영어와 화면 정리

2026-11-07. 중단 시점에 `claude-opus-5-5`가 작성한 미커밋 i18n 구조와 일부 화면 수정이 있었다. 이를 보존해 이어받았고, 이번 재개 후 완성·수정 모델은 `gpt-6.1-sol`이며 병렬 번역·검사 작업도 같은 모델이다. 이전 구현을 Sol 작업으로 바꿔 기록하지 않는다. 사용자 요청은 기존 Personal Vault 앱에 한국어·영어를 제공하고, 반복 카드와 어색한 배치를 검사해 개선하는 것이다. 금고 데이터와 동기화 코드는 이 작업 범위가 아니다.

## 구현과 소스

기준은 `d01a33b8101be8761a38ab9b7ed8295e9aed1c40`, 최종 구현은 `6427d6fa73e2501e391e3289580193f3ca01d95b`다.

- `fe5d3fe282a7f233244353cbd55c9216238f92ac`: 한국어·영어 표, 저장하는 언어 선택, 화면 구성과 대비 수정.
- `f1fa393f39eb0392d4443578fc265b3d5f2e3de3`: 탐색의 복수형과 단일 항목 유형의 영어 단수형 분리.
- `a4c1b6d2f75d5033a59106561a239a85c9203dfe`: 작은 추가 대화상자의 네 유형을 모두 보이는 2열 선택으로 수정.
- `6427d6fa73e2501e391e3289580193f3ca01d95b`: 다크 모드 안내 글씨의 대비 보완.

[변경 파일 목록](evidence/personal-vault-i18n-2026-11-07/changed-files.txt). 주요 위치는 `desktop/src/copy/`, `app/`, `screens/`, `styles/`, `ui/LanguageSelect.tsx`, `core/src/settings.rs`, `desktop/test/`다. 이 보고서와 DESIGN/desktop-app 문서 및 증거는 구현 뒤의 별도 문서 커밋에 기록한다.

언어는 첫 실행·잠금·설정 > 잠금과 보안에서 고른다. `settings.json`의 `language`는 `ko`, `en`, 또는 생략(시스템 선호 언어)이다. 기존 파일은 그대로 읽고, 지원하지 않는 값은 거절한다. 저장에 성공한 다음 화면을 전환하며, 실패하면 현재 언어와 입력을 유지한다. 언어 변경으로 화면·폼·첫 실행 단계·터미널을 다시 만들지 않는다. 날짜는 선택한 언어로 표시한다. 표의 키와 자리표시자는 타입 검사와 테스트로 대조한다.

화면에서는 반복된 사이드바 추가·검색을 목록 툴바와 단축키로 모았다. 상세의 큰 카드와 장식용 고정폭 이름을 없애고 제목·간격·옅은 묶음 목록으로 나눴다. 정렬·가져오기·새 위치는 이름 있는 메뉴에서 연다. 내 Mac은 한 칸에 이 Mac과 연결한 Mac을 배치한다. 활동은 시간·이벤트·주체·대상을 읽는 표이며 실패에는 문구와 색을 함께 쓴다. 개발자 화면의 중복 권한 버튼과 파란 왼쪽 선도 제거했다. 더 이상 쓰지 않는 해당 CSS 규칙을 정리했고 의존성은 추가하지 않았다.

## 디자인 검사와 증거의 범위

`hallmark` 1.1.0의 반복 카드·단조로운 구조·토큰·포커스·절제 기준을 기존 macOS 앱에 적용했다. 시스템 글꼴, 최소 창 720×520, 비브런시는 사용자와 프로젝트의 앱 규칙을 따른다. 웹 랜딩 페이지용 58개 기준을 모두 통과했다는 주장은 하지 않는다.

오픈소스 [Impeccable](https://github.com/pbakaus/impeccable)의 실제 렌더링 검사를 격리 macOS VM에서 실행했다. 읽은 upstream은 `687bc381bc9091bf252c0a05303640561014a425`, 스킬 버전은 4.8.0이다. 파일 regex 검사만으로 대비를 확인했다고 하지 않았다. `detect --no-config --json`으로 열린 개발용 fixture 6화면과 첫 실행을 검사했다.

이번 재개 후 첫 7화면 검사에서는 17건(대비 13, 작은 글씨 1, 긴 행 1, 제목 단계 1, 카드 중첩 1)이 나왔다. 버튼·보조 글자 대비와 글자 크기, 제목 단계, 문장 폭을 수정한 다음에는 `div.select` 카드 중첩 1건만 남았다. [첫 결과](evidence/personal-vault-i18n-2026-11-07/impeccable-i18n-1.json)와 [후속 결과](evidence/personal-vault-i18n-2026-11-07/impeccable-i18n-2.json)를 모두 보존했다. 선택 입력의 조상에는 바탕·경계·그림자가 없고, 해당 `div.select`만 일반 입력의 흰 바탕·1px 경계·9px 모서리를 가진다. 이 한 건은 카드 중첩으로 볼 근거가 없어 오탐으로 분류했고 검사 규칙이나 제외 목록은 바꾸지 않았다. 최종 [라이트 검사](evidence/personal-vault-i18n-2026-11-07/impeccable-light-final.json)도 선택 입력 오탐 1건만 남았다. OS 다크 모드에서 다시 실행했을 때 placeholder 세 곳의 대비 4.3:1을 발견했다([수정 전](evidence/personal-vault-i18n-2026-11-07/impeccable-head.json)). 보조 글자 토큰을 조정한 [최종 다크 검사](evidence/personal-vault-i18n-2026-11-07/impeccable-dark-final.json)에서는 이 세 건이 사라지고 선택 입력 오탐 1건만 남았다.

개발용 fixture와 실제 앱 검증을 구분한다.

- [64조합](evidence/personal-vault-i18n-2026-11-07/fixtures-64.json): 8화면 × 한국어/영어 × 밝은/어두운 모드 × 1180×780/760×560. JavaScript 예외·가로 넘침·버튼 내부 잘림·언어 불일치 없음. 브라우저 아이콘 요청의 `/favicon.ico` 404는 별도다.
- [큰 배치 수정 뒤 16조합(영어 단수형·2열 유형 선택·마지막 대비 수정 전)](evidence/personal-vault-i18n-2026-11-07/fixtures-final-16.json): 금고와 설정 재검사. 한 사례에 개발 서버 연결 오류 11건이 있어 원자료를 보존했다. [같은 사례 재확인](evidence/personal-vault-i18n-2026-11-07/fixtures-recheck.json)에서는 재발하지 않았다. 원인은 확인하지 못했다. 실제 앱 오류로 바꾸거나 원래 결과를 삭제하지 않았다.
- 추가 대화상자 검사에서는 760×560 영어 유형 선택이 가로로 스크롤되어 SSH Key 약 47px가 가려지는 문제가 발견됐다. 개별 버튼 내부 너비 검사로는 놓쳤다. 2열 배치로 고쳤으며 조상 경계와 실제 스크린숏을 함께 재검사했다. [수정 뒤 두 모드의 결과](evidence/personal-vault-i18n-2026-11-07/fixtures-head-grid.json)는 타입 그룹의 clientWidth와 scrollWidth가 394px로 같고 버튼이 대화상자·클리핑 조상 경계 안에 있음을 기록한다.

fixture는 Vite 개발 빌드의 mock core를 쓴다. 제품 빌드에는 mock 저장·가짜 기기·잠금 우회가 들어가지 않는다. 실제 macOS 앱, 물리 Mac 두 대, 실제 네트워크 동기화가 통과했다는 증거로 쓰지 않는다.

## 실제 앱과 검증 결과

macOS는 합성 데이터만 있는 Tart `zeropw-ui-redesign` VM(macOS 26.6.2 arm64, 호스트 폴더 마운트 없음), Linux는 기존 합성 검증 VM `zeropw-parity`의 이 작업 전용 경로를 사용했다. 코디네이터 호스트에서는 제품 코드와 시험을 실행하지 않았다. 운영 금고·복구·모델·배포 키를 요청하거나 읽지 않았다.

실제 Tauri 디버그 앱은 실제 `zeropw-admin`과 고정된 link 데몬을 사용했다. 잠금 화면의 시스템 영어에서 한국어 선택, 잠금 해제, 기존 합성 항목 표시, 설정에서 영어 선택, 종료·재시작 뒤 영어 유지와 잠긴 상태, 다시 해제해 같은 항목과 연결이 남는 것을 확인했다. 밝은/어두운 모드와 작은 창의 화면·추가 폼도 확인했다. 검사용 Vite 서버를 종료한 뒤 앱을 다시 실행해 [잠금 화면과 저장한 한국어 설정](evidence/personal-vault-i18n-2026-11-07/cold-start.json)이 나타나는 것도 확인했다. 개발 서버 없이 번들 자산으로 실행하는 디버그 앱이다. 데이터 삭제나 저장 형식 변경을 하지 않았다.

검증의 최종 exit·개수·로그 해시는 이 보고서의 증거 manifest에 기록한다. 전체 결과가 대기 중이거나 실패한 단계는 통과로 쓰지 않는다. 최종 프런트엔드 재검증 1회는 소스 전송과 겹쳐 파일을 읽지 못했다. 원 로그를 보존하고 전송 완료 후 438개 제품 파일이 최종 커밋과 일치함을 확인한 뒤 다시 실행했다. 이 실수의 재실행을 제품 결함 수정으로 표시하지 않는다.

| 검증 | macOS VM | Linux VM |
| --- | --- | --- |
| 최종 frontend check/type/test/build | PASS, 26파일·334시험 | PASS, 26파일·334시험 |
| 실제 Tauri 디버그 앱 빌드·실행 | PASS, 합성 금고 | Linux GUI 수동 시험 NOTRUN |
| `desktop/verify.sh` | FAIL, 8단계 중 core-tests 실패(페어링 2개) | PASS, 8단계·네이티브 194시험 |
| `rust/verify.sh` | FAIL, 100단계 중 99통과·TLS 타깃 1실패. Cargo 결과 합계 1,625통과·1실패·ordinary ignored 4개 | PASS, 100단계·95통합 타깃·1,623통과·ordinary ignored 4개 |
| 별도 ignored signer probe | 4개 PASS | 4개 PASS |
| doc-tests | 실행 PASS(문서 시험 0개) | 실행 PASS |

[전체 manifest와 로그 해시](evidence/personal-vault-i18n-2026-11-07/manifest.json), [macOS Rust 원 로그](evidence/personal-vault-i18n-2026-11-07/macos-rust-verify.log), [Linux 결과와 소스 바인딩](evidence/personal-vault-i18n-2026-11-07/linux/verification-summary.json). Linux의 전체 스크립트는 초기 동결 소스에서 실행하고, 최종 커밋과 Rust/core/native 관련 296파일이 바이트 동일함을 대조했다. 바뀐 UI는 최종 커밋을 따로 풀어 다시 검증했다. Linux 작업 계정은 parity uid/gid 2000, 작업 폴더와 TMPDIR는 0700이다. mount metadata에는 virtiofs/9p나 host-home 공유가 없었지만 광범위한 OS 격리 보장은 아니다.

macOS `desktop/verify.sh`는 core-tests의 `e2e_remote_pairing` 두 시험에서 실패했다. 두 시험은 `team_join_failed` / `handshake_channel_closed`로 기대한 `pending` 대신 `failed`를 받았다. 같은 문제는 [앞선 작업 기록](personal-vault-frontend-2026-11-07.md#51-desktopverifysh)의 작업 전 기준에서도 재현됐다. 이번 실행에서도 실패를 그대로 보존했다. 그 앞의 실제 SSH signer/exec를 포함한 `e2e_real_admin` 7개는 통과했다.

나머지 코어 타깃을 따로 실행할 때 `link_supervisor`의 두 시험도 spawn 기록 수 0/기대 1로 실패했다. 순차 재실행에서도 같았고, 별도로 푼 작업 전 `d01a33b`에서도 동일한 두 실패를 재현했다. 이미 준비된 가짜 소켓과 mock 자식의 기록 시점 간 경합으로 보이지만 이는 소스에서 추론한 원인이다. 제품 코드·시험·시간 제한을 고치거나 이 실패를 통과로 바꾸지 않았다. 별도 `remote_sync` 18, `serve_supervisor` 11, `terminal_close_leak` 1, `terminal_pty` 9개는 통과했다.

전체 Rust 검증에서는 `gateway_tls_parity::common_name_fallback_applies_to_dns_names_only`가 예상한 200 대신 `502/upstream_tls_failed`로 실패했다. 별도로 푼 작업 전 `d01a33b`의 같은 시험도 동일하게 실패했다([기준 재현 로그](evidence/personal-vault-i18n-2026-11-07/macos-tls-baseline.log)). Rust tree는 이번 작업 전후 `f147723da8e8b5b6e42ae678819f20d57ffc36bb`로 같다. 이 기존 macOS 호환성 실패를 수정하거나 통과로 표시하지 않았다.

## 스크린숏

[실제 앱 화면 모음](evidence/personal-vault-i18n-2026-11-07/screens.html). 아래는 모두 최종 구현 `6427d6f` 디버그 앱과 실제 코어를 쓴 합성 금고다.

| 화면 | 증거 |
| --- | --- |
| 한국어 금고 | [PNG](evidence/personal-vault-i18n-2026-11-07/native-ko-vault-light.png) |
| 영어 금고 | [PNG](evidence/personal-vault-i18n-2026-11-07/native-en-vault-light.png) |
| 영어 다크 모드 | [PNG](evidence/personal-vault-i18n-2026-11-07/native-en-vault-dark.png) |
| 영어 작은 창의 추가 대화상자 | [PNG](evidence/personal-vault-i18n-2026-11-07/native-en-add-small-dark.png) |
| 언어 선택 | [PNG](evidence/personal-vault-i18n-2026-11-07/native-en-language-settings.png) |
| 한국어 잠금 | [PNG](evidence/personal-vault-i18n-2026-11-07/native-ko-locked-dark.png) |

브라우저 fixture의 [수정 전](evidence/personal-vault-i18n-2026-11-07/fixture-en-add-before-grid.png)과 [라이트](evidence/personal-vault-i18n-2026-11-07/fixture-en-add-light-grid.png)·[다크](evidence/personal-vault-i18n-2026-11-07/fixture-en-add-dark-grid.png) 수정 뒤 화면은 실제 앱 사진과 구분해 둔다.

## 리뷰와 남은 한계

실제 `gpt-6-astra`가 `fe5d3fe`의 제품·UX 범위를 읽기 전용으로 검토했고 이 UI/i18n slice에 차단 결함은 없으며 작은 수정이 남는다고 답했다. [원 검토 스레드](<t3-thread://v2/5a536fd4-bd15-4f8f-be43-ce624c09b509/thread:delegated-task:command%3Amcp%3A1dfe679c-e0dc-40f8-901b-badd51ab85ca%3Adelegate-task%3A9f73546a-aa4a-414e-a371-d965ca576928>). 영어 단수형 지적은 `f1fa393`에서 직접 수정·검증했다. 기존 토스트는 이미 만들어진 문구를 보관하므로 언어를 바꾸면 이전 언어로 최대 4.2초 남을 수 있다. 이 작은 제한은 남아 있다. 이 검토를 이후 커밋의 새 리뷰나 보안·출시 승인으로 옮기지 않는다.

새 Opus 적대 리뷰는 수행하지 않았다. 앞선 실제 호출이 5시간 제한으로 실패했고 확인된 해제 시각은 2026-11-07 17:50 KST다. 이 작업 중 해제 전 재호출하지 않았고 Astra/Sol 검사를 Opus 리뷰로 대신 표시하지 않았다.

이 브랜치의 인증된 초기 스냅숏 전송과 전체 항목 tombstone은 여전히 지원하지 않는다. 버전 철회는 전체 항목 삭제가 아니며 이전 유효 버전이 남을 수 있다. 외부 서비스의 키 폐기나 이미 얻은 사본 삭제는 보장하지 않는다. 다른 작업자의 동기화·삭제 구현을 가져오거나 덮어쓰지 않았다. 원 보안 리뷰의 `ZPLINK-OPUS-01..03`, `ZPL-SEC-01..04`, `DOS-1`과 네트워크·운영 검토의 후속 인수 상태는 [동기화 검증 기록](remote-sync-validation-2026-11-07.md)에 그대로 남는다.

물리 Mac 두 대, 운영 서버 등록·TURN/페어링, Gatekeeper 설치, 서명·공증한 배포 패키지는 이번 후속 작업에서 시험하지 않았다. macOS VM의 기존 SIP 비활성 환경 한계도 사라지지 않는다. 합성 UI 작업과 개발 빌드를 출시 전체 PASS로 표시하지 않는다.
