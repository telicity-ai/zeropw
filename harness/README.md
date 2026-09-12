# ZeroPW 작업·리뷰 하네스

이 하네스는 클라우드 구현 작업이 끝나면 현재 로컬 Codex 세션에서 Claude Opus 리뷰를 실행하고, 리뷰를 GitHub PR에 게시한 뒤 수정 작업을 다시 제출한다. GitHub 저장소는 `handlecusion/zeropw`로 고정한다. 원본 제품 키나 모델 키를 클라우드 작업자에게 전달하지 않는다.

## 운영 구성

- 클라우드 작업자: 문서에 지정한 범위의 구현과 테스트를 수행한다.
- 이 Codex 세션의 Astra: 작업 범위, 상태 확인, 예외 처리와 최종 인수를 담당한다.
- 로컬 Claude CLI의 `claude-opus-5`: 외부 실행 도구·MCP·훅 없는 별도 호출로 같은 커밋의 코드를 적대적으로 검토한다. 초기화 이벤트와 실제 본문 메시지의 모델 이름을 확인한다. CLI 비용 집계에는 별도 보조 모델이 포함될 수 있으므로 집계 목록만으로 리뷰 모델을 판정하지 않는다.
- GitHub: 코드, CI, 완료 커밋과 리뷰 결과를 공유하는 곳이다.
- 이 세션에 연결한 heartbeat: 주기적으로 `controller.py tick`을 실행한다. 변화가 없는 동안 사용자 알림을 반복하지 않는다.

외부 작업이 이 대화에 직접 HTTP 메시지를 넣는 공개 콜백은 사용하지 않는다. heartbeat가 완료 상태를 가져와 같은 세션의 후속 작업을 시작한다. 앱과 로컬 실행 호스트가 실행 가능해야 동작한다. 앱 종료·절전 중에도 즉시 처리하는 24시간 서비스는 아니다.

Codex Cloud 기본 모델은 현재 변경할 수 없다. 원래의 Sol 구현 조건을 유지하려면 별도 Sol 실행기가 필요하다. 현재 제공하는 Cloud 제출기는 사용자가 기본 모델 사용을 명시적으로 선택한 런타임 설정에서만 열린다. 문서나 프롬프트의 역할 이름을 실제 모델 선택으로 취급하지 않는다.

## 최초 준비

Python 3.11 이상, Git, 로그인된 `gh`·`codex`·`claude` CLI가 로컬 조정기에 필요하다. 신뢰하는 조정기에서만 이 CLI들을 사용한다. 키나 세션 토큰을 저장소나 작업 프롬프트에 복사하지 않는다.

1. Codex Cloud의 GitHub 연결에서 `handlecusion/zeropw` 접근을 허용하고 해당 저장소의 환경을 만든다. 자동으로 다른 저장소 권한을 넓히지 않는다.
2. Cloud setup 명령은 `bash harness/cloud_setup.sh`로 지정한다. 이 단계는 필요한 명령의 존재와 격리 모드 Python 컴파일만 확인하며 테스트를 실행하지 않는다. 테스트는 CI와 작업자 단계에서 수행한다. 현재 추가 패키지 설치는 없으며 실제 키나 토큰을 환경 Secrets에 넣지 않는다. 제품 의존성이 생기면 검증한 설치 절차를 별도로 추가한다.
3. 실제 Cloud 환경 ID와 사용자가 결정한 작업자 모드를 `.zeropw-harness/config.json`에 기록한다. 이 경로는 Git에서 제외한다.
4. 로컬에서 doctor와 테스트를 실행한 뒤 작업을 제출한다.

설정 예시는 `config.example.json`이다. `cloud_default_model_accepted`를 true로 바꾸는 것은 실제 사용자 선택 뒤에만 한다. 이 설정에는 API 키를 넣지 않는다.

```sh
python3 harness/zeropw_harness.py doctor
python3 -m unittest discover -s harness -p 'test_*.py' -v
python3 harness/cloud_runner.py submit --prompt-file harness/prompts/m1-cloud.txt --branch main
python3 harness/controller.py tick
```

첫 명령의 성공은 CLI가 존재한다는 확인이다. 저장소 접근, 모델 호출과 Cloud 환경의 실제 연결은 각각 별도로 검증한다. 이 하네스를 구축한 것만으로 ZeroPW 제품이 배포되는 것은 아니다.

## 완료와 리뷰 절차

제출기는 원격 브랜치의 시작 SHA, 프롬프트 hash, Cloud 환경, 작업 ID와 로컬 실행 ID를 기록한다. 제출 결과가 불명확하면 같은 요청을 무작정 다시 보내지 않는다.

작업이 READY가 되면 Cloud diff를 받아 임시 bare Git 저장소의 index에 적용한다. 조정기에서 제출된 코드를 checkout하거나 실행하지 않는다. 별도 브랜치와 PR을 만들고 다음 마커를 실제 head SHA에 결합한다.

수집 전에 기록된 작업 ID와 응답의 `environment_id`가 각각 정확히 일치해야 한다. `codex cloud list --env`의 필터나 환경 이름만으로 환경 소속이 확인되었다고 간주하지 않는다. 환경 ID가 누락·null·빈 값이면 상태·diff 조회와 게시를 중단한다. 2026-09-13 실제 CLI 점검에서 다른 환경 이름과 null ID가 반환된 사례를 확인했으므로, 해당 응답 형식에서는 자동 수집을 완료할 수 없다. 환경 생성과 초기화 성공은 작업의 환경 식별이나 제출·수집 전체 경로 검증을 의미하지 않는다.

```text
<!-- zeropw:ready-for-review -->
<!-- zeropw-ready-sha:실제_40자리_commit_SHA -->
```

마커만으로 검토를 시작하지 않는다. PR이 같은 저장소의 main을 대상으로 하는지, draft가 아닌지, 현재 SHA와 마커가 일치하는지, 필요한 CI가 통과했는지 확인한다. CI 정의가 로컬 조정기의 신뢰 사본과 같은지도 확인한다. 제품 테스트는 `tests/test_*.py`에 두면 기존 CI가 실행한다.

Cloud 결과가 `.github/`, `harness/`, `AGENTS.md`, `docs/harness.md`, `docs/product-intent.md`, `docs/security-design.md`를 변경하면 자동 push 전에 중단한다. 이 변경은 조정기가 범위와 내용을 검토한 뒤 별도로 반영한다. 작업자가 새 워크플로를 먼저 실행하거나 제품 요구사항·보안 기준·리뷰 정책을 스스로 바꾸는 경로로 사용하지 않는다.

리뷰 입력에는 변경한 파일의 base/head 원문과 신뢰하는 제품 문서를 넣는다. 원문·Git blob·입력 hash를 검증하고, 입력이 잘리거나 지원하지 않는 바이너리·심볼릭 링크 등이 있으면 생략한 채 PASS를 받지 않고 중단한다. 리뷰어의 오류 응답, 다른 모델, 잘못된 JSON, 범위를 벗어난 파일·행과 PASS에 남아 있는 발견 사항도 거부한다.

현재 Cloud 패치 수집기는 Git이 따옴표로 인용한 파일 경로를 지원하지 않는다. 비ASCII 문자나 일부 특수문자가 포함된 경로가 인용 헤더로 반환되면 해당 파일을 건너뛰지 않고 패치 전체를 거부한다. 한 PR의 예상 가능한 검증 실패는 해당 PR의 attention으로 남기고 다른 PR 처리를 이어간다. 외부 쓰기 결과가 불명확할 수 있는 예상치 못한 오류는 기존처럼 조정기 잠금을 보존한다.

Claude 호출은 Opus, effort `medium`, 최대 20분으로 운영한다. 검토 지시와 통과 기준은 동일하며 실제 사용 모델·실행 설정을 기록한다. 시간 초과 시 검토 입력과 받은 부분 응답을 비공개 기록에 보존하고 미완료로 처리한다. 비정상 종료 시에도 stdout 원문과 종료 코드·stderr를 비공개 파일에 보존한다. 실패 프로세스가 PASS처럼 보이는 JSON을 출력해도 검토 결과로 채택하지 않는다. 사용 한도와 초기화 시각이 확인되면 해당 시각 전에는 같은 검토 호출을 반복하지 않는다.

리뷰 결과는 정확한 commit ID에 결합한 GitHub COMMENT 리뷰로 게시한다. 이는 GitHub의 승인 리뷰나 병합 명령이 아니다. 코드가 바뀌면 이전 리뷰를 새 코드의 PASS로 쓰지 않는다.

| 상태 | 다음 행동 |
| --- | --- |
| Cloud 실행 중 / CI 대기 | 기다린다. 같은 상태를 반복 알리지 않는다. |
| CI 실패 | 실패 상태를 알리고 자동 Opus PASS나 무조건 재시도로 우회하지 않는다. |
| Opus PASS | Astra의 최종 인수 대상으로 알린다. 자동 병합·배포하지 않는다. |
| Opus REVISE | 원본 발견 사항과 심각도를 유지해 같은 PR의 현재 SHA에서 수정 작업을 제출한다. |
| Opus BLOCKED / 불명확한 결과 | 입력이나 연동 문제를 확인하도록 알리고 자동 진행을 멈춘다. |
| 설정 미완료 | 리뷰 게시까지 가능하며 수정 제출은 대기한다. 설정 뒤 같은 기록에서 이어간다. |
| 운영 제어 파일 변경 | 자동 push를 멈추고 조정기 검토 대상으로 알린다. |
| 자동 수정 3회 도달 | 반복을 멈추고 미해결 항목과 기록을 알린다. 해결된 것으로 표시하지 않는다. |

## 개별 실행과 기록

```sh
python3 harness/cloud_runner.py collect --run 실행_UUID
python3 harness/zeropw_harness.py scan
python3 harness/zeropw_harness.py review --pr PR번호
python3 harness/zeropw_harness.py publish --pr PR번호 --sha 검토한_SHA
```

`.zeropw-harness/runs/`에는 제출·수집 이력이, `.zeropw-harness/reviews/PR번호/SHA/`에는 검토 입력과 결과가 남는다. `controller-events.json`은 같은 상태의 알림을 중복하지 않기 위한 기록이다. 이 파일들은 비밀 저장소가 아니며 운영 토큰을 저장하지 않는다. 소스와 리뷰 원문이 들어 있으므로 임의 공개하지 않는다.

프로세스 중단이나 불명확한 외부 요청 뒤에는 잠금과 기록을 자동 삭제하지 않는다. 해당 PID가 종료되었는지, Cloud 작업이 실제 생성되었는지, 브랜치·PR·리뷰가 이미 게시되었는지를 읽기 전용으로 확인하고 기록을 맞춘 뒤 재개한다. 반복 호출로 중복 작업을 만드는 복구는 하지 않는다.

조정기는 검토된 하네스 checkout을 유지한다. Cloud 결과를 조정기 작업 디렉터리에 적용하거나 Cloud가 수정한 하네스를 자동으로 실행하지 않는다. 제품 또는 하네스 변경의 자동 병합은 제공하지 않으며, 검증·인수 후 사람이 선택한 버전으로 조정기를 갱신한다.

## 현재 구현 범위와 근거

2026-09-13에 ZeroPW 전용 Codex Cloud 환경을 생성하고 저장소 checkout, Python 3.12.13, Git·SSH와 초기화 스크립트 실행을 확인했다. 실제 비밀과 사용자 환경변수는 등록하지 않았고 에이전트 인터넷 접근은 꺼 두었다. main에 하네스가 아직 없는 초기 단계에도 환경을 검증할 수 있도록, 현재 환경 설정에는 런타임 확인과 하네스가 있을 때의 격리 모드 컴파일을 인라인으로 지정했다. 테스트는 setup에서 실행하지 않는다. 환경 ID와 실제 설정·검증 근거는 Git에서 제외된 `.zeropw-harness/cloud-environment.json`에 보존한다. Cloud 기본 구현 모델 사용 결정과 실제 작업의 환경 식별 검증은 별도 대기 조건이다.

HTTP 인증 중계 첫 구현 작업 프롬프트는 `prompts/m1-cloud.txt`에 있다. SSH 서명 위임은 다음 구현 단계이며 제품의 핵심 기능에서 제외하지 않는다. 본 하네스는 개발 흐름을 연결하며 원본 키를 격리하는 ZeroPW 제품 자체를 구현한 것은 아니다.

공식 기능 확인일은 2026-09-12다.

- [Codex Cloud 시작](https://learn.chatgpt.com/docs/cloud)
- [Cloud 환경과 Secrets의 적용 단계](https://learn.chatgpt.com/docs/environments/cloud-environment)
- [Cloud 기본 모델 변경 제약](https://learn.chatgpt.com/docs/models)
