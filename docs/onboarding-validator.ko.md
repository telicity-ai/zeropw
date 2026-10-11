# 교환한 온보딩 결과 검증

`/2` 스키마에는 승인 명단, 설치 파일의 출처, 실행 환경을 추가했다. 이 가이드에서는 `/1` 결과를 사용하지 않는다. 모델의 판정은 검증 전 자료다. 사람이나 신뢰하는 코디네이터가 별도로 검증기를 실행한 뒤 수락한다. 검증기는 JSON의 구조와 일관성을 확인하며, 명령의 실제 실행·확인 자료의 진위·운영 격리를 증명하지 않는다.

검토된 체크아웃의 `scripts/validate-onboarding.py`와 `docs/onboarding-schemas/`를 사용한다. Python 3.11 이상의 표준 라이브러리만 필요하다. 상대 결과에 들어 있는 스크립트는 실행하지 않는다. 검증기는 지정한 JSON 파일만 읽고 환경변수·금고·자격증명·네트워크에 접근하거나 입력에 있는 명령을 실행하지 않는다.

## 결과 교환 전에 정책 승인

`docs/onboarding-policy.example.json`을 `policy.json`으로 복사하고 env_id를 포함한 모든 예시 표식을 사람이 별도로 확인한 메타데이터로 바꾼다. 기존·제거된 멤버까지 승인 명단 전체를 포함한다. A는 유일한 active admin/owner, B는 초대한 역할의 active 멤버이며 `owner=false`여야 한다. 상대 결과를 보고 정책을 작성하지 않는다. 검사 경로, 성공 HTTP 상태, 응답 조건 문구, 시험용·실제 환경 구분도 미리 합의한다.

실행 전에 각 플랫폼의 압축 파일 SHA-256을 v0.1.0 릴리스와 대조한다. Homebrew는 tap 커밋과 formula의 URL·SHA-256도 확인한다. `artifact_receipts.A/B`에 기록하며 플랫폼별 해시는 다를 수 있다. Homebrew의 `tap_commit`은 검증한 40자리 커밋, 압축 파일 설치는 `null`이다. 자료는 사람의 확인이며 서명된 증명이 아니다.

| 릴리스 압축 파일 | SHA-256 |
| --- | --- |
| ARM64 macOS | `7f7218e467f2f913e73bbc20785caeb96bc9f63a916fdca4e217abcdd37deef9` |
| ARM64 Linux | `c8c48db2dab796790248115cc74b366c5be7ecba3bb9c40db9b308697297ac75` |

[v0.1.0 릴리스](https://github.com/telicity-ai/zeropw/releases/tag/v0.1.0)의 해시를 스키마에도 고정했다. 체크섬 일치는 해당 릴리스와 같은 파일이라는 근거이며 배포자 서명 검증은 아니다.

## 검증기 실행

전체 JSON 객체를 `install.json`, `A.json`, `B.json`으로 저장한다. 설명문·Markdown 펜스·중복 키·추가 필드는 거절한다. 원본을 보존하고 모순된 값을 고쳐 통과시키지 않는다.

```sh
python3 scripts/validate-onboarding.py install install.json --artifact approved-artifact.json
python3 scripts/validate-onboarding.py local A.json --policy policy.json
python3 scripts/validate-onboarding.py local B.json --policy policy.json
python3 scripts/validate-onboarding.py pair A.json B.json --policy policy.json
```

종료 코드가 **0**이어야 수락한다. 다른 코드는 차단이다. pair 명령은 모델의 `ready`를 믿지 않고 직접 판정한다. 모델이 반환한 전체 비교 JSON까지 대조하려면 `--reported pair.json`을 추가한다. 모든 필드가 계산된 결과와 같아야 한다. 교환에는 검증기가 계산한 비교 결과를 사용한다.

시각은 UTC `YYYY-MM-DDTHH:MM:SSZ`로 쓴다. 확인·표본은 현재 기준 10분 이내이며 최대 30초의 시계 차이만 허용한다. 두 표본은 5초 이상 간격, 로컬 확인 시각의 최대 10분 전 자료여야 하며 같은 쓰기 중지 구간에 속해야 한다. 쓰기나 만료가 발생하면 새 자료를 수집한다. 승인 정책이 공통 세션 ID·쓰기 중지 시각을 대신하지 않는다.

`synthetic`의 `ready`는 표시된 시험 결과다. 실제 자격증명은 사람이 양쪽의 별도 격리를 확인해야 한다. 검증기는 이 확인의 진위를 증명하지 않는다.

## 거절 기록

`rejected_commits`가 0이 아니면 벡터가 같고 HTTP 요청이 성공해도 `/2`는 차단한다. 사람은 각 격리 기록의 ID·사유, 거절 주석만 제외한 내용과 수락된 커밋의 일치, 수락 당시 작성자의 승인 상태, 표본 수집 중 기록 집합·개수의 불변 여부를 확인한다. 근거는 비공개로 보존하고 원본 커밋·금고 파일을 에이전트에게 보내지 않는다.

확인 후에도 0 조건은 면제되지 않는다. 기록 삭제·카운터 초기화·확인 자료의 값 변경은 하지 않는다. 검토된 이력의 처리는 별도 제품 결정과 버전이 구분된 판정이 필요하다. 현재 v0.1.0 온보딩 시험은 `ready` 쌍을 입증하지 못했다.

## 이유·행동 코드

오래된 자료도 `blocked`로 판정하며 사람이 새 자료를 수집한다. 설치 통과에는 `install_isolation_confirmed=true`와 `--artifact`로 지정한 별도 승인 파일이 필요하다. 모델 비교 결과가 다르면 계산된 원인을 보존하고 `reported_pair_mismatch`를 추가한다.

일관성 실패 코드: `artifact_identity_mismatch`, `artifact_identity_unverified`, `environment_mismatch`, `execution_context_mismatch`, `human_receipt_missing`, `installation_action_missing`, `installation_checks_failed`, `installation_exit_failed`, `installation_isolation_unconfirmed`, `installation_not_pass`, `invalid_sampling_interval`, `invalid_utc_time`, `invalid_vector_count`, `local_result_not_pass`, `members_mismatch`, `planned_fingerprint_mismatch`, `probe_mismatch`, `readonly_request_unverified`, `rejected_commits_nonzero`, `reported_pair_mismatch`, `role_mismatch`, `self_fingerprint_role_mismatch`, `stale_or_future_evidence`, `unexecuted_install_exit`, `unexpected_member_present`, `unknown_vector_author`, `unresolved_team_state`, `unstable_vector`, `vectors_mismatch`, `verification_session_mismatch`, `version_unverified`, `writes_not_paused`. 구조·파싱 오류는 고정 분류(`schema_type`, `schema_enum`, `schema_missing`, `schema_extra`, `schema_size`, `schema_pattern`, `schema_range`, `duplicate_json_key`, `nonfinite_json`, `invalid_input`, `invalid_arguments`, `input_too_large`, `unsupported_schema_keyword`)로 보고한다.

거절 기록의 행동 코드는 `review_quarantine_records`, `confirm_identical_accepted_commit`, `confirm_author_approved_at_acceptance`, `confirm_rejection_set_stable`다. 다른 실패는 `review_evidence_and_repeat`를 쓴다. 이는 증거 삭제나 권한 변경의 허가가 아니다.
