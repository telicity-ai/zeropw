# .env 가져오기

작성일: 2026-10-25 · 설계 명세 · 아직 구현하지 않음. 정한 것은 §9에 있다.

`.env` 파일 하나를 읽어 그 안의 키를 보관함에 한 번에 넣는다. 공유 중인 환경에 넣으면 커밋 하나로 다른 기기에 퍼진다. [제품 정의](product-intent.md), [보안 경계](security-design.md), [팀 공유](team-sync.md), [데스크톱 앱](desktop-app.md)의 요구사항은 바꾸지 않는다.

## 1. 왜 필요한가

지금은 키마다 `secret put --stdin`을 한 번씩 실행해야 한다. 이미 `.env`에 키가 여러 개 있는 사람이 ZeroPW로 옮기거나 팀과 나누려면 이 일이 가장 번거롭다.

가져오는 쪽은 보안 경계와 부딪히지 않는다. 값은 관리자 입력 경로로만 들어오고 저장 방식은 `secret put`과 같다. 보안 설계는 이미 "Any environment-file import must parse data, never execute it"라고 정해 두었다([security-design.md](security-design.md) 83행). 반대 방향, 즉 보관함에서 `.env`로 내보내거나 프로세스 환경변수에 넣는 일은 이 문서의 범위가 아니고 앞으로도 하지 않는다(§8).

## 2. 흐름

1. 사람이 관리 화면이나 `zeropw-admin`으로 `.env` 파일을 고른다.
2. 미리 보기: 파일을 해석해 줄마다 변수 이름, 만들어질 키 ID, 가져올지 여부와 그 이유를 보여 준다. 값은 보여 주지 않는다.
3. 사람이 가져올 항목을 고른다. 기본 선택은 §4의 규칙을 따른다.
4. 고른 항목을 한 번에 쓴다. 하나라도 실패하면 아무것도 쓰지 않는다.
5. 결과로 만든 키, 그대로 둔 키, 건너뛴 항목을 보여 주고, 원본 파일이 아직 디스크에 남아 있다고 알린다.

## 3. 파일 해석 규칙

여러 도구(Node `dotenv`, `python-dotenv`, Docker Compose)가 `.env`를 조금씩 다르게 읽는다. 사용자의 앱이 실제로 읽던 값과 다른 값을 저장하면 조용히 고장 나므로, **도구마다 결과가 같은 형태만 받고 애매한 줄은 오류로 멈춘다.** 셸 문법을 실행하지 않는다.

| 항목 | 규칙 |
| --- | --- |
| 크기 | 파일 64 KiB(`MAX_SECRET_BYTES`)까지, 항목 200개까지. UTF-8만 받고 맨 앞 BOM은 지운다. NUL 바이트는 오류다. |
| 줄 | `\n`과 `\r\n`을 받는다. 빈 줄과 `#`로 시작하는 줄(앞 공백 허용)은 건너뛴다. |
| 형태 | `[export ]NAME=VALUE`. `=` 앞뒤 공백은 지운다. `=`가 없는 줄은 오류다. |
| 이름 | `[A-Za-z_][A-Za-z0-9_]*`. 같은 이름이 두 번 나오면 오류다(도구마다 앞을 쓰기도 하고 뒤를 쓰기도 한다). |
| 따옴표 없는 값 | 앞뒤 공백을 지운다. 공백 뒤 `#`부터는 주석이다. 공백 없이 붙은 `#`(`abc#def`)는 도구마다 달라 오류다. |
| 작은따옴표 값 | 안의 내용을 그대로 쓴다. 여러 줄을 받는다. `\`가 들어 있으면 오류다(도구마다 다르게 푼다). |
| 큰따옴표 값 | 여러 줄을 받는다. `\n`, `\r`만 풀고 다른 `\` 조합은 오류다. |
| `$` | 따옴표 없는 값과 큰따옴표 값에 `$`가 있으면 오류다. 변수 치환 여부가 도구마다 다르다. 작은따옴표로 감싸면 그대로 받는다. |
| 기타 | 백틱 따옴표, 닫는 따옴표 뒤의 주석이 아닌 글자, 닫히지 않은 따옴표는 오류다. |
| 빈 값 | `NAME=`, `NAME=""`는 오류가 아니라 건너뛴다. |

오류는 모두 모아 한 번에 알린다. 알릴 때는 **줄 번호와 이유 코드만** 쓰고 그 줄의 글자는 되풀이하지 않는다. 변수 이름은 제대로 해석되고 값이 비어 있지 않은 항목에만 출력한다. 토큰을 `=` 없이 붙여 넣은 줄 같은 것이 출력에 새지 않게 하려는 것이다.

이유 코드: `not_assignment`, `invalid_name`, `name_too_long`, `duplicate_name`, `unquoted_hash`, `dollar_needs_single_quotes`, `unsupported_escape`, `backslash_in_single_quotes`, `backtick_quote`, `unterminated_quote`, `trailing_text`, `nul_byte`.

## 4. 무엇을 가져올지

**설정값까지 보관함에 넣으면 다른 기능이 막힌다.** 보관함의 모든 값은 다음 검사에 쓰인다.

- CLI 프로필 검사([tools.rs](../rust/src/tools.rs)의 `profile_env_carries_vault_value`): 저장된 CLI 연결의 환경변수 이름이나 값에 보관함 값이 들어 있으면 그 연결을 만들지도 실행하지도 못한다(`cli_env_contains_credential`).
- 사고 기록 검사([incident.rs](../rust/src/incident.rs)의 `value_leak`): 사고 기록 JSON에 보관함 값이 나오면 평가 내용을 가리고, 알림 메일은 `rendered_value_detected`로 보내지 않는다.

이슈 #60 이후 두 검사는 값의 길이에 따라 다르게 맞춘다(`runs::vault_scan_patterns`, `tools::profile_env_carries_other_value`). 8바이트(`MIN_PATTERN_LENGTH`) 이상인 값은 다른 글자 속에 섞여 있어도 걸린다. 그래서 `NODE_ENV=development`를 넣으면 `development`가 들어간 CLI 연결이 거부되고, 그 글자가 나온 사고 기록은 가려진다. 8바이트보다 짧은 값은 사고 기록 검사에서는 빠지지만, CLI 프로필 검사에서는 환경변수 이름이나 값 전체가 그 값과 같으면 걸린다. 그래서 `PORT=3000`을 넣으면 `3000`을 값으로 주는 CLI 연결이 거부된다.

그래서 항목마다 기본 선택을 정한다. 규칙은 결정적이고, 결과는 미리 보기에 이유와 함께 나온다.

| 순서 | 조건 | 기본 | 이유 코드 |
| --- | --- | --- | --- |
| 1 | 값이 숫자·`.`·`-`로만 되어 있거나 `true/false/yes/no/on/off`(대소문자 무시) | 건너뜀 | `plain_value` |
| 2 | 값이 8바이트(`MIN_PATTERN_LENGTH`)보다 짧다 | 건너뜀 | `short_value` |
| 3 | 이름을 `_`로 나눈 조각에 `KEY`, `APIKEY`, `SECRET`, `TOKEN`, `PASSWORD`, `PASSWD`, `PWD`, `PASS`, `PASSPHRASE`, `CREDENTIAL(S)`, `AUTH`, `PRIVATE`, `DSN`, `SIGNING`, `SALT`, `COOKIE`, `SESSION`, `WEBHOOK` 중 하나가 있다 | 가져옴 | `secret_name` |
| 4 | 값이 `scheme://user:password@…` 형태의 URL이다 | 가져옴 | `url_password` |
| 5 | 그 밖 | 건너뜀 | `no_hint` |

규칙 1, 2는 3보다 먼저 본다. `AUTH_ENABLED=true`나 `TOKEN_TTL=3600`이 키로 들어가지 않게 하려는 것이다. 8바이트보다 짧은 값은 API 키일 가능성이 낮고, 넣으면 같은 값을 쓰는 CLI 연결이 거부된다. 규칙 5는 `development`나 API 주소처럼 긴 설정값을 막는다. 틀리게 분류하면 안전한 쪽으로 틀리도록 했다. 놓친 키는 원본 파일에 그대로 있고 결과의 "건너뜀" 목록에 이름이 나오므로 다시 가져오면 된다.

사람은 기본값을 바꿀 수 있다. `--include NAME,…`는 건너뛸 항목을 가져오게 하고 `--exclude NAME,…`는 가져올 항목을 뺀다. 기본으로 건너뛰는 항목(규칙 1, 2, 5)을 억지로 가져오면 결과 항목에 `forced: true`를 붙이고 위 부작용을 한 줄로 알린다.

## 5. 키 ID와 이미 있는 키

키 ID 규칙([projects.rs](../rust/src/projects.rs)의 `validate_name`)은 소문자·숫자로 시작하고 `[a-z0-9._-]` 64자까지다. 키 ID는 프로젝트·환경과 상관없이 보관함 전체에서 하나다.

- ID는 `--id-prefix`(선택) + 이름을 소문자로 바꾼 것이다. `OPENAI_API_KEY` → `openai_api_key`.
- 결과가 규칙에 맞지 않으면(`_`로 시작하는 이름, 64자 초과) `invalid_name`, `name_too_long`이다.
- 대소문자만 다른 두 이름이 같은 ID가 되면 `id_collision`으로 멈춘다.
- 같은 ID가 **다른** 프로젝트·환경에 이미 있으면 `secret_identity_mismatch`로 멈추고, 미리 보기는 `--id-prefix`를 쓰라고 알린다. 같은 `.env`를 `dev`와 `prod`에 각각 넣는 경우가 이렇다.
- 같은 프로젝트·환경에 이미 있으면 사용 중인 버전과 값을 비교한다(신뢰 프로세스 안에서만).
  - 같으면 `unchanged`, 아무것도 쓰지 않는다.
  - 다르면 기본은 `conflict`로 전체를 멈춘다. `--update`를 주면 새 버전을 만들어 사용 중으로 바꾼다. 이전 버전 은퇴, 연결 다시 묶기, 이전 버전에 고정된 연결 옮기기(`moved_connections`)는 `secret put`과 같다.
  - 종류는 이미 있는 키의 종류를 그대로 쓴다.
- 새 키의 종류는 `--kind`(기본 `env_var`, `api_key`·`password`도 받음)다. HTTP 연결은 세 종류를 모두 받는다. `ssh_private_key`는 받지 않는다.

원래 변수 이름은 저장하지 않는다. ID에서 거꾸로 알 수 있고, 저장 형식을 바꾸지 않아도 된다(§9).

## 6. CLI

```
zeropw-admin secret import --project P --environment E (--file PATH | --stdin)
    [--dry-run] [--include A,B] [--exclude A,B] [--id-prefix X] [--kind K] [--update]
```

- `--stdin`과 입력 봉투는 `secret put`과 같다. 봉투가 있으면 `value_b64`에 파일 내용 전체를 담는다. 봉투에 새 필드는 없다. 64 KiB를 base64로 바꿔도 봉투 한도 256 KiB 안에 든다.
- `--dry-run`은 아무것도 쓰지 않고 미리 보기만 낸다. 앱의 미리 보기도 이걸 쓰므로 해석과 분류는 CLI 한 곳에만 있다.
- 출력(값 없음):

```json
{
  "project": "team-keys", "environment": "shared", "dry_run": false,
  "entries": [
    {"line": 3, "name": "OPENAI_API_KEY", "id": "openai_api_key",
     "selected": true, "why": "secret_name", "action": "created", "version": 1},
    {"line": 5, "name": "PORT", "id": "port",
     "selected": false, "why": "plain_value", "action": "skipped"}
  ],
  "empty_lines": [9],
  "commit": null, "propagated_to": 0,
  "source_left_in_place": true
}
```

  `action`은 미리 보기에서 `create|new_version|unchanged|conflict|skip`, 실제 실행에서 `created|new_version|unchanged|skipped`이다. 공유 환경이면 `commit`에 `{author_seq, hlc}`가 들어가고 버전은 `version_id`로 나온다.
- 해석 오류는 `env_file_invalid`로 멈추고 detail에 `줄:이유` 목록(최대 50개)만 담는다. 그 밖의 오류: `env_file_too_large`, `env_file_not_utf8`, `env_file_too_many_entries`, `import_nothing_selected`, `id_collision`, `secret_identity_mismatch`, `import_conflict`, `cli_env_contains_credential`.

## 7. 쓰기

**전부 아니면 아무것도.** 해석, ID 계산, 기존 키 비교, CLI 프로필 검사를 모두 끝낸 뒤에야 쓴다.

- 개인 환경: 상태 잠금을 잡은 채 보관함 문서를 한 번만 쓰는 일괄 쓰기(`Vault::put_secrets`)를 더한다. 검증은 `put_secret_values`와 같다. 쓰고 나서 바뀐 키마다 연결을 다시 묶고, 감사 기록은 키마다 지금과 같은 `secret_put`을 남긴 뒤 요약 `secret_import`(개수, ID 목록, 원천 `file|stdin`. 경로와 이름은 남기지 않음)를 하나 더한다.
- CLI 프로필 검사: 고른 값마다 `secret put`과 같은 규칙(`profile_env_carries_new_value`)으로 저장된 CLI 연결을 검사한다. 그 키를 쓰는 연결은 길이와 상관없이, 나머지 연결은 §4의 길이 규칙으로 본다. 걸리면 전체를 멈추고 연결 ID와 항목 이름을 알린다. 공유 환경에도 같은 검사를 한다. 지금 공유 환경의 `secret put`(`shared_put`)은 이 검사를 하지 않지만, 가져오기는 처음부터 막는다.
- 공유 환경: 고른 항목의 `secret.put_version`과 `secret.activate`(새 버전으로 옮길 연결의 연산 포함, `shared_put`과 같음)를 **커밋 하나**에 담는다. 키 교체 대기 중이면 `team_rekey_pending`으로 멈추는 것은 `secret put`과 같다. 관리자가 아닌 기기는 쓰기 전에 `sync::is_admin`으로 확인해 `not_admin`으로 멈춘다. 지금 `secret put`은 관리자가 아닌 기기에서도 커밋을 만들고 폴드가 그 연산을 `not_admin`으로 건너뛰는데, 가져오기에서 그러면 사용자는 성공한 줄 알게 된다. 실행 중인 `serve`가 다음 폴링 때 다른 기기로 보낸다. 항목 200개의 암호문은 프레임 한도 4 MiB 안에 든다.
- 값은 처음부터 끝까지 `Zeroizing` 버퍼에만 둔다. 해석 중간 결과도 마찬가지다.

## 8. 데스크톱 앱

- 키 화면에 ".env 가져오기"를 더한다.
- `file_pick {purpose: "env_file"}`: 새 용도 `FilePurpose::EnvFile`. 다른 용도의 토큰으로는 가져오기를 할 수 없다.
- `secret_import_preview {file_token, project, environment, id_prefix?}` → `{import_ref, preview}`: 코어가 파일(64 KiB까지)을 읽어 `secret import --stdin --dry-run`에 봉투로 넘긴다. 읽은 내용은 일회용 보관소에 새 종류 `env_import`로 10분 동안 둔다. 이 종류는 `onetime_show`·`onetime_copy`로 꺼낼 수 없고 `secret_import`만 읽는다. 웹뷰에는 미리 보기(이름, ID, 선택 여부, 이유, 동작)만 간다.
- `secret_import {import_ref, selected: [name…], update}`: 코어가 기본 선택과 비교해 `--include`/`--exclude`로 바꿔 실행하고, 성공하면 보관해 둔 내용을 지운다. 재인증은 `secret_put`처럼 받지 않는다.
- 화면 문구(예시): 목록 위에 "키로 보이는 항목만 골라 뒀어요. 설정값은 넣지 않는 게 좋아요." 끝난 뒤에 "원래 .env 파일은 그대로 있어요. 에이전트가 읽을 수 있는 곳이면 지워 주세요."

하지 않는 것:

- 보관함에서 `.env`로 내보내기, 프로세스 환경변수에 넣기, 셸 문법 실행.
- 원본 파일 고치기·지우기. 이미 에이전트가 읽을 수 있던 파일에 있던 키라면 가져와도 노출된 사실은 그대로이므로, 필요하면 서비스 쪽에서 키를 새로 발급한다.
- 변수 치환, JSON·YAML 같은 다른 형식, 저장소를 뒤져 `.env` 자동 찾기.
- 에이전트 도구(`zeropw-agent`, MCP)로 가져오기. 관리자 입력 경로에서만 한다.

## 9. 정한 것

소유자가 2026-10-25에 아래 다섯 가지를 모두 제안대로 정했다. 본문(§3~§8)은 이 결정을 따른다.

| 항목 | 결정 | 고르지 않은 선택 |
| --- | --- | --- |
| 분류 규칙(§4) | 표의 이름 조각 목록과 8바이트 기준으로 기본 선택을 정한다 | 분류 없이 전부 고른 채 시작 |
| 애매한 문법(`$`, 붙은 `#`, `\`) | 오류로 멈춘다(§3) | 글자 그대로 받고 경고만 |
| 원래 변수 이름 저장 | 저장하지 않는다(§5) | 버전 `public`에 `env_name`을 넣어 팀원 화면에도 표시. 지금 폴드는 `public`을 아무 객체나 받으므로 0.2.0 기기와도 섞어 쓸 수 있다. |
| 원본 파일 | 안내만 한다(§8) | 앱에서 휴지통으로 옮기기 버튼(코어가 고른 파일 하나만 옮김) |
| 이미 있는 키의 값이 다를 때 | 기본은 멈추고, `--update`를 주면 새 버전(§5) | 기본으로 새 버전 |

고르지 않은 선택은 나중에 다시 볼 때를 위해 남긴다. 바꾸려면 소유자가 새로 정한다.

## 10. 구현 순서와 시험

1. **해석·분류 모듈**(`rust/src/envfile.rs`): §3의 각 규칙과 오류 코드, §4의 분류 표, BOM·CRLF·여러 줄·한도. 오류 출력에 줄 내용이 없는지는 합성 값으로 확인한다. `$(touch 파일)`·백틱이 든 파일을 넣어도 그 파일이 생기지 않는지 본다.
2. **CLI 개인 환경**: `secret import`, `Vault::put_secrets`. 시험은 생성·변경 없음·충돌·`--update`, 다른 환경의 같은 ID, 대소문자 충돌, `--id-prefix`, CLI 프로필 거부, `--include`/`--exclude`, 봉투 경로다. 실패하면 보관함 문서가 바이트 단위로 그대로인지, `secret_put` 감사 기록이 없는지 확인한다. 출력·오류·감사 기록·상태 파일에서 합성 값을 찾아 평문이 없는지 본다.
3. **공유 환경**: 커밋 하나, 관리자가 아닌 기기 거부, `team_rekey_pending`. 세 기기 시험(`native_team_e2e` 방식)으로 다른 기기에 퍼지는지와 전선 캡처에 평문이 없는지 확인한다.
4. **데스크톱**: 파일 토큰 용도 묶기, 미리 보기에 값 없음, `env_import`를 `onetime_*`로 꺼낼 수 없음, 10분 만료, 선택을 include/exclude로 바꾸는 계산.
5. **문서**: [implementation.md](implementation.md), [desktop-app.md](desktop-app.md)의 명령 표, 사용자 문서.

제품 변경은 Linux와 macOS에서 `rust/verify.sh`를, 앱 변경은 `desktop/verify.sh`를 돌린다.
