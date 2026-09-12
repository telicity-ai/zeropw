# 1Password 공식 출처 확인 기록

확인일: 2026-09-11 KST. Sol의 공식 문서 조사 후 Astra가 아래 공식 페이지를 web 도구로 직접 열어 확인했다. HTTP 상태 코드는 도구 결과에 별도로 제공되지 않아 기록하지 않는다. 내용이 반환된 페이지의 제목과 핵심 관찰을 기록한다. 외부 페이지는 변경될 수 있다.

증거 성격은 작성자 확인과 Sol의 사실 점검이다. 외부 기관의 독립 검증이나 Opus의 직접 웹 검증은 아니다.

| ID | 공식 페이지 제목 | 확인한 핵심 내용 |
| --- | --- | --- |
| S1 | Environments | 프로젝트·개발 단계별 변수, 파일 import, 실행 시 접근 |
| S2 | run | 자식 프로세스에 실제 값 주입; stdout/stderr의 비밀값 기본 마스킹과 해제 옵션 |
| S3 | Secure secrets for AI agents and tools | 1Password MCP 관리와 외부 MCP 프로세스 주입의 차이 |
| S4 | Tutorial Integrate 1Password SDKs with AI agents | 모델에 raw credentials 전달을 비권장하는 명시적 주의 |
| S5 | 1Password Service Account security | 자동화 권한과 service account token의 보호 책임 |
| S6 | About 1Password SSH Agent security | 키를 내보내지 않는 인증·서명과 승인 |
| S7 | 1Password Connect | 자체 환경에 배치하는 API와 캐시 |
| S8 | Use 1Password to securely provide credentials to AI agents | 별도 브라우저 agent autofill 통합 |

URL은 product-intent.md의 S1-S8과 대응한다. Sol의 2차 사실 확인에서 `op run` 마스킹의 범위와 MCP 두 경로가 혼동될 수 있음을 지적해 해당 문장을 수정했다. Opus는 도구 없는 설계 검증을 수행했으며 출처 사실 확인을 대신하지 않았다.
