# ZeroPW

에이전트에게 원본 비밀값을 주지 않고 CLI·API를 사용하게 하는 개인용 클라우드 금고다. 서비스와 자격증명을 한 번 연결하면 작업별 등록 없이 지원하는 CLI·API를 사용하며, 인증 중계와 SSH 서명 위임으로 원본 키를 실행 코드에서 분리한다.

제품은 정의 단계이며 구현·배포 전이다. 별도 개발 하네스는 클라우드 구현 작업과 현재 로컬 Codex 세션의 Opus 리뷰를 연결한다. 실제 운영 준비 상태와 명령은 [하네스 안내](harness/README.md)를 따른다.

## 현행 문서

- [제품 정의](docs/product-intent.md)
- [인증 중계와 보안 경계](docs/security-design.md)
- [클라우드 개발 하네스](docs/harness.md)
- [개정 반영 현황](docs/reviews/review-summary.md)
- [제품 정의 PDF](output/pdf/zeropw-product-definition.pdf) — 2026-09-12 세션 연계 하네스 결정 전의 제품 설명 스냅샷. 현재 개발 운영 방식은 Markdown을 따른다.

docs/archive의 자료와 2026-09-11 검토 기록은 이전 설계의 이력이다. 현행 요구사항이나 새 보안 검증 통과의 근거로 사용하지 않는다.
