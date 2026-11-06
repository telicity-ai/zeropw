# 개인 기기 동기화: coturn 서비스 설계와 구현 체크리스트

작성: 2026-11-06 · Astra · 상태: 소스 조사와 설계, 구현·배포·부하시험 전

갱신: 2026-11-06 · 같은 날 사용자 결정(아래 §0)을 반영했다. 이 갱신도 구현·시험 완료 표시가 아니다. 실행 증거는 [remote-sync.md](remote-sync.md)와 날짜가 붙은 검증 기록에 따로 남긴다.

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

## 1. 확정된 결정과 범위

사용자의 최신 결정이 이전 제품 문서의 개인 동기화·클라우드 전제보다 우선한다.

- 개인의 로그인 정보·비밀번호·API 키를 본인 기기 사이에서 암호화 동기화한다.
- 별도 저장소에서 재사용 가능한 연결 모듈과 서비스 계층을 관리한다. 저장소 이름·소유자는 미정이다.
- Iroh 전체 SDK를 제품 의존성으로 넣지 않는다. 소스와 테스트를 참고해 요구사항을 도출한다.
- 암호화·ICE·TURN 처리를 위한 필요한 소형 라이브러리는 허용한다. 암호 알고리즘이나 신뢰성 전송을 새로 발명하지 않는다.
- 서버 중계는 coturn, 운영 환경은 Oracle Cloud로 한다.
- 베타는 초대 코드로 기기를 등록하며 이메일 계정을 요구하지 않는다.
- 무료 VM으로 시작하며 일시적인 원격 동기화 중단을 허용한다. 유료 자원 자동 전환은 하지 않는다.
- 원본 비밀 비전달, 신뢰 금고·HTTP gateway·SSH signer 경계는 유지한다. 이번 결정은 SSH 서명 기능 제거가 아니다.

다음은 제안 기본값이며 사용자 확정과 구분한다: 100명/사용자당 2기기, 양쪽 온라인일 때 자동 동기화, 첨부파일 제외, 서버에 금고 암호문도 영구 보관하지 않음. 이 문서는 TURN 기반 신규 구현의 인수 기준이며 기존 제품이 이미 이를 지원한다는 뜻이 아니다.

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
- 배포 입력: OCI 현재 리전/shape, 사용할 도메인, 새 저장소 소유자·이름·공개 여부. 비밀값은 채팅으로 받지 않음.
- ~~제한 네트워크~~: §0에서 5349 TURN TLS로 시작하기로 확정.
- 메타데이터 보관: 제안은 최소 기기 등록·회수 상태 영구 보관(서비스 탈퇴까지), rendezvous 최대 5분, 원본 IP 운영 로그 최대 24시간, 익명 집계 7일. 공개 전 실제 로그 설정과 사용자 안내에 일치시킬 것.

라이브러리·상태 머신·테스트 상세는 위 요구를 기준으로 엔지니어링에서 결정하며 사용자에게 개별 API 선택을 떠넘기지 않는다. 위 제안 기본값은 아직 사용자가 확정한 결정으로 기록하지 않는다.

## 7. 추가 근거

- [ICE RFC 8445](https://www.rfc-editor.org/rfc/rfc8445.html): 직접/중계 후보와 연결성 검사.
- [TURN RFC 8656](https://www.rfc-editor.org/rfc/rfc8656.html): allocation·permission·channel·refresh. TURN만으로 종단 간 암호화나 파일 전송을 제공하지 않음.
- [coturn 조사 설정](https://github.com/coturn/coturn/blob/ad8885a54ac1d59a39f2cc49ae7662fc2d842c64/examples/etc/turnserver.conf): 단기 자격, quota, 포트, 접근 제한, metrics 설정.
- [Oracle Always Free](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm): shape·네트워크·유휴 회수 정책. 배포 시 계정의 실제 할당량 재확인.

이번 변경은 문서만 추가한다. 원격 저장소 생성, OCI 프로비저닝, coturn 실행, 실제 서비스 통합 및 테스트는 아직 수행하지 않았다.
