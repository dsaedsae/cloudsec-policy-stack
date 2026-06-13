# 평가 — MLS 보상통제 *검증가능성* 커버리지 분석

> **이 프로젝트의 정량 결과.** "21/21 통과"는 *기능 회귀 스위트*(통제가 실제로 발동함을 증명)
> 일 뿐, 연구 증거가 아니다(분모가 없다). 여기서는 **검증가능성 기준(verifiability criterion)** 을
> 도입한다: *각 규제 요구사항은 그 시행을 증명하는 실행 가능한 테스트에 대응되어야 한다.* 이
> 기준을 FSC 망분리 완화/MLS 보상통제에 적용해, **무엇이 코드로 증명되고 무엇이 안 되는지를
> 정량화**한다.

## 기여 재정의 (contribution)
"우리가 통제를 구현했다"가 아니라:
> **우리는 검증가능성 기준을 제안하고, 이를 MLS 보상통제 요구사항 집합에 적용하여, 워크로드
> 계층에서 *코드로 검증 가능한 비율*을 측정하고 그 갭을 정직하게 드러낸다.**

이 재정의가 중요한 이유: "오프더셸프 통제를 모았다"는 신규성 비판을 부르지만, "어떤 규제
요구가 *증명 가능한가*를 정량화한다"는 측정 가능한 질문이며 — 감사·컴플라이언스 관점에서
직접 유용하다(증명 못 하는 통제는 보상통제로 인정받기 어렵다).

## 방법 (재현 가능)
1. **분해** — 1차 출처에서 요구사항을 원자적·검사가능 sub-requirement로 분해(현재 **42개**).
   출처 구분: A=FSC 로드맵 직접 명시, B=MLS/NIST 800-207/ISMS-P 파생, G=거버넌스.
2. **분류** — 각 sub-requirement를 4범주로(하드룰):
   - **VERIFIED-AS-CODE** — `verify.sh`/`authz.py`에 시행을 증명하는 실행 assertion 존재 → 라인 인용.
   - **CONFIGURED-NOT-VERIFIED** — IaC엔 있으나 시행 테스트 없음(예: WireGuard 동일노드 홉, SPIFFE opt-in).
   - **GOVERNANCE-ONLY** — 워크로드 테스트로 만들 수 없음(C/S/O 등급분류 거버넌스, 이사회 보고).
   - **NOT-COVERED** — 전사 MLS엔 필요하나 여기 없음(DLP, HSM/KMS, SIEM).
3. **계산** — 가족별·전체 커버리지 분율, 분모 명시. 인벤토리 = [`mls-coverage.csv`](mls-coverage.csv),
   계산·그림 = [`scripts/coverage.py`](https://github.com/dsaedsae/cloudsec-policy-stack/blob/main/scripts/coverage.py)
   (`python scripts/coverage.py`로 재생성).

## 결과

**헤드라인 메트릭:**

!!! success "검증가능-as-code 커버리지"
    **워크로드 적용가능 sub-requirement의 65% (26/40)** 가 코드로 검증된다.
    (거버넌스 포함 전체로는 26/42 = 62%.) 범주 분포: **VERIFIED 26 · CONFIGURED 8 ·
    GOVERNANCE 2 · NOT-COVERED 6.**

![MLS verifiability coverage per family](assets/coverage.png)

**가족별 (VERIFIED / 전체):**

| 통제 가족 | VERIFIED / 전체 | 주요 갭 |
|---|---|---|
| micro-segmentation | 4 / 5 | 교차네임스페이스 격리 미테스트 |
| zero-trust (egress) | 4 / 4 | — |
| credential-forgery (B7) | 4 / 8 | SPIFFE opt-in, 토큰미마운트 미assert, 타 ns 미포함, 요청자 JWT 검증(ID8) 라이브 강제 미배선(CONFIGURED) |
| least-privilege | 6 / 7 | deployer RBAC 부분 |
| encryption-in-transit | 2 / 2 | 크로스노드 암호화 + tcpdump 패킷캡처(WG UDP/51871 40pkt·캡처상한 존재, eth0 평문 0) — scripts/capture-wg.sh |
| encryption-at-rest | 1 / 3 | 키회전·KMS는 수동/문서 |
| detection (EDR) | 1 / 3 | 프로세스감사·광역룰 미assert |
| shift-left | 4 / 6 | gitleaks는 CI만; 이미지 서명(cosign)은 ECR 경로(레지스트리 필요) |
| governance (C/S/O) | 0 / 4 | 본질적으로 워크로드 테스트 불가 |

→ 전체 Table 1(42행, sub-requirement→출처→범주→verify 라인/갭)은 [`mls-coverage.csv`](mls-coverage.csv).

## 논의 (정직한 갭이 곧 기여)
- **VERIFIED 65%** 는 "워크로드 보상통제를 *어디까지 코드로 증명할 수 있는가*"의 정직한 상한에
  가깝다 — 망·인가·런타임·암호화(전송 tcpdump 캡처 포함)는 증명되고, **데이터 거버넌스(C/S/O
  분류·DLP·SIEM)는 워크로드 계층 밖**이다. 이 경계를 수치로 보이는 것이 핵심.
- **ID8(요청자 JWT audience 검증) 신규 — 헤드라인이 67%→65%로 *내려갔다*(정직한 방향).** 이전까지
  PDP의 명시된 #1 잔여는 *미인증 X-User 헤더*였고, 이는 산문으로만 추적되던 갭이었다. 이번에 그것을
  **인벤토리 행(ID8)으로 정식 편입**하면서 분모가 39→40으로 늘었다. PDP 엣지에 Bearer-JWT 검증을
  추가해 서명 + **audience 바인딩(RFC 8707)**·만료·위조·미지원 스킴을 fail-closed로 거절하는 *검증기
  로직*은 단위테스트됐지만(`app/api/auth_test.py` **13/13**, CI 게이트), **라이브 API는 여전히 X-User
  폴백을 허용해 인증을 강제하지 않으므로** 이 행은 **VERIFIED가 아니라 CONFIGURED**다. 그래서 분자는
  그대로(26)고 분모만 +1 → 비율이 *떨어진다*. 이는 메트릭 부풀리기의 반대 — 부분적으로만 해소된 통제를
  정직하게 드러내는 것이다. VERIFIED 승격 조건: Bearer 필수화 + `unauth→401`을 라이브 스위트에서 단언
  (ET2가 CONFIGURED→VERIFIED로 간 것과 같은 경로). 프로덕션 OAuth 2.1 RS/JWKS·RFC 8693 OBO는
  [authorization-model](authorization-model.md) 문서 매핑(doc-only).
- **CONFIGURED 8** 은 "있지만 (라이브로) 증명 안 됨" — 가장 위험한 범주(감사 시 "있다"고 주장하나
  시행 미증명). 우선 타깃이던 WireGuard tcpdump 캡처는 이번에 VERIFIED로 승격(ET2); 남은 타깃은
  SPIFFE 시행 테스트(ID4)·etcd 키회전 자동화(ER2)·요청자 인증 라이브 강제(ID8).
- **GOVERNANCE 2 / NOT-COVERED 6** 은 *이 레퍼런스의 범위 밖*이거나 명시된 갭(예: ID7 SA-use 타 ns —
  Kyverno ClusterPolicy 설계·스크립트 제공하나 RAM 사유로 본 세션 미기동 → 라이브 미증명이라 NOT_COVERED 유지).

## 한계
- 분해·분류는 저자 수행 → 주관 개입. 1차 출처(FSC·국정원 MLS·금융보안원 가이드) 대조와
  복수 평가자 합의가 다음 단계.
- 42개 sub-requirement는 *이 데모 워크로드* 기준. 전사 요구집합은 더 크고 분모가 달라진다.
- 오버헤드(지연·자원) 측정은 미수행 — 시스템 논문이면 별도 평가 필요(여기선 *커버리지*가 헤드라인).

## 발표/논문 타깃 (정직)
- **발표(토크): 지금 가능** — BoB / 금융보안 세미나 / AWS Summit 커뮤니티.
- **논문: 국내 응용/워크숍** (KIISC CISC-S/W·CISC-W, 금융보안원/KISA 기술트랙) — 이 커버리지 평가가
  그 바를 넘기는 단일 요소.
- **탑티어(USENIX/CCS/S&P): 비현실적** — 신규 메커니즘 없음(통합·규제매핑 기여). 과장 금지.
