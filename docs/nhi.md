# NHI(비인간 신원) 생애주기 — 이 스택을 신원 관점으로 다시 보기

> **TL;DR.** 이 스택의 principal은 *전부 비인간(NHI)* 이다 — tier ServiceAccount, SPIFFE SVID,
> 애플리케이션 principal(`X-User`), 그리고 확장 스레드인 AI 에이전트. 이 문서는 **새 통제를
> 추가하지 않는다.** 이미 검증된 통제를 **NHI 생애주기 6단계**(provision → authenticate →
> authorize → rotate → detect → decommission)로 재조명하고, 각 항목을
> [`mls-coverage.csv`](mls-coverage.csv)의 **기존 id와 그 라벨**(VERIFIED/CONFIGURED/NOT_COVERED)에
> 그대로 연결한다. 헤드라인 67%(26/39)는 **바뀌지 않는다** — 이 문서는 메트릭을 더하지 않고,
> 같은 증거를 다른 렌즈로 본다.

## NHI란, 그리고 왜 2024–2026의 핵심인가

NHI(Non-Human Identity)는 사람이 아닌 신원 — ServiceAccount·워크로드 신원·API 키·토큰·인증서/SVID,
그리고 이제 **AI 에이전트** — 를 가리킨다. NHI는 사람보다 수십 배 많지만 사람이 받는 생애주기 위생
(입·전출입·퇴직 절차, 회전, MFA)을 대개 못 받는다: 회전되지 않는 시크릿, 주인 없는 토큰, 폐기되지
않는 권한. OWASP가 2025년 **NHI Top 10**을 별도 카테고리로 낸 것이 이 우선순위를 보여준다.

> **범위 정직 고지:** 이 repo는 *워크로드 NHI*의 레퍼런스다. NHI **인벤토리 제품**도, **시크릿
> 매니저**도 아니다. 아래 매핑은 그 경계 안에서만 주장한다.

## 이 스택은 이미 NHI다

[`authorization-model.md` §5](authorization-model.md)가 짚듯, 여기 신원은 전부 비인간이다:
`web-sa`/`api-sa`/`db-sa` ServiceAccount, 그 SA에서 파생되는 SPIFFE SVID, PDP의 `X-User` 애플리케이션
principal, 그리고 확장 스레드인 AI 에이전트(`cedar/agent/`). 그래서 이 스택의 통제는 곧 NHI 통제다.

## 핵심: 통제 → NHI 생애주기 6단계

각 행의 증거는 [`mls-coverage.csv`](mls-coverage.csv)의 **기존 id와 동일 라벨**을 가리킨다(새 행 없음).

| 단계 | 이 스택의 통제 | 증거(CSV id) | 라벨 |
|---|---|---|---|
| **PROVISION** (신원 생성) | tier별 최소권한 SA, RoleBinding 0 | ID5 | ✅ VERIFIED |
| **AUTHENTICATE** (신원 증명) | 라벨↔SA 일관성(admission) | ID1 | ✅ VERIFIED |
| | 요청자↔SA 바인딩(SA-use gate) | ID2 | ✅ VERIFIED |
| | CronJob 경로까지 SA-use 적용 | ID3 | ✅ VERIFIED |
| | SPIFFE SVID 상호인증(엣지) | ID4 | ⚙️ CONFIGURED (opt-in·Lab4 수동) |
| **AUTHORIZE** (권한 행사) | tier SA의 K8s API 권한 0 | ID5 | ✅ VERIFIED |
| | 네트워크 도달 L3/L7(Cilium) | NS3·NS4 | ✅ VERIFIED |
| | 요청별 Cedar ABAC + 에이전트 위임 | LP1–LP6 · `cedar/agent/` 12/12 | ✅ VERIFIED |
| **ROTATE** (자격증명 위생) | SPIRE 단명 SVID 자동회전(~1h) | ID4 | ⚙️ CONFIGURED |
| | etcd Secret 키 회전 절차(2-key) | ER2 | ⚙️ CONFIGURED (런북·미자동) |
| | SA 토큰 미마운트(정적 시크릿 회피) | ID6 | ⚙️ CONFIGURED (미assert) |
| **DETECT** (오작동 NHI 포착) | 런타임 셸 즉시 SIGKILL(data tier) | ED1 | ✅ VERIFIED |
| | egress default-deny(beacon 차단) | ZT1–ZT3 | ✅ VERIFIED |
| | 프로세스 감사·광역 룰 | ED2·ED3 | ⚙️/⛔ CONFIGURED/NOT_COVERED |
| **DECOMMISSION** (신원 폐기) | **자동 deprovision·주인없는 신원 탐지·NHI 인벤토리** | — | ⛔ **NOT_COVERED** (정직한 구멍) |

### 단계별 메모 (정직한 강·약)

- **AUTHENTICATE가 가장 강하다.** 라벨↔SA·SA-use gate(B7)는 라이브로 *위조를 거부*함을 증명한다
  (ID1: 위조 `app:api`를 `web-sa`로 DENY / ID2: CI SA가 `api-sa`로 DENY / ID3: CronJob 경로 DENY).
  SPIFFE SVID(ID4)는 **CONFIGURED** — opt-in이고 verify 스위트에 없으므로 VERIFIED로 올리지 않는다.
- **ROTATE의 진짜 의미:** 이 스택은 *정적 장수 시크릿을 만들지 않는다*(토큰 미마운트 + 단명 SVID).
  "정적 API 키 회전"이 없는 건 갭이 아니라 **설계 선택**이다. 단, 그 항목들은 라이브 assert가 아니라
  **CONFIGURED**임을 분명히 한다.
- **DECOMMISSION은 정직한 구멍이다.** 자동 NHI 폐기·offboarding·정체된 자격증명 탐지·NHI 인벤토리는
  **없다**(NOT_COVERED). SVID가 ~1h로 만료되어 *제거된 워크로드는 자연히 암호학적 신원을 잃는* 구조적
  강점은 있으나, SA/RoleBinding 정리·고아 신원 탐지는 수동/범위 밖이다. 거버넌스(C/S/O)=0/4를 다루는
  방식과 똑같이, 경계를 숨기지 않고 이름 붙인다.

## 확장 스레드 (이미 수립된 내러티브에 연결)

AI 에이전트도 NHI다. 자세한 모델은 [`authorization-model.md` §4·§5](authorization-model.md)에 있고,
요점만:

- **위임은 본질적으로 관계다.** "에이전트 A가 사용자 U를 *대행*"은 [`rebac/`](../rebac/)의 관계
  그래프(`delegate from owner`)로, 또는 [`cedar/agent/`](../cedar/agent/)의 **ABAC 교집합**
  (에이전트 천장 ∧ 대행 사용자 등급, *비소유* 데이터 한정 — 소유 데이터는 owner override로 천장까지)로
  표현된다 — 후자는 confused-deputy 차단을 12/12로 단위테스트하며 P2·P3 mutation으로 반증가능하다.
- **`api` PDP = AI/Agent Gateway가 호스팅할 PEP의 축소판.** 단, 이 repo는 에이전트 런타임·위임
  체인·게이트웨이를 **구현하지 않는다** — 그것이 명시된 확장 경로이지 주장이 아니다.

## 평가 분석과의 연결 (새 메트릭 없음)

이 문서는 **CSV에 행을 더하지 않고, 헤드라인 67%(26/39)를 바꾸지 않는다.** 위 표의 모든 id
(ID1–ID6, NS3·NS4, ZT1–ZT3, LP1–LP6, ED1–ED3, ER2)는 이미 [`mls-coverage.csv`](mls-coverage.csv)에
*그 범주 그대로* 존재한다. NHI 렌즈는 **이미 검증된 증거 위에 올라탄다** — 증거를 부풀리지 않는다.
이 불변성 자체가 정직성의 보증이다(`python scripts/coverage.py` 출력은 이 문서로 인해 변하지 않는다).

## 출처

- NIST SP 800-207, *Zero Trust Architecture* (동적 정책·매 접근 인가) — <https://csrc.nist.gov/pubs/sp/800/207/final>
- OWASP *Non-Human Identities Top 10* (2025) — <https://owasp.org/www-project-non-human-identities-top-10/>
- CSA, *Non-Human Identity Management* — <https://cloudsecurityalliance.org/research/topics/non-human-identity-management>
- SPIFFE/SPIRE (워크로드 신원·단명 SVID) — <https://spiffe.io/>
- Kubernetes *ServiceAccount* 문서 — <https://kubernetes.io/docs/concepts/security/service-accounts/>
- Cedar / Amazon Verified Permissions — <https://www.cedarpolicy.com/>

> 정직 메모: 이 문서는 *포지셔닝*(렌즈)이다. PROVISION-동적발급·ROTATE-정적시크릿·DECOMMISSION·
> AI-에이전트 런타임은 **구현된 것이 아니라 명시된 확장 경로**다. SPIFFE는 CONFIGURED이지 VERIFIED가
> 아니다. 모든 NHI 주장은 위 표의 기존 CSV id와 그 라벨로 환원된다.
