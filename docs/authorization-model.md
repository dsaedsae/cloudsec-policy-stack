# 인가 모델 포지셔닝 — RBAC + ABAC 하이브리드 · policy-as-code · 지속 평가

> **TL;DR.** 이 스택의 인가는 *유행*이 아니라 *현재 베스트프랙티스*에 정확히 정렬돼 있다:
> 실무 기본값인 **RBAC + 필요한 곳에 ABAC 하이브리드**를, 프런티어 전달방식인 **policy-as-code**
> 로 구현하고, **매 요청 지속/동적 평가**(캐시된 grant가 아니라)로 시행한다. 프런티어 모델인
> **ReBAC**(관계기반)와 **AI-에이전트 위임**까지 **실행 가능한 데모**로 충족했다(`rebac/`,
> `cedar/agent/`) — 단, 라이브 `api` PDP는 여전히 Cedar/ABAC이고 OpenFGA는 그 PDP가 *조회할*
> 관계 오라클이라는 경계를 정직하게 유지한다.

"Cedar 썼다"가 아니라 "인가 지형을 알고 적합한 모델을 적합한 자리에 썼다"를 보이는 문서다.

---

## 1. 지형 (정확히)

| 모델/흐름 | 성격 | 강점 | 이 repo에서 |
|---|---|---|---|
| **RBAC** | 검증된 *기본값* | 단순·감사 쉬움·거친 단위 | k8s RBAC: tier SA(권한 0), `shop-deployer`/`shop:tier-operators` Role/바인딩 |
| **ABAC** | 검증된 *현역* (novel 아님) | 속성 조건으로 세밀하게 | **Cedar**: owner·transferLimit·frozen·role·`amount>0` 조건 |
| **ReBAC** | *프런티어* (관계/그래프) | "X의 소유자", "팀 멤버" 같은 관계 | **실행 데모** (`rebac/`, OpenFGA `fga model test` 11/11 + 라이브 `/check`). 라이브 PDP엔 미배선 — §4 |
| **policy-as-code** | 프런티어 *전달방식* | 코드·테스트·CI·리뷰 가능 | Cedar/CEL(VAP)/CiliumNetworkPolicy/checkov 전부 코드 + 단위테스트 + CI 게이트 |
| **지속/동적 평가** | 프런티어 *시행* | 위치·시점·문맥으로 매번 결정 | 매 요청 Cedar, 매 생성 admission, 런타임 Tetragon (캐시된 grant ✗) |

> 핵심: RBAC vs ABAC vs ReBAC는 *대체*가 아니라 *계층*이다. 실무 정답은 "거친 건 RBAC, 세밀한
> 건 ABAC, 관계는 ReBAC"의 하이브리드다. 이 스택은 **RBAC+ABAC를 라이브로 시행**하고, **ReBAC와
> 에이전트 위임은 실행 데모로 충족**하되(§4) 라이브 PDP에 ReBAC를 *배선하지 않은* 트레이드오프를 밝힌다.

---

## 2. 하이브리드가 이 스택에서 실제로 도는 법

한 요청이 **거친 통제 → 세밀한 통제**를 순서대로 통과한다:

```
배포 권한        : RBAC      누가 워크로드를 만들 수 있나 (k8s RBAC, shop-deployer)
워크로드 신원    : admission CEL  라벨↔SA 일관성 + 누가 티어 SA로 도나 (SA-use gate)
네트워크 도달    : Cilium policy  app:web→api→db만, L7 메서드/경로
요청 인가        : ABAC(Cedar)    이 principal이 이 자원에 이 action을? (owner·한도·동결)
```

- **RBAC로 충분한 곳**(배포 권한, SA의 API 권한)은 RBAC로 — 단순·감사 용이.
- **속성이 필요한 곳**(소유자인가? 한도 이내인가? 동결인가? 양수인가?)은 ABAC(Cedar)로.
- 둘을 **admission CEL**(요청자 신원 ↔ 사용 가능 SA)이 잇는다 — RBAC 주체와 ABAC 자원 사이의 신원 정합.

이게 AWS IAM(아이덴티티 정책=RBAC적 + Condition=ABAC적)이나 k8s(RBAC + admission)와 같은,
**검증된 하이브리드 패턴**이다.

---

## 3. "지속/동적 평가"가 왜 핵심인가 (망분리 완화·제로트러스트와 직결)

전통 모델은 *한 번 grant하면 캐시*한다. 망분리가 풀린(=위치로 신뢰 못 하는) 환경에선 **매 접근마다
다시 판정**해야 한다 — NIST 800-207 Tenet 4(동적 정책)·6(접근 전 매번 인증·인가). 이 스택:

- **Cedar는 매 요청 평가**한다(세션 grant 캐시 ✗). 한도·동결은 *요청 시점 컨텍스트*로 결정.
- **admission은 매 생성/수정마다** 신원 정합을 본다.
- **Tetragon은 런타임에 지속**적으로 본다.

→ `verify` 21/21이 이 "매번 시행"을 라이브로 증명한다. 이것이 정적 RBAC 테이블과의 결정적 차이.

---

## 4. ReBAC — 실행 데모 (`rebac/`)

ReBAC는 "문서 D의 *소유자*인 사용자", "프로젝트 P의 *멤버*가 속한 *팀*" 같은 **관계 그래프**로
권한을 도출한다(Google Zanzibar 계열: OpenFGA, SpiceDB). 이 repo는 그것을 **실행 가능한 데모**로
구현했다 — `cedar/authz.py`의 OpenFGA 쌍둥이:

- **무엇:** [`rebac/model.fga`](https://github.com/dsaedsae/cloudsec-policy-stack/blob/master/rebac/model.fga) 의 관계 모델 +
  [`rebac/store.fga.yaml`](https://github.com/dsaedsae/cloudsec-policy-stack/blob/master/rebac/store.fga.yaml) 의 단언(assertion)을 `fga model test`로 검증(서버
  불필요, **11/11**), 그리고 docker로 실제 OpenFGA `/check` API에 재검증하는 opt-in 경로(`rebac/check_live.py`).
- **핵심 관계(ABAC가 깔끔히 못 푸는 것):** 에이전트가 계정을 보려면
  `account.owner = alice` **AND** `alice.delegate = assistant` 두 관계의 **그래프 조인**
  (`delegate from owner`)이 성립해야 한다 — 에이전트의 도달은 *소유자와의 관계*에서 파생되지,
  에이전트가 들고 있는 속성에서 나오지 않는다. NHI 소유관계(`workload.owner_team`)도 동일.
- **정직한 경계:** 라이브 `api` PDP는 여전히 **Cedar/ABAC**다. OpenFGA는 그 PDP가 위임·소유 엣지를
  *조회할* 관계 오라클로 제시한 **설계**이며, `verify` 21-체크 라이브 스위트에 in-request로 배선돼
  있지 않다(과대주장 금지 — CLAUDE.md). 두 데모의 tuple은 Cedar와 **같은 alice/account 엔티티**를
  써서 한 세계로 합쳐진다.

같은 위임 아이디어를 **ABAC 교집합**으로 표현한 것이 [`cedar/agent/`](https://github.com/dsaedsae/cloudsec-policy-stack/tree/master/cedar/agent)다(§5).

---

## 5. NHI · AI 에이전트 · AI Gateway 와의 연결

- **NHI(Non-Human Identity):** 이 스택의 신원은 전부 NHI다 — ServiceAccount, SPIFFE SVID, 워크로드
  신원, 토큰 미마운트, 자격증명 위조 차단. NHI 보안 = 2024–2026 핵심 토픽이고, 이 repo는 그
  *워크로드 NHI* 통제의 레퍼런스다.
- **AI 에이전트 인가 (실행 데모 — [`cedar/agent/`](https://github.com/dsaedsae/cloudsec-policy-stack/tree/master/cedar/agent)):** 에이전트도 NHI다. 에이전트를
  principal로, 도구호출/데이터읽기를 action으로, 데이터를 resource(등급 C/S/O)로 둔 Cedar 번들을
  `python cedar/agent_authz.py`로 단위테스트한다(**17/17**). 핵심은 **위임 교집합**(delegation
  intersection)으로 **confused-deputy 차단**이다 — *비소유* 데이터 인가 = (에이전트 자신의 천장
  `max_classification`) **∧** (대행하는 사용자의 등급 `on_behalf_of.clearance`). 과잉권한 에이전트라도
  저등급 사용자를 대행하면 그 사용자가 닿지 못하는 *비소유* 데이터엔 닿을 수 없다. **단, 대행 사용자가
  *소유한* 레코드는 등급 사다리와 무관하게 에이전트 천장까지 읽을 수 있다**(owner override, `policies.cedar`
  P3) — 즉 교집합은 비소유 데이터에 적용되고, 소유 데이터는 에이전트 천장으로만 제한된다. 테스트는
  *반증가능*하게 설계됐다: P2를 지우면 "P2 IS LOAD-BEARING" 케이스가 Allow→Deny로 뒤집히고, P3를 지우면
  "P3 IS LOAD-BEARING" 케이스가 뒤집힌다(mutation으로 확인). 관계로 표현한 같은 위임이 §4의 ReBAC다.
- **위임 체인 깊이 cap + 홉별 클램프 + 출처 게이트 (ASI08 — `policies.cedar` P5·P6·P7, 신규):** 에이전트가
  *서브에이전트를 스폰*하면 human→agent→sub→… 체인이 생기고, 경계가 없으면 권한이 무한 스폰 트리로 **연쇄
  (cascade)**한다(OWASP Agentic Top 10 2025-12-09의 **ASI08 Cascading Failures** — 위임 연쇄 측면). **P5**:
  `delegation_depth`(휴먼 위 agent→agent 홉 수)>1 에이전트를 모든 action에서 거부(0=직접조작·1=허용된 한 홉·2+=거부).
  **P6**: 스폰 시 control plane이 기록한 **스칼라 `delegated_by_max_classification`**(스폰 에이전트의 천장)으로
  읽기를 클램프 — 서브 자신의 천장이 높아도 부모의 낮은 천장이 막는다. **P7(fail-closed)**: 그 스칼라는 optional이라,
  depth≥1인데 스칼라가 없는 서브에이전트를 모든 action에서 거부해 부모 천장 기록을 강제한다.
  > **fail-closed by construction (실제 버그 수정):** 초기 버전은 `delegated_by`를 **Agent 엔티티**로 두고 천장을
  > *역참조*했는데, 참조가 **dangling**(엔티티 부재)이면 정책이 **에러**나고 Cedar는 *에러난 forbid를 건너뛴다* →
  > 클램프가 **fail-OPEN**되어 서브가 자기 천장까지 증폭했다(전문가 리뷰가 라이브 확인). 스칼라는 dangle할 수 없어
  > fail-open이 불가능하다. 회귀 테스트: 스칼라 누락 depth-1 서브의 기밀 읽기 → Deny(`requests.json` P7 케이스).
  > ✅ **성립하는 것(범위 명시):** P5(depth≤1→중간 에이전트 최대 한 명)+P7(스칼라 필수)+P6(스칼라 클램프)로 바운드
  > 체인의 **실효 천장 = (루트 휴먼 등급)∧(스폰 에이전트 천장)∧(서브 천장)의 최소** — *단, control plane이
  > `on_behalf_of`와 `delegated_by_max_classification`를 **진실하게** 기록한다는 TCB 가정 하에서만* 성립한다
  > (라벨/JWT와 동일한 신뢰 경계). 정책은 입력의 진실성을 검증하지 않는다.
  > ⚠️ **모델이 *안* 하는 것(과장 금지):** 자식의 `on_behalf_of`를 부모의 것과 *대조*하지 않는다 — guest(0)를 대행하는
  > 부모가 bob(2)을 대행한다고 *선언한* 자식을 스폰하면 기밀을 읽을 수 있다(확인됨). 휴먼-등급 floor는 자식이 선언한
  > on_behalf_of 기준이지 체인의 진짜 최저 휴먼이 아니며, 이 역시 위 TCB 가정에 포함된다. depth>1은 P5가 막는다.

  P5·P6·P7 모두 *반증가능*하다 — P5 삭제 시 depth-2가 공개데이터 읽기 Deny→Allow, P6 삭제 시 부모 천장 0 서브가
  기밀 읽기 Deny→Allow, P7 삭제 시 스칼라 누락 depth-1 서브가 기밀로 증폭 Deny→Allow(셋 다 확인됨).
- **OWASP Agentic Top 10 (2025-12-09) 매핑** — P1–P7이 어디에 대응하고, 무엇이 *아직 doc-only*인지 정직하게:

  | 정책/통제 | OWASP Agentic 항목 | 이 repo |
  |---|---|---|
  | P1 도구 allowlist | ASI02 Tool Misuse (도구 오남용) | VERIFIED (agent 17/17) |
  | P2 위임 교집합 / P3 owner override | **ASI03 Identity & Privilege Abuse** (권한 오남용/confused-deputy) | VERIFIED (mutation 반증) |
  | P5 깊이 cap / P6 홉별 클램프 / P7 출처 게이트(fail-closed) | **ASI08 Cascading Failures** (위임 연쇄·증폭 방지) | VERIFIED (P5·P6·P7 각각 mutation 반증) |
  | (PDP 엣지) Bearer-JWT audience 검증 | **ASI03 Identity & Privilege Abuse** (신원 위조/token replay) | `auth_test.py` 18/18 + `verify-jwt-enforce.ps1` 라이브(unauth→401·Bearer→200) → **coverage ID8 = VERIFIED** (enforce opt-in) |
  | 메모리/RAG 오염 | ASI06 Memory & Context Poisoning | **NOT_COVERED — doc-only** (이 스택은 인가 계층; 메모리 무결성은 범위 밖) |
  | 에이전트 간 통신 신뢰 | ASI07 Insecure Inter-Agent Communication | **doc-only** — SPIFFE 상호인증(ID4, CONFIGURED)이 *부분* 토대이나 에이전트 프로토콜 수준 미구현 |

  > 과대주장 금지: 이 데모는 **인가 결정**(누가 무엇을)을 다룬다. ASI06(메모리 오염)·ASI07(에이전트 간
  > 프로토콜)은 별도 계층이라 여기서 **충족했다고 주장하지 않는다** — 경계만 표시한다.
- **요청자 인증 / OAuth 2.1 (PDP 엣지, [`app/api/auth.py`](https://github.com/dsaedsae/cloudsec-policy-stack/blob/master/app/api/auth.py)):** PDP는 `Authorization:
  Bearer` 토큰이 제시되면 **서명 + audience**(이 리소스용으로 발급됐는지, **RFC 8707** resource indicator)
  를 검증한 뒤에야 그 `sub`를 principal로 삼고, 검증 실패·미지원 스킴은 **fail-closed(401)** 한다 — 다른
  서비스용 토큰의 재생(replay)을 막는다(`auth_test.py` 18/18). **기본 배포는** Authorization이 없으면
  미인증 **X-User 데모 폴백**으로 내려가지만, **`AUTH_REQUIRE_JWT=1` enforce 모드**는 Bearer를 필수화하고
  X-User 폴백을 끈다 — 이를 라이브로 증명했다(`scripts/verify-jwt-enforce.ps1`: unauth→401·Bearer→200).
  따라서 이 통제는 coverage에서 **ID8 = VERIFIED**다(enforce는 opt-in; 기본은 데모 폴백). **데모 한계:** 서명키는
  로컬 HS256 픽스처이고(프로덕션은 IdP **JWKS** 비대칭 검증). **프로덕션 매핑(doc-only):** OAuth 2.1
  **Resource Server**, **RFC 8693** 토큰 교환 OBO, MCP Authorization 스펙. full OAuth(DCR/discovery/실 OBO)는 미구현.
- **AI Gateway:** API Gateway가 PEP이듯, AI/Agent Gateway는 에이전트 행동의 PEP다. 여기서 위
  인가 모델이 시행된다. 이 repo의 PDP가 그 자리에 들어갈 수 있다. NHI 생애주기 관점은
  [`nhi.md`](nhi.md) 참조.

---

## 6. 출처
- NIST SP 800-207, *Zero Trust Architecture* (동적 정책·지속 평가) — <https://csrc.nist.gov/pubs/sp/800/207/final>
- Google *Zanzibar: Google's Consistent, Global Authorization System* (ReBAC 기원, 2019) — <https://research.google/pubs/pub48190/>
- OpenFGA (CNCF, Zanzibar 계열) — <https://openfga.dev/> · SpiceDB — <https://authzed.com/spicedb>
- Cedar / Amazon Verified Permissions (정책+속성 인가) — <https://www.cedarpolicy.com/> · <https://aws.amazon.com/verified-permissions/>
- OWASP *Top 10 for Agentic Applications* (2025-12-09; ASI02 Tool Misuse·ASI03 Identity & Privilege Abuse·ASI06 Memory & Context Poisoning·ASI07 Insecure Inter-Agent Communication·ASI08 Cascading Failures) — <https://genai.owasp.org/>
- MCP *Authorization* 스펙 (OAuth 2.1 Resource Server) — <https://modelcontextprotocol.io/specification/draft/basic/authorization>
- RFC 8707 *Resource Indicators for OAuth 2.0* (audience binding) · RFC 8693 *OAuth 2.0 Token Exchange* (OBO) — <https://www.rfc-editor.org/rfc/rfc8707> · <https://www.rfc-editor.org/rfc/rfc8693>

> 정직 메모: 이 문서는 *포지셔닝*이다. ReBAC와 에이전트 위임은 §4·§5의 **실행 데모**로 충족했으나,
> 라이브 `api` PDP에 in-request로 배선하지는 않았다(설계·오라클 수준). 이 경계를 분명히 하는 것이
> 모델을 안다는 증거다 — 데모를 라이브 통합으로 과대주장하지 않는다.
