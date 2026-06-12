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

- **무엇:** [`rebac/model.fga`](../rebac/model.fga) 의 관계 모델 +
  [`rebac/store.fga.yaml`](../rebac/store.fga.yaml) 의 단언(assertion)을 `fga model test`로 검증(서버
  불필요, **11/11**), 그리고 docker로 실제 OpenFGA `/check` API에 재검증하는 opt-in 경로(`rebac/check_live.py`).
- **핵심 관계(ABAC가 깔끔히 못 푸는 것):** 에이전트가 계정을 보려면
  `account.owner = alice` **AND** `alice.delegate = assistant` 두 관계의 **그래프 조인**
  (`delegate from owner`)이 성립해야 한다 — 에이전트의 도달은 *소유자와의 관계*에서 파생되지,
  에이전트가 들고 있는 속성에서 나오지 않는다. NHI 소유관계(`workload.owner_team`)도 동일.
- **정직한 경계:** 라이브 `api` PDP는 여전히 **Cedar/ABAC**다. OpenFGA는 그 PDP가 위임·소유 엣지를
  *조회할* 관계 오라클로 제시한 **설계**이며, `verify` 21-체크 라이브 스위트에 in-request로 배선돼
  있지 않다(과대주장 금지 — CLAUDE.md). 두 데모의 tuple은 Cedar와 **같은 alice/account 엔티티**를
  써서 한 세계로 합쳐진다.

같은 위임 아이디어를 **ABAC 교집합**으로 표현한 것이 [`cedar/agent/`](../cedar/agent/)다(§5).

---

## 5. NHI · AI 에이전트 · AI Gateway 와의 연결

- **NHI(Non-Human Identity):** 이 스택의 신원은 전부 NHI다 — ServiceAccount, SPIFFE SVID, 워크로드
  신원, 토큰 미마운트, 자격증명 위조 차단. NHI 보안 = 2024–2026 핵심 토픽이고, 이 repo는 그
  *워크로드 NHI* 통제의 레퍼런스다.
- **AI 에이전트 인가 (실행 데모 — [`cedar/agent/`](../cedar/agent/)):** 에이전트도 NHI다. 에이전트를
  principal로, 도구호출/데이터읽기를 action으로, 데이터를 resource(등급 C/S/O)로 둔 Cedar 번들을
  `python cedar/agent_authz.py`로 단위테스트한다(**12/12**). 핵심은 **위임 교집합**(delegation
  intersection)으로 **confused-deputy 차단**이다 — *비소유* 데이터 인가 = (에이전트 자신의 천장
  `max_classification`) **∧** (대행하는 사용자의 등급 `on_behalf_of.clearance`). 과잉권한 에이전트라도
  저등급 사용자를 대행하면 그 사용자가 닿지 못하는 *비소유* 데이터엔 닿을 수 없다. **단, 대행 사용자가
  *소유한* 레코드는 등급 사다리와 무관하게 에이전트 천장까지 읽을 수 있다**(owner override, `policies.cedar`
  P3) — 즉 교집합은 비소유 데이터에 적용되고, 소유 데이터는 에이전트 천장으로만 제한된다. 테스트는
  *반증가능*하게 설계됐다: P2를 지우면 "P2 IS LOAD-BEARING" 케이스가 Allow→Deny로 뒤집히고, P3를 지우면
  "P3 IS LOAD-BEARING" 케이스가 뒤집힌다(mutation으로 확인). 관계로 표현한 같은 위임이 §4의 ReBAC다.
- **AI Gateway:** API Gateway가 PEP이듯, AI/Agent Gateway는 에이전트 행동의 PEP다. 여기서 위
  인가 모델이 시행된다. 이 repo의 PDP가 그 자리에 들어갈 수 있다. NHI 생애주기 관점은
  [`nhi.md`](nhi.md) 참조.

---

## 6. 출처
- NIST SP 800-207, *Zero Trust Architecture* (동적 정책·지속 평가) — <https://csrc.nist.gov/pubs/sp/800/207/final>
- Google *Zanzibar: Google's Consistent, Global Authorization System* (ReBAC 기원, 2019) — <https://research.google/pubs/pub48190/>
- OpenFGA (CNCF, Zanzibar 계열) — <https://openfga.dev/> · SpiceDB — <https://authzed.com/spicedb>
- Cedar / Amazon Verified Permissions (정책+속성 인가) — <https://www.cedarpolicy.com/> · <https://aws.amazon.com/verified-permissions/>

> 정직 메모: 이 문서는 *포지셔닝*이다. ReBAC와 에이전트 위임은 §4·§5의 **실행 데모**로 충족했으나,
> 라이브 `api` PDP에 in-request로 배선하지는 않았다(설계·오라클 수준). 이 경계를 분명히 하는 것이
> 모델을 안다는 증거다 — 데모를 라이브 통합으로 과대주장하지 않는다.
