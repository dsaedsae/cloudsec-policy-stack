# 인가 모델 포지셔닝 — RBAC + ABAC 하이브리드 · policy-as-code · 지속 평가

> **TL;DR.** 이 스택의 인가는 *유행*이 아니라 *현재 베스트프랙티스*에 정확히 정렬돼 있다:
> 실무 기본값인 **RBAC + 필요한 곳에 ABAC 하이브리드**를, 프런티어 전달방식인 **policy-as-code**
> 로 구현하고, **매 요청 지속/동적 평가**(캐시된 grant가 아니라)로 시행한다. 프런티어 모델 중
> **ReBAC**(관계기반)만 아직 구현하지 않았고 — 이를 정직한 갭이자 확장 경로로 명시한다.

"Cedar 썼다"가 아니라 "인가 지형을 알고 적합한 모델을 적합한 자리에 썼다"를 보이는 문서다.

---

## 1. 지형 (정확히)

| 모델/흐름 | 성격 | 강점 | 이 repo에서 |
|---|---|---|---|
| **RBAC** | 검증된 *기본값* | 단순·감사 쉬움·거친 단위 | k8s RBAC: tier SA(권한 0), `shop-deployer`/`shop:tier-operators` Role/바인딩 |
| **ABAC** | 검증된 *현역* (novel 아님) | 속성 조건으로 세밀하게 | **Cedar**: owner·transferLimit·frozen·role·`amount>0` 조건 |
| **ReBAC** | *프런티어* (관계/그래프) | "X의 소유자", "팀 멤버" 같은 관계 | **미구현** (Zanzibar/OpenFGA/SpiceDB). §4 갭·확장 |
| **policy-as-code** | 프런티어 *전달방식* | 코드·테스트·CI·리뷰 가능 | Cedar/CEL(VAP)/CiliumNetworkPolicy/checkov 전부 코드 + 단위테스트 + CI 게이트 |
| **지속/동적 평가** | 프런티어 *시행* | 위치·시점·문맥으로 매번 결정 | 매 요청 Cedar, 매 생성 admission, 런타임 Tetragon (캐시된 grant ✗) |

> 핵심: RBAC vs ABAC vs ReBAC는 *대체*가 아니라 *계층*이다. 실무 정답은 "거친 건 RBAC, 세밀한
> 건 ABAC, 관계는 ReBAC"의 하이브리드다. 이 스택은 RBAC+ABAC 하이브리드를 채택했고 ReBAC는
> 의도적 미채택(필요성·복잡도 트레이드오프)임을 밝힌다.

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

## 4. ReBAC — 정직한 갭이자 확장 경로

이 스택은 **관계기반(ReBAC)을 하지 않는다.** ReBAC는 "문서 D의 *소유자*인 사용자", "프로젝트 P의
*멤버*가 속한 *팀*" 같은 **관계 그래프**로 권한을 도출한다(Google Zanzibar 계열: OpenFGA, SpiceDB).

- **왜 안 했나:** 이 데모의 권한은 속성으로 충분(owner는 Cedar `principal == resource.owner`로 표현).
  깊은 관계 그래프가 필요 없어 ABAC가 적합. ReBAC는 복잡도·인프라(별도 권한 그래프 DB) 비용이 큼.
- **언제 필요한가 / 어떻게 확장하나:**
  - **AI 에이전트 위임**(on-behalf-of)은 본질적으로 *관계*다 — "에이전트 A가 사용자 U를 *대행*". 위임
    체인이 깊어지면 ReBAC가 자연스럽다.
  - **NHI 소유관계** — "워크로드 W를 *소유한* 팀 T", "서비스 S에 *바인딩된* 신원" 같은 관계.
  - 확장: **OpenFGA/SpiceDB**를 권한 그래프로 두고 Cedar/PDP가 그 관계를 조회(또는 Cedar 엔티티
    계층으로 *얕은* 관계 표현). 이 repo의 `api` PDP가 그대로 PEP 역할을 유지한다.

이 갭을 명시하는 것 자체가 "모델을 안다"의 증거다 — 모든 걸 한 모델로 우기지 않는다.

---

## 5. NHI · AI 에이전트 · AI Gateway 와의 연결

- **NHI(Non-Human Identity):** 이 스택의 신원은 전부 NHI다 — ServiceAccount, SPIFFE SVID, 워크로드
  신원, 토큰 미마운트, 자격증명 위조 차단. NHI 보안 = 2024–2026 핵심 토픽이고, 이 repo는 그
  *워크로드 NHI* 통제의 레퍼런스다.
- **AI 에이전트 인가:** 에이전트도 NHI다. 에이전트를 principal로, 도구호출을 action으로, 데이터를
  resource(등급 C/S/O)로 두면 **ABAC + 지속평가 + (위임은) ReBAC** 가 그대로 "에이전트 인가 스택"이
  된다. `api` PDP = 그 PEP의 축소판.
- **AI Gateway:** API Gateway가 PEP이듯, AI/Agent Gateway는 에이전트 행동의 PEP다. 여기서 위
  인가 모델이 시행된다. 이 repo의 PDP가 그 자리에 들어갈 수 있다.

---

## 6. 출처
- NIST SP 800-207, *Zero Trust Architecture* (동적 정책·지속 평가) — <https://csrc.nist.gov/pubs/sp/800/207/final>
- Google *Zanzibar: Google's Consistent, Global Authorization System* (ReBAC 기원, 2019) — <https://research.google/pubs/pub48190/>
- OpenFGA (CNCF, Zanzibar 계열) — <https://openfga.dev/> · SpiceDB — <https://authzed.com/spicedb>
- Cedar / Amazon Verified Permissions (정책+속성 인가) — <https://www.cedarpolicy.com/> · <https://aws.amazon.com/verified-permissions/>

> 정직 메모: 이 문서는 *포지셔닝*이다. ReBAC 미구현은 결함이 아니라 트레이드오프 선택이며, 필요가
> 생기면 §4 경로로 확장한다.
