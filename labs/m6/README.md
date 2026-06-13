# M6 — 프런티어: AI 에이전트 위임 인가 (ABAC 교집합 + ReBAC)

<div class="lab-pills">
<span class="lab-progress">모듈 7 / 7</span> · <span class="lab-badge">스택 Cedar+OpenFGA</span> · <span class="lab-badge">소요 ~2–4h</span> · <span class="lab-badge no-cluster">클러스터 불필요 · Part B Docker</span> · <span class="lab-badge">비용 $0 로컬</span>
</div>

> **준비:** `.venv`(requirements-dev) — [SETUP](../SETUP.md). **Part B(ReBAC)는 Docker Desktop 필요**
> (없으면 Part A만 채점, 졸업 표시 안 됨).

**미션:** 같은 "위임" 문제를 두 모델로 구현한다 — **(A) Cedar ABAC 교집합**으로 confused-deputy를
막고, **(B) OpenFGA ReBAC** 관계 그래프로 같은 위임을 표현한다. 클러스터 불필요(python + docker).

> 🎯 **학습 성과 (면접에서 말할 수 있는 것):** AI 에이전트 위임을 ABAC 교집합(+ASI08 위임깊이 cap·홉별 클램프·출처 게이트)과 ReBAC 그래프로 구현해 confused-deputy를 막고, 이것이 라이브 에이전트 런타임이 아니라 위임 *인가 정책*의 단위테스트임을 정직히 말할 수 있다. → [캡스톤 M6](../capstone.md)

**편집 파일:** `labs/m6/agent-policies.cedar` (Part A), `labs/m6/model.fga` (Part B).

> 선행: **M0**(Cedar 문법)을 먼저 졸업하라 — Part A는 M0의 연장이다.
> 배경(읽기): [authorization-model §4–§5](../../docs/authorization-model.md) + [nhi.md](../../docs/nhi.md)
> — 에이전트/NHI 위임을 ABAC 교집합·ReBAC 그래프로.

---

## 왜 이게 "프런티어"인가

AI 에이전트는 사용자를 **대행**하는 비인간 신원(NHI)이다. 위험은 *confused deputy*: 권한 큰
에이전트가 권한 작은 사용자를 대행하면서 그 사용자가 못 닿을 데이터에 닿는 것. 해법은 인가를
**교집합**으로 만드는 것 — (에이전트 천장) ∧ (대행 사용자 등급). 이건 2024–2026 AI 보안의
핵심 주제이고, 같은 위임이 *관계*로 보면 ReBAC다(`docs/authorization-model.md` §4–§5,
`docs/nhi.md`).

## Part A — Cedar ABAC 교집합 (목표 17/17)

```powershell
.venv\Scripts\python.exe labs\m6\grade.py agent     # 시작: 9/17 (default-deny만)
```

`labs/m6/agent-policies.cedar`의 P1–P7 TODO를 채워라. 스키마는 `cedar/agent/schema.json`(열람 OK).

| 정책 | 규칙 | 핵심 힌트 |
|---|---|---|
| **P1** 도구 허용목록 | 에이전트는 `allowed_tools` 안의 도구만 `InvokeTool` | 문자열 Set 멤버십은 `principal.allowed_tools.contains(resource.name)` — Cedar `in`은 엔티티 계층용이니 **쓰지 마라**(검증 에러) |
| **P2** 위임 교집합 | `ReadData`는 `classification <= max_classification` **AND** `classification <= on_behalf_of.clearance` | 두 조건의 `&&` — 이게 confused-deputy를 막는 본체 |
| **P3** owner override | 대행 사용자가 *소유한* 레코드(`resource.owner == principal.on_behalf_of`)는 천장 이하면 읽기 허용 | 비소유 데이터엔 P2, 소유 데이터엔 P3 |
| **P4** forbid 가드레일 | 천장<2 에이전트는 기밀(2) 읽기 금지 | `forbid (...) when { resource.classification >= 2 && principal.max_classification < 2 }` |
| **P5** 위임깊이 cap (ASI08) | `delegation_depth > 1` 에이전트는 *모든 action* 거부 — 서브에이전트 cascade 차단 | action 제약 없는 `forbid (principal, action, resource) when { principal.delegation_depth > 1 }` |
| **P6** 홉별 천장 클램프 | 스폰 시 기록한 *스칼라* `delegated_by_max_classification`(부모 천장)으로 읽기 제한 — 중간 홉 증폭 방지. 엔티티 역참조는 dangling 시 에러→skip→fail-OPEN이라 스칼라로 | `forbid (ReadData) when { principal has delegated_by_max_classification && resource.classification > principal.delegated_by_max_classification }` |
| **P7** 출처 게이트 (fail-closed) | 그 스칼라는 optional이라 P6은 *없으면 fail-open* — depth≥1인데 부모 천장 미기록 에이전트를 *모든 action* 거부 | `forbid (principal, action, resource) when { principal.delegation_depth >= 1 && !(principal has delegated_by_max_classification) }` |

> **반증가능성(이 repo의 핵심 명제):** 17개 시나리오 중 다섯은 *일부러* P2·P3·P5·P6·P7이 **유일한 결정자**가
> 되도록 설계됐다("P2/P3/ASI08 P5/P6/P7 IS LOAD-BEARING"). 17/17를 만든 뒤, P2를 통째로 지워보라 →
> "P2 IS LOAD-BEARING"이 Allow→Deny로 *뒤집힌다*. P3·P5·P6·**P7**도 마찬가지(P7을 지우면 부모 엣지를
> *누락한* depth-1 서브에이전트가 자기 천장(2)까지 증폭해 기밀 읽기 Deny→Allow로 뒤집힌다). **뒤집히지 않으면**
> 그 정책은 죽은 코드다(테스트가 그걸 증명 못 함). 이게 "통과한다 ≠ 옳다"의 결정판 — M0 Step 3의 뮤테이션 교훈과 같은 것.

> **ASI08이 왜 새 정책인가:** 에이전트가 다른 에이전트를 *스폰*하는 멀티에이전트 시스템에서, 권한이
> 체인을 따라 무한 cascade하면 안 된다(OWASP Agentic Top 10 2025-12-09). **P5**는 *체인 길이*를 묶고
> (depth≤1 → 중간 에이전트 최대 한 명), **P6**은 스폰 시 기록한 스칼라 부모 천장으로 *중간 에이전트
> 천장*을 클램프한다. `on_behalf_of`가 휴먼 등급 floor가 되므로 — 셋이 합쳐 바운드 체인에서 **실효 천장 =
> (휴먼)∧(스폰 에이전트)∧(서브)의 최소** (*단 control plane이 스폰 속성을 진실하게 기록한다는 TCB 가정 하*),
> 즉 *어느 홉에서도 증폭되지
> 않는다*가 실제로 성립한다(단일 정수 depth만으론 불가능했던 것). 배경: [authorization-model §5](../../docs/authorization-model.md).

## Part B — OpenFGA ReBAC (목표 11/11)

```powershell
.venv\Scripts\python.exe labs\m6\grade.py rebac     # 시작: 8/11 (owner 케이스만 통과)
```

`labs/m6/model.fga`의 `define` 우변 TODO를 채워라. **타입/relation 이름은 그대로 둬라**(채점
테스트가 그 이름을 참조). 트래버설 문법: `<relationA> from <relationB>`.

| 재작성 | 규칙 | 힌트 |
|---|---|---|
| `account.can_view` / `can_transfer` | 소유자, 또는 *소유자가 위임한 에이전트* | `owner or delegate from owner` — 이게 그래프 조인(소유 관계 + 위임 관계) |
| `workload.operator` | 직접 지정 user, 또는 `owner_team` 팀의 member | `[user] or member from owner_team` |

> **payoff:** `delegate from owner` = "account의 owner를 구하고(→alice), 그 alice의 delegate를
> 구한다(→assistant)". 에이전트의 도달이 *소유자와의 관계*에서 파생된다 — 속성(ABAC)으론 깔끔히
> 표현 못 하는 것. 8/11에서 시작하는 이유: owner 자신은 이미 통과하지만, **delegate/team 트래버설이
> 비어서** 위임·팀 케이스가 실패한다. 어느 시나리오가 실패하는지 보고 거꾸로 채워라.

## Step — 졸업

```powershell
.venv\Scripts\python.exe labs\m6\grade.py           # 17/17 + 11/11 → M6 GRADUATED
```

## Step — 설계 과제 (반증가능 시나리오 직접 만들기)

종이에: **소유관계가 없는** 제3자 데이터에 대해, "에이전트는 capable하지만 대행 사용자가 등급
미달"인 시나리오를 하나 설계하라. 어떤 정책이 막아야 하나? 기대 결과는? — 그다음 `cedar/agent/
requests.json`에서 "P2 INTERSECTION GATE" 시나리오를 찾아 네 설계와 비교하라(그게 정확히 그 케이스다).

## Step — 구두 문답

1. <details><summary>confused deputy를 한 문장으로, 이 데모에서 무엇이 막는가?</summary>대리자(에이전트)가 자기 권한으로 의뢰자(사용자)가 못 할 일을 해주는 것. P2의 교집합(대행 사용자 등급도 만족해야 함)이 막는다.</details>
2. <details><summary>P2가 "교집합"인데 P3(owner override)가 그 교집합을 깨지 않나? 정직하게.</summary>깬다 — 부분적으로. 교집합은 *비소유* 데이터에만 적용되고, 사용자가 *소유한* 데이터는 에이전트 천장까지 읽힌다. 그래서 "에이전트는 사용자가 못 닿는 *비소유* 데이터엔 못 닿는다"가 정확한 주장. 이 carve-out을 문서에 안 밝히면 과장이다(이 repo는 §5에 명시).</details>
3. <details><summary>ABAC 교집합(Part A)과 ReBAC 그래프(Part B)는 같은 위임을 다르게 표현한다 — 언제 어느 쪽?</summary>한 홉 속성 비교면 ABAC가 간단. 위임 체인이 깊거나("A가 B를 대행, B가 C를 대행") 소유·멤버십 관계가 그래프를 이루면 ReBAC. 실무는 RBAC+ABAC 기본에 관계는 ReBAC 하이브리드.</details>
4. <details><summary>`delegate from owner`에서 화살표 방향은? 왜 user에 delegate를 두고 agent에 안 뒀나?</summary>account.owner→user, user.delegate→agent. 재작성은 object의 relation을 따라 *앞으로* 간다. owner(→user)에서 그 user의 delegate(→agent)로 조인하려면 delegate가 user 쪽에 있어야 한다. agent.principal로 뒀다면 역방향이라 이 재작성이 안 된다(그래서 canonical은 principal 엣지를 지웠다).</details>
5. <details><summary>왜 P4(forbid)가 현재 permit 집합에선 "죽은 코드"인가? 그래도 두는 이유?</summary>P2·P3가 이미 천장으로 캡하므로 천장<2 에이전트는 애초에 기밀 permit을 못 받는다 → forbid가 덮을 게 없다. 그래도 미래에 천장을 안 캡하는 permit이 추가되면 백스톱이 된다(belt-and-suspenders). 정직하게 "현재 중복"이라 라벨해야 한다.</details>
6. <details><summary>이 데모는 "라이브 에이전트 런타임"인가? 면접에서 어떻게 말하나?</summary>아니다 — 로컬 정책 단위테스트(authz.py의 peer)다. 라이브 클러스터 검사도, AI Gateway 통합도 아니다. "위임 *인가 정책*을 코드로 검증한 것"이라고 정확히 말해야 과장이 아니다.</details>

## 졸업 기준

- [ ] `grade.py` **17/17 + 11/11**
- [ ] P2/P3/P5/P6/P7을 각각 지우면 대응하는 "... IS LOAD-BEARING" 시나리오가 뒤집히는 걸 직접 확인(P6: 부모 천장 0 서브의 기밀 읽기, P7: 부모 미선언 서브의 기밀 증폭 — 둘 다 Deny→Allow)
- [ ] ABAC 교집합과 ReBAC 그래프가 같은 위임의 두 표현임을 설명할 수 있다
- [ ] owner-override carve-out 때문에 "교집합" 주장에 *비소유* 단서가 붙는 이유를 안다
- [ ] 구두 문답 6개를 답안 없이 말했다
- [ ] `cedar/agent/policies.cedar` · `rebac/model.fga`와 내 답을 비교했다
