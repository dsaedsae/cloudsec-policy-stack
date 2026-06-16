# M6 — 프런티어: AI 에이전트 위임 인가 (ABAC 교집합 + ReBAC)

<div class="lab-pills">
<span class="lab-progress">모듈 7 / 7</span> · <span class="lab-badge">스택 Cedar+OpenFGA</span> · <span class="lab-badge">소요 ~2–4h</span> · <span class="lab-badge no-cluster">클러스터 불필요 · Part B Docker</span> · <span class="lab-badge">비용 $0 로컬</span>
</div>

> **준비:** `.venv`(requirements-dev) — [SETUP](../SETUP.md). **Part B(ReBAC)는 Docker Desktop 필요**
> (없으면 Part A만 채점, 졸업 표시 안 됨).

**미션:** 같은 "위임" 문제를 두 모델로 구현한다 — **(A) Cedar ABAC 교집합**으로 confused-deputy를
막고, **(B) OpenFGA ReBAC** 관계 그래프로 같은 위임을 표현한다. 클러스터 불필요(python + docker).

> **학습 성과 (면접에서 말할 수 있는 것):** AI 에이전트 위임을 ABAC 교집합(+ASI08 위임깊이 cap·홉별 클램프·출처 게이트)과 ReBAC 그래프로 구현해 confused-deputy를 막고, 이것이 라이브 에이전트 런타임이 아니라 위임 *인가 정책*의 단위테스트임을 정직히 말할 수 있다. → [캡스톤 M6](../capstone.md)

**편집 파일:** `labs/m6/agent-policies.cedar` (Part A), `labs/m6/model.fga` (Part B).

> **Cedar·fga 문법이 막막하면 → [배우기 모드: LEARN.md](LEARN.md).** 파트별 완성 예시 1개(주석)를 읽고 → 1칸을 채우고 → 나머지는 직접.

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

### 정책 한 줄씩 — 실제 `policies.cedar`를 따라 (정답 보기 전에 *왜*를 잡아라)

- **P1** `principal.allowed_tools.contains(resource.name)` — `allowed_tools`는 스키마상 `Set<String>`
  (schema.json L16), `resource.name`은 `Tool`의 String 속성. **왜 `.contains()`이고 `in`이 아닌가:**
  Cedar `in`은 *엔티티 계층*(그룹 멤버십) 연산자라 String Set엔 타입이 안 맞아 **검증 에러**(`grade.py`가
  평가 전 `validate_policies`로 잡는다 — authz.py L31). 문자열 멤버십은 항상 `.contains()`.
- **P2** `resource.classification <= principal.max_classification && resource.classification <= principal.on_behalf_of.clearance`
  — 두 부등식의 `&&`가 confused-deputy 본체다. 첫 항은 *에이전트 천장*, 둘째 항은 `on_behalf_of`로
  **엔티티 역참조**해 *대행 휴먼의 등급*. agent-overpriv(max=2)가 guest(clearance=0)를 대행해 기밀(2)을
  읽으려 하면 — 첫 항은 통과(2≤2)하지만 둘째 항 `2 <= 0`이 거짓 → permit 안 떨어짐 → default-deny.
  *과잉권한 에이전트라도 저등급 휴먼의 천장으로 끌려내려간다.*
- **P3** `resource.owner == principal.on_behalf_of && resource.classification <= principal.max_classification`
  — owner override. `resource.owner`와 `on_behalf_of`는 둘 다 `User` 엔티티라 `==`는 *엔티티 동일성*
  비교(uid 일치). P2의 휴먼-등급 floor를 *건너뛰지만* 에이전트 천장은 여전히 캡(둘째 항). 그래서 정확한
  주장은 "에이전트는 휴먼이 못 닿는 *비소유* 데이터엔 못 닿는다" — 소유 데이터엔 carve-out이 있다(§5에 명시).
- **P4** forbid. `forbid`는 Cedar에서 *항상* permit을 이긴다. 현재 permit 집합에선 P2·P3가 이미 천장으로
  캡하므로 죽은 코드다(구두 5번). 백스톱으로만 둔다.
- **P5** `forbid (principal, action, resource) when { principal.delegation_depth > 1 }` — action 제약이
  *없다*. 그래서 InvokeTool·ReadData 가리지 않고 depth≥2 에이전트의 **모든 결정**을 거부한다. P5가 체인을
  depth≤1로 묶기 때문에 — 중간 에이전트는 항상 0명 또는 1명 — P6의 *단일* `delegated_by` 스칼라로 체인
  전체를 커버할 수 있다(Cedar엔 재귀가 없어 가변 길이 체인은 애초에 표현 불가).
- **P6** `principal has delegated_by_max_classification && resource.classification > principal.delegated_by_max_classification`
  → forbid. `has`는 optional 속성의 *존재* 검사. agent-sub-clamped는 자기 천장 max=2지만 부모 천장이
  스칼라 0으로 기록돼 → 기밀(2) 읽기에서 `2 > 0`이 참 → forbid. P2/P3가 permit을 줘도 forbid가 이긴다.
- **P7** `principal.delegation_depth >= 1 && !(principal has delegated_by_max_classification)` → forbid,
  action 제약 없음. P6의 스칼라는 *optional*이라 — 안 적어내면 P6의 `has`가 거짓 → P6이 발동 안 함 →
  fail-open. P7이 그 구멍을 닫는다: depth≥1인데 스칼라가 없는 에이전트(agent-sub-orphan)는 *모든 action*
  거부. **존재**를 강제하는 게 P7, **값**으로 클램프하는 게 P6.

### 흔한 실수와 정확한 증상 (실제 출력 → 고침)

- **P1에 `in`을 썼다** → `schema validation: ERRORS`가 뜨고 시나리오 줄이 **한 줄도 안 찍힌다**(authz.py는
  검증 실패 시 `return 1`로 평가를 *건너뛴다*). String Set엔 `in`이 타입 미스매치라 *타입* 검증 에러지
  parse 에러가 아니다 — 세미콜론 힌트는 안 뜬다. 17/17이 아니라 **0줄**이 증상. → `.contains()`로 교체.
- **세미콜론 누락.** Cedar 문은 마지막 `}` 다음 `;`로 끝난다. 빠뜨리면 `parse error`가 나고, 이때만
  채점기가 세미콜론 힌트를 찍는다(authz.py L38–41은 parse류 에러에만 그 힌트를 건다) — 문법 골격은 M0.
- **P2를 `||`로 썼다.** `&&` 대신 `||`면 "둘 중 하나만 만족해도 허용"이 돼 교집합이 *합집합*으로 뒤집힌다 →
  agent-overpriv가 자기 천장만으로 기밀을 읽어 confused-deputy 케이스가 Allow로 새고 17/17이 깨진다.
- **P6을 `>=`로 썼다.** `resource.classification >= delegated_by_max_classification`이면 부모 천장과
  *같은* 등급까지 막아버려 정당한 floor 읽기(agent-sub-clamped의 public 읽기, 0 >= 0)가 Deny로 과차단된다.
  올바른 비교는 `>`(부모 천장을 *초과*하는 것만 금지).
- **P6/P7을 엔티티 역참조로 바꿨다.** "더 깔끔해 보여서" `delegated_by.max_classification`처럼 짜면 —
  그게 바로 §5가 기록한 *실제 버그*다: 참조가 dangling이면 정책이 에러나고 Cedar가 그 forbid를 *건너뛰어*
  fail-open한다. 스칼라를 쓰는 건 미학이 아니라 fail-closed 보증이다.

### Break-and-fix 뮤테이션 (predict → break → confirm)

17/17을 만든 *뒤*에 `agent-policies.cedar`에서 P6·P7을 직접 깨 보고 예측과 맞춰라(P2 `||` 뮤테이션은
위 흔한 실수 참조). 두 뮤테이션 다 *자기 천장으로의 증폭*이라 fail-open의 두 경로를 보여준다.

1. **P6 삭제.** 예측: agent-sub-clamped(자기 천장 2, 부모 천장 스칼라 0)의 *기밀* 읽기가 클램프를 잃고
   자기 천장 2까지 증폭 → Deny→**Allow**. 확인: "P6 IS LOAD-BEARING" 줄이 뒤집힌다. (단 "chain clamp still
   allows the floor"의 public 읽기는 그대로 Allow — P6은 floor를 안 건드린다.)
2. **P7 삭제.** 예측: agent-sub-orphan(depth=1, 스칼라 *누락*)이 P6의 `has`-게이트를 못 만나 통과 →
   자기 천장 2로 기밀 증폭 → Deny→**Allow**. 확인: "P7 IS LOAD-BEARING (fail-closed)" 줄이 뒤집힌다.
   P6 삭제는 *값* 클램프를, P7 삭제는 *존재* 게이트를 잃는 것 — 같은 증폭을 닫는 두 자물쇠다.

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

> **`from`의 방향을 정확히:** `<relationA> from <relationB>`는 *object의* relationB가 가리키는 대상으로
> 한 홉 가서, 거기서 relationA를 평가한다. `delegate from owner`를 acct-alice에 대고 풀면 — acct-alice의
> `owner`(→user:alice)로 가서, user:alice의 `delegate`(→agent:assistant)를 본다. 그래서 위임 엣지는
> **user 쪽**(`user.delegate`)에 있어야 한다(store.fga.yaml의 튜플도 `user:alice --delegate--> agent:assistant`).
> 만약 엣지를 agent 쪽(`agent.principal`)에 뒀다면 트래버설이 *역방향*이라 이 재작성이 성립 안 한다 —
> canonical model이 `type agent`를 relation 없이 빈 채로 두는 이유다(구두 4번).

> **트래버설이 비면 왜 *틀린 답*이 아니라 *적은 답*인가:** `define can_view: owner`만 두면 모델은
> 문법상 유효하다 — 그래서 0/11이 아니라 8/11에서 시작한다. 통과하는 8개 중 *진짜* owner 통과는
> alice/acct-alice 두 줄(can_view·can_transfer)뿐이고, 나머지 6개는 *덜 허용*하는 모델이 deny 기대
> 케이스를 우연히 맞힌 것이다(틀린 게 아니라 아직 안 채운 것). ReBAC 실수는 보통 "에러"가 아니라 "조용히
> *덜* 허용"으로 난다 — agent:assistant→acct-alice의 `can_view`가 *false*(기대 true)로 찍히는 줄이
> 정확히 비어 있는 트래버설을 가리킨다. 거꾸로 채워라.

> **break-and-fix:** 11/11을 만든 뒤 `can_view`를 `owner or delegate from owner` → `owner`로 되돌려
> `grade.py rebac`(Docker 필요)을 돌려라. agent:assistant 케이스 2줄(can_view/can_transfer)이
> true→**false**로 떨어진다. 위임 권한이 *그래프 조인 한 줄*에 전부 실려 있다는 증거다.

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
7. <details><summary>P6은 왜 엔티티 참조 대신 *스칼라*인가? 어떤 fail 모드를 닫나?</summary>초기 버전은 `delegated_by`를 Agent 엔티티로 두고 그 천장을 역참조했다. 참조가 dangling(엔티티 미존재)이면 정책 평가가 *에러*나고, Cedar는 에러난 forbid를 *건너뛴다* → 클램프가 fail-OPEN되어 서브가 자기 천장까지 증폭했다. 스칼라(Long)는 dangle할 수 없으니 그 에러 경로 자체가 사라진다 — fail-closed by construction. 핵심: "fail-open이냐 fail-closed냐"가 정책 *문법 선택*에서 갈린다는 것.</details>
8. <details><summary>P5(depth≤1) 덕분에 P6이 스칼라 *하나*면 충분하다는 논증을 펴 보라.</summary>임의 길이 체인이면 각 홉의 부모 천장을 다 추적해야 하는데 Cedar엔 재귀/리스트 폴드가 없어 표현 불가다. P5가 depth>1을 전부 거부하므로 합법 체인은 human→agent(0)→sub(1)뿐 — 중간 에이전트가 최대 한 명이다. 그 한 명의 천장만 sub에 스칼라로 박으면 체인 전체가 커버된다. 즉 P5는 P6을 "유한·고정 길이"로 만들어 *표현 가능하게* 하는 전제다. 둘은 독립 통제가 아니라 짝이다.</details>
9. <details><summary>이 모델이 *안* 막는 것 하나를 정확히 말하라(과장 금지).</summary>자식의 `on_behalf_of`를 부모의 것과 *대조하지 않는다*. guest(0)를 대행하는 부모가, bob(2)을 대행한다고 *선언한* 자식을 스폰하면 그 자식은 기밀을 읽을 수 있다(확인됨). 휴먼-등급 floor는 자식이 선언한 on_behalf_of 기준이지 체인의 진짜 최저 휴먼이 아니다 — 이건 control plane이 속성을 진실하게 기록한다는 TCB 가정에 들어간다. 정책은 입력의 진실성을 검증하지 않는다(§5의 "모델이 안 하는 것").</details>
10. <details><summary>P5는 action 제약이 없는데 P6은 `ReadData`에만 건다 — 왜 비대칭인가?</summary>P5/P7은 "이 에이전트는 신뢰 못 한다"(체인이 너무 깊다 / 출처 미기록)는 *주체* 판단이라 도구호출이든 읽기든 전부 거부하는 게 맞다. P6은 "이 *읽기*가 부모 천장을 초과하나"라는 *자원 등급* 판단이라 ReadData에만 의미가 있다(InvokeTool엔 classification 비교 대상이 없다). 통제의 *대상*이 주체냐 자원이냐가 action 스코프를 정한다.</details>

> **실세계 연결:** confused-deputy는 OWASP Agentic의 **ASI03**(Identity & Privilege Abuse)이고, 위임
> 연쇄는 **ASI08**(Cascading Failures)이다(2025-12-09). 클라우드에서 같은 클래스의 대표 사례가 AWS의
> **cross-account `confused deputy`** — 그래서 IAM은 `aws:SourceArn`/`sts:ExternalId` *Condition*으로
> "누구를 *대행해* 호출하는가"를 묶는다. P2의 `on_behalf_of` 교집합이 정확히 같은 셈법(대리자 권한 ∧
> 의뢰자 권한)을 Cedar로 표현한 것이다. 또 P6/P7의 fail-open→fail-closed 전환은 일반적 인가 결함 패턴
> **CWE-636 *Not Failing Securely*** 의 교과서 사례다(에러 시 *건너뛰어* 허용으로 새는 것).

## 더 깊이 (1차 출처)

- OWASP, *Top 10 for Agentic Applications* (2025-12-09; ASI02 Tool Misuse · ASI03 Identity & Privilege
  Abuse · ASI08 Cascading Failures) — <https://genai.owasp.org/>
- OWASP, *Non-Human Identities Top 10* (2025) — <https://owasp.org/www-project-non-human-identities-top-10/>
- Google, *Zanzibar: Google's Consistent, Global Authorization System* (ReBAC 기원, `from` 트래버설의
  원형 "tupleset rewrite") — <https://research.google/pubs/pub48190/>
- OpenFGA *Modeling* 문서 (CNCF; `X from Y` = tuple-to-userset) — <https://openfga.dev/docs/modeling>
- Cedar 정책 언어 레퍼런스 (`in` = 엔티티 계층 · Set `.contains()` · forbid 우선) —
  <https://docs.cedarpolicy.com/>
- NIST SP 800-207, *Zero Trust Architecture* (Tenet 4 동적 정책 · Tenet 6 매 접근 인가) —
  <https://csrc.nist.gov/pubs/sp/800/207/final>
- MITRE **CWE-636** *Not Failing Securely* (fail-open 결함 — P6/P7이 닫는 클래스) —
  <https://cwe.mitre.org/data/definitions/636.html>

## 졸업 기준

- [ ] `grade.py` **17/17 + 11/11**
- [ ] P2/P3/P5/P6/P7을 각각 지우면 대응하는 "... IS LOAD-BEARING" 시나리오가 뒤집히는 걸 직접 확인(P6: 부모 천장 0 서브의 기밀 읽기, P7: 부모 미선언 서브의 기밀 증폭 — 둘 다 Deny→Allow)
- [ ] ABAC 교집합과 ReBAC 그래프가 같은 위임의 두 표현임을 설명할 수 있다
- [ ] owner-override carve-out 때문에 "교집합" 주장에 *비소유* 단서가 붙는 이유를 안다
- [ ] 구두 문답 6개를 답안 없이 말했다
- [ ] `cedar/agent/policies.cedar` · `rebac/model.fga`와 내 답을 비교했다
