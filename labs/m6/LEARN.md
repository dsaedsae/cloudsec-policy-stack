# M6 배우기 — AI 에이전트 위임 인가: Cedar 교집합 + OpenFGA 관계 그래프

## 개요

M6은 *같은 위임* 문제를 두 모델로 푼다 — **(A) Cedar ABAC 교집합**과 **(B) OpenFGA ReBAC 그래프**.
그래서 worked example도 둘이다. 각 파트에서 **완성된 한 줄을 읽고 이해** → **핵심 개념 하나를 빈칸으로
채우고** → **나머지는 직접 작성**한다. 정답 통째 베끼기가 아니라 문법을 한 계단씩 올라가는 게 목적이다.

> **핵심 규칙:** 각 파트마다 worked example **하나**, 빈칸 **하나**만 떠먹인다. 나머지 TODO(Part A의
> P1·P3·P4·P6·P7, Part B의 `can_transfer`)는 **당신이** 채워야 grade.py가 통과한다. 정답지(`cedar/agent/
> policies.cedar`, `rebac/model.fga`)는 **졸업 전 열람 금지** — 작업 파일은 `labs/m6/agent-policies.cedar`,
> `labs/m6/model.fga`다.

> 선행: **M0**(Cedar 문법)을 먼저 졸업하라. Part A는 M0의 연장이다.

---

## Part A — Cedar ABAC 교집합

### 1) 완성 예시 읽고 이해: P5 위임 깊이 cap (ASI08)

**왜 이 규칙인가:** Cedar 정책 중 가장 *단순한 골격*인데(조건 한 줄) 가장 새로운 통제다 —
에이전트가 에이전트를 스폰하는 멀티에이전트 cascade를 한 줄로 막는다.

```cedar
forbid (
    principal,        // 어떤 에이전트든 (제약 없음)
    action,           // action 제약이 *없다* — InvokeTool·ReadData 가리지 않고 모든 결정에 적용
    resource          // 어떤 자원이든
)
when { principal.delegation_depth > 1 };   // 휴먼 위 agent->agent 홉 수가 1을 넘으면
```

**문법 라인별 해설:**

- `forbid ( ... )`: 조건이 참이면 **거부(Deny)**. Cedar에서 **forbid는 항상 permit을 이긴다** — P2가
  permit을 줘도 이 forbid가 걸리면 Deny.
- `principal, action, resource`: 셋 다 변수로 두고 제약을 안 걸었다 → **모든 요청**이 후보. `action ==
  Action::"..."`로 좁히지 *않은* 게 의도다.
- **왜 action 제약이 없나:** P5는 "이 에이전트는 체인이 너무 깊어 *통째로* 신뢰 못 한다"는 *주체* 판단이다.
  도구호출이든 데이터읽기든 전부 막는 게 맞다. (대조: P6은 *읽기 등급* 판단이라 `ReadData`에만 건다 —
  통제 대상이 주체냐 자원이냐가 action 스코프를 정한다.)
- `principal.delegation_depth`: 스키마상 `Long`(schema.json L19). `0`=휴먼이 직접 조작, `1`=허용된 한 홉
  (서브에이전트), `2+`=거부.
- `> 1`: depth 2부터 거부. `>= 1`이 아니다 — depth 1(서브에이전트 한 명)은 *허용*해야 한다.
- `;`: Cedar 문의 끝 — 필수(M0에서 다룬 골격).

---

### 2) 빈칸 채우기: P2 위임 교집합 (핵심 개념 = 교집합 연산자)

이게 **confused-deputy를 막는 본체**다. 한 곳만 비워뒀다.

```cedar
permit (
    principal,
    action == Action::"ReadData",
    resource
)
when {
    resource.classification <= principal.max_classification        // 항①: 에이전트 자신의 천장
    __?__ resource.classification <= principal.on_behalf_of.clearance  // 항②: 대행 휴먼의 등급
};
```

**채워야 할 부분과 힌트:**

- 두 항이 **둘 다** 참이어야 읽기를 허용한다 — 교집합. 둘 중 하나만 만족해도 되는 *합집합*이 아니다.
- 항②의 `principal.on_behalf_of`는 `User` 엔티티 참조(schema.json L18)라 `.clearance`로 **엔티티
  역참조** → *대행하는 휴먼의 등급*을 읽는다.
- 핵심 질문: "A 그리고 B"를 뜻하는 Cedar 논리 연산자는?

**정답 공개 후 자가 검증:**

```cedar
    && resource.classification <= principal.on_behalf_of.clearance
```

`&&`(AND)다. **만약 `||`(OR)로 쓰면** "둘 중 하나만 만족해도 허용"이 돼 교집합이 합집합으로 *뒤집힌다* —
과잉권한 에이전트(max=2)가 guest(clearance=0)를 대행하면서 자기 천장만으로 기밀(2)을 읽어버려
confused-deputy 케이스가 Allow로 새고 17/17이 깨진다. 항②(`2 <= 0`이 거짓)가 *과잉권한 에이전트를 저등급
휴먼의 천장으로 끌어내리는* 자물쇠다.

---

### 3) 이제 혼자 — 나머지 정책 (P1·P3·P4·P6·P7)

`labs/m6/agent-policies.cedar`의 남은 TODO를 채워라. 스키마는 `cedar/agent/schema.json`(열람 OK).

위 P5(완성)와 P2(빈칸)에서 배운 골격으로 나머지를 직접 쓴다. 전체 `when` 블록은 일부러 안 적는다 —
어떤 속성·연산자가 들어가는지만 짚고, 조립은 당신 몫이다. 스키마 타입과 시나리오 이름은 README 표와 맞춰라.

- **P1 — 도구 허용목록:** `InvokeTool`을 `principal.allowed_tools`에 든 도구만 허용(permit).
  - `allowed_tools`는 `Set<String>`(schema.json L16). 문자열 Set 멤버십 연산자 하나면 된다 — `in`이 *아니다*.
  - 주의: Cedar `in`은 *엔티티 계층*(그룹 멤버십)용이라 String Set엔 타입 미스매치 → **검증 에러** → 시나리오가
    *한 줄도 안 찍힌다*(채점기가 평가 전에 막는다). 17/17이 아니라 0줄이 증상이면 여기다.
- **P3 — owner override(permit):** 대행 사용자가 *소유한* 레코드는 등급 사다리를 건너뛰되, *에이전트
  천장으론 여전히 캡*. 두 항의 `&&`: `resource.owner == on_behalf_of`(둘 다 `User` 엔티티 → 동일성 비교)와
  P2의 천장 항. P2(교집합)는 *비소유* 데이터에, P3는 *소유* 데이터에 — 다른 permit이다.
- **P4 — 하드 가드레일(forbid):** 천장<2 에이전트는 기밀(2)을 절대 못 읽는다. `ReadData` forbid에 두 항
  (`classification >= 2`와 `max_classification < 2`)을 `&&`. 정직하게: 지금 permit 집합에선 P2·P3가 이미
  천장으로 캡하므로 **중복(죽은 코드)**이다 — 미래 permit 대비 백스톱으로만 둔다.
- **P6 — 홉별 천장 클램프(forbid):** 서브에이전트는 스폰 시 기록한 *스칼라* `delegated_by_max_classification`
  (부모 천장)으로 읽기를 제한 — 중간 홉 증폭 금지. `ReadData` forbid, 두 항 `&&`: `has`로 그 스칼라의 *존재*
  검사 + `classification`과의 비교.
  - 비교 연산자가 함정이다: 부모 천장을 *초과*하는 것만 막아야 한다(`>`). `>=`로 쓰면 부모와 같은 등급의
    정당한 floor 읽기까지 과차단된다.
  - 주의: 엔티티 역참조(`delegated_by.max_classification`)로 바꾸지 마라 — dangling 시 정책이 에러→Cedar가
    skip→**fail-OPEN**. 스칼라를 쓰는 건 미학이 아니라 fail-closed 보증이다(§5의 실제 버그 수정).
- **P7 — 출처 게이트(forbid, fail-closed):** P6의 스칼라는 optional이라, *누락한* depth≥1 에이전트는 P6의
  `has`가 거짓 → P6 미발동 → fail-open. P7이 그 구멍을 닫는다. P5처럼 **action 제약 없음**, 두 항 `&&`:
  `delegation_depth >= 1`과 그 스칼라가 *없다*는 조건(`!(... has ...)`). **존재**를 강제하는 게 P7,
  **값**으로 클램프하는 게 P6.

```powershell
.venv\Scripts\python.exe labs\m6\grade.py agent     # 시작 9/17 → 목표 17/17
```

---

## Part B — OpenFGA ReBAC 그래프

ReBAC는 *속성*이 아니라 *관계 그래프*에서 권한을 도출한다. 트래버설 문법:
`<relationA> from <relationB>` = "object의 relationB가 가리키는 대상으로 한 홉 가서, 거기서 relationA를 본다".

### 1) 완성 예시 읽고 이해: workload.operator (팀 멤버십 조인)

```fga
type workload
  relations
    define owner_team: [team]                      # 이 workload를 소유한 팀 (직접 지정)
    # operator = 직접 지정된 user, 또는 owner_team 팀의 member
    define operator: [user] or member from owner_team
    define can_admin: operator                     # admin은 operator로 재작성(별칭)
```

**문법 분해:**

- `define operator: [user] or member from owner_team`
  - `[user]`: **직접 지정** 가능 타입. 튜플로 `user:X --operator--> workload:Y`를 박으면 그 user가 operator.
  - `or`: 둘 중 하나면 성립(합집합). ReBAC의 권한 결합.
  - `member from owner_team`: **그래프 조인**. workload의 `owner_team`(→`team:payments`)으로 한 홉 가서,
    그 팀의 `member`(→`user:bob`)를 본다. 즉 *팀 멤버는 자동으로 operator*.
- `define can_admin: operator`: 우변이 *다른 relation 하나*면 별칭 재작성. operator인 자는 can_admin.

**왜 이렇게 푸나:** "이 워크로드를 소유한 *팀*의 *멤버*"는 두 관계를 잇는 그래프다 —
`workload.owner_team` + `team.member`. 속성(ABAC) 하나론 깔끔히 못 푼다. `from`이 그 한 홉이다.

---

### 2) 빈칸 채우기: account.can_view (핵심 개념 = 위임 그래프 조인)

```fga
type account
  relations
    define owner: [user]
    # 소유자, 또는 *소유자가 위임한 에이전트*가 볼 수 있다
    define can_view: owner __?__ delegate from owner
```

**채워야 할 부분과 힌트:**

- `owner`(계정 소유자 본인)와 `delegate from owner`(소유자가 위임한 에이전트) — **둘 중 하나면** 허용.
- `delegate from owner`를 acct-alice에 풀면: 그 `owner`(→`user:alice`)로 가서, alice의
  `delegate`(→`agent:assistant`)를 본다. **위임 엣지는 user 쪽**(`user.delegate`)에 있어야 이 트래버설이
  성립한다(`store.fga.yaml`의 튜플도 `user:alice --delegate--> agent:assistant`).
- 핵심 질문: 두 관계를 "둘 중 하나면"으로 잇는 OpenFGA 연산자는?

**정답 공개 후 자가 검증:**

```fga
    define can_view: owner or delegate from owner
```

`or`다. 이게 ReBAC의 payoff — 에이전트의 도달이 *소유자와의 관계*에서 파생된다(에이전트가 들고 있는 속성이
아니라). agent:assistant는 alice의 계정만 보고, **bob의 계정엔 엣지가 없어** 못 본다(cross-owner 차단).

> **8/11에서 시작하는 이유:** `define can_view: owner`만 둬도 모델은 문법상 유효하다 — 그래서 0이 아니라
> 8에서 시작한다. 트래버설이 비면 *틀린 답*이 아니라 *덜 허용하는 답*이라, deny 기대 케이스는 우연히 맞고
> allow 기대 케이스(agent:assistant→acct-alice의 can_view=true)만 *false*로 찍힌다. 그 줄이 정확히 빈
> 트래버설을 가리킨다 — 거꾸로 채워라.

---

### 3) 이제 혼자 — 나머지 재작성 (`can_transfer`)

`labs/m6/model.fga`의 남은 TODO를 채워라. **타입·relation 이름은 그대로 둬라**(채점 테스트가 그 이름을 참조).

- **`account.can_transfer`:** `can_view`와 *같은 규칙*이다 — 소유자, 또는 소유자가 위임한 에이전트.
  위 빈칸에서 쓴 것을 그대로 적용하면 된다.
- (`account.owner`, `workload.owner_team`, `workload.can_admin`, `user.delegate` 등 직접 지정/별칭 줄은
  이미 채워져 있다. 당신이 손댈 우변은 `can_view`·`can_transfer`·`operator` 세 개뿐이다.)

```powershell
.venv\Scripts\python.exe labs\m6\grade.py rebac     # 시작 8/11 → 목표 11/11 (Docker 필요)
```

> Docker Desktop이 없으면 Part B는 채점 SKIP(졸업 표시 안 됨)이다 — Part A만 17/17이면 절반만 통과.

---

## 다음 — 졸업과 break-and-fix

```powershell
.venv\Scripts\python.exe labs\m6\grade.py           # 17/17 + 11/11 → M6 GRADUATED
```

17/17 + 11/11을 만든 *뒤*, 이번엔 **일부러 깨 보고** 예측과 맞춰라 (M0 Step 3 뮤테이션 교훈의 결정판):

- **Part A:** `agent-policies.cedar`에서 P2(permit)를 통째로 지워라 → "P2 IS LOAD-BEARING"의 정당한 읽기가
  permit을 잃고 **Allow→Deny**로 뒤집힌다. P6/P7(forbid) 삭제는 반대 방향 — 부모 천장 0/미선언 서브가
  기밀로 증폭해 **Deny→Allow**. **뒤집히지 않으면 그 정책은 죽은 코드다.**
- **Part B:** `can_view`를 `owner or delegate from owner` → `owner`로 되돌려 `grade.py rebac`을 돌려라 →
  agent:assistant 케이스 2줄이 true→false로 떨어진다. 위임 권한이 *그래프 조인 한 줄*에 전부 실려 있다는 증거.

정답지(`cedar/agent/policies.cedar`, `rebac/model.fga`)는 **이 단계를 마친 뒤** 내 답과 비교하라.
배경: [authorization-model §4–§5](../../docs/authorization-model.md).
