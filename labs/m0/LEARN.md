# M0 — 배우기 모드: 빈 파일에서 Cedar 정책 재구현하기

Cedar로 작성한 인가 정책을 배운다. 먼저 완성된 한 규칙을 읽고 이해하고 → 비슷한 예시를 반은 공백으로 채우고 → 나머지는 직접 작성한다.

> **핵심 규칙:** 우리는 DSL의 한 **구체적 사례**를 완전히 보여주고(R1), 비슷한 **두 사례**를 반 공백으로(R2·R3 — 속성 idiom 하나, 역할 idiom 하나) 제시한다. **나머지 R4, E1은 당신이 직접 작성**해야 한다. 그래야 실제 스켈레톤 채점에서 정책을 이해하고 쓸 수 있다.

---

## 1) 완성 예시 — 소유자 검증 (R1)

```cedar
permit (
    principal,
    action == Action::"ViewAccount",
    resource
)
when { resource.owner == principal };
```

**문법 라인별 해설:**

- `permit ( ... )`: 이 조건이 만족되면 **허용(Allow)** 결정을 내린다
- `principal, action == Action::"ViewAccount", resource`: PARC 모델의 3가지 핵심 = 누가(principal), 무엇을(action), 어디에(resource) 대해
  - `principal`: 요청자(예: User::"alice")를 변수로 두고 조건에서 검증
  - `action == Action::"ViewAccount"`: 스키마에 정의된 액션을 정확히 매치 (다른 액션은 이 정책 적용 안 됨)
  - `resource`: 대상(예: Account::"savings")을 변수로 두고 조건에서 검증
- `when { resource.owner == principal }`: 조건식 — **오직 이 리소스의 소유자만** 조회 허용
  - `resource.owner`: Account 스키마에서 owner 속성 읽기
  - `== principal`: 호출자 ID와 비교 — 엔티티 타입이 같아야 함 (User와 Account.owner 모두 User 타입)
  - 피연산자 순서(`resource.owner == principal` vs `principal == resource.owner`)는 `==`가 대칭이므로 스타일 차이일 뿐 의미는 동일
- `;`: Cedar 정책의 끝 — 필수

**핵심 구분 — scope vs when (두 개의 매칭 단계):**

| 위치 | 역할 | 이 예시에서 |
|---|---|---|
| **scope** `( principal, action == ..., resource )` | 이 정책이 **어떤 요청에 적용되나** (PARC 모양 필터) | action이 `ViewAccount`인 요청만 골라낸다 |
| **when** `{ ... }` | scope가 걸린 요청에 대해 **추가로 참이어야 할 조건** | 그 요청에서 owner가 호출자와 같은가 |

- scope의 `principal`/`resource`는 **타입 제약 없이 비워둔** 형태 — "누구든/무엇이든"이다. 좁히는 일은 `when`이 한다.
- action만 `== Action::"ViewAccount"`로 **고정**돼 있다 — 다른 액션(Transfer 등) 요청은 scope에서 이미 탈락해 `when`까지 가지도 않는다. **action을 비워두면 이 정책이 모든 액션에 적용된다**(과잉 허용의 시작 — Step 4 EXT2가 잡는 결함).
- `==`가 비교하는 두 값의 **엔티티 타입이 일치**해야 validation을 통과한다: `resource.owner`는 schema상 `User` 타입(Account의 owner 속성), `principal`도 `User` → OK. 만약 `resource.owner == resource`로 잘못 쓰면 `User == Account`라 타입 불일치로 validation에서 멈춘다.

---

## 2) 빈칸 채우기 — 이체 한도 검증 (R2, 일부 공백)

```cedar
permit (
    principal,
    action == Action::"Transfer",
    resource
)
when {
    resource.owner == principal
    && context.amount > 0
    && context.amount __?__ principal.transferLimit
};
```

**채워야 할 부분과 힌트:**

- 금액이 **한도 이하**여야 Transfer를 허용한다
- `context.amount`는 API 요청 본문에서 나온 이체 금액
- `principal.transferLimit`는 고객의 개인 한도(schema에 정의된 User 속성)
- 정확히 한도만큼(1000) 이체도 허용해야 한다 — 어떤 비교 연산자?

**정답 공개 후 자가 검증:**

```cedar
&& context.amount <= principal.transferLimit
```

`<` 아니라 `<=`를 써야 경계 케이스(정확히 1000)가 통과한다(경계값 테스트의 중요성).

---

## 2-2) 빈칸 채우기 — 역할 멤버십 (R3, 다른 idiom)

R1·R2는 **속성**(owner, amount)으로 판정하는 ABAC였다. R3는 **역할**로 판정하는 RBAC다 — 다른 문법을 쓴다.

```cedar
permit (
    principal __?__ Role::"auditor",
    action == Action::"ViewAuditLog",
    resource
);
```

**채워야 할 부분과 힌트:**

- "auditor **역할 멤버**만 감사로그 조회" — 속성 비교(`==`)가 아니라 **그룹 소속** 판정이다
- schema에서 `User`는 `memberOfTypes: ["Role"]` — 즉 User 엔티티가 Role의 자식이 될 수 있다(엔티티 계층)
- `==`(정확히 그 엔티티인가)와 다른, **계층 소속**을 묻는 키워드가 필요하다
- 이 정책엔 `when`이 **없다** — scope의 역할 체크만으로 충분하므로 끝에 바로 `;`

**정답 공개 후 자가 검증:**

```cedar
permit (
    principal in Role::"auditor",
    ...
);
```

- `in`은 "principal이 `Role::"auditor"`의 (직접/간접) 멤버인가"를 묻는다 — `==`였다면 "principal이 *바로 그 Role 엔티티 자체*인가"라 절대 참이 안 된다(User는 Role이 아니므로).
- scope에서 바로 역할을 거르므로 `when` 블록이 통째로 생략됐다 — Cedar에서 `when`은 **선택**이다(조건이 없으면 안 쓴다).

---

## 3) 이제 혼자 — 나머지 규칙들 (R4, E1)

> R3는 2-2)에서 정답을 봤다 — 그래도 빈칸 정답을 **그대로 `policies.cedar`에 옮겨 적고** 채점기를 돌려야 R3 시나리오가 PASS로 바뀐다(읽기≠적용).

**R4 — 동결 계좌 금지:**
- forbid를 사용하는 첫 정책 — permit과 forbid가 모두 매치되면 **forbid가 이긴다**
- 언제 이체를 **절대 금지**할까? → 계좌가 frozen인 경우
- 힌트: `resource.frozen == true` 를 when에

**E1 — 확장: 감사역의 조회 전용 권한:**
- 기존 R1은 "소유자만 자신의 계좌 조회" → R3는 "감사역만 감사로그 조회"
- 새 요구: "감사역도 **모든 고객의 일반 계좌를 조회**할 수 있어야 한다" — 단, **이체는 절대 불가**
- 이미 작성한 R1, R2, R4는 건드리지 말 것
- 각 permit은 독립적으로 평가되어 OR로 결합된다(매칭되는 permit이 하나라도 있고 forbid가 없으면 Allow)
- 힌트: R3 문법을 기반으로, ViewAccount 액션만, role 체크로

---

## 흔한 첫 실수 (채점 전에 이것부터 의심)

세 가지가 처음 작성의 거의 전부다. 증상으로 역추적하라.

| 실수 | 잘못된 코드 | 증상 / 채점기가 뭐라 하나 |
|---|---|---|
| **`;` 누락** | `when { ... }` 뒤에 세미콜론 없음 (특히 여러 정책을 이어 쓸 때 앞 정책 끝) | 파싱 에러로 멈춤 — `grade.py`가 **세미콜론 힌트**까지 찍어준다(`authz.py`의 hint 분기). 시나리오 평가까지 가지도 못한다 |
| **action에 `==` 빠짐** | `action Action::"Transfer"` (또는 `action,`로 비워둠) | `==` 없으면 파싱 실패; 비워두면 **모든 액션에 적용**돼 과잉 허용 — Step 4 EXT2가 Deny 기대를 Allow로 뒤집으며 잡는다 |
| **조건을 scope에 씀** | `( principal, action == ..., resource, resource.owner == principal )` ← 조건이 scope 안 | scope에는 PARC 3칸만 온다. 조건은 **반드시 `when {}`** 안. scope에 식을 넣으면 파싱 에러 |

추가로 자주 나오는 validation 단계 실수(파싱은 통과하나 스키마 정적검증에서 멈춤):

- **principal/resource 혼동:** `principal.owner`나 `resource.transferLimit` → ``attribute ... not found``. owner는 **Account**(resource) 속성, transferLimit은 **User**(principal) 속성이다(`schema.json` 확인). 자세한 진단은 README의 "schema validation" 절.
- **`in` 자리에 `==`:** R3에서 `principal == Role::"auditor"`로 쓰면 파싱은 되지만 User는 Role이 아니라 **항상 거짓** → auditor 시나리오가 조용히 FAIL. 역할 소속은 `in`(2-2 참조).

