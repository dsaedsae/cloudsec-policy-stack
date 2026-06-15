# M0 — 배우기 모드: 빈 파일에서 Cedar 정책 재구현하기

Cedar로 작성한 인가 정책을 배운다. 먼저 완성된 한 규칙을 읽고 이해하고 → 비슷한 예시를 반은 공백으로 채우고 → 나머지는 직접 작성한다.

> **핵심 규칙:** 우리는 DSL의 한 **구체적 사례**를 완전히 보여주고(R1), 비슷한 **두 번째 사례**를 반 공백으로(R2) 제시한다. **나머지 R3, R4, E1은 당신이 직접 작성**해야 한다. 그래야 실제 스켈레톤 채점에서 정책을 이해하고 쓸 수 있다.

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

## 3) 이제 혼자 — 나머지 규칙들 (R3, R4, E1)

**R3 — 감사역 권한:**
- ViewAuditLog 액션을 누가 할 수 있는가? → **Role::"auditor" 멤버만**
- 힌트: Cedar에서 역할 멤버십은 `principal in Role::"name"` 문법
- 이 정책은 when 조건이 필요 없다 (role 체크만으로 충분)

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

