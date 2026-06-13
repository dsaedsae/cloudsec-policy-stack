# M0 — 인가 as-code: Cedar 정책을 빈 파일에서 재구현

[모듈 1 / 7]{ .lab-progress } · [스택 Cedar]{ .lab-badge } · [소요 ~3–6h]{ .lab-badge } · [클러스터 불필요]{ .lab-badge .no-cluster } · [비용 $0 로컬]{ .lab-badge }

> **준비(한 번만):** 클론엔 `.venv`가 없다 → `python -m venv .venv` 후
> `.venv\Scripts\python.exe -m pip install -r requirements-dev.txt`. 자세히는 [SETUP](../SETUP.md).

**미션:** 핀테크 데모의 인가 정책을 **스펙만 보고** 직접 작성해 채점기 11/11을 달성한다.
클러스터 불필요 — 노트북에서 python만으로 한다.

**편집하는 파일은 단 하나:** [`labs/m0/policies.cedar`](policies.cedar).
`cedar/policies.cedar`(정답지)는 졸업 전 열람 금지.

---

## Step 0 — 베이스라인 확인 (5분)

```powershell
# repo 루트에서 (.venv의 python 사용)
.venv\Scripts\python.exe cedar\authz.py        # 정답 정책의 8/8 — 목표 상태를 눈으로 확인
.venv\Scripts\python.exe labs\m0\grade.py      # 내 (빈) 정책의 채점 — 5/8부터 시작한다
```

> **첫 교훈이 바로 여기 있다:** 정책이 *하나도 없는데* 5/8이 통과한다. Cedar는 **default-deny** —
> permit이 없으면 전부 Deny이므로, "Deny 기대" 시나리오 5개는 공짜로 맞는다. 즉 **Deny 통과는
> 정책이 옳다는 증거가 아니다.** 이 함정은 Step 3에서 다시 만난다.

## Step 1 — 읽기 (30–60분)

- [`docs/01-authz-no-cluster.md`](../../docs/01-authz-no-cluster.md) — 이 데모의 인가 레이어 개요
- [`docs/authorization-model.md`](../../docs/authorization-model.md) §1–§3 — RBAC/ABAC/지속평가 지형
- Cedar 공식 튜토리얼 (<https://www.cedarpolicy.com/>) — 문법 감 잡기
- **`cedar/schema.json`은 열람 OK** — 스키마는 스펙의 일부다(엔티티 타입·속성·액션 정의).
  `cedar/entities.json`도 열람 OK(테스트 데이터). **`cedar/policies.cedar`만 보지 마라.**

### 문법 치트시트 (언어를 가르치는 것이지 답이 아니다)

```cedar
// 기본 골격 — permit(허용) / forbid(금지), 조건은 when 절에:
permit ( principal, action == Action::"X", resource )
when { /* 조건식 */ };

// 자주 쓰는 조건식:
//   principal == resource.owner          엔티티 참조 비교
//   principal in Role::"name"            역할(부모 그룹) 멤버십
//   context.amount > 0                   컨텍스트 값
//   resource.frozen == true              불리언 속성
//   && / ||                              결합
// forbid는 어떤 permit보다 우선한다 (explicit deny wins).
```

## Step 2 — 재구현: 스펙 → 정책 (핵심, 1–3시간)

은행의 인가 요구사항(스펙). 이걸 `labs/m0/policies.cedar`에 Cedar로 옮겨라:

| # | 요구사항 |
|---|---|
| **R1** | 계좌 조회(`ViewAccount`)는 **그 계좌의 소유자만** 할 수 있다 |
| **R2** | 이체(`Transfer`)는 소유자이면서, 금액이 **양수**이고, 본인의 **transferLimit 이하**일 때만 |
| **R3** | 감사로그 조회(`ViewAuditLog`)는 **auditor 역할** 멤버만 |
| **R4** | **동결(frozen) 계좌의 이체는 무조건 금지** — 다른 어떤 허용보다 우선 |

```powershell
.venv\Scripts\python.exe labs\m0\grade.py        # 반복: 작성 → 채점 → 8/8까지
.venv\Scripts\python.exe labs\m0\grade.py --hint # 막히면: FAIL 행마다 어느 요건인지 넛지(정답 아님)
```

채점기는 시나리오별 expect/actual을 보여준다. 틀리면 **왜 그 시나리오가 그 결과를 냈는지**
정책을 다시 읽어라 — 그 인과 추적이 학습의 본체다. (`--hint`는 *어느 요건*인지만 알려주지 답은 안 준다.)

<details><summary>첫 한 줄이 막히면: R1 완성 예시 (R2~R4·E1은 직접)</summary>

R1을 그대로 옮기면 이렇게 된다 — scope 3칸(principal, action ==, resource) + `when` 블록 + 끝에 `;`:

```cedar
permit ( principal, action == Action::"ViewAccount", resource )
when { principal == resource.owner };
```

이걸 `policies.cedar`에 넣고 채점하면 `owner views own account`가 PASS로 바뀐다.
**문법 함정 3가지:** ① 모든 문장은 `;`로 끝난다 ② action 앞에 반드시 `==` ③ 조건은 scope가 아니라 `when {}` 안에.
(R2의 양수/한도, R3의 역할, R4의 forbid는 이 골격을 따라 직접.)
</details>

## Step 3 — break-and-fix: 예측 → 파괴 → 확인 (30분)

8/8이 된 **내 정책**에 아래 뮤테이션을 하나씩 적용한다.
**규칙: 실행 전에 "어느 시나리오가 깨질지" 먼저 종이에 적는다.** 그 다음 채점해서 예측과 비교.

| 뮤테이션 | 예측해 볼 것 |
|---|---|
| **A** | R4(forbid) 정책 전체 삭제 | 몇 개가, 어떤 시나리오가 깨지나? |
| **B** | R1의 소유자 조건 제거(무조건 permit) | ? |
| **C** | R2의 한도 비교를 `<=`에서 `<`로 | ? |

<details><summary>뮤테이션 C를 돌려본 후에 열 것</summary>

**C는 core 8/8을 그대로 통과한다.** 시나리오에 "정확히 한도만큼(1000) 이체"하는 **경계 케이스가
없기** 때문이다 — 뮤턴트가 살아남으면 테스트 스위트에 구멍이 있다는 뜻이다(*mutation testing*).
이 repo의 적대적 검증이 `cedar/agent/`에서 실제로 같은 클래스의 결함("시나리오가 잘못된 이유로
통과")을 찾아 falsifiable 테스트를 추가했다 — Step 4의 ext 시나리오 3번이 바로 이 뮤턴트를 잡는
경계 테스트다. 뮤테이션을 되돌리고 Step 4로.

</details>

## Step 4 — 졸업 과제: 스펙에 없던 확장 (30–60분)

새 요구가 내려왔다:

> **E1.** 감사역(auditor)은 **모든 계좌를 조회**할 수 있어야 한다. 단, **이체 권한은 절대 아니다.**

설계해서 `labs/m0/policies.cedar`에 추가하라. 졸업 채점:

```powershell
.venv\Scripts\python.exe labs\m0\grade.py --ext     # core 8 + ext 3 = 11/11 목표
```

ext 시나리오 3개: ① auditor가 남의 계좌 조회 → Allow ② auditor가 남의 계좌 이체 → **Deny**
(과잉 허용을 잡는다 — "auditor에게 다 열어주기"로 풀면 여기서 걸린다) ③ **정확히 한도만큼(1000)**
이체 → Allow (Step 3-C의 경계 테스트).

## Step 5 — 구두 문답 (면접 방어)

답안을 보기 전에 **소리 내어** 답하라. 모듈 졸업 후와 면접 전에 다시 돌아올 것.

1. <details><summary>Cedar의 기본 판정은? permit이 하나도 없으면 무슨 일이 일어나는가?</summary>default-deny. 매치되는 permit이 없으면 무조건 Deny. 그래서 빈 정책으로도 Deny-기대 시나리오는 통과한다 — Deny 통과는 정책의 증거가 아니다.</details>
2. <details><summary>permit과 forbid가 동시에 매치되면?</summary>forbid가 이긴다(explicit deny overrides). R4가 R2의 허용을 덮는 구조가 그 예다.</details>
3. <details><summary>PARC 모델의 각 요소는 이 데모에서 구체적으로 무엇인가?</summary>Principal=User::"alice"(X-User에서 파생), Action=ViewAccount/Transfer/ViewAuditLog, Resource=Account/AuditLog 엔티티, Context={amount} 같은 요청 시점 값.</details>
4. <details><summary>R3은 RBAC적이고 R2는 ABAC적이다 — 왜?</summary>R3은 역할 멤버십(principal in Role)만 보는 거친 판정=RBAC. R2는 소유자 관계+금액+개인 한도라는 속성/컨텍스트 조건=ABAC. 한 엔진에서 둘을 계층으로 섞는 게 실무 하이브리드다.</details>
5. <details><summary>schema validation은 무엇을 잡고, 평가(evaluate)와 어떻게 다른가?</summary>validation은 정책이 스키마에 없는 속성/타입오류/없는 액션을 참조하는 걸 배포 전에 정적으로 잡는다. 평가는 런타임에 요청별 판정. authz.py가 둘 다 수행한다 — "배포 전 검증 가능"이 policy-as-code의 핵심 가치.</details>
6. <details><summary>왜 인가를 코드로 두는가? 한 문장으로.</summary>코드면 단위테스트·리뷰·CI 게이트·뮤테이션 검증이 가능해서 "시행된다"를 증명할 수 있다 — 이 repo의 명제(검증가능성) 그 자체.</details>
7. <details><summary>context.amount는 누가 주는 값인가? 신뢰할 수 있나?</summary>호출자(PEP, 여기선 api)가 요청 본문에서 추출해 넣는다. 신뢰 불가 입력이므로 PEP가 정규화해야 한다 — app/api/main.py는 파싱 실패 시 10^9로 강제해 한도 초과 Deny로 fail-closed한다.</details>
8. <details><summary>principal id가 공격자 제어 입력(X-User 헤더)일 때 무엇을 막아야 하나?</summary>charset 검증. User::"..." 문자열에 따옴표 등을 인젝션해 UID를 탈출하는 것 — main.py가 정규식 ^[A-Za-z0-9_-]{1,64}$로 막고 400을 돌려준다.</details>
9. <details><summary>이 정책을 AWS 관리형으로 옮기려면?</summary>Amazon Verified Permissions — 같은 Cedar 정책/스키마가 그대로 올라간다. isAuthorized API로 평가. ($5/100만 요청)</details>
10. <details><summary>빈 정책이 5/8을 통과하고, 뮤테이션 C가 core 8/8을 통과했다 — 두 사건의 공통 교훈은?</summary>둘 다 "통과 = 증명"이 아님을 보여준다. Deny는 default-deny 때문에 공짜로 맞을 수 있고(옳은 이유로 Deny인지 별도 확인 필요), Allow도 경계를 안 찌르면 뮤턴트가 살아남는다. 통과하는 스위트 ≠ 좋은 스위트 — 뮤턴트를 죽이는 스위트가 좋은 스위트다(mutation testing).</details>

## 졸업 기준 (셀프 체크)

- [ ] `grade.py --ext` **11/11**
- [ ] 뮤테이션 A·B의 깨질 시나리오를 **사전에 정확히 예측**했다
- [ ] 뮤테이션 C가 core를 통과하는 이유와, ext ③이 그것을 잡는 이유를 설명할 수 있다
- [ ] 구두 문답 10개를 답안 안 보고 말로 답했다
- [ ] **이제 정답지를 열어라:** `git diff --no-index labs/m0/policies.cedar cedar/policies.cedar` —
  내 답과 원본의 차이를 읽고, 각 차이가 *스타일*인지 *의미*인지 판별할 수 있다

다음: **[M1 — 쉬프트레프트 결함 사냥](../m1/README.md)** (클러스터 불필요).
