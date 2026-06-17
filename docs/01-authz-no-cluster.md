# Lab 0 — 인가 as-code (클러스터 불필요)

> **직접 해보기 (재구현 트랙):** 읽었다면 빈 파일에서 재구현하라 → **[M0 · Cedar 인가](../labs/m0/README.md)** (자동 채점 11/11, 클러스터 불필요).

**목표:** *authz-as-code* — 선언적 규칙을 단위테스트로 — 를 5분 만에, Python만으로 이해한다.
이건 Amazon Verified Permissions와 같은 Cedar 정책 언어다.

## 모델 — PARC (이 데모에서 구체적으로 무엇인가)

Cedar의 모든 결정은 네 조각의 튜플 `(Principal, Action, Resource, Context)`을 정책에 대해 평가한 것이다.
추상어가 아니라 이 repo에선 정확히 이렇다 (`cedar/schema.json` + `cedar/entities.json`):

- **Principal** = `User`(`alice`/`bob`/`carol`). `entities.json`에서 `Role`(`customer`/`auditor`)의
  자식이고 — 그래서 `principal in Role::"auditor"`가 동작한다(역할은 그룹 멤버십, ABAC 속성이 아니다) —
  `transferLimit` 속성을 단다(`carol`은 0: 감사자는 이체 못 함). 신원 자체는 Cedar 밖에서 온다 (HTTP는
  `X-User` 헤더, 그게 곧 *정직한 한계*다 — 아래).
- **Action** = `ViewAccount` / `Transfer` / `ViewAuditLog`. schema가 각각의 `appliesTo`를 못 박는다
  (`Transfer`는 `User`→`Account`만, `ViewAuditLog`는 `User`→`AuditLog`만) — 액션은 타입 수준에서
  엮인다.
- **Resource** = `Account`(`owner`, `frozen` 속성) 또는 `AuditLog`. `forbid`가 보는 `resource.frozen`,
  소유권을 판정하는 `resource.owner == principal`이 전부 여기서 온다.
- **Context** = 요청별 부수 데이터. 여기선 **`Transfer`에만** `amount`(`Long`)가 붙는다 — schema가
  `Transfer` 액션의 `context`에만 선언하므로, `ViewAccount` 요청에 `amount`를 끼워 넣으면 검증이 잡는다.
  *principal/resource 속성은 등록된 사실(누가 무엇을 소유)이고, context는 이번 한 번의 시도(이체액)다* —
  Cedar가 둘을 분리하는 이유다.

`forbid`(동결)가 `permit`을 덮는 우선순위, 그리고 `permit`이 하나도 안 맞으면 **기본 거부**(default-deny)인
것이 이 모델의 골격이다.

## 왜 policy-as-code가 검증을 가능케 하나 — 2단계 분리

`cedar/authz.py`는 의도적으로 두 단계를 *분리*해 돈다:

1. **schema-validate (요청 0건, 한 번):** `cedarpy.validate_policies(policies, schema)`. 데이터·요청
   없이 정책을 타입체크한다 — `resource.frozn`(오타) 같은 존재하지 않는 속성, 잘못 엮인 액션을 *배포 전*에
   잡는다. 위 기대 출력의 `schema validation: OK`가 이 줄이다. CI에서 깨지는 건 시나리오가 아니라 정책
   자체의 타입 버그다.
2. **per-request-evaluate (요청마다):** `cedarpy.is_authorized(...)`를 `requests.json`의 각 케이스에
   돌려 결정이 `expect`와 맞는지 본다. 같은 정책·schema·엔티티에 *입력만 바꿔* 평가하므로 — `amount: 500`
   vs `5000` vs `-100` — 결정 경계가 표 한 장으로 드러난다.

이 분리가 핵심이다: 정책은 정적으로 *맞는지*(validate) 따로, 실제 시나리오에서 *옳은지*(evaluate) 따로
증명된다. 둘 다 같은 텍스트 파일이라 git diff로 리뷰되고 PR에서 빨개진다 — 그게 "as-code"의 실체다.

> **정직한 한계 — Cedar는 *입력의 진실성*은 증명하지 않는다.** validate는 정책이 schema에 *타입-정합*임을,
> evaluate는 *주어진 입력*에 대해 정책이 옳음을 보일 뿐이다. `resource.owner == principal`은 누군가
> `entities.json`의 `owner`를 정직하게 채웠고 principal이 *진짜* 그 사람일 때만 의미가 있다 — 신원 위조
> (헤더 스푸핑)·잘못된 엔티티 데이터는 Cedar 밖의 문제다. authz는 *결정* 계층이지 *인증·데이터 무결성*
> 계층이 아니다. 그 위조 경계를 실제로 닫는 건 [Lab 4 — 신원](05-identity.md)이다.

## 실행

```bash
python -m venv .venv && ./.venv/bin/python -m pip install -r requirements-dev.txt
./.venv/bin/python cedar/authz.py
```

기대 결과:

```
schema validation: OK

scenario                                        expect  actual  result
--------------------------------------------------------------------------
owner views own account                          Allow   Allow  PASS
non-owner views another's account                 Deny    Deny  PASS
owner transfers within limit                     Allow   Allow  PASS
owner transfers OVER limit                        Deny    Deny  PASS
owner transfers a NEGATIVE amount (value extraction)    Deny    Deny  PASS
transfer from FROZEN account (forbid overrides)    Deny    Deny  PASS
auditor reads audit log                          Allow   Allow  PASS
customer reads audit log (no role)                Deny    Deny  PASS
--------------------------------------------------------------------------
8/8 scenarios passed
```

> ⚠️ **M0 재구현 트랙이라면 — 정답지 주의:** 아래 **무엇을 읽나 / 망가뜨려 보기**는 정답지 `cedar/policies.cedar`를 직접 읽고 편집한다. **M0 랩([labs/m0](../labs/m0/README.md))을 빈 파일에서 재구현할 계획이면 졸업 전에는 이 절을 건너뛰어라** — `cedar/policies.cedar`는 그 트랙의 잠긴 정답지다(이 개념 페이지는 *개념 파악*용으로만 M0 Step 1에서 가리킨다).

## 무엇을 읽나

- `cedar/policies.cedar` — 규칙. `forbid`(동결 계좌)가 `permit`을 덮고, 이체 규칙은
  `context.amount > 0 && <= limit`이 필요함에 주목.
- `cedar/schema.json` — 타입 모델(엔티티, 액션, `Transfer` context).
- `cedar/entities.json` — 데이터(누가 무엇을 소유하나, 이체 한도, 역할).
- `cedar/requests.json` — 테스트 케이스 + 그 기대 결정.

## 망가뜨려 보기 (그리고 고치기)

1. `cedar/policies.cedar`에서 `Transfer` permit의 `&& context.amount > 0`을 지운다.
2. `python cedar/authz.py`를 다시 돌린다. **음수 금액(negative-amount)** 시나리오가
   `Allow` / **FAIL**로 뒤집힌다 — 실제 핀테크 버그(음수 "이체"는 가치를 빼낸다)를 재도입한 것이고,
   테스트가 그걸 잡아냈다.
3. 그 줄을 되살린다. 다시 green.

그 루프 — 정책을 바꾸면 테스트가 빨개진다 — 가 authz-as-code의 전부다.
다음: [Lab 1 — 스캔](02-scan.md).
