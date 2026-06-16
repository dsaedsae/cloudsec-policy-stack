# M2 배우기 — ValidatingAdmissionPolicy CEL: 라벨↔SA 일관성 검증식

## 개요

`labs/m2/admission-policy.yaml`의 skeleton은 `matchConstraints`·`variables`·binding을 이미 채워뒀다.
네가 쓸 것은 `validations`의 **expression**(과 `messageExpression`) 한 줄 — `app` 라벨을 주장하는
파드가 자기 ServiceAccount와 어긋나면 admission에서 거부하는 CEL이다.

이 페이지는:
1. **완성 예시** — `web` 한 절(clause)만 완성해 보여준다. 변수 가드가 왜 그렇게 생겼는지까지 읽는다.
2. **빈칸 채우기** — 핵심 개념(비교 연산자) 하나를 직접 기입.
3. **이제 혼자** — 나머지 절(`api`/`db`)과 `!hasApp` 앞단을 직접 붙여 식을 완성.

> **핵심 규칙:** 정답 통째를 베끼는 게 아니라 CEL 문법을 한 계단씩 올린다. `web` 절 하나만
> 떠먹이고, `api`/`db` 절과 무라벨 통과(`!variables.hasApp ||`)는 네가 직접 쓴다.
> 정답지(`k8s/admission-policy.yaml`)는 졸업 전 열람 금지.

---

## 1) 완성 예시 (읽고 이해): `web` 절 하나

skeleton의 `variables`는 이미 세 개가 정의돼 있다(여기는 안 건드린다). 식을 쓰기 전에 **왜 이렇게
생겼는지**부터 읽어라 — 검증식이 이 세 변수 위에서 돌기 때문이다.

```yaml
variables:
  - name: sa
    expression: "object.spec.serviceAccountName"
  - name: hasApp
    expression: "has(object.metadata.labels) && 'app' in object.metadata.labels"
  - name: app
    expression: "variables.hasApp ? object.metadata.labels['app'] : ''"
```

**가드 순서가 핵심이다 (이게 이 랩의 idiom):**

- `has(object.metadata.labels)`를 **먼저** 보고 `&&`로 묶은 이유 — 라벨 맵 자체가 없는 파드에서
  곧장 `object.metadata.labels['app']`를 읽으면 CEL은 **no such key** 런타임 에러를 낸다.
  `has()`는 필드/키 존재를 검사하는 CEL 매크로다. `&&`는 **단락(short-circuit)** 평가라, 왼쪽이
  false면 오른쪽(`'app' in ...`)을 아예 평가하지 않는다 → 에러가 안 난다.
  **순서가 거꾸로면 가드가 가드 역할을 못 한다** — 인덱싱이 검사보다 먼저 평가되기 때문.
- `app`이 삼항(`hasApp ? ... : ''`)인 이유 — 검증식에서 `variables.app`을 무조건 비교에 쓰려면
  라벨이 없을 때도 **타입이 string**이어야 한다. `''`(빈 문자열)로 떨어뜨려 두면
  `variables.app == 'web'`이 그냥 false가 되고 타입 에러가 안 난다.
- `sa`엔 `has()`가 없는 이유 — `spec.serviceAccountName`은 API 서버가 validating admission **이전**에
  `default`로 채운다(defaulting). 늘 채워져 있어 가드가 불필요하다.

이제 **검증식 한 절**만 완성한 모습이다. `app: web` 파드는 반드시 `web-sa`로 떠야 한다:

```yaml
validations:
  - expression: >
      (variables.app == 'web' && variables.sa == 'web-sa')   # app이 web이면 SA도 web-sa여야 통과
    messageExpression: >
      "pod label app=" + variables.app + " must run as ServiceAccount " +
      variables.app + "-sa (got " + variables.sa +
      "); forged network identity denied — see THREAT_MODEL.md B7"
```

**한 줄씩:**

- `variables.app == 'web'` — 라벨 값이 `web`인가. (`==`는 CEL 비교 연산자. `=`은 비교가 아니다 →
  컴파일 에러로 apply 거부.)
- `&& variables.sa == 'web-sa'` — *그리고* SA가 `web-sa`인가. 둘 다 참이어야 이 절이 true.
- expression이 **true면 ADMIT, false면 DENY**. 그래서 "통과 조건"을 쓴다 — 막을 것을 쓰는 게 아니라
  *통과할 것*을 쓴다.
- `messageExpression`은 거부 사유다. 변수 보간(`+`로 문자열 결합)으로 *왜* 거부됐는지 운영자가
  읽을 수 있게 한다. 정책명(`shop-label-identity`)은 VAP 거부 메시지에 자동으로 붙으므로
  채점기가 "내 정책이 막았다"를 RBAC 403과 구분할 수 있다.

> 단, 위 식만 두면 `app: api` 정합 파드도, 무라벨 시스템 파드도 전부 false → DENY가 된다.
> 한 절로는 부족하다. 2)·3)에서 나머지를 붙인다.

---

## 2) 빈칸 채우기 (핵심 이해: 비교 연산자)

다음 `api` 절에서 `__?__`를 채워라.

```yaml
(variables.app == 'api' __?__ variables.sa == 'api-sa')
```

**핵심 질문: "app이 api이고 *그리고* SA도 api-sa"를 표현하는 연산자는?**

- 라벨이 `api`인데 SA는 아무거나여도 통과시키면 안 된다 — *둘 다* 맞아야 한다.
- `||`(또는)를 쓰면? `app == 'api'`만 맞아도 절이 true가 돼 SA 검사가 무력화된다 → 위조 통과.
- CEL의 논리곱(둘 다 참) 연산자는?

<details><summary>정답 (직접 써 본 뒤 열 것)</summary>

```yaml
(variables.app == 'api' && variables.sa == 'api-sa')
```

`&&`(논리곱) — 양변이 모두 참이어야 절이 true. `web` 절과 구조가 똑같고 값(`api`/`api-sa`)만 다르다.
`||`였다면 라벨만 맞고 SA가 틀린 위조(`app:api` + `web-sa`)가 통과해 통제가 무력해진다.

</details>

---

## 3) 이제 혼자 — 식 완성

`labs/m2/admission-policy.yaml`의 `validations[0].expression`을 완성하라. 가진 재료:

- 1)의 완성 예시 = `web` 절
- 2)의 정답 = `api` 절
- 같은 구조로 직접 쓸 `db` 절
- 무라벨 파드를 먼저 통과시키는 앞단

**붙이는 순서와 이유** (web 절만 둔 골격 — 나머지 `__?__`는 직접):

```yaml
- expression: >
    __?__ ||
    (variables.app == 'web' && variables.sa == 'web-sa') ||
    __?__ ||
    __?__
```

1. **맨 앞 `__?__`** — 라벨이 없는 파드(shop의 프로브·시스템 파드 등)는 범위 밖, 통과시켜야 한다.
   - 힌트: `variables.hasApp`이 false이면 통과. "hasApp이 아니면"을 한 토큰으로? → `!`(부정)
   - 이게 맨 앞에 `||`로 오는 이유: CEL `||`도 왼쪽부터 단락 평가다. 무라벨 파드는 여기서 즉시
     true가 돼 뒤 절들을 *안 본다* → 무라벨인데 SA 비교를 타다 엉키는 일이 없다.
2. **`api`·`db` 절** — `web` 절을 보고 값만 바꿔 직접 써라. `db`는 어떤 SA여야 하나?
3. **allowlist의 자동 효과** — 어느 절도 안 맞으면 식 전체가 false → DENY. 그래서 `app: cache`처럼
   *정의 안 된* tier나 `app: api` + `web-sa` 위조는 모든 절을 떨어뜨려 자동으로 거부된다.
   "모르는 라벨값 = 거부"가 allowlist 형태에서 공짜로 따라온다.

`messageExpression`은 1)의 예시를 그대로 쓰면 된다(변수 보간 + `B7` 토큰).

**binding은 이미 맞다 — 한 줄만 확인하라:**

```yaml
spec:
  policyName: shop-label-identity
  validationActions: ["Deny"]      # ← 이게 핵심. Deny여야 식이 false일 때 *실제로 거부*한다.
```

`validationActions`가 `["Warn"]`이나 `["Audit"]`이면 식이 false여도 경고/감사만 찍고 **ADMIT**한다 —
위조가 그대로 새 들어간다. skeleton엔 `Deny`로 박혀 있으니 건드리지 말고, 거부가 안 일어나면 여기부터 봐라.

**검증:**

```bash
bash labs/m2/grade.sh        # 5/5 PASS 확인 (클러스터 up 필요)
```

다섯 케이스 — 위조 2개는 **DENY**, 정합 2개 + 무라벨 1개는 **ADMIT**여야 한다:

- `forge-1` (app:api + web-sa) → DENY
- `forge-2` (app:web + api-sa) → DENY
- `ok-1` (app:api + api-sa) → ADMIT
- `ok-2` (app:web + web-sa) → ADMIT
- `ok-3` (라벨 없음 + default) → ADMIT

**"다섯 개 다" 가 필요한 이유:** 위조를 막는 것만으론 부족하다. 정합·무라벨까지 통과해야 통제가
*막을 것만 막고 나머진 통과*시킨다는 증거가 된다. 전부 거부하는 식(`expression: false`)도 위조를
막지만 정합 파드·무라벨 파드까지 죽여 워크로드를 못 띄운다 — 과잉 거부도 결함이다(M0의 교훈).

---

## 다음 배우기

- **Step 2 (break-and-fix):** README의 5개 실험을 *예측 먼저, 확인 나중*으로. 특히 #2(`!hasApp ||`
  삭제 → 무라벨 파드 전부 거부)와 #4(`app` 변수에서 삼항 가드 제거 → no such key 에러)는 이 페이지의
  가드/순서가 왜 거기 있는지를 깨뜨려서 보여준다.

- **이 통제의 한계(THREAT_MODEL §B7):** 이 식은 라벨↔SA의 *일관성*만 본다 — `request.userInfo`(요청자)는
  안 본다. 그래서 자기일관 위조(`app:api` + `api-sa`를 둘 다 맞춰 생성)는 **통과한다**. 그 잔여는
  SA-use 게이트(`k8s/admission-sa-use.yaml` — 누가 tier SA를 *쓸* 수 있나)와 SPIFFE 암호 신원이 닫는다.
  전체 체인은 `docs/05-identity.md` 참조.

---

정리: 무라벨 통과 앞단과 세 tier 절을 직접 이어 식을 완성하고 `grade.sh`로 5/5를 확인한 뒤,
**왜 `has()`가 인덱싱보다 먼저인지**·**왜 통과 조건을 쓰는지(true=ADMIT)**·**이 식이 못 막는
것(자기일관 위조)**을 답안 없이 설명할 수 있으면 M2 통과다.
