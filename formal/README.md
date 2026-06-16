# formal/ — cross-layer policy consistency (M7, formal stretch)

<div class="lab-pills">
<span class="lab-progress">심화 / formal</span> · <span class="lab-badge">스택 z3 (SMT)</span> · <span class="lab-badge">소요 ~1–2h</span> · <span class="lab-badge no-cluster">클러스터 불필요</span> · <span class="lab-badge">비용 $0 로컬</span>
</div>

> **학습 성과:** 교차계층(Cilium L7 × Cedar PDP) shadow/dead-rule을 z3로 *형식 검증*하고, 반증가능성(`--ungate-transfer`로 ungated 검출)을 설명할 수 있다.

## 왜 (the gap nobody tests)

이 스택은 한 자산(api)을 **여섯 정책 엔진**으로 직렬 방어한다(admission → Cilium L3/L7 →
Cedar → WireGuard → Tetragon → shift-left). `verify.sh`·`authz.py`·`checkov`는 각 층을 **개별로**
검증한다. 그러나 **층들이 의도대로 *합성*되는가** — 특히 Cilium **L7 네트워크 정책**과 **Cedar PDP**가
"어떤 action이 도달가능하면서 인가되는가"에 *동의*하는가 — 는 아무도 테스트하지 않는다.

`cross_layer.py`는 web→api L7 엣지와 Cedar PDP 사이의 두 가지 교차계층 속성을 검사하고, 각 action을
분류한다:

- **SHADOWED(죽은 규칙):** Cedar가 *허용*하는 action인데 그 HTTP 경로를 L7이 *차단*한다 → 그 permit은
  web→api로는 도달 불가. 이 데모에선 **`ViewAuditLog`**가 그렇다 — `k8s/netpol.yaml`이 `/auditlogs/*`를
  L7에서 드롭하므로(그 파일 주석도 "dropped HERE ... before it ever reaches ... Cedar"라 명시), Cedar의
  auditor용 `ViewAuditLog` permit은 이 엣지로는 발동될 수 없다. *버그가 아니라 층 상호작용* — 의도된
  out-of-band 접근인지 확인해야 할 지점을 명시적으로 드러낸다.
- **UNGATED(진짜 갭):** L7으로 도달가능한데 Cedar 게이트가 *없는* action. `gate`는 **`app/api/main.py`에서
  유도**된다(그 action의 라우트가 `authorize()`를 호출하는가) — 하드코딩 상수가 아니다. 여기선 셋 다 호출하므로
  UNGATED 없음(방어심층 성립). `--ungate-transfer`로 *Cedar 호출을 빠뜨린* 라우트를 흉내내면 UNGATED가
  **발화**하고 `exit 1` — 이 체크가 죽지 않고 살아있음을 보인다(CI 게이트가 진짜 회귀를 잡을 수 있음).

### 이게 막는 구체적 실패 (왜 *교차*계층이 별도 체크인가)

각 층의 단위 테스트는 "이 층이 자기 규칙대로 동작하는가"만 본다. SHADOWED/UNGATED는 **어느 단일 층 테스트로도
잡히지 않는다** — 두 층의 *연접*에서만 드러나기 때문이다.

- **UNGATED = 사일런트 인가 우회.** 흔한 회귀 시나리오: 라우트 핸들러를 리팩터링하다 `authorize()` 호출을
  떨어뜨린다. Cedar 단위 테스트(`cedar/authz.py`)는 *여전히 전부 통과*한다 — 정책은 멀쩡하니까. netpol 린트도
  통과한다 — L7 규칙은 그 경로를 정당하게 연다. 그런데 그 경로는 이제 PDP를 *안 거치고* 200을 돌려준다.
  이건 IDOR/BOLA(객체-수준 인가 부재, OWASP API #1)가 코드로 새어든 정확한 형태다. 교차계층 린트만이
  "L7-도달가능 ∧ ¬gated"라는 곱집합 조건으로 이걸 본다.
- **SHADOWED = 죽은 정책의 위험.** Cedar에 `ViewAuditLog` permit이 있는데 web→api로 영원히 안 닿으면,
  운영자는 "auditor는 감사로그를 본다"고 *믿지만* 실제론 403(L7 드롭)이다. 둘 중 하나다: (a) 의도된
  out-of-band 접근(예: 내부 콘솔이 다른 엣지로 붙음)인데 *문서화 안 됨*, (b) netpol이 잘못 좁혀 정당한 기능이
  죽음. 어느 쪽이든 "정책에 규칙이 *있다*"가 "그 규칙이 *발동한다*"를 의미하지 않음을 드러낸다.

## 실행

```powershell
.venv\Scripts\python.exe formal\cross_layer.py                   # 리포트; UNGATED 발견 시에만 exit 1
.venv\Scripts\python.exe formal\cross_layer.py --open-auditlogs  # 뮤테이션: L7 경로를 열면 shadow 소멸
.venv\Scripts\python.exe formal\cross_layer.py --ungate-transfer # 뮤테이션: Cedar 미호출 라우트 흉내 → UNGATED 발화(exit 1)
```

base는 `ViewAuditLog`를 SHADOWED로 잡는다(증인 `['ViewAuditLog']`). `--open-auditlogs`로 L7에 `GET
/auditlogs/*`를 추가하면 shadow가 사라지고, `--ungate-transfer`는 UNGATED를 발화시킨다 — 도구가 **양쪽
교차계층 변화를 실제로 추적**함을 보이는 *반증가능* 데모(M0 mutation 교훈과 같은 결).

base 실행의 실제 출력(핵심 줄):

```
  ViewAuditLog   grant=True  reach=False gate=True  SHADOWED — Cedar permits this action but the L7 edge drops its path (dead via web->api)
  SMT shadowed-permit witnesses : ['ViewAuditLog']
  SMT ungated-reachable witnesses: []
```

`exit 0`이다 — SHADOWED는 *경고*이지 *실패*가 아니다. `exit 1`은 **UNGATED일 때만** 난다(코드의
`if ungated: return 1`). 이 비대칭이 의도된 설계인 이유는 아래 구술 점검 첫 항목에서 다룬다.

## 어떻게 (real Cedar + 작은 z3 유한도메인 체크)

세 입력 모두 **실제 아티팩트**에서 나온다: **Cedar 결정**은 `cedarpy`로 `cedar/`의 *진짜 정책*을 평가(핸드모델
드리프트 없음); **L7 도달성**은 `k8s/netpol.yaml`의 `allow-web-to-api` HTTP 규칙 전사; **gate**(라우트가 PDP를
부르는가)는 `app/api/main.py`에서 유도. z3가 세 관계를 인코딩하고 *교차계층 불일치 증인*(shadowed / ungated)을
열거한다.

### 세 입력이 어떻게 *유도*되는가 (코드 한 줄씩)

세 술어가 각자 다른 방식으로 진짜 아티팩트를 읽는다 — 이게 "드리프트 없음"의 실체다.

- **`cedar_grants(action)`** — `GRANT_PROBE[action]`의 `(principal, action, resource, context)` 튜플을
  `cedarpy.is_authorized()`에 그대로 넣어 *살아있는* `cedar/policies.cedar`를 평가한다. 예: `ViewAuditLog`는
  `('User::"carol"', ..., 'AuditLog::"2026-06"', {})`로 프로브 — carol이 `Role::"auditor"`라서 permit이 발동,
  `True`. 핵심은 **프로브가 정책을 다시 베끼지 않는다**는 점: 정책을 고치면 이 술어의 답도 자동으로 바뀐다.
- **`l7_reachable(action, rules)`** — `ACTION_HTTP[action]`의 `(method, path)`를 `rules`의 정규식과
  `re.fullmatch`로 맞춘다. `rules`는 `L7_RULES_BASE`(netpol의 `allow-web-to-api` HTTP 블록 두 줄을 손으로 옮긴
  것). `/auditlogs/2026-06`은 base 규칙 어디에도 매칭 안 돼 `False` → 이게 SHADOWED의 `reach=False`다.
  `--open-auditlogs`는 `rules`에 `("GET", r"/auditlogs/[^/]+$")`를 *append*해서 같은 술어가 `True`를 내게 한다.
- **`gated_in_app(action)`** — 하드코딩 상수가 아니라 **AST 워크**다. `app/api/main.py`를 `ast.parse`하고,
  `ACTION_HANDLER[action]`(예: `view_audit_log`) 이름의 함수 정의를 찾아 그 본문에 `authorize(...)` 또는
  `resolve_principal(...)` *호출*이 있는지 `ast.walk`로 검사한다. 그래서 핸들러에서 `authorize()` 한 줄을 지우면
  이 술어가 *코드를 다시 읽어* `False`로 바뀐다 — `--ungate-transfer`는 이 AST 결과를 사후에 덮어써(`gated["Transfer"] = False`)
  같은 회귀를 *파일 수정 없이* 흉내낼 뿐이다.

### z3 인코딩이 실제로 하는 일

`main()`은 세 dict(`grants`/`reach`/`gated`)를 z3 `EnumSort`("Action")와 세 개의 uninterpreted
`Function(Action → Bool)`로 올린다. `facts`는 각 action에 대해 `Grant(a) == BoolVal(grants[a])` 식으로
구체값을 *못박는* 등식들이다. 그다음 `_enum`이 솔버에 `And(Grant(a), Not(Reach(a)))`(= shadowed) 같은 속성을
넣고 `sat`인 동안 모델을 뽑아 `a != v`로 블로킹하며 **모든 증인을 열거**한다(단일 SAT이 아니라 all-SAT 루프).
`EnumSort`라 도메인이 유한이고 매 모델이 한 값을 지우므로 루프는 최대 action 수만큼 돌고 `unsat`으로 끝난다.
이 규모에선 컴프리헨션과 동치라는 caveat는 아래 "정직한 경계"에 있다.

## 정직한 경계 (과장 금지)

- **유한 도메인(현재 action 3개)이라 z3는 기법을 *시연*하는 것이다** — 이 규모에선 증인이 평범한 파이썬
  컴프리헨션(`[a for a in actions if grants[a] and not reach[a]]`)과 **바이트 단위로 동일**하다. z3의 실제
  레버리지는 관계가 심볼릭/uninterpreted 구조를 가질 때 나온다. 그래서 헤드라인을 "SMT 검증"이 아니라
  "z3로 인코딩한 유한도메인 일관성 체크"로 읽어야 정확하다.
- Cedar 결정은 **concrete** 평가다(cedarpy, 유한 엔티티 집합) — *심볼릭이 아니다*. 정책 전체를 무한 입력에 대해
  기호적으로 검증하려면 **cedar-policy-symcc**(Cedar 공식 SMT 컴파일러)가 필요하며, 그것이 rigor/scaling 업그레이드다.
- L7 규칙은 라이브 Cilium 데이터플레인을 파싱한 게 아니라 netpol YAML을 **손으로 옮긴 스펙**이다.
- 이건 교차계층 **shadow(층 상호작용)** 를 드러내는 것이지 *취약점*을 찾는 게 아니다. 그리고 이 기여는
  정직하게 **빅4 미만**(워크숍/툴-페이퍼 고도)이다 — 단일/이중계층 정책 검증은 이미 출판됐고(Cedar의
  Lean-검증 SMT 컴파일러, Zelkova 등), 여기 delta는 *이종 계층(netpol+PDP)의 합성에서 shadow를 드러내는*
  좁지만 실재하는 각도다.

## SARIF 출력 (GitHub code scanning 연동)

`--sarif x.sarif`(또는 `--out`으로 셋 다)는 SARIF 2.1.0을 낸다 → GitHub Security 탭에 인라인 알림으로 뜬다.
주의할 설계 디테일:

- **두 규칙은 *항상* 선언된다.** `emit_sarif`는 `SARIF_RULES`의 `cross-layer/ungated`·`cross-layer/shadowed`를
  결과 유무와 무관하게 `tool.driver.rules`에 넣는다. SARIF 소비자가 규칙 메타데이터(이름/설명/기본 레벨)를
  결과 0건일 때도 안정적으로 읽게 하기 위함이다.
- **result는 두 결함 종류만.** `defense`/`denied`/`none`은 결과로 안 나온다(`if f["kind"] not in (...): continue`).
  스캐너는 *문제*만 보고하고 정상은 침묵해야 하기 때문 — base 실행의 SARIF엔 `shadowed` 1건(warning)만 들어간다.
- **location이 "고칠 파일"을 가리킨다.** ungated는 `app/api/main.py`(빠진 `authorize()`를 *여기* 추가),
  shadowed는 `k8s/netpol.yaml`(L7 규칙을 *여기* 손봄)로 라우팅된다(`emit_sarif`의 `loc` 분기). 알림을 클릭한
  엔지니어가 *원인 파일*로 바로 가게 만드는 작은 정확성이다.

## 깨보기: 예측 → 깨기 → 확인

진짜 아티팩트로 회귀를 흉내내 도구가 살아있음을 본다(M0 mutation과 같은 결).

**뮤테이션 A — UNGATED 발화 (`--ungate-transfer`):**
- 예측: `Transfer`가 L7 도달가능(`reach=True`)인데 게이트가 사라지면 → UNGATED, `exit 1`.
- 깨기/확인:
  ```
  Transfer       grant=True  reach=True  gate=False UNGATED — L7-reachable but the route does not call the Cedar PDP
  SMT ungated-reachable witnesses: ['Transfer']
  GAP: L7-reachable action(s) with no Cedar gate: ['Transfer'] -> FAIL
  ```
  (`exit 1` — 위 GAP 줄 다음 프로세스 종료 코드)
  주의: 이 플래그는 AST 결과를 사후에 `gated["Transfer"] = False`로 덮는 *흉내*다. 진짜 회귀(핸들러에서
  `authorize()` 줄을 실제로 삭제)도 **같은 출력**을 낸다 — `gated_in_app`이 AST를 다시 읽기 때문. 둘이 같다는 게
  플래그가 정직한 프록시라는 증거다.

**뮤테이션 B — SHADOW 소멸 (`--open-auditlogs`):**
- 예측: L7에 `GET /auditlogs/*`를 열면 `ViewAuditLog.reach`가 `True`가 되고, shadow 증인이 *사라진다*. UNGATED는
  안 생긴다(라우트가 여전히 `authorize()`를 부르므로 `gate=True`).
- 확인: `SMT shadowed-permit witnesses : []`, `exit 0`, "every Cedar-permitted action is L7-reachable".

**뮤테이션 C — netpol을 좁혀 *새* shadow 만들기:** `k8s/netpol.yaml`을 건드리지 *않고도* `L7_RULES_BASE`에서
`("GET", r"/accounts/[^/]+$")` 줄을 잠깐 지우면(또는 주석), `ViewAccount.reach`가 `False`가 된다.
- 예측: `ViewAccount`가 `grant=True, reach=False` → SHADOWED 증인이 `['ViewAccount', 'ViewAuditLog']`로 늘어난다
  (z3는 `EnumSort` 선언 순서로 열거하므로 `ViewAccount`가 먼저).
- 확인 후 **반드시 되돌려라** — 이 줄은 netpol HTTP 블록의 손-번역 스펙이라, 지워두면 도구가 실제 정책과
  드리프트한다(그게 바로 "정직한 경계"에서 경고한 손-번역 리스크다). 교훈: 손-번역 입력은 *그 자체가* 깨질 수
  있는 표면이다.

## 흔한 실수 (real gotcha)

- **"shadow가 떴으니 버그다" 단정.** SHADOWED는 `warning`이고 `exit 0`이다 — `ViewAuditLog`는 *의도된*
  out-of-band일 수 있다(감사 콘솔이 web 엣지가 아닌 다른 경로로 붙음). 도구의 일은 *판정*이 아니라 *명시화*다.
  remediation 텍스트도 "confirm the out-of-band intent"라고 적혀 있지 "고쳐라"가 아니다.
- **`--sarif`/`--out`에 경로 인자를 안 줌.** `--sarif`만 쓰고 뒤에 파일을 안 적으면 `error: --sarif requires a
  path argument`로 `exit 2`다(`main()` 앞부분의 가드). 다음 `--`로 시작하는 토큰도 경로로 못 본다.
- **`gate`를 정책이라고 오해.** `gated_in_app`은 Cedar 정책이 아니라 *FastAPI 핸들러가 PDP를 호출하는가*를 본다.
  Cedar에 완벽한 permit/forbid가 있어도 핸들러가 `authorize()`를 안 부르면 그 정책은 **그 라우트에서 죽은 코드**다 —
  UNGATED가 정확히 그 상황이다.
- **SARIF를 cp949로 읽기(Windows).** 출력은 UTF-8(한글·`×`·`→` 포함)이다. PowerShell/파이썬에서 다시 파싱한다면
  `encoding="utf-8"`을 명시하라 — 안 그러면 `UnicodeDecodeError: 'cp949' ...`가 난다.

## make it yours

1. `ACTION_HTTP`/`GRANT_PROBE`에 action을 하나 추가하고, netpol에서 그 경로를 막아 새 shadow를 만들어보라.
2. `--open-auditlogs` 없이 vs 있이 돌려, *어느* 증인이 사라지는지 **먼저 예측**한 뒤 확인하라.
3. 토론: shadow는 항상 버그인가? (아니다 — out-of-band 접근일 수 있다. 핵심은 *명시화*다.)

## 구술 점검 (mechanism / tradeoff)

<details><summary>UNGATED는 빌드를 깨고(exit 1) SHADOWED는 안 깬다. 왜 비대칭으로 설계했나?</summary>

UNGATED("L7 도달가능 ∧ ¬PDP-게이트")는 *항상* 인가 우회 — out-of-band로 정당화될 여지가 없다(어떤 합법
설계도 도달가능한 라우트의 PDP 호출을 의도적으로 빼지 않는다). 그래서 `error`/`exit 1`로 CI를 깬다. 반면
SHADOWED는 "Cedar permit ∧ ¬L7-도달"로, 감사 콘솔이 다른 엣지로 붙는 등 *정당한* out-of-band가 흔하다. 이걸
빌드 실패로 만들면 false-positive로 게이트가 무력화(사람들이 무시)된다. 그래서 `warning`/`exit 0` — 보고하되
판정하지 않는다. SARIF 레벨(`error` vs `warning`)도 같은 비대칭을 그대로 따른다.
</details>

<details><summary>`gate`를 Cedar 정책에서 읽지 않고 `app/api/main.py`의 AST에서 유도한 이유는?</summary>

질문이 "정책이 무엇을 허용하나"가 아니라 "이 라우트가 PDP를 *호출하기는 하나*"이기 때문이다. Cedar 정책이
아무리 완벽해도 핸들러가 `authorize()`를 안 부르면 그 정책은 그 엣지에서 죽은 코드다. 이건 *enforcement
point의 존재*에 대한 질문이라 정책 텍스트가 아니라 **호출 사이트**(코드)에서만 답할 수 있다. 그래서 `ast.walk`로
핸들러 함수 본문의 `authorize`/`resolve_principal` 호출을 찾는다 — 하드코딩 상수로 두면 코드가 드리프트해도
린트가 모른다.
</details>

<details><summary>유한도메인이라 컴프리헨션과 동치인데, 그럼 z3가 *틀린* 답을 줄 가능성은? all-SAT 루프의 종료는 보장되나?</summary>

이 인코딩에서 z3는 컴프리헨션과 같은 답을 준다(그래서 정직히 "기법 시연"이다). 종료는 보장된다: `EnumSort`라
도메인이 유한(현재 3개)이고, `_enum`이 매 모델마다 `a != v`로 그 값을 블로킹하므로 sat 모델이 단조 감소한다 →
최대 도메인 크기만큼 돌고 `unsat`으로 끝난다. z3의 *레버리지*는 술어가 심볼릭/uninterpreted 구조를 가질 때
(예: 경로를 정규식이 아니라 문자열 제약으로, 엔티티를 무한 집합으로) 비로소 컴프리헨션을 못 따라온다.
</details>

<details><summary>cedarpy(concrete)를 cedar-policy-symcc(symbolic)로 바꾸면 정확히 무엇이 달라지나?</summary>

지금은 `GRANT_PROBE`의 *한 점*(carol/2026-06 등)을 평가해 "이 입력에서 Allow인가"만 안다. symcc는 정책을 SMT로
컴파일해 "*어떤* 입력에서 Allow/Deny인가"를 무한 입력 공간에 대해 기호적으로 묻는다(equivalence, 항상-deny,
shadow 같은 속성 검증). 그러면 교차계층 체크가 "이 프로브가 도달 불가"가 아니라 "Cedar가 permit하는 *모든*
(principal, resource) 중 L7로 도달 불가한 집합"을 풀 수 있다 — 유한 프로브의 sampling 한계가 사라진다. 그게
"rigor/scaling 업그레이드"의 구체적 의미다.
</details>

<details><summary>이 린트가 잡지 *못하는* 교차계층 결함 하나를 들어보라.</summary>

행 단위(per-action) 일관성만 본다. **L7 정규식과 FastAPI 라우트 패턴의 불일치**는 못 본다 — 예: netpol이
`/accounts/[^/]+$`로 한 세그먼트만 허용하는데 앱이 `/accounts/{acct}/statements/{id}`를 서빙하면, 그 하위 경로의
도달성/게이트는 `ACTION_HTTP`에 없어서 분석 자체가 안 된다. 또 **컨텍스트 의존 permit**(Cedar의 `amount`
가드처럼 값에 따라 갈리는 결정)은 단일 프로브 값으로만 보므로, "amount=500은 허용이지만 도달 불가"는 잡아도
"amount=−1에서의 행동"은 이 프로브로 안 본다. 둘 다 symcc/경로-스펙 확장이 필요한 영역이다.
</details>

## 실세계 연결

UNGATED가 잡는 건 **인가 호출 자체의 부재**다 — 핸들러가 PDP를 아예 안 부르는 경우. 이건 객체-수준 검사를
빠뜨리는 **API1:2023 BOLA**(구 IDOR, 수년째 OWASP API #1)가 새어드는 *전제 조건*이다: PDP를 안 부르면
`resource.owner == principal` 같은 객체 검사도 당연히 안 돈다. 거꾸로, 핸들러가 `authorize()`를 *부르되* 객체로
스코프를 안 좁히면(gate=True인데도) BOLA는 여전히 가능 — 그건 이 린트가 못 본다(구술 점검의 "context 의존
permit" 한계). 그러니 정확히는: UNGATED = "인가 누락"의 가장 거친 형태를 코드+네트워크 합성에서 정적으로 잡는
좁은 시도다. 런타임 퍼징(BOLA 탐지의 통상 수단)을 대체하진 않고, 회귀가 production에 닿기 전 CI에서 끊는 보완 게이트다.

## 더 파기 (primary sources)

- **Cedar 기호 검증:** [cedar-policy/cedar-spec](https://github.com/cedar-policy/cedar-spec) (Lean으로 검증된
  Cedar 의미론) 및 **cedar-policy-symcc**(Cedar SMT 컴파일러) — 이 랩이 "unbounded upgrade"로 가리키는 도구.
- **Cilium L7 네트워크 정책:** [Cilium docs — Layer 7 Policy](https://docs.cilium.io/en/stable/security/policy/language/#layer-7-examples)
  (HTTP method/path 규칙의 시맨틱; 이 랩이 손-번역한 그 형식).
- **SARIF 2.1.0:** [OASIS SARIF spec](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) /
  [GitHub code scanning에 SARIF 업로드](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning).
- **BOLA / 인가 우회:** [OWASP API Security Top 10 — API1:2023 BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/).
- **AWS Zelkova / Verified Permissions:** [Backes et al., "Semantic-based Automated Reasoning for AWS Access Policies" (FMCAD 2018)](https://d1.awsstatic.com/Security/pdfs/Semantic_Based_Automated_Reasoning_for_AWS_Access_Policies_Using_SMT.pdf)
  — 정책을 SMT로 환원하는 Zelkova의 원 논문. 단일계층 정책 검증이 "출판된 기술"이라는 근거(이 랩의 delta가
  *교차계층 합성*임을 위치 짓는다).
