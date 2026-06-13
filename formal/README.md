# formal/ — cross-layer policy consistency (M7, formal stretch)

[심화 / formal]{ .lab-progress } · [스택 z3 (SMT)]{ .lab-badge } · [소요 ~1–2h]{ .lab-badge } · [클러스터 불필요]{ .lab-badge .no-cluster } · [비용 $0 로컬]{ .lab-badge }

> 🎯 **학습 성과:** 교차계층(Cilium L7 × Cedar PDP) shadow/dead-rule을 z3로 *형식 검증*하고, 반증가능성(`--ungate-transfer`로 ungated 검출)을 설명할 수 있다.

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

## 실행

```powershell
.venv\Scripts\python.exe formal\cross_layer.py                   # 리포트; UNGATED 발견 시에만 exit 1
.venv\Scripts\python.exe formal\cross_layer.py --open-auditlogs  # 뮤테이션: L7 경로를 열면 shadow 소멸
.venv\Scripts\python.exe formal\cross_layer.py --ungate-transfer # 뮤테이션: Cedar 미호출 라우트 흉내 → UNGATED 발화(exit 1)
```

base는 `ViewAuditLog`를 SHADOWED로 잡는다(증인 `['ViewAuditLog']`). `--open-auditlogs`로 L7에 `GET
/auditlogs/*`를 추가하면 shadow가 사라지고, `--ungate-transfer`는 UNGATED를 발화시킨다 — 도구가 **양쪽
교차계층 변화를 실제로 추적**함을 보이는 *반증가능* 데모(M0 mutation 교훈과 같은 결).

## 어떻게 (real Cedar + 작은 z3 유한도메인 체크)

세 입력 모두 **실제 아티팩트**에서 나온다: **Cedar 결정**은 `cedarpy`로 `cedar/`의 *진짜 정책*을 평가(핸드모델
드리프트 없음); **L7 도달성**은 `k8s/netpol.yaml`의 `allow-web-to-api` HTTP 규칙 전사; **gate**(라우트가 PDP를
부르는가)는 `app/api/main.py`에서 유도. z3가 세 관계를 인코딩하고 *교차계층 불일치 증인*(shadowed / ungated)을
열거한다.

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

## make it yours

1. `ACTION_HTTP`/`GRANT_PROBE`에 action을 하나 추가하고, netpol에서 그 경로를 막아 새 shadow를 만들어보라.
2. `--open-auditlogs` 없이 vs 있이 돌려, *어느* 증인이 사라지는지 **먼저 예측**한 뒤 확인하라.
3. 토론: shadow는 항상 버그인가? (아니다 — out-of-band 접근일 수 있다. 핵심은 *명시화*다.)
