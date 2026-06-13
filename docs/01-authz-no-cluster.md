# Lab 0 — 인가 as-code (클러스터 불필요)

> 💡 **직접 해보기 (재구현 트랙):** 읽었다면 빈 파일에서 재구현하라 → **[M0 · Cedar 인가](../labs/m0/README.md)** (자동 채점 11/11, 클러스터 불필요).

**목표:** *authz-as-code* — 선언적 규칙을 단위테스트로 — 를 5분 만에, Python만으로 이해한다.
이건 Amazon Verified Permissions와 같은 Cedar 정책 언어다.

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
