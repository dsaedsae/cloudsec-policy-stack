# Lab 0 — Authorization as code (no cluster)

!!! tip "직접 해보기 (재구현 트랙)"
    읽었다면 빈 파일에서 재구현하라 → **[M0 · Cedar 인가](../labs/m0/README.md)** (자동 채점 11/11, 클러스터 불필요).

**Goal:** understand *authz-as-code* — declarative rules, unit-tested — in 5
minutes, with nothing but Python. This is the same Cedar policy language as
Amazon Verified Permissions.

## Run it

```bash
python -m venv .venv && ./.venv/bin/python -m pip install -r requirements-dev.txt
./.venv/bin/python cedar/authz.py
```

Expected:

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

!!! warning "M0 재구현 트랙이라면 — 정답지 주의"
    아래 **What to read / Break it**은 정답지 `cedar/policies.cedar`를 직접 읽고 편집한다.
    **M0 랩([labs/m0](../labs/m0/README.md))을 빈 파일에서 재구현할 계획이면 졸업 전에는 이 절을 건너뛰어라**
    — `cedar/policies.cedar`는 그 트랙의 잠긴 정답지다(이 개념 페이지는 *개념 파악*용으로만 M0 Step 1에서 가리킨다).

## What to read

- `cedar/policies.cedar` — the rules. Note `forbid` (frozen account) overrides
  `permit`, and the transfer rule needs `context.amount > 0 && <= limit`.
- `cedar/schema.json` — the typed model (entities, actions, the `Transfer` context).
- `cedar/entities.json` — the data (who owns what, transfer limits, roles).
- `cedar/requests.json` — the test cases + their expected decisions.

## Break it (then fix it)

1. In `cedar/policies.cedar`, delete `&& context.amount > 0` from the `Transfer`
   permit.
2. Re-run `python cedar/authz.py`. The **negative-amount** scenario now flips to
   `Allow` / **FAIL** — you just re-introduced a real fintech bug (a negative
   "transfer" extracts value), and the test caught it.
3. Restore the line. Green again.

That loop — change policy, a test goes red — is the whole point of authz-as-code.
Next: [Lab 1 — scanning](02-scan.md).
