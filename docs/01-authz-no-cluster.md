# Lab 0 — Authorization as code (no cluster)

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
