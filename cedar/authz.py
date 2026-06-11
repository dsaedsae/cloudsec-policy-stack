"""Cedar authorization demo + test harness (runs with cedarpy, no AWS/cloud).

1. Validates policies.cedar against schema.json (catches policy bugs pre-deploy).
2. Evaluates each request in requests.json and checks the decision matches `expect`.

    python authz.py        # prints a PASS/FAIL table; exit 1 on any mismatch

This is "authorization as code": the same Cedar policies/schema you'd ship to
Amazon Verified Permissions, evaluated locally and unit-tested in CI.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import cedarpy

HERE = Path(__file__).resolve().parent


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    policies = (HERE / "policies.cedar").read_text(encoding="utf-8")
    schema = (HERE / "schema.json").read_text(encoding="utf-8")
    entities = (HERE / "entities.json").read_text(encoding="utf-8")
    requests = json.loads((HERE / "requests.json").read_text(encoding="utf-8"))

    # 1) Validate policies against the schema (policy-as-code hygiene).
    vr = cedarpy.validate_policies(policies, schema)
    errors = getattr(vr, "errors", None) or []
    print(f"schema validation: {'OK' if not errors else 'ERRORS'}")
    for e in errors:
        print(f"  ! {e}")
    if errors:
        return 1

    # 2) Evaluate every request and compare against the expected decision.
    print(f"\n{'scenario':<46}{'expect':>8}{'actual':>8}  result")
    print("-" * 74)
    failures = 0
    for r in requests:
        res = cedarpy.is_authorized(
            {"principal": r["principal"], "action": r["action"],
             "resource": r["resource"], "context": r.get("context", {})},
            policies, entities, schema,
        )
        actual = res.decision.value
        ok = actual == r["expect"]
        failures += not ok
        print(f"{r['name']:<46}{r['expect']:>8}{actual:>8}  {'PASS' if ok else 'FAIL'}")

    print("-" * 74)
    print(f"{len(requests) - failures}/{len(requests)} scenarios passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
