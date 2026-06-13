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


def main(base: Path = HERE, hint_map: dict | None = None) -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    policies = (base / "policies.cedar").read_text(encoding="utf-8")
    schema = (base / "schema.json").read_text(encoding="utf-8")
    entities = (base / "entities.json").read_text(encoding="utf-8")
    requests = json.loads((base / "requests.json").read_text(encoding="utf-8"))

    # 1) Validate policies against the schema (policy-as-code hygiene).
    vr = cedarpy.validate_policies(policies, schema)
    errors = getattr(vr, "errors", None) or []
    print(f"schema validation: {'OK' if not errors else 'ERRORS'}")
    for e in errors:
        print(f"  ! {e}")
    if errors:
        # The #1 Cedar beginner mistake is a missing trailing ';' — give a hint.
        if any(k in str(e).lower() for e in errors
               for k in ("parse error", "unexpected end of input", "unexpected token")):
            print("  힌트: Cedar 문(permit/forbid)은 모두 세미콜론(;)으로 끝난다 — when {...} 블록 끝의 ;,"
                  " 그리고 각 정책의 마지막 } 다음 ;를 확인하라. 문법 골격은 labs/m0/README §문법 치트시트.")
        return 1

    # 2) Evaluate every request and compare against the expected decision.
    #    Column width is computed from the data so long scenario names stay aligned.
    w = max((len(r["name"]) for r in requests), default=8) + 2
    print(f"\n{'scenario':<{w}}{'expect':>8}{'actual':>8}  result")
    print("-" * (w + 24))
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
        print(f"{r['name']:<{w}}{r['expect']:>8}{actual:>8}  {'PASS' if ok else 'FAIL'}")
        # Opt-in beginner nudge (concept, not the answer) on a FAIL row.
        if not ok and hint_map and r["name"] in hint_map:
            print(f"     -> {hint_map[r['name']]}")

    print("-" * (w + 24))
    print(f"{len(requests) - failures}/{len(requests)} scenarios passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
