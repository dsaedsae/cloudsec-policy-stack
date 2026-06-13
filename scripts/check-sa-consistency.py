#!/usr/bin/env python3
"""check-sa-consistency.py — static drift guard (no cluster).

The tier ServiceAccount name set (web-sa/api-sa/db-sa) is hard-coded in FOUR places:
k8s/rbac.yaml (the SA definitions) and the three identity policies that gate them
(admission-policy.yaml label<->SA, admission-sa-use.yaml SA-use gate, kyverno-sa-use.yaml
cluster-wide SA-use). If a future tier SA is added to RBAC but not to a gate — or removed
from one gate only — a self-consistent-forgery hole opens silently. This asserts all four
agree, so drift fails CI instead of shipping.

    python scripts/check-sa-consistency.py     # exit 1 on any mismatch
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

K = Path(__file__).resolve().parent.parent / "k8s"


def read(name: str) -> str:
    return (K / name).read_text(encoding="utf-8")


# rbac.yaml: ServiceAccount metadata names ending in -sa (the tier SAs; shop-deployer is excluded
# because it does not end in -sa). The metadata is on the line after `kind: ServiceAccount`.
rbac = set(re.findall(r"kind:\s*ServiceAccount\s*\n\s*metadata:\s*\{\s*name:\s*([a-z0-9-]+-sa)\b", read("rbac.yaml")))
# admission-sa-use.yaml CEL: variables.sa in ['web-sa', 'api-sa', 'db-sa']
adm_use = set(re.findall(r"'([a-z0-9-]+-sa)'", read("admission-sa-use.yaml")))
# kyverno-sa-use.yaml: value: ["web-sa", "api-sa", "db-sa"]
kyv = set(re.findall(r'"([a-z0-9-]+-sa)"', read("kyverno-sa-use.yaml")))
# admission-policy.yaml CEL: variables.sa == 'web-sa' (per tier)
adm_pol = set(re.findall(r"variables\.sa\s*==\s*'([a-z0-9-]+-sa)'", read("admission-policy.yaml")))

sources = {
    "rbac.yaml (defined)": rbac,
    "admission-sa-use.yaml (SA-use gate)": adm_use,
    "kyverno-sa-use.yaml (cluster-wide)": kyv,
    "admission-policy.yaml (label<->SA)": adm_pol,
}
print("Tier ServiceAccount sets across the identity TCB:")
for name, s in sources.items():
    print(f"  {name:42s} {sorted(s)}")

ref = rbac
drift = {name: s for name, s in sources.items() if s != ref}
if not rbac:
    print("\nFAIL: could not parse any tier SA from rbac.yaml (regex drift?)")
    sys.exit(1)
if drift:
    print("\nFAIL: tier-SA sets disagree (a gate is missing or extra a tier SA vs rbac.yaml):")
    for name, s in drift.items():
        print(f"  {name}: {sorted(s)}  (rbac has {sorted(ref)}; missing={sorted(ref - s)}, extra={sorted(s - ref)})")
    sys.exit(1)
print(f"\nPASS: all four sources gate exactly {sorted(ref)} - no tier-SA drift.")
sys.exit(0)
