#!/usr/bin/env python3
"""check-sync-wave-order.py — the 'identity-first' ordering invariant, as data (L5 / B7-B8).

Today the deploy order lives only in a shell comment ('Identity FIRST') in
.github/workflows/ci.yml: rbac/admission are applied before the workload, or the
ServiceAccount admission controller rejects pods that reference a not-yet-created SA. A
future contributor who reorders those two `kubectl apply` lines breaks it silently. M10
re-expresses the order as ArgoCD sync-wave annotations (gitops/apps/*.yaml), which makes it
a CHECKABLE artifact: this asserts identity-wave < workload-wave <= network-wave, no cluster
needed (regex, no yaml dep — twin of scripts/check-sa-consistency.py). That GitOps turns
ordering-from-tribal-knowledge into ordering-as-data is the whole point of L5.

    python scripts/check-sync-wave-order.py    # exit 1 if the wave order regresses
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

APPS = Path(__file__).resolve().parent.parent / "gitops" / "apps"
# logical tier -> the Application name that carries it:
TIERS = {"identity": "shop-identity", "workload": "shop-workload", "network": "shop-network-runtime"}


def _wave(path: Path) -> tuple[str, int] | None:
    t = path.read_text(encoding="utf-8")
    nm = re.search(r"(?m)^\s*name:\s*([\w-]+)", t)
    wv = re.search(r"argocd\.argoproj\.io/sync-wave:\s*['\"]?(-?\d+)['\"]?", t)
    if not nm or not wv:
        return None
    return nm.group(1), int(wv.group(1))


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    print("== L5: sync-wave order — identity-first invariant (static, no cluster) ==")
    waves: dict[str, int] = {}
    for p in sorted(APPS.glob("*.yaml")):
        w = _wave(p)
        if w is None:
            print(f"  FAIL  {p.name}: missing name or argocd.argoproj.io/sync-wave annotation")
            return 1
        waves[w[0]] = w[1]
        print(f"  {p.name}: {w[0]} -> wave {w[1]}")

    missing = [name for name in TIERS.values() if name not in waves]
    if missing:
        print(f"  FAIL  missing expected Application(s): {missing}")
        return 1

    ident, work, net = (waves[TIERS[k]] for k in ("identity", "workload", "network"))
    fail = 0

    def check(ok: bool, msg: str) -> None:
        nonlocal fail
        print(f"  {'PASS' if ok else 'FAIL'}  {msg}")
        if not ok:
            fail = 1

    check(ident < work, f"identity wave ({ident}) < workload wave ({work}) — SA exists before pods reference it")
    check(work <= net, f"workload wave ({work}) <= network/runtime wave ({net}) — policy attaches to existing pods")

    print("\nL5 " + ("PASS — sync-wave order encodes the identity-first invariant."
                     if not fail else "FAIL — sync-wave order regressed; SA-not-found / unguarded-pod window reopens."))
    return fail


if __name__ == "__main__":
    raise SystemExit(main())
