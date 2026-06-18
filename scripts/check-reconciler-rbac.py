#!/usr/bin/env python3
"""check-reconciler-rbac.py — static least-privilege guard for the GitOps reconciler (L3 / B8).

The Argo reconciler that may apply RBAC / NetworkPolicy / admission policy IS the new
identity-TCB (B7 relocated -> B8): a cluster-admin reconciler could mint `app:api`, rewrite
the VAP that guards it, and revert your incident-response edit. So its blast radius — the
AppProject `shop` (gitops/projects/shop-project.yaml) — must stay least-privilege, exactly
as shop:tier-operators was. This asserts that statically (regex, no yaml dep — twin of
scripts/check-deployer-rbac.py); `--live` proves the EFFECTIVE grant on a running cluster
via `kubectl auth can-i --as ...argocd-application-controller` (the opt-in half, like
check-deployer-rbac.py --live).

    python scripts/check-reconciler-rbac.py            # static; exit 1 on any violation
    python scripts/check-reconciler-rbac.py --live     # + effective-RBAC proof (needs a cluster)
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

PROJ = Path(__file__).resolve().parent.parent / "gitops" / "projects" / "shop-project.yaml"
ALLOWED_NS = {"shop", "argocd"}
# the reconciler must NEVER be granted these (self-escalation / identity-mint / theft):
FORBIDDEN_CLUSTER = {"ClusterRole", "ClusterRoleBinding"}
FORBIDDEN_NS = {"Secret", "ClusterRole", "ClusterRoleBinding"}
RECONCILER = "system:serviceaccount:argocd:argocd-application-controller"


def _section(text: str, key: str) -> str:
    """Body of a 2-space-indented spec key (`  key:`) until the next such key or EOF."""
    m = re.search(r"(?m)^  " + re.escape(key) + r":\s*$(.*?)(?=^  \w|\Z)", text, re.S)
    return m.group(1) if m else ""


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    text = PROJ.read_text(encoding="utf-8")
    fail = 0
    print("== L3: shop AppProject — reconciler least-privilege (static, no cluster) ==")

    if not re.search(r"(?m)^kind:\s*AppProject", text):
        print(f"  FAIL  {PROJ.name} is not an AppProject")
        return 1

    def check(ok: bool, msg: str) -> None:
        nonlocal fail
        print(f"  {'PASS' if ok else 'FAIL'}  {msg}")
        if not ok:
            fail = 1

    # 1) no allow-all wildcard anywhere (a '*' source / destination namespace = the footgun)
    wild = re.findall(r"(?m)(?:namespace|name|server):\s*['\"]?\*['\"]?\s*$", text) + \
        re.findall(r"(?m)^\s*-\s*['\"]?\*['\"]?\s*$", text)
    check(not wild, f"no '*' allow-all in sourceRepos/destinations — found: {wild or 'none'}")

    # 2) destinations namespaces are a subset of {shop, argocd}
    dest = _section(text, "destinations")
    ns = set(re.findall(r"namespace:\s*([\w-]+)", dest))
    bad_ns = sorted(ns - ALLOWED_NS)
    check(ns and not bad_ns, f"destinations limited to {sorted(ALLOWED_NS)} — found: {sorted(ns) or 'none'}")

    # 3) clusterResourceWhitelist grants no ClusterRole/ClusterRoleBinding (no self-escalation)
    cw = _section(text, "clusterResourceWhitelist")
    cw_bad = sorted({k for k in FORBIDDEN_CLUSTER if re.search(r"kind:\s*" + k + r"\b", cw)})
    check(not cw_bad, f"clusterResourceWhitelist holds no ClusterRole(Binding) — found: {cw_bad or 'none'}")

    # 4) the reconciler cannot mint Secrets / bind ClusterRoles in-namespace: those kinds must
    #    be absent from the namespace whitelist AND present in the blacklist.
    nw = _section(text, "namespaceResourceWhitelist")
    nb = _section(text, "namespaceResourceBlacklist")
    nw_bad = sorted({k for k in FORBIDDEN_NS if re.search(r"kind:\s*" + k + r"\b", nw)})
    check(not nw_bad, f"namespaceResourceWhitelist holds no Secret/ClusterRole(Binding) — found: {nw_bad or 'none'}")
    check(re.search(r"kind:\s*Secret\b", nb) is not None,
          "namespaceResourceBlacklist explicitly denies Secret (defense in depth)")

    print("\nL3 STATIC " + ("PASS — reconciler scope is least-privilege (no '*', ns-scoped, no CRB/Secret)."
                            if not fail else "FAIL — the AppProject grants the reconciler more than least-privilege."))
    return fail


def _can_i(verb: str, resource: str, ns: str | None = None) -> bool:
    cmd = ["kubectl", "auth", "can-i", verb, resource, "--as", RECONCILER]
    if ns:
        cmd += ["-n", ns]
    return subprocess.run(cmd, capture_output=True, text=True).stdout.strip() == "yes"


def live_check() -> int:
    print("\n== L3 LIVE: kubectl auth can-i — effective RBAC of the reconciler ==")
    if shutil.which("kubectl") is None or subprocess.run(
            ["kubectl", "cluster-info"], capture_output=True).returncode != 0:
        print("  SKIP  no reachable cluster — the live proof runs in the opt-in gitops job "
              "(enable-gitops.sh, then: python scripts/check-reconciler-rbac.py --live)")
        return 0
    fail = 0

    def a(ok: bool, msg: str) -> None:
        nonlocal fail
        print(f"  {'PASS' if ok else 'FAIL'}  {msg}")
        if not ok:
            fail = 1

    # bounded TIGHT, not BROKEN: cannot self-escalate / steal, but CAN do its job.
    a(not _can_i("create", "clusterrolebindings"), "cannot create clusterrolebindings (no self-escalation)")
    a(not _can_i("get", "secrets", "kube-system"), "cannot get kube-system secrets (no theft)")
    a(_can_i("patch", "ciliumnetworkpolicies", "shop"), "CAN patch ciliumnetworkpolicies in shop (drift-revert works)")
    print("\nL3 LIVE " + ("PASS — reconciler grant is tight, not broken (bounded effective RBAC)."
                          if not fail else "FAIL — reconciler effective RBAC exceeds its least-privilege scope."))
    return fail


if __name__ == "__main__":
    rc = main()
    if "--live" in sys.argv:
        rc = rc or live_check()
    raise SystemExit(rc)
