#!/usr/bin/env python3
"""check-deployer-rbac.py — static least-privilege guard (no cluster) for LP7.

The shop-deployer Role (k8s/rbac.yaml) is the app-deploy principal (CI / operator). Least
privilege means it must NOT directly create pods (exec foothold), read secrets (theft), mint
serviceaccounts / edit roles+bindings (identity forge / privilege escalation), or hold a `*`
wildcard — and it must be a namespaced Role bound by a RoleBinding, never cluster-scoped. This
asserts exactly that against the policy file (regex, no yaml dep — twin of check-sa-consistency.py),
so a future rule that widens the deployer (e.g. adds `secrets`) fails CI instead of silently
regressing least-privilege. Static policy assertion, like the cross-layer/SA-consistency checks.

    python scripts/check-deployer-rbac.py     # exit 1 on any least-privilege violation
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

RBAC = Path(__file__).resolve().parent.parent / "k8s" / "rbac.yaml"
ROLE = "shop-deployer"
# resources a least-privilege app-deployer must never hold:
FORBIDDEN = {"pods", "pods/exec", "pods/attach", "secrets", "serviceaccounts",
             "roles", "rolebindings", "clusterroles", "clusterrolebindings"}
# the placeholder deploy groups bound to shop-deployer (k8s/rbac.yaml RoleBindings):
GROUPS = ["shop:deployers", "shop:tier-operators"]


def _docs(text: str) -> list[str]:
    return re.split(r"(?m)^---\s*$", text)


def _kind(d: str) -> str:
    m = re.search(r"(?m)^\s*kind:\s*([A-Za-z]+)", d)
    return m.group(1) if m else ""


def _has_name(d: str, name: str) -> bool:
    return re.search(r"name:\s*" + re.escape(name) + r"\b", d) is not None


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    text = RBAC.read_text(encoding="utf-8")
    ds = _docs(text)
    fail = 0
    print(f"== LP7: {ROLE} least-privilege (static, no cluster) ==")

    if any(_kind(d) == "ClusterRole" and _has_name(d, ROLE) for d in ds):
        print(f"  FAIL  {ROLE} is a ClusterRole — app-deploy must be a namespaced Role")
        return 1
    role_blocks = [d for d in ds if _kind(d) == "Role" and _has_name(d, ROLE)]
    if not role_blocks:
        print(f"  FAIL  Role {ROLE} not found in k8s/rbac.yaml")
        return 1
    block = role_blocks[0]

    held: set[str] = set()
    wildcard = False
    for arr in re.findall(r"resources:\s*\[([^\]]*)\]", block):
        held.update(re.findall(r"[\w./*-]+", arr))
    for arr in re.findall(r"(?:verbs|apiGroups|resources):\s*\[([^\]]*)\]", block):
        if "*" in arr:
            wildcard = True

    def check(ok: bool, msg: str) -> None:
        nonlocal fail
        print(f"  {'PASS' if ok else 'FAIL'}  {msg}")
        if not ok:
            fail = 1

    bad = sorted(held & FORBIDDEN)
    check(not bad, f"no forbidden resources (pods/secrets/serviceaccounts/roles) — found: {bad or 'none'}")
    check(not wildcard, "no '*' wildcard in resources/verbs/apiGroups")
    crb = [d for d in ds if _kind(d) == "ClusterRoleBinding" and _has_name(d, ROLE)]
    check(not crb, f"bound only by a namespaced RoleBinding (no ClusterRoleBinding) — found {len(crb)}")

    print(f"  granted resources: {sorted(held)}")
    print("\nLP7 " + ("PASS — holds no pods/secrets/SA/wildcard, namespaced only."
                       if not fail else f"FAIL — {ROLE} exceeds least-privilege; tighten k8s/rbac.yaml."))
    return fail


def _can_i(verb: str, resource: str, group: str, ns: str = "shop") -> bool:
    r = subprocess.run(["kubectl", "auth", "can-i", verb, resource, "-n", ns,
                        "--as", "lp7-probe", "--as-group", group],
                       capture_output=True, text=True)
    return r.stdout.strip() == "yes"


def live_check() -> int:
    """Effective-RBAC proof on the running cluster: what the deployer groups can ACTUALLY do
    (aggregates EVERY binding, not just this file's text — answers the 'static text-check is
    necessary-not-sufficient' critique). Needs a reachable cluster; SKIPs (not FAILs) without one."""
    print("\n== LP7 LIVE: kubectl auth can-i — effective RBAC of the deployer groups ==")
    if shutil.which("kubectl") is None or subprocess.run(
            ["kubectl", "cluster-info"], capture_output=True).returncode != 0:
        print("  SKIP  no reachable cluster — the live proof runs in the CI integration job "
              "(after `kubectl apply -f k8s/rbac.yaml`: python scripts/check-deployer-rbac.py --live)")
        return 0
    fail = 0
    deny = [("create", "pods"), ("get", "secrets"), ("create", "serviceaccounts"),
            ("create", "rolebindings")]
    for g in GROUPS:
        for verb, res in deny:
            allowed = _can_i(verb, res, g)
            print(f"  {'PASS' if not allowed else 'FAIL'}  {g}: cannot {verb} {res}  (can-i={'yes' if allowed else 'no'})")
            if allowed:
                fail = 1
        works = _can_i("create", "deployments", g)
        print(f"  {'PASS' if works else 'FAIL'}  {g}: CAN create deployments (Role bound + effective)  (can-i={'yes' if works else 'no'})")
        if not works:
            fail = 1
    print("\nLP7 LIVE " + ("PASS — deployer groups hold no pods/secrets/SA/rolebindings, only deploy verbs (effective RBAC)."
                           if not fail else "FAIL — a deployer group has more effective RBAC than least-privilege permits."))
    return fail


if __name__ == "__main__":
    rc = main()
    if "--live" in sys.argv:
        rc = rc or live_check()
    raise SystemExit(rc)
