#!/usr/bin/env python3
"""check_negatives_test.py — who tests the test? (no cluster)

The four static drift-guards (scripts/check-*.py) run once against the KNOWN-GOOD
repo files in CI / `make test` and report PASS. But a guard that *always* returned
PASS would look identical in that CI step. This proves each one actually FAILs on a
KNOWN-BAD version of the same artifact — the catch-known-bad / pass-known-good shape
already used by scripts/verify-gitleaks.sh (SL2) and the SL4 trivy gate.

For each guard it: (1) copies the guard + its real inputs into a temp tree, runs it
on the UNMUTATED copy and asserts exit 0 (pass-known-good); then (2) mutates one input
to violate exactly the invariant the guard asserts and re-runs it, asserting a NON-zero
exit (catch-known-bad). The guards resolve their inputs via __file__.parent.parent, so
running the copy from temp/scripts/ reads temp/k8s + temp/gitops — no repo file is
touched and no cluster is needed.

    python scripts/check_negatives_test.py   # exit 1 if any guard fails to catch its bad case

(Scope: the static no-cluster guards that gate VERIFIED rows in the CI policy job.
cedar/authz.py, agent_authz.py, auth_test.py and formal/cross_layer_test.py already
carry their own falsifiable/negative tests; the cluster verifiers fail-closed on a
half-up stack via the empty-IP guards. Lab grade.py negative cases are a follow-up.)
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _mut_sa(d: Path) -> None:
    """Add a tier ServiceAccount to rbac.yaml that no identity gate knows about -> drift."""
    p = d / "k8s" / "rbac.yaml"
    p.write_text(p.read_text(encoding="utf-8") +
                 "\n---\nkind: ServiceAccount\nmetadata: { name: drift-sa }\n", encoding="utf-8")


def _mut_deployer(d: Path) -> None:
    """Bind shop-deployer with a ClusterRoleBinding -> no longer namespaced-only."""
    p = d / "k8s" / "rbac.yaml"
    p.write_text(p.read_text(encoding="utf-8") +
                 "\n---\nkind: ClusterRoleBinding\nmetadata: { name: shop-deployer }\n", encoding="utf-8")


def _mut_reconciler(d: Path) -> None:
    """Add a '*' allow-all line to the AppProject -> wildcard footgun."""
    p = d / "gitops" / "projects" / "shop-project.yaml"
    p.write_text(p.read_text(encoding="utf-8") + "\n  - '*'\n", encoding="utf-8")


def _mut_wave(d: Path) -> None:
    """Push the identity sync-wave AFTER the workload -> SA-not-found window reopens."""
    for f in (d / "gitops" / "apps").glob("*.yaml"):
        t = f.read_text(encoding="utf-8")
        if re.search(r"(?m)^\s*name:\s*shop-identity\b", t):
            f.write_text(re.sub(r"(argocd\.argoproj\.io/sync-wave:\s*['\"]?)(-?\d+)(['\"]?)",
                                r"\g<1>99\3", t, count=1), encoding="utf-8")
            return
    raise RuntimeError("fixture error: could not find the shop-identity Application to mutate")


# (guard, real inputs to copy, mutation that must trip it, human description of the bad case)
SPECS = [
    ("check-sa-consistency.py",
     ["k8s/rbac.yaml", "k8s/admission-sa-use.yaml", "k8s/kyverno-sa-use.yaml", "k8s/admission-policy.yaml"],
     _mut_sa, "a tier SA exists in rbac.yaml but not in the gates"),
    ("check-deployer-rbac.py", ["k8s/rbac.yaml"],
     _mut_deployer, "shop-deployer bound by a ClusterRoleBinding"),
    ("check-reconciler-rbac.py", ["gitops/projects/shop-project.yaml"],
     _mut_reconciler, "a '*' allow-all in the AppProject"),
    ("check-sync-wave-order.py", ["gitops/apps"],
     _mut_wave, "identity sync-wave moved after workload"),
]


def _run(grader: Path) -> int:
    return subprocess.run([sys.executable, str(grader)], capture_output=True, text=True,
                          encoding="utf-8", errors="replace").returncode


def _stage(tmp: Path, grader_name: str, inputs: list[str]) -> Path:
    (tmp / "scripts").mkdir(parents=True, exist_ok=True)
    shutil.copy(ROOT / "scripts" / grader_name, tmp / "scripts" / grader_name)
    for rel in inputs:
        src, dst = ROOT / rel, tmp / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, dst, dirs_exist_ok=True) if src.is_dir() else shutil.copy(src, dst)
    return tmp / "scripts" / grader_name


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    print("== who tests the test? — negative-fixture proof for the static drift-guards ==")
    fails = 0
    for grader_name, inputs, mutate, desc in SPECS:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            grader = _stage(tmp, grader_name, inputs)
            good = _run(grader)        # pass-known-good: real file -> must exit 0
            mutate(tmp)
            bad = _run(grader)         # catch-known-bad: violating file -> must exit != 0
        ok = good == 0 and bad != 0
        fails += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  {grader_name:28s} "
              f"good=exit{good} (pass-known-good) | bad=exit{bad} (catch: {desc})")
        if good != 0:
            print(f"        ! pass-known-good FAILED — the guard rejected the REAL file (exit {good})")
        if bad == 0:
            print(f"        ! catch-known-bad FAILED — the guard PASSED a violating file; "
                  f"it does not actually enforce its invariant")
    print(f"\n{'PASS' if not fails else 'FAIL'}: {len(SPECS) - fails}/{len(SPECS)} static guards "
          f"proven to catch their bad case (and pass the good).")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
