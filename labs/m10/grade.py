#!/usr/bin/env python3
"""grade.py — M10 무클러스터 채점기 (학습자의 application.yaml 정적 검증).

졸업-critical 절반: 클러스터 없이 학습자가 채운 labs/m10/application.yaml의 load-bearing 필드를
canonical(gitops/apps/network-runtime.yaml) 기준으로 채점한다. regex (no yaml dep — check-deployer-rbac.py
스타일). 라이브 절반(drift 자동교정·fighting-controllers)은 labs/m10/grade.sh.

    python labs/m10/grade.py        # 스켈레톤(__TODO__)은 FAIL, 올바르게 채우면 PASS
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

APP = Path(__file__).resolve().parent / "application.yaml"
# 이 App은 network-runtime child = wave 1, project shop, namespace shop, prune+selfHeal true.
EXPECT = {"wave": "1", "project": "shop", "namespace": "shop"}


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    t = APP.read_text(encoding="utf-8")
    fail = 0
    print("== M10 (무클러스터) — application.yaml 정적 채점 ==")

    def check(ok: bool, msg: str) -> None:
        nonlocal fail
        print(f"  {'PASS' if ok else 'FAIL'}  {msg}")
        if not ok:
            fail = 1

    if "__TODO" in t:
        print("  …아직 __TODO__가 남아있다. README/LEARN을 보고 채워라.")

    check(re.search(r"(?m)^kind:\s*Application", t) is not None, "kind: Application")

    m = re.search(r"sync-wave:\s*['\"]?(-?\d+|__TODO\w*__)['\"]?", t)
    wave = m.group(1) if m else None
    check(wave == EXPECT["wave"], f"sync-wave == \"{EXPECT['wave']}\" (network는 가장 나중) — got {wave!r}")

    m = re.search(r"(?m)^\s*project:\s*([\w-]+)", t)
    proj = m.group(1) if m else None
    check(proj == EXPECT["project"], f"project == {EXPECT['project']} (cluster-admin 금지, AppProject 최소권한) — got {proj!r}")

    m = re.search(r"namespace:\s*([\w-]+)\s*$", t, re.M)
    # destination.namespace = the LAST namespace: in the file (metadata.namespace=argocd is first)
    ns = re.findall(r"namespace:\s*([\w-]+)", t)
    dest_ns = ns[-1] if ns else None
    check(dest_ns == EXPECT["namespace"], f"destination.namespace == {EXPECT['namespace']} — got {dest_ns!r}")

    prune = re.search(r"prune:\s*(true|false|__TODO\w*__)", t)
    check(prune and prune.group(1) == "true", f"syncPolicy.automated.prune == true — got {prune.group(1) if prune else None!r}")

    self_heal = re.search(r"selfHeal:\s*(true|false|__TODO\w*__)", t)
    sh = self_heal.group(1) if self_heal else None
    check(sh == "true", f"syncPolicy.automated.selfHeal == true (drift 자동교정 ON; false면 공격자 patch 생존) — got {sh!r}")

    print("\nM10 정적 " + ("PASS — application.yaml이 canonical과 정합(L1 selfHeal·L5 sync-wave). "
                          "이제 라이브: bash labs/m10/grade.sh"
                          if not fail else "FAIL — 위 빈칸을 채워라. 정답지: gitops/apps/network-runtime.yaml (졸업 후 diff)."))
    return fail


if __name__ == "__main__":
    raise SystemExit(main())
