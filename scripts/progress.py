"""학습 진도 한눈에 — 무클러스터 모듈을 실제로 채점해 완료 상태를 표로 보여준다.

    python scripts/progress.py

각 무클러스터 그레이더(M0/M1/M6/M7)를 실제로 돌려 종료코드로 done/todo를 판정한다.
학습자 작업 파일(labs/<m>/)을 채점하므로, 빈 스켈레톤은 todo, 완성하면 done으로 바뀐다.
클러스터 모듈(M2-M5, M8)은 살아있는 kind 클러스터가 필요하므로 'cluster'로 표시한다
(scripts/up 세션에서 채점). 리포트 전용 — 항상 exit 0.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (label, argv, todo-힌트) — 같은 인터프리터로 실행.
# 재구현 가능한 무클러스터 모듈 (학습자 스켈레톤이 있어 진도에 집계).
NOCLUSTER = [
    ("M0  Cedar authz",        [sys.executable, "labs/m0/grade.py", "--ext"], "labs/m0/policies.cedar 재구현 (목표 11/11)"),
    ("M1  shift-left scan",    [sys.executable, "labs/m1/grade.py"],          "labs/m1/workload.yaml 16결함 수정 (Failed 0)"),
    ("M6  agent-ABAC+ReBAC",   [sys.executable, "labs/m6/grade.py"],          "labs/m6/{agent-policies.cedar,model.fga} (17/17+11/11; Part B=docker)"),
]
# 레퍼런스 모듈: 재구현 스켈레톤이 없음(읽고 실행) → 표시는 하되 진도에는 미집계.
REFERENCE = [
    ("M7  formal cross-layer", [sys.executable, "formal/cross_layer.py"]),
]
CLUSTER = [
    ("M2  identity VAP/CEL",   "bash labs/m2/grade.sh"),
    ("M3  Cilium netpol",      "bash labs/m3/grade.sh"),
    ("M4  Tetragon runtime",   "bash labs/m4/grade.sh"),
    ("M5  data encryption",    "bash labs/m5/grade.sh"),
    ("M8  kill-boundary",      "powershell -File scripts/verify-runtime-scope.ps1"),
    ("M9  assume-breach",      "bash labs/m9/grade.sh"),
]


def run(argv: list[str]) -> tuple[int | None, str, str]:
    try:
        p = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=300)
    except Exception as e:  # missing interpreter, timeout, etc.
        return None, f"실행 실패: {e}", ""
    full = p.stdout + "\n" + p.stderr
    last = ""
    for line in full.splitlines():
        if line.strip():
            last = line.strip()
    return p.returncode, last, full


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    print("\n  cloudsec-policy-stack — 학습 진도 (무클러스터 자동 채점)\n")
    done = 0
    for label, argv, hint in NOCLUSTER:
        rc, last, full = run(argv)
        if rc == 0 and "SKIP:" in full:          # e.g. M6 Part B skipped (no docker)
            print(f"  [ part ]  {label:<24}  {last[:72]}")
        elif rc == 0:
            done += 1
            print(f"  [ done ]  {label:<24}  {last[:72]}")
        else:
            print(f"  [ todo ]  {label:<24}  {hint}")

    print()
    for label, argv in REFERENCE:
        rc, last, _ = run(argv)
        status = last[:56] if rc == 0 else "실행 실패"
        print(f"  [ ref  ]  {label:<24}  {status}")
    print("            (M7 = reference 모듈 · 재구현 스켈레톤 없음 → 진도 미집계)\n")

    for label, how in CLUSTER:
        print(f"  [cluster] {label:<24}  {how}")

    print(f"\n  무클러스터 완료: {done}/{len(NOCLUSTER)}   ·   클러스터 모듈은 scripts/up 세션에서 채점")
    print("  전체 트랙·졸업 기준: labs/README.md\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
