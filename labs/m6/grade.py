"""M6 채점기 — agent-ABAC (Cedar 12/12) + ReBAC (OpenFGA fga model test 11/11).

    python labs/m6/grade.py            # 둘 다 채점 (졸업 = 둘 다 통과)
    python labs/m6/grade.py agent      # Part A 만
    python labs/m6/grade.py rebac      # Part B 만

agent: cedar/authz.py main(base) 하네스에 학습자 정책 + canonical agent schema/entities/
requests 를 묶어 평가(드리프트 0). rebac: 학습자 model.fga + canonical store.fga.yaml 을
docker openfga/cli 로 `model test`. docker 없으면 정직하게 SKIP.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "cedar"))


def grade_agent() -> int:
    try:
        from authz import main  # canonical harness
    except ImportError as e:
        print(f"의존성 누락({e}). 먼저: .venv\\Scripts\\python.exe -m pip install -r requirements-dev.txt "
              "(점검: scripts\\doctor.ps1)")
        return 2
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        shutil.copy(HERE / "agent-policies.cedar", base / "policies.cedar")
        for f in ("schema.json", "entities.json", "requests.json"):
            shutil.copy(ROOT / "cedar" / "agent" / f, base / f)
        print("== Part A: agent-ABAC (Cedar) ==")
        return main(base)


def grade_rebac() -> int:
    if shutil.which("docker") is None:
        print("== Part B: ReBAC == SKIP: docker 미설치 — Part B(11/11)는 채점되지 않았다.")
        return 2  # sentinel: skipped (not passed) — graduation gate must see this
    print("== Part B: ReBAC (OpenFGA fga model test) ==")
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        shutil.copy(HERE / "model.fga", base / "model.fga")
        shutil.copy(ROOT / "rebac" / "store.fga.yaml", base / "store.fga.yaml")
        proc = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{base}:/data", "openfga/cli:latest",
             "model", "test", "--tests", "/data/store.fga.yaml"],
            capture_output=True, text=True,
        )
        out = (proc.stdout + proc.stderr).strip()
        print(out)
        # `fga model test` exits 0 only when all checks pass.
        return 0 if proc.returncode == 0 else 1


if __name__ == "__main__":
    # Print Korean cleanly on cp949 (Korean Windows). The agent/all paths run authz.main()
    # (which reconfigures) first, but `grade.py rebac` does not — guard here so every path
    # is safe, including the docker-absent SKIP message.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    rc_agent = grade_agent() if which in ("agent", "all") else 0
    rc_rebac = None
    if which in ("rebac", "all"):
        if which == "all":
            print()
        rc_rebac = grade_rebac()

    if which == "all":
        if rc_agent == 0 and rc_rebac == 0:
            print("\nM6 GRADUATED — 위임 인가를 ABAC 교집합(Cedar)과 관계 그래프(ReBAC) 양쪽으로 구현했다. "
                  "정답지 diff: cedar/agent/policies.cedar, rebac/model.fga")
        elif rc_agent == 0 and rc_rebac == 2:
            # Part A passed but Part B was skipped — NOT graduated (only half graded).
            print("\nM6 Part A 통과(12/12). Part B(ReBAC)는 SKIP — Docker Desktop 필요 (labs/SETUP.md). "
                  "설치 후 재실행하면 11/11까지 채점되어 졸업.")
    # Exit nonzero only on a real FAIL (a skip is not a failure but is not graduation).
    fail = (rc_agent not in (0, None)) or (rc_rebac == 1)
    raise SystemExit(1 if fail else 0)
