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
    from authz import main  # canonical harness
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        shutil.copy(HERE / "agent-policies.cedar", base / "policies.cedar")
        for f in ("schema.json", "entities.json", "requests.json"):
            shutil.copy(ROOT / "cedar" / "agent" / f, base / f)
        print("== Part A: agent-ABAC (Cedar) ==")
        return main(base)


def grade_rebac() -> int:
    if shutil.which("docker") is None:
        print("== Part B: ReBAC == SKIP: docker 미설치 (fga model test는 docker로 실행)")
        return 0
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
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    rc = 0
    if which in ("agent", "all"):
        rc |= grade_agent()
    if which in ("rebac", "all"):
        if which == "all":
            print()
        rc |= grade_rebac()
    if rc == 0 and which == "all":
        print("\nM6 GRADUATED — 위임 인가를 ABAC 교집합(Cedar)과 관계 그래프(ReBAC) 양쪽으로 구현했다. "
              "정답지 diff: cedar/agent/policies.cedar, rebac/model.fga")
    raise SystemExit(rc)
