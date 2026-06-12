"""M1 채점기 — labs/m1/workload.yaml 을 checkov로 스캔, Failed checks: 0 이면 졸업.

    python labs/m1/grade.py

checkov를 venv 모듈 엔트리(`python -m checkov.main`)로 호출한다(scan.ps1과 동일 — 콘솔
스크립트 shim보다 견고). 졸업 조건: Failed checks == 0. 추가로 '스킵 주석으로 덮기' 꼼수를
감지해 경고한다(은폐는 사냥이 아니다 — README의 triage 교훈).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORKLOAD = HERE / "workload.yaml"
CFG = HERE / ".checkov.yaml"


def main() -> int:
    # Cheating guard: inline checkov skip annotations hide a finding instead of fixing it.
    text = WORKLOAD.read_text(encoding="utf-8")
    sneaky = re.findall(r"checkov\.io/skip|checkov:skip", text)
    if sneaky:
        print(f"⚠  workload.yaml에 스킵 주석 {len(sneaky)}개 발견 — 은폐가 아니라 *수정*하라 "
              f"(하든드 워크로드에는 스킵 주석이 필요 없다). 그래도 채점은 진행한다.\n")

    proc = subprocess.run(
        [sys.executable, "-m", "checkov.main", "-f", str(WORKLOAD),
         "--config-file", str(CFG), "--compact"],
        capture_output=True, text=True,
    )
    out = proc.stdout + proc.stderr
    m = re.search(r"Failed checks:\s*(\d+)", out)
    if not m:
        print("checkov 출력을 해석하지 못했습니다. 원문:\n" + out[-1500:])
        return 2
    failed = int(m.group(1))
    summary = re.search(r"Passed checks:.*", out)
    print(summary.group(0) if summary else f"Failed checks: {failed}")

    if failed == 0:
        print("\nM1 GRADUATED — 16개 위반을 전부 *수정*했다. "
              "참고 하든드 패턴: k8s/app.yaml 의 web/api/db 워크로드(같은 securityContext 구조)를 "
              "내 답과 비교해 보라.")
        return 0
    # Show which checks still fail, so the hunt is guided.
    print(f"\n아직 {failed}개 남았다. 남은 위반:")
    for cid, desc in re.findall(r'Check:\s*(CKV[0-9A-Z_]+):\s*"([^"]+)"', out):
        print(f"  - {cid}: {desc}")
    print("\n각 CKV의 의미·수정법은 labs/m1/README.md 표를 보라. 한 번에 하나씩.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
