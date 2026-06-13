"""M0 채점기 — labs/m0/policies.cedar (학습자 작성분)를 canonical 스키마/엔티티/시나리오로 평가.

    python labs/m0/grade.py          # core 8 시나리오 (cedar/requests.json 그대로)
    python labs/m0/grade.py --ext    # 졸업: core 8 + ext 3 (labs/m0/requests-ext.json)
    python labs/m0/grade.py --hint   # FAIL 행마다 어느 요건(R1~R4/E1)인지 개념 넛지 (정답은 아님)

cedar/authz.py 의 main(base) 하네스를 그대로 재사용한다 — 학습자 정책 + canonical
schema/entities/requests 를 임시 디렉터리에 모아 평가하므로, canonical 파일은 절대
건드리지 않고 드리프트도 없다.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "cedar"))

try:
    from authz import main  # noqa: E402  (after sys.path tweak)
except ImportError as _e:
    print(f"의존성 누락({_e}). 먼저 설치하세요:\n"
          "  .venv\\Scripts\\python.exe -m pip install -r requirements-dev.txt\n"
          "  (환경 점검: scripts\\doctor.ps1 · 자세히: labs/SETUP.md)")
    raise SystemExit(2)

# 개념 넛지(정답이 아님) — 시나리오 이름 → 어느 요건이고 무엇을 점검할지. --hint 일 때만 출력.
HINTS = {
    "owner views own account": "R1(조회): ViewAccount permit이 있나? 소유자만 — principal == resource.owner.",
    "non-owner views another's account": "R1: 이건 Deny가 정답. Allow면 소유자 조건이 빠진 것.",
    "owner transfers within limit": "R2(이체): Transfer permit + 소유자 && 양수 && 한도 이하.",
    "owner transfers OVER limit": "R2: 한도 초과는 Deny — amount <= principal.transferLimit 확인.",
    "owner transfers a NEGATIVE amount (value extraction)": "R2: 음수는 Deny — amount > 0 가드 확인.",
    "transfer from FROZEN account (forbid overrides)": "R4(동결): forbid + resource.frozen == true. forbid가 permit보다 우선.",
    "auditor reads audit log": "R3(감사): ViewAuditLog permit — principal in Role::\"auditor\".",
    "customer reads audit log (no role)": "R3: 역할 없는 고객은 Deny가 정답.",
    "EXT1: auditor views ANOTHER user's account (E1)": "E1: auditor가 남의 계좌 조회 Allow — 역할 기반 ViewAccount permit.",
    "EXT2: auditor must NOT be able to transfer (over-grant catch)": "E1 과잉허용: auditor에게 Transfer까지 열렸나? E1은 조회만.",
    "EXT3: transfer of EXACTLY the limit (1000) is allowed (boundary)": "R2 경계: <= 인지 < 인지. 정확히 한도면 허용.",
}


def grade(ext: bool, hint: bool) -> int:
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        shutil.copy(HERE / "policies.cedar", base / "policies.cedar")
        shutil.copy(ROOT / "cedar" / "schema.json", base / "schema.json")
        shutil.copy(ROOT / "cedar" / "entities.json", base / "entities.json")
        requests = json.loads((ROOT / "cedar" / "requests.json").read_text(encoding="utf-8"))
        if ext:
            requests += json.loads((HERE / "requests-ext.json").read_text(encoding="utf-8"))
        (base / "requests.json").write_text(json.dumps(requests), encoding="utf-8")
        rc = main(base, hint_map=HINTS if hint else None)
    if rc == 0:
        print("\nM0 " + ("GRADUATED — 정답지와 diff 리뷰로 마무리하라 (README 졸업 기준)"
                          if ext else "core CLEAR — 졸업 채점은 --ext"))
    elif not hint:
        print("\n막히면: `python labs/m0/grade.py --hint` 로 FAIL 행마다 요건 넛지를 본다.")
    return rc


if __name__ == "__main__":
    args = sys.argv[1:]
    raise SystemExit(grade("--ext" in args, "--hint" in args))
