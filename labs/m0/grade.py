"""M0 채점기 — labs/m0/policies.cedar (학습자 작성분)를 canonical 스키마/엔티티/시나리오로 평가.

    python labs/m0/grade.py          # core 8 시나리오 (cedar/requests.json 그대로)
    python labs/m0/grade.py --ext    # 졸업: core 8 + ext 3 (labs/m0/requests-ext.json)

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

from authz import main  # noqa: E402  (after sys.path tweak)


def grade(ext: bool) -> int:
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        shutil.copy(HERE / "policies.cedar", base / "policies.cedar")
        shutil.copy(ROOT / "cedar" / "schema.json", base / "schema.json")
        shutil.copy(ROOT / "cedar" / "entities.json", base / "entities.json")
        requests = json.loads((ROOT / "cedar" / "requests.json").read_text(encoding="utf-8"))
        if ext:
            requests += json.loads((HERE / "requests-ext.json").read_text(encoding="utf-8"))
        (base / "requests.json").write_text(json.dumps(requests), encoding="utf-8")
        rc = main(base)
    if rc == 0:
        print("\nM0 " + ("GRADUATED — 정답지와 diff 리뷰로 마무리하라 (README 졸업 기준)"
                          if ext else "core CLEAR — 졸업 채점은 --ext"))
    return rc


if __name__ == "__main__":
    raise SystemExit(grade("--ext" in sys.argv[1:]))
