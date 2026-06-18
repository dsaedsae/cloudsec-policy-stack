#!/usr/bin/env python3
"""grade.py — M11 무클러스터 채점기: LSM exec-allowlist 정책 구조 검증 + 핵심 개념 확인.

라이브 절반(labs/m11/grade.sh)은 BPF-LSM 커널이 있어야 하고 kind에선 대개 SKIP이다. 이 무클러스터
절반은 정책이 *올바른 메커니즘*을 쓰는지 정적으로 채점한다(regex, no yaml dep — check-* 스타일):
LSM bprm 훅 + 적재-이미지 matchArgs(caller matchBinaries 아님) + Sigkill + 테스트 라벨 한정.

    python labs/m11/grade.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

POLICY = Path(__file__).resolve().parent / "tracingpolicy-lsm-exec-allowlist.yaml"


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    t = POLICY.read_text(encoding="utf-8")
    fail = 0
    print("== M11 (무클러스터) — LSM exec-allowlist 정책 구조 채점 ==")

    def check(ok: bool, msg: str) -> None:
        nonlocal fail
        print(f"  {'PASS' if ok else 'FAIL'}  {msg}")
        if not ok:
            fail = 1

    check(re.search(r"(?m)^kind:\s*TracingPolicy", t) is not None, "kind: TracingPolicy")
    check(re.search(r"(?m)^\s*lsmhooks:", t) is not None,
          "lsmhooks 사용 (syscall kprobe가 아니라 LSM 레이어)")
    check(re.search(r"hook:\s*['\"]?bprm_check_security", t) is not None,
          "hook = bprm_check_security (적재되는 이미지를 보는 LSM exec 훅)")
    check(re.search(r"type:\s*['\"]?linux_binprm", t) is not None,
          "arg type = linux_binprm (호출자 아닌 *적재 이미지*)")
    # the senior point: the allowlist keys on the LOADED-image path (matchArgs), NOT the caller
    # (matchBinaries). matchBinaries for an exec allowlist is backwards (ADR 0001).
    check(re.search(r"matchArgs:", t) is not None,
          "허용목록을 matchArgs(적재-이미지 경로)로 — caller matchBinaries로 거는 함정 회피")
    check(re.search(r"action:\s*Sigkill", t) is not None,
          "matchActions: Sigkill (prevention-grade는 Override -> EPERM, 헤더 주석)")
    check(re.search(r"matchLabels:\s*\{?\s*lab:\s*m11-lsm", t) is not None,
          "테스트 라벨(lab: m11-lsm)에만 적용 — shipped web/api/db 불간섭")

    print("\nM11 정적 " + ("PASS — 메커니즘이 옳다: LSM bprm + 적재-이미지 matchArgs(=caller/arg0 함정 회피). "
                          "라이브 증명은 BPF-LSM 커널에서 grade.sh (kind는 SKIP-prone)."
                          if not fail else "FAIL — 위 구조를 맞춰라(정답: caller가 아닌 적재-이미지를 보는 LSM 훅)."))
    return fail


if __name__ == "__main__":
    raise SystemExit(main())
