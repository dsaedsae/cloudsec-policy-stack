"""tutor_server.py — cloudsec-tutor MCP server (local stdio).

Answer-leak-proof Socratic learning tools for the cloudsec-policy-stack re-implementation
track. Run it in YOUR clone; connect an MCP client (Claude Desktop, etc.). The exposed tools
are progress / grade-result+hint / read-OK spec / answer-stripped lesson + the Socratic
prompt — there is NO tool that reads an answer key, so an AI reaching the repo ONLY through
this server cannot leak the solution (a stronger firewall than the TUTOR.md prompt alone).
Honest scope + residuals: mcp/README.md.

    python mcp/tutor_server.py        # stdio server

(`mcp` SDK: see requirements-mcp.txt. The graders need this repo + the .venv from
requirements-dev.txt; cluster modules SKIP — they need a kind cluster, run them in a
scripts/up session.)
"""
from __future__ import annotations

import re
import subprocess
import sys

from mcp.server.fastmcp import FastMCP

import firewall as fw  # same directory (mcp/)

ROOT = fw.ROOT
PY = sys.executable
mcp = FastMCP("cloudsec-tutor")


def _run(argv: list[str], timeout: int = 180) -> str:
    try:
        p = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        return (p.stdout or "") + (("\n" + p.stderr) if p.stderr.strip() else "")
    except Exception as e:  # missing interpreter, timeout, etc.
        return f"(실행 실패: {e})"


@mcp.tool()
def list_progress() -> str:
    """무클러스터 모듈(M0/M1/M6/M7)을 실제 채점해 done/todo 진도 + 다음 단계를 보여준다. 정답 없음."""
    return _run([PY, "scripts/progress.py"]) + \
        "\n(클러스터 모듈 M2–M5·M8–M11은 scripts/up 세션에서 — grade()가 안내한다.)"


@mcp.tool()
def grade(module: str) -> str:
    """모듈 채점기를 실행해 점수/PASS·FAIL + (실패 시) 요건 힌트를 반환한다. 정답지·canonical diff는 절대 반환하지 않는다(채점기 출력은 점수·시나리오표·힌트뿐)."""
    module = module.lower().strip()
    m = fw.MODULES.get(module)
    if not m:
        return f"모듈 미상: {module!r}. 사용 가능: {', '.join(fw.MODULES)}"
    if module not in fw.NOCLUSTER:
        return (f"M{module[1:]} ({m['title']})는 클러스터 모듈 — MCP에서 직접 채점하지 않는다.\n"
                f"  scripts/up 세션을 띄운 뒤:  {m.get('cluster_cmd')}\n"
                f"  (정확한 절차는 runbooks/00-lab-cluster-session.md · labs/SETUP.md)")
    return _run([PY] + list(m["grader"]))


@mcp.tool()
def hint(module: str) -> str:
    """채점기의 --hint 수준 요건 넛지만 반환한다(코드/정답이 아님 — 채점기가 스스로 '정답은 아님'이라 명시하는 그 고도)."""
    module = module.lower().strip()
    m = fw.MODULES.get(module)
    if not m:
        return f"모듈 미상: {module!r}"
    if module not in fw.NOCLUSTER:
        return f"M{module[1:]}는 클러스터 모듈 — README의 힌트/구두문답을 보라(read_lesson)."
    grader = list(m.get("grader") or [])
    if grader and grader[0].endswith("grade.py"):
        return _run([PY] + grader + ["--hint"])
    return "이 모듈 채점기엔 --hint가 없다 — read_lesson(README)를 참고하라."


@mcp.tool()
def read_spec(module: str) -> str:
    """모듈이 *대상으로 작성*하는 열람-OK 스펙(cedar schema/entities/requests, probes 등)을 반환한다. 정답지가 아니라 '무엇을 만들지'의 문제 정의다."""
    module = module.lower().strip()
    m = fw.MODULES.get(module)
    if not m:
        return f"모듈 미상: {module!r}"
    specs = list(m.get("spec") or [])
    if not specs:
        return f"M{module[1:]}는 별도 스펙 파일이 없다 — read_lesson + README의 요건표를 보라."
    return "\n\n".join(f"### {s}\n```\n{fw.read_guarded(s)}\n```" for s in specs)


@mcp.tool()
def read_lesson(module: str) -> str:
    """모듈 README(접힌 구두문답 *답*은 제거됨) + 개념랩 docs 포인터를 반환한다. 정답지·접힌-답·LEARN.md(떠먹여주기)는 노출하지 않는다."""
    module = module.lower().strip()
    m = fw.MODULES.get(module)
    if not m:
        return f"모듈 미상: {module!r}"
    parts = [fw.redact_lesson(fw.read_guarded(f)) for f in (m.get("lesson") or [])]
    doc = m.get("lesson_doc")
    if doc:
        parts.append(f"> 개념 읽기: `{doc}` (공개 사이트에서도 열람 — 재구현 전에 읽어라).")
    return "\n\n---\n\n".join(parts)


@mcp.prompt()
def socratic_tutor() -> str:
    """이 트랙용 '답 안 흘리는' 소크라테스 튜터 시스템 프롬프트(TUTOR.md의 붙여넣기 블록). 이걸 시스템/세션 프롬프트로 깔고 위 도구들과 함께 쓰면 된다."""
    t = fw.read_guarded("TUTOR.md")
    blk = re.search(r"`{3,}markdown\n(.*?)\n`{3,}", t, re.S)
    return blk.group(1) if blk else t


if __name__ == "__main__":
    mcp.run()
