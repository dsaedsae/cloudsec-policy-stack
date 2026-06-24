"""firewall.py — the answer-leak firewall for the cloudsec-tutor MCP server.

Pure logic, NO `mcp` dependency, so it is unit-testable on its own (mcp/firewall_test.py).
The MCP tools expose a FIXED per-module allowlist of files — there is no free-form
`read_file(path)` tool — so the answer-key files are *structurally* unreachable through the
server. This module defines that allowlist (MODULES), the answer-key denylist (ANSWER_KEYS,
a defense-in-depth assertion the test verifies the allowlist never intersects), and the
three-layer `redact_lesson` for module READMEs: it strips folded `<details>` answers, every
non-shell fenced code block (any tag), and author-marked `<!-- TUTOR:CUT -->` answer-walk
regions — so a README's worked policy/idiom code never reaches the AI tutor through the server.
"""
from __future__ import annotations

import fnmatch
import posixpath
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Answer-key / canonical files — NEVER exposed by any tool (mirrors TUTOR.md's protect set).
# `formal/cross_layer.py` (M7's worked z3 proof) and the `*/LEARN.md` spoon-feed docs are answers
# too — added so the denylist (read_guarded) backstops them, not only the structural allowlist.
ANSWER_KEYS = {
    "cedar/policies.cedar", "cedar/agent/policies.cedar",
    "rebac/model.fga", "rebac/store.fga.yaml",
    "k8s/admission-policy.yaml", "k8s/admission-sa-use.yaml", "k8s/kyverno-sa-use.yaml",
    "k8s/netpol.yaml", "k8s/netpol-mutual.yaml", "k8s/tracingpolicy.yaml", "k8s/app.yaml",
    "gitops/apps/network-runtime.yaml", "formal/cross_layer.py",
}
ANSWER_GLOBS = ["*.solution.*", "site/*", "*/site/*", "*/learn.md", "learn.md"]


def _norm(rel: str) -> str:
    """Repo-relative, forward-slashed, collapsed (//, ./, ..), lower-cased — so case /
    double-slash / trailing-slash / dot-segment variants can't slip past the denylist
    (Windows opens files case-insensitively, so the match must be too)."""
    return posixpath.normpath(rel.replace("\\", "/")).lstrip("./").lower()


def is_answer_key(rel: str) -> bool:
    """True if `rel` (repo-relative) is an answer key the firewall must never expose."""
    n = _norm(rel)
    if n in {k.lower() for k in ANSWER_KEYS}:
        return True
    return any(fnmatch.fnmatch(n, g.lower()) for g in ANSWER_GLOBS)


# No-cluster modules whose grader the MCP server can actually run; cluster modules return
# a SKIP + the up->grade.sh->down instructions instead.
NOCLUSTER = {"m0", "m1", "m6", "m7"}

# Per-module map. `lesson`/`spec` are FIXED allowlists — the read tools take a MODULE id,
# never a path, so an answer-key path can't be requested.
MODULES: dict[str, dict] = {
    "m0":  dict(title="Cedar 인가 (owner·한도·역할·동결)", grader=["labs/m0/grade.py"],
                lesson=["labs/m0/README.md"], lesson_doc="docs/01-authz-no-cluster.md",
                spec=["cedar/schema.json", "cedar/entities.json", "cedar/requests.json"]),
    "m1":  dict(title="shift-left checkov triage", grader=["labs/m1/grade.py"],
                lesson=["labs/m1/README.md"], lesson_doc="docs/02-scan.md", spec=[]),
    "m6":  dict(title="agent-ABAC + ReBAC", grader=["labs/m6/grade.py"],
                lesson=["labs/m6/README.md"], lesson_doc="docs/authorization-model.md", spec=[]),
    "m7":  dict(title="cross-layer formal (z3)", grader=["formal/cross_layer.py"],
                lesson=["formal/README.md"], lesson_doc=None, spec=[]),
    "m2":  dict(title="identity VAP/CEL", cluster_cmd="bash labs/m2/grade.sh",
                lesson=["labs/m2/README.md"], lesson_doc="docs/05-identity.md", spec=["k8s/probes.yaml"]),
    "m3":  dict(title="Cilium netpol", cluster_cmd="bash labs/m3/grade.sh",
                lesson=["labs/m3/README.md"], lesson_doc="docs/03-network-and-authz.md", spec=["k8s/probes.yaml"]),
    "m4":  dict(title="Tetragon 셸-kill", cluster_cmd="bash labs/m4/grade.sh",
                lesson=["labs/m4/README.md"], lesson_doc="docs/04-runtime.md", spec=[]),
    "m5":  dict(title="암호화 실행·해석", cluster_cmd="bash labs/m5/grade.sh",
                lesson=["labs/m5/README.md"], lesson_doc="docs/06-data-protection.md", spec=[]),
    "m8":  dict(title="런타임 kill 경계", cluster_cmd="powershell -File scripts/verify-runtime-scope.ps1",
                lesson=["labs/m8/README.md"], lesson_doc="docs/04-runtime.md", spec=[]),
    "m9":  dict(title="침해 가정·블래스트 반경", cluster_cmd="bash labs/m9/grade.sh",
                lesson=["labs/m9/README.md"], lesson_doc=None, spec=[]),
    "m10": dict(title="GitOps 무결성", cluster_cmd="bash labs/m10/grade.sh",
                lesson=["labs/m10/README.md"], lesson_doc=None, spec=[]),
    "m11": dict(title="BPF-LSM exec 허용목록", cluster_cmd="bash labs/m11/grade.sh",
                lesson=["labs/m11/README.md"], lesson_doc=None, spec=[]),
}


def allowlisted_files(module: str) -> list[str]:
    """Every file the read tools may expose for a module (lesson + spec) — the firewall surface."""
    m = MODULES.get(module, {})
    return list(m.get("lesson") or []) + list(m.get("spec") or [])


# Strip the folded <details …>…</details> ANSWER body, keep the <summary> question prompt.
# Tolerates attributes (`<details open>`) and a missing <summary> (whole fold then redacted).
_DETAILS = re.compile(r"(<details[^>]*>\s*(?:<summary>.*?</summary>)?).*?(</details>)", re.S | re.I)

# Author-marked answer regions: a README's guided answer-walk (the "정책 한 줄씩 / 정답지 기준"
# sections + hint tables that spell out the canonical control) is intended teaching for a human
# reading the PUBLIC site, but read_lesson must not relay it to an AI tutor. Wrap such a region in
# `<!-- TUTOR:CUT -->` … `<!-- /TUTOR:CUT -->` (HTML comments — invisible on the rendered site).
_CUT = re.compile(r"<!--\s*TUTOR:CUT\s*-->.*?<!--\s*/TUTOR:CUT\s*-->", re.S | re.I)


def strip_answers(md: str) -> str:
    return _DETAILS.sub(
        r"\1\n\n> (답은 스스로 — `grade.py --hint`로 확인; 정답지는 졸업 후 diff)\n\n\2", md)


# Fenced code blocks. The lesson READMEs mix shell COMMANDS (safe — how to run the grader) with
# worked POLICY/MANIFEST/DSL code (cedar/yaml/fga/cel/rego/untagged…) that would hand the idiom.
# A language *denylist* is fragile (it missed fga/cel/rego/untagged fences), so we ALLOWLIST the
# shell-command languages to KEEP and redact every other fence regardless of its tag — surfacing
# prose + commands while removing all worked code. (The full README is still public on the site.)
_KEEP_FENCE_LANGS = {"bash", "sh", "shell", "console", "powershell", "pwsh", "ps1", "cmd", "bat"}
_FENCE = re.compile(r"```([^\n`]*)\n.*?```", re.S)
_REDACTED = "\n> (정책/매니페스트 코드 예시 생략 — 직접 작성; 실행·힌트는 grade()/hint() 도구로)\n"


def _redact_fence(m: re.Match) -> str:
    lang = m.group(1).strip().lower()
    return m.group(0) if lang in _KEEP_FENCE_LANGS else _REDACTED


def redact_lesson(md: str) -> str:
    """What read_lesson serves: author-marked answer-walk regions cut + folded oral-Q&A answers
    stripped + every non-shell fenced code block redacted (worked policy/manifest/DSL code, any
    tag). Keeps prose, requirements, Socratic questions, and shell-command blocks."""
    md = _CUT.sub("\n> (가이드 답-walk 생략 — 먼저 스스로 작성하라; 전체 해설은 공개 사이트에)\n", md)
    return _FENCE.sub(_redact_fence, strip_answers(md))


def read_guarded(rel: str) -> str:
    """Read a repo file ONLY if it is not an answer key AND it resolves inside the repo (defense
    in depth — the tools already pass fixed allowlisted paths, never user-supplied paths)."""
    if is_answer_key(rel):
        raise PermissionError(f"firewall: '{rel}' is an answer key — not exposed (졸업 후 diff)")
    p = (ROOT / rel).resolve()
    if not p.is_relative_to(ROOT.resolve()):
        raise PermissionError(f"firewall: '{rel}' escapes the repo root — refused")
    return p.read_text(encoding="utf-8", errors="replace") if p.is_file() else f"(없음: {rel})"
