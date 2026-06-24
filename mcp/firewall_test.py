"""firewall_test.py — who tests the firewall? (no `mcp` dependency)

Proves the cloudsec-tutor MCP server cannot leak an answer key:
  (1) every module's exposed allowlist (lesson+spec) is DISJOINT from the answer-key denylist;
  (2) is_answer_key flags every answer key + a synthetic *.solution.* path, and PASSES the read-OK specs;
  (3) read_guarded REFUSES an answer key;
  (4) strip_answers removes a folded <details> answer (keeps the question);
  (5) the actual exposed read-surface for M0 (lesson+spec, after stripping) does NOT reproduce
      any distinctive multi-token line of the canonical answer file cedar/policies.cedar.

    python mcp/firewall_test.py     # exit 1 on any leak
"""
from __future__ import annotations

import sys

import firewall as fw

fails = 0


def check(ok: bool, msg: str) -> None:
    global fails
    print(("  PASS" if ok else "  FAIL") + "  " + msg)
    if not ok:
        fails += 1


print("== cloudsec-tutor firewall — answer-leak proof ==")

# (1) exposed allowlist never intersects the answer-key denylist
for mod in fw.MODULES:
    bad = [f for f in fw.allowlisted_files(mod) if fw.is_answer_key(f)]
    check(not bad, f"{mod}: exposed allowlist holds no answer key (found {bad or 'none'})")

# (2) is_answer_key correctness
for k in fw.ANSWER_KEYS:
    check(fw.is_answer_key(k), f"is_answer_key flags {k}")
check(fw.is_answer_key("labs/m4/tracingpolicy.solution.yaml"), "flags *.solution.* glob")
check(fw.is_answer_key("site/cedar/policies.cedar"), "flags site/ copies")
for ok in ["cedar/schema.json", "cedar/entities.json", "cedar/requests.json",
           "k8s/probes.yaml", "labs/m0/README.md", "docs/01-authz-no-cluster.md"]:
    check(not fw.is_answer_key(ok), f"read-OK passes: {ok}")

# (2b) normalization bypasses — case / double-slash / trailing-slash / dot-segment / LEARN /
# formal proof must all still be flagged (Windows opens case-insensitively, so matching must too).
for bypass in ["CEDAR/POLICIES.CEDAR", "cedar//policies.cedar", "cedar/policies.cedar/",
               "./cedar/policies.cedar", "k8s\\NETPOL.yaml",
               "labs/m0/LEARN.md", "formal/cross_layer.py"]:
    check(fw.is_answer_key(bypass), f"is_answer_key flags normalized bypass: {bypass}")
# read_guarded refuses a repo-escaping traversal
try:
    fw.read_guarded("../escape.txt")
    check(False, "read_guarded refuses repo-escaping path")
except PermissionError:
    check(True, "read_guarded refuses repo-escaping path")

# (3) read_guarded refuses an answer key
try:
    fw.read_guarded("cedar/policies.cedar")
    check(False, "read_guarded refuses cedar/policies.cedar")
except PermissionError:
    check(True, "read_guarded refuses cedar/policies.cedar")

# (4) strip_answers removes the folded answer, keeps the question — incl. <details open> and
# summary-less folds (a contributor habit that would otherwise leak the prose answer).
sample = '<details><summary>R4는 무엇?</summary>SECRET: `resource.frozen == true` 를 when에</details>'
stripped = fw.strip_answers(sample)
check("SECRET" not in stripped and "resource.frozen == true" not in stripped and "R4는 무엇?" in stripped,
      "strip_answers removes a folded answer, keeps the question")
check("SECRET" not in fw.strip_answers('<details open><summary>Q?</summary>SECRET</details>'),
      "strip_answers folds <details open> (attribute)")
check("SECRET" not in fw.strip_answers('<details>\nSECRET answer prose\n</details>'),
      "strip_answers folds a summary-less <details>")

# (5) the firewall's real guarantee on the exposed read-surface: it must NOT (a) reproduce a
# verbatim chunk of the canonical answer FILE (no full-answer dump — inline backticks / prose
# answer-tables included, not just fenced code), nor (b) leak the *folded* oral-Q&A answers
# (R4/E1, the "이제 혼자" rules the repo protects). Public scaffold lines the README intentionally
# teaches (R1/R3 — already on the public docs site) are NOT secret and are allowed to appear.
def _canon_lines(rel: str) -> list[str]:
    # comment-stripped, non-empty lines (// for cedar, # for yaml/fga)
    out = []
    for ln in (fw.ROOT / rel).read_text(encoding="utf-8").splitlines():
        c = ln.split("//", 1)[0].split("#", 1)[0].strip()
        if c:
            out.append(c)
    return out


def _dumps(text: str, lines: list[str], n: int = 3) -> bool:
    return any(len(set(lines[i:i + n])) == n and all(l in text for l in lines[i:i + n])
               for i in range(len(lines) - n + 1))


# (5a) GENERALIZED across every module whose answer is DERIVED policy logic: read_lesson
# reproduces no verbatim 3-consecutive-line chunk of its canonical answer file (catches inline /
# prose answer dumps, not only fences). M1 is deliberately ABSENT: its objective is *triaging
# scanner findings*, and its remediation is the universally-standard PSS-`restricted`
# securityContext (public Kubernetes hardening — in every CIS/NSA guide and on this repo's own
# public site), not a repo-specific secret to derive. Redacting M1's CKV-grouping teaching tables
# would gut the lab for zero security gain; the content red-team rated M1 clean on this basis.
CANON = {
    "m0": ["cedar/policies.cedar"],
    "m2": ["k8s/admission-policy.yaml"],
    "m3": ["k8s/netpol.yaml", "k8s/netpol-mutual.yaml"],
    "m4": ["labs/m4/tracingpolicy.solution.yaml", "k8s/tracingpolicy.yaml"],
    "m5": ["k8s/encryption-config.yaml"],
    "m6": ["cedar/agent/policies.cedar", "rebac/model.fga"],
    "m7": ["formal/cross_layer.py"],
    "m8": ["labs/m4/tracingpolicy.solution.yaml", "k8s/tracingpolicy.yaml"],
    "m10": ["gitops/apps/network-runtime.yaml"],
}
for mod, canons in CANON.items():
    red = "\n".join(fw.redact_lesson(fw.read_guarded(f)) for f in fw.MODULES[mod].get("lesson", []))
    for c in canons:
        if (fw.ROOT / c).is_file():
            check(not _dumps(red, _canon_lines(c)),
                  f"{mod}: read_lesson reproduces no verbatim 3-line chunk of {c}")

# (5b) the protected folded answers are stripped — R4 (frozen guard) + E1 (over-grant action fix)
m0_red = "\n".join(fw.redact_lesson(fw.read_guarded(f)) for f in fw.MODULES["m0"].get("lesson", []))
for tok in ('resource.frozen == true', 'action == Action::"ViewAccount"'):
    check(tok not in m0_red, f"M0 exposed surface strips the protected folded answer: {tok}")

# (6) STRUCTURAL invariant across EVERY module: read_lesson redacts EVERY non-shell fenced code
# block (any tag — cedar/yaml/fga/cel/rego/text/untagged), so no module's worked policy/manifest
# code can leak regardless of how it was tagged. (Denylist-by-language missed fga/cel/untagged.)
for mod, m in fw.MODULES.items():
    for f in (m.get("lesson") or []):
        red = fw.redact_lesson(fw.read_guarded(f))
        bad = sorted({(lang.strip().lower() or "<untagged>") for lang in fw._FENCE.findall(red)
                      if lang.strip().lower() not in fw._KEEP_FENCE_LANGS})
        check(not bad, f"{mod}:{f} — read_lesson leaves only shell fences (stray: {bad or 'none'})")

# (7) the ACTUAL guarantee, token-level: the red-team's exact verbatim answer fragments (inline
# backticks + prose answer-tables the fence redactor alone missed) must NOT survive read_lesson.
FORBIDDEN = {
    "m6": ["delegated_by_max_classification", "delegation_depth > 1", "delegation_depth >= 1",
           "owner or delegate from owner", "allowed_tools.contains", "member from owner_team"],
    "m4": ['/sh","/bash', "sys_execve", "action: Sigkill"],
    "m8": ['/sh","/bash'],
    "m3": ["/accounts/[^/]+"],
    "m2": ["object.metadata.name", "request.userInfo.username"],
}
for mod, toks in FORBIDDEN.items():
    red = "\n".join(fw.redact_lesson(fw.read_guarded(f)) for f in fw.MODULES[mod].get("lesson", []))
    for t in toks:
        check(t not in red, f"{mod}: read_lesson does not leak answer fragment {t!r}")

print(("\nPASS" if not fails else "\nFAIL") + f": firewall — {fails} failing check(s).")
sys.exit(1 if fails else 0)
