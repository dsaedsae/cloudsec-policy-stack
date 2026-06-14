"""cross_layer.py — cross-layer policy-consistency lint (Cilium L7 x Cedar PDP).

The stack defends one asset with SIX policy engines in series. Each is unit/live tested
in ISOLATION (verify.sh, authz.py, checkov). What NOBODY tests is whether the layers
COMPOSE — does the Cilium L7 network policy and the Cedar PDP AGREE about which actions
are reachable-and-authorized? This finds two cross-layer defects and classifies every
action as defense-in-depth / shadowed(dead) / ungated:

  - SHADOWED (dead) rule: Cedar PERMITS an action whose HTTP path the L7 policy DROPS.
    The permit is unreachable through web->api (is /auditlogs meant to be out-of-band,
    or an accident?). Surfaced for review — a layer interaction, not a vulnerability.
  - UNGATED path: an L7-reachable action with NO Cedar gate. A real gap -> exit 1.

    python formal/cross_layer.py                      # text report; exit 1 only on UNGATED
    python formal/cross_layer.py --out outputs/xl     # also write report.{json,sarif,html}
    python formal/cross_layer.py --sarif x.sarif      # SARIF only (GitHub code scanning)
    python formal/cross_layer.py --open-auditlogs     # mutation: open L7 route -> shadow vanishes
    python formal/cross_layer.py --ungate-transfer    # mutation: route skips Cedar -> UNGATED (exit 1)

Inputs: Cedar decisions via cedarpy over cedar/ (read live); the per-route `gate` DERIVED
from app/api/main.py (AST, read live); and L7 reachability from a HAND-TRANSLATION of
k8s/netpol.yaml's HTTP block (the file itself is NOT parsed — see HONEST SCOPE). A small z3
finite-domain model enumerates the cross-layer witnesses.

HONEST SCOPE (no over-claim): the domain is the 3 demo actions, so this is a FINITE-DOMAIN
consistency check — z3 demonstrates the *technique*; the witnesses are reproducible by a
plain comprehension. Cedar decisions are CONCRETE (cedarpy), NOT symbolic — **cedar-policy-symcc**
is the unbounded upgrade. L7 rules are a hand-translation of the netpol HTTP block, not a
parsed live dataplane. It surfaces a cross-layer SHADOW (a layer-interaction to confirm),
not a CVE; contribution is honestly below big-four (single/dual-layer verification is published art).
It complements RBAC-graph / misconfig scanners (kubescape, trivy, kubesplaining) — a different gap.
"""

from __future__ import annotations

import ast
import html
import json
import re
import sys
from pathlib import Path

import cedarpy
import z3

HERE = Path(__file__).resolve().parent
CEDAR = HERE.parent / "cedar"
APP_MAIN = HERE.parent / "app" / "api" / "main.py"
NETPOL = HERE.parent / "k8s" / "netpol.yaml"

ACTION_HANDLER = {"ViewAccount": "view_account", "Transfer": "transfer", "ViewAuditLog": "view_audit_log"}
ACTION_HTTP = {
    "ViewAccount": ("GET", "/accounts/acct-alice"),
    "Transfer": ("POST", "/accounts/acct-alice/transfer"),
    "ViewAuditLog": ("GET", "/auditlogs/2026-06"),
}
GRANT_PROBE = {
    "ViewAccount": ('User::"alice"', 'Action::"ViewAccount"', 'Account::"acct-alice"', {}),
    "Transfer": ('User::"alice"', 'Action::"Transfer"', 'Account::"acct-alice"', {"amount": 500}),
    "ViewAuditLog": ('User::"carol"', 'Action::"ViewAuditLog"', 'AuditLog::"2026-06"', {}),
}
L7_RULES_BASE = [("GET", r"/accounts/[^/]+$"), ("POST", r"/accounts/[^/]+/transfer$")]


def cedar_grants(action: str) -> bool:
    pol = (CEDAR / "policies.cedar").read_text(encoding="utf-8")
    sch = (CEDAR / "schema.json").read_text(encoding="utf-8")
    ent = (CEDAR / "entities.json").read_text(encoding="utf-8")
    p, a, r, ctx = GRANT_PROBE[action]
    res = cedarpy.is_authorized({"principal": p, "action": a, "resource": r, "context": ctx}, pol, ent, sch)
    return res.decision.value == "Allow"


def l7_reachable(action: str, rules: list[tuple[str, str]]) -> bool:
    method, path = ACTION_HTTP[action]
    path = path.split("?", 1)[0]
    return any(m == method and re.fullmatch(p, path) for m, p in rules)


def gated_in_app(action: str) -> bool:
    fn = ACTION_HANDLER[action]
    tree = ast.parse(APP_MAIN.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == fn:
            return any(
                isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
                and c.func.id in ("authorize", "resolve_principal")
                for c in ast.walk(node)
            )
    return False


def _enum(solver_facts, A, prop) -> list[str]:
    s = z3.Solver()
    s.add(solver_facts)
    a = z3.Const("a", A)
    s.add(prop(a))
    out = []
    while s.check() == z3.sat:
        v = s.model()[a]
        out.append(str(v))
        s.add(a != v)
    return out


def classify(action, grants, reach, gated):
    """Return (kind, severity, verdict, remediation). kind drives report findings."""
    m, p = ACTION_HTTP[action]
    if reach and not gated:
        return ("ungated", "error",
                "UNGATED — L7-reachable but the route does not call the Cedar PDP",
                f"Add an authorize() call in the {ACTION_HANDLER[action]}() handler (app/api/main.py), "
                f"or drop the `{m} {p}` route from the L7 allow-list (k8s/netpol.yaml).")
    if grants and not reach:
        return ("shadowed", "warning",
                "SHADOWED — Cedar permits this action but the L7 edge drops its path (dead via web->api)",
                f"Confirm the out-of-band intent for `{m} {p}`. If it should be reachable, add it to the L7 "
                f"allow-list (k8s/netpol.yaml); if not, the Cedar permit is dead through this edge — document it.")
    if reach and grants:
        return ("defense", "note", "defense-in-depth — both L7 and Cedar gate this action", "")
    if reach and not grants:
        return ("denied", "note", "L7-reachable, Cedar-gated, never grants (fully denied)", "")
    return ("none", "note", "neither reachable nor granted", "")


def build_findings(actions, grants, reach, gated):
    out = []
    for a in actions:
        kind, sev, verdict, rem = classify(a, grants[a], reach[a], gated[a])
        m, p = ACTION_HTTP[a]
        out.append({
            "action": a, "kind": kind, "severity": sev, "verdict": verdict,
            "remediation": rem, "http": f"{m} {p}",
            "grant": grants[a], "reach": reach[a], "gate": gated[a],
            "ruleId": f"cross-layer/{kind}",
        })
    return out


SARIF_RULES = {
    "cross-layer/ungated": ("UNGATED reachable path",
        "An L7-reachable HTTP route serves a Cedar action but the handler never calls the PDP."),
    "cross-layer/shadowed": ("SHADOWED (dead) permit",
        "Cedar permits an action whose HTTP path the L7 edge drops; the permit is unreachable via web->api."),
}


def emit_json(findings, meta):
    return json.dumps({"tool": "cross-layer-lint", "scope": meta, "findings": findings}, indent=2, ensure_ascii=False)


def emit_sarif(findings):
    rules = [{"id": rid, "name": name, "shortDescription": {"text": desc},
              "defaultConfiguration": {"level": "error" if rid.endswith("ungated") else "warning"}}
             for rid, (name, desc) in SARIF_RULES.items()]
    results = []
    for f in findings:
        if f["kind"] not in ("ungated", "shadowed"):
            continue
        loc = "app/api/main.py" if f["kind"] == "ungated" else "k8s/netpol.yaml"
        results.append({
            "ruleId": f["ruleId"], "level": "error" if f["kind"] == "ungated" else "warning",
            "message": {"text": f"{f['action']} ({f['http']}): {f['verdict']}. {f['remediation']}".strip()},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": loc}}}],
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name": "cross-layer-lint",
            "informationUri": "https://github.com/dsaedsae/cloudsec-policy-stack",
            "shortDescription": {"text": "Cilium L7 x Cedar PDP cross-layer consistency (shadow/dead-rule + ungated)"},
            "rules": rules}}, "results": results}],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def emit_html(findings, meta):
    sev_color = {"error": "#f06f6f", "warning": "#e0b341", "note": "#8b9099"}
    rows = "\n".join(
        f'<tr><td class=a>{html.escape(f["action"])}</td><td class=h>{html.escape(f["http"])}</td>'
        f'<td style="color:{sev_color[f["severity"]]}">{html.escape(f["kind"])}</td>'
        f'<td class=m>{html.escape(f["verdict"])}</td></tr>' for f in findings)
    rem = "\n".join(
        f'<li><b>{html.escape(f["action"])}</b> — {html.escape(f["remediation"])}</li>'
        for f in findings if f["remediation"])
    n_err = sum(1 for f in findings if f["severity"] == "error")
    n_warn = sum(1 for f in findings if f["severity"] == "warning")
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<title>cross-layer-lint report</title><style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Noto+Sans+KR:wght@400;700;900&display=swap');
:root{{--bg:#0b0d10;--fg:#e7e9ee;--mut:#8b9099;--line:#1b1f25;--acc:#34d399;--mono:'JetBrains Mono',Consolas,monospace;--sans:'Noto Sans KR',-apple-system,'Segoe UI',sans-serif}}
body{{margin:0;background:var(--bg);color:var(--fg);font-family:var(--sans);font-size:15px;line-height:1.6}}
.wrap{{max-width:820px;margin:0 auto;padding:56px 32px}}
.k{{font:700 12px/1 var(--mono);letter-spacing:.04em;color:var(--acc)}}
h1{{font-weight:900;font-size:34px;letter-spacing:-.02em;margin:.4em 0 .2em}}
.sum{{font:700 14px var(--mono);color:var(--mut);margin:0 0 8px}}
.sum b{{color:{sev_color['error']}}}
table{{border-collapse:collapse;width:100%;font-family:var(--mono);font-size:13px;margin:22px 0}}
td,th{{border-bottom:1px solid var(--line);padding:.6em .4em;text-align:left;vertical-align:top}}
.a{{color:var(--fg);font-weight:700}}.h{{color:var(--mut)}}.m{{font-family:var(--sans);color:var(--mut)}}
h2{{font:700 12px var(--mono);letter-spacing:.04em;color:var(--mut);margin:32px 0 10px}}
ul{{padding-left:18px}}li{{margin:8px 0;color:var(--mut)}}li b{{color:var(--fg)}}
.note{{color:#4b515b;font-family:var(--mono);font-size:11.5px;border-top:1px solid var(--line);margin-top:34px;padding-top:14px}}
</style></head><body><div class=wrap>
<div class=k>cross-layer-lint &middot; Cilium L7 &times; Cedar PDP</div>
<h1>교차계층 정책 일관성 보고서</h1>
<p class=sum><b>{n_err} ungated</b> &nbsp; {n_warn} shadowed &nbsp; <span style="color:var(--acc)">{len(findings)} actions analyzed</span></p>
<table><tr><th>action</th><th>http</th><th>kind</th><th>verdict</th></tr>
{rows}
</table>
{f'<h2>remediation</h2><ul>{rem}</ul>' if rem else ''}
<p class=note>// scope: {html.escape(meta)}. finite-domain check (3 demo actions); z3 demonstrates the technique.
cedar-policy-symcc = unbounded upgrade. complements RBAC/misconfig scanners (different gap). not a CVE.</p>
</div></body></html>"""


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    argv = sys.argv[1:]
    for flag in ("--out", "--json", "--sarif", "--html"):  # value-taking flags must be followed by a path
        if flag in argv:
            i = argv.index(flag)
            if i + 1 >= len(argv) or argv[i + 1].startswith("--"):
                print(f"error: {flag} requires a path argument", file=sys.stderr)
                return 2
    open_audit = "--open-auditlogs" in argv
    rules = list(L7_RULES_BASE)
    if open_audit:
        rules.append(("GET", r"/auditlogs/[^/]+$"))

    actions = list(ACTION_HTTP)
    try:
        grants = {a: cedar_grants(a) for a in actions}
        reach = {a: l7_reachable(a, rules) for a in actions}
        gated = {a: gated_in_app(a) for a in actions}
    except FileNotFoundError as e:
        print(f"error: missing input artifact: {e.filename or e}", file=sys.stderr)
        return 1
    if "--ungate-transfer" in argv:
        gated["Transfer"] = False

    A, consts = z3.EnumSort("Action", actions)
    amap = dict(zip(actions, consts))
    Grant = z3.Function("Grant", A, z3.BoolSort())
    Reach = z3.Function("Reach", A, z3.BoolSort())
    Gated = z3.Function("Gated", A, z3.BoolSort())
    facts = []
    for a in actions:
        facts += [Grant(amap[a]) == z3.BoolVal(grants[a]),
                  Reach(amap[a]) == z3.BoolVal(reach[a]),
                  Gated(amap[a]) == z3.BoolVal(gated[a])]
    shadowed = _enum(facts, A, lambda a: z3.And(Grant(a), z3.Not(Reach(a))))
    ungated = _enum(facts, A, lambda a: z3.And(Reach(a), z3.Not(Gated(a))))

    findings = build_findings(actions, grants, reach, gated)
    meta = f"netpol={NETPOL.name} (hand-translated), cedar={CEDAR.name}/, app={APP_MAIN.name}{' [--open-auditlogs]' if open_audit else ''}"

    # --- report output (json / sarif / html) ---
    def _arg(flag):
        return argv[argv.index(flag) + 1] if flag in argv and argv.index(flag) + 1 < len(argv) else None
    out_dir = _arg("--out")
    wrote = []
    def _write(path, text):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(text, encoding="utf-8")
        wrote.append(path)
    if out_dir:
        _write(f"{out_dir}/report.json", emit_json(findings, meta))
        _write(f"{out_dir}/report.sarif", emit_sarif(findings))
        _write(f"{out_dir}/report.html", emit_html(findings, meta))
    for flag, emit in (("--json", lambda: emit_json(findings, meta)),
                       ("--sarif", lambda: emit_sarif(findings)),
                       ("--html", lambda: emit_html(findings, meta))):
        if (pth := _arg(flag)):
            _write(pth, emit())

    print(f"== Cross-layer consistency: Cilium L7 (web->api) x Cedar PDP {'[--open-auditlogs]' if open_audit else ''} ==")
    w = max(len(a) for a in actions) + 2
    for f in findings:
        print(f"  {f['action']:<{w}} grant={str(f['grant']):5} reach={str(f['reach']):5} gate={str(f['gate']):5} {f['verdict']}")
    print("-" * 64)
    print(f"  SMT shadowed-permit witnesses : {shadowed or '[]'}")
    print(f"  SMT ungated-reachable witnesses: {ungated or '[]'}")
    for p in wrote:
        print(f"  wrote {p}")
    if ungated:
        print(f"\nGAP: L7-reachable action(s) with no Cedar gate: {ungated} -> FAIL")
        return 1
    if shadowed:
        print(f"\nNo ungated path (defense-in-depth holds). SHADOW surfaced for review: {shadowed}")
        print("  -> Cedar authorizes these but the L7 edge drops their path; confirm intent (out-of-band access?)")
        print("  Falsifiable: `--open-auditlogs` opens the L7 route and the shadow disappears.")
    else:
        print("\nNo ungated path and no shadowed permit — every Cedar-permitted action is L7-reachable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
