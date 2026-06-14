"""cross_layer_test.py — unit tests for the report emitters + classifier.

No cluster, no cedar/app files: this exercises classify()/build_findings()/emit_* directly
with synthetic inputs, so it covers the branches the CI text-gate does NOT (the gate runs the
live SHADOWED path only — never the UNGATED branch, the SARIF/JSON shape, or HTML escaping).

Self-running like cedar/authz.py: `python formal/cross_layer_test.py` -> prints PASS/FAIL per
case and exits nonzero on any failure (wired into `make test` and CI).
"""
from __future__ import annotations

import json
import sys

from cross_layer import (build_findings, classify, emit_html, emit_json,
                         emit_sarif)


def main() -> int:
    ok = True

    def check(name, cond):
        nonlocal ok
        ok = ok and bool(cond)
        print(f"  {'PASS' if cond else 'FAIL'}  {name}")

    # --- classify(): all four meaningful reach/grant/gate combinations ---
    kind, sev, _verdict, rem = classify("Transfer", grants=True, reach=True, gated=False)
    check("reachable + ungated -> ungated/error with remediation", kind == "ungated" and sev == "error" and bool(rem))

    kind, sev, *_ = classify("ViewAuditLog", grants=True, reach=False, gated=True)
    check("granted but L7-dropped -> shadowed/warning", kind == "shadowed" and sev == "warning")

    kind, sev, *_ = classify("Transfer", grants=True, reach=True, gated=True)
    check("both layers gate -> defense/note", kind == "defense" and sev == "note")

    kind, *_ = classify("Transfer", grants=False, reach=True, gated=True)
    check("reachable, gated, never grants -> denied", kind == "denied")

    # --- emit_json: shape + required finding keys (synthetic UNGATED scenario) ---
    ungated = build_findings(["Transfer"], {"Transfer": True}, {"Transfer": True}, {"Transfer": False})
    j = json.loads(emit_json(ungated, "test-scope"))
    check("json: tool/scope/findings present",
          j["tool"] == "cross-layer-lint" and j["scope"] == "test-scope" and len(j["findings"]) == 1)
    keys = ("action", "kind", "severity", "verdict", "remediation", "http", "ruleId")
    check("json: finding carries all required keys", all(k in j["findings"][0] for k in keys))

    # --- emit_sarif: valid 2.1.0 shell, results only for the two defect kinds ---
    s = json.loads(emit_sarif(ungated))
    run = s["runs"][0]
    check("sarif: version 2.1.0", s["version"] == "2.1.0")
    check("sarif: driver name", run["tool"]["driver"]["name"] == "cross-layer-lint")
    check("sarif: both rules declared",
          {r["id"] for r in run["tool"]["driver"]["rules"]} == {"cross-layer/ungated", "cross-layer/shadowed"})
    res = run["results"]
    check("sarif: ungated -> 1 error result at app/api/main.py",
          len(res) == 1 and res[0]["level"] == "error"
          and res[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app/api/main.py")

    clean = build_findings(["Transfer"], {"Transfer": True}, {"Transfer": True}, {"Transfer": True})
    check("sarif: defense-in-depth -> 0 results", len(json.loads(emit_sarif(clean))["runs"][0]["results"]) == 0)

    # --- emit_html: interpolated fields are HTML-escaped (NTC-5 regression guard) ---
    evil = [{"action": "X<script>", "kind": "ungated", "severity": "error",
             "verdict": "<img src=x onerror=alert(1)>", "remediation": "fix <b>now</b>",
             "http": "GET /x", "grant": True, "reach": True, "gate": False,
             "ruleId": "cross-layer/ungated"}]
    h = emit_html(evil, "scope & <inject>")
    check("html: payloads escaped, not injected",
          "<script>" not in h and "<img src=x" not in h and "&lt;script&gt;" in h and "&lt;inject&gt;" in h)

    print("\nALL PASS" if ok else "\nFAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
