#!/usr/bin/env python3
"""coverage.py — MLS compensating-control verifiability-coverage analysis.

Reads docs/mls-coverage.csv (the decomposed MLS sub-requirement inventory), computes
the headline metric ("% of workload-applicable MLS sub-requirements that are
verifiable-as-code"), prints Table 1, and renders Figure 1 (a stacked bar per control
family) to docs/assets/coverage.png. Re-runnable; the figure is regenerated from the
single CSV so the evaluation is reproducible.

Usage:  python scripts/coverage.py
"""
from __future__ import annotations
import csv
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CSV = ROOT / "docs" / "mls-coverage.csv"
OUT = ROOT / "docs" / "assets" / "coverage.png"

CATS = ["VERIFIED", "CONFIGURED", "GOVERNANCE", "NOT_COVERED"]
# brand palette (matches docs/stylesheets/extra.css + the decision-maker one-pager):
# teal = "a test proved this" (VERIFIED), amber = claimed-untested, slate = governance, red = gap.
COLORS = {"VERIFIED": "#1f8a70", "CONFIGURED": "#b8860b",
          "GOVERNANCE": "#607d8b", "NOT_COVERED": "#c0392b"}


def load(rows_path: pathlib.Path) -> list[dict]:
    with open(rows_path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def summarize(rows: list[dict]) -> None:
    total = len(rows)
    by_cat = {c: sum(1 for r in rows if r["category"] == c) for c in CATS}
    workload_applicable = total - by_cat["GOVERNANCE"]
    verifiable = by_cat["VERIFIED"]
    pct_app = 100 * verifiable / workload_applicable if workload_applicable else 0
    pct_all = 100 * verifiable / total if total else 0

    print(f"= MLS verifiability-coverage analysis ({total} decomposed sub-requirements) =")
    for c in CATS:
        print(f"  {c:14s}: {by_cat[c]:2d}")
    # exact, not rounded up: 31/40 = 77.5% must print "77.5%", not "78%" (anti-inflation).
    pct_app_s = f"{pct_app:.1f}".rstrip("0").rstrip(".")
    print(f"\n  HEADLINE: {verifiable}/{workload_applicable} = {pct_app_s}% of "
          f"workload-applicable sub-requirements are VERIFIED-AS-CODE")
    print(f"           ({verifiable}/{total} = {pct_all:.0f}% incl. governance-only)\n")

    fams = []
    for r in rows:
        if r["family"] not in fams:
            fams.append(r["family"])
    print("  Per-family (VERIFIED / total):")
    for fam in fams:
        fr = [r for r in rows if r["family"] == fam]
        v = sum(1 for r in fr if r["category"] == "VERIFIED")
        print(f"    {fam:22s} {v}/{len(fr)}")
    return by_cat, fams


def figure(rows: list[dict], fams: list[str]) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("  [figure skipped — `pip install matplotlib` to render docs/assets/coverage.png]")
        return
    OUT.parent.mkdir(parents=True, exist_ok=True)
    data = {c: [sum(1 for r in rows if r["family"] == fam and r["category"] == c)
                for fam in fams] for c in CATS}
    fig, ax = plt.subplots(figsize=(10, 4.5))
    import numpy as np
    bottom = np.zeros(len(fams))
    for c in CATS:
        vals = np.array(data[c])
        ax.bar(fams, vals, bottom=bottom, label=c, color=COLORS[c])
        bottom += vals
    ax.set_ylabel("sub-requirements")
    ax.set_title("MLS compensating-control verifiability coverage (per family)")
    ax.legend(ncol=4, loc="upper center", bbox_to_anchor=(0.5, -0.18), frameon=False)
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    fig.savefig(OUT, dpi=140, bbox_inches="tight")
    print(f"  Figure 1 -> {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    if not CSV.exists():
        sys.exit(f"missing {CSV}")
    rows = load(CSV)
    _, fams = summarize(rows)
    figure(rows, fams)
