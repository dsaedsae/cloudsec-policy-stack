"""AI-agent ABAC demo runner (delegation intersection / confused-deputy).

Reuses the same Cedar harness as cedar/authz.py, pointed at cedar/agent/.
Proves an AI agent (a Non-Human Identity) is authorized only at the INTERSECTION
of its own clearance ceiling and the clearance of the user it acts on behalf of.

    python cedar/agent_authz.py     # PASS/FAIL table; exit 1 on any mismatch
"""

from __future__ import annotations

from pathlib import Path

from authz import main

if __name__ == "__main__":
    raise SystemExit(main(Path(__file__).resolve().parent / "agent"))
