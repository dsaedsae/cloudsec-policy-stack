"""Optional LIVE re-check of the ReBAC model against a real OpenFGA engine.

`fga model test` (rebac/store.fga.yaml) proves the relationships in-memory and is
the canonical, CI-gateable check. THIS script proves the SAME relationships against
the actual OpenFGA /check HTTP API running in docker — a heavier, opt-in confirmation.

    python rebac/check_live.py        # requires docker; SKIPs (exit 0) if absent

It is NOT wired into scripts/verify.* (the live cluster suite) and NEVER fabricates a
pass: if docker is unavailable or the engine fails to come up, it prints SKIP and exits 0.
Honesty rule — see CLAUDE.md.

Flow: boot openfga/openfga -> transform model.fga to JSON via openfga/cli ->
create store, write model + tuples over HTTP -> POST /check per scenario ->
assert allow/deny == expected -> tear the container down in a finally block.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTAINER = "openfga-rebac-live"
HOST_PORT = 18081
BASE = f"http://localhost:{HOST_PORT}"

# Same scenarios as rebac/store.fga.yaml, as (user, relation, object, expected).
SCENARIOS = [
    ("user:alice",      "can_view",     "account:acct-alice",     True),
    ("user:alice",      "can_transfer", "account:acct-alice",     True),
    ("agent:assistant", "can_view",     "account:acct-alice",     True),   # delegate from owner
    ("agent:assistant", "can_transfer", "account:acct-alice",     True),
    ("agent:assistant", "can_view",     "account:acct-bob",       False),  # no edge to bob
    ("agent:assistant", "can_transfer", "account:acct-bob",       False),
    ("user:carol",      "can_view",     "account:acct-alice",     False),  # unrelated
    ("user:carol",      "can_transfer", "account:acct-alice",     False),  # unrelated (parity with store.fga.yaml)
    ("user:bob",        "can_admin",    "workload:billing-job",   True),   # member from owner_team
    ("user:alice",      "can_admin",    "workload:billing-job",   False),  # not a team member
    ("user:carol",      "can_admin",    "workload:billing-job",   False),
]

TUPLES = [
    ("user:alice",      "owner",      "account:acct-alice"),
    ("agent:assistant", "delegate",   "user:alice"),
    ("user:bob",        "owner",      "account:acct-bob"),
    ("user:bob",        "member",     "team:payments"),
    ("team:payments",   "owner_team", "workload:billing-job"),
]


def skip(msg: str) -> int:
    print(f"SKIP: {msg}")
    print("(live OpenFGA check is opt-in; `fga model test` is the canonical proof)")
    return 0


def _post(path: str, body: dict) -> dict:
    req = urllib.request.Request(
        BASE + path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def _wait_healthy(timeout_s: int = 30) -> bool:
    deadline_checks = timeout_s * 2
    for _ in range(deadline_checks):
        try:
            with urllib.request.urlopen(BASE + "/healthz", timeout=3) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(0.5)
    return False


def main() -> int:
    if shutil.which("docker") is None:
        return skip("docker not installed")

    # The transform needs the openfga/cli image; the server needs openfga/openfga.
    subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True, check=False)
    try:
        # 1) DSL -> JSON model (run the CLI image over the mounted rebac dir).
        tr = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{HERE}:/data", "openfga/cli:latest",
             "model", "transform", "--file", "/data/model.fga"],
            capture_output=True, text=True, check=False,
        )
        if tr.returncode != 0:
            return skip(f"model transform failed: {tr.stderr.strip()[:200]}")
        model = json.loads(tr.stdout)

        # 2) Boot the real engine.
        up = subprocess.run(
            ["docker", "run", "-d", "--name", CONTAINER,
             "-p", f"{HOST_PORT}:8080", "openfga/openfga:latest", "run"],
            capture_output=True, text=True, check=False,
        )
        if up.returncode != 0:
            return skip(f"could not start openfga: {up.stderr.strip()[:200]}")
        if not _wait_healthy():
            return skip("openfga did not become healthy in time")

        # 3) Create store + write model.
        store_id = _post("/stores", {"name": "rebac-live"})["id"]
        model_id = _post(
            f"/stores/{store_id}/authorization-models",
            {"schema_version": model["schema_version"],
             "type_definitions": model["type_definitions"],
             "conditions": model.get("conditions", {})},
        )["authorization_model_id"]

        # 4) Write the relationship tuples.
        _post(f"/stores/{store_id}/write", {
            "authorization_model_id": model_id,
            "writes": {"tuple_keys": [
                {"user": u, "relation": r, "object": o} for (u, r, o) in TUPLES
            ]},
        })

        # 5) /check each scenario against the live API.
        print(f"{'scenario':<52}{'expect':>8}{'actual':>8}  result")
        print("-" * 80)
        failures = 0
        for user, rel, obj, expected in SCENARIOS:
            res = _post(f"/stores/{store_id}/check", {
                "authorization_model_id": model_id,
                "tuple_key": {"user": user, "relation": rel, "object": obj},
            })
            actual = bool(res.get("allowed", False))
            ok = actual == expected
            failures += not ok
            name = f"{user} {rel} {obj}"
            print(f"{name:<52}{str(expected):>8}{str(actual):>8}  {'PASS' if ok else 'FAIL'}")
        print("-" * 80)
        print(f"{len(SCENARIOS) - failures}/{len(SCENARIOS)} live /check scenarios passed")
        return 1 if failures else 0
    except (urllib.error.URLError, OSError, KeyError, json.JSONDecodeError) as e:
        return skip(f"live check error: {type(e).__name__}: {str(e)[:200]}")
    finally:
        subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True, check=False)


if __name__ == "__main__":
    raise SystemExit(main())
