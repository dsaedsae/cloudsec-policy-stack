# ReBAC demo — relationship-based authorization (OpenFGA)

This directory fills the gap [`docs/authorization-model.md` §4](../docs/authorization-model.md)
names explicitly: the `api` PDP is **Cedar / ABAC**; **ReBAC** (Zanzibar-style
relationship graph — OpenFGA / SpiceDB) was the unimplemented frontier. Here it is a
focused, **executable** demo — the OpenFGA twin of [`cedar/authz.py`](../cedar/authz.py).

## What it proves (the relationship that ABAC can't express cleanly)

An AI agent (a Non-Human Identity) may view/transfer an account **only when the
account's owner delegated to that agent** — a graph join across two relationships:

```
account.owner = alice   AND   alice.delegate = assistant
        └──────────────  delegate from owner  ──────────────┘
```

The agent's reach is *derived from a relationship to the owner*, not from an attribute
it carries. Plus NHI ownership: a `workload` is owned by a `team`, and team members
operate it transitively (`member from owner_team`).

| Check | Result | Why |
|---|---|---|
| `agent:assistant` → `can_view` `acct-alice` | ✅ allow | `delegate from owner` (alice owns + delegated) |
| `agent:assistant` → `can_view` `acct-bob` | ⛔ deny | no delegation edge from bob |
| `user:carol` → `can_view` `acct-alice` | ⛔ deny | no relationship path |
| `user:bob` → `can_admin` `billing-job` | ✅ allow | `member from owner_team` (payments team) |
| `user:alice` → `can_admin` `billing-job` | ⛔ deny | not on the payments team |

## Run it

**Canonical (deterministic, no server — the verifiable criterion):**

```bash
# native CLI (https://github.com/openfga/cli):  winget install openfga.cli   (or go install)
fga model test --tests rebac/store.fga.yaml
# or, with no native install, via docker:
docker run --rm -v "$PWD/rebac:/data" openfga/cli:latest model test --tests /data/store.fga.yaml
```

Expected: `Tests 1/1 passing  Checks 11/11 passing`.

**Optional live re-check (requires docker) — the SAME relationships against the real
OpenFGA `/check` HTTP API:**

```bash
python rebac/check_live.py        # boots openfga/openfga, asserts /check, tears it down
```

Expected: `11/11 live /check scenarios passed`. SKIPs honestly (exit 0) if docker is absent.

## Honest scope

- This is the **relationship oracle the Cedar PDP would consult** for delegation /
  ownership edges — it is **design-level**, *not* wired into the live `verify.*` 21-check
  cluster suite, and the running `api` PDP does **not** call OpenFGA in-request.
- The tuples reuse the same `alice` / `account` entities as the Cedar demo, so the two
  compose into one world (Cedar = per-request ABAC; OpenFGA = the relationship graph).
- It is a minimal demo, not a production delegation system (one model + one test file).

See also: [`cedar/agent/`](../cedar/agent/) — the same delegation idea as an **ABAC
intersection** in Cedar (agent ceiling ∧ delegating-user clearance), and
[`docs/nhi.md`](../docs/nhi.md) for the NHI lifecycle framing.
