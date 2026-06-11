# cloudsec-policy-stack

[![ci](https://github.com/dsaedsae/cloudsec-policy-stack/actions/workflows/ci.yml/badge.svg)](https://github.com/dsaedsae/cloudsec-policy-stack/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Defense-in-depth, as code, on a free local cluster.** One request to one service
passes through three independent policy layers — network (L3/L4), HTTP (L7), and
application authorization — each enforced and verified live, with a shift-left gate in CI.

```
   a single request:  web ──▶ api ──▶ (resource)
   ─────────────────────────────────────────────────────────────────────────
   Terraform │ kind cluster + Cilium (CNI), as code                  │ IaC
   Cilium L3 │ default-deny in+out; only web→api→db; egress locked    │ no exfil
   Cilium L7 │ only GET/POST on /accounts/* reach api (Envoy)         │ path/method
   Cedar     │ api PDP authorizes every call: owner? limit? role?     │ authz-as-code
   Tetragon  │ eBPF runtime: SIGKILLs a shell spawned in the db pod   │ detect+prevent
   ─────────────────────────────────────────────────────────────────────────
   checkov   │ shift-left scan of Terraform + K8s (CI gate, 0 fail)   │ + gitleaks
```

## What it demonstrates

- **IaC (Terraform)** — the cluster *and* its CNI are declarative/reproducible; `terraform validate` clean in CI.
- **Zero-trust network (Cilium / eBPF)** — default-deny on **both ingress and egress**; least-privilege hops
  only. The `web→api` rule is **L7** (Envoy): only the account API is reachable; other paths are dropped at
  the edge. Egress is locked to next-hop + DNS, so a **compromised pod cannot reach the internet, cloud
  metadata, or the API server** (proven live).
- **Authorization as code (Cedar), enforced inline** — the `api` is a small PDP service that calls Cedar on
  **every request** (owner check, transfer limit via request context, `forbid` on frozen accounts, role
  hierarchy). Same policies are unit-tested (`cedar/authz.py`, 7/7) and portable to **Amazon Verified Permissions**.
- **Runtime detection + prevention (Tetragon / eBPF)** — network and authz act before/at the request; nothing
  watches a workload once it's popped. A `TracingPolicy` **SIGKILLs any shell exec in the db tier in-kernel**
  (legit processes unaffected, pod stays healthy), and Tetragon records every process exec. Hubble adds
  flow visibility (`hubble observe -n shop --verdict DROPPED`).
- **Shift-left CI gate** — GitHub Actions runs Cedar tests + checkov + `terraform validate` + gitleaks on
  every push, and a kind job that stands up the stack and re-runs the live enforcement proof (incl. runtime).
- **Hardened workloads** — non-root, no priv-esc, all caps dropped, read-only rootfs, seccomp, probes,
  limits, `restricted` Pod Security. checkov exceptions are documented in `.checkov.yaml` — triage, not theater.

## The defense-in-depth proof (verified live + in CI)

One asset (`api`), three layers. `scripts/verify.{sh,ps1}` runs all of these:

| Layer | Test | Result | Enforced by |
|-------|------|--------|-------------|
| L1 network | web → db (no allowed hop) | **000** | Cilium L3 drop |
| L2 HTTP | web → api `GET /auditlogs/*` | **403** | Cilium L7 (path not allowed) |
| L3 authz | `alice` → `GET /accounts/acct-alice` | **200** | Cedar allow (owner) |
| L3 authz | `bob` → `GET /accounts/acct-alice` | **403** | **Cedar deny (not owner)** |
| L3 authz | `alice` transfer 500 (≤ limit) | **200** | Cedar allow |
| L3 authz | `alice` transfer 5000 (> limit) | **403** | Cedar deny (limit) |
| L3 authz | `alice` transfer from frozen acct | **403** | Cedar `forbid` |
| L3 authz | `alice` transfer **-100** (negative) | **403** | Cedar positive-amount guard |
| L3 input | malformed `X-User` header | **400** | PDP validates before Cedar |
| L1 network | api → db (allowed hop) | **200** | Cilium allow |
| egress | web → `https://example.com` | **000** | Cilium egress default-deny |
| egress | web → cloud metadata `169.254.169.254` | **000** | egress default-deny (no SSRF→metadata) |
| egress | web → kube-apiserver `10.96.0.1:443` | **000** | egress default-deny |
| L4 runtime | shell exec inside `db` pod | **SIGKILL (137)** | Tetragon `TracingPolicy` (eBPF) |

The two 403s are the point: `GET /auditlogs` (blocked at L7 before reaching the app, body `Access denied`
from Envoy) vs `bob`'s account read (reaches the app, body `Cedar denied: ...`) — **same network path, same
L7-allowed route, different principal**. That is layered control on one asset, not three disjoint demos.

## Layout

```
terraform/   kind + Cilium + Tetragon (helm)     app/api/    FastAPI Cedar PDP (the api image)
cedar/       schema + policies + 8 unit tests    k8s/        app, netpol, tracingpolicy, probes
scripts/     up / verify / scan / down (.ps1+.sh) .github/   CI workflow + kind config
```

## Quickstart

Prereqs: Docker, `kind`, `kubectl`, `helm`, `cilium`, `terraform`, Python 3.12.

```bash
python -m venv .venv && ./.venv/bin/python -m pip install -r requirements-dev.txt

./.venv/bin/python cedar/authz.py     # authz unit tests, no cluster needed -> 7/7
bash scripts/up.sh    || pwsh scripts/up.ps1       # provision kind+Cilium, build api, deploy
bash scripts/verify.sh|| pwsh scripts/verify.ps1   # prove all 3 layers live (table above)
bash scripts/down.sh  || pwsh scripts/down.ps1     # tear down
```

(Windows: `.venv\Scripts\python`, and the `.ps1` scripts. CI runs the `bash` path on Linux.)

## Learn it

New here? Follow the **[guided labs](docs/)** — Lab 0 needs only Python (5 min):
authz-as-code → shift-left scanning → network+authz on a cluster → eBPF runtime.
Each lab shows the payoff, then has you *break and fix* one layer.

## Validation status

- **CI** (`.github/workflows/ci.yml`) on every push: Cedar tests, checkov, `terraform validate`/`fmt`, gitleaks,
  and a kind integration job that brings up the stack and runs `scripts/verify.sh`.
- `cedar/authz.py` — schema validates, **8/8** scenarios pass (incl. negative-amount deny).
- `checkov` (Terraform + K8s) — **424 passed / 0 failed / 4 documented skips**. Scope: checkov validates the
  *workloads + Terraform*; the CiliumNetworkPolicy (a CRD it can't see) and Cedar are covered by the live
  `verify` job and `cedar/authz.py`.
- Live enforcement — **14/14** checks in the table above pass on kind+Cilium+Tetragon (locally and in CI).

## Roadmap

The core (IaC + zero-trust net incl. egress + inline Cedar authz + Tetragon runtime + CI) is in. Next:
- **Identity hardening** — Cilium mutual auth / SPIFFE; document the label-as-identity threat model + RBAC on who may set pod labels.
- **Supply chain** — pin images by `@sha256` digest + `cosign verify`; SLSA provenance.
- **Learning labs** — numbered `docs/` walkthroughs ("break the L7 rule and watch it drop", "add a Cedar deny").

## Notes

Local `kind` cluster — no cloud cost. Cedar policies port to **Amazon Verified Permissions**; Cilium policies
to any Cilium cluster (EKS/GKE/AKS). Identity (`X-User`) is **unauthenticated demo input** (charset-validated
to prevent injection); a real system derives the principal from a verified JWT `sub`. Entities are static
fixtures baked into the image. Learning/portfolio artifact, not turnkey prod. Licensed under [MIT](LICENSE).
