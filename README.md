# cloudsec-policy-stack

[![ci](https://github.com/dsaedsae/cloudsec-policy-stack/actions/workflows/ci.yml/badge.svg)](https://github.com/dsaedsae/cloudsec-policy-stack/actions/workflows/ci.yml)
[![docs](https://github.com/dsaedsae/cloudsec-policy-stack/actions/workflows/docs.yml/badge.svg)](https://dsaedsae.github.io/cloudsec-policy-stack/)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A defense-in-depth Kubernetes security stack that runs on a free local `kind` cluster, paired with a self-graded track for rebuilding each control yourself. It is a learning and portfolio artifact, not a production deployment.

One request to one service passes through independent policy layers — network, HTTP, application authorization, and runtime — and each layer is enforced and verified by a script you run.

```
   a single request:  web ──▶ api ──▶ (resource)
   ─────────────────────────────────────────────────────────────────────────
   Terraform │ kind cluster + Cilium (CNI), as code                  │ IaC
   Identity  │ RBAC + label↔SA admission + SPIFFE mutual auth        │ who is web/api
   Cilium L3 │ default-deny in+out; only web→api→db; egress locked   │ no exfil
   Cilium L7 │ only GET/POST on /accounts/* reach api (Envoy)        │ path/method
   Cedar     │ api PDP authorizes every call: owner? limit? role?    │ authz-as-code
   Tetragon  │ eBPF runtime: SIGKILLs a shell spawned in the db pod  │ detect+prevent
   Data      │ WireGuard in-transit + Secret encryption at-rest      │ protect the data
   ─────────────────────────────────────────────────────────────────────────
   checkov   │ shift-left scan of Terraform + K8s (CI gate, 0 fail)  │ + gitleaks
```

## Build it yourself

This is the point of the repo. Every control here ships with a runnable check. The [re-implementation track](labs/README.md) flips those checks into an **autograder**: strip a control to a skeleton, rewrite it from the spec, and the existing harness grades you PASS or FAIL. You don't copy the canonical answer — you write your own and find out where it's wrong.

The track runs M0 through M6. Three modules need no cluster (Python only); the rest run against the local stack in one `up` → `down` session.

| Module | Control | Cluster |
|--------|---------|---------|
| M0 | Cedar authz: owner / limit / role / freeze | no |
| M1 | shift-left scan triage | no |
| M2 | identity: label↔ServiceAccount admission | yes |
| M3 | network: Cilium L3/L7/egress | yes |
| M4 | runtime: Tetragon shell-kill (eBPF) | yes |
| M5 | encryption: WireGuard + etcd-at-rest | yes |
| M6 | agent delegation + ReBAC graph | no |

Start with [환경 준비 (SETUP)](labs/SETUP.md), then [M0](labs/m0/README.md): a blank Cedar policy to a passing grade in about five minutes, no cluster. Prefer to read first? The [guided concept labs](docs/) walk the same controls before you rebuild them.

> Docs and labs are written in Korean (English README, 한국어 문서/실습).

## What's in the stack

- **IaC** — the cluster and its Cilium CNI are declarative Terraform; `terraform validate` runs in CI.
- **Zero-trust network (Cilium / eBPF)** — default-deny on ingress and egress, least-privilege hops only. `web→api` is L7 (Envoy) so only the account API is reachable, and egress is locked to next-hop plus DNS, so a compromised pod can't reach the internet, cloud metadata, or the API server.
- **Authorization as code (Cedar)** — the `api` is a PDP that calls Cedar on every request: owner check, transfer limit, a deny on frozen accounts, and role hierarchy. Portable to Amazon Verified Permissions.
- **Runtime (Tetragon / eBPF)** — a `TracingPolicy` that SIGKILLs a shell exec in the db tier in-kernel while leaving legitimate processes alone.
- **Identity** — per-tier ServiceAccounts, a `ValidatingAdmissionPolicy` binding the `app` label to its SA, and SPIFFE mutual auth (configured, verified manually rather than in the always-on suite).
- **Data** — WireGuard pod-to-pod encryption in transit and Secret encryption at rest in etcd.
- **CI gate** — GitHub Actions runs the Cedar tests, checkov, `terraform validate`, and gitleaks, plus a kind job that stands up the stack and re-runs the live proof.

## Quickstart

Prereqs: Python 3.12. For the cluster path you also need Docker, `kind`, `kubectl`, `helm`, `cilium-cli`, `terraform`, and Git for Windows (the `.sh` scripts and graders run in Git Bash, not PowerShell).

```powershell
# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe cedar\authz.py     # authz unit tests, no cluster -> 8/8
powershell -File scripts\up.ps1             # provision kind + Cilium, build api, deploy
bash scripts/verify.sh                      # (Git Bash) prove the layers live
powershell -File scripts\down.ps1           # tear down
```

```bash
# Linux / macOS / CI
python -m venv .venv && ./.venv/bin/python -m pip install -r requirements-dev.txt
./.venv/bin/python cedar/authz.py
bash scripts/up.sh && bash scripts/verify.sh && bash scripts/down.sh
```

## Status

- `scripts/verify.sh` — 21/21 live checks on kind + Cilium + Tetragon, locally and in CI.
- Cedar — 8/8 core authz, 12/12 agent delegation. ReBAC — 11/11 (`fga model test`).
- checkov — 452 pass / 0 fail / 5 documented skips.
- MLS verifiability coverage — 67% (26/39); the gaps are published in [`docs/mls-coverage.csv`](docs/mls-coverage.csv).

The per-check breakdown, validation notes, and roadmap live on the [docs site](https://dsaedsae.github.io/cloudsec-policy-stack/).

## Layout

```
terraform/   kind + Cilium + Tetragon (helm)     app/api/    FastAPI Cedar PDP (the api image)
cedar/       schema + policies + unit tests       k8s/        app, netpol, tracingpolicy, probes
labs/        re-implementation track (M0–M6)      docs/       guided concept labs + mappings
scripts/     up / verify / scan / down (.ps1+.sh) .github/    CI workflow + kind config
```

## Notes

Local `kind` cluster, no cloud cost. Cedar policies port to Amazon Verified Permissions; Cilium policies to any Cilium cluster (EKS / GKE / AKS). The `X-User` identity is unauthenticated demo input, charset-validated; a real system would derive the principal from a verified JWT `sub`. Entities are static fixtures baked into the image. Licensed under [MIT](LICENSE).
