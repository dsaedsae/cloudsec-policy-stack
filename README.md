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
   Identity  │ RBAC + label↔SA admission + SPIFFE mutual auth (B7)    │ who is web/api
   Cilium L3 │ default-deny in+out; only web→api→db; egress locked    │ no exfil
   Cilium L7 │ only GET/POST on /accounts/* reach api (Envoy)         │ path/method
   Cedar     │ api PDP authorizes every call: owner? limit? role?     │ authz-as-code
   Tetragon  │ eBPF runtime: SIGKILLs a shell spawned in the db pod   │ detect+prevent
   Data      │ WireGuard in-transit + Secret encryption at-rest       │ protect the data
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
  hierarchy). Same policies are unit-tested (`cedar/authz.py`, 8/8) and portable to **Amazon Verified Permissions**.
- **Runtime detection + prevention (Tetragon / eBPF)** — network and authz act before/at the request; nothing
  watches a workload once it's popped. A `TracingPolicy` **SIGKILLs any shell exec in the db tier in-kernel**
  (legit processes unaffected, pod stays healthy), and Tetragon records every process exec. Hubble adds
  flow visibility (`hubble observe -n shop --verdict DROPPED`).
- **Shift-left CI gate** — GitHub Actions runs Cedar tests + checkov + `terraform validate` + gitleaks on
  every push, and a kind job that stands up the stack and re-runs the live enforcement proof (incl. runtime).
- **Hardened workloads** — non-root, no priv-esc, all caps dropped, read-only rootfs, seccomp, probes,
  limits, `restricted` Pod Security. checkov exceptions are documented in `.checkov.yaml` — triage, not theater.

## The defense-in-depth proof (verified live + in CI)

One asset (`api`), every layer. `scripts/verify.{sh,ps1}` runs all of these (18/18):

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
| identity | `api-sa` create-pods / read-secrets | **no** | least-privilege RBAC (no RoleBinding) |
| identity | forged `app:api` on `web-sa` | **admission DENY** | `ValidatingAdmissionPolicy` (label↔SA) |
| identity | self-consistent `app:api`+`api-sa` | **admitted (residual)** | documented gap → mutual auth closes it |
| data-in-transit | pod-to-pod traffic | **WireGuard** | Cilium transparent encryption |

That's **18/18** in `scripts/verify.{sh,ps1}`. The two 403s are a highlight: `GET /auditlogs` (blocked at L7
before reaching the app, body `Access denied` from Envoy) vs `bob`'s account read (reaches the app, body
`Cedar denied: ...`) — **same network path, same L7-allowed route, different principal**. The identity rows
are the other highlight: the admission policy denies the *mismatched* forgery but **honestly admits** the
self-consistent one — the residual that mutual auth (below) is what actually closes.

Two further controls are demonstrated by their own scripts (not in the always-on suite, since both alter the
cluster substrate):
- **Mutual auth (SPIFFE)** — `kubectl apply -f k8s/netpol-mutual.yaml` upgrades the `web→api` edge to
  `authentication.mode: required`; the request still returns **200** because the SVID handshake completes
  (SPIRE issues each workload an identity from its ServiceAccount). Verified live.
- **Secret encryption-at-rest** — `scripts/enable-secrets-encryption.*` turns on AES-CBC in etcd and proves it
  by reading the raw datastore: the stored Secret begins `k8s:enc:aescbc:v1:` with **no plaintext**. Verified live.

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

./.venv/bin/python cedar/authz.py     # authz unit tests, no cluster needed -> 8/8
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
- `checkov` (Terraform + K8s) — **K8s 445 passed / 0 failed / 5 documented skips**, Terraform clean. Scope:
  checkov validates the *workloads + Terraform*; the CiliumNetworkPolicy (a CRD it can't see) and Cedar are
  covered by the live `verify` job and `cedar/authz.py`. Images are digest-pinned (`@sha256`) except the
  locally-built api image, which carries one *scoped* (not global) skip — see `.checkov.yaml` / `k8s/app.yaml`.
- Live enforcement — **18/18** checks in the table above pass on kind+Cilium+Tetragon (locally and in CI),
  on a pinned `kindest/node:v1.34.0` (k8s ≥1.30 so the identity admission policy installs). Mutual auth
  (SPIFFE) and Secret encryption-at-rest are each verified live by their own scripts.

## Roadmap

The core (IaC + zero-trust net incl. egress + inline Cedar authz + Tetragon runtime + CI) is in.

Done since:
- ✅ **Identity hardening (B7)** — threat model of label-as-identity (`THREAT_MODEL.md`), least-privilege per-tier ServiceAccounts + a `ValidatingAdmissionPolicy` binding the `app` label to its SA, and Cilium **mutual auth / SPIFFE** on the `web→api` edge (`k8s/netpol-mutual.yaml`). The residual (who may run as a tier SA) is documented honestly, not hidden.
- ✅ **Supply chain (partial)** — public images pinned by `@sha256` digest (the local api image carries a scoped, documented exception). Build provenance (cosign/SLSA) still open.
- ✅ **Data protection** — WireGuard pod-to-pod encryption (in transit) + Secret encryption-at-rest in etcd (`scripts/enable-secrets-encryption.*`); the three data states mapped to controls in `docs/06-data-protection.md`.
- ✅ **Learning labs** — numbered `docs/` walkthroughs (0–5), each break-and-fix.

Next:
- **Build provenance** — `cosign verify` + SLSA attestation for the api image.
- **SA-use admission** — bind the requesting identity to the ServiceAccounts it may reference (close the B7 residual).

## Notes

Local `kind` cluster — no cloud cost. Cedar policies port to **Amazon Verified Permissions**; Cilium policies
to any Cilium cluster (EKS/GKE/AKS). Identity (`X-User`) is **unauthenticated demo input** (charset-validated
to prevent injection); a real system derives the principal from a verified JWT `sub`. Entities are static
fixtures baked into the image. Learning/portfolio artifact, not turnkey prod. Licensed under [MIT](LICENSE).
