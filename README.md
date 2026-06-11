# cloudsec-policy-stack

**Defense-in-depth, as code, on a free local cluster.** Three policy layers that
a real cloud-native security role owns — provisioning, network, and application
authorization — wired into one runnable stack with a shift-left security gate.

```
            ┌─────────────────────────────────────────────────────────┐
  Terraform │  kind cluster + Cilium (CNI)   ← infra & network plane    │  IaC
  ──────────┼─────────────────────────────────────────────────────────┤
   Cilium   │  default-deny in+out ▸ web ─HTTP GET─▶ api ─▶ db          │  L3/L4 + L7
            │  egress locked: no pod may reach the internet/metadata     │  (ingress+egress)
  ──────────┼─────────────────────────────────────────────────────────┤
   Cedar    │  who may do which action on which resource (authz-as-code)│  app layer
            └─────────────────────────────────────────────────────────┘
   checkov  │  shift-left scan of Terraform + K8s manifests (CI gate)
```

## What it demonstrates

- **IaC (Terraform)** — the cluster *and* its CNI are declarative/reproducible; `terraform validate` clean.
- **Zero-trust network policy (Cilium / eBPF)** — default-deny on **both ingress and egress**, then
  least-privilege hops. The `web→api` rule is **L7**: only `GET /get*` is allowed; a different path/method
  is dropped by Cilium's Envoy proxy, not just L3/L4. Egress is locked to the next hop + DNS only, so a
  **compromised pod cannot reach the internet, cloud metadata, or the API server** (proven live below).
- **Authorization as code (Cedar)** — the same policy language as Amazon Verified Permissions, evaluated
  locally and **unit-tested** (`forbid` overrides `permit`; context-based transfer limits; role hierarchy).
- **Shift-left gate (checkov)** — scans Terraform + K8s; workloads are hardened (non-root, no priv-esc, all
  caps dropped, read-only rootfs, seccomp, probes, limits). Intentional exceptions live in `.checkov.yaml`
  with written justifications — triage, not "0 findings" theater.

## Layout

```
terraform/   kind + Cilium (helm)         k8s/app.yaml     hardened 3-tier app
cedar/       schema + policies + tests    k8s/netpol.yaml  CiliumNetworkPolicy (L3/L7)
scripts/     up / verify / scan / down    .checkov.yaml    documented scan baseline
```

## Quickstart

Prereqs: Docker, `kind`, `kubectl`, `helm`, `cilium`, `terraform`, Python 3.12.

```powershell
python -m venv .venv ; .venv\Scripts\python -m pip install cedarpy checkov

.venv\Scripts\python cedar\authz.py        # authz tests (no cluster needed)  -> 7/7
powershell scripts\scan.ps1                # checkov gate (Terraform + K8s)
powershell scripts\up.ps1                  # provision kind+Cilium, deploy app + policies
powershell scripts\verify.ps1              # prove enforcement (network + authz)
powershell scripts\down.ps1                # tear down
```

## What `verify.ps1` proves

| Hop | Path/Method | Expected | Why |
|-----|-------------|----------|-----|
| web → api | `GET /get` | **ALLOW (200)** | L7 rule permits this method+path |
| web → api | `GET /headers` | **DENY (403)** | L7: wrong path dropped by Envoy |
| web → db | any | **DENY (000)** | no ingress rule allows web→db (L3 drop) |
| api → db | any | **ALLOW (200)** | least-privilege hop permitted |
| web → internet | `https://example.com` | **DENY (000)** | egress default-deny — no exfil/beacon |
| api → internet | `https://example.com` | **DENY (000)** | egress default-deny |
| Cedar | 7 authz scenarios | **7/7** | owner/limit/frozen/role (offline PDP tests) |

> All six network rows are **verified live** (kind+Cilium). The Cedar row is an offline
> policy-decision test today; wiring Cedar inline as the api's request-time PDP is on the roadmap.

## Validation status

- `cedar/authz.py` — schema validates, **7/7** authorization scenarios pass.
- `terraform validate` — **clean**.
- `checkov` — **workload hardening: 258 passed / 0 failed** (K8s), 4 documented suppressions.
  Scope: checkov validates the *workloads*; it does **not** evaluate the CiliumNetworkPolicy (a CRD it
  can't see) or Cedar — those have their own gates (live verify + `cedar/authz.py`).
- Live network enforcement (ingress L3/L4+L7 **and** egress) — `scripts/up.ps1` then `scripts/verify.ps1`.

## Roadmap (review-driven)

Senior review (5 perspectives) rated the core respectable; these raise it toward production-grade:
- **CI** — GitHub Actions running `terraform validate` + checkov + `cedar/authz.py` + a kind integration job.
- **Cedar inline** — replace the demo api with a tiny PDP service that calls Cedar at request time, so one
  request traverses all three layers (network → L7 → authz) end to end.
- **Cross-platform** — POSIX `*.sh`/Makefile beside the PowerShell scripts.
- **Runtime layer** — Tetragon (eBPF) TracingPolicy for runtime detection; Hubble for flow visibility.
- **Supply chain** — pin images by digest + `cosign verify`; `requirements.txt` for pinned Python deps.

## Notes

Local `kind` cluster — no cloud cost. Cedar policies are portable to **Amazon Verified Permissions**;
Cilium policies to any Cilium-enabled cluster (EKS/GKE/AKS). Learning/portfolio artifact, not turnkey prod.
Licensed under [MIT](LICENSE).
