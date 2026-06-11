# cloudsec-policy-stack

**Defense-in-depth, as code, on a free local cluster.** Three policy layers that
a real cloud-native security role owns — provisioning, network, and application
authorization — wired into one runnable stack with a shift-left security gate.

```
            ┌─────────────────────────────────────────────────────────┐
  Terraform │  kind cluster + Cilium (CNI)   ← infra & network plane    │  IaC
  ──────────┼─────────────────────────────────────────────────────────┤
   Cilium   │  default-deny  ▸  web ──HTTP GET──▶ api ──▶ db            │  L3/L4 + L7
  ──────────┼─────────────────────────────────────────────────────────┤
   Cedar    │  who may do which action on which resource (authz-as-code)│  app layer
            └─────────────────────────────────────────────────────────┘
   checkov  │  shift-left scan of Terraform + K8s manifests (CI gate)
```

## What it demonstrates

- **IaC (Terraform)** — the cluster *and* its CNI are declarative/reproducible; `terraform validate` clean.
- **Zero-trust network policy (Cilium / eBPF)** — default-deny, then least-privilege hops. The `web→api`
  rule is **L7**: only `GET /get*` is allowed; a different path/method is dropped by Cilium's Envoy proxy,
  not just L3/L4.
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
| web → api | `GET /get` | **ALLOW** | L7 rule permits this method+path |
| web → api | `GET /headers` | **DENY** | L7: wrong path dropped by Envoy |
| web → db | any | **DENY** | no L3 rule allows web→db |
| api → db | any | **ALLOW** | least-privilege hop permitted |
| Cedar | 7 authz scenarios | **7/7** | owner/limit/frozen/role rules |

## Validation status

- `cedar/authz.py` — schema validates, **7/7** authorization scenarios pass.
- `terraform validate` — **clean**.
- `checkov` (K8s) — **258 passed / 0 failed**, 4 documented suppressions.
- Live network enforcement — run `scripts/up.ps1` then `scripts/verify.ps1` (local kind, free).

## Notes

Local `kind` cluster — no cloud cost. Cedar policies are portable to **Amazon Verified Permissions**;
Cilium policies to any Cilium-enabled cluster (EKS/GKE/AKS). This is a learning/portfolio artifact, not
a turnkey prod deployment.
