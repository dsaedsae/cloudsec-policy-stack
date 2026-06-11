# Threat model

A defense-in-depth stack is only as honest as the assumptions under each layer.
This document states what each control *does* protect, what it *doesn't*, and —
most importantly — **what the layers themselves trust**. The interesting gap in a
Cilium + Cedar design is identity: who gets to *be* `web` or `api`.

## System under analysis

```
client ──▶ web (frontend) ──▶ api (backend, Cedar PDP) ──▶ db (data)
            CiliumNetworkPolicy enforces the arrows; Cedar authorizes inside api;
            Tetragon watches every exec; checkov gates the manifests in CI.
```

- **Namespace** `shop`, Pod Security Admission `restricted`.
- **Network identity** is derived by Cilium from **pod labels** (`app: web|api|db`).
- **Application identity** (`X-User`) is an HTTP header consumed by the Cedar PDP.
- Workloads are non-root, drop ALL caps, read-only rootfs, and **do not mount a
  ServiceAccount token** (`automountServiceAccountToken: false`).

## Trust boundaries

| # | Boundary | Crossing | Control |
|---|----------|----------|---------|
| B1 | Internet / cluster edge → `web` | inbound request | Cilium ingress (only `web:8080` reachable) |
| B2 | `web` → `api` | east-west call | Cilium L3 + **L7** (only `GET/POST /accounts/*`) |
| B3 | inside `api` | per-request decision | **Cedar** (owner, limit, frozen, role) |
| B4 | `api` → `db` | east-west call | Cilium L3 (only `api`→`db:8080`) |
| B5 | any pod → outside | egress / exfil | Cilium egress default-deny (DNS + next-hop only) |
| B6 | compromised workload | post-exploit behavior | Tetragon (SIGKILL shell exec in `db`) |
| **B7** | **K8s API → pod identity** | **who may create/label pods** | **RBAC + admission policy** ← the identity TCB |

B1–B6 are the live-verified layers (`scripts/verify.sh`, 14/14). **B7 is the one
the other six all silently depend on**, and is what this round hardens.

## The identity problem (B7) — why labels are a TCB

Cilium computes a workload's security identity from its **labels**. Policy B2 says
"traffic from `app: web` may reach `api`." That sentence is only as trustworthy as
the answer to: *who can create a pod labeled `app: web`?*

> Anyone with RBAC to `create`/`patch` pods (or `patch` a pod's labels) in `shop`
> can mint a workload that **is** `web` or `api` to Cilium — and walk straight
> through the network policy. The Cedar PDP is also bypassed if the attacker
> simply talks to `db` *as* `api`.

So the network and authz layers inherit the Kubernetes API's authorization as part
of their trusted computing base. A defense-in-depth story that stops at "we have a
NetworkPolicy" is incomplete: **label integrity is a precondition for network
identity.** This is the single most common gap reviewers find in policy-as-code
portfolios, and it is exactly where this stack now adds controls.

### Mitigations in this repo

1. **Least-privilege ServiceAccounts** — `k8s/rbac.yaml` gives each tier its own
   SA (`web-sa`/`api-sa`/`db-sa`) with **no RoleBinding at all**, so a popped pod
   that *did* get a token (it doesn't — tokens are unmounted) still has **zero**
   Kubernetes API rights. Verify:
   `kubectl auth can-i --list --as=system:serviceaccount:shop:api-sa` → only the
   public baseline; it cannot create pods, read secrets, or patch anything.

2. **Label↔identity binding at admission** — `k8s/admission-policy.yaml` is a
   `ValidatingAdmissionPolicy` (built-in, GA) that **rejects any pod in `shop`
   whose `app` label doesn't match its ServiceAccount**. You cannot create a pod
   labeled `app: api` running as `web-sa`; the forged-identity move is denied
   before the object is persisted — no external admission controller required.

3. **Cryptographic identity (production path)** — labels are *administratively*
   asserted; the strongest fix makes identity *cryptographic*. Cilium **mutual
   authentication** issues each workload a SPIFFE identity (SPIRE) and can require
   it on a policy edge (`authentication.mode: required`). `k8s/netpol-mutual.yaml`
   shows the `web→api` edge upgraded to require mutual auth, and
   `terraform/main.tf` carries the Helm flag to enable the SPIRE backend. Then a
   forged label is not enough — the peer must also present a valid SVID.

## What each layer does NOT protect against (residual risk)

- **`X-User` is unauthenticated demo input.** It is charset-validated to prevent
  injection, but the PDP trusts the caller to state who they are. A real system
  derives the principal from a **verified JWT `sub`** (or mTLS SVID), not a header.
  This is deliberate scoping for a local portfolio, stated in the README too.
- **Cilium identity still trusts the CNI and kernel.** mutual auth raises the bar
  to "compromise SPIRE or the node," but a root-on-node attacker is out of scope.
- **checkov sees manifests, not runtime.** It cannot see the CiliumNetworkPolicy
  CRD or Cedar logic; those are covered by `cedar/authz.py` and the live `verify`
  job. "0 findings" is never claimed as "secure" — see `.checkov.yaml` triage.
- **Entities are static fixtures** baked into the api image; there is no user
  store, rotation, or revocation. Out of scope for the demo, called out as such.
- **Supply chain:** images are pinned by `@sha256` digest (B1 integrity), but this
  repo does not yet verify build provenance (cosign/SLSA) — see README roadmap.

## STRIDE quick-map

| Threat | Where it would land | Control |
|--------|--------------------|---------|
| **S**poofing identity | forge `app:` label → become `api` | RBAC + admission policy (B7); mutual auth |
| **T**ampering | mutate pod spec/labels | PSA `restricted` + admission policy |
| **R**epudiation | who ran what in `db` | Tetragon process-exec audit trail |
| **I**nfo disclosure | exfil to internet/metadata | Cilium egress default-deny (B5) |
| **D**enial of service | resource exhaustion | per-container CPU/memory limits |
| **E**levation of privilege | shell in data tier | Tetragon SIGKILL (B6); drop-ALL-caps, no-priv-esc |

The point of the table is not completeness — it is to show every row maps to a
control that exists in this repo and is tested, not aspirational.
