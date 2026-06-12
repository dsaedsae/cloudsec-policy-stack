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

B1–B6 are the original live-verified layers. **B7 is the one the other six all
silently depend on**, and is what this round hardens. `scripts/verify.{sh,ps1}`
now also exercises B7 directly: a tier ServiceAccount has zero K8s API rights; a
*mismatched* workload (`app: api` on `web-sa`) is denied at admission; the limited
`shop:deployers` principal trying to run a workload as `api-sa` is denied by the
SA-use gate, while an authorized operator deploying the same workload is admitted.

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

2. **Label↔SA *consistency* at admission** — `k8s/admission-policy.yaml` is a
   `ValidatingAdmissionPolicy` (built-in, GA in k8s ≥1.30 — the node image is
   pinned accordingly) that **rejects any pod claiming `app: web|api|db` whose
   label disagrees with its ServiceAccount**. This is a *consistency guard, not a
   closure*: it kills the trivial forgery (`kubectl run --labels app=api`, which
   defaults to the `default` SA → label≠SA → denied), and it lines the label up
   with the SA so the SPIFFE SVID (derived from the SA) and the network label
   agree. **What it does NOT do:** stop a principal who controls *both* fields
   from minting a *self-consistent* workload — a pod labeled `app: api` **and**
   running as `api-sa`. So the VAP is a necessary hygiene control, not the identity
   boundary on its own; that self-consistent case is what mitigation #3 addresses.

3. **SA-use gate — bind *use of a tier ServiceAccount* to an authorized requester**
   — `k8s/admission-sa-use.yaml` supplies the check Kubernetes lacks natively. The
   self-consistent case above survives the label↔SA policy because anyone who can
   create a Deployment may set `serviceAccountName: api-sa` (there is **no
   `serviceaccounts/use` gate** — PodSecurityPolicy, which had one, was removed in
   1.25). This `ValidatingAdmissionPolicy` reads `request.userInfo` and admits a
   workload running as `web-sa`/`api-sa`/`db-sa` **only** when the requester is a
   Kubernetes controller (`system:*`), a cluster admin (`system:masters`), or a
   member of `shop:tier-operators`. So the limited `shop:deployers` role can still
   deploy, but **can no longer run a workload under a tier identity** — verified
   live (impersonating `shop:deployers` to deploy as `api-sa` is denied; an admin
   deploy of the same workload is admitted). **Honest scope:** it covers Pods + apps
   workloads (Deployment/ReplicaSet/StatefulSet/DaemonSet) + batch Jobs in `shop`;
   CronJob and other namespaces apply the same pattern, and fully generic coverage
   is what a policy engine (Kyverno/Gatekeeper) generates from one rule. The trust
   is now **explicit and minimized** (named operators) rather than "anyone who can
   deploy."

4. **Cryptographic identity (mutual auth / SPIFFE)** — #1–#3 are *administrative*;
   the strongest layer makes identity *cryptographic*. Cilium **mutual
   authentication** is enabled in this repo (`terraform/main.tf`:
   `authentication.mutual.spire.{enabled,install.enabled}=true` stands up an
   in-cluster SPIRE), and `k8s/netpol-mutual.yaml` upgrades the `web→api` edge to
   `authentication.mode: required`. Each workload gets a SPIFFE SVID derived from
   its **ServiceAccount**, and the api endpoint refuses any peer that cannot
   complete the mTLS handshake — so a forged *label* alone is necessary-but-
   insufficient. The chain — RBAC (who may deploy) → label/SA consistency → SA-use
   gate (who may run as a tier SA) → SVID handshake — raises the bar at every step.
   **What remains, stated plainly:** the SA-use gate trusts the admission layer and
   the named operators; a compromised admin or a gap in resource coverage (e.g.
   CronJob) is out of scope here, and a root-on-node attacker is below the whole
   model. The point is that each link is now a *named, minimized* trust rather than
   an open default.

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
- **Supply chain:** the public images (web/db, and the curl probe) are pinned by
  `@sha256` digest (B1 integrity); the `api` image is built locally and side-loaded
  via `kind load`, so it has no registry digest (a *scoped* checkov skip documents
  this — every other workload is still held to digest pinning). Build provenance
  (cosign/SLSA) is not yet verified — see README roadmap.
- **Data protection vs. access control.** B1–B7 govern *who may reach/do what*.
  Separately, this stack protects the **data itself**: pod-to-pod traffic is
  WireGuard-encrypted (data-in-transit, verified live), and Secrets can be
  AES-CBC encrypted in etcd (data-at-rest, `scripts/enable-secrets-encryption.*`).
  Honest scope: there is no real datastore here (the `db` tier is a placeholder
  and entities are static fixtures), so this demonstrates the *controls* mapped to
  data states, not a production data-lifecycle. See `docs/06-data-protection.md`.

## STRIDE quick-map

| Threat | Where it would land | Control |
|--------|--------------------|---------|
| **S**poofing identity | claim `app:` label to become `api` | RBAC (who may deploy) → label/SA consistency → SA-use gate (who may run as a tier SA) → mutual-auth SVID. Each link a named, minimized trust (B7). |
| **T**ampering | mutate pod spec/labels | PSA `restricted` + label/SA admission policy |
| **R**epudiation | who ran what in `db` | Tetragon process-exec audit trail |
| **I**nfo disclosure | exfil to internet/metadata | Cilium egress default-deny (B5) |
| **I**nfo disclosure | read data on the wire / in etcd | WireGuard (in-transit) + Secret encryption (at-rest) |
| **D**enial of service | resource exhaustion | per-container CPU/memory limits |
| **E**levation of privilege | shell in data tier | Tetragon SIGKILL (B6); drop-ALL-caps, no-priv-esc |

The point of the table is not completeness — it is that every row maps to a
control **implemented in this repo**, and that the ones billed as enforced are
exercised by `cedar/authz.py` or the live `verify` job. Where a control only
*raises* the bar rather than closing a threat (the Spoofing row), the row says so
and the residual is named above — that honesty is the point, not a clean table.
