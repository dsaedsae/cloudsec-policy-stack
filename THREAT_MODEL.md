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

## Attacker model

We make the adversary explicit (security claims are only meaningful against a stated
attacker). Three concrete profiles, each mapped to the controls that stop it and the
`verify` check that proves it:

| # | Attacker | Capability | Goal | Stopped by (verify) | Residual |
|---|----------|-----------|------|---------------------|----------|
| **A1** | **Popped `web` pod** | RCE inside the `web` container (e.g. via a web vuln) | reach `db`, exfiltrate, beacon out, escalate | L3 drop `web→db` (`000`); egress default-deny → internet/metadata/apiserver (`000`); unmounted SA token → no cluster API. (Note: Tetragon's shell-kill targets `tier: data`, so it protects `db` *if* the attacker pivots there — not `web` itself.) | A root-on-node escape; a non-shell post-exploit that stays within `web`'s allowed L7 calls |
| **A2** | **Malicious / compromised `shop:deployers`** | can `create` Deployments/Jobs/CronJobs in `shop` (CI identity) | run a workload **as a tier identity** (`api-sa`) to *become* `api` | label↔SA admission (mismatch DENY); **SA-use gate** denies a non-operator running as a tier SA — incl. via Deployment **and CronJob** (`SA-use DENY`) | An *authorized* operator (cluster-admin / `shop:tier-operators`) is trusted by design; a `system:serviceaccount:kube-system:*` controller is trusted |
| **A3** | **On-path between nodes** | passive capture of inter-node pod traffic | read `X-User` / account data on the wire | Cilium **WireGuard** encrypts cross-node pod traffic (ciphertext, not plaintext) | Same-node hops don't traverse the wire; a host/kernel compromise; mutual-auth (SVID) is opt-in on the demo edge |

**Out of scope (stated, not hand-waved):** root-on-node / kernel compromise; a malicious
cluster-admin (the top of every trust chain); supply-chain compromise of an upstream
image *before* digest pinning; the unauthenticated `X-User` demo input (a real system
derives the principal from a verified JWT/SVID). These are the honest edges — each
control raises the bar against A1–A3, not against an attacker who owns the substrate.

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
| **B8** | **Git repo / reconciler → cluster desired-state** | **who may merge + what the controller may apply/impersonate** | **AppProject scoping + signed commits + the reconciler's own least-priv RBAC** ← B7 *relocated* (M10) |

B1–B6 are the original live-verified layers. **B7 is the one the other six all
silently depend on**, and is what this round hardens. `scripts/verify.{sh,ps1}`
now also exercises B7 directly: a tier ServiceAccount has zero K8s API rights; a
*mismatched* workload (`app: api` on `web-sa`) is denied at admission; the limited
`shop:deployers` principal trying to run a workload as `api-sa` is denied by the
SA-use gate, while an authorized operator deploying the same workload is admitted.

**B8 (M10 — GitOps) does not add a control; it *relocates* B7.** Under GitOps the
question "who may create an `app: api` pod" becomes "who may merge to the repo, and
what may the reconciler ServiceAccount impersonate/apply." The reconciler is a new,
*re-centralized* identity-TCB: a controller with apply rights over RBAC, NetworkPolicy,
and admission policy can mint `api`, rewrite the VAP that guards it, and revert your
incident-response `kubectl edit` — so it must be minimized exactly as `shop:tier-operators`
was (AppProject allowlist + a named, non-`kube-system` reconciler SA; `k8s/rbac.yaml`
already foreshadows this — "map this Group to your privileged GitOps controller").
What it *does* add is a **runtime-integrity** control — drift on a tracked object is
auto-reverted within the sync interval — measured live in [M10](labs/m10/README.md). It
does **not** protect against a compromised Git repo or a signed-but-malicious PR (trust
is *moved* to code-review + signed commits, not created), it cannot revert what it does
not track, and ArgoCD itself is a net-new control-plane attack surface
([ADR 0002](docs/decisions/0002-argocd-gitops-relocates-identity-tcb.md)).

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
   kube-system workload controller (`system:serviceaccount:kube-system:*`), a cluster
   admin (`system:masters` / `kubeadm:cluster-admins`), or a member of
   `shop:tier-operators` — deliberately **not** the broad `system:*` (which also
   matches a CI/app SA and would be a bypass). So the limited `shop:deployers` role can still
   deploy, but **can no longer run a workload under a tier identity** — verified
   live (impersonating `shop:deployers` to deploy as `api-sa` is denied; an admin
   deploy of the same workload is admitted). **Honest scope:** it covers Pods + apps
   workloads (Deployment/ReplicaSet/StatefulSet/DaemonSet) + batch Jobs **and CronJobs**
   in `shop` (each resolved to the SA via its own template path); *other namespaces*
   apply the same pattern, and fully generic coverage is what a policy engine
   (Kyverno/Gatekeeper) generates from one rule — **provided here as an opt-in
   capstone** (`k8s/kyverno-sa-use.yaml` + `scripts/enable-kyverno.*`/`verify-kyverno.*`),
   and it is now **stood up and proven live** — the Kyverno SA-use ClusterPolicy denies a
   tier-SA workload created in a *second* namespace (`scripts/verify-kyverno`), so the
   cross-namespace claim (coverage ID7) is now **VERIFIED**. Note the generalization carries the
   **same scoping caveat**: like the VAP it gates the workload *controller*, not the
   controller-spawned Pod (a Pod's `userInfo` is its controller's SA). The trust
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
   the named operators; a compromised admin, resource kinds outside the matched set
   (other namespaces; a future API kind), or a root-on-node attacker are out of scope
   here. The point is that each link is now a *named, minimized* trust rather than
   an open default.

## What each layer does NOT protect against (residual risk)

- **`X-User` is unauthenticated demo input.** It is charset-validated to prevent
  injection, but the PDP trusts the caller to state who they are. A real system
  derives the principal from a **verified JWT `sub`** (or mTLS SVID), not a header.
  This is deliberate scoping for a local portfolio, stated in the README too.
- **Cilium identity still trusts the CNI and kernel.** mutual auth raises the bar
  to "compromise SPIRE or the node," but a root-on-node attacker is out of scope.
- **The shipped runtime rule is zero-exec (robust for data-tier exec); residuals are below.** The
  data tier runs only its main process (db probes are `httpGet`, not exec), so the shipped
  `TracingPolicy` hooks **both `sys_execve` and `sys_execveat`** and SIGKILLs **all** exec in
  `tier: data` — `id` / `sh` / a renamed `/tmp/x` busybox copy / busybox-by-name all rc 137, while
  nginx (PID 1, exec'd before the policy) keeps serving (live-validated, kind + Tetragon 1.7.0). It is
  **arg0/name-independent and covers execveat**, so the bypasses that defeat a naive rule are closed.
  *Why zero-exec and not a selective shell-name rule:* the earlier arg0-Postfix cut (now the **M4 lab
  primitive** `block-shell-in-data-tier`) killed only the naive `kubectl exec … sh` case and was
  evadable — (a) **renamed binary** (`cp /bin/busybox /tmp/x && /tmp/x sh`, arg0 unmatched),
  (b) **execveat** (a syscall a lone `sys_execve` kprobe never sees), (c) **fd-exec** (arg0
  `/proc/self/fd/N`); and `matchBinaries` is the WRONG fix (on `sys_execve` it matches the *caller*, so
  `NotIn [/usr/sbin/nginx]` kills `nginx -v` and MISSES an in-nginx-RCE shell whose caller is nginx).
  Forbidding ALL exec sidesteps name/arg0 spoofing entirely. Decision record:
  `docs/decisions/0001-data-tier-zero-exec.md`; the selective→bypass→zero-exec measurement is Lab M8.
  **Residual risk that REMAINS under zero-exec:** (1) restart-tolerance comes from Tetragon's
  enforcement-attach **window**, not the image — validated live that BOTH the alpine image AND a
  distroless `chainguard/nginx` come up Ready with the policy active from t=0 (the PID1 entrypoint
  execve slips the window; fragile + image-independent; a faster attach could SIGKILL the entrypoint
  → CrashLoop). (2) It scopes the **data tier only** — web/api tiers are not zero-exec (ED3
  NOT_COVERED). (3) I/O is detection- not prevention-grade, and (4) the io_uring/LSM surface still
  applies (both next bullets). **Defense-in-depth — image layer:** a distroless data-tier image ships
  NO `/bin/sh` and NO busybox (validated: `/bin/sh` → "no such file" before the policy applies), so it
  removes the shell entirely while this runtime rule still kills any binary an attacker WRITES into a
  writable mount — use both. An allowlist (some exec permitted) would need **BPF-LSM**
  (`security_bprm_creds_for_exec`) for binary identity, not arg0 strings. Surfaced by expert review,
  live-validated in Lab M8.
- **Runtime detection watches the *syscall* surface — which has a known evasion class.**
  `execve` has no io_uring opcode, so io_uring does not route around the exec rule — a *narrow* fact
  about io_uring, not a completeness claim. The exec defense's real residuals (attach-window, other
  tiers) are in the bullet above; arg0/execveat/fd-exec spoofing is **closed** by zero-exec. Broader
  syscall-kprobe rules (file read/write, network connect) CAN be bypassed via **io_uring**'s
  submission queue (ARMO "Curing" PoC, 2025). Robust answer: hook the **LSM layer (BPF-LSM/KRSI)**,
  which observes the kernel *operation* regardless of invocation. Precision (per ARMO): Tetragon's
  **default syscall policies** are io_uring-blind, not Tetragon itself — kprobe/LSM hooks *can* see
  io_uring — so "default syscall policies are blind; LSM/KRSI would see it," NOT "Tetragon is
  bypassed." Stated residual (doc-only / NOT_COVERED); the single `execve` rule is intentionally narrow.
- **The kill is detection-grade for I/O, prevention-grade only for execve (timing).** The
  execve+Sigkill rule kills *before the new image loads* (the shell never runs its first
  command — prevention-grade). But Tetragon's own docs note a SIGKILL sent during a `write()`
  does **not** guarantee the bytes were not written — the process dies synchronously, yet the
  kernel may already have done the I/O (detection-point ≠ prevention-point). Making a kprobe
  rule prevention-grade for I/O requires combining Sigkill with the **Override** action; our
  shell rule is Sigkill-only by design. In **Lab M8** (`labs/m8/`) the *scope* is measured live
  (`scripts/verify-runtime-scope.ps1`: sh=137 / id=0 / cat=0), while the I/O write-window is
  *explored* (documented Tetragon caveat + a SKIP-prone learner policy, not measured here) and the
  execve pre-image-load timing is documented kprobe semantics. ED1 stays VERIFIED — M8 sharpens its meaning, not its status.
- **Egress allows unrestricted DNS — a residual covert-exfil/C2 channel.** The egress
  baseline (B5) lets every pod resolve via kube-dns with `matchPattern: "*"` (k8s/netpol.yaml).
  A popped pod that cannot open a TCP beacon CAN still tunnel data out over DNS queries
  (DNS-tunnel exfil) — so "cannot beacon out" is precise about *TCP* egress, not a claim of
  zero covert egress. Hardening: restrict the pattern to in-cluster suffixes
  (`*.svc.cluster.local` + the needed upstreams) or add egress-DNS inspection. Named here as a
  residual (surfaced by expert review).
- **checkov sees manifests, not runtime.** It cannot see the CiliumNetworkPolicy
  CRD or Cedar logic; those are covered by `cedar/authz.py` and the live `verify`
  job. "0 findings" is never claimed as "secure" — see `.checkov.yaml` triage.
- **Entities are static fixtures** baked into the api image; there is no user
  store, rotation, or revocation. Out of scope for the demo, called out as such.
- **Supply chain:** the public images (web/db, and the curl probe) are pinned by
  `@sha256` digest (B1 integrity); the `api` image is built locally and side-loaded
  via `kind load`, so it has no registry digest (a *scoped* checkov skip documents
  this — every other workload is still held to digest pinning). Build provenance
  (cosign) image SIGNING is now verified on a **local-key path** — a local OCI registry
  (removing the cosign#3832 no-registry blocker) + keyful cosign + Kyverno verifyImages
  proves signed→ADMIT / unsigned→DENY at admission (`scripts/verify-image-signing`,
  coverage SL6). Keyless/Rekor + SLSA provenance attestation remain the ECR-path roadmap.
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
