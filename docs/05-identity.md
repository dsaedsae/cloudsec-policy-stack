# Lab 4 — Identity: who gets to *be* `web` or `api` (B7)

!!! tip "직접 해보기 (재구현 트랙)"
    라벨↔SA admission CEL을 직접 작성하라 → **[M2 · 신원 admission](../labs/m2/README.md)** (5/5, 클러스터 필요).

**Goal:** every layer so far trusts the pod's `app` label — Cilium derives network
identity from it. So the whole stack silently depends on one question: *who can
create a pod that claims `app: api`?* This lab makes that dependency explicit and
hardens it. It is the most common gap reviewers find in policy-as-code portfolios.

**Needs:** the cluster from [Lab 2](03-network-and-authz.md) (identity manifests
applied by `up.sh`). Background: [THREAT_MODEL.md](../THREAT_MODEL.md) §B7.

## The problem in one sentence

`CiliumNetworkPolicy` says "traffic from `app: web` may reach `api`." That is only
as trustworthy as the answer to *who may create a pod labeled `app: web`*. Anyone
with RBAC to create a workload in `shop` can mint a pod that **is** `web` (or `api`)
to Cilium — and walk straight through the network policy, bypassing Cedar too.

## Control 1 — least-privilege ServiceAccounts (blast radius)

Each tier runs as its own SA with **no RoleBinding at all**:

```bash
kubectl auth can-i create pods   --as=system:serviceaccount:shop:api-sa -n shop   # no
kubectl auth can-i get secrets   --as=system:serviceaccount:shop:api-sa -n shop   # no
kubectl auth can-i --list        --as=system:serviceaccount:shop:api-sa -n shop   # only the public baseline
```

Even though tokens aren't mounted (`automountServiceAccountToken: false`), if one
*were*, a popped `api` pod still has **zero** Kubernetes API rights. That is the
defense-in-depth point: minimize what a compromised workload can do to the cluster.

## Control 2 — label↔SA consistency at admission (break it)

`k8s/admission-policy.yaml` is a `ValidatingAdmissionPolicy` (built-in, GA in
k8s ≥1.30) that rejects a pod claiming `app: web|api|db` whose label disagrees with
its ServiceAccount. Try the trivial forgery — server dry-run runs admission without
creating anything:

```bash
cat <<'YAML' | kubectl create --dry-run=server -f -
apiVersion: v1
kind: Pod
metadata: { name: forge, namespace: shop, labels: { app: api } }
spec:
  serviceAccountName: web-sa            # claims api, runs as web -> mismatch
  automountServiceAccountToken: false
  securityContext: { runAsNonRoot: true, runAsUser: 100, seccompProfile: { type: RuntimeDefault } }
  containers:
    - name: c
      image: curlimages/curl:8.11.1
      command: ["sleep","1"]
      securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } }
      resources: { requests: { cpu: "5m", memory: "8Mi" }, limits: { cpu: "50m", memory: "32Mi" } }
YAML
```

Expected — denied before it is ever persisted:

```
... pod label app=api must run as ServiceAccount api-sa (got web-sa);
    forged network identity denied — see THREAT_MODEL.md B7
```

This kills the easy attack: `kubectl run --labels app=api ...` defaults to the
`default` SA, so label≠SA → denied.

## The honest part — what Control 2 does NOT close

Now change `web-sa` to `api-sa` above and re-run. It is **admitted**. Control 2 only
enforces label↔SA *consistency*; a self-consistent pod (`app: api` + `api-sa`) is a
perfectly valid `api`. And because modern Kubernetes has no `serviceaccounts/use`
gate (PodSecurityPolicy was removed in 1.25), anyone who can create a Deployment in
`shop` could otherwise choose `serviceAccountName: api-sa`. So Control 2 is a
*consistency guard*, not the identity boundary — that boundary is Control 3.

## Control 3 — SA-use gate (who may run as a tier identity)

`k8s/admission-sa-use.yaml` adds the missing `serviceaccounts/use` check at the
workload level. It reads `request.userInfo` and admits a workload running as
`web-sa`/`api-sa`/`db-sa` **only** for a kube-system workload controller
(`system:serviceaccount:kube-system:*`), a cluster admin (`system:masters` /
`kubeadm:cluster-admins`), or the `shop:tier-operators` group — **not** the broad
`system:*` (which would also match a CI/app SA and be a bypass). Try it as the
limited deploy role (impersonation; this group has `create deployments` but is not a
tier operator):

```bash
cat <<'YAML' | kubectl --as=ci-deployer --as-group=shop:deployers create --dry-run=server -f -
apiVersion: apps/v1
kind: Deployment
metadata: { name: probe, namespace: shop, labels: { app: api } }
spec:
  replicas: 1
  selector: { matchLabels: { app: api } }
  template:
    metadata: { labels: { app: api } }
    spec:
      serviceAccountName: api-sa            # run as the api tier identity
      containers: [{ name: c, image: curlimages/curl:8.11.1, command: ["sleep","1"],
        securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true,
        runAsNonRoot: true, runAsUser: 100, capabilities: { drop: ["ALL"] },
        seccompProfile: { type: RuntimeDefault } } }]
YAML
```

Expected — denied:

```
... running a workload as tier ServiceAccount 'api-sa' requires an authorized
    operator ...; requester 'ci-deployer' is not — see THREAT_MODEL.md B7 (SA-use gate)
```

Drop the `--as` flags (run as admin) and the **same** workload is admitted — the
legitimate rollout is unaffected, and so are the controller-created pods of the real
app (created by `system:serviceaccount:kube-system:*` controllers). So *use* of a tier
identity is now bound to a named, minimized set of requesters, not open to anyone who
can deploy. The `verify` scripts assert both the deny and the admit.

## Control 4 — cryptographic identity (mutual auth / SPIFFE)

`terraform/main.tf` enables Cilium mutual authentication (an in-cluster SPIRE issues
each workload a SPIFFE SVID derived from its ServiceAccount), and
`k8s/netpol-mutual.yaml` upgrades the `web→api` edge to require it:

```bash
kubectl apply -f k8s/netpol-mutual.yaml
# SPIRE must be ready first:
kubectl -n cilium-spire rollout status statefulset/spire-server
# web->api still works — the SVID handshake completes transparently:
WEB=$(kubectl -n shop get pod -l app=web -o jsonpath='{.items[0].metadata.name}')
API=$(kubectl -n shop get pod -l app=api -o jsonpath='{.items[0].status.podIP}')
kubectl -n shop exec "$WEB" -- curl -s -o /dev/null -w '%{http_code}\n' -H 'X-User: alice' "http://$API:8080/accounts/acct-alice"   # 200
```

Now a forged *label* is necessary-but-insufficient: the peer must also present a
valid SVID, which it cannot mint without the SA's cryptographic identity. The full
chain is now: **who may deploy** (RBAC) → **label matches SA** (Control 2) → **who
may run as a tier SA** (Control 3) → **must hold the SVID** (Control 4). What remains
is named honestly in the threat model — the SA-use gate trusts the admission layer
and the named operators, and a resource kind outside the matched set (it covers
Pods/Deployments/RS/STS/DS/Jobs/CronJobs in `shop`; other namespaces or a future API
kind) would extend the same one rule.

## Capstone (opt-in) — the SA-use gate, cluster-wide via Kyverno

The VAP above is hand-pinned to `shop`. The same rule expressed **once, generically,
cluster-wide** is a Kyverno `ClusterPolicy` (`k8s/kyverno-sa-use.yaml`): one rule over
Pods/Deployments/RS/STS/DS/Jobs/CronJobs in every namespace except the excluded ones
(`kube-system`, `kyverno`, and `shop` — the VAP already owns `shop`). It reproduces the
exact authorization predicate (`background: false`, since it reads `request.userInfo`).

```bash
scripts/enable-kyverno.sh     # helm install (dev-sized) + apply the ClusterPolicy
scripts/verify-kyverno.sh     # proves DENY/ADMIT in a SECOND namespace (not shop)
```

**Honest scope (two parts):** (1) Kyverno's real delta is *namespace genericity* and
*one rule vs per-kind CEL* — it does **not** remove the structural limit: a Pod created
by a controller carries the *controller's* SA in `userInfo`, so (exactly like the VAP)
the gate matches the workload **controller**, not the controller-spawned Pod, and an
authorized operator/cluster-admin stays trusted by design. (2) It is an **opt-in
capstone** (extra controllers = real RAM on top of Cilium+Tetragon+SPIRE), enabled via
`scripts/enable-kyverno`; it has now been **stood up and proven live** — `scripts/verify-kyverno`
shows the SA-use ClusterPolicy denying a tier-SA workload in a *second* namespace, so the
cross-namespace coverage row (ID7) is now **VERIFIED** (opt-in). The modern equivalent is the new
Kyverno `ValidatingPolicy` / native VAP cluster-wide — this is one of three honest ways.

## Make it yours

The `verify` scripts assert all of this: `api-sa` has no API rights, the mismatched
workload is denied, the limited `shop:deployers` principal is denied from running a
workload as `api-sa`, and an authorized operator deploying the same workload is
admitted. Try adding a fourth tier (`app: cache` + `cache-sa`) to `k8s/rbac.yaml` and
both admission policies, then watch a `cache`-labeled pod on the wrong SA get denied.

---

Identity is the layer the other six depend on. Next: protecting the **data** those
identities touch — [Lab 5: data protection](06-data-protection.md). Back to the
[learning path](README.md).
