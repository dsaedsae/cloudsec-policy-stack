# Lab 4 — Identity: who gets to *be* `web` or `api` (B7)

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

Now change `web-sa` to `api-sa` above and re-run. It is **admitted**. The policy
only enforces label↔SA *consistency*; a self-consistent pod (`app: api` + `api-sa`)
is a perfectly valid `api`. And because modern Kubernetes has no
`serviceaccounts/use` gate (PodSecurityPolicy was removed in 1.25), anyone who can
create a Deployment in `shop` can choose `serviceAccountName: api-sa`. So the
admission policy is a *consistency guard*, not the identity boundary. The real
boundaries are (1) RBAC over who may create workloads at all, and (2) cryptographic
identity, next.

## Control 3 — cryptographic identity (mutual auth / SPIFFE)

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
valid SVID, which it cannot mint without the SA's cryptographic identity. The one
residual that remains — who may run a workload *as* `api-sa` — is an RBAC/admission
question (bind the requester to the SAs they may use), and is named honestly as the
next step in the threat model.

## Make it yours

The `verify` scripts assert all of this: `api-sa` has no API rights, the mismatched
forgery is denied, and (documented, not hidden) the self-consistent one is admitted.
Try adding a fourth tier (`app: cache` + `cache-sa`) to `k8s/rbac.yaml` and the
admission policy, then watch a `cache`-labeled pod on the wrong SA get denied.

---

Identity is the layer the other six depend on. Next: protecting the **data** those
identities touch — [Lab 5: data protection](06-data-protection.md). Back to the
[learning path](README.md).
