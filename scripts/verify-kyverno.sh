#!/usr/bin/env bash
# verify-kyverno.sh — OPT-IN proof that the Kyverno SA-use ClusterPolicy enforces the
# gate CLUSTER-WIDE, in a SECOND namespace (not shop). Does NOT touch the always-on
# verify.sh suite. Self-contained: it creates its own namespace + a deployer identity
# that CAN create workloads but is NOT an authorized SA-use requester, so a DENY here
# is the Kyverno gate (asserted via its distinctive message), not an RBAC 403.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CTX="kind-$(terraform -chdir="$ROOT/terraform" output -raw cluster_name 2>/dev/null || echo cloudsec)"
k() { kubectl --context "$CTX" "$@"; }
NS=kyv-demo
CURL_IMG="curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69"
fail=0

# Precheck: the policy must be installed + Ready, else SKIP honestly (never fake).
READY=$(k get clusterpolicy sa-use -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
if [ "$READY" != "True" ]; then
  echo "SKIP: Kyverno ClusterPolicy sa-use not Ready (run scripts/enable-kyverno.sh first)"
  exit 0
fi

# Setup: a 2nd namespace + a Role/Group that may CREATE workloads but is not authorized
# for SA-use. The shop VAP does not apply here (binding is shop-only); Kyverno does.
k create namespace "$NS" --dry-run=client -o yaml | k apply -f - >/dev/null
cat <<YAML | k apply -f - >/dev/null
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { name: kyv-deployer, namespace: $NS }
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["create"]
  - apiGroups: ["batch"]
    resources: ["cronjobs"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { name: kyv-deployer, namespace: $NS }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: kyv-deployer }
subjects:
  - { kind: Group, name: "kyv:deployers", apiGroup: rbac.authorization.k8s.io }
YAML
trap 'k delete namespace "$NS" --ignore-not-found >/dev/null 2>&1 || true' EXIT

workload() { # $1=serviceAccountName
  cat <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: { name: sa-use-xns, namespace: $NS }
spec:
  replicas: 1
  selector: { matchLabels: { app: probe } }
  template:
    metadata: { labels: { app: probe } }
    spec:
      serviceAccountName: $1
      containers:
        - name: c
          image: $CURL_IMG
          command: ["sleep", "1"]
YAML
}

echo "== Kyverno cluster-wide SA-use (namespace: $NS, not shop) =="

# 1) Unauthorized deployer runs a workload as a TIER SA -> Kyverno DENY (by message).
DENY_OUT=$(workload api-sa | k --as=system:serviceaccount:$NS:ci --as-group=kyv:deployers create --dry-run=server -f - 2>&1 || true)
if echo "$DENY_OUT" | grep -qE "SA-use gate|sa-use|authorized operator"; then
  printf '  %-52s expect %-5s got %-5s %s\n' "deployer runs api-sa in $NS -> Kyverno DENY" "DENY" "DENY" "PASS"
else
  printf '  %-52s expect %-5s got %-5s %s\n' "deployer runs api-sa in $NS (Kyverno SA-use)" "DENY" "?" "FAIL"; fail=1
fi

# 2) Same deployer with a NON-tier SA -> ADMIT (gate is scoped to tier SAs, not a blanket block).
if workload default | k --as=system:serviceaccount:$NS:ci --as-group=kyv:deployers create --dry-run=server -f - >/dev/null 2>&1; then
  printf '  %-52s expect %-5s got %-5s %s\n' "deployer runs non-tier SA in $NS -> ADMIT" "ADMIT" "ADMIT" "PASS"
else
  printf '  %-52s expect %-5s got %-5s %s\n' "deployer runs non-tier SA in $NS" "ADMIT" "DENY" "FAIL"; fail=1
fi

# 3) Authorized operator (admin / kubeadm:cluster-admins) runs the SAME tier workload -> ADMIT.
if workload api-sa | k create --dry-run=server -f - >/dev/null 2>&1; then
  printf '  %-52s expect %-5s got %-5s %s\n' "authorized operator runs api-sa in $NS -> ADMIT" "ADMIT" "ADMIT" "PASS"
else
  printf '  %-52s expect %-5s got %-5s %s\n' "authorized operator runs api-sa in $NS" "ADMIT" "DENY" "FAIL"; fail=1
fi

echo "----------------------------------------------------------------"
if [ "$fail" = 0 ]; then echo "Kyverno cluster-wide SA-use: ALL PASS (proven in $NS)"; else echo "Kyverno cluster-wide SA-use: FAILURES above"; fi
exit $fail
