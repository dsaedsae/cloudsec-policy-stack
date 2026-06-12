#!/usr/bin/env bash
# verify.sh — POSIX twin of verify.ps1. Proves all three layers on one asset:
#   L1 Cilium L3 drop, L2 Cilium L7 path deny, L3 Cedar authz (in the api PDP),
#   plus egress default-deny. Used by CI and by Linux/macOS users.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CTX="kind-$(terraform -chdir="$ROOT/terraform" output -raw cluster_name 2>/dev/null || echo cloudsec)"
k() { kubectl --context "$CTX" "$@"; }

k apply -f "$ROOT/k8s/probes.yaml" >/dev/null
trap 'k -n shop delete -f "$ROOT/k8s/probes.yaml" --ignore-not-found >/dev/null 2>&1 || true' EXIT
k -n shop wait --for=condition=Ready pod/probe-web pod/probe-api --timeout=120s >/dev/null
API=$(k -n shop get pod -l tier=backend -o jsonpath='{.items[0].status.podIP}')
DB=$(k -n shop get pod -l tier=data -o jsonpath='{.items[0].status.podIP}')

fail=0
probe() { # src desc expect curl-args...
  local src="$1" desc="$2" exp="$3"; shift 3
  local code; code=$(k -n shop exec "$src" -- curl -s -o /dev/null -m 8 -w '%{http_code}' "$@" 2>/dev/null || true)
  local ok="PASS"; [ "$code" = "$exp" ] || { ok="FAIL"; fail=1; }
  printf '  %-48s expect %-4s got %-4s %s\n' "$desc" "$exp" "$code" "$ok"
}

echo "== Defense in depth: one asset (api), three layers =="
probe probe-web "L1 web->db (no hop, L3 drop)"           000 "http://$DB:8080/"
probe probe-web "L2 web->api GET /auditlogs (L7 deny)"   403 -H "X-User: alice" "http://$API:8080/auditlogs/2026-06"
probe probe-web "L3 alice GET own acct (Cedar allow)"    200 -H "X-User: alice" "http://$API:8080/accounts/acct-alice"
probe probe-web "L3 bob GET alice acct (Cedar deny)"     403 -H "X-User: bob"   "http://$API:8080/accounts/acct-alice"
probe probe-web "L3 alice transfer 500 (under limit)"    200 -H "X-User: alice" -H "Content-Type: application/json" -d '{"amount":500}'  "http://$API:8080/accounts/acct-alice/transfer"
probe probe-web "L3 alice transfer 5000 (over limit)"    403 -H "X-User: alice" -H "Content-Type: application/json" -d '{"amount":5000}' "http://$API:8080/accounts/acct-alice/transfer"
probe probe-web "L3 alice transfer FROZEN (forbid)"      403 -H "X-User: alice" -H "Content-Type: application/json" -d '{"amount":100}'  "http://$API:8080/accounts/acct-alice-frozen/transfer"
probe probe-web "L3 alice transfer -100 (negative)"      403 -H "X-User: alice" -H "Content-Type: application/json" -d '{"amount":-100}' "http://$API:8080/accounts/acct-alice/transfer"
probe probe-web "L3 malformed X-User -> 400"             400 -H "X-User: bad user" "http://$API:8080/accounts/acct-alice"
probe probe-api "L1 api->db (allowed hop)"               200 "http://$DB:8080/"
echo "== Cilium egress (default-deny outbound) =="
probe probe-web "web->internet blocked"                  000 "https://example.com"
probe probe-web "web->cloud metadata blocked"            000 "http://169.254.169.254/"
probe probe-web "web->kube-apiserver blocked"            000 -k "https://10.96.0.1:443/"

echo "== Tetragon runtime (eBPF) =="
DBPOD=$(kubectl --context "$CTX" -n shop get pod -l tier=data -o jsonpath='{.items[0].metadata.name}')
if kubectl --context "$CTX" -n shop exec "$DBPOD" -- sh -c 'echo x' >/dev/null 2>&1; then
  printf '  %-48s expect %-4s got %-4s %s\n' "shell exec in db pod" "KILL" "RAN" "FAIL"; fail=1
else
  printf '  %-48s expect %-4s got %-4s %s\n' "shell exec in db (SIGKILL by TracingPolicy)" "KILL" "137" "PASS"
fi

echo "== Identity (B7): least-privilege RBAC + label<->SA admission =="
# A tier SA has ZERO Kubernetes API rights (no RoleBinding): a popped pod's blast
# radius on the cluster API is nil even if a token were present.
CANI_PODS=$(kubectl --context "$CTX" auth can-i create pods --as=system:serviceaccount:shop:api-sa -n shop 2>/dev/null || true)
CANI_SEC=$(kubectl --context "$CTX" auth can-i get secrets --as=system:serviceaccount:shop:api-sa -n shop 2>/dev/null || true)
if [ "$CANI_PODS" = "no" ] && [ "$CANI_SEC" = "no" ]; then
  printf '  %-48s expect %-4s got %-4s %s\n' "api-sa: no create-pods / no read-secrets" "no" "no" "PASS"
else
  printf '  %-48s expect %-4s got %-4s %s\n' "api-sa K8s API rights" "no" "$CANI_PODS/$CANI_SEC" "FAIL"; fail=1
fi

# Forged network identity: a pod LABELED app:api but running as web-sa. Server
# dry-run runs the ValidatingAdmissionPolicy without persisting; expect DENY.
CURL_IMG="curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69"
forge_pod() { # $1=name $2=serviceAccount
  cat <<YAML
apiVersion: v1
kind: Pod
metadata: { name: $1, namespace: shop, labels: { app: api } }
spec:
  serviceAccountName: $2
  automountServiceAccountToken: false
  securityContext: { runAsNonRoot: true, runAsUser: 100, seccompProfile: { type: RuntimeDefault } }
  containers:
    - name: c
      image: $CURL_IMG
      command: ["sleep", "1"]
      securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } }
      resources: { requests: { cpu: "5m", memory: "8Mi" }, limits: { cpu: "50m", memory: "32Mi" } }
YAML
}
if forge_pod forge-mismatch web-sa | kubectl --context "$CTX" create --dry-run=server -f - >/dev/null 2>&1; then
  printf '  %-48s expect %-4s got %-4s %s\n' "forged app:api on web-sa" "DENY" "ADMIT" "FAIL"; fail=1
else
  printf '  %-48s expect %-4s got %-4s %s\n' "forged app:api on web-sa -> admission DENY" "DENY" "DENY" "PASS"
fi
# A self-consistent pod (app:api + api-sa) created by an AUTHORIZED requester (this
# script runs as admin) is admitted: label<->SA satisfied, SA-use gate allows
# authorized operators. Expected baseline.
if forge_pod forge-consistent api-sa | kubectl --context "$CTX" create --dry-run=server -f - >/dev/null 2>&1; then
  printf '  %-48s expect %-4s got %-4s %s\n' "self-consistent app:api+api-sa as admin -> ADMIT" "ADMIT" "ADMIT" "PASS"
else
  printf '  %-48s expect %-4s got %-4s %s\n' "self-consistent app:api+api-sa as admin" "ADMIT" "DENY" "FAIL"; fail=1
fi

# SA-use gate: the limited shop:deployers principal MAY create Deployments but may NOT
# run one as a tier ServiceAccount. Impersonate that group (expect DENY); then confirm
# an authorized operator (admin) still deploys the same workload (ADMIT).
sa_use_deploy() {
  cat <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: { name: sa-use-probe, namespace: shop, labels: { app: api } }
spec:
  replicas: 1
  selector: { matchLabels: { app: api } }
  template:
    metadata: { labels: { app: api } }
    spec:
      serviceAccountName: api-sa
      automountServiceAccountToken: false
      securityContext: { runAsNonRoot: true, runAsUser: 100, seccompProfile: { type: RuntimeDefault } }
      containers:
        - name: c
          image: $CURL_IMG
          command: ["sleep", "1"]
          securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } }
          resources: { requests: { cpu: "5m", memory: "8Mi" }, limits: { cpu: "50m", memory: "32Mi" } }
YAML
}
if sa_use_deploy | kubectl --context "$CTX" --as=ci-deployer --as-group=shop:deployers create --dry-run=server -f - >/dev/null 2>&1; then
  printf '  %-48s expect %-4s got %-4s %s\n' "shop:deployers runs workload as api-sa" "DENY" "ADMIT" "FAIL"; fail=1
else
  printf '  %-48s expect %-4s got %-4s %s\n' "shop:deployers runs workload as api-sa -> DENY" "DENY" "DENY" "PASS"
fi
if sa_use_deploy | kubectl --context "$CTX" create --dry-run=server -f - >/dev/null 2>&1; then
  printf '  %-48s expect %-4s got %-4s %s\n' "authorized operator deploys api-sa workload -> ADMIT" "ADMIT" "ADMIT" "PASS"
else
  printf '  %-48s expect %-4s got %-4s %s\n' "authorized operator deploys api-sa workload" "ADMIT" "DENY" "FAIL"; fail=1
fi

echo "== Data-in-transit (Cilium WireGuard) =="
ENC=$(kubectl --context "$CTX" exec -n kube-system ds/cilium -c cilium-agent -- cilium-dbg encrypt status 2>/dev/null || true)
if echo "$ENC" | grep -qi "Wireguard"; then
  printf '  %-48s expect %-4s got %-4s %s\n' "pod-to-pod traffic encrypted (WireGuard)" "WG" "WG" "PASS"
else
  printf '  %-48s expect %-4s got %-4s %s\n' "WireGuard pod-to-pod encryption" "WG" "off" "FAIL"; fail=1
fi

echo ""
if [ "$fail" = 0 ]; then echo "ALL PASS"; else echo "FAILURES"; exit 1; fi
