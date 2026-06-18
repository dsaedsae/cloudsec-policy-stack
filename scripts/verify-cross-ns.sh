#!/usr/bin/env bash
# verify-cross-ns.sh — NS5 LIVE proof: cross-NAMESPACE isolation of the sensitive tiers.
#
# A pod in a SEPARATE namespace (ns/intruder, no shop identity) must NOT reach shop's db or api
# (the data + logic tiers). The control probe is load-bearing: the intruder CAN reach web — by
# design (k8s/netpol.yaml allow-ingress-to-web uses fromEntities:["cluster"], the documented
# blast-radius). That control PROVES the intruder pod has L3 connectivity into shop, so the db/api
# blocks are POLICY isolation, not a missing route — and if the test apparatus is broken (pod not
# Ready, exec fails), the web control returns 000 and the whole run FAILS rather than silently
# "passing" the blocked checks. This is what makes NS5 VERIFIED rather than CONFIGURED.
#
# Honest scope: this proves the SENSITIVE tiers (db, api) are namespace-isolated. web is
# intentionally cluster-reachable (see allow-ingress-to-web) and is NOT claimed isolated.
#
# SKIP-first: exits 0 with a SKIP notice when no cluster is reachable (local dev). The CI
# integration job (kind + Cilium) is the live proof venue.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CTX="kind-$(terraform -chdir="$ROOT/terraform" output -raw cluster_name 2>/dev/null || echo cloudsec)"
k() { kubectl --context "$CTX" "$@"; }

if ! k cluster-info >/dev/null 2>&1; then
  echo "== no cluster ($CTX) — SKIP NS5 cross-ns live proof (the CI integration job proves it live) =="
  exit 0
fi

NS=intruder
cleanup() { k delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true; }
trap cleanup EXIT
k get ns "$NS" >/dev/null 2>&1 || k create ns "$NS" >/dev/null

# An outsider pod: hardened to pass restricted Pod Security, with NO shop identity/label.
cat <<YAML | k apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: intruder
  namespace: $NS
  labels: { role: intruder }
spec:
  automountServiceAccountToken: false
  securityContext: { runAsNonRoot: true, runAsUser: 100, seccompProfile: { type: RuntimeDefault } }
  containers:
    - name: c
      image: curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69
      command: ["sleep", "600"]
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: { drop: ["ALL"] }
      resources: { requests: { cpu: "5m", memory: "8Mi" }, limits: { cpu: "50m", memory: "32Mi" } }
YAML
if ! k -n "$NS" wait --for=condition=Ready pod/intruder --timeout=120s >/dev/null 2>&1; then
  echo "FAIL(NS5): intruder probe pod did not become Ready — cannot measure isolation." >&2
  exit 1
fi

WEB=$(k -n shop get pod -l tier=frontend -o jsonpath='{.items[0].status.podIP}')
API=$(k -n shop get pod -l tier=backend  -o jsonpath='{.items[0].status.podIP}')
DB=$(k -n shop get pod -l tier=data      -o jsonpath='{.items[0].status.podIP}')
if [ -z "$WEB" ] || [ -z "$API" ] || [ -z "$DB" ]; then
  echo "FAIL(NS5): could not resolve shop tier pod IPs (web=$WEB api=$API db=$DB)." >&2
  exit 1
fi

fail=0
hit() { local c; c=$(k -n "$NS" exec intruder -- curl -s -o /dev/null -m 8 -w '%{http_code}' "$1" 2>/dev/null || true); echo "${c:-000}"; }
check() { # desc mode got     mode: reachable|blocked   (000 = no connection)
  local desc="$1" mode="$2" got="$3" ok
  if [ "$mode" = blocked ]; then { [ "$got" = 000 ] && ok=PASS; } || ok=FAIL
  else { [ "$got" != 000 ] && ok=PASS; } || ok=FAIL; fi
  printf '  %-54s %-10s got %-4s %s\n' "$desc" "$mode" "$got" "$ok"
  [ "$ok" = PASS ] || fail=1
}

echo "== NS5 cross-namespace isolation (probing from ns/$NS, an outsider) =="
check "intruder -> web:8080  (control: cluster-reachable)" reachable "$(hit "http://$WEB:8080/")"
check "intruder -> db:8080   (sensitive tier ISOLATED)"    blocked   "$(hit "http://$DB:8080/")"
check "intruder -> api:8080  (sensitive tier ISOLATED)"    blocked   "$(hit "http://$API:8080/accounts/acct-alice")"

if [ "$fail" = 0 ]; then
  echo "PASS(NS5): db + api unreachable from a foreign namespace (policy isolation); web reachable by design (connectivity control held)."
else
  echo "FAIL(NS5): cross-namespace isolation did not hold as expected." >&2
fi
exit "$fail"
