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

echo ""
if [ "$fail" = 0 ]; then echo "ALL PASS"; else echo "FAILURES"; exit 1; fi
