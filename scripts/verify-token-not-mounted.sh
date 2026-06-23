#!/usr/bin/env bash
# verify-token-not-mounted.sh — ID6 re-runnable proof: tier pods carry NO ServiceAccount token.
#
# The static half (automountServiceAccountToken=false in k8s/app.yaml) lives in the manifests; this
# is the LIVE half the coverage row claims ("token path ABSENT") — now a RE-RUNNABLE test, not a
# one-time manual `kubectl exec`. A mounted SA token is the credential a popped pod would use to
# reach the K8s API (B7); proving it is absent is defense-in-depth on top of the tier SA's zero RBAC.
# SKIP (rc=2) without a cluster. Run on the kind stack after rollout (CI integration job).
set -uo pipefail
CTX="${CTX:-kind-cloudsec}"
TOKEN_PATH="/var/run/secrets/kubernetes.io/serviceaccount/token"
k() { kubectl --context "$CTX" "$@"; }

command -v kubectl >/dev/null 2>&1 || { echo "SKIP: kubectl 없음 (FAIL 아님)"; exit 2; }
k cluster-info >/dev/null 2>&1       || { echo "SKIP: 클러스터 미응답 ($CTX)"; exit 2; }
k -n shop get deploy/web >/dev/null 2>&1 || { echo "SKIP: shop 스택 미배포"; exit 2; }

fail=0; checked=0
echo "== ID6: SA token not mounted on tier pods (live, re-runnable) =="
# Live-check the network-reachable tiers (web/api) — the ones ID6 has always claimed live. db is
# covered by the STATIC guarantee instead (db-sa + pod automountServiceAccountToken=false, k8s/app.yaml):
# db mounts an emptyDir at /var/run under readOnlyRootFS, which makes a live path-probe of that mount
# ambiguous, while automount=false guarantees no token at the API level regardless. (Not an overclaim:
# making this re-runnable is exactly what caught an earlier over-broadening of the claim to db-live.)
for app in web api; do
  pod="$(k -n shop get pod -l "app=$app" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
  if [ -z "$pod" ]; then echo "  SKIP: $app pod 없음"; continue; fi
  checked=$((checked + 1))
  if k -n shop exec "$pod" -- sh -c "test ! -e $TOKEN_PATH" >/dev/null 2>&1; then
    echo "  PASS  $app ($pod): $TOKEN_PATH ABSENT"
  else
    echo "  FAIL  $app ($pod): SA token mounted (automount leak)"; fail=1
  fi
done
# 측정 가드: web/api 파드를 하나도 검사 못 했으면 PASS로 떨어지면 안 된다 (false-PASS 방지).
if [ "$checked" -eq 0 ]; then
  echo "SKIP: 측정할 web/api 티어 파드가 없다 (스택 미배포/라벨 드리프트?) — ID6 미증명 (PASS 아님·FAIL 아님)"; exit 2
fi
echo "ID6 $([ "$fail" -eq 0 ] && echo 'PASS — tier pods carry no SA token (live).' \
                              || echo 'FAIL — a tier pod has a mounted SA token; check automountServiceAccountToken.')"
exit "$fail"
