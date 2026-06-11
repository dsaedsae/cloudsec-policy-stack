#!/usr/bin/env bash
# down.sh — tear everything down.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CTX="kind-cloudsec"
kubectl --context "$CTX" delete -f "$ROOT/k8s/netpol.yaml" --ignore-not-found 2>/dev/null || true
kubectl --context "$CTX" delete -f "$ROOT/k8s/app.yaml" --ignore-not-found 2>/dev/null || true
terraform -chdir="$ROOT/terraform" destroy -input=false -auto-approve
echo "Down."
