#!/usr/bin/env bash
# up.sh — POSIX twin of up.ps1. Stand up the whole stack locally (free).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CTX="kind-cloudsec"

# Helm provider needs the chart repo cached first.
helm repo add cilium https://helm.cilium.io/ 2>/dev/null || true
helm repo update cilium >/dev/null

terraform -chdir="$ROOT/terraform" init -input=false >/dev/null
# Provider config depends on cluster outputs -> create the cluster first, then Cilium.
terraform -chdir="$ROOT/terraform" apply -input=false -auto-approve -target=kind_cluster.this
terraform -chdir="$ROOT/terraform" apply -input=false -auto-approve

cilium status --context "$CTX" --wait

docker build -t cloudsec-api:local -f "$ROOT/app/api/Dockerfile" "$ROOT"
kind load docker-image cloudsec-api:local --name cloudsec

kubectl --context "$CTX" apply -f "$ROOT/k8s/app.yaml" -f "$ROOT/k8s/netpol.yaml" -f "$ROOT/k8s/tracingpolicy.yaml"
for d in web api db; do kubectl --context "$CTX" -n shop rollout status "deploy/$d" --timeout=180s; done
echo "Up. Run scripts/verify.sh"
