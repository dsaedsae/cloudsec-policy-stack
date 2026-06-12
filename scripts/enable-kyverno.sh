#!/usr/bin/env bash
# enable-kyverno.sh — OPT-IN capstone: install Kyverno (dev/kind-sized) and apply the
# cluster-wide SA-use ClusterPolicy. NOT part of the default scripts/up.* (it adds
# admission+background controllers = real RAM on top of Cilium+Tetragon+SPIRE).
#
# Idempotent (helm upgrade --install + kubectl apply). Twin of enable-secrets-encryption.*.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CTX="kind-$(terraform -chdir="$ROOT/terraform" output -raw cluster_name 2>/dev/null || echo cloudsec)"

helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update >/dev/null
helm repo update kyverno >/dev/null

# Dev-sized: single replica, and DISABLE the cleanup/reports controllers — we only demo
# the admission gate, so we don't pay for the extra controllers' RAM.
helm upgrade --install kyverno kyverno/kyverno -n kyverno --create-namespace \
  --kube-context "$CTX" \
  --set admissionController.replicas=1 \
  --set backgroundController.replicas=1 \
  --set cleanupController.enabled=false \
  --set reportsController.enabled=false \
  --wait --timeout 5m

kubectl --context "$CTX" apply -f "$ROOT/k8s/kyverno-sa-use.yaml"
kubectl --context "$CTX" wait --for=condition=Ready clusterpolicy/sa-use --timeout=120s
echo "Kyverno SA-use ClusterPolicy ready. Prove it cluster-wide: scripts/verify-kyverno.sh"
