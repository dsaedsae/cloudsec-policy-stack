#!/usr/bin/env bash
# enable-gitops.sh — OPT-IN: install ArgoCD (dev-sized) + apply the app-of-apps root.
#
# This is "the documented last imperative act": a push-model, admin-kubectl install of the
# pull-model reconciler. GitOps cannot bootstrap itself (ADR 0002 / B8 — turtles all the way down).
# Mirrors scripts/enable-kyverno.* (opt-in, idempotent, NOT in the heavy always-on integration job
# to avoid OOM). Needs: a running kind cluster (scripts/up.sh) + helm + kubectl.
set -uo pipefail
CTX="${CTX:-kind-cloudsec}"
CHART_VERSION="${ARGOCD_CHART_VERSION:-7.7.7}"   # pin (argo-cd helm chart); bump deliberately
k() { kubectl --context "$CTX" "$@"; }

command -v helm >/dev/null 2>&1 || { echo "helm not found — install helm first"; exit 1; }
if ! k cluster-info >/dev/null 2>&1; then
  echo "no reachable cluster on context $CTX — run scripts/up.sh first"; exit 1
fi

echo "==> installing ArgoCD (dev-sized: HA/dex/applicationset/notifications OFF, 1 replica) into ns argocd"
helm repo add argo https://argoproj.github.io/argo-helm >/dev/null 2>&1 || true
helm repo update argo >/dev/null 2>&1 || true
helm upgrade --install argocd argo/argo-cd -n argocd --create-namespace --version "$CHART_VERSION" \
  --set dex.enabled=false \
  --set notifications.enabled=false \
  --set applicationSet.enabled=false \
  --set redis-ha.enabled=false \
  --set controller.replicas=1 --set server.replicas=1 --set repoServer.replicas=1 \
  --wait --timeout 5m || { echo "ArgoCD install failed"; exit 1; }

echo "==> applying AppProject (least-privilege reconciler scope) + root app-of-apps"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
k apply -f "$ROOT/gitops/projects/shop-project.yaml" || exit 1
k apply -f "$ROOT/gitops/bootstrap/root-app.yaml"    || exit 1

cat <<'NOTE'
OK — ArgoCD is up and shop-root (app-of-apps) is applied = the last imperative act.
  - auto-sync is OFF by default (opt-in / RAM honesty). Sync once:  argocd app sync shop-root
  - the M10 lab turns on syncPolicy.automated{prune,selfHeal} on the network App to show
    drift auto-correction (labs/m10/application.yaml + labs/m10/grade.sh).
  - tear down later:  helm uninstall argocd -n argocd  (kind cluster stays via scripts/down.sh)
NOTE
