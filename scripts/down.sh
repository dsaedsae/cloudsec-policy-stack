#!/usr/bin/env bash
# down.sh — tear everything down.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CTX="kind-cloudsec"
# Delete everything up.sh applies (incl. CLUSTER-SCOPED VAPs/bindings, which a
# namespace delete would NOT remove), so a soft down — or a down where terraform
# destroy is skipped/fails — leaves no lingering policy to skew a later run.
for f in netpol tracingpolicy app admission-sa-use admission-policy rbac; do
  kubectl --context "$CTX" delete -f "$ROOT/k8s/$f.yaml" --ignore-not-found 2>/dev/null || true
done
terraform -chdir="$ROOT/terraform" destroy -input=false -auto-approve
echo "Down."
