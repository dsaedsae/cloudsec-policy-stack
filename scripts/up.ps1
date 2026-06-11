# up.ps1 — bring the whole stack up locally (free, no cloud).
#   Terraform: kind cluster + Cilium (CNI)  ->  kubectl: app + network policies
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$ctx = "kind-cloudsec"

Push-Location (Join-Path $Root "terraform")
try {
    terraform init -input=false | Out-Null
    # Create the cluster first (provider config depends on its outputs), then Cilium.
    terraform apply -input=false -auto-approve -target=kind_cluster.this
    terraform apply -input=false -auto-approve
} finally { Pop-Location }

Write-Host "Waiting for Cilium to be ready..."
cilium status --context $ctx --wait

Write-Host "Deploying app + network policies..."
kubectl --context $ctx apply -f (Join-Path $Root "k8s\app.yaml")
kubectl --context $ctx apply -f (Join-Path $Root "k8s\netpol.yaml")
kubectl --context $ctx -n shop rollout status deploy/web
kubectl --context $ctx -n shop rollout status deploy/api
kubectl --context $ctx -n shop rollout status deploy/db
Write-Host "`nUp. Run scripts\verify.ps1 to test enforcement."
