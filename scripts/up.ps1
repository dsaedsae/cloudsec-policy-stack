# up.ps1 — bring the whole stack up locally (free, no cloud).
#   Terraform: kind cluster + Cilium (CNI)  ->  kubectl: app + network policies
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$ctx = "kind-cloudsec"

# The Helm provider needs the chart repo cached locally first.
helm repo add cilium https://helm.cilium.io/ 2>$null
helm repo update cilium | Out-Null

Push-Location (Join-Path $Root "terraform")
try {
    terraform init -input=false | Out-Null
    # Create the cluster first (provider config depends on its outputs), then Cilium.
    terraform apply -input=false -auto-approve -target=kind_cluster.this
    terraform apply -input=false -auto-approve
} finally { Pop-Location }

Write-Host "Waiting for Cilium to be ready..."
cilium status --context $ctx --wait

Write-Host "Building + loading the Cedar PDP api image..."
docker build -t cloudsec-api:local -f (Join-Path $Root "app\api\Dockerfile") $Root
kind load docker-image cloudsec-api:local --name cloudsec

Write-Host "Deploying identity (SAs + label<->SA admission policy)..."
kubectl --context $ctx apply -f (Join-Path $Root "k8s\rbac.yaml")
kubectl --context $ctx apply -f (Join-Path $Root "k8s\admission-policy.yaml")

Write-Host "Deploying app + network policies..."
kubectl --context $ctx apply -f (Join-Path $Root "k8s\app.yaml")
kubectl --context $ctx apply -f (Join-Path $Root "k8s\netpol.yaml")
kubectl --context $ctx apply -f (Join-Path $Root "k8s\tracingpolicy.yaml")
kubectl --context $ctx -n shop rollout status deploy/web
kubectl --context $ctx -n shop rollout status deploy/api
kubectl --context $ctx -n shop rollout status deploy/db
Write-Host "`nUp. Run scripts\verify.ps1 to test enforcement."
