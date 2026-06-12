# up.ps1 — bring the whole stack up locally (free, no cloud).
#   Terraform: kind cluster + Cilium (CNI) -> kubectl: identity + app + policies
#
# 'Continue', not 'Stop': native tools here (docker, kind, terraform) write progress
# to stderr even on success, and under $ErrorActionPreference=Stop PowerShell 5.1
# turns ANY stderr line into a terminating error. So we drive failure off exit codes
# explicitly via Step().
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
$ctx = "kind-cloudsec"

function Step($label, [scriptblock]$cmd) {
    Write-Host "==> $label"
    & $cmd
    if ($LASTEXITCODE -ne 0) { Write-Host "FAILED ($LASTEXITCODE): $label"; exit 1 }
}

# The Helm provider needs the chart repo cached first. --force-update refreshes a
# pre-existing 'cilium' entry instead of erroring on "already exists".
helm repo add cilium https://helm.cilium.io/ --force-update | Out-Null
helm repo update cilium | Out-Null

Push-Location (Join-Path $Root "terraform")
try {
    Step "terraform init" { terraform init -input=false }
    # Create the cluster first (provider config depends on its outputs), then Cilium.
    # Quote the target: PowerShell otherwise mangles the `.this` suffix and terraform
    # sees an invalid target ("kind_cluster").
    Step "terraform apply (cluster)" { terraform apply -input=false -auto-approve -target='kind_cluster.this' }
    Step "terraform apply (Cilium + Tetragon + SPIRE + WireGuard)" { terraform apply -input=false -auto-approve }
} finally { Pop-Location }

Step "wait for Cilium" { cilium status --context $ctx --wait }

Step "build Cedar PDP api image" { docker build -t cloudsec-api:local -f (Join-Path $Root "app\api\Dockerfile") $Root }
Step "load image into kind" { kind load docker-image cloudsec-api:local --name cloudsec }

# Identity FIRST: rbac.yaml creates the `shop` namespace + tier ServiceAccounts that
# app.yaml's Deployments reference. admission-policy.yaml is the B7 label<->SA control.
Step "deploy identity (ns + SAs + admission policies)" {
    kubectl --context $ctx apply -f (Join-Path $Root "k8s\rbac.yaml")
    kubectl --context $ctx apply -f (Join-Path $Root "k8s\admission-policy.yaml")
    kubectl --context $ctx apply -f (Join-Path $Root "k8s\admission-sa-use.yaml")
}
Step "deploy app + network + runtime policies" {
    kubectl --context $ctx apply -f (Join-Path $Root "k8s\app.yaml")
    kubectl --context $ctx apply -f (Join-Path $Root "k8s\netpol.yaml")
    kubectl --context $ctx apply -f (Join-Path $Root "k8s\tracingpolicy.yaml")
}
Step "rollout web" { kubectl --context $ctx -n shop rollout status deploy/web --timeout=180s }
Step "rollout api" { kubectl --context $ctx -n shop rollout status deploy/api --timeout=180s }
Step "rollout db"  { kubectl --context $ctx -n shop rollout status deploy/db  --timeout=180s }

Write-Host "`nUp. Run scripts\verify.ps1 to test enforcement."
Write-Host "Optional capstones: kubectl apply -f k8s\netpol-mutual.yaml (mutual auth);"
Write-Host "                    scripts\enable-secrets-encryption.ps1 (Secret encryption at rest)."
