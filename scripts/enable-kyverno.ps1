# enable-kyverno.ps1 — OPT-IN capstone: install Kyverno (dev/kind-sized) and apply the
# cluster-wide SA-use ClusterPolicy. NOT part of the default scripts\up.ps1 (it adds
# admission+background controllers = real RAM on top of Cilium+Tetragon+SPIRE).
# Idempotent. Twin of enable-secrets-encryption.ps1.
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
$ctx = "kind-cloudsec"

function Step($label, [scriptblock]$cmd) {
    Write-Host "==> $label"; & $cmd
    if ($LASTEXITCODE -ne 0) { Write-Host "FAILED ($LASTEXITCODE): $label"; exit 1 }
}

helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update | Out-Null
helm repo update kyverno | Out-Null

Step "helm install kyverno (dev-sized: 1 replica, no cleanup/reports controllers)" {
    helm upgrade --install kyverno kyverno/kyverno -n kyverno --create-namespace `
        --kube-context $ctx `
        --set admissionController.replicas=1 `
        --set backgroundController.replicas=1 `
        --set cleanupController.enabled=false `
        --set reportsController.enabled=false `
        --wait --timeout 5m
}
Step "apply SA-use ClusterPolicy" { kubectl --context $ctx apply -f (Join-Path $Root "k8s\kyverno-sa-use.yaml") }
Step "wait ClusterPolicy Ready" { kubectl --context $ctx wait --for=condition=Ready clusterpolicy/sa-use --timeout=120s }
Write-Host "`nKyverno SA-use ClusterPolicy ready. Prove it cluster-wide: scripts\verify-kyverno.ps1"
