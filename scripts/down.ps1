# down.ps1 — tear everything down.
$ErrorActionPreference = "SilentlyContinue"
$Root = Split-Path -Parent $PSScriptRoot
$ctx = "kind-cloudsec"
kubectl --context $ctx delete -f (Join-Path $Root "k8s\netpol.yaml")
kubectl --context $ctx delete -f (Join-Path $Root "k8s\app.yaml")
Push-Location (Join-Path $Root "terraform")
terraform destroy -input=false -auto-approve
Pop-Location
Write-Host "Down."
