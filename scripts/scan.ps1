# scan.ps1 — IaC security gate. Checkov scans Terraform AND the K8s manifests.
# This is the "shift-left" gate you'd wire into CI before anything is applied.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$checkov = Join-Path $Root ".venv\Scripts\checkov.exe"

Write-Host "== checkov: Terraform =="
& $checkov -d (Join-Path $Root "terraform") --quiet --compact

Write-Host "`n== checkov: Kubernetes manifests =="
& $checkov -d (Join-Path $Root "k8s") --quiet --compact
