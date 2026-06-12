# scan.ps1 — IaC security gate. Checkov scans Terraform AND the K8s manifests.
# This is the "shift-left" gate you'd wire into CI before anything is applied.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
# Invoke checkov via the venv interpreter (`python -m checkov.main`) rather than a
# console-script shim: pip on Windows may produce `checkov` / `checkov.cmd` but not
# always `checkov.exe`, so a hard-coded .exe path is brittle. The module entrypoint
# is stable regardless of how the venv was built.
$py = Join-Path $Root ".venv\Scripts\python.exe"
$cfg = Join-Path $Root ".checkov.yaml"
# Force UTF-8 file reads so checkov doesn't choke on non-ASCII comments under a
# non-UTF-8 OS locale (e.g. cp949 on Korean Windows).
$env:PYTHONUTF8 = "1"

Write-Host "== checkov: Terraform =="
& $py -m checkov.main -d (Join-Path $Root "terraform") --config-file $cfg --quiet --compact

Write-Host "`n== checkov: Kubernetes manifests =="
& $py -m checkov.main -d (Join-Path $Root "k8s") --config-file $cfg --quiet --compact
