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

# $ErrorActionPreference=Stop does NOT abort on a NATIVE exe's nonzero exit (only on
# PowerShell cmdlet errors), so checkov's gate must be enforced via $LASTEXITCODE — or
# a policy violation (exit 1) would be silently ignored and the build would false-pass.
Write-Host "== checkov: Terraform =="
& $py -m checkov.main -d (Join-Path $Root "terraform") --config-file $cfg --quiet --compact
if ($LASTEXITCODE -ne 0) { throw "checkov gate failed (terraform)" }

Write-Host "`n== checkov: Kubernetes manifests =="
& $py -m checkov.main -d (Join-Path $Root "k8s") --config-file $cfg --quiet --compact
if ($LASTEXITCODE -ne 0) { throw "checkov gate failed (k8s)" }

# --- Image scan + SBOM (build provenance) -----------------------------------
# Gated behind trivy's presence so the checkov gate above still runs anywhere.
# Honesty (CLAUDE.md): image SIGNING (cosign) is NOT done here — the kind-loaded
# local image has no registry to attach a signature to; signing is documented on
# the ECR path (docs/aws-eks-path.md). See docs/02-scan.md.
$image = "cloudsec-api:local"
$sbomDir = Join-Path $Root "outputs\sbom"
if (Get-Command trivy -ErrorAction SilentlyContinue) {
    if (-not (docker images -q $image)) {
        Write-Host "`n== building $image for scan =="
        docker build -t $image -f (Join-Path $Root "app\api\Dockerfile") $Root
        if ($LASTEXITCODE -ne 0) { throw "docker build failed" }
    }
    Write-Host "`n== trivy: image vuln+secret gate ($image) =="
    trivy image --scanners vuln,secret --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 $image
    if ($LASTEXITCODE -ne 0) { throw "trivy image gate failed (CRITICAL/HIGH fixable vuln or secret found)" }
    Write-Host "`n== trivy: SBOM (CycloneDX) =="
    New-Item -ItemType Directory -Force $sbomDir | Out-Null
    trivy image --quiet --format cyclonedx --output (Join-Path $sbomDir "cloudsec-api.cdx.json") $image
    Write-Host "SBOM written: outputs/sbom/cloudsec-api.cdx.json"
} else {
    Write-Host "`n== trivy not installed - skipping image scan + SBOM (checkov gate above still ran) =="
    Write-Host "   install: winget install AquaSecurity.Trivy"
}
