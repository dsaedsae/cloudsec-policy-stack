# doctor.ps1 — learning-track preflight. Reports what's installed per module and the
# exact fix for each gap. Never installs anything. See labs/SETUP.md.
#   powershell -File scripts\doctor.ps1
$ErrorActionPreference = "Continue"
# Render Korean correctly on a cp949 console (Korean Windows) instead of mojibake.
try { chcp 65001 | Out-Null; [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$Root = Split-Path -Parent $PSScriptRoot
$ok = "  [OK]   "; $no = "  [MISS] "

function Has($name) { [bool](Get-Command $name -ErrorAction SilentlyContinue) }

Write-Host "=== cloudsec 학습 트랙 환경 점검 ===`n"

# ---- Track A: no-cluster Python labs (M0/M1/M6) ----
Write-Host "Track A — Python 랩 (M0 / M1 / M6):"
$py = Join-Path $Root ".venv\Scripts\python.exe"
$venv = Test-Path $py
$cedarpy = $false; $checkov = $false; $pyver = ""
if ($venv) {
    $pyver = (& $py --version 2>&1)
    & $py -c "import cedarpy" 2>$null; $cedarpy = ($LASTEXITCODE -eq 0)
    & $py -c "import checkov" 2>$null; $checkov = ($LASTEXITCODE -eq 0)
}
Write-Host (("{0}.venv 인터프리터  {1}" -f $(if ($venv) {$ok} else {$no}), $pyver))
Write-Host (("{0}cedarpy (M0/M6)" -f $(if ($cedarpy) {$ok} else {$no})))
Write-Host (("{0}checkov (M1)" -f $(if ($checkov) {$ok} else {$no})))
$dockerForA = Has docker
Write-Host (("{0}docker (M6 Part B ReBAC / M1 trivy)" -f $(if ($dockerForA) {$ok} else {$no})))
if (-not ($venv -and $cedarpy -and $checkov)) {
    Write-Host "   고치기: python -m venv .venv ; .venv\Scripts\python.exe -m pip install -r requirements-dev.txt"
}

# ---- Track B: cluster labs (M2-M5) ----
Write-Host "`nTrack B — 클러스터 랩 (M2 / M3 / M4 / M5):"
$tools = @{ docker="Docker.DockerDesktop"; kind="kind"; kubectl="kubernetes-cli"; helm="kubernetes-helm"; cilium="cilium-cli"; terraform="Hashicorp.Terraform" }
$missing = @()
foreach ($t in 'docker','kind','kubectl','helm','cilium','terraform') {
    $h = Has $t
    Write-Host (("{0}{1}" -f $(if ($h) {$ok} else {$no}), $t))
    if (-not $h) { $missing += $t }
}
$bash = Has bash
Write-Host (("{0}bash (Git Bash — .sh 채점기 실행; Git for Windows 제공)" -f $(if ($bash) {$ok} else {$no})))
if (-not $bash) { $missing += "bash(Git for Windows)" }
# Docker daemon reachable?
$daemon = $false
if (Has docker) { docker info *> $null; $daemon = ($LASTEXITCODE -eq 0) }
Write-Host (("{0}docker 데몬 실행중 (Docker Desktop 켜기)" -f $(if ($daemon) {$ok} else {$no})))
if ($missing.Count -gt 0) {
    Write-Host "   choco 미설치면 먼저(관리자 PowerShell): Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
    Write-Host "   고치기(choco/winget): choco install kind kubernetes-cli kubernetes-helm cilium-cli ; winget install Hashicorp.Terraform Git.Git Docker.DockerDesktop"
}

# ---- per-module verdict ----
$A = ($venv -and $cedarpy)
$M1 = ($venv -and $checkov)
$M6 = ($venv -and $cedarpy -and $dockerForA)
$B = ($missing.Count -eq 0 -and $daemon)
Write-Host "`n=== 모듈별 준비 ==="
Write-Host (("  M0 : {0}" -f $(if ($A) {"READY"} else {"미비 (Track A 설치)"})))
Write-Host (("  M1 : {0}" -f $(if ($M1) {"READY"} else {"미비 (checkov)"})))
Write-Host (("  M6 : {0}" -f $(if ($M6) {"READY"} else {"Part A만 가능 (Part B는 docker 필요)"})))
Write-Host (("  M2-M5 : {0}" -f $(if ($B) {"READY (scripts\up.ps1로 시작)"} else {"미비 (Track B 도구/데몬)"})))
Write-Host "`n자세히: labs\SETUP.md"
