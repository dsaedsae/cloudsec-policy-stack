#!/usr/bin/env bash
# doctor.sh — learning-track preflight (Git Bash twin of doctor.ps1). Reports per-module
# readiness + the fix for each gap. Never installs anything. See labs/SETUP.md.
#   bash scripts/doctor.sh
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OK="  [OK]   "; NO="  [MISS] "
has() { command -v "$1" >/dev/null 2>&1; }
mark() { if "$1" "$2" >/dev/null 2>&1 || [ "$3" = "y" ]; then printf "%s" "$OK"; else printf "%s" "$NO"; fi; }

echo "=== cloudsec 학습 트랙 환경 점검 ==="
echo
# Track A
echo "Track A — Python 랩 (M0 / M1 / M6):"
PY="$ROOT/.venv/Scripts/python.exe"; [ -x "$PY" ] || PY="$ROOT/.venv/bin/python"
venv=false; cedarpy=false; checkov=false; pyver=""
if [ -x "$PY" ]; then
  venv=true; pyver="$("$PY" --version 2>&1)"
  "$PY" -c "import cedarpy" 2>/dev/null && cedarpy=true
  "$PY" -c "import checkov" 2>/dev/null && checkov=true
fi
$venv && echo "$OK.venv 인터프리터  $pyver" || echo "$NO.venv 인터프리터"
$cedarpy && echo "$OK""cedarpy (M0/M6)" || echo "$NO""cedarpy (M0/M6)"
$checkov && echo "$OK""checkov (M1)" || echo "$NO""checkov (M1)"
has docker && echo "$OK""docker (M6 Part B / M1 trivy)" || echo "$NO""docker"
if ! ($venv && $cedarpy && $checkov); then
  echo "   고치기: python -m venv .venv ; .venv\\Scripts\\python.exe -m pip install -r requirements-dev.txt"
fi
# Track B
echo
echo "Track B — 클러스터 랩 (M2 / M3 / M4 / M5):"
missing=()
for t in docker kind kubectl helm cilium terraform; do
  if has "$t"; then echo "$OK$t"; else echo "$NO$t"; missing+=("$t"); fi
done
daemon=false; has docker && docker info >/dev/null 2>&1 && daemon=true
$daemon && echo "$OK""docker 데몬 실행중" || echo "$NO""docker 데몬 (Docker Desktop 켜기)"
[ ${#missing[@]} -gt 0 ] && echo "   고치기: choco install kind kubernetes-cli kubernetes-helm cilium-cli ; winget install Hashicorp.Terraform Docker.DockerDesktop"
echo
echo "=== 모듈별 준비 ==="
( $venv && $cedarpy ) && echo "  M0 : READY" || echo "  M0 : 미비 (Track A)"
( $venv && $checkov ) && echo "  M1 : READY" || echo "  M1 : 미비 (checkov)"
( $venv && $cedarpy && has docker ) && echo "  M6 : READY" || echo "  M6 : Part A만 (Part B는 docker)"
( [ ${#missing[@]} -eq 0 ] && $daemon ) && echo "  M2-M5 : READY (scripts\\up.ps1로 시작)" || echo "  M2-M5 : 미비 (Track B)"
echo
echo "자세히: labs/SETUP.md"
