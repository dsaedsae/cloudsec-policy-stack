#!/usr/bin/env bash
# scan.sh — POSIX twin of scan.ps1. Shift-left checkov gate (Terraform + K8s).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Force UTF-8 file reads so checkov doesn't choke on non-ASCII comments under a
# non-UTF-8 OS locale (e.g. cp949 on Korean Windows). Linux/CI default to UTF-8.
export PYTHONUTF8=1
checkov -d "$ROOT/terraform" -d "$ROOT/k8s" --config-file "$ROOT/.checkov.yaml" --compact

# --- Image scan + SBOM (build provenance) -----------------------------------
# Gated behind trivy's presence so the checkov gate above still runs anywhere.
# Honesty (CLAUDE.md): image SIGNING (cosign) is NOT done here — the kind-loaded
# local image has no registry to attach a signature to; signing is documented on
# the ECR path (docs/aws-eks-path.md). See docs/02-scan.md.
IMAGE="cloudsec-api:local"
SBOM_DIR="$ROOT/outputs/sbom"
if command -v trivy >/dev/null 2>&1; then
  if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "== building $IMAGE for scan =="
    docker build -t "$IMAGE" -f "$ROOT/app/api/Dockerfile" "$ROOT"
  fi
  echo "== trivy: image vuln+secret gate ($IMAGE) =="
  trivy image --scanners vuln,secret --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 "$IMAGE"
  echo "== trivy: SBOM (CycloneDX) =="
  mkdir -p "$SBOM_DIR"
  trivy image --quiet --format cyclonedx --output "$SBOM_DIR/cloudsec-api.cdx.json" "$IMAGE"
  echo "SBOM written: outputs/sbom/cloudsec-api.cdx.json"
else
  echo "== trivy not installed — skipping image scan + SBOM (checkov gate above still ran) =="
  echo "   install: winget install AquaSecurity.Trivy   (or: brew install trivy)"
fi
