#!/usr/bin/env bash
# scan.sh — POSIX twin of scan.ps1. Shift-left checkov gate (Terraform + K8s).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
checkov -d "$ROOT/terraform" -d "$ROOT/k8s" --config-file "$ROOT/.checkov.yaml" --compact
