#!/usr/bin/env bash
# scan.sh — POSIX twin of scan.ps1. Shift-left checkov gate (Terraform + K8s).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Force UTF-8 file reads so checkov doesn't choke on non-ASCII comments under a
# non-UTF-8 OS locale (e.g. cp949 on Korean Windows). Linux/CI default to UTF-8.
export PYTHONUTF8=1
checkov -d "$ROOT/terraform" -d "$ROOT/k8s" --config-file "$ROOT/.checkov.yaml" --compact
