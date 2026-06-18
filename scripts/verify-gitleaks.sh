#!/usr/bin/env bash
# verify-gitleaks.sh — SL2 gate-proof. Demonstrates the gitleaks secret-scan gate
# actually FIRES, rather than merely running on an already-clean tree. It plants a
# SYNTHETIC secret into an ephemeral temp dir and asserts gitleaks catches it
# (exit != 0, "leaks found"), then asserts a clean dir passes (exit 0). This is the
# secret-scan analogue of the SL4/trivy "catch known-bad, pass known-good" proof
# (docs/02-scan.md) — it is what moves SL2 from CONFIGURED to VERIFIED.
#
# The planted secret is SYNTHETIC and EPHEMERAL (written under mktemp, never committed).
# This script's own fixture literals are allowlisted BY PATH in .gitleaks.toml so the
# repo-wide gate (gitleaks-action) stays green; the temp-dir scan below uses gitleaks'
# DEFAULT config, so detection itself is not weakened.
#
# Tool-gated: SKIPs (exit 0) when gitleaks is absent so `make test` still runs the rest
# of the gate locally. CI installs a pinned gitleaks and runs this as the SL2 proof.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

GL="${GITLEAKS:-gitleaks}"
if ! command -v "$GL" >/dev/null 2>&1; then
  echo "== gitleaks not installed — SKIP SL2 gate-proof (CI installs a pinned binary; see .github/workflows/ci.yml) =="
  exit 0
fi
echo "== gitleaks $("$GL" version 2>/dev/null) — SL2 secret-scan gate-proof =="

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
bad="$work/planted"; good="$work/clean"
mkdir -p "$bad" "$good"

# --- synthetic fixture (ephemeral, clearly fake — NOT real credentials) -----------
cat > "$bad/credentials" <<'FIXTURE'
# SYNTHETIC test fixture — not a real credential.
aws_access_key_id = AKIA3KL9QW8ZX7VBN2MC
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsynthetic000fixture000not000a000real000private000key0
-----END RSA PRIVATE KEY-----
FIXTURE
echo "greeting = not-a-secret" > "$good/app.conf"

fail() { echo "FAIL(SL2): $1" >&2; exit 1; }

# 1) the gate MUST catch the planted secret (non-zero exit). Default config, so the
#    repo-level path allowlist cannot mask it.
if "$GL" dir "$bad" --no-banner --exit-code 1 >/dev/null 2>&1; then
  fail "gitleaks did NOT flag the planted secret — the gate would miss a real leak"
fi
echo "  [1/2] planted secret CAUGHT (gitleaks exit != 0)   OK"

# 2) the gate MUST pass a clean tree (no false-positive).
if ! "$GL" dir "$good" --no-banner --exit-code 1 >/dev/null 2>&1; then
  fail "gitleaks false-positived on a clean tree"
fi
echo "  [2/2] clean tree PASSED (gitleaks exit 0)           OK"

echo "PASS(SL2): gitleaks gate proven — catches a planted secret, passes a clean tree."
