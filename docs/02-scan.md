# Lab 1 — Shift-left scanning (no cluster)

**Goal:** run the same IaC/K8s security gate CI runs, and learn *honest triage* —
why "0 findings" is a red flag, not a goal.

## Run it

```bash
bash scripts/scan.sh        # or: pwsh scripts/scan.ps1
```

Expected (checkov over `terraform/` + `k8s/`):

```
Passed checks: 452, Failed checks: 0, Skipped checks: 5
```
(The passed count grows as manifests are added — the gate is **Failed checks: 0**.)

## What to read

`.checkov.yaml` lists **3** global suppressions, each with a written reason
(`CKV_K8S_15` — `IfNotPresent` for kind; `CKV_K8S_40` — `nginx-unprivileged` fixes
UID 101; `CKV2_K8S_6` — checkov can't see the CiliumNetworkPolicy CRD). Plus *scoped*
annotation skips: `CKV_K8S_43` on the locally-built api image (no registry digest) in
`k8s/app.yaml`, and liveness/readiness on the ephemeral probe pods (`k8s/probes.yaml`).

The lesson: a real review *triages* findings with justification; it doesn't chase
a green number by disabling everything. The README scopes the claim precisely —
checkov validates **workloads + Terraform**, not the network policy or Cedar
(those have their own gates).

## Image scan + SBOM (build provenance)

`scripts/scan.*` also runs an **image vuln+secret gate** and emits a **CycloneDX
SBOM** — gated behind `trivy` being installed, so the checkov gate above still runs
anywhere:

```bash
trivy image --scanners vuln,secret --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 cloudsec-api:local
trivy image --format cyclonedx --output outputs/sbom/cloudsec-api.cdx.json cloudsec-api:local
# install (Windows host): winget install AquaSecurity.Trivy   (or: brew install trivy)
```

**This gate caught a real vulnerability — and we fixed it, not suppressed it.** The
first run failed (`exit 1`) on `CVE-2025-62727` (HIGH — Starlette DoS via Range-header
merging), present because `fastapi==0.115.6` pulled `starlette 0.41.3`. The remediation
was a dependency bump in `app/api/requirements.txt`
(`fastapi 0.115.6→0.136.3`, `starlette 0.41.3→1.3.1`, `uvicorn 0.34.0→0.49.0`); the
api was rebuilt, the Cedar PDP re-smoke-tested (alice 200 / bob 403 / over-limit 403),
and the gate went green (`0 vuln / 0 secret`). That is the whole point of shift-left:
catch → remediate → green, before deploy.

**Honest scope — what is NOT here:** image **signing**. Released `cosign` needs a
registry to attach a signature to (sigstore/cosign#3832; the no-registry PR #4014 is
unmerged), and this `cloudsec-api:local` image is `kind`-loaded with no registry. So
signing / SLSA attestation is **documented on the ECR path**
([aws-eks-path.md](aws-eks-path.md)), not claimed locally — no fake `cosign verify`
check exists. `--ignore-unfixed` mirrors checkov's honest-suppression lesson: gate on
what you can actually act on.

## Break it (then fix it)

1. In `k8s/app.yaml`, delete `readOnlyRootFilesystem: true` from the `web`
   container.
2. Re-run `bash scripts/scan.sh` → a new **CKV_K8S_22** failure appears.
3. Restore it. Clean again.

Next: [Lab 2 — network + authz on a real cluster](03-network-and-authz.md).
