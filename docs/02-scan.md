# Lab 1 — Shift-left scanning (no cluster)

**Goal:** run the same IaC/K8s security gate CI runs, and learn *honest triage* —
why "0 findings" is a red flag, not a goal.

## Run it

```bash
bash scripts/scan.sh        # or: pwsh scripts/scan.ps1
```

Expected (checkov over `terraform/` + `k8s/`):

```
Passed checks: 424, Failed checks: 0, Skipped checks: 4
```

## What to read

`.checkov.yaml` lists exactly **4** suppressions, each with a written reason
(e.g. `CKV2_K8S_6` — checkov can't see the CiliumNetworkPolicy CRD; `CKV_K8S_40`
— `nginx-unprivileged` fixes UID 101). Plus inline skips on the probe pods
(`k8s/probes.yaml`) for liveness/readiness — they're ephemeral `sleep` clients.

The lesson: a real review *triages* findings with justification; it doesn't chase
a green number by disabling everything. The README scopes the claim precisely —
checkov validates **workloads + Terraform**, not the network policy or Cedar
(those have their own gates).

## Break it (then fix it)

1. In `k8s/app.yaml`, delete `readOnlyRootFilesystem: true` from the `web`
   container.
2. Re-run `bash scripts/scan.sh` → a new **CKV_K8S_22** failure appears.
3. Restore it. Clean again.

Next: [Lab 2 — network + authz on a real cluster](03-network-and-authz.md).
