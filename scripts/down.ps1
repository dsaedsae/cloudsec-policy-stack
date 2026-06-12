# down.ps1 — tear everything down.
$ErrorActionPreference = "SilentlyContinue"
$Root = Split-Path -Parent $PSScriptRoot
$ctx = "kind-cloudsec"
# Delete everything up.ps1 applies (incl. CLUSTER-SCOPED VAPs/bindings, which a
# namespace delete would NOT remove), so a soft down leaves no lingering policy.
foreach ($f in 'netpol','tracingpolicy','app','admission-sa-use','admission-policy','rbac') {
    kubectl --context $ctx delete -f (Join-Path $Root "k8s\$f.yaml") --ignore-not-found
}
Push-Location (Join-Path $Root "terraform")
terraform destroy -input=false -auto-approve
Pop-Location
Write-Host "Down."
