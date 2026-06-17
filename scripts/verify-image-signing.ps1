# verify-image-signing.ps1 — OPT-IN proof of admission-time image SIGNATURE verification (SL6).
# Stands up a LOCAL OCI registry on the kind network (removes the cosign#3832 "no registry"
# blocker), cosign-signs the api image with a FRESH per-run key pair, applies the Kyverno
# verifyImages ClusterPolicy bound to that public key, and proves at admission (server
# dry-run) that a SIGNED image is ADMITTED while an UNSIGNED one is DENIED.
#
# Prereqs: scripts\up.ps1 (cluster + cloudsec-api:local image) and scripts\enable-kyverno.ps1.
# The PRIVATE key is generated into a temp dir and never leaves it; only the PUBLIC key goes
# into the (in-memory) policy. Twin/reference: k8s\kyverno-image-verify.yaml.
$ErrorActionPreference = "Continue"
$ctx = "kind-cloudsec"; $reg = "kind-registry"; $port = 5001
# cosign: prefer PATH, then common install locations, else a per-user bin (created on download below).
$cs = (Get-Command cosign -ErrorAction SilentlyContinue).Source
if (-not $cs) {
    foreach ($p in @("$env:USERPROFILE\bin\cosign.exe", "$env:LOCALAPPDATA\Microsoft\WinGet\Links\cosign.exe")) {
        if (Test-Path $p) { $cs = $p; break }
    }
}
if (-not $cs) { $cs = Join-Path "$env:USERPROFILE\bin" "cosign.exe" }
$cdir = Join-Path $env:TEMP "cosign-sl6"; $pw = "demo-cosign-pw-not-real"
$fail = 0
function Step($label, [scriptblock]$cmd) { Write-Host "==> $label"; & $cmd; if ($LASTEXITCODE -ne 0) { Write-Host "FAILED ($LASTEXITCODE): $label"; exit 1 } }

# 0) Preconditions.
docker image inspect cloudsec-api:local *> $null
if ($LASTEXITCODE -ne 0) { Write-Host "missing image cloudsec-api:local — run scripts\up.ps1 first"; exit 1 }
$ky = kubectl --context $ctx get ns kyverno -o name 2>$null
if (-not $ky) { Write-Host "Kyverno not installed — run scripts\enable-kyverno.ps1 first"; exit 1 }
if (-not (Test-Path $cs)) {
    Step "download cosign (host binary)" { curl.exe -sSL -o $cs "https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign-windows-amd64.exe" }
}

# 1) Local registry on the kind network (idempotent). Reachable host-side at localhost:5001
#    (cosign signs over http via the localhost special-case) and in-cluster at kind-registry:5000.
docker inspect $reg *> $null
if ($LASTEXITCODE -ne 0) {
    Step "start local registry" { docker run -d --restart=always -p "${port}:5000" --network kind --name $reg registry:2 | Out-Null; $global:LASTEXITCODE = 0 }
    Start-Sleep -Seconds 3
}

# 2) Push a SIGNED-target (api) and an UNSIGNED (busybox) image.
Step "push api image"      { docker tag cloudsec-api:local "localhost:$port/cloudsec-api:signed"; docker push "localhost:$port/cloudsec-api:signed" | Out-Null; $global:LASTEXITCODE = 0 }
Step "push unsigned image" { docker pull busybox:1.36 | Out-Null; docker tag busybox:1.36 "localhost:$port/busybox:unsigned"; docker push "localhost:$port/busybox:unsigned" | Out-Null; $global:LASTEXITCODE = 0 }
$dig = (docker inspect --format '{{index .RepoDigests 0}}' "localhost:$port/cloudsec-api:signed") -replace '.*@', ''
Write-Host "   signed digest: $dig"

# 3) Fresh key pair + sign the digest (offline: no transparency-log upload).
New-Item -ItemType Directory -Force $cdir | Out-Null
Remove-Item (Join-Path $cdir "cosign.key"), (Join-Path $cdir "cosign.pub") -ErrorAction SilentlyContinue
$env:COSIGN_PASSWORD = $pw
Step "cosign generate-key-pair (per-run, temp)" { & $cs generate-key-pair --output-key-prefix (Join-Path $cdir "cosign") | Out-Null; $global:LASTEXITCODE = 0 }
Step "cosign sign (localhost:$port -> http)"    { & $cs sign --key (Join-Path $cdir "cosign.key") --allow-insecure-registry --tlog-upload=false --yes "localhost:$port/cloudsec-api@$dig" | Out-Null; $global:LASTEXITCODE = 0 }
$pub = (Get-Content (Join-Path $cdir "cosign.pub")) -join "`n"

# 4) Let Kyverno reach the http registry, then apply the verifyImages policy bound to THIS pub key.
$args0 = kubectl --context $ctx -n kyverno get deploy kyverno-admission-controller -o "jsonpath={.spec.template.spec.containers[0].args}"
if ($args0 -notmatch "allowInsecureRegistry=true") {
    Step "allow insecure registry on Kyverno" { kubectl --context $ctx -n kyverno patch deploy kyverno-admission-controller --type=json -p '[{\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/args/-\",\"value\":\"--allowInsecureRegistry=true\"}]' | Out-Null; $global:LASTEXITCODE = 0 }
    Step "wait Kyverno rollout" { kubectl --context $ctx -n kyverno rollout status deploy/kyverno-admission-controller --timeout=120s | Out-Null; $global:LASTEXITCODE = 0 }
}
$pubIndented = ($pub -split "`n" | ForEach-Object { "                      $_" }) -join "`n"
$policy = @"
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata: { name: verify-image-signature }
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: check-cosign-signature
      match: { any: [ { resources: { kinds: [Pod] } } ] }
      verifyImages:
        - imageReferences: ["kind-registry:5000/*"]
          mutateDigest: false
          verifyDigest: false
          required: true
          attestors:
            - count: 1
              entries:
                - keys:
                    publicKeys: |-
$pubIndented
                    rekor: { ignoreTlog: true }
                    ctlog: { ignoreSCT: true }
"@
Step "apply verifyImages policy" { $policy | kubectl --context $ctx apply -f - | Out-Null; $global:LASTEXITCODE = 0 }
Step "wait policy ready" { kubectl --context $ctx wait --for=condition=Ready clusterpolicy/verify-image-signature --timeout=60s | Out-Null; $global:LASTEXITCODE = 0 }

# 5) Prove the gate at admission (server dry-run; no pull needed).
Write-Host "`n== Admission-time image-signature gate (kind-registry:5000/*) =="
$signedPod   = "apiVersion: v1`nkind: Pod`nmetadata: { name: sl6-signed, namespace: default }`nspec: { containers: [ { name: c, image: kind-registry:5000/cloudsec-api@$dig } ] }`n"
$unsignedPod = "apiVersion: v1`nkind: Pod`nmetadata: { name: sl6-unsigned, namespace: default }`nspec: { containers: [ { name: c, image: kind-registry:5000/busybox:unsigned } ] }`n"
$o1 = $signedPod   | kubectl --context $ctx create --dry-run=server -f - 2>&1 | Out-String
if ($o1 -match "created") { Write-Host "  signed image   -> ADMIT   expect ADMIT  PASS" } else { Write-Host "  signed image   -> expect ADMIT  got DENY/ERR  FAIL"; $fail = 1 }
$o2 = $unsignedPod | kubectl --context $ctx create --dry-run=server -f - 2>&1 | Out-String
if ($o2 -match "created") { Write-Host "  unsigned image -> expect DENY   got ADMIT  FAIL"; $fail = 1 } else { Write-Host "  unsigned image -> DENY    expect DENY   got DENY   PASS" }

Write-Host "----------------------------------------------------------------"
if ($fail -eq 0) { Write-Host "Image-signature admission gate: ALL PASS (signed ADMIT / unsigned DENY) - SL6 proven (local-key)" } else { Write-Host "Image-signature gate: FAILURES above" }
exit $fail
