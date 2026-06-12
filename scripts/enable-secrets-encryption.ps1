# enable-secrets-encryption.ps1 — turn on Kubernetes Secret encryption-at-rest on
# the running kind cluster, then PROVE it by reading raw etcd.
#
# Why: a default K8s Secret is only base64 in etcd (anyone with the datastore/backup
# reads it). This configures the kube-apiserver with an AES-CBC EncryptionConfiguration
# so Secrets are ciphertext at rest (GDPR Art.32 / PCI-DSS req3 / ISMS-P 2.7).
#
# Method: all changes are pushed into the control-plane node with `docker cp`/`docker
# exec` (no host bind-mounts, so it is OS-independent), and the apiserver static-pod
# manifest is backed up first so the change is reversible. Idempotent: re-running
# detects an existing config and only re-verifies. The 32-byte key is generated here
# and never committed (kept under terraform/.enc/, which is gitignored).
# 'Continue', not 'Stop': the apiserver is briefly unreachable while it restarts
# with the new config, so the health poll must tolerate transient kubectl errors.
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
$ctx  = "kind-cloudsec"
$node = "cloudsec-control-plane"
$encDir = Join-Path $Root "terraform\.enc"
New-Item -ItemType Directory -Force -Path $encDir | Out-Null

# PROVE encryption-at-rest by reading raw etcd. etcdctl lives INSIDE the etcd pod
# (not on the node) and needs the HTTPS endpoint; the ciphertext prefix
# (k8s:enc:aescbc) is ASCII at the head of the stored value, so a substring match
# survives even though the rest is binary.
function Test-AtRest {
    kubectl --context $ctx -n default delete secret atrest-proof --ignore-not-found | Out-Null
    kubectl --context $ctx -n default create secret generic atrest-proof --from-literal=card=4111111111111111 | Out-Null
    $etcd = "etcd-$node"
    $raw = (kubectl --context $ctx -n kube-system exec $etcd -- etcdctl --endpoints=https://127.0.0.1:2379 --cacert /etc/kubernetes/pki/etcd/ca.crt --cert /etc/kubernetes/pki/etcd/server.crt --key /etc/kubernetes/pki/etcd/server.key get /registry/secrets/default/atrest-proof 2>$null) -join "`n"
    kubectl --context $ctx -n default delete secret atrest-proof --ignore-not-found | Out-Null
    Write-Host "`n== etcd stored value for secret/atrest-proof (head) =="
    Write-Host ($raw.Substring(0, [Math]::Min(120, $raw.Length)))
    if (($raw -match "k8s:enc:aescbc") -and ($raw -notmatch "4111111111111111")) {
        Write-Host "`nPASS: Secret is AES-CBC encrypted at rest in etcd (k8s:enc:aescbc prefix; no plaintext card number)."
        return $true
    }
    Write-Host "`nFAIL: expected k8s:enc:aescbc prefix and no plaintext in etcd; got the above."
    return $false
}

# Idempotency: if the apiserver already carries the encryption flag, do NOT generate
# a new key (that would orphan secrets encrypted with the old one) — skip straight to
# verification. Re-running is then safe.
$already = docker exec $node sh -c "grep -c encryption-provider-config /etc/kubernetes/manifests/kube-apiserver.yaml 2>/dev/null || echo 0"
if ("$already".Trim() -ne "0") {
    Write-Host "Encryption-at-rest already enabled on the apiserver; verifying only."
    if (Test-AtRest) { exit 0 } else { exit 1 }
}

# 1. Generate a fresh 32-byte AES key (base64) and render the EncryptionConfiguration.
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$key = [Convert]::ToBase64String($bytes)
$tmpl = Get-Content (Join-Path $Root "k8s\encryption-config.yaml") -Raw
$encYaml = $tmpl -replace "__ENC_KEY_B64__", $key
$encPath = Join-Path $encDir "enc.yaml"
# Write WITHOUT a BOM so the apiserver's YAML parser is happy.
[System.IO.File]::WriteAllText($encPath, $encYaml, (New-Object System.Text.UTF8Encoding $false))

# 2. Push the config into the node and back up the apiserver static manifest.
docker exec $node mkdir -p /etc/kubernetes/enc | Out-Null
docker cp $encPath "${node}:/etc/kubernetes/enc/enc.yaml" | Out-Null
$bak = Join-Path $encDir "kube-apiserver.yaml.bak"
docker cp "${node}:/etc/kubernetes/manifests/kube-apiserver.yaml" $bak | Out-Null

# 3. Edit the apiserver manifest (add the flag + a read-only mount of /etc/kubernetes/enc).
#    Done host-side with PyYAML (in the venv) so we never string-munge YAML by hand.
$py = Join-Path $Root ".venv\Scripts\python.exe"
$editted = Join-Path $encDir "kube-apiserver.yaml"
# The program is read from stdin (`python -`); the two paths are argv[1]/argv[2].
# Pipe the here-string in — passing it as an argument would NOT reach stdin.
$pyedit = @'
import sys, yaml
src, dst = sys.argv[1], sys.argv[2]
d = yaml.safe_load(open(src, encoding="utf-8"))
c = d["spec"]["containers"][0]
flag = "--encryption-provider-config=/etc/kubernetes/enc/enc.yaml"
cmd = c.setdefault("command", [])
if flag not in cmd:
    cmd.append(flag)
vm = c.setdefault("volumeMounts", [])
if not any(m.get("name") == "enc" for m in vm):
    vm.append({"name": "enc", "mountPath": "/etc/kubernetes/enc", "readOnly": True})
vols = d["spec"].setdefault("volumes", [])
if not any(v.get("name") == "enc" for v in vols):
    vols.append({"name": "enc", "hostPath": {"path": "/etc/kubernetes/enc", "type": "DirectoryOrCreate"}})
yaml.safe_dump(d, open(dst, "w", encoding="utf-8"), default_flow_style=False, sort_keys=False)
print("apiserver manifest patched")
'@
$pyedit | & $py - $bak $editted

# 4. Apply it — kubelet restarts the static apiserver pod when the file changes.
docker cp $editted "${node}:/etc/kubernetes/manifests/kube-apiserver.yaml" | Out-Null
Write-Host "Waiting for kube-apiserver to come back with encryption enabled..."
$ok = $false
foreach ($i in 1..60) {
    Start-Sleep -Seconds 3
    # `get ns default` succeeding = apiserver is serving AND authorizing again
    # (more reliable here than --raw=/healthz, which returned empty mid-restart).
    kubectl --context $ctx get ns default -o name 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { $ok = $true; break }
}
if (-not $ok) { Write-Host "apiserver did not return healthy; restore with: docker cp $bak ${node}:/etc/kubernetes/manifests/kube-apiserver.yaml"; exit 1 }

# 5. Re-encrypt Secrets that were written before the change (rollover).
kubectl --context $ctx get secrets --all-namespaces -o json | kubectl --context $ctx replace -f - | Out-Null

# 6. PROVE it: create a secret, read the raw etcd value, expect ciphertext not plaintext.
if (-not (Test-AtRest)) { exit 1 }
