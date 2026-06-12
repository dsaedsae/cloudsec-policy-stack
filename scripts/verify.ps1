# verify.ps1 — prove all three layers on ONE asset (api): Cilium L3 drop, Cilium
# L7 path deny, and Cedar authz inside the api PDP — plus egress default-deny.
# POSIX twin: scripts/verify.sh (used by CI).
# NOTE: 'Continue', not 'Stop'. A dropped connection makes curl exit non-zero (that
# is the POINT of an L3 drop), and kubectl surfaces that exit code; under 'Stop'
# PowerShell would abort on the very first expected drop. We detect failures by
# comparing the HTTP code to the expectation, not by trapping native exit codes.
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
# Resolve the kube context from terraform's cluster_name, robustly: PowerShell does
# not concatenate `-chdir=(Join-Path ...)`, so pass the flag as one quoted token, and
# fall back to the default if terraform isn't on PATH / has no state.
$tfdir = Join-Path $Root "terraform"
try { $cn = (terraform "-chdir=$tfdir" output -raw cluster_name 2>$null) } catch { $cn = $null }
if (-not $cn) { $cn = "cloudsec" }
$ctx = "kind-$cn"
$script:fail = 0

kubectl --context $ctx apply -f (Join-Path $Root "k8s\probes.yaml") | Out-Null
try {
    kubectl --context $ctx -n shop wait --for=condition=Ready pod/probe-web pod/probe-api --timeout=120s | Out-Null
    $api = kubectl --context $ctx -n shop get pod -l tier=backend -o jsonpath="{.items[0].status.podIP}"
    $db = kubectl --context $ctx -n shop get pod -l tier=data -o jsonpath="{.items[0].status.podIP}"

    function Probe($src, $desc, $exp, $cargs) {
        $code = & kubectl --context $ctx -n shop exec $src -- curl -s -o /dev/null -m 8 -w "%{http_code}" @cargs 2>$null
        if ($code -eq $exp) { $res = "PASS" } else { $res = "FAIL"; $script:fail = 1 }
        "{0,-46} expect {1,-4} got {2,-4} {3}" -f $desc, $exp, $code, $res
    }

    # NOTE: the transfer bodies are written '{\"amount\":N}' on purpose. PowerShell
    # 5.1 does not escape embedded double-quotes when building a native command line,
    # so a bare '{"amount":N}' reaches curl as {amount:N} (invalid JSON) -> the PDP
    # defaults amount to a huge value -> every transfer wrongly 403s. The backslashes
    # make PS emit literal quotes. verify.sh (bash) needs no such escaping.
    Write-Host "== Defense in depth: one asset (api), three layers =="
    Probe "probe-web" "L1 web->db (no hop, L3 drop)"          "000" @("http://$($db):8080/")
    Probe "probe-web" "L2 web->api GET /auditlogs (L7 deny)"  "403" @("-H", "X-User: alice", "http://$($api):8080/auditlogs/2026-06")
    Probe "probe-web" "L3 alice GET own acct (Cedar allow)"   "200" @("-H", "X-User: alice", "http://$($api):8080/accounts/acct-alice")
    Probe "probe-web" "L3 bob GET alice acct (Cedar deny)"    "403" @("-H", "X-User: bob", "http://$($api):8080/accounts/acct-alice")
    Probe "probe-web" "L3 alice transfer 500 (under limit)"   "200" @("-H", "X-User: alice", "-H", "Content-Type: application/json", "-d", '{\"amount\":500}', "http://$($api):8080/accounts/acct-alice/transfer")
    Probe "probe-web" "L3 alice transfer 5000 (over limit)"   "403" @("-H", "X-User: alice", "-H", "Content-Type: application/json", "-d", '{\"amount\":5000}', "http://$($api):8080/accounts/acct-alice/transfer")
    Probe "probe-web" "L3 alice transfer FROZEN (forbid)"     "403" @("-H", "X-User: alice", "-H", "Content-Type: application/json", "-d", '{\"amount\":100}', "http://$($api):8080/accounts/acct-alice-frozen/transfer")
    Probe "probe-web" "L3 alice transfer -100 (negative)"     "403" @("-H", "X-User: alice", "-H", "Content-Type: application/json", "-d", '{\"amount\":-100}', "http://$($api):8080/accounts/acct-alice/transfer")
    Probe "probe-web" "L3 malformed X-User -> 400"            "400" @("-H", "X-User: bad user", "http://$($api):8080/accounts/acct-alice")
    Probe "probe-api" "L1 api->db (allowed hop)"              "200" @("http://$($db):8080/")
    Write-Host "== Cilium egress (default-deny outbound) =="
    Probe "probe-web" "web->internet blocked"                 "000" @("https://example.com")
    Probe "probe-web" "web->cloud metadata blocked"           "000" @("http://169.254.169.254/")
    Probe "probe-web" "web->kube-apiserver blocked"           "000" @("-k", "https://10.96.0.1:443/")

    Write-Host "== Tetragon runtime (eBPF) =="
    # Prove a SELECTIVE in-kernel kill, robustly: a NON-shell exec (id) still runs
    # (pod healthy, rc=0) while a shell exec is SIGKILLed (rc=137). Requiring BOTH rules
    # out a false-pass on container-not-Ready / no-sh / RBAC-deny (those break id too).
    $dbpod = kubectl --context $ctx -n shop get pod -l tier=data -o jsonpath="{.items[0].metadata.name}"
    kubectl --context $ctx -n shop exec $dbpod -- id 2>$null | Out-Null; $rcId = $LASTEXITCODE
    kubectl --context $ctx -n shop exec $dbpod -- sh -c "echo x" 2>$null | Out-Null; $rcSh = $LASTEXITCODE
    if ($rcId -eq 0 -and ($rcSh -eq 137 -or $rcSh -eq 143)) { "{0,-46} expect {1,-4} got {2,-4} {3}" -f "shell killed (137), id runs (0): Tetragon", "137", "$rcSh", "PASS" }
    else { "{0,-46} expect {1,-4} got {2,-4} {3}" -f "Tetragon selective kill (id=$rcId sh=$rcSh)", "137", "$rcSh", "FAIL"; $script:fail = 1 }

    Write-Host "== Identity (B7): least-privilege RBAC + label<->SA admission =="
    # A tier SA has ZERO Kubernetes API rights (no RoleBinding), so a popped pod's
    # blast radius on the cluster API is nil even if a token were present.
    $caniPods = kubectl --context $ctx auth can-i create pods   --as="system:serviceaccount:shop:api-sa" -n shop 2>$null
    $caniSec  = kubectl --context $ctx auth can-i get secrets   --as="system:serviceaccount:shop:api-sa" -n shop 2>$null
    if ("$caniPods$caniSec" -eq "nono") { "{0,-46} expect {1,-4} got {2,-4} {3}" -f "api-sa: no create-pods / no read-secrets", "no", "no", "PASS" }
    else { "{0,-46} expect {1,-4} got {2,-4} {3}" -f "api-sa K8s API rights", "no", "$caniPods/$caniSec", "FAIL"; $script:fail = 1 }

    # Forged network identity: a pod LABELED app:api but running as web-sa. Server
    # dry-run runs the ValidatingAdmissionPolicy without persisting; expect DENY.
    $curlImg = "curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69"
    $forge = @"
apiVersion: v1
kind: Pod
metadata: { name: forge-mismatch, namespace: shop, labels: { app: api } }
spec:
  serviceAccountName: web-sa
  automountServiceAccountToken: false
  securityContext: { runAsNonRoot: true, runAsUser: 100, seccompProfile: { type: RuntimeDefault } }
  containers:
    - name: c
      image: $curlImg
      command: ["sleep", "1"]
      securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } }
      resources: { requests: { cpu: "5m", memory: "8Mi" }, limits: { cpu: "50m", memory: "32Mi" } }
"@
    $forge | kubectl --context $ctx create --dry-run=server -f - 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { "{0,-46} expect {1,-4} got {2,-4} {3}" -f "forged app:api on web-sa -> admission DENY", "DENY", "DENY", "PASS" }
    else { "{0,-46} expect {1,-4} got {2,-4} {3}" -f "forged app:api on web-sa", "DENY", "ADMIT", "FAIL"; $script:fail = 1 }

    # A self-consistent pod (app:api + api-sa) created by an AUTHORIZED requester
    # (this script runs as admin) is admitted — the label<->SA policy is satisfied
    # and the SA-use gate allows authorized operators. This is the expected baseline.
    $consistent = ($forge -replace "web-sa", "api-sa") -replace "forge-mismatch", "forge-consistent"
    $consistent | kubectl --context $ctx create --dry-run=server -f - 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { "{0,-46} expect {1,-4} got {2,-4} {3}" -f "self-consistent app:api+api-sa as admin -> ADMIT", "ADMIT", "ADMIT", "PASS" }
    else { "{0,-46} expect {1,-4} got {2,-4} {3}" -f "self-consistent app:api+api-sa as admin", "ADMIT", "DENY", "FAIL"; $script:fail = 1 }

    # SA-use gate: the limited shop:deployers principal MAY create Deployments but may
    # NOT run one as a tier ServiceAccount. Impersonate that group; expect DENY. Then
    # confirm an authorized operator (admin) still deploys the same workload (ADMIT).
    $saUse = @"
apiVersion: apps/v1
kind: Deployment
metadata: { name: sa-use-probe, namespace: shop, labels: { app: api } }
spec:
  replicas: 1
  selector: { matchLabels: { app: api } }
  template:
    metadata: { labels: { app: api } }
    spec:
      serviceAccountName: api-sa
      automountServiceAccountToken: false
      securityContext: { runAsNonRoot: true, runAsUser: 100, seccompProfile: { type: RuntimeDefault } }
      containers:
        - name: c
          image: $curlImg
          command: ["sleep", "1"]
          securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } }
          resources: { requests: { cpu: "5m", memory: "8Mi" }, limits: { cpu: "50m", memory: "32Mi" } }
"@
    # Realistic attacker: a CI *ServiceAccount* (system:serviceaccount:...) WITH deploy
    # rights (shop:deployers) tries to run a workload as api-sa. It must be DENIED *by the
    # SA-use gate* — assert the policy's distinctive message so an RBAC 403 / typo / down
    # apiserver can't false-pass (and so an absent/unbound policy is caught).
    $denyOut = ($saUse | kubectl --context $ctx --as="system:serviceaccount:shop:ci-deployer" --as-group=shop:deployers create --dry-run=server -f - 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0 -and $denyOut -match "SA-use gate|shop-sa-use|authorized operator") { "{0,-46} expect {1,-4} got {2,-4} {3}" -f "CI SA runs workload as api-sa -> SA-use DENY", "DENY", "DENY", "PASS" }
    else { "{0,-46} expect {1,-4} got {2,-4} {3}" -f "CI SA runs workload as api-sa (SA-use gate)", "DENY", "?", "FAIL"; $script:fail = 1 }
    # Authorized operator (admin here; shop:tier-operators in prod) deploys the same -> ADMIT.
    $saUse | kubectl --context $ctx create --dry-run=server -f - 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { "{0,-46} expect {1,-4} got {2,-4} {3}" -f "authorized operator deploys api-sa workload -> ADMIT", "ADMIT", "ADMIT", "PASS" }
    else { "{0,-46} expect {1,-4} got {2,-4} {3}" -f "authorized operator deploys api-sa workload", "ADMIT", "DENY", "FAIL"; $script:fail = 1 }

    # SA-use also covers the CronJob jobTemplate path: a CI SA scheduling a CronJob as api-sa is DENIED.
    $saUseCron = @"
apiVersion: batch/v1
kind: CronJob
metadata: { name: sa-use-cron, namespace: shop }
spec:
  schedule: "0 0 * * *"
  jobTemplate:
    spec:
      template:
        metadata: { labels: { app: api } }
        spec:
          serviceAccountName: api-sa
          restartPolicy: Never
          automountServiceAccountToken: false
          securityContext: { runAsNonRoot: true, runAsUser: 100, seccompProfile: { type: RuntimeDefault } }
          containers:
            - name: c
              image: $curlImg
              command: ["sleep", "1"]
              securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } }
              resources: { requests: { cpu: "5m", memory: "8Mi" }, limits: { cpu: "50m", memory: "32Mi" } }
"@
    $cronOut = ($saUseCron | kubectl --context $ctx --as="system:serviceaccount:shop:ci-deployer" --as-group=shop:deployers create --dry-run=server -f - 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0 -and $cronOut -match "SA-use gate|shop-sa-use|authorized operator") { "{0,-46} expect {1,-4} got {2,-4} {3}" -f "CI SA schedules CronJob as api-sa -> SA-use DENY", "DENY", "DENY", "PASS" }
    else { "{0,-46} expect {1,-4} got {2,-4} {3}" -f "CI SA schedules CronJob as api-sa (SA-use gate)", "DENY", "?", "FAIL"; $script:fail = 1 }

    Write-Host "== Data-in-transit (Cilium WireGuard, cross-node) =="
    # Real cross-node proof: WireGuard active AND api/db on DIFFERENT nodes (podAntiAffinity)
    # -> the api->db hop crosses the wire and is WireGuard-encrypted.
    $enc = (kubectl --context $ctx exec -n kube-system ds/cilium -c cilium-agent -- cilium-dbg encrypt status 2>$null) -join "`n"
    $apiNode = kubectl --context $ctx -n shop get pod -l tier=backend -o jsonpath="{.items[0].spec.nodeName}"
    $dbNode  = kubectl --context $ctx -n shop get pod -l tier=data -o jsonpath="{.items[0].spec.nodeName}"
    if ($enc -match "Wireguard" -and $apiNode -and $apiNode -ne $dbNode) { "{0,-46} expect {1,-8} got {2,-8} {3}" -f "api->db cross-node, WireGuard-encrypted", "WG+xnode", "WG+xnode", "PASS" }
    else { "{0,-46} expect {1,-8} got {2,-8} {3}" -f "WireGuard cross-node (api=$apiNode db=$dbNode)", "WG+xnode", "?", "FAIL"; $script:fail = 1 }
}
finally {
    kubectl --context $ctx -n shop delete -f (Join-Path $Root "k8s\probes.yaml") --ignore-not-found | Out-Null
}
if ($script:fail -ne 0) { Write-Host "`nFAILURES"; exit 1 } else { Write-Host "`nALL PASS" }
