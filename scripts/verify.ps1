# verify.ps1 — prove all three layers on ONE asset (api): Cilium L3 drop, Cilium
# L7 path deny, and Cedar authz inside the api PDP — plus egress default-deny.
# POSIX twin: scripts/verify.sh (used by CI).
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$ctx = "kind-" + (terraform -chdir=(Join-Path $Root "terraform") output -raw cluster_name 2>$null)
if (-not $ctx -or $ctx -eq "kind-") { $ctx = "kind-cloudsec" }
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

    Write-Host "== Defense in depth: one asset (api), three layers =="
    Probe "probe-web" "L1 web->db (no hop, L3 drop)"          "000" @("http://$($db):8080/")
    Probe "probe-web" "L2 web->api GET /auditlogs (L7 deny)"  "403" @("-H", "X-User: alice", "http://$($api):8080/auditlogs/2026-06")
    Probe "probe-web" "L3 alice GET own acct (Cedar allow)"   "200" @("-H", "X-User: alice", "http://$($api):8080/accounts/acct-alice")
    Probe "probe-web" "L3 bob GET alice acct (Cedar deny)"    "403" @("-H", "X-User: bob", "http://$($api):8080/accounts/acct-alice")
    Probe "probe-web" "L3 alice transfer 500 (under limit)"   "200" @("-H", "X-User: alice", "-H", "Content-Type: application/json", "-d", '{"amount":500}', "http://$($api):8080/accounts/acct-alice/transfer")
    Probe "probe-web" "L3 alice transfer 5000 (over limit)"   "403" @("-H", "X-User: alice", "-H", "Content-Type: application/json", "-d", '{"amount":5000}', "http://$($api):8080/accounts/acct-alice/transfer")
    Probe "probe-web" "L3 alice transfer FROZEN (forbid)"     "403" @("-H", "X-User: alice", "-H", "Content-Type: application/json", "-d", '{"amount":100}', "http://$($api):8080/accounts/acct-alice-frozen/transfer")
    Probe "probe-api" "L1 api->db (allowed hop)"              "200" @("http://$($db):8080/")
    Write-Host "== Cilium egress (default-deny outbound) =="
    Probe "probe-web" "web->internet blocked"                 "000" @("https://example.com")
}
finally {
    kubectl --context $ctx -n shop delete -f (Join-Path $Root "k8s\probes.yaml") --ignore-not-found | Out-Null
}
if ($script:fail -ne 0) { Write-Host "`nFAILURES"; exit 1 } else { Write-Host "`nALL PASS" }
