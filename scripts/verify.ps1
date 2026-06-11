# verify.ps1 — prove enforcement at both layers.
# Network (Cilium): hardened probe pods (k8s/probes.yaml) carry the identity
# label under test; we curl pod IPs directly so the L7 rule at the api endpoint
# is exercised cleanly. App (Cedar): run the authz tests.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$ctx = "kind-cloudsec"

kubectl --context $ctx apply -f (Join-Path $Root "k8s\probes.yaml") | Out-Null
kubectl --context $ctx -n shop wait --for=condition=Ready pod/probe-web pod/probe-api --timeout=120s | Out-Null
$api = kubectl --context $ctx -n shop get pod -l tier=backend -o jsonpath="{.items[0].status.podIP}"
$db = kubectl --context $ctx -n shop get pod -l tier=data -o jsonpath="{.items[0].status.podIP}"

function Probe($from, $url, $expect) {
    $code = kubectl --context $ctx -n shop exec $from -- curl -s -o /dev/null -m 6 -w "%{http_code}" $url
    $verdict = if ($code -eq "200") { "ALLOW 200" } else { "DENY $code" }
    $ok = if ($verdict.StartsWith($expect)) { "PASS" } else { "FAIL" }
    "{0,-44} -> {1,-12} {2}" -f $url, $verdict, $ok
}

Write-Host "== Cilium network enforcement (L3/L4 + L7) =="
Probe "probe-web" "http://$($api):8080/get"     "ALLOW"   # web->api GET /get  (L7 allow)
Probe "probe-web" "http://$($api):8080/headers" "DENY"    # web->api wrong path (L7 403)
Probe "probe-web" "http://$($db):8080/"         "DENY"    # web->db (L3 drop)
Probe "probe-api" "http://$($db):8080/"         "ALLOW"   # api->db (allowed hop)

kubectl --context $ctx -n shop delete -f (Join-Path $Root "k8s\probes.yaml") | Out-Null

Write-Host "`n== Cedar application authorization =="
& (Join-Path $Root ".venv\Scripts\python.exe") (Join-Path $Root "cedar\authz.py")
