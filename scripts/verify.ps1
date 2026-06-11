# verify.ps1 — prove enforcement at both layers.
# Network (Cilium): spin up ephemeral curl pods with the right identity labels
# and check each hop is allowed/denied as intended. App (Cedar): run authz tests.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$ctx = "kind-cloudsec"

function Probe($name, $label, $url, $expect) {
    # A pod labeled app=<label> gets that Cilium identity. -m 5 bounds denied (dropped) hops.
    $code = kubectl --context $ctx -n shop run $name --rm -i --restart=Never `
        --image=curlimages/curl:8.11.1 --labels "app=$label" --command -- `
        curl -s -o /dev/null -m 5 -w "%{http_code}" $url 2>$null
    $verdict = if ($code -eq "200") { "ALLOW" } else { "DENY ($code)" }
    $ok = if ($verdict.StartsWith($expect)) { "PASS" } else { "FAIL" }
    "{0,-46} expect {1,-6} -> {2,-12} {3}" -f $name, $expect, $verdict, $ok
}

Write-Host "== Cilium network enforcement ==`n"
Probe "web-to-api-get"   "web" "http://api.shop/get"     "ALLOW"   # web->api, GET /get (L7 ok)
Probe "web-to-api-other" "web" "http://api.shop/headers" "DENY"    # web->api wrong path (L7 drop)
Probe "web-to-db"        "web" "http://db.shop/"         "DENY"    # web->db not allowed (L3 drop)
Probe "api-to-db"        "api" "http://db.shop/"         "ALLOW"   # api->db allowed

Write-Host "`n== Cedar application authorization =="
& (Join-Path $Root ".venv\Scripts\python.exe") (Join-Path $Root "cedar\authz.py")
