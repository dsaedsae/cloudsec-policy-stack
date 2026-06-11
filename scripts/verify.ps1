# verify.ps1 — prove enforcement at both layers (ingress + EGRESS + Cedar).
# Hardened probe pods (k8s/probes.yaml) carry the identity label under test;
# we curl pod IPs directly so the L7 rule at the api endpoint is exercised, and
# distinguish failure modes: 403 = L7 deny (Envoy), 000 = L3/egress drop.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$ctx = "kind-" + (terraform -chdir=(Join-Path $Root "terraform") output -raw cluster_name 2>$null)
if (-not $ctx -or $ctx -eq "kind-") { $ctx = "kind-cloudsec" }

kubectl --context $ctx apply -f (Join-Path $Root "k8s\probes.yaml") | Out-Null
try {
    kubectl --context $ctx -n shop wait --for=condition=Ready pod/probe-web pod/probe-api --timeout=120s | Out-Null
    $api = kubectl --context $ctx -n shop get pod -l tier=backend -o jsonpath="{.items[0].status.podIP}"
    $db = kubectl --context $ctx -n shop get pod -l tier=data -o jsonpath="{.items[0].status.podIP}"

    function Probe($from, $url, $expect) {
        $code = kubectl --context $ctx -n shop exec $from -- curl -s -o /dev/null -m 8 -w "%{http_code}" $url
        $verdict = switch ($code) { "200" { "ALLOW 200" } "403" { "DENY 403(L7)" } default { "DENY $code(drop)" } }
        $ok = if ($verdict.StartsWith($expect)) { "PASS" } else { "FAIL" }
        "{0,-40} -> {1,-16} {2}" -f $url, $verdict, $ok
    }

    Write-Host "== Cilium INGRESS (L3/L4 + L7) =="
    Probe "probe-web" "http://$($api):8080/get"     "ALLOW"   # web->api GET /get (L7 allow)
    Probe "probe-web" "http://$($api):8080/headers" "DENY"    # web->api wrong path (L7 403)
    Probe "probe-web" "http://$($db):8080/"         "DENY"    # web->db (L3 drop)
    Probe "probe-api" "http://$($db):8080/"         "ALLOW"   # api->db (allowed hop)
    Write-Host "`n== Cilium EGRESS (default-deny outbound) =="
    Probe "probe-web" "https://example.com"         "DENY"    # web->internet blocked (no exfil/beacon)
    Probe "probe-api" "https://example.com"         "DENY"    # api->internet blocked
}
finally {
    kubectl --context $ctx -n shop delete -f (Join-Path $Root "k8s\probes.yaml") --ignore-not-found | Out-Null
}

Write-Host "`n== Cedar application authorization (offline PDP tests) =="
& (Join-Path $Root ".venv\Scripts\python.exe") (Join-Path $Root "cedar\authz.py")
