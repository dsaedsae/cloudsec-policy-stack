# verify-jwt-enforce.ps1 — live proof of ID8 (requester Bearer-JWT enforcement, RFC 8707).
#
# With AUTH_REQUIRE_JWT=1 the running api REQUIRES a verified, audience-bound Bearer JWT and
# the unauthenticated X-User fallback is OFF. This is OPT-IN (it mutates the api Deployment,
# proves enforcement, then RESTORES demo mode) because the default scripts/verify.sh suite
# intentionally drives the api with the labeled X-User demo input. Unit twin: app/api/auth_test.py.
#
#   pwsh scripts/verify-jwt-enforce.ps1   # needs the kind cluster (scripts/up.ps1) + pyjwt
$ErrorActionPreference = "Stop"
$ctx = "kind-cloudsec"; $ns = "shop"
$root = Split-Path $PSScriptRoot -Parent
$py = if (Test-Path "$root\.venv\Scripts\python.exe") { "$root\.venv\Scripts\python.exe" } else { "python" }

# A valid token minted with the api's demo fixtures (DEMO_JWT_SECRET / RESOURCE_AUD defaults).
$jwt = & $py -c "import jwt,time;print(jwt.encode({'sub':'alice','aud':'https://api.shop.local','exp':int(time.time())+3600},'demo-fixture-key-not-a-real-secret',algorithm='HS256'))"

kubectl --context $ctx apply -f "$root\k8s\probes.yaml" *>$null
kubectl --context $ctx -n $ns wait --for=condition=Ready pod/probe-web --timeout=120s *>$null

$fail = 0
function chk($name, $got, $exp) {
  $ok = "$got" -eq "$exp"; if (-not $ok) { $script:fail = 1 }
  "{0}  {1,-48} expect {2}  got {3}" -f $(if ($ok) { "PASS" } else { "FAIL" }), $name, $exp, $got
}
try {
  kubectl --context $ctx -n $ns set env deploy/api AUTH_REQUIRE_JWT=1 *>$null
  kubectl --context $ctx -n $ns rollout status deploy/api --timeout=120s *>$null
  Start-Sleep -Seconds 2
  $ip = kubectl --context $ctx -n $ns get pod -l tier=backend -o jsonpath='{.items[0].status.podIP}'
  $u = "http://${ip}:8080/accounts/acct-alice"
  $cx = kubectl --context $ctx -n $ns exec probe-web -- curl -s -o /dev/null -m 10 -w '%{http_code}' -H "X-User: alice" $u
  $cn = kubectl --context $ctx -n $ns exec probe-web -- curl -s -o /dev/null -m 10 -w '%{http_code}' $u
  $cj = kubectl --context $ctx -n $ns exec probe-web -- curl -s -o /dev/null -m 10 -w '%{http_code}' -H "Authorization: Bearer $jwt" $u
  "== ID8: requester JWT enforce mode (AUTH_REQUIRE_JWT=1), live =="
  chk "X-User only -> reject (fallback disabled)" $cx 401
  chk "no credential -> reject"                   $cn 401
  chk "valid audience-bound Bearer -> allow"      $cj 200
} finally {
  kubectl --context $ctx -n $ns set env deploy/api AUTH_REQUIRE_JWT- *>$null
  kubectl --context $ctx -n $ns rollout status deploy/api --timeout=120s *>$null
  kubectl --context $ctx delete -f "$root\k8s\probes.yaml" *>$null
}
if ($fail) { ""; "FAILURES"; exit 1 } else { ""; "ID8 enforce: ALL PASS (X-User 401 / no-cred 401 / Bearer 200), demo mode restored"; exit 0 }
