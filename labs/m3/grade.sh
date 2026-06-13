#!/usr/bin/env bash
# M3 채점기 — labs/m3/netpol.yaml(학습자 정책)을 적용하고 제로트러스트 위상을 검증:
# default-deny(web→db 차단), L7(auditlogs 403), 허용 홉(web→api 200, api→db 200),
# egress default-deny(internet/metadata/apiserver 000). 끝나면 canonical 복원.
#   bash labs/m3/grade.sh   (클러스터 up 필요)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CTX="kind-$(terraform -chdir="$ROOT/terraform" output -raw cluster_name 2>/dev/null || echo cloudsec)"
k() { kubectl --context "$CTX" "$@"; }
LAB="$ROOT/labs/m3/netpol.yaml"
CANON="$ROOT/k8s/netpol.yaml"
fail=0

if ! kubectl config get-contexts -o name 2>/dev/null | grep -qx "$CTX"; then
  echo "SKIP (채점 안 함 — PASS/FAIL 아님): '$CTX' 컨텍스트가 없다."
  echo "  -> PowerShell에서 'scripts/up.ps1' 로 클러스터를 먼저 띄워라."
  echo "  -> 띄웠는데도면: 'kubectl config get-contexts' 로 활성 컨텍스트 확인 (다른 kind 클러스터와 충돌)."
  exit 0
fi
k get ns shop >/dev/null 2>&1 || { echo "SKIP (채점 안 함 — PASS/FAIL 아님): shop ns 없음 — 'scripts/up.ps1' 로 띄워라."; exit 0; }

echo "== 학습자 netpol 적용 =="
if ! k apply -f "$LAB" >/tmp/m3apply.txt 2>&1; then
  echo "apply 실패:"; sed 's/^/  /' /tmp/m3apply.txt; k apply -f "$CANON" >/dev/null 2>&1; exit 1
fi
k apply -f "$ROOT/k8s/probes.yaml" >/dev/null 2>&1
trap 'k apply -f "$CANON" >/dev/null 2>&1; k -n shop delete -f "$ROOT/k8s/probes.yaml" --ignore-not-found >/dev/null 2>&1; echo "(canonical netpol 복원 + probe 정리됨)"' EXIT
k -n shop wait --for=condition=Ready pod/probe-web pod/probe-api --timeout=120s >/dev/null 2>&1
echo "정책 전파 대기..."; sleep 8

API=$(k -n shop get pod -l tier=backend -o jsonpath='{.items[0].status.podIP}')
DB=$(k -n shop get pod -l tier=data -o jsonpath='{.items[0].status.podIP}')

probe() { # src desc expect curl-args...
  local src="$1" desc="$2" exp="$3"; shift 3
  local code; code=$(k -n shop exec "$src" -- curl -s -o /dev/null -m 8 -w '%{http_code}' "$@" 2>/dev/null || true)
  if [ "$code" = "$exp" ]; then printf '  %-46s expect %-4s got %-4s PASS\n' "$desc" "$exp" "$code"
  else printf '  %-46s expect %-4s got %-4s FAIL\n' "$desc" "$exp" "$code"; fail=1; fi
}

echo "== 제로트러스트 위상 채점 =="
probe probe-web "L1 web->db 직접(차단)"              000 "http://$DB:8080/"
probe probe-web "L2 web->api GET /auditlogs(L7 거부)" 403 -H "X-User: alice" "http://$API:8080/auditlogs/2026-06"
probe probe-web "허용 web->api GET 본인계좌"          200 -H "X-User: alice" "http://$API:8080/accounts/acct-alice"
probe probe-api "허용 api->db"                        200 "http://$DB:8080/"
probe probe-web "egress web->인터넷(차단)"            000 "https://example.com"
probe probe-web "egress web->메타데이터(차단)"        000 "http://169.254.169.254/"
probe probe-web "egress web->apiserver(차단)"         000 -k "https://10.96.0.1:443/"

echo "----------------------------------------------------------------"
if [ "$fail" = 0 ]; then echo "M3 GRADUATED — 정답지 비교: k8s/netpol.yaml"; else echo "M3: FAIL 확인. 어느 홉이 과허용/과차단인지 보라."; fi
exit $fail
