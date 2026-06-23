#!/usr/bin/env bash
# M9 grader — Assume-breach blast-radius containment (the zero-day lens).
# We ASSUME a web-tier workload was popped (e.g. a zero-day RCE) and measure how far the
# foothold is CONTAINED. probe-web carries the SAME Cilium identity (app:web / web-sa) as the
# real web pod, so it hits the SAME network policy — network-policy-equivalent to a popped web
# pod. NO real exploit is run. Reuses verify.sh's proven probe mechanics. Cluster needed.
#   bash labs/m9/grade.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CTX="kind-$(terraform -chdir="$ROOT/terraform" output -raw cluster_name 2>/dev/null || echo cloudsec)"
k() { kubectl --context "$CTX" "$@"; }

if ! kubectl config get-contexts -o name 2>/dev/null | grep -qx "$CTX"; then
  echo "SKIP (채점 안 함 — PASS/FAIL 아님): '$CTX' 컨텍스트가 없다 — 'scripts/up.ps1' 로 먼저 띄워라."; exit 0
fi
k get ns shop >/dev/null 2>&1 || { echo "SKIP (채점 안 함): shop ns 없음 — 'scripts/up.ps1' 로 띄워라."; exit 0; }

k apply -f "$ROOT/k8s/probes.yaml" >/dev/null 2>&1
trap 'k -n shop delete -f "$ROOT/k8s/probes.yaml" --ignore-not-found >/dev/null 2>&1 || true' EXIT
if ! k -n shop wait --for=condition=Ready pod/probe-web pod/probe-api --timeout=120s >/dev/null 2>&1; then
  echo "FAIL(M9): probe-web/probe-api 가 Ready가 아니다 — 발판(probe-web)에서 측정을 못 한다. 스택이 up인지 확인하라." >&2; exit 1
fi
API=$(k -n shop get pod -l tier=backend -o jsonpath='{.items[0].status.podIP}' 2>/dev/null || true)
DB=$(k -n shop get pod -l tier=data -o jsonpath='{.items[0].status.podIP}' 2>/dev/null || true)
DBPOD=$(k -n shop get pod -l tier=data -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
# 빈-IP 가드 (verify-cross-ns.sh와 동일한 관용구): 대상 티어가 없으면 'expect 000' 경계가
# *측정 없이* curl 000 -> HELD 로 거짓통과한다. 못 풀면 측정 불가이므로 FAIL (false HELD 금지).
if [ -z "$API" ] || [ -z "$DB" ] || [ -z "$DBPOD" ]; then
  echo "FAIL(M9): shop 티어 파드 IP/이름을 못 구했다 (api=$API db=$DB dbpod=$DBPOD) — 스택이 완전히 up이 아니다. 여기서의 '000'은 봉쇄가 아니라 false HELD다." >&2; exit 1
fi

held=0; total=0
boundary() { # desc expect-code curl-args...  (run FROM the popped web foothold = probe-web)
  local desc="$1" exp="$2"; shift 2; total=$((total + 1))
  local code; code=$(k -n shop exec probe-web -- curl -s -o /dev/null -m 8 -w '%{http_code}' "$@" 2>/dev/null || true)
  if [ "$code" = "$exp" ]; then printf '  HELD    %-44s (got %s)\n' "$desc" "$code"; held=$((held + 1))
  else printf '  BREACH  %-44s (got %s, expected %s)\n' "$desc" "$code" "$exp"; fi
}

echo "== 가정: web 파드가 제로데이 RCE로 털렸다. 발판=probe-web(동일 신원 app:web/web-sa). 어디까지 못 가나? =="
echo "-- 횡이동(lateral movement) --"
boundary "web -> db 직접 (L3 default-deny drop)"     000 "http://$DB:8080/"
boundary "web -> api /auditlogs (L7 method/path deny)" 403 -H "X-User: alice" "http://$API:8080/auditlogs/2026-06"
echo "-- 데이터 유출(exfiltration) --"
boundary "web -> 인터넷 (egress default-deny)"        000 "https://example.com"
boundary "web -> 클라우드 메타데이터 (SSRF 단골)"      000 "http://169.254.169.254/"
boundary "web -> kube-apiserver"                      000 -k "https://10.96.0.1:443/"
echo "-- 권한상승(cluster API takeover) --"
total=$((total + 1))
P=$(k auth can-i create pods --as=system:serviceaccount:shop:web-sa -n shop 2>/dev/null || true)
S=$(k auth can-i get secrets --as=system:serviceaccount:shop:web-sa -n shop 2>/dev/null || true)
if [ "$P" = no ] && [ "$S" = no ]; then printf '  HELD    %-44s (create-pods=%s get-secrets=%s)\n' "web-sa: K8s API 권한 0" "$P" "$S"; held=$((held + 1))
else printf '  BREACH  %-44s (create-pods=%s get-secrets=%s)\n' "web-sa K8s API rights" "$P" "$S"; fi
echo "-- 데이터 티어 최후 방어 (어찌어찌 도달했다면) --"
total=$((total + 1))
k -n shop exec "$DBPOD" -- id >/dev/null 2>&1; rci=$?
if [ "$rci" = 137 ] || [ "$rci" = 143 ]; then printf '  HELD    %-44s (id -> rc=%s; 137=SIGKILL, 143=SIGTERM fallback)\n' "data-tier zero-exec" "$rci"; held=$((held + 1))
else printf '  BREACH  %-44s (id rc=%s)\n' "data-tier exec survived" "$rci"; fi

echo "----------------------------------------------------------------"
echo "봉쇄 경계 $held/$total HELD"
cat <<'NOTE'

정직한 잔여 — assume-breach가 *못* 가두는 것 (force field 아님; THREAT_MODEL 참조):
  - 같은 web 티어 *내부* 피해(메모리·앱 로직·합법 응답 조작)는 봉쇄 대상이 아니다.
  - X-User는 데모 입력 — JWT 미강제 시 호출자 신원 위조 가능(ID8 enforce 모드로 닫음).
  - 허용된 egress 경로(DNS 등)로의 covert 유출 잔여.
  - io_uring 등 *기본 syscall 정책*이 못 보는 회피 클래스(M8) — LSM/KRSI가 해법.
  - 노드 루트·하이퍼바이저 탈출·공급망은 범위 밖.
졸업: 위 잔여를 *말로* 설명할 수 있어야 한다 — 봉쇄는 피해를 *줄이지* 없애지 않는다.
NOTE
if [ "$held" = "$total" ]; then echo "M9 GRADUATED — 모든 봉쇄 경계 HELD (+ 잔여 설명 가능 시)."; exit 0
else echo "M9: 경계 일부 BREACH — 스택이 up인지/정책이 적용됐는지 확인하라(정책 회귀일 수도)."; exit 1; fi
