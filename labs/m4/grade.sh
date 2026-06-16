#!/usr/bin/env bash
# M4 채점기 — labs/m4/tracingpolicy.yaml(학습자 정책)을 적용하고 *선택적* kill 을 검증:
# db 파드에서 `id`(비셸)는 rc=0 으로 살고, `sh`(셸)는 SIGKILL(rc=137). 둘 다여야 통과 —
# 그래야 "셸만 골라 죽인다"가 증명된다(전부 죽이거나 아무것도 안 죽이면 FAIL). 끝나면 canonical 복원.
#   bash labs/m4/grade.sh   (클러스터 up 필요)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CTX="kind-$(terraform -chdir="$ROOT/terraform" output -raw cluster_name 2>/dev/null || echo cloudsec)"
k() { kubectl --context "$CTX" "$@"; }
LAB="$ROOT/labs/m4/tracingpolicy.yaml"
CANON="$ROOT/k8s/tracingpolicy.yaml"
fail=0

if ! kubectl config get-contexts -o name 2>/dev/null | grep -qx "$CTX"; then
  echo "SKIP (채점 안 함 — PASS/FAIL 아님): '$CTX' 컨텍스트가 없다."
  echo "  -> PowerShell에서 'scripts/up.ps1' 로 클러스터를 먼저 띄워라."
  echo "  -> 띄웠는데도면: 'kubectl config get-contexts' 로 활성 컨텍스트 확인 (다른 kind 클러스터와 충돌)."
  exit 0
fi
k get ns shop >/dev/null 2>&1 || { echo "SKIP (채점 안 함 — PASS/FAIL 아님): shop ns 없음 — 'scripts/up.ps1' 로 띄워라."; exit 0; }

echo "== 학습자 TracingPolicy 적용 =="
if ! k apply -f "$LAB" >/tmp/m4apply.txt 2>&1; then
  echo "apply 실패:"; sed 's/^/  /' /tmp/m4apply.txt; k apply -f "$CANON" >/dev/null 2>&1; exit 1
fi
trap 'k apply -f "$CANON" >/dev/null 2>&1; echo "(canonical TracingPolicy 복원됨)"' EXIT
echo "eBPF 정책 로드 대기..."; sleep 6

DBPOD=$(k -n shop get pod -l tier=data -o jsonpath='{.items[0].metadata.name}')
[ -n "$DBPOD" ] || { echo "db 파드를 못 찾음"; exit 1; }

# 비셸 exec(id)는 살아야(rc=0), 셸 exec(sh)는 죽어야(rc=137/143). 둘 다 요구 → false-pass 차단.
k -n shop exec "$DBPOD" -- id >/dev/null 2>&1; rc_id=$?
k -n shop exec "$DBPOD" -- sh -c 'echo x' >/dev/null 2>&1; rc_sh=$?

echo "== 선택적 런타임 kill 채점 =="
if [ "$rc_id" = 0 ]; then printf '  %-46s expect 0    got %-4s PASS\n' "비셸 exec(id) 는 살아있다" "$rc_id"
else printf '  %-46s expect 0    got %-4s FAIL\n' "비셸 exec(id) (셸 아닌데 죽었다=과잉)" "$rc_id"; fail=1; fi
if [ "$rc_sh" = 137 ] || [ "$rc_sh" = 143 ]; then printf '  %-46s expect 137  got %-4s PASS\n' "셸 exec(sh) 는 SIGKILL" "$rc_sh"
else printf '  %-46s expect 137  got %-4s FAIL\n' "셸 exec(sh) (안 죽었다=통제 없음)" "$rc_sh"; fail=1; fi

echo "----------------------------------------------------------------"
if [ "$fail" = 0 ]; then echo "M4 GRADUATED — 정답지 비교: labs/m4/tracingpolicy.solution.yaml (shipped 기본은 zero-exec: k8s/tracingpolicy.yaml, ADR 0001/M8)"; else echo "M4: FAIL 확인. matchArgs(Postfix 셸 목록)·matchActions(Sigkill)을 다시 보라."; fi
exit $fail
