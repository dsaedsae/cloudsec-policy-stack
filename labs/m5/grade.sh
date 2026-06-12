#!/usr/bin/env bash
# M5 채점기 — 암호화는 "재구성"이 아니라 "실행·해석" 모듈이다(정책 로직이 아니라 설정 플래그).
# 라이브로 채점하는 한 가지: ET1 = WireGuard 활성 + api/db가 다른 노드 → api→db 홉이 선상에서 암호화.
# capture-wg(ET2)·etcd 암호화(ER1)는 README의 가이드대로 직접 실행·해석한다(아래 안내 출력).
#   bash labs/m5/grade.sh   (클러스터 up 필요)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CTX="kind-$(terraform -chdir="$ROOT/terraform" output -raw cluster_name 2>/dev/null || echo cloudsec)"
k() { kubectl --context "$CTX" "$@"; }
fail=0

k get ns shop >/dev/null 2>&1 || { echo "SKIP: 클러스터 미기동(scripts\\up.ps1 먼저)."; exit 0; }

echo "== ET1: 크로스노드 WireGuard 암호화 채점 =="
ENC=$(k exec -n kube-system ds/cilium -c cilium-agent -- cilium-dbg encrypt status 2>/dev/null || true)
API_NODE=$(k -n shop get pod -l tier=backend -o jsonpath='{.items[0].spec.nodeName}')
DB_NODE=$(k -n shop get pod -l tier=data -o jsonpath='{.items[0].spec.nodeName}')
echo "  encrypt status: $(echo "$ENC" | grep -i 'Encryption' | head -1 | sed 's/^ *//')"
echo "  api node=$API_NODE  db node=$DB_NODE"
if echo "$ENC" | grep -qi 'Wireguard' && [ -n "$API_NODE" ] && [ -n "$DB_NODE" ] && [ "$API_NODE" != "$DB_NODE" ]; then
  printf '  %-46s PASS\n' "WireGuard 활성 + api/db 다른 노드 → 크로스노드 암호화"
else
  printf '  %-46s FAIL\n' "WireGuard/노드분산"; fail=1
fi

echo ""
echo "== 직접 실행·해석 (이 부분이 M5의 핵심 — README 참고) =="
echo "  [ET2] bash scripts/capture-wg.sh    # db 노드 host netns에서 WG 패킷 캡처(암호문) + 평문 0"
echo "  [ER1] bash scripts/enable-secrets-encryption.sh   # etcd Secret을 AES-CBC로 암호화 후 원시 etcd에서 확인"
echo "        → 둘을 돌려보고 출력을 README Step 2/3의 질문으로 해석하라."

echo "----------------------------------------------------------------"
if [ "$fail" = 0 ]; then echo "M5 ET1 PASS — 이제 capture-wg / etcd 암호화를 직접 실행·해석하면 졸업."; else echo "M5: ET1 FAIL 확인."; fi
exit $fail
