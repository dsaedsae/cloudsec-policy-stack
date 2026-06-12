#!/usr/bin/env bash
# M2 채점기 — labs/m2/admission-policy.yaml(학습자 VAP)을 클러스터에 적용하고, 위조 파드는
# DENY·정합 파드는 ADMIT 되는지 server dry-run 으로 검증. 끝나면 canonical 정책을 복원한다.
#   bash labs/m2/grade.sh        (클러스터 up 필요)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CTX="kind-$(terraform -chdir="$ROOT/terraform" output -raw cluster_name 2>/dev/null || echo cloudsec)"
k() { kubectl --context "$CTX" "$@"; }
LAB="$ROOT/labs/m2/admission-policy.yaml"
CANON="$ROOT/k8s/admission-policy.yaml"
CURL="curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69"
fail=0

k get ns shop >/dev/null 2>&1 || { echo "SKIP: 클러스터 미기동(scripts\\up.ps1 먼저). shop ns 없음."; exit 0; }

echo "== 학습자 VAP 적용 =="
if ! k apply -f "$LAB" >/tmp/m2apply.txt 2>&1; then
  echo "apply 실패 — YAML/CEL 문법 오류:"; sed 's/^/  /' /tmp/m2apply.txt
  k apply -f "$CANON" >/dev/null 2>&1; exit 1
fi
sleep 3   # VAP/binding 반영 대기
trap 'k apply -f "$CANON" >/dev/null 2>&1 || true; echo "(canonical 정책 복원됨)"' EXIT

pod() { # name app sa  (app="" 이면 라벨 없음)
  local labels="{ }"; [ -n "$2" ] && labels="{ app: $2 }"
  cat <<YAML
apiVersion: v1
kind: Pod
metadata: { name: $1, namespace: shop, labels: $labels }
spec:
  serviceAccountName: $3
  automountServiceAccountToken: false
  securityContext: { runAsNonRoot: true, runAsUser: 100, seccompProfile: { type: RuntimeDefault } }
  containers:
    - name: c
      image: $CURL
      command: ["sleep", "1"]
      securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } }
      resources: { requests: { cpu: "5m", memory: "8Mi" }, limits: { cpu: "50m", memory: "32Mi" } }
YAML
}
# DENY는 "이 정책이 막았다"여야 한다 — VAP 거부 메시지엔 정책명이 들어가므로 그걸로 식별
# (RBAC 403/PSA 거부와 구분). ADMIT는 dry-run 성공(rc=0).
deny() { # name app sa  desc
  local out; out=$(pod "$1" "$2" "$3" | k create --dry-run=server -f - 2>&1 || true)
  if echo "$out" | grep -qi 'shop-label-identity'; then printf '  %-46s expect DENY  PASS\n' "$4"
  else printf '  %-46s expect DENY  FAIL\n' "$4"; fail=1; fi
}
admit() { # name app sa  desc
  if pod "$1" "$2" "$3" | k create --dry-run=server -f - >/dev/null 2>&1; then printf '  %-46s expect ADMIT PASS\n' "$4"
  else printf '  %-46s expect ADMIT FAIL\n' "$4"; fail=1; fi
}

echo "== 라벨↔SA 일관성 채점 =="
deny  forge-1 api web-sa "forged app:api on web-sa"
deny  forge-2 web api-sa "forged app:web on api-sa"
admit ok-1    api api-sa "consistent app:api + api-sa"
admit ok-2    web web-sa "consistent app:web + web-sa"
admit ok-3    ""  default "no app label (out of scope)"

echo "----------------------------------------------------------------"
if [ "$fail" = 0 ]; then echo "M2 GRADUATED — 정답지 비교: k8s/admission-policy.yaml"; else echo "M2: 위 FAIL 확인. 한 케이스라도 틀리면 CEL 로직을 다시 보라."; fi
exit $fail
