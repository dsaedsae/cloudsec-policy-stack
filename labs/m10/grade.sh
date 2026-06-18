#!/usr/bin/env bash
# grade.sh — M10 LIVE grader (opt-in; needs kind + ArgoCD via scripts/enable-gitops.sh).
# Measures the GitOps identity-TCB relocation (B8) in the project's "measure it live" style (M8/M9).
# SKIP (not FAIL, rc=2) when cluster/ArgoCD/stack absent. EXIT trap restores canonical so a half-run
# never leaves a boundary open. Run standalone (not alongside verify.sh). Observed times = INFO only.
set -uo pipefail
CTX="${CTX:-kind-cloudsec}"
APP="shop-network-runtime"
WINDOW="${RECONCILE_WINDOW:-300}"          # max seconds to wait for selfHeal to revert drift
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
k() { kubectl --context "$CTX" "$@"; }
held=0; total=0

skip() { echo "SKIP: $1 — M10 라이브 채점 생략(FAIL 아님). scripts/enable-gitops.sh 후 재실행."; exit 2; }
command -v kubectl >/dev/null 2>&1 || skip "kubectl 없음"
k cluster-info >/dev/null 2>&1       || skip "클러스터 미응답 ($CTX)"
k get ns argocd >/dev/null 2>&1      || skip "ArgoCD 미설치 (scripts/enable-gitops.sh)"
k -n shop get cnp allow-web-to-api >/dev/null 2>&1 || skip "shop 스택 미배포 (up.sh + root-app sync)"

cleanup() {                                # restore known-good on ANY exit
  k apply -f "$ROOT/k8s/netpol.yaml" >/dev/null 2>&1 || true
  k -n argocd delete application m10-forge --ignore-not-found >/dev/null 2>&1 || true
  k -n shop delete pod forge-via-git --ignore-not-found >/dev/null 2>&1 || true
  k -n shop delete cnp m10-rogue-untracked --ignore-not-found >/dev/null 2>&1 || true
}
trap cleanup EXIT

gate() { total=$((total+1)); if [ "$1" = ok ]; then held=$((held+1)); printf '  HELD    %-46s %s\n' "$2" "$3"
         else printf '  BREACH  %-46s %s\n' "$2" "$3"; fi; }

echo "== M10 LIVE — GitOps 무결성 통제판 (reconciler = 새 신원-TCB, B8) =="

# ---- L1: drift-correction — attacker kubectl-edit is reverted, AND the boundary re-closes ----
echo "-- L1: drift 자동교정 (공격자 patch를 reconciler가 되돌린다) --"
k -n argocd patch application "$APP" --type merge \
  -p '{"spec":{"syncPolicy":{"automated":{"prune":true,"selfHeal":true}}}}' >/dev/null 2>&1 || true
k apply -f "$ROOT/labs/m10/break/drift-netpol.yaml" >/dev/null 2>&1   # DRIFT: open /auditlogs
reverted=no; waited=0
while [ "$waited" -lt "$WINDOW" ]; do
  k -n shop get cnp allow-web-to-api -o yaml 2>/dev/null | grep -q '/auditlogs' || { reverted=yes; break; }
  sleep 5; waited=$((waited+5))
done
gate "$([ "$reverted" = yes ] && echo ok || echo no)" "netpol drift auto-reverted" "(<= ${WINDOW}s; observed ~${waited}s INFO)"
WEB="$(k -n shop get pod -l app=web -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
code=""
[ -n "$WEB" ] && code="$(k -n shop exec "$WEB" -- sh -c 'curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://api:8080/auditlogs/1' 2>/dev/null)"
gate "$([ "$code" = 403 ] && echo ok || echo no)" "/auditlogs re-closed after revert (semantic)" "(GET -> ${code:-?}, expect 403)"

# ---- L2: fighting controllers — admission denies bad-Git, Application sits OutOfSync forever ----
echo "-- L2: fighting controllers (admission이 나쁜-Git을 막고 reconciler는 OutOfSync) --"
cat <<YAML | k apply -f - >/dev/null 2>&1
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata: { name: m10-forge, namespace: argocd }
spec:
  project: shop
  source: { repoURL: "https://github.com/dsaedsae/cloudsec-policy-stack", targetRevision: master, path: labs/m10/break, directory: { include: "forge-via-git.yaml" } }
  destination: { server: "https://kubernetes.default.svc", namespace: shop }
YAML
k -n argocd patch application m10-forge --type merge -p '{"operation":{"sync":{}}}' >/dev/null 2>&1 || true
sleep 15
sync_status="$(k -n argocd get application m10-forge -o jsonpath='{.status.sync.status}' 2>/dev/null)"
msg="$(k -n argocd get application m10-forge -o jsonpath='{.status.operationState.message} {.status.conditions[*].message}' 2>/dev/null)"
pod_absent=no; k -n shop get pod forge-via-git >/dev/null 2>&1 || pod_absent=yes
adm_msg=no; printf '%s' "$msg" | grep -qiE 'admission|denied|policy|identity|web-sa|app' && adm_msg=yes
if [ "$sync_status" != "Synced" ] && [ "$pod_absent" = yes ] && [ "$adm_msg" = yes ]; then
  gate ok "forged-Git denied at admission, App OutOfSync" "(sync=$sync_status, pod absent, admission msg)"
else
  gate no "fighting-controllers not demonstrated" "(sync=$sync_status pod_absent=$pod_absent adm_msg=$adm_msg)"
fi

# ---- L3 (live): reconciler RBAC is bounded — tight, not broken ----
echo "-- L3: reconciler 실효 RBAC 경계 --"
SA="system:serviceaccount:argocd:argocd-application-controller"
ci() { k auth can-i "$1" "$2" ${3:+-n "$3"} --as "$SA" 2>/dev/null; }
crb="$(ci create clusterrolebindings)"; sec="$(ci get secrets kube-system)"; cnp="$(ci patch ciliumnetworkpolicies shop)"
if [ "$crb" = no ] && [ "$sec" = no ] && [ "$cnp" = yes ]; then
  gate ok "reconciler bounded (no CRB/secret, can patch CNP)" "(tight != broken)"
else
  gate no "reconciler RBAC unexpected" "(crb=$crb secret=$sec cnp=$cnp)"
fi

# ---- L6: negative control — drift-correction is NOT universal (untracked object survives) ----
echo "-- L6: 음성 통제 — un-tracked 객체는 reconciler가 못 되돌린다 --"
cat <<YAML | k apply -f - >/dev/null 2>&1
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: { name: m10-rogue-untracked, namespace: shop }
spec: { endpointSelector: { matchLabels: { app: db } }, ingress: [] }
YAML
sleep 20
survives=no; k -n shop get cnp m10-rogue-untracked >/dev/null 2>&1 && survives=yes
gate "$([ "$survives" = yes ] && echo ok || echo no)" "untracked rogue object SURVIVES (honest limit)" "(correction != universal; NS5)"

echo "----------------------------------------------------------------"
echo "M10 무결성 게이트 $held/$total HELD"
if [ "$held" -eq "$total" ]; then
  echo "PASS — GitOps가 신원-TCB를 이전하되, 그 새 TCB(reconciler)는 bounded이고 admission을 우회 못한다."
else
  echo "일부 BREACH/미충족 — 위 항목 점검(클러스터·ArgoCD 상태 확인)."
fi
[ "$held" -eq "$total" ]
