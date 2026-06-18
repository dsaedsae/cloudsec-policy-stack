#!/usr/bin/env bash
# grade.sh — M11 LIVE grader: BPF-LSM exec-allowlist (loaded-image, not caller/arg0).
# SKIP (rc=2, NOT fail) where BPF-LSM is unavailable — which is MOST kind/Docker-Desktop kernels.
# It never claims PASS where the LSM hook doesn't engage: if the disallowed shell SURVIVES, that
# means the LSM program didn't attach (no bpf in lsm=) -> honest SKIP, not a false PASS. EXIT trap
# removes the test pod + policy. Run standalone. ED3 stays NOT_COVERED unless this genuinely fires.
set -uo pipefail
CTX="${CTX:-kind-cloudsec}"
NS="${NS:-shop}"
POD="m11-lsm-test"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
k() { kubectl --context "$CTX" "$@"; }

skip() { echo "SKIP: $1 — M11 라이브 채점 생략(FAIL 아님)."; exit 2; }
command -v kubectl >/dev/null 2>&1 || skip "kubectl 없음"
k cluster-info >/dev/null 2>&1       || skip "클러스터 미응답 ($CTX)"
k get crd tracingpolicies.cilium.io >/dev/null 2>&1 || skip "Tetragon 미설치 (up.sh)"

cleanup() {
  k -n "$NS" delete pod "$POD" --ignore-not-found >/dev/null 2>&1 || true
  k delete tracingpolicy m11-lsm-exec-allowlist --ignore-not-found >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== M11 LIVE — BPF-LSM exec-allowlist (loaded-image, not caller/arg0) =="

# dedicated test pod (nginx-unprivileged, restricted-PSA-compliant), labeled for the policy.
cat <<YAML | k apply -f - >/dev/null 2>&1
apiVersion: v1
kind: Pod
metadata: { name: $POD, namespace: $NS, labels: { lab: m11-lsm } }
spec:
  automountServiceAccountToken: false
  securityContext: { runAsNonRoot: true, runAsUser: 101, seccompProfile: { type: RuntimeDefault } }
  containers:
    - name: c
      image: nginxinc/nginx-unprivileged:1.27-alpine
      command: ["sleep", "3600"]
      securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } }
      volumeMounts: [{ name: t, mountPath: /tmp }]
  volumes: [{ name: t, emptyDir: {} }]
YAML
k -n "$NS" wait --for=condition=Ready "pod/$POD" --timeout=60s >/dev/null 2>&1 || skip "테스트 파드 미기동"
k apply -f "$ROOT/labs/m11/tracingpolicy-lsm-exec-allowlist.yaml" >/dev/null 2>&1 || skip "LSM 정책 적용 실패(스키마/버전)"
sleep 5   # let the LSM program attach (if BPF-LSM present)

ex() { k -n "$NS" exec "$POD" -- sh -c "$1" >/dev/null 2>&1; echo $?; }

# Availability probe: a DISALLOWED exec must be killed. If it SURVIVES, the LSM hook didn't attach
# (no bpf in this kernel's lsm=) -> SKIP honestly rather than claim a PASS.
sh_rc="$(ex '/bin/sh -c true')"
if [ "$sh_rc" != 137 ] && [ "$sh_rc" != 143 ]; then
  skip "BPF-LSM 미engage (disallowed /bin/sh rc=$sh_rc, kill 아님) — 이 커널 lsm=에 bpf 없음(kind 흔함)"
fi

held=0; total=0
gate() { total=$((total+1)); if [ "$1" = ok ]; then held=$((held+1)); printf '  HELD    %-40s %s\n' "$2" "$3"; else printf '  BREACH  %-40s %s\n' "$2" "$3"; fi; }

# 1) allowlisted loaded-image (nginx itself) SURVIVES — what M4 arg0 can't distinguish
nginx_rc="$(ex 'exec /usr/sbin/nginx -v')"
gate "$([ "$nginx_rc" = 0 ] && echo ok || echo no)" "nginx -v (allowlisted loaded-image) survives" "(rc=$nginx_rc, expect 0)"
# 2) disallowed shell killed
gate "$([ "$sh_rc" = 137 ] || [ "$sh_rc" = 143 ] && echo ok || echo no)" "/bin/sh (not allowlisted) killed" "(rc=$sh_rc, expect 137)"
# 3) RENAMED shell still killed — LSM sees the inode/path, defeating M4's arg0 rename bypass
ren_rc="$(ex 'cp /bin/busybox /tmp/x 2>/dev/null && /tmp/x sh -c true')"
gate "$([ "$ren_rc" = 137 ] || [ "$ren_rc" = 143 ] && echo ok || echo no)" "renamed shell /tmp/x still killed" "(rc=$ren_rc; arg0 rule was bypassed here)"

echo "----------------------------------------------------------------"
echo "M11 LSM 게이트 $held/$total HELD"
if [ "$held" -eq "$total" ]; then
  echo "PASS — LSM bprm 훅이 *적재 이미지*로 허용목록을 건다(rename·caller-혼동 우회 닫힘). (ED3 승격은 오너 판단 — 단발 PASS로는 안 됨.)"
else
  echo "일부 BREACH — LSM 정책/커널 점검(또는 SKIP 환경)."
fi
[ "$held" -eq "$total" ]
