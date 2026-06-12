#!/usr/bin/env bash
# enable-secrets-encryption.sh — POSIX twin of enable-secrets-encryption.ps1.
# Turns on Secret encryption-at-rest on the running kind cluster and proves it by
# reading raw etcd. All node changes go through docker cp/exec (no host mounts);
# the apiserver manifest is backed up first (reversible). The 32-byte key is
# generated here and never committed (terraform/.enc is gitignored).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CTX="kind-cloudsec"; NODE="cloudsec-control-plane"
ENC_DIR="$ROOT/terraform/.enc"; mkdir -p "$ENC_DIR"

# 1. Fresh 32-byte AES key -> EncryptionConfiguration.
KEY="$(head -c 32 /dev/urandom | base64 | tr -d '\n')"
sed "s|__ENC_KEY_B64__|$KEY|" "$ROOT/k8s/encryption-config.yaml" > "$ENC_DIR/enc.yaml"

# 2. Push config into the node; back up the apiserver static manifest.
docker exec "$NODE" mkdir -p /etc/kubernetes/enc
docker cp "$ENC_DIR/enc.yaml" "$NODE:/etc/kubernetes/enc/enc.yaml"
docker cp "$NODE:/etc/kubernetes/manifests/kube-apiserver.yaml" "$ENC_DIR/kube-apiserver.yaml.bak"

# 3. Edit the manifest with PyYAML (no hand YAML munging).
python3 - "$ENC_DIR/kube-apiserver.yaml.bak" "$ENC_DIR/kube-apiserver.yaml" <<'PY'
import sys, yaml
src, dst = sys.argv[1], sys.argv[2]
d = yaml.safe_load(open(src))
c = d["spec"]["containers"][0]
flag = "--encryption-provider-config=/etc/kubernetes/enc/enc.yaml"
cmd = c.setdefault("command", [])
if flag not in cmd: cmd.append(flag)
vm = c.setdefault("volumeMounts", [])
if not any(m.get("name") == "enc" for m in vm):
    vm.append({"name": "enc", "mountPath": "/etc/kubernetes/enc", "readOnly": True})
vols = d["spec"].setdefault("volumes", [])
if not any(v.get("name") == "enc" for v in vols):
    vols.append({"name": "enc", "hostPath": {"path": "/etc/kubernetes/enc", "type": "DirectoryOrCreate"}})
yaml.safe_dump(d, open(dst, "w"), default_flow_style=False, sort_keys=False)
PY

# 4. Apply — kubelet restarts the static apiserver pod on file change.
docker cp "$ENC_DIR/kube-apiserver.yaml" "$NODE:/etc/kubernetes/manifests/kube-apiserver.yaml"
echo "Waiting for kube-apiserver to come back..."
# `get ns default` succeeding = apiserver serving AND authorizing again (more
# reliable than --raw=/healthz, which can be empty mid-restart).
ok=0; for _ in $(seq 1 60); do sleep 3; kubectl --context "$CTX" get ns default -o name >/dev/null 2>&1 && { ok=1; break; }; done
[ "$ok" = 1 ] || { echo "apiserver not healthy; restore: docker cp $ENC_DIR/kube-apiserver.yaml.bak $NODE:/etc/kubernetes/manifests/kube-apiserver.yaml"; exit 1; }

# 5. Re-encrypt pre-existing Secrets.
kubectl --context "$CTX" get secrets --all-namespaces -o json | kubectl --context "$CTX" replace -f - >/dev/null

# 6. Prove it via raw etcd. etcdctl lives INSIDE the etcd pod (not on the node) and
#    needs the HTTPS endpoint. Pipe straight to grep -a so etcd's binary value (with
#    NUL bytes) is searched as text rather than mangled by a shell capture.
ETCD="etcd-$NODE"
ETCDCTL="etcdctl --endpoints=https://127.0.0.1:2379 --cacert /etc/kubernetes/pki/etcd/ca.crt --cert /etc/kubernetes/pki/etcd/server.crt --key /etc/kubernetes/pki/etcd/server.key get /registry/secrets/default/atrest-proof"
kubectl --context "$CTX" -n default delete secret atrest-proof --ignore-not-found >/dev/null
kubectl --context "$CTX" -n default create secret generic atrest-proof --from-literal=card=4111111111111111 >/dev/null
echo "== etcd stored value for secret/atrest-proof (head) =="
kubectl --context "$CTX" -n kube-system exec "$ETCD" -- $ETCDCTL 2>/dev/null | head -c 96 | od -c | head -6
enc=0; leak=0
kubectl --context "$CTX" -n kube-system exec "$ETCD" -- $ETCDCTL 2>/dev/null | grep -aq 'k8s:enc:aescbc' && enc=1
kubectl --context "$CTX" -n kube-system exec "$ETCD" -- $ETCDCTL 2>/dev/null | grep -aq '4111111111111111' && leak=1
kubectl --context "$CTX" -n default delete secret atrest-proof --ignore-not-found >/dev/null
[ "$enc" = 1 ] && [ "$leak" = 0 ] && echo "PASS: Secret AES-CBC encrypted at rest in etcd (k8s:enc:aescbc; no plaintext)." || { echo "FAIL: expected k8s:enc:aescbc and no plaintext"; exit 1; }
