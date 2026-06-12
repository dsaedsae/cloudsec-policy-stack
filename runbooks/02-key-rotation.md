# 02 — 키 회전 (Key Rotation)

정기 회전 또는 유출 의심 시. 무중단 + 회전 후 검증이 원칙.

---

## A. etcd 저장암호화 키 (AES-CBC)

`k8s/encryption-config.yaml`은 `key1`로 Secret을 암호화한다. 회전은 **새 키를 *우선* 키로
추가 → 전체 재암호화 → 옛 키 제거** 순서다. (`enable-secrets-encryption`처럼 새 키로 *교체*만
하면 옛 키로 암호화된 기존 Secret을 못 읽으니, 반드시 2-키 과도기를 거친다.)

**1) 새 키를 첫 번째(=암호화용)로, 옛 키는 두 번째(=복호화용)로:**
```yaml
# terraform/.enc/enc.yaml (런타임 파일) 를 이렇게 만든다
providers:
  - aescbc:
      keys:
        - { name: key2, secret: <새 32바이트 base64> }   # 신규 = 새 쓰기에 사용
        - { name: key1, secret: <기존 키> }                # 기존 = 옛 데이터 복호화
  - identity: {}
```
적용(노드에 push + apiserver 재기동):
```bash
docker cp terraform/.enc/enc.yaml cloudsec-control-plane:/etc/kubernetes/enc/enc.yaml
# apiserver 정적 파드는 파일 변경 시 kubelet이 재기동. healthz 회복 대기.
```

**2) 전체 Secret 재암호화(이제 key2로 다시 써짐):**
```bash
kubectl get secrets --all-namespaces -o json | kubectl replace -f -
```

**3) 옛 키 제거:** enc.yaml에서 `key1` 줄을 지우고 다시 push → 재기동. 이제 key1 없이도 모든
Secret이 읽힌다(전부 key2로 재암호화됨).

**검증:**
```bash
ETCD=etcd-cloudsec-control-plane
kubectl -n kube-system exec $ETCD -- etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert /etc/kubernetes/pki/etcd/ca.crt --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key get /registry/secrets/default/<any> | grep -a "k8s:enc:aescbc:v1:key2"
```
→ 프리픽스가 `key2`면 회전 완료. (MSYS 환경은 `MSYS_NO_PATHCONV=1`.)

**EKS 변형:** EKS는 KMS 봉투암호화를 쓴다. **KMS 키 자동 회전 활성화**(연 1회) 또는 수동:
```bash
aws kms enable-key-rotation --key-id <key>
aws kms get-key-rotation-status --key-id <key>
```
KMS 회전은 데이터키만 바뀌고 기존 데이터는 그대로 복호 가능(봉투 구조) — k8s처럼 재암호화
불필요.

---

## B. SPIRE SVID / CA

- **워크로드 SVID:** 단기(기본 ~1h) X.509로 **SPIRE 에이전트가 자동 회전**. 운영자 개입 불필요.
- **검증:** `kubectl -n cilium-spire get pods`(server/agent Ready). 핸드셰이크는 `netpol-mutual.yaml`
  적용(opt-in) 후 web→api 200으로 확인 — Lab 4에서 라이브 검증(기본 verify 스위트엔 미포함).
- **CA 회전:** SPIRE 서버의 상위 CA/중간 CA 교체는 SPIRE 운영 작업. 데모 범위에선 SVID 자동
  회전만 보증하고, CA 회전은 "SPIRE 운영 절차 위임"으로 기록.

---

## 다루지 않는 것
- HSM/CloudHSM 백업 키 관리, 키 에스크로.
- 유출 *확정* 시의 전사 키·자격증명 일괄 무효화(IR 상위 절차).
