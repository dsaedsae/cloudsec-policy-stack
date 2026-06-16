# M5 — 데이터 보호: 암호화 실행·해석 (전송 + 저장)

<div class="lab-pills">
<span class="lab-progress">모듈 6 / 7</span> · <span class="lab-badge">스택 WireGuard+etcd</span> · <span class="lab-badge">소요 ~30–45m</span> · <span class="lab-badge cluster">클러스터 필요 · RAM ~6–8GB</span> · <span class="lab-badge">비용 $0 로컬</span>
</div>

**미션:** 데이터의 세 상태 중 **전송 중(in-transit)**과 **저장(at-rest)** 암호화를 *직접 실행*하고
그 증거를 *해석*한다. 이 모듈은 정책을 새로 짜는 게 아니라(암호화는 설정 플래그) — **무엇이 어떻게
증명되는지**를 손으로 확인하는 것이 핵심이다.

> **학습 성과 (면접에서 말할 수 있는 것):** 전송(WireGuard)·저장(etcd) 암호화를 직접 실행하고 증거를 해석하며, *평문0은 보강 증거지 결정적 증명이 아니다*(결정적 증거는 WG패킷+노드분산)를 설명할 수 있다. → [캡스톤 M5](../capstone.md)

**클러스터 필요.** 편집 파일 없음 — 실행·관찰·해석.

> 선행: M2–M4 권장(같은 세션). 배경: [`docs/06-data-protection.md`](../../docs/06-data-protection.md).
> 평가 ID: **ET**=Encryption in-Transit(전송 중), **ER**=Encryption at-Rest(저장). 전체 목록은 [`docs/mls-coverage.csv`](../../docs/mls-coverage.csv). **ET1**만 라이브 채점 게이트이고, ET2(패킷 캡처)·ER1(etcd)은 직접 실행·해석 항목이다.

---

## Step 0 — ET1 라이브 채점

> 클러스터가 떠 있다고 가정한다(M2~M5 한 세션). 안 떴으면 PowerShell에서 `scripts\up.ps1` 먼저.
> 채점기는 **Git Bash**에서 (forward slash). [SETUP](../SETUP.md).

```bash
# Git Bash 창에서:
kubectl cluster-info --context kind-cloudsec   # 떴는지 확인 (에러면 → PowerShell: scripts\up.ps1)
bash labs/m5/grade.sh        # WireGuard 활성 + api/db 다른 노드 → 크로스노드 암호화 PASS
```

> `db`는 `podAntiAffinity`로 `api`와 다른 노드에 강제 배치된다. 그래서 api→db 홉이 *노드 경계를
> 넘고*, Cilium WireGuard가 그 트래픽을 암호화한다. 채점기는 *암호화 활성*과 *노드 분산*을 함께
> 단언한다 — "기능 켜짐"이 아니라 "이 앱 홉이 선상에서 암호화됨"을 증명.

## Step 1 — 전송 중 암호화: 패킷 캡처 (ET2)

`encrypt status`는 "켜졌다"만 말한다. 더 강한 증거는 *선상의 바이트*를 보는 것:

```bash
bash scripts/capture-wg.sh
```

이건 db 노드의 host netns(파드가 아니라 — PSA 제약 회피)에서 `tcpdump`로 잡는다.

> **왜 파드가 아니라 `docker exec`인가 (메커니즘).** tcpdump는 `AF_PACKET` raw 소켓을 열어야 하고
> 그건 `CAP_NET_RAW`를 요구한다. shop ns는 PSA `restricted`라 `NET_RAW`를 가진 파드는
> admission에서 거부된다(privileged도 마찬가지). kind 노드는 그냥 docker 컨테이너이고 그 안의
> host netns는 PSA 밖이므로, `docker exec`로 들어가면 admission을 우회해 노드 *물리 iface*를
> 정당하게 캡처할 수 있다.

**스크립트가 실제로 거는 두 필터(line-by-line).** `capture-wg.sh`는 트래픽을 만들기 *전에* 두 캡처를
동시에 띄운다(나중에 띄우면 첫 패킷을 놓친다):

```bash
# 양성(암호문): api 노드 IP와의 WG UDP. -c 상한 없음 → 25s 타임아웃이 끝내므로 보고된 수는
#               '캡처 상한'이 아니라 '측정된 총량'이다.
tcpdump -ni eth0 -w /tmp/wg.pcap "udp port 51871 and host $API_NODE_IP"
# 음성(평문): db '파드' IP의 tcp/8080을 ASCII로. 여기 X-User/HTTP/1이 보이면 평문 누출.
tcpdump -nAi eth0 -c 200 "tcp port 8080 and host $DB_IP"
```

음성 필터가 db **노드** IP가 아니라 db **파드** IP(`10.244.x.x`)를 거는 게 포인트다 — 캡슐화된
내부(inner) 패킷의 주소가 그거이기 때문. 다만 터널 하에선 그 inner 주소가 eth0에 *애초에* 안
나타나므로, 이 음성은 구조적으로 거의 항상 0이다(아래 Q2의 정직 메모와 직결).

**해석 질문:**

1. <details><summary>왜 cilium_wg0가 아니라 eth0에서 잡나?</summary>cilium_wg0는 터널의 *복호화된* 쪽(평문 파드 트래픽). 물리 iface eth0가 노드 간 *암호문*(UDP/51871 WireGuard)이 흐르는 곳. 암호문을 보려면 eth0.</details>
2. <details><summary>"평문 0"이 곧 "암호화됨"의 *결정적* 증거인가? 정직하게.</summary>아니다 — *보강* 증거다. 크로스노드 파드 트래픽은 캡슐화되므로 평문 tcp/8080은 암호화 여부와 무관하게 eth0에 안 나타날 수 있다. *결정적* 증거는 WG 패킷(UDP/51871) 존재 + 노드 분산. 스크립트가 이 한계를 정직하게 출력한다(이 repo가 적대적 검증에서 스스로 잡아 고친 부분).</details>
3. <details><summary>왜 트래픽 흐름 게이트(REQOK>=1)가 필요한가?</summary>트래픽이 0이면 "평문 0"은 공허하다(아무것도 안 흘렀으니). 실제 요청이 성공해야 "암호문은 보이고 평문은 안 보인다"가 의미를 가진다.</details>
4. <details><summary>게이트는 어떻게 "트래픽이 실제로 흘렀다"를 *위조 불가능하게* 단언하나?</summary>트래픽 생성기는 api 파드 안의 파이썬으로 db 파드에 20번 GET을 보내고(슬림 이미지엔 curl이 없어 image 자체 python 사용), 성공 카운트 `r`이 0이면 `sys.exit(7)`로 죽는다. 셸은 `[ REQOK >= 1 ] || skip`으로 받으므로, 한 건도 안 통하면 PASS/FAIL이 아니라 **SKIP**으로 빠진다(exit 0). 즉 "요청을 보냈다"가 아니라 "응답이 돌아왔다"가 게이트다 — NetworkPolicy drop이나 db 미기동이면 자동 SKIP된다(스크립트의 skip 메시지가 이 두 원인을 짚는다).</details>
5. <details><summary>WG 패킷 수가 앱 트래픽보다 많게 나올 수 있다. 그럼 거짓양성 아닌가?</summary>아니다. 양성 카운트(`WG_COUNT`)는 앱 트래픽 + 노드 백그라운드 WG(헬스/하트비트)를 *함께* 포함한다 — 스크립트가 그렇게 명시한다. 그래서 이 수는 "앱 홉이 N개 암호화됐다"의 정밀 측정이 아니라 "이 노드쌍 사이 선상 트래픽이 WG로 캡슐화된다"의 존재 증거다. 정밀한 앱-홉 단언은 ET1(노드분산+encrypt status)이 맡고, 양성은 게이트가 통과한 뒤에만 크레딧된다.</details>

## Step 2 — 저장 암호화: etcd (ER1)

```bash
bash scripts/enable-secrets-encryption.sh
```

이건 apiserver에 AES-CBC `EncryptionConfiguration`을 켜고, Secret을 원시 etcd에서 직접 읽어 증명한다.

**`k8s/encryption-config.yaml` 한 줄씩.** 이 파일은 템플릿이다(키는 런타임에 주입, 절대 커밋 안 함):

```yaml
resources:
  - resources: [secrets]          # Secret만 암호화 대상(ConfigMap 등은 그대로)
    providers:
      - aescbc:                    # 첫 provider = 새 쓰기에 *사용되는* 암호. 순서가 의미를 갖는다.
          keys:
            - name: key1
              secret: __ENC_KEY_B64__   # 스크립트가 32바이트 랜덤 base64로 치환
      - identity: {}               # 마지막 = 평문 패스스루. 회전/마이그레이션 중 옛 미암호화 값을 읽게 함
```

**provider 순서가 전부다.** apiserver는 *쓸 때* 첫 provider(`aescbc/key1`)로 암호화하고, *읽을 때*
프리픽스(`k8s:enc:aescbc:v1:key1:`)를 보고 매칭되는 provider로 복호화한다. `identity`가 마지막인 이유:
암호화 켜기 *전에* 이미 etcd에 들어간 base64 Secret을 회전 중에도 읽어야 하기 때문 —
`identity`를 첫 줄에 두면 모든 새 쓰기가 평문이 되어 암호화가 무력화된다(흔한 사고).

**해석 질문:**

6. <details><summary>증명의 핵심 관찰은 무엇인가?</summary>etcd에 저장된 Secret 값이 `k8s:enc:aescbc:v1:`로 시작하고 평문이 없다. kubectl로 보면 복호화돼 보이지만, *디스크(etcd)*엔 암호문으로 있다 — 백업 유출/디스크 탈취 시 방어.</details>
7. <details><summary>이 데모의 AES 키와 실무 KMS 봉투암호화의 차이는?</summary>여기선 로컬 생성 AES 키(파일, gitignore). 실무는 KMS/HSM가 키를 관리(봉투암호화) — 키 자체가 디스크에 평문으로 안 남는다. AWS 경로는 EKS+KMS(docs/aws-eks-path.md).</details>
8. <details><summary>키 회전은 어떻게? (runbooks/02-key-rotation.md)</summary>2-키 흐름: 새 키를 1순위로 추가 → 모든 Secret 재기록(새 키로) → 옛 키 제거. 무중단. 런북에 절차가 있다.</details>
9. <details><summary>왜 AES-CBC가 upstream에서 "Weak"인가 — 구체적 공격은? (kubernetes#73514)</summary>CBC는 기밀성만 주고 *무결성*이 없다(AEAD가 아님). 즉 ciphertext 변조를 탐지 못 한다. 고전적 위협은 **패딩-오라클**: 복호 측이 PKCS#7 패딩 오류를 (에러/타이밍으로) 흘리면, 공격자가 ciphertext를 한 바이트씩 조작해 평문을 복원하거나 위조할 수 있다. etcd 디스크에 쓰기 가능한 공격자(노드 침해/백업 변조)면 Secret을 조용히 바꿔치기할 수 있다는 뜻. `aesgcm`/`secretbox`는 AEAD라 인증 태그 불일치 시 복호 자체를 거부 → 변조 무력화. 그래서 컴플라이언스 등급 주장엔 GCM/secretbox/KMS를 쓰고, 이 데모의 CBC는 *2-키 회전 절차를 보이기 위한* 선택임을 README가 명시한다.</details>
10. <details><summary>회전 시 왜 새 키를 반드시 *첫 줄*(1순위)에 넣어야 하나? 순서를 바꾸면?</summary>읽기는 프리픽스 매칭이라 두 키가 다 있으면 옛 데이터도 새 데이터도 읽힌다 — 순서 무관. 하지만 *쓰기*는 항상 첫 provider로 한다. 새 키를 1순위로 두어야 재암호화(`replace`)가 새 키로 다시 쓴다. 옛 키를 1순위로 두면 재암호화가 옛 키로 다시 써서 회전이 진전되지 않는다. 더 나쁜 사고: 옛 키를 *지우면서* 새 키로 재암호화를 안 하면, 옛 키로 암호화된 Secret을 복호할 provider가 사라져 **그 Secret이 영구히 읽기 불가**가 된다(런북이 "반드시 2-키 과도기"라고 못 박는 이유).</details>
11. <details><summary>KMS 봉투암호화는 왜 회전 시 전체 재암호화가 불필요한가?</summary>봉투 구조: 각 Secret은 로컬 DEK(data key)로 암호화되고, 그 DEK만 KMS의 KEK로 감싼다(wrap). KMS 키 회전(`aws kms enable-key-rotation`)은 KEK의 *백킹 키*만 바꾸며, 옛 백킹 키는 복호용으로 KMS 안에 남는다. DEK는 그대로라 etcd의 ciphertext를 건드릴 필요가 없다. k8s aescbc는 봉투가 아니라 키로 직접 암호화하므로 키를 바꾸면 데이터를 다시 써야 한다 — 이게 런북 A(전체 replace)와 EKS 변형(재암호화 불필요)의 차이다.</details>

## Step 3 — 세 상태 종합

12. <details><summary>데이터의 세 상태와 이 스택의 통제를 매핑하면?</summary>전송 중=WireGuard(ET1 검증+ET2 캡처), 저장=etcd AES-CBC(ER1), 사용 중(in-use)=이 데모 범위 밖(필드암호화/토큰화/기밀컴퓨팅은 docs에 언급만). 정직하게 "사용 중은 안 했다"고 말하는 게 포인트.</details>

## Step 4 — 망가뜨리고 고치기 (predict → break → confirm)

각 통제가 *무엇 때문에* 통과하는지 손으로 확인한다.

**M1. ET1 채점을 노드분산으로 무너뜨린다.**
- 예측: `grade.sh`의 ET1은 "WireGuard 활성"이 아니라 "api/db가 *다른* 노드"도 함께 단언한다.
  api/db를 같은 노드에 몰면 WireGuard가 켜져 있어도 ET1은 FAIL이어야 한다(선을 안 넘으니).
- 망가뜨리기: `k8s/app.yaml`의 db `podAntiAffinity`를 임시로 제거(또는 약화)하고 db를 api 노드로
  몰아 재배포 → `bash labs/m5/grade.sh`.
- 확인: 출력의 `api node=`/`db node=`가 같아지고 `WireGuard/노드분산  FAIL`. 동시에
  `capture-wg.sh`는 `skip "api and db are co-located ... no cross-node wire hop"`로 빠진다 —
  잡을 선상 홉이 없으므로 거짓 PASS를 만들지 않는다. 되돌리면 다시 PASS. 교훈: "기능 켜짐"과
  "이 앱 홉이 선상에서 암호화됨"은 다른 주장이고, 채점기는 후자를 본다.

**M2. `identity`를 첫 줄로 옮겨 저장암호화를 무력화한다.**
- 예측: provider 순서에서 쓰기는 항상 첫 provider. `identity`를 1순위로 두면 새 Secret이 평문으로
  쓰여 `Test-AtRest`가 FAIL이어야 한다(프리픽스가 `k8s:enc:aescbc`가 아니라 평문).
- 망가뜨리기: 회전 흉내로 `terraform/.enc/enc.yaml`을 손으로 편집해 `- identity: {}`를 `aescbc`
  *위*로 올리고 노드에 push + apiserver 재기동, 그다음 새 Secret 생성 → raw etcd 조회.
- 확인: etcd 값에 카드번호 `4111...`이 그대로 보이고 `k8s:enc:aescbc` 프리픽스가 없다. 즉
  EncryptionConfiguration이 *존재*해도 순서가 틀리면 보호가 0이다. 고치기: `aescbc`를 다시 첫 줄로,
  `identity`를 마지막으로. (이래서 README가 `identity` last를 강조한다.)

**M3. etcd를 직접 들여다본다 — 켜기 *전*에 Secret이 평문임을 네 눈으로 본다(가장 안전한 관찰).**
> M1·M2는 통제를 *깨서* 본다. M3은 아무것도 안 깬다 — 암호화를 켜기 *전* etcd 바이트를 직접 읽고,
> Step 2로 켠 *뒤* 같은 조회와 비교한다. 읽기 전용 + 던져버릴 데모 Secret이라 클러스터를 안 건드린다.
> **순서 주의:** 이건 Step 2(암호화 켜기) *앞에서* 돌려야 "전" 상태가 나온다. 이미 켰다면 스크립트가
> 멱등으로 빠져나가고(키 재생성 안 함) 이 관찰은 곧장 "후" 상태를 보여준다.
- 예측: 기본 Kubernetes Secret은 etcd에 *암호화 없이* 저장된다. `kubectl get -o yaml`로 보면 값이
  base64로 보이지만 그건 인코딩일 뿐 — etcd 안의 원시 바이트에는 카드번호 `4111...`이 **평문 ASCII**로
  들어 있다. 그래서 켜기 전 raw etcd 값을 `grep 4111`하면 *맞고*, `k8s:enc:` 프리픽스는 없을 것이다.
- 깨기/관찰: `enable-secrets-encryption.sh`를 *돌리기 전에* 데모 Secret을 하나 만들고 raw etcd에서
  읽어라(스크립트가 PASS 증명에 쓰는 것과 동일한 etcdctl 경로 — `grep -a`로 바이너리 값을 텍스트 취급).
  Git Bash에서:
  ```bash
  export MSYS_NO_PATHCONV=1            # MSYS 경로변환이 /registry/...를 망가뜨린다(스크립트도 동일)
  kubectl -n default create secret generic before-proof --from-literal=card=4111111111111111
  ETCD=etcd-cloudsec-control-plane
  ETCDCTL="etcdctl --endpoints=https://127.0.0.1:2379 \
    --cacert /etc/kubernetes/pki/etcd/ca.crt --cert /etc/kubernetes/pki/etcd/server.crt \
    --key /etc/kubernetes/pki/etcd/server.key get /registry/secrets/default/before-proof"
  kubectl -n kube-system exec $ETCD -- $ETCDCTL 2>/dev/null | grep -a 4111   # ← 카드번호 평문 노출
  kubectl -n default delete secret before-proof   # 던져버린다(멱등)
  ```
- 확인: `grep 4111`이 *맞는다* — etcd 디스크에 카드번호가 평문으로 누워 있다. 이제 Step 2의
  `bash scripts/enable-secrets-encryption.sh`를 돌리면 스크립트의 끝 증명이 같은 etcd 조회로 `4111`을
  *못 찾고* `k8s:enc:aescbc` 프리픽스만 본다(스크립트의 `enc=1 && leak=0`). 같은 명령, 켜기 전엔
  누출·후엔 암호문 — 이 한 줄 차이가 "저장 암호화"의 전부다. 되돌릴 것 없음: `before-proof`는 이미
  지웠고, 암호화 켜기는 apiserver 매니페스트를 `.bak`으로 백업해 둬 되돌릴 수 있다(스크립트 주석).
- 안전 메모: 이건 *읽기 전용 관찰*이다 — 실 Secret을 건드리지 않고, 데모 Secret만 만들고 지운다.
  apiserver를 재기동하지 않는다(M2와 달리). 그래서 셋 중 가장 안전한 break-and-fix다.

## 졸업 기준

- [ ] `grade.sh` **ET1 PASS**
- [ ] `capture-wg.sh`를 돌리고 Step 1의 질문 3개(eth0 이유, 평문0의 한계, 트래픽 게이트)를 답했다
- [ ] `enable-secrets-encryption.sh`를 돌리고 etcd 암호문 관찰 + KMS 차이를 설명했다
- [ ] Step 4 M3: 켜기 *전* raw etcd에서 `grep 4111`이 맞고, 켜기 *후* 같은 조회가 `k8s:enc:aescbc`만 보임을 직접 봤다
- [ ] 세 데이터 상태와 통제(+ 안 한 것)를 매핑할 수 있다

---

## 더 파기 (1차 출처)

- **etcd 암호화 (공식):** Kubernetes — [Encrypting Confidential Data at Rest](https://kubernetes.io/docs/tasks/administration-cluster/encrypt-data/). aescbc/aesgcm/secretbox/kms provider 표·순서 규칙·회전 절차의 출처.
- **aescbc "Weak" 분류:** [kubernetes/kubernetes#73514](https://github.com/kubernetes/kubernetes/issues/73514) — AEAD 부재/패딩-오라클 우려로 CBC를 비권장하는 논의(README의 정직 메모 근거).
- **KMS 봉투암호화:** Kubernetes — [Using a KMS provider for data encryption](https://kubernetes.io/docs/tasks/administration-cluster/kms-provider/). DEK/KEK 봉투 구조와 KMS v2.
- **WireGuard (Cilium):** [Cilium docs — WireGuard Transparent Encryption](https://docs.cilium.io/en/stable/security/network/encryption-wireguard/). 노드 간 파드 트래픽만 암호화된다는 문서화된 동작.
- **표준 절(이 랩이 매핑하는):** GDPR 제32조(전송·저장 암호화), PCI-DSS v4.0 req 3(저장)·req 4(전송), ISMS-P 2.7(암호화). NIST SP 800-57(키 관리)·SP 800-38D(GCM/AEAD).

---

**트랙 완주 후:** 이제 `scripts\down.ps1`로 클러스터를 내려라(RAM). 그리고 **M0–M6를 전부 졸업한 당신**은
이 스택의 모든 통제를 *직접 재구현하고 검증할 수 있는* 상태다 — 면접에서 "왜?"에 답할 준비가 됐다.
