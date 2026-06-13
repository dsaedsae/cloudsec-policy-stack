# M5 — 데이터 보호: 암호화 실행·해석 (전송 + 저장)

[모듈 6 / 7]{ .lab-progress } · [스택 WireGuard+etcd]{ .lab-badge } · [소요 ~30–45m]{ .lab-badge } · [클러스터 필요 · RAM ~6–8GB]{ .lab-badge .cluster } · [비용 $0 로컬]{ .lab-badge }

**미션:** 데이터의 세 상태 중 **전송 중(in-transit)**과 **저장(at-rest)** 암호화를 *직접 실행*하고
그 증거를 *해석*한다. 이 모듈은 정책을 새로 짜는 게 아니라(암호화는 설정 플래그) — **무엇이 어떻게
증명되는지**를 손으로 확인하는 것이 핵심이다.

> 🎯 **학습 성과 (면접에서 말할 수 있는 것):** 전송(WireGuard)·저장(etcd) 암호화를 직접 실행하고 증거를 해석하며, *평문0은 보강 증거지 결정적 증명이 아니다*(결정적 증거는 WG패킷+노드분산)를 설명할 수 있다. → [캡스톤 M5](../capstone.md)

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

이건 db 노드의 host netns(파드가 아니라 — PSA 제약 회피)에서 `tcpdump`로 잡는다. **해석 질문:**

1. <details><summary>왜 cilium_wg0가 아니라 eth0에서 잡나?</summary>cilium_wg0는 터널의 *복호화된* 쪽(평문 파드 트래픽). 물리 iface eth0가 노드 간 *암호문*(UDP/51871 WireGuard)이 흐르는 곳. 암호문을 보려면 eth0.</details>
2. <details><summary>"평문 0"이 곧 "암호화됨"의 *결정적* 증거인가? 정직하게.</summary>아니다 — *보강* 증거다. 크로스노드 파드 트래픽은 캡슐화되므로 평문 tcp/8080은 암호화 여부와 무관하게 eth0에 안 나타날 수 있다. *결정적* 증거는 WG 패킷(UDP/51871) 존재 + 노드 분산. 스크립트가 이 한계를 정직하게 출력한다(이 repo가 적대적 검증에서 스스로 잡아 고친 부분).</details>
3. <details><summary>왜 트래픽 흐름 게이트(REQOK>=1)가 필요한가?</summary>트래픽이 0이면 "평문 0"은 공허하다(아무것도 안 흘렀으니). 실제 요청이 성공해야 "암호문은 보이고 평문은 안 보인다"가 의미를 가진다.</details>

## Step 2 — 저장 암호화: etcd (ER1)

```bash
bash scripts/enable-secrets-encryption.sh
```

이건 apiserver에 AES-CBC `EncryptionConfiguration`을 켜고, Secret을 원시 etcd에서 직접 읽어 증명한다.
**해석 질문:**

4. <details><summary>증명의 핵심 관찰은 무엇인가?</summary>etcd에 저장된 Secret 값이 `k8s:enc:aescbc:v1:`로 시작하고 평문이 없다. kubectl로 보면 복호화돼 보이지만, *디스크(etcd)*엔 암호문으로 있다 — 백업 유출/디스크 탈취 시 방어.</details>
5. <details><summary>이 데모의 AES 키와 실무 KMS 봉투암호화의 차이는?</summary>여기선 로컬 생성 AES 키(파일, gitignore). 실무는 KMS/HSM가 키를 관리(봉투암호화) — 키 자체가 디스크에 평문으로 안 남는다. AWS 경로는 EKS+KMS(docs/aws-eks-path.md).</details>
6. <details><summary>키 회전은 어떻게? (runbooks/02-key-rotation.md)</summary>2-키 흐름: 새 키를 1순위로 추가 → 모든 Secret 재기록(새 키로) → 옛 키 제거. 무중단. 런북에 절차가 있다.</details>

## Step 3 — 세 상태 종합

7. <details><summary>데이터의 세 상태와 이 스택의 통제를 매핑하면?</summary>전송 중=WireGuard(ET1 검증+ET2 캡처), 저장=etcd AES-CBC(ER1), 사용 중(in-use)=이 데모 범위 밖(필드암호화/토큰화/기밀컴퓨팅은 docs에 언급만). 정직하게 "사용 중은 안 했다"고 말하는 게 포인트.</details>

## 졸업 기준

- [ ] `grade.sh` **ET1 PASS**
- [ ] `capture-wg.sh`를 돌리고 Step 1의 질문 3개(eth0 이유, 평문0의 한계, 트래픽 게이트)를 답했다
- [ ] `enable-secrets-encryption.sh`를 돌리고 etcd 암호문 관찰 + KMS 차이를 설명했다
- [ ] 세 데이터 상태와 통제(+ 안 한 것)를 매핑할 수 있다

---

**트랙 완주 후:** 이제 `scripts\down.ps1`로 클러스터를 내려라(RAM). 그리고 **M0–M6를 전부 졸업한 당신**은
이 스택의 모든 통제를 *직접 재구현하고 검증할 수 있는* 상태다 — 면접에서 "왜?"에 답할 준비가 됐다.
