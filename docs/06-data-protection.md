# Lab 5 — 데이터 보호: 데이터의 세 상태

> **직접 해보기 (재구현 트랙):** 암호화 증거를 직접 실행·해석하라 → **[M5 · 암호화](../labs/m5/README.md)** (ET1 채점, 클러스터 필요).

**목표:** B1–B7은 *누가 무엇에 닿거나 무엇을 할 수 있나*를 다스린다. 데이터 **자체**에 대해선
아무 말도 안 한다. 완전한 태세는 데이터의 세 상태 — **전송 중(in transit)**·**저장(at rest)**·
**사용 중(in use)** — 도 보호한다. 누군가 백업을 읽거나, 선을 도청하거나, 카드번호를 과도하게
로깅하는 순간 접근통제는 fail-open이기 때문이다. 이것이 GDPR 제32조 / PCI-DSS / ISMS-P의
"데이터를 보호하라" 절반의 이야기다.

**필요:** [Lab 2](03-network-and-authz.md)의 클러스터.

> **정직한 범위부터.** 여기엔 실제 데이터스토어가 없다 — `db` 티어는 nginx 자리표시자이고
> PDP의 엔티티는 정적 픽스처다. 그래서 이 랩은 각 데이터 상태에 매핑된 **통제**를 보이는 것이지
> 프로덕션 데이터 생애주기가 아니다. 전송 중은 라이브로 검증되고, 저장은 실행 가능한 스크립트,
> 사용 중은 PDP의 설계 속성이다. 갖지 않은 데이터를 보호한다고 주장하는 건 여기 하나도 없다.

## 전송 중 — WireGuard 투명 암호화 (크로스노드, 라이브 검증)

Cilium은 `encryption.enabled=true, encryption.type=wireguard`(`terraform/main.tf`)로 설치돼,
**노드 간(node-to-node)** 파드 트래픽이 WireGuard로 암호화된다 — *노드 사이*의 on-path 공격자는
`X-User` 헤더나 계좌 데이터가 아니라 암호문을 본다.

클러스터는 **워커 2대**를 돌리고, `k8s/app.yaml`이 `db`를 `api`의 노드에서 **떼어** 배치하므로
(`podAntiAffinity`), `api→db` 홉은 **선을 건너고** 따라서 WireGuard로 암호화된다. `verify` 검사는
두 조건 — WireGuard 활성 AND `api`/`db`가 다른 노드 — 을 모두 단언하므로, 단지 기능이 켜졌다는
게 아니라 *이 앱 홉이 선상에서 암호화됨*을 증명한다.

상시 `verify` 행이 노드 배치 + `encrypt status`로 이를 증명한다(Cilium의 문서화된 동작에서 따라옴:
모든 크로스노드 파드 트래픽이 암호화됨):

```bash
kubectl -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg encrypt status
# Encryption: Wireguard
# Encrypted endpoints / keys in use: ...
```

**패킷 캡처 증명(opt-in 증거 — `scripts/capture-wg.sh`).** 더 강한 주장을 위해, db 노드의 호스트
netns에서 `tcpdump` 캡처(`docker exec`로 — PSA 제한 privileged-pod 함정 회피)를 실제 api→db 트래픽으로
구동하면 그 윈도우 동안: 두 노드 간 **WireGuard 패킷 40개(UDP/51871)**(암호문 존재) + **평문 0바이트**
(`eth0`의 `tcp/8080`에 `X-User`/`HTTP/1` 없음)를 보였다. **결정적** 증거는 WireGuard 패킷 + 크로스노드
배치이고, 평문 부재는 **보강**이다 — 크로스노드 파드 트래픽은 *캡슐화*되므로 평문은 캡슐화 하에서도
`eth0`에 `tcp/8080`으로 나타나지 않으며, 스크립트도 그렇게 말한다. 이로써 ET2가 CONFIGURED에서
**VERIFIED**(게이트된 증거로서)로 올라간다. `tcpdump`가 없거나 트래픽이 흐르지 않으면 스크립트는
정직하게 SKIP한다 — "평문 없음"을 공허하게 단언하지 않는다.

> 커밋된 증거([`docs/assets/evidence/wg-capture-summary.txt`](assets/evidence/wg-capture-summary.txt))는
> *원래* 실행분이다(`-c 40` 상한이라 40은 캡처 상한이지 측정된 총량이 아니다). 현재 스크립트는 상한을
> 제거하고 트래픽-흐름 게이트를 추가했다; 라이브 크로스노드 클러스터에서 다시 돌리면 측정된 요약을
> 재생성한다. 그래서 이것은 증거이지 상시 21개 검사 중 하나가 아니다.

```bash
bash scripts/capture-wg.sh      # -> docs/assets/evidence/wg-capture-summary.txt
```

> **정직한 caveat:** 이것은 패킷이 WireGuard 터널 위에 있고 선상에 평문이 없음을 증명할 뿐 —
> WireGuard의 *암호 강도*도, 같은-노드 홉이 암호화됨도 아니다(아니다 — 크로스노드만).

`scripts/verify.sh`가 상시 행을 단언하고, `capture-wg.sh`는 캡처-증거 업그레이드다. **PCI-DSS req 4 /
GDPR 제32조** "전송 중 개인정보 암호화"에 매핑된다.

## 저장 — etcd Secret 암호화 (실행 가능한 증명)

기본적으로 Kubernetes Secret은 etcd에 **base64**일 뿐이다 — 데이터스토어·디스크 이미지·백업을 읽으면
모든 시크릿을 평문으로 읽는다. 기본 갭을 증명한 뒤, 닫는다:

```bash
# Before: a Secret's value is plainly readable in etcd
kubectl -n default create secret generic demo --from-literal=card=4111111111111111
docker exec cloudsec-control-plane sh -c \
  "ETCDCTL_API=3 etcdctl --cacert /etc/kubernetes/pki/etcd/ca.crt \
   --cert /etc/kubernetes/pki/etcd/server.crt --key /etc/kubernetes/pki/etcd/server.key \
   get /registry/secrets/default/demo | strings" | grep 4111   # the card number is right there

# Enable AES-CBC encryption-at-rest and re-prove:
pwsh scripts/enable-secrets-encryption.ps1   # or: bash scripts/enable-secrets-encryption.sh
```

스크립트는 새 32바이트 AES 키를 생성하고(절대 커밋 안 함 — `terraform/.enc/`는 gitignore),
`EncryptionConfiguration`(`k8s/encryption-config.yaml`)과 apiserver 플래그를 `docker cp`로 control-plane
노드에 밀어넣고(호스트 마운트 없음 → OS 독립적), apiserver 매니페스트를 먼저 백업하고(되돌리기 가능),
그다음 raw etcd를 읽어 결과를 **증명**한다:

```
== etcd raw bytes for secret/atrest-proof ==
k8s:enc:aescbc:v1:key1: <ciphertext>     # no plaintext card number anywhere
PASS: Secret is AES-CBC encrypted at rest in etcd.
```

**GDPR 제32조 / PCI-DSS req 3 / ISMS-P 2.7** "저장 데이터 암호화"에 매핑된다.

> ⚠️ 정직 메모(암호 선택): 데모는 **aescbc**를 쓰는데 upstream Kubernetes는 이를 **Weak**로 분류한다(AEAD/무결성
> 없음, 패딩-오라클 우려 — kubernetes#73514). 컴플라이언스 등급 주장에는 **aesgcm/secretbox**(또는 KMS 봉투암호화)
> 가 적절하다. 여기 aescbc는 2-키 회전 런북([runbooks/02](https://github.com/dsaedsae/cloudsec-policy-stack/blob/main/runbooks/02-key-rotation.md))을 보이기 위한 선택이며, 실 적용 시 cipher는 aesgcm/KMS로.

## 사용 중 — 설계에 의한 데이터 최소화

데이터를 *처리하는 동안* 보호하는 것은 대개 애초에 노출하지 않는 데서 온다. Cedar PDP
(`app/api/main.py`)는 이미 이를 실천한다:

- **Principal은 charset 검증**을 거친 뒤에야 Cedar에 닿는다 — 조작된 `X-User`는 엔티티 UID나
  로그에 인젝션할 수 없다(로그-인젝션 가드).
- **민감 페이로드는 로깅하지 않는다.** PDP는 잔액이 아니라 결정을 반환하고, `X-User` 값이나 계좌
  내용을 stdout에 절대 찍지 않는다.
- **Fail-closed 평가** — 어떤 Cedar 에러든 거부하므로, 잘못된 요청이 서비스를 꾀어 내주면 안 될
  데이터를 반환하게 만들 수 없다.

실제 시스템이라면 여기에 필드 수준 암호화, PAN 토큰화, 보존/삭제 정책(잊힐 권리)을 더할 것이다.
여기선 적용할 실제 데이터가 없기에 정확히 그 이유로 범위 밖이라 명시한다.

## 한 그림

```
data in transit  ── WireGuard (Cilium)        ── verified live  ── PCI req4 / GDPR Art.32
data at rest      ── EncryptionConfiguration   ── runnable proof ── PCI req3 / GDPR Art.32 / ISMS-P 2.7
data in use       ── PDP minimization + fail-closed ── design     ── least data exposed
```

---

이것으로 스택은 **접근통제**(누가 행위할 수 있나)에서 **데이터 보호**(접근통제가 우회돼도 데이터
자체가 보호됨)까지 한 바퀴를 돈다. [학습 경로](README.md)로 돌아가기.
