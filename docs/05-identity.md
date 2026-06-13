# Lab 4 — 신원: 누가 `web`이나 `api`가 *될* 수 있나 (B7)

!!! tip "직접 해보기 (재구현 트랙)"
    라벨↔SA admission CEL을 직접 작성하라 → **[M2 · 신원 admission](../labs/m2/README.md)** (5/5, 클러스터 필요).

**목표:** 지금까지의 모든 계층은 파드의 `app` 라벨을 신뢰한다 — Cilium은 거기서 네트워크 신원을
도출한다. 그래서 스택 전체가 조용히 한 질문에 의존한다: *누가 `app: api`를 주장하는 파드를 만들 수
있나?* 이 랩은 그 의존성을 명시적으로 드러내고 단단히 한다. policy-as-code 포트폴리오에서 리뷰어가
가장 흔히 찾는 갭이다.

**필요:** [Lab 2](03-network-and-authz.md)의 클러스터(`up.sh`가 신원 매니페스트를 적용함).
배경: [THREAT_MODEL.md](../THREAT_MODEL.md) §B7.

## 한 문장으로 본 문제

`CiliumNetworkPolicy`는 "`app: web`에서 온 트래픽은 `api`에 닿을 수 있다"고 말한다. 그건
*누가 `app: web` 라벨 파드를 만들 수 있나*의 답만큼만 신뢰할 수 있다. `shop`에 워크로드를 만들
RBAC을 가진 사람이라면 누구나 Cilium에게 **`web`(또는 `api`)인** 파드를 찍어낼 수 있고 —
네트워크 정책을 그대로 통과해 Cedar까지 우회한다.

## 통제 1 — 최소권한 ServiceAccount (폭발 반경)

각 티어는 **RoleBinding이 전혀 없는** 자기 SA로 돈다:

```bash
kubectl auth can-i create pods   --as=system:serviceaccount:shop:api-sa -n shop   # no
kubectl auth can-i get secrets   --as=system:serviceaccount:shop:api-sa -n shop   # no
kubectl auth can-i --list        --as=system:serviceaccount:shop:api-sa -n shop   # 공개 베이스라인만
```

토큰이 마운트되지 않더라도(`automountServiceAccountToken: false`), *설령 마운트됐대도* 털린
`api` 파드는 Kubernetes API 권한이 **0**이다. 그게 방어심층의 요점이다: 침해된 워크로드가
클러스터에 할 수 있는 일을 최소화한다.

## 통제 2 — admission에서 라벨↔SA 일관성 (망가뜨려 보기)

`k8s/admission-policy.yaml`은 `ValidatingAdmissionPolicy`(내장, k8s ≥1.30에서 GA)로,
`app: web|api|db`를 주장하면서 라벨이 자기 ServiceAccount와 어긋나는 파드를 거부한다.
가장 단순한 위조를 시도해 보라 — 서버 dry-run은 아무것도 만들지 않고 admission만 돌린다:

```bash
cat <<'YAML' | kubectl create --dry-run=server -f -
apiVersion: v1
kind: Pod
metadata: { name: forge, namespace: shop, labels: { app: api } }
spec:
  serviceAccountName: web-sa            # claims api, runs as web -> mismatch
  automountServiceAccountToken: false
  securityContext: { runAsNonRoot: true, runAsUser: 100, seccompProfile: { type: RuntimeDefault } }
  containers:
    - name: c
      image: curlimages/curl:8.11.1
      command: ["sleep","1"]
      securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } }
      resources: { requests: { cpu: "5m", memory: "8Mi" }, limits: { cpu: "50m", memory: "32Mi" } }
YAML
```

기대 결과 — 영속되기 전에 거부:

```
... pod label app=api must run as ServiceAccount api-sa (got web-sa);
    forged network identity denied — see THREAT_MODEL.md B7
```

이게 쉬운 공격을 죽인다: `kubectl run --labels app=api ...`는 `default` SA로 기본 설정되므로
라벨≠SA → 거부.

## 정직한 부분 — 통제 2가 *닫지 못하는* 것

이제 위에서 `web-sa`를 `api-sa`로 바꿔 다시 돌려 보라. **admit된다.** 통제 2는 라벨↔SA의
*일관성*만 강제한다 — 자기일관 파드(`app: api` + `api-sa`)는 완전히 유효한 `api`다. 그리고 현대
Kubernetes에는 `serviceaccounts/use` 게이트가 없으므로(PodSecurityPolicy는 1.25에서 제거됨),
`shop`에 Deployment를 만들 수 있는 사람이라면 누구나 `serviceAccountName: api-sa`를 고를 수
있다. 그래서 통제 2는 신원 경계가 아니라 *일관성 가드*다 — 그 경계는 통제 3이다.

## 통제 3 — SA-use 게이트 (누가 티어 신원으로 *실행*할 수 있나)

`k8s/admission-sa-use.yaml`은 빠진 `serviceaccounts/use` 검사를 워크로드 레벨에서 추가한다.
`request.userInfo`를 읽어, `web-sa`/`api-sa`/`db-sa`로 도는 워크로드를 **오직** kube-system
워크로드 컨트롤러(`system:serviceaccount:kube-system:*`), 클러스터 관리자(`system:masters` /
`kubeadm:cluster-admins`), 또는 `shop:tier-operators` 그룹에 한해 admit한다 — 넓은 `system:*`은
**아니다**(그건 CI/앱 SA까지 매칭돼 우회가 된다). 제한된 deploy 역할로 시도해 보라
(impersonation; 이 그룹은 `create deployments`는 있으나 티어 operator는 아니다):

```bash
cat <<'YAML' | kubectl --as=ci-deployer --as-group=shop:deployers create --dry-run=server -f -
apiVersion: apps/v1
kind: Deployment
metadata: { name: probe, namespace: shop, labels: { app: api } }
spec:
  replicas: 1
  selector: { matchLabels: { app: api } }
  template:
    metadata: { labels: { app: api } }
    spec:
      serviceAccountName: api-sa            # run as the api tier identity
      containers: [{ name: c, image: curlimages/curl:8.11.1, command: ["sleep","1"],
        securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true,
        runAsNonRoot: true, runAsUser: 100, capabilities: { drop: ["ALL"] },
        seccompProfile: { type: RuntimeDefault } } }]
YAML
```

기대 결과 — 거부:

```
... running a workload as tier ServiceAccount 'api-sa' requires an authorized
    operator ...; requester 'ci-deployer' is not — see THREAT_MODEL.md B7 (SA-use gate)
```

`--as` 플래그를 빼면(관리자로 실행) **같은** 워크로드가 admit된다 — 정당한 롤아웃은 영향이 없고,
실제 앱의 컨트롤러-생성 파드(`system:serviceaccount:kube-system:*` 컨트롤러가 만듦)도 마찬가지다.
그래서 티어 신원의 *사용*은 이제 누구나 배포할 수 있는 게 아니라, 이름이 붙은 최소 집합의
요청자에게 묶인다. `verify` 스크립트가 거부와 admit 둘 다 단언한다.

## 통제 4 — 암호 신원 (mutual auth / SPIFFE)

`terraform/main.tf`는 Cilium mutual authentication을 켜고(클러스터 내 SPIRE가 각 워크로드에
ServiceAccount에서 파생한 SPIFFE SVID를 발급), `k8s/netpol-mutual.yaml`은 `web→api` 엣지를
그것을 요구하도록 올린다:

```bash
kubectl apply -f k8s/netpol-mutual.yaml
# SPIRE가 먼저 떠 있어야 한다:
kubectl -n cilium-spire rollout status statefulset/spire-server
# web->api는 여전히 동작한다 — SVID 핸드셰이크가 투명하게 완료된다:
WEB=$(kubectl -n shop get pod -l app=web -o jsonpath='{.items[0].metadata.name}')
API=$(kubectl -n shop get pod -l app=api -o jsonpath='{.items[0].status.podIP}')
kubectl -n shop exec "$WEB" -- curl -s -o /dev/null -w '%{http_code}\n' -H 'X-User: alice' "http://$API:8080/accounts/acct-alice"   # 200
```

이제 위조된 *라벨*은 필요조건이지 충분조건이 아니다: 피어는 유효한 SVID도 제시해야 하고,
그건 SA의 암호 신원 없이는 찍어낼 수 없다. 전체 체인은 이제: **누가 배포할 수 있나**(RBAC) →
**라벨이 SA와 일치**(통제 2) → **누가 티어 SA로 실행할 수 있나**(통제 3) → **SVID를 보유해야
함**(통제 4). 남는 것은 위협모델에 정직하게 명시돼 있다 — SA-use 게이트는 admission 계층과
이름 붙은 operator들을 신뢰하고, 매칭 집합 밖의 리소스 종류(이 게이트는 `shop`의
Pod/Deployment/RS/STS/DS/Job/CronJob을 커버한다; 다른 네임스페이스나 미래의 API 종류)는 같은
한 규칙을 확장하면 된다.

## 캡스톤 (opt-in) — SA-use 게이트, Kyverno로 클러스터 전역

위 VAP는 `shop`에 손으로 고정돼 있다. 같은 규칙을 **한 번, 일반적으로, 클러스터 전역으로**
표현한 것이 Kyverno `ClusterPolicy`(`k8s/kyverno-sa-use.yaml`)다: 제외된 네임스페이스
(`kube-system`, `kyverno`, 그리고 `shop` — VAP가 이미 `shop`을 담당)를 뺀 모든 네임스페이스의
Pod/Deployment/RS/STS/DS/Job/CronJob에 대한 한 규칙. 정확히 같은 인가 술어를 재현한다
(`request.userInfo`를 읽으므로 `background: false`).

```bash
scripts/enable-kyverno.sh     # helm install (dev-sized) + ClusterPolicy 적용
scripts/verify-kyverno.sh     # 두 번째 네임스페이스(shop 아님)에서 DENY/ADMIT를 증명
```

**정직한 범위 (두 부분):** (1) Kyverno의 실제 차별점은 *네임스페이스 일반성*과 *종류별 CEL 대신
한 규칙*이다 — 구조적 한계를 없애는 건 **아니다**: 컨트롤러가 만든 Pod는 `userInfo`에 *컨트롤러의*
SA를 담으므로, (VAP와 똑같이) 게이트는 워크로드 **컨트롤러**를 매칭하지 컨트롤러가 띄운 Pod를
매칭하지 않고, 인가된 operator/클러스터-관리자는 설계상 신뢰된다. (2) 이건 **opt-in 캡스톤**이다
(추가 컨트롤러 = Cilium+Tetragon+SPIRE 위에 실제 RAM), `scripts/enable-kyverno`로 켠다; 이제
**실제로 띄워 라이브로 증명**됐다 — `scripts/verify-kyverno`가 SA-use ClusterPolicy가 *두 번째*
네임스페이스에서 티어-SA 워크로드를 거부하는 걸 보이므로, 크로스-네임스페이스 커버리지 행(ID7)은
이제 **VERIFIED**(opt-in)다. 현대적 등가물은 새 Kyverno `ValidatingPolicy` / 네이티브 VAP의
클러스터 전역 적용 — 이건 정직한 세 가지 방법 중 하나다.

## 내 것으로 만들기

`verify` 스크립트가 이 전부를 단언한다: `api-sa`는 API 권한이 없고, 불일치 워크로드는 거부되며,
제한된 `shop:deployers` principal은 `api-sa`로 워크로드를 실행하는 게 거부되고, 인가된 operator가
같은 워크로드를 배포하면 admit된다. 네 번째 티어(`app: cache` + `cache-sa`)를 `k8s/rbac.yaml`과
두 admission 정책에 추가해 보고, 잘못된 SA의 `cache` 라벨 파드가 거부되는 걸 지켜보라.

---

신원은 나머지 여섯이 의존하는 계층이다. 다음: 그 신원들이 닿는 **데이터**를 보호하기 —
[Lab 5: 데이터 보호](06-data-protection.md). [학습 경로](README.md)로 돌아가기.
