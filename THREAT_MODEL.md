# 위협 모델 (Threat model)

방어심층(defense-in-depth) 스택은 각 계층 아래 깔린 *가정*만큼만 정직하다. 이 문서는 각
통제가 *무엇을* 보호하고, *무엇을* 보호하지 않으며 — 가장 중요하게는 — **계층들 자신이
무엇을 신뢰하는지**를 밝힌다. Cilium + Cedar 설계에서 흥미로운 갭은 신원(identity)이다:
누가 `web` 또는 `api`가 *될* 수 있는가.

## 분석 대상 시스템

```
client ──▶ web (frontend) ──▶ api (backend, Cedar PDP) ──▶ db (data)
            CiliumNetworkPolicy가 화살표를 시행; Cedar가 api 내부에서 인가;
            Tetragon이 모든 exec를 감시; checkov가 CI에서 매니페스트를 게이트.
```

- **Namespace** `shop`, Pod Security Admission `restricted`.
- **네트워크 신원(network identity)**은 Cilium이 **pod 라벨**(`app: web|api|db`)에서 도출한다.
- **애플리케이션 신원**(`X-User`)은 Cedar PDP가 소비하는 HTTP 헤더다.
- 워크로드는 non-root, 모든 capability drop, read-only rootfs이며, **ServiceAccount 토큰을
  마운트하지 않는다**(`automountServiceAccountToken: false`).

## 공격자 모델 (Attacker model)

적대자를 명시한다(보안 주장은 *명시된* 공격자에 대해서만 의미가 있다). 세 가지 구체 프로필,
각각을 막는 통제 + 그것을 증명하는 `verify` 체크에 매핑:

| # | 공격자 | 능력(Capability) | 목표 | 막는 것 (verify) | 잔여(Residual) |
|---|----------|-----------|------|---------------------|----------|
| **A1** | **털린 `web` pod** | `web` 컨테이너 내 RCE(예: 웹 취약점) | `db` 도달, 유출(exfil), 비콘(beacon), 권한상승 | L3 drop `web→db`(`000`); egress default-deny → 인터넷/메타데이터/apiserver(`000`); 미마운트 SA 토큰 → 클러스터 API 불가. (주의: Tetragon의 shell-kill은 `tier: data` 대상이라, 공격자가 *거기로 피벗하면* `db`를 보호하지 — `web` 자체는 아님.) | 노드 루트 탈출(root-on-node escape); `web`의 허용된 L7 호출 범위 내에 머무는 비-셸 후속 공격 |
| **A2** | **악의적/침해된 `shop:deployers`** | `shop`에서 Deployment/Job/CronJob `create` 가능(CI 신원) | **티어 신원**(`api-sa`)으로 워크로드를 돌려 `api`가 *되기* | label↔SA admission(불일치 시 DENY); **SA-use gate**가 비-operator의 티어 SA 실행을 거부 — Deployment **및 CronJob** 경유 포함(`SA-use DENY`) | *인가된* operator(cluster-admin / `shop:tier-operators`)는 설계상 신뢰; `system:serviceaccount:kube-system:*` controller는 신뢰 |
| **A3** | **노드 간 on-path** | 노드 간 pod 트래픽 수동 캡처 | 선상에서 `X-User` / 계좌 데이터 읽기 | Cilium **WireGuard**가 크로스노드 pod 트래픽 암호화(평문 아닌 암호문) | 동일 노드 홉은 선을 안 탐; 호스트/커널 침해; mutual-auth(SVID)는 데모 엣지에서 opt-in |

**범위 밖(hand-wave가 아니라 명시):** 노드 루트/커널 침해; 악의적 cluster-admin(모든 신뢰
사슬의 최상단); digest 핀 *이전*의 업스트림 이미지 공급망 침해; 미인증 `X-User` 데모 입력(실
시스템은 검증된 JWT/SVID에서 principal 도출). 이것들이 정직한 경계다 — 각 통제는 A1–A3에 대해
*문턱을 높일* 뿐, 기반(substrate)을 소유한 공격자에 대해서는 아니다.

## 신뢰 경계 (Trust boundaries)

| # | 경계(Boundary) | 횡단(Crossing) | 통제 |
|---|----------|----------|---------|
| B1 | 인터넷 / 클러스터 엣지 → `web` | inbound 요청 | Cilium ingress(`web:8080`만 도달 가능) |
| B2 | `web` → `api` | east-west 호출 | Cilium L3 + **L7**(`GET/POST /accounts/*`만) |
| B3 | `api` 내부 | per-request 결정 | **Cedar**(owner, limit, frozen, role) |
| B4 | `api` → `db` | east-west 호출 | Cilium L3(`api`→`db:8080`만) |
| B5 | 임의 pod → 외부 | egress / exfil | Cilium egress default-deny(DNS + next-hop만) |
| B6 | 침해된 워크로드 | 후속 행위(post-exploit) | Tetragon(`db`의 shell exec SIGKILL) |
| **B7** | **K8s API → pod 신원** | **누가 pod를 create/label 하는가** | **RBAC + admission policy** ← 신원 TCB |
| **B8** | **Git repo / reconciler → 클러스터 desired-state** | **누가 머지하는가 + controller가 무엇을 apply/사칭(impersonate)할 수 있는가** | **AppProject 스코핑 + 서명 커밋 + reconciler 자신의 최소권한 RBAC** ← B7이 *이전됨*(M10) |

B1–B6은 원래의 라이브-검증 계층이다. **B7은 나머지 여섯이 모두 암묵적으로 의존하는 것**이며,
이번 라운드가 강화하는 대상이다. `scripts/verify.{sh,ps1}`는 이제 B7도 직접 시험한다: 티어
ServiceAccount는 K8s API 권한이 0; *불일치* 워크로드(`web-sa`에 `app: api`)는 admission에서
거부; 제한된 `shop:deployers` principal이 `api-sa`로 워크로드를 돌리려 하면 SA-use gate가
거부하고, 인가된 operator가 같은 워크로드를 배포하면 허용된다.

**B8(M10 — GitOps)은 통제를 추가하지 않는다; B7을 *이전*한다.** GitOps 하에서 "누가 `app: api`
pod를 create 하는가"는 "누가 repo에 머지하는가, 그리고 reconciler ServiceAccount가 무엇을
사칭/apply 할 수 있는가"가 된다. reconciler는 새롭게 *재중앙화된* 신원-TCB다: RBAC·NetworkPolicy·
admission policy에 apply 권한을 가진 controller는 `api`를 mint하고, 그것을 지키는 VAP를 다시
쓰고, 당신의 사고대응 `kubectl edit`를 되돌릴 수 있다 — 그래서 정확히 `shop:tier-operators`가
그랬듯 최소화되어야 한다(AppProject allowlist + 이름 붙은 non-`kube-system` reconciler SA;
`k8s/rbac.yaml`이 이미 이를 예고한다 — "이 Group을 당신의 권한 있는 GitOps controller에
매핑하라"). 그것이 *추가하는* 것은 **런타임 무결성(runtime-integrity)** 통제다 — 추적 객체의
drift가 sync 간격 내에 자동 복원됨 — [M10](labs/m10/README.md)에서 라이브로 측정. 침해된 Git
repo나 서명됐지만-악의적인 PR은 **막지 못한다**(신뢰는 코드리뷰 + 서명 커밋으로 *이동*될 뿐
생성되지 않음), 추적하지 않는 것은 되돌릴 수 없으며, ArgoCD 자체가 순-신규(net-new)
control-plane 공격 표면이다([ADR 0002](docs/decisions/0002-argocd-gitops-relocates-identity-tcb.md)).

## 신원 문제(B7) — 왜 라벨이 TCB인가

Cilium은 워크로드의 보안 신원을 그 **라벨**에서 계산한다. 정책 B2는 "`app: web`에서 온 트래픽이
`api`에 도달할 수 있다"고 말한다. 그 문장은 다음 질문의 답만큼만 신뢰할 수 있다: *누가 `app: web`
라벨을 단 pod를 create 할 수 있는가?*

> `shop`에서 pod를 `create`/`patch`(또는 pod의 라벨을 `patch`)할 RBAC을 가진 누구든 Cilium에게
> `web` 또는 `api`인 워크로드를 mint할 수 있고 — 네트워크 정책을 그대로 통과한다. 공격자가
> 그냥 `api`*로서* `db`에 말하면 Cedar PDP도 우회된다.

그래서 네트워크·authz 계층은 Kubernetes API의 인가를 자신의 trusted computing base의 일부로
상속한다. "우리는 NetworkPolicy가 있다"에서 멈추는 방어심층 서사는 불완전하다: **라벨 무결성은
네트워크 신원의 전제조건이다.** 이것이 policy-as-code 포트폴리오에서 리뷰어가 찾는 가장 흔한
단일 갭이며, 정확히 이 스택이 이제 통제를 추가하는 지점이다.

### 이 repo의 완화책(Mitigations)

1. **최소권한 ServiceAccount** — `k8s/rbac.yaml`은 각 티어에 고유 SA(`web-sa`/`api-sa`/`db-sa`)를
   주되 **RoleBinding을 전혀 두지 않는다**. 그래서 토큰을 *얻은* 털린 pod(얻지 못한다 — 토큰
   미마운트)라도 Kubernetes API 권한이 **0**이다. Verify:
   `kubectl auth can-i --list --as=system:serviceaccount:shop:api-sa` → public baseline만; pod를
   create하거나 secret을 읽거나 무엇을 patch할 수 없다.

2. **admission에서의 Label↔SA *일관성*** — `k8s/admission-policy.yaml`은 **라벨이 ServiceAccount와
   불일치하는, `app: web|api|db`를 주장하는 모든 pod를 거부하는** `ValidatingAdmissionPolicy`(빌트인,
   k8s ≥1.30 GA — node 이미지가 그에 맞춰 핀됨)다. 이것은 *일관성 가드이지 봉쇄(closure)가
   아니다*: 사소한 위조(`kubectl run --labels app=api`, 기본 `default` SA로 떨어짐 → label≠SA →
   거부)를 죽이고, SPIFFE SVID(SA에서 도출)와 네트워크 라벨이 일치하도록 라벨을 SA에 정렬시킨다.
   **하지 *않는* 것:** *두* 필드를 모두 제어하는 principal이 *자기-일관(self-consistent)* 워크로드를
   mint하는 것 — `app: api` 라벨**이며** `api-sa`로 도는 pod — 은 못 막는다. 그래서 VAP는 필요한
   위생 통제이지 그 자체로 신원 경계는 아니다; 그 자기-일관 케이스가 완화책 #3이 다루는 것이다.

3. **SA-use gate — *티어 ServiceAccount의 사용*을 인가된 요청자에 묶기** — `k8s/admission-sa-use.yaml`은
   Kubernetes가 기본 제공하지 않는 체크를 보충한다. 위 자기-일관 케이스가 label↔SA 정책을
   통과하는 이유: Deployment를 만들 수 있는 누구든 `serviceAccountName: api-sa`를 설정할 수 있기
   때문이다(**`serviceaccounts/use` gate가 없음** — 그것을 가졌던 PodSecurityPolicy는 1.25에서
   제거됨). 이 `ValidatingAdmissionPolicy`는 `request.userInfo`를 읽어 `web-sa`/`api-sa`/`db-sa`로
   도는 워크로드를 **오직** 요청자가 kube-system 워크로드 controller(`system:serviceaccount:kube-system:*`),
   cluster admin(`system:masters` / `kubeadm:cluster-admins`), 또는 `shop:tier-operators` 멤버일
   때만 허용한다 — 의도적으로 넓은 `system:*`는 **아니다**(그건 CI/app SA도 매치해 우회가 됨).
   그래서 제한된 `shop:deployers` role은 여전히 배포할 수 있지만 **더 이상 티어 신원으로 워크로드를
   돌릴 수 없다** — 라이브 검증됨(`shop:deployers`를 사칭해 `api-sa`로 배포는 거부; admin이 같은
   워크로드를 배포하면 허용). **정직한 스코프:** `shop`의 Pod + apps 워크로드(Deployment/ReplicaSet/
   StatefulSet/DaemonSet) + batch Job **및 CronJob**을 커버한다(각각 자신의 template 경로로 SA
   해석); *다른 네임스페이스*는 같은 패턴을 적용하며, 완전 generic 커버리지는 정책 엔진(Kyverno/
   Gatekeeper)이 한 규칙에서 생성하는 것 — **여기선 opt-in 캡스톤으로 제공**(`k8s/kyverno-sa-use.yaml`
   + `scripts/enable-kyverno.*`/`verify-kyverno.*`)되며, 이제 **세워져 라이브 증명됨** — Kyverno SA-use
   ClusterPolicy가 *두 번째* 네임스페이스에서 생성된 티어-SA 워크로드를 거부하므로
   (`scripts/verify-kyverno`), 크로스-네임스페이스 주장(coverage ID7)은 이제 **VERIFIED**다. 일반화는
   **같은 스코핑 캐비엇**을 가짐에 유의: VAP처럼 워크로드 *controller*를 게이트하지 controller가
   spawn한 Pod가 아니다(Pod의 `userInfo`는 그 controller의 SA). 신뢰는 이제 "배포할 수 있는
   누구든"이 아니라 **명시적·최소화됨**(이름 붙은 operator)이다.

4. **암호학적 신원(mutual auth / SPIFFE)** — #1–#3은 *행정적(administrative)*이다; 가장 강한
   계층은 신원을 *암호학적*으로 만든다. Cilium **mutual authentication**이 이 repo에서 켜져 있고
   (`terraform/main.tf`: `authentication.mutual.spire.{enabled,install.enabled}=true`가 인-클러스터
   SPIRE를 세움), `k8s/netpol-mutual.yaml`이 `web→api` 엣지를 `authentication.mode: required`로
   올린다. **정직한 메커니즘(Cilium 1.16.5):** 인-클러스터 SPIRE가 각 워크로드에 그 **라벨-도출
   Cilium 보안 신원**(`spiffe://spiffe.cilium/identity/<id>`, selector `cilium:mutual-auth`)에 키된
   SVID를 발급하고, cilium-agent가 delegated identity로 가져온다 — ServiceAccount는 그 신원에 접힌
   하나의 신원-관련 라벨로만 들어간다. 그래서 mutual auth는 **라벨-only** 위조(label↔SA VAP가 이미
   대체로 한 것)는 무력화하지만 **자기-일관** 위조(`app:api` + `api-sa`)는 **닫지 못한다**: 그 pod는
   같은 Cilium 신원으로 해석되고, 같은 `api` SVID를 발급받고, 핸드셰이크를 완료한다. 자기-일관
   위조는 SVID가 아니라 **SA-use gate**(#3, 누가 티어 SA로 *돌릴 수* 있는가 — ID2, 라이브-VERIFIED)가
   닫는다. mutual auth가 더하는 것은 엣지에서의 암호학적 신원-쌍 attestation(agent-to-agent,
   `{local_id, remote_id, node}` 단위, ~30분 만료, 키 폐기; 기밀성은 별도의 WireGuard)이다.
   사슬 — RBAC(누가 배포) → label/SA 일관성 → SA-use gate(누가 티어 SA로 실행) → SVID 신원-쌍
   attestation — 이 매 단계에서 문턱을 높인다. **남는 것, 명확히:** SA-use gate는 admission 계층과
   이름 붙은 operator를 신뢰한다; 침해된 admin, 매치된 집합 밖의 리소스 종류(다른 네임스페이스;
   미래 API 종류), 노드 루트(root-on-node) 공격자는 여기 범위 밖이다. 요점은 각 링크가 이제 열린
   default가 아니라 *이름 붙고 최소화된* 신뢰라는 것이다.

## 각 계층이 보호하지 *않는* 것 (잔여 위험)

- **`X-User`는 미인증 데모 입력이다.** injection 방지를 위해 charset 검증되지만, PDP는 호출자가
  자기가 누구인지 진술하는 것을 신뢰한다. 실 시스템은 principal을 헤더가 아니라 **검증된 JWT
  `sub`**(또는 mTLS SVID)에서 도출한다. 로컬 포트폴리오를 위한 의도적 스코핑이며 README에도 명시.
- **Cilium 신원은 여전히 CNI와 커널을 신뢰한다.** mutual auth는 문턱을 "SPIRE나 노드를 침해하라"로
  높이지만, 노드 루트 공격자는 범위 밖이다.
- **출하 런타임 규칙은 zero-exec(데이터-티어 exec에 robust); 잔여는 아래.** 데이터 티어는 자신의
  main 프로세스만 돌리므로(db probe는 `httpGet`이지 exec가 아님), 출하 `TracingPolicy`는
  **`sys_execve`와 `sys_execveat` 둘 다** 훅해 `tier: data`의 **모든** exec를 SIGKILL한다 — `id` /
  `sh` / 이름을 바꾼 `/tmp/x` busybox 사본 / 이름으로 부른 busybox 전부 rc 137이고, nginx(PID 1,
  정책 이전에 exec됨)는 계속 서빙(라이브-검증, kind + Tetragon 1.7.0). 이것은 **arg0/이름-독립적이고
  execveat를 커버**하므로, 나이브 규칙을 무력화하는 우회들이 닫혀 있다. *왜 선택적 셸-이름 규칙이
  아니라 zero-exec인가:* 이전의 arg0-Postfix 컷(현재 **M4 랩 프리미티브** `block-shell-in-data-tier`)은
  나이브한 `kubectl exec … sh` 케이스만 죽였고 회피 가능했다 — (a) **이름 바꾼 바이너리**
  (`cp /bin/busybox /tmp/x && /tmp/x sh`, arg0 불일치), (b) **execveat**(외로운 `sys_execve` kprobe가
  결코 보지 못하는 syscall), (c) **fd-exec**(arg0 `/proc/self/fd/N`); 그리고 `matchBinaries`는 **틀린**
  해법이다(`sys_execve`에서 *호출자(caller)*를 매치하므로 `NotIn [/usr/sbin/nginx]`는 `nginx -v`를
  죽이고, 호출자가 nginx인 in-nginx-RCE 셸은 *놓친다*). 모든 exec를 금지하면 이름/arg0 스푸핑을
  통째로 비켜간다. 의사결정 기록: `docs/decisions/0001-data-tier-zero-exec.md`; 선택적→우회→zero-exec
  측정은 Lab M8이다. **zero-exec 하에서도 *남는* 잔여 위험:** (1) restart-tolerance는 이미지가 아니라
  Tetragon의 시행-attach **윈도우**에서 온다 — alpine 이미지 **와** distroless `chainguard/nginx`
  **둘 다** t=0부터 정책 활성 상태로 Ready가 됨을 라이브 검증(PID1 entrypoint execve가 윈도우를
  빠져나감; fragile + 이미지-독립적; 더 빠른 attach라면 entrypoint를 SIGKILL → CrashLoop). (2)
  **데이터 티어만** 스코프 — web/api 티어는 zero-exec가 아님(ED3 NOT_COVERED). (3) I/O는 prevention이
  아니라 detection-grade, (4) io_uring/LSM 표면이 여전히 적용됨(다음 두 bullet). **방어심층 — 이미지
  계층:** distroless 데이터-티어 이미지는 `/bin/sh`도 busybox도 **없이** 출하되므로(검증: 정책 적용
  전에도 `/bin/sh` → "no such file"), 셸을 통째로 제거하는 한편 이 런타임 규칙은 공격자가 쓰기 가능
  마운트에 WRITE하는 어떤 바이너리든 여전히 죽인다 — 둘 다 써라. 허용목록(allowlist, 일부 exec
  허용)은 arg0 문자열이 아니라 바이너리 신원을 위한 **BPF-LSM**(`bprm_check_security`)이 필요하다.
  전문가 리뷰에서 표면화, Lab M8에서 라이브-검증.
- **런타임 탐지는 *syscall* 표면을 본다 — 알려진 evasion class가 있다.** `execve`에는 io_uring
  opcode가 없으므로 io_uring이 exec 규칙을 우회해 돌아가지 않는다 — io_uring에 대한 *좁은* 사실이지
  완전성(completeness) 주장이 아니다. exec 방어의 진짜 잔여(attach-window, 다른 티어)는 위 bullet에
  있고; arg0/execveat/fd-exec 스푸핑은 zero-exec로 **닫혀 있다**. 더 넓은 syscall-kprobe 규칙(file
  read/write, network connect)은 **io_uring**의 submission queue를 통해 우회될 수 있다(ARMO "Curing"
  PoC, 2025). Robust한 답: 호출 방식과 무관하게 커널 *연산(operation)*을 관찰하는 **LSM 계층
  (BPF-LSM/KRSI)**을 훅하는 것. 정밀하게(ARMO 기준): io_uring에 blind한 것은 Tetragon 자체가 아니라
  Tetragon의 **default syscall 정책**이다 — kprobe/LSM 훅은 io_uring을 *볼 수* 있다 — 그래서
  "default syscall 정책이 blind; LSM/KRSI라면 볼 것", "Tetragon이 우회됨"이 **아니다**. 명시된 잔여
  (doc-only / NOT_COVERED); 단일 `execve` 규칙은 의도적으로 좁다.
- **kill은 I/O엔 detection-grade, execve엔만 prevention-grade(타이밍).** execve+Sigkill 규칙은 *새
  이미지가 로드되기 전에* 죽인다(셸이 첫 명령을 결코 실행 못 함 — prevention-grade). 그러나 Tetragon
  자체 문서가 적듯, `write()` 도중 보낸 SIGKILL은 바이트가 쓰이지 않았음을 **보장하지 않는다** —
  프로세스는 동기적으로 죽지만 커널은 이미 I/O를 했을 수 있다(detection-point ≠ prevention-point).
  kprobe 규칙을 I/O에 prevention-grade로 만들려면 Sigkill을 **Override** 액션과 결합해야 한다; 우리
  셸 규칙은 설계상 Sigkill-only다. **Lab M8**(`labs/m8/`)에서 *스코프*는 라이브 측정되고
  (`scripts/verify-runtime-scope.ps1`: sh=137 / id=0 / cat=0), I/O write-window는 *탐구*되며(문서화된
  Tetragon 캐비엇 + SKIP-prone 학습자 정책, 여기서 측정 안 함), execve 사전-이미지-로드 타이밍은
  문서화된 kprobe 시맨틱이다. ED1은 VERIFIED 유지 — M8은 그 *상태*가 아니라 *의미*를 날카롭게 한다.
- **Egress는 무제한 DNS를 허용한다 — 잔여 covert-exfil/C2 채널.** egress baseline(B5)은 모든 pod가
  `matchPattern: "*"`로 kube-dns를 통해 해석하도록 둔다(k8s/netpol.yaml). TCP 비콘을 열 수 없는 털린
  pod라도 DNS 질의로 데이터를 터널링해 내보낼 수 있다(DNS-tunnel exfil) — 그래서 "비콘을 못 한다"는
  *TCP* egress에 대해 정확한 것이지 covert egress가 0이라는 주장이 아니다. 하드닝: 패턴을 in-cluster
  suffix(`*.svc.cluster.local` + 필요한 upstream)로 제한하거나 egress-DNS inspection을 추가. 잔여로
  명시(전문가 리뷰에서 표면화).
- **checkov는 매니페스트를 보지 런타임을 못 본다.** CiliumNetworkPolicy CRD나 Cedar 로직을 볼 수
  없다; 그것들은 `cedar/authz.py`와 라이브 `verify` 잡이 커버한다. "0 findings"가 "안전"으로 주장된
  적은 없다 — `.checkov.yaml` triage 참조.
- **엔티티는 정적 픽스처**로 api 이미지에 구워져 있다; user store·rotation·revocation이 없다. 데모
  범위 밖이며, 그렇게 명시함.
- **공급망(Supply chain):** public 이미지(web/db, 그리고 curl probe)는 `@sha256` digest로 핀됨(B1
  무결성); `api` 이미지는 로컬 빌드 후 `kind load`로 side-load되므로 registry digest가 없다(*스코프된*
  checkov skip이 이를 문서화 — 다른 모든 워크로드는 여전히 digest 핀에 묶여 있음). 빌드 provenance
  (cosign) 이미지 SIGNING은 이제 **로컬-키 경로**에서 검증된다 — 로컬 OCI registry(cosign#3832
  no-registry 블로커 제거) + keyful cosign + Kyverno verifyImages가 admission에서 signed→ADMIT /
  unsigned→DENY를 증명(`scripts/verify-image-signing`, coverage SL6). Keyless/Rekor + SLSA provenance
  attestation은 ECR-경로 로드맵으로 남는다.
- **데이터 보호 vs 접근 통제.** B1–B7은 *누가 무엇에 도달/무엇을 할 수 있는가*를 다스린다. 별도로,
  이 스택은 **데이터 자체**를 보호한다: pod-to-pod 트래픽은 WireGuard 암호화(data-in-transit, 라이브
  검증), Secret은 etcd에서 AES-CBC 암호화 가능(data-at-rest, `scripts/enable-secrets-encryption.*`).
  정직한 스코프: 여기 실 데이터스토어는 없다(`db` 티어는 자리표시자이고 엔티티는 정적 픽스처), 그래서
  이것은 데이터 상태에 매핑된 *통제*를 시연하지 프로덕션 데이터 생애주기를 시연하지 않는다.
  `docs/06-data-protection.md` 참조.

## STRIDE 빠른 매핑

| Threat | 어디에 떨어지나 | 통제 |
|--------|--------------------|---------|
| **S**poofing identity | `api`가 되려고 `app:` 라벨 주장 | RBAC(누가 배포) → label/SA 일관성 → SA-use gate(누가 티어 SA로 실행) → mutual-auth SVID. 각 링크가 이름 붙고 최소화된 신뢰(B7). |
| **T**ampering | pod spec/라벨 변조 | PSA `restricted` + label/SA admission policy |
| **R**epudiation | `db`에서 누가 무엇을 돌렸나 | Tetragon process-exec audit trail |
| **I**nfo disclosure | 인터넷/메타데이터로 exfil | Cilium egress default-deny(B5) |
| **I**nfo disclosure | 선상/etcd에서 데이터 읽기 | WireGuard(in-transit) + Secret encryption(at-rest) |
| **D**enial of service | 자원 고갈 | per-container CPU/memory limits |
| **E**levation of privilege | 데이터 티어 셸 | Tetragon SIGKILL(B6); drop-ALL-caps, no-priv-esc |

이 표의 요점은 완전성이 아니다 — 모든 행이 **이 repo에 구현된** 통제에 매핑된다는 것, 그리고
시행된다고 표기된 것들은 `cedar/authz.py` 또는 라이브 `verify` 잡이 시험한다는 것이다. 통제가
위협을 닫기보다 문턱을 *높이기만* 하는 곳(Spoofing 행)은 행이 그렇게 말하고 잔여를 위에 명시한다 —
그 정직함이 요점이지, 깔끔한 표가 요점이 아니다.
