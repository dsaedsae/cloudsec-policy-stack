# ADR 0002 — GitOps(ArgoCD)는 통제를 추가하지 않고 신원-TCB를 이전한다 (B7 → B8)

**상태:** 채택 (2026-06-18) · **범위:** opt-in (auto-sync 기본 OFF, 무거운 always-on integration job 불변) · **관련:** [THREAT_MODEL B8](../../THREAT_MODEL.md) · [M10 랩](../../labs/m10/README.md) · [ADR 0001](0001-data-tier-zero-exec.md)

## 맥락
스택은 매니페스트를 **imperative**하게 적용한다(`kubectl apply -f k8s/`). 적용 순서("Identity FIRST")는
`.github/workflows/ci.yml`의 **셸 주석**에만 산다 — 부족지식. GitOps는 보통 "배포 편의"로 팔리지만, 이
프로젝트의 축(신원-TCB·정책-as-code·B7)에서 보면 GitOps는 **새 통제가 아니라 신원-TCB의 *이전*** 이다:
B7의 "누가 `app:web` 파드를 만드나"가 "누가 repo에 머지하나 + reconciler SA가 무엇을 사칭/적용하나"가 된다.

## 결정
1. **ArgoCD 채택 (Flux 아님).** 정당화는 인기투표가 아니라 *보안 결정*이다:
   - ArgoCD의 app-tree UI가 sync-wave DAG + per-resource OutOfSync/Degraded를 **렌더한다** — M10 주제
     (drift-correction, fighting-controllers)의 *그림 그 자체*. Flux는 1st-party UI가 없어(Weave GUI EOL)
     `flux get` 텍스트로 가르쳐야 한다.
   - **정직한 반대급부(랩에 명시):** ArgoCD는 `argocd-server` API + redis(+opt dex)라는 **stateful·
     internet-adjacent 컨트롤플레인을 클러스터에 *추가*** 한다 — 그 자체가 net-new 공격표면이고 THREAT_MODEL
     대상이 된다(`argocd-server` 침해 = 모든 synced namespace write). Flux는 더 작은 TCB(in-cluster UI 서버
     없음). **"가르치는 데 쓰는 UI가 곧 위협모델해야 할 대상"** 이라는 게 senior 통찰이고, 이 트레이드를
     보안 결정으로 가르친다.
2. **app-of-apps + AppProject 최소권한.** reconciler가 RBAC/NetworkPolicy/admission policy에 apply 권한을
   가지면 *구성상* `app:api`를 mint하고, 그걸 지키는 VAP를 다시 쓰고, 네 사고대응 `kubectl edit`를 되돌릴 수
   있는 principal이다(= **B8**). 그래서 `gitops/projects/shop-project.yaml`(AppProject)이 그 reach를 LP7처럼
   **allowlist**한다 — `scripts/check-reconciler-rbac.py`(정적) + `--live`(`kubectl auth can-i`)가 그게 *tight*
   하지 *broken*하지 않음을 증명. `k8s/rbac.yaml`이 이미 예고했다 — *"map this Group to your privileged GitOps controller"*.
3. **단일 진실원천.** child Application은 `k8s/`를 **복사하지 않고 path-참조**한다 — imperative CI 경로와
   GitOps 경로가 *같은 파일*을 읽는다. 두 진실원천이 생기면 "drift" 교훈 자체가 거짓이 된다.
4. **sync-wave가 순서를 데이터로 격상.** -1 identity → 0 workload → 1 network. `scripts/check-sync-wave-order.py`가
   회귀를 무클러스터로 잡는다(셸 주석 → 감사 가능 불변식).
5. **opt-in/auto-sync OFF.** ArgoCD(~400–700MB)를 이미 RAM 천장 근처인 integration job에 넣지 않는다(OOM 회피).
   정적 절반(check-reconciler-rbac·check-sync-wave-order)만 **항상 CI-게이트**, 라이브 drift/fighting-controllers
   증명은 opt-in(`enable-gitops.sh` + `verify-gitops.sh`, SL6/ID7 선례).

## 헤드라인 정직성 (가장 중요한 콜)
GitOps 대부분은 **ops/거버넌스이거나 기존 통제의 *재계측*** 이지 headline 변화가 아니다.
- **기본: 헤드라인 80%(32/40)는 이 모듈로 바뀌지 않는다.** coverage 행 추가는 **오너 결정**으로 분리한다 — 결정: 행 미추가. coverage 분모는 *고정된* MLS 요구집합을 추적하고, GitOps 무결성은 자체 추가 통제라 위협모델 B8·학습모듈(M10)로 기록한다(라이브 ArgoCD를 상시 CI 게이트로 만들면 재검토).
- 추가 시 후보는 단 1행 — **IN1**(새 family `integrity`): "desired-state drift auto-reverted within sync
  interval". 이건 어느 기존 계층도 증명 못하는 유일한 *런타임 무결성* 통제(detection=ED*·prevention=ID*와
  구별되는 **correction**)다. 정직한 매핑:
  - CI hard-gate(push-triggered)면 → VERIFIED → 33/41 = **80.5%**.
  - 로컬 랩 grader만(ID4 SPIFFE 선례)이면 → CONFIGURED → 32/41 = **78.0%** (denominator +1이 비율을
    *먼저 떨어뜨린다* — ID8이 쓴 "증명 전엔 claim 안 함"의 정직한 방향).
- **이중계상 금지:** L2 fighting-controllers·L3-static·L4 supply-chain·L5 ordering은 *기존* 통제(ID1/SL6/B7)의
  property를 새 actor로 재측정한 것 — evidence 강화지 새 row가 아니다. 모듈의 가치는 coverage가 아니라 **깊이**.

## 결과 / 정직한 한계 (감사가 지적한 "미공개 갭"을 disclose)
- **bootstrap 역설(turtles all the way down):** GitOps는 자기 자신을 bootstrap 못한다. ArgoCD와 root
  Application은 **terraform/admin kubectl**(push-model, cluster-admin)이 설치한다 — pull-model reconciler를
  설치하는 trust-root가 push-model. GitOps는 root kubectl trust를 *제거*하지 않고 *사용 빈도*만 줄인다.
- **reconciler는 OWN하지 않는 것을 못 되돌린다:** drift-correction은 tracked Application 하의 리소스만 커버.
  un-tracked namespace의 rogue NetworkPolicy는 invisible(NS5 cross-ns "CONFIGURED, not verified"와 연결).
- **compromised Git / signed-but-malicious PR은 설계상 in-scope-of-trust:** reconciler는 공격자 의도를 충실히
  적용한다. GitOps는 trust를 code-review+signed-commit으로 *이전*하지 *생성*하지 않는다(SL6 "provenance ≠ contents" 미러).
- **drift-correction엔 WINDOW(sync interval)가 있다:** 그 동안 공격자 edit가 LIVE. "drift를 막는다"가 아니라
  "drift를 ≤ sync interval로 경계짓고 자동교정한다"만 주장(M8 detection≠prevention을 revert-latency로 재측정).
- **EXEMPT-bypass(repo 자체 발견):** `k8s/admission-sa-use.yaml`이 `system:serviceaccount:kube-system:*`를 admit한다.
  reconciler가 kube-system SA로 돌면 SA-use 게이트를 조용히 우회한다 → 완화는 reconciler를 **named·non-kube-system·
  minimally-scoped SA**로(B7이 `shop:tier-operators`를 최소화했듯 새 TCB도 최소화). vuln이 아니라 가장 날카로운 교훈.
