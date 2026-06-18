# M10 배우기 모드 — 떠먹여주는 application.yaml

> [M10 README](README.md)를 먼저 읽고, *직접 작성*을 시도한 뒤 막혔을 때 이걸 펴라. 복붙하면 채점기는 통과해도
> **유일하게 측정되는 것(네 이해)이 사라진다.** 여기 노출되는 한 줄들이 *왜* load-bearing인지가 전부다.

학습자는 `labs/m10/application.yaml`(스켈레톤)의 세 가지를 채운다. canonical 정답지는 `gitops/apps/*.yaml`
+ `gitops/projects/shop-project.yaml`. 채점은 `python labs/m10/grade.py`(무클러스터 정적) + `bash labs/m10/grade.sh`(라이브).

## 1단계 — 노출(읽기): destination scope

```yaml
spec:
  project: shop                       # AppProject = reconciler blast-radius (LP7 analogue)
  destination:
    server: https://kubernetes.default.svc
    namespace: shop                   # 이 App은 shop ns에만 쓴다 — 다른 ns로 못 샌다
```

`project: shop`이 핵심이다. AppProject가 reconciler가 *건드릴 수 있는* 것을 allowlist한다(ns shop/argocd,
ClusterRoleBinding 금지, Secret 금지). 이걸 `default` project로 두면 reconciler가 cluster-wide가 되어 **새
신원-TCB(B8)가 곧 cluster-admin**이 된다 — B7이 `shop:tier-operators`를 최소화한 노력이 무효화된다.

## 2단계 — 한 칸 채우기: syncPolicy.automated

```yaml
  syncPolicy:
    automated:
      prune: true
      selfHeal: __?__        # ← 채워라
    syncOptions: [CreateNamespace=false, ServerSideApply=true]
```

<details><summary>힌트</summary>drift 자동교정(L1)이 동작하려면 reconciler가 *cluster의 변경을 git으로 되돌려야* 한다. `selfHeal:false`면
공격자의 `kubectl patch`가 **살아남는다**(다음 git 변경 전까지). 즉 이 한 줄이 "GitOps = 런타임 무결성 통제"의
on/off 스위치다.</details>

<details><summary>정답</summary><code>selfHeal: true</code>. <code>prune:true</code>는 git에서 *지운* 객체를 cluster에서도 지운다(orphan 방지);
<code>selfHeal:true</code>는 git과 *다른* live 객체를 git으로 되돌린다(drift 교정). 둘 다 켜야 "live == git" 불변식이 강제된다.
단 즉시가 아니라 sync interval만큼 윈도우가 있음을 잊지 마라(README L1).</details>

## 3단계 — 직접 작성: sync-wave + AppProject allowlist

스펙만 보고 작성하라(정답지 보지 말 것):

1. **`sync-wave`** 애너테이션 — identity App은 `"-1"`, workload는 `"0"`, network/runtime은 `"1"`. *왜?*
   identity(SA)가 workload보다 먼저 reconcile돼야 admission이 *아직-없는-SA*를 참조하는 pod를 거부하지 않는다.
   숫자를 scramble하면 `check-sync-wave-order.py`가 FAIL하고, 라이브에선 SA-not-found로 pod가 안 뜬다.
2. **AppProject `clusterResourceWhitelist`** — Namespace + VAP + VAPBinding만. ClusterRoleBinding을 넣으면
   `check-reconciler-rbac.py`가 FAIL한다(reconciler 자기-권한상승 차단). *왜 그게 위험한지* 한 줄로 설명할 수 있어야 한다.

## 채점 + 구두문답

```bash
python labs/m10/grade.py            # application.yaml 정적 채점 (무클러스터, 졸업-critical 절반)
bash labs/m10/grade.sh              # L1/L2/L3 라이브 (클러스터 + enable-gitops)
```

졸업 = 세 칸을 *왜 그렇게* 채웠는지 [README의 구두문답 8개](README.md#구두-문답)에 답할 수 있는 것. 특히:
*"selfHeal:false면 무엇이 깨지나"*, *"reconciler를 cluster-admin으로 두면 B7이 어떻게 무효화되나"*.
