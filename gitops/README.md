# gitops/ — GitOps 무결성 통제판 (M10)

이 디렉터리는 `terraform/`·`labs/`와 동급의 **peer 모듈**이다. 기존 `k8s/` 매니페스트를
**복사하지 않고 path-참조**해서, imperative CI 경로(`kubectl apply -f k8s/`)와 GitOps 경로가
**같은 파일을 진실원천으로** 읽는다 — 두 진실원천이 생기면 "drift" 교훈 자체가 거짓이 되기 때문.

학습/배경은 → **[랩 M10](../labs/m10/README.md)** · 설계 근거는 → **[ADR 0002](../docs/decisions/0002-argocd-gitops-relocates-identity-tcb.md)** ·
위협 모델은 → **[THREAT_MODEL B8](../THREAT_MODEL.md)**.

## 레이아웃

```
gitops/
  bootstrap/root-app.yaml      app-of-apps 루트 — 손으로 apply하는 "마지막 imperative act"
  projects/shop-project.yaml   AppProject = reconciler blast-radius 최소화 (B8, LP7 analogue)
  apps/identity.yaml           wave -1  rbac + admission (신원 먼저)
  apps/workload.yaml           wave  0  app.yaml
  apps/network-runtime.yaml    wave  1  netpol + tracingpolicy (마지막)
```

`sync-wave`가 척추다: `.github/workflows/ci.yml`의 *"Identity FIRST"* 셸 주석(부족지식)을
**감사 가능한 선언적 불변식**(-1 identity → 0 app → 1 network)으로 격상한다. 회귀는
`scripts/check-sync-wave-order.py`가 무클러스터로 잡는다.

## 정직한 경계 (오너 결정 전까지)

- **헤드라인(77.5%)은 이 모듈로 바뀌지 않는다.** GitOps 대부분은 ops/instrumentation이거나
  기존 통제의 *재계측*이다. coverage 행 추가(IN1, family `integrity`)는 **오너 결정** — 자세히는
  [M10 README의 "왜 헤드라인이 안 변하나"](../labs/m10/README.md).
- **opt-in.** ArgoCD는 무거운 always-on integration job에 넣지 않는다(OOM 회피). 정적 절반
  (`check-reconciler-rbac.py`·`check-sync-wave-order.py`)만 항상 CI-게이트, 라이브 drift/
  fighting-controllers 증명은 opt-in(`scripts/enable-gitops.sh` + `verify-gitops.sh`).
