# 05 — 배포 · 롤백

안전한 apply 순서와, 나쁜 배포를 되돌리는 절차.

---

## A. 안전한 배포 순서

**의존성 순서를 지킨다(이 순서가 깨지면 SA 없음/네임스페이스 없음으로 실패):**
```
1. 신원   : k8s/rbac.yaml (ns + 티어 SA)  →  admission-policy.yaml  →  admission-sa-use.yaml
2. 워크로드: k8s/app.yaml
3. 정책   : k8s/netpol.yaml  →  k8s/tracingpolicy.yaml
4. 롤아웃 : kubectl -n shop rollout status deploy/{web,api,db}
```
`scripts/up.{ps1,sh}`가 이 순서를 강제한다. **수동 배포 시에도 1→2→3 순서를 지킬 것.**
(과거 사고: rbac가 app보다 늦어 SA 없음 → 파드 거부. 그래서 ns를 rbac.yaml에 둔다.)

**배포 후 게이트:**
```bash
./.venv/Scripts/python.exe cedar/authz.py              # 8/8
pwsh scripts/verify.ps1                                 # 21/21 (회귀 0)
```

---

## B. 롤백

**워크로드(이미지/스펙) 롤백:**
```bash
kubectl -n shop rollout history deploy/api
kubectl -n shop rollout undo deploy/api                # 직전 리비전으로
kubectl -n shop rollout undo deploy/api --to-revision=N
kubectl -n shop rollout status deploy/api
```

**정책(Cilium/Cedar/admission) 롤백 — git이 원천:**
```bash
git revert <bad-commit>        # 또는 직전 정상 매니페스트로
kubectl apply -f k8s/<rolled-back>.yaml
pwsh scripts/verify.ps1        # 통제 복귀 증명
```
- **Cedar 정책 회귀**는 클러스터 없이 즉시 잡힌다: `cedar/authz.py` 8/8 깨지면 롤백.
- **admission 정책**이 정상 배포를 막으면: [03 브레이크글래스](03-break-glass.md)로 일시 완화 후
  올바른 정책 적용.

**이미지 digest 롤백:** `k8s/app.yaml`은 `@sha256`로 핀됨 → 이전 digest로 되돌리면 정확히 그
빌드로 복귀(태그 롤백과 달리 변조 위험 없음).

---

## 배포 실패 빠른 분류
| 증상 | 원인 | 조치 |
|------|------|------|
| 파드 `CreateContainerError`/`serviceaccount not found` | rbac를 app보다 늦게 apply | 순서 교정(1→2) |
| Deployment 거부(admission 메시지) | 라벨↔SA 또는 SA-use 위반 | 라벨/SA 정렬 또는 인가 신원으로 |
| 롤아웃 멈춤(0/1 available) | PSA restricted 위반/프로브 실패 | `describe pod` 이벤트 확인 |
| verify 일부 FAIL | 정책 회귀 | 해당 파일 git revert |

## 다루지 않는 것
- 블루/그린·카나리(직교 — 이 데모는 단일 리비전 롤아웃).
- DB 스키마 마이그레이션 롤백(데모에 실 DB 없음).
