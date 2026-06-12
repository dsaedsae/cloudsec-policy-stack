# 03 — 브레이크글래스 (Break-Glass)

정상 경로가 막혀 *긴급* 접근이 필요할 때. 원칙: **시간제한 + 전 과정 감사기록 + 사후 즉시 원복**.
브레이크글래스는 통제를 *끄는 것*이 아니라 *기록을 남기며 우회*하는 것이다.

---

## 시나리오 1 — SA-use 게이트가 긴급 작업을 막음

`shop:deployers`로는 티어 SA 워크로드를 못 띄운다(설계대로). 진짜 긴급 상황(예: 장애 복구용
임시 파드)엔 **인가된 운영자 신원**을 쓴다.

**권장(우회 아님):** 클러스터 admin(`kubeadm:cluster-admins`) 또는 `shop:tier-operators`
그룹 신원으로 수행 — SA-use 게이트가 이미 허용한다. 별도 우회 불필요.
```bash
# 누가 했는지 기록되도록, 전용 break-glass 신원으로(impersonation 감사로그 남음)
kubectl --as=breakglass-oncall --as-group=shop:tier-operators apply -f <긴급 매니페스트>
```
→ apiserver 감사로그에 `breakglass-oncall`이 남는다. **끝나면 그 신원의 그룹 매핑을 회수.**

---

## 시나리오 2 — admission 정책 자체를 일시 완화해야 함

정책 버그로 *정상* 배포가 전부 막힌 경우. 정책을 **삭제가 아니라 `Warn`으로 강등**(거부→경고)
한 뒤 작업하고 즉시 복원.

```bash
# 1) 현재 정책 백업
kubectl get validatingadmissionpolicybinding shop-sa-use-binding -o yaml > /tmp/bg-binding.yaml

# 2) 거부를 경고로 강등(일시) — 작업은 통과하되 위반은 로그로 남음
kubectl patch validatingadmissionpolicybinding shop-sa-use-binding \
  --type=json -p='[{"op":"replace","path":"/spec/validationActions","value":["Warn","Audit"]}]'

# 3) 긴급 작업 수행 ...

# 4) 즉시 복원 (Deny)
kubectl apply -f /tmp/bg-binding.yaml
```
**시간제한:** 강등은 분 단위로만. 복원 알람을 걸어두고(예: `at`/타이머) 잊지 않는다.

---

## 사후(브레이크글래스 후 반드시)
1. 무엇을·왜·누가·몇 분간 했는지 **사고 기록** 작성.
2. 감사로그에서 해당 신원/작업 확인: `kubectl ... ` (EKS는 CloudTrail/apiserver audit).
3. 임시 권한·강등 **원복 확인**: `verify` 재실행으로 통제 복귀 증명.
4. 근본원인(왜 정상 경로가 막혔나) 수정 → 다음엔 브레이크글래스 불필요하게.

## 다루지 않는 것
- 영구 비상계정(안티패턴) — 모든 브레이크글래스는 단발·시간제한.
- 물리/콘솔 접근 브레이크글래스(클러스터 밖 범위).
