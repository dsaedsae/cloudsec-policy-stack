# M2 — K8s 신원: 라벨↔SA 일관성을 admission CEL로 (B7)

<div class="lab-pills">
<span class="lab-progress">모듈 3 / 7</span> · <span class="lab-badge">스택 VAP+CEL</span> · <span class="lab-badge">소요 ~30–45m</span> · <span class="lab-badge cluster">클러스터 필요 · RAM ~6–8GB</span> · <span class="lab-badge">비용 $0 로컬</span>
</div>

**미션:** Cilium이 신뢰하는 `app` 라벨을 파드의 ServiceAccount에 묶는 `ValidatingAdmissionPolicy`의
**CEL 검증식**을 직접 써서, 위조 신원(label≠SA)을 admission에서 거부한다.

> **학습 성과 (면접에서 말할 수 있는 것):** 라벨↔SA admission CEL을 작성해 위조 신원을 거부하고, 이 통제가 *못* 막는 자기일관 위조와 그걸 닫는 후속 통제(SA-use 게이트·SPIFFE)를 설명할 수 있다. → [캡스톤 M2](../capstone.md)

**클러스터 필요.** **편집 파일:** `labs/m2/admission-policy.yaml` (validations의 expression/message만).

> 선행: M0/M1 권장. 배경: [`THREAT_MODEL.md`](../../THREAT_MODEL.md) §B7,
> [`docs/05-identity.md`](../../docs/05-identity.md).

---

## 왜 이게 핵심인가

Cilium 네트워크 정책은 "`app:web`에서 온 트래픽은 api에 갈 수 있다"고 한다. 이건 *누가 `app:api`
라벨 파드를 만들 수 있나*에 전적으로 의존한다. shop에 파드 생성 RBAC이 있는 사람은 `app:api`
라벨을 붙여 **api가 되어** db에 닿고 네트워크 정책을 우회할 수 있다. 이 랩은 그 구멍을 막는
*첫 통제* — 라벨과 SA가 **일치**하도록 강제한다(완전한 닫힘은 SA-use 게이트(THREAT_MODEL §B7 #3, *이 랩 범위 밖*) + 암호 신원이지만,
여기선 일관성 가드부터).

## Step 0 — 클러스터 + 베이스라인

> **`up.ps1`/`down.ps1` → PowerShell, `grade.sh`/`verify.sh` → Git Bash** (forward slash).
> PowerShell에서 `bash`를 치면 WSL로 연결돼 실패한다. 도구·RAM(~6–8GB)·설치는 [SETUP](../SETUP.md).

```powershell
scripts\up.ps1                      # PowerShell — 한 번 띄운다 (M2~M5 한 세션; ~6–8GB RAM)
```
```bash
# 그다음 Git Bash 창에서 (PowerShell/WSL 아님):
bash scripts/verify.sh              # canonical 21/21 확인 (목표 상태)
bash labs/m2/grade.sh               # 내 (빈) 정책 채점 — apply는 되지만 일부 FAIL
```

> 시작 정책의 `expression: true`는 *모든 파드를 통과*시킨다 → 위조 파드도 ADMIT → forged 케이스 FAIL.
> ADMIT 케이스(정합·무라벨)는 우연히 통과한다. **ADMIT 통과는 정책이 옳다는 증거가 아니다**(M0의 교훈
> 재등장 — 여기선 default-*allow* 쪽).

## Step 1 — CEL 작성

`labs/m2/admission-policy.yaml`의 `validations[0]`를 채워라. 변수는 이미 있다:

- `variables.hasApp` — `app` 라벨이 있나 (bool)
- `variables.app` — 라벨 값 (없으면 `''`)
- `variables.sa` — `spec.serviceAccountName` (API가 기본 `default`로 채움)

**규칙:** `app` 라벨이 없으면 통과. 있으면 `app∈{web,api,db}`이고 `sa == app+'-sa'`여야 통과.

```
// 형태 (직접 완성):
!variables.hasApp ||
(variables.app == 'web' && variables.sa == 'web-sa') ||
(variables.app == 'api' && variables.sa == 'api-sa') ||
(variables.app == 'db'  && variables.sa == 'db-sa')
```

`messageExpression`엔 왜 거부됐는지(변수 보간) + 토큰 하나(`forged` 또는 `B7`)를 넣어라 —
운영에서 거부 사유를 읽을 수 있어야 하고, 채점기는 거부가 *이 정책*에서 나왔는지 정책명으로 구분한다.

```bash
bash labs/m2/grade.sh               # 5/5 PASS → M2 GRADUATED. 채점 후 canonical 자동 복원.
```

## Step 2 — break-and-fix (예측 → 확인)

5/5 후, 아래를 하나씩. **먼저 어느 케이스가 깨질지 예측**하고 `grade.sh`로 확인:

1. `(variables.app == 'db' && ...)` 절을 지운다 → ?
2. `!variables.hasApp ||` 를 지운다 → ? (힌트: 무라벨 파드는?)
3. `variables.sa == 'web-sa'`를 `!= 'web-sa'`로 → ?

<details><summary>2번을 돌린 후 열 것</summary>`!hasApp ||`를 지우면 라벨 없는 시스템/프로브 파드가 전부 거부된다 → "no app label" 케이스 FAIL, 그리고 *실제 클러스터에선 coredns·probe 등이 안 뜬다*. 통제는 "필요한 것만 막고 나머진 통과"여야 한다 — 과잉 거부도 결함(가용성).</details>

## Step 3 — 구두 문답

1. <details><summary>이 정책이 막는 것과 *못* 막는 것은?</summary>막는다: label≠SA 위조(kubectl run --labels app=api는 default SA → 거부). 못 막는다: 자기일관 위조(app:api + api-sa를 둘 다 맞춰서 생성). 그건 SA-use 게이트(누가 tier SA를 쓸 수 있나)와 SPIFFE 암호신원이 닫는다.</details>
2. <details><summary>왜 webhook이 아니라 ValidatingAdmissionPolicy(VAP)인가?</summary>VAP는 k8s 내장(1.30 GA), CEL로 인라인 — 외부 webhook 서버/인증서/가용성 부담이 없다. 간단한 정합 검사엔 VAP가 적합.</details>
3. <details><summary>failurePolicy: Fail 의 의미는? Ignore였다면?</summary>정책 평가가 에러나면 요청을 거부(fail-closed). Ignore면 에러 시 통과(fail-open) — 보안 통제는 fail-closed가 기본.</details>
4. <details><summary>serviceAccountName을 안 적은 파드는 sa 변수가 뭐가 되나?</summary>'default'. API 서버가 validating admission 전에 기본값을 채우므로 variables.sa는 항상 채워져 있다 — 그래서 `kubectl run`(default SA)이 app:api 라벨과 불일치로 걸린다.</details>
5. <details><summary>채점기는 "내 정책이 막았다"를 RBAC 403과 어떻게 구분하나?</summary>VAP 거부 메시지엔 정책명(shop-label-identity)이 들어간다. 그걸 grep해서 *이 정책*의 거부임을 확인 — 단순히 "거부됨"이 아니라 "이 통제가 거부함"을 증명(이 repo의 검증 철학).</details>

## 졸업 기준

- [ ] `grade.sh` **5/5 PASS**
- [ ] Step 2의 깨질 케이스를 사전 예측했고, 과잉 거부(2번)도 결함인 이유를 안다
- [ ] 이 정책이 *못* 막는 잔여(자기일관 위조)와 그걸 닫는 후속 통제를 설명할 수 있다
- [ ] 구두 문답 5개를 답안 없이 말했다
- [ ] `k8s/admission-policy.yaml`과 내 답 비교

다음: **M3 — Cilium 네트워크 정책** (같은 클러스터 세션에서).
