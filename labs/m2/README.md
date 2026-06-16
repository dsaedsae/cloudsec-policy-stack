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

**왜 라벨이 TCB인가 (구체적 메커니즘).** Cilium은 파드의 IP가 아니라 *라벨*에서 security identity를
계산한다(numeric identity). 그 정책 결정의 입력이 파드 라벨이므로, 라벨을 정하는 주체 = 네트워크
신원을 정하는 주체다. 그런데 라벨은 단순한 문자열 필드라 무결성 검증이 없다 — `kubectl label`,
파드 spec, Deployment 템플릿 어디서든 자유롭게 박힌다(THREAT_MODEL §B7: 라벨이 TCB). admission이
없으면 이 경계는 *Kubernetes RBAC 전체*로 번진다 — shop에 워크로드 생성 권한이 있는 모든 principal이
네트워크 신원을 위조할 수 있게 된다. admission-time에 묶는 이유: admission은 etcd에 **영속되기 전**
단계라, 위조 파드가 만들어졌다 지워지는 게 아니라 *애초에 존재하지 못한다*. 런타임 탐지(Tetragon)나
사후 정책 스캔과 달리 위조 신원이 클러스터에 한 순간도 살아있지 않는다 — preventive vs detective의 차이.

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

### CEL 한 줄씩 읽기 (변수가 왜 그렇게 생겼나)

`k8s/admission-policy.yaml`의 변수 셋을 보면 순서와 가드에 이유가 있다:

```
hasApp: has(object.metadata.labels) && 'app' in object.metadata.labels
app:    variables.hasApp ? object.metadata.labels['app'] : ''
sa:     object.spec.serviceAccountName
```

- `has(object.metadata.labels)` 먼저인 이유: 라벨 맵 자체가 없는 파드(라벨 0개)에서 곧장
  `object.metadata.labels['app']`를 읽으면 CEL은 **no such key**로 에러난다. `has()`는 필드/키
  존재를 검사하는 CEL 매크로 — 단락(short-circuit) `&&`로 묶어 맵이 없으면 `'app' in ...`을
  아예 평가하지 않는다.
- `app`이 삼항(`hasApp ? ... : ''`)인 이유: validation식에서 `variables.app`을 무조건 쓰려면
  라벨이 없을 때도 *타입이 string*이어야 한다. `''`로 떨어뜨려 두면 `variables.app == 'web'`이
  그냥 false가 되고, 앞의 `!variables.hasApp ||`가 무라벨 파드를 먼저 통과시킨다.
- `sa`에 `has()`가 없는 이유: `spec.serviceAccountName`은 API 서버가 validating admission **이전**에
  `default`로 defaulting한다(아래 Step 3 #4). 그래서 늘 채워져 있어 가드가 불필요 — 반면 위
  SA-use 정책(`admission-sa-use.yaml`)의 `podSA`는 Deployment·CronJob 등 *템플릿이 다른* 종류를
  커버하느라 `has()` 가드가 필요하다(구조가 다르면 필드 경로가 없을 수 있음).

validation식의 평가 순서도 의미가 있다. CEL `||`는 왼쪽부터 단락 평가하므로:

```
!variables.hasApp || (web절) || (api절) || (db절)
```

무라벨 파드는 `!hasApp`에서 즉시 true → 뒤를 안 본다. 라벨 있는 파드만 절들을 타고,
*어느 절도 맞지 않으면* false → DENY. 즉 `app: cache`(정의 안 된 tier)나 `app: api`+`web-sa`는
모든 절을 떨어뜨려 거부된다 — allowlist 형태라 "모르는 라벨값 = 거부"가 자동으로 따라온다.

```bash
bash labs/m2/grade.sh               # 5/5 PASS → M2 GRADUATED. 채점 후 canonical 자동 복원.
```

## Step 2 — break-and-fix (예측 → 확인)

5/5 후, 아래를 하나씩. **먼저 어느 케이스가 깨질지 예측**하고 `grade.sh`로 확인:

1. `(variables.app == 'db' && ...)` 절을 지운다 → ?
2. `!variables.hasApp ||` 를 지운다 → ? (힌트: 무라벨 파드는?)
3. `variables.sa == 'web-sa'`를 `!= 'web-sa'`로 → ?
4. 변수 `app`을 `object.metadata.labels['app']`(가드 없이)로 바꾼다 → ?
5. `failurePolicy: Fail`을 `Ignore`로 → 채점은 그대로? 무엇이 달라지나?

<details><summary>1번 예측·확인</summary>db 절만 지우면 `app: db`+`db-sa` 정합 파드가 더는 통과하지 못한다. 채점기엔 db 정합 케이스가 없지만(deny 2 + admit 3 중 admit은 api/web/무라벨), 클러스터에선 db 티어 롤아웃이 전부 거부된다. "정합인데도 거부" = false positive = 가용성 결함. 통제가 *지나치게* 닫혀도 결함임을 보여준다.</details>
<details><summary>2번을 돌린 후 열 것</summary>`!hasApp ||`를 지우면 라벨 없는 시스템/프로브 파드가 전부 거부된다 → "no app label" 케이스 FAIL, 그리고 *실제 클러스터에선 coredns·probe 등이 안 뜬다*. 통제는 "필요한 것만 막고 나머진 통과"여야 한다 — 과잉 거부도 결함(가용성).</details>
<details><summary>3번 예측·확인</summary>`web-sa`를 `!= 'web-sa'`로 뒤집으면 정합(app:web+web-sa)은 절을 떨어뜨려 DENY, *불일치*(app:web+api-sa)는 통과 ADMIT — 통제가 정반대로 뒤집힌다. `grade.sh`에서 `admit ok-2`(정합 web) FAIL + `deny forge-2`(위조 web) ADMIT으로 둘 다 깨진다. polarity 버그는 "어떤 건 막힌다"만 보면 못 잡는다 — *막을 것을 막고 통과할 것을 통과*시키는지 양쪽을 봐야 잡힌다(M0의 교훈).</details>
<details><summary>4번 예측·확인</summary>`app` 변수에서 삼항 가드를 없애면, `app` 키가 없는 파드에서 `object.metadata.labels['app']`가 **no such key** 런타임 에러를 낸다(채점기의 무라벨 파드는 `labels: { }` 빈 맵이라 `has(labels)`는 true지만 `'app' in labels`가 false라 키 접근에서 터진다). `failurePolicy: Fail`이라 평가 에러 = 요청 거부 → `ok-3`("no app label")이 DENY로 떨어져 `admit()`에서 FAIL. 가드는 가용성 + 채점 양쪽에 걸린다. (참고: VAP 평가 에러 메시지에도 정책명은 붙으므로 `deny()`의 grep 자체는 빗나가지 않는다 — 여기서 깨지는 건 grep이 아니라 ADMIT여야 할 케이스가 DENY로 뒤집히는 것.)</details>
<details><summary>5번 예측·확인</summary>모든 입력이 정상이면 평가가 에러나지 않으므로 5/5는 그대로 PASS다 — `failurePolicy`는 *식이 에러났을 때만* 갈린다. 차이는 4번처럼 식이 깨졌을 때 드러난다: `Fail`이면 거부(fail-closed), `Ignore`면 통과(fail-open). 보안 통제에서 `Ignore`는 "정책 버그 = 무방비"를 뜻하므로 위험하다. 채점이 통과한다고 `Ignore`가 안전한 게 아니다 — happy-path 테스트는 fail-open을 못 잡는다.</details>

## 흔한 실수 (실제 틀린 출력 → 고침)

- **`apply` 직후 바로 채점 → forged가 ADMIT.** VAP/Binding은 적용 후 API 서버에 반영되기까지
  짧은 지연이 있다. `grade.sh`가 `sleep 3`을 두는 이유. 직접 돌릴 땐 적용 후 dry-run이 먼저
  나가면 위조 파드가 통과해 버린다 — "정책이 안 먹네"가 아니라 "아직 안 실렸다".
- **`messageExpression`에 정책명/토큰을 안 넣음 → DENY인데 FAIL.** 채점기는 거부 출력에서
  `shop-label-identity`(정책명)를 grep한다(`grade.sh` `deny()`). VAP 거부 메시지엔 정책명이
  자동으로 붙으므로 보통 통과하지만, `validationActions`가 `Warn`/`Audit`로 잘못 가 있으면
  거부 자체가 안 일어나 ADMIT으로 샌다 — Binding의 `validationActions: ["Deny"]` 확인.
- **`expression`을 YAML 블록 스칼라(`>`) 없이 한 줄에 욱여넣어 `||` 들여쓰기 깨짐.** apply가
  *YAML 파싱*에서 죽지 CEL 평가에서 안 죽는다. `grade.sh`는 `apply 실패 — YAML/CEL 문법 오류`로
  찍어준다 — 이 메시지가 나오면 CEL 로직이 아니라 들여쓰기/인용부터 봐라.
- **`==` 대신 `=` 사용.** CEL은 `=`가 비교 연산자가 아니다 → 컴파일 에러로 apply 거부.

## Step 3 — 구두 문답

1. <details><summary>이 정책이 막는 것과 *못* 막는 것은?</summary>막는다: label≠SA 위조(kubectl run --labels app=api는 default SA → 거부). 못 막는다: 자기일관 위조(app:api + api-sa를 둘 다 맞춰서 생성). 그건 SA-use 게이트(누가 tier SA를 쓸 수 있나)와 SPIFFE 암호신원이 닫는다.</details>
2. <details><summary>왜 webhook이 아니라 ValidatingAdmissionPolicy(VAP)인가?</summary>VAP는 k8s 내장(1.30 GA), CEL로 인라인 — 외부 webhook 서버/인증서/가용성 부담이 없다. 간단한 정합 검사엔 VAP가 적합.</details>
3. <details><summary>failurePolicy: Fail 의 의미는? Ignore였다면?</summary>정책 평가가 에러나면 요청을 거부(fail-closed). Ignore면 에러 시 통과(fail-open) — 보안 통제는 fail-closed가 기본.</details>
4. <details><summary>serviceAccountName을 안 적은 파드는 sa 변수가 뭐가 되나?</summary>'default'. API 서버가 validating admission 전에 기본값을 채우므로 variables.sa는 항상 채워져 있다 — 그래서 `kubectl run`(default SA)이 app:api 라벨과 불일치로 걸린다.</details>
5. <details><summary>채점기는 "내 정책이 막았다"를 RBAC 403과 어떻게 구분하나?</summary>VAP 거부 메시지엔 정책명(shop-label-identity)이 들어간다. 그걸 grep해서 *이 정책*의 거부임을 확인 — 단순히 "거부됨"이 아니라 "이 통제가 거부함"을 증명(이 repo의 검증 철학).</details>
6. <details><summary>이 정책은 라벨을 <em>막기만</em> 한다. 만든 뒤 `kubectl label`로 `app`을 바꾸면?</summary>matchConstraints가 `operations: ["CREATE","UPDATE"]`라 UPDATE도 잡는다 — 라벨을 사후에 `app:api`로 patch하면 그 UPDATE가 다시 admission을 타고 SA와 불일치면 거부된다. CREATE만 걸었다면 "정합하게 만든 뒤 라벨만 바꿔치기"로 우회됐을 것. 그래서 mutate 경로(patch)까지 닫는 게 중요하다.</details>
7. <details><summary>왜 binding은 namespaceSelector로 shop만 잡나? 클러스터 전역으로 하면 안 되나?</summary>전역이면 kube-system의 컨트롤러·프로브 파드까지 이 규칙을 타는데, 그쪽 SA 네이밍은 web-sa/api-sa/db-sa 규약이 아니라서 의도와 무관한 거부가 터진다(가용성). VAP는 종류·네임스페이스별로 손으로 고정하는 게 본질적 한계 — 전역·일반 적용은 캡스톤의 Kyverno ClusterPolicy(docs/05-identity.md)가 하는 일이다. 범위를 좁히는 건 over-deny를 막는 의도적 선택.</details>
8. <details><summary>이 정책은 admission-sa-use.yaml과 무엇이 다른가? 왜 둘 다 필요한가?</summary>이 정책은 <em>라벨과 SA의 일관성</em>(label == 어떤 tier면 SA도 그 tier)만 본다 — request.userInfo(요청자)는 안 본다. 그래서 app:api+api-sa 자기일관 파드는 통과한다. SA-use 게이트는 <em>요청자가 그 tier SA를 쓸 자격이 있나</em>를 request.userInfo로 본다. 전자는 "신원이 앞뒤가 맞나", 후자는 "이 신원을 쓸 권한이 있나" — 직교하는 두 질문이라 둘 다 있어야 자기일관 위조까지 닫힌다.</details>
9. <details><summary>CEL을 쓰는 admission이 OPA/Gatekeeper Rego나 외부 webhook보다 나은 점과 못한 점은?</summary>나은 점: k8s 내장(1.30 GA), API 서버 in-process 평가라 외부 서버·인증서·가용성·네트워크 홉이 없고, CEL은 컴파일·비용 한계가 있어 무한루프 불가(API 서버를 못 건다). 못한 점: 네임스페이스·종류별로 정책을 손으로 매칭해야 하고(전역 일반화가 약함), 외부 데이터 조회·복잡한 로직은 Rego/webhook이 유연하다. 단순한 in-cluster 정합 검사 = VAP가 정답, 크로스 리소스·외부 컨텍스트 = 정책엔진.</details>

## 현실 연결

"검증 없이 신뢰된 입력"은 admission 계층의 단골 결함 클래스다. ingress-nginx의
**CVE-2025-1974(IngressNightmare, CVSS 9.8, 2025-03 공개)**는 Ingress 객체의 *어노테이션 값*을
충분히 검증하지 않은 채 admission 컨트롤러가 nginx 설정으로 템플릿화해, 파드 네트워크의 비인증
공격자가 설정 인젝션으로 컨트롤러 파드에서 RCE → 컨트롤러 SA 범위의 시크릿 전체 탈취로 이어진
사례다. 권고 완화책 중 하나가 *admission 엔드포인트를 API 서버만 닿도록 NetworkPolicy로
좁히는 것* — 즉 "admission이 무엇을 신뢰·검증하나"와 "네트워크 신원"이 같은 문제다. 이 랩은 그
관계의 다른 쪽 끝이다: admission을 *검증 지점으로* 써서, 네트워크 계층이 암묵적으로 신뢰하던
라벨을 처음으로 강제 검사한다.

## 더 깊이 (1차 출처)

- Kubernetes — [Validating Admission Policy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
  (변수·matchConstraints·failurePolicy·messageExpression·validationActions)
- CEL — [Common Expression Language spec](https://github.com/google/cel-spec) / k8s
  [CEL in admission](https://kubernetes.io/docs/reference/using-api/cel/) (`has()` 매크로, 단락 평가, 타입 규칙)
- Kubernetes — [Admission Controllers 개요](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
  (admission이 영속 *이전* 단계인 이유)
- SPIFFE — [SVID](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/#spiffe-verifiable-identity-document-svid)
  (통제 4의 암호 신원이 SA에서 파생되는 근거)

## 졸업 기준

- [ ] `grade.sh` **5/5 PASS**
- [ ] Step 2의 깨질 케이스를 사전 예측했고, 과잉 거부(2번)도 결함인 이유를 안다
- [ ] 이 정책이 *못* 막는 잔여(자기일관 위조)와 그걸 닫는 후속 통제를 설명할 수 있다
- [ ] 구두 문답 5개를 답안 없이 말했다
- [ ] `k8s/admission-policy.yaml`과 내 답 비교

다음: **M3 — Cilium 네트워크 정책** (같은 클러스터 세션에서).
