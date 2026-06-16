# M1 — 쉬프트레프트: 심어둔 결함을 사냥해 게이트를 green으로

<div class="lab-pills">
<span class="lab-progress">모듈 2 / 7</span> · <span class="lab-badge">스택 checkov</span> · <span class="lab-badge">소요 ~1.5–3h</span> · <span class="lab-badge no-cluster">클러스터 불필요</span> · <span class="lab-badge">비용 $0 로컬</span>
</div>

> **준비:** `.venv`(requirements-dev) 필요 — [SETUP](../SETUP.md). 미설치 시 채점기가 안내한다.

**미션:** 신입이 짜온 `labs/m1/workload.yaml`을 checkov가 **0 실패**로 통과하도록 *고친다*.
클러스터 불필요 — checkov만 돌린다. 처음엔 **16개 위반**이 잡힌다.

> **학습 성과 (면접에서 말할 수 있는 것):** 워크로드 매니페스트의 결함을 securityContext/리소스/프로브 묶음으로 고치고, 스캐너가 *언제·무엇을* 잡는지(런타임 통제와의 보완)와 스킵 남발이 위험을 *가리는* 이유를 설명할 수 있다. → [캡스톤 M1](../capstone.md)

**편집하는 파일은 단 하나:** `labs/m1/workload.yaml`.

---

## Step 0 — 사냥감 확인

```powershell
.venv\Scripts\python.exe labs\m1\grade.py     # Failed checks: 16, 남은 위반 목록 출력
```

> **Windows 메모:** checkov가 `UnicodeDecodeError: 'cp949'`로 죽으면 한 번만 `$env:PYTHONUTF8=1`을
> 설정하고 다시 돌려라(또는 `setx PYTHONUTF8 1` 영구 설정). 윈도우 기본 코드페이지가 cp949라 UTF-8
> 주석이 든 파일을 못 읽어서 그렇다 — CI(우분투·UTF-8)에서는 안 나는 로컬 한정 이슈다.

> **핵심 사고방식:** "0 findings"가 목표가 아니라 **triage**가 목표다. 각 위반을 (a) 진짜 고치거나
> (b) *문서화된 이유와 함께* 스킵한다. 이 랩은 전부 **고치는** 게 정답이다 — 하든드 워크로드에는
> 스킵 주석이 필요 없다. (`labs/m1/.checkov.yaml`에 이미 *정당한* 스킵 3개가 있다: 로컬 이미지라
> 다이제스트/IfNotPresent, 그리고 네트워크정책은 CNI 몫. 그 외엔 전부 네 손으로 고쳐라.)

## Step 1 — 읽기 (20–40분)

- [`docs/02-scan.md`](../../docs/02-scan.md) — 이 repo의 스캔 게이트와 *정직한 triage* 철학
- 각 위반은 checkov 출력의 CKV 번호로 검색하면 공식 설명이 나온다 (<https://www.checkov.io/5.Policy%20Index/kubernetes.html>)
- **참고 답안은 보지 마라:** `k8s/app.yaml`의 web/api/db는 이미 하든드다. 졸업 *후* 비교용이다.

## Step 2 — 사냥: 16개를 그룹으로 잡는다 (1–2시간)

위반은 흩어져 보이지만 **수정 4–5군데면 16개가 다 사라진다.** 한 번에 하나의 *수정*을 하고
`grade.py`로 줄어드는 걸 확인하라 — 그게 "어떤 설정이 어떤 위험을 막는지" 익히는 방법이다.

| 한 번의 수정 | 사라지는 CKV | 무엇을 / 왜 |
|---|---|---|
| **container `securityContext` 강화** | `CKV_K8S_16`(privileged) · `CKV_K8S_20`(allowPrivilegeEscalation) · `CKV_K8S_22`(readOnlyRootFilesystem) · `CKV_K8S_28`(NET_RAW) · `CKV_K8S_37`(capabilities) | `privileged: true` 제거; `allowPrivilegeEscalation: false`; `readOnlyRootFilesystem: true`; `capabilities: { drop: ["ALL"] }`. 권한상승·쓰기·위험 capability 차단 |
| **pod-level `securityContext`** | `CKV_K8S_23`(root) · `CKV_K8S_40`(high UID) · `CKV_K8S_31`(seccomp) · `CKV_K8S_29`(securityContext 적용) | `runAsNonRoot: true`, `runAsUser: 10001`(>10000), `seccompProfile: { type: RuntimeDefault }`. 루트 금지·호스트 UID 충돌 회피·시스콜 필터 |
| **`resources` 추가** | `CKV_K8S_10`·`CKV_K8S_11`(CPU req/limit) · `CKV_K8S_12`·`CKV_K8S_13`(mem req/limit) | `requests`+`limits` 둘 다. 자원고갈/노이지네이버 방어 |
| **probe 2개** | `CKV_K8S_8`(liveness) · `CKV_K8S_9`(readiness) | `livenessProbe`+`readinessProbe`. 죽은/준비안된 파드 자동 처리 |
| **토큰 미마운트** | `CKV_K8S_38`(SA token) | `automountServiceAccountToken: false`. 팟이 털려도 API 토큰 없음(M2와 직결) |

```powershell
.venv\Scripts\python.exe labs\m1\grade.py     # 16 → ... → 0 까지 반복
```

### 정답 한 덩이를 줄별로 (k8s/app.yaml 패턴)

표만 보면 "어디에 넣나"가 안 보인다. 핵심은 **두 레이어**다 — `spec.template.spec.securityContext`(파드)
와 `containers[].securityContext`(컨테이너). 같은 키여도 레이어가 다르면 checkov가 다르게 본다.

```yaml
    spec:
      automountServiceAccountToken: false   # CKV_K8S_38 — 파드 spec 레벨(컨테이너 아님)
      securityContext:                       # ← 파드 레벨: 아래 셋은 여기에만 둘 수 있다
        runAsNonRoot: true                   # CKV_K8S_23 — UID 0 거부(런타임에 kubelet이 강제)
        runAsUser: 10001                     # CKV_K8S_40 — >10000 이라야 통과(아래 주의)
        seccompProfile: { type: RuntimeDefault }  # CKV_K8S_31 — 시스콜 필터를 명시
      containers:
        - name: app
          image: widget:local
          ports: [{ containerPort: 8080 }]
          readinessProbe: { httpGet: { path: /, port: 8080 }, initialDelaySeconds: 3, periodSeconds: 10 }  # CKV_K8S_9
          livenessProbe:  { httpGet: { path: /, port: 8080 }, initialDelaySeconds: 5, periodSeconds: 20 }  # CKV_K8S_8
          securityContext:                   # ← 컨테이너 레벨: 아래 셋은 컨테이너별이다
            allowPrivilegeEscalation: false  # CKV_K8S_20 (그리고 privileged:true 삭제 = CKV_K8S_16)
            readOnlyRootFilesystem: true     # CKV_K8S_22
            capabilities: { drop: ["ALL"] }  # CKV_K8S_37 + CKV_K8S_28(NET_RAW는 ALL에 포함)
          resources:
            requests: { cpu: "10m", memory: "16Mi" }   # CKV_K8S_10 / _12
            limits:   { cpu: "100m", memory: "64Mi" }  # CKV_K8S_11 / _13
```

줄별로 *왜*:

- **`capabilities: { drop: ["ALL"] }` 하나가 두 CKV를 끈다.** `CKV_K8S_28`(NET_RAW)은 별도 키가
  아니다 — `ALL`을 drop하면 NET_RAW도 빠지므로 함께 사라진다. NET_RAW는 raw 소켓 생성 권한이라
  ARP/ICMP 스푸핑·패킷 위조의 표면이다. 컨테이너가 굳이 raw 소켓을 쓸 일은 거의 없다.
- **`runAsNonRoot` vs `runAsUser`는 다른 통제다.** `runAsNonRoot: true`는 "UID 0이면 기동 거부"(런타임
  강제)이고, `runAsUser: 10001`은 "이 UID로 돌려라"(명시 지정)다. `CKV_K8S_40`은 *높은* UID를 요구하는데,
  낮은 UID(예: 101)는 호스트의 동일 UID 사용자와 충돌해 user-namespace 미사용 시 호스트 파일을
  그 사용자 권한으로 건드릴 위험 때문이다. **주의:** 참고 답안 `k8s/app.yaml`의 web/db는 `runAsUser: 101`인데,
  이건 `nginx-unprivileged` 이미지가 UID 101 고정이라 `CKV_K8S_40`을 *전역 스킵*했기 때문이다
  (`.checkov.yaml`이 아니라 repo 루트 설정). 이 랩의 `widget:local`엔 그런 면제가 없으니 **10001을 써라.**
- **`readOnlyRootFilesystem: true`는 공짜가 아니다.** 앱이 `/tmp`·캐시·`/var/run`에 써야 하면 그
  경로만 `emptyDir`로 마운트해야 한다(`k8s/app.yaml`의 web/db가 그렇게 한다). 이 랩의 `widget:local`은
  실제로 기동하는 이미지가 아니라 *매니페스트 정적 검사*만 받으므로 볼륨 없이 통과한다 — 하지만
  실제 워크로드라면 "RO로 깔고 → 기동 실패하는 경로를 emptyDir로 뚫는" 순서가 정석이다.
- **`CKV_K8S_29`("securityContext 적용")는 위 셋이 들어가면 자동으로 만족된다** — 별도 키가 아니라
  "securityContext 블록이 존재하고 의미 있게 채워졌나"를 보는 메타 체크다. 그래서 표에서 pod-level
  묶음에 딸려 사라진다.

> **수정 순서 팁:** `privileged: true`만 지우면 위반이 16 → 15로 *한 개만* 준다(CKV_K8S_16). 나머지는
> "없어서" 걸리는 것이지 "틀려서"가 아니다 — checkov의 K8s 정책 대부분은 **부재(default)를 위반으로
> 본다.** K8s 기본값이 안전하지 않다는 것의 직접적 증거다(구두 7번과 같은 뿌리).

### 실수 모음 (실제로 걸리는 것)

- **레이어를 바꿔 넣는다.** `allowPrivilegeEscalation`/`readOnlyRootFilesystem`/`capabilities`를
  *파드* securityContext에 넣으면 **위반이 안 사라진다.** 이 셋은 컨테이너 전용 필드(`SecurityContext`)라
  K8s가 파드 레벨(`PodSecurityContext`)에선 무시하고, checkov도 컨테이너에서 못 찾아 계속 잡는다.
  (`runAsNonRoot`/`runAsUser`/`seccompProfile`는 양쪽 다 유효하니 파드 레벨에 두면 컨테이너마다 안 적어도 된다.)
  의심되면 위 "정답 한 덩이" 블록의 레이어 주석대로 맞춰라.
- **`runAsUser: 101`을 베껴 온다.** 참고 답안이 101을 쓰니 따라 했다가 `CKV_K8S_40`이 안 사라진다 —
  101은 >10000이 아니다. app.yaml이 101로 통과하는 건 *전역 스킵* 덕이지 101이 정답이라서가 아니다.
- **flow-style 들여쓰기.** 이 매니페스트는 `labels: { app: widget }` 같은 flow 스타일을 섞어 쓴다.
  새 블록(`securityContext:`)은 **block 스타일**로, 2칸 들여쓰기를 정확히 맞춰라. 들여쓰기가 어긋나면
  checkov는 위반을 줄여 주는 게 아니라 `Failed to parse` 류로 *엉뚱하게* 죽거나 키를 못 본다.
- **스캔 실패를 위반 0으로 오해.** Step 0의 cp949 크래시처럼 `Failed checks:` 줄 자체가 안 나오면
  grade.py는 0이 아니라 "checkov 출력을 해석하지 못했습니다"를 찍고 비정상 종료한다 — 통과 아님.

## Step 3 — break-and-fix: triage vs 은폐 (20분)

0을 만든 뒤:

1. `readOnlyRootFilesystem: true`를 지워라 → `grade.py` → **CKV_K8S_22** 한 개가 돌아온다.
2. 이번엔 *고치지 말고* 컨테이너에 스킵 주석을 달아본다:
   `# checkov:skip=CKV_K8S_22: 임시` → `grade.py`. checkov는 통과하지만 채점기가 `[!] ... 스킵 주석 N개 발견 — 은폐가 아니라 *수정*하라` 경고를 먼저 찍는다.
3. <details><summary>그 경고가 가르치는 것 (열기)</summary>스킵은 위험을 *없애지* 않고 *가린다*. 정당한 스킵(이 랩의 .checkov.yaml 3개처럼)은 "왜 안전한지" 근거가 있어야 한다. CKV_K8S_22를 "임시"로 스킵하는 건 근거가 아니라 회피다. 감사에서 가장 위험한 게 바로 이 "스킵했지만 이유 없음"이다 — 이 repo의 평가 분석이 CONFIGURED("있다고 주장하나 테스트 없음")를 가장 위험한 범주로 꼽는 것과 같은 맥락.</details>
   주석을 지우고 `readOnlyRootFilesystem: true`를 되살려 0으로 복귀.

### 더 망가뜨려 보기 (예측 → 깨기 → 확인)

각 변형 전에 **몇 개가, 어떤 CKV가 돌아올지 먼저 말하고** 돌려라.

- **변형 A — capability를 "필요한 것만" 추가.** `capabilities: { drop: ["ALL"], add: ["NET_RAW"] }`.
  <details><summary>예측 답</summary><b>CKV_K8S_28</b>(NET_RAW)이 돌아온다. `CKV_K8S_37`(capabilities 보유)도 함께 걸릴 수 있다 — drop:ALL을 해도 명시적으로 *add*한 capability는 별개로 잡힌다. 교훈: "ALL 드롭 후 한 개만 add"는 흔한 현업 패턴인데, 그 한 개가 위험 cap(NET_RAW/SYS_ADMIN/NET_ADMIN)이면 전용 체크가 그걸 정확히 집어낸다. 정말 필요하면 *문서화된 스코프 스킵*으로 triage하고, 아니면 빼라.</details>

- **변형 B — limits는 두고 requests만 지운다.** `resources.requests` 블록 삭제, `limits`는 유지.
  <details><summary>예측 답</summary><b>CKV_K8S_10</b>(CPU requests) + <b>CKV_K8S_12</b>(mem requests) 두 개가 돌아온다. limits 두 개(_11/_13)는 그대로 통과. checkov가 req/limit을 *각각* 검사하는 이유: limit만 있고 request가 없으면 K8s가 request=limit으로 잡아 스케줄러가 자원을 과대평가하고, QoS 클래스도 Guaranteed로 강제돼 빈-패킹이 나빠진다. 두 값은 다른 일을 한다 — request는 스케줄링·QoS, limit은 cgroup 상한.</details>

- **변형 C — 프로브를 하나만 둔다.** `livenessProbe`만 남기고 `readinessProbe` 삭제.
  <details><summary>예측 답</summary><b>CKV_K8S_9</b>(readiness) 하나만 돌아온다. 둘은 다른 장애를 본다 — liveness 실패는 컨테이너를 <i>재시작</i>하고, readiness 실패는 Service 엔드포인트에서 <i>빼낸다</i>(재시작 안 함). readiness가 없으면 기동 직후 아직 준비 안 된 파드로 트래픽이 흘러 5xx가 난다. 가용성(CIA의 A)이 보안 통제인 이유와 직결.</details>

## Step 4 — 졸업

```powershell
.venv\Scripts\python.exe labs\m1\grade.py     # Failed checks: 0 → M1 GRADUATED
```

(선택) 이미지 스캔까지: `trivy`가 설치돼 있으면 `bash scripts/scan.sh`로 IaC 게이트 +
이미지 취약점/SBOM까지 한 번에 돌려보라([`docs/02-scan.md`](../../docs/02-scan.md)).

## Step 5 — 구두 문답 (면접 방어)

답을 보기 전에 소리 내어 답하라.

1. <details><summary>checkov 같은 IaC 스캐너는 *언제* 도는가? 런타임 통제와 뭐가 다른가?</summary>커밋/PR/CI 단계 — 배포 *전에* 정적 분석으로 잡는다(shift-left). 런타임 통제(admission/netpol/Tetragon)는 클러스터에서 *실행 시점에* 막는다. 둘은 보완재 — 스캐너는 싸고 빠르지만 매니페스트만 보고, 런타임은 실제 동작을 본다.</details>
2. <details><summary>`allowPrivilegeEscalation: false`와 `privileged: false`의 차이는?</summary>privileged는 거의 모든 호스트 권한을 주는 큰 스위치. allowPrivilegeEscalation는 더 미세 — setuid 바이너리 등으로 *프로세스가 자기 권한을 올리는* 걸 막는다. 둘 다 꺼야 한다.</details>
3. <details><summary>`readOnlyRootFilesystem: true`가 막는 공격은?</summary>침입자가 바이너리/웹셸을 파일시스템에 떨어뜨리거나 설정을 변조하는 것. 쓰기가 필요하면 emptyDir 볼륨을 특정 경로에만 마운트한다.</details>
4. <details><summary>resource limits가 *보안* 통제인 이유는?</summary>한 파드가 자원을 독식해 다른 워크로드를 굶기는 DoS(노이지 네이버)를 막는다. 가용성도 보안의 일부(CIA의 A).</details>
5. <details><summary>`automountServiceAccountToken: false`가 M2(신원)와 어떻게 연결되나?</summary>토큰이 마운트되면 털린 파드가 그 SA로 API를 친다. 미마운트면 토큰 자체가 없다. M2에서 tier SA에 RBAC 권한을 0으로 두는 것과 합쳐, "털려도 클러스터 API엔 손 못 댐"의 방어심층.</details>
6. <details><summary>"0 findings"를 목표로 전부 스킵하면 왜 위험한가?</summary>스킵은 위험을 숨길 뿐 없애지 않는다. 감사자는 green을 신뢰하는데 실제론 통제가 없다 — CONFIGURED("주장하나 미검증")가 가장 위험한 이유. 정당한 스킵엔 근거가, 나머진 수정이 답이다.</details>
7. <details><summary>이 16개 위반의 *공통 뿌리*는 한 문장으로?</summary>"기본값으로 돌아가게만 짠" 매니페스트는 안전하지 않다 — K8s 기본은 편의(루트·풀권한·무제한)이지 보안이 아니다. 하든드는 명시적으로 *거부*를 적어 넣는 것.</details>
8. <details><summary>checkov는 매니페스트의 securityContext만 본다. 실제 클러스터에서 이걸 *강제*하는 건 누구인가?</summary>checkov는 정적 검사일 뿐 — 통과해도 누가 손으로 권한 매니페스트를 apply하면 막을 수 없다. 런타임 강제는 <b>Pod Security Admission</b>(PSA)이 한다: 이 repo는 <code>shop</code> 네임스페이스에 PSA <code>restricted</code>를 걸어(k8s/rbac.yaml), runAsNonRoot·drop ALL·seccomp 없는 파드는 admission에서 거부된다. 즉 shift-left(checkov, PR 시점) + admission(PSA, apply 시점)의 두 게이트가 같은 규칙을 다른 시점에 친다. 면접 포인트: "스캐너는 게이트가 아니라 신호다 — 우회 가능한 권고. 강제는 admission/PSA의 몫."</details>
9. <details><summary>경고만 내는 정책과 차단(deny)하는 정책 — checkov는 어느 쪽이고, 그 한계는?</summary>checkov는 PR에서 <code>exit 1</code>로 머지를 막을 수 있으니 "차단"처럼 쓸 수 있지만, 본질은 <i>파일을 읽는 린터</i>다 — 클러스터에 이미 떠 있는 것이나, checkov 게이트를 안 타는 경로(콘솔에서 직접 kubectl apply, Helm 후처리, operator가 만든 파드)는 못 본다. 그래서 같은 룰을 admission(런타임)에도 둬야 빈틈이 없다. checkov의 가치는 "<i>싸고 빠르게, 배포 전에</i>" 잡는 것이지 최종 방어선이 아니다.</details>
10. <details><summary>스캐너가 <i>틀리게</i> 잡는(false positive) 경우를 어떻게 triage하나? 이 repo의 실제 예 3개는?</summary>FP 또는 "맥락상 안전"은 <b>전역 스킵이 아니라 근거 달린 좁은 스킵</b>으로 처리한다. 이 랩 <code>.checkov.yaml</code>의 3개가 정확히 그 사례다: <code>CKV_K8S_15</code>(IfNotPresent — kind에 로컬 로드한 이미지라 항상 당겨올 레지스트리가 없음), <code>CKV_K8S_43</code>(다이제스트 핀 — <code>widget:local</code>은 레지스트리 @sha256 다이제스트가 없음), <code>CKV2_K8S_6</code>(NetworkPolicy 부재 — checkov가 CiliumNetworkPolicy CRD를 못 봄, 정책은 CNI가 친다). 각 스킵에 "왜 안전한지"가 주석으로 붙어 있다는 게 핵심 — 이게 Step 3의 "임시" 스킵과 다른 점이다.</details>
11. <details><summary><code>capabilities: { drop: ["ALL"] }</code>인데 왜 <code>CKV_K8S_28</code>(NET_RAW) 체크가 따로 있나?</summary>리눅스 컨테이너는 기본으로 NET_RAW를 포함한 capability 묶음을 들고 뜬다. drop ALL이면 NET_RAW도 빠지므로 둘 다 통과하지만, checkov가 NET_RAW에 <i>전용</i> 체크를 둔 이유는 NET_RAW가 단독으로도 위험하기 때문 — raw/packet 소켓으로 ARP 스푸핑·ICMP redirect·패킷 위조가 가능해 네임스페이스 내 다른 파드를 가로채는 L2/L3 MITM의 표면이 된다. drop ALL을 안 하고 <code>add: ["NET_RAW"]</code>만 한 매니페스트를 잡으려는 의도된 중복이다.</details>

## 왜 이게 표준인가 (현실 연결)

이 16개는 checkov가 임의로 고른 게 아니라 컨테이너 보안 표준이 공통으로 요구하는 항목이다.

- **`privileged`/`allowPrivilegeEscalation`/capabilities/root** — 컨테이너 탈출(host breakout)의 1순위
  표면이다. `privileged: true` 파드는 호스트의 모든 디바이스·`/proc`·커널 모듈에 닿아, 셸 하나만
  잡혀도 호스트 루트로 직행한다(노출된 워크로드 침해 → 노드 장악의 전형). PSA `restricted`가
  바로 이 묶음을 admission에서 거부하는 이유다(구두 8번).
- **표준 매핑(면접에서 인용 가능):** 이 컨트롤들은 **CIS Kubernetes Benchmark**의 워크로드 섹션,
  **NSA/CISA Kubernetes Hardening Guidance**(non-root·read-only rootfs·drop capabilities 권고),
  **NIST SP 800-190**(Application Container Security — 최소권한·불변 인프라)이 모두 명시한다.
  checkov의 CKV 번호는 이 권고들의 *기계 검증 가능한* 형태일 뿐이다.
- **불변 인프라(immutable infra)와 `readOnlyRootFilesystem`** — RO rootfs는 단순 변조 방지를 넘어
  "런타임에 바뀐 파일 = 침해 신호"라는 탐지 전제를 만든다. 쓰기 경로를 emptyDir로 한정하면
  공격자가 어디에 쓸 수 있는지 표면이 *알려진 작은 집합*으로 줄고, M4(Tetragon)의 런타임 탐지가
  걸 지점이 명확해진다.

### Go deeper (1차 출처)

- checkov K8s 정책 인덱스 (각 CKV의 공식 정의): <https://www.checkov.io/5.Policy%20Index/kubernetes.html>
- K8s 공식 — Pod Security Standards(privileged/baseline/restricted 프로파일): <https://kubernetes.io/docs/concepts/security/pod-security-standards/>
- K8s 공식 — Security Context 설정 가이드: <https://kubernetes.io/docs/tasks/configure-pod-container/security-context/>
- NSA/CISA — Kubernetes Hardening Guidance: <https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF>
- NIST SP 800-190 — Application Container Security Guide: <https://csrc.nist.gov/pubs/sp/800/190/final>

## 졸업 기준 (셀프 체크)

- [ ] `grade.py` **Failed checks: 0**
- [ ] 16개를 *어떤 securityContext/리소스/프로브 설정*이 *어떤 위험*을 막는지 묶어서 설명할 수 있다
- [ ] Step 3의 스킵-경고가 왜 나오는지, 정당한 스킵과 회피를 구분할 수 있다
- [ ] 구두 문답 11개를 답안 없이 말했다 (특히 8·9: "스캐너 ≠ 강제, admission/PSA가 강제")
- [ ] `k8s/app.yaml`의 web/api/db와 내 답을 비교해, 내가 빠뜨렸거나 다르게 한 부분을 찾았다

다음: **M2 — K8s 신원 (admission CEL 재작성)** — 클러스터 필요(`labs/m2/`).
