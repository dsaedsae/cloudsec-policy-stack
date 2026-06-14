# M1 — 쉬프트레프트: 심어둔 결함을 사냥해 게이트를 green으로

<div class="lab-pills">
<span class="lab-progress">모듈 2 / 7</span> · <span class="lab-badge">스택 checkov</span> · <span class="lab-badge">소요 ~1.5–3h</span> · <span class="lab-badge no-cluster">클러스터 불필요</span> · <span class="lab-badge">비용 $0 로컬</span>
</div>

> **준비:** `.venv`(requirements-dev) 필요 — [SETUP](../SETUP.md). 미설치 시 채점기가 안내한다.

**미션:** 신입이 짜온 `labs/m1/workload.yaml`을 checkov가 **0 실패**로 통과하도록 *고친다*.
클러스터 불필요 — checkov만 돌린다. 처음엔 **16개 위반**이 잡힌다.

> 🎯 **학습 성과 (면접에서 말할 수 있는 것):** 워크로드 매니페스트의 결함을 securityContext/리소스/프로브 묶음으로 고치고, 스캐너가 *언제·무엇을* 잡는지(런타임 통제와의 보완)와 스킵 남발이 위험을 *가리는* 이유를 설명할 수 있다. → [캡스톤 M1](../capstone.md)

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

## Step 3 — break-and-fix: triage vs 은폐 (20분)

0을 만든 뒤:

1. `readOnlyRootFilesystem: true`를 지워라 → `grade.py` → **CKV_K8S_22** 한 개가 돌아온다.
2. 이번엔 *고치지 말고* 컨테이너에 스킵 주석을 달아본다:
   `# checkov:skip=CKV_K8S_22: 임시` → `grade.py`. 통과하지만 채점기가 **⚠ 경고**를 띄운다.
3. <details><summary>그 경고가 가르치는 것 (열기)</summary>스킵은 위험을 *없애지* 않고 *가린다*. 정당한 스킵(이 랩의 .checkov.yaml 3개처럼)은 "왜 안전한지" 근거가 있어야 한다. CKV_K8S_22를 "임시"로 스킵하는 건 근거가 아니라 회피다. 감사에서 가장 위험한 게 바로 이 "스킵했지만 이유 없음"이다 — 이 repo의 평가 분석이 CONFIGURED("있다고 주장하나 테스트 없음")를 가장 위험한 범주로 꼽는 것과 같은 맥락.</details>
   주석을 지우고 `readOnlyRootFilesystem: true`를 되살려 0으로 복귀.

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

## 졸업 기준 (셀프 체크)

- [ ] `grade.py` **Failed checks: 0**
- [ ] 16개를 *어떤 securityContext/리소스/프로브 설정*이 *어떤 위험*을 막는지 묶어서 설명할 수 있다
- [ ] Step 3의 스킵-경고가 왜 나오는지, 정당한 스킵과 회피를 구분할 수 있다
- [ ] 구두 문답 7개를 답안 없이 말했다
- [ ] `k8s/app.yaml`의 web/api/db와 내 답을 비교해, 내가 빠뜨렸거나 다르게 한 부분을 찾았다

다음: **M2 — K8s 신원 (admission CEL 재작성)** — 클러스터 필요(`labs/m2/`).
