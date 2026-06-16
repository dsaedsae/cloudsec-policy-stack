# M9 — 침해 가정(Assume-Breach): 블래스트 반경 봉쇄 (제로데이 렌즈)

<div class="lab-pills">
<span class="lab-progress">심화 / 시나리오</span> · <span class="lab-badge">스택 전 계층</span> · <span class="lab-badge">소요 ~25–40m</span> · <span class="lab-badge cluster">클러스터 필요 · RAM ~6–8GB</span> · <span class="lab-badge">비용 $0 로컬</span>
</div>

**미션:** web 파드가 **제로데이 RCE로 털렸다고 *가정*** 하고 — 막을 수 없는 걸 가정한 채 — *공격자가 거기서 어디까지 못 가나*(블래스트 반경)를 추적한다. 각 계층이 횡이동·유출·권한상승을 어떻게 가두는지, 그리고 **무엇을 못 가두는지**를 라이브로 본다.

> **이 랩의 정체(정직):** 이건 **새 통제를 만드는 랩이 아니다.** 기존 통제(ZT egress·마이크로세분화·SA 권한0·Tetragon zero-exec)를 **공격자 사후 시점이라는 렌즈로 재구성**하는 *시나리오 랩*이다(M8처럼). 그리고 **실제 익스플로잇을 돌리지 않는다** — `probe-web`는 web 파드와 *동일한 Cilium 신원*(`app:web`/`web-sa`)이라 네트워크 정책상 *털린 web 워크로드와 등가*다. 그 등가 위치에서 봉쇄 경계를 측정한다.

> **학습 성과 (면접에서 말할 수 있는 것):** "제로데이를 막는 정책"은 *존재하지 않는다*(미지의 익스플로잇엔 시그니처가 없다)는 걸 설명하고, 그래서 현실적 답이 **assume-breach + 블래스트 반경 봉쇄 + 사후 행위 탐지**임을 — *그리고 그 한계까지* — 말할 수 있다. → [캡스톤](../capstone.md)

**클러스터 필요.** 선행: M2–M5(같은 세션) 권장 — 봉쇄는 *살아있는 정책*이 시행한다. 배경: [THREAT_MODEL](../../THREAT_MODEL.md).

---

## 왜 "제로데이 방어 정책"을 따로 공부할 수 없나

제로데이 = *아직 모르는* 취약점의 익스플로잇. 시그니처가 없으니 "이걸 막아라"라는 *대상 자체가 없다*. (CVE 스캔(M1/trivy)은 *알려진* 취약점이라 정의상 제로데이가 아니다.) 그래서 업계의 현실적 답은 **"막을 수 없다고 가정하고, 터졌을 때 피해를 가둔다"** — 그게 이 랩이 측정하는 것이다.

## 실행 — 봉쇄 경계를 라이브로

```bash
# Git Bash (클러스터가 up 상태)
bash labs/m9/grade.sh
```

채점기가 *털린 web 발판*에서 다음을 시도하고 각 경계가 HELD인지 BREACH인지 보고한다:

| 시도 (공격자가 하려는 것) | 가두는 통제 | 기대 |
|---|---|---|
| **횡이동** web→db 직접 | Cilium L3 default-deny | `000` (drop) |
| **횡이동** web→api 비인가 경로(/auditlogs) | Cilium L7 method/path | `403` |
| **유출** web→인터넷 | egress default-deny | `000` |
| **유출** web→클라우드 메타데이터(169.254.169.254) | egress default-deny | `000` |
| **유출** web→kube-apiserver | egress default-deny | `000` |
| **권한상승** 클러스터 API 장악 | 티어 SA 권한 0 + 토큰 미마운트 | `can-i ... = no` |
| **최후** 데이터 티어 도달 시 도구 실행 | Tetragon zero-exec | exec `137` |

각 줄이 "공격자가 *여기서 막힌다*"는 한 지점이고, 그게 어느 verify 통제(ZT·NS·ID·ED)에 대응하는지 추적한다.

## break-and-fix — 경계를 직접 열어 본다 (예측 → 파괴 → 복원)

봉쇄를 *제거하면* 블래스트 반경이 어떻게 커지나 손으로 확인한다. **먼저 예측하라:** egress 차단을 풀면 grade.sh의 *어느 줄*이 BREACH로 뒤집힐까?

```bash
kubectl apply -f labs/m9/break/allow-web-egress.yaml    # web egress를 인터넷으로 개방 (한 줄 오설정 시뮬)
bash labs/m9/grade.sh                                    # 예측 확인: web -> 인터넷 이 000 HELD -> 200 BREACH
kubectl delete -f labs/m9/break/allow-web-egress.yaml    # 복원 → 다시 000 HELD
```

방금 한 일: 통제 **하나**(egress default-deny)를 떼니 *털린 web이 데이터를 인터넷으로 유출*할 수 있게 됐다. 봉쇄는 "있으면 가두고, 없으면 샌다" — 실무 침해의 상당수가 이런 *한 줄 오설정*이다. (같은 식으로 다른 경계도: `kubectl create rolebinding m9-break --clusterrole=view --serviceaccount=shop:web-sa -n shop` → 권한상승 줄이 BREACH → `kubectl delete rolebinding m9-break -n shop` 로 복원.)

## 정직한 한계 — assume-breach가 *못* 가두는 것

봉쇄는 force field가 아니다. 졸업하려면 이 잔여를 *말로* 설명할 수 있어야 한다:

- **같은 티어 내부 피해**는 봉쇄 대상이 아니다 — 털린 web은 web이 *합법적으로* 할 수 있는 건 다 할 수 있다(메모리·앱 로직·정상 응답 조작).
- **X-User는 데모 입력** — JWT 미강제 시 호출자 신원 위조 가능. enforce 모드(ID8, `AUTH_REQUIRE_JWT`)가 닫는다.
- **허용된 egress 경로**(DNS 등)로의 covert 유출 잔여(채널 자체는 열려 있어야 동작).
- **io_uring 등 회피 클래스**는 *기본 syscall 정책*이 못 본다(M8) — LSM/KRSI가 해법.
- **노드 루트·하이퍼바이저 탈출·공급망**은 범위 밖.

## 졸업 기준

- [ ] `grade.sh` — **모든 봉쇄 경계 HELD**
- [ ] **break-and-fix**: egress를 열어 `web -> 인터넷`이 BREACH로 뒤집히는 걸 *예측·확인*하고 복원했다
- [ ] 각 경계가 *어느 통제*에 대응하는지(L3/L7/egress/SA/Tetragon) 짚을 수 있다
- [ ] "왜 제로데이 *차단* 정책은 없고 assume-breach가 답인가"를 설명할 수 있다
- [ ] 위 *정직한 한계* 5개를 답안 없이 말할 수 있다

## 구두 문답

1. <details><summary>"제로데이를 막는 정책"을 왜 못 만드나?</summary>미지의 취약점엔 시그니처·서명·룰의 *대상*이 없다. 막을 수 있는 건 *알려진* 것뿐(CVE 스캔). 그래서 미지의 공격엔 prevention이 아니라 *containment*(침해 가정 + 블래스트 반경 봉쇄 + 행위 기반 사후 탐지)가 현실적 전략이다.</details>
2. <details><summary>이 봉쇄가 *시그니처 없이* 작동하는 이유는?</summary>네트워크 default-deny·SA 권한0·zero-exec는 "무엇이 나쁜가"를 몰라도 작동한다 — *기본적으로 금지*하고 *명시된 최소 경로만* 연다. 익스플로잇의 정체와 무관하게 횡이동·유출·권한상승 경로 자체가 닫혀 있다.</details>
3. <details><summary>probe-web에서 측정하는 게 왜 "털린 web 파드"와 등가인가?</summary>Cilium 정책은 IP가 아니라 *신원 라벨*(app:web)에 건다. probe-web은 동일 라벨/SA라 같은 ingress·egress·SA 권한을 받는다 — 네트워크-정책 관점에서 동일 봉쇄. (단 *앱 내부* 행위는 등가가 아니다 — 그래서 위 한계 1번.)</details>
4. <details><summary>봉쇄가 다 HELD여도 안심하면 안 되는 이유는?</summary>봉쇄는 피해를 *줄이지* 없애지 않는다. 같은 티어 내부 피해, 위조 가능한 데모 입력, covert 채널, io_uring, 노드 루트는 여전히 잔여다. "다 막았다"가 아니라 "이만큼 가뒀고 이건 못 가둔다"가 정직한 결론.</details>

다음: 전체 트랙 회고는 **[캡스톤 · 면접 노트](../capstone.md)**.
