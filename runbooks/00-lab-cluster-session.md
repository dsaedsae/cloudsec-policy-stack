# 00 — 랩 클러스터 세션 (M2–M5 한 번에)

**언제:** 재구현 트랙의 클러스터 모듈 **M2·M3·M4·M5**를 실습할 때. 이 통제들은 살아있는
kind 클러스터(Cilium+Tetragon+SPIRE+WireGuard)가 필요하고, 그 스택은 RAM을 많이 쓴다 — 그래서
**한 번 띄워 네 모듈을 연속으로** 한 뒤 내린다.

> 전제: 도구 설치(Docker/kind/kubectl/helm/cilium-cli/terraform + Git Bash)와 RAM 설정은
> **[labs/SETUP.md Track B](../labs/SETUP.md)** 에 있다(여긴 *절차* 전용 — 설치를 중복하지 않는다).
> `.ps1`은 PowerShell, `.sh`는 Git Bash. 컨텍스트는 `kind-cloudsec`.

## 1) 띄우기 (PowerShell) — 5~10분

```powershell
powershell -File scripts\doctor.ps1        # (선택) M2-M5 READY 인지 먼저 확인
scripts\up.ps1                             # kind 3노드 + Cilium + Tetragon + SPIRE + WireGuard
kubectl cluster-info --context kind-cloudsec   # 떴는지 확인 (에러면 → 아래 "막히면")
```

`up.ps1`은 **멱등** — 실패해도 다시 돌리면 이어서 수렴한다.

## 2) 채점 (Git Bash 창에서 — PowerShell/WSL 아님) — 순서대로

```bash
bash labs/m2/grade.sh    # 신원: 위조 DENY / 정합 ADMIT       -> 5/5
bash labs/m3/grade.sh    # 네트워크: L1/L7/egress 최소권한 홉  -> 7/7
bash labs/m4/grade.sh    # 런타임: 셸만 선택적 SIGKILL         -> id=0 + sh=137
bash labs/m5/grade.sh    # 암호화: 크로스노드 WireGuard         -> ET1 PASS
```

각 채점기는 학습자 아티팩트를 적용해 검증한 뒤 **canonical 정책을 자동 복원**한다(클러스터는
다음 모듈을 위해 known-good로 돌아온다). 클러스터가 안 떠 있으면 채점기는 `SKIP (채점 안 함 —
PASS/FAIL 아님)`을 출력한다 — 그건 통과가 아니다.

> **통과 신호로 무엇을 보나** — 채점기는 마지막 줄에 **`M2 GRADUATED — ...`**(m3·m4는 `M? GRADUATED`,
> m5는 `M5 ET1 PASS — ...`)를 찍는다. 클러스터가 없으면 **`SKIP (채점 안 함 — PASS/FAIL 아님): ...`**.
> **PASS와 SKIP은 둘 다 종료코드 0**이므로 — 종료코드가 아니라 *이 마지막 줄 문자열*로 판단하라.
> (위 `-> 5/5`·`-> 7/7`은 기대 결과의 *요지*이지 화면에 그대로 찍히는 문자열이 아니다.)

(선택) 항상-켜진 21/21 스위트도 보고 싶으면: `bash scripts/verify.sh`.

## 3) 내리기 (PowerShell) — RAM 회수

```powershell
scripts\down.ps1
```

> **주의:** `down.ps1`은 `cloudsec` 클러스터만 내린다. 다른 kind 클러스터(`agent-dd`,
> `devsecops` 등)는 건드리지 않는다 — `kind delete clusters --all` 같은 건 쓰지 마라.

## 막히면

| 증상 | 원인 / 조치 |
|---|---|
| `up.ps1`이 rollout timeout(180s)으로 FAILED | `kubectl --context kind-cloudsec get pods -A` → `Pending`/`OOMKilled`/`CrashLoopBackOff`면 RAM 부족. Docker Desktop 메모리를 ≥8GB로 올리거나 앱을 닫고 `scripts\down.ps1` → `scripts\up.ps1`(멱등) |
| helm 릴리스 `context deadline exceeded` | 콜드 이미지 풀이 느린 것. terraform helm timeout은 이미 900s로 상향됨 — 그냥 `up.ps1` 재실행 |
| `bash: command not found` | Git for Windows 미설치 ([SETUP](../labs/SETUP.md)) |
| 채점기가 `SKIP ... 컨텍스트 없음` | `up.ps1` 안 했거나 활성 컨텍스트가 다름 → `kubectl config get-contexts` 확인 |
| `cilium status` 단계에서 FAILED | **cilium-cli** 미설치(Cilium-the-CNI와 다른 별도 바이너리, [SETUP](../labs/SETUP.md)) |

## 이 런북이 다루지 않는 것

- 도구/RAM **설치**(→ [SETUP Track B](../labs/SETUP.md)) · 각 모듈의 **학습 내용**(→ 각 `labs/mN/README.md`)
- no-cluster 모듈 **M0·M1·M6**(클러스터 불필요 — `.venv`만)
- 프로덕션(EKS) 운영 — 이건 로컬 학습용 단발 세션이다.
