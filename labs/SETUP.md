# 환경 준비 (Windows 기준) — clone에서 첫 채점까지

이 한 페이지면 **빈 클론에서 M0 첫 PASS까지** 갈 수 있다. 트랙은 둘로 나뉜다:

- **Track A — 클러스터 불필요 (M0 · M1 · M6):** Python만 있으면 된다. **여기부터 시작하라.**
- **Track B — 클러스터 필요 (M2 · M3 · M4 · M5):** Docker + kind 스택. RAM이 든다(아래).

> 빠른 점검: 무엇이 준비됐고 무엇이 빠졌는지 한 번에 보려면 — `powershell -File scripts\doctor.ps1`

---

## Track A — Python 랩 (M0/M1/M6) · 5분

`.venv/`는 `.gitignore`라 클론엔 없다. **한 번만** 만든다 (PowerShell):

```powershell
# 1) Python 3.12 가상환경 생성 (Python 3.12 설치 필요: winget install Python.Python.3.12)
python -m venv .venv

# 2) 의존성 설치 (cedarpy, checkov 등)
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt

# 3) 동작 확인 — 목표 상태(8/8)가 보이면 준비 완료
.venv\Scripts\python.exe cedar\authz.py
```

이제 [M0](m0/README.md)을 시작한다: `.venv\Scripts\python.exe labs\m0\grade.py` (처음엔 5/8).

- **M1**은 위 `.venv`면 충분(checkov 포함). 이미지 스캔까지 해보려면 `trivy`(선택): `winget install AquaSecurity.Trivy`.
- **M6 Part B(ReBAC)** 는 **Docker Desktop**이 필요하다(OpenFGA를 docker로 실행). Docker가 없으면 Part A(Cedar 12/12)만 채점되고 졸업 표시가 안 뜬다.

> Linux/CI 형식(`./.venv/bin/python ...`)은 저장소 루트 `README.md`의 Quickstart 절을 참고.

---

## Track B — 클러스터 랩 (M2–M5)

### 설치할 것

| 도구 | 용도 | Windows 설치 |
|---|---|---|
| **Docker Desktop** | kind 노드가 도는 엔진 | `winget install Docker.DockerDesktop` (실행해 두기) |
| **Git for Windows** | `.sh` 채점기를 도는 **Git Bash** | `winget install Git.Git` |
| **kind** | 로컬 k8s 클러스터 | `choco install kind` |
| **kubectl** | k8s CLI | `choco install kubernetes-cli` |
| **helm** | Cilium/Tetragon 차트 | `choco install kubernetes-helm` |
| **cilium-cli** | `up.ps1`의 `cilium status` (CNI와 **다른** 별도 바이너리) | `choco install cilium-cli` |
| **terraform** | kind+Cilium 프로비저닝 | `winget install Hashicorp.Terraform` |

> **`.ps1`은 PowerShell, `.sh`는 Git Bash.** PowerShell에서 `bash`를 치면 WSL로 연결돼 실패한다 —
> 클러스터 채점기는 반드시 **Git Bash 창**에서 `bash labs/mN/grade.sh` (forward slash).

### RAM

3노드 kind + Cilium/Hubble + Tetragon(eBPF) + SPIRE + WireGuard는 **실측 ~6–8GB**를 쓴다.
**Docker Desktop > Settings > Resources > Memory를 최소 8GB**로 두라. (3노드인 이유: api/db를
다른 노드에 강제 배치해 M5 크로스노드 WireGuard 증명을 가능케 한다.)

### 한 세션으로 (RAM 규율)

M2–M5는 클러스터를 **한 번 띄워** 연속으로 한 뒤 내린다:

```powershell
scripts\up.ps1                       # PowerShell — kind+Cilium+... (5~10분)
kubectl cluster-info --context kind-cloudsec   # 떴는지 확인 (에러면 다시 up.ps1)
```
```bash
# 그다음 Git Bash 창에서 (PowerShell 아님):
bash labs/m2/grade.sh    # 5/5
bash labs/m3/grade.sh    # 7/7
bash labs/m4/grade.sh    # id=0 + sh=137
bash labs/m5/grade.sh    # ET1 PASS
```
```powershell
scripts\down.ps1                     # 끝나면 PowerShell — RAM 회수 (다른 클러스터는 보존)
```

### 막히면

- `up.ps1`이 rollout timeout(180s)으로 FAILED → `kubectl --context kind-cloudsec get pods -A`로
  Pending/OOMKilled/CrashLoopBackOff 확인. 보이면 Docker 메모리를 올리거나 앱을 닫고
  `scripts\down.ps1` 후 `scripts\up.ps1` 재실행(멱등).
- `bash: command not found` → Git for Windows 미설치 (위 표).
- 채점기가 `SKIP: ... 컨텍스트 없음` → `up.ps1`을 아직 안 했거나 활성 컨텍스트가 다름
  (`kubectl config get-contexts`).

---

각 모듈의 채점 명령과 졸업 기준은 [트랙 개요](README.md)의 모듈 사다리에 있다.
