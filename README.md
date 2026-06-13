# cloudsec-policy-stack

[![ci](https://github.com/dsaedsae/cloudsec-policy-stack/actions/workflows/ci.yml/badge.svg)](https://github.com/dsaedsae/cloudsec-policy-stack/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

무료 로컬 `kind` 클러스터 위에서 도는 방어심층(defense-in-depth) 쿠버네티스 보안 스택과, 각 통제를 직접 다시 구현해 보는 자가채점 학습 트랙입니다. 프로덕션 배포물이 아니라 학습·포트폴리오 산출물입니다.

한 요청이 네트워크 → HTTP → 애플리케이션 인가 → 런타임의 독립된 정책 계층을 차례로 통과하고, 각 계층은 직접 돌리는 스크립트로 시행·검증됩니다.

```
   a single request:  web ──▶ api ──▶ (resource)
   ─────────────────────────────────────────────────────────────────────────
   Terraform │ kind cluster + Cilium (CNI), as code                  │ IaC
   Identity  │ RBAC + label↔SA admission + SPIFFE mutual auth        │ who is web/api
   Cilium L3 │ default-deny in+out; only web→api→db; egress locked   │ no exfil
   Cilium L7 │ only GET/POST on /accounts/* reach api (Envoy)        │ path/method
   Cedar     │ api PDP authorizes every call: owner? limit? role?    │ authz-as-code
   Tetragon  │ eBPF runtime: SIGKILLs a shell spawned in the db pod  │ detect+prevent
   Data      │ WireGuard in-transit + Secret encryption at-rest      │ protect the data
   ─────────────────────────────────────────────────────────────────────────
   checkov   │ shift-left scan of Terraform + K8s (CI gate, 0 fail)  │ + gitleaks
```

## 직접 만들어보기

이 repo의 핵심입니다. 모든 통제에는 실행 가능한 검증이 딸려 있고, [재구현 트랙](labs/README.md)은 그 검증기를 **자동채점기**로 뒤집습니다: 통제 하나를 빈 골격으로 만들어 두고, 스펙만 보고 다시 작성하면 기존 하네스가 PASS/FAIL로 채점합니다. 정답지를 베끼는 게 아니라 직접 쓰고 어디가 틀렸는지 확인합니다.

트랙은 M0부터 M6까지입니다. 세 모듈은 클러스터가 필요 없고(Python만), 나머지는 로컬 스택을 `up` → `down` 한 세션으로 띄워서 합니다.

| 모듈 | 통제 | 클러스터 |
|------|------|----------|
| M0 | Cedar 인가: 소유자 / 한도 / 역할 / 동결 | 불필요 |
| M1 | 시프트레프트 스캔 분류(triage) | 불필요 |
| M2 | 신원: 라벨↔ServiceAccount admission | 필요 |
| M3 | 네트워크: Cilium L3/L7/egress | 필요 |
| M4 | 런타임: Tetragon 셸 차단(eBPF) | 필요 |
| M5 | 암호화: WireGuard + etcd 저장 암호화 | 필요 |
| M6 | 에이전트 위임 + ReBAC 그래프 | 불필요 |

[환경 준비 (SETUP)](labs/SETUP.md)부터 보고 [M0](labs/m0/README.md)으로 시작하세요 — 빈 Cedar 정책에서 통과까지 약 5분, 클러스터 불필요. 개념부터 읽고 싶다면 [개념 랩](docs/)이 같은 통제를 먼저 설명합니다.

## 스택 구성

- **IaC** — 클러스터와 Cilium CNI를 선언적 Terraform으로. CI에서 `terraform validate` 수행.
- **제로트러스트 네트워크 (Cilium / eBPF)** — ingress·egress 기본 차단, 최소권한 홉만 허용. `web→api`는 L7(Envoy)이라 계정 API만 도달하고, egress는 다음 홉 + DNS로 잠겨 침해된 파드가 인터넷·클라우드 메타데이터·API 서버에 닿지 못합니다.
- **인가 as-code (Cedar)** — `api`는 매 요청마다 Cedar를 호출하는 PDP입니다: 소유자 확인, 이체 한도, 동결 계좌 거부(forbid), 역할 계층. Amazon Verified Permissions로 이식 가능.
- **런타임 (Tetragon / eBPF)** — db 티어의 셸 실행을 커널에서 SIGKILL하는 `TracingPolicy`(정상 프로세스는 건드리지 않음).
- **신원** — 티어별 ServiceAccount, `app` 라벨을 SA에 묶는 `ValidatingAdmissionPolicy`, 그리고 SPIFFE 상호인증(상시 스위트가 아니라 수동으로 검증되는 configured 상태).
- **데이터** — 전송 중 WireGuard 파드 간 암호화 + etcd 내 Secret 저장 암호화.
- **CI 게이트** — GitHub Actions가 Cedar 테스트·checkov·`terraform validate`·gitleaks를 돌리고, kind 잡이 스택을 띄워 라이브 검증을 재실행합니다.

## 빠른 시작

사전 준비: Python 3.12. 클러스터 경로엔 추가로 Docker, `kind`, `kubectl`, `helm`, `cilium-cli`, `terraform`, 그리고 Git for Windows(.sh 스크립트·채점기는 PowerShell이 아니라 Git Bash에서 실행)가 필요합니다.

```powershell
# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe cedar\authz.py     # 인가 단위테스트, 클러스터 불필요 -> 8/8
powershell -File scripts\up.ps1             # kind + Cilium 프로비저닝, api 빌드, 배포
bash scripts/verify.sh                      # (Git Bash) 계층들을 라이브로 증명
powershell -File scripts\down.ps1           # 정리
```

```bash
# Linux / macOS / CI
python -m venv .venv && ./.venv/bin/python -m pip install -r requirements-dev.txt
./.venv/bin/python cedar/authz.py
bash scripts/up.sh && bash scripts/verify.sh && bash scripts/down.sh
```

## 상태

- `scripts/verify.sh` — kind + Cilium + Tetragon에서 라이브 검증 21/21 (로컬·CI 공통).
- Cedar — 코어 인가 8/8, 에이전트 위임 14/14 (confused-deputy + ASI08 위임깊이 cap). ReBAC — 11/11 (`fga model test`).
- checkov — 452 pass / 0 fail / 5건 문서화된 skip.
- MLS 검증가능성 커버리지 — 65% (26/40); 갭은 [`docs/mls-coverage.csv`](docs/mls-coverage.csv)에 공개.

계층별 상세·검증 노트·로드맵은 [`docs/`](docs/)에 있습니다(로컬에서 `pip install -r requirements-docs.txt && mkdocs serve`로 사이트로도 볼 수 있음).

## 구조

```
terraform/   kind + Cilium + Tetragon (helm)     app/api/    FastAPI Cedar PDP (api 이미지)
cedar/       schema + policies + 단위테스트       k8s/        app, netpol, tracingpolicy, probes
labs/        재구현 트랙 (M0–M6)                   docs/       개념 랩 + 매핑
scripts/     up / verify / scan / down (.ps1+.sh) .github/    CI 워크플로 + kind 설정
```

## 참고

로컬 `kind` 클러스터라 클라우드 비용이 없습니다. Cedar 정책은 Amazon Verified Permissions로, Cilium 정책은 임의의 Cilium 클러스터(EKS / GKE / AKS)로 이식됩니다. `X-User` 신원은 미인증 데모 입력(인젝션 방지용 charset 검증)이며, 실제 시스템은 검증된 JWT `sub`에서 principal을 도출합니다. 엔티티는 이미지에 구운 정적 픽스처입니다. 라이선스: [MIT](LICENSE).
