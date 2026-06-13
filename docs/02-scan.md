# Lab 1 — 쉬프트레프트 스캔 (클러스터 불필요)

!!! tip "직접 해보기 (재구현 트랙)"
    읽었다면 심어둔 결함을 직접 사냥하라 → **[M1 · 쉬프트레프트](../labs/m1/README.md)** (Failed checks 0, 클러스터 불필요).

**목표:** CI가 돌리는 것과 *같은* IaC/K8s 보안 게이트를 직접 돌려 보고, *정직한 triage*를 익힌다 —
왜 "0 findings"가 목표가 아니라 오히려 위험신호인지.

## 실행

```bash
bash scripts/scan.sh        # 또는: pwsh scripts/scan.ps1
```

기대 결과 (checkov가 `terraform/` + `k8s/`를 스캔):

```
Passed checks: 452, Failed checks: 0, Skipped checks: 5
```
(매니페스트가 늘면 passed 수도 늘어난다 — 게이트의 기준은 **Failed checks: 0**.)

## 무엇을 읽나

`.checkov.yaml`에는 **3개**의 전역 suppression이 각각 *문서화된 이유*와 함께 있다
(`CKV_K8S_15` — kind라 `IfNotPresent`; `CKV_K8S_40` — `nginx-unprivileged`가 UID 101을 고침;
`CKV2_K8S_6` — checkov가 CiliumNetworkPolicy CRD를 못 봄). 여기에 *범위가 좁은* annotation
스킵: `k8s/app.yaml`의 로컬 빌드 api 이미지(레지스트리 다이제스트 없음)에 `CKV_K8S_43`,
그리고 일회성 프로브 파드(`k8s/probes.yaml`)의 liveness/readiness.

교훈: 진짜 리뷰는 발견을 *근거와 함께 triage*한다 — 전부 꺼서 green 숫자를 좇지 않는다.
README는 주장 범위를 정확히 한정한다 — checkov는 **워크로드 + Terraform**을 검증하지,
네트워크 정책이나 Cedar는 아니다(그건 각자의 게이트가 있다).

## 이미지 스캔 + SBOM (빌드 프로비넌스)

`scripts/scan.*`는 **이미지 취약점+시크릿 게이트**도 돌리고 **CycloneDX SBOM**도 생성한다 —
`trivy` 설치 여부로 게이트되므로, 위 checkov 게이트는 어디서든 그대로 돈다:

```bash
trivy image --scanners vuln,secret --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 cloudsec-api:local
trivy image --format cyclonedx --output outputs/sbom/cloudsec-api.cdx.json cloudsec-api:local
# 설치 (Windows host): winget install AquaSecurity.Trivy   (또는: brew install trivy)
```

**이 게이트는 실제 취약점을 잡았고 — 우리는 숨긴 게 아니라 고쳤다.** 첫 실행은
`CVE-2025-62727`(HIGH — Range 헤더 병합을 통한 Starlette DoS)에서 실패(`exit 1`)했다.
`fastapi==0.115.6`이 `starlette 0.41.3`을 끌어왔기 때문이다. 조치는 `app/api/requirements.txt`의
의존성 상향(`fastapi 0.115.6→0.136.3`, `starlette 0.41.3→1.3.1`, `uvicorn 0.34.0→0.49.0`)이었고,
api를 재빌드하고 Cedar PDP를 다시 스모크 테스트(alice 200 / bob 403 / 한도초과 403)한 뒤
게이트가 green(`0 vuln / 0 secret`)이 됐다. 그게 쉬프트레프트의 본질이다 —
배포 *전에* 잡고 → 고치고 → green.

**정직한 범위 — 여기 *없는* 것:** 이미지 **서명**. 출시된 `cosign`은 서명을 붙일 레지스트리가
필요하고(sigstore/cosign#3832; no-registry PR #4014은 미머지), 이 `cloudsec-api:local` 이미지는
레지스트리 없이 `kind`에 로드된다. 그래서 서명 / SLSA attestation은 로컬에서 주장하지 않고
**ECR 경로에 문서화**돼 있다([aws-eks-path.md](aws-eks-path.md)) — 가짜 `cosign verify` 검사는 없다.
`--ignore-unfixed`는 checkov의 정직한-suppression 교훈과 같다: *실제로 조치 가능한 것*만 게이트한다.

## 망가뜨려 보기 (그리고 고치기)

1. `k8s/app.yaml`에서 `web` 컨테이너의 `readOnlyRootFilesystem: true`를 지운다.
2. `bash scripts/scan.sh`를 다시 돌린다 → 새 **CKV_K8S_22** 실패가 나타난다.
3. 되살린다. 다시 깨끗해진다.

다음: [Lab 2 — 실제 클러스터에서 네트워크 + 인가](03-network-and-authz.md).
