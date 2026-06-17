# Lab 1 — 쉬프트레프트 스캔 (클러스터 불필요)

> **직접 해보기 (재구현 트랙):** 읽었다면 심어둔 결함을 직접 사냥하라 → **[M1 · 쉬프트레프트](../labs/m1/README.md)** (Failed checks 0, 클러스터 불필요).

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

**왜 *쉬프트레프트*인가 — 게이트가 도는 시점.** 이 검사는 매니페스트가 클러스터에 닿기 *전에*,
즉 PR/CI에서 정적으로 돈다. 같은 룰을 *런타임에* 거는 계층(admission/PSA — [Lab 4](05-identity.md)·
M1 구두 8번)은 잘못 짠 파드를 `apply` 시점에 거부하지만, 그땐 이미 누군가 그 매니페스트를 작성·머지·
배포 파이프라인에 태운 *뒤*다. checkov를 PR에 두면 그 비용을 **머지 전에** 0으로 만든다 — 피드백이
초 단위로 돌아오고(클러스터 기동 불필요), 결함이 main에 들어오기 전에 죽는다. 둘은 경쟁이 아니라
*같은 룰을 다른 시점에* 치는 보완재다: 쉬프트레프트는 *싸고 빠르게 미리*, admission은 *우회 불가능한
최종 강제*. 어느 한쪽만으론 빈틈이 생긴다 — checkov는 콘솔에서 직접 `kubectl apply`한 것·operator가
만든 파드를 못 보고(린터는 게이트를 안 타는 경로엔 장님), admission은 PR 리뷰어에게 *왜 막혔는지*를
머지 전에 못 알려준다.

**CI-게이트 의미론 — `Failed > 0`이면 빌드를 깬다.** checkov는 실패 체크가 하나라도 있으면 비제로로
종료하고, `scripts/scan.sh`는 `set -euo pipefail`이라 그 비제로에서 즉시 멈춘다([`scripts/scan.sh`](../scripts/scan.sh)
는 콘솔 요약을 살리려 `terraform`·`k8s`를 두 번에 나눠 돈다). CI도 같은 게이트다 —
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml)의 `policy` 잡은 한 줄
(`checkov -d terraform -d k8s --config-file .checkov.yaml --compact`)로 같은 설정파일을 돌리므로,
**Failed>0 = 잡 실패 = 머지 차단**이다. 즉 "스캐너가 경고를 찍는다"가 아니라 "빌드가 빨개진다" — 권고가 아니라 게이트다.
(주의: 그래도 checkov의 본질은 *파일을 읽는 린터*이지 admission이 아니다 — M1 구두 9번.)

## 무엇을 읽나

`.checkov.yaml`에는 **3개**의 전역 suppression이 각각 *문서화된 이유*와 함께 있다
(`CKV_K8S_15` — kind라 `IfNotPresent`; `CKV_K8S_40` — `nginx-unprivileged`가 UID 101을 고침;
`CKV2_K8S_6` — checkov가 CiliumNetworkPolicy CRD를 못 봄). 여기에 *범위가 좁은* annotation
스킵: `k8s/app.yaml`의 로컬 빌드 api 이미지(레지스트리 다이제스트 없음)에 `CKV_K8S_43`,
그리고 일회성 프로브 파드(`k8s/probes.yaml`)의 liveness/readiness.

교훈: 진짜 리뷰는 발견을 *근거와 함께 triage*한다 — 전부 꺼서 green 숫자를 좇지 않는다.
README는 주장 범위를 정확히 한정한다 — checkov는 **워크로드 + Terraform**을 검증하지,
네트워크 정책이나 Cedar는 아니다(그건 각자의 게이트가 있다).

**진짜 결함 vs 정당한 스킵 — 둘을 가르는 선.** 하나의 Failed는 두 가지 중 하나다. (1) *고쳐야 할
결함* — 매니페스트가 실제로 위험하다(예: `readOnlyRootFilesystem` 누락 → 위 "망가뜨려 보기"의
CKV_K8S_22). 답은 매니페스트를 고치는 것이지 룰을 끄는 게 아니다. (2) *맥락상 적용 불가* —
룰이 이 데모 환경에선 의미 없다. 답은 **이유를 적은 스킵**이다. `.checkov.yaml`의 세 전역 스킵이
정확히 (2)이고, 각 줄에 *왜 안전한지*가 주석으로 붙어 있다는 게 핵심이다 —
`CKV_K8S_15`는 kind에 로컬 로드한 이미지라 당겨올 레지스트리가 없어서, `CKV_K8S_40`은
`nginx-unprivileged` 이미지가 UID 101로 고정돼 있어서, `CKV2_K8S_6`은 정책이 CiliumNetworkPolicy
CRD로 *존재하는데* checkov의 네이티브 체크가 그 CRD를 못 봐서다. 규율의 비대칭에 주의하라:
스킵은 **좁을수록**, **이유가 검증 가능할수록** 정당하다. 그래서 `CKV_K8S_43`은 *전역* 스킵에서
빠졌다 — web/db/probe 이미지는 `@sha256`으로 핀돼 있고, 면제가 *필요한* 단 하나(레지스트리
다이제스트가 없는 로컬 빌드 api 이미지)만 `k8s/app.yaml`에 *범위가 좁은* annotation으로 스킵된다.
나머지 워크로드는 여전히 다이제스트 핀을 강제받는다. "이유 없는 스킵"이 감사에서 가장 위험하다 —
green인데 통제가 없는, 정확히 *주장하나 미검증*(CONFIGURED) 범주다(M1 Step 3).

**정직한 한계 — 스캐너는 *알려진 패턴*만 본다.** checkov가 잡는 건 룰 셋에 *이미 적힌* 오설정
패턴이다(privileged, 누락된 securityContext, 비핀 이미지…). 매니페스트가 문법적으로 멀쩡하고
모든 CKV를 통과해도, **앱 로직의 결함**(권한 우회, 인가 분기 실수)이나 **신종/제로데이 취약점**은
패턴 매칭의 사정권 밖이다 — 룰이 없으면 안 잡힌다. 그래서 `Failed: 0`은 "이 매니페스트에 *알려진*
오설정이 없다"는 뜻이지 "안전하다"가 아니다. 이게 스택이 한 계층으로 끝나지 않는 이유다:
인가 로직은 Cedar 단위 테스트가, 알려진 취약점은 trivy가(아래), 침해 *후* 행위는 런타임 탐지가
([Lab 3](04-runtime.md)) 각각 다른 사정권을 맡는다. 정적 스캐너는 *값싼 첫 그물*이지 마지막 그물이 아니다.

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
