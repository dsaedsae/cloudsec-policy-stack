# 감사증거 패키지 (예시) — "자격증명 위조 방지" 통제

> **"검증 가능"이 *감사 비용 절감*으로 이어진다**를 한 통제로 끝까지 보인다. 감사자/규제기관이
> 보상통제 이행을 확인할 때 받는 것이, 스크린샷·주장이 아니라 **재현 가능한 테스트 + 통과 캡처**
> 라면 증빙 부담이 줄어든다. 여기서는 통제 **하나**(자격증명 위조 방지)를 요구사항 → 기준 매핑 →
> 산출물 → 증거 → 점검주기 → 잔여위험까지 패키징한다.
>
> ⚠️ **정직 표기:** 아래 ISMS-P 항목번호·전자금융감독규정 조항은 *구조 매핑*이다. 공식
> ISMS-P 인증기준·규정 원문과의 정밀 항목 대조는 인증·제출 단계의 별도 작업이며, 본 문서는
> "증거 패키지의 형태"를 보이는 것이지 인증 확인서가 아니다.

---

## 1. 통제 (control)
**자격증명 위조 방지** — "망 안에 있으니 곧 `api`다"를 깬다.
- `k8s/admission-policy.yaml` — 라벨↔SA 일관성(위조 라벨 거부)
- `k8s/admission-sa-use.yaml` — SA-use gate(인가된 운영자만 티어 SA로 워크로드 실행; Pod/Deployment/Job/**CronJob**)
- `k8s/rbac.yaml` — 티어 SA 권한 0, deployer 최소 Role, `shop:tier-operators` 바인딩
- `k8s/netpol-mutual.yaml` — SPIFFE SVID 상호인증(암호학적 신원, opt-in)

## 2. 요구사항 추적 (requirement trace)
| 출처 | 항목 | 연결 |
|------|------|------|
| **망분리 완화 / MLS** | 보상통제 "강화된 사용자 인증·**자격증명 위조 여부 확인**" (그룹 A, 로드맵 명시) | 망 위치 신뢰 제거 시 신원을 위·변조 못 하게 |
| **전자금융감독규정** | **제15조(해킹 등 방지대책)** 망분리 근거 조항 — *완화된 망분리의 자리를 메우는 보상통제* | ⚠️ 조항 원문 대조 필요 |
| **ISMS-P 인증기준** | **2.5 인증 및 권한관리**(2.5.5 특수계정·권한관리), **2.6 접근통제**(2.6.2 정보시스템 접근, 2.6.3 응용 접근) | 워크로드 신원·권한의 위조 방지 | ⚠️ 항목번호 공식 대조 필요 |
| **NIST SP 800-207** | Tenet 3(세션 단위 접근)·6(접근 전 인증·인가 강제) | 매 생성/요청마다 신원 검증 |

## 3. 증거 (evidence) — 재현 가능한 테스트 + 통과 캡처
**무인가 신원의 위조·오용이 *거부됨*을 증명** (`scripts/verify.{sh,ps1}` 행, 라이브 통과):

```text
forged app:api on web-sa -> admission DENY        expect DENY got DENY  PASS
CI SA runs workload as api-sa -> SA-use DENY        expect DENY got DENY  PASS
CI SA schedules CronJob as api-sa -> SA-use DENY    expect DENY got DENY  PASS
authorized operator deploys api-sa workload -> ADMIT expect ADMIT got ADMIT PASS
api-sa: no create-pods / no read-secrets            expect no   got no   PASS
```

**감사자 직접 재현(server dry-run, 무부작용 — 아무것도 생성되지 않음):**
```bash
# 무인가 CI SA가 api-sa로 워크로드 실행 시도 → SA-use gate가 거부(정책 메시지 포함)
cat <<'YAML' | kubectl --as=system:serviceaccount:shop:ci-deployer --as-group=shop:deployers \
                       create --dry-run=server -f -
apiVersion: apps/v1
kind: Deployment
metadata: { name: audit-probe, namespace: shop, labels: { app: api } }
spec:
  replicas: 1
  selector: { matchLabels: { app: api } }
  template:
    metadata: { labels: { app: api } }
    spec:
      serviceAccountName: api-sa            # 티어 신원으로 실행 시도
      containers: [{ name: c, image: curlimages/curl:8.11.1, command: ["sleep","1"],
        securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true,
        runAsNonRoot: true, runAsUser: 100, capabilities: { drop: ["ALL"] },
        seccompProfile: { type: RuntimeDefault } } }]
YAML
# 기대 출력: error ... "running a workload as tier ServiceAccount 'api-sa' requires an
#            authorized operator ... ; requester 'system:serviceaccount:shop:ci-deployer' is not"
# (verify.sh의 sa_use_deploy / sa_use_cron 함수가 이 검증을 자동화한다.)
```
정책 자체의 존재·바인딩도 증거:
```bash
kubectl get validatingadmissionpolicy shop-sa-use            # 존재
kubectl get validatingadmissionpolicybinding shop-sa-use-binding -o jsonpath='{.spec.validationActions}'  # ["Deny"]
```

## 4. 점검 주기 (control testing cadence)
- **매 변경 시**: CI(`.github/workflows/ci.yml`)가 push마다 `verify.sh`를 클러스터 띄워 재실행 → 통제가 *지금도 막는지* 자동 증명. (망분리 완화 MLS의 **반기 보안점검** 요구와 정렬되는, 더 잦은 연속 점검.)
- **정적 게이트**: checkov 0-fail, cedar 8/8.

## 5. 잔여위험 (residual — 감사자에게 정직하게)
- SPIFFE SVID 상호인증은 **opt-in**(데모 edge). 기본 스위트는 admission 단계까지 증명, 암호학적 신원은 Lab 4 수동.
- `shop:tier-operators`/cluster-admin은 *설계상 신뢰*된다(누가 그 신원을 갖는가는 OIDC/IAM 거버넌스).
- `X-User`는 미인증 데모 입력 — 실서비스는 검증된 JWT `sub`/SVID에서 파생.

## 6. 감사 제출 체크리스트 (복붙)
- [ ] 통제 정의 + 산출물 경로(§1)
- [ ] 요구사항 추적표(§2) + 공식 기준 항목 대조 결과
- [ ] `verify` 통과 캡처(§3) + 재현 명령
- [ ] 정책 존재·바인딩·fail-closed 증거
- [ ] CI 실행 이력(점검 주기 §4)
- [ ] 잔여위험·완화계획(§5)

→ 이 패키지의 핵심: **"있다"가 아니라 "막는다 + 매번 재현된다"**. 감사자가 직접 dry-run으로
검증할 수 있어, 증빙 신뢰성↑·반복 감사비용↓.
