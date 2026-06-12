# 04 — 티어 온보딩 (새 워크로드 추가)

새 티어(예: `cache`)를 들일 때, **신원 → 정책 → 검증**을 빠짐없이 거치는 체크리스트.
하나라도 빠지면 통제 공백이 생긴다. 예시는 `cache` 티어(api ↔ cache).

---

## 체크리스트

**1) 신원 — ServiceAccount + 데이터 등급 결정**
- `cache`의 MLS 등급 결정(예: 민감 S — 캐시에 개인신용정보 파편이 있으면 기밀 C).
- `k8s/rbac.yaml`에 `cache-sa` 추가(RoleBinding 0 = API 권한 0):
  ```yaml
  apiVersion: v1
  kind: ServiceAccount
  metadata: { name: cache-sa, namespace: shop }
  automountServiceAccountToken: false
  ```

**2) 라벨↔SA admission — 위조 방지에 새 티어 등록**
- `k8s/admission-policy.yaml`의 검증식에 `cache`/`cache-sa` 매핑 추가:
  ```
  ... || (variables.app == 'cache' && variables.sa == 'cache-sa') || ...
  ```

**3) SA-use 게이트 — 티어 SA 목록에 추가**
- `k8s/admission-sa-use.yaml`의 `isTierSA` 식에 `cache-sa` 추가:
  ```
  expression: "variables.sa in ['web-sa', 'api-sa', 'db-sa', 'cache-sa']"
  ```

**4) 네트워크 정책 — 누가 cache에 닿는가(default-deny 위에 최소 허용)**
- `k8s/netpol.yaml`에 `api → cache` 만 허용(ingress) + cache의 egress 최소화:
  ```yaml
  apiVersion: cilium.io/v2
  kind: CiliumNetworkPolicy
  metadata: { name: allow-api-to-cache, namespace: shop }
  spec:
    endpointSelector: { matchLabels: { app: cache } }
    ingress: [{ fromEndpoints: [{ matchLabels: { app: api } }], toPorts: [{ ports: [{ port: "6379", protocol: TCP }] }] }]
  ```

**5) 워크로드 — 하드닝 + 올바른 라벨/SA**
- Deployment: `serviceAccountName: cache-sa`, `labels {app: cache, tier: cache}`,
  `automountServiceAccountToken: false`, non-root/drop-ALL/read-only/seccomp/limits(PSA restricted 통과).

**6) (해당 시) 등급별 데이터 보호**
- 기밀(C)/민감(S)면: 저장 시 암호화 대상에 포함, 런타임 정책(`tier: cache` 셸 차단) 추가 검토.

**7) 검증 — 통제가 실제로 적용됐는지**
```bash
./.venv/Scripts/python.exe -m checkov.main -d k8s --config-file .checkov.yaml --compact   # 0 fail
pwsh scripts/up.ps1 && pwsh scripts/verify.ps1                                              # 회귀 없음
# 새 티어 위조 거부 확인(dry-run):
#   app:cache on api-sa  -> 라벨↔SA DENY
#   shop:deployers가 cache-sa 워크로드 -> SA-use DENY
```

---

## 온보딩 시 흔한 누락(반드시 점검)
- admission **두 정책**(라벨↔SA + SA-use) 중 하나만 갱신 → 위조/오용 경로 열림.
- netpol에서 egress 누락 → 새 티어가 인터넷으로 샐 수 있음(default-deny 위에 명시 허용만).
- 라벨과 SA 불일치 → 자기 정책에 자기가 막힘(롤아웃 실패).

## 다루지 않는 것
- 서비스메시 사이드카 주입, HPA/오토스케일 정책(직교 관심사).
