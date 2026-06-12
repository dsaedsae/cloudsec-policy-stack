# 01 — 사고대응 (Incident Response)

이 스택의 탐지 신호 3종에 대한 분류·대응 절차. 공통 흐름: **탐지 → 분류(오탐/실제) →
증거 보존 → 격리 → 복구 → 사후**.

> 컨텍스트 `kind-cloudsec`. AWS(EKS) 변형은 각 절에 별도 표기. 데모 범위라 SIEM/티켓팅 연동은
> 없음 — 실제 운영은 아래 신호를 SIEM(예: Security Hub/OpenSearch)으로 보낸다.

---

## A. Tetragon SIGKILL — 데이터 티어에서 셸 실행 시도

**증상:** `db` 파드에서 셸 exec가 in-kernel SIGKILL(137). 데이터 티어는 셸을 띄울 일이 없으므로
**침해 의심 1순위**.

**1) 탐지/확인 — 프로세스 트리(증거 먼저):**
```bash
# Tetragon 이벤트 스트림에서 차단된 exec와 조상 프로세스 확인
kubectl -n kube-system logs ds/tetragon -c export-stdout --tail=500 | grep -E "process_exec|process_kprobe" | grep -i "shop/db"
```
무엇을 보나: `binary`(/bin/sh 등), `arguments`, `pod`, **부모 프로세스 체인**(누가 셸을
띄웠나 — 앱 프로세스? 사이드카? 외부 셸?).

**2) 분류:**
- **오탐 가능성:** 디버그용 `kubectl exec`를 *사람이* 의도적으로 했나? → 운영자 확인. 의도된
  디버그면 사고 아님(단, 데이터 티어 직접 exec 자체가 정책 위반이므로 기록).
- **실제 의심:** 부모가 앱 프로세스(nginx 등)거나 알 수 없는 바이너리 → **앱이 장악되어 셸을
  스폰**한 신호. 사고로 격상.

**3) 증거 보존(파드 죽이기 전에):**
```bash
DB=$(kubectl -n shop get pod -l tier=data -o jsonpath='{.items[0].metadata.name}')
kubectl -n shop describe pod "$DB" > evidence-$DB.txt
kubectl -n shop logs "$DB" --all-containers > evidence-$DB-logs.txt
kubectl -n kube-system logs ds/tetragon -c export-stdout --tail=2000 > evidence-tetragon.txt
# (선택) 프로세스/네트워크 상태 스냅샷이 필요하면 Hubble 플로우도 같이:
kubectl -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg monitor --type drop > evidence-drops.txt &
```

**4) 격리(전파 차단):** 해당 파드를 네트워크에서 끊는다(삭제보다 격리가 증거 보존에 유리).
⚠️ Cilium 정책은 **allow-list 가산식**이라 빈 `ingress: []`는 아무것도 *빼지* 못한다(파드가
여전히 `app=db`라 `allow-api-to-db`가 계속 허용). 실제 격리는 **deny 규칙**(allow보다 우선)으로
한다:
```bash
kubectl -n shop label pod "$DB" quarantine=true --overwrite
cat <<'YAML' | kubectl apply -f -
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: { name: quarantine, namespace: shop }
spec:
  endpointSelector: { matchLabels: { quarantine: "true" } }
  ingressDeny:
    - fromEntities: ["all"]
  egressDeny:
    - toEntities: ["all"]
YAML
```
→ deny 규칙이 기존 allow를 덮어 in/out 전부 차단. 파드는 살아 있어 포렌식 가능하고,
Deployment가 새 파드를 띄워 가용성 유지. (대안: `kubectl label pod "$DB" app- tier-`로 티어
신원을 떼면 tier 허용에서 빠지지만, 모든-파드 DNS egress는 남으므로 완전 차단엔 deny 규칙이 확실.)

**5) 복구:**
- 원인이 이미지/코드 취약점이면 **패치된 이미지로 롤아웃**([05 배포·롤백](05-deploy-rollback.md)).
- 격리 파드 분석 끝나면 삭제: `kubectl -n shop delete pod "$DB"` + `quarantine` CNP 제거.
- TracingPolicy를 더 좁히거나(예: `/python`,`/nc` 추가) 강화.

**EKS 변형:** Tetragon 이벤트를 export-stdout → Fluent Bit → CloudWatch/OpenSearch. GuardDuty
EKS Runtime Monitoring을 병행하면 관리형 탐지가 같은 신호를 본다.

---

## B. Cedar 403 급증 — 인가 거부 폭증

**증상:** `api`가 403(`Cedar denied: ...`)을 평소보다 많이 반환.

**1) 탐지:**
```bash
kubectl -n shop logs deploy/api --tail=500 | grep -c "Cedar denied"
kubectl -n shop logs deploy/api --tail=500 | grep "Cedar denied" | sort | uniq -c | sort -rn
```

**2) 분류:**
- **공격 패턴:** 한 principal이 여러 계좌를 순회(`bob`이 여러 `acct-*` 시도) → 권한 상승/열거 시도.
- **오탐/배포 사고:** 정책 변경 직후 정상 요청이 막힘 → 정책 회귀. `cedar/authz.py`로 즉시 재현 검증:
  ```bash
  ./.venv/Scripts/python.exe cedar/authz.py   # 8/8 깨지면 정책 회귀 확정
  ```

**3) 대응:**
- 공격이면: 해당 principal 추적(실서비스는 JWT `sub`). 데모는 X-User라 차단은 상위(게이트웨이/
  WAF) 책임 — 런북엔 "principal 식별 → 상위 차단" 으로 기록.
- 정책 회귀면: [05 배포·롤백](05-deploy-rollback.md)으로 직전 정책으로 롤백 후 `authz.py` 재검증.

---

## C. Cilium DROP 급증 — 네트워크 정책 드롭 폭증

**증상:** 정책에 막힌 트래픽이 급증(스캔/측면이동 시도, 또는 정책 오설정).

**1) 탐지(어떤 신원→어디가 막혔나):**
```bash
# 실시간 드롭 모니터(신원 라벨 포함)
kubectl -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg monitor --type drop
# (Hubble CLI가 있으면) 정리된 플로우:
hubble observe -n shop --verdict DROPPED --last 200
```

**2) 분류:**
- **측면이동 의심:** `web`이 `db`로 직접(정책상 000), 또는 어떤 파드가 인터넷/메타데이터(169.254.169.254)
  /API서버(10.96.0.1)로 egress 시도 → **장악된 워크로드의 비콘/유출 시도** 신호.
- **오설정:** 정상 홉이 막힘 → netpol 회귀. `scripts/verify.*`로 즉시 확인.

**3) 대응:**
- 측면이동이면 출발 파드를 [A.4 격리]. egress 시도면 이미 default-deny로 막혀 있으니 **출발지
  파드 침해 분석**에 집중.
- 오설정이면 netpol 롤백 + `verify` 재검증.

---

## 이 런북이 다루지 *않는* 것
- SIEM/티켓/온콜 알림 연동(데모 범위 밖 — 신호 export 지점만 표기).
- 포렌식 디스크 이미징·메모리 덤프(컨테이너 수명주기상 범위 밖, 운영은 노드 스냅샷).
- 사용자(X-User)는 미인증 데모 입력이라 "principal 차단"은 상위 계층 책임으로 위임.
