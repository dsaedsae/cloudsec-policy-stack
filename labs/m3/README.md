# M3 — 네트워크: Cilium 제로트러스트 (L3/L7 + egress)

[모듈 4 / 7]{ .lab-progress } · [스택 Cilium L3/L7]{ .lab-badge } · [소요 ~30–45m]{ .lab-badge } · [클러스터 필요 · RAM~6–8GB]{ .lab-badge .cluster } · [비용 $0 로컬]{ .lab-badge }

**미션:** default-deny에서 시작해 **최소권한 홉**(외부→web→api→db)만 여는 CiliumNetworkPolicy를
직접 구성한다. L7으로 web→api 경로를 메서드/path까지 제한하고, egress도 default-deny로 막는다.

**클러스터 필요.** **편집 파일:** `labs/m3/netpol.yaml` (허용 홉 5개의 rule).

> 선행: M2 권장(같은 클러스터 세션). 배경: [`docs/03-network-and-authz.md`](../../docs/03-network-and-authz.md).

---

## Step 0 — 베이스라인

> 클러스터가 떠 있다고 가정한다(M2~M5 한 세션). 안 떴으면 PowerShell에서 `scripts\up.ps1` 먼저.
> 채점기는 **Git Bash**에서 (forward slash). [SETUP](../SETUP.md).

```bash
# Git Bash 창에서:
kubectl cluster-info --context kind-cloudsec   # 떴는지 확인 (에러면 → PowerShell: scripts\up.ps1)
bash labs/m3/grade.sh        # 시작: web->db는 차단되지만(베이스라인 default-deny), 허용 홉들이 비어서
                             #        web->api 200·api->db 200 이 FAIL (과차단)
```

> 두 베이스라인(default-deny-ingress, DNS egress)은 완성돼 있어 **차단은 처음부터 된다**. 문제는
> *허용*이 비어서 정상 트래픽까지 막히는 것. 보안은 "다 막기"가 아니라 "필요한 것만 열기" — 과차단도
> 결함이다(가용성).

## Step 1 — 허용 홉 5개 작성

`labs/m3/netpol.yaml`의 TODO 5곳을 채워라. 핵심 문법:

```yaml
# ingress 허용 (L3/L4): 누구로부터(fromEndpoints) 어느 포트로
ingress:
  - fromEndpoints: [{ matchLabels: { app: <src> } }]
    toPorts: [{ ports: [{ port: "8080", protocol: TCP }] }]

# L7 HTTP 제한 (web->api 에만): toPorts 안에 rules.http
    toPorts:
      - ports: [{ port: "8080", protocol: TCP }]
        rules:
          http:
            - { method: "GET",  path: "/accounts/[^/]+$" }
            - { method: "POST", path: "/accounts/[^/]+/transfer$" }

# ingress 외부 진입(web): fromEntities: ["cluster"]
# egress 허용: toEndpoints + toPorts (방향만 다름)
```

| TODO | 규칙 |
|---|---|
| `allow-web-to-api` | app:web 에서 8080, **L7으로 GET /accounts/... + POST .../transfer 만** (auditlogs는 자동 403) |
| `allow-api-to-db` | app:api 에서 8080 (L3/L4) |
| `allow-ingress-to-web` | `fromEntities: ["cluster"]` 8080 |
| `egress-web-to-api` | app:api 로 8080 |
| `egress-api-to-db` | app:db 로 8080 |

```bash
bash labs/m3/grade.sh        # 7/7 PASS → M3 GRADUATED. 채점 후 canonical 자동 복원.
```

> db에 egress 규칙을 *안* 주는 게 의도다 — DNS 베이스라인만 적용돼 db는 DNS 외 아무 데도 못 나간다
> (가장 잠긴 tier). "안 적는 것"도 정책이다.

## Step 2 — break-and-fix (예측 → 확인)

1. `allow-web-to-api`의 L7 `rules.http`를 통째로 지우고 포트만 남긴다 → auditlogs 케이스는? (힌트: L7이 사라지면)
2. `egress-web-to-api`를 지운다 → web->api 200 케이스는? egress도 막혔으니.
3. `default-deny-ingress`를 지운다 → web->db 차단 케이스는? (Cilium은 *어떤* 정책이 endpoint를 고르면 그 방향이 default-deny가 된다 — 이 미묘함을 직접 보라)

<details><summary>1번 후 열 것</summary>L7 rules가 없으면 web→api 8080 전체가 열린다 → /auditlogs도 200이 되어 "L2 403" 케이스 FAIL. L7은 *네트워크 계층에서* path/method를 막는 것 — 앱(Cedar)에 닿기 전에 차단하는 다층 방어의 한 겹.</details>

## Step 3 — 구두 문답

1. <details><summary>"제로트러스트"가 이 정책에서 구체적으로 뭘 의미하나?</summary>위치(같은 네임스페이스/네트워크)로 신뢰하지 않음. 모든 ingress·egress가 default-deny이고, web→api→db라는 *명시적 최소권한 홉*만 연다. 털린 web 파드도 인터넷/메타데이터/apiserver/db에 직접 못 간다.</details>
2. <details><summary>egress 통제가 왜 ingress만큼 중요한가?</summary>현실 공격은 침입 후 *나가는* 트래픽(C2 비콘·데이터 유출). egress default-deny가 그걸 막는다. 메타데이터 IP(169.254.169.254) 차단은 클라우드 크레덴셜 탈취(SSRF) 방어.</details>
3. <details><summary>L7(http rules)과 L3/L4(port)의 차이는? 왜 web→api만 L7인가?</summary>L3/L4는 "이 포트로 와도 되나", L7은 "이 메서드+경로로 와도 되나". web→api는 공개 진입점이라 경로 제한이 가치 큼(auditlogs 차단). api→db는 내부라 L3/L4로 충분.</details>
4. <details><summary>db에 egress 규칙을 안 준 이유는?</summary>DNS 베이스라인(모든 파드 대상)이 db도 egress 규칙 보유 상태로 만들어 → DNS 외 전부 차단. 가장 민감한 데이터 tier를 가장 잠근다. "규칙 없음"이 곧 "DNS만 허용"이 되는 Cilium 의미.</details>
5. <details><summary>이 네트워크 통제와 M2(신원)·Cedar(앱 인가)는 어떻게 겹치나?</summary>한 요청이 admission(신원)→netpol(L3/L7)→Cedar(per-request) 순서로 *모두* 통과해야 데이터에 닿는다. 같은 L7 허용 경로라도 principal이 다르면 Cedar가 다르게 판정(alice 200 vs bob 403). 다층 방어.</details>

## 졸업 기준

- [ ] `grade.sh` **7/7 PASS**
- [ ] Step 2의 깨질 케이스 사전 예측 + Cilium의 "정책이 고르면 그 방향 default-deny" 의미 이해
- [ ] L7과 L3/L4를 언제 쓰는지, egress 통제의 공격 시나리오를 설명할 수 있다
- [ ] 구두 문답 5개 답안 없이
- [ ] `k8s/netpol.yaml`과 비교

다음: **M4 — Tetragon 런타임** (같은 세션에서).
