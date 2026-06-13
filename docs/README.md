# Learning path

A guided way to study this repo — each lab builds on the last and shows the
payoff *before* asking you to install more. Defensive/infra only.

> **Why this matters (금융 망분리 완화):** 이 스택이 *어떤 규제 맥락에서 왜 중요한지*는
> **[금융 망분리 완화(MLS) ↔ 통제 매핑](financial-mls-mapping.md)** 참고 — FSC 「금융분야
> 망분리 개선 로드맵」(2024-08-13)의 다층보안(MLS) 보상통제에 각 통제를 1:1 매핑하고
> NIST 800-207·검증 항목까지 연결한다.
>
> **정량 평가:** **[검증가능성 커버리지 분석](evaluation-coverage.md)**(MLS 보상통제의 65%가 코드로
> 검증가능 — 갭 공개) · **감사 적용:** **[감사증거 패키지 예시](audit-evidence.md)**(1통제를 기준·산출물·
> 증거·재현명령까지).
>
> **인가 모델 포지셔닝:** **[RBAC + ABAC 하이브리드 · policy-as-code · 지속평가](authorization-model.md)**
> — 이 스택이 인가 지형(RBAC/ABAC/ReBAC/PaC/지속평가)의 어디에 정렬되는지, ReBAC 갭과
> AI에이전트/NHI 확장까지.
>
> **클라우드로 가면 (비용 포함):** **[로컬 → AWS/EKS 경로 + 가격대별 실습 가이드](aws-eks-path.md)**
> — 각 통제의 AWS 등가물(Cedar→Verified Permissions, etcd암호화→KMS 등) + **무료(로컬)부터**
> Tier 0~3 비용 사다리와 teardown 체크리스트. 발표용 자료: [`presentation/`](../presentation/talk-outline.md).

| Lab | You'll learn | Needs | Time |
|-----|--------------|-------|------|
| [0 — Authorization as code](01-authz-no-cluster.md) | Cedar policies + how `forbid`/limits/roles work, unit-tested | Python only | 5 min |
| [1 — Shift-left scanning](02-scan.md) | checkov on IaC + K8s, and *honest* suppression triage | Python only | 5 min |
| [2 — Network + app authz](03-network-and-authz.md) | one request through Cilium L3 → L7 → Cedar; break each and watch it react | Docker+kind | 20 min |
| [3 — Runtime (eBPF)](04-runtime.md) | Tetragon detects + SIGKILLs a shell in a popped container | Docker+kind | 10 min |
| [4 — Identity (B7)](05-identity.md) | who gets to *be* `web`/`api`: least-priv SAs, label↔SA admission, mutual auth — and the honest residual | Docker+kind | 15 min |
| [5 — Data protection](06-data-protection.md) | the data itself: WireGuard in-transit, Secret encryption at-rest, PDP minimization in-use | Docker+kind | 15 min |

## The idea in one picture

Four independent layers guard the **same** asset (the `api`). Each stops an
attack the others can't see:

```
attacker / bad request
   │  forges its pod identity ....... admission (label↔SA) + mutual auth → denied
   │  wrong pod identity ............ Cilium L3   → dropped (no route)
   │  disallowed HTTP path/method ... Cilium L7   → 403 (Envoy)
   │  not the owner / over limit .... Cedar (app) → 403 (PDP decision)
   │  tries to exfiltrate outbound .. Cilium egress → dropped
   │  sniffs the wire / reads etcd .. WireGuard + Secret-at-rest encryption → ciphertext
   ▼  pops the container, runs a shell  Tetragon   → SIGKILL (eBPF)
```

`scripts/verify.{sh,ps1}` proves the enforcement live. Start at **Lab 0** — it needs
nothing but Python and takes five minutes.
