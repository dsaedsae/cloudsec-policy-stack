# ReBAC 데모 — 관계기반 인가 (OpenFGA)

이 디렉터리는 [`docs/authorization-model.md` §4](../docs/authorization-model.md)가 명시적으로 지목한
갭을 채운다: `api` PDP는 **Cedar / ABAC**이고, **ReBAC**(Zanzibar식 관계 그래프 — OpenFGA / SpiceDB)은
미구현 프런티어였다. 여기서는 그것을 집중적이고 **실행 가능한** 데모로 —
[`cedar/authz.py`](../cedar/authz.py)의 OpenFGA 쌍둥이로 — 보인다.

## 무엇을 증명하나 (ABAC로는 깔끔히 표현 못 하는 관계)

AI 에이전트(비인간 신원, NHI)는 **계좌 소유자가 그 에이전트에게 위임했을 때에만** 계좌를
조회/이체할 수 있다 — 두 관계를 가로지르는 그래프 조인:

```
account.owner = alice   AND   alice.delegate = assistant
        └──────────────  delegate from owner  ──────────────┘
```

에이전트의 도달은 *소유자와의 관계에서 파생*되지, 에이전트가 들고 있는 속성에서 오지 않는다.
여기에 NHI 소유권도 더한다: `workload`는 `team`이 소유하고, 팀 멤버가 전이적으로 운영한다
(`member from owner_team`).

| 검사 | 결과 | 이유 |
|---|---|---|
| `agent:assistant` → `can_view` `acct-alice` | ✅ allow | `delegate from owner` (alice 소유 + 위임) |
| `agent:assistant` → `can_view` `acct-bob` | ⛔ deny | bob의 위임 엣지 없음 |
| `user:carol` → `can_view` `acct-alice` | ⛔ deny | 관계 경로 없음 |
| `user:bob` → `can_admin` `billing-job` | ✅ allow | `member from owner_team` (payments 팀) |
| `user:alice` → `can_admin` `billing-job` | ⛔ deny | payments 팀 아님 |

## 실행

**Canonical (결정적, 서버 불필요 — 검증가능 기준):**

```bash
# native CLI (https://github.com/openfga/cli):  winget install openfga.cli   (또는 go install)
fga model test --tests rebac/store.fga.yaml
# 또는, native 설치 없이 docker로:
docker run --rm -v "$PWD/rebac:/data" openfga/cli:latest model test --tests /data/store.fga.yaml
```

기대 결과: `Tests 1/1 passing  Checks 11/11 passing`.

**선택적 라이브 재검증 (docker 필요) — *같은* 관계를 실제 OpenFGA `/check` HTTP API에 대고:**

```bash
python rebac/check_live.py        # openfga/openfga를 띄우고, /check를 단언하고, 내린다
```

기대 결과: `11/11 live /check scenarios passed`. docker가 없으면 정직하게 SKIP(exit 0).

## 정직한 범위

- 이건 Cedar PDP가 위임/소유권 엣지를 위해 **참조할 관계 oracle**이다 — **설계 수준**이지,
  라이브 `verify.*` 21-check 클러스터 스위트에 *연결돼 있지 않고*, 도는 `api` PDP는 요청 중에
  OpenFGA를 **호출하지 않는다**.
- 튜플은 Cedar 데모와 같은 `alice` / `account` 엔티티를 재사용하므로, 둘은 하나의 세계로 합성된다
  (Cedar = per-request ABAC; OpenFGA = 관계 그래프).
- 최소 데모이지 프로덕션 위임 시스템이 아니다(모델 1개 + 테스트 파일 1개).

함께 보기: [`cedar/agent/`](../cedar/agent/) — 같은 위임 아이디어를 Cedar의 **ABAC 교집합**
(에이전트 천장 ∧ 대행 사용자 등급)으로, 그리고 [`docs/nhi.md`](../docs/nhi.md)의 NHI 생애주기 프레이밍.
