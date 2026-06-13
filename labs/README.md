# 재구현 트랙 — 직접 만들며 전문가가 된다

이 스택의 모든 통제는 **실행 가능한 검증**(verify 스위트·단위테스트)을 갖고 있다. 이 트랙은
그 검증기를 **자동 채점기**로 뒤집는다: 통제 하나를 **빈 파일에서 직접 재구현**하면 채점기가
PASS/FAIL로 판정한다. 따라치기가 아니라 — 스펙만 보고 쓰고, 틀리면 *왜* 틀렸는지 채점으로 배운다.

!!! tip "처음이라면"
    **[M0](m0/README.md)** 부터. 클러스터가 필요 없고 Python만 있으면 된다 — 5분이면 첫 채점을 본다.

!!! note "돌아온 학습자 / 면접 직전"
    각 모듈의 **구두 문답**(접힌 답안)으로 복습하라. 어느 모듈이든 사이드바에서 1클릭으로 점프.

## 모듈 사다리

```mermaid
flowchart LR
    M0[M0 · Cedar 인가] --> M1[M1 · 스캔] --> M2[M2 · 신원]
    subgraph S["클러스터 1세션 · up → down"]
      direction LR
      M2 --> M3[M3 · 네트워크] --> M4[M4 · 런타임] --> M5[M5 · 암호화]
    end
    M5 --> M6[M6 · 에이전트]
    classDef nc fill:#e8eaf6,stroke:#3f51b5,color:#1a237e;
    classDef cl fill:#fff3e0,stroke:#c2410c,color:#7c2d12;
    class M0,M1,M6 nc;
    class M2,M3,M4,M5 cl;
```

??? abstract "각 모듈의 학습 루프 (strip → rebuild → 채점 → 복원)"
    ```mermaid
    flowchart LR
        K[스켈레톤<br/>strip된 통제] --> W["내가 작성<br/>labs/m·/ 만 편집"]
        W --> G{{"채점기 = 유일한 판정자"}}
        G -- FAIL --> W
        G -- PASS --> R[canonical<br/>자동 복원]
        classDef judge fill:#1a1a2e,stroke:#3f51b5,color:#a5d6a7;
        class G judge;
    ```
    클러스터 채점기는 학습자 아티팩트를 적용해 검증한 뒤 **canonical 정책을 자동 복원**한다 —
    스택은 항상 known-good 상태로 돌아온다.

<div class="grid cards" markdown>

-   :material-numeric-0-circle:{ .lg .middle } **M0 · 인가 as-code (Cedar)**

    ---

    [클러스터 불필요]{ .lab-badge .no-cluster }

    빈 정책에서 owner·한도·역할·동결 인가를 작성. 졸업: **core 8 + ext 3 = 11/11**.

    `python labs/m0/grade.py`{ .lab-grade }

    [:octicons-arrow-right-24: M0 시작](m0/README.md)

-   :material-numeric-1-circle:{ .lg .middle } **M1 · 쉬프트레프트 (checkov)**

    ---

    [클러스터 불필요]{ .lab-badge .no-cluster }

    신입이 짠 워크로드의 **16개 결함을 사냥**해 수정. 졸업: **Failed checks 0**.

    `python labs/m1/grade.py`{ .lab-grade }

    [:octicons-arrow-right-24: M1 시작](m1/README.md)

-   :material-numeric-2-circle:{ .lg .middle } **M2 · 신원 (admission CEL)**

    ---

    [클러스터 필요]{ .lab-badge .cluster }

    라벨↔SA 일관성 VAP의 CEL을 작성. 졸업: 위조 DENY / 정합 ADMIT **5/5**.

    `bash labs/m2/grade.sh`{ .lab-grade }

    [:octicons-arrow-right-24: M2 시작](m2/README.md)

-   :material-numeric-3-circle:{ .lg .middle } **M3 · 네트워크 (Cilium)**

    ---

    [클러스터 필요]{ .lab-badge .cluster }

    default-deny에서 최소권한 홉(L3/L7/egress)을 재구성. 졸업: **7/7**.

    `bash labs/m3/grade.sh`{ .lab-grade }

    [:octicons-arrow-right-24: M3 시작](m3/README.md)

-   :material-numeric-4-circle:{ .lg .middle } **M4 · 런타임 (Tetragon eBPF)**

    ---

    [클러스터 필요]{ .lab-badge .cluster }

    셸 exec만 골라 SIGKILL하는 TracingPolicy. 졸업: **id=0 + sh=137**.

    `bash labs/m4/grade.sh`{ .lab-grade }

    [:octicons-arrow-right-24: M4 시작](m4/README.md)

-   :material-numeric-5-circle:{ .lg .middle } **M5 · 암호화 (실행·해석)**

    ---

    [클러스터 필요]{ .lab-badge .cluster }

    WireGuard 캡처·etcd 암호화를 직접 돌리고 해석. 졸업: **ET1 채점 + 해석**.

    `bash labs/m5/grade.sh`{ .lab-grade }

    [:octicons-arrow-right-24: M5 시작](m5/README.md)

-   :material-numeric-6-circle:{ .lg .middle } **M6 · 프런티어 (agent-ABAC + ReBAC)**

    ---

    [클러스터 불필요]{ .lab-badge .no-cluster }

    AI 에이전트 위임을 ABAC 교집합 + ReBAC 그래프로. 졸업: **12/12 + 11/11**.

    `python labs/m6/grade.py`{ .lab-grade }

    [:octicons-arrow-right-24: M6 시작](m6/README.md)

</div>

## 형식 (모든 모듈 공통)

1. **읽기** — `docs/`의 개념 랩으로 정리 (이미 잘 써져 있다)
2. **재구현** — `labs/<모듈>/`의 스켈레톤에 스펙만 보고 작성 → 채점기로 채점
3. **break-and-fix** — 동작하는 내 답을 일부러 망가뜨리고, *어느 시나리오가 깨질지 먼저 예측*한 뒤 확인
4. **구두 문답** — 면접에서 나올 "왜?" (접힌 답안 — 먼저 소리 내어 답하고 열 것)
5. **졸업 과제** — 스펙에 없던 확장을 직접 설계·구현

## 규칙

- **정답을 먼저 보지 않는다.** repo의 canonical 파일(`cedar/policies.cedar`, `k8s/*.yaml` 등)이
  곧 정답지다 — 졸업 **후** `diff`로 내 답과 비교하는 것이 마지막 단계다.
- **편집은 `labs/<모듈>/` 안의 작업 파일만.** canonical을 건드리면 스택·채점기가 같이 망가진다.
- **채점기가 유일한 판정자다.** "된 것 같다"는 없다 — 이 repo의 철학 그대로.
- **클러스터 모듈(M2–M5)은 한 세션에 묶어서**: `scripts/up.ps1` → M2→M3→M4→M5 연속 → `scripts/down.ps1`.
