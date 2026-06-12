# 실습 트랙 — 직접 재구현하며 전문가 되기

이 스택의 모든 통제는 **실행 가능한 검증**(verify 스위트, 단위테스트)을 갖고 있다. 이 트랙은
그 검증기를 **자동 채점기**로 뒤집는다: 통제 하나를 **빈 파일에서 직접 재구현**하고, 채점기가
PASS/FAIL로 판정한다. 따라치기가 아니라 — 스펙만 보고 쓰고, 틀리면 왜 틀렸는지 채점 결과로
배운다.

## 형식 (모든 모듈 공통)

1. **읽기** — 기존 `docs/` 랩 문서로 개념 정리 (이미 잘 써져 있다)
2. **재구현** — `labs/<모듈>/`의 스켈레톤 파일에 스펙만 보고 직접 작성 → `grade.py`로 채점
3. **break-and-fix** — 동작하는 내 답을 일부러 망가뜨리고, *어느 시나리오가 깨질지 먼저 예측*한 뒤 확인
4. **구두 문답** — 면접에서 나올 "왜?" 질문 (모범답안은 접힘 — 먼저 소리 내어 답해보고 열 것)
5. **졸업 과제** — 스펙에 없는 확장 요구를 받아 직접 설계·구현 (채점기에 ext 시나리오 내장)

## 규칙

- **정답을 먼저 보지 않는다.** 이 repo의 canonical 파일(`cedar/policies.cedar`, `k8s/*.yaml` 등)이
  곧 정답지다 — 졸업 **후에** 내 답과 `diff` 하며 리뷰하는 것이 마지막 단계다.
- **편집은 `labs/<모듈>/` 안의 작업 파일만.** canonical 파일을 건드리면 스택과 채점기가 같이 망가진다.
- **채점기가 유일한 판정자다.** "된 것 같다"는 없다 — 이 repo의 철학 그대로.
- **클러스터 모듈(M2–M5)은 한 세션에 묶어서**: `scripts/up.ps1` → 연속 실습 → `scripts/down.ps1` (RAM).

## 모듈 사다리

| 모듈 | 주제 | 클러스터 | 졸업 과제 (자동채점) | 채점 |
|---|---|---|---|---|
| **[M0](m0/README.md)** | **인가 as-code (Cedar)** | ❌ 불필요 | 빈 정책에서 core 8 + ext 3 = **11/11** | `python labs/m0/grade.py` |
| **[M1](m1/README.md)** | **쉬프트레프트 (checkov/trivy)** | ❌ | 심어둔 16개 결함 수정 → Failed checks **0** | `python labs/m1/grade.py` |
| **[M2](m2/README.md)** | **K8s 신원 (admission CEL)** | ✅ | `admission-policy` CEL 작성 → 위조 DENY/정합 ADMIT **5/5** | `bash labs/m2/grade.sh` |
| **[M3](m3/README.md)** | **네트워크 (Cilium L3/L7/egress)** | ✅ | default-deny에서 최소권한 홉 재구성 **7/7** | `bash labs/m3/grade.sh` |
| **[M4](m4/README.md)** | **런타임 (Tetragon eBPF)** | ✅ | TracingPolicy 작성 → selective-kill (id=0 + sh=137) | `bash labs/m4/grade.sh` |
| **[M5](m5/README.md)** | **암호화 (WireGuard/etcd)** | ✅ | ET1 채점 + capture-wg/etcd 직접 실행·해석 | `bash labs/m5/grade.sh` |
| **[M6](m6/README.md)** | **프런티어 (agent-ABAC + ReBAC)** | ❌ | 위임 인가 ABAC 교집합 **12/12** + ReBAC **11/11** | `python labs/m6/grade.py` |

> 클러스터 모듈(M2–M5)은 `scripts/up.ps1` 한 번 → M2→M3→M4→M5 연속 → `scripts/down.ps1` (RAM 규율).
> 각 채점기는 학습자 아티팩트를 적용해 검증한 뒤 **canonical 정책을 자동 복원**한다.

## 학습 순서에 대한 노트

M0·M1·M6은 클러스터가 필요 없다(노트북 RAM 부담 0). M0부터 순서대로 가되, 클러스터 모듈에
도달하면 가능한 한 M2–M5를 묶어 한두 세션에 처리하라. 각 모듈의 구두 문답은 면접 직전에
다시 돌아와 복습하는 용도로도 설계됐다.
