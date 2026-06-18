# 프로덕션 도구 · 선행 도구 매핑 (왜 직접 짰나)

이 프로젝트는 성숙한 보안 도구들의 **경쟁자가 아니다.** 6계층 중 상당수는 프로덕션 도구를 *그대로* 쓰고
(Cilium · Tetragon · OpenFGA · Kyverno · checkov · trivy · cosign · SPIFFE/SPIRE), 직접 손으로 쓴 부분
(Cedar 정책 · zero-exec TracingPolicy)은 그 *메커니즘을 학습·측정*하기 위한 데모이며 각각 프로덕션 도구로
이식·격상된다. 이 페이지는 각 계층이 매핑되는 실제 도구를 명시해 **(a)** 지형 인지를 보이고 **(b)** "왜
X(예: KubeArmor)를 두고 직접 짰나"에 답한다.

## 계층별 매핑

| 계층 | 이 repo의 구현 | 형태 | 프로덕션 · 선행 도구 |
|---|---|---|---|
| 신원 · admission | VAP+CEL · Kyverno SA-use · SPIFFE/SPIRE | Kyverno·SPIRE는 **그대로** | **Kyverno** · **OPA/Gatekeeper** · Kubewarden · **SPIFFE/SPIRE** |
| 네트워크 세분화 | Cilium L3/L7 + egress default-deny | Cilium **그대로** | **Cilium**(프로덕션 동일) · Calico · Istio Authorization |
| 인가 PDP | Cedar(cedarpy) per-request 8/8 | Cedar 정책은 **데모** | **[Amazon Verified Permissions](https://aws.amazon.com/verified-permissions/)**(관리형 Cedar) · **OPA** · Oso |
| ReBAC | OpenFGA `fga model test` 11/11 | OpenFGA **그대로** | **[OpenFGA](https://openfga.dev/)** · SpiceDB (Google Zanzibar 계열) |
| 암호화 | WireGuard(전송) + etcd aescbc(저장) | Cilium WireGuard **그대로** | Cilium WireGuard · **KMS 봉투암호화**(EKS/GKE) · SealedSecrets/SOPS |
| 런타임 | Tetragon zero-exec(execve) | Tetragon **그대로**(룰은 데모) | **[KubeArmor](https://kubearmor.io/)**(LSM 인라인 시행) · **[Falco](https://falco.org/)**(탐지) · **Tetragon**(LSM 훅) |
| 시프트레프트 · 공급망 | checkov · trivy · gitleaks · cosign | 전부 **그대로** | checkov · trivy · gitleaks · **cosign/Sigstore** · Kyverno verifyImages · SLSA |
| 교차계층 형식검증 | z3 유한도메인(M7) | 데모(좁은 범위) | cedar-policy-symcc · OPA conftest (일반 정책분석은 연구영역) |

> 런타임 도구 구분(정확히): **KubeArmor** = LSM(AppArmor/BPF-LSM/SELinux) 기반 *인라인 시행* ·
> **Falco** = eBPF 기반 *탐지*(기본은 알림) · **Tetragon** = 관측+시행(kprobe/LSM, 인커널 필터 + SIGKILL,
> 이 repo가 사용). 셋 다 런타임 보안 공간의 성숙한 도구다.

## 직접 짠 두 부분은 *학습용*이다

- **Cedar 정책(인가)** — M0에서 평가 모델(default-deny, forbid 우선, scope/when)을 빈 파일에서 재구현해
  *이해*하기 위함. 프로덕션은 같은 문법을 **Amazon Verified Permissions**(관리형)로 옮긴다.
- **zero-exec TracingPolicy(런타임)** — M4(선택적 셸-kill)→M8(zero-exec 경계)로 런타임 kill의
  **detection≠prevention**과 회피 클래스(renamed-binary · io_uring)를 *라이브로 측정*하기 위함. 프로덕션의
  robust 시행은 syscall 표면이 아니라 **LSM(BPF-LSM/KRSI)** 이고, 그걸 제품화한 게 **KubeArmor**다.
  이 repo의 [위협 모델](../THREAT_MODEL.md) · [M8](../labs/m8/README.md) · [ADR 0001](decisions/0001-data-tier-zero-exec.md)
  이 이미 LSM을 robust 답으로 지목한다 — 즉 **KubeArmor는 이 프로젝트의 자기진단을 반박하는 게 아니라
  확인**해 준다(프로젝트가 "내 execve 데모의 한계, 진짜는 LSM"이라고 가리킨 자리에 있는 제품).

## 그래서 이 프로젝트의 기여는?

*더 나은 런타임 시행기*가 아니다(그건 KubeArmor/Tetragon이 한다). 위 도구들을 **한 워크로드에 6계층으로
조합·재구현**해 — **(a)** 각 메커니즘을 직접 짜며 학습하는 트랙(M0–M9), **(b)** FSC-MLS 규제 요구 → 통제 →
*재실행 가능한 테스트*의 [검증가능성 커버리지](evaluation-coverage.md)(77.5%, 31/40)를 정량화하고 갭을 행
단위로 공개하는 것 — 이 둘이 산출물이다. 위 도구들은 각자 한 계층의 제품이고, 학습 트랙·커버리지 방법론은
그 위의 다른 층위다. (자기평가: 포트폴리오·발표 READY, 국내 워크숍 한 단계 거리, **탑티어 연구는 아님** —
[평가·커버리지](evaluation-coverage.md) 참고.)
