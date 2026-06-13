# 로컬 → AWS/EKS 경로 + 가격대별 실습 가이드 (무료부터)

> **TL;DR.** 로컬 kind 스택의 모든 통제는 AWS 관리형 등가물이 있다. 하지만 **학습의 ~95%는
> 로컬에서 $0로 가능**하고, AWS 고유의 관리형 구성요소(Amazon Verified Permissions, KMS
> 봉투암호화, IRSA/Pod Identity)만 **짧게 띄웠다 즉시 내리면 세션당 약 $1–3**다. 위험은
> "EKS를 켜둔 채 잊는 것" — 그게 월 $178+의 함정이다. 아래는 **무료(Tier 0) → 현실(Tier 3)**
> 비용 사다리와, 비용을 0에 가깝게 유지하는 법이다.
>
> ⚠️ 모든 금액은 **us-east-1 기준 대략값(2026)**. 리전·프리티어·환율로 달라지니, 실제 집행 전
> AWS 공식 요금/Pricing Calculator로 재확인할 것(§출처).

이 문서는 두 가지를 한다: (1) 로컬 통제 → AWS 매핑(현업·AWS Summit 관련성), (2) **무료부터의
가격대별 실습 가이드**(학습자가 "얼마면 무엇을 할 수 있는지" 알도록).

---

## 1. 통제 매핑: 로컬 스택 → AWS/EKS

| 이 repo (로컬) | AWS/EKS 등가물 | 관리형 vs 자체호스팅 | 비용 메모 |
|---|---|---|---|
| kind 클러스터 | **EKS** 또는 *EC2 위 kind* | 관리형 컨트롤플레인 vs 직접 | EKS $0.10/hr(≈$73/월). EC2 위 kind는 EC2값만 |
| Cilium CNI(L3/L4/**L7**) | **Cilium on EKS**(OSS) 또는 VPC CNI+SG | Cilium 유지 시 L7·정책 동일 | Cilium 무료. VPC CNI는 L7 없음 |
| Cilium **WireGuard**(전송암호화) | Cilium encryption on EKS | 동일 OSS | 무료(컴퓨팅만). 노드 간 암호화 |
| **egress default-deny → 메타데이터(169.254.169.254) 차단**(ZT2) | **IMDSv2 강제(세션 토큰 필수) + hop-limit=1**(EC2/EKS) · Azure **Metadata Security Protocol** | 관리형 호스트 통제 | 무료(설정) |
| **Cedar PDP**(자체) | **Amazon Verified Permissions**(관리형 Cedar) | 정책 그대로 포팅 | **$5 / 100만 요청**, 최소·선결제 없음 → 데모 볼륨 수 센트 |
| etcd **Secret 암호화**(AES) | **EKS envelope encryption + KMS** | 관리형 키 | **KMS 키 $1/월** + $0.03/만요청(2만 무료) |
| **SPIFFE/SPIRE** 상호인증 | SPIRE on EKS, 또는 **IRSA / EKS Pod Identity** | 워크로드 신원 관리형 | IRSA/Pod Identity 무료. SPIRE 자체호스팅도 가능 |
| **Tetragon** 런타임(eBPF) | Tetragon on EKS(OSS) 또는 **GuardDuty EKS Runtime Monitoring** | 자체 무료 vs 관리형 탐지 | GuardDuty는 사용량 과금(보호 vCPU·시간 기준) |
| **checkov** shift-left | 동일(CI) + **Inspector / Config / Security Hub** | 무료 게이트 + 관리형 자세평가 | checkov 무료. AWS 관리형은 과금 |
| `cloudsec-api:local` 이미지 | **ECR** + cosign/**AWS Signer** 서명 + ECR enhanced scan(Inspector) | 레지스트리·서명·스캔 | ECR ≈$0.10/GB-월(500MB 무료) |
| Hubble 플로우 가시성 | Hubble on EKS 또는 **CloudWatch Container Insights** | 무료 vs 관리형 관측 | Container Insights 사용량 과금 |

> 포인트: **Cedar → Amazon Verified Permissions**, **etcd암호화 → KMS 봉투암호화**가 가장 깔끔한
> "코드 그대로, 관리형으로" 전환이다. 발표(특히 Summit)에서 이 두 개를 강조하라.
>
> 🛡️ **메타데이터 차단(ZT2)의 클라우드 등가물 — SSRF 자격증명 탈취 방어.** 이 repo는 워크로드 egress를
> `169.254.169.254`로 default-deny한다. 클라우드에선 같은 위협(앱 **SSRF**로 인스턴스 메타데이터의 임시
> 자격증명 탈취)을 **IMDSv2**(요청에 세션 토큰 필수 → 단순 SSRF GET 무력화)와 **hop-limit=1**(프록시/컨테이너
> 한 홉 너머의 메타데이터 도달 차단)로 막고, Azure는 **Metadata Security Protocol**로 대응한다. 최근 사례:
> Azure OpenAI **SSRF CVE-2025-53767**(CVSS 10). *doc-only 매핑*이며 이 repo의 라이브 검증은 in-cluster
> egress-block(ZT2 `metadata 000`)에 한정된다.

### 1-1. 빌드 프로비넌스: 이미지 서명(cosign) — 로컬 키풀 검증 + 프로덕션 keyless

로컬 스택은 이미지 **취약점·시크릿 스캔 + SBOM**(`trivy`, [02-scan.md](02-scan.md))에 더해 이제
**서명 검증까지 라이브로 증명**한다. 원래 막힘은 출시된 cosign이 서명을 붙일 **레지스트리 다이제스트**를
요구하는데(sigstore/cosign#3832) `cloudsec-api:local`이 kind에 로드된 *레지스트리 없는* 이미지였다는
점이다. 이를 **로컬 OCI 레지스트리**(`registry:2`, kind 네트워크)로 우회한다 —
`scripts/verify-image-signing.ps1`이 이미지를 로컬 레지스트리에 푸시 → **키풀 cosign** 서명 → **Kyverno
`verifyImages` ClusterPolicy**(공개키 바인딩, [`k8s/kyverno-image-verify.yaml`](https://github.com/dsaedsae/cloudsec-policy-stack/blob/main/k8s/kyverno-image-verify.yaml))
적용 → 서버 dry-run으로 **서명됨→ADMIT / 미서명→DENY**를 증명한다(coverage **SL6 VERIFIED**, 로컬-키 경로).

```bash
# 로컬(이 repo): 로컬 OCI 레지스트리 + 키풀 cosign + Kyverno verifyImages
cosign sign --key cosign.key localhost:5001/cloudsec-api@sha256:<digest>     # 로컬 레지스트리(http)
# 프로덕션(ECR): keyless(OIDC) 또는 AWS Signer
cosign sign  $ECR_REPO@sha256:<digest>                                       # keyless: --yes, OIDC 신원
cosign verify $ECR_REPO@sha256:<digest> \
  --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*'
cosign attest --predicate provenance.json --type slsaprovenance $ECR_REPO@sha256:<digest>  # SLSA
```

배포 게이트는 서명 미검증 이미지를 거부한다(Kyverno `verifyImages` — 로컬에서 실증; EKS에선 **AWS Signer**
+ ECR). **정직한 경계:** 로컬은 *키풀(local-key) 서명 검증*까지 VERIFIED이고, **keyless(OIDC)·Rekor 투명성
로그·SLSA 프로비넌스 어테스테이션**은 ECR 경로의 로드맵 항목이다(로컬 데모는 키풀+오프라인). 또한 이는
*프로비넌스*(이 키 소유자가 서명했는가)를 증명할 뿐, 서플라이체인 무결성 전체나 특정 웜 차단을 주장하지 않는다.

---

## 2. 가격대별 실습 사다리 (무료부터)

### Tier 0 — 로컬 kind · **$0** · "거의 전부 여기서 배운다"
- **무엇:** 현재 `scripts/up` 스택. Cilium(L3/L4/L7+egress) · Cedar(자체) · 라벨↔SA/SA-use admission · SPIFFE 상호인증 · Tetragon · WireGuard · etcd Secret 암호화 · checkov.
- **배우는 것:** 제로트러스트·마이크로세분화·정책as코드·런타임탐지·암호화 — MLS 보상통제 6종 전부.
- **비용:** **$0** (노트북 RAM만). **verify 21/21**까지 무료로 재현.
- **언제 충분한가:** 면접·포트폴리오·세미나 데모·개념 학습의 거의 전부. **여기서 멈춰도 된다.**

### Tier 1 — EKS 단발 랩(같은 날 teardown) · **세션당 약 $1–3**
- **무엇:** AWS *고유* 관리형 등가물만 짧게 체험 — **Verified Permissions**(Cedar 정책 업로드+isAuthorized), **KMS 봉투암호화**(EKS secrets), **IRSA/Pod Identity**.
- **비용 구성(3시간 가정):** 컨트롤플레인 $0.10×3=**$0.30** + 노드(t3.medium **spot** 2대 ≈ $0.07, 온디맨드면 ≈$0.25) + KMS 키 ≈**$1**(월 단위 과금) + Verified Permissions 테스트 수백 건 **<$0.01** + EBS 몇 센트. → **세션 총 ≈ $1–3.**
- **0에 가깝게 유지:** **NAT Gateway 쓰지 말 것**(노드를 퍼블릭 서브넷 또는 VPC 엔드포인트로 — NAT는 $0.045/hr+데이터로 조용히 샌다) · **Spot** 노드 · **단일 AZ·단일 노드** · **끝나면 즉시 `eksctl delete cluster`**.
- **함정:** **켜둔 채 잊으면** 컨트롤플레인 $73/월 + NAT $32/월 + 노드가 그대로 청구된다 → "월 $178 함정".

### Tier 2 — 상시 EKS(관리형 노드) · **월 약 $150–200**
- **무엇:** 떠 있는 학습/데모 환경. 관리형 노드그룹 + NAT + KMS + ECR + 관측.
- **비용:** 컨트롤플레인 $73 + 노드 2대 ≈$60 + NAT ≈$32 + KMS $1 + 기타. (예시 ≈$178/월)
- **언제:** 팀 공유 랩, 지속 데모가 필요할 때만. 개인 학습엔 과함.

### Tier 3 — 프로덕션 유사(HA) · **월 $300+**
- 멀티 AZ NAT×3, 큰 노드, (필요시) 프로비저닝드 컨트롤플레인 티어(XL $1.65/hr~), GuardDuty 런타임, Security Hub, WAF 등. 실제 운영 비용. **이 repo의 학습 범위 밖**(현업 설계 참고용).

> 추천 경로: **Tier 0에서 전부 익히고**, Verified Permissions/KMS/IRSA만 **Tier 1로 한 세션**
> 체험 후 즉시 내려라. Tier 2+는 필요가 명확할 때만.

---

## 3. 보조 서비스 요금 참고 (대략, us-east-1, 2026)

| 서비스 | 요금(대략) | 비고 |
|---|---|---|
| EKS 컨트롤플레인 | **$0.10/hr** (≈$73/월) | 노드 수 무관 고정. 확장지원 시 $0.60/hr |
| EKS Auto Mode | EC2값 + **~12%** 관리수수료 | 노드 운영 자동화 |
| EC2 t3.medium | ≈$0.0416/hr (≈$30/월) | **Spot 최대 −90%** |
| NAT Gateway | **$0.045/hr** (≈$32/월) + $0.045/GB + 전송 | *상시 과금 — 잊으면 폭탄* |
| KMS(대칭 CMK) | **$1/월/키** + $0.03/만요청 | 2만 요청/월 무료. 비대칭 $0.15/만 |
| Amazon Verified Permissions | **$5/100만 요청** | pay-as-you-go, 최소 없음(2025.6 −97%) |
| ECR | ≈$0.10/GB-월 | 500MB/월 무료 |
| Secrets Manager | $0.40/시크릿-월 | 필요 시 |
| EBS gp3 | ≈$0.08/GB-월 | 노드 디스크 |
| Application Load Balancer | ≈$16–22/월 + LCU | 외부 노출 시 |

---

## 4. 비용 가드레일 + teardown 체크리스트 ("무료부터" 핵심)

**시작 전:**
- **AWS Budgets** 월 예산 + 알림(예: $5, $20) 설정. 단발 랩엔 $5면 충분히 경고.
- 리전 고정(잘못된 리전에 리소스 흘리지 않기).

**랩 끝나면(순서대로 — 누락이 곧 청구):**
1. `eksctl delete cluster --name <name>` (또는 terraform destroy) → 컨트롤플레인·노드 제거.
2. **NAT Gateway** 남았는지 확인·삭제 + **Elastic IP** 해제(미사용 EIP도 과금).
3. **EBS 볼륨**·스냅샷 잔여 확인.
4. **로드밸런서(ALB/NLB)** 잔여 확인(서비스가 만든 것).
5. **KMS 키**는 즉시 삭제 불가 → **스케줄 삭제(7–30일)**. 그 사이 $1/월 과금됨을 인지.
6. **ECR 이미지**·**CloudWatch 로그 그룹** 정리.
7. Cost Explorer로 다음날 잔여 과금 0 확인.

> 황금률: **Tier 1은 "띄운 날 내린다."** 켜두고 자면 Tier 2 요금이 매달 나온다.

---

## 5. 정직한 한계
- 금액은 **대략·시점 기준**이다. 정확한 견적은 AWS Pricing Calculator로.
- 이 문서는 **학습 비용 가이드**이지 프로덕션 비용 최적화 설계서가 아니다(Savings Plans·RI·
  Karpenter·세분화 과금 등은 범위 밖).
- 관리형 전환이 항상 정답은 아니다 — Cedar/Tetragon/Cilium 자체호스팅이 비용·이식성에서
  유리한 경우가 많다. 관리형(Verified Permissions/KMS/GuardDuty)은 운영부담↓·과금↑의 트레이드오프.
- 로컬 Tier 0가 커버하지 못하는 건 **관리형 서비스의 운영 경험**뿐이다(통제 개념 자체는 전부 로컬에서 학습 가능).

---

## 6. 출처 (요금은 변동 — 집행 전 재확인)
- Amazon EKS Pricing — <https://aws.amazon.com/eks/pricing/>
- Amazon Verified Permissions Pricing(−97%, 2025-06) — <https://aws.amazon.com/verified-permissions/pricing/> · <https://aws.amazon.com/about-aws/whats-new/2025/06/amazon-verified-permissions-reduces-price/>
- AWS KMS Pricing — <https://aws.amazon.com/kms/pricing/>
- Amazon VPC / NAT Gateway Pricing — <https://aws.amazon.com/vpc/pricing/> · <https://docs.aws.amazon.com/vpc/latest/userguide/nat-gateway-pricing.html>
- EKS Spot/비용 최적화 — <https://aws.amazon.com/blogs/compute/cost-optimization-and-resilience-eks-with-spot-instances/> · <https://cloudburn.io/blog/amazon-eks-pricing>
- (참고) EKS 비용 가이드 — <https://www.cloudzero.com/blog/eks-pricing/>
