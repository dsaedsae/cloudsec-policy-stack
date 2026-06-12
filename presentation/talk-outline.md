# 발표 아웃라인 — "망분리를 풀면 무엇으로 신뢰를 대체하는가: MLS 보상통제를 코드로 증명하기"

> 대상: 금융보안 세미나 / BoB 발표 / (영문 변형) AWS Summit 세션.
> 한 줄 주제: **망분리 완화로 사라진 "네트워크=신뢰" 가정을, 검증 가능한 다층 보상통제(as-code)로
> 대체하고 라이브로 증명한다 — 정직한 잔여위험까지.**
> 길이: 코어 15분 + 라이브 데모 5분 + Q&A. (라이트닝 5분 변형은 §6.)

---

## 1. 한 장 — 망분리(전) vs MLS 보상통제(후)

```
[전] 망분리 (Network Separation)
   인터넷망  ══(에어갭/물리·논리 분리)══  업무망
                                          └ 가정: "경계만 지키면 안쪽은 평평하게 신뢰"
   결과: 안전하지만 SaaS·클라우드·생성형 AI·개발도구가 막힘 → 경쟁력 저하
   FSC 「금융분야 망분리 개선 로드맵」(2024-08-13): 위치기반 분리 → 위험기반 MLS로 단계 전환

[후] MLS (Multi-Layered Security) — "업무 목적에 따라 통제된 연결" (위치 ≠ 신뢰)
   데이터 등급:  기밀(C) · 민감(S) · 공개(O)   → 등급별 차등 통제 (시스템=최상위 데이터 기준)
   ┌──────────────────────────────────────────────────────────────────────┐
   │ 신원        자격증명 위조 확인 (라벨↔SA · SA-use gate · SPIFFE mTLS)     │
   │ 세분화      마이크로세그멘테이션 (L3/L4 + L7, default-deny in/out)        │
   │ 인가        per-request 정책결정 (Cedar: owner·한도·역할·동결)            │
   │ 암호화      전송(WireGuard) · 저장(etcd Secret AES)                        │
   │ 탐지        런타임 EDR (Tetragon, eBPF — 데이터 티어 셸 즉시 차단)         │
   │ 사전통제    shift-left (checkov 게이트) + CI + 정직한 위협모델             │
   └──────────────────────────────────────────────────────────────────────┘
   결과: 망을 풀어도 한 요청이 신원→세분화→인가→암호화→탐지를 전부 통과해야 데이터에 닿음
```

핵심 한 마디: **"망분리 완화의 안전성은 보상통제가 *실제로 막는지*에 달렸다 — 슬라이드가
아니라 실행과 검증으로 보인다."**

---

## 2. 슬라이드별 흐름 (코어 15분)

| # | 슬라이드 | 핵심 메시지 (말할 것) |
|---|---------|----------------------|
| 1 | 제목 + 주제 한 줄 | 망분리 완화는 규제 *완화*가 아니라 신뢰 모델의 *교체*다 |
| 2 | 문제 | 망분리 10년 → SaaS/AI 막힘. FSC 2024-08-13 로드맵: MLS로 단계 전환 |
| 3 | "그래서 뭐가 위험한가" | 위치기반 신뢰가 사라지면 *내부에 있으니 곧 api다* 가정이 깨져야 함 |
| 4 | MLS가 요구하는 것 | C/S/O 등급 + 자율보안·사후책임 + 명시된 보상통제 6종 (§1 박스) |
| 5 | 이 프로젝트 = 그 보상통제의 as-code 레퍼런스 | 한 워크로드(web→api→db)에 6종을 중첩, 무료 로컬에서 |
| 6 | **통제 매트릭스** (핵심 슬라이드) | `docs/financial-mls-mapping.md` §4 — 통제→대체가정→구현→NIST 800-207→검증 |
| 7 | 깊게 1: 신원/자격증명 위조 확인 | "내부 = 신원" 깨기. **라이브 DENY**는 admission(라벨↔SA, SA-use gate); SPIFFE는 *설정됨*(SPIRE up, `netpol-mutual.yaml` opt-in)으로 보여줌(데모 DENY는 admission 단계) |
| 8 | 깊게 2: 한 요청·세 결정 | 같은 네트워크 경로, 같은 L7 허용 경로, **다른 principal → 200 vs 403** |
| 9 | 깊게 3: 데이터 보호 | 전송(WireGuard) + 저장(etcd 암호문 `k8s:enc:aescbc`) + 런타임 차단 |
| 10 | **라이브 데모** (§4) | verify 21/21 → 위조 DENY → bob 403 vs alice 200 → 셸 SIGKILL → etcd 암호문 |
| 11 | 결과 | cedar 8/8, checkov 452/0, **verify 21/21 라이브**, CI 통합 |
| 12 | **정직한 한계** | 데모 스코프·WireGuard 노드간·X-User 미인증·전사 MLS의 일부. *과대주장 안 함* |
| 13 | NIST 800-207 / ISMS-P 매핑 | 글로벌 제로트러스트 표준과 정합 (§MLS 문서) |
| 14 | 테이크아웨이 | 보상통제는 "있다"가 아니라 "막는 걸 매번 증명한다" — 자율보안의 본질 |

> 발표 톤: 12번(한계) 슬라이드를 *자신 있게* 발표하라. 심사자/CISO는 "안 되는 것을 아는
> 사람"을 신뢰한다. 이게 이 프로젝트의 최대 차별점이다.

---

## 3. 깊게 들어갈 한 장면 (관객이 기억할 "아하")

> **"같은 경로, 같은 허용 규칙, 다른 신원."**
> `bob`이 `alice` 계좌를 `GET` → 네트워크도 통과, L7도 통과, 그런데 **Cedar에서 403**.
> 반대로 `alice`는 200. *망 안에 있다고 다 같은 권한이 아니다* — 이게 망분리 완화 시대의
> 핵심 통제다. (B7과 묶으면: 애초에 `bob`이 `api`로 *위장*하는 것부터 admission에서 차단.)

---

## 4. 라이브 데모 스크립트 (5분, 그대로 실행 가능)

```bash
# 0. (사전) 클러스터 up — 발표 전 미리 띄워둘 것 (3~5분 소요)
pwsh scripts/up.ps1            # 또는  bash scripts/up.sh

# 1. 전체 방어를 한 번에 — 21/21 라이브
pwsh scripts/verify.ps1        # 표로 21개 통제 PASS

# 2. 신원 위조 차단 (말로: "내부에 있으니 api다 — 를 막는다")
#    forged app:api on web-sa  -> admission DENY   (verify 출력에서 강조)
#    shop:deployers as api-sa  -> admission DENY

# 3. 같은 경로·다른 신원 (핵심 아하)
#    alice GET own acct -> 200   /   bob GET alice acct -> 403   (verify 출력)

# 4. 런타임 — 데이터 티어 셸 즉시 차단
kubectl -n shop exec deploy/db -- sh -c "echo pwned"   # -> exit 137 (SIGKILL)

# 5. 저장 데이터 암호화 — etcd raw 읽기
#    (scripts/enable-secrets-encryption.* 적용 상태) -> 'k8s:enc:aescbc:v1:' 암호문, 평문 0

# 6. 정리
pwsh scripts/down.ps1
```

> 데모 안전장치: 네트워크 불안정 대비, verify 출력 캡처(표)를 백업 슬라이드로 준비.

---

## 5. 청중별 변형

- **BoB / 금융보안 세미나(국내):** 본 아웃라인 그대로. 6·7·12번 슬라이드에 시간 배분.
  규제 정합성(MLS 매핑)이 차별점.
- **AWS Summit(국제/클라우드):** 5번 뒤에 "로컬 → AWS 경로" 한 장 추가(Cedar→Amazon
  Verified Permissions, etcd암호화→KMS/EBS, mutual auth→IRSA/SPIFFE, 이미지→ECR+cosign).
  → 별도 산출물 `docs/aws-eks-path.md`(예정). 영문 슬라이드.
- **라이트닝 5분:** 슬라이드 1(전/후) → 6(매트릭스) → 10(데모 1·3) → 12(한계). 끝.

---

## 6. 제목 후보

- "망분리를 풀면 무엇으로 신뢰를 대체하는가 — MLS 보상통제를 코드로 증명하기"
- "Beyond Network Separation: Verifiable Multi-Layered Security as Code" (영문)
- "위치는 더 이상 신뢰가 아니다 — 금융 망분리 완화 시대의 워크로드 보상통제"

---

## 부속 자료
- 통제 매핑 근거: [`docs/financial-mls-mapping.md`](../docs/financial-mls-mapping.md)
- 기술 위협모델: [`THREAT_MODEL.md`](../THREAT_MODEL.md)
- 실습 랩(데모 분해): [`docs/`](../docs/README.md)
