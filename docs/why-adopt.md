# 왜 *기업이* 이걸 도입하나 — 전략·경제·벤더선택의 "why"

> **한 줄 명제.** 이 랩의 다른 문서들이 *"이 통제가 왜 순진한 대안보다 낫나"*(THREAT_MODEL,
> authorization-model)와 *"규제가 왜 이걸 요구하나"*(financial-mls-mapping)를 다룬다면,
> 이 문서는 그 위층 — **"기업이 *왜* DevSecOps를 *관행으로* 채택하고, *왜* Cilium/eBPF를
> 대안 대신 고르나"** 의 경제·조직·아키텍처 논리를 1차 출처로 정리한다.

> ⚠️ **정직한 면책.** 이 문서는 **교육·포트폴리오 레퍼런스**다. **벤더 벤치마크가 아니고,
> 컨설팅 보고서도 아니며, 구매 의사결정 자료도 아니다.** 여기 인용한 수치는 각 출처가
> *실제로 말한* 범위 안에서만 쓰고, 출처가 명확지 않은 통념(예: "100x")은 **도시전설로
> 명시**한다. 모든 비자명 주장에는 `[출처: URL]`을 인라인으로 달았고, **사실(fact)** 과
> **추론·의견(reasoning)** 을 구분한다. 벤더 발행 벤치마크는 *벤더 수치*로 표기한다.

---

## 1. 이 문서를 읽는 법 (3축의 "why")

보안 스택을 *설명*하는 데는 세 가지 다른 층위의 "왜"가 있고, 이 랩은 셋을 분리해 다룬다.

| 층위 | 질문 | 다루는 문서 |
|------|------|------------|
| **통제/위협 why** | 이 통제가 왜 순진한 대안을 이기나 | `THREAT_MODEL.md`, `authorization-model.md` |
| **규제 why** | 왜 규제가 이걸 요구하나 (FSC 망분리 완화) | `financial-mls-mapping.md` |
| **전략/경제/벤더 why** (← *이 문서*) | 왜 *기업이* DevSecOps를 *관행으로* 채택하고, 왜 *Cilium/eBPF* 를 고르나 | `why-adopt.md` |

→ 이 문서는 앞 둘을 **중복하지 않고 요약·연결**한다(특히 §5는 financial-mls-mapping을
가리키기만 한다). 각 절 끝의 **"이 랩에서의 의미"** 박스가 주장을 실제 모듈(M0–M11, SL)로
되돌려 묶는다.

---

## 2. DevSecOps를 *조직이* 왜 도입하나 — 경제·조직 논리

### 2.1 핵심 논리: "나중에 잡으면 비싸다"는 **방향**은 맞지만 "100x"는 도시전설

shift-left를 정당화할 때 가장 흔히 인용되는 *"프로덕션 버그 수정은 설계 단계의 100배 비용"*
(흔히 "IBM Systems Sciences Institute" 연구로 귀속) **통계는 contested 다 — 사실로 적지
마라.**

- 조사 결과 그 "연구"의 원자료는 추적 불가이며, 'institute'는 IBM 사내 교육 프로그램이었다.
  *"There's one tiny problem with the IBM Systems Sciences Institute study: it doesn't exist."*
  (Hillel Wayne), 원 데이터는 *"not more recent than 1981, and probably older"* (Laurent
  Bossavit) [출처: https://www.theregister.com/2021/07/22/bugs_expense_bs/] — **(contested_flag)**
- 무엇이 실제로 지지되나: **곡선의 방향**(늦게 발견된 결함이 더 비싼 경향)은 잠정적 실증
  지지가 있으나, **정확한 배수는 신뢰 불가**하고 일부 연구는 유의한 차이를 못 찾았다(171개
  프로젝트 연구: *"the times to resolve issues at different times were usually not
  significantly different."*) [출처: https://www.theregister.com/2021/07/22/bugs_expense_bs/]
  — **(contested_flag)**

> **정직 원칙(이 랩의 시그니처):** "100x"는 **이 문서에서 사실로 쓰지 않는다.** 대신 아래의
> *날짜가 박힌* 규제·침해 비용을 경제적 앵커로 쓴다.

### 2.2 신뢰할 수 있는 경제 앵커 — 침해 비용과 탐지 속도 (날짜·출처 명확)

- 2024년 글로벌 평균 데이터 침해 비용은 **USD 4.88M**, 전년 대비 **10% 상승**(팬데믹 이후
  최대폭). [출처: https://newsroom.ibm.com/2024-07-30-ibm-report-escalating-data-breach-disruption-pushes-costs-to-new-highs]
  — **(sourced_fact)**
- 침해 수명주기는 7년 만의 최저인 **258일**로 단축; **내부 탐지가 수명주기를 61일 단축하고
  공격자 폭로 대비 약 USD 1M 비용을 절감**했다. → "shift-left + 내부 탐지가 비용을
  낮춘다"의 실증 근거. [출처: https://newsroom.ibm.com/2024-07-30-ibm-report-escalating-data-breach-disruption-pushes-costs-to-new-highs]
  — **(sourced_fact)**

> ⚠️ **DevSecOps -$227K 수치 주의.** "DevSecOps가 침해 비용을 약 **-$227,192** 낮춘다"는
> 수치가 널리 인용되나, **위에 인용한 IBM 1차 뉴스룸(2024판) 페이지를 직접 패치했을 때 그
> 페이지는 DevSecOps도 -$227,192도 *언급하지 않았다*.** 게다가 이 수치를 전하는 2차 출처
> (No Jitter)는 그것을 IBM **2025판** 보고서에 귀속한다 — 즉 §2.2의 나머지 2024 수치와
> *판본이 다르다*. 따라서 이 수치는 **2차 출처(보도) 기반**으로만 다루고, IBM 1차 자료로
> 단정하지 않는다. [출처(2차): https://www.nojitter.com/data-management/devsecops-cuts-data-breach-costs-supply-chains-add-to-them]
> — **(contested_flag, 판본·1차 미확인)** — IBM 보고서 PDF 대조 전까지 인용 자제.

### 2.3 shift-left가 실제로 *빠르고* *돈이 된다* (DORA)

- DORA(Google State of DevOps)는 shift-left를 *"보안 우려가 SDLC에서 더 일찍(좌측에서)
  다뤄지는 것"* 으로 정의하고, Deming을 인용한다: *"Cease dependence on inspection to
  achieve quality... by building quality into the product in the first place."* [출처:
  https://dora.dev/devops-capabilities/technical/shifting-left-on-security/] — **(sourced_fact)**
- 측정된 효익: *"high-performing teams spend 50 percent less time remediating security
  issues than low-performing teams"* (2016 State of DevOps Report 귀속). → "보안이 느려지는
  게 아니라 빨라진다"의 핵심 정량 주장. [출처: https://dora.dev/devops-capabilities/technical/shifting-left-on-security/]
  — **(sourced_fact)**
- 운영적 "how": InfoSec를 설계 단계부터 참여시키고, 사전승인된 라이브러리/도구를 제공하며,
  보안 테스트를 자동 테스트 스위트에 넣어 *"continuously tested at scale"* 한다. [출처:
  https://dora.dev/capabilities/pervasive-security/] — **(sourced_fact)**

### 2.4 왜 *자동화* 인가 — 스케일이 수동 검토를 무력화

- 조직당 평균 컨테이너 수가 **2,341개** 로 전년 **1,140개** 에서 급증했고, **57%** 가
  취약점 탐지에 자동화 도구를 쓴다. → 이 표면적은 수동 리뷰로 감당 불가. [출처(2차):
  https://cloudnativenow.com/topics/cloudnativedevelopment/cncf-survey-surfaces-steady-pace-of-increased-cloud-native-technology-adoption/]
  — **(sourced_fact, 2차 출처)**
- **그러나 도입의 진짜 병목은 도구가 아니라 문화다:** 응답자의 **46%** 가 문화적 이슈를 최대
  난제로 꼽았고(CI/CD 40%, 교육부족 38%, 보안 37%). → DevSecOps는 파이프라인 플러그인이
  아니라 **조직 변화**다. [출처(2차): https://cloudnativenow.com/topics/cloudnativedevelopment/cncf-survey-surfaces-steady-pace-of-increased-cloud-native-technology-adoption/]
  — **(sourced_fact, 2차 출처)**

> ⚠️ **출처 판본·표본 불일치 명시.** 위 수치는 **CNCF 보고서 본문이 아니라 보도(cloudnativenow)
> 에서 인용**했다. 두 가지 불일치를 정직히 둔다: (a) 이 보고서의 CNCF 1차 랜딩 페이지
> (<https://www.cncf.io/reports/cncf-annual-survey-2024/>)는 제목이 *"Cloud Native 2024:
> Approaching a Decade of Code, Cloud, and Change"* 이고 **2024년 가을 조사·2025-04-01 발행**
> 이며 **표본은 750명**으로 표기된다 — 즉 "2024 Survey"이되 발행은 2025년이다; (b) 인용한
> 보도 출처는 표본을 **689명**으로 적어 CNCF 자체 페이지(750명)와 **일치하지 않는다**. 수치
> 자체는 보도에서 그대로 옮겼으나 이 출처-간 불일치는 미해소 상태로 **표기**한다. — **(contested_flag, 출처 불일치)**

### 2.5 규제·공급망이라는 **강제 함수**

- **US Executive Order 14028**(2021-05-12 발령)은 NIST에 소프트웨어 공급망 보안 표준
  수립을 지시하고, 연방 납품 벤더에 보안개발 증빙을 요구한다 — DevSecOps의 강제 함수. (NIST
  페이지 표현은 "issued"이며 본 문서는 "발령"으로 옮긴다.) [출처:
  https://www.nist.gov/itl/executive-order-14028-improving-nations-cybersecurity] — **(sourced_fact)**
- 구체적으로 EO 14028은 (연방 납품 SW에) **NIST SSDF 적합성 자기증명**, 요청 시 **SBOM**,
  요청 시 취약점 스캔 결과·프로비넌스 같은 증빙을 요구한다. SLSA는 SSDF 적합성의 "on-ramp"
  으로 위치한다. [출처: https://slsa.dev/blog/2022/09/eo-in-plain-english] — **(sourced_fact)**
- **SBOM = 무엇이 들었나(인벤토리), SLSA = 어떻게 빌드됐나(빌드·프로비넌스 무결성, L1~L3
  등급)** — 공급망 보안의 기술적 백본. EO 14028 §10(j)가 SBOM을 *"formal record containing
  the details and supply chain relationships of various components"* 로 정의한다. [출처:
  https://www.nist.gov/itl/executive-order-14028-improving-nations-cybersecurity/software-security-supply-chains-software-1]
  — **(sourced_fact)**
- **Log4Shell**(2021)은 SBOM/인벤토리 가시성의 교과서적 정당화다: 美 Cyber Safety Review
  Board(2022-07)가 *"endemic vulnerability"* 로, 컴포넌트가 어디 박혀 있는지 못 찾기에 10년
  이상 잔존할 것으로 판정. [출처: https://www.cybersecuritydive.com/news/log4j-endemic-vulnerability/627284/]
  — **(sourced_fact)**

### 2.6 OWASP가 보는 DevSecOps의 본질

- OWASP는 DevSecOps를 *"기존 CI/CD 파이프라인에 보안 단계를 추가해 'build security into the
  development and release process'"* 하는 것으로 규정하고, 파이프라인에 흔히 쓰이는 취약점
  스캔 단계로 **SAST·DAST·IAST·SCA·인프라/컨테이너 취약점 스캔**을 열거한다. [출처:
  https://devguide.owasp.org/en/09-operations/01-devsecops/] — **(sourced_fact)**
- *추론:* 위 스캔을 자동화하는 이유를 "보안이 CI/CD 속도를 따라잡으려면"으로 설명하는 것은
  **이 문서의 해석**이다. **OWASP 페이지는 속도/velocity 논거를 명시하지 않는다** — 도구를
  *설명적으로* 나열할 뿐이다. 따라서 "속도 화해" 프레이밍은 사실이 아니라 추론으로 둔다. — **(reasoning)**

### 2.7 최소권한·blast-radius는 통념이 아니라 표준

- **NIST SP 800-207**(Zero Trust)은 *"physical or network location 만으로 암묵적 신뢰를
  부여하지 않는다"*, *"authN/authZ는 세션 수립 전 수행되는 개별 기능"* 으로, 마이크로
  세분화·짧은 수명의 스코프된 자격증명으로 침해 후 측면이동(blast radius)을 제약한다. [출처:
  https://csrc.nist.gov/pubs/sp/800/207/final] — **(sourced_fact)**

> **REASONING — DevSecOps 경제 케이스는 "100x"에 기대지 않는다.** 방어 가능한 논거는
> *수렴하는 사실들의 사슬*이다: (a) 침해는 비싸고 더 비싸진다(IBM $4.88M), (b) 빠른 내부
> 탐지가 비용을 낮춘다(~$1M, 61일), (c) shift-left가 교정시간을 줄인다(DORA 50%), (d)
> 현대적 스케일은 수동 보안을 불가능하게 한다(CNCF). 단일 출처가 이 결합 논거를 말하지
> 않으므로 이는 **사실이 아니라 추론**이다. **(reasoning)**

> **이 랩에서의 의미.** 위 강제 함수·경제 논리가 실제 모듈로 내려온다 —
> **SL/M1**(`checkov`·`trivy`·`gitleaks`·`cosign`)이 SSDF/SBOM/프로비넌스 요구를 *재실행
> 가능한 게이트*로 구현(M1: checkov 452/0); **M2/M0**이 최소권한·세션 전 인가를 코드로 강제.
> 즉 이 랩은 "DevSecOps를 왜 하나"의 답을 *말로* 가 아니라 *매 실행 통과하는 테스트*로
> 보인다(`scripts/verify.*` 라이브). 단, 이 랩은 n=1 워크로드이지 조직 변화의 증거가
> 아니다(§6).

---

## 3. 왜 Cilium / eBPF 인가 — 대안 대비

### 3.1 iptables를 떠나는 **아키텍처적** 이유 (스케일)

- kube-proxy의 iptables 모드 룰셋은 *"a number of iptables rules proportional to the sum
  of the number of Services and the total number of endpoints"* 이고, 패킷이 들어오면
  커널이 모든 Service 룰에 대조하는 시간이 *"O(n) in the number of Services"* 다. [출처:
  https://kubernetes.io/blog/2025/02/28/nftables-kube-proxy/] — **(sourced_fact)**
- 맵 기반 데이터패스(nftables, 그리고 같은 논리로 eBPF)는 이를 *"a roughly O(1) map
  lookup, packet processing time is more or less constant regardless of cluster size"* 로
  바꾼다. [출처: https://kubernetes.io/blog/2025/02/28/nftables-kube-proxy/] — **(sourced_fact)**
- 실측 규모: *"In the 30,000 Service cluster, the p99 ... latency for nftables manages to
  beat out the p01 latency for iptables by a few microseconds!"* [출처:
  https://kubernetes.io/blog/2025/02/28/nftables-kube-proxy/] — **(sourced_fact)**
- 근본 원인 프레이밍: *"The iptables API was designed for implementing simple firewalls,
  and has problems scaling up to support Service proxying ... with tens of thousands of
  Services."* [출처: https://kubernetes.io/blog/2025/02/28/nftables-kube-proxy/] — **(sourced_fact)**

### 3.2 identity 기반 정책 (IP/CIDR 룰 대비)

- Cilium은 보안을 주소에서 분리한다: *"Cilium entirely separates security from network
  addressing. Instead, security is based on the identity of a pod, which is derived through
  labels."* → IP 룰 중심 모델(iptables, 그리고 기본값이 IP 룰 중심인 Calico) 대비 이점. [출처:
  https://docs.cilium.io/en/stable/security/network/identity/] — **(sourced_fact)**
- 동적 클러스터에서 더 잘 확장: 기존 identity의 pod를 추가 기동하면 *"only requires to
  resolve this identity via a key-value store, no action has to be performed on any of the
  cluster nodes hosting role=backend pods"* — IP 룰 fan-out 업데이트로 pod 시작이 지연되는
  문제를 회피. [출처: https://docs.cilium.io/en/stable/security/network/identity/] — **(sourced_fact)**

### 3.3 사이드카 없는 L7 / 서비스 메시

- **사실(인용 페이지가 직접 말하는 것):** Cilium은 *"For all network processing including
  protocols such as IP, TCP, and UDP, Cilium uses eBPF as the highly efficient in-kernel
  datapath"* 이고, *"Protocols at the application layer such as HTTP, Kafka, gRPC, and DNS
  are parsed using a proxy such as Envoy"* 라고 명시한다 — 즉 L3/L4는 in-kernel eBPF,
  L7만 Envoy 프록시. [출처: https://docs.cilium.io/en/stable/network/servicemesh/index.html]
  — **(sourced_fact)**
- *추론(이 페이지엔 없음):* "Envoy를 pod마다 사이드카로 주입하지 않고 노드 단위(DaemonSet)
  로 공유 운영"이라는 **per-node vs per-pod** 배치 주장은 위 servicemesh 인덱스 페이지에
  **명시돼 있지 않다**(그 페이지는 eBPF-L3/L4 + Envoy-L7 분리만 말한다). 사이드카리스/노드
  단위 배치는 Cilium 전반에 대해 사실이지만 *이 URL이* 뒷받침하는 게 아니므로 추론으로 둔다.
  (아래 arXiv 비교가 *"per-pod 프록시 불필요"* 를 독립 확인한다.) — **(reasoning)**
- 사이드카 제거가 전송 암호화/제로트러스트까지 확장된 사례: Cilium 블로그가
  ztunnel 스타일의 노드 단위 컴포넌트로 **native mTLS**(per-pod 사이드카 없이)를 소개한다
  (제목 *"Native mTLS for Cilium: Transparent Encryption Meets Cloud Native Identity with
  ztunnel"* 만 패치 확인; **본문은 JS 렌더링이라 미확인 — 'KubeCon EU 2026' 등 내부
  귀속·수치 인용 금지**). [출처: https://cilium.io/blog/2026/03/23/native-mtls-cilium/]
  — **(contested_flag, 제목만 확인·본문 미확인)**
- **독립(비벤더) 비교(arXiv 프리프린트):** *"Performance Comparison of Service Mesh
  Frameworks: the MTLS Test Case"* (Bremler Barr 외)가 Istio/Linkerd/Cilium 등을 비교한다.
  보도·요약 기준 Istio 사이드카 모델이 ~3,200 RPS에서 지연 증가·자원 오버헤드 최고, Cilium은
  per-pod 프록시가 없어 CPU 소비에서 최선으로 보고된다. **프리프린트이고 PDF 본문 수치를
  직접 패치하지 못했으므로 방향성 참고치로만** 쓴다(메모리·intra-node 암호화 등 불리한
  tradeoff 가능성은 본문 대조 필요). [출처: https://arxiv.org/abs/2411.02267] — **(contested_flag,
  프리프린트·본문 직접 미확인)**

### 3.4 관측성 (Hubble)

- Hubble이 노드/클러스터/멀티클러스터(Cluster Mesh) 범위의 네트워크·보안 관측성을
  *"in a completely transparent manner"* 로 제공하고, L3/L4·L7 서비스 의존성 그래프를 자동
  발견한다 — Cilium 선택의 관측성 기둥. (이 문구·L3/L4·L7 의존성 그래프·멀티클러스터 범위는
  인용 URL 본문에서 verbatim 재확인됨.) [출처:
  https://docs.cilium.io/en/stable/observability/hubble/] — **(sourced_fact)**

### 3.5 ⚠️ 정직한 tradeoff (공짜가 아니다)

- **커널 요구.** Cilium은 커널 **>= 5.10**(또는 RHEL 8.10의 4.18 상당)을 권장하고, 신기능은
  더 새 커널을 요구한다(IPv6 BIG TCP >= 5.19, IPv4 BIG TCP >= 6.3). 구버전 커널에선 기능이
  빠진다 — **RHEL 기반 보수적·규제 환경(FSC 은행)에서 실제 도입 장벽.** (인용 페이지의 netkit
  항목은 `CONFIG_NETKIT=y`만 요구할 뿐 *이 페이지엔* 구체 커널 버전이 표기돼 있지 않아,
  과거 초안의 "netkit >= 6.8"은 본 인용 출처로 확인되지 않으므로 제거했다.) [출처:
  https://docs.cilium.io/en/stable/operations/system_requirements/] — **(sourced_fact)**
- **eBPF host-routing 비호환.** Cilium 자체 문서가 *"BPF Host Routing is incompatible with
  Istio"*, IPsec 사용 시 커널 버그픽스 필요, netfilter 훅 의존 기능(예: GKE Workload
  Identities) 비호환(legacy routing 폴백 필요)이라 명시. **성능 이득은 공짜가 아니다.** [출처:
  https://docs.cilium.io/en/stable/operations/performance/tuning/] — **(sourced_fact)**
- **벤더 벤치마크는 벤더 수치다.** Cilium 자체 CNI 벤치마크가 *"close to 1M requests/s ...
  consuming about 30% of the system resources"* 를 보고하나, 이는 유리한 조건의 **벤더 발행
  수치** — 벤더중립 벤치마크 아님. [출처: https://docs.cilium.io/en/stable/operations/performance/benchmark/]
  — **(contested_flag, 벤더 수치)**

> **REASONING — "iptables가 O(n)"은 Cilium을 단독으로 정당화하지 않는다.** Kubernetes 자체가
> nftables kube-proxy 모드(같은 ~O(1))를 출시했고 IPVS(해시테이블)도 선행한다 — 즉
> "iptables를 떠난다"는 정당화되나 "*Cilium* 을 택한다"는 데이터패스만으로는 충분하지 않다.
> Cilium 케이스는 **결합 패키지**(데이터패스 + identity 정책 + Hubble + 사이드카리스 메시)에
> 선다. [출처: https://kubernetes.io/docs/reference/networking/virtual-ips/] — **(reasoning)**

> **REASONING — 성숙도·lock-in 리스크.** 사이드카리스 mTLS는 최근(2026-03)이고 IPVS는
> k8s 문서상 **deprecated(v1.35)** 로 표기돼 데이터패스 지형이 빠르게 이동 중이다(인용
> 페이지는 IPVS를 deprecated로 명시할 뿐 "nftables 권고"를 *명문화하진* 않는다 — 폐기는
> 회피를 *함의*하나 그 추론은 우리 것이다). 오늘 Cilium을 택함은 *빠르게 움직이는 스택에
> 베팅*하는 것 — 포트폴리오의 'why-adopt'에서 *밝혀야 할* 정당한 리스크지 확정 사실이
> 아니다. [출처: https://kubernetes.io/docs/reference/networking/virtual-ips/] — **(reasoning)**

> **이 랩에서의 의미.** **M3**가 Cilium L3/L7 + egress default-deny를 *그대로*(프로덕션 동일)
> 쓰고(`prior-art.md` 참조), identity 기반 정책·Hubble 관측성을 라이브로 검증한다(`web→db
> 000`, `L7 /auditlogs 403`, `hubble observe --verdict DROPPED`). 커널 요구·host-routing
> tradeoff는 이 랩이 *kind* 위에서 도는 데모임을 정직히 한정한다 — 실 RHEL 도입 장벽은 이
> 랩이 검증하지 않는다(§6).

---

## 4. 통제별 "진짜 공격 → 실제 사고 → 비용" (모듈 연결)

각 행 = 이 스택의 한 통제 클래스 → 그것이 막는 **실제 공격 클래스** → **날짜·출처 박힌 실제
사고/CVE** → "왜 신경 쓰나"의 비용. 표의 **사고/CVE 본문은 1차 출처(OCC·OWASP·k8s 문서·NVD
×3·Codecov·ARMO)에서 직접 패치해 검증**했다. 단 *비용/영향 칸*의 일부 수치(Capital One 유출
규모)는 1차 페이지에 없어 별도 출처로 분리·플래그했다(아래 ⚠️).

| 모듈 | 통제 클래스 | 진짜 공격 | 실제 사고 (출처) | 비용 / 영향 |
|------|------------|-----------|------------------|-------------|
| **M3** (network seg/egress) | egress·메타데이터 차단 | SSRF → IMDSv1 자격증명 탈취 | **Capital One 2019** — OCC **$80M** 민사벌금(2020-08-06), *"failure to establish effective risk assessment processes prior to migrating ... to the public cloud"* [출처: https://www.occ.gov/news-issuances/news-releases/2020/nr-occ-2020-101.html] — **(sourced_fact)**. SSRF→IMDS 체인 자체는 AWS IMDSv2 문서가 방어책으로 명시 [출처: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html] — **(sourced_fact)** | $80M 벌금(OCC). 유출 규모 *"more than 100 million"* (美+캐나다 약 1억+600만)은 **OCC 페이지에 없고** DOJ 발표에 근거 — 출처 분리 표기 [출처(DOJ, 제목 확인·본문 403): https://www.justice.gov/usao-wdwa/pr/former-hacker-sentenced-stealing-computer-power-mine-cryptocurrency-and-stealing] — **(contested_flag, 2차/본문 미패치)** |
| **M0/M6** (object authz, Cedar) | per-object 인가 | BOLA — 요청 내 객체 ID 조작 | **OWASP API1:2023** *"manipulating the ID of an object that is sent within the request"*; 시나리오: *"gains access to the sales data of thousands of e-commerce stores"* [출처: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/] — **(sourced_fact)** | 데이터 유출·조작, 계정 탈취. ⚠️ "API 공격의 ~40%가 BOLA"는 **벤더 출처**(OWASP 페이지엔 없음) — OWASP 통계로 귀속 금지 **(contested_flag)** |
| **M2** (identity, label↔SA / SA-use) | 신원·RBAC 위조 차단 | create-workload로 SA 권한 탈취 / 관리 webhook RCE | k8s 문서: *"granting permission to create workloads also implicitly grants the API access levels of any service account in that namespace"* [출처: https://kubernetes.io/docs/concepts/security/rbac-good-practices/] — **(sourced_fact)**. 최근 사례 **IngressNightmare(CVE-2025-1974, CVSS 9.8 CRITICAL)** = 미인증 공격자가 pod 네트워크 접근만으로 ingress-nginx admission controller RCE → 컨트롤러 기본설정상 전 네임스페이스 시크릿 접근/클러스터 탈취 [출처(1차, NVD): https://nvd.nist.gov/vuln/detail/CVE-2025-1974] (벤더 해설: https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities) — **(sourced_fact)** | 클러스터 takeover |
| **M4/M8** (runtime, Tetragon eBPF) | 컨테이너 탈출·런타임 회피 | runc 탈출 / syscall-우회 | **runc "Leaky Vessels" CVE-2024-21626(CVSS 8.6)** — *"internal file descriptor leak ... working directory in the host filesystem namespace, allowing for a container escape"* (runc 1.0.0-rc93~1.1.11) [출처: https://nvd.nist.gov/vuln/detail/cve-2024-21626] — **(sourced_fact)**. **io_uring/Curing(2025)** — io_uring은 *syscall 없이* I/O 수행 → syscall-후킹 도구(Falco 등)가 *맹점*; 권장 방어는 **LSM 훅(KRSI)** [출처: https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/] — **(sourced_fact)** | 호스트 장악 / EDR 맹점 |
| **SL/M1** (supply-chain, checkov/trivy/cosign/SBOM) | 빌드·아티팩트 무결성 | 빌드에 심긴 백도어 / 유출 자격증명 | **xz-utils CVE-2024-3094(CVSS 10.0, CWE-506)** — *"liblzma build process extracts a prebuilt object file from a disguised test file"* — 소스가 아닌 **빌드**에 심긴 백도어 [출처: https://nvd.nist.gov/vuln/detail/cve-2024-3094] — **(sourced_fact)**. **Codecov 2021** — 공개 Docker 이미지 중간 레이어에서 HMAC 키 탈취 → Bash Uploader 변조 → 하류 CI 시크릿 대량 유출 [출처: https://about.codecov.io/apr-2021-post-mortem/] — **(sourced_fact)** | 대규모 하류 침해 |

> ⚠️ **출처 등급 명시.** **IngressNightmare(CVE-2025-1974)** 의 CVSS 9.8·미인증 RCE·전
> 네임스페이스 시크릿 접근 체인은 **NVD 1차를 직접 패치해 확인**했다(이전 초안의 "NVD 미패치"
> 플래그는 해소). **Capital One 유출 규모(~1억+)** 는 인용한 OCC 페이지에 없어 **DOJ 발표**로
> 분리 귀속했고, 그 DOJ 페이지 본문은 HTTP 403이라 *제목*만 확인되므로 contested로 남긴다.
> **SolarWinds AA20-352A**(또 다른 공급망 플래그십)는 CISA 페이지가 HTTP 403을 반환해 1차
> 인용에서 제외했다(검증 전 단정 금지 — 카테고리 예시로만 언급).

> **이 랩에서의 의미.** 각 통제 모듈이 *바로 그* 공격 클래스를 라이브로 막는다 — M3 egress
> `000`(SSRF→IMDS 경로 봉쇄), M0/M6 Cedar per-request 인가(BOLA), M2 라벨↔SA + SA-use
> gate(신원 위조), M4/M8 Tetragon zero-exec + (정직히) *"진짜 robust 답은 LSM"* 자기진단
> (io_uring 맹점), SL/M1 checkov/cosign(빌드 무결성). **단, 이 랩은 사고를 *재현*하지 않고
> 통제가 *막음* 을 보인다 — 침해 시뮬레이션이나 레드팀 증거가 아니다(§6).**

---

## 5. 규제 why — FSC 망분리 완화 (요약·연결, 중복 X)

이 절은 **`financial-mls-mapping.md` 를 대체하지 않고 한 단락으로 요약·연결**한다. 상세
매핑(보상통제 매트릭스·NIST 800-207 7원칙·C/S/O 등급)은 그 문서를 보라.

- **무슨 일이 있었나(사실).** 금융위·금감원이 「금융분야 망분리 개선 로드맵」을 **2024-08-13**
  발표 — 경직된 망분리를 단계적으로 완화하고, 지배 원칙은 **"자율보안-결과책임"**. 보도자료가
  말하는 단계 구조는 **데이터 민감도 기반 2단계 샌드박스**다: **1단계 = 가명정보**, (1단계의
  운영 성과·안전성이 충분히 검증되면) **2단계 = 개인신용정보 직접 처리**("빠르면 내년"). 생성형
  AI·SaaS·R&D 등은 *완화가 적용될 활용 영역*으로 언급되나, 보도자료는 이를 *1·2·3 순차 단계로
  번호 매기지 않는다* — 따라서 이전 초안의 "1~3단계 = 생성형 AI / SaaS / R&D" 매핑은 오기로
  제거했다. [출처: https://www.fsc.go.kr/no010101/82885] — **(sourced_fact)**
- **왜 이게 이 랩의 *전제* 인가(reasoning).** 망분리는 *위치*를 신뢰의 대용물로 썼다("업무망
  안 ⇒ 신뢰"). 완화는 그 위치-신뢰 목발을 치우므로, 제거된 가정마다 firm이 *입증할 수 있는*
  신원·워크로드·데이터 기반 통제로 대체해야 한다 — 이는 NIST SP 800-207의 *"no implicit
  trust ... based solely on ... physical or network location"* 와 정확히 일치. [출처:
  https://csrc.nist.gov/pubs/sp/800/207/final] — **(reasoning)**
- **"as-code/검증가능" 이 왜 핵심인가(reasoning).** 결과책임 + **"중요 보안사항의 CEO·이사회
  보고의무 등 내부 보안 거버넌스 강화"**(보도자료가 *명시한* 문구)는 통제를 *보유* 만으로
  부족하고 *작동을 증명* 하게 만든다. 이 랩의 자기채점·verify 주도 레퍼런스("정책이 실제로
  막음을 매 실행 증명")가 그 입증 요구의 한 답이다 — 단 이는 이 랩의 *해석 프레이밍* 이지
  "통제는 코드여야 한다"는 규제 문구가 아니다. (이전 초안의 "반기 점검(semi-annual review)"
  은 인용한 FSC 보도자료에 없어 제거했다.) — **(reasoning)**

> ⚠️ **clause 번호는 '대조 필요' 유지(정직 원칙).** FSC 보도자료 1차 패치 결과 **C/S/O·MLS·
> 제로트러스트·구체적 조문번호는 (이) 보도자료에 명시되지 않았다** [출처: https://www.fsc.go.kr/no010101/82885].
> C/S/O 등급은 **국정원(NIS) 공공 MLS** 에서 C(기밀)·S(민감)·O(공개)로 정의된 것을 금융
> 로드맵이 *적용*하는 흐름으로 보이며, 등급의 출처는 FSC가 아니라 NIS로 귀속한다.
> CISO 이사회 보고 조항으로 거론되는 **전자금융감독규정 제8조의2 는 *이 FSC 보도자료* 에는
> 등장하지 않는다**(보도자료는 "CEO·이사회 보고의무"라는 원칙만 서술) — **law.go.kr 1차 법령
> 대조 전까지 조문번호를 사실로 단정하지 않는다(대조 필요)**. SaaS 예외의 **제15조제1항제3호
> (단말기 망분리)** 만이 2026 시행세칙 맥락의 2차 출처(법무법인 해설 등)로 교차확인된다(1차 법령 대조는 financial-mls-mapping §8). 이 문서는 **규정 준수
> 확인서가 아니다.** (상세·출처는 financial-mls-mapping §8)

> **이 랩에서의 의미.** §2(supply-chain·최소권한)·§3(identity·egress)·§4(통제별 사고)의
> 모든 논거가 financial-mls-mapping의 보상통제 매트릭스로 수렴한다 — 특히 "자격증명 위조
> 확인"은 로드맵이 *명시한* 보상통제이고, M2의 라벨↔SA + SA-use gate가 그것을 워크로드
> 레벨 코드로 구현·라이브 거부 증명한다.

---

## 6. 정직한 한계 — 이 문서가 *하지 않는* 것

이 한계를 명시하는 것 자체가 이 랩의 시그니처(가차 없는 정직)이자 FSC 자율보안의 "과대주장
금지"에 부합한다.

- **벤치마크가 아니다.** §3의 성능 주장 중 벤더 발행 수치(Cilium 1M req/s)는 *벤더 수치*로
  표기했고, 비벤더 비교(arXiv)는 *프리프린트·방향성*으로만 썼다. 이 문서는 **자체 측정한
  성능 데이터를 생산하지 않는다.**
- **n=1, 스케일 미검증.** §3의 O(n)→O(1) 스케일 논거는 *문헌의 주장* 이다. 이 랩은 단일
  워크로드를 *kind* 위에서 돌리므로 **3만 Service 규모·프로덕션 부하를 직접 재현하지
  않았다.** 도입 ROI(조직 변화·문화)는 측정 불가 — §2.4의 "문화가 최대 난제"가 그 한계의
  방증이다.
- **사고를 재현하지 않는다.** §4의 CVE·침해는 *왜 이 통제가 필요한가* 의 1차 출처 근거이지,
  이 랩이 그 익스플로잇을 실행·재현했다는 뜻이 아니다(레드팀·침해 시뮬레이션 아님).
- **2차/미확인 출처는 표기했다.** DevSecOps -$227K(§2.2), CNCF 표본 불일치(§2.4), Capital
  One 유출 규모(§4, DOJ 본문 403), arXiv 프리프린트·Cilium mTLS 본문(§3) 등은 **1차 대조
  전까지 단정하지 않는다.** (반면 IngressNightmare CVSS 9.8은 §4에서 NVD 1차로 확인 완료해
  더 이상 미확인 항목이 아니다.)
- **규정 준수 확인서가 아니다(§5).** clause 번호·등급 거버넌스·CISO 보고 조항은 FSC 1차
  법령·금융보안원 가이드 대조가 필요하다.

> **요약.** 이 문서는 "기업이 왜 도입하나"의 **방어 가능한 논거를 1차 출처로 조립**하고, 각
> 논거를 이 랩의 모듈로 되돌려 묶되, **도시전설(100x)·벤더 수치·미확인 2차 출처를 정직히
> 분리**한다. 그 이상(벤치마크·n>1·ROI 측정·규정 준수)은 *이 문서의 스코프가 아니다.*

---

## 부록 — 출처 목록 (직접 패치·검증)

**DevSecOps 경제/조직**
- DORA, *Shifting left on security* — <https://dora.dev/devops-capabilities/technical/shifting-left-on-security/>
- DORA, *Pervasive security* — <https://dora.dev/capabilities/pervasive-security/>
- The Register, *bugs expense* ("100x" 반박) — <https://www.theregister.com/2021/07/22/bugs_expense_bs/>
- IBM, *Cost of a Data Breach 2024* 뉴스룸 — <https://newsroom.ibm.com/2024-07-30-ibm-report-escalating-data-breach-disruption-pushes-costs-to-new-highs>
- No Jitter (DevSecOps -$227K, 2차) — <https://www.nojitter.com/data-management/devsecops-cuts-data-breach-costs-supply-chains-add-to-them>
- CNCF *Cloud Native 2024* 보고서 수치(보도, 2차) — <https://cloudnativenow.com/topics/cloudnativedevelopment/cncf-survey-surfaces-steady-pace-of-increased-cloud-native-technology-adoption/> · CNCF 1차 랜딩(제목 *"Cloud Native 2024: Approaching a Decade…"*, 발행 2025-04-01, 표본 750) <https://www.cncf.io/reports/cncf-annual-survey-2024/> — 보도(689)와 CNCF(750) 표본 불일치 미해소
- OWASP DevSecOps Guideline — <https://devguide.owasp.org/en/09-operations/01-devsecops/>
- NIST EO 14028 — <https://www.nist.gov/itl/executive-order-14028-improving-nations-cybersecurity>
- NIST EO 14028 SBOM 정의 — <https://www.nist.gov/itl/executive-order-14028-improving-nations-cybersecurity/software-security-supply-chains-software-1>
- SLSA, *EO in plain English* — <https://slsa.dev/blog/2022/09/eo-in-plain-english>
- Cybersecurity Dive, Log4j endemic — <https://www.cybersecuritydive.com/news/log4j-endemic-vulnerability/627284/>
- NIST SP 800-207 — <https://csrc.nist.gov/pubs/sp/800/207/final>

**Cilium / eBPF**
- Kubernetes blog, *nftables kube-proxy* (O(n)/O(1)) — <https://kubernetes.io/blog/2025/02/28/nftables-kube-proxy/>
- Kubernetes docs, *Virtual IPs* (IPVS/nftables/iptables) — <https://kubernetes.io/docs/reference/networking/virtual-ips/>
- Cilium docs, *Identity* — <https://docs.cilium.io/en/stable/security/network/identity/>
- Cilium docs, *Service Mesh* — <https://docs.cilium.io/en/stable/network/servicemesh/index.html>
- Cilium docs, *Hubble* — <https://docs.cilium.io/en/stable/observability/hubble/>
- Cilium docs, *System Requirements* (커널) — <https://docs.cilium.io/en/stable/operations/system_requirements/>
- Cilium docs, *Tuning* (host-routing 비호환) — <https://docs.cilium.io/en/stable/operations/performance/tuning/>
- Cilium docs, *Benchmark* (벤더 수치) — <https://docs.cilium.io/en/stable/operations/performance/benchmark/>
- Cilium blog, *Native mTLS* (제목만 확인·본문 미확인) — <https://cilium.io/blog/2026/03/23/native-mtls-cilium/>
- arXiv, *Performance Comparison of Service Mesh Frameworks: the MTLS Test Case* (프리프린트) — <https://arxiv.org/abs/2411.02267>

**통제별 사고/CVE**
- OCC, Capital One $80M 벌금 — <https://www.occ.gov/news-issuances/news-releases/2020/nr-occ-2020-101.html>
- DOJ(WDWA), Capital One 유출 규모 *"more than 100 million"* (제목 확인·본문 403) — <https://www.justice.gov/usao-wdwa/pr/former-hacker-sentenced-stealing-computer-power-mine-cryptocurrency-and-stealing>
- AWS, IMDSv2 문서 — <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html>
- OWASP API1:2023 BOLA — <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/>
- Kubernetes, *RBAC good practices* — <https://kubernetes.io/docs/concepts/security/rbac-good-practices/>
- NVD CVE-2025-1974 (IngressNightmare, 1차) — <https://nvd.nist.gov/vuln/detail/CVE-2025-1974>
- Wiz, IngressNightmare (벤더 해설) — <https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities>
- NVD CVE-2024-21626 (runc) — <https://nvd.nist.gov/vuln/detail/cve-2024-21626>
- ARMO, io_uring/Curing — <https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/>
- NVD CVE-2024-3094 (xz) — <https://nvd.nist.gov/vuln/detail/cve-2024-3094>
- Codecov 2021 post-mortem — <https://about.codecov.io/apr-2021-post-mortem/>

**규제 (FSC)**
- FSC 「금융분야 망분리 개선 로드맵」(2024-08-13) — <https://www.fsc.go.kr/no010101/82885>
- (상세 매핑·추가 출처는 `financial-mls-mapping.md` §8)

> ⚠️ 모든 정책·통계는 변동·해석 여지가 있다. 공개·발표 전 1차 출처(특히 FSC 법령, NVD,
> IBM 보고서 PDF)로 재확인할 것. 이 문서는 **교육·포트폴리오 레퍼런스**다.
