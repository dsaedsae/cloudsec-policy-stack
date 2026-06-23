# 금융 망분리 완화(MLS) ↔ 이 스택 통제 매핑

> **TL;DR (EN).** Korea's FSC is replacing rigid financial-sector *network
> separation* with a risk-based **Multi-Layered Security (MLS)** model
> (roadmap, 2024-08-13): data graded C/S/O, tiered compensating controls,
> autonomous-security-with-post-hoc-accountability. This repo is a **live,
> verifiable, as-code reference implementation of exactly those compensating
> controls** for one workload — zero-trust segmentation, cryptographic identity
> (incl. credential-forgery checks), least privilege, encryption in transit and at
> rest, and runtime detection — each mapped below to the MLS requirement it
> satisfies, to NIST SP 800-207, and to the `verify` check that proves it.

이 문서는 "기술적으로 멋지다"를 "금융보안 관점에서 왜 중요한가"로 연결한다. 망분리를
풀면 그 신뢰를 무엇으로 대체하는지를, **추측이 아니라 실제 정책 문구와 이 repo의
실행·검증 결과로** 보인다.

---

## 1. 배경 — 망분리 완화가 만드는 "보상통제 공백"

- 한국 금융권은 전자금융감독규정에 따라 **물리/논리 망분리**(업무망↔인터넷망)를 약 10년간
  강제받아 왔다.
- **금융위·금감원 「금융분야 망분리 개선 로드맵」(2024-08-13)** 이 위험기반(데이터 민감도 2단계 샌드박스) 완화를
  발표했다. 핵심은 "완전 차단"에서 **위험기반 다층보안(MLS)** 으로의 전환 — *"업무 목적에
  따라 통제된 연결"* 을 허용하되, 보안 공백을 보상통제로 메운다.
- 즉 **"네트워크 위치로 신뢰"가 사라진 자리를 신원·워크로드·데이터 기반 통제로 대체**해야
  한다. 이 repo가 구현·검증하는 것이 정확히 그 대체 통제다.

> 출처·정확도: 아래 §8. 2024-08-13 로드맵은 이후 **전자금융감독규정 개정으로 시행 단계에 진입**했고,
> SaaS 활용 확대 등 추가 완화가 **2026-01 추진**되고 있다(§8 Korea Times). 등급 정의·적용 의무·CISO
> 이사회 보고 등 시행 세부는 개정 규정·금융보안원 가이드로 구체화된다.
> ⚠️ **구체적 고시 번호·조문(예: CISO 이사회 보고 조항으로 거론되는 제8조의2)·시행일은 본 문서에서
> 확정 사실로 단정하지 않는다 — FSC 1차 자료(법령·고시) 대조가 반드시 필요하다**(이 repo는 규제 조문
> 번호를 추측으로 적지 않는다). 이 문서는 "통제 설계의 정합성"을 보이는 것이지 규정 준수 확인서가 아니다.

---

## 2. MLS 핵심 (정책 요약)

| 축 | 내용 |
|----|------|
| **데이터 등급** | **기밀(C, Classified) · 민감(S, Sensitive) · 공개(O, Open)** 3등급, 등급별 **차등 보안통제**, 시스템은 **최상위 등급 기준**. ⚠️ 이 C/S/O 등급체계(기밀 C·민감 S·공개 O)는 **국정원(NIS) 「국가 망 보안체계(N2SF)」** 에서 정의됐다 — 1차 확인: N2SF 실증 사례집 *"기밀정보 C등급 / 민감정보 S등급 / 공개정보 O등급"*(p.11), 출처 표기 "N2SF 보안 가이드라인 1.0". *("다층보안(MLS)"은 FSC 망분리 완화를 가리키는 **2차/통용 표현**(보안뉴스·이글루 등)이지 1차 명칭이 아니다 — N2SF 가이드라인 1.0 본문에 "다층/Multi-Layered"는 0회이고 "MLS"는 오직 CDS 하위유형 "다중등급보안 CDS(Multi-**LEVEL** Security)"로만 등장; FSC 보도자료에도 "MLS" 명시 없음. repo-side 라벨로만 쓴다.)* N2SF는 **공공·정부** 망보안 체계로 금융/FSC를 일절 언급하지 않으므로, "FSC 로드맵이 같은 모델을 *적용*한다"는 것은 *repo의 추론*이지 N2SF 진술이 아니다(대조 필요). 본 데모의 db/api/web C/S/O는 그 모델을 *차용한 가정*. |
| **운영 원칙** | **자율보안 + 사후책임** — CEO·이사회 보고의무, CISO 권한 확대, 검증 미흡 시 시정요구·이행명령, 자율보안 이행 기업에 샌드박스 가점. |
| **보상통제 (A=로드맵 명시 / B=파생)** | **A — FSC 로드맵이 직접 명시:** 제로트러스트(불신·철저확인·최소접근), **강화된 사용자 인증·자격증명 위조 확인**, **최소 권한**. **B — MLS·NIST 800-207·ISMS-P에서 파생되는 보강통제:** **암호화 강화**, **이상 탐지(EDR)**, **네트워크 마이크로 세분화**. (B는 "로드맵이 한 단어로 명시"가 아니라 다층보안 이행을 위해 따라오는 통제 — 정직 구분.) |
| **단계** | 보도자료의 단계 구조 = **데이터 민감도 기반 2단계 샌드박스**(1단계=가명정보 → 2단계=개인신용정보 직접 처리). **생성형 AI·SaaS·R&D는 완화가 적용될 *활용 영역*이지 1·2·3 순차 단계가 아니다** — 이전 초안의 "1~3단계=생성형AI/SaaS/R&D" 매핑은 오기로 정정(why-adopt §5와 일치). 민감정보는 별도 안전장치 전제. |

---

## 3. 데이터 등급(C/S/O) ↔ 이 스택

데모 앱(web → api → db)을 MLS 등급 모델에 대입하면:

| 티어 | MLS 등급(가정) | 다루는 데이터 | 적용된 차등통제 |
|------|---------------|--------------|----------------|
| `db` (data) | **기밀(C)** | 계좌·잔액(개인신용정보 상당) | 진입 차단(api만), 셸 실행 시 즉시 SIGKILL, **저장 시 암호화(etcd)**, egress 없음 |
| `api` (backend) | **민감(S)** | 처리 중 데이터 + 인가 판단 | per-request Cedar 인가, L7 경로/메서드 제한, **전송 중 암호화(WireGuard)**, 신원(mutual auth) |
| `web` (frontend) | **공개(O)** 경계 | 외부 진입점 | 인터넷·메타데이터·API서버로 egress 차단(데이터 유출 경로 봉쇄) |

→ N2SF 보안 가이드라인 1.0 본문은 **"하나의 정보시스템에 서로 다른 등급의 업무정보가 포함되는 경우에는
가장 높은 등급을 해당 정보시스템의 등급으로 분류한다"**(본문 p.24)고 명시한다 — 시스템을 *최상위 등급으로
분류*하는 원칙(가이드라인은 이어 등급별 시스템 분리·운영도 권고). 이를
차용하면 **`db`가 기밀이면 그 경로 전체가
기밀 수준 통제**를 받아야 한다. 이 스택은 db로 가는 모든 홉(network→L7→Cedar→runtime)과
db의 데이터(at-rest 암호화)에 통제를 중첩해 그 요구를 충족한다.

---

## 4. 보상통제 매트릭스 (이 문서의 핵심)

각 행 = MLS가 요구하는 보상통제 → **망분리의 어떤 가정을 대체**하는가 → 이 repo의 구현 →
NIST SP 800-207 원칙 → ISMS-P 분야(분야 명칭은 「ISMS-P 인증제도 안내서(2024.07)」 [표2] 1차 확인; 세부 항목번호 2.x.y는 **대조 필요** — repo-local 세부표는 분야번호가 어긋나 혼용 금지) → **검증 방법**.

| MLS 보상통제 | 대체하는 "망분리 가정" | 이 repo 구현 | NIST 800-207 | ISMS-P(개념) | 검증 (verify 항목) |
|---|---|---|---|---|---|
| **네트워크 마이크로 세분화** | "내부망 안은 평평하고 신뢰 가능" | Cilium default-deny in/out, web→api→db만, **L7**(메서드/경로) | Tenet 1·3 | 2.6 접근통제 | `web→db 000`, `api→db 200`, `L7 /auditlogs 403` |
| **제로트러스트(위치 무관 통신 보호)** | "외부와 분리됐으니 내부 트래픽은 평문 OK" | 이그레스 default-deny(인터넷·메타데이터·API서버 000) + 전 구간 정책 | Tenet 2·6 | 2.6 접근통제 / 2.10 시스템 및 서비스 보안관리 | egress `000` ×3 |
| **강화된 사용자 인증 / 자격증명 위조 확인** | "망 안에 있으면 곧 신원" | 라벨↔SA admission, **SA-use gate**(요청자↔SA 바인딩); **SPIFFE mutual auth(SVID)**=opt-in(`netpol-mutual.yaml`, Lab 4 수동검증) | Tenet 3·6 | 2.5 인증 및 권한관리 | `forged app:api→DENY`, `CI SA as api-sa→DENY`(메시지 일치) |
| **최소 권한** | "내부 시스템 간 광범위 허용" | 티어 SA 권한 0, Cedar(owner·한도·역할·동결), shop-deployer 최소 Role | Tenet 4·6 | 2.5 인증 및 권한관리 / 2.6 접근통제 | `api-sa no create-pods`, Cedar allow/deny 6종 |
| **암호화 강화 (전송)** | "분리망이라 도청 위험 낮음" | Cilium **WireGuard** + api/db 다른 노드 강제 → api→db 크로스노드 암호화 (§7) | Tenet 2 | 2.7 암호화 적용 | `api→db cross-node, WireGuard-encrypted PASS` |
| **암호화 강화 (저장)** | "내부 저장소 접근자 제한으로 충분" | etcd **Secret AES-CBC 암호화**(`k8s:enc:aescbc`; ⚠️ aescbc는 upstream **Weak**[no-AEAD, kubernetes#73514] — 실 적용은 aesgcm/KMS) | Tenet 1 (800-207엔 at-rest 전용 원칙 없음) | 2.7 암호화 적용 | raw etcd 암호문/평문0 |
| **이상 탐지 (EDR)** | "분리로 침투 자체가 어려움" | **Tetragon**(eBPF) 데이터 티어 **모든 exec를 in-kernel 차단(zero-exec: execve+execveat)** — 이름/arg0 무관, renamed·execveat·fd-exec 우회 모두 닫음(나이브 셸-명 룰은 우회 가능했고 M4 랩에 남음; M8 라이브 검증·ADR 0001). distroless=2중 방어. 프로세스 감사(audit)=CONFIGURED(스위트 미단언) | Tenet 5·7 | 2.11 사고 예방 및 대응 | `data-tier exec→SIGKILL 137` |
| **사전 통제(shift-left)** | "운영 후 점검으로 충분" | **checkov** Terraform+K8s 게이트(0 fail), gitleaks | Tenet 4 | 2.8 정보시스템 도입 및 개발 보안 | checkov 452/0, CI |

**핵심 메시지:** "자격증명 위조 여부 확인"은 MLS가 명시한 보상통제다. 이 repo의 B7 작업
(라벨↔SA + SA-use gate + SVID)은 *바로 그것을 워크로드 레벨에서 코드로 구현하고 라이브로
거부를 증명*한다 — 망분리가 풀린 환경에서 "내부에 있으니 곧 `api`다"라는 가정을 깬다.

> **1차 출처 — 전자금융감독규정 조문 매핑(금융보안원 「2026년 전자금융기반시설 보안 취약점 평가기준
> 안내서」, 금융위 고시 제2025-4호·2025-02-05).** 위 통제들은 동 안내서의 *정보보호 관리체계* 표가
> **[근거조항]으로 verbatim 명시**한 전자금융감독규정 조문에 대응한다 — 망분리/네트워크 = **제15조(해킹 등
> 방지대책)** + 시행세칙 **제2조의3(망분리 적용 예외)**; 전산자료·최소권한 = **제13조(전산자료 보호대책)**;
> 암호·키 관리 = **제19조(암호프로그램 및 키 관리 통제)**; 클라우드 거버넌스 = **제14조의2(클라우드컴퓨팅
> 서비스 이용절차 등)** + 시행세칙 **제2조의4**; 취약점 평가주기 = **제37조의2**(전문기관 지정은 제37조의3 —
> 혼동 금지). ⚠️ *조문 '제목'만 확인됨(본문은 law.go.kr 대조 필요); 동 안내서의 가상화·클라우드(AWS/Azure)·
> 서버 기술 통제표는 [근거조항] 컬럼이 없어 micro-seg·at-rest 암호화·credential-rotation·EDR 등 기술 통제의
> 제N조 매핑은 '대조 필요'로 남긴다(추정 금지).*

> **1차 출처 — N2SF 보안통제 항목 매핑(국가정보원 「국가 망 보안체계 보안 가이드라인 1.0」 부록1 「보안통제
> 항목 해설서」; ID·C/S/O 등급 verbatim).** 위 통제들은 N2SF 보안통제 항목에도 대응한다 — 마이크로세분화 =
> **N2SF-SG-4** IP 체계 분리(C/S/O)·**N2SF-IS-4** 네트워크 격리(C/S/O); 제로트러스트 egress = **N2SF-EB-3**
> 화이트리스트 기반 통신 허용(C/S)·**N2SF-EB-6** 외부 위협 발신 차단(C/S)·**N2SF-EB-14** 외부 DNS 통신 제한(C);
> 최소권한 = **N2SF-LP-M3** 접근권한 사전 설정(C/S/O)·**N2SF-LP-5** 코드 실행권한 제한(C/S/O) (LP 해설은 RBAC
> +ABAC PDP/PEP 권고); 강화 인증/위조확인 = **N2SF-IV-1** 관리자 승인(C/S)·**N2SF-AU-3** 권한 위임 토큰(OAuth)
> 보호(C/S); 전송 암호화 = **N2SF-DT-3** 전송간 암호화(C/S); 저장 암호화 = **N2SF-DU-2** 데이터 암호화 저장
> (C/S/O)·**N2SF-EK-1** 암호 키 설정(C/S/O)·**N2SF-EA-1** 검증필 암호모듈(C/S/O — N2SF는 KCMVP 검증필 모듈을
> *의무화*하므로 일반 at-rest보다 강함); 런타임/EDR = **N2SF-IN-16** 악성코드 감염 차단(C/S/O, 해설이 EDR을
> 구현기술로 명시). ⚠️ *shift-left는 N2SF 전용 항목이 없어 관련 항목(SG-5(1) 개발/테스트 분리·IN-4 변경 검증·
> IN-15 해시/서명 무결성)만 '관련'으로 표기 — 1:1 등가 아님(대조 필요).*

---

## 5. 자율보안 · 사후책임 ↔ 이 스택의 "검증가능성"

MLS는 통제를 *갖췄는지*가 아니라 *스스로 입증·책임지는지*를 본다. 이 repo는 그 입증을
산출물로 만든다:

- **자율보안 이행의 증거** = `cedar/authz.py` 8/8, `scripts/verify.*` **21/21 라이브**,
  checkov 게이트, CI 통합잡(클러스터 띄워 재검증). "정책이 있다"가 아니라 "정책이 실제로
  막는다"를 매번 보인다.
- **사후책임/감사추적** = **Tetragon** 프로세스 exec 기록, **Hubble** 플로우 가시성
  (`hubble observe --verdict DROPPED`). 누가·무엇이·어디서를 사후 재구성.
- **정직한 위협모델**(`THREAT_MODEL.md`, 잔여위험·스코프 명시) = 자율보안의 핵심인
  *과대주장 금지*. CISO·이사회 보고 라인이 신뢰할 수 있는 형태.

---

## 6. NIST SP 800-207 제로트러스트 7원칙 (요약 매핑)

| 원칙 | 이 스택에서 |
|------|------------|
| 1 모든 자원을 리소스로 | api/db를 정책 대상 리소스로(Cedar/Cilium) |
| 2 위치 무관 통신 보호 | **WireGuard + mutual auth** — 망분리 완화의 정수(위치≠신뢰) |
| 3 세션 단위 접근 | mutual-auth SVID 핸드셰이크, per-request Cedar |
| 4 동적 정책 | Cedar 컨텍스트(한도·동결) + admission(요청자 신원) |
| 5 자산 무결성 모니터 | Tetragon 런타임 + PSA restricted |
| 6 모든 인증·인가를 접근 전 강제 | L3→L7→Cedar→admission이 접근 전에 결정 |
| 7 상태 정보 수집·활용 | Hubble/Tetragon 텔레메트리 |

---

## 7. 정직한 한계 (무엇을 주장하지 *않는가*)

- **규정 준수 확인서가 아니다.** (C/S/O 등급 정의는 N2SF로, SaaS 예외의 반기 1회 평가는 시행세칙
  제2조의3 제4항으로 1차 확인됨 — §2·§8.) 단 금융권 전반의 적용 의무·금융보안원 인증·등급 분류
  거버넌스의 실제 적용은 여전히 1차 출처/개정 규정 대조가 필요하다.
- **실 데이터스토어가 없다.** `db`는 자리표시자, 엔티티는 정적. 데이터 생애주기(보존·파기·
  가명처리)는 통제 *형태*만 보이고 실제 데이터엔 적용하지 않았다.
- **신원 입력(X-User)은 데모용 미인증 헤더** — 실제는 검증된 JWT `sub`/SVID에서 파생.
- **단일 워크로드 데모**다. 전사 MLS는 등급 분류 거버넌스·DLP·SIEM·키관리(HSM/KMS)까지
  포함하며, 이 repo는 그중 **워크로드 보상통제 레이어의 레퍼런스**다.
- **WireGuard는 노드 간 암호화다.** 이 데모는 **2워커** 구성이고 `db`를 `api`와 다른 노드로
  강제(podAntiAffinity)해, `api→db` 홉이 선상을 가로질러 WireGuard로 암호화된다. `verify`는
  *WireGuard 활성 + api/db 다른 노드*를 함께 단언해(상시 스위트) "이 앱 홉이 선상에서 암호화됨"을
  증명한다. 추가로 `scripts/capture-wg.sh`(opt-in 증거)가 db 노드 host netns에서 실제 api→db
  트래픽 중 WireGuard 패킷(UDP/51871, 원본 런은 `-c 40` 캡처 상한)과 eth0 평문 0을 포착했다 —
  ET2를 CONFIGURED→**VERIFIED**로 승격. *결정적* 증거는 WG패킷 존재+크로스노드 배치이고, 평문부재는
  *보강*이다(크로스노드 트래픽은 캡슐화되어 평문이 eth0에 안 나타날 수 있음). 단, cipher 강도나
  동일노드 홉 암호화는 주장하지 않으며, 이 캡처는 상시 베이스라인이 아닌 opt-in/gated 증거다.
- **ISMS-P 항목번호는 개념 매핑**이다(§4). 실제 인증기준 항목과의 정밀 대조는 별도 작업이다.

이 한계를 명시하는 것 자체가 MLS의 "자율보안·정직성"에 부합한다.

---

## 8. 출처

- 금융위원회, 「금융분야 망분리 개선 로드맵」 보도자료(2024-08-13) — <https://www.fsc.go.kr/no010101/82885>
- 김·장 법률사무소, "금융분야 망분리 개선 로드맵 발표"(3단계 추진·일자) — <https://www.kimchang.com/ko/insights/detail.kc?idx=31199>
- 보안뉴스, "전자금융 분야 다층보안체계 도입과 망분리 개선"(C/S/O 등급·보상통제·3단계) — <https://m.boannews.com/html/detail.html?idx=134355>
- 이글루코퍼레이션, "전자금융 보안의 망분리 개선안 정책과 다층보안체계(MLS)" — <https://www.igloo.co.kr/security-information/>
- The Korea Times, "Gov't to ease network regulations on internal use of cloud-based SaaS"(규정 개정 진행, 2026-01) — <https://www.koreatimes.co.kr/economy/policy/20260119>
- NIST SP 800-207, *Zero Trust Architecture* — <https://csrc.nist.gov/pubs/sp/800/207/final>

**1차 자료 (조문 단위 대조 완료 — 공개 발간물, 본 repo엔 미동봉):**
- 금융보안원, 「내부업무망 SaaS 망분리 예외 적용에 따른 보안 해설서」 — 시행세칙 제2조의3제1항제3호(모법 제15조제1항제3호*나목*) + 반기 1회 평가(제2조의3 제4항).
- 금융보안원, 「2026년 전자금융기반시설 보안 취약점 평가기준 안내서」(금융위 고시 제2025-4호) — 통제별 전자금융감독규정 제N조 [근거조항](§4).
- 국가정보원, 「국가 망 보안체계(N2SF) 실증 사례집」 — 데이터 등급 C/S/O 정의(기밀 C·민감 S·공개 O; 출처 N2SF 보안 가이드라인 1.0).
- KISA, 「SBOM 기반 공급망 보안 모델 구축 사례집」(2026.4) — 공급망/SBOM 모범사례(CycloneDX·Trivy·cosign·in-toto). *사례집(권고)이지 규정 아님; checkov/IaC는 미수록.*

> ⚠️ 정책 세부는 변동·해석 여지가 있다. 공개 발표/제출 전 FSC 1차 자료와 금융보안원
> 가이드로 등급·의무·인증 요건을 반드시 재확인할 것.
