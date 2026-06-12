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
- **금융위·금감원 「금융분야 망분리 개선 로드맵」(2024-08-13)** 이 단계적(1~3단계) 완화를
  발표했다. 핵심은 "완전 차단"에서 **위험기반 다층보안(MLS)** 으로의 전환 — *"업무 목적에
  따라 통제된 연결"* 을 허용하되, 보안 공백을 보상통제로 메운다.
- 즉 **"네트워크 위치로 신뢰"가 사라진 자리를 신원·워크로드·데이터 기반 통제로 대체**해야
  한다. 이 repo가 구현·검증하는 것이 정확히 그 대체 통제다.

> 출처·정확도: 아래 §8. 로드맵의 **시행 세부(등급 정의, 적용 의무)는 전자금융감독규정 개정·
> 금융보안원 가이드로 구체화**되는 중이므로, 실제 인증·제출 시 1차 출처 대조가 필요하다.
> 이 문서는 "통제 설계의 정합성"을 보이는 것이지 규정 준수 확인서가 아니다.

---

## 2. MLS 핵심 (정책 요약)

| 축 | 내용 |
|----|------|
| **데이터 등급** | **기밀(C, Classified) · 민감(S, Sensitive) · 공개(O, Open)** 3등급. 등급별 **차등 보안통제**. 한 시스템에 여러 등급 데이터가 있으면 **최상위 등급 기준**으로 시스템 등급 결정. |
| **운영 원칙** | **자율보안 + 사후책임** — CEO·이사회 보고의무, CISO 권한 확대, 검증 미흡 시 시정요구·이행명령, 자율보안 이행 기업에 샌드박스 가점. |
| **명시된 보상통제** | 제로트러스트 아키텍처(모든 사용자 불신·철저 확인·최소 접근), **강화된 사용자 인증(자격증명 위조 여부 확인)**, **최소 권한**, **암호화 강화**, **이상 탐지(EDR)**, **네트워크 마이크로 세분화**. |
| **단계** | ① 생성형 AI 규제 샌드박스 ② SaaS 활용 확대 ③ R&D 환경 개선(가명 개인신용정보 직접 처리 단계적 허용). 민감정보(개인신용정보)는 별도 안전장치 전제. |

---

## 3. 데이터 등급(C/S/O) ↔ 이 스택

데모 앱(web → api → db)을 MLS 등급 모델에 대입하면:

| 티어 | MLS 등급(가정) | 다루는 데이터 | 적용된 차등통제 |
|------|---------------|--------------|----------------|
| `db` (data) | **기밀(C)** | 계좌·잔액(개인신용정보 상당) | 진입 차단(api만), 셸 실행 시 즉시 SIGKILL, **저장 시 암호화(etcd)**, egress 없음 |
| `api` (backend) | **민감(S)** | 처리 중 데이터 + 인가 판단 | per-request Cedar 인가, L7 경로/메서드 제한, **전송 중 암호화(WireGuard)**, 신원(mutual auth) |
| `web` (frontend) | **공개(O)** 경계 | 외부 진입점 | 인터넷·메타데이터·API서버로 egress 차단(데이터 유출 경로 봉쇄) |

→ "최상위 등급 기준으로 시스템 등급 결정" 원칙에 따라, **`db`가 기밀이면 그 경로 전체가
기밀 수준 통제**를 받아야 한다. 이 스택은 db로 가는 모든 홉(network→L7→Cedar→runtime)과
db의 데이터(at-rest 암호화)에 통제를 중첩해 그 요구를 충족한다.

---

## 4. 보상통제 매트릭스 (이 문서의 핵심)

각 행 = MLS가 요구하는 보상통제 → **망분리의 어떤 가정을 대체**하는가 → 이 repo의 구현 →
NIST SP 800-207 원칙 → ISMS-P 영역(개념 매핑, 정확한 항목번호는 대조 필요) → **검증 방법**.

| MLS 보상통제 | 대체하는 "망분리 가정" | 이 repo 구현 | NIST 800-207 | ISMS-P(개념) | 검증 (verify 항목) |
|---|---|---|---|---|---|
| **네트워크 마이크로 세분화** | "내부망 안은 평평하고 신뢰 가능" | Cilium default-deny in/out, web→api→db만, **L7**(메서드/경로) | Tenet 1·3 | 2.6 접근통제 | `web→db 000`, `api→db 200`, `L7 /auditlogs 403` |
| **제로트러스트(위치 무관 통신 보호)** | "외부와 분리됐으니 내부 트래픽은 평문 OK" | 이그레스 default-deny(인터넷·메타데이터·API서버 000) + 전 구간 정책 | Tenet 2·6 | 2.6/2.10 | egress `000` ×3 |
| **강화된 사용자 인증 / 자격증명 위조 확인** | "망 안에 있으면 곧 신원" | 라벨↔SA admission, **SA-use gate**(요청자↔SA 바인딩), **SPIFFE mutual auth(SVID)** | Tenet 3·6 | 2.5 인증/권한 | `forged app:api→DENY`, `shop:deployers as api-sa→DENY`, mutual-auth `200` |
| **최소 권한** | "내부 시스템 간 광범위 허용" | 티어 SA 권한 0, Cedar(owner·한도·역할·동결), shop-deployer 최소 Role | Tenet 4·6 | 2.5/2.6 | `api-sa no create-pods`, Cedar allow/deny 6종 |
| **암호화 강화 (전송)** | "분리망이라 도청 위험 낮음" | Cilium **WireGuard** 노드 간 파드 트래픽 암호화 (§7 주의) | Tenet 2 | 2.7 암호화 | `WireGuard PASS`(=암호화 활성) |
| **암호화 강화 (저장)** | "내부 저장소 접근자 제한으로 충분" | etcd **Secret AES-CBC 암호화**(`k8s:enc:aescbc`) | Tenet 1·2 | 2.7 암호화 | raw etcd 암호문/평문0 |
| **이상 탐지 (EDR)** | "분리로 침투 자체가 어려움" | **Tetragon**(eBPF) 데이터 티어 셸 실행 in-kernel 차단 + 프로세스 감사 | Tenet 5·7 | 2.11 사고대응/탐지 | `shell exec→SIGKILL 137` |
| **사전 통제(shift-left)** | "운영 후 점검으로 충분" | **checkov** Terraform+K8s 게이트(0 fail), gitleaks | Tenet 4 | 2.8 개발보안 | checkov 445/0, CI |

**핵심 메시지:** "자격증명 위조 여부 확인"은 MLS가 명시한 보상통제다. 이 repo의 B7 작업
(라벨↔SA + SA-use gate + SVID)은 *바로 그것을 워크로드 레벨에서 코드로 구현하고 라이브로
거부를 증명*한다 — 망분리가 풀린 환경에서 "내부에 있으니 곧 `api`다"라는 가정을 깬다.

---

## 5. 자율보안 · 사후책임 ↔ 이 스택의 "검증가능성"

MLS는 통제를 *갖췄는지*가 아니라 *스스로 입증·책임지는지*를 본다. 이 repo는 그 입증을
산출물로 만든다:

- **자율보안 이행의 증거** = `cedar/authz.py` 8/8, `scripts/verify.*` **20/20 라이브**,
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

- **규정 준수 확인서가 아니다.** C/S/O 등급 정의·적용 의무·금융보안원 인증·반기 점검 등은
  전자금융감독규정 개정/가이드로 확정되며, 실제 적용은 1차 출처 대조가 필요하다.
- **실 데이터스토어가 없다.** `db`는 자리표시자, 엔티티는 정적. 데이터 생애주기(보존·파기·
  가명처리)는 통제 *형태*만 보이고 실제 데이터엔 적용하지 않았다.
- **신원 입력(X-User)은 데모용 미인증 헤더** — 실제는 검증된 JWT `sub`/SVID에서 파생.
- **단일 워크로드 데모**다. 전사 MLS는 등급 분류 거버넌스·DLP·SIEM·키관리(HSM/KMS)까지
  포함하며, 이 repo는 그중 **워크로드 보상통제 레이어의 레퍼런스**다.
- **WireGuard는 노드 간 암호화다.** 이 데모는 1워커 구성이라 web/api/db 파드가 같은 노드에
  배치되어, 그 홉은 노드를 떠나지 않아 선상 암호화 대상이 아니다. `verify`의 WireGuard 항목은
  *암호화가 활성(노드 간)임*을 확인한다. 실제 다중 노드 배포에서 파드가 노드를 가로지르면
  그 트래픽이 암호화된다. (정직 차원의 명시 — 등급 데이터가 노드 경계를 넘을 때를 가정.)
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

> ⚠️ 정책 세부는 변동·해석 여지가 있다. 공개 발표/제출 전 FSC 1차 자료와 금융보안원
> 가이드로 등급·의무·인증 요건을 반드시 재확인할 것.
