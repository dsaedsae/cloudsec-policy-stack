<!--
Marp deck — render to HTML/PDF/PPTX:
  npx @marp-team/marp-cli@latest presentation/slides.md -o presentation/slides.html
  npx @marp-team/marp-cli@latest presentation/slides.md --pdf
(or: VS Code "Marp for VS Code" extension, or paste into https://marp.app)
Content tracks presentation/talk-outline.md; numbers are verbatim from index.md 핵심 결과.
-->
---
marp: true
paginate: true
size: 16:9
style: |
  :root{--teal:#1f8a70;--ink:#1a237e;--orange:#c2410c}
  section{font-family:"Noto Sans KR","Segoe UI",sans-serif;font-size:25px;color:#1f2433}
  h1,h2{color:var(--ink)}
  strong{color:var(--teal)}
  code{font-family:"JetBrains Mono",Consolas,monospace;background:#eef1f7;color:var(--ink)}
  section.lead{justify-content:center;text-align:center}
  section.lead h1{font-size:46px;letter-spacing:-.01em}
  .term{background:#16182a;color:#c8d3e6;border-radius:10px;padding:.6em .9em;font-family:"JetBrains Mono",monospace;font-size:21px}
  .ok{color:#7ee0a8}.no{color:#ff8a8a}.cy{color:#8fd0ff}.dim{color:#7681a3}
  table{font-size:22px}
  footer{color:#8a93a6;font-size:13px}
footer: 'cloudsec-policy-stack · 교육·포트폴리오 레퍼런스 (법률/금융 자문·공식 FSC 매핑 아님)'
---

<!-- _class: lead -->
# 망분리를 풀면,<br>신뢰를 무엇으로 대체하는가

### MLS 보상통제를 **코드로 증명**하기

<br>

검증가능 커버리지 **72% (29/40)** · 라이브 검증 **21/21** · 무료 로컬 · MIT

---

## 문제 — 위치 = 신뢰가 사라진다

FSC 「금융분야 망분리 개선 로드맵」(2024-08-13): *위치 기반 분리* → *위험 기반 MLS*.

- "내부망 안이니 신뢰"가 무너진다.
- 그 자리를 **보상통제**로 메워야 한다.
- 핵심 질문: 그 통제가 **실제로 막는지**를 어떻게 증명하나? — 슬라이드가 아니라 **실행과 검증**으로.

---

## 접근 — 한 워크로드, 6개 통제 계층

요청 → **① 신원**(admission·SA·SPIFFE) → **② 세분화**(Cilium L3/L7 default-deny) → **③ 인가**(Cedar per-request) → **db(기밀 C)**

그 위에:

- **④ egress default-deny** — 유출/SSRF 차단
- **⑤⑥ 암호화** — WireGuard 전송 · etcd 저장
- **⑦ 런타임** — Tetragon eBPF, 데이터티어 셸 in-kernel SIGKILL

각 계층은 **실행 가능한 테스트**에 묶인다.

---

## "아하" — 같은 경로, 다른 신원

<div class="term">
alice → GET /accounts/acct-alice &nbsp; <span class="ok">200</span><br>
bob &nbsp;&nbsp;→ GET /accounts/acct-alice &nbsp; <span class="no">403</span>
</div>

<br>

같은 네트워크 경로·같은 L7 허용이라도 **principal이 다르면 결과가 다르다.**
거친 통제(RBAC·세분화) → 세밀한 통제(ABAC·per-request)를 *순서대로* 통과해야 데이터에 닿는다.

---

## 증거 — 전부 재현 가능

| 항목 | 결과 |
|---|---|
| 검증가능성 커버리지 | **72% (29/40)** · 갭 행 단위 공개 |
| 라이브 방어심층 검증 | **21 / 21** (기능 회귀 스위트) |
| Cedar 인가 단위테스트 | **8/8** 코어 · **17/17** 에이전트 위임 |
| ReBAC (OpenFGA) | **11 / 11** |
| checkov shift-left | **452 pass / 0 fail** · 실 CVE 1건 포착→수정 |

<span style="font-size:17px;color:#5b6478">정직 단서: 21/21은 기능 스위트(분모 없는 측정 아님), 72% 분모=40, 28% 갭은 공개.</span>

---

## 왜 신뢰할 수 있나 — "안전하다"가 아니라 "갭을 공개한다"

- **재현 증거** — 감사자가 부작용 없는 dry-run으로 직접 확인.
- **명시된 갭** — CONFIGURED 7 · GOVERNANCE 2 · NOT_COVERED 4 (행 단위).
- **정직성의 증명** — 요청자 JWT 미강제 행(ID8)을 *스스로 추가해 헤드라인을 낮췄다*.
- **적대적 자기검증** — 우리 정책의 실 결함(SA-use 우회 CRITICAL)을 찾아 수정·재검증.

> 증명 못 하는 통제는 감사에서 보상통제로 주장할 수 없다. 증명되는 통제는 **감사 증거 부담을 줄인다.**

---

## 라이브 데모 (5분, 그대로 실행 가능)

<div class="term">
<span class="dim"># 전체 방어 한 번에</span><br>
bash scripts/verify.sh &nbsp; → &nbsp; <span class="ok">21/21 PASS</span><br>
<span class="dim"># 신원 위조 차단</span> &nbsp; forged app:api on web-sa → <span class="no">DENY</span><br>
<span class="dim"># 런타임</span> &nbsp; db: /bin/sh → <span class="no">rc=137</span> &nbsp; db: id → <span class="ok">rc=0</span><br>
<span class="dim"># 저장 암호화</span> &nbsp; etcd raw → <span class="cy">k8s:enc:aescbc:v1:</span> (평문 0)
</div>

---

## 도입

- **자가채점 재구현 트랙** — 보안/플랫폼 엔지니어 온보딩 (무클러스터 랩은 Codespaces 0설치).
- **사내교육 가이드** — 트랙·아젠다·채점·리셋 (`docs/using-for-training.md`).
- **MIT · 당신의 인프라에서 실행** (telemetry/phone-home 없음).

<br>

<!-- _class: lead -->
### 망분리 완화는 규제 *완화*가 아니라 **신뢰 모델의 교체**다.
