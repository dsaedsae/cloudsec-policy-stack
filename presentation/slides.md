---
marp: true
paginate: true
size: 16:9
style: |
  :root{--bg:#0b0d10;--fg:#e7e9ee;--mut:#8b9099;--faint:#4b515b;--line:#1b1f25;--acc:#34d399}
  section{background:var(--bg);color:var(--fg);font-family:"Noto Sans KR","Segoe UI",sans-serif;font-size:26px;padding:64px 76px;letter-spacing:.2px}
  section::after{color:var(--faint);font-family:"JetBrains Mono",monospace;font-size:14px}
  h1{font-size:50px;font-weight:900;letter-spacing:-.02em;margin:0 0 .35em}
  h2{font-size:30px;font-weight:800;margin:0 0 .6em}
  strong{color:#fff;font-weight:700}  em{color:var(--mut);font-style:normal}
  code{font-family:"JetBrains Mono",monospace;background:#14171c;color:var(--acc);padding:.05em .35em;border-radius:4px;font-size:.82em}
  a{color:var(--acc);text-decoration:none}
  hr{border:0;border-top:1px solid var(--line);margin:.5em 0}
  ul{list-style:none;padding:0} li{margin:.55em 0;padding-left:1.2em;position:relative;color:var(--fg)}
  li::before{content:"—";position:absolute;left:0;color:var(--faint)}
  table{border-collapse:collapse;font-family:"JetBrains Mono",monospace;font-size:.82em;width:100%}
  td,th{border:0;border-bottom:1px solid var(--line);padding:.55em .2em;text-align:left}
  th{color:var(--mut);font-weight:500;text-transform:none}
  td:last-child,th:last-child{text-align:right}
  td:last-child{color:var(--acc);font-weight:700}
  .kick{font-family:"JetBrains Mono",monospace;color:var(--acc);font-size:17px;letter-spacing:.12em}
  .mono{font-family:"JetBrains Mono",monospace;font-size:.92em}
  .mut{color:var(--mut)} .no{color:#f06f6f} .ok{color:var(--acc)}
  section.lead{justify-content:center} section.lead h1{font-size:62px}
footer: 'cloudsec / verified by code · 교육·포트폴리오 레퍼런스 — 법률/금융 자문·공식 FSC 매핑 아님'
---

<!-- HTML inline used (spans) → render WITH --html:
     npx @marp-team/marp-cli@latest presentation/slides.md --html -o presentation/slides.html
     (또는 --html --pdf · VS Code "Marp for VS Code"는 설정에서 html 허용). 숫자는 index.md verbatim. -->

<!-- _class: lead -->
<span class="kick">KOREA FSC · 망분리 완화 → 위험기반 MLS</span>

# 망분리를 풀면,<br>신뢰를 무엇으로 대체하는가

<span class="mut">MLS 보상통제를 **코드로** — 막는다는 사실을 매번 라이브로 재현.</span>

---

## 문제

FSC 로드맵(2024-08-13): **위치 기반 분리 → 위험 기반 MLS**.

- "내부망 = 신뢰"가 사라진다
- 그 자리를 보상통제로 메워야 한다
- 핵심: 그 통제가 **실제로 막는지**를 무엇으로 증명하나 — 슬라이드가 아니라 **실행·검증**

---

## 접근 — 한 워크로드, 6개 통제 계층

<p class="mono">identity <span class="mut">→</span> segmentation <span class="mut">→</span> authz <span class="mut">→</span> encrypt <span class="mut">→</span> runtime</p>

- **① 신원** admission · SA-use · SPIFFE
- **② 세분화** Cilium L3/L7 default-deny
- **③ 인가** Cedar per-request (owner·한도·역할·동결)
- **④ egress / ⑤⑥ 암호화 / ⑦ 런타임** — 유출 차단 · WireGuard·etcd · Tetragon 셸 SIGKILL

각 계층은 **재실행 가능한 테스트**에 묶인다.

---

## 증거 — 전부 재현 가능

| metric | | |
|---|---|---|
| coverage | 검증가능-as-code | 75% (30/40) |
| verify | 라이브, 전 계층 | 21/21 |
| cedar | 인가 + 에이전트 위임 | 8/8 · 17/17 |
| rebac | OpenFGA 관계 | 11/11 |
| checkov | shift-left · 실 CVE 포착 | 452 / 0 |

<span class="mut mono" style="font-size:.7em">// 21/21은 기능 회귀 스위트(분모 없음) · 갭 25%(CONFIGURED 6·GOVERNANCE 2·NOT-COVERED 4)는 행 단위 공개</span>

---

## "아하" — 같은 경로, 다른 신원

<p class="mono" style="font-size:1.15em;line-height:2">alice GET acct-alice <span class="ok">200</span><br>bob &nbsp;&nbsp;같은 경로 &nbsp;&nbsp;&nbsp;<span class="no">403</span></p>

같은 네트워크 경로·같은 L7 허용이라도 **principal이 다르면 결과가 다르다.**
거친 통제(세분화) → 세밀한 통제(per-request)를 순서대로 통과해야 데이터에 닿는다.

---

## 왜 신뢰할 수 있나

<span class="mut">"안전하다"가 아니라 — </span>**갭을 공개한다.**

- **재현 증거** — 감사자가 부작용 없는 dry-run으로 직접 확인
- **명시된 갭** — 미검증 25%를 행 단위로 공개
- **정직성** — 요청자 JWT 미강제 행을 *스스로 추가해 헤드라인을 낮췄다* (편한 숫자 대신 참값)
- **적대적 자기검증** — 우리 정책의 실 결함(SA-use CRITICAL)을 찾아 수정·재검증

---

## 라이브 데모 (5분, 그대로 실행)

<p class="mono mut" style="line-height:2.1"><span class="ok">$</span> bash scripts/verify.sh &nbsp;&nbsp;→&nbsp;&nbsp;<span class="ok">21/21 PASS</span><br>forged app:api on web-sa &nbsp;→&nbsp;<span class="no">DENY</span><br>db: /bin/sh <span class="no">137</span> &nbsp; db: id <span class="ok">0</span><br>etcd raw &nbsp;→&nbsp;<span class="ok">k8s:enc:aescbc:v1:</span> (평문 0)</p>

---

<!-- _class: lead -->
## 도입

<span class="mut">자가채점 재구현 트랙 · 무클러스터 랩은 Codespaces 0설치 · MIT · 당신의 인프라</span>

<br>

# 망분리 완화는 규제 *완화*가<br>아니라 **신뢰 모델의 교체**다.
