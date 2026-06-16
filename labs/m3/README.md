# M3 — 네트워크: Cilium 제로트러스트 (L3/L7 + egress)

<div class="lab-pills">
<span class="lab-progress">모듈 4 / 7</span> · <span class="lab-badge">스택 Cilium L3/L7</span> · <span class="lab-badge">소요 ~30–45m</span> · <span class="lab-badge cluster">클러스터 필요 · RAM ~6–8GB</span> · <span class="lab-badge">비용 $0 로컬</span>
</div>

**미션:** default-deny에서 시작해 **최소권한 홉**(외부→web→api→db)만 여는 CiliumNetworkPolicy를
직접 구성한다. L7으로 web→api 경로를 메서드/path까지 제한하고, egress도 default-deny로 막는다.

> **학습 성과 (면접에서 말할 수 있는 것):** default-deny에서 최소권한 L3/L7/egress 홉을 재구성하고, "위치≠신뢰"와 *과차단도 결함*(가용성)이라는 양면을 설명할 수 있다. → [캡스톤 M3](../capstone.md)

**클러스터 필요.** **편집 파일:** `labs/m3/netpol.yaml` (허용 홉 5개의 rule).

> 선행: M2 권장(같은 클러스터 세션). 배경: [`docs/03-network-and-authz.md`](../../docs/03-network-and-authz.md).

> **YAML 구조가 막막하면 → [배우기 모드: LEARN.md](LEARN.md).** 홉 규칙 1개(L3/L4/L7 전체)를 주석과 함께 읽고 → 두 번째 홉을 빈칸으로 채우고 → 나머지는 직접. L3/L4 DROP과 L7 403의 차이까지 짚어준다.

---

## Step 0 — 베이스라인

> 클러스터가 떠 있다고 가정한다(M2~M5 한 세션). 안 떴으면 PowerShell에서 `scripts\up.ps1` 먼저.
> 채점기는 **Git Bash**에서 (forward slash). [SETUP](../SETUP.md).

```bash
# Git Bash 창에서:
kubectl cluster-info --context kind-cloudsec   # 떴는지 확인 (에러면 → PowerShell: scripts\up.ps1)
bash labs/m3/grade.sh        # 시작: web->db는 차단되지만(베이스라인 default-deny), 허용 홉들이 비어서
                             #        web->api 200·api->db 200 이 FAIL (과차단)
```

> 두 베이스라인(default-deny-ingress, DNS egress)은 완성돼 있어 **차단은 처음부터 된다**. 문제는
> *허용*이 비어서 정상 트래픽까지 막히는 것. 보안은 "다 막기"가 아니라 "필요한 것만 열기" — 과차단도
> 결함이다(가용성).

**왜 default-deny가 출발점인가 (allowlist vs blocklist):** blocklist("나쁜 것만 막기")는 공격자가
*안 적힌* 경로를 찾으면 끝난다 — 새 워크로드·새 포트·새 egress 목적지가 늘 때마다 차단 규칙을
사람이 따라 적어야 한다. allowlist(default-deny + 명시 허용)는 반대로 *모르는 것은 자동 차단*이라
새 위협을 사람이 쫓을 필요가 없다. [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final)이
"per-session"·최소권한을 핵심 원리로 두는 것과 같다 — 이 랩의 두 베이스라인이 "deny by default"
표면이고, Step 1의 5개 홉이 명시 허용이다.

## Step 1 — 허용 홉 5개 작성

`labs/m3/netpol.yaml`의 TODO 5곳을 채워라. 핵심 문법:

```yaml
# ingress 허용 (L3/L4): 누구로부터(fromEndpoints) 어느 포트로
ingress:
  - fromEndpoints: [{ matchLabels: { app: <src> } }]
    toPorts: [{ ports: [{ port: "8080", protocol: TCP }] }]

# L7 HTTP 제한 (web->api 에만): toPorts 안에 rules.http
    toPorts:
      - ports: [{ port: "8080", protocol: TCP }]
        rules:
          http:
            - { method: "GET",  path: "/accounts/[^/]+$" }
            - { method: "POST", path: "/accounts/[^/]+/transfer$" }

# ingress 외부 진입(web): fromEntities: ["cluster"]
# egress 허용: toEndpoints + toPorts (방향만 다름)
```

| TODO | 규칙 |
|---|---|
| `allow-web-to-api` | app:web 에서 8080, **L7으로 GET /accounts/... + POST .../transfer 만** (auditlogs는 자동 403) |
| `allow-api-to-db` | app:api 에서 8080 (L3/L4) |
| `allow-ingress-to-web` | `fromEntities: ["cluster"]` 8080 |
| `egress-web-to-api` | app:api 로 8080 |
| `egress-api-to-db` | app:db 로 8080 |

```bash
bash labs/m3/grade.sh        # 7/7 PASS → M3 GRADUATED. 채점 후 canonical 자동 복원.
```

### 흔한 실수 (실제 증상 → 원인)

- **ingress만 열고 egress를 잊음.** `allow-web-to-api`(ingress)는 적었는데 `egress-web-to-api`를 빠뜨리면
  "허용 web->api 200" 줄이 **000**. 연결은 *양 끝* 정책을 다 통과해야 선다 — 발신자 egress(web가 나가도 되나)
  + 수신자 ingress(api가 받아도 되나). 한 방향만 열면 안 된다.
- **port를 숫자가 아니라 문자열로 안 씀.** `port: 8080`(int)으로 적으면 `k apply`가 schema 에러로
  거부 → 채점기는 "apply 실패"를 찍고 canonical을 복원한 뒤 exit 1. Cilium 스키마는 `port: "8080"`(문자열)을
  요구한다. grade.sh의 첫 줄이 PASS/FAIL이 아니라 apply 에러면 거의 이 문제다.
- **L7 path를 prefix로 착각.** `path: "/accounts"`로 적으면 정규식 *부분* 매칭이라 의도와 다르게 동작한다.
  Cilium HTTP path는 정규식이고 canonical은 `$`로 끝을 못 박는다(`/accounts/[^/]+$`). anchor가 없으면
  `/accounts/acct-alice/auditlogs`까지 걸려 L7 차단이 새어 나간다(Step 2의 4번).
- **DNS egress를 빠뜨린 채 다른 egress만 추가.** DNS 베이스라인이 사라지면 파드가 `api`라는 *이름*을
  못 풀어 connect 자체가 실패한다 — egress L3는 열려 있어도 이름 해석이 막혀 200이 안 나온다. 이 랩에선
  DNS 베이스라인이 이미 완성돼 있으니 지우지 마라.

> db에 egress 규칙을 *안* 주는 게 의도다 — DNS 베이스라인만 적용돼 db는 DNS 외 아무 데도 못 나간다
> (가장 잠긴 tier). "안 적는 것"도 정책이다.

### 정체성(identity) 기반이지 IP 기반이 아니다

채점기를 보면 `fromEndpoints: { app: web }`로 적은 규칙이, 실제 검증에선 `probe-web`의 *podIP*로
api에 curl을 친다(`API=$(... podIP)`). 즉 정책은 IP를 한 줄도 안 적었는데 IP 트래픽이 정확히 매칭된다.
Cilium은 파드의 레이블 셋을 **security identity**(숫자 ID)로 해석하고, 데이터플레인(eBPF)이 패킷의
출발 identity를 보고 판정한다 — IP는 부산물이다. 그래서:

- 파드가 죽고 새 IP로 재스케줄돼도 레이블이 같으면 정책이 **그대로** 적용된다. IP 기반 ACL이라면
  매번 갱신해야 한다(레이스 동안 구멍).
- 공격자가 web 파드를 침해해 IP를 바꿔도(또는 IP 스푸핑) api 접근 권한이 따라오지 않는다 —
  권한은 IP가 아니라 *워크로드 정체성*에 묶여 있다.
- 이 정체성은 M2의 admission/ServiceAccount와 같은 축이다. `k8s/probes.yaml`이 `probe-web`에
  `serviceAccountName: web-sa` + `app: web` 레이블을 같이 다는 이유: 한 워크로드의 정체성이
  네트워크(Cilium identity)·인가(Cedar principal)·진입(admission)에서 *일관*되게 쓰인다.

## Step 2 — break-and-fix (예측 → 확인)

채점기 7줄을 기억하라: web→db **000**, auditlogs **403**, accounts **200**, api→db **200**,
egress 인터넷/메타데이터/apiserver **000**. 각 변형이 *어느 줄*을 어떻게 바꾸는지 먼저 적고, 돌려 확인하라.
(`grade.sh`는 끝나면 canonical을 복원하므로 마음껏 깨도 된다.)

1. `allow-web-to-api`의 L7 `rules.http`를 통째로 지우고 포트만 남긴다 → auditlogs 케이스는? (힌트: L7이 사라지면)
2. `egress-web-to-api`를 지운다 → web->api 200 케이스는? egress도 막혔으니.
3. `default-deny-ingress`를 지운다 → web->db 차단 케이스는? (Cilium은 *어떤* 정책이 endpoint를 고르면 그 방향이 default-deny가 된다 — 이 미묘함을 직접 보라)
4. `allow-web-to-api`의 path를 `/accounts/[^/]+$` → `/accounts/.*` 로 푼다 → auditlogs 케이스는? (`.*`는 슬래시도 먹는다)
5. `egress-web-to-api`의 `toEndpoints: { app: api }` → `toEntities: ["world"]` 로 바꾸고 `toPorts`도 지운다(또는 443 추가) → egress 인터넷(000) 케이스는? (힌트: 채점기는 `https://example.com`=443으로 친다 — 포트도 같이 열어야 한다)

<details><summary>1번 후 열 것</summary>L7 rules가 없으면 web→api 8080 전체가 열린다 → /auditlogs도 200이 되어 "L2 403" 케이스 FAIL. L7은 *네트워크 계층에서* path/method를 막는 것 — 앱(Cedar)에 닿기 전에 차단하는 다층 방어의 한 겹.</details>
<details><summary>2번 후 열 것</summary>egress-web-to-api가 사라지면 web가 가진 egress 규칙은 DNS 베이스라인뿐. web는 *이미 egress 정책의 대상*(DNS 규칙이 모든 파드 선택)이라 egress 방향이 default-deny 상태 → api:8080도 막힌다. "허용 web->api 200" 줄이 **000**으로 FAIL. ingress 쪽 `allow-web-to-api`가 멀쩡해도 *나가는* 다리가 없으면 연결이 안 선다 — ingress·egress는 양쪽 다 열려야 한다.</details>
<details><summary>3번 후 열 것</summary>직관과 달리 web→db는 **여전히 000으로 PASS**다. `allow-api-to-db`가 db를 ingress 대상으로 고르는 순간 db의 ingress가 default-deny가 되고, web는 그 허용 목록(api만)에 없다. default-deny-ingress 정책은 *아직 아무 정책도 안 고른* 파드를 잠그는 안전망이지, db 차단의 *유일한* 근거가 아니다. (반대로 어떤 파드도 안 고르는 tier가 생기면 그때 이 베이스라인이 일한다 — 그게 "안전망"의 뜻.)</details>
<details><summary>4번 후 열 것</summary>`/accounts/.*`의 `.`는 슬래시 포함 모든 문자 → `GET /accounts/acct-alice/auditlogs`도 매칭 → **200**. "auditlogs 403" 줄 FAIL. 경로 정규식은 *anchor*(`$`)와 *문자 클래스*(`[^/]+` = 슬래시 제외)가 핵심 — `.*`로 느슨하게 쓰면 한 세그먼트 제한이 무너져 하위 경로가 줄줄이 새어 나간다. 실제 L7 정책 사고의 단골 원인.</details>
<details><summary>5번 후 열 것</summary>`toEntities: ["world"]`는 클러스터 밖(인터넷) 전체를 egress 허용 대상으로 연다. 단, 원래 규칙의 `toPorts`가 8080만 두면 443으로 가는 example.com 프로브는 여전히 DROP(000 PASS)이다 — egress는 *목적지 + 포트* 둘 다 매칭돼야 통과한다. `toPorts`까지 지워(=전 포트) 인터넷을 열면 그때 "egress web->인터넷(차단)" 줄이 연결 성립으로 FAIL. 단 한두 줄로 default-deny egress에 인터넷 구멍이 뚫리고, C2 비콘·데이터 유출이 그 구멍으로 나간다. 넓게(`world`/`0.0.0.0/0`) 적으면 egress 통제가 사실상 무력화된다.</details>

## Step 3 — 구두 문답

1. <details><summary>"제로트러스트"가 이 정책에서 구체적으로 뭘 의미하나?</summary>위치(같은 네임스페이스/네트워크)로 신뢰하지 않음. 모든 ingress·egress가 default-deny이고, web→api→db라는 *명시적 최소권한 홉*만 연다. 털린 web 파드도 인터넷/메타데이터/apiserver/db에 직접 못 간다.</details>
2. <details><summary>egress 통제가 왜 ingress만큼 중요한가?</summary>ingress는 "침입"을, egress는 "침입 *후*"를 막는다. 침해된 web 파드가 실제로 하는 일 3가지가 전부 egress다 — (a) C2 콜백(공격자 서버로 비콘), (b) 데이터 유출(DB 덤프를 외부로), (c) 클라우드 크레덴셜 탈취(메타데이터 IP <code>169.254.169.254</code>에 SSRF로 IAM 토큰 요청). 채점기의 인터넷/메타데이터/apiserver **000** 3줄이 각각 (a)(c)와 lateral pivot을 막는 증거다. egress default-deny면 web를 털어도 공격자는 api:8080 외 어디로도 나가지 못해 *발판이 막다른 골목*이 된다. ingress만 잠근 클러스터는 안에서 밖으로 새는 걸 못 본다.</details>
3. <details><summary>L7(http rules)과 L3/L4(port)의 차이는? 왜 web→api만 L7인가?</summary>L3/L4는 "이 포트로 와도 되나", L7은 "이 메서드+경로로 와도 되나". web→api는 공개 진입점이라 경로 제한이 가치 큼(auditlogs 차단). api→db는 내부라 L3/L4로 충분.</details>
4. <details><summary>db에 egress 규칙을 안 준 이유는?</summary>DNS 베이스라인(모든 파드 대상)이 db도 egress 규칙 보유 상태로 만들어 → DNS 외 전부 차단. 가장 민감한 데이터 티어를 가장 잠근다. "규칙 없음"이 곧 "DNS만 허용"이 되는 Cilium 의미.</details>
5. <details><summary>이 네트워크 통제와 M2(신원)·Cedar(앱 인가)는 어떻게 겹치나?</summary>한 요청이 admission(신원)→netpol(L3/L7)→Cedar(per-request) 순서로 *모두* 통과해야 데이터에 닿는다. 같은 L7 허용 경로라도 principal이 다르면 Cedar가 다르게 판정(alice 200 vs bob 403). 다층 방어.</details>
6. <details><summary>apiserver egress(<code>10.96.0.1:443</code>) 차단이 왜 별도로 중요한가?</summary>침해된 파드가 apiserver에 닿으면, 마운트된 ServiceAccount 토큰으로 RBAC가 허용하는 만큼 클러스터를 조작할 수 있다(secret 읽기·파드 생성으로 권한 상승). egress default-deny가 apiserver(<code>10.96.0.1</code>=default kubernetes Service IP)로 가는 길을 끊어 이 pivot을 차단한다. 보강: probe 파드가 <code>automountServiceAccountToken: false</code>인 것도 같은 맥락 — 토큰을 아예 안 주는 것과 토큰이 있어도 길을 막는 것, 두 겹.</details>
7. <details><summary>fromEntities: ["cluster"] 의 blast-radius 문제는? 더 타이트하게 하려면?</summary>canonical 주석이 솔직히 밝히듯 <code>cluster</code>는 *모든* 인클러스터 endpoint·host·remote-node를 신뢰한다 — "ingress 컨트롤러만"보다 훨씬 넓다. 즉 클러스터 안 *아무* 파드나 web:8080에 닿을 수 있어, 다른 네임스페이스가 털리면 web가 그 발판이 된다. 더 타이트한 답은 ingress 컨트롤러의 레이블로 <code>fromEndpoints</code>를 좁히는 것. 데모 단순성 때문에 넓게 뒀고 *그 사실을 문서화*한 게 핵심 — 숨긴 과허용이 진짜 위험이다.</details>
8. <details><summary>"web가 와도 경로가 틀리면 403, db로 직접 가면 000"의 메커니즘 차이는?</summary>web→db는 L3/L4에서 막힌다: db ingress 허용 목록에 api만 있어(allow-api-to-db) web identity 패킷이 eBPF 데이터플레인에서 <b>DROP</b> → TCP 핸드셰이크도 안 됨 → curl 타임아웃 → HTTP 코드 없음 <b>000</b>. web→/auditlogs는 L3/L4는 통과(web 맞고 8080 맞음)하지만 Envoy L7 프록시가 path 정규식 매칭 실패로 <b>403</b> 응답을 *만들어* 돌려준다. 000=연결이 안 섬, 403=연결은 섰고 HTTP 레벨에서 거부. 디버깅 때 이 구분이 어느 계층이 막았는지를 알려준다.</details>

## 현실 연결 — 메타데이터 egress 차단이 막는 것

채점기의 "egress web->메타데이터(차단) **000**" 한 줄이 막는 공격은 추상적이지 않다. 2019 Capital One
사고는 SSRF로 인스턴스 메타데이터 endpoint(`169.254.169.254`)에 도달해 IAM 역할 크레덴셜을 빼내고,
그 권한으로 S3 ~1억 건을 유출한 사건이다. 패턴은 그대로 클러스터에 옮겨온다 — web 파드의 SSRF →
메타데이터 IP → 노드/파드의 클라우드 크레덴셜. egress default-deny가 그 *한 홉*을 끊는다. (메타데이터
서비스 자체 보강은 IMDSv2 같은 hop-limit·토큰 방식이지만, 그건 네트워크가 아니라 메타데이터 서버
쪽 통제다. 이 랩은 *네트워크 계층*에서 같은 결과를 만든다.) 클라우드에서 흔한 잘못은 egress 정책에
넓은 CIDR(`0.0.0.0/0`)을 열면서 link-local(`169.254.0.0/16`)만 따로 deny하는 것 — Step 2의 5번이
보여주듯 넓게 열고 좁게 막는 순서가 거꾸로다. default-deny 후 명시 허용이 맞다.

## 막지 못하는 것 (정직한 범위)

- **api→db의 *내용*은 안 본다.** api→db는 L3/L4만 — db 8080으로 가는 트래픽의 SQL/페이로드는 검사하지
  않는다. 침해된 api가 db 프로토콜로 무엇을 보내든 네트워크 정책은 통과시킨다. 그 계층 방어는 Cedar(인가)
  + M4 런타임 몫이다.
- **DNS 이름은 와일드카드로 열려 있다.** DNS 베이스라인은 `matchPattern: "*"` — 즉 어떤 도메인이든 *해석*은
  된다(해석된 IP로 *연결*은 egress L3가 막지만). DNS 터널링/exfil over DNS를 막으려면 `matchPattern`을
  필요한 도메인으로 좁혀야 한다. 이 랩은 단순성을 위해 넓게 뒀다.
- **identity 위조는 별도 통제 가정.** 정책은 파드 레이블=Cilium identity를 신뢰한다. 임의 파드가 `app: web`
  레이블을 달면 web 권한을 얻는다 — 그래서 *레이블을 못 붙이게* 하는 admission(M2)이 짝으로 필요하다.
  네트워크 정책 단독으로는 정체성 위조를 막지 못한다.

## Go deeper (1차 소스)

- [Cilium — Network Policy / L7 HTTP rules](https://docs.cilium.io/en/stable/security/policy/) — `endpointSelector`가 방향별 default-deny를 만드는 의미, L7 Envoy 프록시 동작.
- [Cilium — Identity-Relevant Labels & Security Identities](https://docs.cilium.io/en/stable/internals/security-identities/) — 레이블→숫자 identity, IP 비의존 판정.
- [NIST SP 800-207 — Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final) — per-session 최소권한, "위치≠신뢰" 원리.
- [Hubble — observing drops/flows](https://docs.cilium.io/en/stable/observability/hubble/) — `hubble observe --verdict DROPPED`로 L3/L7 판정을 identity와 함께 본다(docs/03 참고).

## 졸업 기준

- [ ] `grade.sh` **7/7 PASS**
- [ ] Step 2의 깨질 케이스 사전 예측 + Cilium의 "정책이 고르면 그 방향 default-deny" 의미 이해
- [ ] L7과 L3/L4를 언제 쓰는지, egress 통제의 공격 시나리오를 설명할 수 있다
- [ ] 구두 문답 8개 답안 없이
- [ ] `k8s/netpol.yaml`과 비교

다음: **M4 — Tetragon 런타임** (같은 세션에서).
