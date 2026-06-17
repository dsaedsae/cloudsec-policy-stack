# Lab 2 — 실제 클러스터에서 네트워크 + 앱 인가

> **직접 해보기 (재구현 트랙):** 네트워크 부분을 직접 재구성하라 → **[M3 · Cilium 네트워크](../labs/m3/README.md)** (7/7, 클러스터 필요). (이 페이지의 인가/신원 부분은 M0·M2와 짝.)

**목표:** 한 요청이 *같은 자산* 위에서 세 계층(Cilium L3 → L7 → Cedar)을 통과하는 걸 보고,
각 계층을 하나씩 망가뜨려 어떻게 반응하는지 확인한다.

**필요:** Docker, `kind`, `kubectl`, `helm`, `cilium`, `terraform`. ~20분.

## 띄우고 + 증명하기

```bash
bash scripts/up.sh        # terraform: kind+Cilium+Tetragon; api 빌드; 배포
bash scripts/verify.sh    # 아래 표를, 라이브로
```

기대 결과 (네트워크 + 인가 행):

```
  L1 web->db (no hop, L3 drop)              expect 000  got 000  PASS
  L2 web->api GET /auditlogs (L7 deny)      expect 403  got 403  PASS
  L3 alice GET own acct (Cedar allow)       expect 200  got 200  PASS
  L3 bob GET alice acct (Cedar deny)        expect 403  got 403  PASS
  ...
```

핵심 쌍: `alice`와 `bob`은 **같은** L7-허용 경로 `GET /accounts/acct-alice`를 친다.
Cilium은 둘 다 통과시키지만, **Cedar**는 alice(소유자)는 허용하고 bob은 거부한다.
같은 네트워크 경로, 다른 principal → 다른 결정. 이게 계층형 통제다 — 따로 노는 데모 3개가 아니다.

`GET /auditlogs/*`는 한 계층 앞에서 막힌다 — Cilium L7이 엣지에서(Envoy의 `Access denied` 본문)
앱에 닿기도 전에 떨군다.

## 왜 이렇게 설계했나 (`k8s/netpol.yaml`)

**신원 기반, IP 기반이 아님.** `fromEndpoints: { matchLabels: { app: web } }`는 IP/CIDR이 아니라
파드 라벨을 매칭한다. Cilium은 라벨에서 안정적인 *보안 신원*을 도출하므로, 파드가 죽고 새 IP로
재스케줄돼도 정책은 그대로 따라간다 — IP 기반 방화벽 규칙이라면 매번 깨질 자리다. 대가는 명확하다:
정책이 라벨을 신뢰하는 만큼만 강하다. *누가 `app: api` 라벨 파드를 만들 수 있나*가 곧 이 신원의
무결성이고, 그 의존성을 닫는 게 [Lab 4 — 신원](05-identity.md)이다.

**default-deny가 ingress와 egress *양쪽*.** `default-deny-ingress`(`endpointSelector: {}`,
`ingress: []`)는 네임스페이스 모든 파드의 인바운드를 0에서 시작시키고, 거기서 web→api→db 홉만
하나씩 연다. 덜 흔한 절반이 egress다: `allow-dns-egress`가 *모든* 파드를 selector로 잡아(그래서
나머지 egress는 자동 default-deny) DNS만 베이스라인으로 허용하고, 그 위에 `egress-web-to-api`·
`egress-api-to-db`가 각 티어의 *다음 홉 하나*만 연다. 이게 막는 현실적 공격은 인바운드가 아니라
**아웃바운드**다 — 털린 web 파드의 C2 비커닝, 데이터 유출(exfil), 클라우드 메타데이터 IP
(169.254.169.254)로의 크리덴셜 탈취, API 서버로의 측면 이동. egress를 안 잠그면 침해된 파드는
인터넷 어디로든 나갈 수 있다. db는 자기 egress 규칙이 아예 없어 DNS 외엔 아무 데도 못 나가는,
가장 잠긴 티어다.

**L3/L4 대 L7 — 어느 계층에서 떨구나.** `allow-api-to-db`는 L3/L4다(포트 8080 TCP, 그게 끝).
반면 `allow-web-to-api`는 `rules.http`로 L7까지 내려가 *메서드+경로*를 매칭한다 —
`GET /accounts/[^/]+$`와 `POST /accounts/[^/]+/transfer$`만 통과한다. `/auditlogs/*`는 진짜로
존재하는 앱 라우트지만 이 allowlist에 없어 **네트워크 엣지에서** 403으로 떨어진다(위 L2 행) —
패킷이 앱 프로세스에 닿기도, Cedar가 평가되기도 전이다. 이게 L3와 L7의 실질 차이다: L3는 "누가
누구와 말할 수 있나", L7은 "그 대화 안에서 *무슨 요청*까지 허용되나".

**네트워크 최소권한과 Cedar 앱 인가의 합성.** 두 계층은 *같은 자산 하나*에 서로 다른 질문을 건다.
L7은 경로 단위로 거친 빗질을 한다(`/accounts/*`는 열고 `/auditlogs/*`는 닫음) — principal을
모른다. Cedar는 그 통과한 요청 안에서 인스턴스·소유권·맥락을 본다(`cedar/policies.cedar`의
`when { resource.owner == principal }`, `context.amount <= principal.transferLimit`, 그리고
frozen 계좌엔 `forbid`가 `permit`을 무조건 덮음). 그래서 alice와 bob은 같은 L7-허용 경로를 쳐도
Cedar에서 갈린다(위 핵심 쌍). 한쪽만으론 안 된다: L7만 있으면 `/accounts/*`에 들어온 누구나 남의
계좌를 읽고, Cedar만 있으면 `/auditlogs`가 매번 앱까지 와 인증 코드가 단 한 줄도 안 틀리길
믿어야 한다. 두 계층을 한 자산에 겹치는 게 방어심층이다.

## 드롭 관찰하기 (Hubble)

```bash
cilium hubble port-forward &
hubble observe -n shop --verdict DROPPED        # L3/L7 드롭을 신원과 함께 관찰
```

## 망가뜨려 보기 (그리고 고치기)

**네트워크 L7:** `k8s/netpol.yaml`의 `allow-web-to-api`에 `GET /auditlogs/.*`를 허용하는 세 번째
rule을 추가하고 `kubectl apply -f k8s/netpol.yaml`. `/auditlogs` 프로브를 다시 돌리면 — 이제
**200**(L7 엣지가 더는 안 막는다). 되돌린다.

**앱 인가:** `cedar/policies.cedar`에서 `ViewAccount` permit의 `resource.owner == principal`
조건을 지운다. 이미지를 재빌드+재로드(`docker build -t cloudsec-api:local -f app/api/Dockerfile . && kind load docker-image cloudsec-api:local --name cloudsec && kubectl -n shop rollout restart deploy/api`).
이제 `bob`이 alice의 계좌를 읽으면 **200** — 소유권 검사를 없앤 것. 되돌리면 테스트가 다시 green.

다음: [Lab 3 — 런타임](04-runtime.md).  정리는 `bash scripts/down.sh`.
