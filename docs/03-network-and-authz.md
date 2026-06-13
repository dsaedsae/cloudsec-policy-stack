# Lab 2 — 실제 클러스터에서 네트워크 + 앱 인가

!!! tip "직접 해보기 (재구현 트랙)"
    네트워크 부분을 직접 재구성하라 → **[M3 · Cilium 네트워크](../labs/m3/README.md)** (7/7, 클러스터 필요).
    (이 페이지의 인가/신원 부분은 M0·M2와 짝.)

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
