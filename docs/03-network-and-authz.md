# Lab 2 — Network + app authz on a real cluster

!!! tip "직접 해보기 (재구현 트랙)"
    네트워크 부분을 직접 재구성하라 → **[M3 · Cilium 네트워크](../labs/m3/README.md)** (7/7, 클러스터 필요).
    (이 페이지의 인가/신원 부분은 M0·M2와 짝.)

**Goal:** see one request pass through three layers (Cilium L3 → L7 → Cedar) on
the same asset, then break each layer and watch it react.

**Needs:** Docker, `kind`, `kubectl`, `helm`, `cilium`, `terraform`. ~20 min.

## Bring it up + prove it

```bash
bash scripts/up.sh        # terraform: kind+Cilium+Tetragon; build api; deploy
bash scripts/verify.sh    # the table below, live
```

Expected (network + authz rows):

```
  L1 web->db (no hop, L3 drop)              expect 000  got 000  PASS
  L2 web->api GET /auditlogs (L7 deny)      expect 403  got 403  PASS
  L3 alice GET own acct (Cedar allow)       expect 200  got 200  PASS
  L3 bob GET alice acct (Cedar deny)        expect 403  got 403  PASS
  ...
```

The key pair: `alice` and `bob` hit the **same** L7-allowed route
`GET /accounts/acct-alice`. Cilium lets both through; **Cedar** allows alice
(owner) and denies bob. Same network path, different principal → different
decision. That's layered control, not three separate demos.

`GET /auditlogs/*` is blocked one layer earlier — Cilium L7 drops it at the edge
(body `Access denied` from Envoy) before it ever reaches the app.

## See the drops (Hubble)

```bash
cilium hubble port-forward &
hubble observe -n shop --verdict DROPPED        # watch L3/L7 drops with identities
```

## Break it (then fix it)

**Network L7:** in `k8s/netpol.yaml`, add a third rule to `allow-web-to-api`
permitting `GET /auditlogs/.*`, then `kubectl apply -f k8s/netpol.yaml`. Re-run
the `/auditlogs` probe — now **200** (the L7 edge no longer blocks it). Revert.

**App authz:** in `cedar/policies.cedar`, change the `ViewAccount` permit to drop
the `resource.owner == principal` condition. Rebuild + reload the image
(`docker build -t cloudsec-api:local -f app/api/Dockerfile . && kind load
docker-image cloudsec-api:local --name cloudsec && kubectl -n shop rollout
restart deploy/api`). Now `bob` reading alice's account returns **200** — you
removed the ownership check. Revert and the test goes green again.

Next: [Lab 3 — runtime](04-runtime.md).  Tear down with `bash scripts/down.sh`.
