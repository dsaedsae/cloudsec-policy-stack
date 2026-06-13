# Lab 3 — Runtime detection + prevention (Tetragon / eBPF)

!!! tip "직접 해보기 (재구현 트랙)"
    TracingPolicy를 직접 작성하라 → **[M4 · Tetragon 런타임](../labs/m4/README.md)** (선택적 kill, 클러스터 필요).

**Goal:** the layers so far act *before/at* the request. This one watches the
workload *after* it's compromised — the gap network policy and authz can't cover.

**Needs:** the cluster from [Lab 2](03-network-and-authz.md) (Tetragon installed by `up.sh`).

## Prevention: a shell in the db pod is killed in-kernel

```bash
DBPOD=$(kubectl -n shop get pod -l tier=data -o jsonpath='{.items[0].metadata.name}')
kubectl -n shop exec "$DBPOD" -- sh -c "echo pwned"
```

Expected:

```
command terminated with exit code 137      # 137 = SIGKILL, by Tetragon
```

But a **non-shell** exec still works (the policy is precise, the pod stays healthy):

```bash
kubectl -n shop exec "$DBPOD" -- id        # uid=101(nginx) ...  — runs fine
```

The rule lives in `k8s/tracingpolicy.yaml`: a `TracingPolicy` that `Sigkill`s an
`execve` of a shell (`/sh`, `/bash`, `/dash`, `/ash`, `/busybox`) in any
`tier: data` pod. A database container never legitimately spawns a shell, so an
attempt is treated as intrusion.

## Detection: every process exec is observed

```bash
# trigger something, then read Tetragon's event stream:
kubectl -n shop exec "$DBPOD" -- id 2>/dev/null || true
kubectl -n kube-system logs ds/tetragon -c export-stdout --tail=200 | grep process_exec
```

You'll see the `binary`, `arguments`, `pod`, and process ancestry for each exec —
the forensic trail of what ran where.

## Make it yours

Add `"/python"` (or `/nc`, `/curl`) to the `values:` list in
`k8s/tracingpolicy.yaml`, `kubectl apply` it, and try to exec that binary in the
db pod — it's now killed too. You just wrote a runtime-security rule.

---

That's the full stack: **provision (Terraform) → network L3/L7 + egress (Cilium)
→ app authz (Cedar) → runtime (Tetragon)**, each enforced and verified. Back to
the [learning path](README.md).
