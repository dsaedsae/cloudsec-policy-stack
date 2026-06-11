# Learning path

A guided way to study this repo — each lab builds on the last and shows the
payoff *before* asking you to install more. Defensive/infra only.

| Lab | You'll learn | Needs | Time |
|-----|--------------|-------|------|
| [0 — Authorization as code](01-authz-no-cluster.md) | Cedar policies + how `forbid`/limits/roles work, unit-tested | Python only | 5 min |
| [1 — Shift-left scanning](02-scan.md) | checkov on IaC + K8s, and *honest* suppression triage | Python only | 5 min |
| [2 — Network + app authz](03-network-and-authz.md) | one request through Cilium L3 → L7 → Cedar; break each and watch it react | Docker+kind | 20 min |
| [3 — Runtime (eBPF)](04-runtime.md) | Tetragon detects + SIGKILLs a shell in a popped container | Docker+kind | 10 min |

## The idea in one picture

Four independent layers guard the **same** asset (the `api`). Each stops an
attack the others can't see:

```
attacker / bad request
   │  wrong pod identity ............ Cilium L3   → dropped (no route)
   │  disallowed HTTP path/method ... Cilium L7   → 403 (Envoy)
   │  not the owner / over limit .... Cedar (app) → 403 (PDP decision)
   │  tries to exfiltrate outbound .. Cilium egress → dropped
   ▼  pops the container, runs a shell  Tetragon   → SIGKILL (eBPF)
```

`scripts/verify.sh` proves all of it live (14/14). Start at **Lab 0** — it needs
nothing but Python and takes five minutes.
