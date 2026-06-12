# Lab 5 — Data protection: the three states of data

**Goal:** B1–B7 govern *who may reach or do what*. They say nothing about the data
**itself**. A complete posture also protects data in its three states — **in
transit**, **at rest**, and **in use** — because access control fails open the
moment someone reads a backup, sniffs the wire, or over-logs a card number. This is
the GDPR Art.32 / PCI-DSS / ISMS-P "protect the data" half of the story.

**Needs:** the cluster from [Lab 2](03-network-and-authz.md).

> **Honest scope first.** There is no real datastore here — the `db` tier is an
> nginx placeholder and the PDP's entities are static fixtures. So this lab
> demonstrates the **controls** mapped to each data state, not a production data
> lifecycle. In-transit is verified live; at-rest is a runnable script; in-use is a
> design property of the PDP. Nothing here is claimed to protect data it doesn't have.

## In transit — WireGuard transparent encryption (cross-node, verified live)

Cilium is installed with `encryption.enabled=true, encryption.type=wireguard`
(`terraform/main.tf`), so **node-to-node** pod traffic is WireGuard-encrypted —
an on-path attacker *between nodes* sees ciphertext, not `X-User` headers or
account data.

The cluster runs **two workers**, and `k8s/app.yaml` pins `db` OFF `api`'s node
(`podAntiAffinity`), so the `api→db` hop **crosses the wire** and is therefore
WireGuard-encrypted. The `verify` check asserts both halves — WireGuard active AND
`api`/`db` on different nodes — so it proves *this app hop is encrypted on the wire*,
not merely that the feature is on.

The always-on `verify` row proves it by node-placement + `encrypt status` (follows from
Cilium's documented behavior: all cross-node pod traffic is encrypted):

```bash
kubectl -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg encrypt status
# Encryption: Wireguard
# Encrypted endpoints / keys in use: ...
```

**Packet-captured proof (opt-in evidence — `scripts/capture-wg.sh`).** For the stronger
claim, a `tcpdump` capture on the db node's host netns (`docker exec`, avoiding the
PSA-restricted privileged-pod trap) shows, during real api→db traffic: **40 WireGuard
packets (UDP/51871)** between the two nodes (ciphertext present) and **0 plaintext bytes**
(no `X-User`/`HTTP/1` on `tcp/8080` over `eth0`) in the same window — i.e. the app hop is
on the wire *only* as ciphertext. This upgrades ET2 from CONFIGURED to **VERIFIED** in the
coverage analysis. It is gated (kind nodes lack `tcpdump`; install needs node internet) and
SKIPs honestly when unavailable, so it is evidence — not one of the always-on 21 checks.

```bash
bash scripts/capture-wg.sh      # -> docs/assets/evidence/wg-capture-summary.txt
```

> **Honest caveat:** this proves packets are on the WireGuard tunnel and plaintext is absent
> on the wire — *not* WireGuard's cipher strength, and *not* that same-node hops are encrypted
> (they are not — only cross-node).

`scripts/verify.sh` asserts the always-on row; `capture-wg.sh` is the captured-evidence
upgrade. Maps to **PCI-DSS req 4 / GDPR Art.32** "encryption of personal data in transit."

## At rest — Secret encryption in etcd (runnable proof)

By default a Kubernetes Secret is only **base64** in etcd — read the datastore, a
disk image, or a backup, and you read every secret in plaintext. Prove the default
gap, then close it:

```bash
# Before: a Secret's value is plainly readable in etcd
kubectl -n default create secret generic demo --from-literal=card=4111111111111111
docker exec cloudsec-control-plane sh -c \
  "ETCDCTL_API=3 etcdctl --cacert /etc/kubernetes/pki/etcd/ca.crt \
   --cert /etc/kubernetes/pki/etcd/server.crt --key /etc/kubernetes/pki/etcd/server.key \
   get /registry/secrets/default/demo | strings" | grep 4111   # the card number is right there

# Enable AES-CBC encryption-at-rest and re-prove:
pwsh scripts/enable-secrets-encryption.ps1   # or: bash scripts/enable-secrets-encryption.sh
```

The script generates a fresh 32-byte AES key (never committed — `terraform/.enc/`
is gitignored), pushes a `EncryptionConfiguration` (`k8s/encryption-config.yaml`)
and the apiserver flag into the control-plane node via `docker cp` (no host mounts,
so it is OS-independent), backs up the apiserver manifest first (reversible), and
then **proves** the result by reading raw etcd:

```
== etcd raw bytes for secret/atrest-proof ==
k8s:enc:aescbc:v1:key1: <ciphertext>     # no plaintext card number anywhere
PASS: Secret is AES-CBC encrypted at rest in etcd.
```

Maps to **GDPR Art.32 / PCI-DSS req 3 / ISMS-P 2.7** "encryption of stored data."

## In use — data minimization by design

Protecting data *while processing it* is mostly about not exposing it in the first
place. The Cedar PDP (`app/api/main.py`) already practices this:

- **Principal is charset-validated** before it ever touches Cedar — a crafted
  `X-User` cannot inject into the entity UID or the logs (log-injection guard).
- **No sensitive payload is logged.** The PDP returns decisions, not balances; it
  never prints the `X-User` value or account contents to stdout.
- **Fail-closed evaluation** — any Cedar error denies, so a malformed request can't
  coax the service into returning data it shouldn't.

In a real system this is where you'd add field-level encryption, tokenization of
PANs, and a retention/erasure policy (right-to-be-forgotten). Those are noted as
out of scope here precisely because there is no real data to apply them to.

## The picture

```
data in transit  ── WireGuard (Cilium)        ── verified live  ── PCI req4 / GDPR Art.32
data at rest      ── EncryptionConfiguration   ── runnable proof ── PCI req3 / GDPR Art.32 / ISMS-P 2.7
data in use       ── PDP minimization + fail-closed ── design     ── least data exposed
```

---

That rounds the stack from **access control** (who may act) to **data protection**
(the data itself is guarded even when access control is bypassed). Back to the
[learning path](README.md).
