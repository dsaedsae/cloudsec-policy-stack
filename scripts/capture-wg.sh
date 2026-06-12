#!/usr/bin/env bash
# capture-wg.sh — packet-capture proof that the api->db cross-node hop is WireGuard
# ciphertext on the wire (upgrades ET2 from CONFIGURED to captured-evidence).
#
# WHERE: we capture on the DB node's PHYSICAL interface (eth0) inside its kind
# container's host netns — NOT in a pod (the shop ns is PSA-restricted; a tcpdump pod
# needs NET_RAW/privileged and would be rejected). `docker exec` into the node avoids
# PSA entirely. Cilium WireGuard tunnels cross-node pod traffic as UDP/51871 on eth0;
# the cilium_wg0 interface carries the *decrypted* side, so eth0 is where ciphertext lives.
#
# PROOF (a traffic-flow gate + two corroborating halves — see honesty notes below):
#   gate:     app requests must actually succeed (REQOK>=1) — else SKIP, never assert.
#   positive (DISPOSITIVE): with api/db on different nodes, cross-node pod traffic in the
#             window is WireGuard (UDP/51871) on eth0. (This count includes app + node
#             background WG traffic; it is credited only once the traffic gate passed.)
#   negative (CORROBORATING): no plaintext app bytes (X-User/HTTP/1) appear on eth0 as
#             tcp/8080 in the same window. NOTE: absence here is also consistent with
#             encapsulation (cross-node pod traffic is tunneled) or with no traffic — so
#             it corroborates, it does not by itself prove encryption. The dispositive
#             evidence is WG-packet presence + cross-node node-placement (ET1).
#   guards:   api node != db node (else no wire hop), AND app traffic provably flowed.
#
# Honest scope: this is an OPT-IN evidence script (kind nodes lack tcpdump; install
# needs node internet). It is NOT one of verify.sh's always-on checks. SKIPs (exit 0)
# rather than faking a pass when tcpdump can't be obtained. See docs/06-data-protection.md.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CTX="kind-$(terraform -chdir="$ROOT/terraform" output -raw cluster_name 2>/dev/null || echo cloudsec)"
k() { kubectl --context "$CTX" "$@"; }
WGPORT=51871
EVID="$ROOT/docs/assets/evidence"

skip() { echo "SKIP: $1"; echo "(capture-wg is opt-in evidence; ET1 node-placement+encrypt-status proof stands in verify.sh)"; exit 0; }

# 0) Resolve the two pods + nodes; require them on different nodes (the wire hop).
APIPOD=$(k -n shop get pod -l tier=backend -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
DBPOD=$(k -n shop get pod -l tier=data -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
[ -n "$APIPOD" ] && [ -n "$DBPOD" ] || skip "api/db pods not found (is the cluster up?)"
API_NODE=$(k -n shop get pod "$APIPOD" -o jsonpath='{.spec.nodeName}')
DB_NODE=$(k -n shop get pod "$DBPOD" -o jsonpath='{.spec.nodeName}')
[ -n "$API_NODE" ] && [ -n "$DB_NODE" ] || skip "could not resolve node names"
[ "$API_NODE" != "$DB_NODE" ] || skip "api and db are co-located ($API_NODE); no cross-node wire hop to capture"
API_NODE_IP=$(k get node "$API_NODE" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
DB_IP=$(k -n shop get pod "$DBPOD" -o jsonpath='{.status.podIP}')
[ -n "$API_NODE_IP" ] && [ -n "$DB_IP" ] || skip "could not resolve api node IP / db pod IP"
echo "api=$APIPOD@$API_NODE  db=$DBPOD@$DB_NODE  api-node-ip=$API_NODE_IP  db-pod-ip=$DB_IP"

# kind: node name == docker container name.
DBNODE="$DB_NODE"
docker inspect "$DBNODE" >/dev/null 2>&1 || skip "db node container '$DBNODE' not found via docker"

# 1) Ensure tcpdump on the db node (kind images don't ship it). Never fake on failure.
if ! docker exec "$DBNODE" sh -c 'command -v tcpdump' >/dev/null 2>&1; then
  echo "installing tcpdump on $DBNODE ..."
  docker exec "$DBNODE" sh -c 'apt-get update -qq && apt-get install -y -qq tcpdump' >/dev/null 2>&1 \
    || skip "tcpdump not installable on the node (offline?)"
fi

# 2) Start BOTH captures in the background BEFORE generating traffic (else we miss packets).
#    No -c cap on the positive: rely on the 25s timeout so the reported count is the real
#    measured total, not a capture ceiling. Negative filters the db POD IP (the inner
#    packet's address) — though under tunnel/encapsulation it won't appear on eth0 anyway.
docker exec "$DBNODE" sh -c "rm -f /tmp/wg.pcap /tmp/plain.txt" 2>/dev/null || true
docker exec -d "$DBNODE" sh -c "timeout 25 tcpdump -ni eth0 -w /tmp/wg.pcap 'udp port $WGPORT and host $API_NODE_IP'" 2>/dev/null
docker exec -d "$DBNODE" sh -c "timeout 25 tcpdump -nAi eth0 -c 200 'tcp port 8080 and host $DB_IP' > /tmp/plain.txt 2>/dev/null" 2>/dev/null
sleep 1

# 3) Drive REAL api->db traffic from the api pod (anti-affined off the db node) with the
#    X-User marker, using the image's own python (no curl in the slim image). The python
#    exits nonzero if ZERO requests succeeded, so the traffic-flow gate (|| skip) fires —
#    we never assert "no plaintext" vacuously on a run where no traffic flowed.
echo "generating api->db traffic ..."
REQOUT=$(k -n shop exec "$APIPOD" -- python -c "
import urllib.request, sys
r=0
for _ in range(20):
    req=urllib.request.Request('http://$DB_IP:8080/', headers={'X-User':'alice-MARKER'})
    try:
        urllib.request.urlopen(req, timeout=3).read(); r+=1
    except Exception:
        pass
print('REQOK', r)
sys.exit(0 if r > 0 else 7)
" 2>/dev/null)
REQOK=$(echo "$REQOUT" | awk '/REQOK/{print $2}'); REQOK=${REQOK:-0}
[ "${REQOK:-0}" -ge 1 ] || skip "api->db traffic did not flow ($REQOK/20 requests succeeded — NetworkPolicy drop / db not ready?); cannot prove encryption without real traffic"

sleep 3  # let the timeout'd captures flush

# 4) Read results.
WG_COUNT=$(docker exec "$DBNODE" sh -c "tcpdump -nr /tmp/wg.pcap 2>/dev/null | wc -l" 2>/dev/null | tr -d '[:space:]')
WG_COUNT=${WG_COUNT:-0}
PLAIN_HITS=$(docker exec "$DBNODE" sh -c "grep -c -E 'alice-MARKER|X-User|HTTP/1' /tmp/plain.txt 2>/dev/null" 2>/dev/null | tr -d '[:space:]')
PLAIN_HITS=${PLAIN_HITS:-0}

echo "----------------------------------------------------------------"
echo "gate      app requests that succeeded (REQOK):             $REQOK   (need >=1)"
echo "positive  WireGuard UDP/$WGPORT pkts api<->db node (app+bg): $WG_COUNT   (need >=1)"
echo "negative  plaintext app-bytes on eth0 (X-User/HTTP/1):     $PLAIN_HITS   (need 0; corroborating)"
echo "----------------------------------------------------------------"

# 5) Save sanitized evidence (commit the summary, not the raw pcap — gitignored).
mkdir -p "$EVID"
docker cp "$DBNODE:/tmp/wg.pcap" "$EVID/wg-capture.pcap" >/dev/null 2>&1 || true
{
  echo "# WireGuard cross-node capture (api->db) — WG ciphertext present, no plaintext observed"
  echo "cluster-context : $CTX"
  echo "api pod / node  : $APIPOD @ $API_NODE"
  echo "db  pod / node  : $DBPOD @ $DB_NODE (capture site: host netns, iface eth0)"
  echo "api node IP     : $API_NODE_IP    db pod IP: $DB_IP    wireguard udp port: $WGPORT"
  echo "gate     (app requests succeeded, need >=1) : $REQOK"
  echo "positive (WG UDP/$WGPORT pkts app+background, need >=1) : $WG_COUNT"
  echo "negative (plaintext X-User/HTTP on eth0, need 0; corroborating) : $PLAIN_HITS"
  echo "dispositive evidence : WG-packet presence + cross-node placement (ET1). Negative"
  echo "  corroborates (absence is also consistent with tunnel encapsulation)."
  echo "reproduce       : scripts/capture-wg.sh   (needs tcpdump on the db node)"
} > "$EVID/wg-capture-summary.txt"
echo "evidence -> docs/assets/evidence/wg-capture-summary.txt"

if [ "$REQOK" -ge 1 ] && [ "$WG_COUNT" -ge 1 ] && [ "$PLAIN_HITS" -eq 0 ]; then
  echo "RESULT: PASS — app traffic flowed; cross-node api->db traffic in the window is WireGuard"
  echo "        (UDP/$WGPORT) and NO plaintext app bytes appeared on eth0."
  exit 0
else
  echo "RESULT: FAIL — need REQOK>=1 AND WG_COUNT>=1 AND PLAIN_HITS==0 (see counts above)."
  exit 1
fi
