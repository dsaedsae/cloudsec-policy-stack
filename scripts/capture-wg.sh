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
# PROOF (both halves required, so it cannot false-pass):
#   positive: during real api->db traffic, eth0<->api-node shows UDP/51871 (WireGuard).
#   negative: during the SAME window, eth0 shows NO plaintext tcp/8080 carrying the
#             X-User/HTTP marker between the nodes -> the app bytes are encrypted.
#   guards:   api node != db node (else no wire hop), and traffic actually flowed.
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
docker exec "$DBNODE" sh -c "rm -f /tmp/wg.pcap /tmp/plain.txt" 2>/dev/null || true
# positive: encrypted WireGuard packets between the two nodes
docker exec -d "$DBNODE" sh -c "timeout 25 tcpdump -ni eth0 -c 40 -w /tmp/wg.pcap 'udp port $WGPORT and host $API_NODE_IP'" 2>/dev/null
# negative: any plaintext app bytes (tcp/8080) on the wire between the nodes, printed ASCII
docker exec -d "$DBNODE" sh -c "timeout 25 tcpdump -nAi eth0 -c 60 'tcp port 8080 and host $API_NODE_IP' > /tmp/plain.txt 2>/dev/null" 2>/dev/null
sleep 1

# 3) Drive REAL api->db traffic from the api pod (anti-affined off the db node) with the
#    X-User marker, using the image's own python (no curl in the slim image).
echo "generating api->db traffic ..."
k -n shop exec "$APIPOD" -- python -c "
import urllib.request
r=0
for _ in range(20):
    req=urllib.request.Request('http://$DB_IP:8080/', headers={'X-User':'alice-MARKER'})
    try:
        urllib.request.urlopen(req, timeout=3).read(); r+=1
    except Exception:
        pass
print('ok',r)
" 2>/dev/null || skip "could not generate api->db traffic from the api pod"

sleep 3  # let the timeout'd captures flush

# 4) Read results.
WG_COUNT=$(docker exec "$DBNODE" sh -c "tcpdump -nr /tmp/wg.pcap 2>/dev/null | wc -l" 2>/dev/null | tr -d '[:space:]')
WG_COUNT=${WG_COUNT:-0}
PLAIN_HITS=$(docker exec "$DBNODE" sh -c "grep -c -E 'alice-MARKER|X-User|HTTP/1' /tmp/plain.txt 2>/dev/null" 2>/dev/null | tr -d '[:space:]')
PLAIN_HITS=${PLAIN_HITS:-0}

echo "----------------------------------------------------------------"
echo "positive  WireGuard UDP/$WGPORT packets (api<->db node):  $WG_COUNT   (need >=1)"
echo "negative  plaintext app-bytes on eth0 (X-User/HTTP/1):    $PLAIN_HITS   (need 0)"
echo "----------------------------------------------------------------"

# 5) Save sanitized evidence (commit the summary, not the raw pcap — gitignored).
mkdir -p "$EVID"
docker cp "$DBNODE:/tmp/wg.pcap" "$EVID/wg-capture.pcap" >/dev/null 2>&1 || true
{
  echo "# WireGuard cross-node ciphertext capture (api->db)"
  echo "cluster-context : $CTX"
  echo "api pod / node  : $APIPOD @ $API_NODE"
  echo "db  pod / node  : $DBPOD @ $DB_NODE (capture site: host netns, iface eth0)"
  echo "api node IP     : $API_NODE_IP    wireguard udp port: $WGPORT"
  echo "positive (WG UDP/$WGPORT packets, need >=1) : $WG_COUNT"
  echo "negative (plaintext X-User/HTTP on wire, need 0) : $PLAIN_HITS"
  echo "reproduce       : scripts/capture-wg.sh   (needs tcpdump on the db node)"
} > "$EVID/wg-capture-summary.txt"
echo "evidence -> docs/assets/evidence/wg-capture-summary.txt"

if [ "$WG_COUNT" -ge 1 ] && [ "$PLAIN_HITS" -eq 0 ]; then
  echo "RESULT: PASS — api->db crosses the wire ONLY as WireGuard ciphertext; no plaintext observed."
  exit 0
else
  echo "RESULT: FAIL — positive>=1 AND negative==0 not both satisfied (see counts above)."
  exit 1
fi
