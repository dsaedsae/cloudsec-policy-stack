# verify-kyverno.ps1 — OPT-IN proof that the Kyverno SA-use ClusterPolicy enforces the
# gate CLUSTER-WIDE in a SECOND namespace (not shop). Twin of verify-kyverno.sh.
# Self-contained (own namespace + deployer Role/Group), so a DENY is the Kyverno gate
# (asserted by message), not an RBAC 403. Does NOT touch the always-on verify.ps1 suite.
$ErrorActionPreference = "Continue"
$ctx = "kind-cloudsec"
$ns = "kyv-demo"
$curl = "curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69"
$fail = 0

$ready = kubectl --context $ctx get clusterpolicy sa-use -o "jsonpath={.status.conditions[?(@.type=='Ready')].status}" 2>$null
if ($ready -ne "True") {
    Write-Host "SKIP: Kyverno ClusterPolicy sa-use not Ready (run scripts\enable-kyverno.ps1 first)"
    exit 0
}

# Setup namespace + a deployer Role/Group that may create workloads but is not authorized for SA-use.
kubectl --context $ctx create namespace $ns --dry-run=client -o yaml | kubectl --context $ctx apply -f - | Out-Null
@"
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { name: kyv-deployer, namespace: $ns }
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["create"]
  - apiGroups: ["batch"]
    resources: ["cronjobs"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { name: kyv-deployer, namespace: $ns }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: kyv-deployer }
subjects:
  - { kind: Group, name: "kyv:deployers", apiGroup: rbac.authorization.k8s.io }
"@ | kubectl --context $ctx apply -f - | Out-Null

function Workload($sa) {
@"
apiVersion: apps/v1
kind: Deployment
metadata: { name: sa-use-xns, namespace: $ns }
spec:
  replicas: 1
  selector: { matchLabels: { app: probe } }
  template:
    metadata: { labels: { app: probe } }
    spec:
      serviceAccountName: $sa
      containers:
        - name: c
          image: $curl
          command: ["sleep", "1"]
"@
}

try {
    Write-Host "== Kyverno cluster-wide SA-use (namespace: $ns, not shop) =="

    $denyOut = Workload "api-sa" | kubectl --context $ctx --as=system:serviceaccount:$ns`:ci --as-group=kyv:deployers create --dry-run=server -f - 2>&1 | Out-String
    if ($denyOut -match "SA-use gate|sa-use|authorized operator") {
        Write-Host "  deployer runs api-sa in $ns -> Kyverno DENY            expect DENY  got DENY  PASS"
    } else { Write-Host "  deployer runs api-sa in $ns (Kyverno SA-use)          expect DENY  got ?     FAIL"; $fail = 1 }

    Workload "default" | kubectl --context $ctx --as=system:serviceaccount:$ns`:ci --as-group=kyv:deployers create --dry-run=server -f - *> $null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  deployer runs non-tier SA in $ns -> ADMIT             expect ADMIT got ADMIT PASS"
    } else { Write-Host "  deployer runs non-tier SA in $ns                      expect ADMIT got DENY  FAIL"; $fail = 1 }

    Workload "api-sa" | kubectl --context $ctx create --dry-run=server -f - *> $null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  authorized operator runs api-sa in $ns -> ADMIT      expect ADMIT got ADMIT PASS"
    } else { Write-Host "  authorized operator runs api-sa in $ns                expect ADMIT got DENY  FAIL"; $fail = 1 }
} finally {
    kubectl --context $ctx delete namespace $ns --ignore-not-found *> $null
}

Write-Host "----------------------------------------------------------------"
if ($fail -eq 0) { Write-Host "Kyverno cluster-wide SA-use: ALL PASS (proven in $ns)" } else { Write-Host "Kyverno cluster-wide SA-use: FAILURES above" }
exit $fail
