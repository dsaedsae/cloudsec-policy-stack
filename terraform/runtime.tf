# Layer 4 (runtime): Tetragon — eBPF runtime security observability + enforcement.
# Installed via the same Helm path as Cilium, so the runtime pillar is also IaC.
# The TracingPolicy itself lives in k8s/tracingpolicy.yaml (applied by up.{sh,ps1}).
resource "helm_release" "tetragon" {
  name       = "tetragon"
  repository = "https://helm.cilium.io/"
  chart      = "tetragon"
  version    = "1.7.0"
  namespace  = "kube-system"

  depends_on = [helm_release.cilium]
}
