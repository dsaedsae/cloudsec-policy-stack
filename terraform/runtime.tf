# Layer 4 (runtime): Tetragon — eBPF runtime security observability + enforcement.
# Installed via the same Helm path as Cilium, so the runtime pillar is also IaC.
# The TracingPolicy itself lives in k8s/tracingpolicy.yaml (applied by up.{sh,ps1}).
resource "helm_release" "tetragon" {
  name       = "tetragon"
  repository = "https://helm.cilium.io/"
  chart      = "tetragon"
  version    = "1.7.0"
  namespace  = "kube-system"

  # Cold image pull headroom (see the cilium release note); avoids a 300s-timeout
  # failed release that would force a destroy+recreate loop on the next apply.
  timeout = 600

  depends_on = [helm_release.cilium]
}
