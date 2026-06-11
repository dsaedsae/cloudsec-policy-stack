# Layer 1 of the stack: provision the cluster + CNI as code (IaC).
# A local kind cluster with the default CNI disabled, then Cilium installed via
# Helm — so the entire substrate (incl. the network-security layer) is declarative
# and reproducible. No cloud cost.

resource "kind_cluster" "this" {
  name           = var.cluster_name
  wait_for_ready = true

  kind_config {
    kind        = "Cluster"
    api_version = "kind.x-k8s.io/v1alpha4"

    # Cilium replaces the CNI, so turn kind's default (kindnet) off.
    networking {
      disable_default_cni = true
    }

    node {
      role = "control-plane"
    }
    node {
      role = "worker"
    }
  }
}

# The Helm provider talks to the cluster kind just created.
# NOTE: provider config references resource outputs that are unknown until the
# cluster exists. If a fresh `terraform apply` races, run once:
#   terraform apply -target=kind_cluster.this    # create the cluster first
#   terraform apply                              # then install Cilium
provider "helm" {
  kubernetes {
    host                   = kind_cluster.this.endpoint
    client_certificate     = kind_cluster.this.client_certificate
    client_key             = kind_cluster.this.client_key
    cluster_ca_certificate = kind_cluster.this.cluster_ca_certificate
  }
}

resource "helm_release" "cilium" {
  name       = "cilium"
  repository = "https://helm.cilium.io/"
  chart      = "cilium"
  version    = var.cilium_version
  namespace  = "kube-system"

  # kind-friendly defaults; Kubernetes-backed IPAM.
  set {
    name  = "ipam.mode"
    value = "kubernetes"
  }
  set {
    name  = "image.pullPolicy"
    value = "IfNotPresent"
  }
  # Enable L7 (HTTP) policy enforcement via the Envoy proxy — needed for the
  # toHTTP rules in the CiliumNetworkPolicy (k8s/netpol/).
  set {
    name  = "l7Proxy"
    value = "true"
  }

  depends_on = [kind_cluster.this]
}
