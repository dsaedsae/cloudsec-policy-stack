# Layer 1 of the stack: provision the cluster + CNI as code (IaC).
# A local kind cluster with the default CNI disabled, then Cilium installed via
# Helm — so the entire substrate (incl. the network-security layer) is declarative
# and reproducible. No cloud cost.

resource "kind_cluster" "this" {
  name       = var.cluster_name
  node_image = var.node_image # k8s >= 1.30 so the VAP identity control installs (see variables.tf)
  # MUST be false: the CNI is disabled below, so nodes stay NotReady until Cilium is
  # installed by the helm_release in a later apply step. wait_for_ready=true would
  # block forever waiting for a readiness that only the not-yet-installed CNI provides.
  wait_for_ready = false

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
    # A second worker so api and db can be forced onto DIFFERENT nodes (podAntiAffinity
    # in k8s/app.yaml). Their traffic then crosses the wire and is WireGuard-encrypted —
    # turning the in-transit claim from "feature enabled" into a real cross-node proof.
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

  # Cilium + the in-cluster SPIRE pull several large images (cilium-envoy, hubble-relay/ui,
  # spire-server/agent). On a cold machine that can exceed Helm's 300s default, and a
  # *failed* release makes the provider destroy+recreate on the next apply — a timeout
  # loop that tears down a healthy CNI. 15 min absorbs the cold image-pull on slow disks.
  timeout = 900

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
  # toHTTP rules in the CiliumNetworkPolicy (k8s/netpol.yaml).
  set {
    name  = "l7Proxy"
    value = "true"
  }
  # Hubble: flow visibility, so policy drops/allows are observable with identity
  # labels (`hubble observe -n shop --verdict DROPPED`).
  set {
    name  = "hubble.enabled"
    value = "true"
  }
  set {
    name  = "hubble.relay.enabled"
    value = "true"
  }
  set {
    name  = "hubble.ui.enabled"
    value = "true"
  }

  # --- Identity (B7): cryptographic workload identity via mutual auth (SPIFFE) ---
  # The label<->SA admission policy only makes the *label* and the *ServiceAccount*
  # agree; it cannot stop a principal who can create a workload from choosing both
  # consistently (a self-consistent forged `api`). Mutual authentication issues each
  # workload a SPIFFE SVID from an in-cluster SPIRE and lets a policy edge REQUIRE it
  # (k8s/netpol-mutual.yaml), so a forged label is no longer sufficient — the peer
  # must also present a valid SVID. This is the actual closer for B7 (THREAT_MODEL.md).
  set {
    name  = "authentication.mutual.spire.enabled"
    value = "true"
  }
  set {
    name  = "authentication.mutual.spire.install.enabled"
    value = "true"
  }

  # --- Data-in-transit: transparent pod-to-pod encryption (WireGuard) ---
  # Defense in depth for data *protection*, not just access: even an on-path
  # attacker between nodes sees only ciphertext. Maps to PCI-DSS req 4 / GDPR
  # Art.32 "encryption of personal data in transit". Verified live with
  # `cilium encrypt status` (scripts/verify.*).
  set {
    name  = "encryption.enabled"
    value = "true"
  }
  set {
    name  = "encryption.type"
    value = "wireguard"
  }

  depends_on = [kind_cluster.this]
}
