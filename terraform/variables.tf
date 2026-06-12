variable "cluster_name" {
  description = "kind cluster name"
  type        = string
  default     = "cloudsec"
}

variable "cilium_version" {
  description = "Cilium Helm chart version"
  type        = string
  default     = "1.16.5"
}

# Pin the Kubernetes version of the kind nodes. The identity layer's
# ValidatingAdmissionPolicy (k8s/admission-policy.yaml) uses
# admissionregistration.k8s.io/v1, which is GA only in Kubernetes >= 1.30
# (v1beta1 behind an off-by-default gate in 1.28-1.29). An unpinned/older node
# image would silently fail to install that policy and provide ZERO B7
# enforcement, so we pin a >= 1.30 image for reproducibility.
variable "node_image" {
  description = "kind node image (must be k8s >= 1.30 for the VAP identity control)"
  type        = string
  default     = "kindest/node:v1.34.0"
}
