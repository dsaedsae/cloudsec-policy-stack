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
