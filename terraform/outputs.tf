output "cluster_name" {
  description = "kind cluster name (kubeconfig context: kind-<name>)"
  value       = kind_cluster.this.name
}

output "kubeconfig_path" {
  description = "Path kind wrote the kubeconfig to"
  value       = kind_cluster.this.kubeconfig_path
}
