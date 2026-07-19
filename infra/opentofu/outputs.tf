output "namespace" {
  description = "Namespace that contains the MS45 GUI resources."
  value       = kubernetes_namespace_v1.this.metadata[0].name
}

output "service_name" {
  description = "ClusterIP service name for the MS45 GUI."
  value       = kubernetes_service_v1.web.metadata[0].name
}
