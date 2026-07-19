variable "app_name" {
  description = "Kubernetes application name used for resource names and selectors."
  type        = string
  default     = "ms45-gui"
}

variable "namespace" {
  description = "Kubernetes namespace for the application."
  type        = string
  default     = "ms45"
}

variable "image" {
  description = "Container image for the browser-based MS45 GUI."
  type        = string
  default     = "ghcr.io/charlesderek/bmw-ms45-dme-unlock/ms45-gui:latest"
}

variable "replicas" {
  description = "Number of web GUI replicas."
  type        = number
  default     = 1

  validation {
    condition     = var.replicas > 0
    error_message = "replicas must be greater than zero."
  }
}

variable "container_port" {
  description = "Port exposed by the ms45-gui server container."
  type        = number
  default     = 4580
}

variable "service_port" {
  description = "ClusterIP service port."
  type        = number
  default     = 80
}

variable "kubernetes_host" {
  description = "Kubernetes API server URL. CI validation does not contact this endpoint."
  type        = string
  default     = "https://127.0.0.1:6443"
}
