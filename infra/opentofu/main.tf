terraform {
  required_version = ">= 1.6.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.30.0, < 3.0.0"
    }
  }
}

provider "kubernetes" {
  host     = var.kubernetes_host
  insecure = true
}

resource "kubernetes_namespace_v1" "this" {
  metadata {
    name = var.namespace

    labels = {
      "app.kubernetes.io/name"       = var.app_name
      "app.kubernetes.io/managed-by" = "opentofu"
    }
  }
}

resource "kubernetes_deployment_v1" "web" {
  metadata {
    name      = var.app_name
    namespace = kubernetes_namespace_v1.this.metadata[0].name

    labels = local.app_labels
  }

  spec {
    replicas = var.replicas

    selector {
      match_labels = local.app_labels
    }

    template {
      metadata {
        labels = local.app_labels
      }

      spec {
        container {
          name  = var.app_name
          image = var.image

          port {
            name           = "http"
            container_port = var.container_port
          }

          liveness_probe {
            http_get {
              path = "/"
              port = "http"
            }
          }

          readiness_probe {
            http_get {
              path = "/"
              port = "http"
            }
          }

          resources {
            requests = {
              cpu    = "50m"
              memory = "64Mi"
            }

            limits = {
              cpu    = "250m"
              memory = "256Mi"
            }
          }
        }
      }
    }
  }
}

resource "kubernetes_service_v1" "web" {
  metadata {
    name      = var.app_name
    namespace = kubernetes_namespace_v1.this.metadata[0].name

    labels = local.app_labels
  }

  spec {
    selector = local.app_labels
    type     = "ClusterIP"

    port {
      name        = "http"
      port        = var.service_port
      target_port = "http"
    }
  }
}
