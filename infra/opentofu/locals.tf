locals {
  app_labels = {
    "app.kubernetes.io/name"      = var.app_name
    "app.kubernetes.io/component" = "web"
  }
}
