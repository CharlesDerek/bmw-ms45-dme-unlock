# OpenTofu Kubernetes Module

This module describes a minimal Kubernetes deployment for the local browser-based `ms45-gui` server. It is intentionally small so CI can run `tofu fmt`, `tofu init -backend=false`, and `tofu validate` without requiring a live Kubernetes cluster.

```bash
cd infra/opentofu
tofu init -backend=false
tofu fmt -check -recursive
tofu validate
```

Applying this module requires a real Kubernetes provider configuration and a container image that runs:

```bash
ms45-gui server --host 0.0.0.0 --port 4580
```
