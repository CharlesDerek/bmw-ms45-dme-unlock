#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if ! command -v tofu >/dev/null 2>&1; then
  echo "error: tofu is required. Install OpenTofu or run this check in GitHub Actions." >&2
  exit 127
fi

while IFS= read -r -d '' module; do
  echo "Validating OpenTofu module: ${module#$repo_root/}"
  (
    cd "$module"
    tofu fmt -check -recursive
    tofu init -backend=false
    tofu validate
  )
done < <(find "$repo_root/infra" -type f -name '*.tf' -printf '%h\0' | sort -zu)
