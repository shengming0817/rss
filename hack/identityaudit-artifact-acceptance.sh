#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
image="${RSS_IDENTITYAUDIT_ACCEPTANCE_IMAGE:-rss-identityaudit:artifact-acceptance}"

cd "$repo_root"
docker build --target identityaudit-runtime --tag "$image" .
RSS_IDENTITYAUDIT_ACCEPTANCE_IMAGE="$image" \
  ./hack/cargo.sh test -p identityaudit --test identityaudit_artifact_acceptance -- \
  --include-ignored --test-threads=1
