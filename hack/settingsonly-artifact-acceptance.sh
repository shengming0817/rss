#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
image="${RSS_SETTINGSONLY_ACCEPTANCE_IMAGE:-rss-settingsonly:artifact-acceptance}"

: "${RSS_SETTINGSONLY_PRODUCTION_FIXTURE_DIR:?installed TLS production fixture directory is required}"
: "${RSS_SETTINGSONLY_PRODUCTION_PRIMARY_ADDR:?production Primary address is required}"
: "${RSS_SETTINGSONLY_PRODUCTION_ADMIN_ADDR:?production Admin address is required}"
: "${RSS_SETTINGSONLY_PRODUCTION_HEALTH_ADDR:?production Health address is required}"
: "${RSS_SETTINGSONLY_PRODUCTION_PUBLISH_TOKEN:?signed settings.config-publish token is required}"
: "${RSS_SETTINGSONLY_PRODUCTION_INVENTORY_TOKEN:?signed runtime:inventory:read token is required}"
: "${RSS_SETTINGSONLY_PRODUCTION_WRONG_PERMISSION_TOKEN:?signed wrong-permission token is required}"

test -f "$RSS_SETTINGSONLY_PRODUCTION_FIXTURE_DIR/settingsonly-binary.toml"
test -f "$RSS_SETTINGSONLY_PRODUCTION_FIXTURE_DIR/settingsonly-image.toml"
test -f "$RSS_SETTINGSONLY_PRODUCTION_FIXTURE_DIR/serving-secret-bundle"
test -f /var/run/rss/secrets/serving-secret-bundle

cd "$repo_root"
docker build --target settingsonly-runtime --tag "$image" .
RSS_SETTINGSONLY_ACCEPTANCE_IMAGE="$image" \
  ./hack/cargo.sh test -p settingsonly --test settingsonly_artifact_acceptance -- \
  --include-ignored --test-threads=1
