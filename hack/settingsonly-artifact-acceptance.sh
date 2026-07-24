#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
image="${RSS_SETTINGSONLY_ACCEPTANCE_IMAGE:-rss-settingsonly:artifact-acceptance}"

unset RSS_SETTINGSONLY_PG_WRITER_PASSWORD
unset RSS_SETTINGSONLY_PG_READER_PASSWORD
unset RSS_SETTINGSONLY_PG_MIGRATOR_PASSWORD
unset RSS_SETTINGSONLY_VAULT_TOKEN

cd "$repo_root"
docker build --target settingsonly-runtime --tag "$image" .
RSS_SETTINGSONLY_ACCEPTANCE_IMAGE="$image" \
  ./hack/cargo.sh test -p settingsonly --test settingsonly_artifact_acceptance -- \
  --include-ignored --test-threads=1
