#!/usr/bin/env sh
set -eu

# Share build artifacts across linked worktrees. In a normal CI checkout,
# git-common-dir is the checkout's .git, so this resolves inside that checkout.
git_common_dir=$(/usr/bin/git rev-parse --path-format=absolute --git-common-dir)
repo_storage_dir=$(/usr/bin/dirname "$git_common_dir")

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_storage_dir/.cache/cargo-target}"

exec cargo "$@"
