#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ADAPTER="$SCRIPT_DIR/ci-tool-adapters.sh"

expect_output() {
  label=$1
  expected=$2
  shift 2
  actual=$("$@")
  if [ "$actual" != "$expected" ]; then
    printf 'not ok - %s\n# expected: %s\n# actual: %s\n' "$label" "$expected" "$actual" >&2
    exit 1
  fi
  printf 'ok - %s\n' "$label"
}

expect_failure() {
  label=$1
  shift
  if "$@" >/dev/null 2>&1; then
    printf 'not ok - %s\n' "$label" >&2
    exit 1
  fi
  printf 'ok - %s\n' "$label"
}

expect_output 'check owns the fixed source and supply-chain tools' \
  'cargo-deny@0.19.9,cargo-audit@0.22.2,cargo-dylint@6.0.1,dylint-link@6.0.1,cargo-public-api@0.52.0,sccache@0.15.0,promtool@3.5.3' \
  "$ADAPTER" specs --lane check --backend all
expect_output 'test-affected owns test and coverage tools' \
  'cargo-nextest@0.9.137,cargo-llvm-cov@0.8.7,sccache@0.15.0' \
  "$ADAPTER" specs --lane test-affected --backend all
expect_output 'integration-critical owns integration tools' \
  'cargo-nextest@0.9.137,sccache@0.15.0' \
  "$ADAPTER" specs --lane integration-critical --backend all
expect_output 'audit owns only scheduled supply-chain tools' \
  'cargo-deny@0.19.9,cargo-audit@0.22.2,sccache@0.15.0' \
  "$ADAPTER" specs --lane audit --backend all
expect_output 'promtool remains digest-pinned and isolated to check' \
  'promtool@3.5.3' \
  "$ADAPTER" specs --lane check --backend docker
expect_output 'sccache identity is derived from the catalog' \
  'sccache|0.15.0|install-action|.install-action/bin/sccache|sccache' \
  "$ADAPTER" sccache-spec

for removed in ci-meta ci-core-prerequisites ci-core-tests ci-security ci-coverage ci-local-only integration; do
  expect_failure "removed lane $removed fails closed" "$ADAPTER" specs --lane "$removed" --backend all
done
expect_failure 'unknown backend fails closed' "$ADAPTER" specs --lane check --backend unknown
expect_failure 'relative sccache candidate fails closed' "$ADAPTER" verify-sccache --candidate relative/sccache
