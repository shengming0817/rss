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
  'cargo-deny@0.19.9,cargo-audit@0.22.2,cargo-dylint@6.0.1,dylint-link@6.0.1,cargo-public-api@0.52.0,cargo-semver-checks@0.49.0,sccache@0.15.0,promtool@3.5.3' \
  "$ADAPTER" specs --lane check --backend all
expect_output 'preflight owns only the compiler cache tool' \
  'sccache@0.15.0' \
  "$ADAPTER" specs --lane preflight --backend all
expect_output 'test-affected owns test and coverage tools' \
  'cargo-nextest@0.9.137,cargo-llvm-cov@0.8.7,sccache@0.15.0' \
  "$ADAPTER" specs --lane test-affected --backend all
expect_output 'integration-critical owns integration tools' \
  'cargo-nextest@0.9.137,sccache@0.15.0' \
  "$ADAPTER" specs --lane integration-critical --backend all
expect_output 'audit owns pinned prose and supply-chain tools' \
  'cargo-deny@0.19.9,cargo-audit@0.22.2,sccache@0.15.0,ripgrep@15.2.0' \
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

fixture=$(mktemp -d "${TMPDIR:-/tmp}/rss-tool-adapter-selftest.XXXXXX")
trap 'rm -rf "$fixture"' EXIT
fixture=$(CDPATH='' cd -- "$fixture" && pwd -P)
mkdir -p "$fixture/.install-action/bin" "$fixture/bin"
for spec in \
  '.install-action/bin/cargo-deny|cargo-deny 0.19.9' \
  '.install-action/bin/cargo-audit|cargo-audit 0.22.2' \
  '.install-action/bin/sccache|sccache 0.15.0'; do
  relative=${spec%%|*}
  version=${spec#*|}
  printf '#!/usr/bin/env bash\nprintf '\''%%s\\n'\'' '\''%s'\''\n' "$version" > "$fixture/$relative"
  chmod +x "$fixture/$relative"
done
printf '%s\n' \
  '#!/usr/bin/env bash' \
  ': > "$RSS_RG_PROBE_MARKER"' \
  "printf '%s\\n' 'ripgrep 15.2.0 (rev e89fff89ac)'" \
  "printf '%s\\n' '' 'features:+pcre2'" > "$fixture/bin/rg"
chmod +x "$fixture/bin/rg"
marker="$fixture/.rg-probed"
RSS_RG_PROBE_MARKER="$marker" "$ADAPTER" verify --mode fresh --lane audit --root "$fixture"
[ -f "$marker" ] || { printf 'not ok - fresh audit setup probes rg\n' >&2; exit 1; }
rm -f "$marker"
RSS_RG_PROBE_MARKER="$marker" "$ADAPTER" verify --mode cache --lane audit --root "$fixture"
[ -f "$marker" ] || { printf 'not ok - cached audit setup probes rg\n' >&2; exit 1; }
printf 'ok - fresh and cached audit setup probe pinned rg\n'
rm -f "$marker"
printf '\n' >> "$fixture/bin/rg"
expect_failure 'tampered cached rg fails closed' env RSS_RG_PROBE_MARKER="$marker" \
  "$ADAPTER" verify --mode cache --lane audit --root "$fixture"
[ ! -f "$marker" ] || { printf 'not ok - tampered cached rg executed before seal verification\n' >&2; exit 1; }
printf 'ok - tampered cached rg is rejected before execution\n'
