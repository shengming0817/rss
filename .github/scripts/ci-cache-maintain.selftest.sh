#!/usr/bin/env bash
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
MAINTAIN="$SCRIPT_DIR/ci-cache-maintain.sh"
TMP_BASE=${TMPDIR:-/tmp}
TMP_ROOT=$(mktemp -d "${TMP_BASE%/}/ci-cache-maintain-selftest.XXXXXX")
FAILURES=0
trap 'rm -rf "$TMP_ROOT"' EXIT HUP INT TERM
TMP_ROOT=$(CDPATH='' cd -- "$TMP_ROOT" && pwd -P)
mkdir -p "$TMP_ROOT/work space" "$TMP_ROOT/runner temp" "$TMP_ROOT/outside"

pass() { printf 'ok - %s\n' "$1"; }
fail() { printf 'not ok - %s\n' "$1" >&2; FAILURES=$((FAILURES + 1)); }
expect_success() {
  name=$1; shift
  if "$@" >"$TMP_ROOT/stdout" 2>"$TMP_ROOT/stderr"; then pass "$name"; else fail "$name"; fi
}
expect_failure() {
  name=$1; shift
  if "$@" >"$TMP_ROOT/stdout" 2>"$TMP_ROOT/stderr"; then fail "$name"; else pass "$name"; fi
}

WORKSPACE="$TMP_ROOT/work space"
RUNNER_TEMP="$TMP_ROOT/runner temp"
TOOL_ROOT="$WORKSPACE/.cache/ci-tools/ci-meta"
FALLBACK_TARGET="$RUNNER_TEMP/rss-tool-build-target"
mkdir -p "$WORKSPACE/cache-data"
printf data >"$WORKSPACE/cache-data/item"

expect_success 'measure reports an integer byte count' "$MAINTAIN" measure --path "$WORKSPACE/cache-data"
case "$(cat "$TMP_ROOT/stdout")" in ''|*[!0-9]*) fail 'measure stdout is only an integer' ;; *) pass 'measure stdout is only an integer' ;; esac
expect_success 'missing cache root measures zero' "$MAINTAIN" measure --path "$WORKSPACE/missing"
if [ "$(cat "$TMP_ROOT/stdout")" = 0 ]; then pass 'missing cache root is zero'; else fail 'missing cache root is zero'; fi
ln -s "$WORKSPACE/cache-data" "$WORKSPACE/cache-link"
expect_failure 'measure rejects a symlink root' "$MAINTAIN" measure --path "$WORKSPACE/cache-link"

expect_success 'prepare roots creates isolated tool and fallback roots' "$MAINTAIN" prepare-roots --workspace "$WORKSPACE" --tool-root "$TOOL_ROOT" --runner-temp "$RUNNER_TEMP" --fallback-target "$FALLBACK_TARGET"
if [ -d "$TOOL_ROOT" ] && [ -d "$FALLBACK_TARGET" ]; then pass 'prepared roots exist'; else fail 'prepared roots exist'; fi
expect_failure 'tool root must stay below workspace' "$MAINTAIN" prepare-roots --workspace "$WORKSPACE" --tool-root "$TMP_ROOT/outside/tools" --runner-temp "$RUNNER_TEMP" --fallback-target "$FALLBACK_TARGET"
expect_failure 'fallback target must stay below runner temp' "$MAINTAIN" prepare-roots --workspace "$WORKSPACE" --tool-root "$TOOL_ROOT" --runner-temp "$RUNNER_TEMP" --fallback-target "$WORKSPACE/fallback"
expect_failure 'removed tree identity command is rejected' "$MAINTAIN" tree-identity --workspace "$WORKSPACE"
expect_failure 'removed target cleanup command is rejected' "$MAINTAIN" cleanup --workspace "$WORKSPACE" --target "$WORKSPACE/.cache/cargo-target"

if [ "$FAILURES" -ne 0 ]; then
  printf '%s cache maintenance selftest(s) failed\n' "$FAILURES" >&2
  exit 1
fi
printf 'all ci cache maintenance selftests passed\n'
