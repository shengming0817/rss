#!/usr/bin/env bash
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
RESULT="$SCRIPT_DIR/ci-cache-result.sh"
FAILURES=0

pass() { printf 'ok - %s\n' "$1"; }
fail() { printf 'not ok - %s\n' "$1" >&2; FAILURES=$((FAILURES + 1)); }
expect_result() {
  name=$1 expected=$2 hit=$3 matched=$4
  if actual=$("$RESULT" classify --hit "$hit" --matched "$matched" 2>/dev/null) && [ "$actual" = "$expected" ]; then
    pass "$name"
  else
    fail "$name"
  fi
}
expect_failure() {
  name=$1; shift
  if "$@" >/dev/null 2>&1; then fail "$name"; else pass "$name"; fi
}

expect_result 'true exact hit classifies exact' exact true primary-key
expect_result 'false matched hit classifies prefix' prefix false prefix-key
expect_result 'empty outputs classify miss' miss '' ''
expect_aggregate() {
  name=$1 expected=$2 first_hit=$3 first_matched=$4 second_hit=$5 second_matched=$6
  if actual=$("$RESULT" aggregate --first-hit "$first_hit" --first-matched "$first_matched" --second-hit "$second_hit" --second-matched "$second_matched" 2>/dev/null) && [ "$actual" = "$expected" ]; then
    pass "$name"
  else
    fail "$name"
  fi
}
expect_aggregate 'two exact caches aggregate exact' exact true download-key true target-key
expect_aggregate 'two misses aggregate miss' miss '' '' '' ''
expect_aggregate 'download-only hit conservatively aggregates miss' miss true download-key '' ''
expect_aggregate 'target-only hit conservatively aggregates miss' miss '' '' true target-key
expect_failure 'aggregate rejects inconsistent first cache' "$RESULT" aggregate --first-hit false --first-matched '' --second-hit true --second-matched target-key
expect_failure 'true without matched key fails closed' "$RESULT" classify --hit true --matched ''
expect_failure 'false without matched key fails closed' "$RESULT" classify --hit false --matched ''
expect_failure 'empty hit with matched key fails closed' "$RESULT" classify --hit '' --matched prefix-key
expect_failure 'invalid hit token fails closed' "$RESULT" classify --hit yes --matched primary-key
expect_failure 'missing arguments fail closed' "$RESULT" classify --hit true

if [ "$FAILURES" -ne 0 ]; then
  printf '%s cache result selftest(s) failed\n' "$FAILURES" >&2
  exit 1
fi
printf 'all ci cache result selftests passed\n'
