#!/usr/bin/env bash
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
RESULT="$SCRIPT_DIR/ci-cache-result.sh"
FAILURES=0

pass() { printf 'ok - %s\n' "$1"; }
fail() { printf 'not ok - %s\n' "$1" >&2; FAILURES=$((FAILURES + 1)); }
expect_result() {
  name=$1 expected=$2 outcome=$3 hit=$4 matched=$5
  if actual=$("$RESULT" classify --outcome "$outcome" --primary primary-key --hit "$hit" --matched "$matched" 2>/dev/null) && [ "$actual" = "$expected" ]; then
    pass "$name"
  else
    fail "$name"
  fi
}
expect_failure() {
  name=$1; shift
  if "$@" >/dev/null 2>&1; then fail "$name"; else pass "$name"; fi
}

expect_result 'successful true exact hit classifies exact' exact success true primary-key
expect_result 'successful false matched hit classifies prefix' prefix success false prefix-key
expect_result 'successful empty outputs classify miss' miss success '' ''
expect_result 'failed restore classifies unknown' unknown failure '' ''
expect_result 'cancelled restore classifies unknown' unknown cancelled '' ''
expect_result 'skipped restore classifies unknown' unknown skipped '' ''
expect_result 'failed restore ignores forged hit outputs' unknown failure true primary-key
expect_failure 'true with a different matched key fails closed' "$RESULT" classify --outcome success --primary primary-key --hit true --matched other-key
expect_failure 'false with the primary key fails closed' "$RESULT" classify --outcome success --primary primary-key --hit false --matched primary-key
expect_failure 'removed aggregate command is rejected' "$RESULT" aggregate --first-hit true --first-matched download-key --second-hit true --second-matched target-key
expect_failure 'true without matched key fails closed' "$RESULT" classify --outcome success --primary primary-key --hit true --matched ''
expect_failure 'false without matched key fails closed' "$RESULT" classify --outcome success --primary primary-key --hit false --matched ''
expect_failure 'empty hit with matched key fails closed' "$RESULT" classify --outcome success --primary primary-key --hit '' --matched prefix-key
expect_failure 'invalid hit token fails closed' "$RESULT" classify --outcome success --primary primary-key --hit yes --matched primary-key
expect_failure 'invalid outcome fails closed' "$RESULT" classify --outcome unknown --primary primary-key --hit '' --matched ''
expect_failure 'missing outcome fails closed' "$RESULT" classify --primary primary-key --hit '' --matched ''
expect_failure 'missing primary fails closed' "$RESULT" classify --outcome success --hit '' --matched ''
expect_failure 'missing arguments fail closed' "$RESULT" classify --outcome success --primary primary-key --hit true

if [ "$FAILURES" -ne 0 ]; then
  printf '%s cache result selftest(s) failed\n' "$FAILURES" >&2
  exit 1
fi
printf 'all ci cache result selftests passed\n'
