#!/usr/bin/env bash
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
PARSER="$SCRIPT_DIR/ci-sccache-stats.sh"
TMP_BASE=${TMPDIR:-/tmp}
TMP_ROOT=$(mktemp -d "${TMP_BASE%/}/ci-sccache-stats-selftest.XXXXXX")
FAILURES=0

cleanup() { rm -rf "$TMP_ROOT"; }
trap cleanup EXIT HUP INT TERM
TMP_ROOT=$(CDPATH='' cd -- "$TMP_ROOT" && pwd -P)

pass() { printf 'ok - %s\n' "$1"; }
fail() { printf 'not ok - %s\n' "$1" >&2; FAILURES=$((FAILURES + 1)); }

expect_output() {
  name=$1 expected=$2
  shift 2
  if actual=$("$@" 2>"$TMP_ROOT/stderr") && [ "$actual" = "$expected" ]; then
    pass "$name"
  else
    sed 's/^/# /' "$TMP_ROOT/stderr" >&2 || true
    printf '# expected: %s\n# actual: %s\n' "$expected" "${actual:-}" >&2
    fail "$name"
  fi
}

expect_failure() {
  name=$1
  shift
  if "$@" >"$TMP_ROOT/stdout" 2>"$TMP_ROOT/stderr"; then fail "$name"; else pass "$name"; fi
}

printf '%s\n' '{"stats":{"compile_requests":9,"cache_hits":{"counts":{"Rust":4,"C/C++":0}},"cache_misses":{"counts":{"Rust":3}},"requests_not_cacheable":2,"cache_errors":{"counts":{"Rust":1}},"cache_timeouts":2,"cache_read_errors":3,"cache_write_errors":4}}' >"$TMP_ROOT/valid.json"
expect_output 'complete stats preserve every diagnostic counter' "9$(printf '\t')4$(printf '\t')3$(printf '\t')2$(printf '\t')1$(printf '\t')2$(printf '\t')3$(printf '\t')4" \
  "$PARSER" parse --input "$TMP_ROOT/valid.json"

printf '%s\n' '{"stats":{"compile_requests":0,"cache_hits":{"counts":{}},"cache_misses":{"counts":{}},"requests_not_cacheable":0,"cache_errors":{"counts":{}},"cache_timeouts":0,"cache_read_errors":0,"cache_write_errors":0}}' >"$TMP_ROOT/zero.json"
expect_output 'zero denominator remains a valid typed row' "0$(printf '\t')0$(printf '\t')0$(printf '\t')0$(printf '\t')0$(printf '\t')0$(printf '\t')0$(printf '\t')0" \
  "$PARSER" parse --input "$TMP_ROOT/zero.json"

printf '%s\n' '{"stats":{"compile_requests":12,"cache_hits":{"counts":{"Rust":3,"C/C++":2}},"cache_misses":{"counts":{"Rust":4,"C/C++":1}},"requests_not_cacheable":2,"cache_errors":{"counts":{"Rust":0,"C/C++":1}},"cache_timeouts":2,"cache_read_errors":3,"cache_write_errors":4}}' >"$TMP_ROOT/multiple.json"
expect_output 'multiple language backends are summed without aggregating error classes' "12$(printf '\t')5$(printf '\t')5$(printf '\t')2$(printf '\t')1$(printf '\t')2$(printf '\t')3$(printf '\t')4" \
  "$PARSER" parse --input "$TMP_ROOT/multiple.json"

printf '%s\n' '{"stats":{}}' >"$TMP_ROOT/missing-fields.json"
expect_failure 'object with missing fields fails closed' \
  "$PARSER" parse --input "$TMP_ROOT/missing-fields.json"

printf '%s\n' '{"stats":{"compile_requests":"9"}}' >"$TMP_ROOT/wrong-type.json"
expect_failure 'wrong counter type fails closed' "$PARSER" parse --input "$TMP_ROOT/wrong-type.json"

printf '%s\n' '{"stats":{"compile_requests":-1,"cache_hits":{"counts":{}},"cache_misses":{"counts":{}},"requests_not_cacheable":0,"cache_errors":{"counts":{}},"cache_timeouts":0,"cache_read_errors":0,"cache_write_errors":0}}' >"$TMP_ROOT/negative.json"
expect_failure 'negative counters fail closed' "$PARSER" parse --input "$TMP_ROOT/negative.json"
printf '%s\n' '{"stats":{"compile_requests":1.5,"cache_hits":{"counts":{}},"cache_misses":{"counts":{}},"requests_not_cacheable":0,"cache_errors":{"counts":{}},"cache_timeouts":0,"cache_read_errors":0,"cache_write_errors":0}}' >"$TMP_ROOT/fractional.json"
expect_failure 'fractional counters fail closed' "$PARSER" parse --input "$TMP_ROOT/fractional.json"
printf '%s\n' '{"stats":{"compile_requests":9007199254740992,"cache_hits":{"counts":{}},"cache_misses":{"counts":{}},"requests_not_cacheable":0,"cache_errors":{"counts":{}},"cache_timeouts":0,"cache_read_errors":0,"cache_write_errors":0}}' >"$TMP_ROOT/oversized.json"
expect_failure 'non JSON-safe counters fail closed' "$PARSER" parse --input "$TMP_ROOT/oversized.json"
printf '%s\n' '{"stats":{"compile_requests":1,"cache_hits":{"counts":[]},"cache_misses":{"counts":{}},"requests_not_cacheable":0,"cache_errors":{"counts":{}},"cache_timeouts":0,"cache_read_errors":0,"cache_write_errors":0}}' >"$TMP_ROOT/wrong-counts.json"
expect_failure 'non-object backend counts fail closed' "$PARSER" parse --input "$TMP_ROOT/wrong-counts.json"

printf '%s\n' '{broken' >"$TMP_ROOT/malformed.json"
expect_failure 'malformed JSON fails closed' "$PARSER" parse --input "$TMP_ROOT/malformed.json"

ln -s "$TMP_ROOT/valid.json" "$TMP_ROOT/stats-link.json"
expect_failure 'symlink input fails closed' "$PARSER" parse --input "$TMP_ROOT/stats-link.json"
expect_failure 'relative input is rejected' "$PARSER" parse --input relative.json
expect_failure 'unknown command is rejected' "$PARSER" unknown

if [ "$FAILURES" -ne 0 ]; then
  printf 'FAIL ci-sccache-stats selftest: %s failure(s)\n' "$FAILURES" >&2
  exit 1
fi
printf 'PASS ci-sccache-stats selftest\n'
