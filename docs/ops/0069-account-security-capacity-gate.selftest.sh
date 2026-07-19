#!/bin/sh
# shellcheck disable=SC2016 # Assertions intentionally match unexpanded shell source literals.
# Executable red/green contract for the production-only 0069 capacity gate.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
gate="$root/docs/ops/0069-account-security-capacity-gate.sh"
readme="$root/adapters/postgres/migrations/README.md"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/rss-0069-capacity-selftest.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

fail() {
  echo "0069 account-security capacity gate selftest: $1" >&2
  exit 1
}

require_literal() {
  file=$1
  literal=$2
  grep -Fq -- "$literal" "$file" || fail "$file missing: $literal"
}

forbid_literal() {
  file=$1
  literal=$2
  if grep -Fq -- "$literal" "$file"; then
    fail "$file still contains forbidden text: $literal"
  fi
}

for literal in \
  ': "${PGSERVICE:?set PGSERVICE to the DB-owner libpq service name}"' \
  ': "${PGSERVICEFILE:?set PGSERVICEFILE to the DB-owner service file}"' \
  ': "${PGPASSFILE:?set PGPASSFILE to the DB-owner password file}"' \
  ': "${EXPECTED_REPLICAS:?set EXPECTED_REPLICAS to the inventory count, including 0}"' \
  ': "${MAINTENANCE_WINDOW_SECONDS:?set remaining maintenance-window seconds}"' \
  'SELECT count(*) FROM public.credentials' \
  "pg_total_relation_size('public.credentials'::regclass)" \
  'SELECT count(*) FROM pg_stat_replication' \
  'sample.byte_lag = 0' \
  "sample.reply_time >= sample.checked_at - interval '60 seconds'" \
  "pg_logical_emit_message(false, 'rss.0069-capacity-gate', 'archive-probe')" \
  'target_wal=$(pg "SELECT pg_walfile_name(pg_switch_wal())")' \
  'if archive_target_present; then'
do
  require_literal "$gate" "$literal"
done
forbid_literal "$gate" 'DATABASE_URL'
forbid_literal "$gate" "COALESCE(replay_lag, interval '0 seconds')"
require_literal "$readme" 'docs/ops/0069-account-security-capacity-gate.sh'

mockbin="$tmp/bin"
pgdata="$tmp/pgdata"
archive="$tmp/archive"
service_file="$tmp/pg_service.conf"
pass_file="$tmp/pgpass"
target_wal=000000010000000000000001
mkdir -p "$mockbin" "$pgdata/pg_wal" "$archive"
printf '[rss-owner]\nhost=localhost\n' >"$service_file"
printf 'localhost:5432:rss:owner:secret\n' >"$pass_file"
chmod 600 "$pass_file"
: >"$archive/$target_wal"

cat >"$mockbin/psql" <<'EOF'
#!/bin/sh
for sql do :; done
case "$sql" in
  *"SELECT count(*) FROM public.credentials"*) printf '%s\n' "$RSS_TEST_ROWS" ;;
  *"pg_total_relation_size"*) printf '%s\n' "$RSS_TEST_BYTES" ;;
  *"SHOW data_directory"*) printf '%s\n' "$RSS_TEST_PGDATA" ;;
  *"SHOW archive_mode"*) printf 'on\n' ;;
  *"SELECT count(*) FROM pg_stat_replication"*) printf '%s\n' "$RSS_TEST_REPLICAS" ;;
  *"WITH sample_clock AS MATERIALIZED"*) printf '%s\n' "$RSS_TEST_HEALTHY_REPLICAS" ;;
  *"pg_logical_emit_message"*) printf '0/1\n' ;;
  *"pg_walfile_name(pg_switch_wal())"*) printf '%s\n' "$RSS_TEST_TARGET_WAL" ;;
  *"SELECT failed_count ||"*) printf '0|1700000000\n' ;;
  *"SELECT COALESCE(last_archived_wal"*)
    printf '%s|%s|1700000000\n' "$RSS_TEST_TARGET_WAL" "$RSS_TEST_FAILED_AFTER"
    ;;
  *) printf 'unexpected psql query: %s\n' "$sql" >&2; exit 64 ;;
esac
EOF
cat >"$mockbin/df" <<'EOF'
#!/bin/sh
cat <<'OUT'
Filesystem 1024-blocks Used Available Capacity Mounted on
mockdev 100000000 1 99999999 1% /
OUT
EOF
cat >"$mockbin/readlink" <<'EOF'
#!/bin/sh
if [ "$1" = -f ] && [ "$#" -eq 2 ]; then
  printf '%s\n' "$2"
else
  exit 64
fi
EOF
cat >"$mockbin/sleep" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$mockbin/psql" "$mockbin/df" "$mockbin/readlink" "$mockbin/sleep"

run_gate() {
  window=$1
  rows=$2
  bytes=$3
  replicas=$4
  healthy=$5
  failed_after=$6
  PATH="$mockbin:$PATH" \
  RSS_TEST_PGDATA="$pgdata" \
  RSS_TEST_TARGET_WAL="$target_wal" \
  RSS_TEST_ROWS="$rows" \
  RSS_TEST_BYTES="$bytes" \
  RSS_TEST_REPLICAS="$replicas" \
  RSS_TEST_HEALTHY_REPLICAS="$healthy" \
  RSS_TEST_FAILED_AFTER="$failed_after" \
  PGSERVICE=rss-owner \
  PGSERVICEFILE="$service_file" \
  PGPASSFILE="$pass_file" \
  EXPECTED_REPLICAS=1 \
  MAINTENANCE_WINDOW_SECONDS="$window" \
  WAL_ARCHIVE_DIR="$archive" \
  "$gate"
}

if ! pass_output=$(run_gate 600 1000 1048576 1 1 0 2>&1); then
  printf '%s\n' "$pass_output" >&2
  fail "healthy capacity envelope must pass"
fi
printf '%s\n' "$pass_output" | grep -Fq '0069 account-security capacity gate: PASS' \
  || fail "PASS receipt is missing"

if window_output=$(run_gate 479 1000 1048576 1 1 0 2>&1); then
  fail "short maintenance window must fail closed"
fi
printf '%s\n' "$window_output" | grep -Fq 'maintenance window 479 seconds is below required 480' \
  || fail "short maintenance-window failure is not explicit"

if rows_output=$(run_gate 600 50000001 1048576 1 1 0 2>&1); then
  fail "credential row overflow must fail closed"
fi
printf '%s\n' "$rows_output" | grep -Fq 'credential rows 50000001 exceeds rollout limit' \
  || fail "credential row overflow is not explicit"

if bytes_output=$(run_gate 600 1000 10737418241 1 1 0 2>&1); then
  fail "credential byte overflow must fail closed"
fi
printf '%s\n' "$bytes_output" | grep -Fq 'credential bytes 10737418241 exceeds rollout limit' \
  || fail "credential byte overflow is not explicit"

if replica_output=$(run_gate 600 1000 1048576 0 0 0 2>&1); then
  fail "replica inventory mismatch must fail closed"
fi
printf '%s\n' "$replica_output" | grep -Fq 'replica count 0 differs from inventory 1' \
  || fail "replica inventory mismatch is not explicit"

if lag_output=$(run_gate 600 1000 1048576 1 0 0 2>&1); then
  fail "unhealthy replica must fail closed"
fi
printf '%s\n' "$lag_output" | grep -Fq 'only 0/1 replicas meet' \
  || fail "replica lag failure is not explicit"

if archive_output=$(run_gate 600 1000 1048576 1 1 1 2>&1); then
  fail "archive failure-count change must fail closed"
fi
printf '%s\n' "$archive_output" | grep -Fq 'pg_stat_archiver failed_count changed: 0 -> 1' \
  || fail "archive failure-count change is not explicit"

echo "0069 account-security capacity gate selftest: PASS"
