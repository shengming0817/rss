#!/bin/sh
# shellcheck disable=SC2016 # Assertions intentionally match unexpanded shell source literals.
# Executable contract for the production-only 0060 capacity gate. Static anchors
# prevent carrier drift; command fakes exercise authorization timing without a
# live primary PostgreSQL host.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
gate="$root/docs/ops/0060-outbox-capacity-gate.sh"
readme="$root/adapters/postgres/migrations/README.md"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/rss-0060-capacity-selftest.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

fail() {
  echo "0060 capacity gate selftest: $1" >&2
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

# Credentials are selected through libpq's named service and 0600 passfile.
# No connection URI may be expanded into psql argv in the executable or examples.
require_literal "$gate" ': "${PGSERVICE:?set PGSERVICE to the DB-owner libpq service name}"'
require_literal "$gate" ': "${PGSERVICEFILE:?set PGSERVICEFILE to the DB-owner service file}"'
require_literal "$gate" ': "${PGPASSFILE:?set PGPASSFILE to the DB-owner password file}"'
require_literal "$gate" 'passfile_mode=$(file_mode "$PGPASSFILE")'
require_literal "$gate" 'psql -XAtq -v ON_ERROR_STOP=1 -c "$1"'
forbid_literal "$gate" 'DATABASE_URL'
forbid_literal "$readme" 'DB_OWNER_URL'

# A NULL time lag is unknown unless the standby is byte-exact and replied
# recently. The old unconditional NULL-to-zero downgrade must never return.
forbid_literal "$gate" "COALESCE(replay_lag, interval '0 seconds')"
require_literal "$gate" 'sample.byte_lag = 0'
require_literal "$gate" "sample.reply_time >= sample.checked_at - interval '60 seconds'"

# Archive proof is bound to the exact file returned by the switch. A global
# counter is observability only and cannot authorize the rollout.
require_literal "$gate" "pg_logical_emit_message(false, 'rss.0060-capacity-gate', 'archive-probe')"
require_literal "$gate" 'target_wal=$(pg "SELECT pg_walfile_name(pg_switch_wal())")'
require_literal "$gate" '"$archive_dir/$target_wal"'
require_literal "$gate" '"$remote_archive_probe" "$target_wal"'
forbid_literal "$gate" '[ "$last_archived_wal" = "$target_wal" ]'
require_literal "$gate" 'if archive_target_present; then'
forbid_literal "$gate" 'archived_after -gt archived_before'
forbid_literal "$gate" 'idle no-op'
wal_probe_line=$(grep -nF -- "pg_logical_emit_message(false, 'rss.0060-capacity-gate', 'archive-probe')" "$gate" | cut -d: -f1)
wal_target_line=$(grep -nF -- 'target_wal=$(pg "SELECT pg_walfile_name(pg_switch_wal())")' "$gate" | cut -d: -f1)
if [ "$wal_probe_line" -ge "$wal_target_line" ]; then
  fail "non-transactional WAL probe must run before pg_switch_wal target capture"
fi

# Busy-primary regression: the exact target object is already readable, while
# pg_stat_archiver.last_archived_wal has advanced to a later segment before the
# first poll. The stable object witness must authorize the rollout; the moving
# diagnostic field must not make success permanently unreachable.
mockbin="$tmp/bin"
pgdata="$tmp/pgdata"
archive="$tmp/archive"
service_file="$tmp/pg_service.conf"
pass_file="$tmp/pgpass"
target_wal=000000010000000000000001
next_wal=000000010000000000000002
mkdir -p "$mockbin" "$pgdata/pg_wal" "$archive"
printf '[rss-owner]\nhost=localhost\n' >"$service_file"
printf 'localhost:5432:rss:owner:secret\n' >"$pass_file"
chmod 600 "$pass_file"
: >"$archive/$target_wal"

cat >"$mockbin/psql" <<'EOF'
#!/bin/sh
for sql do :; done
case "$sql" in
  *"pg_total_relation_size"*) printf '1024\n' ;;
  *"SHOW data_directory"*) printf '%s\n' "$RSS_TEST_PGDATA" ;;
  *"SHOW archive_mode"*) printf 'on\n' ;;
  *"SELECT count(*) FROM pg_stat_replication"*) printf '0\n' ;;
  *"WITH sample_clock AS MATERIALIZED"*) printf '0\n' ;;
  *"pg_logical_emit_message"*) printf '0/1\n' ;;
  *"pg_walfile_name(pg_switch_wal())"*) printf '%s\n' "$RSS_TEST_TARGET_WAL" ;;
  *"SELECT failed_count ||"*) printf '0|1700000000\n' ;;
  *"SELECT COALESCE(last_archived_wal"*)
    printf '%s|%s|%s\n' \
      "$RSS_TEST_NEXT_WAL" "$RSS_TEST_FAILED_AFTER" "$RSS_TEST_STATS_RESET_AFTER"
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
  failed_after=$1
  stats_reset_after=$2
  PATH="$mockbin:$PATH" \
  RSS_TEST_PGDATA="$pgdata" \
  RSS_TEST_TARGET_WAL="$target_wal" \
  RSS_TEST_NEXT_WAL="$next_wal" \
  RSS_TEST_FAILED_AFTER="$failed_after" \
  RSS_TEST_STATS_RESET_AFTER="$stats_reset_after" \
  PGSERVICE=rss-owner \
  PGSERVICEFILE="$service_file" \
  PGPASSFILE="$pass_file" \
  EXPECTED_REPLICAS=0 \
  WAL_ARCHIVE_DIR="$archive" \
  "$gate"
}

if ! busy_output=$(run_gate 0 1700000000 2>&1); then
  printf '%s\n' "$busy_output" >&2
  fail "exact archived target must pass after last_archived_wal advances"
fi
printf '%s\n' "$busy_output" | grep -Fq \
  "archive_switch_ok target_wal=$target_wal last_archived_wal=$next_wal" \
  || fail "busy-primary proof did not report target and diagnostic WAL"

rm "$archive/$target_wal"
if missing_output=$(run_gate 0 1700000000 2>&1); then
  fail "advanced last_archived_wal must not authorize a missing target object"
fi
printf '%s\n' "$missing_output" | grep -Fq "exact WAL segment $target_wal was not visible" \
  || fail "missing target object did not fail closed"
: >"$archive/$target_wal"

if failed_output=$(run_gate 1 1700000000 2>&1); then
  fail "archive failure count change must reject an exact target object"
fi
printf '%s\n' "$failed_output" | grep -Fq 'pg_stat_archiver failed_count changed: 0 -> 1' \
  || fail "failed_count change did not fail closed"

if reset_output=$(run_gate 0 1700000001 2>&1); then
  fail "archive statistics reset must reject an exact target object"
fi
printf '%s\n' "$reset_output" | grep -Fq 'pg_stat_archiver statistics reset' \
  || fail "statistics reset did not fail closed"

# The executable gate owns its inputs; the migration ledger remains a thin link.
require_literal "$gate" 'REMOTE_ARCHIVE_PROBE'
require_literal "$readme" 'docs/ops/0060-outbox-capacity-gate.sh'
forbid_literal "$readme" '| data + `pg_wal` + local archive/spool 共盘 | 57 GiB |'
forbid_literal "$readme" 'REMOTE_ARCHIVE_FREE_BYTES'
forbid_literal "$readme" 'MIGRATION_PID'
forbid_literal "$readme" 'pg_cancel_backend'
forbid_literal "$readme" '4m30s'

echo "0060 capacity gate selftest: PASS"
