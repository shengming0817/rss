#!/bin/sh
# Production preflight for migration 0060. Run on the primary PostgreSQL host
# with a DB-owner connection; it is intentionally fail-closed.
set -eu

: "${PGSERVICE:?set PGSERVICE to the DB-owner libpq service name}"
: "${PGSERVICEFILE:?set PGSERVICEFILE to the DB-owner service file}"
: "${PGPASSFILE:?set PGPASSFILE to the DB-owner password file}"
: "${EXPECTED_REPLICAS:?set EXPECTED_REPLICAS to the inventory count, including 0}"

case "$EXPECTED_REPLICAS" in
  ''|*[!0-9]*) echo "EXPECTED_REPLICAS must be a non-negative integer" >&2; exit 2 ;;
esac

GIB=1073741824
TABLE_LIMIT=$((10 * GIB))
DATA_BUDGET=$((12 * GIB))
WAL_BUDGET=$((20 * GIB))
ARCHIVE_BUDGET=$((20 * GIB))
RESERVE=$((5 * GIB))
REPLICA_LAG_LIMIT=$((256 * 1024 * 1024))

file_mode() {
  if mode=$(stat -c '%a' "$1" 2>/dev/null); then
    printf '%s\n' "$mode"
  elif mode=$(stat -f '%Lp' "$1" 2>/dev/null); then
    printf '%s\n' "$mode"
  else
    echo "cannot read file mode: $1" >&2
    return 1
  fi
}

if [ ! -f "$PGSERVICEFILE" ] || [ ! -r "$PGSERVICEFILE" ]; then
  echo "PGSERVICEFILE must be a readable regular file" >&2
  exit 2
fi
if grep -Eiq '^[[:space:]]*password[[:space:]]*=' "$PGSERVICEFILE"; then
  echo "PGSERVICEFILE must not contain password entries; use PGPASSFILE" >&2
  exit 2
fi
if [ ! -f "$PGPASSFILE" ] || [ ! -r "$PGPASSFILE" ]; then
  echo "PGPASSFILE must be a readable regular file" >&2
  exit 2
fi
passfile_mode=$(file_mode "$PGPASSFILE")
if [ "$passfile_mode" != 600 ]; then
  echo "PGPASSFILE mode must be 0600, got $passfile_mode" >&2
  exit 2
fi

pg() {
  # libpq reads PGSERVICE/PGSERVICEFILE/PGPASSFILE from the environment. Only
  # fixed flags and SQL enter argv; the owner credential never does.
  psql -XAtq -v ON_ERROR_STOP=1 -c "$1"
}

device_for() {
  df -Pk "$1" | awk 'NR == 2 { print $1 }'
}

free_bytes() {
  df -Pk "$1" | awk 'NR == 2 { printf "%.0f\n", $4 * 1024 }'
}

require_free() {
  path=$1
  required=$2
  label=$3
  available=$(free_bytes "$path")
  if [ "$available" -lt "$required" ]; then
    echo "$label free bytes $available is below required $required" >&2
    exit 1
  fi
  echo "$label free_bytes=$available required_bytes=$required"
}

table_bytes=$(pg "SELECT pg_total_relation_size('outbox'::regclass)")
if [ "$table_bytes" -gt "$TABLE_LIMIT" ]; then
  echo "outbox bytes $table_bytes exceeds the 10 GiB rollout limit $TABLE_LIMIT" >&2
  exit 1
fi
echo "outbox_bytes=$table_bytes limit_bytes=$TABLE_LIMIT"

pgdata=$(pg "SHOW data_directory")
if [ ! -d "$pgdata" ] || [ ! -e "$pgdata/pg_wal" ]; then
  echo "data_directory/pg_wal is not locally visible; run this gate on the primary DB host" >&2
  exit 1
fi
wal_dir=$(readlink -f "$pgdata/pg_wal")
data_device=$(device_for "$pgdata")
wal_device=$(device_for "$wal_dir")

archive_mode=$(pg "SHOW archive_mode")
case "$archive_mode" in
  on|always) ;;
  *) echo "archive_mode=$archive_mode; production 0060 rollout requires WAL archive" >&2; exit 1 ;;
esac

# A local archive/spool path is measured and probed directly. Remote object
# storage needs both provider-derived available quota and an executable probe;
# the probe receives the exact WAL file name as its sole argument and returns
# success only after the object is readable from the archive destination.
archive_dir=${WAL_ARCHIVE_DIR:-}
remote_archive_free=${REMOTE_ARCHIVE_FREE_BYTES:-}
remote_archive_probe=${REMOTE_ARCHIVE_PROBE:-}
if [ -n "$archive_dir" ]; then
  if [ -n "$remote_archive_free" ] || [ -n "$remote_archive_probe" ]; then
    echo "choose either WAL_ARCHIVE_DIR or the remote archive settings, not both" >&2
    exit 2
  fi
  if [ ! -d "$archive_dir" ]; then
    echo "WAL_ARCHIVE_DIR does not exist: $archive_dir" >&2
    exit 1
  fi
  archive_device=$(device_for "$archive_dir")
  if [ "$data_device" = "$wal_device" ] && [ "$wal_device" = "$archive_device" ]; then
    require_free "$pgdata" $((DATA_BUDGET + WAL_BUDGET + ARCHIVE_BUDGET + RESERVE)) "data+wal+archive"
  elif [ "$data_device" = "$wal_device" ]; then
    require_free "$pgdata" $((DATA_BUDGET + WAL_BUDGET + RESERVE)) "data+wal"
    require_free "$archive_dir" $((ARCHIVE_BUDGET + RESERVE)) "archive"
  elif [ "$data_device" = "$archive_device" ]; then
    require_free "$pgdata" $((DATA_BUDGET + ARCHIVE_BUDGET + RESERVE)) "data+archive"
    require_free "$wal_dir" $((WAL_BUDGET + RESERVE)) "wal"
  elif [ "$wal_device" = "$archive_device" ]; then
    require_free "$pgdata" $((DATA_BUDGET + RESERVE)) "data"
    require_free "$wal_dir" $((WAL_BUDGET + ARCHIVE_BUDGET + RESERVE)) "wal+archive"
  else
    require_free "$pgdata" $((DATA_BUDGET + RESERVE)) "data"
    require_free "$wal_dir" $((WAL_BUDGET + RESERVE)) "wal"
    require_free "$archive_dir" $((ARCHIVE_BUDGET + RESERVE)) "archive"
  fi
else
  case "$remote_archive_free" in
    ''|*[!0-9]*)
      echo "set WAL_ARCHIVE_DIR or provider-derived REMOTE_ARCHIVE_FREE_BYTES" >&2
      exit 2
      ;;
  esac
  case "$remote_archive_probe" in
    /*) ;;
    *) echo "REMOTE_ARCHIVE_PROBE must be an absolute executable path" >&2; exit 2 ;;
  esac
  if [ ! -x "$remote_archive_probe" ]; then
    echo "REMOTE_ARCHIVE_PROBE is not executable: $remote_archive_probe" >&2
    exit 2
  fi
  if [ "$remote_archive_free" -lt $((ARCHIVE_BUDGET + RESERVE)) ]; then
    echo "remote archive free bytes $remote_archive_free is below required $((ARCHIVE_BUDGET + RESERVE))" >&2
    exit 1
  fi
  if [ "$data_device" = "$wal_device" ]; then
    require_free "$pgdata" $((DATA_BUDGET + WAL_BUDGET + RESERVE)) "data+wal"
  else
    require_free "$pgdata" $((DATA_BUDGET + RESERVE)) "data"
    require_free "$wal_dir" $((WAL_BUDGET + RESERVE)) "wal"
  fi
  echo "remote_archive_free_bytes=$remote_archive_free required_bytes=$((ARCHIVE_BUDGET + RESERVE))"
fi

replica_count=$(pg "SELECT count(*) FROM pg_stat_replication")
if [ "$replica_count" -ne "$EXPECTED_REPLICAS" ]; then
  echo "replica count $replica_count differs from inventory $EXPECTED_REPLICAS" >&2
  exit 1
fi
healthy_replicas=$(pg "
  WITH sample_clock AS MATERIALIZED (
    SELECT pg_current_wal_lsn() AS current_lsn,
           clock_timestamp() AS checked_at
  ),
  sample AS MATERIALIZED (
    SELECT replication.state,
           pg_wal_lsn_diff(sample_clock.current_lsn, replication.replay_lsn) AS byte_lag,
           replication.replay_lag,
           replication.reply_time,
           sample_clock.checked_at
    FROM pg_stat_replication AS replication
    CROSS JOIN sample_clock
    WHERE replication.replay_lsn IS NOT NULL
  )
  SELECT count(*)
  FROM sample
  WHERE sample.state = 'streaming'
    AND sample.byte_lag BETWEEN 0 AND $REPLICA_LAG_LIMIT
    AND (
      (sample.replay_lag IS NOT NULL
       AND sample.replay_lag <= interval '60 seconds')
      OR
      (sample.replay_lag IS NULL
       AND sample.byte_lag = 0
       AND sample.reply_time IS NOT NULL
       AND sample.reply_time >= sample.checked_at - interval '60 seconds')
    )
")
if [ "$healthy_replicas" -ne "$EXPECTED_REPLICAS" ]; then
  echo "only $healthy_replicas/$EXPECTED_REPLICAS replicas meet streaming, byte/replay lag, and fresh-reply gates" >&2
  exit 1
fi
echo "replicas_healthy=$healthy_replicas expected=$EXPECTED_REPLICAS"

# Emit a fixed, non-sensitive, non-transactional WAL message before the switch.
# This prevents pg_switch_wal's idle branch from returning a segment boundary
# that pg_walfile_name could resolve to an already archived predecessor. The
# message creates no table/object and carries no tenant or event data.
pg "SELECT pg_logical_emit_message(false, 'rss.0060-capacity-gate', 'archive-probe')" >/dev/null

# Bind the proof to the exact file completed by the subsequent switch. Global
# archive counts never authorize the rollout because a backlog file could
# increment one.
target_wal=$(pg "SELECT pg_walfile_name(pg_switch_wal())")
if ! printf '%s\n' "$target_wal" | grep -Eq '^[0-9A-F]{24}$'; then
  echo "pg_switch_wal returned an invalid WAL file name" >&2
  exit 1
fi

archive_before=$(pg "
  SELECT failed_count || '|' || EXTRACT(EPOCH FROM stats_reset)::bigint
  FROM pg_stat_archiver
")
failed_before=${archive_before%%|*}
stats_reset_before=${archive_before#*|}

archive_target_present() {
  if [ -n "$archive_dir" ]; then
    [ -f "$archive_dir/$target_wal" ]
  else
    "$remote_archive_probe" "$target_wal" >/dev/null 2>&1
  fi
}

attempt=0
while [ "$attempt" -lt 60 ]; do
  archive_after=$(pg "
    SELECT COALESCE(last_archived_wal, '') || '|' || failed_count || '|'
           || EXTRACT(EPOCH FROM stats_reset)::bigint
    FROM pg_stat_archiver
  ")
  last_archived_wal=${archive_after%%|*}
  archive_after_rest=${archive_after#*|}
  failed_after=${archive_after_rest%%|*}
  stats_reset_after=${archive_after_rest#*|}
  if [ "$stats_reset_after" != "$stats_reset_before" ]; then
    echo "pg_stat_archiver statistics reset during the archive proof" >&2
    exit 1
  fi
  if [ "$failed_after" != "$failed_before" ]; then
    echo "pg_stat_archiver failed_count changed: $failed_before -> $failed_after" >&2
    exit 1
  fi
  # last_archived_wal is diagnostic only: on a busy primary it may already
  # name a later segment. The exact destination object is the stable witness.
  if archive_target_present; then
    echo "archive_switch_ok target_wal=$target_wal last_archived_wal=$last_archived_wal failed_count=$failed_after"
    echo "0060 capacity gate: PASS"
    exit 0
  fi
  attempt=$((attempt + 1))
  sleep 1
done

echo "exact WAL segment $target_wal was not visible in the archive destination within 60 seconds" >&2
exit 1
