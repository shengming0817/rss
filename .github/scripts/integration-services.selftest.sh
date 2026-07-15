#!/usr/bin/env bash
set -eu

# INVARIANT: CI-INTEGRATION-SERVICE-LIFECYCLE-01
# This executable specification intentionally uses an adversarial Docker facade:
# `ps` returns every live container, so cleanup is safe only when it both asks
# Docker for the exact labels and re-inspects every candidate before removal.

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
LIFECYCLE="$SCRIPT_DIR/integration-services.sh"
GOLDEN="$SCRIPT_DIR/testdata/integration-services-v1.golden.json"
TMP_BASE=${TMPDIR:-/tmp}
TMP_ROOT=$(mktemp -d "${TMP_BASE%/}/integration-services-selftest.XXXXXX")
FAILURES=0

cleanup_tmp() { rm -rf "$TMP_ROOT"; }
trap cleanup_tmp EXIT HUP INT TERM

pass() { printf 'ok - %s\n' "$1"; }
fail() { printf 'not ok - %s\n' "$1" >&2; FAILURES=$((FAILURES + 1)); }
expect_success() {
  name=$1
  shift
  if "$@" >"$TMP_ROOT/stdout" 2>"$TMP_ROOT/stderr"; then
    pass "$name"
  else
    sed 's/^/# /' "$TMP_ROOT/stderr" >&2 || true
    fail "$name"
  fi
}
expect_failure() {
  name=$1
  shift
  if "$@" >"$TMP_ROOT/stdout" 2>"$TMP_ROOT/stderr"; then fail "$name"; else pass "$name"; fi
}
assert_jq() {
  name=$1 file=$2 expression=$3
  if jq -e "$expression" "$file" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi
}
assert_absent() {
  name=$1 pattern=$2 file=$3
  if grep -F -- "$pattern" "$file" >/dev/null 2>&1; then fail "$name"; else pass "$name"; fi
}
assert_present() {
  name=$1 pattern=$2 file=$3
  if grep -F -- "$pattern" "$file" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi
}
directory_mode() {
  path=$1
  if gnu_mode=$(stat -c '%a' "$path" 2>/dev/null); then
    mode=$gnu_mode
  elif bsd_mode=$(stat -f '%Lp' "$path" 2>/dev/null); then
    mode=$bsd_mode
  else
    return 1
  fi
  case "$mode" in
    [0-7][0-7][0-7]) printf '%s\n' "$mode" ;;
    *) return 1 ;;
  esac
}
directory_is_private() {
  [ "$(directory_mode "$1")" = 700 ]
}

FAKE_BIN="$TMP_ROOT/fake-bin"
STATE="$TMP_ROOT/docker-state"
REMOVED="$TMP_ROOT/docker-removed"
TRACE="$TMP_ROOT/docker.trace"
mkdir -p "$FAKE_BIN"
: >"$REMOVED"
: >"$TRACE"

for command_name in awk bash cat chmod cp date dd df dirname du find grep gzip head jq mkdir mkfifo mktemp mv pwd rm sed sleep sort stat tar tr wc; do
  command_path=$(command -v "$command_name")
  ln -s "$command_path" "$FAKE_BIN/$command_name"
done

cat >"$FAKE_BIN/docker" <<'FAKE_DOCKER'
#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >>"$FAKE_DOCKER_TRACE"

is_removed() { grep -Fx -- "$1" "$FAKE_DOCKER_REMOVED" >/dev/null 2>&1; }
state_row() { awk -F '|' -v wanted="$1" '$1 == wanted { print; found=1; exit } END { if (!found) exit 1 }' "$FAKE_DOCKER_STATE"; }
field() { printf '%s\n' "$1" | awk -F '|' -v number="$2" '{ print $number }'; }
fail_if_requested() {
  operation=$1
  [ "${FAKE_DOCKER_FAIL_OPERATION:-}" = "$operation" ] || return 0
  case "${FAKE_DOCKER_FAIL_KIND:-}" in
    daemon-unreachable) message='Cannot connect to the Docker daemon' ;;
    permission-denied) message='permission denied while trying to connect' ;;
    not-found) message='No such container' ;;
    conflict) message='Conflict: removal of container is already in progress' ;;
    io) message='input/output error' ;;
    unknown) message='unclassified Docker failure' ;;
    *) message='unrecognized fake failure kind' ;;
  esac
  printf '%s: %s\n' "$message" 'SECRET_DOCKER_STDERR_CANARY' >&2
  exit 42
}
oversize_if_requested() {
  operation=$1
  [ "${FAKE_DOCKER_OVERSIZE_OPERATION:-}" = "$operation" ] || return 0
  dd if=/dev/zero bs=1048576 count=2 2>/dev/null
  printf 'control-producer-finished\n' >"$FAKE_DOCKER_CONTROL_PRODUCER_MARKER"
  exit 0
}

case "${1:-}" in
  ps)
    fail_if_requested ps
    oversize_if_requested ps
    if [ "${FAKE_DOCKER_BLOCK_OPERATION:-}" = ps ]; then sleep 30; fi
    # Deliberately ignore filters: the caller must re-inspect before rm.
    while IFS='|' read -r id _; do
      [ -n "$id" ] || continue
      is_removed "$id" || printf '%s\n' "$id"
    done <"$FAKE_DOCKER_STATE"
    ;;
  inspect)
    fail_if_requested inspect
    shift
    format=
    case "${1:-}" in --format|-f) format=$2; shift 2 ;; esac
    id=${1:-}
    if [ "${FAKE_DOCKER_BLOCK_OPERATION:-}" = inspect ]; then sleep 30; fi
    if [ "${FAKE_DOCKER_INVALID_INSPECT_ID:-}" = "$id" ]; then printf 'not-json\n'; exit 0; fi
    [ -n "$id" ] || exit 64
    is_removed "$id" && exit 1
    row=$(state_row "$id") || exit 1
    managed=$(field "$row" 2)
    scope=$(field "$row" 3)
    shard=$(field "$row" 4)
    partition=$(field "$row" 5)
    service=$(field "$row" 6)
    if [ -z "$format" ]; then
      jq -cn --arg id "$id" --arg managed "$managed" --arg scope "$scope" --arg shard "$shard" \
        --arg partition "$partition" --arg service "$service" \
        '[{Id:$id,Config:{Labels:{"io.rss.integration.managed":$managed,"io.rss.integration.scope":$scope,"io.rss.integration.shard":$shard,"io.rss.integration.partition":$partition,"io.rss.integration.service":$service}}}]'
    elif printf '%s' "$format" | grep -F 'json .Config.Labels' >/dev/null 2>&1; then
      jq -cn --arg managed "$managed" --arg scope "$scope" --arg shard "$shard" \
        --arg partition "$partition" --arg service "$service" \
        '{"io.rss.integration.managed":$managed,"io.rss.integration.scope":$scope,"io.rss.integration.shard":$shard,"io.rss.integration.partition":$partition,"io.rss.integration.service":$service}'
    else
      case "$format" in
        *io.rss.integration.managed*) printf '%s\n' "$managed" ;;
        *io.rss.integration.scope*) printf '%s\n' "$scope" ;;
        *io.rss.integration.shard*) printf '%s\n' "$shard" ;;
        *io.rss.integration.partition*) printf '%s\n' "$partition" ;;
        *io.rss.integration.service*) printf '%s\n' "$service" ;;
        *) exit 65 ;;
      esac
    fi
    ;;
  logs)
    id=${2:-}
    if [ "${FAKE_DOCKER_BLOCK_OPERATION:-}" = logs ]; then sleep 30; fi
    row=$(state_row "$id") || exit 1
    fail_if_requested logs
    [ "$(field "$row" 7)" = logfail ] && { printf 'sensitive docker failure detail\n' >&2; exit 24; }
    if [ "$(field "$row" 7)" = oversize ]; then
      dd if=/dev/zero bs=1048576 count=61 2>/dev/null
      printf 'producer-finished\n' >"$FAKE_DOCKER_PRODUCER_MARKER"
      exit 0
    fi
    printf 'stdout: %s\n' "$(field "$row" 8)"
    ;;
  rm)
    shift
    while [ "$#" -gt 0 ]; do
      case "$1" in -*) shift ;; *) break ;; esac
    done
    id=${1:-}
    fail_if_requested rm
    if [ "${FAKE_DOCKER_BLOCK_OPERATION:-}" = rm ]; then sleep 30; fi
    row=$(state_row "$id") || exit 1
    [ "$(field "$row" 7)" = fail ] && exit 23
    printf '%s\n' "$id" >>"$FAKE_DOCKER_REMOVED"
    printf '%s\n' "$id"
    ;;
  system|image|volume)
    [ "${2:-}" = prune ] && exit 99
    exit 64
    ;;
  *) exit 64 ;;
esac
FAKE_DOCKER
chmod +x "$FAKE_BIN/docker"

cat >"$STATE" <<'EOF'
owned-a|true|repo-42-3-integration-db-1of2|db|1/2|postgres|ok|owned-a-log
owned-b|true|repo-42-3-integration-db-1of2|db|1/2|redis|ok|owned-b-log
other-scope|true|repo-42-2-integration-db-1of2|db|1/2|postgres|ok|scope-canary
other-partition|true|repo-42-3-integration-db-2of2|db|2/2|postgres|ok|partition-canary
testcontainers-only||repo-42-3-integration-db-1of2|db|1/2|postgres|ok|testcontainers-canary
EOF

SCOPE=repo-42-3-integration-db-1of2
SHARD=db
PARTITION=1/2
LOG_DIR="$TMP_ROOT/integration-service-logs-$SCOPE"
EVIDENCE="$TMP_ROOT/lifecycle.json"
ARCHIVE="$TMP_ROOT/service-logs.tar.gz"

run_lifecycle() {
  env -i PATH="$FAKE_BIN" HOME="$TMP_ROOT" \
    FAKE_DOCKER_STATE="$STATE" FAKE_DOCKER_REMOVED="$REMOVED" FAKE_DOCKER_TRACE="$TRACE" \
    FAKE_DOCKER_BLOCK_OPERATION="${FAKE_DOCKER_BLOCK_OPERATION:-}" \
    FAKE_DOCKER_INVALID_INSPECT_ID="${FAKE_DOCKER_INVALID_INSPECT_ID:-}" \
    FAKE_DOCKER_FAIL_OPERATION="${FAKE_DOCKER_FAIL_OPERATION:-}" \
    FAKE_DOCKER_FAIL_KIND="${FAKE_DOCKER_FAIL_KIND:-}" \
    FAKE_DOCKER_PRODUCER_MARKER="${FAKE_DOCKER_PRODUCER_MARKER:-$TMP_ROOT/producer-finished}" \
    FAKE_DOCKER_OVERSIZE_OPERATION="${FAKE_DOCKER_OVERSIZE_OPERATION:-}" \
    FAKE_DOCKER_CONTROL_PRODUCER_MARKER="${FAKE_DOCKER_CONTROL_PRODUCER_MARKER:-$TMP_ROOT/control-producer-finished}" \
    "$LIFECYCLE" "$@"
}
run_common() {
  operation=$1
  shift
  run_lifecycle "$operation" --scope "$SCOPE" --shard "$SHARD" --partition "$PARTITION" \
    --log-dir "$LOG_DIR" --evidence "$EVIDENCE" "$@"
}
prepare_common() {
  run_common bootstrap && run_common prepare
}

expect_failure 'unknown operation fails closed' run_common destroy
expect_failure 'prepare rejects collect-only outcome' run_common prepare --outcome failure
expect_failure 'cleanup rejects collect-only archive' run_common cleanup --archive "$ARCHIVE"
expect_failure 'collect requires an outcome' run_common collect --archive "$ARCHIVE"
expect_failure 'collect requires an archive' run_common collect --outcome failure
expect_failure 'missing common context is rejected' run_lifecycle prepare --scope "$SCOPE" --shard "$SHARD" --partition "$PARTITION" --log-dir "$LOG_DIR"
for bad_scope in '../escape' 'scope;docker system prune' 'scope value' "$(printf 'scope\nbreak')" '--scope'; do
  expect_failure "unsafe scope is rejected: $(printf '%s' "$bad_scope" | tr '\n' '?')" \
    run_lifecycle prepare --scope "$bad_scope" --shard "$SHARD" --partition "$PARTITION" --log-dir "$LOG_DIR" --evidence "$EVIDENCE"
done
assert_absent 'rejected values never reach Docker' 'prune' "$TRACE"
for bad_partition in 2/1 1/3 3/3 01/2; do
  expect_failure "non-canonical partition is rejected: $bad_partition" \
    run_lifecycle bootstrap --scope "$SCOPE" --shard "$SHARD" --partition "$bad_partition" --log-dir "$LOG_DIR" --evidence "$EVIDENCE"
done
expect_failure 'relative log path is rejected' \
  run_lifecycle prepare --scope "$SCOPE" --shard "$SHARD" --partition "$PARTITION" --log-dir relative/logs --evidence "$EVIDENCE"
expect_failure 'filesystem root is rejected as a log directory' \
  run_lifecycle prepare --scope "$SCOPE" --shard "$SHARD" --partition "$PARTITION" --log-dir / --evidence "$EVIDENCE"
expect_failure 'evidence cannot be placed inside collected logs' \
  run_lifecycle prepare --scope "$SCOPE" --shard "$SHARD" --partition "$PARTITION" --log-dir "$LOG_DIR" --evidence "$LOG_DIR/evidence.json"

UNPARTITIONED_SCOPE=repo-42-3-integration-postgres
UNPARTITIONED_LOG_DIR="$TMP_ROOT/integration-service-logs-$UNPARTITIONED_SCOPE"
UNPARTITIONED_EVIDENCE="$TMP_ROOT/unpartitioned.json"
expect_success 'canonical unpartitioned context bootstraps' \
  run_lifecycle bootstrap --scope "$UNPARTITIONED_SCOPE" --shard postgres-domain --partition unpartitioned \
    --log-dir "$UNPARTITIONED_LOG_DIR" --evidence "$UNPARTITIONED_EVIDENCE"
expect_success 'canonical unpartitioned context is accepted' \
  run_lifecycle prepare --scope "$UNPARTITIONED_SCOPE" --shard postgres-domain --partition unpartitioned \
    --log-dir "$UNPARTITIONED_LOG_DIR" --evidence "$UNPARTITIONED_EVIDENCE"
assert_jq 'unpartitioned context is preserved exactly' "$UNPARTITIONED_EVIDENCE" \
  '.context.partition == "unpartitioned" and .context.shard == "postgres-domain"'

STALE_SCOPE=repo-42-3-integration-stale
STALE_LOG_DIR="$TMP_ROOT/integration-service-logs-$STALE_SCOPE"
STALE_EVIDENCE="$TMP_ROOT/stale.json"
expect_success 'stale-directory case first bootstraps evidence' \
  run_lifecycle bootstrap --scope "$STALE_SCOPE" --shard db --partition unpartitioned \
    --log-dir "$STALE_LOG_DIR" --evidence "$STALE_EVIDENCE"
mkdir "$STALE_LOG_DIR"
printf 'canary\n' >"$STALE_LOG_DIR/preserve-me"
expect_failure 'prepare rejects an existing scope directory' \
  run_lifecycle prepare --scope "$STALE_SCOPE" --shard db --partition unpartitioned \
    --log-dir "$STALE_LOG_DIR" --evidence "$STALE_EVIDENCE"
assert_present 'prepare failure preserves a pre-existing directory' 'canary' "$STALE_LOG_DIR/preserve-me"
assert_jq 'prepare failure remains represented in bootstrap evidence' "$STALE_EVIDENCE" \
  '.preparation == {reason:"log-directory-exists",status:"failure"} and .disk.baselineAvailableBytes == null'

NO_DF_BOOTSTRAP_BIN="$TMP_ROOT/no-df-bootstrap-bin"
mkdir "$NO_DF_BOOTSTRAP_BIN"
for command_name in bash chmod jq mkdir mktemp mv rm; do ln -s "$FAKE_BIN/$command_name" "$NO_DF_BOOTSTRAP_BIN/$command_name"; done
BOOTSTRAP_SCOPE=repo-42-3-integration-bootstrap
BOOTSTRAP_LOG_DIR="$TMP_ROOT/integration-service-logs-$BOOTSTRAP_SCOPE"
BOOTSTRAP_EVIDENCE="$TMP_ROOT/bootstrap.json"
expect_success 'bootstrap writes evidence without prepare-only df dependency' \
  env -i PATH="$NO_DF_BOOTSTRAP_BIN" HOME="$TMP_ROOT" "$LIFECYCLE" bootstrap \
    --scope "$BOOTSTRAP_SCOPE" --shard db --partition unpartitioned \
    --log-dir "$BOOTSTRAP_LOG_DIR" --evidence "$BOOTSTRAP_EVIDENCE"
assert_jq 'minimal bootstrap evidence is pending and closed' "$BOOTSTRAP_EVIDENCE" \
  '.preparation == {reason:null,status:"pending"} and .disk.beforeCleanupStatus == "pending"'

PREPARE_FAILURE_SCOPE=repo-42-3-integration-prepare-failure
PREPARE_FAILURE_LOG_DIR="$TMP_ROOT/integration-service-logs-$PREPARE_FAILURE_SCOPE"
PREPARE_FAILURE_EVIDENCE="$TMP_ROOT/prepare-failure.json"
expect_success 'baseline-failure case bootstraps evidence' \
  run_lifecycle bootstrap --scope "$PREPARE_FAILURE_SCOPE" --shard db --partition unpartitioned \
    --log-dir "$PREPARE_FAILURE_LOG_DIR" --evidence "$PREPARE_FAILURE_EVIDENCE"
FAIL_PREPARE_DF_BIN="$TMP_ROOT/fail-prepare-df-bin"
mkdir "$FAIL_PREPARE_DF_BIN"
for command_name in awk bash chmod jq mkdir mktemp mv rm; do ln -s "$FAKE_BIN/$command_name" "$FAIL_PREPARE_DF_BIN/$command_name"; done
cat >"$FAIL_PREPARE_DF_BIN/df" <<'FAIL_PREPARE_DF'
#!/usr/bin/env bash
exit 18
FAIL_PREPARE_DF
chmod +x "$FAIL_PREPARE_DF_BIN/df"
expect_failure 'prepare records baseline measurement failure' \
  env -i PATH="$FAIL_PREPARE_DF_BIN" HOME="$TMP_ROOT" "$LIFECYCLE" prepare \
    --scope "$PREPARE_FAILURE_SCOPE" --shard db --partition unpartitioned \
    --log-dir "$PREPARE_FAILURE_LOG_DIR" --evidence "$PREPARE_FAILURE_EVIDENCE"
if [ ! -e "$PREPARE_FAILURE_LOG_DIR" ]; then pass 'failed prepare removes only its newly-created directory'; else fail 'failed prepare removes only its newly-created directory'; fi
assert_jq 'prepare baseline failure remains in lifecycle evidence' "$PREPARE_FAILURE_EVIDENCE" \
  '.preparation == {reason:"baseline-measure",status:"failure"} and .disk.baselineAvailableBytes == null'

expect_success 'bootstrap creates pending lifecycle evidence' run_common bootstrap
expect_success 'prepare creates lifecycle evidence' run_common prepare
if [ -d "$LOG_DIR" ]; then pass 'prepare creates the service log directory'; else fail 'prepare creates the service log directory'; fi
expect_success '0700 service log directory is private' directory_is_private "$LOG_DIR"
chmod 0755 "$LOG_DIR"
expect_failure '0755 service log directory is rejected' directory_is_private "$LOG_DIR"
chmod 0700 "$LOG_DIR"
POISON_STAT_BIN="$TMP_ROOT/poison-stat-bin"
mkdir "$POISON_STAT_BIN"
cat >"$POISON_STAT_BIN/stat" <<'POISON_STAT'
#!/usr/bin/env bash
case "$1" in
  -c) printf 'poison\n'; exit 1 ;;
  -f) printf '700\n' ;;
  *) exit 64 ;;
esac
POISON_STAT
chmod +x "$POISON_STAT_BIN/stat"
if mode=$(PATH="$POISON_STAT_BIN:$PATH" directory_mode "$LOG_DIR") && [ "$mode" = 700 ]; then
  pass 'failed GNU stat output cannot poison BSD fallback mode'
else
  fail 'failed GNU stat output cannot poison BSD fallback mode'
fi
assert_jq 'prepare writes a closed schema v1 document' "$EVIDENCE" '
  keys == ["cleanup","collection","context","disk","imageCleanup","preparation","schemaVersion"] and
  .schemaVersion == 1 and
  (.context | keys == ["partition","scope","shard"]) and
  .context == {partition:"1/2",scope:"repo-42-3-integration-db-1of2",shard:"db"} and
  .preparation == {reason:null,status:"success"} and
  (.disk | keys == ["afterCleanupAvailableBytes","afterCleanupStatus","baselineAvailableBytes","beforeCleanupAvailableBytes","beforeCleanupStatus"]) and
  (.disk.baselineAvailableBytes | type == "number" and . >= 0) and
  .disk.beforeCleanupAvailableBytes == null and .disk.afterCleanupAvailableBytes == null and
  .disk.beforeCleanupStatus == "pending" and .disk.afterCleanupStatus == "pending" and
  .imageCleanup == "skipped-unprovable-ownership" and
  .collection == {archiveCreated:false,attemptedContainerIds:[],capturedContainerIds:[],degraded:false,errors:[],outcome:null,truncated:false} and
  .cleanup == {attemptedContainerIds:[],errors:[],removedContainerIds:[]}'

expect_success 'successful test outcome does not create an archive' run_common collect --outcome success --archive "$ARCHIVE"
if [ ! -e "$ARCHIVE" ]; then pass 'success archive is absent'; else fail 'success archive is absent'; fi
assert_jq 'successful collection is recorded without archive' "$EVIDENCE" '.collection == {archiveCreated:false,attemptedContainerIds:[],capturedContainerIds:[],degraded:false,errors:[],outcome:"success",truncated:false}'

expect_success 'snapshot records cleanup-before after collection' run_common snapshot
assert_jq 'snapshot records a successful pre-cleanup measurement' "$EVIDENCE" '
  .disk.beforeCleanupStatus == "success" and (.disk.beforeCleanupAvailableBytes | type == "number")'

mkdir -p "$LOG_DIR"
printf 'stdout small\nstderr small\n' >"$LOG_DIR/postgres-123-1.log"
printf 'ok\n' >"$LOG_DIR/postgres-123-1.status"
printf 'must never be collected\n' >"$LOG_DIR/notes.txt"
printf 'must never be collected\n' >"$LOG_DIR/postgres-123-extra.log"
ln -s "$LOG_DIR/postgres-123-1.log" "$LOG_DIR/redis-999-1.log"
printf 'redis small\n' >"$LOG_DIR/redis-456-2.log"
printf 'ok\n' >"$LOG_DIR/redis-456-2.status"
expect_success 'failed test outcome creates a bounded archive' run_common collect --outcome failure --archive "$ARCHIVE"
if [ -f "$ARCHIVE" ]; then pass 'failure archive exists'; else fail 'failure archive exists'; fi
archive_size=$(wc -c <"$ARCHIVE" 2>/dev/null | tr -d ' ' || true)
case "$archive_size" in ''|*[!0-9]*) fail 'archive size is measurable' ;; *)
  if [ "$archive_size" -le 67108864 ]; then pass 'archive is at most 64 MiB'; else fail 'archive is at most 64 MiB'; fi ;;
esac
assert_jq 'failure collection records complete Docker capture' "$EVIDENCE" '
  .collection.archiveCreated == true and .collection.outcome == "failure" and
  .collection.truncated == false and .collection.degraded == false and
  .collection.attemptedContainerIds == ["owned-a","owned-b"] and
  .collection.capturedContainerIds == ["owned-a","owned-b"] and .collection.errors == []'
tar -tzf "$ARCHIVE" >"$TMP_ROOT/archive.list"
assert_present 'archive contains owned Docker logs' 'postgres-owned-a-docker.log' "$TMP_ROOT/archive.list"
assert_present 'archive contains second owned Docker logs' 'redis-owned-b-docker.log' "$TMP_ROOT/archive.list"
assert_absent 'archive excludes arbitrary files' 'notes.txt' "$TMP_ROOT/archive.list"
assert_absent 'archive excludes malformed canonical-looking files' 'postgres-123-extra.log' "$TMP_ROOT/archive.list"
assert_absent 'archive excludes symlinked service logs' 'redis-999-1.log' "$TMP_ROOT/archive.list"
tar -xOzf "$ARCHIVE" "$(grep 'postgres-owned-a-docker.log' "$TMP_ROOT/archive.list" | head -1)" >"$TMP_ROOT/docker-log-content"
assert_present 'archive preserves docker logs content' 'owned-a-log' "$TMP_ROOT/docker-log-content"
assert_absent 'archive excludes cross-scope Docker canary logs' 'scope-canary' "$TMP_ROOT/docker-log-content"

expect_success 'cleanup removes only exact owned containers' run_common cleanup
sort -u "$REMOVED" >"$TMP_ROOT/removed.sorted"
if diff -u - "$TMP_ROOT/removed.sorted" <<'EOF' >/dev/null; then
owned-a
owned-b
EOF
  pass 'exact managed and scope set is removed'
else
  fail 'exact managed and scope set is removed'
fi
assert_absent 'cross-scope canary is retained' 'other-scope' "$REMOVED"
assert_absent 'cross-partition canary is retained' 'other-partition' "$REMOVED"
assert_absent 'container without managed label is retained' 'testcontainers-only' "$REMOVED"
assert_present 'Docker discovery asks for the managed label' 'label=io.rss.integration.managed=true' "$TRACE"
assert_present 'Docker discovery asks for the exact scope label' "label=io.rss.integration.scope=$SCOPE" "$TRACE"
assert_present 'owned candidate is re-inspected before rm' 'inspect' "$TRACE"
assert_absent 'lifecycle never uses global prune' 'system prune' "$TRACE"
assert_absent 'lifecycle never uses image prune' 'image prune' "$TRACE"
assert_absent 'lifecycle never uses volume prune' 'volume prune' "$TRACE"
assert_jq 'cleanup evidence records fixed ownership-safe image policy' "$EVIDENCE" '
  .imageCleanup == "skipped-unprovable-ownership" and
  .cleanup.attemptedContainerIds == ["owned-a","owned-b"] and
  .cleanup.removedContainerIds == ["owned-a","owned-b"] and
  .cleanup.errors == [] and
  (.disk.beforeCleanupAvailableBytes | type == "number") and
  .disk.beforeCleanupStatus == "success" and
  (.disk.afterCleanupAvailableBytes | type == "number") and .disk.afterCleanupStatus == "success"'

if [ -f "$EVIDENCE" ]; then cp "$EVIDENCE" "$TMP_ROOT/complete.json"; else printf '{}\n' >"$TMP_ROOT/complete.json"; fi
jq -S '
  .disk.baselineAvailableBytes = 0 |
  .disk.beforeCleanupAvailableBytes = 0 |
  .disk.afterCleanupAvailableBytes = 0' "$TMP_ROOT/complete.json" >"$TMP_ROOT/normalized.json"
if diff -u "$GOLDEN" "$TMP_ROOT/normalized.json" >"$TMP_ROOT/golden.diff"; then
  pass 'lifecycle evidence matches executable schema golden'
else
  cat "$TMP_ROOT/golden.diff" >&2 || true
  fail 'lifecycle evidence matches executable schema golden'
fi

before_idempotent=$(wc -l <"$REMOVED" | tr -d ' ')
expect_success 'cleanup is idempotent' run_common cleanup
after_idempotent=$(wc -l <"$REMOVED" | tr -d ' ')
if [ "$before_idempotent" = "$after_idempotent" ]; then pass 'idempotent cleanup issues no duplicate rm'; else fail 'idempotent cleanup issues no duplicate rm'; fi

cat >"$STATE" <<'EOF'
budget-exhausted|true|repo-42-3-integration-db-1of2|db|1/2|redis|ok|must-not-be-requested
EOF
rm -rf "$LOG_DIR"
TRUNCATED_ARCHIVE="$TMP_ROOT/truncated-service-logs.tar.gz"
expect_success 'bounded archive cycle bootstraps' run_common bootstrap
expect_success 'bounded archive cycle prepares' run_common prepare
expect_success 'bounded archive cycle snapshots' run_common snapshot
# A sparse over-limit fixture makes the 64 MiB policy cheap to exercise.
dd if=/dev/zero of="$LOG_DIR/redis-456-2.log" bs=1 count=0 seek=67108865 2>/dev/null
printf 'ok\n' >"$LOG_DIR/redis-456-2.status"
: >"$TRACE"
expect_success 'over-limit local logs still create a bounded archive' \
  run_common collect --outcome failure --archive "$TRUNCATED_ARCHIVE"
truncated_archive_size=$(wc -c <"$TRUNCATED_ARCHIVE" | tr -d ' ')
if [ "$truncated_archive_size" -le 67108864 ]; then pass 'truncated archive is at most 64 MiB'; else fail 'truncated archive is at most 64 MiB'; fi
assert_jq 'over-limit local logs set closed truncation state' "$EVIDENCE" \
  '.collection.truncated == true and .collection.degraded == true and .collection.errors == []'
assert_absent 'exhausted payload budget prevents Docker logs producer from starting' 'logs budget-exhausted' "$TRACE"

cat >"$STATE" <<'EOF'
oversize-producer|true|repo-42-3-integration-db-1of2|db|1/2|postgres|oversize|unused
EOF
rm -rf "$LOG_DIR"
rm -f "$TMP_ROOT/producer-finished"
PRODUCER_ARCHIVE="$TMP_ROOT/producer-bounded-service-logs.tar.gz"
expect_success 'producer-bound cycle bootstraps' run_common bootstrap
expect_success 'producer-bound cycle prepares' run_common prepare
expect_success 'producer-bound cycle snapshots' run_common snapshot
expect_success 'over-limit Docker producer still yields a bounded degraded archive' \
  run_common collect --outcome failure --archive "$PRODUCER_ARCHIVE"
if [ ! -e "$TMP_ROOT/producer-finished" ]; then
  pass 'Docker logs producer is terminated before completing over-limit output'
else
  fail 'Docker logs producer is terminated before completing over-limit output'
fi
assert_jq 'producer-side cap records truncation without an open Docker error' "$EVIDENCE" '
  .collection.truncated == true and .collection.degraded == true and
  .collection.attemptedContainerIds == ["oversize-producer"] and
  .collection.capturedContainerIds == ["oversize-producer"] and .collection.errors == []'

cat >"$STATE" <<'EOF'
EOF
rm -rf "$LOG_DIR"
rm -f "$TMP_ROOT/control-producer-finished"
CONTROL_ARCHIVE="$TMP_ROOT/control-bounded-service-logs.tar.gz"
expect_success 'control-bound cycle bootstraps' run_common bootstrap
expect_success 'control-bound cycle prepares' run_common prepare
FAKE_DOCKER_OVERSIZE_OPERATION='ps' \
  expect_success 'over-limit Docker control output degrades collection' \
    run_common collect --outcome failure --archive "$CONTROL_ARCHIVE"
if [ ! -e "$TMP_ROOT/control-producer-finished" ]; then
  pass 'Docker control producer is terminated at its fixed output cap'
else
  fail 'Docker control producer is terminated at its fixed output cap'
fi
assert_jq 'over-limit Docker control output is an error rather than partial success' "$EVIDENCE" '
  .collection.degraded == true and
  .collection.errors == [{containerId:null,exitStatus:null,operation:"discover",reason:"invalid-output"}]'

cat >"$STATE" <<'EOF'
EOF
rm -rf "$LOG_DIR"
WRITER_STATUS_ARCHIVE="$TMP_ROOT/writer-status-service-logs.tar.gz"
expect_success 'writer-status cycle bootstraps' run_common bootstrap
expect_success 'writer-status cycle prepares' run_common prepare
expect_success 'writer-status cycle snapshots' run_common snapshot
printf 'missing status\n' >"$LOG_DIR/postgres-201-1.log"
printf 'symlink status\n' >"$LOG_DIR/redis-202-1.log"
printf 'ok\n' >"$TMP_ROOT/status-target"
ln -s "$TMP_ROOT/status-target" "$LOG_DIR/redis-202-1.status"
printf 'malformed status\n' >"$LOG_DIR/rabbitmq-203-1.log"
printf 'not-a-status\n' >"$LOG_DIR/rabbitmq-203-1.status"
printf 'failed writer\n' >"$LOG_DIR/mosquitto-204-1.log"
printf 'writer-error\n' >"$LOG_DIR/mosquitto-204-1.status"
expect_success 'writer sidecars degrade collection without preventing archive publication' \
  run_common collect --outcome failure --archive "$WRITER_STATUS_ARCHIVE"
assert_jq 'missing, symlinked, malformed and failed writer sidecars produce one closed error' "$EVIDENCE" '
  .collection.archiveCreated == true and .collection.degraded == true and
  .collection.errors == [{containerId:null,exitStatus:null,operation:"writer",reason:"io"}]'
tar -tzf "$WRITER_STATUS_ARCHIVE" >"$TMP_ROOT/writer-status.list"
assert_absent 'writer status sidecars are evidence metadata rather than archive payload' '.status' "$TMP_ROOT/writer-status.list"

cat >"$STATE" <<'EOF'
invalid-inspect|true|repo-42-3-integration-db-1of2|db|1/2|postgres|ok|invalid-inspect-log
log-failure|true|repo-42-3-integration-db-1of2|db|1/2|redis|logfail|must-not-archive
EOF
rm -rf "$LOG_DIR"
DEGRADED_ARCHIVE="$TMP_ROOT/degraded-service-logs.tar.gz"
expect_success 'degraded collection cycle bootstraps' run_common bootstrap
expect_success 'degraded collection cycle prepares' run_common prepare
expect_success 'degraded collection cycle snapshots' run_common snapshot
FAKE_DOCKER_INVALID_INSPECT_ID=invalid-inspect \
  expect_success 'collection archives local evidence despite inspect/log failures' \
    run_common collect --outcome failure --archive "$DEGRADED_ARCHIVE"
assert_jq 'collection failures are closed and degraded' "$EVIDENCE" '
  .collection.degraded == true and
  .collection.attemptedContainerIds == ["log-failure"] and .collection.capturedContainerIds == [] and
  (.collection.errors | sort_by(.containerId)) == [
    {containerId:"invalid-inspect",exitStatus:null,operation:"inspect",reason:"invalid-output"},
    {containerId:"log-failure",exitStatus:24,operation:"logs",reason:"unknown"}
  ]'
tar -tzf "$DEGRADED_ARCHIVE" >"$TMP_ROOT/degraded.list"
assert_absent 'failed docker logs do not leak stderr into archive' 'must-not-archive' "$TMP_ROOT/degraded.list"

cat >"$STATE" <<'EOF'
EOF
rm -rf "$LOG_DIR"
UNAVAILABLE_ARCHIVE="$TMP_ROOT/unavailable-service-logs.tar.gz"
expect_success 'unavailable-Docker collection cycle bootstraps' run_common bootstrap
expect_success 'unavailable-Docker collection cycle prepares' run_common prepare
expect_success 'unavailable-Docker collection cycle snapshots' run_common snapshot
COLLECT_NO_DOCKER_BIN="$TMP_ROOT/collect-no-docker-bin"
mkdir "$COLLECT_NO_DOCKER_BIN"
for command_name in awk bash cat chmod cp df find gzip head jq kill mkdir mkfifo mktemp mv rm sed sleep sort stat tar tr wc; do
  command_path=$(command -v "$command_name")
  [ "$command_name" = kill ] || ln -s "$command_path" "$COLLECT_NO_DOCKER_BIN/$command_name"
done
expect_success 'unavailable Docker degrades collection without losing local archive' \
  env -i PATH="$COLLECT_NO_DOCKER_BIN" HOME="$TMP_ROOT" "$LIFECYCLE" collect \
    --scope "$SCOPE" --shard "$SHARD" --partition "$PARTITION" --log-dir "$LOG_DIR" --evidence "$EVIDENCE" \
    --outcome failure --archive "$UNAVAILABLE_ARCHIVE"
assert_jq 'unavailable Docker collection is explicitly degraded' "$EVIDENCE" '
  .collection.archiveCreated == true and .collection.degraded == true and
  (.collection.errors | any(. == {containerId:null,exitStatus:127,operation:"discover",reason:"unavailable"}))'

cat >"$STATE" <<'EOF'
blocked|true|repo-42-3-integration-db-1of2|db|1/2|postgres|ok|blocked-log
EOF
rm -rf "$LOG_DIR"
expect_success 'blocking Docker cycle bootstraps' run_common bootstrap
expect_success 'blocking Docker cycle prepares' run_common prepare
expect_success 'blocking Docker cycle snapshots' run_common snapshot
FAKE_DOCKER_BLOCK_OPERATION='ps' expect_failure 'blocked Docker discovery is killed within the lifecycle deadline' run_common cleanup
assert_jq 'blocked Docker discovery records timeout without hanging cleanup' "$EVIDENCE" '
  (.cleanup.errors | any(. == {containerId:null,exitStatus:124,operation:"discover",reason:"timeout"})) and
  .disk.afterCleanupStatus == "success"'

cat >"$STATE" <<'EOF'
EOF
rm -rf "$LOG_DIR"
expect_success 'after-df failure cycle bootstraps' run_common bootstrap
expect_success 'after-df failure cycle prepares' run_common prepare
expect_success 'after-df failure cycle snapshots' run_common snapshot
FAIL_DF_BIN="$TMP_ROOT/fail-df-bin"
mkdir "$FAIL_DF_BIN"
for command_name in awk bash cat chmod cp find gzip head jq kill mkdir mkfifo mktemp mv rm sed sleep sort stat tar tr wc; do
  command_path=$(command -v "$command_name")
  [ "$command_name" = kill ] || ln -s "$command_path" "$FAIL_DF_BIN/$command_name"
done
ln -s "$FAKE_BIN/docker" "$FAIL_DF_BIN/docker"
cat >"$FAIL_DF_BIN/df" <<'FAIL_DF'
#!/usr/bin/env bash
exit 19
FAIL_DF
chmod +x "$FAIL_DF_BIN/df"
run_fail_df_cleanup() {
  env -i PATH="$FAIL_DF_BIN" HOME="$TMP_ROOT" \
    FAKE_DOCKER_STATE="$STATE" FAKE_DOCKER_REMOVED="$REMOVED" FAKE_DOCKER_TRACE="$TRACE" \
    "$LIFECYCLE" cleanup --scope "$SCOPE" --shard "$SHARD" --partition "$PARTITION" \
      --log-dir "$LOG_DIR" --evidence "$EVIDENCE"
}
expect_failure 'post-cleanup df failure is retained instead of copied from before' run_fail_df_cleanup
assert_jq 'post-cleanup df failure is explicit and nullable' "$EVIDENCE" '
  .disk.beforeCleanupStatus == "success" and (.disk.beforeCleanupAvailableBytes | type == "number") and
  .disk.afterCleanupStatus == "failure" and .disk.afterCleanupAvailableBytes == null'

cat >"$STATE" <<'EOF'
failure-a|true|repo-42-3-integration-db-1of2|db|1/2|postgres|fail|failure-a-log
failure-b|true|repo-42-3-integration-db-1of2|db|1/2|redis|ok|failure-b-log
EOF
: >"$REMOVED"
rm -rf "$LOG_DIR"
expect_success 'partial failure fixture can be bootstrapped' run_common bootstrap
expect_success 'partial failure fixture can be prepared' run_common prepare
expect_success 'partial failure snapshot succeeds' run_common snapshot
expect_failure 'one rm failure makes cleanup nonzero' run_common cleanup
assert_present 'cleanup continues after one rm failure' 'failure-b' "$REMOVED"
assert_jq 'partial failure is closed in evidence' "$EVIDENCE" '
  .cleanup.attemptedContainerIds == ["failure-a","failure-b"] and
  .cleanup.removedContainerIds == ["failure-b"] and
  (.cleanup.errors | length == 1 and .[0] == {containerId:"failure-a",exitStatus:23,operation:"remove",reason:"unknown"})'

NO_DOCKER_BIN="$TMP_ROOT/no-docker-bin"
mkdir "$NO_DOCKER_BIN"
for command_name in awk bash cat chmod cp date df dirname du find grep gzip head jq mkdir mkfifo mktemp mv pwd rm sed sleep sort stat tar tr wc; do
  ln -s "$FAKE_BIN/$command_name" "$NO_DOCKER_BIN/$command_name"
done
expect_failure 'unavailable Docker fails cleanup after updating evidence' \
  env -i PATH="$NO_DOCKER_BIN" HOME="$TMP_ROOT" "$LIFECYCLE" cleanup \
    --scope "$SCOPE" --shard "$SHARD" --partition "$PARTITION" --log-dir "$LOG_DIR" --evidence "$EVIDENCE"
assert_jq 'Docker discovery failure is represented without an open error string' "$EVIDENCE" '
  (.cleanup.errors | any(. == {containerId:null,exitStatus:127,operation:"discover",reason:"unavailable"})) and
  .imageCleanup == "skipped-unprovable-ownership"'

cat >"$STATE" <<'EOF'
EOF
for failure_kind in daemon-unreachable permission-denied not-found conflict io unknown; do
  rm -rf "$LOG_DIR"
  CLASSIFIED_ARCHIVE="$TMP_ROOT/classified-$failure_kind-service-logs.tar.gz"
  expect_success "Docker $failure_kind cycle bootstraps" run_common bootstrap
  expect_success "Docker $failure_kind cycle prepares" run_common prepare
  expect_success "Docker $failure_kind cycle snapshots" run_common snapshot
  FAKE_DOCKER_FAIL_OPERATION=ps FAKE_DOCKER_FAIL_KIND="$failure_kind" \
    expect_success "Docker $failure_kind remains a closed degraded collection" \
      run_common collect --outcome failure --archive "$CLASSIFIED_ARCHIVE"
  assert_jq "Docker $failure_kind is retained as an actionable closed reason" "$EVIDENCE" \
    ".collection.degraded == true and .collection.errors == [{containerId:null,exitStatus:42,operation:\"discover\",reason:\"$failure_kind\"}]"
  assert_absent "Docker $failure_kind raw stderr is absent from lifecycle console" 'SECRET_DOCKER_STDERR_CANARY' "$TMP_ROOT/stderr"
  assert_absent "Docker $failure_kind raw stderr is absent from lifecycle evidence" 'SECRET_DOCKER_STDERR_CANARY' "$EVIDENCE"
  tar -xOzf "$CLASSIFIED_ARCHIVE" >"$TMP_ROOT/classified-$failure_kind.payload"
  assert_absent "Docker $failure_kind raw stderr is absent from lifecycle archive" \
    'SECRET_DOCKER_STDERR_CANARY' "$TMP_ROOT/classified-$failure_kind.payload"
done

cat >"$STATE" <<'EOF'
classified-operation|true|repo-42-3-integration-db-1of2|db|1/2|postgres|ok|classified-log
EOF
for classified_operation in inspect logs; do
  rm -rf "$LOG_DIR"
  OPERATION_ARCHIVE="$TMP_ROOT/classified-$classified_operation-service-logs.tar.gz"
  expect_success "classified $classified_operation cycle bootstraps" run_common bootstrap
  expect_success "classified $classified_operation cycle prepares" run_common prepare
  FAKE_DOCKER_FAIL_OPERATION="$classified_operation" FAKE_DOCKER_FAIL_KIND=permission-denied \
    expect_success "classified $classified_operation failure preserves a closed reason" \
      run_common collect --outcome failure --archive "$OPERATION_ARCHIVE"
  assert_jq "classified $classified_operation consumer records the shared reason" "$EVIDENCE" \
    ".collection.errors == [{containerId:\"classified-operation\",exitStatus:42,operation:\"$classified_operation\",reason:\"permission-denied\"}]"
done

rm -rf "$LOG_DIR"
expect_success 'classified remove cycle bootstraps' run_common bootstrap
expect_success 'classified remove cycle prepares' run_common prepare
FAKE_DOCKER_FAIL_OPERATION=rm FAKE_DOCKER_FAIL_KIND=conflict \
  expect_failure 'classified remove failure keeps cleanup nonzero' run_common cleanup
assert_jq 'classified remove consumer records the shared reason' "$EVIDENCE" '
  .cleanup.errors == [{containerId:"classified-operation",exitStatus:42,operation:"remove",reason:"conflict"}]'

LEGACY_REASON_EVIDENCE="$TMP_ROOT/legacy-failed-reason.json"
jq '.collection.errors = [{containerId:null,exitStatus:1,operation:"discover",reason:"failed"}]' \
  "$EVIDENCE" >"$LEGACY_REASON_EVIDENCE"
expect_failure 'legacy open-ended Docker failure reason is rejected by schema validation' \
  run_lifecycle snapshot --scope "$SCOPE" --shard "$SHARD" --partition "$PARTITION" \
    --log-dir "$LOG_DIR" --evidence "$LEGACY_REASON_EVIDENCE"

for terminal_outcome in cancelled skipped; do
  rm -rf "$LOG_DIR"
  TERMINAL_ARCHIVE="$TMP_ROOT/$terminal_outcome-service-logs.tar.gz"
  rm -f "$TERMINAL_ARCHIVE"
  expect_success "$terminal_outcome outcome cycle bootstraps" run_common bootstrap
  expect_success "$terminal_outcome outcome cycle prepares" run_common prepare
  expect_success "$terminal_outcome outcome is accepted without creating an archive" \
    run_common collect --outcome "$terminal_outcome" --archive "$TERMINAL_ARCHIVE"
  if [ ! -e "$TERMINAL_ARCHIVE" ]; then
    pass "$terminal_outcome outcome does not create a log archive"
  else
    fail "$terminal_outcome outcome does not create a log archive"
  fi
  assert_jq "$terminal_outcome terminal outcome is preserved exactly" "$EVIDENCE" \
    ".collection.outcome == \"$terminal_outcome\" and .collection.archiveCreated == false"
done

rm -rf "$LOG_DIR" "$TMP_ROOT/missing-archive-parent"
expect_success 'early-failure outcome cycle bootstraps' run_common bootstrap
expect_success 'early-failure outcome cycle prepares' run_common prepare
expect_failure 'failure collection still fails when its archive parent is absent' \
  run_common collect --outcome failure --archive "$TMP_ROOT/missing-archive-parent/service-logs.tar.gz"
assert_jq 'terminal outcome is atomically recorded before later collection failures' "$EVIDENCE" \
  '.collection.outcome == "failure" and .collection.archiveCreated == false'

if [ "$FAILURES" -ne 0 ]; then
  printf '%s integration service lifecycle selftest(s) failed\n' "$FAILURES" >&2
  exit 1
fi
printf 'all integration service lifecycle selftests passed\n'
