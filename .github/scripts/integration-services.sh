#!/usr/bin/env bash
set -eu

# INVARIANT: CI-INTEGRATION-SERVICE-LIFECYCLE-01

ARCHIVE_LIMIT_BYTES=67108864
ARCHIVE_PAYLOAD_BUDGET_BYTES=62914560
DOCKER_CONTROL_STDOUT_LIMIT_BYTES=1048576
DOCKER_STDERR_LIMIT_BYTES=16384
DOCKER_TIMEOUT_SECONDS=5
DOCKER_KILL_AFTER_SECONDS=2

usage() {
  printf 'usage: %s <bootstrap|prepare|snapshot|collect|cleanup> --scope <scope> --shard <shard> --partition <unpartitioned|1/2|2/2> --log-dir <absolute-dir> --evidence <absolute-file> [collect: --outcome <success|failure|cancelled|skipped> --archive <absolute-file>]\n' "$0" >&2
  exit 2
}

die() {
  printf 'integration-services: %s\n' "$1" >&2
  exit 1
}

[ "$#" -gt 0 ] || usage
operation=$1
shift
case "$operation" in bootstrap|prepare|snapshot|collect|cleanup) ;; *) usage ;; esac

scope=
shard=
partition=
log_dir=
evidence=
outcome=
archive=
seen_scope=false
seen_shard=false
seen_partition=false
seen_log_dir=false
seen_evidence=false
seen_outcome=false
seen_archive=false

while [ "$#" -gt 0 ]; do
  [ "$#" -ge 2 ] || usage
  case "$1" in
    --scope) [ "$seen_scope" = false ] || usage; scope=$2; seen_scope=true ;;
    --shard) [ "$seen_shard" = false ] || usage; shard=$2; seen_shard=true ;;
    --partition) [ "$seen_partition" = false ] || usage; partition=$2; seen_partition=true ;;
    --log-dir) [ "$seen_log_dir" = false ] || usage; log_dir=$2; seen_log_dir=true ;;
    --evidence) [ "$seen_evidence" = false ] || usage; evidence=$2; seen_evidence=true ;;
    --outcome) [ "$seen_outcome" = false ] || usage; outcome=$2; seen_outcome=true ;;
    --archive) [ "$seen_archive" = false ] || usage; archive=$2; seen_archive=true ;;
    *) usage ;;
  esac
  shift 2
done

[ "$seen_scope" = true ] && [ "$seen_shard" = true ] && [ "$seen_partition" = true ] && \
  [ "$seen_log_dir" = true ] && [ "$seen_evidence" = true ] || usage
if [ "$operation" = collect ]; then
  [ "$seen_outcome" = true ] && [ "$seen_archive" = true ] || usage
  case "$outcome" in success|failure|cancelled|skipped) ;; *) usage ;; esac
else
  [ "$seen_outcome" = false ] && [ "$seen_archive" = false ] || usage
fi

validate_token() {
  value=$1
  case "$value" in ''|*[!A-Za-z0-9._-]*|[-._]*) return 1 ;; esac
  [ "${#value}" -le 160 ]
}

validate_absolute_path() {
  value=$1
  case "$value" in /*) ;; *) return 1 ;; esac
  case "$value" in *$'\n'*|*$'\r'*|*$'\t'*|*/../*|*/./*|*/..|*/.) return 1 ;; esac
  [ "$value" != / ] || return 1
  case "$value" in */) return 1 ;; esac
  [ "${#value}" -le 4096 ]
}

validate_token "$scope" || die 'invalid scope'
validate_token "$shard" || die 'invalid shard'
case "$partition" in unpartitioned|1/2|2/2) ;; *) die 'invalid partition' ;; esac
validate_absolute_path "$log_dir" || die 'invalid log directory'
validate_absolute_path "$evidence" || die 'invalid evidence path'
case "${log_dir##*/}" in "integration-service-logs-$scope") ;; *) die 'log directory must be scope-derived' ;; esac
if [ "$operation" = collect ]; then validate_absolute_path "$archive" || die 'invalid archive path'; fi
[ "$log_dir" != "$evidence" ] || die 'paths must be distinct'
[ "$archive" = '' ] || { [ "$archive" != "$evidence" ] && [ "$archive" != "$log_dir" ]; } || die 'paths must be distinct'
case "$evidence/" in "$log_dir"/*) die 'evidence must be outside the log directory' ;; esac
case "$archive/" in "$log_dir"/*) die 'archive must be outside the log directory' ;; esac

for dependency in jq mktemp mv mkdir chmod rm; do
  command -v "$dependency" >/dev/null 2>&1 || die "required command unavailable: $dependency"
done
case "$operation" in
  prepare|snapshot|cleanup)
    for dependency in df awk; do command -v "$dependency" >/dev/null 2>&1 || die "required command unavailable: $dependency"; done
    ;;
esac
case "$operation" in
  cleanup)
    for dependency in sleep kill cat head mkfifo wc; do command -v "$dependency" >/dev/null 2>&1 || die "required command unavailable: $dependency"; done
    ;;
esac

available_bytes() {
  path=$1
  line=$(df -Pk "$path" 2>/dev/null | awk 'END { print $4 }') || return 1
  case "$line" in ''|*[!0-9]*) return 1 ;; esac
  printf '%s\n' "$((line * 1024))"
}

evidence_dir=${evidence%/*}
[ -n "$evidence_dir" ] || evidence_dir=/

validate_evidence() {
  [ -f "$evidence" ] || die 'lifecycle evidence does not exist'
  jq -e '
    def uint_or_null: . == null or (type == "number" and . >= 0 and floor == .);
    def docker_error($ops):
      keys == ["containerId","exitStatus","operation","reason"] and
      (.containerId == null or (.containerId | type == "string")) and
      (.exitStatus == null or (.exitStatus | type == "number" and . >= 0 and floor == .)) and
      (.operation as $op | $ops | index($op) != null) and
      (.reason == "unavailable" or .reason == "timeout" or .reason == "daemon-unreachable" or
       .reason == "permission-denied" or .reason == "not-found" or .reason == "conflict" or
       .reason == "io" or .reason == "unknown" or .reason == "invalid-output") and
      (if .operation == "writer" then
         .containerId == null and .exitStatus == null and .reason == "io"
       else
         .operation != "writer"
       end);
    keys == ["cleanup","collection","context","disk","imageCleanup","preparation","schemaVersion"] and
    .schemaVersion == 1 and
    (.context | keys == ["partition","scope","shard"] and ([.[] | type == "string"] | all)) and
    (.preparation | keys == ["reason","status"] and
      (.status == "pending" or .status == "success" or .status == "failure") and
      (.reason == null or .reason == "log-directory-exists" or .reason == "log-directory-create" or
       .reason == "log-directory-protect" or .reason == "baseline-measure")) and
    (.disk | keys == ["afterCleanupAvailableBytes","afterCleanupStatus","baselineAvailableBytes","beforeCleanupAvailableBytes","beforeCleanupStatus"] and
      (.baselineAvailableBytes | uint_or_null) and (.beforeCleanupAvailableBytes | uint_or_null) and
      (.afterCleanupAvailableBytes | uint_or_null) and
      (.beforeCleanupStatus == "pending" or .beforeCleanupStatus == "success" or .beforeCleanupStatus == "failure") and
      (.afterCleanupStatus == "pending" or .afterCleanupStatus == "success" or .afterCleanupStatus == "failure")) and
    .imageCleanup == "skipped-unprovable-ownership" and
    (.collection | keys == ["archiveCreated","attemptedContainerIds","capturedContainerIds","degraded","errors","outcome","truncated"] and
      (.archiveCreated | type == "boolean") and (.degraded | type == "boolean") and (.truncated | type == "boolean") and
      (.outcome == null or .outcome == "success" or .outcome == "failure" or
       .outcome == "cancelled" or .outcome == "skipped") and
      ([.attemptedContainerIds[],.capturedContainerIds[] | type == "string"] | all) and
      ([.errors[] | docker_error(["discover","inspect","logs","writer"])] | all)) and
    (.cleanup | keys == ["attemptedContainerIds","attemptedNetworkIds","errors","removedContainerIds","removedNetworkIds"] and
      ([.attemptedContainerIds[],.removedContainerIds[],.attemptedNetworkIds[],.removedNetworkIds[] | type == "string"] | all) and
      ([.errors[] | docker_error(["discover","inspect","remove","network-discover","network-remove"])] | all))
  ' "$evidence" >/dev/null 2>&1 || die 'lifecycle evidence is invalid'
  jq -e --arg scope "$scope" --arg shard "$shard" --arg partition "$partition" \
    '.context == {partition:$partition,scope:$scope,shard:$shard}' "$evidence" >/dev/null 2>&1 || \
    die 'lifecycle evidence context mismatch'
}

atomic_jq_update() {
  filter=$1
  shift
  tmp=$(mktemp "$evidence_dir/.integration-services.evidence.XXXXXX" 2>/dev/null) || die 'cannot create evidence temporary file'
  if jq "$@" "$filter" "$evidence" >"$tmp" 2>/dev/null && jq -e . "$tmp" >/dev/null 2>&1; then
    chmod 600 "$tmp" || { rm -f "$tmp"; die 'cannot protect evidence temporary file'; }
    mv "$tmp" "$evidence" || { rm -f "$tmp"; die 'cannot replace lifecycle evidence'; }
  else
    rm -f "$tmp"
    die 'cannot update lifecycle evidence'
  fi
}

bootstrap() {
  umask 077
  mkdir -p "$evidence_dir" || die 'cannot create evidence directory'
  tmp=$(mktemp "$evidence_dir/.integration-services.evidence.XXXXXX" 2>/dev/null) || die 'cannot create evidence temporary file'
  if jq -n --arg scope "$scope" --arg shard "$shard" --arg partition "$partition" '
      {schemaVersion:1,
       context:{scope:$scope,shard:$shard,partition:$partition},
       preparation:{status:"pending",reason:null},
       disk:{baselineAvailableBytes:null,beforeCleanupAvailableBytes:null,beforeCleanupStatus:"pending",afterCleanupAvailableBytes:null,afterCleanupStatus:"pending"},
       collection:{archiveCreated:false,outcome:null,truncated:false,degraded:false,attemptedContainerIds:[],capturedContainerIds:[],errors:[]},
       cleanup:{attemptedContainerIds:[],removedContainerIds:[],attemptedNetworkIds:[],removedNetworkIds:[],errors:[]},
       imageCleanup:"skipped-unprovable-ownership"}' >"$tmp" 2>/dev/null; then
    chmod 600 "$tmp" || { rm -f "$tmp"; die 'cannot protect evidence temporary file'; }
    mv "$tmp" "$evidence" || { rm -f "$tmp"; die 'cannot replace lifecycle evidence'; }
  else
    rm -f "$tmp"
    die 'cannot construct lifecycle evidence'
  fi
}

prepare_failure() {
  reason=$1
  if [ "${prepare_created:-false}" = true ] && ! rm -rf "$log_dir"; then
    printf 'integration-services: cannot remove directory created by failed prepare\n' >&2
  fi
  # shellcheck disable=SC2016 # jq variables are supplied with --arg.
  atomic_jq_update '.preparation = {status:"failure",reason:$reason}' --arg reason "$reason"
  die "prepare failed: $reason"
}

prepare() {
  validate_evidence
  jq -e '.preparation == {status:"pending",reason:null}' "$evidence" >/dev/null 2>&1 || die 'lifecycle preparation is not pending'
  umask 077
  prepare_created=false
  [ ! -e "$log_dir" ] && [ ! -L "$log_dir" ] || prepare_failure log-directory-exists
  mkdir "$log_dir" || prepare_failure log-directory-create
  prepare_created=true
  chmod 700 "$log_dir" || prepare_failure log-directory-protect
  baseline=$(available_bytes "$log_dir") || prepare_failure baseline-measure
  # shellcheck disable=SC2016 # jq variables are supplied with --argjson.
  atomic_jq_update '.preparation = {status:"success",reason:null} | .disk.baselineAvailableBytes = $baseline' --argjson baseline "$baseline"
}

snapshot() {
  validate_evidence
  if before=$(available_bytes "$evidence_dir"); then
    # shellcheck disable=SC2016 # jq variables are supplied with --argjson.
    atomic_jq_update '.disk.beforeCleanupAvailableBytes = $before | .disk.beforeCleanupStatus = "success"' --argjson before "$before"
  else
    atomic_jq_update '.disk.beforeCleanupAvailableBytes = null | .disk.beforeCleanupStatus = "failure"'
    die 'cannot measure pre-cleanup disk availability'
  fi
}

docker_failure_reason=unknown
docker_exit_status=1

classify_docker_failure() {
  stderr_file=$1
  stderr_sample=$(cat "$stderr_file" 2>/dev/null || true)
  case "$stderr_sample" in
    *'permission denied'*|*'Permission denied'*) docker_failure_reason=permission-denied ;;
    *'Cannot connect to the Docker daemon'*|*'cannot connect to the Docker daemon'*|*'Is the docker daemon running'*|*'connection refused'*)
      docker_failure_reason=daemon-unreachable
      ;;
    *'No such container'*|*'no such container'*|*'not found'*|*'Not Found'*) docker_failure_reason=not-found ;;
    *'Conflict:'*|*'conflict:'*|*'already in progress'*|*'already in use'*) docker_failure_reason=conflict ;;
    *'input/output error'*|*'Input/output error'*|*'no space left on device'*|*'read-only file system'*) docker_failure_reason=io ;;
    *) docker_failure_reason=unknown ;;
  esac
}

run_docker() {
  stdout_file=$1
  stderr_file=$2
  docker_mode=$3
  case "$docker_mode" in
    control) stdout_limit=$DOCKER_CONTROL_STDOUT_LIMIT_BYTES; shift 3 ;;
    logs) stdout_limit=$4; shift 4 ;;
    *) return 1 ;;
  esac
  docker_failure_reason=unknown
  docker_exit_status=1
  marker=$(mktemp "$evidence_dir/.integration-services.timeout.XXXXXX") || return 1
  rm -f "$marker"
  if ! command -v docker >/dev/null 2>&1; then
    : >"$stdout_file"; : >"$stderr_file"
    docker_failure_reason=unavailable; docker_exit_status=127
    return 1
  fi

  stderr_fifo=$(mktemp "$evidence_dir/.integration-services.docker-err-fifo.XXXXXX") || return 1
  stdout_fifo=$(mktemp "$evidence_dir/.integration-services.docker-out-fifo.XXXXXX") || {
    rm -f "$stderr_fifo"
    return 1
  }
  rm -f "$stderr_fifo" "$stdout_fifo"
  if ! mkfifo "$stderr_fifo" "$stdout_fifo"; then
    rm -f "$stderr_fifo" "$stdout_fifo"
    return 1
  fi
  (
    head -c "$DOCKER_STDERR_LIMIT_BYTES" >"$stderr_file"
    cat >/dev/null
  ) <"$stderr_fifo" &
  stderr_reader_pid=$!
  head -c "$((stdout_limit + 1))" <"$stdout_fifo" >"$stdout_file" &
  stdout_reader_pid=$!
  LC_ALL=C docker "$@" >"$stdout_fifo" 2>"$stderr_fifo" &
  command_pid=$!
  (
    sleeper_pid=
    trap '[ -z "$sleeper_pid" ] || kill -TERM "$sleeper_pid" 2>/dev/null || true; exit 0' TERM
    sleep "$DOCKER_TIMEOUT_SECONDS" &
    sleeper_pid=$!
    wait "$sleeper_pid" 2>/dev/null || exit 0
    if kill -0 "$command_pid" 2>/dev/null; then
      : >"$marker"
      kill -TERM "$command_pid" 2>/dev/null || true
      sleep "$DOCKER_KILL_AFTER_SECONDS" &
      sleeper_pid=$!
      wait "$sleeper_pid" 2>/dev/null || exit 0
      kill -KILL "$command_pid" 2>/dev/null || true
    fi
  ) &
  watchdog_pid=$!
  if wait "$command_pid"; then status=0; else status=$?; fi
  kill -TERM "$watchdog_pid" 2>/dev/null || true
  wait "$watchdog_pid" 2>/dev/null || true
  wait "$stdout_reader_pid" 2>/dev/null || true
  wait "$stderr_reader_pid" 2>/dev/null || true
  rm -f "$stdout_fifo" "$stderr_fifo"

  succeeded=false
  if [ -e "$marker" ]; then
    docker_failure_reason=timeout
    docker_exit_status=124
  elif [ "$(wc -c <"$stdout_file" | awk '{print $1}')" -gt "$stdout_limit" ]; then
    if [ "$docker_mode" = logs ]; then
      docker_exit_status=0
      succeeded=true
    else
      docker_failure_reason=invalid-output
      docker_exit_status=null
    fi
  elif [ "$status" -eq 0 ]; then
    docker_exit_status=0
    succeeded=true
  else
    docker_exit_status=$status
    classify_docker_failure "$stderr_file"
  fi
  rm -f "$marker"
  [ "$succeeded" = true ]
}

report_docker_failure() {
  op=$1 id=$2 reason=$3 status=$4
  target=${id:-scope}
  printf 'integration-services: docker %s failed for %s (reason=%s,status=%s)\n' "$op" "$target" "$reason" "$status" >&2
}

append_error() {
  json=$1 id=$2 op=$3 reason=$4 status=$5
  jq -c --arg id "$id" --arg op "$op" --arg reason "$reason" --argjson status "$status" \
    '. + [{containerId:(if $id == "" then null else $id end),exitStatus:$status,operation:$op,reason:$reason}]' <<EOF
$json
EOF
}

labels_match() {
  labels=$1
  jq -e --arg scope "$scope" --arg shard "$shard" --arg partition "$partition" '
    .["io.rss.integration.managed"] == "true" and
    .["io.rss.integration.scope"] == $scope and
    .["io.rss.integration.shard"] == $shard and
    .["io.rss.integration.partition"] == $partition and
    (.["io.rss.integration.service"] == "postgres" or .["io.rss.integration.service"] == "redis" or
     .["io.rss.integration.service"] == "rabbitmq" or .["io.rss.integration.service"] == "mosquitto" or
     .["io.rss.integration.service"] == "minio" or .["io.rss.integration.service"] == "vault" or
     .["io.rss.integration.service"] == "server")
  ' <<EOF >/dev/null 2>&1
$labels
EOF
}

docker_temp_files() {
  docker_stdout=$(mktemp "$evidence_dir/.integration-services.docker-out.XXXXXX") || die 'cannot create Docker output file'
  docker_stderr=$(mktemp "$evidence_dir/.integration-services.docker-err.XXXXXX") || { rm -f "$docker_stdout"; die 'cannot create Docker error file'; }
}

discover_candidates() {
  docker_temp_files
  if run_docker "$docker_stdout" "$docker_stderr" control ps -aq --filter 'label=io.rss.integration.managed=true' --filter "label=io.rss.integration.scope=$scope"; then
    candidates=$(cat "$docker_stdout")
    rm -f "$docker_stdout" "$docker_stderr"
    return 0
  fi
  discover_reason=$docker_failure_reason
  discover_status=$docker_exit_status
  rm -f "$docker_stdout" "$docker_stderr"
  return 1
}

inspect_labels() {
  id=$1
  docker_temp_files
  if run_docker "$docker_stdout" "$docker_stderr" control inspect --format '{{json .Config.Labels}}' "$id"; then
    inspected_labels=$(cat "$docker_stdout")
    if ! jq -e 'type == "object"' <<EOF >/dev/null 2>&1
$inspected_labels
EOF
    then
      inspect_reason=invalid-output
      inspect_status=null
      rm -f "$docker_stdout" "$docker_stderr"
      return 1
    fi
    rm -f "$docker_stdout" "$docker_stderr"
    return 0
  fi
  inspect_reason=$docker_failure_reason
  inspect_status=$docker_exit_status
  rm -f "$docker_stdout" "$docker_stderr"
  return 1
}

inspect_network_labels() {
  network_id=$1
  docker_temp_files
  if run_docker "$docker_stdout" "$docker_stderr" control network inspect --format '{{json .Labels}}' "$network_id"; then
    inspected_network_labels=$(cat "$docker_stdout")
    if ! jq -e 'type == "object"' <<EOF >/dev/null 2>&1
$inspected_network_labels
EOF
    then
      network_inspect_reason=invalid-output
      network_inspect_status=null
      rm -f "$docker_stdout" "$docker_stderr"
      return 1
    fi
    rm -f "$docker_stdout" "$docker_stderr"
    return 0
  fi
  network_inspect_reason=$docker_failure_reason
  network_inspect_status=$docker_exit_status
  rm -f "$docker_stdout" "$docker_stderr"
  return 1
}

network_labels_match() {
  labels=$1
  jq -e --arg scope "$scope" --arg shard "$shard" --arg partition "$partition" '
    .["io.rss.integration.managed"] == "true" and
    .["io.rss.integration.scope"] == $scope and
    .["io.rss.integration.shard"] == $shard and
    .["io.rss.integration.partition"] == $partition and
    .["io.rss.integration.resource-kind"] == "network" and
    .["io.rss.integration.service"] == "bridge"
  ' <<EOF >/dev/null 2>&1
$labels
EOF
}

collect() {
  validate_evidence
  jq -e '.preparation.status == "success"' "$evidence" >/dev/null 2>&1 || die 'lifecycle preparation did not succeed'
  [ -d "$log_dir" ] && [ ! -L "$log_dir" ] || die 'log directory is not a real directory'
  # Persist the terminal runner outcome before any fallible collection work.
  # shellcheck disable=SC2016 # jq variables are supplied with --arg.
  atomic_jq_update '.collection.outcome = $outcome' --arg outcome "$outcome"
  if [ "$outcome" != failure ]; then
    return 0
  fi
  [ ! -e "$archive" ] && [ ! -L "$archive" ] || die 'archive already exists'

  for dependency in tar gzip find head wc cp sort cat sleep kill mkfifo; do command -v "$dependency" >/dev/null 2>&1 || die "required command unavailable: $dependency"; done
  archive_dir=${archive%/*}
  [ -d "$archive_dir" ] || die 'archive directory does not exist'
  staging=$(mktemp -d "$archive_dir/.integration-services.archive.XXXXXX") || die 'cannot create archive staging directory'
  archive_tmp=$(mktemp "$archive_dir/.integration-services.output.XXXXXX") || die 'cannot create archive temporary file'
  cleanup_collect() { rm -rf "$staging"; rm -f "$archive_tmp"; }
  trap cleanup_collect EXIT HUP INT TERM
  remaining=$ARCHIVE_PAYLOAD_BUDGET_BYTES
  truncated=false
  degraded=false
  sequence=0
  attempted='[]'
  captured_ids='[]'
  errors='[]'
  writer_error_recorded=false

  while IFS= read -r source; do
    [ -f "$source" ] && [ ! -L "$source" ] || continue
    name=${source##*/}
    [[ "$name" =~ ^(postgres|redis|rabbitmq|mosquitto)-[0-9]+-[0-9]+\.log$ ]] || continue
    status_path=${source%.log}.status
    writer_status=
    if [ -f "$status_path" ] && [ ! -L "$status_path" ]; then
      status_size=$(wc -c <"$status_path" 2>/dev/null | awk '{print $1}') || status_size=
      case "$status_size" in
        2|3|12|13) writer_status=$(cat "$status_path" 2>/dev/null || true) ;;
      esac
    fi
    case "$writer_status" in
      ok) ;;
      *)
        degraded=true
        if [ "$writer_error_recorded" = false ]; then
          errors=$(append_error "$errors" '' writer io null)
          writer_error_recorded=true
        fi
        ;;
    esac
    size=$(wc -c <"$source" 2>/dev/null | awk '{print $1}') || size=
    case "$size" in ''|*[!0-9]*) truncated=true; degraded=true; continue ;; esac
    sequence=$((sequence + 1))
    destination="$staging/$sequence-$name"
    if [ "$size" -le "$remaining" ]; then
      cp "$source" "$destination" || { truncated=true; degraded=true; continue; }
      remaining=$((remaining - size))
    elif [ "$remaining" -gt 0 ]; then
      head -c "$remaining" "$source" >"$destination" 2>/dev/null || true
      remaining=0; truncated=true; degraded=true
    else
      truncated=true; degraded=true
    fi
  done <<EOF
$(find "$log_dir" -maxdepth 1 -type f -print 2>/dev/null | sort)
EOF

  if discover_candidates; then
    while IFS= read -r id; do
      [ -n "$id" ] || continue
      case "$id" in *[!A-Za-z0-9_.-]*|[-.]*) continue ;; esac
      if ! inspect_labels "$id"; then
        report_docker_failure inspect "$id" "$inspect_reason" "$inspect_status"
        errors=$(append_error "$errors" "$id" inspect "$inspect_reason" "$inspect_status")
        degraded=true
        continue
      fi
      if ! labels_match "$inspected_labels"; then continue; fi
      service=$(jq -r '.["io.rss.integration.service"]' <<EOF
$inspected_labels
EOF
      )
      attempted=$(jq -c --arg id "$id" '. + [$id]' <<EOF
$attempted
EOF
      )
      sequence=$((sequence + 1))
      if [ "$remaining" -eq 0 ]; then
        truncated=true
        degraded=true
        continue
      fi
      docker_temp_files
      if run_docker "$docker_stdout" "$docker_stderr" logs "$remaining" logs "$id"; then
        if [ "$remaining" -gt 0 ]; then
          size=$(wc -c <"$docker_stdout" | awk '{print $1}')
          destination="$staging/$sequence-$service-$id-docker.log"
          if [ "$size" -le "$remaining" ]; then cp "$docker_stdout" "$destination"; captured=$size
          else head -c "$remaining" "$docker_stdout" >"$destination"; captured=$remaining; truncated=true; degraded=true
          fi
          remaining=$((remaining - captured))
          captured_ids=$(jq -c --arg id "$id" '. + [$id]' <<EOF
$captured_ids
EOF
          )
        else
          truncated=true; degraded=true
        fi
      else
        report_docker_failure logs "$id" "$docker_failure_reason" "$docker_exit_status"
        errors=$(append_error "$errors" "$id" logs "$docker_failure_reason" "$docker_exit_status")
        degraded=true
      fi
      rm -f "$docker_stdout" "$docker_stderr"
    done <<EOF
$candidates
EOF
  else
    report_docker_failure discover '' "$discover_reason" "$discover_status"
    errors=$(append_error "$errors" '' discover "$discover_reason" "$discover_status")
    degraded=true
  fi

  if [ "$truncated" = true ]; then printf 'archive payload truncated at %s bytes\n' "$ARCHIVE_PAYLOAD_BUDGET_BYTES" >"$staging/TRUNCATED.txt"; fi
  tar -czf "$archive_tmp" -C "$staging" . 2>/dev/null || die 'cannot create service log archive'
  archive_size=$(wc -c <"$archive_tmp" | awk '{print $1}')
  [ "$archive_size" -le "$ARCHIVE_LIMIT_BYTES" ] || die 'service log archive exceeds hard limit'
  chmod 600 "$archive_tmp" || die 'cannot protect service log archive'
  mv "$archive_tmp" "$archive" || die 'cannot publish service log archive'
  rm -rf "$staging"
  trap - EXIT HUP INT TERM
  # shellcheck disable=SC2016 # jq variables are supplied with --arg/--argjson.
  atomic_jq_update '.collection = {archiveCreated:true,outcome:$outcome,truncated:$truncated,degraded:$degraded,attemptedContainerIds:$attempted,capturedContainerIds:$captured,errors:$errors}' \
    --arg outcome "$outcome" --argjson truncated "$truncated" --argjson degraded "$degraded" \
    --argjson attempted "$attempted" --argjson captured "$captured_ids" --argjson errors "$errors"
}

cleanup() {
  validate_evidence
  jq -e '.preparation.status == "success"' "$evidence" >/dev/null 2>&1 || die 'lifecycle preparation did not succeed'
  attempted='[]'; removed='[]'; errors='[]'; failed=false
  if ! discover_candidates; then
    report_docker_failure discover '' "$discover_reason" "$discover_status"
    errors=$(append_error "$errors" '' discover "$discover_reason" "$discover_status")
    failed=true; candidates=
  fi

  while IFS= read -r id; do
    [ -n "$id" ] || continue
    case "$id" in *[!A-Za-z0-9_.-]*|[-.]*) continue ;; esac
    if ! inspect_labels "$id"; then
      report_docker_failure inspect "$id" "$inspect_reason" "$inspect_status"
      errors=$(append_error "$errors" "$id" inspect "$inspect_reason" "$inspect_status")
      failed=true
      continue
    fi
    labels_match "$inspected_labels" || continue
    attempted=$(jq -c --arg id "$id" '. + [$id]' <<EOF
$attempted
EOF
    )
    docker_temp_files
    if run_docker "$docker_stdout" "$docker_stderr" control rm -fv "$id"; then
      removed=$(jq -c --arg id "$id" '. + [$id]' <<EOF
$removed
EOF
      )
    else
      report_docker_failure remove "$id" "$docker_failure_reason" "$docker_exit_status"
      errors=$(append_error "$errors" "$id" remove "$docker_failure_reason" "$docker_exit_status")
      failed=true
    fi
    rm -f "$docker_stdout" "$docker_stderr"
  done <<EOF
$candidates
EOF

  # Labeled bridge networks (testkit bridge_network / journey FixtureNetwork) share the same
  # ownership labels with resource-kind=network; remove after containers so endpoints detach first.
  network_attempted='[]'; network_removed='[]'
  docker_temp_files
  if run_docker "$docker_stdout" "$docker_stderr" control network ls -q \
      --filter 'label=io.rss.integration.managed=true' \
      --filter "label=io.rss.integration.scope=$scope" \
      --filter 'label=io.rss.integration.resource-kind=network'; then
    network_candidates=$(cat "$docker_stdout")
    rm -f "$docker_stdout" "$docker_stderr"
    while IFS= read -r nid; do
      [ -n "$nid" ] || continue
      case "$nid" in *[!A-Za-z0-9]* ) continue ;; esac
      if ! inspect_network_labels "$nid"; then
        report_docker_failure network-inspect "$nid" "$network_inspect_reason" "$network_inspect_status"
        errors=$(append_error "$errors" "$nid" network-inspect "$network_inspect_reason" "$network_inspect_status")
        failed=true
        continue
      fi
      network_labels_match "$inspected_network_labels" || continue
      network_attempted=$(jq -c --arg id "$nid" '. + [$id]' <<EOF
$network_attempted
EOF
      )
      docker_temp_files
      if run_docker "$docker_stdout" "$docker_stderr" control network rm -f "$nid"; then
        network_removed=$(jq -c --arg id "$nid" '. + [$id]' <<EOF
$network_removed
EOF
        )
      else
        report_docker_failure network-remove "$nid" "$docker_failure_reason" "$docker_exit_status"
        errors=$(append_error "$errors" "$nid" network-remove "$docker_failure_reason" "$docker_exit_status")
        failed=true
      fi
      rm -f "$docker_stdout" "$docker_stderr"
    done <<EOF
$network_candidates
EOF
  else
    report_docker_failure network-discover '' "$docker_failure_reason" "$docker_exit_status"
    errors=$(append_error "$errors" '' network-discover "$docker_failure_reason" "$docker_exit_status")
    failed=true
    rm -f "$docker_stdout" "$docker_stderr"
  fi

  after=null; after_status=failure
  if measured_after=$(available_bytes "$evidence_dir"); then after=$measured_after; after_status=success
  else printf 'integration-services: post-cleanup disk measurement failed\n' >&2; failed=true
  fi
  # shellcheck disable=SC2016 # jq variables are supplied with --arg/--argjson.
  atomic_jq_update '
      .disk.afterCleanupAvailableBytes = $after |
      .disk.afterCleanupStatus = $afterStatus |
      .cleanup = {attemptedContainerIds:$attempted,removedContainerIds:$removed,attemptedNetworkIds:$network_attempted,removedNetworkIds:$network_removed,errors:$errors} |
      .imageCleanup = "skipped-unprovable-ownership"' \
    --argjson after "$after" --arg afterStatus "$after_status" \
    --argjson attempted "$attempted" --argjson removed "$removed" \
    --argjson network_attempted "$network_attempted" --argjson network_removed "$network_removed" \
    --argjson errors "$errors"
  [ "$failed" = false ]
}

case "$operation" in
  bootstrap) bootstrap ;;
  prepare) prepare ;;
  snapshot) snapshot ;;
  collect) collect ;;
  cleanup) cleanup ;;
esac
