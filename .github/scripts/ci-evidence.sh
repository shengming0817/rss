#!/usr/bin/env bash
set -eu

usage() {
  printf 'usage: %s <snapshot|ensure> <start|after-cache|after-build|before-save|after-save> --output <file> [--outcome <success|failure|cancelled|skipped>] <build/tools cache state options>\n' "$0" >&2
  exit 2
}

die() {
  printf 'ci-evidence: %s\n' "$1" >&2
  exit 1
}

[ "${1:-}" = snapshot ] || [ "${1:-}" = ensure ] || usage
[ "$#" -ge 4 ] || usage
operation=$1
stage=$2
shift 2

case "$stage" in
  start|after-cache|after-build|before-save|after-save) ;;
  *) usage ;;
esac

output=
outcome=
outcome_set=false
build_restore_result=
build_restored_footprint_bytes=
build_save_mode=
build_candidate_size_bytes=
build_save_outcome=
tools_restore_result=
tools_restored_footprint_bytes=
tools_save_mode=
tools_candidate_size_bytes=
tools_save_outcome=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      [ "$#" -ge 2 ] || usage
      output=$2
      shift 2
      ;;
    --outcome)
      [ "$#" -ge 2 ] || usage
      outcome=$2
      outcome_set=true
      shift 2
      ;;
    --build-restore-result) [ "$#" -ge 2 ] || usage; build_restore_result=$2; shift 2 ;;
    --build-restored-footprint-bytes) [ "$#" -ge 2 ] || usage; build_restored_footprint_bytes=$2; shift 2 ;;
    --build-save-mode) [ "$#" -ge 2 ] || usage; build_save_mode=$2; shift 2 ;;
    --build-candidate-size-bytes) [ "$#" -ge 2 ] || usage; build_candidate_size_bytes=$2; shift 2 ;;
    --build-save-outcome) [ "$#" -ge 2 ] || usage; build_save_outcome=$2; shift 2 ;;
    --tools-restore-result) [ "$#" -ge 2 ] || usage; tools_restore_result=$2; shift 2 ;;
    --tools-restored-footprint-bytes) [ "$#" -ge 2 ] || usage; tools_restored_footprint_bytes=$2; shift 2 ;;
    --tools-save-mode) [ "$#" -ge 2 ] || usage; tools_save_mode=$2; shift 2 ;;
    --tools-candidate-size-bytes) [ "$#" -ge 2 ] || usage; tools_candidate_size_bytes=$2; shift 2 ;;
    --tools-save-outcome) [ "$#" -ge 2 ] || usage; tools_save_outcome=$2; shift 2 ;;
    *) usage ;;
  esac
done

[ -n "$output" ] || usage
if [ "$outcome_set" = true ]; then
  [ "$stage" = after-build ] || usage
  case "$outcome" in
    success|failure|cancelled|skipped) ;;
    *) usage ;;
  esac
fi

validate_restore_result() { case "$1" in not-attempted|exact|prefix|miss|unknown) return 0 ;; *) usage ;; esac; }
validate_save_mode() { case "$1" in writer|read-only) return 0 ;; *) usage ;; esac; }
validate_save_outcome() { case "$1" in unknown|ineligible|eligible|skipped|attempted-success|attempted-failure) return 0 ;; *) usage ;; esac; }
validate_bytes() { case "$1" in ''|*[!0-9]*) usage ;; esac; [ "$1" -le 9007199254740991 ] 2>/dev/null || usage; }

validate_restore_result "$build_restore_result"
validate_restore_result "$tools_restore_result"
validate_save_mode "$build_save_mode"
validate_save_mode "$tools_save_mode"
validate_save_outcome "$build_save_outcome"
validate_save_outcome "$tools_save_outcome"
validate_bytes "$build_restored_footprint_bytes"
validate_bytes "$build_candidate_size_bytes"
validate_bytes "$tools_restored_footprint_bytes"
validate_bytes "$tools_candidate_size_bytes"

for dependency in jq mktemp mv date df; do
  command -v "$dependency" >/dev/null 2>&1 || die "required command unavailable: $dependency"
done

workspace=${GITHUB_WORKSPACE:-$(pwd)}
[ -d "$workspace" ] || die 'workspace is not a directory'
output_dir=$(dirname -- "$output")
[ -d "$output_dir" ] || die 'output directory does not exist'
[ ! -d "$output" ] || die 'output path is a directory'

tmp=$(mktemp "$output_dir/.ci-evidence.tmp.XXXXXX" 2>/dev/null) || die 'cannot create output temporary file'
cleanup() { rm -f "$tmp" 2>/dev/null || true; }
trap cleanup EXIT HUP INT TERM

validate_document() {
  jq -e '
    keys == ["job","schemaVersion","snapshots"] and
    .schemaVersion == 2 and
    (.job | type == "object" and keys == ["job","repository","runAttempt","runId","runnerArch","runnerOs","workflow"] and ([.[] | type == "string"] | all)) and
    (.snapshots | type == "array") and
    ([.snapshots[] |
      type == "object" and
      (keys == ["cache","directories","errors","filesystem","largestDirectories","outcome","recordedAt","stage","toolVersions"]) and
      (.stage == "start" or .stage == "after-cache" or .stage == "after-build" or .stage == "before-save" or .stage == "after-save") and
      ((.stage == "after-build" and (.outcome == null or .outcome == "success" or .outcome == "failure" or .outcome == "cancelled" or .outcome == "skipped")) or (.stage != "after-build" and .outcome == null)) and
      (.recordedAt | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
      (.filesystem | type == "object" and keys == ["availableBytes","capacityBytes","usedBytes"] and ([.[] | type == "number" and . >= 0 and floor == .] | all)) and
      (.directories | type == "array" and ([.[].path] == ["workspace","target","cargo-registry","cargo-git","rustup"]) and ([.[] | keys == ["path","sizeBytes"] and (.sizeBytes == null or ((.sizeBytes | type == "number") and .sizeBytes >= 0 and (.sizeBytes | floor) == .sizeBytes))] | all)) and
      (.largestDirectories | type == "array" and length <= 20 and ([.[] | keys == ["path","sizeBytes"] and (.path | type == "string" and ((startswith("workspace/") and (startswith("workspace//") | not)) or (startswith("target/") and (startswith("target//") | not)))) and (.sizeBytes | type == "number") and .sizeBytes >= 0 and (.sizeBytes | floor) == .sizeBytes] | all)) and
      (.cache | type == "object" and keys == ["build","tools"] and ([.[] |
        type == "object" and keys == ["candidateSizeBytes","restoreResult","restoredFootprintBytes","saveMode","saveOutcome"] and
        (.restoreResult == "not-attempted" or .restoreResult == "exact" or .restoreResult == "prefix" or .restoreResult == "miss" or .restoreResult == "unknown") and
        (.restoredFootprintBytes | type == "number" and . >= 0 and floor == .) and
        (.saveMode == "writer" or .saveMode == "read-only") and
        (.candidateSizeBytes | type == "number" and . >= 0 and floor == .) and
        (.saveOutcome == "unknown" or .saveOutcome == "ineligible" or .saveOutcome == "eligible" or .saveOutcome == "skipped" or .saveOutcome == "attempted-success" or .saveOutcome == "attempted-failure")
      ] | all)) and
      (.toolVersions | type == "object" and keys == ["cargo","git","rustc"] and ([.[] | . == null or type == "string"] | all)) and
      (.errors | type == "array" and ([.[] | type == "string"] | all))
    ] | all) and
    ([.snapshots[].stage] == (["start","after-cache","after-build","before-save","after-save"][:(.snapshots | length)]))
  ' "$1" >/dev/null 2>&1
}

if [ -e "$output" ]; then
  [ -f "$output" ] || die 'output path is not a regular file'
  validate_document "$output" || die 'existing evidence is invalid'
  current_stages=$(jq -r '[.snapshots[].stage] | join(",")' "$output" 2>/dev/null) || die 'cannot inspect existing evidence'
else
  current_stages=
fi

if [ "$operation" = ensure ]; then
  current_count=0
  if [ -e "$output" ]; then
    current_count=$(jq -r '.snapshots | length' "$output" 2>/dev/null) || die 'cannot inspect existing evidence'
  fi
  case "$stage" in
    start) target_count=1 ;;
    after-cache) target_count=2 ;;
    after-build) target_count=3 ;;
    before-save) target_count=4 ;;
    after-save) target_count=5 ;;
  esac
  [ "$current_count" -le "$target_count" ] || exit 0
  stages=(start after-cache after-build before-save after-save)
  while [ "$current_count" -lt "$target_count" ]; do
    missing_stage=${stages[$current_count]}
    snapshot_args=(
      snapshot "$missing_stage" --output "$output"
      --build-restore-result "$build_restore_result"
      --build-restored-footprint-bytes "$build_restored_footprint_bytes"
      --build-save-mode "$build_save_mode"
      --build-candidate-size-bytes "$build_candidate_size_bytes"
      --build-save-outcome "$build_save_outcome"
      --tools-restore-result "$tools_restore_result"
      --tools-restored-footprint-bytes "$tools_restored_footprint_bytes"
      --tools-save-mode "$tools_save_mode"
      --tools-candidate-size-bytes "$tools_candidate_size_bytes"
      --tools-save-outcome "$tools_save_outcome"
    )
    if [ "$missing_stage" = after-build ]; then
      snapshot_args+=(--outcome "${outcome:-skipped}")
    fi
    "$0" "${snapshot_args[@]}"
    current_count=$((current_count + 1))
  done
  exit 0
fi

case "$stage:$current_stages" in
  start:|after-cache:start|after-build:start,after-cache|before-save:start,after-cache,after-build|after-save:start,after-cache,after-build,before-save) ;;
  *) die "stage is duplicate or out of order: $stage" ;;
esac

df_output=$(df -Pk "$workspace" 2>/dev/null) || die 'cannot measure workspace filesystem'
df_line=${df_output##*
}
capacity_kib=
used_kib=
available_kib=
read -r _ capacity_kib used_kib available_kib _ <<EOF || true
$df_line
EOF
case "$capacity_kib:$used_kib:$available_kib" in
  *[!0-9:]*|*::*|:*|*:) die 'unexpected df values' ;;
esac
capacity_bytes=$((capacity_kib * 1024))
used_bytes=$((used_kib * 1024))
available_bytes=$((available_kib * 1024))

errors='[]'
directories='[]'
append_error() {
  errors=$(jq -c --arg value "$1" '. + [$value]' <<EOF
$errors
EOF
  ) || die 'cannot construct collection error'
}

append_directory() {
  logical_path=$1
  physical_path=$2
  if [ ! -e "$physical_path" ] && [ ! -L "$physical_path" ]; then
    size_json=0
  elif [ -L "$physical_path" ] || [ ! -d "$physical_path" ]; then
    append_error "directory unavailable: $logical_path"
    size_json=null
  elif ! command -v du >/dev/null 2>&1; then
    append_error "du unavailable: $logical_path"
    size_json=null
  else
    du_output=$(du -sk "$physical_path" 2>/dev/null) || du_output=
    size_kib=${du_output%%[!0-9]*}
    if [ -z "$size_kib" ]; then
      append_error "directory measurement failed: $logical_path"
      size_json=null
    else
      size_json=$((size_kib * 1024))
    fi
  fi
  directories=$(jq -c --arg path "$logical_path" --argjson size "$size_json" '. + [{path:$path,sizeBytes:$size}]' <<EOF
$directories
EOF
  ) || die 'cannot construct directory evidence'
}

cargo_home=${CARGO_HOME:-${HOME:-}/.cargo}
rustup_home=${RUSTUP_HOME:-${HOME:-}/.rustup}
target_dir=${CARGO_TARGET_DIR:-$workspace/.cache/cargo-target}
append_directory workspace "$workspace"
append_directory target "$target_dir"
append_directory cargo-registry "$cargo_home/registry"
append_directory cargo-git "$cargo_home/git"
append_directory rustup "$rustup_home"

largest='[]'
if ! command -v du >/dev/null 2>&1; then
  append_error 'largest directory scan unavailable: du'
elif ! command -v find >/dev/null 2>&1; then
  append_error 'largest directory scan unavailable: find'
else
  append_largest_candidate() {
    physical_dir=$1
    logical_path=$2
    du_output=$(du -sk "$physical_dir" 2>/dev/null) || du_output=
    size_kib=${du_output%%[!0-9]*}
    if [ -n "$size_kib" ]; then
      size_bytes=$((size_kib * 1024))
      largest=$(jq -c --arg path "$logical_path" --argjson size "$size_bytes" '. + [{path:$path,sizeBytes:$size}]' <<EOF
$largest
EOF
      ) || die 'cannot construct largest-directory evidence'
    fi
  }

  while IFS= read -r -d '' physical_dir; do
    relative=${physical_dir#"$workspace"/}
    case "$relative" in
      .git) continue ;;
    esac
    case "$target_dir/" in
      "$physical_dir"/*) continue ;;
    esac
    append_largest_candidate "$physical_dir" "workspace/$relative"
  done < <(find -P "$workspace" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)

  if [ -d "$target_dir" ] && [ ! -L "$target_dir" ]; then
    while IFS= read -r -d '' physical_dir; do
      relative=${physical_dir#"$target_dir"/}
      append_largest_candidate "$physical_dir" "target/$relative"
    done < <(find -P "$target_dir" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)
  fi
  largest=$(jq -c 'sort_by([-.sizeBytes, .path])[:20]' <<EOF
$largest
EOF
  ) || die 'cannot rank largest directories'
fi

tool_version() {
  tool_name=$1
  if ! command -v "$tool_name" >/dev/null 2>&1; then
    printf 'null\n'
    return
  fi
  version_output=$($tool_name --version 2>/dev/null) || version_output=
  version_first=${version_output%%
*}
  if [ -n "$version_first" ]; then
    jq -Rn --arg value "$version_first" '$value'
  else
    printf 'null\n'
  fi
}

rustc_version=$(tool_version rustc)
cargo_version=$(tool_version cargo)
git_version=$(tool_version git)
recorded_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ') || die 'cannot read UTC clock'

if [ "$outcome_set" = true ]; then
  outcome_json=$(jq -Rn --arg value "$outcome" '$value')
else
  outcome_json=null
fi

snapshot=$(jq -cn \
  --arg stage "$stage" \
  --arg recordedAt "$recorded_at" \
  --argjson outcome "$outcome_json" \
  --argjson capacity "$capacity_bytes" \
  --argjson used "$used_bytes" \
  --argjson available "$available_bytes" \
  --argjson directories "$directories" \
  --argjson largest "$largest" \
  --argjson rustc "$rustc_version" \
  --argjson cargo "$cargo_version" \
  --argjson git "$git_version" \
  --argjson errors "$errors" \
  --arg buildRestoreResult "$build_restore_result" \
  --argjson buildRestoredFootprintBytes "$build_restored_footprint_bytes" \
  --arg buildSaveMode "$build_save_mode" \
  --argjson buildCandidateSizeBytes "$build_candidate_size_bytes" \
  --arg buildSaveOutcome "$build_save_outcome" \
  --arg toolsRestoreResult "$tools_restore_result" \
  --argjson toolsRestoredFootprintBytes "$tools_restored_footprint_bytes" \
  --arg toolsSaveMode "$tools_save_mode" \
  --argjson toolsCandidateSizeBytes "$tools_candidate_size_bytes" \
  --arg toolsSaveOutcome "$tools_save_outcome" \
  '{stage:$stage,outcome:$outcome,recordedAt:$recordedAt,filesystem:{capacityBytes:$capacity,usedBytes:$used,availableBytes:$available},directories:$directories,largestDirectories:$largest,cache:{build:{restoreResult:$buildRestoreResult,restoredFootprintBytes:$buildRestoredFootprintBytes,saveMode:$buildSaveMode,candidateSizeBytes:$buildCandidateSizeBytes,saveOutcome:$buildSaveOutcome},tools:{restoreResult:$toolsRestoreResult,restoredFootprintBytes:$toolsRestoredFootprintBytes,saveMode:$toolsSaveMode,candidateSizeBytes:$toolsCandidateSizeBytes,saveOutcome:$toolsSaveOutcome}},toolVersions:{rustc:$rustc,cargo:$cargo,git:$git},errors:$errors}') || die 'cannot construct snapshot'

if [ -e "$output" ]; then
  jq --argjson snapshot "$snapshot" '.snapshots += [$snapshot]' "$output" 2>/dev/null >"$tmp" || die 'cannot append snapshot'
else
  jq -n \
    --arg repository "${GITHUB_REPOSITORY:-}" \
    --arg workflow "${GITHUB_WORKFLOW:-}" \
    --arg job "${GITHUB_JOB:-}" \
    --arg runId "${GITHUB_RUN_ID:-}" \
    --arg runAttempt "${GITHUB_RUN_ATTEMPT:-}" \
    --arg runnerOs "${RUNNER_OS:-}" \
    --arg runnerArch "${RUNNER_ARCH:-}" \
    --argjson snapshot "$snapshot" \
    '{schemaVersion:2,job:{repository:$repository,workflow:$workflow,job:$job,runId:$runId,runAttempt:$runAttempt,runnerOs:$runnerOs,runnerArch:$runnerArch},snapshots:[$snapshot]}' 2>/dev/null >"$tmp" || die 'cannot construct evidence document'
fi

validate_document "$tmp" || die 'constructed evidence failed validation'
mv "$tmp" "$output" 2>/dev/null || die 'cannot commit evidence atomically'
trap - EXIT HUP INT TERM
