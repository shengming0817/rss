#!/usr/bin/env bash
set -eu
set -f

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

usage() {
  printf '%s\n' \
    "usage: $0 measure --path <path>" \
    "       $0 prepare-roots --workspace <path> --tool-root <path> --runner-temp <path> --fallback-target <path>" \
    "       $0 reset-descendant --parent <path> --path <path>" \
    "       $0 snapshot --parent <path> --path <path> --max-bytes <positive-integer>" \
    "       $0 derive-keys --os <id> --arch <id> --toolchain <semver> --nightly <nightly-date|empty> --lane <lane> --profile <profile> --compiler-partition <partition> --download-cache-epoch <vN> --tool-cache-epoch <vN> --compiler-cache-epoch <vN> --sccache-version <semver> --input-hash <sha256> --tools-hash <sha256> --run-id <integer> --run-attempt <positive-integer>" \
    "       $0 finalize-policy --context <absolute-json> --execution-outcome <success|failure|cancelled|skipped> --save-eligible <true|false>" >&2
  exit 2
}

set_once() {
  [ "$1" = false ] || usage
}

valid_identity() {
  [[ "$1" =~ ^[A-Za-z0-9]+([._-][A-Za-z0-9]+)*$ ]]
}

valid_semver() {
  [[ "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

valid_epoch() {
  [[ "$1" =~ ^v[1-9][0-9]*$ ]]
}

valid_hash() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

die() {
  printf 'ci-cache-maintain: %s\n' "$1" >&2
  exit 1
}

canonical_directory() {
  [ -d "$1" ] && [ ! -L "$1" ] || return 1
  (CDPATH='' cd -- "$1" 2>/dev/null && pwd -P)
}

validate_normalized_absolute() {
  case "$1" in /*) ;; *) return 1 ;; esac
  case "$1" in *//*|*/./*|*/.|*/../*|*/..) return 1 ;; esac
}

validate_descendant_path() {
  parent=$1
  child=$2
  validate_normalized_absolute "$parent" || return 1
  validate_normalized_absolute "$child" || return 1
  parent_physical=$(canonical_directory "$parent") || return 1
  case "$child/" in "$parent"/*) ;; *) return 1 ;; esac

  relative_child=${child#"$parent"/}
  current=$parent
  old_ifs=$IFS
  IFS=/
  for component in $relative_child; do
    IFS=$old_ifs
    [ -n "$component" ] && [ "$component" != . ] && [ "$component" != .. ] || return 1
    current=$current/$component
    [ ! -L "$current" ] || return 1
    if [ -e "$current" ] && [ ! -d "$current" ]; then return 1; fi
    IFS=/
  done
  IFS=$old_ifs
  printf '%s\n' "$parent_physical"
}

validate_reset_target() {
  parent=$1
  path=$2
  validate_normalized_absolute "$parent" || return 1
  validate_normalized_absolute "$path" || return 1
  [ "$path" != "$parent" ] || return 1
  case "$path/" in "$parent"/*) ;; *) return 1 ;; esac
  parent_physical=$(canonical_directory "$parent") || return 1
  ancestor=${path%/*}
  if [ "$ancestor" = "$parent" ]; then
    ancestor_physical=$parent_physical
  else
    validate_descendant_path "$parent" "$ancestor" >/dev/null || return 1
    ancestor_physical=$(canonical_directory "$ancestor") || return 1
  fi
  case "$ancestor_physical/" in "$parent_physical"/*|"$parent_physical"/) ;; *) return 1 ;; esac
  printf '%s\n' "$parent_physical"
}

prepare_roots() {
  workspace=
  tool_root=
  runner_temp=
  fallback_target=
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --workspace) [ "$#" -ge 2 ] || usage; workspace=$2; shift 2 ;;
      --tool-root) [ "$#" -ge 2 ] || usage; tool_root=$2; shift 2 ;;
      --runner-temp) [ "$#" -ge 2 ] || usage; runner_temp=$2; shift 2 ;;
      --fallback-target) [ "$#" -ge 2 ] || usage; fallback_target=$2; shift 2 ;;
      *) usage ;;
    esac
  done
  [ -n "$workspace" ] && [ -n "$tool_root" ] && [ -n "$runner_temp" ] && [ -n "$fallback_target" ] || usage
  workspace_physical=$(validate_descendant_path "$workspace" "$tool_root") || die 'tool root is not a safe workspace descendant'
  runner_temp_physical=$(validate_descendant_path "$runner_temp" "$fallback_target") || die 'fallback target is not a safe runner temp descendant'
  command -v mkdir >/dev/null 2>&1 || die 'required command unavailable: mkdir'
  mkdir -p -- "$tool_root" "$fallback_target" || die 'cannot create cache roots'
  validate_descendant_path "$workspace" "$tool_root" >/dev/null || die 'created tool root is unsafe'
  validate_descendant_path "$runner_temp" "$fallback_target" >/dev/null || die 'created fallback target is unsafe'
  tool_physical=$(canonical_directory "$tool_root") || die 'created tool root is unsafe'
  fallback_physical=$(canonical_directory "$fallback_target") || die 'created fallback target is unsafe'
  case "$tool_physical/" in "$workspace_physical"/*) ;; *) die 'tool root escaped workspace' ;; esac
  case "$fallback_physical/" in "$runner_temp_physical"/*) ;; *) die 'fallback target escaped runner temp' ;; esac
  case "$tool_physical/" in "$fallback_physical"/*) die 'tool root overlaps fallback target' ;; esac
  case "$fallback_physical/" in "$tool_physical"/*) die 'fallback target overlaps tool root' ;; esac
}

reset_descendant() {
  parent=
  path=
  parent_set=false
  path_set=false
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --parent) [ "$#" -ge 2 ] || usage; set_once "$parent_set"; parent=$2; parent_set=true; shift 2 ;;
      --path) [ "$#" -ge 2 ] || usage; set_once "$path_set"; path=$2; path_set=true; shift 2 ;;
      *) usage ;;
    esac
  done
  [ "$parent_set" = true ] && [ "$path_set" = true ] || usage
  [ "$path" != "$parent" ] || die 'cache root must be a strict descendant'
  parent_physical=$(validate_reset_target "$parent" "$path") || die 'cache root is not a safe descendant'
  command -v rm >/dev/null 2>&1 || die 'required command unavailable: rm'
  command -v mkdir >/dev/null 2>&1 || die 'required command unavailable: mkdir'
  rm -rf -- "$path" || die 'cannot reset cache root'
  mkdir -p -- "$path" || die 'cannot recreate cache root'
  validate_descendant_path "$parent" "$path" >/dev/null || die 'recreated cache root is unsafe'
  path_physical=$(canonical_directory "$path") || die 'recreated cache root is unsafe'
  case "$path_physical/" in "$parent_physical"/*) ;; *) die 'recreated cache root escaped parent' ;; esac
}

snapshot() {
  parent=
  path=
  max_bytes=
  parent_set=false
  path_set=false
  max_set=false
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --parent) [ "$#" -ge 2 ] || usage; set_once "$parent_set"; parent=$2; parent_set=true; shift 2 ;;
      --path) [ "$#" -ge 2 ] || usage; set_once "$path_set"; path=$2; path_set=true; shift 2 ;;
      --max-bytes) [ "$#" -ge 2 ] || usage; set_once "$max_set"; max_bytes=$2; max_set=true; shift 2 ;;
      *) usage ;;
    esac
  done
  [ "$parent_set" = true ] && [ "$path_set" = true ] && [ "$max_set" = true ] || usage
  [[ "$max_bytes" =~ ^[1-9][0-9]*$ ]] || usage
  [ "$path" != "$parent" ] || die 'cache root must be a strict descendant'
  parent_physical=$(validate_descendant_path "$parent" "$path") || die 'cache root is not a safe descendant'
  path_physical=$(canonical_directory "$path") || die 'cache root is not a safe directory'
  case "$path_physical/" in "$parent_physical"/*) ;; *) die 'cache root escaped parent' ;; esac
  command -v find >/dev/null 2>&1 || die 'required command unavailable: find'
  [ -n "$(find "$path" -mindepth 1 -print -quit 2>/dev/null)" ] || die 'cache root is empty'
  bytes=$(measure --path "$path") || die 'cannot measure cache snapshot'
  [ "$bytes" -gt 0 ] || die 'cache root is empty'
  [ "$bytes" -le "$max_bytes" ] || die 'cache root exceeds snapshot budget'
  printf '%s\n' "$bytes"
}

derive_keys() {
  os=''
  arch=''
  toolchain=''
  nightly=''
  lane=''
  profile=''
  compiler_partition=''
  download_epoch=''
  tool_epoch=''
  compiler_epoch=''
  sccache_version=''
  input_hash=''
  tools_hash=''
  run_id=''
  run_attempt=''
  os_set=false arch_set=false toolchain_set=false nightly_set=false lane_set=false profile_set=false compiler_partition_set=false
  download_epoch_set=false tool_epoch_set=false compiler_epoch_set=false sccache_version_set=false
  input_hash_set=false tools_hash_set=false run_id_set=false run_attempt_set=false
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --os) [ "$#" -ge 2 ] || usage; set_once "$os_set"; os=$2; os_set=true; shift 2 ;;
      --arch) [ "$#" -ge 2 ] || usage; set_once "$arch_set"; arch=$2; arch_set=true; shift 2 ;;
      --toolchain) [ "$#" -ge 2 ] || usage; set_once "$toolchain_set"; toolchain=$2; toolchain_set=true; shift 2 ;;
      --nightly) [ "$#" -ge 2 ] || usage; set_once "$nightly_set"; nightly=$2; nightly_set=true; shift 2 ;;
      --lane) [ "$#" -ge 2 ] || usage; set_once "$lane_set"; lane=$2; lane_set=true; shift 2 ;;
      --profile) [ "$#" -ge 2 ] || usage; set_once "$profile_set"; profile=$2; profile_set=true; shift 2 ;;
      --compiler-partition) [ "$#" -ge 2 ] || usage; set_once "$compiler_partition_set"; compiler_partition=$2; compiler_partition_set=true; shift 2 ;;
      --download-cache-epoch) [ "$#" -ge 2 ] || usage; set_once "$download_epoch_set"; download_epoch=$2; download_epoch_set=true; shift 2 ;;
      --tool-cache-epoch) [ "$#" -ge 2 ] || usage; set_once "$tool_epoch_set"; tool_epoch=$2; tool_epoch_set=true; shift 2 ;;
      --compiler-cache-epoch) [ "$#" -ge 2 ] || usage; set_once "$compiler_epoch_set"; compiler_epoch=$2; compiler_epoch_set=true; shift 2 ;;
      --sccache-version) [ "$#" -ge 2 ] || usage; set_once "$sccache_version_set"; sccache_version=$2; sccache_version_set=true; shift 2 ;;
      --input-hash) [ "$#" -ge 2 ] || usage; set_once "$input_hash_set"; input_hash=$2; input_hash_set=true; shift 2 ;;
      --tools-hash) [ "$#" -ge 2 ] || usage; set_once "$tools_hash_set"; tools_hash=$2; tools_hash_set=true; shift 2 ;;
      --run-id) [ "$#" -ge 2 ] || usage; set_once "$run_id_set"; run_id=$2; run_id_set=true; shift 2 ;;
      --run-attempt) [ "$#" -ge 2 ] || usage; set_once "$run_attempt_set"; run_attempt=$2; run_attempt_set=true; shift 2 ;;
      *) usage ;;
    esac
  done
  for present in "$os_set" "$arch_set" "$toolchain_set" "$nightly_set" "$lane_set" "$profile_set" "$compiler_partition_set" "$download_epoch_set" "$tool_epoch_set" "$compiler_epoch_set" "$sccache_version_set" "$input_hash_set" "$tools_hash_set" "$run_id_set" "$run_attempt_set"; do
    [ "$present" = true ] || usage
  done
  if ! valid_identity "$os" || ! valid_identity "$arch"; then die 'invalid runner identity'; fi
  if ! valid_semver "$toolchain" || ! valid_semver "$sccache_version"; then die 'invalid tool version'; fi
  [[ -z "$nightly" || "$nightly" =~ ^nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die 'invalid nightly identity'
  case "$lane" in preflight|check|test-affected|integration-critical|audit) ;; *) die 'invalid lane' ;; esac
  [ "$profile" = "$lane" ] || die 'profile must match lane'
  case "$lane:$compiler_partition" in
    preflight:preflight|check:check|test-affected:test-affected|audit:audit|integration-critical:postgres|integration-critical:transport|integration-critical:runtime) ;;
    *) die 'invalid compiler partition for lane' ;;
  esac
  if ! valid_epoch "$download_epoch" || ! valid_epoch "$tool_epoch" || ! valid_epoch "$compiler_epoch"; then die 'invalid cache epoch'; fi
  if ! valid_hash "$input_hash" || ! valid_hash "$tools_hash"; then die 'invalid cache digest'; fi
  [[ "$run_id" =~ ^[0-9]+$ ]] && [[ "$run_attempt" =~ ^[1-9][0-9]*$ ]] || die 'invalid run identity'
  nightly_id=${nightly:-none}
  download_base="rss-download-$download_epoch-$os-$arch-$toolchain-$nightly_id-$lane"
  tools_base="rss-tools-$tool_epoch-$os-$arch-$toolchain-$nightly_id-$profile"
  compiler_base="rss-sccache-$compiler_epoch-$os-$arch-$toolchain-$nightly_id-$sccache_version-$lane-$compiler_partition"
  printf '%s\n' \
    "download-primary-key=$download_base-$input_hash-$compiler_partition-$run_id-$run_attempt" \
    "download-input-restore-prefix=$download_base-$input_hash-" \
    "download-restore-prefix=$download_base-" \
    "tools-primary-key=$tools_base-$tools_hash" \
    "compiler-primary-key=$compiler_base-$input_hash-$run_id-$run_attempt" \
    "compiler-input-restore-prefix=$compiler_base-$input_hash-" \
    "compiler-broad-restore-prefix=$compiler_base-"
}

finalize_policy() {
  context=''
  execution_outcome=''
  save_eligible=''
  context_set=false
  outcome_set=false
  eligible_set=false
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --context) [ "$#" -ge 2 ] || usage; set_once "$context_set"; context=$2; context_set=true; shift 2 ;;
      --execution-outcome) [ "$#" -ge 2 ] || usage; set_once "$outcome_set"; execution_outcome=$2; outcome_set=true; shift 2 ;;
      --save-eligible) [ "$#" -ge 2 ] || usage; set_once "$eligible_set"; save_eligible=$2; eligible_set=true; shift 2 ;;
      *) usage ;;
    esac
  done
  [ "$context_set" = true ] && [ "$outcome_set" = true ] && [ "$eligible_set" = true ] || usage
  validate_normalized_absolute "$context" || usage
  [ -f "$context" ] && [ ! -L "$context" ] || die 'cache context must be a regular, non-symlink file'
  case "$execution_outcome" in success|failure) expected_eligible=true ;; cancelled|skipped) expected_eligible=false ;; *) usage ;; esac
  case "$save_eligible" in true|false) ;; *) usage ;; esac
  [ "$save_eligible" = "$expected_eligible" ] || die 'execution outcome and save eligibility disagree'
  command -v jq >/dev/null 2>&1 || die 'required command unavailable: jq'
  jq -e '
    type == "object"
    and (keys | sort) == ["compiler","download","lane","partition","schema"]
    and .schema == "rss-ci-cache-context-v2"
    and (.lane | type == "string" and test("^(preflight|check|test-affected|integration-critical|audit)$"))
    and (.partition | type == "string" and test("^(preflight|check|test-affected|postgres|transport|runtime|audit)$"))
    and ((.lane == "integration-critical" and (.partition | test("^(postgres|transport|runtime)$"))) or (.lane != "integration-critical" and .lane == .partition))
    and (.download |
      type == "object"
      and (keys | sort) == ["enabled","hit","matched","primary","restore_outcome"]
      and (.primary | type == "string" and test("^rss-download-[A-Za-z0-9._-]+$"))
      and (.matched | type == "string" and test("^(rss-download-[A-Za-z0-9._-]+)?$"))
      and (.hit | type == "string" and test("^(true|false)?$"))
      and (.restore_outcome | type == "string" and test("^(success|failure|cancelled|skipped)$"))
      and (.enabled | type == "string" and test("^(true|false)$"))
    )
    and (.compiler |
      type == "object"
      and (keys | sort) == ["enabled","hit","matched","primary","restore_outcome"]
      and (.primary | type == "string" and test("^rss-sccache-[A-Za-z0-9._-]+$"))
      and (.matched | type == "string" and test("^(rss-sccache-[A-Za-z0-9._-]+)?$"))
      and (.hit | type == "string" and test("^(true|false)?$"))
      and (.restore_outcome | type == "string" and test("^(success|failure|cancelled|skipped)$"))
      and (.enabled | type == "string" and test("^(true|false)$"))
    )
  ' "$context" >/dev/null || die 'invalid cache lifecycle context'
  download_primary=$(jq -r '.download.primary' "$context")
  compiler_primary=$(jq -r '.compiler.primary' "$context")
  download_enabled=$(jq -r '.download.enabled' "$context")
  sccache_enabled=$(jq -r '.compiler.enabled' "$context")
  download_class=$("$SCRIPT_DIR/ci-cache-result.sh" classify \
    --outcome "$(jq -r '.download.restore_outcome' "$context")" \
    --primary "$download_primary" \
    --hit "$(jq -r '.download.hit' "$context")" \
    --matched "$(jq -r '.download.matched' "$context")") || die 'invalid download restore result'
  compiler_class=$("$SCRIPT_DIR/ci-cache-result.sh" classify \
    --outcome "$(jq -r '.compiler.restore_outcome' "$context")" \
    --primary "$compiler_primary" \
    --hit "$(jq -r '.compiler.hit' "$context")" \
    --matched "$(jq -r '.compiler.matched' "$context")") || die 'invalid compiler restore result'
  save_cache=false
  save_download=false
  if [ "$save_eligible" = true ]; then
    if [ "$sccache_enabled" = true ]; then save_cache=true; fi
    if [ "$download_enabled" = true ] && [ "$download_class" != exact ]; then save_download=true; fi
  fi
  printf '%s\n' \
    "download-primary-key=$download_primary" \
    "compiler-primary-key=$compiler_primary" \
    "download-restore-class=$download_class" \
    "compiler-restore-class=$compiler_class" \
    "sccache-enabled=$sccache_enabled" \
    "save-cache=$save_cache" \
    "save-download=$save_download"
}

measure() {
  path=
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --path) [ "$#" -ge 2 ] || usage; path=$2; shift 2 ;;
      *) usage ;;
    esac
  done
  [ -n "$path" ] || usage
  if [ ! -e "$path" ]; then
    printf '0\n'
    return
  fi
  canonical_directory "$path" >/dev/null || die 'cache root is not a safe directory'
  command -v du >/dev/null 2>&1 || die 'required command unavailable: du'
  measured=$(du -sk "$path" 2>/dev/null) || die 'cannot measure cache root'
  kib=${measured%%[!0-9]*}
  [ -n "$kib" ] || die 'invalid cache measurement'
  printf '%s\n' "$((kib * 1024))"
}

[ "$#" -gt 0 ] || usage
command_name=$1
shift
case "$command_name" in
  derive-keys) derive_keys "$@" ;;
  finalize-policy) finalize_policy "$@" ;;
  measure) measure "$@" ;;
  prepare-roots) prepare_roots "$@" ;;
  reset-descendant) reset_descendant "$@" ;;
  snapshot) snapshot "$@" ;;
  *) usage ;;
esac
