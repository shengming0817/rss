#!/usr/bin/env bash
set -eu
set -f
temporary_file=
diagnostic_output=
diagnostic_error=
cleanup_temporary_file() {
  [ -z "$temporary_file" ] || rm -f -- "$temporary_file" 2>/dev/null || true
  [ -z "$diagnostic_output" ] || rm -f -- "$diagnostic_output" 2>/dev/null || true
  [ -z "$diagnostic_error" ] || rm -f -- "$diagnostic_error" 2>/dev/null || true
}
trap cleanup_temporary_file EXIT HUP INT TERM

usage() {
  printf '%s\n' \
    "usage: $0 cleanup --workspace <path> --target <path>" \
    "       $0 measure --path <path>" \
    "       $0 tree-identity --workspace <path>" \
    "       $0 prepare-roots --workspace <path> --tool-root <path> --runner-temp <path> --fallback-target <path>" >&2
  exit 2
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

validate_diagnostic_context() {
  stage=$1
  subject=$2
  case "$stage" in
    metadata) [ "$subject" = workspace ] ;;
    clean) [[ "$subject" =~ ^[A-Za-z0-9]+([_-][A-Za-z0-9]+)*$ ]] ;;
    git-tree) [ "$subject" = repository ] ;;
    metadata-parse) case "$subject" in workspace-root|target-directory|packages) return 0 ;; *) return 1 ;; esac ;;
    *) return 1 ;;
  esac
}

run_diagnostic() {
  stage=$1
  subject=$2
  shift 2
  validate_diagnostic_context "$stage" "$subject" || die 'invalid diagnostic context'
  command -v mktemp >/dev/null 2>&1 || die 'required command unavailable: mktemp'
  command -v chmod >/dev/null 2>&1 || die 'required command unavailable: chmod'
  diagnostic_output=$(umask 077 && mktemp "${TMPDIR:-/tmp}/ci-cache-diagnostic-output.XXXXXX" 2>/dev/null) || die 'cannot create diagnostic output'
  diagnostic_error=$(umask 077 && mktemp "${TMPDIR:-/tmp}/ci-cache-diagnostic-error.XXXXXX" 2>/dev/null) || die 'cannot create diagnostic output'
  chmod 600 "$diagnostic_output" "$diagnostic_error" 2>/dev/null || die 'cannot secure diagnostic output'
  if "$@" >"$diagnostic_output" 2>"$diagnostic_error"; then
    rm -f -- "$diagnostic_error" 2>/dev/null || die 'cannot remove diagnostic output'
    diagnostic_error=
    return 0
  else
    status=$?
  fi
  classification=command-failed
  if command -v grep >/dev/null 2>&1; then
    if grep -Eqi 'permission denied|operation not permitted|access is denied' "$diagnostic_error" 2>/dev/null; then
      classification=permission-denied
    elif grep -Eqi 'no such file|not found|command not found' "$diagnostic_error" 2>/dev/null; then
      classification=not-found
    elif grep -Eqi 'parse error|failed to parse|invalid (manifest|json|toml)|syntax error|expected .+ at line' "$diagnostic_error" 2>/dev/null; then
      classification=parse-invalid
    elif grep -Eqi 'could not resolve|unable to resolve|connection refused|network (is )?unavailable|timed out|temporary failure in name resolution' "$diagnostic_error" 2>/dev/null; then
      classification=unavailable
    fi
  fi
  rm -f -- "$diagnostic_output" "$diagnostic_error" 2>/dev/null || true
  diagnostic_output=
  diagnostic_error=
  printf 'ci-cache-maintain: command failed stage=%s subject=%s exit=%s class=%s\n' "$stage" "$subject" "$status" "$classification" >&2
  return 1
}

consume_diagnostic_output() {
  command -v cat >/dev/null 2>&1 || die 'required command unavailable: cat'
  cat -- "$diagnostic_output" 2>/dev/null || die 'cannot read diagnostic output'
  rm -f -- "$diagnostic_output" 2>/dev/null || die 'cannot remove diagnostic output'
  diagnostic_output=
}

tree_identity() {
  workspace=
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --workspace) [ "$#" -ge 2 ] || usage; workspace=$2; shift 2 ;;
      *) usage ;;
    esac
  done
  [ -n "$workspace" ] || usage
  workspace_physical=$(canonical_directory "$workspace") || die 'workspace is not a safe directory'
  command -v git >/dev/null 2>&1 || die 'required command unavailable: git'
  run_diagnostic git-tree repository git -C "$workspace_physical" rev-parse --verify 'HEAD^{tree}' || exit 1
  identity=$(consume_diagnostic_output) || die 'cannot consume git tree identity'
  [[ "$identity" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || die 'git tree identity is invalid'
  printf '%s\n' "$identity"
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

cleanup_cache() {
  workspace=
  target=
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --workspace) [ "$#" -ge 2 ] || usage; workspace=$2; shift 2 ;;
      --target) [ "$#" -ge 2 ] || usage; target=$2; shift 2 ;;
      *) usage ;;
    esac
  done
  [ -n "$workspace" ] && [ -n "$target" ] || usage
  workspace_physical=$(canonical_directory "$workspace") || die 'workspace is not a safe directory'
  target_physical=$(canonical_directory "$target") || die 'target is not a safe directory'
  case "$target/" in "$workspace"/*) ;; *) die 'target must be lexically contained by workspace' ;; esac
  relative_target=${target#"$workspace"/}
  current=$workspace
  old_ifs=$IFS
  IFS=/
  for component in $relative_target; do
    IFS=$old_ifs
    [ -n "$component" ] && [ "$component" != . ] && [ "$component" != .. ] || die 'target path is not normalized'
    current=$current/$component
    [ ! -L "$current" ] || die 'target path contains a symlink'
    IFS=/
  done
  IFS=$old_ifs
  case "$target_physical/" in "$workspace_physical"/*) ;; *) die 'target must be contained by workspace' ;; esac
  command -v cargo >/dev/null 2>&1 || die 'required command unavailable: cargo'
  command -v jq >/dev/null 2>&1 || die 'required command unavailable: jq'
  command -v find >/dev/null 2>&1 || die 'required command unavailable: find'

  run_diagnostic metadata workspace cargo metadata --format-version 1 --no-deps --manifest-path "$workspace_physical/Cargo.toml" || exit 1
  metadata=$(consume_diagnostic_output) || die 'cannot consume cargo metadata'
  if ! run_diagnostic metadata-parse workspace-root jq -er '.workspace_root | select(type == "string")' <<EOF
$metadata
EOF
  then exit 1
  fi
  metadata_workspace=$(consume_diagnostic_output) || die 'cargo metadata workspace is invalid'
  if ! run_diagnostic metadata-parse target-directory jq -er '.target_directory | select(type == "string")' <<EOF
$metadata
EOF
  then exit 1
  fi
  metadata_target=$(consume_diagnostic_output) || die 'cargo metadata target is invalid'
  metadata_workspace_physical=$(canonical_directory "$metadata_workspace") || die 'cargo metadata workspace is unsafe'
  metadata_target_physical=$(canonical_directory "$metadata_target") || die 'cargo metadata target is unsafe'
  [ "$metadata_workspace_physical" = "$workspace_physical" ] || die 'cargo metadata workspace mismatch'
  [ "$metadata_target_physical" = "$target_physical" ] || die 'cargo metadata target mismatch'
  # jq variables are intentionally protected from shell expansion.
  # shellcheck disable=SC2016
  if ! run_diagnostic metadata-parse packages jq -er '.workspace_members as $members | [.packages[] | select(.id as $id | $members | index($id)) | .name] | unique | if length > 0 then .[] else error("empty workspace") end' <<EOF
$metadata
EOF
  then exit 1
  fi
  packages=$(consume_diagnostic_output) || die 'cargo metadata packages are invalid'

  command -v mktemp >/dev/null 2>&1 || die 'required command unavailable: mktemp'
  temporary_file=$(mktemp "${TMPDIR:-/tmp}/ci-cache-incremental.XXXXXX" 2>/dev/null) || die 'cannot create discovery file'
  if ! find -P "$target_physical" -type d -name incremental -print0 >"$temporary_file" 2>/dev/null; then
    die 'incremental discovery failed'
  fi

  while IFS= read -r package; do
    [ -n "$package" ] || die 'cargo metadata contains an empty package name'
    run_diagnostic clean "$package" cargo clean --target-dir "$target_physical" -p "$package" || exit 1
    consume_diagnostic_output >/dev/null || die 'cannot consume package cleanup output'
  done <<EOF
$packages
EOF

  while IFS= read -r -d '' incremental; do
    case "$incremental/" in "$target_physical"/*) ;; *) die 'incremental directory escaped target' ;; esac
    [ ! -L "$incremental" ] || die 'incremental directory is a symlink'
    rm -rf -- "$incremental" 2>/dev/null || die 'incremental cleanup failed'
  done <"$temporary_file"
  rm -f -- "$temporary_file" || die 'cannot remove discovery file'
  temporary_file=
}

[ "$#" -gt 0 ] || usage
command_name=$1
shift
case "$command_name" in
  cleanup) cleanup_cache "$@" ;;
  measure) measure "$@" ;;
  tree-identity) tree_identity "$@" ;;
  prepare-roots) prepare_roots "$@" ;;
  *) usage ;;
esac
