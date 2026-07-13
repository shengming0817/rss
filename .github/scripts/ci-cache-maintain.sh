#!/usr/bin/env bash
set -eu
set -f

usage() {
  printf '%s\n' \
    "usage: $0 measure --path <path>" \
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
  measure) measure "$@" ;;
  prepare-roots) prepare_roots "$@" ;;
  *) usage ;;
esac
