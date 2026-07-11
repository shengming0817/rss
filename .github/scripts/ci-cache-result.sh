#!/usr/bin/env bash
set -eu

usage() {
  printf '%s\n' \
    "usage: $0 classify --hit <true|false|empty> --matched <key|empty>" \
    "       $0 aggregate --first-hit <value> --first-matched <value> --second-hit <value> --second-matched <value>" >&2
  exit 2
}

classify_value() {
  case "$1:$2" in
    true:?*) printf 'exact\n' ;;
    false:?*) printf 'prefix\n' ;;
    :) printf 'miss\n' ;;
    *) return 1 ;;
  esac
}

classify() {
  hit_set=false
  matched_set=false
  hit=
  matched=
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --hit) [ "$#" -ge 2 ] || usage; hit=$2; hit_set=true; shift 2 ;;
      --matched) [ "$#" -ge 2 ] || usage; matched=$2; matched_set=true; shift 2 ;;
      *) usage ;;
    esac
  done
  [ "$hit_set" = true ] && [ "$matched_set" = true ] || usage
  classify_value "$hit" "$matched" || {
    printf 'ci-cache-result: inconsistent cache outputs\n' >&2
    exit 1
  }
}

aggregate() {
  first_hit_set=false first_matched_set=false second_hit_set=false second_matched_set=false
  first_hit=''
  first_matched=''
  second_hit=''
  second_matched=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --first-hit) [ "$#" -ge 2 ] || usage; first_hit=$2; first_hit_set=true; shift 2 ;;
      --first-matched) [ "$#" -ge 2 ] || usage; first_matched=$2; first_matched_set=true; shift 2 ;;
      --second-hit) [ "$#" -ge 2 ] || usage; second_hit=$2; second_hit_set=true; shift 2 ;;
      --second-matched) [ "$#" -ge 2 ] || usage; second_matched=$2; second_matched_set=true; shift 2 ;;
      *) usage ;;
    esac
  done
  [ "$first_hit_set" = true ] && [ "$first_matched_set" = true ] &&
    [ "$second_hit_set" = true ] && [ "$second_matched_set" = true ] || usage
  first=$(classify_value "$first_hit" "$first_matched") || {
    printf 'ci-cache-result: inconsistent first cache outputs\n' >&2
    exit 1
  }
  second=$(classify_value "$second_hit" "$second_matched") || {
    printf 'ci-cache-result: inconsistent second cache outputs\n' >&2
    exit 1
  }
  case "$first:$second" in
    exact:exact) printf 'exact\n' ;;
    *) printf 'miss\n' ;;
  esac
}

[ "$#" -gt 0 ] || usage
command_name=$1
shift
case "$command_name" in
  aggregate) aggregate "$@" ;;
  classify) classify "$@" ;;
  *) usage ;;
esac
