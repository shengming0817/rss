#!/usr/bin/env bash
set -eu

usage() {
  printf '%s\n' \
    "usage: $0 classify --outcome <success|failure|cancelled|skipped> --hit <true|false|empty> --matched <key|empty>" >&2
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
  outcome_set=false
  hit_set=false
  matched_set=false
  outcome=
  hit=
  matched=
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --outcome) [ "$#" -ge 2 ] || usage; outcome=$2; outcome_set=true; shift 2 ;;
      --hit) [ "$#" -ge 2 ] || usage; hit=$2; hit_set=true; shift 2 ;;
      --matched) [ "$#" -ge 2 ] || usage; matched=$2; matched_set=true; shift 2 ;;
      *) usage ;;
    esac
  done
  [ "$outcome_set" = true ] && [ "$hit_set" = true ] && [ "$matched_set" = true ] || usage
  case "$outcome" in
    success)
      classify_value "$hit" "$matched" || {
        printf 'ci-cache-result: inconsistent cache outputs\n' >&2
        exit 1
      }
      ;;
    failure|cancelled|skipped) printf 'unknown\n' ;;
    *) usage ;;
  esac
}

[ "$#" -gt 0 ] || usage
command_name=$1
shift
case "$command_name" in
  classify) classify "$@" ;;
  *) usage ;;
esac
