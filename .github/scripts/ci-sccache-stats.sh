#!/usr/bin/env bash
set -eu

usage() {
  printf '%s\n' "usage: $0 parse --input <absolute-stats-json>" >&2
  exit 2
}

parse_stats() {
  input=
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --input) [ "$#" -ge 2 ] || usage; input=$2; shift 2 ;;
      *) usage ;;
    esac
  done

  case "$input" in /*) ;; *) usage ;; esac
  [ -f "$input" ] && [ ! -L "$input" ] || {
    printf 'ci-sccache-stats: input must be a regular, non-symlink file\n' >&2
    exit 1
  }

  jq -er '
    def uint:
      type == "number" and . >= 0 and . <= 9007199254740991 and floor == .;
    def require_uint:
      if uint then . else error("expected a JSON-safe unsigned integer") end;
    def counter_sum:
      .counts as $counts
      | if ($counts | type) == "object" and ($counts | all(.[]; uint))
        then ([$counts[]] | add // 0) | require_uint
        else error("expected a closed counter object")
        end;

    .stats as $stats
    | if ($stats | type) != "object" then error("expected stats object") else
        [
          ($stats.compile_requests | require_uint),
          ($stats.cache_hits | counter_sum),
          ($stats.cache_misses | counter_sum),
          ($stats.requests_not_cacheable | require_uint),
          ($stats.cache_errors | counter_sum),
          ($stats.cache_timeouts | require_uint),
          ($stats.cache_read_errors | require_uint),
          ($stats.cache_write_errors | require_uint)
        ]
        | @tsv
      end
  ' "$input"
}

[ "$#" -gt 0 ] || usage
command_name=$1
shift
case "$command_name" in
  parse) parse_stats "$@" ;;
  *) usage ;;
esac
