#!/usr/bin/env bash
# pr-comments.sh — pm:* comment PROTOCOL helper. The single fetch/sort/filter point
# over the forge adapter's structured comments (`forge.sh pr-comments-json`). Skills
# and pr-meta consume THIS helper — they never parse forge output directly
# (ADR forge-abstraction, C1 refactor).
#
#   pr-comments.sh latest <pr> <kind>   newest trusted pm:<kind> comment body ("" if none)
#   pr-comments.sh bodies <pr>          all trusted pm:* bodies, oldest→newest (pr-meta block scan)
#   pr-comments.sh json   <pr>          raw structured array passthrough
#
# kind ∈ ship|fix|pr-review|ci|oos. "trusted author" + pm-marker filtering live in
# the forge backend (forge.sh pr-comments-json, each item {createdAt,author,url,
# body,kind}); ordering + kind-selection live here. RSS_FORGE_SH overrides the
# adapter path (offline selftest).
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
FORGE_SH="${RSS_FORGE_SH:-${DIR}/forge.sh}"

_fetch() { bash "${FORGE_SH}" pr-comments-json "$1"; }

cmd_latest() { # <pr> <kind>
    local pr="$1" kind="${2:?pr-comments latest: <kind> required}"
    _fetch "${pr}" | jq -r --arg k "${kind}" \
        '[.[] | select(.kind == $k)] | sort_by(.createdAt) | (last // {}) | (.body // "")'
}

cmd_bodies() { # <pr>
    _fetch "$1" | jq -r 'sort_by(.createdAt) | .[].body'
}

cmd_json() { _fetch "$1"; }

usage() {
    cat >&2 <<'EOF'
usage: pr-comments.sh <latest|bodies|json> <pr> [kind]
  latest <pr> <kind>   newest trusted pm:<kind> comment body ("" if none)
  bodies <pr>          all trusted pm:* bodies, oldest->newest
  json   <pr>          raw [{createdAt,author,url,body,kind}] passthrough
kind: ship|fix|pr-review|ci|oos
EOF
}

main() {
    local sub="${1:-}"
    [ -n "${sub}" ] || { usage; exit 64; }
    shift || true
    case "${sub}" in
        latest) cmd_latest "$@" ;;
        bodies) cmd_bodies "$@" ;;
        json)   cmd_json "$@" ;;
        -h|--help|help) usage; exit 0 ;;
        *) echo "pr-comments.sh: unknown subcommand '${sub}' (latest|bodies|json)" >&2; exit 64 ;;
    esac
}

main "$@"
