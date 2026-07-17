#!/usr/bin/env bash
# forge.sh — forge-agnostic CLI adapter for the rss PR / issue automation.
#
# WHY: the project-management skills (ship/fix/issues/pr-monitor/pr-review) and
# the pr-meta / issue-labels scripts must not embed raw forge CLI commands or
# forge-specific concepts inline. Every forge operation funnels through this
# single adapter: callers speak forge-neutral VERBS, the adapter dispatches to
# the active forge backend (github|azure|gitlab) and NORMALISES the output so
# upstream consumers never see forge-specific shapes.
#
# This file + forge/{github,azure,gitlab}.sh + forge.conf are the SOLE sanctioned
# home for raw `gh` / `az` / `glab` invocations. forge-guard-selftest.sh enforces
# that no other skill or script reintroduces a bare forge CLI (AI-robust Medium
# funnel; downstream lock = backends, upstream lock = the guard scan).
#
# Usage:
#   forge.sh [--dry-run] <verb> [args...]
#   RSS_FORGE=github forge.sh pr-refs 42
#
# --dry-run prints the backend command(s) a verb WOULD run (for selftest command-
# shape assertions) instead of executing them; pure config verbs still print
# their value.
#
# Active forge: RSS_FORGE env > forge.conf DEFAULT_FORGE.
#
# Normalised output shapes (forge-neutral, consumed by pr-meta.sh / skills):
#   repo-slug             -> "<seg1>/<seg2>"           (two segments; schema-safe)
#   remote                -> active forge's git remote name
#   has-ci                -> "true" | "false"
#   issue-ref <N>         -> "#<N>"
#   pr-close-ref <N>      -> "Closes #<N>" | "Fixes #<N>" (azure)
#   pr-state <pr>         -> {"state":"open|closed|merged","labels":[...]}
#   pr-refs <pr>          -> {"baseRef":..,"headRef":..,"headSha":..}
#   pr-mergeable <pr>     -> "MERGEABLE" | "CONFLICTING" | "UNKNOWN"
#   pr-diffstat <pr>      -> integer (additions + deletions)
#   pr-comments-json <pr> -> [{createdAt,author,url,body,kind}] trusted-author pm:* comments
#                            (consumed via pr-comments.sh; skills/pr-meta never parse forge output)
#   pr-comment <pr> <f>   -> created comment URL on stdout
#   ci-* (no-ci forge)    -> "no-ci"
#
# ref: kubernetes/kubernetes hack/lib/util.sh — sourced-helper + dispatch shape.
set -euo pipefail

FORGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=/dev/null
if [ -f "${FORGE_DIR}/forge.conf" ]; then . "${FORGE_DIR}/forge.conf"; fi

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then DRY_RUN=1; shift; fi

FORGE="${RSS_FORGE:-${DEFAULT_FORGE:-github}}"
case "${FORGE}" in
    github) FORGE_REMOTE="${GITHUB_REMOTE:-origin}"; FORGE_HAS_CI="${GITHUB_HAS_CI:-true}" ;;
    azure)  FORGE_REMOTE="${AZURE_REMOTE:-azure}";   FORGE_HAS_CI="${AZURE_HAS_CI:-false}" ;;
    gitlab) FORGE_REMOTE="${GITLAB_REMOTE:-gitlab}"; FORGE_HAS_CI="${GITLAB_HAS_CI:-true}" ;;
    *) echo "forge: unknown forge '${FORGE}' (want github|azure|gitlab)" >&2; exit 64 ;;
esac
export DRY_RUN FORGE FORGE_REMOTE FORGE_HAS_CI

# _dry: in --dry-run mode print the would-be command and signal the verb to stop
# (return 0). Outside dry-run return 1 so the verb proceeds to execute. Composite
# verbs that chain several backend calls check ${DRY_RUN} directly instead.
_dry() {
    [ "${DRY_RUN}" = "1" ] || return 1
    # Force a space join so a caller's local IFS (e.g. "," while splitting a CSV
    # of labels) does not corrupt the displayed command.
    local IFS=' '
    printf '%s\n' "$*"
    return 0
}

# shellcheck disable=SC2153  # *_REPO_SLUG / ADO_* are assigned in sourced forge.conf
_meta_repo_slug() {
    case "${FORGE}" in
        github) printf '%s\n' "${GITHUB_REPO_SLUG}" ;;
        azure)  printf '%s/%s\n' "${ADO_PROJECT}" "${ADO_REPO}" ;;
        gitlab)
            if [ -z "${GITLAB_REPO_SLUG:-}" ]; then
                echo "forge: GITLAB_REPO_SLUG is not set; cannot produce repo slug" >&2
                exit 1
            fi
            printf '%s\n' "${GITLAB_REPO_SLUG}"
            ;;
    esac
}

# pr-close-ref: the PR-body keyword that auto-closes the linked issue / work item
# on merge. GitHub/GitLab use "Closes #N"; Azure DevOps uses "Fixes #N".
_meta_pr_close_ref() {
    case "${FORGE}" in
        azure) printf 'Fixes #%s\n' "$1" ;;
        *)     printf 'Closes #%s\n' "$1" ;;
    esac
}

usage() {
    cat >&2 <<'EOF'
usage: forge.sh [--dry-run] <verb> [args...]
  meta : forge-active repo-slug remote has-ci issue-ref <N> pr-close-ref <N>
  pr   : pr-create <title> <body-file> <base> <head>
         pr-comment <pr> <body-file>        (prints created comment URL)
         pr-add-label <pr> <label> | pr-remove-label <pr> <label>
         pr-set-labels <pr> --add a,b --remove c,d
         pr-state <pr> | pr-refs <pr> | pr-mergeable <pr> | pr-web-url <pr>
         pr-diff <pr> | pr-diffstat <pr> | pr-comments-json <pr>
         branch-pr-merged <branch>   -> true|false (no open PR + has merged; squash-safe)
  ci   : ci-watch <pr> | ci-failed <pr> | ci-logs <args>   (no-op when has-ci=false)
         pipeline-create <name> <repo> <branch> <yaml> [queue-id]
         pipeline-run <name> <branch> <phase> <lint-mode> <base-ref> <with-nightly> <docker-wrapper> <agent-pool> [open]
         pipeline-list <name>
         pipeline-policy rss-local-only <configured-repo> develop "RSS LocalOnly Execution"  (#1815 only)
  issue: issue-create <title> <body-file> <label-csv> [type]
         issue-view <n> | issue-edit-labels <n> --add a,b --remove c,d
         issue-close <n> <reason> <comment> | issue-list <search> <state>
         issue-comment <n> <body-file> | subissue-link <parent> <child>
Active forge from RSS_FORGE env or forge.conf DEFAULT_FORGE.
EOF
}

main() {
    local verb="${1:-}"
    [ -n "${verb}" ] || { usage; exit 64; }
    shift || true
    case "${verb}" in
        -h|--help|help) usage; exit 0 ;;
        forge-active)   printf '%s\n' "${FORGE}"; exit 0 ;;
        repo-slug)      _meta_repo_slug; exit 0 ;;
        remote)         printf '%s\n' "${FORGE_REMOTE}"; exit 0 ;;
        has-ci)         printf '%s\n' "${FORGE_HAS_CI}"; exit 0 ;;
        issue-ref)      printf '#%s\n' "${1:?forge issue-ref: id required}"; exit 0 ;;
        pr-close-ref)   _meta_pr_close_ref "${1:?forge pr-close-ref: id required}"; exit 0 ;;
        ci-watch|ci-failed|ci-logs)
            if [ "${FORGE_HAS_CI}" != "true" ]; then printf 'no-ci\n'; exit 0; fi ;;
    esac
    # shellcheck source=/dev/null
    . "${FORGE_DIR}/forge/${FORGE}.sh"
    local fn="_${FORGE}_${verb//-/_}"
    if ! declare -F "${fn}" >/dev/null 2>&1; then
        echo "forge: verb '${verb}' not implemented for forge '${FORGE}'" >&2
        exit 64
    fi
    "${fn}" "$@"
}

main "$@"
