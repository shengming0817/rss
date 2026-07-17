#!/usr/bin/env bash
# forge/gitlab.sh — GitLab (`glab`) backend for forge.sh. BEST-EFFORT.
#
# Per the forge-abstraction decision, GitLab is mapped but NOT exhaustively
# selftested (the repo does not use GitLab today). Verbs with a clean `glab`
# equivalent are implemented; verbs without one (e.g. subissue-link, ci-logs by
# run/job id) are intentionally absent and surface forge.sh's "verb not
# implemented" error — an honest best-effort boundary, not a silent gap.
#
# One of the three sanctioned homes for raw forge CLI invocations.
# Sourced by forge.sh; relies on its globals: DRY_RUN, _dry, PM_COMMENT_MARKER_RE,
# GITLAB_TRUSTED_AUTHORS. GitLab MRs play the role of PRs; issues are native.

_gitlab_pr_create() {
    # F6: description must NOT enter argv — use stdin redirection with --description -.
    # glab mr create reads description from stdin when --description - is given.
    local title="$1" body_file="$2" base="$3" head="$4"
    _dry glab mr create --title "${title}" --description - --target-branch "${base}" --source-branch "${head}" && return 0
    glab mr create --title "${title}" --description - --target-branch "${base}" --source-branch "${head}" < "${body_file}"
}
_gitlab_pr_comment() {
    # F6: message must NOT enter argv — use stdin redirection with --message -.
    local pr="$1" body_file="$2"
    _dry glab mr note create "${pr}" --message - && return 0
    glab mr note create "${pr}" --message - < "${body_file}"
}
_gitlab_pr_add_label()    { _dry glab mr update "$1" --label "$2" && return 0; glab mr update "$1" --label "$2"; }
_gitlab_pr_remove_label() { _dry glab mr update "$1" --unlabel "$2" && return 0; glab mr update "$1" --unlabel "$2"; }

_gitlab_pr_set_labels() { # <pr> --add a,b --remove c,d
    local pr="$1"; shift
    local add="" rm=""
    while [ $# -gt 0 ]; do case "$1" in --add) add="$2"; shift 2 ;; --remove) rm="$2"; shift 2 ;; *) shift ;; esac; done
    local -a args=(glab mr update "${pr}")
    [ -n "${add}" ] && args+=(--label "${add}")
    [ -n "${rm}" ]  && args+=(--unlabel "${rm}")
    _dry "${args[@]}" && return 0
    "${args[@]}"
}

_gitlab_pr_state() { _dry glab mr view "$1" -F json && return 0; glab mr view "$1" -F json | jq -c '{state:(.state|ascii_downcase), labels:(.labels // [])}'; }
_gitlab_pr_refs()  { _dry glab mr view "$1" -F json && return 0; glab mr view "$1" -F json | jq -c '{baseRef:.target_branch, headRef:.source_branch, headSha:.sha}'; }

_gitlab_pr_comments_json() { # <pr> -> [{createdAt,author,url,body,kind}] trusted pm:* comments
    _dry glab mr note list "$1" -F json && return 0
    [ -z "${GITLAB_TRUSTED_AUTHORS:-}" ] && echo "forge gitlab: GITLAB_TRUSTED_AUTHORS empty -> no comment trusted for dispatch" >&2
    glab mr note list "$1" -F json | jq -c --arg re "${PM_COMMENT_MARKER_RE}" --arg allow "${GITLAB_TRUSTED_AUTHORS:-}" '
        ($allow | split(",") | map(select(length>0))) as $a
        | [ .[] | select( ((.author.username // "") as $u | ($a | index($u)) != null) and ((.body // "") | test($re)) )
            | {createdAt:(.created_at // ""), author:(.author.username // ""), url:(.url // ""), body:(.body // ""),
               kind:((.body // "") | capture("<!-- pm:(?<k>ship|fix|pr-review|ci|oos) -->") | .k)} ]'
}

_gitlab_pr_diff()      { _dry glab mr diff "$1" && return 0; glab mr diff "$1"; }
_gitlab_pr_mergeable() { _dry glab mr view "$1" -F json && return 0; glab mr view "$1" -F json | jq -r '(.merge_status // "") | if .=="can_be_merged" then "MERGEABLE" elif .=="cannot_be_merged" then "CONFLICTING" else "UNKNOWN" end'; }
_gitlab_pr_web_url()   { _dry glab mr view "$1" -F json && return 0; glab mr view "$1" -F json | jq -r '.web_url'; }
_gitlab_pr_diffstat()  {
    if _dry glab mr diff "$1"; then return 0; fi
    glab mr diff "$1" | awk '/^(\+\+\+|---)/{next} /^\+/{a++} /^-/{d++} END{print a+d}'
}

# branch-pr-merged: true when a merged MR used this source branch AND no opened
# MR still uses it (branch-name reuse / continue-after-merge stay false while open).
_gitlab_branch_pr_merged() { # <branch> -> true|false
    local branch="$1"
    case "${branch}" in
        '')
            echo "forge gitlab: branch-pr-merged requires a branch name" >&2
            return 64
            ;;
        refs/heads/*) branch="${branch#refs/heads/}" ;;
    esac
    if [ "${DRY_RUN}" = "1" ]; then
        _dry glab mr list --source-branch "${branch}" --opened -F json
        _dry glab mr list --source-branch "${branch}" --merged -F json
        return 0
    fi
    local open_out merged_out
    open_out="$(glab mr list --source-branch "${branch}" --opened -F json)" || return $?
    if printf '%s' "${open_out}" | jq -e 'length > 0' >/dev/null; then
        printf 'false\n'
        return 0
    fi
    merged_out="$(glab mr list --source-branch "${branch}" --merged -F json)" || return $?
    printf '%s' "${merged_out}" | jq -e 'length > 0' >/dev/null \
        && printf 'true\n' \
        || printf 'false\n'
}

# --- CI (has-ci=true) --------------------------------------------------------
_gitlab_ci_watch()  { if [ "${DRY_RUN}" = "1" ]; then printf 'glab ci status (branch via mr view)\n'; return 0; fi; glab ci status; }
_gitlab_ci_failed() { _dry glab ci list --status failed && return 0; glab ci list --status failed; }
_gitlab_ci_logs()   { _dry glab ci trace "$1" && return 0; glab ci trace "$1"; }

# --- Issues ------------------------------------------------------------------
_gitlab_issue_create() {
    # F6: description must NOT enter argv — use stdin redirection with --description -.
    local title="$1" body_file="$2" labels="$3"
    _dry glab issue create --title "${title}" --description - --label "${labels}" && return 0
    glab issue create --title "${title}" --description - --label "${labels}" < "${body_file}"
}
_gitlab_issue_view()   { _dry glab issue view "$1" -F json && return 0; glab issue view "$1" -F json | jq -c '{number:.iid, title:.title, body:.description, state:(.state|ascii_downcase), labels:(.labels // [])}'; }

_gitlab_issue_edit_labels() {
    local n="$1"; shift
    local add="" rm=""
    while [ $# -gt 0 ]; do case "$1" in --add) add="$2"; shift 2 ;; --remove) rm="$2"; shift 2 ;; *) shift ;; esac; done
    local -a args=(glab issue update "${n}")
    [ -n "${add}" ] && args+=(--label "${add}")
    [ -n "${rm}" ]  && args+=(--unlabel "${rm}")
    _dry "${args[@]}" && return 0
    "${args[@]}"
}

_gitlab_issue_close()   { _dry glab issue close "$1" && return 0; glab issue close "$1"; }
_gitlab_issue_list()    { _dry glab issue list --search "$1" --state "${2:-opened}" -F json && return 0; glab issue list --search "$1" --state "${2:-opened}" -F json; }
_gitlab_issue_comment() {
    # F6: message must NOT enter argv — use stdin redirection with --message -.
    local n="$1" body_file="$2"
    _dry glab issue note "${n}" --message - && return 0
    glab issue note "${n}" --message - < "${body_file}"
}
# subissue-link: GitLab parent/child links need Premium + API; no clean glab verb
# -> intentionally unimplemented (forge.sh reports "verb not implemented").
