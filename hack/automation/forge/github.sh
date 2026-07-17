#!/usr/bin/env bash
# forge/github.sh — GitHub (`gh`) backend for forge.sh.
#
# This is the ACTIVE backend for this repo (rss defaults to GitHub origin). Every
# function here is a faithful port of the `gh` commands that previously lived
# inline in the skills and the pr-meta / issue-labels scripts. This is ONE of the
# three sanctioned homes for raw `gh` invocations (forge.sh + forge/*.sh);
# forge-guard-selftest.sh enforces it.
#
# Sourced by forge.sh; relies on its globals: DRY_RUN, _dry, PM_COMMENT_MARKER_RE,
# GITHUB_REPO_SLUG. Output is normalised to the shapes documented in forge.sh.

_gh_slug() { printf '%s' "${GITHUB_REPO_SLUG}"; }

_github_pr_create() { # <title> <body-file> <base> <head>
    _dry gh pr create --title "$1" --body-file "$2" --base "$3" --head "$4" --repo "$(_gh_slug)" && return 0
    gh pr create --title "$1" --body-file "$2" --base "$3" --head "$4" --repo "$(_gh_slug)"
}

_github_pr_comment() { # <pr> <body-file> -> comment URL
    _dry gh pr comment "$1" --repo "$(_gh_slug)" --body-file "$2" && return 0
    gh pr comment "$1" --repo "$(_gh_slug)" --body-file "$2"
}

_github_pr_add_label()    { _dry gh pr edit "$1" --repo "$(_gh_slug)" --add-label "$2" && return 0; gh pr edit "$1" --repo "$(_gh_slug)" --add-label "$2"; }
_github_pr_remove_label() { _dry gh pr edit "$1" --repo "$(_gh_slug)" --remove-label "$2" && return 0; gh pr edit "$1" --repo "$(_gh_slug)" --remove-label "$2"; }

_github_pr_set_labels() { # <pr> --add a,b --remove c,d
    local pr="$1"; shift
    local add="" rm=""
    while [ $# -gt 0 ]; do case "$1" in --add) add="$2"; shift 2 ;; --remove) rm="$2"; shift 2 ;; *) shift ;; esac; done
    local -a args=(gh pr edit "${pr}" --repo "$(_gh_slug)")
    local IFS=',' l
    for l in ${add}; do [ -n "${l}" ] && args+=(--add-label "${l}"); done
    for l in ${rm};  do [ -n "${l}" ] && args+=(--remove-label "${l}"); done
    _dry "${args[@]}" && return 0
    "${args[@]}"
}

_github_pr_state() { # <pr> -> {state,labels}
    _dry gh pr view "$1" --repo "$(_gh_slug)" --json state,labels && return 0
    gh pr view "$1" --repo "$(_gh_slug)" --json state,labels \
        --jq '{state:(.state|ascii_downcase), labels:[.labels[].name]}'
}

_github_pr_refs() { # <pr> -> {baseRef,headRef,headSha}
    _dry gh pr view "$1" --repo "$(_gh_slug)" --json baseRefName,headRefName,headRefOid && return 0
    gh pr view "$1" --repo "$(_gh_slug)" --json baseRefName,headRefName,headRefOid \
        --jq '{baseRef:.baseRefName, headRef:.headRefName, headSha:.headRefOid}'
}

# pr-comments-json: structured trusted pm:* comments — BOTH from a trusted author
# (author_association OWNER/MEMBER/COLLABORATOR) AND a pm:* protocol comment
# (F3 trust boundary). Consumed via pr-comments.sh (fetch/sort/filter).
_github_pr_comments_json() { # <pr> -> [{createdAt,author,url,body,kind}] trusted pm:* comments
    # --paginate fetches all pages; --slurp merges the per-page arrays into one flat array.
    local ep
    ep="repos/$(_gh_slug)/issues/$1/comments"
    _dry gh api --paginate "${ep}" && return 0
    gh api --paginate --slurp "${ep}" \
        --jq "[ .[][] | select((.author_association == \"OWNER\" or .author_association == \"MEMBER\" or .author_association == \"COLLABORATOR\") and (.body | test(\"${PM_COMMENT_MARKER_RE}\"))) | {createdAt: .created_at, author: .user.login, url: .html_url, body: .body, kind: (.body | capture(\"<!-- pm:(?<k>ship|fix|pr-review|ci|oos) -->\") | .k)} ]"
}

_github_pr_diff() { _dry gh pr diff "$1" --repo "$(_gh_slug)" && return 0; gh pr diff "$1" --repo "$(_gh_slug)"; }

_github_pr_diffstat() { # <pr> -> additions + deletions
    _dry gh pr view "$1" --repo "$(_gh_slug)" --json additions,deletions && return 0
    gh pr view "$1" --repo "$(_gh_slug)" --json additions,deletions --jq '.additions + .deletions'
}

_github_pr_mergeable() { # <pr> -> MERGEABLE|CONFLICTING|UNKNOWN
    _dry gh pr view "$1" --repo "$(_gh_slug)" --json mergeable && return 0
    gh pr view "$1" --repo "$(_gh_slug)" --json mergeable --jq '.mergeable'
}

_github_pr_web_url() { printf 'https://github.com/%s/pull/%s\n' "$(_gh_slug)" "$1"; }

# branch-pr-merged: true when a merged PR used this head branch AND no open PR
# still uses it (branch-name reuse / continue-after-merge stay false while open).
_github_branch_pr_merged() { # <branch> -> true|false
    local branch="$1"
    case "${branch}" in
        '')
            echo "forge github: branch-pr-merged requires a branch name" >&2
            return 64
            ;;
        refs/heads/*) branch="${branch#refs/heads/}" ;;
    esac
    if [ "${DRY_RUN}" = "1" ]; then
        _dry gh pr list --repo "$(_gh_slug)" --head "${branch}" --state open --json number
        _dry gh pr list --repo "$(_gh_slug)" --head "${branch}" --state merged --json number
        return 0
    fi
    local open_out merged_out
    open_out="$(gh pr list --repo "$(_gh_slug)" --head "${branch}" --state open --json number)" || return $?
    if printf '%s' "${open_out}" | jq -e 'length > 0' >/dev/null; then
        printf 'false\n'
        return 0
    fi
    merged_out="$(gh pr list --repo "$(_gh_slug)" --head "${branch}" --state merged --json number)" || return $?
    printf '%s' "${merged_out}" | jq -e 'length > 0' >/dev/null \
        && printf 'true\n' \
        || printf 'false\n'
}

# --- CI (has-ci=true) --------------------------------------------------------
_github_ci_watch() { _dry gh pr checks "$1" --repo "$(_gh_slug)" --watch --interval 30 --fail-fast && return 0; gh pr checks "$1" --repo "$(_gh_slug)" --watch --interval 30 --fail-fast; }
_github_ci_failed() {
    _dry gh pr checks "$1" --repo "$(_gh_slug)" --json name,bucket,link && return 0
    gh pr checks "$1" --repo "$(_gh_slug)" --json name,bucket,link --jq '[.[] | select(.bucket=="fail") | {name:.name, url:.link}]'
}
_github_ci_logs() { local run="$1" job="$2"; _dry gh run view "${run}" --repo "$(_gh_slug)" --job "${job}" --log-failed && return 0; gh run view "${run}" --repo "$(_gh_slug)" --job "${job}" --log-failed; }

# --- Issues ------------------------------------------------------------------
_github_issue_create() { # <title> <body-file> <label-csv> [type-ignored]
    local title="$1" body="$2" labels="$3"
    local -a args=(gh issue create --repo "$(_gh_slug)" --title "${title}" --body-file "${body}")
    local IFS=',' l
    for l in ${labels}; do [ -n "${l}" ] && args+=(--label "${l}"); done
    _dry "${args[@]}" && return 0
    "${args[@]}"
}

_github_issue_view() { # <n> -> {number,title,body,state,labels}
    _dry gh issue view "$1" --repo "$(_gh_slug)" --json number,title,body,labels,state && return 0
    gh issue view "$1" --repo "$(_gh_slug)" --json number,title,body,labels,state \
        --jq '{number:.number, title:.title, body:.body, state:(.state|ascii_downcase), labels:[.labels[].name]}'
}

_github_issue_edit_labels() { # <n> --add a,b --remove c,d
    local n="$1"; shift
    local add="" rm=""
    while [ $# -gt 0 ]; do case "$1" in --add) add="$2"; shift 2 ;; --remove) rm="$2"; shift 2 ;; *) shift ;; esac; done
    local -a args=(gh issue edit "${n}" --repo "$(_gh_slug)")
    local IFS=',' l
    for l in ${add}; do [ -n "${l}" ] && args+=(--add-label "${l}"); done
    for l in ${rm};  do [ -n "${l}" ] && args+=(--remove-label "${l}"); done
    _dry "${args[@]}" && return 0
    "${args[@]}"
}

_github_issue_close() { # <n> <reason> <comment>
    _dry gh issue close "$1" --repo "$(_gh_slug)" --reason "$2" --comment "$3" && return 0
    gh issue close "$1" --repo "$(_gh_slug)" --reason "$2" --comment "$3"
}

_github_issue_list() { # <search> <state>
    local search="$1" state="${2:-open}"
    _dry gh issue list --repo "$(_gh_slug)" --search "${search}" --state "${state}" --json number,title,labels,state && return 0
    gh issue list --repo "$(_gh_slug)" --search "${search}" --state "${state}" --json number,title,labels,state
}

_github_issue_comment() { _dry gh issue comment "$1" --repo "$(_gh_slug)" --body-file "$2" && return 0; gh issue comment "$1" --repo "$(_gh_slug)" --body-file "$2"; }

_github_subissue_link() { # <parent> <child>
    local parent="$1" child="$2"
    if [ "${DRY_RUN}" = "1" ]; then
        printf 'gh api repos/%s/issues/%s --jq .id ; gh api --method POST repos/%s/issues/%s/sub_issues -F sub_issue_id=<id>\n' \
            "$(_gh_slug)" "${child}" "$(_gh_slug)" "${parent}"
        return 0
    fi
    local id
    id="$(gh api "repos/$(_gh_slug)/issues/${child}" --jq .id)"
    gh api --method POST "repos/$(_gh_slug)/issues/${parent}/sub_issues" -F "sub_issue_id=${id}"
}
