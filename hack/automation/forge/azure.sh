#!/usr/bin/env bash
# forge/azure.sh — Azure DevOps (`az repos` / `az boards` / `az devops invoke`)
# backend for forge.sh. Fallback backend, NOT active for this repo (rss defaults
# to the GitHub origin); retained as a behaviour-equivalence reference.
#
# Command syntax verified against learn.microsoft.com (az CLI 2.x + azure-devops
# extension, REST api-version 7.1). One of the three sanctioned homes for raw
# forge CLI invocations.
#
# Auth (non-interactive): export AZURE_DEVOPS_EXT_PAT (Code R/W + Work Items R/W).
# org/project/repo come from forge.conf (ADO_ORG / ADO_PROJECT / ADO_REPO).
#
# Known gaps handled here (see ADR forge-abstraction):
#   - pr-comment: no single-comment CLI -> POST a thread via `az devops invoke`,
#     URL hand-built from the returned thread id.
#   - pr labels: no `az repos pr` label subcommand -> REST POST/GET/DELETE.
#     `az repos pr show` does NOT return labels (field is null) -> read-back goes
#     through the pullRequestLabels GET. DELETE is by resolved label id (GUID),
#     not name: a "/" in a label name (e.g. pr-status/needs-review-again) 404s on
#     the name route even URL-encoded, so we look the id up from the GET first.
#   - pr-diff / pr-diffstat: ADO REST exposes no line-level +/- -> computed from
#     local git against the active remote's branches.
#   - author trust: no author_association -> AZURE_TRUSTED_AUTHORS allowlist.
#   - ci-*: gated off in forge.sh (AZURE_HAS_CI=false); pipeline-* verbs below
#     manage Azure Pipelines explicitly for the local-CI mirror.
#   - issue-edit-labels (System.Tags): read-modify-write via REST op=replace
#     (`az boards --fields` only ADDS tags, never removes; `az devops invoke`
#     PATCH errors); NOT atomic (backlog).
#   - issue-close: state is process-template dependent (AZURE_WI_CLOSE_STATE;
#     Basic process = Done, NOT Closed).
#
# Sourced by forge.sh; relies on its globals: DRY_RUN, _dry, PM_COMMENT_MARKER_RE,
# ADO_ORG/ADO_PROJECT/ADO_REPO, AZURE_REMOTE, AZURE_TRUSTED_AUTHORS, AZURE_WI_TYPE_*.

_az_pr_url_base() { printf '%s/%s/_git/%s' "${ADO_ORG}" "${ADO_PROJECT}" "${ADO_REPO}"; }

# Azure REST auth header for direct curl calls — used only where the az CLI is
# broken (work-item System.Tags REPLACE: `az boards --fields` is add-only, and
# `az devops invoke` PATCH hits an internal az error). Prefers the devops PAT
# (same credential the rest of this backend uses); else a token from `az login`.
_az_auth_header() {
    if [ -n "${AZURE_DEVOPS_EXT_PAT:-}" ]; then
        printf 'Authorization: Basic %s' "$(printf ':%s' "${AZURE_DEVOPS_EXT_PAT}" | base64 | tr -d '\n')"
    else
        local t
        t="$(az account get-access-token --resource 499b84ac-1321-427f-aa17-267ca6975798 --query accessToken -o tsv 2>/dev/null)" \
            || return 1
        printf 'Authorization: Bearer %s' "${t}"
    fi
}

# _az_wit_replace_tags <id> <semicolon-joined-tags>: set System.Tags to exactly
# the given set via REST op=replace (the ONLY reliable add+remove path).
_az_wit_replace_tags() {
    local id="$1" tags="$2" auth body hdr rc
    auth="$(_az_auth_header)" \
        || { echo "forge azure: no ADO credential (set AZURE_DEVOPS_EXT_PAT or run az login)" >&2; return 1; }
    body="$(jq -nc --arg v "${tags}" '[{op:"replace",path:"/fields/System.Tags",value:$v}]')"
    # Pass the auth header via a 0600 temp file (curl -H @file), NOT `-H "<token>"`:
    # an argv-visible Authorization header leaks the PAT/Bearer token to `ps`.
    hdr="$(mktemp "${TMPDIR:-/tmp}/forge-azhdr.XXXXXX")"
    printf '%s\n' "${auth}" > "${hdr}"
    if curl -fsS -X PATCH "${ADO_ORG}/${ADO_PROJECT}/_apis/wit/workitems/${id}?api-version=7.1" \
        -H @"${hdr}" -H "Content-Type: application/json-patch+json" -d "${body}" >/dev/null; then rc=0; else rc=$?; fi
    rm -f "${hdr}"
    return "${rc}"
}

_azure_pr_create() { # <title> <body-file> <base> <head> -> PR URL
    local title="$1" body_file="$2" base="$3" head="$4"
    # F5: description must NOT enter argv (process-list exposure).
    # Use az devops invoke REST POST with --in-file so the body stays in a file.
    # dry-run emits a stable placeholder — no random /tmp path, no body content.
    if [ "${DRY_RUN}" = "1" ]; then
        printf 'az devops invoke --area git --resource pullRequests --http-method POST --route-parameters project=%s repositoryId=%s --in-file <body-json> --api-version 7.1 --output json --org %s\n' \
            "${ADO_PROJECT}" "${ADO_REPO}" "${ADO_ORG}"
        return 0
    fi
    local tmp
    tmp="$(mktemp "${TMPDIR:-/tmp}/forge-azpr.XXXXXX")"
    # jq --rawfile reads the file without shell interpolation; no argv exposure.
    jq -n \
        --arg title "${title}" \
        --arg src "refs/heads/${head}" \
        --arg tgt "refs/heads/${base}" \
        --rawfile desc "${body_file}" \
        '{title:$title, description:$desc, sourceRefName:$src, targetRefName:$tgt}' > "${tmp}"
    local out; out="$(az devops invoke --area git --resource pullRequests \
        --http-method POST \
        --route-parameters "project=${ADO_PROJECT}" "repositoryId=${ADO_REPO}" \
        --in-file "${tmp}" --api-version 7.1 --output json --org "${ADO_ORG}")"
    rm -f "${tmp}"
    printf '%s' "${out}" | jq -r --arg base "$(_az_pr_url_base)" '"\($base)/pullrequest/\(.pullRequestId)"'
}

_azure_pr_comment() { # <pr> <body-file> -> comment URL
    local pr="$1" body="$2" tmp
    # dry-run: emit a stable placeholder — skip mktemp so no random path leaks (F14).
    if [ "${DRY_RUN}" = "1" ]; then
        printf 'az devops invoke --area git --resource pullRequestThreads --route-parameters project=%s repositoryId=%s pullRequestId=%s --http-method POST --in-file <body-file> --api-version 7.1 --output json --org %s\n' \
            "${ADO_PROJECT}" "${ADO_REPO}" "${pr}" "${ADO_ORG}"
        return 0
    fi
    tmp="$(mktemp "${TMPDIR:-/tmp}/forge-azcomment.XXXXXX")"
    # JSON-escape the markdown body via --rawfile; commentType 1 = text, status 1 = active.
    jq -n --rawfile c "${body}" '{comments:[{parentCommentId:0, content:$c, commentType:1}], status:1}' > "${tmp}"
    local -a cmd=(az devops invoke --area git --resource pullRequestThreads
        --route-parameters "project=${ADO_PROJECT}" "repositoryId=${ADO_REPO}" "pullRequestId=${pr}"
        --http-method POST --in-file "${tmp}" --api-version 7.1 --output json --org "${ADO_ORG}")
    local out; out="$("${cmd[@]}")"; rm -f "${tmp}"
    printf '%s' "${out}" | jq -r --arg base "$(_az_pr_url_base)" --arg pr "${pr}" '"\($base)/pullrequest/\($pr)?discussionId=\(.id)"'
}

_azure_pr_add_label() { # <pr> <label>
    local pr="$1" label="$2" tmp
    tmp="$(mktemp "${TMPDIR:-/tmp}/forge-azlabel.XXXXXX")"
    jq -n --arg n "${label}" '{name:$n}' > "${tmp}"
    local -a cmd=(az devops invoke --area git --resource pullRequestLabels
        --route-parameters "project=${ADO_PROJECT}" "repositoryId=${ADO_REPO}" "pullRequestId=${pr}"
        --http-method POST --in-file "${tmp}" --api-version 7.1 --output json --org "${ADO_ORG}")
    if _dry "${cmd[@]}"; then rm -f "${tmp}"; return 0; fi
    "${cmd[@]}" >/dev/null; rm -f "${tmp}"
}

# _azure_pr_labels_json: active label names on a PR as a JSON array. The single
# read-back source for labels (`az repos pr show .labels` is always null).
_azure_pr_labels_json() { # <pr> -> ["name", ...]
    az devops invoke --area git --resource pullRequestLabels \
        --route-parameters "project=${ADO_PROJECT}" "repositoryId=${ADO_REPO}" "pullRequestId=$1" \
        --api-version 7.1 --output json --org "${ADO_ORG}" \
        | jq -c '[(.value // [])[] | select(.active != false) | .name]'
}

_azure_pr_remove_label() { # <pr> <label>  (DELETE by resolved id; name may hold "/")
    local pr="$1" label="$2"
    if _dry "az devops invoke pullRequestLabels GET (resolve id) ; DELETE labelIdOrName=<id>"; then return 0; fi
    local id
    id="$(az devops invoke --area git --resource pullRequestLabels \
        --route-parameters "project=${ADO_PROJECT}" "repositoryId=${ADO_REPO}" "pullRequestId=${pr}" \
        --api-version 7.1 --output json --org "${ADO_ORG}" \
        | jq -r --arg n "${label}" 'first((.value // [])[] | select(.name==$n) | .id) // empty')"
    [ -n "${id}" ] || return 0   # absent -> idempotent no-op
    az devops invoke --area git --resource pullRequestLabels \
        --route-parameters "project=${ADO_PROJECT}" "repositoryId=${ADO_REPO}" "pullRequestId=${pr}" "labelIdOrName=${id}" \
        --http-method DELETE --api-version 7.1 --output json --org "${ADO_ORG}" >/dev/null
}

_azure_pr_set_labels() { # <pr> --add a,b --remove c,d
    local pr="$1"; shift
    local add="" rm=""
    while [ $# -gt 0 ]; do case "$1" in --add) add="$2"; shift 2 ;; --remove) rm="$2"; shift 2 ;; *) shift ;; esac; done
    local IFS=',' l
    for l in ${rm};  do [ -n "${l}" ] && _azure_pr_remove_label "${pr}" "${l}"; done
    for l in ${add}; do [ -n "${l}" ] && _azure_pr_add_label "${pr}" "${l}"; done
}

_azure_pr_state() { # <pr> -> {state,labels}  (labels via pullRequestLabels GET, not pr show)
    if _dry "az repos pr show --id $1 ; az devops invoke pullRequestLabels GET"; then return 0; fi
    local state labels
    state="$(az repos pr show --id "$1" --output json --org "${ADO_ORG}" \
        | jq -r 'if .status=="active" then "open" elif .status=="completed" then "merged" else "closed" end')"
    labels="$(_azure_pr_labels_json "$1")"
    jq -nc --arg s "${state}" --argjson l "${labels:-[]}" '{state:$s, labels:$l}'
}

_azure_pr_refs() { # <pr> -> {baseRef,headRef,headSha}
    local -a cmd=(az repos pr show --id "$1" --output json --org "${ADO_ORG}")
    _dry "${cmd[@]}" && return 0
    "${cmd[@]}" | jq -c '{baseRef:(.targetRefName|sub("^refs/heads/";"")), headRef:(.sourceRefName|sub("^refs/heads/";"")), headSha:(.lastMergeSourceCommit.commitId)}'
}

_azure_pr_comments_json() { # <pr> -> [{createdAt,author,url,body,kind}] trusted pm:* comments
    local -a cmd=(az devops invoke --area git --resource pullRequestThreads
        --route-parameters "project=${ADO_PROJECT}" "repositoryId=${ADO_REPO}" "pullRequestId=$1"
        --http-method GET --api-version 7.1 --output json --org "${ADO_ORG}")
    _dry "${cmd[@]}" && return 0
    if [ -z "${AZURE_TRUSTED_AUTHORS:-}" ]; then
        echo "forge azure: AZURE_TRUSTED_AUTHORS empty -> no comment trusted for dispatch (set it to enable)" >&2
    fi
    "${cmd[@]}" | jq -c --arg re "${PM_COMMENT_MARKER_RE}" --arg allow "${AZURE_TRUSTED_AUTHORS:-}" \
        --arg base "$(_az_pr_url_base)" --arg pr "$1" '
        ($allow | split(",") | map(select(length>0))) as $a
        | [ (.value // [])[] | . as $t | (.comments // [])[]
            | select( ((.author.uniqueName // "") as $u | ($a | index($u)) != null)
                      and ((.content // "") | test($re)) )
            | { createdAt: (.publishedDate // ""),
                author: (.author.uniqueName // ""),
                url: "\($base)/pullrequest/\($pr)?discussionId=\($t.id)",
                body: (.content // ""),
                kind: ((.content // "") | capture("<!-- pm:(?<k>ship|fix|pr-review|ci|oos) -->") | .k) } ]'
}

# _azure_fetch_pr_refs <base> <head>: refresh the remote-tracking refs so a local
# diff isn't computed against a stale tip (F10). Fail-fast on fetch error so stale
# refs don't silently produce wrong diffs.
_azure_fetch_pr_refs() {
    git fetch -q "${AZURE_REMOTE}" \
        "+refs/heads/$1:refs/remotes/${AZURE_REMOTE}/$1" \
        "+refs/heads/$2:refs/remotes/${AZURE_REMOTE}/$2"
}

_azure_pr_diff() { # <pr> (local git; ADO REST has no unified-diff text)
    local pr="$1"
    if [ "${DRY_RUN}" = "1" ]; then printf 'git fetch %s <base> <head> ; git diff %s/<base>...%s/<head>\n' "${AZURE_REMOTE}" "${AZURE_REMOTE}" "${AZURE_REMOTE}"; return 0; fi
    local refs base head; refs="$(_azure_pr_refs "${pr}")" || return 1
    base="$(printf '%s' "${refs}" | jq -r .baseRef)"; head="$(printf '%s' "${refs}" | jq -r .headRef)"
    _azure_fetch_pr_refs "${base}" "${head}"
    git diff "${AZURE_REMOTE}/${base}...${AZURE_REMOTE}/${head}"
}

_azure_pr_diffstat() { # <pr> -> additions + deletions (local git; no REST line counts)
    local pr="$1"
    if [ "${DRY_RUN}" = "1" ]; then printf 'git fetch %s <base> <head> ; git diff --shortstat %s/<base>...%s/<head>\n' "${AZURE_REMOTE}" "${AZURE_REMOTE}" "${AZURE_REMOTE}"; return 0; fi
    local refs base head; refs="$(_azure_pr_refs "${pr}")" || return 1
    base="$(printf '%s' "${refs}" | jq -r .baseRef)"; head="$(printf '%s' "${refs}" | jq -r .headRef)"
    _azure_fetch_pr_refs "${base}" "${head}"
    local stat ins del
    stat="$(git diff --shortstat "${AZURE_REMOTE}/${base}...${AZURE_REMOTE}/${head}")"
    ins="$(printf '%s' "${stat}" | grep -oE '[0-9]+ insertion' | grep -oE '[0-9]+' || true)"
    del="$(printf '%s' "${stat}" | grep -oE '[0-9]+ deletion'  | grep -oE '[0-9]+' || true)"
    echo $(( ${ins:-0} + ${del:-0} ))
}

_azure_pr_mergeable() { # <pr> -> MERGEABLE|CONFLICTING|UNKNOWN
    local -a cmd=(az repos pr show --id "$1" --output json --org "${ADO_ORG}")
    _dry "${cmd[@]}" && return 0
    "${cmd[@]}" | jq -r '(.mergeStatus // "notSet") | if .=="succeeded" then "MERGEABLE" elif .=="conflicts" then "CONFLICTING" else "UNKNOWN" end'
}

_azure_pr_web_url() { printf '%s/pullrequest/%s\n' "$(_az_pr_url_base)" "$1"; }

# --- Azure Pipelines (local-CI mirror) ---------------------------------------
_azure_pipeline_create() { # <name> <repo> <branch> <yaml> [queue-id]
    local name="$1" repo="$2" branch="$3" yaml_path="$4" queue_id="${5:-}"
    local -a cmd=(az pipelines create
        --name "${name}"
        --repository "${repo}"
        --repository-type tfsgit
        --branch "${branch}"
        --yml-path "${yaml_path}")
    [ -n "${queue_id}" ] && cmd+=(--queue-id "${queue_id}")
    cmd+=(
        --skip-first-run true
        --org "${ADO_ORG}"
        --project "${ADO_PROJECT}")
    _dry "${cmd[@]}" && return 0
    "${cmd[@]}"
}

_azure_pipeline_run() { # <name> <branch> <phase> <lint-mode> <base-ref> <with-nightly> <docker-wrapper> <agent-pool> [open]
    local name="$1" branch="$2" phase="$3" lint_mode="$4" base_ref="$5" with_nightly="$6" docker_wrapper="$7" agent_pool="$8" open="${9:-false}"
    local -a cmd=(az pipelines run
        --name "${name}"
        --branch "${branch}"
        --org "${ADO_ORG}"
        --project "${ADO_PROJECT}"
        --parameters
        phase="${phase}"
        lintMode="${lint_mode}"
        baseRef="${base_ref}"
        withNightly="${with_nightly}"
        dockerWrapper="${docker_wrapper}"
        agentPool="${agent_pool}")
    [ "${open}" = "true" ] && cmd+=(--open)
    _dry "${cmd[@]}" && return 0
    "${cmd[@]}"
}

_azure_pipeline_list() { # <name>
    local name="$1"
    if [ "${DRY_RUN}" = "1" ]; then
        printf 'az pipelines show --name %s ; az pipelines runs list --pipeline-ids <id>\n' "${name}"
        return 0
    fi
    local pipeline_id
    pipeline_id="$(az pipelines show --name "${name}" --org "${ADO_ORG}" --project "${ADO_PROJECT}" --query id -o tsv)"
    az pipelines runs list \
        --pipeline-ids "${pipeline_id}" \
        --org "${ADO_ORG}" \
        --project "${ADO_PROJECT}" \
        --top 10 \
        -o table
}

_azure_pipeline_policy() { # <name> <repo> <branch> <display-name>
    local name="$1" repo="$2" branch="$3" display_name="$4"
    if [ "${DRY_RUN}" = "1" ]; then
        printf 'az pipelines show --name %s ; az repos show --repository %s ; az repos policy build create --branch %s --display-name %s\n' "${name}" "${repo}" "${branch}" "${display_name}"
        return 0
    fi
    local pipeline_id repository_id
    pipeline_id="$(az pipelines show --name "${name}" --org "${ADO_ORG}" --project "${ADO_PROJECT}" --query id -o tsv)"
    repository_id="$(az repos show --repository "${repo}" --org "${ADO_ORG}" --project "${ADO_PROJECT}" --query id -o tsv)"
    az repos policy build create \
        --blocking true \
        --enabled true \
        --manual-queue-only false \
        --queue-on-source-update-only true \
        --valid-duration 0 \
        --display-name "${display_name}" \
        --build-definition-id "${pipeline_id}" \
        --repository-id "${repository_id}" \
        --branch "${branch}" \
        --branch-match-type exact \
        --org "${ADO_ORG}" \
        --project "${ADO_PROJECT}"
}

# --- Work Items (issue-* verbs map to Azure Boards) --------------------------
_azure_issue_create() { # <title> <body-file> <label-csv> [type]
    local title="$1" body_file="$2" labels="$3" type="${4:-${AZURE_WI_TYPE_BACKLOG}}"
    local tags; tags="$(printf '%s' "${labels}" | tr ',' ';')"
    # F5: description must NOT enter argv.
    # Create the work item first (title + type + tags via CLI args — these are metadata, not body).
    # Then PATCH the description via REST --in-file so body content never appears in process list.
    if [ "${DRY_RUN}" = "1" ]; then
        printf 'az boards work-item create --title %s --type %s --fields System.Tags=%s ; az devops invoke --area wit --resource workitems --http-method PATCH --in-file <desc-json>\n' \
            "${title}" "${type}" "${tags}"
        return 0
    fi
    local wi_id
    wi_id="$(az boards work-item create --title "${title}" --type "${type}" \
        --fields "System.Tags=${tags}" \
        --org "${ADO_ORG}" --project "${ADO_PROJECT}" --output json \
        | jq -r '.id')"
    # PATCH description via REST JSON-Patch so body stays in a file.
    local tmp
    tmp="$(mktemp "${TMPDIR:-/tmp}/forge-azwi.XXXXXX")"
    jq -n --rawfile desc "${body_file}" \
        '[{op:"add",path:"/fields/System.Description",value:$desc}]' > "${tmp}"
    az devops invoke --area wit --resource workitems \
        --route-parameters "id=${wi_id}" \
        --http-method PATCH --in-file "${tmp}" \
        --api-version 7.1 --output json --org "${ADO_ORG}" >/dev/null
    rm -f "${tmp}"
    printf '#%s\n' "${wi_id}"
}

_azure_issue_view() { # <n> -> {number,title,body,state(open|closed),labels}
    local -a cmd=(az boards work-item show --id "$1" --output json --org "${ADO_ORG}")
    _dry "${cmd[@]}" && return 0
    # state normalised to forge-neutral open|closed (WI close state = AZURE_WI_CLOSE_STATE,
    # else open) so /ship & issues skill don't parse raw "To Do/Doing/Done". Tags split
    # on ";" + trim (Azure stores "a; b"; be robust to either separator) — F4/F9.
    "${cmd[@]}" | jq -c --arg closed "${AZURE_WI_CLOSE_STATE:-Done}" '{
        number: .id,
        title: (.fields["System.Title"] // ""),
        body: (.fields["System.Description"] // ""),
        state: ((.fields["System.State"] // "") | if . == $closed then "closed" else "open" end),
        labels: ((.fields["System.Tags"] // "") | split(";") | map(gsub("^ +| +$";"")) | map(select(length>0)))
    }'
}

# issue-edit-labels: System.Tags is one ";"-joined string with NO atomic add/remove
# API -> read-modify-write (non-atomic; concurrent edits can drop tags — backlog).
_azure_issue_edit_labels() { # <n> --add a,b --remove c,d
    local n="$1"; shift
    local add="" rm=""
    while [ $# -gt 0 ]; do case "$1" in --add) add="$2"; shift 2 ;; --remove) rm="$2"; shift 2 ;; *) shift ;; esac; done
    if [ "${DRY_RUN}" = "1" ]; then
        printf 'az boards work-item show --id %s ; REST PATCH op=replace /fields/System.Tags=<merged>\n' "${n}"
        return 0
    fi
    local cur all rmset final nl=$'\n'
    cur="$(az boards work-item show --id "${n}" --output json --org "${ADO_ORG}" | jq -r '.fields["System.Tags"] // ""')"
    # comma-separated label CSV -> one-per-line (quoted; comma replaced with newline).
    all="$( { printf '%s\n' "${cur}" | tr ';' '\n'; printf '%s\n' "${add//,/${nl}}"; } \
        | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -v '^$' | sort -u )"
    rmset="$(printf '%s\n' "${rm//,/${nl}}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -v '^$' | sort -u)"
    final="$(comm -23 <(printf '%s\n' "${all}") <(printf '%s\n' "${rmset}") | paste -sd ';' -)"
    # op=replace (NOT `az boards --fields`, which only ADDS tags — never removes).
    _az_wit_replace_tags "${n}" "${final}"
}

_azure_issue_close() { # <n> <reason-ignored> <comment>
    # Close state is process-template dependent (AZURE_WI_CLOSE_STATE; Basic=Done,
    # Agile/CMMI=Closed). Basic process has NO "Closed" state.
    # F5: comment content must NOT enter argv — pass state change separately, then
    # POST discussion via REST --in-file.
    local n="$1" comment="$3" state="${AZURE_WI_CLOSE_STATE:-Done}"
    local -a cmd=(az boards work-item update --id "${n}" --state "${state}" --org "${ADO_ORG}" --output json)
    _dry "${cmd[@]}" && return 0
    "${cmd[@]}" >/dev/null
    # Add discussion comment via REST JSON-Patch so comment text stays off argv.
    if [ -n "${comment}" ]; then
        local tmp
        tmp="$(mktemp "${TMPDIR:-/tmp}/forge-azclose.XXXXXX")"
        jq -n --arg c "${comment}" \
            '[{op:"add",path:"/fields/System.History",value:$c}]' > "${tmp}"
        az devops invoke --area wit --resource workitems \
            --route-parameters "id=${n}" \
            --http-method PATCH --in-file "${tmp}" \
            --api-version 7.1 --output json --org "${ADO_ORG}" >/dev/null
        rm -f "${tmp}"
    fi
}

_azure_issue_list() { # <search> <state: open|closed|all> -> WIQL result (id list)
    # WIQL escaping: double single-quotes in the search literal (F7 — '-injection).
    local search="${1//\'/\'\'}" state="${2:-open}" closed="${AZURE_WI_CLOSE_STATE:-Done}" clause=""
    case "${state}" in
        open)   clause=" AND [System.State] <> '${closed}'" ;;
        closed) clause=" AND [System.State] = '${closed}'" ;;
        all|"") clause="" ;;
    esac
    local wiql="SELECT [System.Id],[System.Title],[System.State],[System.Tags] FROM WorkItems WHERE [System.TeamProject]='${ADO_PROJECT}' AND [System.Title] CONTAINS WORDS '${search}'${clause}"
    local -a cmd=(az boards query --wiql "${wiql}" --org "${ADO_ORG}" --project "${ADO_PROJECT}" --output json)
    _dry "${cmd[@]}" && return 0
    "${cmd[@]}"
}

_azure_issue_comment() { # <n> <body-file>
    # F5: comment body must NOT enter argv — use REST JSON-Patch --in-file.
    local n="$1" body_file="$2"
    if [ "${DRY_RUN}" = "1" ]; then
        printf 'az devops invoke --area wit --resource workitems --route-parameters id=%s --http-method PATCH --in-file <body-json> --api-version 7.1 --output json --org %s\n' \
            "${n}" "${ADO_ORG}"
        return 0
    fi
    local tmp
    tmp="$(mktemp "${TMPDIR:-/tmp}/forge-azwicmt.XXXXXX")"
    jq -n --rawfile c "${body_file}" \
        '[{op:"add",path:"/fields/System.History",value:$c}]' > "${tmp}"
    az devops invoke --area wit --resource workitems \
        --route-parameters "id=${n}" \
        --http-method PATCH --in-file "${tmp}" \
        --api-version 7.1 --output json --org "${ADO_ORG}" >/dev/null
    rm -f "${tmp}"
}

_azure_subissue_link() { # <parent> <child>
    local -a cmd=(az boards work-item relation add --id "$2" --relation-type parent --target-id "$1" --org "${ADO_ORG}" --output json)
    _dry "${cmd[@]}" && return 0
    "${cmd[@]}" >/dev/null
}
