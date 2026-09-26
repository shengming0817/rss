#!/usr/bin/env bash
# forge/azure.sh — Azure DevOps (`az repos` / `az boards` / `az devops invoke`)
# backend for forge.sh. This is the active PR/Boards forge for rss. Its narrow
# LocalOnly build-validation carrier is managed explicitly by pipeline-* verbs;
# AZURE_HAS_CI remains false until the complete, observable ship CI exists.
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
#     manage explicit Azure Pipelines such as the narrow LocalOnly validation.
#   - issue-edit-labels (System.Tags): read-modify-write via REST op=replace
#     (`az boards --fields` only ADDS tags, never removes; `az devops invoke`
#     PATCH errors); NOT atomic (backlog).
#   - issue-close: state is process-template dependent (AZURE_WI_CLOSE_STATE;
#     Basic process = Done, NOT Closed).
#   - markdown: System.Description / System.History default to HTML (raw markdown
#     renders literally). Descriptions carry a /multilineFieldsFormat=Markdown op;
#     comments go through the dedicated Comments API (?format=markdown,
#     api-version 7.1-preview.4) — the only path honouring a comment format — NOT a
#     System.History JSON-Patch.
#
# Sourced by forge.sh; relies on its globals: DRY_RUN, _dry, PM_COMMENT_MARKER_RE,
# ADO_ORG/ADO_PROJECT/ADO_REPO, AZURE_REMOTE, AZURE_TRUSTED_AUTHORS, AZURE_WI_TYPE_*.

_az_pr_url_base() { printf '%s/%s/_git/%s' "${ADO_ORG}" "${ADO_PROJECT}" "${ADO_REPO}"; }

# Azure REST auth header for direct curl calls — used only where the az CLI is
# lossy or broken (Policy build update folds integer 0 into the persisted value;
# every work-item field write through `az devops invoke --resource workitems`
# PATCH-by-id resolves a route template carrying a `${type}` placeholder it can't
# fill -> `KeyError: 'type'`; and `az boards --fields` is add-only for tags).
# Prefers the devops PAT (same credential the rest of this backend uses); else a
# token from `az login`.
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

# _az_auth_hdr_file: write the ADO auth header to a fresh 0600 temp file and echo
# its path (caller rm's it). SINGLE source for the PAT-off-argv discipline shared
# by every direct REST curl call (_az_wit_patch / _az_wit_comment /
# _az_policy_configuration_put): the token goes via `curl -H @file`, NEVER
# `-H "<token>"` — an argv-visible Authorization header leaks the PAT/Bearer
# token to `ps`.
_az_auth_hdr_file() {
    local auth hdr
    auth="$(_az_auth_header)" \
        || { echo "forge azure: no ADO credential (set AZURE_DEVOPS_EXT_PAT or run az login)" >&2; return 1; }
    hdr="$(mktemp "${TMPDIR:-/tmp}/forge-azhdr.XXXXXX")"
    chmod 0600 "${hdr}"   # make the 0600 promise explicit, independent of mktemp's default
    printf '%s\n' "${auth}" > "${hdr}"
    printf '%s' "${hdr}"
}

# _az_wit_patch <id> <json-patch-file>: PATCH a work item's fields via REST
# JSON-Patch (the op array lives in the file, off argv — F5). This is the SINGLE
# sanctioned WIT field-write path: `az devops invoke --resource workitems` PATCH
# is broken (its route template needs a `${type}` route value PATCH-by-id has no
# way to supply -> `KeyError: 'type'`), so description / tag writes all funnel here.
_az_wit_patch() {
    local id="$1" patch_file="$2" hdr rc
    hdr="$(_az_auth_hdr_file)" || return 1
    if curl -fsS -X PATCH "${ADO_ORG}/${ADO_PROJECT}/_apis/wit/workitems/${id}?api-version=7.1" \
        -H @"${hdr}" -H "Content-Type: application/json-patch+json" --data-binary @"${patch_file}" >/dev/null; then rc=0; else rc=$?; fi
    rm -f "${hdr}"
    return "${rc}"
}

# _az_wit_comment <id> <body-file>: add a work-item discussion comment rendered as
# Markdown via the dedicated Comments API. System.Description / System.History
# default to HTML, so a JSON-Patch write to System.History renders markdown
# literally; only the comments endpoint honours a format. `?format=markdown` at
# api-version 7.1-preview.4 is where CommentFormat (markdown|html) is exposed
# (ref: azure-devops-rest wit/comments/add-comment@7.1-preview.4). Body off argv
# via --data-binary @file — F5.
_az_wit_comment() {
    local id="$1" body_file="$2" hdr tmp rc
    hdr="$(_az_auth_hdr_file)" || return 1
    tmp="$(mktemp "${TMPDIR:-/tmp}/forge-azcmtbody.XXXXXX")" || { rm -f "${hdr}"; return 1; }
    jq -n --rawfile t "${body_file}" '{text:$t}' > "${tmp}" || { rc=$?; rm -f "${hdr}" "${tmp}"; return "${rc}"; }
    if curl -fsS -X POST \
        "${ADO_ORG}/${ADO_PROJECT}/_apis/wit/workItems/${id}/comments?format=markdown&api-version=7.1-preview.4" \
        -H @"${hdr}" -H "Content-Type: application/json" --data-binary @"${tmp}" >/dev/null; then rc=0; else rc=$?; fi
    rm -f "${hdr}" "${tmp}"
    return "${rc}"
}

# _az_policy_configuration_put <id> <json-file>: replace one Azure policy
# configuration through the official 7.1 PUT endpoint. `az repos policy build
# update --valid-duration 0` cannot express the canonical zero value because the
# Azure DevOps CLI merges it as `valid_duration or current`; a file-backed JSON
# body preserves both integer zero and boolean false exactly.
_az_policy_configuration_put() {
    local id="$1" body_file="$2" hdr rc
    case "${id}" in
        ''|*[!0-9]*)
            echo "forge azure: policy configuration id must be numeric" >&2
            return 64
            ;;
    esac
    if [ ! -f "${body_file}" ]; then
        echo "forge azure: policy configuration body file is missing" >&2
        return 64
    fi
    hdr="$(_az_auth_hdr_file)" || return 1
    if curl -fsS -X PUT \
        "${ADO_ORG}/${ADO_PROJECT}/_apis/policy/configurations/${id}?api-version=7.1" \
        -H @"${hdr}" -H "Content-Type: application/json" \
        --data-binary @"${body_file}"; then rc=0; else rc=$?; fi
    rm -f "${hdr}"
    return "${rc}"
}

# _az_wit_replace_tags <id> <semicolon-joined-tags>: set System.Tags to exactly
# the given set via REST op=replace (the ONLY reliable add+remove path).
_az_wit_replace_tags() {
    local id="$1" tags="$2" tmp rc
    tmp="$(mktemp "${TMPDIR:-/tmp}/forge-aztags.XXXXXX")"
    jq -nc --arg v "${tags}" '[{op:"replace",path:"/fields/System.Tags",value:$v}]' > "${tmp}" || {
        rc=$?; rm -f "${tmp}"; return "${rc}"
    }
    _az_wit_patch "${id}" "${tmp}"; rc=$?
    rm -f "${tmp}"
    return "${rc}"
}

_azure_pr_create() { # <title> <body-file> <base> <head> -> PR URL
    local title="$1" body_file="$2" base="$3" head="$4"
    # Azure's `az devops invoke --resource pullRequests` does not map to the
    # documented PR-create endpoint for POST. Use the stable `az repos pr create`
    # command here; accepted tradeoff: PR description enters argv.
    if [ "${DRY_RUN}" = "1" ]; then
        printf 'az repos pr create --title %s --description <body> --target-branch %s --source-branch %s --repository %s --org %s --project %s --output json\n' \
            "${title}" "${base}" "${head}" "${ADO_REPO}" "${ADO_ORG}" "${ADO_PROJECT}"
        return 0
    fi
    local desc out rc
    desc="$(cat "${body_file}")" || return
    out="$(az repos pr create \
        --title "${title}" \
        --description "${desc}" \
        --target-branch "${base}" \
        --source-branch "${head}" \
        --repository "${ADO_REPO}" \
        --org "${ADO_ORG}" --project "${ADO_PROJECT}" --output json)" || rc=$?
    # Fail-fast on az error (sibling _azure_* verbs all do this; F-regression if
    # omitted: empty ${out} below jq'd into a `.../pullrequest/null` fake URL).
    [ "${rc:-0}" -eq 0 ] || return "${rc}"
    # jq -e: exit non-zero when pullRequestId is absent/null so a malformed (but
    # 0-exit) response can't yield a `.../pullrequest/null` URL either.
    printf '%s' "${out}" | jq -e -r --arg base "$(_az_pr_url_base)" \
        'if (.pullRequestId // null) != null then "\($base)/pullrequest/\(.pullRequestId)" else error("pr-create: no pullRequestId in response") end'
}

_azure_pr_comment() { # <pr> <body-file> -> comment URL
    local pr="$1" body="$2" tmp rc out
    # dry-run: emit a stable placeholder — skip mktemp so no random path leaks (F14).
    if [ "${DRY_RUN}" = "1" ]; then
        printf 'az devops invoke --area git --resource pullRequestThreads --route-parameters project=%s repositoryId=%s pullRequestId=%s --http-method POST --in-file <body-file> --api-version 7.1 --output json --org %s\n' \
            "${ADO_PROJECT}" "${ADO_REPO}" "${pr}" "${ADO_ORG}"
        return 0
    fi
    tmp="$(mktemp "${TMPDIR:-/tmp}/forge-azcomment.XXXXXX")"
    # JSON-escape the markdown body via --rawfile; commentType 1 = text, status 1 = active.
    jq -n --rawfile c "${body}" '{comments:[{parentCommentId:0, content:$c, commentType:1}], status:1}' > "${tmp}" || {
        rc=$?
        rm -f "${tmp}"
        return "${rc}"
    }
    local -a cmd=(az devops invoke --area git --resource pullRequestThreads
        --route-parameters "project=${ADO_PROJECT}" "repositoryId=${ADO_REPO}" "pullRequestId=${pr}"
        --http-method POST --in-file "${tmp}" --api-version 7.1 --output json --org "${ADO_ORG}")
    out="$("${cmd[@]}")" || rc=$?
    rm -f "${tmp}"
    [ "${rc:-0}" -eq 0 ] || return "${rc}"
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

# branch-pr-merged: true when a completed (squash-merged) PR used this source
# branch AND no active PR still uses it. Branch-name history alone is too wide
# after squash: reuse / continue-on-branch must stay false while an open PR exists.
_azure_branch_pr_merged() { # <branch> -> true|false
    local branch="$1" ref
    case "${branch}" in
        '')
            echo "forge azure: branch-pr-merged requires a branch name" >&2
            return 64
            ;;
        refs/heads/*) ref="${branch}" ;;
        *) ref="refs/heads/${branch}" ;;
    esac
    local -a active_cmd=(az repos pr list
        --status active
        --source-branch "${ref}"
        --repository "${ADO_REPO}"
        --org "${ADO_ORG}"
        --project "${ADO_PROJECT}"
        --output json)
    local -a completed_cmd=(az repos pr list
        --status completed
        --source-branch "${ref}"
        --repository "${ADO_REPO}"
        --org "${ADO_ORG}"
        --project "${ADO_PROJECT}"
        --output json)
    if [ "${DRY_RUN}" = "1" ]; then
        _dry "${active_cmd[@]}"
        _dry "${completed_cmd[@]}"
        return 0
    fi
    local active completed
    active="$("${active_cmd[@]}")" || return $?
    if printf '%s' "${active}" | jq -e 'length > 0' >/dev/null; then
        printf 'false\n'
        return 0
    fi
    completed="$("${completed_cmd[@]}")" || return $?
    printf '%s' "${completed}" | jq -e 'length > 0' >/dev/null \
        && printf 'true\n' \
        || printf 'false\n'
}

# --- Azure Pipelines ----------------------------------------------------------
# These registration functions are intentionally read-after-write. CLI success
# is not proof that the persisted definition/policy has the requested scope, so
# every create/update funnels through a strict jq predicate before returning.
_AZURE_TFSGIT_REPOSITORY_TYPE="TfsGit"
_AZURE_BUILD_VALIDATION_POLICY_TYPE_ID="0609b952-1397-4640-95ec-e00a01b2c241"
_AZURE_LOCAL_ONLY_PIPELINE_NAME="rss-local-only"
_AZURE_LOCAL_ONLY_BRANCH="develop"
_AZURE_LOCAL_ONLY_POLICY_DISPLAY_NAME="RSS LocalOnly Execution"
_AZURE_LOCAL_ONLY_PIPELINE_YAML="azure-pipelines.yml"

_azure_repository_id() { # <repo>
    local repository_id
    repository_id="$(az repos show --repository "$1" --org "${ADO_ORG}" --project "${ADO_PROJECT}" --query id -o tsv)" \
        || return 1
    if [ -z "${repository_id}" ]; then
        echo "forge azure: repository id read-back was empty" >&2
        return 1
    fi
    printf '%s\n' "${repository_id}"
}

_azure_pipeline_definition_matches() { # <json> <definition-id> <repository-id> <name> <repo> <branch> <yaml>
    local definition="$1" definition_id="$2" repository_id="$3" name="$4" repo="$5" branch="$6" yaml_path="$7"
    local ref="${branch}"
    case "${ref}" in refs/heads/*) ;; *) ref="refs/heads/${ref}" ;; esac
    printf '%s' "${definition}" | jq -e \
        --arg definition_id "${definition_id}" --arg repository_id "${repository_id}" \
        --arg repository_type "${_AZURE_TFSGIT_REPOSITORY_TYPE}" \
        --arg name "${name}" --arg repo "${repo}" --arg ref "${ref}" --arg yaml "${yaml_path}" '
        ((.id | tostring) == $definition_id)
        and (.name == $name)
        and ((.repository.id | tostring) == $repository_id)
        and (.repository.name == $repo)
        and (.repository.type == $repository_type)
        and (.repository.defaultBranch == $ref)
        and ((.process.yamlFilename | sub("^/"; "")) == ($yaml | sub("^/"; "")))
    ' >/dev/null
}

_azure_pipeline_definition_verify() { # <json> <definition-id> <repository-id> <name> <repo> <branch> <yaml>
    _azure_pipeline_definition_matches "$@" && return 0
    echo "forge azure: pipeline definition drift (expected exact id/name/repository-id/repository-type/branch/yaml)" >&2
    return 1
}

_azure_pipeline_existing_verified_id() { # <name> <repo> <repository-id> <branch> <yaml>
    local name="$1" repo="$2" repository_id="$3" branch="$4" yaml_path="$5"
    local listed exact count pipeline_id readback
    listed="$(az pipelines list --name "${name}" --org "${ADO_ORG}" --project "${ADO_PROJECT}" --output json)" \
        || return 1
    exact="$(printf '%s' "${listed}" | jq -ce --arg name "${name}" \
        '[.[] | select(.name == $name)]')" || return 1
    count="$(printf '%s' "${exact}" | jq -er 'length')" || return 1
    if [ "${count}" -ne 1 ]; then
        echo "forge azure: expected exactly one pipeline named ${name}, found ${count}" >&2
        return 1
    fi
    pipeline_id="$(printf '%s' "${exact}" | jq -er '.[0].id')" || return 1
    readback="$(az pipelines show --id "${pipeline_id}" --org "${ADO_ORG}" --project "${ADO_PROJECT}" --output json)" \
        || return 1
    _azure_pipeline_definition_verify "${readback}" "${pipeline_id}" "${repository_id}" \
        "${name}" "${repo}" "${branch}" "${yaml_path}" || return 1
    printf '%s\n' "${pipeline_id}"
}

_azure_pipeline_create() { # <name> <repo> <branch> <yaml> [queue-id]
    local name="$1" repo="$2" branch="$3" yaml_path="$4" queue_id="${5:-}"
    if [ "${DRY_RUN}" = "1" ]; then
        printf 'az repos show --repository %s ; az pipelines list --name %s ; create-if-missing repo=%s branch=%s yaml=%s ; az pipelines show --id <id> ; verify exact id/name/repository-id/repository-type/branch/yaml\n' \
            "${repo}" \
            "${name}" "${repo}" "${branch}" "${yaml_path}"
        return 0
    fi

    local repository_id listed exact count pipeline_id created readback
    repository_id="$(_azure_repository_id "${repo}")" || return 1
    listed="$(az pipelines list --name "${name}" --org "${ADO_ORG}" --project "${ADO_PROJECT}" --output json)" \
        || return 1
    # `az pipelines list --name` is a prefix match unless the caller adds `*`;
    # select the closed exact-name set ourselves before deciding create/verify.
    exact="$(printf '%s' "${listed}" | jq -ce --arg name "${name}" \
        '[.[] | select(.name == $name)]')" || return 1
    count="$(printf '%s' "${exact}" | jq -er 'length')" || return 1
    case "${count}" in
        0) ;;
        1)
            pipeline_id="$(printf '%s' "${exact}" | jq -er '.[0].id')" || return 1
            ;;
        *)
            echo "forge azure: multiple pipelines named ${name}; refusing ambiguous registration" >&2
            return 1
            ;;
    esac

    if [ "${count}" -eq 0 ]; then
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
        created="$("${cmd[@]}")" || return 1
        pipeline_id="$(printf '%s' "${created}" | jq -er '.id')" || {
            echo "forge azure: created pipeline response has no id" >&2
            return 1
        }
    fi

    readback="$(az pipelines show --id "${pipeline_id}" --org "${ADO_ORG}" --project "${ADO_PROJECT}" --output json)" \
        || return 1
    _azure_pipeline_definition_verify "${readback}" "${pipeline_id}" "${repository_id}" \
        "${name}" "${repo}" "${branch}" "${yaml_path}" || return 1
    printf '%s\n' "${readback}"
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

_azure_pipeline_policy_is_build_validation() { # <json>
    printf '%s' "$1" | jq -e \
        --arg type_id "${_AZURE_BUILD_VALIDATION_POLICY_TYPE_ID}" '
        (((.type.id // "") | ascii_downcase) == ($type_id | ascii_downcase))
    ' >/dev/null
}

_azure_pipeline_policy_matches() { # <json> <policy-id> <pipeline-id> <repo-id> <branch> <display-name>
    local policy="$1" policy_id="$2" pipeline_id="$3" repository_id="$4" branch="$5" display_name="$6"
    local ref="${branch}"
    case "${ref}" in refs/heads/*) ;; *) ref="refs/heads/${ref}" ;; esac
    printf '%s' "${policy}" | jq -e \
        --arg policy_id "${policy_id}" --arg policy_type_id "${_AZURE_BUILD_VALIDATION_POLICY_TYPE_ID}" \
        --arg pipeline_id "${pipeline_id}" --arg repository_id "${repository_id}" \
        --arg ref "${ref}" --arg display_name "${display_name}" '
        ((.id | tostring) == $policy_id)
        and (((.type.id // "") | ascii_downcase) == ($policy_type_id | ascii_downcase))
        and (.isBlocking == true)
        and (.isEnabled == true)
        and ((.settings.buildDefinitionId | tostring) == $pipeline_id)
        and (.settings.displayName == $display_name)
        and (.settings.manualQueueOnly == false)
        and (.settings.queueOnSourceUpdateOnly == false)
        and (.settings.validDuration == 0)
        and ((.settings.filenamePatterns? == null) or (.settings.filenamePatterns == []))
        and ((.settings.scope // []) | length == 1)
        and ((.settings.scope[0].repositoryId | tostring) == $repository_id)
        and (.settings.scope[0].refName == $ref)
        and ((.settings.scope[0].matchKind | ascii_downcase) == "exact")
    ' >/dev/null
}

_azure_pipeline_policy_verify() { # <json> <policy-id> <pipeline-id> <repo-id> <branch> <display-name>
    _azure_pipeline_policy_matches "$@" && return 0
    echo "forge azure: build-validation policy drift after read-back" >&2
    return 1
}

_azure_pipeline_policy_put_exact() { # <policy-id> <pipeline-id> <repo-id> <branch> <display-name>
    local policy_id="$1" pipeline_id="$2" repository_id="$3" branch="$4" display_name="$5"
    local ref="${branch}" body changed rc
    case "${ref}" in refs/heads/*) ;; *) ref="refs/heads/${ref}" ;; esac
    body="$(mktemp "${TMPDIR:-/tmp}/forge-azpolicy.XXXXXX")" || return 1
    chmod 0600 "${body}"
    jq -n \
        --arg policy_type_id "${_AZURE_BUILD_VALIDATION_POLICY_TYPE_ID}" \
        --arg pipeline_id "${pipeline_id}" --arg repository_id "${repository_id}" \
        --arg ref "${ref}" --arg display_name "${display_name}" '
        {
          isEnabled: true,
          isBlocking: true,
          type: {id: $policy_type_id},
          settings: {
            buildDefinitionId: ($pipeline_id | tonumber),
            queueOnSourceUpdateOnly: false,
            manualQueueOnly: false,
            displayName: $display_name,
            validDuration: 0,
            filenamePatterns: [],
            scope: [{
              repositoryId: $repository_id,
              refName: $ref,
              matchKind: "Exact"
            }]
          }
        }
    ' > "${body}" || {
        rc=$?
        rm -f "${body}"
        return "${rc}"
    }
    changed="$(_az_policy_configuration_put "${policy_id}" "${body}")" || rc=$?
    rm -f "${body}"
    [ "${rc:-0}" -eq 0 ] || return "${rc}"
    _azure_pipeline_policy_verify "${changed}" "${policy_id}" "${pipeline_id}" \
        "${repository_id}" "${branch}" "${display_name}" || return 1
    printf '%s\n' "${changed}"
}

_azure_local_only_policy_interface_verify() { # <name> <repo> <branch> <display-name>
    if [ "$#" -ne 4 ]; then
        printf 'forge azure: canonical usage: bash hack/automation/forge.sh pipeline-policy %s %s %s "%s"\n' \
            "${_AZURE_LOCAL_ONLY_PIPELINE_NAME}" "${ADO_REPO}" "${_AZURE_LOCAL_ONLY_BRANCH}" \
            "${_AZURE_LOCAL_ONLY_POLICY_DISPLAY_NAME}" >&2
        return 64
    fi
    local name="$1" repo="$2" branch="$3" display_name="$4"
    if [ "${name}" != "${_AZURE_LOCAL_ONLY_PIPELINE_NAME}" ] \
        || [ "${repo}" != "${ADO_REPO}" ] \
        || [ "${branch}" != "${_AZURE_LOCAL_ONLY_BRANCH}" ] \
        || [ "${display_name}" != "${_AZURE_LOCAL_ONLY_POLICY_DISPLAY_NAME}" ]; then
        printf 'forge azure: canonical usage: bash hack/automation/forge.sh pipeline-policy %s %s %s "%s"\n' \
            "${_AZURE_LOCAL_ONLY_PIPELINE_NAME}" "${ADO_REPO}" "${_AZURE_LOCAL_ONLY_BRANCH}" \
            "${_AZURE_LOCAL_ONLY_POLICY_DISPLAY_NAME}" >&2
        return 64
    fi
}

_azure_pipeline_policy() { # <name> <repo> <branch> <display-name>
    _azure_local_only_policy_interface_verify "$@" || return 64
    local name="$1" repo="$2" branch="$3" display_name="$4"
    if [ "${DRY_RUN}" = "1" ]; then
        printf 'az repos show --repository %s ; az pipelines list --name %s ; az pipelines show --id <id> ; verify exact pipeline identity/type/branch/yaml ; create canonical build-validation policy if missing, otherwise exact Policy Configurations PUT for %s on branch %s ; az repos policy show --id <id> ; verify policy type/blocking/enabled/queue/cache/scope/no-path-filters\n' \
            "${repo}" \
            "${name}" "${display_name}" "${branch}"
        return 0
    fi
    local pipeline_id repository_id listed matches count policy_id current changed readback
    repository_id="$(_azure_repository_id "${repo}")" || return 1
    pipeline_id="$(_azure_pipeline_existing_verified_id \
        "${name}" "${repo}" "${repository_id}" "${branch}" "${_AZURE_LOCAL_ONLY_PIPELINE_YAML}")" || return 1

    # Search project-wide by the fixed display name so a policy whose scope
    # drifted off this repo/branch is repaired rather than hidden by filters.
    listed="$(az repos policy list \
        --org "${ADO_ORG}" --project "${ADO_PROJECT}" --output json)" || return 1
    matches="$(printf '%s' "${listed}" | jq -ce --arg display_name "${display_name}" \
        '[.[] | select(.settings.displayName == $display_name)]')" || return 1
    count="$(printf '%s' "${matches}" | jq -er 'length')" || return 1
    if [ "${count}" -gt 1 ]; then
        echo "forge azure: multiple build policies named ${display_name}; refusing ambiguous update" >&2
        return 1
    fi

    if [ "${count}" -eq 1 ]; then
        policy_id="$(printf '%s' "${matches}" | jq -er '.[0].id')" || return 1
        current="$(az repos policy show --id "${policy_id}" --org "${ADO_ORG}" --project "${ADO_PROJECT}" --output json)" \
            || return 1
        if ! printf '%s' "${current}" | jq -e --arg policy_id "${policy_id}" \
            '((.id | tostring) == $policy_id)' >/dev/null; then
            echo "forge azure: persisted policy id differs from the selected policy" >&2
            return 1
        fi
        if ! _azure_pipeline_policy_is_build_validation "${current}"; then
            echo "forge azure: policy named ${display_name} is not Azure build validation; refusing mutation" >&2
            return 1
        fi
        if ! _azure_pipeline_policy_matches "${current}" "${policy_id}" \
            "${pipeline_id}" "${repository_id}" "${branch}" "${display_name}"; then
            changed="$(_azure_pipeline_policy_put_exact "${policy_id}" "${pipeline_id}" \
                "${repository_id}" "${branch}" "${display_name}")" || return 1
            : "${changed}"
            readback="$(az repos policy show --id "${policy_id}" --org "${ADO_ORG}" --project "${ADO_PROJECT}" --output json)" \
                || return 1
        else
            readback="${current}"
        fi
    else
        changed="$(az repos policy build create \
            --blocking true \
            --enabled true \
            --manual-queue-only false \
            --queue-on-source-update-only false \
            --valid-duration 0 \
            --display-name "${display_name}" \
            --build-definition-id "${pipeline_id}" \
            --repository-id "${repository_id}" \
            --branch "${branch}" \
            --branch-match-type exact \
            --org "${ADO_ORG}" \
            --project "${ADO_PROJECT}" --output json)" || return 1
        policy_id="$(printf '%s' "${changed}" | jq -er '.id')" || {
            echo "forge azure: created build policy response has no id" >&2
            return 1
        }
        readback="$(az repos policy show --id "${policy_id}" --org "${ADO_ORG}" --project "${ADO_PROJECT}" --output json)" \
            || return 1
    fi

    _azure_pipeline_policy_verify "${readback}" "${policy_id}" "${pipeline_id}" \
        "${repository_id}" "${branch}" "${display_name}" || return 1
    printf '%s\n' "${readback}"
}

# --- Work Items (issue-* verbs map to Azure Boards) --------------------------
_azure_issue_create() { # <title> <body-file> <label-csv> [type]
    local title="$1" body_file="$2" labels="$3" type="${4:-${AZURE_WI_TYPE_BACKLOG}}"
    local tags; tags="$(printf '%s' "${labels}" | tr ',' ';')"
    # F5: description must NOT enter argv.
    # Create the work item first (title + type + tags via CLI args — these are metadata, not body).
    # Then PATCH the description via REST --in-file so body content never appears in process list.
    if [ "${DRY_RUN}" = "1" ]; then
        printf 'az boards work-item create --title %s --type "%s" --fields System.Tags=%s ; REST PATCH /wit/workitems/<id> System.Description (curl)\n' \
            "${title}" "${type}" "${tags}"
        return 0
    fi
    # `jq -er '.id'` fail-fasts when create exits 0 but returns no id (exit 1 on
    # null/missing) — never PATCH `/workitems/null`. pipefail carries an az failure.
    local wi_id
    wi_id="$(az boards work-item create --title "${title}" --type "${type}" \
        --fields "System.Tags=${tags}" \
        --org "${ADO_ORG}" --project "${ADO_PROJECT}" --output json \
        | jq -er '.id')" \
        || { echo "forge azure: work-item create returned no id" >&2; return 1; }
    # PATCH description via REST JSON-Patch so body stays in a file (off argv — F5).
    # The multilineFieldsFormat op makes System.Description render Markdown instead
    # of literal text (the field defaults to HTML). The value "Markdown" is the
    # field-format enum (capitalised) — distinct from the Comments API
    # `?format=markdown` query param (lowercase); both spellings are per Azure docs.
    # ref: azure-devops devblogs/markdown-support-arrives-for-work-items
    local tmp rc
    tmp="$(mktemp "${TMPDIR:-/tmp}/forge-azwi.XXXXXX")"
    jq -n --rawfile desc "${body_file}" \
        '[{op:"add",path:"/fields/System.Description",value:$desc},
          {op:"add",path:"/multilineFieldsFormat/System.Description",value:"Markdown"}]' > "${tmp}" || {
            rc=$?
            rm -f "${tmp}"
            return "${rc}"
        }
    _az_wit_patch "${wi_id}" "${tmp}" || rc=$?
    rm -f "${tmp}"
    [ "${rc:-0}" -eq 0 ] || return "${rc}"
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
    if _dry "${cmd[@]}"; then
        # dry-run must model BOTH side effects: the state update AND, when a comment
        # is given, the Markdown Comments API step the real path runs below.
        [ -n "${comment}" ] && printf 'REST POST /wit/workItems/%s/comments?format=markdown (curl, body off argv) --org %s\n' \
            "${n}" "${ADO_ORG}"
        return 0
    fi
    # Fail-fast: don't append a close note to a work item whose state update failed.
    "${cmd[@]}" >/dev/null || return $?
    # Add the discussion comment via the Comments API (Markdown). Write the argv
    # comment to a file first so it stays off curl's argv (F5).
    if [ -n "${comment}" ]; then
        local tmp rc
        tmp="$(mktemp "${TMPDIR:-/tmp}/forge-azclose.XXXXXX")"
        printf '%s' "${comment}" > "${tmp}"
        _az_wit_comment "${n}" "${tmp}" || rc=$?
        rm -f "${tmp}"
        [ "${rc:-0}" -eq 0 ] || return "${rc}"
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
    # Comment renders as Markdown via the Comments API (?format=markdown); the
    # legacy System.History JSON-Patch path is HTML-only. F5: body off argv.
    local n="$1" body_file="$2"
    if [ "${DRY_RUN}" = "1" ]; then
        printf 'REST POST /wit/workItems/%s/comments?format=markdown (curl, body off argv) --org %s\n' \
            "${n}" "${ADO_ORG}"
        return 0
    fi
    _az_wit_comment "${n}" "${body_file}"
}

_azure_subissue_link() { # <parent> <child>
    local -a cmd=(az boards work-item relation add --id "$2" --relation-type parent --target-id "$1" --org "${ADO_ORG}" --output json)
    _dry "${cmd[@]}" && return 0
    "${cmd[@]}" >/dev/null
}
