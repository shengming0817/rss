#!/usr/bin/env bash
# Selftest for forge/azure.sh `_azure_pr_create` — locks the fail-fast contract
# (az error or a response without pullRequestId must NEVER yield a
# `.../pullrequest/null` fake URL). No bats/harness in-repo; this is a
# self-contained, offline test. Run: bash hack/automation/forge/azure.selftest.sh
#
# SC2329: the `az()` stubs below are invoked indirectly (resolved by command
# name inside `_azure_pr_create`), which shellcheck can't trace — disable here.
# shellcheck disable=SC2329
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

# Globals `azure.sh` reads from forge.conf / forge.sh (faked here).
export ADO_ORG="https://dev.azure.com/acme"
export ADO_PROJECT="proj"
export ADO_REPO="repo"
export DRY_RUN=0
URL_BASE="https://dev.azure.com/acme/proj/_git/repo"

# shellcheck source=/dev/null
. "${HERE}/azure.sh"

fail=0
check() { # <name> <expected> <actual>
    if [ "$2" = "$3" ]; then
        printf 'ok   - %s\n' "$1"
    else
        printf 'FAIL - %s\n       expected: %q\n       actual:   %q\n' "$1" "$2" "$3"
        fail=1
    fi
}
nonzero() { [ "$1" -ne 0 ] && echo nonzero || echo zero; }
zero()    { [ "$1" -eq 0 ] && echo zero || echo nonzero; }
has()     { printf '%s' "$1" | grep -q "$2" && echo dirty || echo clean; }
# `_dry` lives in forge.sh (not sourced here); faithfully stub it so functions
# that gate on it (e.g. _azure_issue_close) behave: print + return 0 under
# DRY_RUN=1, else return 1 so the real path runs.
_dry() { [ "${DRY_RUN:-0}" = "1" ] || return 1; local IFS=' '; printf '%s\n' "$*"; return 0; }

body="$(mktemp "${TMPDIR:-/tmp}/azure-selftest.XXXXXX")"
printf 'PR body line1\nline2\n' > "${body}"
trap 'rm -f "${body}"' EXIT

# Case 1: az fails -> fail-fast (non-zero), no URL emitted.
az() { return 1; }
out="$(_azure_pr_create "t" "${body}" develop feature 2>/dev/null)"; rc=$?
check "az-fail: returns non-zero"      "nonzero" "$(nonzero "$rc")"
check "az-fail: no pullrequest/null"   "clean"   "$(has "$out" 'pullrequest/null')"
check "az-fail: empty stdout"          ""        "$out"

# Case 1b: az fails AND writes stdout -> still fail-fast, no URL leaks (the
# function returns before the trailing `printf '%s' "${out}" | jq` line).
az() { printf 'partial-output{not json}'; return 1; }
out="$(_azure_pr_create "t" "${body}" develop feature 2>/dev/null)"; rc=$?
check "az-fail+stdout: returns non-zero" "nonzero" "$(nonzero "$rc")"
check "az-fail+stdout: empty stdout"     ""        "$out"

# Case 2: az ok with pullRequestId -> correct URL, zero exit.
az() { printf '{"pullRequestId":42}\n'; }
out="$(_azure_pr_create "t" "${body}" develop feature)"; rc=$?
check "az-ok: returns zero"            "zero"    "$(zero "$rc")"
check "az-ok: URL"                     "${URL_BASE}/pullrequest/42" "$out"

# Case 3: az ok but missing pullRequestId -> jq -e guards (non-zero, no null URL).
az() { printf '{}\n'; }
out="$(_azure_pr_create "t" "${body}" develop feature 2>/dev/null)"; rc=$?
check "no-id: returns non-zero"        "nonzero" "$(nonzero "$rc")"
check "no-id: no pullrequest/null"     "clean"   "$(has "$out" 'pullrequest/null')"

# Case 4: dry-run -> prints command shape, zero exit, az not invoked.
DRY_RUN=1
az() { echo "SHOULD-NOT-RUN"; return 9; }
out="$(_azure_pr_create "t" "${body}" develop feature)"; rc=$?
DRY_RUN=0
check "dry-run: returns zero"          "zero"    "$(zero "$rc")"
check "dry-run: prints az repos pr create" "match" \
    "$(printf '%s' "$out" | grep -q '^az repos pr create ' && echo match || echo nomatch)"
check "dry-run: az not invoked"        "clean"   "$(has "$out" 'SHOULD-NOT-RUN')"

# ---- _azure_issue_create ----------------------------------------------------
# Regression: the work-item description back-fill must NOT go through
# `az devops invoke --resource workitems PATCH` (its route template needs a
# {type} placeholder PATCH-by-id can't fill -> KeyError: 'type'). It funnels
# through `_az_wit_patch` (REST curl), same path the tags-replace already uses.
ibody="$(mktemp "${TMPDIR:-/tmp}/azure-selftest-ib.XXXXXX")"
printf 'finding body line1\nline2\n' > "${ibody}"
seen="$(mktemp "${TMPDIR:-/tmp}/azure-selftest-seen.XXXXXX")"
patched="$(mktemp "${TMPDIR:-/tmp}/azure-selftest-patched.XXXXXX")"
mdcap="$(mktemp "${TMPDIR:-/tmp}/azure-selftest-mdcap.XXXXXX")"
policy_body="$(mktemp "${TMPDIR:-/tmp}/azure-selftest-policy-body.XXXXXX")"
policy_cap="$(mktemp "${TMPDIR:-/tmp}/azure-selftest-policy-cap.XXXXXX")"
policy_put_seen="$(mktemp "${TMPDIR:-/tmp}/azure-selftest-policy-put.XXXXXX")"
trap 'rm -f "${body}" "${ibody}" "${seen}" "${patched}" "${mdcap}" "${policy_body}" "${policy_cap}" "${policy_put_seen}"' EXIT

# Case I1: dry-run shape -> work-item create (with --type) + REST patch, never
# `az devops invoke`.
DRY_RUN=1
out="$(_azure_issue_create "T" "${ibody}" "backlog,pri-p2" "Product Backlog Item")"; rc=$?
DRY_RUN=0
check "issue-create dry: zero exit"        "zero"  "$(zero "$rc")"
check "issue-create dry: work-item create --type" "match" \
    "$(printf '%s' "$out" | grep -q 'az boards work-item create .*--type "Product Backlog Item"' && echo match || echo nomatch)"
check "issue-create dry: REST patch not invoke" "clean" "$(has "$out" 'devops invoke')"

# Case I2: happy path -> create returns id 99, REST patch ok -> emits "#99".
az() { case "$*" in *"boards work-item create"*) printf '{"id":99}\n' ;; *) printf '{}\n' ;; esac; }
_az_wit_patch() { return 0; }
out="$(_azure_issue_create "T" "${ibody}" "backlog,pri-p2" "Product Backlog Item")"; rc=$?
check "issue-create ok: emits #99"         "#99"   "$out"
check "issue-create ok: zero exit"         "zero"  "$(zero "$rc")"

# Case I3: description patch fails -> fail-fast (non-zero), no id leaked.
_az_wit_patch() { return 1; }
out="$(_azure_issue_create "T" "${ibody}" "backlog,pri-p2" "Product Backlog Item" 2>/dev/null)"; rc=$?
check "issue-create patch-fail: non-zero"  "nonzero" "$(nonzero "$rc")"
check "issue-create patch-fail: no #id"    "clean"   "$(has "$out" '#')"

# Case I3b: create exits 0 but returns null id -> fail-fast, PATCH never sent
# (else we'd PATCH `/workitems/null`). `_az_wit_patch` records a call to ${patched}.
az() { case "$*" in *"boards work-item create"*) printf '{"id":null}\n' ;; *) printf '{}\n' ;; esac; }
: > "${patched}"
_az_wit_patch() { echo called > "${patched}"; return 0; }
out="$(_azure_issue_create "T" "${ibody}" "backlog" "Product Backlog Item" 2>/dev/null)"; rc=$?
check "issue-create null-id: non-zero"     "nonzero" "$(nonzero "$rc")"
check "issue-create null-id: no patch sent" ""       "$(cat "${patched}")"

# Case I4: explicit 4th arg type reaches `--type` (subshell records to file).
az() { case "$*" in *"boards work-item create"*) printf '%s' "$*" > "${seen}"; printf '{"id":7}\n' ;; *) printf '{}\n' ;; esac; }
_az_wit_patch() { return 0; }
_azure_issue_create "T" "${ibody}" "backlog" "Bug" >/dev/null
check "issue-create type passthrough"      "match" \
    "$(grep -q -- '--type Bug' "${seen}" && echo match || echo nomatch)"

# Case I5: omitted type falls back to AZURE_WI_TYPE_BACKLOG default.
export AZURE_WI_TYPE_BACKLOG="Product Backlog Item"
: > "${seen}"
_azure_issue_create "T" "${ibody}" "backlog" >/dev/null
check "issue-create default type"          "match" \
    "$(grep -q -- '--type Product Backlog Item' "${seen}" && echo match || echo nomatch)"

# ---- markdown rendering (work item description + comments) -------------------
# Azure work-item large-text fields (System.Description) and the legacy discussion
# field (System.History) default to HTML, so raw markdown renders literally. The
# description must carry a /multilineFieldsFormat op; comments must go through the
# dedicated Comments API (?format=markdown), NOT a System.History JSON-Patch.

# Case MD1: issue-create description patch carries BOTH the value op and the
# multilineFieldsFormat=Markdown op (else markdown renders as plain text).
az() { case "$*" in *"boards work-item create"*) printf '{"id":99}\n' ;; *) printf '{}\n' ;; esac; }
_az_wit_patch() { cp "$2" "${mdcap}"; return 0; }
: > "${mdcap}"
_azure_issue_create "T" "${ibody}" "backlog" "Product Backlog Item" >/dev/null
check "issue-create: System.Description value op present" "match" \
    "$(jq -e 'any(.[]; .path=="/fields/System.Description")' "${mdcap}" >/dev/null 2>&1 && echo match || echo nomatch)"
check "issue-create: multilineFieldsFormat Markdown op" "match" \
    "$(jq -e 'any(.[]; .path=="/multilineFieldsFormat/System.Description" and .value=="Markdown")' "${mdcap}" >/dev/null 2>&1 && echo match || echo nomatch)"

# Case MD2: _az_wit_comment hits the Comments API with ?format=markdown at the
# preview api-version that exposes CommentFormat. Stub auth + curl (capture argv).
_az_auth_header() { printf 'Authorization: Basic x'; }
# space-join argv ("$@" not "$*"): IFS-independent, and keeps "-X POST" adjacent.
curl() { printf '%s ' "$@" > "${mdcap}"; return 0; }
: > "${mdcap}"
_az_wit_comment 77 "${ibody}" >/dev/null; rc=$?
check "_az_wit_comment: zero exit"          "zero"  "$(zero "$rc")"
check "_az_wit_comment: comments?format=markdown url" "match" \
    "$(grep -q 'workItems/77/comments?format=markdown' "${mdcap}" && echo match || echo nomatch)"
check "_az_wit_comment: api-version 7.1-preview.4" "match" \
    "$(grep -q 'api-version=7.1-preview.4' "${mdcap}" && echo match || echo nomatch)"
check "_az_wit_comment: POST method"        "match" \
    "$(grep -q -- '-X POST' "${mdcap}" && echo match || echo nomatch)"
unset -f curl _az_auth_header   # restore real curl/auth for any later case

# Case MD3: issue-comment dry-run names the Comments API, never System.History.
DRY_RUN=1
out="$(_azure_issue_comment 55 "${ibody}")"; rc=$?
DRY_RUN=0
check "issue-comment dry: zero exit"        "zero"  "$(zero "$rc")"
check "issue-comment dry: comments?format=markdown" "match" \
    "$(printf '%s' "$out" | grep -q 'comments?format=markdown' && echo match || echo nomatch)"
check "issue-comment dry: not System.History" "clean" "$(has "$out" 'System.History')"

# Case MD4: issue-comment happy path funnels the body file through _az_wit_comment
# (the markdown-rendering path), not _az_wit_patch (HTML System.History). Only
# _az_wit_comment writes mdcap; _az_wit_patch is stubbed inert, so if issue-comment
# took the wrong (System.History) path mdcap stays empty -> the assertion nomatch.
_az_wit_patch() { return 0; }
_az_wit_comment() { cp "$2" "${mdcap}"; return 0; }
: > "${mdcap}"
_azure_issue_comment 55 "${ibody}"; rc=$?
check "issue-comment ok: zero exit"         "zero"  "$(zero "$rc")"
check "issue-comment ok: body via _az_wit_comment" "match" \
    "$(grep -q 'finding body line1' "${mdcap}" && echo match || echo nomatch)"

# Case MD5: issue-close discussion comment also goes through _az_wit_comment.
az() { printf '{}\n'; }   # work-item update --state returns ok
: > "${mdcap}"
_azure_issue_close 55 "" "close note via md" ; rc=$?
check "issue-close ok: zero exit"           "zero"  "$(zero "$rc")"
check "issue-close ok: comment via _az_wit_comment" "match" \
    "$(grep -q 'close note via md' "${mdcap}" && echo match || echo nomatch)"

# Case MD6: issue-close dry-run models BOTH side effects — state update AND, when a
# comment is given, the Markdown Comments API step (regression: dry-run returned
# right after the state update, hiding the comment side effect).
DRY_RUN=1
out="$(_azure_issue_close 55 "" "## closed via md")"; rc=$?
DRY_RUN=0
check "issue-close dry: zero exit"          "zero"  "$(zero "$rc")"
check "issue-close dry: state update shown" "match" \
    "$(printf '%s' "$out" | grep -q 'work-item update' && echo match || echo nomatch)"
check "issue-close dry: comment step shown" "match" \
    "$(printf '%s' "$out" | grep -q 'comments?format=markdown' && echo match || echo nomatch)"
# anti-vacuity: empty comment -> only the state update, no comment step printed.
DRY_RUN=1
out="$(_azure_issue_close 55 "" "")"; rc=$?
DRY_RUN=0
check "issue-close dry empty: zero exit"    "zero"  "$(zero "$rc")"
check "issue-close dry empty: no comment step" "clean" "$(has "$out" 'comments?format=markdown')"

# Case CFG: forge.conf regression — backlog WI type must be a real Scrum type,
# never "Issue" (this project's Scrum process template has no "Issue" -> VS402323).
# shellcheck source=/dev/null
( . "${HERE}/../forge.conf" >/dev/null 2>&1; [ -n "${AZURE_WI_TYPE_BACKLOG}" ] && [ "${AZURE_WI_TYPE_BACKLOG}" != "Issue" ] ); cfgrc=$?
check "forge.conf backlog type valid"      "zero"  "$(zero "$cfgrc")"

# Case PCFG: exact policy updates use Azure's Policy Configurations PUT API.
# The body stays in a file and therefore preserves JSON zero/false values; the
# Authorization value must stay out of curl argv.
jq -nc '{isEnabled:true,isBlocking:true,type:{id:"0609b952-1397-4640-95ec-e00a01b2c241"},settings:{queueOnSourceUpdateOnly:false,validDuration:0}}' > "${policy_body}"
: > "${policy_cap}"
_az_auth_header() { printf 'Authorization: Bearer policy-secret'; }
curl() { printf '%s\n' "$*" > "${policy_cap}"; printf '{"id":33}\n'; }
out="$(_az_policy_configuration_put 33 "${policy_body}")"; rc=$?
check "policy PUT helper: zero exit"        "zero"  "$(zero "$rc")"
check "policy PUT helper: response retained" '{"id":33}' "${out}"
check "policy PUT helper: exact endpoint"    "match" \
    "$(grep -q -- '-X PUT https://dev.azure.com/acme/proj/_apis/policy/configurations/33?api-version=7.1' "${policy_cap}" && echo match || echo nomatch)"
check "policy PUT helper: body file"         "match" \
    "$(grep -q -- "--data-binary @${policy_body}" "${policy_cap}" && echo match || echo nomatch)"
check "policy PUT helper: JSON content type"  "match" \
    "$(grep -q -- '-H Content-Type: application/json' "${policy_cap}" && echo match || echo nomatch)"
check "policy PUT helper: auth off argv"     "clean" "$(has "$(cat "${policy_cap}")" 'policy-secret')"
out="$(_az_policy_configuration_put not-an-id "${policy_body}" 2>/dev/null)"; rc=$?
check "policy PUT helper: invalid id rejected" "nonzero" "$(nonzero "$rc")"
out="$(_az_policy_configuration_put 33 "${policy_body}.missing" 2>/dev/null)"; rc=$?
check "policy PUT helper: missing body rejected" "nonzero" "$(nonzero "$rc")"
unset -f curl _az_auth_header

# ---- LocalOnly Azure carrier -------------------------------------------------
# Pipeline registration is idempotent but fail-closed: an existing definition
# must point at exactly the requested repo/branch/YAML. Policy registration may
# upsert the named policy, then MUST read the persisted object back and validate
# every blocking/scope/queue/cache field.
ADO_REPO="rss"
build_policy_type_id='0609b952-1397-4640-95ec-e00a01b2c241'
pipeline_exact='{"id":17,"name":"rss-local-only","repository":{"id":"repo-id","name":"rss","type":"TfsGit","defaultBranch":"refs/heads/develop"},"process":{"yamlFilename":"/azure-pipelines.yml"}}'
policy_exact='{"id":33,"type":{"id":"0609b952-1397-4640-95ec-e00a01b2c241","displayName":"Build"},"isBlocking":true,"isEnabled":true,"settings":{"buildDefinitionId":17,"displayName":"RSS LocalOnly Execution","manualQueueOnly":false,"queueOnSourceUpdateOnly":false,"validDuration":0,"filenamePatterns":[],"scope":[{"repositoryId":"repo-id","refName":"refs/heads/develop","matchKind":"Exact"}]}}'
policy_filename_patterns_absent="${policy_exact/,\"filenamePatterns\":[]/}"
policy_filename_patterns_null="${policy_exact/\"filenamePatterns\":[]/\"filenamePatterns\":null}"
for unfiltered in absent null empty; do
    case "${unfiltered}" in
        absent) policy_unfiltered="${policy_filename_patterns_absent}" ;;
        null) policy_unfiltered="${policy_filename_patterns_null}" ;;
        empty) policy_unfiltered="${policy_exact}" ;;
    esac
    if _azure_pipeline_policy_matches "${policy_unfiltered}" 33 17 repo-id develop "RSS LocalOnly Execution"; then
        unfiltered_rc=0
    else
        unfiltered_rc=$?
    fi
    check "policy filenamePatterns ${unfiltered}: accepted" "zero" "$(zero "${unfiltered_rc}")"
done

# Case P1: an exact existing pipeline is verified without a create side effect.
: > "${seen}"
az() {
    printf '%s\n' "$*" >> "${seen}"
    case "$*" in
        *"repos show"*) printf 'repo-id\n' ;;
        *"pipelines list"*) printf '[{"id":17,"name":"rss-local-only"}]\n' ;;
        *"pipelines show"*) printf '%s\n' "${pipeline_exact}" ;;
        *"pipelines create"*) printf '%s\n' "${pipeline_exact}" ;;
        *) printf '{}\n' ;;
    esac
}
out="$(_azure_pipeline_create rss-local-only rss develop azure-pipelines.yml)"; rc=$?
check "pipeline exact: zero exit"           "zero"  "$(zero "$rc")"
check "pipeline exact: no create"           "clean" "$(has "$(cat "${seen}")" 'pipelines create')"
check "pipeline exact: persisted read-back" "match" \
    "$(grep -q 'pipelines show' "${seen}" && echo match || echo nomatch)"

# Case P2: an existing pipeline with a different YAML path fails closed; it is
# never silently replaced or accepted.
: > "${seen}"
pipeline_drift="${pipeline_exact/\/azure-pipelines.yml/\/other.yml}"
az() {
    printf '%s\n' "$*" >> "${seen}"
    case "$*" in
        *"repos show"*) printf 'repo-id\n' ;;
        *"pipelines list"*) printf '[{"id":17,"name":"rss-local-only"}]\n' ;;
        *"pipelines show"*) printf '%s\n' "${pipeline_drift}" ;;
        *"pipelines create"*) printf '%s\n' "${pipeline_exact}" ;;
        *) printf '{}\n' ;;
    esac
}
out="$(_azure_pipeline_create rss-local-only rss develop azure-pipelines.yml 2>/dev/null)"; rc=$?
check "pipeline drift: non-zero"             "nonzero" "$(nonzero "$rc")"
check "pipeline drift: no replacement"       "clean"   "$(has "$(cat "${seen}")" 'pipelines create')"

# Case P3: a missing pipeline is created exactly once and then read back.
: > "${seen}"
az() {
    printf '%s\n' "$*" >> "${seen}"
    case "$*" in
        *"repos show"*) printf 'repo-id\n' ;;
        *"pipelines list"*) printf '[]\n' ;;
        *"pipelines create"*) printf '{"id":17}\n' ;;
        *"pipelines show"*) printf '%s\n' "${pipeline_exact}" ;;
        *) printf '{}\n' ;;
    esac
}
out="$(_azure_pipeline_create rss-local-only rss develop azure-pipelines.yml)"; rc=$?
check "pipeline missing: zero exit"          "zero"  "$(zero "$rc")"
check "pipeline missing: create once"        "1"     "$(grep -c 'pipelines create' "${seen}" || true)"
check "pipeline missing: read-back once"     "1"     "$(grep -c 'pipelines show' "${seen}" || true)"

# Case P4: name/repo-name/branch/YAML equality is insufficient. The persisted
# definition id, repository id, and Azure repository type are trust-bound too.
for drift in definition-id repository-id repository-type; do
    : > "${seen}"
    case "${drift}" in
        definition-id) pipeline_identity_drift="${pipeline_exact/\"id\":17/\"id\":18}" ;;
        repository-id) pipeline_identity_drift="${pipeline_exact/\"id\":\"repo-id\"/\"id\":\"other-repo\"}" ;;
        repository-type) pipeline_identity_drift="${pipeline_exact/\"type\":\"TfsGit\"/\"type\":\"GitHub\"}" ;;
    esac
    az() {
        printf '%s\n' "$*" >> "${seen}"
        case "$*" in
            *"pipelines list"*) printf '[{"id":17,"name":"rss-local-only"}]\n' ;;
            *"pipelines show"*) printf '%s\n' "${pipeline_identity_drift}" ;;
            *"repos show"*) printf 'repo-id\n' ;;
            *) printf '{}\n' ;;
        esac
    }
    out="$(_azure_pipeline_create rss-local-only rss develop azure-pipelines.yml 2>/dev/null)"; rc=$?
    check "pipeline ${drift} drift: non-zero" "nonzero" "$(nonzero "$rc")"
    check "pipeline ${drift} drift: no replacement" "clean" \
        "$(has "$(cat "${seen}")" 'pipelines create')"
done

# Case BP1: an exact existing blocking policy is verified without mutation.
: > "${seen}"
az() {
    printf '%s\n' "$*" >> "${seen}"
    case "$*" in
        *"pipelines list"*) printf '[{"id":17,"name":"rss-local-only"}]\n' ;;
        *"pipelines show"*) printf '%s\n' "${pipeline_exact}" ;;
        *"repos show"*) printf 'repo-id\n' ;;
        *"repos policy list"*) printf '[%s]\n' "${policy_exact}" ;;
        *"repos policy show"*) printf '%s\n' "${policy_exact}" ;;
        *) printf '{}\n' ;;
    esac
}
out="$(_azure_pipeline_policy rss-local-only rss develop "RSS LocalOnly Execution")"; rc=$?
check "policy exact: zero exit"              "zero"  "$(zero "$rc")"
check "policy exact: no create/update"       "clean" \
    "$(cat "${seen}" | grep -Eq 'policy build (create|update)' && echo dirty || echo clean)"
check "policy exact: persisted read-back"    "match" \
    "$(grep -q 'repos policy show' "${seen}" && echo match || echo nomatch)"

# Case BP2: the unique named policy may be repaired through update, but the
# persisted result is read back and all exact blocking fields are enforced.
: > "${seen}"
policy_drift='{"id":33,"type":{"id":"0609b952-1397-4640-95ec-e00a01b2c241","displayName":"Build"},"isBlocking":false,"isEnabled":true,"settings":{"buildDefinitionId":17,"displayName":"RSS LocalOnly Execution","manualQueueOnly":true,"queueOnSourceUpdateOnly":true,"validDuration":30,"scope":[{"repositoryId":"repo-id","refName":"refs/heads/develop","matchKind":"Exact"}]}}'
: > "${policy_put_seen}"
_az_policy_configuration_put() {
    printf '%s\n' "$1" > "${policy_put_seen}"
    cp "$2" "${policy_cap}"
    printf '%s\n' "${policy_exact}"
}
az() {
    printf '%s\n' "$*" >> "${seen}"
    case "$*" in
        *"pipelines list"*) printf '[{"id":17,"name":"rss-local-only"}]\n' ;;
        *"pipelines show"*) printf '%s\n' "${pipeline_exact}" ;;
        *"repos show"*) printf 'repo-id\n' ;;
        *"repos policy list"*) printf '[%s]\n' "${policy_drift}" ;;
        *"repos policy show"*)
            if [ ! -s "${policy_put_seen}" ]; then
                printf '%s\n' "${policy_drift}"
            else
                printf '%s\n' "${policy_exact}"
            fi
            ;;
        *) printf '{}\n' ;;
    esac
}
out="$(_azure_pipeline_policy rss-local-only rss develop "RSS LocalOnly Execution")"; rc=$?
check "policy drift: zero after repair"       "zero"  "$(zero "$rc")"
check "policy drift: exact PUT used"           "33"    "$(cat "${policy_put_seen}")"
check "policy drift: no lossy CLI update"      "clean" \
    "$(has "$(cat "${seen}")" 'repos policy build update')"
check "policy drift: exact false/zero body"    "match" \
    "$(jq -e '.isBlocking == true and .isEnabled == true and .settings.manualQueueOnly == false and .settings.queueOnSourceUpdateOnly == false and .settings.validDuration == 0' "${policy_cap}" >/dev/null && echo match || echo nomatch)"

# Case BP3: a lying/lagging server read-back still fails closed after update.
: > "${seen}"
policy_bad_readback='{"id":33,"type":{"id":"0609b952-1397-4640-95ec-e00a01b2c241","displayName":"Build"},"isBlocking":true,"isEnabled":true,"settings":{"buildDefinitionId":17,"displayName":"RSS LocalOnly Execution","manualQueueOnly":false,"queueOnSourceUpdateOnly":false,"validDuration":30,"scope":[{"repositoryId":"repo-id","refName":"refs/heads/develop","matchKind":"Exact"}]}}'
: > "${policy_put_seen}"
_az_policy_configuration_put() {
    printf '%s\n' "$1" > "${policy_put_seen}"
    cp "$2" "${policy_cap}"
    printf '%s\n' "${policy_exact}"
}
az() {
    printf '%s\n' "$*" >> "${seen}"
    case "$*" in
        *"pipelines list"*) printf '[{"id":17,"name":"rss-local-only"}]\n' ;;
        *"pipelines show"*) printf '%s\n' "${pipeline_exact}" ;;
        *"repos show"*) printf 'repo-id\n' ;;
        *"repos policy list"*) printf '[%s]\n' "${policy_drift}" ;;
        *"repos policy show"*)
            if [ ! -s "${policy_put_seen}" ]; then
                printf '%s\n' "${policy_drift}"
            else
                printf '%s\n' "${policy_bad_readback}"
            fi
            ;;
        *) printf '{}\n' ;;
    esac
}
out="$(_azure_pipeline_policy rss-local-only rss develop "RSS LocalOnly Execution" 2>/dev/null)"; rc=$?
check "policy bad read-back: non-zero"        "nonzero" "$(nonzero "$rc")"
check "policy bad read-back: exact PUT used"  "33"      "$(cat "${policy_put_seen}")"

# Case BP4: no named policy creates one and still reads persisted state back.
: > "${seen}"
az() {
    printf '%s\n' "$*" >> "${seen}"
    case "$*" in
        *"pipelines list"*) printf '[{"id":17,"name":"rss-local-only"}]\n' ;;
        *"pipelines show"*) printf '%s\n' "${pipeline_exact}" ;;
        *"repos show"*) printf 'repo-id\n' ;;
        *"repos policy list"*) printf '[]\n' ;;
        *"repos policy build create"*) printf '{"id":33}\n' ;;
        *"repos policy show"*) printf '%s\n' "${policy_exact}" ;;
        *) printf '{}\n' ;;
    esac
}
out="$(_azure_pipeline_policy rss-local-only rss develop "RSS LocalOnly Execution")"; rc=$?
check "policy missing: zero exit"             "zero"  "$(zero "$rc")"
check "policy missing: create once"           "1"     "$(grep -c 'repos policy build create' "${seen}" || true)"
check "policy missing: read-back once"        "1"     "$(grep -c 'repos policy show' "${seen}" || true)"
check "policy missing: exact false/zero create" "match" \
    "$(grep 'repos policy build create' "${seen}" | grep -q -- '--queue-on-source-update-only false .*--valid-duration 0' && echo match || echo nomatch)"

# Case BP5: policy registration must re-verify the complete pipeline definition,
# not trust a name-only `--query id` lookup that can bind a drifted definition.
: > "${seen}"
pipeline_wrong_repo="${pipeline_exact/\"id\":\"repo-id\"/\"id\":\"other-repo\"}"
az() {
    printf '%s\n' "$*" >> "${seen}"
    case "$*" in
        *"pipelines list"*) printf '[{"id":17,"name":"rss-local-only"}]\n' ;;
        *"pipelines show"*"--query id"*) printf '17\n' ;;
        *"pipelines show"*) printf '%s\n' "${pipeline_wrong_repo}" ;;
        *"repos show"*) printf 'repo-id\n' ;;
        *"repos policy list"*) printf '[%s]\n' "${policy_exact}" ;;
        *"repos policy show"*) printf '%s\n' "${policy_exact}" ;;
        *) printf '{}\n' ;;
    esac
}
out="$(_azure_pipeline_policy rss-local-only rss develop "RSS LocalOnly Execution" 2>/dev/null)"; rc=$?
check "policy registration: drifted definition rejected" "nonzero" "$(nonzero "$rc")"
check "policy registration: no mutation after definition drift" "clean" \
    "$(cat "${seen}" | grep -Eq 'policy build (create|update)' && echo dirty || echo clean)"

# Case BP6: the named object must be Azure's build-validation policy type. A
# different policy kind with the same display name is rejected before mutation.
: > "${seen}"
policy_wrong_type="${policy_exact/${build_policy_type_id}/11111111-1111-1111-1111-111111111111}"
az() {
    printf '%s\n' "$*" >> "${seen}"
    case "$*" in
        *"pipelines list"*) printf '[{"id":17,"name":"rss-local-only"}]\n' ;;
        *"pipelines show"*"--query id"*) printf '17\n' ;;
        *"pipelines show"*) printf '%s\n' "${pipeline_exact}" ;;
        *"repos show"*) printf 'repo-id\n' ;;
        *"repos policy list"*) printf '[%s]\n' "${policy_wrong_type}" ;;
        *"repos policy build update"*) printf '{}\n' ;;
        *"repos policy show"*) printf '%s\n' "${policy_wrong_type}" ;;
        *) printf '{}\n' ;;
    esac
}
out="$(_azure_pipeline_policy rss-local-only rss develop "RSS LocalOnly Execution" 2>/dev/null)"; rc=$?
check "policy wrong type: non-zero"           "nonzero" "$(nonzero "$rc")"
check "policy wrong type: no update"          "clean" \
    "$(has "$(cat "${seen}")" 'policy build update')"

# Case BP7: path-filtered build validation is not equivalent to every-source-
# update validation. Exact PUT clears the drift instead of depending on the
# Azure CLI's lossy optional-value merge.
: > "${seen}"
: > "${policy_put_seen}"
policy_filtered="${policy_exact/\"filenamePatterns\":[]/\"filenamePatterns\":[\"\/crates\/identity\/*\"]}"
_az_policy_configuration_put() {
    printf '%s\n' "$1" > "${policy_put_seen}"
    cp "$2" "${policy_cap}"
    printf '%s\n' "${policy_exact}"
}
az() {
    printf '%s\n' "$*" >> "${seen}"
    case "$*" in
        *"pipelines list"*) printf '[{"id":17,"name":"rss-local-only"}]\n' ;;
        *"pipelines show"*) printf '%s\n' "${pipeline_exact}" ;;
        *"repos show"*) printf 'repo-id\n' ;;
        *"repos policy list"*) printf '[%s]\n' "${policy_filtered}" ;;
        *"repos policy show"*)
            if [ ! -s "${policy_put_seen}" ]; then
                printf '%s\n' "${policy_filtered}"
            else
                printf '%s\n' "${policy_exact}"
            fi
            ;;
        *) printf '{}\n' ;;
    esac
}
out="$(_azure_pipeline_policy rss-local-only rss develop "RSS LocalOnly Execution")"; rc=$?
check "policy path filter: repaired"          "zero" "$(zero "$rc")"
check "policy path filter: inspected persisted object" "match" \
    "$(grep -q 'repos policy show' "${seen}" && echo match || echo nomatch)"
check "policy path filter: exact PUT used"     "33" "$(cat "${policy_put_seen}")"
check "policy path filter: cleared in body"   "match" \
    "$(jq -e '.settings.filenamePatterns == []' "${policy_cap}" >/dev/null && echo match || echo nomatch)"

# Case PI: pipeline-policy is the #1815 canonical interface, not a generic
# policy editor. Drifted or extra argv is rejected even in dry-run mode.
DRY_RUN=1
for drift in name repo branch display extra; do
    case "${drift}" in
        name) args=(other rss develop "RSS LocalOnly Execution") ;;
        repo) args=(rss-local-only other develop "RSS LocalOnly Execution") ;;
        branch) args=(rss-local-only rss main "RSS LocalOnly Execution") ;;
        display) args=(rss-local-only rss develop "Other Policy") ;;
        extra) args=(rss-local-only rss develop "RSS LocalOnly Execution" extra) ;;
    esac
    out="$(_azure_pipeline_policy "${args[@]}" 2>&1)"; rc=$?
    check "policy interface ${drift}: non-zero" "nonzero" "$(nonzero "$rc")"
    check "policy interface ${drift}: canonical hint" "match" \
        "$(printf '%s' "${out}" | grep -q 'pipeline-policy rss-local-only rss develop "RSS LocalOnly Execution"' && echo match || echo nomatch)"
done
out="$(_azure_pipeline_policy rss-local-only rss develop "RSS LocalOnly Execution")"; rc=$?
check "policy interface canonical dry-run: zero" "zero" "$(zero "$rc")"
DRY_RUN=0
check "forge usage: policy is canonical"        "match" \
    "$(grep -q 'pipeline-policy rss-local-only <configured-repo> develop "RSS LocalOnly Execution"' "${HERE}/../forge.sh" && echo match || echo nomatch)"

# ---- _azure_branch_pr_merged ------------------------------------------------
# true only when no active PR remains and at least one completed PR used the
# source branch. Dry-run must print BOTH list shapes (active then completed).

# Case BPM1: dry-run prints active + completed list commands; az not invoked.
DRY_RUN=1
az() { echo "SHOULD-NOT-RUN"; return 9; }
out="$(_azure_branch_pr_merged feature/x)"; rc=$?
DRY_RUN=0
check "branch-pr-merged dry: zero" "zero" "$(zero "$rc")"
check "branch-pr-merged dry: active list" "match" \
    "$(printf '%s' "$out" | grep -q 'az repos pr list .*--status active' && echo match || echo nomatch)"
check "branch-pr-merged dry: completed list" "match" \
    "$(printf '%s' "$out" | grep -q 'az repos pr list .*--status completed' && echo match || echo nomatch)"
check "branch-pr-merged dry: az not invoked" "clean" "$(has "$out" 'SHOULD-NOT-RUN')"

# Case BPM2: active PR present -> false even if completed history exists.
az() {
    case "$*" in
        *"--status active"*) printf '[{"pullRequestId":1}]\n' ;;
        *"--status completed"*) printf '[{"pullRequestId":2}]\n' ;;
        *) printf '[]\n' ;;
    esac
}
out="$(_azure_branch_pr_merged feature/x)"; rc=$?
check "branch-pr-merged active: zero" "zero" "$(zero "$rc")"
check "branch-pr-merged active: false" "false" "$(printf '%s' "$out" | tr -d '\n')"

# Case BPM3: no active, has completed -> true.
az() {
    case "$*" in
        *"--status active"*) printf '[]\n' ;;
        *"--status completed"*) printf '[{"pullRequestId":9}]\n' ;;
        *) printf '[]\n' ;;
    esac
}
out="$(_azure_branch_pr_merged feature/x)"; rc=$?
check "branch-pr-merged completed: true" "true" "$(printf '%s' "$out" | tr -d '\n')"

# Case BPM4: neither -> false.
az() { printf '[]\n'; }
out="$(_azure_branch_pr_merged feature/x)"; rc=$?
check "branch-pr-merged empty: false" "false" "$(printf '%s' "$out" | tr -d '\n')"

# Case BPM5/BPM6: github + gitlab dry-run shape gates (sourced offline).
GITHUB_REPO_SLUG="acme/rss"
# shellcheck source=/dev/null
. "${HERE}/github.sh"
DRY_RUN=1
out="$(_github_branch_pr_merged feature/x)"; rc=$?
DRY_RUN=0
check "github branch-pr-merged dry: zero" "zero" "$(zero "$rc")"
check "github branch-pr-merged dry: open" "match" \
    "$(printf '%s' "$out" | grep -q 'gh pr list .*--state open' && echo match || echo nomatch)"
check "github branch-pr-merged dry: merged" "match" \
    "$(printf '%s' "$out" | grep -q 'gh pr list .*--state merged' && echo match || echo nomatch)"

# shellcheck source=/dev/null
. "${HERE}/gitlab.sh"
DRY_RUN=1
out="$(_gitlab_branch_pr_merged feature/x)"; rc=$?
DRY_RUN=0
check "gitlab branch-pr-merged dry: zero" "zero" "$(zero "$rc")"
check "gitlab branch-pr-merged dry: opened" "match" \
    "$(printf '%s' "$out" | grep -q 'glab mr list .*--opened' && echo match || echo nomatch)"
check "gitlab branch-pr-merged dry: merged" "match" \
    "$(printf '%s' "$out" | grep -q 'glab mr list .*--merged' && echo match || echo nomatch)"

# Case YAML: the checked-in pipeline is only a typed LocalOnly carrier. No
# contract ids, test names, or alternate cargo test/JUnit path may live here.
pipeline_yaml="${HERE}/../../../azure-pipelines.yml"
check "pipeline yaml: checked in"             "zero" \
    "$(if [ -f "${pipeline_yaml}" ]; then echo zero; else echo nonzero; fi)"
check "pipeline yaml: trigger none"           "match" \
    "$(grep -Eq '^trigger:[[:space:]]+none$' "${pipeline_yaml}" 2>/dev/null && echo match || echo nomatch)"
check "pipeline yaml: pr none"                "match" \
    "$(grep -Eq '^pr:[[:space:]]+none$' "${pipeline_yaml}" 2>/dev/null && echo match || echo nomatch)"
check "pipeline yaml: ubuntu pool"             "match" \
    "$(grep -Eq '^[[:space:]]+vmImage:[[:space:]]+ubuntu-latest$' "${pipeline_yaml}" 2>/dev/null && echo match || echo nomatch)"
check "pipeline yaml: full checkout"           "match" \
    "$(grep -Eq '^[[:space:]]+fetchDepth:[[:space:]]+0$' "${pipeline_yaml}" 2>/dev/null && echo match || echo nomatch)"
check "pipeline yaml: nextest pinned"         "match" \
    "$(grep -q 'cargo install --locked --version 0.9.137 cargo-nextest' "${pipeline_yaml}" 2>/dev/null && echo match || echo nomatch)"
check "pipeline yaml: one typed command"      "1" \
    "$(grep -c 'cargo run --locked -p xtask -- ci localonly-evidence --output' "${pipeline_yaml}" 2>/dev/null || true)"
check "pipeline yaml: no copied test plan"     "clean" \
    "$(grep -Eq 'cargo (test|nextest)|--filter-expr|LOCAL_ONLY_SPECS|contractIds' "${pipeline_yaml}" 2>/dev/null && echo dirty || echo clean)"
check "pipeline yaml: publish on success"      "match" \
    "$(grep -A5 'PublishPipelineArtifact@1' "${pipeline_yaml}" 2>/dev/null | grep -q 'condition: succeeded()' && echo match || echo nomatch)"

# The narrow validation is not the full observable ship CI lane.
# shellcheck source=/dev/null
( . "${HERE}/../forge.conf" >/dev/null 2>&1; [ "${AZURE_HAS_CI}" = "false" ] ); narrow_cfg_rc=$?
check "forge.conf: narrow carrier is not full CI" "zero" "$(zero "${narrow_cfg_rc}")"

if [ "${fail}" -eq 0 ]; then
    echo "PASS azure.selftest.sh"
else
    echo "FAIL azure.selftest.sh"
    exit 1
fi
