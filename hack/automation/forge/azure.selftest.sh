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
trap 'rm -f "${body}" "${ibody}" "${seen}" "${patched}" "${mdcap}"' EXIT

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

if [ "${fail}" -eq 0 ]; then
    echo "PASS azure.selftest.sh"
else
    echo "FAIL azure.selftest.sh"
    exit 1
fi
