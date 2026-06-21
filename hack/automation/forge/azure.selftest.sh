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
trap 'rm -f "${body}" "${ibody}" "${seen}"' EXIT

# Case I1: dry-run shape -> work-item create (with --type) + REST patch, never
# `az devops invoke`.
DRY_RUN=1
out="$(_azure_issue_create "T" "${ibody}" "backlog,pri-p2" "Product Backlog Item")"; rc=$?
DRY_RUN=0
check "issue-create dry: zero exit"        "zero"  "$(zero "$rc")"
check "issue-create dry: work-item create --type" "match" \
    "$(printf '%s' "$out" | grep -q 'az boards work-item create .*--type Product Backlog Item' && echo match || echo nomatch)"
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
