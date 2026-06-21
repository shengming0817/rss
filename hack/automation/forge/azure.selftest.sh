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

if [ "${fail}" -eq 0 ]; then
    echo "PASS azure.selftest.sh"
else
    echo "FAIL azure.selftest.sh"
    exit 1
fi
