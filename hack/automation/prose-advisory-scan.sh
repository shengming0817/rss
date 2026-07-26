#!/usr/bin/env bash
# Scheduled-only advisory scan for stale security and tenancy prose.
# Findings are deliberately non-blocking: scan mode always exits successfully.

set -u

usage() {
    printf 'usage: %s [scan [ROOT] | selftest]\n' "$0" >&2
}

github_command_data() {
    local value=$1
    value=${value//'%'/'%25'}
    value=${value//$'\r'/'%0D'}
    value=${value//$'\n'/'%0A'}
    printf '%s' "$value"
}

github_command_property() {
    local value
    value=$(github_command_data "$1")
    value=${value//':'/'%3A'}
    value=${value//','/'%2C'}
    printf '%s' "$value"
}

emit_github_warning() {
    local title message path=${3:-} line=${4:-}
    [ "${GITHUB_ACTIONS:-}" = true ] || return 0
    title=$(github_command_property "$1")
    message=$(github_command_data "$2")
    if [ -n "$path" ] && [[ "$line" =~ ^[0-9]+$ ]]; then
        path=$(github_command_property "$path")
        printf '::warning file=%s,line=%s,title=%s::%s\n' "$path" "$line" "$title" "$message"
    else
        printf '::warning title=%s::%s\n' "$title" "$message"
    fi
}

scan_root() {
    local root=$1
    local findings=0
    local errors=0
    local category pattern output status match path line text category_findings category_errors
    local -a checks=(
        'opa-parity|full[[:space:]-]+parity|drop[[:space:]-]+in[[:space:]-]+replacement|OPA[[:space:]/-]*Rego[[:space:]-]+compatible'
        'rls-fieldmask|RLS[[:space:]-]+(alone|only)[[:space:]-]+solves[[:space:]-]+tenancy|FieldMask[[:space:]-]+(equals|is)[[:space:]-]+encryption'
        'service-identity-gap|内部[[:space:]]+svc-to-svc[[:space:]]+现阶段用[[:space:]]+service-token|(service[[:space:]-]*token|mTLS|AuthScheme::Mtls).*(验签空窗|verifier[[:space:]-]+gap|无[[:space:]]*verifier[[:space:]]*实现|仅作.*预留|MAC[[:space:]]+binding[[:space:]]+尚未实装)'
        'tenant-rls-stale|(tenantless|actorless).*(command|outbox).*(allowed|supported|permitted|默认|允许|无需)|tenant/AuthZ/projection[[:space:]]+lint[[:space:]]+待补|full-path[[:space:]]+ledger.*随后续[[:space:]]+RLS[[:space:]]+PR[[:space:]]+落地'
    )

    if [ "${GITHUB_ACTIONS:-}" = true ] && [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        {
            printf '### Prose advisory scan\n\n'
            printf '| Category | Findings | Scan errors |\n'
            printf '|---|---:|---:|\n'
        } >> "$GITHUB_STEP_SUMMARY"
    fi

    for check in "${checks[@]}"; do
        category=${check%%|*}
        pattern=${check#*|}
        category_findings=0
        category_errors=0
        output=$(cd "$root" && rg --line-number --with-filename --color never --ignore-case --hidden \
            --glob '*.md' \
            --glob '!.git/**' \
            --glob '!target/**' \
            --glob '!worktrees/**' \
            --glob '!generated/**' \
            --glob '!xtask/tests/golden/**' \
            -- "$pattern" . 2>&1)
        status=$?
        if [ "$status" -eq 1 ]; then
            :
        elif [ "$status" -ne 0 ]; then
            printf 'prose-advisory: scan-error category=%s detail=%s\n' "$category" "$output" >&2
            emit_github_warning "Prose advisory scan error" "category=$category detail=$output"
            errors=$((errors + 1))
            category_errors=1
        else
            while IFS= read -r match; do
                [ -n "$match" ] || continue
                path=${match%%:*}
                text=${match#*:}
                line=${text%%:*}
                text=${text#*:}
                printf 'prose-advisory: finding category=%s path=%s line=%s text=%s\n' \
                    "$category" "$path" "$line" "$text"
                emit_github_warning "Prose advisory: $category" "$text" "$path" "$line"
                findings=$((findings + 1))
                category_findings=$((category_findings + 1))
            done <<< "$output"
        fi
        if [ "${GITHUB_ACTIONS:-}" = true ] && [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
            printf '| %s | %s | %s |\n' \
                "$category" "$category_findings" "$category_errors" >> "$GITHUB_STEP_SUMMARY"
        fi
    done

    printf 'prose-advisory: complete findings=%s scan_errors=%s blocking=false\n' "$findings" "$errors"
    if [ "${GITHUB_ACTIONS:-}" = true ] && [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        printf '| **Total** | **%s** | **%s** |\n\nBlocking: **false**\n' \
            "$findings" "$errors" >> "$GITHUB_STEP_SUMMARY"
    fi
    return 0
}

selftest() (
    local fixture output clean summary error_summary error_output
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/rss-prose-advisory.XXXXXX") || return 1
    trap 'rm -rf "$fixture"' EXIT
    mkdir -p "$fixture/docs" "$fixture/xtask/tests/golden"
    printf '%s\n' \
        'This claims full parity with OPA. %0A::error file=forged,line=1::injected' \
        'RLS alone solves tenancy and FieldMask equals encryption.' \
        'The mTLS verifier gap remains.' \
        'An actorless outbox is supported.' > "$fixture/docs/stale,carrier100%.md"
    printf '%s\n' 'These boundaries are explicit and backed by code.' > "$fixture/docs/clean.md"
    printf '%s\n' 'full parity' > "$fixture/xtask/tests/golden/generated.md"

    summary="$fixture/github-step-summary.md"
    output=$(GITHUB_ACTIONS=true GITHUB_STEP_SUMMARY="$summary" scan_root "$fixture") || {
        printf 'prose-advisory selftest: scan unexpectedly blocked\n' >&2
        return 1
    }
    for category in opa-parity rls-fieldmask service-identity-gap tenant-rls-stale; do
        printf '%s\n' "$output" | rg -q "category=${category}" || {
            printf 'prose-advisory selftest: missing category %s\n%s\n' "$category" "$output" >&2
            return 1
        }
    done
    printf '%s\n' "$output" | rg -q 'blocking=false' || return 1
    printf '%s\n' "$output" | rg -q '^::warning file=\./docs/stale%2Ccarrier100%25\.md,line=1,title=Prose advisory%3A opa-parity::.*%250A::error' || {
        printf 'prose-advisory selftest: finding annotation was not safely escaped\n%s\n' "$output" >&2
        return 1
    }
    [ "$(github_command_property 'carrier:name,100%')" = 'carrier%3Aname%2C100%25' ] || return 1
    rg -q '^\| opa-parity \| 1 \| 0 \|$' "$summary" || return 1
    rg -q '^\| \*\*Total\*\* \| \*\*4\*\* \| \*\*0\*\* \|$' "$summary" || return 1
    rg -q '^Blocking: \*\*false\*\*$' "$summary" || return 1
    error_summary="$fixture/github-error-summary.md"
    mkdir -p "$fixture/failing-bin"
    printf '%s\n' '#!/usr/bin/env bash' \
        'printf '\''forced rg failure %%0A::error injected\n'\'' >&2' \
        'exit 2' > "$fixture/failing-bin/rg"
    chmod +x "$fixture/failing-bin/rg"
    error_output=$(PATH="$fixture/failing-bin:$PATH" GITHUB_ACTIONS=true \
        GITHUB_STEP_SUMMARY="$error_summary" scan_root "$fixture" 2>&1) || return 1
    printf '%s\n' "$error_output" | rg -q '^::warning title=Prose advisory scan error::category=opa-parity detail=' || {
        printf 'prose-advisory selftest: scan error did not emit a warning\n%s\n' "$error_output" >&2
        return 1
    }
    printf '%s\n' "$error_output" | rg -q '%250A::error injected' || return 1
    rg -q '^\| \*\*Total\*\* \| \*\*0\*\* \| \*\*4\*\* \|$' "$error_summary" || return 1
    if printf '%s\n' "$output" | rg -q 'generated\.md'; then
        printf 'prose-advisory selftest: generated Markdown was scanned\n' >&2
        return 1
    fi

    clean=$(mktemp -d "${TMPDIR:-/tmp}/rss-prose-advisory-clean.XXXXXX") || return 1
    mkdir -p "$clean/docs"
    printf '%s\n' 'No stale compatibility or tenancy claim.' > "$clean/docs/clean.md"
    output=$(scan_root "$clean") || return 1
    rm -rf "$clean"
    printf '%s\n' "$output" | rg -q 'findings=0 scan_errors=0 blocking=false' || {
        printf 'prose-advisory selftest: clean fixture failed\n%s\n' "$output" >&2
        return 1
    }
    printf 'prose-advisory selftest: PASS\n'
)

case "${1:-scan}" in
    scan)
        scan_root "${2:-.}"
        ;;
    selftest)
        selftest
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage
        exit 64
        ;;
esac
