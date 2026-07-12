#!/usr/bin/env bash
# issue-labels.sh — guard backlog-issue label completeness (#1832).
#
# Closes the Cx labeling loop. A non-epic backlog issue must carry exactly one
# each of area-* / type-* / pri-* / cx-* — cx is now MANDATORY, symmetric to pri
# (PROJECT.md §2.6). An epic backlog issue requires area-*/pri-* and must NOT
# carry any cx-* (epic 不贴 cx — PROJECT.md :23). Non-backlog issues are out of
# scope (return ok).
#
# INVARIANT: non-epic backlog ⇒ exactly-one {area,type,pri,cx}; epic ⇒
# exactly-one {area,pri} ∧ zero cx. Callers must run `validate --labels`
# successfully before invoking `forge.sh issue-create`.
# Funnel strength (honest, per .claude/rules/rss/ai-robust.md): overall Medium.
# Downstream logic Medium (single decision point; run the golden selftest directly
# with `bash hack/automation/issue-labels.sh selftest`). Upstream
# callsite weak-Medium (skill-routed; a raw forge CLI / web-UI create bypasses it).
# True Hard (违反不可表达) is structurally unreachable — issue/work-item labels (tags)
# are external mutable state no repo-side mechanism can constrain. The unconditional `on: issues`
# CI backstop (the strong-Medium ceiling) is a deliberate future-hardening path,
# not built here.
#
# Usage:
#   issue-labels.sh validate --labels "<csv>"   pure offline validator
#   issue-labels.sh validate --issue <N>        validate a live issue (needs forge auth)
#   issue-labels.sh selftest                    offline red/green regression
# Exit: 0 ok | 1 forge/IO error | 2 validation violation | 64 usage error
#
# ref: hack/automation/pr-meta.sh — subcommand dispatch + embedded selftest shape.

set -euo pipefail

# ---- closed value sets (single source: PROJECT.md §2) -----------------------
#
# These lists mirror PROJECT.md §2.1 (area) and §2.2 (type) exactly.
# When PROJECT.md §2 changes, update both the table there AND the arrays below.
# pri and cx value sets are mathematically fixed (p0-p3, 1-4) and expressed
# as regexes in _validate_labels — no separate array needed.

# area-XX: 8 choices (PROJECT.md §2.1)
_VALID_AREAS="area-kernel area-auth area-http area-eventing area-data area-observability area-tooling area-cross"

# type-XX: 8 choices (PROJECT.md §2.2)
_VALID_TYPES="type-enhancement type-bug type-refactor type-arch-opt type-doc type-test type-debt type-fu"

# _member VALUE SET_STRING -> 0 if VALUE is a word in SET_STRING, else 1.
_member() {
    local val="$1" set_str="$2" word
    for word in ${set_str}; do
        [[ "${word}" == "${val}" ]] && return 0
    done
    return 1
}

# _check_member AXIS_LABEL VALID_SET LABELS -> 0 ok | sets rc=1 and prints error.
# Scans LABELS for any token matching ^AXIS_PREFIX and verifies it is in VALID_SET.
# Used for area and type axes where the prefix scan already guarantees exactly-one,
# so this finds the single value and validates membership.
_check_axis_member() {
    local prefix="$1" valid_set="$2" labels="$3"
    local val rc=0
    while IFS= read -r val; do
        [[ -z "${val}" ]] && continue
        if ! _member "${val}" "${valid_set}"; then
            echo "  - invalid ${val}: not in valid set (${valid_set})" >&2
            rc=1
        fi
    done < <(printf '%s\n' "${labels}" | grep -E "^${prefix}")
    return "${rc}"
}

# ---- core -------------------------------------------------------------------

# _normalize CSV -> newline-separated, trimmed, blank-stripped label list.
_normalize() {
    printf '%s' "$1" \
        | tr ',' '\n' \
        | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
        | grep -v '^[[:space:]]*$' || true
}

# _count REGEX LABELS -> number of labels matching REGEX (anchored by caller).
_count() {
    printf '%s\n' "$2" | grep -cE "$1" || true
}

# _require_one NAME COUNT -> 0 ok; prints + returns 1 on missing/conflict.
_require_one() {
    local name="$1" count="$2"
    if [[ "${count}" -eq 0 ]]; then
        echo "  - missing ${name} label (exactly 1 required)" >&2
        return 1
    fi
    if [[ "${count}" -gt 1 ]]; then
        echo "  - conflict: ${count} ${name} labels (exactly 1 required)" >&2
        return 1
    fi
    return 0
}

# _validate_labels CSV -> 0 ok | 2 violation. Prints violations to stderr.
#
# Axis membership: pri/cx use value-exact regexes (pri-p0..p3, cx-1..cx-4) — these
# axes have small, mathematically-fixed value sets, so value-exactness is drift-free
# and load-bearing: it rejects cx-unknown (deliberately unsupported, #1832) and
# out-of-range typos. Because the count is valid-only, an invalid same-axis extra
# (cx-1 + cx-unknown, pri-p2 + pri-p10) would slip past a valid-count check — so we
# also require any-count == valid-count for pri/cx (#1838 F1).
# area/type: prefix-count enforces exactly-one; _check_axis_member enforces closed-set
# membership against _VALID_AREAS/_VALID_TYPES (PROJECT.md §2.1/§2.2). GitHub time:
# server-side label existence provided this backstop. Azure Boards tags are free-text
# so the validator must enforce it explicitly (F8 regression fix).
# _validate_labels CSV [TIER] -> 0 ok | 2 violation.
# TIER (PROJECT.md §1.1 Work Item Type 三层映射): pbi|feature|epic|"" — the structure
# axis. Container tiers (epic/feature) carry area+pri only and forbid type/cx; the PBI
# leaf requires area+type+pri+cx. Empty TIER infers from the `epic` label (else pbi) so
# the label-only callers (PBI pre-create gate, epic-label create) keep working; Feature has no
# label marker by design (tier is the native Work Item Type), so it needs `--tier feature`.
_validate_labels() {
    local labels tier="${2:-}"
    labels="$(_normalize "$1")"

    # Out of scope: only backlog issues are governed.
    printf '%s\n' "${labels}" | grep -qx 'backlog' || return 0

    local area type pri pri_any cx cx_any is_epic container=0
    area="$(_count '^area-' "${labels}")"
    type="$(_count '^type-' "${labels}")"
    pri="$(_count '^pri-p[0-3]$' "${labels}")"
    pri_any="$(_count '^pri-' "${labels}")"
    cx="$(_count '^cx-[1-4]$' "${labels}")"
    cx_any="$(_count '^cx-' "${labels}")"
    is_epic="$(_count '^epic$' "${labels}")"
    # Effective tier: explicit --tier wins; else `epic` label => epic container; else pbi.
    case "${tier}" in
        epic|feature) container=1 ;;
        pbi)          container=0 ;;
        *)            [[ "${is_epic}" -gt 0 ]] && container=1 ;;
    esac

    local rc=0
    _require_one 'area' "${area}" || rc=1
    _require_one 'pri (pri-p0..p3)' "${pri}" || rc=1
    # Value-locked axes: a valid value can coexist with an invalid same-axis label
    # (pri-p2+pri-p10, cx-1+cx-unknown) that the valid-only count ignores — reject
    # via any==valid. pri applies to epic + non-epic alike.
    [[ "${pri_any}" -le "${pri}" ]] || { echo "  - invalid pri-* label present (only pri-p0..p3)" >&2; rc=1; }
    # Member validation: area and type values must belong to the closed sets defined
    # above (PROJECT.md §2.1/§2.2). This restores the rejection that GitHub's server-
    # side label enforcement provided; Azure Boards tags are free-text so we enforce
    # here instead.
    _check_axis_member 'area-' "${_VALID_AREAS}" "${labels}" || rc=1
    if [[ "${container}" -gt 0 ]]; then
        # Container tiers (epic/feature) carry area+pri only — forbid cx AND type
        # (§1.1: 跨多 PR、无单一 diff). cx_any/type (not cx) so a cx-unknown / typo is
        # also rejected on a container.
        if [[ "${cx_any}" -gt 0 ]]; then
            echo "  - epic/feature container must not carry cx-* (§1.1)" >&2
            rc=1
        fi
        if [[ "${type}" -gt 0 ]]; then
            echo "  - epic/feature container must not carry type-* (§1.1)" >&2
            rc=1
        fi
    else
        _require_one 'type' "${type}" || rc=1
        _check_axis_member 'type-' "${_VALID_TYPES}" "${labels}" || rc=1
        _require_one 'cx (cx-1..cx-4)' "${cx}" || rc=1
        [[ "${cx_any}" -le "${cx}" ]] || { echo "  - invalid cx-* label present (only cx-1..cx-4; cx-unknown unsupported, #1832)" >&2; rc=1; }
    fi

    if [[ "${rc}" -ne 0 ]]; then
        echo "issue-labels: backlog label set incomplete: $1" >&2
        return 2
    fi
    return 0
}

# ---- subcommands ------------------------------------------------------------

cmd_validate() {
    local labels="" issue="" have_labels=0 tier=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --labels)   [[ $# -ge 2 ]] || { echo "issue-labels validate: --labels requires a value" >&2; return 64; }
                        labels="$2"; have_labels=1; shift 2 ;;
            --labels=*) labels="${1#*=}"; have_labels=1; shift ;;
            --issue)    [[ $# -ge 2 ]] || { echo "issue-labels validate: --issue requires a value" >&2; return 64; }
                        issue="$2"; shift 2 ;;
            --issue=*)  issue="${1#*=}"; shift ;;
            --tier)     [[ $# -ge 2 ]] || { echo "issue-labels validate: --tier requires a value" >&2; return 64; }
                        tier="$2"; shift 2 ;;
            --tier=*)   tier="${1#*=}"; shift ;;
            *) echo "issue-labels validate: unknown flag '$1'" >&2; return 64 ;;
        esac
    done

    # --tier (PROJECT.md §1.1): structure axis. pbi leaf (default) vs epic/feature container.
    case "${tier}" in
        ""|pbi|feature|epic) ;;
        *) echo "issue-labels validate: invalid --tier '${tier}' (pbi|feature|epic)" >&2; return 64 ;;
    esac

    if [[ -n "${issue}" ]]; then
        local forge_sh view
        forge_sh="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/forge.sh"
        view="$(bash "${forge_sh}" issue-view "${issue}")" \
            || { echo "issue-labels: forge issue-view ${issue} failed" >&2; return 1; }
        labels="$(printf '%s' "${view}" | jq -r '.labels | join(",")')"
    elif [[ "${have_labels}" -eq 0 ]]; then
        echo "issue-labels validate: --labels or --issue required" >&2
        return 64
    fi

    local rc=0
    _validate_labels "${labels}" "${tier}" || rc=$?
    return "${rc}"
}

cmd_selftest() {
    local pass=0 fail=0
    _expect() {  # NAME WANT_RC -- validate-args...
        local name="$1" want="$2"; shift 2
        local got=0
        cmd_validate "$@" >/dev/null 2>&1 || got=$?
        if [[ "${got}" -eq "${want}" ]]; then
            echo "PASS [${name}]"; pass=$((pass + 1))
        else
            echo "FAIL [${name}]: want rc=${want} got rc=${got}"; fail=$((fail + 1))
        fi
    }

    # non-epic backlog, all four axes present -> ok
    _expect "complete"      0 --labels "backlog,area-tooling,type-debt,pri-p2,cx-1"
    # the #1829/#1830 case: cx omitted -> violation
    _expect "missing-cx"    2 --labels "backlog,area-tooling,type-debt,pri-p2"
    _expect "missing-pri"   2 --labels "backlog,area-tooling,type-debt,cx-1"
    _expect "missing-area"  2 --labels "backlog,type-debt,pri-p2,cx-1"
    _expect "missing-type"  2 --labels "backlog,area-tooling,pri-p2,cx-1"
    # two cx labels -> conflict
    _expect "double-cx"     2 --labels "backlog,area-tooling,type-debt,pri-p2,cx-1,cx-2"
    # epic backlog: area+pri, no cx, no type required -> ok
    _expect "epic-ok"       0 --labels "epic,backlog,area-tooling,pri-p2"
    # epic must not carry cx
    _expect "epic-with-cx"  2 --labels "epic,backlog,area-tooling,pri-p2,cx-1"
    # epic is a container: must not carry type either (§1.1 tier mapping)
    _expect "epic-with-type" 2 --labels "epic,backlog,area-tooling,type-debt,pri-p2"
    # --- tier axis (PROJECT.md §1.1): container tiers forbid type/cx, leaf requires both ---
    # Feature container (no epic label) recognized via --tier: area+pri only -> ok
    _expect "feature-ok"        0 --labels "backlog,area-tooling,pri-p2" --tier feature
    # Feature container must not carry cx / type
    _expect "feature-with-cx"   2 --labels "backlog,area-tooling,pri-p2,cx-1" --tier feature
    _expect "feature-with-type" 2 --labels "backlog,area-tooling,type-debt,pri-p2" --tier feature
    # explicit --tier epic equivalent to epic label
    _expect "epic-tier-flag-ok" 0 --labels "backlog,area-tooling,pri-p2" --tier epic
    # explicit --tier pbi: leaf still requires type+cx
    _expect "pbi-tier-explicit" 0 --labels "backlog,area-tooling,type-debt,pri-p2,cx-1" --tier pbi
    _expect "pbi-tier-missing-cx" 2 --labels "backlog,area-tooling,type-debt,pri-p2" --tier pbi
    # invalid tier value -> usage error
    _expect "bad-tier"         64 --labels "backlog,area-tooling,pri-p2" --tier bogus
    # not a backlog issue -> out of scope, ok
    _expect "non-backlog"   0 --labels "area-tooling,type-debt,pri-p2"
    # tolerates whitespace + orthogonal flag labels
    _expect "ws-and-flag"   0 --labels "backlog, area-tooling , type-debt, pri-p2, cx-3, flag-cond"
    # empty set -> out of scope (no backlog) — locks _normalize / out-of-scope path
    _expect "empty-labels"  0 --labels ""
    # cx-unknown is deliberately unsupported (#1832): not a valid cx -> violation
    _expect "cx-unknown"    2 --labels "backlog,area-tooling,type-debt,pri-p2,cx-unknown"
    # out-of-range cx (Cx5+ must be split, §3.2) is not a valid cx -> violation
    _expect "cx-out-of-range" 2 --labels "backlog,area-tooling,type-debt,pri-p2,cx-5"
    # invalid pri value (only pri-p0..p3) -> violation
    _expect "pri-invalid"   2 --labels "backlog,area-tooling,type-debt,pri-p10,cx-1"
    # epic carrying cx-unknown still rejected (epic forbid uses cx_any, not cx-1..4)
    _expect "epic-cx-unknown" 2 --labels "epic,backlog,area-tooling,pri-p2,cx-unknown"
    # valid value + invalid same-axis extra must be rejected (#1838 F1, Codex review)
    _expect "cx1-plus-unknown" 2 --labels "backlog,area-tooling,type-debt,pri-p2,cx-1,cx-unknown"
    _expect "cx1-plus-cx5"     2 --labels "backlog,area-tooling,type-debt,pri-p2,cx-1,cx-5"
    _expect "pri2-plus-pri10"  2 --labels "backlog,area-tooling,type-debt,pri-p2,pri-p10,cx-1"
    # member validation: invalid area value must be rejected (Azure tag free-text regression)
    _expect "area-typo"      2 --labels "backlog,area-typo,type-bug,pri-p2,cx-2"
    _expect "type-bogus"     2 --labels "backlog,area-tooling,type-bogus,pri-p2,cx-2"
    # member validation: all valid area and type values pass
    _expect "all-areas-valid" 0 --labels "backlog,area-cross,type-enhancement,pri-p1,cx-3"
    # renamed away from Azure "Feature" WIT collision: legacy type-feat rejected for new issues
    _expect "type-feat-renamed" 2 --labels "backlog,area-cross,type-feat,pri-p1,cx-3"
    # epic with invalid area must also be rejected
    _expect "epic-area-typo" 2 --labels "epic,backlog,area-typo,pri-p2"
    # usage errors: missing flag value / no flag at all -> 64
    _expect "labels-no-value" 64 --labels
    _expect "issue-no-value"  64 --issue
    _expect "no-flag"       64

    echo "issue-labels selftest: ${pass} passed, ${fail} failed"
    [[ "${fail}" -eq 0 ]]
}

usage() {
    cat >&2 <<'EOF'
usage: issue-labels.sh <validate|selftest> [args]
  validate --labels "<csv>"   validate an explicit label set (offline)
  validate --issue <N>        validate a live issue's labels (needs forge auth)
  selftest                    run offline red/green regression
exit codes: 0 ok | 1 forge/IO error | 2 validation violation | 64 usage error
EOF
}

main() {
    local sub="${1:-}"
    if [[ $# -gt 0 ]]; then shift; fi
    case "${sub}" in
        validate) cmd_validate "$@" ;;
        selftest) cmd_selftest "$@" ;;
        -h|--help|help) usage; exit 0 ;;
        "") usage; exit 64 ;;
        *) echo "issue-labels: unknown subcommand '${sub}'" >&2; usage; exit 64 ;;
    esac
}

main "$@"
