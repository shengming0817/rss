#!/usr/bin/env bash
# Shared release-identity seam for bins/server bake-in (#1496).
# Sourced by deploy/smoke.sh; also exercised by journeys production_runtime fixtures.
# Local `cargo build -p server` may still omit env (build.rs → unknown); Docker builder
# and smoke must call these helpers so unknown/empty/illegal values fail closed.
#
# Intentionally does NOT `set -euo pipefail` here — callers own shell options; functions
# return non-zero on failure so green/red fixtures can assert exit codes.

rss_require_build_identity() {
    local sha="${GIT_SHA-}"
    local date="${BUILD_DATE-}"
    if [[ -z "$sha" || "$sha" = "unknown" ]]; then
        printf 'rss_require_build_identity: GIT_SHA missing or unknown\n' >&2
        return 1
    fi
    if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
        printf 'rss_require_build_identity: GIT_SHA illegal (expect 40 lowercase hex): %s\n' "$sha" >&2
        return 1
    fi
    if [[ -z "$date" || "$date" = "unknown" ]]; then
        printf 'rss_require_build_identity: BUILD_DATE missing or unknown\n' >&2
        return 1
    fi
    if [[ ! "$date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
        printf 'rss_require_build_identity: BUILD_DATE illegal (expect UTC RFC3339 Z): %s\n' "$date" >&2
        return 1
    fi
    return 0
}

rss_assert_version_matches() {
    local output="$1"
    local sha="${GIT_SHA-}"
    local date="${BUILD_DATE-}"
    rss_require_build_identity || return 1
    printf '%s\n' "$output" | grep -qx "GIT_SHA=${sha}" \
        || {
            printf 'rss_assert_version_matches: GIT_SHA mismatch: %s\n' "$output" >&2
            return 1
        }
    printf '%s\n' "$output" | grep -qx "BUILD_DATE=${date}" \
        || {
            printf 'rss_assert_version_matches: BUILD_DATE mismatch: %s\n' "$output" >&2
            return 1
        }
    return 0
}
