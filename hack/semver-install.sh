#!/usr/bin/env bash
# Dedicated fixed Linux installer; cache transport is owned by the workflow.
# ref: curl docs/cmdline-opts/retry-all-errors.md (retry transport failures).
set -euo pipefail
IFS=$'\t' read -r version platform digest < <(python3 "$(dirname "$0")/ci-semver.py" --tool-spec)
key="rss-semver-$version-$platform-$digest"
if [ "${1:-}" = --identity ]; then
    printf 'key=%s\n' "$key"
    exit 0
fi
archive="${SEMVER_ARCHIVE:?archive path required}"
bin="${SEMVER_BIN_DIR:?binary directory required}"
valid() { local actual; actual="$(sha256sum "$archive")" || return 1; [ "${actual%% *}" = "$digest" ]; }
source=cache
if ! [ -f "$archive" ] || ! valid; then
    source=download
    mkdir -p "$(dirname "$archive")"
    rm -f -- "$archive"
    url="https://github.com/obi1kenobi/cargo-semver-checks/releases/download/v$version/cargo-semver-checks-$platform.tar.gz"
    for attempt in 1 2 3 4; do
        code=0
        facts="$(curl --silent --fail --location --connect-timeout 15 --max-time 120 \
            --output "$archive" --write-out 'http=%{http_code} redirects=%{num_redirects} seconds=%{time_total}' \
            "$url" 2>/dev/null)" || code=$?
        printf 'semver download: attempt=%s host=github.com exit=%s %s\n' "$attempt" "$code" "$facts"
        if [ "$code" = 0 ] && valid; then break; fi
        rm -f -- "$archive"
        if [ "$attempt" = 4 ]; then echo 'semver install: download/checksum failed' >&2; exit 1; fi
        sleep "$attempt"
    done
fi
valid
mkdir -p "$bin"
tar -xzf "$archive" -C "$bin"
"$bin/cargo-semver-checks" --version
if [ -n "${GITHUB_PATH:-}" ]; then printf '%s\n' "$bin" >> "$GITHUB_PATH"; fi
if [ -n "${GITHUB_OUTPUT:-}" ]; then printf 'verified=true\nsource=%s\n' "$source" >> "$GITHUB_OUTPUT"; fi
