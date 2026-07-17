#!/usr/bin/env sh
set -eu

fail() {
    printf 'rss-cargo: %s\n' "$*" >&2
    exit 1
}

find_verified_sccache() {
    remaining_path=${PATH-}:
    while [ -n "$remaining_path" ]; do
        path_entry=${remaining_path%%:*}
        remaining_path=${remaining_path#*:}
        [ -n "$path_entry" ] || path_entry=.
        physical_entry=$(CDPATH='' cd -- "$path_entry" 2>/dev/null && pwd -P) || continue
        case "$physical_entry" in
            /) candidate=/sccache ;;
            *) candidate="$physical_entry/sccache" ;;
        esac
        [ -e "$candidate" ] || [ -L "$candidate" ] || continue
        if verified=$(
            "$tool_adapter" verify-sccache --candidate "$candidate" 2>/dev/null
        ); then
            printf '%s\n' "$verified"
            return 0
        fi
    done
    return 1
}

repo_root=$(/usr/bin/git rev-parse --show-toplevel)
repo_root=$(CDPATH='' cd -- "$repo_root" && pwd -P)
tool_adapter="$repo_root/.github/scripts/ci-tool-adapters.sh"
target_pool="$repo_root/hack/target-pool.py"

# Pool defaults on (N=5). Explicit 0/off restores worktree-local target.
# Dual-explicit RSS_TARGET_POOL_N + CARGO_TARGET_DIR is fail-closed.
pool_n_explicit=0
if [ "${RSS_TARGET_POOL_N+x}" = x ]; then
    pool_n_raw=$RSS_TARGET_POOL_N
    pool_n_explicit=1
else
    pool_n_raw=5
fi

cargo_target_explicit=0
if [ "${CARGO_TARGET_DIR+x}" = x ]; then
    cargo_target_explicit=1
fi

resolve_env_override_target() {
    case "$CARGO_TARGET_DIR" in
        /*) resolved_target=$CARGO_TARGET_DIR ;;
        *) resolved_target="$(pwd -P)/$CARGO_TARGET_DIR" ;;
    esac
}

case "$pool_n_raw" in
    0|off)
        if [ "$cargo_target_explicit" = 1 ]; then
            target_source=env-override
            resolve_env_override_target
        else
            target_source=config-default
            resolved_target="$repo_root/.cache/cargo-target"
        fi
        ;;
    *[!0-9]*|'')
        fail "RSS_TARGET_POOL_N must be a positive integer, 0, or off; got: $pool_n_raw"
        ;;
    *)
        if [ "$pool_n_raw" -lt 1 ]; then
            fail "RSS_TARGET_POOL_N must be a positive integer, 0, or off; got: $pool_n_raw"
        fi
        if [ "$pool_n_explicit" = 1 ] && [ "$cargo_target_explicit" = 1 ]; then
            fail "RSS_TARGET_POOL_N and CARGO_TARGET_DIR are both set; choose one"
        fi
        if [ "$cargo_target_explicit" = 1 ]; then
            target_source=env-override
            resolve_env_override_target
            printf 'rss-cargo: pool=skipped reason=env-override\n' >&2
        else
            pool_root=${RSS_TARGET_POOL_ROOT:-$HOME/.cache/rss-cargo-target-pool}
            branch=$(/usr/bin/git -C "$repo_root" rev-parse --abbrev-ref HEAD 2>/dev/null || printf '')
            resolved_target=$(
                /usr/bin/python3 "$target_pool" acquire \
                    --pool-root "$pool_root" \
                    --n "$pool_n_raw" \
                    --worktree "$repo_root" \
                    --pid "$$" \
                    --branch "$branch"
            ) || fail "target pool acquire failed"
            target_source=pool-lease
            slot_name=${resolved_target##*/}
            printf 'rss-cargo: pool=enabled n=%s slot=%s root=%s\n' \
                "$pool_n_raw" "$slot_name" "$pool_root" >&2
        fi
        ;;
esac

CARGO_TARGET_DIR=$resolved_target
export CARGO_TARGET_DIR

if [ "${CARGO_BUILD_JOBS+x}" = x ]; then
    jobs_source=env-override
else
    CARGO_BUILD_JOBS=2
    export CARGO_BUILD_JOBS
    jobs_source=default
fi

printf 'rss-cargo: target source=%s resolved=%s\n' "$target_source" "$resolved_target" >&2
printf 'rss-cargo: build-jobs source=%s value=%s\n' "$jobs_source" "$CARGO_BUILD_JOBS" >&2

# The wrapper boundary owns compiler-cache selection. Ambient wrapper values are
# never trusted, including the internal handoff used by xtask.
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC_WRAPPER
unset CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER RSS_INTERNAL_SCCACHE_PATH
if [ "${RSS_COMPILER_CACHE+x}" = x ]; then
    compiler_cache_mode=$RSS_COMPILER_CACHE
else
    compiler_cache_mode=auto
fi

case "$compiler_cache_mode" in
    off)
        printf 'rss-cargo: compiler-cache enabled=false reason=disabled\n' >&2
        ;;
    auto)
        if verified_sccache=$(find_verified_sccache); then
            sccache_spec=$("$tool_adapter" sccache-spec) ||
                fail "cannot resolve sccache spec from the tool catalog"
            IFS='|' read -r _sccache_name sccache_version _sccache_backend \
                _sccache_relative _sccache_probe <<EOF
$sccache_spec
EOF
            RUSTC_WRAPPER=$verified_sccache
            RSS_INTERNAL_SCCACHE_PATH=$verified_sccache
            CARGO_INCREMENTAL=0
            SCCACHE_IGNORE_SERVER_IO_ERROR=1
            export RUSTC_WRAPPER RSS_INTERNAL_SCCACHE_PATH CARGO_INCREMENTAL
            export SCCACHE_IGNORE_SERVER_IO_ERROR
            printf 'rss-cargo: compiler-cache enabled=true version=%s path=%s\n' \
                "$sccache_version" "$verified_sccache" >&2
        else
            printf 'rss-cargo: compiler-cache enabled=false reason=no-verified-candidate\n' >&2
        fi
        ;;
    *) fail "RSS_COMPILER_CACHE must be auto or off, got: $compiler_cache_mode" ;;
esac

exec cargo "$@"
