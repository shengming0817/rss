#!/usr/bin/env bash
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
MAINTAIN="$SCRIPT_DIR/ci-cache-maintain.sh"
TMP_BASE=${TMPDIR:-/tmp}
TMP_ROOT=$(mktemp -d "${TMP_BASE%/}/ci-cache-maintain-selftest.XXXXXX")
FAILURES=0
trap 'rm -rf "$TMP_ROOT"' EXIT HUP INT TERM
TMP_ROOT=$(CDPATH='' cd -- "$TMP_ROOT" && pwd -P)
mkdir -p "$TMP_ROOT/work space" "$TMP_ROOT/runner temp" "$TMP_ROOT/outside"

pass() { printf 'ok - %s\n' "$1"; }
fail() { printf 'not ok - %s\n' "$1" >&2; FAILURES=$((FAILURES + 1)); }
expect_success() {
  name=$1; shift
  if "$@" >"$TMP_ROOT/stdout" 2>"$TMP_ROOT/stderr"; then pass "$name"; else fail "$name"; fi
}
expect_failure() {
  name=$1; shift
  if "$@" >"$TMP_ROOT/stdout" 2>"$TMP_ROOT/stderr"; then fail "$name"; else pass "$name"; fi
}

WORKSPACE="$TMP_ROOT/work space"
RUNNER_TEMP="$TMP_ROOT/runner temp"
TOOL_ROOT="$WORKSPACE/.cache/ci-tools/check"
FALLBACK_TARGET="$RUNNER_TEMP/rss-tool-build-target"
COMPILER_ROOT="$RUNNER_TEMP/rss-sccache-cache"
mkdir -p "$WORKSPACE/cache-data"
printf data >"$WORKSPACE/cache-data/item"

expect_success 'measure reports an integer byte count' "$MAINTAIN" measure --path "$WORKSPACE/cache-data"
case "$(cat "$TMP_ROOT/stdout")" in ''|*[!0-9]*) fail 'measure stdout is only an integer' ;; *) pass 'measure stdout is only an integer' ;; esac
expect_success 'missing cache root measures zero' "$MAINTAIN" measure --path "$WORKSPACE/missing"
if [ "$(cat "$TMP_ROOT/stdout")" = 0 ]; then pass 'missing cache root is zero'; else fail 'missing cache root is zero'; fi
ln -s "$WORKSPACE/cache-data" "$WORKSPACE/cache-link"
expect_failure 'measure rejects a symlink root' "$MAINTAIN" measure --path "$WORKSPACE/cache-link"

expect_success 'prepare roots creates isolated tool and fallback roots' "$MAINTAIN" prepare-roots --workspace "$WORKSPACE" --tool-root "$TOOL_ROOT" --runner-temp "$RUNNER_TEMP" --fallback-target "$FALLBACK_TARGET"
if [ -d "$TOOL_ROOT" ] && [ -d "$FALLBACK_TARGET" ]; then pass 'prepared roots exist'; else fail 'prepared roots exist'; fi
expect_failure 'tool root must stay below workspace' "$MAINTAIN" prepare-roots --workspace "$WORKSPACE" --tool-root "$TMP_ROOT/outside/tools" --runner-temp "$RUNNER_TEMP" --fallback-target "$FALLBACK_TARGET"
expect_failure 'fallback target must stay below runner temp' "$MAINTAIN" prepare-roots --workspace "$WORKSPACE" --tool-root "$TOOL_ROOT" --runner-temp "$RUNNER_TEMP" --fallback-target "$WORKSPACE/fallback"
expect_failure 'removed tree identity command is rejected' "$MAINTAIN" tree-identity --workspace "$WORKSPACE"
expect_failure 'removed target cleanup command is rejected' "$MAINTAIN" cleanup --workspace "$WORKSPACE" --target "$WORKSPACE/.cache/cargo-target"

hash_a=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
hash_b=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
derive_keys() {
  lane=${4:-check}
  partition=${5:-$lane}
  "$MAINTAIN" derive-keys \
    --os Linux \
    --arch X64 \
    --toolchain 1.96.0 \
    --nightly nightly-2026-04-16 \
    --lane "$lane" \
    --profile "$lane" \
    --compiler-partition "$partition" \
    --download-cache-epoch v5 \
    --tool-cache-epoch v4 \
    --compiler-cache-epoch v4 \
    --sccache-version 0.15.0 \
    --input-hash "$1" \
    --tools-hash "$hash_b" \
    --run-id "$2" \
    --run-attempt "$3"
}

expect_success 'derive keys emits the closed cache policy' derive_keys "$hash_a" 42 1
expected_keys=$(cat <<EOF
download-primary-key=rss-download-v5-Linux-X64-1.96.0-nightly-2026-04-16-check-$hash_a-check-42-1
download-input-restore-prefix=rss-download-v5-Linux-X64-1.96.0-nightly-2026-04-16-check-$hash_a-
download-restore-prefix=rss-download-v5-Linux-X64-1.96.0-nightly-2026-04-16-check-
tools-primary-key=rss-tools-v4-Linux-X64-1.96.0-nightly-2026-04-16-check-$hash_b
compiler-primary-key=rss-sccache-v4-Linux-X64-1.96.0-nightly-2026-04-16-0.15.0-check-check-$hash_a-42-1
compiler-input-restore-prefix=rss-sccache-v4-Linux-X64-1.96.0-nightly-2026-04-16-0.15.0-check-check-$hash_a-
compiler-broad-restore-prefix=rss-sccache-v4-Linux-X64-1.96.0-nightly-2026-04-16-0.15.0-check-check-
EOF
)
if [ "$(cat "$TMP_ROOT/stdout")" = "$expected_keys" ]; then pass 'derived key dimensions are exact'; else fail 'derived key dimensions are exact'; fi

derive_keys "$hash_a" 42 1 >"$TMP_ROOT/keys-a"
derive_keys "$hash_b" 43 2 >"$TMP_ROOT/keys-b"
derive_keys "$hash_a" 43 2 >"$TMP_ROOT/keys-run"
derive_keys "$hash_a" 42 1 test-affected >"$TMP_ROOT/keys-other-lane"
compiler_broad_a=$(sed -n 's/^compiler-broad-restore-prefix=//p' "$TMP_ROOT/keys-a")
compiler_broad_b=$(sed -n 's/^compiler-broad-restore-prefix=//p' "$TMP_ROOT/keys-b")
if [ "$compiler_broad_a" = "$compiler_broad_b" ]; then pass 'input and run changes retain broad compiler reuse'; else fail 'input and run changes retain broad compiler reuse'; fi
compiler_primary_a=$(sed -n 's/^compiler-primary-key=//p' "$TMP_ROOT/keys-a")
compiler_primary_run=$(sed -n 's/^compiler-primary-key=//p' "$TMP_ROOT/keys-run")
if [ "$compiler_primary_a" != "$compiler_primary_run" ]; then pass 'run and attempt produce immutable unique compiler keys'; else fail 'run and attempt produce immutable unique compiler keys'; fi
download_prefix_a=$(sed -n 's/^download-restore-prefix=//p' "$TMP_ROOT/keys-a")
download_prefix_b=$(sed -n 's/^download-restore-prefix=//p' "$TMP_ROOT/keys-b")
if [ "$download_prefix_a" = "$download_prefix_b" ]; then pass 'download input changes retain broad reuse'; else fail 'download input changes retain broad reuse'; fi
download_primary_a=$(sed -n 's/^download-primary-key=//p' "$TMP_ROOT/keys-a")
download_primary_b=$(sed -n 's/^download-primary-key=//p' "$TMP_ROOT/keys-b")
if [ "$download_primary_a" != "$download_primary_b" ]; then pass 'download input changes refresh the immutable primary'; else fail 'download input changes refresh the immutable primary'; fi
download_primary_run=$(sed -n 's/^download-primary-key=//p' "$TMP_ROOT/keys-run")
if [ "$download_primary_a" != "$download_primary_run" ]; then pass 'run and attempt produce immutable unique download keys'; else fail 'run and attempt produce immutable unique download keys'; fi
download_input_a=$(sed -n 's/^download-input-restore-prefix=//p' "$TMP_ROOT/keys-a")
download_input_run=$(sed -n 's/^download-input-restore-prefix=//p' "$TMP_ROOT/keys-run")
if [ "$download_input_a" = "$download_input_run" ]; then pass 'same download inputs retain the nearest restore prefix'; else fail 'same download inputs retain the nearest restore prefix'; fi
download_prefix_other_lane=$(sed -n 's/^download-restore-prefix=//p' "$TMP_ROOT/keys-other-lane")
if [ "$download_prefix_a" != "$download_prefix_other_lane" ]; then pass 'download lanes own independent immutable namespaces'; else fail 'download lanes own independent immutable namespaces'; fi
tools_key_a=$(sed -n 's/^tools-primary-key=//p' "$TMP_ROOT/keys-a")
tools_key_b=$(sed -n 's/^tools-primary-key=//p' "$TMP_ROOT/keys-b")
if [ "$tools_key_a" = "$tools_key_b" ]; then pass 'tool key ignores lock and compiler input changes'; else fail 'tool key ignores lock and compiler input changes'; fi

expect_success 'empty nightly normalizes to none' "$MAINTAIN" derive-keys --os Linux --arch ARM64 --toolchain 1.96.0 --nightly '' --lane audit --profile audit --compiler-partition audit --download-cache-epoch v6 --tool-cache-epoch v4 --compiler-cache-epoch v4 --sccache-version 0.15.0 --input-hash "$hash_b" --tools-hash "$hash_a" --run-id 9 --run-attempt 1
if grep -q -- '-none-' "$TMP_ROOT/stdout"; then pass 'normalized nightly is represented in every applicable namespace'; else fail 'normalized nightly is represented in every applicable namespace'; fi
expect_failure 'derive keys rejects an open lane' "$MAINTAIN" derive-keys --os Linux --arch X64 --toolchain 1.96.0 --nightly '' --lane legacy --profile legacy --compiler-partition legacy --download-cache-epoch v6 --tool-cache-epoch v4 --compiler-cache-epoch v4 --sccache-version 0.15.0 --input-hash "$hash_b" --tools-hash "$hash_a" --run-id 9 --run-attempt 1
expect_failure 'derive keys rejects lane and profile drift' "$MAINTAIN" derive-keys --os Linux --arch X64 --toolchain 1.96.0 --nightly '' --lane check --profile audit --compiler-partition check --download-cache-epoch v6 --tool-cache-epoch v4 --compiler-cache-epoch v4 --sccache-version 0.15.0 --input-hash "$hash_b" --tools-hash "$hash_a" --run-id 9 --run-attempt 1
expect_failure 'derive keys rejects malformed hashes' "$MAINTAIN" derive-keys --os Linux --arch X64 --toolchain 1.96.0 --nightly '' --lane check --profile check --compiler-partition check --download-cache-epoch v6 --tool-cache-epoch v4 --compiler-cache-epoch v4 --sccache-version 0.15.0 --input-hash short --tools-hash "$hash_a" --run-id 9 --run-attempt 1
expect_failure 'derive keys rejects unknown arguments' "$MAINTAIN" derive-keys --os Linux --arch X64 --toolchain 1.96.0 --nightly '' --lane check --profile check --compiler-partition check --download-cache-epoch v6 --tool-cache-epoch v4 --compiler-cache-epoch v4 --sccache-version 0.15.0 --input-hash "$hash_b" --tools-hash "$hash_a" --run-id 9 --run-attempt 1 --unknown value

expect_success 'integration compiler partitions are isolated' derive_keys "$hash_a" 42 1 integration-critical postgres
postgres_compiler=$(sed -n 's/^compiler-primary-key=//p' "$TMP_ROOT/stdout")
postgres_download=$(sed -n 's/^download-primary-key=//p' "$TMP_ROOT/stdout")
postgres_download_restore=$(sed -n 's/^download-input-restore-prefix=//p' "$TMP_ROOT/stdout")
expect_success 'second integration compiler partition is valid' derive_keys "$hash_a" 42 1 integration-critical transport
transport_compiler=$(sed -n 's/^compiler-primary-key=//p' "$TMP_ROOT/stdout")
transport_download=$(sed -n 's/^download-primary-key=//p' "$TMP_ROOT/stdout")
transport_download_restore=$(sed -n 's/^download-input-restore-prefix=//p' "$TMP_ROOT/stdout")
if [ "$postgres_compiler" != "$transport_compiler" ]; then pass 'integration compiler partitions are isolated'; else fail 'integration compiler partitions are isolated'; fi
if [ "$postgres_download" != "$transport_download" ]; then pass 'integration download writers use immutable partitioned primaries'; else fail 'integration download writers use immutable partitioned primaries'; fi
if [ "$postgres_download_restore" = "$transport_download_restore" ]; then pass 'integration download readers retain shared input restore'; else fail 'integration download readers retain shared input restore'; fi
expect_failure 'integration rejects unpartitioned compiler identity' derive_keys "$hash_a" 42 1 integration-critical integration-critical

download_primary="rss-download-v5-Linux-X64-1.96.0-none-check-$hash_a-check-42-1"
compiler_primary="rss-sccache-v4-Linux-X64-1.96.0-none-0.15.0-check-check-$hash_b-42-1"
jq -cn \
  --arg download "$download_primary" \
  --arg compiler "$compiler_primary" \
  '{schema:"rss-ci-cache-context-v2",lane:"check",partition:"check",download:{primary:$download,restore_outcome:"success",hit:"false",matched:"rss-download-v5-Linux-X64-1.96.0-none-check-old",enabled:"true"},compiler:{primary:$compiler,restore_outcome:"success",hit:"",matched:"",enabled:"true"}}' >"$TMP_ROOT/context.json"
expect_success 'failed repository execution remains cache-save eligible' "$MAINTAIN" finalize-policy --context "$TMP_ROOT/context.json" --execution-outcome failure --save-eligible true
expected_policy=$(cat <<EOF
download-primary-key=$download_primary
compiler-primary-key=$compiler_primary
download-restore-class=prefix
compiler-restore-class=miss
sccache-enabled=true
save-cache=true
save-download=true
EOF
)
if [ "$(cat "$TMP_ROOT/stdout")" = "$expected_policy" ]; then pass 'failure save policy is exact'; else fail 'failure save policy is exact'; fi

jq '.compiler.enabled = "false"' "$TMP_ROOT/context.json" >"$TMP_ROOT/context-disabled.json"
expect_success 'disabled sccache still permits Cargo download save' "$MAINTAIN" finalize-policy --context "$TMP_ROOT/context-disabled.json" --execution-outcome success --save-eligible true
if grep -qx 'save-cache=false' "$TMP_ROOT/stdout" && grep -qx 'save-download=true' "$TMP_ROOT/stdout"; then pass 'compiler fallback does not suppress download save'; else fail 'compiler fallback does not suppress download save'; fi
jq '.download.enabled = "false"' "$TMP_ROOT/context.json" >"$TMP_ROOT/context-download-disabled.json"
expect_success 'disabled Cargo snapshot remains fail-open' "$MAINTAIN" finalize-policy --context "$TMP_ROOT/context-download-disabled.json" --execution-outcome success --save-eligible true
if grep -qx 'save-download=false' "$TMP_ROOT/stdout"; then pass 'unsafe Cargo snapshot cannot save'; else fail 'unsafe Cargo snapshot cannot save'; fi
expect_success 'cancelled execution is explicitly ineligible' "$MAINTAIN" finalize-policy --context "$TMP_ROOT/context.json" --execution-outcome cancelled --save-eligible false
if grep -qx 'save-cache=false' "$TMP_ROOT/stdout" && grep -qx 'save-download=false' "$TMP_ROOT/stdout"; then pass 'cancelled execution cannot save'; else fail 'cancelled execution cannot save'; fi
expect_failure 'outcome and eligibility disagreement fails closed' "$MAINTAIN" finalize-policy --context "$TMP_ROOT/context.json" --execution-outcome failure --save-eligible false
jq '.legacy = true' "$TMP_ROOT/context.json" >"$TMP_ROOT/context-open.json"
expect_failure 'open cache context schema fails closed' "$MAINTAIN" finalize-policy --context "$TMP_ROOT/context-open.json" --execution-outcome success --save-eligible true
ln -s "$TMP_ROOT/context.json" "$TMP_ROOT/context-link.json"
expect_failure 'symlink cache context fails closed' "$MAINTAIN" finalize-policy --context "$TMP_ROOT/context-link.json" --execution-outcome success --save-eligible true

mkdir -p "$COMPILER_ROOT/nested"
printf stale >"$COMPILER_ROOT/nested/object"
expect_success 'reset descendant recreates an exact cache root' "$MAINTAIN" reset-descendant --parent "$RUNNER_TEMP" --path "$COMPILER_ROOT"
if [ -d "$COMPILER_ROOT" ] && [ -z "$(find "$COMPILER_ROOT" -mindepth 1 -print -quit)" ]; then pass 'reset cache root is empty'; else fail 'reset cache root is empty'; fi
expect_failure 'reset descendant rejects the parent itself' "$MAINTAIN" reset-descendant --parent "$RUNNER_TEMP" --path "$RUNNER_TEMP"
expect_failure 'reset descendant rejects an escaping path' "$MAINTAIN" reset-descendant --parent "$RUNNER_TEMP" --path "$WORKSPACE/cache-data"
ln -s "$WORKSPACE/cache-data" "$RUNNER_TEMP/cache-link"
expect_success 'reset descendant safely replaces a symlink leaf' "$MAINTAIN" reset-descendant --parent "$RUNNER_TEMP" --path "$RUNNER_TEMP/cache-link"
if [ -d "$RUNNER_TEMP/cache-link" ] && [ ! -L "$RUNNER_TEMP/cache-link" ]; then pass 'reset leaf no longer aliases outside data'; else fail 'reset leaf no longer aliases outside data'; fi
ln -s "$WORKSPACE" "$RUNNER_TEMP/linked-parent"
expect_failure 'reset descendant rejects a symlink ancestor' "$MAINTAIN" reset-descendant --parent "$RUNNER_TEMP" --path "$RUNNER_TEMP/linked-parent/cache"

printf object >"$COMPILER_ROOT/object"
expect_success 'snapshot accepts a bounded non-empty cache root' "$MAINTAIN" snapshot --parent "$RUNNER_TEMP" --path "$COMPILER_ROOT" --max-bytes 2147483648
case "$(cat "$TMP_ROOT/stdout")" in ''|0|*[!0-9]*) fail 'snapshot emits positive bytes' ;; *) pass 'snapshot emits positive bytes' ;; esac
expect_failure 'snapshot rejects an over-budget cache root' "$MAINTAIN" snapshot --parent "$RUNNER_TEMP" --path "$COMPILER_ROOT" --max-bytes 1
expect_success 'reset prepares an empty snapshot fixture' "$MAINTAIN" reset-descendant --parent "$RUNNER_TEMP" --path "$COMPILER_ROOT"
expect_failure 'snapshot rejects an empty cache root' "$MAINTAIN" snapshot --parent "$RUNNER_TEMP" --path "$COMPILER_ROOT" --max-bytes 2147483648
expect_failure 'snapshot rejects a root outside the parent' "$MAINTAIN" snapshot --parent "$RUNNER_TEMP" --path "$WORKSPACE/cache-data" --max-bytes 2147483648

if [ "$FAILURES" -ne 0 ]; then
  printf '%s cache maintenance selftest(s) failed\n' "$FAILURES" >&2
  exit 1
fi
printf 'all ci cache maintenance selftests passed\n'
