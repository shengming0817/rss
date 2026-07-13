#!/usr/bin/env bash
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
EVIDENCE="$SCRIPT_DIR/ci-evidence.sh"
BUDGET="$SCRIPT_DIR/ci-disk-budget.sh"
GOLDEN="$SCRIPT_DIR/testdata/ci-evidence-v4.golden.json"
TMP_ROOT=${TMPDIR:-/tmp}/ci-evidence-selftest.$$
FAILURES=0

cleanup() { rm -rf "$TMP_ROOT"; }
trap cleanup EXIT HUP INT TERM
mkdir -p "$TMP_ROOT"

pass() { printf 'ok - %s\n' "$1"; }
fail() { printf 'not ok - %s\n' "$1" >&2; FAILURES=$((FAILURES + 1)); }

expect_success() {
  name=$1
  shift
  if "$@" >"$TMP_ROOT/stdout" 2>"$TMP_ROOT/stderr"; then pass "$name"; else
    sed 's/^/# /' "$TMP_ROOT/stderr" >&2 || true
    fail "$name"
  fi
}

expect_failure() {
  name=$1
  shift
  if "$@" >"$TMP_ROOT/stdout" 2>"$TMP_ROOT/stderr"; then fail "$name"; else pass "$name"; fi
}

assert_jq() {
  name=$1 file=$2 expression=$3
  if jq -e "$expression" "$file" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi
}

WORKSPACE="$TMP_ROOT/workspace"
HOME_DIR="$TMP_ROOT/home"
OUTPUT="$TMP_ROOT/evidence.json"
mkdir -p "$WORKSPACE/a/nested" "$WORKSPACE/space dir" \
  "$WORKSPACE/.config" \
  "$WORKSPACE/.cache/cargo-target/incremental/depth-two" \
  "$HOME_DIR/.cargo/registry" "$HOME_DIR/.cargo/git" "$HOME_DIR/.rustup"
cp "$SCRIPT_DIR/../../.config/ci-slo.toml" "$WORKSPACE/.config/ci-slo.toml"
set_disk_budget() {
  value=$1
  sed "s/^min_disk_free_gib = .*/min_disk_free_gib = $value/" \
    "$SCRIPT_DIR/../../.config/ci-slo.toml" >"$WORKSPACE/.config/ci-slo.toml"
}
newline_dir=$(printf 'line\nbreak')
mkdir -p "$WORKSPACE/$newline_dir"
ln -s "$TMP_ROOT" "$WORKSPACE/outside-link"
printf 'fixture\n' >"$WORKSPACE/a/data"
/usr/bin/git -C "$WORKSPACE" init -q
/usr/bin/git -C "$WORKSPACE" -c user.name='CI Evidence' -c user.email='ci-evidence@example.invalid' add .
/usr/bin/git -C "$WORKSPACE" -c user.name='CI Evidence' -c user.email='ci-evidence@example.invalid' commit -qm fixture
CHECKOUT_REVISION=$(/usr/bin/git -C "$WORKSPACE" rev-parse HEAD)

TOOL_BIN="$TMP_ROOT/tool-bin"
mkdir "$TOOL_BIN"
for command_name in bash dirname jq mktemp mv rm date find df du; do
  command_path=$(command -v "$command_name")
  ln -s "$command_path" "$TOOL_BIN/$command_name"
done
for tool_name in rustc cargo git; do
  printf '#!/bin/sh\nprintf "fixture-%s 1.0\\n"\n' "$tool_name" >"$TOOL_BIN/$tool_name"
  chmod +x "$TOOL_BIN/$tool_name"
done

run_evidence() {
  env -i PATH="$TOOL_BIN" HOME="$HOME_DIR" CARGO_HOME="$HOME_DIR/.cargo" \
    RUSTUP_HOME="$HOME_DIR/.rustup" GITHUB_WORKSPACE="$WORKSPACE" \
    GITHUB_REPOSITORY='owner/repo' GITHUB_WORKFLOW='CI' GITHUB_JOB='test' \
    GITHUB_RUN_ID='123' GITHUB_RUN_ATTEMPT='2' RUNNER_OS='Linux' RUNNER_ARCH='X64' \
    RSS_CI_JOB_KEY='ci-meta' RSS_CI_SOURCE_REVISION="${TEST_SOURCE_REVISION:-$CHECKOUT_REVISION}" \
    RSS_CI_PLAN_DIGEST='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
    SECRET_CANARY='must-not-leak-7f3a' \
    "$EVIDENCE" "$@" \
    --download-restore-result "${TEST_DOWNLOAD_RESTORE_RESULT:-miss}" --download-restored-footprint-bytes "${TEST_DOWNLOAD_RESTORED_BYTES:-0}" \
    --download-save-mode writer --download-candidate-size-bytes 4096 \
    --download-save-outcome "${TEST_DOWNLOAD_SAVE_OUTCOME:-eligible}" \
    --tools-restore-result exact --tools-restored-footprint-bytes 2048 \
    --tools-save-mode read-only --tools-candidate-size-bytes 2048 \
    --tools-save-outcome "${TEST_TOOLS_SAVE_OUTCOME:-skipped}" \
    --compiler-cache-enabled true --compiler-cache-version 0.15.0 \
    --compiler-cache-access remote-read-write --compiler-cache-requests "${TEST_COMPILER_REQUESTS:-9}" \
    --compiler-cache-hits "${TEST_COMPILER_HITS:-4}" --compiler-cache-misses "${TEST_COMPILER_MISSES:-3}" \
    --compiler-cache-non-cacheable 2 \
    --compiler-cache-error-restore "${TEST_ERROR_RESTORE:-0}" \
    --compiler-cache-error-stats "${TEST_ERROR_STATS:-0}" \
    --compiler-cache-error-cache-io "${TEST_ERROR_CACHE_IO:-0}" \
    --compiler-cache-error-no-requests "${TEST_ERROR_NO_REQUESTS:-0}" \
    --compiler-cache-error-measure "${TEST_ERROR_MEASURE:-0}" \
    --compiler-cache-error-save "${TEST_ERROR_SAVE:-0}" \
    --cpu-time-ms "${TEST_CPU_TIME_MS:-none}" --peak-rss-bytes "${TEST_PEAK_RSS_BYTES:-none}"
}

run_evidence_with_path() {
  evidence_path=$1
  shift
  env -i PATH="$evidence_path" HOME="$HOME_DIR" CARGO_HOME="$HOME_DIR/.cargo" \
    RUSTUP_HOME="$HOME_DIR/.rustup" GITHUB_WORKSPACE="$WORKSPACE" \
    GITHUB_REPOSITORY='owner/repo' GITHUB_WORKFLOW='CI' GITHUB_JOB='test' \
    GITHUB_RUN_ID='123' GITHUB_RUN_ATTEMPT='2' RUNNER_OS='Linux' RUNNER_ARCH='X64' \
    RSS_CI_JOB_KEY='ci-meta' RSS_CI_SOURCE_REVISION="${TEST_SOURCE_REVISION:-$CHECKOUT_REVISION}" \
    RSS_CI_PLAN_DIGEST='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
    SECRET_CANARY='must-not-leak-7f3a' \
    "$EVIDENCE" "$@" \
    --download-restore-result "${TEST_DOWNLOAD_RESTORE_RESULT:-miss}" --download-restored-footprint-bytes "${TEST_DOWNLOAD_RESTORED_BYTES:-0}" \
    --download-save-mode writer --download-candidate-size-bytes 4096 \
    --download-save-outcome "${TEST_DOWNLOAD_SAVE_OUTCOME:-eligible}" \
    --tools-restore-result exact --tools-restored-footprint-bytes 2048 \
    --tools-save-mode read-only --tools-candidate-size-bytes 2048 \
    --tools-save-outcome "${TEST_TOOLS_SAVE_OUTCOME:-skipped}" \
    --compiler-cache-enabled true --compiler-cache-version 0.15.0 \
    --compiler-cache-access remote-read-write --compiler-cache-requests "${TEST_COMPILER_REQUESTS:-9}" \
    --compiler-cache-hits "${TEST_COMPILER_HITS:-4}" --compiler-cache-misses "${TEST_COMPILER_MISSES:-3}" \
    --compiler-cache-non-cacheable 2 \
    --compiler-cache-error-restore "${TEST_ERROR_RESTORE:-0}" \
    --compiler-cache-error-stats "${TEST_ERROR_STATS:-0}" \
    --compiler-cache-error-cache-io "${TEST_ERROR_CACHE_IO:-0}" \
    --compiler-cache-error-no-requests "${TEST_ERROR_NO_REQUESTS:-0}" \
    --compiler-cache-error-measure "${TEST_ERROR_MEASURE:-0}" \
    --compiler-cache-error-save "${TEST_ERROR_SAVE:-0}" \
    --cpu-time-ms "${TEST_CPU_TIME_MS:-none}" --peak-rss-bytes "${TEST_PEAK_RSS_BYTES:-none}"
}

run_disabled_evidence() {
  evidence_path=$1 home_dir=$2 workspace=$3 output=$4
  if ! /usr/bin/git -C "$workspace" rev-parse HEAD >/dev/null 2>&1; then
    /usr/bin/git -C "$workspace" init -q
    /usr/bin/git -C "$workspace" -c user.name='CI Evidence' -c user.email='ci-evidence@example.invalid' commit --allow-empty -qm fixture
  fi
  checkout_revision=$(/usr/bin/git -C "$workspace" rev-parse HEAD)
  env -i PATH="$evidence_path" HOME="$home_dir" CARGO_HOME="$home_dir/.cargo" \
    RUSTUP_HOME="$home_dir/.rustup" GITHUB_WORKSPACE="$workspace" \
    RSS_CI_JOB_KEY='ci-meta' RSS_CI_SOURCE_REVISION="$checkout_revision" \
    RSS_CI_PLAN_DIGEST='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
    "$EVIDENCE" snapshot start --output "$output" \
    --download-restore-result not-attempted --download-restored-footprint-bytes 0 \
    --download-save-mode read-only --download-candidate-size-bytes 0 --download-save-outcome skipped \
    --tools-restore-result not-attempted --tools-restored-footprint-bytes 0 \
    --tools-save-mode read-only --tools-candidate-size-bytes 0 --tools-save-outcome skipped \
    --compiler-cache-enabled false --compiler-cache-version none \
    --compiler-cache-access disabled --compiler-cache-requests 0 \
    --compiler-cache-hits 0 --compiler-cache-misses 0 --compiler-cache-non-cacheable 0 \
    --compiler-cache-error-restore 0 --compiler-cache-error-stats 0 \
    --compiler-cache-error-cache-io 0 --compiler-cache-error-no-requests 0 \
    --compiler-cache-error-measure 0 --compiler-cache-error-save 0
}

expect_success 'start snapshot is created' run_evidence snapshot start --output "$OUTPUT"
assert_jq 'start snapshot is valid and closed' "$OUTPUT" '
  keys == ["job","schemaVersion","snapshots"] and
  .schemaVersion == 4 and
  (.job | keys == ["ciJobKey","job","planDigest","repository","runAttempt","runId","runnerArch","runnerOs","sourceRevision","workflow"]) and
  .job.ciJobKey == "ci-meta" and
  .job.sourceRevision == "'"$CHECKOUT_REVISION"'" and
  .job.planDigest == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" and
  (.snapshots[0] | keys == ["cache","directories","errors","filesystem","largestDirectories","outcome","recordedAt","resourceUsage","stage","toolVersions"]) and
  (.snapshots[0].cache | keys == ["compilerCache","download","tools"]) and
  ([.snapshots[0].cache.download,.snapshots[0].cache.tools | keys == ["candidateSizeBytes","restoreResult","restoredFootprintBytes","saveMode","saveOutcome"]] | all) and
  (.snapshots[0].cache.compilerCache | keys == ["access","enabled","errors","hits","misses","nonCacheable","requests","version"]) and
  (.snapshots[0].cache.compilerCache.errors | keys == ["cacheIo","measure","noRequests","restore","save","stats"]) and
  (.snapshots[0].resourceUsage | keys == ["cpuTimeMs","peakRssBytes"]) and
  (.snapshots[0].filesystem | keys == ["availableBytes","capacityBytes","usedBytes"]) and
  (.snapshots[0].toolVersions | keys == ["cargo","git","rustc"])'

MISMATCH_OUTPUT="$TMP_ROOT/mismatch.json"
run_evidence_with_mismatched_revision() {
  TEST_SOURCE_REVISION=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    run_evidence snapshot start --output "$MISMATCH_OUTPUT"
}
expect_failure 'source revision must match the observed checkout HEAD' run_evidence_with_mismatched_revision
STALE_REVISION_OUTPUT="$TMP_ROOT/stale-revision.json"
jq '.job.sourceRevision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' "$OUTPUT" >"$STALE_REVISION_OUTPUT"
expect_failure 'existing evidence revision must match the observed checkout HEAD' \
  run_evidence snapshot after-cache --output "$STALE_REVISION_OUTPUT"

jq -S '(.job[] |= "<string>") |
  .snapshots[0].recordedAt = "<utc>" |
  .snapshots[0].filesystem[] = 0 |
  (.snapshots[0].directories[]?.sizeBytes = 0) |
  .snapshots[0].directories |= sort_by(.path) |
  .snapshots[0].largestDirectories = (if (.snapshots[0].largestDirectories | length) > 0 then [{"path":"<relative>","sizeBytes":0}] else [] end) |
  .snapshots[0].toolVersions |= with_entries(.value = "<string-or-null>")' "$OUTPUT" >"$TMP_ROOT/normalized.json"
if diff -u "$GOLDEN" "$TMP_ROOT/normalized.json" >"$TMP_ROOT/golden.diff"; then
  pass 'schema matches executable golden'
else
  cat "$TMP_ROOT/golden.diff" >&2
  fail 'schema matches executable golden'
fi

append_with_mismatched_revision() {
  TEST_SOURCE_REVISION=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    run_evidence snapshot after-cache --output "$OUTPUT"
}
expect_failure 'every append revalidates the observed checkout HEAD' append_with_mismatched_revision
expect_success 'after-cache appends atomically' run_evidence snapshot after-cache --output "$OUTPUT"
run_after_build_with_resources() {
  TEST_CPU_TIME_MS=1234 TEST_PEAK_RSS_BYTES=5678 \
    run_evidence snapshot after-build --output "$OUTPUT" --outcome success
}
expect_success 'after-build appends outcome and resource usage' run_after_build_with_resources
expect_success 'before-save completes four stages' run_evidence snapshot before-save --output "$OUTPUT"
expect_success 'after-save completes five stages' run_evidence snapshot after-save --output "$OUTPUT"
assert_jq 'five stages retain order, outcome, and resource usage' "$OUTPUT" '
  [.snapshots[].stage] == ["start","after-cache","after-build","before-save","after-save"] and
  .snapshots[2].outcome == "success" and
  .snapshots[2].resourceUsage == {"cpuTimeMs":1234,"peakRssBytes":5678}'

EARLY_FAILURE_OUTPUT="$TMP_ROOT/early-failure.json"
expect_success 'ensure closes phases through after-cache when setup is skipped' run_evidence ensure after-cache --output "$EARLY_FAILURE_OUTPUT"
expect_success 'ensure is idempotent for an already closed phase' run_evidence ensure after-cache --output "$EARLY_FAILURE_OUTPUT"
expect_success 'ensure fills later missing phases after an early failure' run_evidence ensure before-save --output "$EARLY_FAILURE_OUTPUT"
assert_jq 'early failure evidence remains ordered and marks the synthetic build skipped' "$EARLY_FAILURE_OUTPUT" '
  [.snapshots[].stage] == ["start","after-cache","after-build","before-save"] and
  .snapshots[2].outcome == "skipped"'

BUDGET_FAILURE_OUTPUT="$TMP_ROOT/budget-failure.json"
expect_success 'budget fixture starts evidence' run_evidence snapshot start --output "$BUDGET_FAILURE_OUTPUT"
expect_success 'budget fixture records cache restore' run_evidence snapshot after-cache --output "$BUDGET_FAILURE_OUTPUT"
expect_success 'budget fixture records successful build' run_evidence snapshot after-build --output "$BUDGET_FAILURE_OUTPUT" --outcome success
record_budget_failure() {
  budget_conclusion=success
  set_disk_budget 999999999
  if ! "$BUDGET" --stage before-save --path "$WORKSPACE"; then
    budget_conclusion=failure
  fi
  set_disk_budget 5
  TEST_DOWNLOAD_SAVE_OUTCOME=ineligible TEST_TOOLS_SAVE_OUTCOME=ineligible \
    run_evidence snapshot before-save --output "$BUDGET_FAILURE_OUTPUT"
  [ "$budget_conclusion" = success ]
}
expect_failure 'budget failure returns nonzero only after evidence is recorded' record_budget_failure
assert_jq 'budget failure makes both cache candidates ineligible' "$BUDGET_FAILURE_OUTPUT" '
  .snapshots[-1].stage == "before-save" and
  .snapshots[-1].cache.download.saveOutcome == "ineligible" and
  .snapshots[-1].cache.tools.saveOutcome == "ineligible"'

cp "$OUTPUT" "$TMP_ROOT/before-failure.json"
expect_failure 'duplicate stage is rejected' run_evidence snapshot after-save --output "$OUTPUT"
if cmp -s "$OUTPUT" "$TMP_ROOT/before-failure.json"; then pass 'failed append preserves previous output'; else fail 'failed append preserves previous output'; fi
expect_failure 'unknown stage is rejected' run_evidence snapshot mystery --output "$OUTPUT"
expect_failure 'out-of-order initial stage is rejected' run_evidence snapshot after-cache --output "$TMP_ROOT/out-of-order.json"
expect_failure 'outcome outside after-build is rejected' run_evidence snapshot start --output "$TMP_ROOT/bad-outcome.json" --outcome failure
run_bad_restore_result() { TEST_DOWNLOAD_RESTORE_RESULT=hit run_evidence snapshot start --output "$TMP_ROOT/bad-restore.json"; }
run_bad_byte_count() { TEST_DOWNLOAD_RESTORED_BYTES=-1 run_evidence snapshot start --output "$TMP_ROOT/bad-bytes.json"; }
expect_failure 'unknown restore result is rejected' run_bad_restore_result
expect_failure 'negative cache byte count is rejected' run_bad_byte_count

jq '.schemaVersion = 3 | .snapshots = [.snapshots[0]]' "$OUTPUT" >"$TMP_ROOT/legacy-v3.json"
expect_failure 'schema v3 has no compatibility shim' run_evidence snapshot after-cache --output "$TMP_ROOT/legacy-v3.json"
expect_failure 'scalar compiler cache errors flag has no compatibility shim' \
  run_evidence snapshot start --output "$TMP_ROOT/legacy-errors.json" --compiler-cache-errors 1

run_bad_compiler_counts() {
  TEST_COMPILER_REQUESTS=1 TEST_COMPILER_HITS=1 TEST_COMPILER_MISSES=1 \
    run_evidence snapshot start --output "$TMP_ROOT/bad-compiler-counts.json"
}
expect_failure 'compiler cache hits and misses cannot exceed requests' run_bad_compiler_counts
DEGRADED_OUTPUT="$TMP_ROOT/degraded-compiler-cache.json"
run_degraded_compiler_cache() { TEST_ERROR_STATS=1 run_evidence snapshot start --output "$DEGRADED_OUTPUT"; }
expect_success 'compiler cache stats failure is recorded without invalidating evidence' run_degraded_compiler_cache
assert_jq 'compiler cache degradation uses a closed classified object' "$DEGRADED_OUTPUT" '
  .snapshots[0].cache.compilerCache.errors ==
    {"cacheIo":0,"measure":0,"noRequests":0,"restore":0,"save":0,"stats":1} and
  .snapshots[0].errors == []'
run_bad_compiler_error() {
  error_class=$1
  output="$TMP_ROOT/bad-error-$error_class.json"
  case "$error_class" in
    RESTORE) TEST_ERROR_RESTORE=-1 run_evidence snapshot start --output "$output" ;;
    STATS) TEST_ERROR_STATS=-1 run_evidence snapshot start --output "$output" ;;
    CACHE_IO) TEST_ERROR_CACHE_IO=-1 run_evidence snapshot start --output "$output" ;;
    NO_REQUESTS) TEST_ERROR_NO_REQUESTS=-1 run_evidence snapshot start --output "$output" ;;
    MEASURE) TEST_ERROR_MEASURE=-1 run_evidence snapshot start --output "$output" ;;
    SAVE) TEST_ERROR_SAVE=-1 run_evidence snapshot start --output "$output" ;;
    *) return 2 ;;
  esac
}
for error_class in RESTORE STATS CACHE_IO NO_REQUESTS MEASURE SAVE; do
  expect_failure "compiler cache $error_class error count rejects negative values" \
    run_bad_compiler_error "$error_class"
done

printf '{broken' >"$TMP_ROOT/corrupt.json"
cp "$TMP_ROOT/corrupt.json" "$TMP_ROOT/corrupt.before"
expect_failure 'corrupt prior JSON fails closed' run_evidence snapshot after-cache --output "$TMP_ROOT/corrupt.json"
if cmp -s "$TMP_ROOT/corrupt.json" "$TMP_ROOT/corrupt.before"; then pass 'corrupt prior JSON is preserved'; else fail 'corrupt prior JSON is preserved'; fi

mkdir "$TMP_ROOT/unwritable-dir"
expect_failure 'directory output path is rejected' run_evidence snapshot start --output "$TMP_ROOT/unwritable-dir"

if grep -R -F 'must-not-leak-7f3a' "$OUTPUT" "$TMP_ROOT/stdout" "$TMP_ROOT/stderr" >/dev/null 2>&1; then
  fail 'secret canary is absent from all outputs'
else
  pass 'secret canary is absent from all outputs'
fi
assert_jq 'evidence excludes raw cache and identity fields' "$OUTPUT" '
  [.. | objects | keys[]] | all(. != "key" and . != "ref" and . != "actor" and . != "environment" and . != "home")'
assert_jq 'newline paths remain valid JSON and symlinks are excluded' "$OUTPUT" '
  ([.snapshots[].largestDirectories[].path | contains("line\nbreak")] | any) and
  ([.snapshots[].largestDirectories[].path | contains("outside-link")] | any | not)'

DU_TRACE="$TMP_ROOT/du.trace"
TRACE_BIN="$TMP_ROOT/trace-bin"
mkdir "$TRACE_BIN"
for command_name in bash dirname jq mktemp mv rm date find df; do
  ln -s "$TOOL_BIN/$command_name" "$TRACE_BIN/$command_name"
done
for tool_name in rustc cargo git; do
  ln -s "$TOOL_BIN/$tool_name" "$TRACE_BIN/$tool_name"
done
real_du=$(command -v du)
cat >"$TRACE_BIN/du" <<EOF
#!/bin/sh
printf '%s\n' "\${2:-}" >>'$DU_TRACE'
exec '$real_du' "\$@"
EOF
chmod +x "$TRACE_BIN/du"
expect_success 'bounded top directories snapshot succeeds' run_evidence_with_path "$TRACE_BIN" snapshot start --output "$TMP_ROOT/trace.json"
if grep -Fx "$WORKSPACE/a/nested" "$DU_TRACE" >/dev/null 2>&1 || \
   grep -Fx "$WORKSPACE/.cache/cargo-target/incremental/depth-two" "$DU_TRACE" >/dev/null 2>&1; then
  fail 'top directory scan does not remeasure depth-two descendants'
else
  pass 'top directory scan does not remeasure depth-two descendants'
fi
assert_jq 'top directory paths use workspace and target logical roots' "$TMP_ROOT/trace.json" '
  ([.snapshots[0].largestDirectories[].path | startswith("workspace/") or startswith("target/")] | all) and
  ([.snapshots[0].largestDirectories[].path | contains("a/nested") or contains("incremental/depth-two")] | any | not)'

PATH_CANARY="$TMP_ROOT/absolute-path-must-not-leak-91b7"
mkdir "$PATH_CANARY"
chmod 500 "$PATH_CANARY"
expect_failure 'unwritable output directory fails closed' run_evidence snapshot start --output "$PATH_CANARY/evidence.json"
chmod 700 "$PATH_CANARY"
if grep -F "$PATH_CANARY" "$TMP_ROOT/stdout" "$TMP_ROOT/stderr" >/dev/null 2>&1; then
  fail 'unwritable output directory does not leak its absolute path'
else
  pass 'unwritable output directory does not leak its absolute path'
fi

NO_DU_BIN="$TMP_ROOT/no-du-bin"
mkdir "$NO_DU_BIN"
for command_name in bash dirname jq mktemp mv rm date find git cargo rustc df; do
  ln -s "$TOOL_BIN/$command_name" "$NO_DU_BIN/$command_name"
done
expect_success 'missing du degrades to recorded errors' run_disabled_evidence "$NO_DU_BIN" "$HOME_DIR" "$WORKSPACE" "$TMP_ROOT/no-du.json"
assert_jq 'du degradation remains schema-valid' "$TMP_ROOT/no-du.json" '
  (.snapshots[0].errors | length) >= 5 and
  ([.snapshots[0].directories[] | select(.path != "sccache") | .sizeBytes] | all(. == null)) and
  (.snapshots[0].directories[] | select(.path == "sccache") | .sizeBytes) == 0'

CLEAN_HOME="$TMP_ROOT/clean-home"
CLEAN_WORKSPACE="$TMP_ROOT/clean-workspace"
mkdir -p "$CLEAN_HOME" "$CLEAN_WORKSPACE/.cache/cargo-target"
expect_success 'controlled clean start measures canonical target' run_disabled_evidence "$TOOL_BIN" "$CLEAN_HOME" "$CLEAN_WORKSPACE" "$TMP_ROOT/clean-start.json"
assert_jq 'controlled clean start has complete measurements' "$TMP_ROOT/clean-start.json" '
  ([.snapshots[0].directories[].sizeBytes] | all(. != null)) and
  ([.snapshots[0].directories[] | select(.path == "sccache" or .path == "cargo-registry" or .path == "cargo-git" or .path == "rustup") | .sizeBytes] | all(. == 0)) and
  (.snapshots[0].errors | length) == 0'

EMPTY_HOME="$TMP_ROOT/empty-home"
EMPTY_WORKSPACE="$TMP_ROOT/empty-workspace"
mkdir "$EMPTY_HOME" "$EMPTY_WORKSPACE"
expect_success 'missing logical directories are measured as zero' run_disabled_evidence "$TOOL_BIN" "$EMPTY_HOME" "$EMPTY_WORKSPACE" "$TMP_ROOT/missing-dirs.json"
assert_jq 'missing directories retain fixed zero-valued logical entries' "$TMP_ROOT/missing-dirs.json" '
  ([.snapshots[0].directories[] | select(.path == "target" or .path == "sccache" or .path == "cargo-registry" or .path == "cargo-git" or .path == "rustup") | .sizeBytes] | all(. == 0)) and
  (.snapshots[0].errors | length) == 0'

INVALID_HOME="$TMP_ROOT/invalid-home"
mkdir -p "$INVALID_HOME/.cargo"
printf 'not a directory\n' >"$INVALID_HOME/.cargo/registry"
ln -s "$WORKSPACE" "$INVALID_HOME/.cargo/git"
expect_success 'invalid logical directories remain recorded errors' run_disabled_evidence "$TOOL_BIN" "$INVALID_HOME" "$WORKSPACE" "$TMP_ROOT/invalid-dirs.json"
assert_jq 'non-directory and symlink inputs fail loud while absence remains zero' "$TMP_ROOT/invalid-dirs.json" '
  [.snapshots[0].directories[] | select(.sizeBytes == null) | .path] == ["cargo-registry","cargo-git"] and
  (.snapshots[0].directories[] | select(.path == "rustup") | .sizeBytes) == 0 and
  (.snapshots[0].errors | length) == 2'

set_disk_budget 1
expect_success 'disk budget accepts config threshold' "$BUDGET" --stage start --path "$WORKSPACE"
set_disk_budget 999999999
expect_failure 'disk budget rejects synthetic high config threshold' "$BUDGET" --stage before-build --path "$WORKSPACE"
if grep -F '::error title=ci-disk-budget::' "$TMP_ROOT/stderr" >/dev/null; then pass 'budget failure emits stable annotation'; else fail 'budget failure emits stable annotation'; fi
if grep -F 'stage=before-build' "$TMP_ROOT/stderr" >/dev/null; then pass 'budget diagnostic identifies stage'; else fail 'budget diagnostic identifies stage'; fi
for bad in 0 -1 nope 1.5; do
  set_disk_budget "$bad"
  expect_failure "invalid config threshold $bad is rejected" "$BUDGET" --stage test --path "$WORKSPACE"
done
set_disk_budget 999999999999999999999999
expect_failure 'overflowing config threshold is rejected with usage' "$BUDGET" --stage test --path "$WORKSPACE"
if grep -E 'value too great|integer expression|unbound variable' "$TMP_ROOT/stderr" >/dev/null 2>&1; then
  fail 'overflowing threshold avoids raw arithmetic diagnostics'
else
  pass 'overflowing threshold avoids raw arithmetic diagnostics'
fi
set_disk_budget 5
expect_failure 'threshold CLI override is rejected' "$BUDGET" --stage test --path "$WORKSPACE" --min-free-gib 1
printf '\nmin_disk_free_gib = 5\n' >>"$WORKSPACE/.config/ci-slo.toml"
expect_failure 'duplicate config threshold is rejected' "$BUDGET" --stage test --path "$WORKSPACE"
set_disk_budget 5
mv "$WORKSPACE/.config/ci-slo.toml" "$WORKSPACE/.config/ci-slo.real.toml"
ln -s ci-slo.real.toml "$WORKSPACE/.config/ci-slo.toml"
expect_failure 'symlinked config threshold is rejected' "$BUDGET" --stage test --path "$WORKSPACE"
rm "$WORKSPACE/.config/ci-slo.toml"
mv "$WORKSPACE/.config/ci-slo.real.toml" "$WORKSPACE/.config/ci-slo.toml"

FAKE_DF_BIN="$TMP_ROOT/fake-df-bin"
mkdir "$FAKE_DF_BIN"
cat >"$FAKE_DF_BIN/df" <<'EOF'
#!/bin/sh
printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
available=${FAKE_AVAILABLE_KIB:-4194304}
printf 'fixture 20971520 4194304 %s 20%% /fixture\n' "$available"
EOF
chmod +x "$FAKE_DF_BIN/df"
for padded in 01 08 09; do
  set_disk_budget "$padded"
  expect_success "zero-padded config threshold $padded is decimal" env FAKE_AVAILABLE_KIB=10485760 PATH="$FAKE_DF_BIN:$PATH" "$BUDGET" --stage padded --path "$WORKSPACE"
done
set_disk_budget 5
expect_failure 'configured disk budget rejects four GiB' env PATH="$FAKE_DF_BIN:$PATH" "$BUDGET" --stage configured --path "$WORKSPACE"
if grep -F 'requiredGiB=5 reason=' "$TMP_ROOT/stderr" >/dev/null; then
  pass 'config-driven disk budget reports five GiB requirement'
else
  fail 'config-driven disk budget reports five GiB requirement'
fi
set_disk_budget 9
expect_failure 'live guard consumes changed config threshold' env FAKE_AVAILABLE_KIB=6291456 PATH="$FAKE_DF_BIN:$PATH" "$BUDGET" --stage changed --path "$WORKSPACE"
available_kib=$(df -Pk "$WORKSPACE" | awk 'END { print $4 }')
boundary_gib=$((available_kib / 1048576))
if [ "$boundary_gib" -gt 0 ]; then
  set_disk_budget "$boundary_gib"
  expect_success 'exact integer GiB floor is accepted' "$BUDGET" --stage boundary --path "$WORKSPACE"
  set_disk_budget "$((boundary_gib + 1))"
  expect_failure 'next integer GiB above available space is rejected' "$BUDGET" --stage boundary --path "$WORKSPACE"
fi
set_disk_budget 5
expect_failure 'missing budget path is rejected' "$BUDGET" --stage test --path "$TMP_ROOT/missing"
expect_failure 'unknown budget argument is rejected' "$BUDGET" --stage test --wat

NO_DF_BIN="$TMP_ROOT/no-df-bin"
mkdir "$NO_DF_BIN"
ln -s "$(command -v awk)" "$NO_DF_BIN/awk"
expect_failure 'missing df fails closed' env PATH="$NO_DF_BIN" /bin/bash "$BUDGET" --stage test --path "$WORKSPACE"

sentinel="$TMP_ROOT/expensive-ran"
set_disk_budget 999999999
if "$BUDGET" --stage before-build --path "$WORKSPACE" >/dev/null 2>&1 && : >"$sentinel"; then :; fi
if [ ! -e "$sentinel" ]; then pass 'budget failure prevents expensive command sentinel'; else fail 'budget failure prevents expensive command sentinel'; fi

if [ "$FAILURES" -ne 0 ]; then
  printf '%s selftest(s) failed\n' "$FAILURES" >&2
  exit 1
fi
printf 'all ci evidence selftests passed\n'
