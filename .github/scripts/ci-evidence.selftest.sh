#!/usr/bin/env bash
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
EVIDENCE="$SCRIPT_DIR/ci-evidence.sh"
BUDGET="$SCRIPT_DIR/ci-disk-budget.sh"
GOLDEN="$SCRIPT_DIR/testdata/ci-evidence-v2.golden.json"
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
  "$WORKSPACE/.cache/cargo-target/incremental/depth-two" \
  "$HOME_DIR/.cargo/registry" "$HOME_DIR/.cargo/git" "$HOME_DIR/.rustup"
newline_dir=$(printf 'line\nbreak')
mkdir -p "$WORKSPACE/$newline_dir"
ln -s "$TMP_ROOT" "$WORKSPACE/outside-link"
printf 'fixture\n' >"$WORKSPACE/a/data"

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
    SECRET_CANARY='must-not-leak-7f3a' \
    "$EVIDENCE" "$@" \
    --build-restore-result "${TEST_BUILD_RESTORE_RESULT:-miss}" --build-restored-footprint-bytes "${TEST_BUILD_RESTORED_BYTES:-0}" \
    --build-save-mode writer --build-candidate-size-bytes 4096 \
    --build-save-outcome "${TEST_BUILD_SAVE_OUTCOME:-eligible}" \
    --tools-restore-result exact --tools-restored-footprint-bytes 2048 \
    --tools-save-mode read-only --tools-candidate-size-bytes 2048 \
    --tools-save-outcome "${TEST_TOOLS_SAVE_OUTCOME:-skipped}"
}

run_evidence_with_path() {
  evidence_path=$1
  shift
  env -i PATH="$evidence_path" HOME="$HOME_DIR" CARGO_HOME="$HOME_DIR/.cargo" \
    RUSTUP_HOME="$HOME_DIR/.rustup" GITHUB_WORKSPACE="$WORKSPACE" \
    GITHUB_REPOSITORY='owner/repo' GITHUB_WORKFLOW='CI' GITHUB_JOB='test' \
    GITHUB_RUN_ID='123' GITHUB_RUN_ATTEMPT='2' RUNNER_OS='Linux' RUNNER_ARCH='X64' \
    SECRET_CANARY='must-not-leak-7f3a' \
    "$EVIDENCE" "$@" \
    --build-restore-result "${TEST_BUILD_RESTORE_RESULT:-miss}" --build-restored-footprint-bytes "${TEST_BUILD_RESTORED_BYTES:-0}" \
    --build-save-mode writer --build-candidate-size-bytes 4096 \
    --build-save-outcome "${TEST_BUILD_SAVE_OUTCOME:-eligible}" \
    --tools-restore-result exact --tools-restored-footprint-bytes 2048 \
    --tools-save-mode read-only --tools-candidate-size-bytes 2048 \
    --tools-save-outcome "${TEST_TOOLS_SAVE_OUTCOME:-skipped}"
}

expect_success 'start snapshot is created' run_evidence snapshot start --output "$OUTPUT"
assert_jq 'start snapshot is valid and closed' "$OUTPUT" '
  keys == ["job","schemaVersion","snapshots"] and
  .schemaVersion == 2 and
  (.job | keys == ["job","repository","runAttempt","runId","runnerArch","runnerOs","workflow"]) and
  (.snapshots[0] | keys == ["cache","directories","errors","filesystem","largestDirectories","outcome","recordedAt","stage","toolVersions"]) and
  (.snapshots[0].cache | keys == ["build","tools"]) and
  ([.snapshots[0].cache[] | keys == ["candidateSizeBytes","restoreResult","restoredFootprintBytes","saveMode","saveOutcome"]] | all) and
  (.snapshots[0].filesystem | keys == ["availableBytes","capacityBytes","usedBytes"]) and
  (.snapshots[0].toolVersions | keys == ["cargo","git","rustc"])'

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

expect_success 'after-cache appends atomically' run_evidence snapshot after-cache --output "$OUTPUT"
expect_success 'after-build appends outcome' run_evidence snapshot after-build --output "$OUTPUT" --outcome success
expect_success 'before-save completes four stages' run_evidence snapshot before-save --output "$OUTPUT"
expect_success 'after-save completes five stages' run_evidence snapshot after-save --output "$OUTPUT"
assert_jq 'five stages retain order and outcome' "$OUTPUT" '[.snapshots[].stage] == ["start","after-cache","after-build","before-save","after-save"] and .snapshots[2].outcome == "success"'

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
  if ! "$BUDGET" --stage before-save --path "$WORKSPACE" --min-free-gib 999999999; then
    budget_conclusion=failure
  fi
  TEST_BUILD_SAVE_OUTCOME=ineligible TEST_TOOLS_SAVE_OUTCOME=ineligible \
    run_evidence snapshot before-save --output "$BUDGET_FAILURE_OUTPUT"
  [ "$budget_conclusion" = success ]
}
expect_failure 'budget failure returns nonzero only after evidence is recorded' record_budget_failure
assert_jq 'budget failure makes both cache candidates ineligible' "$BUDGET_FAILURE_OUTPUT" '
  .snapshots[-1].stage == "before-save" and
  .snapshots[-1].cache.build.saveOutcome == "ineligible" and
  .snapshots[-1].cache.tools.saveOutcome == "ineligible"'

cp "$OUTPUT" "$TMP_ROOT/before-failure.json"
expect_failure 'duplicate stage is rejected' run_evidence snapshot after-save --output "$OUTPUT"
if cmp -s "$OUTPUT" "$TMP_ROOT/before-failure.json"; then pass 'failed append preserves previous output'; else fail 'failed append preserves previous output'; fi
expect_failure 'unknown stage is rejected' run_evidence snapshot mystery --output "$OUTPUT"
expect_failure 'out-of-order initial stage is rejected' run_evidence snapshot after-cache --output "$TMP_ROOT/out-of-order.json"
expect_failure 'outcome outside after-build is rejected' run_evidence snapshot start --output "$TMP_ROOT/bad-outcome.json" --outcome failure
run_bad_restore_result() { TEST_BUILD_RESTORE_RESULT=hit run_evidence snapshot start --output "$TMP_ROOT/bad-restore.json"; }
run_bad_byte_count() { TEST_BUILD_RESTORED_BYTES=-1 run_evidence snapshot start --output "$TMP_ROOT/bad-bytes.json"; }
expect_failure 'unknown restore result is rejected' run_bad_restore_result
expect_failure 'negative cache byte count is rejected' run_bad_byte_count

jq '.schemaVersion = 1 | .snapshots = [.snapshots[0]]' "$OUTPUT" >"$TMP_ROOT/legacy-v1.json"
expect_failure 'schema v1 has no compatibility shim' run_evidence snapshot after-cache --output "$TMP_ROOT/legacy-v1.json"

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
expect_success 'missing du degrades to recorded errors' env -i PATH="$NO_DU_BIN" HOME="$HOME_DIR" CARGO_HOME="$HOME_DIR/.cargo" RUSTUP_HOME="$HOME_DIR/.rustup" GITHUB_WORKSPACE="$WORKSPACE" "$EVIDENCE" snapshot start --output "$TMP_ROOT/no-du.json" --build-restore-result not-attempted --build-restored-footprint-bytes 0 --build-save-mode read-only --build-candidate-size-bytes 0 --build-save-outcome skipped --tools-restore-result not-attempted --tools-restored-footprint-bytes 0 --tools-save-mode read-only --tools-candidate-size-bytes 0 --tools-save-outcome skipped
assert_jq 'du degradation remains schema-valid' "$TMP_ROOT/no-du.json" '(.snapshots[0].errors | length) >= 5 and ([.snapshots[0].directories[].sizeBytes] | all(. == null))'

EMPTY_HOME="$TMP_ROOT/empty-home"
EMPTY_WORKSPACE="$TMP_ROOT/empty-workspace"
mkdir "$EMPTY_HOME" "$EMPTY_WORKSPACE"
expect_success 'missing logical directories degrade to recorded errors' env -i PATH="$TOOL_BIN" HOME="$EMPTY_HOME" GITHUB_WORKSPACE="$EMPTY_WORKSPACE" "$EVIDENCE" snapshot start --output "$TMP_ROOT/missing-dirs.json" --build-restore-result not-attempted --build-restored-footprint-bytes 0 --build-save-mode read-only --build-candidate-size-bytes 0 --build-save-outcome skipped --tools-restore-result not-attempted --tools-restored-footprint-bytes 0 --tools-save-mode read-only --tools-candidate-size-bytes 0 --tools-save-outcome skipped
assert_jq 'missing directory degradation retains fixed logical entries' "$TMP_ROOT/missing-dirs.json" '
  [.snapshots[0].directories[] | select(.sizeBytes == null) | .path] == ["target","cargo-registry","cargo-git","rustup"] and
  (.snapshots[0].errors | length) == 4'

expect_success 'disk budget accepts available space' "$BUDGET" --stage start --path "$WORKSPACE" --min-free-gib 1
expect_failure 'disk budget rejects synthetic high threshold' "$BUDGET" --stage before-build --path "$WORKSPACE" --min-free-gib 999999999
if grep -F '::error title=ci-disk-budget::' "$TMP_ROOT/stderr" >/dev/null; then pass 'budget failure emits stable annotation'; else fail 'budget failure emits stable annotation'; fi
if grep -F 'stage=before-build' "$TMP_ROOT/stderr" >/dev/null; then pass 'budget diagnostic identifies stage'; else fail 'budget diagnostic identifies stage'; fi
for bad in 0 -1 nope 1.5; do
  expect_failure "invalid threshold $bad is rejected" "$BUDGET" --stage test --path "$WORKSPACE" --min-free-gib "$bad"
done
expect_failure 'overflowing threshold is rejected with usage' "$BUDGET" --stage test --path "$WORKSPACE" --min-free-gib 999999999999999999999999
if grep -E 'value too great|integer expression|unbound variable' "$TMP_ROOT/stderr" >/dev/null 2>&1; then
  fail 'overflowing threshold avoids raw arithmetic diagnostics'
else
  pass 'overflowing threshold avoids raw arithmetic diagnostics'
fi

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
  expect_success "zero-padded threshold $padded is decimal" env FAKE_AVAILABLE_KIB=10485760 PATH="$FAKE_DF_BIN:$PATH" "$BUDGET" --stage padded --path "$WORKSPACE" --min-free-gib "$padded"
done
expect_failure 'default disk budget rejects four GiB' env PATH="$FAKE_DF_BIN:$PATH" "$BUDGET" --stage default --path "$WORKSPACE"
if grep -F 'requiredGiB=5 reason=' "$TMP_ROOT/stderr" >/dev/null; then
  pass 'default disk budget reports five GiB requirement'
else
  fail 'default disk budget reports five GiB requirement'
fi
available_kib=$(df -Pk "$WORKSPACE" | awk 'END { print $4 }')
boundary_gib=$((available_kib / 1048576))
if [ "$boundary_gib" -gt 0 ]; then
  expect_success 'exact integer GiB floor is accepted' "$BUDGET" --stage boundary --path "$WORKSPACE" --min-free-gib "$boundary_gib"
  expect_failure 'next integer GiB above available space is rejected' "$BUDGET" --stage boundary --path "$WORKSPACE" --min-free-gib "$((boundary_gib + 1))"
fi
expect_failure 'missing budget path is rejected' "$BUDGET" --stage test --path "$TMP_ROOT/missing" --min-free-gib 1
expect_failure 'unknown budget argument is rejected' "$BUDGET" --stage test --wat

NO_DF_BIN="$TMP_ROOT/no-df-bin"
mkdir "$NO_DF_BIN"
expect_failure 'missing df fails closed' env PATH="$NO_DF_BIN" /bin/bash "$BUDGET" --stage test --path "$WORKSPACE" --min-free-gib 1

sentinel="$TMP_ROOT/expensive-ran"
if "$BUDGET" --stage before-build --path "$WORKSPACE" --min-free-gib 999999999 >/dev/null 2>&1 && : >"$sentinel"; then :; fi
if [ ! -e "$sentinel" ]; then pass 'budget failure prevents expensive command sentinel'; else fail 'budget failure prevents expensive command sentinel'; fi

if [ "$FAILURES" -ne 0 ]; then
  printf '%s selftest(s) failed\n' "$FAILURES" >&2
  exit 1
fi
printf 'all ci evidence selftests passed\n'
