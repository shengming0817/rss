#!/usr/bin/env bash
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
MAINTAIN="$SCRIPT_DIR/ci-cache-maintain.sh"
TMP_BASE=${TMPDIR:-/tmp}
TMP_ROOT=${TMP_BASE%/}/ci-cache-maintain-selftest.$$
FAILURES=0
cleanup_tmp() { rm -rf "$TMP_ROOT"; }
trap cleanup_tmp EXIT HUP INT TERM
mkdir -p "$TMP_ROOT"

pass() { printf 'ok - %s\n' "$1"; }
fail() { printf 'not ok - %s\n' "$1" >&2; FAILURES=$((FAILURES + 1)); }
expect_success() {
  name=$1; shift
  if "$@" >"$TMP_ROOT/stdout" 2>"$TMP_ROOT/stderr"; then pass "$name"; else
    sed 's/^/# /' "$TMP_ROOT/stderr" >&2 || true
    fail "$name"
  fi
}
expect_failure() {
  name=$1; shift
  if "$@" >"$TMP_ROOT/stdout" 2>"$TMP_ROOT/stderr"; then fail "$name"; else pass "$name"; fi
}
expect_safe_failure() {
  name=$1 expected=$2; shift 2
  if "$@" >"$TMP_ROOT/stdout" 2>"$TMP_ROOT/stderr"; then
    fail "$name"
  elif [ "$(cat "$TMP_ROOT/stderr")" = "$expected" ] &&
       ! grep -Eq 'SECRET_CANARY|https?://|token=|work space' "$TMP_ROOT/stderr"; then
    pass "$name"
  else
    sed 's/^/# /' "$TMP_ROOT/stderr" >&2 || true
    fail "$name"
  fi
}

WORKSPACE="$TMP_ROOT/work space"
TARGET="$WORKSPACE/.cache/cargo-target"
OUTSIDE="$TMP_ROOT/outside"
mkdir -p "$TARGET/debug/incremental/a" "$TARGET/release/incremental/b" \
  "$TARGET/debug/deps" "$TARGET/workspace-owned-alpha" "$TARGET/workspace-owned-beta" "$OUTSIDE"
printf keep >"$TARGET/debug/deps/third-party.keep"
printf sentinel >"$OUTSIDE/sentinel"
ln -s "$OUTSIDE" "$TARGET/debug/incremental-link"

FAKE_BIN="$TMP_ROOT/fake-bin"
mkdir "$FAKE_BIN"
for command_name in bash cat chmod dirname pwd readlink find grep rm du jq mktemp mkdir; do
  ln -s "$(command -v "$command_name")" "$FAKE_BIN/$command_name"
done
cat >"$FAKE_BIN/git" <<'EOF'
#!/usr/bin/env bash
set -eu
if [ "${FAKE_DIAGNOSTIC_FAIL_STAGE:-}" = git-tree ]; then
  printf 'SECRET_CANARY token=credential https://example.invalid %s\n' "$FAKE_WORKSPACE" >&2
  exit 26
fi
printf '%s\n' "${FAKE_TREE_ID:-0123456789abcdef0123456789abcdef01234567}"
EOF
chmod +x "$FAKE_BIN/git"
cat >"$FAKE_BIN/cargo" <<'EOF'
#!/usr/bin/env bash
set -eu
case "${1:-}" in
  metadata)
    if [ "${FAKE_DIAGNOSTIC_FAIL_STAGE:-}" = metadata ]; then
      printf 'Permission denied SECRET_CANARY token=credential https://example.invalid %s\n' "$FAKE_WORKSPACE" >&2
      exit 23
    fi
    if [ "${FAKE_METADATA_INVALID:-}" = true ]; then
      printf '{SECRET_CANARY token=credential https://example.invalid %s\n' "$FAKE_WORKSPACE"
      exit 0
    fi
    jq -cn --arg workspace "$FAKE_WORKSPACE" --arg target "$FAKE_TARGET" \
      '{workspace_root:$workspace,target_directory:$target,packages:[{name:"alpha",manifest_path:($workspace+"/Cargo.toml")},{name:"beta",manifest_path:($workspace+"/crates/beta/Cargo.toml")}],workspace_members:["alpha-id","beta-id"]} | .packages[0].id="alpha-id" | .packages[1].id="beta-id"'
    ;;
  clean)
    [ "${2:-}" = --target-dir ]
    target=$3
    [ "${4:-}" = -p ]
    package=$5
    if [ "${FAKE_DIAGNOSTIC_FAIL_STAGE:-}" = clean ]; then
      printf 'SECRET_CANARY token=credential https://example.invalid %s\n' "$FAKE_WORKSPACE" >&2
      exit 24
    fi
    printf '%s\n' "$package" >>"$FAKE_CLEAN_TRACE"
    rm -rf "$target/workspace-owned-$package"
    ;;
  *) exit 9 ;;
esac
EOF
chmod +x "$FAKE_BIN/cargo"

run_maintain() {
  env PATH="$FAKE_BIN" FAKE_WORKSPACE="$WORKSPACE" FAKE_TARGET="$TARGET" \
    FAKE_CLEAN_TRACE="$TMP_ROOT/clean.trace" "$MAINTAIN" "$@"
}

expect_success 'measure reports an integer byte count' run_maintain measure --path "$TARGET"
case "$(cat "$TMP_ROOT/stdout")" in ''|*[!0-9]*) fail 'measure stdout is only an integer' ;; *) pass 'measure stdout is only an integer' ;; esac
expect_success 'missing cache root measures zero' run_maintain measure --path "$WORKSPACE/missing"
if [ "$(cat "$TMP_ROOT/stdout")" = 0 ]; then pass 'missing cache root is zero'; else fail 'missing cache root is zero'; fi
expect_failure 'measure rejects a symlink root' run_maintain measure --path "$TARGET/debug/incremental-link"
expect_success 'git tree identity is full and validated' run_maintain tree-identity --workspace "$WORKSPACE"
if [ "$(cat "$TMP_ROOT/stdout")" = 0123456789abcdef0123456789abcdef01234567 ]; then pass 'git tree identity is emitted exactly'; else fail 'git tree identity is emitted exactly'; fi
expect_failure 'abbreviated git tree identity fails closed' env PATH="$FAKE_BIN" FAKE_WORKSPACE="$WORKSPACE" FAKE_TARGET="$TARGET" FAKE_TREE_ID=01234567 FAKE_CLEAN_TRACE="$TMP_ROOT/clean.trace" "$MAINTAIN" tree-identity --workspace "$WORKSPACE"
expect_safe_failure 'git tree lookup failure emits closed diagnostic only' \
  'ci-cache-maintain: command failed stage=git-tree subject=repository exit=26 class=command-failed' \
  env PATH="$FAKE_BIN" FAKE_WORKSPACE="$WORKSPACE" FAKE_TARGET="$TARGET" FAKE_DIAGNOSTIC_FAIL_STAGE=git-tree FAKE_CLEAN_TRACE="$TMP_ROOT/clean.trace" "$MAINTAIN" tree-identity --workspace "$WORKSPACE"

expect_success 'metadata-driven cleanup succeeds' run_maintain cleanup --workspace "$WORKSPACE" --target "$TARGET"
if [ ! -e "$TARGET/debug/incremental" ] && [ ! -e "$TARGET/release/incremental" ]; then pass 'cleanup removes incremental directories'; else fail 'cleanup removes incremental directories'; fi
if [ ! -e "$TARGET/workspace-owned-alpha" ] && [ ! -e "$TARGET/workspace-owned-beta" ]; then pass 'cleanup asks cargo to remove every workspace package'; else fail 'cleanup asks cargo to remove every workspace package'; fi
if [ -f "$TARGET/debug/deps/third-party.keep" ]; then pass 'cleanup preserves dependency cache'; else fail 'cleanup preserves dependency cache'; fi
if [ -f "$OUTSIDE/sentinel" ]; then pass 'cleanup does not follow symlinks'; else fail 'cleanup does not follow symlinks'; fi
expect_success 'cleanup is idempotent' run_maintain cleanup --workspace "$WORKSPACE" --target "$TARGET"

ln -s "$OUTSIDE" "$WORKSPACE/target-link"
expect_failure 'cleanup rejects symlink target root' run_maintain cleanup --workspace "$WORKSPACE" --target "$WORKSPACE/target-link"
expect_failure 'cleanup rejects target outside workspace' run_maintain cleanup --workspace "$WORKSPACE" --target "$OUTSIDE"
expect_failure 'metadata target mismatch fails closed' env PATH="$FAKE_BIN" FAKE_WORKSPACE="$WORKSPACE" FAKE_TARGET="$OUTSIDE" FAKE_CLEAN_TRACE="$TMP_ROOT/clean.trace" "$MAINTAIN" cleanup --workspace "$WORKSPACE" --target "$TARGET"
expect_safe_failure 'metadata failure emits closed diagnostic only' \
  'ci-cache-maintain: command failed stage=metadata subject=workspace exit=23 class=permission-denied' \
  env PATH="$FAKE_BIN" FAKE_WORKSPACE="$WORKSPACE" FAKE_TARGET="$TARGET" FAKE_CLEAN_TRACE="$TMP_ROOT/clean.trace" \
  FAKE_DIAGNOSTIC_FAIL_STAGE=metadata "$MAINTAIN" cleanup --workspace "$WORKSPACE" --target "$TARGET"
expect_safe_failure 'metadata parse failure emits a closed parse classification' \
  'ci-cache-maintain: command failed stage=metadata-parse subject=workspace-root exit=5 class=parse-invalid' \
  env PATH="$FAKE_BIN" FAKE_WORKSPACE="$WORKSPACE" FAKE_TARGET="$TARGET" FAKE_CLEAN_TRACE="$TMP_ROOT/clean.trace" \
  FAKE_METADATA_INVALID=true "$MAINTAIN" cleanup --workspace "$WORKSPACE" --target "$TARGET"
expect_safe_failure 'package cleanup failure emits validated package context only' \
  'ci-cache-maintain: command failed stage=clean subject=alpha exit=24 class=command-failed' \
  env PATH="$FAKE_BIN" FAKE_WORKSPACE="$WORKSPACE" FAKE_TARGET="$TARGET" FAKE_CLEAN_TRACE="$TMP_ROOT/clean.trace" \
  FAKE_DIAGNOSTIC_FAIL_STAGE=clean "$MAINTAIN" cleanup --workspace "$WORKSPACE" --target "$TARGET"

mkdir -p "$TARGET/debug/incremental/fail-case"
FAIL_FIND_BIN="$TMP_ROOT/fail-find-bin"
mkdir "$FAIL_FIND_BIN"
for command_name in bash dirname pwd readlink rm du jq mktemp cargo; do
  ln -s "$FAKE_BIN/$command_name" "$FAIL_FIND_BIN/$command_name"
done
printf '#!/bin/sh\nexit 7\n' >"$FAIL_FIND_BIN/find"
chmod +x "$FAIL_FIND_BIN/find"
expect_failure 'incremental discovery failure fails closed' env PATH="$FAIL_FIND_BIN" FAKE_WORKSPACE="$WORKSPACE" FAKE_TARGET="$TARGET" FAKE_CLEAN_TRACE="$TMP_ROOT/clean.trace" "$MAINTAIN" cleanup --workspace "$WORKSPACE" --target "$TARGET"
if [ -d "$TARGET/debug/incremental/fail-case" ]; then pass 'failed discovery does not partially delete incremental data'; else fail 'failed discovery does not partially delete incremental data'; fi
if [ "$(wc -l <"$TMP_ROOT/clean.trace" | tr -d ' ')" = 4 ]; then pass 'failed discovery does not invoke cargo clean'; else fail 'failed discovery does not invoke cargo clean'; fi

TOOL_ROOT="$WORKSPACE/.cache/ci-tools/test"
FALLBACK_TARGET="$WORKSPACE/.cache/ci-tool-build/test"
mkdir -p "$TOOL_ROOT/bin" "$FALLBACK_TARGET"
expect_success 'strict tool specs and isolated roots validate' run_maintain validate-tools --specs 'cargo-nextest@0.9.85,cargo-deny@0.18.3' --tool-root "$TOOL_ROOT" --fallback-target "$FALLBACK_TARGET"
expect_success 'empty optional tool specs are a no-op' run_maintain validate-tools --specs ''
for bad in '--evil@1.2.3' 'cargo-nextest@1' 'cargo-nextest@1.2' 'cargo-nextest@1.2.3;touch' 'cargo_nextest@1.2.3' 'cargo-nextest@01.2.3' 'cargo-nextest@1.2.3,'; do
  expect_failure "invalid tool spec is rejected: $bad" run_maintain validate-tools --specs "$bad"
done
expect_failure 'tool root and fallback target cannot overlap' run_maintain validate-tools --specs 'cargo-nextest@0.9.85' --tool-root "$TOOL_ROOT" --fallback-target "$TOOL_ROOT/build"

PREPARE_WORKSPACE="$TMP_ROOT/prepare-workspace"
PREPARE_TEMP="$TMP_ROOT/runner-temp"
mkdir -p "$PREPARE_WORKSPACE/.cache" "$PREPARE_TEMP"
expect_success 'prepare-roots creates contained cache roots' run_maintain prepare-roots \
  --workspace "$PREPARE_WORKSPACE" --tool-root "$PREPARE_WORKSPACE/.cache/ci-tools/test" \
  --runner-temp "$PREPARE_TEMP" --fallback-target "$PREPARE_TEMP/rss-tool-build-target"
if [ -d "$PREPARE_WORKSPACE/.cache/ci-tools/test" ] && [ -d "$PREPARE_TEMP/rss-tool-build-target" ]; then
  pass 'prepare-roots materializes both roots'
else
  fail 'prepare-roots materializes both roots'
fi
ln -s "$OUTSIDE" "$PREPARE_WORKSPACE/.cache/tool-link"
expect_failure 'prepare-roots rejects a symlink ancestor' run_maintain prepare-roots \
  --workspace "$PREPARE_WORKSPACE" --tool-root "$PREPARE_WORKSPACE/.cache/tool-link/profile" \
  --runner-temp "$PREPARE_TEMP" --fallback-target "$PREPARE_TEMP/other-target"
expect_failure 'prepare-roots rejects lexical escape' run_maintain prepare-roots \
  --workspace "$PREPARE_WORKSPACE" --tool-root "$PREPARE_WORKSPACE/../outside/tool-root" \
  --runner-temp "$PREPARE_TEMP" --fallback-target "$PREPARE_TEMP/other-target"
expect_failure 'prepare-roots rejects a non-normalized tool root' run_maintain prepare-roots \
  --workspace "$PREPARE_WORKSPACE" --tool-root "$PREPARE_WORKSPACE/.cache/../tool-root" \
  --runner-temp "$PREPARE_TEMP" --fallback-target "$PREPARE_TEMP/other-target"
expect_failure 'prepare-roots rejects fallback target outside runner temp' run_maintain prepare-roots \
  --workspace "$PREPARE_WORKSPACE" --tool-root "$PREPARE_WORKSPACE/.cache/ci-tools/other" \
  --runner-temp "$PREPARE_TEMP" --fallback-target "$OUTSIDE/build-target"
ln -s "$OUTSIDE" "$PREPARE_TEMP/target-link"
expect_failure 'prepare-roots rejects fallback symlink ancestor' run_maintain prepare-roots \
  --workspace "$PREPARE_WORKSPACE" --tool-root "$PREPARE_WORKSPACE/.cache/ci-tools/other" \
  --runner-temp "$PREPARE_TEMP" --fallback-target "$PREPARE_TEMP/target-link/build"

cat >"$TOOL_ROOT/bin/cargo-nextest" <<'EOF'
#!/bin/sh
printf 'cargo-nextest 0.9.85\n'
EOF
chmod +x "$TOOL_ROOT/bin/cargo-nextest"
expect_success 'cached tool exact version verifies' run_maintain verify-tool --root "$TOOL_ROOT" --spec 'cargo-nextest@0.9.85'
expect_success 'cached tool layout validates without execution' run_maintain validate-tool-layout --root "$TOOL_ROOT" --spec 'cargo-nextest@0.9.85'
SIDE_EFFECT="$TMP_ROOT/version-side-effect"
cat >"$TOOL_ROOT/bin/cargo-side-effect" <<EOF
#!/bin/sh
touch '$SIDE_EFFECT'
printf 'cargo-side-effect 1.2.3\n'
EOF
chmod +x "$TOOL_ROOT/bin/cargo-side-effect"
expect_success 'cache-hit layout check accepts a safe executable' run_maintain validate-tool-layout --root "$TOOL_ROOT" --spec 'cargo-side-effect@1.2.3'
if [ ! -e "$SIDE_EFFECT" ]; then pass 'cache-hit layout check never executes the binary'; else fail 'cache-hit layout check never executes the binary'; fi
cat >"$TOOL_ROOT/bin/cargo-mixed" <<'EOF'
#!/bin/sh
printf 'cargo-mixed 1.2.3 dependency 9.8.7\n'
EOF
chmod +x "$TOOL_ROOT/bin/cargo-mixed"
expect_failure 'fresh tool verification rejects mixed version output' run_maintain verify-tool --root "$TOOL_ROOT" --spec 'cargo-mixed@1.2.3'
cat >"$TOOL_ROOT/bin/cargo-failing" <<EOF
#!/bin/sh
printf 'No such file or directory SECRET_CANARY token=credential https://example.invalid $WORKSPACE\n' >&2
exit 25
EOF
chmod +x "$TOOL_ROOT/bin/cargo-failing"
expect_safe_failure 'tool version failure emits closed diagnostic only' \
  'ci-cache-maintain: command failed stage=tool-version subject=cargo-failing@1.2.3 exit=25 class=not-found' \
  run_maintain verify-tool --root "$TOOL_ROOT" --spec 'cargo-failing@1.2.3'
expect_failure 'cached tool version pollution fails closed' run_maintain verify-tool --root "$TOOL_ROOT" --spec 'cargo-nextest@0.9.84'
ln -s "$TOOL_ROOT/bin/cargo-nextest" "$TOOL_ROOT/bin/cargo-deny"
expect_failure 'cached tool symlink is rejected' run_maintain verify-tool --root "$TOOL_ROOT" --spec 'cargo-deny@0.9.85'

if [ "$FAILURES" -ne 0 ]; then
  printf '%s cache maintenance selftest(s) failed\n' "$FAILURES" >&2
  exit 1
fi
printf 'all ci cache maintenance selftests passed\n'
