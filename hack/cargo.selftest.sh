#!/usr/bin/env sh
set -eu

# The harness owns every input it asserts. Cargo sets CARGO_BUILD_JOBS for its
# own child tests, which must not turn the wrapper's default-path case into an
# accidental override case.
unset CARGO_BUILD_JOBS CARGO_TARGET_DIR RSS_COMPILER_CACHE RUSTC_WRAPPER
unset RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC_WRAPPER
unset CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER
unset RSS_INTERNAL_SCCACHE_PATH CARGO_INCREMENTAL SCCACHE_IGNORE_SERVER_IO_ERROR

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd -P)
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/rss-cargo-selftest.XXXXXX")
trap 'rm -rf "$TMP_ROOT"' EXIT HUP INT TERM

(CDPATH='' cd -- "$REPO_ROOT" && \
    /usr/bin/python3 -m unittest discover -s hack/tests -p 'test_ci_local_supervisor.py')

fail() {
    printf 'cargo selftest: %s\n' "$*" >&2
    exit 1
}

assert_distinct_targets() {
    [ "$1" != "$2" ] || return 1
    case "$1" in
        "$3"/.cache/cargo-target) ;;
        *) return 1 ;;
    esac
    case "$2" in
        "$4"/.cache/cargo-target) ;;
        *) return 1 ;;
    esac
}

write_fixture() {
    fixture=$1
    mkdir -p "$fixture/.cargo" "$fixture/hack" "$fixture/src"
    mkdir -p "$fixture/.github/scripts"
    cp "$REPO_ROOT/.cargo/config.toml" "$fixture/.cargo/config.toml"
    cp "$REPO_ROOT/hack/cargo.sh" "$fixture/hack/cargo.sh"
    cp "$REPO_ROOT/.github/scripts/ci-tool-adapters.sh" \
        "$REPO_ROOT/.github/scripts/ci-tool-catalog.txt" "$fixture/.github/scripts/"

    cat >"$fixture/Cargo.toml" <<'EOF'
[package]
name = "target-isolation-fixture"
version = "0.0.0"
edition = "2021"
build = "build.rs"
EOF
    cat >"$fixture/src/main.rs" <<'EOF'
fn main() {}
EOF
    cat >"$fixture/build.rs" <<'EOF'
use std::{env, fs, path::PathBuf, thread, time::{Duration, Instant}};

fn main() {
    println!("cargo:rerun-if-env-changed=RSS_BARRIER_ID");
    let root = PathBuf::from(env::var_os("RSS_BARRIER_ROOT").expect("barrier root"));
    let id = env::var("RSS_BARRIER_ID").expect("barrier id");
    fs::create_dir_all(&root).expect("create barrier root");
    fs::write(root.join(format!("entered-{id}")), b"entered").expect("enter barrier");
    let deadline = Instant::now() + Duration::from_secs(15);
    while !(root.join("entered-main").is_file() && root.join("entered-linked").is_file()) {
        assert!(Instant::now() < deadline, "the other worktree never entered its build script");
        thread::sleep(Duration::from_millis(50));
    }
    fs::write(root.join(format!("released-{id}")), b"released").expect("release barrier");
}
EOF
    cat >"$fixture/Makefile" <<'EOF'
RSS_CARGO ?= ./hack/cargo.sh
.PHONY: cargo-probe
cargo-probe:
	@$(RSS_CARGO) metadata --no-deps --format-version 1 >/dev/null
EOF
}

metadata_target() {
    cargo metadata --no-deps --format-version 1 | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p'
}

write_fake_cargo() {
    destination=$1
    cat >"$destination" <<'EOF'
#!/bin/sh
set -eu
: "${RSS_CAPTURE:?capture path is required}"
{
    printf 'RUSTC_WRAPPER=%s\n' "${RUSTC_WRAPPER-<unset>}"
    printf 'RUSTC_WORKSPACE_WRAPPER=%s\n' "${RUSTC_WORKSPACE_WRAPPER-<unset>}"
    printf 'CARGO_BUILD_RUSTC_WRAPPER=%s\n' "${CARGO_BUILD_RUSTC_WRAPPER-<unset>}"
    printf 'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=%s\n' \
        "${CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER-<unset>}"
    printf 'RSS_INTERNAL_SCCACHE_PATH=%s\n' "${RSS_INTERNAL_SCCACHE_PATH-<unset>}"
    printf 'CARGO_INCREMENTAL=%s\n' "${CARGO_INCREMENTAL-<unset>}"
    printf 'SCCACHE_IGNORE_SERVER_IO_ERROR=%s\n' "${SCCACHE_IGNORE_SERVER_IO_ERROR-<unset>}"
    printf 'CARGO_TARGET_DIR=%s\n' "${CARGO_TARGET_DIR-<unset>}"
} >"$RSS_CAPTURE"
EOF
    chmod +x "$destination"
}

write_fake_sccache() {
    destination=$1
    version=$2
    cat >"$destination" <<EOF
#!/bin/sh
set -eu
[ "\$#" -eq 1 ] && [ "\$1" = --version ]
printf '%s\\n' '$version'
EOF
    chmod +x "$destination"
}

assert_capture() {
    capture=$1
    shift
    [ -s "$capture" ] || fail "fake Cargo capture is empty"
    for expected in "$@"; do
        grep -F -x "$expected" "$capture" >/dev/null ||
            fail "fake Cargo capture is missing: $expected"
    done
}

root="$TMP_ROOT/root repo"
linked="$TMP_ROOT/linked worktree"
write_fixture "$root"
root=$(CDPATH='' cd -- "$root" && pwd -P)
/usr/bin/git -C "$root" init -q
/usr/bin/git -C "$root" config user.email cargo-selftest@example.invalid
/usr/bin/git -C "$root" config user.name cargo-selftest
/usr/bin/git -C "$root" add .
/usr/bin/git -C "$root" commit -qm fixture
/usr/bin/git -C "$root" worktree add -q -b linked "$linked"
linked=$(CDPATH='' cd -- "$linked" && pwd -P)

main_target=$(CDPATH='' cd -- "$root" && metadata_target)
linked_target=$(CDPATH='' cd -- "$linked" && metadata_target)
assert_distinct_targets "$main_target" "$linked_target" "$root" "$linked" ||
    fail "direct Cargo did not resolve distinct worktree-local targets"

# Synthetic red: prove the isolation assertion rejects the former shared-target shape.
if assert_distinct_targets "$main_target" "$main_target" "$root" "$linked"; then
    fail "target isolation guard accepted a shared target"
fi

diag="$TMP_ROOT/wrapper.diag"
(CDPATH='' cd -- "$root" && ./hack/cargo.sh metadata --no-deps --format-version 1 >/dev/null 2>"$diag")
grep -F "source=config-default resolved=$main_target" "$diag" >/dev/null ||
    fail "wrapper did not diagnose the config-default target"
grep -F "source=default value=2" "$diag" >/dev/null ||
    fail "wrapper did not diagnose the default build job limit"

custom_target="$root/custom target"
custom_json="$TMP_ROOT/custom.json"
custom_diag="$TMP_ROOT/custom.diag"
(CDPATH='' cd -- "$root" && CARGO_TARGET_DIR='custom target' CARGO_BUILD_JOBS=7 \
    ./hack/cargo.sh metadata --no-deps --format-version 1 >"$custom_json" 2>"$custom_diag")
grep -F "source=env-override resolved=$custom_target" "$custom_diag" >/dev/null ||
    fail "wrapper did not diagnose the custom target override"
grep -F "source=env-override value=7" "$custom_diag" >/dev/null ||
    fail "wrapper did not preserve the build job override"
grep -F "\"target_directory\":\"$custom_target\"" "$custom_json" >/dev/null ||
    fail "wrapper did not preserve CARGO_TARGET_DIR for Cargo"

make_diag="$TMP_ROOT/make.diag"
(CDPATH='' cd -- "$linked" && make -s cargo-probe 2>"$make_diag")
grep -F "source=config-default resolved=$linked_target" "$make_diag" >/dev/null ||
    fail "Make did not use the diagnosed Cargo wrapper"

policy_root="$TMP_ROOT/compiler cache policy"
mkdir -p "$policy_root/exact" "$policy_root/missing" "$policy_root/nonexec" \
    "$policy_root/wrong" "$policy_root/symlink"
policy_root=$(CDPATH='' cd -- "$policy_root" && pwd -P)
write_fake_cargo "$policy_root/exact/cargo"
write_fake_cargo "$policy_root/missing/cargo"
write_fake_cargo "$policy_root/nonexec/cargo"
write_fake_cargo "$policy_root/wrong/cargo"
write_fake_cargo "$policy_root/symlink/cargo"
write_fake_sccache "$policy_root/exact/sccache" 'sccache 0.15.0'
write_fake_sccache "$policy_root/nonexec/sccache" 'sccache 0.15.0'
chmod -x "$policy_root/nonexec/sccache"
write_fake_sccache "$policy_root/wrong/sccache" 'sccache 0.14.0'
ln -s "$policy_root/exact/sccache" "$policy_root/symlink/sccache"

auto_capture="$TMP_ROOT/auto.capture"
(CDPATH='' cd -- "$root" && PATH="$policy_root/exact:/usr/bin:/bin" \
    RSS_CAPTURE="$auto_capture" RUSTC_WRAPPER=/ambient/wrapper \
    RUSTC_WORKSPACE_WRAPPER=/ambient/workspace-wrapper \
    CARGO_BUILD_RUSTC_WRAPPER=/ambient/config-wrapper \
    CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=/ambient/config-workspace-wrapper \
    RSS_INTERNAL_SCCACHE_PATH=/ambient/sccache CARGO_INCREMENTAL=1 \
    SCCACHE_IGNORE_SERVER_IO_ERROR=0 ./hack/cargo.sh probe >/dev/null 2>&1)
assert_capture "$auto_capture" \
    "CARGO_TARGET_DIR=$main_target" \
    "RUSTC_WRAPPER=$policy_root/exact/sccache" \
    'RUSTC_WORKSPACE_WRAPPER=<unset>' \
    'CARGO_BUILD_RUSTC_WRAPPER=<unset>' \
    'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=<unset>' \
    "RSS_INTERNAL_SCCACHE_PATH=$policy_root/exact/sccache" \
    'CARGO_INCREMENTAL=0' \
    'SCCACHE_IGNORE_SERVER_IO_ERROR=1'

off_capture="$TMP_ROOT/off.capture"
(CDPATH='' cd -- "$root" && PATH="$policy_root/exact:/usr/bin:/bin" \
    RSS_CAPTURE="$off_capture" RSS_COMPILER_CACHE=off RUSTC_WRAPPER=/ambient/wrapper \
    RUSTC_WORKSPACE_WRAPPER=/ambient/workspace-wrapper \
    CARGO_BUILD_RUSTC_WRAPPER=/ambient/config-wrapper \
    CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=/ambient/config-workspace-wrapper \
    RSS_INTERNAL_SCCACHE_PATH=/ambient/sccache ./hack/cargo.sh probe >/dev/null 2>&1)
assert_capture "$off_capture" 'RUSTC_WRAPPER=<unset>' \
    'RUSTC_WORKSPACE_WRAPPER=<unset>' 'CARGO_BUILD_RUSTC_WRAPPER=<unset>' \
    'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=<unset>' 'RSS_INTERNAL_SCCACHE_PATH=<unset>'

missing_capture="$TMP_ROOT/missing.capture"
(CDPATH='' cd -- "$root" && PATH="$policy_root/missing:/usr/bin:/bin" \
    RSS_CAPTURE="$missing_capture" RUSTC_WRAPPER=/ambient/wrapper \
    RUSTC_WORKSPACE_WRAPPER=/ambient/workspace-wrapper \
    CARGO_BUILD_RUSTC_WRAPPER=/ambient/config-wrapper \
    CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=/ambient/config-workspace-wrapper \
    RSS_INTERNAL_SCCACHE_PATH=/ambient/sccache ./hack/cargo.sh probe >/dev/null 2>&1)
assert_capture "$missing_capture" 'RUSTC_WRAPPER=<unset>' \
    'RUSTC_WORKSPACE_WRAPPER=<unset>' 'CARGO_BUILD_RUSTC_WRAPPER=<unset>' \
    'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=<unset>' 'RSS_INTERNAL_SCCACHE_PATH=<unset>'

mkdir -p "$root/relative-bin"
write_fake_cargo "$root/relative-bin/cargo"
write_fake_sccache "$root/relative-bin/sccache" 'sccache 0.15.0'

for skipped in nonexec wrong symlink; do
    skipped_capture="$TMP_ROOT/$skipped.capture"
    (CDPATH='' cd -- "$root" && \
        PATH="$policy_root/$skipped:$policy_root/exact:/usr/bin:/bin" \
        RSS_CAPTURE="$skipped_capture" RUSTC_WRAPPER=/ambient/wrapper \
        ./hack/cargo.sh probe >/dev/null 2>&1)
    assert_capture "$skipped_capture" \
        "RUSTC_WRAPPER=$policy_root/exact/sccache" \
        "RSS_INTERNAL_SCCACHE_PATH=$policy_root/exact/sccache" \
        'CARGO_INCREMENTAL=0' 'SCCACHE_IGNORE_SERVER_IO_ERROR=1'
done

# A relative PATH entry is physically normalized before validation and handoff.
relative_capture="$TMP_ROOT/relative.capture"
(CDPATH='' cd -- "$root" && PATH="relative-bin:$policy_root/missing:/usr/bin:/bin" \
    RSS_CAPTURE="$relative_capture" RUSTC_WRAPPER=/ambient/wrapper \
    ./hack/cargo.sh probe >/dev/null 2>&1)
assert_capture "$relative_capture" \
    "RUSTC_WRAPPER=$root/relative-bin/sccache" \
    "RSS_INTERNAL_SCCACHE_PATH=$root/relative-bin/sccache" \
    'CARGO_INCREMENTAL=0' 'SCCACHE_IGNORE_SERVER_IO_ERROR=1'

# Auto is opportunistic: when every candidate is invalid, Cargo still runs with
# all compiler-wrapper handoffs disabled. Use a closed PATH so the harness does
# not accidentally discover a host-installed sccache.
invalid_only_capture="$TMP_ROOT/invalid-only.capture"
(CDPATH='' cd -- "$root" && PATH="$policy_root/wrong:$policy_root/missing" \
    RSS_CAPTURE="$invalid_only_capture" RUSTC_WRAPPER=/ambient/wrapper \
    /bin/sh ./hack/cargo.sh probe >/dev/null 2>&1)
assert_capture "$invalid_only_capture" 'RUSTC_WRAPPER=<unset>' \
    'RUSTC_WORKSPACE_WRAPPER=<unset>' 'CARGO_BUILD_RUSTC_WRAPPER=<unset>' \
    'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=<unset>' 'RSS_INTERNAL_SCCACHE_PATH=<unset>'

unknown_capture="$TMP_ROOT/unknown.capture"
if (CDPATH='' cd -- "$root" && PATH="$policy_root/exact:/usr/bin:/bin" \
    RSS_CAPTURE="$unknown_capture" RSS_COMPILER_CACHE=unexpected \
    ./hack/cargo.sh probe >/dev/null 2>&1); then
    fail "compiler-cache policy accepted an unknown mode"
fi
[ ! -e "$unknown_capture" ] || fail "unknown compiler-cache mode reached Cargo"

barrier="$TMP_ROOT/barrier"
(CDPATH='' cd -- "$root" && RSS_BARRIER_ROOT="$barrier" RSS_BARRIER_ID=main \
    ./hack/cargo.sh build --quiet) &
main_pid=$!
(CDPATH='' cd -- "$linked" && RSS_BARRIER_ROOT="$barrier" RSS_BARRIER_ID=linked \
    ./hack/cargo.sh build --quiet) &
linked_pid=$!
wait "$main_pid" || fail "main worktree barrier build failed"
wait "$linked_pid" || fail "linked worktree barrier build failed"

for marker in entered-main entered-linked released-main released-linked; do
    [ -s "$barrier/$marker" ] || fail "barrier anti-vacuity marker is missing: $marker"
done
[ -s "$main_target/debug/target-isolation-fixture" ] || fail "main target artifact is missing"
[ -s "$linked_target/debug/target-isolation-fixture" ] || fail "linked target artifact is missing"

printf 'cargo selftest: ok\n'
