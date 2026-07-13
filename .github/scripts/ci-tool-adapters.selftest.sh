#!/usr/bin/env bash
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ADAPTER="$SCRIPT_DIR/ci-tool-adapters.sh"
FIXTURES="$SCRIPT_DIR/testdata"
TMP_BASE=${TMPDIR:-/tmp}
TMP_ROOT=${TMP_BASE%/}/ci-tool-adapters-selftest.$$
FAILURES=0
trap 'rm -rf "$TMP_ROOT"' EXIT HUP INT TERM
mkdir -p "$TMP_ROOT"
TMP_ROOT=$(CDPATH='' cd -- "$TMP_ROOT" && pwd -P)

pass() { printf 'ok - %s\n' "$1"; }
fail() { printf 'not ok - %s\n' "$1" >&2; FAILURES=$((FAILURES + 1)); }
expect_output() {
  name=$1 expected=$2; shift 2
  if actual=$("$@" 2>"$TMP_ROOT/stderr") && [ "$actual" = "$expected" ]; then pass "$name"; else
    sed 's/^/# /' "$TMP_ROOT/stderr" >&2 || true
    printf '# expected: %s\n# actual: %s\n' "$expected" "${actual:-}" >&2
    fail "$name"
  fi
}
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
expect_failure_stderr_contains() {
  name=$1 expected=$2; shift 2
  if "$@" >"$TMP_ROOT/stdout" 2>"$TMP_ROOT/stderr"; then
    fail "$name"
  elif grep -Fq -- "$expected" "$TMP_ROOT/stderr"; then
    pass "$name"
  else
    sed 's/^/# /' "$TMP_ROOT/stderr" >&2 || true
    printf '# expected stderr to contain: %s\n' "$expected" >&2
    fail "$name"
  fi
}

[ -x "$ADAPTER" ] || {
  printf 'not ok - ci-tool-adapters.sh must exist and be executable\n' >&2
  exit 1
}

# The executable catalog is the only source of lane/backend/version policy.
expect_output 'ci-meta seals compiler cache plus digest-pinned promtool' 'sccache@0.15.0,promtool@3.5.3' "$ADAPTER" specs --lane ci-meta --backend all
expect_output 'ci-meta promtool uses the hermetic docker backend' 'promtool@3.5.3' "$ADAPTER" specs --lane ci-meta --backend docker
expect_output 'prerequisites use only binstall tools' \
  'cargo-dylint@6.0.1,dylint-link@6.0.1' \
  "$ADAPTER" specs --lane ci-core-prerequisites --backend binstall
expect_output 'core tests use nextest and sccache' 'cargo-nextest@0.9.137,sccache@0.15.0' \
  "$ADAPTER" specs --lane ci-core-tests --backend install-action
expect_output 'security tools have one closed set' \
  'cargo-deny@0.19.9,cargo-audit@0.22.2,sccache@0.15.0' \
  "$ADAPTER" specs --lane ci-security --backend install-action
expect_output 'coverage splits prebuilt tools precisely' \
  'cargo-nextest@0.9.137,cargo-llvm-cov@0.8.7,sccache@0.15.0' \
  "$ADAPTER" specs --lane ci-coverage --backend install-action
expect_output 'coverage assigns public-api to binstall' 'cargo-public-api@0.52.0' \
  "$ADAPTER" specs --lane ci-coverage --backend binstall
expect_output 'integration uses nextest' 'cargo-nextest@0.9.137,sccache@0.15.0' \
  "$ADAPTER" specs --lane integration --backend all
expect_output 'audit shares the security set' \
  'cargo-deny@0.19.9,cargo-audit@0.22.2,sccache@0.15.0' "$ADAPTER" specs --lane audit --backend all
expect_failure 'unknown lane fails closed' "$ADAPTER" specs --lane unknown --backend all
expect_failure 'unknown backend fails closed' "$ADAPTER" specs --lane audit --backend mystery
expect_output 'all tools preserve canonical catalog order' \
  'cargo-nextest@0.9.137,cargo-llvm-cov@0.8.7,cargo-deny@0.19.9,cargo-audit@0.22.2,cargo-dylint@6.0.1,dylint-link@6.0.1,cargo-public-api@0.52.0,sccache@0.15.0,promtool@3.5.3' \
  "$ADAPTER" specs --lane all --backend all
expect_output 'sccache spec is derived from the catalog' \
  'sccache|0.15.0|install-action|.install-action/bin/sccache|sccache' \
  "$ADAPTER" sccache-spec

# Catalog parsing accepts complete SemVer and rejects numeric prerelease leading zeroes.
for variant in legal illegal duplicate wrong-backend wrong-path alphanumeric; do
  mkdir -p "$TMP_ROOT/$variant"
  cp "$ADAPTER" "$TMP_ROOT/$variant/ci-tool-adapters.sh"
done
LEGAL="$TMP_ROOT/legal/ci-tool-adapters.sh"
ILLEGAL="$TMP_ROOT/illegal/ci-tool-adapters.sh"
DUPLICATE="$TMP_ROOT/duplicate/ci-tool-adapters.sh"
WRONG_BACKEND="$TMP_ROOT/wrong-backend/ci-tool-adapters.sh"
WRONG_PATH="$TMP_ROOT/wrong-path/ci-tool-adapters.sh"
ALPHANUMERIC="$TMP_ROOT/alphanumeric/ci-tool-adapters.sh"
CATALOG="$SCRIPT_DIR/ci-tool-catalog.txt"
sed 's/0\.9\.137/1.2.3-alpha.1+build.7/g' "$CATALOG" >"$TMP_ROOT/legal/ci-tool-catalog.txt"
sed 's/0\.9\.137/1.2.3-01/g' "$CATALOG" >"$TMP_ROOT/illegal/ci-tool-catalog.txt"
awk '{ print; if ($0 == "cargo-nextest|0.9.137|install-action|.install-action/bin/cargo-nextest|nextest") print }' \
  "$CATALOG" >"$TMP_ROOT/duplicate/ci-tool-catalog.txt"
sed 's/cargo-nextest|0\.9\.137|install-action|/cargo-nextest|0.9.137|unknown-backend|/' \
  "$CATALOG" >"$TMP_ROOT/wrong-backend/ci-tool-catalog.txt"
sed 's#cargo-nextest|0\.9\.137|install-action|\.install-action/bin/#cargo-nextest|0.9.137|install-action|bin/#' \
  "$CATALOG" >"$TMP_ROOT/wrong-path/ci-tool-catalog.txt"
sed 's/0\.9\.137/1.2.3-12alpha/g' "$CATALOG" >"$TMP_ROOT/alphanumeric/ci-tool-catalog.txt"
chmod +x "$LEGAL" "$ILLEGAL" "$DUPLICATE" "$WRONG_BACKEND" "$WRONG_PATH" "$ALPHANUMERIC"
expect_output 'complete prerelease and build SemVer is accepted' \
  'cargo-nextest@1.2.3-alpha.1+build.7,sccache@0.15.0' "$LEGAL" specs --lane ci-core-tests --backend all
expect_failure 'numeric prerelease leading zero is rejected' \
  "$ILLEGAL" specs --lane ci-core-tests --backend all
expect_failure 'duplicate catalog tool is rejected' \
  "$DUPLICATE" specs --lane ci-core-tests --backend all
expect_failure 'catalog tool with unknown backend is rejected' \
  "$WRONG_BACKEND" specs --lane ci-core-tests --backend all
expect_failure 'catalog backend and binary path mismatch is rejected' \
  "$WRONG_PATH" specs --lane ci-core-tests --backend all
expect_output 'alphanumeric prerelease beginning with digits is accepted' \
  'cargo-nextest@1.2.3-12alpha,sccache@0.15.0' "$ALPHANUMERIC" specs --lane ci-core-tests --backend all

make_binary() {
  path=$1 body=$2
  mkdir -p "$(dirname -- "$path")"
  # The generated fixture must expand these expressions when it is executed.
  # shellcheck disable=SC2016
  printf '#!/usr/bin/env bash\nset -eu\nprintf "%%s\\n" "$*" >>"${RSS_TEST_TRACE:?}"\n%s\n' "$body" >"$path"
  chmod +x "$path"
}

ROOT="$TMP_ROOT/tools"
TRACE="$TMP_ROOT/trace"
export RSS_TEST_TRACE="$TRACE"
mkdir -p "$ROOT/.install-action/bin"
make_binary "$ROOT/.install-action/bin/cargo-nextest" \
  "printf '%s\\n' 'cargo-nextest 1.2.3-alpha.1+build.7 (75ddba7e9 2026-05-26)' 'release: 1.2.3-alpha.1+build.7' 'commit-hash: 75ddba7e911b44c5c0700dac0415d824403de9bd' 'commit-date: 2026-05-26' 'host: x86_64-unknown-linux-gnu'"
make_binary "$ROOT/.install-action/bin/sccache" \
  "[ \"\$*\" = '--version' ]; printf '%s\\n' 'sccache 0.15.0'"
expect_output 'standalone sccache verification returns the canonical path' \
  "$ROOT/.install-action/bin/sccache" "$ADAPTER" verify-sccache \
  --candidate "$ROOT/.install-action/bin/sccache"
ln -s "$ROOT/.install-action/bin/sccache" "$TMP_ROOT/sccache-link"
expect_failure 'standalone sccache verification rejects a symlink' \
  "$ADAPTER" verify-sccache --candidate "$TMP_ROOT/sccache-link"
expect_failure 'standalone sccache verification rejects a relative path' \
  "$ADAPTER" verify-sccache --candidate .install-action/bin/sccache
expect_success 'prerelease and build SemVer passes a literal fresh nextest probe' \
  "$LEGAL" verify --mode fresh --lane ci-core-tests --root "$ROOT"
rm -f "$ROOT/.rss-tool-seal-v1"
make_binary "$ROOT/.install-action/bin/sccache" \
  "[ \"\$*\" = '--version' ]; printf '%s\\n' 'sccache v0.15.0'"
expect_failure 'sccache probe rejects a non-exact version wire shape' \
  "$LEGAL" verify --mode fresh --lane ci-core-tests --root "$ROOT"

rm -rf "$ROOT"; : >"$TRACE"
mkdir -p "$ROOT/.install-action/bin" "$ROOT/bin"
make_binary "$ROOT/.install-action/bin/cargo-nextest" \
  "cat '$FIXTURES/cargo-nextest-0.9.137.version.txt'"
make_binary "$ROOT/.install-action/bin/cargo-llvm-cov" \
  "[ \"\$*\" = 'llvm-cov --version' ]; printf '%s\\n' 'cargo-llvm-cov 0.8.7'"
make_binary "$ROOT/.install-action/bin/sccache" \
  "[ \"\$*\" = '--version' ]; printf '%s\\n' 'sccache 0.15.0'"
make_binary "$ROOT/bin/cargo-public-api" \
  "[ \"\$*\" = '--version' ]; printf '%s\\n' 'cargo-public-api 0.52.0'"

expect_success 'fresh coverage verifies real protocols and seals atomically' \
  "$ADAPTER" verify --mode fresh --lane ci-coverage --root "$ROOT"
SEAL="$ROOT/.rss-tool-seal-v1"
if [ -f "$SEAL" ] && grep -q 'cargo-nextest@0.9.137' "$SEAL" &&
   grep -q 'cargo-llvm-cov@0.8.7' "$SEAL" && grep -q 'cargo-public-api@0.52.0' "$SEAL" &&
   grep -q 'sccache@0.15.0' "$SEAL"; then
  pass 'seal records the exact requested set'
else fail 'seal records the exact requested set'; fi
if grep -qx -- '--version' "$TRACE" && grep -qx -- 'llvm-cov --version' "$TRACE"; then
  pass 'tool-specific argv are used'
else fail 'tool-specific argv are used'; fi

: >"$TRACE"
expect_success 'cache hit verifies the seal without executing tools' \
  "$ADAPTER" verify --mode cache --lane ci-coverage --root "$ROOT"
if [ ! -s "$TRACE" ]; then pass 'cache verification executes no binary'; else fail 'cache verification executes no binary'; fi
expect_failure 'cache hit rejects a different requested lane set' \
  "$ADAPTER" verify --mode cache --lane ci-core-tests --root "$ROOT"
printf '\n# tamper\n' >>"$ROOT/.install-action/bin/cargo-nextest"
expect_failure 'cache hit rejects a binary digest mismatch' \
  "$ADAPTER" verify --mode cache --lane ci-coverage --root "$ROOT"

rm -rf "$ROOT"; mkdir -p "$ROOT/.install-action/bin" "$ROOT/bin"; : >"$TRACE"
make_binary "$ROOT/.install-action/bin/cargo-nextest" \
  "cat '$FIXTURES/cargo-nextest-0.9.137.version.txt'"
make_binary "$ROOT/.install-action/bin/cargo-llvm-cov" \
  "[ \"\$*\" = 'llvm-cov --version' ]; printf '%s\\n' 'cargo-llvm-cov 0.8.7'"
make_binary "$ROOT/.install-action/bin/sccache" \
  "[ \"\$*\" = '--version' ]; printf '%s\\n' 'sccache 0.15.0'"
make_binary "$ROOT/bin/cargo-public-api" \
  "[ \"\$*\" = '--version' ]; printf '%s\\n' 'cargo-public-api 0.52.0'"
expect_success 'fresh verification reseals an exact restored set' \
  "$ADAPTER" verify --mode fresh --lane ci-coverage --root "$ROOT"
make_binary "$ROOT/bin/cargo-extra" "printf '%s\\n' 'cargo-extra 1.0.0'"
expect_failure_stderr_contains 'cache hit classifies an extra executable' \
  'tool binary layout mismatch: missing=0 extra=1' \
  "$ADAPTER" verify --mode cache --lane ci-coverage --root "$ROOT"
rm -f "$ROOT/bin/cargo-extra"
mkdir "$ROOT/bin/extra-directory"
expect_failure 'cache hit rejects an extra directory' \
  "$ADAPTER" verify --mode cache --lane ci-coverage --root "$ROOT"
rmdir "$ROOT/bin/extra-directory"
rm -f "$ROOT/.install-action/bin/cargo-nextest"
ln -s "$ROOT/.install-action/bin/cargo-llvm-cov" "$ROOT/.install-action/bin/cargo-nextest"
expect_failure_stderr_contains 'cache hit identifies a symlinked executable safely' \
  'tool binary is unsafe or unavailable: cargo-nextest@0.9.137 (.install-action/bin/cargo-nextest)' \
  "$ADAPTER" verify --mode cache --lane ci-coverage --root "$ROOT"

# nextest may repeat the expected release in metadata, but conflicting releases fail.
rm -rf "$ROOT"; mkdir -p "$ROOT/.install-action/bin"; : >"$TRACE"
make_binary "$ROOT/.install-action/bin/cargo-nextest" \
  "cat '$FIXTURES/cargo-nextest-conflicting.version.txt'"
make_binary "$ROOT/.install-action/bin/sccache" \
  "[ \"\$*\" = '--version' ]; printf '%s\\n' 'sccache 0.15.0'"
expect_failure 'nextest conflicting release metadata fails closed' \
  "$ADAPTER" verify --mode fresh --lane ci-core-tests --root "$ROOT"
if [ ! -e "$ROOT/.rss-tool-seal-v1" ]; then pass 'partial fresh verification leaves no seal'; else fail 'partial fresh verification leaves no seal'; fi
make_binary "$ROOT/.install-action/bin/cargo-nextest" \
  "cat '$FIXTURES/cargo-nextest-0.9.137.version.txt'; printf '%s\\n' 'dependency: 9.8.7'"
expect_failure 'nextest extra version-bearing output fails closed' \
  "$ADAPTER" verify --mode fresh --lane ci-core-tests --root "$ROOT"

# dylint is a Cargo subcommand; dylint-link is proven only by the cargo receipt.
rm -rf "$ROOT"; mkdir -p "$ROOT/.install-action/bin" "$ROOT/bin"; : >"$TRACE"
make_binary "$ROOT/.install-action/bin/sccache" \
  "[ \"\$*\" = '--version' ]; printf '%s\\n' 'sccache 0.15.0'"
make_binary "$ROOT/bin/cargo-dylint" \
  "[ \"\$*\" = 'dylint --version' ]; printf '%s\\n' 'cargo-dylint 6.0.1'"
make_binary "$ROOT/bin/dylint-link" "exit 91"
cat >"$ROOT/.crates.toml" <<'EOF'
[v1]
"cargo-dylint 6.0.1 (registry+https://github.com/rust-lang/crates.io-index)" = ["cargo-dylint"]
"dylint-link 6.0.1 (registry+https://github.com/rust-lang/crates.io-index)" = ["dylint-link"]
EOF
expect_success 'fresh prerequisites use dylint argv and exact install receipt' \
  "$ADAPTER" verify --mode fresh --lane ci-core-prerequisites --root "$ROOT"
if grep -qx -- 'dylint --version' "$TRACE" && ! grep -qx -- '' "$TRACE"; then
  pass 'dylint-link is never executed'
else fail 'dylint-link is never executed'; fi
printf '%s\n' '"dylint-link 6.0.0 (registry+https://github.com/rust-lang/crates.io-index)" = ["dylint-link"]' >>"$ROOT/.crates.toml"
rm -f "$ROOT/.rss-tool-seal-v1"
expect_failure 'duplicate dylint-link receipt evidence fails closed' \
  "$ADAPTER" verify --mode fresh --lane ci-core-prerequisites --root "$ROOT"
sed -i.bak '/dylint-link 6\.0\.0/d' "$ROOT/.crates.toml"
sed -i.bak 's/dylint-link 6\.0\.1/dylint-link 6.0.0/' "$ROOT/.crates.toml"
rm -f "$ROOT/.rss-tool-seal-v1"
expect_failure 'wrong dylint-link receipt version fails closed' \
  "$ADAPTER" verify --mode fresh --lane ci-core-prerequisites --root "$ROOT"
sed -i.bak 's/dylint-link 6\.0\.0 (registry+https:\/\/github.com\/rust-lang\/crates.io-index)/dylint-link 6.0.1 (path+file:\/\/\/tmp\/forged)/' "$ROOT/.crates.toml"
expect_failure 'non-registry dylint-link receipt source fails closed' \
  "$ADAPTER" verify --mode fresh --lane ci-core-prerequisites --root "$ROOT"
sed -i.bak 's/dylint-link 6\.0\.1 (path+file:\/\/\/tmp\/forged)\" = \[\"dylint-link\"\]/dylint-link 6.0.1 (registry+https:\/\/github.com\/rust-lang\/crates.io-index)\" = [\"other-bin\"]/' "$ROOT/.crates.toml"
expect_failure 'wrong dylint-link receipt binary fails closed' \
  "$ADAPTER" verify --mode fresh --lane ci-core-prerequisites --root "$ROOT"

# Seals bind adapter identity, lane/request set, safe paths, regular executables, and OCI digest.
FAKE_DOCKER_BIN="$TMP_ROOT/fake-docker-bin"
mkdir -p "$FAKE_DOCKER_BIN"
make_binary "$FAKE_DOCKER_BIN/docker" \
  "printf '%s\n' 'promtool, version 3.5.3 (branch: HEAD, revision: fixture)'"
PATH="$FAKE_DOCKER_BIN:$PATH"
export PATH
rm -rf "$ROOT"; mkdir -p "$ROOT/.install-action/bin"
make_binary "$ROOT/.install-action/bin/sccache" \
  "[ \"\$*\" = '--version' ]; printf '%s\\n' 'sccache 0.15.0'"
expect_success 'ci-meta creates a compiler-cache and OCI policy seal' \
  "$ADAPTER" verify --mode fresh --lane ci-meta --root "$ROOT"
if grep -Fq 'prom/prometheus@sha256:ddc2493835a1509976d5e4e0c94199c4f843ce1f42dd6bcfc8231ba734a93ff7' "$ROOT/.rss-tool-seal-v1"; then
  pass 'seal records the exact promtool image digest'
else fail 'seal records the exact promtool image digest'; fi
expect_failure 'missing docker fails the fresh promtool probe closed' \
  env PATH=/usr/bin:/bin "$ADAPTER" verify --mode fresh --lane ci-meta --root "$ROOT"
BAD_DOCKER_BIN="$TMP_ROOT/bad-docker-bin"
mkdir -p "$BAD_DOCKER_BIN"
make_binary "$BAD_DOCKER_BIN/docker" \
  "printf '%s\n' 'promtool, version 3.5.2 (branch: HEAD, revision: fixture)'"
expect_failure 'promtool version mismatch fails the fresh probe closed' \
  env PATH="$BAD_DOCKER_BIN:/usr/bin:/bin" "$ADAPTER" verify --mode fresh --lane ci-meta --root "$ROOT"
expect_success 'exact promtool version restores the fresh seal after negative probes' \
  "$ADAPTER" verify --mode fresh --lane ci-meta --root "$ROOT"
cp "$SEAL" "$TMP_ROOT/empty-seal" 2>/dev/null || true
printf '\n# identity change\n' >>"$LEGAL"
expect_failure 'adapter identity change invalidates an old seal' \
  "$LEGAL" verify --mode cache --lane ci-meta --root "$ROOT"

CATALOG_ADAPTER_DIR="$TMP_ROOT/catalog-identity"
mkdir -p "$CATALOG_ADAPTER_DIR"
cp "$ADAPTER" "$CATALOG_ADAPTER_DIR/ci-tool-adapters.sh"
cp "$CATALOG" "$CATALOG_ADAPTER_DIR/ci-tool-catalog.txt"
chmod +x "$CATALOG_ADAPTER_DIR/ci-tool-adapters.sh"
rm -rf "$ROOT"; mkdir -p "$ROOT/.install-action/bin"
make_binary "$ROOT/.install-action/bin/sccache" \
  "[ \"\$*\" = '--version' ]; printf '%s\\n' 'sccache 0.15.0'"
expect_success 'catalog identity is sealed independently from the adapter' \
  "$CATALOG_ADAPTER_DIR/ci-tool-adapters.sh" verify --mode fresh --lane ci-meta --root "$ROOT"
sed -i.bak 's/cargo-nextest|0\.9\.137|/cargo-nextest|9.9.9|/' \
  "$CATALOG_ADAPTER_DIR/ci-tool-catalog.txt"
expect_failure_stderr_contains 'catalog identity change invalidates an old seal' \
  'tool seal metadata mismatch: lane=ci-meta' \
  "$CATALOG_ADAPTER_DIR/ci-tool-adapters.sh" verify --mode cache --lane ci-meta --root "$ROOT"

# Hash command status and output are both part of the evidence boundary.
FAKE_HASH_BIN="$TMP_ROOT/fake-hash-bin"
mkdir -p "$FAKE_HASH_BIN"
cat >"$FAKE_HASH_BIN/sha256sum" <<'EOF'
#!/usr/bin/env bash
set -eu
case "${FAKE_HASH_MODE:?}" in
  fail) printf '%064d  %s\n' 0 "$1"; exit 7 ;;
  empty) exit 0 ;;
  malformed) printf 'not-a-sha256  %s\n' "$1" ;;
  binary-fail|binary-empty|binary-malformed)
    case "$1" in
      */ci-tool-adapters.sh|*/ci-tool-catalog.txt) printf '%064d  %s\n' 1 "$1" ;;
      *)
        case "$FAKE_HASH_MODE" in
          binary-fail) printf '%064d  %s\n' 0 "$1"; exit 7 ;;
          binary-empty) exit 0 ;;
          binary-malformed) printf 'not-a-sha256  %s\n' "$1" ;;
        esac
        ;;
    esac
    ;;
  *) exit 64 ;;
esac
EOF
chmod +x "$FAKE_HASH_BIN/sha256sum"
for mode in fail empty malformed; do
  rm -rf "$ROOT"; mkdir -p "$ROOT/.install-action/bin"
  make_binary "$ROOT/.install-action/bin/sccache" \
    "[ \"\$*\" = '--version' ]; printf '%s\\n' 'sccache 0.15.0'"
  expect_failure "hash evidence fails closed: $mode" \
    env PATH="$FAKE_HASH_BIN:$PATH" FAKE_HASH_MODE="$mode" \
    "$ADAPTER" verify --mode fresh --lane ci-meta --root "$ROOT"
  if [ ! -e "$ROOT/.rss-tool-seal-v1" ]; then
    pass "failed hash evidence leaves no seal: $mode"
  else
    fail "failed hash evidence leaves no seal: $mode"
  fi
done

for mode in binary-fail binary-empty binary-malformed; do
  rm -rf "$ROOT"; mkdir -p "$ROOT/.install-action/bin"; : >"$TRACE"
  make_binary "$ROOT/.install-action/bin/cargo-nextest" \
    "cat '$FIXTURES/cargo-nextest-0.9.137.version.txt'"
  make_binary "$ROOT/.install-action/bin/sccache" \
    "[ \"\$*\" = '--version' ]; printf '%s\\n' 'sccache 0.15.0'"
  expect_failure "binary hash evidence fails closed: $mode" \
    env PATH="$FAKE_HASH_BIN:$PATH" FAKE_HASH_MODE="$mode" \
    "$ADAPTER" verify --mode fresh --lane ci-core-tests --root "$ROOT"
  if [ ! -e "$ROOT/.rss-tool-seal-v1" ]; then
    pass "failed binary hash evidence leaves no seal: $mode"
  else
    fail "failed binary hash evidence leaves no seal: $mode"
  fi
done

if [ "$FAILURES" -ne 0 ]; then
  printf '%s ci tool adapter selftest(s) failed\n' "$FAILURES" >&2
  exit 1
fi
printf 'all ci tool adapter selftests passed\n'
