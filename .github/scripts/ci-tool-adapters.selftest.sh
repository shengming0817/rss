#!/usr/bin/env bash
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ADAPTER="$SCRIPT_DIR/ci-tool-adapters.sh"
FIXTURES="$SCRIPT_DIR/testdata"
TMP_BASE=${TMPDIR:-/tmp}
TMP_ROOT=$(mktemp -d "${TMP_BASE%/}/ci-tool-adapters-selftest.XXXXXX")
FAILURES=0
trap 'rm -rf "$TMP_ROOT"' EXIT HUP INT TERM
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
expect_failure_stderr_equals() {
  name=$1 expected=$2; shift 2
  if "$@" >"$TMP_ROOT/stdout" 2>"$TMP_ROOT/stderr"; then
    fail "$name"
  elif [ ! -s "$TMP_ROOT/stdout" ] && [ "$(cat "$TMP_ROOT/stderr")" = "$expected" ]; then
    pass "$name"
  else
    sed 's/^/# /' "$TMP_ROOT/stderr" >&2 || true
    printf '# expected exact stderr: %s\n' "$expected" >&2
    fail "$name"
  fi
}

[ -x "$ADAPTER" ] || {
  printf 'not ok - ci-tool-adapters.sh must exist and be executable\n' >&2
  exit 1
}

# The executable catalog is the only source of lane/backend/version policy.
expect_output 'ci-meta seals compiler cache, promtool, and Helm' 'sccache@0.15.0,promtool@3.5.3,helm@4.2.0' "$ADAPTER" specs --lane ci-meta --backend all
expect_output 'ci-meta promtool uses the hermetic docker backend' 'promtool@3.5.3' "$ADAPTER" specs --lane ci-meta --backend docker
expect_output 'ci-meta Helm uses the checksum-pinned download backend' 'helm@4.2.0' "$ADAPTER" specs --lane ci-meta --backend download
expect_output 'prerequisites use only binstall tools' \
  'cargo-dylint@6.0.1,dylint-link@6.0.1' \
  "$ADAPTER" specs --lane ci-core-prerequisites --backend binstall
expect_output 'core tests use nextest and sccache' 'cargo-nextest@0.9.137,sccache@0.15.0' \
  "$ADAPTER" specs --lane ci-core-tests --backend install-action
expect_output 'LocalOnly execution uses only pinned nextest plus the compiler cache' \
  'cargo-nextest@0.9.137,sccache@0.15.0' \
  "$ADAPTER" specs --lane ci-local-only --backend install-action
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
  'cargo-nextest@0.9.137,cargo-llvm-cov@0.8.7,cargo-deny@0.19.9,cargo-audit@0.22.2,cargo-dylint@6.0.1,dylint-link@6.0.1,cargo-public-api@0.52.0,sccache@0.15.0,promtool@3.5.3,helm@4.2.0' \
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

make_ci_meta_tools() {
  mkdir -p "$ROOT/.install-action/bin" "$ROOT/.download/bin"
  make_binary "$ROOT/.install-action/bin/sccache" \
    "[ \"\$*\" = '--version' ]; printf '%s\\n' 'sccache 0.15.0'"
  make_binary "$ROOT/.download/bin/helm" \
    "[ \"\$*\" = 'version --template {{.Version}}' ]; printf '%s\\n' 'v4.2.0'"
}

make_download_fixture() {
  download_fake_bin=$1
  mkdir -p "$download_fake_bin"
  cat >"$download_fake_bin/uname" <<'EOF'
#!/usr/bin/env bash
set -eu
case "$1" in
  -s) printf '%s\n' Linux ;;
  -m) printf '%s\n' x86_64 ;;
  *) exit 64 ;;
esac
EOF
  cat >"$download_fake_bin/curl" <<'EOF'
#!/usr/bin/env bash
set -eu
printf 'curl|%s\n' "$*" >>"${RSS_DOWNLOAD_TRACE:?}"
[ "$#" -eq 10 ] && [ "$1" = --proto ] && [ "$2" = '=https' ] &&
  [ "$3" = --tlsv1.2 ] && [ "$4" = --fail ] && [ "$5" = --location ] &&
  [ "$6" = --silent ] && [ "$7" = --show-error ] && [ "$8" = --output ] &&
  [ "${10}" = 'https://get.helm.sh/helm-v4.2.0-linux-amd64.tar.gz' ] || exit 65
printf '%s\n' offline-helm-archive >"$9"
EOF
  cat >"$download_fake_bin/sha256sum" <<'EOF'
#!/usr/bin/env bash
set -eu
printf 'sha256sum|%s\n' "$*" >>"${RSS_DOWNLOAD_TRACE:?}"
case "${RSS_DOWNLOAD_MODE:-success}" in
  checksum-mismatch) digest=0000000000000000000000000000000000000000000000000000000000000000 ;;
  *) digest=97dbeb971be4ac4b27e3839976d9564c0fb35c6f3b1da89dd1e292d236af4096 ;;
esac
printf '%s  %s\n' "$digest" "$1"
EOF
  cat >"$download_fake_bin/tar" <<'EOF'
#!/usr/bin/env bash
set -eu
printf 'tar|%s\n' "$*" >>"${RSS_DOWNLOAD_TRACE:?}"
[ "$#" -eq 5 ] && [ "$1" = -xzf ] && [ "$3" = -C ] &&
  [ "$5" = linux-amd64/helm ] || exit 66
[ "${RSS_DOWNLOAD_MODE:-success}" != extract-fail ] || exit 67
mkdir -p "$4/linux-amd64"
printf '#!/usr/bin/env sh\nprintf "v4.2.0\\n"\n' >"$4/linux-amd64/helm"
EOF
  cat >"$download_fake_bin/mv" <<'EOF'
#!/usr/bin/env bash
set -eu
printf 'mv|%s\n' "$*" >>"${RSS_DOWNLOAD_TRACE:?}"
[ "${RSS_DOWNLOAD_MODE:-success}" != publish-fail ] || exit 68
exec /bin/mv "$@"
EOF
  chmod +x "$download_fake_bin/uname" "$download_fake_bin/curl" \
    "$download_fake_bin/sha256sum" "$download_fake_bin/tar" "$download_fake_bin/mv"
}

assert_download_clean() {
  name=$1 root=$2 staging=$3
  if [ ! -e "$root/.download" ] &&
     [ -z "$(find "$staging" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    pass "$name"
  else
    fail "$name"
  fi
}

# Download installation is exercised without the network. Fakes enforce the
# pinned transport, checksum, archive member, and atomic publication protocol.
DOWNLOAD_FAKE_BIN="$TMP_ROOT/download-fake-bin"
DOWNLOAD_TMP="$TMP_ROOT/download-tmp"
DOWNLOAD_TRACE="$TMP_ROOT/download-trace"
DOWNLOAD_ROOT="$TMP_ROOT/download-tools"
mkdir -p "$DOWNLOAD_TMP" "$DOWNLOAD_ROOT"
make_download_fixture "$DOWNLOAD_FAKE_BIN"
export RSS_DOWNLOAD_TRACE="$DOWNLOAD_TRACE"
: >"$DOWNLOAD_TRACE"
expect_success 'offline Helm download uses the pinned installation protocol' \
  env PATH="$DOWNLOAD_FAKE_BIN:$PATH" TMPDIR="$DOWNLOAD_TMP" RSS_DOWNLOAD_MODE=success \
  "$ADAPTER" install-download --lane ci-meta --root "$DOWNLOAD_ROOT"
if [ -f "$DOWNLOAD_ROOT/.download/bin/helm" ] &&
   [ -x "$DOWNLOAD_ROOT/.download/bin/helm" ] &&
   [ "$("$DOWNLOAD_ROOT/.download/bin/helm")" = v4.2.0 ] &&
   grep -Eq '^curl\|--proto =https --tlsv1\.2 --fail --location --silent --show-error --output .*/helm\.tar\.gz https://get\.helm\.sh/helm-v4\.2\.0-linux-amd64\.tar\.gz$' "$DOWNLOAD_TRACE" &&
   grep -Eq '^sha256sum\|.*/helm\.tar\.gz$' "$DOWNLOAD_TRACE" &&
   grep -Eq '^tar\|-xzf .*/helm\.tar\.gz -C .*/rss-helm-download\.[^/]+ linux-amd64/helm$' "$DOWNLOAD_TRACE" &&
   grep -Eq '^mv\|-f -- .*/\.helm\.tmp\.[^/]+ .*/\.download/bin/helm$' "$DOWNLOAD_TRACE" &&
   [ -z "$(find "$DOWNLOAD_TMP" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
  pass 'offline Helm download publishes only the expected executable'
else
  fail 'offline Helm download publishes only the expected executable'
fi

for mode in checksum-mismatch extract-fail publish-fail; do
  rm -rf "$DOWNLOAD_ROOT/.download"
  : >"$DOWNLOAD_TRACE"
  expect_failure "offline Helm download fails closed: $mode" \
    env PATH="$DOWNLOAD_FAKE_BIN:$PATH" TMPDIR="$DOWNLOAD_TMP" RSS_DOWNLOAD_MODE="$mode" \
    "$ADAPTER" install-download --lane ci-meta --root "$DOWNLOAD_ROOT"
  assert_download_clean "failed Helm download leaves zero pollution: $mode" \
    "$DOWNLOAD_ROOT" "$DOWNLOAD_TMP"
done

mkdir -p "$DOWNLOAD_ROOT/.download/bin"
expect_failure 'publication failure preserves pre-existing safe directories' \
  env PATH="$DOWNLOAD_FAKE_BIN:$PATH" TMPDIR="$DOWNLOAD_TMP" RSS_DOWNLOAD_MODE=publish-fail \
  "$ADAPTER" install-download --lane ci-meta --root "$DOWNLOAD_ROOT"
if [ -d "$DOWNLOAD_ROOT/.download/bin" ] &&
   [ -z "$(find "$DOWNLOAD_ROOT/.download/bin" -mindepth 1 -print -quit)" ] &&
   [ -z "$(find "$DOWNLOAD_TMP" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
  pass 'publication failure does not remove or pollute pre-existing directories'
else
  fail 'publication failure does not remove or pollute pre-existing directories'
fi
rm -rf "$DOWNLOAD_ROOT/.download"

UNSAFE_DOWNLOAD_TARGET="$TMP_ROOT/unsafe-download-target"
mkdir -p "$UNSAFE_DOWNLOAD_TARGET"
ln -s "$UNSAFE_DOWNLOAD_TARGET" "$DOWNLOAD_ROOT/.download"
expect_failure_stderr_contains 'symlinked download root fails closed' \
  'download tool directory is unsafe' \
  env PATH="$DOWNLOAD_FAKE_BIN:$PATH" TMPDIR="$DOWNLOAD_TMP" RSS_DOWNLOAD_MODE=success \
  "$ADAPTER" install-download --lane ci-meta --root "$DOWNLOAD_ROOT"
if [ -z "$(find "$UNSAFE_DOWNLOAD_TARGET" -mindepth 1 -print -quit)" ] &&
   [ -z "$(find "$DOWNLOAD_TMP" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
  pass 'unsafe download root leaves its target and staging clean'
else
  fail 'unsafe download root leaves its target and staging clean'
fi
rm -f "$DOWNLOAD_ROOT/.download"
mkdir -p "$DOWNLOAD_ROOT/.download/bin/helm"
expect_failure_stderr_contains 'directory at Helm destination fails closed' \
  'download binary destination is unsafe' \
  env PATH="$DOWNLOAD_FAKE_BIN:$PATH" TMPDIR="$DOWNLOAD_TMP" RSS_DOWNLOAD_MODE=success \
  "$ADAPTER" install-download --lane ci-meta --root "$DOWNLOAD_ROOT"
if [ -z "$(find "$DOWNLOAD_ROOT/.download/bin/helm" -mindepth 1 -print -quit)" ] &&
   [ -z "$(find "$DOWNLOAD_TMP" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
  pass 'unsafe Helm destination receives no published file'
else
  fail 'unsafe Helm destination receives no published file'
fi

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
  "$LEGAL" verify --mode fresh --lane ci-local-only --root "$ROOT"
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
rm -rf "$ROOT"; make_ci_meta_tools
expect_success 'ci-meta creates a compiler-cache and OCI policy seal' \
  "$ADAPTER" verify --mode fresh --lane ci-meta --root "$ROOT"
if grep -Fq 'prom/prometheus@sha256:ddc2493835a1509976d5e4e0c94199c4f843ce1f42dd6bcfc8231ba734a93ff7' "$ROOT/.rss-tool-seal-v1"; then
  pass 'seal records the exact promtool image digest'
else fail 'seal records the exact promtool image digest'; fi
if grep -Fq $'tool\tdownload\thelm@4.2.0\t.download/bin/helm\t' "$ROOT/.rss-tool-seal-v1"; then
  pass 'seal records the exact Helm binary identity'
else fail 'seal records the exact Helm binary identity'; fi
NO_DOCKER_BIN="$TMP_ROOT/no-docker-bin"
mkdir -p "$NO_DOCKER_BIN"
for command_name in bash cat cmp comm dirname find mktemp rm sort tr wc; do
  ln -s "$(command -v "$command_name")" "$NO_DOCKER_BIN/$command_name"
done
expect_failure_stderr_equals 'missing docker fails for the intended promtool reason' \
  'ci-tool-adapters: required docker runner unavailable: promtool@3.5.3' \
  /usr/bin/env -i PATH="$NO_DOCKER_BIN" TMPDIR="$TMP_ROOT" RSS_TEST_TRACE="$TRACE" \
    /bin/bash "$ADAPTER" verify --mode fresh --lane ci-meta --root "$ROOT"
if [ ! -e "$ROOT/.rss-tool-seal-v1" ]; then
  pass 'missing Docker leaves no tool seal'
else
  fail 'missing Docker leaves no tool seal'
fi
BAD_DOCKER_BIN="$TMP_ROOT/bad-docker-bin"
mkdir -p "$BAD_DOCKER_BIN"
make_binary "$BAD_DOCKER_BIN/docker" \
  "printf '%s\n' 'promtool, version 3.5.2 (branch: HEAD, revision: fixture)'"
expect_failure 'promtool version mismatch fails the fresh probe closed' \
  env PATH="$BAD_DOCKER_BIN:/usr/bin:/bin" "$ADAPTER" verify --mode fresh --lane ci-meta --root "$ROOT"
make_binary "$ROOT/.download/bin/helm" \
  "[ \"\$*\" = 'version --template {{.Version}}' ]; printf '%s\\n' 'v4.1.0'"
expect_failure 'Helm version mismatch fails the dedicated fresh probe closed' \
  "$ADAPTER" verify --mode fresh --lane ci-meta --root "$ROOT"
make_binary "$ROOT/.download/bin/helm" \
  "[ \"\$*\" = 'version --template {{.Version}}' ]; printf '%s\\n' 'v4.2.0'"
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
rm -rf "$ROOT"; make_ci_meta_tools
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
  rm -rf "$ROOT"; make_ci_meta_tools
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
