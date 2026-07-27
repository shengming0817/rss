#!/usr/bin/env bash
set -eu
set -f
set -o pipefail

SEAL_NAME=.rss-tool-seal-v1
HELM_LINUX_AMD64_SHA256=97dbeb971be4ac4b27e3839976d9564c0fb35c6f3b1da89dd1e292d236af4096
KUBECONFORM_LINUX_AMD64_SHA256=c31518ddd122663b3f3aa874cfe8178cb0988de944f29c74a0b9260920d115d3
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
CATALOG=$SCRIPT_DIR/ci-tool-catalog.txt

usage() {
  printf '%s\n' \
    "usage: $0 specs --lane <lane|all> --backend <install-action|binstall|download|docker|all>" \
    "       $0 install-download --lane <lane> --root <absolute-profile-tool-root>" \
    "       $0 sccache-spec" \
    "       $0 verify-sccache --candidate <absolute-sccache-path>" \
    "       $0 verify --mode <fresh|cache> --lane <lane> --root <absolute-profile-tool-root>" >&2
  exit 2
}

die() {
  printf 'ci-tool-adapters: %s\n' "$1" >&2
  exit 1
}

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    hash_output=$(sha256sum "$1") || die 'SHA-256 command failed'
  elif command -v shasum >/dev/null 2>&1; then
    hash_output=$(shasum -a 256 "$1") || die 'SHA-256 command failed'
  else
    die 'required SHA-256 command unavailable'
  fi
  digest=${hash_output%%[[:space:]]*}
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || die 'SHA-256 command returned an invalid digest'
  printf '%s\n' "$digest"
}

valid_semver() {
  version=$1
  [[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?(\+([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?$ ]] || return 1
  prerelease=${version#*-}
  if [ "$prerelease" != "$version" ]; then
    prerelease=${prerelease%%+*}
    old_ifs=$IFS
    IFS=.
    for identifier in $prerelease; do
      IFS=$old_ifs
      case "$identifier" in
        *[!0-9]*) ;;
        0|[1-9]|[1-9][0-9]*) ;;
        *) return 1 ;;
      esac
      IFS=.
    done
    IFS=$old_ifs
  fi
}

catalog() {
  cat -- "$CATALOG" || die 'cannot read tool catalog'
}

valid_lane() {
  case "$1" in
    all|ci-meta|ci-core-prerequisites|ci-core-tests|ci-local-only|ci-security|ci-coverage|integration|audit) return 0 ;;
    *) return 1 ;;
  esac
}

lane_has_tool() {
  lane=$1 name=$2
  case "$lane:$name" in
    all:* | \
    *:sccache | \
    ci-meta:promtool | ci-meta:helm | ci-meta:kubeconform | \
    ci-core-prerequisites:cargo-dylint | ci-core-prerequisites:dylint-link | \
    ci-core-tests:cargo-nextest | ci-local-only:cargo-nextest | \
    ci-security:cargo-deny | ci-security:cargo-audit | \
    ci-coverage:cargo-nextest | ci-coverage:cargo-llvm-cov | ci-coverage:cargo-public-api | \
    integration:cargo-nextest | \
    audit:cargo-deny | audit:cargo-audit) return 0 ;;
    *) return 1 ;;
  esac
}

validate_catalog() {
  [ -f "$CATALOG" ] && [ ! -L "$CATALOG" ] || die 'tool catalog is unsafe or unavailable'
  seen='|'
  while IFS='|' read -r name version backend relative probe extra; do
    [ -n "$name" ] && [ -z "$extra" ] || die 'invalid catalog row'
    [[ "$name" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]] || die 'invalid catalog tool name'
    valid_semver "$version" || die 'invalid catalog SemVer'
    case "$backend" in install-action|binstall|download|docker) ;; *) die 'invalid catalog backend' ;; esac
    case "$backend:$relative" in
      "install-action:.install-action/bin/$name"|"binstall:bin/$name"|"download:.download/bin/$name") ;;
      docker:prom/prometheus@sha256:*)
        digest=${relative#prom/prometheus@sha256:}
        [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || die 'invalid digest-pinned docker image'
        ;;
      *) die 'catalog backend and binary path disagree' ;;
    esac
    if [ "$backend" != docker ]; then
      case "$relative" in *//*|*/./*|*/../*|*/..|/*) die 'invalid catalog binary path' ;; esac
    fi
    case "$backend:$probe" in
      install-action:nextest|install-action:llvm-cov|install-action:direct|install-action:sccache|binstall:dylint|binstall:direct|binstall:receipt|download:helm|download:kubeconform|docker:promtool) ;;
      *) die 'invalid catalog probe/backend combination' ;;
    esac
    case "$seen" in *"|$name|"*) die 'duplicate catalog tool' ;; esac
    seen="$seen$name|"
  done <<EOF
$(catalog)
EOF
}

selected_rows() {
  lane=$1 backend_filter=$2
  while IFS='|' read -r name version backend relative probe; do
    lane_has_tool "$lane" "$name" || continue
    [ "$backend_filter" = all ] || [ "$backend_filter" = "$backend" ] || continue
    printf '%s|%s|%s|%s|%s\n' "$name" "$version" "$backend" "$relative" "$probe"
  done <<EOF
$(catalog)
EOF
}

sccache_row() {
  row=''
  while IFS='|' read -r name version backend relative probe; do
    [ "$name" = sccache ] || continue
    [ "$probe" = sccache ] || die 'sccache catalog row must use the sccache probe'
    row="$name|$version|$backend|$relative|$probe"
  done <<EOF
$(catalog)
EOF
  [ -n "$row" ] || die 'sccache is missing from the tool catalog'
  printf '%s\n' "$row"
}

emit_sccache_spec() {
  [ "$#" -eq 0 ] || usage
  sccache_row
}

emit_specs() {
  lane='' backend=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --lane) [ "$#" -ge 2 ] || usage; lane=$2; shift 2 ;;
      --backend) [ "$#" -ge 2 ] || usage; backend=$2; shift 2 ;;
      *) usage ;;
    esac
  done
  valid_lane "$lane" || die 'unknown lane'
  case "$backend" in install-action|binstall|download|docker|all) ;; *) die 'unknown backend' ;; esac
  output=
  while IFS='|' read -r name version _backend _relative _probe; do
    [ -n "$name" ] || continue
    if [ -n "$output" ]; then output="$output,"; fi
    output="$output$name@$version"
  done <<EOF
$(selected_rows "$lane" "$backend")
EOF
  printf '%s\n' "$output"
}

validate_root() {
  root=$1
  case "$root" in /*) ;; *) return 1 ;; esac
  case "$root" in *//*|*/./*|*/.|*/../*|*/..) return 1 ;; esac
  [ -d "$root" ] && [ ! -L "$root" ] || return 1
  physical=$(CDPATH='' cd -- "$root" 2>/dev/null && pwd -P) || return 1
  [ "$physical" = "$root" ] || return 1
}

validate_binary() {
  root=$1 relative=$2
  current=$root
  remainder=$relative
  while [ -n "$remainder" ]; do
    component=${remainder%%/*}
    if [ "$component" = "$remainder" ]; then remainder=; else remainder=${remainder#*/}; fi
    current=$current/$component
    [ ! -L "$current" ] || return 1
  done
  [ -f "$current" ] && [ -x "$current" ]
}

verify_exact_layout() {
  root=$1 lane=$2
  expected=$(mktemp "${TMPDIR:-/tmp}/rss-tool-expected.XXXXXX") || die 'cannot create layout list'
  actual=$(mktemp "${TMPDIR:-/tmp}/rss-tool-actual.XXXXXX") || { rm -f "$expected"; die 'cannot create layout list'; }
  while IFS='|' read -r name version backend relative probe; do
    [ -n "$name" ] || continue
    [ "$backend" != docker ] || continue
    validate_binary "$root" "$relative" || {
      rm -f "$expected" "$actual"
      die "tool binary is unsafe or unavailable: $name@$version ($relative)"
    }
    printf '%s\n' "$relative" >>"$expected"
  done <<EOF
$(selected_rows "$lane" all)
EOF
  for directory in "$root/.install-action/bin" "$root/bin" "$root/.download/bin"; do
    [ ! -L "$directory" ] || {
      rm -f "$expected" "$actual"
      die "tool binary directory is unsafe: ${directory#"$root"/}"
    }
    if [ -d "$directory" ]; then
      find -P "$directory" -mindepth 1 -maxdepth 1 -print | while IFS= read -r path; do
        printf '%s\n' "${path#"$root"/}"
      done >>"$actual"
    fi
  done
  LC_ALL=C sort -o "$expected" "$expected"
  LC_ALL=C sort -o "$actual" "$actual"
  if ! cmp -s "$expected" "$actual"; then
    missing=$(comm -23 "$expected" "$actual" | wc -l | tr -d ' ')
    extra=$(comm -13 "$expected" "$actual" | wc -l | tr -d ' ')
    rm -f "$expected" "$actual"
    die "tool binary layout mismatch: missing=$missing extra=$extra"
  fi
  rm -f "$expected" "$actual"
}

capture_probe() {
  binary=$1 spec=$2
  shift 2
  output_file=$(mktemp "${TMPDIR:-/tmp}/rss-tool-probe.XXXXXX") || die 'cannot create probe output'
  if ! "$binary" "$@" >"$output_file" 2>/dev/null; then
    rm -f "$output_file"
    die "tool probe failed: $spec"
  fi
  output=$(cat "$output_file") || { rm -f "$output_file"; die 'cannot read probe output'; }
  rm -f "$output_file"
  printf '%s\n' "$output"
}

verify_sccache_version() {
  binary=$1 name=$2 version=$3
  output=$(capture_probe "$binary" "$name@$version" --version)
  [ "$output" = "sccache $version" ] || die "tool version mismatch: $name@$version"
}

verify_sccache_candidate() {
  candidate=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --candidate) [ "$#" -ge 2 ] || usage; candidate=$2; shift 2 ;;
      *) usage ;;
    esac
  done
  case "$candidate" in /*) ;; *) die 'sccache candidate must be an absolute path' ;; esac
  case "$candidate" in *//*|*/./*|*/.|*/../*|*/..) die 'sccache candidate is not normalized' ;; esac
  [ -e "$candidate" ] || [ -L "$candidate" ] || die 'sccache candidate is unavailable'
  [ ! -L "$candidate" ] || die 'sccache candidate must not be a symlink'
  [ -f "$candidate" ] || die 'sccache candidate is not a regular file'
  [ -x "$candidate" ] || die 'sccache candidate is not executable'

  directory=${candidate%/*}
  [ -n "$directory" ] || directory=/
  basename=${candidate##*/}
  physical_directory=$(CDPATH='' cd -- "$directory" 2>/dev/null && pwd -P) ||
    die 'sccache candidate directory cannot be resolved'
  if [ "$physical_directory" = / ]; then
    canonical=/$basename
  else
    canonical=$physical_directory/$basename
  fi
  [ "$candidate" = "$canonical" ] || die 'sccache candidate is not canonical'

  row=$(sccache_row)
  IFS='|' read -r name version backend relative probe <<EOF
$row
EOF
  verify_sccache_version "$canonical" "$name" "$version"
  printf '%s\n' "$canonical"
}

verify_nextest_output() {
  version=$1 output=$2
  [ "$(printf '%s\n' "$output" | wc -l | tr -d ' ')" -eq 5 ] || return 1
  first=$(printf '%s\n' "$output" | sed -n '1p')
  release=$(printf '%s\n' "$output" | sed -n '2p')
  commit=$(printf '%s\n' "$output" | sed -n '3p')
  commit_date=$(printf '%s\n' "$output" | sed -n '4p')
  host=$(printf '%s\n' "$output" | sed -n '5p')
  prefix="cargo-nextest $version ("
  case "$first" in "$prefix"*) metadata=${first#"$prefix"} ;; *) return 1 ;; esac
  [[ "$metadata" =~ ^([0-9a-f]{9,40})\ ([0-9]{4}-[0-9]{2}-[0-9]{2})\)$ ]] || return 1
  short_commit=${BASH_REMATCH[1]}
  first_date=${BASH_REMATCH[2]}
  [ "$release" = "release: $version" ] || return 1
  [[ "$commit" =~ ^commit-hash:\ ([0-9a-f]{40})$ ]] || return 1
  full_commit=${BASH_REMATCH[1]}
  case "$full_commit" in "$short_commit"*) ;; *) return 1 ;; esac
  [ "$commit_date" = "commit-date: $first_date" ] || return 1
  [[ "$host" =~ ^host:\ [A-Za-z0-9_.-]+$ ]]
}

verify_direct_output() {
  name=$1 version=$2 output=$3
  [ "$output" = "$name $version" ] || [ "$output" = "$name v$version" ]
}

verify_receipt() {
  root=$1 name=$2 version=$3
  receipt=$root/.crates.toml
  [ -f "$receipt" ] && [ ! -L "$receipt" ] || return 1
  expected="\"$name $version (registry+https://github.com/rust-lang/crates.io-index)\" = [\"$name\"]"
  [ "$(grep -Ec "^\"$name [^\"]+\" = \\[\"$name\"\\]$" "$receipt" || true)" -eq 1 ] &&
    [ "$(grep -Fxc "$expected" "$receipt" || true)" -eq 1 ]
}

fresh_probe() {
  root=$1 name=$2 version=$3 relative=$4 probe=$5
  binary=$root/$relative
  spec=$name@$version
  case "$probe" in
    promtool)
      command -v docker >/dev/null 2>&1 || die "required docker runner unavailable: $spec"
      output=$(capture_probe docker "$spec" run --rm --network=none --entrypoint=/bin/promtool "$relative" --version)
      printf '%s\n' "$output" | grep -Eq "^promtool, version $version([[:space:]]|$)" || die "tool version mismatch: $spec"
      ;;
    nextest)
      output=$(capture_probe "$binary" "$spec" --version)
      verify_nextest_output "$version" "$output" || die "tool version mismatch: $spec"
      ;;
    llvm-cov)
      output=$(capture_probe "$binary" "$spec" llvm-cov --version)
      verify_direct_output "$name" "$version" "$output" || die "tool version mismatch: $spec"
      ;;
    dylint)
      output=$(capture_probe "$binary" "$spec" dylint --version)
      verify_direct_output "$name" "$version" "$output" || die "tool version mismatch: $spec"
      ;;
    direct)
      output=$(capture_probe "$binary" "$spec" --version)
      verify_direct_output "$name" "$version" "$output" || die "tool version mismatch: $spec"
      ;;
    helm)
      output=$(capture_probe "$binary" "$spec" version --template '{{.Version}}')
      [ "$output" = "v$version" ] || die "tool version mismatch: $spec"
      ;;
    kubeconform)
      output=$(capture_probe "$binary" "$spec" -v)
      [ "$output" = "v$version" ] || die "tool version mismatch: $spec"
      ;;
    sccache)
      verify_sccache_version "$binary" "$name" "$version"
      ;;
    receipt)
      verify_receipt "$root" "$name" "$version" || die "tool install receipt mismatch: $spec"
      ;;
  esac
}

install_download() {
  lane='' root=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --lane) [ "$#" -ge 2 ] || usage; lane=$2; shift 2 ;;
      --root) [ "$#" -ge 2 ] || usage; root=$2; shift 2 ;;
      *) usage ;;
    esac
  done
  valid_lane "$lane" && [ "$lane" != all ] || die 'unknown lane'
  validate_root "$root" || die 'tool root is not a normalized physical directory'
  rows=$(selected_rows "$lane" download)
  [ -n "$rows" ] || return 0
  [ "$(uname -s)" = Linux ] || die 'download backend only supports Linux'
  case "$(uname -m)" in x86_64|amd64) ;; *) die 'download backend only supports x86_64' ;; esac

  while IFS='|' read -r name version backend relative probe; do
    [ "$backend" = download ] || die 'unsupported download catalog row'
    case "$name:$probe" in
      helm:helm)
        archive_url="https://get.helm.sh/helm-v$version-linux-amd64.tar.gz"
        expected_digest=$HELM_LINUX_AMD64_SHA256
        archive_member=linux-amd64/helm
        extracted_relative=linux-amd64/helm
        ;;
      kubeconform:kubeconform)
        archive_url="https://github.com/yannh/kubeconform/releases/download/v$version/kubeconform-linux-amd64.tar.gz"
        expected_digest=$KUBECONFORM_LINUX_AMD64_SHA256
        archive_member=kubeconform
        extracted_relative=kubeconform
        ;;
      *) die 'unsupported download catalog row' ;;
    esac
    stage=$(mktemp -d "${TMPDIR:-/tmp}/rss-$name-download.XXXXXX") || die 'cannot create download staging directory'
    archive=$stage/$name.tar.gz
    curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
      --output "$archive" "$archive_url" || { rm -rf -- "$stage"; die "$name download failed"; }
    [ "$(hash_file "$archive")" = "$expected_digest" ] || {
      rm -rf -- "$stage"
      die "$name archive SHA-256 mismatch"
    }
    tar -xzf "$archive" -C "$stage" "$archive_member" || {
      rm -rf -- "$stage"
      die "$name archive extraction failed"
    }
    extracted=$stage/$extracted_relative
    [ -f "$extracted" ] && [ ! -L "$extracted" ] || {
      rm -rf -- "$stage"
      die "$name archive binary is unsafe"
    }
    destination=$root/$relative
    directory=${destination%/*}
    download_root=$root/.download
    download_root_existed=0
    directory_existed=0
    if [ -e "$download_root" ] || [ -L "$download_root" ]; then
      [ -d "$download_root" ] && [ ! -L "$download_root" ] || {
        rm -rf -- "$stage"
        die 'download tool directory is unsafe'
      }
      download_root_existed=1
    fi
    if [ -e "$directory" ] || [ -L "$directory" ]; then
      [ -d "$directory" ] && [ ! -L "$directory" ] || {
        rm -rf -- "$stage"
        die 'download binary directory is unsafe'
      }
      directory_existed=1
    fi
    mkdir -p -- "$directory" || { rm -rf -- "$stage"; die 'cannot create download tool directory'; }
    if [ -e "$destination" ] || [ -L "$destination" ]; then
      [ -f "$destination" ] && [ ! -L "$destination" ] || {
        rm -rf -- "$stage"
        die 'download binary destination is unsafe'
      }
    fi
    temporary=$(mktemp "$directory/.$name.tmp.XXXXXX") || {
      if [ "$directory_existed" -eq 0 ]; then rmdir -- "$directory" 2>/dev/null || true; fi
      if [ "$download_root_existed" -eq 0 ]; then rmdir -- "$download_root" 2>/dev/null || true; fi
      rm -rf -- "$stage"
      die "cannot stage $name binary"
    }
    if ! cp -- "$extracted" "$temporary" ||
       ! chmod 755 "$temporary" ||
       ! mv -f -- "$temporary" "$destination"; then
      rm -f -- "$temporary"
      if [ "$directory_existed" -eq 0 ]; then rmdir -- "$directory" 2>/dev/null || true; fi
      if [ "$download_root_existed" -eq 0 ]; then rmdir -- "$download_root" 2>/dev/null || true; fi
      rm -rf -- "$stage"
      die "cannot publish $name binary"
    fi
    rm -rf -- "$stage"
  done <<EOF
$rows
EOF
}

write_expected_seal() {
  destination=$1 root=$2 lane=$3
  adapter_hash=$(hash_file "$0") || return 1
  catalog_hash=$(hash_file "$CATALOG") || return 1
  requests=
  while IFS='|' read -r name version backend relative probe; do
    [ -n "$name" ] || continue
    if [ -n "$requests" ]; then requests="$requests,"; fi
    requests="$requests$backend:$name@$version"
  done <<EOF
$(selected_rows "$lane" all)
EOF
  {
    printf 'rss-tool-seal-v1\n'
    printf 'adapter-sha256\t%s\n' "$adapter_hash"
    printf 'catalog-sha256\t%s\n' "$catalog_hash"
    printf 'lane\t%s\n' "$lane"
    printf 'requests\t%s\n' "$requests"
    while IFS='|' read -r name version backend relative probe; do
      [ -n "$name" ] || continue
      if [ "$backend" = docker ]; then
        image_digest=${relative#*@sha256:}
        printf 'tool\t%s\t%s@%s\t%s\t%s\n' "$backend" "$name" "$version" "$relative" "$image_digest"
      else
        binary_hash=$(hash_file "$root/$relative") || return 1
        printf 'tool\t%s\t%s@%s\t%s\t%s\n' "$backend" "$name" "$version" "$relative" "$binary_hash"
      fi
    done <<EOF
$(selected_rows "$lane" all)
EOF
  } >"$destination"
}

die_seal_mismatch() {
  expected=$1 seal=$2 lane=$3
  mismatch_spec=''
  mismatch_relative=''
  while IFS="$(printf '\t')" read -r kind backend spec relative digest extra; do
    [ "$kind" = tool ] || continue
    if ! grep -Fqx -- "tool$(printf '\t')$backend$(printf '\t')$spec$(printf '\t')$relative$(printf '\t')$digest" "$seal"; then
      mismatch_spec=$spec
      mismatch_relative=$relative
      break
    fi
  done <"$expected"
  rm -f "$expected"
  if [ -n "$mismatch_spec" ]; then
    die "tool seal mismatch: $mismatch_spec ($mismatch_relative)"
  fi
  die "tool seal metadata mismatch: lane=$lane"
}

verify_set() {
  mode='' lane='' root=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --mode) [ "$#" -ge 2 ] || usage; mode=$2; shift 2 ;;
      --lane) [ "$#" -ge 2 ] || usage; lane=$2; shift 2 ;;
      --root) [ "$#" -ge 2 ] || usage; root=$2; shift 2 ;;
      *) usage ;;
    esac
  done
  case "$mode" in fresh|cache) ;; *) usage ;; esac
  valid_lane "$lane" && [ "$lane" != all ] || die 'unknown lane'
  validate_root "$root" || die 'tool root is not a normalized physical directory'
  seal=$root/$SEAL_NAME
  if [ "$mode" = fresh ]; then rm -f -- "$seal"; fi
  verify_exact_layout "$root" "$lane"

  if [ "$mode" = fresh ]; then
    while IFS='|' read -r name version backend relative probe; do
      [ -n "$name" ] || continue
      fresh_probe "$root" "$name" "$version" "$relative" "$probe"
    done <<EOF
$(selected_rows "$lane" all)
EOF
  fi

  temporary=$(mktemp "$root/.rss-tool-seal-v1.tmp.XXXXXX") || die 'cannot create tool seal'
  chmod 600 "$temporary" || { rm -f "$temporary"; die 'cannot secure tool seal'; }
  write_expected_seal "$temporary" "$root" "$lane" || {
    rm -f "$temporary"
    die 'cannot build tool seal'
  }
  if [ "$mode" = fresh ]; then
    mv -f -- "$temporary" "$seal" || { rm -f "$temporary"; die 'cannot publish tool seal'; }
  elif [ ! -f "$seal" ] || [ -L "$seal" ]; then
    rm -f "$temporary"
    die "tool seal is unsafe or unavailable: lane=$lane"
  elif ! cmp -s "$temporary" "$seal"; then
    die_seal_mismatch "$temporary" "$seal" "$lane"
  else
    rm -f "$temporary"
  fi
}

validate_catalog
[ "$#" -gt 0 ] || usage
command_name=$1
shift
case "$command_name" in
  specs) emit_specs "$@" ;;
  install-download) install_download "$@" ;;
  sccache-spec) emit_sccache_spec "$@" ;;
  verify-sccache) verify_sccache_candidate "$@" ;;
  verify) verify_set "$@" ;;
  *) usage ;;
esac
