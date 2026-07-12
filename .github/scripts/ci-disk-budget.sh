#!/usr/bin/env bash
set -eu

usage() {
  printf 'usage: %s --stage <name> [--path <path>]\n' "$0" >&2
  exit 2
}

annotation() {
  printf '::error title=ci-disk-budget::%s\n' "$1" >&2
}

stage=
path=${GITHUB_WORKSPACE:-$(pwd)}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --stage)
      [ "$#" -ge 2 ] || usage
      stage=$2
      shift 2
      ;;
    --path)
      [ "$#" -ge 2 ] || usage
      path=$2
      shift 2
      ;;
    *) usage ;;
  esac
done

[ -n "$stage" ] || usage
case "$stage" in *[!A-Za-z0-9_.-]*|'') usage ;; esac

if [ ! -d "$path" ]; then
  annotation "stage=$stage path=workspace reason=path-unavailable"
  exit 1
fi
config_path=$path/.config/ci-slo.toml
if [ -L "$path/.config" ] || [ -L "$config_path" ] || [ ! -f "$config_path" ]; then
  annotation "stage=$stage path=workspace reason=config-unavailable"
  exit 1
fi
if ! command -v awk >/dev/null 2>&1; then
  annotation "stage=$stage path=workspace reason=awk-unavailable"
  exit 1
fi
min_free_gib=$(awk '
  BEGIN { count = 0; valid = 0 }
  /^[[:space:]]*min_disk_free_gib[[:space:]]*=/ {
    count++
    if ($0 ~ /^[[:space:]]*min_disk_free_gib[[:space:]]*=[[:space:]]*[0-9]+[[:space:]]*$/) {
      value = $0
      sub(/^[^=]*=[[:space:]]*/, "", value)
      sub(/[[:space:]]*$/, "", value)
      valid = 1
    }
  }
  END { if (count == 1 && valid == 1) print value; else exit 1 }
' "$config_path") || {
  annotation "stage=$stage path=workspace reason=config-invalid"
  exit 1
}
case "$min_free_gib" in ''|*[!0-9]*)
  annotation "stage=$stage path=workspace reason=config-invalid"
  exit 1
  ;;
esac
while [ "${min_free_gib#0}" != "$min_free_gib" ]; do
  min_free_gib=${min_free_gib#0}
done
[ -n "$min_free_gib" ] || min_free_gib=0
if ! [ "$min_free_gib" -gt 0 ] 2>/dev/null || ! [ "$min_free_gib" -le 8589934591 ] 2>/dev/null; then
  annotation "stage=$stage path=workspace reason=config-invalid"
  exit 1
fi
if ! command -v df >/dev/null 2>&1; then
  annotation "stage=$stage path=workspace reason=df-unavailable requiredGiB=$min_free_gib"
  exit 1
fi

df_output=$(df -Pk "$path" 2>/dev/null) || {
  annotation "stage=$stage path=workspace reason=df-failed requiredGiB=$min_free_gib"
  exit 1
}
df_line=${df_output##*
}
available_kib=
read -r _ _ _ available_kib _ <<EOF || true
$df_line
EOF
case "$available_kib" in ''|*[!0-9]*)
  annotation "stage=$stage path=workspace reason=df-invalid requiredGiB=$min_free_gib"
  exit 1
  ;;
esac

available_bytes=$((available_kib * 1024))
required_bytes=$((min_free_gib * 1073741824))
available_gib=$((available_bytes / 1073741824))
if [ "$available_bytes" -ge "$required_bytes" ]; then
  printf 'ci-disk-budget: stage=%s path=workspace availableGiB=%s requiredGiB=%s status=ok\n' "$stage" "$available_gib" "$min_free_gib"
  exit 0
fi

annotation "stage=$stage path=workspace actualGiB=$available_gib requiredGiB=$min_free_gib reason=below-low-watermark"
if command -v find >/dev/null 2>&1 && command -v du >/dev/null 2>&1; then
  printf 'ci-disk-budget: largest workspace directories (KiB, depth<=1, top<=10):\n' >&2
  diagnostic=
  while IFS= read -r -d '' candidate; do
    relative=${candidate#"$path"/}
    case "$relative" in .git|.git/*) continue ;; esac
    measured=$(du -sk "$candidate" 2>/dev/null) || measured=
    size_kib=${measured%%[!0-9]*}
    [ -n "$size_kib" ] || continue
    safe_relative=$(printf '%s' "$relative" | tr '\n\r\t' '???')
    diagnostic=${diagnostic}${size_kib}' workspace/'${safe_relative}'
'
  done < <(find -P "$path" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)
  if [ -n "$diagnostic" ] && command -v sort >/dev/null 2>&1 && command -v head >/dev/null 2>&1; then
    printf '%s' "$diagnostic" | sort -rn | head -n 10 >&2
  fi
fi
exit 1
