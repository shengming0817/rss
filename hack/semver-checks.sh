#!/usr/bin/env bash
# Run Release Surface semver checks, allowing only exact pre-publication breaking authorizations.
set -euo pipefail

base_ref="${1:?base ref required}"
head_ref="${2:?head ref required}"
base="$(/usr/bin/git rev-parse --verify "${base_ref}^{commit}")"
head="$(/usr/bin/git rev-parse --verify "${head_ref}^{commit}")"
if [[ "${base}" == "${head}" ]]; then
	base="$(/usr/bin/git rev-parse --verify "${head}^")"
fi

baseline_packages="$(/usr/bin/git show "${base}:Cargo.toml" | python3 -c 'import sys,tomllib; entries=tomllib.loads(sys.stdin.read())["workspace"]["metadata"]["release-surface"]["packages"]; print("\n".join(sorted(entry["package"] for entry in entries)))')"
current_metadata="$(cargo metadata --locked --no-deps --format-version 1)"
library_packages="$(printf '%s\n' "${current_metadata}" | python3 -c 'import json,sys; print("\n".join(sorted(package["name"] for package in json.load(sys.stdin)["packages"] if any("lib" in target["kind"] for target in package["targets"]))))')"

printf '%s\n' "${current_metadata}" | python3 -c '
import json,re,sys
metadata=json.load(sys.stdin)["metadata"]
entries=metadata["release-surface"]["packages"]
packages={entry["package"] for entry in entries}
authorizations=metadata.get("semver-breaking-authorizations", [])
seen=set()
for authorization in authorizations:
    assert set(authorization) == {"package", "baseline-rev", "issue"}
    package=authorization["package"]
    baseline=authorization["baseline-rev"]
    issue=authorization["issue"]
    assert package in packages and package not in seen
    assert re.fullmatch(r"[0-9a-f]{40}", baseline)
    assert type(issue) is int and issue > 0
    seen.add(package)
for entry in sorted(entries, key=lambda item: item["package"]):
    package=entry["package"]
    authorization=next((item for item in authorizations if item["package"] == package), None)
    mode=""
    if authorization is not None and authorization["baseline-rev"] == sys.argv[1]:
        issue=authorization["issue"]
        mode=f"major:{issue}"
    print(f"{package}|{mode}")
' "${base}" | while IFS='|' read -r package mode; do
	if ! grep -Fqx "${package}" <<<"${library_packages}"; then
		echo "semver-checks: skipping non-library target for ${package}"
	elif ! grep -Fqx "${package}" <<<"${baseline_packages}"; then
		echo "semver-checks: skipping first Release Surface version for ${package}"
	else
		if [[ "${mode}" == major:* ]]; then
			echo "semver-checks: exact pre-publication breaking authorization for ${package} (${mode#major:})"
			cargo semver-checks check-release --package "${package}" --baseline-rev "${base}" --release-type major
			cargo semver-checks check-release --package "${package}" --all-features --baseline-rev "${base}" --release-type major
		else
			cargo semver-checks check-release --package "${package}" --baseline-rev "${base}"
			cargo semver-checks check-release --package "${package}" --all-features --baseline-rev "${base}"
		fi
	fi
done
