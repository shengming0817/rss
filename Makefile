# Thin local and CI entry points. Scheduling is Cargo package based; time budgets belong to callers.

.PHONY: ci ci-full audit

CI_BASE ?= origin/develop
CI_HEAD ?= HEAD

ci:
	@set -eu; \
	decision="$$(python3 hack/ci-impact.py --base "$(CI_BASE)" --head "$(CI_HEAD)" 2>/dev/null)" || decision=invalid; \
	selection="$$(printf '%s' "$$decision" | python3 -c 'import json,re,sys; d=json.load(sys.stdin); assert list(d)==["full","packages","reasons"] and type(d["full"]) is bool and type(d["packages"]) is list and type(d["reasons"]) is list and all(type(v) is str and v for k in ("packages","reasons") for v in d[k]) and d["packages"]==sorted(set(d["packages"])) and d["reasons"]==sorted(set(d["reasons"])) and (not d["full"] or (not d["packages"] and d["reasons"])) and all(re.fullmatch(r"[A-Za-z0-9_-]+", p) for p in d["packages"]); print("full" if d["full"] else " ".join("-p "+p for p in d["packages"]))' 2>/dev/null || printf '%s' full)"; \
	if [ "$$selection" = full ]; then \
		echo "ci-impact selected the full workspace"; \
		$(MAKE) ci-full; \
	elif [ -z "$$selection" ]; then \
		echo "ci-impact selected no Cargo packages"; \
	else \
		echo "ci-impact packages: $$selection"; \
		cargo check --locked $$selection; \
		cargo check --locked --no-default-features $$selection; \
		cargo check --locked --all-features $$selection; \
		cargo nextest run --locked --all-features $$selection; \
		cargo clippy --locked --all-targets --all-features $$selection -- -D warnings; \
	fi

ci-full:
	@base="$$(/usr/bin/git rev-parse --verify "$(CI_BASE)^{commit}")"; head="$$(/usr/bin/git rev-parse --verify "$(CI_HEAD)^{commit}")"; if [ "$$base" = "$$head" ]; then /usr/bin/git rev-parse --verify "$$head^" >/dev/null; fi
	cargo check --locked --workspace
	cargo check --locked --workspace --no-default-features
	cargo check --locked --workspace --all-features
	cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
	cargo deny check -D unused-wrapper
	@base="$$(/usr/bin/git rev-parse --verify "$(CI_BASE)^{commit}")"; head="$$(/usr/bin/git rev-parse --verify "$(CI_HEAD)^{commit}")"; if [ "$$base" = "$$head" ]; then base="$$(/usr/bin/git rev-parse --verify "$$head^")"; fi; cargo metadata --locked --no-deps --format-version 1 | python3 -c 'import json,sys; entries=json.load(sys.stdin)["metadata"]["release-surface"]["packages"]; print("\n".join(sorted(entry["package"] for entry in entries)))' | while read -r package; do cargo semver-checks check-release --package "$$package" --baseline-rev "$$base"; cargo semver-checks check-release --package "$$package" --all-features --baseline-rev "$$base"; done
	cargo llvm-cov nextest --locked --workspace --all-features --no-report
	cargo llvm-cov report --fail-under-lines 80 --lcov --output-path lcov.info

audit:
	cargo deny check advisories
	cargo audit --ignore RUSTSEC-2023-0071
