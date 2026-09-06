# Make owns checks; ci-run owns one whole-command target lease.
.PHONY: ci ci-full audit _ci _ci-checks _ci-tests
CI_MAKE := $(MAKE)
CI_BASE ?= origin/develop
CI_HEAD ?= HEAD
CI_PART ?= all
CI_FULL ?= 0
CI_PACKAGES ?= --workspace

ci:
	@python3 hack/ci-run.py -- $(CI_MAKE) -j1 --no-print-directory _ci

ci-full:
	@python3 hack/ci-run.py -- $(CI_MAKE) -j1 --no-print-directory _ci CI_FULL=1

_ci:
	@case "$(CI_PART)" in all|checks|tests) ;; *) echo 'CI_PART must be all, checks or tests' >&2; exit 2;; esac
	+@status=0; \
	if [ "$(CI_PART)" != tests ]; then python3 -m unittest discover -s hack/tests -p 'test_ci_*.py' || status=$$?; fi; \
	if [ "$(CI_FULL)" = 1 ]; then selection=full; else \
	decision="$$(python3 hack/ci-impact.py --base "$(CI_BASE)" --head "$(CI_HEAD)" 2>/dev/null)" || decision=invalid; \
	selection="$$(printf '%s' "$$decision" | python3 -c 'import json,re,sys; d=json.load(sys.stdin); assert list(d)==["full","packages","reasons"] and type(d["full"]) is bool and type(d["packages"]) is list and type(d["reasons"]) is list and all(type(v) is str and v for k in ("packages","reasons") for v in d[k]) and d["packages"]==sorted(set(d["packages"])) and d["reasons"]==sorted(set(d["reasons"])) and (not d["full"] or (not d["packages"] and d["reasons"])) and all(re.fullmatch(r"[A-Za-z0-9_-]+", p) for p in d["packages"]); print("full" if d["full"] else " ".join("-p "+p for p in d["packages"]))' 2>/dev/null || printf '%s' full)"; \
	fi; \
	if [ "$$selection" = full ]; then packages=--workspace; full=1; \
	elif [ -z "$$selection" ]; then echo 'ci-impact selected no Cargo packages'; exit $$status; \
	else packages="$$selection"; full=0; fi; \
	echo "ci-impact packages: $$packages full=$$full part=$(CI_PART)"; \
	for part in checks tests; do \
		if [ "$(CI_PART)" = all ] || [ "$(CI_PART)" = "$$part" ]; then \
			$(MAKE) --no-print-directory _ci-$$part CI_PACKAGES="$$packages" CI_FULL="$$full" || status=$$?; \
		fi; \
	done; exit $$status

_ci-checks:
	cargo check --locked $(CI_PACKAGES)
	cargo check --locked --no-default-features $(CI_PACKAGES)
	cargo check --locked --all-features $(CI_PACKAGES)
	cargo clippy --locked --all-targets --all-features $(CI_PACKAGES) -- -D warnings
ifeq ($(CI_FULL),1)
	@base="$$(/usr/bin/git rev-parse --verify "$(CI_BASE)^{commit}")"; head="$$(/usr/bin/git rev-parse --verify "$(CI_HEAD)^{commit}")"; if [ "$$base" = "$$head" ]; then /usr/bin/git rev-parse --verify "$$head^" >/dev/null; fi
	cargo deny check -D unused-wrapper
	@bash hack/semver-checks.sh "$(CI_BASE)" "$(CI_HEAD)"
endif

_ci-tests:
ifeq ($(CI_FULL),1)
	cargo llvm-cov nextest --locked $(CI_PACKAGES) --all-features --no-report
else
	cargo nextest run --locked --all-features $(CI_PACKAGES)
endif
	cargo test --doc --locked --all-features $(CI_PACKAGES)
ifeq ($(CI_FULL),1)
	cargo llvm-cov report --fail-under-lines 80 --lcov --output-path lcov.info
endif

audit:
	cargo deny check advisories
	cargo audit --ignore RUSTSEC-2023-0071
