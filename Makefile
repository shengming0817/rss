# Make owns checks; ci-run owns one whole-command target lease.
.PHONY: ci ci-full audit _ci _ci-checks
CI_MAKE := $(MAKE)
CI_BASE ?= origin/develop
CI_HEAD ?= HEAD
CI_PART ?= all
CI_FULL ?= 0
CI_PACKAGES ?= --workspace
CI_FILTER ?= all()
CI_PLAN ?=
CI_ARTIFACTS ?= $(CURDIR)/.local-ci-runs/current

ci:
	@python3 hack/ci-run.py -- $(CI_MAKE) -j1 --no-print-directory _ci

ci-full:
	@python3 hack/ci-run.py -- $(CI_MAKE) -j1 --no-print-directory _ci CI_FULL=1

export CI_BASE CI_HEAD CI_PART CI_FULL CI_FILTER CI_PLAN CI_ARTIFACTS
_ci:
	@python3 hack/ci-pipeline.py

# Keep each group in one shell so every executable check contributes to its verdict.
_ci-checks:
	@status=0; \
	cargo check --locked $(CI_PACKAGES) || status=$$?; \
	cargo check --locked --no-default-features $(CI_PACKAGES) || status=$$?; \
	cargo check --locked --all-features $(CI_PACKAGES) || status=$$?; \
	cargo clippy --locked --all-targets --all-features $(CI_PACKAGES) -- -D warnings || status=$$?; \
	if [ "$(CI_FULL)" = 1 ]; then \
	cargo deny check -D unused-wrapper || status=$$?; \
	bash hack/semver-checks.sh "$(CI_BASE)" "$(CI_HEAD)" || status=$$?; \
	fi; \
	exit $$status


audit:
	cargo deny check advisories
	cargo audit --ignore RUSTSEC-2023-0071
