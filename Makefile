# RSS 治理门的受控本地 bootstrap。
#
# typed gate plan 单源在 `cargo xtask`（跨平台、CI-ready、对齐 rust-analyzer xtask 范式）；Make
# 通过 `hack/cargo.sh` 统一 build-jobs、ambient wrapper 清洗和 compiler-cache policy。直接执行
# `cargo xtask` 使用同一 gate plan 与 target-dir 默认值，但不具备等价的外层 Cargo bootstrap。
#
#   make verify       本地 stable-only 快门：fmt + meta + build + clippy + nextest + deny + dylint。
#   make verify-fast  inner typed plan 的 NoCompile 子集（仅 fmt + meta + deny）；冷缓存或 xtask
#                     变更时，外层 Cargo 仍会构建 xtask 启动器。
#   make ci           本地去重兼容聚合（非 GitHub job）：Coverage 取代 Core 的 default-profile
#                     nextest；因此不与真实 checks 的执行语义完全等价。复现各 checks
#                     须分别经 `hack/cargo.sh xtask` 运行 ci-meta / ci-core-prerequisites /
#                     ci-core-tests --partition 1/2（及 2/2）/ ci-security / ci-coverage。
#                     需全套工具 + nightly。
#   make cargo-selftest 本地 Cargo 入口的 target 隔离与 override 机器验收。
#   make audit        供应链漏洞刷新 lane（与 GitHub Actions schedule 使用同一 typed audit plan，
#                     #1133）：inner plan 只有 advisory-scoped `deny check advisories` + cargo-audit，
#                     不包含 workspace 编译 gate；外层 Cargo 启动器边界同上。
#   make docker-build server 多阶段镜像构建（#1134）：cargo-chef + distroless/cc:nonroot → rss-server:dev。
#   make docker-smoke 容器冒烟验收（#1134，**docker-gated**）：build → compose up → /readyz 200 → 非 root /
#                     只读 rootfs 断言 → down -v。逻辑在 deploy/smoke.sh（机器可判定 acceptance harness）。
#
# CI lane = GitHub Actions workflows（issue #1132）：当前处于 Shadow 取证阶段；Azure 仍是 active forge，
# `ci-gate` 尚非 required check。现状见 docs/ops/202607130824-1765-diff-adaptive-ci.md；门集 / --fast /
# 缺工具策略见 xtask/src/verify.rs。

.PHONY: verify verify-fast verify-hooks ci cargo-selftest audit docker-build docker-smoke

RSS_CARGO ?= ./hack/cargo.sh

verify:
	$(RSS_CARGO) xtask verify

verify-fast: verify-hooks
	$(RSS_CARGO) xtask verify --fast

verify-hooks:
	/usr/bin/python3 -m unittest discover -s .codex/hooks -p 'test_*.py'

ci:
	$(RSS_CARGO) xtask ci

cargo-selftest:
	./hack/cargo.selftest.sh

audit:
	$(RSS_CARGO) xtask audit

docker-build:
	docker build -t rss-server:dev .

docker-smoke:
	./deploy/smoke.sh
