# RSS 治理门的受控本地 bootstrap。
#
# typed gate plan 单源在 `cargo xtask`（跨平台、CI-ready、对齐 rust-analyzer xtask 范式）；Make
# 通过 `hack/cargo.sh` 统一 build-jobs、ambient wrapper 清洗和 compiler-cache policy。直接执行
# `cargo xtask` 使用同一 gate plan 与 target-dir 默认值，但不具备等价的外层 Cargo bootstrap。
#
#   make verify       本地 stable-only 快门：默认 keep-going；VERIFY_ARGS 可传 --fail-fast/--only。
#   make verify-fast  registry 显式 Always 的本地 meta 门；VERIFY_ARGS 可传 --fresh/--fail-fast/--only；冷缓存或 xtask
#                     变更时，外层 Cargo 仍会构建 xtask 启动器。
#   make ci           按 CI_BASE...HEAD 的已提交差异执行默认 keep-going 的 10 分钟有界 typed preflight；默认
#                     CI_BASE=origin/develop。未知路径只跑固定 meta，full-only 门不属于本地计划；
#                     影响分析失败直接报错，不自动回退完整 verify。
#   make ci-full      仅人工诊断时显式执行默认 keep-going 的完整 CI 门集；不得作为 PR 默认收尾。
#   make cargo-selftest 本地 Cargo 入口的 target 隔离与 override 机器验收。
#   make audit        供应链漏洞刷新 lane（与 GitHub Actions schedule 使用同一 typed audit plan）：
#                     inner plan 只有 advisory-scoped `deny check advisories` + cargo-audit，
#                     不包含 workspace 编译 gate；外层 Cargo 启动器边界同上。
#   make docker-build server 多阶段镜像构建（#1134）：cargo-chef + distroless/cc:nonroot → rss-server:dev。
#   make docker-smoke 容器冒烟验收（#1134，**docker-gated**）：build → compose up → /readyz 200 → 非 root /
#                     只读 rootfs 断言 → down -v。逻辑在 deploy/smoke.sh（机器可判定 acceptance harness）。
#
# CI 架构与运维状态见 docs/ops/202606231530-001-ci-lane.md；精确门集与缺工具策略见
# xtask/src/verify.rs。

.PHONY: verify verify-fast verify-hooks ci ci-full cargo-selftest audit docker-build docker-smoke postgres-reader-upgrade-smoke

RSS_CARGO ?= ./hack/cargo.sh
CI_BASE ?= origin/develop
VERIFY_ARGS =
CI_ARGS =

verify:
	$(RSS_CARGO) xtask verify $(VERIFY_ARGS)

verify-fast:
	$(RSS_CARGO) xtask verify --fast $(VERIFY_ARGS)

verify-hooks:
	/usr/bin/python3 -m unittest discover -s .codex/hooks -p 'test_*.py'

ci:
	/usr/bin/python3 hack/ci-local-supervisor.py --repo-root "$(CURDIR)" --budget-seconds 600 -- $(RSS_CARGO) xtask ci local --base "$(CI_BASE)" $(CI_ARGS)

ci-full:
	$(RSS_CARGO) xtask ci full $(CI_ARGS)

cargo-selftest:
	./hack/cargo.selftest.sh

audit:
	$(RSS_CARGO) xtask ci run --job audit

docker-build:
	docker build -t rss-server:dev .

docker-smoke:
	RSS_SMOKE_MODE=developer ./deploy/smoke.sh

postgres-reader-upgrade-smoke:
	./deploy/postgres-upgrade/smoke-retained-volume.sh
