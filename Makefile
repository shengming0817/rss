# RSS 治理门的受控本地 bootstrap。
#
# typed gate plan 单源在 `cargo xtask`（跨平台、CI-ready、对齐 rust-analyzer xtask 范式）；Make
# 通过 `hack/cargo.sh` 统一 build-jobs、ambient wrapper 清洗和 compiler-cache policy；`ci local` 还会在
# Cargo 前进入 committed-snapshot supervisor。直接执行 `cargo xtask ci local` 不具备来源边界并 fail-closed。
#
#   make verify       本地 stable-only 快门：默认 keep-going；VERIFY_ARGS 可传 --fail-fast/--only。
#   make verify-fast  registry 显式 Always 的本地 meta 门；VERIFY_ARGS 可传 --fail-fast/--only；冷缓存或 xtask
#                     变更时，外层 Cargo 仍会构建 xtask 启动器。
#   make ci           按 CI_BASE...HEAD 的已提交差异执行默认 keep-going 的 10 分钟有界 typed preflight；默认
#                     CI_BASE=origin/develop。未知路径只跑固定 meta，full-only 门不属于本地计划；
#                     影响分析失败直接报错，不自动回退完整 verify。
#   make ci-full      仅人工诊断时显式执行默认 keep-going 的 release-check；workspace coverage 吸收 component
#                     nextest，不维护独立成员表；不得作为 PR 默认收尾。
#   make cargo-selftest 本地 Cargo 入口的 target 隔离与 override 机器验收。
#   make audit        供应链漏洞刷新 lane（与 security-audit.yml 的每日 UTC schedule 使用同一 typed audit plan）：
#                     inner plan 只有 advisory-scoped `deny check advisories` + cargo-audit，
#                     不包含 workspace 编译 gate；外层 Cargo 启动器边界同上。
# CI 架构与运维状态见 docs/ops/202606231530-001-ci-lane.md；精确门集与缺工具策略见
# xtask/src/verify.rs。

.PHONY: verify verify-fast ci ci-full cargo-selftest audit

RSS_CARGO ?= ./hack/cargo.sh
CI_BASE ?= origin/develop
VERIFY_ARGS =
CI_ARGS =

verify:
	$(RSS_CARGO) xtask verify $(VERIFY_ARGS)

verify-fast:
	$(RSS_CARGO) xtask verify --fast $(VERIFY_ARGS)

ci:
	$(RSS_CARGO) xtask ci local --base "$(CI_BASE)" $(CI_ARGS)

ci-full:
	$(RSS_CARGO) xtask ci full $(CI_ARGS)

cargo-selftest:
	./hack/cargo.selftest.sh

audit:
	$(RSS_CARGO) xtask ci audit
