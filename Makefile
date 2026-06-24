# RSS 治理门聚合入口（薄 alias）。
#
# 逻辑单源在 `cargo xtask`（跨平台、CI-ready、对齐 rust-analyzer xtask 范式）；本 Makefile 只为文档
# 一直引用的 `make verify` / `make ci` 名字提供入口。
#
#   make verify       本地 stable-only 快门：fmt + meta + build + clippy + nextest + deny + dylint。
#   make verify-fast  verify 的无编译子集（仅 fmt + meta + deny），供快速迭代（= cargo xtask verify --fast）。
#   make ci           CI lane 超集（= azure-pipelines.yml 调的同一条 `cargo xtask ci`）：verify 全门 +
#                     build/clippy 升 --all-features --all-targets + 覆盖率门（llvm-cov，引擎/基础 ≥90%）
#                     + public-api --check（轴 A）+ cargo-audit（供应链漏洞，#1133）。需全套工具 + nightly。
#   make audit        供应链漏洞刷新 lane（= azure-pipelines.yml 每日 cron 调的同一条 `cargo xtask audit`，
#                     #1133）：advisory-scoped `deny check advisories` + cargo-audit（皆 no-compile、快）。
#   make integration  真集成 lane（#1137，opt-in，不入 verify/ci）：testcontainers self-provision
#                     postgres/redis/rabbitmq 跑 --features integration 测试。**docker-gated**（无 docker 且未设
#                     env URL 即 fail-closed）；设 PGHOST/REDIS_TEST_URL/RSS_AMQP_TEST_URL 指向长存服务可免 docker。
#                     azure-pipelines 接线待 #1145（需 docker-enabled agent）——CI 激活前本 lane 仅本地/手动跑。
#
# CI lane = azure-pipelines.yml（issue #1132）：PR 触发 + 失败阻断合入经 Azure 分支策略 build validation。
# 激活前（AZURE_HAS_CI=false，见 hack/automation/forge.conf 激活 runbook）`make ci` 本地即等价门——azure
# CI 未启用期间它是治理门的实际 gate。门集 / --fast / 缺工具策略见 xtask/src/verify.rs。

.PHONY: verify verify-fast ci audit integration

verify:
	cargo xtask verify

verify-fast:
	cargo xtask verify --fast

ci:
	cargo xtask ci

audit:
	cargo xtask audit

integration:
	cargo xtask integration
