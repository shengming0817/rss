# RSS 治理门聚合入口（薄 alias）。
#
# 逻辑单源在 `cargo xtask`（跨平台、CI-ready、对齐 rust-analyzer xtask 范式）；本 Makefile 只为文档
# 一直引用的 `make verify` / `make ci` 名字提供入口。
#
#   make verify       本地 stable-only 快门：fmt + meta + build + clippy + nextest + deny + dylint。
#   make verify-fast  verify 的无编译子集（仅 fmt + meta + deny），供快速迭代（= cargo xtask verify --fast）。
#   make ci           CI lane 超集（= GitHub Actions 调的同一条 `cargo xtask ci`）：verify 全门 +
#                     build/clippy 升 --all-features --all-targets + 覆盖率门（llvm-cov，引擎/基础 ≥90%）
#                     + public-api --check（轴 A）+ cargo-audit（供应链漏洞，#1133）。需全套工具 + nightly。
#   make audit        供应链漏洞刷新 lane（= GitHub Actions schedule 调的同一条 `cargo xtask audit`，
#                     #1133）：advisory-scoped `deny check advisories` + cargo-audit（皆 no-compile、快）。
#   make integration  真集成 lane（#1137，opt-in，不入 verify/ci）：testcontainers self-provision
#                     postgres/redis/rabbitmq/mosquitto 跑 --features integration 测试。**docker-gated**（无 docker
#                     且未设 env URL 即 fail-closed）；设 RSS_TEST_ALLOW_EXTERNAL_POSTGRES +
#                     PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD + REDIS_TEST_URL + RSS_AMQP_TEST_URL +
#                     RSS_MQTT_TEST_URL 指向长存服务可免 docker。
#                     GitHub Actions runner 需 docker；本地/手动可用同一 `cargo xtask integration`。
#   make docker-build server 多阶段镜像构建（#1134）：cargo-chef + distroless/cc:nonroot → rss-server:dev。
#   make docker-smoke 容器冒烟验收（#1134，**docker-gated**）：build → compose up → /readyz 200 → 非 root /
#                     只读 rootfs 断言 → down -v。逻辑在 deploy/smoke.sh（机器可判定 acceptance harness）。
#
# CI lane = GitHub Actions workflows（issue #1132）：PR/push 触发 + GitHub required checks 阻断合入。
# 门集 / --fast / 缺工具策略见 xtask/src/verify.rs。

.PHONY: verify verify-fast ci audit integration docker-build docker-smoke

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

docker-build:
	docker build -t rss-server:dev .

docker-smoke:
	./deploy/smoke.sh
