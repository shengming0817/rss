# RSS 治理门聚合入口（薄 alias）。
#
# 逻辑单源在 `cargo xtask`（跨平台、CI-ready、对齐 rust-analyzer xtask 范式）；本 Makefile 只为文档
# 一直引用的 `make verify` / `make ci` 名字提供入口。
#
#   make verify       本地 stable-only 快门：fmt + meta + build + clippy + nextest + deny + dylint。
#   make verify-fast  verify 的无编译子集（仅 fmt + meta + deny），供快速迭代（= cargo xtask verify --fast）。
#   make ci           本地去重兼容聚合（非 GitHub job）：保留 43 个唯一 gate，Coverage 取代 Core 的
#                     default-profile nextest；因此不与四个真实 check 的执行语义完全等价。复现真实 checks
#                     须分别运行 cargo xtask ci-meta / ci-core / ci-security / ci-coverage。
#                     需全套工具 + nightly。
#   make audit        供应链漏洞刷新 lane（= GitHub Actions schedule 调的同一条 `cargo xtask audit`，
#                     #1133）：advisory-scoped `deny check advisories` + cargo-audit（皆 no-compile、快）。
#   make docker-build server 多阶段镜像构建（#1134）：cargo-chef + distroless/cc:nonroot → rss-server:dev。
#   make docker-smoke 容器冒烟验收（#1134，**docker-gated**）：build → compose up → /readyz 200 → 非 root /
#                     只读 rootfs 断言 → down -v。逻辑在 deploy/smoke.sh（机器可判定 acceptance harness）。
#
# CI lane = GitHub Actions workflows（issue #1132）：PR/push 触发 + GitHub required checks 阻断合入。
# 门集 / --fast / 缺工具策略见 xtask/src/verify.rs。

.PHONY: verify verify-fast ci audit docker-build docker-smoke

RSS_CARGO ?= ./hack/cargo.sh

verify:
	$(RSS_CARGO) xtask verify

verify-fast:
	$(RSS_CARGO) xtask verify --fast

ci:
	$(RSS_CARGO) xtask ci

audit:
	$(RSS_CARGO) xtask audit

docker-build:
	docker build -t rss-server:dev .

docker-smoke:
	./deploy/smoke.sh
