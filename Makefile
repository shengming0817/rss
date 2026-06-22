# RSS 本地治理门聚合入口（薄 alias）。
#
# 逻辑单源在 `cargo xtask verify`（跨平台、CI-ready、对齐 rust-analyzer xtask 范式）；本 Makefile
# 只是为文档里一直引用的 `make verify` 名字提供入口。azure 无 CI ⇒ 本门是治理门的唯一实际 gate。
# 门集 / --fast / 缺工具策略见 xtask/src/verify.rs。

.PHONY: verify verify-fast

verify:
	cargo xtask verify

verify-fast:
	cargo xtask verify --fast
