# rss

RSS 是 GoCell 的 Rust 重写——domain-native 治理 + 惯用扁平 Cargo workspace（无 cell/slice 外壳）。

## 结构

扁平 workspace：`crates/`（库 crate，分基础/引擎/服务/域四层）、`adapters/`、`bins/`、`xtask/`、`generated/`。
完整结构树 / 分层 / 命名的**单一事实源**见 [`docs/rules/architecture.md`](docs/rules/architecture.md)；
最高协作规范见 [`CLAUDE.md`](CLAUDE.md)。分层由 crate 依赖图（编译期）+ `deny.toml` wrappers 强制。

## 构建与本地验证

单一聚合入口（GitHub Actions 与本地共用同一 `cargo xtask` 门）：

```bash
make verify              # == cargo xtask verify（薄 alias）
cargo xtask verify       # fmt + 契约/分层/codegen meta + build + clippy + nextest + deny + dylint，fail-fast
cargo xtask verify --fast            # 只跑无需编译的步（fmt + meta + deny），快速迭代
cargo xtask verify --allow-missing-tools   # 缺外部工具时显式宽限（默认 fail-closed）
```

`verify` 串联的逐条命令（也可单独跑）：

```bash
cargo fmt --all -- --check                             # 格式
cargo xtask contract validate                          # 契约元数据校验
cargo xtask layer-deps                                 # source-centric 分层依赖 lint
cargo xtask codegen --check                            # 契约 codegen 漂移门
cargo build --workspace                                # 编译全 workspace（分层有环即失败）
cargo clippy --workspace --all-targets -- -D warnings  # lint（clock 注入 / panic 纪律）
cargo nextest run --workspace --no-tests=pass          # 测试（或 cargo test --workspace）
cargo deny check                                       # 分层禁依赖 + license + advisory
cargo dylint --all                                     # AST 级自写 lint（domain 禁 derive serde 等）
```

工具链由 `rust-toolchain.toml` 钉定（首次进入目录自动安装）。治理工具：

```bash
cargo install cargo-nextest@0.9.137 cargo-deny@0.19.9 --locked
cargo install cargo-dylint@6.0.1 dylint-link@6.0.1 --locked
cargo install cargo-llvm-cov@0.8.7 cargo-public-api@0.52.0 cargo-audit@0.22.2 --locked
```

> dylint 须 nightly：`cargo-dylint` / `dylint-link` 版本与 `lints/rust-toolchain.toml` 的 channel +
> `clippy_utils` rev **成对**，升级步骤见 `lints/README.md`（勿单独升任一侧，否则 ABI 不齐编译失败）。

门集 / `--fast` / 缺工具策略单源见 `xtask/src/verify.rs`。
