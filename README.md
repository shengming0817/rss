# rss

RSS 是 GoCell 的 Rust 重写——domain-native 治理 + 惯用扁平 Cargo workspace（无 cell/slice 外壳）。

## 结构

扁平 workspace：`crates/`（库 crate，分基础/引擎/服务/域四层）、`adapters/`、`bins/`、`xtask/`、`generated/`。
完整结构树 / 分层 / 命名的**单一事实源**见 [`docs/rules/architecture.md`](docs/rules/architecture.md)；
最高协作规范见 [`CLAUDE.md`](CLAUDE.md)。分层由 crate 依赖图（编译期）+ `deny.toml` wrappers 强制。

## 构建与本地验证

```bash
cargo build --workspace                                # 编译全 workspace（分层有环即失败）
cargo fmt --all -- --check                             # 格式
cargo clippy --workspace --all-targets -- -D warnings  # lint（clock 注入 / panic 纪律）
cargo test --workspace                                 # 测试（或 cargo nextest run --workspace --no-tests=pass）
cargo deny check                                       # 分层禁依赖 + license + advisory
```

工具链由 `rust-toolchain.toml` 钉定（首次进入目录自动安装）。治理工具：
`cargo install cargo-deny cargo-nextest --locked`。
