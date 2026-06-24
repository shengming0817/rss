# Quickstart: identity crate 端到端最小验证路径

本文覆盖 identity 域 crate 在本地的快速验证步骤，适用于每个子 PR 落地后的自检。

## 前置

- `rust-toolchain.toml` 固定的 Rust 工具链已安装（`rustup show`）。
- `cargo-nextest`、`cargo-llvm-cov`、`cargo-dylint` 已安装。

## 1. 单元测试（每 PR 必跑）

```bash
cargo nextest run -p identity
```

全绿后视为基本通过。

## 2. Lint 与格式

```bash
cargo clippy -p identity --all-targets -- -D warnings
cargo fmt --check -p identity
```

## 3. domain 序列化约束（domain 类型禁 Serialize）

```bash
DYLINT_RUSTFLAGS=-D warnings cargo dylint --all
```

`rss_domain_no_serialize` 等 lint 经 `DYLINT_RUSTFLAGS=-D warnings` **fail-closed**（warning 即非零退出）——这是 Medium 机器守卫，不是「看输出」观察项；等价入口 `cargo xtask verify`（已封装该环境）。

## 4. 覆盖率门

```bash
cargo llvm-cov --lib -p identity
```

新增代码 diff coverage ≥ 80%（domain 纯逻辑趋近 90%）。

## 5. seed-login feature 冒烟（G1 已验接缝）

```bash
cargo test -p identity --features seed-login
```

验证「登录 → outbox → audit」in-mem 拓扑端到端跑通（fake Publisher + in-mem repos）。

## 6. 契约完整性（PR5 后）

```bash
cargo xtask contract validate
```

验收：`identity.login` / `identity.session-created` 升 active；`identity.role-assigned` / `identity.role-revoked` 等新契约扇出闭环完整；generated 与 schema 字节一致。

## 7. workspace 级别最终门

```bash
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

步骤 1–4 在每个子 PR 合并前必跑；步骤 5 在 PR3 完成后可用；步骤 6 在 PR5b 后必跑；步骤 7 在 PR5b 提交前必跑。
