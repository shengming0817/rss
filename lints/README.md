# RSS 自写 dylint lint

RSS 治理三档载体里「残留真要 AST 级的少数 funnel」那一档（见 `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps`
§Rust 原生强制 二档表）。clippy `disallowed-*` / `cargo-deny` / 类型系统表达不了的 AST 级约束，
落到这里的自写 [dylint](https://github.com/trailofbits/dylint) lint。

## 为什么是独立 workspace

lint crate 链接 `rustc_private`，须用 **nightly** 工具链（见 `rust-toolchain.toml`）。`lints/` 自成
一个嵌套 Cargo workspace（本目录 `Cargo.toml` 的 `[workspace]`）+ 根 `Cargo.toml` 的 `exclude = ["lints"]`，
与根 **stable 1.96** workspace 完全隔离——`cargo build/test/clippy --workspace`（根）不会编译这里、
不触碰 nightly。

**隔离的副作用**：根 `deny.toml`（`[sources] unknown-git = "deny"` 等）也**不扫描** `lints/` 子 workspace。
本子树唯一 git 依赖是 `clippy_utils`（rust-lang 官方 `rust-clippy` 仓库，`rev` 与 nightly channel 配对），经人工审核；
`lints/Cargo.lock` **刻意提交**（与根 workspace 策略一致，保证 nightly + clippy_utils rev 可复现，勿删）。
dylint 自写 lint 不走根 `[workspace.lints.clippy]`——与 clippy 是平行机制，只经 `cargo dylint` 触发。
新增 lint 引入新的 git/registry 依赖时须人工核查（因根 `deny.toml` 不覆盖本子 workspace）。

## 前置

```bash
cargo install cargo-dylint dylint-link
```

`channel`（`rust-toolchain.toml`）与各 lint crate 的 `clippy_utils` git `rev` **成对**绑定，升级须同步改两者
（勿单独动其一，否则 nightly 与 clippy_utils ABI 不齐、编译失败、排查难）。升级步骤：① 取目标 dylint
版本的 [releases](https://github.com/trailofbits/dylint/releases) → `internal/template/{rust-toolchain,Cargo.toml}`
拿配对的 channel + `clippy_utils` rev；② 同步改 `lints/rust-toolchain.toml` 与各 `lints/*/Cargo.toml`；
③ `cd lints && cargo test` 验证。

## 运行

```bash
# 仓库根：对整个 workspace 跑所有已注册 lint（注册在根 Cargo.toml [workspace.metadata.dylint]）
cargo dylint --all
cargo dylint list            # 列出已注册 lint

# 所有 lint 自测（对 lints/ 子 workspace 跑全部 UI 测试）
cd lints && cargo test --workspace

# 单个 lint 自测（UI 测试，自动取 lints/ 的 nightly）
cd lints/rss_domain_no_serialize && cargo test
```

> ✅ **已接入聚合门（#1023）**：`cargo dylint --all` 现是 `cargo xtask verify` / `make verify` 的一步，并经
> `DYLINT_RUSTFLAGS=-D warnings` 升为 **fail-closed**（默认 `Warn` 的注册 lint 违例即让 verify 非零退出）。
> 激活 forge=azure 无 CI ⇒ verify 是治理门的唯一实际 gate（提交前 / ship·fix 收尾跑）。
> **仍在 #1054**：覆盖面仍是 `domain` 模块命名约定（非完整域 crate 边界）；细节见
> `rss_domain_no_serialize`（[`lints/rss_domain_no_serialize/src/lib.rs`](rss_domain_no_serialize/src/lib.rs) rustdoc）。

## 如何查事实（不在此维护 inventory）

本 README **不**维护已落地 lint 清单或 INVARIANT 对照表。查机器单源：

1. **注册** → 根 `Cargo.toml` `[workspace.metadata.dylint]`
2. **members** → `lints/Cargo.toml` `[workspace].members`
3. **反向索引** → `cargo xtask archrules list` / `cargo xtask archrules verify`
4. **符号 / 红例 / 盲区** → 各 `lints/<lint>/src/lib.rs` rustdoc

运行时也可 `cargo dylint list` / `cargo dylint --all` 查看当前已注册 lint。

## 逃生门与新增 lint

逃生门：确需豁免的 callsite（如确需序列化的非 DTO 类型、确需读裸 ctx 的 spawn），在该 item 上加
`#[allow(<lint_id>)] // reason: ...`（与仓库 item-level carve-out 纪律一致）。
每条 lint 的符号 / 红例 / 盲区单源在其 `src/lib.rs` rustdoc。新增 lint：复制
[dylint 模板](https://github.com/trailofbits/dylint/tree/master/internal/template) 到
`lints/<rss_xxx>/`，加进本目录 `Cargo.toml` members + 根 `[workspace.metadata.dylint] libraries`。
**ui example target 名取唯一 `<lint>_ui`**（非裸 `ui`）：多个 lint crate 同名 example 在 `cargo test --workspace`
会产生 artifact 路径碰撞（Cargo 警告、未来或升 hard error，见 rust-lang/cargo#6313）；`src/lib.rs` 的
`ui_test_example(env!("CARGO_PKG_NAME"), "<lint>_ui")` 第二参须同步，golden 仍随源文件名 `ui/main.stderr`。

> **例外（caller-crate-name lint 的绿例）**：若 lint 按 **caller crate 名** 判 allowlist（如
> `rss_crosstenant_callsite` 只准 `authn` 调），绿例须把 example target 名取作 allowlist 项本身（如 `authn`）
> ——UI fixture 编译为单一 example crate、其 crate 名 = target 名，故只有这样 `crate_name(LOCAL_CRATE)` 才命中
> allowlist 分支。此时 target 名**故意偏离** `<lint>_ui`；红例仍用 `<lint>_ui`。碰撞风险：不同 lint 的同名绿例
> target（如两个 lint 都用 `authn`）——届时按需在 target 名加 lint 前缀消歧。golden 随各源文件名（如 `ui/authn.stderr`，
> 无诊断时为**空文件**，须提交以锁定「期望零诊断」）。
