# RSS 自写 dylint lint

RSS 治理三档载体里「残留真要 AST 级的少数 funnel」那一档（见 `docs/rules/architecture.md`
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

# 单个 lint 自测（UI 测试，自动取 lints/ 的 nightly）
cd lints/rss_domain_no_serialize && cargo test
```

> ⚠ **当前未接入 CI 门**：把 `cargo dylint` 接进 `cargo xtask verify` / make verify 是 **#1023** 的范围。
> 在 #1023 完成前，本 lint 不在 CI 自动跑——须手动 `cargo dylint --all` 触发（实质处于「可手动跑、CI 不强制」
> 的临时降级状态，未达强制 Medium）。本 PR（#1001）只保证 `cargo dylint --all` 独立可跑。

## 已落地 lint

| lint id | INVARIANT | 守的约束 |
|---------|-----------|---------|
| `rss_domain_no_serialize` | SERDE-DOMAIN-FREEZE-01 | domain 实体禁 derive serde `Serialize`/`Deserialize`（只有 contract/DTO/`generated` 可序列化到 wire）。默认 `Warn`。 |

逃生门：确需序列化的非 DTO 类型，在该类型上加
`#[allow(rss_domain_no_serialize)] // reason: ...`（与仓库 item-level carve-out 纪律一致）。
每条 lint 的符号 / 红例 / 盲区单源在其 `src/lib.rs` rustdoc。新增 lint：复制
[dylint 模板](https://github.com/trailofbits/dylint/tree/master/internal/template) 到
`lints/<rss_xxx>/`，加进本目录 `Cargo.toml` members + 根 `[workspace.metadata.dylint] libraries`。
