# Issue 1359 Redact Debug 重构计划

## 背景

Issue #1359 要求把敏感类型的 `Debug` 脱敏从手写实现提升为字段级 derive 机器守卫。#1360 已先落地
`securederive` proc-macro、`secure::Redact` 字段级策略模型、`redact_struct` funnel 与部分类型迁移。本计划在
该基础上完成 #1359 的公开接口收敛、核心类型迁移和裸 `derive(Debug)` 回退守卫。

## 开源探索

- `ref: iqlusioninc/crates secrecy/src/lib.rs@main`：采纳 `SecretBox` 默认 `Debug` 脱敏和显式暴露边界。RSS
  偏离为字段级 declared policy，而非所有敏感值都包 `Secret<T>`。
- `ref: serde-rs/serde serde_derive/src/internals/attr.rs@master`：采纳 derive 属性解析的 fail-fast 模式，
  对重复/未知属性定位到字段属性。
- `ref: dtolnay/thiserror impl/src/attr.rs@master`：采纳 derive 宏只生成 trait/debug 实现、不引入运行时分支的模式，
  保持业务类型 API 简洁。

## 公共接口

- `secure` 导出 `secure::Redact` trait + `#[derive(secure::Redact)]` proc-macro。
- 不保留 `Redactable` 兼容别名；本仓无外部调用方，按项目规则不做向后兼容 shim。
- 字段属性语法：
  - `#[redact(sensitivity = public)]`
  - `#[redact(sensitivity = internal)]`
  - `#[redact(sensitivity = secret)]`
  - `#[redact(sensitivity = pii|pii_email|pii_phone|pii_name|pii_address)]`
  - 可选 `mode = "show|fixed|last4|email_mask|drop"`
- 宏规则：
  - 每字段必须声明且只能声明一个 sensitivity。
  - 缺标注、重复 sensitivity、未知 sensitivity、未知 mode 均编译失败。
  - `mode = "show"` 只允许搭配 `public`。
  - 字段级 `mode = "hash"` 已移除；关联令牌须走显式 keyed HMAC API。
  - `public` 默认 `show`；`internal`/`secret` 默认 `fixed`；`pii` 默认由 `PiiKind::default_mode()` 决定。

## 批次与依赖

1. 计划文件：写入本文档，作为 ship 阶段 2 的实施计划单源。
2. `securederive`：把 derive 从 `Redactable` 改为 `Redact`，重写 `#[redact(...)]` parser 与 trybuild golden。
3. `secure`：把 trait 改名为 `Redact`，更新 `redact_struct`/`RedactValue` 以支持 public 字段按 `Debug` 渲染。
4. 核心类型迁移：迁移 `AuditEvent`、`RoleBinding`、`Session`/`SessionId`、`RequestCtx`/`PrincipalSlot`、
   `SecretMaterial`/`SecretCoordinate` 到 `#[derive(secure::Redact)]`。
5. dylint 守卫：新增裸敏感 DTO `derive(Debug)` 回退守卫，并注册到 `cargo dylint --all`。
6. 文档：同步 `crates/observ`、`secure::redact_error` 与 typed metric enums、`Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps`、`lints/README.md`。

批次 2 依赖批次 1；批次 3 依赖批次 2；批次 4 依赖批次 3；批次 5 可在批次 4 后独立开发；批次 6 收尾。

## TDD 清单

- `securederive` trybuild compile-fail：缺字段标注、重复 sensitivity、未知 sensitivity、未知 mode、
  `secret|internal|pii + mode = "show"`、`mode = "hash"`。
- `secure` 单测：新语法端到端、public 字段 Debug 渲染、fixed/drop 不要求字段实现 `RedactField`。
- 核心类型单测：泄漏 marker 不出现在 `format!("{:?}", value)` 中，公共诊断字段仍可见。
- dylint UI：敏感结构裸 `#[derive(Debug)]` 报错，`#[derive(secure::Redact)]` 或带 reason 的 item-level allow 放行。

## 验证命令

```bash
cargo test -p secure -p securederive -p diport -p runctx -p identity --workspace
cd lints && cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo xtask verify
```
