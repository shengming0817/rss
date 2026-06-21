# 契约变更扇出闭环

## 触发条件

改动 contract schema、contract.toml、generated contract、event topic、command key、
HTTP path、auth 语义、consistency level、subscription role 时，必须做扇出检查。

## 必查载体

| 载体 | 必查内容 |
|------|----------|
| contract schema | request/response/payload 字段、required、enum、format |
| generated code | handler、client、types、registration glue |
| 域 crate metadata | `Cargo.toml [dependencies]` + `contract.toml`（role、field、consistencyLevel、verify target） |
| journey/fixture | 测试输入和验收路径是否仍匹配 |
| governance / crate-graph lint | 是否需要新增或更新机器守卫（`cargo-deny` / clippy lint / 类型系统） |

## 规则

- contract 是跨域通信单源，共享 Rust 类型不是单源。
- 破坏式 wire 变更走新版本目录（`contracts/{kind}/{domain}/{version+1}/`，新一份 `contract.toml` + `*.schema.json`）。**Pre-GA 窗口例外**：`api-versioning.md` §兼容窗口（至 2026-12-31）内允许原地改 active 版本，仍须完成本扇出闭环；窗口后才强制新版本目录。
- generated diff 是一等审查材料。
- 新增 contract kind 或 role 必须补 governance 与 codegen 测试。
- 暂不支持的扇出项必须登记 GitHub Issue，不能写在 rules 中当计划占位。

## 契约归属（域 crate vs framework）

契约的 owner 是 sealed `vocab::ContractOwner`（`Domain(name) | Framework`，sealed enum）：

- 默认 owner 是某个**域 crate**（`owner: <domain>` 或经 `endpoints.server/publisher` 派生）。
- **中立、provider-agnostic** 契约（正确性要求 provider 可互换，如设备身份/证书签发）由**框架**归属：
  `owner: _framework`（保留 sentinel）。不绑单一 consumer 域——对齐 cert-manager/SPIFFE/k8s 范式。
- owner→域 crate 解析**只经 `c.owner().domain()`**（框架 owner 返回 `None`）；禁止直接索引 `project.domains[c.owner]`。
- 框架归属今仅 http/event；`lifecycle: active` 须在某 `assembly.toml` 的 `frameworkContracts` 声明且经 `bootstrap::validate_framework_serving` 验证 route group 已挂载；否则须为 draft|deprecated。

owner→域 crate 收口由 sealed enum + `owner().domain()` API（类型系统强制 `Framework` 无法解析成域）守，无需运行期 guard。
符号/盲区见 `crates/vocab/src/contract/owner.rs`。

## Implementation matrix

PR body 或实施计划中列：

| 变更 | contract | generated | 域 crate | tests | docs |
|------|----------|-----------|----------|-------|------|
| ... | ... | ... | ... | ... | ... |
