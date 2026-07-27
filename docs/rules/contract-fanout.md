# 契约变更扇出闭环

## 触发条件

改动 contract schema、contract.toml、generated contract、event topic、command key、
HTTP path、auth 语义、consistency level、subscription role 时，必须做扇出检查。

DI-infra port provider（如 `diport::RevocationStore` / `Signer` / `Pdp`）不是跨域 wire contract，
不新增 `contracts/**/contract.toml` 伪契约；其组合根注入事实走 `assemblies/{name}/assembly.toml`
的 `[[diportProviders]]` 声明与 `cargo xtask assembly validate` 校验。

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
- `active` 破坏式 wire 变更默认走新版本目录（`contracts/{kind}/{domain}/{version+1}/`，新 contract ID +
  新一份 `contract.toml` + `*.schema.json`），并完整保留旧 contract identity。#1696 仅将
  `LOCAL_ONLY_BOUNDARY_CHANGED`、`EFFECT_ADDED`、`EFFECT_REMOVED` 固定为 pre-ratchet review finding；
  它们须有命令生成、绑定 base + rule/subject/detail 的精确 `Contract-Review-Ack` commit trailer 才能通过。
  `deprecated` warn / `draft` skip 不得通过 lifecycle 降级绕过其它 active deny。
- INVARIANT: CONSISTENCY-EFFECT-BREAKING-REVIEW-01（carrier 在 `xtask/src/contract/breaking.rs`）：active 默认 deny；
  三条固定 review rule 未确认 fail-closed，且不提供 flag、环境变量、日期窗口或自由文本豁免。
- generated diff 是一等审查材料。
- 新增 contract kind 或 role 必须补 governance 与 codegen 测试。
- 暂不支持的扇出项必须登记 GitHub Issue，不能写在 rules 中当计划占位。

## DI provider 扇出（assembly.toml）

改动 provider 注入、provider 生命周期、生产 / demo 后端选择、持久性等级时，必须同步：

| 载体 | 必查内容 |
|------|----------|
| `assemblies/{name}/assembly.toml` | `[[diportProviders]]` 的 port / provider / providerCrate / requiredFeatures / consumer / lifecycle / durability / scope / failurePosture / purpose |
| assembly `Cargo.toml` | `lifecycle=active` 的 providerCrate 必须是 `[dependencies]` 直接依赖，且启用 provider symbol 所需 feature |
| adapter docs/tests | dev/demo provider 边界、持久 provider 行为与 shutdown 语义 |
| governance | `cargo xtask assembly validate` 是否覆盖新 port 的 active 约束 |

现行硬约束：每个 `assemblies/{name}/Cargo.toml` 必须有同目录 `assembly.toml`，且
`diportProviders` 不得为空。`profile="production"` 的 `diport::RevocationStore` provider 必须
`durability = "persistent"`；`ephemeral-memory` 只能用于 demo/test assembly 的 draft/dev-demo 声明。
生产 `service-token-replay-store` 还必须同时声明 `durability = "persistent"`、
`scope = "cluster-global"`、`failurePosture = "fail-closed"`；缺失或弱化任一事实均由
`PdpReplayStoreCapability` assembly guard fail-closed 拒绝。

## 契约归属（域 crate vs framework）

契约的 owner 是 sealed `vocab::ContractOwner`（公开 struct 包私有内层 enum `Domain(name) | Framework`；构造只经 `ContractOwner::framework()` / `ContractOwner::of_domain(DomainName)` 受控入口，外部 crate 无法命名内层 ⇒ 无法 raw-mint 任意 owner）：

- 默认 owner 是某个**域 crate**（`owner: <domain>` 或经 `endpoints.server/publisher` 派生）。
- **中立、provider-agnostic** 契约（正确性要求 provider 可互换，如设备身份/证书签发）由**框架**归属：
  `owner: _framework`（保留 sentinel）。不绑单一 consumer 域——对齐 cert-manager/SPIFFE/k8s 范式。
- owner→域 crate 解析**只经 `c.owner().domain()`**（框架 owner 返回 `None`）；禁止直接索引 `project.domains[c.owner]`。
- 框架归属今适用于 http/event/command（command 是 provider-agnostic 分发机制，#1124 扩展 R2）；`lifecycle: active` 须在某 `assembly.toml` 的 `frameworkContracts` 声明且经 `bootstrap::validate_framework_serving` 验证 route group 已挂载；否则须为 draft|deprecated。

`frameworkContracts` 是必填闭合 mount 列表（无默认/兼容路径），每项必须同时显式声明
`{ id = "<contract>", listener = "<listener-id>" }`；旧字符串项和隐式 listener 均拒绝。每个 active framework
contract 在 workspace 中至少有一个声明者；同一 assembly 内 contract ID 必须唯一，且 mount 的 listener ID 必须
存在于该 assembly。HTTP declaration 经 assembly codegen 变成同时携带 generated route evidence 与 listener kind 的
`FrameworkHttpRoute` typed expected evidence；assembly 只能通过实例化的
`FrameworkRoutes::register(&mut Registry)` 注册。auth finalize 前，`validate_framework_serving` 按
`(listener, contract)` 对 framework-owned actual mount 做 exact-set 校验，拒绝 missing、duplicate、mismatch、
extra 和挂错 listener；不得以全局静态 route 实例或仅比较 contract ID 绕过 listener 归属。

owner→域 crate 收口由 sealed struct（私有内层 enum + 受控构造关联函数）+ `owner().domain()` API（类型系统强制 `Framework` 无法解析成域、外部无法 mint 任意 owner）守，无需运行期 guard。
构造封闭符号/盲区见 `crates/vocab/src/contract/owner.rs`（INVARIANT: CONTRACT-OWNER-SEAL-01）。

## Implementation matrix

PR body 或实施计划中列：

| 变更 | contract | generated | 域 crate | tests | docs |
|------|----------|-----------|----------|-------|------|
| ... | ... | ... | ... | ... | ... |
