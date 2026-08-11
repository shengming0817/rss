# 契约变更扇出闭环

## 触发条件

改动 contract schema、`contracts/components/**`、contract.toml、generated contract、event topic、command key、
HTTP path、auth 语义、consistency level、subscription role 时，必须做扇出检查。

DI-infra port provider（如 `diport::RevocationStore` / `Signer` / `Pdp`）不是跨域 wire contract，
不新增 `contracts/**/contract.toml` 伪契约；其组合根注入事实走 `assemblies/{name}/assembly.toml`
的 `[[diportProviders]]` 声明与 `cargo xtask assembly validate` 校验。

## 必查载体

| 载体 | 必查内容 |
|------|----------|
| contract schema | request/response/payload 字段、required、enum、format |
| schema component | base/working 引用并集的全部 consumer、owner/subscriber、resolved hash 与 breaking findings |
| generated code | handler、client、types、registration glue |
| 域 crate metadata | `Cargo.toml [dependencies]` + `contract.toml`（role、field、consistencyLevel、verify target） |
| journey/fixture | 测试输入和验收路径是否仍匹配 |
| governance / crate-graph lint | 是否需要新增或更新机器守卫（`cargo-deny` / clippy lint / 类型系统） |

## 规则

- contract 是跨域通信单源，共享 Rust 类型不是单源。
- component 是本仓库内 path-derived 的 authoring 单源，不是 registry。`assembly-schema` 的 typed
  `ComponentId` + 纯 `ComponentGraph` 唯一拥有 ID/path/ref 语法与传递引用；working filesystem 和 Git base
  reader 只负责提供文档 bytes。CI impact 必须沿 base/working 引用图的并集扇出，删除或改名不得丢失旧 consumer。
- `active` 破坏式 wire 变更默认走新版本目录（`contracts/{kind}/{domain}/{version+1}/`，新 contract ID +
  新一份 `contract.toml` + `*.schema.json`），并完整保留旧 contract identity。#1696 仅将
  `LOCAL_ONLY_BOUNDARY_CHANGED`、`EFFECT_ADDED`、`EFFECT_REMOVED` 固定为 pre-ratchet review finding；
  它们须有命令生成、绑定 base + rule/subject/detail 的精确 `Contract-Review-Ack` commit trailer 才能通过。
  `deprecated` warn / `draft` skip 不得通过 lifecycle 降级绕过其它 active deny。
- INVARIANT: CONSISTENCY-EFFECT-BREAKING-REVIEW-01（carrier 在 `xtask/src/contract/breaking.rs`）：active 默认 deny；
  三条固定 review rule 未确认 fail-closed，且不提供 flag、环境变量、日期窗口或自由文本豁免。
- generated diff 是一等审查材料。
- durable event/command/saga/projection 的 resolved schema hash 旋转是一等 breaking identity；即使字段
  集合论兼容也不得静默通过。`format` 新增会改变 generated scalar，必须与 hash 旋转分别进入精确
  breaking findings，并由同一 base-bound authorization 完整覆盖。
- 新增 contract kind 或 role 必须补 governance 与 codegen 测试。
- 暂不支持的扇出项必须登记 GitHub Issue，不能写在 rules 中当计划占位。

## Contract Governance IR

- **MUST**：typed catalog 独占 validation/breaking 的 identity、handler、owner、source 与文档；production
  consumer 只在 `ContractGovernanceIr::read` / `commit` 内消费 `GovernedContract`，codegen 先规划全量输出再
  原子提交，测试专项输入只走显式 `load_test_fixture_root`。
- **Schema source funnel**：repository discovery 先按规范化物理路径捕获并 parse-once schema/component，
  只有 source 全部存在、安全、JSON 良构且引用可解析时才能 consuming promotion 为 `RepositoryContract`；
  validation、breaking、schema hash、AssemblyLock 与 codegen 只接收 promoted contract。malformed source
  由 R5 按物理路径产生一次 canonical finding，不新增平行 parser、registry 或独立规则。promoted
  working-schema consumer 复用 captured `Value` / `ResolvedSchema` 与预计算 hash；HIR backstop 在既有
  Dylint gate 中拒绝其 crate-local 调用闭包重新进入 JSON parser。该 Medium backstop 不承诺 filesystem
  capability isolation，也不阻止刻意硬编码外部解析。
- **失败语义**：完整仓为空、catalog/handler 漂移、manifest/schema/文件集合在快照期间变化均 fail-closed；
  写入或最终 closeout 失败须逆序恢复全批输出。仅 breaking working side 可显式为空，用于检测删除全部契约。
- **INVARIANT 指针**：`CONTRACT-GOVERNANCE-IR-01` 与
  `CONTRACT-GOVERNANCE-SOURCE-FUNNEL-01`（`xtask/src/contract/governance.rs`），以及
  `CONTRACT-SCHEMA-PARSE-01`（`xtask/src/contract/validate.rs`）与
  `CONTRACT-SCHEMA-PARSER-HIR-01`（`lints/rss_contract_schema_parse_funnel/src/lib.rs`）。

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

- **MUST**：governance owner 使用 manifest-backed `assembly_schema::ContractOwner`，只能由 repository
  snapshot promotion；生产消费者只经 `GovernedContract::owner()` 读取，owner→域 crate 只经
  `owner().domain()` 解析。
- **失败语义**：无真实 `contract.toml` 来源的字符串不得 mint governance owner；framework owner 解析为域、
  或 production 绕过 Governance IR 直接发现 repository，均 fail-closed。
- **不同载体**：仍存在的 `vocab::HttpContractOwner` 是 generated/runtime HTTP route evidence，承载路由鉴权与
  serving 归属；它不是 repository governance 的 `assembly_schema::ContractOwner`，也不能替代其来源证明。
- **INVARIANT 指针**：`CONTRACT-GOVERNANCE-IR-01`、`CONTRACT-GOVERNANCE-SOURCE-FUNNEL-01`
  （`xtask/src/contract/governance.rs`）与 HTTP route carrier 定义（`crates/vocab/src/http.rs`）。

- 默认 owner 是某个**域 crate**（`owner: <domain>` 或经 `endpoints.server/publisher` 派生）。
- **中立、provider-agnostic** 契约（正确性要求 provider 可互换，如设备身份/证书签发）由**框架**归属：
  `owner: _framework`（保留 sentinel）。不绑单一 consumer 域——对齐 provider-agnostic identity 范式。
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

## Implementation matrix

PR body 或实施计划中列：

| 变更 | contract | generated | 域 crate | tests | docs |
|------|----------|-----------|----------|-------|------|
| ... | ... | ... | ... | ... | ... |
