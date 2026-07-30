# Phase 1 Contracts: 新增契约形态

本 feature 主体是「在冻结签名内填 body」，绝大多数接口已是冻结的 Rust trait/type（见 spec / data-model）。新增**跨边界 wire 契约**仅两处 kind，均走 `contracts/` 声明 → `generated/` 派生 + 扇出闭环。

## 1. command 契约 kind（P12）

新增 `contracts/command/<domain>/v1/`：
- `contract.toml`：`id="<domain>.<command>"`、`kind="command"`、`consistencyLevel="OutboxFact"`（L2，**机器锁定**：R15 `CommandConsistency` 强制 `kind=command ⇒ OutboxFact`，误标 L0/L1/L3/L4 即 verify 红，见 `docs/rules/eventbus.md` §command dispatch）、`owner`、`topic="<domain>.commands.<name>"`（R8：`lifecycle=active` 时 **必填**；R9 `PerKindFieldScope` 允许 event ∪ command 使用 `topic`，出现在 command 是合法的，不会被拒）。runtime consumer/producer 的路由 key 从此 `topic` 读取，经 codegen 烤入 wrapper 常量，不在运行期重新派生。
- `*.schema.json`：command Request payload schema（typify 消费；R4 命令 kind 仅需 request）。

**codegen 产物**（generated/）：
- producer wrapper `pub async fn emit_async<E: CommandEmit>(emitter: &E, request: <Cmd>Request, tenant: vocab::TenantId, subject_id: E::SubjectId, actor: E::Actor, idempotency_key: Option<String>) -> Result<(), E::Error>`。baked `CONTRACT_ID`/`TOPIC`；`tenant` = typed RLS scope（**runtime 必填**，落 reserved `tenantId` envelope）；`subject_id` = bridge 绑定的 typed opaque subject（生产 impl 绑定 `diport::EnvelopeSubjectId`）；`actor` = bridge 绑定的 typed actor（生产 impl 绑定 `diport::OutboxActor`）；`idempotency_key` = 可选业务幂等键（`Some` ⇒ 稳定 `DispatchId`、同键二次 emit 被 claimer 拒；`None` ⇒ bridge mint 随机 `DispatchId`）。subject / actor 写入 outbox persisted metadata，不进 broker header / MQTT user property。返回 `Result<()>` 而非 `DispatchId`（`DispatchId` 由 runtime 层 `eventexec::command` mint + seal，不返回给业务）。无 `ctx` 参数。
- consumer wrapper `pub fn register_handler<Reg: CommandRegister, H, Fut>(registrar: &mut Reg, handler: H) -> Reg::Output`。baked `CONTRACT_ID`/`TOPIC`（无显式 group-name 绑定参数；group 由 registrar 内部携带）。无 `ctx` 参数。
- **typed authoring funnel**：业务 → policy-exclusive generated wrapper → `DirectCommandDispatcher` / `JournaledCommandDispatcher` → 不可外部构造的 reviewed DTO → provider store。event `EventEntry` 与 storage `StoredOutboxEntry` 均不能构造 command authoring DTO。

> **bridge 延迟落地**：`CommandEmit` / `CommandRegister` trait 定义在 `generated::command`，由组合根（bin / assembly crate）提供唯一 sanctioned impl（serde 编码 payload、mint `DispatchId`、转发到 `eventexec::command`）。该 bridge impl **随第一个真实命令消费域**一并接线，不在本 PR 的 mechanism-landing 阶段包含。首个域作者需实现的 bridge 接线细节见 `docs/rules/eventbus.md` §Command dispatch。

**治理**（xtask，Medium）：
- `COMMAND-JOURNAL-GENERATED-01#manifest-policy`：每 command schema 显式 required/none 且只生成对应 producer wrapper（Hard codegen）；`COMMAND-IMPL-ALLOWLIST-01#provider-set` 只扫描生产 provider impl/callsite 集合（Medium AST）。
- `COMMAND-IMPL-ALLOWLIST-01`：`impl CommandEmit`/`impl CommandRegister` 仅允许在组合根 `bins/`/`assemblies/`（sanctioned bridge/registrar）；非组合根 impl 即红（对齐 `DIPORT-IMPL-ALLOWLIST-01`）。
- `R15 CommandConsistency`：`kind=command ⇒ consistencyLevel=OutboxFact`（contract validate）。

> authoring Hard seal 由私有 `CommandSpec`、eventexec reviewed DTO 构造器与 event/command 分离类型共同提供；provider 集合事实保留 Medium，并具有 alias/glob red case。

## 2. saga 契约 kind（P9）

新增 `contracts/saga/<domain>/v1/`：
- `contract.toml`：`kind="saga"`、`consistencyLevel="WorkflowEventual"`(L3)、非空 `[saga]` 与 `[saga.retry]`（TOML 键 **camelCase**，`deny_unknown_fields`）。有序 step 必填 `name`、`receiptSchema`、forward/compensation effect scope、deterministic-key idempotency、receipt compensation input 与闭值 retry class；retry 必填 attempt/time 双预算、fixed/exponential backoff、初值/上限与 none/full jitter。
- codegen 派生唯一 receipt DTO、sealed definition/step/receipt marker、definition 专属 typestate cursor、完整 policy 与域分离/长度前缀 SHA-256 `ACTION_REGISTRY_GENERATION`。
- runtime 只有显式 `Transient` 且 step 允许时重试；attempt budget 包含首次调用，time budget 覆盖 action/backoff，backoff 饱和且 jitter entropy 可测试。
- 组合根经 `eventexec::TypedSagaActionFactory<Definition>::builder()` 注册 typed `eventexec::SagaStep<GeneratedStepMarker>`；注册消费 cursor，只有 `End` 有 `finish()`。wrong receipt、漏步、多步、重排或跨 definition step 均编译失败。

**治理**（xtask，SAGA-CONTRACT-01，对齐 saga.md §Governance）：
- 非空 saga/retry block + ≥1 step；step name = 合法 Rust 标识符且唯一；每步完整声明 receipt/effect/idempotency/compensation/retry 语义；compensation order 仅 reverse；consistencyLevel=L3；attempt/time/backoff/jitter 良构。
- 正/负 synthetic 用例（anti-vacuity）。

## 既有契约影响

- `contracts/event/identity/v1/`（identity.session-created，已 draft，consistencyLevel=OutboxFact L2）：P8 把 lifecycle 从 draft graduate 到 active（须有 subscriber + route group，经 bootstrap 验证），并完成 durable 接线扇出。
- 不新增手写共享 wire crate；跨域只经 contract（generated）。

## 扇出闭环（每个契约变更 PR 必查）

| 载体 | 必查 |
|------|------|
| contract schema | request/response/payload 字段、required、enum、format |
| generated | handler/client/types/registration glue |
| 域 crate metadata | Cargo.toml [dependencies] + contract.toml（role/field/consistencyLevel/verify target） |
| journey/fixture | 测试输入与验收路径 |
| governance/lint | 新增机器守卫（xtask / dylint / 类型系统） |
