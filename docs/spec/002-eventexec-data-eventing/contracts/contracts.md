# Phase 1 Contracts: 新增契约形态

本 feature 主体是「在冻结签名内填 body」，绝大多数接口已是冻结的 Rust trait/type（见 spec / data-model）。新增**跨边界 wire 契约**仅两处 kind，均走 `contracts/` 声明 → `generated/` 派生 + 扇出闭环。

## 1. command 契约 kind（P12）

新增 `contracts/command/<domain>/v1/`：
- `contract.toml`：`id="<domain>.<command>"`、`kind="command"`、`consistencyLevel="OutboxFact"`(L2) 或 L3、`owner`。command **无 per-kind 必填字段**（README R8）；`topic`/`delivery` 仅属 event，出现在 command 会被 R9（`PerKindFieldScope`）拒——runtime command topic 由 generated/runtime 从 command id 派生，鉴权/路由经生成 wrapper + runtime 语义承载，不在 contract.toml 复用 event 字段。
- `*.schema.json`：command Request payload schema（typify 消费；R4 命令 kind 仅需 request）。

**codegen 产物**（generated/）：
- producer `<cmd>::emit_async(ctx, payload) -> DispatchId` wrapper（bake DispatchId + payload → runtime `command::emit_async`）。
- consumer `<cmd>::register_handler(ctx, handler_fn)` wrapper（绑定 group name）。
- **triple funnel**：业务 → 生成 wrapper → runtime `command::emit_async` → `outbox::Entry::new`。禁裸调 runtime emit（codegen 锁出口）。

**治理**（xtask，COMMAND-SYMMETRY-01）：每 command schema 有对应 emit + register wrapper；emit 源有对应 consumer handler（双侧对称）；无手写裸 emit 出口。

## 2. saga 契约 kind（P9）

新增 `contracts/saga/<domain>/v1/`：
- `contract.toml`：`kind="saga"`、`consistencyLevel="WorkflowEventual"`(L3)、非空 `[saga]` block（TOML 键 **camelCase**，`deny_unknown_fields`）：`steps=[{name, outputSchema}...]`（≥1）+ `compensationOrder="reverse"` + `retryMillis`/`timeoutMillis`（`u64` 毫秒，**block 级、非 per-step**）。完整形态见 `xtask` 解析测试 `VALID_SAGA` 与 `contracts/README.md` §[saga]。
- step `outputSchema` 引用 `*.schema.json`。

**治理**（xtask，SAGA-CONTRACT-01，对齐 saga.md §Governance）：
- 非空 saga block + ≥1 step；step name = 合法 Rust 标识符且唯一；每步声明 output schema；compensation order 仅 reverse；consistencyLevel=L3；retry/timeout 合法非负 duration。
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
