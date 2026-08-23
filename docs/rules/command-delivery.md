# Command Delivery 规则

本文拥有 command contract、typed dispatch、durable journal 与 reconcile command seam。

## Contract 与 dispatch

- command contract 必须是 OutboxFact consistency，并声明 canonical topic、owner、request/response schema。
- generated `CommandEmit`/binding 是唯一 typed dispatch 入口；禁止 raw topic、untyped payload 或直接 publisher。
- command ID、tenant、schema identity、causation 与 deadline 从 generated/envelope 单源派生。
- transport acceptance 不是 application completion；completion 只能来自对应 typed fact/receipt。

## Direct 与 journaled

- direct dispatch 只允许明确的 non-durable/local topology；durable topology 必须使用 journaled dispatch。
- durable command journal 与业务 mutation/outbox intent 在同一 tenant transaction；不得先 publish 后补 journal。
- journal 状态、attempt、deadline 与 terminal outcome 为闭值；restart 从 durable state 恢复，不从内存 registry 猜测。
- ambiguous publish 保持同 command ID；不得创建 replacement command 掩盖未知结果。

## Registration

- active command 必须有唯一 typed consumer registration；omitted/disabled workflow 不得隐式激活。
- composition root 从 RuntimePlan/activation 构造 registration；contract lifecycle、topology 或 provider resolver
  不提供 activation default。
- 缺 consumer、重复 owner、topic/schema mismatch 或 store capability 不完整时启动 fail-closed。

## Reconcile seam

- reconcile 只经 transactional command seam 写 durable intent；不得直接调用 transport 或绕过 outbox fencing。
- command ID 必须包含资源/tenant/generation 的稳定幂等维度；framework 不解析业务 payload 代替该责任。
- stale generation 的 command 必须由 target/reconcile fencing 拒绝，不得用最后写入覆盖。

## Carrier

- Hard：generated typed bindings、closed command identity/state、private journal/registration constructors。
- Medium：contract validation、activation closure、journal/provider conformance 与 restart/fault proof。
