# Saga 引擎规则

本文件只保留当前行为约束。完整盲区、符号清单、评级证明写在 `xtask` 的 saga 不变量校验、
generated 类型、`eventexec` runtime、saga ADR 和 runbook 中；Markdown 不是 enforcement carrier。

## 架构语义

使用 saga 编排意味着 L3；L3 不等价于 saga。投影型、CQRS 型最终一致可以是 L3，
但不使用 saga 引擎。

## Governance

`kind: saga` contract 必须：

- 有非空 `[saga]` 与 `[saga.retry]` block，且至少一个 step。
- step name 可生成 Rust 标识符且唯一。
- 每个 step 声明 `receiptSchema`、`effectScope`、`compensationEffectScope`、
  `idempotencyClass = "deterministic-key"`、`compensationInput = "receipt"` 和闭值
  `retryClass = "never" | "transient"`。
- `compensationOrder` 只能是 `reverse`，consistency level 必须为 L3。
- retry 完整声明 `maxAttempts`、`timeBudgetMillis`、闭值 `backoff`、
  `initialBackoffMillis`、`maxBackoffMillis` 和闭值 `jitter`；`maxAttempts` 包含首次调用，
  backoff 上限不得小于初值。

不存在 optional、pure 或 legacy step 分支；`outputSchema`、`retryMillis` 和 `timeoutMillis` 不再是合法字段。
编排逻辑落在域 crate 的 saga 模块。

## Runtime policy

`cargo xtask codegen` 从完整 `[saga.retry]` 派生闭合 retry policy。attempt budget 与 time budget
同时生效；time budget 覆盖 action 和 backoff。fixed/exponential backoff 使用饱和计算，full jitter
使用 runtime 提供的 entropy；确定性 entropy 只用于可复现测试。

action failure 必须显式分类为 `Transient | Permanent | Invariant | OutcomeUnknown | OwnershipLost`。
只有 `Transient` 且当前 generated step 声明 `retryClass = "transient"` 才可重试；没有默认 retry
分支。`OutcomeUnknown` 与 `OwnershipLost` 均 fail-closed，不能伪装成普通 transient。前向预算耗尽
进入逆序补偿；补偿预算耗尽进入 dead-letter 路径。

## Definition identity 与精确解析

Saga definition identity 是 contract ID、definition version、schema digest 与
`ACTION_REGISTRY_GENERATION` 的完整四元组。action generation 使用域分离、长度前缀 SHA-256，覆盖
完整 retry policy 与有序 step 的全部执行语义；TOML key 排序不改变结果，任一执行语义变化必须改变结果。

- start 只能使用 assembly 选择的精确 identity；resume 只能读取 instance 已固定的 identity 后精确解析。
- instance 注册与存储必须携带完整 identity；同一 tenant/Saga UUID 使用不同 identity 注册时返回 typed conflict。
- unknown version、schema digest 或 action generation 返回明确 unsupported/degraded 结果；禁止回退 latest、
  相似 definition 或当前 contract。
- registry 是 generated identity 到 typed factory 的 immutable exact map，不提供 remove/retire API。
- Saga definition 的破坏式演进使用新版本目录和新 contract ID；旧 definition 必须保留。durable、跨副本
  retirement proof carrier 落地前只能 deprecated，不能删除。

## Typed step wrapper

`cargo xtask codegen` 对 saga payload 和每个 step `receiptSchema` 生成唯一 receipt DTO，并独占生成
sealed definition/step/receipt marker、definition 专属 typestate cursor 链、完整 step binding/policy、
action generation 与稳定 registry metadata。

业务实现 `eventexec::SagaStep<GeneratedStepMarker>`：

- `execute` 只能返回该 marker 唯一合法的 generated receipt DTO；
- `compensate` 必须接收同一 typed receipt；
- forward/compensation context 是不同 phase 类型，构造器保持 crate-private；
- wrong receipt、跨 definition step 或手工实现 sealed marker 均编译失败。

外部组合根只能通过 `eventexec::TypedSagaActionFactory<Definition>::builder()` 构造 factory。
每次 `register` 消费当前 cursor 并返回下一 cursor，只有 generated `End` 状态存在 `finish()`；漏步、
多步、重排和提前 finish 均编译失败，不保留运行期 mismatch 分支。raw erased action primitive 保持内部实现细节。

## Idempotency 与 receipt 边界

executor 是 opaque `SagaIdempotencyKey` 的唯一构造者；key 由 tenant、Saga UUID、完整 pinned
definition、step、phase-specific effect scope 派生，attempt 不参与，因此同一 effect 的所有 retry
共享同一 key。Debug 不得泄露 key material。这个 key 只把业务 effect 收敛到可探测、可去重的 scope；
Saga runtime 的执行边界仍是 **at-least-once**，不得据此声明 exactly-once execution/effect。

#1924 起，forward 成功必须把 canonical JSON receipt 经专用 `rss-saga-receipt` KMS purpose、Saga scope AAD
和 versioned keyed fingerprint 保护后，与匹配的 `ForwardCompleted` journal transition 在同一 tenant local
transaction 中提交。`SagaDurableStore::mutate(SagaDurableMutation::ForwardCompleted(..))` 是唯一 completion
写漏斗；不存在 plain journal/receipt 写 port。完整 scope 固定 tenant、Saga UUID、owner/contract、definition
version/schema/action generation、step、receipt schema 与 forward effect key，successful attempt 作为审计元数据
单独持久化。

同 scope、同 attempt、同 format、同 completed seq 且同明文内容的重复提交是 idempotent；任一维度或内容不同
都必须 conflict 并 fail-closed。commit result unknown 不能补偿、不能重放 effect，instance 进入 degraded。
加密、完整性校验或不支持的 format/version 错误不得降级成“缺失”。日志与 `Debug` 禁止输出 plaintext、token、
payment data、密钥或可逆 envelope。

#1925 起，executor 只通过一个 durable store 获取 instance、fenced lease、append-only journal、protected receipt
与 journal cursor checkpoint 的一致视图。cursor 是 journal 恢复位置，不是独立可推进的 checkpoint store；旧的
instance/journal/receipt 三 port、`SagaRuntimeLock` 和 Saga 专用 `OwnerCheckpointStore` 接线均不得保留或包装回流。
lease epoch/token 必须约束 intent、receipt、journal cursor 与 terminal status 的每次写入，stale holder 全部失败。

崩溃恢复协议保持闭合顺序：先按 pinned definition 加载 durable recovery state，再把 protected receipt 经
schema-version-aware typed hydrate 转为该 step 唯一合法的 generated receipt；不存在 receipt 时根据 durable intent
进入 typed effect probe。probe 只能得出 applied（携 receipt/reference）、not-applied 或 unknown：applied 走 fenced
completion，not-applied 才能在预算内取得下一次 permit，unknown 必须 durable 标记 operator-required，绝不进入
transient retry/backoff。完整性、保护、格式/upcast 失败同样是 typed operator reason，不得伪装成 missing。

每次外部 effect 必须遵循真实可达的 `intent → permit → effect → completion`：intent 在 effect 前 durable；permit
绑定当前 lease 与 intent；completion 原子提交 protected receipt、journal transition 和 cursor。operator repair
只能通过授权、审计且 fenced 的 typed decision 提交 confirmed-applied / confirmed-not-applied 结论；不能直接改表、
伪造 receipt 或把 unknown 改写成 retry。补偿沿用同一协议，并从 durable forward receipt hydrate typed input。

operator inspection/repair authorization 必须由受信 assembly capability 签发并绑定 caller、worker identity、tenant、
start-audit ID；repair authorization 还必须绑定 instance、expected reason 与 change ticket。provider 独占并按值消费
move-only claim，executor 不得取得或复制底层 `SagaLease`，也不得把裸 target 与另一份 proof 混配。

PostgreSQL terminal Saga aggregate 使用数据库权威 `terminal_at`；迁移固定 30 天 eligibility 与每批最多 1000
个 root 的 operator-invoked maintenance 函数，删除 root 后经 FK cascade 原子清理 instance/journal/receipt。
#1924 不注册周期 worker 或 probe，因此不承诺自动 retention SLA；该 live requirement 随 #1925 后的 #1926
production activation 一并闭合。runtime 与 operator 均无 caller-controlled retain 或 batch 参数。

## Activation 与 backend selection

- contract lifecycle 只描述 Saga definition；assembly manifest v2 `workflowActivations` 才描述 deployment
  activation。AssemblyLock v2 校验 definition identity，RuntimePlan v2 `workflowPlans` 携带 assembly-local
  闭值结果。`Topology`、环境配置和 resolver 均不是 activation/default truth。
- active Saga 的 requirement 集合固定为 typed actions、单一 durable store（内含 lease/journal/receipt/cursor）、
  dead-letter store、typed hydrate/probe/operator capability、worker 与 readiness probe。组合根必须先从已验证 plan
  得到 requirements，再按 exact set 闭合能力。
- `bootstrap::sagaprojectiondeps::resolve` 仅为 requirements 之后的 topology backend selector：它在 demo 与
  durable PostgreSQL backend 之间选择同一 `SagaDurableStore` capability，不选择 Saga 是否激活，也不把
  lease/journal/receipt/cursor 拆成多个 runtime owner；它不证明 typed action、dead-letter、hydrate/probe/operator、
  worker 或 readiness probe 已存在。
- production Saga registry/worker 只能消费 sealed `WorkflowRuntimePlan` 借出的 `SagaRuntimeView`；generated
  definition 存在不等于 activation。omitted/disabled Saga 不得注册 action、store、worker 或 probe，active
  Saga 缺少任一 requirement 必须在 provider 初始化前 fail-closed。

## 构造器

`eventexec` crate 的 saga 模块必填依赖走构造器必填位置参（非 `Option`），缺失即编译错误；异步基础设施
port 可在组合根经唯一 dyn wrapper 注入，但不得拆回 legacy 三 store、运行期 lock/checkpoint，也不得提供
no-op/default durable store、hydrator、probe 或 operator capability。
`SagaExecutorDeps::new` 必须接收 typed registry/factory，禁止外部注入 raw erased factory。
`SagaExecutorConfig` 必须从同一 generated definition 派生完整 identity 和 retry policy，禁止 raw spec、
无策略 constructor、builder option 或兼容 shim。

## Worker runtime

saga background worker 是生产运行形态，不替代 direct executor primitive：

- runnable listing 必须返回 instance 固定的完整 definition identity；worker 禁止从裸 owner/contract id
  猜测 definition。
- worker 只做 polling/orchestration：`SagaTenantSource` 按稳定 tenant ID keyset cursor 返回 runnable tenant 页，
  durable store 在 tenant scope 下列
  `Ready` / `Running` / `Compensating` 且 lease 空闲或过期的 instance；`OperatorRequired` 不属于 runnable。
- unresolved observation 是独立的 identity-wide current-state 投影，不占 runnable page 配额。worker 只在 discovery
  成功后推进 cursor；单个 tenant 执行失败不能阻止访问后续页，页尾 `next=None` 后下一 tick 从头开始。
- worker 对 `Ready` 调 `run`，对 `Running` / `Compensating` 调 `resume`；正确性由同一 durable store 的 lease
  fencing + intent/completion CAS 保证，listing 只是 advisory。
- readyz probe 名从 identity 单源派生：`saga_executor:<owner>__<contract_slug>`，不带 `_ready`。
- 无 live saga contract/factory registration 时不得注册假 worker 或假 probe。
- health 语义：无任务/成功/业务失败但已 durable 记录为 Healthy；当前 unresolved backlog 与 transient source/store
  故障每 tick 重算，clean tick 必须恢复 Healthy；journal/definition/identity 等进程内不可恢复 invariant 才 latch
  Degraded；worker 停止或 panic 为 Unhealthy。

`billing.checkout` 只允许作为 draft generated/test fixture。production assembly、runtime view、DB instance、
worker、probe 和 route 必须保持 omitted；不得新增 billing crate/provider 或以 fixture 宣称 production capability。

## 参考

- 扇出规则：`docs/rules/contract-fanout.md`
