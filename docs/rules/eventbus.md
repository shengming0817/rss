# EventBus 规范

## 事件传输选型（topology-gated）

组合根（assembly / bin crate）经 `bootstrap::eventtransport::resolve(topo, cfg, required_domains)`
按 `Topology` 单源选型事件传输。**bootstrap 是服务层 crate**（`deny.toml` + `xtask layer-deps` +
cargo 依赖图三道门禁其依赖 `adapters/*`），故 resolver 是**纯策略函数**——做拓扑选型 + fail-closed
校验 + 凭据 redaction，返回**已校验决策** `ResolvedTransport::{Demo | Durable { per_domain }}`，
**不构造具体 adapter**；组合根 `match` 该决策再构造 `MemBus`（`adapters/memory`）/ amqp
（`adapters/amqp`）。`clk` 不入 eventtransport `resolve` 签名（传输决策不依赖时钟；replaydeps /
sagaprojectiondeps 才需 ctx/clk）：

- `Topology::Demo`（demo / memory）→ `ResolvedTransport::Demo` → 组合根构造进程内 in-mem bus（Publisher == Subscriber 同实例）。
- `Topology::DurableShared`（共享 broker）→ `ResolvedTransport::Durable { per_domain }`：每个 required 域
  一条已校验 URL，per-domain（`RSS_<DOMAIN>_AMQP_URL`）缺则**回退**共享 `RSS_AMQP_URL`。
- `Topology::DurableIsolated`（per-domain 隔离 broker）→ `ResolvedTransport::Durable { per_domain }`：每域
  **必须**有 per-domain URL，**禁回退**共享；配置含 shared URL 即 `IsolatedFallbackForbidden` fail-closed
  （防误用共享凭据），缺 per-domain URL 即 `MissingBrokerUrl{domain}` fail-closed。shared vs isolated 是不同
  安全策略，由不同 `Topology` 变体类型编码（非运行期约定）——对应 §per-domain 隔离安全模型。

durable 缺 broker URL **resolve 即返 `Err`**、组合根 fail-fast 拒绝启动，**不静默降级回 in-memory**（relay
必须把已持久化 outbox entry 发到 broker，而非进程内 bus，否则跨进程/重启丢事件）。env 读取在组合根（读后填
typed `TransportConfig`，domain key 自动规范化大写），resolver 保持纯函数可测；`MissingBrokerUrl{domain}`
含 domain + 应设 env 名（可操作，domain 名非 PII）。INVARIANT: TOPO-FAILCLOSED-01（`Result` + bootstrap
fail-fast，Medium）。

in-memory bus **仅** demo 决策可达（INVARIANT: TOPO-INMEM-SEAL-01）——sealing 落**组合根**（bootstrap
命名不到 adapter 类型，无法在本层 sealing）：

- 生产 bin（`bins/server` / `bins/rss`）经 `deny.toml` 连 `memory` adapter 都依赖不到 ⇒ in-mem bus
  类型层不可命名（**Hard，比「bootstrap 内 sealing」更强**；这是 in-mem 生产不可达的**主守卫**）。
- dev 组合根（`journeys` / `examples`，合法依赖 `memory` + `amqp`）：in-mem 仅经
  `match ResolvedTransport::Demo` 臂构造——**决策绑定纪律（Medium）**，把构造收束到已校验决策；
  dev root 仍能直接 `MemBus::new()` 绕过（类型层未封闭，dev-only 可接受），非编译期 Hard。

扩展新 broker（mqtt）：给 `ResolvedTransport` 加变体 + 组合根 `match` 加分支 + 暴露选择 env，不在本约束外另开旁路。
权威语义见 `bootstrap::eventtransport` 模块的 rustdoc。

## per-domain AMQP vhost/credential 隔离

per-domain URL（`RSS_<DOMAIN>_AMQP_URL`，DOMAIN 大写，缺省回退 `RSS_AMQP_URL`）携带 per-domain
凭据（user:pass）和 vhost，是 per-domain 凭据/vhost 隔离的 **seam**。**目标安全模型**（split 拓扑）：operator
为每个域 crate provision 独立 vhost/AMQP user，使每个进程只持有访问自身 broker 资源所需凭据、无法跨域
发布或消费事件。凭据由 broker operator 外部配置（非 framework 派生，无 HKDF/派生层，原因：AMQP broker
用户是外部对象，不存在 framework 可控的 master key）。

在 **split/per-domain 隔离拓扑**下，per-domain URL（`RSS_<DOMAIN>_AMQP_URL`）缺失必须**启动期 fail-closed**，不静默降级回共享 `RSS_AMQP_URL` / 共享凭据；非隔离（共享 broker）拓扑才允许回退 `RSS_AMQP_URL`。URL 含 user:pass，凭据 non-leak
由 typed redaction funnel（Medium）守。权威语义见 `bootstrap::eventtransport` 模块的 rustdoc。

## 复用层选型（claimer / nonce，topology-gated）

组合根的 outbox 消费幂等 claimer + 内部 listener service-token nonce store 同样经
`bootstrap::replaydeps::resolve(ctx, clk, topo)` 按 `Topology` 单源选型：demo/single-pod → in-memory；
real multi-pod → Redis-backed（client 作 ManagedResource），缺 Redis 配置启动期 fail-closed。两个
组合根（`bins/server` + `examples/ssobff`）复用同一 crate，不各自接线 in-memory 原语。`idempotency::InMemClaimer::new`
/ `authn::InMemoryNonceStore::new` 在这两个 root 内**仅** `bootstrap::replaydeps::resolve` 的 demo 分支可达——用
sealed resolver + `pub(crate)` 构造器从类型层封闭（Hard，编译期不可达）。bus / claimer / nonce 三 funnel 合起来确保组合根内每个 in-memory
单 pod 原语只经 sealed resolver 可达。权威语义见 `bootstrap::replaydeps` 模块的 rustdoc。

## saga 投影资源选型（journal / checkpoint / dead-letter / locker，topology-gated）

saga-journal CQRS 投影消费者的运行依赖经 `bootstrap::sagaprojectiondeps::resolve(ctx, clk, topo, cfg)`
按 `Topology` 单源选型（bootstrap::eventtransport / bootstrap::replaydeps 的第 3 个 sibling resolver）：saga journal（与
Coordinator 共用，再以 `journal::GlobalReader` 喂投影）+ `projection::OwnerCheckpointStore` +
`projection::DeadLetterStore`（poison-event sink）+ 投影 `TxRunner` + 每投影 leader `distlock::Locker`：

- demo/memory → `MemJournal` + `MemOwnerCheckpointStore` + `MemDeadLetterStore` + in-process locker + `DemoTxRunner`。
- postgres → PG `PgJournal` + PG `ProjectionCheckpointStore` + PG `SagaProjectionDeadLetterStore` + PG `TxManager`；单 pod in-process
  locker，real multi-pod → Redis-backed locker。PG pool / Redis client 由组合根注入
  （root 已持 pool 跑 migration，避免开第二个 pool）。
- fail-closed：postgres 缺 pool / multi-pod 缺 Redis → 启动期报错，**不静默降级**回 in-memory
  journal（丢重启事件）或 in-process locker（多副本各自当 leader 双投影）。

in-process 单 pod 锁原语 `distlock::InProcessDriver::new` 在 wiring 层（`bins/*` / 组合根 crate /
`examples/*`）**仅** `bootstrap::sagaprojectiondeps::resolve` 的 demo 分支可达——优先用 sealed resolver +
`pub(crate)` 构造器从类型层封闭 `adapters/*` 的 in-process driver（Hard，编译期不可达）。这是 bus / claimer / nonce 之外**第 4 个**
sealed 单 pod 原语 funnel。权威语义见 `bootstrap::sagaprojectiondeps` 模块的 rustdoc。

## ConsumerBase

所有 consumer 使用 `ConsumerBase`。它负责 Claim / Commit / Release、幂等、
退避重试和 DLX。业务 handler 只返回 `outbox::HandleResult`。

```rust
async fn handle(ctx: &Context, entry: outbox::Entry) -> outbox::HandleResult {
    if permanent {
        // reject 接 PermanentError（kind: Permanent | Invariant，排除 Transient）
        return outbox::HandleResult::reject(outbox::PermanentError::new(perm_kind));
    }
    if transient {
        // requeue 接 EngineError（不同类型；kind message 进 error_summary 落 DLX）
        let engine_err: consistency::error::EngineError = /* 瞬态因由 */;
        return outbox::HandleResult::requeue(engine_err);
    }
    outbox::HandleResult::ack()
}
```

`HandleResult` 不用裸构造（无公开字段构造路径）；业务代码使用 `ack`、`requeue`、`reject`
构造器，不手写 struct literal。`reject`/`requeue` 携带的 error kind 经 `HandleResult::error_summary()`
（`&'static str` const，PII-safe）随结果流到 ConsumerBase 的 DLX funnel 落日志（#1125），不再在 HandleResult
边界静默丢弃；更丰富的 per-delivery 扩展信息仍走 `DeliveryOutcome`，不污染业务结果。

## Disposition

| Disposition | 语义 | 行为 |
|-------------|------|------|
| Ack | 成功 | broker ack + receipt commit |
| Requeue | 瞬态失败 | 退避重试，预算耗尽后 reject |
| Reject | 永久失败 | broker nack/reject，进入 DLX |

`PermanentError` 只是错误分类，不自动把 Requeue 改成 Reject。

## Service required deps

service 必填依赖走构造器**必填参数**（非 `Option`）——缺失即编译错误。可选依赖在构造器内或 builder 给默认值，
累加式 builder 在 `build()` 末尾 validate。

## 订阅注册

订阅单源是域 crate 的 `Cargo.toml [dependencies]`（+ `contract.toml` 订阅声明）。codegen
（build.rs / proc-macro）从 metadata 派生注册代码；业务不手写平行 registry。订阅必须同时绑定
`ContractId`、`DomainId`、consumer group。

webhook、grpc serve、event subscribe 遵循同一范式：声明在 metadata，派生到
`generated`（`generated/`），运行时 registration 只消费派生结果。

## DLX 与幂等

- 永久错误进入 DLX。
- PG outbox claim 写入 lease/fencing token；所有状态回写以 lease 做 CAS。
- handler 不接触 lease；relay 或 subscriber write-back 负责透传。
- consumer group 命名必须稳定，避免重放时变成新消费者。

## Command dispatch

命令 dispatch 通过 generated typed API 和 Claimer 两阶段去重。producer 侧 key、
consumer 侧 claim、组合根 wiring 必须同源；不得新增裸字符串 dispatch。

producer 与 consumer **双侧**都收口到 codegen typed API：域 crate 经生成式
`<cmd>::emit_async` / `<cmd>::emit_async_from_idempotency_key`（per-command wrapper，bake
DispatchId + 锁 payload 为 `Request`）发命令，**不**直调 runtime `command::emit_async`
（裸 DispatchId）。三层嵌套 funnel：业务 → 生成 wrapper（锁两个 runtime emit 出口的调用方为 generated/runtime）
→ runtime `command::emit_async`（锁裸 `outbox::emit`/`Entry::new` 命令 topic 构造）→
`outbox::Entry::new`。consumer 侧对称收口（dispatch caller + register caller 两道）。wrapper 存在性由 codegen + golden（Hard）守；
caller funnel 用 sealed API + `pub(crate)` 可见性把裸 `emit` 出口封进 generated/runtime crate
（Hard，编译期强制，比 Go 的 type-aware scan funnel 更强）。符号/盲区见对应 rustdoc。

## Projection

projection consumer 必须 wire `bootstrap::with_consumer_base`。投影事件载体使用
`consistency::ProjectionEvent` trait；outbox entry 与 saga journal event 都实现该 trait。
retained journal、checkpoint、tailer 的完整约束以对应 rustdoc 和 ADR 为准。

outbox 派生投影的 durable journal（`projection_events`）由 emit 期同事务双写
装饰器写入：append 收口单一 sanctioned 路径（sealed 写入入口），
双写 topic 集从域 crate 的投影声明（`contract.toml` / proc-macro 标注）派生、非手写。
append-only 主守卫是 serving role 的 DB 引擎 `REVOKE UPDATE, DELETE`（migration 内 GRANT 收紧，Hard、不可绕）；
code-level `DELETE`/`TRUNCATE projection_events` 字面量另由 clippy lint（Medium，含 anti-vacuity + RED/GREEN fixture）守。
盲区/评级/符号以对应 rustdoc 为准。

## 命名与 payload

- stream / topic / command key 使用稳定 dotted 名称。
- event payload 是 JSON object，字段 camelCase。
- event metadata 的 trace、request、principal 信息由 outbox envelope 注入，业务
  不伪造 reserved metadata key。
