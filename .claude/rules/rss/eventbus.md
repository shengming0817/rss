# EventBus 规范

## 事件传输选型（topology-gated）

组合根（assembly / bin crate）的 `outbox::Publisher`/`outbox::Subscriber` 经
`eventtransport::resolve(clk, topo, cfg)` 按 `Topology` 单源选型：

- demo / memory 拓扑 → 进程内 `rss-runtime` 的 eventbus（Publisher == Subscriber 同实例）。
- postgres 拓扑 → 真实 broker（RabbitMQ，从 `RSS_<CELLID>_AMQP_URL`，缺省回退
  `RSS_AMQP_URL`）；缺 broker URL 启动期 fail-closed，**不静默降级回 in-memory**（relay
  必须把已持久化的 outbox entry 发到 broker，而非进程内 bus，否则跨进程/重启丢事件）。

in-memory bus **仅** demo 拓扑可达：**组合根**（`crates/cmd/corebundle` + `examples/ssobff`）
生产代码禁止直接依赖 `rss-runtime` 的 eventbus 模块——优先用 sealed port trait + `pub(crate)`
可见性从类型层封闭进程内 bus（替代 depguard `corebundle-no-direct-eventbus` /
`ssobff-no-direct-eventbus` 的 `COREBUNDLE-EVENTBUS-FUNNEL-01` 路径级 import ban）。扩展新
broker（mqtt）在 `eventtransport` 的 `BrokerKind` match 加分支 + 暴露选择 env，不在本约束外另开旁路。
权威语义见 `eventtransport` crate 的 rustdoc 与 ADR `202606131500-1940`。

## per-cell AMQP vhost/credential 隔离

per-cell URL（`RSS_<CELLID>_AMQP_URL`，CELLID 大写，缺省回退 `RSS_AMQP_URL`）携带 per-cell
凭据（user:pass）和 vhost，是 per-cell 凭据/vhost 隔离的 **seam**。**目标安全模型**（split 拓扑）：operator
为每个 cell provision 独立 vhost/AMQP user，使每个进程只持有访问自身 broker 资源所需凭据、无法跨 cell
发布或消费事件。凭据由 broker operator 外部配置（非 framework 派生，无 HKDF/派生层，原因：AMQP broker
用户是外部对象，不存在 framework 可控的 master key）。

**当前可运行边界（非目标态）**：distinct per-cell broker URL 尚不可启用——broker 侧 egress-only fail-closed（运行期
per-cell broker 隔离 blocked-by #2366，ingress N-router），故当前唯一可运行配置是所有 cell 用同一 URL（共享同一 AMQP
凭据）。注：per-cell DB 池/relay fan-out 已由 **#2341 独立落地**（distinct DSN → N keyed pool/relay 实例），但不解除
broker 的 distinct-URL fail-closed（DB 与 broker 资源不对称，二者不再 in-lockstep 解除）。当前**已生效**
的控制 = distinct broker-URL fail-closed + 凭据 non-leak（由 `AMQP-URL-REDACTION-FUNNEL-01` Medium typed funnel 守），
**非** live per-cell 凭据隔离。权威语义见 `eventtransport` crate 的 rustdoc 与 ADR `202606131500-1940`。

## 复用层选型（claimer / nonce，topology-gated）

组合根的 outbox 消费幂等 claimer + 内部 listener service-token nonce store 同样经
`replaydeps::resolve(ctx, clk, topo)` 按 `Topology` 单源选型：demo/single-pod → in-memory；
real multi-pod → Redis-backed（client 作 ManagedResource），缺 Redis 配置启动期 fail-closed。两个
组合根（corebundle + ssobff）复用同一 crate，不各自接线 in-memory 原语。`idempotency::InMemClaimer::new`
/ `auth::InMemoryNonceStore::new` 在这两个 root 内**仅** `replaydeps::resolve` 的 demo 分支可达——优先用
sealed resolver + `pub(crate)` 构造器从类型层封闭（替代 archtest `REPLAYDEPS-INMEM-FUNNEL-01`
调用级 AST 扫描）。bus / claimer / nonce 三 funnel 合起来确保组合根内每个 in-memory
单 pod 原语只经 sealed resolver 可达。权威语义见 `replaydeps` crate 的 rustdoc。

## saga 投影资源选型（journal / checkpoint / dead-letter / locker，topology-gated）

saga-journal CQRS 投影消费者的运行依赖经 `sagaprojectiondeps::resolve(ctx, clk, topo, cfg)`
按 `Topology` 单源选型（eventtransport / replaydeps 的第 3 个 sibling resolver）：saga journal（与
Coordinator 共用，再以 `journal::GlobalReader` 喂投影）+ `projection::OwnerCheckpointStore` +
`projection::DeadLetterStore`（poison-event sink，#2110）+ 投影 `TxRunner` + 每投影 leader `distlock::Locker`：

- demo/memory → `MemJournal` + `MemOwnerCheckpointStore` + `MemDeadLetterStore` + in-process locker + `DemoTxRunner`。
- postgres → PG `PgJournal` + PG `ProjectionCheckpointStore` + PG `SagaProjectionDeadLetterStore` + PG `TxManager`；单 pod in-process
  locker，real multi-pod → Redis-backed locker。PG pool / Redis client 由组合根注入
  （root 已持 pool 跑 migration，避免开第二个 pool）。
- fail-closed：postgres 缺 pool / multi-pod 缺 Redis → 启动期报错，**不静默降级**回 in-memory
  journal（丢重启事件）或 in-process locker（多副本各自当 leader 双投影）。

in-process 单 pod 锁原语 `distlock::InProcessDriver::new` 在 wiring 层（`crates/cmd/*` / 组合根 crate /
`examples/*`）**仅** `sagaprojectiondeps::resolve` 的 demo 分支可达——优先用 sealed resolver +
`pub(crate)` 构造器从类型层封闭 `adapter-*` 的 in-process driver（替代 archtest
`SAGA-PROJECTION-DEPS-INMEM-FUNNEL-01` 调用级 AST 扫描）。这是 bus / claimer / nonce 之外**第 4 个**
sealed 单 pod 原语 funnel。权威语义见 `sagaprojectiondeps` crate 的 rustdoc。

## ConsumerBase

所有 consumer 使用 `ConsumerBase`。它负责 Claim / Commit / Release、幂等、
退避重试和 DLX。业务 handler 只返回 `outbox::HandleResult`。

```rust
async fn handle(ctx: &Context, entry: outbox::Entry) -> outbox::HandleResult {
    if permanent {
        return outbox::HandleResult::reject(outbox::PermanentError::new(err));
    }
    if transient {
        return outbox::HandleResult::requeue(err);
    }
    outbox::HandleResult::ack()
}
```

`HandleResult` 不用裸构造（无公开字段构造路径）；业务代码使用 `ack`、`requeue`、`reject`
构造器，不手写 struct literal。subscriber 层扩展信息放 `DeliveryOutcome`，不污染业务结果。

## Disposition

| Disposition | 语义 | 行为 |
|-------------|------|------|
| Ack | 成功 | broker ack + receipt commit |
| Requeue | 瞬态失败 | 退避重试，预算耗尽后 reject |
| Reject | 永久失败 | broker nack/reject，进入 DLX |

`PermanentError` 只是错误分类，不自动把 Requeue 改成 Reject。

## Service required deps

service 必填依赖走构造器**必填参数**（非 `Option`）——缺失即编译错误，替代 gocell 的
`gocell:"required"` tag + 生成 `validateRequired()`。可选依赖在构造器内或 builder 给默认值，
累加式 builder 在 `build()` 末尾 validate。

## 订阅注册

订阅单源是 `slice.yaml contractUsages`（= crate `Cargo.toml` 的 `[dependencies]`）。codegen
（build.rs / proc-macro）从 metadata 派生注册代码；业务不手写平行 registry。订阅必须同时绑定
`ContractId`、`CellId`、consumer group。

webhook、grpc serve、event subscribe 遵循同一范式：声明在 metadata，派生到
`generated`（`crates/generated/`），运行时 registration 只消费派生结果。

## DLX 与幂等

- 永久错误进入 DLX。
- PG outbox claim 写入 lease/fencing token；所有状态回写以 lease 做 CAS。
- handler 不接触 lease；relay 或 subscriber write-back 负责透传。
- consumer group 命名必须稳定，避免重放时变成新消费者。

## Command dispatch

命令 dispatch 通过 generated typed API 和 Claimer 两阶段去重。producer 侧 key、
consumer 侧 claim、组合根 wiring 必须同源；不得新增裸字符串 dispatch。

producer 与 consumer **双侧**都收口到 codegen typed API：cell 经生成式
`<cmd>::emit_async` / `<cmd>::emit_async_from_idempotency_key`（per-command wrapper，bake
DispatchId + 锁 payload 为 `Request`）发命令，**不**直调 runtime `command::emit_async`
（裸 DispatchId）。三层嵌套 funnel：业务 → 生成 wrapper（`COMMAND-ASYNC-EMIT-CALLER-01`
锁两个 runtime emit 出口的调用方为 generated/runtime） → runtime `command::emit_async`
（`COMMAND-ASYNC-EMIT-FUNNEL-01` 锁裸 `outbox::emit`/`Entry::new` 命令 topic 构造）→
`outbox::Entry::new`。consumer 侧对称由 `COMMAND-ASYNC-DISPATCH-CALLER-01` +
`COMMAND-DISPATCH-REGISTER-CALLER-01` 锁。wrapper 存在性 codegen+golden Hard；caller funnel
在 Rust 优先用 sealed API + `pub(crate)` 可见性把裸 `emit` 出口封进 generated/runtime crate
（编译期强制，比 Go 的 type-aware scan Medium funnel 更强，解除 #2059 的 Go 天花板）。
符号/盲区见对应 rustdoc 与 ADR `202606040550-1044`。

## Projection

projection consumer 必须 wire `bootstrap::with_consumer_base`。投影事件载体使用
`cellvocab::ProjectionEvent` trait；outbox entry 与 saga journal event 都实现该 trait。
retained journal、checkpoint、tailer 的完整约束以对应 rustdoc 和 ADR 为准。

outbox 派生投影的 durable journal（`projection_events`，EPIC #1504）由 emit 期同事务双写
装饰器写入：append 收口单一 sanctioned 路径（`PROJECTION-EVENT-JOURNAL-APPEND-CALLER-01`），
双写 topic 集从 `slice.yaml` 投影声明派生、非手写（`PROJECTION-EVENT-JOURNAL-TOPIC-ALLOWLIST-DERIVED-01`）。
append-only 主守卫是 serving role 的 DB 引擎 `REVOKE UPDATE, DELETE`（migration 058，Hard、不可绕）；
code-level `DELETE`/`TRUNCATE projection_events` 字面量另由 clippy lint / 类型层守卫
（`PROJECTION-EVENT-JOURNAL-NO-DELETE-01`，含 anti-vacuity + RED/GREEN fixture）守。盲区/评级/
符号以对应 rustdoc 与 ADR `202606071600-1504` 为准。

## 命名与 payload

- stream / topic / command key 使用稳定 dotted 名称。
- event payload 是 JSON object，字段 camelCase。
- event metadata 的 trace、request、principal 信息由 outbox envelope 注入，业务
  不伪造 reserved metadata key。
