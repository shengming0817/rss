# ADR-001：关闭逆序编排（无 async Drop）

- 状态：Accepted（spike RW-G0.6 接缝冻结）
- 日期：2026-06-21
- 关联：Issue #996（RW-G0.6 spike）· Epic #991（最大并行迁移）
- 阶段：G0「接缝冻结」——重写顺序见 `docs/migration-from-gocell/gocell-rewrite-sequence.md` P2/§三
- 落地：`crates/bootstrap/src/shutdown.rs`

> 本 ADR 是 RSS workspace 的首个架构决策记录，确立**进程关闭时资源按依赖逆序 await 关干净**的范式。
> 这是 G0 阶段要冻结的边界之一（rewrite-sequence §「历史里代价最大的晚做」：边界越晚改越贵）。

---

## 1. 背景与问题

进程关闭时，已注册的运行时资源——DB pool、outbox relay、event consumer、后台 worker、HTTP
listener 等——必须按**依赖反序**依次关闭：依赖别人的先关，被依赖的后关。例如先注册 DB pool、
再注册依赖它的 outbox relay，关闭时必须**先关 relay（让它 flush 完最后一批写）再关 pool**，
否则 pool 先关、relay 仍在写 → 写失败 / 连接泄漏。

Go（GoCell 原实现）靠 `defer` 的 LIFO 语义天然表达：`defer db.Close()` 后 `defer relay.Close()`，
退栈顺序即逆序。**Rust 没有等价物**：

- `Drop::drop(&mut self)` 是**同步**的，不能 `.await`——而关闭一个资源往往要 await（drain 队列、
  flush、等后台 task join）。
- `Drop` 的执行顺序是字段/作用域声明的逆序，但**无法表达「await 关干净后再关下一个」**，也无法
  聚合关闭错误、施加超时、隔离 panic。

因此 RSS 不能靠 RAII `Drop` 做关闭编排，必须由 `bootstrap`（组合根）**显式驱动**一个注册栈，
按 LIFO 顺序 `.await` 每个资源的异步关闭。本 ADR 定该范式。

---

## 2. 决策

引入 `crates/bootstrap/src/shutdown.rs`，三件套：

1. **`ManagedResource` trait**（`async_trait`，`Send + Sync + 'static`）——资源关闭契约：
   `async fn shutdown(&self) -> Result<(), ShutdownError>` + `fn name(&self)` + `fn shutdown_timeout(&self)`。
   失败用 typed `ShutdownError`（本 crate `thiserror`）而非 `anyhow`：`Display` 仅安全摘要常量、
   原始错误仅作内部 `source`——公共 port 不暴露 `anyhow`、不泄漏 adapter runtime 信息（PII 边界）。
2. **`ShutdownStack`**——注册栈：`Vec<Arc<dyn ManagedResource>>` 按注册顺序排列，持有 root
   `CancellationToken`。token 经 `register_with_token(|token| …)` funnel 由本 stack 派生注入；
   无后台 task 资源经 `register_detached(…)`（无 `pub child_token`，发放即收口于注册）。
3. **两阶段逆序驱动器**——`ShutdownStack::shutdown(self)` / `shutdown_within(self, total_budget)`：
   - **阶段 1 · 广播（并发、无序）**：`root_token.cancel()`，所有经 `register_with_token` 注入的
     后台 task 同时感知关闭、开始自行退出。
   - **阶段 2 · 逆序确认（串行、有序）**：按注册逆序（LIFO）逐个 `await` 每个资源的 `shutdown()`，
     per-resource 超时 + panic 隔离，**遇错继续**，聚合所有失败返回 `Vec<ResourceShutdownError>`。
   - **整体预算（可选）**：`shutdown_within` 附加 cancel-safe 总预算上界（单一共享 deadline），
     预算耗尽时剩余资源记 `BudgetExhausted` 由驱动器自身聚合——**不**交外层 `timeout`。

### 2.1 为什么两阶段都要

仅阶段 1（cancel 广播）不保证**资源释放顺序**：cancel 让所有 task 同时开始退出，但 outbox relay
可能晚于它依赖的 DB pool 关闭完成 → 仍有「pool 已关、relay 还在写」窗口。
仅阶段 2（LIFO await）则后台 task 不知道「系统要关了」，`shutdown()` 可能要傻等 task 自然结束。

> 分工：**cancel 让各 task 快速进入退出路径**（并发广播），**LIFO await 确认每层资源按依赖反序
> 安全释放**（有序）。源码论证见 §6 对标。

### 2.2 单次性：消费 self（编译期 Hard）

`shutdown(self)` **消费** `ShutdownStack`：double-shutdown 与「关闭后再注册」在类型层**不可表达**
（值已被 move）。这比 Go/fx 用运行时状态机 + mutex 保证幂等（Medium）更强——是编译期 Hard 不变式，
契合 AI-robust 章程「优先把约束上移到编译期」。故本范式**不设**运行时关闭状态机。

---

## 3. 不变式

| ID | 不变式 | 强度 | 载体 |
|----|--------|------|------|
| `SHUTDOWN-SINGLE-SHOT-01` | double-shutdown / 关闭后注册不可表达 | **Hard** | `shutdown(self)` 消费 self（move 语义）——违反在类型层不可表达 |
| `SHUTDOWN-LIFO-ORDER-01` | 关闭顺序 = 注册顺序逆序（后注册先关，被依赖后关） | Medium | `Vec` + `.rev()` 代码结构 + 测试断言（类型系统不阻止改回正序） |
| `SHUTDOWN-CONTINUE-ON-ERROR-01` | 任一资源失败/超时/panic 必须**继续**关后续，禁 fail-fast | Medium | 驱动循环无 early-return + 测试断言（类型系统不阻止未来加 `?`） |
| `SHUTDOWN-ERROR-AGGREGATE-01` | 所有 per-resource 失败聚合返回 `Vec`，不丢弃 | Medium | `Vec` 收集 + `#[must_use]` + 测试断言 |
| `SHUTDOWN-TIMEOUT-BOUNDED-01` | 每个资源关闭有 per-resource 超时上界 | Medium | `tokio::time::timeout(budget, …)` 包裹 + 测试断言 |
| `SHUTDOWN-PANIC-ISOLATE-01` | 下游资源 `shutdown` panic 被隔离，不击穿驱动循环 | Medium | `tokio::spawn` + `JoinError` 捕获 + 测试断言 |
| `SHUTDOWN-NO-PANIC-ON-ERROR-01` | 关闭路径自身绝不 `panic!`/`unwrap`/`expect`，失败走 `Result` | Medium | clippy `panic`/`unwrap_used`/`expect_used` deny |
| `SHUTDOWN-TOKEN-FUNNEL-01` | 后台 task 取消 token 只能经 `register_with_token` 由本 stack 派生注入；无 task 资源经 `register_detached` 显式声明 | Medium→ | **无 `pub child_token`**（裸 token 发放无公开入口，可见性收口，编译期）+ 两入口覆盖全部注册路径。资源仍可忽略注入 token（sealed handle 才 Hard，见 §5 follow-up） |
| `SHUTDOWN-BUDGET-CANCEL-SAFE-01` | 整体预算由驱动器内部 `shutdown_within` 承担（cancel-safe），不交外层 `timeout` | Medium | 驱动器内单一共享 deadline + `BudgetExhausted` 聚合 + 测试断言；rustdoc 危险说明禁外层 timeout（footgun 防护） |

> 强度说明（AI-robust）：仅 `SHUTDOWN-SINGLE-SHOT-01` 是 **Hard**——消费 self 让违反在类型层
> 不可表达。`SHUTDOWN-TOKEN-FUNNEL-01` 的 token 发放经 `pub(crate)` 可见性收口于注册 funnel
> （编译期半 Hard：外部无法裸取 token），但「资源构造时是否真用注入 token」仍需 sealed handle 才
> 能编译期锁死（§5 follow-up），故记 **Medium→**。其余靠代码结构 + 测试断言守，违反**可表达**但
> CI 测试会抓 → **Medium**，不虚标为 Hard。把 LIFO / continue-on-error 上移到编译期（如
> typestate）成本高于收益，登记为可选 follow-up。
>
> 红线（运维语义，不可降级，与强度评级无关）：关闭路径**绝不能** panic-on-error、**绝不能**漏关资源、
> 超时**必须**有界。「部分失败必须继续 + 聚合错误」是 §1 依赖泄漏问题的直接对策。
>
> `ManagedResource` **不 sealed**：各 adapter 实现它经组合根注入是预期用例（对照 `Domain` 生命周期
> trait），故不封闭——与 domain-patterns「sealed port」阻止外部伪造的场景不同。
>
> 测试 carve-out 登记（ADR registry 尚未建立，暂记于此）：`shutdown.rs` 测试 mock 用 item-level
> `#[allow(clippy::panic)]` 刻意 panic 以验证 `SHUTDOWN-PANIC-ISOLATE-01`；ADR registry 落地后迁入。

---

## 4. 接口（范式）

```rust
#[async_trait::async_trait]
pub trait ManagedResource: Send + Sync + 'static {
    fn name(&self) -> &str;
    async fn shutdown(&self) -> Result<(), ShutdownError>;       // typed，非 anyhow
    fn shutdown_timeout(&self) -> Duration { DEFAULT_SHUTDOWN_TIMEOUT } // 默认 30s
}

// typed 关闭错误：Display 安全摘要常量，原始错误仅作内部 source（PII 边界，不暴露 anyhow）。
pub struct ShutdownError { /* source: Box<dyn Error + Send + Sync> */ }
impl ShutdownError { pub fn new<E: Error + Send + Sync + 'static>(source: E) -> Self; }

pub struct ShutdownStack { /* root_token, resources */ }

impl ShutdownStack {
    pub fn new(root_token: CancellationToken) -> Self;     // root 必填（构造器位置参）
    // 有后台 task：token 由本 stack 派生、闭包内经构造器注入（注册即收口，无 pub child_token）。
    pub fn register_with_token<F>(&mut self, make: F)
        where F: FnOnce(CancellationToken) -> Arc<dyn ManagedResource>;
    // 无后台 task / 不接广播：显式 no-token 入口（声明有意，而非忘记接线）。
    pub fn register_detached(&mut self, resource: Arc<dyn ManagedResource>);
    pub async fn shutdown(self) -> Vec<ResourceShutdownError>;             // 两阶段；空 = 全成功
    pub async fn shutdown_within(self, total_budget: Duration)            // 同上 + cancel-safe 整体预算
        -> Vec<ResourceShutdownError>;
}

// thiserror：Failed(ShutdownError) | TimedOut(Duration) | Panicked | BudgetExhausted，
//            包成 ResourceShutdownError{name, kind}
```

### 4.1 消费侧接线范式（P2 落地，本 spike 仅冻结接缝）

组合根（`bins/server` / `assemblies`）按依赖顺序注册，信号到达时驱动：

```text
// 注册（先注册 = 被依赖 = 最后关）：
//   1. DB pool        2. outbox relay(依赖 pool)   3. event consumer
//   4. background worker      5. HTTP listener(最后注册 → LIFO 最先关，先停外部流量)
//
// 有后台 task 的资源经 register_with_token 注入 token；纯 drain 资源经 register_detached：
//   stack.register_with_token(|tok| Arc::new(OutboxRelay::new(pool.clone(), tok)));
//   stack.register_detached(Arc::new(SyncBuffer::new()));
//
// 驱动（P2 实现）：
//   tokio::select! { _ = sigterm() => {}, _ = ctrl_c() => {} }            // 感知
//   let failures = stack.shutdown_within(grace - buffer).await;           // 两阶段 + 整体预算
//   if !failures.is_empty() { for f in &failures { error!(%f) } exit(1) }
```

token 发放并入注册 funnel（`register_with_token(|token| …)`）：资源经**构造器注入** token
（RSS「必填依赖走构造器位置参」），闭包先收到本 stack 派生的 child token 再构造资源——
「该资源后台 task 监听本 stack 广播」由注册路径强制，**无 `pub child_token`** 裸入口（早先把
`register`/`child_token` 拆开依赖调用方记得先取 token，是 Soft 约定；funnel 把它收口到编译期可见性，
见 §3 `SHUTDOWN-TOKEN-FUNNEL-01`）。无后台 task 的资源经 `register_detached` 显式声明不接广播。

实现者若需在 `shutdown(&self)`（`&self`，因驱动器 `Arc` 持有以 spawn 隔离 panic）中消费内部
mut 状态（drain sender / take oneshot），用 `Mutex<Option<Inner>>` 包装后 `take()`（见 trait rustdoc）。

---

## 5. 后果与权衡

**收益**

- 关闭顺序、错误聚合、超时、panic 隔离全部显式可测，替代 Go `defer` 的隐式 LIFO。
- 接缝冻结：`ManagedResource` 是各 adapter（postgres / amqp / relay …）将实现的稳定 port，
  P3+ 资源接入时不需重开此接缝——故关键约束（typed 错误、token 发放、整体预算）**在冻结时一并收口**，
  不留给调用方记忆或事后破坏式补：取消 token 经 `register_with_token` funnel 发放（无裸 `child_token`）、
  关闭失败用 typed `ShutdownError`（公共 port 不暴露 `anyhow`、Display 安全摘要）、整体预算经 cancel-safe
  `shutdown_within` 承担。
- 单次性是编译期 Hard（消费 self）；其余不变式 Medium，由代码结构 + 测试断言 + clippy deny 守（见 §3）。

**代价 / 偏离**

- per-resource panic 隔离用 `tokio::spawn`，要求 `ManagedResource: Send + Sync + 'static`
  并 `Arc` 持有——比裸 `&dyn` 重，但换来「一个 adapter panic 不漏关其它资源」的零信任鲁棒性。
- 超时后 hung task 被 `abort()` 后**不 `await` 等其 join** 即继续下一个资源——刻意为之以保
  `SHUTDOWN-TIMEOUT-BOUNDED`：尊重取消的 task 会在 `abort` 后即刻 drop 释放句柄；忽略取消的
  阻塞型 task 若 `await` 会重新无界等待、破坏超时上界，故不 await，由进程退出回收。代价是被依赖
  资源关闭前可能存在极短的「hung task 仍持旧句柄」窗口（cancel 广播已令其进入退出路径，已最小化）。
- 超时后 hung task `abort` 不强杀进程——与 k8s `terminationGracePeriodSeconds` 语义一致
  （grace 后 SIGKILL 是 kubelet 职责）。N 个资源串行 LIFO、各自最坏 `DEFAULT_SHUTDOWN_TIMEOUT`(30s)，
  per-resource 累加最坏 ≈ N×30s 可能超过 grace period。**封顶**：`shutdown_within(total_budget)`
  以 cancel-safe 单一共享 deadline 把**总**耗时封在 `total_budget` 内（P2 注入 `< grace − buffer`）；
  预算耗尽时剩余资源记 `BudgetExhausted` 由驱动器自身聚合，**不**交外层 `timeout`（外层取消会在 LIFO
  中途 drop future、中断后续关闭——见 §3 `SHUTDOWN-BUDGET-CANCEL-SAFE-01`）。重 I/O 之外资源仍应
  `shutdown_timeout()` 调小，30s 默认对齐 k8s grace 默认。
- `shutdown_within` 预算耗尽时，**正在关闭**的当前资源其 spawn task 随 future drop 而 detach（非
  `abort`，因驱动器已不持其句柄），由进程退出回收——与上条「超时 hung task 不 await join」同一权衡
  （关闭路径，进程即将退出）。整体预算用单一共享 deadline 而非 per-resource 余额分配，因后者需测
  per-resource elapsed（`Instant` 被 clippy 禁、待注入 `Clock`），属下方延后项。

**已延后（非本 spike 范围，登记去向，非藏 TODO）**

| 延后项 | 去向 | 理由 |
|--------|------|------|
| SIGTERM/SIGINT 信号驱动 + k8s grace period 接线 | P2 装配骨架（rewrite-sequence P2） | 属进程组合根接线，本 spike 只冻结 `ShutdownStack` 接缝 |
| 真实资源 adapter（DB pool / relay …）实现 `ManagedResource` | P3+（随各 adapter 落地） | 资源本体在后续阶段 |
| 关闭时延 metric / 耗时测量（注入 `Clock`） | 待 `primitives::Clock` 落地后接入 | `primitives` 当前为空骨架；超时强制已用 `tokio::time`（运行时时钟，测试经 `start_paused` 控制），不裸调 `Instant`（clippy 禁） |
| 整体预算的 **grace-period 值注入**（机制已落地为 `shutdown_within`） | P2（与信号 grace period 一并） | 机制（cancel-safe 单一共享 deadline + `BudgetExhausted` 聚合）本 spike 已冻结于驱动器；仅「`total_budget = grace − buffer`」值来自进程级接线层 |
| 整体预算的 **per-resource 余额精化**（`min(per_resource, 全局剩余)`，替代单一共享 deadline） | 待 `primitives::Clock` 落地（可选优化） | 需测 per-resource elapsed，`Instant` 被 clippy 禁；当前单一共享 deadline 已满足「总耗时封顶」语义，余额分配是后续可选精度提升 |
| 关闭错误日志经 `secure::redact_error` 清洗（observability.md §redaction） | 随 P3+ 真实 adapter 接入 + `secure` redaction 模块落地 | typed `ShutdownError` 已落地（`anyhow` 移出公共 port、Display 安全摘要、原始 source 仅内部保留**当前不打印**）；`secure` 当前为空骨架，redaction **调用**待其落地后接入，届时业务错误分支改为 `warn!(error = %secure::redact_error(&source))` |
| `ManagedResource` 资源构造时**强制使用**注入 token（sealed resource handle，把 `SHUTDOWN-TOKEN-FUNNEL-01` Medium→ 升 Hard） | 可选 follow-up（GitHub Issue） | 当前 funnel 收口 token *发放*（无裸 `child_token`），但资源仍可在构造中忽略注入 token；sealed handle 才能编译期锁死「后台 task 必用本 stack token」，成本高于本 spike 收益 |

> Clock 边界：超时**强制**由 `tokio::time::timeout`（runtime 时钟）承担，可经 `tokio::time::pause`
> 确定性测试；耗时**测量**（日志/metric）未来用注入 `Clock`。二者分层、不冲突。

---

## 6. 对标（真实拉源码）

- `ref: uber-go/fx internal/lifecycle/lifecycle.go@master` —— LIFO `Stop` 循环（`allHooks[numStarted-1]`
  倒序）+ best-effort 继续（`// keep going after errors`）+ `multierr.Combine` 聚合 + `numStarted`
  只关已启动的。RSS 的「只关已 `register` 的」由 `Vec` 位置语义等价表达。
- `ref: tokio-rs/tokio tokio-util/src/sync/cancellation_token.rs@master` + `task/task_tracker.rs@master`
  —— `cancel()` O(1) 树形广播（并发无序）vs `TaskTracker.wait()` 并发 join（无 LIFO）。印证「广播 ≠ 有序关闭」，
  二者分工。
- `ref: oxidecomputer/dropshot dropshot/src/server.rs@main` + `omicron sled-agent/src/services.rs@main`
  —— Rust `close()` 串行有序关闭 + `Vec<(name, Box<Error>)>` 聚合 + drain（先发信号、释放 waitgroup、
  等 handler 收敛）。
- `ref: hyperium/hyper-util src/server/graceful.rs@master` + `tokio-rs/axum examples/graceful-shutdown@main`
  —— `with_graceful_shutdown` 连接 drain；HTTP listener 是「**最后**注册、LIFO **最先**关」的资源（先停外部流量，与 §4.1 注册示例一致）。
- `ref: tokio-rs/tokio tokio/src/runtime/task/harness.rs@master` —— `panic::catch_unwind` → `JoinError`，
  印证 `tokio::spawn` 隔离下游 panic 的正确性。
- `ref: Finomnis/tokio-graceful-shutdown tests/integration_test.rs@main` —— `#[tokio::test(start_paused)]`
  + `sleep(Duration::MAX)` 做确定性超时测试（不靠真实时间），本 PR 的超时测试采此法。

---

## 7. Implementation matrix

| 变更 | contract | generated | crate | tests | docs |
|------|----------|-----------|-------|-------|------|
| `ManagedResource` + `ShutdownStack` + 两阶段 LIFO 驱动器 | —（非 wire 契约，进程内 port） | — | `crates/bootstrap/src/shutdown.rs`、`lib.rs`、`Cargo.toml` | `shutdown.rs` `#[cfg(test)]` 13 例（逆序/继续-聚合/超时/panic 隔离/取消/空/单/全错 + token funnel/typed-error PII 边界/整体预算耗尽×2/充裕预算） | 本 ADR |
| token funnel（`register_with_token`/`register_detached`，移除 `pub child_token`/`register`） | — | — | `crates/bootstrap/src/shutdown.rs` | `cancellation_broadcast_*`（funnel 注入）+ 全测试经 `register_detached` | 本 ADR §3/§4.1 |
| typed `ShutdownError`（移除公共 port 的 `anyhow`，drop `anyhow` 依赖） | — | — | `crates/bootstrap/src/shutdown.rs`、`Cargo.toml` | `shutdown_error_display_is_safe_summary_only`（PII 边界） | 本 ADR §2/§5 |
| `shutdown_within` 整体预算（cancel-safe，`BudgetExhausted`） | — | — | `crates/bootstrap/src/shutdown.rs` | `shutdown_within_*` 3 例 | 本 ADR §3/§5 |
| `tokio-util` 入 workspace 依赖 | — | — | 根 `Cargo.toml [workspace.dependencies]` | cargo-deny bans/licenses ok | 本 ADR §5 |

> 本 ADR 不涉及跨域 wire 契约（无 schema/generated 扇出）：`ManagedResource` 是进程内关闭 port，
> 经组合根注入，跨域仍只走 contract。
