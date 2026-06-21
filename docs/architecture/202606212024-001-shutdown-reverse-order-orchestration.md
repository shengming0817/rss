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
   `async fn shutdown(&self) -> anyhow::Result<()>` + `fn name(&self)` + `fn shutdown_timeout(&self)`。
2. **`ShutdownStack`**——注册栈：`Vec<Arc<dyn ManagedResource>>` 按注册顺序排列，持有 root
   `CancellationToken`。
3. **两阶段逆序驱动器**——`ShutdownStack::shutdown(self)`：
   - **阶段 1 · 广播（并发、无序）**：`root_token.cancel()`，所有经 `child_token()` 派生的后台
     task 同时感知关闭、开始自行退出。
   - **阶段 2 · 逆序确认（串行、有序）**：按注册逆序（LIFO）逐个 `await` 每个资源的 `shutdown()`，
     per-resource 超时 + panic 隔离，**遇错继续**，聚合所有失败返回 `Vec<ResourceShutdownError>`。

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

> 强度说明（AI-robust）：仅 `SHUTDOWN-SINGLE-SHOT-01` 是 **Hard**——消费 self 让违反在类型层
> 不可表达。其余靠代码结构 + 测试断言守，违反**可表达**但 CI 测试会抓 → **Medium**，不虚标为 Hard。
> 把 LIFO / continue-on-error 上移到编译期（如 typestate）成本高于收益，登记为可选 follow-up。
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
    async fn shutdown(&self) -> anyhow::Result<()>;
    fn shutdown_timeout(&self) -> Duration { DEFAULT_SHUTDOWN_TIMEOUT } // 默认 30s
}

pub struct ShutdownStack { /* root_token, resources */ }

impl ShutdownStack {
    pub fn new(root_token: CancellationToken) -> Self;     // root 必填（构造器位置参）
    pub fn child_token(&self) -> CancellationToken;        // 派生给资源后台 task（构造器注入）
    pub fn register(&mut self, resource: Arc<dyn ManagedResource>); // 注册顺序 = 依赖顺序
    pub async fn shutdown(self) -> Vec<ResourceShutdownError>;      // 两阶段；空 = 全成功
}

// thiserror：Failed(anyhow) | TimedOut(Duration) | Panicked，包成 ResourceShutdownError{name, kind}
```

### 4.1 消费侧接线范式（P2 落地，本 spike 仅冻结接缝）

组合根（`bins/server` / `assemblies`）按依赖顺序注册，信号到达时驱动：

```text
// 注册（先注册 = 被依赖 = 最后关）：
//   1. DB pool        2. outbox relay(依赖 pool)   3. event consumer
//   4. background worker      5. HTTP listener(最后注册 → LIFO 最先关，先停外部流量)
//
// 驱动（P2 实现）：
//   tokio::select! { _ = sigterm() => {}, _ = ctrl_c() => {} }   // 感知
//   let failures = stack.shutdown().await;                       // 两阶段关闭
//   if !failures.is_empty() { for f in &failures { error!(%f) } exit(1) }
```

`register` 与 `child_token` 拆开（不让 `register` 返回 token），因为资源经**构造器注入** token
（RSS「必填依赖走构造器位置参」），需在 `register` 之前先 `child_token()` 拿到 token 再构造资源。
`child_token()` 须在 `shutdown` 前调用——`shutdown` 已 `cancel` 后再派生的 token 是已 cancelled 态。

实现者若需在 `shutdown(&self)`（`&self`，因驱动器 `Arc` 持有以 spawn 隔离 panic）中消费内部
mut 状态（drain sender / take oneshot），用 `Mutex<Option<Inner>>` 包装后 `take()`（见 trait rustdoc）。

---

## 5. 后果与权衡

**收益**

- 关闭顺序、错误聚合、超时、panic 隔离全部显式可测，替代 Go `defer` 的隐式 LIFO。
- 接缝冻结：`ManagedResource` 是各 adapter（postgres / amqp / relay …）将实现的稳定 port，
  P3+ 资源接入时不需重开此接缝。
- 单次性是编译期 Hard（消费 self）；其余不变式 Medium，由代码结构 + 测试断言 + clippy deny 守（见 §3）。

**代价 / 偏离**

- per-resource panic 隔离用 `tokio::spawn`，要求 `ManagedResource: Send + Sync + 'static`
  并 `Arc` 持有——比裸 `&dyn` 重，但换来「一个 adapter panic 不漏关其它资源」的零信任鲁棒性。
- 超时后 hung task 被 `abort()` 后**不 `await` 等其 join** 即继续下一个资源——刻意为之以保
  `SHUTDOWN-TIMEOUT-BOUNDED`：尊重取消的 task 会在 `abort` 后即刻 drop 释放句柄；忽略取消的
  阻塞型 task 若 `await` 会重新无界等待、破坏超时上界，故不 await，由进程退出回收。代价是被依赖
  资源关闭前可能存在极短的「hung task 仍持旧句柄」窗口（cancel 广播已令其进入退出路径，已最小化）。
- 超时后 hung task `abort` 不强杀进程——与 k8s `terminationGracePeriodSeconds` 语义一致
  （grace 后 SIGKILL 是 kubelet 职责）。**风险**：当前无整体 deadline，N 个资源串行 LIFO、各自
  最坏 `DEFAULT_SHUTDOWN_TIMEOUT`(30s)，最坏总耗时 ≈ N×30s 可能超过 grace period，导致 SIGKILL
  到来时尾部资源（最先注册的 DB pool）未及关闭。缓解：重 I/O 之外资源应 `shutdown_timeout()` 调小；
  P2 整体 deadline（< grace − buffer）封顶总耗时。30s 默认对齐 k8s grace 默认，单资源合理。

**已延后（非本 spike 范围，登记去向，非藏 TODO）**

| 延后项 | 去向 | 理由 |
|--------|------|------|
| SIGTERM/SIGINT 信号驱动 + k8s grace period 接线 | P2 装配骨架（rewrite-sequence P2） | 属进程组合根接线，本 spike 只冻结 `ShutdownStack` 接缝 |
| 真实资源 adapter（DB pool / relay …）实现 `ManagedResource` | P3+（随各 adapter 落地） | 资源本体在后续阶段 |
| 关闭时延 metric / 耗时测量（注入 `Clock`） | 待 `primitives::Clock` 落地后接入 | `primitives` 当前为空骨架；超时强制已用 `tokio::time`（运行时时钟，测试经 `start_paused` 控制），不裸调 `Instant`（clippy 禁） |
| 整体 shutdown deadline（叠加在 per-resource 超时之上） | P2（与信号 grace period 一并） | 需要进程级时间预算，属接线层 |
| 关闭错误日志经 `secure::redact_error` 清洗（observability.md §redaction） | 随 P3+ 真实 adapter 接入 + `secure` redaction 模块落地 | `secure` 当前为空骨架；本 spike 无真实 adapter、无敏感值流经，故错误仅记 top-level Display（非 `{:#}` 全链）缩小 PII 面，redaction 待 sink 真有敏感值时接 |

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
  —— `with_graceful_shutdown` 连接 drain；HTTP listener 是「最先注册、LIFO 最后关」的资源（先停外部流量）。
- `ref: tokio-rs/tokio tokio/src/runtime/task/harness.rs@master` —— `panic::catch_unwind` → `JoinError`，
  印证 `tokio::spawn` 隔离下游 panic 的正确性。
- `ref: Finomnis/tokio-graceful-shutdown tests/integration_test.rs@main` —— `#[tokio::test(start_paused)]`
  + `sleep(Duration::MAX)` 做确定性超时测试（不靠真实时间），本 PR 的超时测试采此法。

---

## 7. Implementation matrix

| 变更 | contract | generated | crate | tests | docs |
|------|----------|-----------|-------|-------|------|
| `ManagedResource` + `ShutdownStack` + 两阶段 LIFO 驱动器 | —（非 wire 契约，进程内 port） | — | `crates/bootstrap/src/shutdown.rs`、`lib.rs`、`Cargo.toml` | `shutdown.rs` `#[cfg(test)]` 8 例（逆序/继续-聚合/超时/panic 隔离/取消/空/单/全错） | 本 ADR |
| `tokio-util` 入 workspace 依赖 | — | — | 根 `Cargo.toml [workspace.dependencies]` | cargo-deny bans/licenses ok | 本 ADR §5 |

> 本 ADR 不涉及跨域 wire 契约（无 schema/generated 扇出）：`ManagedResource` 是进程内关闭 port，
> 经组合根注入，跨域仍只走 contract。
