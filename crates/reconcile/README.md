# rss-reconcile

独立、tenant-scoped 的持久化收敛执行库。核心拥有 comparison、durable port、调度和恢复；产品拥有业务观察、动作、认证和策略。模型从固定历史 `5b63e10a1b396b0ff70b7d1e6e55db296cd7a891` 提取，没有旧 API 兼容层。

调用方构造 `Scope` / `Target`、显式时钟 `Timer`、`Control`、有界 `Policy`，显式提供 `ResourceSet` 并实现 `Reconciler<Store::Claim>`，提供独立的停止领取 token，然后 await `run(..., control, stop, observe)`。失败诊断通过同步观察回调交给调用方，回调应保持非阻塞。`DurableStore::wake` 必须先提交；基础 `run` 不需要 Notify；`run_with_notify` 的 `Notify` 仅提前唤醒，启动和周期扫描不依赖通知。

每次领取工作后执行 `observe → diff → apply`。只有 observe 确认无差异才记录 Converged；apply 成功持久化 Reobserve，下一轮重新观察。不相交的资源集合并行，相交集合在领取前协调，同实体单飞，扫描和续租等待不阻断在途回调。一个持久 wake version 防止旧完成吞掉新工作。

`Policy::try_from(PolicyConfig { ... })` 用具名字段明确 concurrency、lease_ttl、attempt_timeout、scan_interval、idle_scan_interval、initial_backoff、max_backoff、max_attempts；要求并发 1..=64、最大尝试次数 max_attempts 1..=1000（包含第一次尝试）、整毫秒正时长（至多 24h），lease 至少 3ms。`scan_interval` 控制成功动作后的 Reobserve 和可恢复扫描错误的重试；`idle_scan_interval` 控制空闲补扫。已确认提交的 Reobserve / Retry 截止时间可提前唤醒，通知丢失或进程重启仍由补扫恢复。退避计数持久化，重启不重置；同轮失败的不同 target 在指数退避底值之上错开重试，最终时长不超过 `max_backoff`，选定的截止仍由 provider 持久化；永久/invariant 错误及重试耗尽暂停到下一次显式 wake。成功提交动作只重置失败计数，不等于业务收敛。

`run` 没有 detached task。取消 `stop` 后停止新扫描，在途 claim 完成领取后与已有活动任务一起排空；业务和 finish 分别受 `attempt_timeout` 限制，排空期间继续续租与 fencing。`Control` 的取消/截止属于强制中断，和 `stop` 使用不同 token；排空期间遭强制中断会返回错误。直接 drop runner 或丢 lease 也会 drop 对应回调；未完成 claim 通过 TTL 恢复。宿主关闭预算须覆盖尚在途的领取、业务 attempt 与 finish；不能把正常停止 token 同时接到强制取消边界。panic 原样传播到运行 owner，保留原 payload，不转成可重试错误。`Observation::AttemptFailed` 保留目标、Observe/Apply/Renew/Finish 阶段、ErrorKind 与脱敏 source，Retry/Suspended 的原因也会发出；`ScanFailed` 携带 scope 与错误。Report 是本次执行计数，execution_failed 按目标尝试计数，scan_failed 按失败扫描操作计数，claim_unknown_batches 按结果未知的领取批次计数，不是业务事务 receipt。调用方停止并 join worker 后再关闭 provider。

外部动作必须使用跨 attempt 稳定的业务幂等身份。超时、取消、panic 或提交未知都可能已产生效果，下一次尝试先观察；业务仍无法判明是否执行时应返回错误或继续观察，不能盲重放。数据库 claim 不能撤销或 fence 远端在途操作；只有远端自己验证 token/条件写时才有远端保护。不得把外部网络动作放进声明为数据库原子事务的回调。

core 没有 provider、消息引擎、设备命令或产品运行框架依赖。PostgreSQL 实现见 `rss-reconcile-postgres`。

源码参考：kube-rs `kube-runtime/src/controller/runner.rs` 和 `scheduler.rs`，commit `f2774b13d66910a8a0fe456cc8e6e52414eb1d0e`。采用实体去重与有界执行；持久恢复由本组件 port 实现。


最小可运行使用流程及独立源码/候选 artifact 命令见 [rss-examples](../examples/README.md)。

`Scope` / `Target` 的默认 `Debug` 使用固定脱敏占位，`Observation` 递归格式化不会展开租户、reconciler 或 entity 身份。显式访问器仍返回原身份，调用方须自行控制其输出边界。

## 共享资源与正常等待

`ResourceSet::new(tenant, keys)` 校验最多 1000 个不透明键、排序去重；键遵循 Target 的 1..128 字节字符限制。资源不包含 reconciler，因此同租户跨 Scope 共用；`ResourceSet::empty(tenant)` 必须显式选择。资源只是调度信息，不替代产品授权、事务锁和远端幂等。

`DurableStore::wake(target, resources, control)` 将新输入和完整声明原子登记；`bind_resources` 只修正声明，保留 failures、wake version 和 next_run。`claim_due` 返回 `ClaimBatch { claims, more }`，runner 按空槽继续有界扫描；只有成功领取的 claim 占槽。

`observe` / `apply` 返回 `ReconcileStep::Ready(value)` 或 `Deferred(after)`。正常忙必须在效果未提交或事务已确认回滚后让出，不能把提交未知、回滚失败或真实存储故障转换为 Deferred。Deferred 的正整毫秒延迟至多一天，持久化后保留 failures，独立计入 Report.deferred 与 Observation::Deferred；不表示 apply 成功。资源绑定变化会取消旧执行资格并让出；只有原 token/epoch 仍有效时能交回旧资源。

公平推进要求相关 Scope 持续扫描、事务最终结束、holder 释放或过期。已入队老多资源工作先于相交年轻工作，不相交资源可继续；未扫描的旧工作可能暂时被越过，不承诺严格全局 FIFO、固定时限或容量指标。产品停掉某个 Scope 后，其持久等待者可能继续阻挡相交工作，应由产品负责恢复该 owner。
