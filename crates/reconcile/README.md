# rss-reconcile

独立、tenant-scoped 的持久化收敛执行库。核心拥有 comparison、durable port、调度和恢复；产品拥有业务观察、动作、认证和策略。模型从固定历史 `5b63e10a1b396b0ff70b7d1e6e55db296cd7a891` 提取，没有旧 API 兼容层。

调用方构造 `Scope` / `Target`、显式时钟 `Timer`、`Control`、有界 `Policy`，实现 `Reconciler<Store::Claim>`，然后 await `run(..., observe)`。失败诊断通过同步观察回调交给调用方，回调应保持非阻塞。`DurableStore::wake` 必须先提交；基础 `run` 不需要 Notify；`run_with_notify` 的 `Notify` 仅提前唤醒，启动和周期扫描不依赖通知。

每次领取工作后执行 `observe → diff → apply`。只有 observe 确认无差异才记录 Converged；apply 成功持久化 Reobserve，下一轮重新观察。多个实体并行，同实体单飞，扫描和续租等待不阻断在途回调。一个持久 wake version 防止旧完成吞掉新工作。

`Policy::try_from(PolicyConfig { ... })` 用具名字段明确 concurrency、lease_ttl、attempt_timeout、scan_interval、initial_backoff、max_backoff、max_attempts；要求并发 1..=64、最大尝试次数 max_attempts 1..=1000（包含第一次尝试）、整毫秒正时长（至多 24h），lease 至少 3ms。退避计数持久化，重启不重置；永久/invariant 错误及重试耗尽暂停到下一次显式 wake。成功提交动作只重置失败计数，不等于业务收敛。

`run` 没有 detached task。取消、截止时间或丢 lease 会 drop 对应回调；未完成 claim 通过 TTL 恢复。panic 原样传播到运行 owner，保留原 payload，不转成可重试错误。`Observation::AttemptFailed` 保留目标、Observe/Apply/Renew/Finish 阶段、ErrorKind 与脱敏 source，Retry/Suspended 的原因也会发出；`ScanFailed` 携带 scope 与错误。Report 是本次执行计数，execution_failed 按目标尝试计数，scan_failed 按失败扫描操作计数，claim_unknown_batches 按结果未知的领取批次计数，不是业务事务 receipt。调用方停止并 join worker 后再关闭 provider。

外部动作必须使用跨 attempt 稳定的业务幂等身份。超时、取消、panic 或提交未知都可能已产生效果，下一次尝试先观察；业务仍无法判明是否执行时应返回错误或继续观察，不能盲重放。数据库 claim 不能撤销或 fence 远端在途操作；只有远端自己验证 token/条件写时才有远端保护。不得把外部网络动作放进声明为数据库原子事务的回调。

core 没有 provider、消息引擎、设备命令或产品运行框架依赖。PostgreSQL 实现见 `rss-reconcile-postgres`。

源码参考：kube-rs `kube-runtime/src/controller/runner.rs` 和 `scheduler.rs`，commit `f2774b13d66910a8a0fe456cc8e6e52414eb1d0e`。采用实体去重与有界执行；持久恢复由本组件 port 实现。
