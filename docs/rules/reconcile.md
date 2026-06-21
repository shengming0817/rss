# Reconcile 控制环规则

本文件只保留当前行为约束。完整 invariant 清单、符号、盲区写在
`crates/consistency/src/reconcile/mod.rs` 模块级 rustdoc §Enforced invariants、
对应 `RECONCILE-*` 守卫（类型系统 / clippy lint / `#[test]` 纵深，见 §参考）和 reconcile ADR 中。

## 适用范围

reconcile 是 L4 desired-state 收敛控制环：周期观察一个域 crate **自己 OWN** 的非终态实体
（设备命令、证书行、trust score），把每个驱动趋向 desired。收敛权属于消费域 crate——框架只
提供 Loop harness，域 crate 在 `Reconcile` 内对自己的实体表行使写权。

reconcile **不是业务编排器**（那是 saga），**不是 CQRS 读模型构建器**（那是 projection
harness）。三者正交，边界见下。

## Reconciler 实现要点

- 签名 `async fn reconcile(&self, ctx: &Context, req: Request) -> Result<Outcome, ReconcileError>`，
  trait 方法集冻结。
- 默认值 `Request::default()`（空 `EntityId`）是 resync pulse——「re-observe 你拥有的全部」，fan out 到每个
  实体；ticker 每 interval 再发，早退的 sweep 下个 tick 被重驱动（level-triggered，不丢）。
- transient error → Loop 退避重试（per-entity 指数退避）。
- `PermanentError` / `is_permanent` 只是不可重试分类，**不**自动把重试改成放弃下一步逻辑。
- `Outcome.requeue_after` 表达健康态稍后复检；result label 值集冻结，捕获的 panic（`catch_unwind`）映射 transient。

## Builder 强制

`reconcile::Builder::new(r, tenancy).with_*().build()` 是**唯一**公开构造入口；Loop config 字段全部
`pub(crate)` / 私有，`build()` 强制要求一个 Trigger。消费方禁止裸构造 Loop，禁止旁路 Builder 注入调度逻辑。

`Builder::new` 第二参 `tenancy` 是必填 sealed `Tenancy`（`Tenancy::single_tenant()` / `Tenancy::tenant_scoped()`，
仿 `Clock` 位置参约定，非可漏链的 `with_*`）：reconciler 在 tenantless system 身份下发射命令（Claimer key 落
`_notenant`），故必须显式声明该命名空间是否正确。漏声明=编译错（构造器必填参数）；TenantScoped
reconciler 须自行在 command-id 编码 tenant 维度（框架不验证 body，残留盲区）。由 builder fail-fast + 类型系统（Hard）强制：构造器必填 sealed 参数使漏传无法编译。

## Leader-elect

- `None` `LeaderElector`（`Option<...>`）= 单进程模式（always leader，Epoch 0，无 fencing）。
- wire 后整环 leader-gated：仅 lease holder dispatch；丢 lease 取消 lease-scoped `CancellationToken` 中断在途 reconcile。
- **leader ≠ fencing**：跨副本正确性靠单调 `LeaseToken.epoch` 注入 `FencedWriter`（写路径 CAS）+
  消费方幂等，绝不靠 lease 本身。
- `LeaderElector` trait 实现只允许在 `adapters/{redis,postgres}`（裸后端名，无前缀）+
  `reconciletest` fake；adapter 选型 Redis vs PG 按部署形态决定。

## 与 saga / projection 边界

- **saga**：边沿触发、有限步前向编排 + 补偿，跑完即终态（对标 Temporal）。
- **reconcile**：水平触发、desired↔actual 无限收敛环（对标 controller-runtime）。
- **projection**：CQRS 读模型构建，事件驱动重放投影。

L3 最终一致可用 projection / saga；reconcile 用于 L4 跨不可靠边界（设备 / 证书）的主动收敛。

## 参考

- 权威 rustdoc：`crates/consistency/src/reconcile/mod.rs` 模块级文档 §Enforced invariants
- Invariants：`RECONCILE-*` 族完整清单、符号与盲区以对应守卫（类型系统 / clippy lint / `#[test]`·
  `rstest` 纵深，可执行真源）与 `crates/consistency/src/reconcile/mod.rs` §Enforced invariants 为准；
  规则文件不另维护清单。能编译期强制的不退化成运行期测试。
