//! consistency — RSS 一致性引擎接缝：outbox / saga / reconcile / projection / idempotency 纯态机 + 策略 trait（引擎层 L0–L4，依赖基础层）。
//!
//! # 派发范式（ADR-003 §2 / ADR-004 C1）
//!
//! 本 crate 冻结的是**引擎策略 trait**（L0–L4 一致性等级）：`IdempotencyStore`/`OutboxRelay`/`SagaStep`/
//! `Reconciler`/`Projector` 一律 **native AFIT**（trait 内直接 `async fn`）+ **泛型静态分发**
//! （消费方 `fn run<S: Trait>(s: &S)`，零开销、零 box）——**不引 dynosaur、不引 async-trait**。
//! native AFIT trait 不 object-safe，故全 crate 禁 `Box<dyn Trait>`：消费方一律泛型 `<S: Trait>`。
//!
//! 这些是引擎侧策略接缝，**非** DI 注入 infra port（provider-可换的 Store/Publisher/Clock 走 dynosaur，
//! 归未来 `diport` crate，不在本 crate）。错误用本地 [`EngineError`]（thiserror，message `&'static str`
//! const，ADR-004 C10）。engine 类型**不** derive serde（ADR-004 C6）。
//!
//! ref: kube-rs kube-runtime/src/{controller,watcher}.rs@main（Reconciler 函数式接缝 + 内部 native AFIT）；
//! oxidecomputer/steno src/saga_action_generic.rs@main（saga do/undo + 逆序补偿）。
//!
//! # 模块一致性等级
//!
//! | 模块 | 等级 |
//! |------|------|
//! | idempotency | L0 |
//! | outbox | L1/L2 |
//! | saga | L3 |
//! | reconcile | L4 |
//! | projection | L3 |

pub mod error;
pub mod idempotency;
pub mod outbox;
pub mod projection;
pub mod reconcile;
pub mod saga;
pub mod tx_retry;

pub use error::{EngineError, EngineErrorKind};
pub use idempotency::{
    ConsumerGroup, ConsumerGroupError, IdemKey, IdemKeyError, IdempotencyStore, LeaseOutcome,
    LeaseToken, SeenState,
};
pub use outbox::{
    BacklogSample, Disposition, Entry, HandleResult, OutboxBacklog, OutboxRelay, OutboxSource,
    PartitionKey, PartitionKeyError, PermanentError, PermanentErrorKind, RetentionSweeper, Topic,
    TopicError,
};
pub use projection::{
    Lsn, PartitionSerialDelivery, ProjectionEvent, Projector, SerialInOrder, SerialInOrderGuarantor,
};
pub use reconcile::{
    Context, EntityId, EntityIdError, Outcome, ReconcileError, Reconciler, Request,
};
pub use saga::{CompensationOutcome, SagaOutcome, SagaStep, StepName, StepNameError};
pub use tx_retry::{
    TxRetryClass, TxRetryFinalStatus, TxRetryPolicy, TxRetryPolicyError, TxRetryReport,
    run_tx_retry,
};

#[cfg(test)]
mod static_dispatch_smoke {
    //! 泛型静态分发编译过 smoke（PORT-SHAPE 引擎版）：证明每个 native AFIT 引擎策略 trait
    //! 可被泛型 `<S: Trait>` 单态消费（零 box、非 object-safe 路径成立）。**只编译不执行**——
    //! 方法体 todo!() 永不调用（无 `.await`），故无 panic 实际触发。

    use super::idempotency::IdempotencyStore;
    use super::outbox::{OutboxBacklog, OutboxRelay, OutboxSource, RetentionSweeper};
    use super::projection::{
        PartitionSerialDelivery, ProjectionEvent, Projector, SerialInOrderGuarantor,
    };
    use super::reconcile::Reconciler;
    use super::saga::SagaStep;

    // 每个 driver 接受泛型 `&S`（非 `Box<dyn>`）——证明 native AFIT trait 可泛型静态分发消费。
    // 函数体空：仅约束类型成立（编译期），不构造实例、不调 async（避免 todo!() panic）。
    #[allow(dead_code)]
    // reason: 冻结期 driver 函数只为证编译，不被调用（行为 PR 兑现调用方）。
    fn _drives_idem<S: IdempotencyStore>(_s: &S) {}
    #[allow(dead_code)] // reason: 同上。
    fn _drives_relay<R: OutboxRelay>(_r: &R) {}
    #[allow(dead_code)] // reason: 同上，证 OutboxSource 读侧端口可泛型静态分发消费。
    fn _drives_source<S: OutboxSource>(_s: &S) {}
    #[allow(dead_code)] // reason: 同上，证 RetentionSweeper 清理端口可泛型静态分发消费。
    fn _drives_sweeper<S: RetentionSweeper>(_s: &S) {}
    #[allow(dead_code)] // reason: 同上，证 OutboxBacklog 采样端口可泛型静态分发消费。
    fn _drives_backlog<B: OutboxBacklog>(_b: &B) {}
    #[allow(dead_code)] // reason: 同上。
    fn _drives_saga<S: SagaStep>(_s: &S) {}
    #[allow(dead_code)] // reason: 同上。
    fn _drives_reconciler<R: Reconciler>(_r: &R) {}
    #[allow(dead_code)] // reason: 同上。
    fn _drives_projector<P: Projector>(_p: &P) {}
    #[allow(dead_code)] // reason: 同上，证 ProjectionEvent sync trait 可泛型消费。
    fn _drives_projection_event<E: ProjectionEvent>(_e: &E) {}
    #[allow(dead_code)] // reason: 同上，证串行有序 witness bound 可泛型消费（projection harness attach 门禁形）。
    fn _drives_guarantor<G: SerialInOrderGuarantor>(_g: G) {}
    #[allow(dead_code)] // reason: 同上，证 PartitionSerialDelivery 契约 trait 可泛型消费（witness 铸造侧）。
    fn _drives_partition_serial<S: PartitionSerialDelivery>(_s: &S) {}
}
