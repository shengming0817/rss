//! compile-fail（#1095，INVARIANT: DIPORT-ASYNC-ARC-SEND-01）：**所有** async DI port 的 dynosaur Send
//! 变体 `DynX` 都是 `Send` 但 **非 `Sync`**（`#[trait_variant::make(X: Send)]` 只加 Send），故每个
//! `Arc<DynX>` 都是 `!Send`——无法被多次调用且在 `tokio::spawn` / Send `'static` future 中消费的 async
//! 消费者持有。
//!
//! 既定范式（ADR-003 amendment §注入形态收口）：多次调用 async 消费者用**泛型静态分发**
//! （`<S: X + Send + Sync + 'static>` + `Arc<S>`），而非 `Arc<DynX>`；`Box<DynX>` 用于单 owner 注入。
//!
//! 本负例覆盖全部 10 个 async DI port（anti-vacuity 回归锁，与 `dyn_compatible_pass.rs` 端口集对称）：
//! Signer / AuditSink / Subscriber / Publisher / RateLimiter / ManagedResource / ObjectStore / Pdp /
//! OutboxEmitter / RevocationStore。若任一 wrapper 改为 `Send + Sync`（ADR-003 Option A，#1152），对应
//! `assert_send` 转可编译，强制有意识更新本测试 + ADR + crate rustdoc，而非静默漂移。
use diport::{
    DynAuditSink, DynManagedResource, DynObjectStore, DynOutboxEmitter, DynPdp, DynPublisher,
    DynRateLimiter, DynRevocationStore, DynSigner, DynSubscriber,
};
use std::sync::Arc;

fn assert_send<T: Send>() {}

fn main() {
    // 每个 Arc<DynX>: Send 都需 DynX: Send + Sync，但其仅 Send ⇒ 全部 !Send（E0277）。
    assert_send::<Arc<DynAuditSink<'static>>>();
    assert_send::<Arc<DynPublisher<'static>>>();
    assert_send::<Arc<DynSubscriber<'static>>>();
    assert_send::<Arc<DynSigner<'static>>>();
    assert_send::<Arc<DynRateLimiter<'static>>>();
    assert_send::<Arc<DynManagedResource<'static>>>();
    assert_send::<Arc<DynObjectStore<'static>>>();
    assert_send::<Arc<DynPdp<'static>>>();
    assert_send::<Arc<DynOutboxEmitter<'static>>>();
    assert_send::<Arc<DynRevocationStore<'static>>>();
}
