//! amqp — RSS AMQP 事件传输 adapter（lapin）。
//!
//! 直接实现 transactional messaging native ports：[`AmqpPublisher`]（`Publisher`）+
//! [`AmqpSubscriber`]（`DeliverySource`）；两者同时实现 `ManagedResource`。
//! 生产事件主干——relay 经 `Publisher` 把已持久化 outbox entry 发到跨进程 broker；
//! consumer 经 `DeliverySource`（at-least-once，manual-ack）收取。
//!
//! # per-domain vhost/credential 隔离
//!
//! adapter 从已验证 per-domain AMQP endpoint 连接；生产 private-CA 组合根必须分别注入 publisher 与
//! subscriber role endpoint——隔离经 broker 侧的 **vhost + role credential**，**不**经 exchange/queue
//! 命名前缀（命名前缀会把域身份泄进 wire 且可绕过）。URL 由消费方完成策略选择后注入。
//! 凭据 non-leak：连接日志经 `conn_events`（`AmqpEndpoint` Display + `rss_redact::redact_error`）。
//! 明文 `amqp://` 只允许 testcontainer / dev loopback fixture 显式 opt-in，非 loopback 明文不可表达。
//!
//! # P7 传输边界（manual-ack，at-least-once）
//!
//! [`AmqpSubscriber`] 仅实现 [`rss_transactional_messaging::transport::DeliverySource`]（at-least-once）：
//!
//! - **[`rss_transactional_messaging::transport::DeliverySource`]（manual-ack，`no_ack=false`，at-least-once）**：
//!   每条 [`rss_transactional_messaging::transport::Delivery`] 携 move-only settlement receipt，由 `rss_transactional_messaging_runtime::consumer::consume_once` 据
//!   [`rss_transactional_messaging::transaction::SettlementKind`] 结算（`Ack`→basic_ack、`Requeue`→basic_nack(requeue=true)、
//!   `Reject`→basic_nack(requeue=false)）。在途消息于消费者崩溃窗口 broker 自动 requeue——
//!   channel close 即重投，兑现 **at-least-once**。
//!   prefetch=1（channel 级单在途 delivery，保证排空期间不领取下一条消息）。
//! - subscriber 为每个 source topic 声明 durable quorum `<topic>.dlq`（`.dlq` 是保留后缀），source
//!   quorum queue 通过现有 `amq.topic`
//!   exchange 的 exact `<topic>.dlq` key 把 `Reject` 路由到该 queue；subscriber topic permission 只允许
//!   写该 quarantine key，不能向 source/adjacent queue 发布。source 使用 RabbitMQ at-least-once
//!   dead-letter strategy；source 与 broker quarantine 各固定 256 MiB、overflow=reject-publish，quarantine
//!   固定保留 24 小时。参数漂移由 durable queue 声明 fail-fast；不使用外部 policy、兼容 topology 或
//!   custom DLX exchange。
//! - broker DLQ 只承接 ConsumerBase 的 fail-closed transport Reject，不是 app DLX 或 replay API。
//!   handler 永久 Reject 仍由 ConsumerBase 写入加密 app DLX，成功后 broker Ack，避免双 owner。
//!
//! Provider-neutral test doubles live in `rss-transactional-messaging-testkit`.
//!
//! # Publisher transport replacement 与 ambiguous outcome
//!
//! Publisher 以 generation-scoped `connection + confirm channel` 为不可拆分 transport。只有 Ready generation
//! 接受 publish；发送后/confirm 阶段的 IO reset、connection/channel close、confirm lost 与共享 deadline
//! 都先退休整代 transport，再返回 `PublishOutcome::Ambiguous`。relay 只能用原 message ID 重试，因此 transport
//! 保持 at-least-once，broker duplicate 由 Inbox/ConsumerTx 收口事务内数据库副作用。
//!
//! RSS 独占 reconnect：同一 absolute recovery deadline 依次覆盖旧 confirms drain、旧 connection close、fresh
//! connection + confirm channel 建立。lapin `ConnectionProperties::enable_auto_recover` 明确不启用，避免产生不受
//! RSS deadline 取消的第二套 TCP recovery owner。Recovering/Unavailable fail-fast；stale generation 不能退休或
//! 覆盖 replacement。
//! ref: amqp-rs/lapin src/generated/channel.rs@v4.10.0（采纳 publish/confirm 生命周期，偏离 auto-recovery）。
//!
//! # feature 门控
//!
//! 真实 lapin broker I/O 在 `backend` feature 下编译；默认 build（无 feature）退化为 sealed-marker
//! 签名冻结壳（`todo!()` body），保 ADAPTER-PORT-FREEZE-01 默认 `cargo test` / `verify` 绿、不拉
//! broker 客户端树。`backend` feature 使用 lapin rustls + ring + webpki roots；native-tls / OpenSSL /
//! aws-lc provider 由 workspace feature 选择和 `deny.toml` bans 防漂移。
//! `integration-test-support` 只额外暴露确定性 post-send close、只读 generation evidence 与 typed broker
//! quarantine observation seam，不引容器或 raw lapin handle；
//! `integration` 才叠加 testcontainers fixture。两者都不属于默认生产 surface。
//!
//! ref: lapin examples/pubsub.rs@main（connect → create_channel → queue_declare → basic_publish →
//! basic_consume → Consumer Stream），与 `adapters/memory` 的 `take_until(token)` 流取消范式一致。

// feature-agnostic：SettlementKind→broker 结算模式映射（不依赖 lapin）。`cfg(any(test, backend))`：
// 默认 `cargo test`（test cfg）下编译并跑表驱动测试（进 verify gate）；backend 下提供 broker settlement；
// 纯默认 lib build（无 test / 无 backend）无生产消费方 ⇒ 不编译，免 dead_code。
#[cfg(any(test, feature = "backend"))]
mod settle;

// feature-agnostic：connect 成功/失败 tracing emit（无 lapin）。Hard 入参 `&AmqpEndpoint`；
// Medium EVENTTRANSPORT-CRED-REDACT-01 负向门默认 `cargo test` 可跑（同 settle）。
#[cfg(any(test, feature = "backend"))]
mod conn_events;

#[cfg(feature = "backend")]
mod bundle;
#[cfg(feature = "backend")]
mod conn;
#[cfg(feature = "backend")]
mod publisher;
#[cfg(feature = "backend")]
mod subscriber;

/// Broker-owned topic exchange shared by the production publisher and subscriber. RabbitMQ topic
/// permissions can close routing keys on this exchange; its default exchange cannot.
#[cfg(feature = "backend")]
pub(crate) const EVENT_EXCHANGE: &str = "amq.topic";

#[cfg(not(feature = "backend"))]
mod fallback;

#[cfg(feature = "backend")]
pub use bundle::{AmqpInfraDeps, AmqpPublisherEndpoint, AmqpRuntimeDeps, AmqpSubscriberEndpoint};
#[cfg(feature = "backend")]
pub use conn::{AmqpConnectError, AmqpPrivateCa, AmqpPrivateCaError};
#[cfg(feature = "backend")]
pub use publisher::AmqpPublisher;
#[cfg(feature = "backend")]
pub use subscriber::AmqpSubscriber;

#[cfg(not(feature = "backend"))]
pub use fallback::{AmqpPublisher, AmqpSubscriber};

#[cfg(test)]
mod smoke {
    //! build smoke：编译期断言 adapter 已 impl canonical native ports（PhantomData 绑定检查，不构造、
    //! 不执行 body）。两种 build 都过——默认 fallback（`todo!()`）/ `integration` 真实 lapin impl。
    //! INVARIANT: ADAPTER-PORT-FREEZE-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— [`AmqpPublisher`] impl `Publisher`+`ManagedResource`、
    //! [`AmqpSubscriber`] impl `DeliverySource`+`ManagedResource`；去掉任一 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    fn assert_managed_resource<T: rss_runtime::ManagedResource>(_: PhantomData<T>) {}
    fn assert_publisher<T: rss_transactional_messaging::transport::Publisher<Vec<u8>>>(
        _: PhantomData<T>,
    ) {
    }
    fn assert_delivery_source<
        T: rss_transactional_messaging::transport::DeliverySource<Vec<u8>>,
    >(
        _: PhantomData<T>,
    ) {
    }

    #[test]
    fn impls_frozen_ports() {
        assert_publisher(PhantomData::<super::AmqpPublisher>);
        assert_managed_resource(PhantomData::<super::AmqpPublisher>);
        assert_managed_resource(PhantomData::<super::AmqpSubscriber>);
        assert_delivery_source(PhantomData::<super::AmqpSubscriber>);
    }
}
