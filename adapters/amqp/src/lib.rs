//! amqp — RSS AMQP 事件传输 adapter（lapin）。
//!
//! impl `diport` 已冻 DI port：[`AmqpPublisher`]（`Publisher` + `ManagedResource`）+
//! [`AmqpSubscriber`]（`Subscriber` + `AckableSubscriber` + `ManagedResource`）。
//! 生产事件主干——relay 经 `Publisher` 把已持久化 outbox entry 发到跨进程 broker；
//! consumer 经 `Subscriber`（at-most-once）或 `AckableSubscriber`（at-least-once）收取。
//!
//! # per-domain vhost/credential 隔离
//!
//! adapter 从**单个 per-domain AMQP URL**（`amqp://user:pass@host/vhost`）连接——隔离经 broker
//! 侧的 **vhost + credential**（operator 为每个域 provision 独立 vhost/user），**不**经 exchange/queue
//! 命名前缀（命名前缀会把域身份泄进 wire 且可绕过）。URL 由组合根经 `bootstrap::eventtransport` 决策
//! 注入。凭据 non-leak：连接失败日志只经 `secure::redact_url_credentials` / `secure::redact_error`。
//!
//! # P7 传输边界（manual-ack + auto-ack 对偶）
//!
//! [`AmqpSubscriber`] 同时实现两个 port，语义对偶：
//!
//! - **[`diport::Subscriber`]（auto-ack，`no_ack=true`，at-most-once）**：broker 投递即出队，
//!   stream 产出无 ack 义务的 [`diport::Message`]。遗留/brokerless 对偶，保持原 P6 语义。
//!
//! - **[`diport::AckableSubscriber`]（manual-ack，`no_ack=false`，at-least-once）**：
//!   每条 [`diport::Delivery`] 携 `AmqpAcker` 句柄，由 `eventexec::run_consumer_ackable` 据
//!   [`diport::AckAction`] 结算（`Ack`→basic_ack、`Requeue`→basic_nack(requeue=true)、
//!   `Reject`→basic_nack(requeue=false)）。在途消息于消费者崩溃窗口 broker 自动 requeue——
//!   channel close 即重投，兑现 **at-least-once**。
//!   prefetch=100（channel 级 unacked 上限，RabbitMQ 推荐 100–300）。
//!
//! # feature 门控
//!
//! 真实 lapin broker I/O 在 `integration` feature 下编译；默认 build（无 feature）退化为 sealed-marker
//! 签名冻结壳（`todo!()` body），保 ADAPTER-PORT-FREEZE-01 默认 `cargo test` / `verify` 绿、不拉
//! broker 客户端树。本 PR 仅明文 `amqp://`（rustls/native-tls 后端的 crypto provider license 不在
//! deny.toml allow-list）；生产 AMQPS/TLS = follow-up。
//!
//! ref: lapin examples/pubsub.rs@main（connect → create_channel → queue_declare → basic_publish →
//! basic_consume → Consumer Stream），与 `adapters/memory` 的 `take_until(token)` 流取消范式一致。

// feature-agnostic：AckAction→broker 结算模式映射（不依赖 lapin）。`cfg(any(test, integration))`：
// 默认 `cargo test`（test cfg）下编译并跑表驱动测试（进 verify gate）；integration 下供 AmqpAcker 消费；
// 纯默认 lib build（无 test / 无 integration）无生产消费方 ⇒ 不编译，免 dead_code。
#[cfg(any(test, feature = "integration"))]
mod settle;

#[cfg(feature = "integration")]
mod conn;
#[cfg(feature = "integration")]
mod publisher;
#[cfg(feature = "integration")]
mod subscriber;

#[cfg(not(feature = "integration"))]
mod fallback;

#[cfg(feature = "integration")]
pub use conn::AmqpConnectError;
#[cfg(feature = "integration")]
pub use publisher::AmqpPublisher;
#[cfg(feature = "integration")]
pub use subscriber::AmqpSubscriber;

#[cfg(not(feature = "integration"))]
pub use fallback::{AmqpPublisher, AmqpSubscriber};

#[cfg(test)]
mod smoke {
    //! build smoke：编译期断言 adapter 已 impl 冻结的 diport DI port（PhantomData 绑定检查，不构造、
    //! 不执行 body）。两种 build 都过——默认 fallback（`todo!()`）/ `integration` 真实 lapin impl。
    //! INVARIANT: ADAPTER-PORT-FREEZE-01 —— [`AmqpPublisher`] impl `Publisher`+`ManagedResource`、
    //! [`AmqpSubscriber`] impl `Subscriber`+`AckableSubscriber`+`ManagedResource`；去掉任一 impl 即编译
    //! 失败（anti-vacuity）。
    use core::marker::PhantomData;

    fn assert_managed_resource<T: diport::ManagedResource>(_: PhantomData<T>) {}
    fn assert_publisher<T: diport::Publisher>(_: PhantomData<T>) {}
    fn assert_subscriber<T: diport::Subscriber>(_: PhantomData<T>) {}
    fn assert_ackable_subscriber<T: diport::AckableSubscriber>(_: PhantomData<T>) {}

    #[test]
    fn impls_frozen_ports() {
        assert_publisher(PhantomData::<super::AmqpPublisher>);
        assert_managed_resource(PhantomData::<super::AmqpPublisher>);
        assert_subscriber(PhantomData::<super::AmqpSubscriber>);
        assert_managed_resource(PhantomData::<super::AmqpSubscriber>);
        assert_ackable_subscriber(PhantomData::<super::AmqpSubscriber>);
    }
}
