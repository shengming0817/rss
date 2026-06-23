//! amqp — RSS AMQP 事件传输 adapter（lapin）。
//!
//! impl `diport` 已冻 DI port：[`AmqpPublisher`]（`Publisher` + `ManagedResource`）+
//! [`AmqpSubscriber`]（`Subscriber` + `ManagedResource`）。生产事件主干——relay 经 `Publisher`
//! 把已持久化 outbox entry 发到跨进程 broker，consumer 经 `Subscriber` 收取。
//!
//! # per-domain vhost/credential 隔离
//!
//! adapter 从**单个 per-domain AMQP URL**（`amqp://user:pass@host/vhost`）连接——隔离经 broker
//! 侧的 **vhost + credential**（operator 为每个域 provision 独立 vhost/user），**不**经 exchange/queue
//! 命名前缀（命名前缀会把域身份泄进 wire 且可绕过）。URL 由组合根经 `bootstrap::eventtransport` 决策
//! 注入。凭据 non-leak：连接失败日志只经 `secure::redact_url_credentials` / `secure::redact_error`。
//!
//! # P6 传输边界（auto-ack）
//!
//! [`AmqpSubscriber::subscribe`] 用 `no_ack = true`（auto-ack）：broker 投递即出队，stream 产出无 ack
//! 义务的 [`diport::Message`]（`Message`/`MessageStream` 类型层不携 acker）。这是 **P6「只做传输」边界**；
//! 手工 ack / Disposition 驱动 / DLX 由 **P7 ConsumerBase** 接管（届时加 manual-ack subscribe 变体 +
//! `DeliveryOutcome` seam）。代价：在途消息于崩溃窗口 at-most-once——P6 可接受，P7 兑现 at-least-once。
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
    //! [`AmqpSubscriber`] impl `Subscriber`+`ManagedResource`；去掉任一 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    fn assert_managed_resource<T: diport::ManagedResource>(_: PhantomData<T>) {}
    fn assert_publisher<T: diport::Publisher>(_: PhantomData<T>) {}
    fn assert_subscriber<T: diport::Subscriber>(_: PhantomData<T>) {}

    #[test]
    fn impls_frozen_ports() {
        assert_publisher(PhantomData::<super::AmqpPublisher>);
        assert_managed_resource(PhantomData::<super::AmqpPublisher>);
        assert_subscriber(PhantomData::<super::AmqpSubscriber>);
        assert_managed_resource(PhantomData::<super::AmqpSubscriber>);
    }
}
