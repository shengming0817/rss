//! mqtt — RSS MQTT 设备传输 adapter（rumqttc，MQTT v5）。
//!
//! impl `diport` 已冻 DI port：[`MqttPublisher`]（`Publisher` + `ManagedResource`）+
//! [`MqttSubscriber`]（`Subscriber` + `ManagedResource`）。设备命令下行经 `Publisher` 发到 broker、
//! 上行遥测 / 回执经 `Subscriber` 收取。rumqttc 须调用方持续 poll `EventLoop`——故每条连接 spawn 一个
//! driver task 泵 eventloop（见 `publisher` / `subscriber`）。
//!
//! # per-domain 隔离（MQTT 无 vhost）
//!
//! adapter 从**单个 per-domain MQTT URL**（`mqtt://host[:port]`）连接。MQTT **无 vhost**（不同于 AMQP）。
//! **v1 明文 = 匿名**：`mqtt://` **禁止携带 userinfo 凭据**（fail-closed——凭据走明文 = 泄露；见
//! `conn::MqttUrlError::CredentialsRequireTls`），故 v1 跨域隔离经 broker 侧 **网络 / ACL（按 client-id）**；
//! **per-domain 凭据 / mTLS 认证须 `mqtts://`**（follow-up #1264）。**不**经 topic 命名前缀（命名前缀会把
//! 域身份泄进 wire 且可绕过，同 amqp 决策）。URL 由组合根注入；连接失败日志只经
//! `secure::redact_url_credentials` / `secure::redact_error`。
//!
//! # event_id 传播（去重锚点）
//!
//! `publish` 把 `PublishRequest.event_id` 盖进 v5 `correlation_data`，订阅侧读回填入 `Message.id`
//! （与 amqp `message_id` 传播对称），实现跨进程「至少一次 + 幂等去重」。
//!
//! # P6 传输边界
//!
//! QoS1 + **broker ACK 确认**（对标 amqp publisher confirms）：`publish` 等 PUBACK、`subscribe` 等 SUBACK
//! 才返回 `Ok`（broker 拒绝 / 断连 / 超时 ⇒ `Err`），故消费方〔outbox relay〕据 `Ok` 结算 published 是真
//! at-least-once（未确认的 publish 不被当成功）。入站消息**有界队列**（满则 drop+warn，不阻塞 driver）。
//! 不暴露手工 ack。MQTT 无 native DLX，app-level `$dead/<topic>` DLT / `SupportsRequeue=false` / HoL 规避 /
//! poison-as-ack / 背压 metric = follow-up（P1-8 #1265，对标 amqp 把手工 ack/DLX 推到 P7 ConsumerBase）。
//!
//! # feature 门控
//!
//! 真实 rumqttc broker I/O 在 `integration` feature 下编译；默认 build（无 feature）退化为 sealed-marker
//! 签名冻结壳（`todo!()` body），保 ADAPTER-PORT-FREEZE 默认 `cargo test` / `verify` 绿、不拉 broker
//! 客户端树。本 PR 仅明文 `mqtt://`（rumqttc TLS 后端 crypto provider license 不在 deny.toml allow-list）；
//! 生产 `mqtts://` / 设备 mTLS（依赖 softca〔已落地 PR #249〕，组合根 TLS 门禁）= follow-up #1264。
//!
//! ref: bytebeamio/rumqtt rumqttc/examples/asyncpubsub_v5.rs@main（MqttOptions → AsyncClient::new →
//! 循环 eventloop.poll() 驱动 + client.publish / Packet::Publish 收取），与 `adapters/amqp` 的
//! `take_until(token)` 流取消范式一致。

mod envelope;

#[cfg(feature = "integration")]
mod conn;
#[cfg(feature = "integration")]
mod publisher;
#[cfg(feature = "integration")]
mod subscriber;

#[cfg(not(feature = "integration"))]
mod fallback;

#[cfg(feature = "integration")]
pub use conn::MqttConnectError;
#[cfg(feature = "integration")]
pub use publisher::MqttPublisher;
#[cfg(feature = "integration")]
pub use subscriber::MqttSubscriber;

#[cfg(not(feature = "integration"))]
pub use fallback::{MqttPublisher, MqttSubscriber};

#[cfg(test)]
mod smoke {
    //! build smoke：编译期断言 adapter 已 impl 冻结的 diport DI port（PhantomData 绑定检查，不构造、
    //! 不执行 body）。两种 build 都过——默认 fallback（`todo!()`）/ `integration` 真实 rumqttc impl。
    //! INVARIANT: ADAPTER-PORT-FREEZE-03 { level = "Medium", exec = "manual/opt-in", source = "code" }—— [`MqttPublisher`] impl `Publisher`+`ManagedResource`、
    //! [`MqttSubscriber`] impl `Subscriber`+`ManagedResource`；去掉任一 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    fn assert_managed_resource<T: diport::ManagedResource>(_: PhantomData<T>) {}
    fn assert_publisher<T: diport::Publisher>(_: PhantomData<T>) {}
    fn assert_subscriber<T: diport::Subscriber>(_: PhantomData<T>) {}

    #[test]
    fn impls_frozen_ports() {
        assert_publisher(PhantomData::<super::MqttPublisher>);
        assert_managed_resource(PhantomData::<super::MqttPublisher>);
        assert_subscriber(PhantomData::<super::MqttSubscriber>);
        assert_managed_resource(PhantomData::<super::MqttSubscriber>);
    }
}
