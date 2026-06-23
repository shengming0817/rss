//! sealed-marker 签名冻结壳（无 `integration` feature）——保 ADAPTER-PORT-FREEZE-01 默认 build 绿。
//!
//! body = `todo!()`：真实 lapin broker I/O 在 `integration` feature 下编译（见 `publisher` / `subscriber`
//! 模块）；默认 build 不拉 broker 客户端树。crate 保持 forbid(unsafe_code)（继承 workspace lints，
//! 不 invoke dynosaur 宏）。
//!
//! **私有字段 `(())` ⇒ 外部 crate 不可构造**：生产组合根（`server`/`rss` 经 deny.toml 可依赖 amqp）即便
//! 在默认 build 拿到这些类型，也无法 mint 实例（无 `connect`、无公开字段），故 `todo!()` body 永不可达——
//! 杜绝生产路径拿到 panic-on-call provider（review F4）。smoke test 仅 PhantomData 绑定检查、不构造。

use diport::{
    ManagedResource, MessageStream, PublishRequest, Publisher, PublisherError, ShutdownError,
    Subscriber, SubscriberError, Topic,
};
use tokio_util::sync::CancellationToken;

/// AMQP 发布 adapter（sealed-marker；真实 lapin impl 见 `integration` feature）。私有字段 ⇒ 外部不可构造。
pub struct AmqpPublisher(());

/// AMQP 订阅 adapter（sealed-marker；真实 lapin impl 见 `integration` feature）。私有字段 ⇒ 外部不可构造。
pub struct AmqpSubscriber(());

impl Publisher for AmqpPublisher {
    async fn publish(&self, _request: PublishRequest) -> Result<(), PublisherError> {
        // reason: sealed-marker 占位——仅签名冻结（ADAPTER-PORT-FREEZE-01），真实实现在 integration feature。
        todo!()
    }

    async fn shutdown(&self) -> Result<(), PublisherError> {
        // reason: sealed-marker 占位——仅签名冻结（ADAPTER-PORT-FREEZE-01），真实实现在 integration feature。
        todo!()
    }
}

impl ManagedResource for AmqpPublisher {
    fn name(&self) -> &str {
        // reason: sealed-marker 占位——仅签名冻结（ADAPTER-PORT-FREEZE-01），真实实现在 integration feature。
        todo!()
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        // reason: sealed-marker 占位——仅签名冻结（ADAPTER-PORT-FREEZE-01），真实实现在 integration feature。
        todo!()
    }
}

impl Subscriber for AmqpSubscriber {
    async fn subscribe(
        &self,
        _topic: Topic,
        _token: CancellationToken,
    ) -> Result<MessageStream, SubscriberError> {
        // reason: sealed-marker 占位——仅签名冻结（ADAPTER-PORT-FREEZE-01），真实实现在 integration feature。
        todo!()
    }

    async fn shutdown(&self) -> Result<(), SubscriberError> {
        // reason: sealed-marker 占位——仅签名冻结（ADAPTER-PORT-FREEZE-01），真实实现在 integration feature。
        todo!()
    }
}

impl ManagedResource for AmqpSubscriber {
    fn name(&self) -> &str {
        // reason: sealed-marker 占位——仅签名冻结（ADAPTER-PORT-FREEZE-01），真实实现在 integration feature。
        todo!()
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        // reason: sealed-marker 占位——仅签名冻结（ADAPTER-PORT-FREEZE-01），真实实现在 integration feature。
        todo!()
    }
}
