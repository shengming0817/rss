//! sealed-marker 签名冻结壳（无 `backend` feature）——保 ADAPTER-PORT-FREEZE-01 默认 build 绿。
//!
//! body = `todo!()`：真实 lapin broker I/O 在 `backend` feature 下编译（见 `publisher` / `subscriber`
//! 模块）；默认 build 不拉 broker 客户端树。crate 保持 forbid(unsafe_code)（继承 workspace lints，
//! 不 invoke dynosaur 宏）。
//!
//! **私有字段 `(())` ⇒ 外部 crate 不可构造**：生产组合根（`server`/`rss` 经 deny.toml 可依赖 amqp）即便
//! 在默认 build 拿到这些类型，也无法 mint 实例（无 `connect`、无公开字段），故 `todo!()` body 永不可达——
//! 杜绝生产路径拿到 panic-on-call provider（review F4）。smoke test 仅 PhantomData 绑定检查、不构造。
//!
//! **Freeze（#1974）**：本例外仅限当前 `AmqpPublisher` / `AmqpSubscriber` feature-off 私有 tuple marker。
//! 禁止新增公开 constructor / factory / `Default` / `Clone` / deserialize / test-support mint 或
//! production consumer；禁止复制到其它 adapter。清理 `todo!()` 时须保留不可构造边界或改走 `backend`，
//! 不得误删签名面。

use diport::{
    AckableSubscriber, DeliveryStream, PublishRequest, Publisher, PublisherError, SubscriberError,
    Topic,
};
use rss_runtime::{ManagedResource, ShutdownError};
use tokio_util::sync::CancellationToken;

/// AMQP 发布 adapter（sealed-marker；真实 lapin impl 见 `backend` feature）。私有字段 ⇒ 外部不可构造。
pub struct AmqpPublisher(());

/// AMQP 订阅 adapter（sealed-marker；真实 lapin impl 见 `backend` feature）。私有字段 ⇒ 外部不可构造。
pub struct AmqpSubscriber(());

impl Publisher for AmqpPublisher {
    async fn publish(&self, _request: PublishRequest) -> Result<(), PublisherError> {
        // reason: sealed-marker 占位——仅签名冻结（ADAPTER-PORT-FREEZE-01），真实实现在 backend feature。
        todo!()
    }

    async fn shutdown(&self) -> Result<(), PublisherError> {
        // reason: sealed-marker 占位——仅签名冻结（ADAPTER-PORT-FREEZE-01），真实实现在 backend feature。
        todo!()
    }
}

impl ManagedResource for AmqpPublisher {
    fn name(&self) -> &str {
        // reason: sealed-marker 占位——仅签名冻结（ADAPTER-PORT-FREEZE-01），真实实现在 backend feature。
        todo!()
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        // reason: sealed-marker 占位——仅签名冻结（ADAPTER-PORT-FREEZE-01），真实实现在 backend feature。
        todo!()
    }
}

impl ManagedResource for AmqpSubscriber {
    fn name(&self) -> &str {
        // reason: sealed-marker 占位——仅签名冻结（ADAPTER-PORT-FREEZE-01），真实实现在 backend feature。
        todo!()
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        // reason: sealed-marker 占位——仅签名冻结（ADAPTER-PORT-FREEZE-01），真实实现在 backend feature。
        todo!()
    }
}

impl AckableSubscriber for AmqpSubscriber {
    async fn subscribe_ackable(
        &self,
        _topic: Topic,
        _token: CancellationToken,
    ) -> Result<DeliveryStream, SubscriberError> {
        // reason: sealed-marker 占位——仅签名冻结（ADAPTER-PORT-FREEZE-01），真实实现在 backend feature。
        todo!()
    }

    async fn shutdown(&self) -> Result<(), SubscriberError> {
        // reason: sealed-marker 占位——仅签名冻结（ADAPTER-PORT-FREEZE-01），真实实现在 backend feature。
        todo!()
    }
}
