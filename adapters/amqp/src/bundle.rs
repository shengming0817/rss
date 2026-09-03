//! amqp capability bundle（#1498 / RW-W-hardening）：把一个域 vhost 的 publisher + subscriber 装配 +
//! managed-resource/rollback 单源派生收口到单一装配出口，杜绝组合根回退多通道手写（D5）。
//!
//! 泛化自 pg `PgRuntimeDeps`/`PgInfraDeps`（#1422/#1423，ADR-010 §2.2）。amqp publisher/subscriber 是
//! **provider-agnostic transport infra**（非绑单一域的 repo），故落 [`AmqpInfraDeps`]——无 per-domain
//! `AmqpDomainDeps<D>`（amqp **per-domain 隔离经 vhost URL = per-connection**，非 sealed-caps type marker；
//! 每个域的 vhost 是独立 [`AmqpRuntimeDeps`] 实例，不在类型层分域）。
//!
//! ## per-vhost = per-connection（非单 conn 中心化）
//!
//! AMQP per-domain 隔离经 **vhost + role credential**，即 per-vhost = **per-connection**。
//! 故 bundle **不**把所有能力塞进单一 `Connection`——一个 [`AmqpRuntimeDeps`] 持**一个域 vhost** 的
//! publisher + subscriber（各自 `connect` 拿独立连接）；生产 private-CA 路径还要求两个不可互换的
//! role endpoint，避免同一 credential 同时获得 publish/consume 权限。
//!
//! ## INVARIANT
//!
//! - **AMQP-BUNDLE-CONN-01**（Hard）：bundle 私有持 `Arc<AmqpPublisher>` / `Arc<AmqpSubscriber>`，dispatch
//!   （port handle）与 guard（shutdown）共享同一 Arc——单源 lifecycle，不泄漏 raw `Connection`（沿用
//!   publisher/subscriber 的 raw-conn 私有封装）。每个 publisher/subscriber 各持**自己的**连接，guard 各关
//!   各的（一 guard 一 conn，无 double-close）。
//!
//! ## 单源装配（`runtime_resources`）
//!
//! adapter **不依赖 `bootstrap`**（与 pg adapter 一致），故经 [`AmqpRuntimeDeps::runtime_resources`] 单源
//! 派生 `Vec<Box<DynManagedResource>>`（仅 `diport` 类型），组合根
//! `module.resources.extend(deps.amqp.runtime_resources())` 装配进 `DomainModuleResult.resources`。
//! 当前产 publisher-guard + subscriber-guard（各关其 connection）；杜绝逐 channel 手写。
//!
//! ## 开源对标
//!
//! `ref: oxidecomputer/omicron nexus/src/context.rs@8eb92537bd12598dfd2c861f897a88962fabf684`——
//! `Arc<ServerContext>` 共享 infra clone 进各 server（RSS `SharedRuntimeDeps` 同 lineage）。本模块对应：
//! `Arc<AmqpPublisher/Subscriber>` 私有持有 + `infra()` 派发受控句柄 + guard 单源 rollback。
//!
//! ## Live 接入
//!
//! amqp bundle live 接入已落地（#1251）：组合根 `runtime` 经 topology-gated resolver
//! （`bootstrap::eventtransport::resolve`）注入 publisher（outbox relay 发布）+ subscriber（consumer 订阅）
//! 到 `eventexec`。
//!
//! ## 测试覆盖
//!
//! amqp bundle 触碰 lapin `Connection`/`Channel`（无法在无 broker 下构造或 mock），故**无法**像
//! redis/vault bundle 那样写无后端单元测试。其覆盖经
//! `adapters/amqp/tests/integration.rs::integration_bundle_dispatch_and_single_source_resources`
//! （真实 RabbitMQ testcontainer）。纯函数（`build_properties`/`extract_metadata`）走 crate 内单元测试；
//! 连接相关逻辑（bundle connect / guard shutdown）走 integration feature。

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use diport::{
    AckableSubscriber, DeliveryStream, DynAckableSubscriber, DynManagedResource, DynPublisher,
    ManagedResource, PublishRequest, Publisher, PublisherError, ShutdownError, SubscriberError,
    Topic,
};
use tokio_util::sync::CancellationToken;

use crate::conn::AmqpConnectError;
use crate::publisher::AmqpPublisher;
use crate::subscriber::AmqpSubscriber;

/// AMQP endpoint carrying only publisher authority. It is intentionally not interchangeable with
/// [`AmqpSubscriberEndpoint`], so production assembly code must bind each credential to its role.
pub struct AmqpPublisherEndpoint(secure::AmqpEndpoint);

impl AmqpPublisherEndpoint {
    #[must_use]
    pub fn new(endpoint: secure::AmqpEndpoint) -> Self {
        Self(endpoint)
    }
}

/// AMQP endpoint carrying only subscriber authority. It is intentionally not interchangeable with
/// [`AmqpPublisherEndpoint`], so a subscriber credential cannot be wired into a publisher slot.
pub struct AmqpSubscriberEndpoint(secure::AmqpEndpoint);

impl AmqpSubscriberEndpoint {
    #[must_use]
    pub fn new(endpoint: secure::AmqpEndpoint) -> Self {
        Self(endpoint)
    }
}

async fn connect_second_or_rollback<P, S, E, Second, Rollback, RollbackFuture>(
    first: P,
    second: Second,
    rollback: Rollback,
) -> Result<(P, S), (E, Option<ShutdownError>)>
where
    Second: Future<Output = Result<S, E>>,
    Rollback: FnOnce(P) -> RollbackFuture,
    RollbackFuture: Future<Output = Result<(), ShutdownError>>,
{
    match second.await {
        Ok(second) => Ok((first, second)),
        Err(primary) => {
            let cleanup = rollback(first).await.err();
            Err((primary, cleanup))
        }
    }
}

/// 组合根级 amqp 能力包（**一个域 vhost**）：私有持 `Arc<AmqpPublisher>` + `Arc<AmqpSubscriber>`，派发
/// transport 能力句柄并产出 shutdown 资源。生产环境经
/// [`AmqpRuntimeDeps::connect_with_private_ca`] 构造。`Clone` 廉价（仅 `Arc` clone）。
#[derive(Clone)]
pub struct AmqpRuntimeDeps {
    publisher: Arc<AmqpPublisher>,
    subscriber: Arc<AmqpSubscriber>,
}

/// Opaque publisher transport readiness; no raw connection/channel escapes the adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AmqpPublisherReadinessSnapshot(bool);

impl AmqpPublisherReadinessSnapshot {
    #[must_use]
    pub const fn is_ready(self) -> bool {
        self.0
    }
}

/// Opaque subscriber transport readiness; readiness requires its connection and every activated
/// subscription channel to remain connected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AmqpSubscriberReadinessSnapshot(bool);

impl AmqpSubscriberReadinessSnapshot {
    #[must_use]
    pub const fn is_ready(self) -> bool {
        self.0
    }
}

impl AmqpRuntimeDeps {
    #[must_use]
    pub fn publisher_readiness(&self) -> AmqpPublisherReadinessSnapshot {
        AmqpPublisherReadinessSnapshot(self.publisher.readiness_snapshot())
    }

    #[must_use]
    pub fn subscriber_readiness(&self) -> AmqpSubscriberReadinessSnapshot {
        AmqpSubscriberReadinessSnapshot(self.subscriber.readiness_snapshot())
    }

    /// Test-only default-root seam for local/plaintext fixtures. Production `backend` builds do not
    /// contain this method; shipped feature graphs also reject `integration-test-support`.
    ///
    /// `name` 应使用该 vhost 所属**域名 kebab-case**（如 `"identity"` / `"settings"`），产生
    /// `<域>-pub` / `<域>-sub` 的稳定 `ManagedResource` 名，供 ShutdownStack 关停日志与告警规则建立
    /// 稳定标签（对比 redis 固定 `"redis"` / vault 固定 `"vault-secret-resolver"`）。
    ///
    /// Publisher / subscriber each retain an independent connection and preserve rollback behavior.
    #[cfg(any(test, feature = "integration-test-support"))]
    pub async fn connect_with_webpki_for_test(
        endpoint: &secure::AmqpEndpoint,
        name: &str,
        publish_timeout: Duration,
    ) -> Result<Self, AmqpConnectError> {
        let publisher = Arc::new(
            AmqpPublisher::connect_with_webpki_for_test(
                endpoint,
                format!("{name}-pub"),
                publish_timeout,
            )
            .await?,
        );
        let publisher_name = ManagedResource::name(publisher.as_ref()).to_owned();
        let (publisher, subscriber) = match connect_second_or_rollback(
            publisher,
            AmqpSubscriber::connect_with_webpki_for_test(endpoint, format!("{name}-sub")),
            |publisher: Arc<AmqpPublisher>| async move {
                ManagedResource::shutdown(publisher.as_ref()).await
            },
        )
        .await
        {
            Ok((publisher, subscriber)) => (publisher, Arc::new(subscriber)),
            Err((primary, cleanup)) => {
                if let Some(cleanup) = cleanup {
                    tracing::warn!(
                        target: "amqp",
                        resource = publisher_name,
                        error = %secure::redact_error(&cleanup),
                        "partial AMQP bundle cleanup failed; preserving subscriber connect error"
                    );
                }
                return Err(primary);
            }
        };
        Ok(Self {
            publisher,
            subscriber,
        })
    }

    /// Production AMQPS assembly path with distinct publisher/subscriber endpoint capabilities and
    /// a required, explicitly configured private CA. There is no single-endpoint or default-trust
    /// production fallback.
    pub async fn connect_with_private_ca(
        publisher_endpoint: &AmqpPublisherEndpoint,
        subscriber_endpoint: &AmqpSubscriberEndpoint,
        ca: crate::AmqpPrivateCa,
        name: &str,
        publish_timeout: Duration,
    ) -> Result<Self, AmqpConnectError> {
        let publisher = Arc::new(
            AmqpPublisher::connect_with_private_ca(
                &publisher_endpoint.0,
                format!("{name}-pub"),
                publish_timeout,
                &ca,
            )
            .await?,
        );
        let publisher_name = ManagedResource::name(publisher.as_ref()).to_owned();
        let (publisher, subscriber) = match connect_second_or_rollback(
            publisher,
            AmqpSubscriber::connect_with_private_ca(
                &subscriber_endpoint.0,
                format!("{name}-sub"),
                &ca,
            ),
            |publisher: Arc<AmqpPublisher>| async move {
                ManagedResource::shutdown(publisher.as_ref()).await
            },
        )
        .await
        {
            Ok((publisher, subscriber)) => (publisher, Arc::new(subscriber)),
            Err((primary, cleanup)) => {
                if let Some(cleanup) = cleanup {
                    tracing::warn!(
                        target: "amqp",
                        resource = publisher_name,
                        error = %secure::redact_error(&cleanup),
                        "partial AMQP bundle cleanup failed; preserving subscriber connect error"
                    );
                }
                return Err(primary);
            }
        };
        Ok(Self {
            publisher,
            subscriber,
        })
    }

    /// 派发 framework/global transport 能力句柄 [`AmqpInfraDeps`]——publisher / subscriber 是
    /// provider-agnostic transport infra（非绑单一域 repo），故不进（不存在的）per-domain 句柄。
    #[must_use]
    pub fn infra(&self) -> AmqpInfraDeps {
        AmqpInfraDeps {
            publisher: Arc::clone(&self.publisher),
            subscriber: Arc::clone(&self.subscriber),
        }
    }

    /// Integration-only access to the typed publisher fault/recovery seam. It does not expose the
    /// underlying connection, channel, trust roots, or a way to replace the production trust.
    #[cfg(feature = "integration-test-support")]
    #[must_use]
    pub fn publisher_for_integration_test(&self) -> &AmqpPublisher {
        self.publisher.as_ref()
    }

    /// Integration-only access to the typed subscriber quarantine observation seam. It exposes
    /// neither the underlying connection/channel nor arbitrary queue operations.
    #[cfg(feature = "integration-test-support")]
    #[must_use]
    pub fn subscriber_for_integration_test(&self) -> &AmqpSubscriber {
        self.subscriber.as_ref()
    }

    /// **单源** managed-resource/rollback 派生：组合根
    /// `module.resources.extend(deps.amqp.runtime_resources())` 即装配该 vhost 全部受管连接
    /// （publisher-guard + subscriber-guard，各关其 connection），杜绝逐 channel 手写 `register_detached`（D5）。
    #[must_use]
    pub fn runtime_resources(&self) -> Vec<Box<DynManagedResource<'static>>> {
        vec![
            DynManagedResource::new_box(AmqpPublisherGuard(Arc::clone(&self.publisher))),
            DynManagedResource::new_box(AmqpSubscriberGuard(Arc::clone(&self.subscriber))),
        ]
    }
}

/// framework/global amqp transport 能力句柄（`Clone`，provider-agnostic、非单域）。
///
/// 私有持 `Arc<AmqpPublisher>` / `Arc<AmqpSubscriber>`，经 [`AmqpRuntimeDeps::infra`] 派发；派发 DI-ready
/// `Box<DynPublisher>` / `Box<DynAckableSubscriber>`（经 delegating handle 共享 bundle 的 Arc，不泄漏 raw
/// connection，AMQP-BUNDLE-CONN-01）。port 句柄的 `shutdown` 关 channel（port-local）；connection lifecycle
/// 由 [`AmqpRuntimeDeps::runtime_resources`] 的 guard 单源关闭。
#[derive(Clone)]
pub struct AmqpInfraDeps {
    publisher: Arc<AmqpPublisher>,
    subscriber: Arc<AmqpSubscriber>,
}

impl AmqpInfraDeps {
    /// 事件发布句柄（`Box<DynPublisher>`，注入 `eventexec` relay）。经 [`SharedAmqpPublisher`] 共享 bundle
    /// 的 `Arc<AmqpPublisher>`——`Publisher::shutdown` 关 publisher channel（port-local）；connection 由
    /// runtime_resources guard 关。
    #[must_use]
    pub fn publisher(&self) -> Box<DynPublisher<'static>> {
        DynPublisher::new_box(SharedAmqpPublisher(Arc::clone(&self.publisher)))
    }

    /// 事件订阅句柄（`Box<DynAckableSubscriber>`，注入 `eventexec` consumer）。经 [`SharedAmqpSubscriber`]
    /// 共享 bundle 的 `Arc<AmqpSubscriber>`——每订阅独立 channel（token cancel 等待本订阅
    /// `basic.cancel-ok`）；connection
    /// 由 runtime_resources guard 关。
    #[must_use]
    pub fn subscriber(&self) -> Box<DynAckableSubscriber<'static>> {
        DynAckableSubscriber::new_box(SharedAmqpSubscriber(Arc::clone(&self.subscriber)))
    }
}

/// `Arc<AmqpPublisher>` 的 `Publisher` delegating handle——`DynPublisher::new_box` 需 owned `impl Publisher`，
/// 而 `Arc<AmqpPublisher>` 无 blanket impl，故经 newtype 委托（让 port dispatch 与 shutdown guard 共享同一 Arc，
/// 不泄漏 Arc 本身）。`shutdown` 委托 publisher 的 **port-local** `Publisher::shutdown`（关 channel）。
struct SharedAmqpPublisher(Arc<AmqpPublisher>);

impl Publisher for SharedAmqpPublisher {
    async fn publish(&self, request: PublishRequest) -> Result<(), PublisherError> {
        Publisher::publish(self.publisher(), request).await
    }

    async fn shutdown(&self) -> Result<(), PublisherError> {
        // UFCS 消歧：AmqpPublisher 同时 impl Publisher + ManagedResource（各有 shutdown）。port-local
        // shutdown 关 channel；connection 由 AmqpPublisherGuard（ManagedResource）单源关。
        Publisher::shutdown(self.publisher()).await
    }
}

impl SharedAmqpPublisher {
    fn publisher(&self) -> &AmqpPublisher {
        self.0.as_ref()
    }
}

/// `Arc<S>` 的 `AckableSubscriber` delegating handle（同 [`SharedAmqpPublisher`] 范式）。
struct SharedAmqpSubscriber<S>(Arc<S>);

impl<S> AckableSubscriber for SharedAmqpSubscriber<S>
where
    S: AckableSubscriber + Sync,
{
    fn prepare_ackable(
        &self,
        topic: Topic,
    ) -> impl std::future::Future<Output = Result<(), SubscriberError>> + Send {
        AckableSubscriber::prepare_ackable(self.0.as_ref(), topic)
    }

    async fn subscribe_ackable(
        &self,
        topic: Topic,
        token: CancellationToken,
    ) -> Result<DeliveryStream, SubscriberError> {
        AckableSubscriber::subscribe_ackable(self.0.as_ref(), topic, token).await
    }

    async fn shutdown(&self) -> Result<(), SubscriberError> {
        // Shared port 不拥有 connection；token cancel 只停止订阅的新投递，connection 由
        // AmqpSubscriberGuard（runtime_resources）单源关闭，避免 bundle 派发句柄与 guard double-close。
        Ok(())
    }
}

/// `Arc<AmqpPublisher>` 的 `ManagedResource` guard wrapper——`Arc` 非 fundamental ⇒ newtype 委托（对标
/// `PgStoreGuard`）。`shutdown` 委托 publisher 的 `ManagedResource::shutdown`（关 connection，单源 rollback）。
/// crate 内可见（`pub(crate)`）：组合根只经 `runtime_resources()` 消费 `Box<DynManagedResource>`，
/// 无需命名 guard 类型本身。
pub(crate) struct AmqpPublisherGuard(Arc<AmqpPublisher>);

impl ManagedResource for AmqpPublisherGuard {
    fn name(&self) -> &str {
        ManagedResource::name(self.0.as_ref())
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        // UFCS 消歧：取 ManagedResource::shutdown（关 connection），非 Publisher::shutdown（关 channel）。
        ManagedResource::shutdown(self.0.as_ref()).await
    }
}

/// `Arc<AmqpSubscriber>` 的 `ManagedResource` guard wrapper（同 [`AmqpPublisherGuard`] 范式）。
/// crate 内可见（`pub(crate)`）：组合根只经 `runtime_resources()` 消费 `Box<DynManagedResource>`，
/// 无需命名 guard 类型本身。
pub(crate) struct AmqpSubscriberGuard(Arc<AmqpSubscriber>);

impl ManagedResource for AmqpSubscriberGuard {
    fn name(&self) -> &str {
        ManagedResource::name(self.0.as_ref())
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        ManagedResource::shutdown(self.0.as_ref()).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use diport::{AckableSubscriber, DeliveryStream, SubscriberError, Topic};
    use tokio_util::sync::CancellationToken;

    use super::{SharedAmqpSubscriber, connect_second_or_rollback};

    #[derive(Default)]
    struct RecordingSubscriber {
        prepare_called: AtomicBool,
        subscribe_called: AtomicBool,
        shutdown_calls: AtomicUsize,
    }

    impl AckableSubscriber for RecordingSubscriber {
        fn prepare_ackable(
            &self,
            _topic: Topic,
        ) -> impl std::future::Future<Output = Result<(), SubscriberError>> + Send {
            self.prepare_called.store(true, Ordering::SeqCst);
            std::future::ready(Ok(()))
        }

        async fn subscribe_ackable(
            &self,
            _topic: Topic,
            _token: CancellationToken,
        ) -> Result<DeliveryStream, SubscriberError> {
            self.subscribe_called.store(true, Ordering::SeqCst);
            Ok(Box::pin(futures::stream::empty()))
        }

        async fn shutdown(&self) -> Result<(), SubscriberError> {
            self.shutdown_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn shared_subscriber_port_delegates_subscribe() -> Result<(), SubscriberError> {
        let inner = Arc::new(RecordingSubscriber::default());
        let handle = SharedAmqpSubscriber(Arc::clone(&inner));

        let _stream = AckableSubscriber::subscribe_ackable(
            &handle,
            Topic::new("session.created"),
            CancellationToken::new(),
        )
        .await?;

        assert!(inner.subscribe_called.load(Ordering::SeqCst));
        Ok(())
    }

    #[tokio::test]
    async fn shared_subscriber_port_delegates_topology_preparation() -> Result<(), SubscriberError>
    {
        let inner = Arc::new(RecordingSubscriber::default());
        let handle = SharedAmqpSubscriber(Arc::clone(&inner));

        AckableSubscriber::prepare_ackable(&handle, Topic::new("session.created")).await?;

        assert!(inner.prepare_called.load(Ordering::SeqCst));
        Ok(())
    }

    #[tokio::test]
    async fn shared_subscriber_port_shutdown_is_noop() -> Result<(), SubscriberError> {
        let inner = Arc::new(RecordingSubscriber::default());
        let handle = SharedAmqpSubscriber(Arc::clone(&inner));

        AckableSubscriber::shutdown(&handle).await?;

        assert_eq!(inner.shutdown_calls.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[tokio::test]
    async fn second_connect_failure_rolls_back_first_and_preserves_primary()
    -> Result<(), &'static str> {
        let cleanup_called = Arc::new(AtomicBool::new(false));
        let cleanup_evidence = Arc::clone(&cleanup_called);

        let result = connect_second_or_rollback(
            "publisher",
            async { Err::<(), _>("subscriber-primary") },
            move |first| async move {
                assert_eq!(first, "publisher");
                cleanup_evidence.store(true, Ordering::SeqCst);
                Err(diport::ShutdownError::new(std::io::Error::other(
                    "cleanup-secondary",
                )))
            },
        )
        .await;

        let Err((primary, cleanup)) = result else {
            return Err("second connect must fail");
        };
        assert_eq!(primary, "subscriber-primary");
        assert!(cleanup.is_some(), "cleanup failure must remain diagnostic");
        assert!(cleanup_called.load(Ordering::SeqCst));
        Ok(())
    }

    #[tokio::test]
    async fn successful_second_connect_does_not_rollback_first() -> Result<(), &'static str> {
        let cleanup_called = Arc::new(AtomicBool::new(false));
        let cleanup_evidence = Arc::clone(&cleanup_called);

        let result = connect_second_or_rollback(
            "publisher",
            async { Ok::<_, &'static str>("subscriber") },
            move |_| async move {
                cleanup_evidence.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;

        let Ok(pair) = result else {
            return Err("pair must succeed");
        };
        assert_eq!(pair, ("publisher", "subscriber"));
        assert!(!cleanup_called.load(Ordering::SeqCst));
        Ok(())
    }
}
