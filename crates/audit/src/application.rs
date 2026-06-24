//! audit 应用层：session-created 订阅 handler（RW-G1 追踪弹）。
//!
//! 消费 identity 域发布的 `identity.session-created` event（跨域只经 contract），解码 payload →
//! 构造 [`diport::AuditEvent`] → 经注入的 [`diport::AuditSink`] 落审计。证明
//! identity 登录 → outbox → 分发 → audit append 接缝闭环的终点。
//!
//! 追踪弹边界（见 #999 计划）：跨域审计接缝是 flat [`diport::AuditEvent`]；audit domain 哈希链
//! （`AuditEntry` / `link_hash` / `verify_chain`，[`crate::domain`]）是域内持久化关注点，**保持冻结**，
//! 随真实持久化（postgres adapter）到 W 落地。
//!
//! # 接缝发现（RW-G1 surfaced）：AuditSink DI 经 **port 泛型** 而非 `Arc<DynAuditSink>`
//!
//! `SubscriberHandler::handle` 须返回 `Send` 的 `'static` future（被 eventexec 分发驱动 / `tokio::spawn`
//! 消费）。`diport` 的 Dyn wrapper 由 `#[trait_variant::make(AuditSink: Send)]` 生成 **Send 但非 Sync**，
//! 故 `Arc<DynAuditSink>`（ADR-003 列的注入形态之一）是 `!Send`、无法被 clone 进 `Send` future
//! 供多次调用的 async 消费者持有。本 handler 改为**泛型于 `AuditSink` port**（`Arc<S>`，`S: Send + Sync`，
//! 静态分发 DI），既保持 provider 可互换（trait bound）又产出 `Send` future，且**不改冻结的 diport**。
//! dyn-erased 注入路径的 Send/Sync 取舍是 diport 的待定项（见 PR 说明，留 review / W 评估）。
//!
//! ref: open-telemetry/opentelemetry-rust opentelemetry/src/logs/logger.rs@main（audit sink 接缝）

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bootstrap::{Domain, KernelError, Registry, SubscriberHandler, SubscriberHandlerError};
use consistency::ConsumerGroup;
use diport::{AuditEvent, AuditOutcome, AuditSink, Message};
use futures::future::BoxFuture;
use generated::event::identity_v1::{
    CONTRACT_ID as SESSION_CONTRACT_ID, IdentitySessionCreatedPayload, TOPIC as SESSION_TOPIC,
};

/// audit 域消费 session-created 事件的 consumer group（稳定标识，幂等去重 PK 第二维度）。
const AUDIT_SESSION_CREATED_GROUP: &str = "audit.session-created";

/// 审计资源类别（const literal，AuditEvent.resource_kind 要求 &'static str）。
const RESOURCE_KIND_SESSION: &str = "session";
/// 审计动作（const literal）。
const ACTION_LOGIN: &str = "login";

/// i64 unix 秒 → `SystemTime`（负值收口为 epoch）。
fn from_unix_secs(secs: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(secs).unwrap_or(0))
}

/// session-created 订阅 handler：解码 payload → 构造 [`AuditEvent`] → 经 [`AuditSink`] 落审计。
///
/// 泛型于 `AuditSink` port（见模块 rustdoc §接缝发现）：`Arc<S>` 可 clone 进 `Send` future。
pub struct SessionCreatedAuditHandler<S> {
    sink: Arc<S>,
}

impl<S> SessionCreatedAuditHandler<S>
where
    S: AuditSink + Send + Sync + 'static,
{
    /// 注入审计 sink（DI port）构造。
    pub fn new(sink: Arc<S>) -> Self {
        Self { sink }
    }
}

impl<S> SubscriberHandler for SessionCreatedAuditHandler<S>
where
    S: AuditSink + Send + Sync + 'static,
{
    fn handle(&self, message: Message) -> BoxFuture<'static, Result<(), SubscriberHandlerError>> {
        let sink = self.sink.clone();
        Box::pin(async move {
            // 审计管道失败不可静默（合规/运维盲点）：各失败路径结构化记录后再冒泡（Err→驱动侧 Nack）。
            // source 错误不进 Display（PII 边界），但 message_id 进日志便于关联。
            let msg_id = message.id.clone();
            let payload: IdentitySessionCreatedPayload = serde_json::from_slice(&message.payload)
                .map_err(|e| {
                tracing::error!(
                    message_id = msg_id.as_str(),
                    error = %e,
                    "audit handler: session-created payload decode failed"
                );
                SubscriberHandlerError::new(e)
            })?;
            // tenant fail-closed：非 canonical UUID 即拒（tenancy.md），不静默落空租户。
            let tenant = vocab::TenantId::parse(&payload.tenant_id).map_err(|e| {
                tracing::error!(
                    message_id = msg_id.as_str(),
                    error = %e,
                    "audit handler: non-canonical tenant, refusing to audit"
                );
                SubscriberHandlerError::new(e)
            })?;
            let event = AuditEvent {
                occurred_at: from_unix_secs(payload.occurred_at),
                principal_id: payload.subject,
                tenant_id: tenant,
                resource_kind: RESOURCE_KIND_SESSION,
                resource_id: payload.session_id,
                action: ACTION_LOGIN,
                outcome: AuditOutcome::Success,
                request_id: None,
                correlation_id: None,
            };
            sink.record(event).await.map_err(|e| {
                tracing::error!(
                    message_id = msg_id.as_str(),
                    error = %e,
                    "audit handler: sink record failed"
                );
                SubscriberHandlerError::new(e)
            })?;
            Ok(())
        })
    }
}

/// audit 域 bootstrap 生命周期：声明 session-created 订阅。
pub struct AuditDomain<S> {
    sink: Arc<S>,
}

impl<S> AuditDomain<S>
where
    S: AuditSink + Send + Sync + 'static,
{
    /// 注入审计 sink（DI port）构造。
    pub fn new(sink: Arc<S>) -> Self {
        Self { sink }
    }
}

impl<S> Domain for AuditDomain<S>
where
    S: AuditSink + Send + Sync + 'static,
{
    fn init(&self, reg: &mut Registry) -> Result<(), KernelError> {
        let group = ConsumerGroup::parse(AUDIT_SESSION_CREATED_GROUP)
            .map_err(|_| KernelError::Subscriber)?;
        reg.subscriber(
            SESSION_CONTRACT_ID,
            SESSION_TOPIC,
            group,
            Box::new(SessionCreatedAuditHandler::new(self.sink.clone())),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use diport::AuditSinkError;

    const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    // 域单测不依赖 adapter crate（rust-standards.md §命名）：AuditSink 替身在此手写。
    #[derive(Default)]
    struct CapturingSink {
        records: Mutex<Vec<AuditEvent>>,
    }
    impl AuditSink for CapturingSink {
        async fn record(&self, event: AuditEvent) -> Result<(), AuditSinkError> {
            self.records
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(event);
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), AuditSinkError> {
            Ok(())
        }
    }

    // 测试构造 / 断言用 expect：item-level carve-out（error-handling.md §Carve-out 要求 item-level）。
    #[allow(clippy::expect_used)]
    fn payload_bytes() -> Vec<u8> {
        let payload = IdentitySessionCreatedPayload {
            session_id: "sess-1".to_string(),
            subject: "alice-subject".to_string(),
            tenant_id: CANON_TENANT.to_string(),
            occurred_at: 1_000,
        };
        serde_json::to_vec(&payload).expect("encode")
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn handles_session_created_into_audit_event() {
        let sink = Arc::new(CapturingSink::default());
        let handler = SessionCreatedAuditHandler::new(sink.clone());

        handler
            .handle(Message::new("m-1", payload_bytes()))
            .await
            .expect("handle ok");

        let recs = sink.records.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].action, ACTION_LOGIN);
        assert_eq!(recs[0].resource_kind, RESOURCE_KIND_SESSION);
        assert_eq!(recs[0].resource_id, "sess-1");
        assert_eq!(recs[0].principal_id, "alice-subject");
        assert_eq!(recs[0].tenant_id.to_string(), CANON_TENANT);
        assert!(matches!(recs[0].outcome, AuditOutcome::Success));
        assert_eq!(
            recs[0].occurred_at,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000)
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rejects_undecodable_payload_without_recording() {
        let sink = Arc::new(CapturingSink::default());
        let handler = SessionCreatedAuditHandler::new(sink.clone());

        let result = handler
            .handle(Message::new("m-bad", b"not json".to_vec()))
            .await;
        assert!(result.is_err());
        assert_eq!(
            sink.records.lock().unwrap_or_else(|e| e.into_inner()).len(),
            0
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rejects_non_canonical_tenant() {
        let sink = Arc::new(CapturingSink::default());
        let handler = SessionCreatedAuditHandler::new(sink.clone());

        let payload = IdentitySessionCreatedPayload {
            session_id: "s".to_string(),
            subject: "x".to_string(),
            tenant_id: "NOT-A-UUID".to_string(),
            occurred_at: 1,
        };
        let bytes = serde_json::to_vec(&payload).expect("encode");
        let result = handler.handle(Message::new("m", bytes)).await;
        assert!(result.is_err());
        assert_eq!(
            sink.records.lock().unwrap_or_else(|e| e.into_inner()).len(),
            0
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn audit_domain_declares_session_created_subscriber() {
        let reg = bootstrap::compose(&[&AuditDomain::new(Arc::new(CapturingSink::default()))])
            .expect("compose ok");
        let subs = reg.into_subscribers();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].contract_id, SESSION_CONTRACT_ID);
        assert_eq!(subs[0].topic, SESSION_TOPIC);
        assert_eq!(subs[0].group.as_str(), AUDIT_SESSION_CREATED_GROUP);
    }
}
