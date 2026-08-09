//! PostgreSQL ConsumerTx handlers.
//!
//! These handlers are the durable consumer path for generated subscriptions. They keep
//! `TenantTx` sealed inside this crate: runtime chooses a handler, but cannot construct or
//! escape transaction capability values.

use std::sync::Arc;

#[cfg(feature = "domain-audit")]
use audit::ports::{
    AuditChainHasher, AuditEventKind, AuditEventRecordError, AuditRecord,
    audit_record_from_event_message, security_audit_command_from_message,
};
use consistency::idempotency::LeaseOutcome;
use consistency::{EngineErrorKind, IdemKey, InboxReceiptContext, LeaseToken};
#[cfg(feature = "domain-settings")]
use consistency::{HandleResult, Settled};
#[cfg(feature = "domain-audit")]
use primitives::MacVerifier;

#[cfg(feature = "domain-audit")]
use crate::cotx::settings_audit::audit_write_tx;
use crate::cotx::{ServingWriteLane, TenantDb, infra_tenant_scope};
use crate::inbox::commit_in_tx;
use crate::pool::VerifiedPgWriteStore;

/// Opaque evidence that the postgres ConsumerTx unit committed while its inbox lease was held.
///
/// The field and constructor stay provider-private. Runtime and eventexec may carry and consume the
/// type, but downstream code cannot mint a value that would authorize a broker Ack.
pub struct PgConsumerTxCommitProof {
    _provider_owned: (),
}

impl PgConsumerTxCommitProof {
    fn committed() -> Self {
        Self {
            _provider_owned: (),
        }
    }
}

/// Provider-owned result of one ConsumerTx attempt.
///
/// Only the concrete Postgres handler methods can return `Committed` with the opaque proof.
/// The Ack-authorizing consumer trait and runner live crate-private in the runtime assembly.
pub enum PgConsumerTxOutcome {
    Committed(PgConsumerTxCommitProof),
    Requeue(PgConsumerTxRequeue),
    LeaseLost { summary: &'static str },
    Reject { summary: &'static str },
}

pub struct PgConsumerTxRequeue {
    category: PgConsumerTxRequeueCategory,
    summary: &'static str,
}

enum PgConsumerTxRequeueCategory {
    #[cfg(feature = "domain-settings")]
    HandlerTransient,
    CommitUnknown,
}

impl PgConsumerTxOutcome {
    #[cfg(feature = "domain-settings")]
    fn handler_transient(summary: &'static str) -> Self {
        Self::Requeue(PgConsumerTxRequeue {
            category: PgConsumerTxRequeueCategory::HandlerTransient,
            summary,
        })
    }

    fn commit_unknown(summary: &'static str) -> Self {
        Self::Requeue(PgConsumerTxRequeue {
            category: PgConsumerTxRequeueCategory::CommitUnknown,
            summary,
        })
    }
}

impl PgConsumerTxRequeue {
    #[must_use]
    pub fn is_commit_unknown(&self) -> bool {
        matches!(self.category, PgConsumerTxRequeueCategory::CommitUnknown)
    }

    #[must_use]
    pub fn summary(&self) -> &'static str {
        self.summary
    }
}

#[cfg(feature = "domain-audit")]
/// Postgres-backed ConsumerTx audit handler.
pub struct PgAuditConsumerTx<M: MacVerifier> {
    pool: TenantDb<ServingWriteLane>,
    hasher: Arc<AuditChainHasher<M>>,
    kind: AuditEventKind,
}

#[cfg(feature = "domain-audit")]
impl<M> PgAuditConsumerTx<M>
where
    M: MacVerifier + Send + Sync + 'static,
{
    pub(crate) fn session_created(
        store: &VerifiedPgWriteStore,
        hasher: AuditChainHasher<M>,
    ) -> Self {
        Self::new(store, hasher, AuditEventKind::SessionCreated)
    }

    pub(crate) fn role_assigned(store: &VerifiedPgWriteStore, hasher: AuditChainHasher<M>) -> Self {
        Self::new(store, hasher, AuditEventKind::RoleAssigned)
    }

    pub(crate) fn role_revoked(store: &VerifiedPgWriteStore, hasher: AuditChainHasher<M>) -> Self {
        Self::new(store, hasher, AuditEventKind::RoleRevoked)
    }

    pub(crate) fn policy_updated(
        store: &VerifiedPgWriteStore,
        hasher: AuditChainHasher<M>,
    ) -> Self {
        Self::new(store, hasher, AuditEventKind::PolicyUpdated)
    }

    pub(crate) fn security_event(
        store: &VerifiedPgWriteStore,
        hasher: AuditChainHasher<M>,
    ) -> Self {
        Self::new(store, hasher, AuditEventKind::SecurityEvent)
    }

    fn new(
        store: &VerifiedPgWriteStore,
        hasher: AuditChainHasher<M>,
        kind: AuditEventKind,
    ) -> Self {
        Self {
            pool: TenantDb::<ServingWriteLane>::new(store),
            hasher: Arc::new(hasher),
            kind,
        }
    }

    async fn handle_attempt(
        &self,
        message: diport::Message,
        ctx: InboxReceiptContext,
        key: IdemKey,
        lease: LeaseToken,
    ) -> PgConsumerTxOutcome {
        if self.kind == AuditEventKind::SecurityEvent {
            return self.handle_security_attempt(message, ctx, key, lease).await;
        }
        let record = match self.validated_record_from_message(&message, &ctx) {
            Ok(record) => record,
            Err(outcome) => return outcome,
        };
        pg_consumer_tx_outcome(
            "audit",
            self.append_and_mark_done(record, ctx, key, lease).await,
        )
    }

    async fn handle_security_attempt(
        &self,
        message: diport::Message,
        ctx: InboxReceiptContext,
        key: IdemKey,
        lease: LeaseToken,
    ) -> PgConsumerTxOutcome {
        let command = match security_audit_command_from_message(&message) {
            Ok(command) if command.tenant() == ctx.tenant_id() => command,
            Ok(command) => {
                return reject_audit_tenant_mismatch(command.tenant(), &ctx);
            }
            Err(error) => return reject_audit_payload(&error),
        };
        pg_consumer_tx_outcome(
            "audit-security-event",
            self.append_and_mark_done(command.into_record(), ctx, key, lease)
                .await,
        )
    }

    async fn append_and_mark_done(
        &self,
        record: AuditRecord,
        ctx: InboxReceiptContext,
        key: IdemKey,
        lease: LeaseToken,
    ) -> Result<(), PgConsumerTxError> {
        let tenant = record.tenant;
        let hasher = Arc::clone(&self.hasher);
        self.pool
            .consumer_write(
                infra_tenant_scope(tenant),
                move |mut tx| {
                    Box::pin(async move {
                        audit_write_tx(&mut tx)
                            .append(&record, &hasher)
                            .await
                            .map_err(PgConsumerTxError::Audit)?;
                        match commit_in_tx(&mut tx, &ctx, &key, &lease)
                            .await
                            .map_err(PgConsumerTxError::Inbox)?
                        {
                            LeaseOutcome::Held => Ok(()),
                            LeaseOutcome::Lost => Err(PgConsumerTxError::LeaseLost),
                            _ => Err(PgConsumerTxError::LeaseLost),
                        }
                    })
                },
                PgConsumerTxError::Storage,
            )
            .await
    }

    fn record_from_message(
        &self,
        message: &diport::Message,
    ) -> Result<AuditRecord, AuditEventRecordError> {
        audit_record_from_event_message(self.kind, message)
    }

    fn validated_record_from_message(
        &self,
        message: &diport::Message,
        ctx: &InboxReceiptContext,
    ) -> Result<AuditRecord, PgConsumerTxOutcome> {
        let record = self
            .record_from_message(message)
            .map_err(|error| reject_audit_payload(&error))?;
        if record.tenant != ctx.tenant_id() {
            return Err(reject_audit_tenant_mismatch(record.tenant, ctx));
        }
        Ok(record)
    }
}

#[cfg(feature = "domain-audit")]
impl<M> PgAuditConsumerTx<M>
where
    M: MacVerifier + Send + Sync + 'static,
{
    pub fn handle(
        self: Arc<Self>,
        message: diport::Message,
        ctx: InboxReceiptContext,
        key: IdemKey,
        lease: LeaseToken,
    ) -> futures::future::BoxFuture<'static, PgConsumerTxOutcome> {
        Box::pin(async move { self.handle_attempt(message, ctx, key, lease).await })
    }
}

#[cfg(feature = "domain-settings")]
/// Postgres-backed ConsumerTx handler for settings config-version-changed.
pub struct PgSettingsConsumerTx {
    pool: TenantDb<ServingWriteLane>,
    reconciler: Arc<settings::ConfigVersionReconciler>,
}

#[cfg(feature = "domain-settings")]
impl PgSettingsConsumerTx {
    pub(crate) fn config_version_changed(
        store: &VerifiedPgWriteStore,
        reconciler: Arc<settings::ConfigVersionReconciler>,
    ) -> Self {
        Self {
            pool: TenantDb::<ServingWriteLane>::new(store),
            reconciler,
        }
    }

    async fn handle_attempt(
        &self,
        message: diport::Message,
        ctx: InboxReceiptContext,
        key: IdemKey,
        lease: LeaseToken,
    ) -> PgConsumerTxOutcome {
        let tenant = ctx.tenant_id();
        if let Err(outcome) =
            settings_refresh_outcome(self.reconciler.reconcile(message, tenant).await)
        {
            return outcome;
        }
        pg_consumer_tx_outcome("settings", self.mark_done_only(ctx, key, lease).await)
    }

    async fn mark_done_only(
        &self,
        ctx: InboxReceiptContext,
        key: IdemKey,
        lease: LeaseToken,
    ) -> Result<(), PgConsumerTxError> {
        self.pool
            .consumer_write(
                infra_tenant_scope(ctx.tenant_id()),
                move |mut tx| {
                    Box::pin(async move {
                        match commit_in_tx(&mut tx, &ctx, &key, &lease)
                            .await
                            .map_err(PgConsumerTxError::Inbox)?
                        {
                            LeaseOutcome::Held => Ok(()),
                            LeaseOutcome::Lost => Err(PgConsumerTxError::LeaseLost),
                            _ => Err(PgConsumerTxError::LeaseLost),
                        }
                    })
                },
                PgConsumerTxError::Storage,
            )
            .await
    }
}

#[cfg(feature = "domain-settings")]
impl PgSettingsConsumerTx {
    pub fn handle(
        self: Arc<Self>,
        message: diport::Message,
        ctx: InboxReceiptContext,
        key: IdemKey,
        lease: LeaseToken,
    ) -> futures::future::BoxFuture<'static, PgConsumerTxOutcome> {
        Box::pin(async move { self.handle_attempt(message, ctx, key, lease).await })
    }
}

fn pg_consumer_tx_outcome(
    scope: &'static str,
    result: Result<(), PgConsumerTxError>,
) -> PgConsumerTxOutcome {
    match result {
        Ok(()) => PgConsumerTxOutcome::Committed(PgConsumerTxCommitProof::committed()),
        Err(PgConsumerTxError::LeaseLost) => PgConsumerTxOutcome::LeaseLost {
            summary: EngineErrorKind::Transient.message(),
        },
        Err(error) => {
            tracing::warn!(
                scope,
                error = %secure::redact_error(&error),
                "consumer-tx: postgres transaction failed"
            );
            PgConsumerTxOutcome::commit_unknown(EngineErrorKind::Transient.message())
        }
    }
}

#[cfg(feature = "domain-audit")]
fn reject_audit_payload(error: &AuditEventRecordError) -> PgConsumerTxOutcome {
    tracing::warn!(
        error = %secure::redact_error(error),
        "consumer-tx: audit payload rejected"
    );
    PgConsumerTxOutcome::Reject {
        summary: consistency::PermanentErrorKind::Permanent.message(),
    }
}

#[cfg(feature = "domain-audit")]
fn reject_audit_tenant_mismatch(
    payload_tenant: vocab::TenantId,
    ctx: &InboxReceiptContext,
) -> PgConsumerTxOutcome {
    tracing::warn!(
        payload_tenant = %payload_tenant,
        receipt_tenant = %ctx.tenant_id(),
        "consumer-tx: audit payload tenant does not match verified envelope tenant"
    );
    PgConsumerTxOutcome::Reject {
        summary: consistency::PermanentErrorKind::Invariant.message(),
    }
}

#[cfg(feature = "domain-settings")]
fn settings_refresh_outcome(result: HandleResult) -> Result<(), PgConsumerTxOutcome> {
    match result.as_settled() {
        Settled::Ack => Ok(()),
        Settled::Requeue { summary } => Err(PgConsumerTxOutcome::handler_transient(summary)),
        Settled::Reject { summary } => Err(PgConsumerTxOutcome::Reject { summary }),
    }
}

#[derive(Debug, thiserror::Error)]
enum PgConsumerTxError {
    #[error("consumer transaction storage failed")]
    Storage(#[source] sqlx::Error),
    #[error("consumer transaction audit append failed")]
    #[cfg(feature = "domain-audit")]
    Audit(#[source] audit::ports::AuditError),
    #[error("consumer transaction inbox commit failed")]
    Inbox(#[source] consistency::EngineError),
    #[error("consumer transaction lease lost")]
    LeaseLost,
}

#[cfg(all(test, feature = "domain-audit"))]
mod tests {
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::sync::Mutex;
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;
    use audit::ports::AuditOutcome;
    use tracing::field::Visit;
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const USER: &str = "550e8400-e29b-41d4-a716-446655440000";
    const ACTOR: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";
    const SESSION: &str = "6f9619ff-8b86-d011-b42d-00cf4fc964ff";

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    fn message(payload: impl Into<Vec<u8>>) -> diport::Message {
        diport::Message::new("33333333-4444-4555-8666-777777777777", payload.into())
    }

    #[derive(Default)]
    struct CapturedFields(BTreeMap<String, String>);

    impl Visit for CapturedFields {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.insert(field.name().to_owned(), value.to_owned());
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn core::fmt::Debug) {
            self.0.insert(field.name().to_owned(), format!("{value:?}"));
        }
    }

    #[derive(Clone, Default)]
    struct WarnCapture {
        records: Arc<Mutex<Vec<BTreeMap<String, String>>>>,
    }

    impl Subscriber for WarnCapture {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            *metadata.level() == tracing::Level::WARN
        }

        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }

        fn record(&self, _: &Id, _: &Record<'_>) {}

        fn record_follows_from(&self, _: &Id, _: &Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut fields = CapturedFields::default();
            event.record(&mut fields);
            self.records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(fields.0);
        }

        fn enter(&self, _: &Id) {}

        fn exit(&self, _: &Id) {}
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn tenant_mismatch_log_does_not_expose_transport_message_id() -> TestResult {
        const OTHER_SESSION_BEARER: &str = "37d9f310-5860-4e59-8423-983a2f7b6bc2";
        let transport_message = diport::Message::new(OTHER_SESSION_BEARER, Vec::new());
        assert_eq!(transport_message.id.as_str(), OTHER_SESSION_BEARER);
        let ctx = InboxReceiptContext::new(
            vocab::TenantId::parse(TENANT)?,
            consistency::ConsumerGroup::parse("audit-log-redaction")?,
            "audit",
            "identity.session-created.v1",
            "identity.session-created.v1",
            "v1",
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            None,
            None,
        )?;
        let capture = WarnCapture::default();
        let records = Arc::clone(&capture.records);
        let dispatch = tracing::Dispatch::new(capture);
        let _guard = tracing::dispatcher::set_default(&dispatch);

        let _ = reject_audit_tenant_mismatch(
            vocab::TenantId::parse("550e8400-e29b-41d4-a716-446655440000")?,
            &ctx,
        );

        let records = records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fields = records.first().expect("tenant mismatch warning is logged");
        assert!(
            !fields
                .values()
                .any(|value| value.contains(OTHER_SESSION_BEARER)),
            "transport message id must not cross the log boundary: {fields:?}"
        );
        assert!(!fields.contains_key("message_id"));
        Ok(())
    }

    #[test]
    fn session_created_record_decodes_strict_payload() -> TestResult {
        let payload = format!(
            r#"{{
                "occurredAt":123,
                "sessionId":"{SESSION}",
                "subject":"{USER}",
                "tenantId":"{TENANT}"
            }}"#
        );

        let record = audit_record_from_event_message(
            AuditEventKind::SessionCreated,
            &message(payload.into_bytes()),
        )?;

        assert_eq!(record.tenant, vocab::TenantId::parse(TENANT)?);
        assert_eq!(record.actor, ids::UserId::parse(USER)?);
        assert_eq!(record.actor_kind, vocab::PrincipalKind::User);
        assert_eq!(record.action.as_str(), "identity:login");
        assert_eq!(record.resource.kind(), "session");
        assert_eq!(
            record.resource.id(),
            "event:33333333-4444-4555-8666-777777777777"
        );
        assert_eq!(record.outcome, AuditOutcome::Success);
        assert_eq!(record.recorded_at, UNIX_EPOCH + Duration::from_secs(123));
        Ok(())
    }

    #[test]
    fn role_assigned_record_decodes_generated_payload() -> TestResult {
        let payload = format!(
            r#"{{
                "actorKind":"service",
                "assignedBy":"{ACTOR}",
                "occurredAt":456,
                "roleId":"admin",
                "subject":"{USER}",
                "tenantId":"{TENANT}"
            }}"#
        );

        let record = audit_record_from_event_message(
            AuditEventKind::RoleAssigned,
            &message(payload.into_bytes()),
        )?;

        assert_eq!(record.tenant, vocab::TenantId::parse(TENANT)?);
        assert_eq!(record.actor, ids::UserId::parse(ACTOR)?);
        assert_eq!(record.actor_kind, vocab::PrincipalKind::Service);
        assert_eq!(record.action.as_str(), "identity:role_assign");
        assert_eq!(record.resource.kind(), "role-binding");
        assert_eq!(
            record.resource.id(),
            format!("tenant/{TENANT}/role/admin/subject/{USER}")
        );
        assert_eq!(record.recorded_at, UNIX_EPOCH + Duration::from_secs(456));
        Ok(())
    }

    #[test]
    fn role_revoked_record_decodes_generated_payload() -> TestResult {
        let payload = format!(
            r#"{{
                "actorKind":"admin",
                "occurredAt":789,
                "revokedBy":"{ACTOR}",
                "roleId":"viewer",
                "subject":"{USER}",
                "tenantId":"{TENANT}"
            }}"#
        );

        let record = audit_record_from_event_message(
            AuditEventKind::RoleRevoked,
            &message(payload.into_bytes()),
        )?;

        assert_eq!(record.tenant, vocab::TenantId::parse(TENANT)?);
        assert_eq!(record.actor, ids::UserId::parse(ACTOR)?);
        assert_eq!(record.actor_kind, vocab::PrincipalKind::Admin);
        assert_eq!(record.action.as_str(), "identity:role_revoke");
        assert_eq!(record.resource.kind(), "role-binding");
        assert_eq!(
            record.resource.id(),
            format!("tenant/{TENANT}/role/viewer/subject/{USER}")
        );
        assert_eq!(record.recorded_at, UNIX_EPOCH + Duration::from_secs(789));
        Ok(())
    }

    #[test]
    fn role_assigned_record_rejects_unknown_payload_fields() {
        let payload = format!(
            r#"{{
                "actorKind":"user",
                "assignedBy":"{USER}",
                "occurredAt":123,
                "roleId":"admin",
                "subject":"{USER}",
                "tenantId":"{TENANT}",
                "extra":true
            }}"#
        );

        assert!(
            audit_record_from_event_message(
                AuditEventKind::RoleAssigned,
                &message(payload.into_bytes())
            )
            .is_err()
        );
    }

    #[test]
    fn settings_payload_rejects_unknown_payload_fields() {
        let payload = format!(
            r#"{{
                "changeKind":"published",
                "key":"auth.session.ttl",
                "occurredAt":123,
                "tenantId":"{TENANT}",
                "version":1,
                "extra":true
            }}"#
        );

        assert!(matches!(
            settings::config_version_changed_event_from_message(&message(payload.into_bytes())),
            Err(settings::ConfigVersionChangedEventError::Decode(_))
        ));
    }
}
