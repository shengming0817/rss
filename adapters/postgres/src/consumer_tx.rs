//! PostgreSQL ConsumerTx handlers.
//!
//! These handlers are the durable consumer path for generated subscriptions. They keep
//! `TenantTx` sealed inside this crate: runtime chooses a handler, but cannot construct or
//! escape transaction capability values.

#[cfg(any(feature = "domain-audit", feature = "domain-settings"))]
use std::sync::Arc;

#[cfg(feature = "domain-audit")]
use audit::ports::{
    AuditChainHasher, AuditEventKind, AuditEventRecordError, AuditRecord,
    audit_record_from_event_message, security_audit_command_from_message,
};
#[cfg(any(feature = "domain-audit", feature = "domain-settings"))]
use consistency::idempotency::LeaseOutcome;
#[cfg(feature = "domain-settings")]
use consistency::{HandleResult, Settled};
#[cfg(any(feature = "domain-audit", feature = "domain-settings"))]
use consistency::{IdemKey, InboxReceiptContext, LeaseToken};
#[cfg(any(feature = "domain-audit", feature = "domain-settings"))]
use eventexec::consumer::ValidatedEvent;
#[cfg(any(feature = "domain-audit", feature = "domain-settings"))]
use eventexec::consumer_tx::ConsumerTxOutcome;
#[cfg(any(feature = "domain-audit", feature = "domain-settings"))]
use eventexec::consumer_tx::RejectKind;
#[cfg(feature = "domain-audit")]
use primitives::MacVerifier;

#[cfg(feature = "domain-audit")]
use crate::cotx::settings_audit::audit_write_tx;
#[cfg(any(feature = "domain-audit", feature = "domain-settings"))]
use crate::cotx::{ServingWriteLane, TenantDb, infra_tenant_scope};
#[cfg(any(feature = "domain-audit", feature = "domain-settings"))]
use crate::inbox::commit_in_tx;
#[cfg(any(feature = "domain-audit", feature = "domain-settings"))]
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

    /// Mint provider-owned proof only in test dependency graphs.
    ///
    /// Keeping the mint on the provider type lets Composition exercise its real Ack path without
    /// reopening the production handler boundary to an arbitrary associated proof type.
    #[cfg(feature = "consumer-tx-composition-test-support")]
    #[doc(hidden)]
    pub fn for_test() -> Self {
        Self::committed()
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
        event: Arc<ValidatedEvent>,
        ctx: InboxReceiptContext,
        key: IdemKey,
        lease: LeaseToken,
    ) -> ConsumerTxOutcome<PgConsumerTxCommitProof> {
        if self.kind == AuditEventKind::SecurityEvent {
            return self.handle_security_attempt(event, ctx, key, lease).await;
        }
        let record = match self.validated_record_from_message(&event, &ctx) {
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
        event: Arc<ValidatedEvent>,
        ctx: InboxReceiptContext,
        key: IdemKey,
        lease: LeaseToken,
    ) -> ConsumerTxOutcome<PgConsumerTxCommitProof> {
        let command = match security_audit_command_from_message(&event) {
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
    ) -> crate::cotx::LocalTxAttempt<(), PgConsumerTxError> {
        let tenant = record.tenant;
        let hasher = Arc::clone(&self.hasher);
        self.pool
            .consumer_write_attempt(
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
        event: &ValidatedEvent,
    ) -> Result<AuditRecord, AuditEventRecordError> {
        audit_record_from_event_message(self.kind, event)
    }

    fn validated_record_from_message(
        &self,
        event: &ValidatedEvent,
        ctx: &InboxReceiptContext,
    ) -> Result<AuditRecord, ConsumerTxOutcome<PgConsumerTxCommitProof>> {
        let record = self
            .record_from_message(event)
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
        event: Arc<ValidatedEvent>,
        ctx: InboxReceiptContext,
        key: IdemKey,
        lease: LeaseToken,
    ) -> futures::future::BoxFuture<'static, ConsumerTxOutcome<PgConsumerTxCommitProof>> {
        Box::pin(async move { self.handle_attempt(event, ctx, key, lease).await })
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
        event: Arc<ValidatedEvent>,
        ctx: InboxReceiptContext,
        key: IdemKey,
        lease: LeaseToken,
    ) -> ConsumerTxOutcome<PgConsumerTxCommitProof> {
        let tenant = ctx.tenant_id();
        if let Err(outcome) = settings_refresh_outcome(
            self.reconciler
                .reconcile(event.message().clone(), tenant)
                .await,
        ) {
            return outcome;
        }
        pg_consumer_tx_outcome("settings", self.mark_done_only(ctx, key, lease).await)
    }

    async fn mark_done_only(
        &self,
        ctx: InboxReceiptContext,
        key: IdemKey,
        lease: LeaseToken,
    ) -> crate::cotx::LocalTxAttempt<(), PgConsumerTxError> {
        self.pool
            .consumer_write_attempt(
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
        event: Arc<ValidatedEvent>,
        ctx: InboxReceiptContext,
        key: IdemKey,
        lease: LeaseToken,
    ) -> futures::future::BoxFuture<'static, ConsumerTxOutcome<PgConsumerTxCommitProof>> {
        Box::pin(async move { self.handle_attempt(event, ctx, key, lease).await })
    }
}

#[cfg(any(feature = "domain-audit", feature = "domain-settings"))]
fn pg_consumer_tx_outcome(
    scope: &'static str,
    attempt: crate::cotx::LocalTxAttempt<(), PgConsumerTxError>,
) -> ConsumerTxOutcome<PgConsumerTxCommitProof> {
    attempt.fold(
        |()| ConsumerTxOutcome::Committed(PgConsumerTxCommitProof::committed()),
        |error| {
            log_consumer_tx_error(scope, &error, "unsettled");
            ConsumerTxOutcome::InfrastructureTransient
        },
        |error| {
            log_consumer_tx_error(scope, &error, "rolled_back");
            match error {
                PgConsumerTxError::LeaseLost => ConsumerTxOutcome::Fenced,
                #[cfg(feature = "domain-audit")]
                PgConsumerTxError::Audit(_) => ConsumerTxOutcome::InfrastructureTransient,
                PgConsumerTxError::Storage(_) | PgConsumerTxError::Inbox(_) => {
                    ConsumerTxOutcome::InfrastructureTransient
                }
            }
        },
        |error| {
            log_consumer_tx_error(scope, &error, "rollback_failed");
            ConsumerTxOutcome::RollbackFailed
        },
        |error| {
            log_consumer_tx_error(scope, &error, "commit_unknown");
            ConsumerTxOutcome::CommitUnknown
        },
    )
}

#[cfg(any(feature = "domain-audit", feature = "domain-settings"))]
fn log_consumer_tx_error(scope: &'static str, error: &PgConsumerTxError, settlement: &'static str) {
    tracing::warn!(
        scope,
        settlement,
        error = %secure::redact_error(error),
        "consumer-tx: postgres transaction failed"
    );
}

#[cfg(feature = "domain-audit")]
fn reject_audit_payload(
    error: &AuditEventRecordError,
) -> ConsumerTxOutcome<PgConsumerTxCommitProof> {
    tracing::warn!(
        error = %secure::redact_error(error),
        "consumer-tx: audit payload rejected"
    );
    ConsumerTxOutcome::Rejected(RejectKind::Permanent)
}

#[cfg(feature = "domain-audit")]
fn reject_audit_tenant_mismatch(
    payload_tenant: rss_request_context::TenantId,
    ctx: &InboxReceiptContext,
) -> ConsumerTxOutcome<PgConsumerTxCommitProof> {
    tracing::warn!(
        payload_tenant = %payload_tenant,
        receipt_tenant = %ctx.tenant_id(),
        "consumer-tx: audit payload tenant does not match verified envelope tenant"
    );
    ConsumerTxOutcome::Rejected(RejectKind::Invariant)
}

#[cfg(feature = "domain-settings")]
fn settings_refresh_outcome(
    result: HandleResult,
) -> Result<(), ConsumerTxOutcome<PgConsumerTxCommitProof>> {
    match result.as_settled() {
        Settled::Ack => Ok(()),
        Settled::Requeue { .. } => Err(ConsumerTxOutcome::HandlerTransient),
        Settled::Reject { kind } => Err(ConsumerTxOutcome::Rejected(match kind {
            consistency::PermanentErrorKind::Permanent => RejectKind::Permanent,
            consistency::PermanentErrorKind::Invariant => RejectKind::Invariant,
        })),
    }
}

#[derive(Debug, thiserror::Error)]
#[cfg(any(feature = "domain-audit", feature = "domain-settings"))]
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

#[cfg(all(test, feature = "integration"))]
#[derive(Clone, Copy)]
pub(crate) enum ConsumerTxSettlementFault {
    None,
    CommitUnknown,
    RollbackFailed,
}

#[cfg(all(test, feature = "integration"))]
pub(crate) async fn consumer_tx_settlement_for_test(
    store: &crate::PgStore,
    tenant: rss_request_context::TenantId,
    fault: ConsumerTxSettlementFault,
    attempts: Arc<std::sync::atomic::AtomicUsize>,
) -> ConsumerTxOutcome<PgConsumerTxCommitProof> {
    let pool = TenantDb::<ServingWriteLane>::from_unverified_for_test(store);
    let attempt_counter = Arc::clone(&attempts);
    let attempt = pool
        .consumer_write_attempt(
            infra_tenant_scope(tenant),
            move |mut tx| {
                Box::pin(async move {
                    attempt_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    match fault {
                        ConsumerTxSettlementFault::None => Ok(()),
                        ConsumerTxSettlementFault::CommitUnknown => {
                            tx.inject_commit_unknown_after_commit()
                                .await
                                .map_err(PgConsumerTxError::Storage)?;
                            Ok(())
                        }
                        ConsumerTxSettlementFault::RollbackFailed => {
                            tx.inject_rollback_failed_after_rollback()
                                .await
                                .map_err(PgConsumerTxError::Storage)?;
                            Err(PgConsumerTxError::Storage(sqlx::Error::Protocol(
                                "injected consumer transaction rollback".into(),
                            )))
                        }
                    }
                })
            },
            PgConsumerTxError::Storage,
        )
        .await;
    pg_consumer_tx_outcome("integration-test", attempt)
}

#[cfg(all(test, feature = "integration"))]
pub(crate) async fn consumer_tx_stale_lease_for_test(
    store: &crate::PgStore,
    tenant: rss_request_context::TenantId,
    ctx: InboxReceiptContext,
    key: IdemKey,
    stale_lease: LeaseToken,
    attempts: Arc<std::sync::atomic::AtomicUsize>,
) -> ConsumerTxOutcome<PgConsumerTxCommitProof> {
    let pool = TenantDb::<ServingWriteLane>::from_unverified_for_test(store);
    let attempt_counter = Arc::clone(&attempts);
    let attempt = pool
        .consumer_write_attempt(
            infra_tenant_scope(tenant),
            move |mut tx| {
                Box::pin(async move {
                    attempt_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    match commit_in_tx(&mut tx, &ctx, &key, &stale_lease)
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
        .await;
    pg_consumer_tx_outcome("integration-test-stale-lease", attempt)
}

#[cfg(all(test, feature = "integration"))]
pub(crate) async fn consumer_tx_confirmed_rollback_for_test(
    store: &crate::PgStore,
    tenant: rss_request_context::TenantId,
    ctx: InboxReceiptContext,
    key: IdemKey,
    lease: LeaseToken,
    marker: String,
    attempts: Arc<std::sync::atomic::AtomicUsize>,
) -> ConsumerTxOutcome<PgConsumerTxCommitProof> {
    let pool = TenantDb::<ServingWriteLane>::from_unverified_for_test(store);
    let attempt_counter = Arc::clone(&attempts);
    let attempt = pool
        .consumer_write_attempt(
            infra_tenant_scope(tenant),
            move |mut tx| {
                Box::pin(async move {
                    attempt_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    tx.insert_consumer_rollback_probe(&marker)
                        .await
                        .map_err(PgConsumerTxError::Storage)?;
                    match commit_in_tx(&mut tx, &ctx, &key, &lease)
                        .await
                        .map_err(PgConsumerTxError::Inbox)?
                    {
                        LeaseOutcome::Held => {}
                        LeaseOutcome::Lost => return Err(PgConsumerTxError::LeaseLost),
                        _ => return Err(PgConsumerTxError::LeaseLost),
                    }
                    Err(PgConsumerTxError::Storage(sqlx::Error::Protocol(
                        "injected ordinary consumer transaction failure".into(),
                    )))
                })
            },
            PgConsumerTxError::Storage,
        )
        .await;
    pg_consumer_tx_outcome("integration-test-confirmed-rollback", attempt)
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

    fn validated_message(payload: impl Into<Vec<u8>>) -> eventexec::consumer::ValidatedEvent {
        let payload = payload.into();
        let value: serde_json::Value = serde_json::from_slice(&payload).expect("json fixture");
        let mut metadata = diport::EnvelopeMetadata::empty();
        metadata.insert_wire_pair(
            diport::KEY_TENANT_ID,
            value
                .get("tenantId")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(TENANT),
        );
        metadata.insert_wire_pair(
            diport::KEY_OCCURRED_AT,
            value
                .get("occurredAt")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0)
                .to_string(),
        );
        metadata.insert_wire_pair(diport::KEY_SCHEMA_VERSION, "v1");
        metadata.insert_wire_pair(
            diport::KEY_SCHEMA_HASH,
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        eventexec::consumer::ValidatedEvent::for_test(diport::Message::new_with_metadata(
            "33333333-4444-4555-8666-777777777777",
            payload,
            metadata,
        ))
        .expect("valid event fixture")
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
        assert_eq!(transport_message.id().as_str(), OTHER_SESSION_BEARER);
        let ctx = InboxReceiptContext::new(
            rss_request_context::TenantId::parse(TENANT)?,
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
            rss_request_context::TenantId::parse("550e8400-e29b-41d4-a716-446655440000")?,
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
            &validated_message(payload.into_bytes()),
        )?;

        assert_eq!(record.tenant, rss_request_context::TenantId::parse(TENANT)?);
        assert_eq!(record.actor, ids::UserId::parse(USER)?);
        assert_eq!(record.actor_kind, rss_request_context::PrincipalKind::User);
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
            &validated_message(payload.into_bytes()),
        )?;

        assert_eq!(record.tenant, rss_request_context::TenantId::parse(TENANT)?);
        assert_eq!(record.actor, ids::UserId::parse(ACTOR)?);
        assert_eq!(
            record.actor_kind,
            rss_request_context::PrincipalKind::Service
        );
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
            &validated_message(payload.into_bytes()),
        )?;

        assert_eq!(record.tenant, rss_request_context::TenantId::parse(TENANT)?);
        assert_eq!(record.actor, ids::UserId::parse(ACTOR)?);
        assert_eq!(record.actor_kind, rss_request_context::PrincipalKind::Admin);
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
                &validated_message(payload.into_bytes())
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
