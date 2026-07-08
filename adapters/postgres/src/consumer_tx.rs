//! PostgreSQL ConsumerTx handlers.
//!
//! These handlers are the durable consumer path for generated subscriptions. They keep
//! `TxCapability` sealed inside this crate: runtime chooses a handler, but cannot construct or
//! escape transaction capability values.

use std::sync::Arc;

use audit::ports::{
    AuditChainHasher, AuditEventKind, AuditEventRecordError, AuditRecord,
    audit_record_from_event_message,
};
use consistency::idempotency::LeaseOutcome;
use consistency::{
    Disposition, EngineErrorKind, HandleResult, IdemKey, InboxReceiptContext, LeaseToken,
};
use eventexec::{ConsumerTxHandlerFn, ConsumerTxOutcome};
use primitives::MacVerifier;

use crate::PgStore;
use crate::audit_repo::{advisory_lock_key, append_in_tx, tenant_str};
use crate::cotx::PgTenantPool;
use crate::inbox::commit_in_tx;

/// Postgres-backed ConsumerTx audit handler.
pub struct PgAuditConsumerTx<M: MacVerifier> {
    pool: PgTenantPool,
    hasher: Arc<AuditChainHasher<M>>,
    kind: AuditEventKind,
}

impl<M> PgAuditConsumerTx<M>
where
    M: MacVerifier + Send + Sync + 'static,
{
    pub(crate) fn session_created(store: &PgStore, hasher: AuditChainHasher<M>) -> Self {
        Self::new(store, hasher, AuditEventKind::SessionCreated)
    }

    pub(crate) fn role_assigned(store: &PgStore, hasher: AuditChainHasher<M>) -> Self {
        Self::new(store, hasher, AuditEventKind::RoleAssigned)
    }

    pub(crate) fn role_revoked(store: &PgStore, hasher: AuditChainHasher<M>) -> Self {
        Self::new(store, hasher, AuditEventKind::RoleRevoked)
    }

    pub(crate) fn policy_updated(store: &PgStore, hasher: AuditChainHasher<M>) -> Self {
        Self::new(store, hasher, AuditEventKind::PolicyUpdated)
    }

    fn new(store: &PgStore, hasher: AuditChainHasher<M>, kind: AuditEventKind) -> Self {
        Self {
            pool: PgTenantPool::new(store),
            hasher: Arc::new(hasher),
            kind,
        }
    }

    #[must_use]
    pub fn into_handler(self) -> ConsumerTxHandlerFn {
        let this = Arc::new(self);
        Box::new(move |message, ctx, key, lease| {
            let this = Arc::clone(&this);
            Box::pin(async move { this.handle(message, ctx, key, lease).await })
        })
    }

    async fn handle(
        &self,
        message: diport::Message,
        ctx: InboxReceiptContext,
        key: IdemKey,
        lease: LeaseToken,
    ) -> ConsumerTxOutcome {
        let record = match self.validated_record_from_message(&message, &ctx) {
            Ok(record) => record,
            Err(outcome) => return outcome,
        };
        pg_consumer_tx_outcome(
            "audit",
            self.append_and_mark_done(record, ctx, key, lease).await,
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
        let tenant_uuid = tenant_str(tenant);
        let lock_key = advisory_lock_key(tenant);
        let hasher = Arc::clone(&self.hasher);
        self.pool
            .write(
                tenant,
                move |tx| {
                    Box::pin(async move {
                        append_in_tx(tx.conn(), &tenant_uuid, lock_key, &record, &hasher)
                            .await
                            .map_err(PgConsumerTxError::Audit)?;
                        match commit_in_tx(tx, &ctx, &key, &lease)
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
    ) -> Result<AuditRecord, ConsumerTxOutcome> {
        let record = self
            .record_from_message(message)
            .map_err(|error| reject_audit_payload(message, &error))?;
        if record.tenant != ctx.tenant_id() {
            return Err(reject_audit_tenant_mismatch(message, &record, ctx));
        }
        Ok(record)
    }
}

/// Postgres-backed ConsumerTx handler for settings config-version-changed.
pub struct PgSettingsConsumerTx {
    pool: PgTenantPool,
    service: Arc<settings::SettingsService>,
}

impl PgSettingsConsumerTx {
    pub(crate) fn config_version_changed(
        store: &PgStore,
        service: Arc<settings::SettingsService>,
    ) -> Self {
        Self {
            pool: PgTenantPool::new(store),
            service,
        }
    }

    #[must_use]
    pub fn into_handler(self) -> ConsumerTxHandlerFn {
        let this = Arc::new(self);
        Box::new(move |message, ctx, key, lease| {
            let this = Arc::clone(&this);
            Box::pin(async move { this.handle(message, ctx, key, lease).await })
        })
    }

    async fn handle(
        &self,
        message: diport::Message,
        ctx: InboxReceiptContext,
        key: IdemKey,
        lease: LeaseToken,
    ) -> ConsumerTxOutcome {
        let event = match settings::config_version_changed_event_from_message(&message) {
            Ok(event) => event,
            Err(error) => return reject_settings_event(&message, &error),
        };
        if event.tenant() != ctx.tenant_id() {
            return reject_settings_tenant_mismatch(&message, event.tenant(), &ctx);
        }
        if let Err(outcome) = settings_refresh_outcome(
            &message,
            self.service
                .handle_config_version_changed_event(event)
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
    ) -> Result<(), PgConsumerTxError> {
        self.pool
            .write(
                ctx.tenant_id(),
                move |tx| {
                    Box::pin(async move {
                        match commit_in_tx(tx, &ctx, &key, &lease)
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

fn pg_consumer_tx_outcome(
    scope: &'static str,
    result: Result<(), PgConsumerTxError>,
) -> ConsumerTxOutcome {
    match result {
        Ok(()) => ConsumerTxOutcome::Committed,
        Err(PgConsumerTxError::LeaseLost) => ConsumerTxOutcome::LeaseLost {
            summary: EngineErrorKind::Transient.message(),
        },
        Err(error) => {
            tracing::warn!(
                scope,
                error = %secure::redact_error(&error),
                "consumer-tx: postgres transaction failed"
            );
            ConsumerTxOutcome::commit_unknown(EngineErrorKind::Transient.message())
        }
    }
}

fn reject_audit_payload(
    message: &diport::Message,
    error: &AuditEventRecordError,
) -> ConsumerTxOutcome {
    tracing::warn!(
        message_id = message.id.as_str(),
        error = %secure::redact_error(error),
        "consumer-tx: audit payload rejected"
    );
    ConsumerTxOutcome::Reject {
        summary: consistency::PermanentErrorKind::Permanent.message(),
    }
}

fn reject_audit_tenant_mismatch(
    message: &diport::Message,
    record: &AuditRecord,
    ctx: &InboxReceiptContext,
) -> ConsumerTxOutcome {
    tracing::warn!(
        message_id = message.id.as_str(),
        payload_tenant = %record.tenant,
        receipt_tenant = %ctx.tenant_id(),
        "consumer-tx: audit payload tenant does not match verified envelope tenant"
    );
    ConsumerTxOutcome::Reject {
        summary: consistency::PermanentErrorKind::Invariant.message(),
    }
}

fn settings_refresh_outcome(
    message: &diport::Message,
    result: HandleResult,
) -> Result<(), ConsumerTxOutcome> {
    match result.disposition() {
        Disposition::Ack => Ok(()),
        Disposition::Requeue => Err(ConsumerTxOutcome::handler_transient(
            result
                .error_summary()
                .unwrap_or(EngineErrorKind::Transient.message()),
        )),
        Disposition::Reject => Err(ConsumerTxOutcome::Reject {
            summary: result
                .error_summary()
                .unwrap_or(consistency::PermanentErrorKind::Permanent.message()),
        }),
        _ => {
            tracing::warn!(
                message_id = message.id.as_str(),
                "consumer-tx: settings refresh returned unknown disposition"
            );
            Err(ConsumerTxOutcome::handler_transient(
                EngineErrorKind::Invariant.message(),
            ))
        }
    }
}

fn reject_settings_event(
    message: &diport::Message,
    error: &settings::ConfigVersionChangedEventError,
) -> ConsumerTxOutcome {
    tracing::warn!(
        message_id = message.id.as_str(),
        error = %secure::redact_error(error),
        "consumer-tx: settings payload rejected"
    );
    ConsumerTxOutcome::Reject {
        summary: consistency::PermanentErrorKind::Permanent.message(),
    }
}

fn reject_settings_tenant_mismatch(
    message: &diport::Message,
    tenant: vocab::TenantId,
    ctx: &InboxReceiptContext,
) -> ConsumerTxOutcome {
    tracing::warn!(
        message_id = message.id.as_str(),
        payload_tenant = %tenant,
        receipt_tenant = %ctx.tenant_id(),
        "consumer-tx: settings payload tenant does not match verified envelope tenant"
    );
    ConsumerTxOutcome::Reject {
        summary: consistency::PermanentErrorKind::Invariant.message(),
    }
}

#[derive(Debug, thiserror::Error)]
enum PgConsumerTxError {
    #[error("consumer transaction storage failed")]
    Storage(#[source] sqlx::Error),
    #[error("consumer transaction audit append failed")]
    Audit(#[source] audit::ports::AuditError),
    #[error("consumer transaction inbox commit failed")]
    Inbox(#[source] consistency::EngineError),
    #[error("consumer transaction lease lost")]
    LeaseLost,
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;
    use audit::ports::AuditOutcome;

    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const USER: &str = "550e8400-e29b-41d4-a716-446655440000";
    const ACTOR: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";
    const SESSION: &str = "6f9619ff-8b86-d011-b42d-00cf4fc964ff";

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    fn message(payload: impl Into<Vec<u8>>) -> diport::Message {
        diport::Message::new("evt-consumer-tx", payload.into())
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
        assert_eq!(record.resource.id(), SESSION);
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
