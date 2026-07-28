//! PostgreSQL credential-security lifecycle.
//!
//! A sealed identity command is lowered once into exact CAS rows, then the projection and the
//! generated `identity.security-event` OutboxFact are committed through the sole producer
//! transaction funnel. This lifecycle deliberately has no retry entry: a stale snapshot or an
//! unknown commit acknowledgement requires the caller to observe state and construct a new
//! command.
//!
//! INVARIANT: IDENTITY-SECURITY-COTX-01 { level = "Hard", exec = "native-compile", source = "code", native = "sealed command plus ProducerFactAuthorization and one producer_tx" }.
//! INVARIANT: IDENTITY-SECURITY-LOCK-ORDER-01 { level = "Medium", exec = "manual/opt-in", source = "code" }.
//!
//! ref: launchbadge/sqlx sqlx-core/src/transaction.rs@main
//! ref: ory/fosite handler/oauth2/flow_refresh.go@master

use authn::{AuthGrant, AuthGrantCloseMutation, AuthGrantStatus};
use identity::ports::{
    AccountSecurityMutation, CredentialSecurityCommand, CredentialSecurityEmissionParts,
    CredentialSecurityEvent, CredentialSecurityReceipt, IdentityError, IdentitySecurityLifecycle,
    PendingCredentialSecurityCommit, SECURITY_EVENT_CONTRACT, SECURITY_EVENT_FACT, TenantRepoScope,
};

use crate::account_security_repo::status_to_db;
use crate::auth_grant_lifecycle::{GrantCloseCas, apply_grant_close_cas};
use crate::cotx::{PgTenantWritePool, ProducerFactAuthorization, ProducerTxOutcome};
use crate::outbox::{OutboxEnvelope, metadata_with_ambient, unix_secs};
use crate::pool::VerifiedPgWriteStore;
use crate::projection_events::ProjectionWriteRegistry;

/// Durable provider for the active credential-security event protocol.
pub struct PgIdentitySecurityLifecycle {
    write_pool: PgTenantWritePool,
    #[cfg(all(test, feature = "integration"))]
    fault: Option<IdentitySecurityFault>,
    #[cfg(all(test, feature = "integration"))]
    start_barrier: Option<std::sync::Arc<tokio::sync::Barrier>>,
}

#[cfg(all(test, feature = "integration"))]
#[derive(Clone, Copy)]
pub(crate) enum IdentitySecurityFault {
    AfterProjection,
    OutboxAppend,
    AfterOutboxBeforeCommit,
    CommitUnknown,
}

impl PgIdentitySecurityLifecycle {
    pub(crate) fn new(
        writer: &VerifiedPgWriteStore,
        projection_registry: ProjectionWriteRegistry,
    ) -> Self {
        Self {
            write_pool: PgTenantWritePool::with_projection_registry(writer, projection_registry),
            #[cfg(all(test, feature = "integration"))]
            fault: None,
            #[cfg(all(test, feature = "integration"))]
            start_barrier: None,
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            write_pool: PgTenantWritePool::from_unverified_for_test(store),
            fault: None,
            start_barrier: None,
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn with_fault(mut self, fault: IdentitySecurityFault) -> Self {
        self.fault = Some(fault);
        self
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn with_start_barrier(
        mut self,
        barrier: std::sync::Arc<tokio::sync::Barrier>,
    ) -> Self {
        self.start_barrier = Some(barrier);
        self
    }
}

impl IdentitySecurityLifecycle for PgIdentitySecurityLifecycle {
    async fn execute_logout_current(
        &self,
        receipt: identity::ports::LogoutCurrentProducerReceipt,
        scope: TenantRepoScope,
        command: identity::ports::LogoutCurrentCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError> {
        let emission = identity::ports::logout_current_emission(command)?;
        let authorization = receipt
            .authorize(SECURITY_EVENT_FACT, SECURITY_EVENT_CONTRACT)
            .ok_or_else(|| corrupt("logout-current receipt does not authorize security-event"))?;
        let prepared = PreparedSecurityCommand::try_from(emission.into_parts())?;
        self.execute_prepared(authorization, scope, prepared).await
    }

    async fn execute_logout_all(
        &self,
        receipt: identity::ports::LogoutAllProducerReceipt,
        scope: TenantRepoScope,
        command: identity::ports::LogoutAllCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError> {
        let emission = identity::ports::logout_all_emission(command)?;
        let authorization = receipt
            .authorize(SECURITY_EVENT_FACT, SECURITY_EVENT_CONTRACT)
            .ok_or_else(|| corrupt("logout-all receipt does not authorize security-event"))?;
        let prepared = PreparedSecurityCommand::try_from(emission.into_parts())?;
        self.execute_prepared(authorization, scope, prepared).await
    }
}

#[cfg(all(test, feature = "integration"))]
impl PgIdentitySecurityLifecycle {
    pub(crate) async fn execute_test_command(
        &self,
        scope: TenantRepoScope,
        command: CredentialSecurityCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError> {
        let prepared = PreparedSecurityCommand::try_from(
            identity::ports::credential_security_emission_for_test(command)?,
        )?;
        let authorization = crate::cotx::IntegrationCredentialSecurityAuthorization::new();
        self.execute_prepared(authorization, scope, prepared).await
    }
}

impl PgIdentitySecurityLifecycle {
    async fn execute_prepared<A>(
        &self,
        authorization: A,
        scope: TenantRepoScope,
        prepared: PreparedSecurityCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError>
    where
        A: ProducerFactAuthorization,
    {
        let PreparedSecurityCommand {
            entry,
            envelope_parts,
            mutation,
            event,
            pending,
        } = prepared;
        if scope.tenant() != event.tenant() {
            return Err(corrupt("credential security tenant scope mismatch"));
        }
        let (contract, envelope_tenant, subject_id, actor, partition_key, causation_id) =
            envelope_parts.into_parts();
        if envelope_tenant != scope.tenant() {
            return Err(corrupt("credential security envelope tenant mismatch"));
        }
        let envelope = OutboxEnvelope::new(
            contract.domain().to_owned(),
            contract.contract_id().to_owned(),
            metadata_with_ambient(unix_secs(event.occurred_at()), event.tenant(), contract)
                .with_subject_id(subject_id)
                .with_actor(actor),
        )
        .with_partition_key_opt(partition_key)
        .with_causation_id_opt(causation_id);
        #[cfg(all(test, feature = "integration"))]
        let fault = self.fault;
        #[cfg(all(test, feature = "integration"))]
        let start_barrier = self.start_barrier.clone();

        self.write_pool
            .producer_tx(
                scope,
                &entry,
                &envelope,
                move |tx| {
                    Box::pin(async move {
                        #[cfg(all(test, feature = "integration"))]
                        if let Some(start_barrier) = start_barrier {
                            start_barrier.wait().await;
                        }
                        apply_security_mutation(tx.conn(), mutation).await?;
                        #[cfg(all(test, feature = "integration"))]
                        if matches!(fault, Some(IdentitySecurityFault::AfterProjection)) {
                            return Err(corrupt(
                                "injected credential security failure after projection",
                            ));
                        }
                        #[cfg(all(test, feature = "integration"))]
                        if matches!(fault, Some(IdentitySecurityFault::OutboxAppend)) {
                            sqlx::query(
                                "ALTER TABLE public.outbox \
                                 ADD CONSTRAINT credential_security_outbox_fault \
                                 CHECK (false) NOT VALID",
                            )
                            .execute(tx.conn())
                            .await
                            .map_err(storage)?;
                        }
                        #[cfg(all(test, feature = "integration"))]
                        if matches!(fault, Some(IdentitySecurityFault::AfterOutboxBeforeCommit)) {
                            tx.inject_failure_after_outbox_append_before_commit()
                                .await
                                .map_err(storage)?;
                        }
                        #[cfg(all(test, feature = "integration"))]
                        if matches!(fault, Some(IdentitySecurityFault::CommitUnknown)) {
                            tx.inject_commit_unknown_after_commit()
                                .await
                                .map_err(storage)?;
                        }
                        Ok(ProducerTxOutcome::Emitted(pending, authorization))
                    })
                },
                storage,
            )
            .await
            .into_result()
            .map(PendingCredentialSecurityCommit::confirm)
    }
}

struct PreparedSecurityCommand {
    entry: consistency::EventEntry,
    envelope_parts: diport::OutboxEnvelopeParts,
    mutation: SecurityMutation,
    event: CredentialSecurityEvent,
    pending: PendingCredentialSecurityCommit,
}

impl TryFrom<CredentialSecurityEmissionParts> for PreparedSecurityCommand {
    type Error = IdentityError;

    fn try_from(emission: CredentialSecurityEmissionParts) -> Result<Self, Self::Error> {
        let (command, entry, envelope_parts) = emission.into_parts();
        match command {
            CredentialSecurityCommand::Account(command) => {
                let (mutation, event, pending) = command.into_parts();
                Ok(Self {
                    entry,
                    envelope_parts,
                    mutation: SecurityMutation::Account(AccountSecurityRow::try_from((
                        mutation, &event,
                    ))?),
                    event,
                    pending,
                })
            }
            CredentialSecurityCommand::Grant(command) => {
                let (mutation, event, pending) = command.into_parts();
                Ok(Self {
                    entry,
                    envelope_parts,
                    mutation: SecurityMutation::Grant(prepare_grant_security(mutation, &event)?),
                    event,
                    pending,
                })
            }
        }
    }
}

enum SecurityMutation {
    Account(AccountSecurityRow),
    Grant(GrantCloseCas),
}

async fn apply_security_mutation(
    conn: &mut sqlx::PgConnection,
    mutation: SecurityMutation,
) -> Result<(), IdentityError> {
    match mutation {
        SecurityMutation::Account(row) => apply_account_security(conn, &row).await,
        SecurityMutation::Grant(row) => {
            if apply_grant_close_cas(conn, &row).await.map_err(storage)? {
                Ok(())
            } else {
                Err(IdentityError::VersionConflict)
            }
        }
    }
}

struct AccountSecurityRow {
    tenant: String,
    user: String,
    expected_status: &'static str,
    expected_epoch: i64,
    expected_version: i64,
    next_status: &'static str,
    next_epoch: i64,
    next_version: i64,
    status_changed_at: i64,
    updated_at: i64,
    occurred_at: i64,
    reason: &'static str,
}

impl TryFrom<(AccountSecurityMutation, &CredentialSecurityEvent)> for AccountSecurityRow {
    type Error = IdentityError;

    fn try_from(
        (mutation, event): (AccountSecurityMutation, &CredentialSecurityEvent),
    ) -> Result<Self, Self::Error> {
        let (expected, next) = mutation.into_parts();
        if expected.tenant() != event.tenant()
            || next.tenant() != event.tenant()
            || expected.user_id() != event.user_id()
            || next.user_id() != event.user_id()
        {
            return Err(corrupt("credential security account mutation mismatch"));
        }
        Ok(Self {
            tenant: event.tenant().as_uuid().to_string(),
            user: event.user_id().as_uuid().to_string(),
            expected_status: status_to_db(expected.status()),
            expected_epoch: persisted_counter(expected.authn_epoch().get(), "expected epoch")?,
            expected_version: persisted_counter(expected.version().get(), "expected version")?,
            next_status: status_to_db(next.status()),
            next_epoch: persisted_counter(next.authn_epoch().get(), "next epoch")?,
            next_version: persisted_counter(next.version().get(), "next version")?,
            status_changed_at: unix_secs(next.status_changed_at()),
            updated_at: unix_secs(next.updated_at()),
            occurred_at: unix_secs(event.occurred_at()),
            reason: event.kind().as_db_str(),
        })
    }
}

async fn apply_account_security(
    conn: &mut sqlx::PgConnection,
    row: &AccountSecurityRow,
) -> Result<(), IdentityError> {
    let changed = sqlx::query(
        r#"
        UPDATE account_security_states
        SET status = $3,
            authn_epoch = $4,
            version = $5,
            status_changed_at = to_timestamp($6),
            updated_at = to_timestamp($7)
        WHERE tenant_id = $1::uuid
          AND user_id = $2::uuid
          AND status = $8
          AND authn_epoch = $9
          AND version = $10
        "#,
    )
    .bind(&row.tenant)
    .bind(&row.user)
    .bind(row.next_status)
    .bind(row.next_epoch)
    .bind(row.next_version)
    .bind(row.status_changed_at)
    .bind(row.updated_at)
    .bind(row.expected_status)
    .bind(row.expected_epoch)
    .bind(row.expected_version)
    .execute(&mut *conn)
    .await
    .map_err(storage)?;
    if changed.rows_affected() != 1 {
        return Err(IdentityError::VersionConflict);
    }

    sqlx::query(
        r#"
        UPDATE refresh_tokens AS refresh
        SET status = 'revoked'
        FROM auth_grants AS root
        WHERE root.tenant_id = $1::uuid
          AND root.user_id = $2::uuid
          AND root.status = 'active'
          AND refresh.tenant_id = root.tenant_id
          AND refresh.auth_grant_id = root.grant_id
          AND refresh.user_id = root.user_id
          AND refresh.authn_epoch_at_issue = root.authn_epoch_at_issue
          AND refresh.auth_grant_status = root.status
          AND refresh.status <> 'revoked'
        "#,
    )
    .bind(&row.tenant)
    .bind(&row.user)
    .execute(&mut *conn)
    .await
    .map_err(storage)?;

    sqlx::query(
        r#"
        UPDATE auth_grants
        SET status = 'revoked',
            closed_at = to_timestamp($3),
            close_reason = $4
        WHERE tenant_id = $1::uuid
          AND user_id = $2::uuid
          AND status = 'active'
        "#,
    )
    .bind(&row.tenant)
    .bind(&row.user)
    .bind(row.occurred_at)
    .bind(row.reason)
    .execute(&mut *conn)
    .await
    .map_err(storage)?;
    Ok(())
}

fn prepare_grant_security(
    mutation: AuthGrantCloseMutation,
    event: &CredentialSecurityEvent,
) -> Result<GrantCloseCas, IdentityError> {
    let (expected, next) = mutation.into_parts();
    validate_grant_binding(&expected, &next, event)?;
    GrantCloseCas::try_from((&expected, &next))
}

fn validate_grant_binding(
    expected: &AuthGrant,
    next: &AuthGrant,
    event: &CredentialSecurityEvent,
) -> Result<(), IdentityError> {
    if expected.id() != next.id()
        || expected.tenant() != event.tenant()
        || next.tenant() != event.tenant()
        || expected.user_id() != event.user_id()
        || next.user_id() != event.user_id()
        || expected.authn_epoch_at_issue() != next.authn_epoch_at_issue()
        || next.status() == AuthGrantStatus::Active
        || next.close_reason() != Some(event.kind())
    {
        return Err(corrupt("credential security grant mutation mismatch"));
    }
    Ok(())
}

fn persisted_counter(value: u64, field: &'static str) -> Result<i64, IdentityError> {
    i64::try_from(value).map_err(|_| corrupt(field))
}

fn storage(error: impl std::error::Error + Send + Sync + 'static) -> IdentityError {
    crate::tx_retry::identity_storage_error(error)
}

fn corrupt(message: &'static str) -> IdentityError {
    storage(std::io::Error::other(message))
}
