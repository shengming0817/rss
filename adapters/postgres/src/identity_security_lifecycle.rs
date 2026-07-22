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

use authn::{AuthGrant, AuthGrantCloseMutation, AuthGrantId, AuthGrantStatus};
use identity::ports::{
    AccountSecurityMutation, CredentialSecurityCommand, CredentialSecurityEvent,
    CredentialSecurityFactAuthorization, CredentialSecurityReceipt, CredentialSecurityTargetKind,
    CredentialSecurityTargetMapping, CredentialSecurityTargetRef,
    CredentialSecurityTargetResolutionRequest, CredentialSecurityTargetResolver, IdentityError,
    IdentitySecurityLifecycle, PendingCredentialSecurityCommit, ResolvedCredentialSecurityTarget,
    TenantRepoScope,
};

use crate::account_security_repo::status_to_db;
use crate::auth_grant_lifecycle::{GrantCloseCas, apply_grant_close_cas};
use crate::cotx::{PgTenantReadPool, PgTenantWritePool, ProducerTxOutcome};
use crate::outbox::{OutboxEnvelope, metadata_with_ambient, unix_secs};
use crate::pool::VerifiedPgWriteStore;
use crate::projection_events::ProjectionWriteRegistry;

/// Durable provider for the draft credential-security event protocol.
pub struct PgIdentitySecurityLifecycle {
    write_pool: PgTenantWritePool,
    #[cfg(all(test, feature = "integration"))]
    fault: Option<IdentitySecurityFault>,
}

/// Tenant-scoped read provider for opaque security-event targets.
pub struct PgCredentialSecurityTargetResolver {
    read_pool: PgTenantReadPool,
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
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            write_pool: PgTenantWritePool::from_unverified_for_test(store),
            fault: None,
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn with_fault(mut self, fault: IdentitySecurityFault) -> Self {
        self.fault = Some(fault);
        self
    }
}

impl PgCredentialSecurityTargetResolver {
    pub(crate) fn new(reader: &crate::pool::VerifiedPgReadStore) -> Self {
        Self {
            read_pool: PgTenantReadPool::new(reader),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            read_pool: PgTenantReadPool::from_unverified_for_test(store),
        }
    }
}

impl IdentitySecurityLifecycle for PgIdentitySecurityLifecycle {
    async fn execute(
        &self,
        scope: TenantRepoScope,
        command: CredentialSecurityCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError> {
        let PreparedSecurityCommand {
            mutation,
            event,
            pending,
            authorization,
        } = PreparedSecurityCommand::try_from(command)?;
        if scope.tenant() != event.tenant() {
            return Err(corrupt("credential security tenant scope mismatch"));
        }
        let fact = identity::ports::credential_security_fact(&event, authorization)?;
        let (entry, envelope_parts, target_mapping, authorization) = fact.into_parts();
        let target_mapping = CredentialSecurityTargetRow::try_from(target_mapping)?;
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

        self.write_pool
            .producer_tx(
                scope,
                &entry,
                &envelope,
                move |tx| {
                    Box::pin(async move {
                        apply_security_mutation(tx.conn(), mutation).await?;
                        insert_target_mapping(tx.conn(), &target_mapping).await?;
                        #[cfg(all(test, feature = "integration"))]
                        if matches!(fault, Some(IdentitySecurityFault::AfterProjection)) {
                            return Err(corrupt(
                                "injected credential security failure after projection",
                            ));
                        }
                        #[cfg(all(test, feature = "integration"))]
                        if matches!(fault, Some(IdentitySecurityFault::OutboxAppend)) {
                            sqlx::query("CREATE TEMP TABLE outbox (event_id text) ON COMMIT DROP")
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
    mutation: SecurityMutation,
    event: CredentialSecurityEvent,
    pending: PendingCredentialSecurityCommit,
    authorization: CredentialSecurityFactAuthorization,
}

impl TryFrom<CredentialSecurityCommand> for PreparedSecurityCommand {
    type Error = IdentityError;

    fn try_from(command: CredentialSecurityCommand) -> Result<Self, Self::Error> {
        match command {
            CredentialSecurityCommand::Account(command) => {
                let (mutation, event, pending, authorization) = command.into_parts();
                Ok(Self {
                    mutation: SecurityMutation::Account(AccountSecurityRow::try_from((
                        mutation, &event,
                    ))?),
                    event,
                    pending,
                    authorization,
                })
            }
            CredentialSecurityCommand::Grant(command) => {
                let (mutation, event, pending, authorization) = command.into_parts();
                Ok(Self {
                    mutation: SecurityMutation::Grant(prepare_grant_security(mutation, &event)?),
                    event,
                    pending,
                    authorization,
                })
            }
        }
    }
}

enum SecurityMutation {
    Account(AccountSecurityRow),
    Grant(GrantCloseCas),
}

struct CredentialSecurityTargetRow {
    tenant: String,
    target_ref: String,
    target_kind: &'static str,
    user_id: String,
    grant_id: Option<String>,
}

impl TryFrom<CredentialSecurityTargetMapping> for CredentialSecurityTargetRow {
    type Error = IdentityError;

    fn try_from(mapping: CredentialSecurityTargetMapping) -> Result<Self, Self::Error> {
        let (tenant, target_ref, resolved) = mapping.into_parts();
        if resolved.tenant() != tenant || resolved.target_ref() != &target_ref {
            return Err(corrupt("credential security target mapping mismatch"));
        }
        let (target_kind, grant_id) = match resolved.kind() {
            CredentialSecurityTargetKind::Subject => {
                if resolved.grant_id().is_some() {
                    return Err(corrupt("credential security subject mapping has grant"));
                }
                ("subject", None)
            }
            CredentialSecurityTargetKind::Grant => {
                let grant_id = resolved
                    .grant_id()
                    .ok_or_else(|| corrupt("credential security grant mapping lacks grant"))?;
                ("grant", Some(grant_id.as_str().to_owned()))
            }
        };
        Ok(Self {
            tenant: tenant.as_uuid().to_string(),
            target_ref: target_ref.as_uuid().to_string(),
            target_kind,
            user_id: resolved.user_id().as_uuid().to_string(),
            grant_id,
        })
    }
}

async fn insert_target_mapping(
    conn: &mut sqlx::PgConnection,
    row: &CredentialSecurityTargetRow,
) -> Result<(), IdentityError> {
    sqlx::query(
        "INSERT INTO credential_security_target_mappings \
         (target_ref, tenant_id, target_kind, user_id, grant_id) \
         VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5)",
    )
    .bind(&row.target_ref)
    .bind(&row.tenant)
    .bind(row.target_kind)
    .bind(&row.user_id)
    .bind(&row.grant_id)
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(storage)
}

impl CredentialSecurityTargetResolver for PgCredentialSecurityTargetResolver {
    async fn resolve(
        &self,
        request: CredentialSecurityTargetResolutionRequest,
    ) -> Result<Option<ResolvedCredentialSecurityTarget>, IdentityError> {
        let scope = *request.scope();
        let target_ref_query = request.target_ref().as_uuid().to_string();
        let row: Option<(String, String, String, String, Option<String>)> = self
            .read_pool
            .read_map(
                scope,
                move |conn| {
                    Box::pin(async move {
                        sqlx::query_as(
                            "SELECT tenant_id::text, target_ref::text, target_kind, \
                                    user_id::text, grant_id \
                             FROM credential_security_target_mappings \
                             WHERE target_ref = $1::uuid",
                        )
                        .bind(target_ref_query)
                        .fetch_optional(&mut *conn)
                        .await
                        .map_err(storage)
                    })
                },
                storage,
            )
            .await?;
        let Some((stored_tenant, stored_ref, stored_kind, user_id, grant_id)) = row else {
            return Ok(None);
        };
        let stored_tenant = vocab::TenantId::parse(&stored_tenant)
            .map_err(|_| corrupt("corrupt credential security target tenant"))?;
        let stored_ref = CredentialSecurityTargetRef::parse(&stored_ref)
            .map_err(|_| corrupt("corrupt credential security target reference"))?;
        let stored_kind = match stored_kind.as_str() {
            "subject" => CredentialSecurityTargetKind::Subject,
            "grant" => CredentialSecurityTargetKind::Grant,
            _ => return Err(corrupt("corrupt credential security target kind")),
        };
        let user_id = ids::UserId::parse(&user_id)
            .map_err(|_| corrupt("corrupt credential security target user"))?;
        let grant_id = match grant_id {
            Some(grant_id) if grant_id.is_empty() => {
                return Err(corrupt("corrupt credential security target grant"));
            }
            Some(grant_id) => Some(
                AuthGrantId::hydrate(grant_id)
                    .map_err(|_| corrupt("corrupt credential security target grant"))?,
            ),
            None => None,
        };
        request
            .resolve_provider_row(stored_tenant, stored_ref, stored_kind, user_id, grant_id)
            .map_err(storage)
    }
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
    IdentityError::Storage(Box::new(error))
}

fn corrupt(message: &'static str) -> IdentityError {
    storage(std::io::Error::other(message))
}
