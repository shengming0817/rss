//! PostgreSQL authentication-grant lifecycle.
//!
//! Login persists the grant root, initial refresh record and session-created outbox fact through
//! one [`TenantDb::<ServingWriteLane>::producer_tx`]. Terminal security mutations are exclusively owned by
//! [`crate::PgIdentitySecurityLifecycle`].
//!
//! INVARIANT: AUTH-GRANT-LOGIN-COTX-01 { level = "Hard", exec = "native-compile", source = "code", native = "combined port method plus provider-owned transaction" }.
//!
//! ref: launchbadge/sqlx sqlx-core/src/transaction.rs@main

use std::time::SystemTime;

use authn::{
    AuthGrant, AuthGrantId, AuthGrantSnapshot, AuthGrantStatus, AuthnEpoch,
    CredentialSecurityEventKind,
};
use diport::{Clock, OutboxEmitError};
use eventexec::event::ReviewedEvent;
use identity::ports::{
    AuthGrantLifecycle, IdentityError, LoginGrantMutation, RefreshStatus, RefreshTokenRecord,
    SESSION_CREATED_CONTRACT, TenantRepoScope,
};
#[cfg(all(test, feature = "integration"))]
use std::sync::Arc;

use crate::cotx::identity::IdentityTx;
use crate::cotx::{ProducerTxOutcome, ServingReadLane, ServingWriteLane, TenantDb};
use crate::outbox::{OutboxEnvelope, epoch_secs_to_time, metadata_with_ambient};
use crate::pool::{VerifiedPgReadStore, VerifiedPgWriteStore};
use crate::projection_events::ProjectionWriteRegistry;

#[cfg(all(test, feature = "integration"))]
use crate::PgStore;

pub struct PgAuthGrantLifecycle {
    read_pool: TenantDb<ServingReadLane>,
    write_pool: TenantDb<ServingWriteLane>,
    clock: Box<dyn Clock>,
    #[cfg(all(test, feature = "integration"))]
    login_fault: Option<(String, AuthGrantLoginFault)>,
    #[cfg(all(test, feature = "integration"))]
    login_lock_gate: Option<AuthGrantLoginLockGate>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct AuthGrantRow {
    pub(crate) user_id: String,
    pub(crate) auth_time: i64,
    pub(crate) authn_epoch_at_issue: i64,
    pub(crate) status: String,
    pub(crate) expires_at: i64,
    pub(crate) created_at: i64,
    pub(crate) closed_at: Option<i64>,
    pub(crate) close_reason: Option<String>,
}

#[cfg(all(test, feature = "integration"))]
#[derive(Clone, Copy)]
pub(crate) enum AuthGrantLoginFault {
    AfterGrantWrite,
    AfterRefreshWrite,
    CommitUnknown,
}

#[cfg(all(test, feature = "integration"))]
#[derive(Clone, Default)]
pub(crate) struct AuthGrantLoginLockGate {
    locked: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[cfg(all(test, feature = "integration"))]
impl AuthGrantLoginLockGate {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) async fn wait_until_locked(&self) {
        self.locked.notified().await;
    }

    pub(crate) fn release(&self) {
        self.release.notify_one();
    }

    async fn pause_after_lock(&self) {
        self.locked.notify_one();
        self.release.notified().await;
    }
}

impl PgAuthGrantLifecycle {
    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn new(store: &PgStore, clock: Box<dyn Clock>) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::from_unverified_for_test(store),
            write_pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(store),
            clock,
            login_fault: None,
            login_lock_gate: None,
        }
    }

    pub(crate) fn new_with_projection_registry(
        reader: &VerifiedPgReadStore,
        writer: &VerifiedPgWriteStore,
        clock: Box<dyn Clock>,
        projection_registry: ProjectionWriteRegistry,
    ) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::new(reader),
            write_pool: TenantDb::<ServingWriteLane>::with_projection_registry(
                writer,
                projection_registry,
            ),
            clock,
            #[cfg(all(test, feature = "integration"))]
            login_fault: None,
            #[cfg(all(test, feature = "integration"))]
            login_lock_gate: None,
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn with_login_fault(mut self, grant_id: &str, fault: AuthGrantLoginFault) -> Self {
        self.login_fault = Some((grant_id.to_owned(), fault));
        self
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn with_login_lock_gate(mut self, gate: AuthGrantLoginLockGate) -> Self {
        self.login_lock_gate = Some(gate);
        self
    }
}

impl AuthGrantLifecycle for PgAuthGrantLifecycle {
    async fn persist_login_grant(
        &self,
        receipt: identity::ports::LoginProducerReceipt,
        scope: TenantRepoScope,
        mutation: LoginGrantMutation,
        event: ReviewedEvent,
    ) -> Result<identity::ports::PersistedLoginGrantReceipt, OutboxEmitError> {
        let (grant, initial_refresh, persistence) = mutation.into_parts();
        let generated_fact = event.fact();
        let (entry, envelope, _fact) = event.into_parts();
        let (contract, env_tenant, subject_id, actor, partition_key, causation_id) =
            envelope.into_parts();
        let tenant = grant.tenant();
        validate_login_binding(scope, env_tenant, &grant, &initial_refresh)
            .map_err(OutboxEmitError::new)?;
        let env = OutboxEnvelope::new(
            contract.domain().to_owned(),
            contract.contract_id().to_owned(),
            metadata_with_ambient(
                vocab::UnixEpochSeconds::saturating_from_system_time(self.clock.now()).get(),
                tenant,
                contract,
            )
            .with_subject_id(subject_id)
            .with_actor(actor),
        )
        .with_partition_key_opt(partition_key)
        .with_causation_id_opt(causation_id);
        #[cfg(all(test, feature = "integration"))]
        let login_fault = self
            .login_fault
            .as_ref()
            .filter(|(grant_id, _)| grant_id == &grant.id().to_wire())
            .map(|(_, fault)| *fault);
        #[cfg(all(test, feature = "integration"))]
        let login_lock_gate = self.login_lock_gate.clone();

        self.write_pool
            .identity_producer_tx(
                scope,
                &entry,
                &env,
                move |mut tx| {
                    Box::pin(async move {
                        let account_matches = lock_active_login_account(&mut tx, &grant)
                            .await
                            .map_err(OutboxEmitError::new)?;
                        if !account_matches {
                            return Err(OutboxEmitError::new(std::io::Error::other(
                                "login account is inactive or its authentication epoch is stale",
                            )));
                        }
                        #[cfg(all(test, feature = "integration"))]
                        if let Some(gate) = login_lock_gate {
                            gate.pause_after_lock().await;
                        }
                        write_auth_grant(&mut tx, &grant)
                            .await
                            .map_err(OutboxEmitError::new)?;
                        #[cfg(all(test, feature = "integration"))]
                        if matches!(login_fault, Some(AuthGrantLoginFault::AfterGrantWrite)) {
                            return Err(OutboxEmitError::new(std::io::Error::other(
                                "injected failure after AuthGrant write",
                            )));
                        }
                        write_initial_refresh(&mut tx, &initial_refresh)
                            .await
                            .map_err(OutboxEmitError::new)?;
                        #[cfg(all(test, feature = "integration"))]
                        if matches!(login_fault, Some(AuthGrantLoginFault::AfterRefreshWrite)) {
                            return Err(OutboxEmitError::new(std::io::Error::other(
                                "injected failure after initial refresh write",
                            )));
                        }
                        let authorization = receipt
                            .authorize(generated_fact, SESSION_CREATED_CONTRACT)
                            .ok_or_else(|| {
                                OutboxEmitError::new(std::io::Error::other(
                                    "login receipt does not authorize session-created",
                                ))
                            })?;
                        #[cfg(all(test, feature = "integration"))]
                        if matches!(login_fault, Some(AuthGrantLoginFault::CommitUnknown)) {
                            tx.inject_commit_unknown_after_commit()
                                .await
                                .map_err(OutboxEmitError::new)?;
                        }
                        Ok(ProducerTxOutcome::Emitted(
                            persistence.confirm(),
                            authorization,
                        ))
                    })
                },
                OutboxEmitError::new,
            )
            .await
            .into_result()
    }

    async fn find_active(
        &self,
        scope: TenantRepoScope,
        grant_id: AuthGrantId,
        observed_at: SystemTime,
    ) -> Result<Option<AuthGrant>, IdentityError> {
        let tenant = scope.tenant();
        let grant_id_raw = grant_id.to_wire();
        let grant_id_query = grant_id.clone();
        let row = self
            .read_pool
            .identity_read(scope, move |mut conn| {
                Box::pin(async move {
                    conn.identity()
                        .active_auth_grant_row(&grant_id_query, observed_at)
                        .await
                })
            })
            .await
            .map_err(storage)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let user_id =
            ids::UserId::parse(&row.user_id).map_err(|_| corrupt("corrupt auth_grants.user_id"))?;
        let epoch = u64::try_from(row.authn_epoch_at_issue)
            .ok()
            .and_then(|value| AuthnEpoch::hydrate(value).ok())
            .ok_or_else(|| corrupt("corrupt auth_grants.authn_epoch_at_issue"))?;
        let status = AuthGrantStatus::from_db_str(&row.status)
            .ok_or_else(|| corrupt("corrupt auth_grants.status"))?;
        let close_reason = match row.close_reason {
            None => None,
            Some(raw) => Some(
                CredentialSecurityEventKind::from_db_str(&raw)
                    .ok_or_else(|| corrupt("corrupt auth_grants.close_reason"))?,
            ),
        };
        let grant_id = AuthGrantId::hydrate(grant_id_raw)
            .map_err(|_| corrupt("corrupt auth_grants.grant_id"))?;
        AuthGrant::hydrate(AuthGrantSnapshot {
            id: grant_id,
            tenant,
            user_id,
            auth_time: epoch_secs_to_time(row.auth_time),
            authn_epoch_at_issue: epoch,
            status,
            expires_at: epoch_secs_to_time(row.expires_at),
            created_at: epoch_secs_to_time(row.created_at),
            closed_at: row.closed_at.map(epoch_secs_to_time),
            close_reason,
        })
        .map(Some)
        .map_err(|_| corrupt("corrupt auth_grants state"))
    }
}

fn validate_login_binding(
    scope: TenantRepoScope,
    envelope_tenant: rss_request_context::TenantId,
    grant: &AuthGrant,
    refresh: &RefreshTokenRecord,
) -> Result<(), std::io::Error> {
    if scope.tenant() != grant.tenant()
        || envelope_tenant != grant.tenant()
        || refresh.tenant() != grant.tenant()
        || refresh.auth_grant_id() != grant.id()
        || refresh.user_id() != grant.user_id()
        || refresh.issuance_epoch() != grant.authn_epoch_at_issue()
        || refresh.auth_grant_status() != AuthGrantStatus::Active
        || refresh.status() != RefreshStatus::Active
        || refresh.parent_id().is_some()
        || refresh.lineage_id() != refresh.id()
        || refresh.expires_at() > grant.expires_at()
    {
        return Err(std::io::Error::other(
            "login grant mutation contains mismatched grant, refresh or tenant evidence",
        ));
    }
    Ok(())
}

async fn lock_active_login_account(
    conn: &mut IdentityTx<'_, '_, ServingWriteLane>,
    grant: &AuthGrant,
) -> Result<bool, sqlx::Error> {
    conn.identity().lock_active_login_account(grant).await
}

async fn write_auth_grant(
    conn: &mut IdentityTx<'_, '_, ServingWriteLane>,
    grant: &AuthGrant,
) -> Result<(), sqlx::Error> {
    conn.identity().insert_auth_grant(grant).await
}

async fn write_initial_refresh(
    conn: &mut IdentityTx<'_, '_, ServingWriteLane>,
    record: &RefreshTokenRecord,
) -> Result<(), sqlx::Error> {
    conn.identity().insert_initial_refresh(record).await
}

#[derive(Clone)]
pub(crate) struct GrantCloseCas {
    pub(crate) tenant: rss_request_context::TenantId,
    pub(crate) grant_id: String,
    pub(crate) user_id: String,
    pub(crate) epoch: i64,
    pub(crate) expected_status: &'static str,
    pub(crate) expected_closed_at: Option<i64>,
    pub(crate) expected_reason: Option<&'static str>,
    pub(crate) next_status: &'static str,
    pub(crate) closed_at: i64,
    pub(crate) reason: &'static str,
}

impl TryFrom<(&AuthGrant, &AuthGrant)> for GrantCloseCas {
    type Error = IdentityError;

    fn try_from((expected, next): (&AuthGrant, &AuthGrant)) -> Result<Self, Self::Error> {
        if expected.id() != next.id()
            || expected.tenant() != next.tenant()
            || expected.user_id() != next.user_id()
            || expected.authn_epoch_at_issue() != next.authn_epoch_at_issue()
        {
            return Err(corrupt("auth grant close mutation identity mismatch"));
        }
        Ok(Self {
            tenant: next.tenant(),
            grant_id: next.id().to_wire(),
            user_id: next.user_id().as_uuid().to_string(),
            epoch: i64::try_from(next.authn_epoch_at_issue().get())
                .map_err(|_| corrupt("auth grant epoch exceeds PostgreSQL bigint"))?,
            expected_status: expected.status().as_db_str(),
            expected_closed_at: expected
                .closed_at()
                .map(|value| vocab::UnixEpochSeconds::saturating_from_system_time(value).get()),
            expected_reason: expected.close_reason().map(|reason| reason.as_db_str()),
            next_status: next.status().as_db_str(),
            closed_at: vocab::UnixEpochSeconds::saturating_from_system_time(
                next.closed_at()
                    .ok_or_else(|| corrupt("closed auth grant lacks closed_at"))?,
            )
            .get(),
            reason: next
                .close_reason()
                .ok_or_else(|| corrupt("closed auth grant lacks close_reason"))?
                .as_db_str(),
        })
    }
}

pub(crate) async fn apply_grant_close_cas(
    conn: &mut IdentityTx<'_, '_, ServingWriteLane>,
    close: &GrantCloseCas,
) -> Result<bool, sqlx::Error> {
    conn.identity().close_auth_grant_cas(close).await
}

fn storage(error: sqlx::Error) -> IdentityError {
    crate::tx_retry::identity_storage_error(error)
}

fn corrupt(message: &'static str) -> IdentityError {
    IdentityError::Storage(Box::new(std::io::Error::other(message)))
}
