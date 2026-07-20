//! PostgreSQL authentication-grant lifecycle.
//!
//! Login persists the grant root, initial refresh record and session-created outbox fact through
//! one [`PgTenantWritePool::producer_tx`]. Closing a grant revokes every bound refresh row before
//! changing root status, which is also required by the database composite FK/CHECK.
//!
//! INVARIANT: AUTH-GRANT-LOGIN-COTX-01 { level = "Hard", exec = "native-compile", source = "code", native = "combined port method plus provider-owned transaction" }.
//! INVARIANT: AUTH-GRANT-CLOSE-COTX-01 { level = "Hard", exec = "native-compile", source = "code", native = "sealed terminal mutation plus provider-owned transaction" }.
//!
//! ref: launchbadge/sqlx sqlx-core/src/transaction.rs@main

use std::time::SystemTime;

use consistency::EventEntry;
use diport::{Clock, OutboxEmitError, OutboxEnvelopeParts};
use identity::ports::{
    AuthGrant, AuthGrantCloseCommand, AuthGrantCloseReason, AuthGrantId, AuthGrantLifecycle,
    AuthGrantSnapshot, AuthGrantStatus, AuthnEpoch, IdentityError, LoginGrantMutation,
    RefreshStatus, RefreshTokenRecord, SESSION_CREATED_CONTRACT, TenantRepoScope,
};
use sqlx::Row;

#[cfg(all(test, feature = "integration"))]
use std::collections::HashMap;
#[cfg(all(test, feature = "integration"))]
use std::sync::{Arc, Mutex};

use crate::cotx::{PgTenantReadPool, PgTenantWritePool, ProducerTxOutcome};
use crate::outbox::{OutboxEnvelope, epoch_secs_to_time, metadata_with_ambient, unix_secs};
use crate::pool::{VerifiedPgReadStore, VerifiedPgWriteStore};
use crate::projection_events::ProjectionWriteRegistry;
use crate::tx_retry::{classify_identity_error, run_pg_localtx_retry};

#[cfg(all(test, feature = "integration"))]
use crate::PgStore;

pub struct PgAuthGrantLifecycle {
    read_pool: PgTenantReadPool,
    write_pool: PgTenantWritePool,
    clock: Box<dyn Clock>,
    #[cfg(all(test, feature = "integration"))]
    login_fault: Option<(String, AuthGrantLoginFault)>,
    #[cfg(all(test, feature = "integration"))]
    close_faults: Arc<Mutex<AuthGrantCloseFaultState>>,
}

#[cfg(all(test, feature = "integration"))]
#[derive(Clone, Copy)]
pub(crate) enum AuthGrantLoginFault {
    AfterGrantWrite,
    AfterRefreshWrite,
    CommitUnknown,
}

#[cfg(all(test, feature = "integration"))]
#[derive(Clone, Copy)]
pub(crate) enum AuthGrantCloseFault {
    TransientBeforeWrite,
    TransientAfterWrite,
    Permanent,
    CommitUnknown,
    RollbackFailed,
}

#[cfg(all(test, feature = "integration"))]
#[derive(Clone, Copy)]
struct AuthGrantCloseFaultPlan {
    fault: AuthGrantCloseFault,
    remaining: usize,
}

#[cfg(all(test, feature = "integration"))]
#[derive(Default)]
struct AuthGrantCloseFaultState {
    plans: HashMap<String, AuthGrantCloseFaultPlan>,
    attempts: HashMap<String, usize>,
}

#[cfg(all(test, feature = "integration"))]
pub(crate) struct AuthGrantCloseAttemptProbe {
    state: Arc<Mutex<AuthGrantCloseFaultState>>,
}

#[cfg(all(test, feature = "integration"))]
impl AuthGrantCloseAttemptProbe {
    pub(crate) fn attempts(&self, grant_id: &str) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .attempts
            .get(grant_id)
            .copied()
            .unwrap_or_default()
    }
}

impl PgAuthGrantLifecycle {
    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn new(store: &PgStore, clock: Box<dyn Clock>) -> Self {
        Self {
            read_pool: PgTenantReadPool::from_unverified_for_test(store),
            write_pool: PgTenantWritePool::from_unverified_for_test(store),
            clock,
            login_fault: None,
            close_faults: Arc::new(Mutex::new(AuthGrantCloseFaultState::default())),
        }
    }

    pub(crate) fn new_with_projection_registry(
        reader: &VerifiedPgReadStore,
        writer: &VerifiedPgWriteStore,
        clock: Box<dyn Clock>,
        projection_registry: ProjectionWriteRegistry,
    ) -> Self {
        Self {
            read_pool: PgTenantReadPool::new(reader),
            write_pool: PgTenantWritePool::with_projection_registry(writer, projection_registry),
            clock,
            #[cfg(all(test, feature = "integration"))]
            login_fault: None,
            #[cfg(all(test, feature = "integration"))]
            close_faults: Arc::new(Mutex::new(AuthGrantCloseFaultState::default())),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn with_login_fault(mut self, grant_id: &str, fault: AuthGrantLoginFault) -> Self {
        self.login_fault = Some((grant_id.to_owned(), fault));
        self
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn with_close_fault(
        self,
        grant_id: &str,
        fault: AuthGrantCloseFault,
        remaining: usize,
    ) -> Self {
        assert!(remaining > 0, "fault plan must affect at least one attempt");
        self.close_faults
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .plans
            .insert(
                grant_id.to_owned(),
                AuthGrantCloseFaultPlan { fault, remaining },
            );
        self
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn close_attempt_probe(&self) -> AuthGrantCloseAttemptProbe {
        AuthGrantCloseAttemptProbe {
            state: Arc::clone(&self.close_faults),
        }
    }
}

#[cfg(all(test, feature = "integration"))]
fn record_close_attempt(state: &Mutex<AuthGrantCloseFaultState>, grant_id: &str) {
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *state.attempts.entry(grant_id.to_owned()).or_default() += 1;
}

#[cfg(all(test, feature = "integration"))]
fn take_close_fault(
    state: &Mutex<AuthGrantCloseFaultState>,
    grant_id: &str,
) -> Option<AuthGrantCloseFault> {
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let plan = state.plans.get_mut(grant_id)?;
    let fault = plan.fault;
    plan.remaining -= 1;
    if plan.remaining == 0 {
        state.plans.remove(grant_id);
    }
    Some(fault)
}

impl AuthGrantLifecycle for PgAuthGrantLifecycle {
    async fn persist_login_grant(
        &self,
        receipt: identity::ports::LoginProducerReceipt,
        scope: TenantRepoScope,
        mutation: LoginGrantMutation,
        entry: EventEntry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<identity::ports::PersistedLoginGrantReceipt, OutboxEmitError> {
        let (grant, initial_refresh, persistence) = mutation.into_parts();
        let (contract, env_tenant, subject_id, actor, partition_key, causation_id) =
            envelope.into_parts();
        let tenant = grant.tenant();
        validate_login_binding(scope, env_tenant, &grant, &initial_refresh)
            .map_err(OutboxEmitError::new)?;
        let env = OutboxEnvelope::new(
            contract.domain().to_owned(),
            contract.contract_id().to_owned(),
            metadata_with_ambient(unix_secs(self.clock.now()), tenant, contract)
                .with_subject_id(subject_id)
                .with_actor(actor),
        )
        .with_partition_key_opt(partition_key)
        .with_causation_id_opt(causation_id);
        let generated_fact = entry.generated_fact().ok_or_else(|| {
            OutboxEmitError::new(std::io::Error::other(
                "login grant entry lacks generated fact provenance",
            ))
        })?;
        #[cfg(all(test, feature = "integration"))]
        let login_fault = self
            .login_fault
            .as_ref()
            .filter(|(grant_id, _)| grant_id == grant.id().as_str())
            .map(|(_, fault)| *fault);

        self.write_pool
            .producer_tx(
                scope,
                &entry,
                &env,
                move |tx| {
                    Box::pin(async move {
                        write_auth_grant(tx.conn(), &grant)
                            .await
                            .map_err(OutboxEmitError::new)?;
                        #[cfg(all(test, feature = "integration"))]
                        if matches!(login_fault, Some(AuthGrantLoginFault::AfterGrantWrite)) {
                            return Err(OutboxEmitError::new(std::io::Error::other(
                                "injected failure after AuthGrant write",
                            )));
                        }
                        write_initial_refresh(tx.conn(), &initial_refresh)
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
        let tenant_uuid = tenant.as_uuid().to_string();
        let grant_id_raw = grant_id.as_str().to_owned();
        let grant_id_query = grant_id_raw.clone();
        let row = self
            .read_pool
            .read(scope, move |conn| {
                Box::pin(async move {
                    sqlx::query(
                        r#"
                        SELECT user_id::text,
                               extract(epoch from auth_time)::bigint AS auth_time,
                               authn_epoch_at_issue,
                               status,
                               extract(epoch from expires_at)::bigint AS expires_at,
                               extract(epoch from created_at)::bigint AS created_at,
                               extract(epoch from closed_at)::bigint AS closed_at,
                               close_reason
                        FROM auth_grants
                        WHERE tenant_id = $1::uuid
                          AND grant_id = $2
                          AND status = 'active'
                          AND expires_at > to_timestamp($3)
                        "#,
                    )
                    .bind(tenant_uuid)
                    .bind(grant_id_query)
                    .bind(unix_secs(observed_at))
                    .fetch_optional(&mut *conn)
                    .await
                })
            })
            .await
            .map_err(storage)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let user_raw: String = row.try_get("user_id").map_err(storage)?;
        let auth_time: i64 = row.try_get("auth_time").map_err(storage)?;
        let epoch: i64 = row.try_get("authn_epoch_at_issue").map_err(storage)?;
        let status_raw: String = row.try_get("status").map_err(storage)?;
        let expires_at: i64 = row.try_get("expires_at").map_err(storage)?;
        let created_at: i64 = row.try_get("created_at").map_err(storage)?;
        let closed_at: Option<i64> = row.try_get("closed_at").map_err(storage)?;
        let close_reason_raw: Option<String> = row.try_get("close_reason").map_err(storage)?;
        let user_id =
            ids::UserId::parse(&user_raw).map_err(|_| corrupt("corrupt auth_grants.user_id"))?;
        let epoch = u64::try_from(epoch)
            .ok()
            .and_then(|value| AuthnEpoch::hydrate(value).ok())
            .ok_or_else(|| corrupt("corrupt auth_grants.authn_epoch_at_issue"))?;
        let status = AuthGrantStatus::from_db_str(&status_raw)
            .ok_or_else(|| corrupt("corrupt auth_grants.status"))?;
        let close_reason = match close_reason_raw {
            None => None,
            Some(raw) => Some(
                AuthGrantCloseReason::from_db_str(&raw)
                    .ok_or_else(|| corrupt("corrupt auth_grants.close_reason"))?,
            ),
        };
        AuthGrant::hydrate(AuthGrantSnapshot {
            id: AuthGrantId::hydrate(grant_id_raw),
            tenant,
            user_id,
            auth_time: epoch_secs_to_time(auth_time),
            authn_epoch_at_issue: epoch,
            status,
            expires_at: epoch_secs_to_time(expires_at),
            created_at: epoch_secs_to_time(created_at),
            closed_at: closed_at.map(epoch_secs_to_time),
            close_reason,
        })
        .map(Some)
        .map_err(|_| corrupt("corrupt auth_grants state"))
    }

    async fn close(
        &self,
        scope: TenantRepoScope,
        command: AuthGrantCloseCommand,
    ) -> Result<(), IdentityError> {
        let (mutation, observation) = command.into_parts();
        let next = mutation.into_next();
        if next.tenant() != scope.tenant() || next.status() == AuthGrantStatus::Active {
            return Err(corrupt("auth grant close scope or status mismatch"));
        }
        let close_row = AuthGrantCloseRow::try_from(&next)?;
        #[cfg(all(test, feature = "integration"))]
        let grant_id = close_row.grant_id.clone();
        #[cfg(all(test, feature = "integration"))]
        let close_faults = Arc::clone(&self.close_faults);
        run_pg_localtx_retry(
            observation,
            |_attempt, deadline| {
                let close_row = close_row.clone();
                #[cfg(all(test, feature = "integration"))]
                let grant_id = grant_id.clone();
                #[cfg(all(test, feature = "integration"))]
                let close_faults = Arc::clone(&close_faults);
                #[cfg(all(test, feature = "integration"))]
                record_close_attempt(&close_faults, &grant_id);
                async move {
                    self.write_pool
                        .retry_write(
                            scope,
                            deadline,
                            move |tx| {
                                Box::pin(async move {
                                    #[cfg(all(test, feature = "integration"))]
                                    let fault = take_close_fault(&close_faults, &grant_id);
                                    #[cfg(all(test, feature = "integration"))]
                                    if matches!(
                                        fault,
                                        Some(AuthGrantCloseFault::TransientBeforeWrite)
                                    ) {
                                        return Err(storage(sqlx::Error::PoolTimedOut));
                                    }
                                    close_auth_grant_tx(tx.conn(), &close_row)
                                        .await
                                        .map_err(storage)?;
                                    #[cfg(all(test, feature = "integration"))]
                                    if let Some(fault) = fault {
                                        match fault {
                                            AuthGrantCloseFault::TransientBeforeWrite => {}
                                            AuthGrantCloseFault::TransientAfterWrite => {
                                                return Err(storage(sqlx::Error::PoolTimedOut));
                                            }
                                            AuthGrantCloseFault::Permanent => {
                                                return Err(IdentityError::Storage(Box::new(
                                                    std::io::Error::other(
                                                        "injected AuthGrant close failure",
                                                    ),
                                                )));
                                            }
                                            AuthGrantCloseFault::CommitUnknown => {
                                                tx.inject_commit_unknown_after_commit()
                                                    .await
                                                    .map_err(storage)?;
                                            }
                                            AuthGrantCloseFault::RollbackFailed => {
                                                tx.inject_rollback_failed_after_rollback()
                                                    .await
                                                    .map_err(storage)?;
                                                return Err(storage(sqlx::Error::PoolTimedOut));
                                            }
                                        }
                                    }
                                    Ok(())
                                })
                            },
                            storage,
                        )
                        .await
                }
            },
            classify_identity_error,
        )
        .await
    }
}

fn validate_login_binding(
    scope: TenantRepoScope,
    envelope_tenant: vocab::TenantId,
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

async fn write_auth_grant(
    conn: &mut sqlx::PgConnection,
    grant: &AuthGrant,
) -> Result<(), sqlx::Error> {
    let epoch = i64::try_from(grant.authn_epoch_at_issue().get())
        .map_err(|_| sqlx::Error::Protocol("auth grant epoch exceeds bigint".to_owned()))?;
    sqlx::query(
        r#"
        INSERT INTO auth_grants (
            tenant_id, grant_id, user_id, auth_time, authn_epoch_at_issue,
            status, expires_at, created_at, closed_at, close_reason
        )
        VALUES (
            $1::uuid, $2, $3::uuid, to_timestamp($4), $5,
            $6, to_timestamp($7), to_timestamp($8), NULL, NULL
        )
        "#,
    )
    .bind(grant.tenant().as_uuid().to_string())
    .bind(grant.id().as_str())
    .bind(grant.user_id().as_uuid().to_string())
    .bind(unix_secs(grant.auth_time()))
    .bind(epoch)
    .bind(grant.status().as_db_str())
    .bind(unix_secs(grant.expires_at()))
    .bind(unix_secs(grant.created_at()))
    .execute(conn)
    .await
    .map(|_| ())
}

async fn write_initial_refresh(
    conn: &mut sqlx::PgConnection,
    record: &RefreshTokenRecord,
) -> Result<(), sqlx::Error> {
    let epoch = i64::try_from(record.issuance_epoch().get())
        .map_err(|_| sqlx::Error::Protocol("refresh epoch exceeds bigint".to_owned()))?;
    sqlx::query(
        r#"
        INSERT INTO refresh_tokens (
            id, tenant_id, auth_grant_id, user_id, authn_epoch_at_issue,
            auth_grant_status, token_hash, parent_id, lineage_id, status,
            issued_at, expires_at
        )
        VALUES (
            $1::uuid, $2::uuid, $3, $4::uuid, $5,
            $6, $7, NULL, $8::uuid, $9,
            to_timestamp($10), to_timestamp($11)
        )
        "#,
    )
    .bind(record.id().as_str())
    .bind(record.tenant().as_uuid().to_string())
    .bind(record.auth_grant_id().as_str())
    .bind(record.user_id().as_uuid().to_string())
    .bind(epoch)
    .bind(record.auth_grant_status().as_db_str())
    .bind(record.token_hash().as_bytes() as &[u8])
    .bind(record.lineage_id().as_str())
    .bind(record.status().as_db_str())
    .bind(unix_secs(record.issued_at()))
    .bind(unix_secs(record.expires_at()))
    .execute(conn)
    .await
    .map(|_| ())
}

#[derive(Clone)]
struct AuthGrantCloseRow {
    tenant_uuid: String,
    grant_id: String,
    user_id: String,
    epoch: i64,
    status: &'static str,
    closed_at: i64,
    reason: &'static str,
}

impl TryFrom<&AuthGrant> for AuthGrantCloseRow {
    type Error = IdentityError;

    fn try_from(grant: &AuthGrant) -> Result<Self, Self::Error> {
        Ok(Self {
            tenant_uuid: grant.tenant().as_uuid().to_string(),
            grant_id: grant.id().as_str().to_owned(),
            user_id: grant.user_id().as_uuid().to_string(),
            epoch: i64::try_from(grant.authn_epoch_at_issue().get())
                .map_err(|_| corrupt("auth grant epoch exceeds PostgreSQL bigint"))?,
            status: grant.status().as_db_str(),
            closed_at: unix_secs(
                grant
                    .closed_at()
                    .ok_or_else(|| corrupt("closed auth grant lacks closed_at"))?,
            ),
            reason: grant
                .close_reason()
                .ok_or_else(|| corrupt("closed auth grant lacks close_reason"))?
                .as_db_str(),
        })
    }
}

async fn close_auth_grant_tx(
    conn: &mut sqlx::PgConnection,
    close: &AuthGrantCloseRow,
) -> Result<(), sqlx::Error> {
    let closed: Option<String> = sqlx::query_scalar(
        r#"
        WITH revoked AS (
            UPDATE refresh_tokens
            SET status = 'revoked'
            WHERE tenant_id = $1::uuid
              AND auth_grant_id = $2
              AND user_id = $3::uuid
              AND authn_epoch_at_issue = $4
              AND status <> 'revoked'
            RETURNING 1
        )
        UPDATE auth_grants
        SET status = $5,
            closed_at = to_timestamp($6),
            close_reason = $7
        WHERE tenant_id = $1::uuid
          AND grant_id = $2
          AND user_id = $3::uuid
          AND authn_epoch_at_issue = $4
          AND status = 'active'
          AND (SELECT count(*) FROM revoked) >= 0
        RETURNING grant_id
        "#,
    )
    .bind(&close.tenant_uuid)
    .bind(&close.grant_id)
    .bind(&close.user_id)
    .bind(close.epoch)
    .bind(close.status)
    .bind(close.closed_at)
    .bind(close.reason)
    .fetch_optional(&mut *conn)
    .await?;
    if closed.as_deref() == Some(close.grant_id.as_str()) {
        return Ok(());
    }

    let already_closed: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM auth_grants
            WHERE tenant_id = $1::uuid
              AND grant_id = $2
              AND user_id = $3::uuid
              AND authn_epoch_at_issue = $4
              AND status = $5
              AND close_reason = $6
        )
        "#,
    )
    .bind(&close.tenant_uuid)
    .bind(&close.grant_id)
    .bind(&close.user_id)
    .bind(close.epoch)
    .bind(close.status)
    .bind(close.reason)
    .fetch_one(&mut *conn)
    .await?;
    if already_closed {
        Ok(())
    } else {
        Err(sqlx::Error::Protocol(
            "auth grant close lost active root".to_owned(),
        ))
    }
}

fn storage(error: sqlx::Error) -> IdentityError {
    IdentityError::Storage(Box::new(error))
}

fn corrupt(message: &'static str) -> IdentityError {
    IdentityError::Storage(Box::new(std::io::Error::other(message)))
}
