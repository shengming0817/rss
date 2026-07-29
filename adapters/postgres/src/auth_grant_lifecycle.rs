//! PostgreSQL authentication-grant lifecycle.
//!
//! Login persists the grant root, initial refresh record and session-created outbox fact through
//! one [`PgTenantWritePool::producer_tx`]. Terminal security mutations are exclusively owned by
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
use consistency::EventEntry;
use diport::{Clock, OutboxEmitError, OutboxEnvelopeParts};
use identity::ports::{
    AuthGrantLifecycle, IdentityError, LoginGrantMutation, RefreshStatus, RefreshTokenRecord,
    SESSION_CREATED_CONTRACT, TenantRepoScope,
};
use sqlx::Row;

#[cfg(all(test, feature = "integration"))]
use std::sync::Arc;

use crate::cotx::{PgTenantReadPool, PgTenantWritePool, ProducerTxOutcome};
use crate::outbox::{OutboxEnvelope, epoch_secs_to_time, metadata_with_ambient, unix_secs};
use crate::pool::{VerifiedPgReadStore, VerifiedPgWriteStore};
use crate::projection_events::ProjectionWriteRegistry;

#[cfg(all(test, feature = "integration"))]
use crate::PgStore;

pub struct PgAuthGrantLifecycle {
    read_pool: PgTenantReadPool,
    write_pool: PgTenantWritePool,
    clock: Box<dyn Clock>,
    #[cfg(all(test, feature = "integration"))]
    login_fault: Option<(String, AuthGrantLoginFault)>,
    #[cfg(all(test, feature = "integration"))]
    login_lock_gate: Option<AuthGrantLoginLockGate>,
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
            read_pool: PgTenantReadPool::from_unverified_for_test(store),
            write_pool: PgTenantWritePool::from_unverified_for_test(store),
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
            read_pool: PgTenantReadPool::new(reader),
            write_pool: PgTenantWritePool::with_projection_registry(writer, projection_registry),
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
        #[cfg(all(test, feature = "integration"))]
        let login_lock_gate = self.login_lock_gate.clone();

        self.write_pool
            .producer_tx(
                scope,
                &entry,
                &env,
                move |tx| {
                    Box::pin(async move {
                        let account_matches = lock_active_login_account(tx.conn(), &grant)
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

async fn lock_active_login_account(
    conn: &mut sqlx::PgConnection,
    grant: &AuthGrant,
) -> Result<bool, sqlx::Error> {
    let expected_epoch = i64::try_from(grant.authn_epoch_at_issue().get())
        .map_err(|_| sqlx::Error::Protocol("auth grant epoch exceeds bigint".to_owned()))?;
    let state: Option<(String, i64)> = sqlx::query_as(
        r#"
        SELECT status, authn_epoch
        FROM account_security_states
        WHERE tenant_id = $1::uuid
          AND user_id = $2::uuid
        FOR UPDATE
        "#,
    )
    .bind(grant.tenant().as_uuid().to_string())
    .bind(grant.user_id().as_uuid().to_string())
    .fetch_optional(&mut *conn)
    .await?;
    Ok(matches!(state, Some((status, epoch)) if status == "active" && epoch == expected_epoch))
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
pub(crate) struct GrantCloseCas {
    tenant_uuid: String,
    grant_id: String,
    user_id: String,
    epoch: i64,
    expected_status: &'static str,
    expected_closed_at: Option<i64>,
    expected_reason: Option<&'static str>,
    next_status: &'static str,
    closed_at: i64,
    reason: &'static str,
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
            tenant_uuid: next.tenant().as_uuid().to_string(),
            grant_id: next.id().as_str().to_owned(),
            user_id: next.user_id().as_uuid().to_string(),
            epoch: i64::try_from(next.authn_epoch_at_issue().get())
                .map_err(|_| corrupt("auth grant epoch exceeds PostgreSQL bigint"))?,
            expected_status: expected.status().as_db_str(),
            expected_closed_at: expected.closed_at().map(unix_secs),
            expected_reason: expected.close_reason().map(|reason| reason.as_db_str()),
            next_status: next.status().as_db_str(),
            closed_at: unix_secs(
                next.closed_at()
                    .ok_or_else(|| corrupt("closed auth grant lacks closed_at"))?,
            ),
            reason: next
                .close_reason()
                .ok_or_else(|| corrupt("closed auth grant lacks close_reason"))?
                .as_db_str(),
        })
    }
}

pub(crate) async fn apply_grant_close_cas(
    conn: &mut sqlx::PgConnection,
    close: &GrantCloseCas,
) -> Result<bool, sqlx::Error> {
    let account_locked: Option<i32> = sqlx::query_scalar(
        r#"
        SELECT 1
        FROM account_security_states
        WHERE tenant_id = $1::uuid
          AND user_id = $2::uuid
        FOR UPDATE
        "#,
    )
    .bind(&close.tenant_uuid)
    .bind(&close.user_id)
    .fetch_optional(&mut *conn)
    .await?;
    if account_locked.is_none() {
        return Ok(false);
    }

    sqlx::query(
        "SELECT id FROM refresh_tokens \
         WHERE tenant_id = $1::uuid \
           AND auth_grant_id = $2 \
           AND user_id = $3::uuid \
           AND authn_epoch_at_issue = $4 \
         ORDER BY id FOR UPDATE",
    )
    .bind(&close.tenant_uuid)
    .bind(&close.grant_id)
    .bind(&close.user_id)
    .bind(close.epoch)
    .fetch_all(&mut *conn)
    .await?;

    let closed: Option<String> = sqlx::query_scalar(
        r#"
        WITH revoked AS (
            UPDATE refresh_tokens
            SET status = 'revoked'
            WHERE tenant_id = $1::uuid
              AND auth_grant_id = $2
              AND user_id = $3::uuid
              AND authn_epoch_at_issue = $4
              AND auth_grant_status = $8
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
          AND status = $8
          AND closed_at IS NOT DISTINCT FROM to_timestamp($9)
          AND close_reason IS NOT DISTINCT FROM $10
          AND (SELECT count(*) FROM revoked) >= 0
        RETURNING grant_id
        "#,
    )
    .bind(&close.tenant_uuid)
    .bind(&close.grant_id)
    .bind(&close.user_id)
    .bind(close.epoch)
    .bind(close.next_status)
    .bind(close.closed_at)
    .bind(close.reason)
    .bind(close.expected_status)
    .bind(close.expected_closed_at)
    .bind(close.expected_reason)
    .fetch_optional(&mut *conn)
    .await?;
    if closed.as_deref() == Some(close.grant_id.as_str()) {
        return Ok(true);
    }

    Ok(false)
}

fn storage(error: sqlx::Error) -> IdentityError {
    crate::tx_retry::identity_storage_error(error)
}

fn corrupt(message: &'static str) -> IdentityError {
    IdentityError::Storage(Box::new(std::io::Error::other(message)))
}
