//! PostgreSQL account-security state adapter.

use crate::cotx::{PgTenantReadPool, PgTenantWritePool};
use crate::outbox::{epoch_secs_to_time, unix_secs};
use crate::pool::{VerifiedPgReadStore, VerifiedPgWriteStore};
use identity::ports::{
    AccountSecurityLifecycle, AccountSecurityMutation, AccountSecurityReadRepo,
    AccountSecuritySnapshot, AccountSecurityState, AccountStatus, IdentityError, TenantId,
    TenantRepoScope,
};

/// The single PostgreSQL provider for read-only authentication gates and sealed lifecycle CAS.
pub struct PgAccountSecurityRepo {
    read_pool: PgTenantReadPool,
    write_pool: PgTenantWritePool,
}

impl Clone for PgAccountSecurityRepo {
    fn clone(&self) -> Self {
        Self {
            read_pool: self.read_pool.clone(),
            write_pool: self.write_pool.clone(),
        }
    }
}

impl PgAccountSecurityRepo {
    pub(crate) fn new(reader: &VerifiedPgReadStore, writer: &VerifiedPgWriteStore) -> Self {
        Self {
            read_pool: PgTenantReadPool::new(reader),
            write_pool: PgTenantWritePool::new(writer),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            read_pool: PgTenantReadPool::from_unverified_for_test(store),
            write_pool: PgTenantWritePool::from_unverified_for_test(store),
        }
    }
}

fn storage(error: impl std::error::Error + Send + Sync + 'static) -> IdentityError {
    crate::tx_retry::identity_storage_error(error)
}

fn tenant_param(tenant: TenantId) -> String {
    tenant.as_uuid().to_string()
}

pub(crate) fn status_from_db(raw: &str) -> Result<AccountStatus, IdentityError> {
    match raw {
        "active" => Ok(AccountStatus::Active),
        "suspended" => Ok(AccountStatus::Suspended),
        "locked" => Ok(AccountStatus::Locked),
        "deactivated" => Ok(AccountStatus::Deactivated),
        _ => Err(storage(std::io::Error::other(
            "invalid persisted account security status",
        ))),
    }
}

pub(crate) fn status_to_db(status: AccountStatus) -> &'static str {
    match status {
        AccountStatus::Active => "active",
        AccountStatus::Suspended => "suspended",
        AccountStatus::Locked => "locked",
        AccountStatus::Deactivated => "deactivated",
    }
}

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct SecurityRow {
    pub(crate) status: String,
    pub(crate) authn_epoch: i64,
    pub(crate) version: i64,
    pub(crate) status_changed_at: i64,
    pub(crate) updated_at: i64,
}

pub(crate) fn hydrate_security(
    tenant: TenantId,
    user_id: ids::UserId,
    row: SecurityRow,
) -> Result<AccountSecurityState, IdentityError> {
    let authn_epoch = u64::try_from(row.authn_epoch)
        .map_err(|_| storage(std::io::Error::other("negative authentication epoch")))?;
    let version = u64::try_from(row.version)
        .map_err(|_| storage(std::io::Error::other("negative account security version")))?;
    AccountSecurityState::try_from(AccountSecuritySnapshot {
        tenant,
        user_id,
        status: status_from_db(&row.status)?,
        authn_epoch,
        version,
        status_changed_at: epoch_secs_to_time(row.status_changed_at),
        updated_at: epoch_secs_to_time(row.updated_at),
    })
    .map_err(storage)
}

async fn fetch_row(
    conn: &mut sqlx::PgConnection,
    tenant: &str,
    user: &str,
) -> Result<Option<SecurityRow>, sqlx::Error> {
    sqlx::query_as::<_, SecurityRow>(
        r#"
        SELECT status,
               authn_epoch,
               version,
               extract(epoch from status_changed_at)::bigint AS status_changed_at,
               extract(epoch from updated_at)::bigint AS updated_at
        FROM account_security_states
        WHERE tenant_id = $1::uuid AND user_id = $2::uuid
        "#,
    )
    .bind(tenant)
    .bind(user)
    .fetch_optional(conn)
    .await
}

impl AccountSecurityReadRepo for PgAccountSecurityRepo {
    async fn find(
        &self,
        scope: TenantRepoScope,
        user_id: ids::UserId,
    ) -> Result<Option<AccountSecurityState>, IdentityError> {
        let tenant = scope.tenant();
        let tenant_sql = tenant_param(tenant);
        let user_sql = user_id.as_uuid().to_string();
        let raw = self
            .read_pool
            .read(scope, move |conn| {
                Box::pin(async move { fetch_row(conn, &tenant_sql, &user_sql).await })
            })
            .await
            .map_err(storage)?;
        raw.map(|row| hydrate_security(tenant, user_id, row))
            .transpose()
    }
}

impl AccountSecurityLifecycle for PgAccountSecurityRepo {
    async fn apply_transition(
        &self,
        scope: TenantRepoScope,
        mutation: AccountSecurityMutation,
    ) -> Result<AccountSecurityState, IdentityError> {
        let tenant = scope.tenant();
        let (expected, next) = mutation.into_parts();
        if expected.tenant() != tenant
            || next.tenant() != tenant
            || expected.user_id() != next.user_id()
        {
            return Err(storage(std::io::Error::other(
                "account security tenant scope mismatch",
            )));
        }
        let tenant_sql = tenant_param(tenant);
        let user_id = next.user_id();
        let user_sql = user_id.as_uuid().to_string();
        let status = status_to_db(next.status());
        let epoch = i64::try_from(next.authn_epoch().get())
            .map_err(|_| storage(std::io::Error::other("authentication epoch overflow")))?;
        let version = i64::try_from(next.version().get())
            .map_err(|_| storage(std::io::Error::other("account security version overflow")))?;
        let expected_version = i64::try_from(expected.version().get())
            .map_err(|_| storage(std::io::Error::other("expected version overflow")))?;
        let expected_status = status_to_db(expected.status());
        let expected_epoch = i64::try_from(expected.authn_epoch().get())
            .map_err(|_| storage(std::io::Error::other("expected epoch overflow")))?;
        let changed = unix_secs(next.status_changed_at());
        let updated = unix_secs(next.updated_at());

        let applied = self
            .write_pool
            .write(
                scope,
                move |tx| {
                    Box::pin(async move {
                        let result = sqlx::query(
                            r#"
                            UPDATE account_security_states
                            SET status = $3,
                                authn_epoch = $4,
                                version = $5,
                                status_changed_at = to_timestamp($6),
                                updated_at = to_timestamp($7)
                            WHERE tenant_id = $1::uuid
                              AND user_id = $2::uuid
                              AND version = $8
                              AND status = $9
                              AND authn_epoch = $10
                            "#,
                        )
                        .bind(tenant_sql)
                        .bind(user_sql)
                        .bind(status)
                        .bind(epoch)
                        .bind(version)
                        .bind(changed)
                        .bind(updated)
                        .bind(expected_version)
                        .bind(expected_status)
                        .bind(expected_epoch)
                        .execute(tx.conn())
                        .await
                        .map_err(storage)?;
                        Ok(result.rows_affected())
                    })
                },
                storage,
            )
            .await?;
        if applied != 1 {
            return Err(IdentityError::VersionConflict);
        }
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::{status_from_db, status_to_db};
    use identity::ports::{AccountStatus, IdentityError};

    #[test]
    fn account_security_status_codec_is_closed_and_roundtrips_every_variant()
    -> Result<(), IdentityError> {
        let cases = [
            (AccountStatus::Active, "active"),
            (AccountStatus::Suspended, "suspended"),
            (AccountStatus::Locked, "locked"),
            (AccountStatus::Deactivated, "deactivated"),
        ];
        for (status, encoded) in cases {
            assert_eq!(status_to_db(status), encoded);
            assert_eq!(status_from_db(encoded)?, status);
        }

        assert!(status_from_db("pending").is_err());
        assert!(status_from_db("").is_err());
        Ok(())
    }
}
