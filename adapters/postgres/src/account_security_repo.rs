//! PostgreSQL account-security state adapter.

use crate::cotx::{ServingReadLane, TenantDb};
use crate::pool::VerifiedPgReadStore;
use identity::ports::{
    AccountSecurityReadRepo, AccountSecuritySnapshot, AccountSecurityState, AccountStatus,
    IdentityError, TenantRepoScope,
};
use rss_request_context::TenantId;

/// PostgreSQL read model for authentication gates.
pub struct PgAccountSecurityRepo {
    read_pool: TenantDb<ServingReadLane>,
}

impl Clone for PgAccountSecurityRepo {
    fn clone(&self) -> Self {
        Self {
            read_pool: self.read_pool.clone(),
        }
    }
}

impl PgAccountSecurityRepo {
    pub(crate) fn new(reader: &VerifiedPgReadStore) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::new(reader),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::from_unverified_for_test(store),
        }
    }
}

fn storage(error: impl std::error::Error + Send + Sync + 'static) -> IdentityError {
    crate::tx_retry::identity_storage_error(error)
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
    pub(crate) status_changed_at_micros: i64,
    pub(crate) updated_at_micros: i64,
}

fn epoch_micros_to_time(
    micros: i64,
    field: &'static str,
) -> Result<std::time::SystemTime, IdentityError> {
    let micros = u64::try_from(micros).map_err(|_| storage(std::io::Error::other(field)))?;
    Ok(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_micros(micros))
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
        status_changed_at: epoch_micros_to_time(
            row.status_changed_at_micros,
            "negative account security status_changed_at",
        )?,
        updated_at: epoch_micros_to_time(
            row.updated_at_micros,
            "negative account security updated_at",
        )?,
    })
    .map_err(storage)
}

impl AccountSecurityReadRepo for PgAccountSecurityRepo {
    async fn find(
        &self,
        scope: TenantRepoScope,
        user_id: ids::UserId,
    ) -> Result<Option<AccountSecurityState>, IdentityError> {
        let tenant = scope.tenant();
        let query_user = user_id;
        let raw = self
            .read_pool
            .identity_read(scope, move |mut conn| {
                Box::pin(async move { conn.identity().account_security_row(&query_user).await })
            })
            .await
            .map_err(storage)?;
        raw.map(|row| hydrate_security(tenant, user_id, row))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::{SecurityRow, hydrate_security, status_from_db, status_to_db};
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

    #[test]
    fn account_security_hydration_rejects_each_negative_persisted_timestamp()
    -> Result<(), Box<dyn std::error::Error>> {
        let tenant = rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?;
        let user_id = ids::UserId::parse("67e55044-10b1-426f-9247-bb680e5fe0c8")?;

        for (status_changed_at_micros, updated_at_micros, field) in
            [(-1, 0, "status_changed_at"), (0, -1, "updated_at")]
        {
            let hydrated = hydrate_security(
                tenant,
                user_id,
                SecurityRow {
                    status: "active".to_owned(),
                    authn_epoch: 0,
                    version: 1,
                    status_changed_at_micros,
                    updated_at_micros,
                },
            );
            assert!(
                hydrated.is_err(),
                "negative persisted {field} must fail closed instead of becoming Unix epoch"
            );
        }
        Ok(())
    }
}
