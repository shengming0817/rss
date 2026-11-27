//! Borrowed-transaction subject admission for host-owned native platform protocols.
//! ref: sqlx v0.9.0 sqlx-core/src/connection.rs (transaction detection).
use super::PlatformBinding;
use rss_identity_core::InstanceId;
use serde::{Deserialize, Serialize};
use sqlx::{Connection, PgConnection};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlatformSubjectVersion {
    auth_epoch: i64,
    membership_epoch: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum PlatformSubjectAdmissionError {
    #[error("platform subject admission rejected")]
    Rejected,
    #[error(transparent)]
    Storage(#[from] rss_transactional_messaging_postgres::PgError),
}
impl From<sqlx::Error> for PlatformSubjectAdmissionError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(error.into())
    }
}

/// Check Identity-owned subject state without issuing a session or reading credentials.
/// Requires an explicit READ COMMITTED transaction scoped to the binding's tenant and instance.
/// Call after Audit/Ledger locks and before host device/authorization/business locks. Shared tenant, source Provider,
/// account and membership locks last until the caller settles its transaction. The host must check its binding,
/// source, platform proof and authorization in that same transaction before issuing native tokens.
/// Persist the returned version with the source; subsequent use must supply it as `expected` so
/// disabling/re-enabling an account or membership cannot resurrect an old native registration.
/// This value is not an authentication credential and makes no assurance claim.
pub async fn admit_platform_subject_on(
    c: &mut PgConnection,
    instance: InstanceId,
    binding: &PlatformBinding,
    expected: Option<PlatformSubjectVersion>,
) -> Result<PlatformSubjectVersion, PlatformSubjectAdmissionError> {
    use PlatformSubjectAdmissionError::Rejected;
    if !c.is_in_transaction() || !binding.valid() || binding.instance != instance {
        return Err(Rejected);
    }
    let (scope, isolation): (Option<String>, String) = sqlx::query_as(
        "SELECT current_setting('rss.tenant_id',true),current_setting('transaction_isolation')",
    )
    .fetch_one(&mut *c)
    .await?;
    if scope.as_deref() != Some(binding.account.tenant.to_string().as_str())
        || isolation != "read committed"
        || crate::storage::authority_id(c).await? != instance.as_uuid()
    {
        return Err(Rejected);
    }
    let admitted: bool = sqlx::query_scalar("SELECT identity_authority.share_host_tenant()")
        .fetch_one(&mut *c)
        .await?;
    if !admitted {
        return Err(Rejected);
    }
    if let Some(source) = &binding.external_identity {
        let locked: bool = sqlx::query_scalar("SELECT identity_authority.share_provider($1::uuid)")
            .bind(source.provider.to_string())
            .fetch_one(&mut *c)
            .await?;
        if !locked {
            return Err(Rejected);
        }
    }
    let locked: bool = sqlx::query_scalar("SELECT identity_authority.share_subject($1)")
        .bind(binding.account.principal.as_uuid())
        .fetch_one(&mut *c)
        .await?;
    if !locked {
        return Err(Rejected);
    }
    let epochs: Option<(i64, i64)> = sqlx::query_as(
        "SELECT a.auth_epoch,m.epoch FROM identity_authority.accounts a JOIN identity_authority.memberships m USING(tenant_id,principal_id) WHERE a.tenant_id=$1::uuid AND a.principal_id=$2 AND a.enabled AND m.active",
    ).bind(binding.account.tenant.to_string()).bind(binding.account.principal.as_uuid()).fetch_optional(&mut *c).await?;
    let (auth_epoch, membership_epoch) = epochs.ok_or(Rejected)?;
    let version = PlatformSubjectVersion {
        auth_epoch,
        membership_epoch,
    };
    if auth_epoch < 1 || membership_epoch < 1 || expected.is_some_and(|v| v != version) {
        return Err(Rejected);
    }
    if !super::external_valid(c, binding).await? {
        return Err(Rejected);
    }
    Ok(version)
}

#[cfg(test)]
mod tests {
    #[test]
    fn storage_errors_keep_private_details_out_of_diagnostics() {
        use std::error::Error;
        let error = super::PlatformSubjectAdmissionError::from(sqlx::Error::Protocol(
            "private-subject-detail".into(),
        ));
        let mut current: Option<&dyn Error> = Some(&error);
        while let Some(value) = current {
            assert!(!format!("{value:?} {value}").contains("private-subject-detail"));
            current = value.source();
        }
    }
}
