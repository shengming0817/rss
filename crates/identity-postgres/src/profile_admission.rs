//! Source publication admission in a host-owned transaction; this grants no person access.
//! ref: sqlx v0.9.0 sqlx-core/src/connection.rs (borrowed transaction detection).
use crate::{ProfileSource, ProfileSourceView};
use rss_identity_core::{InstanceId, profile::ProfileSettings};
use rss_request_context::TenantId;
use sqlx::{Connection, PgConnection, Row};

#[derive(Debug, thiserror::Error)]
pub enum ProfileSourceAdmissionError {
    #[error("profile source admission rejected")]
    Rejected,
    #[error("profile source storage contract invalid")]
    Invariant,
    #[error(transparent)]
    Storage(#[from] rss_transactional_messaging_postgres::PgError),
}
impl From<sqlx::Error> for ProfileSourceAdmissionError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(error.into())
    }
}
/// Call after Audit/Ledger locks and before host authorization/business locks.
/// Requires an explicit READ COMMITTED, tenant-scoped transaction on this instance's database. Shared tenant admission and the
/// selected IdP's Provider lock remain held until the caller commits or rolls back. No pool, credentials, sessions, profile observations or host permissions are read.
pub async fn admit_profile_source_on(
    c: &mut PgConnection,
    instance: InstanceId,
    tenant: TenantId,
    source: ProfileSource,
) -> Result<ProfileSourceView, ProfileSourceAdmissionError> {
    use ProfileSourceAdmissionError as Error;
    if !c.is_in_transaction() {
        return Err(Error::Rejected);
    }
    let (scope, isolation): (Option<String>, String) = sqlx::query_as(
        "SELECT current_setting('rss.tenant_id',true),current_setting('transaction_isolation')",
    )
    .fetch_one(&mut *c)
    .await?;
    if scope.as_deref() != Some(tenant.to_string().as_str()) || isolation != "read committed" {
        return Err(Error::Rejected);
    }
    let id: uuid::Uuid =
        sqlx::query_scalar("SELECT authority_id FROM identity_authority.deployment")
            .fetch_one(&mut *c)
            .await?;
    if id != instance.as_uuid() {
        return Err(Error::Rejected);
    }
    let admitted: bool = sqlx::query_scalar("SELECT identity_authority.share_host_tenant()")
        .fetch_one(&mut *c)
        .await?;
    if !admitted {
        return Err(Error::Rejected);
    }
    let (version, settings) = match source {
        ProfileSource::IdentityLocal => (
            None,
            ProfileSettings {
                extensions_claim: Some("extensions".into()),
                ..ProfileSettings::default()
            },
        ),
        ProfileSource::Idp { provider } => {
            let locked: bool =
                sqlx::query_scalar("SELECT identity_authority.share_provider($1::uuid)")
                    .bind(provider.to_string())
                    .fetch_one(&mut *c)
                    .await?;
            if !locked {
                return Err(Error::Rejected);
            }
            let row=sqlx::query("SELECT config_version,settings FROM identity_authority.providers WHERE tenant_id=$1::uuid AND provider_id=$2::uuid AND enabled")
                .bind(tenant.to_string()).bind(provider.to_string()).fetch_optional(c).await?.ok_or(Error::Rejected)?;
            let settings: rss_identity_core::federation::ProviderSettings =
                serde_json::from_value(row.try_get("settings")?).map_err(|_| Error::Invariant)?;
            (
                Some(row.try_get("config_version")?),
                settings.claims().profile.clone(),
            )
        }
    };
    Ok(ProfileSourceView {
        source,
        provider_config_version: version,
        extensions_root: settings.extensions_claim,
        max_age_seconds: settings.max_age_seconds,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn storage_diagnostics_do_not_expose_provider_text() {
        use std::error::Error;
        let error = super::ProfileSourceAdmissionError::from(sqlx::Error::Protocol(
            "private-provider-detail".into(),
        ));
        let mut current: Option<&dyn Error> = Some(&error);
        while let Some(value) = current {
            assert!(!format!("{value:?} {value}").contains("private-provider-detail"));
            current = value.source();
        }
    }
}
