//! Typed, read-only PostgreSQL PIP for External Resource Security Facts.

use std::collections::HashMap;
use std::time::SystemTime;

use identity::ports::device_certificate::DeviceCertificateScope;
use identity::ports::{
    IdentityError, ResourceFactPrincipalId, ResourceFactSourceId, ResourceRiskClass,
    ResourceSecurityFact, ResourceSecurityFactKey, ResourceSecurityFactReadRepo,
    ResourceSecurityFactResolution, ResourceSecurityFactValue, TenantRepoScope,
};
use sqlx::Row;

use crate::cotx::{ServingReadLane, TenantDb};
use crate::pool::VerifiedPgReadStore;

pub struct PgResourceSecurityFactRepo {
    read_pool: TenantDb<ServingReadLane>,
}

impl PgResourceSecurityFactRepo {
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

fn storage(error: sqlx::Error) -> IdentityError {
    IdentityError::Storage(Box::new(error))
}

fn invalid_projection() -> IdentityError {
    IdentityError::InvalidResourceSecurityFactProjection
}

pub(crate) struct RawResourceSecurityFact {
    key: String,
    revision: i64,
    source_id: String,
    owner_principal_id: Option<String>,
    risk_class: Option<String>,
    observed_at_micros: i64,
    expires_at_micros: i64,
}

impl std::fmt::Debug for RawResourceSecurityFact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RawResourceSecurityFact")
            .field("key", &self.key)
            .field("revision", &self.revision)
            .field("source_id", &"<redacted>")
            .field("value", &"<redacted>")
            .field("observed_at_micros", &self.observed_at_micros)
            .field("expires_at_micros", &self.expires_at_micros)
            .finish()
    }
}

pub(crate) fn row_to_raw(
    row: sqlx::postgres::PgRow,
) -> Result<RawResourceSecurityFact, sqlx::Error> {
    Ok(RawResourceSecurityFact {
        key: row.try_get("fact_key")?,
        revision: row.try_get("revision")?,
        source_id: row.try_get("source_id")?,
        owner_principal_id: row.try_get("owner_principal_id")?,
        risk_class: row.try_get("risk_class")?,
        observed_at_micros: row.try_get("observed_at_micros")?,
        expires_at_micros: row.try_get("expires_at_micros")?,
    })
}

fn hydrate_fact(
    tenant: rss_request_context::TenantId,
    device: ids::DeviceId,
    raw: RawResourceSecurityFact,
) -> Result<ResourceSecurityFact, IdentityError> {
    let value = match ResourceSecurityFactKey::parse(&raw.key).map_err(|_| invalid_projection())? {
        ResourceSecurityFactKey::Owner => ResourceSecurityFactValue::Owner(
            ResourceFactPrincipalId::parse(
                raw.owner_principal_id
                    .as_deref()
                    .ok_or_else(invalid_projection)?,
            )
            .map_err(|_| invalid_projection())?,
        ),
        ResourceSecurityFactKey::RiskClass => ResourceSecurityFactValue::RiskClass(
            ResourceRiskClass::parse(raw.risk_class.as_deref().ok_or_else(invalid_projection)?)
                .map_err(|_| invalid_projection())?,
        ),
    };
    let revision = u64::try_from(raw.revision).map_err(|_| invalid_projection())?;
    ResourceSecurityFact::hydrate(
        tenant,
        device,
        ResourceFactSourceId::parse(&raw.source_id).map_err(|_| invalid_projection())?,
        value,
        revision,
        epoch_micros_to_time(raw.observed_at_micros)?,
        epoch_micros_to_time(raw.expires_at_micros)?,
    )
    .map_err(|_| invalid_projection())
}

fn epoch_micros_to_time(micros: i64) -> Result<SystemTime, IdentityError> {
    let micros = u64::try_from(micros).map_err(|_| invalid_projection())?;
    SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_micros(micros))
        .ok_or_else(invalid_projection)
}

fn unix_micros(at: SystemTime) -> Result<i64, IdentityError> {
    let micros = at
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| invalid_projection())?
        .as_micros();
    i64::try_from(micros).map_err(|_| invalid_projection())
}

impl ResourceSecurityFactReadRepo for PgResourceSecurityFactRepo {
    async fn resolve_latest(
        &self,
        tenant_scope: TenantRepoScope,
        device_scope: DeviceCertificateScope,
        required_keys: Vec<ResourceSecurityFactKey>,
        at: SystemTime,
    ) -> Result<ResourceSecurityFactResolution, IdentityError> {
        let tenant = tenant_scope.tenant();
        if device_scope.tenant() != tenant {
            return Err(IdentityError::InvalidPolicy);
        }
        if required_keys.is_empty() {
            return Ok(ResourceSecurityFactResolution::Known(Vec::new()));
        }
        let device = device_scope.device();
        let query_keys = required_keys.clone();
        let rows = self
            .read_pool
            .identity_read(tenant_scope, move |mut connection| {
                Box::pin(async move {
                    connection
                        .identity()
                        .resource_security_fact_rows(device, &query_keys)
                        .await
                })
            })
            .await
            .map_err(storage)?;
        let mut by_key = rows
            .into_iter()
            .map(|row| (row.key.clone(), row))
            .collect::<HashMap<_, _>>();
        let at_micros = unix_micros(at)?;
        let mut facts = Vec::with_capacity(required_keys.len());
        for key in required_keys {
            let Some(raw) = by_key.remove(key.as_str()) else {
                return Ok(ResourceSecurityFactResolution::Missing(key));
            };
            if raw.observed_at_micros > at_micros || at_micros >= raw.expires_at_micros {
                return Ok(ResourceSecurityFactResolution::Stale(key));
            }
            facts.push(hydrate_fact(tenant, device, raw)?);
        }
        Ok(ResourceSecurityFactResolution::Known(facts))
    }
}
