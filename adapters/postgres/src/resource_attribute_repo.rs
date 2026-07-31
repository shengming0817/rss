//! `PgResourceAttributeRepo` —— identity durable resource attribute store / resolver（#1590）。

use std::collections::HashMap;
use std::time::SystemTime;

use identity::ports::PolicyRouteScope;
use identity::ports::{
    AttributeValue, IdentityError, ResourceAttribute, ResourceAttributeKey,
    ResourceAttributeReadRepo, ResourceAttributeResolution, ResourceAttributeResourceId,
    ResourceAttributeVersion, ResourceAttributeWriteRepo, TenantId, TenantRepoScope,
};
use sqlx::Row;

use crate::cotx::{ServingReadLane, ServingWriteLane, TenantDb};
use crate::outbox::{epoch_secs_to_time, unix_secs};
use crate::pool::{VerifiedPgReadStore, VerifiedPgWriteStore};

pub struct PgResourceAttributeRepo {
    read_pool: TenantDb<ServingReadLane>,
    write_pool: TenantDb<ServingWriteLane>,
}

impl PgResourceAttributeRepo {
    pub(crate) fn new(reader: &VerifiedPgReadStore, writer: &VerifiedPgWriteStore) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::new(reader),
            write_pool: TenantDb::<ServingWriteLane>::new(writer),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::from_unverified_for_test(store),
            write_pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(store),
        }
    }
}

fn storage(e: sqlx::Error) -> IdentityError {
    IdentityError::Storage(Box::new(e))
}

#[derive(Debug)]
pub(crate) struct RawResourceAttribute {
    key: String,
    value: String,
    version: i32,
    effective_from: i64,
    effective_until: Option<i64>,
    deleted: bool,
}

pub(crate) fn row_to_raw(row: sqlx::postgres::PgRow) -> Result<RawResourceAttribute, sqlx::Error> {
    Ok(RawResourceAttribute {
        key: row.try_get("attribute_key")?,
        value: row.try_get("attribute_value")?,
        version: row.try_get("version")?,
        effective_from: row.try_get("effective_from")?,
        effective_until: row.try_get("effective_until")?,
        deleted: row.try_get("deleted")?,
    })
}

fn hydrate_attribute(
    tenant: TenantId,
    scope: PolicyRouteScope,
    resource_id: ResourceAttributeResourceId,
    raw: RawResourceAttribute,
) -> Result<ResourceAttribute, IdentityError> {
    let version = u32::try_from(raw.version).map_err(|_| IdentityError::InvalidPolicy)?;
    ResourceAttribute::hydrate(
        tenant,
        scope,
        resource_id,
        ResourceAttributeKey::parse(&raw.key).map_err(|_| IdentityError::InvalidPolicy)?,
        AttributeValue::parse(&raw.value).map_err(|_| IdentityError::InvalidPolicy)?,
        version,
        epoch_secs_to_time(raw.effective_from),
        raw.effective_until.map(epoch_secs_to_time),
    )
}

fn row_is_effective(raw: &RawResourceAttribute, at_secs: i64) -> bool {
    !raw.deleted
        && raw.effective_from <= at_secs
        && raw.effective_until.is_none_or(|until| at_secs < until)
}

impl ResourceAttributeReadRepo for PgResourceAttributeRepo {
    async fn resolve_effective(
        &self,
        tenant_scope: TenantRepoScope,
        scope: PolicyRouteScope,
        resource_id: ResourceAttributeResourceId,
        required_keys: Vec<ResourceAttributeKey>,
        at: SystemTime,
    ) -> Result<ResourceAttributeResolution, IdentityError> {
        let tenant = tenant_scope.tenant();
        if required_keys.is_empty() {
            return Ok(ResourceAttributeResolution::Known(Vec::new()));
        }
        let query_scope = scope.clone();
        let query_resource = resource_id.clone();
        let query_keys = required_keys.clone();
        let rows: Vec<RawResourceAttribute> = self
            .read_pool
            .identity_read(tenant_scope, move |mut conn| {
                Box::pin(async move {
                    conn.identity()
                        .resource_attribute_rows(&query_scope, &query_resource, &query_keys)
                        .await
                })
            })
            .await
            .map_err(storage)?;
        let mut by_key = rows
            .into_iter()
            .map(|raw| (raw.key.clone(), raw))
            .collect::<HashMap<_, _>>();
        let at_secs = unix_secs(at);
        let mut attrs = Vec::with_capacity(required_keys.len());
        for key in required_keys {
            let Some(raw) = by_key.remove(key.as_str()) else {
                return Ok(ResourceAttributeResolution::Missing(key));
            };
            if !row_is_effective(&raw, at_secs) {
                return Ok(ResourceAttributeResolution::Stale(key));
            }
            attrs.push(hydrate_attribute(
                tenant,
                scope.clone(),
                resource_id.clone(),
                raw,
            )?);
        }
        Ok(ResourceAttributeResolution::Known(attrs))
    }
}

impl ResourceAttributeWriteRepo for PgResourceAttributeRepo {
    async fn upsert(
        &self,
        tenant_scope: TenantRepoScope,
        attribute: ResourceAttribute,
        expected: Option<ResourceAttributeVersion>,
    ) -> Result<ResourceAttribute, IdentityError> {
        let tenant = tenant_scope.tenant();
        if attribute.tenant() != tenant {
            return Err(IdentityError::InvalidPolicy);
        }
        let persisted_attribute = attribute.clone();
        let raw: Option<RawResourceAttribute> = self
            .write_pool
            .identity_write(
                tenant_scope,
                move |mut conn| {
                    Box::pin(async move {
                        conn.identity()
                            .upsert_resource_attribute(&persisted_attribute, expected)
                            .await
                    })
                },
                storage,
            )
            .await?;
        let raw = raw.ok_or(IdentityError::VersionConflict)?;
        hydrate_attribute(
            tenant,
            attribute.route_scope().clone(),
            attribute.resource_id().clone(),
            raw,
        )
    }

    async fn expire(
        &self,
        tenant_scope: TenantRepoScope,
        scope: PolicyRouteScope,
        resource_id: ResourceAttributeResourceId,
        key: ResourceAttributeKey,
        expected: ResourceAttributeVersion,
    ) -> Result<bool, IdentityError> {
        let query_scope = scope.clone();
        let query_resource = resource_id.clone();
        let query_key = key.clone();
        let outcome = self
            .write_pool
            .identity_write(
                tenant_scope,
                move |mut conn| {
                    Box::pin(async move {
                        conn.identity()
                            .expire_resource_attribute(
                                &query_scope,
                                &query_resource,
                                &query_key,
                                expected,
                            )
                            .await
                    })
                },
                storage,
            )
            .await?;
        match outcome {
            ExpireOutcome::Expired => Ok(true),
            ExpireOutcome::Missing => Ok(false),
            ExpireOutcome::VersionConflict => Err(IdentityError::VersionConflict),
        }
    }
}

pub(crate) enum ExpireOutcome {
    Expired,
    Missing,
    VersionConflict,
}

#[cfg(test)]
mod attribute_value_bound_tests {
    use super::*;
    use identity::ports::ATTR_VALUE_MAX_LEN;

    #[allow(clippy::expect_used)]
    fn sample_scope() -> PolicyRouteScope {
        PolicyRouteScope::parse("other.contract", "identity:policy:read").expect("scope")
    }

    #[allow(clippy::expect_used)]
    fn sample_resource_id() -> ResourceAttributeResourceId {
        ResourceAttributeResourceId::parse("550e8400-e29b-41d4-a716-446655440000")
            .expect("resource id")
    }

    #[allow(clippy::expect_used)]
    fn sample_tenant() -> TenantId {
        TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant")
    }

    #[test]
    fn hydrate_attribute_rejects_overlong_value_as_invalid_policy() {
        let raw = RawResourceAttribute {
            key: "resource.owner".into(),
            value: "a".repeat(ATTR_VALUE_MAX_LEN + 1),
            version: 1,
            effective_from: 0,
            effective_until: None,
            deleted: false,
        };
        assert!(matches!(
            hydrate_attribute(sample_tenant(), sample_scope(), sample_resource_id(), raw),
            Err(IdentityError::InvalidPolicy)
        ));
    }

    #[test]
    fn hydrate_attribute_accepts_exact_max_value() {
        let raw = RawResourceAttribute {
            key: "resource.owner".into(),
            value: "a".repeat(ATTR_VALUE_MAX_LEN),
            version: 1,
            effective_from: 0,
            effective_until: None,
            deleted: false,
        };
        assert!(
            matches!(
                hydrate_attribute(sample_tenant(), sample_scope(), sample_resource_id(), raw),
                Ok(attr) if attr.value().as_str().len() == ATTR_VALUE_MAX_LEN
            ),
            "exact-max must hydrate"
        );
    }
}
