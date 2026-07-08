//! `PgResourceAttributeRepo` —— identity durable resource attribute store / resolver（#1590）。

use std::collections::HashMap;
use std::time::SystemTime;

use identity::ports::PolicyRouteScope;
use identity::ports::{
    AttributeValue, IdentityError, ResourceAttribute, ResourceAttributeKey, ResourceAttributeRepo,
    ResourceAttributeResolution, ResourceAttributeResourceId, ResourceAttributeVersion, TenantId,
};
use sqlx::Row;

use crate::PgStore;
use crate::cotx::PgTenantPool;
use crate::outbox::{epoch_secs_to_time, unix_secs};

pub struct PgResourceAttributeRepo {
    pool: PgTenantPool,
}

impl PgResourceAttributeRepo {
    pub(crate) fn new(store: &PgStore) -> Self {
        Self {
            pool: PgTenantPool::new(store),
        }
    }
}

fn storage(e: sqlx::Error) -> IdentityError {
    IdentityError::Storage(Box::new(e))
}

fn tenant_param(tenant: TenantId) -> String {
    tenant.as_uuid().to_string()
}

fn version_param(version: ResourceAttributeVersion) -> Result<i32, IdentityError> {
    i32::try_from(version.get()).map_err(|_| IdentityError::InvalidPolicy)
}

#[derive(Debug)]
struct RawResourceAttribute {
    key: String,
    value: String,
    version: i32,
    effective_from: i64,
    effective_until: Option<i64>,
    deleted: bool,
}

fn row_to_raw(row: sqlx::postgres::PgRow) -> Result<RawResourceAttribute, sqlx::Error> {
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
        AttributeValue::new(raw.value),
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

impl ResourceAttributeRepo for PgResourceAttributeRepo {
    async fn resolve_effective(
        &self,
        tenant: TenantId,
        scope: PolicyRouteScope,
        resource_id: ResourceAttributeResourceId,
        required_keys: Vec<ResourceAttributeKey>,
        at: SystemTime,
    ) -> Result<ResourceAttributeResolution, IdentityError> {
        if required_keys.is_empty() {
            return Ok(ResourceAttributeResolution::Known(Vec::new()));
        }
        let tenant_uuid = tenant_param(tenant);
        let contract_id = scope.contract_id().to_string();
        let permission = scope.permission().to_string();
        let resource_id_str = resource_id.as_str().to_string();
        let key_params = required_keys
            .iter()
            .map(|key| key.as_str().to_string())
            .collect::<Vec<_>>();
        let rows: Vec<RawResourceAttribute> = self
            .pool
            .read(tenant, move |conn| {
                Box::pin(async move {
                    let rows = sqlx::query(
                        r#"
                        SELECT attribute_key, attribute_value, version,
                               extract(epoch from effective_from)::bigint AS effective_from,
                               extract(epoch from effective_until)::bigint AS effective_until,
                               deleted_at IS NOT NULL AS deleted
                        FROM resource_attributes
                        WHERE tenant_id = $1::uuid
                          AND contract_id = $2
                          AND permission = $3
                          AND resource_id = $4::uuid
                          AND attribute_key = ANY($5::text[])
                          AND deleted_at IS NULL
                        "#,
                    )
                    .bind(tenant_uuid)
                    .bind(contract_id)
                    .bind(permission)
                    .bind(resource_id_str)
                    .bind(key_params)
                    .fetch_all(&mut *conn)
                    .await?;
                    rows.into_iter()
                        .map(row_to_raw)
                        .collect::<Result<Vec<_>, sqlx::Error>>()
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

    async fn upsert(
        &self,
        tenant: TenantId,
        attribute: ResourceAttribute,
        expected: Option<ResourceAttributeVersion>,
    ) -> Result<ResourceAttribute, IdentityError> {
        if attribute.tenant() != tenant {
            return Err(IdentityError::InvalidPolicy);
        }
        let tenant_uuid = tenant_param(tenant);
        let contract_id = attribute.route_scope().contract_id().to_string();
        let permission = attribute.route_scope().permission().to_string();
        let resource_id = attribute.resource_id().as_str().to_string();
        let key = attribute.key().as_str().to_string();
        let value = attribute.value().as_str().to_string();
        let effective_from = unix_secs(attribute.effective_from());
        let effective_until = attribute.effective_until().map(unix_secs);
        let raw: Option<RawResourceAttribute> = match expected {
            None => {
                if attribute.version() != ResourceAttributeVersion::first() {
                    return Err(IdentityError::InvalidPolicy);
                }
                let version = version_param(ResourceAttributeVersion::first())?;
                self.pool
                    .write(
                        tenant,
                        move |conn| {
                            Box::pin(async move {
                                let row = sqlx::query(
                                    r#"
                                    INSERT INTO resource_attributes
                                        (tenant_id, contract_id, permission, resource_id,
                                         attribute_key, attribute_value, version,
                                         effective_from, effective_until)
                                    VALUES
                                        ($1::uuid, $2, $3, $4::uuid,
                                         $5, $6, $7,
                                         to_timestamp($8), to_timestamp($9))
                                    ON CONFLICT (tenant_id, contract_id, permission, resource_id, attribute_key)
                                        DO NOTHING
                                    RETURNING attribute_key, attribute_value, version,
                                              extract(epoch from effective_from)::bigint AS effective_from,
                                              extract(epoch from effective_until)::bigint AS effective_until,
                                              deleted_at IS NOT NULL AS deleted
                                    "#,
                                )
                                .bind(&tenant_uuid)
                                .bind(&contract_id)
                                .bind(&permission)
                                .bind(&resource_id)
                                .bind(&key)
                                .bind(&value)
                                .bind(version)
                                .bind(effective_from)
                                .bind(effective_until)
                                .fetch_optional(conn.conn())
                                .await
                                .map_err(storage)?;
                                row.map(row_to_raw).transpose().map_err(storage)
                            })
                        },
                        storage,
                    )
                    .await?
            }
            Some(expected) => {
                let expected_version = version_param(expected)?;
                self.pool
                    .write(
                        tenant,
                        move |conn| {
                            Box::pin(async move {
                                let row = sqlx::query(
                                    r#"
                                    UPDATE resource_attributes
                                    SET attribute_value = $6,
                                        version = version + 1,
                                        effective_from = to_timestamp($7),
                                        effective_until = to_timestamp($8),
                                        deleted_at = NULL,
                                        updated_at = now()
                                    WHERE tenant_id = $1::uuid
                                      AND contract_id = $2
                                      AND permission = $3
                                      AND resource_id = $4::uuid
                                      AND attribute_key = $5
                                      AND version = $9
                                      AND deleted_at IS NULL
                                    RETURNING attribute_key, attribute_value, version,
                                              extract(epoch from effective_from)::bigint AS effective_from,
                                              extract(epoch from effective_until)::bigint AS effective_until,
                                              deleted_at IS NOT NULL AS deleted
                                    "#,
                                )
                                .bind(&tenant_uuid)
                                .bind(&contract_id)
                                .bind(&permission)
                                .bind(&resource_id)
                                .bind(&key)
                                .bind(&value)
                                .bind(effective_from)
                                .bind(effective_until)
                                .bind(expected_version)
                                .fetch_optional(conn.conn())
                                .await
                                .map_err(storage)?;
                                row.map(row_to_raw).transpose().map_err(storage)
                            })
                        },
                        storage,
                    )
                    .await?
            }
        };
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
        tenant: TenantId,
        scope: PolicyRouteScope,
        resource_id: ResourceAttributeResourceId,
        key: ResourceAttributeKey,
        expected: ResourceAttributeVersion,
    ) -> Result<bool, IdentityError> {
        let tenant_uuid = tenant_param(tenant);
        let contract_id = scope.contract_id().to_string();
        let permission = scope.permission().to_string();
        let resource_id_str = resource_id.as_str().to_string();
        let key_str = key.as_str().to_string();
        let expected_version = version_param(expected)?;
        let outcome = self
            .pool
            .write(
                tenant,
                move |conn| {
                    Box::pin(async move {
                        let updated = sqlx::query(
                            r#"
                            UPDATE resource_attributes
                            SET version = version + 1,
                                deleted_at = now(),
                                updated_at = now()
                            WHERE tenant_id = $1::uuid
                              AND contract_id = $2
                              AND permission = $3
                              AND resource_id = $4::uuid
                              AND attribute_key = $5
                              AND version = $6
                              AND deleted_at IS NULL
                            "#,
                        )
                        .bind(&tenant_uuid)
                        .bind(&contract_id)
                        .bind(&permission)
                        .bind(&resource_id_str)
                        .bind(&key_str)
                        .bind(expected_version)
                        .execute(conn.conn())
                        .await
                        .map_err(storage)?
                        .rows_affected();
                        if updated > 0 {
                            return Ok(ExpireOutcome::Expired);
                        }
                        let active_exists: bool = sqlx::query_scalar(
                            r#"
                            SELECT EXISTS(
                                SELECT 1
                                FROM resource_attributes
                                WHERE tenant_id = $1::uuid
                                  AND contract_id = $2
                                  AND permission = $3
                                  AND resource_id = $4::uuid
                                  AND attribute_key = $5
                                  AND deleted_at IS NULL
                            )
                            "#,
                        )
                        .bind(&tenant_uuid)
                        .bind(&contract_id)
                        .bind(&permission)
                        .bind(&resource_id_str)
                        .bind(&key_str)
                        .fetch_one(conn.conn())
                        .await
                        .map_err(storage)?;
                        if active_exists {
                            Ok(ExpireOutcome::VersionConflict)
                        } else {
                            Ok(ExpireOutcome::Missing)
                        }
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

enum ExpireOutcome {
    Expired,
    Missing,
    VersionConflict,
}
