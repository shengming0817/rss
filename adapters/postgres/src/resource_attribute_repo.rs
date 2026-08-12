//! `PgResourceAttributeRepo` —— identity durable resource attribute store / resolver（#1590）。

use rss_request_context::TenantId;
use std::collections::HashMap;
use std::time::SystemTime;

use identity::ports::PolicyRouteScope;
use identity::ports::{
    IdentityError, PolicyValue, PolicyValueRef, ResourceAttribute, ResourceAttributeKey,
    ResourceAttributeReadRepo, ResourceAttributeResolution, ResourceAttributeResourceId,
    ResourceAttributeVersion, ResourceAttributeWriteRepo, TenantRepoScope,
};
use serde::{Deserialize, Serialize};
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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyValueDto {
    value_type: PolicyValueTypeDto,
    value: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum PolicyValueTypeDto {
    String,
    Boolean,
    Integer,
    Decimal,
}

pub(crate) fn encode_policy_value(value: &PolicyValue) -> Result<String, IdentityError> {
    let dto = match value.as_ref() {
        PolicyValueRef::String(value) => PolicyValueDto {
            value_type: PolicyValueTypeDto::String,
            value: serde_json::Value::String(value.to_string()),
        },
        PolicyValueRef::Boolean(value) => PolicyValueDto {
            value_type: PolicyValueTypeDto::Boolean,
            value: serde_json::Value::Bool(value),
        },
        PolicyValueRef::Integer(value) => PolicyValueDto {
            value_type: PolicyValueTypeDto::Integer,
            value: serde_json::Value::Number(value.into()),
        },
        PolicyValueRef::Decimal(value) => PolicyValueDto {
            value_type: PolicyValueTypeDto::Decimal,
            value: serde_json::Value::String(value.as_str().to_string()),
        },
    };
    serde_json::to_string(&dto).map_err(|error| IdentityError::Storage(Box::new(error)))
}

fn decode_policy_value(raw: &str) -> Result<PolicyValue, IdentityError> {
    let dto: PolicyValueDto =
        serde_json::from_str(raw).map_err(|_| IdentityError::InvalidPolicy)?;
    match dto.value_type {
        PolicyValueTypeDto::String => dto
            .value
            .as_str()
            .ok_or(IdentityError::InvalidPolicy)
            .and_then(|value| PolicyValue::string(value).map_err(|_| IdentityError::InvalidPolicy)),
        PolicyValueTypeDto::Boolean => dto
            .value
            .as_bool()
            .map(PolicyValue::boolean)
            .ok_or(IdentityError::InvalidPolicy),
        PolicyValueTypeDto::Integer => dto
            .value
            .as_i64()
            .map(PolicyValue::integer)
            .ok_or(IdentityError::InvalidPolicy),
        PolicyValueTypeDto::Decimal => dto
            .value
            .as_str()
            .ok_or(IdentityError::InvalidPolicy)
            .and_then(|value| {
                PolicyValue::decimal(value).map_err(|_| IdentityError::InvalidPolicy)
            }),
    }
}

pub(crate) struct RawResourceAttribute {
    key: String,
    value: String,
    version: i32,
    effective_from: i64,
    effective_until: Option<i64>,
    deleted: bool,
}

impl std::fmt::Debug for RawResourceAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawResourceAttribute")
            .field("key", &self.key)
            .field("value", &"<redacted>")
            .field("version", &self.version)
            .field("effective_from", &self.effective_from)
            .field("effective_until", &self.effective_until)
            .field("deleted", &self.deleted)
            .finish()
    }
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
        decode_policy_value(&raw.value)?,
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
            value:
                serde_json::json!({"valueType":"string","value":"a".repeat(ATTR_VALUE_MAX_LEN + 1)})
                    .to_string(),
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
            value: serde_json::json!({"valueType":"string","value":"a".repeat(ATTR_VALUE_MAX_LEN)})
                .to_string(),
            version: 1,
            effective_from: 0,
            effective_until: None,
            deleted: false,
        };
        assert!(
            matches!(
                hydrate_attribute(sample_tenant(), sample_scope(), sample_resource_id(), raw),
                Ok(attr) if attr.value().string_value().is_some_and(|value| value.len() == ATTR_VALUE_MAX_LEN)
            ),
            "exact-max must hydrate"
        );
    }

    #[test]
    fn typed_value_codec_round_trips_without_coercion() {
        for value in [
            PolicyValue::boolean(true),
            PolicyValue::integer(42),
            PolicyValue::decimal("12.34").expect("decimal"),
            PolicyValue::string("eng").expect("string"),
        ] {
            let encoded = encode_policy_value(&value).expect("encode");
            assert_eq!(decode_policy_value(&encoded).expect("decode"), value);
        }
    }

    #[test]
    fn raw_attribute_debug_redacts_typed_value() {
        let raw = RawResourceAttribute {
            key: "resource.secret".into(),
            value: r#"{"valueType":"string","value":"do-not-log"}"#.into(),
            version: 1,
            effective_from: 0,
            effective_until: None,
            deleted: false,
        };
        let debug = format!("{raw:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("do-not-log"));
    }
}
