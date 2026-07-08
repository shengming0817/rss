//! `PgPolicyRepo` —— identity durable ABAC policy store（#1588）。

use std::time::SystemTime;

use consistency::Entry;
use diport::{Clock, OutboxEnvelopeParts};
use identity::ports::{
    AttributeKey, AttributeValue, GlobPattern, IdentityError, Operator, Policy, PolicyCondition,
    PolicyEffect, PolicyId, PolicyLifecycle, PolicyListResult, PolicyObligations, PolicyPage,
    PolicyRepo, PolicyRouteScope, PolicyRule, PolicyVersion, TenantId,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::PgStore;
use crate::cotx::PgTenantPool;
use crate::outbox::{
    OutboxEnvelope, append_outbox_with_projection, epoch_secs_to_time, metadata_with_ambient,
    unix_secs,
};
use crate::projection_events::ProjectionWriteRegistry;

pub struct PgPolicyRepo {
    pool: PgTenantPool,
}

impl PgPolicyRepo {
    pub(crate) fn new(store: &PgStore) -> Self {
        Self {
            pool: PgTenantPool::new(store),
        }
    }
}

pub struct PgPolicyLifecycle {
    pool: PgTenantPool,
    clock: Box<dyn Clock>,
}

impl PgPolicyLifecycle {
    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn new(store: &PgStore, clock: Box<dyn Clock>) -> Self {
        Self::new_with_projection_registry(store, clock, ProjectionWriteRegistry::empty())
    }

    pub(crate) fn new_with_projection_registry(
        store: &PgStore,
        clock: Box<dyn Clock>,
        projection_registry: ProjectionWriteRegistry,
    ) -> Self {
        Self {
            pool: PgTenantPool::with_projection_registry(store, projection_registry),
            clock,
        }
    }

    fn envelope(
        &self,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(TenantId, OutboxEnvelope), IdentityError> {
        let (contract, tenant, subject_id, actor, partition_key, causation_id) =
            envelope.into_parts();
        let env = OutboxEnvelope::new(
            contract.domain().to_string(),
            contract.contract_id().to_string(),
            metadata_with_ambient(unix_secs(self.clock.now()), tenant, contract)
                .with_subject_id(subject_id)
                .with_actor(actor),
        )
        .with_partition_key_opt(partition_key)
        .with_causation_id_opt(causation_id);
        Ok((tenant, env))
    }
}

fn storage(e: sqlx::Error) -> IdentityError {
    IdentityError::Storage(Box::new(e))
}

fn storage_boxed(e: impl std::error::Error + Send + Sync + 'static) -> IdentityError {
    IdentityError::Storage(Box::new(e))
}

fn tenant_param(tenant: TenantId) -> String {
    tenant.as_uuid().to_string()
}

fn version_param(version: PolicyVersion) -> Result<i32, IdentityError> {
    i32::try_from(version.get()).map_err(|_| IdentityError::InvalidPolicy)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesDoc {
    rules: Vec<RuleDto>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RuleDto {
    condition: ConditionDto,
    effect: EffectDto,
    #[serde(default)]
    obligations: ObligationsDto,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ConditionDto {
    attribute: String,
    operator: OperatorDto,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields, rename_all = "camelCase")]
enum OperatorDto {
    Eq { value: String },
    Ne { value: String },
    Like { pattern: String },
    Gt { value: String },
    Lt { value: String },
    EqAttr { attribute: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum EffectDto {
    Allow,
    Deny,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ObligationsDto {
    row_scope: Option<RowScopeDto>,
    #[serde(default)]
    field_mask: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum RowScopeDto {
    SelfOnly,
    Device,
    Tenant,
}

impl RuleDto {
    fn from_rule(rule: &PolicyRule) -> Result<Self, IdentityError> {
        Ok(Self {
            condition: ConditionDto::from_rule(rule)?,
            effect: EffectDto::from_effect(rule.effect())?,
            obligations: ObligationsDto::from_obligations(rule.obligations())?,
        })
    }

    fn into_rule(self) -> Result<PolicyRule, IdentityError> {
        Ok(PolicyRule::with_obligations(
            self.condition.into_condition()?,
            self.effect.into_effect(),
            self.obligations.into_obligations()?,
        ))
    }
}

impl ConditionDto {
    fn from_rule(rule: &PolicyRule) -> Result<Self, IdentityError> {
        Ok(Self {
            attribute: rule.attribute_key().as_str().to_string(),
            operator: OperatorDto::from_operator(rule.operator())?,
        })
    }

    fn into_condition(self) -> Result<PolicyCondition, IdentityError> {
        Ok(PolicyCondition::new(
            AttributeKey::parse(&self.attribute).map_err(|_| IdentityError::InvalidPolicy)?,
            self.operator.into_operator()?,
        ))
    }
}

impl OperatorDto {
    fn from_operator(operator: &Operator) -> Result<Self, IdentityError> {
        match operator {
            Operator::Eq(value) => Ok(Self::Eq {
                value: value.as_str().to_string(),
            }),
            Operator::Ne(value) => Ok(Self::Ne {
                value: value.as_str().to_string(),
            }),
            Operator::Like(pattern) => Ok(Self::Like {
                pattern: pattern.as_str().to_string(),
            }),
            Operator::Gt(value) => Ok(Self::Gt {
                value: value.as_str().to_string(),
            }),
            Operator::Lt(value) => Ok(Self::Lt {
                value: value.as_str().to_string(),
            }),
            Operator::EqAttr(attribute) => Ok(Self::EqAttr {
                attribute: attribute.as_str().to_string(),
            }),
            _ => Err(IdentityError::InvalidPolicy),
        }
    }

    fn into_operator(self) -> Result<Operator, IdentityError> {
        Ok(match self {
            Self::Eq { value } => Operator::Eq(AttributeValue::new(value)),
            Self::Ne { value } => Operator::Ne(AttributeValue::new(value)),
            Self::Like { pattern } => Operator::Like(
                GlobPattern::parse(&pattern).map_err(|_| IdentityError::InvalidPolicy)?,
            ),
            Self::Gt { value } => Operator::Gt(AttributeValue::new(value)),
            Self::Lt { value } => Operator::Lt(AttributeValue::new(value)),
            Self::EqAttr { attribute } => Operator::EqAttr(
                AttributeKey::parse(&attribute).map_err(|_| IdentityError::InvalidPolicy)?,
            ),
        })
    }
}

impl EffectDto {
    fn from_effect(effect: PolicyEffect) -> Result<Self, IdentityError> {
        match effect {
            PolicyEffect::Allow => Ok(Self::Allow),
            PolicyEffect::Deny => Ok(Self::Deny),
            _ => Err(IdentityError::InvalidPolicy),
        }
    }

    fn into_effect(self) -> PolicyEffect {
        match self {
            Self::Allow => PolicyEffect::Allow,
            Self::Deny => PolicyEffect::Deny,
        }
    }
}

impl ObligationsDto {
    fn from_obligations(obligations: &PolicyObligations) -> Result<Self, IdentityError> {
        Ok(Self {
            row_scope: obligations
                .row_scope()
                .map(RowScopeDto::from_scoped)
                .transpose()?,
            field_mask: obligations
                .field_mask()
                .iter()
                .map(|key| key.as_str().to_string())
                .collect(),
        })
    }

    fn into_obligations(self) -> Result<PolicyObligations, IdentityError> {
        let row_scope = self.row_scope.map(RowScopeDto::into_scoped).transpose()?;
        let field_mask = self
            .field_mask
            .into_iter()
            .map(|key| AttributeKey::parse(&key).map_err(|_| IdentityError::InvalidPolicy))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PolicyObligations::new(row_scope, field_mask))
    }
}

impl RowScopeDto {
    fn from_scoped(scope: vocab::ScopedTenant) -> Result<Self, IdentityError> {
        match scope {
            vocab::ScopedTenant::SelfOnly => Ok(Self::SelfOnly),
            vocab::ScopedTenant::Device => Ok(Self::Device),
            vocab::ScopedTenant::Tenant => Ok(Self::Tenant),
            _ => Err(IdentityError::InvalidPolicy),
        }
    }

    fn into_scoped(self) -> Result<vocab::ScopedTenant, IdentityError> {
        Ok(match self {
            Self::SelfOnly => vocab::ScopedTenant::SelfOnly,
            Self::Device => vocab::ScopedTenant::Device,
            Self::Tenant => vocab::ScopedTenant::Tenant,
        })
    }
}

fn encode_rules(policy: &Policy) -> Result<String, IdentityError> {
    let doc = RulesDoc {
        rules: policy
            .rules()
            .iter()
            .map(RuleDto::from_rule)
            .collect::<Result<Vec<_>, _>>()?,
    };
    serde_json::to_string(&doc).map_err(storage_boxed)
}

fn decode_rules(raw: &str) -> Result<Vec<PolicyRule>, IdentityError> {
    let doc: RulesDoc = serde_json::from_str(raw).map_err(|_| IdentityError::InvalidPolicy)?;
    doc.rules
        .into_iter()
        .map(RuleDto::into_rule)
        .collect::<Result<Vec<_>, _>>()
}

#[derive(Debug)]
struct RawPolicy {
    id: String,
    version: i32,
    contract_id: String,
    permission: String,
    effective_from: i64,
    effective_until: Option<i64>,
    rules_json: String,
}

fn hydrate_policy(tenant: TenantId, raw: RawPolicy) -> Result<Policy, IdentityError> {
    let version = u32::try_from(raw.version).map_err(|_| IdentityError::InvalidPolicy)?;
    let scope = PolicyRouteScope::parse(&raw.contract_id, &raw.permission)?;
    Policy::hydrate(
        &raw.id,
        tenant,
        scope,
        version,
        epoch_secs_to_time(raw.effective_from),
        raw.effective_until.map(epoch_secs_to_time),
        decode_rules(&raw.rules_json)?,
    )
}

impl PolicyRepo for PgPolicyRepo {
    async fn find(&self, tenant: TenantId, id: PolicyId) -> Result<Option<Policy>, IdentityError> {
        let tenant_uuid = tenant_param(tenant);
        let id_str = id.as_str().to_string();
        let raw: Option<RawPolicy> = self
            .pool
            .read(tenant, move |conn| {
                Box::pin(async move {
                    let row = sqlx::query(
                        r#"
                        SELECT id, version, contract_id, permission,
                               extract(epoch from effective_from)::bigint AS effective_from,
                               extract(epoch from effective_until)::bigint AS effective_until,
                               rules::text AS rules_json
                        FROM abac_policies
                        WHERE tenant_id = $1::uuid
                          AND id = $2
                          AND deleted_at IS NULL
                        "#,
                    )
                    .bind(tenant_uuid)
                    .bind(id_str)
                    .fetch_optional(&mut *conn)
                    .await?;
                    row.map(row_to_raw).transpose()
                })
            })
            .await
            .map_err(storage)?;
        raw.map(|raw| hydrate_policy(tenant, raw)).transpose()
    }

    async fn list_active(
        &self,
        tenant: TenantId,
        page: PolicyPage,
    ) -> Result<PolicyListResult, IdentityError> {
        let tenant_uuid = tenant_param(tenant);
        let limit = usize::from(page.limit.get());
        let fetch_limit = i64::try_from(limit.saturating_add(1)).map_err(storage_boxed)?;
        let after = page.after.map(|id| id.as_str().to_string());
        let raw: Vec<RawPolicy> = self
            .pool
            .read(tenant, move |conn| {
                Box::pin(async move {
                    let rows = sqlx::query(
                        r#"
                        SELECT id, version, contract_id, permission,
                               extract(epoch from effective_from)::bigint AS effective_from,
                               extract(epoch from effective_until)::bigint AS effective_until,
                               rules::text AS rules_json
                        FROM abac_policies
                        WHERE tenant_id = $1::uuid
                          AND ($2::text IS NULL OR id > $2)
                          AND deleted_at IS NULL
                        ORDER BY id ASC
                        LIMIT $3
                        "#,
                    )
                    .bind(tenant_uuid)
                    .bind(after)
                    .bind(fetch_limit)
                    .fetch_all(&mut *conn)
                    .await?;
                    rows.into_iter()
                        .map(row_to_raw)
                        .collect::<Result<Vec<RawPolicy>, sqlx::Error>>()
                })
            })
            .await
            .map_err(storage)?;
        let has_more = raw.len() > limit;
        let mut policies = raw
            .into_iter()
            .map(|raw| hydrate_policy(tenant, raw))
            .collect::<Result<Vec<_>, _>>()?;
        policies.truncate(limit);
        Ok(PolicyListResult { policies, has_more })
    }

    async fn list_effective(
        &self,
        tenant: TenantId,
        scope: PolicyRouteScope,
        at: SystemTime,
    ) -> Result<Vec<Policy>, IdentityError> {
        let tenant_uuid = tenant_param(tenant);
        let at_secs = unix_secs(at);
        let raw: Vec<RawPolicy> = self
            .pool
            .read(tenant, move |conn| {
                Box::pin(async move {
                    let rows = sqlx::query(
                        r#"
                        SELECT id, version, contract_id, permission,
                               extract(epoch from effective_from)::bigint AS effective_from,
                               extract(epoch from effective_until)::bigint AS effective_until,
                               rules::text AS rules_json
                        FROM abac_policies
                        WHERE tenant_id = $1::uuid
                          AND contract_id = $2
                          AND permission = $3
                          AND effective_from <= to_timestamp($4)
                          AND (effective_until IS NULL OR effective_until > to_timestamp($4))
                          AND deleted_at IS NULL
                        ORDER BY id ASC
                        "#,
                    )
                    .bind(tenant_uuid)
                    .bind(scope.contract_id().to_string())
                    .bind(scope.permission().as_str().to_string())
                    .bind(at_secs)
                    .fetch_all(&mut *conn)
                    .await?;
                    rows.into_iter()
                        .map(row_to_raw)
                        .collect::<Result<Vec<RawPolicy>, sqlx::Error>>()
                })
            })
            .await
            .map_err(storage)?;
        raw.into_iter()
            .map(|raw| hydrate_policy(tenant, raw))
            .collect()
    }
}

impl PolicyLifecycle for PgPolicyLifecycle {
    async fn create_and_emit(
        &self,
        tenant: TenantId,
        policy: Policy,
        entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<Policy, IdentityError> {
        if policy.tenant() != tenant || policy.version().get() != 1 {
            return Err(IdentityError::InvalidPolicy);
        }
        let (env_tenant, env) = self.envelope(envelope)?;
        if env_tenant != tenant {
            return Err(IdentityError::InvalidPolicy);
        }
        let tenant_uuid = tenant_param(tenant);
        let rules_json = encode_rules(&policy)?;
        let id = policy.id().as_str().to_string();
        let version = version_param(policy.version())?;
        let contract_id = policy.route_scope().contract_id().to_string();
        let permission = policy.route_scope().permission().as_str().to_string();
        let effective_from = unix_secs(policy.effective_from());
        let effective_until = policy.effective_until().map(unix_secs);
        let projection_registry = self.pool.projection_registry();
        let inserted = self
            .pool
            .write(
                tenant,
                move |conn| {
                    Box::pin(async move {
                        sqlx::query(
                            r#"
                            INSERT INTO abac_policies
                                (tenant_id, id, version, contract_id, permission,
                                 effective_from, effective_until, rules)
                            VALUES
                                ($1::uuid, $2, $3, $4, $5,
                                 to_timestamp($6), to_timestamp($7), $8::jsonb)
                            ON CONFLICT (tenant_id, id) DO NOTHING
                            "#,
                        )
                        .bind(&tenant_uuid)
                        .bind(&id)
                        .bind(version)
                        .bind(&contract_id)
                        .bind(&permission)
                        .bind(effective_from)
                        .bind(effective_until)
                        .bind(rules_json)
                        .execute(conn.conn())
                        .await
                        .map_err(storage)
                        .and_then(|r| {
                            let rows = r.rows_affected();
                            if rows > 0 {
                                Ok(rows)
                            } else {
                                Err(IdentityError::PolicyAlreadyExists)
                            }
                        })?;
                        append_outbox_with_projection(conn, &entry, &env, &projection_registry)
                            .await
                            .map_err(storage)?;
                        Ok(1)
                    })
                },
                storage,
            )
            .await?;
        debug_assert_eq!(inserted, 1);
        Ok(policy)
    }

    async fn update_and_emit(
        &self,
        tenant: TenantId,
        policy: Policy,
        expected: PolicyVersion,
        entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<Policy, IdentityError> {
        if policy.tenant() != tenant {
            return Err(IdentityError::InvalidPolicy);
        }
        let (env_tenant, env) = self.envelope(envelope)?;
        if env_tenant != tenant {
            return Err(IdentityError::InvalidPolicy);
        }
        let tenant_uuid = tenant_param(tenant);
        let rules_json = encode_rules(&policy)?;
        let id = policy.id().clone();
        let expected_version = version_param(expected)?;
        let projection_registry = self.pool.projection_registry();
        let raw: Option<RawPolicy> = self
            .pool
            .write(
                tenant,
                move |conn| {
                    Box::pin(async move {
                        let row = sqlx::query(
                            r#"
                            UPDATE abac_policies
                            SET version = version + 1,
                                contract_id = $4,
                                permission = $5,
                                effective_from = to_timestamp($6),
                                effective_until = to_timestamp($7),
                                rules = $8::jsonb,
                                updated_at = now()
                            WHERE tenant_id = $1::uuid
                              AND id = $2
                              AND version = $3
                              AND deleted_at IS NULL
                            RETURNING id, version, contract_id, permission,
                                      extract(epoch from effective_from)::bigint AS effective_from,
                                      extract(epoch from effective_until)::bigint AS effective_until,
                                      rules::text AS rules_json
                            "#,
                        )
                        .bind(&tenant_uuid)
                        .bind(policy.id().as_str())
                        .bind(expected_version)
                        .bind(policy.route_scope().contract_id())
                        .bind(policy.route_scope().permission().as_str())
                        .bind(unix_secs(policy.effective_from()))
                        .bind(policy.effective_until().map(unix_secs))
                        .bind(rules_json)
                        .fetch_optional(conn.conn())
                        .await
                        .map_err(storage)?;
                        if row.is_some() {
                            append_outbox_with_projection(
                                conn,
                                &entry,
                                &env,
                                &projection_registry,
                            )
                            .await
                            .map_err(storage)?;
                        }
                        row.map(row_to_raw).transpose().map_err(storage)
                    })
                },
                storage,
            )
            .await?;

        match raw {
            Some(raw) => hydrate_policy(tenant, raw),
            None => {
                if (PgPolicyRepo {
                    pool: self.pool.clone(),
                })
                .find(tenant, id)
                .await?
                .is_some()
                {
                    Err(IdentityError::VersionConflict)
                } else {
                    Err(IdentityError::PolicyNotFound)
                }
            }
        }
    }

    async fn deactivate_and_emit(
        &self,
        tenant: TenantId,
        id: PolicyId,
        expected: PolicyVersion,
        entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<bool, IdentityError> {
        let (env_tenant, env) = self.envelope(envelope)?;
        if env_tenant != tenant {
            return Err(IdentityError::InvalidPolicy);
        }
        let tenant_uuid = tenant_param(tenant);
        let id_str = id.as_str().to_string();
        let expected_version = version_param(expected)?;
        let projection_registry = self.pool.projection_registry();
        let deleted = self
            .pool
            .write(
                tenant,
                move |conn| {
                    Box::pin(async move {
                        let rows = sqlx::query(
                            r#"
                            UPDATE abac_policies
                            SET version = version + 1,
                                deleted_at = now(),
                                updated_at = now()
                            WHERE tenant_id = $1::uuid
                              AND id = $2
                              AND version = $3
                              AND deleted_at IS NULL
                            "#,
                        )
                        .bind(&tenant_uuid)
                        .bind(&id_str)
                        .bind(expected_version)
                        .execute(conn.conn())
                        .await
                        .map_err(storage)
                        .map(|r| r.rows_affected())?;
                        if rows > 0 {
                            append_outbox_with_projection(conn, &entry, &env, &projection_registry)
                                .await
                                .map_err(storage)?;
                        }
                        Ok(rows)
                    })
                },
                storage,
            )
            .await?;
        if deleted > 0 {
            return Ok(true);
        }
        if (PgPolicyRepo {
            pool: self.pool.clone(),
        })
        .find(tenant, id)
        .await?
        .is_some()
        {
            Err(IdentityError::VersionConflict)
        } else {
            Ok(false)
        }
    }
}

fn row_to_raw(row: sqlx::postgres::PgRow) -> Result<RawPolicy, sqlx::Error> {
    Ok(RawPolicy {
        id: row.try_get("id")?,
        version: row.try_get("version")?,
        contract_id: row.try_get("contract_id")?,
        permission: row.try_get("permission")?,
        effective_from: row.try_get("effective_from")?,
        effective_until: row.try_get("effective_until")?,
        rules_json: row.try_get("rules_json")?,
    })
}
