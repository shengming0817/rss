//! `PgPolicyRepo` —— identity durable ABAC policy store（#1588）。

use std::time::SystemTime;

use diport::{Clock, OutboxEnvelopeParts};
use eventexec::event::ReviewedEvent;
use identity::ports::{
    AttributeKey, AttributeValue, GlobPattern, IdentityError, Operator, POLICY_UPDATED_CONTRACT,
    PipAttributeKey, PoliciesCreateProducerReceipt, PoliciesDeactivateProducerReceipt,
    PoliciesUpdateProducerReceipt, Policy, PolicyCondition, PolicyEffect, PolicyId,
    PolicyLifecycle, PolicyListResult, PolicyObligations, PolicyPage, PolicyRepo, PolicyRouteScope,
    PolicyRule, PolicyVersion, TenantId, TenantRepoScope,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;

#[cfg(all(test, feature = "integration"))]
use crate::PgStore;
use crate::cotx::{ProducerTxOutcome, ServingReadLane, ServingWriteLane, TenantDb};
use crate::outbox::{OutboxEnvelope, epoch_secs_to_time, metadata_with_ambient, unix_secs};
use crate::pool::{VerifiedPgReadStore, VerifiedPgWriteStore};
use crate::projection_events::ProjectionWriteRegistry;

pub struct PgPolicyRepo {
    pool: TenantDb<ServingReadLane>,
}

impl PgPolicyRepo {
    pub(crate) fn new(reader: &VerifiedPgReadStore) -> Self {
        Self {
            pool: TenantDb::<ServingReadLane>::new(reader),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(store: &PgStore) -> Self {
        Self {
            pool: TenantDb::<ServingReadLane>::from_unverified_for_test(store),
        }
    }
}

pub struct PgPolicyLifecycle {
    pool: TenantDb<ServingWriteLane>,
    clock: Box<dyn Clock>,
}

impl PgPolicyLifecycle {
    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn new(store: &PgStore, clock: Box<dyn Clock>) -> Self {
        Self {
            pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(store),
            clock,
        }
    }

    pub(crate) fn new_with_projection_registry(
        writer: &VerifiedPgWriteStore,
        clock: Box<dyn Clock>,
        projection_registry: ProjectionWriteRegistry,
    ) -> Self {
        Self {
            pool: TenantDb::<ServingWriteLane>::with_projection_registry(
                writer,
                projection_registry,
            ),
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

fn producer_authorization_storage_error(path: &'static str) -> IdentityError {
    storage_boxed(std::io::Error::other(format!(
        "{path}: producer receipt does not authorize outbox envelope contract"
    )))
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
            Self::Eq { value } => Operator::Eq(
                AttributeValue::parse(&value).map_err(|_| IdentityError::InvalidPolicy)?,
            ),
            Self::Ne { value } => Operator::Ne(
                AttributeValue::parse(&value).map_err(|_| IdentityError::InvalidPolicy)?,
            ),
            Self::Like { pattern } => Operator::Like(
                GlobPattern::parse(&pattern).map_err(|_| IdentityError::InvalidPolicy)?,
            ),
            Self::Gt { value } => Operator::Gt(
                AttributeValue::parse(&value).map_err(|_| IdentityError::InvalidPolicy)?,
            ),
            Self::Lt { value } => Operator::Lt(
                AttributeValue::parse(&value).map_err(|_| IdentityError::InvalidPolicy)?,
            ),
            Self::EqAttr { attribute } => Operator::EqAttr(
                PipAttributeKey::parse(&attribute).map_err(|_| IdentityError::InvalidPolicy)?,
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
pub(crate) struct RawPolicy {
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
    async fn find(
        &self,
        tenant_scope: TenantRepoScope,
        id: PolicyId,
    ) -> Result<Option<Policy>, IdentityError> {
        let tenant = tenant_scope.tenant();
        let query_id = id.clone();
        let raw: Option<RawPolicy> = self
            .pool
            .identity_read(tenant_scope, move |mut conn| {
                Box::pin(async move { conn.identity().policy_row(&query_id).await })
            })
            .await
            .map_err(storage)?;
        raw.map(|raw| hydrate_policy(tenant, raw)).transpose()
    }

    async fn list_active(
        &self,
        tenant_scope: TenantRepoScope,
        page: PolicyPage,
    ) -> Result<PolicyListResult, IdentityError> {
        let tenant = tenant_scope.tenant();
        let limit = usize::from(page.limit.get());
        let fetch_limit = i64::try_from(limit.saturating_add(1)).map_err(storage_boxed)?;
        let after = page.after;
        let raw: Vec<RawPolicy> = self
            .pool
            .identity_read(tenant_scope, move |mut conn| {
                Box::pin(async move {
                    conn.identity()
                        .active_policy_rows(after.as_ref(), fetch_limit)
                        .await
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
        tenant_scope: TenantRepoScope,
        scope: PolicyRouteScope,
        at: SystemTime,
    ) -> Result<Vec<Policy>, IdentityError> {
        let tenant = tenant_scope.tenant();
        let query_scope = scope.clone();
        let raw: Vec<RawPolicy> = self
            .pool
            .identity_read(tenant_scope, move |mut conn| {
                Box::pin(async move {
                    conn.identity()
                        .effective_policy_rows(&query_scope, at)
                        .await
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
        receipt: PoliciesCreateProducerReceipt,
        tenant_scope: TenantRepoScope,
        policy: Policy,
        event: ReviewedEvent,
    ) -> Result<Policy, IdentityError> {
        let tenant = tenant_scope.tenant();
        if policy.tenant() != tenant || policy.version().get() != 1 {
            return Err(IdentityError::InvalidPolicy);
        }
        let generated_fact = event.fact();
        let (entry, envelope, _fact) = event.into_parts();
        let (env_tenant, env) = self.envelope(envelope)?;
        if env_tenant != tenant {
            return Err(IdentityError::InvalidPolicy);
        }
        let rules_json = encode_rules(&policy)?;
        let persisted_policy = policy.clone();
        let inserted = self
            .pool
            .identity_producer_tx(
                tenant_scope,
                &entry,
                &env,
                move |mut conn| {
                    Box::pin(async move {
                        conn.identity()
                            .create_policy(&persisted_policy, &rules_json)
                            .await
                            .and_then(|rows| {
                                if rows > 0 {
                                    Ok(rows)
                                } else {
                                    Err(IdentityError::PolicyAlreadyExists)
                                }
                            })?;
                        let authorization = receipt
                            .authorize(generated_fact, POLICY_UPDATED_CONTRACT)
                            .ok_or_else(|| {
                                producer_authorization_storage_error("policy create co-tx")
                            })?;
                        Ok(ProducerTxOutcome::Emitted(1, authorization))
                    })
                },
                storage,
            )
            .await
            .into_result()?;
        debug_assert_eq!(inserted, 1);
        Ok(policy)
    }

    async fn update_and_emit(
        &self,
        receipt: PoliciesUpdateProducerReceipt,
        tenant_scope: TenantRepoScope,
        policy: Policy,
        expected: PolicyVersion,
        event: ReviewedEvent,
    ) -> Result<Policy, IdentityError> {
        let tenant = tenant_scope.tenant();
        if policy.tenant() != tenant {
            return Err(IdentityError::InvalidPolicy);
        }
        let generated_fact = event.fact();
        let (entry, envelope, _fact) = event.into_parts();
        let (env_tenant, env) = self.envelope(envelope)?;
        if env_tenant != tenant {
            return Err(IdentityError::InvalidPolicy);
        }
        let rules_json = encode_rules(&policy)?;
        let (raw, exists): (Option<RawPolicy>, bool) = self
            .pool
            .identity_producer_tx(
                tenant_scope,
                &entry,
                &env,
                move |mut conn| {
                    Box::pin(async move {
                        let (row, exists) = conn
                            .identity()
                            .update_policy(&policy, expected, &rules_json)
                            .await?;
                        let authorization = if row.is_some() {
                            let authorization = receipt
                                .authorize(generated_fact, POLICY_UPDATED_CONTRACT)
                                .ok_or_else(|| {
                                    producer_authorization_storage_error("policy update co-tx")
                                })?;
                            Some(authorization)
                        } else {
                            None
                        };
                        let value = (row, exists);
                        Ok(match authorization {
                            Some(authorization) => ProducerTxOutcome::Emitted(value, authorization),
                            None => ProducerTxOutcome::NoMutation(value),
                        })
                    })
                },
                storage,
            )
            .await
            .into_result()?;

        match raw {
            Some(raw) => hydrate_policy(tenant, raw),
            None => {
                if exists {
                    Err(IdentityError::VersionConflict)
                } else {
                    Err(IdentityError::PolicyNotFound)
                }
            }
        }
    }

    async fn deactivate_and_emit(
        &self,
        receipt: PoliciesDeactivateProducerReceipt,
        tenant_scope: TenantRepoScope,
        id: PolicyId,
        expected: PolicyVersion,
        event: ReviewedEvent,
    ) -> Result<bool, IdentityError> {
        let tenant = tenant_scope.tenant();
        let generated_fact = event.fact();
        let (entry, envelope, _fact) = event.into_parts();
        let (env_tenant, env) = self.envelope(envelope)?;
        if env_tenant != tenant {
            return Err(IdentityError::InvalidPolicy);
        }
        let (deleted, exists) = self
            .pool
            .identity_producer_tx(
                tenant_scope,
                &entry,
                &env,
                move |mut conn| {
                    Box::pin(async move {
                        let (rows, exists) =
                            conn.identity().deactivate_policy(&id, expected).await?;
                        let authorization = if rows > 0 {
                            let authorization = receipt
                                .authorize(generated_fact, POLICY_UPDATED_CONTRACT)
                                .ok_or_else(|| {
                                    producer_authorization_storage_error("policy deactivate co-tx")
                                })?;
                            Some(authorization)
                        } else {
                            None
                        };
                        let value = (rows, exists);
                        Ok(match authorization {
                            Some(authorization) => ProducerTxOutcome::Emitted(value, authorization),
                            None => ProducerTxOutcome::NoMutation(value),
                        })
                    })
                },
                storage,
            )
            .await
            .into_result()?;
        if deleted > 0 {
            return Ok(true);
        }
        if exists {
            Err(IdentityError::VersionConflict)
        } else {
            Ok(false)
        }
    }
}

pub(crate) fn row_to_raw(row: sqlx::postgres::PgRow) -> Result<RawPolicy, sqlx::Error> {
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

#[cfg(test)]
mod operator_dto_tests {
    use super::*;
    use identity::ports::ATTR_VALUE_MAX_LEN;

    #[test]
    fn operator_dto_rejects_overlong_value_as_invalid_policy() {
        let dto = OperatorDto::Eq {
            value: "a".repeat(ATTR_VALUE_MAX_LEN + 1),
        };
        assert!(matches!(
            dto.into_operator(),
            Err(IdentityError::InvalidPolicy)
        ));
    }

    #[test]
    fn operator_dto_accepts_exact_max_value() {
        let dto = OperatorDto::Eq {
            value: "a".repeat(ATTR_VALUE_MAX_LEN),
        };
        assert!(
            matches!(
                dto.into_operator(),
                Ok(Operator::Eq(v)) if v.as_str().len() == ATTR_VALUE_MAX_LEN
            ),
            "exact-max must decode as Eq"
        );
    }

    #[test]
    fn operator_dto_eq_attr_accepts_pip_principal_id() {
        let dto = OperatorDto::EqAttr {
            attribute: "principal.id".to_string(),
        };
        assert!(
            matches!(
                dto.into_operator(),
                Ok(Operator::EqAttr(key)) if key.as_str() == "principal.id"
            ),
            "PIP principal.id must decode"
        );
    }

    #[test]
    fn operator_dto_eq_attr_rejects_non_pip_attribute() {
        let dto = OperatorDto::EqAttr {
            attribute: "secret.probe".to_string(),
        };
        assert!(matches!(
            dto.into_operator(),
            Err(IdentityError::InvalidPolicy)
        ));
    }
}
