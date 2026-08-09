//! `PgPolicyRepo` —— identity durable ABAC policy store（#1588）。

use std::time::SystemTime;

use diport::{Clock, OutboxEnvelopeParts};
use eventexec::event::ReviewedEvent;
use identity::ports::{
    AttributeKey, EqualityOperand, EqualityOperator, EqualityPredicate, IdentityError,
    MembershipOperator, MembershipPredicate, NumericValue, Operator, OrderingOperand,
    OrderingOperator, OrderingPredicate, POLICY_UPDATED_CONTRACT, PipAttributeKey,
    PoliciesCreateProducerReceipt, PoliciesDeactivateProducerReceipt,
    PoliciesUpdateProducerReceipt, Policy, PolicyCondition, PolicyEffect, PolicyId,
    PolicyLifecycle, PolicyListResult, PolicyObligations, PolicyPage, PolicyRepo, PolicyRouteScope,
    PolicyRule, PolicyValue, PolicyValueRef, PolicyValueSet, PolicyValueType, PolicyVersion,
    StringOperator, StringPredicate, TenantId, TenantRepoScope, TypedAttributeOperand,
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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesDoc {
    rules: Vec<RuleDto>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RuleDto {
    condition: ConditionDto,
    effect: EffectDto,
    #[serde(default)]
    obligations: ObligationsDto,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ConditionDto {
    attribute: String,
    operator: OperatorDto,
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "family",
    deny_unknown_fields,
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum OperatorDto {
    Equality {
        predicate: EqualityPredicateDto,
        operand: ScalarOperandDto,
    },
    Ordering {
        predicate: OrderingPredicateDto,
        operand: ScalarOperandDto,
    },
    Membership {
        predicate: MembershipPredicateDto,
        operand: SetOperandDto,
    },
    String {
        predicate: StringPredicateDto,
        operand: PatternOperandDto,
    },
}

impl std::fmt::Debug for OperatorDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OperatorDto(<redacted>)")
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum EqualityPredicateDto {
    Eq,
    Ne,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum OrderingPredicateDto {
    Gt,
    Ge,
    Lt,
    Le,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum MembershipPredicateDto {
    In,
    NotIn,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum StringPredicateDto {
    StartsWith,
    EndsWith,
    Contains,
    Glob,
    Regex,
}
#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "camelCase")]
enum ValueTypeDto {
    String,
    Boolean,
    Integer,
    Decimal,
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    deny_unknown_fields,
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum ScalarOperandDto {
    Literal {
        value_type: ValueTypeDto,
        value: serde_json::Value,
    },
    Attribute {
        value_type: ValueTypeDto,
        attribute: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SetOperandDto {
    kind: SetKindDto,
    value_type: ValueTypeDto,
    values: Vec<serde_json::Value>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum SetKindDto {
    Set,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PatternOperandDto {
    kind: PatternKindDto,
    value_type: StringTypeDto,
    value: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum PatternKindDto {
    Pattern,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum StringTypeDto {
    String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum EffectDto {
    Allow,
    Deny,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ObligationsDto {
    row_scope: Option<RowScopeDto>,
    #[serde(default)]
    field_mask: Vec<String>,
}

#[derive(Serialize, Deserialize)]
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
            Operator::Equality(value) => Ok(Self::Equality {
                predicate: match value.predicate() {
                    EqualityPredicate::Eq => EqualityPredicateDto::Eq,
                    EqualityPredicate::Ne => EqualityPredicateDto::Ne,
                },
                operand: ScalarOperandDto::from_equality(value.operand()),
            }),
            Operator::Ordering(value) => Ok(Self::Ordering {
                predicate: match value.predicate() {
                    OrderingPredicate::Gt => OrderingPredicateDto::Gt,
                    OrderingPredicate::Ge => OrderingPredicateDto::Ge,
                    OrderingPredicate::Lt => OrderingPredicateDto::Lt,
                    OrderingPredicate::Le => OrderingPredicateDto::Le,
                },
                operand: ScalarOperandDto::from_ordering(value.operand()),
            }),
            Operator::Membership(value) => Ok(Self::Membership {
                predicate: match value.predicate() {
                    MembershipPredicate::In => MembershipPredicateDto::In,
                    MembershipPredicate::NotIn => MembershipPredicateDto::NotIn,
                },
                operand: SetOperandDto {
                    kind: SetKindDto::Set,
                    value_type: ValueTypeDto::from_domain(value.operand().value_type()),
                    values: value.operand().values().iter().map(json_value).collect(),
                },
            }),
            Operator::StringMatch(value) => Ok(Self::String {
                predicate: match value.predicate() {
                    StringPredicate::StartsWith => StringPredicateDto::StartsWith,
                    StringPredicate::EndsWith => StringPredicateDto::EndsWith,
                    StringPredicate::Contains => StringPredicateDto::Contains,
                    StringPredicate::Glob => StringPredicateDto::Glob,
                    StringPredicate::Regex => StringPredicateDto::Regex,
                },
                operand: PatternOperandDto {
                    kind: PatternKindDto::Pattern,
                    value_type: StringTypeDto::String,
                    value: value.pattern().to_string(),
                },
            }),
        }
    }

    fn into_operator(self) -> Result<Operator, IdentityError> {
        Ok(match self {
            Self::Equality { predicate, operand } => Operator::Equality(EqualityOperator::new(
                match predicate {
                    EqualityPredicateDto::Eq => EqualityPredicate::Eq,
                    EqualityPredicateDto::Ne => EqualityPredicate::Ne,
                },
                operand.into_equality()?,
            )),
            Self::Ordering { predicate, operand } => Operator::Ordering(OrderingOperator::new(
                match predicate {
                    OrderingPredicateDto::Gt => OrderingPredicate::Gt,
                    OrderingPredicateDto::Ge => OrderingPredicate::Ge,
                    OrderingPredicateDto::Lt => OrderingPredicate::Lt,
                    OrderingPredicateDto::Le => OrderingPredicate::Le,
                },
                operand.into_ordering()?,
            )),
            Self::Membership { predicate, operand } => {
                Operator::Membership(MembershipOperator::new(
                    match predicate {
                        MembershipPredicateDto::In => MembershipPredicate::In,
                        MembershipPredicateDto::NotIn => MembershipPredicate::NotIn,
                    },
                    PolicyValueSet::new(operand.into_values()?)
                        .map_err(|_| IdentityError::InvalidPolicy)?,
                ))
            }
            Self::String { predicate, operand } => Operator::StringMatch(
                StringOperator::parse(
                    match predicate {
                        StringPredicateDto::StartsWith => StringPredicate::StartsWith,
                        StringPredicateDto::EndsWith => StringPredicate::EndsWith,
                        StringPredicateDto::Contains => StringPredicate::Contains,
                        StringPredicateDto::Glob => StringPredicate::Glob,
                        StringPredicateDto::Regex => StringPredicate::Regex,
                    },
                    &operand.value,
                )
                .map_err(|_| IdentityError::InvalidPolicy)?,
            ),
        })
    }
}

impl ScalarOperandDto {
    fn from_equality(value: &EqualityOperand) -> Self {
        match value {
            EqualityOperand::Literal(value) => Self::Literal {
                value_type: ValueTypeDto::from_domain(value.value_type()),
                value: json_value(value),
            },
            EqualityOperand::Attribute(value) => Self::Attribute {
                value_type: ValueTypeDto::from_domain(value.value_type()),
                attribute: value.attribute().as_str().to_string(),
            },
        }
    }
    fn from_ordering(value: &OrderingOperand) -> Self {
        let value = value.value().clone().into_policy_value();
        Self::Literal {
            value_type: ValueTypeDto::from_domain(value.value_type()),
            value: json_value(&value),
        }
    }
    fn into_equality(self) -> Result<EqualityOperand, IdentityError> {
        match self {
            Self::Literal { value_type, value } => {
                Ok(EqualityOperand::Literal(parse_value(value_type, value)?))
            }
            Self::Attribute {
                value_type,
                attribute,
            } => {
                if !matches!(value_type, ValueTypeDto::String) {
                    return Err(IdentityError::InvalidPolicy);
                }
                Ok(EqualityOperand::Attribute(TypedAttributeOperand::new(
                    PipAttributeKey::parse(&attribute).map_err(|_| IdentityError::InvalidPolicy)?,
                )))
            }
        }
    }
    fn into_ordering(self) -> Result<OrderingOperand, IdentityError> {
        match self {
            Self::Literal { value_type, value } => {
                NumericValue::from_policy_value(parse_value(value_type, value)?)
                    .map(OrderingOperand::literal)
                    .ok_or(IdentityError::InvalidPolicy)
            }
            Self::Attribute { .. } => Err(IdentityError::InvalidPolicy),
        }
    }
}

impl SetOperandDto {
    fn into_values(self) -> Result<Vec<PolicyValue>, IdentityError> {
        self.values
            .into_iter()
            .map(|value| parse_value(self.value_type, value))
            .collect()
    }
}

impl ValueTypeDto {
    const fn from_domain(value: PolicyValueType) -> Self {
        match value {
            PolicyValueType::String => Self::String,
            PolicyValueType::Boolean => Self::Boolean,
            PolicyValueType::Integer => Self::Integer,
            PolicyValueType::Decimal => Self::Decimal,
        }
    }
}

fn parse_value(
    value_type: ValueTypeDto,
    value: serde_json::Value,
) -> Result<PolicyValue, IdentityError> {
    match value_type {
        ValueTypeDto::String => value
            .as_str()
            .ok_or(IdentityError::InvalidPolicy)
            .and_then(|value| PolicyValue::string(value).map_err(|_| IdentityError::InvalidPolicy)),
        ValueTypeDto::Boolean => value
            .as_bool()
            .map(PolicyValue::boolean)
            .ok_or(IdentityError::InvalidPolicy),
        ValueTypeDto::Integer => value
            .as_i64()
            .map(PolicyValue::integer)
            .ok_or(IdentityError::InvalidPolicy),
        ValueTypeDto::Decimal => {
            value
                .as_str()
                .ok_or(IdentityError::InvalidPolicy)
                .and_then(|value| {
                    PolicyValue::decimal(value).map_err(|_| IdentityError::InvalidPolicy)
                })
        }
    }
}

fn json_value(value: &PolicyValue) -> serde_json::Value {
    match value.as_ref() {
        PolicyValueRef::String(value) => serde_json::Value::String(value.to_string()),
        PolicyValueRef::Boolean(value) => serde_json::Value::Bool(value),
        PolicyValueRef::Integer(value) => serde_json::Value::Number(value.into()),
        PolicyValueRef::Decimal(value) => serde_json::Value::String(value.as_str().to_string()),
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

pub(crate) struct RawPolicy {
    id: String,
    version: i32,
    contract_id: String,
    permission: String,
    effective_from: i64,
    effective_until: Option<i64>,
    rules_json: String,
}

impl std::fmt::Debug for RawPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawPolicy")
            .field("id", &self.id)
            .field("version", &self.version)
            .field("contract_id", &self.contract_id)
            .field("permission", &self.permission)
            .field("effective_from", &self.effective_from)
            .field("effective_until", &self.effective_until)
            .field("rules_json", &"<redacted>")
            .finish()
    }
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
        let dto = OperatorDto::Equality {
            predicate: EqualityPredicateDto::Eq,
            operand: ScalarOperandDto::Literal {
                value_type: ValueTypeDto::String,
                value: serde_json::json!("a".repeat(ATTR_VALUE_MAX_LEN + 1)),
            },
        };
        assert!(matches!(
            dto.into_operator(),
            Err(IdentityError::InvalidPolicy)
        ));
    }

    #[test]
    fn operator_dto_accepts_exact_max_value() {
        let dto = OperatorDto::Equality {
            predicate: EqualityPredicateDto::Eq,
            operand: ScalarOperandDto::Literal {
                value_type: ValueTypeDto::String,
                value: serde_json::json!("a".repeat(ATTR_VALUE_MAX_LEN)),
            },
        };
        assert!(
            matches!(
                dto.into_operator(),
                Ok(Operator::Equality(ref op)) if matches!(op.operand(), EqualityOperand::Literal(v) if v.string_value().is_some_and(|value| value.len() == ATTR_VALUE_MAX_LEN))
            ),
            "exact-max must decode as Eq"
        );
    }

    #[test]
    fn operator_dto_eq_attr_accepts_pip_principal_id() {
        let dto = OperatorDto::Equality {
            predicate: EqualityPredicateDto::Eq,
            operand: ScalarOperandDto::Attribute {
                value_type: ValueTypeDto::String,
                attribute: "principal.id".to_string(),
            },
        };
        assert!(
            matches!(
                dto.into_operator(),
                Ok(Operator::Equality(ref op)) if matches!(op.operand(), EqualityOperand::Attribute(value) if value.attribute().as_str() == "principal.id")
            ),
            "PIP principal.id must decode"
        );
    }

    #[test]
    fn operator_dto_eq_attr_rejects_non_pip_attribute() {
        let dto = OperatorDto::Equality {
            predicate: EqualityPredicateDto::Eq,
            operand: ScalarOperandDto::Attribute {
                value_type: ValueTypeDto::String,
                attribute: "secret.probe".to_string(),
            },
        };
        assert!(matches!(
            dto.into_operator(),
            Err(IdentityError::InvalidPolicy)
        ));
    }

    #[test]
    fn operator_dto_round_trips_typed_membership() {
        let operator = Operator::Membership(MembershipOperator::new(
            MembershipPredicate::In,
            PolicyValueSet::new(vec![PolicyValue::integer(2), PolicyValue::integer(1)])
                .expect("set"),
        ));
        let dto = OperatorDto::from_operator(&operator).expect("encode");
        let json = serde_json::to_value(&dto).expect("json");
        assert_eq!(json["operand"]["values"], serde_json::json!([1, 2]));
        assert_eq!(
            serde_json::from_value::<OperatorDto>(json)
                .expect("decode")
                .into_operator()
                .expect("domain"),
            operator
        );
    }

    #[test]
    fn operator_dto_round_trips_complete_common_profile_matrix() {
        let string = PolicyValue::string("团队Ops").expect("string");
        let decimal = PolicyValue::decimal("1.25").expect("decimal");
        let operators = vec![
            Operator::Equality(EqualityOperator::new(
                EqualityPredicate::Eq,
                EqualityOperand::Literal(string.clone()),
            )),
            Operator::Equality(EqualityOperator::new(
                EqualityPredicate::Ne,
                EqualityOperand::Literal(PolicyValue::boolean(true)),
            )),
            Operator::equal_attribute(PipAttributeKey::principal_id()),
            Operator::Ordering(OrderingOperator::new(
                OrderingPredicate::Gt,
                OrderingOperand::literal(NumericValue::Integer(7)),
            )),
            Operator::Ordering(OrderingOperator::new(
                OrderingPredicate::Ge,
                OrderingOperand::literal(NumericValue::Decimal(
                    identity::ports::DecimalValue::parse("1.25").expect("decimal"),
                )),
            )),
            Operator::Ordering(OrderingOperator::new(
                OrderingPredicate::Lt,
                OrderingOperand::literal(NumericValue::Integer(-7)),
            )),
            Operator::Ordering(OrderingOperator::new(
                OrderingPredicate::Le,
                OrderingOperand::literal(NumericValue::Integer(0)),
            )),
            Operator::Membership(MembershipOperator::new(
                MembershipPredicate::In,
                PolicyValueSet::new(vec![string, PolicyValue::string("ops").expect("string")])
                    .expect("string set"),
            )),
            Operator::Membership(MembershipOperator::new(
                MembershipPredicate::NotIn,
                PolicyValueSet::new(vec![
                    PolicyValue::boolean(false),
                    PolicyValue::boolean(true),
                ])
                .expect("bool set"),
            )),
            Operator::Membership(MembershipOperator::new(
                MembershipPredicate::In,
                PolicyValueSet::new(vec![PolicyValue::integer(1), PolicyValue::integer(2)])
                    .expect("integer set"),
            )),
            Operator::Membership(MembershipOperator::new(
                MembershipPredicate::NotIn,
                PolicyValueSet::new(vec![decimal]).expect("decimal set"),
            )),
        ];
        let operators = operators.into_iter().chain(
            [
                StringPredicate::StartsWith,
                StringPredicate::EndsWith,
                StringPredicate::Contains,
                StringPredicate::Glob,
                StringPredicate::Regex,
            ]
            .into_iter()
            .map(|predicate| {
                let pattern = if predicate == StringPredicate::Regex {
                    "^团队Ops$"
                } else {
                    "团队*"
                };
                Operator::string(predicate, pattern).expect("pattern")
            }),
        );

        for operator in operators {
            let dto = OperatorDto::from_operator(&operator).expect("encode");
            let json = serde_json::to_value(dto).expect("json");
            let decoded = serde_json::from_value::<OperatorDto>(json)
                .expect("decode")
                .into_operator()
                .expect("domain");
            assert_eq!(decoded, operator);
        }
    }

    #[test]
    fn adapter_debug_redacts_policy_operands_and_raw_rules() {
        let dto = OperatorDto::String {
            predicate: StringPredicateDto::Regex,
            operand: PatternOperandDto {
                kind: PatternKindDto::Pattern,
                value_type: StringTypeDto::String,
                value: "do-not-log".into(),
            },
        };
        let raw = RawPolicy {
            id: "policy-safe-id".into(),
            version: 1,
            contract_id: "contract".into(),
            permission: "permission".into(),
            effective_from: 0,
            effective_until: None,
            rules_json: "do-not-log".into(),
        };
        let debug = format!("{dto:?} {raw:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("do-not-log"));
    }
}
