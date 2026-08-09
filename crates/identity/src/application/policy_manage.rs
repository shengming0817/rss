//! Identity policy management write side.

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use consistency::IdemKey;
use diport::Clock;
use eventexec::event::{EventEncodeError, ReviewedEvent};
use generated::event::identity_v1::policy_updated::{
    IdentityPolicyUpdatedPayload, IdentityPolicyUpdatedPayloadActorKind,
    IdentityPolicyUpdatedPayloadChangeKind, SPEC as POLICY_UPDATED_SPEC,
};
use generated::http::identity_v1::{
    policies_create as create_wire,
    policies_create::{IdentityPoliciesCreateRequest, IdentityPoliciesCreateResponse},
    policies_deactivate::{IdentityPoliciesDeactivateRequest, IdentityPoliciesDeactivateResponse},
    policies_get as get_wire,
    policies_get::IdentityPoliciesGetResponse,
    policies_list as list_wire,
    policies_list::IdentityPoliciesListResponse,
    policies_update as update_wire,
    policies_update::{IdentityPoliciesUpdateRequest, IdentityPoliciesUpdateResponse},
};
use generated::http::{HttpSpec, SPECS as HTTP_SPECS};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vocab::{HttpRouteAuth, TenantId, http::HttpResourceSharing as HttpResourceSharingMode};

use super::{EventWireProjectionError, unix_secs};
use crate::domain::{
    AttributeKey, EqualityOperand, EqualityOperator, EqualityPredicate, IdentityError,
    MembershipOperator, MembershipPredicate, NumericValue, Operator, OperatorError,
    OrderingOperand, OrderingOperator, OrderingPredicate, PipAttributeKey, Policy, PolicyCondition,
    PolicyEffect, PolicyId, PolicyObligations, PolicyRouteScope, PolicyRule, PolicyValue,
    PolicyValueRef, PolicyValueSet, PolicyValueType, PolicyVersion, ResourcePolicyAttributeKey,
    StringOperator, StringPredicate, TypedAttributeOperand,
};
use crate::ports::{
    DynPolicyLifecycle, DynPolicyRepo, PoliciesCreateProducerReceipt,
    PoliciesDeactivateProducerReceipt, PoliciesUpdateProducerReceipt, PolicyLifecycle, PolicyPage,
    PolicyRepo, TenantRepoScope,
};

const POLICY_DOMAIN: &str = POLICY_UPDATED_SPEC.contract().domain();

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyManageError {
    #[error("policy is invalid")]
    InvalidPolicy,
    /// 属性值超过域 UTF-8 字节上界（wire 字符上界可能仍放行；见 [`ATTR_VALUE_MAX_LEN`]）。
    #[error("attribute value exceeds max length")]
    PolicyValueTooLong,
    #[error("policy operator is invalid: {0:?}")]
    InvalidOperator(PolicyOperatorReason),
    #[error("policy not found")]
    PolicyNotFound,
    #[error("policy already exists")]
    PolicyAlreadyExists,
    #[error("policy version conflict")]
    VersionConflict,
    #[error("policy outbox fact conflict")]
    OutboxFactConflict(#[source] consistency::OutboxFactConflict),
    #[error("policy-event payload encode failed")]
    PayloadEncode(#[source] serde_json::Error),
    /// Generated event authoring boundary rejected the payload or topology.
    #[error("policy-event authoring failed")]
    EventEncode(#[source] EventEncodeError),
    #[error("policy-event idempotency identity validation failed")]
    IdempotencyKey(#[source] consistency::IdemKeyError),
    #[error("policy wire projection failed")]
    WireProjection(#[source] EventWireProjectionError),
    #[error("policy store failed")]
    Store(#[source] IdentityError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyOperatorReason {
    InvalidRegex,
    InvalidPattern,
    DuplicateSetValue,
    MixedSet,
    InvalidSetSize,
    InvalidDecimal,
    InvalidOperatorCombination,
}

impl PolicyOperatorReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRegex => "invalidRegex",
            Self::InvalidPattern => "invalidPattern",
            Self::DuplicateSetValue => "duplicateSetValue",
            Self::MixedSet => "mixedSet",
            Self::InvalidSetSize => "invalidSetSize",
            Self::InvalidDecimal => "invalidDecimal",
            Self::InvalidOperatorCombination => "invalidOperatorCombination",
        }
    }
}

fn operator_reason(error: OperatorError) -> PolicyOperatorReason {
    match error {
        OperatorError::InvalidRegex => PolicyOperatorReason::InvalidRegex,
        OperatorError::InvalidPattern => PolicyOperatorReason::InvalidPattern,
        OperatorError::DuplicateSetValue => PolicyOperatorReason::DuplicateSetValue,
        OperatorError::MixedSet => PolicyOperatorReason::MixedSet,
        OperatorError::EmptySet | OperatorError::SetTooLarge => {
            PolicyOperatorReason::InvalidSetSize
        }
    }
}

pub struct PolicyCreateDraft {
    id: PolicyId,
    scope: PolicyRouteScope,
    effective_from: SystemTime,
    effective_until: Option<SystemTime>,
    rules: Vec<PolicyRule>,
}

pub struct PolicyUpdateDraft {
    id: PolicyId,
    scope: PolicyRouteScope,
    expected: PolicyVersion,
    effective_from: SystemTime,
    effective_until: Option<SystemTime>,
    rules: Vec<PolicyRule>,
}

pub struct PolicyDeactivateDraft {
    id: PolicyId,
    expected: PolicyVersion,
}

impl PolicyCreateDraft {
    pub(crate) fn target_scope(&self) -> &PolicyRouteScope {
        &self.scope
    }
}

impl TryFrom<IdentityPoliciesCreateRequest> for PolicyCreateDraft {
    type Error = PolicyManageError;

    fn try_from(request: IdentityPoliciesCreateRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            id: policy_id_from_wire(&request.policy_id)?,
            scope: PolicyRouteScope::parse(&request.contract_id, &request.permission)
                .map_err(|_| PolicyManageError::InvalidPolicy)?,
            effective_from: wire_time(request.effective_from)?,
            effective_until: request.effective_until.map(wire_time).transpose()?,
            rules: create_rules_from_wire(request.rules)?,
        })
    }
}

impl PolicyUpdateDraft {
    pub(crate) fn policy_id(&self) -> &PolicyId {
        &self.id
    }

    pub(crate) fn target_scope(&self) -> &PolicyRouteScope {
        &self.scope
    }

    pub fn try_from_wire(
        policy_id: PolicyId,
        request: IdentityPoliciesUpdateRequest,
    ) -> Result<Self, PolicyManageError> {
        Ok(Self {
            id: policy_id,
            scope: PolicyRouteScope::parse(&request.contract_id, &request.permission)
                .map_err(|_| PolicyManageError::InvalidPolicy)?,
            expected: PolicyVersion::new(request.expected_version.get())
                .map_err(|_| PolicyManageError::InvalidPolicy)?,
            effective_from: wire_time(request.effective_from)?,
            effective_until: request.effective_until.map(wire_time).transpose()?,
            rules: update_rules_from_wire(request.rules)?,
        })
    }
}

impl PolicyDeactivateDraft {
    pub(crate) fn policy_id(&self) -> &PolicyId {
        &self.id
    }

    pub fn try_from_wire(
        policy_id: PolicyId,
        request: IdentityPoliciesDeactivateRequest,
    ) -> Result<Self, PolicyManageError> {
        Ok(Self {
            id: policy_id,
            expected: PolicyVersion::new(request.expected_version.get())
                .map_err(|_| PolicyManageError::InvalidPolicy)?,
        })
    }
}

pub struct PolicyManageService {
    policies: Arc<DynPolicyRepo<'static>>,
    lifecycle: Arc<DynPolicyLifecycle<'static>>,
    clock: Box<dyn Clock>,
    http_specs: &'static [HttpSpec],
}

/// Policy 查询侧：仅持有已分类的认证读 port，不暴露 lifecycle、clock 或 outbox 能力。
#[derive(Clone)]
pub(crate) struct PolicyQueryService {
    pub(super) policies: Arc<DynPolicyRepo<'static>>,
}

impl PolicyQueryService {
    pub(crate) async fn get_policy(
        &self,
        tenant: TenantId,
        id: PolicyId,
    ) -> Result<Policy, PolicyManageError> {
        let tenant_scope = TenantRepoScope::from_authenticated_tenant(tenant);
        self.policies
            .find(tenant_scope, id)
            .await
            .map_err(map_identity_error)?
            .ok_or(PolicyManageError::PolicyNotFound)
    }

    pub(crate) async fn list_policies(
        &self,
        tenant: TenantId,
        page: PolicyPage,
    ) -> Result<crate::ports::PolicyListResult, PolicyManageError> {
        let tenant_scope = TenantRepoScope::from_authenticated_tenant(tenant);
        self.policies
            .list_active(tenant_scope, page)
            .await
            .map_err(map_identity_error)
    }
}

impl httpserve::ClassifiedRouteState for PolicyQueryService {
    type Effect = diport::AuthEffect;
    type Privilege = diport::LocalPrivilege;
}

struct PolicyEventDraft<'a> {
    tenant: TenantId,
    actor: ids::UserId,
    actor_kind: vocab::PrincipalKind,
    policy_id: &'a PolicyId,
    scope: &'a PolicyRouteScope,
    change_kind: IdentityPolicyUpdatedPayloadChangeKind,
    version: PolicyVersion,
}

impl PolicyManageService {
    pub fn new(
        policies: Arc<DynPolicyRepo<'static>>,
        lifecycle: Arc<DynPolicyLifecycle<'static>>,
        clock: Box<dyn Clock>,
    ) -> Self {
        Self {
            policies,
            lifecycle,
            clock,
            http_specs: HTTP_SPECS,
        }
    }

    pub(crate) async fn find_policy_for_management(
        &self,
        tenant: TenantId,
        id: PolicyId,
    ) -> Result<Policy, PolicyManageError> {
        let tenant_scope = TenantRepoScope::from_authenticated_tenant(tenant);
        self.policies
            .find(tenant_scope, id)
            .await
            .map_err(map_identity_error)?
            .ok_or(PolicyManageError::PolicyNotFound)
    }

    #[cfg(test)]
    fn new_with_http_specs(
        policies: Arc<DynPolicyRepo<'static>>,
        lifecycle: Arc<DynPolicyLifecycle<'static>>,
        clock: Box<dyn Clock>,
        http_specs: &'static [HttpSpec],
    ) -> Self {
        Self {
            policies,
            lifecycle,
            clock,
            http_specs,
        }
    }

    #[tracing::instrument(
        skip_all,
        fields(domain = POLICY_DOMAIN, operation = "policy_create", tenant_id = %tenant),
        err(level = "warn")
    )]
    pub async fn create_policy(
        &self,
        receipt: PoliciesCreateProducerReceipt,
        tenant: TenantId,
        actor: ids::UserId,
        actor_kind: vocab::PrincipalKind,
        draft: PolicyCreateDraft,
    ) -> Result<Policy, PolicyManageError> {
        let tenant_scope = TenantRepoScope::from_authenticated_tenant(tenant);
        let policy = Policy::build(
            draft.id.as_str(),
            tenant,
            draft.scope,
            draft.effective_from,
            draft.effective_until,
            draft.rules,
        )
        .map_err(|_| PolicyManageError::InvalidPolicy)?;
        reject_global_resource_policy(policy.route_scope(), policy.rules(), self.http_specs)?;
        let event = self
            .event_parts(PolicyEventDraft {
                tenant,
                actor,
                actor_kind,
                policy_id: policy.id(),
                scope: policy.route_scope(),
                change_kind: IdentityPolicyUpdatedPayloadChangeKind::Created,
                version: policy.version(),
            })
            .await?;
        self.lifecycle
            .create_and_emit(receipt, tenant_scope, policy, event)
            .await
            .map_err(map_identity_error)
    }

    #[tracing::instrument(
        skip_all,
        fields(domain = POLICY_DOMAIN, operation = "policy_update", tenant_id = %tenant),
        err(level = "warn")
    )]
    pub async fn update_policy(
        &self,
        receipt: PoliciesUpdateProducerReceipt,
        tenant: TenantId,
        actor: ids::UserId,
        actor_kind: vocab::PrincipalKind,
        draft: PolicyUpdateDraft,
    ) -> Result<Policy, PolicyManageError> {
        let tenant_scope = TenantRepoScope::from_authenticated_tenant(tenant);
        let next = draft
            .expected
            .next_checked()
            .map_err(|_| PolicyManageError::VersionConflict)?;
        let policy = Policy::hydrate(
            draft.id.as_str(),
            tenant,
            draft.scope,
            draft.expected.get(),
            draft.effective_from,
            draft.effective_until,
            draft.rules,
        )
        .map_err(|_| PolicyManageError::InvalidPolicy)?;
        reject_global_resource_policy(policy.route_scope(), policy.rules(), self.http_specs)?;
        let event = self
            .event_parts(PolicyEventDraft {
                tenant,
                actor,
                actor_kind,
                policy_id: policy.id(),
                scope: policy.route_scope(),
                change_kind: IdentityPolicyUpdatedPayloadChangeKind::Updated,
                version: next,
            })
            .await?;
        self.lifecycle
            .update_and_emit(receipt, tenant_scope, policy, draft.expected, event)
            .await
            .map_err(map_identity_error)
    }

    #[tracing::instrument(
        skip_all,
        fields(domain = POLICY_DOMAIN, operation = "policy_deactivate", tenant_id = %tenant),
        err(level = "warn")
    )]
    pub async fn deactivate_policy(
        &self,
        receipt: PoliciesDeactivateProducerReceipt,
        tenant: TenantId,
        actor: ids::UserId,
        actor_kind: vocab::PrincipalKind,
        draft: PolicyDeactivateDraft,
    ) -> Result<PolicyVersion, PolicyManageError> {
        let tenant_scope = TenantRepoScope::from_authenticated_tenant(tenant);
        let current = self
            .policies
            .find(tenant_scope, draft.id.clone())
            .await
            .map_err(map_identity_error)?
            .ok_or(PolicyManageError::PolicyNotFound)?;
        if current.version() != draft.expected {
            return Err(PolicyManageError::VersionConflict);
        }
        let next = draft
            .expected
            .next_checked()
            .map_err(|_| PolicyManageError::VersionConflict)?;
        let event = self
            .event_parts(PolicyEventDraft {
                tenant,
                actor,
                actor_kind,
                policy_id: current.id(),
                scope: current.route_scope(),
                change_kind: IdentityPolicyUpdatedPayloadChangeKind::Deactivated,
                version: next,
            })
            .await?;
        match self
            .lifecycle
            .deactivate_and_emit(receipt, tenant_scope, draft.id, draft.expected, event)
            .await
            .map_err(map_identity_error)?
        {
            true => Ok(next),
            false => Err(PolicyManageError::PolicyNotFound),
        }
    }

    async fn event_parts(
        &self,
        draft: PolicyEventDraft<'_>,
    ) -> Result<ReviewedEvent, PolicyManageError> {
        let PolicyEventDraft {
            tenant,
            actor,
            actor_kind,
            policy_id,
            scope,
            change_kind,
            version,
        } = draft;
        let payload = IdentityPolicyUpdatedPayload {
            policy_id: policy_id.as_str().to_string(),
            change_kind,
            version: NonZeroU32::new(version.get()).ok_or(PolicyManageError::WireProjection(
                EventWireProjectionError::Version,
            ))?,
            contract_id: scope.contract_id().to_string(),
            permission: scope.permission().as_str().to_string(),
            updated_by: actor.as_uuid(),
            actor_kind: actor_kind_wire(actor_kind)?,
            tenant_id: tenant.to_string(),
            occurred_at: unix_secs(self.clock.now()),
        };
        // #1235 / #648 F1：canonical UserId typed funnel（actor = 策略变更操作者，非 login/PII）。
        crate::outbox_emit::emit_policy_updated(
            payload,
            tenant,
            actor,
            actor_kind,
            IdemKey::parse(&Uuid::new_v4().to_string())
                .map_err(PolicyManageError::IdempotencyKey)?,
        )
        .await
        .map_err(PolicyManageError::EventEncode)
    }
}

pub fn policy_id_from_wire(raw: &str) -> Result<PolicyId, PolicyManageError> {
    PolicyId::parse(raw).map_err(|_| PolicyManageError::InvalidPolicy)
}

pub fn create_response(
    policy: &Policy,
) -> Result<IdentityPoliciesCreateResponse, PolicyManageError> {
    Ok(IdentityPoliciesCreateResponse {
        data: create_policy_view(WirePolicyView::from_policy(policy)?)?,
    })
}

pub fn update_response(
    policy: &Policy,
) -> Result<IdentityPoliciesUpdateResponse, PolicyManageError> {
    Ok(IdentityPoliciesUpdateResponse {
        data: update_policy_view(WirePolicyView::from_policy(policy)?)?,
    })
}

pub fn deactivate_response(
    version: PolicyVersion,
) -> Result<IdentityPoliciesDeactivateResponse, PolicyManageError> {
    Ok(IdentityPoliciesDeactivateResponse {
        data: generated::http::identity_v1::policies_deactivate::IdentityPoliciesDeactivateData {
            deactivated: true,
            version: NonZeroU32::new(version.get()).ok_or(PolicyManageError::WireProjection(
                EventWireProjectionError::Version,
            ))?,
        },
    })
}

pub fn get_response(policy: &Policy) -> Result<IdentityPoliciesGetResponse, PolicyManageError> {
    Ok(IdentityPoliciesGetResponse {
        data: get_policy_view(WirePolicyView::from_policy(policy)?)?,
    })
}

pub fn list_response(
    policies: Vec<Policy>,
    has_more: bool,
    next_cursor: Option<String>,
) -> Result<IdentityPoliciesListResponse, PolicyManageError> {
    let data = policies
        .iter()
        .map(|policy| WirePolicyView::from_policy(policy).and_then(list_policy_view))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(IdentityPoliciesListResponse {
        data,
        has_more,
        next_cursor,
    })
}

fn map_identity_error(err: IdentityError) -> PolicyManageError {
    match err {
        // Hydrate / store 毒化（含超长 attribute value）→ Store/Internal，不得映射为 Validation。
        IdentityError::InvalidPolicy => PolicyManageError::Store(IdentityError::InvalidPolicy),
        IdentityError::PolicyNotFound => PolicyManageError::PolicyNotFound,
        IdentityError::PolicyAlreadyExists => PolicyManageError::PolicyAlreadyExists,
        IdentityError::VersionConflict => PolicyManageError::VersionConflict,
        IdentityError::OutboxFactConflict(source) => PolicyManageError::OutboxFactConflict(source),
        other => PolicyManageError::Store(other),
    }
}

fn actor_kind_wire(
    kind: vocab::PrincipalKind,
) -> Result<IdentityPolicyUpdatedPayloadActorKind, PolicyManageError> {
    match kind {
        vocab::PrincipalKind::User => Ok(IdentityPolicyUpdatedPayloadActorKind::User),
        vocab::PrincipalKind::Device => Ok(IdentityPolicyUpdatedPayloadActorKind::Device),
        vocab::PrincipalKind::Admin => Ok(IdentityPolicyUpdatedPayloadActorKind::Admin),
        vocab::PrincipalKind::SuperAdmin => Ok(IdentityPolicyUpdatedPayloadActorKind::SuperAdmin),
        vocab::PrincipalKind::Service => Ok(IdentityPolicyUpdatedPayloadActorKind::Service),
        vocab::PrincipalKind::Anonymous => Ok(IdentityPolicyUpdatedPayloadActorKind::Anonymous),
        _ => Err(PolicyManageError::WireProjection(
            EventWireProjectionError::PrincipalKind,
        )),
    }
}

fn wire_time(raw: i64) -> Result<SystemTime, PolicyManageError> {
    let secs = u64::try_from(raw).map_err(|_| PolicyManageError::InvalidPolicy)?;
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(secs))
        .ok_or(PolicyManageError::InvalidPolicy)
}

fn reject_global_resource_policy(
    scope: &PolicyRouteScope,
    rules: &[PolicyRule],
    specs: &[HttpSpec],
) -> Result<(), PolicyManageError> {
    if route_scope_is_global_resource_in(scope, specs)
        && rules_use_dynamic_resource_attributes(rules)?
    {
        return Err(PolicyManageError::InvalidPolicy);
    }
    Ok(())
}

fn route_scope_is_global_resource_in(scope: &PolicyRouteScope, specs: &[HttpSpec]) -> bool {
    specs.iter().any(|spec| {
        spec.route.contract_id() == scope.contract_id()
            && spec.route.auth() == HttpRouteAuth::Permission(scope.permission())
            && spec.resource_sharing.mode == HttpResourceSharingMode::Global
    })
}

fn rules_use_dynamic_resource_attributes(rules: &[PolicyRule]) -> Result<bool, PolicyManageError> {
    for rule in rules {
        if policy_attribute_key_is_dynamic_resource(rule.attribute_key())? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn policy_attribute_key_is_dynamic_resource(key: &AttributeKey) -> Result<bool, PolicyManageError> {
    ResourcePolicyAttributeKey::classify(key)
        .map(|classified| classified.is_dynamic())
        .map_err(|_| PolicyManageError::InvalidPolicy)
}

fn typed_rules_from_wire(
    rules: impl IntoIterator<Item = Result<WireRule, PolicyManageError>>,
) -> Result<Vec<PolicyRule>, PolicyManageError> {
    let rules = rules.into_iter().collect::<Result<Vec<_>, _>>()?;
    if rules.is_empty() {
        return Err(PolicyManageError::InvalidPolicy);
    }
    rules.into_iter().map(WireRule::into_rule).collect()
}

fn create_rules_from_wire(
    rules: Vec<create_wire::IdentityPolicyCreateRule>,
) -> Result<Vec<PolicyRule>, PolicyManageError> {
    typed_rules_from_wire(rules.into_iter().map(create_rule_from_wire))
}

fn update_rules_from_wire(
    rules: Vec<update_wire::IdentityPolicyUpdateRule>,
) -> Result<Vec<PolicyRule>, PolicyManageError> {
    typed_rules_from_wire(rules.into_iter().map(update_rule_from_wire))
}

fn create_rule_from_wire(
    rule: create_wire::IdentityPolicyCreateRule,
) -> Result<WireRule, PolicyManageError> {
    Ok(WireRule {
        condition: WireCondition {
            attribute: rule.condition.attribute,
            operator: create_operator_from_wire(rule.condition.operator)?,
        },
        effect: match rule.effect {
            create_wire::IdentityPolicyCreateRuleEffect::Allow => WireEffect::Allow,
            create_wire::IdentityPolicyCreateRuleEffect::Deny => WireEffect::Deny,
        },
        obligations: rule.obligations.map(|value| WireObligations {
            row_scope: value.row_scope.map(|scope| match scope {
                create_wire::IdentityPolicyCreateObligationsRowScope::SelfOnly => {
                    WireRowScope::SelfOnly
                }
                create_wire::IdentityPolicyCreateObligationsRowScope::Device => {
                    WireRowScope::Device
                }
                create_wire::IdentityPolicyCreateObligationsRowScope::Tenant => {
                    WireRowScope::Tenant
                }
            }),
            field_mask: value.field_mask,
        }),
    })
}

fn update_rule_from_wire(
    rule: update_wire::IdentityPolicyUpdateRule,
) -> Result<WireRule, PolicyManageError> {
    Ok(WireRule {
        condition: WireCondition {
            attribute: rule.condition.attribute,
            operator: update_operator_from_wire(rule.condition.operator)?,
        },
        effect: match rule.effect {
            update_wire::IdentityPolicyUpdateRuleEffect::Allow => WireEffect::Allow,
            update_wire::IdentityPolicyUpdateRuleEffect::Deny => WireEffect::Deny,
        },
        obligations: rule.obligations.map(|value| WireObligations {
            row_scope: value.row_scope.map(|scope| match scope {
                update_wire::IdentityPolicyUpdateObligationsRowScope::SelfOnly => {
                    WireRowScope::SelfOnly
                }
                update_wire::IdentityPolicyUpdateObligationsRowScope::Device => {
                    WireRowScope::Device
                }
                update_wire::IdentityPolicyUpdateObligationsRowScope::Tenant => {
                    WireRowScope::Tenant
                }
            }),
            field_mask: value.field_mask,
        }),
    })
}

fn create_attribute_name(
    value: create_wire::IdentityPolicyCreateOperatorAttributeOperandAttribute,
) -> &'static str {
    match value {
        create_wire::IdentityPolicyCreateOperatorAttributeOperandAttribute::PrincipalKind => {
            "principal.kind"
        }
        create_wire::IdentityPolicyCreateOperatorAttributeOperandAttribute::PrincipalId => {
            "principal.id"
        }
        create_wire::IdentityPolicyCreateOperatorAttributeOperandAttribute::TenantId => "tenant.id",
        create_wire::IdentityPolicyCreateOperatorAttributeOperandAttribute::ContractId => {
            "contract.id"
        }
        create_wire::IdentityPolicyCreateOperatorAttributeOperandAttribute::Permission => {
            "permission"
        }
        create_wire::IdentityPolicyCreateOperatorAttributeOperandAttribute::ResourceId => {
            "resource.id"
        }
    }
}

fn update_attribute_name(
    value: update_wire::IdentityPolicyUpdateOperatorAttributeOperandAttribute,
) -> &'static str {
    match value {
        update_wire::IdentityPolicyUpdateOperatorAttributeOperandAttribute::PrincipalKind => {
            "principal.kind"
        }
        update_wire::IdentityPolicyUpdateOperatorAttributeOperandAttribute::PrincipalId => {
            "principal.id"
        }
        update_wire::IdentityPolicyUpdateOperatorAttributeOperandAttribute::TenantId => "tenant.id",
        update_wire::IdentityPolicyUpdateOperatorAttributeOperandAttribute::ContractId => {
            "contract.id"
        }
        update_wire::IdentityPolicyUpdateOperatorAttributeOperandAttribute::Permission => {
            "permission"
        }
        update_wire::IdentityPolicyUpdateOperatorAttributeOperandAttribute::ResourceId => {
            "resource.id"
        }
    }
}

fn create_operator_from_wire(
    operator: create_wire::IdentityPolicyCreateOperator,
) -> Result<WireOperator, PolicyManageError> {
    use create_wire::IdentityPolicyCreateOperator as O;
    Ok(match operator {
        O::EqualityFamily(value) => WireOperator::Equality {
            predicate: match value.predicate {
                create_wire::IdentityPolicyCreateOperatorEqualityFamilyPredicate::Eq => {
                    WireEqualityPredicate::Eq
                }
                create_wire::IdentityPolicyCreateOperatorEqualityFamilyPredicate::Ne => {
                    WireEqualityPredicate::Ne
                }
            },
            operand: match value.operand {
                create_wire::IdentityPolicyCreateOperatorEqualityFamilyOperand::LiteralOperand(
                    operand,
                ) => match operand {
                    create_wire::IdentityPolicyCreateOperatorLiteralOperand::String { value, .. } => WireScalarOperand::Literal { value_type: WireValueType::String, value: serde_json::Value::String(value.into()) },
                    create_wire::IdentityPolicyCreateOperatorLiteralOperand::Boolean { value, .. } => WireScalarOperand::Literal { value_type: WireValueType::Boolean, value: serde_json::Value::Bool(value) },
                    create_wire::IdentityPolicyCreateOperatorLiteralOperand::Integer { value, .. } => WireScalarOperand::Literal { value_type: WireValueType::Integer, value: value.into() },
                    create_wire::IdentityPolicyCreateOperatorLiteralOperand::Decimal { value, .. } => WireScalarOperand::Literal { value_type: WireValueType::Decimal, value: serde_json::Value::String(value.into()) },
                },
                create_wire::IdentityPolicyCreateOperatorEqualityFamilyOperand::AttributeOperand(
                    create_wire::IdentityPolicyCreateOperatorAttributeOperand::Attribute { attribute, .. },
                ) => WireScalarOperand::Attribute { value_type: WireValueType::String, attribute: create_attribute_name(attribute).to_string() },
            },
        },
        O::OrderingFamily(value) => WireOperator::Ordering {
            predicate: match value.predicate {
                create_wire::IdentityPolicyCreateOperatorOrderingFamilyPredicate::Gt => WireOrderingPredicate::Gt,
                create_wire::IdentityPolicyCreateOperatorOrderingFamilyPredicate::Ge => WireOrderingPredicate::Ge,
                create_wire::IdentityPolicyCreateOperatorOrderingFamilyPredicate::Lt => WireOrderingPredicate::Lt,
                create_wire::IdentityPolicyCreateOperatorOrderingFamilyPredicate::Le => WireOrderingPredicate::Le,
            },
            operand: match value.operand {
                create_wire::IdentityPolicyCreateOperatorNumericLiteralOperand::Integer { value, .. } => WireScalarOperand::Literal { value_type: WireValueType::Integer, value: value.into() },
                create_wire::IdentityPolicyCreateOperatorNumericLiteralOperand::Decimal { value, .. } => WireScalarOperand::Literal { value_type: WireValueType::Decimal, value: serde_json::Value::String(value.into()) },
            },
        },
        O::MembershipFamily(value) => WireOperator::Membership {
            predicate: match value.predicate {
                create_wire::IdentityPolicyCreateOperatorMembershipFamilyPredicate::In => WireMembershipPredicate::In,
                create_wire::IdentityPolicyCreateOperatorMembershipFamilyPredicate::NotIn => WireMembershipPredicate::NotIn,
            },
            operand: match value.operand {
                create_wire::IdentityPolicyCreateOperatorSetOperand::String { values, .. } => WireSetOperand { kind: WireSetKind::Set, value_type: WireValueType::String, values: values.into_iter().map(|value| serde_json::Value::String(value.into())).collect() },
                create_wire::IdentityPolicyCreateOperatorSetOperand::Boolean { values, .. } => WireSetOperand { kind: WireSetKind::Set, value_type: WireValueType::Boolean, values: values.into_iter().map(serde_json::Value::Bool).collect() },
                create_wire::IdentityPolicyCreateOperatorSetOperand::Integer { values, .. } => WireSetOperand { kind: WireSetKind::Set, value_type: WireValueType::Integer, values: values.into_iter().map(Into::into).collect() },
                create_wire::IdentityPolicyCreateOperatorSetOperand::Decimal { values, .. } => WireSetOperand { kind: WireSetKind::Set, value_type: WireValueType::Decimal, values: values.into_iter().map(|value| serde_json::Value::String(value.into())).collect() },
            },
        },
        O::StringFamily(value) => WireOperator::String {
            predicate: match value.predicate {
                create_wire::IdentityPolicyCreateOperatorStringFamilyPredicate::StartsWith => WireStringPredicate::StartsWith,
                create_wire::IdentityPolicyCreateOperatorStringFamilyPredicate::EndsWith => WireStringPredicate::EndsWith,
                create_wire::IdentityPolicyCreateOperatorStringFamilyPredicate::Contains => WireStringPredicate::Contains,
                create_wire::IdentityPolicyCreateOperatorStringFamilyPredicate::Glob => WireStringPredicate::Glob,
                create_wire::IdentityPolicyCreateOperatorStringFamilyPredicate::Regex => WireStringPredicate::Regex,
            },
            operand: WirePatternOperand { kind: WirePatternKind::Pattern, value_type: WireStringType::String, value: value.operand.value.into() },
        },
    })
}

fn update_operator_from_wire(
    operator: update_wire::IdentityPolicyUpdateOperator,
) -> Result<WireOperator, PolicyManageError> {
    let json = match operator {
        update_wire::IdentityPolicyUpdateOperator::EqualityFamily(value) => {
            let predicate = match value.predicate {
                update_wire::IdentityPolicyUpdateOperatorEqualityFamilyPredicate::Eq => {
                    WireEqualityPredicate::Eq
                }
                update_wire::IdentityPolicyUpdateOperatorEqualityFamilyPredicate::Ne => {
                    WireEqualityPredicate::Ne
                }
            };
            let operand = match value.operand {
                update_wire::IdentityPolicyUpdateOperatorEqualityFamilyOperand::LiteralOperand(operand) => match operand {
                    update_wire::IdentityPolicyUpdateOperatorLiteralOperand::String { value, .. } => WireScalarOperand::Literal { value_type: WireValueType::String, value: serde_json::Value::String(value.into()) },
                    update_wire::IdentityPolicyUpdateOperatorLiteralOperand::Boolean { value, .. } => WireScalarOperand::Literal { value_type: WireValueType::Boolean, value: serde_json::Value::Bool(value) },
                    update_wire::IdentityPolicyUpdateOperatorLiteralOperand::Integer { value, .. } => WireScalarOperand::Literal { value_type: WireValueType::Integer, value: value.into() },
                    update_wire::IdentityPolicyUpdateOperatorLiteralOperand::Decimal { value, .. } => WireScalarOperand::Literal { value_type: WireValueType::Decimal, value: serde_json::Value::String(value.into()) },
                },
                update_wire::IdentityPolicyUpdateOperatorEqualityFamilyOperand::AttributeOperand(update_wire::IdentityPolicyUpdateOperatorAttributeOperand::Attribute { attribute, .. }) => WireScalarOperand::Attribute { value_type: WireValueType::String, attribute: update_attribute_name(attribute).to_string() },
            };
            WireOperator::Equality { predicate, operand }
        }
        update_wire::IdentityPolicyUpdateOperator::OrderingFamily(value) => {
            WireOperator::Ordering {
                predicate: match value.predicate {
                    update_wire::IdentityPolicyUpdateOperatorOrderingFamilyPredicate::Gt => {
                        WireOrderingPredicate::Gt
                    }
                    update_wire::IdentityPolicyUpdateOperatorOrderingFamilyPredicate::Ge => {
                        WireOrderingPredicate::Ge
                    }
                    update_wire::IdentityPolicyUpdateOperatorOrderingFamilyPredicate::Lt => {
                        WireOrderingPredicate::Lt
                    }
                    update_wire::IdentityPolicyUpdateOperatorOrderingFamilyPredicate::Le => {
                        WireOrderingPredicate::Le
                    }
                },
                operand: match value.operand {
                    update_wire::IdentityPolicyUpdateOperatorNumericLiteralOperand::Integer {
                        value,
                        ..
                    } => WireScalarOperand::Literal {
                        value_type: WireValueType::Integer,
                        value: value.into(),
                    },
                    update_wire::IdentityPolicyUpdateOperatorNumericLiteralOperand::Decimal {
                        value,
                        ..
                    } => WireScalarOperand::Literal {
                        value_type: WireValueType::Decimal,
                        value: serde_json::Value::String(value.into()),
                    },
                },
            }
        }
        update_wire::IdentityPolicyUpdateOperator::MembershipFamily(value) => {
            WireOperator::Membership {
                predicate: match value.predicate {
                    update_wire::IdentityPolicyUpdateOperatorMembershipFamilyPredicate::In => {
                        WireMembershipPredicate::In
                    }
                    update_wire::IdentityPolicyUpdateOperatorMembershipFamilyPredicate::NotIn => {
                        WireMembershipPredicate::NotIn
                    }
                },
                operand: match value.operand {
                    update_wire::IdentityPolicyUpdateOperatorSetOperand::String {
                        values, ..
                    } => WireSetOperand {
                        kind: WireSetKind::Set,
                        value_type: WireValueType::String,
                        values: values
                            .into_iter()
                            .map(|value| serde_json::Value::String(value.into()))
                            .collect(),
                    },
                    update_wire::IdentityPolicyUpdateOperatorSetOperand::Boolean {
                        values, ..
                    } => WireSetOperand {
                        kind: WireSetKind::Set,
                        value_type: WireValueType::Boolean,
                        values: values.into_iter().map(serde_json::Value::Bool).collect(),
                    },
                    update_wire::IdentityPolicyUpdateOperatorSetOperand::Integer {
                        values, ..
                    } => WireSetOperand {
                        kind: WireSetKind::Set,
                        value_type: WireValueType::Integer,
                        values: values.into_iter().map(Into::into).collect(),
                    },
                    update_wire::IdentityPolicyUpdateOperatorSetOperand::Decimal {
                        values, ..
                    } => WireSetOperand {
                        kind: WireSetKind::Set,
                        value_type: WireValueType::Decimal,
                        values: values
                            .into_iter()
                            .map(|value| serde_json::Value::String(value.into()))
                            .collect(),
                    },
                },
            }
        }
        update_wire::IdentityPolicyUpdateOperator::StringFamily(value) => WireOperator::String {
            predicate: match value.predicate {
                update_wire::IdentityPolicyUpdateOperatorStringFamilyPredicate::StartsWith => {
                    WireStringPredicate::StartsWith
                }
                update_wire::IdentityPolicyUpdateOperatorStringFamilyPredicate::EndsWith => {
                    WireStringPredicate::EndsWith
                }
                update_wire::IdentityPolicyUpdateOperatorStringFamilyPredicate::Contains => {
                    WireStringPredicate::Contains
                }
                update_wire::IdentityPolicyUpdateOperatorStringFamilyPredicate::Glob => {
                    WireStringPredicate::Glob
                }
                update_wire::IdentityPolicyUpdateOperatorStringFamilyPredicate::Regex => {
                    WireStringPredicate::Regex
                }
            },
            operand: WirePatternOperand {
                kind: WirePatternKind::Pattern,
                value_type: WireStringType::String,
                value: value.operand.value.into(),
            },
        },
    };
    Ok(json)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireRule {
    condition: WireCondition,
    effect: WireEffect,
    #[serde(default)]
    obligations: Option<WireObligations>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireCondition {
    attribute: String,
    operator: WireOperator,
}

#[derive(Deserialize, Serialize)]
#[serde(
    tag = "family",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum WireOperator {
    Equality {
        predicate: WireEqualityPredicate,
        operand: WireScalarOperand,
    },
    Ordering {
        predicate: WireOrderingPredicate,
        operand: WireScalarOperand,
    },
    Membership {
        predicate: WireMembershipPredicate,
        operand: WireSetOperand,
    },
    String {
        predicate: WireStringPredicate,
        operand: WirePatternOperand,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum WireEqualityPredicate {
    Eq,
    Ne,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum WireOrderingPredicate {
    Gt,
    Ge,
    Lt,
    Le,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum WireMembershipPredicate {
    In,
    NotIn,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum WireStringPredicate {
    StartsWith,
    EndsWith,
    Contains,
    Glob,
    Regex,
}

#[derive(Deserialize, Serialize, Clone, Copy)]
#[serde(rename_all = "camelCase")]
enum WireValueType {
    String,
    Boolean,
    Integer,
    Decimal,
}

#[derive(Deserialize, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum WireScalarOperand {
    Literal {
        value_type: WireValueType,
        value: serde_json::Value,
    },
    Attribute {
        value_type: WireValueType,
        attribute: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireSetOperand {
    kind: WireSetKind,
    value_type: WireValueType,
    values: Vec<serde_json::Value>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum WireSetKind {
    Set,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WirePatternOperand {
    kind: WirePatternKind,
    value_type: WireStringType,
    value: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum WirePatternKind {
    Pattern,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum WireStringType {
    String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum WireEffect {
    Allow,
    Deny,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireObligations {
    row_scope: Option<WireRowScope>,
    #[serde(default)]
    field_mask: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum WireRowScope {
    SelfOnly,
    Device,
    Tenant,
}

impl WireRule {
    fn into_rule(self) -> Result<PolicyRule, PolicyManageError> {
        let condition = PolicyCondition::new(
            AttributeKey::parse(&self.condition.attribute)
                .map_err(|_| PolicyManageError::InvalidPolicy)?,
            self.condition.operator.into_operator()?,
        );
        let effect = match self.effect {
            WireEffect::Allow => PolicyEffect::Allow,
            WireEffect::Deny => PolicyEffect::Deny,
        };
        let obligations = self
            .obligations
            .map(WireObligations::into_obligations)
            .transpose()?
            .unwrap_or_else(PolicyObligations::empty);
        Ok(PolicyRule::with_obligations(condition, effect, obligations))
    }
}

impl WireOperator {
    fn into_operator(self) -> Result<Operator, PolicyManageError> {
        match self {
            Self::Equality { predicate, operand } => Ok(Operator::Equality(EqualityOperator::new(
                match predicate {
                    WireEqualityPredicate::Eq => EqualityPredicate::Eq,
                    WireEqualityPredicate::Ne => EqualityPredicate::Ne,
                },
                operand.into_equality()?,
            ))),
            Self::Ordering { predicate, operand } => Ok(Operator::Ordering(OrderingOperator::new(
                match predicate {
                    WireOrderingPredicate::Gt => OrderingPredicate::Gt,
                    WireOrderingPredicate::Ge => OrderingPredicate::Ge,
                    WireOrderingPredicate::Lt => OrderingPredicate::Lt,
                    WireOrderingPredicate::Le => OrderingPredicate::Le,
                },
                operand.into_ordering()?,
            ))),
            Self::Membership { predicate, operand } => {
                Ok(Operator::Membership(MembershipOperator::new(
                    match predicate {
                        WireMembershipPredicate::In => MembershipPredicate::In,
                        WireMembershipPredicate::NotIn => MembershipPredicate::NotIn,
                    },
                    PolicyValueSet::new(operand.into_values()?).map_err(|error| {
                        PolicyManageError::InvalidOperator(operator_reason(error))
                    })?,
                )))
            }
            Self::String { predicate, operand } => Ok(Operator::StringMatch(
                StringOperator::parse(
                    match predicate {
                        WireStringPredicate::StartsWith => StringPredicate::StartsWith,
                        WireStringPredicate::EndsWith => StringPredicate::EndsWith,
                        WireStringPredicate::Contains => StringPredicate::Contains,
                        WireStringPredicate::Glob => StringPredicate::Glob,
                        WireStringPredicate::Regex => StringPredicate::Regex,
                    },
                    &operand.value,
                )
                .map_err(|error| PolicyManageError::InvalidOperator(operator_reason(error)))?,
            )),
        }
    }
}

impl WireScalarOperand {
    fn into_equality(self) -> Result<EqualityOperand, PolicyManageError> {
        match self {
            Self::Literal { value_type, value } => Ok(EqualityOperand::Literal(parse_wire_value(
                value_type, value,
            )?)),
            Self::Attribute {
                value_type,
                attribute,
            } => {
                if !matches!(value_type, WireValueType::String) {
                    return Err(PolicyManageError::InvalidOperator(
                        PolicyOperatorReason::InvalidOperatorCombination,
                    ));
                }
                Ok(EqualityOperand::Attribute(TypedAttributeOperand::new(
                    PipAttributeKey::parse(&attribute)
                        .map_err(|_| PolicyManageError::InvalidPolicy)?,
                )))
            }
        }
    }

    fn into_ordering(self) -> Result<OrderingOperand, PolicyManageError> {
        match self {
            Self::Literal { value_type, value } => {
                NumericValue::from_policy_value(parse_wire_value(value_type, value)?)
                    .map(OrderingOperand::literal)
                    .ok_or(PolicyManageError::InvalidOperator(
                        PolicyOperatorReason::InvalidOperatorCombination,
                    ))
            }
            Self::Attribute { .. } => Err(PolicyManageError::InvalidOperator(
                PolicyOperatorReason::InvalidOperatorCombination,
            )),
        }
    }
}

impl WireSetOperand {
    fn into_values(self) -> Result<Vec<PolicyValue>, PolicyManageError> {
        if !matches!(self.kind, WireSetKind::Set) {
            return Err(PolicyManageError::InvalidPolicy);
        }
        self.values
            .into_iter()
            .map(|value| parse_wire_value(self.value_type, value))
            .collect()
    }
}

fn parse_wire_value(
    value_type: WireValueType,
    value: serde_json::Value,
) -> Result<PolicyValue, PolicyManageError> {
    match value_type {
        WireValueType::String => value
            .as_str()
            .ok_or(PolicyManageError::InvalidPolicy)
            .and_then(|value| {
                PolicyValue::string(value).map_err(|_| PolicyManageError::PolicyValueTooLong)
            }),
        WireValueType::Boolean => value
            .as_bool()
            .map(PolicyValue::boolean)
            .ok_or(PolicyManageError::InvalidPolicy),
        WireValueType::Integer => value
            .as_i64()
            .map(PolicyValue::integer)
            .ok_or(PolicyManageError::InvalidPolicy),
        WireValueType::Decimal => value
            .as_str()
            .ok_or(PolicyManageError::InvalidPolicy)
            .and_then(|value| {
                PolicyValue::decimal(value).map_err(|_| {
                    PolicyManageError::InvalidOperator(PolicyOperatorReason::InvalidDecimal)
                })
            }),
    }
}

impl WireObligations {
    fn into_obligations(self) -> Result<PolicyObligations, PolicyManageError> {
        let row_scope = self.row_scope.map(WireRowScope::into_scoped).transpose()?;
        let field_mask = self
            .field_mask
            .into_iter()
            .map(|key| AttributeKey::parse(&key).map_err(|_| PolicyManageError::InvalidPolicy))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PolicyObligations::new(row_scope, field_mask))
    }
}

impl WireRowScope {
    fn into_scoped(self) -> Result<vocab::ScopedTenant, PolicyManageError> {
        Ok(match self {
            Self::SelfOnly => vocab::ScopedTenant::SelfOnly,
            Self::Device => vocab::ScopedTenant::Device,
            Self::Tenant => vocab::ScopedTenant::Tenant,
        })
    }

    fn from_scoped(scope: vocab::ScopedTenant) -> Result<Self, PolicyManageError> {
        match scope {
            vocab::ScopedTenant::SelfOnly => Ok(Self::SelfOnly),
            vocab::ScopedTenant::Device => Ok(Self::Device),
            vocab::ScopedTenant::Tenant => Ok(Self::Tenant),
            _ => Err(PolicyManageError::InvalidPolicy),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WirePolicyView {
    policy_id: String,
    version: u32,
    contract_id: String,
    permission: String,
    effective_from: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    effective_until: Option<i64>,
    rules: Vec<WireRuleView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WireRuleView {
    condition: WireConditionView,
    effect: WireEffect,
    #[serde(skip_serializing_if = "Option::is_none")]
    obligations: Option<WireObligationsView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WireConditionView {
    attribute: String,
    operator: WireOperator,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WireObligationsView {
    #[serde(skip_serializing_if = "Option::is_none")]
    row_scope: Option<WireRowScope>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    field_mask: Vec<String>,
}

macro_rules! define_typed_policy_view_projection {
    ($view_fn:ident, $operator_fn:ident, $module:ident) => {
        fn $view_fn(
            view: WirePolicyView,
        ) -> Result<$module::IdentityPolicyView, PolicyManageError> {
            Ok($module::IdentityPolicyView {
                policy_id: view.policy_id,
                version: NonZeroU32::new(view.version)
                    .ok_or(PolicyManageError::InvalidPolicy)?,
                contract_id: view.contract_id,
                permission: view.permission,
                effective_from: view.effective_from,
                effective_until: view.effective_until,
                rules: view
                    .rules
                    .into_iter()
                    .map(|rule| {
                        Ok($module::IdentityPolicyRuleView {
                            condition: $module::IdentityPolicyConditionView {
                                attribute: rule.condition.attribute,
                                operator: $operator_fn(rule.condition.operator)?,
                            },
                            effect: match rule.effect {
                                WireEffect::Allow => $module::IdentityPolicyRuleViewEffect::Allow,
                                WireEffect::Deny => $module::IdentityPolicyRuleViewEffect::Deny,
                            },
                            obligations: rule.obligations.map(|obligations| {
                                $module::IdentityPolicyObligationsView {
                                    row_scope: obligations.row_scope.map(|scope| match scope {
                                        WireRowScope::SelfOnly => $module::IdentityPolicyObligationsViewRowScope::SelfOnly,
                                        WireRowScope::Device => $module::IdentityPolicyObligationsViewRowScope::Device,
                                        WireRowScope::Tenant => $module::IdentityPolicyObligationsViewRowScope::Tenant,
                                    }),
                                    field_mask: obligations.field_mask,
                                }
                            }),
                        })
                    })
                    .collect::<Result<Vec<_>, PolicyManageError>>()?,
            })
        }

        fn $operator_fn(
            operator: WireOperator,
        ) -> Result<$module::IdentityPolicyOperatorView, PolicyManageError> {
            let invalid = |_| PolicyManageError::InvalidPolicy;
            Ok(match operator {
                WireOperator::Equality { predicate, operand } => {
                    let operand = match operand {
                        WireScalarOperand::Literal { value_type, value } => {
                            let kind = $module::IdentityPolicyOperatorViewLiteralOperandKind::Literal;
                            let value = match value_type {
                                WireValueType::String => $module::IdentityPolicyOperatorViewLiteralOperand::String {
                                    kind,
                                    value: $module::IdentityPolicyOperatorViewLiteralOperandValue::try_from(value.as_str().ok_or(PolicyManageError::InvalidPolicy)?.to_string()).map_err(invalid)?,
                                },
                                WireValueType::Boolean => $module::IdentityPolicyOperatorViewLiteralOperand::Boolean {
                                    kind,
                                    value: value.as_bool().ok_or(PolicyManageError::InvalidPolicy)?,
                                },
                                WireValueType::Integer => $module::IdentityPolicyOperatorViewLiteralOperand::Integer {
                                    kind,
                                    value: value.as_i64().ok_or(PolicyManageError::InvalidPolicy)?,
                                },
                                WireValueType::Decimal => $module::IdentityPolicyOperatorViewLiteralOperand::Decimal {
                                    kind,
                                    value: $module::IdentityPolicyOperatorViewLiteralOperandValue::try_from(value.as_str().ok_or(PolicyManageError::InvalidPolicy)?.to_string()).map_err(invalid)?,
                                },
                            };
                            $module::IdentityPolicyOperatorViewEqualityFamilyOperand::LiteralOperand(value)
                        }
                        WireScalarOperand::Attribute { value_type: WireValueType::String, attribute } => {
                            let attribute = $module::IdentityPolicyOperatorViewAttributeOperandAttribute::try_from(attribute.as_str()).map_err(invalid)?;
                            $module::IdentityPolicyOperatorViewEqualityFamilyOperand::AttributeOperand(
                                $module::IdentityPolicyOperatorViewAttributeOperand::Attribute {
                                    attribute,
                                    value_type: $module::IdentityPolicyOperatorViewAttributeOperandValueType::String,
                                },
                            )
                        }
                        WireScalarOperand::Attribute { .. } => return Err(PolicyManageError::InvalidPolicy),
                    };
                    $module::IdentityPolicyOperatorView::EqualityFamily(
                        $module::IdentityPolicyOperatorViewEqualityFamily {
                            family: $module::IdentityPolicyOperatorViewEqualityFamilyFamily::Equality,
                            predicate: match predicate {
                                WireEqualityPredicate::Eq => $module::IdentityPolicyOperatorViewEqualityFamilyPredicate::Eq,
                                WireEqualityPredicate::Ne => $module::IdentityPolicyOperatorViewEqualityFamilyPredicate::Ne,
                            },
                            operand,
                        },
                    )
                }
                WireOperator::Ordering { predicate, operand } => {
                    let WireScalarOperand::Literal { value_type, value } = operand else {
                        return Err(PolicyManageError::InvalidPolicy);
                    };
                    let kind = $module::IdentityPolicyOperatorViewNumericLiteralOperandKind::Literal;
                    let operand = match value_type {
                        WireValueType::Integer => $module::IdentityPolicyOperatorViewNumericLiteralOperand::Integer {
                            kind,
                            value: value.as_i64().ok_or(PolicyManageError::InvalidPolicy)?,
                        },
                        WireValueType::Decimal => $module::IdentityPolicyOperatorViewNumericLiteralOperand::Decimal {
                            kind,
                            value: $module::IdentityPolicyOperatorViewNumericLiteralOperandValue::try_from(value.as_str().ok_or(PolicyManageError::InvalidPolicy)?.to_string()).map_err(invalid)?,
                        },
                        WireValueType::String | WireValueType::Boolean => return Err(PolicyManageError::InvalidPolicy),
                    };
                    $module::IdentityPolicyOperatorView::OrderingFamily(
                        $module::IdentityPolicyOperatorViewOrderingFamily {
                            family: $module::IdentityPolicyOperatorViewOrderingFamilyFamily::Ordering,
                            predicate: match predicate {
                                WireOrderingPredicate::Gt => $module::IdentityPolicyOperatorViewOrderingFamilyPredicate::Gt,
                                WireOrderingPredicate::Ge => $module::IdentityPolicyOperatorViewOrderingFamilyPredicate::Ge,
                                WireOrderingPredicate::Lt => $module::IdentityPolicyOperatorViewOrderingFamilyPredicate::Lt,
                                WireOrderingPredicate::Le => $module::IdentityPolicyOperatorViewOrderingFamilyPredicate::Le,
                            },
                            operand,
                        },
                    )
                }
                WireOperator::Membership { predicate, operand } => {
                    let kind = $module::IdentityPolicyOperatorViewSetOperandKind::Set;
                    let values = operand.values;
                    let operand = match operand.value_type {
                        WireValueType::String => $module::IdentityPolicyOperatorViewSetOperand::String {
                            kind,
                            values: values.into_iter().map(|value| $module::IdentityPolicyOperatorViewSetOperandValuesItem::try_from(value.as_str().ok_or(PolicyManageError::InvalidPolicy)?.to_string()).map_err(invalid)).collect::<Result<Vec<_>, _>>()?,
                        },
                        WireValueType::Boolean => $module::IdentityPolicyOperatorViewSetOperand::Boolean {
                            kind,
                            values: values.into_iter().map(|value| value.as_bool().ok_or(PolicyManageError::InvalidPolicy)).collect::<Result<Vec<_>, _>>()?,
                        },
                        WireValueType::Integer => $module::IdentityPolicyOperatorViewSetOperand::Integer {
                            kind,
                            values: values.into_iter().map(|value| value.as_i64().ok_or(PolicyManageError::InvalidPolicy)).collect::<Result<Vec<_>, _>>()?,
                        },
                        WireValueType::Decimal => $module::IdentityPolicyOperatorViewSetOperand::Decimal {
                            kind,
                            values: values.into_iter().map(|value| $module::IdentityPolicyOperatorViewSetOperandValuesItem::try_from(value.as_str().ok_or(PolicyManageError::InvalidPolicy)?.to_string()).map_err(invalid)).collect::<Result<Vec<_>, _>>()?,
                        },
                    };
                    $module::IdentityPolicyOperatorView::MembershipFamily(
                        $module::IdentityPolicyOperatorViewMembershipFamily {
                            family: $module::IdentityPolicyOperatorViewMembershipFamilyFamily::Membership,
                            predicate: match predicate {
                                WireMembershipPredicate::In => $module::IdentityPolicyOperatorViewMembershipFamilyPredicate::In,
                                WireMembershipPredicate::NotIn => $module::IdentityPolicyOperatorViewMembershipFamilyPredicate::NotIn,
                            },
                            operand,
                        },
                    )
                }
                WireOperator::String { predicate, operand } => {
                    $module::IdentityPolicyOperatorView::StringFamily(
                        $module::IdentityPolicyOperatorViewStringFamily {
                            family: $module::IdentityPolicyOperatorViewStringFamilyFamily::String,
                            predicate: match predicate {
                                WireStringPredicate::StartsWith => $module::IdentityPolicyOperatorViewStringFamilyPredicate::StartsWith,
                                WireStringPredicate::EndsWith => $module::IdentityPolicyOperatorViewStringFamilyPredicate::EndsWith,
                                WireStringPredicate::Contains => $module::IdentityPolicyOperatorViewStringFamilyPredicate::Contains,
                                WireStringPredicate::Glob => $module::IdentityPolicyOperatorViewStringFamilyPredicate::Glob,
                                WireStringPredicate::Regex => $module::IdentityPolicyOperatorViewStringFamilyPredicate::Regex,
                            },
                            operand: $module::IdentityPolicyOperatorViewPatternOperand {
                                kind: $module::IdentityPolicyOperatorViewPatternOperandKind::Pattern,
                                value_type: $module::IdentityPolicyOperatorViewPatternOperandValueType::String,
                                value: $module::IdentityPolicyOperatorViewPatternOperandValue::try_from(operand.value).map_err(invalid)?,
                            },
                        },
                    )
                }
            })
        }
    };
}

define_typed_policy_view_projection!(create_policy_view, create_operator_view, create_wire);
define_typed_policy_view_projection!(update_policy_view, update_operator_view, update_wire);
define_typed_policy_view_projection!(get_policy_view, get_operator_view, get_wire);
define_typed_policy_view_projection!(list_policy_view, list_operator_view, list_wire);

impl WirePolicyView {
    fn from_policy(policy: &Policy) -> Result<Self, PolicyManageError> {
        Ok(Self {
            policy_id: policy.id().as_str().to_string(),
            version: policy.version().get(),
            contract_id: policy.route_scope().contract_id().to_string(),
            permission: policy.route_scope().permission().as_str().to_string(),
            effective_from: unix_secs(policy.effective_from()),
            effective_until: policy.effective_until().map(unix_secs),
            rules: policy
                .rules()
                .iter()
                .map(WireRuleView::from_rule)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl WireRuleView {
    fn from_rule(rule: &PolicyRule) -> Result<Self, PolicyManageError> {
        let obligations = WireObligationsView::from_obligations(rule.obligations())?;
        Ok(Self {
            condition: WireConditionView {
                attribute: rule.attribute_key().as_str().to_string(),
                operator: WireOperator::from_operator(rule.operator())?,
            },
            effect: match rule.effect() {
                PolicyEffect::Allow => WireEffect::Allow,
                PolicyEffect::Deny => WireEffect::Deny,
            },
            obligations,
        })
    }
}

impl WireOperator {
    fn from_operator(operator: &Operator) -> Result<Self, PolicyManageError> {
        match operator {
            Operator::Equality(operator) => Ok(Self::Equality {
                predicate: match operator.predicate() {
                    EqualityPredicate::Eq => WireEqualityPredicate::Eq,
                    EqualityPredicate::Ne => WireEqualityPredicate::Ne,
                },
                operand: WireScalarOperand::from_equality(operator.operand()),
            }),
            Operator::Ordering(operator) => Ok(Self::Ordering {
                predicate: match operator.predicate() {
                    OrderingPredicate::Gt => WireOrderingPredicate::Gt,
                    OrderingPredicate::Ge => WireOrderingPredicate::Ge,
                    OrderingPredicate::Lt => WireOrderingPredicate::Lt,
                    OrderingPredicate::Le => WireOrderingPredicate::Le,
                },
                operand: WireScalarOperand::from_ordering(operator.operand()),
            }),
            Operator::Membership(operator) => Ok(Self::Membership {
                predicate: match operator.predicate() {
                    MembershipPredicate::In => WireMembershipPredicate::In,
                    MembershipPredicate::NotIn => WireMembershipPredicate::NotIn,
                },
                operand: WireSetOperand {
                    kind: WireSetKind::Set,
                    value_type: WireValueType::from_domain(operator.operand().value_type()),
                    values: operator
                        .operand()
                        .values()
                        .iter()
                        .map(wire_json_value)
                        .collect(),
                },
            }),
            Operator::StringMatch(operator) => Ok(Self::String {
                predicate: match operator.predicate() {
                    StringPredicate::StartsWith => WireStringPredicate::StartsWith,
                    StringPredicate::EndsWith => WireStringPredicate::EndsWith,
                    StringPredicate::Contains => WireStringPredicate::Contains,
                    StringPredicate::Glob => WireStringPredicate::Glob,
                    StringPredicate::Regex => WireStringPredicate::Regex,
                },
                operand: WirePatternOperand {
                    kind: WirePatternKind::Pattern,
                    value_type: WireStringType::String,
                    value: operator.pattern().to_string(),
                },
            }),
        }
    }
}

impl WireScalarOperand {
    fn from_equality(operand: &EqualityOperand) -> Self {
        match operand {
            EqualityOperand::Literal(value) => Self::Literal {
                value_type: WireValueType::from_domain(value.value_type()),
                value: wire_json_value(value),
            },
            EqualityOperand::Attribute(value) => Self::Attribute {
                value_type: WireValueType::from_domain(value.value_type()),
                attribute: value.attribute().as_str().to_string(),
            },
        }
    }
    fn from_ordering(operand: &OrderingOperand) -> Self {
        let value = operand.value().clone().into_policy_value();
        Self::Literal {
            value_type: WireValueType::from_domain(value.value_type()),
            value: wire_json_value(&value),
        }
    }
}

impl WireValueType {
    const fn from_domain(value: PolicyValueType) -> Self {
        match value {
            PolicyValueType::String => Self::String,
            PolicyValueType::Boolean => Self::Boolean,
            PolicyValueType::Integer => Self::Integer,
            PolicyValueType::Decimal => Self::Decimal,
        }
    }
}

fn wire_json_value(value: &PolicyValue) -> serde_json::Value {
    match value.as_ref() {
        PolicyValueRef::String(value) => serde_json::Value::String(value.to_string()),
        PolicyValueRef::Boolean(value) => serde_json::Value::Bool(value),
        PolicyValueRef::Integer(value) => serde_json::Value::Number(value.into()),
        PolicyValueRef::Decimal(value) => serde_json::Value::String(value.as_str().to_string()),
    }
}

impl WireObligationsView {
    fn from_obligations(
        obligations: &PolicyObligations,
    ) -> Result<Option<Self>, PolicyManageError> {
        if obligations.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self {
            row_scope: obligations
                .row_scope()
                .map(WireRowScope::from_scoped)
                .transpose()?,
            field_mask: obligations
                .field_mask()
                .iter()
                .map(|key| key.as_str().to_string())
                .collect(),
        }))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    use crate::domain::ATTR_VALUE_MAX_LEN;
    use generated::event::identity_v1::policy_updated::{
        IdentityPolicyUpdatedPayload, IdentityPolicyUpdatedPayloadChangeKind,
    };
    use generated::http::identity_v1::{
        policies_create::PRODUCER as POLICIES_CREATE_PRODUCER,
        policies_deactivate::PRODUCER as POLICIES_DEACTIVATE_PRODUCER,
        policies_update::PRODUCER as POLICIES_UPDATE_PRODUCER,
    };
    use httpserve::ProducerMarker;

    struct FixedClock(SystemTime);

    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const ACTOR: &str = "11111111-2222-4333-8444-555555555555";

    fn tenant() -> TenantId {
        TenantId::parse(TENANT).expect("tenant parses")
    }

    fn actor() -> ids::UserId {
        ids::UserId::parse(ACTOR).expect("actor parses")
    }

    fn create_receipt() -> PoliciesCreateProducerReceipt {
        ProducerMarker::for_test(POLICIES_CREATE_PRODUCER).into_receipt()
    }

    fn update_receipt() -> PoliciesUpdateProducerReceipt {
        ProducerMarker::for_test(POLICIES_UPDATE_PRODUCER).into_receipt()
    }

    fn deactivate_receipt() -> PoliciesDeactivateProducerReceipt {
        ProducerMarker::for_test(POLICIES_DEACTIVATE_PRODUCER).into_receipt()
    }

    fn clock() -> Box<dyn Clock> {
        Box::new(FixedClock(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        ))
    }

    fn service_with(
        repo: crate::internal::mem::InMemPolicyRepo,
    ) -> (PolicyManageService, crate::internal::mem::InMemPolicyRepo) {
        let policies: Arc<DynPolicyRepo<'static>> = Arc::from(DynPolicyRepo::new_box(repo.clone()));
        let lifecycle: Arc<DynPolicyLifecycle<'static>> =
            Arc::from(DynPolicyLifecycle::new_box(repo.clone()));
        (PolicyManageService::new(policies, lifecycle, clock()), repo)
    }

    fn service_with_specs(
        repo: crate::internal::mem::InMemPolicyRepo,
        http_specs: &'static [HttpSpec],
    ) -> (PolicyManageService, crate::internal::mem::InMemPolicyRepo) {
        let policies: Arc<DynPolicyRepo<'static>> = Arc::from(DynPolicyRepo::new_box(repo.clone()));
        let lifecycle: Arc<DynPolicyLifecycle<'static>> =
            Arc::from(DynPolicyLifecycle::new_box(repo.clone()));
        (
            PolicyManageService::new_with_http_specs(policies, lifecycle, clock(), http_specs),
            repo,
        )
    }

    fn create_request(policy_id: &str) -> IdentityPoliciesCreateRequest {
        serde_json::from_value(serde_json::json!({
            "policyId": policy_id,
            "contractId": "identity.policies-list",
            "permission": "identity:policy:read",
            "effectiveFrom": 1_700_000_000,
            "rules": [{
                "condition": {
                    "attribute": "principal.kind",
                    "operator": { "family": "equality", "predicate": "eq", "operand": { "kind": "literal", "valueType": "string", "value": "admin" } }
                },
                "effect": "allow"
            }]
        }))
        .expect("create request json")
    }

    fn update_request(expected: u32) -> IdentityPoliciesUpdateRequest {
        serde_json::from_value(serde_json::json!({
            "contractId": "identity.policies-get",
            "permission": "identity:policy:read",
            "effectiveFrom": 1_700_000_010,
            "expectedVersion": expected,
            "rules": [{
                "condition": {
                    "attribute": "principal.kind",
                    "operator": { "family": "equality", "predicate": "eq", "operand": { "kind": "literal", "valueType": "string", "value": "admin" } }
                },
                "effect": "allow",
                "obligations": { "fieldMask": ["actor"] }
            }]
        }))
        .expect("update request json")
    }

    fn global_static_create_request(policy_id: &str) -> IdentityPoliciesCreateRequest {
        serde_json::from_value(serde_json::json!({
            "policyId": policy_id,
            "contractId": "identity.global-resource",
            "permission": "identity:policy:read",
            "effectiveFrom": 1_700_000_000,
            "rules": [{
                "condition": {
                    "attribute": "principal.kind",
                    "operator": { "family": "equality", "predicate": "eq", "operand": { "kind": "literal", "valueType": "string", "value": "admin" } }
                },
                "effect": "allow"
            }]
        }))
        .expect("global static create request json")
    }

    fn global_dynamic_create_request(policy_id: &str) -> IdentityPoliciesCreateRequest {
        serde_json::from_value(serde_json::json!({
            "policyId": policy_id,
            "contractId": "identity.global-resource",
            "permission": "identity:policy:read",
            "effectiveFrom": 1_700_000_000,
            "rules": [{
                "condition": {
                    "attribute": "resource.owner",
                    "operator": { "family": "equality", "predicate": "eq", "operand": { "kind": "attribute", "valueType": "string", "attribute": "principal.id" } }
                },
                "effect": "allow"
            }]
        }))
        .expect("global dynamic create request json")
    }

    fn global_dynamic_update_request(expected: u32) -> IdentityPoliciesUpdateRequest {
        serde_json::from_value(serde_json::json!({
            "contractId": "identity.global-resource",
            "permission": "identity:policy:read",
            "effectiveFrom": 1_700_000_010,
            "expectedVersion": expected,
            "rules": [{
                "condition": {
                    "attribute": "resource.owner",
                    "operator": { "family": "equality", "predicate": "eq", "operand": { "kind": "attribute", "valueType": "string", "attribute": "principal.id" } }
                },
                "effect": "allow"
            }]
        }))
        .expect("global dynamic update request json")
    }

    fn deactivate_request(expected: u32) -> IdentityPoliciesDeactivateRequest {
        serde_json::from_value(serde_json::json!({ "expectedVersion": expected }))
            .expect("deactivate request json")
    }

    fn synthetic_global_spec() -> HttpSpec {
        HttpSpec {
            mount_key: "identity_v1::global_resource",
            route: vocab::HttpRouteEvidence::from_static(
                vocab::HttpContractOwner::domain("identity"),
                vocab::ContractBinding::from_static(
                    "identity",
                    "identity.global-resource",
                    "v1",
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                ),
                "/api/v1/identity/global/{resourceId}",
                "GET",
                &[],
                vocab::HttpSuccessStatus::new(200),
                vocab::HttpIdempotency::Idempotent,
                vocab::HttpRouteAuth::Permission(vocab::RoutePermissionId::IdentityPolicyRead),
                Some("resourceId"),
                false,
                vocab::http::HttpResourceSharing::Global,
                vocab::HttpConsistencyLevel::LocalOnly,
                vocab::HttpEffectProfile::new(&[
                    vocab::HttpEffectKind::Auth,
                    vocab::HttpEffectKind::Read,
                ]),
            ),
            local_tx: None,
            resource_sharing: generated::http::HttpResourceSharingSpec {
                mode: HttpResourceSharingMode::Global,
                reason: Some("shared synthetic test route"),
            },
            projection_fields: &[],
            headers: &[],
        }
    }

    fn synthetic_global_specs() -> &'static [HttpSpec] {
        Box::leak(Box::new([synthetic_global_spec()]))
    }

    fn global_scope() -> PolicyRouteScope {
        PolicyRouteScope::parse("identity.global-resource", "identity:policy:read")
            .expect("global scope")
    }

    fn dynamic_resource_rule() -> PolicyRule {
        PolicyRule::with_obligations(
            PolicyCondition::new(
                AttributeKey::new("resource.owner"),
                Operator::equal_attribute(PipAttributeKey::principal_id()),
            ),
            PolicyEffect::Allow,
            PolicyObligations::empty(),
        )
    }

    fn decode(payload: &[u8]) -> IdentityPolicyUpdatedPayload {
        serde_json::from_slice(payload).expect("policy-updated payload decodes")
    }

    #[test]
    fn global_resource_specs_reject_dynamic_resource_policy_rules() {
        let specs = [synthetic_global_spec()];
        let rules = vec![dynamic_resource_rule()];

        assert!(route_scope_is_global_resource_in(&global_scope(), &specs));
        assert!(rules_use_dynamic_resource_attributes(&rules).expect("rules classify"));
        assert!(matches!(
            reject_global_resource_policy(&global_scope(), &rules, &specs),
            Err(PolicyManageError::InvalidPolicy)
        ));
    }

    #[test]
    fn wire_operator_rejects_overlong_attribute_value() {
        let wire = WireOperator::Equality {
            predicate: WireEqualityPredicate::Eq,
            operand: WireScalarOperand::Literal {
                value_type: WireValueType::String,
                value: serde_json::json!("a".repeat(ATTR_VALUE_MAX_LEN + 1)),
            },
        };
        assert!(matches!(
            wire.into_operator(),
            Err(PolicyManageError::PolicyValueTooLong)
        ));
    }

    #[test]
    fn wire_operator_accepts_exact_max_attribute_value() {
        let wire = WireOperator::Equality {
            predicate: WireEqualityPredicate::Eq,
            operand: WireScalarOperand::Literal {
                value_type: WireValueType::String,
                value: serde_json::json!("a".repeat(ATTR_VALUE_MAX_LEN)),
            },
        };
        assert!(
            matches!(
                wire.into_operator(),
                Ok(Operator::Equality(ref op)) if matches!(op.operand(), EqualityOperand::Literal(v) if v.string_value().is_some_and(|value| value.len() == ATTR_VALUE_MAX_LEN))
            ),
            "exact-max value must parse as Eq"
        );
    }

    #[test]
    fn wire_operator_eq_attr_accepts_pip_principal_id() {
        let wire = WireOperator::Equality {
            predicate: WireEqualityPredicate::Eq,
            operand: WireScalarOperand::Attribute {
                value_type: WireValueType::String,
                attribute: "principal.id".to_string(),
            },
        };
        assert!(
            matches!(
                wire.into_operator(),
                Ok(Operator::Equality(ref op)) if matches!(op.operand(), EqualityOperand::Attribute(value) if value.attribute().as_str() == "principal.id")
            ),
            "PIP principal.id must parse as EqAttr"
        );
    }

    #[test]
    fn wire_operator_eq_attr_rejects_non_pip_attribute() {
        let wire = WireOperator::Equality {
            predicate: WireEqualityPredicate::Eq,
            operand: WireScalarOperand::Attribute {
                value_type: WireValueType::String,
                attribute: "secret.probe".to_string(),
            },
        };
        assert!(matches!(
            wire.into_operator(),
            Err(PolicyManageError::InvalidPolicy)
        ));
    }

    #[test]
    fn active_v1_rejects_legacy_flat_operator_payload() {
        let payload = serde_json::json!({
            "policyId": "legacy-shape",
            "contractId": "identity.policies-list",
            "permission": "identity:policy:read",
            "effectiveFrom": 1_700_000_000,
            "rules": [{"condition":{"attribute":"principal.kind","operator":{"kind":"eq","value":"admin"}},"effect":"allow"}]
        });
        assert!(serde_json::from_value::<IdentityPoliciesCreateRequest>(payload).is_err());
    }

    #[test]
    fn membership_schema_and_domain_enforce_canonical_bounded_set() {
        let values = (0..32)
            .map(|value| format!("team-{value:02}"))
            .collect::<Vec<_>>();
        let payload = serde_json::json!({
            "policyId": "membership",
            "contractId": "identity.policies-list",
            "permission": "identity:policy:read",
            "effectiveFrom": 1_700_000_000,
            "rules": [{"condition":{"attribute":"principal.kind","operator":{"family":"membership","predicate":"in","operand":{"kind":"set","valueType":"string","values":values}}},"effect":"allow"}]
        });
        let request: IdentityPoliciesCreateRequest =
            serde_json::from_value(payload).expect("32 values");
        let draft = PolicyCreateDraft::try_from(request).expect("domain set");
        assert!(matches!(draft.rules[0].operator(), Operator::Membership(_)));

        let duplicate = serde_json::json!({
            "policyId": "duplicate",
            "contractId": "identity.policies-list",
            "permission": "identity:policy:read",
            "effectiveFrom": 1_700_000_000,
            "rules": [{"condition":{"attribute":"principal.kind","operator":{"family":"membership","predicate":"in","operand":{"kind":"set","valueType":"string","values":["eng","eng"]}}},"effect":"allow"}]
        });
        let duplicate: IdentityPoliciesCreateRequest =
            serde_json::from_value(duplicate).expect("wire shape");
        assert!(matches!(
            PolicyCreateDraft::try_from(duplicate),
            Err(PolicyManageError::InvalidOperator(
                PolicyOperatorReason::DuplicateSetValue
            ))
        ));
    }

    #[test]
    fn ordering_rejects_string_operand_before_domain_construction() {
        let payload = serde_json::json!({
            "policyId": "bad-ordering",
            "contractId": "identity.policies-list",
            "permission": "identity:policy:read",
            "effectiveFrom": 1_700_000_000,
            "rules": [{"condition":{"attribute":"resource.rank","operator":{"family":"ordering","predicate":"gt","operand":{"kind":"literal","valueType":"string","value":"3"}}},"effect":"allow"}]
        });
        assert!(serde_json::from_value::<IdentityPoliciesCreateRequest>(payload).is_err());
    }

    #[test]
    fn active_v1_all_predicates_round_trip_canonically_across_views() {
        let decimal = |raw: &str| PolicyValue::decimal(raw).expect("canonical decimal");
        let operators = vec![
            Operator::equal(PolicyValue::boolean(true)),
            Operator::not_equal(decimal("2.5")),
            Operator::equal_attribute(PipAttributeKey::principal_id()),
            Operator::ordering(OrderingPredicate::Gt, NumericValue::Integer(1)),
            Operator::ordering(OrderingPredicate::Ge, NumericValue::Integer(1)),
            Operator::ordering(
                OrderingPredicate::Lt,
                NumericValue::Decimal(crate::domain::DecimalValue::parse("1.1").expect("decimal")),
            ),
            Operator::ordering(OrderingPredicate::Le, NumericValue::Integer(1)),
            Operator::Membership(MembershipOperator::new(
                MembershipPredicate::In,
                PolicyValueSet::new(vec![
                    PolicyValue::string("eng").expect("string"),
                    PolicyValue::string("ops").expect("string"),
                ])
                .expect("set"),
            )),
            Operator::Membership(MembershipOperator::new(
                MembershipPredicate::NotIn,
                PolicyValueSet::new(vec![PolicyValue::integer(1)]).expect("set"),
            )),
            Operator::string(StringPredicate::StartsWith, "team-").expect("pattern"),
            Operator::string(StringPredicate::EndsWith, "-ops").expect("pattern"),
            Operator::string(StringPredicate::Contains, "eng").expect("pattern"),
            Operator::string(StringPredicate::Glob, "team-*").expect("pattern"),
            Operator::string(StringPredicate::Regex, r"^team-[0-9]+$").expect("pattern"),
        ];
        let expected_operators = operators
            .iter()
            .map(|operator| {
                serde_json::to_value(WireOperator::from_operator(operator).expect("wire"))
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("json");
        let rules = expected_operators
            .iter()
            .enumerate()
            .map(|(index, operator)| serde_json::json!({
                "condition": {"attribute": format!("resource.test{index}"), "operator": operator},
                "effect": "allow"
            }))
            .collect::<Vec<_>>();
        let payload = serde_json::json!({
            "policyId": "all-predicates",
            "contractId": "identity.policies-list",
            "permission": "identity:policy:read",
            "effectiveFrom": 1_700_000_000,
            "rules": rules
        });
        let request: IdentityPoliciesCreateRequest =
            serde_json::from_value(payload.clone()).expect("create schema");
        let draft = PolicyCreateDraft::try_from(request).expect("domain");
        let policy = Policy::build(
            draft.id.as_str(),
            tenant(),
            draft.scope,
            draft.effective_from,
            draft.effective_until,
            draft.rules,
        )
        .expect("policy");

        let update_payload = serde_json::json!({
            "contractId": "identity.policies-list",
            "permission": "identity:policy:read",
            "effectiveFrom": 1_700_000_000,
            "expectedVersion": 1,
            "rules": payload["rules"].clone()
        });
        let update: IdentityPoliciesUpdateRequest =
            serde_json::from_value(update_payload).expect("update schema");
        assert_eq!(
            PolicyUpdateDraft::try_from_wire(policy.id().clone(), update)
                .expect("update domain")
                .rules
                .len(),
            operators.len()
        );

        let views = [
            serde_json::to_value(create_response(&policy).expect("create view")).expect("json"),
            serde_json::to_value(update_response(&policy).expect("update view")).expect("json"),
            serde_json::to_value(get_response(&policy).expect("get view")).expect("json"),
            serde_json::to_value(list_response(vec![policy], false, None).expect("list view"))
                .expect("json"),
        ];
        for (index, view) in views.iter().enumerate() {
            let rules = if index == 3 {
                &view["data"][0]["rules"]
            } else {
                &view["data"]["rules"]
            };
            let got = rules
                .as_array()
                .expect("rules")
                .iter()
                .map(|rule| rule["condition"]["operator"].clone())
                .collect::<Vec<_>>();
            assert_eq!(got, expected_operators);
        }
    }

    #[test]
    fn active_v1_rejects_impossible_attribute_types_noncanonical_decimal_and_unknown_fields() {
        for operator in [
            serde_json::json!({"family":"equality","predicate":"eq","operand":{"kind":"attribute","valueType":"boolean","attribute":"principal.id"}}),
            serde_json::json!({"family":"ordering","predicate":"gt","operand":{"kind":"attribute","valueType":"integer","attribute":"principal.id"}}),
            serde_json::json!({"family":"ordering","predicate":"gt","operand":{"kind":"literal","valueType":"decimal","value":"1.0"}}),
            serde_json::json!({"family":"equality","predicate":"eq","operand":{"kind":"literal","valueType":"string","value":"ok","unknown":true}}),
        ] {
            let payload = serde_json::json!({
                "policyId": "invalid-combination",
                "contractId": "identity.policies-list",
                "permission": "identity:policy:read",
                "effectiveFrom": 1_700_000_000,
                "rules": [{"condition":{"attribute":"resource.test","operator":operator},"effect":"allow"}]
            });
            assert!(serde_json::from_value::<IdentityPoliciesCreateRequest>(payload).is_err());
        }
    }

    #[test]
    fn create_request_rejects_non_pip_eq_attr_at_generated_schema() {
        let err = serde_json::from_value::<IdentityPoliciesCreateRequest>(serde_json::json!({
            "policyId": "policy-eqattr-probe",
            "contractId": "identity.policies-list",
            "permission": "identity:policy:read",
            "effectiveFrom": 1_700_000_000,
            "rules": [{
                "condition": {
                    "attribute": "resource.owner",
                    "operator": { "family": "equality", "predicate": "eq", "operand": { "kind": "attribute", "valueType": "string", "attribute": "secret.probe" } }
                },
                "effect": "allow"
            }]
        }));
        assert!(
            err.is_err(),
            "generated schema must reject non-PIP eqAttr RHS"
        );
    }

    #[test]
    fn create_request_rejects_overlong_operator_value_at_wire() {
        let err = serde_json::from_value::<IdentityPoliciesCreateRequest>(serde_json::json!({
            "policyId": "policy-overlong",
            "contractId": "identity.policies-list",
            "permission": "identity:policy:read",
            "effectiveFrom": 1_700_000_000,
            "rules": [{
                "condition": {
                    "attribute": "principal.kind",
                    "operator": { "family": "equality", "predicate": "eq", "operand": { "kind": "literal", "valueType": "string", "value": "a".repeat(ATTR_VALUE_MAX_LEN + 1) } }
                },
                "effect": "allow"
            }]
        }));
        assert!(
            err.is_err(),
            "generated wire maxLength must reject over-max char value"
        );
    }

    #[test]
    fn create_request_accepts_exact_max_operator_value_at_wire() {
        let req = serde_json::from_value::<IdentityPoliciesCreateRequest>(serde_json::json!({
            "policyId": "policy-exact-max",
            "contractId": "identity.policies-list",
            "permission": "identity:policy:read",
            "effectiveFrom": 1_700_000_000,
            "rules": [{
                "condition": {
                    "attribute": "principal.kind",
                    "operator": { "family": "equality", "predicate": "eq", "operand": { "kind": "literal", "valueType": "string", "value": "a".repeat(ATTR_VALUE_MAX_LEN) } }
                },
                "effect": "allow"
            }]
        }));
        assert!(
            req.is_ok(),
            "generated wire maxLength must accept exact-max char value: {req:?}"
        );
    }

    #[test]
    fn update_request_rejects_overlong_operator_value_at_wire() {
        let err = serde_json::from_value::<IdentityPoliciesUpdateRequest>(serde_json::json!({
            "expectedVersion": 1,
            "contractId": "identity.policies-list",
            "permission": "identity:policy:read",
            "effectiveFrom": 1_700_000_000,
            "rules": [{
                "condition": {
                    "attribute": "principal.kind",
                    "operator": { "family": "equality", "predicate": "eq", "operand": { "kind": "literal", "valueType": "string", "value": "a".repeat(ATTR_VALUE_MAX_LEN + 1) } }
                },
                "effect": "allow"
            }]
        }));
        assert!(
            err.is_err(),
            "generated wire maxLength must reject over-max char value on update"
        );
    }

    #[test]
    fn update_request_accepts_exact_max_operator_value_at_wire() {
        let req = serde_json::from_value::<IdentityPoliciesUpdateRequest>(serde_json::json!({
            "expectedVersion": 1,
            "contractId": "identity.policies-list",
            "permission": "identity:policy:read",
            "effectiveFrom": 1_700_000_000,
            "rules": [{
                "condition": {
                    "attribute": "principal.kind",
                    "operator": { "family": "equality", "predicate": "eq", "operand": { "kind": "literal", "valueType": "string", "value": "a".repeat(ATTR_VALUE_MAX_LEN) } }
                },
                "effect": "allow"
            }]
        }));
        assert!(
            req.is_ok(),
            "generated wire maxLength must accept exact-max char value on update: {req:?}"
        );
    }

    #[test]
    fn multibyte_wire_accepts_chars_but_domain_rejects_over_byte_bound_on_create() {
        // "あ" = 3 UTF-8 bytes; 86 chars = 258 bytes > ATTR_VALUE_MAX_LEN, but chars < wire maxLength.
        let multibyte = "あ".repeat(86);
        assert_eq!(multibyte.chars().count(), 86);
        assert_eq!(multibyte.len(), 258);
        assert!(multibyte.len() > ATTR_VALUE_MAX_LEN);
        assert!(multibyte.chars().count() <= ATTR_VALUE_MAX_LEN);

        let req = serde_json::from_value::<IdentityPoliciesCreateRequest>(serde_json::json!({
            "policyId": "policy-multibyte",
            "contractId": "identity.policies-list",
            "permission": "identity:policy:read",
            "effectiveFrom": 1_700_000_000,
            "rules": [{
                "condition": {
                    "attribute": "principal.kind",
                    "operator": { "family": "equality", "predicate": "eq", "operand": { "kind": "literal", "valueType": "string", "value": multibyte } }
                },
                "effect": "allow"
            }]
        }))
        .expect("wire Unicode maxLength must accept 86 multibyte chars");

        assert!(matches!(
            PolicyCreateDraft::try_from(req),
            Err(PolicyManageError::PolicyValueTooLong)
        ));
    }

    #[test]
    fn multibyte_wire_accepts_chars_but_domain_rejects_over_byte_bound_on_update() {
        let multibyte = "あ".repeat(86);
        assert!(multibyte.len() > ATTR_VALUE_MAX_LEN);
        assert!(multibyte.chars().count() <= ATTR_VALUE_MAX_LEN);

        let req = serde_json::from_value::<IdentityPoliciesUpdateRequest>(serde_json::json!({
            "expectedVersion": 1,
            "contractId": "identity.policies-list",
            "permission": "identity:policy:read",
            "effectiveFrom": 1_700_000_000,
            "rules": [{
                "condition": {
                    "attribute": "principal.kind",
                    "operator": { "family": "equality", "predicate": "eq", "operand": { "kind": "literal", "valueType": "string", "value": multibyte } }
                },
                "effect": "allow"
            }]
        }))
        .expect("wire Unicode maxLength must accept 86 multibyte chars on update");

        let policy_id = PolicyId::parse("policy-multibyte-upd").expect("policy id");
        assert!(matches!(
            PolicyUpdateDraft::try_from_wire(policy_id, req),
            Err(PolicyManageError::PolicyValueTooLong)
        ));
    }

    #[tokio::test]
    async fn create_policy_rejects_global_resource_dynamic_attrs_without_write_or_event() {
        let (service, probe) = service_with_specs(
            crate::internal::mem::InMemPolicyRepo::new(),
            synthetic_global_specs(),
        );
        let t = tenant();

        let err = service
            .create_policy(
                create_receipt(),
                t,
                actor(),
                vocab::PrincipalKind::Admin,
                PolicyCreateDraft::try_from(global_dynamic_create_request("policy-global-dyn"))
                    .expect("create draft"),
            )
            .await
            .expect_err("global resource dynamic attr must be rejected");

        assert!(matches!(err, PolicyManageError::InvalidPolicy));
        assert!(probe.emitted().is_empty(), "rejected create must not emit");
        assert!(matches!(
            service
                .find_policy_for_management(
                    t,
                    PolicyId::parse("policy-global-dyn").expect("policy id"),
                )
                .await,
            Err(PolicyManageError::PolicyNotFound)
        ));
    }

    #[tokio::test]
    async fn update_policy_rejects_global_resource_dynamic_attrs_without_write_or_event() {
        let (service, probe) = service_with_specs(
            crate::internal::mem::InMemPolicyRepo::new(),
            synthetic_global_specs(),
        );
        let t = tenant();
        let policy_id = PolicyId::parse("policy-global-static").expect("policy id");
        let created = service
            .create_policy(
                create_receipt(),
                t,
                actor(),
                vocab::PrincipalKind::Admin,
                PolicyCreateDraft::try_from(global_static_create_request(policy_id.as_str()))
                    .expect("create draft"),
            )
            .await
            .expect("static global policy is allowed");
        assert_eq!(created.version().get(), 1);
        assert_eq!(probe.emitted().len(), 1);

        let err = service
            .update_policy(
                update_receipt(),
                t,
                actor(),
                vocab::PrincipalKind::Admin,
                PolicyUpdateDraft::try_from_wire(
                    policy_id.clone(),
                    global_dynamic_update_request(created.version().get()),
                )
                .expect("update draft"),
            )
            .await
            .expect_err("global resource dynamic attr update must be rejected");

        assert!(matches!(err, PolicyManageError::InvalidPolicy));
        assert_eq!(probe.emitted().len(), 1, "rejected update must not emit");
        let stored = service
            .find_policy_for_management(t, policy_id)
            .await
            .expect("original policy remains");
        assert_eq!(stored.version().get(), 1);
    }

    #[tokio::test]
    async fn create_update_deactivate_emit_policy_updated() {
        let (service, probe) = service_with(crate::internal::mem::InMemPolicyRepo::new());
        let t = tenant();
        let created = service
            .create_policy(
                create_receipt(),
                t,
                actor(),
                vocab::PrincipalKind::Admin,
                PolicyCreateDraft::try_from(create_request("policy-a")).expect("create draft"),
            )
            .await
            .expect("create policy");
        assert_eq!(created.version().get(), 1);

        let updated = service
            .update_policy(
                update_receipt(),
                t,
                actor(),
                vocab::PrincipalKind::Admin,
                PolicyUpdateDraft::try_from_wire(
                    PolicyId::parse("policy-a").expect("policy id"),
                    update_request(1),
                )
                .expect("update draft"),
            )
            .await
            .expect("update policy");
        assert_eq!(updated.version().get(), 2);

        let deactivated = service
            .deactivate_policy(
                deactivate_receipt(),
                t,
                actor(),
                vocab::PrincipalKind::Admin,
                PolicyDeactivateDraft::try_from_wire(
                    PolicyId::parse("policy-a").expect("policy id"),
                    deactivate_request(2),
                )
                .expect("deactivate draft"),
            )
            .await
            .expect("deactivate policy");
        assert_eq!(deactivated.get(), 3);

        let emitted = probe.emitted();
        assert_eq!(emitted.len(), 3);
        assert_eq!(
            decode(&emitted[0].payload).change_kind,
            IdentityPolicyUpdatedPayloadChangeKind::Created
        );
        assert_eq!(
            decode(&emitted[1].payload).change_kind,
            IdentityPolicyUpdatedPayloadChangeKind::Updated
        );
        assert_eq!(
            decode(&emitted[2].payload).change_kind,
            IdentityPolicyUpdatedPayloadChangeKind::Deactivated
        );
        assert!(
            service
                .find_policy_for_management(t, PolicyId::parse("policy-a").expect("policy id"))
                .await
                .is_err(),
            "deactivated policy must be hidden from get"
        );
    }

    #[tokio::test]
    async fn get_and_list_do_not_emit_policy_updated() {
        let (service, probe) = service_with(crate::internal::mem::InMemPolicyRepo::new());
        let t = tenant();
        service
            .create_policy(
                create_receipt(),
                t,
                actor(),
                vocab::PrincipalKind::Admin,
                PolicyCreateDraft::try_from(create_request("policy-read")).expect("create draft"),
            )
            .await
            .expect("create policy");
        assert_eq!(probe.emitted().len(), 1);

        let query = PolicyQueryService {
            policies: Arc::from(DynPolicyRepo::new_box(probe.clone())),
        };
        query
            .get_policy(t, PolicyId::parse("policy-read").expect("policy id"))
            .await
            .expect("get policy");
        query
            .list_policies(
                t,
                PolicyPage {
                    limit: vocab::Limit::new(50).expect("limit"),
                    after: None,
                },
            )
            .await
            .expect("list policies");
        assert_eq!(probe.emitted().len(), 1, "read side must not emit events");
    }

    #[tokio::test]
    async fn create_cotx_failure_leaves_no_policy_and_no_event() {
        let (service, probe) =
            service_with(crate::internal::mem::InMemPolicyRepo::failing_writes());
        let t = tenant();
        let err = service
            .create_policy(
                create_receipt(),
                t,
                actor(),
                vocab::PrincipalKind::Admin,
                PolicyCreateDraft::try_from(create_request("policy-fail")).expect("create draft"),
            )
            .await
            .expect_err("write failure must bubble");
        assert!(matches!(err, PolicyManageError::Store(_)));
        assert!(probe.emitted().is_empty(), "failed co-tx must not emit");
        assert!(
            service
                .find_policy_for_management(t, PolicyId::parse("policy-fail").expect("policy id"),)
                .await
                .is_err(),
            "failed co-tx must not leave policy"
        );
    }
}
