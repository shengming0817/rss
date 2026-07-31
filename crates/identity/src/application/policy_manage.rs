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
    policies_create::{
        IdentityPoliciesCreateRequest, IdentityPoliciesCreateResponse, IdentityPolicyCreateView,
    },
    policies_deactivate::{IdentityPoliciesDeactivateRequest, IdentityPoliciesDeactivateResponse},
    policies_get::{IdentityPoliciesGetResponse, IdentityPolicyGetView},
    policies_list::{IdentityPoliciesListResponse, IdentityPolicyListView},
    policies_update::{
        IdentityPoliciesUpdateRequest, IdentityPoliciesUpdateResponse, IdentityPolicyUpdateView,
    },
};
use generated::http::{HttpSpec, SPECS as HTTP_SPECS};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use uuid::Uuid;
use vocab::{HttpRouteAuth, TenantId, http::HttpResourceSharing as HttpResourceSharingMode};

use super::{EventWireProjectionError, unix_secs};
use crate::domain::{
    AttributeKey, AttributeValue, GlobPattern, IdentityError, Operator, PipAttributeKey, Policy,
    PolicyCondition, PolicyEffect, PolicyId, PolicyObligations, PolicyRouteScope, PolicyRule,
    PolicyVersion, ResourcePolicyAttributeKey,
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
    AttributeValueTooLong,
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
            rules: policy_rules_from_wire(&request.rules)?,
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
            rules: policy_rules_from_wire(&request.rules)?,
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
        err
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
        err
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
        err
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
        data: policy_view::<IdentityPolicyCreateView>(policy)?,
    })
}

pub fn update_response(
    policy: &Policy,
) -> Result<IdentityPoliciesUpdateResponse, PolicyManageError> {
    Ok(IdentityPoliciesUpdateResponse {
        data: policy_view::<IdentityPolicyUpdateView>(policy)?,
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
        data: policy_view::<IdentityPolicyGetView>(policy)?,
    })
}

pub fn list_response(
    policies: Vec<Policy>,
    has_more: bool,
    next_cursor: Option<String>,
) -> Result<IdentityPoliciesListResponse, PolicyManageError> {
    let data = policies
        .iter()
        .map(policy_view::<IdentityPolicyListView>)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(IdentityPoliciesListResponse {
        data,
        has_more,
        next_cursor,
    })
}

fn policy_view<T: DeserializeOwned>(policy: &Policy) -> Result<T, PolicyManageError> {
    let value = WirePolicyView::from_policy(policy)?;
    serde_json::from_value(serde_json::to_value(value).map_err(PolicyManageError::PayloadEncode)?)
        .map_err(|_| PolicyManageError::InvalidPolicy)
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

fn policy_rules_from_wire<T: Serialize>(rules: &[T]) -> Result<Vec<PolicyRule>, PolicyManageError> {
    if rules.is_empty() {
        return Err(PolicyManageError::InvalidPolicy);
    }
    let wire: Vec<WireRule> = serde_json::from_value(
        serde_json::to_value(rules).map_err(PolicyManageError::PayloadEncode)?,
    )
    .map_err(|_| PolicyManageError::InvalidPolicy)?;
    wire.into_iter().map(WireRule::into_rule).collect()
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireOperator {
    kind: WireOperatorKind,
    value: Option<String>,
    pattern: Option<String>,
    attribute: Option<String>,
}

#[derive(Deserialize)]
enum WireOperatorKind {
    #[serde(rename = "eq")]
    Eq,
    #[serde(rename = "ne")]
    Ne,
    #[serde(rename = "like")]
    Like,
    #[serde(rename = "gt")]
    Gt,
    #[serde(rename = "lt")]
    Lt,
    #[serde(rename = "eqAttr")]
    EqAttr,
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
        match self.kind {
            WireOperatorKind::Eq => Ok(Operator::Eq(
                AttributeValue::parse(&self.only_value()?)
                    .map_err(|_| PolicyManageError::AttributeValueTooLong)?,
            )),
            WireOperatorKind::Ne => Ok(Operator::Ne(
                AttributeValue::parse(&self.only_value()?)
                    .map_err(|_| PolicyManageError::AttributeValueTooLong)?,
            )),
            WireOperatorKind::Gt => Ok(Operator::Gt(
                AttributeValue::parse(&self.only_value()?)
                    .map_err(|_| PolicyManageError::AttributeValueTooLong)?,
            )),
            WireOperatorKind::Lt => Ok(Operator::Lt(
                AttributeValue::parse(&self.only_value()?)
                    .map_err(|_| PolicyManageError::AttributeValueTooLong)?,
            )),
            WireOperatorKind::Like => {
                let pattern = self.only_pattern()?;
                Ok(Operator::Like(
                    GlobPattern::parse(&pattern).map_err(|_| PolicyManageError::InvalidPolicy)?,
                ))
            }
            WireOperatorKind::EqAttr => {
                let attribute = self.only_attribute()?;
                Ok(Operator::EqAttr(
                    PipAttributeKey::parse(&attribute)
                        .map_err(|_| PolicyManageError::InvalidPolicy)?,
                ))
            }
        }
    }

    fn only_value(self) -> Result<String, PolicyManageError> {
        if self.pattern.is_none() && self.attribute.is_none() {
            self.value.ok_or(PolicyManageError::InvalidPolicy)
        } else {
            Err(PolicyManageError::InvalidPolicy)
        }
    }

    fn only_pattern(self) -> Result<String, PolicyManageError> {
        if self.value.is_none() && self.attribute.is_none() {
            self.pattern.ok_or(PolicyManageError::InvalidPolicy)
        } else {
            Err(PolicyManageError::InvalidPolicy)
        }
    }

    fn only_attribute(self) -> Result<String, PolicyManageError> {
        if self.value.is_none() && self.pattern.is_none() {
            self.attribute.ok_or(PolicyManageError::InvalidPolicy)
        } else {
            Err(PolicyManageError::InvalidPolicy)
        }
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
    operator: WireOperatorView,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WireOperatorView {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attribute: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WireObligationsView {
    #[serde(skip_serializing_if = "Option::is_none")]
    row_scope: Option<WireRowScope>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    field_mask: Vec<String>,
}

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
                operator: WireOperatorView::from_operator(rule.operator())?,
            },
            effect: match rule.effect() {
                PolicyEffect::Allow => WireEffect::Allow,
                PolicyEffect::Deny => WireEffect::Deny,
            },
            obligations,
        })
    }
}

impl WireOperatorView {
    fn from_operator(operator: &Operator) -> Result<Self, PolicyManageError> {
        match operator {
            Operator::Eq(value) => Ok(Self {
                kind: "eq",
                value: Some(value.as_str().to_string()),
                pattern: None,
                attribute: None,
            }),
            Operator::Ne(value) => Ok(Self {
                kind: "ne",
                value: Some(value.as_str().to_string()),
                pattern: None,
                attribute: None,
            }),
            Operator::Gt(value) => Ok(Self {
                kind: "gt",
                value: Some(value.as_str().to_string()),
                pattern: None,
                attribute: None,
            }),
            Operator::Lt(value) => Ok(Self {
                kind: "lt",
                value: Some(value.as_str().to_string()),
                pattern: None,
                attribute: None,
            }),
            Operator::Like(pattern) => Ok(Self {
                kind: "like",
                value: None,
                pattern: Some(pattern.as_str().to_string()),
                attribute: None,
            }),
            Operator::EqAttr(attribute) => Ok(Self {
                kind: "eqAttr",
                value: None,
                pattern: None,
                attribute: Some(attribute.as_str().to_string()),
            }),
        }
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
                    "operator": { "kind": "eq", "value": "admin" }
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
                    "operator": { "kind": "eq", "value": "admin" }
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
                    "operator": { "kind": "eq", "value": "admin" }
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
                    "operator": { "kind": "eqAttr", "attribute": "principal.id" }
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
                    "operator": { "kind": "eqAttr", "attribute": "principal.id" }
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
                Operator::EqAttr(PipAttributeKey::principal_id()),
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
        let wire = WireOperator {
            kind: WireOperatorKind::Eq,
            value: Some("a".repeat(ATTR_VALUE_MAX_LEN + 1)),
            pattern: None,
            attribute: None,
        };
        assert!(matches!(
            wire.into_operator(),
            Err(PolicyManageError::AttributeValueTooLong)
        ));
    }

    #[test]
    fn wire_operator_accepts_exact_max_attribute_value() {
        let wire = WireOperator {
            kind: WireOperatorKind::Eq,
            value: Some("a".repeat(ATTR_VALUE_MAX_LEN)),
            pattern: None,
            attribute: None,
        };
        assert!(
            matches!(
                wire.into_operator(),
                Ok(Operator::Eq(v)) if v.as_str().len() == ATTR_VALUE_MAX_LEN
            ),
            "exact-max value must parse as Eq"
        );
    }

    #[test]
    fn wire_operator_eq_attr_accepts_pip_principal_id() {
        let wire = WireOperator {
            kind: WireOperatorKind::EqAttr,
            value: None,
            pattern: None,
            attribute: Some("principal.id".to_string()),
        };
        assert!(
            matches!(
                wire.into_operator(),
                Ok(Operator::EqAttr(key)) if key.as_str() == "principal.id"
            ),
            "PIP principal.id must parse as EqAttr"
        );
    }

    #[test]
    fn wire_operator_eq_attr_rejects_non_pip_attribute() {
        let wire = WireOperator {
            kind: WireOperatorKind::EqAttr,
            value: None,
            pattern: None,
            attribute: Some("secret.probe".to_string()),
        };
        assert!(matches!(
            wire.into_operator(),
            Err(PolicyManageError::InvalidPolicy)
        ));
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
                    "operator": { "kind": "eqAttr", "attribute": "secret.probe" }
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
                    "operator": { "kind": "eq", "value": "a".repeat(ATTR_VALUE_MAX_LEN + 1) }
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
                    "operator": { "kind": "eq", "value": "a".repeat(ATTR_VALUE_MAX_LEN) }
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
                    "operator": { "kind": "eq", "value": "a".repeat(ATTR_VALUE_MAX_LEN + 1) }
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
                    "operator": { "kind": "eq", "value": "a".repeat(ATTR_VALUE_MAX_LEN) }
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
                    "operator": { "kind": "eq", "value": multibyte }
                },
                "effect": "allow"
            }]
        }))
        .expect("wire Unicode maxLength must accept 86 multibyte chars");

        assert!(matches!(
            PolicyCreateDraft::try_from(req),
            Err(PolicyManageError::AttributeValueTooLong)
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
                    "operator": { "kind": "eq", "value": multibyte }
                },
                "effect": "allow"
            }]
        }))
        .expect("wire Unicode maxLength must accept 86 multibyte chars on update");

        let policy_id = PolicyId::parse("policy-multibyte-upd").expect("policy id");
        assert!(matches!(
            PolicyUpdateDraft::try_from_wire(policy_id, req),
            Err(PolicyManageError::AttributeValueTooLong)
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
