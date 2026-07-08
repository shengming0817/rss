//! identity::domain::abac — ABAC 属性 / durable route policy 值类型与策略求值。
//!
//! `Policy` 是 tenant-scoped、route-scoped、versioned 的 durable policy facade；字段私有、
//! 构造经 hydrate/build funnel，adapter 可命名/收发/读取但不可绕过校验伪造。
//!
//! # 求值语义（deny-overrides）
//!
//! 单个 policy 内：任一命中 `Deny` 规则 → `Deny`；否则命中 `Allow` 规则 → `Allow(obligations)`；
//! 无规则命中 → `NoMatch`。对外旧 `evaluate_abac` 仍把 `NoMatch` 映射为 `Decision::Deny`，保持
//! fail-closed 二值接口。
//!
//! ref: casbin/casbin-rs src/effector.rs@fc425d4（`EffectKind{Allow,Indeterminate,Deny}`，
//! `DefaultEffectStream::push_effect` 中 Deny 压过 Allow）。

use std::time::SystemTime;

use super::{AttributeKey, AttributeValue, IdentityError, PolicyId};

const GLOB_MAX_LEN: usize = 256;
const ROUTE_SCOPE_MAX_LEN: usize = 256;

/// Route policy attribute key for the principal kind (`user`, `admin`, `service`, ...).
pub const POLICY_ATTR_PRINCIPAL_KIND: &str = "principal.kind";
/// Route policy attribute key for the authenticated subject id.
pub const POLICY_ATTR_PRINCIPAL_ID: &str = "principal.id";
/// Route policy attribute key for the tenant id.
pub const POLICY_ATTR_TENANT_ID: &str = "tenant.id";
/// Route policy attribute key for the contract id.
pub const POLICY_ATTR_CONTRACT_ID: &str = "contract.id";
/// Route policy attribute key for the contract permission.
pub const POLICY_ATTR_PERMISSION: &str = "permission";
/// Route policy attribute key for the optional route resource id.
pub const POLICY_ATTR_RESOURCE_ID: &str = "resource.id";

// ---------------------------------------------------------------------------
// ABAC 属性
// ---------------------------------------------------------------------------

/// ABAC 属性（key-value 对；不 derive Serialize——域类型）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbacAttribute {
    key: AttributeKey,
    value: AttributeValue,
}

impl AbacAttribute {
    /// 构造 ABAC 属性。
    pub fn new(key: AttributeKey, value: AttributeValue) -> Self {
        Self { key, value }
    }

    /// 取属性键引用。
    pub fn key(&self) -> &AttributeKey {
        &self.key
    }

    /// 取属性值引用。
    pub fn value(&self) -> &AttributeValue {
        &self.value
    }
}

// ---------------------------------------------------------------------------
// Route scope / version / obligations
// ---------------------------------------------------------------------------

/// durable policy 适用的 route scope（contract_id + permission）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyRouteScope {
    contract_id: String,
    permission: String,
}

impl PolicyRouteScope {
    pub fn parse(contract_id: &str, permission: &str) -> Result<Self, IdentityError> {
        validate_route_token(contract_id)?;
        validate_route_token(permission)?;
        Ok(Self {
            contract_id: contract_id.to_string(),
            permission: permission.to_string(),
        })
    }

    #[cfg(test)]
    pub(crate) fn new_unchecked(
        contract_id: impl Into<String>,
        permission: impl Into<String>,
    ) -> Self {
        Self {
            contract_id: contract_id.into(),
            permission: permission.into(),
        }
    }

    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }

    pub fn permission(&self) -> &str {
        &self.permission
    }

    pub fn matches(&self, contract_id: &str, permission: &str) -> bool {
        self.contract_id == contract_id && self.permission == permission
    }
}

fn validate_route_token(raw: &str) -> Result<(), IdentityError> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '/');
    super::validate_token(raw, ROUTE_SCOPE_MAX_LEN, allowed)
        .map_err(|_| IdentityError::InvalidPolicy)
}

/// current-row CAS version for a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyVersion(u32);

impl PolicyVersion {
    pub fn new(raw: u32) -> Result<Self, IdentityError> {
        if raw == 0 {
            return Err(IdentityError::InvalidPolicy);
        }
        Ok(Self(raw))
    }

    #[cfg(test)]
    pub(crate) fn first() -> Self {
        Self(1)
    }

    pub fn get(self) -> u32 {
        self.0
    }

    pub fn next_checked(self) -> Result<Self, IdentityError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(IdentityError::VersionConflict)
    }
}

/// Policy obligations captured by PDP evaluation.
///
/// Row-scope uses `ScopedTenant`, not `RowScope`, so ordinary policy rows cannot express `All`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyObligations {
    row_scope: Option<vocab::ScopedTenant>,
    field_mask: Vec<AttributeKey>,
}

impl PolicyObligations {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn new(row_scope: Option<vocab::ScopedTenant>, field_mask: Vec<AttributeKey>) -> Self {
        Self {
            row_scope,
            field_mask,
        }
    }

    pub fn row_scope(&self) -> Option<vocab::ScopedTenant> {
        self.row_scope
    }

    pub fn field_mask(&self) -> &[AttributeKey] {
        &self.field_mask
    }

    pub fn is_empty(&self) -> bool {
        self.row_scope.is_none() && self.field_mask.is_empty()
    }

    fn merge(&mut self, other: &Self) {
        if self.row_scope.is_none() {
            self.row_scope = other.row_scope;
        }
        for key in &other.field_mask {
            if !self.field_mask.iter().any(|existing| existing == key) {
                self.field_mask.push(key.clone());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Operator / PolicyEffect / PolicyCondition
// ---------------------------------------------------------------------------

/// 比较 operator。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Operator {
    Eq(AttributeValue),
    Ne(AttributeValue),
    Like(GlobPattern),
    Gt(AttributeValue),
    Lt(AttributeValue),
    EqAttr(AttributeKey),
}

/// 规则效果（命中后贡献 Allow 或 Deny；deny-overrides 下 Deny 压过 Allow）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyEffect {
    Allow,
    Deny,
}

/// `like` glob 模式 newtype（私有字段；parse funnel fail-closed）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobPattern(String);

impl GlobPattern {
    pub fn parse(raw: &str) -> Result<Self, GlobPatternError> {
        super::validate_token(raw, GLOB_MAX_LEN, |c| c.is_ascii_graphic()).map_err(
            |r| match r {
                super::Reason::Empty => GlobPatternError::Empty,
                super::Reason::Format => GlobPatternError::Format,
            },
        )?;
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// glob 模式解析错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GlobPatternError {
    #[error("glob pattern is empty")]
    Empty,
    #[error("glob pattern is too long or has invalid characters")]
    Format,
}

/// 单条规则条件（属性键 + 比较 operator）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyCondition {
    attribute_key: AttributeKey,
    operator: Operator,
}

impl PolicyCondition {
    pub fn new(attribute_key: AttributeKey, operator: Operator) -> Self {
        Self {
            attribute_key,
            operator,
        }
    }

    pub fn attribute_key(&self) -> &AttributeKey {
        &self.attribute_key
    }

    pub fn operator(&self) -> &Operator {
        &self.operator
    }
}

/// 策略规则（条件 + 效果 + obligations；不 derive Serialize——域类型）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    condition: PolicyCondition,
    effect: PolicyEffect,
    obligations: PolicyObligations,
}

impl PolicyRule {
    /// 兼容域内纯求值测试的空-obligation 构造器。
    #[cfg(test)]
    pub(crate) fn new(
        attribute_key: AttributeKey,
        operator: Operator,
        effect: PolicyEffect,
    ) -> Self {
        Self::with_obligations(
            PolicyCondition::new(attribute_key, operator),
            effect,
            PolicyObligations::empty(),
        )
    }

    pub fn with_obligations(
        condition: PolicyCondition,
        effect: PolicyEffect,
        obligations: PolicyObligations,
    ) -> Self {
        Self {
            condition,
            effect,
            obligations,
        }
    }

    pub fn condition(&self) -> &PolicyCondition {
        &self.condition
    }

    pub fn attribute_key(&self) -> &AttributeKey {
        self.condition.attribute_key()
    }

    pub fn operator(&self) -> &Operator {
        self.condition.operator()
    }

    pub fn effect(&self) -> PolicyEffect {
        self.effect
    }

    pub fn obligations(&self) -> &PolicyObligations {
        &self.obligations
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// ABAC durable policy（tenant + route scope + version + effective window + rules）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    id: PolicyId,
    tenant: vocab::TenantId,
    route_scope: PolicyRouteScope,
    version: PolicyVersion,
    effective_from: SystemTime,
    effective_until: Option<SystemTime>,
    rules: Vec<PolicyRule>,
}

impl Policy {
    /// 域内测试用构造器：默认 version=1、立即生效、不带 route 约束。
    #[cfg(test)]
    pub(crate) fn new(id: PolicyId, tenant: vocab::TenantId, rules: Vec<PolicyRule>) -> Self {
        Self {
            id,
            tenant,
            route_scope: PolicyRouteScope::new_unchecked("test.contract", "test:permission"),
            version: PolicyVersion::first(),
            effective_from: SystemTime::UNIX_EPOCH,
            effective_until: None,
            rules,
        }
    }

    /// 跨 crate 受控重建 funnel（postgres adapter 从持久化行重建）。
    pub fn hydrate(
        id: &str,
        tenant: vocab::TenantId,
        route_scope: PolicyRouteScope,
        version: u32,
        effective_from: SystemTime,
        effective_until: Option<SystemTime>,
        rules: Vec<PolicyRule>,
    ) -> Result<Self, IdentityError> {
        if effective_until.is_some_and(|until| until <= effective_from) {
            return Err(IdentityError::InvalidPolicy);
        }
        Ok(Self {
            id: PolicyId::parse(id).map_err(|_| IdentityError::InvalidPolicy)?,
            tenant,
            route_scope,
            version: PolicyVersion::new(version)?,
            effective_from,
            effective_until,
            rules,
        })
    }

    /// 构建新的 authoring policy；新 row 的 CAS version 固定从 1 开始。
    pub fn build(
        id: &str,
        tenant: vocab::TenantId,
        route_scope: PolicyRouteScope,
        effective_from: SystemTime,
        effective_until: Option<SystemTime>,
        rules: Vec<PolicyRule>,
    ) -> Result<Self, IdentityError> {
        Self::hydrate(
            id,
            tenant,
            route_scope,
            1,
            effective_from,
            effective_until,
            rules,
        )
    }

    pub fn id(&self) -> &PolicyId {
        &self.id
    }

    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    pub fn route_scope(&self) -> &PolicyRouteScope {
        &self.route_scope
    }

    pub fn version(&self) -> PolicyVersion {
        self.version
    }

    pub fn effective_from(&self) -> SystemTime {
        self.effective_from
    }

    pub fn effective_until(&self) -> Option<SystemTime> {
        self.effective_until
    }

    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    #[cfg(test)]
    pub(crate) fn with_version(self, version: PolicyVersion) -> Self {
        Self { version, ..self }
    }

    #[cfg(test)]
    pub(crate) fn is_effective_at(&self, at: SystemTime) -> bool {
        self.effective_from <= at && self.effective_until.is_none_or(|until| at < until)
    }
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PolicyEvaluation {
    NoMatch,
    Allow(PolicyObligations),
    Deny,
}

impl PolicyEvaluation {
    #[cfg(test)]
    pub(crate) fn route_allows(&self) -> bool {
        matches!(self, Self::Allow(obligations) if obligations.is_empty())
    }

    #[cfg(test)]
    pub(crate) fn to_decision(&self) -> vocab::Decision {
        match self {
            Self::Allow(_) => vocab::Decision::Allow,
            Self::NoMatch | Self::Deny => vocab::Decision::Deny,
        }
    }
}

pub(crate) fn evaluate_abac_for_tenant(
    tenant: Option<vocab::TenantId>,
    attrs: &[AbacAttribute],
    policy: &Policy,
) -> PolicyEvaluation {
    let Some(tenant) = tenant else {
        return PolicyEvaluation::Deny;
    };
    if policy.tenant() != tenant || has_duplicate_key(attrs) {
        return PolicyEvaluation::Deny;
    }

    let mut obligations = PolicyObligations::empty();
    let mut saw_allow = false;
    for rule in policy.rules() {
        if !rule_matches(rule, attrs) {
            continue;
        }
        match rule.effect() {
            PolicyEffect::Deny => return PolicyEvaluation::Deny,
            PolicyEffect::Allow => {
                saw_allow = true;
                obligations.merge(rule.obligations());
            }
        }
    }
    if saw_allow {
        PolicyEvaluation::Allow(obligations)
    } else {
        PolicyEvaluation::NoMatch
    }
}

pub(crate) fn evaluate_policies_for_tenant(
    tenant: Option<vocab::TenantId>,
    attrs: &[AbacAttribute],
    policies: &[Policy],
) -> PolicyEvaluation {
    let mut obligations = PolicyObligations::empty();
    let mut saw_allow = false;
    for policy in policies {
        match evaluate_abac_for_tenant(tenant, attrs, policy) {
            PolicyEvaluation::Deny => return PolicyEvaluation::Deny,
            PolicyEvaluation::NoMatch => {}
            PolicyEvaluation::Allow(next) => {
                saw_allow = true;
                obligations.merge(&next);
            }
        }
    }
    if saw_allow {
        PolicyEvaluation::Allow(obligations)
    } else {
        PolicyEvaluation::NoMatch
    }
}

/// 旧二值 ABAC 求值入口：NoMatch 也按 Deny 落地。
#[cfg(test)]
pub(crate) fn evaluate_abac(
    principal: &authn::Principal,
    attrs: &[AbacAttribute],
    policy: &Policy,
) -> vocab::Decision {
    evaluate_abac_for_tenant(principal.tenant(), attrs, policy).to_decision()
}

fn rule_matches(rule: &PolicyRule, attrs: &[AbacAttribute]) -> bool {
    let Some(actual) = find_attr(attrs, rule.attribute_key()) else {
        return false;
    };
    match rule.operator() {
        Operator::Eq(expected) => actual == expected,
        Operator::Ne(expected) => actual != expected,
        Operator::Like(pattern) => glob_match(pattern.as_str(), actual.as_str()),
        Operator::Gt(threshold) => numeric_cmp(actual, threshold, std::cmp::Ordering::Greater),
        Operator::Lt(threshold) => numeric_cmp(actual, threshold, std::cmp::Ordering::Less),
        Operator::EqAttr(other_key) => {
            find_attr(attrs, other_key).is_some_and(|other| other == actual)
        }
    }
}

fn find_attr<'a>(attrs: &'a [AbacAttribute], key: &AttributeKey) -> Option<&'a AttributeValue> {
    attrs
        .iter()
        .find(|a| a.key() == key)
        .map(AbacAttribute::value)
}

fn has_duplicate_key(attrs: &[AbacAttribute]) -> bool {
    let mut seen = std::collections::HashSet::with_capacity(attrs.len());
    !attrs.iter().all(|a| seen.insert(a.key()))
}

fn numeric_cmp(
    actual: &AttributeValue,
    threshold: &AttributeValue,
    want: std::cmp::Ordering,
) -> bool {
    match (numeric(actual.as_str()), numeric(threshold.as_str())) {
        (Some(a), Some(b)) => a.partial_cmp(&b) == Some(want),
        _ => false,
    }
}

fn numeric(raw: &str) -> Option<f64> {
    raw.parse::<f64>().ok().filter(|n| n.is_finite())
}

fn glob_match(pattern: &str, value: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let val: Vec<char> = value.chars().collect();
    let (mut p, mut v) = (0usize, 0usize);
    let (mut star, mut mark): (Option<usize>, usize) = (None, 0);
    while v < val.len() {
        if p < pat.len() && (pat[p] == '?' || pat[p] == val[v]) {
            p += 1;
            v += 1;
        } else if p < pat.len() && pat[p] == '*' {
            star = Some(p);
            mark = v;
            p += 1;
        } else if let Some(sp) = star {
            p = sp + 1;
            mark += 1;
            v = mark;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == '*' {
        p += 1;
    }
    p == pat.len()
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::{
        AbacAttribute, GlobPattern, Operator, Policy, PolicyCondition, PolicyEffect,
        PolicyEvaluation, PolicyObligations, PolicyRouteScope, PolicyRule, evaluate_abac,
        evaluate_abac_for_tenant, evaluate_policies_for_tenant,
    };
    use crate::domain::{AttributeKey, AttributeValue, PolicyId};
    use authn::Principal;
    use rstest::rstest;
    use vocab::tenant::{ScopedTenant, TenantId};
    use vocab::{Decision, PrincipalKind};

    const TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const TENANT_B: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn tid(raw: &str) -> TenantId {
        #[allow(clippy::expect_used)]
        TenantId::parse(raw).expect("canonical tenant uuid")
    }

    fn akey(raw: &str) -> AttributeKey {
        #[allow(clippy::expect_used)]
        AttributeKey::parse(raw).expect("valid attribute key")
    }

    fn aval(raw: &str) -> AttributeValue {
        AttributeValue::new(raw)
    }

    fn attr(key: &str, value: &str) -> AbacAttribute {
        AbacAttribute::new(akey(key), aval(value))
    }

    fn glob(raw: &str) -> GlobPattern {
        #[allow(clippy::expect_used)]
        GlobPattern::parse(raw).expect("valid glob pattern")
    }

    fn pid(raw: &str) -> PolicyId {
        #[allow(clippy::expect_used)]
        PolicyId::parse(raw).expect("valid policy id")
    }

    fn user(tenant: Option<&str>) -> Principal {
        authn::test_support::principal(PrincipalKind::User, "alice", tenant.map(tid))
    }

    fn rule(key: &str, operator: Operator, effect: PolicyEffect) -> PolicyRule {
        PolicyRule::new(akey(key), operator, effect)
    }

    fn eval(attrs: &[AbacAttribute], rules: Vec<PolicyRule>) -> Decision {
        let policy = Policy::new(pid("pol-1"), tid(TENANT_A), rules);
        evaluate_abac(&user(Some(TENANT_A)), attrs, &policy)
    }

    #[test]
    fn entity_accessors_echo() {
        let a = attr("dept", "eng");
        assert_eq!(a.key().as_str(), "dept");
        assert_eq!(a.value().as_str(), "eng");

        let r = rule("dept", Operator::Eq(aval("eng")), PolicyEffect::Allow);
        assert_eq!(r.attribute_key().as_str(), "dept");
        assert!(matches!(r.operator(), Operator::Eq(_)));
        assert_eq!(r.effect(), PolicyEffect::Allow);
        assert!(r.obligations().is_empty());

        let p = Policy::new(pid("pol-1"), tid(TENANT_A), vec![r]);
        assert_eq!(p.id().as_str(), "pol-1");
        assert_eq!(p.tenant(), tid(TENANT_A));
        assert_eq!(p.version().get(), 1);
        assert!(p.is_effective_at(SystemTime::UNIX_EPOCH + Duration::from_secs(1)));
        assert_eq!(p.rules().len(), 1);
    }

    #[test]
    fn hydrate_rejects_invalid_version_and_window() -> Result<(), crate::domain::IdentityError> {
        let scope = PolicyRouteScope::parse("identity.roles", "identity:role:read")?;
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        assert!(matches!(
            Policy::hydrate("pol-1", tid(TENANT_A), scope.clone(), 0, base, None, vec![]),
            Err(crate::domain::IdentityError::InvalidPolicy)
        ));
        assert!(matches!(
            Policy::hydrate("pol-1", tid(TENANT_A), scope, 1, base, Some(base), vec![]),
            Err(crate::domain::IdentityError::InvalidPolicy)
        ));
        Ok(())
    }

    enum Op {
        EqTrue,
        EqFalse,
        EqMissing,
        NeTrue,
        NeFalse,
        NeMissing,
        LikeStar,
        LikeStarMiss,
        LikeQuestion,
        LikeQuestionMiss,
        GtTrue,
        GtFalse,
        GtEqual,
        GtTypeMismatch,
        LtTrue,
        LtFalse,
        LtEqual,
        EqAttrTrue,
        EqAttrFalse,
        EqAttrMissing,
    }

    fn build_op(op: &Op) -> (Vec<AbacAttribute>, PolicyRule) {
        let allow = PolicyEffect::Allow;
        match op {
            Op::EqTrue => (
                vec![attr("role", "admin")],
                rule("role", Operator::Eq(aval("admin")), allow),
            ),
            Op::EqFalse => (
                vec![attr("role", "user")],
                rule("role", Operator::Eq(aval("admin")), allow),
            ),
            Op::EqMissing => (vec![], rule("role", Operator::Eq(aval("admin")), allow)),
            Op::NeTrue => (
                vec![attr("role", "user")],
                rule("role", Operator::Ne(aval("admin")), allow),
            ),
            Op::NeFalse => (
                vec![attr("role", "admin")],
                rule("role", Operator::Ne(aval("admin")), allow),
            ),
            Op::NeMissing => (vec![], rule("role", Operator::Ne(aval("admin")), allow)),
            Op::LikeStar => (
                vec![attr("path", "/docs/a/b")],
                rule("path", Operator::Like(glob("/docs/*")), allow),
            ),
            Op::LikeStarMiss => (
                vec![attr("path", "/etc/passwd")],
                rule("path", Operator::Like(glob("/docs/*")), allow),
            ),
            Op::LikeQuestion => (
                vec![attr("code", "ab")],
                rule("code", Operator::Like(glob("a?")), allow),
            ),
            Op::LikeQuestionMiss => (
                vec![attr("code", "abc")],
                rule("code", Operator::Like(glob("a?")), allow),
            ),
            Op::GtTrue => (
                vec![attr("level", "5")],
                rule("level", Operator::Gt(aval("3")), allow),
            ),
            Op::GtFalse => (
                vec![attr("level", "2")],
                rule("level", Operator::Gt(aval("3")), allow),
            ),
            Op::GtEqual => (
                vec![attr("level", "3")],
                rule("level", Operator::Gt(aval("3")), allow),
            ),
            Op::GtTypeMismatch => (
                vec![attr("level", "high")],
                rule("level", Operator::Gt(aval("3")), allow),
            ),
            Op::LtTrue => (
                vec![attr("level", "2")],
                rule("level", Operator::Lt(aval("3")), allow),
            ),
            Op::LtFalse => (
                vec![attr("level", "5")],
                rule("level", Operator::Lt(aval("3")), allow),
            ),
            Op::LtEqual => (
                vec![attr("level", "3")],
                rule("level", Operator::Lt(aval("3")), allow),
            ),
            Op::EqAttrTrue => (
                vec![attr("owner", "alice"), attr("requester", "alice")],
                rule("owner", Operator::EqAttr(akey("requester")), allow),
            ),
            Op::EqAttrFalse => (
                vec![attr("owner", "alice"), attr("requester", "bob")],
                rule("owner", Operator::EqAttr(akey("requester")), allow),
            ),
            Op::EqAttrMissing => (
                vec![attr("owner", "alice")],
                rule("owner", Operator::EqAttr(akey("requester")), allow),
            ),
        }
    }

    #[rstest]
    #[case::eq_true(Op::EqTrue, Decision::Allow)]
    #[case::eq_false(Op::EqFalse, Decision::Deny)]
    #[case::eq_missing(Op::EqMissing, Decision::Deny)]
    #[case::ne_true(Op::NeTrue, Decision::Allow)]
    #[case::ne_false(Op::NeFalse, Decision::Deny)]
    #[case::ne_missing(Op::NeMissing, Decision::Deny)]
    #[case::like_star(Op::LikeStar, Decision::Allow)]
    #[case::like_star_miss(Op::LikeStarMiss, Decision::Deny)]
    #[case::like_question(Op::LikeQuestion, Decision::Allow)]
    #[case::like_question_miss(Op::LikeQuestionMiss, Decision::Deny)]
    #[case::gt_true(Op::GtTrue, Decision::Allow)]
    #[case::gt_false(Op::GtFalse, Decision::Deny)]
    #[case::gt_equal(Op::GtEqual, Decision::Deny)]
    #[case::gt_type_mismatch(Op::GtTypeMismatch, Decision::Deny)]
    #[case::lt_true(Op::LtTrue, Decision::Allow)]
    #[case::lt_false(Op::LtFalse, Decision::Deny)]
    #[case::lt_equal(Op::LtEqual, Decision::Deny)]
    #[case::eq_attr_true(Op::EqAttrTrue, Decision::Allow)]
    #[case::eq_attr_false(Op::EqAttrFalse, Decision::Deny)]
    #[case::eq_attr_missing(Op::EqAttrMissing, Decision::Deny)]
    fn operator_cases(#[case] op: Op, #[case] want: Decision) {
        let (attrs, r) = build_op(&op);
        assert_eq!(eval(&attrs, vec![r]), want);
    }

    #[rstest]
    #[case::deny_after_allow(false)]
    #[case::deny_before_allow(true)]
    fn deny_overrides(#[case] deny_first: bool) {
        let attrs = vec![attr("role", "admin")];
        let allow = rule("role", Operator::Eq(aval("admin")), PolicyEffect::Allow);
        let deny = rule("role", Operator::Eq(aval("admin")), PolicyEffect::Deny);
        let rules = if deny_first {
            vec![deny, allow]
        } else {
            vec![allow, deny]
        };
        assert_eq!(eval(&attrs, rules), Decision::Deny);
    }

    #[test]
    fn deny_hit_with_allow_miss_still_denies() {
        let attrs = vec![attr("role", "admin")];
        let allow = rule("role", Operator::Eq(aval("user")), PolicyEffect::Allow);
        let deny = rule("role", Operator::Eq(aval("admin")), PolicyEffect::Deny);
        assert_eq!(eval(&attrs, vec![allow, deny]), Decision::Deny);
    }

    #[test]
    fn duplicate_attribute_key_denies() {
        let attrs = vec![attr("clearance", "public"), attr("clearance", "secret")];
        let allow = rule(
            "clearance",
            Operator::Eq(aval("public")),
            PolicyEffect::Allow,
        );
        assert_eq!(eval(&attrs, vec![allow]), Decision::Deny);
    }

    #[test]
    fn default_deny_and_single_allow() {
        let allow = rule("role", Operator::Eq(aval("admin")), PolicyEffect::Allow);
        assert_eq!(
            eval(&[attr("role", "user")], vec![allow.clone()]),
            Decision::Deny
        );
        assert_eq!(eval(&[attr("role", "admin")], vec![allow]), Decision::Allow);
    }

    #[test]
    fn empty_rule_set_denies() {
        assert_eq!(eval(&[attr("role", "admin")], vec![]), Decision::Deny);
    }

    #[rstest]
    #[case::cross_tenant(user(Some(TENANT_B)))]
    #[case::no_tenant(authn::test_support::principal(PrincipalKind::Service, "svc", None))]
    fn tenant_gate_denies(#[case] principal: Principal) {
        let policy = Policy::new(
            pid("pol-1"),
            tid(TENANT_A),
            vec![rule(
                "role",
                Operator::Eq(aval("admin")),
                PolicyEffect::Allow,
            )],
        );
        assert_eq!(
            evaluate_abac(&principal, &[attr("role", "admin")], &policy),
            Decision::Deny
        );
    }

    #[test]
    fn obligations_are_preserved_but_route_allow_requires_empty_obligations() {
        let obligations = PolicyObligations::new(Some(ScopedTenant::Tenant), vec![akey("email")]);
        let rule = PolicyRule::with_obligations(
            PolicyCondition::new(akey("role"), Operator::Eq(aval("admin"))),
            PolicyEffect::Allow,
            obligations.clone(),
        );
        let policy = Policy::new(pid("pol-1"), tid(TENANT_A), vec![rule]);
        let got = evaluate_abac_for_tenant(Some(tid(TENANT_A)), &[attr("role", "admin")], &policy);
        assert_eq!(got, PolicyEvaluation::Allow(obligations));
        assert!(
            !got.route_allows(),
            "route gate cannot discharge obligations"
        );
    }

    #[test]
    fn multiple_policies_merge_allows_and_deny_overrides() {
        let empty_allow = Policy::new(
            pid("allow-1"),
            tid(TENANT_A),
            vec![rule(
                "role",
                Operator::Eq(aval("admin")),
                PolicyEffect::Allow,
            )],
        );
        let obligated_allow = Policy::new(
            pid("allow-2"),
            tid(TENANT_A),
            vec![PolicyRule::with_obligations(
                PolicyCondition::new(akey("dept"), Operator::Eq(aval("eng"))),
                PolicyEffect::Allow,
                PolicyObligations::new(Some(ScopedTenant::Tenant), vec![]),
            )],
        );
        let attrs = vec![attr("role", "admin"), attr("dept", "eng")];
        let got = evaluate_policies_for_tenant(
            Some(tid(TENANT_A)),
            &attrs,
            &[empty_allow, obligated_allow],
        );
        assert!(matches!(got, PolicyEvaluation::Allow(ref o) if !o.is_empty()));
        assert!(!got.route_allows());

        let deny = Policy::new(
            pid("deny-1"),
            tid(TENANT_A),
            vec![rule(
                "role",
                Operator::Eq(aval("admin")),
                PolicyEffect::Deny,
            )],
        );
        let got = evaluate_policies_for_tenant(Some(tid(TENANT_A)), &attrs, &[deny]);
        assert_eq!(got, PolicyEvaluation::Deny);
    }

    #[rstest]
    #[case::ok_literal("docs".to_string(), true)]
    #[case::ok_wildcards("a?b*c".to_string(), true)]
    #[case::ok_max_len("a".repeat(256), true)]
    #[case::empty(String::new(), false)]
    #[case::space("a b".to_string(), false)]
    #[case::tab("a\tb".to_string(), false)]
    #[case::null("a\u{0}b".to_string(), false)]
    #[case::newline("a\nb".to_string(), false)]
    #[case::non_ascii("café".to_string(), false)]
    #[case::too_long("a".repeat(257), false)]
    fn glob_pattern_parse_fail_closed(#[case] raw: String, #[case] ok: bool) {
        assert_eq!(GlobPattern::parse(&raw).is_ok(), ok);
    }

    #[rstest]
    #[case("*", "anything", true)]
    #[case("*", "", true)]
    #[case("a*", "abc", true)]
    #[case("a*", "xbc", false)]
    #[case("*c", "abc", true)]
    #[case("a*c", "abxyzc", true)]
    #[case("a*c", "abxyz", false)]
    #[case("a?c", "abc", true)]
    #[case("a?c", "ac", false)]
    #[case("a*b*c", "a-b-c", true)]
    #[case("a*b*c", "abc", true)]
    #[case("a*b*c", "a-b-b-c", true)]
    #[case("a*b*c", "aXc", false)]
    #[case("*", "a/b/c", true)]
    #[case("/docs/*", "/docs/x/y", true)]
    #[case("abc", "abc", true)]
    #[case("abc", "abd", false)]
    fn glob_match_cases(#[case] pattern: &str, #[case] value: &str, #[case] want: bool) {
        assert_eq!(super::glob_match(pattern, value), want);
    }
}
