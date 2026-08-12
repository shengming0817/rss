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
//! ref: casbin/casbin-rs src/model/function_map.rs@52bc1ad57371aef1b16399cc0b5f338c4b484539
//! （动态 function registry）；RSS 明确拒绝该扩展面，operator 保持 closed enum + exhaustive seam。

use std::time::SystemTime;

use super::{
    AttributeKey, DecimalValue, IdentityError, PolicyId, PolicyValue, PolicyValueError,
    PolicyValueRef, PolicyValueType,
};
use vocab::RoutePermissionId;

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
    value: PolicyValue,
}

impl AbacAttribute {
    /// 构造 ABAC 属性。
    pub fn new(key: AttributeKey, value: PolicyValue) -> Self {
        Self { key, value }
    }

    /// 取属性键引用。
    pub fn key(&self) -> &AttributeKey {
        &self.key
    }

    /// 取属性值引用。
    pub fn value(&self) -> &PolicyValue {
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
    permission: RoutePermissionId,
}

impl PolicyRouteScope {
    pub fn parse(contract_id: &str, permission: &str) -> Result<Self, IdentityError> {
        validate_route_token(contract_id)?;
        let permission =
            RoutePermissionId::parse(permission).map_err(|_| IdentityError::InvalidPolicy)?;
        Ok(Self {
            contract_id: contract_id.to_string(),
            permission,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_unchecked(
        contract_id: impl Into<String>,
        permission: RoutePermissionId,
    ) -> Self {
        Self {
            contract_id: contract_id.into(),
            permission,
        }
    }

    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }

    pub fn permission(&self) -> RoutePermissionId {
        self.permission
    }

    pub fn matches(&self, contract_id: &str, permission: RoutePermissionId) -> bool {
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
/// Row-scope uses `RowScope`, not `RowScope`, so ordinary policy rows cannot express `All`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyObligations {
    row_scope: Option<rss_request_context::RowScope>,
    field_mask: Vec<AttributeKey>,
}

impl PolicyObligations {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn new(
        row_scope: Option<rss_request_context::RowScope>,
        field_mask: Vec<AttributeKey>,
    ) -> Self {
        Self {
            row_scope,
            field_mask,
        }
    }

    pub fn row_scope(&self) -> Option<rss_request_context::RowScope> {
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

/// PIP 属性键闭集：仅 `POLICY_ATTR_*` 常量可成为 typed attribute operand。
///
/// INVARIANT: ABAC-TYPED-ATTRIBUTE-PIP-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "tests::pip_attribute_key_parse_rejects_non_pip", anti_vacuity = "tests::pip_attribute_key_parse_accepts_closed_set" } — attribute operand 载荷只能是本类型；非 PIP 键在域内不可表达，
/// 外部字符串入口必须经 [`PipAttributeKey::parse`] fail-closed。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PipAttributeKey(AttributeKey);

/// `PipAttributeKey::parse` 失败：输入不是内置 PIP 键。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum PipAttributeKeyError {
    #[error("attribute operand is not a PIP policy attribute key")]
    NotPip,
}

impl PipAttributeKey {
    /// 解析 attribute operand 可引用的 PIP 键；仅命中 `POLICY_ATTR_*` 闭集，否则 fail-closed。
    pub fn parse(raw: &str) -> Result<Self, PipAttributeKeyError> {
        match raw {
            POLICY_ATTR_PRINCIPAL_KIND
            | POLICY_ATTR_PRINCIPAL_ID
            | POLICY_ATTR_TENANT_ID
            | POLICY_ATTR_CONTRACT_ID
            | POLICY_ATTR_PERMISSION
            | POLICY_ATTR_RESOURCE_ID => Ok(Self(AttributeKey::new(raw))),
            _ => Err(PipAttributeKeyError::NotPip),
        }
    }

    /// `principal.id` PIP 键（所有权 equality attribute operand 的标准 RHS）。
    pub fn principal_id() -> Self {
        Self(AttributeKey::new(POLICY_ATTR_PRINCIPAL_ID))
    }

    /// 取底层 [`AttributeKey`] 引用（求值用）。
    pub fn as_attribute_key(&self) -> &AttributeKey {
        &self.0
    }

    /// 取键字符串引用。
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

pub const POLICY_VALUE_SET_MAX_ITEMS: usize = 32;

/// Rejection reasons shared by the four closed operator families.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OperatorError {
    #[error("policy value set must not be empty")]
    EmptySet,
    #[error("policy value set exceeds 32 items")]
    SetTooLarge,
    #[error("policy value set must be homogeneous")]
    MixedSet,
    #[error("policy value set contains a duplicate")]
    DuplicateSetValue,
    #[error("string pattern is empty, too long, or contains control characters")]
    InvalidPattern,
    #[error("regular expression is invalid")]
    InvalidRegex,
}

/// Untrusted scalar carrier shared by HTTP and persistence hydration. String also carries the
/// exact decimal wire representation; the declared [`PolicyValueType`] selects its parser.
#[derive(Clone, PartialEq, Eq)]
pub enum PolicyScalarInput {
    String(String),
    Boolean(bool),
    Integer(i64),
}

impl std::fmt::Debug for PolicyScalarInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PolicyScalarInput(<redacted>)")
    }
}

/// Declared ABAC type plus the untrusted scalar shape observed at a serde boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct TypedPolicyValueInput {
    value_type: PolicyValueType,
    value: PolicyScalarInput,
}

impl TypedPolicyValueInput {
    pub const fn new(value_type: PolicyValueType, value: PolicyScalarInput) -> Self {
        Self { value_type, value }
    }
}

impl std::fmt::Debug for TypedPolicyValueInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypedPolicyValueInput")
            .field("value_type", &self.value_type)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ScalarOperandInput {
    Literal(TypedPolicyValueInput),
    Attribute {
        value_type: PolicyValueType,
        attribute: String,
    },
}

impl std::fmt::Debug for ScalarOperandInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScalarOperandInput(<redacted>)")
    }
}

/// Closed, serde-free operator hydration input. It deliberately permits wire-invalid scalar/type
/// combinations so every adapter must pass through the same fallible domain funnel.
#[derive(Clone, PartialEq, Eq)]
pub enum OperatorInput {
    Equality {
        predicate: EqualityPredicate,
        operand: ScalarOperandInput,
    },
    Ordering {
        predicate: OrderingPredicate,
        operand: ScalarOperandInput,
    },
    Membership {
        predicate: MembershipPredicate,
        value_type: PolicyValueType,
        values: Vec<PolicyScalarInput>,
    },
    String {
        predicate: StringPredicate,
        pattern: String,
    },
}

impl std::fmt::Debug for OperatorInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OperatorInput(<redacted>)")
    }
}

/// Stable, non-sensitive reasons emitted by the unique untrusted operator hydration funnel.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OperatorInputError {
    #[error("policy scalar shape does not match its declared type")]
    ScalarKindMismatch,
    #[error("operator family and operand combination is invalid")]
    InvalidCombination,
    #[error("attribute operand is not a supported PIP key")]
    InvalidPipAttribute,
    #[error("attribute value exceeds max length")]
    ValueTooLong,
    #[error("decimal value is not canonical")]
    InvalidDecimal,
    #[error("policy value set must not be empty")]
    EmptySet,
    #[error("policy value set exceeds 32 items")]
    SetTooLarge,
    #[error("policy value set must be homogeneous")]
    MixedSet,
    #[error("policy value set contains a duplicate")]
    DuplicateSetValue,
    #[error("string pattern is invalid")]
    InvalidPattern,
    #[error("regular expression is invalid")]
    InvalidRegex,
}

impl From<PolicyValueError> for OperatorInputError {
    fn from(value: PolicyValueError) -> Self {
        match value {
            PolicyValueError::TooLong => Self::ValueTooLong,
            PolicyValueError::InvalidDecimal => Self::InvalidDecimal,
        }
    }
}

impl From<OperatorError> for OperatorInputError {
    fn from(value: OperatorError) -> Self {
        match value {
            OperatorError::EmptySet => Self::EmptySet,
            OperatorError::SetTooLarge => Self::SetTooLarge,
            OperatorError::MixedSet => Self::MixedSet,
            OperatorError::DuplicateSetValue => Self::DuplicateSetValue,
            OperatorError::InvalidPattern => Self::InvalidPattern,
            OperatorError::InvalidRegex => Self::InvalidRegex,
        }
    }
}

/// Exact equality predicates. `Ne` never turns a missing or ill-typed value into a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EqualityPredicate {
    Eq,
    Ne,
}

/// Exact numeric ordering predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderingPredicate {
    Gt,
    Ge,
    Lt,
    Le,
}

/// Homogeneous-set membership predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipPredicate {
    In,
    NotIn,
}

/// Case-sensitive, bounded string predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringPredicate {
    StartsWith,
    EndsWith,
    Contains,
    Glob,
    Regex,
}

/// Equality RHS bound to the closed, intrinsically typed PIP key set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedAttributeOperand {
    attribute: PipAttributeKey,
}

impl TypedAttributeOperand {
    /// Builds an equality RHS from the closed PIP set. Every currently supported PIP attribute
    /// has an intrinsic string type, so callers cannot claim an impossible numeric/bool type.
    pub const fn new(attribute: PipAttributeKey) -> Self {
        Self { attribute }
    }

    pub const fn value_type(&self) -> PolicyValueType {
        PolicyValueType::String
    }

    pub fn attribute(&self) -> &PipAttributeKey {
        &self.attribute
    }
}

/// Equality compares either a typed literal or another closed PIP attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EqualityOperand {
    Literal(PolicyValue),
    Attribute(TypedAttributeOperand),
}

/// Numeric literal accepted by the ordering family.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum NumericValue {
    Integer(i64),
    Decimal(DecimalValue),
}

impl NumericValue {
    pub fn into_policy_value(self) -> PolicyValue {
        match self {
            Self::Integer(value) => PolicyValue::integer(value),
            Self::Decimal(value) => PolicyValue::from_decimal(value),
        }
    }

    pub fn from_policy_value(value: PolicyValue) -> Option<Self> {
        if let Some(integer) = value.integer_value() {
            Some(Self::Integer(integer))
        } else {
            value.decimal_value().cloned().map(Self::Decimal)
        }
    }
}

/// Ordering operand sealed to numeric literals until a numeric PIP key exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderingOperand {
    value: NumericValue,
}

impl OrderingOperand {
    pub const fn literal(value: NumericValue) -> Self {
        Self { value }
    }

    pub const fn value(&self) -> &NumericValue {
        &self.value
    }
}

/// Canonically sorted, homogeneous, unique set containing between 1 and 32 values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyValueSet {
    value_type: PolicyValueType,
    values: Vec<PolicyValue>,
}

impl PolicyValueSet {
    pub fn new(mut values: Vec<PolicyValue>) -> Result<Self, OperatorError> {
        let Some(first) = values.first() else {
            return Err(OperatorError::EmptySet);
        };
        if values.len() > POLICY_VALUE_SET_MAX_ITEMS {
            return Err(OperatorError::SetTooLarge);
        }
        let value_type = first.value_type();
        if values.iter().any(|value| value.value_type() != value_type) {
            return Err(OperatorError::MixedSet);
        }
        values.sort();
        if values.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(OperatorError::DuplicateSetValue);
        }
        Ok(Self { value_type, values })
    }

    pub const fn value_type(&self) -> PolicyValueType {
        self.value_type
    }

    pub fn values(&self) -> &[PolicyValue] {
        &self.values
    }

    fn contains(&self, actual: &PolicyValue) -> bool {
        actual.value_type() == self.value_type && self.values.binary_search(actual).is_ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EqualityOperator {
    predicate: EqualityPredicate,
    operand: EqualityOperand,
}

impl EqualityOperator {
    pub const fn new(predicate: EqualityPredicate, operand: EqualityOperand) -> Self {
        Self { predicate, operand }
    }
    pub const fn predicate(&self) -> EqualityPredicate {
        self.predicate
    }
    pub fn operand(&self) -> &EqualityOperand {
        &self.operand
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderingOperator {
    predicate: OrderingPredicate,
    operand: OrderingOperand,
}

impl OrderingOperator {
    pub const fn new(predicate: OrderingPredicate, operand: OrderingOperand) -> Self {
        Self { predicate, operand }
    }
    pub const fn predicate(&self) -> OrderingPredicate {
        self.predicate
    }
    pub fn operand(&self) -> &OrderingOperand {
        &self.operand
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipOperator {
    predicate: MembershipPredicate,
    operand: PolicyValueSet,
}

impl MembershipOperator {
    pub const fn new(predicate: MembershipPredicate, operand: PolicyValueSet) -> Self {
        Self { predicate, operand }
    }
    pub const fn predicate(&self) -> MembershipPredicate {
        self.predicate
    }
    pub fn operand(&self) -> &PolicyValueSet {
        &self.operand
    }
}

#[derive(Clone)]
pub struct StringOperator {
    predicate: StringPredicate,
    pattern: String,
    regex: Option<regex::Regex>,
}

impl std::fmt::Debug for StringOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StringOperator")
            .field("predicate", &self.predicate)
            .field("pattern", &"<redacted>")
            .finish()
    }
}

impl PartialEq for StringOperator {
    fn eq(&self, other: &Self) -> bool {
        self.predicate == other.predicate && self.pattern == other.pattern
    }
}
impl Eq for StringOperator {}

impl StringOperator {
    pub fn parse(predicate: StringPredicate, pattern: &str) -> Result<Self, OperatorError> {
        if pattern.is_empty()
            || pattern.len() > GLOB_MAX_LEN
            || pattern.chars().any(char::is_control)
        {
            return Err(OperatorError::InvalidPattern);
        }
        let regex = if predicate == StringPredicate::Regex {
            Some(regex::Regex::new(pattern).map_err(|_| OperatorError::InvalidRegex)?)
        } else {
            None
        };
        Ok(Self {
            predicate,
            pattern: pattern.to_string(),
            regex,
        })
    }

    pub const fn predicate(&self) -> StringPredicate {
        self.predicate
    }
    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}

/// RSS Common ABAC Profile：family 与 operand 的非法组合在类型层不可表达。
#[derive(Clone, PartialEq, Eq)]
pub struct Operator(OperatorKind);

#[derive(Debug, Clone, PartialEq, Eq)]
enum OperatorKind {
    Equality(EqualityOperator),
    Ordering(OrderingOperator),
    Membership(MembershipOperator),
    StringMatch(StringOperator),
}

impl std::fmt::Debug for Operator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Operator(<redacted>)")
    }
}

pub enum ScalarOperandRef<'a> {
    Literal(PolicyValueRef<'a>),
    Attribute(&'a PipAttributeKey),
}

pub enum OperatorRef<'a> {
    Equality {
        predicate: EqualityPredicate,
        operand: ScalarOperandRef<'a>,
    },
    Ordering {
        predicate: OrderingPredicate,
        value: PolicyValueRef<'a>,
    },
    Membership {
        predicate: MembershipPredicate,
        value_type: PolicyValueType,
        values: &'a [PolicyValue],
    },
    String {
        predicate: StringPredicate,
        pattern: &'a str,
    },
}

impl Operator {
    #[allow(non_snake_case)]
    pub(crate) const fn Equality(value: EqualityOperator) -> Self {
        Self(OperatorKind::Equality(value))
    }

    #[allow(non_snake_case)]
    pub(crate) const fn Ordering(value: OrderingOperator) -> Self {
        Self(OperatorKind::Ordering(value))
    }

    #[allow(non_snake_case)]
    pub(crate) const fn Membership(value: MembershipOperator) -> Self {
        Self(OperatorKind::Membership(value))
    }

    #[allow(non_snake_case)]
    pub(crate) const fn StringMatch(value: StringOperator) -> Self {
        Self(OperatorKind::StringMatch(value))
    }

    #[allow(dead_code)]
    pub(crate) const fn equal(value: PolicyValue) -> Self {
        Self::Equality(EqualityOperator::new(
            EqualityPredicate::Eq,
            EqualityOperand::Literal(value),
        ))
    }

    #[allow(dead_code)]
    pub(crate) const fn not_equal(value: PolicyValue) -> Self {
        Self::Equality(EqualityOperator::new(
            EqualityPredicate::Ne,
            EqualityOperand::Literal(value),
        ))
    }

    #[allow(dead_code)]
    pub(crate) const fn equal_attribute(attribute: PipAttributeKey) -> Self {
        Self::Equality(EqualityOperator::new(
            EqualityPredicate::Eq,
            EqualityOperand::Attribute(TypedAttributeOperand::new(attribute)),
        ))
    }

    #[allow(dead_code)]
    pub(crate) const fn ordering(predicate: OrderingPredicate, value: NumericValue) -> Self {
        Self::Ordering(OrderingOperator::new(
            predicate,
            OrderingOperand::literal(value),
        ))
    }

    #[allow(dead_code)]
    pub(crate) fn string(predicate: StringPredicate, pattern: &str) -> Result<Self, OperatorError> {
        StringOperator::parse(predicate, pattern).map(Self::StringMatch)
    }

    pub fn as_ref(&self) -> OperatorRef<'_> {
        match &self.0 {
            OperatorKind::Equality(operator) => OperatorRef::Equality {
                predicate: operator.predicate(),
                operand: match operator.operand() {
                    EqualityOperand::Literal(value) => ScalarOperandRef::Literal(value.as_ref()),
                    EqualityOperand::Attribute(value) => {
                        ScalarOperandRef::Attribute(value.attribute())
                    }
                },
            },
            OperatorKind::Ordering(operator) => OperatorRef::Ordering {
                predicate: operator.predicate(),
                value: match operator.operand().value() {
                    NumericValue::Integer(value) => PolicyValueRef::Integer(*value),
                    NumericValue::Decimal(value) => PolicyValueRef::Decimal(value),
                },
            },
            OperatorKind::Membership(operator) => OperatorRef::Membership {
                predicate: operator.predicate(),
                value_type: operator.operand().value_type(),
                values: operator.operand().values(),
            },
            OperatorKind::StringMatch(operator) => OperatorRef::String {
                predicate: operator.predicate(),
                pattern: operator.pattern(),
            },
        }
    }
}

impl TryFrom<TypedPolicyValueInput> for PolicyValue {
    type Error = OperatorInputError;

    fn try_from(input: TypedPolicyValueInput) -> Result<Self, Self::Error> {
        match (input.value_type, input.value) {
            (PolicyValueType::String, PolicyScalarInput::String(value)) => {
                Self::string(&value).map_err(Into::into)
            }
            (PolicyValueType::Decimal, PolicyScalarInput::String(value)) => {
                Self::decimal(&value).map_err(Into::into)
            }
            (PolicyValueType::Boolean, PolicyScalarInput::Boolean(value)) => {
                Ok(Self::boolean(value))
            }
            (PolicyValueType::Integer, PolicyScalarInput::Integer(value)) => {
                Ok(Self::integer(value))
            }
            _ => Err(OperatorInputError::ScalarKindMismatch),
        }
    }
}

impl TryFrom<OperatorInput> for Operator {
    type Error = OperatorInputError;

    fn try_from(input: OperatorInput) -> Result<Self, Self::Error> {
        match input {
            OperatorInput::Equality { predicate, operand } => {
                let operand = match operand {
                    ScalarOperandInput::Literal(value) => {
                        EqualityOperand::Literal(value.try_into()?)
                    }
                    ScalarOperandInput::Attribute {
                        value_type,
                        attribute,
                    } => {
                        if value_type != PolicyValueType::String {
                            return Err(OperatorInputError::InvalidCombination);
                        }
                        let attribute = PipAttributeKey::parse(&attribute)
                            .map_err(|_| OperatorInputError::InvalidPipAttribute)?;
                        EqualityOperand::Attribute(TypedAttributeOperand::new(attribute))
                    }
                };
                Ok(Self::Equality(EqualityOperator::new(predicate, operand)))
            }
            OperatorInput::Ordering { predicate, operand } => {
                let ScalarOperandInput::Literal(value) = operand else {
                    return Err(OperatorInputError::InvalidCombination);
                };
                let value = PolicyValue::try_from(value)?;
                let value = NumericValue::from_policy_value(value)
                    .ok_or(OperatorInputError::InvalidCombination)?;
                Ok(Self::Ordering(OrderingOperator::new(
                    predicate,
                    OrderingOperand::literal(value),
                )))
            }
            OperatorInput::Membership {
                predicate,
                value_type,
                values,
            } => {
                let values = values
                    .into_iter()
                    .map(|value| TypedPolicyValueInput::new(value_type, value).try_into())
                    .collect::<Result<Vec<PolicyValue>, OperatorInputError>>()?;
                let values = PolicyValueSet::new(values).map_err(OperatorInputError::from)?;
                Ok(Self::Membership(MembershipOperator::new(predicate, values)))
            }
            OperatorInput::String { predicate, pattern } => {
                StringOperator::parse(predicate, &pattern)
                    .map(Self::StringMatch)
                    .map_err(OperatorInputError::from)
            }
        }
    }
}

/// 规则效果（命中后贡献 Allow 或 Deny；deny-overrides 下 Deny 压过 Allow）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyEffect {
    Allow,
    Deny,
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
    tenant: rss_request_context::TenantId,
    route_scope: PolicyRouteScope,
    version: PolicyVersion,
    effective_from: SystemTime,
    effective_until: Option<SystemTime>,
    rules: Vec<PolicyRule>,
}

impl Policy {
    /// 域内测试用构造器：默认 version=1、立即生效、不带 route 约束。
    #[cfg(test)]
    pub(crate) fn new(
        id: PolicyId,
        tenant: rss_request_context::TenantId,
        rules: Vec<PolicyRule>,
    ) -> Self {
        Self {
            id,
            tenant,
            route_scope: PolicyRouteScope::new_unchecked(
                "test.contract",
                RoutePermissionId::IdentityPolicyRead,
            ),
            version: PolicyVersion::first(),
            effective_from: SystemTime::UNIX_EPOCH,
            effective_until: None,
            rules,
        }
    }

    /// 跨 crate 受控重建 funnel（postgres adapter 从持久化行重建）。
    pub fn hydrate(
        id: &str,
        tenant: rss_request_context::TenantId,
        route_scope: PolicyRouteScope,
        version: u32,
        effective_from: SystemTime,
        effective_until: Option<SystemTime>,
        rules: Vec<PolicyRule>,
    ) -> Result<Self, IdentityError> {
        if effective_until.is_some_and(|until| until <= effective_from) {
            return Err(IdentityError::InvalidPolicy);
        }
        for rule in &rules {
            let key = super::ResourceSecurityFactPolicyKey::classify(rule.attribute_key())
                .map_err(|_| IdentityError::InvalidPolicy)?;
            // #2111 installs the typed projection only. The sole production consumer is owned by
            // #2115, so generic durable policies must not mint a device-fact consumption path.
            if key.into_fact().is_some() {
                return Err(IdentityError::InvalidPolicy);
            }
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
        tenant: rss_request_context::TenantId,
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

    pub fn tenant(&self) -> rss_request_context::TenantId {
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
    Allow(PolicyAllowEvaluation),
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvaluatedPolicyReference {
    policy_id: PolicyId,
    version: PolicyVersion,
}

impl EvaluatedPolicyReference {
    pub(crate) fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }

    pub(crate) fn version(&self) -> PolicyVersion {
        self.version
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyAllowEvaluation {
    obligations: PolicyObligations,
    policies: Vec<EvaluatedPolicyReference>,
}

impl PolicyAllowEvaluation {
    pub(crate) fn obligations(&self) -> &PolicyObligations {
        &self.obligations
    }

    pub(crate) fn policies(&self) -> &[EvaluatedPolicyReference] {
        &self.policies
    }
}

impl PolicyEvaluation {
    #[cfg(test)]
    pub(crate) fn route_allows(&self) -> bool {
        matches!(self, Self::Allow(allow) if allow.obligations.is_empty())
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
    tenant: Option<rss_request_context::TenantId>,
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
        PolicyEvaluation::Allow(PolicyAllowEvaluation {
            obligations,
            policies: vec![EvaluatedPolicyReference {
                policy_id: policy.id().clone(),
                version: policy.version(),
            }],
        })
    } else {
        PolicyEvaluation::NoMatch
    }
}

pub(crate) fn evaluate_policies_for_tenant(
    tenant: Option<rss_request_context::TenantId>,
    attrs: &[AbacAttribute],
    policies: &[Policy],
) -> PolicyEvaluation {
    let mut policy_ids = policies.iter().map(Policy::id).collect::<Vec<_>>();
    policy_ids.sort_unstable();
    if policy_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return PolicyEvaluation::Deny;
    }

    let mut obligations = PolicyObligations::empty();
    let mut matched_policies = Vec::new();
    let mut saw_allow = false;
    for policy in policies {
        match evaluate_abac_for_tenant(tenant, attrs, policy) {
            PolicyEvaluation::Deny => return PolicyEvaluation::Deny,
            PolicyEvaluation::NoMatch => {}
            PolicyEvaluation::Allow(next) => {
                saw_allow = true;
                obligations.merge(next.obligations());
                matched_policies.extend_from_slice(next.policies());
            }
        }
    }
    if saw_allow {
        matched_policies.sort_unstable_by(|left, right| {
            left.policy_id
                .cmp(&right.policy_id)
                .then(left.version.cmp(&right.version))
        });
        if matched_policies
            .windows(2)
            .any(|pair| pair[0].policy_id == pair[1].policy_id)
        {
            return PolicyEvaluation::Deny;
        }
        PolicyEvaluation::Allow(PolicyAllowEvaluation {
            obligations,
            policies: matched_policies,
        })
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
    match &rule.operator().0 {
        OperatorKind::Equality(operator) => equality_matches(operator, actual, attrs),
        OperatorKind::Ordering(operator) => ordering_matches(operator, actual, attrs),
        OperatorKind::Membership(operator) => {
            let contains = operator.operand().contains(actual);
            match operator.predicate() {
                MembershipPredicate::In => contains,
                MembershipPredicate::NotIn => {
                    actual.value_type() == operator.operand().value_type() && !contains
                }
            }
        }
        OperatorKind::StringMatch(operator) => string_matches(operator, actual),
    }
}

fn find_attr<'a>(attrs: &'a [AbacAttribute], key: &AttributeKey) -> Option<&'a PolicyValue> {
    attrs
        .iter()
        .find(|a| a.key() == key)
        .map(AbacAttribute::value)
}

fn has_duplicate_key(attrs: &[AbacAttribute]) -> bool {
    let mut seen = std::collections::HashSet::with_capacity(attrs.len());
    !attrs.iter().all(|a| seen.insert(a.key()))
}

fn equality_matches(
    operator: &EqualityOperator,
    actual: &PolicyValue,
    attrs: &[AbacAttribute],
) -> bool {
    let expected = match operator.operand() {
        EqualityOperand::Literal(expected) => expected,
        EqualityOperand::Attribute(operand) => {
            if actual.value_type() != operand.value_type() {
                return false;
            }
            let Some(expected) = find_attr(attrs, operand.attribute().as_attribute_key()) else {
                return false;
            };
            expected
        }
    };
    if actual.value_type() != expected.value_type() {
        return false;
    }
    match operator.predicate() {
        EqualityPredicate::Eq => actual == expected,
        EqualityPredicate::Ne => actual != expected,
    }
}

fn ordering_matches(
    operator: &OrderingOperator,
    actual: &PolicyValue,
    _attrs: &[AbacAttribute],
) -> bool {
    let expected = operator.operand().value().clone().into_policy_value();
    if actual.value_type() != expected.value_type()
        || !matches!(
            actual.value_type(),
            PolicyValueType::Integer | PolicyValueType::Decimal
        )
    {
        return false;
    }
    let ordering = actual.cmp(&expected);
    match operator.predicate() {
        OrderingPredicate::Gt => ordering.is_gt(),
        OrderingPredicate::Ge => ordering.is_ge(),
        OrderingPredicate::Lt => ordering.is_lt(),
        OrderingPredicate::Le => ordering.is_le(),
    }
}

fn string_matches(operator: &StringOperator, actual: &PolicyValue) -> bool {
    let Some(actual) = actual.string_value() else {
        return false;
    };
    match operator.predicate() {
        StringPredicate::StartsWith => actual.starts_with(operator.pattern()),
        StringPredicate::EndsWith => actual.ends_with(operator.pattern()),
        StringPredicate::Contains => actual.contains(operator.pattern()),
        StringPredicate::Glob => glob_match(operator.pattern(), actual),
        StringPredicate::Regex => operator
            .regex
            .as_ref()
            .is_some_and(|regex| regex.is_match(actual)),
    }
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
        AbacAttribute, EqualityOperand, EqualityOperator, EqualityPredicate, MembershipOperator,
        MembershipPredicate, NumericValue, Operator, OperatorRef, OrderingOperand,
        OrderingOperator, OrderingPredicate, POLICY_ATTR_CONTRACT_ID, POLICY_ATTR_PERMISSION,
        POLICY_ATTR_PRINCIPAL_ID, POLICY_ATTR_PRINCIPAL_KIND, POLICY_ATTR_RESOURCE_ID,
        POLICY_ATTR_TENANT_ID, POLICY_VALUE_SET_MAX_ITEMS, PipAttributeKey, PipAttributeKeyError,
        Policy, PolicyCondition, PolicyEffect, PolicyEvaluation, PolicyObligations,
        PolicyRouteScope, PolicyRule, PolicyValueSet, PolicyVersion, StringOperator,
        StringPredicate, TypedAttributeOperand, evaluate_abac, evaluate_abac_for_tenant,
        evaluate_policies_for_tenant,
    };
    use crate::domain::{AttributeKey, DecimalValue, PolicyId, PolicyValue};
    use authn::Principal;
    use rss_request_context::PrincipalKind;
    use rss_request_context::RowScope;
    use rss_request_context::TenantId;
    use rstest::rstest;
    use vocab::Decision;

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

    fn aval(raw: &str) -> PolicyValue {
        PolicyValue::new(raw)
    }

    fn attr(key: &str, value: &str) -> AbacAttribute {
        AbacAttribute::new(akey(key), aval(value))
    }

    fn int_attr(key: &str, value: i64) -> AbacAttribute {
        AbacAttribute::new(akey(key), PolicyValue::integer(value))
    }

    fn eq(value: PolicyValue) -> Operator {
        Operator::Equality(EqualityOperator::new(
            EqualityPredicate::Eq,
            EqualityOperand::Literal(value),
        ))
    }

    fn ne(value: PolicyValue) -> Operator {
        Operator::Equality(EqualityOperator::new(
            EqualityPredicate::Ne,
            EqualityOperand::Literal(value),
        ))
    }

    fn glob(raw: &str) -> Operator {
        #[allow(clippy::expect_used)]
        let operator =
            StringOperator::parse(StringPredicate::Glob, raw).expect("valid glob pattern");
        Operator::StringMatch(operator)
    }

    fn gt(value: i64) -> Operator {
        Operator::Ordering(OrderingOperator::new(
            OrderingPredicate::Gt,
            OrderingOperand::literal(NumericValue::Integer(value)),
        ))
    }

    fn lt(value: i64) -> Operator {
        Operator::Ordering(OrderingOperator::new(
            OrderingPredicate::Lt,
            OrderingOperand::literal(NumericValue::Integer(value)),
        ))
    }

    fn eq_attr(attribute: PipAttributeKey) -> Operator {
        Operator::Equality(EqualityOperator::new(
            EqualityPredicate::Eq,
            EqualityOperand::Attribute(TypedAttributeOperand::new(attribute)),
        ))
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
        assert_eq!(a.value().string_value(), Some("eng"));

        let r = rule("dept", eq(aval("eng")), PolicyEffect::Allow);
        assert_eq!(r.attribute_key().as_str(), "dept");
        assert!(matches!(
            r.operator().as_ref(),
            OperatorRef::Equality { .. }
        ));
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

    #[test]
    fn hydrate_rejects_resource_security_facts_until_typed_device_handler_exists() {
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        for key in [
            "resource.owner",
            "resource.riskClass",
            "resource.location",
            "resource.software",
            "resource.fleet",
            "resource.inventory.kind",
        ] {
            let scope = PolicyRouteScope::parse("identity.roles", "identity:role:read")
                .expect("policy scope");
            let rules = vec![rule(key, eq(aval("value")), PolicyEffect::Allow)];
            assert!(matches!(
                Policy::hydrate("pol-resource", tid(TENANT_A), scope, 1, base, None, rules),
                Err(crate::domain::IdentityError::InvalidPolicy)
            ));
        }
    }

    #[test]
    fn canonical_operator_funnel_classifies_errors_and_redacts_debug() {
        use super::{
            OperatorInput, OperatorInputError, PolicyScalarInput, ScalarOperandInput,
            TypedPolicyValueInput,
        };
        use crate::domain::PolicyValueType;

        let mismatch = OperatorInput::Equality {
            predicate: EqualityPredicate::Eq,
            operand: ScalarOperandInput::Literal(TypedPolicyValueInput::new(
                PolicyValueType::Boolean,
                PolicyScalarInput::String("secret".to_string()),
            )),
        };
        assert_eq!(
            Operator::try_from(mismatch.clone()),
            Err(OperatorInputError::ScalarKindMismatch)
        );
        assert_eq!(format!("{mismatch:?}"), "OperatorInput(<redacted>)");

        let duplicate = OperatorInput::Membership {
            predicate: MembershipPredicate::In,
            value_type: PolicyValueType::String,
            values: vec![
                PolicyScalarInput::String("secret".to_string()),
                PolicyScalarInput::String("secret".to_string()),
            ],
        };
        assert_eq!(
            Operator::try_from(duplicate),
            Err(OperatorInputError::DuplicateSetValue)
        );

        let operator = Operator::try_from(OperatorInput::String {
            predicate: StringPredicate::Contains,
            pattern: "secret-pattern".to_string(),
        })
        .expect("valid canonical operator");
        assert_eq!(format!("{operator:?}"), "Operator(<redacted>)");
        assert!(matches!(
            operator.as_ref(),
            OperatorRef::String {
                predicate: StringPredicate::Contains,
                pattern: "secret-pattern"
            }
        ));
    }

    #[rstest]
    #[case::principal_kind(POLICY_ATTR_PRINCIPAL_KIND)]
    #[case::principal_id(POLICY_ATTR_PRINCIPAL_ID)]
    #[case::tenant_id(POLICY_ATTR_TENANT_ID)]
    #[case::contract_id(POLICY_ATTR_CONTRACT_ID)]
    #[case::permission(POLICY_ATTR_PERMISSION)]
    #[case::resource_id(POLICY_ATTR_RESOURCE_ID)]
    fn pip_attribute_key_parse_accepts_closed_set(#[case] raw: &str) {
        let key = PipAttributeKey::parse(raw).expect("PIP key");
        assert_eq!(key.as_str(), raw);
        assert_eq!(key.as_attribute_key().as_str(), raw);
    }

    #[rstest]
    #[case::secret_probe("secret.probe")]
    #[case::resource_owner("resource.owner")]
    #[case::empty("")]
    #[case::requester("requester")]
    fn pip_attribute_key_parse_rejects_non_pip(#[case] raw: &str) {
        assert_eq!(
            PipAttributeKey::parse(raw),
            Err(PipAttributeKeyError::NotPip)
        );
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
                rule("role", eq(aval("admin")), allow),
            ),
            Op::EqFalse => (
                vec![attr("role", "user")],
                rule("role", eq(aval("admin")), allow),
            ),
            Op::EqMissing => (vec![], rule("role", eq(aval("admin")), allow)),
            Op::NeTrue => (
                vec![attr("role", "user")],
                rule("role", ne(aval("admin")), allow),
            ),
            Op::NeFalse => (
                vec![attr("role", "admin")],
                rule("role", ne(aval("admin")), allow),
            ),
            Op::NeMissing => (vec![], rule("role", ne(aval("admin")), allow)),
            Op::LikeStar => (
                vec![attr("path", "/docs/a/b")],
                rule("path", glob("/docs/*"), allow),
            ),
            Op::LikeStarMiss => (
                vec![attr("path", "/etc/passwd")],
                rule("path", glob("/docs/*"), allow),
            ),
            Op::LikeQuestion => (vec![attr("code", "ab")], rule("code", glob("a?"), allow)),
            Op::LikeQuestionMiss => (vec![attr("code", "abc")], rule("code", glob("a?"), allow)),
            Op::GtTrue => (vec![int_attr("level", 5)], rule("level", gt(3), allow)),
            Op::GtFalse => (vec![int_attr("level", 2)], rule("level", gt(3), allow)),
            Op::GtEqual => (vec![int_attr("level", 3)], rule("level", gt(3), allow)),
            Op::GtTypeMismatch => (vec![attr("level", "high")], rule("level", gt(3), allow)),
            Op::LtTrue => (vec![int_attr("level", 2)], rule("level", lt(3), allow)),
            Op::LtFalse => (vec![int_attr("level", 5)], rule("level", lt(3), allow)),
            Op::LtEqual => (vec![int_attr("level", 3)], rule("level", lt(3), allow)),
            Op::EqAttrTrue => (
                vec![
                    attr("owner", "alice"),
                    attr(POLICY_ATTR_PRINCIPAL_ID, "alice"),
                ],
                rule("owner", eq_attr(PipAttributeKey::principal_id()), allow),
            ),
            Op::EqAttrFalse => (
                vec![
                    attr("owner", "alice"),
                    attr(POLICY_ATTR_PRINCIPAL_ID, "bob"),
                ],
                rule("owner", eq_attr(PipAttributeKey::principal_id()), allow),
            ),
            Op::EqAttrMissing => (
                vec![attr("owner", "alice")],
                rule("owner", eq_attr(PipAttributeKey::principal_id()), allow),
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
        let allow = rule("role", eq(aval("admin")), PolicyEffect::Allow);
        let deny = rule("role", eq(aval("admin")), PolicyEffect::Deny);
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
        let allow = rule("role", eq(aval("user")), PolicyEffect::Allow);
        let deny = rule("role", eq(aval("admin")), PolicyEffect::Deny);
        assert_eq!(eval(&attrs, vec![allow, deny]), Decision::Deny);
    }

    #[test]
    fn duplicate_attribute_key_denies() {
        let attrs = vec![attr("clearance", "public"), attr("clearance", "secret")];
        let allow = rule("clearance", eq(aval("public")), PolicyEffect::Allow);
        assert_eq!(eval(&attrs, vec![allow]), Decision::Deny);
    }

    #[test]
    fn default_deny_and_single_allow() {
        let allow = rule("role", eq(aval("admin")), PolicyEffect::Allow);
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
            vec![rule("role", eq(aval("admin")), PolicyEffect::Allow)],
        );
        assert_eq!(
            evaluate_abac(&principal, &[attr("role", "admin")], &policy),
            Decision::Deny
        );
    }

    #[test]
    fn obligations_are_preserved_but_route_allow_requires_empty_obligations() {
        let obligations = PolicyObligations::new(Some(RowScope::Tenant), vec![akey("email")]);
        let rule = PolicyRule::with_obligations(
            PolicyCondition::new(akey("role"), eq(aval("admin"))),
            PolicyEffect::Allow,
            obligations.clone(),
        );
        let policy = Policy::new(pid("pol-1"), tid(TENANT_A), vec![rule]);
        let got = evaluate_abac_for_tenant(Some(tid(TENANT_A)), &[attr("role", "admin")], &policy);
        assert!(matches!(
            got,
            PolicyEvaluation::Allow(ref allow) if allow.obligations() == &obligations
                && allow.policies().len() == 1
        ));
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
            vec![rule("role", eq(aval("admin")), PolicyEffect::Allow)],
        );
        let obligated_allow = Policy::new(
            pid("allow-2"),
            tid(TENANT_A),
            vec![PolicyRule::with_obligations(
                PolicyCondition::new(akey("dept"), eq(aval("eng"))),
                PolicyEffect::Allow,
                PolicyObligations::new(Some(RowScope::Tenant), vec![]),
            )],
        );
        let attrs = vec![attr("role", "admin"), attr("dept", "eng")];
        let got = evaluate_policies_for_tenant(
            Some(tid(TENANT_A)),
            &attrs,
            &[empty_allow, obligated_allow],
        );
        assert!(matches!(
            got,
            PolicyEvaluation::Allow(ref allow)
                if !allow.obligations().is_empty() && allow.policies().len() == 2
        ));
        assert!(!got.route_allows());

        let deny = Policy::new(
            pid("deny-1"),
            tid(TENANT_A),
            vec![rule("role", eq(aval("admin")), PolicyEffect::Deny)],
        );
        let got = evaluate_policies_for_tenant(Some(tid(TENANT_A)), &attrs, &[deny]);
        assert_eq!(got, PolicyEvaluation::Deny);
    }

    #[test]
    fn contributing_policy_lineage_is_sorted_and_duplicate_ids_fail_closed() {
        let make_policy = |id: &str, version: u32| {
            Policy::new(
                pid(id),
                tid(TENANT_A),
                vec![rule("role", eq(aval("admin")), PolicyEffect::Allow)],
            )
            .with_version(PolicyVersion::new(version).unwrap())
        };
        let attrs = [attr("role", "admin")];
        let evaluation = evaluate_policies_for_tenant(
            Some(tid(TENANT_A)),
            &attrs,
            &[make_policy("policy-z", 3), make_policy("policy-a", 2)],
        );
        let PolicyEvaluation::Allow(evaluation_allow) = evaluation else {
            panic!("matching policies must allow");
        };
        let lineage = evaluation_allow
            .policies()
            .iter()
            .map(|policy| (policy.policy_id().as_str(), policy.version().get()))
            .collect::<Vec<_>>();
        assert_eq!(lineage, vec![("policy-a", 2), ("policy-z", 3)]);

        let duplicate = evaluate_policies_for_tenant(
            Some(tid(TENANT_A)),
            &attrs,
            &[make_policy("same-policy", 1), make_policy("same-policy", 2)],
        );
        assert_eq!(duplicate, PolicyEvaluation::Deny);

        let no_match = Policy::new(
            pid("same-policy"),
            tid(TENANT_A),
            vec![rule("role", eq(aval("user")), PolicyEffect::Allow)],
        )
        .with_version(PolicyVersion::new(2).unwrap());
        let allow_plus_no_match = evaluate_policies_for_tenant(
            Some(tid(TENANT_A)),
            &attrs,
            &[make_policy("same-policy", 1), no_match],
        );
        assert_eq!(allow_plus_no_match, PolicyEvaluation::Deny);

        let no_match_v1 = Policy::new(
            pid("no-match-policy"),
            tid(TENANT_A),
            vec![rule("role", eq(aval("user")), PolicyEffect::Allow)],
        );
        let no_match_v2 = no_match_v1
            .clone()
            .with_version(PolicyVersion::new(2).unwrap());
        assert_eq!(
            evaluate_policies_for_tenant(Some(tid(TENANT_A)), &attrs, &[no_match_v1, no_match_v2],),
            PolicyEvaluation::Deny
        );
    }

    #[rstest]
    #[case::ok_literal("docs".to_string(), true)]
    #[case::ok_wildcards("a?b*c".to_string(), true)]
    #[case::ok_max_len("a".repeat(256), true)]
    #[case::empty(String::new(), false)]
    #[case::space("a b".to_string(), true)]
    #[case::tab("a\tb".to_string(), false)]
    #[case::null("a\u{0}b".to_string(), false)]
    #[case::newline("a\nb".to_string(), false)]
    #[case::non_ascii("café".to_string(), true)]
    #[case::too_long("a".repeat(257), false)]
    fn glob_pattern_parse_fail_closed(#[case] raw: String, #[case] ok: bool) {
        assert_eq!(
            StringOperator::parse(StringPredicate::Glob, &raw).is_ok(),
            ok
        );
    }

    #[test]
    fn value_set_is_bounded_homogeneous_unique_and_canonical() {
        assert_eq!(
            PolicyValueSet::new(Vec::new()),
            Err(super::OperatorError::EmptySet)
        );
        assert_eq!(
            PolicyValueSet::new(vec![aval("a"), PolicyValue::integer(1)]),
            Err(super::OperatorError::MixedSet)
        );
        assert_eq!(
            PolicyValueSet::new(vec![aval("a"), aval("a")]),
            Err(super::OperatorError::DuplicateSetValue)
        );
        assert_eq!(
            PolicyValueSet::new(
                (0..=POLICY_VALUE_SET_MAX_ITEMS)
                    .map(|value| PolicyValue::integer(value as i64))
                    .collect()
            ),
            Err(super::OperatorError::SetTooLarge)
        );
        let set = PolicyValueSet::new(vec![aval("ops"), aval("eng")]).expect("valid set");
        assert_eq!(set.values(), &[aval("eng"), aval("ops")]);
    }

    #[test]
    fn membership_and_regex_are_typed_and_fail_closed() {
        let set = PolicyValueSet::new(vec![aval("eng"), aval("ops")]).expect("valid set");
        let in_rule = rule(
            "dept",
            Operator::Membership(MembershipOperator::new(
                MembershipPredicate::In,
                set.clone(),
            )),
            PolicyEffect::Allow,
        );
        assert_eq!(eval(&[attr("dept", "ops")], vec![in_rule]), Decision::Allow);

        let not_in = rule(
            "dept",
            Operator::Membership(MembershipOperator::new(MembershipPredicate::NotIn, set)),
            PolicyEffect::Allow,
        );
        assert_eq!(eval(&[], vec![not_in.clone()]), Decision::Deny);
        assert_eq!(eval(&[int_attr("dept", 7)], vec![not_in]), Decision::Deny);

        let regex = StringOperator::parse(StringPredicate::Regex, r"^team-[0-9]+$").expect("regex");
        assert_eq!(
            eval(
                &[attr("name", "team-42")],
                vec![rule(
                    "name",
                    Operator::StringMatch(regex),
                    PolicyEffect::Allow
                )]
            ),
            Decision::Allow
        );
        assert!(StringOperator::parse(StringPredicate::Regex, "(").is_err());
    }

    #[test]
    fn common_profile_predicate_matrix_is_typed_and_fail_closed() {
        let allow = PolicyEffect::Allow;
        for (predicate, actual, expected) in [
            (OrderingPredicate::Gt, 3, Decision::Allow),
            (OrderingPredicate::Ge, 2, Decision::Allow),
            (OrderingPredicate::Lt, 1, Decision::Allow),
            (OrderingPredicate::Le, 2, Decision::Allow),
        ] {
            let operator = Operator::ordering(predicate, NumericValue::Integer(2));
            assert_eq!(
                eval(&[int_attr("n", actual)], vec![rule("n", operator, allow)]),
                expected
            );
        }
        let decimal = |raw: &str| PolicyValue::decimal(raw).expect("canonical decimal");
        let decimal_rule = Operator::ordering(
            OrderingPredicate::Gt,
            NumericValue::Decimal(DecimalValue::parse("1.09").expect("decimal")),
        );
        assert_eq!(
            eval(
                &[AbacAttribute::new(akey("n"), decimal("1.1"))],
                vec![rule("n", decimal_rule.clone(), allow)]
            ),
            Decision::Allow
        );
        assert_eq!(
            eval(&[attr("n", "1.1")], vec![rule("n", decimal_rule, allow)]),
            Decision::Deny
        );

        for predicate in [
            StringPredicate::StartsWith,
            StringPredicate::EndsWith,
            StringPredicate::Contains,
            StringPredicate::Glob,
            StringPredicate::Regex,
        ] {
            let pattern = match predicate {
                StringPredicate::StartsWith => "团队",
                StringPredicate::EndsWith => "Ops",
                StringPredicate::Contains => "队O",
                StringPredicate::Glob => "团队?ps",
                StringPredicate::Regex => r"^团队Ops$",
            };
            let miss = match predicate {
                StringPredicate::StartsWith => "小组Ops",
                StringPredicate::Glob => "团队opx",
                StringPredicate::EndsWith | StringPredicate::Contains | StringPredicate::Regex => {
                    "团队ops"
                }
            };
            let operator = Operator::string(predicate, pattern).expect("pattern");
            assert_eq!(
                eval(
                    &[attr("name", "团队Ops")],
                    vec![rule("name", operator.clone(), allow)]
                ),
                Decision::Allow
            );
            assert_eq!(
                eval(
                    &[attr("name", miss)],
                    vec![rule("name", operator.clone(), allow)]
                ),
                Decision::Deny
            );
            assert_eq!(
                eval(&[], vec![rule("name", operator.clone(), allow)]),
                Decision::Deny
            );
            assert_eq!(
                eval(&[int_attr("name", 1)], vec![rule("name", operator, allow)]),
                Decision::Deny
            );
        }

        let bool_set = PolicyValueSet::new(vec![
            PolicyValue::boolean(false),
            PolicyValue::boolean(true),
        ])
        .expect("set");
        for (predicate, actual, expected) in [
            (MembershipPredicate::In, true, Decision::Allow),
            (MembershipPredicate::NotIn, true, Decision::Deny),
        ] {
            let operator =
                Operator::Membership(MembershipOperator::new(predicate, bool_set.clone()));
            assert_eq!(
                eval(
                    &[AbacAttribute::new(
                        akey("enabled"),
                        PolicyValue::boolean(actual)
                    )],
                    vec![rule("enabled", operator, allow)]
                ),
                expected
            );
        }
        let one = PolicyValueSet::new(vec![PolicyValue::integer(1)]).expect("set");
        let not_in = Operator::Membership(MembershipOperator::new(MembershipPredicate::NotIn, one));
        assert_eq!(
            eval(&[int_attr("n", 2)], vec![rule("n", not_in.clone(), allow)]),
            Decision::Allow
        );
        assert_eq!(
            eval(&[attr("n", "2")], vec![rule("n", not_in.clone(), allow)]),
            Decision::Deny
        );
        assert_eq!(eval(&[], vec![rule("n", not_in, allow)]), Decision::Deny);

        let bool_eq = Operator::equal(PolicyValue::boolean(true));
        assert_eq!(
            eval(
                &[AbacAttribute::new(
                    akey("enabled"),
                    PolicyValue::boolean(true)
                )],
                vec![rule("enabled", bool_eq, allow)]
            ),
            Decision::Allow
        );
        let decimal_ne = Operator::not_equal(decimal("2.5"));
        assert_eq!(
            eval(
                &[AbacAttribute::new(akey("ratio"), decimal("2.6"))],
                vec![rule("ratio", decimal_ne, allow)]
            ),
            Decision::Allow
        );
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
