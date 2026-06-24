//! identity::domain::abac — ABAC 属性 / 策略值类型与策略求值（dylint rss_domain_no_serialize 守护区）。
//!
//! `AbacAttribute` / `PolicyRule`（typed `operator` + `effect`）/ `Policy` + `evaluate_abac`
//! （L0 纯计算，deny-overrides，fail-closed）。
//! 共享 newtype（`AttributeKey` / `AttributeValue` / `PolicyId`）定义在 `super`（`domain/mod.rs`）。
//!
//! # 求值语义（deny-overrides）
//!
//! `evaluate_abac` 遍历**命中**的规则：任一命中的 `Deny` 规则 → 整体 `Decision::Deny`（短路）；
//! 否则有命中的 `Allow` 规则 → `Allow`；无规则命中 → 默认 `Deny`（比 casbin 更严的 fail-closed
//! 缺省，对齐零信任）。跨租 / 类型不匹配 / 缺失属性均 fail-closed 判**不命中**（不 panic）。
//!
//! # 对标
//!
//! ref: casbin/casbin-rs src/effector.rs@fc425d4（`EffectKind{Allow,Indeterminate,Deny}`，
//! `DefaultEffectStream::push_effect`：单条 Deny 压过任意 Allow——本模块 deny-overrides 同形）。
//! 偏离：casbin 用 matcher 表达式 DSL，本模块用 typed `Operator` 枚举（eq/ne/like/gt/lt/eq_attr）
//! 做属性比较——更窄、编译期可枚举、无运行期表达式解析攻击面（优雅简洁 + AI-HARD）。

use super::{AttributeKey, AttributeValue, PolicyId};

/// `like` glob 模式长度上界（字节；防超长模式 DoS，parse 阶段 fail-closed）。
// reason: 仅被 GlobPattern::parse funnel 引用，生产调用方待 W 阶段（PR4/PR5）⇒ 非 test 构建 dead（ADR-004 C8）。
#[allow(dead_code)]
const GLOB_MAX_LEN: usize = 256;

// ---------------------------------------------------------------------------
// ABAC 属性
// ---------------------------------------------------------------------------

/// ABAC 属性（key-value 对；不 derive Serialize——域类型）。
// reason: 实现已落地，生产调用方（handler / authz 接线）待 W 阶段（PR4/PR5）；当前仅测试消费，
// 非 test 构建无调用方 ⇒ 仍 dead，保留 allow 以过 `-D warnings`（ADR-004 C8 遗留期 carve-out）。
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct AbacAttribute {
    key: AttributeKey,
    value: AttributeValue,
}

// reason: 同上（实现已落地，消费方待 W；ADR-004 C8）。
#[allow(dead_code)]
impl AbacAttribute {
    /// 构造 ABAC 属性。
    pub(crate) fn new(key: AttributeKey, value: AttributeValue) -> Self {
        Self { key, value }
    }

    /// 取属性键引用。
    pub(crate) fn key(&self) -> &AttributeKey {
        &self.key
    }

    /// 取属性值引用。
    pub(crate) fn value(&self) -> &AttributeValue {
        &self.value
    }
}

// ---------------------------------------------------------------------------
// Operator / PolicyEffect — 规则条件与效果
// ---------------------------------------------------------------------------

/// 比较 operator（operand 内联——illegal 组合「eq_attr 配字面值 / like 配非 glob」类型层不可表达，
/// AI-HARD；不 derive Serialize——域类型）。
///
/// - `Eq` / `Ne`：subject 属性值与字面值（不）等值。
/// - `Like`：subject 属性值 glob 匹配（`*` 任意序列 / `?` 单字符，无正则）。
/// - `Gt` / `Lt`：subject 属性值与字面值**数值**比较（双方 parse `f64` 且有限，否则类型不匹配不命中）。
/// - `EqAttr`：subject 属性值与**另一属性**值等值（跨属性比较）。
// reason: 同上（实现已落地，消费方待 W；变体仅测试构造 ⇒ 非 test 构建 dead；ADR-004 C8）。
#[allow(dead_code)]
#[derive(Debug)]
#[non_exhaustive]
pub(crate) enum Operator {
    Eq(AttributeValue),
    Ne(AttributeValue),
    Like(GlobPattern),
    Gt(AttributeValue),
    Lt(AttributeValue),
    EqAttr(AttributeKey),
}

/// 规则效果（命中后贡献 Allow 或 Deny；deny-overrides 下 Deny 压过 Allow）。
// reason: 同上（实现已落地，消费方待 W；ADR-004 C8）。
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum PolicyEffect {
    Allow,
    Deny,
}

/// `like` glob 模式 newtype（私有字段；parse funnel fail-closed：非空 / ≤256 字节 / ASCII graphic
/// 白名单——超长或含非法字符在 parse 阶段拒绝，防超长模式 DoS；不 derive Serialize——域类型）。
// reason: 同上（实现已落地，消费方待 W；ADR-004 C8）。
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GlobPattern(String);

// reason: 同上（实现已落地，消费方待 W；ADR-004 C8）。
#[allow(dead_code)]
impl GlobPattern {
    /// 解析 glob 模式；拒绝空 / 越界（>256 字节）/ 含 ASCII graphic 白名单外字符（fail-closed，永不 panic）。
    pub(crate) fn parse(raw: &str) -> Result<Self, GlobPatternError> {
        super::validate_token(raw, GLOB_MAX_LEN, |c| c.is_ascii_graphic()).map_err(
            |r| match r {
                super::Reason::Empty => GlobPatternError::Empty,
                super::Reason::Format => GlobPatternError::Format,
            },
        )?;
        Ok(Self(raw.to_string()))
    }

    /// 取模式字符串引用。
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// glob 模式解析错误。
// reason: 库错误枚举尚无生产返回方（funnel 调用方待 W），dead_code 来自遗留期（ADR-004 C8）。
#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum GlobPatternError {
    #[error("glob pattern is empty")]
    Empty,
    #[error("glob pattern is too long or has invalid characters")]
    Format,
}

// ---------------------------------------------------------------------------
// Policy / PolicyRule — ABAC 策略
// ---------------------------------------------------------------------------

/// 策略规则（属性键 + 比较 operator + 效果；不 derive Serialize——域类型）。
///
/// 单条规则在 subject 属性集上「命中」= 属性存在 ∧ operator 比较为真（类型不匹配 / 缺失属性 →
/// 不命中，fail-closed）；命中后按 `effect` 贡献 Allow 或 Deny（deny-overrides）。
// reason: 同上（实现已落地，消费方待 W；ADR-004 C8）。
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct PolicyRule {
    attribute_key: AttributeKey,
    operator: Operator,
    effect: PolicyEffect,
}

// reason: 同上（实现已落地，消费方待 W；ADR-004 C8）。
#[allow(dead_code)]
impl PolicyRule {
    /// 构造策略规则（属性键 + operator + 效果，均必填）。
    pub(crate) fn new(
        attribute_key: AttributeKey,
        operator: Operator,
        effect: PolicyEffect,
    ) -> Self {
        Self {
            attribute_key,
            operator,
            effect,
        }
    }

    /// 取属性键引用。
    pub(crate) fn attribute_key(&self) -> &AttributeKey {
        &self.attribute_key
    }

    /// 取比较 operator 引用。
    pub(crate) fn operator(&self) -> &Operator {
        &self.operator
    }

    /// 取规则效果。
    pub(crate) fn effect(&self) -> PolicyEffect {
        self.effect
    }
}

/// ABAC 策略（规则集；deny-overrides 求值；不 derive Serialize——域类型）。
///
/// 多租隔离：策略必须归属租户（对标 `RoleBinding.tenant`）；跨租求值 fail-closed Deny。
// reason: 同上（实现已落地，消费方待 W；ADR-004 C8）。
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct Policy {
    id: PolicyId,
    tenant: vocab::TenantId,
    rules: Vec<PolicyRule>,
}

// reason: 同上（实现已落地，消费方待 W；ADR-004 C8）。
#[allow(dead_code)]
impl Policy {
    /// 构造策略（id + tenant + 规则集，必填）。
    pub(crate) fn new(id: PolicyId, tenant: vocab::TenantId, rules: Vec<PolicyRule>) -> Self {
        Self { id, tenant, rules }
    }

    /// 取策略 ID 引用。
    pub(crate) fn id(&self) -> &PolicyId {
        &self.id
    }

    /// 取绑定租户。
    pub(crate) fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    /// 取规则列表引用。
    pub(crate) fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }
}

// ---------------------------------------------------------------------------
// 非 DI 纯逻辑自由函数（L0 纯计算；deny-overrides，fail-closed）
// ---------------------------------------------------------------------------

/// ABAC 策略求值（纯函数，L0；deny-overrides + fail-closed）。
///
/// INVARIANT: IDENTITY-AUTHZ-TENANT-01 — 实现仅对 `policy.tenant() == principal.tenant()`
/// 的策略求值；`principal.tenant()` 为 `None`（Service/SuperAdmin 跨租场景）或租户不匹配时返回
/// `Decision::Deny`（通用 ABAC 路径不放行跨租，跨租走独立管理面）。
///
/// 与 `rbac::authorize_rbac` **共用同一 INVARIANT ID**（有意）：两者是「仅同租记录参与求值 +
/// `principal.tenant()==None` → Deny」的两个实例——RBAC 按 `binding.tenant`、ABAC 按 `policy.tenant`，
/// 租户隔离语义等价。签名 `principal` 位参使「跨租 mismatch fail-closed」由签名承载（Hard）。
///
/// deny-overrides：遍历命中规则——任一命中 `Deny` → 整体 `Deny`（短路）；否则有命中 `Allow` → `Allow`；
/// 无规则命中（空策略 / 全不命中）→ 默认 `Deny`。缺失属性 / 类型不匹配 → 该规则不命中（fail-closed）。
/// **重复属性 key**（单值模型下歧义输入）→ 求值入口整体 `Deny`（防 Deny 规则被重复 key 顺序绕过）。
/// （ref: casbin/casbin-rs src/effector.rs@fc425d4，deny-overrides 同形）
///
/// 设计决策（可观测性）：返回纯 `Decision`（不携 deny-reason / 命中规则）。决策链路的结构化追踪
/// （区分租户门 Deny vs 规则 Deny vs 无命中 Deny）由 W 阶段 handler/authz 接线层在调用点记 `tracing`
/// span 承载——L0 纯函数不引入 I/O / tracing。审计所需的 obligations 解析是 T011 后续项（出本 PR 范围）。
// reason: 实现已落地，但生产调用方（handler / authz 接线）待 W 阶段（PR4/PR5）；当前仅测试消费，
// 非 test 构建无调用方 ⇒ 仍 dead，保留 allow 以过 `-D warnings`（ADR-004 C8 遗留期 carve-out）。
#[allow(dead_code)]
pub(crate) fn evaluate_abac(
    principal: &authn::Principal,
    attrs: &[AbacAttribute],
    policy: &Policy,
) -> vocab::Decision {
    // 租户门：无租户主体（Service / SuperAdmin）或跨租 → fail-closed（INVARIANT IDENTITY-AUTHZ-TENANT-01）。
    let Some(tenant) = principal.tenant() else {
        return vocab::Decision::Deny;
    };
    if policy.tenant() != tenant {
        return vocab::Decision::Deny;
    }
    // 重复属性 key fail-closed：单值属性模型下 `find_attr` 只取首个同 key 值，重复 key 会让后置 Deny
    // 规则读不到第二个值而漏判（deny-overrides 被输入顺序绕过）。歧义属性集不可信 → 整体 Deny，把唯一性
    // 责任显式留给 W 阶段输入边界（类型层 unique-attr funnel 需改本 wave 冻结签名，留后续）。
    if has_duplicate_key(attrs) {
        return vocab::Decision::Deny;
    }
    // deny-overrides：命中 Deny 立即短路；记录是否见过命中 Allow；末尾无命中 → 默认 Deny。
    let mut saw_allow = false;
    for rule in policy.rules() {
        if !rule_matches(rule, attrs) {
            continue;
        }
        match rule.effect() {
            PolicyEffect::Deny => return vocab::Decision::Deny,
            PolicyEffect::Allow => saw_allow = true,
        }
    }
    if saw_allow {
        vocab::Decision::Allow
    } else {
        vocab::Decision::Deny
    }
}

/// 单条规则是否命中（属性存在 ∧ operator 比较为真；缺失 / 类型不匹配 → false，fail-closed）。
// reason: 仅被 evaluate_abac（dead 待 W）调用 ⇒ 非 test 构建 dead（ADR-004 C8）。
#[allow(dead_code)]
fn rule_matches(rule: &PolicyRule, attrs: &[AbacAttribute]) -> bool {
    let Some(actual) = find_attr(attrs, rule.attribute_key()) else {
        return false; // 缺失属性 → 不命中。
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

/// 在属性集中按键查找属性值（首个匹配；调用方须先经 `has_duplicate_key` 排除重复 key 歧义）。
// reason: 同 rule_matches（dead 待 W；ADR-004 C8）。
#[allow(dead_code)]
fn find_attr<'a>(attrs: &'a [AbacAttribute], key: &AttributeKey) -> Option<&'a AttributeValue> {
    attrs
        .iter()
        .find(|a| a.key() == key)
        .map(AbacAttribute::value)
}

/// 属性集是否含重复 key（单值属性模型下重复 = 歧义输入；`AttributeKey: Hash + Eq` ⇒ O(n) 判定）。
// reason: 同 rule_matches（仅 evaluate_abac 调用，dead 待 W；ADR-004 C8）。
#[allow(dead_code)]
fn has_duplicate_key(attrs: &[AbacAttribute]) -> bool {
    let mut seen = std::collections::HashSet::with_capacity(attrs.len());
    !attrs.iter().all(|a| seen.insert(a.key()))
}

/// 数值比较：双方 parse `f64` 且有限时按 `want` 比较，否则类型不匹配 → false（fail-closed，不 panic）。
// reason: 同 rule_matches（dead 待 W；ADR-004 C8）。
#[allow(dead_code)]
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

/// 解析有限 `f64`（拒 NaN / Inf——非有限值视作类型不匹配）。
///
/// 精度上限 = `f64` 尾数（整数精确到 2^53）；超界整数策略阈值（如 `Gt("9007199254740993")`）会经
/// `f64` 截断，比较可能不直觉。MDM 数值属性（level / count / age）远在此界内，故不引入 `Decimal`。
// reason: 同 rule_matches（dead 待 W；ADR-004 C8）。
#[allow(dead_code)]
fn numeric(raw: &str) -> Option<f64> {
    raw.parse::<f64>().ok().filter(|n| n.is_finite())
}

/// glob 匹配（`*` 匹配任意（含空）字符序列、`?` 匹配单字符；无正则、无转义）。
///
/// **`*` 跨路径分隔符**：shell-glob 风格，`*` 匹配含 `/` 的任意序列（非 fnmatch `FNM_PATHNAME`）；
/// 路径形 ABAC 策略（`/docs/*`）作者须知 `*` 会跨目录层级。
///
/// 标准单回溯迭代算法：遇 `*` 记录回溯点；不匹配则回退到最近 `*` 并多吞一个字符。
/// 复杂度受 `pattern` 长度（≤256，parse 期约束）约束，线性有界（无 ReDoS）。
// reason: 同 rule_matches（dead 待 W；ADR-004 C8）。
#[allow(dead_code)]
fn glob_match(pattern: &str, value: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let val: Vec<char> = value.chars().collect();
    let (mut p, mut v) = (0usize, 0usize);
    // star = 最近 `*` 在 pat 的下标；mark = 该 `*` 已吞到 val 的下标（回溯点）。
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
    // 尾部剩余 pattern 必须全是 `*` 才算整体匹配。
    while p < pat.len() && pat[p] == '*' {
        p += 1;
    }
    p == pat.len()
}

// ---------------------------------------------------------------------------
// 测试（实体构造 / 访问器 / Debug 脱敏 + operator 表驱动 + deny-overrides / 默认 Deny / 跨租）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{
        AbacAttribute, GlobPattern, Operator, Policy, PolicyEffect, PolicyRule, evaluate_abac,
    };
    use crate::domain::{AttributeKey, AttributeValue, PolicyId};
    use authn::{Principal, PrincipalKind};
    use rstest::rstest;
    use vocab::Decision;
    use vocab::tenant::TenantId;

    // 两个 canonical UUID：tenant A（principal 所属）/ tenant B（跨租）。
    const TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const TENANT_B: &str = "550e8400-e29b-41d4-a716-446655440000";

    #[allow(clippy::expect_used)]
    fn tid(raw: &str) -> TenantId {
        TenantId::parse(raw).expect("canonical tenant uuid")
    }

    #[allow(clippy::expect_used)]
    fn akey(raw: &str) -> AttributeKey {
        AttributeKey::parse(raw).expect("valid attribute key")
    }

    fn aval(raw: &str) -> AttributeValue {
        AttributeValue::new(raw)
    }

    fn attr(key: &str, value: &str) -> AbacAttribute {
        AbacAttribute::new(akey(key), aval(value))
    }

    #[allow(clippy::expect_used)]
    fn glob(raw: &str) -> GlobPattern {
        GlobPattern::parse(raw).expect("valid glob pattern")
    }

    #[allow(clippy::expect_used)]
    fn pid(raw: &str) -> PolicyId {
        PolicyId::parse(raw).expect("valid policy id")
    }

    fn user(tenant: Option<&str>) -> Principal {
        authn::test_support::principal(PrincipalKind::User, "alice", tenant.map(tid))
    }

    fn rule(key: &str, operator: Operator, effect: PolicyEffect) -> PolicyRule {
        PolicyRule::new(akey(key), operator, effect)
    }

    /// 单租（tenant A）下用一组规则求值（principal 同租，租户门必过）。
    fn eval(attrs: &[AbacAttribute], rules: Vec<PolicyRule>) -> Decision {
        let policy = Policy::new(pid("pol-1"), tid(TENANT_A), rules);
        evaluate_abac(&user(Some(TENANT_A)), attrs, &policy)
    }

    /// 实体构造器 / 访问器回声。
    #[test]
    fn entity_accessors_echo() {
        let a = attr("dept", "eng");
        assert_eq!(a.key().as_str(), "dept");
        assert_eq!(a.value().as_str(), "eng");

        let r = rule("dept", Operator::Eq(aval("eng")), PolicyEffect::Allow);
        assert_eq!(r.attribute_key().as_str(), "dept");
        assert!(matches!(r.operator(), Operator::Eq(_)));
        assert_eq!(r.effect(), PolicyEffect::Allow);

        let p = Policy::new(pid("pol-1"), tid(TENANT_A), vec![r]);
        assert_eq!(p.id().as_str(), "pol-1");
        assert_eq!(p.tenant(), tid(TENANT_A));
        assert_eq!(p.rules().len(), 1);
    }

    /// AttributeValue Debug 脱敏：属性值（可能含 PII）不得原文打印。
    #[test]
    fn attribute_value_debug_redacts() {
        let a = attr("ssn", "123-45-6789");
        let dbg = format!("{a:?}");
        assert!(dbg.contains("<redacted>"), "属性值必须脱敏: {dbg}");
        assert!(!dbg.contains("123-45-6789"), "Debug 不得泄露属性值明文");
    }

    /// operator 真 / 假 / 类型不匹配（命中→Allow，不命中→Deny；单条 Allow 规则、同租）。
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
            // 缺失属性 → 不命中（fail-closed），即便是 Ne。
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
            // 等值边界 → Gt 是严格 `>`，level==threshold 不命中（fail-closed，锁「不含等值」语义）。
            Op::GtEqual => (
                vec![attr("level", "3")],
                rule("level", Operator::Gt(aval("3")), allow),
            ),
            // 非数值属性值 → 类型不匹配 → 不命中。
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
            // 等值边界 → Lt 是严格 `<`，level==threshold 不命中（fail-closed）。
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
            // 第二属性缺失 → 不命中（fail-closed）。
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

    /// deny-overrides：同策略并存命中 Deny + 命中 Allow → 整体 Deny（两种规则顺序均验证短路与顺序无关）。
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

    /// deny-overrides 短路独立于 `saw_allow`：命中 Deny + **不命中** Allow → 仍 Deny。
    /// （锁 `return Deny` 短路路径与 saw_allow 标志无关——防「只有 saw_allow=true 才 Deny」误改回归。）
    #[test]
    fn deny_hit_with_allow_miss_still_deny() {
        let attrs = vec![attr("role", "admin")];
        // Allow 规则要求 role==user（不命中）；Deny 规则要求 role==admin（命中）。
        let allow = rule("role", Operator::Eq(aval("user")), PolicyEffect::Allow);
        let deny = rule("role", Operator::Eq(aval("admin")), PolicyEffect::Deny);
        assert_eq!(eval(&attrs, vec![allow, deny]), Decision::Deny);
    }

    /// 重复属性 key fail-closed：单值属性模型下重复 key = 歧义/不可信输入 → 整体 Deny。
    /// （回归：`find_attr` 只取首值会让后置 Deny 被重复 key 顺序绕过——
    /// case 1 直接绕过、case 2 经无关 Allow 绕过，两变体均须 Deny。）
    #[rstest]
    #[case::direct_bypass(vec![attr("clearance", "public"), attr("clearance", "secret")])]
    #[case::via_unrelated_allow(vec![
        attr("dept", "eng"),
        attr("clearance", "public"),
        attr("clearance", "secret"),
    ])]
    fn duplicate_attribute_key_denies(#[case] attrs: Vec<AbacAttribute>) {
        // Allow(dept==eng 或 clearance==public) 本可命中放行；Deny(clearance==secret) 因 find_attr
        // 只读首个 clearance(public) 而漏判。重复 key 必须在求值入口整体 fail-closed Deny。
        let allow_dept = rule("dept", Operator::Eq(aval("eng")), PolicyEffect::Allow);
        let allow_clearance = rule(
            "clearance",
            Operator::Eq(aval("public")),
            PolicyEffect::Allow,
        );
        let deny = rule(
            "clearance",
            Operator::Eq(aval("secret")),
            PolicyEffect::Deny,
        );
        assert_eq!(
            eval(&attrs, vec![allow_dept, allow_clearance, deny]),
            Decision::Deny
        );
    }

    /// 默认 Deny：空属性集 / 全不命中 → Deny（规则要求 role==admin，二者均不命中）。
    #[rstest]
    #[case::empty_attrs(vec![])]
    #[case::all_miss(vec![attr("role", "user")])]
    fn default_deny(#[case] attrs: Vec<AbacAttribute>) {
        let rules = vec![rule(
            "role",
            Operator::Eq(aval("admin")),
            PolicyEffect::Allow,
        )];
        assert_eq!(eval(&attrs, rules), Decision::Deny);
    }

    /// 真·空规则集：即便有本可匹配的属性，无任何规则 → 默认 Deny（锁 saw_allow=false 末尾分支）。
    #[test]
    fn empty_rule_set_denies() {
        let attrs = vec![attr("role", "admin")];
        assert_eq!(eval(&attrs, vec![]), Decision::Deny);
    }

    /// 单条命中 Allow 规则 → Allow（无 Deny 时正向放行）。
    #[test]
    fn single_allow_grants() {
        let attrs = vec![attr("role", "admin")];
        let rules = vec![rule(
            "role",
            Operator::Eq(aval("admin")),
            PolicyEffect::Allow,
        )];
        assert_eq!(eval(&attrs, rules), Decision::Allow);
    }

    /// 跨租 fail-closed：策略租户 ≠ principal 租户、或 principal 无租户 → Deny（即便规则命中 Allow）。
    enum TenantScn {
        CrossTenant,
        NoTenantSuperAdmin,
        NoTenantService,
    }

    #[rstest]
    #[case::cross_tenant(TenantScn::CrossTenant)]
    #[case::no_tenant_super_admin(TenantScn::NoTenantSuperAdmin)]
    #[case::no_tenant_service(TenantScn::NoTenantService)]
    fn cross_tenant_deny(#[case] scn: TenantScn) {
        let attrs = vec![attr("role", "admin")];
        // 命中 Allow 规则：唯一阻断来源是租户门。
        let rules = vec![rule(
            "role",
            Operator::Eq(aval("admin")),
            PolicyEffect::Allow,
        )];
        let policy = Policy::new(pid("pol-1"), tid(TENANT_A), rules);
        let principal = match scn {
            // principal 在 tenant B，策略在 tenant A → 跨租。
            TenantScn::CrossTenant => user(Some(TENANT_B)),
            TenantScn::NoTenantSuperAdmin => {
                authn::test_support::principal(PrincipalKind::SuperAdmin, "root", None)
            }
            TenantScn::NoTenantService => {
                authn::test_support::principal(PrincipalKind::Service, "svc", None)
            }
        };
        assert_eq!(evaluate_abac(&principal, &attrs, &policy), Decision::Deny);
    }

    /// GlobPattern::parse fail-closed：空 / 越界 / 非 ASCII graphic / 含空格 → Err；合法（含边界 256）→ Ok。
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

    /// glob_match 语义边界（直接覆盖匹配器分支：前缀 / 后缀 / 中段 / 多 `*` 回溯 / `?` 边界 / `*` 跨 `/`）。
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
    // 多 `*` 回溯：`*` 均匹配空 / 多次回溯 / 缺中段失败（锁单回溯算法分支）。
    #[case("a*b*c", "abc", true)]
    #[case("a*b*c", "a-b-b-c", true)]
    #[case("a*b*c", "aXc", false)]
    // `*` 跨路径分隔符 `/`（shell-glob 风格，非 fnmatch；路径策略须知此语义）。
    #[case("*", "a/b/c", true)]
    #[case("/docs/*", "/docs/x/y", true)]
    #[case("abc", "abc", true)]
    #[case("abc", "abd", false)]
    fn glob_match_cases(#[case] pattern: &str, #[case] value: &str, #[case] want: bool) {
        assert_eq!(super::glob_match(pattern, value), want);
    }
}
