//! [`RequestCtx`]：请求级控制流值快照（tenant / principal）。
//!
//! 不可变快照，经 [`crate::local`] 的 `task_local!` 传播。私有字段 + 无 `Deserialize`
//! ⇒ sealed 构造，从 request body 反序列化构造**不可表达**（ADR-002 §D5）。

use std::sync::Arc;

use vocab::PrincipalKind;

/// 请求级授权快照——**只**装控制流值（tenant / principal），不装可观测 ID（见 crate 级文档）。
///
/// 泛型 `T`（tenant）/ `P`（principal）把 runctx 对具体 payload 的耦合收敛到单一别名点：
/// - `P` 必须 trait/泛型擦除——`Principal` 归 `authn`（service 层），而 `authn` 已依赖 runctx，
///   故 `runctx → authn` 是 cargo 拒绝的闭环，principal 永不可被 runctx 按具体类型持有（ADR-002 §D3）。
///   [`AppCtx`] 收敛为 `Arc<dyn PrincipalFacet>`：authn 的 `Principal` 经 trait 擦除注入。
/// - `T` 在 [`AppCtx`] 收敛为具体 `vocab::tenant::TenantId`（ADR-002 §D3「intra-base sub-DAG」
///   已落地：sanctioned `runctx → vocab` 边）；泛型 `T` 仍保留，切换 tenant 类型只改别名一处。
///
/// 字段私有 = sealed 构造：唯一入口 [`RequestCtx::new`]。具体 [`AppCtx`] 的 principal payload
/// （`Arc<dyn PrincipalFacet>`）的生产 impl 面只有 authn（[`PrincipalFacet`] 文档 + dylint
/// `rss_principal_facet_impl_allowlist`，Medium）——外部 crate 无法 impl facet ⇒ 无法 mint 合法
/// principal payload ⇒ `AppCtx` 不可被下游伪造（ADR-002 §D5）。
///
/// **Debug 经 `secure::Redact` 字段级脱敏**：tenant/principal 是授权 PII，`Debug` 只出占位，绝不打印
/// payload（ADR-002 §D1 / §威胁矩阵），杜绝 `?ctx` / 断言失败 / 临时日志泄露原值。
///
/// 注：派生 `PartialEq`/`Eq` 对泛型条件成立——[`AppCtx`] 的 principal payload 是 trait object
/// （`Arc<dyn PrincipalFacet>`，无 `PartialEq`），故 `AppCtx` **不**实现相等比较；ambient 能力快照
/// 不是值类型，无生产相等语义需求（消费方读 [`RequestCtx::tenant`] / [`RequestCtx::principal`]）。
#[derive(Clone, PartialEq, Eq, secure::Redact)]
pub struct RequestCtx<T, P> {
    #[redact(sensitivity = internal)]
    tenant: T,
    #[redact(sensitivity = internal)]
    principal: P,
}

impl<T, P> RequestCtx<T, P> {
    /// 唯一构造入口。调用方须处于已认证通道（JWT tenant claim / service-token signed typed
    /// `tenant_id` claim）；service-token 的 exact-one `X-Tenant-ID` 仅 challenger equality，**不能**
    /// 单独建立 ambient。body 派生的 tenant 在 codegen 处被拒（`docs/rules/tenancy.md`）。
    ///
    /// 泛型本体公开，但具体 [`AppCtx`] 的伪造门收敛在 principal payload：`Arc<dyn PrincipalFacet>`
    /// 的生产 impl 面经 dylint `rss_principal_facet_impl_allowlist` 限定只在 authn（Medium，跨 crate
    /// sealed-trait 不可行——ADR-003 §4.2 / ADR-002 §D5）。外部 crate impl 不了 [`PrincipalFacet`]，
    /// 就拿不到 `Arc<dyn PrincipalFacet>`，也就构造不出 `AppCtx`。
    pub fn new(tenant: T, principal: P) -> Self {
        Self { tenant, principal }
    }

    /// 借用 tenant 控制流值。
    pub fn tenant(&self) -> &T {
        &self.tenant
    }

    /// 借用 principal 控制流值。
    pub fn principal(&self) -> &P {
        &self.principal
    }
}

/// 擦除的认证主体 facet——[`AppCtx`] 的 principal payload（`Arc<dyn PrincipalFacet>`）。
///
/// 只暴露 **vetted 非-PII** 访问器：[`PrincipalFacet::kind`]（可观测分类标量）与
/// [`PrincipalFacet::matches_subject`]（受控比较，不泄露 subject 明文）。具体 `authn::Principal`
/// 经 trait 擦除注入——`runctx → authn` 是 cargo 拒绝的闭环，故 runctx 永不按具体类型持有 principal。
///
/// **impl 面 allowlist（INVARIANT: PRINCIPAL-FACET-IMPL-AUTHN-01 { level = "Medium", exec = "manual/opt-in", source = "code" }）**：生产唯一 impl-er 是 `authn`
/// （+ runctx 自身的 test facet）。跨 crate「只有 authn 能 impl」**类型层不可表达**——sealed-trait 只能
/// 封闭到定义 crate，无法选择性放行下游 authn（ADR-003 §4.2 / ADR-006 / ADR-005 §6 已确立）。故本 trait
/// 是 open `pub trait`，impl 面由 dylint `rss_principal_facet_impl_allowlist`（Medium，镜像
/// `rss_diport_impl_allowlist`）守。这是 `AppCtx` 生产伪造门的载体（外部 impl 不了 facet ⇒ 造不出 `AppCtx`）。
pub trait PrincipalFacet: Send + Sync + 'static {
    /// 主体类别（非-PII 可观测分类标量；消费方做 ABAC / 归因）。
    fn kind(&self) -> PrincipalKind;

    /// 本主体 subject 是否等于 `subject`（**受控比较，不泄露明文**）——授权 / 归因路径判定绑定归属。
    fn matches_subject(&self, subject: &str) -> bool;
}

/// 进程级实例化别名：`task_local!` 不能泛型，须钉死一组具体 payload 类型。
///
/// tenant 收敛为具体 [`vocab::tenant::TenantId`]（ADR-002 §D3 intra-base sub-DAG：sanctioned
/// `runctx → vocab` 边）。principal 收敛为 `Arc<dyn PrincipalFacet>`：authn 的 `Principal` 经
/// [`PrincipalFacet`] 擦除注入（生产 impl 面 dylint 限 authn）。`Arc` 而非 `Box`——`AppCtx` 须 `Clone`
/// （[`crate::local::try_current`] clone 出快照），trait object 经 `Arc` 廉价共享。
pub type AppCtx = RequestCtx<vocab::tenant::TenantId, Arc<dyn PrincipalFacet>>;

/// 测试 facet（仅 `test` / `test-support`）：runctx 自身的 [`PrincipalFacet`] impl，供 [`test_support`]
/// 构造 [`AppCtx`]——audit 等域 crate 单测**不依赖 authn**，故测试 facet 必须在 runctx 提供。
///
/// dylint `rss_principal_facet_impl_allowlist` 的 impl 面 allowlist 含 `runctx`（定义 crate，与
/// `rss_diport_impl_allowlist` 放行 diport 自身同理）。
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone)]
pub(crate) struct TestPrincipalFacet {
    kind: PrincipalKind,
    subject: String,
}

#[cfg(any(test, feature = "test-support"))]
impl TestPrincipalFacet {
    /// 构造测试 facet（供 [`test_support`] 与 crate 内 `local` 测试模块复用）。
    pub(crate) fn new(kind: PrincipalKind, subject: impl Into<String>) -> Self {
        Self {
            kind,
            subject: subject.into(),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl PrincipalFacet for TestPrincipalFacet {
    fn kind(&self) -> PrincipalKind {
        self.kind
    }

    fn matches_subject(&self, subject: &str) -> bool {
        self.subject == subject
    }
}

/// 测试支撑：仅 `test-support` feature 下编译，供下游 crate（audit / authn / identity）单测构造 [`AppCtx`]。
///
/// 生产构建不启用此 feature（消费方仅经 `[dev-dependencies]` 开启）⇒ 测试 facet impl 不进生产构建，
/// `AppCtx` 生产伪造门（impl 面 dylint 限 authn）不受影响。
#[cfg(feature = "test-support")]
pub mod test_support {
    use super::{AppCtx, PrincipalFacet, RequestCtx, TestPrincipalFacet};
    use std::sync::Arc;
    use vocab::PrincipalKind;
    use vocab::tenant::TenantId;

    /// 构造一个绑定 `tenant` 的 [`AppCtx`]，principal 槽填测试 facet（`subject` + 默认 `kind=User`）。
    ///
    /// principal payload 的 `kind` 默认 [`PrincipalKind::User`]——既有调用方只关心 tenant scope，
    /// 不断言 principal kind；需指定 kind 的测试用 [`app_ctx_with_kind`]。
    pub fn app_ctx(tenant: TenantId, subject: impl Into<String>) -> AppCtx {
        app_ctx_with_kind(tenant, PrincipalKind::User, subject)
    }

    /// 构造一个绑定 `tenant` + 指定 `kind` 的 [`AppCtx`]（principal 槽填测试 facet）。
    pub fn app_ctx_with_kind(
        tenant: TenantId,
        kind: PrincipalKind,
        subject: impl Into<String>,
    ) -> AppCtx {
        let facet: Arc<dyn PrincipalFacet> = Arc::new(TestPrincipalFacet::new(kind, subject));
        RequestCtx::new(tenant, facet)
    }
}
