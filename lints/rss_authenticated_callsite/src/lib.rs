#![feature(rustc_private)]
//! `rss_authenticated_callsite` — RSS 治理 dylint lint：限定认证证据、审计 subject 与 verified
//! maintenance capability funnel 仅组合根可调用。
//! `httpserve::Authenticated` profile-specific constructors 与
//! `authn::Principal::{audit_subject,service_caller_domain}` 与
//! `postgres::ConfigValueMaintenanceCapability::from_verified_service_caller` 仅 assembly / bin crate
//! （组合根）可调用。DLQ verified subject 由专用 `rss_dlq_operator_callsite` 守护。
//!
//! INVARIANT: AUTH-EVIDENCE-MINT-01 { level = "Medium", exec = "verify", source = "dylint" }
//!
//! `Authenticated` 是 enforce 层放行 `Require` 路由的认证证据（INVARIANT AUTH-EVIDENCE-REQUIRE-01）：
//! 请求携该 extension 即放行。它必须由组合根（assembly / bin）的验签桥在凭据校验通过后经外层 `.layer()`
//! 注入；域 crate 若直接调用任一 `Authenticated` 构造 funnel 并注入 extension 即可伪造证据绕过鉴权。
//!
//! 与 `rss_authplan_callsite`（AUTH-PLAN-MINT-01）同治理姿态：`AuthPlan` 是 listener 级认证计划、
//! `Authenticated` 是 per-request 认证证据，二者均为安全敏感 mint，均限组合根构造。`Authenticated` 字段私有
//! （外部无法 struct-literal 伪造），构造入口闭集为 profile-specific constructors；
//! AuthGrant/RSS issue 生产链亦按 callee DefId + caller impl ADT 的完整
//! DefPath 同闸闭合 funnel；caller 的 crate/type/method 短名不足以证明它是 canonical service。
//!
//! 上下游强度（ai-robust.md §审查要求「Funnel 类约束分别说明上游 / 下游」）：
//! - 上游（构造守卫）：`Authenticated` 字段私有，外部 crate 仅能经构造入口闭集合法构造——类型层私有字段已封
//!   struct literal，但 runtime 验签桥跨 crate，故 profile-specific constructors 经同一 callsite lint 约束。
//! - 下游（使用守卫）：`Authenticated` 可 Clone 传递，使用侧无需 mint——mint 点即唯一约束面。
//!
//! 判定四步：① callee crate 名；② item 名属于对应闭集；③ parent 是 Impl；
//! ④ impl self 类型的 adt 名 == "Authenticated"（self-ty 检查，杜绝 `Vec::new` 等同名 fn 误报）。
//!
//! 检测面：捕获 funnel assoc fn 的 path 引用与 method-call——直接 call、函数项别名、fn-pointer
//! 强转、`principal.service_caller_domain()` 都解析到受守 `DefId`。
//!
//! 盲区：① 仅 `cargo dylint --all`（接 `cargo xtask verify`，`-D warnings` fail-closed）拦；
//! ② **跨函数**洗白仍未覆盖（intraprocedural，跟踪 #1085）；③ dylint 不扫未编译的
//! `#[cfg(test)]` 树，settingsonly 因此另由 `SETTINGSONLY-L2-PRODUCTION-CLOSURE-01` 对完整源码 AST
//! fail-closed 扫描 raw JWT reparse bait。`Authenticated` mint 与 Principal 降维 accessor 均不采用整
//! crate allowlist，只允许列明的精确 verification wrapper。

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_hir::def::{DefKind, Res};
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_hir::{Expr, ExprKind, HirId};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::Span;

/// 仅这些 crate 可调用认证证据 / 审计 subject funnel——单一 greppable 真源，扩项须治理评审。
/// 组合根（assembly / bin）的验签桥在凭据校验通过后构造 `Authenticated` 并经外层 `.layer()` 注入，是唯一合法构造点。
/// 当前生产 runtime 与 identityaudit 验签桥构造 access/mTLS 与 service-token evidence；
/// allowlist 精确覆盖列明 `auth_bridge` 与 `operator::{projection,dlq,settings}` nested def-path。
/// assemblies/runtime → package name "runtime"（#1309 单一组合根；薄 bin bins/server、bins/rss 已移出）。
/// 定义 crate `httpserve` 不入 allowlist：其生产代码不构造 `Authenticated`（仅 `#[cfg(test)]` 调，不被扫）。
const ALLOWED_AUTHENTICATED_MINT_FUNCTIONS: &[(&str, &str, &str)] = &[
    ("runtime", "allow_evidence", "auth_bridge::allow_evidence"),
    ("runtime", "mtls_evidence", "auth_bridge::mtls_evidence"),
    (
        "identityaudit",
        "allow_evidence",
        "auth_bridge::allow_evidence",
    ),
    (
        "settingsonly",
        "federated_evidence",
        "auth_bridge::federated_evidence",
    ),
];
const ALLOWED_PRINCIPAL_ACCESSOR_FUNCTIONS: &[(&str, &str, &str)] = &[
    ("runtime", "allow_evidence", "auth_bridge::allow_evidence"),
    (
        "identityaudit",
        "allow_evidence",
        "auth_bridge::allow_evidence",
    ),
    (
        "settingsonly",
        "federated_evidence",
        "auth_bridge::federated_evidence",
    ),
    (
        "runtime",
        "verified_service_maintenance_operator_subject",
        "operator::projection::verified_service_maintenance_operator_subject",
    ),
    (
        "runtime",
        "verified_projection_maintenance_operator_subject",
        "operator::projection::verified_projection_maintenance_operator_subject",
    ),
    (
        "runtime",
        "projection_maintenance_operator_receipt",
        "operator::projection::projection_maintenance_operator_receipt",
    ),
    (
        "runtime",
        "authenticate_dlq_operator_principal",
        "operator::dlq::authenticate_dlq_operator_principal",
    ),
    (
        "runtime",
        "dlq_operator_receipt",
        "operator::dlq::dlq_operator_receipt",
    ),
];
const ALLOWED_CONFIG_VALUE_CAPABILITY_FUNCTION: (&str, &str) = (
    "run_settings_config_value_maintenance",
    "operator::settings::run_settings_config_value_maintenance",
);

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// 标记未授权 caller 对 evidence / AuthGrant / RSS issue funnel 的**任意 path 引用**（直接
    /// call、函数项别名、fn-pointer 强转——凡解析到对应 assoc fn DefId）。
    ///
    /// ### Why is this bad?
    /// `Authenticated` 是 enforce 层放行 `Require` 路由的认证证据，必须由组合根（assembly / bin crate）的验签桥
    /// 在凭据校验通过后构造并经外层 `.layer()` 注入。域 crate 直接 mint `Authenticated` 可伪造证据绕过鉴权。
    /// INVARIANT: AUTH-EVIDENCE-MINT-01 { level = "Medium", exec = "verify", source = "dylint" }（与 AUTH-PLAN-MINT-01 同治理姿态）。
    ///
    /// ### Known problems
    /// 仍 intraprocedural：allowlist crate 内 wrapper fn 被外部调用会**跨函数**洗白（跟踪 #1085）。
    /// 精确 wrapper closed set 扩项须同步 UI 红/绿 fixture；确需例外时加
    /// `#[allow(rss_authenticated_callsite)] // reason: ...` 并接受治理复核。
    ///
    /// ### Example
    /// ```ignore
    /// // 域 crate（非组合根）：
    /// let ev = httpserve::Authenticated::new_federated(
    ///     vocab::PrincipalKind::User,
    ///     "subject-1",
    ///     None,
    /// ); // 触发
    /// ```
    /// Use instead: 在 assembly / bin crate 的组合根验签桥中构造 `Authenticated`，经外层 `.layer()` 注入。
    pub RSS_AUTHENTICATED_CALLSITE,
    Warn,
    "Authenticated 证据构造仅限组合根 crate（assembly / bin）（callsite-allowlist，INVARIANT AUTH-EVIDENCE-MINT-01)"
}

impl<'tcx> LateLintPass<'tcx> for RssAuthenticatedCallsite {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        // 捕获 funnel fn-item path 与 method-call；别名、fn-pointer 和 method syntax 均解析到受守 DefId。
        let did = match expr.kind {
            ExprKind::Path(ref qpath) => {
                let Res::Def(DefKind::AssocFn | DefKind::Fn, did) =
                    cx.qpath_res(qpath, expr.hir_id)
                else {
                    return;
                };
                did
            }
            ExprKind::MethodCall(..) => {
                let Some(did) = cx.typeck_results().type_dependent_def_id(expr.hir_id) else {
                    return;
                };
                did
            }
            _ => return,
        };
        if is_settingsonly_raw_jwt_reparse_did(cx, did) {
            emit(
                cx,
                expr.hir_id,
                expr.span,
                "settingsonly 不得重新解析 raw federated JWT 或投影 verified raw token",
                "仅消费 authn::verify_federated_access 返回的 VerifiedFederatedAccess；不得直接调用、别名或函数指针引用 Jwt::parse / VerifiedJwt::raw",
            );
        }
        if is_authenticated_mint_did(cx, did)
            && !authenticated_mint_caller_is_allowed(cx, expr.hir_id)
        {
            emit(
                cx,
                expr.hir_id,
                expr.span,
                "Authenticated 证据仅组合根（assembly / bin crate）可构造：profile-specific constructor 不得在此 crate 调用",
                authenticated_mint_help(cx),
            );
        }
        if let Some(funnel) = authn_grant_issue_funnel(cx, did)
            && !authn_grant_issue_caller_is_allowed(cx, expr.hir_id, funnel)
        {
            emit(
                cx,
                expr.hir_id,
                expr.span,
                "AuthGrant/RSS access-token 生产 funnel 出现在未授权调用点",
                funnel.help(),
            );
        }
        if is_principal_audit_subject_did(cx, did)
            && !principal_accessor_caller_is_allowed(cx, expr.hir_id)
        {
            emit(
                cx,
                expr.hir_id,
                expr.span,
                "Principal 身份降维 accessor（`audit_subject` / `service_caller_domain`）仅组合根可调用",
                principal_accessor_help(cx),
            );
        }
        if let Some(funnel) = restricted_service_capability_funnel(cx, did)
            && !config_value_capability_caller_is_allowed(cx, expr.hir_id)
        {
            emit(
                cx,
                expr.hir_id,
                expr.span,
                "verified maintenance capability 仅组合根可 mint",
                funnel.help,
            );
        }
    }
}

/// settingsonly must consume the sealed `VerifiedFederatedAccess` aggregate. Matching the
/// resolved callee `DefId` catches direct calls, function-item aliases, and fn-pointer coercions;
/// spelling or import aliases cannot evade it.
fn is_settingsonly_raw_jwt_reparse_did(cx: &LateContext<'_>, did: DefId) -> bool {
    if cx.tcx.crate_name(LOCAL_CRATE).as_str() != "settingsonly"
        || cx.tcx.crate_name(did.krate).as_str() != "authn"
    {
        return false;
    }
    let parent_did = cx.tcx.parent(did);
    if !matches!(cx.tcx.def_kind(parent_did), DefKind::Impl { .. }) {
        return false;
    }
    let Some(self_name) = cx
        .tcx
        .type_of(parent_did)
        .skip_binder()
        .ty_adt_def()
        .map(|adt| cx.tcx.item_name(adt.did()))
    else {
        return false;
    };
    matches!(
        (self_name.as_str(), cx.tcx.item_name(did).as_str()),
        ("Jwt", "parse") | ("VerifiedJwt", "raw")
    )
}

fn authenticated_mint_help(cx: &LateContext<'_>) -> &'static str {
    if cx.tcx.crate_name(LOCAL_CRATE).as_str() == "identityaudit" {
        "仅在 identityaudit `auth_bridge::allow_evidence` 精确 proof-consuming 验签桥中构造 RSS Authenticated evidence；其它位置不得 mint evidence"
    } else {
        "仅在 runtime `auth_bridge::{allow_evidence,mtls_evidence}` 的精确验签桥函数中构造 Authenticated；其它 runtime 代码同样不得 mint evidence"
    }
}

fn principal_accessor_help(cx: &LateContext<'_>) -> &'static str {
    if cx.tcx.crate_name(LOCAL_CRATE).as_str() == "identityaudit" {
        "仅在 identityaudit `auth_bridge::allow_evidence` proof-consuming wrapper 中读取 Principal 身份；其它位置不得降维 verified Principal"
    } else {
        "仅在列明的 runtime verification wrapper 中读取 Principal 身份；其它 runtime 代码同样不得把 verified Principal 降维为可转传值"
    }
}

fn config_value_capability_caller_is_allowed(cx: &LateContext<'_>, hir_id: HirId) -> bool {
    if cx.tcx.crate_name(LOCAL_CRATE).as_str() != "runtime" {
        return false;
    }
    let parent = cx.tcx.hir_get_parent_item(hir_id).to_def_id();
    let item_name = cx.tcx.item_name(parent);
    let def_path = cx.tcx.def_path_str(parent);
    item_name.as_str() == ALLOWED_CONFIG_VALUE_CAPABILITY_FUNCTION.0
        && is_exact_runtime_path(&def_path, ALLOWED_CONFIG_VALUE_CAPABILITY_FUNCTION.1)
}

fn authenticated_mint_caller_is_allowed(cx: &LateContext<'_>, hir_id: HirId) -> bool {
    let crate_name = cx.tcx.crate_name(LOCAL_CRATE);
    let parent = cx.tcx.hir_get_parent_item(hir_id).to_def_id();
    let item_name = cx.tcx.item_name(parent);
    let def_path = cx.tcx.def_path_str(parent);
    ALLOWED_AUTHENTICATED_MINT_FUNCTIONS.iter().any(
        |(expected_crate, expected_name, expected_path)| {
            let exact_caller = crate_name.as_str() == *expected_crate
                && item_name.as_str() == *expected_name
                && is_exact_crate_path(&def_path, expected_crate, expected_path);
            exact_caller
                && (*expected_crate != "identityaudit"
                    || caller_consumes_validated_auth_grant(cx, parent, false))
                && (*expected_crate != "settingsonly"
                    || caller_consumes_verified_federated_access(cx, parent))
        },
    )
}

/// settingsonly's only evidence mint must consume the sealed aggregate directly. Requiring the
/// concrete aggregate as the sole input prevents a wrapper from accepting independently supplied
/// principal/claims/permission values that could be split, substituted, or reparsed.
fn caller_consumes_verified_federated_access(cx: &LateContext<'_>, caller: DefId) -> bool {
    if !matches!(cx.tcx.def_kind(caller), DefKind::Fn | DefKind::AssocFn) {
        return false;
    }
    let signature = cx.tcx.fn_sig(caller).instantiate_identity().skip_binder();
    let inputs = signature.inputs();
    inputs.len() == 1
        && inputs[0].peel_refs().ty_adt_def().is_some_and(|adt| {
            cx.tcx.crate_name(adt.did().krate).as_str() == "authn"
                && cx.tcx.item_name(adt.did()).as_str() == "VerifiedFederatedAccess"
        })
}

/// The durable proof is deliberately move-only. The only mint wrappers must take the concrete
/// proof by value, so deleting validation or weakening the wrapper to an optional/borrowed marker
/// stops compiling or trips this lint instead of silently minting current-grant evidence.
fn caller_consumes_validated_auth_grant(
    cx: &LateContext<'_>,
    caller: DefId,
    require_single_input: bool,
) -> bool {
    if !matches!(cx.tcx.def_kind(caller), DefKind::Fn | DefKind::AssocFn) {
        return false;
    }
    let signature = cx.tcx.fn_sig(caller).instantiate_identity().skip_binder();
    let inputs = signature.inputs();
    (!require_single_input || inputs.len() == 1)
        && inputs.iter().any(|input| {
            input.ty_adt_def().is_some_and(|adt| {
                cx.tcx.crate_name(adt.did().krate).as_str() == "identity"
                    && cx.tcx.item_name(adt.did()).as_str() == "ValidatedAuthGrant"
            })
        })
}

#[derive(Clone, Copy)]
enum AuthnGrantIssueFunnel {
    NewActive,
    Hydrate,
    IssueInput,
    IssueAccess,
}

impl AuthnGrantIssueFunnel {
    const fn help(self) -> &'static str {
        match self {
            Self::NewActive => "AuthGrant::new_active 仅允许 identity::LoginService::login",
            Self::Hydrate => {
                "AuthGrant::hydrate 仅允许 AuthGrant 内部状态转换与 postgres::auth_grant_lifecycle::find_active"
            }
            Self::IssueInput | Self::IssueAccess => {
                "RSS access issue input 与 issuer 仅允许 identity refresh 的 prepare_initial/rotate"
            }
        }
    }
}

fn authn_grant_issue_funnel(cx: &LateContext<'_>, did: DefId) -> Option<AuthnGrantIssueFunnel> {
    if cx.tcx.crate_name(did.krate).as_str() != "authn" {
        return None;
    }
    let parent_did = cx.tcx.parent(did);
    if !matches!(cx.tcx.def_kind(parent_did), DefKind::Impl { .. }) {
        return None;
    }
    let self_ty = cx.tcx.type_of(parent_did).skip_binder();
    let self_name = self_ty
        .ty_adt_def()
        .map(|adt| cx.tcx.item_name(adt.did()))?;
    match (self_name.as_str(), cx.tcx.item_name(did).as_str()) {
        ("AuthGrant", "new_active") => Some(AuthnGrantIssueFunnel::NewActive),
        ("AuthGrant", "hydrate") => Some(AuthnGrantIssueFunnel::Hydrate),
        ("AuthGrant", "access_issue_input") => Some(AuthnGrantIssueFunnel::IssueInput),
        ("JwtIssuer", "issue_access") => Some(AuthnGrantIssueFunnel::IssueAccess),
        _ => None,
    }
}

fn authn_grant_issue_caller_is_allowed(
    cx: &LateContext<'_>,
    hir_id: HirId,
    funnel: AuthnGrantIssueFunnel,
) -> bool {
    let caller = cx.tcx.hir_get_parent_item(hir_id).to_def_id();
    match funnel {
        AuthnGrantIssueFunnel::NewActive => exact_inherent_caller_is(
            cx,
            caller,
            "identity",
            "application::LoginService",
            &["login"],
        ),
        AuthnGrantIssueFunnel::Hydrate => {
            exact_inherent_caller_is(
                cx,
                caller,
                "authn",
                "grant::AuthGrant",
                &["new_active", "close"],
            ) || exact_inherent_caller_is(
                cx,
                caller,
                "postgres",
                "auth_grant_lifecycle::PgAuthGrantLifecycle",
                &["find_active"],
            )
        }
        AuthnGrantIssueFunnel::IssueInput | AuthnGrantIssueFunnel::IssueAccess => {
            exact_inherent_caller_is(
                cx,
                caller,
                "identity",
                "application::RefreshService",
                &["prepare_initial", "rotate"],
            )
        }
    }
}

/// Match a caller by its resolved method `DefId` and the full DefPath of the inherent impl ADT.
/// The ADT path is the stable identity here: impl-block indices in a method's printed DefPath are
/// intentionally unstable, while a short type name permits `fake::LoginService` impersonation.
fn exact_inherent_caller_is(
    cx: &LateContext<'_>,
    method: DefId,
    expected_crate: &str,
    expected_self_path: &str,
    expected_methods: &[&str],
) -> bool {
    if method.krate != LOCAL_CRATE
        || cx.tcx.crate_name(LOCAL_CRATE).as_str() != expected_crate
        || !expected_methods.contains(&cx.tcx.item_name(method).as_str())
    {
        return false;
    }
    let impl_did = cx.tcx.parent(method);
    if !matches!(cx.tcx.def_kind(impl_did), DefKind::Impl { .. }) {
        return false;
    }
    cx.tcx
        .type_of(impl_did)
        .instantiate_identity()
        .ty_adt_def()
        .is_some_and(|adt| {
            is_exact_crate_path(
                &cx.tcx.def_path_str(adt.did()),
                expected_crate,
                expected_self_path,
            )
        })
}

struct RestrictedFunnel {
    help: &'static str,
}

/// Workspace-visible typed constructors still cross a trust boundary: the closed caller value
/// identifies *who*, not whether authentication and route/grant authorization happened. Restrict
/// these constructors to runtime so arbitrary domain crates cannot mint a verified capability.
fn restricted_service_capability_funnel(
    cx: &LateContext<'_>,
    did: DefId,
) -> Option<RestrictedFunnel> {
    let crate_name = cx.tcx.crate_name(did.krate);
    let item_name = cx.tcx.item_name(did);
    let parent_did = cx.tcx.parent(did);
    if !matches!(cx.tcx.def_kind(parent_did), DefKind::Impl { .. }) {
        return None;
    }
    let self_ty = cx.tcx.type_of(parent_did).skip_binder();
    let self_name = self_ty
        .ty_adt_def()
        .map(|adt| cx.tcx.item_name(adt.did()))?;
    match (crate_name.as_str(), self_name.as_str(), item_name.as_str()) {
        ("postgres", "ConfigValueMaintenanceCapability", "from_verified_service_caller") => {
            Some(RestrictedFunnel {
                help: "仅在 runtime 完成 maintenance service-token 验证后 mint `ConfigValueMaintenanceCapability`；其它 crate 不得把 typed caller 伪装成 verified capability",
            })
        }
        _ => None,
    }
}

/// `did` 是 `httpserve::Authenticated` 的 profile-specific 关联构造 fn。
/// 四步判定——缺第 4 步会误命中所有 `X::new`：
/// 1. callee crate 名 == "httpserve"
/// 2. item 名属于 profile-specific constructor 闭集
/// 3. parent def_kind 是 Impl（assoc fn）
/// 4. impl self 类型的 adt 名 == "Authenticated"（关键：区分 Vec::new 等同名 fn）
fn is_authenticated_mint_did(cx: &LateContext<'_>, did: DefId) -> bool {
    // 步骤 1：callee 属于 httpserve crate
    if cx.tcx.crate_name(did.krate).as_str() != "httpserve" {
        return false;
    }
    // 步骤 2：item 名是 "new"
    if !matches!(
        cx.tcx.item_name(did).as_str(),
        "new_federated" | "new_rss_user" | "new_mtls" | "new_service"
    ) {
        return false;
    }
    // 步骤 3：parent 是 Impl（assoc fn，非自由 fn）
    let parent_did = cx.tcx.parent(did);
    if !matches!(cx.tcx.def_kind(parent_did), DefKind::Impl { .. }) {
        return false;
    }
    // 步骤 4：impl self 类型的 adt 名 == "Authenticated"（杜绝 Vec::new 等误报）
    let self_ty = cx.tcx.type_of(parent_did).skip_binder();
    if let Some(adt_def) = self_ty.ty_adt_def() {
        cx.tcx.item_name(adt_def.did()).as_str() == "Authenticated"
    } else {
        false
    }
}

/// `did` 是 `authn::Principal` 的审计 subject accessor。
fn is_principal_audit_subject_did(cx: &LateContext<'_>, did: DefId) -> bool {
    if cx.tcx.crate_name(did.krate).as_str() != "authn" {
        return false;
    }
    if !matches!(
        cx.tcx.item_name(did).as_str(),
        "audit_subject" | "service_caller_domain"
    ) {
        return false;
    }
    let parent_did = cx.tcx.parent(did);
    if !matches!(cx.tcx.def_kind(parent_did), DefKind::Impl { .. }) {
        return false;
    }
    let self_ty = cx.tcx.type_of(parent_did).skip_binder();
    if let Some(adt_def) = self_ty.ty_adt_def() {
        cx.tcx.item_name(adt_def.did()).as_str() == "Principal"
    } else {
        false
    }
}

/// 当前被编译 crate（caller）在 allowlist 内。`LOCAL_CRATE` 是 caller，区别于 callee 的 `did.krate`；
/// 按 crate 名判定不可被「在别的 crate 里 `mod server`」伪造。
fn principal_accessor_caller_is_allowed(cx: &LateContext<'_>, hir_id: HirId) -> bool {
    let crate_name = cx.tcx.crate_name(LOCAL_CRATE);
    let parent = cx.tcx.hir_get_parent_item(hir_id).to_def_id();
    let item_name = cx.tcx.item_name(parent);
    let def_path = cx.tcx.def_path_str(parent);
    ALLOWED_PRINCIPAL_ACCESSOR_FUNCTIONS.iter().any(
        |(expected_crate, expected_name, expected_path)| {
            let exact_caller = crate_name.as_str() == *expected_crate
                && item_name.as_str() == *expected_name
                && is_exact_crate_path(&def_path, expected_crate, expected_path);
            exact_caller
                && (*expected_crate != "identityaudit"
                    || caller_consumes_validated_auth_grant(cx, parent, false))
        },
    )
}

fn is_exact_runtime_path(actual: &str, expected_without_crate: &str) -> bool {
    is_exact_crate_path(actual, "runtime", expected_without_crate)
}

fn is_exact_crate_path(actual: &str, crate_name: &str, expected_without_crate: &str) -> bool {
    actual == expected_without_crate
        || actual
            .strip_prefix(crate_name)
            .and_then(|path| path.strip_prefix("::"))
            .is_some_and(|path| path == expected_without_crate)
}

/// 在调用处报告；用调用 expr 的 `HirId` 解析 lint 级别，使 item/expr 级
/// `#[allow(rss_authenticated_callsite)]` 逃生门生效（同 rss_authplan_callsite）。
fn emit(
    cx: &LateContext<'_>,
    hir_id: HirId,
    span: Span,
    message: &'static str,
    help: &'static str,
) {
    span_lint_hir_and_then(
        cx,
        RSS_AUTHENTICATED_CALLSITE,
        hir_id,
        span,
        message,
        |diag| {
            diag.help(help);
        },
    );
}

#[test]
fn ui_disallowed() {
    // example target 名 `authenticated_callsite_ui`（非 allowlist）→ evidence/grant funnel 触发；
    // 含 anti-vacuity（Vec::new / httpserve 非-new fn 不触发，证明 lint 非「任意 ::new / 任意 httpserve 调用」）。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "authenticated_callsite_ui");
}

#[test]
fn ui_runtime_exact_wrappers() {
    // example target 名 `runtime`（= 唯一合法组合根 crate）验证 Authenticated/Principal 的 crate
    // allowlist，同时用 exact nested wrapper 绿与 direct/nested 红锁住 verification 分支。
    // "runtime" 不与 rss_authplan_callsite 的 "primitives" 在共享 lints workspace 撞 target 名。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "runtime");
}

#[test]
fn ui_settingsonly_exact_federated_wrapper() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "settingsonly");
}

#[test]
fn ui_identityaudit_exact_proof_consuming_wrapper() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "identityaudit");
}

#[test]
fn ui_identity_exact_grant_issue_wrappers() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "identity");
}

#[test]
fn ui_postgres_exact_grant_hydrate_wrapper() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "postgres");
}

#[test]
fn ui_authn_internal_hydrate_only_allowed() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "authn");
}
