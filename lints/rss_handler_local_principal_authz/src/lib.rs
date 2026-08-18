#![feature(rustc_private)]
//! `rss_handler_local_principal_authz` — RSS G0.4 治理 dylint lint：禁止 handler/domain
//! 直接读取 `Authenticated` tenant / principal kind / self subject 做本地授权，并禁止
//! 非 allowlist 的 `PrincipalKind::{Admin,SuperAdmin,...}` / role-name 字面量授权分支。
//!
//! INVARIANT: HANDLER-LOCAL-PRINCIPAL-AUTHZ-01 { level = "Medium", exec = "check", source = "dylint" }
//!
//! `Authenticated` 是 listener 级认证证据，只能表达「谁通过了入口认证」。域 crate 若直接读取
//! `tenant_id` / `principal_kind` / `self_scoped_principal_id` 做权限判断，会绕过 primary route gate 的
//! `RouteAuthorizer` / `AuthorizedSubject` 资源授权链路。
//! 同理，业务 crate 在 handler-local 分支里比较 `PrincipalKind::Admin` 或 `"Admin"` / `"superAdmin"`
//! 等 role-name 字面量，会把授权退回到身份展示数据；生产授权必须比较 typed
//! `GrantPermission` / `RoutePermissionId`。
//!
//! `tenancy.md` 明文：primary handler 只能消费 `AuthorizedSubject` 中的已授权主体上下文；
//! `Authenticated` 的 tenant/principal getter 仅允许 httpserve 内部 route gate 与 runtime 组合根审计链路使用。
//!
//! 上下游强度（ai-robust.md §审查要求「Funnel 类约束分别说明上游 / 下游」）：
//! - 上游：primary 路由统一在 `httpserve` route gate 调 `RouteAuthorizer`，成功后插入 `AuthorizedSubject`。
//! - 下游：handler/domain 若绕回 `Authenticated` getter 做 principal/subject 分支，即绕开 funnel；
//!   因 getter 本身是公开 API，必须经 callsite lint 约束。
//!
//! 关键差异（vs `rss_crosstenant_callsite`）：`tenant_id` / `principal_kind` / `self_scoped_principal_id` 是常见 fn 名，
//! 必须额外验证关联 fn 的 parent impl 的 self 类型确实是 `Authenticated`，否则同名方法会误报。
//! 判定四步：① callee crate 名 == "httpserve"；② item 名 ∈ {"tenant_id","principal_kind","self_scoped_principal_id"}；③ parent 是 Impl；
//! ④ impl self 类型的 adt 名 == "Authenticated"（self-ty 检查，本 lint 与 crosstenant 的唯一实质差异）。
//!
//! 检测面：捕获直接 method call，以及对这些 getter assoc fn 的 path 引用——`let f = Authenticated::principal_kind`
//! 函数项别名、fn-pointer 强转都解析到同一 `DefId`。
//!
//! 盲区：① 仅 `cargo dylint --all`（接 `cargo xtask verify`，`-D warnings` fail-closed）拦；
//! ② `ALLOWED_CALLER_CRATES` 扩项无机器复核，靠 greppable + 治理评审；③ **跨函数**洗白仍未覆盖
//! （intraprocedural）：allowlist crate 内 `pub fn wrap(ev: Authenticated) -> PrincipalKind { ev.principal_kind() }`
//! 被外部调用，lint 只见各自直接引用、不跨函数追（跟踪 #1085）；④ role-name literal 只覆盖治理登记的
//! 内置角色名称拼写和同函数内 `match` pattern，不做通用字符串语义分析；⑤ `#[cfg(test)]` 树不扫，httpserve
//! 内自测调用不命中（与 crosstenant 同）。

extern crate rustc_ast;
extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_ast::ast::LitKind;
use rustc_hir::def::{DefKind, Res};
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_hir::{BinOpKind, Expr, ExprKind, HirId, Lit, Pat, PatExprKind, PatKind, QPath};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::Span;

/// 仅这些 crate 可读取 `Authenticated` tenant / principal kind / self subject——单一 greppable 真源，扩项须治理评审。
/// `httpserve` route gate 负责把认证证据升级为 `AuthorizedSubject`；runtime 组合根保留审计链路读取权。
/// assemblies/runtime → package name "runtime"（#1309 单一组合根；薄 bin bins/server、bins/rss 已移出）。
/// `httpserve` 本身定义 `Authenticated`，并在 route gate 内构造授权请求，合法豁免。
const ALLOWED_CALLER_CRATES: &[&str] = &["httpserve", "runtime"];
const PRINCIPAL_BRANCH_ALLOWED_CRATES: &[&str] = &["httpserve", "generated"];
const AUTHN_PRINCIPAL_BRANCH_ALLOWED_ITEMS: &[&str] = &[
    "kind_claim",
    "needs_tenant",
    "alg_allows_kind",
    "issue_inner",
    "row_visibility",
    "cross_tenant_audit_grant",
];
const DIPORT_PRINCIPAL_BRANCH_ALLOWED_ITEMS: &[&str] = &["federated_access"];
const RUNTIME_PRINCIPAL_BRANCH_ALLOWED_ITEMS: &[&str] = &[
    "allow_evidence",
    "verify_maintenance_operator_subject",
    "verified_service_maintenance_operator",
    "verified_projection_maintenance_operator_subject",
];
/// 关联方法例外使用 local-crate 内的完整 DefPath，禁止跨模块同名类型误命中。
const RUNTIME_PRINCIPAL_BRANCH_ALLOWED_METHODS: &[(&str, &str)] =
    &[("authorize", "routes::MtlsRouteAuthorizer")];
const REQUEST_CONTEXT_PRINCIPAL_KIND_REPR_ITEMS: &[&str] = &["fmt", "as_actor_metadata_label"];
const IDENTITY_CONTRACT_AUTHORIZER_METHODS: &[&str] = &[
    "authorize_request",
    "authorize_role_permission",
    "authorize_policy_scope_management",
    "role_assigned_actor_kind_wire",
    "role_revoked_actor_kind_wire",
    "actor_kind_wire",
    "profile_kind_wire",
    "kind_to_db",
    // wire / grant-binding mappers（非 handler-local 授权分支）
    "privacy_ref",
    "current_user_grant_context",
    "credential_security_fact",
];
const AUDIT_ALLOWED_METHODS: &[&str] = &[
    "list_entries_target_tenant",
    "principal_kind_wire",
    "actor_kind_to_db",
    "principal_kind_tag",
];
/// postgres adapter：audit sink 的 PrincipalKind→DB 标签 mapper（非授权分支）。
const POSTGRES_ALLOWED_ITEMS: &[&str] = &["actor_kind_to_db"];
/// postgres adapter：canonical device-ingress envelope shape 验证（非授权分支）。
/// receiver 以 local-crate 内完整 DefPath 登记，短名不足以证明 canonical identity。
const POSTGRES_ALLOWED_METHODS: &[(&str, &str)] = &[(
    "from_reviewed_event",
    "cotx::identity::CanonicalDeviceIngressFact",
)];
/// identityaudit 组合根：RSS access verify 后绑定 User（非 primary handler 授权）。
const IDENTITYAUDIT_ALLOWED_METHODS: &[&str] = &["authenticate"];

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// 标记非 allowlist crate 对 `httpserve::Authenticated::{tenant_id,principal_kind,self_scoped_principal_id}` 的
    /// 直接 method call 或 path 引用（`let f = Authenticated::principal_kind` 别名、fn-pointer 强转）。
    /// 同时标记非 allowlist crate 中 `PrincipalKind::{Admin,SuperAdmin,...}` 或 role-name 字面量比较形成的
    /// handler-local 授权条件。
    ///
    /// ### Why is this bad?
    /// `Authenticated` 只能表达入口认证结果；tenant、权限、资源、自服务授权必须由 primary route gate 统一完成。
    /// handler/domain 直接读取 tenant/principal/subject 做本地授权，会绕过 `RouteAuthorizer` 和 `AuthorizedSubject`。
    /// 直接比较 principal kind 或 role-name 字面量也会绕过 typed `GrantPermission` / `RoutePermissionId`。
    /// INVARIANT: HANDLER-LOCAL-PRINCIPAL-AUTHZ-01 { level = "Medium", exec = "check", source = "dylint" }。
    ///
    /// ### Known problems
    /// 仍 intraprocedural：allowlist crate 内 wrapper fn（`pub fn kind(ev: Authenticated) { ev.principal_kind() }`）被外部
    /// 调用会**跨函数**洗白（lint 只见各自直接引用，跟踪 #1085）。`ALLOWED_CALLER_CRATES` 扩项
    /// 无机器复核（靠 greppable + 治理）。确需在 allowlist 外引用加
    /// `#[allow(rss_handler_local_principal_authz)] // reason: ...`。
    ///
    /// ### Example
    /// ```ignore
    /// // 域 crate（非组合根）：
    /// if ev.principal_kind() == PrincipalKind::Admin { /* 本地授权 */ } // 触发
    /// ```
    /// Use instead: handler 读取 route gate 插入的 `AuthorizedSubject`。
    pub RSS_HANDLER_LOCAL_PRINCIPAL_AUTHZ,
    Warn,
    "handler/domain 不得直接读取 Authenticated 或用 principal/role 字面量做本地授权（callsite-allowlist）"
}

impl<'tcx> LateLintPass<'tcx> for RssHandlerLocalPrincipalAuthz {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        if is_principal_or_role_literal_branch(cx, expr)
            && !principal_branch_caller_is_allowed(cx, expr.hir_id)
        {
            emit_principal_branch(cx, expr.hir_id, expr.span);
            return;
        }
        if let ExprKind::MethodCall(..) = expr.kind {
            if let Some(did) = cx.typeck_results().type_dependent_def_id(expr.hir_id)
                && is_authenticated_context_getter_did(cx, did)
                && !caller_is_allowed(cx)
            {
                emit(cx, expr.hir_id, expr.span);
            }
            return;
        }
        // 捕获对 getter fn-item 的**任意** path 引用——直接 call 的 callee、`let f = Authenticated::principal_kind` 别名、
        // fn-pointer 强转都是 `ExprKind::Path` 解析到该 assoc fn `DefId`；只拦表面 call 会被「先别名再调用」绕过。
        let ExprKind::Path(ref qpath) = expr.kind else {
            return;
        };
        let Res::Def(DefKind::AssocFn | DefKind::Fn, did) = cx.qpath_res(qpath, expr.hir_id) else {
            return;
        };
        if is_authenticated_context_getter_did(cx, did) && !caller_is_allowed(cx) {
            emit(cx, expr.hir_id, expr.span);
        }
    }
}

fn is_principal_or_role_literal_branch(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    match expr.kind {
        ExprKind::Binary(op, lhs, rhs) if matches!(op.node, BinOpKind::Eq | BinOpKind::Ne) => {
            principal_kind_variant_expr(cx, lhs)
                || principal_kind_variant_expr(cx, rhs)
                || role_name_literal_expr(lhs)
                || role_name_literal_expr(rhs)
        }
        ExprKind::Match(scrutinee, arms, _) => {
            let role_like_scrutinee = role_like_expr(scrutinee);
            arms.iter().any(|arm| {
                principal_kind_variant_pat(cx, arm.pat)
                    || (role_like_scrutinee && role_name_literal_pat(arm.pat))
            })
        }
        _ => false,
    }
}

fn principal_kind_variant_expr(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let ExprKind::Path(ref qpath) = expr.kind else {
        return false;
    };
    principal_kind_variant_qpath(cx, qpath, expr.hir_id)
}

fn principal_kind_variant_pat(cx: &LateContext<'_>, pat: &Pat<'_>) -> bool {
    match pat.kind {
        PatKind::Expr(expr) => match expr.kind {
            PatExprKind::Path(ref qpath) => principal_kind_variant_qpath(cx, qpath, expr.hir_id),
            PatExprKind::Lit { .. } => false,
        },
        PatKind::Struct(ref qpath, fields, _) => {
            principal_kind_variant_qpath(cx, qpath, pat.hir_id)
                || fields
                    .iter()
                    .any(|field| principal_kind_variant_pat(cx, field.pat))
        }
        PatKind::TupleStruct(ref qpath, patterns, _) => {
            principal_kind_variant_qpath(cx, qpath, pat.hir_id)
                || patterns
                    .iter()
                    .any(|pattern| principal_kind_variant_pat(cx, pattern))
        }
        PatKind::Or(patterns) => patterns
            .iter()
            .any(|pattern| principal_kind_variant_pat(cx, pattern)),
        PatKind::Binding(_, _, _, Some(subpattern)) => principal_kind_variant_pat(cx, subpattern),
        PatKind::Tuple(patterns, _) => patterns
            .iter()
            .any(|pattern| principal_kind_variant_pat(cx, pattern)),
        PatKind::Slice(before, middle, after) => {
            before
                .iter()
                .chain(after.iter())
                .any(|pattern| principal_kind_variant_pat(cx, pattern))
                || middle.is_some_and(|pattern| principal_kind_variant_pat(cx, pattern))
        }
        PatKind::Box(subpattern) | PatKind::Deref(subpattern) | PatKind::Ref(subpattern, _, _) => {
            principal_kind_variant_pat(cx, subpattern)
        }
        PatKind::Guard(subpattern, guard) => {
            principal_kind_variant_pat(cx, subpattern)
                || is_principal_or_role_literal_branch(cx, guard)
        }
        _ => false,
    }
}

fn role_name_literal_pat(pat: &Pat<'_>) -> bool {
    match pat.kind {
        PatKind::Expr(expr) => match expr.kind {
            PatExprKind::Lit { lit, .. } => role_name_literal_lit(&lit),
            PatExprKind::Path(_) => false,
        },
        PatKind::Struct(_, fields, _) => {
            fields.iter().any(|field| role_name_literal_pat(field.pat))
        }
        PatKind::TupleStruct(_, patterns, _) | PatKind::Tuple(patterns, _) => {
            patterns.iter().any(role_name_literal_pat)
        }
        PatKind::Or(patterns) => patterns.iter().any(role_name_literal_pat),
        PatKind::Binding(_, _, _, Some(subpattern)) => role_name_literal_pat(subpattern),
        PatKind::Slice(before, middle, after) => {
            before.iter().chain(after.iter()).any(role_name_literal_pat)
                || middle.is_some_and(role_name_literal_pat)
        }
        PatKind::Box(subpattern) | PatKind::Deref(subpattern) | PatKind::Ref(subpattern, _, _) => {
            role_name_literal_pat(subpattern)
        }
        PatKind::Guard(subpattern, _) => role_name_literal_pat(subpattern),
        _ => false,
    }
}

fn role_like_expr(expr: &Expr<'_>) -> bool {
    match expr.kind {
        ExprKind::Path(ref qpath) => qpath_is_role_like(qpath),
        ExprKind::MethodCall(segment, ..) => role_like_name(segment.ident.name.as_str().as_ref()),
        _ => false,
    }
}

fn qpath_is_role_like(qpath: &QPath<'_>) -> bool {
    match qpath {
        QPath::Resolved(_, path) => path
            .segments
            .last()
            .is_some_and(|segment| role_like_name(segment.ident.name.as_str().as_ref())),
        QPath::TypeRelative(_, segment) => role_like_name(segment.ident.name.as_str().as_ref()),
    }
}

fn role_like_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("role") || name.contains("kind") || name.contains("principal")
}

fn principal_kind_variant_qpath(cx: &LateContext<'_>, qpath: &QPath<'_>, hir_id: HirId) -> bool {
    let Res::Def(_, did) = cx.qpath_res(qpath, hir_id) else {
        return false;
    };
    if cx.tcx.crate_name(did.krate).as_str() != "rss_request_context" {
        return false;
    }
    let item_name = cx.tcx.item_name(did);
    if !matches!(
        item_name.as_str(),
        "User" | "Device" | "Admin" | "SuperAdmin" | "Service"
    ) {
        return false;
    }
    cx.tcx.def_path_str(did).contains("PrincipalKind")
}

fn role_name_literal_expr(expr: &Expr<'_>) -> bool {
    let ExprKind::Lit(lit) = expr.kind else {
        return false;
    };
    role_name_literal_lit(&lit)
}

fn role_name_literal_lit(lit: &Lit) -> bool {
    let LitKind::Str(symbol, _) = lit.node else {
        return false;
    };
    matches!(
        symbol.as_str().as_ref(),
        "admin"
            | "Admin"
            | "superAdmin"
            | "SuperAdmin"
            | "super_admin"
            | "user"
            | "User"
            | "device"
            | "Device"
            | "service"
            | "Service"
    )
}

fn principal_branch_caller_is_allowed(cx: &LateContext<'_>, hir_id: HirId) -> bool {
    let crate_name = cx.tcx.crate_name(LOCAL_CRATE);
    let crate_name = crate_name.as_str();
    if PRINCIPAL_BRANCH_ALLOWED_CRATES.contains(&crate_name) {
        return true;
    }
    match crate_name {
        "rss_request_context" => {
            enclosing_item_is_any(cx, hir_id, REQUEST_CONTEXT_PRINCIPAL_KIND_REPR_ITEMS)
        }
        "authn" => enclosing_item_is_any(cx, hir_id, AUTHN_PRINCIPAL_BRANCH_ALLOWED_ITEMS),
        "diport" => enclosing_item_is_any(cx, hir_id, DIPORT_PRINCIPAL_BRANCH_ALLOWED_ITEMS),
        "runtime" => {
            enclosing_item_is_any(cx, hir_id, RUNTIME_PRINCIPAL_BRANCH_ALLOWED_ITEMS)
                || enclosing_method_on_allowed_type_is(
                    cx,
                    hir_id,
                    RUNTIME_PRINCIPAL_BRANCH_ALLOWED_METHODS,
                )
        }
        "identity" => enclosing_item_is_any(cx, hir_id, IDENTITY_CONTRACT_AUTHORIZER_METHODS),
        "audit" => enclosing_item_is_any(cx, hir_id, AUDIT_ALLOWED_METHODS),
        "postgres" => {
            enclosing_item_is_any(cx, hir_id, POSTGRES_ALLOWED_ITEMS)
                || enclosing_method_on_allowed_type_is(cx, hir_id, POSTGRES_ALLOWED_METHODS)
        }
        "identityaudit" => enclosing_item_is_any(cx, hir_id, IDENTITYAUDIT_ALLOWED_METHODS),
        _ => false,
    }
}

fn enclosing_item_is_any(cx: &LateContext<'_>, hir_id: HirId, allowed: &[&str]) -> bool {
    cx.tcx.hir_parent_owner_iter(hir_id).any(|(owner, _)| {
        let did = owner.def_id.to_def_id();
        if !matches!(cx.tcx.def_kind(did), DefKind::Fn | DefKind::AssocFn) {
            return false;
        }
        let name = cx.tcx.item_name(did);
        allowed.iter().any(|candidate| name.as_str() == *candidate)
    })
}

fn enclosing_method_on_allowed_type_is(
    cx: &LateContext<'_>,
    hir_id: HirId,
    allowed: &[(&str, &str)],
) -> bool {
    cx.tcx.hir_parent_owner_iter(hir_id).any(|(owner, _)| {
        let did = owner.def_id.to_def_id();
        if !matches!(cx.tcx.def_kind(did), DefKind::AssocFn) {
            return false;
        }
        let item_name = cx.tcx.item_name(did);
        let Some((_, self_type)) = allowed
            .iter()
            .find(|(method, _)| item_name.as_str() == *method)
        else {
            return false;
        };
        let parent_did = cx.tcx.parent(did);
        if !matches!(cx.tcx.def_kind(parent_did), DefKind::Impl { .. }) {
            return false;
        }
        let self_ty = cx.tcx.type_of(parent_did).skip_binder();
        self_ty
            .ty_adt_def()
            .is_some_and(|adt_def| cx.tcx.def_path_str(adt_def.did()) == *self_type)
    })
}

/// `did` 是 `httpserve::Authenticated` 的关联 fn `tenant_id`、`principal_kind` 或 `self_scoped_principal_id`。
/// 四步判定——缺第 4 步会误命中所有同名 getter：
/// 1. callee crate 名 == "httpserve"
/// 2. item 名 ∈ {"tenant_id", "principal_kind", "self_scoped_principal_id"}
/// 3. parent def_kind 是 Impl（assoc fn）
/// 4. impl self 类型的 adt 名 == "Authenticated"
fn is_authenticated_context_getter_did(cx: &LateContext<'_>, did: DefId) -> bool {
    // 步骤 1：callee 属于 httpserve crate
    if cx.tcx.crate_name(did.krate).as_str() != "httpserve" {
        return false;
    }
    // 步骤 2：item 名是受治理的 Authenticated 上下文 getter
    let item_name = cx.tcx.item_name(did);
    if item_name.as_str() != "tenant_id"
        && item_name.as_str() != "principal_kind"
        && item_name.as_str() != "self_scoped_principal_id"
    {
        return false;
    }
    // 步骤 3：parent 是 Impl（assoc fn，非自由 fn）
    let parent_did = cx.tcx.parent(did);
    if !matches!(cx.tcx.def_kind(parent_did), DefKind::Impl { .. }) {
        return false;
    }
    // 步骤 4：impl self 类型的 adt 名 == "Authenticated"（杜绝同名 getter 误报）
    let self_ty = cx.tcx.type_of(parent_did).skip_binder();
    if let Some(adt_def) = self_ty.ty_adt_def() {
        cx.tcx.item_name(adt_def.did()).as_str() == "Authenticated"
    } else {
        false
    }
}

/// 当前被编译 crate（caller）在 allowlist 内。`LOCAL_CRATE` 是 caller，区别于 callee 的 `did.krate`；
/// 按 crate 名判定不可被「在别的 crate 里 `mod server`」伪造。
fn caller_is_allowed(cx: &LateContext<'_>) -> bool {
    ALLOWED_CALLER_CRATES.contains(&cx.tcx.crate_name(LOCAL_CRATE).as_str())
}

/// 在调用处报告；用调用 expr 的 `HirId` 解析 lint 级别，使 item/expr 级
/// `#[allow(rss_handler_local_principal_authz)]` 逃生门生效（同 rss_crosstenant_callsite）。
fn emit(cx: &LateContext<'_>, hir_id: HirId, span: Span) {
    span_lint_hir_and_then(
        cx,
        RSS_HANDLER_LOCAL_PRINCIPAL_AUTHZ,
        hir_id,
        span,
        "handler/domain 不得直接读取 Authenticated tenant/principal/self subject 做本地授权",
        |diag| {
            diag.help(
                "改为读取 route gate 插入的 AuthorizedSubject；确需在 allowlist 外调用须经治理评审扩 `ALLOWED_CALLER_CRATES`，或 item-level `#[allow(rss_handler_local_principal_authz)] // reason: ...`",
            );
        },
    );
}

fn emit_principal_branch(cx: &LateContext<'_>, hir_id: HirId, span: Span) {
    span_lint_hir_and_then(
        cx,
        RSS_HANDLER_LOCAL_PRINCIPAL_AUTHZ,
        hir_id,
        span.source_callsite(),
        "handler/domain 不得用 PrincipalKind 或 role-name 字面量做本地授权分支",
        |diag| {
            diag.help(
                "改为比较 typed GrantPermission/RoutePermissionId，或把例外集中在 ContractAuthorizer / route gate / authn funnel",
            );
        },
    );
}

#[test]
fn ui_disallowed() {
    // example target 名 `handler_local_principal_authz_ui`（非 allowlist）→ 调 Authenticated getter 触发；
    // 含 anti-vacuity（同名本地 getter 不触发，证明 lint 非「任意同名方法」）。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "handler_local_principal_authz_ui");
}

#[test]
fn ui_httpserve_allowed() {
    // example target 名 `httpserve`（= allowlist 项，定义 crate 内部豁免）⇒ crate_name(LOCAL_CRATE)=="httpserve"
    // ⇒ 调 funnel 不触发，验证 allowlist 分支（anti-vacuity：lint 非恒报）。golden ui/httpserve.stderr 为空。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "httpserve");
}

#[test]
fn ui_runtime_bridge_only_allowed() {
    // example target 名 `runtime`：真实 DefPath 的 mTLS authorizer 放行；跨模块同名 shadow 与其它
    // handler-local role literal 分支仍触发，证明 allowlist 绑定 canonical identity。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "runtime");
}

#[test]
fn ui_diport_profile_shape_only_allowed() {
    // example target 名 `diport`：闭合 verified profile 构造器可校验 PrincipalKind shape；
    // 同 crate 其它 principal 分支仍触发，证明不是 crate 级白名单。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "diport");
}

#[test]
fn ui_identity_wire_mappers_only_allowed() {
    // example target 名 `identity`：只放行登记的 wire/grant mapper；同 crate handler-local 仍触发。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "identity");
}

#[test]
fn ui_postgres_actor_kind_mapper_only_allowed() {
    // example target 名 `postgres`：只放行 mapper 与真实 DefPath 的 ingress fact；跨模块同名 shadow
    // 及其它 handler-local 分支仍触发。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "postgres");
}

#[test]
fn ui_identityaudit_authenticate_only_allowed() {
    // example target 名 `identityaudit`：只放行组合根 authenticate；同 crate 其它分支仍触发。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "identityaudit");
}
